from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

from deficoser.config import POC_MAX_RETRIES_INITIAL, load_llm_settings, llm_config
from deficoser.graph import build_graph
from deficoser.journal import CaseJournal
from deficoser.llm.client import LLMClient
from deficoser.memory.memory import AttackPatternMemory
from deficoser.state import DeFiState

DEFAULT_LOGS_DIR = Path("logs")


def load_sources(root: Path) -> dict[str, str]:
    sources: dict[str, str] = {}
    for path in sorted(root.rglob("*.sol")):
        sources[path.relative_to(root).as_posix()] = path.read_text(encoding="utf-8", errors="replace")
    return sources


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="run_contract.py",
        description="Run the DeFiCoser detection and PoC-validation pipeline on a directory of Solidity sources.",
    )
    parser.add_argument("--contract-dir", required=True, help="directory holding the victim contract sources (*.sol, scanned recursively)")
    parser.add_argument("--case-id", default=None, help="case identifier recorded in the log; defaults to the contract directory name")
    parser.add_argument("--dataset", default="custom", help="dataset label recorded in the log")
    parser.add_argument("--time-bucket", default=None, help="optional time-bucket label recorded in the log")
    parser.add_argument("--config", default="full", help="configuration label recorded in the log")
    parser.add_argument("--model", default=None, help="override the model resolved from API-KEY.txt / the environment")
    parser.add_argument("--memory-mode", default="none", choices=["none", "frozen", "streaming"], help="attack-pattern memory mode")
    parser.add_argument("--snapshot", default=None, help="snapshot file to preload when --memory-mode is frozen")
    parser.add_argument("--memory-store", default=None, help="pattern store directory; defaults to memory_store/")
    parser.add_argument("--backend", default="auto", choices=["auto", "fastembed", "tfidf"], help="retrieval backend")
    parser.add_argument("--logs-dir", default=str(DEFAULT_LOGS_DIR), help="output directory for the case log and reports")
    parser.add_argument("--timeout", type=int, default=600, help="per forge test timeout in seconds")
    parser.add_argument("--max-recursion", type=int, default=300, help="LangGraph recursion limit")
    return parser.parse_args(argv)


def build_memory(args: argparse.Namespace) -> AttackPatternMemory | None:
    if args.memory_mode == "none":
        return None
    store_path = Path(args.memory_store) if args.memory_store else None
    memory = AttackPatternMemory(store_path=store_path, mode=args.memory_mode, backend=args.backend)
    if args.snapshot:
        memory.load_snapshot(args.snapshot)
    return memory


def journal_fields(state: dict) -> dict:
    verified = state.get("verified_violations") or []
    exploitable = any(entry.get("exploitability") for entry in verified)
    impact = {"type": None, "gain": None}
    for entry in verified:
        verdict = entry.get("impact_verdict") or {}
        impact_type = verdict.get("primary_type") or (verdict.get("impact_types") or [None])[0]
        if impact_type:
            impact = {"type": impact_type, "gain": verdict.get("gain")}
            break
    return {
        "detected": bool(state.get("ac_violations")),
        "exploitable": exploitable,
        "authorization_violation": exploitable,
        "impact": impact,
    }


def print_summary(row: dict, model: str, wall_s: float, llm_calls: int) -> None:
    tokens = row.get("tokens") or {}
    time_ms = row.get("time_ms") or {}
    print("")
    print(f"case {row.get('case_id')} finished | model={model} | llm_calls={llm_calls} | wall={wall_s:.1f}s")
    print(f"{'stage':<24}{'tokens':>10}{'time_ms':>12}")
    for stage in tokens:
        if stage == "total":
            continue
        if tokens.get(stage) or time_ms.get(stage):
            print(f"{stage:<24}{tokens.get(stage, 0):>10}{time_ms.get(stage, 0):>12.0f}")
    print(f"{'total':<24}{tokens.get('total', 0):>10}{time_ms.get('total', 0):>12.0f}")
    print(
        f"detected={row.get('detected')} violations={len(row.get('violations') or [])}"
        f" exploitable={row.get('exploitable')}"
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    contract_dir = Path(args.contract_dir)
    if not contract_dir.is_dir():
        print(f"error: contract directory not found: {contract_dir}", file=sys.stderr)
        return 2
    sources = load_sources(contract_dir)
    if not sources:
        print(f"error: no .sol files under {contract_dir}", file=sys.stderr)
        return 2

    case_id = args.case_id or contract_dir.name or "case_001"
    logs_dir = Path(args.logs_dir)
    logs_dir.mkdir(parents=True, exist_ok=True)

    try:
        memory = build_memory(args)
    except (OSError, ValueError) as exc:
        print(f"error: cannot initialize the pattern memory: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    memory_size = memory.memory_size if memory is not None else 0

    try:
        settings = load_llm_settings(model=args.model)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print(
            "hint: create API-KEY.txt at the repository root, or export"
            " DEFICOSER_BASE_URL / DEFICOSER_API_KEY / DEFICOSER_MODEL",
            file=sys.stderr,
        )
        return 2
    llm = LLMClient(base_url=settings.base_url, api_key=settings.api_key, model=settings.model)

    case_meta = {
        "case_id": case_id,
        "dataset": args.dataset,
        "time_bucket": args.time_bucket,
        "config": args.config,
        "llm_model": settings.model,
        "memory_mode": args.memory_mode,
        "memory_size": memory_size,
        "llm_config": llm_config(model=settings.model),
    }
    journal = CaseJournal(logs_dir=logs_dir, filename="cases.jsonl")
    journal.begin_case(case_meta)

    backend_note = f" | retrieval={memory.backend}" if memory is not None else ""
    print(
        f"case {case_id} | {len(sources)} .sol file(s) | model={settings.model}"
        f" | memory={args.memory_mode}({memory_size}){backend_note}"
    )

    initial_state: DeFiState = {
        "contract_sources": sources,
        "case_id": case_id,
        "dataset": args.dataset,
        "time_bucket": args.time_bucket,
        "config": args.config,
        "memory_mode": args.memory_mode,
        "memory_size": memory_size,
        "poc_max_retries": POC_MAX_RETRIES_INITIAL,
        "poc_retry_count": 0,
    }

    graph = build_graph(llm_client=llm, journal=journal, memory=memory, timeout=args.timeout)

    started = time.perf_counter()
    try:
        state = graph.invoke(initial_state, config={"recursion_limit": args.max_recursion})
    except Exception as exc:
        wall_s = time.perf_counter() - started
        journal.fail_case({"node": "runner", "message": f"{type(exc).__name__}: {exc}", "fatal": True})
        print(
            f"error: graph execution failed after {wall_s:.1f}s: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        return 1
    wall_s = time.perf_counter() - started

    for field, value in journal_fields(state).items():
        journal.set(field, value)
    journal.add_violations(state.get("ac_violations") or [])
    row = journal.finish_case()

    report_path = logs_dir / f"{case_id}_report.json"
    report_path.write_text(
        json.dumps(state.get("report") or {}, indent=2, default=str, ensure_ascii=False),
        encoding="utf-8",
    )
    state_path = logs_dir / f"{case_id}_final_state.json"
    state_path.write_text(
        json.dumps(state, indent=2, default=str, ensure_ascii=False),
        encoding="utf-8",
    )

    print_summary(row, settings.model, wall_s, len(llm.usage_records))
    print(f"case log: {logs_dir / 'cases.jsonl'}")
    print(f"report:   {report_path}")
    print(f"state:    {state_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
