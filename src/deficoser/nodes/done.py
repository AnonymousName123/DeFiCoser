from __future__ import annotations
import json
import time
from typing import Any, Callable
from deficoser.config import load_prompt
from deficoser.journal import VIOLATION_KEYS
from deficoser.llm.schemas import REPORT_SCHEMA
from deficoser.nodes.contract_parser import _call_llm_safe, _cap, _format_template, _split_prompt
from deficoser.state import DeFiState
NODE_NAME = 'done'
_MAX_REPORT_DATA_CHARS = 40000


def normalize_violations(violations: list[dict] | None) -> list[dict]:
    normalized: list[dict] = []
    for violation in violations or []:
        entry = dict(violation) if isinstance(violation, dict) else {}
        for key in VIOLATION_KEYS:
            entry.setdefault(key, None)
        normalized.append(entry)
    return normalized


def exploitability_entries(violations: list[dict], verified: list[dict]) -> list[dict]:
    by_index: dict[int, dict] = {}
    for entry in verified or []:
        if isinstance(entry, dict) and isinstance(entry.get('violation_index'), int):
            by_index[entry['violation_index']] = entry
    result: list[dict] = []
    for index, violation in enumerate(violations):
        entry = by_index.get(index)
        if entry is None:
            result.append({'index': index, 'sink': violation.get('sink'), 'verdict': 'unverified', 'impact': None, 'evidence': None})
            continue
        impact = entry.get('impact_verdict') or {}
        result.append({'index': index, 'sink': violation.get('sink'), 'verdict': bool(entry.get('exploitability')), 'impact': impact, 'evidence': impact.get('evidence') or []})
    return result


def _fallback_summaries(violations: list[dict], exploit_list: list[dict]) -> tuple[str, str]:
    detection_summary = f'Detected {len(violations)} candidate access-control violations; details are in the violations list (sink / attacker role / required role / unauthorized path / location / exploit method).'
    verdicts = [entry.get('verdict') for entry in exploit_list]
    true_count = sum((1 for verdict in verdicts if verdict is True))
    unverified_count = sum((1 for verdict in verdicts if verdict == 'unverified'))
    false_count = len(exploit_list) - true_count - unverified_count
    exploit_summary = f'Of {len(exploit_list)} candidates: {true_count} were judged exploitable by the dual Oracle, {false_count} were judged non-exploitable, and {unverified_count} did not enter PoC verification; per-item decisions and impact evidence are in per_violation.'
    return detection_summary, exploit_summary


def _call_summaries(llm_client: Any, violations: list[dict], exploit_list: list[dict]) -> tuple[dict | None, str]:
    template = load_prompt('report')
    system, user = _split_prompt(template.content)
    user = _format_template(user, {'detection_data': _cap(json.dumps(violations, ensure_ascii=False), _MAX_REPORT_DATA_CHARS), 'exploitability_data': _cap(json.dumps(exploit_list, ensure_ascii=False), _MAX_REPORT_DATA_CHARS), 'json_schema': json.dumps(REPORT_SCHEMA, ensure_ascii=False)})
    return _call_llm_safe(llm_client, 'report', [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}], REPORT_SCHEMA)


def done_node(state: DeFiState, *, llm_client: Any=None, journal: Any=None) -> dict:
    started = time.perf_counter()
    violations = normalize_violations(state.get('ac_violations'))
    verified = list(state.get('verified_violations') or [])
    exploit_list = exploitability_entries(violations, verified)
    detection_summary, exploit_summary = _fallback_summaries(violations, exploit_list)
    llm_tokens = 0.0
    llm_error = ''
    if llm_client is not None:
        records_before = len(getattr(llm_client, 'usage_records', []))
        payload, llm_error = _call_summaries(llm_client, violations, exploit_list)
        new_records = getattr(llm_client, 'usage_records', [])[records_before:]
        llm_tokens = sum((record.total_tokens for record in new_records))
        if payload is not None:
            detection_summary = (payload.get('detection') or {}).get('summary') or detection_summary
            exploit_summary = (payload.get('exploitability') or {}).get('summary') or exploit_summary
    if journal is not None:
        journal.add_stage_usage('report', llm_tokens, (time.perf_counter() - started) * 1000)
    result: dict = {'report': {'detection': {'summary': detection_summary, 'violations': violations}, 'exploitability': {'summary': exploit_summary, 'per_violation': exploit_list}}}
    if llm_error:
        result['error'] = {'node': NODE_NAME, 'message': f'Report narrative LLM generation failed, fell back to placeholder narrative: {llm_error}', 'fatal': False}
    return result


def make_done_node(llm_client: Any=None, journal: Any=None) -> Callable[[DeFiState], dict]:

    def _node(state: DeFiState) -> dict:
        return done_node(state, llm_client=llm_client, journal=journal)
    return _node
