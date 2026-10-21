# DeFiCoser

DeFiCoser is a LangGraph pipeline that analyzes Solidity contracts and reports access control vulnerabilities. It runs two stages end to end:

1. **Detection** — parse the contract, build a Role Space and a Role Capability Graph (RCG), then let an
   adversarial explorer adjudicate candidate unauthorized-access paths against the declared authorization
   predicates.
2. **Exploitability validation** — turn each confirmed candidate into a role-conditioned attack blueprint,
   generate an executable Foundry test, run it against a freshly deployed instance of the victim contract,
   and adjudicate the result with a dual oracle (authorization + impact).

The pipeline can optionally draw on an **attack-pattern memory** of historical incidents (streaming or
frozen), which supplies few-shot personas and action sequences to the explorer and the planner.

> An LLM API key and a working Foundry installation are **required** for a full run. See
> [Requirements](#requirements) and [Configuration](#configuration).

---

## Contents of this artifact

```
config/                      runtime configuration (role name mapping, sensitive-sink keywords)
prompts/                     one prompt template per LLM stage (no version suffixes)
src/deficoser/
  config.py                  all tunable parameters, LLM settings loading, prompt loading
  state.py                   DeFiState — the LangGraph global state
  graph.py                   graph assembly: 9 domain nodes + 3 transition nodes
  journal.py                 per-case JSON Lines logging
  llm/                       OpenAI-compatible client + structured-output JSON schemas
  nodes/                     one module per pipeline node
  tools/                     deterministic tooling: solc, Slither, AST, RCG, path enumeration, forge
  memory/                    attack-pattern memory (store / retriever / learning) + its templates
run_contract.py              CLI runner over a directory of Solidity sources (see Quickstart)
pyproject.toml               dependencies and packaging
```

---

## Requirements

| Requirement | Notes |
|---|---|
| **Python ≥ 3.14** | `pyproject.toml` declares `requires-python = ">=3.14"` |
| **[uv](https://docs.astral.sh/uv/)** | Package manager used by this project |
| **LLM API key** | **Required.** Any OpenAI-compatible endpoint (base URL + key + model) |
| **Foundry** | **Required.** `forge` must be installed and resolvable on `PATH` |
| `solc` | Resolved automatically: Foundry's local `svm` cache is preferred, otherwise `py-solc-x` installs the version the contract pragma requires (the first use may download a binary) |
| `git` | Only needed if you install Foundry via `foundryup` |

**Foundry is mandatory.** The exploitability stage compiles the generated Foundry test and executes it
with `forge test`. `forge-std` itself does **not** need to be fetched: a minimal vendored subset is
injected into each throwaway workspace and exposed through a `forge-std/=std/` remapping, so the PoC
stage does not reach the network.

Verify both prerequisites before continuing:

```bash
python --version      # 3.14 or newer
forge --version       # must print a version, not "command not found"
```

Install Foundry (if needed):

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

---

## Installation

```bash
uv sync                      # creates .venv and installs pinned dependencies
uv run python -c "import deficoser; print(deficoser.__version__)"
```

Optional — semantic retrieval backend:

```bash
uv pip install fastembed
```

The memory module has two retrieval backends. With `fastembed` installed and its model cached, patterns
are retrieved by sentence embeddings. Otherwise it automatically falls back to a deterministic pure-Python
character-3-gram TF-IDF scorer. The fallback is a supported configuration, not an error: a log line
about a missing model archive is expected when `fastembed` is absent. Network access is never used to
download the model unless you pass `allow_download=True` explicitly.

---

## Configuration

The LLM endpoint is resolved from three sources, in decreasing priority:

1. explicit arguments (`load_llm_settings(base_url=..., api_key=..., model=...)`)
2. environment variables — `DEFICOSER_BASE_URL`, `DEFICOSER_API_KEY`, `DEFICOSER_MODEL`
3. the file `API-KEY.txt` at the repository root

`API-KEY.txt` is **not** shipped and must be created by you. Its first line is free-form descriptive
text; the following lines are `KEY=VALUE` pairs:

```text
openai-compatible endpoint
BASE_URL=https://<your-endpoint>/v1
API_KEY=<your-api-key>
MODEL=deepseek-v4-flash
```

The three keys must all resolve, or `load_llm_settings()` raises `ValueError`.

**Model allow-list.** `config.validate_model()` accepts only the six identifiers used in the evaluation:

```text
deepseek-v4-flash  deepseek-v4-pro  minimax-m3  kimi-k2.7-code  glm-5.3  glm-5.3-flash
```

To run against any other OpenAI-compatible model, extend `config.MODELS` accordingly. Environment
variables override the file, which is convenient for switching keys without editing anything:

```bash
export DEFICOSER_API_KEY=<your-api-key>
export DEFICOSER_MODEL=deepseek-v4-flash
export DEFICOSER_BASE_URL=https://<your-endpoint>/v1
```

### Runtime configuration files

| Path | Purpose |
|---|---|
| `config/role_mapping.json` | Maps modifier and state-variable names (`onlyOwner`, `DEFAULT_ADMIN_ROLE`, …) to normalized role names |
| `config/sink_keywords.json` | Whitelists of sensitive function-name keywords used for sink detection |
| `prompts/<stage>.txt` | One template per LLM stage. Templates are plain single files loaded by `config.load_prompt(stage)` |

---

## Quickstart

Run the pipeline on a directory of Solidity sources with the bundled CLI:

```bash
uv run python run_contract.py --contract-dir path/to/victim/contract
```

The runner scans the directory recursively for `.sol` files, resolves the LLM
endpoint from [Configuration](#configuration), executes the full detection and
PoC-validation graph, and writes three artifacts under `logs/`:

```text
logs/cases.jsonl                 one JSON row per case: verdict, impact, token/time accounting
logs/<case_id>_report.json       the detection report and the PoC-verification report
logs/<case_id>_final_state.json  the full final graph state (for debugging)
```

Useful options:

| Option | Purpose |
|---|---|
| `--case-id` | Case identifier in the log; defaults to the contract directory name |
| `--dataset` / `--config` | Free-form labels recorded in the case log |
| `--memory-mode` | `none` (default), `frozen`, or `streaming` attack-pattern memory |
| `--snapshot` | Snapshot file to preload with `--memory-mode frozen` |
| `--backend` | `auto` (default), `fastembed`, or `tfidf` retrieval backend |
| `--model` | Override the model resolved from `API-KEY.txt` / the environment |
| `--logs-dir` | Output directory; defaults to `logs/` |

Example — replay a frozen memory snapshot over a custom contract:

```bash
uv run python run_contract.py \
  --contract-dir path/to/victim/contract \
  --case-id case_042 \
  --memory-mode frozen \
  --snapshot memory_store/snapshot_60cases.json
```

Exit codes: `0` success, `1` pipeline failure mid-run (still journaled), `2`
argument / setup error (missing contract directory, no `.sol` files, missing
LLM configuration, unreadable snapshot).

For programmatic use, `build_graph()` takes four optional collaborators, all
injectable so the pipeline can be tested without network or toolchain access —
`run_contract.py` is a complete working example of wiring them by hand:

| Argument | Purpose |
|---|---|
| `llm_client` | OpenAI-compatible client; omit only if every LLM-dependent node is bypassed |
| `journal` | `CaseJournal` instance receiving per-stage token/time accounting |
| `memory` | `AttackPatternMemory` instance, or `None` for no memory |
| `runner` | `FoundryRunner`; defaults to the standard `forge` binary |
| `timeout` | Per-`forge test` timeout in seconds |

---

## Data layout

`deficoser.memory.learning.load_learning_cases()` reads a dataset from `dataset/` at the repository root.
The layout it expects:

```
dataset/
  AC_dataset.xlsx            one row per historical incident
  Contract/<protocol>/       victim contract sources (*.sol), matched by protocol name
  Event_data/
    _tx_folder_map.json      optional: transaction hash -> event folder
    <event folder>/
      Event.xlsx             structured event log
      event.txt              human-readable timeline
```

Rows in `AC_dataset.xlsx` provide the protocol name, chain, date, loss, transaction hash, and the
vulnerable function list. Rows marked as unverified are skipped. Each case is assigned a sequential
`case_id` (`event_001`, `event_002`, …) in ascending date order.

To run on your own contracts you do not need this dataset at all — construct `contract_sources`
directly as shown in the quickstart.

---

## Pipeline

Nine domain nodes, wired by `graph.build_graph()`:

| Node | Role |
|---|---|
| `contract_parser` | Resolves the `solc` version, compiles, runs Slither (with an AST-based fallback), and produces the contract profile: functions, sensitive sinks, invariants, key roles |
| `role_analyzer` | Builds the Role Space: explicit roles (modifiers, `msg.sender` guards, `hasRole` constants), implicit roles, and a predefined set of adversarial personas |
| `role_graph_builder` | Builds the Role Capability Graph and derives each function's authorization predicate |
| `adversarial_explorer` | Enumerates candidate unauthorized-access paths and adjudicates each one with the LLM |
| `attack_planner` | Produces a role-conditioned attack blueprint for the selected candidate |
| `poc_generator` | Generates the attack contract and Foundry test |
| `foundry_executor` | Compiles and runs the test in an isolated temporary workspace |
| `dual_oracle` | Deterministic verdict: an authorization oracle and an impact oracle over the collected evidence |
| `done` | Assembles the detection report and the PoC-verification report |

Plus three transition nodes (`retry_poc`, `advance`, `record_result`) that control candidate retry and
advancement when a candidate does not pass the dual oracle. The graph stops early on a fatal parse error
or when no candidate violation remains to be tested.

---

## Outputs

| Path | Contents |
|---|---|
| `logs/cases.jsonl` | One JSON object per case: identifiers, configuration, detection verdict, violation list, impact, per-stage token and latency accounting, and the full `llm_config` |
| `logs/<case_id>_report.json` | The two narrative reports produced by the `done` node |
| `memory_store/patterns.jsonl` | Append-only attack-pattern store, when the memory module is used |
| `memory_store/snapshot_<N>cases.json` | Point-in-time snapshot of the pattern store |

---

## Reproducibility

LLM calls are centralized in `deficoser/llm/client.py` with fixed sampling parameters — `temperature=0`,
`top_p=1`, `seed=0`, and a per-stage `max_tokens` ceiling — plus JSON-Schema structured output and
retries on unparseable responses. All tunable parameters live in `deficoser/config.py`; none are meant
to be overridden silently. `llm_config()` records the model, sampling parameters, and call date into
every case log so a run can be described exactly.

The dual oracle is fully deterministic and performs no LLM calls: it reads the evidence events emitted
by the generated test and applies fixed predicates.

---

## Notes and limitations

- `contract_parser` calls Slither through a `python -m` subprocess with a timeout. When Slither is
  unavailable or fails, the node degrades to a direct `solc` AST extraction instead of aborting.
- `solc` versions below `0.4.11` cannot be installed automatically by `py-solc-x` and are rejected with a
  structured error.
- The explorer and planner are the only LLM-dependent stages that consume memory; retrieval is skipped
  entirely when the memory mode is `none`.
- Pattern retrieval prefers embeddings when `fastembed` is present and degrades to deterministic TF-IDF
  scoring otherwise, so retrieval is reproducible without any model download.
