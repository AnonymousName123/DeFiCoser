from __future__ import annotations
import json
import shutil
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Callable
from deficoser.tools.ast_extractor import build_import_graph, extract_from_asts
from deficoser.config import load_prompt
from deficoser.llm.client import LLMParseError
from deficoser.llm.schemas import SEMANTICS_SCHEMA, get_stage_schema
from deficoser.state import DeFiState
from deficoser.tools.sink_detector import detect_sinks
from deficoser.tools.slither_runner import run_slither
from deficoser.tools.solc_manager import SolcManagerError, compile_sources, ensure_solc, parse_pragmas, resolve_solc_version
NODE_NAME = 'contract_parser'
PROFILE_KEYS: tuple[str, ...] = ('files', 'solc_version', 'analysis_source', 'functions', 'state_vars', 'modifiers', 'inheritance', 'call_graph', 'protected_functions', 'gov_functions', 'pause_functions', 'sinks', 'sensitive_states', 'invariants', 'business_semantics', 'import_graph')
_MAX_PROFILE_JSON_CHARS = 48000
_MAX_SOURCES_CHARS = 96000
_EMPTY_SEMANTICS: dict = {'business_type': 'unknown', 'summary': '', 'function_intents': [], 'key_roles': []}

def _generic_invariants(analysis: dict) -> list[dict]:
    interface_like = {c['name'] for c in analysis.get('contracts', []) if c.get('kind') in ('interface', 'library')}
    names = {f.get('name', '') for f in analysis.get('functions', []) if f.get('contract') not in interface_like}
    state_vars = analysis.get('state_vars', [])
    invariants: list[dict] = []
    if {'totalSupply', 'balanceOf'} <= names and {'transfer', 'transferFrom'} & names:
        invariants.append({'name': 'token_conservation', 'expression': 'totalSupply() == sum(balanceOf(account) for all accounts)', 'source': 'generic'})
        invariants.append({'name': 'balance_nonnegative', 'expression': 'balanceOf(account) >= 0 for all accounts', 'source': 'generic'})
        if 'allowance' in names:
            invariants.append({'name': 'allowance_nonnegative', 'expression': 'allowance(owner, spender) >= 0 for all pairs', 'source': 'generic'})
    else:
        invariants.append({'name': 'solvency', 'expression': 'the total value of underlying assets held by the contract is >= the total user liabilities (solvency invariant)', 'source': 'generic'})
    if any((v.get('name') == 'owner' for v in state_vars)):
        invariants.append({'name': 'ownership_exclusive', 'expression': 'there is at most one owner address at any time', 'source': 'generic'})
    return invariants

def _split_prompt(content: str) -> tuple[str, str]:
    system = content
    user = ''
    if '[INPUT]' in content:
        system, rest = content.split('[INPUT]', 1)
        if '[OUTPUT]' in rest:
            user, output_part = rest.split('[OUTPUT]', 1)
            system = system + '[OUTPUT]' + output_part
        else:
            user = rest
    return (system.strip(), user.strip())

def _cap(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + '\n... (truncated)'

def _static_profile_json(analysis: dict) -> str:
    summary = {'contracts': analysis.get('contracts', []), 'functions': [{'fqn': f['fqn'], 'visibility': f['visibility'], 'modifiers': f['modifiers'], 'state_reads': f['state_reads'], 'state_writes': f['state_writes']} for f in analysis.get('functions', [])], 'state_vars': [{k: v[k] for k in ('name', 'contract', 'type', 'visibility')} for v in analysis.get('state_vars', [])], 'modifiers': [{'name': m['name'], 'contract': m['contract'], 'used_by': m.get('used_by', [])} for m in analysis.get('modifiers', [])], 'inheritance': analysis.get('inheritance', {})}
    return _cap(json.dumps(summary, ensure_ascii=False), _MAX_PROFILE_JSON_CHARS)

def _call_llm_safe(llm_client: Any, stage: str, messages: list[dict], schema: dict) -> tuple[dict | None, str]:
    try:
        return (llm_client.call(stage, messages, schema=schema), '')
    except LLMParseError as exc:
        return (None, f'LLM parsing failed (retries={exc.retries}): {exc.last_error}')
    except Exception as exc:
        return (None, f'{type(exc).__name__}: {exc}')

def _format_template(content: str, variables: dict[str, str]) -> str:
    text = content
    for key, value in variables.items():
        text = text.replace('{{' + key + '}}', value)
    return text

def contract_parser_node(state: DeFiState, *, llm_client: Any=None, journal: Any=None) -> dict:
    started = time.perf_counter()
    sources: dict[str, str] = state.get('contract_sources') or {}
    if not sources:
        return _failed('input state is missing contract_sources', started, journal)
    try:
        pragmas = parse_pragmas(sources)
        solc_version = resolve_solc_version(pragmas)
    except SolcManagerError as exc:
        return _failed(f'solc version resolution failed: {exc}', started, journal)
    try:
        solc_path = ensure_solc(solc_version)
    except SolcManagerError as exc:
        return _failed(f'solc preparation failed: {exc}', started, journal)
    work_dir = Path(tempfile.mkdtemp(prefix='deficoser_m2_'))
    try:
        compilation = compile_sources(sources, solc_version, work_dir=work_dir, solc_path=solc_path)
        if not compilation.get('success'):
            first_error = (compilation.get('errors') or ['unknown compilation error'])[0]
            return _failed(f'compilation failed (solc {solc_version}): {first_error}', started, journal)
        slither_result = run_slither(work_dir, solc_path)
        if slither_result.get('success'):
            analysis_source = 'slither'
            analysis = slither_result
        else:
            analysis_source = 'ast_fallback'
            analysis = extract_from_asts(compilation, sources)
        sink_result = detect_sinks(analysis.get('functions', []), analysis.get('state_vars', []))
        protected_functions = [f['fqn'] for f in analysis.get('functions', []) if f.get('modifiers') or f.get('has_msg_sender_check')]
        llm_semantics_error = ''
        llm_invariants_error = ''
        business_semantics: dict = dict(_EMPTY_SEMANTICS)
        contract_invariants: list[dict] = []
        if llm_client is not None:
            records_before = len(getattr(llm_client, 'usage_records', []))
            profile_json = _static_profile_json(analysis)
            semantics_template = load_prompt('contract_understanding')
            system, user = _split_prompt(semantics_template.content)
            user = _format_template(user, {'static_profile': profile_json, 'json_schema': json.dumps(SEMANTICS_SCHEMA, ensure_ascii=False)})
            semantics_messages = [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}]
            invariant_template = load_prompt('invariant_extraction')
            system, user = _split_prompt(invariant_template.content)
            sources_text = _cap('\n\n'.join((f'// file: {name}\n{content}' for name, content in sorted(sources.items()))), _MAX_SOURCES_CHARS)
            user = _format_template(user, {'contract_sources': sources_text, 'static_profile': profile_json, 'json_schema': json.dumps(get_stage_schema('invariant_extraction'), ensure_ascii=False)})
            invariant_messages = [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}]
            with ThreadPoolExecutor(max_workers=2) as pool:
                semantics_future = pool.submit(_call_llm_safe, llm_client, 'contract_understanding', semantics_messages, SEMANTICS_SCHEMA)
                invariant_future = pool.submit(_call_llm_safe, llm_client, 'invariant_extraction', invariant_messages, get_stage_schema('invariant_extraction'))
                semantics, llm_semantics_error = semantics_future.result()
                invariant_payload, llm_invariants_error = invariant_future.result()
            if semantics is not None:
                business_semantics = {**_EMPTY_SEMANTICS, **semantics}
            if invariant_payload is not None:
                contract_invariants = list(invariant_payload.get('invariants') or [])
            new_records = getattr(llm_client, 'usage_records', [])[records_before:]
            llm_tokens = sum((r.total_tokens for r in new_records))
        else:
            llm_tokens = 0
        invariants = {'generic': _generic_invariants(analysis), 'contract': contract_invariants, 'filtered': False}
        profile: dict = {'files': sorted(sources), 'solc_version': solc_version, 'analysis_source': analysis_source, 'functions': analysis.get('functions', []), 'state_vars': analysis.get('state_vars', []), 'modifiers': analysis.get('modifiers', []), 'inheritance': analysis.get('inheritance', {}), 'call_graph': analysis.get('call_graph', []), 'protected_functions': protected_functions, 'gov_functions': sink_result['gov_functions'], 'pause_functions': sink_result['pause_functions'], 'sinks': sink_result['sinks'], 'sensitive_states': sink_result['sensitive_states'], 'invariants': invariants, 'business_semantics': business_semantics, 'import_graph': build_import_graph(sources)}
        if llm_semantics_error or llm_invariants_error:
            notes = [n for n in (llm_semantics_error, llm_invariants_error) if n]
            profile['business_semantics'] = {**business_semantics, 'summary': (business_semantics.get('summary', '') + f' [LLM fallback: {notes}]').strip()}
        assert set(profile) == set(PROFILE_KEYS)
        elapsed_ms = (time.perf_counter() - started) * 1000
        if journal is not None:
            journal.add_stage_usage('contract_understanding', llm_tokens, elapsed_ms)
        return {'contract_profile': profile, 'sensitive_sinks': [s['function_fqn'] for s in sink_result['sinks']]}
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

def _failed(message: str, started: float, journal: Any) -> dict:
    if journal is not None:
        elapsed_ms = (time.perf_counter() - started) * 1000
        journal.add_stage_usage('contract_understanding', 0, elapsed_ms)
    return {'error': {'node': NODE_NAME, 'message': message, 'fatal': True}, 'contract_profile': None, 'sensitive_sinks': []}

def make_contract_parser_node(llm_client: Any=None, journal: Any=None) -> Callable[[DeFiState], dict]:

    def _node(state: DeFiState) -> dict:
        return contract_parser_node(state, llm_client=llm_client, journal=journal)
    return _node
