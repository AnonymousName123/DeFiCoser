from __future__ import annotations
import json
import time
from typing import Any, Callable
from deficoser.config import load_prompt
from deficoser.llm.client import _extract_json
from deficoser.nodes.contract_parser import _cap, _format_template, _split_prompt
from deficoser.state import DeFiState
from deficoser.tools.poc_checker import check_poc
NODE_NAME = 'poc_generator'
_MAX_SOURCES_CHARS = 120000
_MAX_FEEDBACK_CHARS = 1500
_MAX_PREV_CODE_CHARS = 4000
_DEFAULT_SOLC = '0.8.28'

def _solc_version(state: DeFiState) -> str:
    profile = state.get('contract_profile') or {}
    return profile.get('solc_version') or _DEFAULT_SOLC

def _sources_text(sources: dict[str, str]) -> str:
    return _cap('\n\n'.join((f'// file: src/{name}\n{content}' for name, content in sorted(sources.items()))), _MAX_SOURCES_CHARS)

def _generation_failure(state: DeFiState, reason: str, journal: Any, started: float, llm_tokens: int=0) -> dict:
    if journal is not None:
        journal.add_stage_usage('poc_generate', llm_tokens, (time.perf_counter() - started) * 1000)
    return {'poc_invalid_reason': reason, 'poc_retry_count': (state.get('poc_retry_count') or 0) + 1, 'attack_contract_code': '', 'foundry_test_code': '', 'poc_files': {}}

def _retry_feedback_messages(state: DeFiState) -> list[dict]:
    retry_count = state.get('poc_retry_count') or 0
    feedback = state.get('poc_feedback') or ''
    if retry_count <= 0 or not feedback.strip():
        return []
    parts = [f'The previous PoC (attempt {retry_count}) did not pass. Failure reason:\n{_cap(feedback, _MAX_FEEDBACK_CHARS)}']
    prev_attack = state.get('attack_contract_code') or ''
    prev_test = state.get('foundry_test_code') or ''
    if prev_attack.strip() or prev_test.strip():
        parts.append(f"Previous attack contract code:\n{_cap(prev_attack, _MAX_PREV_CODE_CHARS) or ' (none)'}")
        parts.append(f"Previous test code:\n{_cap(prev_test, _MAX_PREV_CODE_CHARS) or '(none)'}")
    parts.append('Please fix the issues above while preserving the attack logic blueprint and the Evidence protocol (prioritize fixing compilation errors and static validation violations), and output the complete JSON again.')
    return [{'role': 'user', 'content': '\n\n'.join(parts)}]

def poc_generator_node(state: DeFiState, *, llm_client: Any=None, journal: Any=None) -> dict:
    started = time.perf_counter()
    blueprints = state.get('attack_blueprints') or []
    sources = state.get('contract_sources') or {}
    if not blueprints:
        return _generation_failure(state, 'input state is missing attack_blueprints (no blueprint from which to generate a PoC)', journal, started)
    if not sources:
        return _generation_failure(state, 'input state is missing contract_sources', journal, started)
    if llm_client is None:
        return _generation_failure(state, 'poc_generator requires an LLM (llm_client not injected)', journal, started)
    blueprint = blueprints[0]
    template = load_prompt('poc_generate')
    system, user = _split_prompt(template.content)
    user = _format_template(user, {'attack_blueprint': json.dumps(blueprint, ensure_ascii=False, indent=1), 'contract_sources': _sources_text(sources), 'solc_version': _solc_version(state)})
    messages = [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}] + _retry_feedback_messages(state)
    records_before = len(getattr(llm_client, 'usage_records', []))
    try:
        response = llm_client.call('poc_generate', messages, schema=None)
        content = response.get('content') or ''
    except Exception as exc:
        return _generation_failure(state, f'LLM call failed ({type(exc).__name__}): {exc}', journal, started)
    new_records = getattr(llm_client, 'usage_records', [])[records_before:]
    llm_tokens = sum((r.total_tokens for r in new_records))
    try:
        poc = _extract_json(content)
    except (ValueError, json.JSONDecodeError) as exc:
        return _generation_failure(state, f'PoC output is not valid JSON: {exc}', journal, started, llm_tokens)
    invalid = check_poc(poc)
    if invalid:
        return _generation_failure(state, invalid['poc_invalid_reason'], journal, started, llm_tokens)
    attack = poc['attack_contract']
    test = poc['foundry_test']
    if journal is not None:
        journal.add_stage_usage('poc_generate', llm_tokens, (time.perf_counter() - started) * 1000)
    return {'attack_contract_code': attack['code'], 'foundry_test_code': test['code'], 'poc_files': {attack['filename']: attack['code'], test['filename']: test['code']}, 'poc_invalid_reason': None, 'poc_retry_count': (state.get('poc_retry_count') or 0) + 1}

def make_poc_generator_node(llm_client: Any=None, journal: Any=None) -> Callable[[DeFiState], dict]:

    def _node(state: DeFiState) -> dict:
        return poc_generator_node(state, llm_client=llm_client, journal=journal)
    return _node
