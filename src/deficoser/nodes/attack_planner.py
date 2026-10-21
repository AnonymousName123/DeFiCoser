from __future__ import annotations
import json
import time
from typing import Any, Callable
from deficoser.config import load_prompt
from deficoser.llm.client import LLMParseError
from deficoser.llm.schemas import BLUEPRINT_SCHEMA
from deficoser.nodes.contract_parser import _call_llm_safe, _cap, _format_template, _split_prompt
from deficoser.state import DeFiState
from deficoser.tools.function_text import extract_function_text
NODE_NAME = 'attack_planner'
_MAX_PROFILE_CHARS = 6000
_MAX_SOURCES_CHARS = 16000

def _violation_view(violation: dict) -> str:
    keys = ('sink', 'attacker_role', 'required_role', 'predicate', 'path', 'path_edges', 'location', 'exploit_method')
    return json.dumps({k: violation.get(k) for k in keys}, ensure_ascii=False, indent=1)

def _function_sources_text(violation: dict, profile: dict, sources: dict[str, str]) -> str:
    functions = {f.get('fqn'): f for f in profile.get('functions', []) if f.get('fqn')}
    modifiers = profile.get('modifiers') or []
    wanted: list[str] = []
    for node in violation.get('path') or []:
        if isinstance(node, str) and node.startswith('function:'):
            fqn = node[len('function:'):]
            if fqn not in wanted:
                wanted.append(fqn)
    sink_fqn = violation.get('sink')
    if sink_fqn and sink_fqn not in wanted:
        wanted.append(sink_fqn)
    snippets: list[str] = []
    for fqn in wanted:
        function = functions.get(fqn)
        if function is None:
            continue
        text = extract_function_text(sources, function) or f'// {fqn} (source location failed)'
        parts = [f'// function: {fqn}\n{_cap(text, 2000)}']
        for mod_name in function.get('modifiers') or []:
            modifier = next((m for m in modifiers if m.get('name') == mod_name), None)
            if modifier is not None and modifier.get('source_text'):
                parts.append(f"// modifier {mod_name}: {_cap(modifier['source_text'], 600)}")
        snippets.append('\n'.join(parts))
        if sum((len(s) for s in snippets)) > _MAX_SOURCES_CHARS:
            break
    return _cap('\n\n'.join(snippets), _MAX_SOURCES_CHARS) or '(no source snippets)'

def _profile_summary(profile: dict) -> str:
    semantics = profile.get('business_semantics') or {}
    invariants = profile.get('invariants') or {}
    summary = {'solc_version': profile.get('solc_version'), 'business_type': semantics.get('business_type'), 'business_summary': semantics.get('summary'), 'gov_functions': profile.get('gov_functions'), 'pause_functions': profile.get('pause_functions'), 'invariants_generic': [i.get('name') for i in invariants.get('generic') or [] if i.get('name')], 'invariants_contract': [i.get('name') for i in invariants.get('contract') or [] if i.get('name')]}
    return _cap(json.dumps(summary, ensure_ascii=False), _MAX_PROFILE_CHARS)

def attack_planner_node(state: DeFiState, *, llm_client: Any=None, journal: Any=None, retrieved_patterns: list[dict] | None=None) -> dict:
    started = time.perf_counter()
    violation = state.get('current_violation')
    if not violation:
        if journal is not None:
            journal.add_stage_usage('attack_plan', 0, (time.perf_counter() - started) * 1000)
        return {'error': {'node': NODE_NAME, 'message': 'input state is missing current_violation (no candidate violation to plan)', 'fatal': True}, 'attack_blueprints': []}
    if llm_client is None:
        if journal is not None:
            journal.add_stage_usage('attack_plan', 0, (time.perf_counter() - started) * 1000)
        return {'error': {'node': NODE_NAME, 'message': 'attack_planner requires an LLM (llm_client not injected)', 'fatal': True}, 'attack_blueprints': []}
    profile = state.get('contract_profile') or {}
    sources = state.get('contract_sources') or {}
    patterns = list(retrieved_patterns) if retrieved_patterns is not None else list(state.get('retrieved_patterns') or [])
    feedback = state.get('poc_feedback') or ''
    template = load_prompt('attack_plan')
    system, user = _split_prompt(template.content)
    user = _format_template(user, {'violation': _violation_view(violation), 'function_sources': _function_sources_text(violation, profile, sources), 'contract_profile': _profile_summary(profile), 'retrieved_patterns': json.dumps(patterns, ensure_ascii=False) if patterns else ' (none)', 'poc_feedback': feedback or ' (none; first-round generation)', 'json_schema': json.dumps(BLUEPRINT_SCHEMA, ensure_ascii=False)})
    records_before = len(getattr(llm_client, 'usage_records', []))
    blueprint, error = _call_llm_safe(llm_client, 'attack_plan', [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}], BLUEPRINT_SCHEMA)
    new_records = getattr(llm_client, 'usage_records', [])[records_before:]
    llm_tokens = sum((r.total_tokens for r in new_records))
    if journal is not None:
        journal.add_stage_usage('attack_plan', llm_tokens, (time.perf_counter() - started) * 1000)
    if blueprint is None:
        return {'error': {'node': NODE_NAME, 'message': error, 'fatal': False}, 'attack_blueprints': []}
    return {'attack_blueprints': [blueprint]}

def make_attack_planner_node(llm_client: Any=None, journal: Any=None, retrieved_patterns: list[dict] | None=None) -> Callable[[DeFiState], dict]:

    def _node(state: DeFiState) -> dict:
        return attack_planner_node(state, llm_client=llm_client, journal=journal, retrieved_patterns=retrieved_patterns)
    return _node
