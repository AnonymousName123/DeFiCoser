from __future__ import annotations
import json
import time
from typing import Any, Callable
from deficoser.config import load_prompt
from deficoser.llm.schemas import get_stage_schema
from deficoser.nodes.contract_parser import _call_llm_safe, _cap, _format_template, _split_prompt
from deficoser.state import DeFiState
from deficoser.tools.role_extractor import extract_explicit_roles
NODE_NAME = 'role_analyzer'
_MAX_FUNCTION_LIST_CHARS = 24000
_MAX_MODIFIER_CHARS = 16000
ADVERSARIAL_ROLES: list[dict] = [{'id': 'eoa', 'privileges': [], 'state': 'unrestricted', 'capabilities': ['external_call'], 'source': 'adversarial'}, {'id': 'unauthorized_user', 'privileges': [], 'state': 'unauthenticated', 'capabilities': ['external_call'], 'source': 'adversarial'}, {'id': 'malicious_contract', 'privileges': [], 'state': 'deployed', 'capabilities': ['external_call', 'callback'], 'source': 'adversarial'}, {'id': 'callback_contract', 'privileges': [], 'state': 'deployed', 'capabilities': ['callback', 'reentrancy'], 'source': 'adversarial'}, {'id': 'flash_loan_attacker', 'privileges': [], 'state': 'unbounded_capital', 'capabilities': ['external_call', 'flash_loan'], 'source': 'adversarial'}, {'id': 'token_holder', 'privileges': [], 'state': 'holding_tokens', 'capabilities': ['external_call', 'token_transfer'], 'source': 'adversarial'}, {'id': 'newly_deployed_user', 'privileges': [], 'state': 'uninitialized', 'capabilities': ['external_call', 'uninitialized'], 'source': 'adversarial'}, {'id': 'delegate_caller', 'privileges': [], 'state': 'deployed', 'capabilities': ['delegatecall'], 'source': 'adversarial'}, {'id': 'cross_protocol_attacker', 'privileges': [], 'state': 'cross_protocol', 'capabilities': ['external_call', 'cross_protocol'], 'source': 'adversarial'}]

def _function_list_json(profile: dict) -> str:
    summary = [{'fqn': f.get('fqn'), 'visibility': f.get('visibility'), 'modifiers': f.get('modifiers'), 'has_msg_sender_check': f.get('has_msg_sender_check')} for f in profile.get('functions', [])]
    return _cap(json.dumps(summary, ensure_ascii=False), _MAX_FUNCTION_LIST_CHARS)

def _modifier_sources_json(profile: dict) -> str:
    summary = [{'name': m.get('name'), 'contract': m.get('contract'), 'source_text': _cap(m.get('source_text', ''), 600), 'used_by': m.get('used_by')} for m in profile.get('modifiers', [])]
    return _cap(json.dumps(summary, ensure_ascii=False), _MAX_MODIFIER_CHARS)

def _normalize_implicit_roles(payload: dict, explicit_ids: set[str]) -> list[dict]:
    roles: list[dict] = []
    for raw in payload.get('roles') or []:
        if not isinstance(raw, dict):
            continue
        role_id = str(raw.get('id') or '').strip()
        if not role_id or role_id in explicit_ids:
            continue
        roles.append({'id': role_id, 'privileges': [str(p) for p in raw.get('privileges') or []], 'state': str(raw.get('state') or ''), 'capabilities': [str(c) for c in raw.get('capabilities') or []], 'source': 'implicit', 'evidence': [e for e in raw.get('evidence') or [] if isinstance(e, dict)]})
    return roles

def role_analyzer_node(state: DeFiState, *, llm_client: Any=None, journal: Any=None) -> dict:
    started = time.perf_counter()
    profile = state.get('contract_profile')
    if not profile:
        if journal is not None:
            journal.add_stage_usage('role_extraction', 0, (time.perf_counter() - started) * 1000)
        return {'error': {'node': NODE_NAME, 'message': 'input state is missing contract_profile', 'fatal': True}, 'roles': []}
    sources = state.get('contract_sources') or {}
    explicit_roles = extract_explicit_roles(profile, sources)
    implicit_roles: list[dict] = []
    llm_tokens = 0
    if llm_client is not None:
        records_before = len(getattr(llm_client, 'usage_records', []))
        template = load_prompt('role_extraction')
        system, user = _split_prompt(template.content)
        user = _format_template(user, {'function_list': _function_list_json(profile), 'modifier_sources': _modifier_sources_json(profile), 'key_roles': _cap(json.dumps(profile.get('business_semantics', {}).get('key_roles') or [], ensure_ascii=False), 4000), 'explicit_roles': _cap(json.dumps([{'id': r['id'], 'state': r['state']} for r in explicit_roles], ensure_ascii=False), 4000), 'json_schema': json.dumps(get_stage_schema('role_extraction'), ensure_ascii=False)})
        payload, _error = _call_llm_safe(llm_client, 'role_extraction', [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}], get_stage_schema('role_extraction'))
        if payload is not None:
            implicit_roles = _normalize_implicit_roles(payload, {r['id'] for r in explicit_roles})
        new_records = getattr(llm_client, 'usage_records', [])[records_before:]
        llm_tokens = sum((r.total_tokens for r in new_records))
    roles: list[dict] = []
    seen: set[str] = set()
    for role in [*explicit_roles, *implicit_roles, *ADVERSARIAL_ROLES]:
        if role['id'] in seen:
            continue
        seen.add(role['id'])
        roles.append(role)
    if journal is not None:
        journal.add_stage_usage('role_extraction', llm_tokens, (time.perf_counter() - started) * 1000)
    return {'roles': roles}

def make_role_analyzer_node(llm_client: Any=None, journal: Any=None) -> Callable[[DeFiState], dict]:

    def _node(state: DeFiState) -> dict:
        return role_analyzer_node(state, llm_client=llm_client, journal=journal)
    return _node
