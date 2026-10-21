from __future__ import annotations
import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable
from deficoser.config import EXPLORER_MAX_WORKERS, MAX_CANDIDATES_GLOBAL, MAX_CANDIDATES_PER_TARGET, load_prompt
from deficoser.llm.schemas import get_stage_schema
from deficoser.nodes.contract_parser import _call_llm_safe, _cap, _format_template, _split_prompt
from deficoser.state import DeFiState
from deficoser.tools.function_text import extract_function_text
from deficoser.tools.path_enum import all_paths_to_targets
from deficoser.tools.rcg_builder import function_node_id, load_rcg, role_node_id
NODE_NAME = 'adversarial_explorer'
_MAX_FUNCTION_SOURCE_CHARS = 1500
_MAX_FUNCTION_SOURCES_CHARS = 12000
_VIOLATION_QUEUE_KEYS = ('sink', 'attacker_role', 'required_role', 'path', 'location', 'exploit_method')

def _sink_priorities(profile: dict) -> dict[str, tuple[int, str]]:
    priorities: dict[str, tuple[int, str]] = {}
    for sink in profile.get('sinks') or []:
        fqn = sink.get('function_fqn')
        if not fqn:
            continue
        reason = sink.get('reason') or 'propagation'
        priorities[fqn] = (0 if reason == 'keyword' else 1, reason)
    return priorities

def enumerate_candidates(roles: list[dict], graph, profile: dict, predicates: dict, *, max_per_target: int | None=None, max_global: int | None=None) -> tuple[list[dict], int]:
    functions = {f.get('fqn'): f for f in profile.get('functions', []) if f.get('fqn')}
    priorities = _sink_priorities(profile)
    authorized = predicates.get('authorized') or {}
    unknown = set(predicates.get('authorized_unknown') or [])
    predicate_by_fqn = {e.get('function_fqn'): e for e in predicates.get('permission_predicates') or []}
    targets: list[str] = []
    for fqn in list(profile.get('protected_functions') or []) + sorted(priorities):
        if fqn and fqn in functions and (fqn not in targets):
            targets.append(fqn)
    target_nodes = {function_node_id(fqn) for fqn in targets}
    adversarial = [r for r in roles if r.get('source') == 'adversarial' and r.get('id')]
    candidates: list[dict] = []
    for role in sorted(adversarial, key=lambda r: r['id']):
        role_node = role_node_id(role['id'])
        paths_by_target = all_paths_to_targets(graph, role_node, target_nodes)
        for fqn in targets:
            auth_list = [] if fqn in unknown else authorized.get(fqn, [])
            if role['id'] in auth_list:
                continue
            entry = predicate_by_fqn.get(fqn) or {}
            required = entry.get('required_roles') or []
            for path in paths_by_target.get(function_node_id(fqn), []):
                function = functions[fqn]
                candidates.append({'sink': fqn, 'sink_priority': priorities.get(fqn, (2, 'protected'))[0], 'sink_reason': priorities.get(fqn, (2, 'protected'))[1], 'attacker_role': role['id'], 'required_role': required[0] if required else None, 'predicate': entry.get('predicate'), 'path': path['nodes'], 'path_edges': path['edges'], 'path_length': path['length'], 'location': f"{function.get('file', '')}:{function.get('line_number', 0)}" if function.get('file') else None})
    candidates.sort(key=lambda c: (c['sink_priority'], c['path_length'], c['sink'], c['attacker_role'], tuple(c['path'])))
    total = len(candidates)
    kept: list[dict] = []
    per_target_count: dict[str, int] = {}
    for candidate in candidates:
        if max_per_target is not None and per_target_count.get(candidate['sink'], 0) >= max_per_target:
            continue
        if max_global is not None and len(kept) >= max_global:
            continue
        kept.append(candidate)
        per_target_count[candidate['sink']] = per_target_count.get(candidate['sink'], 0) + 1
    return (kept, total - len(kept))

def _function_sources_text(candidate: dict, profile: dict, sources: dict[str, str]) -> str:
    functions = {f.get('fqn'): f for f in profile.get('functions', []) if f.get('fqn')}
    modifiers = profile.get('modifiers', [])
    snippets: list[str] = []
    for node in candidate['path']:
        if not node.startswith('function:'):
            continue
        fqn = node[len('function:'):]
        function = functions.get(fqn)
        if function is None:
            continue
        text = extract_function_text(sources, function) or f'// {fqn} (source location failed)'
        parts = [f'// function: {fqn}\n{_cap(text, _MAX_FUNCTION_SOURCE_CHARS)}']
        for mod_name in function.get('modifiers') or []:
            modifier = next((m for m in modifiers if m.get('name') == mod_name), None)
            if modifier is not None and modifier.get('source_text'):
                parts.append(f"// modifier {mod_name}: {_cap(modifier['source_text'], 400)}")
        snippets.append('\n'.join(parts))
        if sum((len(s) for s in snippets)) > _MAX_FUNCTION_SOURCES_CHARS:
            break
    return _cap('\n\n'.join(snippets), _MAX_FUNCTION_SOURCES_CHARS) or ' (no source snippet)'

def _judge_candidate(llm_client: Any, candidate: dict, profile: dict, sources: dict[str, str], retrieved_patterns: list[dict]) -> dict | None:
    template = load_prompt('adversarial_explore')
    system, user = _split_prompt(template.content)
    path_view = {'sink': candidate['sink'], 'attacker_role': candidate['attacker_role'], 'required_role': candidate['required_role'], 'predicate': candidate['predicate'], 'path': candidate['path'], 'path_edges': candidate['path_edges']}
    user = _format_template(user, {'candidate_path': json.dumps(path_view, ensure_ascii=False, indent=1), 'function_sources': _function_sources_text(candidate, profile, sources), 'predicate': json.dumps({'predicate': candidate['predicate'], 'required_roles': [candidate['required_role']] if candidate['required_role'] else []}, ensure_ascii=False), 'retrieved_patterns': json.dumps(retrieved_patterns, ensure_ascii=False) if retrieved_patterns else '(none)', 'json_schema': json.dumps(get_stage_schema('adversarial_explore'), ensure_ascii=False)})
    payload, _error = _call_llm_safe(llm_client, 'adversarial_explore', [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}], get_stage_schema('adversarial_explore'))
    if payload is None:
        return None
    for verdict in payload.get('violations') or []:
        if not verdict.get('reachable'):
            continue
        violation = {key: candidate.get(key) for key in _VIOLATION_QUEUE_KEYS}
        violation['location'] = verdict.get('location') or candidate.get('location')
        violation['exploit_method'] = verdict.get('exploit_method')
        violation['reasoning'] = verdict.get('reasoning', '')
        violation['reachable'] = True
        violation['path_edges'] = candidate.get('path_edges')
        violation['path_length'] = candidate.get('path_length')
        violation['sink_reason'] = candidate.get('sink_reason')
        violation['predicate'] = candidate.get('predicate')
        return violation
    return None

def adversarial_explorer_node(state: DeFiState, *, llm_client: Any=None, journal: Any=None, retrieved_patterns: list[dict] | None=None) -> dict:
    started = time.perf_counter()
    profile = state.get('contract_profile')
    roles = state.get('roles')
    role_graph = state.get('role_graph')
    if not profile or roles is None or (not role_graph):
        if journal is not None:
            journal.add_stage_usage('adversarial_explore', 0, (time.perf_counter() - started) * 1000)
        return {'error': {'node': NODE_NAME, 'message': 'input state is missing contract_profile / roles / role_graph', 'fatal': True}, 'ac_violations': [], 'violation_index': 0, 'current_violation': None, 'retrieved_patterns': []}
    sources = state.get('contract_sources') or {}
    patterns = list(retrieved_patterns) if retrieved_patterns is not None else list(state.get('retrieved_patterns') or [])
    graph = load_rcg(role_graph)
    predicates = {'permission_predicates': state.get('permission_predicates') or [], 'authorized': state.get('authorized') or {}, 'authorized_unknown': [e.get('function_fqn') for e in state.get('permission_predicates') or [] if e.get('unknown')]}
    candidates, truncated = enumerate_candidates(roles, graph, profile, predicates, max_per_target=MAX_CANDIDATES_PER_TARGET, max_global=MAX_CANDIDATES_GLOBAL)
    llm_tokens = 0
    if llm_client is None:
        violations = [dict(candidate, reachable=True, exploit_method=None) for candidate in candidates]
    else:
        records_before = len(getattr(llm_client, 'usage_records', []))
        with ThreadPoolExecutor(max_workers=EXPLORER_MAX_WORKERS) as pool:
            judged = list(pool.map(lambda candidate: _judge_candidate(llm_client, candidate, profile, sources, patterns), candidates))
        violations = [violation for violation in judged if violation is not None]
        new_records = getattr(llm_client, 'usage_records', [])[records_before:]
        llm_tokens = sum((r.total_tokens for r in new_records))
    violations.sort(key=lambda v: ({'keyword': 0, 'propagation': 1}.get(v.get('sink_reason'), 2), v.get('path_length', 0)))
    if journal is not None:
        journal.add_stage_usage('adversarial_explore', llm_tokens, (time.perf_counter() - started) * 1000)
    return {'ac_violations': violations, 'violation_index': 0, 'current_violation': violations[0] if violations else None, 'retrieved_patterns': patterns, 'exploration_truncated': truncated > 0, 'exploration_truncated_count': truncated}

def make_adversarial_explorer_node(llm_client: Any=None, journal: Any=None, retrieved_patterns: list[dict] | None=None) -> Callable[[DeFiState], dict]:

    def _node(state: DeFiState) -> dict:
        return adversarial_explorer_node(state, llm_client=llm_client, journal=journal, retrieved_patterns=retrieved_patterns)
    return _node
