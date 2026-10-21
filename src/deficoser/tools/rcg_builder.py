from __future__ import annotations
import re
import networkx as nx
from deficoser.tools.predicate_extractor import _resolve_modifier
_CALLABLE_VISIBILITIES = frozenset({'public', 'external', 'default'})
_DELEGATE_NAME_RE = re.compile('delegatecall', re.IGNORECASE)
_PROXY_NAME_RE = re.compile('upgradeto|upgradeandcall|setimplementation|proxy', re.IGNORECASE)

def role_node_id(role_id: str) -> str:
    return f'role:{role_id}'

def function_node_id(fqn: str) -> str:
    return f'function:{fqn}'

def state_node_id(name: str) -> str:
    return f'state:{name}'

def _is_delegate_like(function: dict) -> bool:
    if _DELEGATE_NAME_RE.search(function.get('name') or ''):
        return True
    for call in function.get('external_calls') or []:
        if _DELEGATE_NAME_RE.search(str(call.get('name', ''))):
            return True
    return False

def _is_proxy_like(function: dict) -> bool:
    return bool(_PROXY_NAME_RE.search(function.get('name') or ''))

def build_rcg(roles: list[dict], profile: dict, authorized: dict[str, list[str]] | None=None) -> tuple[nx.MultiDiGraph, dict]:
    functions = [f for f in profile.get('functions', []) if f.get('fqn')]
    functions_by_fqn = {f['fqn']: f for f in functions}
    modifiers = profile.get('modifiers', [])
    authorized = authorized or {}
    graph = nx.MultiDiGraph()
    for role in roles:
        role_id = role.get('id') or ''
        if role_id:
            graph.add_node(role_node_id(role_id), kind='role', id=role_id, label=role_id)
    for function in functions:
        graph.add_node(function_node_id(function['fqn']), kind='function', id=function['fqn'], label=function.get('name') or function['fqn'])
    for var in profile.get('state_vars', []):
        name = var.get('name') or ''
        if name:
            graph.add_node(state_node_id(name), kind='state', id=name, label=name)
    role_nodes = sorted((n for n, d in graph.nodes(data=True) if d['kind'] == 'role'))
    adversarial_nodes = sorted((role_node_id(r['id']) for r in roles if r.get('source') == 'adversarial' and r.get('id')))
    callable_functions = [f for f in functions if f.get('visibility') in _CALLABLE_VISIBILITIES and f.get('name') != 'constructor']
    for role_node in role_nodes:
        for function in callable_functions:
            graph.add_edge(role_node, function_node_id(function['fqn']), type='can-call')
    for fqn, role_ids in sorted(authorized.items()):
        if fqn not in functions_by_fqn:
            continue
        for role_id in sorted(role_ids):
            role_node = role_node_id(role_id)
            if role_node in graph:
                graph.add_edge(role_node, function_node_id(fqn), type='can-call', via='authorized')
    for function in functions:
        if function.get('name') == 'constructor':
            continue
        semantic = None
        if _is_delegate_like(function):
            semantic = 'delegate'
        elif _is_proxy_like(function):
            semantic = 'proxy'
        if semantic:
            for role_node in adversarial_nodes:
                graph.add_edge(role_node, function_node_id(function['fqn']), type='can-call', semantic=semantic)
    for edge in profile.get('call_graph') or []:
        if not edge.get('external'):
            continue
        caller_node = function_node_id(edge.get('caller_fqn') or '')
        callee_node = function_node_id(edge.get('callee_fqn') or '')
        if caller_node not in graph or callee_node not in graph:
            continue
        for role_node in role_nodes:
            if graph.has_edge(role_node, caller_node):
                graph.add_edge(role_node, callee_node, type='can-call', semantic='cross_contract')
    for function in functions:
        for state in function.get('state_writes') or []:
            state_node = state_node_id(state)
            if state_node in graph:
                graph.add_edge(function_node_id(function['fqn']), state_node, type='changes')
    var_to_roles: dict[str, set[str]] = {}
    for role in roles:
        if role.get('source') == 'adversarial' or not role.get('id'):
            continue
        state_var = role.get('state') or ''
        if state_var:
            var_to_roles.setdefault(state_var, set()).add(role['id'])
    for function in functions:
        for state in function.get('state_writes') or []:
            for role_id in sorted(var_to_roles.get(state, set())):
                graph.add_edge(function_node_id(function['fqn']), role_node_id(role_id), type='grants')
    for fqn in profile.get('protected_functions') or []:
        function = functions_by_fqn.get(fqn)
        if function is None:
            continue
        read_states = set(function.get('state_reads') or [])
        for mod_name in function.get('modifiers') or []:
            modifier = _resolve_modifier(mod_name, function.get('contract', ''), modifiers)
            if modifier is not None:
                read_states.update(modifier.get('referenced_vars') or [])
        for state in sorted(read_states):
            state_node = state_node_id(state)
            if state_node in graph:
                graph.add_edge(state_node, function_node_id(fqn), type='enables')
    return (graph, serialize_rcg(graph))

def serialize_rcg(graph: nx.MultiDiGraph) -> dict:
    nodes = [{'kind': data['kind'], 'id': data['id'], 'label': data.get('label', data['id'])} for _, data in graph.nodes(data=True)]
    nodes.sort(key=lambda n: (n['kind'], n['id']))
    edges = []
    for u, v, data in graph.edges(data=True):
        entry = {'from': u, 'to': v, 'type': data.get('type', '')}
        if data.get('semantic'):
            entry['semantic'] = data['semantic']
        if data.get('via'):
            entry['via'] = data['via']
        edges.append(entry)
    edges.sort(key=lambda e: (e['from'], e['to'], e['type'], e.get('semantic', ''), e.get('via', '')))
    return {'nodes': nodes, 'edges': edges}

def load_rcg(data: dict) -> nx.MultiDiGraph:
    graph = nx.MultiDiGraph()
    for node in data.get('nodes', []):
        graph.add_node(f"{node['kind']}:{node['id']}", kind=node['kind'], id=node['id'], label=node.get('label', node['id']))
    for edge in data.get('edges', []):
        attrs = {'type': edge.get('type', '')}
        if edge.get('semantic'):
            attrs['semantic'] = edge['semantic']
        if edge.get('via'):
            attrs['via'] = edge['via']
        if edge['from'] in graph and edge['to'] in graph:
            graph.add_edge(edge['from'], edge['to'], **attrs)
    return graph
