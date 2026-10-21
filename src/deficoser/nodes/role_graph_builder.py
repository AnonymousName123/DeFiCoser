from __future__ import annotations
import time
from typing import Any, Callable
from deficoser.state import DeFiState
from deficoser.tools.predicate_extractor import extract_predicates
from deficoser.tools.rcg_builder import build_rcg
NODE_NAME = 'role_graph_builder'

def role_graph_builder_node(state: DeFiState, *, journal: Any=None) -> dict:
    started = time.perf_counter()
    profile = state.get('contract_profile')
    roles = state.get('roles')
    if not profile or roles is None:
        if journal is not None:
            journal.add_stage_usage('role_graph', 0, (time.perf_counter() - started) * 1000)
        return {'error': {'node': NODE_NAME, 'message': 'input state is missing contract_profile or roles', 'fatal': True}, 'role_graph': None, 'permission_predicates': [], 'authorized': {}}
    sources = state.get('contract_sources') or {}
    predicates = extract_predicates(profile, sources, roles)
    _graph, serialized = build_rcg(roles, profile, authorized=predicates['authorized'])
    if journal is not None:
        journal.add_stage_usage('role_graph', 0, (time.perf_counter() - started) * 1000)
    return {'role_graph': serialized, 'permission_predicates': predicates['permission_predicates'], 'authorized': predicates['authorized']}

def make_role_graph_builder_node(journal: Any=None) -> Callable[[DeFiState], dict]:

    def _node(state: DeFiState) -> dict:
        return role_graph_builder_node(state, journal=journal)
    return _node
