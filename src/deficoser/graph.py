from __future__ import annotations
from typing import Any, Callable
from langgraph.graph import END, START, StateGraph
from deficoser.config import MAX_POC_CANDIDATES
from deficoser.nodes.adversarial_explorer import adversarial_explorer_node
from deficoser.nodes.attack_planner import attack_planner_node
from deficoser.nodes.contract_parser import make_contract_parser_node
from deficoser.nodes.done import make_done_node
from deficoser.nodes.dual_oracle import make_dual_oracle_node
from deficoser.nodes.foundry_executor import make_foundry_executor_node
from deficoser.nodes.poc_generator import make_poc_generator_node
from deficoser.nodes.role_analyzer import make_role_analyzer_node
from deficoser.nodes.role_graph_builder import make_role_graph_builder_node
from deficoser.state import DeFiState
from deficoser.tools.poc_flow import advance_violation, poc_failure_feedback, record_verified_violation, should_retry_poc

DOMAIN_NODES: tuple[str, ...] = ('contract_parser', 'role_analyzer', 'role_graph_builder', 'adversarial_explorer', 'attack_planner', 'poc_generator', 'foundry_executor', 'dual_oracle', 'done')


def route_after_parser(state: DeFiState) -> str:
    error = state.get('error') or {}
    if isinstance(error, dict) and error.get('fatal'):
        return 'done'
    return 'role_analyzer'


def route_after_explorer(state: DeFiState) -> str:
    if state.get('current_violation') is None:
        return 'done'
    return 'attack_planner'


def route_after_dual_oracle(state: DeFiState) -> str:
    if state.get('exploitability'):
        return 'record_result'
    if should_retry_poc(state):
        return 'retry_poc'
    return 'advance'


def _is_compile_level_failure(state: DeFiState) -> bool:
    if state.get('poc_invalid_reason'):
        return True
    foundry_result = state.get('foundry_result') or {}
    if foundry_result.get('timed_out') or foundry_result.get('compile_errors'):
        return True
    return False


def route_after_retry(state: DeFiState) -> str:
    if not (state.get('attack_blueprints') or []):
        return 'attack_planner'
    if _is_compile_level_failure(state):
        return 'poc_generator'
    return 'attack_planner'


def route_after_advance(state: DeFiState) -> str:
    index = state.get('violation_index') or 0
    if state.get('current_violation') is None or index >= MAX_POC_CANDIDATES:
        return 'done'
    return 'attack_planner'


def route_after_record(state: DeFiState) -> str:
    index = state.get('violation_index') or 0
    if state.get('current_violation') is None or index >= MAX_POC_CANDIDATES:
        return 'done'
    return 'attack_planner'


def _retry_poc_node(state: DeFiState) -> dict:
    return poc_failure_feedback(state)


def _advance_node(state: DeFiState) -> dict:
    return {**advance_violation(state), 'poc_feedback': None}


def _record_result_node(state: DeFiState) -> dict:
    return {**record_verified_violation(state), 'poc_feedback': None}


def _profile_summary(state: DeFiState) -> str:
    profile = state.get('contract_profile') or {}
    summary = profile.get('business_semantics')
    return str(summary if summary else '')[:800]


def _make_explorer_with_memory(llm_client: Any, journal: Any, memory: Any) -> Callable[[DeFiState], dict]:

    def _node(state: DeFiState) -> dict:
        patterns: list[dict] = []
        if memory is not None and memory.mode != 'none':
            patterns = memory.retrieve_for_violation({}, profile_summary=_profile_summary(state))
        return adversarial_explorer_node(state, llm_client=llm_client, journal=journal, retrieved_patterns=patterns)
    return _node


def _make_planner_with_memory(llm_client: Any, journal: Any, memory: Any) -> Callable[[DeFiState], dict]:

    def _node(state: DeFiState) -> dict:
        patterns: list[dict] = []
        if memory is not None and memory.mode != 'none':
            patterns = memory.retrieve_for_violation(state.get('current_violation') or {}, profile_summary=_profile_summary(state))
        return attack_planner_node(state, llm_client=llm_client, journal=journal, retrieved_patterns=patterns)
    return _node


def build_graph(llm_client: Any=None, journal: Any=None, memory: Any=None, runner: Any=None, timeout: int=600):
    builder = StateGraph(DeFiState)
    builder.add_node('contract_parser', make_contract_parser_node(llm_client, journal))
    builder.add_node('role_analyzer', make_role_analyzer_node(llm_client, journal))
    builder.add_node('role_graph_builder', make_role_graph_builder_node(journal))
    builder.add_node('adversarial_explorer', _make_explorer_with_memory(llm_client, journal, memory))
    builder.add_node('attack_planner', _make_planner_with_memory(llm_client, journal, memory))
    builder.add_node('poc_generator', make_poc_generator_node(llm_client, journal))
    builder.add_node('foundry_executor', make_foundry_executor_node(runner, journal, timeout=timeout))
    builder.add_node('dual_oracle', make_dual_oracle_node())
    builder.add_node('retry_poc', _retry_poc_node)
    builder.add_node('advance', _advance_node)
    builder.add_node('record_result', _record_result_node)
    builder.add_node('done', make_done_node(llm_client, journal))
    builder.add_edge(START, 'contract_parser')
    builder.add_conditional_edges('contract_parser', route_after_parser, {'role_analyzer': 'role_analyzer', 'done': 'done'})
    builder.add_edge('role_analyzer', 'role_graph_builder')
    builder.add_edge('role_graph_builder', 'adversarial_explorer')
    builder.add_conditional_edges('adversarial_explorer', route_after_explorer, {'attack_planner': 'attack_planner', 'done': 'done'})
    builder.add_edge('attack_planner', 'poc_generator')
    builder.add_edge('poc_generator', 'foundry_executor')
    builder.add_edge('foundry_executor', 'dual_oracle')
    builder.add_conditional_edges('dual_oracle', route_after_dual_oracle, {'record_result': 'record_result', 'retry_poc': 'retry_poc', 'advance': 'advance'})
    builder.add_conditional_edges('retry_poc', route_after_retry, {'poc_generator': 'poc_generator', 'attack_planner': 'attack_planner'})
    builder.add_conditional_edges('advance', route_after_advance, {'attack_planner': 'attack_planner', 'done': 'done'})
    builder.add_conditional_edges('record_result', route_after_record, {'attack_planner': 'attack_planner', 'done': 'done'})
    builder.add_edge('done', END)
    return builder.compile()
