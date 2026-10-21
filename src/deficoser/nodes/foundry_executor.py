from __future__ import annotations
import time
from typing import Any, Callable
from deficoser.state import DeFiState
from deficoser.tools.foundry_runner import FoundryRunner
NODE_NAME = 'foundry_executor'
_DEFAULT_SOLC = '0.8.28'

def _filenames_from_state(state: DeFiState) -> tuple[str | None, str | None]:
    poc_files: dict[str, str] = state.get('poc_files') or {}
    test_code = state.get('foundry_test_code') or ''
    attack_code = state.get('attack_contract_code') or ''
    test_name: str | None = None
    attack_name: str | None = None
    for filename, code in poc_files.items():
        if test_name is None and test_code and (code == test_code):
            test_name = filename
        elif attack_name is None and attack_code and (code == attack_code):
            attack_name = filename
    return (test_name, attack_name)

def foundry_executor_node(state: DeFiState, *, runner: Any=None, journal: Any=None, timeout: int=600) -> dict:
    started = time.perf_counter()
    sources = state.get('contract_sources') or {}
    test_code = state.get('foundry_test_code') or ''
    attack_code = state.get('attack_contract_code') or ''
    if not sources or not test_code.strip():
        if journal is not None:
            journal.add_stage_usage('foundry_execute', 0, (time.perf_counter() - started) * 1000)
        return {'error': {'node': NODE_NAME, 'message': 'input state is missing contract_sources / foundry_test_code (no executable PoC)', 'fatal': False}, 'foundry_result': {'compiled': False, 'compile_errors': ['no PoC test code available'], 'test_passed': False, 'revert_reason': None, 'evidence': [], 'logs': [], 'duration_ms': 0.0, 'timed_out': False}}
    profile = state.get('contract_profile') or {}
    solc_version = profile.get('solc_version') or _DEFAULT_SOLC
    test_filename, attack_filename = _filenames_from_state(state)
    executor = runner if runner is not None else FoundryRunner()
    result = executor.run(sources, test_code, attack_code, solc_version, timeout=timeout, test_filename=test_filename, attack_filename=attack_filename)
    if journal is not None:
        journal.add_stage_usage('foundry_execute', 0, (time.perf_counter() - started) * 1000)
    return {'foundry_result': result}

def make_foundry_executor_node(runner: Any=None, journal: Any=None, timeout: int=600) -> Callable[[DeFiState], dict]:

    def _node(state: DeFiState) -> dict:
        return foundry_executor_node(state, runner=runner, journal=journal, timeout=timeout)
    return _node
