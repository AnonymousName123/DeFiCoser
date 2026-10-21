from __future__ import annotations
from deficoser.config import POC_MAX_RETRIES_INITIAL
from deficoser.state import DeFiState
_PART_LIMIT = 400
_MAX_ITEMS = 4

def should_retry_poc(state: DeFiState) -> bool:
    max_retries = state.get('poc_max_retries')
    if max_retries is None:
        max_retries = POC_MAX_RETRIES_INITIAL
    count = state.get('poc_retry_count') or 0
    return count < max_retries

def advance_violation(state: DeFiState) -> dict:
    violations = state.get('ac_violations') or []
    index = (state.get('violation_index') or 0) + 1
    nxt = violations[index] if index < len(violations) else None
    return {'violation_index': index, 'current_violation': nxt, 'poc_retry_count': 0}

def poc_failure_feedback(state: DeFiState) -> dict:
    parts: list[str] = []
    invalid = state.get('poc_invalid_reason')
    if invalid:
        parts.append(f'The previous PoC generation failed static validation: {invalid}')
    foundry = state.get('foundry_result') or {}
    if not parts:
        compile_errors = foundry.get('compile_errors') or []
        if foundry.get('timed_out'):
            parts.append('The previous PoC execution timed out (forge test timed out)')
        elif compile_errors:
            for error in compile_errors[:_MAX_ITEMS]:
                parts.append(f'The previous PoC failed to compile: {error[:_PART_LIMIT]}')
        elif foundry.get('revert_reason'):
            parts.append(f"The previous PoC execution failed (revert/assertion failure): {str(foundry['revert_reason'])[:_PART_LIMIT]}")
        elif foundry and foundry.get('test_passed') is False:
            parts.append('The previous PoC test did not pass (no specific revert reason captured)')
    if not parts:
        parts.append('The previous PoC did not prove exploitability (dual Oracle did not pass)')
    feedback = '; '.join(parts)
    return {'poc_feedback': feedback}

def record_verified_violation(state: DeFiState) -> dict:
    index = state.get('violation_index') or 0
    entry = {'violation_index': index, 'violation': state.get('current_violation') or {}, 'exploitability': bool(state.get('exploitability')), 'impact_verdict': state.get('impact_verdict') or {}}
    verified = list(state.get('verified_violations') or [])
    verified.append(entry)
    violations = state.get('ac_violations') or []
    next_index = index + 1
    return {'verified_violations': verified, 'violation_index': next_index, 'current_violation': violations[next_index] if next_index < len(violations) else None, 'poc_retry_count': 0}
