from typing import TypedDict

class DeFiState(TypedDict, total=False):
    contract_sources: dict[str, str]
    contract_profile: dict
    sensitive_sinks: list[str]
    roles: list[dict]
    permission_predicates: list[dict]
    role_graph: dict
    authorized: dict
    ac_violations: list[dict]
    retrieved_patterns: list[dict]
    exploration_truncated: bool
    exploration_truncated_count: int
    attack_blueprints: list[dict]
    attack_contract_code: str
    foundry_test_code: str
    foundry_result: dict
    poc_files: dict[str, str]
    poc_invalid_reason: str
    poc_feedback: str
    authorization_violation: bool
    impact_verdict: dict
    exploitability: bool
    poc_retry_count: int
    poc_max_retries: int
    report: dict
    llm_config: dict
    violation_index: int
    current_violation: dict
    verified_violations: list[dict]
    case_id: str
    dataset: str
    time_bucket: str
    config: str
    memory_mode: str
    memory_size: int
    error: dict
