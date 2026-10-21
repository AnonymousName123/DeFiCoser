from __future__ import annotations
import re
from deficoser.state import DeFiState
from deficoser.tools.oracle_utils import has_authorization_violation
NODE_NAME = 'dual_oracle'
_IMPACT_ORDER: tuple[str, ...] = ('asset_gain', 'privilege_escalation', 'governance_control', 'state_corruption', 'protocol_denial')
_CATEGORY_TO_IMPACT: dict[str, str] = {'impact_asset_gain': 'asset_gain', 'impact_privilege_escalation': 'privilege_escalation', 'impact_governance_control': 'governance_control', 'impact_state_corruption': 'state_corruption', 'impact_protocol_denial': 'protocol_denial'}
_GAIN_RE = re.compile('gain\\s*=\\s*(\\d+)')

def _parse_gain(evidence: list[dict]) -> int | None:
    gains: list[int] = []
    for item in evidence:
        if item.get('category') != 'impact_asset_gain':
            continue
        match = _GAIN_RE.search(item.get('detail') or '')
        if match:
            gains.append(int(match.group(1)))
    return gains[0] if gains else None

def dual_oracle_node(state: DeFiState) -> dict:
    foundry = state.get('foundry_result') or {}
    evidence: list[dict] = foundry.get('evidence') or []
    blueprints = state.get('attack_blueprints') or []
    blueprint = blueprints[0] if blueprints else {}
    profile = state.get('contract_profile') or {}
    invariants = profile.get('invariants') or {}
    invariant_names = [i.get('name') for i in (invariants.get('generic') or []) + (invariants.get('contract') or []) if i.get('name')]
    authorization_violation = has_authorization_violation(foundry, state.get('current_violation'))
    impact_evidence = [item for item in evidence if item.get('category') in _CATEGORY_TO_IMPACT]
    gain = _parse_gain(evidence)
    impact_types: list[str] = []
    for item in impact_evidence:
        impact = _CATEGORY_TO_IMPACT[item['category']]
        if impact == 'asset_gain' and (not (gain is not None and gain > 0)):
            continue
        if impact not in impact_types:
            impact_types.append(impact)
    impact_types.sort(key=_IMPACT_ORDER.index)
    expected_type = (blueprint.get('expected_impact') or {}).get('type') or ''
    evidence_incomplete = expected_type == 'asset_gain' and 'asset_gain' not in impact_types and (gain is None)
    primary_type = expected_type if expected_type in impact_types else impact_types[0] if impact_types else None
    impact_verdict = {'impact_types': impact_types, 'primary_type': primary_type, 'gain': gain, 'evidence': impact_evidence, 'evidence_incomplete': evidence_incomplete, 'invariants': invariant_names}
    exploitability = authorization_violation and len(impact_types) > 0
    return {'authorization_violation': authorization_violation, 'impact_verdict': impact_verdict, 'exploitability': exploitability}

def make_dual_oracle_node():

    def _node(state: DeFiState) -> dict:
        return dual_oracle_node(state)
    return _node
