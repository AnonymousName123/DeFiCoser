from __future__ import annotations
import json
import re
from pathlib import Path
from typing import Iterator
from deficoser.config import APP_CONFIG_DIR
from deficoser.tools.function_text import extract_function_text, iter_require_calls
ROLE_MAPPING_FILE = APP_CONFIG_DIR / 'role_mapping.json'
_FALLBACK_MAPPING: dict[str, dict[str, str]] = {'modifier_names': {'onlyOwner': 'owner', 'onlyAdmin': 'admin', 'onlyOperator': 'operator', 'onlyKeeper': 'keeper', 'onlyMinter': 'minter', 'onlyBurner': 'burner', 'onlyPauser': 'pauser', 'onlyGovernance': 'governance', 'onlyGovernor': 'governor', 'onlyStrategist': 'strategist', 'onlyManager': 'manager', 'onlyController': 'controller', 'onlyVault': 'vault', 'onlyTreasury': 'treasury', 'onlyFeeManager': 'fee_manager', 'onlyAuthorized': 'authorized', 'onlyWhitelisted': 'whitelisted', 'onlyApproved': 'approved', 'onlyOracle': 'oracle', 'onlyPair': 'pair', 'onlyRouter': 'router', 'onlyFactory': 'factory', 'onlyBridge': 'bridge', 'onlyCaller': 'caller', 'onlyRole': 'role_holder', 'onlySigner': 'signer', 'onlyExecutor': 'executor', 'onlyLiquidator': 'liquidator', 'onlyRelayer': 'relayer', 'onlyMultisig': 'multisig', 'onlyTimelock': 'timelock'}, 'variable_names': {'owner': 'owner', 'admin': 'admin', 'administrator': 'admin', 'governance': 'governance', 'governor': 'governor', 'operator': 'operator', 'keeper': 'keeper', 'strategist': 'strategist', 'manager': 'manager', 'controller': 'controller', 'treasury': 'treasury', 'feeTo': 'fee_to', 'feeToSetter': 'fee_to_setter', 'dev': 'dev', 'devFund': 'dev_fund', 'ceo': 'ceo', 'cto': 'cto', 'coo': 'coo', 'minter': 'minter', 'burner': 'burner', 'pauser': 'pauser', 'whitelister': 'whitelister', 'signer': 'signer', 'liquidator': 'liquidator', 'relayer': 'relayer', 'executor': 'executor', 'DEFAULT_ADMIN_ROLE': 'admin', 'ADMIN_ROLE': 'admin', 'MINTER_ROLE': 'minter', 'BURNER_ROLE': 'burner', 'PAUSER_ROLE': 'pauser', 'SNAPSHOT_ROLE': 'snapshot', 'OPERATOR_ROLE': 'operator', 'GOVERNOR_ROLE': 'governor', 'GOVERNANCE_ROLE': 'governance', 'STRATEGIST_ROLE': 'strategist', 'KEEPER_ROLE': 'keeper', 'ORACLE_ROLE': 'oracle', 'LIQUIDATOR_ROLE': 'liquidator', 'UPGRADER_ROLE': 'upgrader', 'TRANSFER_ROLE': 'transfer', 'CALLER_ROLE': 'caller', 'BRIDGE_ROLE': 'bridge', 'RELAYER_ROLE': 'relayer', 'EXECUTOR_ROLE': 'executor', 'WHITELIST_ROLE': 'whitelist', 'SIGNER_ROLE': 'signer'}}
_CAMEL_BOUND_RE = re.compile('(?<=[a-z0-9])(?=[A-Z])')
_ROLE_SUFFIX_RE = re.compile('_?role$', re.IGNORECASE)
_SENDER_EQ_RE = re.compile('\\bmsg\\.sender\\s*==\\s*([A-Za-z_$][\\w$]*)(?![\\w$.\\[(])')
_SENDER_EQ_REV_RE = re.compile('(?<![\\w$.])([A-Za-z_$][\\w$]*)\\s*==\\s*msg\\.sender\\b')
_SENDER_NE_RE = re.compile('\\bmsg\\.sender\\s*!=\\s*([A-Za-z_$][\\w$]*)(?![\\w$.\\[(])')
_ORIGIN_EQ_RE = re.compile('\\btx\\.origin\\s*==\\s*([A-Za-z_$][\\w$]*)(?![\\w$.\\[(])')
_ORIGIN_EQ_REV_RE = re.compile('(?<![\\w$.])([A-Za-z_$][\\w$]*)\\s*==\\s*tx\\.origin\\b')
_HAS_ROLE_RE = re.compile('\\b_?hasRole\\s*\\(\\s*([A-Za-z_$][\\w$]*|\\"[^\\"]*\\"|\'[^\']*\')\\s*,\\s*msg\\.sender\\s*\\)')

def load_role_mapping(path: str | Path | None=None) -> dict[str, dict[str, str]]:
    file = Path(path) if path is not None else ROLE_MAPPING_FILE
    data: dict = {}
    try:
        data = json.loads(file.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        data = {}
    mapping: dict[str, dict[str, str]] = {}
    for group, fallback in _FALLBACK_MAPPING.items():
        value = data.get(group)
        mapping[group] = {str(k): str(v) for k, v in value.items() if str(k).strip() and str(v).strip()} if isinstance(value, dict) else dict(fallback)
    return mapping

def _to_snake(token: str) -> str:
    return _CAMEL_BOUND_RE.sub('_', token).lower()

def _lookup(table: dict[str, str], token: str) -> str | None:
    if token in table:
        return table[token]
    lowered = token.lower()
    for key, value in table.items():
        if key.lower() == lowered:
            return value
    return None

def normalize_variable_role(token: str, mapping: dict[str, dict[str, str]] | None=None) -> str:
    if mapping is None:
        mapping = load_role_mapping()
    token = token.strip().strip('"\'')
    if not token:
        return ''
    mapped = _lookup(mapping['variable_names'], token)
    if mapped:
        return mapped
    stripped = _ROLE_SUFFIX_RE.sub('', token)
    if stripped and stripped != token:
        mapped = _lookup(mapping['variable_names'], stripped)
        return mapped or _to_snake(stripped)
    return _to_snake(token)

def normalize_modifier_role(name: str, mapping: dict[str, dict[str, str]] | None=None) -> str | None:
    if mapping is None:
        mapping = load_role_mapping()
    name = (name or '').strip()
    if not name:
        return None
    mapped = _lookup(mapping['modifier_names'], name)
    if mapped:
        return mapped
    if name.lower().startswith('only') and len(name) > 4:
        rest = name[4:]
        mapped = _lookup(mapping['variable_names'], rest)
        return mapped or normalize_variable_role(rest, mapping)
    return None

def _iter_mentions(text: str) -> Iterator[tuple[str, str, str, int]]:
    patterns = ((_SENDER_EQ_RE, 'sender_eq'), (_SENDER_EQ_REV_RE, 'sender_eq'), (_SENDER_NE_RE, 'sender_ne'), (_ORIGIN_EQ_RE, 'origin_eq'), (_ORIGIN_EQ_REV_RE, 'origin_eq'), (_HAS_ROLE_RE, 'has_role'))
    for pattern, form in patterns:
        for match in pattern.finditer(text):
            yield (form, match.group(1), match.group(0), match.start())

def _line_of(text: str, offset: int, base_line: int) -> int:
    return base_line + text.count('\n', 0, max(offset, 0))

def extract_explicit_roles(profile: dict, sources: dict[str, str] | None=None, mapping: dict[str, dict[str, str]] | None=None) -> list[dict]:
    sources = sources or {}
    mapping = mapping or load_role_mapping()
    roles: dict[str, dict] = {}
    gated: dict[str, set[str]] = {}

    def _add(role_id: str, state_var: str, evidence: dict) -> None:
        if not role_id:
            return
        role = roles.setdefault(role_id, {'id': role_id, 'privileges': [], 'state': state_var or role_id, 'capabilities': [], 'source': 'explicit', 'evidence': []})
        if evidence:
            role['evidence'].append(evidence)
            fqn = evidence.get('function_fqn')
            if fqn:
                gated.setdefault(role_id, set()).add(fqn)

    def _evidence(form: str, matched_text: str, function_fqn, location: str) -> dict:
        entry = {'kind': 'require', 'text': matched_text, 'function_fqn': function_fqn, 'location': location}
        if form == 'origin_eq':
            entry['tx_origin'] = True
        return entry
    for modifier in profile.get('modifiers', []):
        name = modifier.get('name', '')
        contract = modifier.get('contract', '')
        source_text = modifier.get('source_text', '')
        location = f'{contract}.{name}' if contract else name
        used_by = modifier.get('used_by') or []
        for form, token, matched_text, _start in _iter_mentions(source_text):
            role_id = normalize_variable_role(token, mapping)
            _add(role_id, token if form != 'has_role' else '', _evidence(form, matched_text, None, location))
        name_role = normalize_modifier_role(name, mapping)
        if name_role:
            for fqn in used_by or [None]:
                _add(name_role, '', {'kind': 'modifier', 'text': f'modifier {name}', 'function_fqn': fqn, 'location': location})
    for function in profile.get('functions', []):
        fqn = function.get('fqn', '')
        file = function.get('file', '')
        base_line = function.get('line_number') or 0
        text = extract_function_text(sources, function)
        if not text:
            continue
        for start, _end, call_text in iter_require_calls(text):
            for form, token, matched_text, m_start in _iter_mentions(call_text):
                role_id = normalize_variable_role(token, mapping)
                location = f'{file}:{_line_of(text, start + m_start, base_line)}'
                _add(role_id, token if form != 'has_role' else '', _evidence(form, matched_text, fqn, location))
    result = []
    for role_id in sorted(roles):
        role = roles[role_id]
        role['privileges'] = sorted(gated.get(role_id, set()))
        result.append(role)
    return result
