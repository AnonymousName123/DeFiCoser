from __future__ import annotations
import re
from deficoser.tools.function_text import extract_function_text, iter_require_calls
from deficoser.tools.role_extractor import normalize_variable_role
_MENTIONS_AC_RE = re.compile('msg\\.sender|tx\\.origin|\\b_?hasRole\\s*\\(')
_ATOM_PATTERNS: tuple[tuple[re.Pattern, str], ...] = ((re.compile('\\bmsg\\.sender\\s*==\\s*([A-Za-z_$][\\w$]*)(?![\\w$.\\[(])'), 'sender_eq'), (re.compile('(?<![\\w$.])([A-Za-z_$][\\w$]*)\\s*==\\s*msg\\.sender\\b'), 'sender_eq'), (re.compile('\\bmsg\\.sender\\s*!=\\s*([A-Za-z_$][\\w$]*)(?![\\w$.\\[(])'), 'sender_ne'), (re.compile('\\btx\\.origin\\s*==\\s*([A-Za-z_$][\\w$]*)(?![\\w$.\\[(])'), 'origin_eq'), (re.compile('(?<![\\w$.])([A-Za-z_$][\\w$]*)\\s*==\\s*tx\\.origin\\b'), 'origin_eq'), (re.compile('\\b_?hasRole\\s*\\(\\s*([A-Za-z_$][\\w$]*|\\"[^\\"]*\\"|\'[^\']*\')\\s*,\\s*msg\\.sender\\s*\\)'), 'has_role'))

def _condition_inner(call_text: str) -> str:
    return call_text[call_text.index('(') + 1:call_text.rindex(')')]

def _normalize_condition(call_text: str) -> str:
    text = _condition_inner(call_text)
    text = text.replace('msg.sender', 'sender').replace('tx.origin', 'origin')
    text = text.replace('||', ' or ').replace('&&', ' and ')
    return re.sub('\\s+', ' ', text).strip()

def _split_disjuncts(condition: str) -> list[str]:
    disjuncts: list[str] = []
    depth = 0
    state: str | None = None
    start = 0
    i = 0
    n = len(condition)
    while i < n:
        ch = condition[i]
        if state in ("'", '"'):
            if ch == '\\':
                i += 1
            elif ch == state:
                state = None
        elif ch in ("'", '"'):
            state = ch
        elif ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        elif depth == 0 and ch == '|' and (i + 1 < n) and (condition[i + 1] == '|'):
            disjuncts.append(condition[start:i])
            i += 1
            start = i + 1
        i += 1
    disjuncts.append(condition[start:])
    return [d.strip() for d in disjuncts if d.strip()]

def _parse_atoms(disjunct: str) -> list[tuple[str, str]]:
    atoms: list[tuple[str, str]] = []
    for pattern, form in _ATOM_PATTERNS:
        for match in pattern.finditer(disjunct):
            atoms.append((form, match.group(1)))
    return atoms

class _RoleIndex:

    def __init__(self, roles: list[dict] | None) -> None:
        self._by_var: dict[str, set[str]] = {}
        for role in roles or []:
            if role.get('source') == 'adversarial':
                continue
            role_id = role.get('id') or ''
            state = role.get('state') or ''
            if not role_id:
                continue
            for token in {state, normalize_variable_role(state)}:
                if token:
                    self._by_var.setdefault(token, set()).add(role_id)

    def match(self, token: str) -> set[str]:
        roles = set(self._by_var.get(token, set()))
        normalized = normalize_variable_role(token)
        if normalized:
            roles |= self._by_var.get(normalized, set())
        return roles

def _disjunct_satisfiable(atoms: list[tuple[str, str]], disjunct: str, index: _RoleIndex) -> tuple[set[str], bool]:
    identity_tokens = [t for f, t in atoms if f in ('sender_eq', 'has_role')]
    origin_tokens = [t for f, t in atoms if f == 'origin_eq']
    if not identity_tokens and (not origin_tokens):
        return (set(), True)
    candidates: set[str] = set()
    for token in identity_tokens or origin_tokens:
        candidates |= index.match(token)
    if not candidates:
        return (set(), True)
    satisfiable: set[str] = set()
    for role_id in candidates:
        consistent = True
        for form, token in atoms:
            matched = index.match(token)
            if form in ('sender_eq', 'has_role', 'origin_eq') and role_id not in matched:
                consistent = False
                break
            if form == 'sender_ne' and role_id in matched:
                consistent = False
                break
        if consistent:
            satisfiable.add(role_id)
    has_uncovered_sender = 'msg.sender' in disjunct and (not any((f in ('sender_eq', 'sender_ne', 'has_role') for f, _ in atoms)))
    return (satisfiable, has_uncovered_sender)

def _resolve_modifier(name: str, contract: str, modifiers: list[dict]) -> dict | None:
    same_contract = None
    any_contract = None
    for modifier in modifiers:
        if modifier.get('name') != name:
            continue
        if modifier.get('contract') == contract:
            same_contract = modifier
            break
        any_contract = any_contract or modifier
    return same_contract or any_contract

def extract_predicates(profile: dict, sources: dict[str, str] | None=None, roles: list[dict] | None=None) -> dict:
    sources = sources or {}
    functions = {f.get('fqn'): f for f in profile.get('functions', []) if f.get('fqn')}
    modifiers = profile.get('modifiers', [])
    targets: list[str] = []
    for fqn in list(profile.get('protected_functions') or []) + [s.get('function_fqn') for s in profile.get('sinks') or []]:
        if fqn and fqn in functions and (fqn not in targets):
            targets.append(fqn)
    index = _RoleIndex(roles)
    entries: list[dict] = []
    authorized: dict[str, list[str]] = {}
    authorized_unknown: list[str] = []
    for fqn in targets:
        function = functions[fqn]
        conditions: list[dict] = []
        for mod_name in function.get('modifiers') or []:
            modifier = _resolve_modifier(mod_name, function.get('contract', ''), modifiers)
            if modifier is None:
                continue
            location = f"{modifier.get('contract', '')}.{mod_name}"
            for _start, _end, call_text in iter_require_calls(modifier.get('source_text', '')):
                if _MENTIONS_AC_RE.search(call_text):
                    conditions.append({'text': call_text, 'location': location})
        body = extract_function_text(sources, function)
        base_line = function.get('line_number') or 0
        file = function.get('file', '')
        if body:
            for start, _end, call_text in iter_require_calls(body):
                if _MENTIONS_AC_RE.search(call_text):
                    line = base_line + body.count('\n', 0, start)
                    conditions.append({'text': call_text, 'location': f'{file}:{line}'})
        required_roles: set[str] = set()
        if not conditions:
            predicate = 'true'
            fn_authorized: set[str] = set()
            unknown = False
        else:
            fragments = []
            for condition in conditions:
                fragment = _normalize_condition(condition['text'])
                fragments.append(f'({fragment})' if ' or ' in fragment else fragment)
            predicate = ' and '.join(fragments)
            fn_authorized: set[str] | None = None
            unknown = False
            for condition in conditions:
                cond_roles: set[str] = set()
                cond_unknown = False
                for disjunct in _split_disjuncts(_condition_inner(condition['text'])):
                    atoms = _parse_atoms(disjunct)
                    for form, token in atoms:
                        if form in ('sender_eq', 'has_role', 'origin_eq'):
                            required_roles.add(normalize_variable_role(token))
                    if not atoms:
                        if _MENTIONS_AC_RE.search(disjunct):
                            cond_unknown = True
                        continue
                    satisfiable, is_unknown = _disjunct_satisfiable(atoms, disjunct, index)
                    cond_roles |= satisfiable
                    cond_unknown = cond_unknown or is_unknown
                fn_authorized = cond_roles if fn_authorized is None else fn_authorized & cond_roles
                unknown = unknown or cond_unknown
        entries.append({'function_fqn': fqn, 'predicate': predicate, 'required_roles': sorted(required_roles), 'conditions': conditions, 'authorized': sorted(fn_authorized or set()), 'unknown': unknown, 'unprotected': not conditions})
        authorized[fqn] = sorted(fn_authorized or set())
        if unknown:
            authorized_unknown.append(fqn)
    return {'permission_predicates': entries, 'authorized': authorized, 'authorized_unknown': authorized_unknown}
