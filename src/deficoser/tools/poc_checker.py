from __future__ import annotations
import re
from pathlib import PurePosixPath
from deficoser.tools.function_text import match_delimiter
_SETUP_MARKER_RE = re.compile('//[ \\t]*===[ \\t]*SETUP[ \\t]*===[ \\t]*')
_ATTACK_MARKER_RE = re.compile('//[ \\t]*===[ \\t]*ATTACK[ \\t]*===[ \\t]*')
_PRANK_START_RE = re.compile('\\bvm\\.(?:prank|startPrank)\\s*\\(')
_ATTACKER_NAME_RE = re.compile('attack|malicious|hacker|intruder|unauthorized|exploiter|adversary|attacker')
_EVIDENCE_DEF_RE = re.compile('event\\s+Evidence\\s*\\(\\s*string\\s+\\w+\\s*,\\s*string\\s+\\w+\\s*\\)')
_EMIT_EVIDENCE_RE = re.compile('\\bemit\\s+Evidence\\s*\\(')
_MAKEADDR_ASSIGN_RE = re.compile('\\b([A-Za-z_$][\\w$]*)\\s*=\\s*makeAddr\\s*\\(\\s*\\"([^\\"]*)\\"')

def _safe_solidity_filename(filename: object) -> bool:
    if not isinstance(filename, str) or not filename.strip():
        return False
    if '\\' in filename or ':' in filename:
        return False
    path = PurePosixPath(filename)
    if path.is_absolute() or '..' in path.parts:
        return False
    return path.suffix == '.sol'

def _iter_pranks(code: str):
    for match in _PRANK_START_RE.finditer(code):
        open_pos = match.end() - 1
        close_pos = match_delimiter(code, open_pos, opener='(', closer=')')
        if close_pos < 0:
            continue
        yield (match.start(), code[match.end():close_pos])

def _attacker_derived_labels(code: str) -> set[str]:
    derived: set[str] = set()
    for var, label in _MAKEADDR_ASSIGN_RE.findall(code):
        if label.strip().lower().startswith('attacker'):
            derived.add(var)
    return derived

def _is_attacker_side(arg: str, derived_vars: set[str]) -> bool:
    text = arg.strip()
    if not text:
        return False
    if text == 'address(this)':
        return True
    for literal in re.findall('"([^"]*)"', text):
        if literal.strip().lower().startswith('attacker'):
            return True
    wrapped = re.fullmatch('(?:address|payable)\\s*\\((.+)\\)', text, re.S)
    if wrapped:
        return _is_attacker_side(wrapped.group(1), derived_vars)
    identifier = re.match('[A-Za-z_$][\\w$]*', text)
    if identifier:
        name = identifier.group(0)
        if _ATTACKER_NAME_RE.search(name) or name in derived_vars:
            return True
    return False

def find_prank_violations(test_code: str) -> list[str]:
    events: list[tuple[int, str]] = []
    events.extend(((m.start(), 'SETUP') for m in _SETUP_MARKER_RE.finditer(test_code)))
    events.extend(((m.start(), 'ATTACK') for m in _ATTACK_MARKER_RE.finditer(test_code)))
    events.sort()
    derived = _attacker_derived_labels(test_code)
    violations: list[str] = []
    for position, arg in _iter_pranks(test_code):
        phase = 'SETUP'
        for marker_pos, marker_kind in events:
            if marker_pos < position:
                phase = marker_kind
            else:
                break
        if phase != 'ATTACK':
            continue
        if not _is_attacker_side(arg, derived):
            violations.append(f'vm.prank({arg.strip()}) in the ATTACK section is not an attacker-side address (do not assume the attacker already has privileges; privileged pranks are allowed only in SETUP for state preparation)')
    return violations

def check_poc(poc: object) -> dict:
    if not isinstance(poc, dict):
        return {'poc_invalid_reason': f'PoC output must be a JSON object; got {type(poc).__name__}'}
    for key in ('attack_contract', 'foundry_test'):
        part = poc.get(key)
        if not isinstance(part, dict):
            return {'poc_invalid_reason': f'missing or invalid {key} object'}
        if not _safe_solidity_filename(part.get('filename')):
            return {'poc_invalid_reason': f'{key}.filename must be a safe relative .sol filename'}
        code = part.get('code')
        if not isinstance(code, str) or not code.strip():
            return {'poc_invalid_reason': f'{key}.code is empty'}
    notes = poc.get('notes')
    if notes is not None and (not isinstance(notes, str)):
        return {'poc_invalid_reason': 'notes must be a string'}
    test_code: str = poc['foundry_test']['code']
    attack_code: str = poc['attack_contract']['code']
    if not _EVIDENCE_DEF_RE.search(test_code):
        return {'poc_invalid_reason': 'test code does not define event Evidence(string category, string detail); (required by the Evidence evidence protocol)'}
    if not (_EMIT_EVIDENCE_RE.search(test_code) or _EMIT_EVIDENCE_RE.search(attack_code)):
        return {'poc_invalid_reason': 'no emit Evidence(...) found in code (attack-critical points must emit evidence as required by the protocol)'}
    if not _SETUP_MARKER_RE.search(test_code):
        return {'poc_invalid_reason': "test code is missing the '// === SETUP ===' phase marker comment"}
    if not _ATTACK_MARKER_RE.search(test_code):
        return {'poc_invalid_reason': "test code is missing the '// === ATTACK ===' phase marker comment"}
    prank_violations = find_prank_violations(test_code)
    if prank_violations:
        return {'poc_invalid_reason': '; '.join(prank_violations)}
    if not re.search('function\\s+testExploit', test_code):
        return {'poc_invalid_reason': 'test code is missing a function testExploit_* test function (forge runs it with --match-test "testExploit.*")'}
    return {}
