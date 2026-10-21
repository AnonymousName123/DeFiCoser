from __future__ import annotations
import re
from typing import Any
_MSG_SENDER_CHECK_RE = re.compile('(?:require|assert)\\s*\\([^;]{0,300}?msg\\.sender|if\\s*\\([^;]{0,300}?msg\\.sender', re.S)
_IMPORT_RE = re.compile('import\\s+(?:[a-zA-Z0-9_{},\\s*]*?\\s+from\\s+)?["\']([^"\']+)["\']')

def _src_span(node: dict) -> tuple[int, int]:
    parts = str(node.get('src', '0:0:0')).split(':')
    try:
        return (int(parts[0]), int(parts[1]))
    except (ValueError, IndexError):
        return (0, 0)

def _line_of(text: str, offset: int) -> int:
    return text.count('\n', 0, offset) + 1 if offset > 0 else 1

def _type_name(decl: dict) -> str:
    descriptions = decl.get('typeDescriptions') or {}
    return str(descriptions.get('typeString') or decl.get('typeName', {}).get('name', ''))

def _collect_state_var_declarations(nodes: list[dict], into: dict[int, str]) -> None:
    for node in nodes:
        if not isinstance(node, dict):
            continue
        if node.get('nodeType') == 'ContractDefinition':
            for child in node.get('nodes', []):
                if isinstance(child, dict) and child.get('nodeType') == 'VariableDeclaration' and child.get('stateVariable') and child.get('name'):
                    into[child['id']] = child['name']
        _collect_state_var_declarations(node.get('nodes', []) if isinstance(node, dict) else [], into)

def _identifiers(node: Any) -> list[dict]:
    if isinstance(node, dict):
        if node.get('nodeType') == 'Identifier':
            yield node
        for value in node.values():
            yield from _identifiers(value)
    elif isinstance(node, list):
        for item in node:
            yield from _identifiers(item)

def _fn_accesses(body: Any) -> tuple[set[int], set[int]]:
    reads: set[int] = set()
    writes: set[int] = set()
    _walk_access(body, reads, writes)
    return (reads, writes)

def _walk_access(node: Any, reads: set[int], writes: set[int]) -> None:
    if isinstance(node, dict):
        node_type = node.get('nodeType')
        if node_type == 'Identifier':
            ref = node.get('referencedDeclaration')
            if ref is not None:
                reads.add(ref)
            return
        if node_type == 'Assignment':
            lhs = node.get('leftHandSide')
            _lvalue_parts(lhs, writes, reads)
            if node.get('operator') != '=':
                _lvalue_base_ids(lhs, reads)
            _walk_access(node.get('rightHandSide'), reads, writes)
            return
        if node_type == 'UnaryOperation' and node.get('operator') in ('++', '--'):
            operand = node.get('subExpression')
            _lvalue_parts(operand, writes, reads)
            _lvalue_base_ids(operand, reads)
            return
        for value in node.values():
            _walk_access(value, reads, writes)
    elif isinstance(node, list):
        for item in node:
            _walk_access(item, reads, writes)

def _lvalue_parts(node: Any, writes: set[int], reads: set[int]) -> None:
    if not isinstance(node, dict):
        return
    node_type = node.get('nodeType')
    if node_type == 'Identifier':
        ref = node.get('referencedDeclaration')
        if ref is not None:
            writes.add(ref)
    elif node_type == 'IndexAccess':
        _lvalue_parts(node.get('baseExpression'), writes, reads)
        _walk_access(node.get('indexExpression'), reads, writes)
    elif node_type == 'MemberAccess':
        _lvalue_parts(node.get('expression'), writes, reads)
    elif node_type == 'TupleExpression':
        for component in node.get('components') or []:
            _lvalue_parts(component, writes, reads)

def _lvalue_base_ids(node: Any, into: set[int]) -> None:
    if not isinstance(node, dict):
        return
    node_type = node.get('nodeType')
    if node_type == 'Identifier':
        ref = node.get('referencedDeclaration')
        if ref is not None:
            into.add(ref)
    elif node_type in ('IndexAccess', 'MemberAccess'):
        key = 'baseExpression' if node_type == 'IndexAccess' else 'expression'
        _lvalue_base_ids(node.get(key), into)
    elif node_type == 'TupleExpression':
        for component in node.get('components') or []:
            _lvalue_base_ids(component, into)

def extract_from_asts(compile_result: dict, sources: dict[str, str]) -> dict:
    functions: list[dict] = []
    state_vars: list[dict] = []
    modifiers: list[dict] = []
    inheritance: dict[str, list[str]] = {}
    using_for: dict[str, dict[str, list[str]]] = {}
    access: dict[str, dict[str, set]] = {}
    modifier_used: dict[tuple, set] = {}
    asts = {key: payload.get('ast') for key, payload in (compile_result.get('sources') or {}).items() if payload.get('ast')}
    state_ids: dict[int, str] = {}
    for ast in asts.values():
        _collect_state_var_declarations(ast.get('nodes', []), state_ids)
    for rel in sorted(sources):
        ast = asts.get(rel)
        if not ast:
            continue
        text = sources[rel]
        for node in ast.get('nodes', []):
            if not isinstance(node, dict):
                continue
            node_type = node.get('nodeType')
            if node_type == 'UsingForDirective':
                library = node.get('libraryName') or {}
                libraries = [str(library.get('name') or library.get('path') or '')]
                using_for.setdefault('__top_level__', {})[str(node.get('typeName', {}).get('typeDescriptions', {}).get('typeString') or '*')] = libraries
            if node_type != 'ContractDefinition':
                continue
            contract = str(node.get('name') or '<anonymous>')
            bases = [str((base.get('baseName') or {}).get('name') or '') for base in node.get('baseContracts', [])]
            inheritance[contract] = [b for b in bases if b]
            contract_using: dict[str, list[str]] = {}
            for child in node.get('nodes', []):
                if not isinstance(child, dict):
                    continue
                if child.get('nodeType') == 'UsingForDirective':
                    library = child.get('libraryName') or {}
                    contract_using[str((child.get('typeName') or {}).get('typeDescriptions', {}).get('typeString') or '*')] = [str(library.get('name') or '')]
                if child.get('nodeType') == 'VariableDeclaration' and child.get('stateVariable') and child.get('name'):
                    canonical = f"{contract}.{child['name']}"
                    state_vars.append({'name': child['name'], 'contract': contract, 'type': _type_name(child), 'visibility': child.get('visibility') or 'default', 'read_by': [], 'written_by': []})
                    access[canonical] = {'read_by': set(), 'written_by': set()}
                if child.get('nodeType') == 'ModifierDefinition':
                    name = str(child.get('name') or '')
                    start, length = _src_span(child)
                    body = child.get('body') or {}
                    read_ids, written_ids = _fn_accesses(body)
                    referenced = {state_ids[i] for i in written_ids | read_ids if i in state_ids}
                    modifiers.append({'name': name, 'contract': contract, 'source_text': text[start:start + length], 'referenced_vars': sorted(referenced), 'used_by': []})
                    modifier_used.setdefault((contract, name), set())
                if child.get('nodeType') == 'FunctionDefinition':
                    kind = child.get('kind', 'function')
                    name = str(child.get('name') or ('constructor' if kind == 'constructor' else kind))
                    fqn = f"{contract}.{name}({', '.join((_type_name(p) for p in (child.get('parameters') or {}).get('parameters', [])))})"
                    start, length = _src_span(child)
                    fn_text = text[start:start + length]
                    body = child.get('body') or {}
                    read_ids, written_ids = _fn_accesses(body)
                    state_writes = {state_ids[i] for i in written_ids if i in state_ids}
                    state_reads = {state_ids[i] for i in read_ids if i in state_ids}
                    fn_modifiers = [str((m.get('modifierName') or {}).get('name') or '') for m in child.get('modifiers', [])]
                    for modifier_name in fn_modifiers:
                        if modifier_name:
                            modifier_used.setdefault((contract, modifier_name), set()).add(fqn)
                    functions.append({'fqn': fqn, 'name': name, 'contract': contract, 'visibility': child.get('visibility') or 'internal', 'modifiers': [m for m in fn_modifiers if m], 'params': [{'name': p.get('name') or '', 'type': _type_name(p)} for p in (child.get('parameters') or {}).get('parameters', [])], 'returns': [{'name': p.get('name') or '', 'type': _type_name(p)} for p in (child.get('returnParameters') or {}).get('parameters', [])], 'state_reads': sorted(state_reads), 'state_writes': sorted(state_writes), 'internal_calls': [], 'external_calls': [], 'file': rel, 'line_number': _line_of(text, start), 'has_msg_sender_check': bool(_MSG_SENDER_CHECK_RE.search(fn_text))})
                    for var in state_reads:
                        entry = access.get(f'{contract}.{var}')
                        if entry is not None:
                            entry['read_by'].add(fqn)
                    for var in state_writes:
                        entry = access.get(f'{contract}.{var}')
                        if entry is not None:
                            entry['written_by'].add(fqn)
            if contract_using:
                using_for[contract] = contract_using
    for var in state_vars:
        entry = access.get(f"{var['contract']}.{var['name']}", {})
        var['read_by'] = sorted(entry.get('read_by', set()))
        var['written_by'] = sorted(entry.get('written_by', set()))
    by_key = {(m['contract'], m['name']): m for m in modifiers}
    for (contract, name), used in modifier_used.items():
        if (contract, name) in by_key:
            by_key[contract, name]['used_by'] = sorted(used)
    return {'analysis_source': 'ast_fallback', 'contracts': _contracts_from(inheritance, functions), 'functions': functions, 'state_vars': state_vars, 'modifiers': modifiers, 'inheritance': inheritance, 'using_for': using_for, 'call_graph': []}

def _contracts_from(inheritance: dict, functions: list[dict]) -> list[dict]:
    seen: dict[str, dict] = {}
    for function in functions:
        seen.setdefault(function['contract'], {'name': function['contract'], 'file': function['file'], 'kind': 'contract'})
    for contract in inheritance:
        seen.setdefault(contract, {'name': contract, 'file': '', 'kind': 'contract'})
    return [seen[name] for name in sorted(seen)]

def build_import_graph(sources: dict[str, str]) -> dict[str, list[str]]:
    keys = set(sources)
    graph: dict[str, list[str]] = {}
    for rel in sorted(sources):
        targets = []
        base = rel.rsplit('/', 1)[0] if '/' in rel else ''
        for match in _IMPORT_RE.finditer(sources[rel]):
            target = match.group(1)
            candidates = []
            if target.startswith('.'):
                parts = (base.split('/') if base else []) + [target]
                stack: list[str] = []
                for part in '/'.join(parts).split('/'):
                    if part == '.':
                        continue
                    if part == '..':
                        if stack:
                            stack.pop()
                        continue
                    stack.append(part)
                candidates.append('/'.join(stack))
            else:
                candidates.append(target.lstrip('./'))
                candidates.append(target)
            for candidate in candidates:
                if candidate in keys:
                    targets.append(candidate)
                    break
        graph[rel] = sorted(set(targets))
    return graph
