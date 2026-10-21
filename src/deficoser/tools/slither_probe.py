from __future__ import annotations
import argparse
import json
import logging
import re
import sys
from pathlib import Path
_IMPORT_RE = re.compile('import\\s+(?:[a-zA-Z0-9_{},\\s*]*?\\s+from\\s+)?["\']([^"\']+)["\']')
_MSG_SENDER_CHECK_RE = re.compile('(?:require|assert)\\s*\\([^;]{0,300}?msg\\.sender|if\\s*\\([^;]{0,300}?msg\\.sender', re.S)

def _rel(path: str | Path, work: Path) -> str:
    try:
        return Path(path).resolve().relative_to(work.resolve()).as_posix()
    except (ValueError, OSError):
        return str(path).replace('\\', '/')

def _source_text(source_code: dict, absolute: str, start: int, length: int) -> str:
    text = source_code.get(absolute)
    if text is None:
        return ''
    if isinstance(text, bytes):
        text = text.decode('utf-8', errors='replace')
    return text[start:start + length]

def _has_msg_sender_check(text: str) -> bool:
    return bool(_MSG_SENDER_CHECK_RE.search(text))

class _Accumulator:

    def __init__(self, work: Path) -> None:
        from slither.core.declarations.modifier import Modifier
        self._modifier_cls = Modifier
        self.work = work
        self.contracts: list[dict] = []
        self.functions: list[dict] = []
        self.state_vars: list[dict] = []
        self.modifiers: list[dict] = []
        self.inheritance: dict[str, list[str]] = {}
        self.using_for: dict[str, dict[str, list[str]]] = {}
        self.call_graph: list[dict] = []
        self._contract_names: set[str] = set()
        self._function_keys: set[tuple] = set()
        self._state_var_keys: set[str] = set()
        self._modifier_keys: set[tuple] = set()
        self._edge_keys: set[tuple] = set()
        self._var_access: dict[str, dict[str, set]] = {}
        self._modifier_used: dict[tuple, set] = {}

    def extract(self, slither) -> None:
        source_code = {}
        for key, text in slither.source_code.items():
            if isinstance(text, bytes):
                text = text.decode('utf-8', errors='replace')
            source_code[key] = text
        Modifier = self._modifier_cls
        for contract in slither.contracts:
            if contract.name in self._contract_names:
                continue
            self._contract_names.add(contract.name)
            file = _rel(contract.source_mapping.filename.absolute, self.work)
            self.contracts.append({'name': contract.name, 'file': file, 'kind': contract.contract_kind or 'contract'})
            self.inheritance[contract.name] = [base.name for base in contract.immediate_inheritance]
            using_for: dict[str, list[str]] = {}
            for type_str, libraries in (contract.using_for or {}).items():
                using_for[str(type_str)] = [getattr(lib, 'name', str(lib)) for lib in libraries]
            if using_for:
                self.using_for[contract.name] = using_for
            for var in contract.state_variables_declared:
                if var.canonical_name in self._state_var_keys or not var.name:
                    continue
                self._state_var_keys.add(var.canonical_name)
                self.state_vars.append({'name': var.name, 'contract': contract.name, 'type': str(var.type), 'visibility': var.visibility or 'default'})
                self._var_access[var.canonical_name] = {'read_by': set(), 'written_by': set()}
            for modifier in contract.modifiers_declared:
                key = (contract.name, modifier.name)
                if key in self._modifier_keys:
                    continue
                self._modifier_keys.add(key)
                sm = modifier.source_mapping
                self.modifiers.append({'name': modifier.name, 'contract': contract.name, 'source_text': _source_text(source_code, sm.filename.absolute, sm.start, sm.length), 'referenced_vars': sorted({v.name for v in list(modifier.state_variables_read) + list(modifier.state_variables_written) if v.name})})
                self._modifier_used.setdefault(key, set())
            for function in contract.functions_declared:
                if function.name.startswith('slitherConstructor'):
                    continue
                key = (contract.name, function.full_name)
                if key in self._function_keys:
                    continue
                self._function_keys.add(key)
                fqn = f'{contract.name}.{function.full_name}'
                sm = function.source_mapping
                fn_text = _source_text(source_code, sm.filename.absolute, sm.start, sm.length)
                internal_calls: set[str] = set()
                external_calls: list[dict] = []
                edges: list[tuple] = []
                for ir in function.internal_calls:
                    if not hasattr(ir, 'is_modifier_call') or ir.is_modifier_call:
                        continue
                    callee = getattr(ir, 'function', None)
                    if callee is None or not getattr(callee, 'full_name', None):
                        continue
                    callee_contract = getattr(callee, 'contract', None)
                    callee_fqn = f'{callee_contract.name}.{callee.full_name}' if callee_contract is not None else callee.full_name
                    internal_calls.add(callee_fqn)
                    edges.append((fqn, callee_fqn, False))
                for called_contract, ir in function.high_level_calls:
                    name = str(ir.function_name)
                    external_calls.append({'contract': called_contract.name, 'name': name})
                    edges.append((fqn, f'{called_contract.name}.{name}', True))
                for ir in function.library_calls:
                    name = str(ir.function_name)
                    destination = getattr(ir, 'destination', None)
                    lib_name = getattr(destination, 'name', str(destination))
                    external_calls.append({'contract': lib_name, 'name': name})
                    edges.append((fqn, f'{lib_name}.{name}', True))
                for ir in function.low_level_calls:
                    external_calls.append({'contract': str(ir.destination), 'name': str(ir.type_call), 'kind': 'low_level'})
                for caller, callee, external in edges:
                    if (caller, callee, external) not in self._edge_keys:
                        self._edge_keys.add((caller, callee, external))
                        self.call_graph.append({'caller_fqn': caller, 'callee_fqn': callee, 'external': external})
                self.functions.append({'fqn': fqn, 'name': function.name, 'contract': contract.name, 'visibility': function.visibility, 'modifiers': [m.name for m in function.modifiers if isinstance(m, Modifier) and getattr(m, 'name', None)], 'params': [{'name': p.name or '', 'type': str(p.type)} for p in function.parameters], 'returns': [{'name': r.name or '', 'type': str(r.type)} for r in function.returns], 'state_reads': sorted({v.name for v in function.state_variables_read if v.name}), 'state_writes': sorted({v.name for v in function.state_variables_written if v.name}), 'internal_calls': sorted(internal_calls), 'external_calls': external_calls, 'file': _rel(sm.filename.absolute, self.work), 'line_number': min(sm.lines) if sm.lines else 0, 'has_msg_sender_check': _has_msg_sender_check(fn_text)})
                for var in function.state_variables_read:
                    entry = self._var_access.get(var.canonical_name)
                    if entry is not None:
                        entry['read_by'].add(fqn)
                for var in function.state_variables_written:
                    entry = self._var_access.get(var.canonical_name)
                    if entry is not None:
                        entry['written_by'].add(fqn)
        for contract in slither.contracts:
            for function in contract.functions:
                for m in function.modifiers:
                    if not isinstance(m, Modifier):
                        continue
                    declared_contract = getattr(m, 'contract', None)
                    key = (declared_contract.name, m.name) if declared_contract is not None else (contract.name, m.name)
                    if key in self._modifier_used:
                        self._modifier_used[key].add(f'{function.contract.name}.{function.full_name}')

    def payload(self) -> dict:
        for var in self.state_vars:
            access = self._var_access.get(f"{var['contract']}.{var['name']}", {})
            var['read_by'] = sorted(access.get('read_by', set()))
            var['written_by'] = sorted(access.get('written_by', set()))
        by_key = {(m['contract'], m['name']): m for m in self.modifiers}
        for (contract, name), used_by in self._modifier_used.items():
            if (contract, name) in by_key:
                by_key[contract, name]['used_by'] = sorted(used_by)
        for modifier in self.modifiers:
            modifier.setdefault('used_by', [])
        return {'contracts': self.contracts, 'functions': self.functions, 'state_vars': self.state_vars, 'modifiers': self.modifiers, 'inheritance': self.inheritance, 'using_for': self.using_for, 'call_graph': self.call_graph}

def _find_at_dirs(work: Path) -> dict[str, Path]:
    found: dict[str, tuple[int, Path]] = {}
    for directory in sorted(work.rglob('@*')):
        if not directory.is_dir() or not directory.name.startswith('@'):
            continue
        depth = len(directory.relative_to(work).parts)
        current = found.get(directory.name)
        if current is None or depth < current[0]:
            found[directory.name] = (depth, directory)
    return {name: path.resolve() for name, (_, path) in sorted(found.items())}

def _build_remappings(work: Path) -> list[str]:
    return [f'{name}/={path.as_posix()}/' for name, path in _find_at_dirs(work).items()]

def _resolve_import(target: str, importing_file: Path, work: Path, at_dirs: dict[str, Path]) -> Path | None:
    if target.startswith('@'):
        package = target.split('/', 1)[0]
        base = at_dirs.get(package)
        if base is None:
            return None
        candidate = (base / target[len(package) + 1:]).resolve()
    else:
        candidate = (importing_file.parent / target).resolve()
        if not candidate.exists():
            candidate = (work / target).resolve()
    return candidate if candidate.exists() and candidate.is_file() else None

def _imported_files(files: list[Path], work: Path, at_dirs: dict[str, Path]) -> set[Path]:
    imported: set[Path] = set()
    for file in files:
        try:
            text = file.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        for match in _IMPORT_RE.finditer(text):
            resolved = _resolve_import(match.group(1), file, work, at_dirs)
            if resolved is not None:
                imported.add(resolved)
    return imported

def analyze(work: Path, solc: str) -> dict:
    try:
        from crytic_compile import CryticCompile
        from slither import Slither
    except ImportError as exc:
        return {'status': 'error', 'message': f'slither import failed: {exc}'}
    logging.getLogger('CryticCompile').setLevel(logging.ERROR)
    logging.getLogger('Slither').setLevel(logging.ERROR)
    files = sorted((p for p in work.rglob('*.sol')))
    if not files:
        return {'status': 'compile_error', 'message': f'Working directory {work} contains no .sol files', 'failed_files': []}
    remaps = _build_remappings(work)
    imported = _imported_files(files, work, _find_at_dirs(work))
    roots = [f for f in files if f not in imported] or files
    accumulator = _Accumulator(work)
    covered: set[Path] = set()
    failed_files: list[str] = []
    errors: list[str] = []

    def _compile_and_extract(target: Path) -> bool:
        try:
            compilation = CryticCompile(str(target), solc=solc, solc_remaps=remaps)
            slither = Slither(compilation)
        except Exception as exc:
            failed_files.append(_rel(target, work))
            errors.append(f'{_rel(target, work)}: {exc}')
            return False
        covered.update((Path(key) for key in slither.source_code))
        accumulator.extract(slither)
        return True
    for root in roots:
        _compile_and_extract(root)
    for file in files:
        if file not in covered:
            _compile_and_extract(file)
    payload = accumulator.payload()
    if not payload['contracts'] and (not payload['functions']):
        message = errors[0] if errors else 'All source files failed to compile'
        return {'status': 'compile_error', 'message': message[:2000], 'failed_files': sorted(set(failed_files))}
    return {'status': 'ok', 'failed_files': sorted(set(failed_files)), 'errors': errors[:10], 'covered_files': sorted((_rel(f, work) for f in covered)), **payload}

def main(argv: list[str] | None=None) -> int:
    parser = argparse.ArgumentParser(description='DeFiCoser Slither probe')
    parser.add_argument('target', help='working directory (contains the .sol file tree)')
    parser.add_argument('--solc', required=True, help='solc executable path')
    parser.add_argument('--out', required=True, help='result JSON output path')
    args = parser.parse_args(argv)
    work = Path(args.target).resolve()
    try:
        result = analyze(work, args.solc)
    except Exception as exc:
        result = {'status': 'error', 'message': f'{type(exc).__name__}: {exc}'}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, ensure_ascii=False), encoding='utf-8')
    return 0 if result.get('status') == 'ok' else 2
if __name__ == '__main__':
    sys.exit(main())
