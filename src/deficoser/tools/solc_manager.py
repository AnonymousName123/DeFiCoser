from __future__ import annotations
import re
import shutil
import tempfile
from pathlib import Path
from typing import Optional
import solcx
from solcx.exceptions import SolcError
from solcx.install import get_executable as _solcx_get_executable
SOLC_RELEASES: tuple[str, ...] = ('0.4.11', '0.4.12', '0.4.13', '0.4.14', '0.4.15', '0.4.16', '0.4.17', '0.4.18', '0.4.19', '0.4.20', '0.4.21', '0.4.22', '0.4.23', '0.4.24', '0.4.25', '0.4.26', '0.5.0', '0.5.1', '0.5.2', '0.5.3', '0.5.4', '0.5.5', '0.5.6', '0.5.7', '0.5.8', '0.5.9', '0.5.10', '0.5.11', '0.5.12', '0.5.13', '0.5.14', '0.5.15', '0.5.16', '0.5.17', '0.6.0', '0.6.1', '0.6.2', '0.6.3', '0.6.4', '0.6.5', '0.6.6', '0.6.7', '0.6.8', '0.6.9', '0.6.10', '0.6.11', '0.6.12', '0.7.0', '0.7.1', '0.7.2', '0.7.3', '0.7.4', '0.7.5', '0.7.6', '0.8.0', '0.8.1', '0.8.2', '0.8.3', '0.8.4', '0.8.5', '0.8.6', '0.8.7', '0.8.8', '0.8.9', '0.8.10', '0.8.11', '0.8.12', '0.8.13', '0.8.14', '0.8.15', '0.8.16', '0.8.17', '0.8.18', '0.8.19', '0.8.20', '0.8.21', '0.8.22', '0.8.23', '0.8.24', '0.8.25', '0.8.26', '0.8.27', '0.8.28', '0.8.29', '0.8.30', '0.8.31', '0.8.32', '0.8.33', '0.8.34', '0.8.35', '0.8.36')
_MIN_SOLC_VERSION = '0.4.11'

class SolcManagerError(Exception):

    def __init__(self, kind: str, message: str) -> None:
        self.kind = kind
        self.message = message
        super().__init__(f'[{kind}] {message}')
_PRAGMA_RE = re.compile('pragma\\s+solidity\\s+([^;]+);')
_LINE_COMMENT_RE = re.compile('//[^\\n]*')
_BLOCK_COMMENT_RE = re.compile('/\\*.*?\\*/', re.S)

def parse_pragmas(sources: dict[str, str]) -> list[str]:
    found: list[str] = []
    for name in sorted(sources):
        text = _BLOCK_COMMENT_RE.sub(' ', sources[name])
        text = _LINE_COMMENT_RE.sub(' ', text)
        for match in _PRAGMA_RE.finditer(text):
            constraint = ' '.join(match.group(1).split())
            if constraint and constraint not in found:
                found.append(constraint)
    return found
_Interval = tuple[Optional[tuple[int, int, int]], bool, Optional[tuple[int, int, int]], bool]
_UNIVERSE: _Interval = (None, False, None, False)

def _parse_version(text: str) -> tuple[int, int, int]:
    parts = text.strip().split('.')
    if not 1 <= len(parts) <= 3 or not all((p.isdigit() for p in parts)):
        raise SolcManagerError('version_conflict', f'unparseable version number: {text!r}')
    nums = [int(p) for p in parts] + [0] * (3 - len(parts))
    return (nums[0], nums[1], nums[2])

def _comparator_interval(comp: str) -> _Interval:
    comp = comp.strip()
    if comp.startswith('^'):
        base = _parse_version(comp[1:])
        upper = (0, base[1] + 1, 0) if base[0] == 0 else (base[0] + 1, 0, 0)
        return (base, True, upper, False)
    if comp.startswith('~'):
        base = _parse_version(comp[1:])
        return (base, True, (base[0], base[1] + 1, 0), False)
    for op in ('>=', '<=', '==', '>', '<', '='):
        if comp.startswith(op):
            version = _parse_version(comp[len(op):])
            if op == '>=':
                return (version, True, None, False)
            if op == '>':
                return (version, False, None, False)
            if op == '<=':
                return (None, False, version, True)
            if op == '<':
                return (None, False, version, False)
            return (version, True, version, True)
    version = _parse_version(comp)
    return (version, True, version, True)

def _split_comparators(part: str) -> list[str]:
    joined = re.sub('([<>=~^])\\s+', '\\1', part)
    tokens = joined.split()
    comparators = []
    for token in tokens:
        if re.match('^[~^<>=]*\\d', token):
            comparators.append(token)
        elif token:
            raise SolcManagerError('version_conflict', f'unparseable pragma fragment: {token!r}')
    return comparators

def _intersect(a: _Interval, b: _Interval) -> Optional[_Interval]:
    if a is None or b is None:
        return None
    lo_a, lo_inc_a, hi_a, hi_inc_a = a
    lo_b, lo_inc_b, hi_b, hi_inc_b = b
    if lo_a is None:
        lo, lo_inc = (lo_b, lo_inc_b)
    elif lo_b is None:
        lo, lo_inc = (lo_a, lo_inc_a)
    elif lo_a > lo_b:
        lo, lo_inc = (lo_a, lo_inc_a)
    elif lo_b > lo_a:
        lo, lo_inc = (lo_b, lo_inc_b)
    else:
        lo, lo_inc = (lo_a, lo_inc_a and lo_inc_b)
    if hi_a is None:
        hi, hi_inc = (hi_b, hi_inc_b)
    elif hi_b is None:
        hi, hi_inc = (hi_a, hi_inc_a)
    elif hi_a < hi_b:
        hi, hi_inc = (hi_a, hi_inc_a)
    elif hi_b < hi_a:
        hi, hi_inc = (hi_b, hi_inc_b)
    else:
        hi, hi_inc = (hi_a, hi_inc_a and hi_inc_b)
    if lo is not None and hi is not None:
        if lo > hi or (lo == hi and (not (lo_inc and hi_inc))):
            return None
    return (lo, lo_inc, hi, hi_inc)

def _contains(interval: _Interval, version: tuple[int, int, int]) -> bool:
    lo, lo_inc, hi, hi_inc = interval
    if lo is not None:
        if version < lo or (version == lo and (not lo_inc)):
            return False
    if hi is not None:
        if version > hi or (version == hi and (not hi_inc)):
            return False
    return True

def resolve_solc_version(pragmas: list[str]) -> str:
    if not pragmas:
        return SOLC_RELEASES[-1]
    solution: list[_Interval] = [_UNIVERSE]
    for pragma in pragmas:
        alternatives: list[_Interval] = []
        for part in pragma.split('||'):
            comparators = _split_comparators(part)
            if not comparators:
                continue
            interval: _Interval = _UNIVERSE
            for comp in comparators:
                merged = _intersect(interval, _comparator_interval(comp))
                if merged is None:
                    interval = None
                    break
                interval = merged
            if interval is not None:
                alternatives.append(interval)
        if not alternatives:
            raise SolcManagerError('version_conflict', f'the pragma constraint itself is empty: {pragma!r}')
        solution = [merged for alt in alternatives for prev in solution if (merged := _intersect(prev, alt)) is not None]
        if not solution:
            raise SolcManagerError('version_conflict', f'the intersection of multi-file pragma version constraints is empty: {pragmas}')
    candidates = [release for release in SOLC_RELEASES if any((_contains(interval, _parse_version(release)) for interval in solution))]
    if not candidates:
        raise SolcManagerError('version_conflict', f'Constraint {pragmas} has no satisfying version among known solc releases ({SOLC_RELEASES[0]}–{SOLC_RELEASES[-1]})')
    lower_bounds = [iv[0] for iv in solution if iv[0] is not None]
    if lower_bounds:
        binding = max(lower_bounds)
        same_minor = [r for r in candidates if _parse_version(r)[:2] == binding[:2]]
        if same_minor:
            return same_minor[-1]
    return candidates[-1]

def ensure_solc(version: str) -> str:
    if version not in SOLC_RELEASES:
        if _parse_version(version) < _parse_version(_MIN_SOLC_VERSION):
            raise SolcManagerError('install_failed', f'solc {version} is below the minimum version supported by py-solc-x {_MIN_SOLC_VERSION}; automatic installation is unavailable (and there is no corresponding Windows binary)')
        raise SolcManagerError('install_failed', f'solc {version} is not in the known release list and cannot be installed')
    try:
        installed = {str(v) for v in solcx.get_installed_solc_versions()}
    except Exception:
        installed = set()
    if version not in installed:
        try:
            solcx.install_solc(version)
        except Exception as exc:
            raise SolcManagerError('install_failed', f'solc {version} download/installation failed ({type(exc).__name__}): {exc}') from exc
    try:
        return str(_solcx_get_executable(version))
    except Exception as exc:
        raise SolcManagerError('install_failed', f'failed to get the solc {version} executable path: {exc}') from exc

def compile_sources(sources: dict[str, str], version: str, *, work_dir: str | Path | None=None, solc_path: str | None=None) -> dict:
    if work_dir is None:
        work_dir = Path(tempfile.mkdtemp(prefix='deficoser_solc_'))
        cleanup = True
    else:
        work_dir = Path(work_dir)
        cleanup = False
    try:
        for rel, content in sources.items():
            target = work_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding='utf-8')
        if solc_path is None:
            solc_path = ensure_solc(version)
        at_depth: dict[str, int] = {}
        at_dirs: dict[str, Path] = {}
        for rel in sources:
            segments = rel.split('/')
            for index, segment in enumerate(segments[:-1]):
                if segment.startswith('@'):
                    if segment not in at_depth or index < at_depth[segment]:
                        at_depth[segment] = index
                        at_dirs[segment] = work_dir.joinpath(*segments[:index + 1])
                    break
        remappings = [f'{name}/={directory.resolve().as_posix()}/' for name, directory in sorted(at_dirs.items())]
        input_data = {'language': 'Solidity', 'sources': {rel: {'urls': [str((work_dir / rel).resolve())]} for rel in sources}, 'settings': {'optimizer': {'enabled': False}, 'remappings': remappings, 'outputSelection': {'*': {'*': ['abi'], '': ['ast']}}}}
        try:
            output = solcx.compile_standard(input_data, allow_paths=str(work_dir.resolve()), solc_binary=solc_path, allow_empty=True)
        except SolcError as exc:
            items = getattr(exc, 'error_dict', None) or []
            errors = [i.get('formattedMessage') or str(i) for i in items if i.get('severity') == 'error']
            warnings = [i.get('formattedMessage') or str(i) for i in items if i.get('severity') != 'error']
            return {'success': False, 'errors': errors or [str(exc)], 'warnings': warnings, 'sources': {}, 'contracts': {}, 'solc_version': version}
        except Exception as exc:
            return {'success': False, 'errors': [f'{type(exc).__name__}: {exc}'], 'warnings': [], 'sources': {}, 'contracts': {}, 'solc_version': version}
        error_items = [item for item in output.get('errors', []) if item.get('severity') == 'error']
        errors = [item.get('formattedMessage') or str(item) for item in error_items]
        warnings = [item.get('formattedMessage') or str(item) for item in output.get('errors', []) if item.get('severity') != 'error']
        normalized: dict[str, dict] = {}
        for key, payload in output.get('sources', {}).items():
            rel_key = _normalize_key(key, work_dir)
            normalized[rel_key] = {'ast': payload.get('ast')}
        return {'success': not error_items, 'errors': errors, 'warnings': warnings, 'sources': normalized, 'contracts': output.get('contracts', {}), 'solc_version': version}
    finally:
        if cleanup:
            shutil.rmtree(work_dir, ignore_errors=True)

def _normalize_key(key: str, work_dir: Path) -> str:
    path = Path(key)
    try:
        return path.resolve().relative_to(work_dir.resolve()).as_posix()
    except (ValueError, OSError):
        return key.replace('\\', '/')
