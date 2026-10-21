from __future__ import annotations
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from deficoser.tools.foundry_std import stdlib_for_solc
from deficoser.tools.solc_manager import SolcManagerError, _comparator_interval, _contains, _intersect, _parse_version, _split_comparators, _UNIVERSE, parse_pragmas
_EVIDENCE_RE = re.compile('emit Evidence\\(category: "((?:[^"\\\\]|\\\\.)*)", detail: "((?:[^"\\\\]|\\\\.)*)"\\)')
_FAIL_RE = re.compile('\\[FAIL(?::|\\. Reason:)\\s*([^\\]]*)\\]')
_SUITE_RE = re.compile('Suite result: (ok|FAILED)\\. (\\d+) passed; (\\d+) failed')
_TOTAL_RE = re.compile('(\\d+) tests? passed, (\\d+) failed, (\\d+) skipped \\((\\d+) total tests\\)')
_COMPILE_ERROR_RE = re.compile('^Error \\(\\d+\\): (.+)$', re.M)
_PER_TEST_RE = re.compile('^\\[(PASS|FAIL)([^\\]]*)\\]\\s+([A-Za-z_$][\\w$]*)', re.M)
_DEFAULT_TEST_FILENAME = 'Exploit.t.sol'
_DEFAULT_ATTACK_FILENAME = 'Attack.sol'
_LOGS_TAIL_LINES = 80

def parse_evidence(output: str) -> list[dict]:
    return [{'category': m.group(1), 'detail': m.group(2)} for m in _EVIDENCE_RE.finditer(output)]

def parse_test_outcome(output: str) -> dict:
    if 'No tests found' in output:
        return {'test_passed': False, 'revert_reason': "no tests matched pattern 'testExploit.*' (tests must be named testExploit_*)", 'total_tests': 0}
    suites = _SUITE_RE.findall(output)
    total_match = _TOTAL_RE.search(output)
    total_tests = int(total_match.group(4)) if total_match else sum((int(p) + int(f) for _, p, f in suites)) if suites else 0
    passed = bool(suites) and all((s == 'ok' for s, _, _ in suites)) and (total_tests > 0)
    reason: str | None = None
    fail = _FAIL_RE.search(output)
    if fail:
        reason = fail.group(1).strip() or None
    return {'test_passed': passed, 'revert_reason': reason, 'total_tests': total_tests}

def parse_per_test_results(output: str) -> dict[str, dict]:
    results: dict[str, dict] = {}
    for m in _PER_TEST_RE.finditer(output):
        status, suffix, name = (m.group(1), m.group(2), m.group(3))
        reason: str | None = None
        if status == 'FAIL':
            reason = suffix.strip().lstrip(':').strip() or None
        results[name] = {'passed': status == 'PASS', 'reason': reason}
    return results

def parse_compile_errors(output: str) -> list[str]:
    errors: list[str] = []
    lines = output.splitlines()
    for i, line in enumerate(lines):
        m = re.match('^Error \\(\\d+\\): (.+)$', line)
        if m:
            entry = m.group(1)
            for j in range(i + 1, min(i + 4, len(lines))):
                loc = re.match('^\\s*-->\\s+(\\S+)', lines[j])
                if loc:
                    entry = f"{entry} @{loc.group(1).rstrip(':')}"
                    break
            errors.append(entry)
    if not errors and ('Compiler run failed' in output or 'Error: Compilation failed' in output):
        errors = ['Compilation failed (unparsed forge output)']
    return errors

def _forge_solc_versions() -> set[str]:
    roots: list[Path] = []
    if sys.platform == 'win32':
        appdata = _env('APPDATA')
        if appdata:
            roots.append(Path(appdata) / 'svm')
    roots.append(Path.home() / '.svm')
    versions: set[str] = set()
    for root in roots:
        if not root.is_dir():
            continue
        for child in root.iterdir():
            if child.is_dir() and re.fullmatch('\\d+\\.\\d+\\.\\d+', child.name):
                versions.add(child.name)
    return versions

def _env(name: str) -> str | None:
    return os.environ.get(name)

def _satisfies_pragma(version: tuple[int, int, int], pragma: str) -> bool:
    for part in pragma.split('||'):
        try:
            comparators = _split_comparators(part)
        except SolcManagerError:
            return False
        interval = _UNIVERSE
        for comp in comparators:
            merged = _intersect(interval, _comparator_interval(comp))
            if merged is None:
                interval = None
                break
            interval = merged
        if interval is not None and _contains(interval, version):
            return True
    return False

def _resolve_solc(sources: dict[str, str], requested: str) -> tuple[str, str]:
    available = _forge_solc_versions()
    if requested in available:
        return (requested, '')
    try:
        parsed = _parse_version(requested)
    except SolcManagerError:
        return (requested, '')
    pragmas = parse_pragmas(sources)
    candidates = [version for version in available if all((_satisfies_pragma(_parse_version(version), p) for p in pragmas))]
    if candidates:
        chosen = max(candidates, key=_parse_version)
        return (chosen, f'solc {requested} not in the local forge cache; using the latest cached version satisfying the pragma: {chosen}')
    return (requested, f'solc {requested} is not in the local forge cache and no compatible alternative version; forge will try to fetch it')

class FoundryRunner:

    def __init__(self, forge_bin: str='forge', keep_workspace: bool=False, workspace_root: str | Path | None=None) -> None:
        self.forge_bin = forge_bin
        self.keep_workspace = keep_workspace
        self.workspace_root = workspace_root

    def run(self, sources: dict[str, str], test_code: str, attack_code: str, solc_version: str, timeout: int=600, *, test_filename: str | None=None, attack_filename: str | None=None, match_test: str | None='testExploit.*') -> dict:
        started = time.perf_counter()
        workspace = Path(tempfile.mkdtemp(prefix='deficoser_poc_', dir=self.workspace_root))
        result: dict = {'compiled': False, 'compile_errors': [], 'test_passed': False, 'revert_reason': None, 'evidence': [], 'per_test': {}, 'logs': [], 'duration_ms': 0.0, 'timed_out': False, 'solc_requested': solc_version, 'solc_used': solc_version, 'solc_note': '', 'workspace': None}
        try:
            solc_used, solc_note = _resolve_solc(sources, solc_version)
            result['solc_used'] = solc_used
            result['solc_note'] = solc_note
            self._write_workspace(workspace, sources, test_code, attack_code, solc_used, test_filename or _DEFAULT_TEST_FILENAME, attack_filename or _DEFAULT_ATTACK_FILENAME)
            build = self._run_command([self.forge_bin, 'build'], workspace, timeout)
            result['logs'] = _tail_lines(build['output'], _LOGS_TAIL_LINES)
            if build['timed_out']:
                result['timed_out'] = True
                result['compile_errors'] = [f'forge build timed out after {timeout}s']
                return result
            if build['returncode'] != 0 or 'Compiler run failed' in build['output']:
                result['compile_errors'] = parse_compile_errors(build['output'])
                return result
            result['compiled'] = True
            if match_test is None:
                return result
            test = self._run_command([self.forge_bin, 'test', '--match-test', match_test, '-vvvv'], workspace, timeout)
            output = test['output']
            result['logs'] = _tail_lines(output, _LOGS_TAIL_LINES)
            if test['timed_out']:
                result['timed_out'] = True
                result['revert_reason'] = f'forge test timed out after {timeout}s'
                return result
            outcome = parse_test_outcome(output)
            result['test_passed'] = outcome['test_passed']
            result['revert_reason'] = outcome['revert_reason']
            result['evidence'] = parse_evidence(output)
            result['per_test'] = parse_per_test_results(output)
            return result
        except FileNotFoundError as exc:
            result['compile_errors'] = [f'forge not available: {exc}']
            return result
        except OSError as exc:
            result['compile_errors'] = [f'workspace setup/execution failed: {type(exc).__name__}: {exc}']
            return result
        finally:
            result['duration_ms'] = (time.perf_counter() - started) * 1000
            if self.keep_workspace:
                result['workspace'] = str(workspace)
            else:
                shutil.rmtree(workspace, ignore_errors=True)

    def _write_workspace(self, workspace: Path, sources: dict[str, str], test_code: str, attack_code: str, solc_used: str, test_filename: str, attack_filename: str) -> None:
        (workspace / 'src').mkdir(parents=True, exist_ok=True)
        (workspace / 'test').mkdir(parents=True, exist_ok=True)
        (workspace / 'std').mkdir(parents=True, exist_ok=True)
        for rel, content in sources.items():
            is_test_source = (rel.endswith('.t.sol') or rel.startswith('test/')) and (not rel.startswith('src/'))
            if is_test_source:
                target = workspace / 'test' / (rel[len('test/'):] if rel.startswith('test/') else rel)
            else:
                target = workspace / 'src' / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding='utf-8', newline='\n')
        if attack_code.strip():
            attack_rel = Path('test') / attack_filename if attack_filename.endswith('.t.sol') else Path('src') / attack_filename
            (workspace / attack_rel).write_text(attack_code, encoding='utf-8', newline='\n')
        if test_code.strip():
            (workspace / 'test' / test_filename).write_text(test_code, encoding='utf-8', newline='\n')
        for name, content in stdlib_for_solc(solc_used).items():
            (workspace / 'std' / name).write_text(content, encoding='utf-8', newline='\n')
        remappings = ['forge-std/=std/']
        at_dirs: dict[str, tuple[int, Path]] = {}
        for rel in sources:
            segments = rel.split('/')
            for index, segment in enumerate(segments[:-1]):
                if segment.startswith('@'):
                    depth, _prev = at_dirs.get(segment, (10 ** 9, None))
                    if index < depth:
                        at_dirs[segment] = (index, (workspace / 'src').joinpath(*segments[:index + 1]))
                    break
        for name, (_depth, directory) in sorted(at_dirs.items()):
            remappings.append(f'{name}/={directory.resolve().as_posix()}/')
        toml = ['[profile.default]', 'src = "src"', 'test = "test"', 'out = "out"', 'libs = ["lib"]', f'solc = "{solc_used}"', 'remappings = [' + ', '.join((f'"{r}"' for r in remappings)) + ']']
        (workspace / 'foundry.toml').write_text('\n'.join(toml) + '\n', encoding='utf-8', newline='\n')

    def _run_command(self, args: list[str], cwd: Path, timeout: int) -> dict[str, object]:
        try:
            proc = subprocess.run(args, cwd=str(cwd), capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=timeout)
            return {'returncode': proc.returncode, 'output': (proc.stdout or '') + '\n' + (proc.stderr or ''), 'timed_out': False}
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout or ''
            err = exc.stderr or ''
            if isinstance(out, bytes):
                out = out.decode('utf-8', errors='replace')
            if isinstance(err, bytes):
                err = err.decode('utf-8', errors='replace')
            return {'returncode': None, 'output': str(out) + '\n' + str(err), 'timed_out': True}

def _tail_lines(text: str, n: int) -> list[str]:
    lines = text.splitlines()
    return lines[-n:] if len(lines) > n else lines
