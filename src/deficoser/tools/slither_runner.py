from __future__ import annotations
import json
import subprocess
import sys
from pathlib import Path
SLITHER_TIMEOUT_DEFAULT = 300

def run_slither(work_dir: str | Path, solc_path: str, *, timeout: float=SLITHER_TIMEOUT_DEFAULT) -> dict:
    work = Path(work_dir)
    out_file = work / '_slither_result.json'
    command = [sys.executable, '-m', 'deficoser.tools.slither_probe', str(work), '--solc', str(solc_path), '--out', str(out_file)]
    try:
        completed = subprocess.run(command, capture_output=True, timeout=timeout, cwd=str(work))
    except subprocess.TimeoutExpired:
        return {'success': False, 'error_type': 'timeout', 'message': f'slither analysis timed out (>{timeout}s): {work}'}
    except OSError as exc:
        return {'success': False, 'error_type': 'probe_crash', 'message': f'failed to start the slither subprocess: {exc}'}
    stdout = completed.stdout.decode('utf-8', errors='replace')
    stderr = completed.stderr.decode('utf-8', errors='replace')
    if not out_file.exists():
        return {'success': False, 'error_type': 'probe_crash', 'message': _tail(f'slither probe did not produce a result file (exit={completed.returncode})\nstdout: {stdout}\nstderr: {stderr}')}
    try:
        payload = json.loads(out_file.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError) as exc:
        return {'success': False, 'error_type': 'probe_crash', 'message': f'failed to parse slither result JSON: {exc}'}
    status = payload.get('status')
    if status == 'ok':
        payload['success'] = True
        payload['analysis_source'] = 'slither'
        return payload
    return {'success': False, 'error_type': status or 'error', 'message': _tail(str(payload.get('message', '')) or stderr)}

def _tail(text: str, limit: int=2000) -> str:
    return text if len(text) <= limit else '...' + text[-limit:]
