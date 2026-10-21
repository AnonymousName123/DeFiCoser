from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from deficoser.config import LOGS_DIR
JOURNAL_STAGES: tuple[str, ...] = ('contract_understanding', 'role_extraction', 'role_graph', 'adversarial_explore', 'attack_plan', 'poc_generate', 'foundry_execute', 'report')
VIOLATION_KEYS: tuple[str, ...] = ('sink', 'attacker_role', 'required_role', 'path', 'location', 'exploit_method')
_META_KEYS: tuple[str, ...] = ('case_id', 'dataset', 'time_bucket', 'config', 'llm_model', 'memory_mode', 'memory_size', 'llm_config')
_SETTABLE_FIELDS: frozenset[str] = frozenset({'case_id', 'dataset', 'time_bucket', 'config', 'llm_model', 'memory_mode', 'memory_size', 'llm_config', 'impact', 'detected', 'exploitable', 'authorization_violation', 'is_true_positive', 'is_false_positive'})
_ROW_FIELDS: tuple[str, ...] = ('case_id', 'dataset', 'time_bucket', 'config', 'llm_model', 'memory_mode', 'memory_size', 'detected', 'violations', 'exploitable', 'authorization_violation', 'impact', 'tokens', 'time_ms', 'is_true_positive', 'is_false_positive', 'llm_config', 'error')

class CaseJournal:

    def __init__(self, logs_dir: str | Path | None=None, filename: str='cases.jsonl') -> None:
        self._logs_dir = Path(logs_dir) if logs_dir is not None else LOGS_DIR
        self._filename = filename
        self._active = False
        self._reset()

    def _reset(self) -> None:
        self._meta: dict[str, Any] = {}
        self._fields: dict[str, Any] = {}
        self._violations: list[dict] = []
        self._tokens: dict[str, float] = {}
        self._time_ms: dict[str, float] = {}

    def begin_case(self, case_meta: dict) -> None:
        self._reset()
        self._meta = {key: case_meta.get(key) for key in _META_KEYS}
        self._active = True

    def finish_case(self) -> dict:
        return self._write_row(error=None)

    def fail_case(self, error: dict) -> dict:
        if not isinstance(error, dict):
            raise TypeError('error must be a dict ({node, message, fatal})')
        return self._write_row(error=error)

    def set(self, field: str, value: Any) -> None:
        self._ensure_active()
        if field not in _SETTABLE_FIELDS:
            raise ValueError(f'Field {field!r} cannot be written with set(): use add_violations() for violations, add_stage_usage() for tokens/time_ms, and fail_case() for error')
        if field == 'impact':
            if not isinstance(value, dict):
                raise TypeError('impact must be a {type, gain} dict')
            self._fields['impact'] = {'type': value.get('type'), 'gain': value.get('gain')}
        else:
            self._fields[field] = value

    def add_violations(self, violations: list[dict]) -> None:
        self._ensure_active()
        if not isinstance(violations, list):
            raise TypeError('violations must be list[dict]')
        for violation in violations:
            if not isinstance(violation, dict):
                raise TypeError('each item in violations must be a dict')
            entry = dict(violation)
            for key in VIOLATION_KEYS:
                entry.setdefault(key, None)
            self._violations.append(entry)

    def add_stage_usage(self, stage: str, tokens: float, time_ms: float) -> None:
        self._ensure_active()
        if stage not in JOURNAL_STAGES:
            raise ValueError(f'Unknown log stage {stage!r}; must be one of {JOURNAL_STAGES}')
        self._tokens[stage] = self._tokens.get(stage, 0) + tokens
        self._time_ms[stage] = self._time_ms.get(stage, 0) + time_ms

    def _write_row(self, error: dict | None) -> dict:
        self._ensure_active()
        row = self._build_row(error)
        self._logs_dir.mkdir(parents=True, exist_ok=True)
        with open(self._logs_dir / self._filename, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(row, ensure_ascii=False) + '\n')
        self._active = False
        return row

    def _build_row(self, error: dict | None) -> dict:
        merged = {**self._meta, **self._fields}
        tokens = {stage: self._tokens.get(stage, 0) for stage in JOURNAL_STAGES}
        time_ms = {stage: self._time_ms.get(stage, 0) for stage in JOURNAL_STAGES}
        tokens['total'] = sum(tokens.values())
        time_ms['total'] = sum(time_ms.values())
        impact = merged.get('impact') or {}
        row: dict[str, Any] = {}
        for field in _ROW_FIELDS:
            if field == 'violations':
                row[field] = self._violations
            elif field == 'impact':
                row[field] = {'type': impact.get('type'), 'gain': impact.get('gain')}
            elif field == 'tokens':
                row[field] = tokens
            elif field == 'time_ms':
                row[field] = time_ms
            elif field == 'error':
                row[field] = error
            else:
                row[field] = merged.get(field)
        return row

    def _ensure_active(self) -> None:
        if not self._active:
            raise RuntimeError('begin_case() has not run, or the current case already finished/failed')
