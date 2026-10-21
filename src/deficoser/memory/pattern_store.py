from __future__ import annotations
import json
import logging
from pathlib import Path
from typing import TypedDict
from deficoser.config import MEMORY_STORE_DIR
logger = logging.getLogger('deficoser.memory')
PATTERNS_FILENAME = 'patterns.jsonl'
PATTERN_REQUIRED_KEYS: tuple[str, ...] = ('case_id', 'protocol', 'chain', 'date', 'loss_usd', 'tx_hash', 'R', 'S', 'A', 'T', 'P', 'G', 'extraction')
_SUB_KEYS: dict[str, tuple[str, ...]] = {'R': ('attacker_role', 'description'), 'S': ('description',), 'P': ('vulnerable_predicate', 'location', 'sink'), 'G': ('impact_type', 'gain', 'description'), 'extraction': ('source',)}

class AttackPattern(TypedDict, total=False):
    case_id: str
    protocol: str
    chain: str
    date: str
    loss_usd: float | None
    tx_hash: str
    R: dict
    S: dict
    A: list
    T: list
    P: dict
    G: dict
    extraction: dict

def validate_pattern(pattern: dict) -> None:
    if not isinstance(pattern, dict):
        raise ValueError(f'pattern must be a dict; got {type(pattern).__name__}')
    missing = [key for key in PATTERN_REQUIRED_KEYS if key not in pattern]
    if missing:
        raise ValueError(f'pattern is missing required keys: {missing}')
    for key, sub_keys in _SUB_KEYS.items():
        sub = pattern[key]
        if not isinstance(sub, dict):
            raise ValueError(f'pattern field {key!r} must be a dict; got {type(sub).__name__}')
        sub_missing = [k for k in sub_keys if k not in sub]
        if sub_missing:
            raise ValueError(f'pattern field {key!r} is missing required keys: {sub_missing}')
    for key in ('A', 'T'):
        if not isinstance(pattern[key], list):
            raise ValueError(f'Field {key!r} must be list[str]')
    if pattern['extraction'].get('source') not in ('llm', 'fallback'):
        raise ValueError("extraction.source must be 'llm' or 'fallback'")

class PatternStore:

    def __init__(self, path: str | Path | None=None) -> None:
        if path is None:
            target = MEMORY_STORE_DIR / PATTERNS_FILENAME
        else:
            target = Path(path)
            if target.suffix != '.jsonl':
                target = target / PATTERNS_FILENAME
        self.path: Path = target
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.touch(exist_ok=True)
        self._patterns: list[dict] = self._load()

    def append(self, pattern: dict) -> dict:
        validate_pattern(pattern)
        entry = json.loads(json.dumps(pattern, ensure_ascii=False))
        with open(self.path, 'a', encoding='utf-8') as fh:
            fh.write(json.dumps(entry, ensure_ascii=False) + '\n')
        self._patterns.append(entry)
        return json.loads(json.dumps(entry, ensure_ascii=False))

    def __len__(self) -> int:
        return len(self._patterns)

    def get_all(self) -> list[dict]:
        return list(self._patterns)

    def clear(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text('', encoding='utf-8')
        self._patterns = []

    def _load(self) -> list[dict]:
        if not self.path.exists():
            return []
        patterns: list[dict] = []
        with open(self.path, encoding='utf-8') as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.warning('patterns.jsonl line %d could not be parsed and was skipped: %s', line_no, exc)
                    continue
                if not isinstance(entry, dict):
                    logger.warning('patterns.jsonl line %d is not a JSON object and was skipped', line_no)
                    continue
                patterns.append(entry)
        return patterns
