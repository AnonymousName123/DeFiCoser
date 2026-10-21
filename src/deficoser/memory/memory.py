from __future__ import annotations
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from deficoser.config import MEMORY_TOP_K, MEMORY_STORE_DIR
from deficoser.memory.pattern_store import PatternStore, validate_pattern
from deficoser.memory.retriever import PatternRetriever
logger = logging.getLogger('deficoser.memory')
MODES: tuple[str, ...] = ('streaming', 'frozen', 'none')
SNAPSHOT_VERSION = 1

def _snapshot_name(case_count: int) -> str:
    return f'snapshot_{case_count}cases.json'

class AttackPatternMemory:

    def __init__(self, store_path: str | Path | None=None, mode: str='streaming', visible_limit: int | None=None, *, backend: str='auto', allow_download: bool=False, k: int=MEMORY_TOP_K) -> None:
        if mode not in MODES:
            raise ValueError(f'Unknown memory mode {mode!r}; must be one of {MODES}')
        self._mode = mode
        self._visible_limit = visible_limit
        self._store = PatternStore(store_path)
        store_dir = self._store.path.parent
        self._retriever = PatternRetriever(backend=backend, embeddings_cache_path=store_dir / 'embeddings.npz', allow_download=allow_download, k=k)
        self._retriever.index(self._store.get_all())

    @property
    def mode(self) -> str:
        return self._mode

    def set_visible_limit(self, limit: int | None) -> None:
        if self._mode != 'streaming':
            logger.debug('set_visible_limit(%s) is a no-op in %s mode', limit, self._mode)
            return
        self._visible_limit = limit

    @property
    def memory_size(self) -> int:
        if self._mode == 'none':
            return 0
        if self._mode == 'streaming' and self._visible_limit is not None:
            return min(self._visible_limit, len(self._store))
        return len(self._store)

    @property
    def backend(self) -> str:
        return self._retriever.backend

    @property
    def embedding_model(self) -> str:
        return self._retriever.model_name

    def retrieve(self, query_text: str, k: int | None=None) -> list[dict]:
        if self._mode == 'none':
            return []
        limit = self._visible_limit if self._mode == 'streaming' and self._visible_limit is not None else None
        return self._retriever.retrieve(query_text, k, limit=limit)

    def retrieve_for_violation(self, violation: dict, profile_summary: str='') -> list[dict]:
        if self._mode == 'none':
            return []
        path = ' -> '.join((str(node) for node in violation.get('path') or []))
        parts = [f"attacker role {violation.get('attacker_role') or ''}", f"sink {violation.get('sink') or ''}", f"predicate {violation.get('predicate') or ''}", f'path {path}', str(profile_summary or '')]
        query = ' | '.join((str(p) for p in parts if p and str(p).strip()))
        return self.retrieve(query)

    def commit_case(self, pattern: dict) -> None:
        if self._mode == 'none':
            logger.debug('none mode: commit_case is a no-op (%s)', pattern.get('case_id'))
            return
        if self._mode == 'frozen':
            logger.warning('frozen mode: commit_case ignored (snapshot locked at %d patterns): %s', len(self._store), pattern.get('case_id'))
            return
        validate_pattern(pattern)
        self._store.append(pattern)
        self._retriever.add(pattern)
        if self._visible_limit is not None:
            self._visible_limit = min(self._visible_limit + 1, len(self._store))
        logger.info('streaming mode: appended pattern %s (memory_size=%d)', pattern.get('case_id'), self.memory_size)

    def snapshot(self, path: str | Path | None=None) -> Path:
        patterns = self._store.get_all()
        target = Path(path) if path is not None else self._store.path.parent / _snapshot_name(len(patterns))
        payload = {'meta': {'version': SNAPSHOT_VERSION, 'generated_at': datetime.now(timezone.utc).isoformat(), 'case_count': len(patterns), 'embedding_backend': self._retriever.backend, 'embedding_model': self._retriever.model_name}, 'patterns': patterns}
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')
        logger.info('snapshot saved: %s (%d patterns)', target, len(patterns))
        return target

    def load_snapshot(self, path: str | Path) -> int:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
        patterns = data.get('patterns') or []
        for pattern in patterns:
            validate_pattern(pattern)
        self._store.clear()
        for pattern in patterns:
            self._store.append(pattern)
        self._retriever.index(self._store.get_all())
        self._visible_limit = None
        logger.info('snapshot loaded: %s (%d patterns, meta=%s)', path, len(patterns), data.get('meta'))
        return len(patterns)

    def get_all(self) -> list[dict]:
        return self._store.get_all()

    def __len__(self) -> int:
        return len(self._store)

def default_store_dir() -> Path:
    return MEMORY_STORE_DIR
