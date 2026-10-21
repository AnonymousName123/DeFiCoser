from __future__ import annotations
import copy
import hashlib
import logging
import math
from collections import Counter
from pathlib import Path
import numpy as np
from deficoser.config import FASTEMBED_CACHE_DIR, FASTEMBED_MODEL, MEMORY_STORE_DIR, MEMORY_TOP_K
logger = logging.getLogger('deficoser.memory')
EMBEDDINGS_CACHE_FILENAME = 'embeddings.npz'
_NGRAM_SIZE = 3

def pattern_to_text(pattern: dict) -> str:
    role = pattern.get('R') or {}
    predicate = pattern.get('P') or {}
    impact = pattern.get('G') or {}
    state = pattern.get('S') or {}
    actions = ' -> '.join((str(a) for a in pattern.get('A') or []))
    transitions = ' -> '.join((str(t) for t in pattern.get('T') or []))
    parts = [f"attacker role {role.get('attacker_role', '')}", f"vulnerable predicate {predicate.get('vulnerable_predicate', '')}", f"sink {predicate.get('sink', '')}", f'actions {actions}', f"impact {impact.get('impact_type', '')}", f"protocol {pattern.get('protocol', '')}", f"state {state.get('description', '')}", f'transitions {transitions}']
    return ' | '.join((str(p) for p in parts if p and str(p).strip()))

def _text_hash(text: str) -> str:
    return hashlib.sha1(text.encode('utf-8')).hexdigest()

def _char_ngrams(text: str, n: int=_NGRAM_SIZE) -> Counter:
    normalized = ' '.join(text.lower().split())
    if not normalized:
        return Counter()
    if len(normalized) <= n:
        return Counter({normalized: 1})
    return Counter((normalized[i:i + n] for i in range(len(normalized) - n + 1)))

class PatternRetriever:

    def __init__(self, *, backend: str='auto', embeddings_cache_path: str | Path | None=None, allow_download: bool=False, k: int=MEMORY_TOP_K) -> None:
        if backend not in ('auto', 'fastembed', 'tfidf'):
            raise ValueError(f'Unknown retrieval backend {backend!r}; must be one of auto / fastembed / tfidf')
        self._k = k
        self._embeddings_cache_path = Path(embeddings_cache_path) if embeddings_cache_path is not None else MEMORY_STORE_DIR / EMBEDDINGS_CACHE_FILENAME
        self._patterns: list[dict] = []
        self._texts: list[str] = []
        self._model = None
        self._vectors: list[np.ndarray] = []
        self._doc_vectors: list[dict[str, float]] = []
        self._idf_values: dict[str, float] = {}
        self._resolve_backend(backend, allow_download)

    @property
    def backend(self) -> str:
        return 'fastembed' if self._model is not None else 'tfidf_3gram'

    @property
    def model_name(self) -> str:
        if self._model is not None:
            return FASTEMBED_MODEL
        return 'char-3gram-tfidf'

    def _resolve_backend(self, backend: str, allow_download: bool) -> None:
        if backend == 'tfidf':
            return
        if backend in ('auto', 'fastembed'):
            try:
                from fastembed import TextEmbedding
                self._model = TextEmbedding(model_name=FASTEMBED_MODEL, cache_dir=str(FASTEMBED_CACHE_DIR), local_files_only=not allow_download)
                logger.info('retrieval backend = fastembed (%s)', FASTEMBED_MODEL)
            except Exception as exc:
                self._model = None
                if backend == 'fastembed':
                    logger.warning('fastembed backend unavailable; falling back to TF-IDF: %s', exc)
                else:
                    logger.info('fastembed unavailable (%s); falling back to character 3-gram TF-IDF', exc)

    def index(self, patterns: list[dict]) -> None:
        self._patterns = [copy.deepcopy(p) for p in patterns]
        self._texts = [pattern_to_text(p) for p in patterns]
        if self._model is not None:
            self._rebuild_fastembed()
        else:
            self._rebuild_tfidf()

    def add(self, pattern: dict) -> None:
        self._patterns.append(copy.deepcopy(pattern))
        self._texts.append(pattern_to_text(pattern))
        if self._model is not None:
            vector = self._embed_texts([self._texts[-1]])[0]
            self._vectors.append(vector)
            self._save_embeddings_cache()
        else:
            self._rebuild_tfidf()

    def __len__(self) -> int:
        return len(self._patterns)

    def retrieve(self, query_text: str, k: int | None=None, *, limit: int | None=None) -> list[dict]:
        n = len(self._patterns) if limit is None else min(max(limit, 0), len(self._patterns))
        if n == 0:
            return []
        k_eff = min(k if k is not None else self._k, n)
        if k_eff <= 0:
            return []
        scores = self._scores(query_text, n)
        order = sorted(range(n), key=lambda i: (-scores[i], i))
        return [copy.deepcopy(self._patterns[i]) for i in order[:k_eff]]

    def _scores(self, query_text: str, n: int) -> list[float]:
        if self._model is not None:
            qvec = self._embed_texts([query_text])[0]
            matrix = np.vstack([v / (np.linalg.norm(v) or 1.0) for v in self._vectors[:n]])
            return [float(x) for x in matrix @ qvec]
        query_vec = self._tfidf_vector(_char_ngrams(query_text), normalized=True)
        if not query_vec:
            return [0.0] * n
        return [self._dot(query_vec, doc_vec) if doc_vec else 0.0 for doc_vec in self._doc_vectors[:n]]

    def _dot(self, a: dict[str, float], b: dict[str, float]) -> float:
        if len(b) < len(a):
            a, b = (b, a)
        return sum((weight * b.get(gram, 0.0) for gram, weight in a.items()))

    def _embed_texts(self, texts: list[str]) -> list[np.ndarray]:
        assert self._model is not None
        vectors = [np.asarray(v, dtype=np.float32) for v in self._model.embed(texts)]
        return [v / (np.linalg.norm(v) or 1.0) for v in vectors]

    def _rebuild_fastembed(self) -> None:
        cached = self._load_embeddings_cache()
        self._vectors = []
        missing_positions: list[int] = []
        for i, text in enumerate(self._texts):
            vector = cached.get((self._patterns[i].get('case_id'), _text_hash(text)))
            if vector is not None:
                self._vectors.append(vector)
            else:
                self._vectors.append(np.zeros(0, dtype=np.float32))
                missing_positions.append(i)
        if missing_positions:
            new_vectors = self._embed_texts([self._texts[i] for i in missing_positions])
            for pos, vector in zip(missing_positions, new_vectors):
                self._vectors[pos] = vector
        self._save_embeddings_cache()

    def _load_embeddings_cache(self) -> dict[tuple[str | None, str], np.ndarray]:
        path = self._embeddings_cache_path
        if not path.exists():
            return {}
        try:
            with np.load(path, allow_pickle=False) as data:
                if str(data['backend'][()]) != 'fastembed' or str(data['model'][()]) != FASTEMBED_MODEL:
                    return {}
                case_ids = [str(x) for x in data['case_ids'].tolist()]
                hashes = [str(x) for x in data['text_hashes'].tolist()]
                vectors = data['vectors']
            if not len(case_ids) == len(hashes) == len(vectors):
                return {}
            return {(case_id, text_hash): np.asarray(vector, dtype=np.float32) for case_id, text_hash, vector in zip(case_ids, hashes, vectors)}
        except Exception as exc:
            logger.warning('failed to read embedding cache %s (ignoring and recomputing): %s', path, exc)
            return {}

    def _save_embeddings_cache(self) -> None:
        path = self._embeddings_cache_path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            case_ids = [str(p.get('case_id')) for p in self._patterns]
            hashes = [_text_hash(t) for t in self._texts]
            dim = self._vectors[0].shape[0] if self._vectors else 0
            vectors = np.vstack(self._vectors).astype(np.float32) if self._vectors and dim else np.zeros((0, 0), dtype=np.float32)
            np.savez(path, backend=np.array('fastembed'), model=np.array(FASTEMBED_MODEL), case_ids=np.array(case_ids), text_hashes=np.array(hashes), vectors=vectors)
        except Exception as exc:
            logger.warning('failed to write embedding cache %s (retrieval unaffected): %s', path, exc)

    def _idf(self) -> dict[str, float]:
        n_docs = len(self._texts)
        df: Counter = Counter()
        for text in self._texts:
            df.update(set(_char_ngrams(text)))
        return {gram: math.log((1 + n_docs) / (1 + doc_freq)) + 1.0 for gram, doc_freq in df.items()}

    def _tfidf_vector(self, grams: Counter, *, normalized: bool) -> dict[str, float]:
        if not grams:
            return {}
        vector = {gram: count * self._idf_values.get(gram, math.log(1 + len(self._texts)) + 1.0) for gram, count in grams.items()}
        if normalized:
            norm = math.sqrt(sum((w * w for w in vector.values())))
            if norm > 0:
                vector = {gram: w / norm for gram, w in vector.items()}
        return vector

    def _rebuild_tfidf(self) -> None:
        self._idf_values = self._idf()
        self._doc_vectors = [self._tfidf_vector(_char_ngrams(text), normalized=True) for text in self._texts]
