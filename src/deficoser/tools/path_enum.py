from __future__ import annotations
from collections.abc import Iterable
from deficoser.config import PATH_LENGTH_BOUND_K

def _edge_rank(data: dict) -> tuple[int, str]:
    semantic = data.get('semantic') or ''
    return (0, semantic) if semantic else (1, '')

def _successors(graph, node: str) -> list[tuple[str, dict]]:
    best: dict[str, dict] = {}
    for _u, v, data in graph.out_edges(node, data=True):
        current = best.get(v)
        if current is None or _edge_rank(data) < _edge_rank(current):
            best[v] = dict(data)
    return sorted(best.items())

def _edge_summary(data: dict) -> dict:
    entry = {'type': data.get('type', '')}
    if data.get('semantic'):
        entry['semantic'] = data['semantic']
    return entry

def all_paths_to_targets(graph, source: str, targets: Iterable[str], k: int=PATH_LENGTH_BOUND_K) -> dict[str, list[dict]]:
    target_set = {t for t in targets if t in graph}
    results: dict[str, list[dict]] = {t: [] for t in target_set}
    if source not in graph:
        return results
    nodes: list[str] = [source]
    edges: list[dict] = []
    visited = {source}

    def _dfs(current: str, fn_count: int) -> None:
        if graph.nodes[current].get('kind') == 'function' and current in target_set:
            results[current].append({'nodes': list(nodes), 'edges': list(edges), 'length': fn_count})
        if fn_count >= k:
            return
        for nxt, data in _successors(graph, current):
            if nxt in visited:
                continue
            is_function = graph.nodes[nxt].get('kind') == 'function'
            if is_function and fn_count + 1 > k:
                continue
            nodes.append(nxt)
            edges.append(_edge_summary(data))
            visited.add(nxt)
            _dfs(nxt, fn_count + 1 if is_function else fn_count)
            nodes.pop()
            edges.pop()
            visited.discard(nxt)
    _dfs(source, 0)
    return results

def all_reachable_paths(graph, source: str, target: str, k: int=PATH_LENGTH_BOUND_K) -> list[dict]:
    return all_paths_to_targets(graph, source, [target], k).get(target, [])
