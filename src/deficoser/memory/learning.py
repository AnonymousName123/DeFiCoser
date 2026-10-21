from __future__ import annotations
import json
import logging
import math
import re
import time
from pathlib import Path
from typing import Any
import pandas as pd
from deficoser.config import DATA_DIR, LOGS_DIR
from deficoser.memory.schemas import PATTERN_SCHEMA
from deficoser.tools.ast_extractor import build_import_graph
logger = logging.getLogger('deficoser.memory')
LEARNING_LOG_FILENAME = 'learning.jsonl'
DATASET_FILENAME = 'AC_dataset.xlsx'
TX_FOLDER_MAP_FILENAME = '_tx_folder_map.json'
INVALID_PROTOCOL = 'logic contract unverified'
TEMPLATES_DIR = Path(__file__).parent / 'templates'
_MAX_SOURCES_CHARS = 48000
_MAX_SOURCE_FILES = 8
_MAX_TIMELINE_CHARS = 6000
_MAX_EVENT_ROWS = 40
_MAX_EVENT_ROWS_CHARS = 6000
_SOURCE_HEADER_CHARS = 2000
_SOURCE_WINDOW_CHARS = 1600
_SOURCE_MAX_WINDOWS = 4

def parse_loss_usd(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        if isinstance(value, float) and math.isnan(value):
            return None
        return float(value)
    text = str(value).strip().replace(',', '').replace('$', '')
    if not text or text.lower() == 'nan':
        return None
    match = re.fullmatch('([\\d.]+)\\s*([KkMmBb]?)', text)
    if not match:
        return None
    multiplier = {'': 1.0, 'k': 1000.0, 'm': 1000000.0, 'b': 1000000000.0}[match.group(2).lower()]
    return float(match.group(1)) * multiplier

def parse_date(value: Any) -> str | None:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return None
    try:
        digits = str(int(value))
    except (TypeError, ValueError):
        return None
    if len(digits) != 8:
        return None
    year, month, day = (digits[:4], digits[4:6], digits[6:])
    if not (1 <= int(month) <= 12 and 1 <= int(day) <= 31):
        return None
    return f'{year}-{month}-{day}'

def parse_vulnerable_functions(value: Any) -> list[str]:
    if not isinstance(value, str) or not value.strip():
        return []
    return [part.strip() for part in re.split('[,;\\n]+', value) if part.strip()]

def _normalize_name(name: str) -> str:
    return re.sub('[^a-z0-9]', '', name.lower())

def _normalize_dir_base(name: str) -> str:
    stripped = re.sub('\\(\\d+\\)\\s*$', '', str(name).strip())
    return _normalize_name(stripped)

def _resolve_contract_dir(contract_root: Path, protocol: str) -> Path | None:
    if not contract_root.is_dir():
        return None
    target = _normalize_name(protocol)
    for entry in sorted(contract_root.iterdir()):
        if entry.is_dir() and (not entry.name.startswith('.')) and (_normalize_name(entry.name) == target):
            return entry
    return None

def _resolve_event_dir(event_root: Path, chain: str, protocol: str, tx_hashes: list[str], tx_map: dict[str, str]) -> Path | None:
    chain_dir = event_root / chain
    if not chain_dir.is_dir():
        return None
    for tx in tx_hashes:
        folder = tx_map.get(tx)
        if folder and (chain_dir / folder).is_dir():
            return chain_dir / folder
    target = _normalize_dir_base(protocol)
    for entry in sorted(chain_dir.iterdir()):
        if entry.is_dir() and _normalize_dir_base(entry.name) == target:
            return entry
    return None

def load_learning_cases(data_dir: str | Path | None=None) -> list[dict]:
    root = Path(data_dir) if data_dir is not None else DATA_DIR
    df = pd.read_excel(root / DATASET_FILENAME)
    event_root = root / 'Event_data'
    tx_map_path = event_root / TX_FOLDER_MAP_FILENAME
    tx_map: dict[str, str] = json.loads(tx_map_path.read_text(encoding='utf-8')) if tx_map_path.exists() else {}
    cases: list[dict] = []
    for _, row in df.iterrows():
        protocol = row.get('Protocol')
        if not isinstance(protocol, str) or not protocol.strip():
            continue
        if protocol.strip() == INVALID_PROTOCOL:
            continue
        date = parse_date(row.get('Date'))
        if date is None:
            continue
        chain = str(row.get('Chain') or '').strip().upper()
        tx_hashes = [t for t in re.split('\\s+', str(row.get('Transaction Hash') or '')) if t]
        contract_dir = _resolve_contract_dir(root / 'Contract', protocol)
        event_dir = _resolve_event_dir(event_root, chain, protocol, tx_hashes, tx_map)
        cases.append({'case_id': '', 'protocol': protocol.strip(), 'chain': chain, 'date': date, 'loss_usd': parse_loss_usd(row.get('Loss ($)')), 'tx_hash': tx_hashes[0] if tx_hashes else '', 'contract_dir': contract_dir, 'event_dir': event_dir, 'event_data': 'present' if event_dir is not None else 'missing', 'vulnerable_functions': parse_vulnerable_functions(row.get('Vulnerable Functions'))})
    cases.sort(key=lambda case: (case['date'], case['protocol']))
    for index, case in enumerate(cases, start=1):
        case['case_id'] = f'event_{index:03d}'
    logger.info('Loaded %d learning cases (ascending by date, event_001..event_%03d)', len(cases), len(cases))
    return cases

def load_pattern_prompt() -> str:
    path = TEMPLATES_DIR / 'pattern_extraction.txt'
    if not path.exists():
        raise FileNotFoundError(f'pattern_extraction prompt template not found: {path}')
    return path.read_text(encoding='utf-8-sig')

def _cap(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[:limit] + '\n... (truncated)'

def _load_contract_sources(contract_dir: Path | None) -> dict[str, str]:
    if contract_dir is None or not contract_dir.is_dir():
        return {}
    sources: dict[str, str] = {}
    for path in sorted(contract_dir.rglob('*.sol')):
        sources[path.relative_to(contract_dir).as_posix()] = path.read_text(encoding='utf-8', errors='replace')
    return sources

def _select_source_files(sources: dict[str, str], functions: list[str]) -> list[str]:
    if not sources:
        return []
    names = [name for name in functions if name]
    matched: list[str] = []
    if names:
        pattern = re.compile('(?<![A-Za-z0-9_$])(' + '|'.join((re.escape(n) for n in names)) + ')(?![A-Za-z0-9_$])')
        matched = [rel for rel, text in sources.items() if pattern.search(text)]
    if not matched:
        matched = sorted(sources, key=lambda rel: (-len(sources[rel]), rel))[:2]
        return matched[:_MAX_SOURCE_FILES]
    graph = build_import_graph(sources)
    closure = set(matched)
    queue = list(matched)
    while queue:
        for dep in graph.get(queue.pop(), []):
            if dep not in closure:
                closure.add(dep)
                queue.append(dep)
    dependencies = sorted(closure - set(matched))
    return (matched + dependencies)[:_MAX_SOURCE_FILES]

def _truncate_source(text: str, functions: list[str]) -> str:
    if len(text) <= _SOURCE_HEADER_CHARS + _SOURCE_WINDOW_CHARS * 2:
        return text
    header = text[:_SOURCE_HEADER_CHARS]
    names = [name for name in functions if name]
    positions: list[int] = []
    if names:
        pattern = re.compile('(?<![A-Za-z0-9_$])(' + '|'.join((re.escape(n) for n in names)) + ')(?![A-Za-z0-9_$])')
        positions = [match.start() for match in pattern.finditer(text)]
    if not positions:
        return header + '\n... (middle truncated) ...'
    half = _SOURCE_WINDOW_CHARS // 2
    intervals: list[tuple[int, int]] = []
    for pos in positions:
        start, end = (max(0, pos - half), min(len(text), pos + half))
        if intervals and start <= intervals[-1][1]:
            intervals[-1] = (intervals[-1][0], end)
        else:
            intervals.append((start, end))
    windows = [text[start:end] for start, end in intervals[:_SOURCE_MAX_WINDOWS]]
    return header + '\n... (middle truncated) ...\n' + '\n... (omitted) ...\n'.join(windows)

def _format_contract_sources(case: dict) -> str:
    sources = _load_contract_sources(case.get('contract_dir'))
    if not sources:
        return ' (no victim contract source directory)'
    functions = case.get('vulnerable_functions') or []
    blocks: list[str] = []
    for rel in _select_source_files(sources, functions):
        blocks.append(f'// ===== File: {rel} =====\n{_truncate_source(sources[rel], functions)}')
    return _cap('\n\n'.join(blocks), _MAX_SOURCES_CHARS)

def _format_event_timeline(event_dir: Path | None) -> str:
    if event_dir is None:
        return '(no event log directory)'
    path = event_dir / 'event.txt'
    if not path.exists():
        return ' (no event.txt timeline)'
    text = path.read_text(encoding='utf-8', errors='replace')
    return _cap(text, _MAX_TIMELINE_CHARS)

def _format_event_rows(event_dir: Path | None) -> str:
    if event_dir is None:
        return ' (no event log directory)'
    path = event_dir / 'Event.xlsx'
    if not path.exists():
        return ' (no Event.xlsx)'
    try:
        df = pd.read_excel(path)
    except Exception as exc:
        return f'(failed to read Event.xlsx: {exc})'
    lines: list[str] = [f' ({len(df)} event lines; showing the first {_MAX_EVENT_ROWS} named key lines)']
    for _, row in df.iterrows():
        name = row.get('Name')
        if not isinstance(name, str) or not name.strip():
            continue
        number = row.get('Number')
        topics = str(row.get('Topics') or '').strip()
        data = ' '.join(str(row.get('Data') or '').split())
        lines.append(f'#{number} {name.strip()} | topics={topics[:60]} | data={data[:160]}')
        if len(lines) - 1 >= _MAX_EVENT_ROWS:
            break
    return _cap('\n'.join(lines), _MAX_EVENT_ROWS_CHARS)

def _format_case_metadata(case: dict) -> str:
    return json.dumps({'protocol': case.get('protocol'), 'chain': case.get('chain'), 'date': case.get('date'), 'loss_usd': case.get('loss_usd'), 'tx_hash': case.get('tx_hash'), 'vulnerable_functions': case.get('vulnerable_functions'), 'event_data': case.get('event_data')}, ensure_ascii=False, indent=1)

def _build_messages(case: dict) -> list[dict]:
    template = load_pattern_prompt()
    system, user = _split_prompt(template)
    user = _format_placeholders(user, {'case_metadata': _format_case_metadata(case), 'contract_sources': _format_contract_sources(case), 'event_timeline': _format_event_timeline(case.get('event_dir')), 'event_rows': _format_event_rows(case.get('event_dir')), 'json_schema': json.dumps(PATTERN_SCHEMA, ensure_ascii=False)})
    return [{'role': 'system', 'content': system}, {'role': 'user', 'content': user}]

def _split_prompt(content: str) -> tuple[str, str]:
    system, user = (content, '')
    if '[INPUT]' in content:
        system, rest = content.split('[INPUT]', 1)
        if '[OUTPUT]' in rest:
            user, output_part = rest.split('[OUTPUT]', 1)
            system = system + '[OUTPUT]' + output_part
        else:
            user = rest
    return (system.strip(), user.strip())

def _format_placeholders(content: str, variables: dict[str, str]) -> str:
    text = content
    for key, value in variables.items():
        text = text.replace('{{' + key + '}}', value)
    return text

def _case_meta_fields(case: dict) -> dict:
    return {'case_id': case.get('case_id'), 'protocol': case.get('protocol'), 'chain': case.get('chain'), 'date': case.get('date'), 'loss_usd': case.get('loss_usd'), 'tx_hash': case.get('tx_hash')}

def _pattern_from_llm(case: dict, payload: dict, model: str | None, online_trace: bool) -> dict:
    pattern = dict(_case_meta_fields(case))
    pattern.update({'R': payload['R'], 'S': payload['S'], 'A': payload['A'], 'T': payload['T'], 'P': payload['P'], 'G': payload['G'], 'extraction': {'source': 'llm', 'model': model, 'online_trace': online_trace}})
    return pattern

def _fallback_pattern(case: dict, model: str | None, error: str | None=None) -> dict:
    functions = [f for f in case.get('vulnerable_functions') or [] if f]
    actions = list(functions) if functions else ['unknown']
    sink = functions[0] if functions else 'unknown'
    predicate = f"missing authorization check on {', '.join(functions)}" if functions else 'unknown'
    pattern = dict(_case_meta_fields(case))
    pattern.update({'R': {'attacker_role': 'unknown', 'description': f"{case.get('protocol')} attacker identity could not be abstracted from the offline triad (fallback)"}, 'S': {'description': 'unknown (offline event material is insufficient or LLM abstraction failed; pre-attack state unknown)'}, 'A': actions, 'T': ['unknown'], 'P': {'vulnerable_predicate': predicate, 'location': None, 'sink': sink}, 'G': {'impact_type': 'unknown', 'gain': case.get('loss_usd'), 'description': 'fallback: impact type unknown; gain records the dataset loss amount'}, 'extraction': {'source': 'fallback', 'model': model}})
    if error:
        pattern['extraction']['error'] = error
    return pattern

def extract_pattern(case: dict, llm_client: Any, online_trace: bool=False) -> dict:
    model = getattr(llm_client, 'model', None)
    if online_trace:
        logger.info('case %s marked online_trace=True (online retrieval is not implemented in this milestone; flag only)', case.get('case_id'))
    messages = _build_messages(case)
    try:
        payload = llm_client.call('pattern_extraction', messages, schema=PATTERN_SCHEMA)
        return _pattern_from_llm(case, payload, model, online_trace)
    except Exception as exc:
        logger.warning('case %s LLM abstraction failed; using fallback: %s: %s', case.get('case_id'), type(exc).__name__, exc)
        return _fallback_pattern(case, model, error=f'{type(exc).__name__}: {exc}')

def run_learning(cases: list[dict], llm_client: Any, memory: Any, log_path: str | Path | None=None) -> dict:
    log_file = Path(log_path) if log_path is not None else LOGS_DIR / LEARNING_LOG_FILENAME
    log_file.parent.mkdir(parents=True, exist_ok=True)
    stats = {'total': len(cases), 'llm_extracted': 0, 'fallback': 0, 'failed': 0}
    with open(log_file, 'a', encoding='utf-8') as fh:
        for case in cases:
            started = time.perf_counter()
            records_before = len(getattr(llm_client, 'usage_records', []) or [])
            pattern: dict | None = None
            error: str | None = None
            try:
                pattern = extract_pattern(case, llm_client)
                memory.commit_case(pattern)
            except Exception as exc:
                error = f'{type(exc).__name__}: {exc}'
                logger.exception('case %s learning-phase exception', case.get('case_id'))
            records_after = getattr(llm_client, 'usage_records', []) or []
            new_records = records_after[records_before:]
            prompt_tokens = sum((int(r.prompt_tokens) for r in new_records))
            completion_tokens = sum((int(r.completion_tokens) for r in new_records))
            source = 'failed' if pattern is None else str(pattern.get('extraction', {}).get('source', 'unknown'))
            if source == 'llm':
                stats['llm_extracted'] += 1
            elif source == 'fallback':
                stats['fallback'] += 1
            else:
                stats['failed'] += 1
            row = {'ts': time.strftime('%Y-%m-%dT%H:%M:%S%z'), 'case_id': case.get('case_id'), 'protocol': case.get('protocol'), 'source': source, 'prompt_tokens': prompt_tokens, 'completion_tokens': completion_tokens, 'total_tokens': prompt_tokens + completion_tokens, 'latency_ms': round((time.perf_counter() - started) * 1000, 1), 'error': error or pattern.get('extraction', {}).get('error'), 'online_trace': bool(pattern and pattern['extraction'].get('online_trace')), 'memory_size': getattr(memory, 'memory_size', None)}
            fh.write(json.dumps(row, ensure_ascii=False) + '\n')
    logger.info('Learning phase completed: %s', stats)
    return stats
