from __future__ import annotations
import json
from pathlib import Path
from deficoser.config import APP_CONFIG_DIR
SINK_KEYWORDS_FILE = APP_CONFIG_DIR / 'sink_keywords.json'
_FALLBACK_KEYWORDS: dict[str, list[str]] = {'seed_sinks': ['mint', 'withdraw', 'transferownership', 'setoracle', 'setprice', 'setfee', 'setltv', 'pause', 'unpause', 'upgradeto', 'setgovernance', 'grantrole', 'setadmin', 'renounceownership', 'revokerole', 'sweep', 'setstrategy', 'setvault', 'setcontroller', 'settreasury', 'setkeeper', 'setoperator', 'setminter', 'setpauser', 'setburner', 'setallocator', 'emergencywithdraw', 'setreward', 'setratio', 'setlimit', 'setcap', 'setamplitude'], 'gov_keywords': ['transferownership', 'setgovernance', 'grantrole', 'revokerole', 'renounceownership', 'setadmin', 'upgradeto', 'setoracle', 'setstrategy', 'setvault', 'setcontroller', 'setkeeper', 'setoperator', 'setminter', 'setpauser', 'setburner', 'setallocator', 'settreasury', 'setowner', 'addowner', 'removeowner', 'setgovernor'], 'pause_keywords': ['pause', 'unpause', 'setpaused']}
MAX_PROPAGATION_ROUNDS = 5

def load_sink_keywords(path: str | Path | None=None) -> dict[str, list[str]]:
    file = Path(path) if path is not None else SINK_KEYWORDS_FILE
    data: dict = {}
    try:
        data = json.loads(file.read_text(encoding='utf-8'))
    except (OSError, json.JSONDecodeError):
        data = {}
    keywords: dict[str, list[str]] = {}
    for group, fallback in _FALLBACK_KEYWORDS.items():
        value = data.get(group)
        keywords[group] = [str(k).lower() for k in value if str(k).strip()] if isinstance(value, list) else list(fallback)
    return keywords

def _match(name: str, keywords: list[str]) -> str | None:
    lowered = (name or '').lower()
    for keyword in keywords:
        if keyword in lowered:
            return keyword
    return None

def detect_sinks(functions: list[dict], state_vars: list[dict] | None=None, *, keywords: dict[str, list[str]] | None=None, max_rounds: int=MAX_PROPAGATION_ROUNDS) -> dict:
    if keywords is None:
        keywords = load_sink_keywords()
    seed_keywords = keywords.get('seed_sinks') or _FALLBACK_KEYWORDS['seed_sinks']
    gov_keywords = keywords.get('gov_keywords') or _FALLBACK_KEYWORDS['gov_keywords']
    pause_keywords = keywords.get('pause_keywords') or _FALLBACK_KEYWORDS['pause_keywords']
    sinks: dict[str, dict] = {}
    order: list[str] = []
    gov_functions: list[str] = []
    pause_functions: list[str] = []

    def _add_sink(fqn: str, entry: dict) -> None:
        if fqn not in sinks:
            sinks[fqn] = entry
            order.append(fqn)
    for function in functions:
        fqn = function.get('fqn') or ''
        if not fqn:
            continue
        if function.get('name') == 'constructor':
            continue
        keyword = _match(function.get('name', ''), seed_keywords)
        if keyword is not None:
            _add_sink(fqn, {'function_fqn': fqn, 'reason': 'keyword', 'keyword': keyword})
        if _match(function.get('name', ''), gov_keywords) is not None:
            gov_functions.append(fqn)
        if _match(function.get('name', ''), pause_keywords) is not None:
            pause_functions.append(fqn)
    sensitive_states: set[str] = set()
    for _ in range(max_rounds):
        changed = False
        for function in functions:
            fqn = function.get('fqn') or ''
            if not fqn or fqn in sinks or function.get('name') == 'constructor':
                continue
            if sensitive_states.intersection(function.get('state_writes') or []):
                _add_sink(fqn, {'function_fqn': fqn, 'reason': 'propagation'})
                changed = True
        new_sensitive = set(sensitive_states)
        for function in functions:
            if function.get('fqn') in sinks:
                new_sensitive.update(function.get('state_writes') or [])
        if new_sensitive != sensitive_states:
            sensitive_states = new_sensitive
            changed = True
        if not changed:
            break
    return {'sinks': [sinks[fqn] for fqn in order], 'sensitive_states': sorted(sensitive_states), 'gov_functions': gov_functions, 'pause_functions': pause_functions}
