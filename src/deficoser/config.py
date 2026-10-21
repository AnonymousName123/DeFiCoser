from __future__ import annotations
import os
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, Mapping

def _find_project_root() -> Path:
    root = Path(__file__).resolve().parents[2]
    if (root / 'pyproject.toml').exists():
        return root
    cwd = Path.cwd().resolve()
    for candidate in (cwd, *cwd.parents):
        if (candidate / 'src' / 'deficoser').is_dir() and (candidate / 'pyproject.toml').exists():
            return candidate
    return root
PROJECT_ROOT: Path = _find_project_root()
DATA_DIR: Path = PROJECT_ROOT / 'dataset'
LOGS_DIR: Path = PROJECT_ROOT / 'logs'
PROMPTS_DIR: Path = PROJECT_ROOT / 'prompts'
APP_CONFIG_DIR: Path = PROJECT_ROOT / 'config'
MEMORY_STORE_DIR: Path = PROJECT_ROOT / 'memory_store'
API_KEY_FILE: Path = PROJECT_ROOT / 'API-KEY.txt'
MODELS: tuple[str, ...] = ('deepseek-v4-flash', 'minimax-m3', 'kimi-k2.7-code', 'glm-5.3', 'glm-5.3-flash', 'deepseek-v4-pro')

def validate_model(model: str) -> str:
    if model not in MODELS:
        raise ValueError(f'Unknown model {model!r}; must be one of {MODELS}')
    return model
POC_MAX_RETRIES_INITIAL = 3
MEMORY_TOP_K = 5
FASTEMBED_MODEL = 'sentence-transformers/all-MiniLM-L6-v2'
FASTEMBED_CACHE_DIR: Path = MEMORY_STORE_DIR / 'fastembed_cache'
PATH_LENGTH_BOUND_K = 3
MAX_CANDIDATES_PER_TARGET = 30
MAX_CANDIDATES_GLOBAL = 100
MAX_POC_CANDIDATES = 3
EXPLORER_MAX_WORKERS = 64
API_MAX_TOKENS_CAP = 131072
LLM_PARSE_MAX_RETRIES = 3
NUM_SAMPLES = 1
SEED = 0
TEMPERATURE = 0
TOP_P = 1
PRESENCE_PENALTY = 0
FREQUENCY_PENALTY = 0
STAGE_MAX_TOKENS: dict[str, int] = {'contract_understanding': 2048, 'invariant_extraction': 2048, 'role_extraction': 2048, 'permission_predicate': 2048, 'adversarial_explore': 2048, 'attack_plan': 4096, 'poc_generate': 131072, 'report': 4096, 'pattern_extraction': 4096}
_ENV_BASE_URL = 'DEFICOSER_BASE_URL'
_ENV_API_KEY = 'DEFICOSER_API_KEY'
_ENV_MODEL = 'DEFICOSER_MODEL'
_FILE_KEY_MAP = {'BASE_URL': 'base_url', 'API_KEY': 'api_key', 'MODEL': 'model'}

@dataclass(frozen=True)
class LLMSettings:
    base_url: str
    api_key: str
    model: str

def parse_api_key_file(path: str | Path) -> dict[str, str]:
    text = Path(path).read_text(encoding='utf-8-sig')
    settings: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or '=' not in line:
            continue
        key, _, value = line.partition('=')
        normalized = _FILE_KEY_MAP.get(key.strip().upper())
        if normalized is not None and value.strip():
            settings[normalized] = value.strip()
    return settings

def load_llm_settings(base_url: str | None=None, api_key: str | None=None, model: str | None=None, *, env: Mapping[str, str] | None=None, key_file: str | Path | None=None) -> LLMSettings:
    env_map = os.environ if env is None else env
    file_path = API_KEY_FILE if key_file is None else Path(key_file)
    file_cfg = parse_api_key_file(file_path) if file_path.exists() else {}
    resolved_base_url = base_url or env_map.get(_ENV_BASE_URL) or file_cfg.get('base_url')
    resolved_api_key = api_key or env_map.get(_ENV_API_KEY) or file_cfg.get('api_key')
    resolved_model = model or env_map.get(_ENV_MODEL) or file_cfg.get('model')
    missing = [name for name, value in (('base_url', resolved_base_url), ('api_key', resolved_api_key), ('model', resolved_model)) if not value]
    if missing:
        raise ValueError(f'Missing LLM configuration item: {missing}; provide it through CLI arguments, environment variables ({_ENV_BASE_URL} / {_ENV_API_KEY} / {_ENV_MODEL}) or the root API-KEY.txt')
    validate_model(resolved_model)
    return LLMSettings(base_url=resolved_base_url, api_key=resolved_api_key, model=resolved_model)

def llm_config(model: str | None=None, model_version: str | None=None, *, num_samples: int=NUM_SAMPLES, max_tokens: int | None=None, call_date: str | None=None) -> dict[str, Any]:
    if model is None:
        model = load_llm_settings().model
    return {'model': model, 'model_version': model_version, 'provider': 'api', 'temperature': TEMPERATURE, 'top_p': TOP_P, 'seed': SEED, 'max_tokens': max_tokens if max_tokens is not None else max(STAGE_MAX_TOKENS.values()), 'structured_output': True, 'num_samples': num_samples, 'call_date': call_date if call_date is not None else date.today().isoformat()}

@dataclass(frozen=True)
class PromptTemplate:
    stage: str
    content: str

def load_prompt(stage: str, *, prompts_dir: str | Path | None=None) -> PromptTemplate:
    directory = PROMPTS_DIR if prompts_dir is None else Path(prompts_dir)
    template_path = directory / f'{stage}.txt'
    if not template_path.exists():
        raise FileNotFoundError(f'Prompt template not found: {template_path}')
    return PromptTemplate(stage=stage, content=template_path.read_text(encoding='utf-8-sig'))
