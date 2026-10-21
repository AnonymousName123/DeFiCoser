from __future__ import annotations
import json
import threading
import time
from dataclasses import dataclass
from typing import Any
import jsonschema
from openai import OpenAI
from deficoser.config import API_MAX_TOKENS_CAP, FREQUENCY_PENALTY, LLM_PARSE_MAX_RETRIES, PRESENCE_PENALTY, SEED, STAGE_MAX_TOKENS, TEMPERATURE, TOP_P

@dataclass
class TokenUsageRecord:
    stage: str
    prompt_tokens: int
    completion_tokens: int
    model: str
    latency_ms: float
    retries: int

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

class LLMParseError(Exception):

    def __init__(self, stage: str, retries: int, last_error: str) -> None:
        self.stage = stage
        self.retries = retries
        self.last_error = last_error
        super().__init__(f'LLM structured-output parsing failed: stage={stage}, retries={retries}, last_error={last_error}')

class LLMBudgetExhausted(Exception):
    pass

def _extract_json(text: str | None) -> Any:
    if not isinstance(text, str) or not text.strip():
        raise ValueError('Model output is empty; cannot parse JSON')
    s = text.strip()
    if s.startswith('```'):
        lines = s.splitlines()[1:]
        if lines and lines[-1].strip().startswith('```'):
            lines = lines[:-1]
        s = '\n'.join(lines).strip()
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        pass
    for open_char, close_char in (('{', '}'), ('[', ']')):
        start, end = (s.find(open_char), s.rfind(close_char))
        if start != -1 and end > start:
            try:
                return json.loads(s[start:end + 1])
            except json.JSONDecodeError:
                continue
    raise ValueError(f'Cannot parse JSON from model output: {text[:200]!r}')

def _is_transient(exc: Exception) -> bool:
    try:
        from openai import APIConnectionError, APITimeoutError, RateLimitError
    except ImportError:
        return False
    return isinstance(exc, (RateLimitError, APITimeoutError, APIConnectionError))

def _json_instruction_message(schema: dict) -> dict:
    return {'role': 'system', 'content': 'Structured output requirements: Reply with exactly one JSON object. Do not include markdown code fences, comments, or any other text. The JSON must strictly conform to this JSON Schema:\n' + json.dumps(schema, ensure_ascii=False, indent=2)}

def _feedback_messages(previous_output: str | None, error: str) -> list[dict]:
    return [{'role': 'assistant', 'content': previous_output or ''}, {'role': 'user', 'content': f'Your previous output failed parsing or validation, error: {error}\nPlease output again: exactly one JSON object conforming to the JSON Schema, without markdown code fences, comments, or any extra text.'}]

class LLMClient:

    def __init__(self, base_url: str, api_key: str, model: str, timeout: float=600, max_parse_retries: int=LLM_PARSE_MAX_RETRIES) -> None:
        self.base_url = base_url
        self.api_key = api_key
        self.model = model
        self.timeout = timeout
        self.max_parse_retries = max_parse_retries
        self.usage_records: list[TokenUsageRecord] = []
        self._native_json_mode = True
        self._lock = threading.Lock()
        self._client = OpenAI(base_url=base_url, api_key=api_key, timeout=timeout)

    def call(self, stage: str, messages: list[dict], schema: dict | None=None) -> dict:
        if stage not in STAGE_MAX_TOKENS:
            raise ValueError(f'Unknown stage {stage!r}; must be one of {sorted(STAGE_MAX_TOKENS)}')
        max_tokens = STAGE_MAX_TOKENS[stage]
        attempt_messages: list[dict] = [dict(m) for m in messages]
        prompt_tokens = 0
        completion_tokens = 0
        retries = 0
        budget_bumped = False
        last_error = ''
        started = time.perf_counter()
        while True:
            request_messages = attempt_messages
            response_format: dict | None = None
            if schema is not None:
                if self._native_json_mode:
                    response_format = {'type': 'json_schema', 'json_schema': {'name': f'deficoser_{stage}', 'schema': schema, 'strict': False}}
                else:
                    request_messages = attempt_messages + [_json_instruction_message(schema)]
            try:
                content, usage, finish_reason = self._create_completion(request_messages, max_tokens, response_format)
            except Exception as exc:
                if response_format is not None and self._native_json_mode and (not _is_transient(exc)):
                    with self._lock:
                        self._native_json_mode = False
                    continue
                raise
            prompt_tokens += usage['prompt_tokens']
            completion_tokens += usage['completion_tokens']
            if finish_reason == 'length' and (not (content or '').strip()):
                if not budget_bumped and max_tokens < API_MAX_TOKENS_CAP:
                    max_tokens = min(max_tokens * 2, API_MAX_TOKENS_CAP)
                    budget_bumped = True
                    continue
                self._record(stage, prompt_tokens, completion_tokens, started, retries)
                raise LLMBudgetExhausted(f'stage={stage}: max_tokens={max_tokens} fully consumed by reasoning (content is empty, finish_reason=length)')
            if schema is None:
                self._record(stage, prompt_tokens, completion_tokens, started, retries)
                return {'content': content}
            try:
                data = _extract_json(content)
                jsonschema.validate(instance=data, schema=schema)
            except (ValueError, jsonschema.ValidationError) as exc:
                last_error = str(exc) or type(exc).__name__
                if self._native_json_mode:
                    with self._lock:
                        self._native_json_mode = False
                if retries >= self.max_parse_retries:
                    self._record(stage, prompt_tokens, completion_tokens, started, retries)
                    raise LLMParseError(stage=stage, retries=retries, last_error=last_error) from exc
                retries += 1
                attempt_messages = attempt_messages + _feedback_messages(content, last_error)
                continue
            self._record(stage, prompt_tokens, completion_tokens, started, retries)
            return data

    def token_summary(self) -> dict[str, dict[str, Any]]:
        summary: dict[str, dict[str, Any]] = {}
        for record in self.usage_records:
            entry = summary.setdefault(record.stage, {'calls': 0, 'prompt_tokens': 0, 'completion_tokens': 0, 'total_tokens': 0, 'retries': 0, 'latency_ms': 0.0})
            entry['calls'] += 1
            entry['prompt_tokens'] += record.prompt_tokens
            entry['completion_tokens'] += record.completion_tokens
            entry['total_tokens'] += record.total_tokens
            entry['retries'] += record.retries
            entry['latency_ms'] += record.latency_ms
        return summary

    def _create_completion(self, messages: list[dict], max_tokens: int, response_format: dict | None) -> tuple[str | None, dict[str, int], str | None]:
        kwargs: dict[str, Any] = dict(model=self.model, messages=messages, temperature=TEMPERATURE, top_p=TOP_P, seed=SEED, presence_penalty=PRESENCE_PENALTY, frequency_penalty=FREQUENCY_PENALTY, max_tokens=max_tokens)
        if response_format is not None:
            kwargs['response_format'] = response_format
        response = self._client.chat.completions.create(**kwargs)
        content: str | None = None
        finish_reason: str | None = None
        if getattr(response, 'choices', None):
            content = response.choices[0].message.content
            finish_reason = getattr(response.choices[0], 'finish_reason', None)
        usage = getattr(response, 'usage', None)
        return (content, {'prompt_tokens': getattr(usage, 'prompt_tokens', 0) or 0, 'completion_tokens': getattr(usage, 'completion_tokens', 0) or 0}, finish_reason)

    def _record(self, stage: str, prompt_tokens: int, completion_tokens: int, started: float, retries: int) -> None:
        latency_ms = (time.perf_counter() - started) * 1000
        with self._lock:
            self.usage_records.append(TokenUsageRecord(stage=stage, prompt_tokens=prompt_tokens, completion_tokens=completion_tokens, model=self.model, latency_ms=latency_ms, retries=retries))
