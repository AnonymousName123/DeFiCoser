from __future__ import annotations
import re
from typing import Iterator
_BARE_KEYWORDS = frozenset({'constructor', 'receive', 'fallback'})
_REQUIRE_START_RE = re.compile('\\b(require|assert)\\s*\\(')

def match_delimiter(text: str, open_pos: int, *, opener: str='{', closer: str='}') -> int:
    depth = 0
    i = open_pos
    n = len(text)
    state: str | None = None
    while i < n:
        ch = text[i]
        if state == 'line':
            if ch == '\n':
                state = None
        elif state == 'block':
            if ch == '*' and i + 1 < n and (text[i + 1] == '/'):
                state = None
                i += 1
        elif state in ("'", '"'):
            if ch == '\\':
                i += 1
            elif ch == state:
                state = None
        elif ch == '/' and i + 1 < n:
            if text[i + 1] == '/':
                state = 'line'
                i += 1
            elif text[i + 1] == '*':
                state = 'block'
                i += 1
        elif ch in ("'", '"'):
            state = ch
        elif ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1

def _first_top_level_arg(inner: str) -> str:
    depth = 0
    i = 0
    n = len(inner)
    state: str | None = None
    while i < n:
        ch = inner[i]
        if state == 'line':
            if ch == '\n':
                state = None
        elif state == 'block':
            if ch == '*' and i + 1 < n and (inner[i + 1] == '/'):
                state = None
                i += 1
        elif state in ("'", '"'):
            if ch == '\\':
                i += 1
            elif ch == state:
                state = None
        elif ch == '/' and i + 1 < n:
            if inner[i + 1] == '/':
                state = 'line'
                i += 1
            elif inner[i + 1] == '*':
                state = 'block'
                i += 1
        elif ch in ("'", '"'):
            state = ch
        elif ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        elif ch == ',' and depth == 0:
            return inner[:i]
        i += 1
    return inner

def iter_require_calls(text: str) -> Iterator[tuple[int, int, str]]:
    if not text:
        return
    for match in _REQUIRE_START_RE.finditer(text):
        open_pos = match.end() - 1
        close_pos = match_delimiter(text, open_pos, opener='(', closer=')')
        if close_pos < 0:
            continue
        condition = _first_top_level_arg(text[open_pos + 1:close_pos])
        if not condition.strip():
            continue
        condition = re.sub('\\s+', ' ', condition).strip()
        yield (match.start(), close_pos + 1, f'{match.group(1)}({condition})')

def extract_function_text(sources: dict[str, str], function: dict) -> str:
    name = function.get('name') or ''
    if not name:
        return ''
    text = sources.get(function.get('file') or '')
    if not text:
        return ''
    if name in _BARE_KEYWORDS:
        pattern = re.compile(f'\\b{re.escape(name)}\\s*\\(')
    else:
        pattern = re.compile(f'\\bfunction\\s+{re.escape(name)}\\s*\\(')
    target_line = function.get('line_number') or 0
    best_start = -1
    best_dist = -1
    for match in pattern.finditer(text):
        line = text.count('\n', 0, match.start()) + 1
        dist = abs(line - target_line)
        if best_start < 0 or dist < best_dist:
            best_start, best_dist = (match.start(), dist)
        if dist == 0:
            break
    if best_start < 0:
        return ''
    open_pos = -1
    for i in range(best_start, len(text)):
        ch = text[i]
        if ch == ';':
            return ''
        if ch == '{':
            open_pos = i
            break
    if open_pos < 0:
        return ''
    close_pos = match_delimiter(text, open_pos)
    if close_pos < 0:
        return ''
    return text[best_start:close_pos + 1]
