"""
DSEC JSON Repair Utility — Inspired by Hermes Agent.

Fixes common malformations in LLM-generated JSON tool calls:
- Truncated JSON (missing closing braces/brackets)
- Trailing commas
- Python-style literals (True/False/None)
- Single quotes instead of double quotes
- Unquoted keys
- Comments (// and /* */)
- Unescaped control characters
"""
import json
import re
import logging

logger = logging.getLogger(__name__)


def _strip_comments(s: str) -> str:
    """Remove // and /* */ comments outside of JSON strings."""
    out: list[str] = []
    i = 0
    in_str = False
    esc = False
    while i < len(s):
        ch = s[i]
        if esc:
            out.append(ch)
            esc = False
            i += 1
            continue
        if ch == '\\' and in_str:
            out.append(ch)
            esc = True
            i += 1
            continue
        if ch == '"':
            in_str = not in_str
            out.append(ch)
            i += 1
            continue
        if not in_str:
            if s[i:i+2] == '//':
                nl = s.find('\n', i)
                i = nl if nl != -1 else len(s)
                continue
            if s[i:i+2] == '/*':
                end = s.find('*/', i + 2)
                i = end + 2 if end != -1 else len(s)
                continue
        out.append(ch)
        i += 1
    return ''.join(out)


def _fix_single_quotes(s: str) -> str:
    """Replace single-quoted keys/values with double-quoted ones.

    Only operates when the string looks like it uses single quotes as
    the primary quoting style (no double quotes around keys/values).
    """
    if '"name"' in s or '"command"' in s:
        return s

    out: list[str] = []
    i = 0
    while i < len(s):
        ch = s[i]
        if ch == "'":
            out.append('"')
            i += 1
            while i < len(s) and s[i] != "'":
                if s[i] == '"':
                    out.append('\\"')
                elif s[i] == '\\' and i + 1 < len(s) and s[i+1] == "'":
                    out.append("'")
                    i += 1
                else:
                    out.append(s[i])
                i += 1
            out.append('"')
            i += 1
        else:
            out.append(ch)
            i += 1
    return ''.join(out)


def _fix_unquoted_keys(s: str) -> str:
    """Quote bare identifier keys: {name: "bash"} -> {"name": "bash"}."""
    return re.sub(r'(?<=[\{,])\s*([a-zA-Z_]\w*)\s*:', r' "\1":', s)


def repair_json(raw: str) -> str:
    """Attempt to repair malformed JSON string."""
    if not raw or not isinstance(raw, str):
        return "{}"

    raw = raw.strip()

    # Pass 0: try as-is first (fast path)
    try:
        json.loads(raw)
        return raw
    except json.JSONDecodeError:
        pass

    # 1. Strip comments
    raw = _strip_comments(raw)

    # 2. Handle Python-style literals
    raw = raw.replace(": True", ": true").replace(": False", ": false").replace(": None", ": null")
    raw = raw.replace(",True", ",true").replace(",False", ",false").replace(",None", ",null")
    raw = raw.replace("[True", "[true").replace("[False", "[false").replace("[None", "[null")

    # 3. Fix invalid JSON escape sequences (e.g., \., \$, \&)
    raw = re.sub(r'\\([^"\\/bfnrtu])', r'\\\\\1', raw)

    try:
        json.loads(raw)
        return raw
    except json.JSONDecodeError:
        pass

    # Pass 2: Loose JSON (allow control chars)
    try:
        parsed = json.loads(raw, strict=False)
        return json.dumps(parsed)
    except json.JSONDecodeError:
        pass

    # Pass 3: Single quotes and unquoted keys
    fixed = _fix_single_quotes(raw)
    fixed = _fix_unquoted_keys(fixed)

    try:
        parsed = json.loads(fixed, strict=False)
        return json.dumps(parsed)
    except json.JSONDecodeError:
        pass

    # Pass 4: Structural repairs
    # Remove trailing commas
    fixed = re.sub(r',\s*([}\]])', r'\1', fixed)

    # Fix missing closing braces/brackets
    open_curly = fixed.count('{') - fixed.count('}')
    open_bracket = fixed.count('[') - fixed.count(']')

    if open_curly > 0:
        fixed += '}' * open_curly
    if open_bracket > 0:
        fixed += ']' * open_bracket

    # Final attempt
    try:
        parsed = json.loads(fixed, strict=False)
        return json.dumps(parsed)
    except json.JSONDecodeError as e:
        logger.debug(f"JSON Repair failed: {e}")
        return "{}"
