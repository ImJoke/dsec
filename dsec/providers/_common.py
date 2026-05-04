"""
DSEC Provider — shared utilities.

Stream chunk contract, <think> block parser shared by both DeepSeek and
Ollama providers, and a normaliser that rewrites native tool-call tokens
emitted by some open-weight models into dsec's <tool_call>...</tool_call>
text format so the existing extractor in cli._extract_tool_calls keeps
working unchanged.
"""
from __future__ import annotations

import re
from typing import List, Tuple, TypedDict


class StreamChunk(TypedDict, total=False):
    type: str            # "thinking" | "content" | "done" | "error" | "info"
    text: str
    conversation_id: str | None


def split_think_blocks(content: str, in_think_block: bool) -> Tuple[List[Tuple[str, str]], bool]:
    """Split a content fragment into ("thinking"|"content", text) pairs.

    Handles multiple <think>…</think> blocks within a single chunk.
    Returns (chunks, new_in_think_state).
    """
    out: List[Tuple[str, str]] = []
    if not content:
        return out, in_think_block

    remaining = content
    while remaining:
        if in_think_block:
            if "</think>" in remaining:
                think_part, rest = remaining.split("</think>", 1)
                if think_part:
                    out.append(("thinking", think_part))
                in_think_block = False
                remaining = rest
            else:
                out.append(("thinking", remaining))
                remaining = ""
        else:
            if "<think>" in remaining:
                before, rest = remaining.split("<think>", 1)
                if before:
                    out.append(("content", before))
                in_think_block = True
                remaining = rest
            else:
                out.append(("content", remaining))
                remaining = ""

    return out, in_think_block


# Native tool-call token formats seen on open-weight models.
_TOOL_CALL_OPEN = re.compile(r"<\|tool_call\|>|<\|python_tag\|>|\[TOOL_CALL\]|\[TOOL_CALLS\]")
_TOOL_CALL_CLOSE = re.compile(r"<\|/tool_call\|>|\[/TOOL_CALL\]|\[/TOOL_CALLS\]")


def normalize_tool_calls(content: str) -> str:
    """Rewrite native open-weight tool-call tokens into dsec's text format.

    Examples handled:
        <|tool_call|>{"name":"x"}<|/tool_call|>
        <|python_tag|>{"name":"x"}
        [TOOL_CALLS]{"name":"x"}[/TOOL_CALLS]

    Output: <tool_call>{...}</tool_call>

    Conservative: if no opening token is detected, returns input unchanged.
    """
    if not content:
        return content
    if not _TOOL_CALL_OPEN.search(content):
        return content
    rewritten = _TOOL_CALL_OPEN.sub("<tool_call>", content)
    rewritten = _TOOL_CALL_CLOSE.sub("</tool_call>", rewritten)
    return rewritten
