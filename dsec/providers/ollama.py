"""
DSEC Ollama provider.

Streams from an Ollama server's /api/chat endpoint. Yields chunks matching
the DeepSeek provider's contract:

    {"type": "thinking" | "content" | "done" | "error", "text": str,
     "conversation_id": str | None}

Ollama returns NDJSON (one JSON object per line), not SSE. Reasoning
models emit <think>...</think> inline in `message.content`; the shared
parser at providers/_common.split_think_blocks handles that. Native
tool-call tokens (e.g. <|tool_call|>) are normalised to dsec's
<tool_call>...</tool_call> text format so cli._extract_tool_calls keeps
working unchanged.
"""
from __future__ import annotations

import json
from typing import Any, Dict, Generator, List, Optional

import httpx

from dsec.providers._common import normalize_tool_calls, split_think_blocks


def ollama_chat_stream(
    message: str,
    model: str,
    conversation_id: Optional[str] = None,
    base_url: str = "http://localhost:11434",
    history: Optional[List[Dict[str, str]]] = None,
    *,
    auth_header: Optional[str] = None,
    timeout_seconds: float = 300.0,
) -> Generator[Dict[str, Any], None, None]:
    """Stream a chat response from an Ollama endpoint.

    `auth_header`, when given, is sent verbatim as the `Authorization` header
    (e.g. "Bearer sk-..."). Ollama itself doesn't authenticate, but reverse
    proxies in front of self-hosted VPS pools commonly do.
    """
    url = f"{base_url.rstrip('/')}/api/chat"

    if history:
        messages: List[Dict[str, str]] = list(history)
        last = messages[-1] if messages else None
        if not last or last.get("role") != "user" or last.get("content") != message:
            messages.append({"role": "user", "content": message})
    else:
        messages = [{"role": "user", "content": message}]

    payload: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "stream": True,
        # `think: True` opts the request into Ollama's native reasoning
        # surface (returned as `message.thinking`). Models that don't
        # support thinking ignore the flag harmlessly. Combined with
        # the legacy <think>...</think> path in split_think_blocks
        # we now capture both styles.
        "think": True,
        # Loop-prevention. Some cloud frontier models (notably the
        # smaller cloud variants and qwen3-coder branches) get stuck
        # repeating the same sentence ~30 times when context is dense.
        # repeat_penalty 1.18 + frequency_penalty 0.4 + presence_penalty
        # 0.3 are conservative — strong enough to break loops, mild
        # enough to keep instruction-following intact.
        "options": {
            "repeat_penalty": 1.18,
            "frequency_penalty": 0.4,
            "presence_penalty": 0.3,
            "num_ctx": 32768,
        },
    }

    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if auth_header:
        headers["Authorization"] = auth_header

    in_think_block = False

    try:
        with httpx.Client(timeout=httpx.Timeout(timeout_seconds, connect=10.0)) as client:
            with client.stream("POST", url, json=payload, headers=headers) as response:
                if response.status_code == 401:
                    yield {
                        "type": "error",
                        "text": f"Ollama 401 at {base_url} (auth header rejected).",
                        "fatal_endpoint": True,
                    }
                    return
                if response.status_code == 404:
                    yield {
                        "type": "error",
                        "text": f"Ollama 404 at {base_url} (model '{model}' not pulled?).",
                        "fatal_endpoint": True,
                    }
                    return
                if response.status_code == 429:
                    yield {
                        "type": "error",
                        "text": f"Ollama 429 rate-limit at {base_url}.",
                        "rate_limited": True,
                    }
                    return
                if response.status_code in (502, 503, 504):
                    yield {
                        "type": "error",
                        "text": f"Ollama upstream {response.status_code} at {base_url}.",
                        "transient": True,
                    }
                    return
                if response.status_code not in (200, 206):
                    body = ""
                    try:
                        body = response.read()[:300].decode("utf-8", errors="replace")
                    except Exception:
                        pass
                    yield {"type": "error", "text": f"Ollama HTTP {response.status_code} at {base_url}: {body}"}
                    return

                for raw_line in response.iter_lines():
                    line = raw_line if isinstance(raw_line, str) else raw_line.decode("utf-8", errors="replace")
                    if not line or not line.strip():
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    err = data.get("error")
                    if err:
                        yield {"type": "error", "text": f"Ollama error at {base_url}: {err}"}
                        return

                    if data.get("done"):
                        yield {"type": "done", "conversation_id": None}
                        return

                    msg = data.get("message") or {}
                    # Ollama 0.5+ surfaces reasoning models' chain-of-thought
                    # in a separate `message.thinking` field. Stream it as
                    # `type: thinking` so the formatter can render it as a
                    # live "💭 thinking…" block — matches aider's
                    # reasoning_tags.format_reasoning_content pattern.
                    thinking = msg.get("thinking") or ""
                    if thinking:
                        yield {"type": "thinking", "text": thinking}

                    content = msg.get("content") or ""
                    if not content:
                        continue

                    content = normalize_tool_calls(content)
                    # Some models still inline <think>...</think> in `content`
                    # rather than using the dedicated `thinking` field —
                    # split_think_blocks routes those to the thinking lane too.
                    chunks, in_think_block = split_think_blocks(content, in_think_block)
                    for kind, text in chunks:
                        if text:
                            yield {"type": kind, "text": text}

        yield {"type": "done", "conversation_id": None}

    except httpx.ConnectError:
        yield {"type": "error", "text": f"Ollama unreachable at {base_url}."}
    except httpx.TimeoutException:
        yield {"type": "error", "text": f"Ollama timed out at {base_url}."}
    except httpx.RemoteProtocolError as exc:
        yield {"type": "error", "text": f"Ollama protocol error at {base_url}: {exc}"}
    except Exception as exc:
        yield {"type": "error", "text": f"Ollama client crashed at {base_url}: {type(exc).__name__}: {exc}"}
