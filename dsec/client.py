"""
DSEC HTTP Client
OpenAI-compatible streaming client for deepseek-free-api.
"""
import json
from typing import Any, Dict, Generator, List, Optional

import httpx
from dsec.providers.manager import provider_chat_stream as chat_stream


def chat(
    message: str,
    model: str,
    conversation_id: Optional[str] = None,
    base_url: str = "http://localhost:8000",
    token: Optional[str] = None,
    provider: str = "deepseek",
    role: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Non-streaming chat request.
    Returns {"conversation_id": str, "content": str, "thinking": str}
    """
    thinking_parts = []
    content_parts = []
    final_conv_id = conversation_id

    for chunk in chat_stream(
        message,
        model,
        conversation_id,
        base_url,
        token,
        provider,
        history=None,
        role=role,
    ):
        ctype = chunk.get("type")
        if ctype == "thinking":
            thinking_parts.append(chunk["text"])
        elif ctype == "content":
            content_parts.append(chunk["text"])
        elif ctype == "done":
            final_conv_id = chunk.get("conversation_id") or final_conv_id
        elif ctype == "error":
            return {"error": chunk["text"], "conversation_id": None, "content": "", "thinking": ""}

    return {
        "conversation_id": final_conv_id,
        "content": "".join(content_parts),
        "thinking": "".join(thinking_parts),
    }


def _deepseek_chat_stream(
    message: str,
    model: str,
    conversation_id: Optional[str] = None,
    base_url: str = "http://localhost:8000",
    token: Optional[str] = None,
    history: Optional[List[Dict[str, str]]] = None,
) -> Generator[Dict[str, Any], None, None]:
    """
    Streaming chat.  Yields dicts:
      {"type": "thinking",  "text": str}
      {"type": "content",   "text": str}
      {"type": "done",      "conversation_id": str | None}
      {"type": "error",     "text": str}
    """
    url = f"{base_url.rstrip('/')}/v1/chat/completions"
    headers = {"Content-Type": "application/json", "Accept": "text/event-stream"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    # Use history if provided, otherwise default to current message
    if history:
        messages = list(history)
        last = messages[-1] if messages else None
        if not last or last.get("role") != "user" or last.get("content") != message:
            messages.append({"role": "user", "content": message})
    else:
        messages = [{"role": "user", "content": message}]

    payload: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "stream": True,
        "max_tokens": 8192,
    }
    if conversation_id:
        payload["conversation_id"] = conversation_id

    conv_id_found: Optional[str] = None
    in_think_block: bool = False

    try:
        with httpx.Client(timeout=httpx.Timeout(180.0, connect=10.0)) as client:
            with client.stream("POST", url, json=payload, headers=headers) as response:
                # Handle HTTP errors
                if response.status_code == 401:
                    yield {
                        "type": "error",
                        "text": (
                            "Token expired or invalid.\n"
                            "Get a new token: chat.deepseek.com → F12 → "
                            "Application → LocalStorage → userToken\n"
                            "Then: dsec token --add YOUR_TOKEN"
                        ),
                    }
                    return
                if response.status_code == 403:
                    yield {
                        "type": "error",
                        "text": (
                            "Access forbidden (403). Your token may be invalid.\n"
                            "dsec token --add NEW_TOKEN"
                        ),
                    }
                    return
                if response.status_code == 429:
                    yield {
                        "type": "error",
                        "text": (
                            "Rate limited (429). Add more tokens to rotate:\n"
                            "dsec token --add TOKEN1,TOKEN2,TOKEN3"
                        ),
                    }
                    return
                if response.status_code not in (200, 206):
                    body = ""
                    try:
                        body = response.read()[:300].decode("utf-8", errors="replace")
                    except Exception:
                        pass
                    yield {
                        "type": "error",
                        "text": f"API error {response.status_code}: {body}",
                    }
                    return

                # Parse SSE stream
                for raw_line in response.iter_lines():
                    line = raw_line.strip() if isinstance(raw_line, str) else raw_line.strip().decode("utf-8", errors="replace")
                    if not line:
                        continue
                    if not line.startswith("data:"):
                        continue

                    data_str = line[5:].strip()
                    if data_str == "[DONE]":
                        yield {"type": "done", "conversation_id": conv_id_found}
                        return

                    try:
                        chunk_json = json.loads(data_str)
                    except json.JSONDecodeError:
                        continue

                    # Capture the stream-level ID as conversation_id
                    if not conv_id_found:
                        raw_id = chunk_json.get("id")
                        if raw_id:
                            conv_id_found = str(raw_id)

                    choices = chunk_json.get("choices", [])
                    if not choices:
                        continue

                    delta = choices[0].get("delta", {})

                    # Thinking / reasoning content (DeepSeek-R1 style)
                    reasoning = delta.get("reasoning_content") or ""
                    if reasoning:
                        yield {"type": "thinking", "text": reasoning}

                    # Regular content
                    content = delta.get("content") or ""
                    if content:
                        # Fallback parser if the API proxy fails to separate reasoning_content
                        if "<think>" in content:
                            before, after = content.split("<think>", 1)
                            if before and not in_think_block:
                                yield {"type": "content", "text": before}
                            in_think_block = True
                            content = after

                        if "</think>" in content:
                            in_think_block = False
                            parts = content.split("</think>", 1)
                            if parts[0]:
                                yield {"type": "thinking", "text": parts[0]}
                            if len(parts) > 1 and parts[1]:
                                yield {"type": "content", "text": parts[1]}
                        elif content:
                            if in_think_block:
                                yield {"type": "thinking", "text": content}
                            else:
                                yield {"type": "content", "text": content}

                    # Finish reason
                    finish = choices[0].get("finish_reason")
                    if finish and finish != "null":
                        yield {"type": "done", "conversation_id": conv_id_found}
                        return

        # If we reach here without a DONE, emit done anyway
        yield {"type": "done", "conversation_id": conv_id_found}

    except httpx.ConnectError:
        yield {
            "type": "error",
            "text": (
                f"Cannot connect to deepseek-free-api at {base_url}.\n"
                "Is Docker running?  Try:\n"
                "  docker ps\n"
                "  docker run -d -p 8000:8000 ... (your deepseek-free-api image)"
            ),
        }
    except httpx.TimeoutException:
        yield {
            "type": "error",
            "text": (
                f"Request timed out connecting to {base_url}.\n"
                "The model may be processing a very long context. Try a shorter input."
            ),
        }
    except httpx.RemoteProtocolError as e:
        yield {
            "type": "error",
            "text": f"Protocol error talking to API: {e}\nIs the endpoint really OpenAI-compatible?",
        }
    except Exception as e:
        yield {"type": "error", "text": f"Unexpected client error: {type(e).__name__}: {e}"}
