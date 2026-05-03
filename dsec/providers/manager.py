"""
DSEC Multi-Provider Backend Manager

Routes LLM requests to different backends:
  • deepseek: Default deepseek-free-api (local Docker)
  • gpt4free: Via the g4f library (no API key)
  • local: Via local Ollama-compatible endpoint

Inspired by: gpt4free, deepseek4free
"""
from typing import Generator, Dict, Any, List, Optional


def gpt4free_stream(
    message: str,
    model: str,
    history: Optional[List[Dict[str, str]]] = None,
) -> Generator[Dict[str, Any], None, None]:
    """Streams response from gpt4free via the g4f library."""
    try:
        from g4f.client import Client
        import g4f
        client = Client()

        messages = list(history) if history else []
        last = messages[-1] if messages else None
        if not last or last.get("role") != "user" or last.get("content") != message:
            messages.append({"role": "user", "content": message})

        response = client.chat.completions.create(
            model=model if model else g4f.models.default,
            messages=messages,
            stream=True
        )

        for chunk in response:
            if chunk.choices[0].delta.content:
                yield {"type": "content", "text": chunk.choices[0].delta.content}

        yield {"type": "done", "conversation_id": None}
    except ImportError:
        yield {"type": "error", "text": "gpt4free library (g4f) is not installed. Run `pip install g4f`."}
    except Exception as e:
        yield {"type": "error", "text": f"gpt4free error: {str(e)}"}


def local_model_stream(
    message: str,
    model: str,
    base_url: str = "http://localhost:11434",
    history: Optional[List[Dict[str, str]]] = None,
) -> Generator[Dict[str, Any], None, None]:
    """
    Streams response from a local Ollama-compatible endpoint.
    Uses the /api/chat endpoint for streaming.
    """
    try:
        import httpx
        import json

        url = f"{base_url.rstrip('/')}/api/chat"
        messages = list(history) if history else []
        last = messages[-1] if messages else None
        if not last or last.get("role") != "user" or last.get("content") != message:
            messages.append({"role": "user", "content": message})

        payload = {
            "model": model or "llama3",
            "messages": messages,
            "stream": True,
        }

        with httpx.Client(timeout=httpx.Timeout(300.0, connect=10.0)) as client:
            with client.stream("POST", url, json=payload) as response:
                if response.status_code != 200:
                    yield {"type": "error", "text": f"Local model error {response.status_code}"}
                    return

                for line in response.iter_lines():
                    if not line:
                        continue
                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    if data.get("done"):
                        yield {"type": "done", "conversation_id": None}
                        return

                    content = data.get("message", {}).get("content", "")
                    if content:
                        yield {"type": "content", "text": content}

        yield {"type": "done", "conversation_id": None}
    except ImportError:
        yield {"type": "error", "text": "httpx not installed. Run: pip install httpx"}
    except Exception as e:
        yield {"type": "error", "text": f"Local model error: {str(e)}"}


def check_deepseek_health(base_url: str) -> bool:
    """Checks if the deepseek-free-api docker container is reachable."""
    import httpx
    try:
        url = f"{base_url.rstrip('/')}/health"
        # We use a short timeout so we don't hang if it's down
        res = httpx.get(url, timeout=2.0)
        return res.status_code == 200
    except Exception:
        return False

def provider_chat_stream(
    message: str,
    model: str,
    conversation_id: Optional[str] = None,
    base_url: str = "http://localhost:8000",
    token: Optional[str] = None,
    provider: str = "deepseek",
    history: Optional[List[Dict[str, str]]] = None,
) -> Generator[Dict[str, Any], None, None]:
    """
    DeepSeek-only routing. gpt4free / local fallback removed — they were
    making things worse (gpt4free needs `pip install g4f`, local needs
    Ollama running on :11434, neither set up by default).

    Transient API errors ("服务暂时不可用", "第三方响应错误") that the
    DeepSeek free API yields as ordinary content chunks pass through to the
    agent loop, which detects them via _has_server_overflow_error and runs
    its own inner-retry loop with exponential backoff + token rotation.
    """
    from dsec.client import _deepseek_chat_stream

    if not check_deepseek_health(base_url):
        yield {
            "type": "error",
            "text": (
                f"DeepSeek API unreachable at {base_url}.\n"
                f"Start the deepseek-free-api Docker container, or set --base-url."
            ),
        }
        return

    try:
        for chunk in _deepseek_chat_stream(
            message, model, conversation_id, base_url, token, history=history
        ):
            yield chunk
    except Exception as exc:
        yield {
            "type": "error",
            "text": f"DeepSeek stream crashed: {type(exc).__name__}: {exc}",
        }


def list_providers() -> List[Dict[str, str]]:
    """Return metadata about available providers."""
    return [
        {"name": "deepseek", "description": "DeepSeek free API (Docker)", "requires": "deepseek-free-api container"},
    ]
