"""
DSEC Multi-Provider Backend Manager

Routes LLM requests to a registered provider:
  • deepseek: deepseek-free-api (default)
  • ollama:   self-hosted Ollama VPS pool with round-robin endpoint rotation

Provider entries live in config["providers"]. Each role mapping in
config["roles"][role] points at a provider key (with optional fallback);
when an Ollama pool's endpoints all error or are marked dead, the
fallback provider is invoked once with a single user-visible info chunk.

Dormant gpt4free + plain local-Ollama functions below are kept for
reference but no longer routed to.
"""
from typing import Generator, Dict, Any, List, Optional

from dsec.providers._common import split_think_blocks
from dsec.providers import pool as provider_pool


def gpt4free_stream(
    message: str,
    model: str,
    history: Optional[List[Dict[str, str]]] = None,
) -> Generator[Dict[str, Any], None, None]:
    """Streams response from gpt4free via the g4f library. (Dormant — not routed.)"""
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
    """Dormant — superseded by dsec/providers/ollama.py. Kept for back-compat."""
    from dsec.providers.ollama import ollama_chat_stream
    yield from ollama_chat_stream(message, model, None, base_url, history)


def check_deepseek_health(base_url: str) -> bool:
    """Checks if the deepseek-free-api docker container is reachable."""
    import httpx
    try:
        url = f"{base_url.rstrip('/')}/health"
        res = httpx.get(url, timeout=2.0)
        return res.status_code == 200
    except Exception:
        return False


def _stream_deepseek(
    message: str,
    model: str,
    conversation_id: Optional[str],
    base_url: str,
    token: Optional[str],
    history: Optional[List[Dict[str, str]]],
) -> Generator[Dict[str, Any], None, None]:
    """Wrap _deepseek_chat_stream with the existing health check + error envelope."""
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


def _stream_ollama_pool(
    provider_key: str,
    pool: Dict[str, Any],
    message: str,
    history: Optional[List[Dict[str, str]]],
) -> Generator[Dict[str, Any], None, None]:
    """Stream from an Ollama pool with endpoint round-robin and dead-marking.

    Yields the first endpoint's chunks once content starts flowing. On
    transient errors (connect/timeout/HTTP 5xx) before any content has
    been emitted, marks the endpoint dead and rotates to the next. When
    every endpoint has been tried, returns without yielding — the caller
    is responsible for fallback.
    """
    from dsec.providers.ollama import ollama_chat_stream

    model = pool.get("model")
    if not model:
        yield {"type": "error", "text": f"Ollama provider '{provider_key}' missing 'model' config."}
        return

    endpoints_total = len(pool.get("endpoints") or [])
    if endpoints_total == 0:
        yield {"type": "error", "text": f"Ollama provider '{provider_key}' has no endpoints."}
        return

    attempts = 0
    max_attempts = max(1, endpoints_total)

    while attempts < max_attempts:
        endpoint = provider_pool.next_endpoint(provider_key)
        if not endpoint:
            return  # pool exhausted
        attempts += 1
        auth = provider_pool.auth_header_for(provider_key, endpoint)
        produced_content = False
        had_error = False

        for chunk in ollama_chat_stream(
            message=message,
            model=model,
            base_url=endpoint,
            history=history,
            auth_header=auth,
        ):
            ctype = chunk.get("type")
            if ctype == "error" and not produced_content:
                had_error = True
                # Pick a TTL based on the failure mode:
                #   rate_limited → long cooldown so the limit window expires
                #   fatal_endpoint (401/404) → very long; misconfigured endpoint
                #   transient (5xx) → short; upstream may recover quickly
                #   default → 60s
                if chunk.get("rate_limited"):
                    ttl = 600.0
                elif chunk.get("fatal_endpoint"):
                    ttl = 1800.0
                elif chunk.get("transient"):
                    ttl = 30.0
                else:
                    ttl = 60.0
                provider_pool.mark_endpoint_dead(provider_key, endpoint, ttl_sec=ttl)
                break  # rotate to next endpoint
            if ctype in ("content", "thinking"):
                produced_content = True
            yield chunk
            if ctype == "done":
                return

        if not had_error:
            return  # stream ended cleanly without explicit done — treat as finished


def provider_chat_stream(
    message: str,
    model: str,
    conversation_id: Optional[str] = None,
    base_url: str = "http://localhost:8000",
    token: Optional[str] = None,
    provider: str = "deepseek",
    history: Optional[List[Dict[str, str]]] = None,
    role: Optional[str] = None,
) -> Generator[Dict[str, Any], None, None]:
    """Route a chat request to the configured provider.

    Resolution precedence:
      1. If `role` is set and config["roles"][role] exists, use that
         entry's provider (with its declared fallback).
      2. Else use the explicit `provider` arg as the provider key.
      3. The legacy default "deepseek" path is preserved when no role
         and no matching provider entry are configured.

    Transient API errors that the DeepSeek free API yields as ordinary
    content chunks ("服务暂时不可用", "第三方响应错误") still pass through;
    the agentic loop's _has_server_overflow_error detector handles them.
    """
    original_model = model
    provider_key, eff_model, fallback_key = _resolve_role(role, provider, model)

    pool = provider_pool.get_pool(provider_key)
    if pool is None:
        # Unknown provider key — fall back to the legacy hardcoded DeepSeek path.
        yield from _stream_deepseek(message, eff_model, conversation_id, base_url, token, history)
        return

    pool_type = pool.get("type", "deepseek")

    if pool_type == "deepseek":
        yield from _stream_deepseek(
            message,
            eff_model,
            conversation_id,
            pool.get("base_url", base_url),
            token,
            history,
        )
        return

    if pool_type == "ollama":
        produced_anything = False
        for chunk in _stream_ollama_pool(provider_key, pool, message, history):
            if chunk.get("type") in ("content", "thinking", "done"):
                produced_anything = True
            yield chunk
        if produced_anything:
            return
        # Pool exhausted → cascade to fallback.
        cascade = fallback_key or provider_pool.fallback_provider(provider_key)
        if cascade and cascade != provider_key:
            yield {
                "type": "info",
                "text": f"[provider] {provider_key} exhausted, falling back to {cascade}",
            }
            yield from provider_chat_stream(
                message=message,
                model=original_model,
                conversation_id=conversation_id,
                base_url=base_url,
                token=token,
                provider=cascade,
                history=history,
                role=None,  # avoid infinite recursion via role config
            )
            return
        yield {
            "type": "error",
            "text": f"All Ollama endpoints in pool '{provider_key}' unreachable; no fallback configured.",
        }
        return

    yield {"type": "error", "text": f"Unknown provider type '{pool_type}' for '{provider_key}'."}


def _resolve_role(
    role: Optional[str],
    explicit_provider: str,
    explicit_model: str,
) -> tuple[str, str, Optional[str]]:
    """Return (provider_key, model, fallback_key) for the request.

    When a role is configured under config["roles"][role]:
        - provider key is taken from the entry
        - model is taken from role.model if set, else from the provider's
          own `model` field (Ollama pools), else `explicit_model`
        - fallback is taken from the role entry

    Otherwise the explicit provider/model are returned and no fallback is
    implied (the provider entry itself may still declare one, handled in
    the dispatcher).
    """
    if not role:
        return explicit_provider, explicit_model, None
    try:
        from dsec.config import load_config
        cfg = load_config()
        roles = cfg.get("roles") or {}
        entry = roles.get(role)
        if isinstance(entry, dict):
            pkey = entry.get("provider")
            if not isinstance(pkey, str) or not pkey.strip():
                return explicit_provider, explicit_model, None
            pkey = pkey.strip()
            fkey = entry.get("fallback")
            fkey = fkey.strip() if isinstance(fkey, str) and fkey.strip() else None

            model = entry.get("model")
            if not isinstance(model, str) or not model.strip():
                providers = cfg.get("providers") or {}
                pool_entry = providers.get(pkey, {})
                if pool_entry.get("type") == "ollama":
                    pool_model = pool_entry.get("model")
                    model = pool_model if isinstance(pool_model, str) and pool_model.strip() else explicit_model
                else:
                    model = explicit_model
            return pkey, model.strip(), fkey
    except Exception:
        pass
    return explicit_provider, explicit_model, None


def list_providers() -> List[Dict[str, str]]:
    """Return metadata about configured providers."""
    out: List[Dict[str, str]] = [
        {"name": "deepseek", "description": "DeepSeek free API (Docker)", "requires": "deepseek-free-api container"},
    ]
    try:
        from dsec.config import load_config
        cfg = load_config()
        for key, entry in (cfg.get("providers") or {}).items():
            if key == "deepseek":
                continue
            if isinstance(entry, dict):
                ptype = str(entry.get("type", "?"))
                model = str(entry.get("model", ""))
                eps = entry.get("endpoints") or []
                out.append({
                    "name": key,
                    "description": f"{ptype} pool: {model} ({len(eps)} endpoints)",
                    "requires": "endpoints reachable",
                })
    except Exception:
        pass
    return out


# Re-export for back-compat with any external callers reaching for the parser.
__all__ = [
    "provider_chat_stream",
    "check_deepseek_health",
    "list_providers",
    "split_think_blocks",
    "gpt4free_stream",
    "local_model_stream",
]
