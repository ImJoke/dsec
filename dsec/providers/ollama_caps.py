"""
Probe Ollama for model capabilities (context length, family) via
`/api/show`. Authoritative — beats any hardcoded model→ctx table.

Usage:
    ctx = get_context_length(base_url="http://vps:11434",
                             model="deepseek-v4-pro:cloud")

Cache scope: in-memory per (base_url, model). Refresh by passing
force=True. The probe is cheap (~1s) but we still cache because the
ContextManager constructor runs on every chat call.
"""
from __future__ import annotations

from typing import Dict, Optional, Tuple

import httpx


_PROBE_TIMEOUT_SEC = 4.0
_cache: Dict[Tuple[str, str], int] = {}

# Persistent disk cache so we don't re-probe every shell start.
import json as _json
import os as _os
import time as _time
from pathlib import Path as _Path

_DISK_CACHE_PATH = _Path(_os.path.expanduser("~/.dsec/ctx_cache.json"))
_DISK_CACHE_TTL_SEC = 7 * 24 * 3600  # one week — long enough for stability,
                                     # short enough to pick up model upgrades


def _load_disk_cache() -> Dict[str, Dict[str, int]]:
    try:
        if _DISK_CACHE_PATH.exists():
            return _json.loads(_DISK_CACHE_PATH.read_text())
    except Exception:
        pass
    return {}


def _save_disk_cache(data: Dict[str, Dict[str, int]]) -> None:
    try:
        _DISK_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _DISK_CACHE_PATH.write_text(_json.dumps(data, indent=2))
    except Exception:
        pass


def _disk_lookup(base_url: str, model: str) -> Optional[int]:
    data = _load_disk_cache()
    entry = data.get(model)
    if not isinstance(entry, dict):
        return None
    ts = entry.get("ts")
    ctx = entry.get("ctx")
    if not isinstance(ts, (int, float)) or not isinstance(ctx, int):
        return None
    if _time.time() - ts > _DISK_CACHE_TTL_SEC:
        return None  # stale — re-probe
    return ctx


def _disk_store(model: str, ctx: int) -> None:
    data = _load_disk_cache()
    data[model] = {"ctx": int(ctx), "ts": _time.time()}
    _save_disk_cache(data)


def _extract_ctx_from_show(payload: Dict) -> Optional[int]:
    """Pull a context length out of an `/api/show` response.

    Ollama 0.5+ exposes capabilities under `model_info`, where the key
    is `<family>.context_length` (e.g. `qwen3.context_length`,
    `llama.context_length`). Older versions stash it in
    `parameters` as `num_ctx` lines. We try every well-known location.
    """
    # 1. Modern model_info
    info = payload.get("model_info") or {}
    if isinstance(info, dict):
        for k, v in info.items():
            if isinstance(k, str) and k.endswith(".context_length") and isinstance(v, (int, float)):
                return int(v)
    # 2. Ollama generic field
    n = payload.get("context_length")
    if isinstance(n, (int, float)) and n > 0:
        return int(n)
    # 3. parameters block (text — `num_ctx N`)
    params = payload.get("parameters")
    if isinstance(params, str):
        for line in params.splitlines():
            parts = line.split(maxsplit=1)
            if len(parts) == 2 and parts[0].strip() == "num_ctx":
                try:
                    return int(parts[1].strip())
                except ValueError:
                    pass
    # 4. details block
    details = payload.get("details") or {}
    if isinstance(details, dict):
        for k in ("context_length", "max_context_length"):
            v = details.get(k)
            if isinstance(v, (int, float)) and v > 0:
                return int(v)
    return None


def get_context_length(
    base_url: str,
    model: str,
    *,
    auth_header: Optional[str] = None,
    force: bool = False,
) -> Optional[int]:
    """Return the model's context length in tokens, or None on failure.

    Lookup chain:
      1. in-memory `_cache` (process-local)
      2. on-disk `~/.dsec/ctx_cache.json` (one-week TTL)
      3. probe `/api/show` against `base_url`
    Disk + memory caches are populated on every successful probe.
    """
    if not base_url or not model:
        return None
    key = (base_url.rstrip("/"), model)

    if not force:
        if key in _cache:
            return _cache[key]
        disk_ctx = _disk_lookup(base_url, model)
        if disk_ctx:
            _cache[key] = disk_ctx
            return disk_ctx

    headers: Dict[str, str] = {"Content-Type": "application/json"}
    if auth_header:
        headers["Authorization"] = auth_header

    url = f"{base_url.rstrip('/')}/api/show"
    try:
        r = httpx.post(url, json={"name": model}, headers=headers, timeout=_PROBE_TIMEOUT_SEC)
        if r.status_code != 200:
            return None
        ctx = _extract_ctx_from_show(r.json())
    except Exception:
        return None
    if ctx and ctx > 0:
        _cache[key] = ctx
        _disk_store(model, ctx)
    return ctx


def best_effort_context_for_pool(
    pool_provider_key: str,
    *,
    fallback: int = 128_000,
) -> int:
    """Probe the first healthy endpoint of a configured pool for its
    context length. Falls back to `fallback` if the probe fails.

    Used by ContextManager when initializing the brain budget so we don't
    have to maintain a stale model→ctx table.
    """
    try:
        from dsec.providers import pool as _ppool
    except Exception:
        return fallback
    cfg = _ppool.get_pool(pool_provider_key) or {}
    model = cfg.get("model") or ""
    eps = list(cfg.get("endpoints") or [])
    auths = list(cfg.get("auth_headers") or [])
    for i, ep in enumerate(eps):
        auth = auths[i] if i < len(auths) else None
        ctx = get_context_length(ep, model, auth_header=auth)
        if ctx:
            return ctx
    return fallback
