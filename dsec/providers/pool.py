"""
DSEC Provider Pool — endpoint round-robin + health tracking.

A provider entry in config["providers"] looks like:
    {
        "type": "ollama",
        "model": "gpt-oss:120b",
        "endpoints": ["http://vps1:11434", "http://vps2:11434"],
        "auth_headers": [...],   # optional, aligned to endpoints
        "fallback": "deepseek",  # optional provider key for cascading fallback
    }

For "deepseek" the entry only needs base_url (token pool is the legacy
top-level config["tokens"]):
    {"type": "deepseek", "base_url": "http://localhost:8000"}

State is in-memory only — round-robin counter and dead-endpoint cache.
Restart-safe: a fresh process starts with everyone healthy.
"""
from __future__ import annotations

import threading
import time
from typing import Dict, List, Optional, Tuple

import httpx

from dsec.config import DEFAULT_CONFIG, load_config

_HEALTH_TTL_SEC = 30.0
_DEAD_TTL_SEC = 60.0
_HEALTH_TIMEOUT_SEC = 2.0

_pool_lock = threading.Lock()

# Per-provider round-robin counter
_round_robin: Dict[str, int] = {}
# (provider_key, endpoint_url) -> dead-until epoch seconds
_dead_until: Dict[Tuple[str, str], float] = {}
# endpoint_url -> (epoch_seconds, healthy)
_health_cache: Dict[str, Tuple[float, bool]] = {}


def get_pool(provider_key: str) -> Optional[Dict]:
    """Return the provider config dict, or None if unknown."""
    cfg = load_config()
    providers = cfg.get("providers") or {}
    entry = providers.get(provider_key)
    if entry:
        return dict(entry)
    # Synthetic legacy fallback: top-level base_url for the implicit "deepseek"
    if provider_key == "deepseek":
        return {
            "type": "deepseek",
            "base_url": cfg.get("base_url", DEFAULT_CONFIG["base_url"]),
        }
    return None


def _is_dead(provider_key: str, url: str) -> bool:
    with _pool_lock:
        until = _dead_until.get((provider_key, url))
        if until is None:
            return False
        if time.time() >= until:
            _dead_until.pop((provider_key, url), None)
            return False
        return True


def mark_endpoint_dead(provider_key: str, url: str, ttl_sec: float = _DEAD_TTL_SEC) -> None:
    with _pool_lock:
        _dead_until[(provider_key, url)] = time.time() + ttl_sec


def check_health(url: str, *, force: bool = False) -> bool:
    """GET {url}/api/tags with 2s timeout. Cached 30s."""
    now = time.time()
    if not force:
        with _pool_lock:
            cached = _health_cache.get(url)
        if cached and now - cached[0] < _HEALTH_TTL_SEC:
            return cached[1]

    healthy = False
    try:
        probe = f"{url.rstrip('/')}/api/tags"
        res = httpx.get(probe, timeout=_HEALTH_TIMEOUT_SEC)
        healthy = res.status_code == 200
    except Exception:
        healthy = False
    with _pool_lock:
        _health_cache[url] = (now, healthy)
    return healthy


def healthy_endpoints(provider_key: str) -> List[str]:
    """Return endpoints that are not currently marked dead."""
    pool = get_pool(provider_key)
    if not pool:
        return []
    endpoints: List[str] = list(pool.get("endpoints") or [])
    return [e for e in endpoints if not _is_dead(provider_key, e)]


def next_endpoint(provider_key: str) -> Optional[str]:
    """Round-robin one endpoint that isn't currently dead. None if pool exhausted."""
    candidates = healthy_endpoints(provider_key)
    if not candidates:
        return None
    with _pool_lock:
        idx = _round_robin.get(provider_key, 0) % len(candidates)
        chosen = candidates[idx]
        _round_robin[provider_key] = (idx + 1) % len(candidates)
    return chosen


def auth_header_for(provider_key: str, endpoint: str) -> Optional[str]:
    """Return the optional auth header aligned to the given endpoint, if configured."""
    pool = get_pool(provider_key)
    if not pool:
        return None
    endpoints: List[str] = list(pool.get("endpoints") or [])
    headers: List[str] = list(pool.get("auth_headers") or [])
    if not headers:
        return None
    try:
        idx = endpoints.index(endpoint)
    except ValueError:
        return None
    if idx >= len(headers):
        return None
    return headers[idx]


def fallback_provider(provider_key: str) -> Optional[str]:
    """Return the configured fallback provider key, if any."""
    pool = get_pool(provider_key)
    if not pool:
        return None
    fb = pool.get("fallback")
    if isinstance(fb, str) and fb.strip():
        return fb.strip()
    return None
