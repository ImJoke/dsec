"""
DSEC display helpers — resolve user-facing strings (model, domain) from the
layered config so the banner / status line never shows the legacy DeepSeek
default when multi-agent + Ollama pools are active.
"""
from __future__ import annotations

from typing import Any, Dict


_LEGACY_DEFAULT_MODEL = "deepseek-expert-r1-search"


def resolve_brain_display_model(config: Dict[str, Any], model_override: str = "") -> str:
    """Return the model string to display.

    Resolution order:
      1. Explicit `model_override` (caller-provided, e.g. --model flag).
      2. If `enable_multi_agent` is true, the brain role's pool model
         (so the banner reflects the model that will actually serve
         the operator's prompt — not the legacy single-agent default).
      3. Legacy `config["default_model"]`.
      4. Final fallback: the legacy DeepSeek free-API model name.
    """
    if model_override:
        return model_override
    if config.get("enable_multi_agent"):
        roles = config.get("roles") or {}
        brain_entry = roles.get("brain") or {}
        explicit = brain_entry.get("model")
        if isinstance(explicit, str) and explicit.strip():
            return explicit.strip()
        provider_key = brain_entry.get("provider")
        if isinstance(provider_key, str) and provider_key.strip():
            providers = config.get("providers") or {}
            pool = providers.get(provider_key.strip()) or {}
            pool_model = pool.get("model")
            if isinstance(pool_model, str) and pool_model.strip():
                return pool_model.strip()
    cfg_default = config.get("default_model")
    if isinstance(cfg_default, str) and cfg_default.strip():
        return cfg_default.strip()
    return _LEGACY_DEFAULT_MODEL


def resolve_default_domain(config: Dict[str, Any]) -> str:
    """Return the default domain — `auto` unless the operator explicitly
    pinned a different one in config (`config["default_domain"]`)."""
    pinned = config.get("default_domain")
    if isinstance(pinned, str) and pinned.strip():
        return pinned.strip()
    return "auto"
