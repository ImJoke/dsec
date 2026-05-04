"""
DSEC config management.

Configuration lives in ~/.dsec/config.json and is validated/coerced on load.
Known keys are type-safe; invalid persisted values are reset to defaults.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

CONFIG_DIR = Path.home() / ".dsec"
CONFIG_FILE = CONFIG_DIR / "config.json"

DEFAULT_CONFIG: Dict[str, Any] = {
    "base_url": "http://localhost:8000",
    "default_model": "deepseek-expert-r1-search",
    "stream": True,
    "show_thinking": True,
    "compress_threshold": 500,
    "sessions_dir": "~/.dsec/sessions",
    "memory_dir": "~/.dsec/memory",
    "auto_research": True,
    "research_max_results": 5,
    "memory_similarity_threshold": 0.82,
    "memory_max_inject": 3,
    "tokens": [],
    "current_token_index": 0,
    # Multi-provider routing. The implicit "deepseek" entry stays available
    # even when this dict is empty, sourced from top-level base_url.
    "providers": {},
    # Per-role provider mapping: roles[role] = {"provider": "<key>", "fallback": "<key>"}
    "roles": {},
    # Master switch for the brain/research/executor multi-agent split.
    "enable_multi_agent": False,
}

ConfigValidator = Callable[[Any], Any]


class ConfigError(ValueError):
    """Raised when a config key or value is invalid."""


def _ensure_base_dirs() -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)


def _ensure_runtime_dirs(config: Dict[str, Any]) -> None:
    Path(str(config["sessions_dir"])).expanduser().mkdir(parents=True, exist_ok=True)
    (Path(str(config["memory_dir"])).expanduser() / "chroma").mkdir(parents=True, exist_ok=True)


def _write_config(config: Dict[str, Any]) -> None:
    _ensure_base_dirs()
    with open(CONFIG_FILE, "w", encoding="utf-8") as handle:
        json.dump(config, handle, indent=2)
        handle.write("\n")
    try:
        os.chmod(CONFIG_FILE, 0o600)
    except OSError:
        pass


def _read_extra_keys() -> Dict[str, Any]:
    """Return the unknown (non-DEFAULT_CONFIG) keys from the config file.

    These are keys such as ``mcp_servers`` that are written by other parts of
    the application and must survive every round-trip through ``load_config``
    and ``save_config``.
    """
    try:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
                raw = json.load(handle)
            if isinstance(raw, dict):
                return {k: raw[k] for k in raw if k not in DEFAULT_CONFIG}
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _coerce_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "on"}:
            return True
        if lowered in {"false", "0", "no", "off"}:
            return False
    raise ConfigError("expected a boolean value")


def _coerce_int(value: Any, *, minimum: int | None = None) -> int:
    if isinstance(value, bool):
        raise ConfigError("expected an integer value")
    if isinstance(value, int):
        result = value
    elif isinstance(value, str) and value.strip():
        try:
            result = int(value.strip())
        except ValueError as exc:
            raise ConfigError("expected an integer value") from exc
    else:
        raise ConfigError("expected an integer value")

    if minimum is not None and result < minimum:
        raise ConfigError(f"expected an integer >= {minimum}")
    return result


def _coerce_float(value: Any, *, minimum: float | None = None, maximum: float | None = None) -> float:
    if isinstance(value, bool):
        raise ConfigError("expected a float value")
    if isinstance(value, (int, float)):
        result = float(value)
    elif isinstance(value, str) and value.strip():
        try:
            result = float(value.strip())
        except ValueError as exc:
            raise ConfigError("expected a float value") from exc
    else:
        raise ConfigError("expected a float value")

    if minimum is not None and result < minimum:
        raise ConfigError(f"expected a value >= {minimum}")
    if maximum is not None and result > maximum:
        raise ConfigError(f"expected a value <= {maximum}")
    return result


def _coerce_path(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError("expected a non-empty path")
    return str(Path(value.strip()).expanduser())


def _coerce_string(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError("expected a non-empty string")
    return value.strip()


def _coerce_tokens(value: Any) -> List[str]:
    if not isinstance(value, list):
        raise ConfigError("expected a list of tokens")
    tokens: List[str] = []
    seen = set()
    for item in value:
        if not isinstance(item, str):
            raise ConfigError("tokens must be strings")
        token = item.strip()
        if token and token not in seen:
            tokens.append(token)
            seen.add(token)
    return tokens


def _coerce_providers(value: Any) -> Dict[str, Dict[str, Any]]:
    """Validate config["providers"]: {key: {type, ...}}."""
    if value in (None, ""):
        return {}
    if not isinstance(value, dict):
        raise ConfigError("providers must be an object")

    out: Dict[str, Dict[str, Any]] = {}
    for key, entry in value.items():
        if not isinstance(key, str) or not key.strip():
            raise ConfigError("provider key must be a non-empty string")
        if not isinstance(entry, dict):
            raise ConfigError(f"provider '{key}' must be an object")

        ptype = entry.get("type")
        if ptype not in ("deepseek", "ollama"):
            raise ConfigError(f"provider '{key}': type must be 'deepseek' or 'ollama'")

        norm: Dict[str, Any] = {"type": ptype}
        if ptype == "deepseek":
            base_url = entry.get("base_url")
            if base_url is not None:
                norm["base_url"] = _coerce_string(base_url)
        else:  # ollama
            model = entry.get("model")
            if not isinstance(model, str) or not model.strip():
                raise ConfigError(f"provider '{key}': 'model' is required for ollama")
            norm["model"] = model.strip()

            endpoints = entry.get("endpoints")
            if not isinstance(endpoints, list) or not endpoints:
                raise ConfigError(f"provider '{key}': 'endpoints' must be a non-empty list")
            cleaned: List[str] = []
            for ep in endpoints:
                if not isinstance(ep, str) or not ep.strip():
                    raise ConfigError(f"provider '{key}': endpoint must be non-empty string")
                cleaned.append(ep.strip().rstrip("/"))
            norm["endpoints"] = cleaned

            auth_headers = entry.get("auth_headers")
            if auth_headers is not None:
                if not isinstance(auth_headers, list):
                    raise ConfigError(f"provider '{key}': 'auth_headers' must be a list")
                if len(auth_headers) > len(cleaned):
                    raise ConfigError(
                        f"provider '{key}': 'auth_headers' length must be <= endpoints length"
                    )
                norm["auth_headers"] = [str(h) if h is not None else "" for h in auth_headers]

        fallback = entry.get("fallback")
        if fallback is not None:
            if not isinstance(fallback, str) or not fallback.strip():
                raise ConfigError(f"provider '{key}': 'fallback' must be non-empty string")
            norm["fallback"] = fallback.strip()

        out[key.strip()] = norm

    return out


def _coerce_roles(value: Any) -> Dict[str, Dict[str, Any]]:
    """Validate config["roles"]: {role: {provider: key, fallback?: key}}."""
    if value in (None, ""):
        return {}
    if not isinstance(value, dict):
        raise ConfigError("roles must be an object")

    out: Dict[str, Dict[str, Any]] = {}
    for role, entry in value.items():
        if not isinstance(role, str) or not role.strip():
            raise ConfigError("role key must be a non-empty string")
        if not isinstance(entry, dict):
            raise ConfigError(f"role '{role}' must be an object")
        provider = entry.get("provider")
        if not isinstance(provider, str) or not provider.strip():
            raise ConfigError(f"role '{role}': 'provider' is required")
        norm: Dict[str, Any] = {"provider": provider.strip()}
        fallback = entry.get("fallback")
        if fallback is not None:
            if not isinstance(fallback, str) or not fallback.strip():
                raise ConfigError(f"role '{role}': 'fallback' must be non-empty string")
            norm["fallback"] = fallback.strip()
        model_override = entry.get("model")
        if model_override is not None:
            if not isinstance(model_override, str) or not model_override.strip():
                raise ConfigError(f"role '{role}': 'model' must be non-empty string when set")
            norm["model"] = model_override.strip()
        out[role.strip()] = norm

    return out


VALIDATORS: Dict[str, ConfigValidator] = {
    "base_url": _coerce_string,
    "default_model": _coerce_string,
    "stream": _coerce_bool,
    "show_thinking": _coerce_bool,
    "compress_threshold": lambda value: _coerce_int(value, minimum=0),
    "sessions_dir": _coerce_path,
    "memory_dir": _coerce_path,
    "auto_research": _coerce_bool,
    "research_max_results": lambda value: _coerce_int(value, minimum=1),
    "memory_similarity_threshold": lambda value: _coerce_float(value, minimum=0.0, maximum=1.0),
    "memory_max_inject": lambda value: _coerce_int(value, minimum=1),
    "tokens": _coerce_tokens,
    "current_token_index": lambda value: _coerce_int(value, minimum=0),
    "providers": _coerce_providers,
    "roles": _coerce_roles,
    "enable_multi_agent": _coerce_bool,
}

# ── In-memory config cache (avoids re-reading disk on every call) ────────
_config_cache: Dict[str, Any] | None = None
_config_cache_mtime: float = 0.0
_token_index_override: int | None = None


def _invalidate_cache() -> None:
    global _config_cache, _config_cache_mtime
    _config_cache = None
    _config_cache_mtime = 0.0


def _normalise_config(raw: Dict[str, Any], *, strict: bool = False) -> Tuple[Dict[str, Any], bool]:
    config: Dict[str, Any] = {}
    changed = False

    extras = sorted(set(raw) - set(DEFAULT_CONFIG))
    if extras:
        if strict:
            raise ConfigError(f"unknown config key(s): {', '.join(extras)}")
        changed = True

    for key, default_value in DEFAULT_CONFIG.items():
        validator = VALIDATORS[key]
        candidate = raw.get(key, default_value)
        try:
            config[key] = validator(candidate)
        except ConfigError:
            if strict:
                raise
            config[key] = validator(default_value)
            changed = True
            continue

        if key not in raw or config[key] != candidate:
            changed = True

    if config["tokens"]:
        config["current_token_index"] = config["current_token_index"] % len(config["tokens"])
    elif config["current_token_index"] != 0:
        config["current_token_index"] = 0
        changed = True

    return config, changed


def init_config() -> None:
    """Create the config file and runtime directories if they do not exist."""
    _ensure_base_dirs()
    if not CONFIG_FILE.exists():
        _write_config(DEFAULT_CONFIG)
    _ensure_runtime_dirs(load_config())


def load_config() -> Dict[str, Any]:
    """Load, validate, and normalize config from disk. Uses mtime-based cache."""
    global _config_cache, _config_cache_mtime

    _ensure_base_dirs()

    if not CONFIG_FILE.exists():
        _write_config(DEFAULT_CONFIG)
        _ensure_runtime_dirs(DEFAULT_CONFIG)
        _config_cache = dict(DEFAULT_CONFIG)
        return dict(DEFAULT_CONFIG)

    try:
        current_mtime = os.path.getmtime(CONFIG_FILE)
    except OSError:
        current_mtime = 0.0

    if _config_cache is not None and current_mtime == _config_cache_mtime:
        return dict(_config_cache)

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, json.JSONDecodeError):
        raw = {}

    if not isinstance(raw, dict):
        raw = {}

    config, changed = _normalise_config(raw)
    if changed:
        extras = {k: raw[k] for k in raw if k not in DEFAULT_CONFIG}
        _write_config({**extras, **config})
        try:
            current_mtime = os.path.getmtime(CONFIG_FILE)
        except OSError:
            current_mtime = 0.0
    _ensure_runtime_dirs(config)
    _config_cache = dict(config)
    _config_cache_mtime = current_mtime
    return config


def save_config(key: str, value: Any) -> Dict[str, Any]:
    """Update a known config key after validating/coercing the new value."""
    if key not in DEFAULT_CONFIG:
        raise ConfigError(f"unknown config key: {key}")

    _invalidate_cache()
    config = load_config()
    config[key] = VALIDATORS[key](value)
    config, _ = _normalise_config(config)
    extras = _read_extra_keys()
    _write_config({**extras, **config})
    _invalidate_cache()
    _ensure_runtime_dirs(config)
    return config


def add_tokens(token_string: str) -> int:
    """Add comma-separated tokens; returns the count added."""
    config = load_config()
    existing: List[str] = list(config.get("tokens", []))
    existing_set = set(existing)
    added = 0

    for token in (piece.strip() for piece in token_string.split(",")):
        if token and token not in existing_set:
            existing.append(token)
            existing_set.add(token)
            added += 1

    config["tokens"] = existing
    if not existing:
        config["current_token_index"] = 0
    else:
        config["current_token_index"] %= len(existing)
    extras = _read_extra_keys()
    _write_config({**extras, **config})
    _invalidate_cache()
    return added


def get_next_token() -> str | None:
    """Return the next token in round-robin order, if any exist.

    Keeps the rotating index in memory to avoid a disk write per call.
    The index is persisted when save_config or add_tokens is called.
    """
    global _token_index_override

    config = load_config()
    tokens: List[str] = list(config.get("tokens", []))
    if not tokens:
        _token_index_override = None
        return None

    if _token_index_override is not None:
        index = _token_index_override % len(tokens)
    else:
        index = int(config.get("current_token_index", 0)) % len(tokens)

    _token_index_override = (index + 1) % len(tokens)
    return tokens[index]


def flush_token_index() -> None:
    """Persist the in-memory token index to disk. Call on shutdown."""
    global _token_index_override
    if _token_index_override is not None:
        _invalidate_cache()
        config = load_config()
        config["current_token_index"] = _token_index_override
        extras = _read_extra_keys()
        _write_config({**extras, **config})
        _invalidate_cache()


def list_tokens() -> List[str]:
    """Return masked stored tokens."""
    masked: List[str] = []
    for token in load_config().get("tokens", []):
        if len(token) > 8:
            masked.append(token[:4] + "*" * (len(token) - 8) + token[-4:])
        else:
            masked.append("*" * len(token))
    return masked


def check_tokens() -> Dict[str, Any]:
    """Return token status information."""
    config = load_config()
    return {
        "count": len(config.get("tokens", [])),
        "current_index": config.get("current_token_index", 0),
        "base_url": config.get("base_url", DEFAULT_CONFIG["base_url"]),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Sudo password (stored as an extra key, not part of DEFAULT_CONFIG)
# ─────────────────────────────────────────────────────────────────────────────

def get_sudo_password() -> str:
    """Return the persisted sudo password, or empty string if not set.

    Prefers the system keyring when available, falls back to config file.
    """
    try:
        try:
            import keyring
            pw = keyring.get_password("dsec", "sudo_password")
            if pw:
                return pw
        except Exception:
            pass

        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if isinstance(raw, dict):
                return str(raw.get("sudo_password", ""))
    except (OSError, json.JSONDecodeError):
        pass
    return ""


def set_sudo_password(password: str) -> None:
    """Persist the sudo password.

    Attempt to store in the system keyring; fall back to config file if unavailable.
    """
    try:
        import keyring
        try:
            keyring.set_password("dsec", "sudo_password", password)
            return
        except Exception:
            pass
    except Exception:
        pass

    config = load_config()
    extras = _read_extra_keys()
    extras["sudo_password"] = password
    _write_config({**extras, **config})


def clear_sudo_password() -> None:
    """Remove the sudo password from system keyring and config file."""
    try:
        import keyring
        try:
            keyring.delete_password("dsec", "sudo_password")
        except Exception:
            pass
    except Exception:
        pass

    config = load_config()
    extras = _read_extra_keys()
    extras.pop("sudo_password", None)
    _write_config({**extras, **config})
