"""
DSEC config management.

Configuration lives in ~/.dsec/config.json and is validated/coerced on load.
Known keys are type-safe; invalid persisted values are reset to defaults.
"""
from __future__ import annotations

import json
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
}


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
    """Load, validate, and normalize config from disk."""
    _ensure_base_dirs()

    if not CONFIG_FILE.exists():
        _write_config(DEFAULT_CONFIG)
        _ensure_runtime_dirs(DEFAULT_CONFIG)
        return dict(DEFAULT_CONFIG)

    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, json.JSONDecodeError):
        raw = {}

    if not isinstance(raw, dict):
        raw = {}

    config, changed = _normalise_config(raw)
    if changed:
        # Merge extra keys (e.g. mcp_servers) back so they are not silently
        # dropped when the config is rewritten due to a value correction.
        # NOTE: _read_extra_keys() re-reads the file; we use the already-parsed
        # `raw` dict here instead to avoid a second disk read.
        extras = {k: raw[k] for k in raw if k not in DEFAULT_CONFIG}
        _write_config({**extras, **config})
    _ensure_runtime_dirs(config)
    return config


def save_config(key: str, value: Any) -> Dict[str, Any]:
    """Update a known config key after validating/coercing the new value."""
    if key not in DEFAULT_CONFIG:
        raise ConfigError(f"unknown config key: {key}")

    config = load_config()
    config[key] = VALIDATORS[key](value)
    config, _ = _normalise_config(config)
    # Preserve unknown extra keys (e.g. mcp_servers) that survive in the file.
    extras = _read_extra_keys()
    _write_config({**extras, **config})
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
    return added


def get_next_token() -> str | None:
    """Return the next token in round-robin order, if any exist."""
    config = load_config()
    tokens: List[str] = list(config.get("tokens", []))
    if not tokens:
        if config.get("current_token_index", 0) != 0:
            config["current_token_index"] = 0
            extras = _read_extra_keys()
            _write_config({**extras, **config})
        return None

    index = int(config.get("current_token_index", 0)) % len(tokens)
    config["current_token_index"] = (index + 1) % len(tokens)
    extras = _read_extra_keys()
    _write_config({**extras, **config})
    return tokens[index]


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
    """Return the persisted sudo password, or empty string if not set."""
    try:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if isinstance(raw, dict):
                return str(raw.get("sudo_password", ""))
    except (OSError, json.JSONDecodeError):
        pass
    return ""


def set_sudo_password(password: str) -> None:
    """Persist the sudo password in config (stored as an extra key)."""
    config = load_config()
    extras = _read_extra_keys()
    extras["sudo_password"] = password
    _write_config({**extras, **config})


def clear_sudo_password() -> None:
    """Remove the sudo password from config."""
    config = load_config()
    extras = _read_extra_keys()
    extras.pop("sudo_password", None)
    _write_config({**extras, **config})
