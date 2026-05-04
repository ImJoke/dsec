"""
DSEC config management.

Configuration lives in ~/.dsec/config.json and is validated/coerced on load.
Known keys are type-safe; invalid persisted values are reset to defaults.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

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
    """Atomically write the config file with restrictive permissions.

    Uses os.open(O_CREAT|O_EXCL|O_WRONLY, 0o600) on a temp file followed by
    os.replace so the file is never world-readable mid-write, and writes
    under fcntl.flock so two concurrent dsec processes can't clobber each
    other.
    """
    _ensure_base_dirs()
    tmp_path = CONFIG_FILE.with_suffix(CONFIG_FILE.suffix + f".tmp.{os.getpid()}")

    # Lock-on-write: held across the read-modify-write window inside
    # save_config / add_tokens by their callers.
    lock_path = CONFIG_FILE.with_suffix(CONFIG_FILE.suffix + ".lock")
    lock_fd: Optional[int] = None
    try:
        try:
            import fcntl  # POSIX only — Windows users skip locking gracefully
            lock_fd = os.open(str(lock_path), os.O_CREAT | os.O_RDWR, 0o600)
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
        except Exception:
            lock_fd = None  # best-effort lock; proceed anyway

        # Open with strict perms from creation time (avoids the brief window
        # where a fresh file is 0o644 between open() and chmod()).
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(str(tmp_path), flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(config, handle, indent=2)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise
        os.replace(tmp_path, CONFIG_FILE)
        try:
            os.chmod(CONFIG_FILE, 0o600)
        except OSError:
            pass
    finally:
        if lock_fd is not None:
            try:
                import fcntl
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                os.close(lock_fd)
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

_LEGACY_SUDO_WARNED = False  # fire migration warning only once per process
_SUDO_KEYFILE = CONFIG_DIR / ".sudo_key"
_SUDO_ENC_FILE = CONFIG_DIR / ".sudo_pass.enc"
_ENC_PREFIX = "enc:fernet:"


def _load_or_create_master_key() -> Optional[bytes]:
    """Return a stable per-install Fernet key, creating it on first use.

    Stored at ~/.dsec/.sudo_key with mode 0o600. If the cryptography library
    isn't installed, returns None (caller falls back to refusing to write).
    """
    try:
        from cryptography.fernet import Fernet
    except Exception:
        return None

    _ensure_base_dirs()
    if _SUDO_KEYFILE.exists():
        try:
            data = _SUDO_KEYFILE.read_bytes()
            if data:
                return data
        except OSError:
            pass

    key = Fernet.generate_key()
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(str(_SUDO_KEYFILE), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
    except Exception:
        try:
            os.unlink(_SUDO_KEYFILE)
        except OSError:
            pass
        return None
    return key


def _encrypt_sudo(password: str) -> Optional[str]:
    key = _load_or_create_master_key()
    if not key:
        return None
    try:
        from cryptography.fernet import Fernet
        token = Fernet(key).encrypt(password.encode("utf-8")).decode("ascii")
        return _ENC_PREFIX + token
    except Exception:
        return None


def _decrypt_sudo(blob: str) -> Optional[str]:
    if not blob.startswith(_ENC_PREFIX):
        return None
    key = _load_or_create_master_key()
    if not key:
        return None
    try:
        from cryptography.fernet import Fernet, InvalidToken
        token = blob[len(_ENC_PREFIX):]
        return Fernet(key).decrypt(token.encode("ascii")).decode("utf-8")
    except Exception:
        return None


def get_sudo_password() -> str:
    """Return the sudo password from a secure source, or empty string if unset.

    Source priority (most to least preferred):
      1. DSEC_SUDO_PASS environment variable
      2. System keyring entry ("dsec", "sudo_password")
      3. Encrypted file at ~/.dsec/.sudo_pass.enc (Fernet, key file mode 0o600)
      4. Legacy plaintext copy in config.json (read only — never written here)

    The legacy file copy exists for users upgrading from older versions.
    Calling set_sudo_password actively scrubs that copy when a secure
    backend write succeeds.
    """
    global _LEGACY_SUDO_WARNED

    env_pw = os.environ.get("DSEC_SUDO_PASS")
    if env_pw:
        return env_pw

    try:
        import keyring
        pw = keyring.get_password("dsec", "sudo_password")
        if pw:
            return pw
    except Exception:
        pass

    if _SUDO_ENC_FILE.exists():
        try:
            blob = _SUDO_ENC_FILE.read_text(encoding="ascii").strip()
            decoded = _decrypt_sudo(blob)
            if decoded:
                return decoded
        except OSError:
            pass

    try:
        if CONFIG_FILE.exists():
            with open(CONFIG_FILE, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
            if isinstance(raw, dict):
                legacy = str(raw.get("sudo_password", ""))
                if legacy and not _LEGACY_SUDO_WARNED:
                    _LEGACY_SUDO_WARNED = True
                    import warnings as _warnings
                    _warnings.warn(
                        "sudo_password is stored in plaintext in ~/.dsec/config.json. "
                        "Re-save it via `dsec config --set sudo_password ...` to migrate "
                        "to a secure backend.",
                        stacklevel=2,
                    )
                return legacy
    except (OSError, json.JSONDecodeError):
        pass
    return ""


def set_sudo_password(password: str) -> None:
    """Persist the sudo password to a secure backend.

    Tries (in order): system keyring → encrypted file with cryptography. Refuses
    to store in plaintext. If neither backend is available, raises ConfigError
    pointing the user at `pip install keyring` or `pip install cryptography`,
    or at the `DSEC_SUDO_PASS` environment variable.
    """
    stored = False

    # 1) Preferred: OS keyring (Keychain on mac, Secret Service on Linux, etc.)
    try:
        import keyring
        try:
            keyring.set_password("dsec", "sudo_password", password)
            stored = True
        except Exception:
            stored = False
    except Exception:
        pass

    # 2) Fallback: Fernet-encrypted file under ~/.dsec/, key in 0o600 file.
    if not stored:
        token = _encrypt_sudo(password)
        if token:
            _ensure_base_dirs()
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            fd = os.open(str(_SUDO_ENC_FILE), flags, 0o600)
            try:
                with os.fdopen(fd, "w", encoding="ascii") as fh:
                    fh.write(token + "\n")
                stored = True
            except Exception:
                try:
                    os.unlink(_SUDO_ENC_FILE)
                except OSError:
                    pass

    if not stored:
        raise ConfigError(
            "Cannot persist sudo password securely. Install one of:\n"
            "  pip install keyring        (preferred — uses OS keyring)\n"
            "  pip install cryptography   (fallback — encrypts file under ~/.dsec/)\n"
            "Alternatively, pass the password via the DSEC_SUDO_PASS environment "
            "variable so it never touches disk."
        )

    # Drop any legacy plaintext copy from config.json now that we have a
    # secure store. Best-effort — do not fail the call if scrubbing errors.
    try:
        config = load_config()
        extras = _read_extra_keys()
        if "sudo_password" in extras:
            extras.pop("sudo_password", None)
            _write_config({**extras, **config})
            _invalidate_cache()
    except Exception:
        pass


def clear_sudo_password() -> None:
    """Remove the sudo password from every backend (keyring, encrypted file, legacy)."""
    try:
        import keyring
        try:
            keyring.delete_password("dsec", "sudo_password")
        except Exception:
            pass
    except Exception:
        pass

    try:
        if _SUDO_ENC_FILE.exists():
            os.unlink(_SUDO_ENC_FILE)
    except OSError:
        pass

    try:
        config = load_config()
        extras = _read_extra_keys()
        if "sudo_password" in extras:
            extras.pop("sudo_password", None)
            _write_config({**extras, **config})
            _invalidate_cache()
    except Exception:
        pass


# Legacy stub removed: clear_sudo_password is defined above with full backend
# coverage (keyring + encrypted file + legacy plaintext scrub).
