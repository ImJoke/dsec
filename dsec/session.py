"""
DSEC Session Management
Each session stored as ~/.dsec/sessions/<name>.json
"""
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import load_config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_cached_sessions_dir: Path | None = None
_session_cache: Dict[str, Dict[str, Any]] = {}
_session_cache_mtime: Dict[str, float] = {}


def _sessions_dir() -> Path:
    global _cached_sessions_dir
    if _cached_sessions_dir is not None and _cached_sessions_dir.is_dir():
        return _cached_sessions_dir
    config = load_config()
    path = Path(config["sessions_dir"]).expanduser()
    path.mkdir(parents=True, exist_ok=True)
    _cached_sessions_dir = path
    return path


def _session_path(name: str) -> Path:
    return _sessions_dir() / f"{name}.json"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Core CRUD
# ---------------------------------------------------------------------------

def load_session(name: str) -> Optional[Dict[str, Any]]:
    """Return session dict or None if not found. Uses mtime-based cache."""
    path = _session_path(name)
    if not path.exists():
        _session_cache.pop(name, None)
        _session_cache_mtime.pop(name, None)
        return None
    try:
        mtime = path.stat().st_mtime
        if name in _session_cache and _session_cache_mtime.get(name) == mtime:
            import copy
            return copy.deepcopy(_session_cache[name])
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        _session_cache[name] = data
        _session_cache_mtime[name] = mtime
        import copy
        return copy.deepcopy(data)
    except (json.JSONDecodeError, IOError):
        return None


def save_session(name: str, data: Dict[str, Any]) -> None:
    """Persist session data; always updates last_used.

    Does NOT mutate the caller's dict — works on a shallow copy.
    Uses an atomic write (temp-file + rename) to prevent corruption.
    """
    data = {**data, "last_used": _now_iso()}
    path = _session_path(name)
    dir_ = path.parent
    dir_.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=dir_, prefix=".tmp_", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
        # Update cache with what we just wrote
        import copy
        _session_cache[name] = copy.deepcopy(data)
        _session_cache_mtime[name] = path.stat().st_mtime
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def list_sessions() -> List[Dict[str, Any]]:
    """Return all sessions sorted by most-recently-modified."""
    sessions_dir = _sessions_dir()
    sessions: List[Dict[str, Any]] = []
    for f in sorted(
        sessions_dir.glob("*.json"),
        key=lambda x: x.stat().st_mtime,
        reverse=True,
    ):
        try:
            with open(f, encoding="utf-8") as fp:
                data = json.load(fp)
            sessions.append(
                {
                    "name": data.get("name", f.stem),
                    "domain": data.get("domain", "htb"),
                    "message_count": data.get("message_count", 0),
                    "model": data.get("model", ""),
                    "last_used": data.get("last_used", ""),
                    "created_at": data.get("created_at", ""),
                    "tags": data.get("tags", []),
                    "conversation_id": data.get("conversation_id"),
                    "notes_count": len(data.get("notes", [])),
                }
            )
        except (json.JSONDecodeError, KeyError, IOError):
            pass
    return sessions


def delete_session(name: str) -> bool:
    """Delete session file. Returns True if it existed."""
    path = _session_path(name)
    if path.exists():
        path.unlink()
        return True
    return False


def rename_session(old: str, new: str) -> bool:
    """Rename session. Returns False if old missing or new already exists."""
    data = load_session(old)
    if not data:
        return False
    new_path = _session_path(new)
    if new_path.exists():
        return False
    data = {**data, "name": new}  # shallow copy is sufficient; we only change a top-level key
    save_session(new, data)
    try:
        _session_path(old).unlink()
    except OSError:
        # If we can't remove the old file, roll back the new one to keep state consistent.
        try:
            new_path.unlink()
        except OSError:
            pass
        return False
    return True


def create_session(name: str, domain: str, model: str) -> Dict[str, Any]:
    """Create a brand-new session and persist it."""
    now = _now_iso()
    data: Dict[str, Any] = {
        "name": name,
        "domain": domain,
        "model": model,
        "conversation_id": None,
        "created_at": now,
        "last_used": now,
        "message_count": 0,
        "tags": [],
        "notes": [],
        "history": [],
        "cumulative_summary": "",  # accumulates all pruned-context summaries across resumes
    }
    save_session(name, data)
    return data


# ---------------------------------------------------------------------------
# Conversation state
# ---------------------------------------------------------------------------

def update_conversation_id(name: str, conversation_id: str) -> bool:
    """Set conversation_id and increment turn count in a single write."""
    data = load_session(name)
    if not data:
        return False
    data["conversation_id"] = conversation_id
    data["message_count"] = data.get("message_count", 0) + 1
    save_session(name, data)
    return True


def set_conversation_id(name: str, conversation_id: str) -> bool:
    """Set the current conversation_id without touching turn counts."""
    data = load_session(name)
    if not data:
        return False
    data["conversation_id"] = conversation_id
    save_session(name, data)
    return True


def increment_message_count(name: str) -> bool:
    """Increment the completed assistant turn count for a session."""
    data = load_session(name)
    if not data:
        return False
    data["message_count"] = data.get("message_count", 0) + 1
    save_session(name, data)
    return True


def add_history_entry(
    name: str,
    role: str,
    content: str,
    thinking: Optional[str] = None,
    compressed: bool = False,
) -> bool:
    """Append a history entry to the session."""
    data = load_session(name)
    if not data:
        return False
    history: List[Dict] = data.get("history", [])
    user_turns = len([h for h in history if h.get("role") == "user"])
    turn = user_turns + (1 if role == "user" else 0)

    entry: Dict[str, Any] = {
        "turn": turn,
        "role": role,
        "content": content,
        "compressed": compressed,
        "timestamp": _now_iso(),
    }
    if thinking:
        entry["thinking"] = thinking[:1000]  # truncate stored thinking
    history.append(entry)
    data["history"] = history
    save_session(name, data)
    return True


# ---------------------------------------------------------------------------
# Notes & Tags
# ---------------------------------------------------------------------------

def add_note(
    name: str, content: str, note_type: str = "misc"
) -> bool:
    """Add a note to the session. Valid types: finding, credential, flag, misc."""
    valid_types = {"finding", "credential", "flag", "misc"}
    if note_type not in valid_types:
        note_type = "misc"
    data = load_session(name)
    if not data:
        return False
    note: Dict[str, Any] = {
        "content": content,
        "timestamp": _now_iso(),
        "type": note_type,
    }
    data.setdefault("notes", []).append(note)
    save_session(name, data)
    return True


def add_tags(name: str, tags: List[str]) -> bool:
    """Add tags to a session (deduplicates automatically)."""
    data = load_session(name)
    if not data:
        return False
    existing = set(data.get("tags", []))
    existing.update(t.lower().strip() for t in tags if t.strip())
    data["tags"] = sorted(existing)
    save_session(name, data)
    return True


def get_current_session_name() -> Optional[str]:
    """Return the most recently used session name, or None."""
    sessions = list_sessions()
    return sessions[0]["name"] if sessions else None


# ---------------------------------------------------------------------------
# Last-session pointer  (~/.dsec/last_session)
# ---------------------------------------------------------------------------

_LAST_SESSION_FILE = Path.home() / ".dsec" / "last_session"


def save_last_session(name: str) -> None:
    """Write the session name to ~/.dsec/last_session for future resume."""
    try:
        _LAST_SESSION_FILE.parent.mkdir(parents=True, exist_ok=True)
        _LAST_SESSION_FILE.write_text(name)
    except Exception:  # noqa: BLE001
        pass


def load_last_session() -> Optional[str]:
    """
    Return the last saved session name if the session file still exists,
    otherwise None.
    """
    try:
        name = _LAST_SESSION_FILE.read_text().strip()
        if name and load_session(name) is not None:
            return name
    except Exception:  # noqa: BLE001
        pass
    return None


def save_turn(
    name: str,
    *,
    conversation_id: Optional[str] = None,
    user_content: str,
    assistant_content: str,
    thinking: Optional[str] = None,
    compressed: bool = False,
) -> bool:
    """Atomically save a full turn (user + assistant) to history."""
    data = load_session(name)
    if not data:
        return False
    
    if conversation_id:
        data["conversation_id"] = conversation_id
        
    history: List[Dict] = data.get("history", [])
    user_turns = len([h for h in history if h.get("role") == "user"])
    turn = user_turns + 1

    # User entry
    history.append({
        "turn": turn,
        "role": "user",
        "content": user_content,
        "compressed": compressed,
        "timestamp": _now_iso(),
    })
    
    # Assistant entry
    ast_entry: Dict[str, Any] = {
        "turn": turn,
        "role": "assistant",
        "content": assistant_content,
        "timestamp": _now_iso(),
    }
    if thinking:
        ast_entry["thinking"] = thinking[:1000] # Thinking boleh dipotong untuk hemat space JSON
    history.append(ast_entry)
    
    data["history"] = history
    data["message_count"] = data.get("message_count", 0) + 1
    save_session(name, data)
    return True