"""
DSEC Session History Full-Text Search (SQLite FTS5)

Maintains a lazy-built FTS5 index over all session histories so that
/history search <query> can find relevant turns across all past sessions.

The index is stored at ~/.dsec/history_fts.db and rebuilt on demand
whenever the sessions directory is newer than the index.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from .config import load_config


_db_conn: Optional[sqlite3.Connection] = None
_db_path: Optional[Path] = None
_db_lock = threading.Lock()


def _get_db_path() -> Path:
    global _db_path
    if _db_path is None:
        config = load_config()
        _db_path = Path(config.get("sessions_dir", "~/.dsec/sessions")).expanduser().parent / "history_fts.db"
    return _db_path


def _get_conn() -> sqlite3.Connection:
    global _db_conn
    if _db_conn is None:
        p = _get_db_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        _db_conn = sqlite3.connect(str(p), check_same_thread=False)
        _db_conn.row_factory = sqlite3.Row
        _db_conn.execute("PRAGMA journal_mode=WAL")
        _db_conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS turns USING fts5(
                session,
                role,
                content,
                timestamp,
                turn UNINDEXED
            )
        """)
        _db_conn.execute("""
            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        _db_conn.commit()
    return _db_conn


def _get_sessions_dir() -> Path:
    config = load_config()
    return Path(config.get("sessions_dir", "~/.dsec/sessions")).expanduser()


def _sessions_mtime() -> float:
    sd = _get_sessions_dir()
    if not sd.exists():
        return 0.0
    try:
        latest = max(
            (f.stat().st_mtime for f in sd.glob("*.json")),
            default=0.0,
        )
        return latest
    except Exception:
        return 0.0


def _index_mtime() -> float:
    conn = _get_conn()
    row = conn.execute("SELECT value FROM meta WHERE key='indexed_at'").fetchone()
    if row:
        try:
            return float(row["value"])
        except (ValueError, TypeError):
            pass
    return 0.0


def _needs_rebuild() -> bool:
    return _sessions_mtime() > _index_mtime()


def rebuild_index(force: bool = False) -> int:
    """
    (Re)build the FTS5 index from all session JSON files.
    Returns the number of turns indexed.
    """
    if not force and not _needs_rebuild():
        return -1  # already up to date

    conn = _get_conn()
    sd = _get_sessions_dir()

    rows_to_insert = []
    for path in sd.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            continue
        session_name = data.get("name", path.stem)
        for entry in data.get("history", []):
            role = entry.get("role", "")
            content = entry.get("content", "")
            ts = entry.get("timestamp", "")
            turn = entry.get("turn", 0)
            if not content:
                continue
            rows_to_insert.append((session_name, role, content[:4000], ts, turn))

    with _db_lock:
        conn.execute("DELETE FROM turns")
        conn.executemany(
            "INSERT INTO turns(session, role, content, timestamp, turn) VALUES (?,?,?,?,?)",
            rows_to_insert,
        )
        conn.execute(
            "INSERT OR REPLACE INTO meta(key, value) VALUES ('indexed_at', ?)",
            (str(time.time()),),
        )
        conn.commit()
    return len(rows_to_insert)


def search_history(
    query: str,
    limit: int = 20,
    session_filter: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Full-text search across all indexed session turns.
    Returns a list of matching entries, ordered by relevance (rank).
    """
    if not query or not query.strip():
        return []

    # Rebuild index if sessions have changed since last index.
    rebuild_index()

    conn = _get_conn()

    try:
        if session_filter:
            rows = conn.execute(
                """
                SELECT session, role, content, timestamp, turn,
                       highlight(turns, 2, '[', ']') AS snippet
                FROM turns
                WHERE turns MATCH ? AND session = ?
                ORDER BY rank
                LIMIT ?
                """,
                (query, session_filter, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT session, role, content, timestamp, turn,
                       highlight(turns, 2, '[', ']') AS snippet
                FROM turns
                WHERE turns MATCH ?
                ORDER BY rank
                LIMIT ?
                """,
                (query, limit),
            ).fetchall()
    except sqlite3.OperationalError:
        # FTS5 syntax error (e.g. bare special chars) — retry with quoted query,
        # preserving the session_filter if one was supplied.
        safe_q = '"' + query.replace('"', '""') + '"'
        try:
            if session_filter:
                rows = conn.execute(
                    """
                    SELECT session, role, content, timestamp, turn,
                           highlight(turns, 2, '[', ']') AS snippet
                    FROM turns
                    WHERE turns MATCH ? AND session = ?
                    ORDER BY rank
                    LIMIT ?
                    """,
                    (safe_q, session_filter, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT session, role, content, timestamp, turn,
                           highlight(turns, 2, '[', ']') AS snippet
                    FROM turns
                    WHERE turns MATCH ?
                    ORDER BY rank
                    LIMIT ?
                    """,
                    (safe_q, limit),
                ).fetchall()
        except Exception:
            return []

    results = []
    for row in rows:
        snippet = row["snippet"] or ""
        # Trim snippet to 200 chars around first highlight marker
        if "[" in snippet:
            start = max(0, snippet.index("[") - 60)
            snippet = ("…" if start > 0 else "") + snippet[start:start + 200]
            if len(row["snippet"] or "") > start + 200:
                snippet += "…"
        results.append({
            "session": row["session"],
            "role": row["role"],
            "turn": row["turn"],
            "timestamp": row["timestamp"],
            "snippet": snippet,
            "content": (row["content"] or "")[:300],
        })
    return results


def invalidate_index() -> None:
    """Force next search to rebuild the index (call after saving a session)."""
    conn = _get_conn()
    with _db_lock:
        conn.execute("DELETE FROM meta WHERE key='indexed_at'")
        conn.commit()
