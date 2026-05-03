"""
DSEC Knowledge Base — Personal Obsidian notes ingestion.

Indexes the user's Obsidian vault (HTB writeups, AD/ADCS attack notes, CTF solves,
crypto techniques, web exploitation references) into an in-memory BM25 index so
the AI agent can semantically retrieve battle-tested commands when stuck.

Default vault: ~/Documents/vincent/The Repository v2
Configurable via DSEC_NOTES_DIR env var or config["notes_dir"].
"""
from __future__ import annotations

import math
import os
import re
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ─── Vault discovery ─────────────────────────────────────────────────────────

_DEFAULT_VAULT_CANDIDATES = [
    "~/Documents/vincent",                               # whole notes directory (preferred)
    "~/Documents/vincent/The Repository v2",
    "~/Documents/vincent/The Repository v3 - Shadow Garden",
    "~/.dsec/notes",
]


def _has_md_shallow(p: Path, max_depth: int = 3) -> bool:
    """Check if path contains .md within max_depth without full rglob."""
    try:
        for entry in p.iterdir():
            if entry.is_file() and entry.suffix == ".md":
                return True
            if entry.is_dir() and not entry.name.startswith("."):
                if max_depth > 0 and _has_md_shallow(entry, max_depth - 1):
                    return True
    except (PermissionError, OSError):
        pass
    return False


def _resolve_vault_dir() -> Optional[Path]:
    """Find the active Obsidian vault. Env var > config > default candidates."""
    env = os.environ.get("DSEC_NOTES_DIR")
    if env:
        p = Path(env).expanduser().resolve()
        return p if p.is_dir() else None
    try:
        from .config import load_config
        cfg = load_config()
        configured = cfg.get("notes_dir")
        if configured:
            p = Path(str(configured)).expanduser().resolve()
            if p.is_dir():
                return p
    except Exception:
        pass
    for cand in _DEFAULT_VAULT_CANDIDATES:
        p = Path(cand).expanduser().resolve()
        if p.is_dir() and _has_md_shallow(p):
            return p
    return None


# ─── Tokenizer ───────────────────────────────────────────────────────────────

_STOPWORDS = {
    "the", "a", "an", "and", "or", "but", "is", "are", "was", "were", "be",
    "been", "being", "to", "of", "in", "on", "at", "for", "with", "by",
    "from", "as", "this", "that", "it", "its", "we", "you", "your", "i",
    "if", "then", "than", "else", "so", "no", "not", "do", "does", "did",
    "have", "has", "had", "can", "will", "would", "should", "could", "may",
    "might", "must", "shall", "very", "just", "also", "any", "some", "all",
}


def _tokenize(text: str) -> List[str]:
    """Lowercase, split on non-alphanumeric (keep dots/dashes for tool names)."""
    # Keep tool names like nxc, evil-winrm, certipy intact.
    tokens = re.findall(r"[a-zA-Z][a-zA-Z0-9_\-\.]*[a-zA-Z0-9]|[a-zA-Z]", text.lower())
    return [t for t in tokens if len(t) > 1 and t not in _STOPWORDS]


# ─── Note parser ─────────────────────────────────────────────────────────────

_TAG_LINE_RE = re.compile(r"^tags:\s*((?:#\S+\s*)+)\s*$", re.MULTILINE)
_TITLE_RE = re.compile(r"^#\s+(.+)$", re.MULTILINE)


def _parse_note(path: Path) -> Optional[Dict[str, Any]]:
    """Parse a single .md note into {path, title, tags, body, tokens}."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None
    if not text.strip():
        return None

    title_m = _TITLE_RE.search(text[:500])
    title = title_m.group(1).strip() if title_m else path.stem

    tags: List[str] = []
    tag_m = _TAG_LINE_RE.search(text[:500])
    if tag_m:
        tags = [t.strip("#") for t in tag_m.group(1).split() if t.startswith("#")]

    # Truncate body to 8KB for memory efficiency (most notes fit, and the agent
    # gets a snippet anyway)
    body = text[:8192]

    tokens = _tokenize(title + " " + " ".join(tags) + " " + body)
    return {
        "path": str(path),
        "title": title,
        "tags": tags,
        "body": body,
        "tokens": tokens,
    }


# ─── BM25 index ──────────────────────────────────────────────────────────────

class _BM25Index:
    """Minimal BM25 (k1=1.5, b=0.75) over a list of token lists."""

    K1 = 1.5
    B = 0.75

    def __init__(self, docs_tokens: List[List[str]]):
        self.docs_tokens = docs_tokens
        self.N = len(docs_tokens)
        self.avgdl = sum(len(d) for d in docs_tokens) / max(1, self.N)
        # Build doc frequency
        df: Dict[str, int] = {}
        for tokens in docs_tokens:
            for term in set(tokens):
                df[term] = df.get(term, 0) + 1
        self.df = df
        # Precompute term frequencies per doc
        self.tf: List[Dict[str, int]] = []
        for tokens in docs_tokens:
            counts: Dict[str, int] = {}
            for t in tokens:
                counts[t] = counts.get(t, 0) + 1
            self.tf.append(counts)

    def _idf(self, term: str) -> float:
        # BM25+ idf with floor at 0 to avoid negative weights
        df = self.df.get(term, 0)
        if df == 0:
            return 0.0
        return max(0.0, math.log((self.N - df + 0.5) / (df + 0.5) + 1.0))

    def score(self, doc_idx: int, query_tokens: List[str]) -> float:
        if doc_idx >= self.N:
            return 0.0
        dl = len(self.docs_tokens[doc_idx])
        tf = self.tf[doc_idx]
        s = 0.0
        for term in query_tokens:
            f = tf.get(term, 0)
            if f == 0:
                continue
            idf = self._idf(term)
            denom = f + self.K1 * (1 - self.B + self.B * dl / max(1.0, self.avgdl))
            s += idf * (f * (self.K1 + 1)) / max(1e-9, denom)
        return s


# ─── Singleton index, lazy-loaded ────────────────────────────────────────────

_lock = threading.Lock()
_state: Dict[str, Any] = {
    "loaded": False,
    "vault": None,
    "notes": [],          # parsed dicts
    "bm25": None,
}


def _load_index(force: bool = False) -> Dict[str, Any]:
    """Build the index under lock. Returns a snapshot dict — readers are safe
    even if another thread later swaps _state, since they hold their own ref."""
    with _lock:
        if _state["loaded"] and not force:
            # Return a shallow snapshot dict (readers hold their own ref to
            # immutable note list + bm25 instance, so later force-reload is safe)
            return dict(_state)
        vault = _resolve_vault_dir()
        if not vault:
            snap = {"loaded": True, "vault": None, "notes": [], "bm25": None}
            _state.update(snap)
            return dict(snap)

        notes: List[Dict[str, Any]] = []
        for md_path in vault.rglob("*.md"):
            # Skip Obsidian internals (case-insensitive on path components)
            parts_lower = {p.lower() for p in md_path.parts}
            if any(s in parts_lower for s in (".obsidian", ".trash", "templates")):
                continue
            note = _parse_note(md_path)
            if note:
                notes.append(note)

        bm25 = _BM25Index([n["tokens"] for n in notes]) if notes else None

        snap = {"loaded": True, "vault": str(vault), "notes": notes, "bm25": bm25}
        _state.update(snap)
        return dict(snap)


# ─── Public API ──────────────────────────────────────────────────────────────

def get_status() -> Dict[str, Any]:
    s = _load_index()
    return {
        "vault": s["vault"],
        "note_count": len(s["notes"]),
        "indexed": s["bm25"] is not None,
    }


def reload_index() -> Dict[str, Any]:
    return _load_index(force=True)


def search(
    query: str,
    *,
    tags: Optional[List[str]] = None,
    limit: int = 5,
    min_score: float = 0.5,
) -> List[Dict[str, Any]]:
    """Return top matching notes for a natural-language query."""
    s = _load_index()
    notes: List[Dict[str, Any]] = s["notes"]
    bm25: Optional[_BM25Index] = s["bm25"]
    if not notes or bm25 is None:
        return []

    q_tokens = _tokenize(query)
    if not q_tokens:
        return []

    # Pre-filter by tag if requested (case-insensitive)
    if tags:
        wanted = {t.lower().strip("#") for t in tags}
        candidate_idx = [
            i for i, n in enumerate(notes)
            if any(t.lower() in wanted for t in n["tags"])
        ]
    else:
        candidate_idx = list(range(len(notes)))

    scored: List[Tuple[float, int]] = []
    for i in candidate_idx:
        sc = bm25.score(i, q_tokens)
        # Boost for query terms appearing in the title
        title_low = notes[i]["title"].lower()
        for tok in q_tokens:
            if tok in title_low:
                sc += 1.5
        if sc >= min_score:
            scored.append((sc, i))

    scored.sort(key=lambda x: x[0], reverse=True)

    out: List[Dict[str, Any]] = []
    for sc, i in scored[:limit]:
        n = notes[i]
        out.append({
            "title": n["title"],
            "path": n["path"],
            "tags": n["tags"],
            "score": round(sc, 3),
            "body": n["body"],
        })
    return out


def get_note(title_or_path: str) -> Optional[Dict[str, Any]]:
    """Fetch a single note by exact title (case-insensitive) or path substring."""
    s = _load_index()
    notes: List[Dict[str, Any]] = s["notes"]
    if not notes:
        return None
    target = title_or_path.lower().strip()
    for n in notes:
        if n["title"].lower() == target:
            return n
    for n in notes:
        if target in n["path"].lower():
            return n
    return None


def list_tags(min_count: int = 2) -> List[Tuple[str, int]]:
    """Return tags with their counts, sorted descending."""
    s = _load_index()
    counts: Dict[str, int] = {}
    for n in s["notes"]:
        for t in n["tags"]:
            counts[t] = counts.get(t, 0) + 1
    return sorted(
        [(t, c) for t, c in counts.items() if c >= min_count],
        key=lambda x: x[1],
        reverse=True,
    )
