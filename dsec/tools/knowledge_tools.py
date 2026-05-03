"""
DSEC Knowledge Base Tools — exposes the user's Obsidian notes to the agent.

The agent can call:
- notes_search(query, tags?, limit?) — semantic search across all notes
- notes_get(title) — fetch a full note by title
- notes_tags() — list available tags
- notes_reload() — re-scan vault after manual edits

Notes are battle-tested HTB writeups, AD/ADCS/Web/CTF techniques, etc.
"""
from __future__ import annotations

from typing import Optional, List

from dsec.core.registry import register
from dsec.knowledge_base import (
    search as kb_search,
    get_note as kb_get,
    list_tags as kb_tags,
    get_status as kb_status,
    reload_index as kb_reload,
)


def _format_snippet(body: str, max_chars: int = 1500) -> str:
    """Trim body to a readable snippet."""
    if len(body) <= max_chars:
        return body
    return body[:max_chars].rstrip() + "\n...[snippet truncated — use notes_get for full content]"


_WRITEUP_TERMS = {
    "writeup", "write-up", "write up", "walkthrough", "walk-through", "solution",
    "spoiler", "solved", "how to solve", "how to get", "flag",
}

_WRITEUP_QUERY_RE = __import__("re").compile(
    r"\b(writeup|write.up|walkthrough|walk.through|solution|spoiler|how to solve|flag)\b",
    __import__("re").IGNORECASE,
)


@register(
    "notes_search",
    "Semantic search over personal Obsidian notes: AD/ADCS/Kerberos/web/CTF techniques, "
    "impacket usage, tool syntax, attack patterns, enumeration references. "
    "ONLY search for TECHNIQUES and TOOLS — never search for a specific machine name "
    "or 'writeup'/'walkthrough' — that would be cheating and is blocked.",
)
def notes_search(query: str, tags: Optional[str] = None, limit: int = 5) -> str:
    # Block writeup/solution searches — agent must solve independently
    if _WRITEUP_QUERY_RE.search(query):
        return (
            "[notes_search] ⛔ Query blocked: searching for writeups or solutions is not allowed. "
            "Use notes_search ONLY for attack techniques, tool syntax, and protocol references. "
            "Solve the machine independently — do not look for hints or solutions."
        )
    status = kb_status()
    if status["note_count"] == 0:
        return (
            "[notes_search] No notes vault found. "
            "Set DSEC_NOTES_DIR env var or config['notes_dir'] to your Obsidian vault path."
        )
    tag_list: Optional[List[str]] = None
    if tags:
        tag_list = [t.strip().lstrip("#") for t in tags.split(",") if t.strip()]

    results = kb_search(query, tags=tag_list, limit=int(limit))
    if not results:
        return f"[notes_search] No matches for '{query}'" + (f" (tags={tag_list})" if tag_list else "")

    lines = [
        f"[notes_search] Found {len(results)} match(es) from {status['note_count']} notes:",
        "",
    ]
    for i, r in enumerate(results, 1):
        tags_str = " ".join(f"#{t}" for t in r["tags"]) if r["tags"] else "(no tags)"
        lines.append(f"━━━ {i}. {r['title']}  [score={r['score']}]")
        lines.append(f"    Tags: {tags_str}")
        lines.append(f"    Path: {r['path']}")
        lines.append("")
        lines.append(_format_snippet(r["body"]))
        lines.append("")
    return "\n".join(lines)


@register(
    "notes_get",
    "Fetch the full content of a note by exact title (e.g. 'ADCS - ESC15 Exploitation'). "
    "Use after notes_search when you need the complete writeup.",
)
def notes_get(title: str) -> str:
    note = kb_get(title)
    if not note:
        return f"[notes_get] No note found matching '{title}'. Try notes_search first."
    tags_str = " ".join(f"#{t}" for t in note["tags"]) if note["tags"] else "(no tags)"
    header = (
        f"━━━ {note['title']}\n"
        f"Tags: {tags_str}\n"
        f"Path: {note['path']}\n"
        f"━━━\n\n"
    )
    return header + note["body"]


@register(
    "notes_tags",
    "List all available note tags with counts. Useful to discover what topics are documented.",
)
def notes_tags(min_count: int = 2) -> str:
    tags = kb_tags(min_count=int(min_count))
    if not tags:
        return "[notes_tags] No tags found."
    status = kb_status()
    lines = [f"[notes_tags] {len(tags)} tag(s) across {status['note_count']} notes:", ""]
    for tag, count in tags:
        lines.append(f"  #{tag} ({count})")
    return "\n".join(lines)


@register(
    "notes_reload",
    "Re-scan the notes vault after manual additions or edits.",
)
def notes_reload() -> str:
    state = kb_reload()
    return (
        f"[notes_reload] Re-indexed {len(state['notes'])} note(s) "
        f"from {state['vault'] or '(no vault found)'}."
    )
