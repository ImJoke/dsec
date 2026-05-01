"""
DSEC File Tools

Lets the AI create and edit scripts/files directly instead of using
`python3 -c "..."` one-liners or shell heredocs.

Tools:
  write_file  — create or overwrite a file with full content
  read_file   — read a file (for verification before editing)
  patch_file  — targeted find-and-replace in an existing file
"""
import os
from pathlib import Path
from typing import Optional

from dsec.core.registry import register


def _safe_path(path: str) -> Path:
    """Resolve path, allowing ~ expansion. Refuses writing outside $HOME."""
    p = Path(path).expanduser().resolve()
    home = Path.home().resolve()
    # /tmp on macOS resolves to /private/tmp — accept both the symlink and the real path
    _tmp_real = Path("/tmp").resolve()
    if not (str(p).startswith(str(home)) or str(p).startswith("/tmp") or str(p).startswith(str(_tmp_real))):
        raise ValueError(
            f"Path '{p}' is outside $HOME and /tmp. "
            "For safety, write_file only writes within your home directory or /tmp."
        )
    return p


# ═══════════════════════════════════════════════════════════════════════════
# write_file
# ═══════════════════════════════════════════════════════════════════════════

@register(
    "write_file",
    (
        "Write content to a file, creating it (and any parent dirs) if needed.\n"
        "\n"
        "USE INSTEAD OF:\n"
        "  - bash python3 -c '...'        → write script, then bash python3 script.py\n"
        "  - bash 'cat << EOF > file\\n...'  → use write_file directly\n"
        "  - bash 'echo -e ... > file'    → use write_file directly\n"
        "\n"
        "TYPICAL WORKFLOW:\n"
        "  1. write_file(path='/tmp/exploit.py', content='...')  # create script\n"
        "  2. bash('python3 /tmp/exploit.py')                    # run it\n"
        "  3. write_file(path='/tmp/exploit.py', content='...')  # edit & retry\n"
        "\n"
        "PARAMETERS:\n"
        "  path     absolute or ~/relative path (creates parent dirs automatically)\n"
        "  content  full file content (UTF-8). Completely replaces existing file.\n"
        "  mode     optional: 'append' to append instead of overwrite (default: 'write')\n"
        "\n"
        "NOTES:\n"
        "  - Restricted to paths inside $HOME or /tmp for safety\n"
        "  - Returns the path and byte size on success\n"
        "  - Use patch_file for targeted edits to avoid re-sending the whole file\n"
    ),
)
def write_file(path: str, content: str, mode: str = "write") -> str:
    if not path:
        return "[error: 'path' is required]"
    if content is None:
        return "[error: 'content' is required]"

    try:
        p = _safe_path(path)
    except ValueError as e:
        return f"[error: {e}]"

    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        write_mode = "a" if mode == "append" else "w"
        p.write_text(content, encoding="utf-8") if write_mode == "w" else open(p, "a", encoding="utf-8").write(content)
        size = p.stat().st_size
        lines = content.count("\n") + (1 if content and not content.endswith("\n") else 0)
        action = "Appended to" if mode == "append" else "Wrote"
        return f"[{action} '{p}' — {size} bytes, {lines} lines]"
    except OSError as e:
        return f"[error writing '{path}': {e}]"


# ═══════════════════════════════════════════════════════════════════════════
# read_file
# ═══════════════════════════════════════════════════════════════════════════

@register(
    "read_file",
    (
        "Read a file's contents. Use to verify a script before running it,\n"
        "or to read tool output saved to disk.\n"
        "\n"
        "PARAMETERS:\n"
        "  path    path to the file\n"
        "  offset  line number to start reading from (1-based, default: 1)\n"
        "  limit   max lines to return (default: 200)\n"
    ),
)
def read_file(path: str, offset: int = 1, limit: int = 200) -> str:
    if not path:
        return "[error: 'path' is required]"
    try:
        p = Path(path).expanduser().resolve()
        if not p.exists():
            return f"[error: '{p}' does not exist]"
        if not p.is_file():
            return f"[error: '{p}' is not a file]"

        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        total = len(lines)
        start = max(0, offset - 1)
        end = start + limit
        chunk = lines[start:end]
        header = f"['{p}' — {total} lines total"
        if start > 0 or end < total:
            header += f", showing lines {start+1}–{min(end, total)}"
        header += "]"
        return header + "\n" + "\n".join(chunk)
    except OSError as e:
        return f"[error reading '{path}': {e}]"


# ═══════════════════════════════════════════════════════════════════════════
# patch_file
# ═══════════════════════════════════════════════════════════════════════════

@register(
    "patch_file",
    (
        "Targeted find-and-replace edit in an existing file.\n"
        "More efficient than write_file for small changes — only send the diff.\n"
        "\n"
        "PARAMETERS:\n"
        "  path        path to the file to edit\n"
        "  old_string  exact text to find (must appear exactly once unless replace_all=true)\n"
        "  new_string  replacement text (empty string to delete the matched section)\n"
        "  replace_all optional: replace every occurrence (default: false)\n"
        "\n"
        "EXAMPLE — change a port number in a script:\n"
        "  patch_file(\n"
        "    path='/tmp/exploit.py',\n"
        "    old_string='PORT = 4444',\n"
        "    new_string='PORT = 9001'\n"
        "  )\n"
    ),
)
def patch_file(
    path: str,
    old_string: str,
    new_string: str,
    replace_all: bool = False,
) -> str:
    if not path:
        return "[error: 'path' is required]"
    if old_string is None:
        return "[error: 'old_string' is required]"
    if new_string is None:
        return "[error: 'new_string' is required]"

    try:
        p = Path(path).expanduser().resolve()
    except Exception as e:
        return f"[error: {e}]"

    if not p.exists():
        return f"[error: '{p}' does not exist — use write_file to create it first]"

    try:
        original = p.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        return f"[error reading '{path}': {e}]"

    count = original.count(old_string)
    if count == 0:
        # Show a snippet of the file to help the AI diagnose
        snippet = "\n".join(original.splitlines()[:20])
        return (
            f"[error: old_string not found in '{p}']\n"
            f"First 20 lines of file:\n{snippet}"
        )
    if count > 1 and not replace_all:
        return (
            f"[error: old_string appears {count} times in '{p}'. "
            "Use replace_all=true to replace all, or provide more context to make it unique.]"
        )

    if replace_all:
        modified = original.replace(old_string, new_string)
        n_replaced = count
    else:
        modified = original.replace(old_string, new_string, 1)
        n_replaced = 1

    try:
        p.write_text(modified, encoding="utf-8")
    except OSError as e:
        return f"[error writing '{path}': {e}]"

    size = p.stat().st_size
    return f"[Patched '{p}' — replaced {n_replaced} occurrence(s), {size} bytes total]"
