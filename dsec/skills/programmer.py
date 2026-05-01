"""
DSEC Programmer Skills – Code editing, file management, and analysis tools.

Provides the agent with Aider/RooCode-style capabilities:
  • View, edit, create, and search files
  • Directory tree listing
  • Diff generation
  • Code search (grep)

Inspired by: Aider, RooCode
"""
import difflib
import os
import re
from typing import List, Optional

from dsec.core.registry import register


@register("programmer_view_file", "Views the content of a local file with line numbers.")
def programmer_view_file(filepath: str, start_line: int = 0, end_line: int = 0) -> str:
    if not os.path.exists(filepath):
        return f"File not found: {filepath}"
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()

        total = len(lines)
        if start_line > 0 and end_line > 0:
            # 1-indexed range
            start = max(0, start_line - 1)
            end = min(total, end_line)
            subset = lines[start:end]
            offset = start
        elif total > 500:
            # Large file: show first 200 lines
            subset = lines[:200]
            offset = 0
            header = f"[showing lines 1-200 of {total}. Use start_line/end_line to view more.]\n"
        else:
            subset = lines
            offset = 0
            header = ""

        numbered = []
        for i, line in enumerate(subset):
            numbered.append(f"{offset + i + 1:>5}: {line.rstrip()}")

        result = "\n".join(numbered)
        if start_line == 0 and end_line == 0 and total > 500:
            result = header + result
        return result
    except Exception as e:
        return f"Error reading file {filepath}: {e}"


@register("programmer_edit_file", "Edits a file by replacing an exact old block of code with a new block (Aider SEARCH/REPLACE style).")
def programmer_edit_file(filepath: str, old_content: str, new_content: str) -> str:
    if not os.path.exists(filepath):
        return f"File not found: {filepath}"
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()

        # Handle Windows vs Unix newlines
        old_content = old_content.replace("\r\n", "\n")
        new_content = new_content.replace("\r\n", "\n")
        content = content.replace("\r\n", "\n")

        if old_content not in content:
            # Try fuzzy matching (ignore leading/trailing whitespace on each line)
            def normalize_lines(text):
                return "\n".join(line.strip() for line in text.strip().splitlines() if line.strip())
                
            norm_old = normalize_lines(old_content)
            norm_content = normalize_lines(content)
            
            if norm_old not in norm_content:
                return "Error: old_content not found in the file exactly as specified. Please check whitespace and try again."
            
            return "Error: old_content found but whitespace/indentation doesn't match exactly. Provide the EXACT whitespace to replace."

        count = content.count(old_content)
        new_file_content = content.replace(old_content, new_content, 1)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(new_file_content)

        msg = f"Successfully updated {filepath}."
        if count > 1:
            msg += f" (Note: {count} occurrences found, only the first was replaced)"
        return msg
    except Exception as e:
        return f"Error editing file {filepath}: {e}"


@register(
    "programmer_create_file",
    "Creates a new file with the specified content. "
    "Params: filepath (or 'path'), content (or 'text'). "
    "Prefer write_file for new code — it handles overwrite and parent-dir creation.",
)
def programmer_create_file(filepath: str = "", content: str = "", **kwargs) -> str:
    # Accept common aliases
    filepath = filepath or kwargs.get("path", "") or kwargs.get("file_path", "")
    content = content or kwargs.get("text", "") or kwargs.get("file_content", "") or kwargs.get("body", "")
    if not filepath:
        return "[error: programmer_create_file requires 'filepath' (or 'path') parameter]"
    if content is None:
        content = ""
    try:
        parent = os.path.dirname(os.path.abspath(filepath))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return f"Successfully created {filepath} ({len(content)} bytes)."
    except Exception as e:
        return f"Error creating file {filepath}: {e}"


@register("programmer_tree", "Lists directory structure as a tree view (max 3 levels deep).")
def programmer_tree(directory: str = ".", max_depth: int = 3) -> str:
    if not os.path.isdir(directory):
        return f"Not a directory: {directory}"

    lines = [f"{os.path.abspath(directory)}/"]
    _IGNORE = {".git", "__pycache__", "node_modules", ".venv", ".pytest_cache", ".mypy_cache", "venv"}

    def _walk(path: str, prefix: str, depth: int):
        if depth > max_depth:
            return
        try:
            entries = sorted(os.listdir(path))
        except PermissionError:
            lines.append(f"{prefix}[permission denied]")
            return

        dirs = [e for e in entries if os.path.isdir(os.path.join(path, e)) and e not in _IGNORE and not e.startswith(".")]
        files = [e for e in entries if os.path.isfile(os.path.join(path, e)) and not e.startswith(".")]

        all_items = [(d, True) for d in dirs] + [(f, False) for f in files]
        for i, (name, is_dir) in enumerate(all_items):
            connector = "└── " if i == len(all_items) - 1 else "├── "
            if is_dir:
                lines.append(f"{prefix}{connector}{name}/")
                extension = "    " if i == len(all_items) - 1 else "│   "
                _walk(os.path.join(path, name), prefix + extension, depth + 1)
            else:
                size = os.path.getsize(os.path.join(path, name))
                lines.append(f"{prefix}{connector}{name} ({size:,}B)")

    _walk(directory, "", 1)
    if len(lines) > 200:
        lines = lines[:200] + [f"... ({len(lines) - 200} more entries)"]
    return "\n".join(lines)


@register("programmer_search", "Searches files for a pattern using regex or literal string matching.")
def programmer_search(pattern: str, directory: str = ".", file_glob: str = "*", max_results: int = 30) -> str:
    import fnmatch

    results = []
    try:
        regex = re.compile(pattern, re.IGNORECASE)
    except re.error:
        regex = re.compile(re.escape(pattern), re.IGNORECASE)

    _IGNORE_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv"}

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in _IGNORE_DIRS]
        for fname in files:
            if not fnmatch.fnmatch(fname, file_glob):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", encoding="utf-8", errors="replace") as f:
                    for line_num, line in enumerate(f, 1):
                        if regex.search(line):
                            results.append(f"  {fpath}:{line_num}: {line.rstrip()[:120]}")
                            if len(results) >= max_results:
                                results.append(f"  ... (results capped at {max_results})")
                                return f"Search results for '{pattern}':\n" + "\n".join(results)
            except (OSError, UnicodeDecodeError):
                continue

    if not results:
        return f"No matches found for '{pattern}' in {directory}"
    return f"Search results for '{pattern}':\n" + "\n".join(results)


@register("programmer_diff", "Generates a unified diff between two files or between old/new content.")
def programmer_diff(filepath: str, new_content: str = "") -> str:
    if not os.path.exists(filepath):
        return f"File not found: {filepath}"
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            old_lines = f.readlines()

        if not new_content:
            return f"File has {len(old_lines)} lines. Provide new_content to generate a diff."

        new_lines = new_content.splitlines(keepends=True)
        diff = difflib.unified_diff(old_lines, new_lines, fromfile=f"a/{filepath}", tofile=f"b/{filepath}")
        result = "".join(diff)
        if not result:
            return "No differences found."
        return result
    except Exception as e:
        return f"Error generating diff: {e}"
