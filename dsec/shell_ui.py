"""
DSEC Shell UI
prompt_toolkit-backed interactive prompt with:
  • Inline ghost-text suggestions (slash commands + history)
  • Multi-line paste support (smart Enter, Ctrl+Enter to force-submit)
  • Context-aware Tab completion
  • Persistent history  (~/.dsec/shell_history)
  • Bottom toolbar showing session / domain / model
  • Ctrl-C = cancel line (or exit when empty)  |  Ctrl-D = exit
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional

# ─────────────────────────────────────────────────────────────────────────────
# prompt_toolkit imports (soft-optional)
# ─────────────────────────────────────────────────────────────────────────────
try:
    from prompt_toolkit import PromptSession
    from prompt_toolkit.auto_suggest import AutoSuggest, AutoSuggestFromHistory, Suggestion
    from prompt_toolkit.buffer import Buffer
    from prompt_toolkit.completion import CompleteEvent, Completer, Completion
    from prompt_toolkit.document import Document
    from prompt_toolkit.formatted_text import HTML
    from prompt_toolkit.history import FileHistory
    from prompt_toolkit.key_binding import KeyBindings
    from prompt_toolkit.styles import Style

    _PROMPT_TOOLKIT_AVAILABLE = True
except ImportError:
    _PROMPT_TOOLKIT_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

HISTORY_FILE = Path.home() / ".dsec" / "shell_history"
CONFIG_FILE  = Path.home() / ".dsec" / "config.json"

_SLASH_COMMANDS: List[str] = [
    "/help",
    "/history",
    "/autoexec",
    "/clear",
    "/session",
    "/status",
    "/note",
    "/domain",
    "/model",
    "/mcp",
    "/tools",
    "/skill",
    "/new",
    "/mode",
    "/personality",
    "/scope",
    "/sudo",
    "/exit",
    "/quit",
]

_SUDO_SUBS: List[str] = ["clear", "save", "status"]

_DOMAIN_CHOICES: List[str] = ["htb", "bugbounty", "ctf", "research", "programmer"]

_KNOWN_MODELS: List[str] = [
    "deepseek-expert-r1-search",
    "deepseek-expert-r1",
    "deepseek-expert",
    "deepseek-expert-search",
]

_MCP_SUBS: List[str] = [
    "list",
    "connect",
    "disconnect",
    "tools",
    "call",
    "reload",
]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _load_mcp_server_names() -> List[str]:
    try:
        raw = json.loads(CONFIG_FILE.read_text())
        return list(raw.get("mcp_servers", {}).keys())
    except Exception:  # noqa: BLE001
        return []


def _completions_for(
    candidates: Iterable[str],
    word: str,
) -> Iterator["Completion"]:
    for c in candidates:
        if c.lower().startswith(word.lower()):
            yield Completion(c, start_position=-len(word))


# ─────────────────────────────────────────────────────────────────────────────
# Tab Completer
# ─────────────────────────────────────────────────────────────────────────────

if _PROMPT_TOOLKIT_AVAILABLE:

    class DsecCompleter(Completer):
        """Context-aware Tab completer for slash commands and their arguments."""

        def get_completions(
            self,
            document: "Document",
            complete_event: "CompleteEvent",
        ) -> Iterable["Completion"]:
            text = document.text_before_cursor

            if text.lstrip().startswith("/mcp"):
                yield from self._complete_mcp(text)
                return

            if text.lstrip().startswith("/autoexec"):
                parts = text.split()
                if len(parts) == 1 and not text.endswith(" "):
                    for c in ("on", "off"):
                        yield Completion(" " + c, start_position=0)
                    return
                word = parts[-1] if len(parts) > 1 and not text.endswith(" ") else ""
                yield from _completions_for(["on", "off"], word)
                return

            if text.lstrip().startswith("/sudo"):
                parts = text.split()
                if len(parts) == 1 and not text.endswith(" "):
                    for c in _SUDO_SUBS:
                        yield Completion(" " + c, start_position=0)
                    return
                word = parts[-1] if len(parts) > 1 and not text.endswith(" ") else ""
                if word.startswith("/"):
                    word = ""
                yield from _completions_for(_SUDO_SUBS, word)
                return

            if text.lstrip().startswith("/domain"):
                parts = text.split()
                if len(parts) == 1 and not text.endswith(" "):
                    # No space yet — prefix completions with a space
                    for c in _DOMAIN_CHOICES:
                        yield Completion(" " + c, start_position=0)
                    return
                word = parts[-1] if len(parts) > 1 and not text.endswith(" ") else ""
                if word.startswith("/"):
                    word = ""
                yield from _completions_for(_DOMAIN_CHOICES, word)
                return

            if text.lstrip().startswith("/skill"):
                parts = text.split()
                from dsec.skills.loader import list_skills
                skills = [s["name"] for s in list_skills()]
                if len(parts) == 1 and not text.endswith(" "):
                    for c in skills:
                        yield Completion(" " + c, start_position=0)
                    return
                word = parts[-1] if len(parts) > 1 and not text.endswith(" ") else ""
                if word.startswith("/"):
                    word = ""
                yield from _completions_for(skills, word)
                return

            if text.lstrip().startswith("/mode"):
                parts = text.split()
                modes = ["architect", "recon", "exploit", "ask", "auto"]
                if len(parts) == 1 and not text.endswith(" "):
                    for c in modes:
                        yield Completion(" " + c, start_position=0)
                    return
                word = parts[-1] if len(parts) > 1 and not text.endswith(" ") else ""
                if word.startswith("/"):
                    word = ""
                yield from _completions_for(modes, word)
                return

            if text.lstrip().startswith("/personality"):
                parts = text.split()
                pers = ["professional", "hacker", "teacher"]
                if len(parts) == 1 and not text.endswith(" "):
                    for c in pers:
                        yield Completion(" " + c, start_position=0)
                    return
                word = parts[-1] if len(parts) > 1 and not text.endswith(" ") else ""
                if word.startswith("/"):
                    word = ""
                yield from _completions_for(pers, word)
                return

            if text.lstrip().startswith("/model"):
                parts = text.split()
                if len(parts) == 1 and not text.endswith(" "):
                    # No space yet — prefix completions with a space
                    for c in _KNOWN_MODELS:
                        yield Completion(" " + c, start_position=0)
                    return
                word = parts[-1] if len(parts) > 1 and not text.endswith(" ") else ""
                if word.startswith("/"):
                    word = ""
                yield from _completions_for(_KNOWN_MODELS, word)
                return

            stripped = text.lstrip()
            if stripped.startswith("/") and " " not in stripped:
                yield from _completions_for(_SLASH_COMMANDS, stripped)
                return

        def _complete_mcp(self, text: str) -> Iterable["Completion"]:
            parts = text.split()
            n = len(parts)
            trailing = text.endswith(" ")

            if n == 1:
                if not trailing:
                    # "/mcp" with no space yet — prefix completions with a space
                    for c in _MCP_SUBS:
                        yield Completion(" " + c, start_position=0)
                else:
                    yield from _completions_for(_MCP_SUBS, "")
                return

            sub = parts[1].lower() if n >= 2 else ""

            if n == 2 and not trailing:
                yield from _completions_for(_MCP_SUBS, sub)
                return

            if sub in {"connect", "disconnect", "tools", "call"}:
                servers = _load_mcp_server_names()
                word = parts[2] if (n >= 3 and not trailing) else ""
                yield from _completions_for(servers, word)
                return


# ─────────────────────────────────────────────────────────────────────────────
# Inline ghost-text suggestion
# Slash commands → shows completion in gray inline (like fish shell)
# Otherwise → falls back to history suggestion
# ─────────────────────────────────────────────────────────────────────────────

if _PROMPT_TOOLKIT_AVAILABLE:

    class DsecAutoSuggest(AutoSuggest):
        """
        Ghost-text (gray inline) suggestions:
          /he  →  shows `lp` in gray → Right arrow or End to accept
          Otherwise falls back to history suggestions.
        """

        def __init__(self) -> None:
            self._history = AutoSuggestFromHistory()

        def get_suggestion(
            self,
            buffer: "Buffer",
            document: "Document",
        ) -> Optional["Suggestion"]:
            text = document.text_before_cursor

            # ── slash command ghost text ───────────────────────────────────────
            # Only activate when text begins with "/" and has no space yet
            # (i.e. the user is still typing the command name).
            if text.startswith("/") and " " not in text and text != "/":
                for cmd in _SLASH_COMMANDS:
                    if cmd.startswith(text) and cmd != text:
                        return Suggestion(cmd[len(text):])
                # Partial slash command typed but no known command matches —
                # suppress history suggestions to avoid confusing completions.
                return None

            # ── fallback: history ─────────────────────────────────────────────
            return self._history.get_suggestion(buffer, document)


# ─────────────────────────────────────────────────────────────────────────────
# Style
# ─────────────────────────────────────────────────────────────────────────────

_DSEC_STYLE = None
if _PROMPT_TOOLKIT_AVAILABLE:
    _DSEC_STYLE = Style.from_dict({
        # prompt
        "dsec":    "#00afff bold",
        "session": "#888888",
        "arrow":   "#555555",
        # ghost-text suggestion (gray, like fish shell)
        "auto-suggestion": "#555555 italic",
        # completion dropdown
        "completion-menu.completion":         "bg:#1c1c1c #aaaaaa",
        "completion-menu.completion.current": "bg:#005f87 #ffffff bold",
        "completion-menu.meta.completion":    "bg:#1c1c1c #666666",
        "completion-menu.meta.current":       "bg:#005f87 #aaaaaa",
        # multi-line continuation indicator
        "continuation": "#555555",
        # toolbar
        "bottom-toolbar":      "bg:#1c1c1c #555555",
        "bottom-toolbar.text": "bg:#1c1c1c #888888",
        "tb.session": "#00afff",
        "tb.domain":  "#ffaf00",
        "tb.model":   "#5faf5f",
        "tb.sep":     "#333333",
    })


# ─────────────────────────────────────────────────────────────────────────────
# Public API
# ─────────────────────────────────────────────────────────────────────────────

def build_prompt_session(state: Dict[str, Any]) -> Optional["PromptSession"]:  # type: ignore[return]
    if not _PROMPT_TOOLKIT_AVAILABLE:
        return None

    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)

    kb = KeyBindings()

    # ── Ctrl-C: clear line if has text, else raise KeyboardInterrupt ──────────
    @kb.add("c-c")
    def _ctrl_c(event: Any) -> None:  # noqa: ANN001
        buf = event.current_buffer
        if buf.text:
            buf.reset()
        else:
            raise KeyboardInterrupt

    # ── Smart Enter ───────────────────────────────────────────────────────────
    # • Buffer has NO newlines → submit immediately (normal single-line usage)
    # • Buffer has newlines (multi-line paste) → pressing Enter on the very
    #   last non-empty line adds a blank line; pressing Enter on a blank last
    #   line submits (two-Enter pattern).
    @kb.add("enter")
    def _smart_enter(event: Any) -> None:  # noqa: ANN001
        buf = event.current_buffer
        if "\n" not in buf.text:
            # Single-line: submit
            buf.validate_and_handle()
        else:
            lines = buf.text.split("\n")
            if lines[-1].strip() == "":
                # Already an empty trailing line → submit
                buf.validate_and_handle()
            else:
                # Add a blank line; next Enter will submit
                buf.insert_text("\n")

    # ── Ctrl+Enter / Alt+Enter: force-submit from anywhere ───────────────────
    @kb.add("c-j")          # Ctrl+Enter in many terminals
    @kb.add("escape", "enter")  # Alt+Enter / Meta+Enter
    def _force_submit(event: Any) -> None:  # noqa: ANN001
        event.current_buffer.validate_and_handle()

    # ── Toolbar ───────────────────────────────────────────────────────────────
    def _toolbar() -> "HTML":
        session = state.get("session_name", "none")
        domain  = state.get("domain_override") or "auto"
        
        # Context usage
        try:
            from dsec.context_manager import ContextManager
            from dsec.session import load_session
            model_override = state.get("model_override") or state.get("model")
            cm = ContextManager(domain=domain, model=model_override)
            session_data = load_session(session)
            if session_data and "history" in session_data:
                for t in session_data["history"]:
                    cm.add_turn(t["role"], t.get("content", ""), t.get("thinking", ""))
            usage = cm.usage_summary().split("·")[0].strip()
        except Exception:
            usage = "🟢 Context: --"
            
        ae      = "⚡auto" if state.get("auto_exec") else ""
        ae_part = f"  <tb.sep>│</tb.sep>  <tb.domain>{ae}</tb.domain>" if ae else ""
        sudo_part = "  <tb.sep>│</tb.sep>  <tb.domain>🔑</tb.domain>" if state.get("sudo_password") else ""
        return HTML(
            f"<bottom-toolbar>"
            f"  <tb.sep>ℹ</tb.sep>  {usage}  "
            f"  <tb.sep>│</tb.sep>  <tb.session> {session} </tb.session>"
            f"  <tb.sep>│</tb.sep>  <tb.domain> {domain} </tb.domain>"
            f"{ae_part}"
            f"{sudo_part}"
            f"  <tb.sep>│</tb.sep>  ↑↓ history  Tab complete  Ctrl-R search  Ctrl-C cancel  Ctrl-D exit"
            f"</bottom-toolbar>"
        )

    # ── Continuation prompt for multi-line ───────────────────────────────────
    def _continuation(width: int, line_number: int, is_soft_wrap: bool) -> Any:
        return HTML(f"<continuation>{'·' * (width - 1)} </continuation>")

    return PromptSession(
        completer=DsecCompleter(),  # Tab = completer
        auto_suggest=DsecAutoSuggest(),                              # ghost text
        history=FileHistory(str(HISTORY_FILE)),
        key_bindings=kb,
        style=_DSEC_STYLE,
        bottom_toolbar=_toolbar,
        # multiline=True lets pasted content with \n stay in the buffer
        # instead of being split across multiple submissions
        multiline=True,
        prompt_continuation=_continuation,
        complete_while_typing=False,  # only on explicit Tab
        enable_history_search=False,  # plain ↑↓ cycles history in order
        mouse_support=False,
        output=None,
    )


def prompt_available() -> bool:
    return _PROMPT_TOOLKIT_AVAILABLE


def format_prompt(session_name: str, domain: str = "htb") -> "HTML | str":  # type: ignore[return]
    if _PROMPT_TOOLKIT_AVAILABLE:
        from dsec.domain import get_domain
        color = get_domain(domain).get("color", "white")
        # prompt_toolkit HTML expects recognized names or specific formatting.
        # It handles 'green', 'yellow', etc. well in standard tags if defined,
        # but inline styles via <style color="{}"> or <span fg="{}"> is best done via standard tags
        # We can just use the color name as the tag if it's one of the basics, or use style="color: {color}"
        return HTML(
            f"<session>{session_name}</session>"
            f" <{color}>❯</{color}> "
        )
    return f"{session_name} ❯ "
