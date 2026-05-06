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
    "/sessions",
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

            # Extract the command word to avoid prefix collisions
            # (e.g. "/mode" vs "/model", "/session" vs "/sessions")
            cmd = text.split()[0].lower() if text.split() else ""

            if cmd == "/model":
                parts = text.split()
                if len(parts) == 1 and not text.endswith(" "):
                    for c in _KNOWN_MODELS:
                        yield Completion(" " + c, start_position=0)
                    return
                word = parts[-1] if len(parts) > 1 and not text.endswith(" ") else ""
                if word.startswith("/"):
                    word = ""
                yield from _completions_for(_KNOWN_MODELS, word)
                return

            if cmd == "/mode":
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

            if cmd == "/personality":
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

            if cmd == "/history":
                parts = text.split()
                if len(parts) == 1 and not text.endswith(" "):
                    for c in ("search",):
                        yield Completion(" " + c, start_position=0)
                    return
                word = parts[-1] if len(parts) > 1 and not text.endswith(" ") else ""
                if word.startswith("/"):
                    word = ""
                yield from _completions_for(["search"], word)
                return

            if cmd == "/session":
                parts = text.split()
                if len(parts) == 1 and not text.endswith(" "):
                    for c in ("audit",):
                        yield Completion(" " + c, start_position=0)
                    return
                word = parts[-1] if len(parts) > 1 and not text.endswith(" ") else ""
                if word.startswith("/"):
                    word = ""
                yield from _completions_for(["audit"], word)
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
    # Calm dark palette — Tokyo-Night-ish. Bottom toolbar uses `noreverse`
    # so per-segment colors render as fg-on-dark-bg rather than the
    # inverted look that prompt_toolkit's default `bottom-toolbar` style
    # (which is `reverse`) produces.
    _DSEC_STYLE = Style.from_dict({
        # prompt
        "dsec":     "#7aa2f7 bold",
        "session":  "#a9b1d6",
        "session-dim": "#565f89",
        "arrow":    "#7aa2f7 bold",
        "bar":      "#7aa2f7",

        "auto-suggestion": "#3b4261 italic",

        "completion-menu":                       "bg:#1a1b26",
        "completion-menu.completion":            "bg:#1a1b26 #c0caf5",
        "completion-menu.completion.current":    "bg:#3d59a1 #ffffff bold",
        "completion-menu.meta.completion":       "bg:#1a1b26 #565f89",
        "completion-menu.meta.current":          "bg:#3d59a1 #a9b1d6",

        "continuation": "#414868",

        # Bottom toolbar — `noreverse` cancels prompt_toolkit's default
        # reverse-video, so segment fg colors stay on the dark bg.
        "bottom-toolbar":      "noreverse bg:#1a1b26 #a9b1d6",
        "bottom-toolbar.text": "noreverse bg:#1a1b26 #a9b1d6",

        # Segment fg colors only — bg inherited from bottom-toolbar.
        "tb.bar":       "noreverse #7aa2f7 bold",
        "tb.sep":       "noreverse #414868",
        "tb.domain":    "noreverse #f7768e bold",
        "tb.model":     "noreverse #9ece6a",
        "tb.brain":     "noreverse #7dcfff",
        "tb.brain-low": "noreverse #f7768e bold",
        "tb.auto-on":   "noreverse #9ece6a bold",
        "tb.auto-off":  "noreverse #565f89",
        "tb.cwd":       "noreverse #c0caf5",
        "tb.session":   "noreverse #bb9af7 bold",
        "tb.dim":       "noreverse #565f89",
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

    # ── Enter: always submit ──────────────────────────────────────────────────
    # multiline=True was removed because it causes ghost prompt lines on terminal
    # resize (SIGWINCH).  With multiline=False the prompt is always a single line,
    # so prompt_toolkit's resize handler only needs to erase/redraw one line —
    # cursor tracking stays correct even when the window is dragged continuously.
    # Multi-line paste still works: bracketed paste mode inserts the pasted text
    # as-is and this Enter binding just submits it.
    @kb.add("enter")
    def _smart_enter(event: Any) -> None:  # noqa: ANN001
        event.current_buffer.validate_and_handle()

    # ── Ctrl+E: open $EDITOR for multiline editing ───────────────────────────
    @kb.add("c-e")
    def _open_editor(event: Any) -> None:  # noqa: ANN001
        import os
        import subprocess
        import tempfile
        buf = event.current_buffer
        current_text = buf.text
        editor = os.environ.get("EDITOR", os.environ.get("VISUAL", "vi"))
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".txt", prefix="dsec_msg_",
            encoding="utf-8", delete=False
        ) as f:
            f.write(current_text)
            tmpfile = f.name
        try:
            # Temporarily suspend prompt_toolkit's input processing
            with event.app.input.detach():
                subprocess.call([editor, tmpfile])
            with open(tmpfile, encoding="utf-8", errors="replace") as f:
                new_text = f.read()
            # Replace buffer contents with edited text (strip trailing newline)
            buf.set_document(
                buf.document.__class__(
                    text=new_text.rstrip("\n"),
                    cursor_position=len(new_text.rstrip("\n")),
                )
            )
        except Exception:
            pass
        finally:
            try:
                os.unlink(tmpfile)
            except OSError:
                pass

    # ── Ctrl+Enter / Ctrl+J / Alt+Enter: explicit submit ─────────────────────
    @kb.add("c-j")
    @kb.add("escape", "enter")
    def _force_submit(event: Any) -> None:  # noqa: ANN001
        event.current_buffer.validate_and_handle()

    # bottom_toolbar = single-line, static-height statusline. Segment style:
    #   ▍ DOMAIN · model · 🧠 8/8 · auto:ON · ~/cwd · ◉ session ▍
    # Each segment self-styled; separators dim so the eye lands on accents.
    # Single-line with multiline=False resizes cleanly.
    def _bottom_toolbar() -> "HTML":  # type: ignore[name-defined]
        try:
            import os as _os
            from dsec.providers import pool as _ppool
            from dsec.domain import get_domain as _get_domain

            domain = (state.get("resolved_domain")
                      or state.get("domain_override")
                      or "auto")
            dom_cfg = _get_domain(domain) if domain != "auto" else {}
            dom_label = dom_cfg.get("display", domain.upper())

            model_short = state.get("model_override") or "default"

            brain_pool = _ppool.get_pool("brain_pool") or {}
            brain_eps = list(brain_pool.get("endpoints") or [])
            brain_alive = sum(1 for e in brain_eps if not _ppool._is_dead("brain_pool", e))
            brain_total = len(brain_eps)
            brain_model = brain_pool.get("model", "") or model_short
            brain_cls = "tb.brain" if brain_alive == brain_total else "tb.brain-low"

            home = _os.path.expanduser("~")
            cwd = _os.getcwd()
            if cwd.startswith(home):
                cwd = "~" + cwd[len(home):]
            # Truncate long cwd so the toolbar doesn't push other segments off
            if len(cwd) > 32:
                cwd = "…" + cwd[-31:]

            sess = state.get("session_name", "?")
            if len(sess) > 24:
                sess = sess[:21] + "…"

            ae = state.get("auto_exec")
            ae_text = " auto:ON " if ae else " auto:OFF"
            ae_cls = "tb.auto-on" if ae else "tb.auto-off"

            sep = '<tb.sep>  •  </tb.sep>'
            edge_l = '<tb.bar>▎</tb.bar>'
            edge_r = '<tb.bar>▕</tb.bar>'
            short_brain_model = brain_model.split(":")[0] if brain_model else ""

            return HTML(
                f'{edge_l} '
                f'<tb.domain>{dom_label}</tb.domain>'
                f'{sep}<tb.model>{short_brain_model or model_short}</tb.model>'
                f'{sep}<{brain_cls}>🧠 {brain_alive}/{brain_total}</{brain_cls}>'
                f'{sep}<{ae_cls}>{ae_text.strip()}</{ae_cls}>'
                f'{sep}<tb.session>◉ {sess}</tb.session>'
                f'{sep}<tb.cwd>{cwd}</tb.cwd>'
                f' {edge_r}'
            )
        except Exception:
            return HTML(' <tb.bar>▎</tb.bar> dsec <tb.bar>▕</tb.bar> ')

    return PromptSession(
        completer=DsecCompleter(),
        auto_suggest=DsecAutoSuggest(),
        history=FileHistory(str(HISTORY_FILE)),
        key_bindings=kb,
        style=_DSEC_STYLE,
        multiline=False,
        complete_while_typing=False,
        enable_history_search=False,
        mouse_support=False,
        output=None,
        bottom_toolbar=_bottom_toolbar,
    )


def prompt_available() -> bool:
    return _PROMPT_TOOLKIT_AVAILABLE


def format_prompt(session_name: str, domain: str = "htb") -> "HTML | str":  # type: ignore[return]
    if _PROMPT_TOOLKIT_AVAILABLE:
        # Minimal two-glyph prompt: │ <session> ❯  — left-bar accent +
        # session name (soft fg) + colored arrow. No domain noise here;
        # the domain badge lives in the bottom toolbar so the input line
        # stays calm and readable.
        return HTML(
            "<bar>▎</bar>"
            f" <session>{session_name}</session>"
            " <arrow>❯</arrow> "
        )
    return f"▎ {session_name} ❯ "
