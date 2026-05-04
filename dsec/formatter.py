"""
DSEC Terminal Formatter
Rich-based terminal output for streaming responses, tables, and notices.

Split-pane TUI: during streaming, the terminal shows two distinct panels —
a collapsible Thinking pane (top) and a Response pane (bottom), inspired by
OpenCode and Claude Code's split-view experience.
"""
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple
import time

import sys
from rich import box
from rich.columns import Columns
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import re as _re
from rich.markup import escape as _rich_escape

from .domain import get_domain

# Optimized for macOS Terminal and general stability
console = Console()

# Strip <tool_call>...</tool_call> blocks and bare native-tool one-liners
# from the displayed response so only human-readable prose is shown.
# Matches both attribute-form (<tool_call name="bash" arguments="...">...</tool_call>)
# and plain form (<tool_call>...</tool_call>) and self-closing form (<tool_call .../>).
_TOOL_CALL_STRIP_RE = _re.compile(
    r'<tool_call(?:\s[^>]*)?/>|<tool_call(?:\s[^>]*)?>.*?</tool_call>',
    _re.DOTALL | _re.IGNORECASE,
)
# Orphaned closing tags left after block stripping
_TOOL_CALL_CLOSE_RE = _re.compile(r'</tool_call>', _re.IGNORECASE)
# Strip Claude/Anthropic XML format: <tool_calls>...</tool_calls> and <invoke ...>...</invoke>
_XML_INVOKE_STRIP_RE = _re.compile(
    r'<tool_calls\b[^>]*>.*?</tool_calls>|<invoke\b[^>]*>.*?</invoke>',
    _re.DOTALL | _re.IGNORECASE,
)
# Strip malformed tool-call lines such as `tool_call name="bash"> ...`.
_BROKEN_TOOL_CALL_LINE_RE = _re.compile(r'^\s*<?tool_call\b[^>]*name\s*=.*$', _re.IGNORECASE | _re.MULTILINE)
_BARE_TOOL_LINE_RE = _re.compile(
    r'^\s*(?:bash\s+)?([a-z][a-z0-9_]*)\s*(\{[^}]*\})?\s*$'
)
# Known native tool prefixes (avoid stripping normal prose lines)
_NATIVE_TOOL_PREFIXES = frozenset([
    "pty_", "bash", "core_memory", "graph_memory", "browser_", "web_",
    "http_", "file_", "programmer_", "gtfobins", "osint_", "save_skill",
])


def _clean_display_content(text: str, *, streaming: bool = False) -> str:
    """Remove tool call blocks and bare tool-name lines from display text."""
    # Strip XML tool call blocks (attribute-form and plain form)
    text = _TOOL_CALL_STRIP_RE.sub("", text)
    # Strip any orphaned </tool_call> closing tags
    text = _TOOL_CALL_CLOSE_RE.sub("", text)
    # Strip Claude/Anthropic XML invoke format blocks
    text = _XML_INVOKE_STRIP_RE.sub("", text)
    # Strip malformed tool-call openers that are not valid display content.
    text = _BROKEN_TOOL_CALL_LINE_RE.sub("", text)
    if streaming:
        # During streaming skip the heavier line-by-line analysis; just collapse blank lines
        result = _re.sub(r'\n{3,}', '\n\n', text)
        return result.strip()
    # Strip bare tool-name lines (e.g. "bash pty_list_panes", "pty_create_pane")
    lines = []
    for line in text.splitlines():
        m = _BARE_TOOL_LINE_RE.match(line)
        if m:
            name = m.group(1)
            if any(name.startswith(p) for p in _NATIVE_TOOL_PREFIXES) or name in _NATIVE_TOOL_PREFIXES:
                continue
        lines.append(line)
    # Collapse triple+ blank lines to double
    result = _re.sub(r'\n{3,}', '\n\n', "\n".join(lines))
    return result.strip()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _relative_time(iso_str: str) -> str:
    if not iso_str:
        return "never"
    try:
        ds = iso_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ds)
        now = datetime.now(timezone.utc)
        diff = now - dt
        secs = diff.total_seconds()
        if secs < 60:
            return "just now"
        if secs < 3600:
            m = int(secs / 60)
            return f"{m} min{'s' if m != 1 else ''} ago"
        if secs < 86400:
            h = int(secs / 3600)
            return f"{h} hour{'s' if h != 1 else ''} ago"
        if diff.days < 7:
            return f"{diff.days} day{'s' if diff.days != 1 else ''} ago"
        if diff.days < 30:
            w = diff.days // 7
            return f"{w} week{'s' if w != 1 else ''} ago"
        mo = diff.days // 30
        return f"{mo} month{'s' if mo != 1 else ''} ago"
    except (ValueError, TypeError):
        return iso_str[:10] if iso_str else "?"


def _model_short(model: str) -> str:
    # Cache substring tests to avoid repeated string scans and improve readability.
    # Check most-specific variants first so "deepseek-expert-r1-search" is not
    # mis-labelled as plain "expert-r1".
    has_expert = "expert" in model
    has_r1 = "r1" in model
    has_search = "search" in model
    if has_expert and has_r1 and has_search:
        return "expert-r1-search"
    if has_expert and has_r1:
        return "expert-r1"
    if has_expert and has_search:
        return "expert-search"
    if has_expert:
        return "expert"
    if has_search:
        return "search"
    if "chat" in model:
        return "chat"
    return model[:18]


# ---------------------------------------------------------------------------
# Split-Pane Layout Builder (OpenCode / Claude Code inspired)
# ---------------------------------------------------------------------------

_THINKING_MAX_LINES = 20  # Show last N lines of thinking in the pane


def _build_thinking_panel(
    thinking: str,
    domain: str,
    elapsed: float,
    is_streaming: bool,
) -> Panel:
    """Build the top pane: collapsible thinking block with live word count."""
    pal = _get_palette(domain)
    p = pal["primary"]

    word_count = len(thinking.split()) if thinking else 0
    lines = thinking.splitlines() if thinking else []

    # Show only last N lines to keep pane compact
    if len(lines) > _THINKING_MAX_LINES:
        display_lines = lines[-_THINKING_MAX_LINES:]
        display = f"… ({len(lines) - _THINKING_MAX_LINES} lines above)\n" + "\n".join(display_lines)
    else:
        display = "\n".join(lines) if lines else ""

    if not display and is_streaming:
        display = "⏳ Waiting for reasoning…"

    body = Text(display, style="italic #888888")
    status = "streaming" if is_streaming else "done"
    elapsed_str = f"{elapsed:.1f}s"

    return Panel(
        body,
        title=f"[{p}]💭 Thinking[/{p}]  [#666666]{word_count} words · {elapsed_str}[/]",
        title_align="left",
        subtitle=f"[#555555]{status}[/]",
        subtitle_align="right",
        border_style="#555555",
        box=box.ROUNDED,
        padding=(0, 1),
        height=min(max(4, len(display.splitlines()) + 2), _THINKING_MAX_LINES + 4),
    )


def _build_response_panel(
    content: str,
    domain: str,
    session_name: str,
    model: str,
    turn: int,
    compression_info: Optional[Dict],
    research_sources: Optional[List[str]],
    memory_count: int,
    is_streaming: bool,
) -> Panel:
    """Build the bottom pane: rendered AI response with metadata subtitle."""
    domain_cfg = get_domain(domain)
    color = domain_cfg.get("color", "white")
    domain_display = domain_cfg.get("display", domain.upper())
    model_s = _model_short(model)

    # ---- Title ----
    title_parts = [f"[bold {color}]{domain_display}[/bold {color}]"]
    if session_name and session_name != "none":
        title_parts.append(f"[#888888]{session_name}[/]")
    title_parts.append(f"[#666666]{model_s}[/]")
    title = "  ".join(title_parts)

    # ---- Body ----
    if content:
        if is_streaming:
            # During streaming, show raw text (faster rendering)
            body: Any = Text(content)
        else:
            # After completion, render as Markdown
            try:
                body = Markdown(content)
            except Exception:
                body = Text(content)
    elif is_streaming:
        body = Text("⏳ Generating response…", style="#888888")
    else:
        body = Text("")

    # ---- Footer (subtitle) ----
    footer_parts: List[str] = []
    if turn > 0:
        footer_parts.append(f"[#888888]turn {turn}[/]")
    if compression_info:
        ratio = compression_info.get("compression_ratio", "")
        footer_parts.append(f"[{color}]⚡{ratio}[/{color}]")
    if research_sources:
        src_str = "+".join(s[:3].upper() for s in research_sources[:5])
        footer_parts.append(f"[cyan]🔬{src_str}[/cyan]")
    if memory_count > 0:
        footer_parts.append(f"[blue]🧠{memory_count}[/blue]")

    subtitle = "  ".join(footer_parts) if footer_parts else None

    return Panel(
        body,
        title=title,
        title_align="left",
        subtitle=subtitle,
        subtitle_align="left",
        border_style=color,
        box=box.ROUNDED,
        padding=(0, 2),
    )


def _build_inline_layout(
    thinking: str,
    content: str,
    domain: str,
    session_name: str,
    model: str,
    turn: int,
    compression_info: Optional[Dict],
    research_sources: Optional[List[str]],
    memory_count: int,
    is_streaming: bool,
    show_thinking: bool,
    elapsed: float,
    phase_color: Optional[str] = None,
) -> Any:
    """Build the inline layout (natural scroll, Claude Code style)."""
    domain_cfg = get_domain(domain)
    color = phase_color if phase_color else domain_cfg.get("color", "white")

    # ---- Thinking Block (Collapsible style) ----
    thinking_renderable = None
    if show_thinking and thinking:
        lines = thinking.splitlines()
        word_count = len(thinking.split())
        elapsed_str = f"{elapsed:.1f}s"

        if is_streaming and not content:
            # Thinking still in progress – show compact live view of last line
            last_line = lines[-1] if lines else ""
            if len(last_line) > 80:
                last_line = last_line[:80] + "…"
            thinking_renderable = Text(f"💭 Thinking... {last_line}", style="italic #888888")
        elif not is_streaming:
            # Stream finished – show collapsed summary
            thinking_renderable = Text(f"▶ Thinking ({word_count} words, {elapsed_str})", style="italic #666666")
        # else: content is streaming (thinking already done) – hide indicator,
        # focus display on the arriving response text

    # ---- Response Block ----
    if content:
        # Always strip tool-call XML from what the user sees; during streaming use
        # the lightweight path (skip bare-tool-name heuristics for speed).
        display_content = _clean_display_content(content, streaming=is_streaming)
        if is_streaming:
            body: Any = Text(display_content)
        else:
            try:
                body = Markdown(display_content) if display_content else Text("")
            except Exception:
                body = Text(display_content)
    elif is_streaming and not thinking:
        body = Text("⏳ Generating response…", style="#888888")
    else:
        body = Text("")

    # ---- Phase indicator (shown when agent is in a non-idle phase) ----
    phase_renderables = []
    if phase_color and not is_streaming:
        # Map color to a short human-readable label
        _PHASE_LABELS = {
            "#00d4ff": "RECON",
            "#ff4444": "EXPLOIT",
            "#a3e635": "REPORT",
        }
        label = _PHASE_LABELS.get(phase_color, "ACTIVE")
        phase_renderables.append(
            Text(f"  ◆ {label}", style=f"bold {phase_color}")
        )

    # ---- Assembly ----
    renderables = phase_renderables
    if thinking_renderable:
        renderables.append(thinking_renderable)
    if body and str(body):
        renderables.append(body)

    return Group(*renderables)


# ---------------------------------------------------------------------------
# Main Stream Renderer (Split-Pane TUI)
# ---------------------------------------------------------------------------

def stream_response(
    generator: Generator,
    session_name: str = "none",
    domain: str = "htb",
    model: str = "deepseek-expert-r1",
    turn: int = 0,
    compression_info: Optional[Dict] = None,
    research_sources: Optional[List[str]] = None,
    memory_count: int = 0,
    show_thinking: bool = True,
    phase: str = "idle",
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Stream response from generator to the terminal using Rich Live with
    a split-pane layout: Thinking (top) + Response (bottom).

    Returns (thinking, content, conversation_id) or (None, None, None) on error.
    """
    thinking_parts: List[str] = []
    content_parts: List[str] = []
    conv_id: Optional[str] = None
    start_time = time.time()

    # Phase color override: each phase maps to a border color
    _PHASE_COLORS = {
        "recon":   "#00d4ff",   # cyan — reconnaissance / enumeration
        "exploit": "#ff4444",   # red — exploitation
        "report":  "#a3e635",   # lime — reporting / done
        "idle":    None,        # None → use domain color (no override)
    }
    phase_color = _PHASE_COLORS.get(phase)
    effective_domain = domain  # used below; phase color is separate

    cancelled = False

    def _render(streaming: bool) -> Any:
        elapsed = time.time() - start_time
        return _build_inline_layout(
            "".join(thinking_parts), "".join(content_parts),
            effective_domain, session_name, model, turn,
            compression_info, research_sources, memory_count,
            streaming, show_thinking, elapsed,
            phase_color=phase_color,
        )

    try:
        with Live(console=console, refresh_per_second=12, transient=True) as live:
            live.update(_render(True))  # show ⏳ immediately, before first API byte
            for chunk in generator:
                ctype = chunk.get("type")

                if ctype == "thinking":
                    thinking_parts.append(chunk["text"])
                    live.update(_render(True))

                elif ctype == "content":
                    content_parts.append(chunk["text"])
                    live.update(_render(True))

                elif ctype == "done":
                    conv_id = chunk.get("conversation_id")
                    live.update(_render(False))

                elif ctype == "info":
                    notice = chunk.get("text", "")
                    if notice:
                        console.print(f"[dim cyan]ℹ  {notice}[/dim cyan]")

                elif ctype == "error":
                    error_panel = Panel(
                        Text(f"❌  {chunk['text']}", style="bold red"),
                        title="[red]ERROR[/red]",
                        border_style="red",
                        box=box.HEAVY,
                    )
                    live.update(error_panel)
                    live.stop()
                    console.print(error_panel)
                    partial_thinking = "".join(thinking_parts)
                    partial_content = "".join(content_parts)
                    if partial_thinking or partial_content:
                        return partial_thinking or None, partial_content or None, conv_id
                    return None, None, None

    except KeyboardInterrupt:
        # Ctrl-C mid-stream: stop the generator, keep whatever arrived so far,
        # then re-raise so the caller's KeyboardInterrupt handler fires correctly.
        # Previously this swallowed the exception — callers got "✖ Response cancelled."
        # as content and kept looping, making Ctrl+C unable to stop the agentic loop.
        cancelled = True
        try:
            generator.close()  # type: ignore[union-attr]
        except Exception:
            pass

    # Print final output persistently
    partial_content = "".join(content_parts)
    partial_thinking = "".join(thinking_parts)
    if cancelled:
        cancel_suffix = "\n\n✖ Response cancelled."
        partial_content = partial_content + cancel_suffix if partial_content else cancel_suffix

    elapsed = time.time() - start_time
    console.print(
        _build_inline_layout(
            partial_thinking,
            partial_content,
            effective_domain, session_name, model, turn,
            compression_info, research_sources, memory_count,
            False, show_thinking, elapsed,
            phase_color=phase_color,
        )
    )

    # Token rate footer (dim one-liner: "12.3 tok/s · 456 tokens · 37.2s")
    if partial_content and not cancelled and elapsed > 0.1:
        approx_tokens = max(1, len(partial_content) // 4)
        tok_per_sec = approx_tokens / elapsed
        pal = _get_palette(effective_domain)
        p = pal["primary"]
        phase_tag = f" [{p}]{phase}[/{p}]" if phase and phase != "idle" else ""
        console.print(
            f"  [#444444]{tok_per_sec:.1f} tok/s · {approx_tokens} tokens · {elapsed:.1f}s[/]"
            + phase_tag,
            highlight=False,
        )

    if cancelled:
        # Re-raise so the outer except KeyboardInterrupt: block in the caller
        # can perform proper cleanup (save turn, stop loop, etc.).
        raise KeyboardInterrupt

    return "".join(thinking_parts), "".join(content_parts), conv_id


# ---------------------------------------------------------------------------
# Notice Printers
# ---------------------------------------------------------------------------

def print_compression_notice(info: Dict) -> None:
    tool = info.get("tool_detected", "generic")
    orig = info.get("original_length", 0)
    comp = info.get("compressed_length", 0)
    ratio = info.get("compression_ratio", "0%")
    console.print(
        f"[yellow]⚡ {tool} output detected: {orig:,} → {comp:,} chars ({ratio} reduction)[/yellow]",
        highlight=False
    )


def print_research_notice(queries: List[Dict]) -> None:
    q_strs = [f'"{_rich_escape(q["query"])}"' for q in queries[:4]]
    console.print(f"[cyan]🔬 Auto-researching: {', '.join(q_strs)}…[/cyan]", highlight=False)


def print_research_complete(total: int, sources: List[str]) -> None:
    if total > 0:
        src_str = ", ".join(_rich_escape(s) for s in sources[:5])
        console.print(f"[cyan]✅ Research: {total} finding(s) from [{src_str}][/cyan]", highlight=False)
    else:
        console.print("[#888888]🔬 Research: no relevant findings[/]", highlight=False)


def print_memory_notice(count: int, similarities: List[float]) -> None:
    sim_str = ", ".join(f"{s:.2f}" for s in similarities[:3])
    console.print(f"[blue]🧠 Memory: {count} relevant entr{'y' if count == 1 else 'ies'} (similarity: {sim_str})[/blue]", highlight=False)
    console.print("[yellow #888888]⚠️  Injected as unverified historical context[/yellow #888888]", highlight=False)


# ---------------------------------------------------------------------------
# Sessions Table
# ---------------------------------------------------------------------------

def print_sessions_table(sessions: List[Dict]) -> None:
    table = Table(
        title="DSEC SESSIONS",
        title_justify="left",
        box=box.SIMPLE,
        border_style="#888888",
        header_style="bold blue",
        show_lines=False,
    )
    table.add_column("Name", style="bold white", min_width=18)
    table.add_column("Domain", justify="center", min_width=12)
    table.add_column("Turns", justify="right", min_width=6)
    table.add_column("Model", min_width=12)
    table.add_column("Last Used", min_width=14)
    table.add_column("Tags", min_width=15)

    DOMAIN_COLORS = {
        "htb": "green", "bugbounty": "yellow", "ctf": "cyan", "research": "magenta"
    }

    for s in sessions:
        dom = s.get("domain", "htb")
        color = DOMAIN_COLORS.get(dom, "white")
        dom_cfg = get_domain(dom)
        dom_display = dom_cfg.get("display", dom.upper())
        tags = ", ".join(s.get("tags", [])[:3]) or "[#888888]—[/]"
        model_s = _model_short(s.get("model", ""))
        last = _relative_time(s.get("last_used", ""))
        table.add_row(
            s.get("name", ""),
            f"[{color}]{dom_display}[/{color}]",
            str(s.get("message_count", 0)),
            model_s,
            last,
            tags,
        )

    if not sessions:
        table.add_row("[#888888]No sessions yet[/]", "", "", "", "", "")

    console.print(table)


def print_session_detail(session: Dict) -> None:
    name = session.get("name", "?")
    dom = session.get("domain", "htb")
    dom_cfg = get_domain(dom)
    color = dom_cfg.get("color", "white")
    dom_display = dom_cfg.get("display", dom)

    tags_str = ", ".join(session.get("tags", [])) or "none"
    conv_id = session.get("conversation_id") or "none"
    model = session.get("model", "unknown")

    info = Text()
    info.append("Domain:     ", style="bold")
    info.append(f"{dom_display}\n", style=color)
    info.append("Model:      ", style="bold")
    info.append(f"{model}\n")
    info.append("Created:    ", style="bold")
    info.append(f"{session.get('created_at', '?')[:19]}\n")
    info.append("Last Used:  ", style="bold")
    info.append(f"{_relative_time(session.get('last_used', ''))}\n")
    info.append("Messages:   ", style="bold")
    info.append(f"{session.get('message_count', 0)}\n")
    info.append("Tags:       ", style="bold")
    info.append(f"{tags_str}\n")
    info.append("Conv ID:    ", style="bold")
    info.append(f"{conv_id}\n", style="#888888")

    console.print(Panel(info, title=f"[bold {color}]Session: {name}[/bold {color}]",
                        title_align="left", border_style=color, box=box.MINIMAL))

    notes = session.get("notes", [])
    if notes:
        console.print(f"\n[bold]Notes ({len(notes)}):[/bold]")
        TYPE_COLORS = {"finding": "yellow", "credential": "red", "flag": "green", "misc": "white"}
        for note in notes:
            nt = note.get("type", "misc")
            nc = TYPE_COLORS.get(nt, "white")
            ts = note.get("timestamp", "")[:19]
            content = note.get("content", "")
            console.print(f"  [{nc}][{nt.upper()}][/{nc}] [#888888]{ts}[/]  {content}")

    history = session.get("history", [])
    if history:
        console.print(f"\n[bold]History (last 10 of {len(history)}):[/bold]")
        for entry in history[-10:]:
            role = entry.get("role", "?")
            turn = entry.get("turn", "?")
            content = entry.get("content", "")[:100].replace("\n", " ")
            if len(entry.get("content", "")) > 100:
                content += "…"
            compressed_tag = " [#888888] [compressed][/]" if entry.get("compressed") else ""
            if role == "user":
                prefix = f"[green]You[/green] [#888888](t{turn})[/]"
            else:
                prefix = f"[blue]AI[/blue]  [#888888](t{turn})[/]"
            console.print(f"  {prefix}: {content}{compressed_tag}")


# ---------------------------------------------------------------------------
# Memory Tables
# ---------------------------------------------------------------------------

def print_memory_list(memories: List[Dict]) -> None:
    table = Table(
        title="DSEC MEMORIES",
        title_justify="left",
        box=box.SIMPLE,
        border_style="#888888",
        header_style="bold blue",
    )
    table.add_column("ID", style="#888888", max_width=10)
    table.add_column("Session", max_width=18)
    table.add_column("Type", max_width=12)
    table.add_column("Confidence", max_width=13)
    table.add_column("Content", max_width=55)
    table.add_column("Age", max_width=14)

    CONF_COLORS = {"verified": "green", "suspected": "yellow", "false_positive": "red"}
    TYPE_ICONS = {
        "finding": "🔍", "technique": "⚙️", "credential": "🔑",
        "tool_usage": "🛠️", "pattern": "🔄",
    }

    for mem in memories:
        conf = mem.get("confidence", "suspected")
        cc = CONF_COLORS.get(conf, "white")
        mt = mem.get("type", "misc")
        icon = TYPE_ICONS.get(mt, "📌")
        content = (mem.get("content", "") or "")[:75].replace("\n", " ")
        if len(mem.get("content", "")) > 75:
            content += "…"
        table.add_row(
            (mem.get("id") or "")[:10],
            mem.get("session", ""),
            f"{icon} {mt}",
            f"[{cc}]{conf}[/{cc}]",
            content,
            _relative_time(mem.get("timestamp", "")),
        )

    if not memories:
        table.add_row("[#888888]No memories found[/]", "", "", "", "", "")

    console.print(table)


def print_memory_detail(memory: Dict) -> None:
    CONF_COLORS = {"verified": "green", "suspected": "yellow", "false_positive": "red"}
    conf = memory.get("confidence", "suspected")
    cc = CONF_COLORS.get(conf, "white")
    tags_str = ", ".join(memory.get("tags", [])) or "none"

    info = Text()
    info.append("Session:    ", style="bold")
    info.append(f"{memory.get('session', '?')}\n")
    info.append("Domain:     ", style="bold")
    info.append(f"{memory.get('domain', '?')}\n")
    info.append("Type:       ", style="bold")
    info.append(f"{memory.get('type', '?')}\n")
    info.append("Confidence: ", style="bold")
    info.append(f"{conf}\n", style=cc)
    info.append("Source:     ", style="bold")
    info.append(f"{memory.get('source', '?')}\n")
    info.append("Tags:       ", style="bold")
    info.append(f"{tags_str}\n")
    info.append("Timestamp:  ", style="bold")
    info.append(f"{memory.get('timestamp', '?')[:19]}\n\n")
    info.append("Content:\n", style="bold")
    info.append(memory.get("content", ""))

    console.print(
        Panel(
            info,
            title=f"[blue]Memory: {(memory.get('id') or '?')[:20]}[/blue]",
            title_align="left",
            border_style="blue",
            box=box.MINIMAL,
        )
    )


# ---------------------------------------------------------------------------
# Generic printers
# ---------------------------------------------------------------------------

def print_info(msg: str) -> None:
    console.print(f"[bold cyan]ℹ[/bold cyan] {_rich_escape(msg)}", highlight=False)


def print_success(msg: str) -> None:
    console.print(f"[bold green]✓[/bold green] {_rich_escape(msg)}", highlight=False)


def print_error(msg: str) -> None:
    console.print(f"[bold red]✖[/bold red] {_rich_escape(msg)}", highlight=False)


def print_warning(msg: str) -> None:
    console.print(f"[bold yellow]⚠[/bold yellow] {_rich_escape(msg)}", highlight=False)

# ---------------------------------------------------------------------------
# Shell UI & Agentic Loop Formatting (Hermes/OpenCode inspired)
# ---------------------------------------------------------------------------

# Domain color palette — richer than single-word colors
_DOMAIN_PALETTE = {
    "htb":       {"primary": "#00ff41", "accent": "#39ff14", "dim": "#0a3d0a"},
    "bugbounty": {"primary": "#ffaf00", "accent": "#ffd700", "dim": "#4a3800"},
    "ctf":       {"primary": "#00d4ff", "accent": "#00bfff", "dim": "#003d4d"},
    "research":  {"primary": "#ff69b4", "accent": "#ff1493", "dim": "#4a0028"},
    "programmer":{"primary": "#6c9eff", "accent": "#4169e1", "dim": "#1a2d5a"},
    "osint":     {"primary": "#ff8c00", "accent": "#ff6600", "dim": "#4a2800"},
}

def _get_palette(domain: str) -> Dict[str, str]:
    return _DOMAIN_PALETTE.get(domain, _DOMAIN_PALETTE["htb"])


def print_banner(domain: str, version: str = "v3.0.0 (Agentic)") -> None:
    pal = _get_palette(domain)
    p, a = pal["primary"], pal["accent"]
    dom_cfg = get_domain(domain)
    dom_display = dom_cfg.get("display", domain.upper())

    # ASCII Art with fixed width (37 chars)
    art_text = Text.from_markup(f"[{a} bold]"
        " ██████╗  ███████╗ ███████╗  ██████╗ \n"
        " ██╔══██╗ ██╔════╝ ██╔════╝ ██╔════╝ \n"
        " ██║  ██║ ███████╗ █████╗   ██║      \n"
        " ██║  ██║ ╚════██║ ██╔══╝   ██║      \n"
        " ██████╔╝ ███████║ ███████╗ ╚██████╗ \n"
        " ╚═════╝  ╚══════╝ ╚══════╝  ╚═════╝ [/]"
    )
    
    from rich.align import Align
    content = Group(
        Text(""),
        Align.center(art_text),
        Text(""),
        Align.center(Text.from_markup(f"[bold white]DSEC Autonomous Security Agent[/]  [#888888]{version}[/]")),
        Align.center(Text.from_markup(f"[{p}]▸ Domain:[/] [bold]{dom_display}[/]")),
        Text(""),
    )

    banner_panel = Panel(
        content,
        box=box.HEAVY,
        border_style=p,
        width=64,
        padding=(0, 2),
    )
    
    console.print()
    console.print(banner_panel)
    console.print()


def print_thinking_block(thinking: str, domain: str = "htb", collapsed: bool = True) -> None:
    """Render a collapsible thinking block (OpenCode style)."""
    pal = _get_palette(domain)
    p = pal["primary"]
    word_count = len(thinking.split())

    if collapsed and len(thinking) > 500:
        display = thinking[:500].rstrip() + "…"
        suffix = f"  [#666666]({word_count} words — showing first 500 chars)[/]"
    else:
        display = thinking
        suffix = f"  [#666666]({word_count} words)[/]"

    header = f"[{p}]▼ Thinking[/{p}]{suffix}"
    console.print(header)
    console.print(f"  [{p}]┃[/{p}] [italic #888888]{display}[/italic #888888]")
    console.print(f"  [{p}]┗{'━' * 60}[/{p}]")


class ToolSpinner:
    """Animated spinner for API/tool calls."""
    def __init__(self, message: str = "Working..."):
        self.message = message
        self._live = None

    def __enter__(self):
        from rich.spinner import Spinner
        self._live = Live(
            Spinner("dots", text=Text(self.message, style="cyan")),
            console=console, refresh_per_second=12, transient=True,
        )
        self._live.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._live:
            self._live.__exit__(exc_type, exc_val, exc_tb)


def print_tool_header(tool_name: str, index: int, total: int, domain: str = "htb") -> None:
    """Print a tool execution header like hermes-agent."""
    pal = _get_palette(domain)
    p = pal["primary"]
    console.print(f"\n  [{p}]⚡[/{p}] [bold]Tool {index}/{total}[/bold]  [{p}]{tool_name}[/{p}]")


def print_tool_panel(tool_name: str, args: Dict[str, Any], domain: str = "htb") -> None:
    """Render a polished tool execution panel with arguments."""
    import json
    pal = _get_palette(domain)
    p = pal["primary"]

    lines = []
    for k, v in args.items():
        if isinstance(v, str) and len(v) > 200:
            v_display = v[:200] + "…"
        elif isinstance(v, (dict, list)):
            v_display = json.dumps(v, indent=2, ensure_ascii=False)
        else:
            v_display = str(v)
        lines.append(f"  [bold]{k}:[/bold] {v_display}")

    body = "\n".join(lines) if lines else "  (no arguments)"
    console.print(
        Panel(
            body,
            title=f"[{p}]⚙[/{p}] [bold]{tool_name}[/bold]",
            title_align="left",
            subtitle=f"[#666666]awaiting execution[/]",
            subtitle_align="right",
            border_style=p,
            padding=(0, 1),
            box=box.ROUNDED,
        )
    )


def print_tool_result(tool_name: str, success: bool, elapsed: float = 0.0, domain: str = "htb") -> None:
    """Print a tool result summary line."""
    pal = _get_palette(domain)
    if success:
        icon = "[bold green]✓[/bold green]"
    else:
        icon = "[bold red]✗[/bold red]"
    elapsed_str = f"[#666666]{elapsed:.1f}s[/]" if elapsed > 0 else ""
    console.print(f"  {icon} [bold]{tool_name}[/bold]  {elapsed_str}")


def print_iteration_header(iteration: int, max_iter: int, domain: str = "htb") -> None:
    """Print an iteration progress line for the agentic loop."""
    pal = _get_palette(domain)
    p = pal["primary"]
    
    if max_iter > 50:
        # Autonomous Mode indicator
        console.print(f"\n  [{p}]∞[/{p}] [bold]Autonomous Mode[/bold] (Step [{p}]{iteration}[/{p}])")
    else:
        bar_width = 20
        filled = int((iteration / max_iter) * bar_width) if max_iter > 0 else 0
        empty = bar_width - filled
        bar = f"[{p}]{'█' * filled}[/{p}][#333333]{'░' * empty}[/]"
        console.print(f"\n  [{p}]◆[/{p}] [bold]Agent Loop[/bold] [{p}]{iteration}[/{p}]/{max_iter}  {bar}")


def print_context_bar(usage_summary: str) -> None:
    """Print context usage as a right-aligned status bar."""
    console.print(f"  [#555555]{'─' * 60}[/]")
    console.print(f"  {usage_summary}", highlight=False)


def print_install_warning(cmd: str) -> None:
    """Warn when the agent tries to install something."""
    console.print(
        Panel(
            f"[bold yellow]⚠ The agent wants to install software:[/bold yellow]\n\n"
            f"  [bold]{cmd}[/bold]\n\n"
            f"[#888888]Installation commands require explicit approval.\n"
            f"Press [bold]y[/bold] to allow or [bold]n[/bold] to skip.[/]",
            title="[bold yellow]🔒 Install Permission Required[/bold yellow]",
            title_align="left",
            border_style="yellow",
            box=box.HEAVY,
            padding=(1, 2),
        )
    )

