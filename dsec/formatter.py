"""
DSEC Terminal Formatter
Rich-based terminal output for streaming responses, tables, and notices.
"""
from datetime import datetime, timezone
from typing import Any, Dict, Generator, List, Optional, Tuple

import sys
from rich import box
from rich.columns import Columns
from rich.console import Console, Group
from rich.live import Live
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .domain import get_domain

# Optimized for macOS Terminal and general stability
console = Console()


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
# Response Panel Builder
# ---------------------------------------------------------------------------

def _build_panel(
    domain: str,
    session_name: str,
    model: str,
    thinking: str,
    content: str,
    show_thinking: bool,
    turn: int,
    compression_info: Optional[Dict],
    research_sources: Optional[List[str]],
    memory_count: int,
    is_streaming: bool,
) -> Panel:
    domain_cfg = get_domain(domain)
    color = domain_cfg.get("color", "white")
    domain_display = domain_cfg.get("display", domain.upper())
    model_s = _model_short(model)

    # ---- Title ----
    title_parts = [f"[bold {color}]{domain_display}[/bold {color}]"]
    if session_name and session_name != "none":
        title_parts.append(f"[#888888]SESSION:[/] [bold]{session_name}[/bold]")
    title_parts.append(f"[#888888]MODEL:[/] [#888888]{model_s}[/]")
    title = "  ".join(title_parts)

    # ---- Body ----
    body_parts: List[Any] = []

    if thinking and show_thinking:
        think_text = Text()
        think_text.append("💭 Thinking...\n", style=f"bold {color} #888888")
        think_text.append("┄" * 68 + "\n", style="#888888")
        display_thinking = thinking if len(thinking) <= 2000 else thinking[:2000] + "\n…[truncated]"
        think_text.append(display_thinking, style="italic #888888")
        body_parts.append(think_text)
        body_parts.append(Text(""))

    if content:
        if is_streaming:
            body_parts.append(Text(content))
        else:
            try:
                body_parts.append(Markdown(content))
            except Exception:
                body_parts.append(Text(content))
    elif is_streaming and not thinking:
        body_parts.append(Text("⏳ Generating response…", style="#888888"))

    body = Group(*body_parts) if len(body_parts) > 1 else (body_parts[0] if body_parts else Text(""))

    # ---- Footer (subtitle) ----
    footer_parts: List[str] = []
    if turn > 0:
        footer_parts.append(f"[#888888]turn {turn}[/]")
    if compression_info:
        ratio = compression_info.get("compression_ratio", "")
        tool = compression_info.get("tool_detected", "")
        footer_parts.append(f"[{color} #888888]compressed {ratio}[/{color} #888888]")
    if research_sources:
        src_str = "+".join(s[:3].upper() for s in research_sources[:5])
        footer_parts.append(f"[cyan #888888]research:{src_str}[/cyan #888888]")
    if memory_count > 0:
        footer_parts.append(f"[blue #888888]memory:{memory_count}[/blue #888888]")

    subtitle = "  ".join(footer_parts) if footer_parts else None

    return Panel(
        body,
        title=title,
        title_align="left",
        subtitle=subtitle,
        subtitle_align="left",
        border_style=color,
        box=box.MINIMAL,
        padding=(0, 2),
    )


# ---------------------------------------------------------------------------
# Main Stream Renderer
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
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Stream response from generator to the terminal using Rich Live.
    Returns (thinking, content, conversation_id) or (None, None, None) on error.
    """
    thinking_parts: List[str] = []
    content_parts: List[str] = []
    conv_id: Optional[str] = None

    cancelled = False

    try:
        with Live(console=console, refresh_per_second=12, transient=False) as live:
            for chunk in generator:
                ctype = chunk.get("type")

                if ctype == "thinking":
                    thinking_parts.append(chunk["text"])
                    live.update(
                        _build_panel(
                            domain, session_name, model,
                            "".join(thinking_parts), "".join(content_parts),
                            show_thinking, turn, compression_info,
                            research_sources, memory_count, True,
                        )
                    )

                elif ctype == "content":
                    content_parts.append(chunk["text"])
                    live.update(
                        _build_panel(
                            domain, session_name, model,
                            "".join(thinking_parts), "".join(content_parts),
                            show_thinking, turn, compression_info,
                            research_sources, memory_count, True,
                        )
                    )

                elif ctype == "done":
                    conv_id = chunk.get("conversation_id")
                    live.update(
                        _build_panel(
                            domain, session_name, model,
                            "".join(thinking_parts), "".join(content_parts),
                            show_thinking, turn, compression_info,
                            research_sources, memory_count, False,
                        )
                    )

                elif ctype == "error":
                    live.update(
                        Panel(
                            Text(f"❌  {chunk['text']}", style="bold red"),
                            title="[red]ERROR[/red]",
                            border_style="red",
                        )
                    )
                    return None, None, None

    except KeyboardInterrupt:
        # Ctrl-C mid-stream: stop the generator, keep whatever arrived so far
        cancelled = True
        try:
            generator.close()  # type: ignore[union-attr]
        except Exception:
            pass

    if cancelled:
        partial_content = "".join(content_parts)
        partial_thinking = "".join(thinking_parts)
        # Render a final panel with a cancellation marker appended
        cancel_suffix = "\n\n[bold red]✖ Response cancelled.[/bold red]"
        console.print(
            _build_panel(
                domain, session_name, model,
                partial_thinking,
                partial_content + cancel_suffix if partial_content else cancel_suffix,
                show_thinking, turn, compression_info,
                research_sources, memory_count, False,
            )
        )
        # Return partial content so the session history still captures it,
        # but flag it so _persist_successful_turn knows it's incomplete.
        return partial_thinking or None, partial_content or None, conv_id

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
    q_strs = [f'"{q["query"]}"' for q in queries[:4]]
    console.print(f"[cyan]🔬 Auto-researching: {', '.join(q_strs)}…[/cyan]", highlight=False)


def print_research_complete(total: int, sources: List[str]) -> None:
    if total > 0:
        src_str = ", ".join(sources[:5])
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
    console.print(f"[bold cyan]ℹ[/bold cyan] {msg}", highlight=False)


def print_success(msg: str) -> None:
    console.print(f"[bold green]✓[/bold green] {msg}", highlight=False)


def print_error(msg: str) -> None:
    console.print(f"[bold red]✖[/bold red] {msg}", highlight=False)


def print_warning(msg: str) -> None:
    console.print(f"[bold yellow]⚠[/bold yellow] {msg}", highlight=False)
