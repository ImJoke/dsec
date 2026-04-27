#!/usr/bin/env python3
"""
dsec – DeepSeek Security CLI
Agentic security CLI for Bug Bounty, HTB, CTF, and Security Research.

Usage:
  dsec
  dsec shell
  dsec "message"
  dsec --session htb-permx "what next?"
  cat nmap.txt | dsec --session htb-permx "analyze"
  dsec sessions
  dsec note --session htb-permx "Found admin" --type finding
  dsec memory --list
  dsec --help
"""

from __future__ import annotations

import asyncio
import json as _json
import os as _os
import re as _re
import sys
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

import click
from rich.panel import Panel
from rich.text import Text

from .client import chat_stream
from .compressor import compress, should_compress
from .config import (
    CONFIG_FILE,
    ConfigError,
    add_tokens,
    check_tokens,
    clear_sudo_password,
    get_next_token,
    get_sudo_password,
    init_config,
    list_tokens,
    load_config,
    save_config,
    set_sudo_password,
)
from .domain import detect_domain, get_domain, get_system_prompt
from .formatter import (
    console,
    print_compression_notice,
    print_error,
    print_info,
    print_memory_detail,
    print_memory_list,
    print_memory_notice,
    print_research_complete,
    print_research_notice,
    print_session_detail,
    print_sessions_table,
    print_success,
    print_warning,
    stream_response,
)
from .memory import (
    auto_extract_memories,
    delete_memory,
    format_memory_context,
    get_memory,
    list_memories,
    memory_available,
    search_memory,
    store_memory,
    update_confidence,
)
from .executor import CommandResult, get_runner
from .mcp_client import get_mcp_manager
from .shell_ui import build_prompt_session, format_prompt, prompt_available
from .researcher import format_research_context, run_research, should_research
from .session import (
    add_history_entry,
    add_note,
    add_tags,
    create_session,
    delete_session,
    get_current_session_name,
    increment_message_count,
    list_sessions,
    load_last_session,
    load_session,
    rename_session,
    save_last_session,
    save_turn,
    set_conversation_id,
)


# ────────────────────────────────────────────────────────────────────────────
# Safe input (strips ANSI escape sequences from arrow-key presses)
# ────────────────────────────────────────────────────────────────────────────

_ANSI_ESCAPE_RE = _re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _safe_input(prompt: str) -> str:
    raw = console.input(prompt)
    return _ANSI_ESCAPE_RE.sub("", raw).strip()


# ────────────────────────────────────────────────────────────────────────────
# Core chat pipeline helpers
# ────────────────────────────────────────────────────────────────────────────


def _read_stdin_content() -> str:
    if sys.stdin.isatty():
        return ""
    try:
        return sys.stdin.read().strip()
    except OSError:
        return ""


def _combine_user_input(message: str, stdin_content: str) -> str:
    if stdin_content and message:
        return f"{stdin_content}\n\n{message}"
    if stdin_content:
        return stdin_content
    return message


def _resolve_session(
    session_name: str,
    full_input: str,
    config: Dict[str, Any],
    domain_override: str,
    model_override: str,
) -> Optional[Dict[str, Any]]:
    if not session_name:
        return None

    session_data = load_session(session_name)
    if session_data is not None:
        return session_data

    domain_guess = domain_override or detect_domain(full_input, session_name)
    model_guess = model_override or config.get("default_model", "deepseek-expert-r1-search")
    created = create_session(session_name, domain_guess, model_guess)
    print_info(f"Created new session: [bold]{session_name}[/bold] [{domain_guess}]")
    return created


def _resolve_domain_and_model(
    session_data: Optional[Dict[str, Any]],
    full_input: str,
    session_name: str,
    domain_override: str,
    model_override: str,
    config: Dict[str, Any],
) -> Tuple[str, str]:
    if domain_override:
        domain = domain_override
    elif session_data:
        domain = session_data.get("domain", "htb")
    else:
        domain = detect_domain(full_input, session_name)

    if model_override:
        model = model_override
    elif session_data:
        model = session_data.get("model") or config.get("default_model", "deepseek-expert-r1-search")
    else:
        model = config.get("default_model", "deepseek-expert-r1-search")

    return domain, model


def _apply_no_think(full_input: str, no_think: bool) -> str:
    if not no_think:
        return full_input
    return "Respond concisely and directly without extended internal reasoning.\n\n" + full_input


def _compress_input(
    full_input: str,
    stdin_content: str,
    no_compress: bool,
    threshold: int,
) -> Tuple[str, str, Optional[Dict[str, Any]]]:
    if no_compress:
        return full_input, stdin_content, None

    compression_info: Optional[Dict[str, Any]] = None
    compressed_stdin = stdin_content
    compressed_full_input = full_input

    if stdin_content and should_compress(stdin_content, threshold):
        compression_info = compress(stdin_content)
        compressed_stdin = compression_info["compressed_content"]
        print_compression_notice(compression_info)
    elif not stdin_content and should_compress(full_input, threshold):
        compression_info = compress(full_input)
        compressed_full_input = compression_info["compressed_content"]
        print_compression_notice(compression_info)

    return compressed_full_input, compressed_stdin, compression_info


def _load_memory_context(
    final_input: str,
    domain: str,
    *,
    enabled: bool,
) -> Tuple[str, int]:
    if not enabled or not memory_available():
        return "", 0

    memories = search_memory(final_input, domain=domain)
    if not memories:
        return "", 0

    similarities = [m.get("similarity", 0.0) for m in memories]
    print_memory_notice(len(memories), similarities)
    return format_memory_context(memories), len(memories)


def _run_research_context(
    full_input: str,
    domain: str,
    config: Dict[str, Any],
    *,
    enabled: bool,
) -> Tuple[str, List[str]]:
    if not enabled or not config.get("auto_research", True):
        return "", []

    research_queries = should_research(full_input, domain)
    if not research_queries:
        return "", []

    print_research_notice(research_queries)
    try:
        research_results = asyncio.run(
            run_research(research_queries, config.get("research_max_results", 5))
        )
    except RuntimeError:
        research_results = []

    if not research_results:
        print_research_complete(0, [])
        return "", []

    research_sources = list({r["source_key"] for r in research_results if r.get("results")})
    total_findings = sum(len(r.get("results", [])) for r in research_results)
    print_research_complete(total_findings, research_sources)
    return format_research_context(research_results), research_sources


def _build_mcp_context() -> str:
    try:
        mgr = get_mcp_manager()
        tools = mgr.list_tools()
    except Exception:
        return ""
    if not tools:
        return ""
    lines = ["[AVAILABLE MCP TOOLS]"]
    for t in tools:
        schema = t.get("inputSchema", {})
        props = list(schema.get("properties", {}).keys())
        lines.append(f'  mcp__{t["server"]}__{t["name"]}: {t.get("description", "")}')
        if props:
            lines.append(f"    params: {', '.join(props)}")
    lines.append("[END MCP TOOLS]")
    return "\n".join(lines)


def _build_prompt(
    *,
    domain: str,
    conversation_id: Optional[str],
    quick: bool,
    memory_context: str,
    research_context: str,
    stdin_content: str,
    compressed_stdin_content: str,
    message: str,
    final_input: str,
) -> str:
    prompt_parts: List[str] = []

    if not quick:
        # Selalu inject full system prompt dan instruksi eksekusi di setiap turn
        # agar model (terutama R1) tidak "lupa" format <tool_call>
        system_prompt = get_system_prompt(domain)
        prompt_parts.append(f"[SYSTEM INSTRUCTIONS]\n{system_prompt}\n[END SYSTEM]")

        # MCP context juga selalu di-inject
        mcp_ctx = _build_mcp_context()
        if mcp_ctx:
            prompt_parts.append(mcp_ctx)

    if memory_context:
        prompt_parts.append(memory_context)

    if research_context:
        prompt_parts.append(research_context)

    if stdin_content and message:
        prompt_parts.append(
            f"[TOOL OUTPUT]\n{compressed_stdin_content}\n[END TOOL OUTPUT]\n\n{message}"
        )
    elif stdin_content:
        prompt_parts.append(
            f"[TOOL OUTPUT]\n{compressed_stdin_content}\n[END TOOL OUTPUT]\n\nAnalyze the above output."
        )
    else:
        prompt_parts.append(final_input)

    return "\n\n".join(prompt_parts)


def _persist_successful_turn(
    *,
    session_name: str,
    full_input: str,
    response_content: str,
    thinking: Optional[str],
    compression_info: Optional[Dict[str, Any]],
    new_conv_id: Optional[str],
) -> None:
    if not session_name or not response_content:
        return
    save_turn(
        session_name,
        conversation_id=new_conv_id,
        user_content=full_input,
        assistant_content=response_content,
        thinking=thinking,
        compressed=(compression_info is not None),
    )


def _auto_store_memories(
    response_content: str,
    session_name: str,
    domain: str,
    *,
    enabled: bool,
) -> None:
    if not enabled or not response_content or not session_name or not memory_available():
        return

    extracted = auto_extract_memories(
        response=response_content,
        session=session_name,
        domain=domain,
    )
    if extracted:
        print_info(f"Auto-stored {len(extracted)} memory snippet(s) [confidence: suspected]")


# ─────────────────────────────────────────────────────────────────────────────
# Agentic execution helpers
# ─────────────────────────────────────────────────────────────────────────────

_TOOL_CALL_RE = _re.compile(r"<tool_call>\s*(.*?)\s*</tool_call>", _re.DOTALL | _re.IGNORECASE)

def _extract_tool_calls(text: str) -> list[dict]:
    """Ekstrak tool calls berformat JSON dari tag <tool_call>"""
    calls = []
    for match in _TOOL_CALL_RE.finditer(text):
        content = match.group(1).strip()
        # Cari objek JSON { ... } di dalam konten
        json_match = _re.search(r"\{.*\}", content, _re.DOTALL)
        if json_match:
            try:
                call_data = _json.loads(json_match.group(0))
                if isinstance(call_data, dict) and "name" in call_data:
                    calls.append(call_data)
            except _json.JSONDecodeError:
                continue
    return calls

def _run_agentic_loop(
    response_content: str,
    *,
    session_name: str,
    domain: str,
    model: str,
    conversation_id: Optional[str],
    config: Dict[str, Any],
    turn: int,
    no_think: bool,
    no_memory: bool,
    auto_exec: bool = False,
    max_iterations: int = 10
) -> Optional[str]:
    """
    Hermes-style agentic loop.

    Each iteration:
      1. Extract all <tool_call> blocks (plus legacy <bash>/<mcp> for backward compat).
      2. Dispatch each call: bash tools ask for user approval; MCP tools run directly.
      3. Build <tool_response> blocks for every result.
      4. Send results back to the AI and repeat.

    Returns the final conversation_id.
    """
    current_conv_id = conversation_id
    current_response = response_content
    runner = get_runner()

    for iteration in range(1, max_iterations + 1):
        tool_calls = _extract_tool_calls(current_response)
        if not tool_calls:
            break

        console.print(
            f"\n[bold cyan]⚙  Agent requested "
            f"{len(tool_calls)} tool call{'s' if len(tool_calls) > 1 else ''}[/bold cyan]"
        )

        tool_responses: List[Dict[str, Any]] = []
        approve_all = auto_exec

        for idx, call in enumerate(tool_calls, 1):
            tool_name: str = call["name"]
            arguments: Dict[str, Any] = call.get("arguments", {})

            # ── bash tool ─────────────────────────────────────────────────────
            if tool_name == "bash":
                cmd = arguments.get("command", "").strip()
                if not cmd:
                    tool_responses.append({"name": tool_name, "result": "[error: empty command]"})
                    continue

                console.print(
                    Panel(
                        Text(cmd, style="bold green"),
                        title=f"[bold cyan]bash ({idx}/{len(tool_calls)})[/bold cyan]",
                        border_style="cyan",
                    )
                )

                edited_cmd = cmd
                approved = False

                if approve_all:
                    approved = True
                else:
                    try:
                        console.print(
                            "  [bold green]\\[y]es[/bold green]  "
                            "[bold red]\\[n]o[/bold red]  "
                            "[bold yellow]\\[A]ll yes[/bold yellow]  "
                            "[bold]\\[e]dit[/bold]"
                        )
                        choice = _safe_input("> ").lower()
                    except (EOFError, KeyboardInterrupt):
                        console.print()
                        print_warning("Agentic execution cancelled.")
                        return current_conv_id

                    if choice in ("y", ""):
                        approved = True
                    elif choice == "a":
                        approve_all = True
                        approved = True
                    elif choice == "e":
                        try:
                            edited_cmd = _safe_input(
                                f"[bold]Edit → [/bold][#888888]{cmd}[/]\n> "
                            ) or cmd
                            approved = True
                        except (EOFError, KeyboardInterrupt):
                            approved = False

                if not approved:
                    print_info(f"Skipped: {cmd[:80]}")
                    tool_responses.append({"name": tool_name, "result": "[user skipped]"})
                    continue

                console.print(f"[bold #888888]$ {edited_cmd}[/bold #888888]")
                console.print("[#888888]────────────────────────────────────[/]")

                result_holder: List[Optional[CommandResult]] = [None]

                def _worker(c: str = edited_cmd, _sp: Optional[str] = state.get("sudo_password")) -> None:
                    result_holder[0] = runner.run(
                        c,
                        on_stdout=lambda line: console.print(line, end="", highlight=False),
                        on_stderr=lambda line: console.print(f"[#888888]{line}[/]", end="", highlight=False),
                        shell=True,
                        sudo_password=_sp,
                    )

                t = threading.Thread(target=_worker, daemon=True)
                t.start()
                try:
                    while t.is_alive():
                        t.join(timeout=0.25)
                except KeyboardInterrupt:
                    runner.interrupt()
                    t.join(timeout=5)
                    console.print()
                    print_warning("Command interrupted.")

                console.print("[#888888]────────────────────────────────────[/]")

                res = result_holder[0]
                if res is None:
                    result_text = "[command failed to complete]"
                else:
                    if res.returncode not in (0,) and not res.interrupted:
                        print_warning(f"Exit code: {res.returncode}")
                    parts = [res.combined_output() or "(no output)"]
                    if res.interrupted:
                        parts.append("[interrupted]")
                    elif res.returncode not in (0,):
                        parts.append(f"[exit code: {res.returncode}]")
                    result_text = "\n".join(parts)

                tool_responses.append({"name": tool_name, "result": result_text})

            # ── MCP tool (mcp__server__toolname) ──────────────────────────────
            elif tool_name.startswith("mcp__"):
                parts_name = tool_name.split("__", 2)
                if len(parts_name) < 3:
                    tool_responses.append({"name": tool_name, "result": f"[error: bad mcp tool name: {tool_name}]"})
                    continue
                srv_name, mcp_tool = parts_name[1], parts_name[2]
                console.print(
                    f"  [bold #888888]mcp:{srv_name}/{mcp_tool}[/bold #888888] "
                    f"[#888888]{_json.dumps(arguments)}[/]"
                )
                try:
                    mcp_out = get_mcp_manager().call_tool(srv_name, mcp_tool, arguments)
                    tool_responses.append({"name": tool_name, "result": str(mcp_out)})
                except Exception as mcp_exc:
                    print_warning(f"MCP {srv_name}/{mcp_tool} failed: {mcp_exc}")
                    tool_responses.append({"name": tool_name, "result": f"[error: {mcp_exc}]"})

            else:
                tool_responses.append({"name": tool_name, "result": f"[error: unknown tool '{tool_name}']"})

        # ── build Hermes-style <tool_response> follow-up ──────────────────────
        response_blocks = []
        for tr in tool_responses:
            payload = _json.dumps({"name": tr["name"], "result": tr["result"]}, ensure_ascii=False)
            response_blocks.append(f"<tool_response>\n{payload}\n</tool_response>")

        follow_up = "\n\n".join(response_blocks)
        follow_up += "\n\nContinue your analysis. Use <tool_call> blocks if more tool calls are needed."

        # ── send follow-up to AI ──────────────────────────────────────────────
        print_info(f"Feeding results back to AI (agent loop iteration {iteration})…")

        try:
            gen = chat_stream(
                message=follow_up,
                model=model,
                conversation_id=current_conv_id,
                base_url=config.get("base_url", "http://localhost:8000"),
                token=get_next_token(),
            )
            thinking, new_content, new_conv_id = stream_response(
                generator=gen,
                session_name=session_name or "none",
                domain=domain,
                model=model,
                turn=turn + iteration,
                compression_info=None,
                research_sources=None,
                memory_count=0,
                show_thinking=config.get("show_thinking", True) and not no_think,
            )
        except KeyboardInterrupt:
            console.print()
            print_warning("Agentic loop cancelled.")
            return current_conv_id

        if new_conv_id:
            current_conv_id = new_conv_id

        if new_content is None:
            break

        if session_name and not no_memory:
            save_turn(
                session_name,
                conversation_id=current_conv_id,
                user_content=follow_up[:1000],
                assistant_content=new_content[:3000],
                thinking=thinking,
            )

        current_response = new_content

    else:
        print_warning(f"Agentic loop hit the {max_iterations}-iteration limit.")

    return current_conv_id


def _generate_shell_session_name() -> str:
    return datetime.now().strftime("shell-%Y%m%d-%H%M%S")


def _print_shell_banner(session_name: str, domain: str, model: str, sudo_set: bool = False) -> None:
    domain_cfg = get_domain(domain)
    color = domain_cfg.get("color", "white")
    sudo_indicator = "  [bold yellow]🔑 sudo[/bold yellow]" if sudo_set else ""
    console.print()
    console.print(f"[{color}]●[/{color}] [bold]DSEC Interactive[/bold]{sudo_indicator}")
    console.print(f"  [#888888]session:[/] {session_name}  [#888888]domain:[/] {domain_cfg.get('display', domain)}  [#888888]model:[/] {model}")
    cmds = ["!<cmd>", "/history", "/note", "/domain", "/model",
            "/autoexec", "/sudo", "/mcp", "/status", "/help", "/exit"]
    console.print(f"  [cyan]{'  '.join(cmds)}[/cyan]\n")


def _print_shell_help() -> None:
    from rich import box
    console.print(
        Panel(
            Text.from_markup(
                "[bold cyan]── Talking to the AI ────────────────────────────[/bold cyan]\n"
                "Just type your message and press [bold]Enter[/bold].\n"
                "If the AI needs to run a command it wraps it in [bold]<bash>[/bold] tags\n"
                "\xe2\x80\x94 approve each one ([bold]y[/bold]/[bold]n[/bold]/[bold]A[/bold]ll/[bold]e[/bold]dit) before it executes.\n\n"
                "[bold cyan]── Run Commands Yourself ────────────────────��───[/bold cyan]\n"
                "[bold]!<cmd>[/bold]            run a command live (e.g. [#888888]!nmap -sV 10.0.0.1[/])\n"
                "                  streams output; choose to send to AI or discard.\n\n"
                "[bold cyan]── Agentic Execution ────────────────────────────[/bold cyan]\n"
                "[bold]/autoexec on[/bold]      auto-approve AI <bash> blocks (no confirm)\n"
                "[bold]/autoexec off[/bold]     (default) ask y/n/A/e before each AI command\n\n"
                "[bold cyan]── Sudo Auto-Inject ─────────────────────────────[/bold cyan]\n"
                "[bold]/sudo[/bold]             prompt for sudo password (hidden input)\n"
                "[bold]/sudo <pass>[/bold]      set sudo password inline\n"
                "[bold]/sudo save[/bold]        persist password to ~/.dsec/config.json\n"
                "[bold]/sudo clear[/bold]       remove password (in-session and from config)\n"
                "[bold]/sudo status[/bold]      show whether sudo password is active\n"
                "                  [#888888]Also reads DSEC_SUDO_PASS env var on startup.[/]\n\n"
                "[bold cyan]── Session ──────────────────────────────────────[/bold cyan]\n"
                "[bold]/session[/bold]          show session details (notes, flags, history)\n"
                "[bold]/history[/bold]          show last 10 conversation turns\n"
                "[bold]/note <text>[/bold]      add a note to the session\n"
                "[bold]/domain <name>[/bold]    switch domain: [#888888]htb  bugbounty  ctf  research[/]\n"
                "[bold]/model <name>[/bold]     switch AI model\n"
                "[bold]/status[/bold]           show all shell settings\n"
                "[bold]/clear[/bold]            clear screen\n\n"
                "[bold cyan]── MCP Servers ──────────────────────────────────[/bold cyan]\n"
                "[bold]/mcp list[/bold]                     list configured MCP servers\n"
                "[bold]/mcp connect <name>[/bold]           connect to server\n"
                "[bold]/mcp disconnect <name>[/bold]        disconnect\n"
                "[bold]/mcp tools [name][/bold]             list available tools\n"
                "[bold]/mcp call <srv> <tool> [json][/bold] call a tool\n\n"
                "[bold cyan]── Keyboard ─────────────────────────────────────[/bold cyan]\n"
                "[bold]\u2191 \u2193[/bold]       history up/down   [bold]\u2190 \u2192[/bold]  move cursor\n"
                "[bold]Tab[/bold]      autocomplete      [bold]Ctrl-R[/bold]  reverse search\n"
                "[bold]Ctrl-C[/bold]   cancel line / cancel streaming request\n"
                "[bold]Ctrl-D[/bold]   exit shell\n\n"
                "[bold cyan]── Meta ─────────────────────────────────────────[/bold cyan]\n"
                "[bold]/help[/bold]             show this message\n"
                "[bold]/exit[/bold] / [bold]/quit[/bold]    leave the shell"
            ),
            title="[bold]DSEC Shell — Help[/bold]",
            title_align="left",
            border_style="blue",
            box=box.MINIMAL,
        )
    )


def _print_shell_status(state: Dict[str, Any]) -> None:
    info = Text()
    info.append("Session:     ", style="bold")
    info.append(f"{state['session_name']}\n")
    info.append("Domain:      ", style="bold")
    info.append(f"{state['domain_override'] or 'auto'}\n")
    info.append("Model:       ", style="bold")
    info.append(f"{state['model_override'] or 'default'}\n")
    info.append("Compression: ", style="bold")
    info.append(f"{'off' if state['no_compress'] else 'on'}\n")
    info.append("Thinking:    ", style="bold")
    info.append(f"{'off' if state['no_think'] else 'on'}\n")
    info.append("Research:    ", style="bold")
    info.append(f"{'off' if state['no_research'] else 'on'}\n")
    info.append("Memory:      ", style="bold")
    info.append(f"{'off' if state['no_memory'] else 'on'}\n")
    info.append("Auto-exec:   ", style="bold")
    ae = state.get("auto_exec", False)
    info.append(f"[bold {'green' if ae else 'red'}]{'ON' if ae else 'OFF'}[/bold {'green' if ae else 'red'}]\n")
    info.append("Sudo pass:   ", style="bold")
    sudo_set = bool(state.get("sudo_password"))
    info.append(f"[bold {'yellow' if sudo_set else 'dim'}]{'🔑 set' if sudo_set else 'not set'}[/bold {'yellow' if sudo_set else 'dim'}]\n")
    from rich import box
    from rich.panel import Panel
    console.print(Panel(info, title="[bold]Shell Status[/bold]", title_align="left", border_style="blue", box=box.MINIMAL))


def _handle_sudo_command(arg: str, state: Dict[str, Any]) -> None:
    """Handle /sudo subcommands."""
    if arg == "clear":
        state["sudo_password"] = None
        clear_sudo_password()
        print_success("Sudo password cleared.")
        return
    if arg == "save":
        pw = state.get("sudo_password")
        if not pw:
            print_warning("No sudo password active. Set one first with [bold]/sudo[/bold].")
            return
        set_sudo_password(pw)
        print_success("Sudo password saved to [bold]~/.dsec/config.json[/bold].")
        return
    if arg == "status":
        has = bool(state.get("sudo_password"))
        print_info(f"Sudo password: {'🔑 active' if has else 'not set'}")
        return
    if arg:
        state["sudo_password"] = arg
        print_success("Sudo password set [#888888](🔑 auto-injecting for sudo commands)[/]")
        return
    # No argument: hidden prompt via getpass
    import getpass
    try:
        pw = getpass.getpass("Sudo password (input hidden): ")
    except (KeyboardInterrupt, EOFError):
        console.print()
        print_info("Cancelled.")
        return
    if pw:
        state["sudo_password"] = pw
        print_success("Sudo password set [#888888](🔑 auto-injecting for sudo commands)[/]")
    else:
        print_info("No password entered.")


def _handle_shell_command(raw: str, state: Dict[str, Any]) -> bool:
    """Handle a slash command.  Returns True if handled; False if it's a chat message."""
    if not raw.startswith("/"):
        return False

    parts = raw.split(maxsplit=1)
    command = parts[0].lower()
    arg = parts[1].strip() if len(parts) > 1 else ""

    # ── exit ──────────────────────────────────────────────────────────────────
    if command in {"/exit", "/quit"}:
        raise EOFError

    # ── help ──────────────────────────────────────────────────────────────────
    if command == "/help":
        _print_shell_help()
        return True

    # ── clear ─────────────────────────────────────────────────────────────────
    if command == "/clear":
        console.clear()
        return True

    # ── session ───────────────────────────────────────────────────────────────
    if command == "/session":
        data = load_session(state["session_name"])
        if data:
            print_session_detail(data)
        else:
            print_warning("No saved session data yet for this shell.")
        return True

    # ── status ────────────────────────────────────────────────────────────────
    if command == "/status":
        _print_shell_status(state)
        return True

    # ── note ──────────────────────────────────────────────────────────────────
    if command == "/note":
        if not arg:
            print_warning("Usage: /note <text>")
            return True
        add_note(state["session_name"], arg, "misc")
        print_success("Note added to the current session.")
        return True

    # ── domain ────────────────────────────────────────────────────────────────
    if command == "/domain":
        if arg not in {"htb", "bugbounty", "ctf", "research"}:
            print_warning("Usage: /domain <htb|bugbounty|ctf|research>")
            return True
        state["domain_override"] = arg
        print_success(f"Shell domain set to {arg}.")
        return True

    # ── model ─────────────────────────────────────────────────────────────────
    if command == "/model":
        if not arg:
            print_warning("Usage: /model <name>")
            return True
        state["model_override"] = arg
        print_success(f"Shell model set to {arg}.")
        return True

    # ── history ───────────────────────────────────────────────────────────────
    if command == "/history":
        _print_shell_history(state["session_name"])
        return True

    # ── autoexec ──────────────────────────────────────────────────────────────
    if command == "/autoexec":
        if arg in {"on", "1", "true", "yes"}:
            state["auto_exec"] = True
            print_success("Auto-exec [bold green]ON[/bold green] – AI commands run without prompting.")
        elif arg in {"off", "0", "false", "no"}:
            state["auto_exec"] = False
            print_success("Auto-exec [bold red]OFF[/bold red] – AI commands will ask for approval.")
        else:
            ae_status = "ON" if state.get("auto_exec") else "OFF"
            print_info(f"Auto-exec is currently {ae_status}. Usage: /autoexec on|off")
        return True

    # ── mcp ───────────────────────────────────────────────────────────────────
    if command == "/mcp":
        _handle_mcp_command(arg, state)
        return True

    # ── sudo ──────────────────────────────────────────────────────────────────
    if command == "/sudo":
        _handle_sudo_command(arg, state)
        return True

    print_warning(f"Unknown shell command: {command}. Use /help.")
    return True


# ─────────────────────────────────────────────────────────────────────────────
# /history helper
# ─────────────────────────────────────────────────────────────────────────────

def _print_shell_history(session_name: str, max_turns: int = 10) -> None:
    data = load_session(session_name)
    if not data:
        print_info("No session history yet.")
        return

    history = data.get("history", [])
    if not history:
        print_info("No conversation history in this session yet.")
        return

    recent = history[-max_turns * 2:]  # up to max_turns pairs
    from rich.table import Table
    from rich import box
    table = Table(title=f"History – {session_name} (last {len(recent)} entries)", title_justify="left", border_style="#888888", box=box.SIMPLE)
    table.add_column("Role", style="bold", width=12)
    table.add_column("Content", overflow="fold")
    for entry in recent:
        role = entry.get("role", "?")
        content = entry.get("content", "")
        if len(content) > 800:
            content = content[:800] + "…"
        color = "green" if role == "assistant" else "cyan"
        table.add_row(f"[{color}]{role}[/{color}]", content)
    console.print(table)


# ─────────────────────────────────────────────────────────────────────────────
# /run helper
# ─────────────────────────────────────────────────────────────────────────────

def _shell_run_command(cmd: str, state: Dict[str, Any]) -> None:
    """Execute *cmd*, stream output to the console, then ask to send to AI."""
    runner = get_runner()

    if runner.is_running():
        print_warning("A command is already running.  Use /interrupt to stop it.")
        return

    console.print(f"[bold #888888]$ {cmd}[/bold #888888]")
    console.print("[#888888]─────────────────────────────[/]")

    # Run in a background thread so Ctrl-C can reach us
    result_holder: List[Optional[CommandResult]] = [None]

    def _worker() -> None:
        result_holder[0] = runner.run(
            cmd,
            on_stdout=lambda line: console.print(line, end="", highlight=False),
            on_stderr=lambda line: console.print(f"[#888888]{line}[/]", end="", highlight=False),
            shell=True,  # shell=True for convenience in security ops
            sudo_password=state.get("sudo_password"),
        )

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    try:
        while t.is_alive():
            t.join(timeout=0.25)
    except KeyboardInterrupt:
        runner.interrupt()
        t.join(timeout=5)

    console.print("\n[#888888]─────────────────────────────[/]")
    result: CommandResult = result_holder[0]  # type: ignore[assignment]

    if result is None:
        print_error("Command did not complete.")
        return

    if result.returncode != 0 and not result.interrupted:
        print_warning(f"Exit code: {result.returncode}")
    elif result.interrupted:
        print_warning("Command was interrupted.")

    # Ask whether to send output to AI
    combined = result.combined_output()
    if not combined.strip():
        return  # nothing to send

    try:
        console.print(
            "\n[bold]Send this output to the AI?[/bold]  "
            "[bold green]\\[s]end[/bold green]  [bold]\\[d]iscard[/bold]  "
            "[bold]\\[a]sk a question first[/bold]"
        )
        choice = console.input("> ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return

    if choice == "s":
        # Feed directly into _run_chat as a tool output
        try:
            _run_chat(
                message=f"Analyze this command output from: {cmd}",
                session_name=state["session_name"],
                domain_override=state.get("domain_override", ""),
                model_override=state.get("model_override", ""),
                no_compress=state["no_compress"],
                no_think=state["no_think"],
                no_research=state["no_research"],
                no_memory=state["no_memory"],
                quick=state["quick"],
                _tool_output=result.as_tool_output(),
            )
        except KeyboardInterrupt:
            console.print()
            print_warning("Request cancelled.")
    elif choice == "a":
        try:
            question = console.input("[bold cyan]Your question:[/bold cyan] ").strip()
        except (EOFError, KeyboardInterrupt):
            return
        if question:
            try:
                _run_chat(
                    message=question,
                    session_name=state["session_name"],
                    domain_override=state.get("domain_override", ""),
                    model_override=state.get("model_override", ""),
                    no_compress=state["no_compress"],
                    no_think=state["no_think"],
                    no_research=state["no_research"],
                    no_memory=state["no_memory"],
                    quick=state["quick"],
                    _tool_output=result.as_tool_output(),
                )
            except KeyboardInterrupt:
                console.print()
                print_warning("Request cancelled.")
    # else: discard


# ─────────────────────────────────────────────────────────────────────────────
# /mcp helper
# ─────────────────────────────────────────────────────────────────────────────

def _handle_mcp_command(arg: str, state: Dict[str, Any]) -> None:
    mgr = get_mcp_manager()
    sub_parts = arg.split(maxsplit=3) if arg else []
    sub = sub_parts[0].lower() if sub_parts else "list"

    if sub == "list":
        servers = mgr.list_servers()
        if not servers:
            print_info("No MCP servers configured.\n"
                       "Add one in ~/.dsec/config.json under 'mcp_servers'.\n"
                       "Example:\n"
                       '  {"mcp_servers": {"myserver": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]}}}')
            return
        from rich.table import Table
        from rich import box
        table = Table(title="MCP Servers", title_justify="left", border_style="#888888", box=box.SIMPLE)
        table.add_column("Name", style="bold")
        table.add_column("Command")
        table.add_column("Status")
        table.add_column("Tools", justify="right")
        for s in servers:
            status = "[green]connected[/green]" if s["connected"] else "[#888888]disconnected[/]"
            table.add_row(s["name"], s["command"], status, str(s["tools"]))
        console.print(table)

    elif sub == "connect":
        name = sub_parts[1] if len(sub_parts) > 1 else ""
        if not name:
            print_warning("Usage: /mcp connect <server-name>")
            return
        print_info(f"Connecting to MCP server '{name}'…")
        ok = mgr.connect(name)
        if ok:
            print_success(f"Connected to '{name}'.")
        else:
            print_error(f"Failed to connect to '{name}'. Check config and that the command is installed.")

    elif sub == "disconnect":
        name = sub_parts[1] if len(sub_parts) > 1 else ""
        if not name:
            print_warning("Usage: /mcp disconnect <server-name>")
            return
        if mgr.disconnect(name):
            print_success(f"Disconnected '{name}'.")
        else:
            print_error(f"Server '{name}' was not connected.")

    elif sub == "tools":
        name = sub_parts[1] if len(sub_parts) > 1 else None
        tools = mgr.list_tools(name)
        if not tools:
            hint = f" on '{name}'" if name else ""
            print_info(f"No tools available{hint}. Make sure the server is connected.")
            return
        from rich.table import Table
        from rich import box
        table = Table(title=f"MCP Tools{' – ' + name if name else ''}", title_justify="left", border_style="#888888", box=box.SIMPLE)
        table.add_column("Server", style="#888888")
        table.add_column("Tool", style="bold")
        table.add_column("Description", overflow="fold")
        for t in tools:
            desc = t.get("description", "")
            if len(desc) > 80:
                desc = desc[:80] + "…"
            table.add_row(t.get("server", "?"), t.get("name", "?"), desc)
        console.print(table)

    elif sub == "call":
        # /mcp call <server> <tool> [json_params]
        if len(sub_parts) < 3:
            print_warning("Usage: /mcp call <server> <tool> [json_params]")
            return
        srv_name = sub_parts[1]
        tool_name = sub_parts[2]
        params_str = sub_parts[3] if len(sub_parts) > 3 else "{}"
        try:
            import json as _json
            params = _json.loads(params_str)
        except Exception:
            print_error(f"Invalid JSON params: {params_str}")
            return
        try:
            result = mgr.call_tool(srv_name, tool_name, params)
            from rich.syntax import Syntax
            if isinstance(result, str):
                console.print(result)
            else:
                import json as _json2
                console.print(Syntax(_json2.dumps(result, indent=2), "json"))
            # Offer to send to AI
            try:
                console.print("\n[bold]Send result to AI?[/bold] [bold green]\\[y]es[/bold green]/[bold]\\[n]o[/bold]")
                if console.input("> ").strip().lower() == "y":
                    output_str = result if isinstance(result, str) else _json2.dumps(result, indent=2)
                    _run_chat(
                        message=f"Analyze this MCP tool result from {srv_name}/{tool_name}:",
                        session_name=state["session_name"],
                        domain_override=state.get("domain_override", ""),
                        model_override=state.get("model_override", ""),
                        no_compress=state["no_compress"],
                        no_think=state["no_think"],
                        no_research=state["no_research"],
                        no_memory=state["no_memory"],
                        quick=state["quick"],
                        _tool_output=f"[MCP {srv_name}/{tool_name}]\n{output_str}",
                    )
            except (EOFError, KeyboardInterrupt):
                pass
        except Exception as exc:
            print_error(f"MCP call failed: {exc}")

    elif sub == "reload":
        mgr.reload()
        print_success("MCP server definitions reloaded from config.")

    else:
        print_warning(f"Unknown /mcp sub-command: {sub}. Options: list connect disconnect tools call reload")


def _launch_shell(
    *,
    session_name: str,
    domain_override: str,
    model_override: str,
    no_compress: bool,
    no_think: bool,
    no_research: bool,
    no_memory: bool,
    quick: bool,
) -> None:
    config = load_config()

    # ── Session resolution ────────────────────────────────────────────────────
    if session_name:
        shell_session = session_name
    else:
        # Offer to resume the last used session
        last = load_last_session()
        if last and not quick:
            last_data = load_session(last)
            msgs = last_data.get("message_count", 0) if last_data else 0
            try:
                console.print(
                    rf"[#888888]Last session:[/] [bold]{last}[/bold] "
                    rf"[#888888]({msgs} messages)[/]  "
                    rf"[bold cyan]\[r]esume[/bold cyan]  "
                    rf"[bold cyan]\[n]ew[/bold cyan]"
                )
                choice = console.input("> ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                choice = "n"
            shell_session = last if choice in ("r", "") else _generate_shell_session_name()
        else:
            shell_session = _generate_shell_session_name()

    if not quick:
        _resolve_session(shell_session, "", config, domain_override, model_override)
    shell_domain = domain_override or detect_domain("", shell_session)
    shell_model = model_override or config.get("default_model", "deepseek-expert-r1-search")
    # Resolve sudo password: env var → persisted config → None
    _initial_sudo = _os.environ.get("DSEC_SUDO_PASS") or get_sudo_password() or None

    state: Dict[str, Any] = {
        "session_name": shell_session,
        "domain_override": domain_override,
        "model_override": model_override,
        "no_compress": no_compress,
        "no_think": no_think,
        "no_research": no_research,
        "no_memory": no_memory,
        "quick": quick,
        "auto_exec": True,   # /autoexec toggle
        "sudo_password": _initial_sudo,
    }

    _print_shell_banner(shell_session, shell_domain, shell_model, sudo_set=bool(_initial_sudo))

    # ── Build prompt_toolkit session (falls back to None if unavailable) ──────
    pt_session = build_prompt_session(state)
    if pt_session:
        print_info(
            "[bold]↑↓[/bold] history  [bold]←→[/bold] cursor  "
            "[bold]Tab[/bold] complete  [bold]Ctrl-R[/bold] search  "
            "[bold]Ctrl-C[/bold] cancel line  [bold]Ctrl-D[/bold] exit"
        )

    def _read_line() -> str:
        """Read one line – prompt_toolkit (with arrow keys) or Rich fallback."""
        p = format_prompt(state["session_name"])
        if pt_session:
            return pt_session.prompt(p).strip()
        return console.input(
            f"[#888888]{state['session_name']}[/] ❯ "
        ).strip()

    def _run_loop() -> None:
        while True:
            # ── prompt ────────────────────────────────────────────────────────
            raw = _read_line()

            if not raw:
                continue

            # ── !cmd shorthand ─────────────────────────────────────────────────
            if raw.startswith("!"):
                cmd = raw[1:].strip()
                if cmd:
                    _shell_run_command(cmd, state)
                continue

            # ── slash commands ──────────────────────────────────────────────────
            if _handle_shell_command(raw, state):
                continue

            # ── send to AI ──────────────────────────────────────────────────────
            try:
                _run_chat(
                    message=raw,
                    session_name=state["session_name"],
                    domain_override=state["domain_override"],
                    model_override=state["model_override"],
                    no_compress=state["no_compress"],
                    no_think=state["no_think"],
                    no_research=state["no_research"],
                    no_memory=state["no_memory"],
                    quick=state["quick"],
                    _auto_exec=state.get("auto_exec", False),
                )
            except KeyboardInterrupt:
                console.print()
                print_warning("Request cancelled.")

    try:
        _run_loop()
    except (KeyboardInterrupt, EOFError):
        console.print()
        print_info("Leaving DSEC shell.")
        save_last_session(state["session_name"])
        return


def _collect_paste_buffer(pt_session: Any, state: Dict[str, Any]) -> str:
    """
    Multi-line composer.  With prompt_toolkit we use its built-in
    multiline mode (Meta-Enter to submit); without it we fall back to
    line-by-line collection ending on a blank line.
    """
    console.print(
        "[bold blue]Paste mode[/bold blue] – enter or paste your text.\n"
        "[#888888]Blank line to send  |  /cancel to abort[/]"
    )

    lines: List[str] = []

    def _read_paste_line(n: int) -> str:
        prefix = f"[#888888]{n:>3}│[/] "
        if pt_session:
            from prompt_toolkit.formatted_text import HTML
            return pt_session.prompt(HTML(f"<session>{n:>3}│</session> ")).strip("\n")
        return console.input(prefix)

    i = 1
    while True:
        try:
            line = _read_paste_line(i)
        except (EOFError, KeyboardInterrupt):
            break
        if line.strip() == "/cancel":
            console.print("[#888888]Paste cancelled.[/]")
            return ""
        if line == "":
            break
        lines.append(line)
        i += 1

    text = "\n".join(lines).strip()
    if text:
        console.print(f"[#888888]Collected {len(lines)} lines ({len(text)} chars) – sending to AI…[/]")
    return text


def _run_chat(
    message: str,
    session_name: str,
    domain_override: str,
    model_override: str,
    no_compress: bool,
    no_think: bool,
    no_research: bool,
    no_memory: bool,
    quick: bool,
    _tool_output: str = "",   # pre-injected tool output (from /run or /mcp call)
    _auto_exec: bool = False, # auto-approve AI-requested commands
) -> None:
    config = load_config()
    stdin_content = _tool_output or _read_stdin_content()

    if not message and not stdin_content:
        print_error("No message provided. Use: dsec \"your message\" or pipe input.")
        return

    full_input = _combine_user_input(message, stdin_content)
    session_data = _resolve_session(session_name, full_input, config, domain_override, model_override)
    domain, model = _resolve_domain_and_model(
        session_data,
        full_input,
        session_name,
        domain_override,
        model_override,
        config,
    )

    full_input = _apply_no_think(full_input, no_think)
    final_input, compressed_stdin_content, compression_info = _compress_input(
        full_input,
        stdin_content,
        no_compress,
        config.get("compress_threshold", 500),
    )
    memory_context, memory_count = _load_memory_context(
        final_input,
        domain,
        enabled=not no_memory and not quick,
    )
    research_context, research_sources_used = _run_research_context(
        full_input,
        domain,
        config,
        enabled=not no_research and not quick,
    )

    conversation_id = session_data.get("conversation_id") if session_data else None
    turn = (session_data.get("message_count", 0) + 1) if session_data else 1
    final_prompt = _build_prompt(
        domain=domain,
        conversation_id=conversation_id,
        quick=quick,
        memory_context=memory_context,
        research_context=research_context,
        stdin_content=stdin_content,
        compressed_stdin_content=compressed_stdin_content,
        message=message,
        final_input=final_input,
    )

    generator = chat_stream(
        message=final_prompt,
        model=model,
        conversation_id=conversation_id,
        base_url=config.get("base_url", "http://localhost:8000"),
        token=get_next_token(),
    )

    thinking, response_content, new_conv_id = stream_response(
        generator=generator,
        session_name=session_name or "none",
        domain=domain,
        model=model,
        turn=turn,
        compression_info=compression_info,
        research_sources=research_sources_used,
        memory_count=memory_count,
        show_thinking=config.get("show_thinking", True) and not no_think,
    )

    if response_content is None:
        return

    _persist_successful_turn(
        session_name="" if quick else session_name,
        full_input=full_input,
        response_content=response_content,
        thinking=thinking,
        compression_info=compression_info,
        new_conv_id=new_conv_id,
    )
    _auto_store_memories(
        response_content,
        session_name,
        domain,
        enabled=not quick,
    )

    # ── agentic execution loop ─────────────────────────────────────────────────
    if response_content and not quick and _extract_tool_calls(response_content):
        _run_agentic_loop(
            response_content,
            session_name=session_name,
            domain=domain,
            model=model,
            conversation_id=new_conv_id,
            config=config,
            turn=turn,
            no_think=no_think,
            no_memory=no_memory,
            auto_exec=_auto_exec,
        )


# ════════════════════════════════════════════════════════════════════════════
# CLI Definition
# ════════════════════════════════════════════════════════════════════════════

CONTEXT_SETTINGS = dict(
    help_option_names=["-h", "--help"],
    max_content_width=100,
    allow_extra_args=True,
    ignore_unknown_options=True,
)


class ChatGroup(click.Group):
    """Let free-form chat messages coexist with subcommands."""

    def invoke(self, ctx):
        # ctx.protected_args holds the first token Click tentatively reserved
        # as a subcommand name.  If it doesn't match a real subcommand, treat
        # the whole remaining arg list as a free-form chat message.
        # Note: protected_args became read-only in Click 9; we guard for both.
        protected = list(getattr(ctx, "protected_args", []))
        if protected and protected[0] not in self.commands:
            ctx.args = protected + list(ctx.args)
            try:
                ctx.protected_args = []  # Click 8
            except AttributeError:
                pass  # Click 9 – protected_args is already folded into args
            ctx.invoked_subcommand = None
            return click.Command.invoke(self, ctx)
        return super().invoke(ctx)


@click.group(invoke_without_command=True, context_settings=CONTEXT_SETTINGS, cls=ChatGroup)
@click.pass_context
@click.option("--session", "-s", default=None, metavar="NAME", help="Session name to use or create.")
@click.option("--new-session", "-n", "new_session", default=None, metavar="NAME",
              help="Create a new session with this name and start chatting.")
@click.option("--domain", "-d", default=None,
              type=click.Choice(["htb", "bugbounty", "ctf", "research"]),
              help="Override domain detection.")
@click.option("--model", "-m", default=None, metavar="MODEL",
              help="Override model (for example: deepseek-expert-r1-search).")
@click.option("--no-compress", "no_compress", is_flag=True, help="Skip context compression.")
@click.option("--no-think", "no_think", is_flag=True,
              help="Request a concise reply without extended reasoning.")
@click.option("--no-research", "no_research", is_flag=True, help="Skip the auto-research pipeline.")
@click.option("--no-memory", "no_memory", is_flag=True, help="Skip memory context injection.")
@click.option("--quick", "-q", is_flag=True,
              help="Quick one-shot mode: skip memory, research, and session saving.")
@click.option("--search", "use_search", is_flag=True, help="Use the search-capable model variant.")
def cli(
    ctx,
    session,
    new_session,
    domain,
    model,
    no_compress,
    no_think,
    no_research,
    no_memory,
    quick,
    use_search,
):
    """
    \b
    dsec – DeepSeek Security CLI
    Agentic assistant for HTB, Bug Bounty, CTF, and Security Research.

    \b
    Examples:
      dsec "starting htb machine at 10.10.11.23"
      dsec --session htb-permx "what's the next step?"
      dsec --new-session bb-target --domain bugbounty "recon on target.com"
      nmap -sV 10.10.11.23 | dsec --session htb-permx "analyze"
      dsec -q "what port does SMB use?"
      dsec sessions
      dsec memory --list
    """
    init_config()

    if ctx.invoked_subcommand is not None:
        return

    message = " ".join(ctx.args).strip()
    effective_session = new_session or session

    if use_search:
        cfg = load_config()
        base_model = model or cfg.get("default_model", "deepseek-expert-r1-search")
        if not base_model.endswith("-search"):
            model = base_model + "-search"

    if not message and sys.stdin.isatty():
        _launch_shell(
            session_name=effective_session or "",
            domain_override=domain or "",
            model_override=model or "",
            no_compress=no_compress,
            no_think=no_think,
            no_research=no_research,
            no_memory=no_memory,
            quick=quick,
        )
        return

    _run_chat(
        message=message,
        session_name=effective_session or "",
        domain_override=domain or "",
        model_override=model or "",
        no_compress=no_compress,
        no_think=no_think,
        no_research=no_research,
        no_memory=no_memory,
        quick=quick,
    )


# ────────────────────────────────────────────────────────────────────────────
# sessions subcommand
# ────────────────────────────────────────────────────────────────────────────


@cli.command("sessions")
@click.option("--show", "show_name", default=None, metavar="NAME", help="Show detailed view of a session.")
@click.option("--delete", "delete_name", default=None, metavar="NAME", help="Delete a session.")
@click.option("--rename", nargs=2, metavar="OLD NEW", help="Rename a session.")
def sessions_cmd(show_name, delete_name, rename):
    """List and manage sessions."""
    if show_name:
        data = load_session(show_name)
        if not data:
            print_error(f"Session not found: {show_name}")
            return
        print_session_detail(data)
        return

    if delete_name:
        if delete_session(delete_name):
            print_success(f"Deleted session: {delete_name}")
        else:
            print_error(f"Session not found: {delete_name}")
        return

    if rename:
        old, new = rename
        if rename_session(old, new):
            print_success(f"Renamed: {old} → {new}")
        else:
            print_error("Could not rename (source missing or destination exists).")
        return

    print_sessions_table(list_sessions())


# ────────────────────────────────────────────────────────────────────────────
# note subcommand
# ────────────────────────────────────────────────────────────────────────────


@cli.command("note")
@click.argument("content", required=True)
@click.option("--session", "-s", "session_name", default=None, metavar="NAME",
              help="Target session (defaults to the most recent).")
@click.option("--type", "note_type",
              type=click.Choice(["finding", "credential", "flag", "misc"]),
              default="misc", show_default=True,
              help="Note type.")
def note_cmd(content, session_name, note_type):
    """Add a note to a session."""
    effective = session_name or get_current_session_name()
    if not effective:
        print_error("No session found. Specify with --session NAME.")
        return

    if not load_session(effective):
        print_error(f"Session not found: {effective}. Create it first.")
        return

    add_note(effective, content, note_type)
    print_success(f"[{note_type.upper()}] note added to session: {effective}")


# ────────────────────────────────────────────────────────────────────────────
# memory subcommand
# ────────────────────────────────────────────────────────────────────────────


@cli.command("memory")
@click.option("--list", "do_list", is_flag=True, help="List all memories.")
@click.option("--domain", default=None,
              type=click.Choice(["htb", "bugbounty", "ctf", "research"]),
              help="Filter by domain.")
@click.option("--session", "-s", "filter_session", default=None, metavar="NAME",
              help="Filter by session name.")
@click.option("--search", "search_query", default=None, metavar="QUERY", help="Semantic search memories.")
@click.option("--verify", "verify_id", default=None, metavar="ID",
              help="Upgrade memory confidence to 'verified'.")
@click.option("--delete", "delete_id", default=None, metavar="ID", help="Delete a memory entry.")
@click.option("--show", "show_id", default=None, metavar="ID", help="Show the full memory entry.")
@click.option("--add", "add_content", default=None, metavar="CONTENT", help="Manually add a memory.")
@click.option("--type", "mem_type",
              type=click.Choice(["finding", "technique", "credential", "tool_usage", "pattern"]),
              default="finding", show_default=True,
              help="Memory type (used with --add).")
@click.option("--tags", default=None, metavar="TAG1,TAG2",
              help="Comma-separated tags (used with --add).")
def memory_cmd(
    do_list,
    domain,
    filter_session,
    search_query,
    verify_id,
    delete_id,
    show_id,
    add_content,
    mem_type,
    tags,
):
    """Manage cross-session semantic memory."""
    if not memory_available():
        print_warning("ChromaDB not available. Install with: pip install chromadb")
        return

    if show_id:
        mem = get_memory(show_id)
        if not mem:
            print_error(f"Memory not found: {show_id}")
            return
        print_memory_detail(mem)
        return

    if verify_id:
        if update_confidence(verify_id, "verified"):
            print_success(f"Memory {verify_id[:10]}… upgraded to [green]verified[/green]")
        else:
            print_error(f"Memory not found: {verify_id}")
        return

    if delete_id:
        if delete_memory(delete_id):
            print_success(f"Deleted memory: {delete_id[:10]}…")
        else:
            print_error(f"Memory not found: {delete_id}")
        return

    if search_query:
        results = search_memory(search_query, domain=domain)
        if results:
            print_memory_list(results)
        else:
            print_info("No memories found above the similarity threshold.")
        return

    if add_content:
        tag_list = [tag.strip() for tag in (tags or "").split(",") if tag.strip()]
        mem_id = store_memory(
            content=add_content,
            metadata={
                "session": filter_session or "manual",
                "domain": domain or "htb",
                "type": mem_type,
                "confidence": "verified",
                "tags": tag_list,
                "source": "manual",
            },
        )
        if mem_id:
            print_success(f"Memory stored: {mem_id[:12]}…")
        else:
            print_error("Failed to store memory (ChromaDB error).")
        return

    mems = list_memories(domain=domain, session=filter_session)
    print_memory_list(mems)
    if mems:
        print_info(
            f"Total: {len(mems)} memories | threshold: {load_config().get('memory_similarity_threshold', 0.82)}"
        )


# ────────────────────────────────────────────────────────────────────────────
# token subcommand
# ────────────────────────────────────────────────────────────────────────────


@cli.command("token")
@click.option("--add", "add_str", default=None, metavar="TOKEN1,TOKEN2,...",
              help="Add one or more comma-separated tokens.")
@click.option("--check", "do_check", is_flag=True, help="Check token status.")
@click.option("--list", "do_list", is_flag=True, help="List stored tokens (masked).")
def token_cmd(add_str, do_check, do_list):
    """Manage API tokens for deepseek-free-api."""
    if add_str:
        n = add_tokens(add_str)
        print_success(f"Added {n} new token(s).")
        return

    if do_list:
        masked = list_tokens()
        if masked:
            for index, token in enumerate(masked):
                console.print(f"  [{index}] {token}")
        else:
            print_info("No tokens stored. Add with: dsec token --add TOKEN")
        return

    info = check_tokens()
    console.print("[bold]Token Status[/bold]")
    console.print(f"  Count:     {info['count']}")
    console.print(f"  Next idx:  {info['current_index']}")
    console.print(f"  Base URL:  {info['base_url']}")
    if info["count"] == 0:
        print_warning(
            "No tokens configured.\n"
            "Get token: chat.deepseek.com → F12 → Application → LocalStorage → userToken\n"
            "Then: dsec token --add YOUR_TOKEN"
        )


# ────────────────────────────────────────────────────────────────────────────
# config subcommand
# ────────────────────────────────────────────────────────────────────────────


@cli.command("config")
@click.option("--set", "set_kv", nargs=2, metavar="KEY VALUE", help="Set a config value.")
def config_cmd(set_kv):
    """Show or update configuration."""
    if set_kv:
        key, value = set_kv
        try:
            updated = save_config(key, value)
        except ConfigError as exc:
            print_error(str(exc))
            return
        print_success(f"Set [bold]{key}[/bold] = {updated.get(key)!r}")
        return

    cfg = load_config()
    console.print("[bold blue]DSEC Configuration[/bold blue]")
    console.print(f"  Config file: [#888888]{CONFIG_FILE}[/]")
    console.print()
    for key, value in sorted(cfg.items()):
        if key == "tokens":
            console.print(f"  [bold]{key}[/bold]: {len(value)} token(s) stored")
        else:
            console.print(f"  [bold]{key}[/bold]: {value!r}")


# ────────────────────────────────────────────────────────────────────────────
# tags subcommand (convenience)
# ────────────────────────────────────────────────────────────────────────────


@cli.command("tags")
@click.argument("tag_list", nargs=-1, required=True)
@click.option("--session", "-s", "session_name", default=None)
def tags_cmd(tag_list, session_name):
    """Add tags to a session."""
    effective = session_name or get_current_session_name()
    if not effective:
        print_error("No session found. Specify with --session NAME.")
        return
    if add_tags(effective, list(tag_list)):
        print_success(f"Tags added to {effective}: {', '.join(tag_list)}")
    else:
        print_error(f"Session not found: {effective}")


@cli.command("shell")
@click.option("--session", "-s", default=None, metavar="NAME", help="Session name to use or create.")
@click.option("--new-session", "-n", "new_session", default=None, metavar="NAME",
              help="Create a new shell session with this name.")
@click.option("--domain", "-d", default=None,
              type=click.Choice(["htb", "bugbounty", "ctf", "research"]),
              help="Override domain detection.")
@click.option("--model", "-m", default=None, metavar="MODEL", help="Override model.")
@click.option("--no-compress", "no_compress", is_flag=True, help="Skip context compression.")
@click.option("--no-think", "no_think", is_flag=True, help="Disable extended reasoning display.")
@click.option("--no-research", "no_research", is_flag=True, help="Skip the auto-research pipeline.")
@click.option("--no-memory", "no_memory", is_flag=True, help="Skip memory context injection.")
@click.option("--quick", "-q", is_flag=True, help="Skip memory, research, and session saving.")
@click.option("--search", "use_search", is_flag=True, help="Use the search-capable model variant.")
def shell_cmd(
    session,
    new_session,
    domain,
    model,
    no_compress,
    no_think,
    no_research,
    no_memory,
    quick,
    use_search,
):
    """Start an interactive DSEC shell."""
    init_config()
    effective_session = new_session or session

    if use_search:
        cfg = load_config()
        base_model = model or cfg.get("default_model", "deepseek-expert-r1-search")
        if not base_model.endswith("-search"):
            model = base_model + "-search"

    _launch_shell(
        session_name=effective_session or "",
        domain_override=domain or "",
        model_override=model or "",
        no_compress=no_compress,
        no_think=no_think,
        no_research=no_research,
        no_memory=no_memory,
        quick=quick,
    )


if __name__ == "__main__":
    cli()
