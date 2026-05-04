"""
DSEC Executor worker.

Spawned by the brain via the `executor` orchestration tool. Runs a small
agentic loop with the `executor` role: bash, file writes, payload generation,
PTY shells. Returns a digest the brain can fold back into its planning loop.

Loop structure:
  1. Build executor system prompt (role-filtered tool registry)
  2. Call chat(role="executor") with the plan + parent context
  3. Parse <tool_call> blocks
  4. Dispatch:
       - bash → CommandRunner.run() directly (auto_exec, no approval prompt)
       - native tools → registry.call_tool(name, args, caller_role="executor")
  5. Append tool responses to history, loop until: no tool calls, max iters,
     or hard timeout.
  6. Final assistant content is summarised via llm_summarize and returned
     with a structured `[STUCK_SIGNALS] ...` tail line for brain consumption.
"""
from __future__ import annotations

import re as _re
import time
from typing import Any, Dict, List, Optional

from dsec.client import chat_stream
from dsec.config import get_next_token, get_sudo_password, load_config
from dsec.core.registry import build_tools_system_prompt_for_role, call_tool
from dsec.executor import CommandRunner
from dsec.formatter import print_info, print_warning

_MAX_ITERATIONS = 10
_PER_BASH_TIMEOUT = 300
_OUTPUT_TRUNCATE = 8000


def _build_system_prompt(parent_context: Dict[str, Any]) -> str:
    """Compose the executor's system prompt — short and action-oriented."""
    tools_section = build_tools_system_prompt_for_role("executor")
    cumulative = parent_context.get("cumulative_summary") or ""
    domain = parent_context.get("domain", "general")
    session = parent_context.get("session_name", "none")

    parts = [
        "You are the EXECUTOR sub-agent.",
        "You receive a concrete plan from the brain and execute it using bash, "
        "file writes, payload generation, and PTY shells.",
        "Do NOT plan high-level strategy — just execute the brain's instructions and "
        "report back what happened.",
        "",
        "RULES:",
        "  - Emit <tool_call>{...}</tool_call> blocks for every action.",
        "  - Prefer one tool call at a time; re-evaluate after each result.",
        "  - For long-running listeners or interactive shells, use the `background` tool.",
        "  - When the plan is done (or you hit a hard error you cannot resolve), "
        "    stop emitting tool calls and write a concise summary of what you did.",
        f"  - Domain: {domain}; session: {session}.",
        "",
        tools_section,
    ]
    if cumulative:
        parts.append("")
        parts.append("[BRAIN CONTEXT — read-only]")
        parts.append(cumulative[:4000])
        parts.append("[END BRAIN CONTEXT]")
    return "\n".join(parts)


def _truncate(text: str, limit: int = _OUTPUT_TRUNCATE) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n…[truncated {len(text) - limit} bytes]"


def _run_bash(command: str, sudo_password: Optional[str]) -> Dict[str, Any]:
    runner = CommandRunner()
    out_chunks: List[str] = []
    err_chunks: List[str] = []
    result = runner.run(
        command,
        on_stdout=lambda line: out_chunks.append(line),
        on_stderr=lambda line: err_chunks.append(line),
        timeout=_PER_BASH_TIMEOUT,
        sudo_password=sudo_password,
    )
    combined = (result.stdout or "").strip()
    if result.stderr:
        combined = (combined + "\n" + result.stderr).strip() if combined else result.stderr
    return {
        "exit_code": result.returncode,
        "interrupted": getattr(result, "interrupted", False),
        "output": _truncate(combined or "(no output)"),
    }


def _dispatch(call: Dict[str, Any], sudo_password: Optional[str]) -> str:
    name = call.get("name", "")
    args = call.get("arguments") or {}
    if not isinstance(args, dict):
        args = {}
    if name == "bash":
        cmd = args.get("command") or args.get("cmd") or ""
        if not cmd:
            return "[error: bash tool needs 'command' argument]"
        result = _run_bash(cmd, sudo_password)
        return (
            f"[bash exit={result['exit_code']}"
            f"{' interrupted' if result['interrupted'] else ''}]\n"
            f"{result['output']}"
        )
    return str(call_tool(name, args, caller_role="executor"))


def run_executor(
    plan: str,
    *,
    tool_whitelist: Optional[List[str]] = None,
    parent_context: Optional[Dict[str, Any]] = None,
    sudo_password: Optional[str] = None,
    max_iterations: int = _MAX_ITERATIONS,
) -> str:
    """Run the executor mini-loop and return a digest for the brain."""
    from dsec.cli import _extract_tool_calls  # late import to avoid circular dep
    from dsec.llm_utils import llm_summarize

    parent_context = parent_context or {}
    if sudo_password is None:
        try:
            sudo_password = get_sudo_password() or None
        except Exception:
            sudo_password = None

    system_prompt = _build_system_prompt(parent_context)
    cfg = load_config()
    base_url = cfg.get("base_url", "http://localhost:8000")
    model = cfg.get("default_model", "deepseek-chat")

    history: List[Dict[str, str]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": plan},
    ]

    last_assistant_text = ""
    stuck_signals: List[str] = []
    iterations_used = 0

    started = time.time()

    for iteration in range(1, max_iterations + 1):
        iterations_used = iteration
        thinking_parts: List[str] = []
        content_parts: List[str] = []
        had_error = False

        for chunk in chat_stream(
            message=plan if iteration == 1 else "Continue executing the plan or stop and summarise.",
            model=model,
            conversation_id=None,
            base_url=base_url,
            token=get_next_token(),
            history=history,
            role="executor",
        ):
            ctype = chunk.get("type")
            if ctype == "thinking":
                thinking_parts.append(chunk["text"])
            elif ctype == "content":
                content_parts.append(chunk["text"])
            elif ctype == "error":
                had_error = True
                content_parts.append(f"[stream error: {chunk.get('text', '')}]")
                break
            elif ctype == "done":
                break

        assistant_text = "".join(content_parts).strip()
        last_assistant_text = assistant_text or last_assistant_text
        history.append({"role": "assistant", "content": assistant_text})

        if had_error and not assistant_text:
            stuck_signals.append("stream_error")
            break

        calls = _extract_tool_calls(assistant_text) if assistant_text else []
        if tool_whitelist:
            calls = [c for c in calls if c.get("name") in tool_whitelist]

        if not calls:
            break  # brain's plan is complete (or executor gave up)

        tool_blocks: List[str] = []
        for call in calls:
            try:
                result_text = _dispatch(call, sudo_password)
            except Exception as exc:
                result_text = f"[tool dispatch crashed: {type(exc).__name__}: {exc}]"
                stuck_signals.append(f"crash:{call.get('name','?')}")
            tool_blocks.append(
                f"<tool_response>{{\"name\":\"{call.get('name','?')}\",\"result\":{result_text!r}}}</tool_response>"
            )
            # Lightweight stuck-signal detection
            lowered = (result_text or "").lower()
            if "exit=" in lowered and "exit=0" not in lowered and _re.search(r'\bexit=1\b', lowered):
                stuck_signals.append(f"nonzero_exit:{call.get('name','?')}")
            if "timed out" in lowered or "cancelled after" in lowered:
                stuck_signals.append(f"timeout:{call.get('name','?')}")

        history.append({"role": "user", "content": "\n".join(tool_blocks)})

    elapsed = time.time() - started

    # Build digest. Use the assistant's last summary if it produced one;
    # otherwise summarise via llm.
    if last_assistant_text and len(last_assistant_text) < 1500:
        digest_body = last_assistant_text
    else:
        try:
            digest_body = llm_summarize(
                last_assistant_text or "(no assistant output)",
                focus="executor digest: commands run, outputs, errors, current state",
            )
        except Exception:
            digest_body = (last_assistant_text or "")[:1500]

    tail = (
        f"\n[STUCK_SIGNALS] iterations={iterations_used} "
        f"elapsed={elapsed:.1f}s "
        f"signals={','.join(stuck_signals) if stuck_signals else 'none'}"
    )
    return digest_body + tail
