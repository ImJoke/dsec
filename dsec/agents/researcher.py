"""
DSEC Research worker.

Spawned by the brain via the `research` orchestration tool. Performs
KB / CVE / web lookups using the existing dsec.researcher fetchers (NVD,
ExploitDB, GitHub advisories) plus the role="research" filtered registry
(notes_*, gtfobins_*, graph_memory_search, dsec_archival_search).

Returns a textual digest the brain can fold back into its planning loop.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Optional

from dsec.client import chat_stream
from dsec.config import get_next_token, load_config
from dsec.core.registry import build_tools_system_prompt_for_role, call_tool, register

_MAX_ITERATIONS = 5
_OUTPUT_TRUNCATE = 4000


def _build_system_prompt(parent_context: Dict[str, Any]) -> str:
    tools_section = build_tools_system_prompt_for_role("research")
    cumulative = parent_context.get("cumulative_summary") or ""
    domain = parent_context.get("domain", "general")

    parts = [
        "You are the RESEARCH sub-agent.",
        "You receive a research question from the brain. You may consult notes, "
        "GTFOBins, the knowledge graph, archival memory, and live_research (CVE/exploit "
        "feeds). You do NOT execute commands — that's the executor's job.",
        "",
        "RULES:",
        "  - Emit <tool_call>{...}</tool_call> blocks for each lookup.",
        "  - Synthesize findings into bullet points with source citations.",
        "  - If the question is answered, stop calling tools and write the digest.",
        "  - Stop after at most 5 lookups even if uncertain — return what you have.",
        f"  - Domain: {domain}.",
        "",
        tools_section,
    ]
    if cumulative:
        parts.append("")
        parts.append("[BRAIN CONTEXT — read-only]")
        parts.append(cumulative[:3000])
        parts.append("[END BRAIN CONTEXT]")
    return "\n".join(parts)


def _truncate(text: str, limit: int = _OUTPUT_TRUNCATE) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n…[truncated {len(text) - limit} bytes]"


def _dispatch(call: Dict[str, Any]) -> str:
    name = call.get("name", "")
    args = call.get("arguments") or {}
    if not isinstance(args, dict):
        args = {}
    if name == "live_research":
        return _live_research(
            query=str(args.get("query", "")),
            sources=str(args.get("sources", "")),
        )
    return _truncate(str(call_tool(name, args, caller_role="research")))


@register(
    "live_research",
    (
        "Live external lookup against NVD / ExploitDB / GitHub advisories for CVEs, "
        "software versions, or security topics. Returns a formatted research context. "
        "Use sparingly — each call hits public APIs."
    ),
    roles=("research",),
)
def _live_research(query: str, sources: str = "") -> str:
    """Wrap dsec.researcher fetchers as a synchronous tool call."""
    if not query.strip():
        return "[error: live_research needs 'query' argument]"
    try:
        from dsec.researcher import format_research_context, run_research
    except Exception as exc:
        return f"[live_research import failed: {exc}]"

    src_list: Optional[List[str]] = None
    if sources.strip():
        src_list = [s.strip().lower() for s in sources.split(",") if s.strip()]

    queries: List[Dict[str, Any]] = [{
        "query": query,
        "type": "manual",
        "sources": src_list or ["nvd", "exploitdb", "github_advisories"],
    }]

    try:
        loop = asyncio.new_event_loop()
        try:
            results = loop.run_until_complete(run_research(queries, max_results=5))
        finally:
            loop.close()
    except Exception as exc:
        return f"[live_research execution failed: {exc}]"

    formatted = format_research_context(results) if results else ""
    return _truncate(formatted) if formatted else f"[live_research] no results for '{query}'"


def run_research_agent(
    query: str,
    *,
    parent_context: Optional[Dict[str, Any]] = None,
    max_iterations: int = _MAX_ITERATIONS,
) -> str:
    """Run the research mini-loop and return a digest for the brain."""
    from dsec.cli import _extract_tool_calls
    from dsec.llm_utils import llm_summarize

    parent_context = parent_context or {}
    system_prompt = _build_system_prompt(parent_context)

    cfg = load_config()
    base_url = cfg.get("base_url", "http://localhost:8000")
    model = cfg.get("default_model", "deepseek-chat")

    history: List[Dict[str, str]] = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": query},
    ]

    last_assistant_text = ""
    iterations_used = 0
    started = time.time()

    for iteration in range(1, max_iterations + 1):
        iterations_used = iteration
        content_parts: List[str] = []
        had_error = False

        for chunk in chat_stream(
            message=query if iteration == 1 else "Continue researching or summarise findings.",
            model=model,
            conversation_id=None,
            base_url=base_url,
            token=get_next_token(),
            history=history,
            role="research",
        ):
            ctype = chunk.get("type")
            if ctype == "content":
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
            break

        calls = _extract_tool_calls(assistant_text) if assistant_text else []
        if not calls:
            break

        tool_blocks: List[str] = []
        for call in calls:
            try:
                result_text = _dispatch(call)
            except Exception as exc:
                result_text = f"[tool dispatch crashed: {type(exc).__name__}: {exc}]"
            tool_blocks.append(
                f"<tool_response>{{\"name\":\"{call.get('name','?')}\",\"result\":{result_text!r}}}</tool_response>"
            )
        history.append({"role": "user", "content": "\n".join(tool_blocks)})

    elapsed = time.time() - started

    if last_assistant_text and len(last_assistant_text) < 1500:
        digest_body = last_assistant_text
    else:
        try:
            digest_body = llm_summarize(
                last_assistant_text or "(no research output)",
                focus="research digest: facts, sources, key takeaways",
            )
        except Exception:
            digest_body = (last_assistant_text or "")[:1500]

    return f"{digest_body}\n[RESEARCH_META] iterations={iterations_used} elapsed={elapsed:.1f}s"
