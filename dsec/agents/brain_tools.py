"""
Brain orchestration tools.

These are the only tools the brain (when running in multi-agent mode) calls
to delegate work. They spawn worker LLMs with their own role-filtered tool
registries and return digests for the brain to read.

Imported once for side-effects (registry registration). The CLI startup
chain in cli.py imports `dsec.agents.brain_tools` after the other tool
modules so the registry is populated before _run_agentic_loop reads it.
"""
from __future__ import annotations

from typing import Optional

from dsec.agents import get_brain_context
from dsec.core.registry import register

# Import researcher for its @register("live_research") side-effect.
import dsec.agents.researcher  # noqa: F401


@register(
    "executor",
    (
        "Delegate execution work to the executor sub-agent. "
        "Provide a CONCRETE plan in 1-3 sentences (e.g. 'run nmap -sV against 10.10.11.5 "
        "and report open ports + versions'). The executor returns a textual digest "
        "containing commands run, output, errors, and a [STUCK_SIGNALS] tail line."
    ),
    roles=("brain",),
)
def executor(plan: str, tool_whitelist: Optional[str] = None) -> str:
    from dsec.agents.executor import run_executor

    whitelist = None
    if tool_whitelist:
        whitelist = [t.strip() for t in tool_whitelist.split(",") if t.strip()]

    parent_context = get_brain_context()
    return run_executor(plan, tool_whitelist=whitelist, parent_context=parent_context)


@register(
    "research",
    (
        "Delegate research / KB lookup to the research sub-agent. "
        "Provide ONE focused question (e.g. 'what's the impacket syntax for "
        "Kerberos delegation abuse?' or 'find recent CVEs for Joomla 4.2'). "
        "The research sub-agent uses notes, GTFOBins, the knowledge graph, "
        "and live CVE feeds, then returns a digest."
    ),
    roles=("brain",),
)
def research(query: str) -> str:
    from dsec.agents.researcher import run_research_agent

    parent_context = get_brain_context()
    return run_research_agent(query, parent_context=parent_context)
