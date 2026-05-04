"""
DSEC sub-agent workers.

Brain (the main loop in cli._run_agentic_loop) delegates to two workers:

  * executor — runs bash and writes/edits files. See agents/executor.py.
  * researcher — KB / CVE / live web lookups. See agents/researcher.py.

Workers spawn their own LLM call (with role="executor"/"research"), use a
filtered tool registry, and return a textual digest. They cannot mutate
brain state directly; everything flows back through the digest.
"""
import contextvars
from typing import Any, Dict, Optional

# Per-conversation brain context handed down to workers (cumulative_summary,
# recent turns, domain, session_name). Set at the top of each brain
# iteration in cli.py and read by worker code without threading args.
brain_context_var: contextvars.ContextVar[Optional[Dict[str, Any]]] = contextvars.ContextVar(
    "dsec_brain_context",
    default=None,
)


def get_brain_context() -> Dict[str, Any]:
    """Return the current brain context dict, or an empty dict if unset."""
    ctx = brain_context_var.get()
    return ctx if isinstance(ctx, dict) else {}
