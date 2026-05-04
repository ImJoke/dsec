"""
DSEC Memory Tools – Agentic Memory Management (Letta/MemGPT style)

Provides explicit tool calls that the LLM agent can use to consciously
manage its own memory: core memory blocks (persona/human/project) and
the hybrid vector+graph knowledge store.
"""
import json
import os
from typing import Dict, Any, List, Optional

from dsec.core.registry import register
from dsec.memory import (
    store_memory,
    search_memory,
    graph_add_node,
    graph_add_edge,
    graph_query_entity,
    graph_query_path,
    graph_forget_node,
    graph_stats,
)

# ═══════════════════════════════════════════════════════════════════════════
# Core Memory (Letta-style) – explicit agent-managed JSON notepad
# ═══════════════════════════════════════════════════════════════════════════

CORE_MEMORY_FILE = os.path.expanduser("~/.dsec/core_memory.json")


def load_core_memory() -> Dict[str, Any]:
    if not os.path.exists(CORE_MEMORY_FILE):
        return {
            "persona": "I am an elite agentic security AI.",
            "human": "The user.",
            "project": "",
            "scratchpad": "",
        }
    try:
        with open(CORE_MEMORY_FILE, "r") as f:
            data = json.load(f)
            # Ensure all blocks exist
            data.setdefault("persona", "")
            data.setdefault("human", "")
            data.setdefault("project", "")
            data.setdefault("scratchpad", "")
            return data
    except Exception:
        return {"persona": "", "human": "", "project": "", "scratchpad": ""}


def save_core_memory(mem: Dict[str, Any]) -> bool:
    try:
        os.makedirs(os.path.dirname(CORE_MEMORY_FILE), exist_ok=True)
        with open(CORE_MEMORY_FILE, "w") as f:
            json.dump(mem, f, indent=2)
        return True
    except (OSError, PermissionError) as exc:
        import sys
        print(f"Warning: Failed to save core memory: {exc}", file=sys.stderr)
        return False


def format_core_memory_context() -> str:
    """Format core memory for injection into the system prompt."""
    mem = load_core_memory()
    lines = ["[CORE MEMORY – Agent Self-Knowledge]"]
    for block, content in mem.items():
        if content and content.strip():
            lines.append(f"  [{block.upper()}]: {content.strip()}")
    lines.append("[END CORE MEMORY]")
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════════════
# Registered Tools
# ═══════════════════════════════════════════════════════════════════════════

_VALID_BLOCKS = ["persona", "human", "project", "scratchpad"]


_MAX_BLOCK_SIZE = 8000

def _scan_content(content: str) -> str:
    """Security Injection Protection for memory blocks."""
    import re
    import unicodedata
    # Normalize unicode to strip zero-width chars and confusables
    normalized = unicodedata.normalize("NFKD", content)
    cl = re.sub(r"[\s​‌‍﻿]+", " ", normalized).lower().strip()
    forbidden = [
        "ignore all previous instructions",
        "ignore previous instructions",
        "system prompt",
        "you are now a",
        "forget all rules",
        "disregard previous",
        "bypass rules",
        "override instructions",
        "new system prompt",
        "act as if",
        "pretend you are",
    ]
    for f in forbidden:
        if f in cl:
            return f"[SECURITY_BLOCK] Rejected memory write: detected potential prompt injection pattern"
    return ""


@register("core_memory_append", "Appends text to a core memory block (persona, human, project, scratchpad).", roles=("brain",))
def core_memory_append(block: str, content: str) -> str:
    if block not in _VALID_BLOCKS:
        return f"Error: block must be one of {_VALID_BLOCKS}"
    err = _scan_content(content)
    if err: return err
    
    mem = load_core_memory()
    new_val = (mem.get(block, "") + "\n" + content).strip()
    if len(new_val) > _MAX_BLOCK_SIZE:
        return f"Error: appending would exceed {_MAX_BLOCK_SIZE} char limit for block '{block}' (current: {len(mem.get(block, ''))}, adding: {len(content)}). Use core_memory_replace to trim first."
    mem[block] = new_val
    save_core_memory(mem)
    return f"Appended to core memory block '{block}'. Current length: {len(mem[block])} chars."


@register("core_memory_replace", "Replaces the entire content of a core memory block.", roles=("brain",))
def core_memory_replace(block: str, new_content: str) -> str:
    if block not in _VALID_BLOCKS:
        return f"Error: block must be one of {_VALID_BLOCKS}"
    err = _scan_content(new_content)
    if err: return err
        
    if len(new_content) > _MAX_BLOCK_SIZE:
        return f"Error: content exceeds {_MAX_BLOCK_SIZE} char limit ({len(new_content)} chars). Trim before writing."
    mem = load_core_memory()
    old_len = len(mem.get(block, ""))
    mem[block] = new_content
    save_core_memory(mem)
    return f"Replaced core memory block '{block}' ({old_len} → {len(new_content)} chars)."


@register("core_memory_read", "Reads the current content of a core memory block.")
def core_memory_read(block: str) -> str:
    if block not in _VALID_BLOCKS:
        return f"Error: block must be one of {_VALID_BLOCKS}"
    mem = load_core_memory()
    content = mem.get(block, "")
    if not content:
        return f"Core memory block '{block}' is empty."
    return f"[{block.upper()}]:\n{content}"


# ── Graph Memory ──────────────────────────────────────────────────────────

@register("graph_memory_insert", "Inserts a relationship (Entity1 -> Relation -> Entity2) into the knowledge graph.", roles=("brain",))
def graph_memory_insert(source_entity: str, relation: str, target_entity: str) -> str:
    err = _scan_content(source_entity + " " + relation + " " + target_entity)
    if err: return err
    
    # Ensure nodes exist with auto-detected types
    graph_add_node(source_entity)
    graph_add_node(target_entity)
    ok = graph_add_edge(source_entity, relation, target_entity, confidence="verified")
    if ok:
        stats = graph_stats()
        return f"Inserted graph edge: {source_entity} → [{relation}] → {target_entity} (graph: {stats['nodes']} nodes, {stats['edges']} edges)"
    return "Failed to insert graph edge."


@register("graph_memory_search", "Searches the hybrid memory for entities or relationships.", roles=("brain", "research"))
def graph_memory_search(query: str) -> str:
    # First try graph entity lookup
    entity_results = graph_query_entity(query)
    lines = []

    if entity_results["node"]:
        node = entity_results["node"]
        lines.append(f"Entity: {node['entity']} (type: {node['type']})")
        if node.get("properties"):
            lines.append(f"  Properties: {json.dumps(node['properties'])}")
        for e in entity_results["outgoing"][:5]:
            lines.append(f"  → [{e['relation']}] → {e['target']}")
        for e in entity_results["incoming"][:5]:
            lines.append(f"  ← [{e['relation']}] ← {e['source']}")

    # Also do vector search
    results = search_memory(query, limit=5)
    if results:
        lines.append("\nVector search results:")
        for r in results:
            lines.append(f"  [{r.get('similarity', 0.0):.2f}] {r['content']}")

    return "\n".join(lines) if lines else "No results found."


@register("dsec_archival_search", "Advanced structured search over the historical memory store.", roles=("brain", "research"))
def dsec_archival_search(
    query: str, 
    domain: Optional[str] = None, 
    session: Optional[str] = None, 
    type: Optional[str] = None,
    limit: int = 5
) -> str:
    """
    Structured archival search with filters.
    """
    from dsec.memory import list_memories, search_memory
    
    # If a query is provided, we use semantic search first
    if query:
        results = search_memory(query, domain=domain, limit=limit)
    else:
        # Otherwise we list with filters
        results = list_memories(domain=domain, session=session)
        if type:
            results = [r for r in results if r.get("type") == type]
        results = results[:limit]

    if not results:
        return "No archival memories found matching the filters."

    lines = [f"Found {len(results)} historical records:"]
    for r in results:
        ts = r.get("timestamp", "")[:19]
        lines.append(f"  [{ts}] [{r.get('session', 'unknown')}] {r['content']}")
        if r.get("similarity"):
            lines.append(f"    (Similarity: {r['similarity']:.2f})")
    
    return "\n".join(lines)


@register("graph_memory_forget", "Removes an entity and all its relationships from the knowledge graph (intentional forgetting).", roles=("brain",))
def graph_memory_forget(entity: str) -> str:
    ok = graph_forget_node(entity)
    if ok:
        return f"Forgotten entity '{entity}' and all its relationships."
    return f"Entity '{entity}' not found in the knowledge graph."


@register("graph_memory_path", "Finds relationship paths between two entities in the knowledge graph (up to 4 hops).", roles=("brain", "research"))
def graph_memory_path(source: str, target: str) -> str:
    paths = graph_query_path(source, target)
    if not paths:
        return f"No path found between '{source}' and '{target}'."
    lines = [f"Found {len(paths)} path(s) from '{source}' to '{target}':"]
    for i, path in enumerate(paths[:3], 1):
        steps = " → ".join(f"[{e['relation']}] → {e['target']}" for e in path)
        lines.append(f"  Path {i}: {source} → {steps}")
    return "\n".join(lines)
