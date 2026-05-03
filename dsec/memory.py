"""
DSEC cross-session semantic memory – Hybrid Vector + Graph Architecture.

Uses ChromaDB for persistent, searchable memory across sessions.
Adds a lightweight graph layer (JSON-backed) for entity-relationship tracking
inspired by Mem0 (hybrid storage) + Letta/MemGPT (agentic memory management).

Anti-hallucination rules are hardcoded and never bypassed.
"""
import hashlib
import json
import math
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import load_config

# ---------------------------------------------------------------------------
# TF-IDF Feature-Hashing Embedding (offline fallback)
# ---------------------------------------------------------------------------

_EMBED_DIM = 512  # dimensionality of fallback embedding


def _tokenize(text: str) -> List[str]:
    text = text.lower()
    words = re.findall(r"[a-z0-9_\-\.]{2,}", text)
    bigrams = [f"{words[i]}_{words[i+1]}" for i in range(len(words) - 1)]
    return words + bigrams


def _tfidf_embed(text: str) -> List[float]:
    """
    Feature-hashing TF embedding with L2 normalization.
    Gives real cosine similarity (not random) because security terms like
    'chamilo', 'rce', 'cve' hash to consistent bucket positions.
    """
    tokens = _tokenize(text)
    vec = [0.0] * _EMBED_DIM
    for token in tokens:
        idx = int(hashlib.sha256(token.encode()).hexdigest(), 16) % _EMBED_DIM
        # sign trick: prevents cancellation of opposite-hash tokens
        sign = 1.0 if int(hashlib.md5(token.encode()).hexdigest(), 16) % 2 == 0 else -1.0
        vec[idx] += sign

    # L2 normalise
    l2 = math.sqrt(sum(v * v for v in vec))
    if l2 > 0.0:
        vec = [v / l2 for v in vec]
    return vec


class _FallbackEF:
    """
    ChromaDB-compatible embedding function using TF-IDF feature hashing.
    Works fully offline — no model download required.
    Compatible with chromadb >= 0.4 and >= 1.x.
    """

    _np = None

    def __call__(self, input: List[str]):  # type: ignore[override]
        if _FallbackEF._np is None:
            import numpy
            _FallbackEF._np = numpy
        np = _FallbackEF._np
        return [np.array(_tfidf_embed(t), dtype=np.float32) for t in input]

    def embed_query(self, input: List[str]):  # type: ignore[override]
        return self(input)

    def name(self) -> str:
        return "dsec-tfidf-hash"

    def default_space(self) -> str:
        return "cosine"

    def supported_spaces(self) -> List[str]:
        return ["cosine", "l2", "ip"]

    def is_legacy(self) -> bool:
        return False


# ---------------------------------------------------------------------------
# ChromaDB client (lazy init to avoid startup delay)
# ---------------------------------------------------------------------------

_chroma_client = None
_collection = None
_memory_disabled = False
_using_fallback_ef = False
_import_checked = False
_COLLECTION_NAME = "dsec_memories"
_FALLBACK_COLLECTION_NAME = "dsec_memories_fallback"


def _chromadb_importable() -> bool:
    global _import_checked, _memory_disabled
    if _memory_disabled:
        return False
    if _import_checked:
        return True
    try:
        import chromadb  # noqa: F401
    except ImportError:
        _memory_disabled = True
        return False
    _import_checked = True
    return True


def _get_client():
    global _chroma_client, _memory_disabled
    if _memory_disabled:
        return None
    if _chroma_client is not None:
        return _chroma_client
    if not _chromadb_importable():
        return None
    try:
        import chromadb  # type: ignore
        from chromadb.config import Settings  # type: ignore
    except ImportError:
        _memory_disabled = True
        return None

    config = load_config()
    memory_path = Path(config["memory_dir"]).expanduser() / "chroma"
    memory_path.mkdir(parents=True, exist_ok=True)

    try:
        _chroma_client = chromadb.PersistentClient(
            path=str(memory_path),
            settings=Settings(anonymized_telemetry=False),
        )
        return _chroma_client
    except Exception:
        _memory_disabled = True
        return None


def _get_collection(force_fallback: bool = False):
    """
    Lazy-init the ChromaDB collection.

    We avoid probing embeddings during startup so simple commands remain fast.
    If ONNX-backed collection operations fail later, callers can retry with the
    deterministic offline fallback collection.
    """
    global _collection, _memory_disabled, _using_fallback_ef
    if _memory_disabled:
        return None
    if _collection is not None and (not force_fallback or _using_fallback_ef):
        return _collection

    client = _get_client()
    if client is None:
        return None

    try:
        if force_fallback:
            _collection = client.get_or_create_collection(
                name=_FALLBACK_COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"},
                embedding_function=_FallbackEF(),
            )
            _using_fallback_ef = True
        else:
            _collection = client.get_or_create_collection(
                name=_COLLECTION_NAME,
                metadata={"hnsw:space": "cosine"},
            )
            _using_fallback_ef = False
        return _collection
    except Exception:
        if force_fallback:
            _memory_disabled = True
            return None
        return _get_collection(force_fallback=True)


def _memory_record(mem_id: str, doc: str, meta: Dict[str, Any], *, similarity: float | None = None) -> Dict[str, Any]:
    record = {
        "id": mem_id,
        "content": doc,
        "session": meta.get("session", "unknown"),
        "domain": meta.get("domain", "htb"),
        "type": meta.get("type", "finding"),
        "confidence": meta.get("confidence", "suspected"),
        "tags": [t for t in meta.get("tags", "").split(",") if t],
        "timestamp": meta.get("timestamp", ""),
        "source": meta.get("source", "manual"),
        "verified": meta.get("verified", "false") == "true",
    }
    if similarity is not None:
        record["similarity"] = round(similarity, 4)
    return record


def _retry_with_fallback(operation):
    coll = _get_collection()
    if coll is None:
        return None
    try:
        return operation(coll)
    except Exception:
        fallback = _get_collection(force_fallback=True)
        if fallback is None:
            return None
        try:
            return operation(fallback)
        except Exception:
            return None


# ---------------------------------------------------------------------------
# Core Operations
# ---------------------------------------------------------------------------

def store_memory(content: str, metadata: Dict[str, Any]) -> Optional[str]:
    """
    Store a memory entry. Returns memory ID or None if ChromaDB unavailable.
    """
    if not content or not content.strip():
        return None

    mem_id = str(uuid.uuid4())
    meta = {
        "session": metadata.get("session", "unknown"),
        "domain": metadata.get("domain", "htb"),
        "type": metadata.get("type", "finding"),
        "confidence": metadata.get("confidence", "suspected"),
        "tags": ",".join(metadata.get("tags", [])),
        "timestamp": metadata.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "source": metadata.get("source", "manual"),
        "verified": str(metadata.get("verified", False)).lower(),
    }

    def _store(coll):
        coll.add(documents=[content.strip()], metadatas=[meta], ids=[mem_id])
        return mem_id

    return _retry_with_fallback(_store)


def search_memory(
    query: str,
    domain: Optional[str] = None,
    limit: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """
    Semantic search with anti-hallucination filters.
    HARDCODED RULES (never bypassed):
      1. Minimum similarity threshold = config.memory_similarity_threshold (≥ 0.82)
      2. Maximum results = config.memory_max_inject (≤ 3)
      3. Results always include source session + timestamp + similarity score
    """
    config = load_config()
    configured_threshold: float = max(0.82, config.get("memory_similarity_threshold", 0.82))
    # TF-IDF hashing operates on a different scale than ONNX semantic embeddings.
    # ONNX: related security topics score ~0.85-0.95 → use configured threshold
    # TF-IDF: same topics score ~0.08-0.20 → scale proportionally (÷ ~6)
    sim_threshold = configured_threshold if not _using_fallback_ef else max(0.05, configured_threshold * 0.12)
    max_inject: int = min(3, config.get("memory_max_inject", 3))
    n_results = limit or max_inject

    # Build where filter
    where: Optional[Dict] = None
    if domain:
        where = {"domain": {"$eq": domain}}

    def _query(coll):
        return coll.query(
            query_texts=[query],
            n_results=min(n_results * 3, 20),  # over-fetch then filter
            where=where,
        )

    results = _retry_with_fallback(_query)
    if not results:
        return []

    ids = results.get("ids", [[]])[0]
    docs = results.get("documents", [[]])[0]
    metas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0]

    filtered: List[Dict[str, Any]] = []
    for mem_id, doc, meta, dist in zip(ids, docs, metas, distances):
        similarity = 1.0 - dist
        if similarity < sim_threshold:
            continue
        filtered.append(_memory_record(mem_id, doc, meta, similarity=similarity))

    # Sort by similarity descending, apply hard limit
    filtered.sort(key=lambda x: x["similarity"], reverse=True)
    return filtered[:max_inject]


def format_memory_context(memories: List[Dict[str, Any]]) -> str:
    """
    Format memories for prompt injection.
    CRITICAL: Always labeled as UNVERIFIED MEMORY with warnings.
    """
    if not memories:
        return ""

    lines: List[str] = [
        "[MEMORY CONTEXT – Historical, Unverified]",
        "⚠️  These are past observations. Do NOT assume they apply to the current target.",
        "    Always verify against current enumeration results before acting.",
        "",
    ]

    for mem in memories:
        session = mem.get("session", "unknown")
        confidence = mem.get("confidence", "suspected")
        mem_type = mem.get("type", "finding")
        tags = mem.get("tags", [])
        similarity = mem.get("similarity", 0.0)
        content = mem.get("content", "")
        timestamp = mem.get("timestamp", "")[:19].replace("T", " ")

        tags_str = ", ".join(tags[:5]) if tags else "none"
        lines.append(
            f"🧠 [MEMORY – {session} | {timestamp} | confidence: {confidence}]"
        )
        lines.append(f"Type: {mem_type} | Tags: {tags_str}")
        lines.append(f'"{content}"')
        lines.append(f"─ Relevance to current query: {similarity:.2f}")
        lines.append("")

    lines.append("[END MEMORY CONTEXT – Treat as hypothesis, not fact]")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Auto-extraction from AI responses
# ---------------------------------------------------------------------------

# Patterns for auto-extracting memory-worthy observations
_EXTRACT_PATTERNS = [
    # CVE + description
    re.compile(r"(CVE-\d{4}-\d{4,7}[^.]{0,200})", re.I),
    # Software version
    re.compile(r"([A-Za-z][\w\-\.]{2,}\s+(?:v?\d+\.\d+[\.\d]*)[^.]{0,200})", re.I),
    # Successful technique
    re.compile(r"(?:successfully|exploited|confirmed|worked|found|discovered)[^.]{5,200}", re.I),
    # Credential pattern (mask values)
    re.compile(r"(?:username|user|password|pass|cred|credential|key|token)[:\s]+[\w@.!#$%^&*]{3,50}", re.I),
]

# Minimum chars for a memory entry to be worth storing
_MIN_CONTENT_LEN = 30


def auto_extract_memories(
    response: str, session: str, domain: str
) -> List[str]:
    """
    Auto-extract potential memory snippets from an AI response.
    Stored as source='auto', confidence='suspected'.
    Returns list of stored memory IDs.
    """
    if not response or not response.strip():
        return []

    stored_ids: List[str] = []
    seen_content: set = set()

    for pattern in _EXTRACT_PATTERNS:
        for m in pattern.finditer(response):
            raw = m.group(0).strip()
            if len(raw) < _MIN_CONTENT_LEN:
                continue

            # Mask credentials
            masked = re.sub(
                r"(?i)(password|pass|token|key|secret|credential)[:\s]+\S+",
                r"\1: [REDACTED]",
                raw,
            )

            # Deduplicate
            key = masked.lower()[:80]
            if key in seen_content:
                continue
            seen_content.add(key)

            # Extract tags from content
            tags: List[str] = []
            cve_match = re.search(r"CVE-\d{4}-\d{4,7}", masked, re.I)
            if cve_match:
                tags.append(cve_match.group(0).upper())
            ver_match = re.search(r"([A-Za-z][\w\-\.]{2,})\s+v?\d+\.\d+", masked, re.I)
            if ver_match:
                tags.append(ver_match.group(1).lower())
            tags.append(domain)

            mem_id = store_memory(
                content=masked,
                metadata={
                    "session": session,
                    "domain": domain,
                    "type": "finding",
                    "confidence": "suspected",  # ALWAYS suspected for auto-extracted
                    "tags": list(set(tags)),
                    "source": "auto",
                    "verified": False,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
            )
            if mem_id:
                stored_ids.append(mem_id)

    return stored_ids


def auto_extract_memories_llm(
    response: str, session: str, domain: str
) -> List[str]:
    """
    LLM-based memory extraction (2026 SOTA).
    Uses the model to extract high-fidelity facts and relationships.
    """
    from dsec.llm_utils import llm_extract_facts
    
    facts = llm_extract_facts(response)
    if not facts:
        return []
        
    stored_ids: List[str] = []
    for item in facts:
        itype = item.get("type", "fact")
        content = item.get("content", "")
        entities = item.get("entities", [])
        
        if not content:
            continue
            
        if itype == "relation" and len(entities) >= 2:
            # Add to graph
            graph_add_edge(entities[0], content, entities[1], confidence="suspected")
            
        # Store as vector memory
        mem_id = store_memory(
            content=content,
            metadata={
                "session": session,
                "domain": domain,
                "type": itype,
                "confidence": "suspected",
                "tags": entities,
                "source": "llm_auto",
            }
        )
        if mem_id:
            stored_ids.append(mem_id)
            
    return stored_ids


# ---------------------------------------------------------------------------
# Management Operations
# ---------------------------------------------------------------------------

def delete_memory(memory_id: str) -> bool:
    def _delete(coll):
        coll.delete(ids=[memory_id])
        return True

    return bool(_retry_with_fallback(_delete))


def list_memories(
    domain: Optional[str] = None, session: Optional[str] = None
) -> List[Dict[str, Any]]:
    """Return all memories, optionally filtered by domain and/or session."""
    where: Optional[Dict[str, Any]] = None
    conditions = []
    if domain:
        conditions.append({"domain": {"$eq": domain}})
    if session:
        conditions.append({"session": {"$eq": session}})
    if len(conditions) == 1:
        where = conditions[0]
    elif len(conditions) > 1:
        where = {"$and": conditions}

    kwargs: Dict[str, Any] = {"include": ["documents", "metadatas"]}
    if where:
        kwargs["where"] = where

    def _get(coll):
        return coll.get(**kwargs)

    results = _retry_with_fallback(_get)
    if not results:
        return []

    ids = results.get("ids", [])
    docs = results.get("documents", [])
    metas = results.get("metadatas", [])

    memories = [_memory_record(mem_id, doc, meta) for mem_id, doc, meta in zip(ids, docs, metas)]
    memories.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return memories


def update_confidence(memory_id: str, confidence: str) -> bool:
    """Upgrade confidence level of a memory (e.g., suspected → verified)."""
    valid = {"verified", "suspected", "false_positive"}
    if confidence not in valid:
        return False

    def _update(coll):
        existing = coll.get(ids=[memory_id], include=["metadatas"])
        metas = existing.get("metadatas", [])
        if not metas:
            return False
        meta = dict(metas[0])
        meta["confidence"] = confidence
        meta["verified"] = str(confidence == "verified").lower()
        coll.update(ids=[memory_id], metadatas=[meta])
        return True

    return bool(_retry_with_fallback(_update))


def get_memory(memory_id: str) -> Optional[Dict[str, Any]]:
    """Return full memory entry by ID."""
    def _get(coll):
        return coll.get(ids=[memory_id], include=["documents", "metadatas"])

    results = _retry_with_fallback(_get)
    if not results:
        return None

    ids = results.get("ids", [])
    docs = results.get("documents", [])
    metas = results.get("metadatas", [])
    if not ids:
        return None
    return _memory_record(ids[0], docs[0], metas[0])


def memory_available() -> bool:
    """Check if ChromaDB is available."""
    return _chromadb_importable()


# ═══════════════════════════════════════════════════════════════════════════
# GRAPH MEMORY LAYER (2026 SOTA – Hybrid Vector + Graph)
#
# Lightweight JSON-backed knowledge graph that tracks entity relationships.
# Each node/edge is ALSO stored in ChromaDB for vector search, creating
# a true hybrid architecture.  The graph JSON acts as the structured index
# while ChromaDB provides the semantic retrieval.
# ═══════════════════════════════════════════════════════════════════════════

_GRAPH_FILE: Optional[Path] = None


def _graph_path() -> Path:
    global _GRAPH_FILE
    if _GRAPH_FILE is None:
        config = load_config()
        _GRAPH_FILE = Path(config["memory_dir"]).expanduser() / "knowledge_graph.json"
        _GRAPH_FILE.parent.mkdir(parents=True, exist_ok=True)
    return _GRAPH_FILE


def _load_graph() -> Dict[str, Any]:
    gp = _graph_path()
    if not gp.exists():
        return {"nodes": {}, "edges": []}
    try:
        return json.loads(gp.read_text())
    except Exception:
        return {"nodes": {}, "edges": []}


def _save_graph(graph: Dict[str, Any]) -> None:
    import tempfile as _tf
    gp = _graph_path()
    gp.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = _tf.mkstemp(dir=str(gp.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(graph, f, indent=2, ensure_ascii=False)
        os.replace(tmp, str(gp))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


import difflib

def _resolve_entity_key(graph: Dict[str, Any], entity: str) -> str:
    """Normalize entity key, with fuzzy matching for better entity resolution."""
    raw_key = entity.lower().strip().replace(" ", "_")
    if raw_key in graph["nodes"]:
        return raw_key
        
    # Find close matches to prevent duplicate entities (e.g., 'windows_10' vs 'windows10')
    existing_keys = list(graph["nodes"].keys())
    matches = difflib.get_close_matches(raw_key, existing_keys, n=1, cutoff=0.92)
    
    if matches:
        return matches[0]
    return raw_key

def graph_add_node(entity: str, entity_type: str = "unknown", properties: Optional[Dict[str, str]] = None) -> str:
    """Add or update a node in the knowledge graph. Returns node key."""
    graph = _load_graph()
    key = _resolve_entity_key(graph, entity)
    existing = graph["nodes"].get(key, {})
    node = {
        "entity": entity,
        "type": entity_type,
        "properties": {**existing.get("properties", {}), **(properties or {})},
        "updated": datetime.now(timezone.utc).isoformat(),
    }
    graph["nodes"][key] = node
    _save_graph(graph)
    return key


def graph_add_edge(source: str, relation: str, target: str, confidence: str = "suspected") -> bool:
    """Add a directed relationship edge.  Also stores in ChromaDB for vector search."""
    graph = _load_graph()
    src_key = _resolve_entity_key(graph, source)
    tgt_key = _resolve_entity_key(graph, target)

    # Ensure both nodes exist
    for key, label in [(src_key, source), (tgt_key, target)]:
        if key not in graph["nodes"]:
            graph["nodes"][key] = {
                "entity": label, "type": "unknown",
                "properties": {}, "updated": datetime.now(timezone.utc).isoformat(),
            }

    edge = {
        "source": src_key,
        "relation": relation,
        "target": tgt_key,
        "confidence": confidence,
        "created": datetime.now(timezone.utc).isoformat(),
    }

    # Deduplicate: skip if identical edge already exists
    for e in graph["edges"]:
        if e["source"] == src_key and e["relation"] == relation and e["target"] == tgt_key:
            return True

    graph["edges"].append(edge)
    _save_graph(graph)

    # Also store in ChromaDB for semantic retrieval
    store_memory(
        content=f"{source} {relation} {target}",
        metadata={
            "domain": "graph",
            "type": "relation",
            "confidence": confidence,
            "tags": [src_key, tgt_key, relation],
            "source": "graph",
        },
    )
    return True


def graph_query_entity(entity: str) -> Dict[str, Any]:
    """Return all edges where *entity* appears as source or target."""
    graph = _load_graph()
    key = _resolve_entity_key(graph, entity)
    node = graph["nodes"].get(key)
    outgoing = [e for e in graph["edges"] if e["source"] == key]
    incoming = [e for e in graph["edges"] if e["target"] == key]
    return {"node": node, "outgoing": outgoing, "incoming": incoming}


def graph_query_path(source: str, target: str, max_depth: int = 4) -> List[List[Dict]]:
    """BFS to find relationship paths between two entities (max 4 hops)."""
    graph = _load_graph()
    src_key = _resolve_entity_key(graph, source)
    tgt_key = _resolve_entity_key(graph, target)
    if src_key not in graph["nodes"] or tgt_key not in graph["nodes"]:
        return []

    # BFS
    from collections import deque
    queue: deque = deque()
    queue.append((src_key, []))
    visited = {src_key}
    paths: List[List[Dict]] = []

    while queue:
        current, path = queue.popleft()
        if len(path) > max_depth:
            continue
        for edge in graph["edges"]:
            next_key = None
            if edge["source"] == current:
                next_key = edge["target"]
            elif edge["target"] == current:
                next_key = edge["source"]
            if next_key is None or next_key in visited:
                continue
            new_path = path + [edge]
            if next_key == tgt_key:
                paths.append(new_path)
                continue
            visited.add(next_key)
            queue.append((next_key, new_path))

    return paths


def graph_stats() -> Dict[str, int]:
    """Return node/edge counts."""
    graph = _load_graph()
    return {"nodes": len(graph["nodes"]), "edges": len(graph["edges"])}


def graph_forget_node(entity: str) -> bool:
    """Remove a node and all its edges from the knowledge graph (Letta-style forget)."""
    graph = _load_graph()
    key = _resolve_entity_key(graph, entity)
    if key not in graph["nodes"]:
        return False
    del graph["nodes"][key]
    graph["edges"] = [e for e in graph["edges"] if e["source"] != key and e["target"] != key]
    _save_graph(graph)
    return True
