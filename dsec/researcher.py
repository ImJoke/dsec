"""
DSEC Research Pipeline
Auto-detects research triggers from user input, runs concurrent fetches,
and formats results for injection into the prompt.
"""
import asyncio
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .domain import get_domain
from .sources import SOURCE_FETCHERS, SOURCE_DISPLAY


# ---------------------------------------------------------------------------
# Trigger Detection
# ---------------------------------------------------------------------------

# Software + version patterns
_VERSION_PATTERNS = [
    re.compile(r"([A-Za-z][\w\-\.]{2,})\s+v?(\d+\.\d+[\.\d]*(?:p\d+)?(?:[-_]\w+)?)", re.I),
    re.compile(r"([A-Za-z][\w\-\.]{2,})/v?(\d+\.\d+[\.\d]*(?:p\d+)?)", re.I),
]

_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)

# Binaries commonly exploitable via GTFOBins
_GTFO_BINARIES = frozenset({
    "vim", "vi", "python", "python2", "python3", "perl", "ruby", "find",
    "wget", "curl", "tar", "less", "more", "man", "awk", "nmap", "lua",
    "env", "ld.so", "php", "node", "nodejs", "bash", "sh", "dash",
    "docker", "sudo", "git", "zip", "unzip", "ssh", "scp", "rsync",
    "cp", "mv", "cat", "tee", "nano", "emacs", "screen", "tmux",
    "socat", "nc", "netcat", "strace", "ltrace", "gdb", "mysql",
    "sqlite3", "ftp", "tftp", "scp", "sftp", "zip", "gzip", "bzip2",
    "xz", "7z", "ar", "cpio", "dd", "head", "tail", "cut", "awk",
    "sed", "make", "gcc", "g++", "openssl", "base64", "xxd",
})

# Privesc context signals
_PRIVESC_CONTEXT = frozenset({
    "suid", "sgid", "sudo", "setuid", "setgid", "privesc",
    "privilege", "root", "escalat",
})

# Vuln types for bug bounty domain
_VULN_TYPES = [
    "SSRF", "XSS", "SQLi", "SQL injection", "IDOR", "XXE", "RCE",
    "LFI", "RFI", "SSTI", "deserialization", "open redirect",
    "command injection", "path traversal", "subdomain takeover",
]

# Software names to skip (too generic / not worth researching)
_SKIP_SOFTWARE = frozenset({
    "the", "and", "for", "with", "this", "from", "http", "https",
    "www", "port", "tcp", "udp", "ssl", "tls", "uri", "url",
})


def _append_query(
    queries: List[Dict[str, Any]],
    seen: set,
    *,
    query_type: str,
    query: str,
    sources: List[str],
) -> None:
    normalized = query.strip()
    key = normalized.lower()
    if not normalized or key in seen:
        return
    seen.add(key)
    queries.append({"type": query_type, "query": normalized, "sources": sources})


def should_research(text: str, domain: str) -> List[Dict[str, Any]]:
    """
    Analyse text and return a list of research query descriptors.
    Each descriptor: {type, query, sources}
    """
    domain_config = get_domain(domain)
    domain_sources: List[str] = domain_config.get("research_sources", [])
    queries: List[Dict[str, Any]] = []
    seen: set = set()

    # ---- 1. Software + version pairs ----
    for pattern in _VERSION_PATTERNS:
        for m in pattern.finditer(text):
            software = m.group(1).strip()
            version = m.group(2).strip()
            key = f"{software.lower()} {version}"
            if key in seen or software.lower() in _SKIP_SOFTWARE or len(software) < 3:
                continue
            q_sources = [s for s in ("nvd", "exploitdb", "github_advisories") if s in domain_sources]
            if not q_sources:
                q_sources = ["nvd", "exploitdb"]
            _append_query(
                queries,
                seen,
                query_type="software_version",
                query=f"{software} {version}",
                sources=q_sources[:3],
            )

    # ---- 2. Explicit CVE mentions ----
    for m in _CVE_PATTERN.finditer(text):
        cve = m.group(0).upper()
        _append_query(
            queries,
            seen,
            query_type="cve",
            query=cve,
            sources=["nvd", "github_advisories"],
        )

    # ---- 3. GTFOBins (HTB / CTF only, when privesc context present) ----
    if domain in ("htb", "ctf") and "gtfobins" in domain_sources:
        text_lower = text.lower()
        has_privesc_context = any(ctx in text_lower for ctx in _PRIVESC_CONTEXT)
        if has_privesc_context:
            for binary in _GTFO_BINARIES:
                pattern = re.compile(r"\b" + re.escape(binary) + r"\b", re.I)
                if pattern.search(text):
                    _append_query(
                        queries,
                        seen,
                        query_type="binary",
                        query=binary,
                        sources=["gtfobins"],
                    )

    # ---- 4. Vulnerability types (bug bounty) ----
    if domain == "bugbounty":
        text_lower = text.lower()
        for vuln in _VULN_TYPES:
            if vuln.lower() in text_lower:
                q_sources = [s for s in ("portswigger", "hackerone_disclosed") if s in domain_sources]
                if not q_sources:
                    q_sources = ["portswigger"]
                _append_query(
                    queries,
                    seen,
                    query_type="vulnerability",
                    query=vuln,
                    sources=q_sources,
                )

    return queries


# ---------------------------------------------------------------------------
# Research Execution
# ---------------------------------------------------------------------------

async def _fetch_one(query_info: Dict[str, Any], max_results: int) -> Optional[Dict[str, Any]]:
    """Fetch from all sources for one query descriptor concurrently."""
    query = query_info["query"]
    sources = query_info["sources"]
    all_results: List[Dict] = []

    task_pairs = [
        (sk, SOURCE_FETCHERS[sk](query, max_results))
        for sk in sources
        if sk in SOURCE_FETCHERS
    ]

    if not task_pairs:
        return None

    source_keys = [sk for sk, _ in task_pairs]
    coros = [coro for _, coro in task_pairs]

    gathered = await asyncio.gather(
        *[asyncio.wait_for(c, timeout=12.0) for c in coros],
        return_exceptions=True,
    )
    for sk, result in zip(source_keys, gathered):
        if isinstance(result, Exception):
            continue
        if not isinstance(result, list):
            continue
        for r in result:
            if not isinstance(r, dict):
                continue
            r["_source"] = sk
            r["_source_display"] = SOURCE_DISPLAY.get(sk, sk)
        all_results.extend(result)

    if not all_results:
        return None

    # Group by source for cleaner output
    by_source: Dict[str, List[Dict]] = {}
    for r in all_results:
        sk = r["_source"]
        by_source.setdefault(sk, []).append(r)

    combined_results: List[Dict] = []
    for sk in sources:
        combined_results.extend(by_source.get(sk, []))

    return {
        "query_type": query_info["type"],
        "query": query,
        "sources": sources,
        "source_key": sources[0] if sources else "unknown",
        "source_display": SOURCE_DISPLAY.get(sources[0], sources[0]) if sources else "Unknown",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "confidence": "high" if query_info["type"] in ("cve", "software_version") else "medium",
        "results": combined_results,
    }


async def run_research(queries: List[Dict[str, Any]], max_results: int = 5) -> List[Dict[str, Any]]:
    """Run all research queries concurrently. Returns list of result dicts."""
    if not queries:
        return []
    tasks = [_fetch_one(q, max_results) for q in queries]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)
    return [r for r in gathered if isinstance(r, dict)]


# ---------------------------------------------------------------------------
# Formatting for Prompt Injection
# ---------------------------------------------------------------------------

def format_research_context(research_results: List[Dict[str, Any]]) -> str:
    """
    Format research results for injection into the prompt.
    Always clearly labeled as LIVE RESEARCH, not internal knowledge.
    """
    if not research_results:
        return ""

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines: List[str] = [
        f"[RESEARCH CONTEXT – Live fetch {timestamp}]",
        "⚠️  Verify all findings against current target before acting.",
        "",
    ]

    for res in research_results:
        query = res.get("query", "")
        results = res.get("results", [])
        if not results:
            continue

        # Group by source
        by_source: Dict[str, List[Dict]] = {}
        for r in results:
            sk = r.get("_source", res.get("source_key", "unknown"))
            sd = r.get("_source_display", SOURCE_DISPLAY.get(sk, sk))
            by_source.setdefault(f"{sk}||{sd}", []).append(r)

        for source_key_disp, items in by_source.items():
            _, source_display = source_key_disp.split("||", 1)
            lines.append(f"📡 {source_display} (queried: \"{query}\"):")
            for item in items[:5]:
                item_id = item.get("id", "")
                title = item.get("title", "")[:100]
                severity = item.get("severity", "")
                score = item.get("score")
                url = item.get("url", "")
                desc = item.get("description", "")[:200]

                score_str = f" {score}" if score else ""
                severity_str = f"[{severity}{score_str}]" if severity and severity not in ("N/A", "EDUCATIONAL", "CTF", "PRIV_ESC") else ""
                lines.append(f"• {item_id} {severity_str} – {title}")
                if desc and desc != title[:len(desc)]:
                    # Only add description if it adds info beyond the title
                    lines.append(f"  └─ {desc[:150]}")
                if url:
                    lines.append(f"  └─ URL: {url}")
            lines.append("")

    lines.append("[END RESEARCH CONTEXT]")
    return "\n".join(lines)
