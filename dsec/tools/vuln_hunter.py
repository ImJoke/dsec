"""
DSEC Vuln Hunter — Xint-style 4-stage 0day discovery pipeline.

Stages (system, not just AI):
  1. TARGET — rank files in a codebase by attack-surface likelihood.
  2. ANALYZE — deep code review of a single file / function for a specific
                vulnerability class (memory safety, integer overflow, auth bypass,
                injection, race, deserialization, type confusion).
  3. VALIDATE — independent second-pass confirms the finding is real and
                exploitable in production context (rejects theoretical-only).
  4. REPORT — structured CVSS-scored finding with repro + patch suggestion.

The pipeline is model-agnostic. Each stage calls the configured `research`
or `utility` role pool — when a model improves, the pipeline absorbs it.

Tools registered (role=brain,research):
  - vuln_target_rank(path, max_files=20, subsystem="")
  - vuln_deep_analyze(file_path, vuln_classes="memory,intover,auth,injection")
  - vuln_validate(finding)
  - vuln_report(finding)
  - vuln_hunt(path, max_files=8, vuln_classes="...") — orchestrates all 4

Usage from the agent:
  <tool_call>{"name":"vuln_hunt","arguments":{"path":"/repo/openbsd/sys/netinet"}}</tool_call>

Heuristic targeting weights are tuned to the same attack-surface buckets
Xint Code targets in their FreeBSD/OpenBSD/FFmpeg/Firecracker scans:
network parsers, codec libraries, RPC/auth, virtio device transports.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from dsec.core.registry import register


# ─── Stage 1: Attack-surface heuristics ─────────────────────────────────────

_EXT_SCORES: Dict[str, int] = {
    ".c": 90, ".h": 70, ".cc": 90, ".cpp": 90, ".hpp": 70, ".cxx": 90,
    ".rs": 85, ".go": 80, ".java": 70,
    ".py": 60, ".rb": 55, ".php": 70, ".js": 60, ".ts": 60,
    ".sol": 95,
}

_PATH_BOOSTS: List[Tuple[str, int]] = [
    ("netinet", 30), ("/net/", 25), ("tcp", 20), ("ip6", 20), ("ipv4", 15),
    ("rpc", 25), ("nfs", 25), ("smb", 20), ("dns", 20), ("dhcp", 18),
    ("libavcodec", 30), ("libavformat", 25), ("h264", 25), ("h265", 25),
    ("hevc", 22), ("vp9", 22), ("decoder", 20), ("encoder", 18),
    ("codec", 20), ("parser", 22),
    ("auth", 18), ("kerberos", 25), ("gssapi", 25), ("openssl", 18),
    ("xdr", 22), ("asn1", 22), ("protobuf", 18), ("serialize", 20),
    ("virtio", 25), ("pci/", 22), ("usb/", 20), ("driver", 18),
    ("kvm", 20), ("vmm", 20), ("hypervisor", 20),
    ("/api/", 12), ("controller", 10), ("middleware", 10), ("session", 12),
    ("/parser", 18), ("/decode", 18), ("/parse", 15),
]

_FN_NAME_RE = re.compile(
    r'\b(?:parse|decode|validate|check|verify|sanitize|deserialize|'
    r'unmarshal|read_packet|dispatch|handle_msg|recv|copy|memcpy|'
    r'sprintf|format|exec|eval|render|inflate|extract)\b',
    re.IGNORECASE,
)

_SCORE_CAP = 100


def _heuristic_file_score(path: Path) -> int:
    p = str(path).lower()
    ext = path.suffix.lower()
    score = _EXT_SCORES.get(ext, 0)
    if score == 0:
        return 0
    for needle, boost in _PATH_BOOSTS:
        if needle in p:
            score += boost
    try:
        with open(path, "rb") as f:
            head = f.read(16 * 1024)
        head_str = head.decode("utf-8", errors="ignore")
        hits = len(_FN_NAME_RE.findall(head_str))
        score += min(20, hits * 2)
    except Exception:
        pass
    return min(_SCORE_CAP, score)


def _walk_code(root: Path, max_files: int = 2000) -> List[Path]:
    skip_dirs = {".git", "node_modules", "vendor", "third_party", "deps",
                 "build", "dist", ".cache", "__pycache__", ".tox", ".venv",
                 "target", ".obsidian", ".idea", ".vscode"}
    out: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs and not d.startswith(".")]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in _EXT_SCORES:
                out.append(p)
                if len(out) >= max_files:
                    return out
    return out


@register(
    "vuln_target_rank",
    (
        "Stage 1 of the Xint-style 0day pipeline. Walk a codebase / subsystem "
        "and return the top N files most likely to contain exploitable "
        "vulnerabilities, ranked by attack-surface heuristics (file type, "
        "directory class — netinet/codec/rpc/virtio/auth — and a quick "
        "function-name scan for parse/decode/copy/exec patterns). Use this "
        "before vuln_deep_analyze to focus expensive deep-review on the "
        "right files instead of guessing.\n"
        "PARAMS: path (codebase / subsystem dir), max_files (default 20), "
        "subsystem (optional substring filter — e.g. 'netinet', 'libavcodec/h264')."
    ),
    roles=("brain", "research"),
)
def vuln_target_rank(path: str, max_files: int = 20, subsystem: str = "") -> str:
    p = Path(os.path.expanduser(path)).resolve()
    if not p.exists():
        return f"[error: path '{path}' does not exist]"
    if p.is_file():
        return f"[error: '{path}' is a file; provide a directory]"

    files = _walk_code(p, max_files=4000)
    if subsystem:
        sub_low = subsystem.lower()
        files = [f for f in files if sub_low in str(f).lower()]
    scored = [(_heuristic_file_score(f), f) for f in files]
    scored = [(s, f) for s, f in scored if s > 0]
    scored.sort(key=lambda sf: sf[0], reverse=True)
    top = scored[:max_files]
    if not top:
        return f"[no code files matched under {p}]"
    rel = lambda fp: str(fp.relative_to(p)) if str(fp).startswith(str(p)) else str(fp)
    lines = [f"[vuln_target_rank — {len(top)} candidate(s), root={p}]"]
    for s, f in top:
        try:
            sz = f.stat().st_size
        except OSError:
            sz = 0
        lines.append(f"  score={s:>3}  size={sz:>7}B  {rel(f)}")
    lines.append(
        f"\nNext: pick the top file(s) and call vuln_deep_analyze on each. "
        f"For a full sweep, use vuln_hunt(path='{path}', max_files=8)."
    )
    return "\n".join(lines)


# ─── Stage 2: Deep-analyze a single file ─────────────────────────────────────

_VULN_CLASS_HINTS: Dict[str, str] = {
    "memory": (
        "memory safety: stack/heap buffer overflow, OOB read/write, "
        "use-after-free, double-free, uninitialized read, type confusion. "
        "Look for memcpy/strcpy/sprintf without explicit length checks, "
        "sentinel-collision (e.g. 0xFFFF used both as count and invalid "
        "marker), reused stale pointers after struct re-init."
    ),
    "intover": (
        "integer overflow / signedness: signed/unsigned mismatch, modular "
        "comparison non-transitivity (SEQ_LT-style), int -> size_t truncation, "
        "addition without overflow check before allocation."
    ),
    "auth": (
        "authentication / authorization bypass: missing auth check on a "
        "code path, TOCTOU between auth and use, credential parsing that "
        "silently accepts trailing garbage, replay attacks."
    ),
    "injection": (
        "injection / unsanitized input: SQL, OS command, LDAP, template "
        "injection, log injection, unsafe object reconstruction from "
        "external data (yaml.load, marshal.loads, unsafe XML)."
    ),
    "race": (
        "race conditions / TOCTOU: stat-then-open, check-then-act, "
        "shared mutable state without locks, reentry while holding a "
        "stale pointer, signal-safety violations."
    ),
    "logic": (
        "logic errors / state-machine flaws: skipped state transitions, "
        "mode confusion, default-allow, off-by-one in loop bounds."
    ),
}


def _build_analyze_prompt(file_path: str, body: str, vuln_classes: List[str]) -> str:
    hints = "\n".join(
        f"  - {cls.upper()}: {_VULN_CLASS_HINTS.get(cls, '(generic)')}"
        for cls in vuln_classes
    )
    return (
        f"You are a senior vulnerability researcher reviewing a single source file "
        f"for **exploitable 0-day vulnerabilities**. Operate like Theori's Xint Code "
        f"deep-analysis stage: trace data flow from any untrusted input to dangerous "
        f"sinks, evaluate control-flow constraints, identify exact trigger conditions.\n\n"
        f"DO NOT flag style issues, missing comments, or non-security bugs. Only "
        f"output candidate findings that are plausibly exploitable in production "
        f"with attacker-controlled input.\n\n"
        f"VULN CLASSES TO LOOK FOR:\n{hints}\n\n"
        f"For each finding emit a JSON object on its own line, prefixed `FINDING: `:\n"
        f'  FINDING: {{"file":"{file_path}","line":N,"function":"...","class":"...",'
        f'"severity":"Critical|High|Medium|Low","cwe":["CWE-..."],"summary":"<1 sentence>",'
        f'"trigger":"<concrete attacker action>","data_flow":"<source->sink in 1 line>",'
        f'"exploit_sketch":"<2-3 sentences>"}}\n\n'
        f"If you find no plausible exploitable bugs, emit exactly: NO_FINDINGS\n\n"
        f"FILE: {file_path}\n```\n{body}\n```"
    )


@register(
    "vuln_deep_analyze",
    (
        "Stage 2 of the Xint-style 0day pipeline. Deep code review of a single "
        "source file for exploitable vulnerabilities (memory safety, integer "
        "overflow, auth bypass, injection, race, logic). Returns one or more "
        "structured FINDING JSON lines, or NO_FINDINGS. Run vuln_target_rank "
        "first to choose which file to analyze.\n"
        "PARAMS: file_path (the source file), vuln_classes (comma-separated "
        "from: memory,intover,auth,injection,race,logic — default all)."
    ),
    roles=("brain", "research"),
)
def vuln_deep_analyze(file_path: str, vuln_classes: str = "memory,intover,auth,injection,race,logic") -> str:
    fp = Path(os.path.expanduser(file_path)).resolve()
    if not fp.exists() or not fp.is_file():
        return f"[error: file '{file_path}' does not exist]"
    try:
        body = fp.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        return f"[error: cannot read {file_path}: {exc}]"
    if len(body) > 40_000:
        head = body[:24_000]
        tail = body[-12_000:]
        body = f"{head}\n\n...[file truncated; {len(body)} bytes total]...\n\n{tail}"
    classes = [c.strip().lower() for c in vuln_classes.split(",") if c.strip()]
    prompt = _build_analyze_prompt(str(fp), body, classes)
    return _call_role("research", prompt)


# ─── Stage 3: Validate ───────────────────────────────────────────────────────


def _build_validate_prompt(finding: Dict[str, Any]) -> str:
    return (
        "You are an INDEPENDENT validator. A primary scanner produced the "
        "vulnerability finding below. You did NOT see the original code; rely "
        "only on the data given. Decide whether the finding is plausibly real "
        "and exploitable in production, or whether it is a false positive or "
        "theoretical-only weakness. Be skeptical — Xint Code's validation "
        "stage rejects findings whose trigger conditions can never occur in "
        "practice.\n\n"
        "OUTPUT EXACTLY ONE LINE in this format:\n"
        "  VERDICT: {real|false_positive|theoretical_only|insufficient_info}\n"
        "  REASON: <one sentence>\n"
        "  CONFIDENCE: {high|medium|low}\n\n"
        "If you need code to confirm, set verdict=insufficient_info and ask "
        "the operator to invoke vuln_deep_analyze on a SECOND file or function.\n\n"
        f"FINDING:\n{json.dumps(finding, indent=2)}"
    )


@register(
    "vuln_validate",
    (
        "Stage 3 of the Xint-style 0day pipeline. Independent second-pass "
        "validator for a finding produced by vuln_deep_analyze. Distinguishes "
        "real exploitable bugs from false positives and theoretical-only "
        "weaknesses. Returns VERDICT / REASON / CONFIDENCE.\n"
        "PARAM: finding (a JSON string from a FINDING line)."
    ),
    roles=("brain", "research"),
)
def vuln_validate(finding: str) -> str:
    try:
        f = json.loads(finding) if isinstance(finding, str) else finding
        if not isinstance(f, dict):
            return "[error: finding must be a JSON object]"
    except json.JSONDecodeError as exc:
        return f"[error: finding is not valid JSON — {exc}]"
    prompt = _build_validate_prompt(f)
    return _call_role("research", prompt)


# ─── Stage 4: Report ─────────────────────────────────────────────────────────


def _cvss_estimate(severity: str) -> str:
    sev = (severity or "").lower()
    if "critical" in sev:
        return "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N (~9.3)"
    if "high" in sev:
        return "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N (~8.7)"
    if "medium" in sev:
        return "CVSS:4.0/AV:N/AC:H/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N (~5.5)"
    return "CVSS:4.0 (severity TBD)"


@register(
    "vuln_report",
    (
        "Stage 4 of the Xint-style 0day pipeline. Format a validated finding "
        "into a structured Markdown advisory with CVSS estimate, repro steps, "
        "and patch suggestion. The output is ready to paste into a security "
        "advisory or bug-bounty submission.\n"
        "PARAM: finding (JSON string from a FINDING line, ideally already "
        "validated by vuln_validate)."
    ),
    roles=("brain", "research"),
)
def vuln_report(finding: str) -> str:
    try:
        f = json.loads(finding) if isinstance(finding, str) else finding
    except json.JSONDecodeError as exc:
        return f"[error: finding is not valid JSON — {exc}]"
    if not isinstance(f, dict):
        return "[error: finding must be a JSON object]"
    cvss = _cvss_estimate(f.get("severity", ""))
    body = [
        f"# Finding: {f.get('summary', '(no summary)')}",
        "",
        f"**Severity:** {f.get('severity', '?')}  ",
        f"**Class:** {f.get('class', '?')}  ",
        f"**File:** `{f.get('file', '?')}:{f.get('line', '?')}`  ",
        f"**Function:** `{f.get('function', '?')}`  ",
        f"**CWE:** {', '.join(f.get('cwe', []) or ['(unspecified)'])}  ",
        f"**CVSS estimate:** {cvss}",
        "",
        "## Trigger",
        f"{f.get('trigger', '(not specified)')}",
        "",
        "## Data flow",
        f"{f.get('data_flow', '(not specified)')}",
        "",
        "## Exploit sketch",
        f"{f.get('exploit_sketch', '(not specified)')}",
        "",
        "## Suggested patch",
        "Add bounds / overflow check or sentinel-collision guard at the "
        "vulnerable call site. Re-validate with vuln_deep_analyze after "
        "applying the fix.",
    ]
    return "\n".join(body)


# ─── Orchestrator: vuln_hunt ─────────────────────────────────────────────────


@register(
    "vuln_hunt",
    (
        "End-to-end 0day discovery pipeline (Xint Code methodology). "
        "Walks a codebase / subsystem, ranks files by attack surface, runs "
        "deep analysis on the top N, validates each finding independently, "
        "and emits a structured Markdown report bundle. This is the "
        "system-level entry point — the operator typically only needs to "
        "call this one tool with a subsystem path.\n"
        "PARAMS: path (subsystem directory), max_files (deep-analyze top N — "
        "default 6, max 30), vuln_classes (comma-separated, default all)."
    ),
    roles=("brain", "research"),
)
def vuln_hunt(path: str, max_files: int = 6, vuln_classes: str = "memory,intover,auth,injection,race,logic") -> str:
    p = Path(os.path.expanduser(path)).resolve()
    if not p.exists() or not p.is_dir():
        return f"[error: path '{path}' is not a directory]"
    max_files = max(1, min(int(max_files), 30))

    rank_out = vuln_target_rank(str(p), max_files=max_files)
    rank_lines = rank_out.splitlines()
    file_lines = [ln for ln in rank_lines if ln.strip().startswith("score=")]
    if not file_lines:
        return f"[vuln_hunt — no candidates under {p}]\n{rank_out}"

    targets: List[Path] = []
    for ln in file_lines[:max_files]:
        try:
            rel = ln.split(maxsplit=2)[-1]
            targets.append(p / rel)
        except Exception:
            continue

    findings_seen: List[Dict[str, Any]] = []
    report_chunks: List[str] = [
        f"# vuln_hunt — {p}",
        "",
        f"**Stage 1 (target rank):** {len(targets)} file(s) selected.",
        "",
        rank_out,
        "",
    ]
    for fp in targets:
        report_chunks.append(f"\n---\n## Deep analysis — `{fp.relative_to(p)}`\n")
        analyze_out = vuln_deep_analyze(str(fp), vuln_classes=vuln_classes)
        report_chunks.append(analyze_out)
        for m in re.finditer(r"^FINDING:\s*(\{.*\})\s*$", analyze_out, re.MULTILINE):
            try:
                finding = json.loads(m.group(1))
            except Exception:
                continue
            findings_seen.append(finding)
            verdict = vuln_validate(json.dumps(finding))
            report_chunks.append(f"\n**Validate:**\n{verdict}\n")
            if "VERDICT: real" in verdict:
                report_chunks.append("\n**Report:**\n")
                report_chunks.append(vuln_report(json.dumps(finding)))

    summary_real = sum(1 for line in report_chunks if isinstance(line, str)
                       and "VERDICT: real" in line)
    report_chunks.insert(2, f"**Findings seen:** {len(findings_seen)} · "
                            f"**Validated real:** {summary_real}\n")
    return "\n".join(report_chunks)


# ─── Internal: dispatch a sub-prompt to the configured role pool ─────────────


def _call_role(role: str, prompt: str) -> str:
    """Dispatch *prompt* to chat() for the given role and collect content."""
    try:
        from dsec.client import chat as _chat
        from dsec.config import load_config
        cfg = load_config()
        out = _chat(
            message=prompt,
            model=cfg.get("default_model", "deepseek-chat"),
            base_url=cfg.get("base_url", "http://localhost:8000"),
            role=role,
        )
        if isinstance(out, dict):
            err = out.get("error")
            if err:
                return f"[vuln_hunter sub-call error: {err}]"
            return out.get("content", "") or "[vuln_hunter: empty response]"
        return str(out)
    except Exception as exc:  # noqa: BLE001
        return f"[vuln_hunter sub-call exception: {type(exc).__name__}: {exc}]"
