"""
DSEC Context Compressor
Detects and compresses verbose tool output before sending to the model.
"""
import re
from difflib import SequenceMatcher
from typing import Dict, List

# ---------------------------------------------------------------------------
# Tool Detection
# ---------------------------------------------------------------------------

def detect_tool(text: str) -> str:
    """Identify which security tool generated the output."""
    # nmap
    if any(p in text for p in ["Nmap scan report", "Starting Nmap", "Nmap done", "PORT   STATE"]):
        return "nmap"
    # gobuster
    if "Gobuster" in text or ("gobuster" in text.lower() and "Status:" in text):
        return "gobuster"
    # ffuf
    if "FFUF" in text or ("ffuf" in text.lower() and ":: Progress:" in text):
        return "ffuf"
    # feroxbuster
    if "feroxbuster" in text.lower() or ("🚀" in text and "Status:" in text):
        return "feroxbuster"
    # sqlmap
    if "sqlmap" in text.lower() or ("[INFO]" in text and "parameter" in text.lower() and "sqlmap" in text.lower()):
        return "sqlmap"
    # nikto
    if "Nikto" in text or ("OSVDB" in text and "+" in text):
        return "nikto"
    # linpeas / winpeas
    if any(p in text for p in ["linPEAS", "winPEAS", "PEASS-ng", "╔══════╣"]):
        return "linpeas"
    # curl / raw HTTP
    if text.lstrip().startswith("HTTP/") or "< HTTP/" in text or (
        "Content-Type:" in text and "Server:" in text and text.lstrip().startswith(("HTTP", "<"))
    ):
        return "curl"
    return "generic"


# ---------------------------------------------------------------------------
# Should Compress?
# ---------------------------------------------------------------------------

COMPRESS_PATTERN = re.compile(
    r"\bPORT\b|\bSTATE\b|\bSERVICE\b|Found|\[\+\]|\[\*\]|Status:|Size:|Words:|"
    r"Lines:|Starting|Scanning|={5,}|^#{1,3}\s|^-{5,}",
    re.MULTILINE,
)


def should_compress(text: str, threshold: int = 500) -> bool:
    """Return True if the text is noisy tool output that should be compressed."""
    if len(text) < threshold:
        return False
    return bool(COMPRESS_PATTERN.search(text))


# ---------------------------------------------------------------------------
# Per-tool Compressors
# ---------------------------------------------------------------------------

def _strip_ansi(text: str) -> str:
    ansi = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
    return ansi.sub("", text)


def _dedupe_similar_lines(lines: List[str], *, window: int, threshold: float) -> List[str]:
    deduped: List[str] = []
    for line in lines:
        is_dup = False
        if line.strip():
            for prev in deduped[-window:]:
                if prev.strip() and SequenceMatcher(None, line, prev).ratio() > threshold:
                    is_dup = True
                    break
        if not is_dup:
            deduped.append(line)
    return deduped


def _compress_nmap(text: str) -> str:
    lines = text.splitlines()
    open_ports: List[str] = []
    script_results: List[str] = []
    os_info: List[str] = []
    hostnames: List[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "Not shown:" in line:
            os_info.append(stripped)
            continue
        if line.startswith("SF-"):
            continue

        if "Nmap scan report for" in line:
            hostnames.append(stripped)
            continue

        if any(kw in line for kw in ["OS:", "Running:", "OS details:", "Aggressive OS"]):
            os_info.append(stripped)
            continue

        m = re.match(r"(\d+)/(\w+)\s+(open(?:\|filtered)?)\s+(\S+)\s*(.*)", line)
        if m:
            port, proto, _, service, version = m.groups()
            version = version.strip()
            port_str = f"{port}/{service}"
            if version:
                port_str += f" ({version[:70]})"
            open_ports.append(port_str)
            continue

        # Skip closed / filtered
        if re.match(r"\d+/\w+\s+(closed|filtered)", line):
            continue

        # Script output lines
        if stripped.startswith("|") or stripped.startswith("|_"):
            script_results.append(stripped[:130])

    parts: List[str] = []
    if hostnames:
        parts.append(" | ".join(hostnames))
    if open_ports:
        parts.append("OPEN PORTS: " + ", ".join(open_ports))
    if os_info:
        parts.append("OS: " + " | ".join(os_info[:2]))
    if script_results:
        parts.append("SCRIPTS:\n" + "\n".join(script_results[:20]))

    return "\n".join(parts) if parts else text[:600]


def _compress_gobuster_ffuf(text: str) -> str:
    lines = text.splitlines()
    buckets: Dict[int, List[str]] = {200: [], 301: [], 302: [], 403: [], 500: []}
    other: List[str] = []
    SKIP = ("====", "----", "Starting", "Progress:", "Gobuster", "FFUF", "feroxbuster",
            ":: ", "[+] Url", "[+] Method", "[+] Threads", "[+] Wordlist", "[+] Status",
            "[+] User", "[+] Timeout", "[+] Extensions")

    for line in lines:
        stripped = line.strip()
        if not stripped or any(s in stripped for s in SKIP):
            continue
        m = re.search(r"\b(\d{3})\b", stripped)
        if m:
            status = int(m.group(1))
            if status == 404:
                continue
            clean = re.sub(r"\s+", " ", stripped)[:130]
            if status in buckets:
                buckets[status].append(clean)
            else:
                other.append(clean)

    parts: List[str] = []
    for code in (200, 301, 302, 403, 500):
        if buckets[code]:
            parts.append(f"[{code}]\n" + "\n".join(buckets[code][:25]))
    if other:
        parts.append("[Other]\n" + "\n".join(other[:10]))

    return "\n".join(parts) if parts else text[:600]


def _compress_sqlmap(text: str) -> str:
    lines = text.splitlines()
    important: List[str] = []
    SKIP_BANNERS = ("___", "(c)", "legal disclaimer", "|_/", "http://sqlmap",
                    "usage:", "[#", "[-]", "___H___")
    KEEP_KEYWORDS = ("vulnerable", "injection", "parameter", "found", "payload",
                     "database", "table", "column", "dumping", "back-end", "[*]",
                     "title:", "type:", "vector:", "rank:", "retrieved")

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if any(b in stripped for b in SKIP_BANNERS):
            continue
        if re.match(r"\[\d{2}:\d{2}:\d{2}\] \[INFO\]", stripped):
            if any(k in stripped.lower() for k in KEEP_KEYWORDS):
                important.append(stripped[:160])
            continue
        if re.match(r"\[\d{2}:\d{2}:\d{2}\] \[(WARNING|CRITICAL|ERROR)\]", stripped):
            important.append(stripped[:160])
            continue
        if any(k in stripped.lower() for k in KEEP_KEYWORDS):
            important.append(stripped[:160])

    return "\n".join(important) if important else text[:600]


def _compress_curl(text: str) -> str:
    lines = text.splitlines()
    important: List[str] = []
    body_lines: List[str] = []
    in_body = False
    status_added = False

    INTERESTING = (
        "server:", "x-powered-by:", "set-cookie:", "location:",
        "www-authenticate:", "x-frame-options:", "content-security-policy:",
        "x-xss-protection:", "access-control-", "x-forwarded-", "x-real-ip:",
        "via:", "x-generator:", "x-drupal", "x-wordpress", "x-aspnet",
        "link:", "authorization:", "x-auth", "x-token",
    )

    for line in lines:
        stripped = line.strip()
        if re.match(r"HTTP/[\d.]+ \d+", stripped) and not status_added:
            important.append(stripped)
            status_added = True
            continue
        if not stripped and status_added and not in_body:
            in_body = True
            continue
        if in_body:
            body_lines.append(line)
            continue
        hl = stripped.lower()
        if any(hl.startswith(h) for h in INTERESTING):
            important.append(stripped[:160])

    if body_lines:
        body = "\n".join(body_lines)
        if len(body) > 500:
            body = body[:500] + "...[truncated]"
        important.append("\nBODY:\n" + body)

    return "\n".join(important) if important else text[:600]


def _compress_nikto(text: str) -> str:
    lines = text.splitlines()
    important: List[str] = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("+") and any(
            kw in stripped for kw in ("OSVDB", "Server:", "/", "X-", "Cookie", "allow", "header", "found")
        ):
            important.append(stripped[:200])
    return "\n".join(important) if important else text[:600]


def _compress_linpeas(text: str) -> str:
    text = _strip_ansi(text)
    lines = text.splitlines()
    important: List[str] = []
    SEPARATORS = re.compile(r"^[═╔╚╠╦╩╬\-=\*╗╝╣#]{4,}$")
    SENSITIVE = re.compile(
        r"(passwd|shadow|\.ssh|\.bash_history|\.env|config|credential|password|token|secret|api.?key)",
        re.I,
    )

    for line in lines:
        stripped = line.strip()
        # Cap line length before regex — keeps regex bounded on pathological
        # base64 dumps or 1MB-no-newline output without losing meaning.
        if len(stripped) > 4000:
            stripped = stripped[:4000]
        if not stripped or SEPARATORS.match(stripped):
            continue
        if any(m in stripped for m in ("[+]", "[!]", "[*]", "CVE-", "SUID", "SGID", "cron", "sudo")):
            important.append(stripped[:200])
            continue
        if SENSITIVE.search(stripped):
            important.append(stripped[:200])

    # Deduplicate similar lines
    deduped = _dedupe_similar_lines(important, window=8, threshold=0.85)

    return "\n".join(deduped) if deduped else text[:600]


def _compress_generic(text: str) -> str:
    text = _strip_ansi(text)
    lines = text.splitlines()

    # Remove consecutive empty lines
    cleaned: List[str] = []
    prev_empty = False
    for line in lines:
        if not line.strip():
            if not prev_empty:
                cleaned.append("")
            prev_empty = True
        else:
            cleaned.append(line)
            prev_empty = False

    # Deduplicate highly similar lines
    deduped = _dedupe_similar_lines(cleaned, window=5, threshold=0.80)

    result = "\n".join(deduped)
    if len(result) > 3000:
        result = result[:3000] + "\n...[output truncated]"
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def compress(text: str) -> Dict:
    """
    Compress tool output.
    Returns dict with original_length, compressed_length, compression_ratio,
    tool_detected, and compressed_content.
    """
    original_length = len(text)
    tool = detect_tool(text)

    dispatcher = {
        "nmap": _compress_nmap,
        "gobuster": _compress_gobuster_ffuf,
        "ffuf": _compress_gobuster_ffuf,
        "feroxbuster": _compress_gobuster_ffuf,
        "sqlmap": _compress_sqlmap,
        "curl": _compress_curl,
        "nikto": _compress_nikto,
        "linpeas": _compress_linpeas,
    }
    fn = dispatcher.get(tool, _compress_generic)
    compressed = fn(text)

    compressed_length = len(compressed)
    ratio = (
        (original_length - compressed_length) / original_length * 100
        if original_length > 0
        else 0.0
    )

    return {
        "original_length": original_length,
        "compressed_length": compressed_length,
        "compression_ratio": f"{ratio:.1f}%",
        "tool_detected": tool,
        "compressed_content": compressed,
    }
