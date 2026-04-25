# dsec – DeepSeek Security CLI

```
 ██████╗ ███████╗███████╗ ██████╗
 ██╔══██╗██╔════╝██╔════╝██╔════╝
 ██║  ██║███████╗█████╗  ██║
 ██║  ██║╚════██║██╔══╝  ██║
 ██████╔╝███████║███████╗╚██████╗
 ╚═════╝ ╚══════╝╚══════╝ ╚═════╝
```

> **Agentic AI security assistant** for Bug Bounty, HackTheBox, CTF, and Vulnerability Research — powered by DeepSeek with live research, semantic memory, and context-aware compression.

---

## ✨ Features

- 🧠 **Semantic Memory** — cross-session ChromaDB memory with anti-hallucination rules; auto-extracts CVEs, credentials, and findings
- 🔬 **Auto-Research Pipeline** — detects software versions, CVEs, and GTFOBins binaries then fetches live data from NVD, ExploitDB, GitHub Advisories, HackerOne, PortSwigger, and PacketStorm concurrently
- ⚡ **Smart Compression** — detects and compresses nmap, gobuster, ffuf, feroxbuster, sqlmap, nikto, linpeas, and curl output before sending to the model
- 🎯 **Domain-Aware Prompts** — specialized system prompts for HTB, Bug Bounty, CTF, and Research contexts, auto-detected from input
- 🔄 **Session Management** — persistent sessions with history, notes, tags, and conversation continuity
- 🔑 **Round-Robin Token Rotation** — store multiple DeepSeek tokens for automatic rotation
- 📡 **Streaming Output** — real-time streaming with thinking process display using Rich

---

## 📋 Requirements

- Python 3.8+
- [deepseek-free-api](https://github.com/fu-jie/deepseek-free-api) running locally (Docker)
- A DeepSeek session token from [chat.deepseek.com](https://chat.deepseek.com)

**Python dependencies** (auto-installed by `install.sh`):
```
httpx>=0.27.0
rich>=13.0.0
click>=8.1.0
chromadb>=0.4.0
beautifulsoup4>=4.12.0
```

---

## 🚀 Installation

```bash
git clone https://github.com/ImJoke/dsec.git
cd dsec
bash install.sh
```

The installer will:
1. Verify Python 3.8+
2. Install all Python dependencies
3. Create `~/.dsec/` directory structure
4. Initialize `~/.dsec/config.json`
5. Install the `dsec` command to `/usr/local/bin/` (or `~/bin/` as fallback)

---

## 🐳 Docker Setup

dsec uses [deepseek-free-api](https://github.com/fu-jie/deepseek-free-api) as its backend — a local proxy that bridges the DeepSeek web API.

**1. Get your DeepSeek session token:**
- Go to [chat.deepseek.com](https://chat.deepseek.com) and log in
- Press `F12` → Application → Local Storage → `https://chat.deepseek.com`
- Copy the value of `userToken`

**2. Configure your token:**
```bash
cp .env.example .env
# Edit .env and set DEEP_SEEK_CHAT_AUTHORIZATION=your_token_here
```

**3. Start the API backend:**
```bash
docker-compose up -d
```

**4. Add your token to dsec:**
```bash
dsec token --add YOUR_TOKEN_HERE
```

The API will be available at `http://localhost:8000`.

---

## ⚙️ Configuration

Config is stored in `~/.dsec/config.json`.

Known config keys are validated on write. If a stored value becomes invalid,
dsec resets it to a safe default the next time config is loaded.

```bash
# View all settings
dsec config

# Change base URL (default: http://localhost:8000)
dsec config --set base_url http://localhost:8000

# Change default model
dsec config --set default_model deepseek-expert-r1-search

# Disable streaming thinking display
dsec config --set show_thinking false

# Adjust compression threshold (chars before compressing)
dsec config --set compress_threshold 500

# Tune memory similarity threshold (0.0–1.0, higher = stricter)
dsec config --set memory_similarity_threshold 0.82

# Max memory entries to inject per query
dsec config --set memory_max_inject 3

# Max research results per source
dsec config --set research_max_results 5
```

**Available settings:**

| Key | Default | Description |
|-----|---------|-------------|
| `base_url` | `http://localhost:8000` | deepseek-free-api endpoint |
| `default_model` | `deepseek-expert-r1-search` | Default model name |
| `stream` | `true` | Enable streaming responses |
| `show_thinking` | `true` | Show DeepSeek-R1 thinking process |
| `compress_threshold` | `500` | Char count before compression kicks in |
| `auto_research` | `true` | Enable automatic research pipeline |
| `research_max_results` | `5` | Max results per research source |
| `memory_similarity_threshold` | `0.82` | Minimum cosine similarity for memory injection |
| `memory_max_inject` | `3` | Max memory entries injected per query |

## 💻 Usage

### Basic Chat

```bash
# Start interactive shell (like a terminal chat session)
dsec

# Explicit interactive shell command
dsec shell

# Ask a question (quick mode — no session, memory, or research)
dsec -q "what port does SMB use?"

# Full pipeline with domain auto-detection
dsec "how do I enumerate SMB shares on 10.10.11.23?"

# Force a specific domain
dsec --domain htb "what's a good nmap command for initial recon?"

# Use search-capable model variant
dsec --search "latest RCE exploits for Apache 2.4.49"

# Suppress DeepSeek-R1 extended reasoning
dsec --no-think "give me a quick python reverse shell one-liner"
```

### Interactive Shell

`dsec` now supports an interactive terminal mode for back-and-forth work inside a
single session, closer to a REPL workflow than one-shot prompts.

```bash
# Start a named shell session
dsec shell --session htb-permx

# Start a search-capable shell
dsec shell --search
```

Available shell commands:

- `/help` — show shell commands
- `/status` — show the current shell settings
- `/session` — show current session detail and recent history
- `/note <text>` — add a note to the current session
- `/domain <htb|bugbounty|ctf|research>` — switch domain
- `/model <name>` — switch model
- `/clear` — clear the screen
- `/exit` or `/quit` — leave the shell

### Sessions

Sessions preserve conversation history, notes, and DeepSeek's conversation context (multi-turn memory).

```bash
# Create a new session and start chatting
dsec --new-session htb-permx "starting enumeration on 10.10.11.23"

# Continue an existing session
dsec --session htb-permx "I found SSH on port 22 and HTTP on 80"

# Short form
dsec -s htb-permx "nmap found SMB open, what next?"

# List all sessions
dsec sessions

# Show detailed session view (history, notes, tags)
dsec sessions --show htb-permx

# Delete a session
dsec sessions --delete htb-old

# Rename a session
dsec sessions --rename htb-permx htb-permx-complete
```

**Session name prefixes** auto-set the domain:
- `htb-*` → HackTheBox
- `bb-*` / `bugbounty-*` → Bug Bounty
- `ctf-*` → CTF
- `research-*` / `cve-*` → Research

### Piping Tool Output

dsec wraps tool output in `[TOOL OUTPUT]` markers and compresses verbose output automatically.

```bash
# Analyze nmap results
nmap -sV -sC 10.10.11.23 | dsec -s htb-permx "analyze these results"

# Gobuster directory scan
gobuster dir -u http://10.10.11.23 -w /usr/share/wordlists/dirb/common.txt | dsec -s htb-permx "what looks interesting?"

# SQLMap output
sqlmap -u "http://target.com/page?id=1" --dbs 2>&1 | dsec -s bb-target "summarize findings"

# LinPEAS privilege escalation
./linpeas.sh 2>&1 | dsec -s htb-permx "what are the best privesc vectors?"

# Curl HTTP response analysis
curl -i http://10.10.11.23/ | dsec -s htb-permx "fingerprint this web server"

# Feroxbuster results
feroxbuster --url http://10.10.11.23 | dsec -s htb-permx "prioritize these paths"

# Read from file
cat nmap_full.txt | dsec -s htb-permx "full analysis"
```

### Notes

Attach structured notes to sessions for later reference.

```bash
# Add a finding note
dsec note "Found admin panel at /admin/login.php" --session htb-permx --type finding

# Add credentials
dsec note "SSH creds: admin:Password123" --session htb-permx --type credential

# Record the user flag
dsec note "user.txt: 8f3a2c..." --session htb-permx --type flag

# General note
dsec note "Machine difficulty: Medium, theme: CMS exploitation" --session htb-permx
```

Note types: `finding`, `credential`, `flag`, `misc`

### Tags

```bash
# Tag a session for easy searching
dsec tags web smb privesc --session htb-permx

# Tags are shown in the sessions table
dsec sessions
```

### Memory Management

Cross-session semantic memory uses ChromaDB with anti-hallucination safeguards.

```bash
# List all stored memories
dsec memory --list

# Filter by domain
dsec memory --list --domain htb

# Filter by session
dsec memory --list --session htb-permx

# Semantic search
dsec memory --search "chamilo RCE"
dsec memory --search "CVE-2023"
dsec memory --search "sudo misconfiguration"

# Manually add a verified memory
dsec memory --add "CVE-2023-33568: Chamilo LMS unauthenticated RCE via big upload" \
  --type finding --tags "chamilo,rce,cve-2023-33568" --session htb-permx

# Show full memory entry
dsec memory --show <memory-id>

# Upgrade confidence from 'suspected' to 'verified'
dsec memory --verify <memory-id>

# Delete a memory
dsec memory --delete <memory-id>
```

### Token Management

```bash
# Add tokens (comma-separated for multiple)
dsec token --add TOKEN1
dsec token --add TOKEN1,TOKEN2,TOKEN3

# List stored tokens (masked)
dsec token --list

# Check token status
dsec token --check
dsec token
```

---

## 🎯 Domains

dsec auto-detects the security context from your session name and message content:

| Domain | Prefix | Color | Research Sources |
|--------|--------|-------|-----------------|
| **HackTheBox** | `htb-` | 🟢 Green | NVD, ExploitDB, GitHub Advisories, PacketStorm, GTFOBins |
| **Bug Bounty** | `bb-` / `bugbounty-` | 🟡 Yellow | NVD, HackerOne, PortSwigger, GitHub Advisories |
| **CTF** | `ctf-` | 🔵 Cyan | CTFTime Writeups, GitHub CTF, ExploitDB |
| **Research** | `research-` / `cve-` | 🟣 Magenta | NVD, GitHub Advisories, ExploitDB, PacketStorm |

---

## 🚩 Flags Reference

| Flag | Short | Description |
|------|-------|-------------|
| `--session NAME` | `-s` | Use/create named session |
| `--new-session NAME` | `-n` | Create new session and start chatting |
| `--domain DOMAIN` | `-d` | Override domain (`htb`/`bugbounty`/`ctf`/`research`) |
| `--model MODEL` | `-m` | Override model name |
| `--search` | | Use search-capable model variant |
| `--quick` | `-q` | Skip memory, research, session saving |
| `--no-compress` | | Disable context compression |
| `--no-think` | | Skip extended reasoning (concise replies) |
| `--no-research` | | Skip auto-research pipeline |
| `--no-memory` | | Skip memory context injection |

---

## 📁 Project Structure

```
dsec/                           ← repo root
├── README.md
├── requirements.txt
├── install.sh                  ← installer
├── docker-compose.yml          ← deepseek-free-api container
├── .env.example                ← environment variable template
└── dsec/                       ← Python package
    ├── __init__.py             ← package metadata (version)
    ├── __main__.py             ← entry point (python -m dsec)
    ├── cli.py                  ← CLI commands and chat pipeline
    ├── client.py               ← HTTP streaming client
    ├── compressor.py           ← tool output compression
    ├── config.py               ← config management (~/.dsec/config.json)
    ├── domain.py               ← domain definitions and detection
    ├── formatter.py            ← Rich terminal output
    ├── memory.py               ← ChromaDB semantic memory
    ├── researcher.py           ← auto-research pipeline
    ├── session.py              ← session CRUD
    └── sources.py              ← research data sources
```

---

## ⚙️ How It Works

dsec processes every query through a 12-step pipeline:

1. **Read stdin** — detect piped tool output
2. **Load/create session** — restore conversation history and context
3. **Compress** — detect tool type (nmap/gobuster/etc.) and compress verbose output; stdin and message are compressed separately to preserve prompt structure
4. **Search memory** — semantic search of ChromaDB for relevant past findings (similarity ≥ 0.82)
5. **Detect research triggers** — scan input for software versions, CVEs, GTFOBins binaries, and vulnerability types
6. **Run research concurrently** — fetch from all relevant sources in parallel with 12s timeout per source
7. **Build prompt** — assemble system prompt + memory context + research context + tool output + user message
8. **Get token** — round-robin token selection from stored pool
9. **Stream response** — SSE streaming with live Rich terminal updates, thinking process display
10. **Update session** — save conversation ID, increment message count, append history
11. **Auto-extract memories** — regex-extract CVEs, software versions, credentials, and successful techniques from the AI response
12. **Store memories** — persist extracted snippets to ChromaDB with `confidence: suspected`