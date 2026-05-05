# dsec – Autonomous Security Agent

```
 ██████╗ ███████╗███████╗ ██████╗
 ██╔══██╗██╔════╝██╔════╝██╔════╝
 ██║  ██║███████╗█████╗  ██║
 ██║  ██║╚════██║██╔══╝  ██║
 ██████╔╝███████║███████╗╚██████╗
 ╚═════╝ ╚══════╝╚══════╝ ╚═════╝
```

> **Agentic AI security assistant** for Bug Bounty, HackTheBox, CTF, Vulnerability Research, and Code Auditing — powered by a **multi-agent cloud-frontier orchestrator** with autonomous tool execution, persistent PTY shell, hybrid knowledge base, and stealth-oriented attack defaults.

---

## 🧠 Multi-Agent Orchestrator (NEW)

dsec runs as four specialized agents over rotating Ollama cloud-frontier endpoints, with automatic cascade to local DeepSeek when every cloud endpoint is down or rate-limited:

| Role | Default cloud model | Endpoint pool | Job |
|---|---|---|---|
| **brain** | `deepseek-v4-pro:cloud` | `brain_pool` (round-robin, 8 endpoints) | Plans, hypothesizes, delegates. Cannot run bash directly when `enable_multi_agent=true`. |
| **executor** | `qwen3-coder:480b-cloud` | `exec_pool` | Receives concrete plan from brain, runs bash + MCP tools, returns digest. |
| **research** | `qwen3.5:397b-cloud` | `research_pool` | KB lookup (Obsidian + ctf-skills), live CVE feeds, GTFOBins, methodology recall. |
| **utility** | `minimax-m2.7:cloud` | `util_pool` | Cheap classifier / summarizer (mostly invisible). |

**Auto-rotation:** rate-limited (HTTP 429) endpoints are marked dead for 10 min, fatal endpoints (401/404) for 30 min, transient 5xx for 30 s. The pool moves on automatically — no manual switching.

**Auto-stop:** when the brain emits a flag pattern (`HTB{...}`, `FLAG{...}`, `THM{...}`, etc.) or the explicit marker `TASK_COMPLETE`, the agentic loop exits cleanly so it doesn't keep spinning past the answer.

Build pools from an OllamaHound scan CSV:

```
python3 tools/build_ollama_pools.py \
  --csv ~/tools/OllamaHound/results/scanner/<scan>.csv \
  --pool-size 8 --candidates-per-role 40 --apply
```

The picker honors `ROLE_MODELS` priority (strongest cloud frontier first, local fallback last) and only keeps models with ≥2 chat-OK endpoints in the pool. Backups are atomic; `~/.dsec/config.json.bak` is written before every apply.

## 🐚 Persistent PTY Shell (NEW)

The `pty_shell` tool gives the AI a single long-lived bash session. State (cwd, env, sourced venvs, exported funcs, aliases) survives every call — `cd` once and stay there, `source venv/bin/activate` once and pip-install in place. Pre-tuned PS1 / TERM / COLUMNS / `HISTFILE=/dev/null` for clean low-footprint output.

```python
pty_shell(command="cd /opt/work")
pty_shell(command="source venv/bin/activate && python3 attack.py")
pty_shell(command="echo $PATH")   # reflects the venv from the previous turn
```

For listeners (`nc`, `responder`, `chisel`) and interactive shells (`evil-winrm`, `mssqlclient`, `python REPL`), use the `background` tool — same Pane infrastructure, dedicated `job_id`s.

## 📚 Knowledge Base (NEW)

`notes_search` indexes both:

- the user's Obsidian vault (`~/Documents/vincent` — 752+ Permanent / Fleeting / Storage notes covering AD/ADCS, Kerberos, RSA/ECDSA, web exploitation, CTF write-ups)
- the `ctf-skills` reference (forensics, crypto, pwn, web, reverse, misc playbooks)

Combined corpus is BM25-indexed in-memory. Hot-reload with `notes_reload`. Add extra vault paths with `DSEC_EXTRA_NOTES_DIRS` env var or `extra_notes_dirs` config key.

## 🥷 Stealth-Oriented Defaults (NEW)

The brain system prompt includes red-team operator principles: prefer PTY-allocated SSH (`ssh -tt -o LogLevel=ERROR`), avoid disk artifacts (in-memory `bash -c`, `python3 -c`), use LOLBINs over dropped tools, sanitize remote shell history on entry, and tag every tool call with intent. The non-PTY default for `bash` calls pipes `/dev/null` to stdin so prompts that probe for a TTY (`certipy "Overwrite?"`, `ffuf`, etc.) abort cleanly instead of hanging.

---

## ✨ Features

### Core Intelligence
- 🧠 **Hybrid Memory** — ChromaDB vector store + JSON knowledge graph with fuzzy entity resolution (difflib 85% threshold). Auto-extracts CVEs, credentials, techniques, and findings across sessions.
- 🔬 **Auto-Research Pipeline** — detects software versions, CVEs, and GTFOBins binaries then fetches live data from NVD, ExploitDB, GitHub Advisories, HackerOne, PortSwigger, and PacketStorm concurrently.
- ⚡ **Smart Compression** — detects and compresses nmap, gobuster, ffuf, feroxbuster, sqlmap, nikto, linpeas, and curl output before sending to the model.
- 🎯 **Domain-Aware Prompts** — specialized system prompts for HTB, Bug Bounty, CTF, Research, and Programmer contexts with auto-detection from input.

### Agentic Capabilities
- 🤖 **Autonomous Execution** — Hermes-style agentic loop with `<tool_call>` blocks, stuck detection, and configurable iteration budgets (up to 15 iterations).
- 🖥️ **Interactive PTY Terminals** — spawn persistent background terminals (tmux-style) for interactive tools like `msfconsole`, `nc` listeners, SSH sessions, and Python REPLs. The AI can send raw keystrokes including Ctrl+C/Ctrl+D.
- 🛡️ **Install Protection** — mandatory manual approval gate for `apt`, `pip`, `brew`, `npm` install commands, even with `/autoexec on`.
- 📝 **Aider-Style Code Editing** — precise SEARCH/REPLACE block editing with automatic whitespace normalization for vulnerability patching and code review.

### Agent Modes & Personalities
- 🏗️ **Agent Modes** — constrain AI behavior via `/mode`:
  - `architect` — planning only, no tool execution
  - `recon` — scanning & enumeration only
  - `exploit` — aggressive exploitation & privilege escalation
  - `ask` — Q&A only, no tool usage
  - `auto` — full autonomy (default)
- 🎭 **Personalities** — change communication style via `/personality`:
  - `professional` — formal, precise, and structured (default)
  - `hacker` — edgy 1337 speak, calls targets "boxes"
  - `teacher` — detailed step-by-step explanations

### Offensive Security Skills
- 📦 **Modular Skill Bundles** — Claude-Red inspired `SKILL.md` methodology checklists that auto-load based on conversation context:
  - Active Directory Penetration Testing
  - Cloud Security (AWS / Azure / GCP)
  - API Security Testing
  - Mobile App Security (Frida / Objection)
  - Malware Analysis & Reverse Engineering
  - Windows Privilege Escalation
  - Pivoting & Tunneling (Chisel / Ligolo)
  - Phishing & Social Engineering
  - Wireless Attacks
  - Container & Kubernetes Security
  - Static Analysis (Trail of Bits methodology)
  - Bug Bounty Recon
- 🔓 **Offline GTFOBins** — searchable database of 40+ binary exploitation techniques (SUID, sudo, capabilities, file read/write, reverse shell).
- 🧪 **Learning Loop** — the agent can create and save new `SKILL.md` files from successful engagements via the `save_skill` tool.

### Rich Terminal UI
- 🖼️ **Split-Pane TUI** — during streaming, the terminal displays two panels: a compact Thinking pane (top, with live word count and elapsed time) and a Response pane (bottom, with Markdown rendering). Inspired by OpenCode and Claude Code.
- 🎨 **Gradient Banner** — Unicode block-art banner with domain-specific color palettes.
- 📊 **Context Status Bar** — token usage and context budget tracking after each turn.
- ⚙️ **Tool Execution Panels** — colored tool headers with argument display and elapsed time.

### Infrastructure
- 🔄 **Session Management** — persistent sessions with history, notes, tags, and DeepSeek conversation continuity.
- 🔑 **Round-Robin Token Rotation** — store multiple DeepSeek tokens for automatic rotation.
- 📡 **Multi-Provider Backend** — supports DeepSeek (Docker proxy), GPT4Free (g4f), and local Ollama-compatible models.
- 🌐 **MCP Protocol Support** — connect external tool servers via Model Context Protocol.
- 📈 **Extended Context** — dynamic token budget scaling for 64K, 128K, and 1M context window models.

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
prompt_toolkit>=3.0.0
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

---

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

`dsec` supports an interactive terminal mode for back-and-forth work inside a
single session, closer to a REPL workflow than one-shot prompts.

```bash
# Start a named shell session
dsec shell --session htb-permx

# Start a search-capable shell
dsec shell --search
```

### Shell Commands

#### Agent Modes & Personality
| Command | Description |
|---------|-------------|
| `/mode <name>` | Set agent behavior: `architect`, `recon`, `exploit`, `ask`, `auto` |
| `/personality <name>` | Set persona: `professional`, `hacker`, `teacher` |

#### Agentic Execution
| Command | Description |
|---------|-------------|
| `/autoexec on` | Auto-approve AI tool calls (no confirm prompts) |
| `/autoexec off` | Require y/n/A/e approval before each command (default) |
| `!<cmd>` | Run a shell command yourself, optionally pipe output to AI |

#### Session Management
| Command | Description |
|---------|-------------|
| `/session` | Show session details, notes, flags, history |
| `/history` | Show last 10 conversation turns |
| `/note <text>` | Add a note to the current session |
| `/new [name]` | Start a new session (clear context) |
| `/status` | Show all current settings |
| `/clear` | Clear screen |

#### Domain & Model
| Command | Description |
|---------|-------------|
| `/domain <name>` | Switch domain: `htb`, `bugbounty`, `ctf`, `research`, `programmer` |
| `/model <name>` | Switch AI model |

#### Skills & Tools
| Command | Description |
|---------|-------------|
| `/skill [name]` | Load a security methodology skill |
| `/tools` | List all registered native tools |

#### MCP Servers
| Command | Description |
|---------|-------------|
| `/mcp list` | List configured MCP servers |
| `/mcp connect <name>` | Connect to server |
| `/mcp disconnect <name>` | Disconnect |
| `/mcp tools [name]` | List available tools |
| `/mcp call <srv> <tool> [json]` | Call a tool |

#### Navigation
| Command | Description |
|---------|-------------|
| `/help` | Show help menu |
| `/exit` / `/quit` | Leave the shell |

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
```

### Notes & Tags

```bash
# Add notes to sessions
dsec note "Found admin panel at /admin/login.php" --session htb-permx --type finding
dsec note "SSH creds: admin:Password123" --session htb-permx --type credential
dsec note "user.txt: 8f3a2c..." --session htb-permx --type flag

# Tag sessions
dsec tags web smb privesc --session htb-permx
```

### Memory Management

Cross-session semantic memory uses ChromaDB + knowledge graph with anti-hallucination safeguards.

```bash
# List all stored memories
dsec memory --list

# Filter by domain or session
dsec memory --list --domain htb
dsec memory --list --session htb-permx

# Semantic search
dsec memory --search "chamilo RCE"

# Manually add a verified memory
dsec memory --add "CVE-2023-33568: Chamilo LMS unauthenticated RCE" \
  --type finding --tags "chamilo,rce,cve-2023-33568" --session htb-permx

# Show / verify / delete
dsec memory --show <memory-id>
dsec memory --verify <memory-id>
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
```

---

## 🎯 Domains

dsec auto-detects the security context from your session name and message content:

| Domain | Prefix | Color | Use Case |
|--------|--------|-------|----------|
| **HackTheBox** | `htb-` | 🟢 Green | CTF-style pentesting, machine pwning |
| **Bug Bounty** | `bb-` / `bugbounty-` | 🟡 Yellow | Responsible disclosure, scope-aware |
| **CTF** | `ctf-` | 🔵 Cyan | Capture The Flag competitions |
| **Research** | `research-` / `cve-` | 🟣 Magenta | Vulnerability research, exploit dev |
| **Programmer** | — | 🔷 Royal Blue | Code review, secure development |

---

## 🛠️ Native Tools

The agent has access to these built-in tools (viewable via `/tools`):

| Category | Tools |
|----------|-------|
| **Memory** | `core_memory_append`, `core_memory_replace`, `core_memory_read`, `graph_memory_insert`, `graph_memory_search`, `graph_memory_forget`, `graph_memory_path` |
| **PTY Terminal** | `pty_create_pane`, `pty_run_command`, `pty_read_output`, `pty_send_input`, `pty_send_signal`, `pty_list_panes`, `pty_close_pane` |
| **Browser** | `browser_goto`, `browser_extract`, `web_search`, `browser_screenshot`, `browser_links` |
| **Code Editing** | `programmer_view_file`, `programmer_edit_file`, `programmer_create_file`, `programmer_tree`, `programmer_search`, `programmer_diff` |
| **Security** | `gtfobins_search`, `save_skill` |
| **OSINT** | `osint_crawl_twitter`, `osint_crawl_telegram` |

---

## 🚩 CLI Flags

| Flag | Short | Description |
|------|-------|-------------|
| `--session NAME` | `-s` | Use/create named session |
| `--new-session NAME` | `-n` | Create new session and start chatting |
| `--domain DOMAIN` | `-d` | Override domain (`htb`/`bugbounty`/`ctf`/`research`/`programmer`) |
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
dsec/                              ← repo root
├── README.md
├── requirements.txt
├── install.sh                     ← installer
├── docker-compose.yml             ← deepseek-free-api container
├── .env.example                   ← environment variable template
└── dsec/                          ← Python package
    ├── __init__.py                ← package metadata (version)
    ├── __main__.py                ← entry point (python -m dsec)
    ├── cli.py                     ← CLI commands, shell, and agentic loop
    ├── client.py                  ← HTTP streaming client
    ├── compressor.py              ← tool output compression
    ├── config.py                  ← config management (~/.dsec/config.json)
    ├── context_manager.py         ← token budget tracking (up to 1M)
    ├── domain.py                  ← domain definitions, system prompts, modes
    ├── formatter.py               ← Rich split-pane TUI
    ├── memory.py                  ← ChromaDB vector + JSON knowledge graph
    ├── researcher.py              ← auto-research pipeline
    ├── session.py                 ← session CRUD
    ├── shell_ui.py                ← prompt_toolkit integration & autocomplete
    ├── sources.py                 ← research data sources
    ├── core/
    │   └── registry.py            ← native tool registry (@register decorator)
    ├── providers/
    │   └── manager.py             ← multi-provider backend (DeepSeek, g4f, Ollama)
    ├── tools/
    │   ├── memory_tools.py        ← graph + vector memory tools
    │   ├── pty_terminal.py        ← persistent PTY multiplexer
    │   ├── gtfobins.py            ← offline GTFOBins database
    │   └── skill_manager.py       ← learning loop (save_skill)
    └── skills/
        ├── loader.py              ← SKILL.md loader with trigger phrases
        ├── programmer.py          ← code editing tools (view/edit/create/search/diff)
        └── bundled/               ← 12+ offensive methodology checklists
            ├── ad-pentest/SKILL.md
            ├── api-security/SKILL.md
            ├── bugbounty-recon/SKILL.md
            ├── cloud-security/SKILL.md
            ├── container-k8s/SKILL.md
            ├── malware-analysis/SKILL.md
            ├── mobile-app/SKILL.md
            ├── phishing-se/SKILL.md
            ├── pivoting-tunnel/SKILL.md
            ├── static-analysis/SKILL.md
            ├── windows-privesc/SKILL.md
            └── wireless-attacks/SKILL.md
```

---

## ⚙️ How It Works

dsec processes every query through a multi-stage pipeline:

1. **Read stdin** — detect piped tool output
2. **Load/create session** — restore conversation history and context
3. **Compress** — detect tool type (nmap/gobuster/etc.) and compress verbose output
4. **Search memory** — semantic search of ChromaDB + knowledge graph for relevant past findings (similarity ≥ 0.82)
5. **Detect research triggers** — scan input for software versions, CVEs, GTFOBins binaries, and vulnerability types
6. **Run research concurrently** — fetch from all relevant sources in parallel with 12s timeout per source
7. **Load skills** — auto-detect and inject relevant offensive methodology checklists
8. **Build prompt** — assemble system prompt (mode + personality) + memory + research + skills + tool output + user message
9. **Get token** — round-robin token selection from stored pool
10. **Stream response** — SSE streaming with split-pane Rich TUI (Thinking + Response panels)
11. **Agentic loop** — if the response contains `<tool_call>` blocks, dispatch tools and feed results back (up to 15 iterations)
12. **Update session** — save conversation ID, increment message count, append history
13. **Auto-extract memories** — regex-extract CVEs, software versions, credentials, and successful techniques
14. **Store memories** — persist extracted snippets to ChromaDB + knowledge graph with `confidence: suspected`

---

## 📜 Credits & Inspiration

Built on insights and patterns from:

| Project | Inspiration |
|---------|-------------|
| [Hermes Agent](https://github.com/) | Agentic loop, memory nudge system, iteration budgets |
| [Claude Code / OpenCode](https://github.com/) | Rich split-pane TUI, keyboard navigation |
| [Claude-Red](https://github.com/SnailSploit/Claude-Red) | Structured SKILL.md offensive methodology format |
| [Trail of Bits Skills](https://github.com/trailofbits/skills) | Static analysis patterns |
| [Mem0](https://github.com/mem0ai/mem0) | Hybrid vector + graph memory architecture |
| [Letta / MemGPT](https://github.com/letta-ai/letta) | Agentic memory management (core_memory_append/replace) |
| [Open-Interpreter](https://github.com/) | PTY terminal control patterns |
| [Aider](https://github.com/) | SEARCH/REPLACE code editing |
| [Superpowers](https://github.com/obra/superpowers) | Capability-based permissions |
| [GTFOBins](https://gtfobins.github.io/) | Offline privilege escalation database |