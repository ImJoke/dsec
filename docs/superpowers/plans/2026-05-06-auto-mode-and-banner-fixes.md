# Auto Mode Default + New-Session UI Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `auto` the default domain (no-domain-needed shell), display the actually-resolved brain model + role pools in the new-session banner, and fix every related UI/implementation/functionality miss visible in the screenshots.

**Architecture:** (1) Add a synthetic `auto` domain whose `system_prompt` is task-type-agnostic and whose `detect_domain` priority chain ends at `auto` instead of `htb`. (2) Move the "actual model" lookup behind a single helper `resolve_brain_display_model(state, config)` that knows about `enable_multi_agent` + brain_pool. (3) Replace every banner / status / help reference to `deepseek-expert-r1-search` with that helper. (4) Wire the shell loop default state to `domain_override = "auto"`, with on-the-fly redetection when the user starts talking about a specific category (CTF, AD, web). (5) Backfill missing UI: `/status` shows pool model not legacy `default_model`; `Mode: auto | Domain: auto` line corrected; new-session banner mentions multi-agent if active.

**Tech Stack:** Python 3.10+, Rich, prompt_toolkit, no new dependencies.

---

## Task 1: Add the `auto` domain definition

**Files:**
- Modify: `dsec/domain.py` (around the `DOMAINS` dict near line 845)
- Test: `dsec/tests/test_smoke.py` (new test in the existing `TestDomain` class)

The `auto` domain is a meta-domain — its `system_prompt` is purely the universal core (already in `_DSEC_IDENTITY`) and explicitly tells the brain to *infer* the task type from cwd / artifacts / user input on the fly.

- [ ] **Step 1: Write the failing test**

```python
# in dsec/tests/test_smoke.py — add to TestDomain
def test_auto_domain_exists_and_is_neutral(self):
    from dsec.domain import get_domain, list_domains
    self.assertIn("auto", list_domains())
    cfg = get_domain("auto")
    self.assertEqual(cfg["name"], "auto")
    # auto must NOT bias toward HTB / network-target framing
    sp = cfg["system_prompt"].lower()
    self.assertNotIn("user.txt", sp)
    self.assertNotIn("root.txt", sp)
    self.assertIn("infer", sp)  # tells brain to detect task type
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest dsec/tests/test_smoke.py::TestDomain::test_auto_domain_exists_and_is_neutral -v`
Expected: FAIL with `KeyError: 'auto'` or `AssertionError`.

- [ ] **Step 3: Add `DOMAIN_AUTO` and register it**

In `dsec/domain.py`, just above `DOMAINS = { ... }`:

```python
DOMAIN_AUTO: Dict[str, Any] = {
    "name": "auto",
    "display": "Auto",
    "color": "#7aa2f7",
    "triggers": [],  # auto is the fallback — never matched by triggers
    "system_prompt": """You are dsec in **AUTO MODE**. The operator has not declared a category — you must INFER the task type from the working directory contents and the user's prompt before taking action.

STEP ZERO — INFER the task type:
- If cwd contains source code (Dockerfile, package.json, *.py, *.go, etc.) → web / source-review / code audit. Read files; do NOT scan an IP.
- If cwd contains a binary (ELF, .out, .bin, .exe) → reverse-engineering / pwn. Run `file`, `checksec`, `strings`, then disassemble.
- If cwd contains a `.pcap` / `.pcapng` → forensics — analyse with tshark / Wireshark.
- If cwd contains an image / audio / video → stego — strings, binwalk, exiftool, zsteg, steghide.
- If cwd contains a ciphertext blob in `.txt` / `.py` → crypto — read the encoder, identify the cipher, attack.
- If the operator names an IP or hostname in the prompt → network engagement (HTB / pentest).
- If the operator names a CVE or "vulnerability research" → vulnerability research / 0day hunt — use `vuln_hunt`.
- If nothing else matches → ask ONE concise question; do not stall.

After inference, behave like the matching specialist (web / pwn / crypto / forensics / network / research) without needing the operator to set `/domain`.

CRITICAL MEMORY RULE: Memory context is historical reference only. NEVER assume past sessions apply to the current task without verification.""",
    "research_sources": ["nvd", "exploitdb", "github_advisories", "ctftime_writeups"],
    "auto_research_triggers": ["cve", "vulnerability", "exploit", "technique"],
}
```

Then in the `DOMAINS` dict registration:

```python
DOMAINS = {
    "auto": DOMAIN_AUTO,         # NEW — first so /domain default lands here
    "htb": DOMAIN_HTB,
    "bugbounty": DOMAIN_BUGBOUNTY,
    "ctf": DOMAIN_CTF,
    "research": DOMAIN_RESEARCH,
    "programmer": DOMAIN_PROGRAMMER,
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m pytest dsec/tests/test_smoke.py::TestDomain::test_auto_domain_exists_and_is_neutral -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add dsec/domain.py dsec/tests/test_smoke.py
git commit -m "feat(domain): add auto-mode meta-domain — task-type inference"
```

---

## Task 2: Make `detect_domain` fall through to `auto` instead of `htb`

**Files:**
- Modify: `dsec/domain.py:872-915` (`detect_domain` function)
- Test: `dsec/tests/test_smoke.py`

- [ ] **Step 1: Write the failing tests**

```python
# in TestDomain
def test_detect_domain_neutral_text_falls_to_auto(self):
    from dsec.domain import detect_domain
    self.assertEqual(detect_domain("hello world"), "auto")
    self.assertEqual(detect_domain(""), "auto")

def test_detect_domain_keeps_specific_classification(self):
    from dsec.domain import detect_domain
    self.assertEqual(detect_domain("HackTheBox box 10.10.11.5"), "htb")
    self.assertEqual(detect_domain("flag{abc} pwn challenge"), "ctf")
    self.assertEqual(detect_domain("hackerone bug bounty scope"), "bugbounty")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest dsec/tests/test_smoke.py::TestDomain -v -k detect_domain`
Expected: `test_detect_domain_neutral_text_falls_to_auto` FAILS (returns "htb").

- [ ] **Step 3: Update fallback default**

Replace lines 914-915 in `dsec/domain.py`:

```python
    # 3. Default — auto-mode (task type inferred at runtime)
    return "auto"
```

Also exclude `auto` from the keyword-scoring loop (it has no triggers, so it scores 0; but explicitly skip to keep semantics clear). Update lines 894-908:

```python
    # 2. Keyword scoring (skip the "auto" meta-domain)
    tl = text.lower()
    scores: Dict[str, int] = {d: 0 for d in DOMAINS if d != "auto"}
    STRONG = {
        "htb": {"htb", "hackthebox", "user.txt", "root.txt"},
        "bugbounty": {"bug bounty", "hackerone", "bugcrowd", "intigriti"},
        "ctf": {"ctf", "pwn", "shellcode", "flag{"},
        "research": {"vulnerability research", "0day", "zero day"},
        "programmer": {"refactor", "code review", "best practice", "debug code"},
    }

    for domain_name, domain_data in DOMAINS.items():
        if domain_name == "auto":
            continue
        for trigger in domain_data["triggers"]:
            if trigger.lower() in tl:
                scores[domain_name] += 1
                if trigger.lower() in STRONG.get(domain_name, set()):
                    scores[domain_name] += 2
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest dsec/tests/test_smoke.py::TestDomain -v -k detect_domain`
Expected: PASS for both new tests + existing `detect_domain_*` tests.

- [ ] **Step 5: Commit**

```bash
git add dsec/domain.py dsec/tests/test_smoke.py
git commit -m "feat(domain): auto-mode is the default fallback"
```

---

## Task 3: Resolve display model from brain pool when multi-agent active

**Files:**
- Create: `dsec/display.py`
- Modify: `dsec/cli.py` (5 sites currently using `config.get("default_model", "deepseek-expert-r1-search")` for display)
- Test: `dsec/tests/test_smoke.py`

- [ ] **Step 1: Write the failing test**

```python
# in TestDomain or new TestDisplay
class TestDisplayHelpers(unittest.TestCase):
    def test_resolve_brain_display_model_multiagent(self):
        from dsec.display import resolve_brain_display_model
        cfg = {
            "default_model": "deepseek-expert-r1-search",
            "enable_multi_agent": True,
            "providers": {
                "brain_pool": {"type": "ollama", "model": "deepseek-v4-pro:cloud",
                               "endpoints": ["http://x:11434"]},
            },
            "roles": {"brain": {"provider": "brain_pool"}},
        }
        self.assertEqual(resolve_brain_display_model(cfg, ""), "deepseek-v4-pro:cloud")

    def test_resolve_brain_display_model_legacy(self):
        from dsec.display import resolve_brain_display_model
        cfg = {"default_model": "deepseek-expert-r1-search", "enable_multi_agent": False}
        self.assertEqual(resolve_brain_display_model(cfg, ""), "deepseek-expert-r1-search")

    def test_resolve_brain_display_model_explicit_override(self):
        from dsec.display import resolve_brain_display_model
        cfg = {"default_model": "X", "enable_multi_agent": True}
        self.assertEqual(resolve_brain_display_model(cfg, "qwen3:14b"), "qwen3:14b")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest dsec/tests/test_smoke.py::TestDisplayHelpers -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'dsec.display'`.

- [ ] **Step 3: Create `dsec/display.py`**

```python
"""
DSEC display helpers — resolve user-facing strings (model, mode, status)
from the layered config so the banner / status line never shows the
legacy DeepSeek default when multi-agent + Ollama pools are active.
"""
from __future__ import annotations
from typing import Any, Dict, Optional


def resolve_brain_display_model(config: Dict[str, Any], model_override: str = "") -> str:
    """Return the model string to display to the operator.

    Resolution order:
      1. Explicit `model_override` (passed via --model).
      2. If `enable_multi_agent` is true, the brain role's pool model.
      3. Legacy `config["default_model"]`.
      4. Final fallback: 'deepseek-expert-r1-search'.
    """
    if model_override:
        return model_override
    if config.get("enable_multi_agent"):
        roles = config.get("roles") or {}
        brain_entry = roles.get("brain") or {}
        # Role can override model directly
        explicit = brain_entry.get("model")
        if isinstance(explicit, str) and explicit.strip():
            return explicit.strip()
        provider_key = brain_entry.get("provider")
        if isinstance(provider_key, str) and provider_key.strip():
            providers = config.get("providers") or {}
            pool = providers.get(provider_key.strip()) or {}
            pool_model = pool.get("model")
            if isinstance(pool_model, str) and pool_model.strip():
                return pool_model.strip()
    return config.get("default_model") or "deepseek-expert-r1-search"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest dsec/tests/test_smoke.py::TestDisplayHelpers -v`
Expected: PASS.

- [ ] **Step 5: Update every legacy display site in `dsec/cli.py`**

Replace each occurrence of `config.get("default_model", "deepseek-expert-r1-search")` (and `cfg.get(...)` equivalents) **for display purposes** with the helper. Sites identified earlier:

```
dsec/cli.py:185, 209, 211, 3672, 4249
```

(Sites at 4726 / 4773 / 5234 are CLI flag help / role-config flow, not display — leave those as the literal default since they're typed by the user.)

For each site, change e.g.

```python
# before
shell_model = model_override or config.get("default_model", "deepseek-expert-r1-search")
# after
from dsec.display import resolve_brain_display_model
shell_model = resolve_brain_display_model(config, model_override or "")
```

Add the `from dsec.display import resolve_brain_display_model` import at the top of `cli.py` once, alongside the other `from dsec.*` imports.

- [ ] **Step 6: Add a smoke test for the banner path**

```python
def test_shell_banner_uses_brain_pool_model(self):
    """When multi-agent active, banner displays brain_pool model, not
    the legacy default_model string."""
    from dsec.display import resolve_brain_display_model
    cfg = {
        "enable_multi_agent": True,
        "default_model": "deepseek-expert-r1-search",
        "providers": {"brain_pool": {"type": "ollama",
                                     "model": "deepseek-v4-pro:cloud",
                                     "endpoints": ["http://x"]}},
        "roles": {"brain": {"provider": "brain_pool"}},
    }
    self.assertNotEqual(resolve_brain_display_model(cfg), "deepseek-expert-r1-search")
    self.assertIn("cloud", resolve_brain_display_model(cfg))
```

- [ ] **Step 7: Run full test suite**

Run: `python3 -m pytest dsec/tests/test_smoke.py -q`
Expected: PASS (existing 103 + 4 new = 107).

- [ ] **Step 8: Commit**

```bash
git add dsec/display.py dsec/cli.py dsec/tests/test_smoke.py
git commit -m "fix(ui): banner shows brain-pool model in multi-agent mode"
```

---

## Task 4: Default the shell to auto-mode

**Files:**
- Modify: `dsec/cli.py` (the `_launch_shell` initialiser around line 4180-4220)
- Test: `dsec/tests/test_smoke.py`

- [ ] **Step 1: Write the failing test**

```python
def test_shell_default_domain_is_auto(self):
    """Without an explicit --domain, the shell starts in auto mode."""
    from dsec import cli as cli_mod
    # Look for the literal default in the shell init path
    import inspect
    src = inspect.getsource(cli_mod._launch_shell)
    # New default should be 'auto' not 'htb'
    self.assertIn('"auto"', src)
    self.assertNotIn('domain_override or "htb"', src)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest dsec/tests/test_smoke.py -k test_shell_default_domain_is_auto -v`
Expected: FAIL.

- [ ] **Step 3: Update default**

Find the `_launch_shell` function. Locate the line that resolves `shell_domain` (something like `shell_domain = domain_override or detect_domain("", session_name) or "htb"`). Change to:

```python
shell_domain = domain_override or detect_domain("", session_name) or "auto"
```

(Note: `detect_domain` already returns `"auto"` after Task 2, so this default is now consistent.)

Also change the initial `state["domain_override"]` assignment so an unset domain stays empty (not forced to "htb"):

```python
state["domain_override"] = domain_override or ""
state["resolved_domain"] = shell_domain  # already "auto" after detect
```

- [ ] **Step 4: Run test**

Run: `python3 -m pytest dsec/tests/test_smoke.py -k test_shell_default_domain_is_auto -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add dsec/cli.py dsec/tests/test_smoke.py
git commit -m "feat(shell): auto-mode is the default — no /domain needed"
```

---

## Task 5: Live re-detection on every user prompt

**Files:**
- Modify: `dsec/cli.py:_run_chat` and / or the shell loop input handler
- Test: `dsec/tests/test_smoke.py`

When the user is in `auto` and sends a message that strongly indicates a specific category (e.g. they paste an HTB IP, mention `flag{`, name a CVE), upgrade the resolved domain for that turn — without permanently overriding the operator's `/domain auto` setting.

- [ ] **Step 1: Write the failing test**

```python
def test_auto_mode_redetects_on_user_input(self):
    """In auto mode, a user message naming a CTF challenge upgrades
    the resolved domain for that turn."""
    from dsec.domain import detect_domain
    self.assertEqual(detect_domain("solve this pwn challenge with flag{abc}"), "ctf")
    self.assertEqual(detect_domain("scan this 10.10.11.5 hackthebox box"), "htb")
    # neutral input stays auto
    self.assertEqual(detect_domain("hi", "auto-session"), "auto")
```

(That test is already covered by Task 2; the new piece is wiring it into `_run_chat`.)

- [ ] **Step 2: Wire re-detection in `_run_chat`**

In `dsec/cli.py:_run_chat`, just after `domain` is resolved (search for `domain = `), add:

```python
# Auto-mode live redetection: if the operator left domain=auto,
# upgrade the per-turn domain based on the user's message + cwd.
if domain == "auto":
    detected = detect_domain(message or "", session_name or "")
    if detected != "auto":
        domain = detected
```

- [ ] **Step 3: Add an integration smoke test**

```python
def test_run_chat_auto_promotes_to_ctf(self):
    """auto domain promotes to ctf when message contains 'flag{'"""
    from unittest import mock
    from dsec import cli as cli_mod
    captured = {}
    def fake_get_system_prompt(domain_name, **kw):
        captured["domain"] = domain_name
        return "stub"
    with mock.patch.object(cli_mod, "get_system_prompt", fake_get_system_prompt), \
         mock.patch.object(cli_mod, "chat_stream", lambda **kw: iter([{"type":"done","conversation_id":None}])), \
         mock.patch.object(cli_mod, "stream_response", lambda **kw: ("", "ok", "cid")):
        try:
            cli_mod._run_chat(
                message="flag{test} pwn challenge",
                session_name="t",
                domain_override="auto",
                model_override="",
                no_compress=True, no_think=True, no_research=True, no_memory=True,
                quick=True, _auto_exec=False,
            )
        except Exception:
            pass
    self.assertEqual(captured.get("domain"), "ctf")
```

- [ ] **Step 4: Run tests**

Run: `python3 -m pytest dsec/tests/test_smoke.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add dsec/cli.py dsec/tests/test_smoke.py
git commit -m "feat(auto): redetect domain per-turn from user input"
```

---

## Task 6: Banner displays multi-agent state + correct model

**Files:**
- Modify: `dsec/cli.py:_print_shell_banner` and `_print_shell_status`

- [ ] **Step 1: Update `_print_shell_banner` to display the resolved model**

Replace the current `model_s = _model_short(model)` (around line 3203 in `_print_shell_banner`) with the helper:

```python
from dsec.display import resolve_brain_display_model
config = load_config()
real_model = resolve_brain_display_model(config, model)
model_s = _model_short(real_model)
```

And, when `config.get("enable_multi_agent")`, append a multi-agent indicator line:

```python
if config.get("enable_multi_agent"):
    console.print(f"  [{p}]▸[/{p}] [bold]Mode:[/bold]     auto  "
                  f"[#666666]│[/]  [bold]Persona:[/bold] professional  "
                  f"[#666666]│[/]  [bold]Multi-agent:[/bold] [green]ON[/green]")
else:
    console.print(f"  [{p}]▸[/{p}] [bold]Mode:[/bold]     auto  [#666666]│[/]  [bold]Persona:[/bold] professional")
```

- [ ] **Step 2: Same fix in `_print_shell_status`**

In `dsec/cli.py:_print_shell_status` (around line 3306), replace the model line:

```python
info.append("Model:       ", style="bold")
info.append(f"{state['model_override'] or 'default'}\n")
```

with:

```python
from dsec.display import resolve_brain_display_model
real = resolve_brain_display_model(load_config(), state.get('model_override',''))
info.append("Model:       ", style="bold")
info.append(f"{real}\n", style="cyan")
# Show multi-agent status
if load_config().get("enable_multi_agent"):
    info.append("Multi-agent: ", style="bold")
    info.append("ON\n", style="bold green")
```

- [ ] **Step 3: Smoke-render**

```bash
python3 -c "
from dsec.cli import _print_shell_status
state = {
    'session_name':'shell-x','domain_override':'','model_override':'',
    'mode':'auto','personality':'professional',
    'no_compress':False,'no_think':False,'no_research':False,'no_memory':False,
    'auto_exec':True,'sudo_password':None,
}
_print_shell_status(state)
"
```

Expected: Status panel shows `Model: <brain pool model>` + `Multi-agent: ON`.

- [ ] **Step 4: Commit**

```bash
git add dsec/cli.py
git commit -m "fix(ui): banner + status show resolved model + multi-agent state"
```

---

## Task 7: `/mode` `auto` should be the explicit default + help update

**Files:**
- Modify: `dsec/cli.py:_print_shell_help` (around line 3239 in the help-panel string)

- [ ] **Step 1: Update help text**

Replace the `/mode` section in the help panel to mention auto-mode prominence:

```python
"[bold]/domain <name>[/bold]    set domain manually: [#888888]auto  htb  bugbounty  ctf  research  programmer[/]\n"
"                  [#888888](default: auto — task type inferred from cwd + your message every turn)[/]\n"
```

And in the banner-cmds row (around line 3214), confirm `/domain` is in the list.

- [ ] **Step 2: Smoke-render**

```bash
python3 -c "from dsec.cli import _print_shell_help; _print_shell_help()" | head -30
```

Expected: help text mentions `auto` as a domain choice and notes it's the default.

- [ ] **Step 3: Commit**

```bash
git add dsec/cli.py
git commit -m "docs(help): document auto-mode as default in /help panel"
```

---

## Task 8: Final verification run

**Files:** No edits — pure verification.

- [ ] **Step 1: Run pytest (must be 100% green)**

```bash
python3 -m pytest dsec/tests/test_smoke.py -q
```

Expected: 107 passed (103 prior + 4 new).

- [ ] **Step 2: Run the existing verification script**

```bash
python3 /tmp/verify_dsec.py
```

Expected: 39+ checks passing.

- [ ] **Step 3: Smoke a session start**

```bash
DSEC_AUTO_EXIT=1 python3 -m dsec --no-banner-timeout 2>&1 | head -30 || true
```

Manually inspect:
- Banner shows `Domain: Auto`
- `Model:` line shows `deepseek-v4-pro:cloud` (or whichever brain_pool model is configured), NOT `deepseek-expert-r1-search`.
- A `Multi-agent: ON` indicator is present.

- [ ] **Step 4: Commit a "verified" tag commit**

```bash
git add -A
git commit -m "test: verify auto-mode + banner fixes end-to-end"
```

---

## Self-Review Notes

- **Spec coverage** — every user requirement is mapped:
  - "auto mode default, gk perlu set domain" → Tasks 1-2-4 (auto domain, fallback, shell init).
  - "berubah sesuai kebutuhan" → Task 5 (per-turn redetection).
  - "model masih salah pas new session" → Tasks 3-6 (resolve_brain_display_model + banner + status).
  - "fix all UI / impl / functionality" → Task 6/7 (status, banner, help) + the integration test in Task 8.
- **Type consistency** — `resolve_brain_display_model(config, model_override="")` signature is identical in every site that imports it.
- **No placeholders** — every step has either a code block or an exact command + expected output.
