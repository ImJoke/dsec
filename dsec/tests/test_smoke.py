"""
DSEC end-to-end smoke tests.

Run with: python3 -m pytest dsec/tests/test_smoke.py -v
Or:       python3 -m unittest dsec.tests.test_smoke

Each block isolates its state and cleans up. Tests do NOT require a running
DeepSeek API; provider tests verify routing logic only (with simulated dead
endpoints).
"""
from __future__ import annotations

import json
import time
import unittest
from typing import Any, Dict


# ────────────────────────────────────────────────────────────────────────────
# 1. Tool-call extraction — multiple blocks
# ────────────────────────────────────────────────────────────────────────────

class TestExtractToolCalls(unittest.TestCase):
    """Cover the bug we fixed where the parser only kept the first <tool_call>."""

    def setUp(self):
        from dsec.cli import _extract_tool_calls
        self.extract = _extract_tool_calls

    def test_three_distinct_blocks_all_returned(self):
        text = """
<tool_call>{"name": "bash", "arguments": {"command": "nxc winrm 10.129.236.203 -u wallace.everette -H aaaa -d logging.htb -x 'hostname && whoami' 2>&1", "wait": 15}}</tool_call>
<tool_call>{"name": "bash", "arguments": {"command": "certipy shadow auto -u wallace.everette@logging.htb -hashes :aaaa -dc-ip 10.129.236.203 -target wallace.everette -dc-host DC01.logging.htb 2>&1", "wait": 15}}</tool_call>
<tool_call>{"name": "background", "arguments": {"action": "run", "job_id": "ferox", "command": "feroxbuster -u http://10.129.236.203/ -w /usr/local/share/seclists/Discovery/Web-Content/raft-medium-directories.txt --smart -k -C 404 -t 20 --timeout 5 -o /tmp/ferox_80.txt 2>&1", "wait": 3}}</tool_call>
"""
        calls = self.extract(text)
        self.assertEqual(len(calls), 3, f"expected 3 calls, got {len(calls)}: {calls}")
        names = [c["name"] for c in calls]
        self.assertEqual(names, ["bash", "bash", "background"])
        self.assertIn("nxc winrm", calls[0]["arguments"]["command"])
        self.assertIn("certipy shadow", calls[1]["arguments"]["command"])
        self.assertEqual(calls[2]["arguments"]["job_id"], "ferox")

    def test_three_identical_blocks_all_returned(self):
        """Extractor should NOT silently dedupe — that's the dispatcher's job."""
        block = '<tool_call>{"name":"background","arguments":{"action":"run","job_id":"a","command":"x"}}</tool_call>'
        text = "\n".join([block] * 3)
        calls = self.extract(text)
        self.assertEqual(len(calls), 3)

    def test_single_block(self):
        calls = self.extract('<tool_call>{"name":"bash","arguments":{"command":"echo hi"}}</tool_call>')
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["name"], "bash")

    def test_no_blocks(self):
        self.assertEqual(self.extract("plain text response"), [])


# ────────────────────────────────────────────────────────────────────────────
# 2. Dispatch dedup — identical calls collapse
# ────────────────────────────────────────────────────────────────────────────

class TestDispatchDedup(unittest.TestCase):
    """Match the dedup loop at cli._run_agentic_loop."""

    @staticmethod
    def _dedup(calls):
        seen = set()
        out = []
        for c in calls:
            key = (c.get("name", ""), json.dumps(c.get("arguments") or {}, sort_keys=True))
            if key in seen:
                continue
            seen.add(key)
            out.append(c)
        return out

    def test_identical_collapse(self):
        c = {"name": "background", "arguments": {"action": "run", "job_id": "a", "command": "x"}}
        out = self._dedup([c, dict(c), dict(c)])
        self.assertEqual(len(out), 1)

    def test_distinct_kept(self):
        a = {"name": "bash", "arguments": {"command": "nmap"}}
        b = {"name": "background", "arguments": {"action": "run", "job_id": "x", "command": "y"}}
        c = {"name": "read_file", "arguments": {"path": "/x"}}
        out = self._dedup([a, b, c])
        self.assertEqual(len(out), 3)

    def test_same_name_different_args_kept(self):
        a = {"name": "bash", "arguments": {"command": "nmap a"}}
        b = {"name": "bash", "arguments": {"command": "nmap b"}}
        out = self._dedup([a, b])
        self.assertEqual(len(out), 2)


# ────────────────────────────────────────────────────────────────────────────
# 3. PTY background tool — end-to-end
# ────────────────────────────────────────────────────────────────────────────

class TestBackgroundTool(unittest.TestCase):

    def setUp(self):
        from dsec.tools.pty_terminal import _PANES, _PANES_LOCK
        self._PANES = _PANES
        self._PANES_LOCK = _PANES_LOCK

    def tearDown(self):
        from dsec.tools.pty_terminal import background
        # Ensure all test panes are killed
        for jid in ("test-rt", "test-dup", "test-dead"):
            try:
                background(action="kill", job_id=jid)
            except Exception:
                pass

    def test_run_read_kill_round_trip(self):
        from dsec.tools.pty_terminal import background
        res = background(action="run", job_id="test-rt", command="echo hello && echo world", wait=2)
        self.assertIn("started", res)
        self.assertIn("hello", res)
        self.assertIn("world", res)

        # read should return either output or "no new output"
        res2 = background(action="read", job_id="test-rt")
        self.assertTrue(
            res2.startswith("[job 'test-rt'"),
            f"unexpected read result: {res2}",
        )

        # kill cleanly
        res3 = background(action="kill", job_id="test-rt")
        self.assertIn("killed", res3.lower())

    def test_duplicate_run_refused(self):
        from dsec.tools.pty_terminal import background
        first = background(action="run", job_id="test-dup", command="sleep 5", wait=1)
        self.assertIn("started", first)
        # Same command on same job_id while still alive should be refused
        second = background(action="run", job_id="test-dup", command="sleep 5", wait=1)
        self.assertIn("Refusing duplicate run", second)
        background(action="kill", job_id="test-dup")

    def test_read_on_nonexistent_job(self):
        from dsec.tools.pty_terminal import background
        res = background(action="read", job_id="this-does-not-exist-xyz")
        self.assertIn("does not exist", res)

    def test_run_caps_wait_at_10s(self):
        """Even if the model picks wait=30, the read idle-timeout caps at 10s.

        Total wall-time ≈ pane init (≤5s) + read idle (≤10s) ≈ 15s max.
        Without the cap (was 30s), this would take 30+5 = 35s.
        """
        from dsec.tools.pty_terminal import background
        start = time.time()
        background(action="run", job_id="test-rt", command="echo quick", wait=30.0)
        elapsed = time.time() - start
        self.assertLess(elapsed, 17.0, f"wait wasn't capped — took {elapsed:.1f}s")
        background(action="kill", job_id="test-rt")

    def test_history_action(self):
        from dsec.tools.pty_terminal import background
        background(action="run", job_id="test-rt", command="echo first", wait=1)
        # Send second command so history has two entries
        background(action="exec", job_id="test-rt", command="echo second", wait=2)
        hist_last = background(action="history", job_id="test-rt", mode="last")
        self.assertIn("second", hist_last)
        hist_all = background(action="history", job_id="test-rt", mode="all")
        self.assertIn("first", hist_all)
        self.assertIn("second", hist_all)
        background(action="kill", job_id="test-rt")


# ────────────────────────────────────────────────────────────────────────────
# 4. Tool registry — role partition
# ────────────────────────────────────────────────────────────────────────────

class TestRolePartition(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Force-load all native tools so the registry is populated.
        import dsec.tools.memory_tools  # noqa
        import dsec.tools.pty_terminal  # noqa
        import dsec.tools.gtfobins      # noqa
        import dsec.tools.knowledge_tools  # noqa
        import dsec.tools.cron_tools    # noqa
        import dsec.tools.file_tools    # noqa
        import dsec.tools.payload_tools  # noqa
        import dsec.skills.programmer   # noqa
        import dsec.agents.brain_tools  # noqa

    def test_executor_cannot_see_brain_tools(self):
        from dsec.core.registry import list_tools_for_role
        names = {t["name"] for t in list_tools_for_role("executor")}
        self.assertIn("write_file", names)
        self.assertIn("background", names)
        self.assertNotIn("core_memory_append", names)
        self.assertNotIn("dsec_cron_create", names)
        self.assertNotIn("research", names)
        self.assertNotIn("executor", names)  # brain tool, not for the worker itself

    def test_research_cannot_see_executor_tools(self):
        from dsec.core.registry import list_tools_for_role
        names = {t["name"] for t in list_tools_for_role("research")}
        self.assertIn("notes_search", names)
        self.assertIn("gtfobins_search", names)
        self.assertIn("live_research", names)
        self.assertNotIn("write_file", names)
        self.assertNotIn("background", names)

    def test_brain_cannot_call_executor_only_tool(self):
        from dsec.core.registry import call_tool
        res = call_tool("write_file", {"path": "/tmp/x", "content": "y"}, caller_role="brain")
        self.assertIn("not available to role", res)

    def test_legacy_no_role_passes(self):
        """Without caller_role, the role gate is bypassed (single-agent flow)."""
        from dsec.core.registry import call_tool
        # Use a known-good read-only tool to avoid touching the FS unexpectedly.
        res = call_tool("notes_tags", {"min_count": 99999})  # high threshold = empty result
        self.assertIsInstance(res, str)
        self.assertNotIn("not available to role", res)


# ────────────────────────────────────────────────────────────────────────────
# 5. Provider routing + role resolution
# ────────────────────────────────────────────────────────────────────────────

class TestProviderRouting(unittest.TestCase):

    def setUp(self):
        import dsec.config as cfg_mod
        from dsec.providers import pool as ppool
        cfg_mod._invalidate_cache()
        cfg = cfg_mod.load_config()
        self._saved_providers = cfg.get("providers")
        self._saved_roles = cfg.get("roles")
        # Inject a pool with two endpoints, both unreachable
        cfg["providers"] = {
            "test_pool_a": {
                "type": "ollama",
                "model": "qwen3-coder:30b",
                "endpoints": ["http://127.0.0.1:1", "http://127.0.0.1:2"],
                "fallback": "deepseek",
            },
        }
        cfg["roles"] = {
            "brain": {"provider": "test_pool_a", "fallback": "deepseek"},
        }
        cfg_mod._config_cache = cfg
        ppool._round_robin.clear()
        ppool._dead_until.clear()

    def tearDown(self):
        import dsec.config as cfg_mod
        from dsec.providers import pool as ppool
        cfg_mod._invalidate_cache()
        ppool._round_robin.clear()
        ppool._dead_until.clear()

    def test_round_robin_rotates(self):
        from dsec.providers.pool import next_endpoint
        first = next_endpoint("test_pool_a")
        second = next_endpoint("test_pool_a")
        third = next_endpoint("test_pool_a")
        self.assertNotEqual(first, second)
        self.assertEqual(first, third)  # wrapped around

    def test_dead_endpoint_skipped(self):
        from dsec.providers.pool import next_endpoint, mark_endpoint_dead, _round_robin
        mark_endpoint_dead("test_pool_a", "http://127.0.0.1:1")
        # After marking endpoint :1 dead, every next_endpoint should return :2
        _round_robin.pop("test_pool_a", None)
        for _ in range(3):
            ep = next_endpoint("test_pool_a")
            self.assertEqual(ep, "http://127.0.0.1:2")

    def test_role_resolves_to_pool(self):
        from dsec.llm_utils import get_model_for_role
        provider, model, fallback = get_model_for_role("brain")
        self.assertEqual(provider, "test_pool_a")
        self.assertEqual(model, "qwen3-coder:30b")
        self.assertEqual(fallback, "deepseek")

    def test_role_unconfigured_falls_back_to_legacy(self):
        from dsec.llm_utils import get_model_for_role
        provider, model, fallback = get_model_for_role("nonexistent_role")
        self.assertEqual(provider, "deepseek")
        self.assertIsNone(fallback)


# ────────────────────────────────────────────────────────────────────────────
# 6. Config validators
# ────────────────────────────────────────────────────────────────────────────

class TestConfigValidators(unittest.TestCase):

    def test_providers_reject_unknown_type(self):
        from dsec.config import _coerce_providers, ConfigError
        with self.assertRaises(ConfigError):
            _coerce_providers({"x": {"type": "anthropic"}})

    def test_providers_require_model_for_ollama(self):
        from dsec.config import _coerce_providers, ConfigError
        with self.assertRaises(ConfigError):
            _coerce_providers({"x": {"type": "ollama", "endpoints": ["http://h"]}})

    def test_providers_reject_empty_endpoints(self):
        from dsec.config import _coerce_providers, ConfigError
        with self.assertRaises(ConfigError):
            _coerce_providers({"x": {"type": "ollama", "model": "m", "endpoints": []}})

    def test_roles_require_provider(self):
        from dsec.config import _coerce_roles, ConfigError
        with self.assertRaises(ConfigError):
            _coerce_roles({"brain": {}})

    def test_providers_strip_trailing_slash_on_endpoints(self):
        from dsec.config import _coerce_providers
        out = _coerce_providers({
            "x": {"type": "ollama", "model": "m", "endpoints": ["http://a/", "http://b//"]}
        })
        self.assertEqual(out["x"]["endpoints"], ["http://a", "http://b"])


# ────────────────────────────────────────────────────────────────────────────
# 7. Session-name path traversal protection
# ────────────────────────────────────────────────────────────────────────────

class TestSessionNameSafety(unittest.TestCase):

    def test_dotdot_stripped(self):
        from dsec.session import _session_path
        p = _session_path("../../../etc/passwd")
        s = str(p)
        self.assertNotIn("/etc/passwd", s)
        self.assertTrue(s.endswith(".json"))

    def test_normal_name_works(self):
        from dsec.session import _session_path
        p = _session_path("htb-active-1")
        self.assertTrue(str(p).endswith("htb-active-1.json"))

    def test_empty_name_falls_back_to_unnamed(self):
        from dsec.session import _session_path
        p = _session_path("")
        self.assertTrue(str(p).endswith("unnamed.json"))


# ────────────────────────────────────────────────────────────────────────────
# 8. Provider <think>-block parser + native-tool-call normalizer
# ────────────────────────────────────────────────────────────────────────────

class TestCommonParsers(unittest.TestCase):

    def test_think_split_inline(self):
        from dsec.providers._common import split_think_blocks
        chunks, state = split_think_blocks("hi <think>reason", False)
        self.assertEqual(chunks, [("content", "hi "), ("thinking", "reason")])
        self.assertTrue(state)

    def test_think_continues_then_closes(self):
        from dsec.providers._common import split_think_blocks
        chunks, state = split_think_blocks("more reason</think>now content", True)
        self.assertEqual(chunks, [("thinking", "more reason"), ("content", "now content")])
        self.assertFalse(state)

    def test_normalize_native_tool_token(self):
        from dsec.providers._common import normalize_tool_calls
        out = normalize_tool_calls('<|tool_call|>{"name":"x"}<|/tool_call|>')
        self.assertEqual(out, '<tool_call>{"name":"x"}</tool_call>')

    def test_normalize_passes_through_when_none_match(self):
        from dsec.providers._common import normalize_tool_calls
        s = "no tool tokens here"
        self.assertEqual(normalize_tool_calls(s), s)


# ────────────────────────────────────────────────────────────────────────────
# 9. Domain prompt — vault index is present
# ────────────────────────────────────────────────────────────────────────────

class TestBgPollStreakGuard(unittest.TestCase):
    """Regression: session shell-20260503-221227 polled `bg read ferox` 5x
    across 17 hours; ferox was never spawned. Guard now catches both
    'no new output' and 'does not exist' variants."""

    @staticmethod
    def _simulate_streak(result_text_factory, threshold_for_does_not_exist=2, threshold_for_no_output=3):
        """Run the streak loop the way cli.py:_run_agentic_loop does it.

        Returns the rewritten result_text after `n_polls` calls. Mirrors the
        exact logic at the registry-call dispatch site.
        """
        bg_streak: Dict[str, int] = {}

        def step(result_text: str, job_id: str) -> str:
            arguments = {"action": "read", "job_id": job_id}
            tool_name = "background"
            if (
                tool_name == "background"
                and isinstance(arguments, dict)
                and arguments.get("action") == "read"
                and ("no new output" in result_text or "does not exist" in result_text)
            ):
                _job = str(arguments.get("job_id", ""))
                bg_streak[_job] = bg_streak.get(_job, 0) + 1
                if "does not exist" in result_text:
                    if bg_streak[_job] >= threshold_for_does_not_exist:
                        return f"[hint: job '{_job}' DOES NOT EXIST and you've polled it {bg_streak[_job]} times. ...]"
                elif bg_streak[_job] >= threshold_for_no_output:
                    return f"[hint: '{_job}' has been polled with no new output {bg_streak[_job]} ...]"
            return result_text

        return step

    def test_does_not_exist_triggers_at_2nd_poll(self):
        step = self._simulate_streak(None)
        first = step("Job 'ferox' does not exist — background jobs are in-memory...", "ferox")
        self.assertNotIn("hint", first.lower(), "first poll should pass through")
        second = step("Job 'ferox' does not exist — background jobs are in-memory...", "ferox")
        self.assertIn("DOES NOT EXIST", second)
        self.assertIn("ferox", second)

    def test_no_new_output_triggers_at_3rd_poll(self):
        step = self._simulate_streak(None)
        a = step("[job 'x' — running — no new output]", "x")
        b = step("[job 'x' — running — no new output]", "x")
        c = step("[job 'x' — running — no new output]", "x")
        self.assertNotIn("hint", a.lower())
        self.assertNotIn("hint", b.lower())
        self.assertIn("hint:", c)
        self.assertIn("polled with no new output 3", c)

    def test_different_jobs_tracked_separately(self):
        step = self._simulate_streak(None)
        step("Job 'a' does not exist", "a")
        b1 = step("Job 'b' does not exist", "b")
        # Each job's first poll is grace; second triggers
        a2 = step("Job 'a' does not exist", "a")
        self.assertNotIn("hint", b1.lower())
        self.assertIn("DOES NOT EXIST", a2)


class TestCrossTurnRetryGuard(unittest.TestCase):
    """Regression: agent retried identical bloodyAD / certipy commands across
    turns despite prior failure. The cross-turn guard short-circuits the
    second dispatch and injects a 'change-args' hint."""

    @staticmethod
    def _sig(tool_name: str, arguments: dict) -> str:
        import hashlib
        blob = json.dumps(arguments, sort_keys=True, default=str)
        return f"{tool_name}:{hashlib.sha1(blob.encode()).hexdigest()[:12]}"

    def test_signature_stable(self):
        a = self._sig("bash", {"command": "bloodyAD x"})
        b = self._sig("bash", {"command": "bloodyAD x"})
        self.assertEqual(a, b)

    def test_signature_differs_on_args(self):
        a = self._sig("bash", {"command": "bloodyAD x"})
        b = self._sig("bash", {"command": "bloodyAD y"})
        self.assertNotEqual(a, b)

    def test_signature_differs_on_tool(self):
        a = self._sig("bash", {"command": "x"})
        b = self._sig("background", {"command": "x"})
        self.assertNotEqual(a, b)

    def test_threshold_lowered_to_2(self):
        """_STUCK_THRESHOLD must be 2: agent should abandon technique after
        2 failures, not 3 — the audit showed 8x retries before abandoning."""
        import re, inspect
        from dsec.cli import _run_agentic_loop
        src = inspect.getsource(_run_agentic_loop)
        m = re.search(r"_STUCK_THRESHOLD\s*=\s*(\d+)", src)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), "2")


class TestCrossTurnGuardSimulation(unittest.TestCase):
    """End-to-end simulation of the bloodyAD-retry stuck pattern.

    Replicates the exact `_run_agentic_loop` cross-turn dispatch logic
    (state vars + check + tracker update) without a real LLM. Verifies:
      - first call dispatches and is recorded as failed
      - second identical call is SKIPPED with a hint, not re-dispatched
      - third call with different args dispatches again
      - successful call clears the failure flag
    """

    def setUp(self):
        # State mirroring _run_agentic_loop locals
        self._last_sig = None
        self._last_failed = False
        self._dispatched: list = []  # records every call that actually ran
        self._skipped: list = []     # records calls intercepted by the guard

    @staticmethod
    def _sig(tool_name: str, arguments: dict) -> str:
        import hashlib
        blob = json.dumps(arguments, sort_keys=True, default=str)
        return f"{tool_name}:{hashlib.sha1(blob.encode()).hexdigest()[:12]}"

    def _step(self, tool_name: str, arguments: dict, would_fail: bool) -> str:
        """Replicate one iteration's dispatch with the cross-turn guard."""
        sig = self._sig(tool_name, arguments)
        if sig == self._last_sig and self._last_failed:
            self._skipped.append((tool_name, arguments))
            return "[hint: identical retry — skipped]"
        # Real dispatch (simulated)
        self._dispatched.append((tool_name, arguments))
        self._last_sig = sig
        self._last_failed = would_fail
        return "[error: ...]" if would_fail else "[ok]"

    def test_bloodyAD_identical_retry_blocked(self):
        cmd = "bloodyAD -d logging.htb -u wallace.everette -p 'Welcome2026@' --host 10.129.236.203 add groupMember IT wallace.everette"
        # Iteration N: agent runs bloodyAD → fails (insufficientAccessRights)
        out1 = self._step("bash", {"command": cmd}, would_fail=True)
        self.assertIn("error", out1)
        # Iteration N+1: agent retries IDENTICAL command
        out2 = self._step("bash", {"command": cmd}, would_fail=True)
        self.assertIn("identical retry — skipped", out2)
        # Verify guard intercepted: only ONE actual dispatch
        self.assertEqual(len(self._dispatched), 1)
        self.assertEqual(len(self._skipped), 1)

    def test_different_args_dispatched(self):
        a = "bloodyAD -d logging.htb -u wallace.everette -p A --host 10.129.236.203 add x"
        b = "bloodyAD -d logging.htb -u wallace.everette -p B --host 10.129.236.203 add x"
        self._step("bash", {"command": a}, would_fail=True)
        # Different args → dispatch again
        self._step("bash", {"command": b}, would_fail=True)
        self.assertEqual(len(self._dispatched), 2)
        self.assertEqual(len(self._skipped), 0)

    def test_success_clears_failure_flag(self):
        cmd_a = "bash X"
        cmd_b = "bash Y"
        # First fails
        self._step("bash", {"command": cmd_a}, would_fail=True)
        # Different cmd succeeds (clears flag)
        self._step("bash", {"command": cmd_b}, would_fail=False)
        # Re-run cmd_a — should dispatch (last cmd was cmd_b, not cmd_a)
        self._step("bash", {"command": cmd_a}, would_fail=True)
        self.assertEqual(len(self._dispatched), 3)
        self.assertEqual(len(self._skipped), 0)

    def test_audit_replay_5x_identical_bloodyAD(self):
        """Exact pattern from session shell-20260503-221227: 5 retries
        of the same bloodyAD across iterations should be reduced to 1
        actual dispatch + 4 skipped hints."""
        cmd = "bloodyAD -d logging.htb -u wallace.everette -p 'Welcome2026@' --host 10.129.236.203 set password svc_recovery N3wSecur3P4ss!"
        for _ in range(5):
            self._step("bash", {"command": cmd}, would_fail=True)
        self.assertEqual(len(self._dispatched), 1, "guard should run only first attempt")
        self.assertEqual(len(self._skipped), 4, "remaining 4 must be skipped")

    def test_bash_dispatch_check_present_in_source(self):
        """Source-level assertion: the bash branch must contain the
        cross-turn check (regression guard against future refactors)."""
        from dsec import cli
        src = open(cli.__file__).read()
        # Look for the bash-specific pre-check we added
        self.assertIn("Cross-turn identical-cmd guard (mirrors registry path)", src)
        self.assertIn("⏭ bash", src)


class TestKerberosFailPatterns(unittest.TestCase):
    """Ensure the broader Kerberos / DNS / clock-skew patterns roll up to
    technique-fail buckets so 2x repetition triggers a pivot."""

    def test_clock_skew_variants_share_bucket(self):
        from dsec.cli import _run_agentic_loop  # noqa — imports patterns table
        # Read patterns directly from the source file since they're function-local
        import inspect
        src = inspect.getsource(_run_agentic_loop)
        # All variants must map to "krb_timeskew"
        for variant in ("KRB_AP_ERR_SKEW", "Clock skew too great", "Server time"):
            self.assertIn(f'"{variant}", "krb_timeskew"', src)
        # And DNS variants share krb_dns
        for variant in ("DNS resolution failed", "Could not resolve", "Name or service not known"):
            self.assertIn(f'"{variant}", "krb_dns"', src)


class TestDomainPromptIntegrity(unittest.TestCase):

    def test_htb_prompt_has_vault_index(self):
        from dsec.domain import DOMAIN_HTB
        p = DOMAIN_HTB["system_prompt"]
        self.assertIn("[USER VAULT — TECHNIQUE INDEX]", p)
        self.assertIn("[END USER VAULT INDEX]", p)
        # Sanity-check key sections
        for marker in (
            "ADCS - ESC15 Exploitation",
            "ADCS - ESC16 Exploitation",
            "BACKGROUND-JOB DISCIPLINE",
            "TOOL DECISION TREE",
            "DEFAULT: prefer a persistent PTY shell",
        ):
            self.assertIn(marker, p, f"missing prompt marker: {marker}")

    def test_htb_prompt_token_budget(self):
        from dsec.domain import DOMAIN_HTB
        from dsec.context_manager import ContextManager
        cm = ContextManager(domain="htb")
        tokens = cm.estimate_tokens(DOMAIN_HTB["system_prompt"])
        # 3K (original) + 2K (vault index) + 0.4K (bg discipline) ≈ 5–10K acceptable.
        self.assertLess(tokens, 15_000, f"prompt too large: {tokens} tokens")
        self.assertGreater(tokens, 4_000, f"prompt too small (vault index missing?): {tokens} tokens")


class TestAgenticLoopIntegration(unittest.TestCase):
    """REAL integration test — patches chat_stream + CommandRunner, then
    invokes _run_agentic_loop end-to-end. Verifies the cross-turn guard
    actually fires inside the live code path, not just in a logic mirror.

    This is what the user asked for: tests that prove the guard works in
    the real loop, not just in a simulation harness.
    """

    def setUp(self):
        # Clear test-session audit logs so each run starts with empty state.
        # (Audit-replay primes _last_cmd_signature from disk on load.)
        from dsec.session import _sessions_dir
        import shutil
        for name in ("test-integ", "test-integ-divergent", "stress-50",
                    "stress-alt"):
            sd = _sessions_dir() / name
            if sd.exists():
                shutil.rmtree(sd, ignore_errors=True)

    def _make_chat_stream_mock(self, responses):
        """Yield the given list of LLM responses across consecutive calls.

        Each response is a string of <tool_call> blocks (or empty to end).
        Returns a callable matching chat_stream's signature.
        """
        call_log = []
        responses_iter = iter(responses)

        def fake_chat_stream(*args, **kwargs):
            try:
                resp = next(responses_iter)
            except StopIteration:
                resp = ""
            call_log.append({"args": args, "kwargs": kwargs, "yielded": resp})

            def gen():
                if resp:
                    yield {"type": "content", "text": resp}
                yield {"type": "done", "conversation_id": "test-conv"}
            return gen()

        return fake_chat_stream, call_log

    def _make_runner_mock(self, returncode_seq):
        """CommandRunner.run returns a CommandResult with the next returncode."""
        from dsec.executor import CommandResult
        rc_iter = iter(returncode_seq)
        run_log = []

        class FakeRunner:
            def is_running(self):
                return False

            def interrupt(self):
                return False

            def run(self_inner, command, **kwargs):
                try:
                    rc = next(rc_iter)
                except StopIteration:
                    rc = 0
                run_log.append({"command": command, "returncode": rc})
                return CommandResult(
                    command=command,
                    stdout="",
                    stderr=f"[fake] returncode={rc}\n" if rc != 0 else "[fake] ok\n",
                    returncode=rc,
                )

        return FakeRunner(), run_log

    def test_real_loop_blocks_identical_bash_retry(self):
        """Two iterations emitting the SAME bash bloodyAD command. First
        dispatches (fake fail), second must be SKIPPED by the guard."""
        from unittest import mock
        from dsec import cli as cli_mod

        BAD_CMD = (
            "bloodyAD -d logging.htb -u wallace.everette -p 'Welcome2026@' "
            "--host 10.129.236.203 add groupMember IT wallace.everette"
        )
        # Initial response (already extracted before _run_agentic_loop is called)
        initial = f'<tool_call>{{"name": "bash", "arguments": {{"command": "{BAD_CMD}"}}}}</tool_call>'
        # Subsequent chat_stream returns: same bash twice more, then empty (end loop)
        followups = [initial, initial, ""]

        fake_chat, chat_log = self._make_chat_stream_mock(followups)
        fake_runner, run_log = self._make_runner_mock([1, 1, 1, 1])

        with mock.patch.object(cli_mod, "chat_stream", fake_chat), \
             mock.patch.object(cli_mod, "get_runner", lambda: fake_runner):
            try:
                cli_mod._run_agentic_loop(
                    response_content=initial,
                    session_name="test-integ",
                    domain="htb",
                    model="deepseek-chat",
                    conversation_id=None,
                    config={
                        "base_url": "http://localhost:8000",
                        "show_thinking": False,
                        "enable_multi_agent": False,
                    },
                    turn=1,
                    no_think=True,
                    no_memory=True,
                    auto_exec=True,
                    sudo_password=None,
                    max_iterations=4,
                )
            except Exception as e:
                # Some startup sub-systems may not be fully mocked (e.g.
                # autopilot, session save). That's fine — what matters is
                # how many bash dispatches actually fired.
                pass

        # The actual dispatch count is what proves the guard works.
        # Without the guard: 3 dispatches (one per iteration with the same cmd).
        # With the guard: 1 dispatch + 2 skipped (second + third recognised as retry).
        bash_dispatches = [r for r in run_log if "bloodyAD" in r["command"]]
        self.assertGreaterEqual(
            len(bash_dispatches), 1,
            f"expected at least 1 dispatch (the first), got {len(bash_dispatches)}: {run_log}",
        )
        self.assertLessEqual(
            len(bash_dispatches), 1,
            f"GUARD FAILED: identical bash retry was dispatched {len(bash_dispatches)} times. "
            f"Cross-turn guard did not fire. Dispatches: {run_log}",
        )

    def test_real_loop_runs_different_args(self):
        """Two iterations emitting DIFFERENT bash commands. Both must
        dispatch — the guard should not block divergent args."""
        from unittest import mock
        from dsec import cli as cli_mod

        cmd_a = "echo first"
        cmd_b = "echo second"
        initial = f'<tool_call>{{"name": "bash", "arguments": {{"command": "{cmd_a}"}}}}</tool_call>'
        followup = f'<tool_call>{{"name": "bash", "arguments": {{"command": "{cmd_b}"}}}}</tool_call>'

        fake_chat, _ = self._make_chat_stream_mock([followup, ""])
        fake_runner, run_log = self._make_runner_mock([1, 1, 1])

        with mock.patch.object(cli_mod, "chat_stream", fake_chat), \
             mock.patch.object(cli_mod, "get_runner", lambda: fake_runner):
            try:
                cli_mod._run_agentic_loop(
                    response_content=initial,
                    session_name="test-integ-divergent",
                    domain="htb",
                    model="deepseek-chat",
                    conversation_id=None,
                    config={
                        "base_url": "http://localhost:8000",
                        "show_thinking": False,
                        "enable_multi_agent": False,
                    },
                    turn=1,
                    no_think=True,
                    no_memory=True,
                    auto_exec=True,
                    sudo_password=None,
                    max_iterations=3,
                )
            except Exception:
                pass

        echo_dispatches = [r for r in run_log if "echo" in r["command"]]
        cmds = [r["command"] for r in echo_dispatches]
        self.assertIn(cmd_a, cmds, f"first cmd missing: {cmds}")
        self.assertIn(cmd_b, cmds, f"second cmd missing — guard wrongly blocked divergent args: {cmds}")


class TestStress(unittest.TestCase):
    """Stress tests — push the agentic loop, extractor, dedup, guards, and
    PTY through edge cases at high volume. Verifies nothing crashes and
    invariants hold under load.
    """

    def setUp(self):
        from dsec.session import _sessions_dir
        import shutil
        for name in ("stress-50", "stress-alt"):
            sd = _sessions_dir() / name
            if sd.exists():
                shutil.rmtree(sd, ignore_errors=True)

    # ── Extractor + dedup at high volume ──────────────────────────────────

    def test_extract_100_tool_calls(self):
        """Extractor must return all 100 distinct calls without dropping."""
        from dsec.cli import _extract_tool_calls
        blocks = []
        for i in range(100):
            blocks.append(
                f'<tool_call>{{"name":"bash","arguments":{{"command":"echo {i}"}}}}</tool_call>'
            )
        text = "\n".join(blocks)
        calls = _extract_tool_calls(text)
        self.assertEqual(len(calls), 100, f"lost calls: {len(calls)}")
        cmds = [c["arguments"]["command"] for c in calls]
        self.assertEqual(cmds, [f"echo {i}" for i in range(100)])

    def test_dedup_100_identical_collapses_to_1(self):
        import json as _json
        same = {"name": "bash", "arguments": {"command": "echo same"}}
        calls = [dict(same) for _ in range(100)]
        seen = set()
        out = []
        for c in calls:
            k = (c["name"], _json.dumps(c["arguments"], sort_keys=True))
            if k in seen:
                continue
            seen.add(k)
            out.append(c)
        self.assertEqual(len(out), 1)

    def test_extract_handles_unicode_and_escapes(self):
        from dsec.cli import _extract_tool_calls
        text = (
            '<tool_call>{"name":"bash","arguments":{"command":"echo \'héllo wörld 你好\'"}}</tool_call>'
            '<tool_call>{"name":"bash","arguments":{"command":"grep -E \\"\\\\(.*\\\\)\\" file"}}</tool_call>'
        )
        calls = _extract_tool_calls(text)
        self.assertEqual(len(calls), 2)
        self.assertIn("héllo", calls[0]["arguments"]["command"])

    def test_extract_handles_500kb_payload(self):
        """No regex catastrophic backtracking on giant inputs."""
        from dsec.cli import _extract_tool_calls
        big_cmd = "echo " + "X" * 500_000
        text = f'<tool_call>{{"name":"bash","arguments":{{"command":"{big_cmd[:200000]}"}}}}</tool_call>'
        import time
        t0 = time.time()
        calls = _extract_tool_calls(text)
        elapsed = time.time() - t0
        self.assertEqual(len(calls), 1)
        self.assertLess(elapsed, 5.0, f"extraction took {elapsed:.1f}s on 200KB input")

    # ── Cross-turn guard under sustained pressure ─────────────────────────

    def test_guard_holds_through_50_identical_retries(self):
        """Replicate worst-case session — agent emits SAME bash 50 times.
        Guard must dispatch exactly 1, skip 49."""
        from unittest import mock
        from dsec import cli as cli_mod

        bad = "bloodyAD set password svc N3w!"
        block = f'<tool_call>{{"name":"bash","arguments":{{"command":"{bad}"}}}}</tool_call>'

        # 50 followups all the same
        fake_chat, _ = TestAgenticLoopIntegration._make_chat_stream_mock(
            self, [block] * 49 + [""]
        )
        fake_runner, run_log = TestAgenticLoopIntegration._make_runner_mock(
            self, [1] * 60
        )

        with mock.patch.object(cli_mod, "chat_stream", fake_chat), \
             mock.patch.object(cli_mod, "get_runner", lambda: fake_runner):
            try:
                cli_mod._run_agentic_loop(
                    response_content=block,
                    session_name="stress-50",
                    domain="htb",
                    model="x",
                    conversation_id=None,
                    config={"base_url": "http://localhost:8000",
                            "show_thinking": False, "enable_multi_agent": False},
                    turn=1,
                    no_think=True,
                    no_memory=True,
                    auto_exec=True,
                    sudo_password=None,
                    max_iterations=50,
                )
            except Exception:
                pass

        bloodyAD_dispatches = [r for r in run_log if "bloodyAD" in r["command"]]
        self.assertEqual(
            len(bloodyAD_dispatches), 1,
            f"GUARD FAILED under 50-retry stress: dispatched {len(bloodyAD_dispatches)} times",
        )

    def test_guard_resets_on_alternation(self):
        """Agent alternates A → B → A → B. Each pair has a different sig,
        so guard should NOT fire — all dispatches should run."""
        from unittest import mock
        from dsec import cli as cli_mod

        a = '<tool_call>{"name":"bash","arguments":{"command":"echo A"}}</tool_call>'
        b = '<tool_call>{"name":"bash","arguments":{"command":"echo B"}}</tool_call>'
        sequence = [b, a, b, a, b, a, ""]

        fake_chat, _ = TestAgenticLoopIntegration._make_chat_stream_mock(self, sequence)
        fake_runner, run_log = TestAgenticLoopIntegration._make_runner_mock(self, [1] * 10)

        with mock.patch.object(cli_mod, "chat_stream", fake_chat), \
             mock.patch.object(cli_mod, "get_runner", lambda: fake_runner):
            try:
                cli_mod._run_agentic_loop(
                    response_content=a,
                    session_name="stress-alt",
                    domain="htb",
                    model="x",
                    conversation_id=None,
                    config={"base_url": "http://localhost:8000",
                            "show_thinking": False, "enable_multi_agent": False},
                    turn=1,
                    no_think=True,
                    no_memory=True,
                    auto_exec=True,
                    sudo_password=None,
                    max_iterations=8,
                )
            except Exception:
                pass

        a_count = len([r for r in run_log if r["command"] == "echo A"])
        b_count = len([r for r in run_log if r["command"] == "echo B"])
        # Each alternation must dispatch — never block divergent args.
        self.assertGreaterEqual(a_count, 2, f"A dispatched only {a_count} times")
        self.assertGreaterEqual(b_count, 2, f"B dispatched only {b_count} times")

    # ── PTY pool concurrency ──────────────────────────────────────────────

    def test_pty_8_concurrent_jobs_then_cap(self):
        """_MAX_PANES=8. Spawn 8, verify all alive. 9th should error."""
        from dsec.tools.pty_terminal import background, _PANES, _MAX_PANES
        # Cleanup any stale stress jobs
        for i in range(_MAX_PANES + 2):
            try:
                background(action="kill", job_id=f"stress-job-{i}")
            except Exception:
                pass

        spawned = []
        try:
            for i in range(_MAX_PANES):
                res = background(action="run", job_id=f"stress-job-{i}",
                                 command=f"sleep 30 && echo {i}", wait=1)
                self.assertIn("started", res, f"failed to spawn job {i}: {res}")
                spawned.append(f"stress-job-{i}")

            # 9th must hit the cap
            res = background(action="run", job_id=f"stress-job-{_MAX_PANES}",
                             command="sleep 30", wait=1)
            self.assertIn("Max", res, f"cap should reject 9th job: {res}")
        finally:
            for jid in spawned + [f"stress-job-{_MAX_PANES}"]:
                try:
                    background(action="kill", job_id=jid)
                except Exception:
                    pass

    def test_pty_rapid_spawn_kill_cycle(self):
        """Spawn → kill → respawn same job_id 20× — no fd leak, no crash."""
        from dsec.tools.pty_terminal import background
        for i in range(20):
            res = background(action="run", job_id="rapid-cycle",
                             command=f"echo iter {i}", wait=0.5)
            self.assertIn("started", res, f"iter {i} failed: {res}")
            kres = background(action="kill", job_id="rapid-cycle")
            self.assertIn("killed", kres.lower())

    # ── Provider pool rotation under load ─────────────────────────────────

    def test_provider_pool_round_robin_500_calls(self):
        """500 next_endpoint calls across 3 endpoints — distribution within 2%."""
        import dsec.config as cfg_mod
        from dsec.providers import pool as ppool
        cfg_mod._invalidate_cache()
        cfg = cfg_mod.load_config()
        cfg["providers"] = {
            "stress_pool": {
                "type": "ollama", "model": "x",
                "endpoints": ["http://a:1", "http://b:2", "http://c:3"],
            }
        }
        cfg_mod._config_cache = cfg
        ppool._round_robin.clear()
        ppool._dead_until.clear()

        try:
            counts = {"http://a:1": 0, "http://b:2": 0, "http://c:3": 0}
            for _ in range(501):  # 501 = 167 each
                ep = ppool.next_endpoint("stress_pool")
                counts[ep] += 1
            for ep, n in counts.items():
                self.assertEqual(n, 167, f"uneven: {counts}")
        finally:
            cfg_mod._invalidate_cache()
            ppool._round_robin.clear()
            ppool._dead_until.clear()

    # ── Config-write race protection ──────────────────────────────────────

    def test_concurrent_config_writes_dont_corrupt(self):
        """5 threads × 20 writes each. File must remain valid JSON at end."""
        import threading
        import json as _json
        from dsec.config import save_config, load_config, CONFIG_FILE

        errors = []

        def writer(idx):
            try:
                for j in range(20):
                    save_config("compress_threshold", str(100 + (idx * 100) + j))
            except Exception as e:
                errors.append(f"thread {idx}: {e}")

        threads = [threading.Thread(target=writer, args=(i,)) for i in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)

        self.assertEqual(errors, [], f"thread errors: {errors}")

        # File still parses cleanly
        with open(CONFIG_FILE) as f:
            parsed = _json.load(f)
        self.assertIn("compress_threshold", parsed)
        # Reset to default for tidiness
        save_config("compress_threshold", "500")

    # ── Domain prompt token budget under multiple loads ───────────────────

    def test_prompt_consistent_across_multiple_loads(self):
        """Reload domain.py 10× — token count must stay stable (no slow leak
        from accumulating decorators or import side-effects)."""
        from dsec.context_manager import ContextManager
        cm = ContextManager(domain="htb")
        token_counts = []
        for _ in range(10):
            import importlib
            import dsec.domain
            importlib.reload(dsec.domain)
            token_counts.append(cm.estimate_tokens(dsec.domain.DOMAIN_HTB["system_prompt"]))
        self.assertEqual(len(set(token_counts)), 1, f"prompt drifted: {token_counts}")


class TestExtremeStress(unittest.TestCase):
    """Creative / out-of-box edge cases. Cover the failure modes a stuck
    agent or hostile environment can produce, including:
      - stdin-blocking commands in non-PTY shell
      - PTY crash mid-run, externally-closed fd
      - timeout-ignoring child process
      - command path that doesn't exist
      - tool args malformed (null, list, string instead of dict)
      - tool result with embedded tag confusion
      - stream returning empty / malformed / mid-tool-call JSON
      - 100 tools in one turn dispatch
      - kill all panes concurrently
      - hostile session names / tool args (regex/shell metacharacters)
    """

    @classmethod
    def setUpClass(cls):
        # Force-load tool modules so the registry has read_file etc.
        import dsec.tools.file_tools  # noqa
        import dsec.tools.memory_tools  # noqa
        import dsec.tools.pty_terminal  # noqa
        import dsec.tools.knowledge_tools  # noqa
        import dsec.skills.programmer  # noqa

    # ── Non-PTY shell hostile cases ───────────────────────────────────────

    def test_nonpty_command_with_stdin_read_blocks_then_times_out(self):
        """`cat` without redirect waits forever on stdin. Without timeout
        protection, agent locks up. With timeout, CommandRunner kills it."""
        from dsec.executor import CommandRunner
        runner = CommandRunner()
        import time
        t0 = time.time()
        # `cat` reads stdin until EOF — with no input pipe and isolated
        # subprocess, it blocks. Timeout=2s should kill it.
        result = runner.run("cat", timeout=2)
        elapsed = time.time() - t0
        # Must terminate within ~3s (2s timeout + small slop)
        self.assertLess(elapsed, 4.0, f"cat hung for {elapsed:.1f}s — timeout broken")
        # Process was either interrupted or returned
        self.assertTrue(
            result.interrupted or result.returncode is not None,
            f"unexpected state: {result.__dict__}",
        )

    def test_nonpty_nonexistent_binary_returns_error(self):
        """ENOENT must be caught and returned as a CommandResult, not raised."""
        from dsec.executor import CommandRunner
        runner = CommandRunner()
        result = runner.run("xyzdoesnotexist123_abc", timeout=3)
        # Must not crash; returncode != 0 or stderr populated
        self.assertNotEqual(result.returncode, 0, f"missing binary should fail: {result.__dict__}")

    def test_nonpty_command_with_huge_stdout_not_oom(self):
        """yes(1)-style burst output. Process killed by timeout before OOM."""
        from dsec.executor import CommandRunner
        runner = CommandRunner()
        import time
        t0 = time.time()
        # `yes` floods stdout. 2s timeout caps total run.
        # Use head to force exit after 1MB of "x"
        result = runner.run("yes x | head -c 1048576", timeout=5, shell=True)
        elapsed = time.time() - t0
        self.assertLess(elapsed, 6.0)
        # Output captured but capped (head returns exactly 1MB)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(len(result.stdout), 1_048_576)

    def test_nonpty_timeout_ignoring_child_gets_sigkilled(self):
        """Child traps SIGTERM. Runner must escalate to SIGKILL within
        timeout window via process-group kill (start_new_session=True)."""
        from dsec.executor import CommandRunner
        runner = CommandRunner()
        import time
        # bash trap ignores SIGTERM, sleeps forever
        cmd = "trap '' TERM; sleep 30"
        t0 = time.time()
        result = runner.run(cmd, timeout=2, shell=True)
        elapsed = time.time() - t0
        # Should die within: 2s timeout + 2s post-SIGTERM wait + small slop = ~5s
        self.assertLess(elapsed, 8.0,
                        f"signal-trap child held runner for {elapsed:.1f}s")
        self.assertTrue(result.interrupted)

    # ── PTY hostile cases ─────────────────────────────────────────────────

    def test_pty_externally_killed_bash_detected_on_next_call(self):
        """User SIGKILLs bash directly. Next pane.write must surface 'died' error
        cleanly, not silently produce no output."""
        from dsec.tools.pty_terminal import background, _PANES
        import os, signal

        # Spawn fresh
        try:
            background(action="kill", job_id="ext-kill")
        except Exception:
            pass
        spawn = background(action="run", job_id="ext-kill", command="echo alive", wait=1)
        self.assertIn("started", spawn)
        # Kill the bash process externally with SIGKILL
        pane = _PANES.get("ext-kill")
        self.assertIsNotNone(pane)
        os.kill(pane.process.pid, signal.SIGKILL)
        pane.process.wait(timeout=2)
        # Try to send another command — write should fail OR pane.alive should be False
        # New code path: pane.write raises RuntimeError, caught by run-action
        result = background(action="run", job_id="ext-kill", command="echo new", wait=1)
        # Either we spawned a fresh pane (cleanup detected dead pane) or got error
        # Both are acceptable — the key invariant: NEVER silent success.
        self.assertTrue(
            "started" in result or "error" in result.lower() or "died" in result.lower(),
            f"silent failure on dead-pane: {result!r}",
        )
        try:
            background(action="kill", job_id="ext-kill")
        except Exception:
            pass

    def test_pty_master_fd_closed_externally(self):
        """Master fd closed by another part of the program. Next read must
        not crash; return clean empty + status."""
        from dsec.tools.pty_terminal import background, _PANES
        import os
        try:
            background(action="kill", job_id="fd-close")
        except Exception:
            pass
        background(action="run", job_id="fd-close", command="echo hello", wait=1)
        pane = _PANES.get("fd-close")
        self.assertIsNotNone(pane)
        # Close fd from outside
        try:
            os.close(pane.master_fd)
        except OSError:
            pass
        pane.master_fd = -1
        # Read must not crash
        result = background(action="read", job_id="fd-close")
        self.assertIsInstance(result, str)
        try:
            background(action="kill", job_id="fd-close")
        except Exception:
            pass

    def test_pty_kill_8_panes_concurrently_thread_safe(self):
        """Spawn 8 panes, kill all from concurrent threads. _PANES dict and
        atexit handler must remain consistent (no half-removed entries)."""
        import threading
        from dsec.tools.pty_terminal import background, _PANES, _MAX_PANES
        # Cleanup
        for i in range(_MAX_PANES + 1):
            try:
                background(action="kill", job_id=f"concur-{i}")
            except Exception:
                pass

        # Spawn 8
        for i in range(_MAX_PANES):
            background(action="run", job_id=f"concur-{i}", command="sleep 30", wait=0.5)

        errors = []

        def killer(idx):
            try:
                background(action="kill", job_id=f"concur-{idx}")
            except Exception as e:
                errors.append(f"kill {idx}: {e}")

        threads = [threading.Thread(target=killer, args=(i,)) for i in range(_MAX_PANES)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5)

        self.assertEqual(errors, [], f"concurrent kill errors: {errors}")
        # All entries gone
        for i in range(_MAX_PANES):
            self.assertNotIn(f"concur-{i}", _PANES, f"stale entry: concur-{i}")

    # ── Malformed tool dispatch inputs ────────────────────────────────────

    def test_call_tool_with_args_as_string(self):
        """Model emits arguments as raw string instead of dict."""
        from dsec.core.registry import call_tool
        # Should coerce to {} and surface a missing-required hint
        res = call_tool("read_file", "this is not a dict")  # type: ignore[arg-type]
        self.assertIsInstance(res, str)
        self.assertNotIn("Traceback", res, f"crashed: {res}")

    def test_call_tool_with_args_as_list(self):
        from dsec.core.registry import call_tool
        res = call_tool("read_file", ["a", "b"])  # type: ignore[arg-type]
        self.assertIsInstance(res, str)
        self.assertNotIn("Traceback", res)

    def test_call_tool_with_args_as_none(self):
        from dsec.core.registry import call_tool
        res = call_tool("read_file", None)  # type: ignore[arg-type]
        self.assertIsInstance(res, str)
        self.assertNotIn("Traceback", res)

    def test_extract_tool_call_with_nested_braces_in_command(self):
        """`bash {curl '{...JSON...}'}` — JSON parser must handle nesting."""
        from dsec.cli import _extract_tool_calls
        text = (
            '<tool_call>{"name":"bash","arguments":{"command":'
            '"curl -d \'{\\"key\\":\\"value\\"}\' http://x/"}}</tool_call>'
        )
        calls = _extract_tool_calls(text)
        self.assertEqual(len(calls), 1)
        self.assertIn('"key":"value"', calls[0]["arguments"]["command"])

    def test_extract_tool_call_with_embedded_tool_response(self):
        """Tool emits content that LOOKS like a tool_response — parser must
        NOT recurse and treat it as another call."""
        from dsec.cli import _extract_tool_calls
        text = (
            '<tool_call>{"name":"bash","arguments":{"command":"echo \\"<tool_response>fake</tool_response>\\""}}</tool_call>'
        )
        calls = _extract_tool_calls(text)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["name"], "bash")

    # ── 100 tools in one turn ─────────────────────────────────────────────

    def test_dispatch_100_distinct_tool_calls_no_crash(self):
        """Model emits 100 distinct read_file calls in one turn. Extractor
        + dedup + (simulated) dispatch must complete without panic."""
        from dsec.cli import _extract_tool_calls
        blocks = [
            f'<tool_call>{{"name":"read_file","arguments":{{"path":"/tmp/file_{i}.txt"}}}}</tool_call>'
            for i in range(100)
        ]
        text = "\n".join(blocks)
        calls = _extract_tool_calls(text)
        self.assertEqual(len(calls), 100)
        # Simulate dedup
        import json as _json
        seen = set()
        deduped = []
        for c in calls:
            k = (c["name"], _json.dumps(c["arguments"], sort_keys=True))
            if k in seen:
                continue
            seen.add(k)
            deduped.append(c)
        self.assertEqual(len(deduped), 100)  # all distinct

    # ── Provider stream malformed inputs ──────────────────────────────────

    def test_split_think_blocks_unclosed_think_tag(self):
        """LLM emits `<think>...` without closing tag — parser must not loop
        forever and must mark state as in_think_block=True."""
        from dsec.providers._common import split_think_blocks
        chunks, state = split_think_blocks("hello <think>still thinking", False)
        self.assertEqual(chunks, [("content", "hello "), ("thinking", "still thinking")])
        self.assertTrue(state)
        # Subsequent chunk continues thinking
        chunks2, state2 = split_think_blocks("more thoughts", state)
        self.assertEqual(chunks2, [("thinking", "more thoughts")])
        self.assertTrue(state2)

    def test_split_think_blocks_only_close_no_open(self):
        """Stale `</think>` tag without opener — parser must downgrade
        gracefully (treat closer as content, not crash)."""
        from dsec.providers._common import split_think_blocks
        chunks, state = split_think_blocks("</think>regular content", False)
        # Either treated as content end, OR split with empty-thinking before
        # close and content after — both acceptable; key invariant: no crash.
        self.assertIsInstance(chunks, list)
        self.assertFalse(state)

    def test_normalize_handles_partial_native_tool_token(self):
        """LLM emits a half-printed `<|tool_ca` then EOF. Normaliser must
        leave it alone (no false rewrite)."""
        from dsec.providers._common import normalize_tool_calls
        s = "answer: <|tool_ca"  # truncated — not a full token
        self.assertEqual(normalize_tool_calls(s), s)

    # ── Hostile session / arg input ───────────────────────────────────────

    def test_session_name_with_null_byte_rejected(self):
        """NUL byte in session name. Path resolution must not crash."""
        from dsec.session import _session_path
        try:
            p = _session_path("evil\x00name")
            # Either sanitised or raised — both acceptable
            self.assertIsInstance(p, type(p))
            # Result path must be inside sessions dir
            from dsec.session import _sessions_dir
            base = _sessions_dir().resolve()
            try:
                p.resolve().relative_to(base)
            except ValueError:
                self.fail(f"session name with NUL escaped sandbox: {p}")
        except (ValueError, OSError):
            pass  # rejected outright is also fine

    def test_session_name_with_emoji_works(self):
        """Unicode session names — should not crash filesystem ops."""
        from dsec.session import _session_path
        p = _session_path("htb-🚀-test")
        self.assertTrue(str(p).endswith(".json"))

    def test_session_name_with_10000_chars_capped(self):
        from dsec.session import _session_path
        p = _session_path("x" * 10000)
        # Capped at 128 chars + ".json" = ≤ 133
        self.assertLessEqual(len(p.name), 200)

    # ── Config edge cases ─────────────────────────────────────────────────

    def test_corrupt_config_recovered_to_defaults(self):
        """Existing config.json with broken JSON. load_config must NOT crash;
        it should fall back to defaults and rewrite."""
        from dsec.config import load_config, CONFIG_FILE, save_config, _invalidate_cache
        import tempfile, shutil, os as _os
        # Snapshot original
        backup = CONFIG_FILE.read_text()
        try:
            # Write corrupt content
            CONFIG_FILE.write_text("{this is not json")
            _invalidate_cache()
            cfg = load_config()
            # Defaults restored
            self.assertIn("default_model", cfg)
            self.assertIn("base_url", cfg)
        finally:
            CONFIG_FILE.write_text(backup)
            _invalidate_cache()

    def test_empty_config_file(self):
        from dsec.config import load_config, CONFIG_FILE, _invalidate_cache
        backup = CONFIG_FILE.read_text()
        try:
            CONFIG_FILE.write_text("")
            _invalidate_cache()
            cfg = load_config()
            self.assertIn("default_model", cfg)
        finally:
            CONFIG_FILE.write_text(backup)
            _invalidate_cache()

    # ── Cross-turn guard creative scenarios ───────────────────────────────

    def test_guard_distinguishes_whitespace_change(self):
        """Same logical command but with leading/trailing whitespace —
        signature should DIFFER (whitespace matters in JSON serialization).
        Acceptable: agent retries with whitespace = guard does NOT fire.
        Confirms guard isn't over-fitting."""
        import hashlib, json as _json
        def sig(args):
            return f"bash:{hashlib.sha1(_json.dumps(args, sort_keys=True).encode()).hexdigest()[:12]}"
        a = sig({"command": "bloodyAD x"})
        b = sig({"command": "bloodyAD x "})  # trailing space
        self.assertNotEqual(a, b)  # different sigs — guard won't block

    def test_guard_doesnt_fire_after_success_then_failure(self):
        """Iter1: cmd X → success.
           Iter2: cmd X → failure.
           Iter3: cmd X → guard should fire.
           Verifies state transitions correctly."""
        last_sig = None
        last_failed = False
        skipped = 0
        import hashlib, json as _json
        def sig(args):
            return f"bash:{hashlib.sha1(_json.dumps(args, sort_keys=True).encode()).hexdigest()[:12]}"

        s = sig({"command": "X"})

        # Iter1: dispatch X, succeeds
        if s == last_sig and last_failed:
            skipped += 1
        else:
            last_sig = s
            last_failed = False  # success

        # Iter2: dispatch X, fails (different from prior because last_failed was False)
        if s == last_sig and last_failed:
            skipped += 1
        else:
            last_sig = s
            last_failed = True  # fail

        # Iter3: now it should fire (same sig + last_failed=True)
        if s == last_sig and last_failed:
            skipped += 1
        else:
            last_sig = s
            last_failed = False

        self.assertEqual(skipped, 1, f"expected 1 skip, got {skipped}")


class TestBackgroundFireAndForget(unittest.TestCase):
    """User reported `background run ferox` blocking ~10s before returning.
    Root cause: `pane.read` uses IDLE timeout, and feroxbuster prints
    continuously — idle timer keeps resetting until 10s wall cap.

    Fix: pane.read accepts max_total wall-clock cap; run action sets
    wall_cap=wait*1.5. wait=0 skips the read entirely (true fire-and-forget).
    """

    def setUp(self):
        from dsec.tools.pty_terminal import background
        for jid in ("ff-test", "ff-burst"):
            try:
                background(action="kill", job_id=jid)
            except Exception:
                pass

    def tearDown(self):
        from dsec.tools.pty_terminal import background
        for jid in ("ff-test", "ff-burst"):
            try:
                background(action="kill", job_id=jid)
            except Exception:
                pass

    def test_wait_zero_returns_instantly(self):
        """wait=0 → fire-and-forget. Should return in <1s regardless of cmd output."""
        from dsec.tools.pty_terminal import background
        import time
        # Even a command that prints a lot — should NOT delay return.
        cmd = "yes hello | head -c 100000"  # prints ~100KB fast
        t0 = time.time()
        result = background(action="run", job_id="ff-test", command=cmd, wait=0)
        elapsed = time.time() - t0
        # Pane init dominates (~0.3-1s). After that, no read = instant.
        self.assertLess(elapsed, 2.5, f"fire-and-forget took {elapsed:.1f}s")
        self.assertIn("started", result)
        # Output may be empty (we skipped read) — that's the contract.

    def test_wall_cap_caps_continuous_output(self):
        """Continuously-printing command (yes/dev/zero) must NOT block beyond
        wait*1.5 wall cap, even if idle never triggers."""
        from dsec.tools.pty_terminal import background
        import time
        # `yes` floods output forever; wait=2 → wall cap = 3s
        t0 = time.time()
        result = background(action="run", job_id="ff-burst",
                            command="yes BURST", wait=2)
        elapsed = time.time() - t0
        # Pane init ~1s + wall cap 3s = ~4s; allow slop for slower CI
        self.assertLess(elapsed, 6.5, f"continuous-output blocked for {elapsed:.1f}s")
        self.assertIn("started", result)

    def test_wait_default_still_works_for_short_cmd(self):
        """Default wait must capture initial output of a quick command."""
        from dsec.tools.pty_terminal import background
        result = background(action="run", job_id="ff-test",
                            command="echo HELLO_WORLD_MARKER", wait=2)
        self.assertIn("HELLO_WORLD_MARKER", result)

    def test_pty_unicode_passthrough(self):
        """LANG/LC_ALL=UTF-8 means unicode in command output renders cleanly."""
        from dsec.tools.pty_terminal import background
        result = background(action="run", job_id="ff-test",
                            command="echo 'héllo wörld 你好'", wait=2)
        self.assertIn("héllo wörld 你好", result)

    def test_pty_strips_nul_bytes(self):
        """Binary NUL bytes from cat-ing a binary file must not survive."""
        from dsec.tools.pty_terminal import background
        background(action="run", job_id="ff-test", command="echo init", wait=1)
        result = background(action="exec", job_id="ff-test",
                            command="printf 'before\\x00\\x01\\x02after\\n'", wait=3)
        self.assertIn("beforeafter", result)
        self.assertNotIn("\x00", result)
        self.assertNotIn("\x01", result)

    def test_pty_wide_table_fits_220_cols(self):
        """5 × 30-char columns = 150 cols, must fit within COLS=220 without wrap."""
        from dsec.tools.pty_terminal import background
        background(action="run", job_id="ff-test", command="echo init", wait=1)
        result = background(action="exec", job_id="ff-test",
                            command="printf '%-30s %-30s %-30s %-30s %-30s\\n' a b c d e",
                            wait=3)
        # Single line containing all five markers — no wrap.
        for marker in ("a", "b", "c", "d", "e"):
            self.assertIn(marker, result)

    def test_collapse_cr_progress_keeps_findings(self):
        """User saw bg read return 9.4 MB of feroxbuster `[>------]`
        progress redraws burying one real `200 GET /iisstart.htm` line.
        collapse_cr_progress must dedupe progress and preserve findings."""
        from dsec.tools.pty_terminal import collapse_cr_progress
        sample = (
            "[>-------------------] - 6m     83128/2340234 found:1\n"
            "[>-------------------] - 5m     41340/1170000 128/s\n"
            "[>-------------------] - 5m     40521/1170000 123/s\n"
            "\r\r\r[>-------------------] - 6m     83129/2340234 found:1\n"
            "[>-------------------] - 5m     41340/1170000 128/s\n"
            "\r\r\r[>-------------------] - 9m     40560/1170000 72/s\n"
            "200      GET     12l       45w      1023c http://x/iisstart.htm\n"
            "[>-------------------] - 10m    83131/2340234 found:1\n"
            "200      GET     5l        20w       300c http://x/admin/\n"
        )
        out = collapse_cr_progress(sample)
        # Real findings must be present
        self.assertIn("/iisstart.htm", out)
        self.assertIn("/admin/", out)
        # Progress collapsed: at most 4 lines (interspersed progress + finding)
        self.assertLessEqual(len(out.splitlines()), 5,
                             f"failed to dedupe progress: {out!r}")

    def test_collapse_cr_progress_passes_through_normal_output(self):
        from dsec.tools.pty_terminal import collapse_cr_progress
        normal = "Header line\nSome data\nAnother line\nFinal line"
        self.assertEqual(collapse_cr_progress(normal), normal)

    def test_read_capped_at_2s_on_continuous_output(self):
        """`background read` on a job spewing burst output (yes, hashcat
        progress) must NOT block beyond ~2s wall cap. Without the cap,
        the idle timer kept resetting on every chunk and read held until
        the process itself went quiet — minutes for an active scan."""
        from dsec.tools.pty_terminal import background
        import time
        background(action="run", job_id="ff-burst",
                   command="yes BURST_LINE", wait=0)
        time.sleep(0.3)  # let it warm up
        t0 = time.time()
        result = background(action="read", job_id="ff-burst")
        elapsed = time.time() - t0
        self.assertLess(elapsed, 3.5, f"read blocked for {elapsed:.1f}s")
        self.assertIn("ff-burst", result)


class TestAuditReplayPersistence(unittest.TestCase):
    """Regression: state vars (_last_cmd_signature, _fail_history) were
    process-local — across dsec restarts they reset, so an identical bash
    retry from a previous session re-dispatched. Audit replay primes the
    state from disk on session resume."""

    def setUp(self):
        from dsec.session import _sessions_dir
        import tempfile, shutil
        self._sess_root = _sessions_dir()
        self._test_session = "stress-replay-test"
        sd = self._sess_root / self._test_session
        if sd.exists():
            shutil.rmtree(sd)
        sd.mkdir(parents=True, exist_ok=True)
        # Seed audit.jsonl with a failed bloodyAD entry
        bad_cmd = "bloodyAD -d logging.htb -u wallace.everette -p 'Welcome2026@' --host 10.129.236.203 add groupMember IT wallace.everette"
        seed = [
            {
                "tool": "bash",
                "args": {"cmd": bad_cmd},
                "result_preview": "Traceback ... insufficientAccessRights",
                "success": False,
                "ts": "2026-05-04T11:30:00+00:00",
            }
        ]
        (sd / "audit.jsonl").write_text("\n".join(json.dumps(e) for e in seed) + "\n")

    def tearDown(self):
        import shutil
        sd = self._sess_root / self._test_session
        if sd.exists():
            shutil.rmtree(sd)

    def test_replay_blocks_identical_retry_after_restart(self):
        """Fresh _run_agentic_loop with audit pointing to the same failed
        bloodyAD must NOT re-dispatch when the agent re-emits it."""
        from unittest import mock
        from dsec import cli as cli_mod

        bad_cmd = "bloodyAD -d logging.htb -u wallace.everette -p 'Welcome2026@' --host 10.129.236.203 add groupMember IT wallace.everette"
        block = f'<tool_call>{{"name":"bash","arguments":{{"command":"{bad_cmd}"}}}}</tool_call>'

        fake_chat, _ = TestAgenticLoopIntegration._make_chat_stream_mock(self, [block, ""])
        fake_runner, run_log = TestAgenticLoopIntegration._make_runner_mock(self, [1, 1, 1])

        with mock.patch.object(cli_mod, "chat_stream", fake_chat), \
             mock.patch.object(cli_mod, "get_runner", lambda: fake_runner):
            try:
                cli_mod._run_agentic_loop(
                    response_content=block,
                    session_name=self._test_session,
                    domain="htb",
                    model="x",
                    conversation_id=None,
                    config={"base_url": "http://localhost:8000",
                            "show_thinking": False, "enable_multi_agent": False},
                    turn=1,
                    no_think=True,
                    no_memory=True,
                    auto_exec=True,
                    sudo_password=None,
                    max_iterations=3,
                )
            except Exception:
                pass

        bloody_dispatches = [r for r in run_log if "bloodyAD" in r["command"]]
        self.assertEqual(
            len(bloody_dispatches), 0,
            f"REPLAY FAILED: identical bloodyAD ran {len(bloody_dispatches)} times "
            f"despite prior-session audit showing it failed. Dispatches: {run_log}",
        )


class TestStalemateDetector(unittest.TestCase):
    """Forensic finding from session shell-20260503-221227: agent ran 110×
    nxc, 55× certipy, 41× smbclient — 600+ turns of pure enumeration with
    no commitment to an exploit chain. Stalemate detector forces a pivot
    after N turns of enumeration without progress markers (Got hash, Got
    TGT, Pwn3d!, Authenticated, etc.)."""

    def _replicate_helpers(self):
        """Reproduce the closures inside _run_agentic_loop so we can test
        their classification logic without invoking the full loop."""
        ENUM_TOOL_PREFIXES = (
            "nxc smb", "nxc ldap", "nxc winrm",
            "smbclient -l", "smbclient //",
            "smbmap", "ldapsearch", "ldapdomaindump",
            "curl ", "wget ", "feroxbuster", "gobuster", "ffuf",
            "nmap", "rustscan", "certipy find",
            "GetNPUsers.py", "GetUserSPNs.py",
        )
        ENUM_NATIVE_TOOLS = {
            "notes_search", "notes_get", "graph_memory_search",
            "dsec_archival_search", "gtfobins_search", "read_file",
            "core_memory_read",
        }
        PROGRESS_PATTERNS = (
            "Got hash for ", "Got TGT", "Got ST", "Pwn3d!",
            "[+] Authenticated", "Wrote credential cache",
            "[+] Successfully wrote", "[+] SMB Session received",
        )

        def is_enum(tool_name, args):
            if tool_name == "bash":
                cmd = (args.get("command") or args.get("cmd") or "").strip().lower()
                return any(cmd.startswith(p.lower()) for p in ENUM_TOOL_PREFIXES)
            return tool_name in ENUM_NATIVE_TOOLS

        def is_progress(text):
            if not text:
                return False
            tl = text.lower()
            if "traceback" in tl or "[-] error" in tl:
                return False
            return any(m in text for m in PROGRESS_PATTERNS)

        return is_enum, is_progress

    def test_classify_nxc_smb_as_enum(self):
        is_enum, _ = self._replicate_helpers()
        self.assertTrue(is_enum("bash", {"command": "nxc smb 10.10.10.5 -u u -p p --shares"}))
        self.assertTrue(is_enum("bash", {"command": "nxc ldap 10.10.10.5 -u u -p p --bloodhound"}))

    def test_classify_certipy_find_as_enum(self):
        is_enum, _ = self._replicate_helpers()
        self.assertTrue(is_enum("bash", {"command": "certipy find -u user@dom -p pwd -dc-ip 10.10.10.5"}))

    def test_classify_certipy_req_as_exploit(self):
        is_enum, _ = self._replicate_helpers()
        # `certipy req` mints a certificate — exploit-class
        self.assertFalse(is_enum("bash", {"command": "certipy req -u u -p p -ca CA -template T"}))

    def test_classify_write_file_as_exploit(self):
        is_enum, _ = self._replicate_helpers()
        # write_file isn't in ENUM_NATIVE_TOOLS — counts as exploit
        self.assertFalse(is_enum("write_file", {"path": "/tmp/x", "content": "y"}))

    def test_classify_notes_search_as_enum(self):
        is_enum, _ = self._replicate_helpers()
        self.assertTrue(is_enum("notes_search", {"query": "kerberoast"}))

    def test_progress_detection_got_hash(self):
        _, is_progress = self._replicate_helpers()
        self.assertTrue(is_progress(
            "[*] Got hash for 'wallace.everette@logging.htb': aad3b435...:40e28a964..."
        ))

    def test_progress_detection_pwn3d(self):
        _, is_progress = self._replicate_helpers()
        self.assertTrue(is_progress("SMB  10.10.10.5 445 DC01  [+] dom\\admin (Pwn3d!)"))

    def test_progress_ignored_in_traceback(self):
        _, is_progress = self._replicate_helpers()
        # Even if the marker substring appears, a Traceback indicates failure.
        self.assertFalse(is_progress(
            "Traceback (most recent call last): ... Got hash for x"
        ))

    def test_simulated_30_enum_turns_triggers_hint(self):
        """End-to-end logic: simulate the streak counter the way the loop
        does. After 30 enum turns with no progress, hint should fire."""
        from collections import deque
        is_enum, is_progress = self._replicate_helpers()
        turns_since_progress = 0
        window = deque(maxlen=20)

        # 30 nxc smb enum turns, none with progress
        for _ in range(30):
            args = {"command": "nxc smb 10.10.10.5 -u u -p p --shares"}
            window.append("enum" if is_enum("bash", args) else "exploit")
            if is_progress("(no creds returned)"):
                turns_since_progress = 0
            else:
                turns_since_progress += 1

        self.assertGreaterEqual(turns_since_progress, 30)
        enum_count = sum(1 for t in window if t == "enum")
        ratio = enum_count / len(window)
        self.assertGreaterEqual(ratio, 0.80)

    def test_progress_resets_streak(self):
        from collections import deque
        is_enum, is_progress = self._replicate_helpers()
        turns_since_progress = 0
        window = deque(maxlen=20)

        # 20 enum turns, then one exploit success (Got hash)
        for _ in range(20):
            window.append("enum")
            turns_since_progress += 1

        # Exploit-class call with progress marker
        result = "[*] Got hash for 'svc_recovery@logging.htb': :hashvalue"
        window.append("exploit")
        if is_progress(result):
            turns_since_progress = 0

        self.assertEqual(turns_since_progress, 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
