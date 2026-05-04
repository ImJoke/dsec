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


if __name__ == "__main__":
    unittest.main(verbosity=2)
