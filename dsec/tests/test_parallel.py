"""
Smoke tests for the parallel sub-agent coordinator.

Run with: python3 -m pytest dsec/tests/test_parallel.py -v
Or:       python3 -m unittest dsec.tests.test_parallel

Tests use a custom `runner=` callback so we never spawn real LLMs — fast
and deterministic.
"""
from __future__ import annotations

import threading
import time
import unittest

from dsec.agents.coordinator import (
    Coordinator,
    Job,
    TargetConflict,
    get_current_job,
)


def _make_runner(text: str, sleep: float = 0.05):
    def runner(job: Job) -> str:
        time.sleep(sleep)
        return text
    return runner


def _slow_runner(barrier: threading.Event, text: str = "slow ok"):
    def runner(job: Job) -> str:
        barrier.wait(timeout=5.0)
        return text
    return runner


class TestCoordinatorBasics(unittest.TestCase):
    def setUp(self) -> None:
        Coordinator.reset()
        self.coord = Coordinator.get()

    def test_submit_runs_and_completes(self):
        jid = self.coord.submit(
            "executor", "test plan", runner=_make_runner("digest-A"),
        )
        digest = self.coord.await_jobs([jid], timeout=5.0)
        job = self.coord.get_job(jid)
        self.assertIsNotNone(job)
        self.assertEqual(job.state, "done")
        self.assertEqual(job.digest, "digest-A")
        self.assertIn("digest-A", digest)
        self.assertIn(jid, digest)

    def test_failed_job_captures_error(self):
        def boom(job):
            raise RuntimeError("synthetic failure")
        jid = self.coord.submit("executor", "x", runner=boom)
        digest = self.coord.await_jobs([jid], timeout=5.0)
        job = self.coord.get_job(jid)
        self.assertEqual(job.state, "failed")
        self.assertIn("synthetic failure", job.error or "")
        self.assertIn("failed", digest)

    def test_two_jobs_complete_in_parallel(self):
        jid_a = self.coord.submit(
            "executor", "A", runner=_make_runner("A-out", sleep=0.1),
        )
        jid_b = self.coord.submit(
            "research", "B", runner=_make_runner("B-out", sleep=0.1),
        )
        digest = self.coord.await_jobs([jid_a, jid_b], timeout=5.0)
        self.assertEqual(self.coord.get_job(jid_a).state, "done")
        self.assertEqual(self.coord.get_job(jid_b).state, "done")
        self.assertIn("A-out", digest)
        self.assertIn("B-out", digest)


class TestClaimAndConflict(unittest.TestCase):
    def setUp(self) -> None:
        Coordinator.reset()
        self.coord = Coordinator.get()

    def test_claim_conflict_raises_on_second_submit(self):
        gate = threading.Event()
        jid_a = self.coord.submit(
            "executor", "first",
            target="10.10.11.5",
            runner=_slow_runner(gate, "A"),
        )
        with self.assertRaises(TargetConflict):
            self.coord.submit(
                "executor", "second",
                target="10.10.11.5",
                runner=_make_runner("B"),
            )
        gate.set()
        self.coord.await_jobs([jid_a], timeout=5.0)

    def test_claim_released_after_terminal_allows_resubmit(self):
        jid_a = self.coord.submit(
            "executor", "first",
            target="10.10.11.6",
            runner=_make_runner("A"),
        )
        self.coord.await_jobs([jid_a], timeout=5.0)
        jid_b = self.coord.submit(
            "executor", "second",
            target="10.10.11.6",
            runner=_make_runner("B"),
        )
        self.coord.await_jobs([jid_b], timeout=5.0)
        self.assertEqual(self.coord.get_job(jid_b).state, "done")


class TestCancellation(unittest.TestCase):
    def setUp(self) -> None:
        Coordinator.reset()
        self.coord = Coordinator.get()

    def test_cancel_before_start_marks_cancelled(self):
        # Saturate worker pool so the new job stays pending.
        self.coord.set_max_workers(1)
        gate = threading.Event()
        blocker = self.coord.submit(
            "executor", "blocker", runner=_slow_runner(gate, "ok"),
        )
        target_jid = self.coord.submit(
            "executor", "queued", runner=_make_runner("nope"),
        )
        self.assertTrue(self.coord.cancel(target_jid))
        gate.set()
        self.coord.await_jobs([blocker, target_jid], timeout=5.0)
        self.assertEqual(self.coord.get_job(target_jid).state, "cancelled")

    def test_cancel_terminal_returns_false(self):
        jid = self.coord.submit("executor", "x", runner=_make_runner("ok"))
        self.coord.await_jobs([jid], timeout=5.0)
        self.assertFalse(self.coord.cancel(jid))


class TestFindingsAndTLS(unittest.TestCase):
    def setUp(self) -> None:
        Coordinator.reset()
        self.coord = Coordinator.get()

    def test_report_note_attached_via_tls(self):
        captured: dict = {}

        def runner(job):
            captured["job_id_seen"] = get_current_job()
            self.coord.note(job.id, "found CVE-2024-1234")
            self.coord.note(job.id, "creds: admin:admin")
            return "digest"

        jid = self.coord.submit("executor", "x", runner=runner)
        digest = self.coord.await_jobs([jid], timeout=5.0)
        job = self.coord.get_job(jid)
        self.assertEqual(captured["job_id_seen"], jid)
        self.assertEqual(len(job.findings), 2)
        self.assertIn("CVE-2024-1234", digest)
        self.assertIn("admin:admin", digest)


class TestPoolResize(unittest.TestCase):
    def setUp(self) -> None:
        Coordinator.reset()
        self.coord = Coordinator.get()

    def test_set_max_workers_clamps(self):
        self.assertEqual(self.coord.set_max_workers(8), 8)
        self.assertEqual(self.coord.set_max_workers(0), 1)
        self.assertEqual(self.coord.set_max_workers(999), 32)


class TestListJobs(unittest.TestCase):
    def setUp(self) -> None:
        Coordinator.reset()
        self.coord = Coordinator.get()

    def test_list_includes_completed_jobs(self):
        jid = self.coord.submit("executor", "x", runner=_make_runner("ok"))
        self.coord.await_jobs([jid], timeout=5.0)
        rows = self.coord.list_jobs()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], jid)
        self.assertEqual(rows[0]["state"], "done")


if __name__ == "__main__":
    unittest.main()
