"""
Smoke tests for ResumeStore + ReportWriter persistence layer.
"""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dsec.agents.coordinator import Coordinator
from dsec.agents.report_writer import ReportWriter
from dsec.agents.resume_store import ResumeStore, load_terminal_jobs


def _runner(text: str = "ok"):
    def fn(job):
        return text
    return fn


class TestReportWriter(unittest.TestCase):
    def setUp(self) -> None:
        Coordinator.reset()
        ReportWriter.reset()
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / ".report.md"
        ReportWriter.install(self.path)
        self.coord = Coordinator.get()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_note_appends_to_report_md(self):
        def runner(job):
            self.coord.note(job.id, "found admin:admin")
            return "done"
        jid = self.coord.submit("executor", "x", runner=runner)
        self.coord.await_jobs([jid], timeout=5.0)
        content = self.path.read_text()
        self.assertIn(jid, content)
        self.assertIn("admin:admin", content)


class TestResumeStore(unittest.TestCase):
    def setUp(self) -> None:
        Coordinator.reset()
        ResumeStore.reset()
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / ".dsec_jobs.jsonl"
        ResumeStore.install(self.path)
        self.coord = Coordinator.get()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_jsonl_logs_submit_state_and_digest(self):
        jid = self.coord.submit("executor", "do X", runner=_runner("digest-1"))
        self.coord.await_jobs([jid], timeout=5.0)
        lines = self.path.read_text().splitlines()
        self.assertTrue(any('"evt": "submit"' in l for l in lines))
        self.assertTrue(any('"evt": "state"' in l and '"running"' in l for l in lines))
        self.assertTrue(any('"evt": "state"' in l and '"done"' in l for l in lines))
        self.assertTrue(any('"evt": "digest"' in l and 'digest-1' in l for l in lines))

    def test_load_terminal_jobs_restores_done_state(self):
        jid = self.coord.submit("executor", "do Y", runner=_runner("digest-Y"))
        self.coord.await_jobs([jid], timeout=5.0)

        # Simulate fresh process: new coordinator, JSONL still on disk.
        Coordinator.reset()
        ResumeStore.reset()
        coord2 = Coordinator.get()
        loaded = load_terminal_jobs(coord2, self.path)
        self.assertEqual(loaded, 1)
        job = coord2.get_job(jid)
        self.assertIsNotNone(job)
        self.assertEqual(job.state, "done")
        self.assertEqual(job.digest, "digest-Y")


if __name__ == "__main__":
    unittest.main()
