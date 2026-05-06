"""
ReportWriter — dual-log of curated findings.

Companion to Coordinator. Hooks Coordinator.add_note_callback so every
report_note(text) call is appended to two places:

  * In-memory Job.findings (already done by Coordinator.note)
  * .report.md in the session dir, timestamped, grouped by job

The Coordinator's full JSONL transcript (every job lifecycle event) is
written separately by ResumeStore (Section 5/8). ReportWriter is the
*curated* surface: only what report_note explicitly tagged as worth
keeping.

Initialised once from cli.py startup. Idempotent — calling install()
twice attaches only one callback.
"""
from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Optional

from dsec.agents.coordinator import Coordinator


class ReportWriter:
    _installed: bool = False
    _lock = threading.Lock()

    def __init__(self, path: Path):
        self.path = path
        self._file_lock = threading.Lock()

    def append(self, job_id: str, text: str) -> None:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"- `{ts}` **{job_id}** — {text}\n"
        with self._file_lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)

    @classmethod
    def install(cls, path: Optional[Path] = None) -> "ReportWriter":
        with cls._lock:
            target = path or (Path.cwd() / ".report.md")
            writer = cls(target)
            if not cls._installed:
                Coordinator.get().add_note_callback(writer.append)
                cls._installed = True
            return writer

    @classmethod
    def reset(cls) -> None:
        """Test helper."""
        with cls._lock:
            cls._installed = False
