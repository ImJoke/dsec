"""
Parallel sub-agent coordinator.

In-process job registry, claim map, and thread-pool gate. Brain submits jobs
via parallel_* tools; workers run in threads sharing the registry. Single
host, single Python process — no Zenoh / IPC needed for the coordinator
itself (the existing Zenoh transport is for remote MCP only).

Design (Sections 7-8 of multi-agent plan):
  * Coordinator is a singleton accessed via Coordinator.get().
  * submit() → returns job_id immediately, spawns _WorkerThread.
  * _WorkerThread acquires the semaphore (so cap is enforced),
    runs run_executor / run_research_agent / vuln_hunt, and
    transitions the Job state machine.
  * Findings are appended in-process via .note(); report_note tool
    reads the current job_id from a thread-local set on entry.
  * await_jobs() blocks on a Condition until all listed jobs are
    in a terminal state, then formats a Markdown digest for the brain.
"""
from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Literal, Optional


JobKind = Literal["executor", "research", "vuln_hunt"]
JobState = Literal["pending", "running", "done", "failed", "cancelled"]
_TERMINAL: tuple = ("done", "failed", "cancelled")


class TargetConflict(Exception):
    """Raised when a target is already claimed by another active job."""


@dataclass
class Job:
    id: str
    kind: JobKind
    plan: str
    target: Optional[str]
    state: JobState
    created_at: float
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    digest: Optional[str] = None
    error: Optional[str] = None
    findings: List[str] = field(default_factory=list)
    cancel_evt: threading.Event = field(default_factory=threading.Event)

    def is_terminal(self) -> bool:
        return self.state in _TERMINAL

    def age(self) -> float:
        return time.time() - self.created_at

    def runtime(self) -> float:
        if self.started_at is None:
            return 0.0
        end = self.finished_at if self.finished_at is not None else time.time()
        return end - self.started_at


_tls = threading.local()


def set_current_job(job_id: Optional[str]) -> None:
    _tls.job_id = job_id


def get_current_job() -> Optional[str]:
    return getattr(_tls, "job_id", None)


class Coordinator:
    _instance: Optional["Coordinator"] = None
    _instance_lock = threading.Lock()

    def __init__(self, max_workers: int = 4) -> None:
        self._jobs: Dict[str, Job] = {}
        self._claims: Dict[str, str] = {}
        self._lock = threading.RLock()
        self._cond = threading.Condition(self._lock)
        self._max_workers = max_workers
        self._sem = threading.BoundedSemaphore(max_workers)
        self._note_callbacks: List[Callable[[str, str], None]] = []

    # ── singleton access ────────────────────────────────────────────────
    @classmethod
    def get(cls) -> "Coordinator":
        if cls._instance is None:
            with cls._instance_lock:
                if cls._instance is None:
                    cls._instance = cls()
        return cls._instance

    @classmethod
    def reset(cls) -> None:
        """Test helper. Drops the singleton and any in-flight state."""
        with cls._instance_lock:
            cls._instance = None

    # ── claim API ───────────────────────────────────────────────────────
    def claim(self, target: str, job_id: str) -> None:
        """Atomically pre-lock a target. Raises TargetConflict if held."""
        with self._lock:
            holder = self._claims.get(target)
            if holder is not None and holder != job_id:
                holder_job = self._jobs.get(holder)
                if holder_job is not None and not holder_job.is_terminal():
                    raise TargetConflict(
                        f"target {target!r} already claimed by job {holder}"
                    )
            self._claims[target] = job_id

    def _release_claim(self, target: str, job_id: str) -> None:
        with self._lock:
            if self._claims.get(target) == job_id:
                self._claims.pop(target, None)

    # ── submit ──────────────────────────────────────────────────────────
    def submit(
        self,
        kind: JobKind,
        plan: str,
        *,
        target: Optional[str] = None,
        parent_context: Optional[Dict[str, Any]] = None,
        runner: Optional[Callable[[Job], str]] = None,
    ) -> str:
        job_id = uuid.uuid4().hex[:8]
        job = Job(
            id=job_id,
            kind=kind,
            plan=plan,
            target=target,
            state="pending",
            created_at=time.time(),
        )
        with self._lock:
            if target is not None:
                self.claim(target, job_id)
            self._jobs[job_id] = job

        thread = _WorkerThread(
            coordinator=self,
            job=job,
            parent_context=parent_context or {},
            runner=runner,
        )
        thread.daemon = True
        thread.start()
        return job_id

    # ── transitions called by worker thread ─────────────────────────────
    def _set_state(
        self,
        job: Job,
        state: JobState,
        *,
        digest: Optional[str] = None,
        error: Optional[str] = None,
    ) -> None:
        with self._cond:
            job.state = state
            if state == "running" and job.started_at is None:
                job.started_at = time.time()
            if state in _TERMINAL:
                job.finished_at = time.time()
                if digest is not None:
                    job.digest = digest
                if error is not None:
                    job.error = error
                if job.target is not None:
                    self._release_claim(job.target, job.id)
            self._cond.notify_all()

    # ── findings ────────────────────────────────────────────────────────
    def note(self, job_id: str, text: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                return
            entry = text.strip()
            if not entry:
                return
            job.findings.append(entry)
        for cb in list(self._note_callbacks):
            try:
                cb(job_id, entry)
            except Exception:
                pass

    def add_note_callback(self, cb: Callable[[str, str], None]) -> None:
        with self._lock:
            self._note_callbacks.append(cb)

    # ── cancel ──────────────────────────────────────────────────────────
    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None or job.is_terminal():
                return False
            job.cancel_evt.set()
            return True

    # ── await ───────────────────────────────────────────────────────────
    def await_jobs(
        self,
        job_ids: List[str],
        *,
        timeout: float = 300.0,
    ) -> str:
        deadline = time.time() + timeout
        with self._cond:
            while True:
                pending = [
                    jid for jid in job_ids
                    if jid in self._jobs and not self._jobs[jid].is_terminal()
                ]
                if not pending:
                    break
                remaining = deadline - time.time()
                if remaining <= 0:
                    break
                self._cond.wait(timeout=remaining)
            return self._format_digest(job_ids)

    def _format_digest(self, job_ids: List[str]) -> str:
        with self._lock:
            jobs = [self._jobs.get(jid) for jid in job_ids]
        jobs = [j for j in jobs if j is not None]
        if not jobs:
            return "## Job Results — no jobs found"

        done = sum(1 for j in jobs if j.state == "done")
        failed = sum(1 for j in jobs if j.state == "failed")
        cancelled = sum(1 for j in jobs if j.state == "cancelled")
        running = sum(1 for j in jobs if j.state == "running")

        lines: List[str] = [
            f"## Job Results — {done} done, {failed} failed, "
            f"{cancelled} cancelled, {running} still running"
        ]
        for j in jobs:
            icon = {
                "done": "✅",
                "failed": "❌",
                "cancelled": "⚠️",
                "running": "⏳",
                "pending": "⏳",
            }[j.state]
            header = f"### {icon} {j.id} ({j.kind}) — {j.runtime():.0f}s — {j.state}"
            if j.target:
                header += f" — target={j.target}"
            lines.append("")
            lines.append(header)
            if j.state == "failed" and j.error:
                lines.append(f"error: {j.error}")
            body = (j.digest or "").strip()
            if body:
                lines.append(body[-1200:])

        all_findings = [
            (j.id, n) for j in jobs for n in j.findings
        ]
        if all_findings:
            lines.append("")
            lines.append("## Findings (report_note entries)")
            for jid, note in all_findings:
                lines.append(f"- [{jid}] {note}")
        return "\n".join(lines)

    # ── introspection ───────────────────────────────────────────────────
    def list_jobs(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [
                {
                    "id": j.id,
                    "kind": j.kind,
                    "state": j.state,
                    "target": j.target,
                    "age": round(j.age(), 1),
                    "runtime": round(j.runtime(), 1),
                    "findings": len(j.findings),
                }
                for j in self._jobs.values()
            ]

    def get_job(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

    # ── pool resize ─────────────────────────────────────────────────────
    def set_max_workers(self, n: int) -> int:
        n = max(1, min(int(n), 32))
        with self._lock:
            self._max_workers = n
            self._sem = threading.BoundedSemaphore(n)
        return n

    @property
    def max_workers(self) -> int:
        return self._max_workers


class _WorkerThread(threading.Thread):
    def __init__(
        self,
        *,
        coordinator: Coordinator,
        job: Job,
        parent_context: Dict[str, Any],
        runner: Optional[Callable[[Job], str]] = None,
    ) -> None:
        super().__init__(name=f"dsec-worker-{job.id}")
        self._coord = coordinator
        self._job = job
        self._parent_context = parent_context
        self._runner = runner

    def run(self) -> None:
        coord = self._coord
        job = self._job

        if job.cancel_evt.is_set():
            coord._set_state(job, "cancelled", error="cancelled before start")
            return

        with coord._sem:
            if job.cancel_evt.is_set():
                coord._set_state(job, "cancelled", error="cancelled in queue")
                return

            coord._set_state(job, "running")
            set_current_job(job.id)
            try:
                digest = (
                    self._runner(job) if self._runner is not None
                    else self._dispatch_default()
                )
                coord._set_state(job, "done", digest=str(digest))
            except Exception as exc:
                coord._set_state(job, "failed", error=f"{type(exc).__name__}: {exc}")
            finally:
                set_current_job(None)

    def _dispatch_default(self) -> str:
        kind = self._job.kind
        plan = self._job.plan
        ctx = self._parent_context

        if kind == "executor":
            from dsec.agents.executor import run_executor
            return run_executor(plan, parent_context=ctx)
        if kind == "research":
            from dsec.agents.researcher import run_research_agent
            return run_research_agent(plan, parent_context=ctx)
        if kind == "vuln_hunt":
            from dsec.core.registry import call_tool
            args = {"path": plan} if plan and "/" in plan else {"path": plan}
            return str(call_tool("vuln_hunt", args, caller_role="brain"))
        raise ValueError(f"unknown job kind: {kind}")
