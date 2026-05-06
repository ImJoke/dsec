"""
ResumeStore — JSONL persistence for parallel job lifecycle.

Sister of ReportWriter (curated .report.md). Where ReportWriter logs only
report_note entries, ResumeStore logs every state transition + finding so a
session resume can reconstruct terminal jobs. Brain can then call
`await_jobs(prior_id)` after a /clear or process restart.

File layout (cwd-local, mirrors .report.md):
  .dsec_jobs.jsonl  — append-only event log

Event shapes:
  {"t": ts, "evt": "submit",       "id": "...", "kind": "...", "plan": "...", "target": "..."}
  {"t": ts, "evt": "state",        "id": "...", "state": "running"|"done"|"failed"|"cancelled", "error": "..."}
  {"t": ts, "evt": "digest",       "id": "...", "digest": "..."}
  {"t": ts, "evt": "note",         "id": "...", "text": "..."}

On install(), the store:
  * registers a note callback (writes "note" events)
  * monkey-patches Coordinator._set_state to also emit "state"+"digest"
    events through the same file lock
  * registers a submit-shim by patching Coordinator.submit

Load via load_terminal_jobs(coord) — replays the JSONL into the registry,
keeping only jobs that reached a terminal state (running/pending jobs are
discarded — re-running them blindly would be unsafe).
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Optional

from dsec.agents.coordinator import Coordinator, Job


class ResumeStore:
    _installed: bool = False
    _lock = threading.Lock()

    def __init__(self, path: Path):
        self.path = path
        self._file_lock = threading.Lock()

    def _write(self, payload: dict) -> None:
        payload = {"t": time.time(), **payload}
        with self._file_lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(payload, ensure_ascii=False) + "\n")

    def on_note(self, job_id: str, text: str) -> None:
        self._write({"evt": "note", "id": job_id, "text": text})

    @classmethod
    def install(cls, path: Optional[Path] = None) -> "ResumeStore":
        with cls._lock:
            target = path or (Path.cwd() / ".dsec_jobs.jsonl")
            store = cls(target)
            if cls._installed:
                return store
            cls._installed = True

            coord = Coordinator.get()
            coord.add_note_callback(store.on_note)

            orig_submit = coord.submit
            orig_set_state = coord._set_state

            def wrapped_submit(kind, plan, *, target=None, parent_context=None, runner=None):
                jid = orig_submit(
                    kind, plan,
                    target=target,
                    parent_context=parent_context,
                    runner=runner,
                )
                store._write({
                    "evt": "submit", "id": jid, "kind": kind,
                    "plan": plan[:500], "target": target,
                })
                return jid

            def wrapped_set_state(job, state, *, digest=None, error=None):
                orig_set_state(job, state, digest=digest, error=error)
                payload = {"evt": "state", "id": job.id, "state": state}
                if error is not None:
                    payload["error"] = error
                store._write(payload)
                if digest is not None:
                    store._write({"evt": "digest", "id": job.id, "digest": digest})

            coord.submit = wrapped_submit  # type: ignore[method-assign]
            coord._set_state = wrapped_set_state  # type: ignore[method-assign]
            return store

    @classmethod
    def reset(cls) -> None:
        """Test helper."""
        with cls._lock:
            cls._installed = False


def load_terminal_jobs(
    coord: Coordinator,
    path: Optional[Path] = None,
) -> int:
    """Replay JSONL into coord registry. Returns count of terminal jobs loaded.

    Only jobs whose last state is done/failed/cancelled are inserted.
    Running/pending jobs are dropped (their threads died with the prior process).
    """
    target = path or (Path.cwd() / ".dsec_jobs.jsonl")
    if not target.exists():
        return 0

    submits: dict = {}
    states: dict = {}
    digests: dict = {}
    errors: dict = {}
    notes: dict = {}

    with target.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            kind = evt.get("evt")
            jid = evt.get("id")
            if not jid:
                continue
            if kind == "submit":
                submits[jid] = evt
            elif kind == "state":
                states[jid] = evt.get("state")
                if evt.get("error"):
                    errors[jid] = evt["error"]
            elif kind == "digest":
                digests[jid] = evt.get("digest", "")
            elif kind == "note":
                notes.setdefault(jid, []).append(evt.get("text", ""))

    terminal = {"done", "failed", "cancelled"}
    loaded = 0
    for jid, sub in submits.items():
        state = states.get(jid)
        if state not in terminal:
            continue
        job = Job(
            id=jid,
            kind=sub.get("kind", "executor"),
            plan=sub.get("plan", ""),
            target=sub.get("target"),
            state=state,  # type: ignore[arg-type]
            created_at=sub.get("t", time.time()),
            started_at=sub.get("t"),
            finished_at=time.time(),
            digest=digests.get(jid),
            error=errors.get(jid),
            findings=notes.get(jid, []),
        )
        coord._jobs[jid] = job
        loaded += 1
    return loaded
