"""
Brain-callable tools for parallel sub-agent orchestration.

These wrap the Coordinator (dsec.agents.coordinator) and are registered with
roles=("brain",) — workers cannot recursively spawn parallel jobs (no fork
bombs). The brain submits a job and either:

  * fire-and-forget: receive job_id, keep planning, results surface in the
    next coord/findings drain or via await_jobs.
  * blocking: call await_jobs([id, ...]) for a Markdown digest.

Tools:
  * parallel_executor / parallel_research / parallel_vuln_hunt — submit
  * await_jobs — block until terminal, return digest
  * list_jobs — snapshot of registry
  * cancel_job — request cancellation
  * claim_target — atomic pre-lock (rare; for contested targets)
  * report_note — curate a finding into the active worker's findings list

Imported once for side-effects in cli.py before brain_tools.
"""
from __future__ import annotations

from typing import Optional

from dsec.agents import get_brain_context
from dsec.agents.coordinator import Coordinator, TargetConflict, get_current_job
from dsec.core.registry import register


@register(
    "parallel_executor",
    (
        "Submit an executor job to run in parallel. Returns a job_id "
        "immediately (fire-and-forget). Use await_jobs([id]) to block on "
        "results, or check coord/findings via list_jobs. Provide a CONCRETE "
        "plan (e.g. 'run nmap -sV against 10.10.11.5 and report open ports'). "
        "Optionally set target to atomically claim it (e.g. an IP, AD host, "
        "CTF challenge dir) so a sibling parallel job cannot collide. "
        "Returns 'job_id=<id>' on success or '[error: ...]' on conflict."
    ),
    roles=("brain",),
)
def parallel_executor(plan: str, target: Optional[str] = None) -> str:
    coord = Coordinator.get()
    try:
        jid = coord.submit(
            "executor",
            plan,
            target=target,
            parent_context=get_brain_context(),
        )
    except TargetConflict as exc:
        return f"[error: {exc}]"
    return f"job_id={jid}"


@register(
    "parallel_research",
    (
        "Submit a research/KB lookup job to run in parallel. Returns a "
        "job_id immediately. Use await_jobs([id]) for the digest. Provide "
        "ONE focused question (e.g. 'CVE list for vsftpd 2.3.4'). Useful "
        "to fan out multiple independent lookups while the brain keeps "
        "planning."
    ),
    roles=("brain",),
)
def parallel_research(query: str) -> str:
    coord = Coordinator.get()
    jid = coord.submit("research", query, parent_context=get_brain_context())
    return f"job_id={jid}"


@register(
    "parallel_vuln_hunt",
    (
        "Submit a vuln_hunt code-audit job to run in parallel against a "
        "source path. Returns a job_id immediately. Use await_jobs([id]) "
        "for the report. The path is auto-claimed so two hunts cannot "
        "stomp the same tree."
    ),
    roles=("brain",),
)
def parallel_vuln_hunt(path: str) -> str:
    coord = Coordinator.get()
    try:
        jid = coord.submit(
            "vuln_hunt",
            path,
            target=path,
            parent_context=get_brain_context(),
        )
    except TargetConflict as exc:
        return f"[error: {exc}]"
    return f"job_id={jid}"


@register(
    "await_jobs",
    (
        "Block until the listed jobs reach a terminal state (done/failed/"
        "cancelled) or the timeout elapses, then return a Markdown digest "
        "of outcomes and findings. Pass job_ids as a comma-separated string "
        "(e.g. 'a1b2c3d4,e5f6a7b8'). Default timeout 300s."
    ),
    roles=("brain",),
)
def await_jobs(job_ids: str, timeout: int = 300) -> str:
    ids = [s.strip() for s in (job_ids or "").split(",") if s.strip()]
    if not ids:
        return "[error: await_jobs needs at least one job_id]"
    coord = Coordinator.get()
    return coord.await_jobs(ids, timeout=float(timeout))


@register(
    "list_jobs",
    (
        "Return a snapshot of all parallel jobs in the registry — id, kind, "
        "state, target, age, runtime, findings count. Cheap introspection."
    ),
    roles=("brain",),
)
def list_jobs() -> str:
    coord = Coordinator.get()
    rows = coord.list_jobs()
    if not rows:
        return "[no jobs]"
    out = ["id        kind         state       target                 age   runtime  finds"]
    for r in rows:
        out.append(
            f"{r['id']:<9} {r['kind']:<12} {r['state']:<11} "
            f"{(r['target'] or '-')[:22]:<22} "
            f"{r['age']:>5.1f} {r['runtime']:>7.1f}  {r['findings']:>3}"
        )
    return "\n".join(out)


@register(
    "cancel_job",
    (
        "Request cancellation of a parallel job by id. Returns 'cancelled' "
        "or '[error: ...]'. Cancellation is cooperative — already-running "
        "workers stop on the next loop iteration."
    ),
    roles=("brain",),
)
def cancel_job(job_id: str) -> str:
    coord = Coordinator.get()
    if coord.cancel(job_id):
        return f"cancelled: {job_id}"
    return f"[error: job {job_id} not found or already terminal]"


@register(
    "claim_target",
    (
        "Atomically pre-lock a target (IP, host, dir, etc.) for the current "
        "job before spawning a parallel worker. Use only when you need to "
        "reserve a contested target across multiple brain turns. Returns "
        "'claimed: <target>' or '[error: ...]' if held by another job."
    ),
    roles=("brain",),
)
def claim_target(target: str) -> str:
    coord = Coordinator.get()
    placeholder_id = "manual-" + target.replace("/", "_").replace(":", "_")[:24]
    try:
        coord.claim(target, placeholder_id)
    except TargetConflict as exc:
        return f"[error: {exc}]"
    return f"claimed: {target}"


@register(
    "report_note",
    (
        "Curate a high-value finding (vuln, cred, exploit, key inference) "
        "into the active worker's findings list. Idempotent. Only useful "
        "from inside a worker; from the brain it's a no-op (no current "
        "job). Use sparingly — this is the curated transcript, not a log."
    ),
    roles=("brain", "executor", "research"),
)
def report_note(text: str) -> str:
    jid = get_current_job()
    if jid is None:
        return "[report_note: no active worker job — skipped]"
    Coordinator.get().note(jid, text)
    return f"noted on {jid}"
