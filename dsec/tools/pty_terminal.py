"""
DSEC Background Process Manager

Provides the agent with persistent background processes (listeners, shells,
relay tools) through a single `background` tool with clear action verbs.

Internal implementation uses PTY pseudo-terminals for full interactive support.
"""
import atexit
import os
import pty
import re
import select
import signal
import subprocess
import time
import fcntl
import uuid
from typing import Dict

from dsec.core.registry import register


def strip_ansi(text: str) -> str:
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)


class Pane:
    """A persistent PTY pane with a bash shell."""

    def __init__(self, pane_id: str, init_timeout: float = 5.0):
        self.pane_id = pane_id
        self.master_fd, self.slave_fd = pty.openpty()

        def preexec():
            try:
                os.setsid()
                import fcntl, termios
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            except Exception:
                pass

        self.process = subprocess.Popen(
            ["/bin/bash"],
            stdin=self.slave_fd,
            stdout=self.slave_fd,
            stderr=self.slave_fd,
            close_fds=True,
            env=os.environ.copy(),
            preexec_fn=preexec,
        )
        try:
            os.close(self.slave_fd)
        except OSError:
            pass
        self.slave_fd = -1

        fl = fcntl.fcntl(self.master_fd, fcntl.F_GETFL)
        fcntl.fcntl(self.master_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        time.sleep(0.3)
        try:
            self.read(timeout=init_timeout)
        except Exception:
            try:
                self.close()
            except Exception:
                pass
            raise RuntimeError(f"PTY shell initialization failed for '{pane_id}'")

    @property
    def alive(self) -> bool:
        return self.process.poll() is None

    def write(self, data: str):
        if not self.alive:
            raise RuntimeError(f"Job '{self.pane_id}' process has exited.")
        os.write(self.master_fd, data.encode("utf-8"))

    def read(self, timeout: float = 0.5) -> str:
        output = b""
        start_time = time.time()
        while True:
            try:
                r, _, _ = select.select([self.master_fd], [], [], 0.05)
            except (ValueError, OSError):
                break
            if self.master_fd in r:
                try:
                    chunk = os.read(self.master_fd, 8192)
                    if not chunk:
                        break
                    output += chunk
                    start_time = time.time()
                except OSError:
                    break
            else:
                if time.time() - start_time > timeout:
                    break
        return output.decode("utf-8", errors="replace")

    def send_signal(self, sig: int):
        if self.alive:
            try:
                os.killpg(os.getpgid(self.process.pid), sig)
            except OSError:
                self.process.send_signal(sig)

    def close(self):
        if self.alive:
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
                self.process.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                self.process.kill()
                try:
                    self.process.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    pass
        if self.slave_fd >= 0:
            try:
                os.close(self.slave_fd)
            except OSError:
                pass
            self.slave_fd = -1
        try:
            os.close(self.master_fd)
        except OSError:
            pass
        self.master_fd = -1


_PANES: Dict[str, Pane] = {}
_MAX_PANES = 8


def _cleanup_all_panes():
    for pane in list(_PANES.values()):
        try:
            pane.close()
        except Exception:
            pass
    _PANES.clear()


atexit.register(_cleanup_all_panes)


def _get_or_create(job_id: str) -> Pane:
    if job_id in _PANES:
        pane = _PANES[job_id]
        if not pane.alive:
            pane.close()
            _PANES[job_id] = Pane(job_id)
        return _PANES[job_id]
    if len(_PANES) >= _MAX_PANES:
        raise RuntimeError(f"Max {_MAX_PANES} background jobs reached. Kill one first.")
    _PANES[job_id] = Pane(job_id)
    return _PANES[job_id]


# ═══════════════════════════════════════════════════════════════════════════
# Single unified tool
# ═══════════════════════════════════════════════════════════════════════════

@register(
    "background",
    (
        "Manage persistent background processes (listeners, shells, relay tools).\n"
        "Actions:\n"
        "  run   — start a command in a named background job (auto-creates job if needed)\n"
        "          Returns initial output captured while wait_seconds elapses.\n"
        "  read  — read accumulated output from a running job (non-blocking poll)\n"
        "  send  — send raw input to a job; use \\x03 for Ctrl+C, \\n for Enter\n"
        "  kill  — terminate a background job\n"
        "  list  — list all active background jobs\n"
        "\n"
        "Parameters:\n"
        "  action      (required) one of: run | read | send | kill | list\n"
        "  job_id      name for the job, e.g. 'relay', 'winrm', 'listener'\n"
        "              (omit for 'list'; auto-generated if omitted for 'run')\n"
        "  command     shell command to execute (required for action='run')\n"
        "  input       text to send to stdin   (required for action='send')\n"
        "  wait        seconds to wait for output after 'run' (default 3, max 30)\n"
        "\n"
        "Typical workflow:\n"
        "  1. background(action='run', job_id='relay', command='ntlmrelayx ...')\n"
        "  2. [trigger auth from victim via bash]\n"
        "  3. background(action='read', job_id='relay')  # poll for captured hash\n"
        "  4. background(action='kill', job_id='relay')\n"
    ),
)
def background(
    action: str,
    job_id: str = "",
    command: str = "",
    input: str = "",
    wait: float = 3.0,
) -> str:
    action = action.strip().lower()

    # ── list ─────────────────────────────────────────────────────────────────
    if action == "list":
        if not _PANES:
            return "No active background jobs."
        lines = [f"{'Job ID':<18} {'PID':<8} Status"]
        lines.append("─" * 38)
        for jid, pane in _PANES.items():
            status = "running" if pane.alive else f"exited({pane.process.returncode})"
            lines.append(f"{jid:<18} {pane.process.pid:<8} {status}")
        return "\n".join(lines)

    # ── run ──────────────────────────────────────────────────────────────────
    if action == "run":
        if not command:
            return "Error: 'command' is required for action='run'."
        if not job_id:
            job_id = "job-" + uuid.uuid4().hex[:6]
        try:
            pane = _get_or_create(job_id)
        except RuntimeError as e:
            return f"Error: {e}"
        pane.write(command + "\n")
        wait_clamped = max(0.5, min(float(wait), 30.0))
        output = strip_ansi(pane.read(timeout=wait_clamped))
        status = "running" if pane.alive else "exited"
        return (
            f"[job '{job_id}' started — PID {pane.process.pid}, status: {status}]\n"
            f"{output or '(no output yet — job is still starting)'}"
        )

    # ── read ─────────────────────────────────────────────────────────────────
    if action == "read":
        if not job_id:
            return "Error: 'job_id' is required for action='read'."
        if job_id not in _PANES:
            existing = list(_PANES.keys())
            hint = f" Active jobs: {existing}." if existing else " No active jobs."
            return f"Error: job '{job_id}' does not exist.{hint}"
        pane = _PANES[job_id]
        output = strip_ansi(pane.read(timeout=1.0))
        status = "running" if pane.alive else f"exited({pane.process.returncode})"
        if not output:
            return f"[job '{job_id}' — {status} — no new output]"
        return f"[job '{job_id}' — {status}]\n{output}"

    # ── send ─────────────────────────────────────────────────────────────────
    if action == "send":
        if not job_id:
            return "Error: 'job_id' is required for action='send'."
        if job_id not in _PANES:
            return f"Error: job '{job_id}' does not exist."
        if not input:
            return "Error: 'input' is required for action='send'."
        pane = _PANES[job_id]
        processed = (
            input
            .replace("\\x03", "\x03")
            .replace("\\x04", "\x04")
            .replace("\\x1a", "\x1a")
            .replace("\\n", "\n")
        )
        pane.write(processed)
        output = strip_ansi(pane.read(timeout=0.5))
        return f"[sent to '{job_id}']\n{output}" if output else f"[sent to '{job_id}']"

    # ── kill ─────────────────────────────────────────────────────────────────
    if action == "kill":
        if not job_id:
            return "Error: 'job_id' is required for action='kill'."
        if job_id not in _PANES:
            return f"Error: job '{job_id}' does not exist."
        _PANES[job_id].close()
        del _PANES[job_id]
        return f"[job '{job_id}' killed]"

    return f"Error: unknown action '{action}'. Valid actions: run, read, send, kill, list."
