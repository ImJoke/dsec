"""
DSEC PTY Terminal – Persistent Split-Terminal Multiplexer (tmux-style)

Provides the agent with multiple persistent terminal panes that run
independently. Each pane is a real PTY with a bash shell, allowing the
agent to run long-lived processes (e.g., listeners, servers) in the
background while continuing to interact with other panes.

Inspired by: OpenInterpreter, tmux
"""
import atexit
import os
import pty
import select
import signal
import subprocess
import time
import fcntl
import termios
import struct
import re
from typing import Dict, Any, List, Optional

from dsec.core.registry import register


def strip_ansi(text: str) -> str:
    """Removes ANSI escape sequences from a string."""
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)


class Pane:
    """A single persistent PTY pane with a bash shell and proper controlling terminal."""

    def __init__(self, pane_id: str):
        self.pane_id = pane_id
        self.master_fd, self.slave_fd = pty.openpty()
        
        # Proper PTY setup on macOS/Linux
        def preexec():
            try:
                os.setsid()
                # On some systems, we need to explicitly set the controlling terminal
                # We use fd 0 (stdin) which is already the slave_fd
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
        # Close parent's copy of slave_fd — the child keeps it open.
        # Keeping it open in the parent prevents EIO/EOF from being raised on
        # master_fd when the child exits, which is the root cause of stuck reads.
        try:
            os.close(self.slave_fd)
        except OSError:
            pass
        self.slave_fd = -1

        # Set master_fd to non-blocking
        fl = fcntl.fcntl(self.master_fd, fcntl.F_GETFL)
        fcntl.fcntl(self.master_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        # Read the initial prompt (with a bit more patience)
        time.sleep(0.3)
        self.read()

    @property
    def alive(self) -> bool:
        return self.process.poll() is None

    def write(self, data: str):
        if not self.alive:
            raise RuntimeError(f"Pane '{self.pane_id}' process has exited.")
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
                    start_time = time.time()  # Reset timeout on data
                except OSError:
                    break
            else:
                if time.time() - start_time > timeout:
                    break
        return output.decode("utf-8", errors="replace")

    def send_signal(self, sig: int):
        """Send a signal to the shell process group."""
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
    """Kill all panes at process exit to prevent orphaned PTY processes."""
    for pane in list(_PANES.values()):
        try:
            pane.close()
        except Exception:
            pass
    _PANES.clear()


atexit.register(_cleanup_all_panes)


# ═══════════════════════════════════════════════════════════════════════════
# Registered Tools
# ═══════════════════════════════════════════════════════════════════════════


@register(
    "pty_create_pane",
    "Creates a new persistent background terminal pane (like a tmux window). Max 8 panes.",
)
def pty_create_pane(pane_id: str) -> str:
    if pane_id in _PANES:
        if _PANES[pane_id].alive:
            return f"Pane '{pane_id}' already exists and is alive."
        # Dead pane — clean up and recreate
        _PANES[pane_id].close()
        del _PANES[pane_id]

    if len(_PANES) >= _MAX_PANES:
        return f"Error: maximum {_MAX_PANES} panes reached. Close one first with pty_close_pane."

    _PANES[pane_id] = Pane(pane_id)
    return f"Created new PTY pane: '{pane_id}' (PID: {_PANES[pane_id].process.pid})"


@register(
    "pty_run_command",
    "Runs a command in a named terminal pane and returns immediate output. Good for servers or listeners.",
)
def pty_run_command(pane_id: str, command: str, timeout: float = 1.0) -> str:
    if pane_id not in _PANES:
        if len(_PANES) >= _MAX_PANES:
            return (
                f"Error: max {_MAX_PANES} panes reached; cannot auto-create '{pane_id}'. "
                "Close an existing pane first with pty_close_pane."
            )
        _PANES[pane_id] = Pane(pane_id)

    pane = _PANES[pane_id]
    if not pane.alive:
        pane.close()
        _PANES[pane_id] = Pane(pane_id)
        pane = _PANES[pane_id]

    pane.write(command + "\n")
    raw_output = pane.read(timeout=max(0.2, min(timeout, 30.0)))
    return strip_ansi(raw_output)


@register(
    "pty_read_output",
    "Reads recent asynchronous output from a background terminal pane.",
)
def pty_read_output(pane_id: str) -> str:
    if pane_id not in _PANES:
        existing = list(_PANES.keys())
        hint = f" Active panes: {existing}. Use pty_list_panes to list all panes, or pty_create_pane to create a new one." if existing else " No active panes exist. Use pty_create_pane to create one."
        return f"Error: pane '{pane_id}' does not exist.{hint}"

    raw_output = _PANES[pane_id].read(timeout=0.3)
    if not raw_output:
        return "(no new output)"
    return strip_ansi(raw_output)


@register(
    "pty_send_input",
    "Sends raw keystrokes to a pane. Use \\x03 for Ctrl+C, \\x04 for Ctrl+D, \\x1a for Ctrl+Z.",
)
def pty_send_input(pane_id: str, keys: str) -> str:
    if pane_id not in _PANES:
        existing = list(_PANES.keys())
        hint = f" Active panes: {existing}." if existing else " No active panes exist."
        return f"Error: pane '{pane_id}' does not exist.{hint}"

    # Interpret common escape sequences
    processed = keys.replace("\\x03", "\x03").replace("\\x04", "\x04").replace("\\x1a", "\x1a").replace("\\n", "\n")
    _PANES[pane_id].write(processed)
    raw_output = _PANES[pane_id].read(timeout=0.3)
    return strip_ansi(raw_output)


@register(
    "pty_send_keys",
    "Alias for pty_send_input. Sends raw keystrokes to a pane (supports \\x03/\\x04/\\n escapes).",
)
def pty_send_keys(pane_id: str, keys: str) -> str:
    return pty_send_input(pane_id=pane_id, keys=keys)


@register(
    "pty_send_signal",
    "Sends a POSIX signal to a pane's shell process group. Common: 2=SIGINT, 15=SIGTERM, 9=SIGKILL.",
)
def pty_send_signal(pane_id: str, signal_number: int = 2) -> str:
    if pane_id not in _PANES:
        return f"Error: pane '{pane_id}' does not exist."

    pane = _PANES[pane_id]
    if not pane.alive:
        return f"Pane '{pane_id}' process already exited."

    pane.send_signal(signal_number)
    time.sleep(0.2)
    raw_output = pane.read(timeout=0.3)
    status = "alive" if pane.alive else "exited"
    return f"Sent signal {signal_number} to pane '{pane_id}' (status: {status})\n{strip_ansi(raw_output)}"


@register(
    "pty_list_panes",
    "Lists all active terminal panes with their status and PID.",
)
def pty_list_panes() -> str:
    if not _PANES:
        return "No active panes. Use pty_create_pane to create one."

    lines = [f"{'Pane ID':<15} {'PID':<8} {'Status':<10}"]
    lines.append("-" * 35)
    for pane_id, pane in _PANES.items():
        status = "alive" if pane.alive else f"exited({pane.process.returncode})"
        lines.append(f"{pane_id:<15} {pane.process.pid:<8} {status:<10}")
    return "\n".join(lines)


@register(
    "pty_close_pane",
    "Closes and cleans up a terminal pane, terminating its shell process.",
)
def pty_close_pane(pane_id: str) -> str:
    if pane_id not in _PANES:
        return f"Error: pane '{pane_id}' does not exist."

    _PANES[pane_id].close()
    del _PANES[pane_id]
    return f"Closed pane '{pane_id}'."

