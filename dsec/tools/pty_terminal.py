"""
DSEC Background Process Manager

Two distinct use cases, handled cleanly:

1. LISTENERS / SERVERS (ntlmrelayx, nc, chisel, ligolo):
   background(action="run",  job_id="relay", command="ntlmrelayx.py ...", wait=5)
   background(action="read", job_id="relay")
   background(action="kill", job_id="relay")

2. INTERACTIVE SHELLS (evil-winrm, mssqlclient, python REPL):
   background(action="run",  job_id="winrm", command="evil-winrm -i ip -u user -H hash", wait=8)
   background(action="exec", job_id="winrm", command="whoami /priv", wait=15)
   background(action="exec", job_id="winrm", command="certutil -store My", wait=15)
   → exec sends the command and waits for the shell prompt to reappear (smart, no timing guesses)

NOTE: For single WinRM commands, prefer `nxc winrm -x "cmd"` over background — cleaner and stateless.
Use background only when you need a persistent session (file uploads, multi-step ops).
"""
import atexit
import os
import pty
import re
import select
import signal
import struct
import subprocess
import time
import fcntl
import termios
import uuid
from typing import Dict, List, Optional

from dsec.core.registry import register


# Output above this threshold is saved to /tmp and the AI gets a preview + path
_LARGE_OUTPUT_THRESHOLD = 8000  # chars


def _maybe_save_output(job_id: str, output: str) -> str:
    """If output exceeds threshold, save to /tmp and return preview + path."""
    if len(output) <= _LARGE_OUTPUT_THRESHOLD:
        return output
    from datetime import datetime as _dt
    ts = _dt.now().strftime("%Y%m%d_%H%M%S")
    safe_id = re.sub(r"[^a-zA-Z0-9_-]", "_", job_id)
    path = f"/tmp/dsec_{safe_id}_{ts}.txt"
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(output)
        preview = output[:3000]
        return (
            f"[Output large ({len(output):,} chars) — full output saved to {path}]\n"
            f"{preview}\n"
            f"...[read {path} for complete output]"
        )
    except OSError:
        return output[:_LARGE_OUTPUT_THRESHOLD] + f"\n...[truncated at {_LARGE_OUTPUT_THRESHOLD} chars]"


def strip_ansi(text: str) -> str:
    ansi_escape = re.compile(r'(?:\x1B[@-_]|[\x80-\x9F])[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', text)


# Prompt patterns for known interactive shells — used by action="exec"
# All patterns are plain substring matches (no glob/fnmatch).
# evil-winrm prompt is literally: *Evil-WinRM shell v3.x Final* PS C:\Users\>
# So check for "Evil-WinRM" (the asterisks are literal in the output but vary in position).
_PROMPT_PATTERNS: List[str] = [
    "Evil-WinRM",      # evil-winrm (literal asterisks in prompt vary; match core string)
    "PS C:\\",         # PowerShell
    "PS C:/",
    "C:\\Windows\\",
    "C:\\Users\\",
    "SQL>",            # mssqlclient
    ">>> ",            # Python REPL
    "$ ",              # bash
    "# ",              # root bash
    "bash-",           # bash without PS1
    "smb: \\>",        # smbclient
]


class Pane:
    """A persistent PTY pane with a bash shell."""

    # Dimensions used for all panes — large enough for tool output
    COLS: int = 220
    ROWS: int = 50

    def __init__(self, pane_id: str, init_timeout: float = 5.0):
        self.pane_id = pane_id
        self.master_fd, self.slave_fd = pty.openpty()

        # Set a real terminal size immediately — default is 0×0 which breaks
        # programs that call TIOCGWINSZ (less, vim, evil-winrm, certipy …)
        size = struct.pack("HHHH", self.ROWS, self.COLS, 0, 0)
        try:
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, size)
            fcntl.ioctl(self.slave_fd,  termios.TIOCSWINSZ, size)
        except OSError:
            pass

        def preexec():
            try:
                os.setsid()
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)
                # Re-apply size inside the child process
                fcntl.ioctl(0, termios.TIOCSWINSZ,
                            struct.pack("HHHH", Pane.ROWS, Pane.COLS, 0, 0))
            except Exception:
                pass

        env = os.environ.copy()
        env.update({
            "TERM": "xterm-256color",
            "COLUMNS": str(self.COLS),
            "LINES": str(self.ROWS),
        })

        self.process = subprocess.Popen(
            ["/bin/bash"],
            stdin=self.slave_fd,
            stdout=self.slave_fd,
            stderr=self.slave_fd,
            close_fds=True,
            env=env,
            preexec_fn=preexec,
        )
        try:
            os.close(self.slave_fd)
        except OSError:
            pass
        self.slave_fd = -1

        fl = fcntl.fcntl(self.master_fd, fcntl.F_GETFL)
        fcntl.fcntl(self.master_fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)

        # Per-pane command history: list of {"cmd": str, "output": str}
        self._history: List[Dict[str, str]] = []

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
        if self.master_fd < 0:
            raise RuntimeError(f"Job '{self.pane_id}' PTY is already closed.")
        if not self.alive:
            raise RuntimeError(f"Job '{self.pane_id}' process has exited.")
        os.write(self.master_fd, data.encode("utf-8"))

    def read(self, timeout: float = 0.5) -> str:
        """Read all available output until no new data for `timeout` seconds."""
        output = b""
        start_time = time.time()
        while True:
            fd = self.master_fd  # snapshot — close() may race
            if fd < 0:
                break
            try:
                r, _, _ = select.select([fd], [], [], 0.05)
            except (ValueError, OSError):
                break
            if fd in r:
                try:
                    chunk = os.read(fd, 8192)
                    if not chunk:
                        break
                    output += chunk
                    start_time = time.time()  # reset idle timer on new data
                except OSError:
                    break
            else:
                if time.time() - start_time > timeout:
                    break
        return output.decode("utf-8", errors="replace")

    def read_until_prompt(self, patterns: List[str], timeout: float = 15.0) -> str:
        """
        Read until one of the prompt patterns appears in output or timeout.
        Returns the full output INCLUDING the prompt line.
        """
        output = b""
        start_time = time.time()
        while time.time() - start_time < timeout:
            fd = self.master_fd  # snapshot — close() may race
            if fd < 0:
                break
            try:
                r, _, _ = select.select([fd], [], [], 0.05)
            except (ValueError, OSError):
                break
            if fd in r:
                try:
                    chunk = os.read(fd, 8192)
                    if not chunk:
                        break
                    output += chunk
                    decoded = output.decode("utf-8", errors="replace")
                    clean = strip_ansi(decoded)
                    for pat in patterns:
                        if pat in clean:
                            return clean
                except OSError:
                    break
            else:
                # No data — if we already have output and saw something prompt-like, stop
                if output:
                    decoded = strip_ansi(output.decode("utf-8", errors="replace"))
                    for pat in patterns:
                        if pat in decoded:
                            return decoded
        return strip_ansi(output.decode("utf-8", errors="replace"))

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


import threading as _threading

_PANES: Dict[str, Pane] = {}
_PANES_LOCK = _threading.Lock()
_MAX_PANES = 8
_RESUME_ERR = (
    "Job '{}' does not exist — background jobs are in-memory and do not survive "
    "session compression or resume. Use action='run' to restart the job, or check "
    "action='list' to see what's currently running."
)


def _cleanup_all_panes():
    with _PANES_LOCK:
        panes = list(_PANES.values())
        _PANES.clear()
    for pane in panes:
        try:
            pane.close()
        except Exception:
            pass


atexit.register(_cleanup_all_panes)


def _get_or_create(job_id: str) -> Pane:
    """Atomically look up or create a pane for the given job_id.

    Lock scope intentionally narrow: spawn the new Pane (which opens a PTY
    and forks bash) outside the lock so other callers can still read/list
    while a slow spawn is in progress.
    """
    with _PANES_LOCK:
        existing = _PANES.get(job_id)
        if existing and existing.alive:
            return existing

    # Either new id, or stale dead pane — spawn a fresh one outside the lock.
    new_pane = Pane(job_id)

    with _PANES_LOCK:
        # Re-check inside the lock in case another thread won the race.
        existing = _PANES.get(job_id)
        if existing and existing.alive:
            # Lost the race — discard our spare and use the winner.
            try:
                new_pane.close()
            except Exception:
                pass
            return existing
        if existing and not existing.alive:
            try:
                existing.close()
            except Exception:
                pass
        if len(_PANES) >= _MAX_PANES and job_id not in _PANES:
            try:
                new_pane.close()
            except Exception:
                pass
            raise RuntimeError(f"Max {_MAX_PANES} background jobs reached. Kill one first.")
        _PANES[job_id] = new_pane
        return new_pane


def _clean_exec_output(raw: str, command: str) -> str:
    """
    Strip command echo and trailing prompt from exec output.
    Returns just the command's output, ready for the AI to parse.
    """
    lines = raw.splitlines()
    result_lines = []
    cmd_stripped = command.strip()
    in_output = False

    for line in lines:
        line_clean = line.strip()
        # Skip the command echo line
        if not in_output:
            if cmd_stripped and cmd_stripped in line_clean:
                in_output = True
                continue
            # Fallback: start after first non-empty line
            if line_clean:
                in_output = True
                result_lines.append(line)
            continue
        # Skip trailing prompt lines
        is_prompt = any(pat.strip() in line_clean for pat in _PROMPT_PATTERNS if pat.strip())
        if is_prompt and (line_clean.endswith(">") or line_clean.endswith("$") or line_clean.endswith("# ")):
            break
        result_lines.append(line)

    return "\n".join(result_lines).strip()


# ═══════════════════════════════════════════════════════════════════════════
# Single unified tool
# ═══════════════════════════════════════════════════════════════════════════

@register(
    "background",
    (
        "Manage persistent background processes: listeners, relay tools, interactive shells.\n"
        "\n"
        "WHEN TO USE:\n"
        "  - Listeners/servers: ntlmrelayx, nc -lvnp, chisel, ligolo, responder\n"
        "  - Interactive shells: evil-winrm, mssqlclient, python REPL\n"
        "  - NOT for single WinRM commands — use `nxc winrm -x 'cmd'` instead (cleaner)\n"
        "\n"
        "ACTIONS:\n"
        "  run   — start command in a background job. For listeners: use wait=3-5.\n"
        "          For interactive shells (evil-winrm): use wait=8 to get the banner.\n"
        "  exec  — send ONE command to a running interactive shell and wait for the\n"
        "          prompt to reappear. Returns clean output. BEST for interactive shells.\n"
        "          Use this instead of send+read for evil-winrm, mssqlclient, etc.\n"
        "  read  — poll accumulated output from a listener (non-blocking)\n"
        "  send    — send raw keystrokes (\\x03=Ctrl+C, \\x04=Ctrl+D, \\n=Enter). Use for special keys only.\n"
        "  history — show command history for a job\n"
        "            mode='last' (default): last command + its output\n"
        "            mode='all':  every command + output run in this pane\n"
        "            Large outputs are auto-saved to /tmp/dsec_<job>_<ts>.txt — preview shown inline.\n"
        "  kill    — terminate a job\n"
        "  list    — list all active jobs\n"
        "\n"
        "PARAMETERS:\n"
        "  action   (required) run | exec | read | send | history | kill | list\n"
        "  job_id   name for this job (e.g. 'relay', 'winrm', 'listener')\n"
        "  command  shell command (required for run; the command to execute for exec)\n"
        "  input    raw keystrokes (required for send)\n"
        "  wait     seconds to wait for output after 'run' or 'exec' (default 3, max 30/60)\n"
        "  mode     for action='history': 'last' (default) or 'all'\n"
        "\n"
        "LARGE OUTPUT: Any output > 8000 chars is auto-saved to /tmp/dsec_<job>_<ts>.txt.\n"
        "  The tool returns a 3000-char preview + file path. Use bash `cat` or `grep` on the file.\n"
        "\n"
        "INTERACTIVE SHELL WORKFLOW (evil-winrm example):\n"
        "  1. background(action='run',  job_id='winrm', command='evil-winrm -i IP -u USER -H HASH', wait=8)\n"
        "  2. background(action='exec', job_id='winrm', command='whoami /priv', wait=15)\n"
        "  3. background(action='exec', job_id='winrm', command='certutil -store My', wait=15)\n"
        "  4. background(action='history', job_id='winrm', mode='all')  # review all commands run\n"
        "  5. background(action='kill', job_id='winrm')\n"
        "\n"
        "LISTENER WORKFLOW (ntlmrelayx example):\n"
        "  1. background(action='run',  job_id='relay', command='ntlmrelayx.py -t ldap://DC ...', wait=5)\n"
        "  2. [trigger auth from victim]\n"
        "  3. background(action='read', job_id='relay')   # poll for captured hashes\n"
        "  4. background(action='kill', job_id='relay')\n"
        "\n"
        "NOTE: Background jobs are IN-MEMORY. They do NOT survive session compression\n"
        "or resume. If a job 'does not exist', restart it with action='run'.\n"
    ),
    roles=("executor",),
)
def background(
    action: str,
    job_id: str = "",
    command: str = "",
    input: str = "",
    wait: float = 3.0,
    mode: str = "last",
) -> str:
    action = action.strip().lower()

    # ── list ─────────────────────────────────────────────────────────────────
    if action == "list":
        if not _PANES:
            return "No active background jobs. (Jobs are in-memory — they don't survive session resume.)"
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

        # Reject duplicate run on a pane that already has an active command.
        # Heuristic: pane exists, process alive, last command was issued within
        # the last 60 seconds and identical to this one. The model sometimes
        # re-emits the same background-run after a slow first response — the
        # second call would queue the SAME command behind the first and bork
        # the agent's mental model of which job is doing what.
        existing = _PANES.get(job_id)
        if existing and existing.alive and getattr(existing, "_history", None):
            last = existing._history[-1] if existing._history else None
            if last and last.get("cmd", "").strip() == command.strip():
                return (
                    f"[job '{job_id}' is already running '{command[:60]}' (PID {existing.process.pid}). "
                    "Use action='read' to poll output or action='kill' to stop. "
                    "Refusing duplicate run to avoid queueing the same command twice.]"
                )

        try:
            pane = _get_or_create(job_id)
        except RuntimeError as e:
            return f"Error: {e}"
        pane.write(command + "\n")
        # Cap wait at 10s for background runs — anything longer should poll via
        # action='read'. Previously up to 30s; that turned `background run` into
        # a near-blocking call when the model picked wait=20-30.
        wait_clamped = max(0.5, min(float(wait), 10.0))
        output = strip_ansi(pane.read(timeout=wait_clamped))
        status = "running" if pane.alive else "exited"
        # Track history (raw output before large-output truncation)
        pane._history.append({"cmd": command, "output": output})
        display_output = _maybe_save_output(job_id, output) if output else "(no output yet — use action=read to poll later)"
        return (
            f"[job '{job_id}' started — PID {pane.process.pid}, status: {status}]\n"
            f"{display_output}"
        )

    # ── exec (smart prompt-aware command dispatch) ────────────────────────────
    if action == "exec":
        if not job_id:
            return "Error: 'job_id' is required for action='exec'."
        if not command:
            return "Error: 'command' is required for action='exec'."
        if job_id not in _PANES:
            return _RESUME_ERR.format(job_id)
        pane = _PANES[job_id]
        if not pane.alive:
            return f"[job '{job_id}' has exited — use action='run' to restart]"

        # Clear any pending output before sending command
        pane.read(timeout=0.2)

        # Send the command
        pane.write(command + "\n")

        # Wait for a prompt pattern to signal completion
        wait_clamped = max(3.0, min(float(wait), 60.0))
        raw = pane.read_until_prompt(_PROMPT_PATTERNS, timeout=wait_clamped)

        # Clean up: strip command echo + trailing prompt
        clean = _clean_exec_output(raw, command)
        # Track history (raw clean output before large-output truncation)
        pane._history.append({"cmd": command, "output": clean})
        status = "running" if pane.alive else "exited"
        if not clean:
            return f"[job '{job_id}' exec '{command[:40]}' — {status}]\n(no output)"
        return f"[job '{job_id}' exec '{command[:40]}' — {status}]\n{_maybe_save_output(job_id, clean)}"

    # ── read ─────────────────────────────────────────────────────────────────
    if action == "read":
        if not job_id:
            return "Error: 'job_id' is required for action='read'."
        if job_id not in _PANES:
            return _RESUME_ERR.format(job_id)
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
            return _RESUME_ERR.format(job_id)
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

    # ── history ──────────────────────────────────────────────────────────────
    if action == "history":
        if not job_id:
            return "Error: 'job_id' is required for action='history'."
        if job_id not in _PANES:
            return _RESUME_ERR.format(job_id)
        pane = _PANES[job_id]
        if not pane._history:
            return f"[job '{job_id}'] No command history recorded yet."
        mode_lower = (mode or "last").strip().lower()
        if mode_lower in ("all", "full"):
            parts = [f"[job '{job_id}' — command history, {len(pane._history)} commands]"]
            for i, entry in enumerate(pane._history, 1):
                parts.append(f"\n── [{i}] $ {entry['cmd']}")
                parts.append(entry["output"] or "(no output)")
            combined = "\n".join(parts)
            return _maybe_save_output(job_id, combined)
        else:
            # mode="last" — only most recent command
            last = pane._history[-1]
            output = _maybe_save_output(job_id, last["output"] or "(no output)")
            return f"[job '{job_id}'] $ {last['cmd']}\n{output}"

    # ── kill ─────────────────────────────────────────────────────────────────
    if action == "kill":
        if not job_id:
            return "Error: 'job_id' is required for action='kill'."
        if job_id not in _PANES:
            return f"[job '{job_id}' does not exist — already gone or never started]"
        _PANES[job_id].close()
        del _PANES[job_id]
        return f"[job '{job_id}' killed]"

    return f"Error: unknown action '{action}'. Valid: run, exec, read, send, history, kill, list."
