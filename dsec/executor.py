"""
DSEC Command Executor
Run local shell commands with streaming output and interrupt support.
"""
from __future__ import annotations

import os
import re as _re
import shlex
import stat
import subprocess
import tempfile
import threading
from typing import Callable, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Sudo helpers
# ─────────────────────────────────────────────────────────────────────────────

_SUDO_RE = _re.compile(r'\bsudo\b')


def _has_sudo(cmd: "str | list[str]") -> bool:
    if isinstance(cmd, list):
        return bool(cmd) and cmd[0] == "sudo"
    return bool(_SUDO_RE.search(cmd))


def _inject_sudo_A(cmd: "str | list[str]") -> "str | list[str]":
    """Replace first sudo with sudo -A (use SUDO_ASKPASS helper)."""
    if isinstance(cmd, list):
        if cmd and cmd[0] == "sudo" and "-A" not in cmd:
            return ["sudo", "-A"] + cmd[1:]
        return cmd
    return _SUDO_RE.sub("sudo -A", cmd, count=1)


def _create_askpass(password: str) -> str:
    """Write a temp chmod-700 shell script that prints the sudo password."""
    fd, path = tempfile.mkstemp(prefix=".dsec_ap_", suffix=".sh")
    try:
        script = f"#!/bin/sh\nprintf '%s\\n' {shlex.quote(password)}\n"
        os.write(fd, script.encode())
        os.fchmod(fd, stat.S_IRWXU)
    finally:
        os.close(fd)
    return path


# ─────────────────────────────────────────────────────────────────────────────
# Result
# ─────────────────────────────────────────────────────────────────────────────

class CommandResult:
    """Holds the finished output of a command."""

    def __init__(
        self,
        command: str,
        stdout: str,
        stderr: str,
        returncode: int,
        interrupted: bool = False,
    ) -> None:
        self.command = command
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode
        self.interrupted = interrupted

    # ── helpers ───────────────────────────────────────────────────────────────

    def combined_output(self) -> str:
        parts: list[str] = []
        if self.stdout.strip():
            parts.append(self.stdout.rstrip())
        if self.stderr.strip():
            parts.append(f"[stderr]\n{self.stderr.rstrip()}")
        return "\n".join(parts)

    def as_tool_output(self) -> str:
        """Format as a [TOOL OUTPUT] block for injecting into the AI prompt."""
        lines = [f"$ {self.command}", self.combined_output() or "(no output)"]
        if self.interrupted:
            lines.append("[interrupted by user]")
        elif self.returncode != 0:
            lines.append(f"[exit code: {self.returncode}]")
        return "\n".join(lines)

    def short_summary(self) -> str:
        out = self.combined_output()
        if len(out) > 300:
            out = out[:300] + "\n…(truncated)"
        return out or "(no output)"


# ─────────────────────────────────────────────────────────────────────────────
# Runner
# ─────────────────────────────────────────────────────────────────────────────

class CommandRunner:
    """
    Runs a single shell command at a time.

    Usage::

        runner = CommandRunner()
        result = runner.run("nmap -sV 10.10.11.23",
                            on_stdout=lambda l: print(l, end=""))
        # In another thread: runner.interrupt()
    """

    def __init__(self) -> None:
        self._proc: Optional[subprocess.Popen] = None  # type: ignore[type-arg]
        self._lock = threading.Lock()

    # ── public ────────────────────────────────────────────────────────────────

    def is_running(self) -> bool:
        with self._lock:
            return self._proc is not None and self._proc.poll() is None

    def interrupt(self) -> bool:
        """Send SIGTERM to the running process.  Returns True if something was running."""
        with self._lock:
            if self._proc and self._proc.poll() is None:
                try:
                    self._proc.terminate()
                except OSError:
                    pass
                return True
        return False

    def run(
        self,
        command: str,
        *,
        on_stdout: Optional[Callable[[str], None]] = None,
        on_stderr: Optional[Callable[[str], None]] = None,
        timeout: int = 300,
        shell: bool = False,
        cwd: Optional[str] = None,
        sudo_password: Optional[str] = None,
    ) -> CommandResult:
        """
        Run *command* (synchronously) and return a CommandResult.

        :param on_stdout: called line-by-line as stdout arrives.
        :param on_stderr: called line-by-line as stderr arrives.
        :param timeout:   seconds before the process is SIGTERM'd (default 300).
        :param shell:     if True, pass command as a shell string (risky – default False).
        :param cwd:       working directory override.
        """
        stdout_parts: list[str] = []
        stderr_parts: list[str] = []
        interrupted = False

        # Resolve the actual argv
        if shell:
            argv: str | list[str] = command
        else:
            try:
                argv = shlex.split(command)
            except ValueError as exc:
                return CommandResult(command, "", f"Parse error: {exc}", 1)

        # Check the executable exists (skip for shell mode)
        if not shell:
            exe = argv[0] if argv else ""
            if not exe:
                return CommandResult(command, "", "Empty command.", 1)
            # shutil.which would be ideal but let the OS raise FileNotFoundError

        # Prepare sudo password injection via SUDO_ASKPASS (no stdin race condition)
        _sudo_inject = bool(sudo_password and _has_sudo(argv))
        _askpass_path: Optional[str] = None
        if _sudo_inject:
            argv = _inject_sudo_A(argv)  # type: ignore[assignment]
            _askpass_path = _create_askpass(sudo_password)

        try:
            env = os.environ.copy()
            env.pop("DSEC_SUDO_PASS", None)  # don't leak into child env
            if _askpass_path:
                env["SUDO_ASKPASS"] = _askpass_path
            with self._lock:
                self._proc = subprocess.Popen(
                    argv,
                    stdin=None,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    shell=shell,
                    cwd=cwd or None,
                    env=env,
                )
            proc = self._proc  # local ref for thread closures

            def _read_stdout() -> None:
                assert proc.stdout is not None
                try:
                    for line in proc.stdout:
                        stdout_parts.append(line)
                        if on_stdout:
                            on_stdout(line)
                except (OSError, ValueError):
                    pass

            def _read_stderr() -> None:
                assert proc.stderr is not None
                try:
                    for line in proc.stderr:
                        stderr_parts.append(line)
                        if on_stderr:
                            on_stderr(line)
                except (OSError, ValueError):
                    pass

            t_out = threading.Thread(target=_read_stdout, daemon=True)
            t_err = threading.Thread(target=_read_stderr, daemon=True)
            t_out.start()
            t_err.start()

            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                interrupted = True

            t_out.join(timeout=10)
            t_err.join(timeout=10)

            returncode = proc.returncode if proc.returncode is not None else 0

        except FileNotFoundError:
            cmd_name = command.split()[0] if command.split() else command
            return CommandResult(command, "", f"Command not found: {cmd_name}", 127)
        except PermissionError:
            return CommandResult(command, "", f"Permission denied: {command}", 126)
        except Exception as exc:  # noqa: BLE001
            return CommandResult(command, "", f"Execution error: {type(exc).__name__}: {exc}", 1)
        finally:
            with self._lock:
                self._proc = None
            if _askpass_path:
                try:
                    os.unlink(_askpass_path)
                except OSError:
                    pass

        return CommandResult(
            command=command,
            stdout="".join(stdout_parts),
            stderr="".join(stderr_parts),
            returncode=returncode,
            interrupted=interrupted,
        )


# ─────────────────────────────────────────────────────────────────────────────
# Singleton runner (shared across the shell session)
# ─────────────────────────────────────────────────────────────────────────────

_runner = CommandRunner()


def get_runner() -> CommandRunner:
    """Return the process-level shared CommandRunner."""
    return _runner
