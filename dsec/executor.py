"""
DSEC Command Executor
Run local shell commands with streaming output and interrupt support.
"""
from __future__ import annotations

import os
import re as _re
import shlex
import subprocess
import threading
from typing import Callable, Optional


# ─────────────────────────────────────────────────────────────────────────────
# Sudo helpers
# ─────────────────────────────────────────────────────────────────────────────

# Match 'sudo' only when it is actually the command being run, not inside
# a quoted argument (e.g. nxc -X "sudo cmd").  We consider sudo "leading"
# when it appears at the very start of the string or right after a shell
# separator (&&, ||, ;, |, backtick, or opening paren/brace).
_LEADING_SUDO_RE = _re.compile(
    r'(?:^|(?<=&&)|(?<=\|\|)|(?<=;)|(?<=\|)|(?<=`)|(?<=\())(\s*)sudo\b'
)


def _has_sudo(cmd: "str | list[str]") -> bool:
    if isinstance(cmd, list):
        return bool(cmd) and cmd[0] == "sudo"
    return bool(_LEADING_SUDO_RE.search(cmd))


def _inject_sudo_password_inline(cmd: str, password: str) -> str:
    """
    Insert a printf pipe directly before the first leading sudo so that
    sudo -S reads the password from stdin.  Inserting at the sudo site
    (not at string start) keeps compound commands like 'A && sudo B'
    working correctly:

        A && printf '%s\\n' 'PASS' | sudo -S -p "" B

    Bash parses | before &&, so printf's stdout goes to sudo, not A.

    -S  → read password from stdin
    -p "" → suppress the 'Password:' prompt
    """
    first_match = _LEADING_SUDO_RE.search(cmd)
    if not first_match:
        return cmd
    start, end = first_match.span()
    leading_space = first_match.group(1)
    pw_quoted = shlex.quote(password)
    prefix = f"printf '%s\\n' {pw_quoted} | "
    # Insert: [before match][leading_space][prefix][sudo -S -p ""][rest]
    return cmd[:start] + leading_space + prefix + 'sudo -S -p ""' + cmd[end:]


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

        # Inject sudo password inline: printf 'PASS' | sudo -S -p "" cmd
        # Works regardless of TTY, env_reset, or macOS sandbox restrictions.
        if sudo_password and _has_sudo(argv):
            if isinstance(argv, str):
                argv = _inject_sudo_password_inline(argv, sudo_password)
            # list form: convert to shell string so we can use the pipe trick
            elif isinstance(argv, list) and argv and argv[0] == "sudo":
                argv = _inject_sudo_password_inline(shlex.join(argv), sudo_password)
                shell = True  # now a shell string

        try:
            env = os.environ.copy()
            env.pop("DSEC_SUDO_PASS", None)  # don't leak into child env
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
