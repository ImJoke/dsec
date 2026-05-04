"""
DSEC Command Executor
Run local shell commands with streaming output and interrupt support.
"""
from __future__ import annotations

import os
import signal
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


def _inject_sudo_stdin_flag(cmd: str) -> str:
    """Add -S -p '' flags to the first leading sudo so it reads from stdin.

    Returns the modified command.  The actual password is fed via Popen's
    stdin to avoid leaking it in `ps aux`.
    """
    first_match = _LEADING_SUDO_RE.search(cmd)
    if not first_match:
        return cmd
    start, end = first_match.span()
    leading_space = first_match.group(1)
    return cmd[:start] + leading_space + 'sudo -S -p ""' + cmd[end:]


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
        """Send SIGTERM to the entire process group of the running process.
        Returns True if something was running."""
        with self._lock:
            if self._proc and self._proc.poll() is None:
                try:
                    os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
                except (OSError, ProcessLookupError):
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

        # Inject sudo -S flag and feed password via stdin pipe (not visible in ps aux).
        _sudo_stdin: Optional[str] = None
        if sudo_password and _has_sudo(argv):
            if isinstance(argv, str):
                argv = _inject_sudo_stdin_flag(argv)
            elif isinstance(argv, list) and argv and argv[0] == "sudo":
                argv = _inject_sudo_stdin_flag(shlex.join(argv))
                shell = True
            _sudo_stdin = sudo_password + "\n"

        try:
            env = os.environ.copy()
            env.pop("DSEC_SUDO_PASS", None)
            # Run the child in its own process group so we can kill the entire
            # group (shell + spawned children + orphans) on timeout. Without
            # this, a `trap '' TERM; sleep 30` shell ignores SIGTERM, the
            # spawned `sleep` survives the SIGKILL on the shell parent, and
            # our pipe-reader threads block until the orphaned child exits.
            with self._lock:
                self._proc = subprocess.Popen(
                    argv,
                    stdin=subprocess.PIPE if _sudo_stdin else None,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1,
                    shell=shell,
                    cwd=cwd or None,
                    env=env,
                    start_new_session=True,
                )
            proc = self._proc

            if _sudo_stdin and proc.stdin:
                try:
                    proc.stdin.write(_sudo_stdin)
                    proc.stdin.flush()
                except OSError:
                    pass
                finally:
                    # close() must run even if write/flush failed; otherwise the
                    # child blocks forever waiting for stdin EOF on sudo prompts.
                    try:
                        proc.stdin.close()
                    except OSError:
                        pass

            exception_holder = {"out": None, "err": None}

            def _read_stdout() -> None:
                assert proc.stdout is not None
                try:
                    for line in proc.stdout:
                        stdout_parts.append(line)
                        if on_stdout:
                            on_stdout(line)
                except (OSError, ValueError) as e:
                    exception_holder["out"] = e

            def _read_stderr() -> None:
                assert proc.stderr is not None
                try:
                    for line in proc.stderr:
                        stderr_parts.append(line)
                        if on_stderr:
                            on_stderr(line)
                except (OSError, ValueError) as e:
                    exception_holder["err"] = e

            t_out = threading.Thread(target=_read_stdout, daemon=True)
            t_err = threading.Thread(target=_read_stderr, daemon=True)
            t_out.start()
            t_err.start()

            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                # Kill the WHOLE process group so trap-ignoring shells +
                # spawned-but-unreaped children all die. Without group-kill,
                # a `trap '' TERM; sleep 30` would let the sleep keep our
                # stdout pipe open for 30s and stall the reader threads.
                _killed_group = False
                try:
                    pgid = os.getpgid(proc.pid)
                    os.killpg(pgid, signal.SIGTERM)
                    _killed_group = True
                except (OSError, ProcessLookupError):
                    proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    if _killed_group:
                        try:
                            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                        except (OSError, ProcessLookupError):
                            proc.kill()
                    else:
                        proc.kill()
                    try:
                        proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        pass
                interrupted = True

            # Reader threads should exit within 1-2s after the process group
            # is fully dead (pipes EOF). Cap at 3s — beyond that the threads
            # are stuck on a fd held open by an unkillable orphan, and the
            # explicit pipe-close below handles that.
            t_out.join(timeout=3)
            t_err.join(timeout=3)

            # If a reader thread is still alive (rare: shell spawned a child
            # that holds the pipe open), force-close the pipe so the thread
            # gets EOF and exits. Otherwise daemon threads accumulate over a
            # 100+ command run and eventually exhaust file descriptors.
            if t_out.is_alive() and proc.stdout is not None:
                try:
                    proc.stdout.close()
                except Exception:
                    pass
                t_out.join(timeout=2)
            if t_err.is_alive() and proc.stderr is not None:
                try:
                    proc.stderr.close()
                except Exception:
                    pass
                t_err.join(timeout=2)

            # Report reader thread exceptions (they would otherwise be lost)
            if exception_holder.get("out"):
                try:
                    import sys as _sys
                    print(f"Stdout reader thread error: {exception_holder['out']}", file=_sys.stderr)
                except Exception:
                    pass
            if exception_holder.get("err"):
                try:
                    import sys as _sys
                    print(f"Stderr reader thread error: {exception_holder['err']}", file=_sys.stderr)
                except Exception:
                    pass

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
