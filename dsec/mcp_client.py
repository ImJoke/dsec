"""
DSEC MCP Client
Minimal Model Context Protocol client (JSON-RPC 2.0 over stdio).

Server definitions live in ~/.dsec/config.json under the key "mcp_servers":
    {
      "mcp_servers": {
        "filesystem": {
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
          "env": {}
        }
      }
    }

Usage::
    mgr = get_mcp_manager()
    mgr.connect("filesystem")
    tools = mgr.list_tools("filesystem")
    result = mgr.call_tool("filesystem", "read_file", {"path": "/tmp/test.txt"})
    mgr.disconnect("filesystem")
"""
from __future__ import annotations

import itertools
import json
import sys
import os
import subprocess
import threading
import time
import select
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional


CONFIG_PATH = Path.home() / ".dsec" / "config.json"

_JSONRPC_VERSION = "2.0"


# ─────────────────────────────────────────────────────────────────────────────
# Low-level JSON-RPC I/O helpers
# ─────────────────────────────────────────────────────────────────────────────

def _send(proc: subprocess.Popen, method: str, params: Any, req_id: int) -> None:  # type: ignore[type-arg]
    msg = json.dumps({
        "jsonrpc": _JSONRPC_VERSION,
        "id": req_id,
        "method": method,
        "params": params,
    }) + "\n"
    assert proc.stdin is not None
    proc.stdin.write(msg)
    proc.stdin.flush()


def _notify(proc: subprocess.Popen, method: str, params: Any) -> None:  # type: ignore[type-arg]
    msg = json.dumps({
        "jsonrpc": _JSONRPC_VERSION,
        "method": method,
        "params": params,
    }) + "\n"
    assert proc.stdin is not None
    proc.stdin.write(msg)
    proc.stdin.flush()


def _read_response(proc: subprocess.Popen, req_id: int, timeout: float = 10.0) -> Optional[Dict[str, Any]]:  # type: ignore[type-arg]
    """Block until we receive the JSON-RPC response for *req_id* or time out."""
    assert proc.stdout is not None
    deadline = time.monotonic() + timeout
    fd = None
    try:
        fd = proc.stdout.fileno()
    except Exception:
        # Fallback to simple readline if fileno unavailable
        fd = None

    while time.monotonic() < deadline:
        remaining = max(0.0, deadline - time.monotonic())
        try:
            if fd is not None:
                # Wait up to min(0.5, remaining) seconds for data
                r, _, _ = select.select([fd], [], [], min(0.5, remaining))
                if not r:
                    continue
                line = proc.stdout.readline()
            else:
                # Older fallback: non-blocking readline with small sleeps
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.05)
                    continue
        except (ValueError, OSError):
            # stdout closed or fileno invalid
            # Try to capture stderr for hints
            try:
                if proc.stderr:
                    err = proc.stderr.read()
                    if err:
                        # best-effort logging to stderr
                        print(f"MCP stderr: {err}", file=sys.stderr)
            except Exception:
                pass
            return None

        if not line:
            # EOF
            return None

        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("id") == req_id:
            return obj
    return None


# ─────────────────────────────────────────────────────────────────────────────
# MCPServer
# ─────────────────────────────────────────────────────────────────────────────

class MCPServer:
    """Wraps a single MCP server process."""

    def __init__(
        self,
        name: str,
        command: str,
        args: Optional[List[str]] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> None:
        self.name = name
        self._command = command
        self._args = args or []
        self._extra_env = env or {}
        self._proc: Optional[subprocess.Popen] = None  # type: ignore[type-arg]
        self._tools: List[Dict[str, Any]] = []
        self._req_id_gen = itertools.count(1)
        self._lock = threading.Lock()
        self._stderr_thread: Optional[threading.Thread] = None
        self._stderr_buf: list[str] = []

    # ── state ─────────────────────────────────────────────────────────────────

    @property
    def connected(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def connect(self, timeout: float = 10.0) -> bool:
        """Start the server process and perform MCP initialisation handshake."""
        if self.connected:
            return True

        env = os.environ.copy()
        env.update(self._extra_env)

        try:
            argv = [self._command] + self._args
            self._proc = subprocess.Popen(
                argv,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                env=env,
            )
        except FileNotFoundError:
            return False
        except Exception:  # noqa: BLE001
            return False

        # Drain stderr in background to prevent pipe buffer deadlock
        self._stderr_buf = []
        def _drain_stderr(proc: subprocess.Popen) -> None:  # type: ignore[type-arg]
            try:
                assert proc.stderr is not None
                for line in proc.stderr:
                    self._stderr_buf.append(line.rstrip("\n"))
                    if len(self._stderr_buf) > 200:
                        self._stderr_buf = self._stderr_buf[-100:]
            except (ValueError, OSError):
                pass
        self._stderr_thread = threading.Thread(target=_drain_stderr, args=(self._proc,), daemon=True)
        self._stderr_thread.start()

        # MCP initialise — all I/O under the lock
        with self._lock:
            req_id = next(self._req_id_gen)
            try:
                _send(self._proc, "initialize", {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "dsec", "version": "1.0"},
                }, req_id)
                resp = _read_response(self._proc, req_id, timeout=timeout)
            except Exception:  # noqa: BLE001
                self.disconnect()
                return False

            if not resp or "result" not in resp:
                self.disconnect()
                return False

            # Acknowledge
            try:
                _notify(self._proc, "notifications/initialized", {})
            except Exception:  # noqa: BLE001
                pass

        # Discover tools (acquires lock internally)
        self._refresh_tools(timeout=timeout)
        return True

    def disconnect(self) -> None:
        if self._proc:
            try:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    self._proc.wait()
            except Exception:  # noqa: BLE001
                pass
            finally:
                for pipe in (self._proc.stdin, self._proc.stdout, self._proc.stderr):
                    if pipe:
                        try:
                            pipe.close()
                        except Exception:  # noqa: BLE001
                            pass
                self._proc = None
        self._tools = []

    # ── tool management ───────────────────────────────────────────────────────

    def _refresh_tools(self, timeout: float = 10.0) -> None:
        if not self._proc:
            return
        with self._lock:
            req_id = next(self._req_id_gen)
            try:
                _send(self._proc, "tools/list", {}, req_id)
                resp = _read_response(self._proc, req_id, timeout=timeout)
            except Exception:  # noqa: BLE001
                return
            if resp and "result" in resp:
                self._tools = resp["result"].get("tools", [])

    def list_tools(self) -> List[Dict[str, Any]]:
        return list(self._tools)

    def call_tool(
        self,
        tool_name: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: float = 30.0,
    ) -> Any:
        """Call a tool on this server.  Returns the parsed result or raises."""
        if not self.connected:
            raise RuntimeError(f"MCP server '{self.name}' is not connected.")

        # Pre-validate arguments against the stored tool schema before hitting the wire.
        # This catches missing required params and type mismatches (e.g. int where bool
        # is expected) locally, producing a clear error rather than an opaque -32602.
        params = dict(params or {})
        for tool in self._tools:
            if tool.get("name") == tool_name:
                schema = tool.get("inputSchema", {})
                required = list(schema.get("required", []))
                props = schema.get("properties", {})

                # Common alias map — models routinely use synonyms.
                # Apply BEFORE missing/required check so aliased keys count as present.
                _ALIASES = {
                    "address": ("addr", "function_address", "func_addr", "offset", "ea"),
                    "name": ("function_name", "func_name", "symbol", "tool_name"),
                    "file_path": ("path", "file", "filepath", "filename"),
                    "program": ("binary", "module", "prog"),
                    "count": ("limit", "n", "max"),
                }
                for canonical, aliases in _ALIASES.items():
                    if canonical in props and canonical not in params:
                        for a in aliases:
                            if a in params:
                                params[canonical] = params.pop(a)
                                break

                # Coerce types per schema BEFORE missing-required so well-formed
                # but mistyped params don't trigger spurious "missing" errors.
                for pname, pschema in props.items():
                    if pname not in params:
                        continue
                    val = params[pname]
                    decl = pschema.get("type")
                    if decl == "boolean":
                        if isinstance(val, bool):
                            pass
                        elif isinstance(val, int):
                            params[pname] = bool(val)
                        elif isinstance(val, str):
                            v = val.strip().lower()
                            if v in ("true", "1", "yes", "y"):
                                params[pname] = True
                            elif v in ("false", "0", "no", "n", ""):
                                params[pname] = False
                    elif decl == "integer":
                        if isinstance(val, str):
                            try:
                                params[pname] = int(val, 0) if val.strip() else 0
                            except ValueError:
                                pass
                        elif isinstance(val, bool):
                            params[pname] = int(val)
                    elif decl == "number":
                        if isinstance(val, str):
                            try:
                                params[pname] = float(val)
                            except ValueError:
                                pass
                    elif decl == "string":
                        if isinstance(val, (int, float)) and not isinstance(val, bool):
                            # r2/ghidra address fields sometimes typed as string
                            # but the model passes 0x401000 as int. Stringify.
                            if pname.lower() in ("address", "addr", "offset", "ea"):
                                params[pname] = hex(int(val)) if isinstance(val, int) else str(val)
                            else:
                                params[pname] = str(val)

                missing = [r for r in required if r not in params]
                if missing:
                    sig = ", ".join(
                        f"{k}: {v.get('type', 'any')}" for k, v in props.items()
                    )
                    desc_lines = (tool.get("description") or "").splitlines()
                    desc = desc_lines[0][:120] if desc_lines else ""
                    raise ValueError(
                        f"Missing required parameter(s) {missing} for '{tool_name}'. "
                        f"Signature: {tool_name}({sig})."
                        + (f" Hint: {desc}." if desc else "")
                    )
                break

        assert self._proc is not None

        with self._lock:
            req_id = next(self._req_id_gen)
            _send(self._proc, "tools/call", {
                "name": tool_name,
                "arguments": params,
            }, req_id)
            resp = _read_response(self._proc, req_id, timeout=timeout)

        if resp is None:
            raise TimeoutError(f"No response from MCP server '{self.name}' within {timeout}s.")

        if "error" in resp:
            err = resp["error"]
            raise RuntimeError(f"MCP error {err.get('code', '?')}: {err.get('message', str(err))}")

        result = resp.get("result", {})
        # Unwrap content array if present (MCP spec)
        content = result.get("content")
        if isinstance(content, list):
            parts: list[str] = []
            for item in content:
                if isinstance(item, dict):
                    if item.get("type") == "text":
                        parts.append(item.get("text", ""))
                    else:
                        parts.append(json.dumps(item))
                else:
                    parts.append(str(item))
            return "\n".join(parts)
        return result


# ─────────────────────────────────────────────────────────────────────────────
# MCPManager
# ─────────────────────────────────────────────────────────────────────────────

class MCPManager:
    """Manages a collection of named MCP servers loaded from dsec config."""

    def __init__(self) -> None:
        self._servers: Dict[str, MCPServer] = {}
        self._defs: Dict[str, Dict[str, Any]] = {}
        self._reload_defs()

    # ── config ────────────────────────────────────────────────────────────────

    def _reload_defs(self) -> None:
        try:
            raw = json.loads(CONFIG_PATH.read_text())
            self._defs = raw.get("mcp_servers", {})
        except Exception:  # noqa: BLE001
            self._defs = {}

    def reload(self) -> None:
        self._reload_defs()

    # ── connection management ─────────────────────────────────────────────────

    def connect(self, name: str) -> bool:
        """Connect to a named server.  Returns True on success."""
        if name not in self._defs:
            return False

        if name in self._servers and self._servers[name].connected:
            return True

        # Clean up old dead server before creating a new one
        old = self._servers.pop(name, None)
        if old:
            old.disconnect()

        defn = self._defs[name]
        srv = MCPServer(
            name=name,
            command=defn["command"],
            args=defn.get("args", []),
            env=defn.get("env", {}),
        )
        ok = srv.connect()
        if ok:
            self._servers[name] = srv
        return ok

    def disconnect(self, name: str) -> bool:
        srv = self._servers.get(name)
        if not srv:
            return False
        srv.disconnect()
        del self._servers[name]
        return True

    def disconnect_all(self) -> None:
        for name in list(self._servers):
            self.disconnect(name)

    # ── inspection ────────────────────────────────────────────────────────────

    def list_servers(self) -> List[Dict[str, Any]]:
        rows = []
        for name, defn in self._defs.items():
            srv = self._servers.get(name)
            rows.append({
                "name": name,
                "command": defn.get("command", "?"),
                "connected": bool(srv and srv.connected),
                "tools": len(srv.list_tools()) if (srv and srv.connected) else 0,
            })
        return rows

    def list_tools(self, server_name: Optional[str] = None) -> List[Dict[str, Any]]:
        results: list[Dict[str, Any]] = []
        targets: Iterator[str]
        if server_name:
            targets = iter([server_name])
        else:
            targets = iter(self._servers.keys())

        for name in targets:
            srv = self._servers.get(name)
            if srv and srv.connected:
                for tool in srv.list_tools():
                    results.append({"server": name, **tool})
        return results

    # ── tool invocation ───────────────────────────────────────────────────────

    def call_tool(
        self,
        server_name: str,
        tool_name: str,
        params: Optional[Dict[str, Any]] = None,
        timeout: float = 30.0,
    ) -> Any:
        """Call a tool on a connected server."""
        srv = self._servers.get(server_name)
        if not srv or not srv.connected:
            raise RuntimeError(
                f"Server '{server_name}' is not connected. "
                "Use: /mcp connect <server>"
            )
        return srv.call_tool(tool_name, params, timeout=timeout)

    # ── add server def at runtime ─────────────────────────────────────────────

    def add_server_def(self, name: str, command: str, args: Optional[List[str]] = None, env: Optional[Dict[str, str]] = None) -> None:
        """Persist a new server definition to ~/.dsec/config.json."""
        try:
            raw = json.loads(CONFIG_PATH.read_text())
        except Exception:  # noqa: BLE001
            raw = {}
        raw.setdefault("mcp_servers", {})[name] = {
            "command": command,
            "args": args or [],
            "env": env or {},
        }
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        CONFIG_PATH.write_text(json.dumps(raw, indent=2))
        self._defs[name] = raw["mcp_servers"][name]


# ─────────────────────────────────────────────────────────────────────────────
# Zenoh Pub/Sub Bridge for Remote MCP Tools
# ─────────────────────────────────────────────────────────────────────────────

class ZenohMCPBridge:
    """
    Wraps MCP tool calls over Zenoh pub/sub for remote tool access.

    When enabled, tool calls are published to a Zenoh topic and responses
    are received via subscription.  This allows connecting to MCP tools
    running on remote machines across the network.

    Requires: pip install eclipse-zenoh

    Config (in ~/.dsec/config.json):
        "zenoh": {
            "enabled": true,
            "connect": ["tcp/192.168.1.100:7447"],
            "prefix": "dsec/mcp"
        }
    """

    def __init__(self, connect: Optional[list] = None, prefix: str = "dsec/mcp") -> None:
        self._session = None
        self._connect = connect or []
        self._prefix = prefix
        self._available = False

        try:
            import zenoh  # type: ignore
            self._zenoh = zenoh
            self._available = True
        except ImportError:
            self._zenoh = None

    @property
    def available(self) -> bool:
        return self._available

    def open(self) -> bool:
        """Open a Zenoh session."""
        if not self._available:
            return False
        if self._session is not None:
            return True
        try:
            config = self._zenoh.Config()
            if self._connect:
                config.insert_json5("connect/endpoints", json.dumps(self._connect))
            self._session = self._zenoh.open(config)
            return True
        except Exception:
            return False

    def close(self) -> None:
        if self._session:
            try:
                self._session.close()
            except Exception:
                pass
            self._session = None

    def publish_tool_call(self, server: str, tool: str, params: Dict[str, Any]) -> Optional[Any]:
        """
        Publish a tool call request and wait for the response.
        Uses Zenoh's get() (query/reply) pattern for RPC-style calls.
        """
        if not self._session:
            if not self.open():
                return None
        if not self._session:
            return None

        topic = f"{self._prefix}/{server}/{tool}"
        payload = json.dumps({"params": params})

        try:
            replies = self._session.get(
                topic,
                payload=payload.encode(),
                timeout=30.0,
            )
            for reply in replies:
                if reply.ok:
                    return json.loads(reply.ok.payload.to_string())
            return None
        except Exception:
            return None

    def list_remote_tools(self) -> List[Dict[str, str]]:
        """Discover remote tools by querying the Zenoh key space."""
        if not self._session:
            if not self.open():
                return []
        if not self._session:
            return []

        try:
            replies = self._session.get(
                f"{self._prefix}/*/list_tools",
                timeout=5.0,
            )
            tools = []
            for reply in replies:
                if reply.ok:
                    data = json.loads(reply.ok.payload.to_string())
                    if isinstance(data, list):
                        tools.extend(data)
            return tools
        except Exception:
            return []


_zenoh_bridge: Optional[ZenohMCPBridge] = None


def get_zenoh_bridge() -> Optional[ZenohMCPBridge]:
    """Return the Zenoh bridge singleton, initializing from config if needed."""
    global _zenoh_bridge
    if _zenoh_bridge is not None:
        return _zenoh_bridge

    try:
        raw = json.loads(CONFIG_PATH.read_text())
    except Exception:
        return None

    if not isinstance(raw, dict):
        return None

    zenoh_cfg_raw = raw.get("zenoh", {})
    if not isinstance(zenoh_cfg_raw, dict):
        return None
    zenoh_cfg: Dict[str, Any] = zenoh_cfg_raw

    if not zenoh_cfg.get("enabled", False):
        return None

    _zenoh_bridge = ZenohMCPBridge(
        connect=zenoh_cfg.get("connect", []),
        prefix=zenoh_cfg.get("prefix", "dsec/mcp"),
    )
    return _zenoh_bridge


# ─────────────────────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────────────────────

_manager: Optional[MCPManager] = None


def get_mcp_manager() -> MCPManager:
    global _manager
    if _manager is None:
        _manager = MCPManager()
    return _manager
