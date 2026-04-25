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

import json
import os
import subprocess
import threading
import time
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
    while time.monotonic() < deadline:
        line = proc.stdout.readline()
        if not line:
            time.sleep(0.05)
            continue
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
        self._req_id = 0
        self._lock = threading.Lock()

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

        # MCP initialise
        self._req_id += 1
        try:
            _send(self._proc, "initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "dsec", "version": "1.0"},
            }, self._req_id)
            resp = _read_response(self._proc, self._req_id, timeout=timeout)
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

        # Discover tools
        self._refresh_tools(timeout=timeout)
        return True

    def disconnect(self) -> None:
        if self._proc:
            try:
                self._proc.terminate()
                self._proc.wait(timeout=3)
            except Exception:  # noqa: BLE001
                pass
            finally:
                self._proc = None
        self._tools = []

    # ── tool management ───────────────────────────────────────────────────────

    def _refresh_tools(self, timeout: float = 10.0) -> None:
        if not self._proc:
            return
        self._req_id += 1
        try:
            _send(self._proc, "tools/list", {}, self._req_id)
            resp = _read_response(self._proc, self._req_id, timeout=timeout)
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

        assert self._proc is not None

        with self._lock:
            self._req_id += 1
            req_id = self._req_id
            _send(self._proc, "tools/call", {
                "name": tool_name,
                "arguments": params or {},
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
        CONFIG_PATH.write_text(json.dumps(raw, indent=2))
        self._defs[name] = raw["mcp_servers"][name]


# ─────────────────────────────────────────────────────────────────────────────
# Singleton
# ─────────────────────────────────────────────────────────────────────────────

_manager: Optional[MCPManager] = None


def get_mcp_manager() -> MCPManager:
    global _manager
    if _manager is None:
        _manager = MCPManager()
    return _manager
