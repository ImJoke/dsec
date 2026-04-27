import json
import uuid
import threading
from typing import Dict, Any, Optional

try:
    import zenoh
    ZENOH_AVAILABLE = True
except ImportError:
    ZENOH_AVAILABLE = False

class ZenohMCPTransport:
    """
    Experimental Zenoh transport for Model Context Protocol.
    Allows executing MCP tools on remote machines (e.g. headless VMs) via Zenoh topics.
    """
    def __init__(self, router_url: str = "tcp/localhost:7447", base_topic: str = "dsec/mcp"):
        self.router_url = router_url
        self.base_topic = base_topic
        self.session = None
        self._responses: Dict[str, Any] = {}
        self._cond = threading.Condition()
        self._subscriber = None

    def connect(self):
        if not ZENOH_AVAILABLE:
            raise ImportError("zenoh is not installed. Run `pip install eclipse-zenoh`.")
            
        conf = zenoh.Config()
        conf.insert_json5("connect/endpoints", f'["{self.router_url}"]')
        self.session = zenoh.open(conf)
        
        reply_topic = f"{self.base_topic}/reply"
        self._subscriber = self.session.declare_subscriber(reply_topic, self._on_reply)

    def _on_reply(self, sample):
        try:
            payload = json.loads(sample.payload.decode('utf-8'))
            msg_id = payload.get("id")
            if msg_id:
                with self._cond:
                    self._responses[msg_id] = payload
                    self._cond.notify_all()
        except Exception:
            pass

    def call_tool(self, server_name: str, tool_name: str, arguments: Dict[str, Any], timeout: float = 10.0) -> Any:
        if not self.session:
            self.connect()
            
        msg_id = str(uuid.uuid4())
        req = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "method": "call_tool",
            "params": {
                "server": server_name,
                "name": tool_name,
                "arguments": arguments
            }
        }
        
        topic = f"{self.base_topic}/request/{server_name}"
        self.session.put(topic, json.dumps(req))
        
        with self._cond:
            self._cond.wait_for(lambda: msg_id in self._responses, timeout=timeout)
            
        res = self._responses.pop(msg_id, None)
        if not res:
            raise TimeoutError(f"Zenoh MCP request timed out for {server_name}/{tool_name}")
            
        if "error" in res:
            raise Exception(res["error"])
            
        return res.get("result")

    def disconnect(self):
        if self._subscriber:
            self._subscriber.undeclare()
        if self.session:
            self.session.close()
