"""Minimal MCP client for Streamable HTTP (JSON or SSE responses) with a bearer token.

The UniFi MCP server restarts when it's rebuilt each week, which drops its sessions: a call
that's refused for an unknown session starts a new one and is tried once more.
"""

from __future__ import annotations

import itertools
import json
from typing import Any

import requests

PROTOCOL_VERSION = "2025-06-18"
CLIENT_INFO = {"name": "unifi-health-agent", "version": "1.0"}


class MCPError(RuntimeError):
    pass


class ToolError(MCPError):
    """The tool ran but reported an error (isError=true)."""


class SessionLost(MCPError):
    pass


class MCPClient:
    def __init__(self, url: str, token: str, timeout: float = 60.0, session: requests.Session | None = None):
        self.url, self.timeout = url, timeout
        self.http = session or requests.Session()
        self.http.headers.update({"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
                                  "Authorization": f"Bearer {token}"})
        self._ids = itertools.count(1)
        self._initialized = False

    def _post(self, body: dict) -> dict | None:
        resp = self.http.post(self.url, json=body, timeout=self.timeout)
        if resp.status_code == 401:
            raise MCPError("unauthorized (check UNIFI_MCP_TOKEN)")
        if resp.status_code in (400, 404) and "session" in resp.text.lower():
            raise SessionLost(resp.text[:200])
        if resp.status_code >= 400:
            raise MCPError(f"HTTP {resp.status_code}: {resp.text[:200]}")
        if "mcp-session-id" in resp.headers:
            self.http.headers["mcp-session-id"] = resp.headers["mcp-session-id"]
        if not resp.content:
            return None
        if "text/event-stream" in resp.headers.get("content-type", ""):
            for line in resp.text.splitlines():  # the response with our id; skip interleaved notifications
                if line.startswith("data:") and line[5:].strip():
                    msg = json.loads(line[5:])
                    if msg.get("id") == body.get("id"):
                        return msg
            return None
        return resp.json()

    def _request(self, method: str, params: dict | None = None) -> Any:
        msg = self._post({"jsonrpc": "2.0", "id": next(self._ids), "method": method, "params": params or {}})
        if msg is None:
            raise MCPError(f"{method}: empty response")
        if "error" in msg:
            raise MCPError(f"{method}: {msg['error'].get('message', msg['error'])}")
        return msg.get("result")

    def _initialize(self) -> None:
        self.http.headers.pop("mcp-session-id", None)
        result = self._request("initialize", {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                                              "clientInfo": CLIENT_INFO})
        self.http.headers["MCP-Protocol-Version"] = result.get("protocolVersion", PROTOCOL_VERSION)
        self._post({"jsonrpc": "2.0", "method": "notifications/initialized"})
        self._initialized = True

    def call_tool(self, name: str, arguments: dict | None = None) -> Any:
        """Call a tool; returns its JSON result (or text). An empty result is None."""
        for attempt in (1, 2):
            if not self._initialized:
                self._initialize()
            try:
                result = self._request("tools/call", {"name": name, "arguments": arguments or {}})
                break
            except SessionLost:
                self._initialized = False
                if attempt == 2:
                    raise
        text = "".join(c.get("text", "") for c in result.get("content", []) if c.get("type") == "text")
        try:
            data: Any = json.loads(text) if text.strip() else None
        except ValueError:
            data = text
        if data is None and isinstance(result.get("structuredContent"), dict):
            data = result["structuredContent"].get("result")  # FastMCP wraps non-object results
        if result.get("isError"):
            raise ToolError(f"{name}: {data if isinstance(data, str) else json.dumps(data)[:300]}")
        return data
