"""Errors that alert right away: active UniFi alarms, devices offline, and error events in the log.

UniFi has no syslog over its API; its event log (list_events) is the log. Most of it is chatter
(clients roaming, firewall blocks), so an event counts as an error when its severity is one of
ALERT_SEVERITIES, or its name matches ALERT_EVENTS outside IGNORE_CATEGORIES. The first run only
records the events already there, so a backlog isn't replayed.
"""

from __future__ import annotations

import logging
import math
import re
import time
from collections import Counter

import requests

from .config import Config
from .findings import Finding
from .mcp import MCPClient, MCPError, ToolError
from .state import State

log = logging.getLogger(__name__)

EVENT_WINDOW_HOURS = 1  # list_events takes whole hours; seen ids make the overlap harmless
SEEN_DAYS = 7


def as_list(data) -> list[dict]:
    """A tool's list result: an empty answer ("" or null) is an empty list."""
    if isinstance(data, list):
        return [d for d in data if isinstance(d, dict)]
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list):
                return [d for d in v if isinstance(d, dict)]
    return []


def render(event: dict) -> str:
    """An event's message with its {PLACEHOLDERS} filled from its parameters."""
    params = event.get("parameters") or {}

    def name(m: re.Match) -> str:
        p = params.get(m.group(1))
        return str((p or {}).get("name") or (p or {}).get("id") or m.group(0)) if isinstance(p, dict) else str(p or m.group(0))

    text = event.get("message_raw") or event.get("title_raw") or event.get("event") or "event"
    return re.sub(r"\{([A-Z_]+)\}", name, str(text))


class Monitor:
    def __init__(self, mcp: MCPClient, cfg: Config, state: State, clock=time.time):
        self.mcp, self.cfg, self.state, self.clock = mcp, cfg, state, clock
        self.devices: list[dict] = []  # from the last check, for the agent bus
        self.last_check_at: float | None = None

    def is_error(self, e: dict) -> bool:
        if str(e.get("severity") or "").upper() in self.cfg.alert_severities:
            return True
        return (str(e.get("category") or "").upper() not in self.cfg.ignore_categories
                and bool(self.cfg.alert_events.search(str(e.get("event") or e.get("key") or ""))))

    def run(self) -> tuple[list[Finding], bool, tuple[str, ...]]:
        """(findings, complete, unchecked key prefixes). complete=False: the server couldn't be read."""
        now = self.clock()
        try:
            self.mcp.call_tool("health_check")
        except (MCPError, requests.RequestException) as exc:
            return self._server_down(now, exc), False, ()
        self.state["outage"].pop("mcp", None)

        findings, unchecked = [], []
        for prefix, check in (("alarm:", self.alarms), ("device:", self.device_states), ("event:", self.events)):
            try:
                findings += check(now)
            except (ToolError, MCPError, requests.RequestException) as exc:
                log.warning("%s check failed: %s", prefix.rstrip(":"), exc)
                unchecked.append(prefix)
                findings.append(Finding(f"check:{prefix.rstrip(':')}", f"Couldn't check UniFi {prefix.rstrip(':')}s: {exc}"))
        self.last_check_at = now
        return findings, True, tuple(unchecked)

    def _server_down(self, now: float, exc: Exception) -> list[Finding]:
        since = self.state["outage"].setdefault("mcp", now)
        minutes = (now - since) / 60
        if minutes < self.cfg.device_grace_minutes:
            log.warning("UniFi MCP server unreachable (%.0f min): %s", minutes, exc)
            return []
        return [Finding("mcp:down", f"The UniFi MCP server at {self.cfg.mcp_url} has been unreachable for "
                                    f"{minutes:.0f} min: {exc}", "error")]

    def alarms(self, now: float) -> list[Finding]:
        out = []
        for a in as_list(self.mcp.call_tool("list_alarms", {"site_id": self.cfg.site_id})):
            ident = str(a.get("_id") or a.get("id") or a.get("key") or a.get("msg"))
            text = a.get("msg") or a.get("message") or a.get("title") or a.get("key") or "alarm"
            out.append(Finding(f"alarm:{ident}", f"UniFi alarm: {text}", "error", details={"alarm": a}))
        return out

    def device_states(self, now: float) -> list[Finding]:
        self.devices = as_list(self.mcp.call_tool("search_devices", {"site_id": self.cfg.site_id, "query": ""}))
        down = self.state["offline"]  # device id -> when it was first seen not ONLINE
        out, present = [], set()
        for d in self.devices:
            ident = str(d.get("id") or d.get("mac_address"))
            present.add(ident)
            state = str(d.get("state") or "UNKNOWN").upper()
            if state == "ONLINE":
                down.pop(ident, None)
                continue
            since = down.setdefault(ident, now)
            minutes = (now - since) / 60
            if minutes < self.cfg.device_grace_minutes:  # restarts and firmware updates come back on their own
                continue
            out.append(Finding(f"device:{ident}:state",
                               f"{d.get('name') or ident} ({d.get('model') or 'device'}) is {state} "
                               f"(for {minutes:.0f} min or more).", "error", details={"device": d}))
        for gone in [k for k in down if k not in present]:
            del down[gone]
        return out

    def events(self, now: float) -> list[Finding]:
        hours = max(EVENT_WINDOW_HOURS, math.ceil(self.cfg.poll_minutes * 2 / 60))
        rows = as_list(self.mcp.call_tool("list_events", {"site_id": self.cfg.site_id, "hours": hours, "limit": 1000}))
        seen = self.state["seen_events"]
        for k in [k for k, ts in seen.items() if now - ts > SEEN_DAYS * 86400]:
            del seen[k]
        baseline = not self.state["outage"].get("events_baselined")
        new = [e for e in rows if str(e.get("id")) not in seen]
        for e in new:
            seen[str(e.get("id"))] = now
        if baseline:
            self.state["outage"]["events_baselined"] = now
            return []
        errors = [e for e in new if self.is_error(e)]
        out = []
        groups = Counter((str(e.get("event") or e.get("key")), render(e)) for e in errors)
        for (name, text), count in groups.items():
            sample = next(e for e in errors if render(e) == text)
            sev = str(sample.get("severity") or "").upper()
            out.append(Finding(f"event:{sample.get('id')}",
                               f"{text}" + (f" (×{count})" if count > 1 else "") + f" [{name}]",
                               "error" if sev in self.cfg.alert_severities else "warning", once=True,
                               details={"event": sample, "count": count}))
        return out
