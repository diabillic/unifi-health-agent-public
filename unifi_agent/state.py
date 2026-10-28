"""Small JSON state file so decisions survive restarts (what was notified, outages, seen events)."""

from __future__ import annotations

import json
import os
import tempfile
from typing import Any


class State:
    # notified: alert dedupe · outage: when the server went unreachable, event baseline · offline: devices
    # not ONLINE since · seen_events: event ids · advice: the last delivered digest · schedule: last digest date
    SECTIONS = ("notified", "outage", "offline", "seen_events", "advice", "schedule")

    def __init__(self, path: str):
        self.path = path
        self.data: dict[str, dict[str, Any]] = {s: {} for s in self.SECTIONS}
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as fh:
                    loaded = json.load(fh)
                for s in self.SECTIONS:
                    self.data[s] = loaded.get(s, {})
            except (OSError, ValueError):
                pass  # corrupt state just means everything looks new once

    def save(self) -> None:
        directory = os.path.dirname(self.path) or "."
        os.makedirs(directory, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".state-")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(self.data, fh, indent=1, sort_keys=True)
        os.replace(tmp, self.path)

    def __getitem__(self, section: str) -> dict[str, Any]:
        return self.data[section]
