"""Notifications: Discord embeds, or any Apprise URL as markdown (see notice.py)."""

from __future__ import annotations

import logging
import time

from .advisor import AREAS, Advice
from .bus import push_alert
from .findings import Finding
from .notice import ICON, Message, Outbox, Section, digest
from .state import State

log = logging.getLogger(__name__)

AUTHOR = "UniFi agent"
FOREVER_HOURS = 24 * 365 * 10
PRIORITY_ICON = {"high": "🔴", "medium": "🟠", "low": "⚪"}


class Notifier:
    def __init__(self, urls: list[str], renotify_hours: int, state: State, bot_url: str = "", bot_token: str = ""):
        self.renotify_hours = renotify_hours
        self.state = state
        self.bot_url, self.bot_token = bot_url, bot_token  # assistant first, Apprise as fallback
        self.outbox = Outbox(urls)
        # From an alert that wasn't delivered: one-off events, which no later check finds again.
        # Open issues (alarms, offline devices) come back by themselves.
        self.unsent: list[Finding] = []

    def _deliver(self, msg: Message, findings: list[Finding]) -> bool:
        body = msg.markdown()
        log.info("%s\n%s", msg.title, body)
        return bool(self.bot_url and push_alert(self.bot_url, self.bot_token, "unifi", msg.title, body, findings,
                                                None)) or self.outbox.send(msg)

    def send(self, findings: list[Finding], complete: bool = True, unchecked: tuple[str, ...] = ()) -> None:
        """One alert per check: new issues, reminders every renotify_hours, and issues that cleared.

        complete=False (the server couldn't be read) suppresses "cleared": a missing finding then
        means "not checked", not "fixed". unchecked does the same for keys with these prefixes.
        Nothing counts as sent until it's delivered.
        """
        keys = {f.key for f in findings}
        findings = findings + [f for f in self.unsent if f.key not in keys]
        notified = self.state["notified"]
        now = time.time()
        current = {f.key for f in findings} if complete else set(notified) | {f.key for f in findings}
        current |= {k for k in notified if k.startswith(tuple(unchecked))}

        due = []
        for f in findings:
            prev = notified.get(f.key)
            hours = FOREVER_HOURS if f.once else self.renotify_hours
            if prev is None or now - prev["ts"] >= hours * 3600:
                due.append(f)
        gone = [k for k in notified if k not in current]
        cleared = [notified[k]["summary"] for k in gone
                   if not notified[k].get("once") and notified[k].get("severity") in ("warning", "error")]

        if (due or cleared) and not self._deliver(digest(AUTHOR, due, cleared), due):
            self.unsent = [f for f in due if f.once]
            return  # the cleared items stay recorded, so they're reported cleared again next check
        self.unsent = []
        for k in gone:
            del notified[k]
        for f in due:
            notified[f.key] = {"ts": now, "summary": f.summary, "severity": f.severity, "once": f.once}

    def weekly(self, advice: list[Advice], writeup: str | None, failed: list[str] = ()) -> bool:
        """The weekly recommendations digest: new ones marked, fixed ones listed. False if not delivered,
        and then nothing is recorded, so the next attempt reports the same changes."""
        seen = self.state["advice"]  # key -> summary, from the last delivered digest
        current = {a.key: a.summary for a in advice}
        fixed = [s for k, s in seen.items() if k not in current]
        sections = []
        if writeup:
            sections.append(Section("🧠 What to do first", [writeup], bullets=False))
        for area in AREAS:
            lines = [f"{PRIORITY_ICON[a.priority]} {'**New:** ' if a.key not in seen else ''}{a.summary}\n   ↳ {a.fix}"
                     for a in advice if a.area == area]
            if lines:
                sections.append(Section(area, lines, bullets=False))
        if fixed:
            sections.append(Section("✅ Fixed since last week", fixed))
        if failed:
            sections.append(Section("⚠️ Not checked this week", [f"Couldn't read the {', '.join(failed)} settings."]))
        new = sum(1 for a in advice if a.key not in seen)
        title = (f"{ICON['info']} {len(advice)} recommendation{'s' if len(advice) != 1 else ''}"
                 + (f" ({new} new)" if new else "") if advice else f"{ICON['ok']} Nothing to recommend this week")
        msg = Message(title, "info" if advice else "ok", sections or [Section("", ["Everything checked follows best practice."],
                                                                              bullets=False)], AUTHOR,
                      "🔴 high · 🟠 medium · ⚪ low · ADVICE_IGNORE accepts an item as it is")
        if not self._deliver(msg, []):
            return False
        self.state.data["advice"] = current
        return True
