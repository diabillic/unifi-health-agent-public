"""The weekly digest's AI write-up: the rule findings explained and prioritised by an OpenCode Go model.

One Chat Completions call, no tools. The model only sees the findings and the facts each rule
looked at (names, settings, counts): no passphrases, keys or MAC addresses. A failure just leaves
the digest with the rules' own wording.
"""

from __future__ import annotations

import json
import logging
import uuid

import requests

from .advisor import Advice
from .config import Config

log = logging.getLogger(__name__)

USER_AGENT = "unifi-health-agent/1.0"
PROMPT = """You review a home UniFi network for its owner. A rule-based checker found the items below \
(priority, area, what it saw, the suggested fix). Write the weekly recommendations note.

Keep it under 250 words of plain text for a Discord message: start with the one or two changes that \
matter most and why, then a short numbered list of the rest with the exact UniFi page to change. Merge \
items that share a fix. Don't invent problems that aren't in the list, and say so when an item is a \
judgement call (e.g. IoT devices that can't use WPA3). No preamble."""


def write_up(cfg: Config, advice: list[Advice], session: requests.Session | None = None) -> str | None:
    if not cfg.writeup_enabled or not advice:
        return None
    items = [{"priority": a.priority, "area": a.area, "finding": a.summary, "fix": a.fix, "facts": a.facts} for a in advice]
    system = PROMPT + (f"\n\nAbout this network, from its owner: {cfg.network_notes}" if cfg.network_notes else "")
    # Reasoning models spend 2000+ tokens thinking before they write; too low a cap leaves no text
    body = {"model": cfg.opencode_model, "max_tokens": 8192, "messages": [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(items, default=str)}]}
    http = session or requests.Session()
    try:
        resp = http.post(cfg.opencode_base_url.rstrip("/") + "/chat/completions", json=body, timeout=180, headers={
            "Authorization": f"Bearer {cfg.opencode_api_key}", "User-Agent": USER_AGENT,
            "x-opencode-session": str(uuid.uuid4())})  # OpenCode Go wants one id per conversation
        resp.raise_for_status()
        choice = resp.json()["choices"][0]
        text = (choice["message"].get("content") or "").strip()
    except (requests.RequestException, KeyError, IndexError, ValueError) as exc:
        log.error("AI write-up via OpenCode Go failed: %s", exc)
        return None
    if not text:
        log.error("AI write-up via OpenCode Go was empty (finish_reason %s)", choice.get("finish_reason"))
    return text or None
