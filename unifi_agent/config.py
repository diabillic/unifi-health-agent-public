"""Environment-driven configuration."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

DAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")

# What counts as an error in UniFi's event log: these severities, or an event name like this, outside
# the categories that are only chatter (clients roaming, connecting and disconnecting).
ALERT_SEVERITIES = "HIGH,VERY_HIGH,CRITICAL"
ALERT_EVENTS = r"LOST|DOWN|FAIL|ERROR|OFFLINE|DISCONNECTED|ISOLATED|RESTART|REBOOT|FAILOVER|THREAT|INTRUSION|IPS_|OVERHEAT|POE_OVERLOAD"
IGNORE_CATEGORIES = "CLIENT_DEVICES"
ISOLATE_NETWORKS = r"iot|camera|guest|lab"  # networks that should have no way into the main LAN


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    try:
        return int(raw) if raw else default
    except ValueError:
        raise SystemExit(f"{name} must be a whole number, got {raw!r}") from None


def _list(name: str, default: str = "") -> list[str]:
    raw = os.environ.get(name, default)
    return [p.strip() for p in raw.replace("\n", ",").split(",") if p.strip()]


def _time(name: str, default: str) -> str:
    raw = os.environ.get(name, "").strip() or default
    if not re.fullmatch(r"([01]\d|2[0-3]):[0-5]\d", raw):
        raise SystemExit(f"{name} must be HH:MM (24h), got {raw!r}")
    return raw


def _regex(name: str, default: str) -> re.Pattern:
    raw = os.environ.get(name, "").strip() or default
    try:
        return re.compile(raw, re.I)
    except re.error as exc:
        raise SystemExit(f"{name} is not a valid regex: {exc}") from None


@dataclass
class Config:
    # The UniFi MCP server (Streamable HTTP) and this agent's own bearer token on it
    mcp_url: str
    mcp_token: str
    site_id: str = "default"

    poll_minutes: int = 5
    device_grace_minutes: int = 10  # a device must be offline this long before it's reported
    alert_severities: list[str] = field(default_factory=lambda: ALERT_SEVERITIES.split(","))
    alert_events: re.Pattern = field(default_factory=lambda: re.compile(ALERT_EVENTS, re.I))
    ignore_categories: list[str] = field(default_factory=lambda: IGNORE_CATEGORIES.split(","))

    # Weekly recommendations digest (local time in `timezone`)
    timezone: str = "UTC"
    digest_day: str = "sun"
    digest_time: str = "09:00"
    isolate_networks: re.Pattern = field(default_factory=lambda: re.compile(ISOLATE_NETWORKS, re.I))
    backup_max_days: int = 7  # recommend more frequent automatic backups than this
    advice_ignore: list[str] = field(default_factory=list)  # rule ids, or rule:target, accepted as they are

    # AI write-up of the recommendations via OpenCode Go (off without a key)
    opencode_api_key: str = ""
    opencode_model: str = "glm-5.2"
    opencode_base_url: str = "https://opencode.ai/inference/go/openai/v1"
    network_notes: str = ""  # free text about this network, added to the write-up prompt

    state_path: str = "/var/lib/unifi-agent/state.json"
    notify_urls: list[str] = field(default_factory=list)
    renotify_hours: int = 24

    # Agent bus: MCP endpoint for an assistant (Hermes), and where to hand it alerts
    bus_token: str = ""
    bus_port: int = 8765
    bot_alert_url: str = ""

    @property
    def writeup_enabled(self) -> bool:
        return bool(self.opencode_api_key)

    @classmethod
    def from_env(cls) -> "Config":
        url, token = os.environ.get("UNIFI_MCP_URL", "").strip(), os.environ.get("UNIFI_MCP_TOKEN", "").strip()
        if not url or not token:
            raise SystemExit("UNIFI_MCP_URL and UNIFI_MCP_TOKEN are required")
        day = (os.environ.get("DIGEST_DAY") or "sun").strip().lower()[:3]
        if day not in DAYS:
            raise SystemExit(f"DIGEST_DAY must be a weekday name, got {day!r}")
        return cls(
            mcp_url=url,
            mcp_token=token,
            site_id=os.environ.get("UNIFI_SITE", "").strip() or "default",
            poll_minutes=max(1, _int("POLL_MINUTES", 5)),
            device_grace_minutes=max(0, _int("DEVICE_GRACE_MINUTES", 10)),
            alert_severities=[s.upper() for s in _list("ALERT_SEVERITIES", ALERT_SEVERITIES)],
            alert_events=_regex("ALERT_EVENTS", ALERT_EVENTS),
            ignore_categories=[s.upper() for s in _list("IGNORE_CATEGORIES", IGNORE_CATEGORIES)],
            timezone=os.environ.get("TIMEZONE", "").strip() or "UTC",
            digest_day=day,
            digest_time=_time("DIGEST_TIME", "09:00"),
            isolate_networks=_regex("ISOLATE_NETWORKS", ISOLATE_NETWORKS),
            backup_max_days=max(1, _int("BACKUP_MAX_DAYS", 7)),
            advice_ignore=_list("ADVICE_IGNORE"),
            opencode_api_key=os.environ.get("OPENCODE_API_KEY", "").strip(),
            opencode_model=os.environ.get("OPENCODE_MODEL", "").strip() or "glm-5.2",
            opencode_base_url=os.environ.get("OPENCODE_BASE_URL", "").strip() or "https://opencode.ai/inference/go/openai/v1",
            network_notes=os.environ.get("NETWORK_NOTES", "").strip(),
            state_path=os.environ.get("STATE_PATH", "").strip() or "/var/lib/unifi-agent/state.json",
            notify_urls=_list("NOTIFY_URLS"),
            renotify_hours=_int("RENOTIFY_HOURS", 24),
            bus_token=os.environ.get("AGENT_BUS_TOKEN", "").strip(),
            bus_port=_int("AGENT_BUS_PORT", 8765),
            bot_alert_url=os.environ.get("BOT_ALERT_URL", "").strip(),
        )
