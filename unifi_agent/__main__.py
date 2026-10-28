"""Entry point: python -m unifi_agent [--once] [--digest]"""

from __future__ import annotations

import argparse
import logging
import os
from datetime import datetime
from zoneinfo import ZoneInfo

from . import health
from .advisor import Advisor
from .bus import Approvals, BusTool, Runtime, schema, serve_mcp
from .checks import Monitor
from .config import DAYS, Config
from .mcp import MCPClient
from .notify import Notifier
from .state import State
from .writeup import write_up

log = logging.getLogger("unifi_agent")

CYCLE_GRACE = 15 * 60  # longest a cycle (checks, plus the weekly digest and its write-up) should take


def digest_due(cfg: Config, last: dict, now: datetime) -> bool:
    """The weekly digest is due from DIGEST_DAY at DIGEST_TIME (local) until it's been delivered that day."""
    return (DAYS[now.weekday()] == cfg.digest_day and now.strftime("%H:%M") >= cfg.digest_time
            and last.get("digest") != now.date().isoformat())


def bus_tools(runtime: Runtime, monitor: Monitor, advisor: Advisor, state: State, cfg: Config) -> list[BusTool]:
    """What the assistant may call: all read-only."""

    def status() -> dict:
        return {"devices": [{k: d.get(k) for k in ("name", "model", "state", "firmware_version", "firmware_updatable")}
                            for d in monitor.devices],
                "open_alerts": [v["summary"] for v in state["notified"].values() if not v.get("once")],
                "last_check": monitor.last_check_at,
                "weekly_digest": f"{cfg.digest_day.title()} {cfg.digest_time} ({cfg.timezone}), last sent "
                                 f"{state['schedule'].get('digest') or 'never'}"}

    def recommendations() -> dict:
        advice, failed = advisor.run()
        return {"recommendations": [{"priority": a.priority, "area": a.area, "finding": a.summary, "fix": a.fix,
                                     "id": a.key} for a in advice],
                "not_checked": failed, "ignored": cfg.advice_ignore}

    return runtime.common_tools(check_is_destructive=False) + [
        BusTool("unifi_status", "UniFi: every device with its state and firmware, the alerts that are open now, and "
                "when the weekly recommendations digest runs.", schema(), status),
        BusTool("unifi_recommendations", "UniFi: run the best-practice checks now (WiFi security, firewall policy "
                "order, network isolation, firmware, backups, port forwards) and list what to change, highest "
                "priority first. id is what ADVICE_IGNORE takes to accept an item.", schema(), recommendations),
    ]


def send_digest(advisor: Advisor, notifier: Notifier, cfg: Config, writeups: dict) -> bool:
    """writeups caches the AI write-up per set of recommendations, so a retry doesn't ask again."""
    advice, failed = advisor.run()
    keys = tuple(a.key for a in advice)
    if keys not in writeups:
        writeups.clear()
        writeups[keys] = write_up(cfg, advice)
    return notifier.weekly(advice, writeups[keys], failed)


def main() -> None:
    parser = argparse.ArgumentParser(description="UniFi health agent")
    parser.add_argument("--once", action="store_true", help="run one check and exit")
    parser.add_argument("--digest", action="store_true", help="send the recommendations digest now and exit")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    cfg = Config.from_env()
    try:
        tz = ZoneInfo(cfg.timezone)
    except Exception:
        raise SystemExit(f"Unknown TIMEZONE {cfg.timezone!r}")
    state = State(cfg.state_path)
    mcp = MCPClient(cfg.mcp_url, cfg.mcp_token)
    monitor, advisor = Monitor(mcp, cfg, state), Advisor(mcp, cfg)
    notifier = Notifier(cfg.notify_urls, cfg.renotify_hours, state, cfg.bot_alert_url, cfg.bus_token)
    runtime = Runtime("unifi", revision=_revision())
    writeups: dict = {}
    if args.digest:
        delivered = send_digest(advisor, notifier, cfg, writeups)
        state.save()
        raise SystemExit(0 if delivered else 1)
    health.reset()
    if cfg.bus_token and cfg.bus_port and not args.once:
        # No destructive tools, so no approval channel is needed.
        serve_mcp("0.0.0.0", cfg.bus_port, cfg.bus_token, bus_tools(runtime, monitor, advisor, state, cfg),
                  "unifi-agent", Approvals("unifi", [], mode="client"))
        health.endpoint("agent bus", f"http://127.0.0.1:{cfg.bus_port}/health")
    log.info("Starting: server=%s site=%s poll=%smin grace=%smin digest=%s %s %s writeup=%s bus=%s",
             cfg.mcp_url, cfg.site_id, cfg.poll_minutes, cfg.device_grace_minutes, cfg.digest_day, cfg.digest_time,
             cfg.timezone, cfg.writeup_enabled, bool(cfg.bus_token))

    while True:
        health.beat("checks", cfg.poll_minutes * 60 + CYCLE_GRACE)
        try:
            findings, complete, unchecked = monitor.run()
            notifier.send(findings, complete, unchecked)
            runtime.record(findings, None)
            now = datetime.now(tz)
            if digest_due(cfg, state["schedule"], now) and send_digest(advisor, notifier, cfg, writeups):
                state["schedule"]["digest"] = now.date().isoformat()  # undelivered: tried again next check
            state.save()
        except Exception:  # keep the daemon alive; next cycle may succeed
            log.exception("Cycle crashed")
        if args.once:
            return
        if runtime.wake.wait(cfg.poll_minutes * 60):
            log.info("Check requested via the agent bus")
        runtime.wake.clear()


def _revision() -> str:
    try:
        with open(os.path.join(os.path.dirname(__file__), "..", "REVISION"), encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return "dev"


if __name__ == "__main__":
    main()
