"""Best-practice checks of the UniFi configuration, read through the MCP server.

Each rule yields Advice keyed rule:target, so a recommendation is tracked from week to week and
ADVICE_IGNORE can accept one (the whole rule, or one target) as it is. The rules only read.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

import requests

from .checks import as_list
from .config import Config
from .mcp import MCPClient, MCPError

log = logging.getLogger(__name__)

PRIORITY = {"high": 0, "medium": 1, "low": 2}
VPN = re.compile(r"wireguard|openvpn|\bvpn\b|ipsec", re.I)
AREAS = ("Firewall", "WiFi", "Networks", "Devices", "Gateway")


@dataclass
class Advice:
    rule: str
    target: str
    area: str  # one of AREAS
    priority: str  # high | medium | low
    summary: str
    fix: str
    facts: dict = field(default_factory=dict)  # what the rule saw, for the AI write-up

    @property
    def key(self) -> str:
        return f"{self.rule}:{self.target}"


def backup_interval_days(cron: str) -> int | None:
    """Rough interval of a cron schedule: monthly, weekly or daily (None when unreadable)."""
    parts = (cron or "").split()
    if len(parts) != 5:
        return None
    dom, _, dow = parts[2], parts[3], parts[4]
    if dom != "*":
        return 30
    return 7 if dow != "*" else 1


def is_catch_all(p: dict) -> bool:
    """A policy that matches all traffic between its zones (any protocol, address and port)."""
    if p.get("protocol") != "all" or (p.get("schedule") or {}).get("mode", "ALWAYS") != "ALWAYS":
        return False
    for side in ("source", "destination"):
        s = p.get(side) or {}
        if s.get("matching_target") not in (None, "ANY") or s.get("port_matching_type") not in (None, "ANY"):
            return False
    return True


class Advisor:
    def __init__(self, mcp: MCPClient, cfg: Config):
        self.mcp, self.cfg = mcp, cfg

    def _get(self, tool: str, **args):
        return self.mcp.call_tool(tool, {"site_id": self.cfg.site_id, **args})

    def run(self) -> tuple[list[Advice], list[str]]:
        """(advice, the checks that couldn't run), highest priority first, ignored ones left out."""
        out, failed = [], []
        for name, rule in (("firewall", self.firewall), ("wifi", self.wifi), ("networks", self.networks),
                           ("devices", self.devices), ("gateway", self.gateway)):
            try:
                out += rule()
            except (MCPError, requests.RequestException, KeyError, TypeError, ValueError) as exc:
                log.warning("advice check %s failed: %s", name, exc)
                failed.append(name)
        ignore = set(self.cfg.advice_ignore)
        out = [a for a in out if a.rule not in ignore and a.key not in ignore]
        return sorted(out, key=lambda a: (PRIORITY[a.priority], AREAS.index(a.area), a.key)), failed

    # --- rules ---

    def firewall(self) -> list[Advice]:
        policies = [p for p in as_list(self._get("list_firewall_policies")) if p.get("enabled")]
        out, by_pair = [], {}
        for p in sorted(policies, key=lambda p: p.get("index") or 0):
            pair = ((p.get("source") or {}).get("zone_id"), (p.get("destination") or {}).get("zone_id"))
            by_pair.setdefault(pair, []).append(p)
        for rules in by_pair.values():
            blocker = None
            for p in rules:
                if p.get("predefined"):
                    continue
                if blocker and p.get("action") == "ALLOW" and blocker.get("ip_version") in ("BOTH", p.get("ip_version")):
                    hits = p.get("hits")
                    out.append(Advice(
                        "firewall.shadowed", p["name"], "Firewall", "high",
                        f"Firewall policy \"{p['name']}\" can never match: \"{blocker['name']}\" blocks all traffic "
                        f"between the same zones and comes first" + (" (it has never been hit)." if not hits else "."),
                        f"In Settings > Policy Engine > Zones, move \"{p['name']}\" above \"{blocker['name']}\" "
                        "(policies apply in order and the first match wins), or delete it if it's no longer needed.",
                        {"policy": p["name"], "index": p.get("index"), "hits": hits, "blocked_by": blocker["name"],
                         "blocker_index": blocker.get("index")}))
                elif not blocker and p.get("action") in ("BLOCK", "REJECT") and is_catch_all(p):
                    blocker = p
        return out

    def wifi(self) -> list[Advice]:
        out = []
        aps = sum(1 for d in as_list(self._get("search_devices", query="")) if "accessPoint" in (d.get("features") or []))
        for w in as_list(self._get("list_wlans")):
            if not w.get("enabled"):
                continue
            name, bands = w.get("name", "?"), set(w.get("wlan_bands") or [w.get("wlan_band")])
            iot = "iot" in name.lower()
            facts = {k: w.get(k) for k in ("security", "wpa_mode", "wpa3_support", "wpa3_transition", "pmf_mode",
                                          "wlan_bands", "is_guest", "l2_isolation", "hide_ssid", "bss_transition",
                                          "fast_roaming_enabled", "minrate_ng_enabled", "minrate_ng_data_rate_kbps")}
            if w.get("security") == "wpapsk" and not w.get("wpa3_support"):
                out.append(Advice(
                    "wifi.wpa3", name, "WiFi", "low" if iot else "medium",
                    f"SSID \"{name}\" uses WPA2 only." + (" Many IoT devices can't join WPA3, so check yours first." if iot else ""),
                    f"Settings > WiFi > {name} > Security Protocol: WPA2/WPA3 (transition mode keeps WPA2 clients "
                    "working while newer ones use WPA3).", facts))
            if w.get("pmf_mode") == "disabled":
                out.append(Advice(
                    "wifi.pmf", name, "WiFi", "low" if iot else "medium",
                    f"SSID \"{name}\" has Protected Management Frames off, so clients can be knocked off with forged "
                    "deauthentication frames.",
                    f"Settings > WiFi > {name} > PMF: Optional (required by WPA3; Required once every client supports it).",
                    facts))
            guestish = "guest" in name.lower()
            if guestish and not (w.get("is_guest") or w.get("l2_isolation")):
                out.append(Advice(
                    "wifi.guest_isolation", name, "WiFi", "high",
                    f"Guest SSID \"{name}\" lets its clients reach each other.",
                    f"Settings > WiFi > {name} > Client Device Isolation: on (or make it a Guest Hotspot network).", facts))
            if "2g" in bands and not iot and (not w.get("minrate_ng_enabled") or (w.get("minrate_ng_data_rate_kbps") or 0) < 6000):
                out.append(Advice(
                    "wifi.legacy_rates", name, "WiFi", "low",
                    f"SSID \"{name}\" still allows 802.11b data rates on 2.4 GHz, which slow the whole band down.",
                    f"Settings > WiFi > {name} > Minimum Data Rate Control: 2.4 GHz at 6 Mbps or more.", facts))
            if w.get("hide_ssid"):
                out.append(Advice(
                    "wifi.hidden", name, "WiFi", "low",
                    f"SSID \"{name}\" is hidden. That adds no security, and clients then probe for it everywhere they go.",
                    f"Settings > WiFi > {name} > Hide WiFi Name: off.", facts))
            if aps > 1 and not iot and not (w.get("bss_transition") or w.get("fast_roaming_enabled")):
                out.append(Advice(
                    "wifi.roaming", name, "WiFi", "low",
                    f"SSID \"{name}\" spans {aps} access points without BSS Transition or Fast Roaming, so clients "
                    "hang on to a distant AP.",
                    f"Settings > WiFi > {name} > BSS Transition: on.", facts))
        return out

    def networks(self) -> list[Advice]:
        zones = as_list(self._get("list_firewall_zones_v2"))
        zone_of = {nid: z.get("name") for z in zones for nid in (z.get("network_ids") or [])}
        out = []
        for n in as_list(self._get("list_vlans")):
            name = n.get("name", "?")
            if n.get("purpose") not in ("corporate", "guest") or not self.cfg.isolate_networks.search(name):
                continue
            if zone_of.get(n.get("id"), "Internal") == "Internal":
                out.append(Advice(
                    "network.isolation", name, "Networks", "high",
                    f"Network \"{name}\" is in the Internal zone with your main LAN, so nothing stops its devices "
                    "reaching everything on the LAN.",
                    f"Settings > Policy Engine > Zones: put \"{name}\" in its own zone, then allow only what it needs "
                    "(e.g. DNS) into Internal.", {"network": name, "zone": zone_of.get(n.get("id"))}))
        return out

    def devices(self) -> list[Advice]:
        out = []
        for d in as_list(self._get("search_devices", query="")):
            if d.get("firmware_updatable"):
                name = d.get("name") or d.get("model") or "device"
                out.append(Advice(
                    "device.firmware", name, "Devices", "medium",
                    f"{name} ({d.get('model')}) has a firmware update available (running {d.get('firmware_version')}).",
                    f"UniFi Devices > {name} > Update (or turn on automatic updates with a maintenance window).",
                    {"model": d.get("model"), "firmware": d.get("firmware_version")}))
        return out

    def gateway(self) -> list[Advice]:
        out = []
        for f in as_list(self._get("list_port_forwards")):
            name = f.get("name") or f"{f.get('proto')} {f.get('dst_port')}"
            if VPN.search(name):
                continue  # a VPN endpoint has to be reachable from anywhere
            if f.get("enabled") and str(f.get("src") or "any").lower() in ("any", ""):
                out.append(Advice(
                    "gateway.port_forward_open", name, "Gateway", "low",
                    f"Port forward \"{name}\" ({f.get('proto')} {f.get('dst_port')}) accepts connections from anywhere.",
                    "If only some places need it, set its Source to those addresses; otherwise keep the service behind it "
                    "patched and filtered (IPS, CrowdSec), and accept this with ADVICE_IGNORE.",
                    {"proto": f.get("proto"), "port": f.get("dst_port"), "log": f.get("log")}))
        backup = self._get("get_backup_schedule") or {}
        if isinstance(backup, dict):
            days = backup_interval_days(backup.get("cron_expr", ""))
            if not backup.get("enabled"):
                out.append(Advice("gateway.backup", "schedule", "Gateway", "high",
                                  "Automatic configuration backups are off.",
                                  "Settings > Control Plane > Backups: turn on automatic backups (weekly or more often).",
                                  {"schedule": backup}))
            elif days and days > self.cfg.backup_max_days:
                out.append(Advice("gateway.backup", "schedule", "Gateway", "low",
                                  f"Configuration is backed up automatically only about every {days} days.",
                                  "Settings > Control Plane > Backups: back up weekly, so a restore loses at most a "
                                  "week of changes.", {"cron": backup.get("cron_expr"), "keep": backup.get("max_backups")}))
        dns = self._get("get_dns_filter_settings") or {}
        if isinstance(dns, dict) and dns.get("dns_filtering") and all(
                (f.get("filter") or "none") == "none" for f in dns.get("dns_filters") or []):
            out.append(Advice("gateway.dns_filter", "settings", "Gateway", "low",
                              "DNS filtering is turned on, but no network has a filter level, so it filters nothing.",
                              "Settings > Security > Content Filtering: pick a level for the networks that need one, "
                              "or turn it off.", {"networks": len(dns.get("dns_filters") or [])}))
        return out
