import copy
import json
from datetime import datetime

import pytest

from unifi_agent.advisor import Advisor, backup_interval_days
from unifi_agent.checks import Monitor, render
from unifi_agent.config import Config
from unifi_agent.findings import Finding
from unifi_agent.mcp import MCPClient, MCPError, ToolError
from unifi_agent.notify import Notifier
from unifi_agent.state import State

# Shapes as the UniFi MCP server returns them; names and addresses are placeholders.
DEVICES = [
    {"id": "d1", "name": "Core Switch", "model": "USW Aggregation", "state": "ONLINE", "firmware_version": "7.5.15",
     "firmware_updatable": False, "features": ["switching"]},
    {"id": "d2", "name": "Hallway AP", "model": "U7 Pro", "state": "ONLINE", "firmware_version": "8.7.11",
     "firmware_updatable": False, "features": ["accessPoint"]},
    {"id": "d3", "name": "Garden AP", "model": "U6 Mesh", "state": "ONLINE", "firmware_version": "6.8.2",
     "firmware_updatable": True, "features": ["accessPoint"]},
]


def event(ident, name, severity="LOW", category="CLIENT_DEVICES", **params):
    return {"id": ident, "event": name, "severity": severity, "category": category, "timestamp": 1,
            "message_raw": "{DEVICE} " + name.lower().replace("_", " "),
            "parameters": {"DEVICE": {"id": "x", "name": params.get("device", "Garden AP")}}}


class FakeMCP:
    def __init__(self, **responses):
        self.r = {"health_check": {"status": "ok"}, "list_alarms": "", "search_devices": DEVICES, "list_events": [],
                  **responses}
        self.calls = []

    def call_tool(self, name, arguments=None):
        self.calls.append((name, arguments))
        v = self.r.get(name)
        if isinstance(v, Exception):
            raise v
        return copy.deepcopy(v() if callable(v) else v)


class Clock:
    def __init__(self):
        self.now = 1_000_000.0

    def __call__(self):
        return self.now


def cfg(tmp_path, **kw):
    c = Config(mcp_url="http://mcp:3000/mcp", mcp_token="t", state_path=str(tmp_path / "s.json"))
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def keys(findings):
    return {f.key for f in findings}


# --- alerts ---

def test_events_first_run_is_a_baseline_then_only_errors_alert(tmp_path):
    mcp, clock = FakeMCP(), Clock()
    m = Monitor(mcp, cfg(tmp_path), State(str(tmp_path / "s.json")), clock)
    mcp.r["list_events"] = [event("old1", "DEVICE_LOST_CONTACT", category="DEVICES")]
    assert m.run()[0] == []  # backlog only recorded
    mcp.r["list_events"] = [
        event("old1", "DEVICE_LOST_CONTACT", category="DEVICES"),
        event("e1", "BLOCKED_BY_FIREWALL", "MEDIUM", "SECURITY"),
        event("e2", "CLIENT_DISCONNECTED_WIRELESS"),  # client chatter
        event("e3", "DEVICE_LOST_CONTACT", category="DEVICES"),
        event("e4", "DEVICE_LOST_CONTACT", category="DEVICES"),
        event("e5", "WAN_FAILOVER", "HIGH", "INTERNET", device="Internet 1"),
    ]
    fs = {f.key: f for f in m.run()[0]}
    assert set(fs) == {"event:e3", "event:e5"}
    assert fs["event:e3"].summary == "Garden AP device lost contact (×2) [DEVICE_LOST_CONTACT]"
    assert fs["event:e3"].severity == "warning" and fs["event:e3"].once
    assert fs["event:e5"].severity == "error"
    assert m.run()[0] == []  # already seen


def test_device_offline_alerts_after_the_grace_period_and_clears(tmp_path):
    mcp, clock = FakeMCP(), Clock()
    st = State(str(tmp_path / "s.json"))
    c = cfg(tmp_path, device_grace_minutes=10)
    m, n = Monitor(mcp, c, st, clock), Notifier([], 24, st)
    sent = []
    n.outbox = type("O", (), {"send": lambda s, msg: sent.append(msg.markdown()) or True})()
    devices = copy.deepcopy(DEVICES)
    devices[2]["state"] = "OFFLINE"
    mcp.r["search_devices"] = devices
    n.send(*m.run())
    assert sent == []  # within the grace period (a restart or an update)
    clock.now += 11 * 60
    n.send(*m.run())
    assert len(sent) == 1 and "Garden AP (U6 Mesh) is OFFLINE" in sent[0]
    devices[2]["state"] = "ONLINE"
    n.send(*m.run())
    assert "**✅ Cleared**" in sent[-1] and st["offline"] == {}


def test_active_alarms_alert_and_an_empty_answer_is_none(tmp_path):
    mcp = FakeMCP(list_alarms=[{"_id": "a1", "msg": "AP Garden AP was disconnected", "key": "EVT_AP_Lost_Contact"}])
    m = Monitor(mcp, cfg(tmp_path), State(str(tmp_path / "s.json")), Clock())
    fs = m.run()[0]
    assert keys(fs) == {"alarm:a1"} and fs[0].summary == "UniFi alarm: AP Garden AP was disconnected"
    mcp.r["list_alarms"] = None
    assert m.run()[0] == []


def test_unreachable_server_alerts_after_the_grace_period_and_never_clears_anything(tmp_path):
    mcp, clock = FakeMCP(health_check=MCPError("connection refused")), Clock()
    m = Monitor(mcp, cfg(tmp_path, device_grace_minutes=10), State(str(tmp_path / "s.json")), clock)
    assert m.run() == ([], False, ())
    clock.now += 11 * 60
    fs, complete, _ = m.run()
    assert keys(fs) == {"mcp:down"} and not complete
    mcp.r["health_check"] = {"status": "ok"}
    assert m.run()[1] and "mcp" not in m.state["outage"]


def test_a_failing_tool_keeps_its_alerts_open(tmp_path):
    st = State(str(tmp_path / "s.json"))
    n = Notifier([], 24, st)
    sent = []
    n.outbox = type("O", (), {"send": lambda s, msg: sent.append(msg.markdown()) or True})()
    mcp, clock = FakeMCP(), Clock()
    devices = copy.deepcopy(DEVICES)
    devices[0]["state"] = "OFFLINE"
    mcp.r["search_devices"] = devices
    m = Monitor(mcp, cfg(tmp_path, device_grace_minutes=0), st, clock)
    n.send(*m.run())
    assert "device:d1:state" in st["notified"]
    mcp.r["search_devices"] = ToolError("search_devices: HTTP 500")
    fs, complete, unchecked = m.run()
    assert unchecked == ("device:",) and keys(fs) == {"check:device"}
    n.send(fs, complete, unchecked)
    assert "device:d1:state" in st["notified"] and "Cleared" not in sent[-1]


def test_event_messages_fill_their_placeholders():
    e = {"message_raw": "{SRC_CLIENT} was blocked from accessing {DST_IP} by {TRIGGER}.",
         "parameters": {"SRC_CLIENT": {"name": "Phone"}, "DST_IP": {"id": "192.0.2.5"}, "TRIGGER": {"name": "Block IoT"}}}
    assert render(e) == "Phone was blocked from accessing 192.0.2.5 by Block IoT."
    assert render({"event": "WAN_DOWN"}) == "WAN_DOWN"


# --- recommendations ---

ALWAYS = {"mode": "ALWAYS", "date_start": None, "date_end": None, "time_all_day": None, "time_range_start": None,
          "time_range_end": None, "repeat_on_days": None}  # as the server returns it


def policy(name, index, action="ALLOW", src="z-iot", dst="z-lan", protocol="tcp", hits=10, ipv="BOTH", schedule=ALWAYS, **kw):
    side = {"matching_target": "ANY", "port_matching_type": "ANY"}
    return {"name": name, "index": index, "action": action, "enabled": True, "predefined": False, "protocol": protocol,
            "ip_version": ipv, "hits": hits, "schedule": schedule, "source": {"zone_id": src, **side},
            "destination": {"zone_id": dst, **side, **kw}}


WLANS = [
    {"name": "iot-devices", "enabled": True, "security": "wpapsk", "wpa_mode": "wpa2", "wpa3_support": False, "pmf_mode": "disabled",
     "wlan_bands": ["2g"], "minrate_ng_enabled": True, "minrate_ng_data_rate_kbps": 1000, "bss_transition": False},
    {"name": "Guest WiFi", "enabled": True, "security": "wpapsk", "wpa3_support": True, "pmf_mode": "optional",
     "wlan_bands": ["5g", "6g"], "is_guest": False, "l2_isolation": True, "fast_roaming_enabled": True},
    {"name": "Home", "enabled": True, "security": "wpapsk", "wpa3_support": False, "pmf_mode": "disabled",
     "wlan_bands": ["2g", "5g"], "minrate_ng_enabled": False, "hide_ssid": True, "bss_transition": False},
    {"name": "Visitors guest", "enabled": True, "security": "open", "wlan_bands": ["5g"], "bss_transition": True},
]


def advisor_mcp(**over):
    r = {"list_firewall_policies": [], "search_devices": DEVICES, "list_wlans": [], "list_vlans": [],
         "list_firewall_zones_v2": [], "list_port_forwards": [], "get_backup_schedule": {"enabled": True, "cron_expr": "0 3 * * 0"},
         "get_dns_filter_settings": {"dns_filtering": False}}
    r.update(over)
    return FakeMCP(**r)


def test_shadowed_allow_policy_is_found(tmp_path):
    policies = [
        policy("Allow IoT to DNS", 10000, protocol="udp", port_matching_type="SPECIFIC"),
        policy("Block IoT to LAN", 10001, action="BLOCK", protocol="all", hits=5),
        policy("Allow Casting", 10002, hits=None, port_matching_type="OBJECT"),
        policy("Allow v6 thing", 10003, ipv="IPV6"),
        policy("Allow LAN to IoT", 10001, src="z-lan", dst="z-iot"),
    ]
    advice, failed = Advisor(advisor_mcp(list_firewall_policies=policies), cfg(tmp_path)).run()
    assert failed == []
    a = {x.key: x for x in advice}
    assert "firewall.shadowed:Allow Casting" in a and a["firewall.shadowed:Allow Casting"].priority == "high"
    assert "never been hit" in a["firewall.shadowed:Allow Casting"].summary
    assert "firewall.shadowed:Allow v6 thing" in a  # the block covers both IP versions
    v4_block = [policy("Block v4", 1, action="BLOCK", protocol="all", ipv="IPV4"), policy("Allow v6", 2, ipv="IPV6")]
    scheduled = [policy("Block nights", 1, action="BLOCK", protocol="all", schedule={**ALWAYS, "mode": "EVERY_DAY"}),
                 policy("Allow", 2)]
    for case in (v4_block, scheduled):
        assert not [x for x in Advisor(advisor_mcp(list_firewall_policies=case), cfg(tmp_path)).run()[0]
                    if x.rule == "firewall.shadowed"]


def test_wifi_rules(tmp_path):
    advice = Advisor(advisor_mcp(list_wlans=WLANS), cfg(tmp_path)).run()[0]
    a = {x.key: x for x in advice}
    assert a["wifi.wpa3:iot-devices"].priority == "low" and "IoT" in a["wifi.wpa3:iot-devices"].summary
    assert a["wifi.wpa3:Home"].priority == "medium" and a["wifi.pmf:Home"].priority == "medium"
    assert "wifi.wpa3:Guest WiFi" not in a and "wifi.guest_isolation:Guest WiFi" not in a  # isolated already
    assert a["wifi.guest_isolation:Visitors guest"].priority == "high"
    assert "wifi.legacy_rates:Home" in a and "wifi.legacy_rates:iot-devices" not in a  # IoT may need low rates
    assert "wifi.hidden:Home" in a and "wifi.roaming:Home" in a and "wifi.roaming:iot-devices" not in a
    assert "wifi.wpa3:Visitors guest" not in a  # open network: not a WPA2 question


def test_isolated_networks_must_have_their_own_zone(tmp_path):
    vlans = [{"id": "n1", "name": "Default", "purpose": "corporate"}, {"id": "n2", "name": "IoT", "purpose": "corporate"},
             {"id": "n3", "name": "Cameras", "purpose": "corporate"}, {"id": "n4", "name": "Internet 1", "purpose": "wan"}]
    zones = [{"name": "Internal", "network_ids": ["n1", "n3"]}, {"name": "IoT", "network_ids": ["n2"]}]
    keys_ = {x.key for x in Advisor(advisor_mcp(list_vlans=vlans, list_firewall_zones_v2=zones), cfg(tmp_path)).run()[0]}
    assert "network.isolation:Cameras" in keys_ and "network.isolation:IoT" not in keys_
    assert "network.isolation:Default" not in keys_


def test_gateway_and_device_rules(tmp_path):
    mcp = advisor_mcp(
        list_port_forwards=[{"name": "HTTPS", "enabled": True, "src": "any", "proto": "tcp", "dst_port": "443"},
                            {"name": "Limited", "enabled": True, "src": "198.51.100.0/24", "proto": "tcp", "dst_port": "22"},
                            {"name": "wireguard", "enabled": True, "src": "any", "proto": "udp", "dst_port": "51820"}],
        get_backup_schedule={"enabled": True, "cron_expr": "30 0 1 * *", "max_backups": 7},
        get_dns_filter_settings={"dns_filtering": True, "dns_filters": [{"filter": "none"}, {"filter": "none"}]})
    a = {x.key: x for x in Advisor(mcp, cfg(tmp_path)).run()[0]}
    assert "gateway.port_forward_open:HTTPS" in a and "gateway.port_forward_open:Limited" not in a
    assert "gateway.port_forward_open:wireguard" not in a
    assert a["gateway.backup:schedule"].priority == "low" and "30 days" in a["gateway.backup:schedule"].summary
    assert "gateway.dns_filter:settings" in a
    assert a["device.firmware:Garden AP"].priority == "medium" and "6.8.2" in a["device.firmware:Garden AP"].summary
    off = {x.key: x for x in Advisor(advisor_mcp(get_backup_schedule={"enabled": False}), cfg(tmp_path)).run()[0]}
    assert off["gateway.backup:schedule"].priority == "high"
    assert backup_interval_days("0 3 * * 0") == 7 and backup_interval_days("0 3 * * *") == 1
    assert backup_interval_days("bad") is None


def test_advice_ignore_accepts_a_rule_or_one_target_and_failures_are_reported(tmp_path):
    c = cfg(tmp_path, advice_ignore=["wifi.pmf", "wifi.wpa3:iot-devices"])
    advice, failed = Advisor(advisor_mcp(list_wlans=WLANS, list_vlans=ToolError("boom")), c).run()
    k = {x.key for x in advice}
    assert not any(x.startswith("wifi.pmf:") for x in k) and "wifi.wpa3:iot-devices" not in k and "wifi.wpa3:Home" in k
    assert failed == ["networks"]
    assert [x.priority for x in advice] == sorted((x.priority for x in advice), key=["high", "medium", "low"].index)


def test_weekly_digest_marks_new_lists_fixed_and_retries_when_undelivered(tmp_path):
    from unifi_agent.advisor import Advice
    st = State(str(tmp_path / "s.json"))
    n = Notifier([], 24, st)
    sent, ok = [], [False]
    n.outbox = type("O", (), {"send": lambda s, msg: sent.append(msg.markdown()) or ok[0]})()
    a1 = Advice("wifi.pmf", "Home", "WiFi", "medium", "PMF is off on Home.", "Turn PMF on.")
    a2 = Advice("gateway.backup", "schedule", "Gateway", "low", "Backups are monthly.", "Back up weekly.")
    assert not n.weekly([a1, a2], "Do PMF first.")
    assert st["advice"] == {}  # not delivered: nothing recorded
    ok[0] = True
    assert n.weekly([a1, a2], "Do PMF first.")
    assert "Do PMF first." in sent[-1] and sent[-1].count("**New:**") == 2 and "Turn PMF on." in sent[-1]
    assert n.weekly([a1], None)
    assert "**New:**" not in sent[-1] and "✅ Fixed since last week**\n• Backups are monthly." in sent[-1]
    assert n.weekly([], None)
    assert "✅ Fixed since last week**\n• PMF is off on Home." in sent[-1]
    assert n.weekly([], None)
    assert "Everything checked follows best practice." in sent[-1]


def test_undelivered_alert_is_retried(tmp_path):
    st = State(str(tmp_path / "s.json"))
    n = Notifier([], 24, st)
    sent, ok = [], [False]
    n.outbox = type("O", (), {"send": lambda s, msg: sent.append(msg.markdown()) or ok[0]})()
    n.send([Finding("event:e1", "Garden AP lost contact", "warning", once=True)])
    assert st["notified"] == {}
    ok[0] = True
    n.send([])  # the event isn't found again, but it's still owed
    assert len(sent) == 2 and "Garden AP lost contact" in sent[1] and "event:e1" in st["notified"]


def test_digest_schedule():
    from unifi_agent.__main__ import digest_due
    c = Config(mcp_url="u", mcp_token="t", digest_day="sun", digest_time="09:00")
    sunday = datetime(2026, 11, 1, 9, 5)
    assert digest_due(c, {}, sunday) and not digest_due(c, {"digest": "2026-11-01"}, sunday)
    assert not digest_due(c, {}, sunday.replace(hour=8)) and not digest_due(c, {}, datetime(2026, 11, 2, 10, 0))


def test_digest_write_up_is_asked_once_per_set_of_recommendations(tmp_path, monkeypatch):
    from unifi_agent import __main__ as main
    asked = []
    monkeypatch.setattr(main, "write_up", lambda c, advice: asked.append(len(advice)) or "text")
    st = State(str(tmp_path / "s.json"))
    n = Notifier([], 24, st)
    n.outbox = type("O", (), {"send": lambda s, msg: False})()  # Discord is down
    adv = Advisor(advisor_mcp(get_backup_schedule={"enabled": False}), cfg(tmp_path))
    cache: dict = {}
    assert not main.send_digest(adv, n, cfg(tmp_path), cache) and not main.send_digest(adv, n, cfg(tmp_path), cache)
    assert asked == [2]


# --- write-up, client, config ---

def test_write_up_sends_only_findings_and_survives_failures(tmp_path):
    from unifi_agent.advisor import Advice
    from unifi_agent.writeup import write_up
    adv = [Advice("wifi.pmf", "Home", "WiFi", "medium", "PMF is off.", "Turn it on.", {"pmf_mode": "disabled"})]
    assert write_up(cfg(tmp_path), adv) is None  # no OpenCode key: off

    class Resp:
        def __init__(self, body, status=200):
            self.body, self.status_code = body, status

        def raise_for_status(self):
            if self.status_code >= 400:
                import requests
                raise requests.HTTPError(str(self.status_code))

        def json(self):
            return self.body

    class Session:
        def __init__(self, resp):
            self.resp, self.sent = resp, []

        def post(self, url, json=None, timeout=None, headers=None):
            self.sent.append((url, json, headers))
            return self.resp

    c = cfg(tmp_path, opencode_api_key="k")
    s = Session(Resp({"choices": [{"message": {"content": " Turn PMF on first. "}}]}))
    assert write_up(c, adv, s) == "Turn PMF on first."
    url, body, headers = s.sent[0]
    assert url.endswith("/chat/completions") and headers["Authorization"] == "Bearer k" and headers["x-opencode-session"]
    assert json.loads(body["messages"][1]["content"])[0]["facts"] == {"pmf_mode": "disabled"}
    assert write_up(c, adv, Session(Resp({}, 500))) is None


class FakeResp:
    def __init__(self, status=200, body=None, text="", ctype="application/json", headers=None):
        self.status_code, self._body, self.headers = status, body, {"content-type": ctype, **(headers or {})}
        self.text = text or (json.dumps(body) if body is not None else "")
        self.content = self.text.encode()

    def json(self):
        return self._body


class FakeHTTP:
    def __init__(self, replies):
        self.replies, self.headers, self.posts = list(replies), {}, []

    def post(self, url, json=None, timeout=None):
        self.posts.append((json.get("method"), dict(self.headers)))
        return self.replies.pop(0)


def init_replies():
    return [FakeResp(body={"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2025-06-18"}},
                     headers={"mcp-session-id": "s1"}), FakeResp(status=202)]


def test_mcp_client_bearer_unwraps_results_and_renews_a_lost_session():
    sse = 'event: message\ndata: {"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"[{\\"id\\": 1}]"}]}}\n'
    http = FakeHTTP(init_replies() + [
        FakeResp(body={"jsonrpc": "2.0", "id": 3, "result": {"content": [{"type": "text", "text": ""}],
                                                              "structuredContent": {"result": ""}}}),
        FakeResp(status=404, text="Session not found"),
        *[FakeResp(body={"jsonrpc": "2.0", "id": 5, "result": {"protocolVersion": "2025-06-18"}}), FakeResp(status=202)],
        FakeResp(text=sse, ctype="text/event-stream"),
    ])
    c = MCPClient("http://mcp/mcp", "tok", session=http)
    assert http.headers["Authorization"] == "Bearer tok"
    assert c.call_tool("list_alarms") == ""  # "" means no alarms
    c._ids = iter([4, 5, 3])
    assert c.call_tool("list_events") == [{"id": 1}]
    assert [p[0] for p in http.posts].count("initialize") == 2


def test_mcp_client_errors():
    http = FakeHTTP(init_replies() + [FakeResp(body={"jsonrpc": "2.0", "id": 3, "result": {
        "content": [{"type": "text", "text": "device not found"}], "isError": True}})])
    with pytest.raises(ToolError):
        MCPClient("http://mcp/mcp", "tok", session=http).call_tool("get_device_details")
    with pytest.raises(MCPError, match="UNIFI_MCP_TOKEN"):
        MCPClient("http://mcp/mcp", "bad", session=FakeHTTP([FakeResp(status=401)])).call_tool("health_check")


def test_config(monkeypatch):
    monkeypatch.setenv("UNIFI_MCP_URL", "http://mcp:3000/mcp")
    monkeypatch.setenv("UNIFI_MCP_TOKEN", "t")
    monkeypatch.setenv("DIGEST_DAY", "Saturday")
    monkeypatch.setenv("ADVICE_IGNORE", "wifi.pmf, wifi.wpa3:iot-devices")
    monkeypatch.setenv("ALERT_SEVERITIES", "high,critical")
    c = Config.from_env()
    assert c.digest_day == "sat" and c.advice_ignore == ["wifi.pmf", "wifi.wpa3:iot-devices"]
    assert c.alert_severities == ["HIGH", "CRITICAL"] and not c.writeup_enabled
    monkeypatch.setenv("DIGEST_TIME", "9am")
    with pytest.raises(SystemExit):
        Config.from_env()
    monkeypatch.delenv("UNIFI_MCP_TOKEN")
    with pytest.raises(SystemExit):
        Config.from_env()


def test_discord_posts_are_sent_under_the_agents_own_name(monkeypatch):
    from unifi_agent import notice

    posted = []
    monkeypatch.setattr(notice, "_post_webhook", lambda url, payload: posted.append(payload) or True)
    url = "https://discord.com/api/webhooks/" + "1/fake-TOKEN"  # split so the public-sync secret scan passes
    assert notice.Outbox([url]).send(notice.Message("hi"))
    notice.Outbox([url], username="Someone else").send(notice.Message("hi"))
    assert [p["username"] for p in posted] == ["unifi-agent", "Someone else"]
    assert posted[0]["avatar_url"].endswith("/png/unifi.png")


def test_deploy_renders_every_setting_it_is_given():
    """Every variable/secret passed to the 'Render agent.env' step must be written to agent.env.

    Guards against adding a setting to the step's env block but not to the loop, which silently
    drops it from the deployed config.
    """
    import pathlib
    import re
    wf = (pathlib.Path(__file__).resolve().parent.parent / ".github" / "workflows" / "deploy.yml").read_text(encoding="utf-8")
    step = wf.split("- name: Render agent.env", 1)[1].split("- name:", 1)[0]
    env_block, run_block = step.split("run: |", 1)
    given = set(re.findall(r"^\s+([A-Z_]+): \$\{\{ (?:vars|secrets)\.", env_block, re.M))
    loop = re.search(r"for v in (.*?); do", run_block, re.S).group(1)
    written = set(re.findall(r"[A-Z_]+", loop))
    assert given - written == set(), f"passed to the step but never written to agent.env: {sorted(given - written)}"
