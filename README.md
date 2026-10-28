# unifi-health-agent

Watches a UniFi network through the [UniFi MCP server](https://github.com/enuno/unifi-mcp-server)
and posts to Discord (or any Apprise target):

- **Errors, right away:** active UniFi alarms, devices that stay offline, and error events in
  UniFi's event log.
- **Recommendations, weekly:** a digest of configuration changes that follow best practice
  (firewall policy order, network isolation, WiFi security, firmware, backups, port forwards),
  with an optional AI write-up that explains what to do first.

It only reads. The MCP server should run read-only (`UNIFI_READ_ONLY=true`) with this agent's own
`viewer:` token, so the agent couldn't change anything even if it tried.

## Errors (every `POLL_MINUTES`, default 5)

| Check | Reported when | Cleared when |
|---|---|---|
| UniFi alarms (`list_alarms`) | an alarm is active | it's archived |
| Devices (`search_devices`) | a device isn't `ONLINE` for `DEVICE_GRACE_MINUTES` (10), so restarts and firmware updates don't alert | it's back online |
| Event log (`list_events`) | a new event's severity is in `ALERT_SEVERITIES` (HIGH, VERY_HIGH, CRITICAL), or its name matches `ALERT_EVENTS` (lost contact, down, failed, failover, IPS, overheating...) outside `IGNORE_CATEGORIES` (client roaming and connects) | once (events are one-off) |
| The MCP server | unreachable for `DEVICE_GRACE_MINUTES` | it answers again |

UniFi has no syslog over its API: its event log is the log, and most of it is chatter (firewall
blocks, clients roaming), which is why only errors are forwarded. Repeats of the same event in one
check are merged ("×3"). The first run only records the events already there, so a backlog isn't
replayed. While the server can't be read, nothing is reported as cleared.

## Recommendations (weekly, `DIGEST_DAY` at `DIGEST_TIME`)

| Rule | Recommends | Priority |
|---|---|---|
| `firewall.shadowed` | moving an ALLOW policy that sits below a catch-all BLOCK between the same zones, so it can never match (its hit count is shown) | high |
| `network.isolation` | putting IoT/camera/guest/lab networks (`ISOLATE_NETWORKS`) in their own zone, not Internal with the LAN | high |
| `wifi.guest_isolation` | client isolation on a guest SSID | high |
| `gateway.backup` | turning on automatic backups (high), or running them at least every `BACKUP_MAX_DAYS` (low) | high/low |
| `wifi.wpa3` | WPA2/WPA3 transition mode instead of WPA2 only (low for IoT SSIDs, whose devices may not support it) | medium/low |
| `wifi.pmf` | Protected Management Frames on Optional | medium/low |
| `device.firmware` | installing an available firmware update | medium |
| `wifi.legacy_rates` | a 2.4 GHz minimum data rate of 6 Mbps or more (not on IoT SSIDs) | low |
| `wifi.roaming` | BSS Transition on SSIDs that span several APs | low |
| `wifi.hidden` | not hiding SSIDs | low |
| `gateway.port_forward_open` | limiting the source of port forwards open to anyone (VPN endpoints are exempt) | low |
| `gateway.dns_filter` | giving DNS filtering a level, or turning it off when no network uses it | low |

Each item says where to change it in the UniFi UI. New items are marked **New**, and items fixed
since the last digest are listed. To accept an item as it is, add its id to `ADVICE_IGNORE`: a whole
rule (`wifi.pmf`) or one target (`wifi.wpa3:IoT WiFi`). The `unifi_recommendations` bus tool shows the
ids.

With `OPENCODE_API_KEY` set, an [OpenCode Go](https://opencode.ai/go) model (`OPENCODE_MODEL`,
default `glm-5.2`) turns the items into a short "what to do first" note. It sees only the findings
and the settings each rule looked at (names, modes, counts): no passphrases, keys or MAC addresses.
`NETWORK_NOTES` tells it what it should know ("the IoT SSID must stay WPA2"). Without a key, or if
the call fails, the digest goes out with the rules' own wording. A digest that can't be delivered is
retried at the next check, without asking the model again.

`python -m unifi_agent --digest` sends the digest now.

## The UniFi MCP server

The agent needs tools from several of the server's groups (events, devices, firewall, WiFi), so
the server should register every read-only tool: leave `UNIFI_PROFILE` unset. An assistant that
should see fewer can filter on its side. Give each client its own token:
`MCP_AUTH_TOKEN=viewer:<token-for-assistant>,viewer:<token-for-this-agent>`, and set this agent's
`UNIFI_MCP_TOKEN` to its token without the `viewer:` prefix. Tools need a site; `UNIFI_SITE`
defaults to `default`.

## Deployment

Every push to `main` runs the tests. The deploy job then sends the build context (the generated
`Dockerfile` and `.dockerignore`, `requirements.txt` and the package) and a rendered `agent.env` to
a Docker host. There, the root-owned `agent-deploy` builds the image and replaces the container,
and rolls back if the new one doesn't stay up. Each build pulls the newest base image and runs
`apt-get full-upgrade`, so every deployed image is fully patched. State lives in the
`unifi-agent-data` volume.

| Variable | Expected value |
|---|---|
| `AGENT_HOST` | Address of the Docker host. |
| `PRIORITY` | `high` (default) or `low`. Picks the deploying runner (`[self-hosted, proxmox]` or `[self-hosted, low-priority]`) and sets the container label `homelab.priority`. |
| `BUS_HOST_PORT` | Optional. Host port for the agent bus when several agents share a host. The container still listens on `AGENT_BUS_PORT`. |

To prepare a Docker host, run `deploy/docker-host.sh` from the dockerfile-agent repository. The
systemd unit in `deploy/lxc/unifi-agent-install` is what dockerfile-agent generates the Dockerfile
from.

### Self-hosted runners and public repositories

GitHub advises against attaching self-hosted runners to public repositories, because a pull
request from a fork could run code on your hardware. This workflow runs tests on GitHub-hosted
runners and never runs the deploy job for pull requests, but to be safe deploy from a **private**
copy, or require approval for fork pull request workflows.

## Secrets and variables (required before the first deploy)

This repository contains **no secrets**. Set them under **Settings → Secrets and variables →
Actions**. The deploy job writes them to the container's `agent.env`.

### Secrets

| Name | Required | Expected value |
|---|---|---|
| `UNIFI_MCP_TOKEN` | **yes** | This agent's bearer token on the UniFi MCP server: the part after `viewer:` of its entry in the server's `MCP_AUTH_TOKEN` (`openssl rand -hex 32`). |
| `NOTIFY_URLS` | recommended | Comma-separated Apprise URLs. A Discord webhook (`https://discord.com/api/webhooks/<id>/<token>`) gets formatted embeds. |
| `OPENCODE_API_KEY` | no | OpenCode Go API key for the AI write-up. Empty: no write-up. |
| `AGENT_BUS_TOKEN` | no | Long random bearer token for the agent bus (`openssl rand -hex 32`); the same value goes in your assistant's MCP config. |
| `PUBLIC_DEPLOY_KEY` | no | Only for mirroring a private copy to a public one. |

### Variables

| Name | Required | Expected value |
|---|---|---|
| `UNIFI_MCP_URL` | **yes** | The MCP server as the agent reaches it, e.g. `http://192.0.2.10:3000/mcp`. |
| `AGENT_HOST`, `PRIORITY`, `BUS_HOST_PORT` | `AGENT_HOST` yes | See Deployment. |
| `TIMEZONE`, `DIGEST_DAY`, `DIGEST_TIME` | no | Weekly digest schedule (default `UTC`, `sun`, `09:00`). |
| `UNIFI_SITE`, `POLL_MINUTES`, `DEVICE_GRACE_MINUTES`, `ALERT_SEVERITIES`, `ALERT_EVENTS`, `IGNORE_CATEGORIES`, `ISOLATE_NETWORKS`, `BACKUP_MAX_DAYS`, `ADVICE_IGNORE`, `OPENCODE_MODEL`, `OPENCODE_BASE_URL`, `NETWORK_NOTES`, `RENOTIFY_HOURS`, `AGENT_BUS_PORT`, `BOT_ALERT_URL` | no | See `.env.example` for each default. |

## Agent bus (MCP for an assistant such as Hermes Agent)

With `AGENT_BUS_TOKEN` set, the agent serves MCP on `AGENT_BUS_PORT` (`/mcp`, bearer token). All
tools are read-only:

| Tool | Returns |
|---|---|
| `unifi_status` | every device with its state and firmware, the open alerts, and the digest schedule |
| `unifi_recommendations` | the best-practice checks, run now, highest priority first, with their ids |
| `agent_status`, `agent_last_diagnosis`, `agent_run_check` | the agent's revision and its latest findings, and a check now |

## Develop

```bash
pip install -r requirements.txt pytest
pytest -q
# with UNIFI_MCP_URL / UNIFI_MCP_TOKEN / STATE_PATH exported:
python -m unifi_agent --once
```
