# Google Workspace Governance Gateway

A self-hosted governance gateway for Google Workspace access by AI agents, MCP clients, scripts, and automations.

Instead of giving every agent a broad Google OAuth refresh token, agents call this gateway. The gateway owns Google account custody, enforces profile/action/resource policy, supports multiple account routes per agent profile, records audit logs, and exposes an authenticated browser control plane for setup and day-to-day administration.

## What it does

- Exposes governed Google Workspace tools for Gmail, Calendar, Drive, Docs, Sheets, Slides, and Contacts/People.
- Stores Google OAuth credentials centrally in gateway-owned state instead of in each agent profile.
- Lets administrators connect Google accounts from a browser UI using a Google OAuth Desktop App `client_secret.json`.
- Maps agent profiles to one or more Google account routes such as `agent-a/workspace-primary` or `agent-b/workspace-shared`.
- Enforces `allow`, `ask`, or `deny` decisions for each profile/action/resource surface.
- Supports approval-required flows for high-risk operations such as sending mail, deleting calendar events, Drive sharing, and Drive deletes.
- Generates and reloads runtime policy from the control UI.
- Provides live access logs, control-plane audit logs, and optional Prometheus/Loki/Grafana integration.
- Includes a governed MCP server so Claude Desktop/Code or another MCP-capable runtime can use Google Workspace without direct Google token access.

## How this differs from typical Google Workspace MCP servers

Most Google Workspace MCP servers are thin wrappers around Google APIs. They usually require each MCP host/profile to hold Google OAuth credentials and decide safety at the prompt/tool layer.

This project is different:

| Area | Typical Google MCP server | Google Workspace Governance Gateway |
|---|---|---|
| Google token custody | Token lives beside the agent/MCP server | Gateway-owned token store, managed through control UI |
| Auth between agent and Google layer | Often local trust or long-lived local credentials | Short-lived HS256 JWT from agent/profile to gateway |
| Account routing | Usually one active Google token per server/profile | Multiple routes per profile, e.g. `profile/account-alias` |
| Policy model | Minimal or app-specific | `profile + resource + action => allow/ask/deny` |
| High-risk operations | Often directly callable if OAuth scope allows it | Approval path for externalizing/destructive operations |
| Auditability | Depends on host logs | Gateway JSONL audit, control audit, request IDs, optional metrics |
| Operator workflow | Config files and tokens on disk | Browser UI for OAuth connection, route mapping, ACL edits, runtime apply |
| Google OAuth exposure | Agents often need refresh tokens | Agents receive only gateway URL, profile, route, and JWT secret |

The goal is not just “Google tools over MCP.” The goal is a governed Google access layer that can safely sit between multiple agents and multiple Google accounts.

## Core concepts

### Profile

A profile is the calling agent or runtime identity. Example runtime identities might be:

- `agent-a`
- `agent-b`
- `support-bot`
- `ops-automation`

Use stable slugs that represent your own agent or automation identities.

### Account alias

An account alias names a Google Workspace account inside the gateway. Examples:

- `workspace-primary`
- `workspace-shared`
- `finance-workspace`

The alias is separate from the OAuth token file and separate from any one agent profile. One Google account can be routed to multiple profiles.

### Token route

A token route combines the profile and account alias:

```text
<profile>/<account-alias>
```

Examples:

```text
agent-a/workspace-primary
agent-b/workspace-shared
support-bot/workspace-primary
```

A profile may have multiple routes. A tool call can pass an explicit `token_route` to choose which connected account to use. If omitted, the MCP wrapper may use `GOOGLE_GOVERNANCE_TOKEN_ROUTE` as that profile's default.

### Policy decision

The policy decision shape is:

```text
profile + resource_alias + action => allow | ask | deny
```

Profile-level service decisions are used for broad Workspace actions. Resource overrides can narrow or expand behavior for specific documents, calendars, Drive surfaces, or other resource aliases.

### API-token authentication

Agents do not call the gateway anonymously. The MCP wrapper sends a bearer token generated in the control UI:

- `Authorization: Bearer $GOOGLE_GOVERNANCE_ACCESS_TOKEN`
- the request body includes `profile`, `token_route`, `workflow_intent`, and audit metadata
- the gateway stores only token hashes and validates the presented token before policy evaluation

Clients never read gateway-local OAuth files, signing secrets, or server-side config. Google OAuth refresh tokens remain in gateway custody.

## Quick start: native Linux/systemd

The recommended deployment is native Linux/systemd.

```bash
git clone <your-fork-url> google-workspace-governance-gateway
cd google-workspace-governance-gateway
sudo PROJECT_DIR="$PWD" bash scripts/install_systemd.sh
sudo bash scripts/verify_systemd.sh
```

The native installer is self-contained: runtime copy, venv, SQLite state, OAuth custody, setup secrets, logs, and backups live under `./.google-governance/` inside the clone. The only host-level install artifacts are the systemd units plus the dedicated service user/group.

Open the control UI:

```text
http://localhost:8095/
```

Create the first admin user with the setup token:

```bash
sudo cat .google-governance/config/control_setup_token
```

The default install creates:

| Service | Purpose | Default bind |
|---|---|---|
| `google-workspace-governance.service` | Private gateway API used by agents/tools | `127.0.0.1:8768` |
| `google-workspace-governance-control.service` | Browser control UI for OAuth, route mapping, ACLs, logs, health | `127.0.0.1:8095` |

## Normal setup flow

1. Install the services with [`SETUP.md`](SETUP.md).
2. Open the control UI and create the first admin user.
3. In Google Cloud Console, create a Google OAuth **Desktop App** client and download `client_secret.json`.
4. In the control UI, go to **Admin settings → Google Workspace → Configure new workspace**.
5. Upload/paste the Desktop App `client_secret.json` and complete Google consent.
6. Go to **Configure workspace routes** and map profiles to connected account routes.
7. Go to **ACL rules** and set `allow`, `ask`, or `deny` for each profile/action/service row.
8. Connect your agent/MCP host to `.google-governance/runtime/governed_google_mcp.py` using the gateway URL, profile, optional default route, and a UI-generated `GOOGLE_GOVERNANCE_ACCESS_TOKEN`. Client connections are API-only; clients do not need filesystem permission to server-side state, OAuth custody, config, or secret files.

The YAML files in this repository are seed/source artifacts and recovery material. Routine operators should use the web UI so validation, runtime policy generation, audit logging, and rollback behavior stay consistent.

## Repository layout

| Path | Purpose |
|---|---|
| `scripts/unified_google_gateway.py` | Gateway API, Google API adapters, ACL enforcement, approvals, audit/metrics |
| `scripts/google_governance_control_plane.py` | Browser control UI and control APIs |
| `scripts/governance_policy.py` | Runtime policy classifier and resource resolver |
| `scripts/governed_google_mcp.py` | MCP server exposing governed Google Workspace tools |
| `scripts/google_governance_approval_cli.py` | Approval helper CLI for operators |
| `scripts/install_systemd.sh` | Native Linux/systemd installer |
| `scripts/verify_systemd.sh` | Native Linux/systemd verifier |
| `scripts/test_*.py` | Offline regression tests |
| `google-governance-policy.yaml` | Example/seed ACL policy |
| `google-resource-registry.yaml` | Example/seed account/profile/resource registry |
| `generated/profile_policy.json` | Example generated runtime policy |
| `generated/loki/` | Optional Promtail/Loki scrape config example |
| `grafana/google-workspace-governance-ops-dashboard.json` | Importable Grafana operations dashboard for governance metrics/logs |
| `generated/ui/control-plane/` | Logo and reverse-proxy example |
| `Dockerfile`, `docker-compose.example.yml` | Optional container evaluation path |

## MCP usage example

```json
{
  "mcpServers": {
    "google-governance": {
      "command": "/path/to/google-workspace-governance-gateway/.google-governance/venv/bin/python",
      "args": ["/path/to/google-workspace-governance-gateway/.google-governance/runtime/governed_google_mcp.py"],
      "env": {
        "GOOGLE_GOVERNANCE_URL": "http://127.0.0.1:8768",
        "GOOGLE_GOVERNANCE_PROFILE": "agent-a",
        "GOOGLE_GOVERNANCE_TOKEN_ROUTE": "agent-a/workspace-primary",
        "GOOGLE_GOVERNANCE_ACCESS_TOKEN": "paste-ui-generated-token-here"
      }
    }
  }
}
```

Each tool also supports an explicit `token_route` argument so the same profile can choose among multiple mapped Google accounts when policy allows it.


## Grafana dashboard

The repository includes an importable Grafana operations dashboard at `grafana/google-workspace-governance-ops-dashboard.json`. It is designed around the gateway's exported Prometheus metrics (`google_workspace_governance_*`) plus Loki audit jobs for the gateway and control UI. Host/node panels are intentionally not required, so the dashboard remains useful even when node-exporter is not installed.

Expected data sources:

- Prometheus containing `google-workspace-governance` scrape metrics.
- Loki jobs `google-workspace-governance-gateway-audit` and `google-workspace-governance-control-audit`.

## Local verification

```bash
PYTHONPYCACHEPREFIX=/tmp/google-gov-pycache python3 -m py_compile scripts/*.py
python3 scripts/test_control_plane.py
python3 scripts/test_approval_workflow.py
python3 scripts/test_governed_mcp.py
```

These tests are offline/static and do not require real Google tokens.

## Security defaults

- Keep the gateway API private to localhost or an internal network.
- Publish only the authenticated control UI, preferably behind your reverse proxy or SSO.
- Do not commit OAuth refresh/access tokens, `.env`, SQLite DBs, audit logs, setup tokens, JWT secrets, approval secrets, or Google client secrets.
- Default high-risk operations to `ask` or `deny` until reviewed.
- Give agents only the gateway URL plus `GOOGLE_GOVERNANCE_ACCESS_TOKEN`; never give agents filesystem paths to OAuth custody, JWT/signing secrets, or server-side config.

See [`SETUP.md`](SETUP.md), [`ARCHITECTURE.md`](ARCHITECTURE.md), and [`SECURITY.md`](SECURITY.md) for details.
