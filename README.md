<!-- mcp-name: io.github.karthikvenkatachalapathi/google-workspace-governance -->

<div align="center">

# <span style="color:#cad8d9">Google Workspace Governance Gateway</span>

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/MCP-Google%20Workspace-purple.svg)](https://modelcontextprotocol.io/)
[![Control Plane](https://img.shields.io/badge/Control%20Plane-Admin%20UI-0969DA.svg)](#admin-control-plane)
[![Governance](https://img.shields.io/badge/Governance-allow%20%7C%20ask%20%7C%20deny-2EA44F.svg)](#governance-model)
[![Inspired by Workspace MCP](https://img.shields.io/badge/Inspired%20by-taylorwilsdon%2Fgoogle__workspace__mcp-cad8d9.svg)](https://github.com/taylorwilsdon/google_workspace_mcp)

*A self-hosted governance layer for Google Workspace access by AI agents, MCP clients, scripts, and automations.*

*Inspired by the excellent [`taylorwilsdon/google_workspace_mcp`](https://github.com/taylorwilsdon/google_workspace_mcp) project. This repository keeps the Workspace MCP-style Google tool surface, then adds a gateway, policy engine, approval workflow, audit trail, and admin control plane around it.*

</div>

<p align="center">
  <a href="https://governance-gateway-demo.pages.dev/">
    <img src="https://img.shields.io/badge/View%20Demo-0969DA?style=for-the-badge" alt="View Demo">
  </a>
  <a href="docs/SCREENSHOTS.md">
    <img src="https://img.shields.io/badge/Screenshots-2EA44F?style=for-the-badge" alt="Screenshots">
  </a>
</p>

<div align="center">
<table>
<tr>
<td align="center">
<b>⚡ Start</b><br>
<sub>
<a href="#quick-start">Quick Start</a> · <a href="SETUP.md">Setup</a><br>
<a href="#normal-setup-flow">Normal Flow</a> · <a href="#mcp-client-example">MCP Client</a>
</sub>
</td>
<td align="center">
<b>🧰 Workspace Tools</b><br>
<sub>
<a href="#features">Services</a> · <a href="#credits-and-upstream">Upstream Credit</a><br>
<a href="#how-this-differs-from-a-google-workspace-mcp-server">Gateway Layer</a>
</sub>
</td>
<td align="center">
<b>🔐 Govern</b><br>
<sub>
<a href="#governance-model">Policy</a> · <a href="#approval-workflows">Approvals</a><br>
<a href="#credential-custody">Credential Custody</a> · <a href="#security-recommendations">Security</a>
</sub>
</td>
<td align="center">
<b>🖥 Operate</b><br>
<sub>
<a href="#admin-control-plane">Admin UI</a> · <a href="#grafana-dashboard">Grafana</a><br>
<a href="#-development">Development</a> · <a href="#local-verification">Tests</a>
</sub>
</td>
<td align="center">
<b>📐 Design</b><br>
<sub>
<a href="ARCHITECTURE.md">Architecture</a> · <a href="SECURITY.md">Security Guide</a><br>
<a href="PUBLISHING_MANIFEST.md">Publishing</a> · <a href="#roadmap-direction">Roadmap</a>
</sub>
</td>
</tr>
</table>
</div>

---

## <span style="color:#adbcbc">Overview</span>

Google Workspace MCP servers make Gmail, Calendar, Drive, Docs, Sheets, Slides, Forms, Contacts, and other Workspace surfaces available to AI agents through tools.

That tool layer is valuable. This repository is intentionally not positioned as a replacement for it.

The Google Workspace Governance Gateway adds the missing operational boundary around those tools:

- a central gateway between agents and Google Workspace
- gateway-owned OAuth credential custody
- per-agent identity and token validation
- route-based Workspace account selection
- `allow`, `ask`, and `deny` policy decisions
- approval workflows for sensitive actions
- audit logs, request IDs, and optional Prometheus/Loki/Grafana observability
- an admin-only browser control plane for setup and day-to-day administration

Instead of giving every agent a broad Google OAuth refresh token, agents call the gateway. The gateway resolves the agent identity, selects the allowed Workspace route, evaluates policy, records audit evidence, and only then calls Google.

---

## <span style="color:#adbcbc">Credits and upstream</span>

This project is inspired by and gives credit to [`taylorwilsdon/google_workspace_mcp`](https://github.com/taylorwilsdon/google_workspace_mcp), a broad, production-minded Google Workspace MCP server.

`google_workspace_mcp` provides the reference shape for a complete Workspace MCP surface: service-oriented tool modules, strong OAuth/runtime concerns, and coverage across Gmail, Drive, Calendar, Docs, Sheets, Slides, Forms, Tasks, Contacts, Chat, Apps Script, and Search. This repository follows that public-facing README/layout style while adding a separate governance boundary rather than presenting itself as a replacement.

This repository adds a governance gateway on top:

| Layer | Upstream Workspace MCP pattern | This project adds |
|---|---|---|
| Tool surface | Agent-callable Google Workspace tools | Governed versions of Workspace operations |
| Credential model | Workspace OAuth credentials for MCP usage | Gateway-owned OAuth custody and client/agent tokens |
| Routing | Tool call reaches an authenticated Google account | Canonical `agent/workspace-alias` token routes |
| Policy | Tool availability and OAuth scope boundaries | `agent + resource + action => allow / ask / deny` |
| Sensitive actions | Callable when tool + OAuth scope allow | Approval-required execution path |
| Operations | MCP server runtime | Admin UI, logs, metrics, backups, and runtime policy apply |

The goal is simple: keep the useful Workspace MCP experience, but make it accountable enough for multi-agent and multi-workspace use.

---

## <span style="color:#adbcbc">Features</span>

> **Governed Workspace access** &ensp;—&ensp; Gmail · Drive · Calendar · Docs · Sheets · Slides · Forms · Contacts/People · Apps Script · Tasks · Chat · Search

<table>
<tr>
<td valign="top" width="50%">

**📧 Gmail** — governed read, attachment download, draft, send, label, thread, and filter operations<br>
**📁 Drive** — file search, content access, import/export, sharing, permissions, and deletes<br>
**📅 Calendar** — events, availability, focus time, out-of-office, reminders, and recurrence<br>
**📝 Docs** — document creation, content extraction, text edits, comments, tables, images, headers/footers<br>
**📊 Sheets** — cell reads/writes, formatting, comments, tables, row movement, conditional formatting<br>
**🖼️ Slides** — presentation creation, page details, thumbnails, comments, batch updates

</td>
<td valign="top" width="50%">

**📋 Forms** — form creation, responses, questions, publish settings<br>
**👤 Contacts** — contact and group lookup, update, and batch operations<br>
**💬 Chat** — spaces, messages, reactions, attachments<br>
**⚡ Apps Script** — projects, deployments, file updates, executions, process inspection<br>
**✅ Tasks** — lists, tasks, hierarchy, updates, completion state<br>
**🔍 Search** — governed Custom Search integration when enabled by policy

---

**🔐 Governance layer**<br>
<sub>agent identity · route mapping · OAuth custody · policy enforcement · human approval · audit trail · metrics</sub>

</td>
</tr>
</table>

---

## Quick Start

> Install services → create admin → connect Workspace → map agent route → set policy → connect MCP client

```bash
git clone <your-fork-url> google-workspace-governance-gateway
cd google-workspace-governance-gateway
sudo PROJECT_DIR="$PWD" bash scripts/install_systemd.sh
sudo bash scripts/verify_systemd.sh
```

Open the control UI:

```text
http://localhost:8095/
```

Create the first admin user with the setup token:

```bash
sudo cat .google-governance/config/control_setup_token
```

The native installer is self-contained: runtime copy, venv, SQLite state, OAuth custody, setup secrets, logs, and backups live under `./.google-governance/` plus `./database/` inside the clone. Those paths are runtime state and are ignored by Git.

| Service | Purpose | Default bind |
|---|---|---|
| `google-workspace-governance.service` | Private gateway API used by agents/tools | `127.0.0.1:8768` |
| `google-workspace-governance-control.service` | Browser control UI for OAuth, route mapping, ACLs, logs, health | `127.0.0.1:8095` |

---

## Normal setup flow

1. Install the services with [`SETUP.md`](SETUP.md).
2. Open the control UI and create the first admin user.
3. In Google Cloud Console, create a Google OAuth **Desktop App** client and download `client_secret.json`.
4. In the control UI, go to **Admin settings → Google Workspace → Configure new workspace**.
5. Upload/paste the Desktop App `client_secret.json` and complete Google consent.
6. Go to **Configure Agent Identity** and create or select the agent/workload identity.
7. Go to **Configure Agent-Workspace Route** and map profiles to connected account routes.
8. Go to **ACL rules** and set `allow`, `ask`, or `deny` for each profile/action/service row.
9. Connect your agent/MCP host to `.google-governance/runtime/governed_google_mcp.py` using the gateway URL, optional default route, a UI-generated `GOOGLE_GOVERNANCE_ACCESS_TOKEN`, and an agent-specific `GOOGLE_GOVERNANCE_AGENT_TOKEN`.

The admin UI/API is the source of truth for workspace connections, routes, ACLs, approvals, and runtime policy generation.

---

## Governance model

The policy decision shape is:

```text
agent identity + resource alias + action => allow | ask | deny
```

Examples:

- A research agent can read Drive files but cannot share them externally.
- A scheduling assistant can create events but cannot delete them.
- A spreadsheet workflow can update one approved sheet but must request approval before sending email.
- Destructive or externally visible actions can be gated behind human approval.
- Different tenants/workspaces can use different policies, approval routes, and audit trails.

### Core concepts

| Concept | Meaning | Example |
|---|---|---|
| **Agent / profile** | Calling workload identity | `agent-a`, `support-bot`, `ops-automation` |
| **Account alias** | Google account name inside the gateway | `workspace-primary`, `workspace-shared` |
| **Token route** | Agent-to-account route | `agent-a/workspace-primary` |
| **Resource alias** | Workspace resource or service boundary | `gmail`, `calendar`, `drive`, `approved-sheet` |
| **Action** | Governed operation being requested | `gmail.send`, `drive.share`, `calendar.create` |
| **Decision** | Runtime policy outcome | `allow`, `ask`, `deny` |

### Token routes

A token route combines the agent identity and account alias:

```text
<agent>/<account-alias>
```

Examples:

```text
agent-a/workspace-primary
agent-b/workspace-shared
support-bot/customer-workspace
```

A profile may have multiple routes. A tool call can pass an explicit `token_route` to choose which connected account to use, if policy allows it.

---

## Credential custody

Agents do not directly hold Google OAuth refresh tokens.

The MCP wrapper sends two separate credentials to the gateway:

- `Authorization: Bearer $GOOGLE_GOVERNANCE_ACCESS_TOKEN` authenticates the MCP bridge/client to the gateway.
- `X-Google-Governance-Agent-Token: $GOOGLE_GOVERNANCE_AGENT_TOKEN` identifies the agent or workload.

The gateway stores token hashes, validates both presented tokens before policy evaluation, and keeps Google OAuth refresh tokens in gateway custody.

Clients never read gateway-local OAuth files, signing secrets, server-side config, SQLite state, setup tokens, approval secrets, or generated runtime policy files.

---

## Admin control plane

The browser control plane is intentionally admin-only. Human workspace owners and application users should not need to manage OAuth custody, route mappings, approval state, ACL generation, or runtime policy files.

Expected operating model:

1. A user or team requests Google Workspace access for an agent/workload.
2. An admin connects or reauthorizes the Workspace account in the control UI.
3. An admin creates or assigns the agent identity.
4. An admin maps the agent-to-workspace route.
5. An admin applies ACL policy.
6. The agent receives only gateway connection settings and tokens.
7. Approvals and audits continue through the governance layer.

The demo uses the real control-plane UI shell and navigation with mock data only. It does not connect to Google, send requests to a live gateway, or expose real credentials.

---

## MCP client example

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
        "GOOGLE_GOVERNANCE_ACCESS_TOKEN": "paste-ui-generated-client-token-here",
        "GOOGLE_GOVERNANCE_AGENT_TOKEN": "paste-ui-generated-agent-token-here"
      }
    }
  }
}
```

Each tool also supports an explicit `token_route` argument so the same profile can choose among multiple mapped Google accounts when policy allows it.

---

## <span style="color:#adbcbc">◆ Development</span>

### <span style="color:#72898f">Project Structure</span>

| Path | Role |
|---|---|
| `scripts/governed_google_mcp.py` | MCP-facing governed Workspace tool server |
| `scripts/unified_google_gateway.py` | Private gateway API, Google API adapters, ACL enforcement, approvals, audit/metrics |
| `scripts/google_workspace_action_catalog.py` | Workspace action/service catalog for policy/UI surfaces |
| `scripts/governance_policy.py` | Runtime policy classifier and resource resolver |
| `scripts/google_governance_control_plane.py` | Browser control UI and control APIs |
| `scripts/google_governance_approval_cli.py` | Approval helper CLI for operators |
| `scripts/install_systemd.sh`, `scripts/verify_systemd.sh` | Native Linux/systemd install and verification |
| `scripts/test_*.py` | Offline regression tests, kept script-local for the single-file runtime shape |
| `ARCHITECTURE.md`, `SECURITY.md`, `SETUP.md` | Deep-dive docs split out from the README |
| `generated/ui/control-plane/` | Control-plane logos/icons and UI deployment assets |
| `grafana/google-workspace-governance-ops-dashboard.json` | Importable operations dashboard |
| `.google-governance/`, `database/` | Ignored local runtime state created by install/UI; never committed |

---

## Grafana dashboard

The repository includes an importable Grafana operations dashboard at `grafana/google-workspace-governance-ops-dashboard.json`. It is designed around the gateway's exported Prometheus metrics (`google_workspace_governance_*`) plus Loki audit jobs for the gateway and control UI.

Expected data sources:

- Prometheus containing `google-workspace-governance` scrape metrics.
- Loki jobs `google-workspace-governance-gateway-audit` and `google-workspace-governance-control-audit`.

---

## Local verification

```bash
PYTHONPYCACHEPREFIX=/tmp/google-gov-pycache python3 -m py_compile scripts/*.py
python3 scripts/test_control_plane.py
python3 scripts/test_approval_workflow.py
python3 scripts/test_governed_mcp.py
```

These tests are offline/static and do not require real Google tokens.

---

## Security recommendations

- Same-host installs may use `http://127.0.0.1:<gateway-port>/mcp` because bearer tokens stay on loopback.
- Cross-host installs must not use raw `http://<gateway-lan-ip>:<gateway-port>/mcp` over a shared LAN.
- For cross-host MCP, use `https://<domain-or-private-dns>/mcp`, SSH tunnel, WireGuard/Tailscale, mTLS, or equivalent encrypted transport.
- Firewall the raw gateway port so ordinary LAN clients cannot bypass the reverse proxy/tunnel and hit `http://<gateway-ip>:<gateway-port>/mcp` directly.
- Do not log `Authorization`, `GOOGLE_GOVERNANCE_ACCESS_TOKEN`, or `GOOGLE_GOVERNANCE_AGENT_TOKEN` values.
- Keep high-risk Workspace actions on `ask` or `deny` so stolen tokens and prompt-injection attempts do not silently execute write/externalizing operations.
- Publish only the authenticated control UI, preferably behind your reverse proxy, VPN, or SSO.
- Do not commit OAuth refresh/access tokens, `.env`, SQLite DBs, audit logs, setup tokens, gateway client tokens, agent tokens, approval secrets, or Google client secrets.
- Give agents only the gateway URL, a client access token, and their own agent token; never give agents filesystem paths to OAuth custody, signing secrets, or server-side config.

See [`SECURITY.md`](SECURITY.md) for full deployment guidance, including same-host vs cross-host MCP patterns, token compromise posture, and prompt-injection controls. See also [`SETUP.md`](SETUP.md) and [`ARCHITECTURE.md`](ARCHITECTURE.md).

---

## Approval workflows

Approval-required actions are represented as `ask` decisions. The gateway records the request, returns an approval requirement, and resumes execution only after an authorized approver approves the stored request.

Use `ask` for actions that are externally visible, destructive, or expensive to reverse, such as:

- sending email
- deleting calendar events
- changing Drive sharing
- deleting Drive files
- modifying shared operational spreadsheets
- running broad batch operations

---

## Roadmap direction

The first version of a governance system naturally starts with explicit ACL rows. The longer-term direction is reusable policy templates and stronger enterprise operating models:

- read-only Workspace assistant
- scheduling assistant
- spreadsheet update workflow
- document drafting assistant
- approval-required external sharing
- deny destructive actions by default
- tenant/workspace policy templates
- richer audit review and export flows
- optional SSO/OIDC and multi-approver workflows

Connectivity lets an agent act. Governance decides whether it should.
