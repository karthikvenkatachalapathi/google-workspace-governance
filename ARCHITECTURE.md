---
Date Created: 07/09/2026 14:45
Last Updated Date: 07/09/2026 14:45
Last Updated by: Hermione
Update Changelog: Updated metadata headers and enforced required fields.
---


# Architecture

Google Workspace Governance Gateway is a policy-enforcing access layer between agents and Google Workspace APIs.

It is designed for environments where multiple AI agents, profiles, or automations need Google Workspace access, but where giving every agent its own broad OAuth token is too risky and too hard to audit.

## High-level flow

```text
MCP host / agent / automation
        |
        | short-lived HS256 JWT
        | profile + optional token_route + action payload
        v
Governed Google Workspace MCP wrapper
        |
        | normalized gateway request
        v
Google Workspace Governance Gateway
        |-- validates JWT/profile
        |-- resolves profile/account route
        |-- resolves resource alias
        |-- classifies policy decision
        |-- blocks, asks, or allows
        |-- performs Google API call when allowed
        |-- writes audit + metrics
        v
Google Workspace APIs
```

The browser control plane runs beside the gateway:

```text
Admin/operator browser
        |
        | app username/password session
        v
Control UI
        |-- first-admin setup
        |-- Google OAuth connection
        |-- profile/account route mapping
        |-- ACL rule editing
        |-- live access log
        |-- runtime apply
        v
Policy YAML + runtime JSON + SQLite token/control state
```

## Components

| Component | File | Role |
|---|---|---|
| Gateway API | `scripts/unified_google_gateway.py` | Private HTTP API used by MCP clients and wrappers. Enforces policy, calls Google APIs, writes audit logs. |
| Control plane | `scripts/google_governance_control_plane.py` | Browser UI and admin APIs for setup, OAuth, route mapping, ACL edits, user management, and runtime health. |
| Policy classifier | `scripts/governance_policy.py` | Loads generated runtime policy and decides `allow`, `ask`, or `deny`. |
| MCP server | `scripts/governed_google_mcp.py` | Exposes Google Workspace tools to MCP hosts while routing everything through the gateway. |
| Approval CLI | `scripts/google_governance_approval_cli.py` | Operator helper for approval-required flows. |
| Policy source | `google-governance-policy.yaml` | Human-reviewable source/seed policy. Updated by control plane in normal operation. |
| Resource registry | `google-resource-registry.yaml` | Source/seed registry for accounts, profiles, resource aliases, and operation metadata. |
| Runtime policy | `generated/profile_policy.json` or installed state path | Generated policy consumed by the gateway runtime. |

## Trust boundaries

### Agent boundary

Agents are not trusted with Google OAuth refresh tokens. They receive:

- gateway URL
- profile name
- optional default token route
- JWT signing secret path

The agent/MCP wrapper signs short-lived JWTs for the gateway. The gateway then performs policy evaluation and Google API calls.

### Gateway boundary

The gateway is the only component that should hold or refresh Google OAuth credentials. It should bind to localhost or an internal network and should not be exposed publicly.

### Control-plane boundary

The control UI is for human operators. It has app-level username/password sessions and should preferably sit behind local access, VPN, reverse proxy auth, or SSO if exposed beyond localhost.

## Authentication model

### Agent to gateway

The MCP wrapper creates an HS256 JWT per request. Claims include:

| Claim | Purpose |
|---|---|
| `iss` | Active profile, e.g. `reasoning` |
| `aud` | `google-workspace-governance` |
| `iat`, `nbf`, `exp` | Short-lived request validity window |
| `scope` | `google.governed` |
| `workflow` | Calling workflow, e.g. `mcp.governed_google` |

The bundled MCP wrapper uses a short expiry window, currently about 60 seconds. This limits replay value and makes the gateway the durable authority instead of the bearer token.

### Operator to control UI

The control UI uses:

- a first-run setup token to create the initial admin;
- app username/password login;
- server-side session state;
- audit logs for control actions.

This is separate from Google OAuth and separate from the agent JWT path.

### Gateway to Google

The gateway uses Google OAuth authorized-user credentials obtained through the control UI. The OAuth credentials are stored in gateway-owned SQLite/token custody state and are not given to agents.

## Route model

A route is:

```text
<profile>/<account-alias>
```

Examples:

```text
reasoning/personal-primary
reasoning/business-airbnb
airbnb/business-airbnb
librarian/personal-primary
```

Properties:

- One profile can have multiple routes.
- One Google account can be mapped to multiple profiles.
- A route chooses the account context for Google API calls.
- Policy still decides whether the action is allowed.
- Use account aliases for account identity, not task-specific route names.

Recommended route practice:

- Keep route names canonical and stable: `profile/account-alias`.
- Do not create use-case-specific account aliases such as `career_packet_sheets` when the same account should be constrained by ACL/resource policy.
- Put purpose-specific limits in policy/resource rules, not in separate duplicate OAuth tokens.

## Policy model

The canonical decision key is:

```text
profile + resource_alias + action => allow | ask | deny
```

Decision order:

1. Global denies.
2. Profile/resource override.
3. Profile default for action.
4. Unknown-profile or unknown-resource fallback.

The policy supports:

- profile defaults for Workspace service actions;
- resource-specific overrides;
- global denies for high-risk classes;
- unknown-profile and unknown-resource fallback decisions;
- operation metadata and risk labels for UI/audit display.

Workflow names and natural-language reasons can be useful audit metadata, but they should not become required policy dimensions unless they represent a distinct actor, action, resource, or stricter exception.

## Approval model

High-risk operations can return `ask` instead of executing. Examples:

- sending a Gmail draft;
- deleting a Calendar event;
- sharing a Drive file externally;
- deleting a Drive file.

Approval flow:

1. Agent calls a high-risk tool.
2. Gateway returns an approval-required response.
3. Operator reviews and approves using the control/approval path.
4. Agent retries with the approval ID.
5. Gateway executes the approved one-time operation and audits it.

The model separates “the OAuth token technically has scope” from “the profile is allowed to perform this action now.”

## Control UI responsibilities

The UI is intended to be the primary operator surface:

- Create first admin.
- Manage control users.
- Connect Google Workspace accounts.
- Show authenticated workspace tokens with friendly labels and discovered emails.
- Map profiles to account routes.
- Revoke route relationships without necessarily deleting the Google account token.
- Disconnect a workspace account and clean up dependent routes/ACL visibility.
- Edit ACL decisions inline or in bulk.
- Display live gateway access logs in plain English.
- Apply runtime policy.

YAML remains useful for source review, seeds, export, and emergency recovery, but normal operators should not need to edit YAML for routine account, route, or ACL changes.

## Observability

The gateway emits:

- request-level JSONL audit logs;
- control-plane JSONL audit logs;
- change-event logs for policy/route/admin mutations;
- optional Prometheus-compatible metrics;
- optional Promtail/Loki scrape configuration.

Audit logs should avoid raw credentials, OAuth headers, full message bodies, or private file contents. Prefer IDs, hashes, profile, action, route, decision, and outcome.

## Deployment shape

Recommended production-like shape is self-contained inside the installed clone:

```text
<repo>/.google-governance/runtime       # installed runtime copy
<repo>/.google-governance/venv          # Python virtualenv
<repo>/.google-governance/state         # SQLite state, runtime policy, token custody
<repo>/.google-governance/config        # setup/admin secrets
<repo>/.google-governance/logs          # audit logs
```

The native installer still writes systemd unit files under `/etc/systemd/system/` and creates the dedicated service user/group during initial setup. After that, clients talk to the gateway API only; they never need filesystem permission to any server-side path.

Services:

```text
google-workspace-governance.service           # private gateway API
google-workspace-governance-control.service   # browser control UI
```

Default binds:

```text
Gateway API: http://127.0.0.1:8768
Control UI:  http://127.0.0.1:8095
```

The gateway API should remain private. The control UI may be exposed behind a trusted reverse proxy or SSO layer if needed.

## Why not just use Google OAuth scopes?

OAuth scopes are too coarse for multi-agent operation. A token with Gmail or Drive scope can usually do far more than a particular agent/workflow should be allowed to do.

This gateway adds a second, local governance layer:

```text
Google OAuth scope says what the account token can technically do.
Gateway policy says what this profile/route/action is allowed to do now.
```

That distinction is the core safety benefit of the project.
