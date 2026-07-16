# Security and publishing checklist

Use this checklist before pushing the project to a public GitHub repository and before deploying it for real Google Workspace use.

## Do not publish secrets or private state

Never commit:

- Google OAuth refresh/access tokens.
- Google OAuth Desktop App `client_secret.json` files.
- `.env` files, except `.env.example`.
- `.google-governance/` installed runtime/state/secrets/logs.
- `database/` runtime SQLite state.
- SQLite databases.
- JSONL audit logs.
- setup tokens.
- gateway client tokens and agent tokens.
- approval admin secrets.
- session secrets.
- local backups containing private emails, document IDs, calendar IDs, or account-specific runtime state.

The repository `.gitignore` excludes common state files, but do not rely on ignore rules alone. Review `git status --short` and `git diff --cached` before pushing.

## Security recommendations

### Same-host deployments

For a single-machine installation, the recommended shape is:

```text
agent/MCP client -> http://127.0.0.1:<gateway-port>/mcp -> gateway
```

This is acceptable because bearer tokens never leave the local host's loopback interface.

### Cross-host deployments

If the agent/MCP host is on a different machine from the gateway, do **not** point clients at raw HTTP over the LAN:

```text
# Do not use this for production cross-host installs
agent/MCP client -> http://<gateway-lan-ip>:<gateway-port>/mcp
```

Use an encrypted private transport instead:

```text
agent/MCP client -> https://<domain-or-private-dns>/mcp -> reverse proxy/tunnel -> gateway localhost/private port
```

Recommended cross-host patterns, from simplest to strongest:

| Pattern | Use when | Notes |
|---|---|---|
| SSH tunnel | One/few known agent hosts | Simple, no public listener required. |
| WireGuard/Tailscale | Homelab/private fleet | Good default for private cross-host installs. |
| HTTPS reverse proxy | Operators want a normal URL | Must firewall the raw gateway port and avoid auth-header logging. |
| mTLS | Higher-assurance service-to-service deployments | Strongest identity boundary, more operational overhead. |

Hard requirements for cross-host installs:

- Use `https://<domain-or-private-dns>/mcp`, SSH tunnel, WireGuard/Tailscale, mTLS, or equivalent encrypted transport.
- Block direct `http://<gateway-ip>:<gateway-port>/mcp` access with host/network firewall rules.
- Bind the raw gateway to `127.0.0.1` when the reverse proxy runs on the same host.
- If the gateway must bind on a private interface, allow only the reverse proxy or tunnel interface to reach it.
- Do not log `Authorization`, `GOOGLE_GOVERNANCE_ACCESS_TOKEN`, or `GOOGLE_GOVERNANCE_AGENT_TOKEN` values in the reverse proxy, gateway, MCP client, or process supervisor.
- Treat bearer tokens as replayable credentials: if intercepted, they can be used until revoked.

### Token compromise and prompt-injection posture

The gateway uses two distinct credentials:

| Credential | Purpose | Risk if stolen |
|---|---|---|
| `GOOGLE_GOVERNANCE_ACCESS_TOKEN` | Authenticates the client/bridge to the gateway | Lets an attacker reach gateway APIs allowed to that client. |
| `GOOGLE_GOVERNANCE_AGENT_TOKEN` | Resolves canonical agent/workload identity | Lets an attacker act as that agent identity when paired with client access. |

If both tokens are stolen, the attacker can act as that agent identity until tokens are revoked. This is credential compromise, not merely prompt injection.

Prompt injection can still cause an agent to *attempt* unsafe actions, especially when reading email, documents, web pages, or chat content. The gateway should therefore keep high-risk actions on `ask` or `deny` so model output is never treated as approval.

Recommended policy posture:

- Use strict agent-token identity; do not trust a request-body `profile` value for authorization.
- Keep write/externalizing actions on `ask` or `deny` by default.
- Require human approval for Gmail send, Drive share/delete, Calendar delete, and broad Docs/Sheets writes.
- Show approval users the exact action, route/account, target recipient/resource, and summarized payload before execution.
- Revoke and rotate both client and agent tokens after suspected exposure.
- Audit every gateway call with request ID, resolved agent identity, route/account, action, decision, and outcome.

## Recommended service boundary

- Run the gateway under a dedicated service user, default `google-workspace-gateway`.
- Keep the gateway API bound to `127.0.0.1` or an internal-only network.
- Treat the browser control plane as an admin-only surface. End users and workspace owners should request access through an administrative workflow; they should not need UI accounts or direct control-plane visibility.
- For cross-host agent deployments, do not rely on raw HTTP over a shared LAN. Use HTTPS, mTLS, SSH tunneling, WireGuard/Tailscale, or an equivalent encrypted private network so bearer tokens are not exposed in transit.
- Expose the control UI only to trusted operators.
- Put the control UI behind VPN, reverse proxy auth, or SSO if it is reachable beyond localhost.
- Keep runtime state, logs, and custody files out of Git, but inside the installed repository folder under `./.google-governance/` by default.

Default installed paths:

| Data | Path |
|---|---|
| Runtime copy | `./.google-governance/runtime` |
| State/token custody | `./.google-governance/state` |
| Secrets/setup material | `./.google-governance/config` |
| Logs | `./.google-governance/logs` |

## Secret files

Generated by the systemd installer:

| Secret | Purpose |
|---|---|
| `.google-governance/config/approval_admin_secret` | Approval/admin operation secret |
| `.google-governance/config/control_session_secret` | Control UI session signing/encryption material |
| `.google-governance/config/control_setup_token` | First-admin setup token |

Protect these with root/service-user permissions. Rotate if exposed.

## Agent authentication

Agents should authenticate to the gateway with a UI-generated client bearer token and a separate agent token. They should not receive Google refresh tokens, signing secrets, or filesystem paths to server-side custody.

Good:

```text
agent runtime -> client bearer token + agent token -> gateway -> policy -> Google API
```

Bad:

```text
agent profile -> direct filesystem read of gateway secrets or OAuth tokens -> Google API
```

The bundled MCP wrapper uses `GOOGLE_GOVERNANCE_ACCESS_TOKEN` for bridge/client authentication and `GOOGLE_GOVERNANCE_AGENT_TOKEN` for canonical agent identity. The gateway should evaluate policy against the resolved agent token identity, not a user-editable request-body `profile` field.

If both tokens are stolen, the attacker can act as that agent identity until the tokens are revoked. Keep write/externalizing actions on `ask` or `deny` so stolen tokens and prompt-injection attempts still hit approval policy instead of executing silently.

## OAuth token custody

Google OAuth credentials belong to the gateway. Connect and manage accounts through the control UI.

Security expectations:

- One Google account token can be mapped to multiple profile/account routes.
- Route mapping does not bypass policy.
- Disconnecting an account should clean up dependent routes/ACL visibility.
- Revoking a profile/account route should remove that profile's visible access surface without necessarily deleting the token.

## Policy defaults

For new deployments, start conservative:

| Action class | Suggested default |
|---|---|
| Gmail send | `ask` or `deny` |
| Gmail label/modify | `ask` |
| Calendar create/update | `ask` |
| Calendar delete | `ask` or `deny` |
| Drive share/delete | `ask` or `deny` |
| Docs/Sheets write | `ask` until narrowed |
| Read-only metadata | `allow` only after profile/route review |

Unknown profile/resource fallbacks should normally be `ask` or `deny`, not broad `allow`.

## Audit safety

Audit logs should include:

- timestamp;
- request ID;
- profile;
- route;
- action;
- resource alias;
- decision;
- status/outcome;
- hashes of sensitive IDs when useful.

Audit logs should not include:

- OAuth headers;
- refresh/access tokens;
- full email bodies;
- attachment contents;
- private document text;
- raw Google client secrets.

## Public GitHub pre-push checklist

Run from the repository root:

```bash
git status --short
git diff --check
PYTHONPYCACHEPREFIX=/tmp/google-gov-pycache python3 -m py_compile scripts/*.py
python3 scripts/test_control_plane.py
python3 scripts/test_approval_workflow.py
python3 scripts/test_governed_mcp.py
```

Manual review:

- [ ] README explains what the project does and how it differs from generic Google MCP servers.
- [ ] SETUP covers fresh clone, systemd install, OAuth, route mapping, ACLs, MCP config, verification, update commands.
- [ ] ARCHITECTURE explains gateway/client + agent-token auth, route model, token custody, policy model, approvals, observability.
- [ ] Example YAML does not contain private production secrets.
- [ ] No `.bak`, `__pycache__`, `.pyc`, SQLite, JSONL, logs, `.env`, token, or client-secret files are staged.
- [ ] Default docs do not mention private hostnames, private emails, or local-only deployment history unless they are sanitized examples.

## Incident response

If a token or secret is exposed:

1. Revoke the Google OAuth token from the Google account/security console.
2. Rotate the relevant gateway secret file.
3. Restart affected services.
4. Review audit logs for unexpected use.
5. Remove the leaked artifact from Git history if it was committed.
