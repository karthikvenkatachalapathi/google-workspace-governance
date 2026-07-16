# Setup guide

This guide is written for a fresh clone on a Linux machine. It covers native systemd installation, Google OAuth setup, route mapping, agent/MCP integration, verification, and update commands.

## Prerequisites

- Linux host with systemd.
- Python 3.11+ and `python3-venv` available.
- `curl`, `bash`, and root/sudo access for service installation.
- A Google Cloud project where you can create an OAuth Desktop App client.
- Workspace APIs enabled for the services you want to use, for example Gmail, Calendar, Drive, Docs, Sheets, Slides, and People/Contacts.

The installer creates a dedicated service user by default:

```text
google-workspace-gateway
```

The gateway API and control UI bind to localhost by default. Keep the gateway API private.

For same-host agents, use loopback HTTP:

```text
http://127.0.0.1:<gateway-port>/mcp
```

If the agent/MCP host runs on a different machine than the gateway, treat raw HTTP as a development-only transport. Do **not** configure cross-host clients with:

```text
http://<gateway-lan-ip>:<gateway-port>/mcp
```

Use one of these production patterns instead:

- `https://<domain-or-private-dns>/mcp` through a reverse proxy with strict firewall rules.
- SSH tunnel from the agent host to the gateway host.
- WireGuard, Tailscale, or another encrypted private overlay.
- mTLS between the agent host and gateway host.

For reverse-proxy installs, block direct access to the raw gateway IP/port so clients cannot bypass TLS. Do not log authorization headers or gateway/agent token values.

## 1. Clone the repository

```bash
git clone <repo-url> google-workspace-governance-gateway
cd google-workspace-governance-gateway
```

The repository no longer ships editable YAML policy seeds. The installer creates SQLite-backed state and runtime JSON policy under `.google-governance/`; routine configuration happens through the admin-only web UI after installation.

## 2. Install natively with systemd

```bash
sudo PROJECT_DIR="$PWD" bash scripts/install_systemd.sh
```

Default paths are self-contained inside the clone:

| Item | Default |
|---|---|
| State and token custody | `./.google-governance/state` |
| SQLite DB | `./database/control.sqlite` |
| Secrets/setup material | `./.google-governance/config` |
| Logs | `./.google-governance/logs` |
| Gateway API | `http://127.0.0.1:8768` |
| Control UI | `http://127.0.0.1:8095` |
| Gateway service | `google-workspace-governance.service` |
| Control UI service | `google-workspace-governance-control.service` |
| Service user | `google-workspace-gateway` |

The only host-level artifacts created by the native installer are the two systemd unit files and the dedicated service user/group. Normal operation, OAuth custody, runtime policy, logs, backups, and UI state stay under the clone root (`./.google-governance/` plus `./database/`).

Optional install overrides:

```bash
sudo PROJECT_DIR="$PWD" \
  SELF_CONTAINED_DIR="$PWD/.google-governance" \
  SERVICE_USER=google-workspace-gateway \
  GOOGLE_GOVERNANCE_CONTROL_HOST=127.0.0.1 \
  GOOGLE_GOVERNANCE_CONTROL_PORT=8095 \
  GOOGLE_GOVERNANCE_PORT=8768 \
  bash scripts/install_systemd.sh
```

Verify services:

```bash
sudo bash scripts/verify_systemd.sh
curl -fsS http://127.0.0.1:8768/healthz
curl -fsS http://127.0.0.1:8095/healthz
```

## 3. Create the first control-plane admin

Open:

```text
http://localhost:8095/
```

Get the first-run setup token:

```bash
sudo cat .google-governance/config/control_setup_token
```

Use that token in the browser UI to create the first admin user. After this, routine operations happen through the UI.

## 4. Create a Google OAuth Desktop App

In Google Cloud Console:

1. Create or choose a project.
2. Configure the OAuth consent screen.
3. Enable the Google APIs you want to govern:
   - Gmail API
   - Google Calendar API
   - Google Drive API
   - Google Docs API
   - Google Sheets API
   - Google Slides API
   - People API / Contacts access
4. Create OAuth credentials of type **Desktop App**.
5. Download the `client_secret.json` file.

Do not commit this file. The control UI lets you upload or paste it for the OAuth flow.

## 5. Connect Google Workspace accounts in the admin UI

The control UI is admin-only. Users or teams should submit the Workspace account details and requested agent/workload access to an administrator; they should not need a gateway UI account.

In the control UI:

1. Go to **Admin settings → Google Workspace → Configure new workspace**.
2. Upload or paste the Google OAuth Desktop App `client_secret.json`.
3. Give the account a human-friendly token label, for example `workspace-primary` or `workspace-shared`.
4. Generate the authorization URL.
5. Complete Google consent.
6. Paste the redirect URL or authorization code back into the UI.

The gateway requests Workspace scopes plus identity scopes (`openid`, `email`, `profile`) so it can display the account email where Google provides it.

The OAuth refresh token is stored in gateway-owned state, not in the agent profile.

For multi-tenant deployments, repeat this connection flow per tenant-owned workspace/account and use clear account aliases. A tenant can share the same gateway runtime with other tenants while keeping OAuth custody, account aliases, route mappings, approvals, policy decisions, and audit records separated by resolved agent identity and route.

## 6. Create agent identities and map account routes

Open **Admin settings → Google Workspace → Configure Agent Identity** to create or select the agent/workload identity, then open **Configure Agent-Workspace Route**.

Map real agent profile slugs to connected Google accounts. Route format:

```text
<profile>/<account-alias>
```

Examples:

```text
agent-a/workspace-primary
agent-a/business-agent-b
agent-c/workspace-primary
agent-b/workspace-shared
support-bot/workspace-primary
```

A profile can have multiple routes. This is useful when one agent needs access to both a personal account and a business account, but with separate policy boundaries.

Connecting an account does not mean broad access. Admin-assigned ACL policy still decides what each profile/account route may do. For larger deployments, use repeated ACL patterns as proto-templates and promote them into group/policy-template automation when the same access bundles recur across many agents.

## 7. Configure ACL policy in the UI

Open **ACL rules**.

Each row represents a profile/action/service or profile/resource/action decision. Set the decision to:

- `allow` — execute without approval.
- `ask` — create or require an approval path.
- `deny` — block.

Recommended defaults for a new deployment:

| Operation type | Starting decision |
|---|---|
| Read-only Calendar/Drive metadata | `allow` or `ask` depending on sensitivity |
| Gmail search/get | `ask` until reviewed |
| Gmail draft creation | `ask` |
| Gmail send | `ask` or `deny` |
| Drive share/delete | `ask` or `deny` |
| Calendar create/update | `ask` |
| Calendar delete | `ask` or `deny` |
| Sheets read/update | `ask`, then narrow by route/resource |

Use the UI's save/bulk-apply controls. They validate the change, update backing policy, write runtime policy, and audit the event.

## 8. Configure an MCP host

The MCP wrapper is copied into the self-contained runtime directory after install:

```text
.google-governance/runtime/governed_google_mcp.py
```

Clients must connect over the gateway API. They should not read local OAuth files, signing secrets, or any server-side custody path.

Example MCP configuration:

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

Environment variables:

| Variable | Meaning |
|---|---|
| `GOOGLE_GOVERNANCE_URL` | Gateway API URL, usually `http://127.0.0.1:8768` |
| `GOOGLE_GOVERNANCE_PROFILE` | Calling gateway agent identity, e.g. `agent-a` |
| `GOOGLE_GOVERNANCE_TOKEN_ROUTE` | Optional default route, e.g. `agent-a/workspace-primary` |
| `GOOGLE_GOVERNANCE_ACCESS_TOKEN` | API bearer token generated in **Admin settings → Runtime**; authenticates the MCP bridge/client |
| `GOOGLE_GOVERNANCE_AGENT_TOKEN` | Agent token generated for this profile/agent; identifies the workload on whose behalf requests run |

Each MCP tool also accepts a `token_route` argument. Use it when a profile has more than one mapped Google account route.

## 9. How agent authentication works

The MCP wrapper sends two credentials generated by the control UI:

```text
Authorization: Bearer $GOOGLE_GOVERNANCE_ACCESS_TOKEN
X-Google-Governance-Agent-Token: $GOOGLE_GOVERNANCE_AGENT_TOKEN
```

The gateway validates both token hashes stored in its SQLite state before evaluating policy or using Google OAuth credentials. The access token authenticates the bridge/client. The agent token resolves the canonical profile/agent identity used for ACL and audit attribution. A request body cannot self-declare a different profile than the agent token resolves to.

Important boundaries:

- Agents receive only a gateway client token plus their own agent token, not Google OAuth refresh tokens or signing secrets.
- Agents do not need filesystem access to the installed repository, state directory, config directory, or token custody files.
- Policy is evaluated by the gateway, not by the model prompt.
- OAuth custody stays with the gateway.

## 10. Approval-required operations

High-risk MCP tools are intentionally guarded. Examples include:

- `google_gmail_send_draft`
- `google_calendar_delete`
- `google_drive_share`
- `google_drive_delete`

Without an approval ID, these return a structured approval-required response. After an operator approves, the caller can execute with the approval ID through the gateway.

Approval secrets are generated under:

```text
.google-governance/config/approval_admin_secret
```

Do not commit or expose this secret.

## 11. Verify before real use

Run offline checks from the repository clone:

```bash
PYTHONPYCACHEPREFIX=/tmp/google-gov-pycache python3 -m py_compile scripts/*.py
python3 scripts/test_control_plane.py
python3 scripts/test_approval_workflow.py
python3 scripts/test_governed_mcp.py
```

Run service checks on the installed host:

```bash
sudo systemctl status google-workspace-governance.service google-workspace-governance-control.service --no-pager -l
curl -fsS http://127.0.0.1:8768/healthz
curl -fsS http://127.0.0.1:8095/healthz
```

## 12. Update an existing install from source

After pulling or editing source in the clone:

```bash
sudo PROJECT_DIR="$PWD" bash scripts/install_systemd.sh
sudo systemctl restart google-workspace-governance.service google-workspace-governance-control.service
curl -fsS http://127.0.0.1:8768/healthz
curl -fsS http://127.0.0.1:8095/healthz
```

If you only changed the control UI:

```bash
sudo PROJECT_DIR="$PWD" bash scripts/install_systemd.sh
sudo systemctl restart google-workspace-governance-control.service
curl -fsS http://127.0.0.1:8095/healthz
```

## 13. Optional Postgres migration and operator cutover

SQLite is the default and remains appropriate for a single-node or same-host gateway. Migrate to Postgres before running active-active gateway instances, multi-host high availability, or any deployment where multiple gateway/control workers need shared transactional state.

The control UI includes a migration helper under:

```text
Admin settings → Runtime → Backups → Postgres migration
```

This helper is deliberately conservative. It does **not** silently repoint the live gateway. It:

1. reads the current SQLite control/token state,
2. creates a runtime backup before migration work,
3. generates a SQLite → Postgres SQL migration script,
4. defaults to dry-run mode, and
5. can execute the SQL against a provided Postgres DSN when the operator explicitly confirms.

### Operator prerequisites

Before executing a live cutover:

- Provision a Postgres database and dedicated least-privilege role.
- Require TLS or a private network path between the gateway host and Postgres.
- Confirm the current gateway release has default Postgres backend support available. The native installer installs the `psycopg` driver and wires `GOOGLE_GOVERNANCE_DB_BACKEND=sqlite` plus an optional blank `GOOGLE_GOVERNANCE_DATABASE_URL` into the gateway, MCP, and control services, so SQLite stays active until an operator deliberately switches the backend.
- Schedule a short maintenance window. The migration copy is safe, but cutover should be treated as a controlled state transition.
- Keep the UI/API as the source of truth. Do not hand-edit generated YAML as part of the migration; direct YAML edits are recovery material and may be overwritten by the UI.

### Recommended migration flow

1. **Plan in the UI**

   Open **Runtime → Backups → Postgres migration**, enter the Postgres DSN, and click **Plan migration**. Review the table list and row counts. The UI redacts DSN passwords in displayed results.

2. **Run a dry run**

   Leave **Dry run** enabled and click **Run migration pipeline**. This creates:

   - a normal runtime backup archive, and
   - a generated SQL migration script.

   Review both paths in the UI result. Keep the backup until the Postgres-backed gateway has been stable long enough to satisfy your rollback policy.

3. **Drain gateway traffic**

   Stop or drain agent traffic before the final copy so SQLite does not receive new approvals, token changes, ACL edits, or audit-relevant writes during cutover.

   For a single native install:

   ```bash
   sudo systemctl stop google-workspace-governance.service
   ```

   Leave the control UI available only long enough to start the final migration, or run the generated SQL manually from the reviewed script. Do not make unrelated UI changes during the maintenance window.

4. **Execute the migration**

   In the UI, disable **Dry run**, type:

   ```text
   MIGRATE TO POSTGRES
   ```

   Then click **Run migration pipeline**.

   If the runtime environment does not have `psycopg` or `psycopg2`, the UI still leaves you with the backup and SQL script. In that case, apply the reviewed script with `psql` from a host that can reach Postgres:

   ```bash
   psql "$POSTGRES_DSN" -v ON_ERROR_STOP=1 -f /path/to/sqlite-to-postgres.sql
   ```

5. **Configure the services for Postgres**

   After the data is loaded, configure the gateway and control UI to use the Postgres backend. Prefer a systemd drop-in or installer-supported environment override rather than editing generated unit files by hand.

   Example drop-in:

   ```bash
   sudo systemctl edit google-workspace-governance.service
   sudo systemctl edit google-workspace-governance-control.service
   ```

   ```ini
   [Service]
   Environment=GOOGLE_GOVERNANCE_DB_BACKEND=postgres
   Environment=GOOGLE_GOVERNANCE_DATABASE_URL=postgresql://gateway_user:REDACTED@postgres-host:5432/google_governance?sslmode=require
   ```

   These are the standard backend variables. Keep the DSN in a protected systemd drop-in or environment file, never in the repo.

6. **Restart one service set and verify**

   ```bash
   sudo systemctl daemon-reload
   sudo systemctl restart google-workspace-governance-control.service
   curl -fsS http://127.0.0.1:8095/healthz

   sudo systemctl restart google-workspace-governance.service
   curl -fsS http://127.0.0.1:8768/healthz
   ```

   In the UI, verify:

   - users still appear,
   - connected workspaces still appear,
   - route mappings still appear,
   - ACL rules still appear,
   - approval channels still appear,
   - runtime validation passes, and
   - a safe read-only MCP test succeeds.

7. **Re-enable traffic**

   Re-add the gateway to the load balancer or restart client traffic only after the health checks and UI inventory checks pass.

8. **Rollback if needed**

   If verification fails, remove or disable the Postgres drop-in, restart both services back on SQLite, and use the backup archive created by the migration pipeline as the rollback anchor. Do not continue writing to both SQLite and Postgres in parallel unless the release explicitly documents dual-write support.

### Cutover rules of thumb

- For one host and one active writer, SQLite is simpler and safer.
- For multi-host or active-active load balancing, Postgres should become the runtime store before production traffic is balanced.
- Treat migration as two separate actions: **copy data to Postgres** first, then **cut over runtime storage** after verification.
- Never expose the Postgres DSN in logs, screenshots, tickets, or committed files.

## 14. Optional Docker evaluation

Docker files are included for evaluation and packaging examples. The primary documented production path is native Linux/systemd because it gives clearer host-level custody, secrets, logs, and service hardening.

If you use Docker, keep secrets and token state in mounted volumes and never bake them into an image.

## 15. Troubleshooting

### Control UI is not reachable

```bash
sudo systemctl status google-workspace-governance-control.service --no-pager -l
sudo journalctl -u google-workspace-governance-control.service -n 100 --no-pager
curl -fsS http://127.0.0.1:8095/healthz
```

### Gateway API is not reachable

```bash
sudo systemctl status google-workspace-governance.service --no-pager -l
sudo journalctl -u google-workspace-governance.service -n 100 --no-pager
curl -fsS http://127.0.0.1:8768/healthz
```

### API/auth errors

Check that:

- The MCP host has `GOOGLE_GOVERNANCE_ACCESS_TOKEN` from the control UI Runtime page.
- The profile in `GOOGLE_GOVERNANCE_PROFILE` matches a profile configured in the UI.
- The token route profile prefix matches the profile, e.g. `agent-a/workspace-primary` for `agent-a`.

### Google consent succeeds but email is missing

Make sure the OAuth flow includes `openid`, `email`, and `profile` scopes. The bundled UI does this for new connections. Older tokens may need reconnecting for display-quality email discovery.

### A profile can see the wrong account

Review **Configure Agent-Workspace Route** and the MCP host's `GOOGLE_GOVERNANCE_TOKEN_ROUTE`. A profile can have multiple routes; explicit `token_route` values are the safest way to disambiguate calls.
