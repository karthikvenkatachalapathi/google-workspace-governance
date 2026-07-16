# Public publishing manifest

This repository is intended to be cloneable and runnable by another operator after they add their own local Google OAuth credentials and secrets.

## Publish these files

### Documentation

- `README.md` — public project overview, differentiators, quick start, concepts, MCP example.
- `SETUP.md` — fresh-clone install guide, OAuth setup, route mapping, ACL setup, MCP integration, verification, update commands.
- `ARCHITECTURE.md` — runtime/control-plane architecture, gateway/client + agent-token auth, route model, policy model, approvals, observability.
- `SECURITY.md` — publishing and deployment safety checklist.
- `PUBLISHING_MANIFEST.md` — this checklist.

### Runtime source

- `scripts/unified_google_gateway.py`
- `scripts/google_governance_control_plane.py`
- `scripts/governance_policy.py`
- `scripts/governed_google_mcp.py`
- `scripts/google_governance_approval_cli.py`

### Install and verification

- `scripts/install_systemd.sh`
- `scripts/verify_systemd.sh`
- `scripts/test_control_plane.py`
- `scripts/test_approval_workflow.py`
- `scripts/test_governed_mcp.py`

### Example configuration and packaging

- `.env.example`
- `.dockerignore`
- `.gitignore`
- `requirements.txt`
- `Dockerfile`
- `docker-compose.example.yml`
- `packaging/docker-entrypoint.sh`
- `generated/loki/promtail-google-workspace-governance.yml`
- `grafana/google-workspace-governance-ops-dashboard.json`
- `generated/ui/control-plane/nginx-authentik-control.example.conf`
- `generated/ui/control-plane/google-agent-gateway-logo.jpg`

## Do not publish private/local state

Do not publish or stage:

- `.env` or `.env.*` except `.env.example`.
- `.google-governance/` installed runtime/state/secrets/logs.
- `database/` runtime SQLite state.
- `secrets/`.
- `data/`.
- `backups/` and local `.tgz` / `.tar.gz` exports.
- `*.sqlite`, `*.sqlite3`, `*.db`.
- `*.jsonl`, `*.log`.
- `*.bak` local policy/registry backups.
- `__pycache__/`, `*.pyc`.
- OAuth refresh/access tokens.
- Google OAuth client-secret JSON files.
- Generated setup tokens.
- gateway client tokens, agent tokens, approval secrets, setup tokens, or session secrets.
- Audit exports, replay artifacts, or private local reports.

## Public-readiness requirements

A public clone should be able to answer:

1. What does the gateway do?
2. How is it different from a normal Google Workspace MCP server?
3. How do I install it on a new Linux machine?
4. How do I create the first admin?
5. How do I connect Google OAuth accounts?
6. How do I map multiple routes per profile?
7. How does multi-tenancy separate tenant workspaces, approval paths, policy, and audit trails?
8. How do MCP clients authenticate with gateway client tokens plus agent identity tokens?
9. How do I configure ACL decisions and approval-required operations?
10. How do I verify the install and tests?
11. What must never be committed?

The current public docs covering those are:

- `README.md`
- `SETUP.md`
- `ARCHITECTURE.md`
- `SECURITY.md`

## Verification commands

Run from the repository root before publishing:

```bash
git status --short
git diff --check
PYTHONPYCACHEPREFIX=/tmp/google-gov-pycache python3 -m py_compile scripts/*.py
python3 scripts/test_control_plane.py
python3 scripts/test_approval_workflow.py
python3 scripts/test_governed_mcp.py
```

The tests are offline/static and do not require real Google tokens.

## Suggested commit scope

A clean documentation/source publish commit should normally include only:

- source files under `scripts/`;
- public docs;
- example config;
- install/packaging examples;
- tests.

Avoid committing one-off vault notes, local backup files, or machine-specific runtime state.

Before publishing, verify local runtime state is absent from the tracked tree:

```bash
git ls-files | grep -E '(^database/|^\.google-governance/|\.sqlite$|\.sqlite3$|\.db$)' && exit 1 || true
git status --ignored --short | grep -E '!! (\.google-governance/|database/)' || true
```

The first command must print nothing. The second command may show ignored local runtime directories; ignored is expected, tracked is not.
