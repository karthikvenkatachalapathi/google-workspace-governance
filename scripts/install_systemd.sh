#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PROJECT_DIR="$(cd "${PROJECT_DIR}" && pwd)"
# The install root is clone-root-relative. If a user clones this repo into
# /opt/governance, /srv/governance, or any other directory, every runtime file
# stays inside that root except the unavoidable systemd unit registration files
# under /etc/systemd/system.
INSTALL_DIR="${INSTALL_DIR:-${PROJECT_DIR}}"
INSTALL_DIR="$(mkdir -p "${INSTALL_DIR}" && cd "${INSTALL_DIR}" && pwd)"
SELF_CONTAINED_DIR="${SELF_CONTAINED_DIR:-${INSTALL_DIR}/.google-governance}"
RUNTIME_DIR="${RUNTIME_DIR:-${SELF_CONTAINED_DIR}/runtime}"
STATE_DIR="${STATE_DIR:-${SELF_CONTAINED_DIR}/state}"
CONFIG_DIR="${CONFIG_DIR:-${SELF_CONTAINED_DIR}/config}"
LOG_DIR="${LOG_DIR:-${SELF_CONTAINED_DIR}/logs}"
DB_DIR="${DB_DIR:-${INSTALL_DIR}/database}"
CONTROL_DB="${CONTROL_DB:-${DB_DIR}/control.sqlite}"
SERVICE_USER="${SERVICE_USER:-google-workspace-gateway}"
SERVICE_GROUP="${SERVICE_GROUP:-google-workspace-gateway}"
GATEWAY_SERVICE="${GATEWAY_SERVICE:-google-workspace-governance.service}"
CONTROL_SERVICE="${CONTROL_SERVICE:-google-workspace-governance-control.service}"
MCP_SERVICE="${MCP_SERVICE:-google-workspace-governance-mcp.service}"
CONTROL_HOST="${GOOGLE_GOVERNANCE_CONTROL_HOST:-0.0.0.0}"
CONTROL_PORT="${GOOGLE_GOVERNANCE_CONTROL_PORT:-8095}"
GATEWAY_PORT="${GOOGLE_GOVERNANCE_PORT:-8768}"
MCP_HOST="${GOOGLE_GOVERNANCE_MCP_HOST:-127.0.0.1}"
MCP_PORT="${GOOGLE_GOVERNANCE_MCP_PORT:-8769}"
MCP_PATH="${GOOGLE_GOVERNANCE_MCP_PATH:-/mcp}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run as root once for systemd registration: sudo PROJECT_DIR=\"${PROJECT_DIR}\" bash $0" >&2
  exit 1
fi

if ! getent group "${SERVICE_GROUP}" >/dev/null 2>&1; then
  groupadd --system "${SERVICE_GROUP}"
fi
if ! id -u "${SERVICE_USER}" >/dev/null 2>&1; then
  useradd --system --gid "${SERVICE_GROUP}" --home "${STATE_DIR}" --shell /usr/sbin/nologin "${SERVICE_USER}"
fi

install -d -m 0755 -o root -g root "${SELF_CONTAINED_DIR}"
install -d -m 0755 -o root -g root "${RUNTIME_DIR}" "${RUNTIME_DIR}/bin"
install -d -m 0750 -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" \
  "${STATE_DIR}" "${STATE_DIR}/policy" "${STATE_DIR}/approvals" "${STATE_DIR}/control" \
  "${STATE_DIR}/tokens/accounts" "${STATE_DIR}/oauth" "${STATE_DIR}/backups" "${LOG_DIR}" "${DB_DIR}"
install -d -m 0750 -o root -g "${SERVICE_GROUP}" "${CONFIG_DIR}"

install -m 0644 -o root -g root "${PROJECT_DIR}/scripts/unified_google_gateway.py" "${RUNTIME_DIR}/unified_google_gateway.py"
install -m 0644 -o root -g root "${PROJECT_DIR}/scripts/google_governance_control_plane.py" "${RUNTIME_DIR}/google_governance_control_plane.py"
install -m 0644 -o root -g root "${PROJECT_DIR}/scripts/governance_policy.py" "${RUNTIME_DIR}/governance_policy.py"
install -m 0644 -o root -g root "${PROJECT_DIR}/scripts/governed_google_mcp.py" "${RUNTIME_DIR}/governed_google_mcp.py"
install -m 0755 -o root -g root "${PROJECT_DIR}/scripts/google_governance_approval_cli.py" "${RUNTIME_DIR}/google_governance_approval_cli.py"
seed_state_file(){
  local src="$1" dest="$2" mode="$3"
  if [[ ! -e "$dest" ]]; then
    install -m "$mode" -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "$src" "$dest"
  else
    chown "${SERVICE_USER}:${SERVICE_GROUP}" "$dest"
    chmod "$mode" "$dest"
  fi
}
# YAML policy/registry artifacts are intentionally not installed; runtime uses SQLite + profile_policy.json.
seed_state_file "${PROJECT_DIR}/generated/profile_policy.json" "${STATE_DIR}/policy/profile_policy.json" 0640
seed_state_file "${PROJECT_DIR}/generated/profile_policy.json" "${STATE_DIR}/policy/generated_profile_policy.json" 0640

python3 -m venv "${SELF_CONTAINED_DIR}/venv"
"${SELF_CONTAINED_DIR}/venv/bin/pip" install --upgrade pip wheel >/dev/null
"${SELF_CONTAINED_DIR}/venv/bin/pip" install -r "${PROJECT_DIR}/requirements.txt"

make_secret(){
  local path="$1" bytes="$2" owner_group="$3" mode="$4"
  if [[ ! -s "$path" ]]; then
    umask 077
    python3 - "$bytes" <<'PY' > "$path"
import secrets, sys
print(secrets.token_urlsafe(int(sys.argv[1])))
PY
  fi
  chown "$owner_group" "$path"
  chmod "$mode" "$path"
}
make_secret "${CONFIG_DIR}/approval_admin_secret" 48 "root:${SERVICE_GROUP}" 0640
make_secret "${CONFIG_DIR}/control_session_secret" 64 "root:${SERVICE_GROUP}" 0640
make_secret "${CONFIG_DIR}/control_setup_token" 40 "root:${SERVICE_GROUP}" 0640

cat > "${RUNTIME_DIR}/bin/run-gateway.sh" <<EOF_RUN
#!/usr/bin/env bash
set -euo pipefail
exec "${SELF_CONTAINED_DIR}/venv/bin/python" "${RUNTIME_DIR}/unified_google_gateway.py"
EOF_RUN
chmod 0755 "${RUNTIME_DIR}/bin/run-gateway.sh"

cat > "${RUNTIME_DIR}/bin/run-mcp.sh" <<EOF_RUN
#!/usr/bin/env bash
set -euo pipefail
exec "${SELF_CONTAINED_DIR}/venv/bin/python" "${RUNTIME_DIR}/governed_google_mcp.py"
EOF_RUN
chmod 0755 "${RUNTIME_DIR}/bin/run-mcp.sh"

cat > "/etc/systemd/system/${GATEWAY_SERVICE}" <<EOF_UNIT
[Unit]
Description=Google Workspace Governance Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${STATE_DIR}
Environment=GOOGLE_GOVERNANCE_HOST=127.0.0.1
Environment=GOOGLE_GOVERNANCE_PORT=${GATEWAY_PORT}
Environment=GOOGLE_GOVERNANCE_PROJECT_DIR=${INSTALL_DIR}
Environment=GOOGLE_GOVERNANCE_SELF_CONTAINED_DIR=${SELF_CONTAINED_DIR}
Environment=GOOGLE_GOVERNANCE_STATE_DIR=${STATE_DIR}
Environment=GOOGLE_GOVERNANCE_CONFIG_DIR=${CONFIG_DIR}
Environment=GOOGLE_GOVERNANCE_LOG_DIR=${LOG_DIR}
Environment=GOOGLE_GOVERNANCE_RUNTIME_DIR=${RUNTIME_DIR}
Environment=GOOGLE_GOVERNANCE_ACCOUNT_TOKEN_ROOT=${STATE_DIR}/tokens/accounts
Environment=GOOGLE_GOVERNANCE_TOKEN_ROOT=${STATE_DIR}/tokens/accounts
Environment=GOOGLE_GOVERNANCE_TOKEN_DB_PATH=${CONTROL_DB}
Environment=GOOGLE_GOVERNANCE_DB_BACKEND=${GOOGLE_GOVERNANCE_DB_BACKEND:-sqlite}
Environment=GOOGLE_GOVERNANCE_DATABASE_URL=${GOOGLE_GOVERNANCE_DATABASE_URL:-}
Environment=GOOGLE_GOVERNANCE_POLICY_JSON=${STATE_DIR}/policy/profile_policy.json
Environment=GOOGLE_GOVERNANCE_AUDIT_LOG=${LOG_DIR}/gateway-audit.jsonl
Environment=GOOGLE_GOVERNANCE_APPROVAL_STORE=${STATE_DIR}/approvals/approval-events.jsonl
Environment=GOOGLE_GOVERNANCE_APPROVAL_ADMIN_SECRET_PATH=${CONFIG_DIR}/approval_admin_secret
Environment=GOOGLE_GOVERNANCE_AGENT_TOKEN_MODE=strict
ExecStart=${RUNTIME_DIR}/bin/run-gateway.sh
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${SELF_CONTAINED_DIR} ${DB_DIR}
ReadOnlyPaths=${INSTALL_DIR}
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF_UNIT

cat > "/etc/systemd/system/${MCP_SERVICE}" <<EOF_UNIT
[Unit]
Description=Google Workspace Governance Remote MCP Server
After=network-online.target ${GATEWAY_SERVICE}
Wants=network-online.target
Requires=${GATEWAY_SERVICE}

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${RUNTIME_DIR}
Environment=GOOGLE_GOVERNANCE_MCP_TRANSPORT=streamable-http
Environment=GOOGLE_GOVERNANCE_MCP_HOST=${MCP_HOST}
Environment=GOOGLE_GOVERNANCE_MCP_PORT=${MCP_PORT}
Environment=GOOGLE_GOVERNANCE_MCP_PATH=${MCP_PATH}
Environment=GOOGLE_GOVERNANCE_MCP_URL=http://${MCP_HOST}:${MCP_PORT}${MCP_PATH}
Environment=GOOGLE_GOVERNANCE_URL=http://127.0.0.1:${GATEWAY_PORT}
Environment=GOOGLE_GOVERNANCE_TOKEN_DB_PATH=${CONTROL_DB}
Environment=GOOGLE_GOVERNANCE_DB_BACKEND=${GOOGLE_GOVERNANCE_DB_BACKEND:-sqlite}
Environment=GOOGLE_GOVERNANCE_DATABASE_URL=${GOOGLE_GOVERNANCE_DATABASE_URL:-}
Environment=GOOGLE_GOVERNANCE_LOG_DIR=${LOG_DIR}
ExecStart=${RUNTIME_DIR}/bin/run-mcp.sh
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${SELF_CONTAINED_DIR} ${DB_DIR}
ReadOnlyPaths=${INSTALL_DIR}
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF_UNIT

cat > "/etc/systemd/system/${CONTROL_SERVICE}" <<EOF_UNIT
[Unit]
Description=Google Workspace Governance Control UI
After=network-online.target ${GATEWAY_SERVICE}
Wants=network-online.target
Requires=${GATEWAY_SERVICE}

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_GROUP}
WorkingDirectory=${RUNTIME_DIR}
Environment=GOOGLE_GOVERNANCE_PROJECT_DIR=${INSTALL_DIR}
Environment=GOOGLE_GOVERNANCE_SELF_CONTAINED_DIR=${SELF_CONTAINED_DIR}
Environment=GOOGLE_GOVERNANCE_STATE_DIR=${STATE_DIR}
Environment=GOOGLE_GOVERNANCE_CONFIG_DIR=${CONFIG_DIR}
Environment=GOOGLE_GOVERNANCE_LOG_DIR=${LOG_DIR}
Environment=GOOGLE_GOVERNANCE_RUNTIME_DIR=${RUNTIME_DIR}
# Legacy YAML paths intentionally omitted; runtime policy is JSON/SQLite-backed.
Environment=GOOGLE_GOVERNANCE_GENERATED_POLICY_JSON=${STATE_DIR}/policy/generated_profile_policy.json
Environment=GOOGLE_GOVERNANCE_RUNTIME_POLICY_JSON=${STATE_DIR}/policy/profile_policy.json
Environment=GOOGLE_GOVERNANCE_PRIVILEGED_APPLY_CMD=
Environment=GOOGLE_GOVERNANCE_CONTROL_HOST=${CONTROL_HOST}
Environment=GOOGLE_GOVERNANCE_CONTROL_PORT=${CONTROL_PORT}
Environment=GOOGLE_GOVERNANCE_CONTROL_AUTH_DISABLED=0
Environment=GOOGLE_GOVERNANCE_URL=http://127.0.0.1:${GATEWAY_PORT}
Environment=GOOGLE_GOVERNANCE_APPROVAL_ADMIN_SECRET_PATH=${CONFIG_DIR}/approval_admin_secret
Environment=GOOGLE_GOVERNANCE_CONTROL_USERS_DB_PATH=${CONTROL_DB}
Environment=GOOGLE_GOVERNANCE_TOKEN_DB_PATH=${CONTROL_DB}
Environment=GOOGLE_GOVERNANCE_DB_BACKEND=${GOOGLE_GOVERNANCE_DB_BACKEND:-sqlite}
Environment=GOOGLE_GOVERNANCE_DATABASE_URL=${GOOGLE_GOVERNANCE_DATABASE_URL:-}
Environment=GOOGLE_GOVERNANCE_CONTROL_AUDIT_LOG=${LOG_DIR}/control-audit.jsonl
Environment=GOOGLE_GOVERNANCE_GATEWAY_AUDIT_LOG=${LOG_DIR}/gateway-audit.jsonl
Environment=GOOGLE_GOVERNANCE_TOKEN_ROOT=${STATE_DIR}/tokens/accounts
Environment=GOOGLE_GOVERNANCE_ACCOUNT_TOKEN_ROOT=${STATE_DIR}/tokens/accounts
Environment=GOOGLE_GOVERNANCE_OAUTH_STATE_ROOT=${STATE_DIR}/oauth
Environment=GOOGLE_GOVERNANCE_RUNTIME_BACKUP_ROOT=${STATE_DIR}/backups
Environment=GOOGLE_GOVERNANCE_RUNTIME_BACKUP_CRON_PATH=${STATE_DIR}/backups/runtime-backup.cron
Environment=GOOGLE_GOVERNANCE_CONTROL_SESSION_SECRET_PATH=${CONFIG_DIR}/control_session_secret
Environment=GOOGLE_GOVERNANCE_CONTROL_SETUP_TOKEN_PATH=${CONFIG_DIR}/control_setup_token
Environment=GOOGLE_GOVERNANCE_INSTALLED_CONTROL_SOURCE=${RUNTIME_DIR}/google_governance_control_plane.py
ExecStart=${SELF_CONTAINED_DIR}/venv/bin/python ${RUNTIME_DIR}/google_governance_control_plane.py
Restart=always
RestartSec=5
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=${SELF_CONTAINED_DIR} ${DB_DIR}
ReadOnlyPaths=${INSTALL_DIR}
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF_UNIT

PYTHONPYCACHEPREFIX=${SELF_CONTAINED_DIR}/pycache "${SELF_CONTAINED_DIR}/venv/bin/python" -m py_compile \
  "${RUNTIME_DIR}/unified_google_gateway.py" "${RUNTIME_DIR}/governance_policy.py" \
  "${RUNTIME_DIR}/google_governance_control_plane.py" "${RUNTIME_DIR}/governed_google_mcp.py" \
  "${RUNTIME_DIR}/google_governance_approval_cli.py"

# Remove stale local override from earlier dual-mode compatibility installs; the unit now
# carries the strict default directly so old drop-ins must not silently override it.
rm -f "/etc/systemd/system/${GATEWAY_SERVICE}.d/40-agent-token-dual-mode.conf"
systemctl daemon-reload
wait_health() {
  local port="$1" name="$2"
  for _ in $(seq 1 30); do
    curl -fsS "http://127.0.0.1:${port}/healthz" >/dev/null 2>&1 && return 0
    sleep 1
  done
  systemctl status "${name}" --no-pager -l >&2 || true
  journalctl -u "${name}" -n 80 --no-pager -l >&2 || true
  return 1
}
systemctl enable --now "${GATEWAY_SERVICE}" "${MCP_SERVICE}" "${CONTROL_SERVICE}"
wait_health "${GATEWAY_PORT}" "${GATEWAY_SERVICE}"
wait_health "${CONTROL_PORT}" "${CONTROL_SERVICE}"

echo "Installed self-contained runtime under: ${SELF_CONTAINED_DIR}"
echo "Control UI: http://${CONTROL_HOST}:${CONTROL_PORT}/"
echo "Remote MCP endpoint: http://${MCP_HOST}:${MCP_PORT}${MCP_PATH}"
echo "First-run setup token: sudo cat ${CONFIG_DIR}/control_setup_token"
echo "Create API tokens from the Control UI: Runtime → Status & actions → Gateway API tokens."
echo "Store generated tokens in Agent Vault; clients should connect to the MCP endpoint by URL, not by a local wrapper path."
