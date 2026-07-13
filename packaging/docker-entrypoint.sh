#!/usr/bin/env bash
set -euo pipefail

mkdir -p /data/policy /data/approvals /data/logs /data/control /data/tokens/accounts /app/config/generated

secret_file() {
  local path="$1" bytes="${2:-48}"
  if [[ ! -s "$path" ]]; then
    mkdir -p "$(dirname "$path")"
    python3 - "$bytes" <<'PY' > "$path"
import secrets, sys
print(secrets.token_urlsafe(int(sys.argv[1])))
PY
    chmod 0600 "$path" || true
  fi
}

secret_file "${GOOGLE_GOVERNANCE_APPROVAL_ADMIN_SECRET_PATH}" 48
secret_file "${GOOGLE_GOVERNANCE_CONTROL_SESSION_SECRET_PATH}" 64
secret_file "${GOOGLE_GOVERNANCE_CONTROL_SETUP_TOKEN_PATH}" 40

if [[ ! -s "${GOOGLE_GOVERNANCE_RUNTIME_POLICY_JSON}" ]]; then
  cp /app/config/generated/profile_policy.json "${GOOGLE_GOVERNANCE_RUNTIME_POLICY_JSON}"
fi

if [[ ! -s "${GOOGLE_GOVERNANCE_CONTROL_USERS_DB_PATH:-/data/control/control_users.sqlite}" && ! -s "${GOOGLE_GOVERNANCE_CONTROL_USERS_JSON_PATH:-${GOOGLE_GOVERNANCE_CONTROL_USERS_PATH:-/data/control/control_users.json}}" ]]; then
  echo "First-run setup required. Use the control UI with setup token from: ${GOOGLE_GOVERNANCE_CONTROL_SETUP_TOKEN_PATH}" >&2
fi

python /app/unified_google_gateway.py &
gateway_pid=$!

for _ in $(seq 1 60); do
  python - <<'PY' >/dev/null 2>&1 && break || true
import urllib.request
urllib.request.urlopen('http://127.0.0.1:8768/healthz', timeout=1).read()
PY
  sleep 1
done

python /app/google_governance_control_plane.py &
control_pid=$!

term() {
  kill "$control_pid" "$gateway_pid" 2>/dev/null || true
  wait "$control_pid" "$gateway_pid" 2>/dev/null || true
}
trap term TERM INT
wait -n "$gateway_pid" "$control_pid"
term
