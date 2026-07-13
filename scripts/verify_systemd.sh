#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PROJECT_DIR="$(cd "${PROJECT_DIR}" && pwd)"
INSTALL_DIR="${INSTALL_DIR:-${PROJECT_DIR}}"
INSTALL_DIR="$(cd "${INSTALL_DIR}" && pwd)"
SELF_CONTAINED_DIR="${SELF_CONTAINED_DIR:-${INSTALL_DIR}/.google-governance}"
LOG_DIR="${LOG_DIR:-${SELF_CONTAINED_DIR}/logs}"
GATEWAY_SERVICE="${GATEWAY_SERVICE:-google-workspace-governance.service}"
CONTROL_SERVICE="${CONTROL_SERVICE:-google-workspace-governance-control.service}"
GATEWAY_PORT="${GOOGLE_GOVERNANCE_PORT:-8768}"
CONTROL_PORT="${GOOGLE_GOVERNANCE_CONTROL_PORT:-8095}"
mkdir -p "${LOG_DIR}"
wait_health() {
  local port="$1" name="$2" out="$3"
  for _ in $(seq 1 30); do
    if curl -fsS "http://127.0.0.1:${port}/healthz" | python3 -m json.tool >"${out}"; then
      return 0
    fi
    sleep 1
  done
  systemctl status "${name}" --no-pager -l >&2 || true
  journalctl -u "${name}" -n 80 --no-pager -l >&2 || true
  return 1
}
systemctl is-active --quiet "$GATEWAY_SERVICE"
systemctl is-active --quiet "$CONTROL_SERVICE"
wait_health "${GATEWAY_PORT}" "${GATEWAY_SERVICE}" "${LOG_DIR}/gateway-health.json"
wait_health "${CONTROL_PORT}" "${CONTROL_SERVICE}" "${LOG_DIR}/control-health.json"
printf 'gateway: %s\ncontrol: %s\n' "$(cat "${LOG_DIR}/gateway-health.json")" "$(cat "${LOG_DIR}/control-health.json")"
