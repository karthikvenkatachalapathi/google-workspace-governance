FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1     PYTHONUNBUFFERED=1     GOOGLE_GOVERNANCE_HOST=127.0.0.1     GOOGLE_GOVERNANCE_PORT=8768     GOOGLE_GOVERNANCE_CONTROL_HOST=0.0.0.0     GOOGLE_GOVERNANCE_CONTROL_PORT=8095     GOOGLE_GOVERNANCE_PROJECT_DIR=/app/config     GOOGLE_GOVERNANCE_RUNTIME_POLICY_JSON=/data/policy/profile_policy.json     GOOGLE_GOVERNANCE_GENERATED_POLICY_JSON=/app/config/generated/profile_policy.json     GOOGLE_GOVERNANCE_APPROVAL_STORE=/data/approvals/approval-events.jsonl     GOOGLE_GOVERNANCE_AUDIT_LOG=/data/logs/gateway-audit.jsonl     GOOGLE_GOVERNANCE_CONTROL_AUDIT_LOG=/data/logs/control-audit.jsonl     GOOGLE_GOVERNANCE_GATEWAY_AUDIT_LOG=/data/logs/gateway-audit.jsonl     GOOGLE_GOVERNANCE_CONTROL_USERS_DB_PATH=/data/control/control_users.sqlite     GOOGLE_GOVERNANCE_TOKEN_DB_PATH=/data/control/control_users.sqlite     GOOGLE_GOVERNANCE_ACCOUNT_TOKEN_ROOT=/data/tokens/accounts     GOOGLE_GOVERNANCE_TOKEN_ROOT=/data/tokens/accounts     GOOGLE_GOVERNANCE_OAUTH_STATE_ROOT=/data/oauth     GOOGLE_GOVERNANCE_APPROVAL_ADMIN_SECRET_PATH=/run/secrets/google_governance_approval_admin_secret     GOOGLE_GOVERNANCE_CONTROL_SESSION_SECRET_PATH=/run/secrets/google_governance_control_session_secret     GOOGLE_GOVERNANCE_CONTROL_SETUP_TOKEN_PATH=/run/secrets/google_governance_control_setup_token

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt
COPY scripts/unified_google_gateway.py scripts/google_governance_control_plane.py scripts/governance_policy.py /app/
COPY google-governance-policy.yaml google-resource-registry.yaml /app/config/
COPY generated/profile_policy.json /app/config/generated/profile_policy.json
COPY generated/ui/control-plane/google-agent-gateway-logo.jpg /app/config/generated/ui/control-plane/google-agent-gateway-logo.jpg
COPY packaging/docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh
VOLUME ["/data"]
EXPOSE 8095
ENTRYPOINT ["/app/docker-entrypoint.sh"]
