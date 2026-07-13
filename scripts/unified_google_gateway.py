#!/usr/bin/env python3
"""Unified Google Workspace governance gateway.

One local service accepts signed requests from configured actors, routes by
profile claims and token-route aliases, reads Google OAuth credentials from
gateway-owned custody, enforces policy decisions, and emits audit/metrics
records.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import sqlite3
import time
import uuid
from collections import Counter
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from typing import Any

from google_workspace_action_catalog import workspace_tool_action, workspace_catalog_tool_names
from urllib.parse import quote, parse_qs, urlencode, urlparse

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import requests

from governance_policy import classify, resource_for

HOST = os.getenv("GOOGLE_GOVERNANCE_HOST", "127.0.0.1")
PORT = int(os.getenv("GOOGLE_GOVERNANCE_PORT", "8768"))
PROJECT_BASE = Path(os.getenv("GOOGLE_GOVERNANCE_PROJECT_DIR", str(Path(__file__).resolve().parents[1])))
SELF_CONTAINED_BASE = Path(os.getenv("GOOGLE_GOVERNANCE_SELF_CONTAINED_DIR", str(PROJECT_BASE / ".google-governance")))
STATE_BASE = Path(os.getenv("GOOGLE_GOVERNANCE_STATE_DIR", str(SELF_CONTAINED_BASE / "state")))
CONFIG_BASE = Path(os.getenv("GOOGLE_GOVERNANCE_CONFIG_DIR", str(SELF_CONTAINED_BASE / "config")))
LOG_BASE = Path(os.getenv("GOOGLE_GOVERNANCE_LOG_DIR", str(SELF_CONTAINED_BASE / "logs")))
TOKEN_ROOT = Path(os.getenv("GOOGLE_GOVERNANCE_ACCOUNT_TOKEN_ROOT", str(STATE_BASE / "tokens/accounts")))
TOKEN_DB_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_TOKEN_DB_PATH", os.getenv("GOOGLE_GOVERNANCE_CONTROL_USERS_DB_PATH", str(STATE_BASE / "control/control_users.sqlite"))))
API_TOKEN_HASHES_ENV = "GOOGLE_GOVERNANCE_API_TOKEN_HASHES"
API_TOKENS_ENV = "GOOGLE_GOVERNANCE_API_TOKENS"  # plaintext compatibility only; prefer hashes
AUDIT_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_AUDIT_LOG", str(LOG_BASE / "gateway-audit.jsonl")))
APPROVAL_STORE_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_APPROVAL_STORE", str(STATE_BASE / "approvals/approval-events.jsonl")))
APPROVAL_ADMIN_SECRET_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_APPROVAL_ADMIN_SECRET_PATH", str(CONFIG_BASE / "approval_admin_secret")))
APPROVAL_DEFAULT_TTL_SECONDS = int(os.getenv("GOOGLE_GOVERNANCE_APPROVAL_DEFAULT_TTL_SECONDS", "900"))
APPROVAL_PUBLIC_BASE_URL = os.getenv("GOOGLE_GOVERNANCE_APPROVAL_PUBLIC_BASE_URL", "").rstrip("/")
START_TIME = time.time()
_METRIC_LOCK = Lock()
_AUDIT_TOTAL: Counter[tuple[str, str, str, str]] = Counter()
_LATENCY_SUM_MS: Counter[tuple[str, str, str, str]] = Counter()
_LATENCY_COUNT: Counter[tuple[str, str, str, str]] = Counter()

DEFAULT_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/documents",
    "https://www.googleapis.com/auth/spreadsheets",
    "https://www.googleapis.com/auth/presentations",
    "https://www.googleapis.com/auth/contacts.readonly",
]

PROFILE_CONFIG: dict[str, dict[str, Any]] = {
    "agent-a": {
        "persona": "AgentA",
        "legacy_audience": "dumbledore-google-governance-gateway",
        "unified_audience": "google-workspace-governance",
        "service_name": "dumbledore-google-governance-gateway",
        "generic_google_request": False,
    },
    "agent-c": {
        "persona": "AgentB",
        "legacy_audience": "hagrid-google-governance-gateway",
        "unified_audience": "google-workspace-governance",
        "service_name": "hagrid-google-governance-gateway",
        "generic_google_request": False,
    },
    "agent-b": {
        "persona": "AgentC",
        "legacy_audience": "hedwig-google-governance-gateway",
        "unified_audience": "google-workspace-governance",
        "service_name": "hedwig-google-governance-gateway",
        "generic_google_request": False,
    },
}

ALLOWED_HOST_PATH_PREFIXES = {
    "sheets.googleapis.com": ["/v4/spreadsheets"],
    "docs.googleapis.com": ["/v1/documents"],
    "slides.googleapis.com": ["/v1/presentations"],
    "gmail.googleapis.com": ["/gmail/v1/users/me"],
    "www.googleapis.com": ["/calendar/v3", "/drive/v3", "/upload/drive/v3"],
    "people.googleapis.com": ["/v1/people", "/v1/contactGroups"],
}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: Any) -> None:
    raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def _text_response(handler: BaseHTTPRequestHandler, status: int, body: str, content_type: str = "text/plain; charset=utf-8") -> None:
    raw = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def _prom_label(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def _metrics_text() -> str:
    with _METRIC_LOCK:
        rows = list(_AUDIT_TOTAL.items())
        latency_sum_rows = list(_LATENCY_SUM_MS.items())
        latency_count_rows = list(_LATENCY_COUNT.items())
    lines = [
        "# HELP google_workspace_governance_up Unified Google governance gateway health (1 = up).",
        "# TYPE google_workspace_governance_up gauge",
        "google_workspace_governance_up 1",
        "# HELP google_workspace_governance_start_time_seconds Unix start time of the unified Google governance gateway.",
        "# TYPE google_workspace_governance_start_time_seconds gauge",
        f"google_workspace_governance_start_time_seconds {START_TIME:.0f}",
        "# HELP google_workspace_governance_audit_events_total Audit events emitted by profile/action/status/decision.",
        "# TYPE google_workspace_governance_audit_events_total counter",
    ]
    for (profile, action, status, decision), count in sorted(rows):
        lines.append(
            'google_workspace_governance_audit_events_total{'
            f'profile="{_prom_label(profile)}",'
            f'action="{_prom_label(action)}",'
            f'status="{_prom_label(status)}",'
            f'decision="{_prom_label(decision)}"'
            f'}} {count}'
        )
    lines.extend([
        "# HELP google_workspace_governance_request_latency_ms_sum Total observed request latency in milliseconds by profile/action/status/decision.",
        "# TYPE google_workspace_governance_request_latency_ms_sum counter",
    ])
    for (profile, action, status, decision), value in sorted(latency_sum_rows):
        lines.append(
            'google_workspace_governance_request_latency_ms_sum{'
            f'profile="{_prom_label(profile)}",'
            f'action="{_prom_label(action)}",'
            f'status="{_prom_label(status)}",'
            f'decision="{_prom_label(decision)}"'
            f'}} {float(value):.3f}'
        )
    lines.extend([
        "# HELP google_workspace_governance_request_latency_ms_count Count of latency observations by profile/action/status/decision.",
        "# TYPE google_workspace_governance_request_latency_ms_count counter",
    ])
    for (profile, action, status, decision), count in sorted(latency_count_rows):
        lines.append(
            'google_workspace_governance_request_latency_ms_count{'
            f'profile="{_prom_label(profile)}",'
            f'action="{_prom_label(action)}",'
            f'status="{_prom_label(status)}",'
            f'decision="{_prom_label(decision)}"'
            f'}} {count}'
        )
    lines.append("")
    return "\n".join(lines)


SENSITIVE_PAYLOAD_KEY_TERMS = (
    "token",
    "secret",
    "authorization",
    "cookie",
    "body",
    "message",
    "raw",
    "data",
    "refresh",
    "credential",
    "headers",
    "email",
    "file_id",
    "event_id",
    "draft_id",
    "json",
    "params",
)


def _redact_value(key: str, value: Any) -> Any:
    lk = str(key).lower()
    if any(term in lk for term in SENSITIVE_PAYLOAD_KEY_TERMS):
        return "<redacted>"
    if isinstance(value, dict):
        return {str(child_key): _redact_value(str(child_key), child_value) for child_key, child_value in value.items()}
    if isinstance(value, list):
        return [_redact_value(key, item) for item in value]
    if isinstance(value, str) and len(value) > 256:
        return value[:64] + "…<truncated>"
    return value


def _redact_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {str(key): _redact_value(str(key), value) for key, value in payload.items()}


def _service_for_action(action: str) -> str:
    return action.split(".", 1)[0] if "." in action else "gateway"


def _operation_for_action(action: str) -> str:
    if "." not in action:
        return action
    suffix = action.split(".", 1)[1]
    if suffix in {"get", "list", "search", "freebusy"} or suffix.startswith("attachments"):
        return "read"
    if suffix in {"draft"}:
        return "write/draft"
    if suffix in {"send", "share", "delete"}:
        return suffix
    if suffix in {"create", "upload", "copy", "append", "update", "batch_update", "modify"}:
        return "write"
    return suffix


def _is_high_risk_action(action: str) -> bool:
    return action in {"gmail.send", "drive.share", "drive.delete", "calendar.delete"}


def _is_unknown_resource(resource_alias: str | None) -> bool:
    value = str(resource_alias or "")
    return value in {"", "unknown"} or value.endswith("_unknown") or value in {"drive_any"}


def _audit(profile: str, action: str, status: str, **fields: Any) -> None:
    resource_alias = str(fields.get("resource_alias") or "unknown")
    latency_raw = fields.get("latency_ms")
    latency_ms = None
    if isinstance(latency_raw, (int, float)):
        latency_ms = round(float(latency_raw), 3)
        fields["latency_ms"] = latency_ms
    elif latency_raw is not None:
        try:
            latency_ms = round(float(str(latency_raw)), 3)
            fields["latency_ms"] = latency_ms
        except ValueError:
            latency_ms = None
    row = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "gateway": "unified",
        "profile": profile,
        "service": str(fields.get("service") or _service_for_action(action)),
        "operation": str(fields.get("operation") or _operation_for_action(action)),
        "token_route": str(fields.get("token_route") or "default"),
        "resource_alias": resource_alias,
        "action": action,
        "decision": str(fields.get("decision") or ""),
        "status": status,
        "high_risk_action": bool(fields.get("high_risk_action", _is_high_risk_action(action))),
        "unknown_resource": bool(fields.get("unknown_resource", _is_unknown_resource(resource_alias))),
        **fields,
    }
    decision = str(row.get("decision") or "")
    metric_key = (profile, action, status, decision)
    with _METRIC_LOCK:
        _AUDIT_TOTAL[metric_key] += 1
        if latency_ms is not None:
            _LATENCY_SUM_MS[metric_key] += latency_ms
            _LATENCY_COUNT[metric_key] += 1
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with AUDIT_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")



def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64u_decode(value: str) -> bytes:
    value = str(value or "")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _approval_retry_secret() -> bytes:
    secret = _approval_admin_secret()
    if not secret:
        raise PermissionError("approval admin secret required for stored retry payload")
    return secret.encode("utf-8")


def _approval_retry_key(purpose: str) -> bytes:
    return hmac.new(_approval_retry_secret(), f"approval-retry-payload:v1:{purpose}".encode("utf-8"), hashlib.sha256).digest()


def _approval_keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hmac.new(key, nonce + counter.to_bytes(4, "big"), hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])


def _approval_xor(data: bytes, stream: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(data, stream))


def _seal_retry_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Seal a short-lived retry payload for UI-side Approve & Execute.

    The approval log remains append-only JSONL. Raw target IDs are not written;
    only this authenticated encrypted blob is stored. The key is derived from the
    approval admin secret so a copied approval store is not executable by itself.
    """
    plaintext = _canonical_json(payload).encode("utf-8")
    nonce = os.urandom(16)
    enc_key = _approval_retry_key("enc")
    mac_key = _approval_retry_key("mac")
    ciphertext = _approval_xor(plaintext, _approval_keystream(enc_key, nonce, len(plaintext)))
    tag = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    return {"v": 1, "alg": "hmac-sha256-stream", "nonce": _b64u(nonce), "ciphertext": _b64u(ciphertext), "tag": _b64u(tag)}


def _unseal_retry_payload(sealed: Any) -> dict[str, Any]:
    if not isinstance(sealed, dict):
        raise PermissionError("stored retry payload unavailable")
    if int(sealed.get("v") or 0) != 1:
        raise PermissionError("stored retry payload version unsupported")
    nonce = _b64u_decode(str(sealed.get("nonce") or ""))
    ciphertext = _b64u_decode(str(sealed.get("ciphertext") or ""))
    tag = _b64u_decode(str(sealed.get("tag") or ""))
    mac_key = _approval_retry_key("mac")
    expected = hmac.new(mac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not tag or not hmac.compare_digest(tag, expected):
        raise PermissionError("stored retry payload authentication failed")
    enc_key = _approval_retry_key("enc")
    plaintext = _approval_xor(ciphertext, _approval_keystream(enc_key, nonce, len(ciphertext)))
    value = json.loads(plaintext.decode("utf-8"))
    if not isinstance(value, dict):
        raise PermissionError("stored retry payload invalid")
    return value


def _approval_request_hash(payload: dict[str, Any]) -> str:
    """Hash approval-relevant raw payload fields without storing raw values.

    Runtime metadata changes between the initial approval request and the approved
    retry (new request_id, no explanatory reason, different client wrapper), so it
    is deliberately excluded. The binding is the actor/action/resource/target.
    """
    volatile = {"approval_id", "request_id", "reason", "client", "workflow_intent", "workflow"}
    stable = {str(k): v for k, v in payload.items() if str(k) not in volatile and not str(k).endswith("_sha256")}
    return hashlib.sha256(_canonical_json(stable).encode("utf-8")).hexdigest()


def _approval_safe_metadata(payload: dict[str, Any]) -> dict[str, Any]:
    """Operator-safe approval card metadata; never store raw email/file/event IDs."""
    safe: dict[str, Any] = {}
    passthrough = {"role", "calendar", "client", "workflow_intent", "token_route"}
    for key, value in payload.items():
        key_str = str(key)
        if key_str in passthrough or key_str.endswith("_sha256"):
            safe[key_str] = value
    for raw_key in ("email", "file_id", "event_id", "draft_id"):
        if payload.get(raw_key) and f"{raw_key}_sha256" not in safe:
            safe[f"{raw_key}_sha256"] = hashlib.sha256(str(payload[raw_key]).encode()).hexdigest()
    return safe


def _append_approval_event(event: dict[str, Any]) -> None:
    APPROVAL_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    row = {"ts": datetime.now(timezone.utc).isoformat(), **event}
    with APPROVAL_STORE_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")


def _approval_delivery_rules_enabled() -> bool:
    value = _approval_setting_value("delivery_rules_enabled", "").strip().lower()
    return value not in {"0", "false", "no", "off"}


def _approval_channel_rows(profile: str) -> list[dict[str, Any]]:
    if not _approval_delivery_rules_enabled():
        return []
    if not TOKEN_DB_PATH.exists():
        return []
    try:
        conn = sqlite3.connect(TOKEN_DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            rows = conn.execute(
                """
                SELECT id,label,chat_id,scope,profile,enabled,button_base_url,bot_token
                FROM approval_telegram_channels
                WHERE enabled=1 AND (scope='all' OR profile=? OR profile='*')
                ORDER BY scope DESC, profile, label
                """,
                (profile,),
            ).fetchall()
            result = [dict(row) for row in rows]
        except sqlite3.OperationalError:
            rows = conn.execute(
                """
                SELECT id,label,chat_id,scope,profile,enabled,button_base_url
                FROM approval_telegram_channels
                WHERE enabled=1 AND (scope='all' OR profile=? OR profile='*')
                ORDER BY scope DESC, profile, label
                """,
                (profile,),
            ).fetchall()
            result = [dict(row) | {"bot_token": ""} for row in rows]
        conn.close()
        return result
    except sqlite3.Error:
        return []


def _approval_setting_value(key: str, env_name: str = "") -> str:
    value = ""
    if TOKEN_DB_PATH.exists():
        try:
            conn = sqlite3.connect(TOKEN_DB_PATH)
            row = conn.execute("SELECT value FROM approval_telegram_settings WHERE key=?", (key,)).fetchone()
            conn.close()
            if row and row[0]:
                value = str(row[0]).strip()
        except sqlite3.Error:
            value = ""
    if not value and env_name:
        value = os.getenv(env_name, "").strip()
    return value


def _approval_public_base_url() -> str:
    return _approval_setting_value("public_base_url", "GOOGLE_GOVERNANCE_APPROVAL_PUBLIC_BASE_URL").rstrip("/")


def _approval_telegram_bot_token() -> str:
    return _approval_setting_value("bot_token", "GOOGLE_GOVERNANCE_TELEGRAM_BOT_TOKEN")


def _approval_decision_token(approval_id: str, decision: str) -> str:
    secret = _approval_admin_secret()
    if not secret:
        return ""
    raw = f"telegram-approval:v1:{approval_id}:{decision}".encode("utf-8")
    return hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()


def _approval_callback_token(approval_id: str, decision: str) -> str:
    # Telegram callback_data is limited to 64 bytes; use a short HMAC prefix.
    return _approval_decision_token(approval_id, decision)[:24]


def _approval_button_url(base_url: str, approval_id: str, decision: str) -> str:
    base = (base_url or _approval_public_base_url()).rstrip("/")
    token = _approval_decision_token(approval_id, decision)
    if not base or not token:
        return ""
    qs = urlencode({"approval_id": approval_id, "decision": decision, "token": token})
    return f"{base}/v1/governance/approvals/telegram-decide?{qs}"


def _approval_webhook_token() -> str:
    configured = _approval_setting_value("webhook_token", "GOOGLE_GOVERNANCE_APPROVAL_WEBHOOK_TOKEN").strip()
    if configured:
        return configured
    secret = _approval_admin_secret()
    if not secret:
        return ""
    raw = b"telegram-webhook:v1"
    return hmac.new(secret.encode("utf-8"), raw, hashlib.sha256).hexdigest()


def _approval_telegram_webhook_url(base_url: str = "") -> str:
    base = (base_url or _approval_public_base_url()).rstrip("/")
    token = _approval_webhook_token()
    if not base or not token:
        return ""
    return f"{base}/v1/governance/approvals/telegram-webhook?{urlencode({'token': token})}"


def _approval_ensure_telegram_webhook(bot_token: str, base_url: str = "") -> None:
    webhook_url = _approval_telegram_webhook_url(base_url)
    if not webhook_url:
        return
    api = f"https://api.telegram.org/bot{bot_token}/setWebhook"
    payload = {
        "url": webhook_url,
        "allowed_updates": ["callback_query"],
        "secret_token": _approval_webhook_token(),
        "drop_pending_updates": False,
    }
    try:
        resp = requests.post(api, json=payload, timeout=10)
        ok = bool(resp.ok and (resp.json().get("ok") if resp.content else True))
        _append_approval_event({"event": "telegram_webhook_configured" if ok else "telegram_webhook_failed", "channel": "telegram", "status_code": resp.status_code})
    except Exception as exc:
        _append_approval_event({"event": "telegram_webhook_failed", "channel": "telegram", "error": type(exc).__name__})


def _telegram_bot_token_for_chat(chat_id: str) -> str:
    default_bot_token = _approval_telegram_bot_token()
    for channel in _approval_channel_rows(""):
        if str(channel.get("chat_id") or "") == str(chat_id or ""):
            return str(channel.get("bot_token") or "").strip() or default_bot_token
    return default_bot_token


def _telegram_callback_response(bot_token: str, callback_id: str, text: str, alert: bool = False) -> None:
    if not bot_token or not callback_id:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{bot_token}/answerCallbackQuery",
            json={"callback_query_id": callback_id, "text": text[:180], "show_alert": alert},
            timeout=10,
        )
    except Exception:
        pass


def _telegram_edit_callback_message(bot_token: str, callback: dict[str, Any], text: str) -> None:
    message = callback.get("message") or {}
    chat = message.get("chat") or {}
    chat_id = chat.get("id")
    message_id = message.get("message_id")
    if not bot_token or not chat_id or not message_id:
        return
    try:
        requests.post(
            f"https://api.telegram.org/bot{bot_token}/editMessageText",
            json={"chat_id": chat_id, "message_id": message_id, "text": text[:3900]},
            timeout=10,
        )
    except Exception:
        pass


def _telegram_handle_update(update: dict[str, Any], query: dict[str, list[str]], headers: dict[str, str] | None = None) -> dict[str, Any]:
    supplied = str((query.get("token") or [""])[0])
    expected = _approval_webhook_token()
    header_secret = ""
    if headers:
        header_secret = str(headers.get("X-Telegram-Bot-Api-Secret-Token") or headers.get("x-telegram-bot-api-secret-token") or "")
    if not expected or (not hmac.compare_digest(supplied, expected) and not hmac.compare_digest(header_secret, expected)):
        raise PermissionError("invalid telegram webhook token")
    callback = update.get("callback_query") or {}
    callback_id = str(callback.get("id") or "")
    data = str(callback.get("data") or "")
    message = callback.get("message") or {}
    chat_id = str(((message.get("chat") or {}).get("id")) or "")
    bot_token = _telegram_bot_token_for_chat(chat_id)
    parts = data.split(":")
    if len(parts) != 4 or parts[0] != "gg" or parts[1] not in {"a", "d"}:
        _telegram_callback_response(bot_token, callback_id, "Unsupported approval action", True)
        raise ValueError("unsupported telegram callback")
    action, approval_id, token = parts[1], parts[2], parts[3]
    decision = "approve_once" if action == "a" else "deny"
    expected_decision = _approval_callback_token(approval_id, decision)
    if not expected_decision or not hmac.compare_digest(token, expected_decision):
        _telegram_callback_response(bot_token, callback_id, "Invalid or stale approval button", True)
        raise PermissionError("invalid telegram approval token")
    actor = str(((callback.get("from") or {}).get("username")) or ((callback.get("from") or {}).get("id")) or "telegram-channel")
    try:
        approval_profile = str((_approval_state().get(approval_id) or {}).get("profile") or "agent-a")
        if decision == "approve_once":
            result = _approval_approve_and_execute(approval_profile, {"approval_admin_secret": _approval_admin_secret(), "approval_id": approval_id, "approver": actor, "reason": "Telegram Approve & Execute"})
            _telegram_callback_response(bot_token, callback_id, "Approved and executed")
            _telegram_edit_callback_message(bot_token, callback, f"✅ Google Workspace approval executed\nApproval: {approval_id}\nStatus: {result.get('status')}")
        else:
            result = _approval_decide(approval_profile, {"approval_admin_secret": _approval_admin_secret(), "approval_id": approval_id, "decision": "deny", "approver": actor, "reason": "Telegram deny"})
            _telegram_callback_response(bot_token, callback_id, "Denied")
            _telegram_edit_callback_message(bot_token, callback, f"❌ Google Workspace approval denied\nApproval: {approval_id}")
    except Exception as exc:
        _telegram_callback_response(bot_token, callback_id, f"Approval failed: {type(exc).__name__}", True)
        raise
    return {"status": "ok", "approval_id": approval_id, "decision": decision, "result": result}


def _approval_notify_telegram(event: dict[str, Any]) -> None:
    default_bot_token = _approval_telegram_bot_token()
    channels = _approval_channel_rows(str(event.get("profile") or ""))
    if not channels:
        _append_approval_event({"event": "notification_skipped", "approval_id": event.get("approval_id"), "channel": "telegram", "reason": "no_enabled_channels"})
        return
    approval_id = str(event.get("approval_id") or "")
    meta = event.get("safe_metadata") or {}
    lines = [
        "🔐 Google Workspace approval required",
        f"Approval: {approval_id}",
        f"Profile: {event.get('profile') or 'unknown'}",
        f"Action: {event.get('action') or 'unknown'}",
        f"Resource: {event.get('resource_alias') or 'unknown'}",
        f"Route: {meta.get('token_route') or 'default'}",
        f"Reason: {event.get('reason') or 'ACL requires approval'}",
        f"Expires: {event.get('expires_at') or 'unknown'}",
    ]
    if meta:
        safe_bits = ", ".join(f"{k}={v}" for k, v in sorted(meta.items()) if v)
        if safe_bits:
            lines.append(f"Safe metadata: {safe_bits}")
    sent_any = False
    for channel in channels:
        bot_token = str(channel.get("bot_token") or "").strip() or default_bot_token
        if not bot_token:
            _append_approval_event({"event": "notification_skipped", "approval_id": approval_id, "channel": "telegram", "chat_id": str(channel.get("chat_id") or ""), "reason": "missing_bot_token"})
            continue
        api = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        payload: dict[str, Any] = {
            "chat_id": str(channel.get("chat_id") or ""),
            "text": "\n".join(lines),
            "disable_web_page_preview": True,
        }
        approve_token = _approval_callback_token(approval_id, "approve_once")
        deny_token = _approval_callback_token(approval_id, "deny")
        if approve_token and deny_token:
            payload["reply_markup"] = {"inline_keyboard": [[{"text": "Approve & Execute", "callback_data": f"gg:a:{approval_id}:{approve_token}"}, {"text": "Deny", "callback_data": f"gg:d:{approval_id}:{deny_token}"}]]}
            _approval_ensure_telegram_webhook(bot_token, str(channel.get("button_base_url") or ""))
        try:
            resp = requests.post(api, json=payload, timeout=10)
            ok = bool(resp.ok and (resp.json().get("ok") if resp.content else True))
            _append_approval_event({"event": "notification_sent" if ok else "notification_failed", "approval_id": approval_id, "channel": "telegram", "target": channel.get("label") or channel.get("chat_id"), "status_code": resp.status_code})
        except Exception as exc:
            _append_approval_event({"event": "notification_failed", "approval_id": approval_id, "channel": "telegram", "target": channel.get("label") or channel.get("chat_id"), "error": type(exc).__name__})


def _approval_events() -> list[dict[str, Any]]:
    if not APPROVAL_STORE_PATH.exists():
        return []
    rows: list[dict[str, Any]] = []
    for line in APPROVAL_STORE_PATH.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _approval_is_expired(item: dict[str, Any]) -> bool:
    if item.get("state") not in {"pending", "request_edit"}:
        return False
    expires_at = item.get("expires_at")
    if not expires_at:
        return False
    try:
        return datetime.fromisoformat(str(expires_at)).timestamp() <= time.time()
    except ValueError:
        return False


def _approval_state() -> dict[str, dict[str, Any]]:
    state: dict[str, dict[str, Any]] = {}
    for event in _approval_events():
        approval_id = str(event.get("approval_id") or "")
        if not approval_id:
            continue
        current = state.setdefault(approval_id, {"approval_id": approval_id, "history": []})
        current["history"].append({k: v for k, v in event.items() if k not in {"safe_metadata"}})
        if event.get("event") == "requested":
            current.update(event)
            current.setdefault("state", "pending")
        elif event.get("event") == "decided":
            current["state"] = str(event.get("decision") or "denied")
            current["decision"] = event.get("decision")
            current["approver"] = event.get("approver")
            current["decision_reason"] = event.get("decision_reason")
            current["approved_until"] = event.get("approved_until")
        elif event.get("event") == "consumed":
            current["state"] = "consumed"
            current["consumed_at"] = event.get("ts")
        elif event.get("event") == "execution_failed":
            current["state"] = "execution_failed"
            current["execution_error"] = event.get("error")
    for current in state.values():
        if _approval_is_expired(current):
            current["state"] = "expired"
            current["expired_at"] = current.get("expires_at")
    return state


def _pending_approval_for_request(request_hash: str) -> dict[str, Any] | None:
    for approval in _approval_state().values():
        if approval.get("request_hash") == request_hash and approval.get("state") == "pending":
            return approval
    return None


def _create_approval_request(profile: str, action: str, resource_alias: str, reason: str, payload: dict[str, Any]) -> dict[str, Any]:
    request_hash = _approval_request_hash(payload)
    existing = _pending_approval_for_request(request_hash)
    if existing:
        return existing
    approval_id = f"gog-{uuid.uuid4().hex[:12]}"
    event = {
        "event": "requested",
        "approval_id": approval_id,
        "state": "pending",
        "profile": profile,
        "action": action,
        "resource_alias": resource_alias,
        "reason": reason,
        "request_hash": request_hash,
        "safe_metadata": _approval_safe_metadata(payload),
        "expires_at": datetime.fromtimestamp(time.time() + APPROVAL_DEFAULT_TTL_SECONDS, timezone.utc).isoformat(),
    }
    retry_payload = _approval_retry_payload(profile, action, resource_alias, payload, event)["retry_payload"]
    try:
        event["retry_payload_sealed"] = _seal_retry_payload(retry_payload)
        event["retry_payload_available"] = True
    except PermissionError:
        event["retry_payload_available"] = False
    _append_approval_event(event)
    _approval_notify_telegram(event)
    return event


def _approval_retry_payload(profile: str, action: str, resource_alias: str, payload: dict[str, Any], approval: dict[str, Any]) -> dict[str, Any]:
    """Return the exact short-lived retry envelope for the originating agent.

    The raw target payload is returned only to the same caller that supplied it;
    it is not persisted in the approval store. The store keeps safe metadata plus
    a request hash, while the active agent session keeps this envelope so a later
    user message like "try again" can execute the already-approved action without
    reconstructing IDs from memory.
    """
    retry_payload = dict(payload)
    retry_payload["profile"] = str(retry_payload.get("profile") or profile)
    retry_payload["action"] = str(retry_payload.get("action") or action)
    retry_payload["resource_alias"] = str(retry_payload.get("resource_alias") or resource_alias)
    retry_payload["approval_id"] = str(approval.get("approval_id") or "")
    retry_payload.setdefault("token_route", str(payload.get("token_route") or "default"))
    return {
        "endpoint": "/v1/governance/execute-approved",
        "mcp_helper": "governance_execute_approved",
        "approval_id": retry_payload["approval_id"],
        "retry_payload": retry_payload,
        "request_hash": approval.get("request_hash"),
        "expires_at": approval.get("expires_at"),
        "instruction": "After the user approves this request, if they say 'try again', call /v1/governance/execute-approved with retry_payload unchanged.",
    }


def _approval_admin_secret() -> str:
    value = os.getenv("GOOGLE_GOVERNANCE_APPROVAL_ADMIN_SECRET", "").strip()
    if value:
        return value
    if APPROVAL_ADMIN_SECRET_PATH.exists():
        return APPROVAL_ADMIN_SECRET_PATH.read_text(encoding="utf-8").strip()
    return ""


def _require_approval_admin(payload: dict[str, Any]) -> None:
    expected = _approval_admin_secret()
    supplied = str(payload.get("approval_admin_secret") or "")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        raise PermissionError("approval admin secret required")


def _approval_list(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    _require_approval_admin(payload)
    state_filter = str(payload.get("state") or "pending")
    approvals = []
    for item in sorted(_approval_state().values(), key=lambda row: str(row.get("ts") or ""), reverse=True):
        if state_filter != "all" and item.get("state") != state_filter:
            continue
        approvals.append({k: v for k, v in item.items() if k != "history"})
    _audit_observed(profile, "approval.list", "ok", payload, "approval_queue", count=len(approvals))
    return {"status": "ok", "approvals": approvals}


def _approval_decide(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    _require_approval_admin(payload)
    approval_id = str(payload.get("approval_id") or "")
    decision = str(payload.get("decision") or "").strip()
    if decision not in {"approve_once", "deny", "request_edit"}:
        raise ValueError("decision must be approve_once, deny, or request_edit")
    current = _approval_state().get(approval_id)
    if not current:
        raise ValueError("unknown approval_id")
    if current.get("state") not in {"pending", "request_edit"}:
        raise ValueError(f"approval is not pending: {current.get('state')}")
    approved_until = None
    if decision == "approve_once":
        ttl = max(60, min(int(payload.get("ttl_seconds") or APPROVAL_DEFAULT_TTL_SECONDS), 3600))
        approved_until = datetime.fromtimestamp(time.time() + ttl, timezone.utc).isoformat()
    event = {
        "event": "decided",
        "approval_id": approval_id,
        "decision": decision,
        "approver": str(payload.get("approver") or "admin"),
        "decision_reason": str(payload.get("reason") or ""),
        "approved_until": approved_until,
    }
    _append_approval_event(event)
    status = "approved" if decision == "approve_once" else decision
    _audit_observed(profile, f"approval.{decision}", status, payload, current.get("resource_alias") or "approval_queue", approval_id=approval_id, target_action=current.get("action"))
    return {"status": status, "approval_id": approval_id, "decision": decision, "approved_until": approved_until}


def _approval_approve_and_execute(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Approve a pending request and execute its sealed retry payload in one UI action."""
    _require_approval_admin(payload)
    approval_id = str(payload.get("approval_id") or "")
    if not approval_id:
        raise ValueError("approval_id is required")
    state = _approval_state()
    current = state.get(approval_id)
    if not current:
        raise ValueError("unknown approval_id")
    if current.get("state") in {"pending", "request_edit"}:
        _approval_decide(profile, {**payload, "decision": "approve_once"})
        current = _approval_state().get(approval_id) or current
    elif current.get("state") != "approve_once":
        raise ValueError(f"approval is not executable: {current.get('state')}")
    retry_payload = _unseal_retry_payload(current.get("retry_payload_sealed"))
    retry_payload.setdefault("request_id", str(payload.get("request_id") or uuid.uuid4()))
    result = _governance_execute_approved(profile, retry_payload)
    return {"status": "executed", "approval_id": approval_id, "decision": "approve_once", "execution": result}


def _approval_for_execution(payload: dict[str, Any]) -> dict[str, Any]:
    approval_id = str(payload.get("approval_id") or "")
    if not approval_id:
        raise PermissionError("approval_id required")
    current = _approval_state().get(approval_id)
    if not current:
        raise PermissionError("unknown approval_id")
    if current.get("state") != "approve_once":
        raise PermissionError(f"approval is not approved: {current.get('state')}")
    until = current.get("approved_until")
    if until:
        try:
            if datetime.fromisoformat(str(until)).timestamp() < time.time():
                raise PermissionError("approval expired")
        except ValueError as exc:
            raise PermissionError("approval expiry invalid") from exc
    request_hash = _approval_request_hash(payload)
    if current.get("request_hash") != request_hash:
        raise PermissionError("approval does not match request payload")
    return current


def _mark_approval_consumed(approval_id: str, action: str) -> None:
    _append_approval_event({"event": "consumed", "approval_id": approval_id, "action": action})


def _telegram_decide_from_query(query: dict[str, list[str]]) -> dict[str, Any]:
    approval_id = str((query.get("approval_id") or [""])[0])
    decision = str((query.get("decision") or [""])[0])
    token = str((query.get("token") or [""])[0])
    if decision not in {"approve_once", "deny"}:
        raise ValueError("decision must be approve_once or deny")
    expected = _approval_decision_token(approval_id, decision)
    if not expected or not token or not hmac.compare_digest(expected, token):
        raise PermissionError("invalid approval token")
    approval_profile = str((_approval_state().get(approval_id) or {}).get("profile") or "agent-a")
    if decision == "approve_once":
        return _approval_approve_and_execute(approval_profile, {"approval_admin_secret": _approval_admin_secret(), "approval_id": approval_id, "approver": "telegram-channel", "reason": "Telegram Approve & Execute"})
    return _approval_decide(approval_profile, {"approval_admin_secret": _approval_admin_secret(), "approval_id": approval_id, "decision": decision, "approver": "telegram-channel"})


def _profile_config(profile: str) -> dict[str, Any]:
    try:
        return PROFILE_CONFIG[profile]
    except KeyError as exc:
        raise ValueError(f"unknown profile: {profile}") from exc


def _load_api_token_map() -> dict[str, str]:
    """Return sha256(token)->allowed profile marker for externally authenticated agents."""
    token_map: dict[str, str] = {}
    raw_hashes = os.getenv(API_TOKEN_HASHES_ENV, "").strip()
    if raw_hashes:
        try:
            parsed = json.loads(raw_hashes)
            if isinstance(parsed, dict):
                token_map.update({str(k): str(v) for k, v in parsed.items()})
        except json.JSONDecodeError as exc:
            raise ValueError(f"{API_TOKEN_HASHES_ENV} must be JSON object sha256_hex->profile") from exc
    raw_tokens = os.getenv(API_TOKENS_ENV, "").strip()
    if raw_tokens:
        try:
            parsed = json.loads(raw_tokens)
            if isinstance(parsed, dict):
                for token, profile in parsed.items():
                    token_map[hashlib.sha256(str(token).encode("utf-8")).hexdigest()] = str(profile)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{API_TOKENS_ENV} must be JSON object token->profile") from exc
    try:
        if TOKEN_DB_PATH.exists():
            with sqlite3.connect(TOKEN_DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute("SELECT token_hash,allowed_profiles_json FROM api_tokens WHERE revoked_at=''").fetchall()
            for row in rows:
                try:
                    profiles = json.loads(row["allowed_profiles_json"] or '["*"]')
                except json.JSONDecodeError:
                    profiles = ["*"]
                if "*" in profiles:
                    token_map[str(row["token_hash"])] = "*"
                elif len(profiles) == 1:
                    token_map[str(row["token_hash"])] = str(profiles[0])
        
    except sqlite3.Error:
        pass
    return token_map


def _mark_api_token_used(token_hash: str) -> None:
    try:
        if TOKEN_DB_PATH.exists():
            with sqlite3.connect(TOKEN_DB_PATH) as conn:
                conn.execute("UPDATE api_tokens SET last_used_at=CURRENT_TIMESTAMP WHERE token_hash=? AND revoked_at=''", (token_hash,))
                conn.commit()
    except sqlite3.Error:
        pass

def _verify_api_token(token: str) -> dict[str, Any] | None:
    token_map = _load_api_token_map()
    if not token_map:
        return None
    digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    profile = token_map.get(digest)
    if not profile:
        raise ValueError("bad API token")
    _mark_api_token_used(digest)
    if profile in {"*", "all", "__all__"}:
        return {"iss": "gateway-api-token", "scope": "google.governed", "auth_method": "api_token", "_profile": "*", "_persona": "gateway"}
    cfg = _profile_config(profile)
    return {"iss": profile, "scope": "google.governed", "auth_method": "api_token", "_profile": profile, "_persona": cfg["persona"]}


def _verify_jwt(header_value: str) -> dict[str, Any]:
    if not header_value.startswith("Bearer "):
        raise ValueError("missing bearer token")
    token = header_value.split(" ", 1)[1].strip()
    if token.count(".") == 2:
        raise ValueError("JWT bearer auth is disabled; use a gateway API access token")
    api_claims = _verify_api_token(token)
    if api_claims:
        return api_claims
    raise ValueError("bad or unconfigured API token")



def _workspace_token_from_db(token_id: str) -> dict[str, Any] | None:
    if not TOKEN_DB_PATH.exists():
        return None
    try:
        with sqlite3.connect(TOKEN_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute("SELECT * FROM workspace_tokens WHERE id=? AND revoked_at=''", (token_id,)).fetchone()
    except sqlite3.Error:
        return None
    if not row:
        return None
    return {"id": row["id"], "account_alias": row["account_alias"], "bundle": row["bundle"], "token_json": json.loads(row["token_json"] or "{}"), "metadata_json": json.loads(row["metadata_json"] or "{}"), "scopes": json.loads(row["scopes_json"] or "[]")}


def _route_lookup_key(value: str | None) -> str:
    return "".join(ch for ch in str(value or "").strip().lower() if ch.isalnum())


def _workspace_token_id_for_name(value: str | None) -> str | None:
    """Resolve a human token/account name to the active SQLite workspace token id.

    The Control UI exposes user-facing token names such as "Shared Workspace". Agents
    should be able to pass that exact name as token_route; hard-coded account
    aliases are only a fallback because the operator may revoke/recreate tokens with
    new names.
    """
    target = _route_lookup_key(value)
    if not target or not TOKEN_DB_PATH.exists():
        return None
    try:
        with sqlite3.connect(TOKEN_DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT * FROM workspace_tokens WHERE revoked_at='' ORDER BY updated_at DESC, created_at DESC").fetchall()
    except sqlite3.Error:
        return None
    label_keys = ("token_label", "label", "display_name", "display_label", "token_name", "name", "account_label")
    for row in rows:
        metadata = json.loads(row["metadata_json"] or "{}")
        candidates = [
            row["id"],
            str(row["id"] or "").split("/", 1)[0],
            row["account_alias"],
            row["email"],
        ]
        candidates.extend(str(metadata.get(key) or "") for key in label_keys)
        if target in {_route_lookup_key(candidate) for candidate in candidates if str(candidate or "").strip()}:
            return str(row["id"])
    return None


def _workspace_token_available(token_id: str) -> bool:
    return _workspace_token_from_db(token_id) is not None


def _store_workspace_token_db(token_id: str, token_payload: dict[str, Any], metadata: dict[str, Any] | None = None) -> None:
    stored = _workspace_token_from_db(token_id)
    if not stored:
        return
    meta = dict(stored.get("metadata_json") or {})
    if metadata:
        meta.update(metadata)
    raw_scopes = token_payload.get("scopes") or token_payload.get("scope") or stored.get("scopes") or []
    if isinstance(raw_scopes, str):
        scopes = [x for x in raw_scopes.split() if x]
    else:
        scopes = [str(x) for x in raw_scopes if x]
    with sqlite3.connect(TOKEN_DB_PATH) as conn:
        conn.execute("UPDATE workspace_tokens SET token_json=?, metadata_json=?, scopes_json=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (json.dumps(token_payload, sort_keys=True), json.dumps(meta, sort_keys=True), json.dumps(scopes), token_id))
        conn.commit()


def _dynamic_token_id(profile: str, route: str | None) -> str | None:
    route_key = route or "default"
    if "/" in route_key:
        route_profile, route_alias = route_key.split("/", 1)
        if route_profile == profile and route_alias:
            named = _workspace_token_id_for_name(route_alias)
            if named:
                return named
            return f"{route_alias}/workspace-full.json"
    if route_key != "default":
        named = _workspace_token_id_for_name(route_key)
        if named:
            return named
    from governance_policy import POLICY_PATH, load_policy
    try:
        policy = load_policy()
    except Exception as exc:
        raise RuntimeError(f"failed to load UI runtime policy {POLICY_PATH}: {type(exc).__name__}: {exc}") from exc
    accounts = policy.get("accounts") or {}
    for account_alias, account_spec in accounts.items():
        routes = account_spec.get("current_profile_routes") or {}
        if routes.get(profile) == f"{profile}/{route_key}":
            return f"{account_alias}/workspace-full.json"
    profile_meta = (policy.get("profiles") or {}).get(profile) or {}
    # UI-managed policies express the default workspace on the profile as
    # `account_alias` / `default_route_alias`. Do not fall back to any static
    # profile-to-token mapping; the UI policy is the source of truth.
    if route_key == "default":
        account_alias = str(profile_meta.get("account_alias") or "").strip()
        if account_alias:
            return f"{account_alias}/workspace-full.json"
        default_route = str(profile_meta.get("default_route_alias") or "").strip()
        if "/" in default_route:
            route_profile, route_alias = default_route.split("/", 1)
            if route_profile == profile and route_alias:
                return f"{route_alias}/workspace-full.json"
    return None


def _canonicalize_payload_token_route(profile: str, payload: dict[str, Any]) -> None:
    """Turn human token names into canonical profile/account routes in-place."""
    route = str(payload.get("token_route") or "").strip()
    if not route or route == "default":
        return
    token_id = _dynamic_token_id(profile, route)
    if not token_id or "/" not in token_id:
        return
    account_alias = token_id.split("/", 1)[0]
    if account_alias:
        payload.setdefault("token_route_requested", route)
        payload["token_route"] = f"{profile}/{account_alias}"


def _token_id_for_route(profile: str, route: str | None) -> str:
    _profile_config(profile)
    route_key = route or "default"
    dynamic = _dynamic_token_id(profile, route_key)
    if dynamic:
        return dynamic
    raise ValueError(f"token route not configured in UI policy for {profile}: {route_key}")


def _token_path(profile: str, route: str | None) -> Path:
    rel = _token_id_for_route(profile, route)
    path = (TOKEN_ROOT / rel).resolve()
    root = TOKEN_ROOT.resolve()
    if root not in path.parents:
        raise ValueError("token path escape rejected")
    return path


def _token_scopes(path: Path) -> list[str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return DEFAULT_SCOPES
    raw = data.get("scopes") or data.get("scope")
    if isinstance(raw, str):
        scopes = [s for s in raw.split() if s]
    elif isinstance(raw, list):
        scopes = [str(s) for s in raw if s]
    else:
        scopes = []
    return scopes or DEFAULT_SCOPES


def _credentials(profile: str, route: str | None = None) -> Credentials:
    token_id = _token_id_for_route(profile, route)
    stored = _workspace_token_from_db(token_id)
    if not stored:
        raise RuntimeError(f"google workspace token not found in SQLite token DB for route: {token_id}")
    token_payload = stored["token_json"]
    creds = Credentials.from_authorized_user_info(token_payload, stored.get("scopes") or DEFAULT_SCOPES)
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        payload = json.loads(creds.to_json())
        payload.setdefault("type", "authorized_user")
        if "client_secret" not in payload and token_payload.get("client_secret"):
            payload["client_secret"] = token_payload["client_secret"]
        _store_workspace_token_db(token_id, payload, {"refreshed_at": datetime.now(timezone.utc).isoformat()})
    if not creds.valid:
        raise RuntimeError("google token invalid")
    return creds


def _session(profile: str, route: str | None = None) -> requests.Session:
    from google.auth.transport.requests import AuthorizedSession
    return AuthorizedSession(_credentials(profile, route))


def _headers_dict(msg: dict[str, Any]) -> dict[str, str]:
    return {h["name"].lower(): h["value"] for h in msg.get("payload", {}).get("headers", []) if h.get("name")}


def _observe(profile: str, action: str, payload: dict[str, Any] | None = None, resource_alias: str | None = None) -> dict[str, Any]:
    payload = payload or {}
    workflow_intent = payload.get("workflow_intent") or payload.get("workflow")
    resource = resource_alias or resource_for(profile, action, payload)
    decision = classify(profile, action, resource, str(workflow_intent or ""))
    decision["persona"] = _profile_config(profile)["persona"]
    return decision


def _route_policy_context(path: str, profile: str, payload: dict[str, Any]) -> tuple[str, str]:
    if path.startswith("/v1/tools/"):
        tool = path.rsplit("/", 1)[-1]
        action = workspace_tool_action(tool)
        return action, str(payload.get("resource_alias") or resource_for(profile, action, payload))
    if path == "/v1/gmail/search":
        return "gmail.search_gmail_messages", resource_for(profile, "gmail.search_gmail_messages", payload)
    if path == "/v1/gmail/draft":
        return "gmail.draft_gmail_message", resource_for(profile, "gmail.draft_gmail_message", payload)
    if path == "/v1/calendar/list":
        return "calendar.get_events", resource_for(profile, "calendar.get_events", payload)
    route_actions = {
        "/v1/calendar/create": "calendar.manage_event",
        "/v1/calendar/get": "calendar.get_events",
        "/v1/calendar/update": "calendar.manage_event",
        "/v1/calendar/freebusy": "calendar.query_freebusy",
        "/v1/gmail/get": "gmail.get_gmail_message_content",
        "/v1/gmail/attachment": "gmail.get_gmail_message_content",
        "/v1/gmail/modify": "gmail.modify_gmail_message_labels",
        "/v1/drive/search": "drive.search_drive_files",
        "/v1/drive/get": "drive.get_drive_file_content",
        "/v1/drive/export": "drive.get_drive_file_download_url",
        "/v1/drive/copy": "drive.copy_drive_file",
        "/v1/drive/create": "drive.create_drive_file",
        "/v1/docs/get": "docs.get_doc_content",
        "/v1/docs/create": "docs.create_doc",
        "/v1/docs/batch_update": "docs.batch_update_doc",
        "/v1/sheets/get": "sheets.read_sheet_values",
        "/v1/sheets/metadata": "sheets.get_spreadsheet_info",
        "/v1/sheets/update": "sheets.modify_sheet_values",
        "/v1/sheets/append": "sheets.append_table_rows",
        "/v1/sheets/clear": "sheets.modify_sheet_values",
        "/v1/sheets/batch_update": "sheets.format_sheet_range",
        "/v1/slides/get": "slides.get_presentation",
        "/v1/slides/create": "slides.create_presentation",
        "/v1/slides/batch_update": "slides.batch_update_presentation",
        "/v1/contacts/search": "contacts.search_contacts",
    }
    if path in route_actions:
        action = route_actions[path]
        return action, str(payload.get("resource_alias") or resource_for(profile, action, payload))
    if path == "/v1/google/request":
        return "google.request", str(payload.get("resource_alias") or "unknown")
    if path == "/v1/governance/execute-approved":
        action = str(payload.get("action") or "")
        return action, str(payload.get("resource_alias") or resource_for(profile, action, payload))
    if path == "/v1/governance/blocked":
        action = str(payload.get("action") or "google.blocked")
        return action, str(payload.get("resource_alias") or resource_for(profile, action, payload))
    return path.strip("/").replace("v1/", ""), str(payload.get("resource_alias") or "unknown")


def _enforce_acl(profile: str, action: str, resource_alias: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    decision = _observe(profile, action, payload, resource_alias)
    value = str(decision.get("decision") or "ask")
    mode = str(decision.get("mode") or "observe_only")
    # observe_only and compatibility modes remain audit-only. enforcement modes block/queue.
    if mode in {"observe_only", "audit_only"}:
        return None
    if value == "allow":
        return None
    if value == "deny":
        _audit_observed(profile, action, "denied", payload, resource_alias, policy_enforced=True)
        raise PermissionError(f"ACL denied {profile} {action} on {resource_alias}")
    # ask means do not execute now; create a bounded approval request.
    reason = str(payload.get("reason") or f"ACL requires approval for {action}")
    approval = _create_approval_request(profile, action, resource_alias, reason, payload)
    _audit_observed(profile, action, "approval_required", payload, resource_alias, policy_enforced=True, approval_id=approval["approval_id"], reason=reason)
    return {
        "status": "approval_required",
        "action": action,
        "resource_alias": resource_alias,
        "reason": reason,
        "approval_id": approval["approval_id"],
        "approval_state": approval.get("state", "pending"),
        "approval_expires_at": approval.get("expires_at"),
        "retry_after_approval": _approval_retry_payload(profile, action, resource_alias, payload, approval),
        "agent_instruction": "Ask the user to approve this in the Governance UI, then say 'try again'. Keep retry_after_approval.retry_payload for that retry.",
    }


def _audit_observed(profile: str, action: str, status: str, payload: dict[str, Any] | None = None, resource_alias: str | None = None, **fields: Any) -> None:
    payload = payload or {}
    observe = _observe(profile, action, payload, resource_alias)
    resolved_resource = str(observe.get("resource_alias") or resource_alias or resource_for(profile, action, payload))
    fields.setdefault("resource_alias", resolved_resource)
    fields.setdefault("service", _service_for_action(action))
    fields.setdefault("operation", _operation_for_action(action))
    fields.setdefault("token_route", str(payload.get("token_route") or "default"))
    fields.setdefault("high_risk_action", _is_high_risk_action(action))
    fields.setdefault("unknown_resource", _is_unknown_resource(resolved_resource))
    if payload.get("request_id"):
        fields.setdefault("request_id", str(payload["request_id"]))
    if payload.get("workflow_intent") or payload.get("workflow"):
        fields.setdefault("workflow_intent", str(payload.get("workflow_intent") or payload.get("workflow")))
    request_fingerprint_src = json.dumps(_redact_payload(payload), sort_keys=True, default=str)
    fields.setdefault("request_hash", hashlib.sha256(request_fingerprint_src.encode()).hexdigest())
    # Classifier output includes audit fields such as workflow_intent/resource_alias/action.
    # Strip signature-owned keys and any caller-supplied field keys before splatting so
    # denied/blocked paths cannot fail before writing their audit row.
    for key in {"profile", "action", "status", *fields.keys()}:
        observe.pop(key, None)
    _audit(profile, action, status, **observe, **fields)


def _gmail_search(profile: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    started = time.monotonic()
    query = str(payload.get("query") or "")
    max_results = max(1, min(int(payload.get("max") or 10), 25))
    session = _session(profile, payload.get("token_route"))
    list_resp = session.get("https://gmail.googleapis.com/gmail/v1/users/me/messages", params={"q": query, "maxResults": max_results}, timeout=60)
    list_resp.raise_for_status()
    output = []
    for msg_meta in list_resp.json().get("messages", []):
        msg_resp = session.get(f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_meta['id']}", params={"format": "metadata", "metadataHeaders": ["From", "To", "Subject", "Date"]}, timeout=60)
        msg_resp.raise_for_status()
        msg = msg_resp.json()
        headers = _headers_dict(msg)
        output.append({"id": msg["id"], "threadId": msg["threadId"], "from": headers.get("from", ""), "to": headers.get("to", ""), "subject": headers.get("subject", ""), "date": headers.get("date", ""), "snippet": msg.get("snippet", ""), "labels": msg.get("labelIds", [])})
    _audit_observed(profile, "gmail.search", "ok", payload, count=len(output), query_sha256=hashlib.sha256(query.encode()).hexdigest(), max=max_results, latency_ms=(time.monotonic() - started) * 1000)
    return output


def _calendar_list(profile: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    started = time.monotonic()
    now = datetime.now(timezone.utc)
    time_min = str(payload.get("time_min") or payload.get("start") or now.isoformat())
    time_max = str(payload.get("time_max") or payload.get("end") or (now + timedelta(days=7)).isoformat())
    calendar = str(payload.get("calendar") or "primary")
    max_results = max(1, min(int(payload.get("max") or 25), 50))
    session = _session(profile, payload.get("token_route"))
    url_calendar = quote(calendar, safe="")
    resp = session.get(f"https://www.googleapis.com/calendar/v3/calendars/{url_calendar}/events", params={"timeMin": time_min, "timeMax": time_max, "maxResults": max_results, "singleEvents": "true", "orderBy": "startTime"}, timeout=60)
    resp.raise_for_status()
    events = []
    for e in resp.json().get("items", []):
        events.append({"id": e["id"], "summary": e.get("summary", "(no title)"), "start": e.get("start", {}).get("dateTime", e.get("start", {}).get("date", "")), "end": e.get("end", {}).get("dateTime", e.get("end", {}).get("date", "")), "location": e.get("location", ""), "description": e.get("description", ""), "status": e.get("status", ""), "htmlLink": e.get("htmlLink", "")})
    _audit_observed(profile, "calendar.list", "ok", payload, count=len(events), calendar=calendar, max=max_results, latency_ms=(time.monotonic() - started) * 1000)
    return events


def _calendar_create(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    summary = str(payload.get("summary") or "").strip()
    start = str(payload.get("start") or "").strip()
    end = str(payload.get("end") or "").strip()
    calendar = str(payload.get("calendar") or "primary")
    if not summary or not start or not end:
        raise ValueError("summary, start, and end are required")
    event: dict[str, Any] = {"summary": summary, "start": {"dateTime": start}, "end": {"dateTime": end}}
    if payload.get("location"):
        event["location"] = str(payload["location"])
    if payload.get("description"):
        event["description"] = str(payload["description"])
    attendees = payload.get("attendees") or []
    if isinstance(attendees, str):
        attendees = [e.strip() for e in attendees.split(",") if e.strip()]
    if attendees:
        event["attendees"] = [{"email": str(e).strip()} for e in attendees if str(e).strip()]
    session = _session(profile, payload.get("token_route"))
    url_calendar = quote(calendar, safe="")
    resp = session.post(f"https://www.googleapis.com/calendar/v3/calendars/{url_calendar}/events", json=event, timeout=60)
    resp.raise_for_status()
    result = resp.json()
    _audit_observed(profile, "calendar.create", "ok", payload, calendar=calendar, event_id=result.get("id", ""), summary_sha256=hashlib.sha256(summary.encode()).hexdigest(), latency_ms=(time.monotonic() - started) * 1000)
    return {"status": "created", "id": result["id"], "summary": result.get("summary", ""), "start": result.get("start", {}).get("dateTime", result.get("start", {}).get("date", "")), "end": result.get("end", {}).get("dateTime", result.get("end", {}).get("date", "")), "location": result.get("location", ""), "description": result.get("description", ""), "htmlLink": result.get("htmlLink", "")}


def _gmail_draft(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    to = str(payload.get("to") or "").strip()
    subject = str(payload.get("subject") or "")
    body = str(payload.get("body") or "")
    if not to:
        raise ValueError("to is required")
    msg = MIMEText(body, "html" if payload.get("html") else "plain")
    msg["To"] = to
    msg["Subject"] = subject
    if payload.get("cc"):
        msg["Cc"] = str(payload["cc"])
    if payload.get("from"):
        msg["From"] = str(payload["from"])
    if payload.get("message_id"):
        msg["In-Reply-To"] = str(payload["message_id"])
        msg["References"] = str(payload["message_id"])
    raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")
    draft: dict[str, Any] = {"message": {"raw": raw}}
    if payload.get("thread_id"):
        draft["message"]["threadId"] = str(payload["thread_id"])
    session = _session(profile, payload.get("token_route"))
    resp = session.post("https://gmail.googleapis.com/gmail/v1/users/me/drafts", json=draft, timeout=60)
    resp.raise_for_status()
    result = resp.json()
    _audit_observed(profile, "gmail.draft", "ok", payload, draft_id=result.get("id", ""), to_sha256=hashlib.sha256(to.encode()).hexdigest(), subject_sha256=hashlib.sha256(subject.encode()).hexdigest(), latency_ms=(time.monotonic() - started) * 1000)
    return {"status": "draft_created", "id": result.get("id", ""), "message_id": result.get("message", {}).get("id", "")}



def _google_response_body(resp: requests.Response) -> dict[str, Any]:
    content_type = resp.headers.get("content-type", "")
    body: dict[str, Any] = {"status_code": resp.status_code, "headers": {"content-type": content_type}}
    if "application/json" in content_type:
        body["json"] = resp.json() if resp.content else None
    elif content_type.startswith("text/"):
        body["text"] = resp.text
    else:
        body["content_b64"] = base64.b64encode(resp.content).decode("ascii")
    return body


def _typed_google_request(profile: str, action: str, payload: dict[str, Any], method: str, url: str, *, params: dict[str, Any] | None = None, json_body: dict[str, Any] | None = None, data: str | None = None, resource_alias: str | None = None) -> dict[str, Any]:
    started = time.monotonic()
    session = _session(profile, payload.get("token_route"))
    resp = session.request(method, url, params=params or None, json=json_body if json_body is not None else None, data=data if data is not None else None, timeout=min(int(payload.get("timeout") or 60), 180))
    body = _google_response_body(resp)
    _audit_observed(profile, action, "ok" if resp.status_code < 400 else "error", payload, resource_alias or resource_for(profile, action, payload), method=method, status_code=resp.status_code, latency_ms=(time.monotonic() - started) * 1000)
    return body


def _calendar_get(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    event_id = str(payload.get("event_id") or "")
    calendar = str(payload.get("calendar") or "primary")
    if not event_id:
        raise ValueError("event_id is required")
    return _typed_google_request(profile, "calendar.get", payload, "GET", f"https://www.googleapis.com/calendar/v3/calendars/{quote(calendar, safe='')}/events/{quote(event_id, safe='')}")


def _calendar_update(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    event_id = str(payload.get("event_id") or "")
    calendar = str(payload.get("calendar") or "primary")
    if not event_id:
        raise ValueError("event_id is required")
    body: dict[str, Any] = {}
    for key in ("summary", "location", "description"):
        if key in payload and payload.get(key) is not None:
            body[key] = str(payload[key])
    if payload.get("start") is not None:
        body["start"] = {"dateTime": str(payload["start"])}
    if payload.get("end") is not None:
        body["end"] = {"dateTime": str(payload["end"])}
    if not body:
        raise ValueError("at least one update field is required")
    return _typed_google_request(profile, "calendar.update", payload, "PATCH", f"https://www.googleapis.com/calendar/v3/calendars/{quote(calendar, safe='')}/events/{quote(event_id, safe='')}", json_body=body)


def _calendar_freebusy(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    calendars = payload.get("calendar_ids") or ["primary"]
    time_min = str(payload.get("time_min") or payload.get("start") or "")
    time_max = str(payload.get("time_max") or payload.get("end") or "")
    if not time_min or not time_max:
        raise ValueError("time_min and time_max are required")
    return _typed_google_request(profile, "calendar.freebusy", payload, "POST", "https://www.googleapis.com/calendar/v3/freeBusy", json_body={"timeMin": time_min, "timeMax": time_max, "items": [{"id": str(c)} for c in calendars]})


def _gmail_get(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    message_id = str(payload.get("message_id") or "")
    fmt = str(payload.get("fmt") or "metadata")
    if fmt not in {"metadata", "full", "raw", "minimal"}:
        fmt = "metadata"
    if not message_id:
        raise ValueError("message_id is required")
    return _typed_google_request(profile, "gmail.get", payload, "GET", f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{quote(message_id, safe='')}", params={"format": fmt})


def _gmail_get_attachment(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    message_id = str(payload.get("message_id") or "")
    attachment_id = str(payload.get("attachment_id") or "")
    if not message_id or not attachment_id:
        raise ValueError("message_id and attachment_id are required")
    return _typed_google_request(profile, "gmail.attachments.get", payload, "GET", f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{quote(message_id, safe='')}/attachments/{quote(attachment_id, safe='')}")


def _gmail_modify(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    message_id = str(payload.get("message_id") or "")
    if not message_id:
        raise ValueError("message_id is required")
    body = {"addLabelIds": payload.get("add_label_ids") or [], "removeLabelIds": payload.get("remove_label_ids") or []}
    return _typed_google_request(profile, "gmail.modify", payload, "POST", f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{quote(message_id, safe='')}/modify", json_body=body)


def _drive_search(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    page_size = min(max(int(payload.get("page_size") or 10), 1), 50)
    return _typed_google_request(profile, "drive.search", payload, "GET", "https://www.googleapis.com/drive/v3/files", params={"q": str(payload.get("query") or "trashed = false"), "pageSize": page_size, "fields": "files(id,name,mimeType,modifiedTime,webViewLink),nextPageToken"})


def _drive_get(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    file_id = str(payload.get("file_id") or "")
    if not file_id:
        raise ValueError("file_id is required")
    return _typed_google_request(profile, "drive.get", payload, "GET", f"https://www.googleapis.com/drive/v3/files/{quote(file_id, safe='')}", params={"fields": "id,name,mimeType,modifiedTime,webViewLink,parents,owners"})


def _drive_export(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    file_id = str(payload.get("file_id") or "")
    mime_type = str(payload.get("mime_type") or "application/pdf")
    if not file_id:
        raise ValueError("file_id is required")
    return _typed_google_request(profile, "drive.download", payload, "GET", f"https://www.googleapis.com/drive/v3/files/{quote(file_id, safe='')}/export", params={"mimeType": mime_type})


def _drive_copy(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    file_id = str(payload.get("file_id") or "")
    name = str(payload.get("name") or "")
    if not file_id or not name:
        raise ValueError("file_id and name are required")
    body: dict[str, Any] = {"name": name}
    if payload.get("parent_id"):
        body["parents"] = [str(payload["parent_id"])]
    return _typed_google_request(profile, "drive.copy", payload, "POST", f"https://www.googleapis.com/drive/v3/files/{quote(file_id, safe='')}/copy", json_body=body)


def _drive_create(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    name = str(payload.get("name") or "")
    mime_type = str(payload.get("mime_type") or "")
    if not name or not mime_type:
        raise ValueError("name and mime_type are required")
    body: dict[str, Any] = {"name": name, "mimeType": mime_type}
    if payload.get("parent_id"):
        body["parents"] = [str(payload["parent_id"])]
    return _typed_google_request(profile, "drive.create", payload, "POST", "https://www.googleapis.com/drive/v3/files", json_body=body)


def _docs_get(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    document_id = str(payload.get("document_id") or "")
    if not document_id:
        raise ValueError("document_id is required")
    return _typed_google_request(profile, "docs.get", payload, "GET", f"https://docs.googleapis.com/v1/documents/{quote(document_id, safe='')}")


def _docs_create(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    title = str(payload.get("title") or "")
    if not title:
        raise ValueError("title is required")
    return _typed_google_request(profile, "docs.create", payload, "POST", "https://docs.googleapis.com/v1/documents", json_body={"title": title})


def _docs_batch_update(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    document_id = str(payload.get("document_id") or "")
    if not document_id:
        raise ValueError("document_id is required")
    return _typed_google_request(profile, "docs.update", payload, "POST", f"https://docs.googleapis.com/v1/documents/{quote(document_id, safe='')}:batchUpdate", json_body={"requests": payload.get("requests") or []})


def _sheets_get(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    spreadsheet_id = str(payload.get("spreadsheet_id") or "")
    range_a1 = str(payload.get("range_a1") or "")
    if not spreadsheet_id or not range_a1:
        raise ValueError("spreadsheet_id and range_a1 are required")
    return _typed_google_request(profile, "sheets.get", payload, "GET", f"https://sheets.googleapis.com/v4/spreadsheets/{quote(spreadsheet_id, safe='')}/values/{quote(range_a1, safe='')}", params={"valueRenderOption": "FORMATTED_VALUE"})


def _sheets_metadata(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    spreadsheet_id = str(payload.get("spreadsheet_id") or "")
    if not spreadsheet_id:
        raise ValueError("spreadsheet_id is required")
    params: dict[str, Any] = {}
    if payload.get("fields"):
        params["fields"] = str(payload.get("fields"))
    return _typed_google_request(profile, "sheets.get", payload, "GET", f"https://sheets.googleapis.com/v4/spreadsheets/{quote(spreadsheet_id, safe='')}", params=params)


def _sheets_update(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    spreadsheet_id = str(payload.get("spreadsheet_id") or "")
    range_a1 = str(payload.get("range_a1") or "")
    if not spreadsheet_id or not range_a1:
        raise ValueError("spreadsheet_id and range_a1 are required")
    value_input_option = str(payload.get("value_input_option") or "USER_ENTERED")
    return _typed_google_request(profile, "sheets.update", payload, "PUT", f"https://sheets.googleapis.com/v4/spreadsheets/{quote(spreadsheet_id, safe='')}/values/{quote(range_a1, safe='')}", params={"valueInputOption": value_input_option}, json_body={"range": range_a1, "majorDimension": "ROWS", "values": payload.get("values") or []})


def _sheets_clear(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    spreadsheet_id = str(payload.get("spreadsheet_id") or "")
    range_a1 = str(payload.get("range_a1") or "")
    if not spreadsheet_id or not range_a1:
        raise ValueError("spreadsheet_id and range_a1 are required")
    return _typed_google_request(profile, "sheets.update", payload, "POST", f"https://sheets.googleapis.com/v4/spreadsheets/{quote(spreadsheet_id, safe='')}/values/{quote(range_a1, safe='')}:clear", json_body={})


def _sheets_append(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    spreadsheet_id = str(payload.get("spreadsheet_id") or "")
    range_a1 = str(payload.get("range_a1") or "")
    if not spreadsheet_id or not range_a1:
        raise ValueError("spreadsheet_id and range_a1 are required")
    value_input_option = str(payload.get("value_input_option") or "USER_ENTERED")
    return _typed_google_request(profile, "sheets.append", payload, "POST", f"https://sheets.googleapis.com/v4/spreadsheets/{quote(spreadsheet_id, safe='')}/values/{quote(range_a1, safe='')}:append", params={"valueInputOption": value_input_option}, json_body={"range": range_a1, "majorDimension": "ROWS", "values": payload.get("values") or []})


def _sheets_batch_update(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    spreadsheet_id = str(payload.get("spreadsheet_id") or "")
    if not spreadsheet_id:
        raise ValueError("spreadsheet_id is required")
    return _typed_google_request(profile, "sheets.update", payload, "POST", f"https://sheets.googleapis.com/v4/spreadsheets/{quote(spreadsheet_id, safe='')}:batchUpdate", json_body={"requests": payload.get("requests") or []})


def _slides_get(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    presentation_id = str(payload.get("presentation_id") or "")
    if not presentation_id:
        raise ValueError("presentation_id is required")
    return _typed_google_request(profile, "slides.get", payload, "GET", f"https://slides.googleapis.com/v1/presentations/{quote(presentation_id, safe='')}")


def _slides_create(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    title = str(payload.get("title") or "")
    if not title:
        raise ValueError("title is required")
    return _typed_google_request(profile, "slides.create", payload, "POST", "https://slides.googleapis.com/v1/presentations", json_body={"title": title})


def _slides_batch_update(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    presentation_id = str(payload.get("presentation_id") or "")
    if not presentation_id:
        raise ValueError("presentation_id is required")
    return _typed_google_request(profile, "slides.update", payload, "POST", f"https://slides.googleapis.com/v1/presentations/{quote(presentation_id, safe='')}:batchUpdate", json_body={"requests": payload.get("requests") or []})


def _contacts_search(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    page_size = min(max(int(payload.get("page_size") or 10), 1), 30)
    params = {"pageSize": page_size, "personFields": "names,emailAddresses,phoneNumbers"}
    query = str(payload.get("query") or "")
    if query:
        params["query"] = query
        url = "https://people.googleapis.com/v1/people:searchContacts"
    else:
        url = "https://people.googleapis.com/v1/people/me/connections"
    return _typed_google_request(profile, "contacts.search", payload, "GET", url, params=params)


def _require(payload: dict[str, Any], *keys: str) -> list[str]:
    values: list[str] = []
    for key in keys:
        value = str(payload.get(key) or "").strip()
        if not value:
            raise ValueError(", ".join(keys) + " required")
        values.append(value)
    return values


def _normalize_workspace_tool_payload(tool: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Normalize upstream google_workspace_mcp parameter names for gateway execution.

    The governed MCP exposes upstream-style typed signatures, while this gateway
    historically executed compact REST-shaped payloads. Keep the governance layer
    as an adapter instead of forcing agents to know gateway-internal names.
    """
    normalized = dict(payload or {})

    if tool in {"manage_event", "manage_out_of_office", "manage_focus_time"}:
        if normalized.get("action") and not normalized.get("operation"):
            normalized["operation"] = normalized.get("action")
        if normalized.get("start_time") is not None and normalized.get("start") is None:
            normalized["start"] = normalized.get("start_time")
        if normalized.get("end_time") is not None and normalized.get("end") is None:
            normalized["end"] = normalized.get("end_time")
        if normalized.get("calendar_id") is not None and normalized.get("calendar") is None:
            normalized["calendar"] = normalized.get("calendar_id")

    if tool in {"query_freebusy", "get_events"}:
        if normalized.get("calendar_id") is not None and normalized.get("calendar") is None:
            normalized["calendar"] = normalized.get("calendar_id")

    if tool in {"read_sheet_values", "modify_sheet_values"}:
        if normalized.get("range_name") is not None and normalized.get("range_a1") is None:
            normalized["range_a1"] = normalized.get("range_name")
        if normalized.get("clear_values") is True and not normalized.get("operation"):
            normalized["operation"] = "clear"

    if tool in {"manage_drive_access", "set_drive_file_permissions"}:
        if normalized.get("action") and not normalized.get("operation"):
            normalized["operation"] = normalized.get("action")
        if normalized.get("share_with") is not None and normalized.get("email") is None:
            normalized["email"] = normalized.get("share_with")
        if normalized.get("share_type") is not None and normalized.get("type") is None:
            normalized["type"] = normalized.get("share_type")

    return normalized


def _workspace_tool_execute(profile: str, tool: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Execute a typed route mirroring taylorwilsdon/google_workspace_mcp tools.

    This is intentionally not a generic URL pass-through: every branch pins a
    known Google API endpoint and governance action from the canonical catalog.
    Unknown tools are rejected before any network call.
    """
    payload = _normalize_workspace_tool_payload(tool, payload)
    action = workspace_tool_action(tool)
    session = _session(profile, payload.get("token_route"))
    q = quote
    def req(method: str, url: str, *, params: dict[str, Any] | None = None, body: dict[str, Any] | None = None, data: str | None = None) -> dict[str, Any]:
        return _typed_google_request(profile, action, payload, method, url, params=params, json_body=body, data=data)

    # Calendar
    if tool == "list_calendars":
        return req("GET", "https://www.googleapis.com/calendar/v3/users/me/calendarList", params={"maxResults": int(payload.get("max_results") or 100)})
    if tool == "get_events":
        calendar = str(payload.get("calendar") or payload.get("calendar_id") or "primary")
        params = {"timeMin": str(payload.get("time_min") or payload.get("start") or ""), "timeMax": str(payload.get("time_max") or payload.get("end") or ""), "maxResults": int(payload.get("max_results") or 25), "singleEvents": "true", "orderBy": "startTime"}
        return req("GET", f"https://www.googleapis.com/calendar/v3/calendars/{q(calendar, safe='')}/events", params={k:v for k,v in params.items() if v != ""})
    if tool == "manage_event":
        raw_op = payload.get("operation") or payload.get("action_type") or payload.get("action") or payload.get("op")
        op = str(raw_op or "").strip().lower().replace("-", "_")
        op = {
            "insert": "create",
            "add": "create",
            "edit": "update",
            "modify": "update",
            "patch": "update",
            "remove": "delete",
            "cancel": "delete",
            "cancel_event": "delete",
            "delete_event": "delete",
        }.get(op, op)
        calendar = str(payload.get("calendar") or payload.get("calendar_id") or "primary")
        event_id = str(payload.get("event_id") or "").strip()
        if not op:
            # Fail closed: after removing legacy tools, callers sometimes send
            # event_id with an assumed delete/update intent. Defaulting that to
            # create produced junk duplicate events. Only bare no-event_id calls
            # may default to create for backward compatibility with upstream MCP.
            if event_id:
                raise ValueError("operation is required when event_id is provided; use operation=update or operation=delete")
            op = "create"
        if op not in {"create", "update", "delete"}:
            raise ValueError("operation/action must be create, update, or delete")
        body = payload.get("event") if isinstance(payload.get("event"), dict) else {k: payload[k] for k in ("summary","location","description","start","end","attendees","eventType","outOfOfficeProperties","focusTimeProperties") if k in payload}
        body = dict(body or {})
        for time_key in ("start", "end"):
            if isinstance(body.get(time_key), str):
                body[time_key] = {"dateTime": body[time_key]}
        if isinstance(body.get("attendees"), list):
            body["attendees"] = [{"email": a} if isinstance(a, str) else a for a in body["attendees"]]
        if op == "create":
            return req("POST", f"https://www.googleapis.com/calendar/v3/calendars/{q(calendar, safe='')}/events", body=body)
        if not event_id:
            raise ValueError("event_id required")
        if op == "update":
            if not body:
                raise ValueError("at least one update field is required")
            return req("PATCH", f"https://www.googleapis.com/calendar/v3/calendars/{q(calendar, safe='')}/events/{q(event_id, safe='')}", body=body)
        return req("DELETE", f"https://www.googleapis.com/calendar/v3/calendars/{q(calendar, safe='')}/events/{q(event_id, safe='')}")
    if tool == "create_calendar":
        summary = str(payload.get("summary") or payload.get("name") or "").strip()
        if not summary: raise ValueError("summary required")
        return req("POST", "https://www.googleapis.com/calendar/v3/calendars", body={"summary": summary, **({"description": payload.get("description")} if payload.get("description") else {})})
    if tool == "query_freebusy":
        return req("POST", "https://www.googleapis.com/calendar/v3/freeBusy", body={"timeMin": payload.get("time_min") or payload.get("start"), "timeMax": payload.get("time_max") or payload.get("end"), "items": [{"id": c} for c in (payload.get("calendar_ids") or ["primary"])]})
    if tool in {"manage_out_of_office", "manage_focus_time"}:
        payload = {**payload, "event": {**(payload.get("event") if isinstance(payload.get("event"), dict) else {}), "eventType": "outOfOffice" if tool == "manage_out_of_office" else "focusTime"}}
        return _workspace_tool_execute(profile, "manage_event", payload)

    # Gmail
    if tool == "search_gmail_messages":
        return req("GET", "https://gmail.googleapis.com/gmail/v1/users/me/messages", params={"q": str(payload.get("query") or ""), "maxResults": int(payload.get("max_results") or 10)})
    if tool == "get_gmail_message_content":
        mid, = _require(payload, "message_id")
        return req("GET", f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{q(mid, safe='')}", params={"format": str(payload.get("fmt") or payload.get("format") or "full")})
    if tool == "get_gmail_messages_content_batch":
        return {"items": [_workspace_tool_execute(profile, "get_gmail_message_content", {**payload, "message_id": mid}) for mid in payload.get("message_ids", [])]}
    if tool == "get_gmail_thread_content":
        tid, = _require(payload, "thread_id")
        return req("GET", f"https://gmail.googleapis.com/gmail/v1/users/me/threads/{q(tid, safe='')}", params={"format": str(payload.get("fmt") or payload.get("format") or "full")})
    if tool == "get_gmail_threads_content_batch":
        return {"items": [_workspace_tool_execute(profile, "get_gmail_thread_content", {**payload, "thread_id": tid}) for tid in payload.get("thread_ids", [])]}
    if tool == "modify_gmail_message_labels":
        mid, = _require(payload, "message_id")
        return req("POST", f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{q(mid, safe='')}/modify", body={"addLabelIds": payload.get("add_label_ids") or [], "removeLabelIds": payload.get("remove_label_ids") or []})
    if tool == "batch_modify_gmail_message_labels":
        return req("POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/batchModify", body={"ids": payload.get("message_ids") or [], "addLabelIds": payload.get("add_label_ids") or [], "removeLabelIds": payload.get("remove_label_ids") or []})
    if tool == "list_gmail_labels":
        return req("GET", "https://gmail.googleapis.com/gmail/v1/users/me/labels")
    if tool == "manage_gmail_label":
        op = str(payload.get("operation") or "create").lower(); label_id = str(payload.get("label_id") or "")
        body = payload.get("label") if isinstance(payload.get("label"), dict) else {k: payload[k] for k in ("name","labelListVisibility","messageListVisibility") if k in payload}
        if op == "create": return req("POST", "https://gmail.googleapis.com/gmail/v1/users/me/labels", body=body)
        if not label_id: raise ValueError("label_id required")
        if op in {"update", "patch"}: return req("PATCH", f"https://gmail.googleapis.com/gmail/v1/users/me/labels/{q(label_id, safe='')}", body=body)
        if op == "delete": return req("DELETE", f"https://gmail.googleapis.com/gmail/v1/users/me/labels/{q(label_id, safe='')}")
    if tool == "list_gmail_filters":
        return req("GET", "https://gmail.googleapis.com/gmail/v1/users/me/settings/filters")
    if tool == "manage_gmail_filter":
        op = str(payload.get("operation") or "create").lower(); filter_id=str(payload.get("filter_id") or "")
        if op == "create": return req("POST", "https://gmail.googleapis.com/gmail/v1/users/me/settings/filters", body=payload.get("filter") if isinstance(payload.get("filter"), dict) else {})
        if op == "delete" and filter_id: return req("DELETE", f"https://gmail.googleapis.com/gmail/v1/users/me/settings/filters/{q(filter_id, safe='')}")
        raise ValueError("operation create/delete and filter_id for delete required")
    if tool in {"draft_gmail_message", "send_gmail_message"}:
        to=str(payload.get("to") or "").strip(); subject=str(payload.get("subject") or ""); body_txt=str(payload.get("body") or "")
        if not to: raise ValueError("to required")
        msg = MIMEText(body_txt, "html" if payload.get("html") else "plain"); msg["To"]=to; msg["Subject"]=subject
        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")
        if tool == "draft_gmail_message": return req("POST", "https://gmail.googleapis.com/gmail/v1/users/me/drafts", body={"message":{"raw":raw}})
        return req("POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/send", body={"raw":raw})
    if tool == "start_google_auth":
        raise ValueError("OAuth setup is managed by the governance UI, not by agent tools")

    # Drive
    if tool == "search_drive_files":
        return req("GET", "https://www.googleapis.com/drive/v3/files", params={"q": str(payload.get("query") or "trashed = false"), "pageSize": int(payload.get("page_size") or 10), "fields": "files(id,name,mimeType,modifiedTime,webViewLink,webContentLink),nextPageToken"})
    if tool in {"get_drive_file_content", "get_drive_file_download_url"}:
        fid, = _require(payload, "file_id")
        if tool == "get_drive_file_download_url": return req("GET", f"https://www.googleapis.com/drive/v3/files/{q(fid, safe='')}", params={"fields":"id,name,mimeType,webContentLink,webViewLink,exportLinks"})
        if payload.get("mime_type"): return req("GET", f"https://www.googleapis.com/drive/v3/files/{q(fid, safe='')}/export", params={"mimeType": str(payload.get("mime_type"))})
        return req("GET", f"https://www.googleapis.com/drive/v3/files/{q(fid, safe='')}", params={"alt":"media"})
    if tool in {"create_drive_file", "create_drive_folder", "import_to_google_doc", "import_to_google_slides", "import_to_google_sheets"}:
        name=str(payload.get("name") or payload.get("title") or "").strip();
        if not name: raise ValueError("name required")
        mime={"create_drive_folder":"application/vnd.google-apps.folder","import_to_google_doc":"application/vnd.google-apps.document","import_to_google_slides":"application/vnd.google-apps.presentation","import_to_google_sheets":"application/vnd.google-apps.spreadsheet"}.get(tool, str(payload.get("mime_type") or "application/octet-stream"))
        body={"name":name,"mimeType":mime};
        if payload.get("parent_id"): body["parents"]=[str(payload.get("parent_id"))]
        return req("POST", "https://www.googleapis.com/drive/v3/files", body=body)
    if tool == "get_drive_shareable_link":
        fid, = _require(payload,"file_id"); return req("GET", f"https://www.googleapis.com/drive/v3/files/{q(fid, safe='')}", params={"fields":"id,name,webViewLink,webContentLink"})
    if tool == "list_drive_items":
        folder=str(payload.get("folder_id") or "root"); query=str(payload.get("query") or f"'{folder}' in parents and trashed = false")
        return req("GET", "https://www.googleapis.com/drive/v3/files", params={"q":query,"pageSize":int(payload.get("page_size") or 50),"fields":"files(id,name,mimeType,parents,modifiedTime,webViewLink),nextPageToken"})
    if tool == "copy_drive_file":
        fid, = _require(payload,"file_id"); body={"name":str(payload.get("name") or payload.get("new_name") or "Copy")};
        if payload.get("parent_id"): body["parents"]=[str(payload.get("parent_id"))]
        return req("POST", f"https://www.googleapis.com/drive/v3/files/{q(fid, safe='')}/copy", body=body)
    if tool == "update_drive_file":
        fid, = _require(payload,"file_id"); body={k:payload[k] for k in ("name","description","mimeType","parents") if k in payload}
        return req("PATCH", f"https://www.googleapis.com/drive/v3/files/{q(fid, safe='')}", body=body)
    if tool in {"manage_drive_access", "set_drive_file_permissions"}:
        fid, = _require(payload,"file_id"); op=str(payload.get("operation") or "create").lower(); perm_id=str(payload.get("permission_id") or "")
        if op in {"create","grant","share"}: return req("POST", f"https://www.googleapis.com/drive/v3/files/{q(fid, safe='')}/permissions", params={"sendNotificationEmail": str(bool(payload.get("send_notification"))).lower()}, body={"type":payload.get("type") or "user", "role":payload.get("role") or "reader", **({"emailAddress":payload.get("email")} if payload.get("email") else {})})
        if op in {"update","patch"} and perm_id: return req("PATCH", f"https://www.googleapis.com/drive/v3/files/{q(fid, safe='')}/permissions/{q(perm_id, safe='')}", body={"role":payload.get("role") or "reader"})
        if op in {"delete","revoke"} and perm_id: return req("DELETE", f"https://www.googleapis.com/drive/v3/files/{q(fid, safe='')}/permissions/{q(perm_id, safe='')}")
        raise ValueError("valid permission operation required")
    if tool in {"get_drive_file_permissions", "check_drive_file_public_access"}:
        fid, = _require(payload,"file_id"); return req("GET", f"https://www.googleapis.com/drive/v3/files/{q(fid, safe='')}", params={"fields":"id,name,permissions,owners,parents,webViewLink"})

    # Docs/Sheets/Slides use native APIs and Drive helpers
    if tool in {"get_doc_content", "inspect_doc_structure"}: doc,=_require(payload,"document_id"); return req("GET", f"https://docs.googleapis.com/v1/documents/{q(doc, safe='')}")
    if tool == "create_doc": return req("POST", "https://docs.googleapis.com/v1/documents", body={"title": str(payload.get("title") or "Untitled")})
    if tool in {"modify_doc_text","find_and_replace_doc","insert_doc_elements","update_paragraph_style","insert_doc_image","update_doc_headers_footers","batch_update_doc","create_table_with_data","manage_doc_tab"}:
        doc,=_require(payload,"document_id"); return req("POST", f"https://docs.googleapis.com/v1/documents/{q(doc, safe='')}:batchUpdate", body={"requests": payload.get("requests") or []})
    if tool in {"search_docs", "list_docs_in_folder"}:
        query=str(payload.get("query") or "mimeType='application/vnd.google-apps.document' and trashed=false")
        if tool == "list_docs_in_folder" and payload.get("folder_id"): query=f"'{payload.get('folder_id')}' in parents and mimeType='application/vnd.google-apps.document' and trashed=false"
        return req("GET", "https://www.googleapis.com/drive/v3/files", params={"q": query, "pageSize": int(payload.get("page_size") or 20), "fields":"files(id,name,modifiedTime,webViewLink)"})
    if tool in {"get_doc_as_markdown","export_doc_to_pdf"}: doc,=_require(payload,"document_id"); return req("GET", f"https://www.googleapis.com/drive/v3/files/{q(doc, safe='')}/export", params={"mimeType": payload.get("mime_type") or ("text/markdown" if tool=="get_doc_as_markdown" else "application/pdf")})
    if tool == "debug_table_structure": return _workspace_tool_execute(profile,"inspect_doc_structure",payload)
    if tool in {"list_document_comments","list_spreadsheet_comments","list_presentation_comments"}: fid=str(payload.get("file_id") or payload.get("document_id") or payload.get("spreadsheet_id") or payload.get("presentation_id") or "");
    
    if tool in {"list_document_comments","list_spreadsheet_comments","list_presentation_comments"}:
        fid = str(payload.get("file_id") or payload.get("document_id") or payload.get("spreadsheet_id") or payload.get("presentation_id") or "")
        if not fid: raise ValueError("file/document/spreadsheet/presentation id required")
        return req("GET", f"https://www.googleapis.com/drive/v3/files/{q(fid, safe='')}/comments", params={"fields":"comments,nextPageToken"})
    if tool in {"manage_document_comment","manage_spreadsheet_comment","manage_presentation_comment"}:
        fid = str(payload.get("file_id") or payload.get("document_id") or payload.get("spreadsheet_id") or payload.get("presentation_id") or ""); op=str(payload.get("operation") or "create").lower(); cid=str(payload.get("comment_id") or "")
        if not fid: raise ValueError("file id required")
        if op in {"create","reply"}: return req("POST", f"https://www.googleapis.com/drive/v3/files/{q(fid, safe='')}/comments" + ((f"/{q(cid,safe='')}/replies") if op=="reply" and cid else ""), body={"content": str(payload.get("content") or payload.get("text") or "")})
        if op in {"update","resolve"} and cid: return req("PATCH", f"https://www.googleapis.com/drive/v3/files/{q(fid, safe='')}/comments/{q(cid, safe='')}", body={"content": payload.get("content"), **({"resolved": True} if op=="resolve" else {})})
        if op == "delete" and cid: return req("DELETE", f"https://www.googleapis.com/drive/v3/files/{q(fid, safe='')}/comments/{q(cid, safe='')}")
        raise ValueError("valid comment operation required")

    if tool == "read_sheet_values": sid, rng = _require(payload,"spreadsheet_id","range_a1"); return req("GET", f"https://sheets.googleapis.com/v4/spreadsheets/{q(sid, safe='')}/values/{q(rng, safe='')}")
    if tool == "modify_sheet_values":
        sid, rng = _require(payload,"spreadsheet_id","range_a1"); op=str(payload.get("operation") or "update").lower()
        if op == "clear": return req("POST", f"https://sheets.googleapis.com/v4/spreadsheets/{q(sid, safe='')}/values/{q(rng, safe='')}:clear", body={})
        return req("PUT", f"https://sheets.googleapis.com/v4/spreadsheets/{q(sid, safe='')}/values/{q(rng, safe='')}", params={"valueInputOption": payload.get("value_input_option") or "USER_ENTERED"}, body={"range":rng,"values":payload.get("values") or []})
    if tool == "create_spreadsheet": return req("POST", "https://sheets.googleapis.com/v4/spreadsheets", body={"properties":{"title":str(payload.get("title") or "Untitled")}})
    if tool == "list_spreadsheets": return _workspace_tool_execute(profile,"search_drive_files", {**payload, "query":"mimeType='application/vnd.google-apps.spreadsheet' and trashed=false"})
    if tool in {"get_spreadsheet_info","list_sheet_tables"}: sid,=_require(payload,"spreadsheet_id"); return req("GET", f"https://sheets.googleapis.com/v4/spreadsheets/{q(sid, safe='')}")
    if tool in {"format_sheet_range","create_sheet","move_sheet_rows","append_table_rows","manage_conditional_formatting"}: sid,=_require(payload,"spreadsheet_id"); return req("POST", f"https://sheets.googleapis.com/v4/spreadsheets/{q(sid, safe='')}:batchUpdate", body={"requests":payload.get("requests") or []})

    if tool == "create_presentation": return req("POST", "https://slides.googleapis.com/v1/presentations", body={"title":str(payload.get("title") or "Untitled")})
    if tool == "get_presentation": pid,=_require(payload,"presentation_id"); return req("GET", f"https://slides.googleapis.com/v1/presentations/{q(pid, safe='')}")
    if tool == "batch_update_presentation": pid,=_require(payload,"presentation_id"); return req("POST", f"https://slides.googleapis.com/v1/presentations/{q(pid, safe='')}:batchUpdate", body={"requests":payload.get("requests") or []})
    if tool == "get_page": pid, page_id = _require(payload,"presentation_id","page_id"); return req("GET", f"https://slides.googleapis.com/v1/presentations/{q(pid,safe='')}/pages/{q(page_id,safe='')}")
    if tool == "get_page_thumbnail": pid, page_id = _require(payload,"presentation_id","page_id"); return req("GET", f"https://slides.googleapis.com/v1/presentations/{q(pid,safe='')}/pages/{q(page_id,safe='')}/thumbnail")

    # Forms, Tasks, Contacts, Chat, Search, Apps Script
    if tool == "create_form": return req("POST", "https://forms.googleapis.com/v1/forms", body={"info":{"title":str(payload.get("title") or "Untitled")}})
    if tool == "get_form": fid,=_require(payload,"form_id"); return req("GET", f"https://forms.googleapis.com/v1/forms/{q(fid,safe='')}")
    if tool == "set_publish_settings": fid,=_require(payload,"form_id"); return req("POST", f"https://forms.googleapis.com/v1/forms/{q(fid,safe='')}:setPublishSettings", body=payload.get("settings") if isinstance(payload.get("settings"),dict) else {})
    if tool == "get_form_response": fid,rid=_require(payload,"form_id","response_id"); return req("GET", f"https://forms.googleapis.com/v1/forms/{q(fid,safe='')}/responses/{q(rid,safe='')}")
    if tool == "list_form_responses": fid,=_require(payload,"form_id"); return req("GET", f"https://forms.googleapis.com/v1/forms/{q(fid,safe='')}/responses", params={"pageSize":int(payload.get("page_size") or 100)})
    if tool == "batch_update_form": fid,=_require(payload,"form_id"); return req("POST", f"https://forms.googleapis.com/v1/forms/{q(fid,safe='')}:batchUpdate", body={"requests":payload.get("requests") or []})
    if tool == "list_tasks": tl=str(payload.get("tasklist_id") or "@default"); return req("GET", f"https://tasks.googleapis.com/tasks/v1/lists/{q(tl,safe='')}/tasks")
    if tool == "get_task": tl,tid=_require(payload,"tasklist_id","task_id"); return req("GET", f"https://tasks.googleapis.com/tasks/v1/lists/{q(tl,safe='')}/tasks/{q(tid,safe='')}")
    if tool == "manage_task":
        tl=str(payload.get("tasklist_id") or "@default"); op=str(payload.get("operation") or "create").lower(); tid=str(payload.get("task_id") or "")
        body=payload.get("task") if isinstance(payload.get("task"),dict) else {k:payload[k] for k in ("title","notes","due","status") if k in payload}
        if op=="create": return req("POST", f"https://tasks.googleapis.com/tasks/v1/lists/{q(tl,safe='')}/tasks", body=body)
        if not tid: raise ValueError("task_id required")
        if op in {"update","patch"}: return req("PATCH", f"https://tasks.googleapis.com/tasks/v1/lists/{q(tl,safe='')}/tasks/{q(tid,safe='')}", body=body)
        if op=="delete": return req("DELETE", f"https://tasks.googleapis.com/tasks/v1/lists/{q(tl,safe='')}/tasks/{q(tid,safe='')}")
        if op=="move": return req("POST", f"https://tasks.googleapis.com/tasks/v1/lists/{q(tl,safe='')}/tasks/{q(tid,safe='')}/move", params={k:payload[k] for k in ("parent","previous") if k in payload})
    if tool == "list_task_lists": return req("GET", "https://tasks.googleapis.com/tasks/v1/users/@me/lists")
    if tool == "get_task_list": tl,=_require(payload,"tasklist_id"); return req("GET", f"https://tasks.googleapis.com/tasks/v1/users/@me/lists/{q(tl,safe='')}")
    if tool == "manage_task_list":
        op=str(payload.get("operation") or "create").lower(); tl=str(payload.get("tasklist_id") or ""); body={"title":str(payload.get("title") or "Untitled")}
        if op=="create": return req("POST", "https://tasks.googleapis.com/tasks/v1/users/@me/lists", body=body)
        if not tl: raise ValueError("tasklist_id required")
        if op in {"update","patch"}: return req("PATCH", f"https://tasks.googleapis.com/tasks/v1/users/@me/lists/{q(tl,safe='')}", body=body)
        if op=="delete": return req("DELETE", f"https://tasks.googleapis.com/tasks/v1/users/@me/lists/{q(tl,safe='')}")
        if op=="clear": return req("POST", f"https://tasks.googleapis.com/tasks/v1/lists/{q(tl,safe='')}/clear")
    if tool in {"search_contacts","list_contacts"}: return req("GET", "https://people.googleapis.com/v1/people/me/connections" if tool=="list_contacts" else "https://people.googleapis.com/v1/people:searchContacts", params={"query":str(payload.get("query") or ""),"pageSize":int(payload.get("page_size") or 10),"personFields":"names,emailAddresses,phoneNumbers,organizations"})
    if tool == "get_contact": rid,=_require(payload,"resource_name"); return req("GET", f"https://people.googleapis.com/v1/{rid}", params={"personFields":"names,emailAddresses,phoneNumbers,organizations"})
    if tool == "manage_contact":
        op = str(payload.get("operation") or "create").lower()
        person = payload.get("person") if isinstance(payload.get("person"), dict) else {k: payload[k] for k in ("names", "emailAddresses", "phoneNumbers", "organizations") if k in payload}
        resource_name = str(payload.get("resource_name") or "")
        if op == "create":
            return req("POST", "https://people.googleapis.com/v1/people:createContact", body=person)
        if not resource_name:
            raise ValueError("resource_name required")
        if op in {"update", "patch"}:
            return req("PATCH", f"https://people.googleapis.com/v1/{resource_name}:updateContact", params={"updatePersonFields": str(payload.get("update_person_fields") or "names,emailAddresses,phoneNumbers,organizations")}, body=person)
        if op == "delete":
            return req("DELETE", f"https://people.googleapis.com/v1/{resource_name}:deleteContact")
        raise ValueError("operation must be create, update, or delete")
    if tool == "list_contact_groups": return req("GET", "https://people.googleapis.com/v1/contactGroups")
    if tool == "get_contact_group": gid,=_require(payload,"resource_name"); return req("GET", f"https://people.googleapis.com/v1/{gid}")
    if tool == "manage_contacts_batch":
        op = str(payload.get("operation") or "create").lower()
        if op == "create":
            return req("POST", "https://people.googleapis.com/v1/people:batchCreateContacts", body={"contacts": payload.get("contacts") or []})
        if op in {"update", "patch"}:
            return req("POST", "https://people.googleapis.com/v1/people:batchUpdateContacts", params={"updateMask": str(payload.get("update_mask") or "names,emailAddresses,phoneNumbers,organizations")}, body={"contacts": payload.get("contacts") or {}})
        if op == "delete":
            return req("POST", "https://people.googleapis.com/v1/people:batchDeleteContacts", body={"resourceNames": payload.get("resource_names") or []})
        raise ValueError("operation must be create, update, or delete")
    if tool == "manage_contact_group":
        op = str(payload.get("operation") or "create").lower()
        resource_name = str(payload.get("resource_name") or "")
        if op == "create":
            return req("POST", "https://people.googleapis.com/v1/contactGroups", body={"contactGroup": payload.get("contact_group") if isinstance(payload.get("contact_group"), dict) else {"name": str(payload.get("name") or "New group")}})
        if not resource_name:
            raise ValueError("resource_name required")
        if op in {"update", "patch"}:
            return req("PUT", f"https://people.googleapis.com/v1/{resource_name}", body={"contactGroup": payload.get("contact_group") if isinstance(payload.get("contact_group"), dict) else {"name": str(payload.get("name") or "")}})
        if op == "delete":
            return req("DELETE", f"https://people.googleapis.com/v1/{resource_name}", params={"deleteContacts": str(bool(payload.get("delete_contacts"))).lower()})
        if op in {"modify_members", "membership"}:
            return req("POST", f"https://people.googleapis.com/v1/{resource_name}/members:modify", body={"resourceNamesToAdd": payload.get("resource_names_to_add") or [], "resourceNamesToRemove": payload.get("resource_names_to_remove") or []})
        raise ValueError("operation must be create, update, delete, or modify_members")
    if tool == "list_spaces": return req("GET", "https://chat.googleapis.com/v1/spaces")
    if tool == "get_messages": sid,=_require(payload,"space_name"); return req("GET", f"https://chat.googleapis.com/v1/{sid}/messages")
    if tool == "send_message": sid,=_require(payload,"space_name"); return req("POST", f"https://chat.googleapis.com/v1/{sid}/messages", body={"text":str(payload.get("text") or "")})
    if tool == "search_messages": return req("GET", "https://chat.googleapis.com/v1/spaces/-/messages:search", params={"query":str(payload.get("query") or "")})
    if tool == "create_reaction": mid,=_require(payload,"message_name"); return req("POST", f"https://chat.googleapis.com/v1/{mid}/reactions", body={"emoji":{"unicode":str(payload.get("emoji") or "👍")}})
    if tool == "download_chat_attachment": aname,=_require(payload,"attachment_name"); return req("GET", f"https://chat.googleapis.com/v1/media/{q(aname,safe='')}")
    if tool == "search_custom": return req("GET", "https://customsearch.googleapis.com/customsearch/v1", params={"q":str(payload.get("query") or ""),"cx":str(payload.get("cx") or payload.get("search_engine_id") or ""),"num":int(payload.get("num") or 10)})
    if tool == "get_search_engine_info": return req("GET", "https://customsearch.googleapis.com/customsearch/v1/siterestrict", params={"cx":str(payload.get("cx") or payload.get("search_engine_id") or "")})
    if tool == "list_script_projects": return req("GET", "https://script.googleapis.com/v1/projects")
    if tool == "get_script_project": sid,=_require(payload,"script_id"); return req("GET", f"https://script.googleapis.com/v1/projects/{q(sid,safe='')}")
    if tool == "get_script_content": sid,=_require(payload,"script_id"); return req("GET", f"https://script.googleapis.com/v1/projects/{q(sid,safe='')}/content")
    if tool == "create_script_project": return req("POST", "https://script.googleapis.com/v1/projects", body={"title":str(payload.get("title") or "Untitled")})
    if tool == "update_script_content": sid,=_require(payload,"script_id"); return req("PUT", f"https://script.googleapis.com/v1/projects/{q(sid,safe='')}/content", body={"files":payload.get("files") or []})
    if tool == "run_script_function": sid,=_require(payload,"script_id"); return req("POST", f"https://script.googleapis.com/v1/scripts/{q(sid,safe='')}:run", body={"function":str(payload.get("function") or payload.get("function_name") or ""),"parameters":payload.get("parameters") or []})
    if tool == "list_deployments": sid,=_require(payload,"script_id"); return req("GET", f"https://script.googleapis.com/v1/projects/{q(sid,safe='')}/deployments")
    if tool == "manage_deployment": sid,=_require(payload,"script_id"); op=str(payload.get("operation") or "create").lower(); did=str(payload.get("deployment_id") or "")
    if tool == "manage_deployment":
        if op=="create": return req("POST", f"https://script.googleapis.com/v1/projects/{q(sid,safe='')}/deployments", body=payload.get("deployment") if isinstance(payload.get("deployment"),dict) else {})
        if not did: raise ValueError("deployment_id required")
        if op in {"update","patch"}: return req("PUT", f"https://script.googleapis.com/v1/projects/{q(sid,safe='')}/deployments/{q(did,safe='')}", body=payload.get("deployment") if isinstance(payload.get("deployment"),dict) else {})
        if op=="delete": return req("DELETE", f"https://script.googleapis.com/v1/projects/{q(sid,safe='')}/deployments/{q(did,safe='')}")
    if tool == "list_script_processes": return req("GET", "https://script.googleapis.com/v1/processes")
    raise ValueError(f"unknown typed tool route: {tool}")

def _workspace_tool_route(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    tool = str(payload.get("_tool") or "")
    if not tool:
        raise ValueError("_tool required")
    return _workspace_tool_execute(profile, tool, payload)

def _governance_blocked(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Create/audit a pending approval request for high-risk governed surfaces."""
    started = time.monotonic()
    action = str(payload.get("action") or "google.blocked")
    resource_alias = str(payload.get("resource_alias") or resource_for(profile, action, payload))
    reason = str(payload.get("reason") or "approval workflow required before execution")
    approval = _create_approval_request(profile, action, resource_alias, reason, payload)
    safe_fields = _approval_safe_metadata(payload)
    _audit_observed(profile, action, "approval_required", payload, resource_alias, reason=reason, approval_id=approval["approval_id"], latency_ms=(time.monotonic() - started) * 1000, **safe_fields)
    return {
        "status": "approval_required",
        "action": action,
        "resource_alias": resource_alias,
        "reason": reason,
        "approval_id": approval["approval_id"],
        "approval_state": approval.get("state", "pending"),
        "approval_expires_at": approval.get("expires_at"),
        "retry_after_approval": _approval_retry_payload(profile, action, resource_alias, payload, approval),
        "agent_instruction": "Ask the user to approve this in the Governance UI, then say 'try again'. Keep retry_after_approval.retry_payload for that retry.",
    }


def _execute_high_risk_action(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    action = str(payload.get("action") or "")
    session = _session(profile, payload.get("token_route"))
    if action == "calendar.delete":
        calendar = str(payload.get("calendar") or "primary")
        event_id = str(payload.get("event_id") or "")
        if not event_id:
            raise ValueError("event_id is required")
        resp = session.delete(f"https://www.googleapis.com/calendar/v3/calendars/{quote(calendar, safe='')}/events/{quote(event_id, safe='')}", timeout=60)
        return {"status_code": resp.status_code, "status": "deleted" if resp.status_code in {200, 204} else "error"}
    if action in {"gmail.send", "gmail.send_gmail_message"}:
        draft_id = str(payload.get("draft_id") or "")
        if draft_id:
            resp = session.post(f"https://gmail.googleapis.com/gmail/v1/users/me/drafts/{quote(draft_id, safe='')}/send", timeout=60)
        else:
            to = str(payload.get("to") or "").strip()
            subject = str(payload.get("subject") or "")
            body_txt = str(payload.get("body") or "")
            if not to:
                raise ValueError("to or draft_id is required")
            msg = MIMEText(body_txt, "html" if payload.get("html") or str(payload.get("body_format") or "").lower() == "html" else "plain")
            msg["To"] = to
            msg["Subject"] = subject
            raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("ascii")
            resp = session.post("https://gmail.googleapis.com/gmail/v1/users/me/messages/send", json={"raw": raw}, timeout=60)
        body = resp.json() if resp.content else {}
        return {"status_code": resp.status_code, "status": "sent" if resp.status_code < 400 else "error", "id": body.get("id", "")}
    if action == "drive.share":
        file_id = str(payload.get("file_id") or "")
        email = str(payload.get("email") or "")
        role = str(payload.get("role") or "reader")
        if not file_id or not email:
            raise ValueError("file_id and email are required")
        body = {"type": "user", "role": role, "emailAddress": email}
        resp = session.post(f"https://www.googleapis.com/drive/v3/files/{quote(file_id, safe='')}/permissions", params={"sendNotificationEmail": "false"}, json=body, timeout=60)
        out = resp.json() if resp.content else {}
        return {"status_code": resp.status_code, "status": "shared" if resp.status_code < 400 else "error", "permission_id": out.get("id", "")}
    if action == "drive.delete":
        file_id = str(payload.get("file_id") or "")
        if not file_id:
            raise ValueError("file_id is required")
        resp = session.delete(f"https://www.googleapis.com/drive/v3/files/{quote(file_id, safe='')}", timeout=60)
        return {"status_code": resp.status_code, "status": "deleted" if resp.status_code in {200, 204} else "error"}
    raise ValueError(f"unsupported approved action: {action}")


def _governance_execute_approved(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Execute a high-risk Google action after a one-time human approval."""
    started = time.monotonic()
    action = str(payload.get("action") or "")
    resource_alias = str(payload.get("resource_alias") or resource_for(profile, action, payload))
    approval = _approval_for_execution(payload)
    try:
        result = _execute_high_risk_action(profile, {k: v for k, v in payload.items() if k != "approval_id"})
        status = "ok" if int(result.get("status_code") or 200) < 400 else "error"
        _mark_approval_consumed(str(payload["approval_id"]), action)
        _audit_observed(profile, action, status, payload, resource_alias, approval_id=payload["approval_id"], approved_by=approval.get("approver"), latency_ms=(time.monotonic() - started) * 1000, **_approval_safe_metadata(payload))
        return {"status": "executed" if status == "ok" else "error", "approval_id": payload["approval_id"], "action": action, "resource_alias": resource_alias, "result": result}
    except Exception as exc:
        _append_approval_event({"event": "execution_failed", "approval_id": str(payload.get("approval_id") or ""), "action": action, "error": type(exc).__name__})
        _audit_observed(profile, action, "error", payload, resource_alias, approval_id=payload.get("approval_id"), error=type(exc).__name__, latency_ms=(time.monotonic() - started) * 1000, **_approval_safe_metadata(payload))
        raise


def _google_request_action(method: str, url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    host = parsed.netloc
    path = parsed.path
    method = method.upper()
    if host == "sheets.googleapis.com":
        resource = "sheet_example_tracker"
        if method == "GET": return "sheets.get", resource
        if method == "POST" and ":append" in path: return "sheets.append", resource
        return "sheets.update", resource
    if host == "docs.googleapis.com":
        if method == "GET": return "docs.get", "docs_unknown"
        if method == "POST" and path.rstrip("/") == "/v1/documents": return "docs.create", "docs_unknown"
        return "docs.update", "docs_unknown"
    if host == "slides.googleapis.com":
        if method == "GET": return "slides.get", "slides_unknown"
        if method == "POST" and path.rstrip("/") == "/v1/presentations": return "slides.create", "slides_unknown"
        return "slides.update", "slides_unknown"
    if host == "people.googleapis.com": return "contacts.search", "contacts_personal"
    if host == "gmail.googleapis.com":
        if "/drafts" in path: return "gmail.draft", "gmail_inbox"
        if "/attachments/" in path: return "gmail.attachments.get", "gmail_inbox"
        if path.endswith("/modify"): return "gmail.modify", "gmail_inbox"
        return "gmail.get" if "/messages/" in path else "gmail.search", "gmail_inbox"
    if host == "www.googleapis.com" and path.startswith("/calendar/v3/calendars/"):
        action = {"GET": "calendar.list", "POST": "calendar.create", "PATCH": "calendar.update", "PUT": "calendar.update", "DELETE": "calendar.delete"}.get(method, "calendar.request")
        if "/events/" in path and method == "GET": action = "calendar.get"
        return action, "calendar_primary"
    if host == "www.googleapis.com" and path.startswith("/calendar/v3/freeBusy"):
        return "calendar.freebusy", "calendar_primary"
    if host == "www.googleapis.com" and path.startswith("/upload/drive/v3/files"): return "drive.upload", "drive_any"
    if host == "www.googleapis.com" and path.startswith("/drive/v3/files"):
        if method == "DELETE": return "drive.delete", "drive_any"
        if "/export" in path: return "drive.download", "drive_any"
        if "/copy" in path: return "drive.copy", "drive_any"
        if method == "GET": return ("drive.search" if path.rstrip("/") == "/drive/v3/files" else "drive.get"), "drive_any"
        if method == "POST": return "drive.create", "drive_any"
        return "drive.update", "drive_any"
    return "google.request", "unknown"


def _is_allowed_google_url(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return False
    return any(parsed.path.startswith(prefix) for prefix in ALLOWED_HOST_PATH_PREFIXES.get(parsed.netloc, []))


def _google_request(profile: str, payload: dict[str, Any]) -> dict[str, Any]:
    started = time.monotonic()
    if not _profile_config(profile).get("generic_google_request"):
        raise ValueError(f"generic google request not enabled for {profile}")
    method = str(payload.get("method") or "GET").upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError("method not allowed")
    url = str(payload.get("url") or "")
    if not _is_allowed_google_url(url):
        raise ValueError("google url not allowed")
    session = _session(profile, payload.get("token_route"))
    resp = session.request(method, url, params=payload.get("params") or None, headers=payload.get("headers") or None, json=payload.get("json") if "json" in payload else None, data=payload.get("data") if "data" in payload else None, timeout=min(int(payload.get("timeout") or 60), 180))
    content_type = resp.headers.get("content-type", "")
    body: dict[str, Any] = {"status_code": resp.status_code, "headers": {"content-type": content_type}}
    if "application/json" in content_type:
        body["json"] = resp.json() if resp.content else None
    elif content_type.startswith("text/"):
        body["text"] = resp.text
    else:
        body["content_b64"] = base64.b64encode(resp.content).decode("ascii")
    observed_action, _generic_resource = _google_request_action(method, url)
    observed_resource = str(payload.get("resource_alias") or resource_for(profile, observed_action, payload))
    _audit_observed(profile, observed_action, "ok" if resp.status_code < 400 else "error", payload, observed_resource, method=method, host=urlparse(url).netloc, path_sha256=hashlib.sha256(urlparse(url).path.encode()).hexdigest(), status_code=resp.status_code, latency_ms=(time.monotonic() - started) * 1000)
    return body


ROUTES = {
    "/v1/gmail/search": _gmail_search,
    "/v1/gmail/draft": _gmail_draft,
    "/v1/gmail/get": _gmail_get,
    "/v1/gmail/attachment": _gmail_get_attachment,
    "/v1/gmail/modify": _gmail_modify,
    "/v1/calendar/list": _calendar_list,
    "/v1/calendar/create": _calendar_create,
    "/v1/calendar/get": _calendar_get,
    "/v1/calendar/update": _calendar_update,
    "/v1/calendar/freebusy": _calendar_freebusy,
    "/v1/drive/search": _drive_search,
    "/v1/drive/get": _drive_get,
    "/v1/drive/export": _drive_export,
    "/v1/drive/copy": _drive_copy,
    "/v1/drive/create": _drive_create,
    "/v1/docs/get": _docs_get,
    "/v1/docs/create": _docs_create,
    "/v1/docs/batch_update": _docs_batch_update,
    "/v1/sheets/get": _sheets_get,
    "/v1/sheets/metadata": _sheets_metadata,
    "/v1/sheets/update": _sheets_update,
    "/v1/sheets/append": _sheets_append,
    "/v1/sheets/clear": _sheets_clear,
    "/v1/sheets/batch_update": _sheets_batch_update,
    "/v1/slides/get": _slides_get,
    "/v1/slides/create": _slides_create,
    "/v1/slides/batch_update": _slides_batch_update,
    "/v1/contacts/search": _contacts_search,
    "/v1/tools/list_calendars": _workspace_tool_route,
    "/v1/tools/get_events": _workspace_tool_route,
    "/v1/tools/manage_event": _workspace_tool_route,
    "/v1/tools/create_calendar": _workspace_tool_route,
    "/v1/tools/query_freebusy": _workspace_tool_route,
    "/v1/tools/manage_out_of_office": _workspace_tool_route,
    "/v1/tools/manage_focus_time": _workspace_tool_route,
    "/v1/tools/search_drive_files": _workspace_tool_route,
    "/v1/tools/get_drive_file_content": _workspace_tool_route,
    "/v1/tools/get_drive_file_download_url": _workspace_tool_route,
    "/v1/tools/create_drive_file": _workspace_tool_route,
    "/v1/tools/create_drive_folder": _workspace_tool_route,
    "/v1/tools/import_to_google_doc": _workspace_tool_route,
    "/v1/tools/import_to_google_slides": _workspace_tool_route,
    "/v1/tools/import_to_google_sheets": _workspace_tool_route,
    "/v1/tools/get_drive_shareable_link": _workspace_tool_route,
    "/v1/tools/list_drive_items": _workspace_tool_route,
    "/v1/tools/copy_drive_file": _workspace_tool_route,
    "/v1/tools/update_drive_file": _workspace_tool_route,
    "/v1/tools/manage_drive_access": _workspace_tool_route,
    "/v1/tools/set_drive_file_permissions": _workspace_tool_route,
    "/v1/tools/get_drive_file_permissions": _workspace_tool_route,
    "/v1/tools/check_drive_file_public_access": _workspace_tool_route,
    "/v1/tools/search_gmail_messages": _workspace_tool_route,
    "/v1/tools/get_gmail_message_content": _workspace_tool_route,
    "/v1/tools/get_gmail_messages_content_batch": _workspace_tool_route,
    "/v1/tools/send_gmail_message": _workspace_tool_route,
    "/v1/tools/get_gmail_thread_content": _workspace_tool_route,
    "/v1/tools/modify_gmail_message_labels": _workspace_tool_route,
    "/v1/tools/list_gmail_labels": _workspace_tool_route,
    "/v1/tools/list_gmail_filters": _workspace_tool_route,
    "/v1/tools/manage_gmail_label": _workspace_tool_route,
    "/v1/tools/manage_gmail_filter": _workspace_tool_route,
    "/v1/tools/draft_gmail_message": _workspace_tool_route,
    "/v1/tools/get_gmail_threads_content_batch": _workspace_tool_route,
    "/v1/tools/batch_modify_gmail_message_labels": _workspace_tool_route,
    "/v1/tools/start_google_auth": _workspace_tool_route,
    "/v1/tools/get_doc_content": _workspace_tool_route,
    "/v1/tools/create_doc": _workspace_tool_route,
    "/v1/tools/modify_doc_text": _workspace_tool_route,
    "/v1/tools/search_docs": _workspace_tool_route,
    "/v1/tools/find_and_replace_doc": _workspace_tool_route,
    "/v1/tools/list_docs_in_folder": _workspace_tool_route,
    "/v1/tools/insert_doc_elements": _workspace_tool_route,
    "/v1/tools/update_paragraph_style": _workspace_tool_route,
    "/v1/tools/get_doc_as_markdown": _workspace_tool_route,
    "/v1/tools/insert_doc_image": _workspace_tool_route,
    "/v1/tools/update_doc_headers_footers": _workspace_tool_route,
    "/v1/tools/batch_update_doc": _workspace_tool_route,
    "/v1/tools/inspect_doc_structure": _workspace_tool_route,
    "/v1/tools/export_doc_to_pdf": _workspace_tool_route,
    "/v1/tools/create_table_with_data": _workspace_tool_route,
    "/v1/tools/debug_table_structure": _workspace_tool_route,
    "/v1/tools/list_document_comments": _workspace_tool_route,
    "/v1/tools/manage_document_comment": _workspace_tool_route,
    "/v1/tools/manage_doc_tab": _workspace_tool_route,
    "/v1/tools/read_sheet_values": _workspace_tool_route,
    "/v1/tools/modify_sheet_values": _workspace_tool_route,
    "/v1/tools/create_spreadsheet": _workspace_tool_route,
    "/v1/tools/list_spreadsheets": _workspace_tool_route,
    "/v1/tools/get_spreadsheet_info": _workspace_tool_route,
    "/v1/tools/format_sheet_range": _workspace_tool_route,
    "/v1/tools/list_sheet_tables": _workspace_tool_route,
    "/v1/tools/create_sheet": _workspace_tool_route,
    "/v1/tools/move_sheet_rows": _workspace_tool_route,
    "/v1/tools/append_table_rows": _workspace_tool_route,
    "/v1/tools/list_spreadsheet_comments": _workspace_tool_route,
    "/v1/tools/manage_spreadsheet_comment": _workspace_tool_route,
    "/v1/tools/manage_conditional_formatting": _workspace_tool_route,
    "/v1/tools/create_presentation": _workspace_tool_route,
    "/v1/tools/get_presentation": _workspace_tool_route,
    "/v1/tools/batch_update_presentation": _workspace_tool_route,
    "/v1/tools/get_page": _workspace_tool_route,
    "/v1/tools/get_page_thumbnail": _workspace_tool_route,
    "/v1/tools/list_presentation_comments": _workspace_tool_route,
    "/v1/tools/manage_presentation_comment": _workspace_tool_route,
    "/v1/tools/create_form": _workspace_tool_route,
    "/v1/tools/get_form": _workspace_tool_route,
    "/v1/tools/set_publish_settings": _workspace_tool_route,
    "/v1/tools/get_form_response": _workspace_tool_route,
    "/v1/tools/list_form_responses": _workspace_tool_route,
    "/v1/tools/batch_update_form": _workspace_tool_route,
    "/v1/tools/list_tasks": _workspace_tool_route,
    "/v1/tools/get_task": _workspace_tool_route,
    "/v1/tools/manage_task": _workspace_tool_route,
    "/v1/tools/list_task_lists": _workspace_tool_route,
    "/v1/tools/get_task_list": _workspace_tool_route,
    "/v1/tools/manage_task_list": _workspace_tool_route,
    "/v1/tools/search_contacts": _workspace_tool_route,
    "/v1/tools/get_contact": _workspace_tool_route,
    "/v1/tools/list_contacts": _workspace_tool_route,
    "/v1/tools/manage_contact": _workspace_tool_route,
    "/v1/tools/list_contact_groups": _workspace_tool_route,
    "/v1/tools/get_contact_group": _workspace_tool_route,
    "/v1/tools/manage_contacts_batch": _workspace_tool_route,
    "/v1/tools/manage_contact_group": _workspace_tool_route,
    "/v1/tools/list_spaces": _workspace_tool_route,
    "/v1/tools/get_messages": _workspace_tool_route,
    "/v1/tools/send_message": _workspace_tool_route,
    "/v1/tools/search_messages": _workspace_tool_route,
    "/v1/tools/create_reaction": _workspace_tool_route,
    "/v1/tools/download_chat_attachment": _workspace_tool_route,
    "/v1/tools/search_custom": _workspace_tool_route,
    "/v1/tools/get_search_engine_info": _workspace_tool_route,
    "/v1/tools/list_script_projects": _workspace_tool_route,
    "/v1/tools/get_script_project": _workspace_tool_route,
    "/v1/tools/get_script_content": _workspace_tool_route,
    "/v1/tools/create_script_project": _workspace_tool_route,
    "/v1/tools/update_script_content": _workspace_tool_route,
    "/v1/tools/run_script_function": _workspace_tool_route,
    "/v1/tools/list_deployments": _workspace_tool_route,
    "/v1/tools/manage_deployment": _workspace_tool_route,
    "/v1/tools/list_script_processes": _workspace_tool_route,
    "/v1/governance/blocked": _governance_blocked,
    "/v1/governance/approvals/list": _approval_list,
    "/v1/governance/approvals/decide": _approval_decide,
    "/v1/governance/approve-and-execute": _approval_approve_and_execute,
    "/v1/governance/execute-approved": _governance_execute_approved,
}


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentGoogleGovernance/3.0"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        if path == "/healthz":
            _json_response(self, 200, {"status": "ok", "service": "google-workspace-governance", "profiles": sorted(PROFILE_CONFIG), "token_root": str(TOKEN_ROOT), "token_db": str(TOKEN_DB_PATH)})
        elif path == "/metrics":
            _text_response(self, 200, _metrics_text(), "text/plain; version=0.0.4; charset=utf-8")
        elif path == "/v1/governance/approvals/telegram-decide":
            try:
                result = _telegram_decide_from_query(parse_qs(parsed.query))
                _text_response(self, 200, f"Google Workspace approval {result.get('status')}: {result.get('approval_id')}\n", "text/plain; charset=utf-8")
            except Exception as exc:
                _json_response(self, 403 if isinstance(exc, PermissionError) else 400, {"error": type(exc).__name__, "message": str(exc)})
        else:
            _json_response(self, 404, {"error": "not_found"})

    def do_POST(self) -> None:
        started = time.monotonic()
        action = self.path.strip("/").replace("v1/", "")
        profile = "unknown"
        payload: dict[str, Any] = {}
        try:
            parsed = urlparse(self.path)
            if parsed.path == "/v1/governance/approvals/telegram-webhook":
                length = int(self.headers.get("Content-Length", "0"))
                update = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
                result = _telegram_handle_update(update, parse_qs(parsed.query), dict(self.headers))
                _json_response(self, 200, result)
                return
            claims = _verify_jwt(self.headers.get("Authorization", ""))
            profile = str(claims["_profile"])
            length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(length).decode("utf-8") or "{}")
            requested_profile = str(payload.get("profile") or profile)
            if profile == "*":
                profile = requested_profile
                _profile_config(profile)
            elif payload.get("profile") and requested_profile != profile:
                raise ValueError("profile claim/body mismatch")
            _canonicalize_payload_token_route(profile, payload)
            fn = ROUTES.get(self.path)
            if not fn:
                _json_response(self, 404, {"error": "not_found"})
                return
            if self.path not in {"/v1/governance/approvals/list", "/v1/governance/approvals/decide", "/v1/governance/approve-and-execute", "/v1/governance/execute-approved"}:
                policy_action, policy_resource = _route_policy_context(self.path, profile, payload)
                enforcement = _enforce_acl(profile, policy_action, policy_resource, payload)
                if enforcement is not None:
                    _json_response(self, 200, enforcement)
                    return
            if self.path.startswith("/v1/tools/"):
                payload.setdefault("_tool", self.path.rsplit("/", 1)[-1])
            result = fn(profile, payload)
            _json_response(self, 200, result)
        except Exception as exc:
            try:
                observed_action = action or "unknown"
                observed_resource = str(payload.get("resource_alias") or "unknown")
                if self.path == "/v1/google/request" and payload.get("url"):
                    observed_action, _generic_resource = _google_request_action(str(payload.get("method") or "GET"), str(payload.get("url")))
                    observed_resource = str(payload.get("resource_alias") or resource_for(profile, observed_action, payload))
                _audit_observed(
                    profile,
                    observed_action,
                    "error",
                    payload,
                    observed_resource,
                    latency_ms=(time.monotonic() - started) * 1000,
                    error=type(exc).__name__,
                    payload=_redact_payload(payload),
                )
            except Exception:
                pass
            _json_response(self, 403 if isinstance(exc, PermissionError) else (500 if not isinstance(exc, ValueError) else 401), {"error": type(exc).__name__, "message": str(exc)})


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), Handler)
    _audit("gateway", "service.start", "ok", host=HOST, port=PORT, profiles=sorted(PROFILE_CONFIG))
    print(f"Unified Google Workspace governance gateway listening on {HOST}:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
