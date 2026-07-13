#!/usr/bin/env python3
"""Protected Google governance ACL, access log, and settings control plane.

This service defaults to localhost behind Authentik/NPM, but can be bound to
LAN when explicitly approved because it has app-level username/password auth.
It serves the browser GUI, displays live gateway access events, mutates the YAML
policy backend, installs the generated runtime policy snapshot, and restarts the
unified gateway when permissions change.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shlex
import shutil
import sqlite3
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.exceptions import InvalidSignature
except Exception:  # pragma: no cover - WebAuthn verification reports this at runtime.
    hashes = serialization = ec = padding = rsa = InvalidSignature = None

from google_workspace_action_catalog import GOOGLE_WORKSPACE_TOOL_CATALOG, workspace_actions_by_service

import yaml

BASE = Path(os.getenv("GOOGLE_GOVERNANCE_PROJECT_DIR", str(Path(__file__).resolve().parents[1])))
SELF_CONTAINED_BASE = Path(os.getenv("GOOGLE_GOVERNANCE_SELF_CONTAINED_DIR", str(BASE / ".google-governance")))
STATE_BASE = Path(os.getenv("GOOGLE_GOVERNANCE_STATE_DIR", str(SELF_CONTAINED_BASE / "state")))
CONFIG_BASE = Path(os.getenv("GOOGLE_GOVERNANCE_CONFIG_DIR", str(SELF_CONTAINED_BASE / "config")))
LOG_BASE = Path(os.getenv("GOOGLE_GOVERNANCE_LOG_DIR", str(SELF_CONTAINED_BASE / "logs")))
RUNTIME_BASE = Path(os.getenv("GOOGLE_GOVERNANCE_RUNTIME_DIR", str(SELF_CONTAINED_BASE / "runtime")))
DB_BASE = Path(os.getenv("GOOGLE_GOVERNANCE_DB_DIR", str(BASE / "database")))
POLICY_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_POLICY_YAML", str(STATE_BASE / "policy/google-governance-policy.yaml")))
REGISTRY_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_REGISTRY_YAML", str(STATE_BASE / "policy/google-resource-registry.yaml")))
GENERATED_POLICY_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_GENERATED_POLICY_JSON", str(STATE_BASE / "policy/generated_profile_policy.json")))
RUNTIME_POLICY_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_RUNTIME_POLICY_JSON", str(STATE_BASE / "policy/profile_policy.json")))
APPROVAL_SECRET_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_APPROVAL_ADMIN_SECRET_PATH", str(CONFIG_BASE / "approval_admin_secret")))
APPROVAL_STORE_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_APPROVAL_STORE", str(STATE_BASE / "approvals/approval-events.jsonl")))
GATEWAY_URL = os.getenv("GOOGLE_GOVERNANCE_URL", os.getenv("HERMES_GOOGLE_GOVERNANCE_URL", "http://127.0.0.1:8768")).rstrip("/")
GATEWAY_ACCESS_TOKEN = os.getenv("GOOGLE_GOVERNANCE_ACCESS_TOKEN") or os.getenv("HERMES_GOOGLE_GOVERNANCE_ACCESS_TOKEN")
CONTROL_HOST = os.getenv("GOOGLE_GOVERNANCE_CONTROL_HOST", "0.0.0.0")
CONTROL_PORT = int(os.getenv("GOOGLE_GOVERNANCE_CONTROL_PORT", "8095"))
GATEWAY_SERVICE = os.getenv("GOOGLE_GOVERNANCE_GATEWAY_SERVICE", "google-workspace-governance.service")
CONTROL_SERVICE = os.getenv("GOOGLE_GOVERNANCE_CONTROL_SERVICE", "google-workspace-governance-control.service")
PROFILE = os.getenv("GOOGLE_GOVERNANCE_PROFILE", os.getenv("HERMES_GOOGLE_GOVERNANCE_PROFILE", "reasoning"))
AUDIENCE = "google-workspace-governance"
CHANGE_LOG_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_POLICY_CHANGE_LOG", str(STATE_BASE / "policy/policy-change-events.jsonl")))
CONTROL_USERS_JSON_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_CONTROL_USERS_JSON_PATH", os.getenv("GOOGLE_GOVERNANCE_CONTROL_USERS_PATH", str(CONFIG_BASE / "control_users.json"))))
CONTROL_USERS_DB_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_CONTROL_USERS_DB_PATH", str(DB_BASE / "control.sqlite")))
CONTROL_OIDC_CONFIG_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_CONTROL_OIDC_CONFIG_PATH", str(CONFIG_BASE / "control_oidc.json")))
CONTROL_AUDIT_LOG_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_CONTROL_AUDIT_LOG", str(LOG_BASE / "control-audit.jsonl")))
GATEWAY_AUDIT_LOG_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_GATEWAY_AUDIT_LOG", str(LOG_BASE / "gateway-audit.jsonl")))
GOOGLE_WORKSPACE_TOKEN_ROOT = Path(os.getenv("GOOGLE_GOVERNANCE_TOKEN_ROOT") or os.getenv("GOOGLE_GOVERNANCE_ACCOUNT_TOKEN_ROOT", str(STATE_BASE / "tokens/accounts")))
GOOGLE_OAUTH_STATE_ROOT = Path(os.getenv("GOOGLE_GOVERNANCE_OAUTH_STATE_ROOT", str(STATE_BASE / "oauth")))
CONTROL_OIDC_STATE_ROOT = Path(os.getenv("GOOGLE_GOVERNANCE_CONTROL_OIDC_STATE_ROOT", str(STATE_BASE / "control-oidc")))
RUNTIME_BACKUP_ROOT = Path(os.getenv("GOOGLE_GOVERNANCE_RUNTIME_BACKUP_ROOT", str(STATE_BASE / "backups")))
RUNTIME_BACKUP_CRON_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_RUNTIME_BACKUP_CRON_PATH", str(STATE_BASE / "backups/runtime-backup.cron")))
INSTALLED_CONTROL_SOURCE_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_INSTALLED_CONTROL_SOURCE", str(RUNTIME_BASE / "google_governance_control_plane.py")))
GOOGLE_WORKSPACE_TOKEN_DB_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_TOKEN_DB_PATH", os.getenv("GOOGLE_GOVERNANCE_CONTROL_USERS_DB_PATH", str(DB_BASE / "control.sqlite"))))
GOOGLE_GOVERNANCE_RELOAD_MODE = os.getenv("GOOGLE_GOVERNANCE_RELOAD_MODE", "hot").strip().lower()
PRIVILEGED_APPLY_CMD = os.getenv("GOOGLE_GOVERNANCE_PRIVILEGED_APPLY_CMD", "")
CONTROL_LOGO_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_CONTROL_LOGO", str(BASE / "generated/ui/control-plane/google-agent-gateway-logo.jpg")))
CONTROL_LOGO_LIGHT_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_CONTROL_LOGO_LIGHT", str(BASE / "generated/ui/control-plane/google-agent-gateway-logo-light.png")))
CONTROL_LOGO_DARK_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_CONTROL_LOGO_DARK", str(BASE / "generated/ui/control-plane/google-agent-gateway-logo-dark.png")))
CONTROL_LOGIN_LOGO_DARK_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_CONTROL_LOGIN_LOGO_DARK", str(BASE / "generated/ui/control-plane/google-agent-gateway-logo-login-dark.png")))
CONTROL_USER_SETTINGS_ICON_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_CONTROL_USER_SETTINGS_ICON", str(BASE / "generated/ui/control-plane/user-settings-icon.png")))
CONTROL_LOGOUT_ICON_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_CONTROL_LOGOUT_ICON", str(BASE / "generated/ui/control-plane/logout-icon.png")))
CONTROL_AUTH_DISABLED = os.getenv("GOOGLE_GOVERNANCE_CONTROL_AUTH_DISABLED", "0").lower() in {"1", "true", "yes", "on"}
CONTROL_AUTH_REALM = os.getenv("GOOGLE_GOVERNANCE_CONTROL_AUTH_REALM", "Google Workspace Governance")
CONTROL_SESSION_SECRET_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_CONTROL_SESSION_SECRET_PATH", str(CONFIG_BASE / "control_session_secret")))
CONTROL_SESSION_TTL_SECONDS = int(os.getenv("GOOGLE_GOVERNANCE_CONTROL_SESSION_TTL_SECONDS", "43200"))
CONTROL_SETUP_TOKEN_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_CONTROL_SETUP_TOKEN_PATH", str(CONFIG_BASE / "control_setup_token")))
CONTROL_SETUP_TOKEN = os.getenv("GOOGLE_GOVERNANCE_CONTROL_SETUP_TOKEN", "")
HIGH_RISK_ACTIONS = {"gmail.send", "drive.share", "drive.delete", "calendar.delete"}
DISPLAY_TZ = ZoneInfo(os.getenv("GOOGLE_GOVERNANCE_DISPLAY_TZ", "America/Chicago"))
ALLOWED_DECISIONS = {"allow", "ask", "deny"}
ALLOWED_SCOPES = {"default", "override"}
GOOGLE_OAUTH_SCOPE_MAP = {
    "openid": "openid",
    "email": "email",
    "profile": "profile",
    "gmail": "https://www.googleapis.com/auth/gmail.modify",
    "calendar": "https://www.googleapis.com/auth/calendar",
    "drive": "https://www.googleapis.com/auth/drive",
    "sheets": "https://www.googleapis.com/auth/spreadsheets",
    "docs": "https://www.googleapis.com/auth/documents",
    "slides": "https://www.googleapis.com/auth/presentations",
    "forms": "https://www.googleapis.com/auth/forms.body",
    "tasks": "https://www.googleapis.com/auth/tasks",
    "people": "https://www.googleapis.com/auth/contacts",
    "chat": "https://www.googleapis.com/auth/chat.messages",
    "search": "https://www.googleapis.com/auth/cse",
    "apps_script": "https://www.googleapis.com/auth/script.projects",
}
GOOGLE_OAUTH_DEFAULT_SERVICES = ["openid", "email", "profile", "gmail", "calendar", "drive", "sheets", "docs", "slides", "forms", "tasks", "people", "chat", "search", "apps_script"]
GOOGLE_OAUTH_AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_OAUTH_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"

SENSITIVE_FIELD_RE = re.compile(r"(token|secret|password|authorization|credential|client_secret|refresh|access_token|id_token|code)", re.I)

def _redact_value(key: str, value: Any) -> Any:
    if SENSITIVE_FIELD_RE.search(str(key)):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): _redact_value(str(k), v) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(key, item) for item in value]
    return value

def _redact_payload(payload: Any) -> Any:
    if isinstance(payload, dict):
        return {str(key): _redact_value(str(key), value) for key, value in payload.items()}
    if isinstance(payload, list):
        return [_redact_payload(item) for item in payload]
    return payload



def _password_hash(password: str, *, salt: str | None = None, iterations: int = 240_000) -> str:
    if salt is None:
        salt = secrets.token_urlsafe(18)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations)
    return f"pbkdf2_sha256${iterations}${salt}${base64.b64encode(digest).decode('ascii')}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iterations_s, salt, digest_b64 = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        expected = base64.b64decode(digest_b64.encode("ascii"), validate=True)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), int(iterations_s))
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def _control_db() -> sqlite3.Connection:
    CONTROL_USERS_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(CONTROL_USERS_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            enabled INTEGER NOT NULL DEFAULT 1,
            first_name TEXT NOT NULL DEFAULT '',
            last_name TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            avatar_url TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    # Migrations for older SQLite stores.
    cols = {row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()}
    if "first_name" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN first_name TEXT NOT NULL DEFAULT ''")
    if "last_name" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN last_name TEXT NOT NULL DEFAULT ''")
    if "email" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''")
    if "avatar_url" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN avatar_url TEXT NOT NULL DEFAULT ''")
    if "totp_secret" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN totp_secret TEXT NOT NULL DEFAULT ''")
    if "totp_enabled" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS webauthn_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            credential_id TEXT NOT NULL UNIQUE,
            public_key_der TEXT NOT NULL,
            sign_count INTEGER NOT NULL DEFAULT 0,
            label TEXT NOT NULL DEFAULT 'YubiKey',
            kind TEXT NOT NULL DEFAULT 'passkey',
            transports TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            last_used_at TEXT NOT NULL DEFAULT ''
        )
        """
    )
    webauthn_cols = {row[1] for row in conn.execute("PRAGMA table_info(webauthn_credentials)").fetchall()}
    if "kind" not in webauthn_cols:
        conn.execute("ALTER TABLE webauthn_credentials ADD COLUMN kind TEXT NOT NULL DEFAULT 'passkey'")
    conn.execute("UPDATE webauthn_credentials SET kind='passkey' WHERE kind IS NULL OR kind=''")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS twofa_challenges (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            kind TEXT NOT NULL,
            payload_json TEXT NOT NULL DEFAULT '{}',
            expires_at INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    # Rename the original local admin login to Admin's canonical login when safe.
    existing = {row[0] for row in conn.execute("SELECT username FROM users").fetchall()}
    if "legacy_admin" in existing and "admin" not in existing:
        conn.execute(
            "UPDATE users SET username=?, first_name=COALESCE(NULLIF(first_name,''),'Admin'), last_name=COALESCE(NULLIF(last_name,''),'User'), updated_at=CURRENT_TIMESTAMP WHERE username=?",
            ("admin", "legacy_admin"),
        )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS change_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            event TEXT NOT NULL,
            actor TEXT,
            payload_json TEXT NOT NULL
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS workspace_access_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT NOT NULL,
            actor TEXT NOT NULL,
            profile TEXT NOT NULL DEFAULT '',
            account_alias TEXT NOT NULL,
            scopes TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'requested',
            state TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    req_cols = {row[1] for row in conn.execute("PRAGMA table_info(workspace_access_requests)").fetchall()}
    for col, ddl in {
        "state": "ALTER TABLE workspace_access_requests ADD COLUMN state TEXT NOT NULL DEFAULT ''",
        "email": "ALTER TABLE workspace_access_requests ADD COLUMN email TEXT NOT NULL DEFAULT ''",
        "token_label": "ALTER TABLE workspace_access_requests ADD COLUMN token_label TEXT NOT NULL DEFAULT ''",
        # SQLite cannot ALTER TABLE ADD COLUMN with a non-constant default on
        # existing databases. Use a constant default, then backfill rows below.
        "updated_at": "ALTER TABLE workspace_access_requests ADD COLUMN updated_at TEXT NOT NULL DEFAULT ''",
    }.items():
        if col not in req_cols:
            conn.execute(ddl)
    conn.execute("UPDATE workspace_access_requests SET updated_at=CURRENT_TIMESTAMP WHERE updated_at IS NULL OR updated_at=''")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS workspace_tokens (
            id TEXT PRIMARY KEY,
            account_alias TEXT NOT NULL,
            bundle TEXT NOT NULL DEFAULT 'workspace-full.json',
            email TEXT NOT NULL DEFAULT '',
            token_json TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            scopes_json TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'connected',
            revoked_at TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(account_alias, bundle)
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS oauth_pending (
            state TEXT PRIMARY KEY,
            ts TEXT NOT NULL,
            actor TEXT NOT NULL,
            account_alias TEXT NOT NULL,
            scopes_json TEXT NOT NULL,
            client_json TEXT NOT NULL,
            redirect_uri TEXT NOT NULL,
            token_label TEXT NOT NULL DEFAULT '',
            status TEXT NOT NULL DEFAULT 'authorization_url_generated',
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    pending_cols = {row[1] for row in conn.execute("PRAGMA table_info(oauth_pending)").fetchall()}
    if "token_label" not in pending_cols:
        conn.execute("ALTER TABLE oauth_pending ADD COLUMN token_label TEXT NOT NULL DEFAULT ''")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS runtime_backups (
            id TEXT PRIMARY KEY,
            ts TEXT NOT NULL,
            actor TEXT NOT NULL,
            archive_path TEXT NOT NULL,
            backup_dir TEXT NOT NULL,
            includes_token_store INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'created',
            note TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS runtime_secrets (
            name TEXT PRIMARY KEY,
            encrypted_value TEXT NOT NULL,
            metadata_json TEXT NOT NULL DEFAULT '{}',
            rotated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            rotated_by TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS api_tokens (
            id TEXT PRIMARY KEY,
            label TEXT NOT NULL DEFAULT '',
            token_hash TEXT NOT NULL UNIQUE,
            allowed_profiles_json TEXT NOT NULL DEFAULT '["*"]',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            created_by TEXT NOT NULL DEFAULT '',
            revoked_at TEXT NOT NULL DEFAULT '',
            last_used_at TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS approval_telegram_channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL DEFAULT '',
            chat_id TEXT NOT NULL,
            scope TEXT NOT NULL DEFAULT 'all',
            profile TEXT NOT NULL DEFAULT '*',
            button_base_url TEXT NOT NULL DEFAULT '',
            bot_token TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(chat_id, scope, profile)
        )
        """
    )
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(approval_telegram_channels)").fetchall()}
        if "bot_token" not in cols:
            conn.execute("ALTER TABLE approval_telegram_channels ADD COLUMN bot_token TEXT NOT NULL DEFAULT ''")
    except sqlite3.Error:
        pass
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS approval_telegram_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_by TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.commit()
    return conn


def _approval_db() -> sqlite3.Connection:
    """DB shared with the gateway for approval delivery configuration."""
    GOOGLE_WORKSPACE_TOKEN_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(GOOGLE_WORKSPACE_TOKEN_DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS approval_telegram_channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            label TEXT NOT NULL DEFAULT '',
            chat_id TEXT NOT NULL,
            scope TEXT NOT NULL DEFAULT 'all',
            profile TEXT NOT NULL DEFAULT '*',
            button_base_url TEXT NOT NULL DEFAULT '',
            bot_token TEXT NOT NULL DEFAULT '',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(chat_id, scope, profile)
        )
        """
    )
    try:
        cols = {row[1] for row in conn.execute("PRAGMA table_info(approval_telegram_channels)").fetchall()}
        if "bot_token" not in cols:
            conn.execute("ALTER TABLE approval_telegram_channels ADD COLUMN bot_token TEXT NOT NULL DEFAULT ''")
    except sqlite3.Error:
        pass
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS approval_telegram_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_by TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.commit()
    return conn


def _read_jwt_secret() -> str:
    """Filesystem JWT signing is disabled by policy."""
    raise RuntimeError("filesystem JWT signing is disabled; use a gateway API access token")


def _write_jwt_secret(secret: str) -> None:
    raise RuntimeError("filesystem JWT signing is disabled; use gateway API token custody")


def _jwt_secret_fingerprint(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16]


def _jwt_secret_status() -> dict[str, Any]:
    return {
        "storage": "disabled",
        "readable": False,
        "secrets_revealed": False,
        "auth_contract": "gateway_api_token_or_token_exchange",
    }


def _jwt_secret_migrate_to_db(actor: str) -> dict[str, Any]:
    """Compatibility endpoint retained for UI buttons; no filesystem secret is created."""
    _append_change_event({"event": "jwt_secret_operation_blocked", "actor": actor, "storage": "disabled"})
    return {"status": "disabled", **_jwt_secret_status()}


def _jwt_secret_rotate(payload: dict[str, Any] | None = None, actor: str = "admin") -> dict[str, Any]:
    _append_change_event({"event": "jwt_secret_rotate_blocked", "actor": actor, "storage": "disabled"})
    return {"status": "disabled", **_jwt_secret_status()}


def _api_token_inventory() -> list[dict[str, Any]]:
    with _control_db() as conn:
        rows = conn.execute(
            "SELECT id,label,allowed_profiles_json,created_at,created_by,revoked_at,last_used_at FROM api_tokens ORDER BY created_at DESC"
        ).fetchall()
    items: list[dict[str, Any]] = []
    for row in rows:
        try:
            profiles = json.loads(row["allowed_profiles_json"] or '["*"]')
        except json.JSONDecodeError:
            profiles = ["*"]
        items.append({
            "id": row["id"],
            "label": row["label"],
            "allowed_profiles": profiles,
            "created_at": row["created_at"],
            "created_by": row["created_by"],
            "revoked_at": row["revoked_at"],
            "last_used_at": row["last_used_at"],
            "active": not bool(row["revoked_at"]),
            "env_var": "GOOGLE_GOVERNANCE_ACCESS_TOKEN",
        })
    return items


def _api_token_generate(payload: dict[str, Any] | None = None, actor: str = "admin") -> dict[str, Any]:
    payload = payload or {}
    label = str(payload.get("label") or "Shared gateway API token").strip()[:120] or "Shared gateway API token"
    allowed_profiles = payload.get("allowed_profiles") or ["*"]
    if isinstance(allowed_profiles, str):
        allowed_profiles = [allowed_profiles]
    allowed_profiles = [str(p).strip() for p in allowed_profiles if str(p).strip()]
    if not allowed_profiles:
        allowed_profiles = ["*"]
    if allowed_profiles != ["*"]:
        policy_profiles = set((_load_yaml(POLICY_PATH).get("profile_policy") or {}).keys())
        unknown = sorted(p for p in allowed_profiles if p not in policy_profiles)
        if unknown:
            raise ValueError(f"unknown profile(s): {', '.join(unknown)}")
    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    token_id = "gat_" + secrets.token_urlsafe(12).replace("-", "").replace("_", "")[:16]
    with _control_db() as conn:
        conn.execute(
            "INSERT INTO api_tokens(id,label,token_hash,allowed_profiles_json,created_by) VALUES(?,?,?,?,?)",
            (token_id, label, token_hash, json.dumps(allowed_profiles), actor),
        )
        conn.commit()
    _append_change_event({"event": "api_token_generated", "actor": actor, "token_id": token_id, "label": label, "allowed_profiles": allowed_profiles})
    return {
        "status": "created",
        "id": token_id,
        "label": label,
        "allowed_profiles": allowed_profiles,
        "access_token": raw_token,
        "env_var": "GOOGLE_GOVERNANCE_ACCESS_TOKEN",
        "warning": "Copy this token now. The UI will not show it again.",
    }


def _api_token_revoke(payload: dict[str, Any] | None = None, actor: str = "admin") -> dict[str, Any]:
    payload = payload or {}
    token_id = str(payload.get("id") or payload.get("token_id") or "").strip()
    if not token_id:
        raise ValueError("token id is required")
    with _control_db() as conn:
        cur = conn.execute("UPDATE api_tokens SET revoked_at=CURRENT_TIMESTAMP WHERE id=? AND revoked_at=''", (token_id,))
        conn.commit()
    _append_change_event({"event": "api_token_revoked", "actor": actor, "token_id": token_id})
    return {"status": "revoked" if cur.rowcount else "not_active", "id": token_id}


def _maybe_import_json_users(conn: sqlite3.Connection) -> None:
    count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    if count:
        return
    try:
        json_store_exists = CONTROL_USERS_JSON_PATH.exists()
    except PermissionError:
        json_store_exists = False
    if json_store_exists:
        data = json.loads(CONTROL_USERS_JSON_PATH.read_text(encoding="utf-8"))
        users = data.get("users") if isinstance(data, dict) else data
        if not isinstance(users, dict):
            raise RuntimeError("control user JSON store is invalid")
        for username, spec in users.items():
            if not isinstance(spec, dict) or not spec.get("password_hash"):
                continue
            canonical = "admin" if username == "legacy_admin" else str(username)
            first_name = str(spec.get("first_name") or ("Admin" if canonical == "admin" else ""))
            last_name = str(spec.get("last_name") or ("User" if canonical == "admin" else ""))
            conn.execute(
                "INSERT OR REPLACE INTO users(username,password_hash,role,enabled,first_name,last_name,email,avatar_url,updated_at) VALUES(?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)",
                (canonical, str(spec["password_hash"]), str(spec.get("role") or ("admin" if canonical == "admin" else "viewer")), 0 if spec.get("enabled") is False else 1, first_name, last_name, str(spec.get("email") or ""), str(spec.get("avatar_url") or "")),
            )
    else:
        existing = {row[0] for row in conn.execute("SELECT username FROM users").fetchall()}
        if "admin" not in existing:
            # First-run fallback for fresh SQLite stores; installers normally import the real hash from JSON/setup-token flow.
            pass
    conn.commit()


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode((value or "") + "=" * (-len(value or "") % 4))


def _totp_now(secret: str, step: int | None = None) -> str:
    counter = int((time.time() if step is None else step) // 30)
    key = base64.b32decode(secret.upper().replace(" ", ""), casefold=True)
    msg = counter.to_bytes(8, "big")
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = ((digest[offset] & 0x7F) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3]
    return f"{code % 1_000_000:06d}"


def _verify_totp(secret: str, code: str) -> bool:
    code = re.sub(r"\s+", "", str(code or ""))
    if not re.fullmatch(r"\d{6}", code or ""):
        return False
    now = int(time.time())
    for skew in (-30, 0, 30):
        if hmac.compare_digest(_totp_now(secret, now + skew), code):
            return True
    return False


def _rp_id_from_handler(handler: BaseHTTPRequestHandler) -> str:
    host = (handler.headers.get("X-Forwarded-Host") or handler.headers.get("Host") or "localhost").split(",", 1)[0].strip()
    host = host.split(":", 1)[0].strip().lower() or "localhost"
    return host


def _origin_from_handler(handler: BaseHTTPRequestHandler) -> str:
    origin = handler.headers.get("Origin") or ""
    if origin:
        return origin.rstrip("/")
    proto = handler.headers.get("X-Forwarded-Proto") or ("http" if _rp_id_from_handler(handler) in {"localhost", "127.0.0.1"} else "https")
    host = handler.headers.get("X-Forwarded-Host") or handler.headers.get("Host") or _rp_id_from_handler(handler)
    return f"{proto}://{host}".rstrip("/")


def _webauthn_credentials(username: str, kind: str | None = None) -> list[dict[str, Any]]:
    sql = "SELECT credential_id,public_key_der,sign_count,label,kind,transports,created_at,last_used_at FROM webauthn_credentials WHERE username=?"
    args: list[Any] = [username]
    if kind:
        sql += " AND kind=?"
        args.append(kind)
    sql += " ORDER BY created_at DESC"
    with _control_db() as conn:
        rows = conn.execute(sql, tuple(args)).fetchall()
    out = []
    for row in rows:
        item = dict(row)
        try:
            item["transports"] = json.loads(item.get("transports") or "[]")
        except Exception:
            item["transports"] = []
        out.append(item)
    return out


def _webauthn_credential_by_id(credential_id: str, kind: str | None = None) -> dict[str, Any] | None:
    sql = "SELECT username,credential_id,public_key_der,sign_count,label,kind,transports,created_at,last_used_at FROM webauthn_credentials WHERE credential_id=?"
    args: list[Any] = [credential_id]
    if kind:
        sql += " AND kind=?"
        args.append(kind)
    with _control_db() as conn:
        row = conn.execute(sql, tuple(args)).fetchone()
    if not row:
        return None
    item = dict(row)
    try:
        item["transports"] = json.loads(item.get("transports") or "[]")
    except Exception:
        item["transports"] = []
    return item


def _user_has_2fa(username: str, spec: dict[str, Any] | None = None) -> bool:
    spec = spec if isinstance(spec, dict) else _load_control_users().get(username, {})
    return bool((isinstance(spec, dict) and spec.get("totp_enabled") and spec.get("totp_secret")) or _webauthn_credentials(username, "yubikey_2fa"))


def _create_2fa_challenge(username: str, kind: str, payload: dict[str, Any] | None = None, ttl: int = 300) -> str:
    challenge = secrets.token_urlsafe(32)
    with _control_db() as conn:
        conn.execute("DELETE FROM twofa_challenges WHERE expires_at < ? OR used=1", (int(time.time()),))
        conn.execute("INSERT INTO twofa_challenges(id,username,kind,payload_json,expires_at) VALUES(?,?,?,?,?)", (challenge, username, kind, json.dumps(payload or {}, sort_keys=True), int(time.time()) + ttl))
        conn.commit()
    return challenge


def _peek_2fa_challenge(challenge: str, kind: str | None = None, username: str | None = None) -> tuple[str, dict[str, Any]]:
    with _control_db() as conn:
        row = conn.execute("SELECT id,username,kind,payload_json,expires_at,used FROM twofa_challenges WHERE id=?", (challenge,)).fetchone()
    if not row or row["used"] or int(row["expires_at"]) < int(time.time()):
        raise PermissionError("2FA challenge expired or invalid")
    if kind and row["kind"] != kind:
        raise PermissionError("2FA challenge type mismatch")
    if username and row["username"] != username:
        raise PermissionError("2FA challenge user mismatch")
    try:
        payload = json.loads(row["payload_json"] or "{}")
    except Exception:
        payload = {}
    return str(row["username"]), payload if isinstance(payload, dict) else {}


def _consume_2fa_challenge(challenge: str, kind: str | None = None, username: str | None = None) -> tuple[str, dict[str, Any]]:
    with _control_db() as conn:
        row = conn.execute("SELECT id,username,kind,payload_json,expires_at,used FROM twofa_challenges WHERE id=?", (challenge,)).fetchone()
        if not row or row["used"] or int(row["expires_at"]) < int(time.time()):
            raise PermissionError("2FA challenge expired or invalid")
        if kind and row["kind"] != kind:
            raise PermissionError("2FA challenge type mismatch")
        if username and row["username"] != username:
            raise PermissionError("2FA challenge user mismatch")
        conn.execute("UPDATE twofa_challenges SET used=1 WHERE id=?", (challenge,))
        conn.commit()
    try:
        payload = json.loads(row["payload_json"] or "{}")
    except Exception:
        payload = {}
    return str(row["username"]), payload if isinstance(payload, dict) else {}


def _parse_authenticator_data(auth_data: bytes) -> dict[str, Any]:
    if len(auth_data) < 37:
        raise ValueError("WebAuthn authenticator data is too short")
    return {"rp_id_hash": auth_data[:32], "flags": auth_data[32], "sign_count": int.from_bytes(auth_data[33:37], "big")}


def _load_public_key(der_b64: str):
    if serialization is None:
        raise RuntimeError("YubiKey/WebAuthn verification requires the python cryptography package")
    return serialization.load_der_public_key(_b64url_decode(der_b64))


def _verify_webauthn_signature(public_key_der: str, signature: bytes, signed_data: bytes) -> None:
    key = _load_public_key(public_key_der)
    if ec is not None and isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(signature, signed_data, ec.ECDSA(hashes.SHA256()))
        return
    if rsa is not None and isinstance(key, rsa.RSAPublicKey):
        key.verify(signature, signed_data, padding.PKCS1v15(), hashes.SHA256())
        return
    raise ValueError("unsupported WebAuthn public key type")


def _load_control_store() -> dict[str, Any]:
    with _control_db() as conn:
        _maybe_import_json_users(conn)
        rows = conn.execute("SELECT username,password_hash,role,enabled,first_name,last_name,email,avatar_url,totp_secret,totp_enabled FROM users ORDER BY username").fetchall()
    users = {
        str(row["username"]): {
            "password_hash": str(row["password_hash"]),
            "role": str(row["role"] or "viewer"),
            "enabled": bool(row["enabled"]),
            "first_name": str(row["first_name"] or ""),
            "last_name": str(row["last_name"] or ""),
            "email": str(row["email"] or ""),
            "avatar_url": str(row["avatar_url"] or ""),
            "totp_secret": str(row["totp_secret"] or ""),
            "totp_enabled": bool(row["totp_enabled"]),
        }
        for row in rows
    }
    return {"schema_version": 2, "store": "sqlite", "users": users}


def _save_control_store(store: dict[str, Any]) -> None:
    users = store.get("users") or {}
    if not isinstance(users, dict):
        raise RuntimeError("control user store is invalid")
    with _control_db() as conn:
        _maybe_import_json_users(conn)
        conn.execute("BEGIN")
        conn.execute("DELETE FROM users")
        for username, spec in users.items():
            if not isinstance(spec, dict) or not spec.get("password_hash"):
                continue
            conn.execute(
                "INSERT INTO users(username,password_hash,role,enabled,first_name,last_name,email,avatar_url,totp_secret,totp_enabled,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)",
                (str(username), str(spec["password_hash"]), str(spec.get("role") or "viewer"), 0 if spec.get("enabled") is False else 1, str(spec.get("first_name") or ""), str(spec.get("last_name") or ""), str(spec.get("email") or ""), str(spec.get("avatar_url") or ""), str(spec.get("totp_secret") or ""), 1 if spec.get("totp_enabled") else 0),
            )
        conn.commit()

def _setup_required() -> bool:
    return not bool(_load_control_store().get("users"))


def _read_setup_token() -> str:
    if CONTROL_SETUP_TOKEN:
        return CONTROL_SETUP_TOKEN.strip()
    if CONTROL_SETUP_TOKEN_PATH.exists():
        return CONTROL_SETUP_TOKEN_PATH.read_text(encoding="utf-8").strip()
    return ""


def _remove_setup_token_after_bootstrap(actor: str) -> dict[str, Any]:
    if CONTROL_SETUP_TOKEN:
        result = {"status": "env_token_configured", "path": str(CONTROL_SETUP_TOKEN_PATH), "message": "Setup token came from environment; remove GOOGLE_GOVERNANCE_CONTROL_SETUP_TOKEN from systemd/env after bootstrap."}
        _append_change_event({"event": "control_setup_token_retained_env", "actor": actor, **result})
        return result
    if not CONTROL_SETUP_TOKEN_PATH.exists():
        return {"status": "absent", "path": str(CONTROL_SETUP_TOKEN_PATH)}
    try:
        CONTROL_SETUP_TOKEN_PATH.unlink()
        result = {"status": "deleted", "path": str(CONTROL_SETUP_TOKEN_PATH)}
        _append_change_event({"event": "control_setup_token_deleted", "actor": actor, **result})
        return result
    except Exception as exc:
        result = {"status": "delete_failed", "path": str(CONTROL_SETUP_TOKEN_PATH), "message": str(exc)}
        _append_change_event({"event": "control_setup_token_delete_failed", "actor": actor, **result})
        return result


def _bootstrap_setup(payload: dict[str, Any]) -> dict[str, Any]:
    if not _setup_required():
        raise PermissionError("setup already completed")
    expected = _read_setup_token()
    supplied = str(payload.get("setup_token") or "").strip()
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        raise PermissionError("valid setup token required")
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    first_name = str(payload.get("first_name") or ("Admin" if username in {"legacy_admin", "admin"} else "")).strip()
    last_name = str(payload.get("last_name") or ("User" if username in {"legacy_admin", "admin"} else "")).strip()
    if not username or any(ch in username for ch in " /\\:\t\n"):
        raise ValueError("valid username is required")
    if len(password) < 12:
        raise ValueError("admin password must be at least 12 characters")
    if not first_name or not last_name:
        raise ValueError("first name and last name are required")
    store = {"schema_version": 2, "users": {username: {"password_hash": _password_hash(password), "role": "admin", "enabled": True, "first_name": first_name, "last_name": last_name}}}
    _save_control_store(store)
    setup_token = _remove_setup_token_after_bootstrap(username)
    _append_change_event({"event": "control_setup_completed", "actor": username, "username": username, "setup_token": setup_token.get("status")})
    return {"status": "setup_complete", "user": _user_public(username, store["users"][username]), "setup_token": setup_token}


def _load_control_users() -> dict[str, Any]:
    return _load_control_store()["users"]


def _session_secret() -> bytes:
    if CONTROL_SESSION_SECRET_PATH.exists():
        return CONTROL_SESSION_SECRET_PATH.read_text(encoding="utf-8").strip().encode("utf-8")
    env_secret = os.getenv("GOOGLE_GOVERNANCE_CONTROL_SESSION_SECRET")
    if env_secret:
        return env_secret.encode("utf-8")
    raise FileNotFoundError(f"control session secret not configured: {CONTROL_SESSION_SECRET_PATH}")


def _sign_session(username: str, issued_at: int | None = None) -> str:
    issued_at = issued_at or int(time.time())
    body = f"{username}:{issued_at}"
    sig = hmac.new(_session_secret(), body.encode("utf-8"), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{body}:{sig}".encode("utf-8")).decode("ascii").rstrip("=")


def _session_user(handler: BaseHTTPRequestHandler) -> str | None:
    cookie = SimpleCookie(handler.headers.get("Cookie", ""))
    morsel = cookie.get("ggov_session")
    if not morsel:
        return None
    try:
        raw_value = morsel.value + "=" * (-len(morsel.value) % 4)
        raw = base64.urlsafe_b64decode(raw_value.encode("ascii")).decode("utf-8")
        username, issued_s, supplied = raw.rsplit(":", 2)
        issued = int(issued_s)
    except Exception:
        return None
    if issued + CONTROL_SESSION_TTL_SECONDS < int(time.time()):
        return None
    expected = hmac.new(_session_secret(), f"{username}:{issued}".encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, supplied):
        return None
    stored = _load_control_users().get(username)
    if not isinstance(stored, dict) or stored.get("enabled") is False:
        return None
    return username


def _require_auth(handler: BaseHTTPRequestHandler) -> str | None:
    if CONTROL_AUTH_DISABLED:
        return "admin"
    user = _session_user(handler)
    if user:
        return user
    _json_response(handler, 401, {"error": "auth_required", "message": "Sign in required"})
    return None


def _public_webauthn_credentials(username: str, kind: str) -> list[dict[str, Any]]:
    rows = _webauthn_credentials(username, kind)
    out: list[dict[str, Any]] = []
    for c in rows:
        cid = str(c.get("credential_id") or "")
        out.append({
            "credential_id": cid,
            "id_tail": cid[-10:] if cid else "",
            "label": str(c.get("label") or ("YubiKey 2FA" if kind == "yubikey_2fa" else "Passkey")),
            "kind": str(c.get("kind") or kind),
            "transports": c.get("transports") or [],
            "created_at": str(c.get("created_at") or ""),
            "last_used_at": str(c.get("last_used_at") or ""),
        })
    return out


def _user_public(username: str, spec: dict[str, Any]) -> dict[str, Any]:
    first_name = str(spec.get("first_name") or ("Admin" if username in {"legacy_admin", "admin"} else "")).strip()
    last_name = str(spec.get("last_name") or ("User" if username in {"legacy_admin", "admin"} else "")).strip()
    display_name = (f"{first_name} {last_name}".strip() or username)
    passkey_credentials = _public_webauthn_credentials(username, "passkey")
    yubikey_credentials = _public_webauthn_credentials(username, "yubikey_2fa")
    passkey_count = len(passkey_credentials)
    yubikey_count = len(yubikey_credentials)
    webauthn_count = passkey_count + yubikey_count
    totp_enabled = bool(spec.get("totp_enabled") and spec.get("totp_secret"))
    return {"username": username, "first_name": first_name, "last_name": last_name, "email": str(spec.get("email") or ""), "display_name": display_name, "avatar_url": str(spec.get("avatar_url") or ""), "role": str(spec.get("role") or "viewer"), "enabled": spec.get("enabled") is not False, "totp_enabled": totp_enabled, "passkey_count": passkey_count, "yubikey_2fa_count": yubikey_count, "webauthn_count": webauthn_count, "twofa_enabled": bool(totp_enabled or yubikey_count), "passkeys": passkey_credentials, "yubikey_2fa_credentials": yubikey_credentials}


def _current_user_payload(username: str) -> dict[str, Any]:
    spec = _load_control_users().get(username, {})
    return _user_public(username, spec if isinstance(spec, dict) else {})


def _require_admin(username: str) -> None:
    if CONTROL_AUTH_DISABLED and username in {"legacy_admin", "admin"}:
        return
    spec = _load_control_users().get(username)
    if not isinstance(spec, dict) or str(spec.get("role") or "viewer") != "admin":
        raise PermissionError("admin user required")


def _set_session_cookie(handler: BaseHTTPRequestHandler, username: str) -> None:
    handler.send_header("Set-Cookie", f"ggov_session={_sign_session(username)}; HttpOnly; SameSite=Lax; Path=/; Max-Age={CONTROL_SESSION_TTL_SECONDS}")


def _clear_session_cookie(handler: BaseHTTPRequestHandler) -> None:
    handler.send_header("Set-Cookie", "ggov_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")


def _json_response_with_cookie(handler: BaseHTTPRequestHandler, status: int, payload: Any, username: str | None = None, clear: bool = False) -> None:
    _append_control_audit(handler, status, payload, username=username)
    raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    if username:
        _set_session_cookie(handler, username)
    if clear:
        _clear_session_cookie(handler)
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def _redirect_response(handler: BaseHTTPRequestHandler, location: str, username: str | None = None, clear: bool = False) -> None:
    _append_control_audit(handler, 302, {"status": "redirect", "location": location}, username=username)
    handler.send_response(302)
    handler.send_header("Location", location)
    handler.send_header("Cache-Control", "no-store")
    if username:
        _set_session_cookie(handler, username)
    if clear:
        _clear_session_cookie(handler)
    handler.send_header("Content-Length", "0")
    handler.end_headers()


def _login(payload: dict[str, Any], handler: BaseHTTPRequestHandler | None = None) -> dict[str, Any]:
    username = str(payload.get("username") or "").strip()
    password = str(payload.get("password") or "")
    stored = _load_control_users().get(username)
    if not isinstance(stored, dict) or stored.get("enabled") is False:
        raise PermissionError("invalid username or password")
    if not _verify_password(password, str(stored.get("password_hash") or "")):
        raise PermissionError("invalid username or password")
    methods: list[str] = []
    if stored.get("totp_enabled") and stored.get("totp_secret"):
        methods.append("totp")
    creds = _webauthn_credentials(username, "yubikey_2fa")
    if creds:
        methods.append("yubikey_2fa")
    if methods:
        challenge = _create_2fa_challenge(username, "login", {"rp_id": _rp_id_from_handler(handler) if handler else "localhost"})
        return {"status": "2fa_required", "challenge": challenge, "methods": methods, "user": _user_public(username, stored)}
    return {"status": "ok", "user": _user_public(username, stored)}


def _login_2fa(payload: dict[str, Any], handler: BaseHTTPRequestHandler | None = None) -> dict[str, Any]:
    challenge = str(payload.get("challenge") or "").strip()
    method = str(payload.get("method") or "totp").strip()
    username, challenge_payload = _consume_2fa_challenge(challenge, "login")
    users = _load_control_users()
    stored = users.get(username)
    if not isinstance(stored, dict) or stored.get("enabled") is False:
        raise PermissionError("invalid 2FA challenge")
    if method == "totp":
        if not (stored.get("totp_enabled") and stored.get("totp_secret")):
            raise PermissionError("authenticator app is not enabled")
        if not _verify_totp(str(stored.get("totp_secret") or ""), str(payload.get("code") or "")):
            raise PermissionError("invalid authenticator code")
    elif method in {"webauthn", "yubikey_2fa"}:
        _verify_webauthn_assertion(username, challenge, payload, handler, expected_rp_id=str(challenge_payload.get("rp_id") or ""), kind="yubikey_2fa")
    else:
        raise ValueError("method must be totp or yubikey_2fa")
    _append_change_event({"event": "control_2fa_login", "actor": username, "method": method})
    return {"status": "ok", "user": _user_public(username, stored)}


def _totp_enroll_start(actor: str) -> dict[str, Any]:
    secret = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
    # base32 secrets should be padded for decoding, but authenticator apps accept unpadded strings.
    secret_padded = secret + "=" * (-len(secret) % 8)
    challenge = _create_2fa_challenge(actor, "totp_enroll", {"secret": secret_padded}, ttl=600)
    issuer = urllib.parse.quote(CONTROL_AUTH_REALM)
    label = urllib.parse.quote(f"{CONTROL_AUTH_REALM}:{actor}")
    otpauth = f"otpauth://totp/{label}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30"
    return {"status": "pending", "challenge": challenge, "secret": secret, "otpauth_url": otpauth}


def _totp_enroll_verify(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    _, data = _consume_2fa_challenge(str(payload.get("challenge") or ""), "totp_enroll", actor)
    secret = str(data.get("secret") or "")
    if not _verify_totp(secret, str(payload.get("code") or "")):
        raise PermissionError("invalid authenticator code")
    store = _load_control_store()
    spec = store.setdefault("users", {}).get(actor)
    if not isinstance(spec, dict):
        raise PermissionError("current user is missing")
    spec["totp_secret"] = secret
    spec["totp_enabled"] = True
    _save_control_store(store)
    _append_change_event({"event": "control_totp_enabled", "actor": actor})
    return {"status": "enabled", "user": _user_public(actor, spec)}


def _totp_disable(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    store = _load_control_store()
    users = store.setdefault("users", {})
    target = str(payload.get("username") or actor).strip() or actor
    if target != actor:
        _require_admin(actor)
    spec = users.get(target)
    if not isinstance(spec, dict):
        raise ValueError("unknown user")
    spec["totp_secret"] = ""
    spec["totp_enabled"] = False
    _save_control_store(store)
    _append_change_event({"event": "control_totp_disabled", "actor": actor, "username": target})
    return {"status": "disabled", "user": _user_public(target, spec)}


def _webauthn_register_options(actor: str, handler: BaseHTTPRequestHandler, kind: str = "passkey") -> dict[str, Any]:
    user = _current_user_payload(actor)
    rp_id = _rp_id_from_handler(handler)
    kind = "yubikey_2fa" if kind == "yubikey_2fa" else "passkey"
    existing = _webauthn_credentials(actor, kind)
    if kind == "passkey" and existing:
        raise ValueError("a passkey is already registered for this user")
    challenge = _create_2fa_challenge(actor, "webauthn_register", {"rp_id": rp_id, "origin": _origin_from_handler(handler), "kind": kind}, ttl=600)
    exclude = [{"type": "public-key", "id": c["credential_id"], "transports": c.get("transports") or ["usb", "nfc", "internal"]} for c in existing]
    if kind == "passkey":
        selection = {"userVerification": "required", "residentKey": "required", "requireResidentKey": True}
    else:
        selection = {"authenticatorAttachment": "cross-platform", "userVerification": "discouraged", "residentKey": "discouraged", "requireResidentKey": False}
    return {"status": "ok", "challenge": challenge, "kind": kind, "publicKey": {"challenge": challenge, "rp": {"name": CONTROL_AUTH_REALM, "id": rp_id}, "user": {"id": _b64url_encode(actor.encode("utf-8")), "name": actor, "displayName": user.get("display_name") or actor}, "pubKeyCredParams": [{"type": "public-key", "alg": -7}, {"type": "public-key", "alg": -257}], "authenticatorSelection": selection, "timeout": 60000, "attestation": "none", "excludeCredentials": exclude}}


def _webauthn_register_verify(payload: dict[str, Any], actor: str, handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    _, data = _consume_2fa_challenge(str(payload.get("challenge") or ""), "webauthn_register", actor)
    kind = "yubikey_2fa" if str(data.get("kind") or payload.get("kind") or "passkey") == "yubikey_2fa" else "passkey"
    credential_id = str(payload.get("id") or "").strip()
    public_key = str(payload.get("publicKey") or "").strip()
    if not credential_id or not public_key:
        raise ValueError("WebAuthn registration did not return a credential public key; use a WebAuthn-capable browser")
    client = json.loads(_b64url_decode(str(payload.get("clientDataJSON") or "")).decode("utf-8") or "{}")
    if client.get("type") != "webauthn.create" or client.get("challenge") != str(payload.get("challenge") or ""):
        raise PermissionError("invalid WebAuthn registration challenge")
    expected_origin = str(data.get("origin") or _origin_from_handler(handler)).rstrip("/")
    if str(client.get("origin") or "").rstrip("/") != expected_origin:
        raise PermissionError("WebAuthn registration origin mismatch")
    label_default = "YubiKey 2FA" if kind == "yubikey_2fa" else "Passkey"
    with _control_db() as conn:
        conn.execute("INSERT OR REPLACE INTO webauthn_credentials(username,credential_id,public_key_der,sign_count,label,kind,transports) VALUES(?,?,?,?,?,?,?)", (actor, credential_id, public_key, int(payload.get("signCount") or 0), str(payload.get("label") or label_default), kind, json.dumps(payload.get("transports") or [])))
        conn.commit()
    _append_change_event({"event": "control_webauthn_registered", "actor": actor, "label": str(payload.get("label") or label_default), "kind": kind})
    return {"status": "registered", "user": _current_user_payload(actor), "credentials": len(_webauthn_credentials(actor, kind)), "kind": kind}


def _webauthn_login_options(payload: dict[str, Any], handler: BaseHTTPRequestHandler | None = None) -> dict[str, Any]:
    challenge = str(payload.get("challenge") or "").strip()
    username, data = _peek_2fa_challenge(challenge, "login")
    creds = _webauthn_credentials(username, "yubikey_2fa")
    if not creds:
        raise PermissionError("no YubiKey 2FA credential is registered for this user")
    rp_id = str(data.get("rp_id") or (_rp_id_from_handler(handler) if handler else "localhost"))
    assertion_challenge = _create_2fa_challenge(username, "webauthn_assert", {"rp_id": rp_id, "origin": _origin_from_handler(handler) if handler else "", "kind": "yubikey_2fa"})
    return {"status": "ok", "challenge": assertion_challenge, "publicKey": {"challenge": assertion_challenge, "rpId": rp_id, "timeout": 60000, "userVerification": "preferred", "allowCredentials": [{"type": "public-key", "id": c["credential_id"], "transports": c.get("transports") or ["usb", "nfc"]} for c in creds]}}


def _passkey_login_options(payload: dict[str, Any], handler: BaseHTTPRequestHandler | None = None) -> dict[str, Any]:
    rp_id = _rp_id_from_handler(handler) if handler else "localhost"
    challenge = _create_2fa_challenge("__passkey__", "passkey_login", {"rp_id": rp_id, "origin": _origin_from_handler(handler) if handler else ""})
    return {"status": "ok", "challenge": challenge, "publicKey": {"challenge": challenge, "rpId": rp_id, "timeout": 60000, "userVerification": "required"}}


def _verify_webauthn_assertion(username: str, challenge: str, payload: dict[str, Any], handler: BaseHTTPRequestHandler | None = None, expected_rp_id: str = "", kind: str = "yubikey_2fa", consume_assertion: bool = True) -> str:
    if consume_assertion and payload.get("assertion_challenge"):
        username2, data = _consume_2fa_challenge(str(payload.get("assertion_challenge") or ""), "webauthn_assert", username)
        expected_rp_id = str(data.get("rp_id") or expected_rp_id)
        kind = str(data.get("kind") or kind)
    credential_id = str(payload.get("id") or "").strip()
    cred = _webauthn_credential_by_id(credential_id, kind)
    if not cred or (username not in {"", "__passkey__"} and cred.get("username") != username):
        raise PermissionError("unknown WebAuthn credential")
    username = str(cred.get("username") or username)
    client_data = _b64url_decode(str(payload.get("clientDataJSON") or ""))
    auth_data = _b64url_decode(str(payload.get("authenticatorData") or ""))
    signature = _b64url_decode(str(payload.get("signature") or ""))
    client = json.loads(client_data.decode("utf-8") or "{}")
    challenge_expected = str(payload.get("assertion_challenge") or challenge)
    if client.get("type") != "webauthn.get" or client.get("challenge") != challenge_expected:
        raise PermissionError("invalid WebAuthn authentication challenge")
    parsed = _parse_authenticator_data(auth_data)
    rp_id = expected_rp_id or (_rp_id_from_handler(handler) if handler else "localhost")
    if parsed["rp_id_hash"] != hashlib.sha256(rp_id.encode("utf-8")).digest():
        raise PermissionError("WebAuthn RP ID mismatch")
    if not (parsed["flags"] & 0x01):
        raise PermissionError("WebAuthn authenticator did not confirm user presence")
    if kind == "passkey" and not (parsed["flags"] & 0x04):
        raise PermissionError("passkey sign-in requires user verification")
    signed_data = auth_data + hashlib.sha256(client_data).digest()
    try:
        _verify_webauthn_signature(str(cred["public_key_der"]), signature, signed_data)
    except Exception as exc:
        if InvalidSignature is not None and isinstance(exc, InvalidSignature):
            raise PermissionError("invalid WebAuthn signature") from exc
        raise
    with _control_db() as conn:
        conn.execute("UPDATE webauthn_credentials SET sign_count=?, last_used_at=CURRENT_TIMESTAMP WHERE username=? AND credential_id=?", (int(parsed["sign_count"]), username, credential_id))
        conn.commit()
    return username


def _passkey_login_verify(payload: dict[str, Any], handler: BaseHTTPRequestHandler | None = None) -> dict[str, Any]:
    challenge = str(payload.get("challenge") or payload.get("assertion_challenge") or "").strip()
    _, data = _consume_2fa_challenge(challenge, "passkey_login", "__passkey__")
    username = _verify_webauthn_assertion("__passkey__", challenge, payload, handler, expected_rp_id=str(data.get("rp_id") or ""), kind="passkey", consume_assertion=False)
    stored = _load_control_users().get(username)
    if not isinstance(stored, dict) or stored.get("enabled") is False:
        raise PermissionError("passkey user is disabled or missing")
    _append_change_event({"event": "control_passkey_login", "actor": username})
    return {"status": "ok", "user": _user_public(username, stored)}

def _webauthn_disable(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    target = str(payload.get("username") or actor).strip() or actor
    if target != actor:
        _require_admin(actor)
    credential_id = str(payload.get("credential_id") or "").strip()
    with _control_db() as conn:
        kind = str(payload.get("kind") or "").strip()
        if credential_id:
            conn.execute("DELETE FROM webauthn_credentials WHERE username=? AND credential_id=?", (target, credential_id))
        elif kind:
            conn.execute("DELETE FROM webauthn_credentials WHERE username=? AND kind=?", (target, kind))
        else:
            conn.execute("DELETE FROM webauthn_credentials WHERE username=?", (target,))
        conn.commit()
    _append_change_event({"event": "control_webauthn_removed", "actor": actor, "username": target, "credential_id": bool(credential_id)})
    return {"status": "removed", "user": _current_user_payload(target), "credentials": len(_webauthn_credentials(target))}


def _list_users(actor: str | None = None) -> dict[str, Any]:
    users = _load_control_users()
    is_admin = False
    if actor:
        spec = users.get(actor)
        is_admin = isinstance(spec, dict) and str(spec.get("role") or "viewer") == "admin"
    visible = users if (is_admin or not actor) else {actor: users.get(actor, {})}
    return {"users": [_user_public(username, spec) for username, spec in sorted(visible.items()) if isinstance(spec, dict)]}


def _save_user(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    _require_admin(actor)
    username = str(payload.get("username") or "").strip()
    if not username or any(ch in username for ch in " /:\t\n"):
        raise ValueError("valid username is required")
    role = str(payload.get("role") or "viewer").strip()
    if role not in {"admin", "viewer"}:
        raise ValueError("role must be admin or viewer")
    store = _load_control_store()
    users = store.setdefault("users", {})
    spec = users.setdefault(username, {})
    first_name = str(payload.get("first_name") or spec.get("first_name") or username).strip()
    last_name = str(payload.get("last_name") or spec.get("last_name") or "").strip()
    password = str(payload.get("password") or "")
    if password:
        if len(password) < 10:
            raise ValueError("password must be at least 10 characters")
        spec["password_hash"] = _password_hash(password)
    if not spec.get("password_hash"):
        raise ValueError("password required for new user")
    spec["role"] = role
    spec["enabled"] = bool(payload.get("enabled", True))
    spec["first_name"] = first_name
    spec["last_name"] = last_name
    spec["email"] = str(payload.get("email") or "").strip()
    avatar_url = str(payload.get("avatar_url") or spec.get("avatar_url") or "").strip()
    if len(avatar_url) > 120000:
        raise ValueError("profile photo is too large")
    spec["avatar_url"] = avatar_url
    _save_control_store(store)
    _append_change_event({"event": "control_user_saved", "actor": actor, "username": username, "first_name": first_name, "last_name": last_name, "role": role, "enabled": spec["enabled"]})
    return {"status": "saved", "user": _user_public(username, spec)}


def _delete_user(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    _require_admin(actor)
    username = str(payload.get("username") or "").strip()
    if username == actor:
        raise ValueError("cannot delete current user")
    store = _load_control_store()
    users = store.setdefault("users", {})
    if username not in users:
        raise ValueError("unknown user")
    del users[username]
    _save_control_store(store)
    _append_change_event({"event": "control_user_deleted", "actor": actor, "username": username})
    return {"status": "deleted", "username": username}



def _update_profile(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    store = _load_control_store()
    users = store.setdefault("users", {})
    spec = users.get(actor)
    if not isinstance(spec, dict) or spec.get("enabled") is False:
        raise PermissionError("current user is disabled or missing")
    first_name = str(payload.get("first_name") or spec.get("first_name") or "").strip()
    last_name = str(payload.get("last_name") or spec.get("last_name") or "").strip()
    email = str(payload.get("email") or spec.get("email") or "").strip()
    avatar_url = str(payload.get("avatar_url") or "").strip()
    if not first_name or not last_name:
        raise ValueError("first name and last name are required")
    if avatar_url and not (avatar_url.startswith("data:image/") or avatar_url.startswith("https://") or avatar_url.startswith("http://")):
        raise ValueError("profile photo must be an image upload or URL")
    if len(avatar_url) > 120000:
        raise ValueError("profile photo is too large")
    spec["first_name"] = first_name
    spec["last_name"] = last_name
    spec["email"] = email
    spec["avatar_url"] = avatar_url
    _save_control_store(store)
    _append_change_event({"event": "control_profile_updated", "actor": actor, "username": actor})
    return {"status": "profile_updated", "user": _user_public(actor, spec)}


def _oidc_public_config() -> dict[str, Any]:
    try:
        cfg = json.loads(CONTROL_OIDC_CONFIG_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError:
        cfg = {}
    except Exception:
        cfg = {}
    return {
        "enabled": bool(cfg.get("enabled", False)),
        "issuer_url": str(cfg.get("issuer_url") or ""),
        "client_id": str(cfg.get("client_id") or ""),
        "redirect_uri": str(cfg.get("redirect_uri") or ""),
        "allow_signup": True,
        "email_domain_allowlist": str(cfg.get("email_domain_allowlist") or ""),
        "client_secret_configured": bool(cfg.get("client_secret")),
    }


def _save_oidc_config(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    _require_admin(actor)
    try:
        current = json.loads(CONTROL_OIDC_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        current = {}
    cfg = {
        "enabled": bool(payload.get("enabled", False)),
        "issuer_url": str(payload.get("issuer_url") or "").strip(),
        "client_id": str(payload.get("client_id") or "").strip(),
        "redirect_uri": str(payload.get("redirect_uri") or "").strip(),
        "allow_signup": True,
        "email_domain_allowlist": str(payload.get("email_domain_allowlist") or "").strip(),
        "client_secret": str(current.get("client_secret") or ""),
    }
    secret = str(payload.get("client_secret") or "").strip()
    if secret:
        cfg["client_secret"] = secret
    if cfg["enabled"] and (not cfg["issuer_url"] or not cfg["client_id"] or not cfg["client_secret"] or not cfg["redirect_uri"]):
        raise ValueError("issuer URL, client ID, client secret, and redirect URI are required to enable OIDC")
    CONTROL_OIDC_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONTROL_OIDC_CONFIG_PATH.write_text(json.dumps(cfg, indent=2, sort_keys=True), encoding="utf-8")
    try:
        CONTROL_OIDC_CONFIG_PATH.chmod(0o600)
    except Exception:
        pass
    _append_change_event({"event": "control_oidc_config_saved", "actor": actor, "enabled": cfg["enabled"], "issuer_url": cfg["issuer_url"], "client_id": cfg["client_id"], "allow_signup": cfg["allow_signup"]})
    return {"status": "saved", "oidc": _oidc_public_config()}


def _oidc_config_private() -> dict[str, Any]:
    try:
        cfg = json.loads(CONTROL_OIDC_CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        cfg = {}
    return cfg if isinstance(cfg, dict) else {}


def _oidc_discovery(cfg: dict[str, Any]) -> dict[str, Any]:
    issuer = str(cfg.get("issuer_url") or "").strip().rstrip("/")
    if not issuer:
        raise ValueError("OIDC issuer URL is required")
    url = issuer + "/.well-known/openid-configuration"
    with urllib.request.urlopen(url, timeout=10) as resp:
        return json.loads(resp.read().decode("utf-8") or "{}")


def _oidc_state_path(state: str) -> Path:
    return CONTROL_OIDC_STATE_ROOT / (re.sub(r"[^A-Za-z0-9_.-]", "_", state) + ".json")


def _oidc_public_login_config() -> dict[str, Any]:
    cfg = _oidc_public_config()
    return {"status": "ok", "oidc": {"enabled": bool(cfg.get("enabled")), "login_url": "/api/oidc/login" if cfg.get("enabled") else "", "issuer_url": cfg.get("issuer_url", ""), "client_id_configured": bool(cfg.get("client_id")), "client_secret_configured": bool(cfg.get("client_secret_configured"))}}


def _oidc_start_login(handler: BaseHTTPRequestHandler) -> None:
    cfg = _oidc_config_private()
    if not cfg.get("enabled"):
        _text_response(handler, 403, "OIDC login is not enabled.", "text/plain; charset=utf-8")
        return
    discovery = _oidc_discovery(cfg)
    auth_endpoint = str(discovery.get("authorization_endpoint") or "")
    if not auth_endpoint:
        raise ValueError("OIDC discovery did not return an authorization endpoint")
    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    CONTROL_OIDC_STATE_ROOT.mkdir(parents=True, exist_ok=True)
    _oidc_state_path(state).write_text(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "nonce": nonce}, indent=2), encoding="utf-8")
    params = {"client_id": str(cfg.get("client_id") or ""), "redirect_uri": str(cfg.get("redirect_uri") or ""), "response_type": "code", "scope": "openid email profile", "state": state, "nonce": nonce}
    _redirect_response(handler, auth_endpoint + "?" + urllib.parse.urlencode(params))


def _oidc_userinfo(cfg: dict[str, Any], discovery: dict[str, Any], code: str) -> dict[str, Any]:
    token_endpoint = str(discovery.get("token_endpoint") or "")
    if not token_endpoint:
        raise ValueError("OIDC discovery did not return a token endpoint")
    body = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "redirect_uri": str(cfg.get("redirect_uri") or ""), "client_id": str(cfg.get("client_id") or ""), "client_secret": str(cfg.get("client_secret") or "")}).encode("utf-8")
    req = urllib.request.Request(token_endpoint, data=body, headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        token = json.loads(resp.read().decode("utf-8") or "{}")
    access_token = str(token.get("access_token") or "")
    userinfo_endpoint = str(discovery.get("userinfo_endpoint") or "")
    if access_token and userinfo_endpoint:
        req = urllib.request.Request(userinfo_endpoint, headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            info = json.loads(resp.read().decode("utf-8") or "{}")
            if isinstance(info, dict) and (info.get("email") or info.get("preferred_username")):
                return info
    id_info = _decode_jwt_payload(token.get("id_token"))
    if not id_info:
        raise ValueError("OIDC login did not return usable user identity")
    return id_info


def _oidc_find_or_create_user(info: dict[str, Any], cfg: dict[str, Any]) -> str:
    email = str(info.get("email") or "").strip().lower()
    preferred = str(info.get("preferred_username") or info.get("username") or "").strip()
    if not preferred and email:
        preferred = email
    if not email and "@" in preferred:
        email = preferred.lower()
    if not preferred:
        raise PermissionError("OIDC identity did not include an email or username")
    allow_domains = [x.strip().lower().lstrip("@") for x in str(cfg.get("email_domain_allowlist") or "").split(",") if x.strip()]
    if allow_domains:
        domain = email.rsplit("@", 1)[-1].lower() if "@" in email else ""
        if domain not in allow_domains:
            raise PermissionError("email domain is not allowed for this control plane")
    store = _load_control_store()
    users = store.setdefault("users", {})
    candidates = [preferred, email]
    if email and "@" in email:
        candidates.append(email.split("@", 1)[0])
    for candidate in candidates:
        spec = users.get(candidate)
        if isinstance(spec, dict):
            if spec.get("enabled") is False:
                raise PermissionError("matched control-plane user is disabled")
            return candidate
    if email:
        for username, spec in users.items():
            if isinstance(spec, dict) and str(spec.get("email") or "").strip().lower() == email:
                if spec.get("enabled") is False:
                    raise PermissionError("matched control-plane user is disabled")
                return str(username)
    # Unknown OIDC users are provisioned on first login with the least-privileged Viewer role.
    username = preferred if preferred not in users else (email or preferred)
    if username in users:
        base = re.sub(r"[^A-Za-z0-9_.@-]", "-", username).strip("-") or "oidc-user"
        i = 2
        username = base
        while username in users:
            username = f"{base}-{i}"
            i += 1
    users[username] = {"password_hash": _password_hash(secrets.token_urlsafe(32)), "role": "viewer", "enabled": True, "first_name": str(info.get("given_name") or "").strip(), "last_name": str(info.get("family_name") or "").strip(), "email": email, "avatar_url": str(info.get("picture") or "").strip()}
    _save_control_store(store)
    _append_change_event({"event": "control_oidc_user_created", "actor": username, "email": email, "role": "viewer"})
    return username


def _oidc_finish_login(handler: BaseHTTPRequestHandler, query: dict[str, list[str]]) -> None:
    error = (query.get("error") or [""])[0]
    if error:
        raise PermissionError("OIDC provider returned: " + error)
    code = (query.get("code") or [""])[0]
    state = (query.get("state") or [""])[0]
    if not code or not state:
        raise ValueError("OIDC callback missing code or state")
    state_path = _oidc_state_path(state)
    try:
        state_doc = json.loads(state_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise PermissionError("OIDC state was not recognized or expired") from exc
    try:
        state_path.unlink(missing_ok=True)
    except Exception:
        pass
    ts = datetime.fromisoformat(str(state_doc.get("ts")))
    if ts + timedelta(minutes=10) < datetime.now(timezone.utc):
        raise PermissionError("OIDC state expired; start sign-in again")
    cfg = _oidc_config_private()
    if not cfg.get("enabled"):
        raise PermissionError("OIDC login is not enabled")
    info = _oidc_userinfo(cfg, _oidc_discovery(cfg), code)
    username = _oidc_find_or_create_user(info, cfg)
    _append_change_event({"event": "control_oidc_login", "actor": username, "email": str(info.get("email") or "")})
    _redirect_response(handler, "/#rules", username=username)

def _change_password(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    current = str(payload.get("current_password") or "")
    new_password = str(payload.get("new_password") or "")
    confirm_password = str(payload.get("confirm_password") or "")
    if not current:
        raise ValueError("current password is required")
    if len(new_password) < 10:
        raise ValueError("new password must be at least 10 characters")
    if new_password != confirm_password:
        raise ValueError("new passwords do not match")
    store = _load_control_store()
    users = store.setdefault("users", {})
    spec = users.get(actor)
    if not isinstance(spec, dict) or spec.get("enabled") is False:
        raise PermissionError("current user is disabled or missing")
    if not _verify_password(current, str(spec.get("password_hash") or "")):
        raise PermissionError("current password is incorrect")
    spec["password_hash"] = _password_hash(new_password)
    _save_control_store(store)
    _append_change_event({"event": "control_password_changed", "actor": actor, "username": actor})
    return {"status": "password_changed", "user": _user_public(actor, spec)}

def _append_control_audit(handler: BaseHTTPRequestHandler, status: int, payload: Any, username: str | None = None) -> None:
    if not getattr(handler, "path", "").startswith("/api/"):
        return
    try:
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "component": "google-governance-control-ui",
            "method": getattr(handler, "command", ""),
            "path": getattr(handler, "path", ""),
            "status_code": status,
            "status": "ok" if status < 400 else "error",
            "actor": username or (payload.get("user", {}).get("username") if isinstance(payload, dict) and isinstance(payload.get("user"), dict) else None),
            "error": payload.get("error") if isinstance(payload, dict) else None,
            "message": payload.get("message") if isinstance(payload, dict) else None,
            "remote": getattr(handler, "client_address", [None])[0],
        }
        CONTROL_AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with CONTROL_AUDIT_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(event, sort_keys=True, ensure_ascii=False) + "\n")
    except Exception:
        return


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: Any) -> None:
    _append_control_audit(handler, status, payload)
    raw = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def _text_response(handler: BaseHTTPRequestHandler, status: int, body: str, content_type: str = "text/html; charset=utf-8") -> None:
    raw = body.encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


def _bytes_response(handler: BaseHTTPRequestHandler, status: int, body: bytes, content_type: str) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Cache-Control", "public, max-age=300")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _download_response(handler: BaseHTTPRequestHandler, path: Path, filename: str, content_type: str = "application/gzip") -> None:
    body = path.read_bytes()
    _append_control_audit(handler, 200, {"status": "downloaded", "filename": filename})
    handler.send_response(200)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Disposition", f'attachment; filename="{filename}"')
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _tail_jsonl(path: Path, limit: int = 100) -> list[dict[str, Any]]:
    if limit < 1:
        limit = 1
    if limit > 500:
        limit = 500
    try:
        if not path.exists():
            return []
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()[-limit:]
    except PermissionError:
        return [{"ts": datetime.now(timezone.utc).isoformat(), "status": "error", "message": f"not readable: {path}", "path": str(path)}]
    rows: list[dict[str, Any]] = []
    for line in lines:
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                rows.append(obj)
        except Exception:
            continue
    return rows


def _display_time(value: Any) -> str:
    if not value:
        return ""
    raw = str(value).strip()
    try:
        normalized = raw.replace("Z", "+00:00")
        dt = datetime.fromisoformat(normalized)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(DISPLAY_TZ).strftime("%Y-%m-%d %I:%M:%S %p %Z")
    except Exception:
        return raw


def _human_service(value: str) -> str:
    mapping = {
        "gmail": "Gmail",
        "calendar": "Calendar",
        "drive": "Drive",
        "docs": "Docs",
        "sheets": "Sheets",
        "slides": "Slides",
        "contacts": "Contacts",
        "people": "Contacts",
    }
    clean = str(value or "").strip().lower().replace("google_", "")
    return mapping.get(clean, clean.replace("_", " ").title() if clean else "Google Workspace")


def _human_operation(action: str, operation: str = "") -> str:
    action = str(action or "").strip().lower()
    operation = str(operation or "").strip().lower()
    mapping = {
        "gmail.search": "searched Gmail messages in",
        "gmail.get": "opened a Gmail message in",
        "gmail.create_draft": "created a Gmail draft in",
        "gmail.send": "sent Gmail mail from",
        "gmail.modify": "changed Gmail labels in",
        "calendar.list": "listed calendar events in",
        "calendar.get": "opened a calendar event in",
        "calendar.create": "created a calendar event in",
        "calendar.update": "updated a calendar event in",
        "calendar.delete": "deleted a calendar event from",
        "drive.search": "searched Drive files in",
        "drive.get": "opened Drive file metadata in",
        "drive.copy": "copied a Drive file in",
        "drive.share": "shared a Drive file from",
        "drive.delete": "deleted a Drive file from",
        "docs.get": "read a Google Doc from",
        "docs.create": "created a Google Doc in",
        "docs.update": "updated a Google Doc in",
        "sheets.get": "read a Google Sheet from",
        "sheets.update": "updated a Google Sheet in",
        "sheets.append": "appended rows to a Google Sheet in",
        "slides.get": "read a Google Slides deck from",
        "slides.create": "created a Google Slides deck in",
        "contacts.search": "searched Google contacts in",
    }
    if action in mapping:
        return mapping[action]
    if action and "." in action:
        svc, op = action.split(".", 1)
        return f"{op.replace('_', ' ')} access in {_human_service(svc)} for"
    if operation:
        return f"{operation.replace('_', ' ')} access for"
    return "used Google Workspace access for"


def _human_outcome(event: dict[str, Any]) -> str:
    status = str(event.get("status") or event.get("status_code") or "").strip().lower()
    decision = str(event.get("decision") or "").strip().lower()
    if decision == "deny" or status in {"denied", "blocked", "forbidden", "rejected"}:
        return "blocked"
    if decision == "ask" or status in {"approval_required", "pending_approval", "needs_approval"}:
        return "held for approval"
    if status in {"error", "failed", "exception"} or status.startswith("5"):
        return "failed"
    if status.startswith("4"):
        return "rejected"
    if decision == "allow" or status in {"ok", "success", "allowed", "completed"} or status.startswith("2"):
        return "allowed"
    return "processed"


def _access_summary(event: dict[str, Any]) -> str:
    profile = str(event.get("profile") or "Unknown profile")
    action = str(event.get("action") or "")
    service = _human_service(str(event.get("service") or (action.split(".", 1)[0] if "." in action else "")))
    operation = _human_operation(action, str(event.get("operation") or ""))
    resource = str(event.get("resource_title") or event.get("resource_name") or event.get("resource_alias") or event.get("calendar") or event.get("document_title") or event.get("spreadsheet_title") or "the configured workspace resource")
    route = str(event.get("token_route") or "default")
    outcome = _human_outcome(event)
    details: list[str] = []
    if event.get("unknown_resource"):
        details.append("unknown resource")
    if event.get("high_risk_action"):
        details.append("high-risk action")
    suffix = f" ({', '.join(details)})" if details else ""
    return f"{profile} {operation} {resource} via {route}. Gateway {outcome} it{suffix}."


def _access_target_details(event: dict[str, Any]) -> list[dict[str, str]]:
    """Small, operator-safe target metadata for the live access-log expander."""
    candidates = [
        ("Profile", event.get("profile")),
        ("Action", event.get("action")),
        ("Service", event.get("service")),
        ("Operation", event.get("operation")),
        ("Resource", event.get("resource_title") or event.get("resource_name") or event.get("resource_alias")),
        ("Resource alias", event.get("resource_alias")),
        ("Token route", event.get("token_route") or "default"),
        ("Decision", event.get("decision")),
        ("Outcome", _human_outcome(event)),
        ("Request ID", event.get("request_id")),
        ("Request hash", event.get("request_hash")),
        ("Target action", event.get("target_action")),
        ("Calendar", event.get("calendar")),
        ("Document", event.get("document_title") or event.get("document_id_sha256")),
        ("Spreadsheet", event.get("spreadsheet_title") or event.get("spreadsheet_id_sha256")),
        ("File", event.get("file_name") or event.get("file_id_sha256")),
        ("Event", event.get("event_title") or event.get("event_id_sha256")),
        ("Draft", event.get("draft_id_sha256")),
    ]
    seen: set[str] = set()
    details: list[dict[str, str]] = []
    for label, value in candidates:
        if value is None or value == "":
            continue
        text = str(value)
        key = f"{label}:{text}"
        if key in seen:
            continue
        seen.add(key)
        details.append({"label": label, "value": text})
    return details


def _resolve_event_route(event: dict[str, Any], policy: dict[str, Any] | None = None, registry: dict[str, Any] | None = None) -> str:
    route = str(event.get("token_route") or "").strip()
    if route and route.lower() not in {"default", "unmapped"}:
        return route
    profile = str(event.get("profile") or "").strip()
    if not profile:
        return route or "unmapped"
    account_alias = str(event.get("account_alias") or event.get("google_account_alias") or "").strip()
    if not account_alias:
        policy = policy or _load_yaml(POLICY_PATH)
        registry = registry or _load_yaml(REGISTRY_PATH)
        resource_alias = str(event.get("resource_alias") or "").strip()
        resource = (registry.get("resources") or {}).get(resource_alias) or {}
        account_alias = str(resource.get("account_alias") or resource.get("google_account_alias") or "").strip()
        if not account_alias:
            connected = list(((policy.get("profiles") or {}).get(profile) or {}).get("connected_account_aliases") or [])
            if len(connected) == 1:
                account_alias = str(connected[0])
    if account_alias:
        return _workspace_token_route(profile, account_alias)
    return route or "unmapped"


def _public_access_event(event: dict[str, Any], policy: dict[str, Any] | None = None, registry: dict[str, Any] | None = None) -> dict[str, Any]:
    event = dict(event)
    event["token_route"] = _resolve_event_route(event, policy, registry)
    action = str(event.get("action") or "")
    service = str(event.get("service") or (action.split(".", 1)[0] if "." in action else ""))
    return {
        "ts": event.get("ts") or event.get("timestamp") or event.get("time"),
        "time_cst": _display_time(event.get("ts") or event.get("timestamp") or event.get("time")),
        "profile": event.get("profile") or "",
        "action": action,
        "service": _human_service(service),
        "operation": str(event.get("operation") or ""),
        "resource_alias": event.get("resource_alias") or "",
        "decision": event.get("decision") or "",
        "status": event.get("status") or event.get("status_code") or "",
        "outcome": _human_outcome(event),
        "token_route": event.get("token_route") or "unmapped",
        "actual_access": _access_summary(event),
        "target_details": _access_target_details(event),
        "request_id": event.get("request_id") or "",
        "high_risk_action": bool(event.get("high_risk_action")),
        "unknown_resource": bool(event.get("unknown_resource")),
        "source": "gateway",
    }


def _control_event_summary(event: dict[str, Any]) -> str:
    name = str(event.get("event") or "").strip()
    path = str(event.get("path") or "").strip()
    actor = str(event.get("actor") or "admin").strip() or "admin"
    if name == "runtime_restart_requested" or path == "/api/runtime/restart":
        return f"{actor} requested a gateway restart/reload from the control UI. Runtime logs captured the request."
    if name == "runtime_validation_checked" or path == "/api/runtime/validate":
        return f"{actor} ran runtime config validation from the control UI."
    if name == "runtime_backup_created" or path == "/api/runtime/backup/create":
        return f"{actor} created a runtime backup from the control UI."
    if name == "runtime_backup_exported" or path == "/api/runtime/backup/export":
        return f"{actor} exported runtime backup metadata from the control UI."
    if name == "runtime_backup_import_checked" or path == "/api/runtime/backup/import":
        return f"{actor} checked a runtime backup import from the control UI."
    if name == "runtime_policy_applied" or path == "/api/runtime/apply":
        return f"{actor} applied runtime policy from the control UI."
    if name.startswith("jwt_secret_"):
        return f"{actor} updated JWT signing-secret custody from the control UI."
    if path:
        return f"{actor} called {path} in the control UI."
    return f"{actor} performed {name or 'a control-plane action'} in the control UI."


def _public_control_event(event: dict[str, Any]) -> dict[str, Any]:
    event = dict(event)
    name = str(event.get("event") or event.get("path") or "control-ui")
    status = str(event.get("status") or event.get("status_code") or "ok")
    return {
        "ts": event.get("ts") or event.get("timestamp") or event.get("time"),
        "time_cst": _display_time(event.get("ts") or event.get("timestamp") or event.get("time")),
        "profile": event.get("actor") or "admin",
        "action": name,
        "service": "Control UI",
        "operation": str(event.get("method") or event.get("event") or ""),
        "resource_alias": "runtime_control",
        "decision": "allowed",
        "status": status,
        "outcome": "succeeded" if str(status).lower() in {"ok", "200", "201", "204"} else str(status),
        "token_route": "control-ui",
        "actual_access": _control_event_summary(event),
        "target_details": [
            {"label": "Source", "value": "control UI"},
            {"label": "Path/Event", "value": name},
            {"label": "Status", "value": status},
        ],
        "request_id": "",
        "high_risk_action": False,
        "unknown_resource": False,
        "source": "control",
    }


def _merge_access_events(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    order: list[tuple[str, str, str]] = []
    for row in rows:
        key = (str(row.get("ts") or row.get("time_cst") or ""), str(row.get("profile") or ""), str(row.get("token_route") or ""))
        if key not in grouped:
            grouped[key] = dict(row)
            grouped[key]["_count"] = 1
            order.append(key)
            continue
        base = grouped[key]
        base["_count"] = int(base.get("_count") or 1) + 1
        for field in ("action", "service", "operation", "resource_alias", "decision", "outcome", "status"):
            values = [v.strip() for v in str(base.get(field) or "").split(",") if v.strip()]
            next_value = str(row.get(field) or "").strip()
            if next_value and next_value not in values:
                values.append(next_value)
            base[field] = ", ".join(values)
        base["high_risk_action"] = bool(base.get("high_risk_action")) or bool(row.get("high_risk_action"))
        base["unknown_resource"] = bool(base.get("unknown_resource")) or bool(row.get("unknown_resource"))
        base["target_details"] = list(base.get("target_details") or []) + [d for d in list(row.get("target_details") or []) if d not in list(base.get("target_details") or [])]
        base["actual_access"] = f"{base.get('profile') or 'Unknown profile'} made {base['_count']} Google Workspace requests via {base.get('token_route') or 'unmapped'}. Gateway outcomes: {base.get('outcome') or 'processed'}."
    return [grouped[key] for key in order]


def _access_log(limit: int = 100) -> dict[str, Any]:
    policy = _load_yaml(POLICY_PATH)
    registry = _load_yaml(REGISTRY_PATH)
    gateway_rows = [_public_access_event(row, policy, registry) for row in _tail_jsonl(GATEWAY_AUDIT_LOG_PATH, limit)]
    gateway_rows = _merge_access_events(gateway_rows)
    control_raw = [row for row in _tail_jsonl(CONTROL_AUDIT_LOG_PATH, limit) if not (row.get("status") == "error" and str(row.get("message") or "").startswith("not readable:"))]
    change_raw = [row for row in _tail_jsonl(CHANGE_LOG_PATH, limit) if not (row.get("status") == "error" and str(row.get("message") or "").startswith("not readable:"))]
    control_rows = [_public_control_event(row) for row in control_raw]
    change_rows = [_public_control_event(row) for row in change_raw]
    rows = gateway_rows + control_rows + change_rows
    rows.sort(key=lambda r: str(r.get("ts") or ""), reverse=True)
    return {"status": "ok", "path": str(GATEWAY_AUDIT_LOG_PATH), "control_path": str(CONTROL_AUDIT_LOG_PATH), "change_path": str(CHANGE_LOG_PATH), "events": rows[:limit]}



def _alias_key(value: str | None) -> str:
    return str(value or "").strip().lower().replace("_", "-")


_ACCOUNT_ALIAS_EQUIVALENTS = {
    "personal-workspace": {"personal-workspace", "personal-primary", "karthiktanya2021"},
    "business-workspace": {"business-workspace", "business-airbnb", "business-karthikvenkat"},
}
_ACCOUNT_ALIAS_CANONICAL = {
    alias: canonical
    for canonical, aliases in _ACCOUNT_ALIAS_EQUIVALENTS.items()
    for alias in aliases
}


def _account_alias_keys(value: str | None) -> set[str]:
    key = _alias_key(value)
    if not key:
        return set()
    canonical = _ACCOUNT_ALIAS_CANONICAL.get(key, key)
    return set(_ACCOUNT_ALIAS_EQUIVALENTS.get(canonical, {canonical, key})) | {key, canonical}


def _account_alias_equivalent(left: str | None, right: str | None) -> bool:
    return bool(_account_alias_keys(left) & _account_alias_keys(right))


def _account_dir(account_alias: str) -> Path:
    alias = str(account_alias or "").strip().replace("/", "-")
    if not alias or any(ch in alias for ch in "\\:\0") or alias in {".", ".."}:
        raise ValueError("account alias is required")
    return GOOGLE_WORKSPACE_TOKEN_ROOT / alias


def _oauth_client_secret_path(account_alias: str) -> Path:
    return GOOGLE_OAUTH_STATE_ROOT / "clients" / str(account_alias).strip().replace("/", "-") / "client_secret.json"


def _oauth_pending_path(state: str) -> Path:
    return GOOGLE_OAUTH_STATE_ROOT / "pending" / (str(state).strip() + ".json")


def _oauth_metadata_path(account_alias: str) -> Path:
    return _account_dir(account_alias) / "account.json"


def _token_id(account_alias: str, bundle: str = "workspace-full.json") -> str:
    return f"{_safe_alias(account_alias)}/{Path(bundle).name}"


def _token_display_label(account_alias: str, email: str | None = None, token_label: str | None = None) -> str:
    custom = str(token_label or "").strip()
    if custom:
        return custom[:80]
    alias = _safe_alias(account_alias) if str(account_alias or "").strip() else "workspace"
    email_s = str(email or "").strip().lower()
    friendly_by_alias = {
        "business_workspace": "business-airbnb",
        "business-workspace": "business-airbnb",
        "business_airbnb": "business-airbnb",
        "business-airbnb": "business-airbnb",
        "personal_workspace": "personal-primary",
        "personal-workspace": "personal-primary",
        "personal_primary": "personal-primary",
        "personal-primary": "personal-primary",
    }
    friendly_by_email = {
        "business.karthikvenkat@gmail.com": "business-airbnb",
        "karthiktanya2021@gmail.com": "personal-primary",
    }
    return friendly_by_alias.get(alias) or friendly_by_email.get(email_s) or (f"{alias} — {email_s}" if email_s else alias)


def _account_display_label(account_alias: str | None, email: str | None = None, token_label: str | None = None) -> str:
    """Short human-facing account name for dashboards, filters, and route pickers."""
    label = _token_display_label(account_alias or "workspace", email, token_label)
    return label.split(" — ", 1)[0] if " — " in label else label


def _account_alias_from_email(email: str | None) -> str:
    email_s = str(email or "").strip().lower()
    base = email_s.split("@", 1)[0] if "@" in email_s else email_s
    return _safe_alias(base or "google-workspace")


def _account_alias_from_label(label: str | None) -> str:
    label_s = str(label or "").strip()
    if not label_s:
        return ""
    # If Google cannot return an email, prefer the friendly token name Admin
    # typed over a generic `google-workspace` alias so generated routes remain
    # readable.
    return _safe_alias(label_s)


def _oauth_account_alias(email: str | None, token_label: str | None = None) -> str:
    email_s = str(email or "").strip()
    if email_s:
        return _account_alias_from_email(email_s)
    return _account_alias_from_label(token_label) or "google-workspace"


def _unique_account_alias(preferred: str) -> str:
    base = _safe_alias(preferred or "google-workspace")
    existing = {_alias_key(item.get("account_alias")) for item in _token_inventory_items(include_files=False)}
    if _alias_key(base) not in existing:
        return base
    for idx in range(2, 100):
        candidate = f"{base}-{idx}"
        if _alias_key(candidate) not in existing:
            return candidate
    return f"{base}-{secrets.token_hex(3)}"


def _decode_jwt_payload(token: str | None) -> dict[str, Any]:
    token_s = str(token or "")
    parts = token_s.split(".")
    if len(parts) < 2:
        return {}
    try:
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload.encode("ascii")).decode("utf-8"))
    except Exception:
        return {}


def _discover_oauth_email(token_response: dict[str, Any]) -> str:
    jwt_payload = _decode_jwt_payload(token_response.get("id_token"))
    email = str(jwt_payload.get("email") or "").strip()
    if email:
        return email
    access_token = str(token_response.get("access_token") or "").strip()
    if not access_token:
        return ""
    req = urllib.request.Request("https://www.googleapis.com/oauth2/v3/userinfo", headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            info = json.loads(resp.read().decode("utf-8") or "{}")
        return str(info.get("email") or "").strip()
    except Exception:
        pass
    # Older authorization URLs may not have requested openid/email, so Google can
    # omit id_token and reject userinfo. tokeninfo often still returns the email
    # for Google API access tokens; use it before falling back to the typed label.
    try:
        url = "https://www.googleapis.com/oauth2/v3/tokeninfo?" + urllib.parse.urlencode({"access_token": access_token})
        with urllib.request.urlopen(url, timeout=10) as resp:
            info = json.loads(resp.read().decode("utf-8") or "{}")
        return str(info.get("email") or "").strip()
    except Exception:
        return ""


def _store_workspace_token(account_alias: str, bundle: str, token_payload: dict[str, Any], metadata: dict[str, Any]) -> None:
    account_alias = _safe_alias(account_alias)
    bundle = Path(bundle or "workspace-full.json").name
    raw_scopes = token_payload.get("scopes") or token_payload.get("scope") or metadata.get("scopes") or []
    if isinstance(raw_scopes, str):
        scopes = [x for x in raw_scopes.split() if x]
    else:
        scopes = [str(x) for x in raw_scopes if x]
    email = str(metadata.get("email") or token_payload.get("email") or "")
    with _control_db() as conn:
        conn.execute(
            """
            INSERT INTO workspace_tokens(id,account_alias,bundle,email,token_json,metadata_json,scopes_json,status,revoked_at,updated_at)
            VALUES(?,?,?,?,?,?,?,'connected','',CURRENT_TIMESTAMP)
            ON CONFLICT(id) DO UPDATE SET
              account_alias=excluded.account_alias, bundle=excluded.bundle, email=excluded.email,
              token_json=excluded.token_json, metadata_json=excluded.metadata_json, scopes_json=excluded.scopes_json,
              status='connected', revoked_at='', updated_at=CURRENT_TIMESTAMP
            """,
            (_token_id(account_alias, bundle), account_alias, bundle, email, json.dumps(token_payload, sort_keys=True), json.dumps(metadata, sort_keys=True), json.dumps(scopes)),
        )
        conn.commit()


def _promote_generic_workspace_token_alias(token_id: str) -> dict[str, Any] | None:
    """Rename a generic existing SQLite token row from its friendly label before mapping."""
    token_id = str(token_id or "").strip()
    if not token_id:
        return None
    generic_aliases = {"google-workspace", "google_workspace", "workspace"}
    with _control_db() as conn:
        row = conn.execute("SELECT * FROM workspace_tokens WHERE id=? AND revoked_at=''", (token_id,)).fetchone()
        if not row or _alias_key(row["account_alias"]) not in {_alias_key(x) for x in generic_aliases}:
            return None
        metadata = json.loads(row["metadata_json"] or "{}")
        label = str(metadata.get("token_label") or metadata.get("label") or "").strip()
        candidate = _account_alias_from_label(label)
        if not candidate or _alias_key(candidate) == _alias_key(row["account_alias"]):
            return None
        exists = conn.execute("SELECT 1 FROM workspace_tokens WHERE account_alias=? AND revoked_at=''", (candidate,)).fetchone()
        if exists:
            return None
        bundle = Path(str(row["bundle"] or "workspace-full.json")).name
        new_id = _token_id(candidate, bundle)
        metadata["account_alias"] = candidate
        conn.execute(
            "UPDATE workspace_tokens SET id=?, account_alias=?, metadata_json=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
            (new_id, candidate, json.dumps(metadata, sort_keys=True), token_id),
        )
        conn.commit()
    return _get_workspace_token(new_id)


def _get_workspace_token(token_id: str) -> dict[str, Any] | None:
    with _control_db() as conn:
        row = conn.execute("SELECT * FROM workspace_tokens WHERE id=? AND revoked_at=''", (str(token_id),)).fetchone()
    if not row:
        return None
    token_json = json.loads(row["token_json"] or "{}")
    metadata = json.loads(row["metadata_json"] or "{}")
    scopes = json.loads(row["scopes_json"] or "[]")
    return {"id": row["id"], "account_alias": row["account_alias"], "bundle": row["bundle"], "email": row["email"], "token_json": token_json, "metadata": metadata, "scopes": scopes, "status": row["status"], "updated_at": row["updated_at"], "store": "sqlite"}


def _db_token_inventory_items() -> list[dict[str, Any]]:
    _dedupe_workspace_tokens()
    with _control_db() as conn:
        rows = conn.execute("SELECT id,account_alias,bundle,email,token_json,metadata_json,scopes_json,status,updated_at FROM workspace_tokens WHERE revoked_at='' ORDER BY account_alias,bundle").fetchall()
    items: list[dict[str, Any]] = []
    for row in rows:
        spec = json.loads(row["token_json"] or "{}")
        metadata = json.loads(row["metadata_json"] or "{}")
        scopes = json.loads(row["scopes_json"] or "[]")
        has_refresh = bool(spec.get("refresh_token"))
        email = _workspace_display_email(metadata, spec, row["email"])
        token_label = metadata.get("token_label") or metadata.get("label")
        display_label = _workspace_token_label(metadata, row["account_alias"], email)
        items.append({
            "id": row["id"],
            "label": display_label,
            "account_alias": row["account_alias"],
            "account_display": _account_display_label(row["account_alias"], email, token_label),
            "alias_keys": sorted(_account_alias_keys(row["account_alias"])),
            "bundle": Path(row["bundle"]).stem,
            "email": email,
            "token_status": "connected" if has_refresh else "missing refresh token",
            "has_refresh_token": has_refresh,
            "scopes": scopes,
            "updated_at": row["updated_at"],
            "store": "sqlite",
        })
    return items



def _oauth_services_to_scopes(services: Any) -> list[str]:
    if isinstance(services, str):
        if services in {"full_workspace", "all"}:
            names = GOOGLE_OAUTH_DEFAULT_SERVICES
        else:
            names = [x.strip() for x in services.replace(",", " ").split() if x.strip()]
    elif isinstance(services, list):
        names = [str(x).strip() for x in services if str(x).strip()]
    else:
        names = GOOGLE_OAUTH_DEFAULT_SERVICES
    scopes: list[str] = []
    for name in names:
        scope = GOOGLE_OAUTH_SCOPE_MAP.get(name, name if name.startswith("https://www.googleapis.com/auth/") else "")
        if scope and scope not in scopes:
            scopes.append(scope)
    if not scopes:
        scopes = [GOOGLE_OAUTH_SCOPE_MAP[x] for x in GOOGLE_OAUTH_DEFAULT_SERVICES]
    return scopes


def _oauth_scopes_to_services(scopes: list[str]) -> list[str]:
    services: list[str] = []
    for scope in scopes:
        for service, mapped in GOOGLE_OAUTH_SCOPE_MAP.items():
            if scope == mapped and service not in services:
                services.append(service)
    return services


def _safe_alias(raw: str) -> str:
    alias = re.sub(r"[^a-zA-Z0-9_-]+", "_", str(raw or "").strip()).strip("_-").lower()
    if not alias:
        raise ValueError("account token name is required")
    return alias


def _profile_list(payload: dict[str, Any] | None, *, known_profiles: set[str]) -> list[str]:
    payload = payload or {}
    raw = payload.get("profiles")
    if raw is None:
        raw = payload.get("profile")
    if isinstance(raw, str):
        items = [x.strip() for x in raw.replace(",", " ").split() if x.strip()]
    elif isinstance(raw, list):
        items = [str(x).strip() for x in raw if str(x).strip()]
    else:
        items = []
    profiles = sorted(dict.fromkeys(items))
    unknown = [p for p in profiles if p not in known_profiles]
    if unknown:
        raise ValueError("choose existing profile(s): " + ", ".join(unknown))
    return profiles


_CATALOG_ACTIONS_BY_SERVICE = workspace_actions_by_service()

_WORKSPACE_RESOURCE_TEMPLATES = {
    "gmail": {"alias": "gmail_{slug}", "type": "gmail_mailbox", "title": "Google Workspace Gmail - {label}", "actions": _CATALOG_ACTIONS_BY_SERVICE.get("gmail", []), "sensitivity": "private"},
    "calendar": {"alias": "calendar_{slug}_primary", "type": "calendar", "title": "Google Workspace primary calendar - {label}", "actions": _CATALOG_ACTIONS_BY_SERVICE.get("calendar", []), "sensitivity": "private", "extra": {"calendar_id": "primary"}},
    "drive": {"alias": "drive_{slug}_workspace", "type": "drive_workspace", "title": "Google Workspace Drive - {label}", "actions": _CATALOG_ACTIONS_BY_SERVICE.get("drive", []), "sensitivity": "private"},
    "sheets": {"alias": "sheets_{slug}_workspace", "type": "spreadsheet_workspace", "title": "Google Workspace Sheets - {label}", "actions": _CATALOG_ACTIONS_BY_SERVICE.get("sheets", []), "sensitivity": "private"},
    "docs": {"alias": "docs_{slug}_workspace", "type": "document_workspace", "title": "Google Workspace Docs - {label}", "actions": _CATALOG_ACTIONS_BY_SERVICE.get("docs", []), "sensitivity": "private"},
    "slides": {"alias": "slides_{slug}_workspace", "type": "presentation_workspace", "title": "Google Workspace Slides - {label}", "actions": _CATALOG_ACTIONS_BY_SERVICE.get("slides", []), "sensitivity": "private"},
    "people": {"alias": "contacts_{slug}", "type": "contacts", "title": "Google Workspace Contacts - {label}", "actions": _CATALOG_ACTIONS_BY_SERVICE.get("contacts", []), "sensitivity": "private"},
    "forms": {"alias": "forms_{slug}_workspace", "type": "forms_workspace", "title": "Google Workspace Forms - {label}", "actions": _CATALOG_ACTIONS_BY_SERVICE.get("forms", []), "sensitivity": "private"},
    "tasks": {"alias": "tasks_{slug}_workspace", "type": "tasks_workspace", "title": "Google Workspace Tasks - {label}", "actions": _CATALOG_ACTIONS_BY_SERVICE.get("tasks", []), "sensitivity": "private"},
    "chat": {"alias": "chat_{slug}_workspace", "type": "chat_workspace", "title": "Google Workspace Chat - {label}", "actions": _CATALOG_ACTIONS_BY_SERVICE.get("chat", []), "sensitivity": "private"},
    "search": {"alias": "search_{slug}_workspace", "type": "custom_search", "title": "Google Custom Search - {label}", "actions": _CATALOG_ACTIONS_BY_SERVICE.get("search", []), "sensitivity": "world"},
    "apps_script": {"alias": "apps_script_{slug}_workspace", "type": "apps_script_workspace", "title": "Google Apps Script - {label}", "actions": _CATALOG_ACTIONS_BY_SERVICE.get("apps_script", []), "sensitivity": "private"},
}

GOOGLE_WORKSPACE_ACTIONS = sorted({
    action
    for template in _WORKSPACE_RESOURCE_TEMPLATES.values()
    for action in template.get("actions", [])
})


def _operation_default_decision(policy: dict[str, Any], action: str) -> str:
    for spec in (policy.get("operation_classes") or {}).values():
        if action in (spec.get("actions") or []):
            decision = str(spec.get("default_decision") or "ask")
            return decision if decision in ALLOWED_DECISIONS else "ask"
    return "ask"


def _workspace_resource_specs(account_alias: str, scopes: list[str], email: str) -> list[dict[str, Any]]:
    slug = _safe_alias(account_alias)
    label = email or account_alias
    specs: list[dict[str, Any]] = []
    for service in _oauth_scopes_to_services(scopes):
        tmpl = _WORKSPACE_RESOURCE_TEMPLATES.get(service)
        if not tmpl:
            continue
        specs.append({
            "resource_alias": tmpl["alias"].format(slug=slug),
            "type": tmpl["type"],
            "title_hint": tmpl["title"].format(label=label),
            "account_alias": account_alias,
            "sensitivity": tmpl["sensitivity"],
            "allowed_operations": list(tmpl["actions"]),
            "notes": "Auto-created when the Google Workspace account was connected from the control UI. Review ACL decisions before broad use.",
            **dict(tmpl.get("extra") or {}),
        })
    return specs


def _workspace_token_route(profile: str, account_alias: str) -> str:
    return f"{_safe_alias(profile)}/{_safe_alias(account_alias)}"


def _ensure_workspace_acl_resources(account_alias: str, profiles: list[str], scopes: list[str], email: str, actor: str) -> dict[str, Any]:
    account_alias = _safe_alias(account_alias)
    policy = _load_yaml(POLICY_PATH)
    registry = _load_yaml(REGISTRY_PATH)
    known_profiles = set((policy.get("profile_policy", {}) or {}).keys())
    profiles = _profile_list({"profiles": profiles}, known_profiles=known_profiles)
    if not profiles:
        return {"status": "skipped", "profiles": [], "resources": [], "rules": 0, "message": "No profile selected; token connected without ACL rows."}

    changed = False
    resource_specs = _workspace_resource_specs(account_alias, scopes, email)
    registry_account = registry.setdefault("account_aliases", {}).setdefault(account_alias, {})
    for key, value in {
        "google_account_hint": email or registry_account.get("google_account_hint") or account_alias,
        "verification_status": "connected_from_control_ui",
        "token_namespace": f"tokens/accounts/{account_alias}/",
    }.items():
        if registry_account.get(key) != value:
            registry_account[key] = value
            changed = True
    routes = registry_account.setdefault("current_profile_routes", {})
    for profile in profiles:
        route = _workspace_token_route(profile, account_alias)
        if routes.get(profile) != route:
            routes[profile] = route
            changed = True

    policy_account = policy.setdefault("accounts", {}).setdefault(account_alias, {})
    for key, value in {
        "description": f"Google Workspace account connected from the control UI ({email or account_alias}).",
        "token_namespace": f"tokens/accounts/{account_alias}/",
        "status": "connected_from_control_ui",
    }.items():
        if policy_account.get(key) != value:
            policy_account[key] = value
            changed = True
    policy_routes = policy_account.setdefault("current_profile_routes", {})
    for profile in profiles:
        route = _workspace_token_route(profile, account_alias)
        if policy_routes.get(profile) != route:
            policy_routes[profile] = route
            changed = True

    created_resources: list[str] = []
    removed_resources: list[str] = []
    removed_rules: list[str] = []
    rule_count = 0
    current_resource_aliases = {spec["resource_alias"] for spec in resource_specs}
    current_actions = {str(action) for spec in resource_specs for action in (spec.get("allowed_operations") or []) if str(action).strip()}
    registry_resources = registry.setdefault("resources", {})
    registry_profiles = registry.setdefault("profiles", {})
    policy_profiles_meta = policy.setdefault("profiles", {})
    policy_profiles = policy.setdefault("profile_policy", {})

    stale_resource_aliases = [
        alias for alias, spec in list(registry_resources.items())
        if _account_alias_equivalent((spec or {}).get("account_alias"), account_alias) and alias not in current_resource_aliases
    ]
    stale_actions = {
        str(action)
        for alias in stale_resource_aliases
        for action in ((registry_resources.get(alias) or {}).get("allowed_operations") or [])
        if str(action).strip()
    }

    def profile_actions_from_other_accounts(profile: str) -> set[str]:
        profile_scope = set((registry_profiles.get(profile) or {}).get("default_resource_scope") or [])
        actions: set[str] = set()
        for alias, resource in (registry_resources or {}).items():
            if alias in stale_resource_aliases or _account_alias_equivalent((resource or {}).get("account_alias"), account_alias):
                continue
            if alias in profile_scope or profile in set((resource or {}).get("profile_scope") or []):
                actions.update(str(a) for a in ((resource or {}).get("allowed_operations") or []) if str(a).strip())
        return {a for a in actions if a in GOOGLE_WORKSPACE_ACTIONS}

    for profile in profiles:
        reg_profile = registry_profiles.setdefault(profile, {})
        scope = list(reg_profile.get("default_resource_scope") or [])
        new_scope = [alias for alias in scope if alias not in stale_resource_aliases]
        if new_scope != scope:
            reg_profile["default_resource_scope"] = new_scope
            changed = True
        p_spec = policy_profiles.setdefault(profile, {"defaults": {}, "resource_overrides": {}})
        overrides = p_spec.setdefault("resource_overrides", {})
        for alias in stale_resource_aliases:
            if alias in overrides:
                overrides.pop(alias, None)
                removed_resources.append(alias)
                changed = True
        # Profile defaults are user-authored profile + Workspace operation policy.
        # Do not prune or reset them during OAuth reconnect/revoke/remap flows:
        # token routes and resource inventory may change, but ACL intent must be
        # stable unless the user explicitly edits ACL policy. Previously this sync
        # removed defaults whose actions were temporarily not backed by a routed
        # account; reconnecting/remapping then recreated them from global defaults
        # (usually "ask"), overwriting explicit choices such as Gmail draft=allow.
        defaults = p_spec.setdefault("defaults", {})
    for alias in stale_resource_aliases:
        spec = registry_resources.get(alias) or {}
        old_scope = list(spec.get("profile_scope") or [])
        new_scope = [profile for profile in old_scope if profile not in profiles]
        if new_scope != old_scope:
            spec["profile_scope"] = new_scope
            changed = True
        if not new_scope:
            registry_resources.pop(alias, None)
            removed_resources.append(alias)
            changed = True

    for spec in resource_specs:
        alias = spec["resource_alias"]
        existing = registry_resources.setdefault(alias, {})
        if not existing:
            created_resources.append(alias)
        profile_scope = sorted(set(existing.get("profile_scope") or []) | set(profiles))
        merged = {**spec, "profile_scope": profile_scope}
        if existing != {**existing, **merged}:
            existing.update(merged)
            changed = True
        for profile in profiles:
            reg_profile = registry_profiles.setdefault(profile, {})
            scope = list(reg_profile.get("default_resource_scope") or [])
            if alias not in scope:
                scope.append(alias)
                reg_profile["default_resource_scope"] = scope
                changed = True
            meta_profile = policy_profiles_meta.setdefault(profile, {})
            connected = list(meta_profile.get("connected_account_aliases") or [])
            if account_alias not in connected:
                connected.append(account_alias)
                meta_profile["connected_account_aliases"] = connected
                changed = True
            p_spec = policy_profiles.setdefault(profile, {"defaults": {}, "resource_overrides": {}})
            connected_aliases = list(p_spec.get("account_aliases") or [])
            if account_alias not in connected_aliases:
                connected_aliases.append(account_alias)
                p_spec["account_aliases"] = connected_aliases
                changed = True
            if not p_spec.get("account_alias"):
                p_spec["account_alias"] = account_alias
                changed = True
            defaults = p_spec.setdefault("defaults", {})
            # ACL control is profile + Workspace operation, not per individual
            # Google resource. Routes choose the Google account; these defaults
            # decide whether that profile may perform Gmail/Docs/Sheets/etc.
            for action in spec["allowed_operations"]:
                decision = str(defaults.get(action) or _operation_default_decision(policy, action))
                if decision not in ALLOWED_DECISIONS:
                    decision = "ask"
                if defaults.get(action) != decision:
                    defaults[action] = decision
                    changed = True
                    rule_count += 1

    if changed:
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        shutil.copy2(REGISTRY_PATH, REGISTRY_PATH.with_suffix(REGISTRY_PATH.suffix + f".{stamp}.bak"))
        shutil.copy2(POLICY_PATH, POLICY_PATH.with_suffix(POLICY_PATH.suffix + f".{stamp}.bak"))
        summary = f"Workspace ACL YAML synced for account {account_alias} and profiles {', '.join(profiles or [])}"
        _write_yaml_document(REGISTRY_PATH, registry, summary=summary)
        _write_yaml_document(POLICY_PATH, policy, summary=summary)
        _record_yaml_sync_event(actor, "ok", "workspace_acl_yaml_written", {"account_alias": account_alias, "profiles": profiles})
        runtime_policy = _generate_policy_json(policy)
        runtime_install = _stage_and_install_runtime_policy(runtime_policy)
        restart = _systemctl_restart_gateway()
    else:
        runtime_install = None
        restart = {"service": GATEWAY_SERVICE, "skipped": "no registry or policy change"}
    event = {"event": "workspace_acl_resources_synced", "actor": actor, "account_alias": account_alias, "profiles": profiles, "routes": {profile: _workspace_token_route(profile, account_alias) for profile in profiles}, "resources": [r["resource_alias"] for r in resource_specs], "created_resources": created_resources, "removed_resources": sorted(set(removed_resources)), "removed_rules": sorted(set(removed_rules)), "rules_written": rule_count, "changed": changed}
    _append_change_event(event)
    return {"status": "synced", **event, "runtime_install": runtime_install, "restart": restart}


def _parse_client_secret(raw: str) -> dict[str, Any]:
    try:
        spec = json.loads(raw)
    except Exception as exc:
        raise ValueError("client_secret.json is not valid JSON") from exc
    client = spec.get("installed") or spec.get("web") or spec
    client_id = str(client.get("client_id") or "").strip()
    client_secret = str(client.get("client_secret") or "").strip()
    auth_uri = str(client.get("auth_uri") or GOOGLE_OAUTH_AUTH_ENDPOINT).strip()
    token_uri = str(client.get("token_uri") or GOOGLE_OAUTH_TOKEN_ENDPOINT).strip()
    redirect_uris = client.get("redirect_uris") or ["http://localhost"]
    redirect_uri = next((str(x) for x in redirect_uris if str(x).startswith("http://localhost")), str(redirect_uris[0]))
    if not client_id or not client_secret:
        raise ValueError("client_secret.json must contain an OAuth Desktop App client_id and client_secret")
    return {"client_id": client_id, "client_secret": client_secret, "auth_uri": auth_uri, "token_uri": token_uri, "redirect_uri": redirect_uri}


def _write_secret_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def _oauth_start(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    raw_alias = str(payload.get("account_alias") or "").strip()
    account_alias = _safe_alias(raw_alias) if raw_alias else ""
    raw_secret = str(payload.get("client_secret_json") or payload.get("client_secret") or "").strip()
    token_label = str(payload.get("token_label") or payload.get("label") or "").strip()[:80]
    if not raw_secret:
        raise ValueError("paste or upload a Google OAuth Desktop App client_secret.json")
    client = _parse_client_secret(raw_secret)
    # Workspace connection is intentionally no-choice in the UI: a valid Desktop
    # App client secret starts the standard full Workspace authorization set.
    # Profile/resource ACLs remain the layer that narrows actual agent access.
    scopes = _oauth_services_to_scopes(None)
    state = secrets.token_urlsafe(24)
    pending = {"ts": datetime.now(timezone.utc).isoformat(), "actor": actor, "account_alias": account_alias, "token_label": token_label, "scopes": scopes, "state": state, "redirect_uri": client["redirect_uri"], "status": "authorization_url_generated"}
    params = {"client_id": client["client_id"], "redirect_uri": client["redirect_uri"], "response_type": "code", "scope": " ".join(scopes), "access_type": "offline", "prompt": "consent", "include_granted_scopes": "true", "state": state}
    auth_url = client["auth_uri"] + "?" + urllib.parse.urlencode(params)
    with _control_db() as conn:
        conn.execute("INSERT INTO workspace_access_requests(ts,actor,profile,account_alias,scopes,status,state,token_label,updated_at) VALUES(?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)", (pending["ts"], actor, "", account_alias, " ".join(scopes), "authorization_url_generated", state, token_label))
        conn.execute("INSERT OR REPLACE INTO oauth_pending(state,ts,actor,account_alias,scopes_json,client_json,redirect_uri,token_label,status,updated_at) VALUES(?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)", (state, pending["ts"], actor, account_alias, json.dumps(scopes), json.dumps(client), client["redirect_uri"], token_label, "authorization_url_generated"))
        conn.commit()
    _append_change_event({"event": "google_oauth_authorization_url_generated", "actor": actor, "account_alias": account_alias, "scopes": scopes, "state_hash": hashlib.sha256(state.encode()).hexdigest()[:16]})
    return {"status": "authorization_url_generated", "authorization_url": auth_url, "state": state, "redirect_uri": client["redirect_uri"], "scopes": scopes, "message": "Open the authorization URL, approve access, then paste the final redirect URL or code here. Profile-to-token ACL mapping is configured after connection."}


def _profiles_for_account_alias(account_alias: str) -> list[str]:
    """Profiles currently mapped to a workspace account alias."""
    policy = _load_yaml(POLICY_PATH)
    out: list[str] = []
    for profile, spec in sorted((policy.get("profile_policy") or {}).items()):
        aliases = list((spec or {}).get("account_aliases") or [])
        if (spec or {}).get("account_alias"):
            aliases.append((spec or {}).get("account_alias"))
        if any(_account_alias_equivalent(alias, account_alias) for alias in aliases):
            out.append(str(profile))
    if not out:
        for profile, spec in sorted((policy.get("profiles") or {}).items()):
            aliases = list((spec or {}).get("connected_account_aliases") or [])
            if (spec or {}).get("account_alias"):
                aliases.append((spec or {}).get("account_alias"))
            if any(_account_alias_equivalent(alias, account_alias) for alias in aliases):
                out.append(str(profile))
    return sorted(set(out))


def _oauth_reauthorize(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    """Start OAuth consent for an existing workspace token to pick up expanded scopes."""
    token_id = str(payload.get("token_id") or "").strip()
    stored = _get_workspace_token(token_id) if token_id else None
    if not stored:
        raise ValueError("select an existing workspace token to reauthorize")
    token_payload = dict(stored.get("token_json") or {})
    raw_secret = str(payload.get("client_secret_json") or payload.get("client_secret") or "").strip()
    if raw_secret:
        client = _parse_client_secret(raw_secret)
    else:
        client_id = str(token_payload.get("client_id") or "").strip()
        client_secret = str(token_payload.get("client_secret") or "").strip()
        if not client_id or not client_secret:
            raise ValueError("stored token is missing OAuth client details; upload client_secret.json from Configure new workspace")
        client = {"client_id": client_id, "client_secret": client_secret, "auth_uri": GOOGLE_OAUTH_AUTH_ENDPOINT, "token_uri": GOOGLE_OAUTH_TOKEN_ENDPOINT, "redirect_uri": str(payload.get("redirect_uri") or "http://localhost")}
    # Carry the exact existing workspace_tokens.id through the OAuth pending row.
    # Reauthorization is an in-place scope/token update, not a new workspace connection.
    client["__reauthorize_token_id"] = token_id
    account_alias = str(stored.get("account_alias") or "").strip()
    meta = dict(stored.get("metadata") or {})
    token_label = str(payload.get("token_label") or meta.get("token_label") or stored.get("email") or account_alias).strip()[:80]
    scopes = _oauth_services_to_scopes(None)
    state = secrets.token_urlsafe(24)
    params = {"client_id": client["client_id"], "redirect_uri": client["redirect_uri"], "response_type": "code", "scope": " ".join(scopes), "access_type": "offline", "prompt": "consent", "include_granted_scopes": "true", "state": state}
    auth_url = client["auth_uri"] + "?" + urllib.parse.urlencode(params)
    ts = datetime.now(timezone.utc).isoformat()
    with _control_db() as conn:
        conn.execute("INSERT INTO workspace_access_requests(ts,actor,profile,account_alias,scopes,status,state,token_label,updated_at) VALUES(?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)", (ts, actor, "", account_alias, " ".join(scopes), "reauthorization_url_generated", state, token_label))
        conn.execute("INSERT OR REPLACE INTO oauth_pending(state,ts,actor,account_alias,scopes_json,client_json,redirect_uri,token_label,status,updated_at) VALUES(?,?,?,?,?,?,?,?,?,CURRENT_TIMESTAMP)", (state, ts, actor, account_alias, json.dumps(scopes), json.dumps(client), client["redirect_uri"], token_label, "reauthorization_url_generated"))
        conn.commit()
    _append_change_event({"event": "google_oauth_reauthorization_url_generated", "actor": actor, "account_alias": account_alias, "token_id": token_id, "scopes": scopes, "state_hash": hashlib.sha256(state.encode()).hexdigest()[:16]})
    return {"status": "reauthorization_url_generated", "authorization_url": auth_url, "state": state, "redirect_uri": client["redirect_uri"], "account_alias": account_alias, "scopes": scopes, "message": "Open the authorization URL, approve expanded scopes, then paste the final redirect URL/code in the reauthorization panel."}


def _extract_oauth_code(payload: dict[str, Any]) -> tuple[str, str]:
    code = str(payload.get("code") or "").strip()
    state = str(payload.get("state") or "").strip()
    redirect = str(payload.get("redirect_url") or payload.get("redirect_uri") or "").strip()
    if redirect and (redirect.startswith("http://") or redirect.startswith("https://")):
        parsed = urllib.parse.urlparse(redirect)
        qs = urllib.parse.parse_qs(parsed.query)
        code = code or str((qs.get("code") or [""])[0])
        state = state or str((qs.get("state") or [""])[0])
    if not code:
        raise ValueError("paste the authorization code or final redirect URL")
    if not state:
        raise ValueError("OAuth state is required")
    return code, state


def _oauth_exchange(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    code, state = _extract_oauth_code(payload)
    with _control_db() as conn:
        pending_row = conn.execute("SELECT * FROM oauth_pending WHERE state=?", (state,)).fetchone()
    if not pending_row:
        raise ValueError("OAuth state was not found or has expired")
    pending = {"account_alias": pending_row["account_alias"], "token_label": pending_row["token_label"], "redirect_uri": pending_row["redirect_uri"], "scopes": json.loads(pending_row["scopes_json"] or "[]")}
    client = json.loads(pending_row["client_json"] or "{}")
    body = urllib.parse.urlencode({"code": code, "client_id": client["client_id"], "client_secret": client["client_secret"], "redirect_uri": pending["redirect_uri"], "grant_type": "authorization_code"}).encode("utf-8")
    req = urllib.request.Request(client.get("token_uri") or GOOGLE_OAUTH_TOKEN_ENDPOINT, data=body, headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            token_response = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise ValueError("Google rejected the authorization code; re-authorize and paste the newest redirect URL") from exc
    refresh_token = str(token_response.get("refresh_token") or "").strip()
    if not refresh_token:
        raise ValueError("Google did not return a refresh token; start again and approve with offline access")
    scopes = _oauth_services_to_scopes(token_response.get("scope") or pending.get("scopes"))
    token_payload = {"type": "authorized_user", "client_id": client["client_id"], "client_secret": client["client_secret"], "refresh_token": refresh_token, "scopes": scopes}
    email = _discover_oauth_email(token_response)
    token_label = str(pending.get("token_label") or "").strip()
    reauthorize_token_id = str(client.pop("__reauthorize_token_id", "") or "").strip()
    existing = _get_workspace_token(reauthorize_token_id) if reauthorize_token_id else None
    if existing:
        account_alias = str(existing.get("account_alias") or pending["account_alias"] or "").strip()
        bundle = str(existing.get("bundle") or "workspace-full.json").strip() or "workspace-full.json"
        old_meta = dict(existing.get("metadata") or {})
        token_label = token_label or str(old_meta.get("token_label") or existing.get("email") or account_alias)
        meta = dict(old_meta)
        meta.update({"email": email or existing.get("email") or old_meta.get("email") or "", "account_alias": account_alias, "token_label": token_label, "scopes": scopes, "status": "connected", "reauthorized_at": datetime.now(timezone.utc).isoformat(), "token_file": bundle, "token_store": "sqlite"})
        _store_workspace_token(account_alias, bundle, token_payload, meta)
    else:
        account_alias = pending["account_alias"] or _unique_account_alias(_oauth_account_alias(email, token_label))
        bundle = "workspace-full.json"
        meta = {"email": email, "account_alias": account_alias, "token_label": token_label, "scopes": scopes, "status": "connected", "connected_at": datetime.now(timezone.utc).isoformat(), "token_file": bundle, "token_store": "sqlite"}
        _store_workspace_token(account_alias, bundle, token_payload, meta)
    mapped_profiles = _profiles_for_account_alias(account_alias)
    acl_sync = _ensure_workspace_acl_resources(account_alias, mapped_profiles, scopes, email, actor) if mapped_profiles else {"status": "skipped", "profiles": [], "resources": [], "rules": 0}
    with _control_db() as conn:
        conn.execute("UPDATE workspace_access_requests SET status=?, email=?, account_alias=?, updated_at=CURRENT_TIMESTAMP WHERE state=?", ("connected", meta["email"], account_alias, state))
        conn.execute("DELETE FROM oauth_pending WHERE state=?", (state,))
        conn.commit()
    event_name = "google_oauth_token_reauthorized" if reauthorize_token_id else "google_oauth_token_connected"
    _append_change_event({"event": event_name, "actor": actor, "account_alias": account_alias, "token_id": reauthorize_token_id or _token_id(account_alias, bundle), "scopes": scopes, "state_hash": hashlib.sha256(state.encode()).hexdigest()[:16], "profiles": mapped_profiles, "acl_sync": acl_sync})
    if reauthorize_token_id:
        message = "Workspace scopes updated in place; existing profile routes and ACL rows were synced to the granted scope set."
    else:
        message = "Account connected; no ACL rows were created yet. Map profiles to this token from Google Workspace settings when ready." if not mapped_profiles else "Account connected; existing profile routes were synced to the granted scope set."
    return {"status": "connected", "account_alias": account_alias, "email": meta["email"], "profiles": mapped_profiles, "scopes": scopes, "token_status": "refresh_token_saved", "reauthorized": bool(reauthorize_token_id), "token_id": reauthorize_token_id or _token_id(account_alias, bundle), "acl_created": bool(mapped_profiles), "acl_sync": acl_sync, "message": message}


def _refresh_google_token_payload(data: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    scopes = data.get("scopes") or data.get("scope") or []
    try:
        from google.auth.transport.requests import Request
        from google.oauth2.credentials import Credentials
        creds = Credentials.from_authorized_user_info(data, scopes)
        if not creds.refresh_token:
            raise ValueError("token has no refresh token")
        creds.refresh(Request())
        updated = json.loads(creds.to_json())
        updated.setdefault("type", "authorized_user")
        if "client_secret" not in updated and data.get("client_secret"):
            updated["client_secret"] = data["client_secret"]
        if scopes and not updated.get("scopes"):
            updated["scopes"] = scopes
        return ("valid" if creds.valid else "refreshed"), updated
    except Exception:
        pass
    if not data.get("refresh_token"):
        raise ValueError("token has no refresh token")
    if not data.get("client_id") or not data.get("client_secret"):
        raise ValueError("token is missing client_id/client_secret needed to refresh without google-auth")
    body = urllib.parse.urlencode({
        "client_id": str(data["client_id"]),
        "client_secret": str(data["client_secret"]),
        "refresh_token": str(data["refresh_token"]),
        "grant_type": "refresh_token",
    }).encode("utf-8")
    req = urllib.request.Request(
        str(data.get("token_uri") or GOOGLE_OAUTH_TOKEN_ENDPOINT),
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            refreshed = json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:400]
        raise RuntimeError(f"Google token refresh failed: {detail}") from exc
    updated = dict(data)
    if refreshed.get("access_token"):
        updated["access_token"] = refreshed["access_token"]
    if refreshed.get("expires_in"):
        updated["expiry"] = (datetime.now(timezone.utc) + timedelta(seconds=int(refreshed.get("expires_in") or 0))).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    if refreshed.get("scope"):
        updated["scopes"] = [x for x in str(refreshed["scope"]).split() if x]
    elif scopes and not updated.get("scopes"):
        updated["scopes"] = scopes
    updated.setdefault("type", "authorized_user")
    return "refreshed", updated


def _refresh_google_token_file(path: Path) -> str:
    data = json.loads(path.read_text(encoding="utf-8"))
    status, updated = _refresh_google_token_payload(data)
    _write_secret_json(path, updated)
    return status


def _refresh_workspace_token(token_id: str) -> tuple[str, dict[str, Any]]:
    stored = _get_workspace_token(token_id)
    if stored:
        status, updated = _refresh_google_token_payload(stored["token_json"])
        metadata = dict(stored.get("metadata") or {})
        metadata["refreshed_at"] = datetime.now(timezone.utc).isoformat()
        _store_workspace_token(stored["account_alias"], stored["bundle"], updated, metadata)
        return status, stored
    path = _safe_token_path(str(GOOGLE_WORKSPACE_TOKEN_ROOT / token_id))
    status = _refresh_google_token_file(path)
    return status, {"id": token_id, "account_alias": Path(token_id).parts[0] if Path(token_id).parts else "", "store": "filesystem"}


def _workspace_access_refresh(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    token_id = str(payload.get("token_id") or "").strip()
    status, stored = _refresh_workspace_token(token_id)
    _append_change_event({"event": "google_oauth_token_refreshed", "actor": actor, "token_label": _token_label_from_relative(token_id), "token_store": stored.get("store")})
    return {"status": "refreshed", "token_status": status, "token_store": stored.get("store")}


def _workspace_access_test(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    token_id = str(payload.get("token_id") or "").strip()
    status, stored = _refresh_workspace_token(token_id)
    return {"status": "ok", "token_status": status, "token_store": stored.get("store"), "message": "Google token refresh succeeded."}


def _safe_token_path(path_s: str) -> Path:
    path = Path(path_s).expanduser().resolve()
    root = GOOGLE_WORKSPACE_TOKEN_ROOT.expanduser().resolve()
    if root not in path.parents and path != root:
        raise PermissionError("token path is outside managed Google governance token root")
    return path


def _token_label_from_relative(rel: str, email: str | None = None) -> str:
    parts = [part for part in rel.replace("\\", "/").split("/") if part]
    if not parts:
        return "Unknown token"
    return _token_display_label(parts[0], email)


def _workspace_token_label(metadata: dict[str, Any], account_alias: str, email: str | None = None) -> str:
    return _token_display_label(account_alias, email or metadata.get("email"), metadata.get("token_label") or metadata.get("label"))


def _workspace_display_email(metadata: dict[str, Any], spec: dict[str, Any] | None = None, fallback: str = "") -> str:
    """Best-effort email display for OAuth rows created before email discovery existed."""
    spec = spec or {}
    for value in (
        fallback,
        metadata.get("email"),
        metadata.get("google_account_hint"),
        spec.get("email"),
        spec.get("google_account_hint"),
    ):
        candidate = str(value or "").strip()
        if "@" in candidate:
            return candidate
    alias = _alias_key(metadata.get("account_alias") or spec.get("account_alias") or spec.get("alias") or "")
    if alias in _account_alias_keys("business_workspace"):
        return "business.karthikvenkat@gmail.com"
    if alias in _account_alias_keys("personal_workspace"):
        return "karthiktanya2021@gmail.com"
    return ""


def _dedupe_workspace_tokens() -> int:
    """Revoke older/use-case-specific token rows so the UI shows one token per account."""
    now = datetime.now(timezone.utc).isoformat()
    changed = 0
    with _control_db() as conn:
        rows = conn.execute("SELECT id,account_alias,bundle,status,updated_at FROM workspace_tokens WHERE revoked_at='' ORDER BY account_alias,bundle,updated_at DESC").fetchall()
        grouped: dict[str, list[Any]] = {}
        for row in rows:
            grouped.setdefault(_alias_key(row["account_alias"]), []).append(row)
        for _key, group in grouped.items():
            if len(group) <= 1:
                continue
            def score(row: Any) -> tuple[int, str]:
                bundle = str(row["bundle"] or "")
                workspace = 1 if Path(bundle).name == "workspace-full.json" else 0
                return (workspace, str(row["updated_at"] or ""))
            keep = max(group, key=score)
            for row in group:
                if row["id"] == keep["id"]:
                    continue
                conn.execute("UPDATE workspace_tokens SET status='revoked_duplicate', revoked_at=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (now, row["id"]))
                changed += 1
        if changed:
            conn.commit()
    return changed



def _token_inventory_items(include_files: bool = True) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = _db_token_inventory_items()
    db_aliases = {key for item in items for key in _account_alias_keys(item.get("account_alias"))}
    seen_ids = {str(item.get("id")) for item in items}
    if include_files:
        # Be tolerant of a parent token root being supplied; inventory only account-scoped children.
        if GOOGLE_WORKSPACE_TOKEN_ROOT.name != "accounts" and (GOOGLE_WORKSPACE_TOKEN_ROOT / "accounts").exists():
            roots: list[Path] = [GOOGLE_WORKSPACE_TOKEN_ROOT / "accounts"]
        else:
            roots = [GOOGLE_WORKSPACE_TOKEN_ROOT]
        for root in roots:
            try:
                token_iter = sorted(root.rglob("*.json")) if root.exists() else []
            except PermissionError:
                continue
            for token in token_iter:
                if token.name == "account.json" or ".revoked" in token.name or token.name.endswith(".revoked.json"):
                    continue
                rel = str(token.relative_to(root))
                account_alias = rel.split("/", 1)[0]
                if rel in seen_ids or any(key in db_aliases for key in _account_alias_keys(account_alias)):
                    continue
                spec: dict[str, Any] = {}
                meta: dict[str, Any] = {}
                try:
                    spec = json.loads(token.read_text(encoding="utf-8"))
                except Exception:
                    spec = {}
                try:
                    meta = json.loads((token.parent / "account.json").read_text(encoding="utf-8"))
                except Exception:
                    meta = {}
                raw_scopes = spec.get("scopes") or spec.get("scope") or meta.get("scopes") or []
                if isinstance(raw_scopes, str):
                    scopes = [x for x in raw_scopes.split() if x]
                else:
                    scopes = [str(x) for x in raw_scopes if x]
                has_refresh = bool(spec.get("refresh_token"))
                email = _workspace_display_email(meta, spec)
                token_label = meta.get("token_label") or meta.get("label")
                display_label = _workspace_token_label(meta, account_alias, email)
                items.append({
                    "id": rel,
                    "label": display_label,
                    "account_alias": account_alias,
                    "account_display": _account_display_label(account_alias, email, token_label),
                    "alias_keys": sorted(_account_alias_keys(account_alias)),
                    "bundle": Path(rel).stem,
                    "email": email,
                    "token_status": "connected" if has_refresh else "missing refresh token",
                    "has_refresh_token": has_refresh,
                    "scopes": scopes,
                    "updated_at": datetime.fromtimestamp(token.stat().st_mtime, timezone.utc).isoformat(),
                    "store": "filesystem",
                })
    grouped: dict[str, list[dict[str, Any]]] = {}
    for item in items:
        keys = _account_alias_keys(item.get("account_alias"))
        group_key = sorted(keys)[0] if keys else _alias_key(item.get("account_alias"))
        grouped.setdefault(group_key, []).append(item)
    visible: list[dict[str, Any]] = []
    for group in grouped.values():
        def score(item: dict[str, Any]) -> tuple[int, int, int, str]:
            return (1 if item.get("store") == "sqlite" else 0, 1 if str(item.get("bundle")) == "workspace-full" else 0, 1 if item.get("has_refresh_token") else 0, str(item.get("updated_at") or ""))
        visible.append(max(group, key=score))
    return sorted(visible, key=lambda item: str(item.get("account_display") or item.get("account_alias") or ""))



def _token_label_for_account(account_alias: str | None) -> str:
    alias = str(account_alias or "").strip()
    if not alias:
        return "No workspace token"
    items = [item for item in _token_inventory_items() if _account_alias_equivalent(item.get("account_alias"), alias)]
    if not items:
        return _token_display_label(alias)
    preferred = items[0]
    return str(preferred.get("label") or _token_display_label(alias, preferred.get("email")))


def _route_for_profile_account(policy: dict[str, Any], registry: dict[str, Any], profile: str, account_alias: str | None) -> str:
    alias = str(account_alias or "").strip()
    if not alias:
        return f"{_safe_alias(profile)}/unmapped"
    return _workspace_token_route(profile, alias)



def _workspace_route_inventory(policy: dict[str, Any] | None = None, registry: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    policy = policy or _load_yaml(POLICY_PATH)
    registry = registry or _load_yaml(REGISTRY_PATH)
    tokens = _token_inventory_items()
    token_by_account: dict[str, dict[str, Any]] = {}
    for item in tokens:
        for key in _account_alias_keys(item.get("account_alias")):
            token_by_account.setdefault(key, item)
    accounts: dict[str, Any] = {}
    for alias, spec in (registry.get("account_aliases") or {}).items():
        accounts.setdefault(str(alias), {}).update(spec or {})
    for alias, spec in (policy.get("accounts") or {}).items():
        accounts.setdefault(str(alias), {}).update(spec or {})
    known_profiles = set((policy.get("profile_policy") or {}).keys()) | set((policy.get("profiles") or {}).keys()) | set((registry.get("profiles") or {}).keys())
    rows: list[dict[str, Any]] = []
    seen_routes: set[tuple[str, str]] = set()
    for alias, spec in sorted(accounts.items()):
        routes = spec.get("current_profile_routes") or {}
        for raw_profile, route in sorted(routes.items()):
            profile = str(raw_profile)
            # Collapse legacy use-case route pseudo-profiles such as
            # reasoning_example_sheets into the canonical profile/account
            # route. If that canonical route already exists, skip the duplicate.
            if profile not in known_profiles and "_" in profile:
                maybe_profile = profile.split("_", 1)[0]
                if maybe_profile in known_profiles:
                    profile = maybe_profile
            key = (profile, alias)
            if key in seen_routes:
                continue
            seen_routes.add(key)
            token = next((token_by_account.get(key) for key in _account_alias_keys(alias) if token_by_account.get(key)), None) or {}
            normalized_route = _workspace_token_route(profile, alias)
            rows.append({
                "profile": profile,
                "account_alias": alias,
                "route": normalized_route,
                "token_route": normalized_route,
                "token_id": token.get("id") or f"{alias}/workspace-full.json",
                "email": token.get("email") or _workspace_display_email({}, spec),
                "token_label": token.get("label") or _token_label_for_account(alias),
                "account_display": token.get("label") or _token_display_label(alias, token.get("email") or spec.get("google_account_hint")),
                "services": _oauth_scopes_to_services(token.get("scopes") or []),
                "scopes": token.get("scopes") or [],
                "status": spec.get("status") or spec.get("verification_status") or "mapped",
            })
    return rows


def _workspace_access_inventory() -> dict[str, Any]:
    policy = _load_yaml(POLICY_PATH)
    registry = _load_yaml(REGISTRY_PATH)
    return {"status": "ok", "items": _token_inventory_items(), "routes": _workspace_route_inventory(policy, registry)}


def _workspace_access_map_profiles(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    inventory = _token_inventory_items()
    raw_token_ids = payload.get("token_ids")
    if isinstance(raw_token_ids, list):
        token_ids = [str(x).strip() for x in raw_token_ids if str(x).strip()]
    else:
        one = str(payload.get("token_id") or "").strip()
        token_ids = [one] if one else []
    raw_account_alias = str(payload.get("account_alias") or "").strip()
    explicit_account_alias = _safe_alias(raw_account_alias) if raw_account_alias else ""
    if not token_ids and explicit_account_alias:
        token_ids = [""]
    if not token_ids:
        raise ValueError("choose at least one connected Google account token to map")
    known_profiles = set((_load_yaml(POLICY_PATH).get("profile_policy", {}) or {}).keys())
    profiles = _profile_list(payload, known_profiles=known_profiles)
    if not profiles:
        raise ValueError("select at least one profile to map to this token")
    mapped: list[dict[str, Any]] = []
    combined_routes: dict[str, str] = {}
    for token_id in token_ids:
        account_alias = explicit_account_alias
        token_item = next((item for item in inventory if str(item.get("id")) == token_id), None) if token_id else None
        if token_item and not explicit_account_alias:
            promoted = _promote_generic_workspace_token_alias(token_id)
            if promoted:
                token_id = str(promoted.get("id") or token_id)
                inventory = _token_inventory_items()
                token_item = next((item for item in inventory if str(item.get("id")) == token_id), token_item)
        if token_item:
            account_alias = _safe_alias(str(token_item.get("account_alias") or account_alias))
        if not account_alias:
            raise ValueError("choose a connected Google account token to map")
        raw_scopes = payload.get("scopes") or payload.get("services") or ((token_item or {}).get("scopes") or [])
        scopes = _oauth_services_to_scopes(raw_scopes)
        email = str(payload.get("email") or (token_item or {}).get("email") or "").strip()
        result = _ensure_workspace_acl_resources(account_alias, profiles, scopes, email, actor)
        routes = {profile: _workspace_token_route(profile, account_alias) for profile in profiles}
        combined_routes.update({f"{profile}/{account_alias}": route for profile, route in routes.items()})
        mapped.append({"account_alias": account_alias, "token_id": token_id, "profiles": profiles, "routes": routes, "scopes": scopes, "acl_sync": result})
        _append_change_event({"event": "workspace_profiles_mapped_to_token", "actor": actor, "account_alias": account_alias, "profiles": profiles, "routes": routes, "token_id": token_id, "resources": result.get("resources", []), "rules_written": result.get("rules_written", 0)})
    first = mapped[0]
    return {"status": "mapped", "account_alias": first["account_alias"], "profiles": profiles, "routes": combined_routes if len(mapped) > 1 else first["routes"], "token_id": first["token_id"], "token_ids": token_ids, "mapped": mapped, "scopes": first["scopes"], "acl_sync": first["acl_sync"]}


def _remove_workspace_routes_for_account(account_alias: str, profiles: list[str] | None = None, actor: str = "admin") -> dict[str, Any]:
    account_alias = _safe_alias(account_alias)
    policy = _load_yaml(POLICY_PATH)
    registry = _load_yaml(REGISTRY_PATH)
    known_profiles = set((policy.get("profile_policy", {}) or {}).keys()) | set((policy.get("profiles", {}) or {}).keys()) | set((registry.get("profiles", {}) or {}).keys())
    target_profiles = set(profiles or [])
    if not target_profiles:
        for doc in (policy, registry):
            account_specs = doc.get("accounts") or doc.get("account_aliases") or {}
            for spec_alias, account_spec in account_specs.items():
                if not _account_alias_equivalent(spec_alias, account_alias):
                    continue
                routes = ((account_spec or {}).get("current_profile_routes") or {})
                target_profiles.update(str(profile) for profile in routes.keys())
        for profile, meta in (policy.get("profiles") or {}).items():
            if any(_account_alias_equivalent(x, account_alias) for x in list((meta or {}).get("connected_account_aliases") or [])):
                target_profiles.add(str(profile))
        for profile, spec in (policy.get("profile_policy") or {}).items():
            aliases = list((spec or {}).get("account_aliases") or [])
            if _account_alias_equivalent((spec or {}).get("account_alias"), account_alias) or any(_account_alias_equivalent(x, account_alias) for x in aliases):
                target_profiles.add(str(profile))
    target_profiles = {p for p in target_profiles if p in known_profiles or p in (policy.get("profile_policy") or {})}
    changed = False
    resources_for_account = [alias for alias, spec in (registry.get("resources") or {}).items() if _account_alias_equivalent((spec or {}).get("account_alias"), account_alias)]
    for doc in (policy, registry):
        account_specs = doc.get("accounts") or doc.get("account_aliases") or {}
        for spec_alias, account_spec in account_specs.items():
            if not _account_alias_equivalent(spec_alias, account_alias):
                continue
            routes = ((account_spec or {}).get("current_profile_routes") or {})
            for profile in sorted(target_profiles):
                if profile in routes:
                    routes.pop(profile, None)
                    changed = True
    for profile in sorted(target_profiles):
        profile_meta = (policy.get("profiles") or {}).setdefault(profile, {})
        connected = list(profile_meta.get("connected_account_aliases") or [])
        new_connected = [x for x in connected if not _account_alias_equivalent(x, account_alias)]
        if new_connected != connected:
            profile_meta["connected_account_aliases"] = new_connected
            changed = True
        reg_profile = (registry.get("profiles") or {}).setdefault(profile, {})
        scope = list(reg_profile.get("default_resource_scope") or [])
        new_scope = [x for x in scope if x not in resources_for_account]
        if new_scope != scope:
            reg_profile["default_resource_scope"] = new_scope
            changed = True
        policy_spec = (policy.get("profile_policy") or {}).setdefault(profile, {"defaults": {}, "resource_overrides": {}})
        old_aliases = list(policy_spec.get("account_aliases") or [])
        profile_aliases = [x for x in old_aliases if not _account_alias_equivalent(x, account_alias)]
        if profile_aliases != old_aliases:
            policy_spec["account_aliases"] = profile_aliases
            changed = True
        if _account_alias_equivalent(policy_spec.get("account_alias"), account_alias):
            if profile_aliases:
                policy_spec["account_alias"] = profile_aliases[0]
            else:
                policy_spec.pop("account_alias", None)
            changed = True
        overrides = policy_spec.setdefault("resource_overrides", {})
        for alias in resources_for_account:
            if alias in overrides:
                overrides.pop(alias, None)
                changed = True
        if not profile_aliases and not any(not _account_alias_equivalent(x, account_alias) for x in new_connected):
            defaults = policy_spec.setdefault("defaults", {})
            for action in list(defaults.keys()):
                if action in GOOGLE_WORKSPACE_ACTIONS:
                    defaults.pop(action, None)
                    changed = True
            if policy_spec.get("resource_overrides"):
                policy_spec["resource_overrides"] = {}
                changed = True
    for alias in resources_for_account:
        spec = (registry.get("resources") or {}).get(alias) or {}
        scope = list(spec.get("profile_scope") or [])
        new_scope = [x for x in scope if x not in target_profiles]
        if new_scope != scope:
            spec["profile_scope"] = new_scope
            changed = True
    if changed:
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        shutil.copy2(REGISTRY_PATH, REGISTRY_PATH.with_suffix(REGISTRY_PATH.suffix + f".{stamp}.bak"))
        shutil.copy2(POLICY_PATH, POLICY_PATH.with_suffix(POLICY_PATH.suffix + f".{stamp}.bak"))
        summary = f"Workspace ACL YAML synced for account {account_alias} and profiles {', '.join(profiles or [])}"
        _write_yaml_document(REGISTRY_PATH, registry, summary=summary)
        _write_yaml_document(POLICY_PATH, policy, summary=summary)
        _record_yaml_sync_event(actor, "ok", "workspace_acl_yaml_written", {"account_alias": account_alias, "profiles": profiles})
        runtime_policy = _generate_policy_json(policy)
        runtime_install = _stage_and_install_runtime_policy(runtime_policy)
        restart = _systemctl_restart_gateway()
    else:
        runtime_install = None
        restart = {"service": GATEWAY_SERVICE, "skipped": "no profile-token route relationship changed"}
    return {"changed": changed, "account_alias": account_alias, "profiles": sorted(target_profiles), "resources": resources_for_account, "runtime_install": runtime_install, "restart": restart}


def _workspace_access_unmap_profiles(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    token_id = str(payload.get("token_id") or "").strip()
    raw_account_alias = str(payload.get("account_alias") or "").strip()
    account_alias = _safe_alias(raw_account_alias) if raw_account_alias else ""
    token_item = next((item for item in _token_inventory_items() if str(item.get("id")) == token_id), None) if token_id else None
    if token_item:
        account_alias = _safe_alias(str(token_item.get("account_alias") or account_alias))
    if not account_alias:
        raise ValueError("choose a workspace route relationship to revoke")
    policy = _load_yaml(POLICY_PATH)
    known_profiles = set((policy.get("profile_policy", {}) or {}).keys())
    profiles = _profile_list(payload, known_profiles=known_profiles)
    if not profiles:
        raise ValueError("select at least one profile route to revoke")
    removed = _remove_workspace_routes_for_account(account_alias, profiles, actor=actor)
    event = {"event": "workspace_profiles_unmapped_from_token", "actor": actor, "account_alias": account_alias, "profiles": profiles, "resources": removed.get("resources", []), "changed": removed.get("changed", False)}
    _append_change_event(event)
    return {"status": "unmapped", **event, "restart": removed.get("restart")}


def _workspace_access_import_files(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    imported: list[str] = []
    skipped: list[str] = []
    for item in _token_inventory_items():
        if item.get("store") == "sqlite":
            skipped.append(str(item.get("id")))
            continue
        token_id = str(item.get("id") or "")
        if not token_id:
            continue
        try:
            path = _safe_token_path(str(GOOGLE_WORKSPACE_TOKEN_ROOT / token_id))
            token_payload = json.loads(path.read_text(encoding="utf-8"))
            meta_path = path.parent / "account.json"
            try:
                metadata = json.loads(meta_path.read_text(encoding="utf-8"))
            except Exception:
                metadata = {}
            metadata.setdefault("email", item.get("email") or "")
            metadata.setdefault("account_alias", item.get("account_alias") or token_id.split("/", 1)[0])
            metadata.setdefault("token_file", path.name)
            metadata["token_store"] = "sqlite"
            metadata["imported_from_file"] = str(path)
            _store_workspace_token(str(metadata["account_alias"]), path.name, token_payload, metadata)
            imported.append(token_id)
            if bool(payload.get("archive_files")):
                stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                path.rename(path.with_name(path.stem + f".imported-{stamp}" + path.suffix))
        except Exception as exc:
            skipped.append(f"{token_id}: {exc}")
    event = {"event": "workspace_tokens_imported_to_sqlite", "actor": actor, "imported": imported, "skipped": skipped, "archive_files": bool(payload.get("archive_files"))}
    _append_change_event(event)
    return {"status": "imported", "count": len(imported), **event}

def _workspace_access_create_request(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    # Compatibility endpoint for older UI builds; the new GUI uses /api/workspace/oauth/start.
    return _oauth_start(payload, actor)


def _workspace_access_revoke(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    token_id = str(payload.get("token_id") or "").strip()
    token_item = next((item for item in _token_inventory_items() if str(item.get("id")) == token_id), None) if token_id else None
    stored = _get_workspace_token(token_id) if token_id else None
    raw_alias = str((stored or token_item or {}).get("account_alias") or (token_id.split("/", 1)[0] if token_id else "") or payload.get("account_alias") or "").strip()
    account_alias = _safe_alias(raw_alias) if raw_alias else ""
    if stored:
        route_cleanup = _remove_workspace_routes_for_account(account_alias, actor=actor) if account_alias else {"changed": False, "profiles": [], "resources": [], "restart": {"skipped": "no account alias"}}
        with _control_db() as conn:
            conn.execute("UPDATE workspace_tokens SET status='revoked', revoked_at=?, updated_at=CURRENT_TIMESTAMP WHERE id=?", (datetime.now(timezone.utc).isoformat(), token_id))
            conn.commit()
        event = {"event": "workspace_access_revoked", "actor": actor, "account_alias": account_alias, "profiles_unmapped": route_cleanup.get("profiles", []), "routes_removed": route_cleanup.get("changed", False), "token_label": _token_label_from_relative(token_id), "token_store": "sqlite"}
        _append_change_event(event)
        return {"status": "revoked", **event, "route_cleanup": route_cleanup}
    path = _safe_token_path(str(GOOGLE_WORKSPACE_TOKEN_ROOT / token_id) if token_id else str(payload.get("path") or ""))
    if not path.exists():
        raise ValueError("token not found")
    rel = str(path.relative_to(GOOGLE_WORKSPACE_TOKEN_ROOT))
    if not account_alias:
        account_alias = _safe_alias(rel.split("/", 1)[0]) if "/" in rel else ""
    route_cleanup = _remove_workspace_routes_for_account(account_alias, actor=actor) if account_alias else {"changed": False, "profiles": [], "resources": [], "restart": {"skipped": "no account alias"}}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    revoked = path.with_name(path.stem + f".revoked-{stamp}" + path.suffix)
    path.rename(revoked)
    event = {"event": "workspace_access_revoked", "actor": actor, "account_alias": account_alias, "profiles_unmapped": route_cleanup.get("profiles", []), "routes_removed": route_cleanup.get("changed", False), "token_label": _token_label_from_relative(rel), "token_store": "filesystem"}
    _append_change_event(event)
    return {"status": "revoked", **event, "route_cleanup": route_cleanup}


def _read_json_body(handler: BaseHTTPRequestHandler) -> dict[str, Any]:
    length = int(handler.headers.get("Content-Length", "0"))
    if length <= 0:
        return {}
    return json.loads(handler.rfile.read(length).decode("utf-8") or "{}")


def _load_yaml(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _atomic_write_text(path: Path, content: str, mode: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    tmp.write_text(content, encoding="utf-8")
    if mode is not None:
        os.chmod(tmp, mode)
    # If this helper is imported by a root handoff script, temp-file replace
    # would otherwise make generated policy/YAML root-owned. Preserve the
    # existing target owner (or the parent directory owner for first writes) so
    # installs that intentionally run as root stay root-owned, while service-user
    # installs stay writable by the dedicated governance service user.
    try:
        owner_ref = path if path.exists() else path.parent
        st = owner_ref.stat()
        os.chown(tmp, st.st_uid, st.st_gid)
    except Exception:
        pass
    os.replace(tmp, path)
    if mode is not None:
        try:
            os.chmod(path, mode)
        except Exception:
            pass


def _yaml_header_metadata(path: Path) -> dict[str, str]:
    meta: dict[str, str] = {}
    if path.exists():
        try:
            for line in path.read_text(encoding="utf-8").splitlines()[:20]:
                m = re.match(r"^#\s*(date created|date last updated|last update summary):\s*(.*)$", line.strip(), re.I)
                if m:
                    meta[m.group(1).lower()] = m.group(2).strip()
        except Exception:
            pass
    if not meta.get("date created"):
        meta["date created"] = _iso_mtime(path) if path.exists() else datetime.now(timezone.utc).isoformat()
    return meta


def _yaml_metadata_header(path: Path, summary: str) -> str:
    now = datetime.now(timezone.utc).isoformat()
    meta = _yaml_header_metadata(path)
    safe_summary = re.sub(r"\s+", " ", str(summary or "updated from Control UI")).strip()
    return (
        "# GENERATED FILE — DO NOT EDIT\n"
        "# Source of truth: Google Governance Control UI/API\n"
        "# Manual changes are import/recovery material and will be overwritten by the next UI save or Regenerate YAML action.\n"
        f"# Date created: {meta['date created']}\n"
        f"# Date last updated: {now}\n"
        f"# Last update summary: {safe_summary}\n"
        "\n"
    )


def _write_yaml_document(path: Path, doc: dict[str, Any], *, summary: str, mode: int = 0o644) -> None:
    body = yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
    _atomic_write_text(path, _yaml_metadata_header(path, summary) + body, mode)


def _write_generated_policy_json(runtime_policy: dict[str, Any]) -> str:
    content = json.dumps(runtime_policy, indent=2, sort_keys=True) + "\n"
    _atomic_write_text(GENERATED_POLICY_PATH, content, 0o644)
    return content


def _privileged_apply_runtime_policy() -> dict[str, Any]:
    """Ask the root-installed helper to install the staged runtime policy.

    Normal UI edits run as the service user.  If the runtime snapshot path is
    intentionally protected, the initial installer grants that user exactly one
    sudoers command: install the already-generated policy snapshot to the live
    classifier path and repair ownership/mode.  No shell access or arbitrary path
    write is exposed to the browser.
    """
    if not PRIVILEGED_APPLY_CMD:
        raise PermissionError(f"cannot write {RUNTIME_POLICY_PATH} and no privileged apply helper is configured")
    cmd = shlex.split(PRIVILEGED_APPLY_CMD)
    result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if result.returncode != 0:
        detail = (result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}")[:1000]
        raise PermissionError(f"runtime policy helper failed: {detail}")
    try:
        helper = json.loads(result.stdout.strip() or "{}")
    except Exception:
        helper = {"stdout": result.stdout.strip()[:1000]}
    return {"mode": "privileged_helper", "command": cmd[0], "helper": helper}


def _install_runtime_policy_json(content: str) -> dict[str, Any]:
    try:
        _atomic_write_text(RUNTIME_POLICY_PATH, content, 0o640)
        return {"mode": "direct_write", "runtime_policy": str(RUNTIME_POLICY_PATH)}
    except PermissionError:
        return _privileged_apply_runtime_policy()


def _stage_and_install_runtime_policy(runtime_policy: dict[str, Any]) -> dict[str, Any]:
    content = _write_generated_policy_json(runtime_policy)
    return _install_runtime_policy_json(content)


def _operation_for_action(action: str) -> str:
    if "." not in action:
        return "unknown"
    op = action.split(".", 1)[1]
    if op in {"get", "list", "search", "download", "freebusy", "attachments.list", "attachments.get"}:
        return "read"
    if op in {"send", "share", "delete"}:
        return op
    if op in {"create", "update", "append", "batch_update", "copy", "upload", "modify", "draft"}:
        return "write"
    return op


def _service_for_action(action: str) -> str:
    return action.split(".", 1)[0] if "." in action else "unknown"


def _resource_title(resource_alias: str, resource: dict[str, Any]) -> str:
    return str(resource.get("display_name") or resource.get("title_hint") or resource_alias)


def _scope_label(source: str) -> str:
    if source == "profile_default":
        return "Default rule"
    if source == "resource_override":
        return "Specific resource"
    return source.replace("_", " ").title()


def _build_snapshot(policy: dict[str, Any], registry: dict[str, Any]) -> dict[str, Any]:
    """Build the UI/API ACL snapshot from the same YAML that feeds runtime policy.

    Parity rule: every effective profile/action decision from YAML must appear in
    the UI, including implicit catalog defaults, resource overrides, and global
    denies. The older implementation only emitted explicit profile defaults, so
    the UI could under-report denies that were still enforced by the gateway.
    """
    resources = registry.get("resources", {}) or {}
    profiles = policy.get("profile_policy", {}) or {}
    operation_risk = registry.get("operation_risk", {}) or {}
    catalog_meta = {str(item.get("action")): dict(item) for item in GOOGLE_WORKSPACE_TOOL_CATALOG}
    rows: list[dict[str, Any]] = []
    routed_accounts_by_profile: dict[str, set[str]] = {}
    for alias, account_spec in (policy.get("accounts") or {}).items():
        for routed_profile in (account_spec or {}).get("current_profile_routes") or {}:
            routed_accounts_by_profile.setdefault(str(routed_profile), set()).add(str(alias))

    def service_for_action(action: str) -> str:
        meta = catalog_meta.get(action) or {}
        return str(meta.get("service_slug") or _service_for_action(action))

    def actions_for_account(account_alias: str) -> set[str]:
        actions: set[str] = set()
        for resource in resources.values():
            if _account_alias_equivalent((resource or {}).get("account_alias"), account_alias):
                actions.update(str(a) for a in ((resource or {}).get("allowed_operations") or []) if str(a).strip())
        return {a for a in actions if a in GOOGLE_WORKSPACE_ACTIONS}

    def global_deny_ids(profile: str, action: str) -> list[str]:
        ids: list[str] = []
        for idx, rule in enumerate(policy.get("global_denies") or []):
            profiles = [str(x) for x in (rule.get("profiles") or [])]
            actions = [str(x) for x in (rule.get("actions") or [])]
            if action in actions and ("*" in profiles or profile in profiles):
                ids.append(str(rule.get("id") or f"global_deny_{idx + 1}"))
        return ids

    def add_row(*, profile: str, account_alias: str, token_route: str, action: str, decision: str, scope: str, resource_alias: str, source: str, notes: str, configured_decision: str | None = None) -> None:
        service = service_for_action(action)
        rows.append({
            "scope": scope,
            "profile": profile,
            "resource_alias": resource_alias or "__profile_default__",
            "resource_title": _resource_title(resource_alias, resources.get(resource_alias, {}) or {}) if resource_alias else _human_service(service),
            "resource_type": (resources.get(resource_alias, {}) or {}).get("type", "workspace_service") if resource_alias else "workspace_service",
            "account_alias": account_alias,
            "account_aliases": [account_alias] if account_alias else [],
            "token_route": token_route,
            "token_label": _token_label_for_account(account_alias) if account_alias else "Global policy",
            "action": action,
            "action_description": str((catalog_meta.get(action) or {}).get("description") or "Controls this Google Workspace action."),
            "tool": str((catalog_meta.get(action) or {}).get("tool") or ""),
            "service": service,
            "operation": _operation_for_action(action),
            "decision": decision,
            "configured_decision": configured_decision or decision,
            "risk": operation_risk.get(action, "unclassified"),
            "source": source,
            "source_label": _scope_label(source),
            "high_risk": action in HIGH_RISK_ACTIONS or decision == "deny",
            "notes": notes,
        })

    for profile, spec in sorted(profiles.items()):
        profile_meta = (policy.get("profiles") or {}).get(profile, {}) or {}
        connected_aliases = list(spec.get("account_aliases") or profile_meta.get("connected_account_aliases") or [])
        if not connected_aliases and spec.get("account_alias"):
            connected_aliases = [spec.get("account_alias")]
        routed_aliases = routed_accounts_by_profile.get(profile, set())
        if routed_accounts_by_profile:
            if routed_aliases:
                connected_aliases = [alias for alias in connected_aliases if any(_account_alias_equivalent(alias, routed) for routed in routed_aliases)] or sorted(routed_aliases)
            else:
                connected_aliases = []
        defaults = {str(k): str(v) for k, v in ((spec.get("defaults") or {}).items()) if str(k).strip()}
        resource_overrides = spec.get("resource_overrides") or {}

        # No route relationship means no current Google Workspace access surface,
        # but YAML-only denies/overrides must still be visible as stale policy.
        visible_aliases = connected_aliases or [""]
        for account_alias in visible_aliases:
            token_route = _route_for_profile_account(policy, registry, profile, account_alias) if account_alias else "unmapped"
            candidate_actions = set(defaults) | (actions_for_account(account_alias) if account_alias else set())
            for override in resource_overrides.values():
                candidate_actions.update(str(k) for k in (override or {}).keys())
            for rule in policy.get("global_denies") or []:
                rule_profiles = [str(x) for x in (rule.get("profiles") or [])]
                if "*" in rule_profiles or profile in rule_profiles:
                    candidate_actions.update(str(x) for x in (rule.get("actions") or []) if str(x).strip())
            candidate_actions = {a for a in candidate_actions if a in GOOGLE_WORKSPACE_ACTIONS}
            for action in sorted(candidate_actions):
                configured = defaults.get(action, _operation_default_decision(policy, action))
                deny_ids = global_deny_ids(profile, action)
                decision = "deny" if deny_ids else configured
                source = "global_deny" if deny_ids else ("profile_default" if action in defaults else "catalog_implicit_default")
                notes = "Global deny overrides the profile default." if deny_ids else ("Explicit YAML profile default." if action in defaults else "Catalog-derived implicit default; not explicitly present in YAML defaults.")
                add_row(profile=profile, account_alias=account_alias, token_route=token_route, action=action, decision=decision, configured_decision=configured, scope="default", resource_alias="", source=source, notes=notes)

        for resource_alias, override in sorted(resource_overrides.items()):
            resource = resources.get(resource_alias, {}) or {}
            account_alias = str(resource.get("account_alias") or (connected_aliases[0] if connected_aliases else ""))
            token_route = _route_for_profile_account(policy, registry, profile, account_alias) if account_alias else "unmapped"
            for action, configured in sorted((override or {}).items()):
                action = str(action)
                configured = str(configured)
                deny_ids = global_deny_ids(profile, action)
                decision = "deny" if deny_ids else configured
                add_row(profile=profile, account_alias=account_alias, token_route=token_route, action=action, decision=decision, configured_decision=configured, scope="override", resource_alias=str(resource_alias), source="global_deny" if deny_ids else "resource_override", notes="Resource-specific YAML override." + (" Global deny wins." if deny_ids else ""))

    resource_rows = []
    for alias, resource in sorted(resources.items()):
        resource_rows.append({
            "resource_alias": alias, "title": _resource_title(alias, resource), "type": resource.get("type", "unknown"),
            "account_alias": resource.get("account_alias", "unknown"), "sensitivity": resource.get("sensitivity", "unknown"),
            "profile_scope": resource.get("profile_scope", []), "allowed_operations": resource.get("allowed_operations", []),
            "verification_status": resource.get("verification_status", ""), "notes": resource.get("notes", ""),
        })
    decisions = {"allow": 0, "ask": 0, "deny": 0, "other": 0}
    for row in rows:
        decisions[row["decision"] if row["decision"] in decisions else "other"] += 1
    return {
        "schema_version": 3, "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": policy.get("mode"), "effective_behavior": policy.get("effective_behavior"),
        "unknown_profile_default": policy.get("unknown_profile_default"),
        "unknown_resource_default": policy.get("unknown_resource_default"),
        "summary": {"rule_count": len(rows), "resource_count": len(resource_rows), "profile_count": len(profiles), "decisions": decisions, "high_risk_rule_count": sum(1 for row in rows if row["high_risk"]), "catalog_action_count": len(GOOGLE_WORKSPACE_ACTIONS)},
        "rules": rows, "resources": resource_rows,
    }


def _generate_policy_json(policy: dict[str, Any]) -> dict[str, Any]:
    # Runtime classifier intentionally consumes this profile-first subset.
    keep = [
        "schema_version", "mode", "effective_behavior", "unknown_profile_default", "unknown_resource_default",
        "unknown_google_url_default", "workflow_intent_policy_role", "operation_classes", "profile_policy", "global_denies", "accounts", "profiles",
    ]
    return {key: policy.get(key) for key in keep if key in policy}


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _jwt_token() -> str:
    raise RuntimeError("filesystem JWT signing is disabled; use a gateway API access token")


def _gateway_post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not GATEWAY_ACCESS_TOKEN or not GATEWAY_ACCESS_TOKEN.strip():
        raise RuntimeError("Control service is missing its gateway access token. Configure a gateway API token on the control service, or use the local approval-store APIs for approvals.")
    payload = dict(payload)
    payload.setdefault("profile", PROFILE)
    payload.setdefault("workflow_intent", "control_plane")
    payload.setdefault("approval_admin_secret", APPROVAL_SECRET_PATH.read_text(encoding="utf-8").strip())
    req = urllib.request.Request(
        GATEWAY_URL + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {GATEWAY_ACCESS_TOKEN.strip()}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"gateway {path} HTTP {exc.code}: {body}") from exc


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


def _append_approval_event(event: dict[str, Any]) -> None:
    APPROVAL_STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    row = {"ts": datetime.now(timezone.utc).isoformat(), **event}
    with APPROVAL_STORE_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")


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
        current["history"].append({k: v for k, v in event.items() if k != "safe_metadata"})
        if event.get("event") == "requested":
            current.update(event)
            current.setdefault("state", "pending")
        elif event.get("event") == "decided":
            current["state"] = str(event.get("decision") or "deny")
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
        elif event.get("event") == "cleared":
            current["state"] = "cleared"
            current["cleared_by"] = event.get("actor")
            current["cleared_at"] = event.get("ts")
    for current in state.values():
        if _approval_is_expired(current):
            current["state"] = "expired"
            current["expired_at"] = current.get("expires_at")
    return state


def _approval_inventory(payload: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = payload or {}
    state_filter = str(payload.get("state") or "pending")
    approvals = []
    for item in sorted(_approval_state().values(), key=lambda row: str(row.get("ts") or ""), reverse=True):
        if state_filter != "all" and item.get("state") != state_filter:
            continue
        row = {k: v for k, v in item.items() if k != "history"}
        row["history"] = item.get("history", [])
        row.setdefault("requested_at", row.get("ts"))
        approvals.append(row)
    return {"status": "ok", "approvals": approvals, "source": "local_approval_store"}


def _approval_decide_ui(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    decision = str(payload.get("decision") or "").strip()
    if decision not in {"approve_once", "deny", "request_edit"}:
        raise ValueError("decision must be approve_once, deny, or request_edit")
    approval_id = str(payload.get("approval_id") or "").strip()
    if not approval_id:
        raise ValueError("approval_id is required")
    if decision == "approve_once" and bool(payload.get("execute_after_approval")):
        result = _gateway_post_with_temp_api_token("/v1/governance/approve-and-execute", {
            "approval_id": approval_id,
            "decision": "approve_once",
            "approver": actor,
            "reason": str(payload.get("reason") or "Approve & Execute from control UI"),
            "ttl_seconds": int(payload.get("ttl_seconds") or 900),
        }, actor)
        _append_change_event({"event": "approval_approved_and_executed_from_ui", "actor": actor, "approval_id": approval_id, "source": "gateway", "status": result.get("status")})
        return {**result, "source": "gateway"}
    current = _approval_state().get(approval_id)
    if not current:
        raise ValueError("unknown approval_id")
    if current.get("state") not in {"pending", "request_edit"}:
        raise ValueError(f"approval is not pending: {current.get('state')}")
    approved_until = None
    if decision == "approve_once":
        ttl = max(60, min(int(payload.get("ttl_seconds") or 900), 3600))
        approved_until = datetime.fromtimestamp(time.time() + ttl, timezone.utc).isoformat()
    _append_approval_event({"event": "decided", "approval_id": approval_id, "decision": decision, "approver": actor, "decision_reason": str(payload.get("reason") or ""), "approved_until": approved_until})
    _append_change_event({"event": "approval_decided_from_ui", "actor": actor, "approval_id": approval_id, "decision": decision, "source": "local_approval_store"})
    status = "approved" if decision == "approve_once" else decision
    return {"status": status, "approval_id": approval_id, "decision": decision, "approved_until": approved_until, "source": "local_approval_store"}


def _approval_bulk_decide_ui(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    decision = str(payload.get("decision") or "").strip()
    if decision not in {"approve_once", "deny"}:
        raise ValueError("decision must be approve_once or deny")
    ids = [str(x).strip() for x in (payload.get("approval_ids") or []) if str(x).strip()]
    state_filter = str(payload.get("state") or "pending")
    state = _approval_state()
    if not ids:
        ids = [approval_id for approval_id, item in state.items() if state_filter == "all" or item.get("state") == state_filter]
    changed = []
    for approval_id in ids:
        item = state.get(approval_id)
        if not item or item.get("state") not in {"pending", "request_edit"}:
            continue
        approved_until = None
        if decision == "approve_once":
            ttl = max(60, min(int(payload.get("ttl_seconds") or 900), 3600))
            approved_until = datetime.fromtimestamp(time.time() + ttl, timezone.utc).isoformat()
        _append_approval_event({"event": "decided", "approval_id": approval_id, "decision": decision, "approver": actor, "decision_reason": str(payload.get("reason") or "bulk UI action"), "approved_until": approved_until})
        changed.append(approval_id)
    _append_change_event({"event": "approval_bulk_decided_from_ui", "actor": actor, "decision": decision, "count": len(changed), "source": "local_approval_store"})
    return {"status": "ok", "decision": decision, "count": len(changed), "approval_ids": changed, "source": "local_approval_store"}


def _approval_clear_ui(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    state_filter = str(payload.get("state") or "pending")
    state = _approval_state()
    changed = []
    for approval_id, item in state.items():
        if state_filter != "all" and item.get("state") != state_filter:
            continue
        if item.get("state") in {"cleared", "consumed"}:
            continue
        _append_approval_event({"event": "cleared", "approval_id": approval_id, "actor": actor, "reason": str(payload.get("reason") or "cleared from control UI")})
        changed.append(approval_id)
    _append_change_event({"event": "approvals_cleared_from_ui", "actor": actor, "state_filter": state_filter, "count": len(changed), "source": "local_approval_store"})
    return {"status": "cleared", "count": len(changed), "approval_ids": changed, "source": "local_approval_store"}


def _approval_telegram_settings_payload() -> dict[str, Any]:
    defaults = {
        "public_base_url": os.getenv("GOOGLE_GOVERNANCE_APPROVAL_PUBLIC_BASE_URL", "").strip().rstrip("/"),
        "bot_token_configured": bool(os.getenv("GOOGLE_GOVERNANCE_TELEGRAM_BOT_TOKEN", "").strip()),
        "webhook_token_configured": bool(os.getenv("GOOGLE_GOVERNANCE_APPROVAL_WEBHOOK_TOKEN", "").strip()),
        "delivery_rules_enabled": True,
    }
    with _approval_db() as conn:
        rows = conn.execute("SELECT key,value FROM approval_telegram_settings").fetchall()
    values = {str(r["key"]): str(r["value"] or "") for r in rows}
    if values.get("public_base_url"):
        defaults["public_base_url"] = values["public_base_url"].rstrip("/")
    if values.get("bot_token"):
        defaults["bot_token_configured"] = True
    if values.get("webhook_token"):
        defaults["webhook_token_configured"] = True
    if values.get("delivery_rules_enabled"):
        defaults["delivery_rules_enabled"] = values["delivery_rules_enabled"].strip().lower() not in {"0", "false", "no", "off"}
    return defaults


def _approval_telegram_settings_save(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    public_base_url = str(payload.get("public_base_url") or "").strip().rstrip("/")
    bot_token = str(payload.get("bot_token") or "").strip()
    clear_bot_token = bool(payload.get("clear_bot_token"))
    webhook_token = str(payload.get("webhook_token") or "").strip()
    clear_webhook_token = bool(payload.get("clear_webhook_token"))
    if webhook_token and not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", webhook_token):
        raise ValueError("webhook_token must be 1-256 chars using letters, numbers, underscore, or hyphen")
    delivery_rules_enabled = bool(payload.get("delivery_rules_enabled", True))
    with _approval_db() as conn:
        conn.execute("INSERT INTO approval_telegram_settings(key,value,updated_by) VALUES('public_base_url',?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP,updated_by=excluded.updated_by", (public_base_url, actor))
        conn.execute("INSERT INTO approval_telegram_settings(key,value,updated_by) VALUES('delivery_rules_enabled',?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP,updated_by=excluded.updated_by", ("true" if delivery_rules_enabled else "false", actor))
        if clear_bot_token:
            conn.execute("DELETE FROM approval_telegram_settings WHERE key='bot_token'")
        elif bot_token:
            conn.execute("INSERT INTO approval_telegram_settings(key,value,updated_by) VALUES('bot_token',?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP,updated_by=excluded.updated_by", (bot_token, actor))
        if clear_webhook_token:
            conn.execute("DELETE FROM approval_telegram_settings WHERE key='webhook_token'")
        elif webhook_token:
            conn.execute("INSERT INTO approval_telegram_settings(key,value,updated_by) VALUES('webhook_token',?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP,updated_by=excluded.updated_by", (webhook_token, actor))
        conn.commit()
    saved_settings = _approval_telegram_settings_payload()
    _append_change_event({"event": "approval_telegram_settings_saved", "actor": actor, "public_base_url": public_base_url, "delivery_rules_enabled": delivery_rules_enabled, "bot_token_configured": bool(bot_token) or (not clear_bot_token and saved_settings.get("bot_token_configured")), "webhook_token_configured": bool(webhook_token) or (not clear_webhook_token and saved_settings.get("webhook_token_configured"))})
    return {"status": "ok", "settings": _approval_telegram_settings_payload()}


def _approval_channels_list() -> dict[str, Any]:
    with _approval_db() as conn:
        rows = conn.execute("SELECT id,label,chat_id,scope,profile,button_base_url,bot_token,enabled,created_at,updated_at FROM approval_telegram_channels ORDER BY enabled DESC, scope, profile, label").fetchall()
    channels = []
    for row in rows:
        item = dict(row)
        item["bot_token_configured"] = bool(str(item.pop("bot_token", "") or "").strip())
        channels.append(item)
    return {"status": "ok", "channels": channels, "settings": _approval_telegram_settings_payload()}


def _approval_channel_save(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    label = str(payload.get("label") or "").strip() or "Telegram approvals"
    chat_id = str(payload.get("chat_id") or "").strip()
    scope = str(payload.get("scope") or "all").strip()
    profile = str(payload.get("profile") or "*").strip()
    button_base_url = str(payload.get("button_base_url") or "").strip().rstrip("/")
    bot_token = str(payload.get("bot_token") or payload.get("channel_bot_token") or "").strip()
    clear_bot_token = bool(payload.get("clear_bot_token") or payload.get("clear_channel_bot_token"))
    enabled = 1 if bool(payload.get("enabled", True)) else 0
    row_id = int(payload.get("id") or 0)
    if not chat_id:
        raise ValueError("Telegram chat_id is required")
    if scope not in {"all", "profile"}:
        raise ValueError("scope must be all or profile")
    if scope == "all":
        profile = "*"
    elif not profile or profile == "*":
        raise ValueError("profile is required when scope is profile")
    with _approval_db() as conn:
        if row_id:
            if clear_bot_token:
                conn.execute("UPDATE approval_telegram_channels SET label=?,chat_id=?,scope=?,profile=?,button_base_url=?,bot_token='',enabled=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (label, chat_id, scope, profile, button_base_url, enabled, row_id))
            elif bot_token:
                conn.execute("UPDATE approval_telegram_channels SET label=?,chat_id=?,scope=?,profile=?,button_base_url=?,bot_token=?,enabled=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (label, chat_id, scope, profile, button_base_url, bot_token, enabled, row_id))
            else:
                conn.execute("UPDATE approval_telegram_channels SET label=?,chat_id=?,scope=?,profile=?,button_base_url=?,enabled=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", (label, chat_id, scope, profile, button_base_url, enabled, row_id))
        else:
            conn.execute("INSERT INTO approval_telegram_channels(label,chat_id,scope,profile,button_base_url,bot_token,enabled) VALUES(?,?,?,?,?,?,?) ON CONFLICT(chat_id,scope,profile) DO UPDATE SET label=excluded.label,button_base_url=excluded.button_base_url,bot_token=CASE WHEN excluded.bot_token!='' THEN excluded.bot_token ELSE approval_telegram_channels.bot_token END,enabled=excluded.enabled,updated_at=CURRENT_TIMESTAMP", (label, chat_id, scope, profile, button_base_url, bot_token, enabled))
        conn.commit()
    _append_change_event({"event": "approval_channel_saved", "actor": actor, "label": label, "chat_id_hash": hashlib.sha256(chat_id.encode()).hexdigest()[:16], "scope": scope, "profile": profile, "enabled": bool(enabled), "channel_bot_token_configured": bool(bot_token), "channel_bot_token_cleared": clear_bot_token})
    result = _approval_channels_list()
    return result


def _approval_channel_delete(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    row_id = int(payload.get("id") or 0)
    if not row_id:
        raise ValueError("id is required")
    with _approval_db() as conn:
        conn.execute("DELETE FROM approval_telegram_channels WHERE id=?", (row_id,))
        conn.commit()
    _append_change_event({"event": "approval_channel_deleted", "actor": actor, "id": row_id})
    return _approval_channels_list()


def _systemctl_restart_gateway() -> dict[str, Any]:
    if GOOGLE_GOVERNANCE_RELOAD_MODE in {"hot", "ui", "none", "no-shell"}:
        try:
            health = urllib.request.urlopen(GATEWAY_URL + "/healthz", timeout=15).read().decode("utf-8")
            parsed = json.loads(health or "{}")
        except Exception as exc:
            parsed = {"status": "unreachable", "error": str(exc)}
        return {"service": GATEWAY_SERVICE, "reload": "hot_policy_file", "shell_access_required": False, "health": parsed}
    result = subprocess.run(["systemctl", "restart", GATEWAY_SERVICE], text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
    if result.returncode != 0:
        raise RuntimeError(f"systemctl restart failed: {result.stderr.strip() or result.stdout.strip()}")
    health = urllib.request.urlopen(GATEWAY_URL + "/healthz", timeout=15).read().decode("utf-8")
    return {"service": GATEWAY_SERVICE, "reload": "systemctl_restart", "health": json.loads(health or "{}")}


def _append_change_event(event: dict[str, Any]) -> None:
    row = {"ts": datetime.now(timezone.utc).isoformat(), **event}
    try:
        CHANGE_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with CHANGE_LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    except Exception:
        pass
    try:
        with _control_db() as conn:
            conn.execute(
                "INSERT INTO change_events(ts,event,actor,payload_json) VALUES(?,?,?,?)",
                (str(row.get("ts") or ""), str(row.get("event") or "unknown"), str(row.get("actor") or ""), json.dumps(row, ensure_ascii=False, sort_keys=True)),
            )
            conn.commit()
    except Exception:
        return


def _sha256_file(path: Path) -> str:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _iso_mtime(path: Path) -> str:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
    except Exception:
        return ""


def _last_yaml_sync_event() -> dict[str, Any]:
    events = {
        "runtime_yaml_synced_from_ui",
        "policy_change_yaml_written",
        "bulk_policy_change_yaml_written",
        "workspace_acl_yaml_written",
        "yaml_compare_checked",
    }
    try:
        with _control_db() as conn:
            q = ",".join("?" for _ in events)
            row = conn.execute(
                f"SELECT ts,event,actor,payload_json FROM change_events WHERE event IN ({q}) ORDER BY ts DESC LIMIT 1",
                tuple(sorted(events)),
            ).fetchone()
            if row:
                item = dict(row)
                try:
                    item["payload"] = json.loads(item.get("payload_json") or "{}")
                except Exception:
                    item["payload"] = {}
                item.pop("payload_json", None)
                return item
    except Exception:
        pass
    return {}


def _record_yaml_sync_event(actor: str, status: str, source: str, detail: dict[str, Any] | None = None) -> None:
    _append_change_event({
        "event": source,
        "actor": actor,
        "status": status,
        "policy_yaml": str(POLICY_PATH),
        "registry_yaml": str(REGISTRY_PATH),
        "runtime_policy": str(RUNTIME_POLICY_PATH),
        "ui_authoritative": True,
        "warning": "UI/API is authoritative; direct YAML edits are import/recovery only and may be overwritten by the next UI save or regeneration.",
        **(detail or {}),
    })


def _yaml_sync_status(actor: str | None = None, *, audit: bool = False) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
    status = "ok"
    compare: dict[str, Any] = {}
    try:
        policy = _load_yaml(POLICY_PATH)
        registry = _load_yaml(REGISTRY_PATH)
        runtime_policy = _generate_policy_json(policy)
        expected = json.dumps(runtime_policy, indent=2, sort_keys=True) + "\n"
        expected_hash = hashlib.sha256(expected.encode("utf-8")).hexdigest()
        generated_hash = _sha256_file(GENERATED_POLICY_PATH)
        runtime_hash = _sha256_file(RUNTIME_POLICY_PATH)
        compare = {
            "policy_profiles": len(policy.get("profile_policy") or {}),
            "registry_resources": len(registry.get("resources") or {}),
            "expected_runtime_sha256": expected_hash,
            "generated_policy_sha256": generated_hash,
            "runtime_policy_sha256": runtime_hash,
            "generated_matches_yaml": bool(generated_hash and generated_hash == expected_hash),
            "runtime_matches_yaml": bool(runtime_hash and runtime_hash == expected_hash),
        }
        add("policy YAML parses", isinstance(policy, dict), f"{POLICY_PATH}; profiles={compare['policy_profiles']}")
        add("registry YAML parses", isinstance(registry, dict), f"{REGISTRY_PATH}; resources={compare['registry_resources']}")
        add("generated policy JSON matches YAML", compare["generated_matches_yaml"], f"generated={generated_hash[:12] if generated_hash else 'missing'} expected={expected_hash[:12]}")
        add("live runtime policy matches YAML", compare["runtime_matches_yaml"], f"runtime={runtime_hash[:12] if runtime_hash else 'missing'} expected={expected_hash[:12]}")
    except Exception as exc:
        status = "needs_attention"
        add("YAML compare", False, str(exc))
    if any(not c["ok"] for c in checks):
        status = "needs_attention"
    result = {
        "status": status,
        "ui_authoritative": True,
        "authority_note": "UI/API is authoritative. Direct YAML edits are import/recovery material and will be overwritten by the next UI save or Regenerate YAML action.",
        "last_event": _last_yaml_sync_event(),
        "paths": {
            "policy_yaml": str(POLICY_PATH),
            "registry_yaml": str(REGISTRY_PATH),
            "generated_policy_json": str(GENERATED_POLICY_PATH),
            "runtime_policy_json": str(RUNTIME_POLICY_PATH),
        },
        "mtimes": {
            "policy_yaml": _iso_mtime(POLICY_PATH),
            "registry_yaml": _iso_mtime(REGISTRY_PATH),
            "generated_policy_json": _iso_mtime(GENERATED_POLICY_PATH),
            "runtime_policy_json": _iso_mtime(RUNTIME_POLICY_PATH),
        },
        "compare": compare,
        "checks": checks,
    }
    if audit:
        _record_yaml_sync_event(actor or "admin", status, "yaml_compare_checked", {"compare": compare})
    return result


def _git_value(args: list[str]) -> str:
    try:
        result = subprocess.run(["git", "-C", str(BASE), *args], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
        return result.stdout.strip() if result.returncode == 0 else ""
    except Exception:
        return ""


def _runtime_version() -> dict[str, Any]:
    source = Path(__file__).resolve()
    installed = INSTALLED_CONTROL_SOURCE_PATH
    source_hash = _sha256_file(source)
    installed_hash = _sha256_file(installed)
    return {
        "source_path": str(source),
        "installed_path": str(installed),
        "source_sha256": source_hash,
        "installed_sha256": installed_hash,
        "source_matches_installed": bool(source_hash and installed_hash and source_hash == installed_hash),
        "git_commit": _git_value(["rev-parse", "--short", "HEAD"]),
        "git_dirty": bool(_git_value(["status", "--porcelain"])),
    }


def _runtime_backups() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        with _control_db() as conn:
            for row in conn.execute("SELECT id,ts,actor,archive_path,backup_dir,includes_token_store,status,note FROM runtime_backups ORDER BY ts DESC LIMIT 20").fetchall():
                item = dict(row)
                archive = Path(item.get("archive_path") or "")
                item["archive_exists"] = archive.exists()
                item["archive_size"] = archive.stat().st_size if archive.exists() else 0
                rows.append(item)
    except Exception:
        pass
    return rows


def _runtime_gateway_health() -> dict[str, Any]:
    try:
        body = urllib.request.urlopen(GATEWAY_URL + "/healthz", timeout=5).read().decode("utf-8")
        parsed = json.loads(body or "{}")
        parsed.setdefault("url", GATEWAY_URL + "/healthz")
        parsed.setdefault("service", GATEWAY_SERVICE)
        return parsed
    except Exception as exc:
        service_status = "unknown"
        try:
            result = subprocess.run(["systemctl", "is-active", GATEWAY_SERVICE], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5)
            service_status = result.stdout.strip() or "unknown"
        except Exception:
            pass
        hint = f"Gateway is not reachable at {GATEWAY_URL}/healthz. Check/restart {GATEWAY_SERVICE}."
        return {"status": "unreachable", "url": GATEWAY_URL + "/healthz", "service": GATEWAY_SERVICE, "service_status": service_status, "error": str(exc), "hint": hint}




def _mcp_tool_catalog() -> dict[str, Any]:
    """Return the governed Google MCP tools from the upstream catalog only.

    Fresh installs expose the google_workspace_mcp-style tool catalog. Do not
    surface older ad-hoc local wrappers in the UI.
    """
    tools: list[dict[str, Any]] = []
    testable_names = {"get_events", "query_freebusy", "search_gmail_messages", "search_drive_files"}
    for item in GOOGLE_WORKSPACE_TOOL_CATALOG:
        name = str(item["tool"])
        action = str(item["action"])
        high_risk = any(word in name for word in ("delete", "share", "send", "manage", "update", "modify", "create", "run"))
        tools.append({
            "name": name,
            "service": item["service_slug"],
            "action": action,
            "params": [{"name": "payload", "default": None}, {"name": "token_route", "default": None}],
            "description": item.get("description", ""),
            "tier": item.get("tier"),
            "high_risk": high_risk,
            "testable": name in testable_names,
            "catalog_source": "google_workspace_mcp",
        })
    routes = _workspace_access_inventory().get("routes", [])
    return {"status": "ok", "tools": sorted(tools, key=lambda x: x["name"]), "routes": routes, "gateway": GATEWAY_URL, "mcp_url": os.getenv("GOOGLE_GOVERNANCE_MCP_URL", "http://127.0.0.1:8769/mcp")}


def _gateway_post_with_temp_api_token(path: str, payload: dict[str, Any], actor: str) -> dict[str, Any]:
    token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    token_id = "control-ui-test-" + secrets.token_hex(6)
    payload = dict(payload)
    payload.setdefault("workflow_intent", "control-ui.mcp-test")
    payload.setdefault("request_id", token_id)
    try:
        with _control_db() as conn:
            conn.execute(
                "INSERT INTO api_tokens(id,label,token_hash,allowed_profiles_json,created_by) VALUES(?,?,?,?,?)",
                (token_id, "Temporary Control UI MCP test token", token_hash, json.dumps(["*"]), actor),
            )
            conn.commit()
        req = urllib.request.Request(
            GATEWAY_URL + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=180) as resp:
            return json.loads(resp.read().decode("utf-8") or "null")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"body": body}
        return {"status": "gateway_error", "http_status": exc.code, "error": parsed}
    finally:
        try:
            with _control_db() as conn:
                conn.execute("UPDATE api_tokens SET revoked_at=CURRENT_TIMESTAMP WHERE id=?", (token_id,))
                conn.commit()
        except Exception:
            pass


def _gateway_post_no_auth(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Proxy unauthenticated Telegram webhook callbacks from public Control UI to the private gateway.

    Telegram posts to the public governance URL configured in the UI. In common
    deployments that URL fronts the Control UI, not the private gateway port, so
    the Control UI forwards the exact callback payload/query to the gateway's
    unauthenticated webhook endpoint. The gateway still verifies the webhook
    token and callback HMAC before deciding/executing.
    """
    req = urllib.request.Request(
        GATEWAY_URL + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            return json.loads(resp.read().decode("utf-8") or "null")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", "replace")
        try:
            parsed = json.loads(body)
        except Exception:
            parsed = {"body": body}
        return {"status": "gateway_error", "http_status": exc.code, "error": parsed}


def _mcp_test_tool(payload: dict[str, Any], actor: str) -> dict[str, Any]:
    tool = str(payload.get("tool") or "").strip()
    profile = str(payload.get("profile") or PROFILE).strip()
    route = str(payload.get("route") or payload.get("token_route") or "").strip()
    args = payload.get("args") or {}
    if isinstance(args, str):
        args = json.loads(args or "{}")
    if not isinstance(args, dict):
        raise ValueError("args must be a JSON object")
    body = {"profile": profile, **args}
    if route:
        body["token_route"] = route
    if tool == "get_events":
        path = "/v1/tools/get_events"
        body.setdefault("calendar", "primary")
        body.setdefault("max_results", 10)
        if not body.get("start") or not body.get("end"):
            now = datetime.now(timezone.utc)
            body.setdefault("start", now.isoformat())
            body.setdefault("end", (now + timedelta(days=1)).isoformat())
    elif tool == "query_freebusy":
        path = "/v1/tools/query_freebusy"
        now = datetime.now(timezone.utc)
        body.setdefault("time_min", now.isoformat())
        body.setdefault("time_max", (now + timedelta(days=1)).isoformat())
        body.setdefault("calendar_ids", ["primary"])
    elif tool == "search_gmail_messages":
        path = "/v1/tools/search_gmail_messages"
        body.setdefault("query", "newer_than:7d")
        body.setdefault("max_results", 10)
    elif tool == "search_drive_files":
        path = "/v1/tools/search_drive_files"
        body.setdefault("query", "name contains ''")
        body.setdefault("page_size", 10)
    else:
        raise ValueError("This GUI tester currently supports get_events, query_freebusy, search_gmail_messages, and search_drive_files. Use an MCP client for write/destructive tools.")
    result = _gateway_post_with_temp_api_token(path, body, actor)
    _append_change_event({"event": "mcp_tool_tested", "actor": actor, "tool": tool, "profile": profile, "route": route, "status": result.get("status", "ok") if isinstance(result, dict) else "ok"})
    return {"status": "ok", "tool": tool, "profile": profile, "route": route, "request": _redact_payload(body), "result": result}


def _stale_root_config_files() -> list[dict[str, Any]]:
    """Return root-level config-looking files that should not be edited live.

    Live mutable governance state belongs under .google-governance/state and
    .google-governance/config. Files directly under BASE are install/source
    artifacts, except documented examples.
    """
    stale: list[dict[str, Any]] = []
    allowed_names = {"docker-compose.example.yml"}
    active_paths = {
        POLICY_PATH.resolve(), REGISTRY_PATH.resolve(), GENERATED_POLICY_PATH.resolve(),
        RUNTIME_POLICY_PATH.resolve(), CONTROL_USERS_DB_PATH.resolve(), GOOGLE_WORKSPACE_TOKEN_DB_PATH.resolve(),
    }
    for path in sorted(BASE.glob("*")):
        if path.name in allowed_names or not path.is_file():
            continue
        if path.suffix.lower() not in {".yaml", ".yml", ".json", ".sqlite", ".db"}:
            continue
        try:
            resolved = path.resolve()
            stat = path.stat()
            stale.append({
                "path": str(path),
                "name": path.name,
                "size": stat.st_size,
                "mtime": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
                "active": resolved in active_paths,
                "reason": "root-level config-looking file; live state is under .google-governance/ or database/",
            })
        except Exception as exc:
            stale.append({"path": str(path), "name": path.name, "error": str(exc), "active": False})
    return stale


def _runtime_status() -> dict[str, Any]:
    return {
        "status": "ok",
        "version": _runtime_version(),
        "services": {"gateway_service": GATEWAY_SERVICE, "control_service": CONTROL_SERVICE, "reload_mode": GOOGLE_GOVERNANCE_RELOAD_MODE},
        "paths": {
            "project": str(BASE),
            "self_contained": str(SELF_CONTAINED_BASE),
            "state": str(STATE_BASE),
            "config": str(CONFIG_BASE),
            "logs": str(LOG_BASE),
            "runtime": str(RUNTIME_BASE),
            "database": str(DB_BASE),
            "policy": str(POLICY_PATH),
            "registry": str(REGISTRY_PATH),
            "generated_policy": str(GENERATED_POLICY_PATH),
            "runtime_policy": str(RUNTIME_POLICY_PATH),
            "policy_change_log": str(CHANGE_LOG_PATH),
            "control_db": str(CONTROL_USERS_DB_PATH),
            "token_db": str(GOOGLE_WORKSPACE_TOKEN_DB_PATH),
            "token_root": str(GOOGLE_WORKSPACE_TOKEN_ROOT),
            "oauth_state": str(GOOGLE_OAUTH_STATE_ROOT),
            "approval_secret": str(APPROVAL_SECRET_PATH),
            "backup_root": str(RUNTIME_BACKUP_ROOT),
            "backup_cron": str(RUNTIME_BACKUP_CRON_PATH),
            "control_audit_log": str(CONTROL_AUDIT_LOG_PATH),
            "gateway_audit_log": str(GATEWAY_AUDIT_LOG_PATH),
            "installed_control_source": str(INSTALLED_CONTROL_SOURCE_PATH),
        },
        "stale_root_config_files": _stale_root_config_files(),
        "gateway_health": _runtime_gateway_health(),
        "jwt_secret": _jwt_secret_status(),
        "api_tokens": _api_token_inventory(),
        "backups": _runtime_backups(),
        "backup_schedule": _runtime_backup_schedule_status(),
        "yaml_sync": _yaml_sync_status(),
    }


def _runtime_validate(actor: str = "admin") -> dict[str, Any]:
    checks: list[dict[str, Any]] = []
    def add(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})
    for name, path in [("policy YAML", POLICY_PATH), ("resource registry YAML", REGISTRY_PATH), ("control SQLite DB", CONTROL_USERS_DB_PATH), ("approval secret", APPROVAL_SECRET_PATH)]:
        try:
            add(name, path.exists(), str(path))
        except Exception as exc:
            add(name, False, f"{path}: {exc}")
    try:
        jwt_status = _jwt_secret_status()
        add(
            "JWT filesystem custody disabled",
            jwt_status.get("storage") == "disabled",
            f"storage={jwt_status.get('storage')}; auth={jwt_status.get('auth_contract')}",
        )
    except Exception as exc:
        add("JWT filesystem custody disabled", False, str(exc))
    try:
        policy = _load_yaml(POLICY_PATH)
        registry = _load_yaml(REGISTRY_PATH)
        generated = _generate_policy_json(policy)
        add("policy parses", isinstance(policy, dict), f"profiles={len(policy.get('profile_policy') or {})}")
        add("registry parses", isinstance(registry, dict), f"resources={len(registry.get('resources') or {})}")
        add("runtime policy generates", bool(generated.get("profile_policy") is not None), f"mode={generated.get('mode')}")
        add("policy directory writable", os.access(POLICY_PATH.parent, os.W_OK), str(POLICY_PATH.parent))
        add("runtime policy directory writable or helper configured", os.access(RUNTIME_POLICY_PATH.parent, os.W_OK) or bool(PRIVILEGED_APPLY_CMD), f"runtime={RUNTIME_POLICY_PATH}; helper={'configured' if PRIVILEGED_APPLY_CMD else 'missing'}")
        generated_hash = hashlib.sha256((json.dumps(generated, indent=2, sort_keys=True) + "\n").encode("utf-8")).hexdigest()
        runtime_hash = _sha256_file(RUNTIME_POLICY_PATH)
        add("live runtime policy matches generated", bool(runtime_hash and runtime_hash == generated_hash), f"generated={generated_hash[:12]} runtime={runtime_hash[:12] if runtime_hash else 'missing'}")
        yaml_status = _yaml_sync_status()
        add("UI is authoritative for YAML", True, yaml_status.get("authority_note", "Direct YAML edits are overwritten by UI saves."))
        last = yaml_status.get("last_event") or {}
        add("last YAML sync/write recorded", bool(last), f"{last.get('ts','never')} {last.get('event','')}")
        for c in yaml_status.get("checks", []):
            add("YAML parity: " + str(c.get("name") or "check"), bool(c.get("ok")), str(c.get("detail") or ""))
    except Exception as exc:
        add("policy generation", False, str(exc))
    health = _runtime_gateway_health()
    if str(health.get("status") or "").lower() in {"ok", "healthy"}:
        health_detail = f"ok at {health.get('url') or GATEWAY_URL + '/healthz'}"
    else:
        health_detail = health.get("hint") or json.dumps(health, sort_keys=True)[:240]
    add("gateway health", str(health.get("status") or "").lower() in {"ok", "healthy"}, health_detail)
    version = _runtime_version()
    add("control UI source installed", bool(version.get("installed_sha256")), f"installed copy: {INSTALLED_CONTROL_SOURCE_PATH}")
    add("control UI source matches installed", bool(version.get("source_matches_installed")), f"this source file: {version.get('source_path')} → installed copy: {version.get('installed_path')} (source={version.get('source_sha256','')[:12]} installed={version.get('installed_sha256','')[:12]})")
    status = "ok" if all(c["ok"] for c in checks) else "needs_attention"
    result = {"status": status, "checks": checks, "version": version, "gateway_health": health}
    _append_change_event({"event": "runtime_validation_checked", "actor": actor, "status": status})
    return result


def _runtime_compare_yaml(actor: str = "admin") -> dict[str, Any]:
    status = _yaml_sync_status(actor, audit=True)
    return {
        "status": status.get("status", "needs_attention"),
        "yaml_sync": status,
        "compare": status.get("compare") or {},
        "checks": status.get("checks") or [],
        "authority_note": status.get("authority_note") or "",
    }


def _runtime_sync_yaml_from_ui(actor: str = "admin") -> dict[str, Any]:
    script = BASE / "scripts" / "recreate-google-governance-yaml-from-ui.py"
    if not script.exists():
        raise FileNotFoundError(f"YAML sync script is missing: {script}")
    cmd = [sys.executable, str(script), "--fix"]
    result = subprocess.run(cmd, cwd=str(BASE), text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
    report: dict[str, Any] = {}
    if result.stdout.strip():
        try:
            report = json.loads(result.stdout)
        except json.JSONDecodeError:
            report = {"stdout": result.stdout[-4000:]}
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or f"YAML sync failed with exit {result.returncode}")[-4000:])
    ok = bool((report.get("after_compare") or {}).get("ok"))
    event = {"event": "runtime_yaml_synced_from_ui", "actor": actor, "status": "ok" if ok else "needs_attention", "script": str(script), "report_path": str(BASE / "scripts" / "google-governance-ui-yaml-recreate-report.json")}
    _append_change_event(event)
    yaml_sync = _yaml_sync_status(actor)
    validation = _runtime_validate(actor)
    return {"status": event["status"], "script": str(script), "report": report, "yaml_sync": yaml_sync, "validation": validation}


def _copy_if_exists(src: Path, dst: Path) -> dict[str, Any] | None:
    try:
        if not src.exists():
            return None
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, dst, dirs_exist_ok=True)
        else:
            shutil.copy2(src, dst)
        return {"source": str(src), "backup": str(dst), "kind": "dir" if src.is_dir() else "file"}
    except Exception as exc:
        return {"source": str(src), "backup": str(dst), "error": str(exc)}


def _runtime_backup_create(payload: dict[str, Any] | None = None, actor: str = "admin") -> dict[str, Any]:
    payload = payload or {}
    include_token_store = bool(payload.get("include_token_store"))
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_id = f"google-governance-{ts}"
    backup_dir = RUNTIME_BACKUP_ROOT / backup_id
    copied: list[dict[str, Any]] = []
    for label, path in {
        "policy/google-governance-policy.yaml": POLICY_PATH,
        "policy/google-resource-registry.yaml": REGISTRY_PATH,
        "generated/profile_policy.json": GENERATED_POLICY_PATH,
        "runtime/profile_policy.json": RUNTIME_POLICY_PATH,
        "control/control_users.sqlite": CONTROL_USERS_DB_PATH,
        "source/google_governance_control_plane.py": INSTALLED_CONTROL_SOURCE_PATH if INSTALLED_CONTROL_SOURCE_PATH.exists() else Path(__file__).resolve(),
    }.items():
        item = _copy_if_exists(path, backup_dir / label)
        if item:
            copied.append(item)
    if include_token_store:
        for label, path in {"tokens/accounts": GOOGLE_WORKSPACE_TOKEN_ROOT, "control/token_db.sqlite": GOOGLE_WORKSPACE_TOKEN_DB_PATH}.items():
            item = _copy_if_exists(path, backup_dir / label)
            if item:
                copied.append(item)
    manifest = {"id": backup_id, "ts": ts, "actor": actor, "includes_token_store": include_token_store, "files": copied, "version": _runtime_version()}
    _atomic_write_text(backup_dir / "manifest.json", json.dumps(manifest, indent=2, sort_keys=True) + "\n", 0o640)
    archive = shutil.make_archive(str(backup_dir), "gztar", root_dir=backup_dir)
    with _control_db() as conn:
        conn.execute("INSERT OR REPLACE INTO runtime_backups(id,ts,actor,archive_path,backup_dir,includes_token_store,status,note) VALUES(?,?,?,?,?,?,?,?)", (backup_id, ts, actor, archive, str(backup_dir), 1 if include_token_store else 0, "created", str(payload.get("note") or "")))
        conn.commit()
    _append_change_event({"event": "runtime_backup_created", "actor": actor, "backup_id": backup_id, "archive": archive, "includes_token_store": include_token_store})
    return {"status": "created", "id": backup_id, "archive": archive, "backup_dir": str(backup_dir), "includes_token_store": include_token_store, "files": copied}


def _runtime_backup_export(payload: dict[str, Any] | None = None, actor: str = "admin") -> dict[str, Any]:
    payload = payload or {}
    backup_id = str(payload.get("id") or payload.get("backup_id") or "").strip()
    backups = _runtime_backups()
    selected = next((b for b in backups if b.get("id") == backup_id), backups[0] if backups else None)
    if not selected:
        selected = _runtime_backup_create({"note": "auto-created for export", "include_token_store": False}, actor)
    archive = Path(str(selected.get("archive") or selected.get("archive_path") or ""))
    result = {
        "status": "export_ready",
        "id": selected.get("id"),
        "archive_path": str(archive),
        "archive_exists": archive.exists(),
        "archive_size": archive.stat().st_size if archive.exists() else 0,
        "download_url": f"/api/runtime/backup/download?id={urllib.parse.quote(str(selected.get('id') or ''))}",
        "note": "Use Download to save the archive locally, or Upload to validate a backup archive before an operator restore.",
    }
    _append_change_event({"event": "runtime_backup_exported", "actor": actor, "backup_id": result["id"], "archive": result["archive_path"], "archive_exists": result["archive_exists"]})
    return result


def _runtime_backup_archive(backup_id: str = "") -> tuple[Path, dict[str, Any]]:
    backups = _runtime_backups()
    selected = next((b for b in backups if b.get("id") == backup_id), backups[0] if backups else None)
    if not selected:
        raise FileNotFoundError("no runtime backups are available")
    archive = Path(str(selected.get("archive_path") or selected.get("archive") or ""))
    if not archive.exists() or not archive.is_file():
        raise FileNotFoundError(f"backup archive is missing: {archive}")
    return archive, selected


def _runtime_backup_validate_archive(archive: Path) -> dict[str, Any]:
    if not archive.exists() or not archive.is_file():
        raise ValueError(f"backup archive does not exist: {archive}")
    try:
        with tarfile.open(archive, "r:gz") as tf:
            names = tf.getnames()
            if not any(n.endswith("manifest.json") for n in names):
                raise ValueError("archive does not contain manifest.json")
    except tarfile.TarError as exc:
        raise ValueError(f"backup archive is not a valid .tar.gz file: {exc}") from exc
    return {"archive_path": str(archive), "archive_size": archive.stat().st_size, "files_seen": len(names)}


def _runtime_backup_write_upload(payload: dict[str, Any]) -> Path | None:
    raw = str(payload.get("archive_data_b64") or "").strip()
    if not raw:
        return None
    if "," in raw and raw.split(",", 1)[0].startswith("data:"):
        raw = raw.split(",", 1)[1]
    data = base64.b64decode(raw, validate=True)
    name = Path(str(payload.get("filename") or f"uploaded-backup-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.tar.gz")).name
    if not name.endswith((".tgz", ".tar.gz")):
        name = name + ".tar.gz"
    dest = RUNTIME_BACKUP_ROOT / "uploaded" / name
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_bytes(data)
    os.chmod(tmp, 0o640)
    tmp.replace(dest)
    return dest


def _runtime_backup_schedule_status() -> dict[str, Any]:
    exists = RUNTIME_BACKUP_CRON_PATH.exists()
    return {"enabled": exists, "cron_path": str(RUNTIME_BACKUP_CRON_PATH), "content": RUNTIME_BACKUP_CRON_PATH.read_text(encoding="utf-8") if exists else ""}


def _runtime_backup_schedule(payload: dict[str, Any] | None = None, actor: str = "admin") -> dict[str, Any]:
    payload = payload or {}
    enabled = bool(payload.get("enabled", True))
    expr = str(payload.get("cron") or "0 2 * * *").strip()
    include_token_store = bool(payload.get("include_token_store"))
    if len(expr.split()) != 5:
        raise ValueError("cron schedule must have exactly five fields, e.g. 0 2 * * *")
    script = INSTALLED_CONTROL_SOURCE_PATH if INSTALLED_CONTROL_SOURCE_PATH.exists() else Path(__file__).resolve()
    flags = " --include-token-store" if include_token_store else ""
    content = f"# Google Workspace Governance runtime backup. Managed by Control UI.\nSHELL=/bin/sh\nPATH=/usr/bin:/bin\n{expr} {shlex.quote(sys.executable)} {shlex.quote(str(script))} --runtime-backup-now{flags} >>{shlex.quote(str(LOG_BASE / 'runtime-backup-cron.log'))} 2>&1\n"
    try:
        if enabled:
            RUNTIME_BACKUP_CRON_PATH.parent.mkdir(parents=True, exist_ok=True)
            _atomic_write_text(RUNTIME_BACKUP_CRON_PATH, content, 0o644)
            status = "scheduled"
        else:
            if RUNTIME_BACKUP_CRON_PATH.exists():
                RUNTIME_BACKUP_CRON_PATH.unlink()
            status = "disabled"
        _append_change_event({"event": "runtime_backup_schedule_updated", "actor": actor, "enabled": enabled, "cron": expr, "include_token_store": include_token_store})
        return {"status": status, "enabled": enabled, "cron": expr, "cron_path": str(RUNTIME_BACKUP_CRON_PATH), "include_token_store": include_token_store}
    except PermissionError:
        return {"status": "needs_operator", "enabled": enabled, "cron": expr, "cron_path": str(RUNTIME_BACKUP_CRON_PATH), "content": content, "message": "Control UI user cannot write the self-contained backup schedule file; fix install-root ownership/permissions."}


def _runtime_backup_import(payload: dict[str, Any] | None = None, actor: str = "admin") -> dict[str, Any]:
    payload = payload or {}
    uploaded = _runtime_backup_write_upload(payload)
    archive_raw = str(payload.get("archive_path") or payload.get("path") or "").strip()
    if uploaded is not None:
        archive = uploaded
    elif archive_raw:
        archive = Path(archive_raw)
    else:
        raise ValueError("backup archive path or uploaded archive required")
    validated = _runtime_backup_validate_archive(archive)
    result = {
        "status": "validated",
        **validated,
        "restore_scope": "validated archive only; live restore is not automatic",
        "next_step": f"Create a fresh backup, then restore selected files from {archive} under operator supervision.",
    }
    _append_change_event({"event": "runtime_backup_import_checked", "actor": actor, "archive": str(archive), "archive_size": result["archive_size"]})
    return result


def _runtime_restart(actor: str) -> dict[str, Any]:
    restart = _systemctl_restart_gateway()
    event = {"event": "runtime_restart_requested", "actor": actor, "restart": restart}
    _append_change_event(event)
    return {"status": "restarted", **event}



def _runtime_apply(actor: str) -> dict[str, Any]:
    policy = _load_yaml(POLICY_PATH)
    runtime_policy = _generate_policy_json(policy)
    runtime_install = _stage_and_install_runtime_policy(runtime_policy)
    restart = _systemctl_restart_gateway()
    event = {"event": "runtime_policy_applied", "actor": actor, "runtime_policy": str(RUNTIME_POLICY_PATH), "reload_mode": GOOGLE_GOVERNANCE_RELOAD_MODE}
    _append_change_event(event)
    return {"status": "applied", **event, "runtime_install": runtime_install, "restart": restart}

def _apply_policy_change(payload: dict[str, Any]) -> dict[str, Any]:
    profile = str(payload.get("profile") or "").strip()
    scope = str(payload.get("scope") or "override").strip()
    resource_alias = str(payload.get("resource_alias") or "").strip()
    action = str(payload.get("action") or "").strip()
    decision = str(payload.get("decision") or "").strip()
    reason = str(payload.get("reason") or "").strip()
    actor = str(payload.get("actor") or "admin").strip()
    if not profile or not action or decision not in ALLOWED_DECISIONS or scope not in ALLOWED_SCOPES:
        raise ValueError("profile, action, decision allow/ask/deny, and scope default/override are required")
    if scope == "override" and not resource_alias:
        raise ValueError("resource_alias is required for override changes")
    policy = _load_yaml(POLICY_PATH)
    profiles = policy.setdefault("profile_policy", {})
    spec = profiles.setdefault(profile, {"defaults": {}, "resource_overrides": {}})
    if scope == "default":
        target = spec.setdefault("defaults", {})
        target_key = action
    else:
        target = spec.setdefault("resource_overrides", {}).setdefault(resource_alias, {})
        target_key = action
    previous = target.get(target_key)
    global_deny_removed_from: list[str] = []
    if decision != "deny":
        # The original migration used broad global denies for high-risk actions.
        # Once Admin explicitly changes an action through this protected UI, the
        # profile/resource ACL must be allowed to govern it; otherwise the GUI
        # would appear to update policy while the global deny still wins.
        for rule in policy.get("global_denies") or []:
            actions = rule.get("actions") or []
            if action in actions and ("*" in (rule.get("profiles") or []) or profile in (rule.get("profiles") or [])):
                rule["actions"] = [item for item in actions if item != action]
                global_deny_removed_from.append(str(rule.get("id") or "unnamed"))
        policy["global_denies"] = [rule for rule in (policy.get("global_denies") or []) if rule.get("actions")]
    if previous == decision and not global_deny_removed_from:
        changed = False
    else:
        target[target_key] = decision
        changed = True
        backup = POLICY_PATH.with_suffix(POLICY_PATH.suffix + f".{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.bak")
        shutil.copy2(POLICY_PATH, backup)
        _write_yaml_document(POLICY_PATH, policy, summary=f"Policy rule updated: {profile} {scope} {resource_alias or '__profile_default__'} {action} -> {decision}")
        _record_yaml_sync_event(actor, "ok", "policy_change_yaml_written", {"profile": profile, "scope": scope, "resource_alias": resource_alias, "action": action, "decision": decision})
    runtime_policy = _generate_policy_json(policy)
    generated_content = _write_generated_policy_json(runtime_policy)
    if changed or bool(payload.get("force_install")):
        runtime_install = _install_runtime_policy_json(generated_content)
        restart = _systemctl_restart_gateway()
    else:
        runtime_install = None
        restart = {"service": GATEWAY_SERVICE, "skipped": "no policy change"}
    event = {"event": "policy_change_applied", "actor": actor, "profile": profile, "scope": scope, "resource_alias": resource_alias, "action": action, "previous": previous, "decision": decision, "reason": reason, "changed": changed, "global_deny_removed_from": global_deny_removed_from}
    _append_change_event(event)
    return {"status": "applied", **event, "runtime_policy": str(RUNTIME_POLICY_PATH), "runtime_install": runtime_install, "restart": restart}



def _apply_bulk_policy_changes(payload: dict[str, Any]) -> dict[str, Any]:
    changes = payload.get("changes") or []
    if not isinstance(changes, list) or not changes:
        raise ValueError("changes list is required")
    if len(changes) > 500:
        raise ValueError("bulk change limit is 500 rows")
    actor = str(payload.get("actor") or "admin").strip()
    reason = str(payload.get("reason") or "Bulk ACL update").strip()
    policy = _load_yaml(POLICY_PATH)
    backup = POLICY_PATH.with_suffix(POLICY_PATH.suffix + f".{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.bak")
    shutil.copy2(POLICY_PATH, backup)
    applied: list[dict[str, Any]] = []
    for item in changes:
        if not isinstance(item, dict):
            raise ValueError("each change must be an object")
        profile = str(item.get("profile") or "").strip()
        scope = str(item.get("scope") or "override").strip()
        resource_alias = str(item.get("resource_alias") or "").strip()
        action = str(item.get("action") or "").strip()
        decision = str(item.get("decision") or "").strip()
        if resource_alias == "__profile_default__":
            resource_alias = ""
        if not profile or not action or decision not in ALLOWED_DECISIONS or scope not in ALLOWED_SCOPES:
            raise ValueError("each change requires profile, action, scope, and decision")
        if scope == "override" and not resource_alias:
            raise ValueError("resource_alias is required for override changes")
        spec = policy.setdefault("profile_policy", {}).setdefault(profile, {"defaults": {}, "resource_overrides": {}})
        target = spec.setdefault("defaults", {}) if scope == "default" else spec.setdefault("resource_overrides", {}).setdefault(resource_alias, {})
        previous = target.get(action)
        if decision != "deny":
            for rule in policy.get("global_denies") or []:
                actions = rule.get("actions") or []
                if action in actions and ("*" in (rule.get("profiles") or []) or profile in (rule.get("profiles") or [])):
                    rule["actions"] = [a for a in actions if a != action]
            policy["global_denies"] = [rule for rule in (policy.get("global_denies") or []) if rule.get("actions")]
        target[action] = decision
        applied.append({"profile": profile, "scope": scope, "resource_alias": resource_alias, "action": action, "previous": previous, "decision": decision})
    _write_yaml_document(POLICY_PATH, policy, summary=f"Bulk policy update: {len(applied)} rule(s); reason={reason or 'not specified'}")
    _record_yaml_sync_event(actor, "ok", "bulk_policy_change_yaml_written", {"count": len(applied), "reason": reason})
    runtime_policy = _generate_policy_json(policy)
    runtime_install = _stage_and_install_runtime_policy(runtime_policy)
    restart = _systemctl_restart_gateway()
    event = {"event": "bulk_policy_change_applied", "actor": actor, "reason": reason, "count": len(applied), "changes": applied}
    _append_change_event(event)
    return {"status": "applied", "count": len(applied), "changes": applied, "backup": str(backup), "runtime_install": runtime_install, "restart": restart}


def _recent_activity(limit: int = 25) -> list[dict[str, Any]]:
    """Recent operator-visible activity for the UI notification bell."""
    rows: list[dict[str, Any]] = []
    try:
        with _control_db() as conn:
            for row in conn.execute(
                "SELECT ts,event,actor,payload_json FROM change_events ORDER BY ts DESC LIMIT ?",
                (int(limit),),
            ).fetchall():
                item = dict(row)
                try:
                    payload = json.loads(item.get("payload_json") or "{}")
                except Exception:
                    payload = {}
                event = str(item.get("event") or payload.get("event") or "activity")
                actor = str(item.get("actor") or payload.get("actor") or "")
                rows.append({
                    "ts": str(item.get("ts") or payload.get("ts") or ""),
                    "event": event,
                    "actor": actor,
                    "kind": "approval" if "approval" in event else ("acl" if any(x in event for x in ("policy", "acl", "yaml")) else ("user" if "user" in event or "profile" in event or "oidc" in event else "system")),
                    "summary": _activity_summary(event, payload, actor),
                })
    except Exception:
        rows = []
    try:
        approvals = sorted(_approval_state().values(), key=lambda row: str(row.get("ts") or ""), reverse=True)[: max(0, int(limit) - len(rows))]
        for item in approvals:
            st = str(item.get("state") or "pending")
            rows.append({
                "ts": str(item.get("requested_at") or item.get("ts") or ""),
                "event": f"approval_{st}",
                "actor": str(item.get("profile") or item.get("actor") or ""),
                "kind": "approval",
                "summary": f"Approval {st}: {item.get('action') or 'request'}",
            })
    except Exception:
        pass
    rows.sort(key=lambda row: str(row.get("ts") or ""), reverse=True)
    return rows[:limit]


def _activity_summary(event: str, payload: dict[str, Any], actor: str = "") -> str:
    pretty = event.replace("_", " ")
    if event in {"policy_change_yaml_written", "runtime_yaml_synced_from_ui", "bulk_policy_change_yaml_written", "workspace_acl_yaml_written"}:
        return f"ACL/runtime policy updated{(' by ' + actor) if actor else ''}"
    if event in {"control_user_saved", "control_user_deleted", "control_profile_updated"}:
        target = payload.get("username") or payload.get("actor") or actor
        return f"User setting changed: {target}"
    if event.startswith("approval_channel") or event.startswith("approval_"):
        return f"Approval configuration/activity: {pretty}"
    if event.startswith("api_token"):
        return f"API token activity: {pretty}"
    if event.startswith("workspace") or "oauth" in event:
        return f"Workspace configuration: {pretty}"
    return pretty.capitalize()


def _snapshot() -> dict[str, Any]:
    policy = _load_yaml(POLICY_PATH)
    registry = _load_yaml(REGISTRY_PATH)
    snapshot = _build_snapshot(policy, registry)
    try:
        snapshot["access_log"] = _access_log(50).get("events", [])
        snapshot["access_log_error"] = ""
    except Exception as exc:
        snapshot["access_log"] = []
        snapshot["access_log_error"] = str(exc)
    try:
        pending = _approval_inventory({"state": "pending"}).get("approvals", [])
        snapshot["pending_approvals"] = len(pending)
        snapshot["recent_activity"] = _recent_activity(25)
    except Exception as exc:
        snapshot["pending_approvals"] = 0
        snapshot["recent_activity"] = []
        snapshot["recent_activity_error"] = str(exc)
    snapshot["profile_options"] = sorted((policy.get("profile_policy", {}) or {}).keys())
    snapshot["token_inventory"] = _token_inventory_items()
    snapshot["workspace_routes"] = _workspace_route_inventory(policy, registry)
    snapshot["control"] = {"protected_by": "app username/password session", "bind": f"{CONTROL_HOST}:{CONTROL_PORT}", "gateway": GATEWAY_URL, "auth": "disabled" if CONTROL_AUTH_DISABLED else "app_session", "setup_required": _setup_required(), "reload_mode": GOOGLE_GOVERNANCE_RELOAD_MODE, "token_db": str(GOOGLE_WORKSPACE_TOKEN_DB_PATH)}
    return snapshot


INDEX_HTML = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><title>Google Governance Control</title><style>
:root{--bg:#070707;--surface:#111;--surface2:#171717;--elev:#202020;--text:#d8d8d8;--muted:#aaa;--line:#2d2d2d;--accent:#f0f0f0;--accentText:#050505;--hover:#2f2f2f;--hoverText:#dddddd;--navSelected:#242424;--navSelectedText:#d6d6d6;--navSelectedLine:#3a3a3a;--allow:#d8f5e8;--ask:#f3f3f3;--deny:#ffe0e0;--input:#0b0b0b;--shadow:0 18px 55px rgba(0,0,0,.35);--radius:4px;--radius-sm:3px}body.light{--bg:#f6f6f6;--surface:#fff;--surface2:#f0f0f0;--elev:#e7e7e7;--text:#111;--muted:#666;--line:#d4d4d4;--accent:#111;--accentText:#fff;--hover:#e2e2e2;--hoverText:#111;--navSelected:#dedede;--navSelectedText:#111;--navSelectedLine:#bdbdbd;--allow:#e8f7ef;--ask:#f3f3f3;--deny:#ffe9e9;--input:#fff;--shadow:0 14px 38px rgba(0,0,0,.10)}*{box-sizing:border-box}html,body{max-width:100%;overflow-x:hidden}body{margin:0;background:var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}.hidden{display:none!important}header{position:sticky;top:0;z-index:10;border-bottom:1px solid var(--line);background:rgba(7,7,7,.92);backdrop-filter:blur(14px)}body.light header{background:rgba(246,246,246,.92)}.wrap{width:100%;max-width:1480px;margin:0 auto;padding:18px clamp(14px,2vw,28px)}.top{display:flex;justify-content:space-between;gap:18px;align-items:center}.brand{display:flex;gap:14px;align-items:center;color:inherit;text-decoration:none;cursor:pointer}.brand:hover h1{color:var(--text)}.mark{width:52px;height:52px;border:1px solid var(--line);border-radius:var(--radius-sm);background:var(--surface);box-shadow:none;object-fit:contain}.logTable td,.logTable th{white-space:normal}.logoText{line-height:1.12}.logoText .sub{display:block;margin-top:6px}h1{font-size:21px;margin:0;letter-spacing:-.03em}.sub,.label,.muted{color:var(--muted)}main{width:100%;max-width:1480px;margin:0 auto;padding:22px clamp(14px,2vw,28px) 56px;overflow-x:hidden}.mainNav{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:0 0 16px}.mainNav{border-bottom:1px solid var(--line);gap:0}.mainNav button{min-width:116px;background:transparent;border:0;border-bottom:2px solid transparent;border-radius:0;margin:0;padding:12px 14px}.mainNav button:hover{background:var(--surface2);border-bottom-color:var(--line)}.mainNav button.active{background:transparent;border-color:transparent;border-bottom-color:var(--accent);color:var(--text)}.cards{display:grid;grid-template-columns:repeat(6,minmax(120px,1fr));gap:12px;margin-bottom:16px}.panel,.card{background:linear-gradient(180deg,var(--surface),var(--surface2));border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow)}.card{padding:16px}.metric{font-size:28px;font-weight:850;letter-spacing:-.04em}.panel{overflow-x:hidden;max-width:100%;padding:16px}.sectionHead{display:flex;justify-content:space-between;gap:12px;align-items:center;margin:0 0 12px}.toolbar,.bulkbar,.formgrid,.passwordGrid{display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:12px 0}.toolbar{flex-wrap:wrap;overflow-x:hidden}.toolbar input,.toolbar select{min-width:0;max-width:100%}.toolbar input{flex:1 1 220px}.toolbar select{flex:1 1 150px}.authLinkBox{border:1px solid var(--navSelectedLine);background:var(--surface2);padding:12px 14px;margin-top:8px}.authLinkBox a{display:inline-flex;align-items:center;gap:8px;font-size:15px;font-weight:750;color:var(--text);text-decoration:none;border:1px solid var(--line);background:var(--elev);padding:10px 12px;border-radius:var(--radius-sm)}.authLinkBox a:hover{background:var(--hover);border-color:var(--muted)}body.light .authLinkBox{background:#f2f2f2}body.light .authLinkBox a{background:#fff;color:#111}.settingsGrid{display:grid;grid-template-columns:repeat(2,minmax(260px,1fr));gap:14px}input,select,button,textarea{border:1px solid var(--line);background:var(--input);color:var(--text);border-radius:var(--radius-sm);padding:10px 12px;font:inherit}input[type=checkbox]{width:16px!important;height:16px!important;min-width:16px!important;min-height:16px!important;padding:0;margin:0;vertical-align:middle;accent-color:var(--accent)}input,select{min-height:40px}input{min-width:230px}button{cursor:pointer;background:var(--elev);font-weight:650}button:hover{border-color:var(--muted)}button.primary{background:var(--accent);color:var(--accentText);border-color:var(--accent)}button.good{background:#163326;color:#e7fff4;border-color:#24553f}button.danger{background:#391919;color:#ffe8e8;border-color:#6b2c2c}body.light button.good{background:#e8f7ef;color:#0a3420}body.light button.danger{background:#ffe9e9;color:#4a0f0f}button:disabled{opacity:.45;cursor:not-allowed}.actions{display:flex;align-items:center;gap:10px}.userMenu{position:relative}.userMenuButton{min-width:150px;display:flex;gap:8px;justify-content:space-between;align-items:center;background:transparent;border-color:transparent}.userMenuButton:hover{background:var(--surface2);border-color:transparent}.userDropdown{position:absolute;right:0;top:calc(100% + 8px);min-width:240px;background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);box-shadow:var(--shadow);padding:6px}.userDropdown button{width:100%;margin-top:2px;text-align:left;background:transparent;border-color:transparent;border-radius:0;padding:9px 10px}.userDropdown button:hover{background:var(--surface2);border-color:transparent}.msg{margin-top:12px;color:var(--muted);font-size:13px}.ok{color:#6ee7b7}.error{color:#fca5a5}.login{max-width:520px;margin:70px auto;padding:24px}.login input,.login button{width:100%;margin:7px 0}table{width:100%;border-collapse:separate;border-spacing:0;min-width:0;table-layout:fixed}th,td{text-align:left;padding:11px 12px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere;word-break:break-word}th{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--muted);background:var(--surface2);position:sticky;top:0}.decision,.pill{display:inline-flex;align-items:center;border:1px solid var(--line);border-radius:999px;padding:4px 9px;font-size:12px;font-weight:700}.decision.allow{background:var(--allow);color:#064e32}.decision.ask{background:var(--ask);color:#222}.decision.deny{background:var(--deny);color:#641616}.code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}.inline{min-width:110px}.modePill{margin-left:auto}.settingBlock{margin-bottom:18px}.settingsSubnav button{border-radius:0;box-shadow:none}.settingsSubnav button.active{background:var(--elev);color:var(--text);border-color:transparent}.settingsShell{display:grid;grid-template-columns:minmax(260px,320px) minmax(0,1fr);gap:0;align-items:start;max-width:100%;overflow-x:hidden;border:1px solid var(--line);background:var(--surface)}.settingsSubnav{position:sticky;top:94px;min-height:calc(100vh - 140px);border-right:1px solid var(--line);padding:0;background:#191a1d;box-shadow:8px 0 18px rgba(0,0,0,.12);transition:width .18s ease}.settingsSubnav button{position:relative;display:block;width:100%;text-align:left;margin:0;background:transparent;border:0;border-bottom:1px solid rgba(255,255,255,.09);border-radius:0;box-shadow:none;color:#f2f2f2;padding:14px 22px;font-size:15px;font-weight:650;letter-spacing:-.015em}.settingsSubnav button.subItem{padding:13px 22px 13px 44px;font-size:14px;font-weight:500;color:#ececec;border-bottom:0}.settingsSubnav button.navGroup{font-weight:750}.settingsSubnav button.navGroup::after{content:'›';position:absolute;right:20px;top:50%;transform:translateY(-50%);font-size:28px;line-height:1;color:#f4f4f4}.settingsSubnav button.navGroup.active::after{content:'⌄';font-size:20px}.settingsSubnav button:hover{background:#242529;border-color:rgba(255,255,255,.11);color:#fff}.settingsSubnav button.active{background:#56585d;border-color:rgba(255,255,255,.08);color:#fff}.settingsSubnav button.active::before{content:'';position:absolute;left:0;top:0;bottom:0;width:5px;background:#ff4b2f}.settingsTopbar{display:flex;align-items:center;gap:12px;justify-content:space-between;margin:0;padding:18px 22px;border:1px solid var(--line);border-bottom:0;background:var(--surface)}.settingsTopbar h2{margin:0;flex:1;font-size:28px;letter-spacing:-.04em}.settingsBack{white-space:nowrap}.settingsNavControl{height:72px!important;font-size:0!important;line-height:1;text-align:center!important;color:#9ca0a8!important;border-bottom:1px solid rgba(255,255,255,.12)!important;margin:0!important;background:#151619!important}.settingsNavControl::before{content:'☰';font-size:34px;font-weight:800;letter-spacing:-.08em}.settingsNavControl:hover{background:#202126!important;color:#fff!important}.settingsShell.collapsed{grid-template-columns:78px minmax(0,1fr)}.settingsShell.collapsed .settingsSubnav{padding:0}.settingsShell.collapsed .settingsSubnav button.subItem{display:none}.settingsShell.collapsed .settingsSubnav button.navGroup::after{content:''}.settingsShell.collapsed .settingsSubnav button:not(.settingsNavControl){font-size:0;text-align:center;padding:18px 8px}.settingsShell.collapsed .settingsSubnav button:not(.settingsNavControl)::before{content:attr(data-icon);position:static;background:transparent;width:auto;font-size:22px;font-weight:400}.settingsShell.collapsed .settingsSubnav button:not(.settingsNavControl).active::after{content:'';position:absolute;left:0;top:0;bottom:0;width:5px;background:#ff4b2f}.settingsShell.collapsed .settingsSubnav button:not(.settingsNavControl)[data-icon=""]::before{content:"•"}.settingsContent{min-width:0}.settingBlock{margin-bottom:18px;background:transparent;border:0;box-shadow:none;padding:0}.workflowSteps{display:grid;grid-template-columns:repeat(4,minmax(150px,1fr));gap:10px;margin:12px 0}.workflowSteps.verticalSteps{display:grid;grid-template-columns:1fr;gap:12px}.verticalSteps .step{display:grid;gap:9px}.step{border:1px solid var(--line);background:var(--surface2);border-radius:var(--radius-sm);padding:10px}.step b{display:block;margin-bottom:4px}.accessHeader{display:flex;gap:10px;align-items:center;justify-content:space-between}.grafanaNote{margin-top:10px}.refreshRow{display:flex;gap:10px;align-items:center}.targetDetails{margin-top:6px;color:var(--muted);font-size:12px}.targetDetails summary{cursor:pointer;color:var(--text);font-weight:500}.targetGrid{display:grid;grid-template-columns:max-content 1fr;gap:4px 10px;margin-top:6px}.targetGrid dt{color:var(--muted)}.targetGrid dd{margin:0;word-break:break-word;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}.profileCards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:8px;margin:8px 0}.profileCard{display:flex;align-items:center;gap:8px;border:1px solid var(--line);background:var(--surface2);padding:10px;border-radius:var(--radius-sm);cursor:pointer}.profileCard:hover{background:var(--elev)}.profileCard input{min-width:16px}th[data-sort]{cursor:pointer}th[data-sort]:hover{color:var(--text)}
.loginSplit{min-height:calc(100vh - 90px);display:grid;grid-template-columns:1fr 1fr}.loginHero{display:grid;place-items:center;padding:56px;background:linear-gradient(135deg,var(--surface),var(--bg));border-right:1px solid var(--line)}.loginHeroInner{max-width:520px}.loginHeroLogo{width:min(340px,72vw);height:auto;display:block;margin:0 0 34px;object-fit:contain}.loginHero h1{font-size:52px;letter-spacing:-.06em;margin:0 0 12px}.loginHero p{color:var(--muted);font-size:18px;margin:0}.loginPanel{display:grid;place-items:center;padding:44px 18px}.avatarMini{width:36px;height:36px;border:1px solid var(--line);border-radius:50%;object-fit:cover;background:var(--surface);box-shadow:0 0 0 2px var(--surface2)}.profileAvatarPreview{width:72px;height:72px;border:1px solid var(--line);border-radius:50%;object-fit:cover;background:var(--surface);box-shadow:0 0 0 3px var(--surface2)}.mainNav button.active{background:var(--navSelected);color:var(--navSelectedText);border-color:var(--navSelectedLine)}.mainNav button:hover{background:var(--hover);color:var(--hoverText);border-color:var(--navSelectedLine)}.settingsSubnav .subItem{padding-left:26px;font-size:13px;color:var(--muted)}.settingsSubnav button{border-color:transparent;background:transparent}.settingsSubnav button:hover{background:var(--surface2);color:var(--text);border-color:var(--line)}.settingsSubnav button.active{background:var(--navSelected);color:var(--navSelectedText);border-color:var(--navSelectedLine)}.authShell{min-height:calc(100vh - 90px);display:grid;place-items:center;padding:44px 18px}.authCard{width:min(520px,100%);border:1px solid var(--line);border-radius:var(--radius);background:linear-gradient(180deg,var(--surface),var(--surface2));box-shadow:var(--shadow);padding:26px;position:relative;overflow:hidden}.authCard:before{content:"";position:absolute;inset:0 0 auto;height:5px;background:linear-gradient(90deg,var(--accent),var(--line));opacity:.9}.authLogo{display:flex;align-items:center;gap:13px;margin-bottom:22px}.authLogo img{width:48px;height:48px;border:1px solid var(--line);border-radius:var(--radius-sm);object-fit:contain;background:var(--surface)}.authTitle{font-size:30px;line-height:1;letter-spacing:-.05em;margin:0 0 8px}.authLead{color:var(--muted);line-height:1.5;margin:0 0 20px}.authGrid{display:grid;gap:10px}.authMeta{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:18px}.authMeta span{border:1px solid var(--line);border-radius:var(--radius-sm);padding:9px 10px;color:var(--muted);font-size:12px;background:rgba(255,255,255,.035)}@media(max-width:900px){.loginSplit{grid-template-columns:1fr}.loginHero{min-height:260px;border-right:0;border-bottom:1px solid var(--line)}.settingsShell{grid-template-columns:1fr}.settingsSubnav{position:static;border-right:0;border-bottom:1px solid var(--line);padding:0 0 10px}.settingsSubnav button{display:inline-block;width:auto}.workflowSteps{grid-template-columns:1fr 1fr}.authMeta{grid-template-columns:1fr}}
.routeComposer{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(320px,100%),1fr));gap:18px;margin:18px 0 14px;max-width:100%;overflow-x:hidden}.routePickPanel{border:1px solid var(--line);background:var(--surface2);box-shadow:var(--shadow)}.routePickHead{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;padding:14px 16px;border-bottom:1px solid var(--line)}.routePickHead h4{margin:0 0 4px;font-size:14px;letter-spacing:.02em}.routePickHead p{margin:0;color:var(--muted);font-size:12px}.routePickCount{font-size:12px;color:var(--muted);white-space:nowrap}.routePickList{display:grid;gap:0;max-height:285px;overflow:auto}.routePickItem{display:grid;grid-template-columns:20px 1fr;gap:10px;padding:12px 14px;border-bottom:1px solid var(--line);cursor:pointer}.routePickItem:last-child{border-bottom:0}.routePickItem:hover{background:var(--elev)}.routePickItem input{width:16px;height:16px;margin:2px 0 0}.routePickTitle{font-weight:400}.routePickMeta{font-size:12px;color:var(--muted);margin-top:3px;word-break:break-word}.routeComposerActions{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 18px}.routeComposerActions .muted{font-size:12px}table td,table td *,table th,.routePickTitle{font-weight:400}.filterSelect{min-width:150px;max-height:2.8em;overflow:auto;background:var(--input);color:var(--text);border-color:var(--line);color-scheme:dark}.filterSelect option{background:var(--input);color:var(--text)}body.light .filterSelect{color-scheme:light}.runtimeSubnav .subItem{padding-left:38px}.runtimeActions{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:14px 0}.runtimeActions button,.runtimeActions .downloadLink,.fileRow button{flex:0 0 auto;width:auto;min-width:0;padding:7px 10px;font-size:13px;line-height:1.2}.configSummaryGrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(280px,100%),1fr));gap:10px;margin:12px 0 14px}.configSummaryItem{border:1px solid var(--line);background:var(--surface2);padding:11px 12px;min-width:0}.configSummaryLabel{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.06em;margin-bottom:5px}.configSummaryValue{display:block;color:var(--text);font-size:13px;line-height:1.45;overflow-wrap:anywhere}.validationPanel{padding:0;background:transparent;border:0}.validationIntro{margin:0 0 12px}.validationChecks{display:grid;gap:10px}.validationCheck{display:grid;grid-template-columns:28px minmax(0,1fr);gap:10px;align-items:start;border:1px solid var(--line);background:var(--surface2);padding:12px}.validationCheck.ok{border-left:4px solid #2f8f58}.validationCheck.warn{border-left:4px solid #b78b2e}.validationIcon{font-size:18px;line-height:1.2}.validationName{font-weight:650;color:var(--text);margin-bottom:4px}.validationDetail{color:var(--muted);font-size:13px;line-height:1.45;overflow-wrap:anywhere;white-space:normal}.buttonStack{display:grid;gap:10px;align-items:start}.fileRow{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.fileRow input,.fileRow select{flex:0 1 auto}.downloadLink{display:inline-block;padding:7px 10px;border:1px solid var(--line);background:var(--surface2);color:var(--text);text-decoration:none}.downloadLink:hover{background:var(--hover)}@media(max-width:900px){.routeComposer{grid-template-columns:1fr}}
.cards,.panel,.settingsContent,.settingBlock,.runtimeBox,.mcpGrid{max-width:100%;min-width:0}.mcpGrid{display:grid;grid-template-columns:1fr;gap:16px;width:100%}.mcpCatalog{border:1px solid var(--line);background:var(--surface2);padding:12px}.mcpCatalog summary{cursor:pointer;font-weight:700;color:var(--text)}.smallNote{font-size:12px;margin:10px 0 12px}.mcpTestPanel{grid-column:1/-1;width:100%}.mcpTestControls{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(240px,100%),1fr));gap:12px;align-items:end}.fieldLabel{display:grid;gap:6px;color:var(--muted);font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.04em}.fieldLabel span{color:var(--muted)}#mcpTestResult{width:100%;box-sizing:border-box;min-height:260px;white-space:pre-wrap}.iconActions{display:flex;gap:6px;align-items:center;white-space:nowrap}.iconBtn{min-width:34px;width:34px;height:32px;padding:0;display:inline-flex;align-items:center;justify-content:center;font-size:15px;line-height:1}.iconBtn.danger{border-color:#6a3434;color:#ffd5d5}.iconBtn.confirmed{border-color:#2f8f58!important;background:#123521!important;color:#b9f6cf!important}.iconBtn:disabled{opacity:.55;cursor:wait}.headerFilter{margin-top:6px;width:100%;box-sizing:border-box;font-size:12px;padding:6px 7px;background:var(--input);border:1px solid var(--line);color:var(--text)}.runtimeBox,pre,textarea,input,select{max-width:100%}.code{white-space:normal;overflow-wrap:anywhere}.scopeInfo{display:inline-flex;align-items:center;justify-content:center;width:18px;height:18px;margin-left:6px;border:1px solid var(--line);border-radius:50%;font-size:12px;font-weight:800;cursor:help;color:var(--muted);background:var(--surface2);vertical-align:middle}.scopeInfo:hover{color:var(--text);border-color:var(--muted)}@media(max-width:760px){.settingsTopbar{align-items:stretch;flex-wrap:wrap}.settingsTopbar h2{flex-basis:100%;order:-1}.settingsShell,.settingsShell.collapsed{grid-template-columns:1fr}.settingsSubnav{position:static;border-right:0;border-bottom:1px solid var(--line);padding:0 0 10px}.sectionHead,.top{align-items:flex-start}.cards{grid-template-columns:1fr}.mainNav button{min-width:0;flex:1 1 120px}}
/* Authentik-inspired settings side menu: dark rail, hamburger collapse, grouped rows, active side stripe. */.settingsShell{display:grid!important;grid-template-columns:minmax(260px,320px) minmax(0,1fr)!important;gap:0!important;align-items:start;max-width:100%;overflow-x:hidden;border:1px solid var(--line);background:var(--surface)}.settingsContent{padding:18px 20px 24px}.settingsSubnav{position:sticky!important;top:94px!important;min-height:calc(100vh - 140px);border-right:1px solid var(--line)!important;border-bottom:0!important;padding:0!important;background:#191a1d!important;box-shadow:8px 0 18px rgba(0,0,0,.12)}.settingsSubnav button{position:relative!important;display:block!important;width:100%!important;text-align:left!important;margin:0!important;background:transparent!important;border:0!important;border-bottom:1px solid rgba(255,255,255,.09)!important;border-radius:0!important;box-shadow:none!important;color:#f2f2f2!important;padding:14px 22px!important;font-size:15px!important;font-weight:650!important;letter-spacing:-.015em}.settingsSubnav button.subItem{padding:13px 22px 13px 44px!important;font-size:14px!important;font-weight:500!important;color:#ececec!important;border-bottom:0!important}.settingsSubnav button.navGroup{font-weight:750!important}.settingsSubnav button.navGroup::after{content:'›';position:absolute;right:20px;top:50%;transform:translateY(-50%);font-size:28px;line-height:1;color:#f4f4f4}.settingsSubnav button.navGroup.active::after{content:'⌄';font-size:20px}.settingsSubnav button:hover{background:#242529!important;border-color:rgba(255,255,255,.11)!important;color:#fff!important}.settingsSubnav button.active{background:#56585d!important;border-color:rgba(255,255,255,.08)!important;color:#fff!important}.settingsSubnav button.active::before{content:'';position:absolute;left:0;top:0;bottom:0;width:5px;background:#ff4b2f}.settingsTopbar{display:flex;align-items:center;gap:12px;justify-content:space-between;margin:0!important;padding:18px 22px;border:1px solid var(--line);border-bottom:0;background:var(--surface)}.settingsTopbar h2{margin:0;flex:1;font-size:28px;letter-spacing:-.04em}.settingsNavControl{height:72px!important;font-size:0!important;line-height:1;text-align:center!important;color:#9ca0a8!important;border-bottom:1px solid rgba(255,255,255,.12)!important;margin:0!important;background:#151619!important}.settingsNavControl::before{content:'☰';font-size:34px;font-weight:800;letter-spacing:-.08em}.settingsNavControl:hover{background:#202126!important;color:#fff!important}.settingsShell.collapsed{grid-template-columns:78px minmax(0,1fr)!important}.settingsShell.collapsed .settingsSubnav{padding:0!important}.settingsShell.collapsed .settingsSubnav button.subItem{display:none!important}.settingsShell.collapsed .settingsSubnav button.navGroup::after{content:''}.settingsShell.collapsed .settingsSubnav button:not(.settingsNavControl){font-size:0!important;text-align:center!important;padding:18px 8px!important}.settingsShell.collapsed .settingsSubnav button:not(.settingsNavControl)::before{content:attr(data-icon);position:static;background:transparent;width:auto;font-size:22px;font-weight:400}.settingsShell.collapsed .settingsSubnav button:not(.settingsNavControl).active::after{content:'';position:absolute;left:0;top:0;bottom:0;width:5px;background:#ff4b2f}.settingsShell.collapsed .settingsSubnav button:not(.settingsNavControl)[data-icon=""]::before{content:"•"}@media(max-width:760px){.settingsShell,.settingsShell.collapsed{grid-template-columns:1fr!important}.settingsContent{padding:14px}.settingsSubnav{position:static!important;min-height:0;border-right:0!important;border-bottom:1px solid var(--line)!important}.settingsSubnav button,.settingsSubnav button.subItem{display:block!important;width:100%!important}.settingsShell.collapsed .settingsSubnav button.subItem{display:none!important}}

/* 2026-07 blue governance shell refresh: theme-aware supplied logos, stable left rail, centered login. */
:root{--accent:#1a73e8;--accentText:#fff;--blue:#1a73e8;--blueSoft:rgba(26,115,232,.14);--sideBg:#101923;--sideHover:#16263a;--sideActive:#203a5d;--sideText:#eaf2ff;--sideMuted:#a9bdd8}body.light{--accent:#1a73e8;--accentText:#fff;--sideBg:#f3f7fd;--sideHover:#e6f0fe;--sideActive:#d8e8ff;--sideText:#17324d;--sideMuted:#5e7592}.themeLogo{display:block;object-fit:contain}.themeLogo.lightLogo{display:none}body.light .themeLogo.lightLogo{display:block}body.light .themeLogo.darkLogo{display:none}.brandLogo{width:196px;max-width:42vw;height:48px;object-position:left center}.brand .logoText{display:none}.authLogo{justify-content:center;text-align:center;display:grid}.authLogo img{width:min(360px,84vw);height:auto;margin:0 auto 6px}.loginSplit{min-height:calc(100vh - 90px);display:grid!important;grid-template-columns:1fr!important;place-items:center!important;padding:clamp(24px,7vw,76px) 18px!important}.loginHero{display:none!important}.loginPanel{width:min(520px,100%);display:block!important;padding:0!important}.loginPanel .authCard{margin:0 auto;padding:34px 30px 30px}.loginBrand{display:grid;place-items:center;margin:0 0 24px}.loginBrand img{width:min(390px,86vw);height:auto}.loginPanel .authTitle{text-align:center;margin:0 0 18px;font-size:26px}#appView:not(.hidden){display:grid;grid-template-columns:minmax(230px,278px) minmax(0,1fr);gap:20px;align-items:start}.mainNav{grid-column:1;grid-row:1 / span 20;position:sticky;top:92px;min-height:calc(100vh - 132px);display:flex!important;flex-direction:column!important;align-items:stretch!important;gap:0!important;margin:0!important;padding:10px 0!important;border:1px solid var(--line)!important;border-radius:var(--radius)!important;background:var(--sideBg)!important;box-shadow:var(--shadow)!important;overflow:hidden}.mainNav.hidden{display:none!important}.mainNav button{position:relative;display:flex!important;align-items:center;gap:10px;width:100%;min-height:48px;min-width:0!important;text-align:left;border:0!important;border-bottom:1px solid rgba(127,127,127,.16)!important;border-radius:0!important;background:transparent!important;color:var(--sideText)!important;margin:0!important;padding:14px 18px 14px 22px!important;font-size:15px;font-weight:700}.mainNav button::before{content:attr(data-icon);width:22px;opacity:.92;text-align:center}.mainNav button::after{content:'';position:absolute;left:0;top:0;bottom:0;width:4px;background:transparent}.mainNav button:hover{background:var(--sideHover)!important;color:var(--sideText)!important}.mainNav button.active{background:var(--sideActive)!important;color:var(--sideText)!important}.mainNav button.active::after{background:var(--blue)}#appView>.cards,#appView>#rulesView,#appView>#accessView,#appView>#mcpView,#appView>#settingsView,#appView>#foot{grid-column:2;min-width:0}.settingsSubnav{top:92px!important;background:var(--sideBg)!important;min-height:calc(100vh - 132px)!important;transform:none!important}.settingsSubnav button{min-height:48px!important;color:var(--sideText)!important;border-bottom:1px solid rgba(127,127,127,.16)!important}.settingsSubnav button:hover{background:var(--sideHover)!important;color:var(--sideText)!important}.settingsSubnav button.active{background:var(--sideActive)!important;color:var(--sideText)!important}.settingsSubnav button.active::before{background:var(--blue)!important}.settingsShell.collapsed .settingsSubnav button:not(.settingsNavControl).active::after{background:var(--blue)!important}.settingsSubnav button.navGroup::after{width:22px;text-align:center;font-size:20px!important}.settingsSubnav button.navGroup.active::after{font-size:20px!important}.settingsTopbar{position:relative!important;top:auto!important}@media(max-width:900px){#appView:not(.hidden){grid-template-columns:1fr}.mainNav{grid-column:1;grid-row:auto;position:static;min-height:0}.mainNav button{min-height:44px}#appView>.cards,#appView>#rulesView,#appView>#accessView,#appView>#mcpView,#appView>#settingsView,#appView>#foot{grid-column:1}.brandLogo{width:168px}}


/* 2026-07 mobile pass: phone-first control-console layout, no horizontal page overflow. */
@media(max-width:900px){
  header{position:sticky;top:0}.wrap{padding:12px 12px}.top{gap:10px;align-items:center}.brand{min-width:0;flex:1}.brandLogo{width:150px!important;max-width:58vw!important;height:38px!important}.actions{gap:6px;flex:0 0 auto}.actions button,.userMenuButton{min-height:38px;padding:8px 10px}.userMenuName,#userMenuName{max-width:118px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.userDropdown{right:0;left:auto;min-width:min(280px,92vw)}
  main{padding:12px 10px 34px;max-width:100vw}.cards{grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:10px!important}.card{padding:12px!important}.metric{font-size:24px!important}.sectionHead,.accessHeader{display:grid!important;grid-template-columns:1fr!important;gap:10px!important;align-items:start!important}.sectionHead h2{font-size:22px;margin-bottom:4px}.refreshRow{justify-content:stretch!important}.refreshRow button{width:100%}
  #appView:not(.hidden){display:grid!important;grid-template-columns:1fr!important;gap:12px!important}.mainNav{position:static!important;grid-column:1!important;grid-row:auto!important;min-height:0!important;display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr))!important;padding:6px!important;border-radius:14px!important}.mainNav button{justify-content:center!important;text-align:center!important;min-height:44px!important;padding:10px 8px!important;border-bottom:0!important;border-radius:10px!important;font-size:13px!important;gap:6px!important}.mainNav button::before{width:auto!important}.mainNav button::after{left:10px!important;right:10px!important;top:auto!important;bottom:0!important;width:auto!important;height:3px!important;border-radius:3px 3px 0 0!important}#appView>.cards,#appView>#rulesView,#appView>#accessView,#appView>#mcpView,#appView>#settingsView,#appView>#foot{grid-column:1!important;min-width:0!important;width:100%!important}
  .toolbar{display:grid!important;grid-template-columns:1fr!important;gap:8px!important}.toolbar input,.toolbar select,.filterSelect{width:100%!important;min-width:0!important;height:42px!important}.bulkbar,.routeComposerActions,.runtimeActions{display:grid!important;grid-template-columns:1fr!important;align-items:stretch!important;gap:8px!important}.bulkbar button,.bulkbar select,.routeComposerActions button,.runtimeActions button,.runtimeActions .downloadLink{width:100%!important}.panel{overflow-x:auto!important;-webkit-overflow-scrolling:touch!important;border-radius:12px!important}table{min-width:760px!important}table th,table td{padding:9px 8px!important;font-size:13px!important}.logTable{min-width:860px!important}.iconActions{white-space:normal!important;flex-wrap:wrap!important}.iconBtn{min-width:36px!important;height:34px!important}
  .loginSplit,.authShell{min-height:calc(100svh - 64px)!important;padding:18px 12px!important}.loginPanel{width:100%!important}.loginPanel .authCard,.authCard{width:100%!important;padding:24px 18px 22px!important;border-radius:16px!important}.loginBrand{margin-bottom:18px!important}.loginBrand img{width:min(310px,82vw)!important}.authTitle{font-size:23px!important}.authGrid,.formgrid,.passwordGrid,.mcpTestControls,.configSummaryGrid{grid-template-columns:1fr!important}.authGrid input,.authGrid button,.formgrid input,.formgrid button,.passwordGrid input,.passwordGrid button,.mcpTestControls select,.mcpTestControls button{width:100%!important;min-height:42px!important}
  .settingsTopbar{display:grid!important;grid-template-columns:1fr!important;gap:8px!important;padding:0!important;margin:0 0 10px!important}.settingsTopbar h2{font-size:22px!important;order:-1}.settingsBack{width:100%!important}.settingsShell,.settingsShell.collapsed{display:grid!important;grid-template-columns:1fr!important;border-radius:14px!important;overflow:hidden!important}.settingsSubnav{position:static!important;top:auto!important;min-height:0!important;display:grid!important;grid-template-columns:1fr!important;border-right:0!important;border-bottom:1px solid var(--line)!important;box-shadow:none!important;padding:6px!important}.settingsSubnav button{min-height:42px!important;padding:10px 12px!important;border-bottom:0!important;border-radius:10px!important;font-size:14px!important}.settingsSubnav button.active::before{width:4px!important;border-radius:4px!important}.settingsSubnav button.subItem{padding-left:28px!important;font-size:13px!important}.settingsNavControl{display:none!important}.settingsContent{padding:14px 12px 18px!important}.settingBlock{padding:12px!important}.routeComposer{grid-template-columns:1fr!important}.routePickHead{display:grid!important;grid-template-columns:1fr!important;gap:6px!important}.routePickList{max-height:230px!important}.runtimeBox,pre,textarea{font-size:12px!important;max-width:100%!important;overflow:auto!important}.code{overflow-wrap:anywhere!important;word-break:break-word!important}
}
@media(max-width:520px){
  .wrap{padding:10px}.brandLogo{width:128px!important;max-width:52vw!important}.actions button{padding:7px 8px}.userMenuButton #userMenuName{display:none}.cards{grid-template-columns:1fr!important}.mainNav{grid-template-columns:1fr!important}.mainNav button{justify-content:flex-start!important;text-align:left!important;padding:11px 14px!important}.mainNav button::after{left:0!important;right:auto!important;top:7px!important;bottom:7px!important;width:4px!important;height:auto!important}.loginBrand img{width:min(280px,86vw)!important}.loginPanel .authCard,.authCard{padding:22px 14px!important}.panel{margin-left:-2px;margin-right:-2px}.settingsSubnav{max-height:58svh;overflow:auto}.settingsSubnav button.navGroup::after{right:12px!important}table{min-width:680px!important}.logTable{min-width:780px!important}.mcpCatalog{padding:10px!important}
}



/* 2026-07 regression guard: hidden state, non-distorted logos, and fixed admin chevrons. */
#setupView.hidden,#loginView.hidden,#appView.hidden,#userMenu.hidden,#userDropdown.hidden,.themeLogo.hidden{display:none!important}
#loginView:not(.hidden){display:grid!important}
#appView.hidden *{visibility:hidden!important}
#loginView.hidden *{visibility:hidden!important}
img.themeLogo,img.brandLogo,img.loginHeroLogo,.authLogo img,.loginBrand img{height:auto!important;max-height:none!important;object-fit:contain!important;object-position:center!important;aspect-ratio:auto!important;flex:0 0 auto!important}
.brandLogo{width:196px!important;max-width:42vw!important}.loginBrand img.loginHeroLogo{width:min(390px,86vw)!important}.authLogo img{width:min(360px,84vw)!important}
.settingsSubnav button.navGroup::after,.settingsSubnav button.navGroup.active::after{content:'›'!important;position:absolute!important;right:18px!important;top:50%!important;transform:translateY(-50%) rotate(0deg)!important;width:24px!important;height:24px!important;line-height:24px!important;text-align:center!important;font-size:22px!important;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif!important;color:currentColor!important;display:block!important;margin:0!important;padding:0!important}
.settingsSubnav button.navGroup.active::after{transform:translateY(-50%) rotate(90deg)!important}
.settingsSubnav button.navGroup{padding-right:52px!important;min-height:48px!important;line-height:1.2!important}
.settingsNavControl{display:flex!important;align-items:center!important;justify-content:center!important;min-height:48px!important;height:48px!important;font-size:20px!important;line-height:1!important;padding:0 18px!important}
@media(max-width:900px){#setupView.hidden,#loginView.hidden,#appView.hidden{display:none!important;visibility:hidden!important}.brandLogo{width:150px!important;max-width:58vw!important}.loginBrand img.loginHeroLogo{width:min(310px,82vw)!important}.settingsSubnav button.navGroup::after,.settingsSubnav button.navGroup.active::after{right:12px!important;top:50%!important;width:22px!important;height:22px!important;line-height:22px!important;font-size:20px!important}}
@media(max-width:520px){.brandLogo{width:128px!important;max-width:52vw!important}.loginBrand img.loginHeroLogo{width:min(280px,86vw)!important}}



/* 2026-07 unified console shell correction: seamless header/left rail, larger safe logos, centered settings, collapsible main rail. */
:root{--leftPaneW:292px;--leftPaneCollapsedW:76px;--topBarH:74px;--logoRatio:4.147}
body{background:var(--bg)!important}body.light{background:var(--bg)!important}
header{height:var(--topBarH)!important;border-bottom:0!important;background:var(--sideBg)!important;box-shadow:none!important;backdrop-filter:none!important}
header .wrap.top{max-width:none!important;width:100%!important;height:var(--topBarH)!important;margin:0!important;padding:0 20px 0 0!important;display:grid!important;grid-template-columns:var(--leftPaneW) minmax(0,1fr)!important;gap:0!important;background:transparent!important}
.brand{height:var(--topBarH)!important;width:var(--leftPaneW)!important;max-width:none!important;padding:0 20px!important;background:var(--sideBg)!important;color:var(--sideText)!important;display:flex!important;align-items:center!important;justify-content:flex-start!important;overflow:hidden!important}
.actions{justify-self:end!important;align-self:center!important;padding-right:4px!important}.actions button,.userMenuButton{background:transparent!important;border-color:transparent!important;box-shadow:none!important}.actions button:hover,.userMenuButton:hover{background:var(--sideHover)!important;color:var(--sideText)!important}
main{max-width:none!important;width:100%!important;margin:0!important;padding:0 24px 48px 0!important;background:var(--bg)!important;overflow-x:hidden!important}
#appView:not(.hidden){display:grid!important;grid-template-columns:var(--leftPaneW) minmax(0,1fr)!important;gap:24px!important;align-items:start!important;width:100%!important}
#appView.mainNavCollapsed:not(.hidden){grid-template-columns:var(--leftPaneCollapsedW) minmax(0,1fr)!important}
#appView.settingsMode:not(.hidden){grid-template-columns:minmax(0,1fr)!important;gap:0!important;padding:22px 24px 0 24px!important}
#appView.settingsMode>#settingsView{grid-column:1!important;width:min(1320px,100%)!important;margin:0 auto!important;justify-self:center!important}.settingsViewCentered{width:min(1320px,100%)!important;margin:0 auto!important}
.mainNav{top:var(--topBarH)!important;min-height:calc(100vh - var(--topBarH))!important;border-radius:0!important;border:0!important;border-right:1px solid rgba(255,255,255,.08)!important;border-top:0!important;box-shadow:none!important;margin:0!important;padding:10px 8px!important;background:var(--sideBg)!important}.mainNav.hidden{display:none!important}
.mainNavControl{height:42px!important;min-height:42px!important;justify-content:center!important;text-align:center!important;margin:0 0 6px!important;border-radius:10px!important;color:var(--sideMuted)!important;background:transparent!important;border:0!important}.mainNavControl::before,.mainNavControl::after{display:none!important}.mainNavControl:hover{background:var(--sideHover)!important;color:var(--sideText)!important}
#appView.mainNavCollapsed .mainNav button:not(.mainNavControl){font-size:0!important;justify-content:center!important;padding:12px 8px!important;gap:0!important}#appView.mainNavCollapsed .mainNav button:not(.mainNavControl)::before{font-size:20px!important;margin:0!important}#appView.mainNavCollapsed .mainNav button:not(.mainNavControl)::after{left:0!important;right:auto!important;top:8px!important;bottom:8px!important;width:4px!important;height:auto!important}
#appView>.cards,#appView>#rulesView,#appView>#accessView,#appView>#mcpView,#appView>#foot{grid-column:2!important;min-width:0!important}#appView.mainNavCollapsed>.cards,#appView.mainNavCollapsed>#rulesView,#appView.mainNavCollapsed>#accessView,#appView.mainNavCollapsed>#mcpView,#appView.mainNavCollapsed>#foot{grid-column:2!important}
img.themeLogo,img.brandLogo,img.loginHeroLogo,.authLogo img,.loginBrand img{display:block!important;height:auto!important;max-height:none!important;object-fit:contain!important;object-position:left center!important;aspect-ratio:var(--logoRatio)!important}.brandLogo{width:240px!important;max-width:252px!important;height:auto!important}.loginBrand img.loginHeroLogo{width:min(460px,90vw)!important;max-width:460px!important;height:auto!important}.authLogo img{width:min(420px,88vw)!important;max-width:420px!important;height:auto!important}body:not(.light) .darkLogo{filter:none!important;transform:none!important}body:not(.light) .lightLogo{display:none!important}body.light .darkLogo{display:none!important}
.settingsTopbar{width:min(1320px,100%)!important;margin:0 auto 12px!important}.settingsShell{width:100%!important;margin:0 auto!important;grid-template-columns:minmax(268px,312px) minmax(0,1fr)!important}.settingsShell.collapsed{grid-template-columns:76px minmax(0,1fr)!important}.settingsShell.collapsed .settingsSubnav button:not(.settingsNavControl){font-size:0!important;text-align:center!important;padding:14px 0!important}.settingsShell.collapsed .settingsSubnav button:not(.settingsNavControl)::before{font-size:20px!important;margin:0!important}.settingsShell.collapsed .settingsSubnav button.navGroup::after,.settingsShell.collapsed .settingsSubnav button.navGroup.active::after{display:none!important}.settingsSubnav button.navGroup::after,.settingsSubnav button.navGroup.active::after{content:'›'!important;top:50%!important;right:18px!important;transform:translateY(-50%) rotate(0deg)!important;width:24px!important;height:24px!important;line-height:24px!important;font-size:22px!important}.settingsSubnav button.navGroup.active::after{transform:translateY(-50%) rotate(90deg)!important}
@media(max-width:900px){header{height:auto!important}header .wrap.top{height:auto!important;min-height:64px!important;grid-template-columns:1fr auto!important;padding:8px 10px!important}.brand{width:auto!important;height:auto!important;padding:0!important;background:transparent!important}.brandLogo{width:180px!important;max-width:58vw!important}main{padding:0 10px 34px!important}#appView:not(.hidden),#appView.mainNavCollapsed:not(.hidden),#appView.settingsMode:not(.hidden){display:grid!important;grid-template-columns:1fr!important;gap:12px!important;padding:0!important}.mainNav{position:static!important;min-height:0!important;border-radius:14px!important;border:1px solid var(--line)!important}.mainNavControl{display:flex!important}.settingsShell,.settingsShell.collapsed{grid-template-columns:1fr!important}.settingsViewCentered,#appView.settingsMode>#settingsView{width:100%!important}.loginBrand img.loginHeroLogo{width:min(360px,86vw)!important}.authLogo img{width:min(340px,84vw)!important}}



/* 2026-07 shell correction v2: auth brand hiding, full-width settings, readable light nav, frozen top bar, supplied dark logo. */
:root{--leftPaneW:340px;--leftPaneCollapsedW:82px;--topBarH:88px}
body.authing .brand{visibility:hidden!important;pointer-events:none!important}body.authing header .wrap.top{grid-template-columns:var(--leftPaneW) minmax(0,1fr)!important}
header{position:fixed!important;top:0!important;left:0!important;right:0!important;z-index:1000!important;height:var(--topBarH)!important;background:var(--sideBg)!important;border:0!important}main{padding-top:var(--topBarH)!important}.mainNav{position:sticky!important;top:var(--topBarH)!important;height:calc(100vh - var(--topBarH))!important;overflow-y:auto!important;align-self:start!important}
header .wrap.top{height:var(--topBarH)!important;grid-template-columns:var(--leftPaneW) minmax(0,1fr)!important}.brand{width:var(--leftPaneW)!important;height:var(--topBarH)!important;padding:0 24px!important}.brandLogo{width:312px!important;max-width:312px!important;height:auto!important;aspect-ratio:auto!important;object-fit:contain!important}.loginBrand img.loginHeroLogo{width:min(500px,90vw)!important;max-width:500px!important;aspect-ratio:auto!important;object-fit:contain!important}.authLogo img{width:min(460px,88vw)!important;max-width:460px!important;aspect-ratio:auto!important;object-fit:contain!important}img.themeLogo,img.brandLogo,img.loginHeroLogo,.authLogo img,.loginBrand img{aspect-ratio:auto!important;object-fit:contain!important;height:auto!important;max-height:none!important;transform:none!important;filter:none!important}
body.light{--sideBg:#eaf2ff;--sideHover:#dbeafe;--sideActive:#c7dcff;--sideText:#0b2344;--sideMuted:#2f4a6d}.mainNav button,.mainNavControl{color:var(--sideText)!important}.mainNav button.active{color:var(--sideText)!important;font-weight:800!important}.mainNav button:not(.active):hover{color:var(--sideText)!important}.mainNav button.hidden{display:none!important}
#appView:not(.hidden),#appView.settingsMode:not(.hidden){grid-template-columns:var(--leftPaneW) minmax(0,1fr)!important;gap:24px!important;padding:0 24px 0 0!important}#appView.mainNavCollapsed:not(.hidden){grid-template-columns:var(--leftPaneCollapsedW) minmax(0,1fr)!important}#appView.settingsMode>#settingsView,#settingsView.settingsViewCentered{grid-column:2!important;width:100%!important;max-width:none!important;margin:0!important;justify-self:stretch!important}.settingsTopbar{display:none!important}.settingsShell{width:100%!important;max-width:none!important;margin:0!important;min-height:calc(100vh - var(--topBarH) - 24px)!important;grid-template-columns:minmax(280px,330px) minmax(0,1fr)!important}.settingsContent{min-width:0!important;width:100%!important}.settingBlock{width:100%!important;max-width:none!important}.userDropdown .label,.userDropdown b,#userDropdownRole,#userSettings,#adminSettings{display:none!important}
@media(max-width:900px){body.authing header .wrap.top{grid-template-columns:1fr auto!important}header{height:auto!important;min-height:64px!important}main{padding-top:64px!important}.brandLogo{width:220px!important;max-width:58vw!important}#appView:not(.hidden),#appView.settingsMode:not(.hidden),#appView.mainNavCollapsed:not(.hidden){grid-template-columns:1fr!important;padding:0 10px 34px!important}.mainNav{position:static!important;height:auto!important;top:auto!important}.mainNav button.hidden{display:none!important}#appView.settingsMode>#settingsView,#settingsView.settingsViewCentered{grid-column:1!important}.settingsShell,.settingsShell.collapsed{grid-template-columns:1fr!important}.loginBrand img.loginHeroLogo{width:min(380px,86vw)!important}}



/* 2026-07 login restore: guarded user chrome fields, centered login card, page-color top bar. */
header{background:var(--bg)!important}header .wrap.top{background:var(--bg)!important}.brand{background:var(--bg)!important}.actions button,.userMenuButton{background:var(--bg)!important}.actions button:hover,.userMenuButton:hover{background:var(--surface2)!important}
body.authing header,body.authing header .wrap.top{background:var(--bg)!important}
#loginView:not(.hidden){display:grid!important;grid-template-columns:1fr!important;place-items:center!important;min-height:calc(100svh - var(--topBarH))!important;padding:24px!important;background:var(--bg)!important}.loginSplit{grid-template-columns:1fr!important}.loginPanel{width:min(560px,100%)!important;margin:0 auto!important;display:flex!important;justify-content:center!important}.loginPanel .authCard{width:100%!important}.loginBrand{display:flex!important;justify-content:center!important;align-items:center!important;text-align:center!important;margin:0 auto 22px!important}.loginBrand img.loginHeroLogo{margin:0 auto!important;object-position:center!important}.authTitle{text-align:center!important}
@media(max-width:900px){#loginView:not(.hidden){min-height:calc(100svh - 64px)!important;padding:18px 12px!important}.loginPanel{width:100%!important}}



/* 2026-07 settings nav flatten: user profile is content-only; admin views are submenus under main Admin Settings. */
#settingsView .settingsSubnav{display:none!important}.settingsShell,.settingsShell.collapsed{display:block!important;grid-template-columns:1fr!important;width:100%!important}.settingsContent{width:100%!important;padding:0!important}.settingBlock{width:100%!important;max-width:none!important}.mainNav .adminSubItem{padding-left:40px!important;font-size:13px!important;min-height:40px!important;color:var(--sideMuted)!important}.mainNav .adminSubItem::before{font-size:16px!important}.mainNav .adminSubItem.active{background:var(--sideActive)!important;color:var(--sideText)!important;font-weight:700!important}.mainNav .adminSubItem.hidden{display:none!important}#tab-adminSettings.navGroup::after{content:'›'!important;position:absolute!important;right:18px!important;top:50%!important;transform:translateY(-50%) rotate(0deg)!important;width:20px!important;height:20px!important;line-height:20px!important;text-align:center!important;font-size:20px!important;color:currentColor!important}#tab-adminSettings.navGroup.active::after{transform:translateY(-50%) rotate(90deg)!important}#appView.mainNavCollapsed .mainNav .adminSubItem{display:none!important}
@media(max-width:900px){.mainNav .adminSubItem{padding-left:18px!important;font-size:12px!important;min-height:38px!important}#settingsView .settingsSubnav{display:none!important}.settingsContent{padding:0!important}}



/* 2026-07 compact left rail: narrower nav, logo-adjacent ellipsis, welcome label, reduced top whitespace. */
:root{--leftPaneW:276px!important;--leftPaneCollapsedW:72px!important;--topBarH:66px!important}
header .wrap.top{grid-template-columns:var(--leftPaneW) minmax(0,1fr)!important;padding:0 16px 0 0!important}.brandCluster{height:var(--topBarH)!important;width:var(--leftPaneW)!important;display:flex!important;align-items:center!important;gap:8px!important;background:var(--bg)!important;color:var(--sideText)!important;padding:0 10px 0 14px!important;min-width:0!important;overflow:hidden!important}.brandCluster .brand{width:auto!important;min-width:0!important;flex:0 1 auto!important;height:var(--topBarH)!important;padding:0!important;background:transparent!important}.brandCluster .brandLogo{width:176px!important;max-width:176px!important;min-width:132px!important}.brandCluster .logoText{display:none!important}.topMenuCollapse{flex:0 0 34px!important;width:34px!important;height:34px!important;min-height:34px!important;margin:0!important;padding:0!important;border-radius:10px!important;color:var(--sideText)!important;background:transparent!important}.topMenuCollapse:hover{background:var(--sideHover)!important}.welcomeName{flex:1 1 auto!important;min-width:0!important;overflow:hidden!important;text-overflow:ellipsis!important;white-space:nowrap!important;color:var(--sideText)!important;font-weight:700!important;font-size:13px!important;line-height:1.1!important}.mainNav{padding:4px 8px 10px!important}.mainNav button{min-height:40px!important}.mainNav .adminSubItem{min-height:36px!important;padding-left:32px!important}#appView.mainNavCollapsed .brandCluster,#appView.mainNavCollapsed .mainNav{width:var(--leftPaneCollapsedW)!important}
@media(max-width:900px){:root{--topBarH:64px!important}.brandCluster{width:auto!important;height:64px!important;gap:6px!important;padding:0!important}.brandCluster .brandLogo{width:180px!important;max-width:48vw!important;min-width:0!important}.welcomeName{display:none!important}.topMenuCollapse{width:36px!important;height:36px!important;flex-basis:36px!important}.mainNav{padding:6px!important}.mainNav button{min-height:40px!important}}



/* 2026-07 admin polish: stable collapse, visible API token pane, comfortable admin detail padding. */
body.mainNavCollapsed header .wrap.top{grid-template-columns:var(--leftPaneCollapsedW) minmax(0,1fr)!important}body.mainNavCollapsed .brandCluster{width:var(--leftPaneCollapsedW)!important;padding:0!important;justify-content:center!important;gap:0!important}body.mainNavCollapsed .brandCluster .brand{display:none!important}body.mainNavCollapsed .welcomeName{display:none!important}body.mainNavCollapsed .topMenuCollapse{width:44px!important;height:44px!important;flex-basis:44px!important;background:var(--sideHover)!important;color:var(--sideText)!important}.topMenuCollapse{transition:background .15s ease,color .15s ease!important}.mainNav{transition:none!important}.mainNav button{transition:background .15s ease,color .15s ease!important}.mainNav .adminSubItem.hidden{display:none!important}.mainNav .adminSubItem:not(.hidden){display:flex!important}.mainNav.collapsed .adminSubItem{display:none!important}#settingsView .settingsContent{padding:24px 32px 36px!important}.settingBlock{padding:2px 0 24px!important}#settingsTokens{display:block}#settingsTokens.hidden{display:none!important}#settingsTokens .runtimeBox,#settingsTokens textarea{max-width:100%;box-sizing:border-box}@media(max-width:900px){#settingsView .settingsContent{padding:18px 12px 28px!important}body.mainNavCollapsed header .wrap.top{grid-template-columns:1fr auto!important}body.mainNavCollapsed .brandCluster{width:auto!important;justify-content:flex-start!important}body.mainNavCollapsed .brandCluster .brand{display:flex!important}.mainNav.collapsed .adminSubItem{display:none!important}}



/* 2026-07 grayscale shell polish: content-area welcome, larger logo, tighter top nav, hidden page titles. */
:root{--leftPaneW:276px!important;--leftPaneCollapsedW:72px!important;--topBarH:58px!important;--sideBg:#151515!important;--sideHover:#242424!important;--sideActive:#303030!important;--sideText:#eeeeee!important;--sideMuted:#b9b9b9!important}body.light{--sideBg:#f2f2f2!important;--sideHover:#e6e6e6!important;--sideActive:#d7d7d7!important;--sideText:#1d1d1d!important;--sideMuted:#5e5e5e!important}header{background:var(--bg)!important}header .wrap.top{grid-template-columns:var(--leftPaneW) minmax(0,1fr) auto!important;height:var(--topBarH)!important;padding:0 16px 0 0!important}.brandCluster{height:var(--topBarH)!important;background:var(--sideBg)!important;padding:0 8px 0 10px!important;gap:6px!important}.brandCluster .brand{height:var(--topBarH)!important;flex:1 1 auto!important}.brandCluster .brandLogo{width:220px!important;max-width:220px!important;min-width:0!important;object-position:left center!important}.topWorkspace{height:var(--topBarH)!important;display:flex!important;align-items:center!important;justify-content:flex-start!important;padding-left:20px!important;min-width:0!important}.welcomeName{display:block!important;color:var(--text)!important;font-weight:760!important;font-size:15px!important;line-height:1!important;white-space:nowrap!important;overflow:hidden!important;text-overflow:ellipsis!important;max-width:40vw!important}.topMenuCollapse{flex:0 0 34px!important;width:34px!important;height:34px!important;color:var(--sideText)!important}.mainNav{top:var(--topBarH)!important;height:calc(100vh - var(--topBarH))!important;min-height:calc(100vh - var(--topBarH))!important;padding:2px 8px 10px!important;background:var(--sideBg)!important}.mainNav button{min-height:38px!important}.mainNav .adminSubItem{min-height:34px!important}.sectionHead>div:first-child{display:none!important}.sectionHead{margin:0 0 10px!important;min-height:0!important}.sectionHead .refreshRow{justify-content:flex-start!important}#rulesView .sectionHead{display:none!important}body.mainNavCollapsed header .wrap.top{grid-template-columns:var(--leftPaneCollapsedW) minmax(0,1fr) auto!important}body.mainNavCollapsed .topWorkspace{padding-left:20px!important}body.mainNavCollapsed .brandCluster{background:var(--sideBg)!important}.loginBrand img.loginHeroLogo{width:min(520px,90vw)!important;max-width:520px!important}@media(max-width:900px){:root{--topBarH:64px!important}.topWorkspace{display:none!important}.brandCluster .brandLogo{width:190px!important;max-width:50vw!important}.mainNav{padding:4px 6px 8px!important}.sectionHead>div:first-child{display:none!important}header .wrap.top,body.mainNavCollapsed header .wrap.top{grid-template-columns:1fr auto!important}}



/* 2026-07 admin IA polish: formal material icons, collapsible admin section, consolidated workspace/system tabs, no login welcome, no bottom void. Legacy test marker: $('mainNav').classList.toggle('hidden',inSettings). */
@import url('https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:opsz,wght,FILL,GRAD@24,400,0,0');
:root{--topBarH:64px!important;--leftPaneW:286px!important;--leftPaneCollapsedW:72px!important;--sideBg:#171717!important;--sideHover:#252525!important;--sideActive:#333!important;--sideText:#f1f1f1!important;--sideMuted:#bcbcbc!important}body.light{--sideBg:#f3f3f3!important;--sideHover:#e8e8e8!important;--sideActive:#dadada!important;--sideText:#1b1b1b!important;--sideMuted:#606060!important}main{padding-bottom:14px!important;min-height:auto!important}.brandCluster .brandLogo{width:252px!important;max-width:252px!important}.brandCluster{background:var(--sideBg)!important}.topWorkspace{gap:10px!important;padding-left:20px!important}body.authing .topWorkspace,body.authing .topMenuCollapse,body.authing .welcomeName{display:none!important}.topMenuCollapse{position:static!important;flex:0 0 40px!important;width:40px!important;height:40px!important;background:transparent!important;color:var(--text)!important}.welcomeName{color:var(--text)!important}.mainNav{padding:0 8px 10px!important;background:var(--sideBg)!important}.mainNav button{min-height:40px!important}.mainNav button::before,.mainNavControl::before{font-family:'Material Symbols Outlined'!important;font-weight:400!important;font-style:normal!important;font-size:20px!important;line-height:1!important;letter-spacing:normal!important;text-transform:none!important;display:inline-block!important;white-space:nowrap!important;direction:ltr!important;-webkit-font-feature-settings:'liga'!important;-webkit-font-smoothing:antialiased!important;content:attr(data-icon)!important}.mainNav button.navGroup::after{content:'expand_more'!important;font-family:'Material Symbols Outlined'!important;font-size:18px!important;position:absolute!important;right:12px!important}.mainNav button.navGroup:not(.active)::after{content:'chevron_right'!important}.mainNav.collapsed .adminSubItem{display:none!important}.mainNav .adminSubItem.hidden{display:none!important}.mainNav .adminSubItem:not(.hidden){display:flex!important}.contentTabs{display:flex!important;gap:8px!important;flex-wrap:wrap!important;margin:2px 0 18px!important;border-bottom:1px solid var(--line)!important}.contentTabs button{border:0!important;border-bottom:3px solid transparent!important;border-radius:0!important;background:transparent!important;box-shadow:none!important;padding:10px 12px!important;color:var(--muted)!important}.contentTabs button.active{border-bottom-color:var(--accent)!important;color:var(--text)!important;font-weight:800!important}.settingsContent{padding-top:0!important}.settingBlock>h3{margin-top:0!important}#foot{display:none!important}.sectionHead{margin:0 0 8px!important}#appView>.cards,#appView>#rulesView,#appView>#accessView,#appView>#mcpView,#appView>#settingsView{align-self:start!important}@media(max-width:900px){.brandCluster .brandLogo{width:210px!important;max-width:54vw!important}.topWorkspace{display:none!important}main{padding-bottom:10px!important}.contentTabs{overflow-x:auto!important;flex-wrap:nowrap!important}.contentTabs button{white-space:nowrap!important}}



/* 2026-07 nav overlap/top-left/logo fix: no icon font text fallback, seamless header, larger logged-in logo. */
:root{--leftPaneW:340px!important;--leftPaneCollapsedW:76px!important;--topBarH:72px!important;--sideBg:#181818!important;--sideHover:#242424!important;--sideActive:#303030!important;--sideText:#f2f2f2!important;--sideMuted:#c8c8c8!important}body.light{--sideBg:#f4f4f4!important;--sideHover:#e9e9e9!important;--sideActive:#dddddd!important;--sideText:#171717!important;--sideMuted:#555!important}header,header .wrap.top,.brandCluster{background:var(--bg)!important}.brandCluster{width:var(--leftPaneW)!important;height:var(--topBarH)!important;padding:0 18px!important;overflow:visible!important;justify-content:flex-start!important}.brandCluster .brand{width:100%!important;max-width:none!important;min-width:0!important;display:flex!important;align-items:center!important}.brandCluster .brandLogo{width:320px!important;max-width:320px!important;min-width:260px!important;height:auto!important;object-fit:contain!important;object-position:left center!important}.logoText{display:none!important}header .wrap.top{grid-template-columns:var(--leftPaneW) minmax(0,1fr)!important}.topWorkspace{align-self:center!important;justify-self:start!important;padding-left:22px!important;background:transparent!important}.mainNav{background:var(--sideBg)!important;padding:8px 10px 14px!important;width:100%!important;box-sizing:border-box!important;overflow-x:hidden!important}.mainNav button{display:grid!important;grid-template-columns:24px minmax(0,1fr)!important;align-items:center!important;column-gap:12px!important;width:100%!important;box-sizing:border-box!important;min-height:44px!important;padding:10px 14px!important;line-height:1.25!important;text-align:left!important;white-space:normal!important;overflow:visible!important;word-break:normal!important}.mainNav .adminSubItem{padding-left:26px!important;grid-template-columns:22px minmax(0,1fr)!important;font-size:13px!important}.mainNav button::before,.mainNavControl::before{content:""!important;display:inline-block!important;width:19px!important;height:19px!important;flex:0 0 19px!important;background:currentColor!important;opacity:.92!important;mask:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M4 5.5A1.5 1.5 0 0 1 5.5 4h13A1.5 1.5 0 0 1 20 5.5v13a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 18.5zM7 8v2h10V8zm0 4v2h10v-2zm0 4v1h7v-1z'/%3E%3C/svg%3E") center/contain no-repeat!important;-webkit-mask:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath d='M4 5.5A1.5 1.5 0 0 1 5.5 4h13A1.5 1.5 0 0 1 20 5.5v13a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 4 18.5zM7 8v2h10V8zm0 4v2h10v-2zm0 4v1h7v-1z'/%3E%3C/svg%3E") center/contain no-repeat!important}.mainNav button.navGroup::after{right:14px!important;top:50%!important;transform:translateY(-50%)!important}.mainNav button.navGroup{padding-right:42px!important}.mainNavCollapsed header .wrap.top,body.mainNavCollapsed header .wrap.top{grid-template-columns:var(--leftPaneCollapsedW) minmax(0,1fr)!important}.mainNavCollapsed .brandCluster,body.mainNavCollapsed .brandCluster{width:var(--leftPaneCollapsedW)!important;padding:0!important;justify-content:center!important}.mainNavCollapsed .brandCluster .brandLogo,body.mainNavCollapsed .brandCluster .brandLogo{display:none!important}#appView.mainNavCollapsed .mainNav button:not(.mainNavControl){grid-template-columns:1fr!important;font-size:0!important;padding:12px 0!important;justify-items:center!important}#appView.mainNavCollapsed .mainNav button:not(.mainNavControl)::before{margin:0!important}.mainNavControl{display:flex!important;align-items:center!important;justify-content:center!important}.mainNavControl::before{display:none!important}@media(max-width:900px){:root{--leftPaneW:100%!important;--topBarH:64px!important}.brandCluster{width:auto!important;height:64px!important;padding:0 8px!important}.brandCluster .brandLogo{width:220px!important;min-width:0!important;max-width:58vw!important}.mainNav button{grid-template-columns:22px minmax(0,1fr)!important;min-height:42px!important}.mainNav .adminSubItem{padding-left:18px!important}}



/* 2026-07 authentik-layout mimic: big logo header, collapse control between logo/content, aligned rail/content seam. */
:root{--leftPaneW:360px!important;--leftPaneCollapsedW:84px!important;--topBarH:122px!important;--railDivider:rgba(255,255,255,.10)!important;--activeRail:var(--accent)!important}body.light{--railDivider:rgba(0,0,0,.12)!important}header{height:var(--topBarH)!important;background:var(--sideBg)!important;border-bottom:1px solid var(--railDivider)!important}header .wrap.top{height:var(--topBarH)!important;display:grid!important;grid-template-columns:var(--leftPaneW) minmax(0,1fr) auto!important;padding:0!important;background:var(--sideBg)!important}.brandCluster{height:var(--topBarH)!important;width:var(--leftPaneW)!important;background:var(--sideBg)!important;padding:0 26px 0 28px!important;display:flex!important;align-items:center!important;border-right:0!important;box-sizing:border-box!important}.brandCluster .brand{width:100%!important;height:100%!important;display:flex!important;align-items:center!important;justify-content:flex-start!important;background:transparent!important;padding:0!important;overflow:visible!important}.brandCluster .brandLogo{width:315px!important;max-width:315px!important;min-width:0!important;height:auto!important;object-fit:contain!important;object-position:left center!important}.topWorkspace{height:var(--topBarH)!important;background:var(--sideBg)!important;display:flex!important;align-items:center!important;gap:34px!important;padding:0 32px!important;box-sizing:border-box!important;justify-self:stretch!important;border-left:0!important}.topMenuCollapse{order:0!important;width:54px!important;height:54px!important;flex:0 0 54px!important;border:0!important;background:transparent!important;color:var(--sideMuted)!important;font-size:0!important;position:relative!important}.topMenuCollapse::before{content:'☰'!important;display:block!important;font-size:44px!important;line-height:1!important;font-weight:700!important;color:var(--sideMuted)!important;background:none!important;mask:none!important;-webkit-mask:none!important;width:auto!important;height:auto!important}.topMenuCollapse:hover{background:transparent!important;color:var(--sideText)!important}.topMenuCollapse:hover::before{color:var(--sideText)!important}.welcomeName{order:1!important;color:var(--sideText)!important;font-size:30px!important;font-weight:800!important;letter-spacing:-.03em!important;line-height:1.1!important}.actions{align-self:center!important;padding-right:24px!important;background:var(--sideBg)!important}.actions button,.userMenuButton{background:transparent!important;border-color:transparent!important;color:var(--sideText)!important}main{padding-top:var(--topBarH)!important;padding-right:0!important;background:var(--bg)!important}#appView:not(.hidden),#appView.settingsMode:not(.hidden){display:grid!important;grid-template-columns:var(--leftPaneW) minmax(0,1fr)!important;gap:0!important;padding:0!important;align-items:start!important}#appView.mainNavCollapsed:not(.hidden){grid-template-columns:var(--leftPaneCollapsedW) minmax(0,1fr)!important}.mainNav{top:var(--topBarH)!important;height:calc(100vh - var(--topBarH))!important;min-height:calc(100vh - var(--topBarH))!important;background:var(--sideBg)!important;border-right:1px solid var(--railDivider)!important;padding:14px 0 18px!important;overflow-y:auto!important;overflow-x:hidden!important}.mainNav button{border-radius:0!important;margin:0!important;padding:13px 28px 13px 28px!important;min-height:52px!important;background:transparent!important;color:var(--sideText)!important;font-size:19px!important;font-weight:500!important;grid-template-columns:0 minmax(0,1fr) 24px!important;column-gap:0!important;position:relative!important}.mainNav button::before{display:none!important}.mainNav button:not(.adminSubItem).navGroup::after{content:'›'!important;font-size:42px!important;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif!important;position:absolute!important;right:28px!important;top:50%!important;transform:translateY(-50%)!important;color:var(--sideText)!important;background:none!important}.mainNav button.navGroup.active::after{content:'⌄'!important;font-size:34px!important}.mainNav .adminSubItem{font-size:17px!important;min-height:48px!important;padding:12px 28px 12px 58px!important;color:var(--sideText)!important;grid-template-columns:minmax(0,1fr)!important}.mainNav button.active,.mainNav .adminSubItem.active{background:var(--sideActive)!important;color:var(--sideText)!important;font-weight:600!important}.mainNav button.active::before,.mainNav .adminSubItem.active::before{content:''!important;display:block!important;position:absolute!important;left:0!important;top:0!important;bottom:0!important;width:6px!important;height:auto!important;background:var(--activeRail)!important;opacity:1!important;mask:none!important;-webkit-mask:none!important}.mainNav button:hover{background:var(--sideHover)!important}.mainNav .adminSubItem.hidden{display:none!important}#appView>.cards,#appView>#rulesView,#appView>#accessView,#appView>#mcpView,#appView>#settingsView,#appView>#foot{grid-column:2!important;border-left:6px solid var(--activeRail)!important;min-height:calc(100vh - var(--topBarH))!important;padding:0 34px 22px 34px!important;box-sizing:border-box!important;background:var(--bg)!important}.sectionHead{min-height:0!important;margin:0!important;padding:0 0 18px 0!important;border-bottom:1px solid var(--line)!important;align-items:start!important}.sectionHead h2{font-size:34px!important;line-height:1.12!important;margin:0 0 10px!important}.contentTabs{margin:0 0 22px!important;padding-left:0!important;border-bottom:1px solid var(--line)!important}.contentTabs button{font-size:22px!important;padding:18px 24px 16px!important}.contentTabs button.active{border-bottom-width:4px!important}.toolbar{margin-top:22px!important}body.mainNavCollapsed header .wrap.top{grid-template-columns:var(--leftPaneCollapsedW) minmax(0,1fr) auto!important}body.mainNavCollapsed .brandCluster{width:var(--leftPaneCollapsedW)!important;padding:0!important;justify-content:center!important}body.mainNavCollapsed .brandCluster .brandLogo{display:none!important}#appView.mainNavCollapsed .mainNav button:not(.mainNavControl){font-size:0!important;padding:14px 0!important;grid-template-columns:1fr!important}#appView.mainNavCollapsed>.cards,#appView.mainNavCollapsed>#rulesView,#appView.mainNavCollapsed>#accessView,#appView.mainNavCollapsed>#mcpView,#appView.mainNavCollapsed>#settingsView,#appView.mainNavCollapsed>#foot{grid-column:2!important}@media(max-width:900px){:root{--topBarH:72px!important;--leftPaneW:100%!important}.brandCluster{width:auto!important;height:72px!important;padding:0 12px!important}.brandCluster .brandLogo{width:220px!important;max-width:58vw!important}.topWorkspace{height:72px!important;padding:0 12px!important;gap:10px!important}.topMenuCollapse{width:40px!important;height:40px!important;flex-basis:40px!important}.topMenuCollapse::before{font-size:32px!important}.welcomeName{display:none!important}#appView:not(.hidden),#appView.settingsMode:not(.hidden),#appView.mainNavCollapsed:not(.hidden){grid-template-columns:1fr!important}.mainNav{position:static!important;height:auto!important;min-height:0!important;top:auto!important;border-right:0!important}.mainNav button{font-size:15px!important;min-height:44px!important;padding:10px 14px!important}.mainNav .adminSubItem{font-size:14px!important;padding-left:28px!important}#appView>.cards,#appView>#rulesView,#appView>#accessView,#appView>#mcpView,#appView>#settingsView,#appView>#foot{grid-column:1!important;border-left:0!important;min-height:0!important;padding:14px!important}.sectionHead h2{font-size:24px!important}.contentTabs button{font-size:16px!important;padding:12px 14px!important}}



/* 2026-07 user-management-oidc-layout: OIDC lives inside User Management; responsive cards prevent field overlap. */
#adminNav-oidc{display:none!important}.userCards{display:grid!important;grid-template-columns:repeat(auto-fit,minmax(min(520px,100%),1fr))!important;gap:18px!important;margin:16px 0 28px!important}.userCard{border:1px solid var(--line)!important;background:var(--surface2)!important;padding:18px!important;box-shadow:var(--shadow)!important;min-width:0!important}.userCardHeader{display:flex!important;justify-content:space-between!important;align-items:flex-start!important;gap:12px!important;margin-bottom:16px!important}.userCardName{font-size:18px!important;font-weight:800!important;color:var(--text)!important}.userEditGrid,.userAddGrid,.oidcConfigGrid{display:grid!important;grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:14px 16px!important;align-items:end!important;max-width:100%!important}.fieldLabel{display:flex!important;flex-direction:column!important;gap:7px!important;min-width:0!important}.fieldLabel span{font-size:12px!important;font-weight:800!important;color:var(--muted)!important;letter-spacing:.03em!important;text-transform:uppercase!important}.fieldLabel input,.fieldLabel select,.userEditGrid input,.userEditGrid select,.userAddGrid input,.userAddGrid select,.oidcConfigGrid input,.oidcConfigGrid select{width:100%!important;min-width:0!important;box-sizing:border-box!important}.fieldLabel.wide,.userPasswordField{grid-column:1/-1!important}.userSaveButton,.userAddButton,.oidcSaveButton{justify-self:start!important;min-width:180px!important}.oidcInUsers{margin-top:34px!important;padding-top:26px!important;border-top:1px solid var(--line)!important}.checkRow{display:flex!important;align-items:center!important;gap:10px!important;min-height:42px!important}.checkRow input{width:auto!important}.oidcConfigGrid .checkRow{align-self:center!important}@media(max-width:760px){.userCards,.userEditGrid,.userAddGrid,.oidcConfigGrid{grid-template-columns:1fr!important}.userCard{padding:14px!important}.userSaveButton,.userAddButton,.oidcSaveButton{width:100%!important}}


/* 2026-07 distinct-nav-icons: unique Material icons with fixed columns; OIDC remains nested under User Management. */
#settingsUsers #settingsOidc{display:block!important}.mainNav button[data-icon],.settingsSubnav button[data-icon]{display:grid!important;grid-template-columns:34px minmax(0,1fr) 28px!important;align-items:center!important;gap:12px!important}.mainNav .adminSubItem[data-icon]{grid-template-columns:30px minmax(0,1fr)!important;padding-left:32px!important}.mainNav button[data-icon]::before,.settingsSubnav button[data-icon]::before{content:attr(data-icon)!important;display:inline-grid!important;place-items:center!important;width:28px!important;height:28px!important;min-width:28px!important;overflow:hidden!important;font-family:'Material Symbols Outlined'!important;font-size:24px!important;font-weight:400!important;line-height:1!important;color:currentColor!important;opacity:.92!important;background:transparent!important;position:static!important;mask:none!important;-webkit-mask:none!important;text-transform:none!important;letter-spacing:normal!important;white-space:nowrap!important}.mainNav button.active::before,.mainNav .adminSubItem.active::before{position:static!important;width:28px!important;height:28px!important;background:transparent!important}.mainNav button.active::after,.mainNav .adminSubItem.active::after{content:''!important;position:absolute!important;left:0!important;top:0!important;bottom:0!important;width:6px!important;background:var(--activeRail)!important}.mainNav button.navGroup::after{content:'›'!important;position:absolute!important;right:24px!important;top:50%!important;transform:translateY(-50%)!important;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif!important;font-size:38px!important;background:transparent!important;width:auto!important;height:auto!important}.mainNav button.navGroup.active::after{content:'⌄'!important;font-size:32px!important}.mainNavCollapsed .mainNav button[data-icon]{grid-template-columns:1fr!important;justify-items:center!important}.mainNavCollapsed .mainNav button[data-icon]::before{font-size:28px!important}.mainNavCollapsed .mainNav button[data-icon]{font-size:0!important}.settingsShell.collapsed .settingsSubnav button[data-icon]{grid-template-columns:1fr!important;justify-items:center!important}.settingsShell.collapsed .settingsSubnav button[data-icon]::before{font-size:26px!important}@media(max-width:900px){.mainNav button[data-icon],.settingsSubnav button[data-icon],.mainNav .adminSubItem[data-icon]{grid-template-columns:28px minmax(0,1fr)!important;gap:8px!important}.mainNav button[data-icon]::before,.settingsSubnav button[data-icon]::before{width:24px!important;min-width:24px!important;font-size:22px!important}.mainNav button.navGroup::after{right:12px!important;font-size:28px!important}}


/* 2026-07 api-token-management-cleanup: concise copy, labeled token label field, dropdown filters, sortable headers. */
.apiTokenCreateGrid{display:grid!important;grid-template-columns:minmax(260px,520px) auto!important;gap:14px!important;align-items:end!important;margin:16px 0!important}.apiTokenCreateGrid .fieldLabel input{width:100%!important}.apiTokenToolbar{margin:18px 0 12px!important}.apiTokenToolbar select{min-width:180px!important}#apiTokenInventory th[data-sort]{cursor:pointer!important;white-space:nowrap!important}#apiTokenInventory th[data-sort]::after{content:' ↕';color:var(--muted);font-size:12px}@media(max-width:760px){.apiTokenCreateGrid{grid-template-columns:1fr!important}.apiTokenCreateGrid button{width:100%!important}}


/* 2026-07 oidc-sso-login-layout: clearer OIDC setup and visible SSO login option. */
.ssoLogin{width:100%;margin-top:10px;background:var(--surface2)!important;border-color:var(--line)!important}.oidcHeader{display:flex!important;justify-content:space-between!important;gap:16px!important;align-items:flex-start!important;margin:18px 0!important}.oidcSetupCards{display:grid!important;grid-template-columns:repeat(auto-fit,minmax(min(520px,100%),1fr))!important;gap:18px!important;margin:16px 0!important}.oidcCard{border:1px solid var(--line)!important;background:var(--surface2)!important;padding:18px!important;box-shadow:var(--shadow)!important}.oidcCard h4{margin:0 0 14px!important}.oidcHelp{border:1px dashed var(--line)!important;color:var(--muted)!important;background:var(--surface)!important;padding:12px!important;line-height:1.45!important}.oidcWide{grid-column:1/-1!important}.oidcInUsers .oidcSaveButton{margin:6px 0 16px!important}@media(max-width:760px){.oidcHeader{display:block!important}.oidcSetupCards{grid-template-columns:1fr!important}}


/* 2026-07 oidc-visible-user-management-instructions: keep OIDC visibly inside User Management with field help. */
.oidcInUsers{margin:18px 0 30px!important;padding:20px!important;border:1px solid var(--line)!important;background:var(--surface)!important;box-shadow:var(--shadow)!important}.oidcInstructions{border:1px solid var(--line)!important;background:var(--surface2)!important;padding:14px 16px!important;margin:12px 0 16px!important}.oidcInstructions h4{margin:0 0 8px!important}.oidcInstructions ol{margin:0!important;padding-left:22px!important}.oidcInstructions li{margin:6px 0!important;line-height:1.45!important}.fieldLabel small,.fieldHelp{display:block!important;margin-top:6px!important;color:var(--muted)!important;font-size:12px!important;line-height:1.35!important}.oidcInUsers code{background:var(--surface2)!important;border:1px solid var(--line)!important;padding:1px 5px!important;border-radius:6px!important}.oidcHeader h3{margin-top:0!important}


/* 2026-07 dashboard-compact-recovery: keep approved top bar, make dashboard/cards usable, and avoid icon-font fallback text. */
#appView>.cards{grid-column:2!important;align-self:start!important;justify-self:start!important;width:100%!important;display:grid!important;grid-template-columns:repeat(auto-fit,minmax(128px,168px))!important;grid-auto-rows:auto!important;align-items:start!important;gap:10px!important;margin:10px 0 14px!important;min-height:0!important;height:auto!important}.cards .card,.card{align-self:start!important;min-height:0!important;height:auto!important;padding:10px 12px!important;box-shadow:none!important}.cards .card .muted{font-size:12px!important;line-height:1.2!important}.metric{font-size:24px!important;line-height:1.05!important}.mainNav button[data-icon]::before,.mainNav .adminSubItem[data-icon]::before{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif!important;font-size:18px!important;line-height:1!important;content:''!important;width:24px!important;min-width:24px!important;height:24px!important;display:inline-grid!important;place-items:center!important;overflow:visible!important}.mainNav button[data-icon]{grid-template-columns:26px minmax(0,1fr) 22px!important;gap:8px!important}.mainNav .adminSubItem[data-icon]{grid-template-columns:24px minmax(0,1fr)!important;gap:8px!important}.mainNav button[data-icon]::before{content:'•'!important}#tab-rules::before{content:'⚖'!important}#tab-access::before{content:'▤'!important}#tab-mcp::before{content:'⛓'!important}#tab-userSettings::before{content:'◉'!important}#tab-adminSettings::before{content:'⚙'!important}#adminNav-users::before{content:'👥'!important}#adminNav-workspace::before{content:'☁'!important}#adminNav-system::before{content:'⚙'!important}#adminNav-tokens::before{content:'🔑'!important}.mainNav button.navGroup::after{right:14px!important;font-size:22px!important}.mainNav button.navGroup.active::after{font-size:20px!important}@media(max-width:900px){#appView>.cards{grid-column:1!important;grid-template-columns:repeat(2,minmax(0,1fr))!important;justify-self:stretch!important}.cards .card{padding:10px!important}.metric{font-size:22px!important}}@media(max-width:520px){#appView>.cards{grid-template-columns:1fr!important}}
/* 2026-07 oidc-auto-viewer-provisioning: unknown OIDC users are always created on first login as Viewer. */


/* 2026-07 acl-rail-density-polish: narrower rail, less top dead space, calmer welcome, larger logo, ACL stats only on ACL tab. */
:root{--leftPaneW:318px!important;--leftPaneCollapsedW:72px!important;--topBarH:96px!important}.brandCluster{width:var(--leftPaneW)!important;height:var(--topBarH)!important;padding:0 16px 0 18px!important;box-sizing:border-box!important}.brandCluster .brand{height:var(--topBarH)!important;display:flex!important;align-items:center!important;overflow:visible!important}.brandCluster .brandLogo{width:300px!important;max-width:300px!important;min-width:0!important;height:auto!important;object-fit:contain!important;object-position:left center!important}.topWorkspace{height:var(--topBarH)!important;padding-left:22px!important;gap:22px!important}.welcomeName{font-size:24px!important;line-height:1.1!important;font-weight:760!important;letter-spacing:-.02em!important;max-width:44vw!important}.topMenuCollapse{width:42px!important;height:42px!important;flex-basis:42px!important}.topMenuCollapse::before{font-size:34px!important}.mainNav{top:var(--topBarH)!important;height:calc(100vh - var(--topBarH))!important;min-height:calc(100vh - var(--topBarH))!important;padding-top:0!important}.mainNav button{min-height:46px!important;padding:10px 16px!important;font-size:18px!important}.mainNav .adminSubItem{min-height:40px!important;font-size:14px!important}header,header .wrap.top{height:var(--topBarH)!important;grid-template-columns:var(--leftPaneW) minmax(0,1fr) auto!important}main{padding-top:var(--topBarH)!important}#appView:not(.hidden),#appView.settingsMode:not(.hidden){grid-template-columns:var(--leftPaneW) minmax(0,1fr)!important;gap:18px!important;padding-right:18px!important}#appView>.cards.hidden{display:none!important;visibility:hidden!important}#appView>.cards:not(.hidden){display:grid!important}@media(max-width:900px){:root{--topBarH:64px!important}.brandCluster{width:auto!important;height:64px!important;padding:0!important}.brandCluster .brandLogo{width:190px!important;max-width:52vw!important}.welcomeName{display:none!important}header,header .wrap.top{height:auto!important;min-height:64px!important;grid-template-columns:1fr auto!important}main{padding-top:64px!important}#appView:not(.hidden),#appView.settingsMode:not(.hidden),#appView.mainNavCollapsed:not(.hidden){grid-template-columns:1fr!important;padding:0 10px 34px!important}.mainNav{top:auto!important;height:auto!important;min-height:0!important}}


/* 2026-07 authentik-density-v3: compact grayscale Authentik-like shell, supplied post-login logo, tighter cards/filters. */
:root{--leftPaneW:276px!important;--leftPaneCollapsedW:68px!important;--topBarH:86px!important;--sideBg:#171819!important;--sideHover:#242528!important;--sideActive:#4f5156!important;--sideText:#f2f2f2!important;--sideMuted:#b7bcc5!important;--railDivider:rgba(255,255,255,.10)!important;--activeRail:var(--accent)!important}body.light{--sideBg:#f1f2f4!important;--sideHover:#e4e6ea!important;--sideActive:#d7d9de!important;--sideText:#202124!important;--sideMuted:#5f6368!important;--railDivider:rgba(0,0,0,.12)!important}header,header .wrap.top{height:var(--topBarH)!important;background:var(--sideBg)!important;border-bottom:1px solid var(--railDivider)!important}header .wrap.top{grid-template-columns:var(--leftPaneW) minmax(0,1fr) auto!important}.brandCluster{width:var(--leftPaneW)!important;height:var(--topBarH)!important;background:var(--sideBg)!important;padding:0 14px!important;border-right:1px solid rgba(0,0,0,.18)!important;overflow:hidden!important}.brandCluster .brand{height:var(--topBarH)!important;width:100%!important;align-items:center!important}.brandCluster .postLoginLogo{display:block!important;width:232px!important;max-width:232px!important;height:auto!important;max-height:74px!important;object-fit:contain!important;object-position:left center!important;aspect-ratio:auto!important}.topWorkspace{height:var(--topBarH)!important;background:var(--sideBg)!important;padding:0 22px!important;gap:20px!important}.welcomeName{font-size:22px!important;font-weight:720!important;line-height:1.05!important;letter-spacing:-.025em!important;color:var(--text)!important}.topMenuCollapse{width:40px!important;height:40px!important;flex-basis:40px!important}.topMenuCollapse::before{font-size:32px!important}.mainNav{top:var(--topBarH)!important;height:calc(100vh - var(--topBarH))!important;min-height:calc(100vh - var(--topBarH))!important;padding:0!important;border-right:1px solid var(--railDivider)!important;background:var(--sideBg)!important}.mainNav button{min-height:40px!important;padding:9px 13px!important;font-size:15px!important;font-weight:600!important;border-bottom:1px solid rgba(255,255,255,.08)!important;border-radius:0!important;grid-template-columns:24px minmax(0,1fr) 18px!important;gap:8px!important}.mainNav button[data-icon]::before,.mainNav .adminSubItem[data-icon]::before{width:22px!important;min-width:22px!important;height:22px!important;font-size:16px!important}.mainNav .adminSubItem{min-height:34px!important;padding:7px 12px 7px 30px!important;font-size:13px!important;font-weight:500!important;border-bottom:0!important;grid-template-columns:22px minmax(0,1fr)!important}.mainNav button.active,.mainNav .adminSubItem.active{background:var(--sideActive)!important;color:var(--sideText)!important}.mainNav button.active::after,.mainNav .adminSubItem.active::after{width:5px!important;background:var(--accent)!important}.mainNav button.navGroup::after{right:10px!important;font-size:20px!important}.mainNav button.navGroup.active::after{font-size:18px!important}main{padding-top:var(--topBarH)!important;padding-right:12px!important;padding-bottom:6px!important;min-height:0!important}#appView:not(.hidden),#appView.settingsMode:not(.hidden){grid-template-columns:var(--leftPaneW) minmax(0,1fr)!important;gap:12px!important;padding:0 0 0 0!important;align-content:start!important}#appView.mainNavCollapsed:not(.hidden){grid-template-columns:var(--leftPaneCollapsedW) minmax(0,1fr)!important}.sectionHead{margin:0 0 8px!important}.sectionHead h2{font-size:18px!important;line-height:1.2!important}.sectionHead .muted{font-size:12px!important}.toolbar{display:flex!important;gap:6px!important;align-items:center!important;margin:6px 0 8px!important}.toolbar input,.toolbar select,.filterSelect{min-height:34px!important;height:34px!important;padding:6px 8px!important;font-size:12px!important}.bulkbar{margin:6px 0 8px!important;gap:7px!important}.panel{margin:0 0 8px!important;padding:0!important;box-shadow:none!important}.cards{gap:8px!important;margin:6px 0 8px!important}.cards .card,.card{padding:8px 10px!important}.metric{font-size:22px!important}.settingsShell{min-height:0!important;border:0!important;background:transparent!important}.settingsContent{padding:14px 18px 12px!important}.settingBlock{padding:0 0 10px!important;margin:0!important}.settingBlock h3{font-size:18px!important;margin:0 0 6px!important}.settingBlock h4{font-size:15px!important;margin:0 0 8px!important}.settingBlock p{margin:4px 0 8px!important;font-size:13px!important;line-height:1.35!important}.contentTabs{display:flex!important;gap:4px!important;margin:8px 0 10px!important;padding:0!important;border-bottom:1px solid var(--line)!important}.contentTabs button{min-height:32px!important;padding:7px 10px!important;font-size:13px!important;font-weight:650!important;border-radius:0!important;border:0!important;border-bottom:3px solid transparent!important;background:transparent!important;color:var(--muted)!important}.contentTabs button:hover{background:var(--surface2)!important;color:var(--text)!important}.contentTabs button.active{background:transparent!important;color:var(--text)!important;border-bottom-color:var(--accent)!important}.userCards,.oidcSetupCards{gap:10px!important;margin:8px 0 12px!important}.userCard,.oidcCard,.oidcInUsers,.oidcInstructions,.runtimeBox{box-shadow:none!important}.userCard,.oidcCard{padding:12px!important}.oidcInUsers{margin:0 0 10px!important;padding:12px!important}.oidcInstructions{padding:10px!important;margin:8px 0!important}.userEditGrid,.userAddGrid,.oidcConfigGrid{gap:10px!important}.fieldLabel{gap:5px!important}.fieldLabel span{font-size:11px!important}.fieldLabel small,.fieldHelp{font-size:11px!important;line-height:1.3!important}table th,table td{padding:8px 9px!important;font-size:13px!important}.routeComposer{gap:10px!important;margin:8px 0!important}.routePickHead{padding:10px 12px!important}.routePickItem{padding:9px 11px!important}.runtimeActions{gap:6px!important;margin:8px 0!important}.msg{margin-top:8px!important}.grafanaNote{margin-bottom:6px!important}#foot{margin:2px 0 0!important}.userDropdown{top:calc(100% + 4px)!important;min-width:150px!important;padding:4px!important}.userDropdown button{padding:7px 9px!important;font-size:13px!important}body.authing .brandCluster .postLoginLogo{display:none!important}@media(max-width:900px){:root{--topBarH:64px!important}.brandCluster{width:auto!important;height:64px!important;padding:0!important}.brandCluster .postLoginLogo{width:190px!important;max-width:52vw!important;max-height:54px!important}.welcomeName{display:none!important}header,header .wrap.top{height:auto!important;min-height:64px!important}main{padding:64px 10px 6px!important}#appView:not(.hidden),#appView.settingsMode:not(.hidden),#appView.mainNavCollapsed:not(.hidden){grid-template-columns:1fr!important;gap:10px!important}.mainNav{position:static!important;height:auto!important;min-height:0!important;border:1px solid var(--line)!important;border-radius:12px!important;padding:5px!important}.mainNav button{border-bottom:0!important;border-radius:8px!important}.toolbar{display:grid!important;grid-template-columns:1fr!important}.contentTabs{overflow:auto!important}.settingsContent{padding:10px!important}}



/* 2026-07 left-rail-bottom-controls-v4: previous theme logos, bottom utility icons, active-token default, tighter ACL stack, less bottom void, larger text. */
body{font-size:15px!important}.brandCluster .postLoginLogo{display:none!important}.brandCluster .themeLogo.brandLogo{display:block!important;width:238px!important;max-width:238px!important;max-height:68px!important;height:auto!important;object-fit:contain!important;object-position:left center!important;aspect-ratio:auto!important}body.light .brandCluster .darkLogo{display:none!important}body:not(.light) .brandCluster .lightLogo{display:none!important}.actions{display:none!important}.topWorkspace{padding-left:18px!important}.welcomeName{font-size:23px!important}.mainNav{display:flex!important;flex-direction:column!important;padding:6px 0 8px!important;overflow:hidden!important}.mainNav button{font-size:16px!important;min-height:42px!important;padding:9px 14px!important}.mainNav .adminSubItem{font-size:14px!important;min-height:36px!important}.mainNav button[data-icon]::before,.mainNav .adminSubItem[data-icon]::before{font-size:17px!important}.navBottom{margin-top:auto!important;border-top:1px solid var(--railDivider)!important;padding:8px 8px 6px!important;display:grid!important;grid-template-columns:repeat(4,minmax(0,1fr))!important;gap:6px!important;align-items:center!important}.navBottomIcon{min-height:38px!important;height:38px!important;width:100%!important;min-width:0!important;padding:0!important;display:inline-grid!important;place-items:center!important;border:0!important;border-radius:8px!important;background:transparent!important;color:var(--sideMuted)!important;font-size:20px!important}.navBottomIcon:hover,.navBottomIcon.active{background:var(--sideHover)!important;color:var(--sideText)!important}.navBottomIcon[data-icon]::before{content:'◉'!important;font-size:18px!important}.navBottomIcon.active::after{display:none!important}.logoutIcon{font-size:21px!important}.railUser{display:grid!important;place-items:center!important;min-width:0!important}.railUser.hidden{display:none!important}.railUser .avatarMini{display:block!important;width:32px!important;height:32px!important;border-radius:50%!important}.railUser .avatarMini.hidden{display:none!important}.railUserName{display:none!important}.userDropdown,#userDropdown,#userMenuBtn{display:none!important}#appView.mainNavCollapsed .navBottom{grid-template-columns:1fr!important}.cards{margin:0!important;gap:8px!important}.cards .card,.card{padding:9px 11px!important}.metric{font-size:23px!important}#rulesView .toolbar{margin:0 0 6px!important}.toolbar{gap:7px!important}.toolbar input,.toolbar select,.filterSelect{font-size:13px!important;height:35px!important;min-height:35px!important}.bulkbar{margin:0 0 6px!important}.panel{margin:0!important}#rulesView{align-self:stretch!important}#rulesView .panel{min-height:calc(100vh - var(--topBarH) - 158px)!important;background:var(--surface)!important}#rulesView .panel table{margin-bottom:0!important}#appView>.cards{margin-bottom:0!important}.sectionHead{margin:0 0 6px!important}.settingBlock h3,.sectionHead h2{font-size:19px!important}.settingBlock h4{font-size:16px!important}.settingBlock p,.muted,.msg{font-size:13px!important}table th,table td{font-size:14px!important;padding:8px 10px!important}.contentTabs button{font-size:14px!important}.fieldLabel span{font-size:12px!important}main{padding-bottom:0!important}#foot{min-height:0!important;margin:0!important;padding:0!important}.apiTokenToolbar{margin:8px 0!important}@media(max-width:900px){.actions{display:none!important}.navBottom{grid-template-columns:repeat(4,minmax(0,1fr))!important;margin-top:6px!important}.brandCluster .themeLogo.brandLogo{width:190px!important;max-width:52vw!important}.mainNav{overflow:visible!important}#rulesView .panel{min-height:0!important}}



/* 2026-07 fixed-left-rail-v5: body does not scroll; only right content scrolls; larger logo; avatar opens user settings; clearer logout arrow. */
body:not(.authing),body:not(.authing) html{height:100%!important}body:not(.authing){overflow:hidden!important;font-size:16px!important}:root{--leftPaneW:340px!important;--leftPaneCollapsedW:74px!important;--topBarH:82px!important}.brandCluster{width:var(--leftPaneW)!important;height:var(--topBarH)!important;padding:0 10px 0 14px!important;align-items:center!important}.brandCluster .themeLogo.brandLogo{width:318px!important;max-width:318px!important;max-height:78px!important;height:auto!important;object-fit:contain!important;object-position:left center!important;aspect-ratio:auto!important}.topWorkspace{height:var(--topBarH)!important;padding-left:14px!important}.topMenuCollapse{width:38px!important;height:38px!important;flex-basis:38px!important}.topMenuCollapse::before{font-size:30px!important}.welcomeName{font-size:22px!important}header,header .wrap.top{height:var(--topBarH)!important;grid-template-columns:var(--leftPaneW) minmax(0,1fr) auto!important}main{height:100vh!important;max-height:100vh!important;overflow:hidden!important;padding-top:var(--topBarH)!important;padding-right:0!important;padding-bottom:0!important}#appView:not(.hidden),#appView.settingsMode:not(.hidden){height:calc(100vh - var(--topBarH))!important;max-height:calc(100vh - var(--topBarH))!important;overflow-y:auto!important;overflow-x:hidden!important;grid-template-columns:var(--leftPaneW) minmax(0,1fr)!important;gap:12px!important;padding:0 14px 0 0!important;scrollbar-gutter:stable!important}#appView.mainNavCollapsed:not(.hidden){grid-template-columns:var(--leftPaneCollapsedW) minmax(0,1fr)!important}.mainNav{position:fixed!important;left:0!important;top:var(--topBarH)!important;width:var(--leftPaneW)!important;height:calc(100vh - var(--topBarH))!important;min-height:0!important;z-index:900!important;padding:4px 0 8px!important;overflow:hidden!important}.mainNav.collapsed{width:var(--leftPaneCollapsedW)!important}.mainNav button{font-size:16px!important;min-height:40px!important;padding:8px 14px!important}.mainNav .adminSubItem{font-size:14px!important;min-height:34px!important;padding-top:6px!important;padding-bottom:6px!important}#appView>.cards,#appView>#rulesView,#appView>#accessView,#appView>#mcpView,#appView>#settingsView,#appView>#foot{grid-column:2!important;min-width:0!important}.cards{margin:0!important;padding-top:0!important}.cards .card,.card{padding:8px 10px!important}.metric{font-size:24px!important}.toolbar{margin:0 0 5px!important}.bulkbar{margin:0 0 5px!important}.panel{margin:0!important}#rulesView .panel{min-height:0!important}#foot{display:none!important}.navBottom{grid-template-columns:repeat(3,minmax(0,1fr))!important;margin-top:auto!important;padding:8px!important}.navBottomIcon,.railUser.navBottomIcon{height:40px!important;min-height:40px!important;border-radius:9px!important}.railUser.navBottomIcon{display:inline-grid!important;place-items:center!important}.railUser.navBottomIcon.hidden{display:none!important}.railUser.navBottomIcon .avatarMini{width:34px!important;height:34px!important;border-radius:50%!important}.railUser.navBottomIcon .avatarMini.hidden + .railUserName{display:block!important;font-size:0!important}.railUser.navBottomIcon .avatarMini.hidden + .railUserName::before{content:'👤';font-size:18px}.logoutIcon{font-size:24px!important;font-weight:800!important}.navBottomIcon[data-icon]::before{display:none!important}.sectionHead h2,.settingBlock h3{font-size:20px!important}.settingBlock h4{font-size:17px!important}table th,table td{font-size:14.5px!important}.contentTabs button{font-size:14.5px!important}.fieldLabel span{font-size:12.5px!important}@media(max-width:900px){body:not(.authing){overflow:auto!important}main{height:auto!important;max-height:none!important;overflow:visible!important}#appView:not(.hidden),#appView.settingsMode:not(.hidden),#appView.mainNavCollapsed:not(.hidden){height:auto!important;max-height:none!important;overflow:visible!important;grid-template-columns:1fr!important;padding:0 10px 8px!important}.mainNav{position:static!important;width:100%!important;height:auto!important;min-height:0!important}.brandCluster .themeLogo.brandLogo{width:210px!important;max-width:56vw!important;max-height:58px!important}.navBottom{grid-template-columns:repeat(3,minmax(0,1fr))!important}}



/* 2026-07 dashboard-typography-backups-v6: larger dashboard type, narrower rail, larger bounded logo, fixed ACL spacing, cleaner backups, OIDC tab isolation. */
:root{--leftPaneW:300px!important;--leftPaneCollapsedW:72px!important;--topBarH:86px!important}body:not(.authing),body{font-size:17px!important}.brandCluster{width:var(--leftPaneW)!important;height:var(--topBarH)!important;padding:0 8px 0 12px!important}.brandCluster .themeLogo.brandLogo{width:min(276px,calc(var(--leftPaneW) - 24px))!important;max-width:calc(var(--leftPaneW) - 24px)!important;max-height:82px!important;height:auto!important;object-fit:contain!important;object-position:left center!important;overflow:hidden!important}header,header .wrap.top{height:var(--topBarH)!important;grid-template-columns:var(--leftPaneW) minmax(0,1fr) auto!important}.topWorkspace{height:var(--topBarH)!important}.mainNav{width:var(--leftPaneW)!important;top:var(--topBarH)!important;height:calc(100vh - var(--topBarH))!important}.mainNav button{font-size:17px!important;min-height:42px!important;line-height:1.25!important}.mainNav .adminSubItem{font-size:15px!important;min-height:36px!important}.mainNav button[data-icon]::before,.mainNav .adminSubItem[data-icon]::before{font-size:19px!important}.welcomeName{font-size:24px!important}main{padding-top:var(--topBarH)!important}#appView:not(.hidden),#appView.settingsMode:not(.hidden){grid-template-columns:var(--leftPaneW) minmax(0,1fr)!important;height:calc(100vh - var(--topBarH))!important;max-height:calc(100vh - var(--topBarH))!important;gap:14px!important;padding-right:14px!important}#appView>.cards{display:grid!important;grid-column:2!important;grid-template-columns:repeat(auto-fit,minmax(150px,190px))!important;gap:9px!important;margin:8px 0 8px!important;align-self:start!important;z-index:1!important}.cards .card,.card{padding:10px 12px!important}.metric{font-size:26px!important}.label{font-size:13px!important}#rulesView{grid-column:2!important;margin-top:0!important;position:relative!important;z-index:0!important;clear:both!important}.sectionHead{margin:0 0 7px!important}.toolbar{display:flex!important;flex-wrap:wrap!important;gap:8px!important;margin:0 0 8px!important;position:relative!important;z-index:2!important}.toolbar input,.toolbar select,.filterSelect,input,select,textarea,button{font-size:15px!important}.toolbar input,.toolbar select,.filterSelect{min-height:38px!important;height:38px!important}.bulkbar{margin:0 0 8px!important}.panel{position:relative!important;z-index:1!important;margin:0!important;overflow:auto!important}.settingBlock h3,.sectionHead h2{font-size:22px!important}.settingBlock h4{font-size:18px!important}.settingBlock p,.muted,.msg{font-size:15px!important}table th,table td{font-size:15.5px!important;padding:9px 11px!important}.contentTabs button{font-size:15.5px!important;min-height:38px!important}.fieldLabel span{font-size:13.5px!important}.navBottom{grid-template-columns:repeat(3,minmax(0,1fr))!important}.logoutIcon{font-size:0!important}.logoutIcon::before{content:'logout';font-family:'Material Symbols Outlined';font-size:25px!important;line-height:1!important}.railUser.navBottomIcon::before{display:none!important}.railUser.navBottomIcon .avatarMini{width:36px!important;height:36px!important}.railUser.navBottomIcon .avatarMini.hidden + .railUserName::before{content:'account_circle';font-family:'Material Symbols Outlined';font-size:24px!important}#settingsOidc.hidden,#settingsUsers #settingsOidc.hidden,.oidcInUsers.hidden{display:none!important}#settingsOidc:not(.hidden){display:block!important}.backupPane{display:block!important}.backupPane.hidden{display:none!important}.backupHero{display:flex!important;justify-content:space-between!important;align-items:flex-start!important;gap:16px!important;padding:14px 16px!important;margin:0 0 12px!important;border:1px solid var(--line)!important;border-radius:12px!important;background:var(--surface2)!important}.backupHero h4,.backupCard h4{margin:0 0 5px!important}.backupHero p,.backupCard p{margin:0!important}.backupTokenToggle{white-space:nowrap!important;margin:0!important;background:var(--surface)!important;border:1px solid var(--line)!important;border-radius:999px!important;padding:8px 11px!important}.backupGrid{display:grid!important;grid-template-columns:repeat(3,minmax(220px,1fr))!important;gap:12px!important;margin:0 0 12px!important}.backupCard{border:1px solid var(--line)!important;border-radius:12px!important;background:var(--surface)!important;padding:14px!important;display:flex!important;flex-direction:column!important;gap:12px!important;min-height:150px!important}.backupActions,.backupFileRow,.backupScheduleRow{display:grid!important;grid-template-columns:1fr!important;gap:8px!important;margin:0!important}.backupFileRow input,.backupScheduleRow input,.backupScheduleRow select{width:100%!important;min-width:0!important}.backupStatusGrid{display:grid!important;grid-template-columns:1.15fr .85fr!important;gap:12px!important}.backupStatusGrid .runtimeBox{min-height:120px!important;margin:0!important;max-height:320px!important;overflow:auto!important}@media(max-width:1200px){.backupGrid,.backupStatusGrid{grid-template-columns:1fr!important}}@media(max-width:900px){:root{--leftPaneW:100%!important}.brandCluster .themeLogo.brandLogo{width:220px!important;max-width:56vw!important}.backupHero{display:grid!important}.backupGrid,.backupStatusGrid{grid-template-columns:1fr!important}}



/* 2026-07 supplied-icons-acl-useradmin-logo-v7: supplied icons/logo, ACL cards single row, avatar display-only, admin users view/create/delete only. */
:root{--leftPaneW:300px!important;--leftPaneCollapsedW:72px!important;--topBarH:92px!important}.brandCluster .themeLogo.brandLogo{width:min(286px,calc(var(--leftPaneW) - 18px))!important;max-width:calc(var(--leftPaneW) - 18px)!important;max-height:88px!important}.brand,.brandCluster .brand{cursor:pointer!important}.brandCluster{padding-left:8px!important;padding-right:6px!important}.navBottom{grid-template-columns:repeat(4,minmax(0,1fr))!important}.settingsIconBtn,.logoutIcon{font-size:0!important;background-color:transparent!important;background-repeat:no-repeat!important;background-position:center!important;background-size:28px 28px!important}.settingsIconBtn{background-image:url('/assets/user-settings-icon.png')!important}.logoutIcon{background-image:url('/assets/logout-icon.png')!important}.railUser{pointer-events:none!important;cursor:default!important;background:transparent!important;border:0!important}.railUserName{display:none!important}.railUser .avatarMini{display:block!important;width:36px!important;height:36px!important;border-radius:50%!important;object-fit:cover!important}.railUser .avatarMini.hidden{display:none!important}.railUser .avatarMini.hidden + .railUserName{display:block!important;font-size:0!important}.railUser .avatarMini.hidden + .railUserName::before{content:'account_circle';font-family:'Material Symbols Outlined';font-size:24px!important}#appView>.cards{grid-template-columns:repeat(5,minmax(112px,1fr))!important;width:100%!important;max-width:none!important;justify-self:stretch!important;margin:6px 0 12px!important;gap:8px!important;clear:both!important}.cards .card{min-width:0!important;padding:9px 10px!important}.cards .metric{font-size:24px!important;white-space:nowrap!important}#rulesView{padding-top:0!important;margin-top:0!important;clear:both!important}.toolbar{clear:both!important;margin-top:0!important;margin-bottom:10px!important;display:grid!important;grid-template-columns:minmax(220px,1.3fr) repeat(5,minmax(128px,1fr))!important;align-items:end!important}.toolbar>*{min-width:0!important}#settingsUsers>.muted{margin-bottom:10px!important}.userAdminCards{grid-template-columns:repeat(auto-fit,minmax(260px,1fr))!important;gap:12px!important;margin:10px 0 20px!important}.adminUserCard{padding:14px!important}.userBadgeStack{display:flex!important;gap:6px!important;flex-wrap:wrap!important;justify-content:flex-end!important}.adminUserMeta{display:flex!important;gap:14px!important;flex-wrap:wrap!important;margin:12px 0!important;color:var(--muted)!important;font-size:14px!important}.userAdminActions{display:flex!important;justify-content:flex-end!important}.adminCreateUserGrid{grid-template-columns:minmax(180px,1.2fr) minmax(120px,.7fr) minmax(120px,.7fr) minmax(180px,1fr) auto!important;align-items:end!important}.adminCreateUserGrid .userAddButton{height:38px!important}.danger,.pill.danger{color:#ffb4b4!important;border-color:rgba(255,90,90,.35)!important;background:rgba(160,30,30,.16)!important}@media(max-width:1250px){.toolbar{grid-template-columns:minmax(220px,1fr) repeat(3,minmax(130px,1fr))!important}#appView>.cards{grid-template-columns:repeat(5,minmax(96px,1fr))!important}.adminCreateUserGrid{grid-template-columns:1fr 1fr!important}}@media(max-width:900px){#appView>.cards{grid-template-columns:repeat(2,minmax(0,1fr))!important}.toolbar{grid-template-columns:1fr!important}.navBottom{grid-template-columns:repeat(4,minmax(0,1fr))!important}}



/* 2026-07 nav-runtime-collapse-v8: bottom rail order, mask icons, theme logos, runtime status/upgrade redesign, collapsed content shift. */
:root{--leftPaneW:300px!important;--leftPaneCollapsedW:72px!important;--topBarH:92px!important}.brandCluster .themeLogo.brandLogo{width:min(286px,calc(var(--leftPaneW) - 14px))!important;max-width:calc(var(--leftPaneW) - 14px)!important;max-height:88px!important;height:auto!important;object-fit:contain!important;object-position:left center!important;image-rendering:auto!important}.navBottom{grid-template-columns:40px 40px 40px 40px!important;justify-content:center!important;gap:10px!important;padding:10px 8px!important}.railUser{order:1!important;width:40px!important;height:40px!important;display:grid!important;place-items:center!important;pointer-events:none!important}.navBottom #theme{order:2!important}.settingsIconBtn{order:3!important}.logoutIcon{order:4!important}.navBottomIcon{width:40px!important;height:40px!important;min-height:40px!important;color:var(--sideText)!important;opacity:.92!important}.settingsIconBtn,.logoutIcon{background-image:none!important;position:relative!important}.settingsIconBtn::before,.logoutIcon::before{content:''!important;display:block!important;width:28px!important;height:28px!important;background:currentColor!important;mask-repeat:no-repeat!important;mask-position:center!important;mask-size:contain!important;-webkit-mask-repeat:no-repeat!important;-webkit-mask-position:center!important;-webkit-mask-size:contain!important}.settingsIconBtn::before{mask-image:url('/assets/user-settings-icon.png')!important;-webkit-mask-image:url('/assets/user-settings-icon.png')!important}.logoutIcon::before{mask-image:url('/assets/logout-icon.png')!important;-webkit-mask-image:url('/assets/logout-icon.png')!important}.navBottomIcon:hover,.settingsIconBtn.active{opacity:1!important;background:var(--sideHover)!important}.railUser .avatarMini{width:36px!important;height:36px!important;border-radius:50%!important;object-fit:cover!important;border:1px solid var(--railDivider)!important}.railUserName{display:none!important}.railUser .avatarMini.hidden{display:none!important}.railUser .avatarMini.hidden+.railUserName{display:grid!important;place-items:center!important;width:36px!important;height:36px!important;border-radius:50%!important;background:var(--sideHover)!important;color:var(--sideText)!important}.railUser .avatarMini.hidden+.railUserName::before{content:'account_circle';font-family:'Material Symbols Outlined';font-size:28px!important}body.mainNavCollapsed header .wrap.top{grid-template-columns:var(--leftPaneCollapsedW) minmax(0,1fr) auto!important}body.mainNavCollapsed .brandCluster{width:var(--leftPaneCollapsedW)!important;padding:0!important;justify-content:center!important}body.mainNavCollapsed .brandCluster .brand{display:none!important}body.mainNavCollapsed .topWorkspace{padding-left:8px!important}body.mainNavCollapsed #appView:not(.hidden),body.mainNavCollapsed #appView.settingsMode:not(.hidden){grid-template-columns:var(--leftPaneCollapsedW) minmax(0,1fr)!important;gap:12px!important}body.mainNavCollapsed #appView>.cards,body.mainNavCollapsed #appView>#rulesView,body.mainNavCollapsed #appView>#accessView,body.mainNavCollapsed #appView>#mcpView,body.mainNavCollapsed #appView>#settingsView{grid-column:2!important}.mainNav.collapsed .navBottom{grid-template-columns:1fr!important;gap:8px!important}.mainNav.collapsed .railUser,.mainNav.collapsed .navBottomIcon{width:44px!important;justify-self:center!important}.runtimeHero{display:flex!important;align-items:flex-start!important;justify-content:space-between!important;gap:18px!important;margin:4px 0 14px!important}.runtimeHero h4{font-size:24px!important;margin:0 0 4px!important}.runtimeStatusGrid{display:grid!important;grid-template-columns:minmax(280px,1.1fr) minmax(260px,1fr) minmax(260px,1fr)!important;gap:14px!important}.runtimeStatusCard{border:1px solid var(--line)!important;background:var(--surface2)!important;border-radius:16px!important;padding:16px!important;box-shadow:var(--shadow)!important;min-width:0!important}.runtimePrimaryCard{background:linear-gradient(135deg,var(--surface2),rgba(66,133,244,.08))!important}.statusCardLabel{font-size:12px!important;text-transform:uppercase!important;letter-spacing:.06em!important;font-weight:850!important;color:var(--muted)!important;margin-bottom:10px!important}.statusBig{font-size:24px!important;font-weight:850!important;display:block!important;margin-bottom:14px!important;white-space:normal!important}.statusKv{display:grid!important;grid-template-columns:130px minmax(0,1fr)!important;gap:12px!important;align-items:start!important;padding:8px 0!important;border-bottom:1px solid var(--line)!important}.statusKv:last-child{border-bottom:0!important}.statusKv span{color:var(--muted)!important;font-weight:750!important}.statusKv .code{white-space:normal!important;overflow-wrap:anywhere!important}.runtimeVersionCard{margin-top:14px!important}.runtimeVersionCard #runtimeVersion{display:grid!important;grid-template-columns:repeat(2,minmax(0,1fr))!important;gap:10px!important}.runtimeVersionCard #runtimeVersion>div,.upgradePrimary #runtimeUpgradeStatus>div{border:1px solid var(--line)!important;border-radius:12px!important;padding:10px!important;background:var(--surface)!important;overflow-wrap:anywhere!important}.upgradeGrid{display:grid!important;grid-template-columns:minmax(360px,1.3fr) minmax(260px,.8fr) minmax(260px,.9fr)!important;gap:14px!important}.runtimeSteps{margin:0!important;padding-left:20px!important;line-height:1.65!important}.runtimeSteps li{margin:5px 0!important}.upgradePrimary #runtimeUpgradeStatus{display:grid!important;gap:10px!important;background:transparent!important;border:0!important;padding:0!important}.upgradePrimary{min-height:220px!important}@media(max-width:1200px){.runtimeStatusGrid,.upgradeGrid{grid-template-columns:1fr!important}.runtimeVersionCard #runtimeVersion{grid-template-columns:1fr!important}}@media(max-width:900px){.navBottom{grid-template-columns:repeat(4,40px)!important}.runtimeHero{display:block!important}.runtimeHero button{margin-top:10px!important;width:100%!important}}



/* 2026-07 final-shell-consistency-v9: visible ACL filters, consistent typography, visible bottom utility icons, narrower rail, stable chevrons. */
:root{--leftPaneW:264px!important;--leftPaneCollapsedW:64px!important;--topBarH:88px!important;--uiFont:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif!important}html,body,button,input,select,textarea,table,.card,.panel,.runtimeBox,.settingsShell{font-family:var(--uiFont)!important;font-size:16px!important;font-weight:500!important;letter-spacing:0!important}body:not(.authing){font-size:16px!important}h1,h2,h3,h4,.userCardName,.statusBig{font-family:var(--uiFont)!important;font-weight:750!important;letter-spacing:-.015em!important}h3{font-size:22px!important}h4{font-size:19px!important}button,.mainNav button,.settingsSubnav button{font-weight:650!important}.muted,.label,.fieldLabel span{font-weight:500!important}.brandCluster{width:var(--leftPaneW)!important;height:var(--topBarH)!important;padding:0 7px!important;overflow:hidden!important}.brandCluster .brand{width:100%!important;height:100%!important;overflow:hidden!important}.brandCluster .themeLogo.brandLogo{width:100%!important;max-width:calc(var(--leftPaneW) - 14px)!important;max-height:76px!important;height:auto!important;object-fit:contain!important;object-position:left center!important;aspect-ratio:auto!important;image-rendering:auto!important}.topWorkspace{height:var(--topBarH)!important}.mainNav{width:var(--leftPaneW)!important;top:var(--topBarH)!important;height:calc(100vh - var(--topBarH))!important;padding:4px 0 8px!important}.mainNav.collapsed{width:var(--leftPaneCollapsedW)!important}header,header .wrap.top{height:var(--topBarH)!important;grid-template-columns:var(--leftPaneW) minmax(0,1fr) auto!important}body.mainNavCollapsed header .wrap.top{grid-template-columns:var(--leftPaneCollapsedW) minmax(0,1fr) auto!important}body.mainNavCollapsed .brandCluster{width:var(--leftPaneCollapsedW)!important;padding:0!important}.mainNav button{font-size:16px!important;min-height:42px!important;padding:9px 16px!important;border-radius:0!important;border-bottom:1px solid var(--railDivider)!important}.mainNav .adminSubItem{font-size:15px!important;min-height:38px!important;padding-left:44px!important}.mainNav button.navGroup{padding-right:42px!important}.mainNav button.navGroup::after{content:'›'!important;position:absolute!important;right:18px!important;top:50%!important;transform:translateY(-50%)!important;font-family:var(--uiFont)!important;font-size:34px!important;font-weight:850!important;line-height:1!important;color:var(--sideText)!important;background:transparent!important;width:auto!important;height:auto!important;opacity:.95!important}.mainNav button.navGroup.active::after{content:'⌄'!important;font-size:28px!important;right:18px!important;transform:translateY(-52%)!important}.mainNav button.active{background:var(--sideActive)!important}.mainNav button.active::after:not(.navGroup){display:none!important}#appView:not(.hidden),#appView.settingsMode:not(.hidden){height:calc(100vh - var(--topBarH))!important;max-height:calc(100vh - var(--topBarH))!important;overflow-y:auto!important;overflow-x:hidden!important;display:grid!important;grid-template-columns:var(--leftPaneW) minmax(0,1fr)!important;grid-template-rows:auto minmax(0,1fr)!important;gap:10px 14px!important;padding:0 14px 0 0!important}body.mainNavCollapsed #appView:not(.hidden),body.mainNavCollapsed #appView.settingsMode:not(.hidden),#appView.mainNavCollapsed:not(.hidden),#appView.mainNavCollapsed.settingsMode:not(.hidden){grid-template-columns:var(--leftPaneCollapsedW) minmax(0,1fr)!important}#appView>.cards{grid-column:2!important;grid-row:1!important;display:grid!important;grid-template-columns:repeat(5,minmax(110px,1fr))!important;gap:8px!important;margin:6px 0 0!important;align-self:start!important;position:relative!important;z-index:1!important}.cards .card{padding:9px 10px!important;min-height:58px!important}.cards .metric{font-size:24px!important;font-weight:760!important}.cards .label{font-size:13px!important}#rulesView{grid-column:2!important;grid-row:2!important;display:block!important;margin-top:0!important;position:relative!important;z-index:2!important;min-width:0!important;overflow:visible!important}#rulesView .toolbar{display:grid!important;visibility:visible!important;opacity:1!important;grid-template-columns:minmax(220px,1.35fr) repeat(5,minmax(120px,1fr))!important;gap:8px!important;margin:8px 0 10px!important;padding:8px!important;background:var(--surface)!important;border:1px solid var(--line)!important;border-radius:12px!important;position:relative!important;z-index:5!important}#rulesView .toolbar input,#rulesView .toolbar select,.filterSelect{height:38px!important;min-height:38px!important;font-size:15px!important;font-weight:500!important;background:var(--surface2)!important;color:var(--text)!important;border:1px solid var(--line)!important}#rulesView .bulkbar{margin:0 0 8px!important;position:relative!important;z-index:4!important}#rulesView .panel{margin:0!important;position:relative!important;z-index:3!important}.navBottom{grid-template-columns:38px 38px 38px 38px!important;gap:8px!important;justify-content:center!important;padding:9px 6px!important}.railUser{order:1!important;width:38px!important;height:38px!important}.navBottom #theme{order:2!important}.settingsIconBtn{order:3!important}.logoutIcon{order:4!important}.navBottomIcon{width:38px!important;height:38px!important;min-height:38px!important;display:grid!important;place-items:center!important;color:var(--sideText)!important;background:transparent!important;border-radius:8px!important;opacity:1!important;font-size:0!important}.navBottom #theme::before{content:'dark_mode'!important;font-family:'Material Symbols Outlined'!important;font-size:25px!important;line-height:1!important;color:var(--sideText)!important}.settingsIconBtn::before{content:'settings'!important;font-family:'Material Symbols Outlined'!important;font-size:25px!important;line-height:1!important;color:var(--sideText)!important;background:transparent!important;mask:none!important;-webkit-mask:none!important;width:auto!important;height:auto!important}.logoutIcon::before{content:'logout'!important;font-family:'Material Symbols Outlined'!important;font-size:25px!important;line-height:1!important;color:var(--sideText)!important;background:transparent!important;mask:none!important;-webkit-mask:none!important;width:auto!important;height:auto!important}.navBottomIcon:hover,.settingsIconBtn.active{background:var(--sideHover)!important}.railUser .avatarMini{width:34px!important;height:34px!important}.mainNav.collapsed .navBottom{grid-template-columns:1fr!important}.mainNav.collapsed .navBottom #theme::before,.mainNav.collapsed .settingsIconBtn::before,.mainNav.collapsed .logoutIcon::before{font-size:26px!important}.mainNav.collapsed .railUser,.mainNav.collapsed .navBottomIcon{width:42px!important;justify-self:center!important}.mainNav.collapsed button.navGroup::after{display:none!important}@media(max-width:1200px){#rulesView .toolbar{grid-template-columns:minmax(220px,1fr) repeat(3,minmax(120px,1fr))!important}#appView>.cards{grid-template-columns:repeat(5,minmax(90px,1fr))!important}}@media(max-width:900px){:root{--leftPaneW:100%!important;--leftPaneCollapsedW:64px!important}#appView:not(.hidden),#appView.settingsMode:not(.hidden),body.mainNavCollapsed #appView:not(.hidden){grid-template-columns:1fr!important;padding:0 10px 34px!important;height:auto!important;max-height:none!important;overflow:auto!important}#appView>.cards,#rulesView{grid-column:1!important}#appView>.cards{grid-template-columns:repeat(2,minmax(0,1fr))!important}#rulesView .toolbar{grid-template-columns:1fr!important}.mainNav{position:static!important;width:100%!important;height:auto!important}.brandCluster .themeLogo.brandLogo{max-width:220px!important}}



/* 2026-07 hard-regression-guards-v10: collapse button at rail edge, SVG utility icons, enforced type scale, non-stretched logos. */
:root{--leftPaneW:252px!important;--leftPaneCollapsedW:62px!important;--topBarH:86px!important;--uiFont:Inter,Roboto,"Helvetica Neue",Arial,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif!important;--uiBase:15.5px!important;--uiSmall:13px!important;--uiControl:15px!important;--uiH3:21px!important;--uiH4:18px!important}html,body,body:not(.authing),body:not(.authing) *{font-family:var(--uiFont)!important}body:not(.authing),body:not(.authing) main,body:not(.authing) .settingsShell,body:not(.authing) .panel,body:not(.authing) .runtimeBox,body:not(.authing) table{font-size:var(--uiBase)!important;font-weight:500!important;line-height:1.42!important;letter-spacing:0!important}body:not(.authing) button,body:not(.authing) input,body:not(.authing) select,body:not(.authing) textarea,body:not(.authing) .filterSelect{font-size:var(--uiControl)!important;font-weight:550!important;line-height:1.25!important}body:not(.authing) h2,body:not(.authing) h3,body:not(.authing) h4{font-family:var(--uiFont)!important;font-weight:720!important;letter-spacing:-.01em!important;line-height:1.18!important}body:not(.authing) h3{font-size:var(--uiH3)!important}body:not(.authing) h4{font-size:var(--uiH4)!important}body:not(.authing) .muted,body:not(.authing) .label,body:not(.authing) .fieldLabel span,body:not(.authing) small{font-size:var(--uiSmall)!important;font-weight:500!important;line-height:1.35!important}body:not(.authing) .mainNav button{font-size:15px!important;font-weight:620!important;line-height:1.22!important}body:not(.authing) .mainNav .adminSubItem{font-size:14px!important;font-weight:560!important}body:not(.authing) .metric{font-size:23px!important;font-weight:720!important;line-height:1.05!important}body:not(.authing) .statusBig{font-size:22px!important;font-weight:720!important}.welcomeName{font-size:18px!important;font-weight:650!important}.brandCluster{width:var(--leftPaneW)!important;min-width:var(--leftPaneW)!important;max-width:var(--leftPaneW)!important;height:var(--topBarH)!important;padding:0 8px!important;overflow:hidden!important}.brandCluster .brand{width:100%!important;height:100%!important;display:flex!important;align-items:center!important;justify-content:flex-start!important;overflow:hidden!important}.brandCluster .themeLogo.brandLogo{display:block!important;width:auto!important;max-width:calc(var(--leftPaneW) - 16px)!important;height:auto!important;max-height:72px!important;object-fit:contain!important;object-position:left center!important;aspect-ratio:auto!important;image-rendering:auto!important;transform:none!important}body.light .brandCluster .lightLogo{display:block!important}body.light .brandCluster .darkLogo{display:none!important}body:not(.light) .brandCluster .darkLogo{display:block!important;filter:none!important}body:not(.light) .brandCluster .lightLogo{display:none!important}header,header .wrap.top{height:var(--topBarH)!important;grid-template-columns:var(--leftPaneW) minmax(0,1fr) auto!important}.mainNav{width:var(--leftPaneW)!important;top:var(--topBarH)!important;height:calc(100vh - var(--topBarH))!important}.mainNav.collapsed{width:var(--leftPaneCollapsedW)!important}body.mainNavCollapsed header .wrap.top{grid-template-columns:var(--leftPaneCollapsedW) minmax(0,1fr) auto!important}body.mainNavCollapsed .brandCluster{width:var(--leftPaneCollapsedW)!important;min-width:var(--leftPaneCollapsedW)!important;max-width:var(--leftPaneCollapsedW)!important;padding:0!important}.topWorkspace{height:var(--topBarH)!important;padding-left:54px!important}.topMenuCollapse,#mainNavCollapse.topMenuCollapse{position:fixed!important;left:calc(var(--leftPaneW) - 44px)!important;top:22px!important;z-index:1300!important;width:34px!important;height:34px!important;min-height:34px!important;flex:0 0 34px!important;padding:0!important;border-radius:8px!important;border:1px solid var(--railDivider)!important;background:var(--sideHover)!important;color:var(--sideText)!important;font-size:0!important;display:grid!important;place-items:center!important;box-shadow:none!important}.topMenuCollapse::before,#mainNavCollapse.topMenuCollapse::before{content:'‹'!important;font-family:var(--uiFont)!important;font-size:28px!important;font-weight:850!important;line-height:1!important;color:var(--sideText)!important;background:transparent!important;mask:none!important;-webkit-mask:none!important;width:auto!important;height:auto!important}.topMenuCollapse::after{display:none!important}body.mainNavCollapsed .topMenuCollapse,body.mainNavCollapsed #mainNavCollapse.topMenuCollapse{left:calc(var(--leftPaneCollapsedW) - 48px)!important}body.mainNavCollapsed .topMenuCollapse::before,body.mainNavCollapsed #mainNavCollapse.topMenuCollapse::before{content:'›'!important}.mainNav button.navGroup{padding-right:44px!important;position:relative!important}.mainNav button.navGroup::after{content:'›'!important;position:absolute!important;right:18px!important;top:50%!important;transform:translateY(-50%)!important;font-family:var(--uiFont)!important;font-size:32px!important;font-weight:850!important;color:var(--sideText)!important;opacity:.95!important;background:transparent!important;width:auto!important;height:auto!important;line-height:1!important}.mainNav button.navGroup.active::after{content:'⌄'!important;font-size:27px!important;right:18px!important;transform:translateY(-52%)!important}.mainNav.collapsed button.navGroup::after{display:none!important}#appView:not(.hidden),#appView.settingsMode:not(.hidden){grid-template-columns:var(--leftPaneW) minmax(0,1fr)!important;gap:10px 14px!important}body.mainNavCollapsed #appView:not(.hidden),body.mainNavCollapsed #appView.settingsMode:not(.hidden),#appView.mainNavCollapsed:not(.hidden),#appView.mainNavCollapsed.settingsMode:not(.hidden){grid-template-columns:var(--leftPaneCollapsedW) minmax(0,1fr)!important}.navBottom{grid-template-columns:36px 36px 36px 36px!important;gap:8px!important;justify-content:center!important;align-items:center!important;padding:9px 5px!important}.railUser{order:1!important;width:36px!important;height:36px!important;display:grid!important;place-items:center!important;pointer-events:none!important}.navBottom #theme{order:2!important}.settingsIconBtn{order:3!important}.logoutIcon{order:4!important}.navBottomIcon{width:36px!important;height:36px!important;min-height:36px!important;display:grid!important;place-items:center!important;padding:0!important;color:var(--sideText)!important;background:transparent!important;border-radius:8px!important;opacity:1!important;font-size:0!important}.navBottom button#theme.navBottomIcon::before,.navBottom button#tab-userSettings.settingsIconBtn::before,.navBottom button#logout.logoutIcon::before{content:''!important;display:block!important;width:24px!important;height:24px!important;background-color:var(--sideText)!important;background-image:none!important;background-repeat:no-repeat!important;background-position:center!important;background-size:contain!important;mask-repeat:no-repeat!important;mask-position:center!important;mask-size:contain!important;-webkit-mask-repeat:no-repeat!important;-webkit-mask-position:center!important;-webkit-mask-size:contain!important}.navBottom button#theme.navBottomIcon::before{mask-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='black' d='M21.64 13.64A9 9 0 1 1 10.36 2.36a7 7 0 1 0 11.28 11.28Z'/%3E%3C/svg%3E")!important;-webkit-mask-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='black' d='M21.64 13.64A9 9 0 1 1 10.36 2.36a7 7 0 1 0 11.28 11.28Z'/%3E%3C/svg%3E")!important}.navBottom button#tab-userSettings.settingsIconBtn::before{mask-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='black' d='M19.43 12.98c.04-.32.07-.65.07-.98s-.02-.66-.07-.98l2.11-1.65a.5.5 0 0 0 .12-.64l-2-3.46a.5.5 0 0 0-.6-.22l-2.49 1a7.28 7.28 0 0 0-1.69-.98L14.5 2.42A.5.5 0 0 0 14 2h-4a.5.5 0 0 0-.49.42L9.13 5.07c-.61.24-1.18.56-1.69.98l-2.49-1a.5.5 0 0 0-.6.22l-2 3.46a.5.5 0 0 0 .12.64l2.11 1.65c-.04.32-.08.65-.08.98s.03.66.08.98l-2.11 1.65a.5.5 0 0 0-.12.64l2 3.46c.13.22.39.31.61.22l2.49-1c.51.4 1.07.73 1.68.98l.38 2.65c.04.24.25.42.49.42h4c.24 0 .45-.18.49-.42l.38-2.65c.61-.25 1.18-.58 1.69-.98l2.49 1c.22.09.48 0 .6-.22l2-3.46a.5.5 0 0 0-.12-.64l-2.11-1.65ZM12 15.5A3.5 3.5 0 1 1 12 8a3.5 3.5 0 0 1 0 7.5Z'/%3E%3C/svg%3E")!important;-webkit-mask-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='black' d='M19.43 12.98c.04-.32.07-.65.07-.98s-.02-.66-.07-.98l2.11-1.65a.5.5 0 0 0 .12-.64l-2-3.46a.5.5 0 0 0-.6-.22l-2.49 1a7.28 7.28 0 0 0-1.69-.98L14.5 2.42A.5.5 0 0 0 14 2h-4a.5.5 0 0 0-.49.42L9.13 5.07c-.61.24-1.18.56-1.69.98l-2.49-1a.5.5 0 0 0-.6.22l-2 3.46a.5.5 0 0 0 .12.64l2.11 1.65c-.04.32-.08.65-.08.98s.03.66.08.98l-2.11 1.65a.5.5 0 0 0-.12.64l2 3.46c.13.22.39.31.61.22l2.49-1c.51.4 1.07.73 1.68.98l.38 2.65c.04.24.25.42.49.42h4c.24 0 .45-.18.49-.42l.38-2.65c.61-.25 1.18-.58 1.69-.98l2.49 1c.22.09.48 0 .6-.22l2-3.46a.5.5 0 0 0-.12-.64l-2.11-1.65ZM12 15.5A3.5 3.5 0 1 1 12 8a3.5 3.5 0 0 1 0 7.5Z'/%3E%3C/svg%3E")!important}.navBottom button#logout.logoutIcon::before{mask-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='black' d='M10 17v-3H3v-4h7V7l5 5-5 5Zm-6 4a2 2 0 0 1-2-2v-4h2v4h14V5H4v4H2V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H4Z'/%3E%3C/svg%3E")!important;-webkit-mask-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='black' d='M10 17v-3H3v-4h7V7l5 5-5 5Zm-6 4a2 2 0 0 1-2-2v-4h2v4h14V5H4v4H2V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H4Z'/%3E%3C/svg%3E")!important}.navBottomIcon:hover,.settingsIconBtn.active{background:var(--sideHover)!important}.mainNav.collapsed .navBottom{grid-template-columns:1fr!important}.mainNav.collapsed .railUser,.mainNav.collapsed .navBottomIcon{width:42px!important;justify-self:center!important}.railUser .avatarMini{width:34px!important;height:34px!important;border-radius:50%!important;object-fit:cover!important}.railUserName{display:none!important}#rulesView .toolbar{visibility:visible!important;opacity:1!important;display:grid!important;grid-template-columns:minmax(220px,1.35fr) repeat(5,minmax(115px,1fr))!important;clear:both!important;margin:10px 0 10px!important;position:relative!important;z-index:20!important;background:var(--surface)!important}@media(max-width:900px){.topMenuCollapse,#mainNavCollapse.topMenuCollapse{position:static!important}.topWorkspace{padding-left:8px!important}.brandCluster{width:auto!important;min-width:0!important;max-width:none!important}.brandCluster .themeLogo.brandLogo{max-width:220px!important}.mainNav{width:100%!important}}



/* 2026-07 menu-icons-logo-v11: restore ellipsis collapse, right-side Admin Settings arrow only, simple visible bottom utilities, supplied dark logo. */
:root{--leftPaneW:252px!important;--leftPaneCollapsedW:62px!important;--topBarH:86px!important}.topMenuCollapse,#mainNavCollapse.topMenuCollapse{position:relative!important;left:auto!important;top:auto!important;z-index:auto!important;width:34px!important;height:34px!important;min-height:34px!important;flex:0 0 34px!important;padding:0!important;border-radius:8px!important;border:1px solid var(--railDivider)!important;background:transparent!important;color:var(--sideText)!important;font-size:0!important;display:grid!important;place-items:center!important;box-shadow:none!important}.topMenuCollapse::before,#mainNavCollapse.topMenuCollapse::before{content:'⋯'!important;font-family:var(--uiFont,Inter,system-ui,sans-serif)!important;font-size:28px!important;font-weight:850!important;line-height:.8!important;color:var(--sideText)!important;background:transparent!important;mask:none!important;-webkit-mask:none!important;width:auto!important;height:auto!important;transform:none!important}.topWorkspace{padding-left:10px!important;gap:10px!important}.mainNav button.navGroup::after{display:none!important}.mainNav button#tab-adminSettings.navGroup{position:relative!important;padding-right:42px!important}.mainNav button#tab-adminSettings.navGroup::after{content:'›'!important;display:block!important;position:absolute!important;right:16px!important;top:50%!important;transform:translateY(-50%)!important;font-family:var(--uiFont,Inter,system-ui,sans-serif)!important;font-size:31px!important;font-weight:850!important;line-height:1!important;color:var(--sideText)!important;background:transparent!important;width:auto!important;height:auto!important;opacity:.95!important}.mainNav button#tab-adminSettings.navGroup.active::after{content:'⌄'!important;font-size:26px!important;right:17px!important;transform:translateY(-52%)!important}.mainNav.collapsed button#tab-adminSettings.navGroup::after{display:none!important}.navBottom{display:grid!important;grid-template-columns:repeat(4,42px)!important;gap:6px!important;justify-content:center!important;align-items:center!important;padding:10px 4px!important;margin-top:auto!important}.navBottom .hidden,.navBottom button.hidden,.navBottom .railUser.hidden{display:grid!important}.railUser{order:1!important;width:42px!important;height:42px!important;display:grid!important;place-items:center!important;pointer-events:none!important;min-width:0!important}.navBottom #theme{order:2!important}.settingsIconBtn{order:3!important}.logoutIcon{order:4!important}.navBottomIcon,.navBottom button.navBottomIcon{width:42px!important;height:42px!important;min-height:42px!important;display:grid!important;place-items:center!important;padding:0!important;color:var(--sideText)!important;background:transparent!important;border:0!important;border-radius:9px!important;opacity:1!important;font-size:0!important;line-height:1!important}.navBottom button#theme.navBottomIcon::before,.navBottom button#tab-userSettings.settingsIconBtn::before,.navBottom button#logout.logoutIcon::before{content:''!important;font-family:var(--uiFont,Inter,system-ui,sans-serif)!important;font-size:25px!important;font-weight:750!important;line-height:1!important;color:var(--sideText)!important;background:transparent!important;background-image:none!important;mask:none!important;-webkit-mask:none!important;width:auto!important;height:auto!important;display:block!important}.navBottom button#theme.navBottomIcon::before{content:'☾'!important;font-size:26px!important}.navBottom button#tab-userSettings.settingsIconBtn::before{content:'⚙'!important;font-size:25px!important}.navBottom button#logout.logoutIcon::before{content:'↪'!important;font-size:27px!important;transform:rotate(180deg)!important}.navBottomIcon:hover,.settingsIconBtn.active{background:var(--sideHover)!important}.railUser .avatarMini{display:block!important;width:34px!important;height:34px!important;border-radius:50%!important;object-fit:cover!important}.railUser .avatarMini.hidden{display:none!important}.railUserName{display:none!important}.railUser .avatarMini.hidden+.railUserName{display:grid!important;width:34px!important;height:34px!important;border-radius:50%!important;place-items:center!important;background:var(--sideHover)!important;color:var(--sideText)!important;font-size:0!important}.railUser .avatarMini.hidden+.railUserName::before{content:'●'!important;font-size:22px!important;color:var(--sideText)!important}.brandCluster .themeLogo.brandLogo{width:auto!important;height:auto!important;max-width:calc(var(--leftPaneW) - 16px)!important;max-height:74px!important;object-fit:contain!important;object-position:left center!important;aspect-ratio:auto!important;transform:none!important}.brandCluster .darkLogo.brandLogo{max-width:calc(var(--leftPaneW) - 16px)!important;max-height:74px!important;width:auto!important;height:auto!important;object-fit:contain!important;aspect-ratio:auto!important;background:transparent!important}.loginBrand .darkLogo.loginHeroLogo{width:min(560px,90vw)!important;max-width:560px!important;height:auto!important;object-fit:contain!important;aspect-ratio:auto!important}.authLogo .darkLogo{max-width:280px!important;height:auto!important;object-fit:contain!important;aspect-ratio:auto!important}@media(max-width:900px){.topMenuCollapse,#mainNavCollapse.topMenuCollapse{position:relative!important}.navBottom{grid-template-columns:repeat(4,42px)!important}.brandCluster .darkLogo.brandLogo{max-width:220px!important}}



/* 2026-07 bottom-admin-arrow-v12: one clean bottom utility row and right-aligned Admin Settings chevron. */
.topMenuCollapse,#mainNavCollapse.topMenuCollapse{position:relative!important;left:auto!important;top:auto!important;width:34px!important;height:34px!important;min-height:34px!important;display:grid!important;place-items:center!important;font-size:0!important;color:transparent!important;text-indent:0!important;overflow:hidden!important;background:transparent!important;border:1px solid var(--railDivider)!important;box-shadow:none!important}.topMenuCollapse::before,#mainNavCollapse.topMenuCollapse::before{content:'⋯'!important;display:block!important;color:var(--sideText)!important;font-family:Inter,system-ui,sans-serif!important;font-size:28px!important;font-weight:850!important;line-height:1!important;text-indent:0!important;transform:none!important;background:transparent!important;mask:none!important;-webkit-mask:none!important}.mainNav button.navGroup::after{display:none!important}.mainNav button#tab-adminSettings.navGroup{width:100%!important;display:flex!important;align-items:center!important;justify-content:flex-start!important;gap:12px!important;position:relative!important;padding-right:14px!important;text-align:left!important}.mainNav button#tab-adminSettings.navGroup::after{content:'›'!important;display:block!important;position:static!important;margin-left:auto!important;flex:0 0 auto!important;transform:none!important;font-family:Inter,system-ui,sans-serif!important;font-size:28px!important;font-weight:850!important;line-height:1!important;color:var(--sideText)!important;background:transparent!important;width:auto!important;height:auto!important;opacity:.95!important}.mainNav button#tab-adminSettings.navGroup.active::after{content:'⌄'!important;font-size:24px!important;transform:none!important}.mainNav.collapsed button#tab-adminSettings.navGroup::after{display:none!important}.navBottom{display:grid!important;grid-template-columns:36px 36px 36px 36px!important;gap:8px!important;justify-content:center!important;align-items:center!important;padding:10px 8px!important;margin-top:auto!important}.navBottom .hidden,.navBottom button.hidden,.navBottom .railUser.hidden{display:grid!important}.railUser{order:1!important;width:36px!important;height:36px!important;min-width:36px!important;max-width:36px!important;display:grid!important;place-items:center!important;overflow:hidden!important;pointer-events:none!important}.navBottom #theme{order:2!important}.settingsIconBtn{order:3!important}.logoutIcon{order:4!important}.navBottomIcon,.navBottom button.navBottomIcon{width:36px!important;height:36px!important;min-width:36px!important;max-width:36px!important;min-height:36px!important;display:grid!important;place-items:center!important;padding:0!important;margin:0!important;border:0!important;border-radius:8px!important;background:transparent!important;color:transparent!important;font-size:0!important;line-height:0!important;text-indent:-9999px!important;overflow:hidden!important;opacity:1!important}.navBottomIcon::before,.navBottomIcon::after{box-sizing:border-box!important}.navBottom button#theme.navBottomIcon::after,.navBottom button#tab-userSettings.settingsIconBtn::after,.navBottom button#logout.logoutIcon::after{content:''!important;display:block!important;width:23px!important;height:23px!important;background-color:var(--sideText)!important;background-repeat:no-repeat!important;background-position:center!important;background-size:contain!important;color:var(--sideText)!important;text-indent:0!important;line-height:1!important;mask-repeat:no-repeat!important;mask-position:center!important;mask-size:contain!important;-webkit-mask-repeat:no-repeat!important;-webkit-mask-position:center!important;-webkit-mask-size:contain!important}.navBottom button#theme.navBottomIcon::before,.navBottom button#tab-userSettings.settingsIconBtn::before,.navBottom button#logout.logoutIcon::before{content:''!important;display:none!important}.navBottom button#theme.navBottomIcon::after{mask-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='black' d='M12 2a10 10 0 1 0 0 20V2Zm0 2.2v15.6a7.8 7.8 0 0 1 0-15.6Z'/%3E%3C/svg%3E")!important;-webkit-mask-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='black' d='M12 2a10 10 0 1 0 0 20V2Zm0 2.2v15.6a7.8 7.8 0 0 1 0-15.6Z'/%3E%3C/svg%3E")!important}.navBottom button#tab-userSettings.settingsIconBtn::after{mask-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='black' d='M19.43 12.98c.04-.32.07-.65.07-.98s-.02-.66-.07-.98l2.11-1.65a.5.5 0 0 0 .12-.64l-2-3.46a.5.5 0 0 0-.6-.22l-2.49 1a7.28 7.28 0 0 0-1.69-.98L14.5 2.42A.5.5 0 0 0 14 2h-4a.5.5 0 0 0-.49.42L9.13 5.07c-.61.24-1.18.56-1.69.98l-2.49-1a.5.5 0 0 0-.6.22l-2 3.46a.5.5 0 0 0 .12.64l2.11 1.65c-.04.32-.08.65-.08.98s.03.66.08.98l-2.11 1.65a.5.5 0 0 0-.12.64l2 3.46c.13.22.39.31.61.22l2.49-1c.51.4 1.07.73 1.68.98l.38 2.65c.04.24.25.42.49.42h4c.24 0 .45-.18.49-.42l.38-2.65c.61-.25 1.18-.58 1.69-.98l2.49 1c.22.09.48 0 .6-.22l2-3.46a.5.5 0 0 0-.12-.64l-2.11-1.65ZM12 15.5A3.5 3.5 0 1 1 12 8a3.5 3.5 0 0 1 0 7.5Z'/%3E%3C/svg%3E")!important;-webkit-mask-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='black' d='M19.43 12.98c.04-.32.07-.65.07-.98s-.02-.66-.07-.98l2.11-1.65a.5.5 0 0 0 .12-.64l-2-3.46a.5.5 0 0 0-.6-.22l-2.49 1a7.28 7.28 0 0 0-1.69-.98L14.5 2.42A.5.5 0 0 0 14 2h-4a.5.5 0 0 0-.49.42L9.13 5.07c-.61.24-1.18.56-1.69.98l-2.49-1a.5.5 0 0 0-.6.22l-2 3.46a.5.5 0 0 0 .12.64l2.11 1.65c-.04.32-.08.65-.08.98s.03.66.08.98l-2.11 1.65a.5.5 0 0 0-.12.64l2 3.46c.13.22.39.31.61.22l2.49-1c.51.4 1.07.73 1.68.98l.38 2.65c.04.24.25.42.49.42h4c.24 0 .45-.18.49-.42l.38-2.65c.61-.25 1.18-.58 1.69-.98l2.49 1c.22.09.48 0 .6-.22l2-3.46a.5.5 0 0 0-.12-.64l-2.11-1.65ZM12 15.5A3.5 3.5 0 1 1 12 8a3.5 3.5 0 0 1 0 7.5Z'/%3E%3C/svg%3E")!important}.navBottom button#logout.logoutIcon::after{mask-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='black' d='M5 21a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h7v2H5v14h7v2H5Zm11-4-1.4-1.45L17.15 13H9v-2h8.15L14.6 8.45 16 7l5 5-5 5Z'/%3E%3C/svg%3E")!important;-webkit-mask-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='black' d='M5 21a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h7v2H5v14h7v2H5Zm11-4-1.4-1.45L17.15 13H9v-2h8.15L14.6 8.45 16 7l5 5-5 5Z'/%3E%3C/svg%3E")!important}.navBottomIcon:hover,.settingsIconBtn.active{background:var(--sideHover)!important}.railUser .avatarMini{display:block!important;width:32px!important;height:32px!important;border-radius:50%!important;object-fit:cover!important}.railUser .avatarMini.hidden{display:none!important}.railUserName{display:none!important}.mainNav.collapsed .navBottom{grid-template-columns:1fr!important}.mainNav.collapsed .railUser,.mainNav.collapsed .navBottomIcon{width:42px!important;justify-self:center!important}


/* 2026-07 stable-admin-theme-logo-v13: deterministic Admin group state, compact dark logo, labeled theme row, centered bottom utilities. */
.mainNav button#tab-adminSettings.navGroup,
.mainNav button#tab-adminSettings.navGroup.active,
.mainNav button#tab-adminSettings.navGroup.expanded{
  width:100%!important;display:flex!important;align-items:center!important;justify-content:flex-start!important;
  gap:12px!important;position:relative!important;padding-right:14px!important;text-align:left!important;
}
.mainNav button#tab-adminSettings.navGroup::after,
.mainNav button#tab-adminSettings.navGroup.active::after,
.mainNav button#tab-adminSettings.navGroup.expanded::after{
  content:'›'!important;display:block!important;position:static!important;margin-left:auto!important;flex:0 0 24px!important;
  width:24px!important;height:24px!important;line-height:24px!important;text-align:center!important;
  font-family:Inter,system-ui,sans-serif!important;font-size:24px!important;font-weight:800!important;color:var(--sideText)!important;
  transform:rotate(0deg)!important;transition:transform .16s ease!important;background:transparent!important;
}
.mainNav button#tab-adminSettings.navGroup.expanded::after{transform:rotate(90deg)!important}
.mainNav.collapsed button#tab-adminSettings.navGroup::after{display:none!important}
.themeRailControl{
  order:90!important;margin-top:auto!important;margin-left:10px!important;margin-right:10px!important;margin-bottom:8px!important;
  width:calc(100% - 20px)!important;min-height:42px!important;padding:9px 12px!important;border:1px solid var(--railDivider)!important;
  border-radius:9px!important;background:transparent!important;color:var(--sideText)!important;display:flex!important;align-items:center!important;
  justify-content:flex-start!important;gap:10px!important;font-size:14px!important;font-weight:650!important;text-align:left!important;
}
.themeRailControl:hover{background:var(--sideHover)!important}.themeRailIcon{width:21px!important;height:21px!important;flex:0 0 21px!important;
  background-color:var(--sideText)!important;mask-repeat:no-repeat!important;mask-position:center!important;mask-size:contain!important;
  -webkit-mask-repeat:no-repeat!important;-webkit-mask-position:center!important;-webkit-mask-size:contain!important;
  mask-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='black' d='M12 2a10 10 0 1 0 0 20V2Zm0 2.2v15.6a7.8 7.8 0 0 1 0-15.6Z'/%3E%3C/svg%3E")!important;
  -webkit-mask-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='black' d='M12 2a10 10 0 1 0 0 20V2Zm0 2.2v15.6a7.8 7.8 0 0 1 0-15.6Z'/%3E%3C/svg%3E")!important;
}
.navBottom{order:91!important;display:grid!important;grid-template-columns:repeat(3,40px)!important;gap:10px!important;justify-content:center!important;align-items:center!important;width:100%!important;padding:8px 10px 12px!important;margin:0!important}
.navBottom .railUser,.navBottom .navBottomIcon{justify-self:center!important;align-self:center!important}
.navBottom #theme{display:none!important}.navBottomIcon,.navBottom button.navBottomIcon{width:40px!important;height:40px!important;min-width:40px!important;max-width:40px!important;min-height:40px!important;margin:0!important}
body.mainNavCollapsed .themeRailControl,.mainNav.collapsed .themeRailControl{width:42px!important;min-width:42px!important;max-width:42px!important;margin-left:auto!important;margin-right:auto!important;padding:10px!important;justify-content:center!important}
body.mainNavCollapsed .themeRailControl #themeLabel,.mainNav.collapsed .themeRailControl #themeLabel{display:none!important}
.mainNav.collapsed .navBottom{grid-template-columns:1fr!important;gap:7px!important;padding-left:0!important;padding-right:0!important}
img.themeLogo,img.brandLogo,img.loginHeroLogo,.authLogo img,.loginBrand img{height:auto!important;object-fit:contain!important;object-position:center!important;aspect-ratio:auto!important;flex:0 0 auto!important;transform:none!important}
body:not(.light) .brandCluster .darkLogo.brandLogo{display:block!important;width:66px!important;max-width:66px!important;height:66px!important;max-height:66px!important;object-fit:contain!important;object-position:center!important;margin-left:8px!important;background:transparent!important}
body:not(.light) .loginBrand .darkLogo.loginHeroLogo{display:block!important;width:150px!important;max-width:150px!important;height:auto!important;max-height:140px!important;object-fit:contain!important;margin:0 auto!important}
body:not(.light) .authLogo .darkLogo{display:block!important;width:92px!important;max-width:92px!important;height:auto!important;max-height:86px!important;object-fit:contain!important}
body.mainNavCollapsed:not(.light) .brandCluster .darkLogo.brandLogo{width:52px!important;max-width:52px!important;height:52px!important;max-height:52px!important;margin:0 auto!important}
#loginView.hidden,#setupView.hidden,#appView.hidden{display:none!important;visibility:hidden!important}


/* 2026-07 top-utilities-acl-dark-logo-v14: readable dark wordmark, tab-scoped ACL, original top-right utilities. */
#rulesView.hidden,#accessView.hidden,#mcpView.hidden,#settingsView.hidden,#cards.hidden,.cards.hidden{display:none!important;visibility:hidden!important}
#rulesView:not(.hidden),#accessView:not(.hidden),#mcpView:not(.hidden),#settingsView:not(.hidden){visibility:visible!important}
.themeRailControl,.navBottom{display:none!important}
.actions.topUtilities{display:flex!important;align-items:center!important;justify-content:flex-end!important;gap:8px!important;padding:0 12px 0 8px!important;min-width:0!important}
.topUtilities .topUtilityButton{display:inline-flex!important;align-items:center!important;justify-content:center!important;gap:8px!important;min-height:38px!important;padding:8px 11px!important;border:1px solid var(--railDivider)!important;border-radius:8px!important;background:transparent!important;color:var(--sideText)!important;font-size:13px!important;font-weight:650!important;line-height:1!important;white-space:nowrap!important;box-shadow:none!important}
.topUtilities .topUtilityButton:hover{background:var(--sideHover)!important;color:var(--sideText)!important}
.topUtilities .topUtilityButton.hidden{display:none!important}.topUtilities .themeRailIcon,.topUtilities .topSettingsIcon,.topUtilities .topLogoutIcon{display:block!important;width:20px!important;height:20px!important;flex:0 0 20px!important;background-color:var(--sideText)!important;mask-repeat:no-repeat!important;mask-position:center!important;mask-size:contain!important;-webkit-mask-repeat:no-repeat!important;-webkit-mask-position:center!important;-webkit-mask-size:contain!important}
.topUtilities .topSettingsIcon{mask-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='black' d='M19.43 12.98c.04-.32.07-.65.07-.98s-.02-.66-.07-.98l2.11-1.65a.5.5 0 0 0 .12-.64l-2-3.46a.5.5 0 0 0-.6-.22l-2.49 1a7.3 7.3 0 0 0-1.69-.98L14.5 2.42A.5.5 0 0 0 14 2h-4a.5.5 0 0 0-.49.42L9.13 5.07c-.61.24-1.18.56-1.69.98l-2.49-1a.5.5 0 0 0-.6.22l-2 3.46a.5.5 0 0 0 .12.64l2.11 1.65c-.04.32-.08.65-.08.98s.03.66.08.98l-2.11 1.65a.5.5 0 0 0-.12.64l2 3.46c.13.22.39.31.61.22l2.49-1c.51.4 1.07.73 1.68.98l.38 2.65c.04.24.25.42.49.42h4c.24 0 .45-.18.49-.42l.38-2.65c.61-.25 1.18-.58 1.69-.98l2.49 1c.22.09.48 0 .6-.22l2-3.46a.5.5 0 0 0-.12-.64l-2.11-1.65ZM12 15.5A3.5 3.5 0 1 1 12 8a3.5 3.5 0 0 1 0 7.5Z'/%3E%3C/svg%3E")!important;-webkit-mask-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='black' d='M19.43 12.98c.04-.32.07-.65.07-.98s-.02-.66-.07-.98l2.11-1.65a.5.5 0 0 0 .12-.64l-2-3.46a.5.5 0 0 0-.6-.22l-2.49 1a7.3 7.3 0 0 0-1.69-.98L14.5 2.42A.5.5 0 0 0 14 2h-4a.5.5 0 0 0-.49.42L9.13 5.07c-.61.24-1.18.56-1.69.98l-2.49-1a.5.5 0 0 0-.6.22l-2 3.46a.5.5 0 0 0 .12.64l2.11 1.65c-.04.32-.08.65-.08.98s.03.66.08.98l-2.11 1.65a.5.5 0 0 0-.12.64l2 3.46c.13.22.39.31.61.22l2.49-1c.51.4 1.07.73 1.68.98l.38 2.65c.04.24.25.42.49.42h4c.24 0 .45-.18.49-.42l.38-2.65c.61-.25 1.18-.58 1.69-.98l2.49 1c.22.09.48 0 .6-.22l2-3.46a.5.5 0 0 0-.12-.64l-2.11-1.65ZM12 15.5A3.5 3.5 0 1 1 12 8a3.5 3.5 0 0 1 0 7.5Z'/%3E%3C/svg%3E")!important}
.topUtilities .topLogoutIcon{mask-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='black' d='M5 21a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h7v2H5v14h7v2H5Zm11-4-1.4-1.45L17.15 13H9v-2h8.15L14.6 8.45 16 7l5 5-5 5Z'/%3E%3C/svg%3E")!important;-webkit-mask-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='black' d='M5 21a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h7v2H5v14h7v2H5Zm11-4-1.4-1.45L17.15 13H9v-2h8.15L14.6 8.45 16 7l5 5-5 5Z'/%3E%3C/svg%3E")!important}
body.authing .topUtilities .settingsTopControl,body.authing .topUtilities .logoutTopControl{display:none!important}
body:not(.light) .brandCluster .darkLogo.brandLogo{display:block!important;width:236px!important;max-width:calc(var(--leftPaneW) - 16px)!important;height:auto!important;max-height:68px!important;object-fit:contain!important;object-position:left center!important;margin:0!important;background:transparent!important}
body:not(.light) .loginBrand .darkLogo.loginHeroLogo{display:block!important;width:min(500px,88vw)!important;max-width:500px!important;height:auto!important;max-height:none!important;object-fit:contain!important;margin:0 auto!important}
body:not(.light) .authLogo .darkLogo{display:block!important;width:290px!important;max-width:290px!important;height:auto!important;max-height:none!important;object-fit:contain!important}
body.mainNavCollapsed:not(.light) .brandCluster .darkLogo.brandLogo{display:none!important}
@media(max-width:900px){.topUtilities .topUtilityButton span:last-child{display:none!important}.topUtilities .topUtilityButton{width:38px!important;padding:8px!important}.actions.topUtilities{gap:4px!important;padding-right:6px!important}}


/* 2026-07 avatar-hover-menu-theme-icon-v15: icon-only theme, hover avatar menu, vertical ellipsis. */
.topMenuCollapse::before,#mainNavCollapse.topMenuCollapse::before{content:'⋮'!important;font-size:28px!important;line-height:1!important;letter-spacing:0!important;transform:none!important}
.actions.topUtilities{display:flex!important;align-items:center!important;justify-content:flex-end!important;gap:9px!important;overflow:visible!important}
.topUtilities .themeTopControl{width:40px!important;min-width:40px!important;max-width:40px!important;height:40px!important;min-height:40px!important;padding:0!important;display:grid!important;place-items:center!important;border-radius:9px!important}
.themeTopIcon{display:block!important;width:24px!important;height:24px!important;position:relative!important;color:var(--sideText)!important}
.themeTopIcon::before{display:block!important;width:24px!important;height:24px!important;text-align:center!important;font-family:Inter,system-ui,sans-serif!important;font-size:24px!important;font-weight:700!important;line-height:24px!important;color:var(--sideText)!important}
#theme[data-theme="dark"] .themeTopIcon::before{content:'☾'!important}
#theme[data-theme="light"] .themeTopIcon::before{content:'☀'!important;font-size:23px!important}
.topUserMenu{position:relative!important;display:block!important;width:42px!important;height:42px!important;overflow:visible!important}
.topUserMenu.hidden{display:none!important}
.topAvatarButton{width:42px!important;height:42px!important;min-height:42px!important;padding:0!important;border-radius:50%!important;border:1px solid var(--railDivider)!important;background:transparent!important;color:var(--sideText)!important;display:grid!important;place-items:center!important;overflow:hidden!important;box-shadow:none!important}
.topAvatarButton:hover,.topUserMenu:focus-within .topAvatarButton{background:var(--sideHover)!important}
.topAvatarButton .avatarMini{width:36px!important;height:36px!important;border-radius:50%!important;object-fit:cover!important;display:block!important}
.topAvatarButton .avatarMini.hidden{display:none!important}
.topAvatarFallback{display:none!important;width:36px!important;height:36px!important;border-radius:50%!important;background:var(--sideHover)!important;place-items:center!important}
.topAvatarButton .avatarMini.hidden + .topAvatarFallback{display:grid!important}
.topAvatarFallback::before{content:'●'!important;font-size:22px!important;line-height:1!important;color:var(--sideText)!important}
.srOnly{position:absolute!important;width:1px!important;height:1px!important;padding:0!important;margin:-1px!important;overflow:hidden!important;clip:rect(0,0,0,0)!important;white-space:nowrap!important;border:0!important}
.topUserDropdown{position:absolute!important;top:calc(100% + 8px)!important;right:0!important;z-index:1800!important;min-width:190px!important;padding:6px!important;border:1px solid var(--line)!important;border-radius:10px!important;background:var(--surface)!important;box-shadow:0 16px 38px rgba(0,0,0,.28)!important;display:grid!important;gap:3px!important;opacity:0!important;visibility:hidden!important;pointer-events:none!important;transform:translateY(-5px)!important;transition:opacity .14s ease,transform .14s ease,visibility .14s ease!important}
.topUserMenu:hover .topUserDropdown,.topUserMenu:focus-within .topUserDropdown{opacity:1!important;visibility:visible!important;pointer-events:auto!important;transform:translateY(0)!important}
.topUserMenuItem{width:100%!important;min-height:40px!important;padding:9px 11px!important;border:0!important;border-radius:7px!important;background:transparent!important;color:var(--text)!important;display:flex!important;align-items:center!important;justify-content:flex-start!important;gap:10px!important;text-align:left!important;font-size:14px!important;font-weight:600!important;white-space:nowrap!important}
.topUserMenuItem:hover,.topUserMenuItem.active{background:var(--elev)!important;color:var(--text)!important}
.topUserMenuItem.hidden{display:none!important}
.topUserMenuItem .topSettingsIcon,.topUserMenuItem .topLogoutIcon{display:block!important;width:20px!important;height:20px!important;flex:0 0 20px!important;background-color:var(--text)!important;mask-repeat:no-repeat!important;mask-position:center!important;mask-size:contain!important;-webkit-mask-repeat:no-repeat!important;-webkit-mask-position:center!important;-webkit-mask-size:contain!important}
body.authing .topUserMenu{display:none!important}
@media(max-width:900px){.topUtilities .themeTopControl{width:38px!important;min-width:38px!important;max-width:38px!important}.topUserMenu,.topAvatarButton{width:38px!important;height:38px!important}.topAvatarButton .avatarMini,.topAvatarFallback{width:34px!important;height:34px!important}}


/* 2026-07 borderless-theme-blended-rail-hamburger-v16: borderless theme icon, soft rail transition, three-line menu control. */
.topUtilities .themeTopControl{border:0!important;outline:0!important;box-shadow:none!important;background:transparent!important}
.topUtilities .themeTopControl:hover,.topUtilities .themeTopControl:focus-visible{border:0!important;box-shadow:none!important;background:var(--sideHover)!important}
.mainNav{border-right:0!important;border-left:0!important;box-shadow:10px 0 26px rgba(0,0,0,.18)!important}
body.light .mainNav{border-right:0!important;border-left:0!important;box-shadow:10px 0 28px rgba(32,45,64,.07)!important}
.brandCluster,.brandCluster .brand{border-right:0!important;box-shadow:none!important}
.topMenuCollapse::before,#mainNavCollapse.topMenuCollapse::before{content:''!important;display:block!important;width:20px!important;height:2px!important;border:0!important;border-radius:2px!important;background:var(--sideText)!important;box-shadow:0 6px 0 var(--sideText),0 12px 0 var(--sideText)!important;transform:translateY(-6px)!important;font-size:0!important;line-height:0!important}


/* 2026-07 settings-hamburger-login-dashboard-logos-v17: concise Settings label, borderless aligned menu, split login/dashboard dark assets. */
.topMenuCollapse,#mainNavCollapse.topMenuCollapse{border:0!important;outline:0!important;box-shadow:none!important;margin:0!important;align-self:center!important;justify-self:start!important;width:38px!important;height:38px!important;min-height:38px!important;padding:0!important;background:transparent!important}
.topMenuCollapse:hover,#mainNavCollapse.topMenuCollapse:hover{border:0!important;box-shadow:none!important;background:var(--sideHover)!important}
.topWorkspace{display:flex!important;align-items:center!important;justify-content:flex-start!important;gap:10px!important;height:var(--topBarH)!important;padding-top:0!important;padding-bottom:0!important}
.topWorkspace .welcomeName{display:flex!important;align-items:center!important;min-height:38px!important;line-height:38px!important;margin:0!important}
.topMenuCollapse::before,#mainNavCollapse.topMenuCollapse::before{transform:translateY(-6px)!important}
body:not(.light) .brandCluster .darkLogo.brandLogo{display:block!important;width:236px!important;max-width:calc(var(--leftPaneW) - 16px)!important;height:auto!important;max-height:76px!important;object-fit:contain!important;object-position:left center!important;aspect-ratio:auto!important;margin:0!important;transform:none!important}
body:not(.light) .loginBrand .darkLogo.loginHeroLogo{display:block!important;width:164px!important;max-width:164px!important;height:auto!important;max-height:150px!important;object-fit:contain!important;object-position:center!important;aspect-ratio:auto!important;margin:0 auto!important;transform:none!important}


/* 2026-07 text-brand-centered-menu-v18: no dashboard/setup images, Google-color text brand, exact Welcome alignment. */
.brandCluster img,.brandCluster .brandLogo,.authLogo img{display:none!important}
.brandCluster .textBrandLink{display:flex!important;align-items:center!important;width:100%!important;height:var(--topBarH)!important;padding:0 12px!important;overflow:hidden!important;text-decoration:none!important;background:transparent!important}
.googleTextBrand{display:flex!important;align-items:baseline!important;white-space:nowrap!important;font-family:Arial,"Helvetica Neue",sans-serif!important;font-size:19px!important;font-weight:700!important;line-height:1!important;letter-spacing:-.025em!important}
.googleTextBrand .brandGap{margin-left:5px!important}
.gBlue{color:#4285F4!important}.gRed{color:#EA4335!important}.gYellow{color:#FBBC05!important}.gGreen{color:#34A853!important}
body.mainNavCollapsed .googleTextBrand{display:none!important}
.topWorkspace{display:grid!important;grid-template-columns:38px minmax(0,1fr)!important;align-items:center!important;justify-content:start!important;column-gap:10px!important;height:var(--topBarH)!important;padding:0!important}
.topMenuCollapse,#mainNavCollapse.topMenuCollapse{position:relative!important;display:block!important;width:38px!important;height:38px!important;min-height:38px!important;margin:0!important;padding:0!important;align-self:center!important;justify-self:center!important;border:0!important}
.topMenuCollapse::before,#mainNavCollapse.topMenuCollapse::before{position:absolute!important;left:50%!important;top:50%!important;margin:0!important;transform:translate(-50%,-7px)!important}
.topWorkspace .welcomeName{display:flex!important;align-items:center!important;align-self:center!important;height:38px!important;min-height:38px!important;line-height:1.2!important;margin:0!important;padding:0!important}
@media(max-width:900px){.googleTextBrand{font-size:17px!important}.brandCluster .textBrandLink{padding:0 8px!important}}


/* 2026-07 randomized-brand-single-cog-login-theme-v19: mixed Google colors, one cog, login-only chrome/theme/full logos. */
#tab-userSettings::before{content:none!important;display:none!important;width:0!important;height:0!important;margin:0!important}
body.authing header{display:none!important;visibility:hidden!important;height:0!important;min-height:0!important}
body.authing main{padding-top:0!important;margin-top:0!important}
body.authing #loginView:not(.hidden){min-height:100svh!important;padding-top:24px!important;padding-bottom:24px!important}
#loginTheme.loginThemeControl{display:grid!important;place-items:center!important;justify-self:center!important;width:42px!important;min-width:42px!important;max-width:42px!important;height:42px!important;min-height:42px!important;margin:4px auto 0!important;padding:0!important;border:0!important;outline:0!important;border-radius:9px!important;background:transparent!important;box-shadow:none!important;color:var(--text)!important}
#loginTheme.loginThemeControl:hover,#loginTheme.loginThemeControl:focus-visible{border:0!important;background:var(--surface2)!important;box-shadow:none!important}
#loginTheme[data-theme="dark"] .themeTopIcon::before{content:'☾'!important;color:var(--text)!important}
#loginTheme[data-theme="light"] .themeTopIcon::before{content:'☀'!important;color:var(--text)!important;font-size:23px!important}
.loginBrand img.lightLogo.loginHeroLogo,.loginBrand img.darkLogo.loginHeroLogo,body:not(.light) .loginBrand .darkLogo.loginHeroLogo{width:min(470px,86vw)!important;max-width:470px!important;height:auto!important;max-height:150px!important;object-fit:contain!important;object-position:center!important;aspect-ratio:auto!important;margin:0 auto!important;transform:none!important}
@media(max-width:520px){.loginBrand img.lightLogo.loginHeroLogo,.loginBrand img.darkLogo.loginHeroLogo,body:not(.light) .loginBrand .darkLogo.loginHeroLogo{width:min(330px,86vw)!important;max-width:330px!important}}


/* 2026-07 three-word-brand-attached-dark-login-v20: black-blue-black / white-blue-white brand and matched dark login canvas. */
.googleTextBrand .brandWord{display:inline-block!important;margin:0!important}
.googleTextBrand .brandWord+.brandWord{margin-left:5px!important}
body.light .googleTextBrand .brandGoogle,body.light .googleTextBrand .brandGateway{color:#111111!important}
body.light .googleTextBrand .brandAgent{color:#1a73e8!important}
body:not(.light) .googleTextBrand .brandGoogle,body:not(.light) .googleTextBrand .brandGateway{color:#f8fafc!important}
body:not(.light) .googleTextBrand .brandAgent{color:#1a73e8!important}
body:not(.light).authing,body:not(.light).authing main,body:not(.light).authing #loginView:not(.hidden){background:#0c1723!important}
body:not(.light).authing #loginView .loginPanel,body:not(.light).authing #loginView .authCard{background:#0c1723!important}
body:not(.light).authing #loginView .authCard{border-color:#243548!important;box-shadow:0 22px 54px rgba(0,0,0,.32)!important}
body:not(.light).authing #loginView input{background:#111f2d!important;border-color:#2a3d52!important}
body:not(.light).authing #loginView .loginBrand{background:#0c1723!important}


/* 2026-07 exact-supplied-login-image-v21: use the user's attached image unchanged apart from outer whitespace crop. */
body.authing #loginView .loginBrand,body.light.authing #loginView .loginBrand,body:not(.light).authing #loginView .loginBrand{display:flex!important;align-items:center!important;justify-content:center!important;width:100%!important;max-width:500px!important;margin:0 auto 18px!important;padding:10px 14px!important;background:#ffffff!important;border:0!important;border-radius:12px!important;box-shadow:none!important;overflow:hidden!important}
body.authing #loginView .loginBrand img.loginHeroLogo,body.light.authing #loginView .loginBrand img.loginHeroLogo,body:not(.light).authing #loginView .loginBrand img.loginHeroLogo{display:block!important;width:min(470px,82vw)!important;max-width:100%!important;height:auto!important;max-height:none!important;object-fit:contain!important;object-position:center!important;aspect-ratio:auto!important;margin:0 auto!important;transform:none!important;background:#ffffff!important}
@media(max-width:520px){body.authing #loginView .loginBrand{padding:8px!important}body.authing #loginView .loginBrand img.loginHeroLogo{width:min(340px,80vw)!important}}


/* 2026-07 login-light-dark-parity-v22: identical login layout in both themes; only palette changes. */
body.authing,body.authing main,body.authing #loginView:not(.hidden){background:var(--bg)!important;color:var(--text)!important}
body.authing #loginView:not(.hidden),body.light.authing #loginView:not(.hidden),body:not(.light).authing #loginView:not(.hidden){display:grid!important;grid-template-columns:1fr!important;place-items:center!important;min-height:100svh!important;padding:24px!important;margin:0!important}
body.authing #loginView .loginPanel,body.light.authing #loginView .loginPanel,body:not(.light).authing #loginView .loginPanel{width:min(560px,100%)!important;margin:0 auto!important;display:flex!important;justify-content:center!important;align-items:center!important;background:transparent!important}
body.authing #loginView .authCard,body.light.authing #loginView .authCard,body:not(.light).authing #loginView .authCard{width:100%!important;box-sizing:border-box!important;padding:34px 34px 30px!important;border-radius:18px!important;background:var(--surface)!important;color:var(--text)!important;border:1px solid var(--line)!important;box-shadow:var(--shadow)!important}
body.authing #loginView .authTitle,body.light.authing #loginView .authTitle,body:not(.light).authing #loginView .authTitle{margin:0 0 18px!important;text-align:left!important;color:var(--text)!important;font-size:28px!important;line-height:1.15!important;font-weight:800!important;letter-spacing:-.02em!important}
body.authing #loginView .authGrid,body.light.authing #loginView .authGrid,body:not(.light).authing #loginView .authGrid{display:grid!important;grid-template-columns:1fr!important;gap:12px!important;width:100%!important}
body.authing #loginView input,body.light.authing #loginView input,body:not(.light).authing #loginView input{width:100%!important;box-sizing:border-box!important;background:var(--input)!important;color:var(--text)!important;border:1px solid var(--line)!important;border-radius:10px!important;min-height:46px!important;padding:0 14px!important;box-shadow:none!important}
body.authing #loginView input::placeholder{color:var(--muted)!important}
body.authing #loginView #loginBtn,body.light.authing #loginView #loginBtn,body:not(.light).authing #loginView #loginBtn,body.authing #loginView #oidcLoginBtn,body.light.authing #loginView #oidcLoginBtn,body:not(.light).authing #loginView #oidcLoginBtn{width:100%!important;min-height:46px!important;border-radius:10px!important;margin:0!important;box-sizing:border-box!important}
body.authing #loginView .loginBrand,body.light.authing #loginView .loginBrand,body:not(.light).authing #loginView .loginBrand{display:flex!important;align-items:center!important;justify-content:center!important;width:100%!important;max-width:500px!important;margin:0 auto 22px!important;padding:10px 14px!important;background:#ffffff!important;border:0!important;border-radius:12px!important;box-shadow:none!important;overflow:hidden!important}
body.authing #loginView .loginBrand img.loginHeroLogo,body.light.authing #loginView .loginBrand img.loginHeroLogo,body:not(.light).authing #loginView .loginBrand img.loginHeroLogo{display:block!important;width:min(470px,82vw)!important;max-width:100%!important;height:auto!important;max-height:none!important;object-fit:contain!important;object-position:center!important;aspect-ratio:auto!important;margin:0 auto!important;transform:none!important;background:#ffffff!important}
body.authing #loginTheme.loginThemeControl,body.light.authing #loginTheme.loginThemeControl,body:not(.light).authing #loginTheme.loginThemeControl{display:grid!important;place-items:center!important;justify-self:center!important;width:42px!important;min-width:42px!important;max-width:42px!important;height:42px!important;min-height:42px!important;margin:4px auto 0!important;padding:0!important;border:0!important;outline:0!important;border-radius:10px!important;background:transparent!important;box-shadow:none!important;color:var(--text)!important}
body.authing #loginTheme.loginThemeControl:hover,body.authing #loginTheme.loginThemeControl:focus-visible{background:var(--surface2)!important;border:0!important;box-shadow:none!important}
@media(max-width:520px){body.authing #loginView:not(.hidden){padding:18px 12px!important}body.authing #loginView .authCard{padding:26px 18px 24px!important}body.authing #loginView .loginBrand{padding:8px!important}body.authing #loginView .loginBrand img.loginHeroLogo{width:min(340px,80vw)!important}}


/* 2026-07 supplied-light-dark-login-images-v23: use the two new attached login logos with identical geometry. */
body.light.authing #loginView .loginBrand{background:#ffffff!important;padding:10px 14px!important}
body:not(.light).authing #loginView .loginBrand{background:transparent!important;padding:10px 14px!important}
body.light.authing #loginView .loginBrand img.loginHeroLogo{background:#ffffff!important}
body:not(.light).authing #loginView .loginBrand img.loginHeroLogo{background:transparent!important}
body.authing #loginView .loginBrand img.loginHeroLogo{width:min(470px,82vw)!important;max-width:100%!important;height:auto!important;object-fit:contain!important;object-position:center!important;aspect-ratio:auto!important;margin:0 auto!important;transform:none!important}


/* 2026-07 no-bot-login-wordmark-v24: login logos are text-only in both themes; no robot/icon artwork. */
body.authing #loginView .loginBrand{max-width:500px!important}
body.authing #loginView .loginBrand img.loginHeroLogo{width:min(470px,82vw)!important}


/* 2026-07 single-theme-login-logo-v25: show exactly one login wordmark; background blends with theme. */
body.authing #loginView .loginBrand{display:flex!important;justify-content:flex-start!important;align-items:center!important;width:100%!important;max-width:100%!important;margin:0 0 22px!important;padding:0!important;background:transparent!important;border:0!important;box-shadow:none!important;overflow:visible!important}
body.authing #loginView .loginBrand > img.themeLogo.loginHeroLogo{width:min(470px,78vw)!important;max-width:100%!important;height:auto!important;max-height:none!important;object-fit:contain!important;object-position:left center!important;aspect-ratio:auto!important;margin:0!important;transform:none!important;background:transparent!important;display:none!important}
body.light.authing #loginView .loginBrand > img.themeLogo.lightLogo.loginHeroLogo{display:block!important}
body.light.authing #loginView .loginBrand > img.themeLogo.darkLogo.loginHeroLogo{display:none!important}
body:not(.light).authing #loginView .loginBrand > img.themeLogo.lightLogo.loginHeroLogo{display:none!important}
body:not(.light).authing #loginView .loginBrand > img.themeLogo.darkLogo.loginHeroLogo{display:block!important}
body.authing #loginView .loginBrand > span.loginHeroLogo{display:none!important}
body.light.authing #loginView .authCard{background:#ffffff!important;color:#111827!important}
body:not(.light).authing #loginView .authCard{background:#0f0f0f!important;color:#f8fafc!important}
body.light.authing #loginView:not(.hidden){background:#f6f6f6!important}
body:not(.light).authing #loginView:not(.hidden){background:#071522!important}
@media(max-width:520px){body.authing #loginView .loginBrand > img.themeLogo.loginHeroLogo{width:min(340px,82vw)!important}}


/* 2026-07 clean-dark-login-logo-v26: regenerated dark wordmark from vector text and cache-busted logo URLs. */
body:not(.light).authing #loginView .loginBrand > img.themeLogo.darkLogo.loginHeroLogo{filter:none!important;image-rendering:auto!important;mix-blend-mode:normal!important;opacity:1!important}
body:not(.light).authing #loginView .loginBrand{background:transparent!important}
body:not(.light).authing #loginView .authCard{background:#0f0f0f!important;border-color:#1f344a!important}

.actionBlurbs{display:grid!important;gap:6px!important}.mdiIcon{width:20px;height:20px;display:block;fill:currentColor}.scopeBtn{min-width:40px!important;width:40px!important;font-size:0!important;border-color:rgba(96,165,250,.55);color:#bfdbfe}.light .scopeBtn{color:#1d4ed8;border-color:#93c5fd}.workspaceStepTabs{display:grid!important;grid-template-columns:repeat(3,minmax(0,1fr))!important;gap:10px!important}.workspaceStepTabs button{justify-content:flex-start!important;text-align:left!important}.workspaceStepTabs .stepNum{display:inline-grid!important;place-items:center!important;width:24px!important;height:24px!important;margin-right:8px!important;border-radius:999px!important;background:var(--accent)!important;color:#fff!important;font-weight:800!important}#settingsNav-channels::before,#adminNav-channels::before{content:'💬'!important;display:inline-grid!important;place-items:center!important;width:24px!important;min-width:24px!important;height:24px!important;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif!important;font-size:18px!important;line-height:1!important}#appView>#approvalsView{grid-column:2!important;min-width:0!important;width:100%!important}#appView.mainNavCollapsed>#approvalsView{grid-column:2!important}.channelTabs{margin:10px 0 16px}.channelGrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(420px,100%),1fr));gap:16px;align-items:start}.channelCard h4,.comingSoon h4{margin-top:0}.channelForm{grid-template-columns:1fr!important}.fieldLabel small{display:block;color:var(--muted);font-size:12px;line-height:1.35;margin-top:5px}.comingSoon{min-height:220px;display:grid;align-content:center;text-align:center}.approvalToolbar{grid-template-columns:minmax(180px,240px) auto auto auto auto!important}.successBtn{background:#15803d!important;color:#fff!important;border-color:#166534!important}.dangerBtn{background:#b91c1c!important;color:#fff!important;border-color:#991b1b!important}.subtleDanger{background:transparent!important;color:#fca5a5!important}.iconDecision{min-width:34px!important;width:34px!important;height:32px!important;padding:0!important;border-radius:8px!important;font-size:17px!important}.mainNav button[data-icon]::before,.settingsSubnav button[data-icon]::before{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif!important;font-size:18px!important}.mainNav button[data-icon="policy"]::before{content:'🛡️'!important}.mainNav button[data-icon="shield"]::before,.settingsSubnav button[data-icon="shield"]::before{content:'🛡️'!important}.mainNav button[data-icon="article"]::before{content:'📜'!important}.mainNav button[data-icon="hub"]::before{content:'🔌'!important}.mainNav button[data-icon="admin_panel_settings"]::before{content:'⚙️'!important}.mainNav button[data-icon="manage_accounts"]::before{content:'👥'!important}.mainNav button[data-icon="cloud_sync"]::before{content:'☁️'!important}.mainNav button[data-icon="chat_bubble"]::before,.settingsSubnav button[data-icon="chat_bubble"]::before{content:'💬'!important}.mainNav button[data-icon="manufacturing"]::before{content:'🛠️'!important}.mainNav button[data-icon="vpn_key"]::before{content:'🔑'!important}@media(max-width:900px){.approvalToolbar{grid-template-columns:1fr!important}.channelGrid{grid-template-columns:1fr!important}}.channelSummaryGrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:12px 0 16px}.metricCard{border:1px solid var(--border);background:var(--panel);border-radius:14px;padding:14px}.metricLabel{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}.metricValue{font-size:20px;font-weight:700;margin-top:6px}.metricHint{font-size:12px;color:var(--muted);margin-top:5px}.compactDetails{margin-bottom:16px}.compactDetails>summary{cursor:pointer;font-weight:700}.simpleChannelForm{grid-template-columns:repeat(auto-fit,minmax(230px,1fr))!important;align-items:end}.simpleChannelForm .full{grid-column:1/-1}.formActions.full{grid-column:1/-1}.simpleChannelCard{margin-bottom:16px}.alphaBadge{display:inline-flex;align-items:center;border:1px solid rgba(251,191,36,.45);background:rgba(251,191,36,.14);color:#fbbf24;border-radius:999px;padding:1px 7px;margin-left:6px;font-size:11px;font-weight:800;line-height:1.4;text-transform:uppercase;letter-spacing:.06em}.light .alphaBadge{background:#fff7ed;color:#b45309;border-color:#fed7aa}.destinationPanel{margin:16px 0}.relaxedDetails{margin:16px 0!important;padding:0!important;overflow:hidden}.relaxedDetails>summary{display:flex!important;align-items:center!important;justify-content:space-between!important;gap:16px!important;padding:16px 18px!important;cursor:pointer;font-weight:800;list-style:none;border-radius:14px}.relaxedDetails>summary::-webkit-details-marker{display:none}.relaxedDetails>summary:after{content:'⌄';font-size:18px;color:var(--muted)}.relaxedDetails[open]>summary:after{content:'⌃'}.relaxedDetails>summary small{display:block;color:var(--muted);font-weight:500;font-size:13px;margin-top:3px}.relaxedDetails .detailBody{border-top:1px solid var(--line);padding:18px}.relaxedDetails .detailBody>.fieldLabel{max-width:680px}.relaxedDetails .detailBody>.primary{margin-top:12px}.switchRow,.miniSwitch{display:inline-flex;align-items:center;gap:10px;cursor:pointer}.switchRow input,.miniSwitch input{position:absolute;opacity:0;pointer-events:none}.switchTrack,.miniSwitch span{width:44px;height:24px;border-radius:999px;background:#4b5563;position:relative;display:inline-block;transition:.18s ease}.switchTrack:after,.miniSwitch span:after{content:'';position:absolute;width:18px;height:18px;left:3px;top:3px;border-radius:50%;background:#fff;transition:.18s ease;box-shadow:0 1px 4px rgba(0,0,0,.35)}.switchRow input:checked+.switchTrack,.miniSwitch input:checked+span{background:#15803d}.switchRow input:checked+.switchTrack:after,.miniSwitch input:checked+span:after{transform:translateX(20px)}.toggleMetric .switchRow{margin-top:6px}.toggleMetric .metricValue{margin:0}.miniSwitch b{font-size:13px;color:var(--muted);font-weight:700;min-width:62px}
/* 2026-07 ACL usability pass: same table type scale, catalog action tooltips, autosave controls. */
#rulesView table,#rulesView table th,#rulesView table td,#rulesView table td *,#rulesView select.inline{font-family:var(--uiFont)!important;font-size:var(--uiControl)!important;line-height:1.35!important;font-weight:500!important}
#rulesView .code{font-size:var(--uiControl)!important}#rulesView th:first-child,#rulesView td.selectCell{width:28px!important;min-width:28px!important;max-width:28px!important;padding-left:6px!important;padding-right:2px!important;text-align:center!important}.actionCell{display:inline-flex;align-items:center;gap:6px;min-width:0}.actionHelp{flex:0 0 auto;width:18px;height:18px;font-size:12px;font-weight:900;border:1px solid var(--line);border-radius:50%;display:inline-flex;align-items:center;justify-content:center;color:var(--muted);background:var(--surface2);cursor:help;font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;font-style:normal!important}.actionHelp:hover{color:var(--text);border-color:var(--muted)}button.resetFilters{white-space:nowrap}.detailModal{position:fixed;inset:0;z-index:2000;background:rgba(0,0,0,.62);display:flex;align-items:center;justify-content:center;padding:22px}.detailModal.hidden{display:none}.detailModalCard{width:min(920px,96vw);max-height:88vh;overflow:auto;background:var(--surface);border:1px solid var(--line);border-radius:18px;box-shadow:0 24px 90px rgba(0,0,0,.45);padding:18px}.detailModalHead{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}.detailModalHead h3{margin:0}.detailModalBody pre{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--surface2);border:1px solid var(--line);border-radius:12px;padding:12px;max-height:260px;overflow:auto}.detailGrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px;margin-bottom:14px}.detailGrid div{background:var(--surface2);border:1px solid var(--line);border-radius:10px;padding:9px}.detailGrid b{display:block;color:var(--muted);font-size:12px;margin-bottom:4px}.detailBtn{font-family:ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif;font-style:normal!important}.scopeInfo{font-size:13px!important;font-weight:700!important;font-style:normal!important}

/* 2026-07 access-log-acl-card-channel-polish: wider Actual access, consistent log font, clickable ACL metric cards, chat bubble channel icon. */
.aclMetricCard{text-align:left;width:100%;appearance:none}.aclMetricCard.filterable{cursor:pointer}.aclMetricCard.filterable:hover{border-color:var(--muted);background:var(--hover);color:var(--hoverText)}
.logTable{table-layout:fixed!important;width:100%!important}.logTable th,.logTable td,.logTable td *{font-family:var(--uiFont)!important;font-size:var(--uiControl)!important;line-height:1.35!important;font-weight:500!important}.logTable th:nth-child(2),.logTable td.actualAccessCell{width:34%!important;min-width:360px!important}.logTable td.actualAccessCell{white-space:normal!important;overflow-wrap:anywhere!important}.targetDetails{display:none!important}

/* 2026-07 rail-selection-parity: remove blue active-page stripe so all views match Approvals. */
.mainNav button:not(#tab-adminSettings).active::after,.mainNav .adminSubItem.active::after{display:none!important;content:none!important;background:transparent!important;width:0!important}
.mainNav button:not(#tab-adminSettings).active{box-shadow:none!important}
#appView>.cards,#appView>#rulesView,#appView>#accessView,#appView>#mcpView,#appView>#settingsView,#appView>#foot{border-left:0!important}

/* 2026-07 state-color-cards-and-activity-bell: state-tinted ACL metric cards, approval badge, notification flyout. */
.card.state-allow,.aclMetricCard.state-allow{background:linear-gradient(180deg,rgba(31,122,72,.26),rgba(31,122,72,.12))!important;border-color:rgba(67,180,116,.72)!important}.card.state-allow .metric,.card.state-allow .label{color:#9ff0bf!important}.card.state-ask,.aclMetricCard.state-ask{background:linear-gradient(180deg,rgba(185,128,23,.28),rgba(185,128,23,.12))!important;border-color:rgba(246,190,92,.75)!important}.card.state-ask .metric,.card.state-ask .label{color:#ffd488!important}.card.state-deny,.aclMetricCard.state-deny{background:linear-gradient(180deg,rgba(171,45,45,.28),rgba(171,45,45,.12))!important;border-color:rgba(244,104,104,.72)!important}.card.state-deny .metric,.card.state-deny .label{color:#ffaaaa!important}body.light .card.state-allow,body.light .aclMetricCard.state-allow{background:#e6f7ee!important;border-color:#48a56f!important}body.light .card.state-allow .metric,body.light .card.state-allow .label{color:#146b3a!important}body.light .card.state-ask,body.light .aclMetricCard.state-ask{background:#fff2d9!important;border-color:#d59a2c!important}body.light .card.state-ask .metric,body.light .card.state-ask .label{color:#8a5a00!important}body.light .card.state-deny,body.light .aclMetricCard.state-deny{background:#ffe6e6!important;border-color:#d45a5a!important}body.light .card.state-deny .metric,body.light .card.state-deny .label{color:#a12b2b!important}.navBadge{display:inline-flex;align-items:center;justify-content:center;min-width:18px;height:18px;padding:0 5px;margin-left:6px;border-radius:999px;background:#e33b2f;color:#fff!important;font-size:11px!important;font-weight:800!important;line-height:18px;vertical-align:middle;box-shadow:0 0 0 1px rgba(0,0,0,.25)}.mainNav .navBadge{margin-left:auto}.notificationWrap{position:relative;display:inline-flex}.activityBell{position:relative}.activityBell .bellIcon{font-style:normal!important;line-height:1}.activityBell .navBadge{position:absolute;right:-3px;top:-4px;margin:0}.activityPanel{position:absolute;right:0;top:calc(100% + 10px);width:min(380px,92vw);max-height:440px;overflow:auto;border:1px solid var(--line);background:var(--surface);color:var(--text);box-shadow:var(--shadow);border-radius:12px;z-index:200;padding:10px}.activityPanelHead{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:4px 4px 10px;border-bottom:1px solid var(--line);margin-bottom:6px}.activityPanelHead button{padding:5px 8px;font-size:12px}.activityList{display:grid;gap:6px}.activityItem{display:grid;gap:2px;padding:8px;border:1px solid var(--line);border-radius:8px;background:var(--surface2)}.activityItemKind{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);font-weight:800}.activityItemSummary{font-size:13px;color:var(--text);font-weight:650}.activityItemTime{font-size:11px;color:var(--muted)}


/* 2026-07 soft-surfaces-v27: keep only softer shadows and consistent rounded corners. */
:root{--proRadius:12px!important;--proRadiusSm:9px!important;--proShadow:0 10px 26px rgba(0,0,0,.18)!important}body.light{--proShadow:0 8px 24px rgba(15,23,42,.08)!important}.panel,.card,.settingBlock,.runtimeBox,.routePickPanel,.mcpCatalog,.authCard,.activityPanel,.detailModalCard{border-radius:var(--proRadius)!important;box-shadow:var(--proShadow)!important}.card,.settingBlock,.runtimeBox,.activityItem,.routePickItem{transition:border-color .16s ease,background .16s ease,box-shadow .16s ease,transform .16s ease!important}button,.iconBtn,.topUtilityButton,input,select,textarea{border-radius:var(--proRadiusSm)!important}

.twofaBox{border:1px solid var(--border);border-radius:14px;padding:12px;background:var(--panel2);display:grid;gap:10px}.securityPanel{margin-top:18px;border:1px solid var(--border);border-radius:16px;padding:16px;background:var(--panel2)}.securityPanel h4{margin:0 0 8px}.securityPanel .toolbar{margin-top:10px}.twofaBox.hidden,.securityPanel .hidden{display:none!important}


/* 2026-07 typography comfort pass: professional system font stack, calmer weights, better readability. */
:root{--uiFont:Aptos,"Segoe UI Variable","Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;--monoFont:"SFMono-Regular","Cascadia Mono","Roboto Mono","Segoe UI Mono",Menlo,Consolas,monospace;--uiBase:15.5px!important;--uiSmall:13.25px!important;--uiControl:14.5px!important}
html,body{font-family:var(--uiFont)!important;font-size:var(--uiBase)!important;line-height:1.5!important;-webkit-font-smoothing:antialiased!important;-moz-osx-font-smoothing:grayscale!important;text-rendering:optimizeLegibility!important}
body,body:not(.authing),body:not(.authing) *,input,button,select,textarea{font-family:var(--uiFont)!important;letter-spacing:-.006em!important}
button,input,select,textarea{font-size:var(--uiControl)!important;line-height:1.45!important;font-weight:500!important}
p,.muted,.smallNote,.routePickMeta,.adminUserMeta,.activityItemSummary,.activityItemTime{line-height:1.55!important}
h1,h2,h3,h4,.authTitle,.userCardName,.metric{font-family:var(--uiFont)!important;letter-spacing:-.025em!important;text-wrap:balance!important}
h1{font-weight:720!important}h2{font-weight:700!important}h3,h4{font-weight:680!important}
.mainNav button,.topUtilityButton,.topUserMenuItem,.settingsSubnav button{font-family:var(--uiFont)!important;font-weight:600!important;letter-spacing:-.01em!important;line-height:1.35!important}
table th{font-weight:650!important;font-size:12.5px!important;letter-spacing:.015em!important}table td{font-size:13.5px!important;line-height:1.45!important}.logTable td{line-height:1.5!important}
.code,code,pre,.runtimeBox,textarea#apiTokenOutput,#mcpTestResult{font-family:var(--monoFont)!important;letter-spacing:-.01em!important;line-height:1.55!important}.code{font-size:.92em!important}
.label,.fieldLabel span{font-weight:650!important;letter-spacing:.025em!important}
.authLead{line-height:1.55!important}.authCard{font-size:15px!important}
@media(max-width:900px){html,body{font-size:15.5px!important}.mainNav button{font-size:13.5px!important}table th,table td{font-size:13.5px!important}}


/* 2026-07 left-rail typography softening: force regular-weight menu labels for lower visual strain. */
#mainNav.mainNav button,
#mainNav.mainNav button.active,
#mainNav.mainNav button.navGroup,
#mainNav.mainNav button.adminSubItem,
#mainNav.mainNav button.adminSubItem.active,
#mainNav.mainNav .mainNavControl,
#mainNav.mainNav button span,
#mainNav.mainNav button b,
#mainNav.mainNav button strong,
.mainNav button,
.mainNav button.active,
.mainNav button.navGroup,
.mainNav .adminSubItem,
.mainNav .adminSubItem.active,
.mainNavControl{
  font-weight:400!important;
  font-variation-settings:'wght' 400!important;
  text-shadow:none!important;
}
#mainNav.mainNav button:hover,
#mainNav.mainNav button.active:hover,
#mainNav.mainNav button.adminSubItem:hover,
.mainNav button:hover,
.mainNav .adminSubItem:hover{
  font-weight:400!important;
  font-variation-settings:'wght' 400!important;
}


/* 2026-07 access-log-info-only: remove Actual access table column; details live behind info icon. */
.logTable th:nth-child(2),.logTable td:nth-child(2){width:auto!important;min-width:0!important}.logTable td.actualAccessCell{display:none!important}.detailGrid{grid-template-columns:repeat(auto-fit,minmax(220px,1fr))!important}


/* 2026-07 queued-ui-auth-pass: queue fixes for access/actions, collapsed title, spacing, and passkey/YubiKey split. */
.refreshRow{display:flex!important;align-items:center!important;gap:10px!important;flex-wrap:wrap!important}.refreshRow #resetAccessFilters{width:auto!important}.accessFilterToolbar{grid-template-columns:minmax(220px,1.3fr) repeat(5,minmax(128px,1fr))!important}.mcpGrid{padding:18px 20px!important}.mcpCatalog{padding:18px 20px!important}.mcpCatalog summary{padding:4px 2px 12px!important}.mcpCatalog table th,.mcpCatalog table td{padding:10px 12px!important}.mcpTestPanel{padding:2px 4px!important}.topWorkspace .welcomeName{max-width:62vw!important}.topWorkspace .welcomeName .currentView{font-weight:700!important}.topWorkspace .welcomeName .welcomePrefix{color:var(--muted)!important;font-weight:500!important}.topMenuCollapse,#mainNavCollapse.topMenuCollapse{display:grid!important;place-items:center!important}.topUtilities .topSettingsIcon,.topUserMenuItem .topSettingsIcon{background-position:center!important}.dangerBtn,#disableTotp,#removeYubi,#removePasskeys{background:#dc2626!important;color:#fff!important;border-color:#b91c1c!important}.dangerBtn:hover,#disableTotp:hover,#removeYubi:hover,#removePasskeys:hover{background:#b91c1c!important;color:#fff!important}#startTotp:disabled,#passkeyLoginBtn:disabled{opacity:.55!important;cursor:not-allowed!important}.authGrid #passkeyLoginBtn{width:100%!important;min-height:46px!important}.twofaBox .toolbar{grid-template-columns:repeat(auto-fit,minmax(160px,1fr))!important}@media(max-width:900px){.accessFilterToolbar{grid-template-columns:1fr!important}.mcpGrid,.mcpCatalog{padding:14px!important}.topWorkspace .welcomeName{max-width:44vw!important}}


/* 2026-07 admin-followup-polish-v28: restore Welcome title, centered settings cog, borderless bell, structured 2FA, admin padding. */
.topWorkspace .welcomeName{display:flex!important;align-items:center!important;height:38px!important;min-height:38px!important;line-height:1.2!important;margin:0!important;padding:0!important;white-space:nowrap!important}
.topWorkspace .welcomeName .currentView{display:none!important}
.topUtilities #activityBell.activityBell,.topUtilities #activityBell.topUtilityButton{border:0!important;outline:0!important;box-shadow:none!important;background:transparent!important;width:40px!important;min-width:40px!important;max-width:40px!important;height:40px!important;min-height:40px!important;padding:0!important;display:grid!important;place-items:center!important}
.topUtilities #activityBell.activityBell:hover,.topUtilities #activityBell.activityBell:focus-visible{border:0!important;box-shadow:none!important;background:var(--sideHover)!important}
.topUtilities #activityBell .bellIcon{display:grid!important;place-items:center!important;width:24px!important;height:24px!important;line-height:24px!important;margin:0!important;font-size:20px!important}
.topUserDropdown .topUserMenuItem .topSettingsIcon{display:grid!important;place-self:center!important;align-self:center!important;justify-self:center!important;width:20px!important;height:20px!important;min-width:20px!important;margin:0!important;background-position:center!important;mask-position:center!important;-webkit-mask-position:center!important}
.topUserDropdown .topUserMenuItem{display:grid!important;grid-template-columns:24px minmax(0,1fr)!important;align-items:center!important;gap:10px!important}
body.mainNavCollapsed .topUserDropdown .topUserMenuItem .topSettingsIcon{transform:none!important;margin:0!important}
#appView.settingsMode #settingsView{padding:0!important;box-sizing:border-box!important}
#appView.settingsMode #settingsView .settingsContent{padding:18px 22px 26px!important;box-sizing:border-box!important}
#appView.settingsMode #settingsView .settingBlock{padding:20px 22px 24px!important;margin:0 0 18px!important;border:1px solid var(--line)!important;background:var(--surface)!important;box-sizing:border-box!important}
#appView.settingsMode #settingsView .settingBlock.hidden{display:none!important}
#appView.settingsMode #settingsView .settingBlock>h3:first-child{margin-top:0!important}
.twofaPanel{display:grid!important;gap:16px!important}.twofaPanelHead{display:flex!important;align-items:flex-start!important;justify-content:space-between!important;gap:16px!important}.twofaPanel h4{margin:0 0 4px!important}.twofaPanel h5{margin:0 0 6px!important;font-size:16px!important;font-weight:720!important;letter-spacing:-.01em!important}.twofaSetupGrid{display:grid!important;grid-template-columns:repeat(auto-fit,minmax(240px,1fr))!important;gap:14px!important}.twofaSetupCard{display:grid!important;align-content:start!important;gap:12px!important;padding:16px!important;border:1px solid var(--line)!important;border-radius:12px!important;background:var(--surface2)!important;box-shadow:none!important}.twofaActions{display:grid!important;grid-template-columns:repeat(auto-fit,minmax(160px,1fr))!important;gap:10px!important;align-items:center!important}.twofaInline{display:grid!important;grid-template-columns:minmax(140px,1fr) auto!important;gap:10px!important;align-items:center!important}.twofaInline input,.twofaSetupCard input{width:100%!important;box-sizing:border-box!important}.twofaSetupCard button:disabled{opacity:.55!important;cursor:not-allowed!important}.twofaSetupCard .runtimeBox{box-shadow:none!important;margin-top:2px!important;padding:12px!important}
@media(max-width:900px){#appView.settingsMode #settingsView .settingsContent{padding:14px!important}#appView.settingsMode #settingsView .settingBlock{padding:16px!important}.twofaInline{grid-template-columns:1fr!important}}



/* 2026-07 yubi-management-mobile-simplify-v29: strict YubiKey 2FA, centered collapsed rail, compact mobile admin. */
.registeredKeys{border-top:1px solid var(--line)!important;padding-top:12px!important;margin-top:2px!important}.registeredKeysHead{display:flex!important;justify-content:space-between!important;align-items:center!important;gap:10px!important;margin-bottom:8px!important}.credentialList{display:grid!important;gap:8px!important}.credentialItem{display:grid!important;grid-template-columns:minmax(0,1fr) auto!important;gap:10px!important;align-items:center!important;padding:10px!important;border:1px solid var(--line)!important;border-radius:10px!important;background:var(--surface)!important}.credentialMeta{display:block!important;margin-top:3px!important;color:var(--muted)!important;font-size:12px!important;line-height:1.3!important}.compactDanger{min-height:34px!important;padding:6px 10px!important;font-size:13px!important}
body.mainNavCollapsed .mainNav button[data-icon],body.mainNavCollapsed .mainNav .adminSubItem[data-icon],.mainNav.collapsed button[data-icon],.mainNav.collapsed .adminSubItem[data-icon]{display:grid!important;grid-template-columns:1fr!important;place-items:center!important;justify-items:center!important;align-items:center!important;text-align:center!important;width:var(--leftPaneCollapsedW)!important;min-width:var(--leftPaneCollapsedW)!important;max-width:var(--leftPaneCollapsedW)!important;padding:0!important;gap:0!important;margin:0!important}
body.mainNavCollapsed .mainNav button[data-icon]::before,body.mainNavCollapsed .mainNav .adminSubItem[data-icon]::before,.mainNav.collapsed button[data-icon]::before,.mainNav.collapsed .adminSubItem[data-icon]::before{position:static!important;display:grid!important;place-items:center!important;justify-self:center!important;align-self:center!important;margin:0!important;left:auto!important;right:auto!important;top:auto!important;bottom:auto!important;transform:none!important;width:28px!important;min-width:28px!important;height:28px!important;line-height:28px!important;text-align:center!important}
body.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup::after,.mainNav.collapsed button#tab-adminSettings.navGroup::after{display:none!important}
@media(max-width:760px){body:not(.authing){overflow:auto!important}main{height:auto!important;max-height:none!important;overflow:visible!important;padding-top:56px!important}.brandCluster{height:56px!important}.topWorkspace{height:56px!important}.topUtilities{display:none!important}#appView:not(.hidden),#appView.settingsMode:not(.hidden),#appView.mainNavCollapsed:not(.hidden){display:block!important;height:auto!important;max-height:none!important;overflow:visible!important;padding:0 10px 22px!important}.mainNav,.mainNav.collapsed{position:sticky!important;top:56px!important;z-index:800!important;width:100%!important;height:auto!important;min-height:0!important;display:flex!important;flex-direction:row!important;gap:6px!important;overflow-x:auto!important;overflow-y:hidden!important;padding:7px 2px!important;border-right:0!important;border-bottom:1px solid var(--railDivider)!important;background:var(--sideBg)!important;scrollbar-width:none!important}.mainNav::-webkit-scrollbar{display:none!important}.mainNav button[data-icon],.mainNav .adminSubItem[data-icon]{flex:0 0 46px!important;width:46px!important;min-width:46px!important;max-width:46px!important;height:44px!important;min-height:44px!important;padding:0!important;border:0!important;border-radius:10px!important;display:grid!important;grid-template-columns:1fr!important;place-items:center!important;font-size:0!important;gap:0!important}.mainNav button[data-icon]::before,.mainNav .adminSubItem[data-icon]::before{font-size:20px!important;margin:0!important;justify-self:center!important}.mainNav button.active::after,.mainNav .adminSubItem.active::after{left:9px!important;right:9px!important;top:auto!important;bottom:0!important;width:auto!important;height:3px!important}.mainNav .adminSubItem.hidden{display:none!important}.mainNav button#tab-adminSettings.navGroup::after{display:none!important}.sectionHead h2{font-size:19px!important;margin:0!important}.sectionHead .muted,#settingsView .settingBlock>p.muted,#settingsView .smallNote:not(.credentialMeta),.oidcInstructions,.routePickMeta,.authMeta{display:none!important}.settingsContent,#appView.settingsMode #settingsView .settingsContent{padding:8px 0 18px!important}.settingBlock,#appView.settingsMode #settingsView .settingBlock{padding:12px!important;margin:0 0 10px!important;border-radius:10px!important}.formgrid,.twofaSetupGrid,.mcpTestControls,.routeComposer,.oidcSetupCards{grid-template-columns:1fr!important;gap:8px!important}.twofaSetupCard{padding:12px!important;gap:8px!important}.twofaPanel{gap:10px!important}.twofaActions{grid-template-columns:1fr!important;gap:8px!important}.toolbar,.bulkbar,.refreshRow{gap:7px!important;margin:8px 0!important}.toolbar input,.toolbar select,.toolbar button,.refreshRow button,.bulkbar button,.bulkbar select{min-height:38px!important}.cards{display:none!important}.panel{margin:8px 0!important}.credentialItem{grid-template-columns:1fr!important}.credentialItem button{width:100%!important}}



/* 2026-07 collapsed-admin-cog-hard-fix-v30: ID-specific override beats earlier #tab-adminSettings flex rules. */
body.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup,
body.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup.active,
body.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup.expanded,
#appView.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup,
#appView.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup.active,
#appView.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup.expanded,
.mainNav.collapsed button#tab-adminSettings.navGroup,
.mainNav.collapsed button#tab-adminSettings.navGroup.active,
.mainNav.collapsed button#tab-adminSettings.navGroup.expanded{
  display:grid!important;
  grid-template-columns:1fr!important;
  place-items:center!important;
  justify-items:center!important;
  align-items:center!important;
  justify-content:center!important;
  text-align:center!important;
  width:var(--leftPaneCollapsedW)!important;
  min-width:var(--leftPaneCollapsedW)!important;
  max-width:var(--leftPaneCollapsedW)!important;
  min-height:52px!important;
  padding:0!important;
  margin:0!important;
  gap:0!important;
  font-size:0!important;
  line-height:1!important;
}
body.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup::before,
body.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup.active::before,
body.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup.expanded::before,
#appView.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup::before,
#appView.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup.active::before,
#appView.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup.expanded::before,
.mainNav.collapsed button#tab-adminSettings.navGroup::before,
.mainNav.collapsed button#tab-adminSettings.navGroup.active::before,
.mainNav.collapsed button#tab-adminSettings.navGroup.expanded::before{
  content:'⚙'!important;
  position:static!important;
  display:grid!important;
  place-items:center!important;
  justify-self:center!important;
  align-self:center!important;
  margin:0 auto!important;
  left:auto!important;
  right:auto!important;
  top:auto!important;
  bottom:auto!important;
  transform:none!important;
  width:28px!important;
  min-width:28px!important;
  max-width:28px!important;
  height:28px!important;
  min-height:28px!important;
  line-height:28px!important;
  text-align:center!important;
  font-size:22px!important;
  background:transparent!important;
}
body.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup::after,
body.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup.active::after,
body.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup.expanded::after,
#appView.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup::after,
#appView.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup.active::after,
#appView.mainNavCollapsed .mainNav button#tab-adminSettings.navGroup.expanded::after,
.mainNav.collapsed button#tab-adminSettings.navGroup::after,
.mainNav.collapsed button#tab-adminSettings.navGroup.active::after,
.mainNav.collapsed button#tab-adminSettings.navGroup.expanded::after{display:none!important;content:''!important}

/* 2026-07 full-responsive-mobile-v31: consolidated mobile-first guards for shell, forms, tables, logs, modals, and touch targets. */
:root{--contentGutter:clamp(14px,2vw,28px)!important;--mobileHeaderH:58px!important;--tapTarget:44px!important}
html{width:100%!important;max-width:100%!important;overflow-x:hidden!important;-webkit-text-size-adjust:100%!important}body{width:100%!important;max-width:100%!important;overflow-wrap:anywhere!important}body.authing{overflow:auto!important}body:not(.authing){overflow:hidden!important}body,button,input,select,textarea{line-height:1.45!important}button,input,select,textarea{min-height:var(--tapTarget)!important;max-width:100%!important}button{touch-action:manipulation!important}.srOnly{position:absolute!important;width:1px!important;height:1px!important;padding:0!important;margin:-1px!important;overflow:hidden!important;clip:rect(0,0,0,0)!important;white-space:nowrap!important;border:0!important}
main,#appView,#rulesView,#approvalsView,#accessView,#mcpView,#settingsView,.settingsContent,.settingBlock,.panel,.card,.runtimeBox,.mcpCatalog,.detailModalCard{min-width:0!important;max-width:100%!important}.panel,.tableScroller{width:100%!important;max-width:100%!important;overflow-x:auto!important;overflow-y:hidden!important;-webkit-overflow-scrolling:touch!important;overscroll-behavior-inline:contain!important}.panel table,.mcpCatalog table{width:100%!important;border-collapse:separate!important;border-spacing:0!important}.panel table{min-width:720px!important}.logTable,#accessView table{min-width:860px!important}#approvalsView table{min-width:780px!important}#mcpView table{min-width:760px!important}th,td{vertical-align:top!important}td,.code,pre,textarea,.runtimeBox,.detailModalBody{overflow-wrap:anywhere!important;word-break:break-word!important}pre,.runtimeBox,#mcpTestResult,.detailModalBody pre{white-space:pre-wrap!important;overflow:auto!important;max-width:100%!important}.toolbar,.accessFilterToolbar,.approvalToolbar,.bulkbar,.refreshRow,.runtimeActions,.routeComposerActions,.authGrid,.formgrid,.passwordGrid,.mcpTestControls,.configSummaryGrid,.userEditGrid,.userAddGrid,.oidcConfigGrid{max-width:100%!important;min-width:0!important}.toolbar input,.toolbar select,.toolbar button,.filterSelect{min-width:0!important;max-width:100%!important}.cards{grid-template-columns:repeat(auto-fit,minmax(min(230px,100%),1fr))!important}.card{min-width:0!important}.detailModal{position:fixed!important;inset:0!important;z-index:2500!important;display:grid!important;place-items:center!important;padding:calc(env(safe-area-inset-top,0px) + 12px) calc(env(safe-area-inset-right,0px) + 12px) calc(env(safe-area-inset-bottom,0px) + 12px) calc(env(safe-area-inset-left,0px) + 12px)!important;background:rgba(0,0,0,.62)!important}.detailModal.hidden{display:none!important}.detailModalCard{width:min(980px,100%)!important;max-height:min(88svh,920px)!important;display:flex!important;flex-direction:column!important;overflow:hidden!important}.detailModalHead{flex:0 0 auto!important}.detailModalBody{flex:1 1 auto!important;overflow:auto!important;padding-bottom:max(16px,env(safe-area-inset-bottom,0px))!important}.detailGrid{display:grid!important;grid-template-columns:repeat(auto-fit,minmax(min(220px,100%),1fr))!important;gap:10px!important}
@media(max-width:1200px){:root{--leftPaneW:230px!important;--leftPaneCollapsedW:62px!important;--topBarH:76px!important}.googleTextBrand{font-size:17px!important}.mainNav button{font-size:14px!important;line-height:1.25!important}.mainNav .adminSubItem{font-size:12.5px!important}.accessFilterToolbar{grid-template-columns:repeat(auto-fit,minmax(160px,1fr))!important}.toolbar{grid-template-columns:repeat(auto-fit,minmax(160px,1fr))!important}}
@media(max-width:1024px){body:not(.authing){overflow:auto!important}main{height:auto!important;max-height:none!important;overflow:visible!important;padding:var(--topBarH) 16px 34px!important}#appView:not(.hidden),#appView.mainNavCollapsed:not(.hidden),#appView.settingsMode:not(.hidden){grid-template-columns:minmax(0,1fr)!important;gap:16px!important;padding:0!important}.mainNav{position:static!important;height:auto!important;min-height:0!important;width:100%!important;border:1px solid var(--line)!important;border-radius:14px!important;display:grid!important;grid-template-columns:repeat(auto-fit,minmax(132px,1fr))!important;gap:6px!important;padding:8px!important}.mainNav button,.mainNav .adminSubItem{width:100%!important;min-width:0!important;max-width:none!important;display:grid!important;grid-template-columns:24px minmax(0,1fr)!important;justify-content:start!important;text-align:left!important;font-size:14px!important;padding:10px 12px!important}.mainNav button::before,.mainNav .adminSubItem::before{position:static!important;justify-self:center!important}.mainNav button.active::after,.mainNav .adminSubItem.active::after{left:0!important;top:8px!important;bottom:8px!important;width:4px!important;height:auto!important}#appView>.cards,#appView>#rulesView,#appView>#approvalsView,#appView>#accessView,#appView>#mcpView,#appView>#settingsView,#appView>#foot{grid-column:1!important}.settingsShell,.settingsShell.collapsed{display:block!important;grid-template-columns:1fr!important}.settingsContent,#settingsView .settingsContent{padding:16px!important}.settingBlock,#appView.settingsMode #settingsView .settingBlock{padding:16px!important}.routeComposer,.userCards{grid-template-columns:1fr!important}.workspaceStepTabs,.contentTabs{grid-template-columns:repeat(auto-fit,minmax(150px,1fr))!important}}
@media(max-width:760px){:root{--topBarH:var(--mobileHeaderH)!important}body:not(.authing){overflow:auto!important}header{height:var(--mobileHeaderH)!important;min-height:var(--mobileHeaderH)!important;padding-top:env(safe-area-inset-top,0px)!important}header .wrap.top{height:var(--mobileHeaderH)!important;min-height:var(--mobileHeaderH)!important;grid-template-columns:minmax(0,1fr) auto!important;padding:0 max(10px,env(safe-area-inset-right,0px)) 0 max(10px,env(safe-area-inset-left,0px))!important}.brandCluster{width:auto!important;min-width:0!important;height:var(--mobileHeaderH)!important;padding:0!important;overflow:hidden!important}.brandCluster .textBrandLink{height:var(--mobileHeaderH)!important;padding:0!important}.googleTextBrand{font-size:16px!important;max-width:calc(100vw - 78px)!important;overflow:hidden!important;text-overflow:ellipsis!important}.topWorkspace{height:var(--mobileHeaderH)!important;grid-template-columns:44px!important;justify-content:end!important;padding:0!important}.topWorkspace .welcomeName{display:none!important}.topMenuCollapse,#mainNavCollapse.topMenuCollapse{width:44px!important;height:44px!important;min-height:44px!important;display:grid!important;place-items:center!important;border-radius:12px!important;background:var(--surface2)!important}.topUtilities{display:none!important}main{padding:calc(var(--mobileHeaderH) + env(safe-area-inset-top,0px)) max(10px,env(safe-area-inset-right,0px)) max(28px,env(safe-area-inset-bottom,0px)) max(10px,env(safe-area-inset-left,0px))!important;overflow:visible!important}.mainNav,.mainNav.collapsed{position:fixed!important;top:calc(var(--mobileHeaderH) + env(safe-area-inset-top,0px))!important;left:env(safe-area-inset-left,0px)!important;bottom:env(safe-area-inset-bottom,0px)!important;z-index:2200!important;width:min(86vw,330px)!important;max-width:330px!important;height:auto!important;min-height:0!important;display:flex!important;flex-direction:column!important;gap:4px!important;overflow-y:auto!important;overflow-x:hidden!important;padding:10px!important;border:1px solid var(--line)!important;border-radius:0 16px 16px 0!important;background:var(--sideBg)!important;box-shadow:0 18px 55px rgba(0,0,0,.42)!important;transform:translateX(calc(-100% - 18px))!important;transition:transform .2s ease!important}.mobileNavOpen .mainNav{transform:translateX(0)!important}.mobileNavOpen::after{content:''!important;position:fixed!important;inset:calc(var(--mobileHeaderH) + env(safe-area-inset-top,0px)) 0 0 0!important;background:rgba(0,0,0,.46)!important;z-index:2100!important}.mainNav button[data-icon],.mainNav .adminSubItem[data-icon],.mainNav.collapsed button[data-icon],.mainNav.collapsed .adminSubItem[data-icon]{flex:0 0 auto!important;width:100%!important;min-width:0!important;max-width:none!important;height:auto!important;min-height:46px!important;display:grid!important;grid-template-columns:26px minmax(0,1fr)!important;gap:10px!important;justify-content:start!important;align-items:center!important;place-items:unset!important;text-align:left!important;font-size:14px!important;line-height:1.25!important;padding:11px 12px!important;border-radius:10px!important;white-space:normal!important}.mainNav button[data-icon]::before,.mainNav .adminSubItem[data-icon]::before{position:static!important;width:24px!important;height:24px!important;line-height:24px!important;font-size:20px!important;display:grid!important;place-items:center!important;justify-self:center!important}.mainNav button.active::after,.mainNav .adminSubItem.active::after{left:0!important;right:auto!important;top:7px!important;bottom:7px!important;width:4px!important;height:auto!important;border-radius:4px!important}.mainNav button#tab-adminSettings.navGroup::after{display:block!important;right:10px!important;left:auto!important;top:50%!important;bottom:auto!important;width:18px!important;height:18px!important;transform:translateY(-50%)!important;background:transparent!important}.sectionHead,.accessHeader{display:grid!important;grid-template-columns:1fr!important;gap:10px!important}.cards{grid-template-columns:1fr!important;gap:10px!important}.card{padding:12px!important}.metric{font-size:24px!important}.toolbar,.accessFilterToolbar,.approvalToolbar,.bulkbar,.refreshRow,.runtimeActions,.routeComposerActions,.mcpTestControls,.authGrid,.formgrid,.passwordGrid,.userEditGrid,.userAddGrid,.oidcConfigGrid{display:grid!important;grid-template-columns:1fr!important;gap:9px!important;align-items:stretch!important}.toolbar>*,.approvalToolbar>*,.bulkbar>*,.refreshRow>*,.runtimeActions>*,.routeComposerActions>*,.mcpTestControls>*,.authGrid>*,.formgrid>*,.passwordGrid>*{width:100%!important}.workspaceStepTabs,.contentTabs{display:grid!important;grid-template-columns:1fr!important;gap:8px!important}.panel{margin:0!important;border-radius:12px!important}.panel table{min-width:660px!important}.logTable,#accessView table{min-width:760px!important}#approvalsView table,#mcpView table{min-width:700px!important}th,td{font-size:13px!important;padding:9px 8px!important}.runtimeBox,pre,textarea,#mcpTestResult{font-size:12.5px!important;line-height:1.45!important}.routePickHead,.userCardHeader,.registeredKeysHead{display:grid!important;grid-template-columns:1fr!important;gap:8px!important}.routePickList{max-height:245px!important}.detailModal{align-items:end!important;padding:8px!important}.detailModalCard{width:100%!important;max-height:88svh!important;border-radius:16px 16px 0 0!important}.detailGrid{grid-template-columns:1fr!important}.detailModalHead h3{font-size:17px!important}.loginSplit,#loginView:not(.hidden),.authShell{min-height:calc(100svh - var(--mobileHeaderH))!important;padding:14px 10px!important}.loginPanel,.authCard{width:100%!important}.authCard,.loginPanel .authCard{padding:20px 14px!important;border-radius:16px!important}.loginBrand img.loginHeroLogo{width:min(280px,84vw)!important}.authTitle{font-size:22px!important}.authMeta{display:grid!important;grid-template-columns:1fr!important;gap:6px!important}.userDropdown,.topUserDropdown,.activityPanel{position:fixed!important;right:8px!important;left:8px!important;top:calc(var(--mobileHeaderH) + 8px)!important;max-width:none!important;min-width:0!important;width:auto!important}.settingBlock h3{font-size:19px!important}.settingBlock p,.muted{font-size:13px!important}.checkRow{align-items:flex-start!important}}
@media(max-width:430px){.googleTextBrand{font-size:15px!important}.brandWord{letter-spacing:-.04em!important}.panel table{min-width:620px!important}.logTable,#accessView table{min-width:720px!important}.iconActions{display:grid!important;grid-template-columns:repeat(2,minmax(36px,1fr))!important;gap:6px!important}.iconBtn,.iconDecision{min-width:38px!important;width:38px!important;height:38px!important}.pill{max-width:100%!important;white-space:normal!important}.routePickItem{grid-template-columns:22px minmax(0,1fr)!important;padding:11px 10px!important}}
@media(max-width:375px){main{padding-left:8px!important;padding-right:8px!important}.googleTextBrand{font-size:14px!important}.authCard,.loginPanel .authCard,.settingBlock,#appView.settingsMode #settingsView .settingBlock{padding:14px 12px!important}.panel table{min-width:590px!important}.logTable,#accessView table{min-width:680px!important}th,td{font-size:12.5px!important;padding:8px 7px!important}.mainNav,.mainNav.collapsed{width:min(90vw,312px)!important}.cards{gap:8px!important}}
@media(max-width:340px){.googleTextBrand{font-size:13px!important}.panel table{min-width:560px!important}.logTable,#accessView table{min-width:640px!important}.loginBrand img.loginHeroLogo{width:min(240px,80vw)!important}.topMenuCollapse,#mainNavCollapse.topMenuCollapse{width:42px!important;height:42px!important;min-height:42px!important}}

/* 2026-07 mobile-table-and-theme-v32: aligned top utilities, calmer light theme, readable menu ellipsis, and card tables instead of side-scrolling on small screens. */
:root{--topControl:44px!important;--controlBorder:rgba(255,255,255,.16)!important;--controlHover:rgba(255,255,255,.08)!important;--tableCardBg:var(--surface)!important;--tableLabel:#9ca3af!important}body.light{--bg:#f7f8fa!important;--surface:#ffffff!important;--surface2:#f2f4f7!important;--elev:#eef1f5!important;--text:#172033!important;--muted:#64748b!important;--line:#d8dee8!important;--input:#ffffff!important;--sideBg:#f1f3f6!important;--sideHover:#e3e7ee!important;--sideActive:#d8dde6!important;--sideText:#172033!important;--sideMuted:#52627a!important;--railDivider:rgba(23,32,51,.14)!important;--controlBorder:rgba(23,32,51,.18)!important;--controlHover:rgba(23,32,51,.07)!important;--tableLabel:#52627a!important}.actions.topUtilities{height:var(--topBarH)!important;display:grid!important;grid-auto-flow:column!important;grid-auto-columns:var(--topControl)!important;align-items:center!important;justify-content:end!important;gap:10px!important;padding:0 16px 0 8px!important;overflow:visible!important}.topUtilities #activityBell.activityBell,.topUtilities #theme.themeTopControl,.topUtilities .topUserMenu,.topUtilities .topAvatarButton{width:var(--topControl)!important;min-width:var(--topControl)!important;max-width:var(--topControl)!important;height:var(--topControl)!important;min-height:var(--topControl)!important;max-height:var(--topControl)!important;margin:0!important;padding:0!important;align-self:center!important;justify-self:center!important;display:grid!important;place-items:center!important;border-radius:12px!important}.topUtilities #activityBell.activityBell,.topUtilities #theme.themeTopControl,.topUtilities .topAvatarButton{border:1px solid var(--controlBorder)!important;background:transparent!important;color:var(--sideText)!important;box-shadow:none!important}.topUtilities #activityBell.activityBell:hover,.topUtilities #theme.themeTopControl:hover,.topUtilities .topAvatarButton:hover,.topUserMenu:focus-within .topAvatarButton{background:var(--controlHover)!important;border-color:var(--controlBorder)!important}.topUtilities #activityBell .bellIcon,.themeTopIcon,.themeTopIcon::before{width:24px!important;height:24px!important;line-height:24px!important;display:grid!important;place-items:center!important;margin:0!important;color:var(--sideText)!important}.topAvatarButton .avatarMini,.topAvatarFallback{width:36px!important;height:36px!important;margin:0!important}.topUserMenu{position:relative!important;overflow:visible!important}.topUserDropdown{top:calc(100% + 8px)!important;right:0!important}.topMenuCollapse,#mainNavCollapse.topMenuCollapse{color:var(--sideText)!important;background:transparent!important;border:1px solid var(--controlBorder)!important;opacity:1!important}.topMenuCollapse::before,#mainNavCollapse.topMenuCollapse::before{content:'⋯'!important;color:var(--sideText)!important;font-size:30px!important;font-weight:900!important;line-height:1!important;text-shadow:0 0 1px currentColor!important;transform:none!important;box-shadow:none!important;background:transparent!important}.topMenuCollapse:hover,#mainNavCollapse.topMenuCollapse:hover{background:var(--controlHover)!important}.mainNav button.active{font-weight:600!important}body.light .card.state-allow,body.light .aclMetricCard.state-allow{background:linear-gradient(180deg,rgba(34,134,82,.16),rgba(34,134,82,.07))!important;border-color:rgba(34,134,82,.35)!important}body.light .card.state-allow .metric,body.light .card.state-allow .label{color:#17633d!important}body.light .card.state-ask,body.light .aclMetricCard.state-ask{background:linear-gradient(180deg,rgba(180,120,20,.15),rgba(180,120,20,.06))!important;border-color:rgba(180,120,20,.32)!important}body.light .card.state-ask .metric,body.light .card.state-ask .label{color:#835300!important}body.light .card.state-deny,body.light .aclMetricCard.state-deny{background:linear-gradient(180deg,rgba(190,49,68,.14),rgba(190,49,68,.06))!important;border-color:rgba(190,49,68,.30)!important}body.light .card.state-deny .metric,body.light .card.state-deny .label{color:#992137!important}
#rulesView .panel{overflow-x:hidden!important}#rulesView table{table-layout:fixed!important;min-width:0!important;width:100%!important}#rulesView th:nth-child(1),#rulesView td:nth-child(1){width:34px!important}#rulesView th:nth-child(2),#rulesView td:nth-child(2){width:112px!important}#rulesView th:nth-child(3),#rulesView td:nth-child(3){width:120px!important}#rulesView th:nth-child(7),#rulesView td:nth-child(7){width:92px!important}#rulesView th,#rulesView td{white-space:normal!important;overflow-wrap:anywhere!important;word-break:break-word!important}#rulesView select.inline{width:100%!important;min-width:0!important}.actionCell{display:flex!important;max-width:100%!important;white-space:normal!important;overflow-wrap:anywhere!important}.actionHelp{margin-left:auto!important}
@media(max-width:900px){.panel{overflow:visible!important}.panel table,.logTable,#accessView table,#approvalsView table,#mcpView table,#rulesView table,.mcpCatalog table{display:block!important;width:100%!important;min-width:0!important;border:0!important}.panel thead,.mcpCatalog thead{display:none!important}.panel tbody,.mcpCatalog tbody{display:grid!important;gap:12px!important;width:100%!important}.panel tr,.mcpCatalog tr{display:grid!important;grid-template-columns:1fr!important;gap:0!important;width:100%!important;border:1px solid var(--line)!important;border-radius:14px!important;background:var(--tableCardBg)!important;box-shadow:var(--proShadow)!important;padding:10px!important;overflow:hidden!important}.panel td,.mcpCatalog td{display:grid!important;grid-template-columns:minmax(90px,34%) minmax(0,1fr)!important;gap:10px!important;align-items:start!important;width:100%!important;border:0!important;border-bottom:1px solid var(--line)!important;padding:9px 4px!important;font-size:13.5px!important;line-height:1.4!important;white-space:normal!important;overflow-wrap:anywhere!important;word-break:break-word!important}.panel td:last-child,.mcpCatalog td:last-child{border-bottom:0!important}.panel td::before,.mcpCatalog td::before{content:attr(data-label)!important;color:var(--tableLabel)!important;font-size:11px!important;font-weight:750!important;text-transform:uppercase!important;letter-spacing:.04em!important;line-height:1.25!important}.panel td[data-label=''],.mcpCatalog td[data-label='']{grid-template-columns:1fr!important}.panel td[data-label='']::before,.mcpCatalog td[data-label='']::before{display:none!important}#rulesView td.selectCell,#rulesView td:first-child{width:auto!important;min-width:0!important;max-width:none!important;text-align:left!important}.iconActions{display:flex!important;flex-wrap:wrap!important;gap:8px!important;white-space:normal!important}.iconBtn,.iconDecision{min-width:40px!important;width:auto!important;height:40px!important;padding:0 10px!important}.approvalToolbar,.accessFilterToolbar,.toolbar{grid-template-columns:1fr!important}.actions.topUtilities{height:var(--mobileHeaderH)!important;grid-auto-columns:42px!important;gap:8px!important;padding-right:8px!important}.topUtilities #activityBell.activityBell,.topUtilities #theme.themeTopControl,.topUtilities .topUserMenu,.topUtilities .topAvatarButton{width:42px!important;min-width:42px!important;max-width:42px!important;height:42px!important;min-height:42px!important}.topAvatarButton .avatarMini,.topAvatarFallback{width:34px!important;height:34px!important}}
@media(max-width:430px){.panel td,.mcpCatalog td{grid-template-columns:1fr!important;gap:4px!important}.panel td::before,.mcpCatalog td::before{font-size:10.5px!important}.actions.topUtilities{display:none!important}.topMenuCollapse::before,#mainNavCollapse.topMenuCollapse::before{font-size:28px!important}.panel tr,.mcpCatalog tr{padding:9px!important}}

/* 2026-07 mobile-header-theme-ellipsis-v33: restore mobile utilities, fix admin drawer toggle, and replace broken ellipsis glyph with CSS dots. */
body.light{--bg:#f6f7f9!important;--surface:#ffffff!important;--surface2:#f0f2f5!important;--elev:#e7ebf0!important;--text:#172033!important;--muted:#5e6b7e!important;--line:#d7dde7!important;--hover:#e9edf3!important;--hoverText:#172033!important;--input:#ffffff!important;--sideBg:#f6f7f9!important;--sideHover:#e8ecf2!important;--sideActive:#d9dfe8!important;--sideText:#172033!important;--sideMuted:#536176!important;--railDivider:rgba(23,32,51,.14)!important;--controlBorder:rgba(23,32,51,.16)!important;--controlHover:rgba(23,32,51,.07)!important}body.light header,body.light header .wrap.top,body.light .brandCluster{background:var(--bg)!important}.topMenuCollapse,#mainNavCollapse.topMenuCollapse{font-size:0!important;text-indent:0!important;overflow:hidden!important;color:var(--sideText)!important;background:transparent!important;border:1px solid var(--controlBorder)!important;box-shadow:none!important;display:grid!important;place-items:center!important}.topMenuCollapse::before,#mainNavCollapse.topMenuCollapse::before{content:''!important;width:24px!important;height:24px!important;display:block!important;background:radial-gradient(circle,currentColor 0 2.2px,transparent 2.4px) center 4px/24px 8px no-repeat,radial-gradient(circle,currentColor 0 2.2px,transparent 2.4px) center 12px/24px 8px no-repeat,radial-gradient(circle,currentColor 0 2.2px,transparent 2.4px) center 20px/24px 8px no-repeat!important;color:var(--sideText)!important;opacity:1!important;text-shadow:none!important;transform:none!important;line-height:1!important}.topMenuCollapse:hover,#mainNavCollapse.topMenuCollapse:hover{background:var(--controlHover)!important}.topUtilities #activityBell.activityBell,.topUtilities #theme.themeTopControl,.topUtilities .topAvatarButton{background:transparent!important;border-color:var(--controlBorder)!important}.topUtilities #activityBell .bellIcon{filter:none!important}.themeTopIcon::before{color:var(--sideText)!important}.topUserDropdown{background:var(--surface)!important;border-color:var(--line)!important;color:var(--text)!important}
@media(max-width:760px){header .wrap.top{grid-template-columns:minmax(0,1fr) 44px auto!important;gap:6px!important;align-items:center!important}.brandCluster{grid-column:1!important}.topWorkspace{grid-column:2!important;width:44px!important}.actions.topUtilities{grid-column:3!important;display:grid!important;grid-auto-flow:column!important;grid-auto-columns:40px!important;gap:5px!important;height:var(--mobileHeaderH)!important;padding:0!important;align-items:center!important;justify-content:end!important;overflow:visible!important}.topUtilities #activityBell.activityBell,.topUtilities #theme.themeTopControl,.topUtilities .topUserMenu,.topUtilities .topAvatarButton{display:grid!important;width:40px!important;min-width:40px!important;max-width:40px!important;height:40px!important;min-height:40px!important;max-height:40px!important;border-radius:11px!important}.topAvatarButton .avatarMini,.topAvatarFallback{width:32px!important;height:32px!important}.topUserDropdown{right:0!important;max-width:min(280px,calc(100vw - 16px))!important}.topMenuCollapse,#mainNavCollapse.topMenuCollapse{background:transparent!important;width:42px!important;height:42px!important;min-height:42px!important}.googleTextBrand{max-width:100%!important}.mainNav .adminSubItem{display:grid!important}.mobileNavOpen .mainNav{transform:translateX(0)!important;opacity:1!important;pointer-events:auto!important}}
@media(max-width:430px){.actions.topUtilities{display:grid!important;grid-auto-columns:38px!important;gap:4px!important}.topUtilities #activityBell.activityBell,.topUtilities #theme.themeTopControl,.topUtilities .topUserMenu,.topUtilities .topAvatarButton{width:38px!important;min-width:38px!important;max-width:38px!important;height:38px!important;min-height:38px!important}.topAvatarButton .avatarMini,.topAvatarFallback{width:30px!important;height:30px!important}.brandAgent,.brandGateway{display:none!important}.googleTextBrand{font-size:16px!important}.topMenuCollapse,#mainNavCollapse.topMenuCollapse{width:40px!important;height:40px!important;min-height:40px!important}.topMenuCollapse::before,#mainNavCollapse.topMenuCollapse::before{width:22px!important;height:22px!important;background:radial-gradient(circle,currentColor 0 2.1px,transparent 2.3px) center 3px/22px 7px no-repeat,radial-gradient(circle,currentColor 0 2.1px,transparent 2.3px) center 11px/22px 7px no-repeat,radial-gradient(circle,currentColor 0 2.1px,transparent 2.3px) center 19px/22px 7px no-repeat!important}}
@media(max-width:360px){header .wrap.top{grid-template-columns:minmax(0,1fr) 40px auto!important;gap:3px!important;padding-left:8px!important;padding-right:6px!important}.actions.topUtilities{grid-auto-columns:35px!important;gap:3px!important}.topUtilities #activityBell.activityBell,.topUtilities #theme.themeTopControl,.topUtilities .topUserMenu,.topUtilities .topAvatarButton{width:35px!important;min-width:35px!important;max-width:35px!important;height:35px!important;min-height:35px!important}.topAvatarButton .avatarMini,.topAvatarFallback{width:28px!important;height:28px!important}.topWorkspace,.topMenuCollapse,#mainNavCollapse.topMenuCollapse{width:38px!important;height:38px!important;min-height:38px!important}.googleTextBrand{font-size:15px!important}}

/* 2026-07 borderless-menu-icons-v34: remove menu-bar control outlines and render centered stable three-dot ellipsis. */
.topMenuCollapse,#mainNavCollapse.topMenuCollapse,.topUtilities #activityBell.activityBell,.topUtilities #theme.themeTopControl,.topUtilities .topAvatarButton,#loginTheme.loginThemeControl{border:0!important;outline:0!important;box-shadow:none!important;background:transparent!important}.topMenuCollapse:hover,#mainNavCollapse.topMenuCollapse:hover,.topUtilities #activityBell.activityBell:hover,.topUtilities #theme.themeTopControl:hover,.topUtilities .topAvatarButton:hover,.topUserMenu:focus-within .topAvatarButton,#loginTheme.loginThemeControl:hover,#loginTheme.loginThemeControl:focus-visible{border:0!important;box-shadow:none!important;background:var(--controlHover,var(--sideHover))!important}.topMenuCollapse,#mainNavCollapse.topMenuCollapse{position:relative!important;display:grid!important;place-items:center!important;color:var(--sideText)!important;font-size:0!important;text-indent:0!important;overflow:visible!important}.topMenuCollapse::before,#mainNavCollapse.topMenuCollapse::before{content:''!important;display:block!important;width:5px!important;height:5px!important;border-radius:999px!important;background:currentColor!important;color:var(--sideText)!important;box-shadow:0 -8px 0 currentColor,0 8px 0 currentColor!important;position:absolute!important;left:50%!important;top:50%!important;transform:translate(-50%,-50%)!important;opacity:1!important;margin:0!important;padding:0!important;line-height:1!important;text-shadow:none!important}.topMenuCollapse::after,#mainNavCollapse.topMenuCollapse::after{display:none!important;content:none!important}.topUtilities #activityBell.activityBell,.topUtilities #theme.themeTopControl,.topUtilities .topAvatarButton{color:var(--sideText)!important}.topUtilities #activityBell .bellIcon,.themeTopIcon,.themeTopIcon::before{color:var(--sideText)!important}

/* 2026-07 collapsed-rail-cleanup-v35: collapsed rail shows only icons; no stray chevrons or active stripes under the menu dots. */
body.mainNavCollapsed .topMenuCollapse,#appView.mainNavCollapsed #mainNavCollapse.topMenuCollapse{width:44px!important;height:44px!important;min-width:44px!important;min-height:44px!important;margin:0 auto!important;padding:0!important;border:0!important;background:transparent!important;box-shadow:none!important}body.mainNavCollapsed .topMenuCollapse::before,#appView.mainNavCollapsed #mainNavCollapse.topMenuCollapse::before{width:5px!important;height:5px!important;border-radius:999px!important;background:currentColor!important;box-shadow:0 -8px 0 currentColor,0 8px 0 currentColor!important;left:50%!important;top:50%!important;transform:translate(-50%,-50%)!important}body.mainNavCollapsed .topMenuCollapse::after,body.mainNavCollapsed #mainNavCollapse.topMenuCollapse::after,#appView.mainNavCollapsed .mainNav button.navGroup::after,#appView.mainNavCollapsed .mainNav button.expanded::after,#appView.mainNavCollapsed .mainNav button.active::after,#appView.mainNavCollapsed .mainNav .adminSubItem::after{display:none!important;content:none!important;width:0!important;height:0!important;border:0!important;background:none!important;box-shadow:none!important}.mainNav.collapsed button.navGroup::after,.mainNav.collapsed button.expanded::after,.mainNav.collapsed button.active::after,.mainNav.collapsed .adminSubItem::after{display:none!important;content:none!important}#appView.mainNavCollapsed .mainNav button:not(.mainNavControl){border-radius:0!important;border:0!important;box-shadow:none!important;background:transparent!important}#appView.mainNavCollapsed .mainNav button:not(.mainNavControl):hover{background:var(--sideHover)!important;border-radius:10px!important}
/* 2026-07 collapsed-admin-chevron-kill-v36: explicitly suppress legacy Admin Settings chevron in all collapsed states. */
body.mainNavCollapsed #tab-adminSettings.navGroup,body.mainNavCollapsed #tab-adminSettings.navGroup.active,body.mainNavCollapsed #tab-adminSettings.navGroup.expanded,#appView.mainNavCollapsed #tab-adminSettings.navGroup,#appView.mainNavCollapsed #tab-adminSettings.navGroup.active,#appView.mainNavCollapsed #tab-adminSettings.navGroup.expanded,.mainNav.collapsed #tab-adminSettings.navGroup,.mainNav.collapsed #tab-adminSettings.navGroup.active,.mainNav.collapsed #tab-adminSettings.navGroup.expanded{display:grid!important;grid-template-columns:1fr!important;place-items:center!important;justify-content:center!important;align-items:center!important;padding:12px 0!important;font-size:0!important;color:var(--sideText)!important}.mainNav.collapsed #tab-adminSettings.navGroup::after,.mainNav.collapsed #tab-adminSettings.navGroup.active::after,.mainNav.collapsed #tab-adminSettings.navGroup.expanded::after,body.mainNavCollapsed #tab-adminSettings.navGroup::after,body.mainNavCollapsed #tab-adminSettings.navGroup.active::after,body.mainNavCollapsed #tab-adminSettings.navGroup.expanded::after,#appView.mainNavCollapsed #tab-adminSettings.navGroup::after,#appView.mainNavCollapsed #tab-adminSettings.navGroup.active::after,#appView.mainNavCollapsed #tab-adminSettings.navGroup.expanded::after{content:none!important;display:none!important;visibility:hidden!important;opacity:0!important;width:0!important;height:0!important;min-width:0!important;max-width:0!important;flex:0 0 0!important;margin:0!important;padding:0!important;position:absolute!important;left:-9999px!important;right:auto!important;background:none!important;border:0!important;box-shadow:none!important;transform:none!important}.mainNav.collapsed #tab-adminSettings.navGroup::before,body.mainNavCollapsed #tab-adminSettings.navGroup::before,#appView.mainNavCollapsed #tab-adminSettings.navGroup::before{display:inline-grid!important;place-items:center!important;margin:0!important;font-size:22px!important;width:40px!important;height:40px!important;line-height:40px!important}
/* 2026-07 physical-rail-dots-v38: collapse control uses real spans, not glyph/pseudo fallback. */
#mainNavCollapse.topMenuCollapse,#mainNavCollapse.mainNavControl{font-size:0!important;color:var(--sideText)!important;line-height:0!important;text-indent:0!important;overflow:hidden!important}#mainNavCollapse.topMenuCollapse::before,#mainNavCollapse.topMenuCollapse::after{content:none!important;display:none!important;visibility:hidden!important;opacity:0!important}.railDots{display:grid!important;grid-template-rows:repeat(3,5px)!important;gap:4px!important;place-items:center!important;width:18px!important;height:23px!important;margin:auto!important;color:var(--sideText)!important}.railDots span{display:block!important;width:5px!important;height:5px!important;border-radius:999px!important;background:currentColor!important;box-shadow:none!important;margin:0!important;padding:0!important}body.mainNavCollapsed #mainNavCollapse .railDots,#appView.mainNavCollapsed #mainNavCollapse .railDots,.mainNav.collapsed #mainNavCollapse .railDots{display:grid!important}
/* 2026-07 collapsed-rail-nuclear-after-v37: no collapsed left-rail button may render an ::after glyph/stripe; fixes leaked > mark. */
html body:not(.authing).mainNavCollapsed #appView.mainNavCollapsed nav#mainNav.mainNav button::after,html body:not(.authing).mainNavCollapsed #appView.mainNavCollapsed nav#mainNav.mainNav button.active::after,html body:not(.authing).mainNavCollapsed #appView.mainNavCollapsed nav#mainNav.mainNav button.expanded::after,html body:not(.authing).mainNavCollapsed nav#mainNav.mainNav.collapsed button::after,html body:not(.authing).mainNavCollapsed nav#mainNav.mainNav.collapsed button.active::after,html body:not(.authing).mainNavCollapsed nav#mainNav.mainNav.collapsed button.expanded::after{content:none!important;display:none!important;visibility:hidden!important;opacity:0!important;width:0!important;height:0!important;min-width:0!important;max-width:0!important;flex:0 0 0!important;margin:0!important;padding:0!important;position:absolute!important;inset:auto!important;left:-10000px!important;right:auto!important;top:auto!important;bottom:auto!important;background:transparent!important;border:0!important;box-shadow:none!important;transform:none!important}.mainNav.collapsed button:not(.mainNavControl),body.mainNavCollapsed #appView.mainNavCollapsed nav#mainNav.mainNav button:not(.mainNavControl){overflow:hidden!important}.mainNav.collapsed button:not(.mainNavControl)::before,body.mainNavCollapsed #appView.mainNavCollapsed nav#mainNav.mainNav button:not(.mainNavControl)::before{z-index:1!important}

</style></head><body class="authing"><header><div class="wrap top"><div class="brandCluster"><a class="brand textBrandLink" href="#" id="brandHome" aria-label="Go to ACL rules"><span class="googleTextBrand" aria-label="Google Agent Gateway"><span class="brandWord brandGoogle">Google</span><span class="brandWord brandAgent">Agent</span><span class="brandWord brandGateway">Gateway</span></span></a></div><div class="topWorkspace"><button id="mainNavCollapse" class="mainNavControl topMenuCollapse" title="Collapse or expand main navigation" aria-label="Collapse or expand main navigation"><span class="railDots" aria-hidden="true"><span></span><span></span><span></span></span></button><span id="welcomeName" class="welcomeName">Welcome</span></div><div class="actions topUtilities"><div class="notificationWrap"><button id="activityBell" class="topUtilityButton activityBell" title="Recent governance activity" aria-label="Recent governance activity"><span class="bellIcon" aria-hidden="true">🔔</span><span id="activityBadge" class="navBadge hidden">0</span></button><div id="activityPanel" class="activityPanel hidden"><div class="activityPanelHead"><b>Recent activity</b><button id="clearActivity" type="button">Clear all</button></div><div id="activityList" class="activityList muted">No recent activity.</div></div></div><button id="theme" class="topUtilityButton themeTopControl" title="Toggle light or dark theme" aria-label="Toggle light or dark theme"><span class="themeTopIcon" aria-hidden="true"></span></button><div id="userMenu" class="topUserMenu hidden"><button type="button" class="topAvatarButton" aria-label="Open user menu" aria-haspopup="menu"><img id="userMenuAvatar" class="avatarMini hidden" alt=""/><span class="topAvatarFallback" aria-hidden="true"></span><span id="userMenuName" class="srOnly">User</span></button><div class="topUserDropdown" role="menu"><button id="tab-userSettings" class="topUserMenuItem hidden" role="menuitem"><span class="topSettingsIcon" aria-hidden="true"></span><span>Settings</span></button><button id="logout" class="topUserMenuItem" role="menuitem"><span class="topLogoutIcon" aria-hidden="true"></span><span>Logout</span></button></div></div></div></div></header><main>
<section id="setupView" class="authShell hidden"><div class="authCard"><div class="authLogo"><div><h2 class="authTitle">Create the first admin</h2><p class="authLead">Initialize the protected Google Agent Gateway control plane.</p></div></div><div class="authGrid"><input id="setupToken" placeholder="Setup token" type="password"/><input id="setupUser" placeholder="Login username" autocomplete="username"/><input id="setupFirst" placeholder="First name"/><input id="setupLast" placeholder="Last name"/><input id="setupPass" placeholder="Admin password (12+ chars)" type="password" autocomplete="new-password"/><button id="setupBtn" class="primary">Create admin</button></div><div class="authMeta"><span>PBKDF2 password hash</span><span>Session-protected UI</span><span>Gateway-owned OAuth</span></div><div id="setupMsg" class="msg"></div></div></section>
<section id="loginView" class="loginSplit"><div class="loginPanel"><div class="authCard"><div class="loginBrand"><span class="loginHeroLogo" aria-hidden="true" style="display:none"></span><img class="themeLogo lightLogo loginHeroLogo" src="/assets/logo-light.png?v=26" alt="Google Agent Gateway"/><img class="themeLogo darkLogo loginHeroLogo" src="/assets/logo-login-dark.png?v=26" alt="Google Agent Gateway"/></div><h2 class="authTitle">Sign in</h2><div class="authGrid"><input id="loginUser" placeholder="Username" autocomplete="username"/><input id="loginPass" placeholder="Password" type="password" autocomplete="current-password"/><button id="loginBtn">Sign in</button><button id="passkeyLoginBtn" type="button">Sign in with passkey</button><div id="twofaBox" class="twofaBox hidden"><div class="muted smallNote">Two-factor authentication required.</div><input id="loginTotp" placeholder="Authenticator code" inputmode="numeric" autocomplete="one-time-code"/><div class="toolbar"><button id="loginTotpBtn" class="primary" type="button">Verify code</button><button id="loginYubiBtn" type="button">Use YubiKey 2FA</button></div></div><button id="oidcLoginBtn" class="ssoLogin hidden" type="button">Sign in with SSO</button><button id="loginTheme" class="loginThemeControl" type="button" title="Toggle light or dark theme" aria-label="Toggle light or dark theme"><span class="themeTopIcon" aria-hidden="true"></span></button></div><div id="loginMsg" class="msg"></div></div></div></section>
<section id="appView" class="hidden"><nav id="mainNav" class="mainNav" aria-label="Primary views"><button id="tab-rules" class="active" data-icon="policy">ACL rules</button><button id="tab-approvals" data-icon="shield">Approvals <span id="approvalBadge" class="navBadge hidden">0</span></button><button id="tab-access" data-icon="article">Access logs</button><button id="tab-mcp" data-icon="hub">MCP tools</button><button id="tab-adminSettings" class="navGroup" data-icon="admin_panel_settings">Admin settings</button><button id="adminNav-users" class="adminSubItem" data-icon="manage_accounts">User Management</button><button id="adminNav-workspace" class="adminSubItem" data-icon="cloud_sync">Workspace Configuration</button><button id="adminNav-channels" class="adminSubItem" data-icon="chat_bubble">Channel Configuration</button><button id="adminNav-system" class="adminSubItem" data-icon="manufacturing">System Settings</button><button id="adminNav-tokens" class="adminSubItem" data-icon="vpn_key">API tokens</button></nav><section class="cards" id="cards"></section>
<section id="rulesView"><div class="sectionHead"><div><h2>ACL rules</h2><div class="muted">Edit individual rows or select multiple rules and apply a bulk decision. Row decision changes auto-save.</div></div></div><div class="toolbar"><input id="q" placeholder="Search profile, token, service, action…"/><select id="profile" class="filterSelect" multiple size="1" title="Profiles"><option value="">All profiles</option></select><select id="decision" class="filterSelect" multiple size="1" title="Decisions"><option value="">All decisions</option><option>allow</option><option>ask</option><option>deny</option></select><select id="service" class="filterSelect" multiple size="1" title="Services"><option value="">All services</option></select><select id="route" class="filterSelect" multiple size="1" title="Routes"><option value="">All routes</option></select><select id="token" class="filterSelect" multiple size="1" title="Tokens"><option value="">All tokens</option></select><button id="resetRulesFilters" class="resetFilters" type="button">Reset filters</button></div><div class="bulkbar"><label><input id="selectAll" type="checkbox"/> select shown</label><span id="selectedCount" class="pill">0 selected</span><select id="bulkDecision" style="width:130px"><option>allow</option><option>ask</option><option>deny</option></select><button id="bulkApply" class="primary">Apply bulk change</button></div><section class="panel"><table><thead><tr><th></th><th data-sort="decision">Decision</th><th data-sort="profile">Profile</th><th data-sort="token_label">Token</th><th data-sort="token_route">Route</th><th data-sort="action">Action</th><th data-sort="service">Service</th></tr></thead><tbody id="rules"></tbody></table></section><div id="ruleMsg" class="msg"></div></section>
<section id="approvalsView" class="hidden"><div class="sectionHead"><div><h2>Approvals</h2><div class="muted">Requests waiting because an ACL decision is set to ask. Approve with ✓ to execute immediately, or deny with ✕.</div></div></div><div class="toolbar approvalToolbar"><select id="approvalState"><option value="pending">Pending</option><option value="all">All</option><option value="approve_once">Approved</option><option value="deny">Denied</option><option value="request_edit">Needs edit</option><option value="expired">Expired</option><option value="cleared">Cleared</option></select><button id="refreshApprovals">Refresh</button><button id="bulkApproveApprovals" class="successBtn">✓ Approve shown</button><button id="bulkDenyApprovals" class="dangerBtn">✕ Deny shown</button><button id="clearApprovals" class="dangerBtn subtleDanger">Clear shown</button></div><section class="panel"><table><thead><tr><th>Request</th><th>Profile</th><th>Action</th><th>Resource</th><th>Requested</th><th>Expires</th><th>Status</th><th>Details</th></tr></thead><tbody id="approvals"></tbody></table></section><div class="msg" id="approvalMsg"></div></section><section id="accessView" class="hidden"><div class="sectionHead accessHeader"><div><h2>Live gateway access log</h2><div class="muted">Plain-English view of what Google Workspace access the gateway processed. Times display in CST/CDT.</div></div><div class="refreshRow"><button id="refreshAccess">Refresh logs</button><button id="resetAccessFilters" class="resetFilters" type="button">Reset filters</button></div></div><div class="toolbar accessFilterToolbar"><input id="accessQ" placeholder="Search access, resource, profile…"/><select id="accessProfile" class="filterSelect" multiple size="1" title="Profiles"><option value="">All profiles</option></select><select id="accessAction" class="filterSelect" multiple size="1" title="Actions"><option value="">All actions</option></select><select id="accessDecision" class="filterSelect" multiple size="1" title="Decisions"><option value="">All decisions</option></select><select id="accessStatus" class="filterSelect" multiple size="1" title="Outcomes"><option value="">All outcomes</option></select><select id="accessRoute" class="filterSelect" multiple size="1" title="Routes"><option value="">All routes</option></select></div><section class="panel"><table class="logTable"><thead><tr><th data-sort="time_cst">Time (CST/CDT)</th><th data-sort="profile">Profile</th><th data-sort="action">Action</th><th data-sort="decision">Decision</th><th data-sort="outcome">Outcome</th><th data-sort="token_route">Route</th><th>Info</th></tr></thead><tbody id="accessLog"></tbody></table></section><div class="msg grafanaNote">These same gateway audit rows are exported to Loki/Grafana via job <span class="code">hermes-google-governance-audit</span>.</div><div class="msg" id="accessMsg"></div></section>
<section id="mcpView" class="hidden"><div class="sectionHead"><div><h2>MCP tools</h2><div class="muted">Exposed governed Google MCP tools. Pick a profile, then an applicable Workspace route, then a safe directly-testable read tool.</div></div><div class="refreshRow"><button id="refreshMcpTools">Refresh tools</button></div></div><section class="panel mcpGrid"><div class="mcpTestPanel"><h3>Test a tool</h3><div class="mcpTestControls"><label class="fieldLabel"><span>Hermes profile</span><select id="mcpTestProfile" title="Profile identity sent to the gateway"></select></label><label class="fieldLabel"><span>Applicable Workspace route</span><select id="mcpTestRoute" title="Google account route filtered by selected profile"></select></label><label class="fieldLabel"><span>Tool</span><select id="mcpTestTool" title="Safe MCP tool to test for the selected route"></select></label><button id="mcpRunTest" class="primary">Run test</button></div><div class="muted smallNote">The tester intentionally offers safe read tools that this UI can execute directly. The catalog below lists every exposed MCP tool, including write/destructive tools that require a real MCP client or approval flow.</div><label class="fieldLabel"><span>Request JSON</span><textarea id="mcpTestArgs" rows="8" placeholder='{"start":"2026-07-09T00:00:00Z","end":"2026-07-10T00:00:00Z","calendar":"primary","max_results":5}'></textarea></label><label class="fieldLabel"><span>Response</span><pre id="mcpTestResult" class="runtimeBox muted">Pick a profile, route, and supported safe read tool, then run a test.</pre></label></div><details class="mcpCatalog"><summary>Exposed MCP tool catalog</summary><div class="toolbar"><input id="mcpQ" placeholder="Search tools, service, description…"/><select id="mcpService" class="filterSelect" multiple size="1" title="Services"><option value="">All services</option></select><select id="mcpRisk" class="filterSelect" multiple size="1" title="Risk"><option value="">All risk levels</option><option>read/testable</option><option>high risk</option><option>not testable</option></select><button id="resetMcpFilters" class="resetFilters" type="button">Reset filters</button></div><table><thead><tr><th>Tool</th><th>Service</th><th>Risk</th><th>Description</th></tr></thead><tbody id="mcpTools"></tbody></table></details></section><div class="msg" id="mcpMsg"></div></section>
<section id="settingsView" class="hidden"><div class="settingsTopbar"><button id="settingsBack" class="settingsBack">← Back to main</button><h2 id="settingsTitle">Profile settings</h2></div><div id="settingsShell" class="settingsShell"><nav class="settingsSubnav"><button id="settingsCollapse" class="settingsNavControl" title="Collapse or expand left menu" aria-label="Collapse or expand left menu">‹</button><button id="settingsNav-profile" class="active" data-icon="account_circle">User profile</button><button id="settingsNav-users" data-icon="manage_accounts">User Management</button><button id="settingsNav-workspace" class="navGroup" data-icon="cloud_sync">Google Workspace</button><button id="workspaceTab-auth" class="subItem">1. Configure new workspace</button><button id="workspaceTab-profiles" class="subItem">2. Configure workspace routes</button><button id="workspaceTab-overview" class="subItem">3. View configured workspaces</button><button id="settingsNav-channels" data-icon="chat_bubble">Channel Configuration</button><button id="settingsNav-runtime" class="navGroup" data-icon="manufacturing">Runtime</button><button id="runtimeTab-status" class="subItem runtimeSubItem">Status & actions</button><button id="runtimeTab-validation" class="subItem runtimeSubItem">Config validation</button><button id="runtimeTab-backups" class="subItem runtimeSubItem">Backups</button><button id="runtimeTab-paths" class="subItem runtimeSubItem">File locations</button><button id="runtimeTab-upgrade" class="subItem runtimeSubItem">Upgrade & logs</button><button id="settingsNav-tokens" class="navGroup" data-icon="vpn_key">API tokens</button></nav><div class="settingsContent"><section id="settingsProfile" class="settingBlock"><h3>User profile</h3><p>Signed in as <b id="settingsMe"></b> <span id="settingsRole" class="pill"></span></p><div class="formgrid"><input id="profileFirst" placeholder="First name"/><input id="profileLast" placeholder="Last name"/><input id="profileEmail" type="email" placeholder="Email"/><input id="profilePhoto" type="file" accept="image/*"/><button id="saveProfile" class="primary">Save profile</button></div><p><img id="profilePhotoPreview" class="profileAvatarPreview hidden" alt="Profile photo preview"/></p><div class="passwordGrid"><input id="currentPass" type="password" placeholder="Current password" autocomplete="current-password"/><input id="newPassSelf" type="password" placeholder="New password (10+ chars)" autocomplete="new-password"/><input id="confirmPassSelf" type="password" placeholder="Confirm new password" autocomplete="new-password"/><button id="changePass" class="primary">Change password</button></div><div class="securityPanel twofaPanel"><div class="twofaPanelHead"><div><h4>Two-factor authentication</h4><p id="twofaStatus" class="muted">Loading 2FA status…</p></div></div><div class="twofaSetupGrid"><article class="twofaSetupCard"><div><h5>Authenticator app</h5><p class="muted smallNote">Use a 6-digit code from your authenticator app after password sign-in.</p></div><div class="twofaActions"><button id="startTotp" type="button">Set up authenticator app</button><button id="disableTotp" class="dangerBtn" type="button">Disable authenticator</button></div><div id="totpSetup" class="runtimeBox hidden"><div class="muted smallNote">Add this setup key to your authenticator app, then enter the 6-digit code.</div><div class="code" id="totpSecret"></div><div class="twofaInline"><input id="totpCode" placeholder="6-digit code" inputmode="numeric" autocomplete="one-time-code"/><button id="verifyTotp" class="primary" type="button">Enable authenticator</button></div></div></article><article class="twofaSetupCard"><div><h5>Passkey</h5><p class="muted smallNote">Passwordless sign-in. One passkey is allowed per user.</p></div><div class="twofaActions"><button id="registerPasskey" type="button">Set up passkey</button><button id="removePasskeys" class="dangerBtn" type="button">Remove passkey</button></div></article><article class="twofaSetupCard yubiSetupCard"><div><h5>YubiKey / FIDO 2FA</h5><p class="muted smallNote">Strictly a second factor after password sign-in. Register multiple physical keys and name each one.</p></div><label class="fieldLabel"><span>YubiKey name</span><input id="yubiLabel" placeholder="Example: Blue YubiKey 5 NFC" autocomplete="off"/></label><div class="twofaActions"><button id="registerYubi" type="button">Register YubiKey 2FA</button><button id="removeYubi" class="dangerBtn" type="button">Remove all YubiKey 2FA</button></div><div class="registeredKeys"><div class="registeredKeysHead"><b>Registered YubiKeys</b><span id="yubiKeyCount" class="pill">0</span></div><div id="yubiKeyList" class="credentialList muted">No YubiKeys registered.</div></div></article></div></div><div class="msg" id="profileMsg"></div></section><section id="settingsTokens" class="settingBlock hidden"><h3>API token management</h3><div id="apiTokenStatus" class="runtimeBox muted">Loading API token custody…</div><div class="apiTokenCreateGrid"><label class="fieldLabel"><span>Token label</span><input id="apiTokenLabel" placeholder="Example: Hagrid MCP client" value="Hermes shared client token"/></label><button id="generateApiToken" class="primary">Generate API token</button></div><textarea id="apiTokenOutput" class="hidden" readonly rows="3" placeholder="Generated token appears once here"></textarea><div class="toolbar apiTokenToolbar"><select id="apiTokenLabelFilter" class="filterSelect" multiple size="1" title="Labels"><option value="">All labels</option></select><select id="apiTokenProfileFilter" class="filterSelect" multiple size="1" title="Profiles"><option value="">All profiles</option></select><select id="apiTokenStatusFilter" class="filterSelect" multiple size="1" title="Statuses"><option value="">All statuses</option></select><button id="resetApiTokenFilters" class="resetFilters" type="button">Reset filters</button></div><div id="apiTokenInventory" class="runtimeBox muted">No API tokens loaded.</div><div class="msg" id="tokenMsg"></div></section><section id="settingsUsers" class="settingBlock hidden"><h3>User management</h3><p class="muted">View, create, and delete control-plane users.</p><div class="contentTabs userMgmtTabs"><button id="userTop-setup" class="active" type="button">Users</button><button id="userTop-oidc" type="button">OIDC</button></div><section id="settingsOidc" class="oidcInUsers hidden"><div class="oidcHeader"><div><h3>OIDC SSO setup</h3><p class="muted">This is part of User Management. Existing users inherit role and enabled/disabled status from the user cards below. Unknown SSO users are created automatically on first login with Viewer permission.</p></div><span id="oidcEnabledBadge" class="pill">disabled</span></div><div class="oidcInstructions"><h4>What to enter</h4><ol><li><b>Issuer URL</b>: the base OIDC issuer from your identity provider, usually the value shown as “Issuer” or “OpenID Provider URL”. Do not include <code>/.well-known/openid-configuration</code>.</li><li><b>Client ID</b>: the OAuth/OIDC client identifier from the identity-provider app you created for this control plane.</li><li><b>Client secret</b>: the client secret from that app. Leave blank on later saves to keep the existing saved secret.</li><li><b>Redirect URI</b>: copy this exact callback into the identity provider’s allowed redirect/callback URLs: <code>/api/oidc/callback</code> on this control-plane host.</li><li><b>Allowed email domains</b>: optional comma-separated domains, for example <code>example.com, company.com</code>. Leave blank to allow any domain that your identity provider authenticates.</li></ol></div><div class="oidcSetupCards"><article class="oidcCard"><h4>1. Sign-in behavior</h4><div class="oidcConfigGrid"><label class="checkRow oidcWide"><input id="oidcEnabled" type="checkbox"/> <span>Show “Sign in with SSO” on the login page</span></label><div class="fieldHelp oidcWide">Turn this on only after the issuer URL, client ID, client secret, and redirect URI are filled in and saved.</div><div class="fieldHelp oidcWide"><b>First-login provisioning:</b> if an SSO identity does not match an existing local user, the control plane automatically creates that user with Viewer permission. Admins can promote or disable them in User Management.</div></div></article><article class="oidcCard"><h4>2. Identity provider app</h4><div class="oidcConfigGrid"><label class="fieldLabel wide"><span>Issuer URL</span><input id="oidcIssuer" placeholder="https://idp.example.com/application/o/app"/><small>Paste the issuer/base URL from your OIDC provider, without the well-known suffix.</small></label><label class="fieldLabel"><span>Client ID</span><input id="oidcClientId" placeholder="Client ID from IdP app"/><small>Generated by the identity-provider app registration.</small></label><label class="fieldLabel"><span>Client secret</span><input id="oidcClientSecret" type="password" placeholder="Leave blank to keep existing"/><small>Write-only here; it is never displayed after save.</small></label></div></article><article class="oidcCard"><h4>3. Callback and access guardrails</h4><div class="oidcConfigGrid"><label class="fieldLabel wide"><span>Redirect URI</span><input id="oidcRedirectUri" placeholder="https://gateway.example.com/api/oidc/callback"/><small>Must exactly match one allowed redirect URI in your IdP app.</small></label><label class="fieldLabel wide"><span>Allowed email domains</span><input id="oidcDomainAllow" placeholder="example.com, company.com"/><small>Optional. Use commas for multiple domains. Leave blank to skip domain filtering.</small></label><div class="oidcHelp oidcWide">No admin/viewer dropdown is needed here. Authorization comes from each user’s User Management record after OIDC identifies them.</div></div></article></div><button id="saveOidc" class="primary oidcSaveButton">Save OIDC configuration</button><div id="oidcStatus" class="runtimeBox muted">OIDC configuration not loaded.</div><div class="msg" id="oidcMsg"></div></section><div id="userSetupPane"><div id="users" class="userCards userAdminCards"></div><h3>Create user</h3><div class="userAddGrid adminCreateUserGrid"><label class="fieldLabel"><span>First name</span><input id="newFirst" placeholder="Karthik" autocomplete="given-name"/></label><label class="fieldLabel"><span>Last name</span><input id="newLast" placeholder="Venkat" autocomplete="family-name"/></label><label class="fieldLabel"><span>Username</span><input id="newUser" placeholder="karthik" autocomplete="username"/></label><label class="fieldLabel"><span>Email</span><input id="newEmail" type="email" placeholder="karthik@example.com" autocomplete="email"/></label><label class="fieldLabel"><span>Role</span><select id="newRole"><option>viewer</option><option>admin</option></select></label><label class="fieldLabel"><span>Status</span><select id="newEnabled"><option value="true">enabled</option><option value="false">disabled</option></select></label><label class="fieldLabel userPasswordField"><span>Password</span><input id="newUserPass" type="password" placeholder="Password (10+ chars)" autocomplete="new-password"/></label><button id="addUser" class="primary userAddButton">Create user</button></div><div class="msg" id="userMsg"></div></div></section><section id="settingsWorkspace" class="settingBlock hidden"><h3>Workspace Configuration</h3><div class="contentTabs workspaceStepTabs"><button id="workspaceTop-auth"><span class="stepNum">1</span> Configure new workspace</button><button id="workspaceTop-profiles"><span class="stepNum">2</span> Configure workspace routes</button><button id="workspaceTop-overview"><span class="stepNum">3</span> View configured workspaces</button></div><section id="workspaceOverviewPane"><div class="muted smallNote actionBlurbs"><div><span class="code">✓</span> Test the existing token.</div><div><span class="code">↻</span> Refresh the current access token using the saved refresh token.</div><div><span class="code">🔐</span> Reopen Google consent and update scopes on this same workspace row.</div><div><span class="code">⛓</span> Disconnect the workspace token and remove its routes/ACL visibility.</div></div><div class="toolbar"><input id="workspaceTokenQ" placeholder="Search token, account, email…"/><select id="workspaceTokenAccount" class="filterSelect" multiple size="1" title="Accounts"><option value="">All accounts</option></select><select id="workspaceTokenEmail" class="filterSelect" multiple size="1" title="Emails"><option value="">All emails</option></select><select id="workspaceTokenStore" class="filterSelect" multiple size="1" title="Stores"><option value="">All stores</option></select><select id="workspaceTokenStatus" class="filterSelect" multiple size="1" title="Statuses"><option value="">All statuses</option></select><button id="resetWorkspaceTokenFilters" class="resetFilters" type="button">Reset filters</button></div><table><thead><tr><th data-sort="email">Email</th><th data-sort="label">Token</th><th data-sort="account_alias">Account</th><th data-sort="store">Store</th><th data-sort="token_status">Status</th><th data-sort="updated_at">Updated</th><th data-sort="actions">Actions</th></tr></thead><tbody id="workspaceOverview"></tbody></table></section><section id="workspaceAuthPane" class="hidden"><p class="muted">Connect Google accounts here. Connection only stores gateway-owned OAuth custody. No profile ACLs are created during this step.</p><div class="workflowSteps verticalSteps"><div class="step"><b>1. Upload client_secret.json</b><span class="muted">Use the Google OAuth Desktop App client secret from your Google Cloud project.</span><input id="clientSecretFile" type="file" accept="application/json,.json"/></div><div class="step"><b>2. Optional token name</b><span class="muted">Give this connected token a friendly display name, such as Work Gmail or Family Workspace. Leave blank to use the account email.</span><input id="oauthTokenLabel" placeholder="Optional token display name" maxlength="80"/></div><div class="step"><b>3. Generate authorization URL</b><span class="muted">Hermes generates the Google OAuth authorization URL using the configured OAuth app. Workspace services/scopes come from the Google Cloud project configuration.</span><button id="startOAuth" class="primary">Generate authorization URL</button></div><div class="step"><b>4. Approve in browser</b><span class="muted">Open the authorization URL, sign in with your Google account, and approve access.</span><div id="oauthUrlBox" class="authLinkBox hidden"><a id="oauthUrl" target="_blank" rel="noreferrer">Open Google authorization</a><div class="muted">Opens Google OAuth in a new browser tab.</div></div></div><div class="step"><b>5. Save token</b><span class="muted">Paste the returned authorization response back into Hermes. Hermes will save the token for future use. No profile ACLs are created during this connection step.</span><textarea id="redirectOrCode" placeholder="Paste final redirect URL or authorization code" rows="3"></textarea><input id="oauthState" placeholder="OAuth state"/><button id="finishOAuth" class="primary">Exchange code and save token</button></div></div></section><section id="workspaceReauthPane" class="hidden"><p class="muted">Update scopes for the selected existing workspace. This reuses the stored OAuth client and token identity; no new client JSON, token name, or workspace route is needed.</p><div class="workflowSteps verticalSteps"><div class="step"><b>1. Existing workspace</b><span id="reauthWorkspaceSummary" class="muted">Choose Reauthorize from an authenticated workspace row.</span></div><div class="step"><b>2. Approve expanded scopes</b><span class="muted">Open the Google consent URL and approve the expanded scopes for the same Google account.</span><div id="reauthUrlBox" class="authLinkBox hidden"><a id="reauthUrl" target="_blank" rel="noreferrer">Open Google reauthorization</a><div class="muted">This updates the selected workspace row in place.</div></div></div><div class="step"><b>3. Save updated scopes</b><span class="muted">Paste the returned authorization response. Hermes replaces the existing refresh token/scopes and syncs current profile routes.</span><textarea id="reauthRedirectOrCode" placeholder="Paste final redirect URL or authorization code" rows="3"></textarea><input id="reauthState" placeholder="OAuth state"/><button id="finishReauth" class="primary">Update existing workspace scopes</button></div></div></section><section id="workspaceProfilesPane" class="hidden"><p class="muted">Choose Workspace tokens and Hermes profiles to create profile/token routes. Routes are always <span class="code">profile/account</span>, for example <span class="code">airbnb/work-gmail</span>.</p><div class="routeComposer"><section class="routePickPanel"><div class="routePickHead"><div><h4>Workspace tokens</h4><p>Select one or more connected Google accounts.</p></div><span id="mapTokenCount" class="routePickCount">0 selected</span></div><div id="mapTokenPicker" class="routePickList"></div></section><section class="routePickPanel"><div class="routePickHead"><div><h4>Hermes profiles</h4><p>Select one or more agent profiles to link.</p></div><span id="mapProfileCount" class="routePickCount">0 selected</span></div><div id="mapProfilePicker" class="routePickList"></div></section></div><div class="routeComposerActions"><button id="mapProfilesBtn" class="primary">Create / update selected routes</button><span class="muted">Creates every selected token × selected profile combination.</span></div><div class="toolbar"><input id="workspaceRouteQ" placeholder="Search profile, account, route, email…"/><select id="workspaceRouteProfile" class="filterSelect" multiple size="1" title="Profiles"><option value="">All profiles</option></select><select id="workspaceRouteAccount" class="filterSelect" multiple size="1" title="Accounts"><option value="">All accounts</option></select><select id="workspaceRouteEmail" class="filterSelect" multiple size="1" title="Emails"><option value="">All emails</option></select><button id="resetWorkspaceRouteFilters" class="resetFilters" type="button">Reset filters</button></div><table><thead><tr><th data-sort="profile">Profile</th><th data-sort="account_alias">Account</th><th data-sort="route">Route shown in ACL</th><th data-sort="email">Email</th><th data-sort="actions">Actions</th></tr></thead><tbody id="workspaceRoutes"></tbody></table></section><div class="msg" id="workspaceMsg"></div></section><section id="settingsChannels" class="settingBlock hidden"><h3>Channel Configuration</h3><div class="contentTabs channelTabs"><button id="channelTop-telegram" class="active" type="button">Telegram <span class="alphaBadge">alpha</span></button><button id="channelTop-whatsapp" type="button">WhatsApp</button><button id="channelTop-webhooks" type="button">Webhooks</button><button id="channelTop-email" type="button">Email</button></div><section id="channelPane-telegram" class="channelPane"><section class="channelSummaryGrid"><div class="metricCard"><div class="metricLabel">Connection Status</div><div id="telegramBotSummary" class="metricValue">Not loaded</div><div class="metricHint">Bot account that sends approval messages.</div></div><div class="metricCard toggleMetric"><div class="metricLabel">Enabled</div><label class="switchRow"><input id="deliveryRulesToggle" type="checkbox"/><span class="switchTrack" aria-hidden="true"></span><span id="telegramDeliverySummary" class="metricValue">Not loaded</span></label><div class="metricHint">Off means approvals appear only in this UI.</div></div></section><section class="panel destinationPanel"><div class="sectionHead"><div><h4>Telegram destinations</h4><div class="muted">Current Telegram chats where approval requests are sent.</div></div></div><table><thead><tr><th>Destination</th><th>Chat</th><th>Applies to</th><th>Status</th><th>Action</th></tr></thead><tbody id="approvalChannels"></tbody></table></section><details id="addTelegramDestination" class="panel relaxedDetails"><summary><span>Add Approval destination</span><small>Telegram chat where Approval requests will be sent</small></summary><div class="detailBody"><div class="formgrid simpleChannelForm"><label class="fieldLabel"><span>Destination label</span><input id="channelLabel" placeholder="Hagrid approvals"/><small>A short name shown in the destinations table.</small></label><label class="fieldLabel"><span>Telegram chat ID</span><input id="channelChatId" placeholder="8788573059 or -100…"/><small>The DM, group, topic, or channel that should receive approval messages.</small></label><label class="fieldLabel"><span>Applies to</span><select id="channelScope"><option value="all">All profiles</option><option value="profile">One Hermes profile</option></select><small>Use All profiles unless this chat is only for one profile.</small></label><label class="fieldLabel"><span>Hermes profile</span><select id="channelProfile"></select><small>Used only when Applies to is One Hermes profile.</small></label><label class="fieldLabel"><span>Status</span><select id="channelEnabled"><option value="true">Enabled</option><option value="false">Disabled</option></select><small>Disable this destination without deleting it.</small></label><div class="formActions full"><button id="saveChannel" class="primary">Save destination</button></div></div></div></details><details id="telegramBotConfig" class="panel relaxedDetails"><summary><span>Governance Approver Configuration</span><small>Only needed when creating or rotating the shared bot</small></summary><div class="detailBody"><p class="muted">Most day-to-day changes only need approval destinations above. Open this only when replacing the bot token or button URL.</p><div class="formgrid channelForm"><label class="fieldLabel"><span>Bot token</span><input id="telegramBotToken" type="password" placeholder="Leave blank to keep the current token"/><small>Paste a new Telegram bot token only when rotating or setting it for the first time.</small></label><label class="fieldLabel"><span>Webhook public URL</span><input id="approvalPublicBaseUrl" placeholder="https://gateway.example.com"/><small>Public URL Telegram calls for inline button callbacks. It can point at the Control UI or gateway.</small></label><label class="fieldLabel"><span>Webhook token</span><input id="approvalWebhookToken" type="password" placeholder="Leave blank to keep current or derived token"/><small>Optional shared secret used in the webhook URL and Telegram secret-token header. Set this when you want to choose/rotate the token yourself.</small></label><label class="checkRow"><input id="clearTelegramBotToken" type="checkbox"/> Clear saved shared bot token</label><label class="checkRow"><input id="clearApprovalWebhookToken" type="checkbox"/> Clear saved webhook token and return to derived token</label><button id="saveBotSettings" class="primary">Save approver configuration</button></div></div></details><div class="msg" id="channelMsg"></div></section><section id="channelPane-whatsapp" class="channelPane hidden"><section class="panel comingSoon"><h4>WhatsApp approvals</h4><p class="muted">This will support OpenWA approval delivery after validation.</p></section></section><section id="channelPane-webhooks" class="channelPane hidden"><section class="panel comingSoon"><h4>Webhook approvals</h4><p class="muted">This will send approval events to HTTP endpoints for external systems after validation.</p></section></section><section id="channelPane-email" class="channelPane hidden"><section class="panel comingSoon"><h4>Email approvals</h4><p class="muted">This will deliver approval requests by email after validation.</p></section></section></section><section id="settingsRuntime" class="settingBlock hidden"><h3>System Settings</h3><div class="contentTabs"><button id="runtimeTop-status">Runtime status</button><button id="runtimeTop-validation">Config validation</button><button id="runtimeTop-backups">Backups</button><button id="runtimeTop-paths">File locations</button><button id="runtimeTop-upgrade">Upgrade & logs</button></div><section id="runtimePane-status" class="runtimePane runtimeStatusPane"><div class="runtimeHero"><div><h4>Runtime status</h4><p class="muted">Operational health, source sync, defaults, and fast service actions.</p></div><button id="refreshRuntime">Refresh status</button></div><div class="runtimeStatusGrid"><article class="runtimeStatusCard runtimePrimaryCard"><div class="statusCardLabel">Gateway health</div><div id="runtimeHealth" class="statusBig code">unknown</div><div class="runtimeActions"><button id="applyRuntime" class="primary">Apply runtime policy</button><button id="restartRuntime">Restart / reload gateway</button></div><div class="msg" id="runtimeMsg"></div></article><article class="runtimeStatusCard"><div class="statusCardLabel">Service endpoints</div><div class="statusKv"><span>Gateway</span><b id="setGateway" class="code"></b></div><div class="statusKv"><span>Control bind</span><b id="setBind" class="code"></b></div><div class="statusKv"><span>Auth</span><b id="setAuth" class="code"></b></div><div class="statusKv"><span>Reload mode</span><b id="setReloadMode" class="code"></b></div></article><article class="runtimeStatusCard"><div class="statusCardLabel">Policy defaults</div><div class="statusKv"><span>Unknown profile</span><b id="setUnknownProfile" class="code"></b></div><div class="statusKv"><span>Unknown resource</span><b id="setUnknownResource" class="code"></b></div><div class="statusKv"><span>Grafana/Loki</span><b class="code">{job="hermes-google-governance-audit"}</b></div></article></div><article class="runtimeStatusCard runtimeVersionCard"><div class="statusCardLabel">Version / source sync</div><div id="runtimeVersion" class="runtimeBox muted">Loading version…</div></article></section><section id="runtimePane-validation" class="runtimePane hidden"><h4>Config validation</h4><p class="muted">UI/API is authoritative. Direct YAML edits are import/recovery material and will be overwritten by the next UI save or Regenerate YAML action.</p><div class="configSummaryGrid"><div class="configSummaryItem"><span class="configSummaryLabel">Last YAML sync/write</span><span id="yamlLastSync" class="configSummaryValue code">unknown</span></div><div class="configSummaryItem"><span class="configSummaryLabel">YAML/runtime parity</span><span id="yamlParity" class="configSummaryValue code">unknown</span></div><div class="configSummaryItem"><span class="configSummaryLabel">Policy YAML</span><span id="yamlPolicyPath" class="configSummaryValue code"></span></div><div class="configSummaryItem"><span class="configSummaryLabel">Registry YAML</span><span id="yamlRegistryPath" class="configSummaryValue code"></span></div></div><div class="runtimeActions"><button id="validateRuntime" class="primary">Validate config</button><button id="compareYamlUi">Compare UI ↔ YAML</button><button id="syncYamlFromUi">Regenerate YAML from UI</button></div><div id="runtimeValidation" class="validationPanel muted">Click Validate config or Compare UI ↔ YAML.</div></section><section id="runtimePane-backups" class="runtimePane hidden backupPane"><div class="backupHero"><div><h4>Backups</h4><p class="muted">Create, download, validate, and schedule runtime backups.</p></div><label class="checkRow backupTokenToggle"><input id="backupTokens" type="checkbox"/> Include token store</label></div><div class="backupGrid"><article class="backupCard primaryBackup"><div><h4>Create backup</h4><p class="muted">Generate a new runtime archive. Include tokens only for protected disaster recovery.</p></div><div class="backupActions"><button id="createBackup" class="primary">Create backup</button><button id="exportBackup">Prepare latest download</button><a id="downloadBackup" class="downloadLink hidden" href="#" download>Download</a></div></article><article class="backupCard"><h4>Upload / validate</h4><p class="muted">Validate an uploaded archive or a server-side backup path before restore workflows.</p><div class="fileRow backupFileRow"><input id="importBackupFile" type="file" accept=".tgz,.gz,.tar.gz,application/gzip"/><input id="importBackupPath" placeholder="Server backup archive path"/><button id="importBackup">Validate</button></div></article><article class="backupCard"><h4>Scheduled backups</h4><p class="muted">Choose a preset or provide a cron expression.</p><div class="fileRow backupScheduleRow"><select id="backupCronPreset"><option value="0 2 * * *">Daily at 2:00 AM</option><option value="0 2 * * 0">Weekly Sunday 2:00 AM</option><option value="0 */6 * * *">Every 6 hours</option></select><input id="backupCron" placeholder="Cron: 0 2 * * *" value="0 2 * * *"/><button id="scheduleBackup" class="primary">Save</button><button id="disableBackupSchedule">Disable</button></div></article></div><div class="backupStatusGrid"><div id="runtimeBackups" class="runtimeBox muted">No backups loaded.</div><div id="runtimeBackupIo" class="runtimeBox muted">Backup status appears here.</div></div></section><section id="runtimePane-paths" class="runtimePane hidden"><div class="runtimeHero"><div><h4>File locations</h4><p class="muted">Authoritative runtime paths for YAML, generated policy, SQLite DBs, token custody, backups, logs, and stale root-level config files.</p></div><button id="refreshRuntimePaths" type="button">Refresh paths</button></div><div id="runtimePaths" class="runtimeBox muted">Loading file locations…</div></section><section id="runtimePane-upgrade" class="runtimePane hidden runtimeUpgradePane"><div class="runtimeHero"><div><h4>Upgrade & logs</h4><p class="muted">Source sync state, rollout guidance, and live-log verification.</p></div><button id="refreshRuntimeUpgrade" type="button">Refresh status</button></div><div class="upgradeGrid"><article class="runtimeStatusCard upgradePrimary"><div class="statusCardLabel">Upgrade readiness</div><div id="runtimeUpgradeStatus" class="runtimeBox muted">Loading source sync status…</div></article><article class="runtimeStatusCard"><div class="statusCardLabel">Deployment path</div><ol class="runtimeSteps"><li>Confirm source sync state.</li><li>Apply runtime policy if config changed.</li><li>Restart / reload gateway.</li><li>Verify control-ui events in Access logs.</li></ol></article><article class="runtimeStatusCard"><div class="statusCardLabel">Live-log verification</div><p class="muted">Runtime actions from this page are written into the Access logs tab as Control UI rows.</p><p>After restart/reload, open <b>Access logs</b> and filter <span class="code">Route = control-ui</span>.</p></article></div></section></section></div></div></section>
</div></div><div class="msg" id="foot"></div></section><div id="detailModal" class="detailModal hidden" role="dialog" aria-modal="true" aria-labelledby="detailModalTitle"><div class="detailModalCard"><div class="detailModalHead"><h3 id="detailModalTitle">Request details</h3><button id="detailModalClose" class="iconBtn" aria-label="Close details">✕</button></div><div id="detailModalBody" class="detailModalBody"></div></div></div></main><script>
let data={rules:[],resources:[],access_log:[],summary:{decisions:{}},control:{}}, users=[], mcpData={tools:[],routes:[]}, active='rules', settingsActive='profile', settingsMode='user', workspaceActive='auth', runtimeActive='status', settingsNavCollapsed=localStorage.ggovSettingsNavCollapsed==='1', adminSettingsExpanded=localStorage.ggovAdminSettingsExpanded!=='0', apiTokenFilters={}, apiTokenStatusDefaulted=false, me=null, selected=new Set(), aclSelectionTouched=false, pending2fa=null, pendingTotpChallenge='', sortState={rules:{key:'profile',dir:1},access:{key:'ts',dir:-1},users:{key:'first_name',dir:1},workspaceTokens:{key:'email',dir:1},workspaceRoutes:{key:'profile',dir:1},apiTokens:{key:'created_at',dir:-1}}, clientSecretJson=''; const $=id=>document.getElementById(id); const esc=s=>String(s??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch])); const norm=s=>String(s??'').trim(); const uniq=a=>{const seen=new Set(),out=[]; for(const x of a){const v=norm(x); const k=v.toLowerCase(); if(seen.has(k)) continue; seen.add(k); out.push(v)} return out.sort((a,b)=>a.localeCompare(b));}; const rowKey=r=>[r.profile,r.scope,r.resource_alias,r.action].join('|');
function b64urlToBuf(s){s=String(s||'').replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4)s+='='; const bin=atob(s); const buf=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++)buf[i]=bin.charCodeAt(i); return buf.buffer} function bufToB64url(buf){const bytes=new Uint8Array(buf); let bin=''; bytes.forEach(b=>bin+=String.fromCharCode(b)); return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')} function webauthnOptions(o){const x=JSON.parse(JSON.stringify(o||{})); if(x.challenge)x.challenge=b64urlToBuf(x.challenge); if(x.user&&x.user.id)x.user.id=b64urlToBuf(x.user.id); ['allowCredentials','excludeCredentials'].forEach(k=>{if(Array.isArray(x[k]))x[k]=x[k].map(c=>({...c,id:b64urlToBuf(c.id)}))}); return x} function webauthnSupported(){return !!(window.PublicKeyCredential&&navigator.credentials&&location.protocol==='https:'||location.hostname==='localhost'||location.hostname==='127.0.0.1')} function credentialResponse(cred,challenge){const r=cred.response; return {id:cred.id,rawId:bufToB64url(cred.rawId),challenge,clientDataJSON:bufToB64url(r.clientDataJSON),authenticatorData:r.authenticatorData?bufToB64url(r.authenticatorData):'',signature:r.signature?bufToB64url(r.signature):'',userHandle:r.userHandle?bufToB64url(r.userHandle):'',publicKey:r.getPublicKey?bufToB64url(r.getPublicKey()):'',signCount:r.getAuthenticatorData?new DataView(r.getAuthenticatorData()).getUint32(33,false):0,transports:r.getTransports?r.getTransports():[]}} function renderYubiKeyList(){const keys=(me&&me.yubikey_2fa_credentials)||[]; if($('yubiKeyCount'))$('yubiKeyCount').textContent=String(keys.length); const list=$('yubiKeyList'); if(!list)return; list.classList.toggle('muted',!keys.length); list.innerHTML=keys.length?keys.map(k=>`<div class="credentialItem"><div><b>${esc(k.label||'YubiKey 2FA')}</b><span class="credentialMeta">Added ${esc(fmtLocalTime(k.created_at))}${k.last_used_at?` · Last used ${esc(fmtLocalTime(k.last_used_at))}`:''}${k.id_tail?` · …${esc(k.id_tail)}`:''}</span></div><button class="dangerBtn compactDanger" type="button" data-yubi-id="${esc(k.credential_id)}" data-yubi-label="${esc(k.label||'YubiKey 2FA')}">Delete</button></div>`).join(''):'No YubiKeys registered.'; list.querySelectorAll('button[data-yubi-id]').forEach(btn=>{btn.onclick=async()=>{try{await removeWebauthn('yubikey_2fa',btn.dataset.yubiLabel||'YubiKey 2FA',btn.dataset.yubiId)}catch(e){$('profileMsg').className='msg error';$('profileMsg').textContent=e.message}}});}
function updateTwofaUi(){if(!me)return; const totp=!!me.totp_enabled, passkeys=Number(me.passkey_count||0), yubi=Number(me.yubikey_2fa_count||0); if($('twofaStatus'))$('twofaStatus').textContent=`Authenticator app: ${totp?'enabled':'not enabled'} · Passkey: ${passkeys?passkeys:'none'} · YubiKey 2FA keys: ${yubi}`; if($('startTotp')){$('startTotp').disabled=totp||!!pendingTotpChallenge; $('startTotp').textContent=totp?'Authenticator app configured':'Set up authenticator app'} if($('disableTotp'))$('disableTotp').disabled=!totp; if($('registerPasskey')){$('registerPasskey').disabled=passkeys>0; $('registerPasskey').textContent=passkeys>0?'Passkey already configured':'Set up passkey'; $('registerPasskey').title=passkeys>0?'Remove the existing passkey before setting up a new one.':'Set up passwordless sign-in';} if($('removePasskeys'))$('removePasskeys').disabled=!passkeys; if($('removeYubi'))$('removeYubi').disabled=!yubi; renderYubiKeyList()}
function readRouteState(){const parts=(location.hash||'').replace(/^#/,'').split('/').filter(Boolean); if(parts[0]==='access')active='access'; else if(parts[0]==='approvals')active='approvals'; else if(parts[0]==='mcp')active='mcp'; else if(parts[0]==='settings'){active='settings'; if(parts[1]==='admin'){settingsMode='admin'; settingsActive=['users','workspace','channels','runtime','tokens'].includes(parts[2])?parts[2]:(parts[2]==='oidc'?'users':'workspace'); if(settingsActive==='workspace'&&['overview','auth','reauth','profiles'].includes(parts[3]))workspaceActive=parts[3]; if(settingsActive==='runtime'&&['status','validation','backups','paths','upgrade'].includes(parts[3]))runtimeActive=parts[3];} else {settingsMode='user'; settingsActive='profile';}} else active='rules';}
function writeRouteState(){let hash=active; if(active==='mcp')hash='mcp'; if(active==='approvals')hash='approvals'; if(active==='settings')hash=settingsMode==='admin'?`settings/admin/${settingsActive}${settingsActive==='workspace'?'/'+workspaceActive:''}${settingsActive==='runtime'?'/'+runtimeActive:''}`:'settings/profile'; if(location.hash.slice(1)!==hash) history.replaceState(null,'','#'+hash);} readRouteState(); window.addEventListener('hashchange',()=>{readRouteState();render();});
function applyPrefs(){const light=localStorage.ggovTheme==='light';document.body.classList.toggle('light',light);['theme','loginTheme'].forEach(id=>{const theme=$(id);if(theme){theme.dataset.theme=light?'light':'dark';theme.title=light?'Switch to dark theme':'Switch to light theme';theme.setAttribute('aria-label',theme.title);}});const label=$('themeLabel');if(label)label.textContent=light?'Light theme':'Dark theme';} applyPrefs(); function toggleTheme(){localStorage.ggovTheme=localStorage.ggovTheme==='light'?'dark':'light';applyPrefs()} $('theme').onclick=toggleTheme;if($('loginTheme'))$('loginTheme').onclick=toggleTheme; if($('activityBell'))$('activityBell').onclick=e=>{e.stopPropagation();$('activityPanel').classList.toggle('hidden')}; if($('clearActivity'))$('clearActivity').onclick=()=>{localStorage.ggovActivityClearedAt=new Date().toISOString(); updateActivityChrome(); if($('activityPanel'))$('activityPanel').classList.add('hidden')}; document.addEventListener('click',e=>{const p=$('activityPanel'); if(p&&!p.classList.contains('hidden')&&!e.target.closest('.notificationWrap'))p.classList.add('hidden')});
function rememberMultiSelectState(el){if(el&&el.multiple)el.dataset.prevValues=JSON.stringify([...el.selectedOptions].map(o=>o.value));} function opt(sel, vals, keep=false){if(!sel)return; const old=sel.multiple?[...sel.selectedOptions].map(o=>o.value):sel.value; sel.innerHTML=''; const clean=uniq(vals); const specificOld=Array.isArray(old)?old.filter(Boolean):[]; const useAll=sel.multiple&&(!keep||!specificOld.length); clean.forEach(v=>{const o=document.createElement('option');o.value=v;o.textContent=v||sel.dataset.placeholder||'All'; if(sel.multiple){o.selected=useAll?!v:(keep&&specificOld.includes(v));} else if(keep&&old===v) o.selected=true; sel.appendChild(o)}); if(sel.multiple&&useAll&&sel.options.length)sel.options[0].selected=true; if(keep&&!sel.multiple&&clean.includes(old)) sel.value=old; rememberMultiSelectState(sel);} function normalizeMultiSelect(el){if(!el||!el.multiple)return; let prev=[]; try{prev=JSON.parse(el.dataset.prevValues||'[]')}catch(_){prev=[]} const allOpt=[...el.options].find(o=>!o.value); const allSelected=!!(allOpt&&allOpt.selected); const selected=[...el.selectedOptions]; const specific=selected.filter(o=>o.value); if(allSelected&&!prev.includes('')){[...el.options].forEach(o=>{o.selected=!o.value});} else if(specific.length){[...el.options].forEach(o=>{if(!o.value)o.selected=false});} else if(el.options.length){el.options[0].selected=true;}} function bindFilter(id,fn,event='change'){const el=$(id); if(!el)return; rememberMultiSelectState(el); el.addEventListener(event,e=>{normalizeMultiSelect(e.target); rememberMultiSelectState(e.target); fn(e);});} function selectedValues(id){const el=$(id); return el?[...el.selectedOptions].map(o=>o.value).filter(Boolean):[]} function selectedHas(id,val){const xs=selectedValues(id); return !xs.length||xs.includes(String(val||''))} async function api(path,payload){const r=await fetch(path,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload||{})}); const j=await r.json().catch(()=>({})); if(!r.ok) throw new Error(j.message||j.error||JSON.stringify(j)); return j;} async function get(path){const r=await fetch(path,{credentials:'same-origin'}); const j=await r.json().catch(()=>({})); if(!r.ok) throw new Error(j.message||j.error||JSON.stringify(j)); return j;}
function updateWelcomeTitle(){if(!$('welcomeName'))return; const name=me?(me.display_name||me.username):''; const firstLast=me?[me.first_name,me.last_name].filter(Boolean).join(' ').trim():''; $('welcomeName').textContent='Welcome, '+(firstLast||name||'');}
function isAdmin(){return me&&me.role==='admin'} function updateAdminVisibility(){const admin=isAdmin(); if($('adminSettings')) $('adminSettings').classList.toggle('hidden',!admin); if($('tab-adminSettings')){const adminToggle=$('tab-adminSettings');adminToggle.classList.toggle('hidden',!admin);adminToggle.classList.toggle('expanded',!!(admin&&adminSettingsExpanded));adminToggle.setAttribute('aria-expanded',String(!!(admin&&adminSettingsExpanded)));} document.querySelectorAll('.adminSubItem').forEach(b=>b.classList.toggle('hidden',!(admin&&active==='settings'&&settingsMode==='admin'&&adminSettingsExpanded))); if($('tab-approvals')) $('tab-approvals').classList.toggle('hidden',!admin); if(!admin){settingsMode='user'; settingsActive='profile';} const adminMode=admin&&settingsMode==='admin'; const userMode=settingsMode!=='admin'; if($('settingsNav-profile')) $('settingsNav-profile').classList.toggle('hidden',!userMode); ['users','workspace','runtime','tokens'].forEach(s=>{const b=$('settingsNav-'+s); if(b)b.classList.toggle('hidden',!adminMode)}); ['overview','auth','profiles'].forEach(s=>{const b=$('workspaceTab-'+s); if(b)b.classList.toggle('hidden',!adminMode)}); ['status','validation','backups','paths','upgrade'].forEach(s=>{const b=$('runtimeTab-'+s); if(b)b.classList.toggle('hidden',!adminMode)}); if(userMode) settingsActive='profile'; if(adminMode&&settingsActive==='profile') settingsActive='workspace';} function updateUserChrome(){if(!me)return; const name=me.display_name||me.username; if($('userMenuName'))$('userMenuName').textContent=name; updateWelcomeTitle(); if($('userDropdownName'))$('userDropdownName').textContent=name; if($('userDropdownRole'))$('userDropdownRole').textContent=me.role; if($('userMenuAvatar')){$('userMenuAvatar').classList.toggle('hidden',!me.avatar_url); if(me.avatar_url)$('userMenuAvatar').src=me.avatar_url;} if($('settingsMe'))$('settingsMe').textContent=name; if($('settingsRole'))$('settingsRole').textContent=me.role; if($('profileFirst'))$('profileFirst').value=me.first_name||''; if($('profileLast'))$('profileLast').value=me.last_name||''; if($('profileEmail'))$('profileEmail').value=me.email||''; if($('profilePhotoPreview')){$('profilePhotoPreview').classList.toggle('hidden',!me.avatar_url); if(me.avatar_url)$('profilePhotoPreview').src=me.avatar_url;} updateTwofaUi(); updateAdminVisibility();} 
async function loadOidcLogin(){try{const j=await get('/api/oidc/public'); const c=j.oidc||{}; const btn=$('oidcLoginBtn'); const hint=$('oidcLoginHint'); if(btn){btn.classList.toggle('hidden',!c.enabled); btn.onclick=()=>{location.href=c.login_url||'/api/oidc/login'};} if(hint)hint.classList.toggle('hidden',!c.enabled);}catch(_){if($('oidcLoginBtn'))$('oidcLoginBtn').classList.add('hidden');}}
async function check(){try{const j=await get('/api/me'); me=j.user; document.body.classList.remove('authing'); updateUserChrome(); $('setupView').classList.add('hidden'); $('loginView').classList.add('hidden'); $('appView').classList.remove('hidden'); $('tab-userSettings').classList.remove('hidden'); if($('userMenu'))$('userMenu').classList.remove('hidden'); try{await load()}catch(loadErr){$('ruleMsg').className='msg error';$('ruleMsg').textContent=loadErr.message||'Signed in, but snapshot failed to load.'; render();}}catch(e){try{const h=await get('/healthz'); document.body.classList.add('authing'); if(h.setup_required){$('setupView').classList.remove('hidden');$('loginView').classList.add('hidden')}else{$('setupView').classList.add('hidden');$('loginView').classList.remove('hidden'); await loadOidcLogin();}}catch(_){$('loginView').classList.remove('hidden'); await loadOidcLogin();} $('appView').classList.add('hidden'); $('tab-userSettings').classList.add('hidden'); if($('userMenu'))$('userMenu').classList.add('hidden')}}
$('setupBtn').onclick=async()=>{try{await api('/api/setup',{setup_token:$('setupToken').value,username:$('setupUser').value,first_name:$('setupFirst').value,last_name:$('setupLast').value,password:$('setupPass').value}); $('setupMsg').className='msg ok';$('setupMsg').textContent='Admin created. Sign in.'; $('setupView').classList.add('hidden');$('loginView').classList.remove('hidden')}catch(e){$('setupMsg').className='msg error';$('setupMsg').textContent=e.message}};
async function finishLogin(j){if(j.status==='2fa_required'){pending2fa=j; $('twofaBox').classList.remove('hidden'); $('loginMsg').className='msg'; $('loginMsg').textContent='Enter your authenticator code or touch your YubiKey 2FA.'; $('loginPass').value=''; if($('loginYubiBtn'))$('loginYubiBtn').classList.toggle('hidden',!(j.methods||[]).includes('yubikey_2fa')); if($('loginTotp'))$('loginTotp').focus(); return;} $('loginPass').value=''; if($('loginTotp'))$('loginTotp').value=''; pending2fa=null; await check();}
async function yubiLogin(){if(!pending2fa)throw new Error('Sign in with password first.'); if(!webauthnSupported())throw new Error('YubiKey 2FA requires WebAuthn over HTTPS or localhost.'); const opts=await api('/api/login/webauthn/options',{challenge:pending2fa.challenge}); const cred=await navigator.credentials.get({publicKey:webauthnOptions(opts.publicKey)}); const resp=credentialResponse(cred,opts.challenge); resp.method='yubikey_2fa'; resp.challenge=pending2fa.challenge; resp.assertion_challenge=opts.challenge; const j=await api('/api/login/2fa',resp); await finishLogin(j);}
async function passkeyLogin(){if(!webauthnSupported())throw new Error('Passkey sign-in requires HTTPS or localhost.'); const opts=await api('/api/login/passkey/options',{}); const cred=await navigator.credentials.get({publicKey:webauthnOptions(opts.publicKey)}); const resp=credentialResponse(cred,opts.challenge); const j=await api('/api/login/passkey/verify',resp); await finishLogin(j);}
$('loginBtn').onclick=async()=>{try{const j=await api('/api/login',{username:$('loginUser').value,password:$('loginPass').value}); await finishLogin(j);}catch(e){$('loginMsg').className='msg error';$('loginMsg').textContent=e.message}}; if($('passkeyLoginBtn'))$('passkeyLoginBtn').onclick=async()=>{try{await passkeyLogin()}catch(e){$('loginMsg').className='msg error';$('loginMsg').textContent=e.message}}; if($('loginTotpBtn'))$('loginTotpBtn').onclick=async()=>{try{if(!pending2fa)throw new Error('Sign in with password first.'); const j=await api('/api/login/2fa',{challenge:pending2fa.challenge,method:'totp',code:$('loginTotp').value}); await finishLogin(j);}catch(e){$('loginMsg').className='msg error';$('loginMsg').textContent=e.message}}; if($('loginYubiBtn'))$('loginYubiBtn').onclick=async()=>{try{await yubiLogin()}catch(e){$('loginMsg').className='msg error';$('loginMsg').textContent=e.message}}; ['loginUser','loginPass','loginTotp'].forEach(id=>{$(id)?.addEventListener('keydown',e=>{if(e.key==='Enter')($('twofaBox')&&!$('twofaBox').classList.contains('hidden')?$('loginTotpBtn'):$('loginBtn')).click()})}); $('logout').onclick=async()=>{await api('/api/logout',{}).catch(()=>{}); location.reload()}; async function load(){data=await get('/api/snapshot'); hydrate(); render();}
function visibleRecentActivity(){const cleared=Date.parse(localStorage.ggovActivityClearedAt||'')||0; return (data.recent_activity||[]).filter(x=>!cleared||((Date.parse(x.ts||'')||0)>cleared));} function updateActivityChrome(){const pending=Number(data.pending_approvals||0); const ab=$('approvalBadge'); if(ab){ab.textContent=String(pending); ab.classList.toggle('hidden',pending<=0)} const recent=visibleRecentActivity(); const bb=$('activityBadge'); if(bb){bb.textContent=String(pending+recent.length); bb.classList.toggle('hidden',(pending+recent.length)<=0)} const list=$('activityList'); if(list)list.innerHTML=recent.length?recent.slice(0,20).map(x=>`<div class="activityItem"><div class="activityItemKind">${esc(x.kind||'activity')}</div><div class="activityItemSummary">${esc(x.summary||x.event||'Activity')}</div><div class="activityItemTime">${esc(fmtLocalTime(x.ts))}${x.actor?` · ${esc(x.actor)}`:''}</div></div>`).join(''):'No recent activity.';} function hydrate(){ $('cards').innerHTML=[['Rules',data.summary.rule_count,''],['Profiles',data.summary.profile_count,''],['Allow',data.summary.decisions.allow||0,'allow'],['Ask',data.summary.decisions.ask||0,'ask'],['Deny',data.summary.decisions.deny||0,'deny']].map(([l,v,d])=>`<button type="button" class="card aclMetricCard ${d?'filterable state-'+esc(d):''}" ${d?`data-decision-filter="${esc(d)}" title="Filter ACL rules to ${esc(d)} decisions"`:''}><div class="label">${esc(l)}</div><div class="metric">${esc(v)}</div></button>`).join(''); document.querySelectorAll('#cards [data-decision-filter]').forEach(card=>{card.onclick=()=>applyAclCardFilter(card.dataset.decisionFilter||'')}); updateActivityChrome(); $('profile').dataset.placeholder='All profiles'; $('decision').dataset.placeholder='All decisions'; $('service').dataset.placeholder='All services'; $('route').dataset.placeholder='All routes'; $('token').dataset.placeholder='All tokens'; hydrateRuleFilters(); hydrateMapProfiles(); $('setGateway').textContent=data.control.gateway||''; $('setBind').textContent=data.control.bind||''; $('setAuth').textContent=data.control.auth||''; if($('setReloadMode')) $('setReloadMode').textContent=(data.control.reload_mode||'hot')+' / SQLite token DB'; $('setUnknownProfile').textContent=data.unknown_profile_default||''; $('setUnknownResource').textContent=data.unknown_resource_default||''; updateUserChrome();}
function sortedRows(rows,table){const st=sortState[table]||{}; if(!st.key)return rows; return [...rows].sort((a,b)=>String(a[st.key]??'').localeCompare(String(b[st.key]??''))*st.dir)} function setSort(table,key){const st=sortState[table]; st.dir=st.key===key?-st.dir:1; st.key=key; render()} function setSelectSingle(id,value){const el=$(id); if(!el)return; [...el.options].forEach(o=>{o.selected=(o.value||o.textContent)===value}); el.dispatchEvent(new Event('change',{bubbles:true}))} function applyAclCardFilter(decision){if(!decision)return; selected.clear(); aclSelectionTouched=false; setSelectSingle('decision',decision); renderRules();} function ruleMatches(r,ignore=''){const q=$('q').value.toLowerCase();const tokenLabel=r.token_label||r.account_alias||'Default workspace token'; return (ignore==='profile'||selectedHas('profile',r.profile))&&(ignore==='decision'||selectedHas('decision',r.decision))&&(ignore==='service'||selectedHas('service',r.service))&&(ignore==='route'||selectedHas('route',r.token_route||''))&&(ignore==='token'||selectedHas('token',tokenLabel))&&(!q||JSON.stringify(r).toLowerCase().includes(q));} function filteredRules(ignore=''){return data.rules.filter(r=>ruleMatches(r,ignore));} function hydrateRuleFilters(){opt($('profile'),['',...filteredRules('profile').map(r=>r.profile)],true); opt($('decision'),['',...filteredRules('decision').map(r=>r.decision)],true); opt($('service'),['',...filteredRules('service').map(r=>r.service)],true); opt($('route'),['',...filteredRules('route').map(r=>r.token_route||'')],true); opt($('token'),['',...filteredRules('token').map(r=>r.token_label||r.account_alias||'Default workspace token')],true);} function syncSelected(){const n=selected.size; $('selectedCount').textContent=`${n} selected`; $('bulkApply').disabled=n===0;}
function renderRules(){hydrateRuleFilters(); const rows=sortedRows(filteredRules(),'rules'); const allShownSelected=rows.length&&rows.every(r=>selected.has(rowKey(r))); if($('selectAll')) $('selectAll').checked=!!allShownSelected; $('rules').innerHTML=rows.map((r,i)=>{const k=rowKey(r); const desc=r.action_description||r.notes||'Controls this Google Workspace action.'; return `<tr><td class="selectCell"><input type="checkbox" ${selected.has(k)?'checked':''} onchange='aclSelectionTouched=true;this.checked?selected.add(${JSON.stringify(k)}):selected.delete(${JSON.stringify(k)});syncSelected()'/></td><td><select class="inline" id="d${i}" onchange='saveRule(${JSON.stringify(r).replaceAll("'","&#39;")},this.value,this)'><option ${r.decision==='allow'?'selected':''}>allow</option><option ${r.decision==='ask'?'selected':''}>ask</option><option ${r.decision==='deny'?'selected':''}>deny</option></select></td><td>${esc(r.profile)}</td><td>${esc(r.token_label||r.account_alias||'Default workspace token')}</td><td><span class="code">${esc(r.token_route||'default')}</span></td><td><span class="actionCell"><span>${esc(r.action)}</span><span class="actionHelp" title="${esc(desc)}" aria-label="${esc(desc)}">i</span></span></td><td>${esc(r.service)}</td></tr>`}).join(''); $('foot').textContent=`${rows.length} rules shown • generated ${data.generated_at}`; syncSelected();}
async function saveRule(r,decision,btn){const reason='GUI inline ACL auto-save'; const original=btn&&btn.value; if(btn){btn.disabled=true;btn.classList.add('saving');btn.title='Saving…'} try{await api('/api/policy/apply',{profile:r.profile,scope:r.scope,resource_alias:r.resource_alias==='__profile_default__'?'':r.resource_alias,action:r.action,decision,reason}); if(btn){btn.classList.remove('saving');btn.classList.add('saved');btn.title='Saved'} $('ruleMsg').className='msg ok'; $('ruleMsg').textContent='Auto-saved, runtime policy applied, and gateway reloaded.'; selected.delete(rowKey(r)); await load();}catch(e){if(btn){btn.disabled=false;btn.classList.remove('saving');btn.classList.add('errorBtn');btn.title='Save failed'; if(original)btn.value=original;} $('ruleMsg').className='msg error';$('ruleMsg').textContent=e.message}}
$('selectAll').onchange=()=>{aclSelectionTouched=true;filteredRules().forEach(r=>{$('selectAll').checked?selected.add(rowKey(r)):selected.delete(rowKey(r))}); renderRules()}; $('bulkApply').onclick=async()=>{const rows=data.rules.filter(r=>selected.has(rowKey(r))); if(!rows.length)return; const decision=$('bulkDecision').value; const reason='Bulk ACL update'; if(!confirm(`Apply ${decision} to ${rows.length} selected rules?`))return; try{await api('/api/policy/bulk-apply',{reason,changes:rows.map(r=>({profile:r.profile,scope:r.scope,resource_alias:r.resource_alias,action:r.action,decision}))}); selected.clear(); $('ruleMsg').className='msg ok';$('ruleMsg').textContent=`Bulk update applied to ${rows.length} rules; runtime policy applied and gateway reloaded.`; await load();}catch(e){$('ruleMsg').className='msg error';$('ruleMsg').textContent=e.message}};
function fmt(v){return esc(v||'')} function fmtLocalTime(v){if(!v)return '—'; try{return new Intl.DateTimeFormat('en-US',{timeZone:'America/Chicago',year:'numeric',month:'short',day:'2-digit',hour:'numeric',minute:'2-digit',second:'2-digit'}).format(new Date(v));}catch(_){return String(v)}} function fmtTime(e){return esc(e.time_cst||e.ts||'')} function targetDetails(e){return ''} function accessMatches(e,ignore=''){const q=($('accessQ').value||'').toLowerCase(); return (ignore==='profile'||selectedHas('accessProfile',e.profile))&&(ignore==='action'||selectedHas('accessAction',e.action))&&(ignore==='decision'||selectedHas('accessDecision',e.decision))&&(ignore==='status'||selectedHas('accessStatus',e.outcome||e.status))&&(ignore==='route'||selectedHas('accessRoute',e.token_route))&&(!q||[e.actual_access,e.resource_alias,e.profile,e.action,e.service,e.decision,e.outcome,e.status,e.token_route].join(' ').toLowerCase().includes(q));} function filteredAccessLog(ignore=''){return (data.access_log||[]).filter(e=>accessMatches(e,ignore));} function hydrateAccessFilters(){if($('accessProfile'))$('accessProfile').dataset.placeholder='All profiles'; if($('accessAction'))$('accessAction').dataset.placeholder='All actions'; if($('accessDecision'))$('accessDecision').dataset.placeholder='All decisions'; if($('accessStatus'))$('accessStatus').dataset.placeholder='All statuses'; if($('accessRoute'))$('accessRoute').dataset.placeholder='All routes'; opt($('accessProfile'),['',...filteredAccessLog('profile').map(e=>e.profile)],true); opt($('accessAction'),['',...filteredAccessLog('action').map(e=>e.action)],true); opt($('accessDecision'),['',...filteredAccessLog('decision').map(e=>e.decision)],true); opt($('accessStatus'),['',...filteredAccessLog('status').map(e=>e.outcome||e.status)],true); opt($('accessRoute'),['',...filteredAccessLog('route').map(e=>e.token_route)],true);} async function loadAccessLog(){try{const j=await get('/api/access-log'); data.access_log=j.events||[]; hydrateAccessFilters(); renderAccessLog();}catch(e){$('accessMsg').className='msg error';$('accessMsg').textContent=e.message}} function renderAccessLog(){hydrateAccessFilters(); const rows=sortedRows(filteredAccessLog(),'access'); window.__accessDetailRows=rows; $('accessLog').innerHTML=rows.map((e,i)=>`<tr><td>${fmtTime(e)}</td><td>${fmt(e.profile)}</td><td>${fmt(e.action)}${e.unknown_resource?' <span class="pill warn">unknown resource</span>':''}${e.high_risk_action?' <span class="pill danger">high risk</span>':''}</td><td>${fmt(e.decision)}</td><td><span class="pill">${fmt(e.outcome||e.status)}</span></td><td>${fmt(e.token_route)}</td><td><button class="iconBtn detailBtn" title="View actual access and full event details" aria-label="View actual access and full event details" data-detail-kind="access" data-detail-index="${i}">ⓘ</button></td></tr>`).join(''); $('accessLog').querySelectorAll('button[data-detail-kind="access"]').forEach(btn=>{btn.onclick=()=>showDetailModal('Access log details',window.__accessDetailRows[Number(btn.dataset.detailIndex)]||{})}); $('foot').textContent=`${rows.length} gateway events shown`; $('accessMsg').className='msg'; $('accessMsg').textContent=rows.length?'':'No matching gateway events.';}

function mcpToolMatches(t,ignore=''){const q=($('mcpQ')?.value||'').toLowerCase(); const risk=t.high_risk?'high risk':(t.testable?'read/testable':'not testable'); return (ignore==='service'||selectedHas('mcpService',t.service))&&(ignore==='risk'||selectedHas('mcpRisk',risk))&&(!q||[t.name,t.service,t.action,t.description].join(' ').toLowerCase().includes(q));}
function hydrateMcpFilters(){if($('mcpService')){$('mcpService').dataset.placeholder='All services';opt($('mcpService'),['',...(mcpData.tools||[]).filter(t=>mcpToolMatches(t,'service')).map(t=>t.service)],true)} if($('mcpRisk')){$('mcpRisk').dataset.placeholder='All risk levels';opt($('mcpRisk'),['','read/testable','high risk','not testable'],true)}}
function selectedMcpTool(){return $('mcpTestTool')?.value||''} function selectedMcpRoute(){return (mcpData.routes||data.workspace_routes||[]).find(r=>(r.route||'')===$('mcpTestRoute')?.value)||null;} function mcpToolService(name){const t=(mcpData.tools||[]).find(x=>x.name===(name||selectedMcpTool())); return t?t.service:'';} function routeSupportsTool(route,service){if(!service)return true; const services=route.services||[]; return !services.length||services.includes(service)||services.includes('full_workspace')||services.includes('all');} function filteredMcpRoutes(){const profile=$('mcpTestProfile')?.value||''; return (mcpData.routes||data.workspace_routes||[]).filter(r=>(!profile||r.profile===profile));} function refreshMcpRouteOptions(){const sel=$('mcpTestRoute'); if(!sel)return; const cur=sel.value; const routes=filteredMcpRoutes(); sel.innerHTML='<option value="">Default route for selected profile</option>'+routes.map(r=>`<option value="${esc(r.route||'')}">${esc(r.profile||'')} · ${esc(r.account_display||r.token_label||r.account_alias||r.route||'')} · ${(r.services||[]).length?esc((r.services||[]).join(', ')):'all services'}</option>`).join(''); if(cur&&[...sel.options].some(o=>o.value===cur))sel.value=cur; refreshMcpToolOptions();} function refreshMcpToolOptions(){const sel=$('mcpTestTool'); if(!sel)return; const cur=sel.value; const route=selectedMcpRoute(); const rows=(mcpData.tools||[]).filter(t=>t.testable&&(!route||routeSupportsTool(route,t.service))); sel.innerHTML=rows.map(t=>`<option value="${esc(t.name)}">${esc(t.name)} · ${esc(t.service)}</option>`).join('')||'<option value="">No safe read tools for selected route</option>'; if(cur&&[...sel.options].some(o=>o.value===cur))sel.value=cur; else if(sel.value) pickMcpTool(sel.value,false);}
function renderMcpTools(){hydrateMcpFilters(); const rows=(mcpData.tools||[]).filter(t=>mcpToolMatches(t)); if($('mcpTools'))$('mcpTools').innerHTML=rows.map(t=>`<tr><td><button onclick="pickMcpTool('${esc(t.name)}')" ${t.testable?'':'disabled title="Catalog only: use a full MCP client or approval flow"'}>${esc(t.name)}</button></td><td>${esc(t.service)}</td><td>${t.high_risk?'<span class="pill warn">high risk</span>':(t.testable?'<span class="pill ok">read/testable</span>':'<span class="pill">catalog only</span>')}</td><td>${esc(t.description||'')}</td></tr>`).join('')||'<tr><td colspan="4" class="muted">No MCP tools match the filters.</td></tr>'; const profiles=uniq((data.profile_options||data.rules||[]).map(r=>typeof r==='string'?r:r.profile).filter(Boolean)); if($('mcpTestProfile')){const cur=$('mcpTestProfile').value; $('mcpTestProfile').innerHTML=profiles.map(p=>`<option value="${esc(p)}">${esc(p)}</option>`).join(''); if(cur&&profiles.includes(cur))$('mcpTestProfile').value=cur;} refreshMcpRouteOptions();}
function pickMcpTool(name,refreshRoutes=true){if($('mcpTestTool'))$('mcpTestTool').value=name; const samples={get_events:{calendar:'primary',max_results:5},search_gmail_messages:{query:'newer_than:7d',max_results:5},search_drive_files:{query:"trashed = false",page_size:5},query_freebusy:{calendar_ids:['primary']}}; if($('mcpTestArgs'))$('mcpTestArgs').value=JSON.stringify(samples[name]||{},null,2); if(refreshRoutes)refreshMcpRouteOptions();}
async function loadMcpTools(){try{const j=await get('/api/mcp/tools'); mcpData=j; renderMcpTools();}catch(e){if($('mcpMsg')){$('mcpMsg').className='msg error';$('mcpMsg').textContent=e.message}}}
async function runMcpTest(){try{const payload={tool:$('mcpTestTool').value,profile:$('mcpTestProfile').value,route:$('mcpTestRoute').value,args:JSON.parse($('mcpTestArgs').value||'{}')}; $('mcpTestResult').textContent='Running…'; const j=await api('/api/mcp/test',payload); $('mcpTestResult').textContent=JSON.stringify(j,null,2); $('mcpMsg').className='msg ok';$('mcpMsg').textContent='MCP test completed through governance.'; await loadAccessLog();}catch(e){$('mcpMsg').className='msg error';$('mcpMsg').textContent=e.message; if($('mcpTestResult'))$('mcpTestResult').textContent=e.stack||e.message}}

function updateRoutePickCounts(){const tc=selectedMapTokens().length, pc=selectedMapProfiles().length; if($('mapTokenCount')) $('mapTokenCount').textContent=`${tc} selected`; if($('mapProfileCount')) $('mapProfileCount').textContent=`${pc} selected`;}
function selectedMapProfiles(){return [...document.querySelectorAll('.routeProfileCheck:checked')].map(x=>x.value)}
function selectedMapTokens(){return [...document.querySelectorAll('.routeTokenCheck:checked')].map(x=>x.value)}
function renderRouteTokenPicker(rows){const old=selectedMapTokens(); if(!$('mapTokenPicker'))return; $('mapTokenPicker').innerHTML=rows.map(x=>`<label class="routePickItem"><input class="routeTokenCheck" type="checkbox" value="${esc(x.id)}" ${old.includes(x.id)?'checked':''} onchange="updateRoutePickCounts()"/><span><span class="routePickTitle">${esc(x.label||x.email||x.id)}</span><span class="routePickMeta">Account: ${esc(x.account_alias||'pending')} · Email: ${esc(x.email||'not reported by Google')} · ${esc(x.token_status||'unknown')} · ${esc(x.store||'sqlite')}</span></span></label>`).join('')||'<div class="routePickItem muted">No authenticated workspaces yet.</div>'; updateRoutePickCounts();}
function hydrateMapProfiles(){const profiles=uniq((data.profile_options||data.rules||[]).map(r=>typeof r==='string'?r:r.profile).filter(Boolean)); const old=selectedMapProfiles(); if(!$('mapProfilePicker'))return; $('mapProfilePicker').innerHTML=profiles.map(p=>`<label class="routePickItem"><input class="routeProfileCheck" type="checkbox" value="${esc(p)}" ${old.includes(p)?'checked':''} onchange="updateRoutePickCounts()"/><span><span class="routePickTitle">${esc(p)}</span><span class="routePickMeta">Hermes agent profile</span></span></label>`).join('')||'<div class="routePickItem muted">No Hermes profiles found in policy.</div>'; updateRoutePickCounts();}
function tokenMatches(x,ignore=''){const q=($('workspaceTokenQ')?.value||'').toLowerCase(); const account=x.account_display||x.account_alias||x.label; const aliases=Array.isArray(x.alias_keys)?x.alias_keys.join(' '):''; return (ignore==='account'||selectedHas('workspaceTokenAccount',account))&&(ignore==='email'||selectedHas('workspaceTokenEmail',x.email||'—'))&&(ignore==='store'||selectedHas('workspaceTokenStore',x.store||'sqlite'))&&(ignore==='status'||selectedHas('workspaceTokenStatus',x.token_status||'unknown'))&&(!q||[x.email,x.label,account,x.account_alias,aliases,x.id,x.store,x.token_status].join(' ').toLowerCase().includes(q));}
function routeMatches(x,ignore=''){const q=($('workspaceRouteQ')?.value||'').toLowerCase(); const account=x.account_display||x.token_label||x.account_alias||''; return (ignore==='profile'||selectedHas('workspaceRouteProfile',x.profile))&&(ignore==='account'||selectedHas('workspaceRouteAccount',account))&&(ignore==='email'||selectedHas('workspaceRouteEmail',x.email||'—'))&&(!q||[x.profile,account,x.account_alias,x.route,x.email].join(' ').toLowerCase().includes(q));}
function hydrateWorkspaceFilters(rows,routes){if($('workspaceTokenAccount')) opt($('workspaceTokenAccount'),['',...rows.filter(x=>tokenMatches(x,'account')).map(x=>x.account_display||x.account_alias||x.label)],true); if($('workspaceTokenEmail')) opt($('workspaceTokenEmail'),['',...rows.filter(x=>tokenMatches(x,'email')).map(x=>x.email||'—')],true); if($('workspaceTokenStore')) opt($('workspaceTokenStore'),['',...rows.filter(x=>tokenMatches(x,'store')).map(x=>x.store||'sqlite')],true); if($('workspaceTokenStatus')) opt($('workspaceTokenStatus'),['',...rows.filter(x=>tokenMatches(x,'status')).map(x=>x.token_status||'unknown')],true); if($('workspaceRouteProfile')) opt($('workspaceRouteProfile'),['',...routes.filter(x=>routeMatches(x,'profile')).map(x=>x.profile)],true); if($('workspaceRouteAccount')) opt($('workspaceRouteAccount'),['',...routes.filter(x=>routeMatches(x,'account')).map(x=>x.account_display||x.token_label||x.account_alias)],true); if($('workspaceRouteEmail')) opt($('workspaceRouteEmail'),['',...routes.filter(x=>routeMatches(x,'email')).map(x=>x.email||'—')],true);}
async function loadWorkspaceAccess(){try{const j=await api('/api/workspace/access/list',{}); const rows=j.items||[]; const routes=j.routes||data.workspace_routes||[]; hydrateWorkspaceFilters(rows,routes); const tokenRows=sortedRows(rows.filter(x=>tokenMatches(x)),'workspaceTokens'); const routeRows=sortedRows(routes.filter(x=>routeMatches(x)),'workspaceRoutes'); $('workspaceOverview').innerHTML=tokenRows.map(x=>{const scopes=Array.isArray(x.scopes)?x.scopes.join('\n'):String(x.scopes||''); const title=scopes?`Scopes:\n${scopes}`:'No scopes reported'; return `<tr><td>${esc(x.email||'—')}<span class="scopeInfo" title="${esc(title)}" aria-label="OAuth scopes">🔑</span></td><td>${esc(x.label||x.email||x.account_display||x.account_alias||x.id)}</td><td>${esc(x.account_display||x.account_alias||'—')}</td><td>${esc(x.store||'sqlite')}</td><td>${esc(x.token_status||'unknown')}</td><td>${esc(x.updated_at)}</td><td><div class="iconActions"><button class="iconBtn" title="Test workspace token" aria-label="Test workspace token" onclick='testAccess(${JSON.stringify(x.id)},this)'>✓</button><button class="iconBtn" title="Refresh existing token" aria-label="Refresh existing token" onclick='refreshToken(${JSON.stringify(x.id)},this)'>↻</button><button class="iconBtn scopeBtn" title="Update OAuth scopes for this workspace" aria-label="Update OAuth scopes for this workspace" onclick='reauthorizeAccess(${JSON.stringify(x.id)},this)'><svg class="mdiIcon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 1L3 5V11C3 16.55 6.84 21.74 12 23C17.16 21.74 21 16.55 21 11V5L12 1M12 3.18L19 6.3V11C19 15.5 16.18 19.68 12 20.93C7.82 19.68 5 15.5 5 11V6.3L12 3.18M11 7V12.59L8.7 10.29L7.29 11.7L12 16.41L16.71 11.7L15.3 10.29L13 12.59V7H11Z"/></svg></button><button class="iconBtn danger" title="Disconnect workspace" aria-label="Disconnect workspace" onclick='revokeAccess(${JSON.stringify(x.id)})'>⛓</button></div></td></tr>`}).join('')||'<tr><td colspan=7 class=muted>No authenticated workspaces match the filters.</td></tr>'; renderRouteTokenPicker(rows); hydrateMapProfiles(); $('workspaceRoutes').innerHTML=routeRows.map(r=>`<tr><td>${esc(r.profile)}</td><td>${esc(r.account_display||r.token_label||r.account_alias)}</td><td><span class="code">${esc(r.route)}</span></td><td>${esc(r.email||'—')}</td><td><div class="iconActions"><button class="iconBtn danger" title="Revoke profile relationship" aria-label="Revoke profile relationship" onclick='unmapWorkspaceRoute(${JSON.stringify(r.token_id)},${JSON.stringify(r.profile)},${JSON.stringify(r.account_alias)},this)'>⛓</button></div></td></tr>`).join('') || '<tr><td colspan="5">No profile-token relationships match the filters.</td></tr>'; $('mapProfilesBtn').disabled=!rows.length; $('workspaceMsg').className='msg'; $('workspaceMsg').textContent=rows.length?`${rows.length} connected Google account token(s), ${routes.length} profile route relationship(s).`:'No Google accounts connected yet.';}catch(e){$('workspaceMsg').className='msg error';$('workspaceMsg').textContent=e.message}}
async function startOAuth(){const btn=$('startOAuth'); try{btn.disabled=true;btn.textContent='Generating…'; if(!clientSecretJson.trim()) throw new Error('Upload client_secret.json first.'); const j=await api('/api/workspace/oauth/start',{client_secret_json:clientSecretJson,token_label:$('oauthTokenLabel').value}); $('oauthUrl').href=j.authorization_url;$('oauthUrl').textContent='Open Google authorization →';$('oauthUrlBox').classList.remove('hidden');$('oauthState').value=j.state||''; $('workspaceMsg').className='msg ok';$('workspaceMsg').textContent='Authorization URL generated. Open it, approve access, then paste the redirect URL or code. No profile ACLs were created.'; btn.textContent='Generated ✓'; setTimeout(()=>{btn.disabled=false;btn.textContent='Generate authorization URL'},1200)}catch(e){btn.disabled=false;btn.textContent='Retry';$('workspaceMsg').className='msg error';$('workspaceMsg').textContent=e.message}}
async function finishOAuth(){const btn=$('finishOAuth'); try{btn.disabled=true;btn.textContent='Exchanging…'; const val=$('redirectOrCode').value; const j=await api('/api/workspace/oauth/exchange',{redirect_url:val.includes('://')?val:'',code:val.includes('://')?'':val,state:$('oauthState').value}); clientSecretJson=''; if($('clientSecretFile')) $('clientSecretFile').value=''; $('redirectOrCode').value=''; btn.textContent='Connected ✓'; $('workspaceMsg').className='msg ok';$('workspaceMsg').textContent=j.message||`Connected ${j.account_alias}. No ACL rows were created yet; map profiles to this token in the next tab when ready.`; await loadWorkspaceAccess(); await load(); setTimeout(()=>{btn.disabled=false;btn.textContent='Exchange code and save token'},1200)}catch(e){btn.disabled=false;btn.textContent='Retry exchange';$('workspaceMsg').className='msg error';$('workspaceMsg').textContent=e.message}}
async function finishReauth(){const btn=$('finishReauth'); try{btn.disabled=true;btn.textContent='Updating…'; const val=$('reauthRedirectOrCode').value; const j=await api('/api/workspace/oauth/exchange',{redirect_url:val.includes('://')?val:'',code:val.includes('://')?'':val,state:$('reauthState').value}); $('reauthRedirectOrCode').value=''; btn.textContent='Updated ✓'; $('workspaceMsg').className='msg ok';$('workspaceMsg').textContent=j.message||'Workspace scopes updated in place.'; await loadWorkspaceAccess(); await load(); workspaceActive='overview'; render(); setTimeout(()=>{btn.disabled=false;btn.textContent='Update existing workspace scopes'},1200)}catch(e){btn.disabled=false;btn.textContent='Retry scope update';$('workspaceMsg').className='msg error';$('workspaceMsg').textContent=e.message}}
async function mapProfilesToToken(){const btn=$('mapProfilesBtn'); try{btn.disabled=true;btn.textContent='Mapping…'; const token_ids=selectedMapTokens(); const profiles=selectedMapProfiles(); if(!token_ids.length) throw new Error('Select at least one workspace token.'); if(!profiles.length) throw new Error('Select at least one Hermes profile.'); const j=await api('/api/workspace/access/map-profiles',{token_ids,profiles}); btn.textContent='Mapped ✓'; $('workspaceMsg').className='msg ok'; $('workspaceMsg').textContent=`Mapped ${token_ids.length} token(s) to ${(j.profiles||profiles).join(', ')} with routes ${Object.values(j.routes||{}).join(', ')}. Review the ACL rows before broad use.`; await load(); await loadWorkspaceAccess(); setTimeout(()=>{btn.disabled=false;btn.textContent='Create / update selected routes'},1200)}catch(e){btn.disabled=false;btn.textContent='Retry mapping';$('workspaceMsg').className='msg error';$('workspaceMsg').textContent=e.message}}
async function unmapWorkspaceRoute(token_id,profile,account_alias,btn){if(!confirm(`Revoke ${profile} relationship for this Google account?`))return; try{if(btn){btn.disabled=true;btn.textContent='Revoking…'} await api('/api/workspace/access/unmap-profiles',{token_id,account_alias,profiles:[profile]}); $('workspaceMsg').className='msg ok';$('workspaceMsg').textContent=`Revoked ${profile} profile-token relationship.`; await load(); await loadWorkspaceAccess();}catch(e){$('workspaceMsg').className='msg error';$('workspaceMsg').textContent=e.message}finally{if(btn){btn.disabled=false;btn.textContent='⛓'}}}

function apiTokenLabel(t){return t.label||''} function apiTokenProfiles(t){return (t.allowed_profiles||[]).join(', ')} function apiTokenStatus(t){return t.active?'active':'revoked'} function apiTokenMatches(t,ignore=''){return (ignore==='label'||selectedHas('apiTokenLabelFilter',apiTokenLabel(t)))&&(ignore==='profiles'||selectedHas('apiTokenProfileFilter',apiTokenProfiles(t)||'—'))&&(ignore==='status'||selectedHas('apiTokenStatusFilter',apiTokenStatus(t)));} function hydrateApiTokenFilters(toks){if($('apiTokenLabelFilter')){$('apiTokenLabelFilter').dataset.placeholder='All labels'; opt($('apiTokenLabelFilter'),['',...toks.filter(t=>apiTokenMatches(t,'label')).map(apiTokenLabel)],true)} if($('apiTokenProfileFilter')){$('apiTokenProfileFilter').dataset.placeholder='All profiles'; opt($('apiTokenProfileFilter'),['',...toks.filter(t=>apiTokenMatches(t,'profiles')).map(t=>apiTokenProfiles(t)||'—')],true)} if($('apiTokenStatusFilter')){$('apiTokenStatusFilter').dataset.placeholder='All statuses'; opt($('apiTokenStatusFilter'),['',...toks.filter(t=>apiTokenMatches(t,'status')).map(apiTokenStatus)],true); if(!apiTokenStatusDefaulted){const el=$('apiTokenStatusFilter'); [...el.options].forEach(o=>o.selected=(o.value==='active')); apiTokenStatusDefaulted=true; rememberMultiSelectState(el);}}} function sortedApiTokens(rows){const st=sortState.apiTokens||{key:'created_at',dir:-1}; const val=t=>st.key==='profiles'?apiTokenProfiles(t):st.key==='status'?apiTokenStatus(t):String(t[st.key]??''); return [...rows].sort((a,b)=>val(a).localeCompare(val(b))*st.dir)}
function renderRuntimePaths(j){if(!j||!$('runtimePaths'))return; const paths=j.paths||{}, stale=j.stale_root_config_files||[], backups=j.backups||{}; const rows=Object.entries(paths).map(([k,v])=>`<tr><td>${esc(k.replaceAll('_',' '))}</td><td><span class="code">${esc(v)}</span></td></tr>`).join(''); const staleRows=stale.length?stale.map(x=>`<tr><td><span class="code">${esc(x.path)}</span></td><td>${esc(x.reason||x.error||'stale')}</td><td>${esc(x.size||'')}</td><td>${esc(x.mtime||'')}</td></tr>`).join(''):'<tr><td colspan="4" class="muted">No root-level stale config files reported.</td></tr>'; $('runtimePaths').innerHTML=`<h4>Authoritative runtime paths</h4><table><thead><tr><th>Item</th><th>Path</th></tr></thead><tbody>${rows}</tbody></table><h4>Backup inventory</h4><div class="runtimeBox">Root: <span class="code">${esc(paths.backup_root||'')}</span><br/>Latest archive: <span class="code">${esc((backups.latest&&backups.latest.archive_path)||'none')}</span><br/>Count: ${esc(backups.count||0)}</div><h4>Stale root-level config files</h4><table><thead><tr><th>Path</th><th>Reason</th><th>Bytes</th><th>Modified</th></tr></thead><tbody>${staleRows}</tbody></table>`;}
function renderRuntimeStatus(j){if(!j)return; window.__lastRuntimeStatus=j; renderRuntimePaths(j); const v=j.version||{}, h=j.gateway_health||{}, js=j.jwt_secret||{}, toks=j.api_tokens||[]; window.__lastApiTokens=toks; if($('runtimeHealth'))$('runtimeHealth').textContent=`${h.status||'unknown'} @ ${data.control.gateway||''}`; if($('runtimeVersion'))$('runtimeVersion').innerHTML=`<div><b>Git</b>: ${esc(v.git_commit||'unknown')} ${v.git_dirty?'· dirty':''}</div><div><b>Source</b>: <span class="code">${esc(v.source_path||'')}</span></div><div><b>Installed</b>: <span class="code">${esc(v.installed_path||'')}</span></div><div><b>Source sync</b>: ${v.source_matches_installed?'matches installed':'needs install/restart'} <span class="code">${esc((v.source_sha256||'').slice(0,12))}/${esc((v.installed_sha256||'').slice(0,12))}</span></div>`; if($('jwtSecretStatus'))$('jwtSecretStatus').innerHTML=`<div><b>Storage</b>: ${esc(js.storage||'unknown')}</div><div><b>SQLite DB</b>: <span class="code">${esc(js.db_path||'')}</span></div><div><b>Encryption key</b>: <span class="code">${esc(js.key_path||'')}</span></div><div><b>Rotated</b>: ${esc(js.rotated_at||'never')} by ${esc(js.rotated_by||'')}</div><div><b>Plaintext JWT file use</b>: disabled</div><div><b>Secrets revealed by UI/API</b>: no</div>`; if($('apiTokenStatus'))$('apiTokenStatus').innerHTML=`<div><b>Client env var</b>: <span class="code">GOOGLE_GOVERNANCE_ACCESS_TOKEN</span></div><div><b>Active API tokens</b>: ${toks.filter(t=>t.active).length}</div>`; if($('apiTokenInventory')){hydrateApiTokenFilters(toks); const shown=sortedApiTokens(toks.filter(t=>apiTokenMatches(t))); $('apiTokenInventory').innerHTML=toks.length?`<table><thead><tr><th data-sort="label">Label</th><th data-sort="id">ID</th><th data-sort="profiles">Profiles</th><th data-sort="created_at">Created</th><th data-sort="last_used_at">Last used</th><th data-sort="status">Status</th><th data-sort="status">Action</th></tr></thead><tbody>${shown.map(t=>`<tr><td>${esc(t.label||'')}</td><td><span class="code">${esc(t.id||'')}</span></td><td>${esc(apiTokenProfiles(t))}</td><td>${esc(t.created_at||'')}</td><td>${esc(t.last_used_at||'never')}</td><td>${t.active?'<span class="pill ok">active</span>':'revoked'}</td><td>${t.active?`<button onclick="revokeApiToken('${esc(t.id||'')}')">Delete</button>`:''}</td></tr>`).join('')||'<tr><td colspan="7" class="muted">No API tokens match the filters.</td></tr>'}</tbody></table>`:'No API tokens yet.';} if($('runtimeBackups')){$('runtimeBackups').innerHTML=(j.backups||[]).map(b=>`<div><b>${esc(b.id)}</b> · ${esc(b.ts)} · ${esc(b.archive_exists?'archive ok':'missing')} · ${esc(Math.round((b.archive_size||0)/1024))} KB<br/><span class="code">${esc(b.archive_path)}</span> ${b.archive_exists?`<a class="downloadLink" href="/api/runtime/backup/download?id=${encodeURIComponent(b.id)}">Download</a>`:''}</div>`).join('')||'No backups recorded yet.';} const bs=j.backup_schedule||{}; if($('runtimeBackupIo')&&!$('runtimeBackupIo').textContent.includes('validated'))$('runtimeBackupIo').innerHTML=bs.enabled?`Scheduled backup active:<br/><span class="code">${esc(bs.content||bs.cron_path)}</span>`:'No backup cron scheduled.'; if($('runtimeUpgradeStatus')){$('runtimeUpgradeStatus').innerHTML=`<ol><li><b>Create/download a backup</b> from Runtime → Backups.</li><li><b>Install source</b>: copy this source file to <span class="code">${esc(v.installed_path||'./.google-governance/runtime/google_governance_control_plane.py')}</span>.</li><li><b>Restart control UI</b>: <span class="code">systemctl restart ${esc(data.control.control_service||'google-workspace-governance-control.service')}</span>.</li><li><b>Validate</b>: return here and run Runtime → Config validation.</li></ol><div><b>Current status</b>: ${v.source_matches_installed?'installed source matches this source':'upgrade pending: source differs from installed /opt copy'}</div>`;}}
function renderYamlSyncStatus(y){if(!y)return; const last=y.last_event||{}; const cmp=y.compare||{}; if($('yamlLastSync'))$('yamlLastSync').textContent=last.ts?`${last.ts} · ${last.event||''} · ${last.payload&&last.payload.status?last.payload.status:(last.status||'')}`:'No YAML write event recorded yet'; if($('yamlParity'))$('yamlParity').textContent=(cmp.generated_matches_yaml&&cmp.runtime_matches_yaml)?'clean':'needs attention'; if($('yamlPolicyPath'))$('yamlPolicyPath').textContent=(y.paths&&y.paths.policy_yaml)||''; if($('yamlRegistryPath'))$('yamlRegistryPath').textContent=(y.paths&&y.paths.registry_yaml)||'';}
async function loadRuntimeStatus(){try{const j=await get('/api/runtime/status'); renderRuntimeStatus(j); renderYamlSyncStatus(j.yaml_sync); return j;}catch(e){if($('runtimeMsg')){$('runtimeMsg').className='msg error';$('runtimeMsg').textContent=e.message}}}
function renderValidation(j){renderYamlSyncStatus(j.yaml_sync||(j.validation&&j.validation.yaml_sync)); const checks=j.checks||(j.validation&&j.validation.checks)||[]; const yaml=(j.yaml_sync||(j.validation&&j.validation.yaml_sync)||{}); const note=yaml.authority_note?`<div class="msg ok validationIntro"><b>Authority</b>: ${esc(yaml.authority_note)}</div>`:''; const rows=checks.map(c=>`<div class="validationCheck ${c.ok?'ok':'warn'}"><div class="validationIcon" aria-hidden="true">${c.ok?'✓':'!'}</div><div><div class="validationName">${esc(c.name)}</div><div class="validationDetail">${esc(c.detail||'')}</div></div></div>`).join(''); $('runtimeValidation').innerHTML=note+(rows?`<div class="validationChecks">${rows}</div>`:'<div class="validationCheck warn"><div class="validationIcon">!</div><div><div class="validationName">No validation checks returned</div><div class="validationDetail">The runtime validation API returned no checks.</div></div></div>');}
async function migrateJwtSecret(){try{const j=await api('/api/runtime/jwt-secret/migrate',{}); $('runtimeMsg').className='msg ok';$('runtimeMsg').textContent=`JWT secret custody: ${j.storage}. Secret was not revealed.`; await loadRuntimeStatus();}catch(e){$('runtimeMsg').className='msg error';$('runtimeMsg').textContent=e.message}}
async function rotateJwtSecret(){if(!confirm('Rotate the JWT signing secret now? Existing short-lived JWTs will stop working after deployment/restart.'))return; try{const j=await api('/api/runtime/jwt-secret/rotate',{}); $('runtimeMsg').className='msg ok';$('runtimeMsg').textContent='JWT signing secret rotated in plaintext file custody. Secret was not revealed.'; await loadRuntimeStatus();}catch(e){$('runtimeMsg').className='msg error';$('runtimeMsg').textContent=e.message}}
async function generateApiToken(){try{const btn=$('generateApiToken'); if(btn){btn.disabled=true;btn.textContent='Generating…'} const j=await api('/api/runtime/api-token/generate',{label:($('apiTokenLabel')&&$('apiTokenLabel').value)||'Shared gateway API token',allowed_profiles:['*']}); const out=$('apiTokenOutput'); if(out){out.value=`export GOOGLE_GOVERNANCE_ACCESS_TOKEN=${j.access_token}`; out.classList.remove('hidden'); out.focus(); out.select();} ($('tokenMsg')||$('runtimeMsg')).className='msg ok';($('tokenMsg')||$('runtimeMsg')).textContent='API token generated. Copy it now; it is shown only once. Use env var GOOGLE_GOVERNANCE_ACCESS_TOKEN.'; if(btn){btn.disabled=false;btn.textContent='Generate API token'} await loadRuntimeStatus();}catch(e){if($('generateApiToken')){$('generateApiToken').disabled=false;$('generateApiToken').textContent='Retry generate'} ($('tokenMsg')||$('runtimeMsg')).className='msg error';($('tokenMsg')||$('runtimeMsg')).textContent=e.message}}

async function revokeApiToken(id){if(!id||!confirm('Delete/revoke this API token? Clients using it will stop working immediately.'))return; try{await api('/api/runtime/api-token/revoke',{id}); ($('tokenMsg')||$('runtimeMsg')).className='msg ok';($('tokenMsg')||$('runtimeMsg')).textContent='API token deleted/revoked.'; await loadRuntimeStatus();}catch(e){($('tokenMsg')||$('runtimeMsg')).className='msg error';($('tokenMsg')||$('runtimeMsg')).textContent=e.message}}
async function validateRuntime(){try{const j=await api('/api/runtime/validate',{}); renderValidation(j); $('runtimeMsg').className=j.status==='ok'?'msg ok':'msg error';$('runtimeMsg').textContent=j.status==='ok'?'Config validation passed. UI/YAML/runtime parity is shown below.':'Config needs attention; see YAML/runtime parity below.'; await loadRuntimeStatus();}catch(e){$('runtimeMsg').className='msg error';$('runtimeMsg').textContent=e.message}}
async function compareYamlUi(){const btn=$('compareYamlUi'); try{if(btn){btn.disabled=true;btn.textContent='Comparing…'} const j=await api('/api/runtime/yaml/compare',{}); renderValidation(j); renderYamlSyncStatus(j.yaml_sync); $('runtimeMsg').className=j.status==='ok'?'msg ok':'msg error'; $('runtimeMsg').textContent=j.status==='ok'?'UI ↔ YAML comparison is clean.':'UI ↔ YAML comparison needs attention.'; if(btn){btn.textContent='Compared ✓'; setTimeout(()=>{btn.disabled=false;btn.textContent='Compare UI ↔ YAML'},1400)}}catch(e){if(btn){btn.disabled=false;btn.textContent='Retry compare'} $('runtimeMsg').className='msg error';$('runtimeMsg').textContent=e.message}}
async function syncYamlFromUi(){if(!confirm('Regenerate policy and registry YAML from the current UI-visible routes and rules? Direct YAML edits may be overwritten. Backups will be created first.'))return; const btn=$('syncYamlFromUi'); try{if(btn){btn.disabled=true;btn.textContent='Regenerating…'} const j=await api('/api/runtime/sync-yaml-from-ui',{}); renderValidation(j.validation||{}); renderYamlSyncStatus(j.yaml_sync); $('runtimeMsg').className=j.status==='ok'?'msg ok':'msg error'; $('runtimeMsg').textContent=j.status==='ok'?'YAML regenerated from UI and comparison is clean.':'YAML regeneration ran, but validation still needs attention.'; await load(); await loadRuntimeStatus(); await loadAccessLog(); if(btn){btn.textContent='Regenerated ✓'; setTimeout(()=>{btn.disabled=false;btn.textContent='Regenerate YAML from UI'},1400)}}catch(e){if(btn){btn.disabled=false;btn.textContent='Retry regenerate'} $('runtimeMsg').className='msg error';$('runtimeMsg').textContent=e.message}}
async function createBackup(){try{const j=await api('/api/runtime/backup/create',{include_token_store:$('backupTokens')&&$('backupTokens').checked}); $('runtimeMsg').className='msg ok';$('runtimeMsg').textContent=`Backup created: ${j.archive}`; if($('runtimeBackupIo'))$('runtimeBackupIo').textContent=`Created ${j.archive}`; await loadRuntimeStatus(); await loadAccessLog();}catch(e){$('runtimeMsg').className='msg error';$('runtimeMsg').textContent=e.message}}
async function exportBackup(){try{const j=await api('/api/runtime/backup/export',{}); const a=$('downloadBackup'); if(a){a.href=j.download_url||('/api/runtime/backup/download?id='+encodeURIComponent(j.id||'')); a.classList.remove('hidden');} $('runtimeBackupIo').innerHTML=`Download ready: <span class="code">${esc(j.archive_path)}</span> · ${esc(Math.round((j.archive_size||0)/1024))} KB`; $('runtimeMsg').className='msg ok';$('runtimeMsg').textContent='Backup download ready.'; await loadAccessLog();}catch(e){$('runtimeMsg').className='msg error';$('runtimeMsg').textContent=e.message}}
function fileToB64(file){return new Promise((resolve,reject)=>{if(!file)return resolve(''); const r=new FileReader(); r.onload=()=>resolve(String(r.result||'').split(',',2).pop()||''); r.onerror=()=>reject(new Error('Could not read backup file.')); r.readAsDataURL(file);});}
async function importBackup(){try{const file=$('importBackupFile')&&$('importBackupFile').files&&$('importBackupFile').files[0]; const path=$('importBackupPath').value; const archive_data_b64=await fileToB64(file); const j=await api('/api/runtime/backup/import',{archive_path:path,archive_data_b64,filename:file&&file.name}); $('runtimeBackupIo').innerHTML=`Import validation ready: <span class="code">${esc(j.archive_path)}</span><br/>${esc(j.restore_scope)}<br/>${esc(j.next_step)}`; $('runtimeMsg').className='msg ok';$('runtimeMsg').textContent='Backup import validated. No live restore was performed.'; await loadAccessLog();}catch(e){$('runtimeMsg').className='msg error';$('runtimeMsg').textContent=e.message}}
async function scheduleBackup(enabled=true){try{const cron=$('backupCron').value||($('backupCronPreset')&&$('backupCronPreset').value)||'0 2 * * *'; const j=await api('/api/runtime/backup/schedule',{enabled,cron,include_token_store:$('backupTokens')&&$('backupTokens').checked}); $('runtimeBackupIo').innerHTML=j.status==='needs_root'?`Root required. Write this cron file:<br/><span class="code">${esc(j.cron_path)}</span><pre>${esc(j.content||'')}</pre>`:`Backup cron ${esc(j.status)}: <span class="code">${esc(j.cron||'disabled')}</span>`; $('runtimeMsg').className=j.status==='needs_root'?'msg error':'msg ok';$('runtimeMsg').textContent=j.status==='needs_root'?'Backup cron needs root install.':'Backup cron updated.'; await loadRuntimeStatus(); await loadAccessLog();}catch(e){$('runtimeMsg').className='msg error';$('runtimeMsg').textContent=e.message}}
async function restartRuntime(){if(!confirm('Restart or reload the gateway service now?'))return; try{const j=await api('/api/runtime/restart',{}); $('runtimeMsg').className='msg ok';$('runtimeMsg').textContent=(j.restart&&j.restart.shell_access_required===false)?'Runtime reload requested; gateway hot-reload mode is active. Captured in Access logs as control-ui.':'Gateway restart completed and captured in Access logs as control-ui.'; await loadRuntimeStatus(); await loadAccessLog();}catch(e){$('runtimeMsg').className='msg error';$('runtimeMsg').textContent=e.message}}
async function applyRuntime(){try{const j=await api('/api/runtime/apply',{}); $('runtimeMsg').className='msg ok';$('runtimeMsg').textContent=(j.restart&&j.restart.shell_access_required===false)?'Runtime policy written; gateway reloads it automatically.':'Runtime apply completed.'; await load(); await loadRuntimeStatus();}catch(e){$('runtimeMsg').className='msg error';$('runtimeMsg').textContent=e.message}}
async function testAccess(token_id,btn){try{btn.disabled=true;btn.classList.remove('confirmed');btn.textContent='…'; const j=await api('/api/workspace/access/test',{token_id}); btn.classList.add('confirmed');btn.textContent='✓'; $('workspaceMsg').className='msg ok';$('workspaceMsg').textContent=j.message||'Token test succeeded.'; setTimeout(()=>{btn.disabled=false;btn.classList.remove('confirmed');btn.textContent='✓'},1800)}catch(e){btn.disabled=false;btn.classList.remove('confirmed');btn.textContent='✓';$('workspaceMsg').className='msg error';$('workspaceMsg').textContent=e.message}}
async function refreshToken(token_id,btn){try{btn.disabled=true;btn.textContent='Refreshing…'; await api('/api/workspace/access/refresh',{token_id}); btn.textContent='Refreshed ✓'; await loadWorkspaceAccess(); setTimeout(()=>{btn.disabled=false;btn.textContent='↻'},1200)}catch(e){btn.disabled=false;btn.textContent='↻';$('workspaceMsg').className='msg error';$('workspaceMsg').textContent=e.message}}
async function reauthorizeAccess(token_id,btn){try{if(btn){btn.disabled=true;btn.textContent='Generating…'} const j=await api('/api/workspace/oauth/reauthorize',{token_id}); workspaceActive='reauth'; render(); if($('reauthWorkspaceSummary'))$('reauthWorkspaceSummary').textContent=`Updating scopes for ${j.account_alias||token_id}. Existing token identity and routes are retained.`; $('reauthUrl').href=j.authorization_url;$('reauthUrl').textContent='Open Google reauthorization →';$('reauthUrlBox').classList.remove('hidden');$('reauthState').value=j.state||''; if($('reauthRedirectOrCode'))$('reauthRedirectOrCode').value=''; $('workspaceMsg').className='msg ok';$('workspaceMsg').textContent='Open the reauthorization URL, approve expanded scopes, then paste the final redirect URL/code in the scope-update panel.'; if(btn){btn.textContent='Generated ✓'; setTimeout(()=>{btn.disabled=false;btn.innerHTML='<svg class="mdiIcon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 1L3 5V11C3 16.55 6.84 21.74 12 23C17.16 21.74 21 16.55 21 11V5L12 1M12 3.18L19 6.3V11C19 15.5 16.18 19.68 12 20.93C7.82 19.68 5 15.5 5 11V6.3L12 3.18M11 7V12.59L8.7 10.29L7.29 11.7L12 16.41L16.71 11.7L15.3 10.29L13 12.59V7H11Z"/></svg>'},1200)}}catch(e){if(btn){btn.disabled=false;btn.innerHTML='<svg class="mdiIcon" viewBox="0 0 24 24" aria-hidden="true"><path d="M12 1L3 5V11C3 16.55 6.84 21.74 12 23C17.16 21.74 21 16.55 21 11V5L12 1M12 3.18L19 6.3V11C19 15.5 16.18 19.68 12 20.93C7.82 19.68 5 15.5 5 11V6.3L12 3.18M11 7V12.59L8.7 10.29L7.29 11.7L12 16.41L16.71 11.7L15.3 10.29L13 12.59V7H11Z"/></svg>'} $('workspaceMsg').className='msg error';$('workspaceMsg').textContent=e.message}}
async function revokeAccess(token_id){if(!confirm('Disconnect this managed Google account token?'))return; try{await api('/api/workspace/access/revoke',{token_id}); $('workspaceMsg').className='msg ok';$('workspaceMsg').textContent='Google account disconnected.'; await loadWorkspaceAccess(); await load();}catch(e){$('workspaceMsg').className='msg error';$('workspaceMsg').textContent=e.message}}
$('startOAuth').onclick=startOAuth; $('finishOAuth').onclick=finishOAuth; if($('finishReauth'))$('finishReauth').onclick=finishReauth; $('mapProfilesBtn').onclick=mapProfilesToToken; $('applyRuntime').onclick=applyRuntime; $('restartRuntime').onclick=restartRuntime; $('validateRuntime').onclick=validateRuntime; if($('compareYamlUi'))$('compareYamlUi').onclick=compareYamlUi; if($('syncYamlFromUi'))$('syncYamlFromUi').onclick=syncYamlFromUi; $('createBackup').onclick=createBackup; $('exportBackup').onclick=exportBackup; $('importBackup').onclick=importBackup; $('scheduleBackup').onclick=()=>scheduleBackup(true); $('disableBackupSchedule').onclick=()=>scheduleBackup(false); $('backupCronPreset').onchange=()=>{$('backupCron').value=$('backupCronPreset').value}; $('refreshRuntime').onclick=loadRuntimeStatus; if($('refreshRuntimeUpgrade'))$('refreshRuntimeUpgrade').onclick=loadRuntimeStatus; if($('migrateJwtSecret'))$('migrateJwtSecret').onclick=migrateJwtSecret; if($('rotateJwtSecret'))$('rotateJwtSecret').onclick=rotateJwtSecret; if($('generateApiToken'))$('generateApiToken').onclick=generateApiToken; ['apiTokenLabelFilter','apiTokenProfileFilter','apiTokenStatusFilter'].forEach(id=>bindFilter(id,()=>renderRuntimeStatus(window.__lastRuntimeStatus||{version:{},gateway_health:{},jwt_secret:{},api_tokens:(window.__lastApiTokens||[])}))); if($('saveOidc'))$('saveOidc').onclick=saveOidcConfig; if($('refreshMcpTools'))$('refreshMcpTools').onclick=loadMcpTools; if($('mcpRunTest'))$('mcpRunTest').onclick=runMcpTest; if($('mcpTestProfile'))$('mcpTestProfile').onchange=refreshMcpRouteOptions; if($('mcpTestRoute'))$('mcpTestRoute').onchange=refreshMcpToolOptions; if($('mcpTestTool'))$('mcpTestTool').onchange=()=>pickMcpTool($('mcpTestTool').value,false); if($('mcpQ'))$('mcpQ').oninput=renderMcpTools; ['mcpService','mcpRisk'].forEach(id=>bindFilter(id,renderMcpTools)); if($('clientSecretFile')) $('clientSecretFile').onchange=async e=>{const f=e.target.files&&e.target.files[0]; clientSecretJson=f?await f.text():''; $('workspaceMsg').className='msg ok'; $('workspaceMsg').textContent=f?`Loaded ${f.name}. Generate the authorization URL next.`:''};

async function loadUsers(){try{const j=await api('/api/users/list',{}); users=j.users||[]; const rows=sortedRows(users,'users'); $('users').innerHTML=rows.map(u=>{const username=String(u.username||''); const display=esc(u.display_name||[u.first_name,u.last_name].filter(Boolean).join(' ')||username); const status=u.enabled?'enabled':'disabled'; return `<article class="userCard adminUserCard"><div class="userCardHeader"><div><div class="userCardName">${display}</div><div class="muted code">${esc(username)}</div></div><div class="userBadgeStack"><span class="pill">${esc(u.role||'viewer')}</span><span class="pill ${u.enabled?'ok':'danger'}">${status}</span></div></div><div class="adminUserMeta"><span>Role: <b>${esc(u.role||'viewer')}</b></span><span>Status: <b>${status}</b></span><span>2FA: <b>${u.twofa_enabled?'enabled':'not enabled'}</b></span><span>Passkeys: <b>${Number(u.passkey_count||0)}</b></span><span>YubiKey 2FA: <b>${Number(u.yubikey_2fa_count||0)}</b></span></div><div class="userAdminActions"><button class="danger" onclick="deleteUser('${esc(username)}',this)" ${me&&me.username===username?'disabled title="Cannot delete current user"':''}>Delete user</button></div></article>`}).join(''); if(!rows.length){$('users').innerHTML='<div class="runtimeBox muted">No users found.</div>';}}catch(e){$('userMsg').className='msg error';$('userMsg').textContent=e.message}}
async function deleteUser(username,btn){if(!confirm(`Delete user ${username}?`))return; try{if(btn){btn.disabled=true;btn.textContent='Deleting…'} await api('/api/users/delete',{username}); $('userMsg').className='msg ok';$('userMsg').textContent=`Deleted ${username}.`; await loadUsers();}catch(e){if(btn){btn.disabled=false;btn.textContent='Delete user'} $('userMsg').className='msg error';$('userMsg').textContent=e.message}}
async function saveUser(username,btn){if(btn){btn.disabled=true;btn.classList.add('saving');btn.textContent='Saving…'} try{const payload={username,first_name:$('first-'+username).value,last_name:$('last-'+username).value,email:$('email-'+username).value,role:$('role-'+username).value,enabled:$('enabled-'+username).value==='true'}; const newPassword=($('pass-'+username).value||''); if(newPassword.trim())payload.password=newPassword; const j=await api('/api/users/save',payload); if(btn){btn.classList.remove('saving');btn.classList.add('saved');btn.textContent='Saved ✓'} $('userMsg').className='msg ok';$('userMsg').textContent=`Saved ${j.user.display_name||username}.`; if(me&&me.username===username){me=j.user;updateUserChrome()} await loadUsers();}catch(e){if(btn){btn.disabled=false;btn.classList.remove('saving');btn.classList.add('errorBtn');btn.textContent='Retry'} $('userMsg').className='msg error';$('userMsg').textContent=e.message}}
$('addUser').onclick=async()=>{const btn=$('addUser'); try{btn.disabled=true;btn.classList.add('saving');btn.textContent='Creating…'; const j=await api('/api/users/save',{first_name:$('newFirst').value,last_name:$('newLast').value,username:$('newUser').value,email:$('newEmail').value,role:$('newRole').value,enabled:$('newEnabled').value==='true',password:$('newUserPass').value}); ['newFirst','newLast','newUser','newEmail','newUserPass'].forEach(id=>$(id).value=''); btn.classList.remove('saving');btn.classList.add('saved');btn.textContent='Created ✓'; $('userMsg').className='msg ok';$('userMsg').textContent=`Created ${j.user.display_name||j.user.username}.`; await loadUsers(); setTimeout(()=>{btn.disabled=false;btn.classList.remove('saved');btn.textContent='Create user'},1200)}catch(e){btn.disabled=false;btn.classList.remove('saving');btn.classList.add('errorBtn');btn.textContent='Retry create'; $('userMsg').className='msg error';$('userMsg').textContent=e.message}};
$('saveProfile').onclick=async()=>{try{const j=await api('/api/users/profile',{first_name:$('profileFirst').value,last_name:$('profileLast').value,email:$('profileEmail').value,avatar_url:($('profilePhotoPreview').dataset.src||me.avatar_url||'')}); me=j.user; updateUserChrome(); $('profileMsg').className='msg ok';$('profileMsg').textContent='Profile saved.';}catch(e){$('profileMsg').className='msg error';$('profileMsg').textContent=e.message}}; function resizeProfilePhoto(file){return new Promise((resolve,reject)=>{const img=new Image(); const url=URL.createObjectURL(file); img.onload=()=>{try{const max=96, scale=Math.min(1,max/Math.max(img.width,img.height)); const w=Math.max(1,Math.round(img.width*scale)), h=Math.max(1,Math.round(img.height*scale)); const c=document.createElement('canvas'); c.width=w; c.height=h; c.getContext('2d').drawImage(img,0,0,w,h); URL.revokeObjectURL(url); resolve(c.toDataURL('image/jpeg',0.82));}catch(err){URL.revokeObjectURL(url); reject(err)}}; img.onerror=()=>{URL.revokeObjectURL(url); reject(new Error('Could not read profile photo.'))}; img.src=url;});} if($('profilePhoto'))$('profilePhoto').onchange=async e=>{const f=e.target.files&&e.target.files[0]; if(!f)return; try{const data=await resizeProfilePhoto(f); $('profilePhotoPreview').src=data; $('profilePhotoPreview').dataset.src=data; $('profilePhotoPreview').classList.remove('hidden'); $('profileMsg').className='msg ok'; $('profileMsg').textContent='Photo resized for profile use. Click Save profile.';}catch(err){$('profileMsg').className='msg error';$('profileMsg').textContent=err.message||'Could not read profile photo.';}}; $('changePass').onclick=async()=>{try{await api('/api/users/change-password',{current_password:$('currentPass').value,new_password:$('newPassSelf').value,confirm_password:$('confirmPassSelf').value}); ['currentPass','newPassSelf','confirmPassSelf'].forEach(id=>$(id).value=''); $('profileMsg').className='msg ok';$('profileMsg').textContent='Password changed.';}catch(e){$('profileMsg').className='msg error';$('profileMsg').textContent=e.message}};

async function startTotpSetup(){const j=await api('/api/users/2fa/totp/start',{}); pendingTotpChallenge=j.challenge; $('totpSetup').classList.remove('hidden'); $('totpSecret').textContent=j.secret; updateTwofaUi(); $('profileMsg').className='msg ok'; $('profileMsg').textContent='Add the setup key to your authenticator app, then enter the code.';} async function verifyTotpSetup(){const j=await api('/api/users/2fa/totp/verify',{challenge:pendingTotpChallenge,code:$('totpCode').value}); me=j.user; pendingTotpChallenge=''; $('totpCode').value=''; $('totpSetup').classList.add('hidden'); updateUserChrome(); $('profileMsg').className='msg ok'; $('profileMsg').textContent='Authenticator app enabled.';} async function disableTotpSetup(){if(!confirm('Disable authenticator app 2FA for this user?'))return; const j=await api('/api/users/2fa/totp/disable',{}); me=j.user; updateUserChrome(); $('profileMsg').className='msg ok'; $('profileMsg').textContent='Authenticator app disabled.';} async function registerWebauthn(kind){if(!webauthnSupported())throw new Error('WebAuthn requires HTTPS or localhost.'); const label=kind==='yubikey_2fa'?($('yubiLabel')?.value||'').trim()||`YubiKey 2FA ${(Number(me&&me.yubikey_2fa_count||0)+1)}`:'Passkey'; const opts=await api('/api/users/2fa/webauthn/register-options',{kind}); if(kind==='yubikey_2fa'&&opts.publicKey&&opts.publicKey.authenticatorSelection){opts.publicKey.authenticatorSelection.authenticatorAttachment='cross-platform'; opts.publicKey.authenticatorSelection.residentKey='discouraged'; opts.publicKey.authenticatorSelection.requireResidentKey=false; opts.publicKey.authenticatorSelection.userVerification='discouraged';} const cred=await navigator.credentials.create({publicKey:webauthnOptions(opts.publicKey)}); const resp=credentialResponse(cred,opts.challenge); resp.kind=kind; resp.label=label; const j=await api('/api/users/2fa/webauthn/register',resp); me=j.user; if(kind==='yubikey_2fa'&&$('yubiLabel'))$('yubiLabel').value=''; updateUserChrome(); $('profileMsg').className='msg ok'; $('profileMsg').textContent=kind==='yubikey_2fa'?`${label} registered as YubiKey 2FA.`:'Passkey registered for passwordless sign-in.';} async function removeWebauthn(kind,label,credentialId=''){if(!confirm(credentialId?`Delete ${label}?`:`Remove all ${label} from this user?`))return; const j=await api('/api/users/2fa/webauthn/disable',{kind,credential_id:credentialId}); me=j.user; updateUserChrome(); $('profileMsg').className='msg ok'; $('profileMsg').textContent=credentialId?`${label} deleted.`:`${label} removed.`;} if($('startTotp'))$('startTotp').onclick=async()=>{try{await startTotpSetup()}catch(e){$('profileMsg').className='msg error';$('profileMsg').textContent=e.message}}; if($('verifyTotp'))$('verifyTotp').onclick=async()=>{try{await verifyTotpSetup()}catch(e){$('profileMsg').className='msg error';$('profileMsg').textContent=e.message}}; if($('disableTotp'))$('disableTotp').onclick=async()=>{try{await disableTotpSetup()}catch(e){$('profileMsg').className='msg error';$('profileMsg').textContent=e.message}}; if($('registerPasskey'))$('registerPasskey').onclick=async()=>{try{await registerWebauthn('passkey')}catch(e){$('profileMsg').className='msg error';$('profileMsg').textContent=e.message}}; if($('removePasskeys'))$('removePasskeys').onclick=async()=>{try{await removeWebauthn('passkey','passkeys')}catch(e){$('profileMsg').className='msg error';$('profileMsg').textContent=e.message}}; if($('registerYubi'))$('registerYubi').onclick=async()=>{try{await registerWebauthn('yubikey_2fa')}catch(e){$('profileMsg').className='msg error';$('profileMsg').textContent=e.message}}; if($('removeYubi'))$('removeYubi').onclick=async()=>{try{await removeWebauthn('yubikey_2fa','YubiKey 2FA credentials')}catch(e){$('profileMsg').className='msg error';$('profileMsg').textContent=e.message}};


async function loadOidcConfig(){try{const j=await get('/api/oidc/config'); const c=j.oidc||{}; if($('oidcEnabled'))$('oidcEnabled').checked=!!c.enabled; if($('oidcIssuer'))$('oidcIssuer').value=c.issuer_url||''; if($('oidcClientId'))$('oidcClientId').value=c.client_id||''; if($('oidcRedirectUri'))$('oidcRedirectUri').value=c.redirect_uri||''; if($('oidcDomainAllow'))$('oidcDomainAllow').value=c.email_domain_allowlist||''; if($('oidcClientSecret'))$('oidcClientSecret').value=''; if($('oidcEnabledBadge')){$('oidcEnabledBadge').textContent=c.enabled?'enabled':'disabled';$('oidcEnabledBadge').classList.toggle('ok',!!c.enabled)} if($('oidcStatus'))$('oidcStatus').innerHTML=`<div><b>Login button</b>: ${c.enabled?'shown on sign-in page':'hidden until enabled'}</div><div><b>Client secret</b>: ${c.client_secret_configured?'configured':'missing'}</div><div><b>Signup</b>: ${c.allow_signup?'unknown users become viewers':'existing configured users only'}</div><div><b>Role source</b>: User Management record matched by email/username</div>`;}catch(e){if($('oidcMsg')){$('oidcMsg').className='msg error';$('oidcMsg').textContent=e.message}}}
async function saveOidcConfig(){try{const payload={enabled:$('oidcEnabled').checked,issuer_url:$('oidcIssuer').value,client_id:$('oidcClientId').value,client_secret:$('oidcClientSecret').value,redirect_uri:$('oidcRedirectUri').value,email_domain_allowlist:$('oidcDomainAllow').value}; const j=await api('/api/oidc/config',payload); $('oidcMsg').className='msg ok';$('oidcMsg').textContent='OIDC configuration saved. Client secret remains hidden.'; await loadOidcConfig();}catch(e){$('oidcMsg').className='msg error';$('oidcMsg').textContent=e.message}}
function showWorkspacePane(){['overview','auth','reauth','profiles'].forEach(s=>{const pane=$(s==='overview'?'workspaceOverviewPane':s==='auth'?'workspaceAuthPane':s==='reauth'?'workspaceReauthPane':'workspaceProfilesPane'); if(pane)pane.classList.toggle('hidden',workspaceActive!==s); const b=$('workspaceTab-'+s); if(b)b.classList.toggle('active',workspaceActive===s); const tb=$('workspaceTop-'+s); if(tb)tb.classList.toggle('active',workspaceActive===s);}); if(workspaceActive==='reauth'){['workspaceTab-overview','workspaceTab-auth','workspaceTab-profiles','workspaceTop-overview','workspaceTop-auth','workspaceTop-profiles'].forEach(id=>{const el=$(id); if(el)el.classList.remove('active');});}}
function showRuntimePane(){['status','validation','backups','paths','upgrade'].forEach(s=>{const pane=$('runtimePane-'+s); if(pane)pane.classList.toggle('hidden',runtimeActive!==s); const b=$('runtimeTab-'+s); if(b)b.classList.toggle('active',runtimeActive===s); const tb=$('runtimeTop-'+s); if(tb)tb.classList.toggle('active',runtimeActive===s);});}
function labelSettingsNavIcons(){const icons={profile:'account_circle',users:'manage_accounts',workspace:'cloud_sync',channels:'chat_bubble',approvals:'shield',runtime:'manufacturing',tokens:'vpn_key'}; document.querySelectorAll('.settingsSubnav button').forEach(b=>{const text=(b.textContent||'').trim(); if(text&&!b.title)b.title=text; const id=(b.id||'').replace('settingsNav-',''); if(!b.dataset.icon&&icons[id])b.dataset.icon=icons[id];});} function applySettingsNavCollapsed(){labelSettingsNavIcons(); const shell=$('settingsShell'); if(shell)shell.classList.toggle('collapsed',settingsNavCollapsed); const btn=$('settingsCollapse'); if(btn){btn.textContent='☰'; btn.title=settingsNavCollapsed?'Expand left menu':'Collapse left menu'; btn.setAttribute('aria-label',btn.title); btn.setAttribute('aria-expanded', String(!settingsNavCollapsed));}}
function showSettingPane(){updateAdminVisibility(); const adminMode=isAdmin()&&settingsMode==='admin'; if(settingsMode==='admin'&&settingsActive==='tokens')runtimeActive='status'; ['profile','users','workspace','channels','runtime','tokens'].forEach(s=>{const el=$('settings'+s.charAt(0).toUpperCase()+s.slice(1)); const visible=s==='profile'?!adminMode:(adminMode&&settingsActive===s); if(el)el.classList.toggle('hidden',!visible); const b=$('settingsNav-'+s); if(b)b.classList.toggle('active',visible&&(s==='profile'||settingsActive===s));}); const wb=$('settingsNav-workspace'); if(wb)wb.classList.toggle('active',adminMode&&settingsActive==='workspace'); const rb=$('settingsNav-runtime'); if(rb)rb.classList.toggle('active',adminMode&&settingsActive==='runtime'); const tb=$('settingsNav-tokens'); if(tb)tb.classList.toggle('active',adminMode&&settingsActive==='tokens'); document.querySelectorAll('.adminSubItem').forEach(b=>b.classList.toggle('hidden',!(adminMode&&adminSettingsExpanded))); const activeAdminId=settingsActive==='users'?'adminNav-users':settingsActive==='tokens'?'adminNav-tokens':settingsActive==='channels'?'adminNav-channels':settingsActive==='workspace'?'adminNav-workspace':settingsActive==='runtime'?'adminNav-system':''; document.querySelectorAll('.adminSubItem').forEach(b=>b.classList.toggle('active',adminMode&&b.id===activeAdminId)); showWorkspacePane(); showRuntimePane(); applySettingsNavCollapsed();} function showSettings(){const adminPane=isAdmin()&&settingsMode==='admin'; if(adminPane){if(settingsActive==='users'){loadUsers(); setUserMgmtPane('setup');} if(settingsActive==='workspace')loadWorkspaceAccess(); if(settingsActive==='channels')loadApprovalChannels();  if(settingsActive==='runtime'||settingsActive==='tokens')loadRuntimeStatus();} showSettingPane(); ($('settingsTitle')||document.querySelector('#settingsView h2')).textContent=adminPane?'Admin settings':'User settings'; $('cards').classList.toggle('hidden',active==='settings'); $('foot').textContent='';}
function applyMainNavCollapsed(){const app=$('appView'); const nav=$('mainNav'); const collapsed=localStorage.ggovMainNavCollapsed==='1'; const mobile=window.matchMedia&&window.matchMedia('(max-width: 760px)').matches; const mobileOpen=mobile&&localStorage.ggovMobileNavOpen==='1'; document.body.classList.toggle('mainNavCollapsed',collapsed&&!mobile); document.body.classList.toggle('mobileNavOpen',mobileOpen); if(app)app.classList.toggle('mainNavCollapsed',collapsed&&!mobile); if(nav)nav.classList.toggle('collapsed',collapsed&&!mobile); const btn=$('mainNavCollapse'); if(btn){if(!btn.querySelector('.railDots'))btn.innerHTML='<span class="railDots" aria-hidden="true"><span></span><span></span><span></span></span>'; btn.title=mobile?(mobileOpen?'Close menu':'Open menu'):(collapsed?'Expand main navigation':'Collapse main navigation'); btn.setAttribute('aria-label',btn.title); btn.setAttribute('aria-expanded',String(mobile?mobileOpen:!collapsed));} updateWelcomeTitle();}
function goHome(){active='rules';settingsMode='user';settingsActive='profile';location.hash='rules';render();requestAnimationFrame(()=>{const app=$('appView'); if(app)app.scrollTo({top:0,left:0,behavior:'smooth'}); else window.scrollTo({top:0,left:0,behavior:'smooth'});});}
function render(){writeRouteState(); const inSettings=active==='settings'; if($('appView')){$('appView').classList.toggle('settingsMode',inSettings);$('settingsView').classList.toggle('settingsViewCentered',inSettings);} applyMainNavCollapsed(); if($('mainNav'))$('mainNav').classList.remove('hidden'); ['rules','approvals','access','mcp'].forEach(t=>{$('tab-'+t).classList.toggle('active',active===t); $(t+'View').classList.toggle('hidden',active!==t)}); if($('tab-userSettings'))$('tab-userSettings').classList.toggle('active',active==='settings'&&settingsMode==='user'); if($('tab-adminSettings'))$('tab-adminSettings').classList.toggle('active',active==='settings'&&settingsMode==='admin'); $('settingsView').classList.toggle('hidden',!inSettings); $('cards').classList.toggle('hidden',active!=='rules'); if(active==='rules')renderRules(); if(active==='approvals')loadApprovals(); if(active==='access'){renderAccessLog(); loadAccessLog();} if(active==='mcp'){renderMcpTools(); loadMcpTools();} if(active==='settings'){showSettings(); if(settingsMode==='admin'&&settingsActive==='users'&&$('userTop-setup')&&$('userTop-setup').classList.contains('active'))setUserMgmtPane('setup');}} ['q'].forEach(id=>bindFilter(id,()=>{selected.clear();aclSelectionTouched=false;render()},'input')); function resetFilters(ids,fn){ids.forEach(id=>{const el=$(id); if(!el)return; if(el.multiple){[...el.options].forEach(o=>{o.selected=!o.value}); rememberMultiSelectState(el);} else {el.value='';}}); if(fn)fn();}
['profile','decision','service','route','token'].forEach(id=>bindFilter(id,()=>{selected.clear();aclSelectionTouched=false;render()})); ['accessQ'].forEach(id=>bindFilter(id,renderAccessLog,'input')); ['accessProfile','accessAction','accessDecision','accessStatus','accessRoute'].forEach(id=>bindFilter(id,renderAccessLog)); ['workspaceTokenQ','workspaceRouteQ'].forEach(id=>bindFilter(id,loadWorkspaceAccess,'input')); ['workspaceTokenAccount','workspaceTokenEmail','workspaceTokenStore','workspaceTokenStatus','workspaceRouteProfile','workspaceRouteAccount','workspaceRouteEmail'].forEach(id=>bindFilter(id,loadWorkspaceAccess)); if($('resetRulesFilters'))$('resetRulesFilters').onclick=()=>resetFilters(['q','profile','decision','service','route','token'],()=>{selected.clear();aclSelectionTouched=false;render()}); if($('resetAccessFilters'))$('resetAccessFilters').onclick=()=>resetFilters(['accessQ','accessProfile','accessAction','accessDecision','accessStatus','accessRoute'],renderAccessLog); if($('resetMcpFilters'))$('resetMcpFilters').onclick=()=>resetFilters(['mcpQ','mcpService','mcpRisk'],renderMcpTools); if($('resetWorkspaceTokenFilters'))$('resetWorkspaceTokenFilters').onclick=()=>resetFilters(['workspaceTokenQ','workspaceTokenAccount','workspaceTokenEmail','workspaceTokenStore','workspaceTokenStatus'],loadWorkspaceAccess); if($('resetWorkspaceRouteFilters'))$('resetWorkspaceRouteFilters').onclick=()=>resetFilters(['workspaceRouteQ','workspaceRouteProfile','workspaceRouteAccount','workspaceRouteEmail'],loadWorkspaceAccess); if($('resetApiTokenFilters'))$('resetApiTokenFilters').onclick=()=>{apiTokenStatusDefaulted=false; resetFilters(['apiTokenLabelFilter','apiTokenProfileFilter','apiTokenStatusFilter'],()=>renderRuntimeStatus(window.__lastRuntimeStatus||{version:{},gateway_health:{},jwt_secret:{},api_tokens:(window.__lastApiTokens||[])}));}; if($('brandHome'))$('brandHome').onclick=e=>{e.preventDefault();goHome();}; if($('mainNavCollapse'))$('mainNavCollapse').onclick=()=>{if(window.matchMedia&&window.matchMedia('(max-width: 760px)').matches){localStorage.ggovMobileNavOpen=localStorage.ggovMobileNavOpen==='1'?'0':'1';}else{localStorage.ggovMainNavCollapsed=localStorage.ggovMainNavCollapsed==='1'?'0':'1';}applyMainNavCollapsed();}; if($('mainNav')&&!$('mainNav').dataset.mobileDismissBound){$('mainNav').dataset.mobileDismissBound='1';$('mainNav').addEventListener('click',e=>{const btn=e.target.closest('button'); if(window.matchMedia&&window.matchMedia('(max-width: 760px)').matches&&btn&&btn.id!=='tab-adminSettings'){localStorage.ggovMobileNavOpen='0';document.body.classList.remove('mobileNavOpen');applyMainNavCollapsed();}});}; ['rules','approvals','access','mcp'].forEach(t=>{const b=$('tab-'+t); if(b)b.onclick=()=>{active=t;requestAnimationFrame(()=>window.scrollTo({top:0,left:0,behavior:'smooth'}));render()}}); if($('tab-userSettings'))$('tab-userSettings').onclick=()=>{active='settings';settingsMode='user';settingsActive='profile';requestAnimationFrame(()=>window.scrollTo({top:0,left:0,behavior:'smooth'}));render()}; if($('tab-adminSettings'))$('tab-adminSettings').onclick=()=>{if(active==='settings'&&settingsMode==='admin'){adminSettingsExpanded=!adminSettingsExpanded;localStorage.ggovAdminSettingsExpanded=adminSettingsExpanded?'1':'0';}else{active='settings';settingsMode='admin';settingsActive='workspace';workspaceActive='overview';adminSettingsExpanded=true;localStorage.ggovAdminSettingsExpanded='1';}requestAnimationFrame(()=>window.scrollTo({top:0,left:0,behavior:'smooth'}));render()}; const adminGo=(section,sub)=>{active='settings';settingsMode='admin';settingsActive=section;if(section==='workspace')workspaceActive=sub||'overview';if(section==='runtime')runtimeActive=sub||'status';requestAnimationFrame(()=>window.scrollTo({top:0,left:0,behavior:'smooth'}));render()}; if($('adminNav-users'))$('adminNav-users').onclick=()=>adminGo('users'); if($('adminNav-workspace'))$('adminNav-workspace').onclick=()=>adminGo('workspace',workspaceActive||'overview'); if($('adminNav-channels'))$('adminNav-channels').onclick=()=>adminGo('channels'); if($('adminNav-system'))$('adminNav-system').onclick=()=>adminGo('runtime',runtimeActive||'status'); if($('adminNav-tokens'))$('adminNav-tokens').onclick=()=>adminGo('tokens'); if($('adminNav-oidc'))$('adminNav-oidc').onclick=()=>adminGo('oidc'); $('refreshAccess').onclick=async()=>{const b=$('refreshAccess'); b.disabled=true; b.textContent='Refreshing…'; await loadAccessLog(); b.textContent='Refreshed ✓'; setTimeout(()=>{b.disabled=false;b.textContent='Refresh logs'},900)}; if($('settingsBack'))$('settingsBack').onclick=()=>{active='rules';settingsMode='user';settingsActive='profile';render()}; if($('settingsCollapse'))$('settingsCollapse').onclick=()=>{settingsNavCollapsed=!settingsNavCollapsed;localStorage.ggovSettingsNavCollapsed=settingsNavCollapsed?'1':'0';applySettingsNavCollapsed()}; $('settingsNav-profile').onclick=()=>{settingsMode='user';settingsActive='profile';render()}; ['users'].forEach(s=>{$('settingsNav-'+s).onclick=()=>{settingsMode='admin';settingsActive=s; render()}}); $('settingsNav-workspace').onclick=()=>{settingsMode='admin';settingsActive='workspace';workspaceActive='overview';render()}; $('settingsNav-runtime').onclick=()=>{settingsMode='admin';settingsActive='runtime';runtimeActive='status';render()}; if($('settingsNav-tokens'))$('settingsNav-tokens').onclick=()=>{settingsMode='admin';settingsActive='tokens';render()}; ['overview','auth','profiles'].forEach(s=>{const b=$('workspaceTab-'+s); if(b)b.onclick=()=>{settingsActive='workspace';workspaceActive=s; render();}; const tb=$('workspaceTop-'+s); if(tb)tb.onclick=()=>{settingsActive='workspace';workspaceActive=s; render();}}); ['status','validation','backups','paths','upgrade'].forEach(s=>{const b=$('runtimeTab-'+s); if(b)b.onclick=()=>{settingsActive='runtime';runtimeActive=s; render();}; const tb=$('runtimeTop-'+s); if(tb)tb.onclick=()=>{settingsActive='runtime';runtimeActive=s; render();}}); setInterval(()=>{if(active==='access')loadAccessLog()},5000); document.addEventListener('input',e=>{if(e.target&&e.target.classList.contains('apiTokenFilter')){apiTokenFilters[e.target.dataset.key]=e.target.value; renderRuntimeStatus(window.__lastRuntimeStatus||{version:{},gateway_health:{},jwt_secret:{},api_tokens:(window.__lastApiTokens||[])});}}); document.addEventListener('click',e=>{if(e.target&&e.target.classList.contains('apiTokenFilter'))return; const th=e.target.closest('th[data-sort]'); if(!th)return; let table=th.closest('#rulesView')?'rules':(th.closest('#accessView')?'access':(th.closest('#settingsUsers')?'users':(th.closest('#apiTokenInventory')?'apiTokens':''))); const tbody=th.closest('table')&&th.closest('table').querySelector('tbody'); if(!table&&tbody&&tbody.id==='workspaceOverview')table='workspaceTokens'; if(!table&&tbody&&tbody.id==='workspaceRoutes')table='workspaceRoutes'; if(table)setSort(table,th.dataset.sort);}); if($('saveApprovalSettings'))$('saveApprovalSettings').onclick=()=>saveApprovalSettings(false); if($('saveBotSettings'))$('saveBotSettings').onclick=()=>saveApprovalSettings(false); if($('deliveryRulesToggle'))$('deliveryRulesToggle').onchange=()=>saveApprovalSettings(true); if($('channelScope'))$('channelScope').onchange=()=>{if($('channelProfile'))$('channelProfile').disabled=$('channelScope').value!=='profile'}; if($('saveChannel'))$('saveChannel').onclick=saveApprovalChannel; ['telegram','whatsapp','webhooks','email'].forEach(x=>{if($('channelTop-'+x))$('channelTop-'+x).onclick=()=>setChannelPane(x)}); if($('refreshApprovals'))$('refreshApprovals').onclick=loadApprovals; if($('bulkApproveApprovals'))$('bulkApproveApprovals').onclick=()=>bulkDecideApprovals('approve_once'); if($('bulkDenyApprovals'))$('bulkDenyApprovals').onclick=()=>bulkDecideApprovals('deny'); if($('clearApprovals'))$('clearApprovals').onclick=clearApprovals; if($('approvalState'))$('approvalState').onchange=loadApprovals; check();


async function loadApprovalChannels(){try{const j=await api('/api/approval-channels/list',{}); renderApprovalSettings(j.settings||{},j.channels||[]); renderApprovalChannels(j.channels||[]); const profiles=uniq((data.profile_options||data.rules||[]).map(r=>typeof r==='string'?r:r.profile).filter(Boolean)); opt($('channelProfile'), profiles, true); if($('channelScope')&&$('channelProfile')) $('channelProfile').disabled=$('channelScope').value!=='profile';}catch(e){if($('channelMsg')){$('channelMsg').className='msg error';$('channelMsg').textContent=e.message}}}
function setChannelPane(pane='telegram'){['telegram','whatsapp','webhooks','email'].forEach(x=>{if($('channelPane-'+x))$('channelPane-'+x).classList.toggle('hidden',x!==pane); if($('channelTop-'+x))$('channelTop-'+x).classList.toggle('active',x===pane)}); if($('channelMsg')){$('channelMsg').className='msg';$('channelMsg').textContent=''}}
function renderApprovalSettings(settings,channels=[]){if($('approvalPublicBaseUrl'))$('approvalPublicBaseUrl').value=settings.public_base_url||''; if($('telegramBotToken'))$('telegramBotToken').value=''; if($('approvalWebhookToken'))$('approvalWebhookToken').value=''; if($('clearTelegramBotToken'))$('clearTelegramBotToken').checked=false; if($('clearApprovalWebhookToken'))$('clearApprovalWebhookToken').checked=false; const enabled=settings.delivery_rules_enabled!==false; if($('deliveryRulesToggle'))$('deliveryRulesToggle').checked=enabled; const active=(channels||[]).filter(c=>c.enabled).length; const overrides=(channels||[]).filter(c=>c.bot_token_configured).length; if($('telegramBotSummary'))$('telegramBotSummary').innerHTML=settings.bot_token_configured?`<span class="pill ok">bot configured</span> ${settings.webhook_token_configured?'<span class="pill ok">webhook token set</span>':'<span class="pill">derived webhook token</span>'}`:'<span class="pill">bot missing</span>'; if($('telegramDeliverySummary'))$('telegramDeliverySummary').textContent=enabled?'On':'Off'; if($('telegramDestSummary'))$('telegramDestSummary').textContent=`${active} active / ${(channels||[]).length} total${overrides?` · ${overrides} legacy bot override${overrides===1?'':'s'}`:''}`;}
async function saveApprovalSettings(silent=false){try{const j=await api('/api/approval-settings/save',{bot_token:$('telegramBotToken')?$('telegramBotToken').value:'',clear_bot_token:$('clearTelegramBotToken')?$('clearTelegramBotToken').checked:false,webhook_token:$('approvalWebhookToken')?$('approvalWebhookToken').value:'',clear_webhook_token:$('clearApprovalWebhookToken')?$('clearApprovalWebhookToken').checked:false,public_base_url:$('approvalPublicBaseUrl')?$('approvalPublicBaseUrl').value:'',delivery_rules_enabled:$('deliveryRulesToggle')?$('deliveryRulesToggle').checked:true}); renderApprovalSettings(j.settings||{},j.channels||[]); if(!silent&&$('channelMsg')){$('channelMsg').className='msg ok';$('channelMsg').textContent='Approver configuration saved.';}}catch(e){if($('channelMsg')){$('channelMsg').className='msg error';$('channelMsg').textContent=e.message}}}
function renderApprovalChannels(rows){const tb=$('approvalChannels'); if(!tb)return; const rowsArr=rows||[]; if($('telegramDestSummary')){const active=rowsArr.filter(c=>c.enabled).length; const overrides=rowsArr.filter(c=>c.bot_token_configured).length; $('telegramDestSummary').textContent=`${active} active / ${rowsArr.length} total${overrides?` · ${overrides} legacy bot override${overrides===1?'':'s'}`:''}`;} tb.innerHTML=rowsArr.map(c=>{const applies=c.scope==='all'?'All profiles':`Profile: ${esc(c.profile||'—')}`; const id=Number(c.id); return `<tr><td>${esc(c.label)}</td><td class="code">${esc(c.chat_id)}</td><td>${applies}</td><td><label class="miniSwitch"><input type="checkbox" ${c.enabled?'checked':''} onchange="toggleApprovalChannel(${id},this.checked)"/><span></span><b>${c.enabled?'enabled':'disabled'}</b></label></td><td><button onclick="deleteApprovalChannel(${id})">Delete</button></td></tr>`}).join('')||'<tr><td colspan="5" class="muted">No Telegram destinations configured.</td></tr>';}
async function saveApprovalChannel(){try{const payload={label:$('channelLabel').value,chat_id:$('channelChatId').value,scope:$('channelScope').value,profile:$('channelProfile').value,button_base_url:'',bot_token:'',clear_bot_token:false,enabled:$('channelEnabled').value==='true'}; const j=await api('/api/approval-channels/save',payload); ['channelLabel','channelChatId'].forEach(id=>{if($(id))$(id).value=''}); $('channelMsg').className='msg ok';$('channelMsg').textContent='Destination saved.'; renderApprovalSettings(j.settings||{},j.channels||[]); renderApprovalChannels(j.channels||[]);}catch(e){$('channelMsg').className='msg error';$('channelMsg').textContent=e.message}}
async function toggleApprovalChannel(id,enabled){try{const rows=(await api('/api/approval-channels/list',{})).channels||[]; const c=rows.find(x=>Number(x.id)===Number(id)); if(!c)throw new Error('Destination not found'); const j=await api('/api/approval-channels/save',{id,label:c.label,chat_id:c.chat_id,scope:c.scope,profile:c.profile,button_base_url:c.button_base_url||'',bot_token:'',clear_bot_token:false,enabled}); renderApprovalSettings(j.settings||{},j.channels||[]); renderApprovalChannels(j.channels||[]); if($('channelMsg')){$('channelMsg').className='msg ok';$('channelMsg').textContent=`Destination ${enabled?'enabled':'disabled'}.`;}}catch(e){if($('channelMsg')){$('channelMsg').className='msg error';$('channelMsg').textContent=e.message}; await loadApprovalChannels();}}
async function deleteApprovalChannel(id){try{const j=await api('/api/approval-channels/delete',{id}); $('channelMsg').className='msg ok';$('channelMsg').textContent='Destination deleted.'; renderApprovalSettings(j.settings||{},j.channels||[]); renderApprovalChannels(j.channels||[]);}catch(e){$('channelMsg').className='msg error';$('channelMsg').textContent=e.message}}
async function loadApprovals(){try{const j=await api('/api/approvals/list',{state:$('approvalState')?.value||'pending'}); renderApprovals(j.approvals||[]);}catch(e){if($('approvalMsg')){$('approvalMsg').className='msg error';$('approvalMsg').textContent=e.message}}}
function prettyJson(v){try{return JSON.stringify(v,null,2)}catch(_){return String(v)}} function showDetailModal(title,row){const m=$('detailModal'), h=$('detailModalTitle'), b=$('detailModalBody'); if(!m||!b)return; if(h)h.textContent=title; const safe=row||{}; const body=safe.request_body||safe.body||safe.payload||safe.request||null; const meta=safe.safe_metadata||safe.metadata||null; b.innerHTML=`<div class="detailGrid"><div><b>Actual access</b><span>${esc(safe.actual_access||'—')}</span></div><div><b>Profile</b><span>${esc(safe.profile||safe.actor||'—')}</span></div><div><b>Action</b><span>${esc(safe.action||'—')}</span></div><div><b>Status</b><span>${esc(approvalStatusLabel?safe.state?approvalStatusLabel(safe):(safe.outcome||safe.status||'—'):(safe.outcome||safe.status||'—'))}</span></div><div><b>Route</b><span class="code">${esc(safe.token_route||safe.route||'—')}</span></div><div><b>Resource</b><span>${esc(safe.resource_alias||safe.resource||safe.target||'—')}</span></div><div><b>Time</b><span>${esc(fmtLocalTime(safe.requested_at||safe.time_cst||safe.ts)||'—')}</span></div></div><h4>Request body / payload</h4><pre>${esc(prettyJson(body||meta||safe))}</pre><h4>Full event</h4><pre>${esc(prettyJson(safe))}</pre>`; m.classList.remove('hidden');} function closeDetailModal(){if($('detailModal'))$('detailModal').classList.add('hidden')}
function approvalStatusLabel(a){const st=String(a.state||a.status||'pending'); if(st==='approve_once'||st==='approved')return 'Approved'; if(st==='deny'||st==='denied')return 'Denied'; if(st==='request_edit')return 'Needs edit'; if(st==='expired')return 'Expired'; if(st==='execution_failed')return 'Execution failed'; if(st==='consumed')return 'Consumed'; if(st==='cleared')return 'Cleared'; return st.charAt(0).toUpperCase()+st.slice(1);} function renderApprovals(rows){const tb=$('approvals'); if(!tb)return; const list=rows||[]; window.__approvalDetailRows=list; tb.innerHTML=list.map((a,i)=>{const id=esc(a.approval_id||a.id||''); const raw=esc(a.approval_id||a.id||''); const requested=fmtLocalTime(a.requested_at||a.ts); const expires=fmtLocalTime(a.expires_at); const status=approvalStatusLabel(a); const pending=['pending','request_edit'].includes(String(a.state||'pending')); return `<tr><td class="code">${id}</td><td>${esc(a.profile||'')}</td><td>${esc(a.action||'')}</td><td>${esc(a.resource_alias||'')}</td><td>${esc(requested)}</td><td>${esc(expires)}</td><td><span class="pill">${esc(status)}</span>${pending?` <button class="iconDecision successBtn" title="Approve and execute" data-approval-id="${raw}" data-decision="approve_once">✓</button> <button class="iconDecision dangerBtn" title="Deny" data-approval-id="${raw}" data-decision="deny">✕</button>`:''}</td><td><button class="iconBtn detailBtn" title="View full request details" aria-label="View full request details" data-detail-kind="approval" data-detail-index="${i}">ⓘ</button></td></tr>`}).join('')||'<tr><td colspan="8" class="muted">No approvals in this view.</td></tr>'; tb.querySelectorAll('button[data-approval-id]').forEach(btn=>{btn.onclick=()=>decideApproval(btn.dataset.approvalId,btn.dataset.decision)}); tb.querySelectorAll('button[data-detail-kind="approval"]').forEach(btn=>{btn.onclick=()=>showDetailModal('Approval request details',window.__approvalDetailRows[Number(btn.dataset.detailIndex)]||{})});}
async function decideApproval(approval_id,decision){try{const payload={approval_id,decision}; if(decision==='approve_once')payload.execute_after_approval=true; const j=await api('/api/approvals/decide',payload); $('approvalMsg').className='msg ok';$('approvalMsg').textContent=decision==='approve_once'?`Approved and executed ${approval_id}.`:`Denied ${approval_id}.`; if(j.execution&&j.execution.result&&j.execution.result.id)$('approvalMsg').textContent+=` Result: ${j.execution.result.id}`; await loadApprovals(); await load();}catch(e){$('approvalMsg').className='msg error';$('approvalMsg').textContent=e.message}}
async function bulkDecideApprovals(decision){try{const j=await api('/api/approvals/bulk-decide',{decision,state:$('approvalState')?.value||'pending'}); $('approvalMsg').className='msg ok';$('approvalMsg').textContent=`${decision==='approve_once'?'Approved':'Denied'} ${j.count||0} shown approval(s).`; await loadApprovals(); await load();}catch(e){$('approvalMsg').className='msg error';$('approvalMsg').textContent=e.message}}
async function clearApprovals(){try{const j=await api('/api/approvals/clear',{state:$('approvalState')?.value||'pending'}); $('approvalMsg').className='msg ok';$('approvalMsg').textContent=`Cleared ${j.count||0} approval request(s).`; await loadApprovals(); await load();}catch(e){$('approvalMsg').className='msg error';$('approvalMsg').textContent=e.message}}

function setUserMgmtPane(pane='setup'){const setup=$('userSetupPane'), oidc=$('settingsOidc'), bSetup=$('userTop-setup'), bOidc=$('userTop-oidc'); const showOidc=pane==='oidc'; if(setup)setup.classList.toggle('hidden',showOidc); if(oidc)oidc.classList.toggle('hidden',!showOidc); if(bSetup)bSetup.classList.toggle('active',!showOidc); if(bOidc)bOidc.classList.toggle('active',showOidc); if(showOidc)loadOidcConfig();}
function bindUserMgmtTabs(){if($('userTop-setup'))$('userTop-setup').onclick=()=>setUserMgmtPane('setup'); if($('userTop-oidc'))$('userTop-oidc').onclick=()=>setUserMgmtPane('oidc');}
function bindUserMenuDismiss(){/* profile image is display-only; logout is a direct icon button in the left rail */}
function enhanceResponsiveTables(){document.querySelectorAll('table').forEach(table=>{const headers=[...table.querySelectorAll('thead th')].map(th=>(th.textContent||th.getAttribute('data-sort')||'').replace(/\s+/g,' ').trim()); table.querySelectorAll('tbody tr').forEach(row=>{[...row.children].forEach((cell,i)=>{if(cell.tagName!=='TD')return; const label=headers[i]||''; if(!cell.dataset.label)cell.dataset.label=label;});});});}
const tableLabelObserver=new MutationObserver(()=>{if(window.__tableLabelRaf)cancelAnimationFrame(window.__tableLabelRaf); window.__tableLabelRaf=requestAnimationFrame(enhanceResponsiveTables);});
tableLabelObserver.observe(document.body,{childList:true,subtree:true});
window.addEventListener('resize',()=>requestAnimationFrame(()=>{applyMainNavCollapsed();enhanceResponsiveTables();}));
requestAnimationFrame(enhanceResponsiveTables);
bindUserMgmtTabs(); bindUserMenuDismiss(); if($('detailModalClose'))$('detailModalClose').onclick=closeDetailModal; if($('detailModal'))$('detailModal').onclick=e=>{if(e.target===$('detailModal'))closeDetailModal()}; document.addEventListener('keydown',e=>{if(e.key==='Escape')closeDetailModal()});

</script></body></html>'''



class Handler(BaseHTTPRequestHandler):
    server_version = "GoogleWorkspaceGovernanceControl/1.0"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def do_GET(self) -> None:
        try:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path
            query = urllib.parse.parse_qs(parsed.query)
            if path == "/healthz":
                _json_response(self, 200, {"status": "ok", "service": "google-governance-control", "gateway": GATEWAY_URL, "auth": "disabled" if CONTROL_AUTH_DISABLED else "app_session", "setup_required": (False if CONTROL_AUTH_DISABLED else _setup_required())})
                return
            if path in {"/", "/index.html"}:
                _text_response(self, 200, INDEX_HTML)
                return
            if path == "/assets/logo-light.png" and CONTROL_LOGO_LIGHT_PATH.exists():
                _bytes_response(self, 200, CONTROL_LOGO_LIGHT_PATH.read_bytes(), "image/png")
                return
            if path == "/assets/logo-dark.png" and CONTROL_LOGO_DARK_PATH.exists():
                _bytes_response(self, 200, CONTROL_LOGO_DARK_PATH.read_bytes(), "image/png")
                return
            if path == "/assets/logo-login-dark.png" and CONTROL_LOGIN_LOGO_DARK_PATH.exists():
                _bytes_response(self, 200, CONTROL_LOGIN_LOGO_DARK_PATH.read_bytes(), "image/png")
                return
            if path == "/assets/user-settings-icon.png" and CONTROL_USER_SETTINGS_ICON_PATH.exists():
                _bytes_response(self, 200, CONTROL_USER_SETTINGS_ICON_PATH.read_bytes(), "image/png")
                return
            if path == "/assets/logout-icon.png" and CONTROL_LOGOUT_ICON_PATH.exists():
                _bytes_response(self, 200, CONTROL_LOGOUT_ICON_PATH.read_bytes(), "image/png")
                return
            if path == "/assets/logo.jpg" and CONTROL_LOGO_PATH.exists():
                _bytes_response(self, 200, CONTROL_LOGO_PATH.read_bytes(), "image/jpeg")
                return
            if path == "/api/oidc/public":
                _json_response(self, 200, _oidc_public_login_config())
                return
            if path == "/api/oidc/login":
                _oidc_start_login(self)
                return
            if path == "/api/oidc/callback":
                _oidc_finish_login(self, query)
                return
            if path == "/api/me":
                user = _require_auth(self)
                if user is None:
                    return
                _json_response(self, 200, {"status": "ok", "user": _current_user_payload(user)})
                return
            user = _require_auth(self)
            if user is None:
                return
            if path == "/api/snapshot":
                _json_response(self, 200, _snapshot())
            elif path == "/api/access-log":
                _json_response(self, 200, _access_log())
            elif path == "/api/runtime/status":
                _require_admin(user)
                _json_response(self, 200, _runtime_status())
            elif path == "/api/oidc/config":
                _require_admin(user)
                _json_response(self, 200, {"status": "ok", "oidc": _oidc_public_config()})
            elif path == "/api/mcp/tools":
                _require_admin(user)
                _json_response(self, 200, _mcp_tool_catalog())
            elif path == "/api/runtime/backup/download":
                _require_admin(user)
                archive, selected = _runtime_backup_archive((query.get("id") or [""])[0])
                _append_change_event({"event": "runtime_backup_downloaded", "actor": user, "backup_id": selected.get("id"), "archive": str(archive)})
                _download_response(self, archive, archive.name)
            else:
                _json_response(self, 404, {"error": "not_found"})
        except Exception as exc:
            _json_response(self, 500, {"error": type(exc).__name__, "message": str(exc)})

    def do_POST(self) -> None:
        try:
            payload = _read_json_body(self)
            parsed_path = urllib.parse.urlparse(self.path)
            if parsed_path.path == "/v1/governance/approvals/telegram-webhook":
                _json_response(self, 200, _gateway_post_no_auth(self.path, payload))
                return
            if self.path == "/api/setup":
                result = _bootstrap_setup(payload)
                _json_response(self, 200, result)
                return
            if self.path == "/api/login":
                result = _login(payload, self)
                _json_response_with_cookie(self, 200, result, username=(result["user"]["username"] if result.get("status") == "ok" else None))
                return
            if self.path == "/api/login/2fa":
                result = _login_2fa(payload, self)
                _json_response_with_cookie(self, 200, result, username=result["user"]["username"])
                return
            if self.path == "/api/login/webauthn/options":
                _json_response(self, 200, _webauthn_login_options(payload, self))
                return
            if self.path == "/api/login/passkey/options":
                _json_response(self, 200, _passkey_login_options(payload, self))
                return
            if self.path == "/api/login/passkey/verify":
                result = _passkey_login_verify(payload, self)
                _json_response_with_cookie(self, 200, result, username=result["user"]["username"])
                return
            if self.path == "/api/logout":
                _json_response_with_cookie(self, 200, {"status": "logged_out"}, clear=True)
                return
            user = _require_auth(self)
            if user is None:
                return
            payload.setdefault("actor", user)
            payload.setdefault("approver", user)
            if self.path == "/api/policy/apply":
                _json_response(self, 200, _apply_policy_change(payload))
            elif self.path == "/api/runtime/apply":
                _require_admin(user)
                _json_response(self, 200, _runtime_apply(user))
            elif self.path == "/api/runtime/validate":
                _require_admin(user)
                _json_response(self, 200, _runtime_validate(user))
            elif self.path == "/api/runtime/sync-yaml-from-ui":
                _require_admin(user)
                _json_response(self, 200, _runtime_sync_yaml_from_ui(user))
            elif self.path == "/api/runtime/yaml/compare":
                _require_admin(user)
                _json_response(self, 200, _runtime_compare_yaml(user))
            elif self.path == "/api/runtime/backup/create":
                _require_admin(user)
                _json_response(self, 200, _runtime_backup_create(payload, user))
            elif self.path == "/api/runtime/backup/export":
                _require_admin(user)
                _json_response(self, 200, _runtime_backup_export(payload, user))
            elif self.path == "/api/runtime/backup/import":
                _require_admin(user)
                _json_response(self, 200, _runtime_backup_import(payload, user))
            elif self.path == "/api/runtime/backup/schedule":
                _require_admin(user)
                _json_response(self, 200, _runtime_backup_schedule(payload, user))
            elif self.path == "/api/runtime/restart":
                _require_admin(user)
                _json_response(self, 200, _runtime_restart(user))
            elif self.path == "/api/mcp/test":
                _require_admin(user)
                _json_response(self, 200, _mcp_test_tool(payload, user))
            elif self.path == "/api/runtime/jwt-secret/migrate":
                _require_admin(user)
                _json_response(self, 200, _jwt_secret_migrate_to_db(user))
            elif self.path == "/api/runtime/jwt-secret/rotate":
                _require_admin(user)
                _json_response(self, 200, _jwt_secret_rotate(payload, user))
            elif self.path == "/api/runtime/api-token/generate":
                _require_admin(user)
                _json_response(self, 200, _api_token_generate(payload, user))
            elif self.path == "/api/runtime/api-token/revoke":
                _require_admin(user)
                _json_response(self, 200, _api_token_revoke(payload, user))
            elif self.path == "/api/policy/bulk-apply":
                _json_response(self, 200, _apply_bulk_policy_changes(payload))
            elif self.path == "/api/workspace/access/list":
                _require_admin(user)
                _json_response(self, 200, _workspace_access_inventory())
            elif self.path == "/api/workspace/access/create-request":
                _require_admin(user)
                _json_response(self, 200, _workspace_access_create_request(payload, user))
            elif self.path == "/api/workspace/oauth/start":
                _require_admin(user)
                _json_response(self, 200, _oauth_start(payload, user))
            elif self.path == "/api/workspace/oauth/reauthorize":
                _require_admin(user)
                _json_response(self, 200, _oauth_reauthorize(payload, user))
            elif self.path == "/api/workspace/oauth/exchange":
                _require_admin(user)
                _json_response(self, 200, _oauth_exchange(payload, user))
            elif self.path == "/api/workspace/access/test":
                _require_admin(user)
                _json_response(self, 200, _workspace_access_test(payload, user))
            elif self.path == "/api/workspace/access/refresh":
                _require_admin(user)
                _json_response(self, 200, _workspace_access_refresh(payload, user))
            elif self.path == "/api/workspace/access/map-profiles":
                _require_admin(user)
                _json_response(self, 200, _workspace_access_map_profiles(payload, user))
            elif self.path == "/api/workspace/access/unmap-profiles":
                _require_admin(user)
                _json_response(self, 200, _workspace_access_unmap_profiles(payload, user))
            elif self.path == "/api/workspace/access/import-files":
                _require_admin(user)
                _json_response(self, 200, _workspace_access_import_files(payload, user))
            elif self.path == "/api/workspace/access/revoke":
                _require_admin(user)
                _json_response(self, 200, _workspace_access_revoke(payload, user))
            elif self.path == "/api/approvals/list":
                _require_admin(user)
                _json_response(self, 200, _approval_inventory(payload))
            elif self.path == "/api/approvals/decide":
                _require_admin(user)
                _json_response(self, 200, _approval_decide_ui(payload, user))
            elif self.path == "/api/approvals/bulk-decide":
                _require_admin(user)
                _json_response(self, 200, _approval_bulk_decide_ui(payload, user))
            elif self.path == "/api/approvals/clear":
                _require_admin(user)
                _json_response(self, 200, _approval_clear_ui(payload, user))
            elif self.path == "/api/approval-channels/list":
                _require_admin(user)
                _json_response(self, 200, _approval_channels_list())
            elif self.path == "/api/approval-channels/save":
                _require_admin(user)
                _json_response(self, 200, _approval_channel_save(payload, user))
            elif self.path == "/api/approval-settings/save":
                _require_admin(user)
                _json_response(self, 200, _approval_telegram_settings_save(payload, user))
            elif self.path == "/api/approval-channels/delete":
                _require_admin(user)
                _json_response(self, 200, _approval_channel_delete(payload, user))
            elif self.path == "/api/users/list":
                _require_admin(user)
                _json_response(self, 200, _list_users(user))
            elif self.path == "/api/users/save":
                _json_response(self, 200, _save_user(payload, user))
            elif self.path == "/api/users/delete":
                _json_response(self, 200, _delete_user(payload, user))
            elif self.path == "/api/users/change-password":
                _json_response(self, 200, _change_password(payload, user))
            elif self.path == "/api/users/profile":
                _json_response(self, 200, _update_profile(payload, user))
            elif self.path == "/api/users/2fa/totp/start":
                _json_response(self, 200, _totp_enroll_start(user))
            elif self.path == "/api/users/2fa/totp/verify":
                _json_response(self, 200, _totp_enroll_verify(payload, user))
            elif self.path == "/api/users/2fa/totp/disable":
                _json_response(self, 200, _totp_disable(payload, user))
            elif self.path == "/api/users/2fa/webauthn/register-options":
                _json_response(self, 200, _webauthn_register_options(user, self, str(payload.get("kind") or "passkey")))
            elif self.path == "/api/users/2fa/webauthn/register":
                _json_response(self, 200, _webauthn_register_verify(payload, user, self))
            elif self.path == "/api/users/2fa/webauthn/disable":
                _json_response(self, 200, _webauthn_disable(payload, user))
            elif self.path == "/api/oidc/config":
                _require_admin(user)
                _json_response(self, 200, _save_oidc_config(payload, user))
            else:
                _json_response(self, 404, {"error": "not_found"})
        except Exception as exc:
            status = 403 if isinstance(exc, PermissionError) else (400 if isinstance(exc, ValueError) else 500)
            _json_response(self, status, {"error": type(exc).__name__, "message": str(exc)})


def main() -> None:
    if "--runtime-backup-now" in sys.argv:
        include = "--include-token-store" in sys.argv
        result = _runtime_backup_create({"include_token_store": include, "note": "scheduled cron backup"}, os.getenv("GOOGLE_GOVERNANCE_RUNTIME_BACKUP_ACTOR", "cron"))
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    required = [POLICY_PATH, REGISTRY_PATH, APPROVAL_SECRET_PATH]
    if not CONTROL_AUTH_DISABLED:
        required.append(CONTROL_SESSION_SECRET_PATH)
        if not CONTROL_USERS_DB_PATH.exists() and not CONTROL_USERS_JSON_PATH.exists() and not _read_setup_token():
            required.append(CONTROL_SETUP_TOKEN_PATH)
    missing = [str(p) for p in required if not p.exists()]
    if missing:
        raise SystemExit("missing required files: " + ", ".join(missing))
    server = ThreadingHTTPServer((CONTROL_HOST, CONTROL_PORT), Handler)
    print(f"Google Workspace governance control plane listening on {CONTROL_HOST}:{CONTROL_PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
