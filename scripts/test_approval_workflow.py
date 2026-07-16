#!/usr/bin/env python3
"""Approval workflow tests for the Google governance gateway.

Tests stay local/offline: no Google API call is made. The high-risk executor is
monkeypatched through _session with a fake requests-like object.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sqlite3
import tempfile
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any

PROJECT_DIR = Path(__file__).resolve().parents[1]
GATEWAY_SCRIPT = PROJECT_DIR / "scripts" / "unified_google_gateway.py"


def load_gateway():
    import sys
    sys.path.insert(0, str(PROJECT_DIR / "scripts"))
    spec = importlib.util.spec_from_file_location("unified_google_gateway_approval_test", GATEWAY_SCRIPT)
    if spec is None or spec.loader is None:
        raise SystemExit("could not load gateway module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    tmp = Path(tempfile.mkdtemp(prefix="google-gov-approval-"))
    setattr(module, "APPROVAL_STORE_PATH", tmp / "approval-events.jsonl")
    setattr(module, "APPROVAL_DB_PATH", tmp / "approval-state.sqlite")
    setattr(module, "AUDIT_PATH", tmp / "audit.jsonl")
    os.environ["GOOGLE_GOVERNANCE_APPROVAL_ADMIN_SECRET"] = "approval-test-secret"
    return module, tmp


class FakeResponse:
    status_code = 200
    content = b'{"id":"perm-test"}'
    headers = {"content-type": "application/json"}

    def json(self) -> dict[str, Any]:
        return {"id": "perm-test"}


class FakeSession:
    def __init__(self):
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def post(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(("POST", url, kwargs))
        return FakeResponse()

    def delete(self, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append(("DELETE", url, kwargs))
        return FakeResponse()

    def request(self, method: str, url: str, **kwargs: Any) -> FakeResponse:
        self.calls.append((method.upper(), url, kwargs))
        return FakeResponse()


def assert_no_raw_values(path: Path, *raw_values: str) -> None:
    text = path.read_text(encoding="utf-8")
    for value in raw_values:
        if value in text:
            raise SystemExit(f"raw sensitive value leaked into approval store: {value}")


def main() -> None:
    gateway, tmp = load_gateway()
    os.environ["GOOGLE_GOVERNANCE_APPROVAL_WEBHOOK_TOKEN"] = "user_selected_webhook_token_123"
    if gateway._approval_webhook_token() != "user_selected_webhook_token_123":
        raise SystemExit("user-configured webhook token was not honored")
    os.environ.pop("GOOGLE_GOVERNANCE_APPROVAL_WEBHOOK_TOKEN", None)
    if gateway._approval_webhook_token() == "user_selected_webhook_token_123":
        raise SystemExit("webhook token did not fall back after env override removal")
    scoped_db = tmp / "scoped-approvals.sqlite"
    setattr(gateway, "TOKEN_DB_PATH", scoped_db)
    with sqlite3.connect(scoped_db) as conn:
        conn.execute("CREATE TABLE approval_tenants(id TEXT PRIMARY KEY,label TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1)")
        conn.execute("CREATE TABLE users(username TEXT PRIMARY KEY,role TEXT NOT NULL DEFAULT 'viewer',enabled INTEGER NOT NULL DEFAULT 1)")
        conn.execute("CREATE TABLE approval_tenant_bots(tenant_id TEXT PRIMARY KEY,bot_token TEXT NOT NULL DEFAULT '',public_base_url TEXT NOT NULL DEFAULT '',webhook_token TEXT NOT NULL DEFAULT '',enabled INTEGER NOT NULL DEFAULT 1)")
        conn.execute("CREATE TABLE approval_tenant_approvers(id INTEGER PRIMARY KEY AUTOINCREMENT,tenant_id TEXT NOT NULL,label TEXT NOT NULL DEFAULT '',chat_id TEXT NOT NULL,enabled INTEGER NOT NULL DEFAULT 1)")
        conn.execute("CREATE TABLE approval_tenant_agent_acl(id INTEGER PRIMARY KEY AUTOINCREMENT,tenant_id TEXT NOT NULL,agent_id TEXT NOT NULL DEFAULT '*',enabled INTEGER NOT NULL DEFAULT 1)")
        conn.execute("ALTER TABLE approval_tenants ADD COLUMN owner_username TEXT NOT NULL DEFAULT ''")
        conn.execute("INSERT INTO users(username,role,enabled) VALUES('admin','admin',1),('viewer','viewer',1)")
        conn.execute("INSERT INTO approval_tenants(id,label,owner_username,enabled) VALUES('tenant-alpha','Tenant Alpha Governor','admin',1),('tenant-beta','Tenant Beta Approver','viewer',1)")
        conn.execute("INSERT INTO approval_tenant_bots(tenant_id,bot_token,enabled) VALUES('tenant-alpha','bot-k',1),('tenant-beta','bot-t',1)")
        conn.execute("INSERT INTO approval_tenant_approvers(tenant_id,label,chat_id,enabled) VALUES('tenant-alpha','Tenant Alpha Governor','111',1),('tenant-beta','Tenant Beta Approver','222',1)")
        conn.execute("INSERT INTO approval_tenant_agent_acl(tenant_id,agent_id,enabled) VALUES('tenant-alpha','*',1),('tenant-beta','daily-assistant',1)")
    scoped_targets = gateway._approval_channel_rows("daily-assistant")
    if {row.get("tenant_id") for row in scoped_targets} != {"tenant-alpha"}:
        raise SystemExit(f"non-admin approval tenant leaked into scoped delivery targets: {scoped_targets}")
    all_targets = gateway._approval_channel_rows("")
    if {row.get("tenant_id") for row in all_targets} != {"tenant-alpha"}:
        raise SystemExit(f"approval channel token discovery included non-admin tenants: {all_targets}")

    import governance_policy
    policy_path = tmp / "profile-policy.json"
    policy_path.write_text(json.dumps({
        "schema_version": 2,
        "mode": "enforce",
        "operation_classes": {},
        "profiles": {
            "daily-assistant": {
                "account_alias": "workspace-secondary",
                "default_route_alias": "daily-assistant/workspace-secondary",
                "connected_account_aliases": ["workspace-primary", "workspace-secondary"],
            }
        },
        "profile_policy": {
            "daily-assistant": {
                "defaults": {"gmail.send_gmail_message": "ask"},
                "resource_overrides": {"gmail_workspace-secondary": {"gmail.send_gmail_message": "deny"}},
            }
        },
        "global_denies": [],
    }), encoding="utf-8")
    governance_policy.POLICY_PATH = policy_path
    governance_policy._POLICY_CACHE = None
    governance_policy._POLICY_MTIME = None
    resolved_resource = governance_policy.resource_for("daily-assistant", "gmail.send_gmail_message", {"token_route": "default"})
    if resolved_resource != "gmail_workspace-secondary":
        raise SystemExit(f"default route used stale connected account instead of active account_alias: {resolved_resource}")
    decision = governance_policy.classify("daily-assistant", "gmail.send_gmail_message", resolved_resource)
    if decision.get("decision") != "deny" or "resource_override" not in str(decision.get("decision_source")):
        raise SystemExit(f"Tanya Gmail send should be denied by active resource override, not escalated to approval: {decision}")

    payload = {
        "profile": "agent-a",
        "workflow_intent": "mcp.governed_google",
        "request_id": "approval-test-request",
        "client": "mcp_governed_google",
        "action": "gmail.send_gmail_message",
        "resource_alias": "requires_approval_approval",
        "reason": "test approval",
        "to": "person@example.com",
        "subject": "Approval retry test",
        "body": "offline test body",
        "token_route": "default",
    }

    blocked = gateway._governance_blocked("agent-a", dict(payload))
    approval_id = blocked.get("approval_id")
    if blocked.get("status") != "approval_required" or not approval_id:
        raise SystemExit(f"blocked request did not create approval: {blocked}")
    retry = blocked.get("retry_after_approval") or {}
    retry_payload = retry.get("retry_payload") or {}
    if retry.get("endpoint") != "/v1/governance/execute-approved" or retry.get("approval_id") != approval_id:
        raise SystemExit(f"approval response did not include executable retry envelope: {blocked}")
    for key in ["action", "resource_alias", "to", "subject", "body", "token_route", "approval_id"]:
        if key not in retry_payload:
            raise SystemExit(f"retry payload missing {key}: {retry_payload}")
    if retry_payload.get("to") != "person@example.com" or retry_payload.get("subject") != "Approval retry test":
        raise SystemExit(f"retry payload did not preserve original target values for same-session retry: {retry_payload}")
    assert_no_raw_values(gateway.APPROVAL_STORE_PATH, "person@example.com", "Approval retry test")

    try:
        gateway._approval_decide("agent-a", {"approval_id": approval_id, "decision": "approve_once"})
    except PermissionError:
        pass
    else:
        raise SystemExit("approval decision succeeded without admin secret")

    decision = gateway._approval_decide(
        "agent-a",
        {
            "approval_admin_secret": "approval-test-secret",
            "approval_id": approval_id,
            "decision": "approve_once",
            "approver": "legacy_admin",
            "ttl_seconds": 300,
        },
    )
    if decision.get("status") != "approved":
        raise SystemExit(f"approval did not succeed: {decision}")

    fake_session = FakeSession()
    setattr(gateway, "_session", lambda profile, route=None: fake_session)
    execute_payload = dict(retry_payload)
    execute_payload["request_id"] = "approval-test-retry-request"
    result = gateway._governance_execute_approved("agent-a", execute_payload)
    if result.get("status") != "executed":
        raise SystemExit(f"approved execution failed: {result}")
    if len(fake_session.calls) != 1 or fake_session.calls[0][0] != "POST" or "/messages/send" not in fake_session.calls[0][1]:
        raise SystemExit(f"unexpected fake session calls: {fake_session.calls}")

    try:
        gateway._governance_execute_approved("agent-a", execute_payload)
    except PermissionError:
        pass
    else:
        raise SystemExit("approve_once token was reusable after consumption")

    payload2 = dict(payload)
    payload2.update({
        "request_id": "approval-test-request-approve-execute",
        "to": "auto-exec@example.com",
        "subject": "Approve Execute test",
        "body": "offline approve and execute body",
    })
    blocked2 = gateway._governance_blocked("agent-a", dict(payload2))
    approval_id2 = blocked2.get("approval_id")
    if not approval_id2:
        raise SystemExit(f"approve-and-execute request did not create approval: {blocked2}")
    assert_no_raw_values(gateway.APPROVAL_STORE_PATH, "auto-exec@example.com", "Approve Execute test")
    fake_session2 = FakeSession()
    setattr(gateway, "_session", lambda profile, route=None: fake_session2)
    auto_result = gateway._approval_approve_and_execute(
        "agent-a",
        {
            "approval_admin_secret": "approval-test-secret",
            "approval_id": approval_id2,
            "approver": "legacy_admin",
            "ttl_seconds": 300,
        },
    )
    if auto_result.get("status") != "executed" or auto_result.get("execution", {}).get("status") != "executed":
        raise SystemExit(f"approve-and-execute failed: {auto_result}")
    if len(fake_session2.calls) != 1 or fake_session2.calls[0][0] != "POST" or "/messages/send" not in fake_session2.calls[0][1]:
        raise SystemExit(f"unexpected approve-and-execute fake session calls: {fake_session2.calls}")

    audit_rows = [json.loads(line) for line in gateway.AUDIT_PATH.read_text(encoding="utf-8").splitlines()]
    if not any(row.get("approval_id") == approval_id and row.get("status") == "ok" and row.get("action") == "gmail.send_gmail_message" for row in audit_rows):
        raise SystemExit("execution audit row missing")
    if not any(row.get("approval_id") == approval_id2 and row.get("status") == "ok" and row.get("action") == "gmail.send_gmail_message" for row in audit_rows):
        raise SystemExit("approve-and-execute audit row missing")

    payload3 = dict(payload)
    payload3.update({
        "request_id": "approval-test-expired",
        "to": "expired@example.com",
        "subject": "Expired test",
        "body": "offline expired body",
    })
    setattr(gateway, "APPROVAL_DEFAULT_TTL_SECONDS", -1)
    blocked3 = gateway._governance_blocked("agent-a", dict(payload3))
    approval_id3 = blocked3.get("approval_id")
    expired = gateway._approval_state().get(approval_id3, {})
    if expired.get("state") != "expired":
        raise SystemExit(f"expired approval did not render as expired: {expired}")
    try:
        gateway._approval_approve_and_execute(
            "agent-a",
            {"approval_admin_secret": "approval-test-secret", "approval_id": approval_id3, "approver": "legacy_admin"},
        )
    except (PermissionError, ValueError):
        pass
    else:
        raise SystemExit("expired approval was executable")
    setattr(gateway, "APPROVAL_DEFAULT_TTL_SECONDS", 900)

    payload4 = dict(payload)
    payload4.update({
        "request_id": "approval-test-telegram-callback",
        "to": "telegram@example.com",
        "subject": "Telegram callback test",
        "body": "offline telegram body",
    })
    blocked4 = gateway._governance_blocked("agent-a", dict(payload4))
    approval_id4 = blocked4.get("approval_id")
    fake_session4 = FakeSession()
    setattr(gateway, "_session", lambda profile, route=None: fake_session4)
    telegram_callback_posts = []
    class FakeTelegramCallbackResponse:
        status_code = 200
        content = b'{"ok":true}'
        ok = True
        def json(self):
            return {"ok": True}
    def fake_telegram_callback_post(url, **kwargs):
        telegram_callback_posts.append((url, kwargs))
        return FakeTelegramCallbackResponse()
    old_requests_post_cb = gateway.requests.post
    old_bot_for_chat_cb = gateway._telegram_bot_token_for_chat
    setattr(gateway.requests, "post", fake_telegram_callback_post)
    setattr(gateway, "_telegram_bot_token_for_chat", lambda chat_id: "bot-token")
    cb_token = gateway._approval_callback_token(approval_id4, "approve_once")
    try:
        callback_result = gateway._telegram_handle_update(
            {
                "callback_query": {
                    "id": "cb-test",
                    "data": f"gg:a:{approval_id4}:{cb_token}",
                    "from": {"username": "legacy_admin"},
                    "message": {"message_id": 1, "chat": {"id": "123"}},
                }
            },
            {"token": [gateway._approval_webhook_token()]},
        )
    finally:
        setattr(gateway.requests, "post", old_requests_post_cb)
        setattr(gateway, "_telegram_bot_token_for_chat", old_bot_for_chat_cb)
    if callback_result.get("status") != "ok" or callback_result.get("result", {}).get("status") != "executed":
        raise SystemExit(f"telegram callback did not approve+execute: {callback_result}")
    if len(fake_session4.calls) != 1 or "/messages/send" not in fake_session4.calls[0][1]:
        raise SystemExit(f"unexpected telegram fake session calls: {fake_session4.calls}")
    edit_payloads = [kwargs.get("json") or {} for url, kwargs in telegram_callback_posts if url.endswith("/editMessageText")]
    if not edit_payloads:
        raise SystemExit(f"telegram callback did not edit the original message: {telegram_callback_posts}")
    if edit_payloads[-1].get("reply_markup") != {"inline_keyboard": []}:
        raise SystemExit(f"telegram callback did not remove approval buttons: {edit_payloads[-1]}")
    if "approval status: approved and executed" not in str(edit_payloads[-1].get("text") or "").lower():
        raise SystemExit(f"telegram callback did not replace text with execution status: {edit_payloads[-1]}")

    payload5 = dict(payload)
    payload5.update({
        "request_id": "approval-test-workspace-tool",
        "action": "calendar.manage_event",
        "resource_alias": "primary_calendar",
        "_gateway_path": "/v1/tools/manage_event",
        "_tool": "manage_event",
        "summary": "Approved tool event",
        "start": "2026-07-13T10:00:00-05:00",
        "end": "2026-07-13T10:30:00-05:00",
        "calendar": "primary",
    })
    blocked5 = gateway._governance_blocked("agent-a", dict(payload5))
    approval_id5 = blocked5.get("approval_id")
    retry5 = (blocked5.get("retry_after_approval") or {}).get("retry_payload") or {}
    if retry5.get("_gateway_path") != "/v1/tools/manage_event" or retry5.get("_tool") != "manage_event":
        raise SystemExit(f"approved retry payload lost original route/tool: {retry5}")
    fake_session5 = FakeSession()
    setattr(gateway, "_session", lambda profile, route=None: fake_session5)
    auto_result5 = gateway._approval_approve_and_execute(
        "agent-a",
        {"approval_admin_secret": "approval-test-secret", "approval_id": approval_id5, "approver": "legacy_admin"},
    )
    if auto_result5.get("status") != "executed" or len(fake_session5.calls) != 1 or fake_session5.calls[0][0] != "POST" or "/calendar/v3/calendars/primary/events" not in fake_session5.calls[0][1]:
        raise SystemExit(f"approved workspace tool did not execute original call: {auto_result5} {fake_session5.calls}")
    if gateway._approval_state().get(approval_id5, {}).get("state") != "consumed":
        raise SystemExit(f"approved workspace tool was not consumed: {gateway._approval_state().get(approval_id5)}")

    payload_concurrent = dict(payload)
    payload_concurrent.update({"request_id": "approval-test-concurrency", "to": "race@example.com", "subject": "Race", "body": "Race body"})
    blocked_concurrent = gateway._governance_blocked("agent-a", dict(payload_concurrent))
    approval_concurrent = blocked_concurrent.get("approval_id")
    fake_session_concurrent = FakeSession()
    setattr(gateway, "_session", lambda profile, route=None: fake_session_concurrent)
    concurrent_results: list[tuple[str, Any]] = []
    def run_concurrent_execute():
        try:
            concurrent_results.append(("ok", gateway._approval_approve_and_execute("agent-a", {"approval_admin_secret": "approval-test-secret", "approval_id": approval_concurrent, "approver": "legacy_admin"})))
        except Exception as exc:
            concurrent_results.append(("err", type(exc).__name__))
    workers = [threading.Thread(target=run_concurrent_execute) for _ in range(20)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=5)
    if len([item for item in concurrent_results if item[0] == "ok"]) != 1 or len(fake_session_concurrent.calls) != 1 or gateway._approval_state().get(approval_concurrent, {}).get("state") != "consumed":
        raise SystemExit(f"concurrent approve-and-execute was not exactly-once: {concurrent_results} {fake_session_concurrent.calls} {gateway._approval_state().get(approval_concurrent)}")
    with sqlite3.connect(gateway.APPROVAL_DB_PATH) as claim_conn:
        db_state = claim_conn.execute("SELECT state, COUNT(*) FROM approvals WHERE approval_id=? GROUP BY state", (approval_concurrent,)).fetchone()
        claimed_count = claim_conn.execute("SELECT COUNT(*) FROM approval_events WHERE approval_id=? AND event='claimed'", (approval_concurrent,)).fetchone()[0]
    if db_state != ("consumed", 1) or claimed_count != 1:
        raise SystemExit(f"SQLite approval claim was not exactly-once: state={db_state} claimed_events={claimed_count}")

    old_max_body = gateway.MAX_JSON_BODY_BYTES
    setattr(gateway, "MAX_JSON_BODY_BYTES", 8)
    server_size = ThreadingHTTPServer(("127.0.0.1", 0), gateway.Handler)
    thread_size = threading.Thread(target=server_size.serve_forever, daemon=True)
    thread_size.start()
    try:
        try:
            urllib.request.urlopen(urllib.request.Request(f"http://127.0.0.1:{server_size.server_port}/v1/google/request", data=b'{"too":"large"}', headers={"Authorization": "Bearer missing", "Content-Type": "application/json"}, method="POST"), timeout=5)
        except urllib.error.HTTPError as exc:
            if exc.code != 413:
                raise SystemExit(f"oversized gateway request returned wrong status: {exc.code} {exc.read().decode('utf-8')}")
        else:
            raise SystemExit("oversized gateway request was accepted")
    finally:
        server_size.shutdown()
        thread_size.join(timeout=5)
        setattr(gateway, "MAX_JSON_BODY_BYTES", old_max_body)

    payload6 = dict(payload)
    payload6.update({
        "request_id": "approval-test-http-admin-gmail",
        "profile": "daily-assistant",
        "action": "gmail.send_gmail_message",
        "resource_alias": "gmail_send",
        "to": "person@example.com",
        "subject": "Test",
        "body": "Body",
    })
    payload6.pop("token_route", None)
    blocked6 = gateway._governance_blocked("daily-assistant", dict(payload6))
    approval_id6 = blocked6.get("approval_id")
    os.environ["GOOGLE_GOVERNANCE_API_TOKENS"] = json.dumps({"admin-token": ["*"]})
    fake_session6 = FakeSession()
    setattr(gateway, "_session", lambda profile, route=None: fake_session6)
    server = ThreadingHTTPServer(("127.0.0.1", 0), gateway.Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/v1/governance/approve-and-execute",
            data=json.dumps({"approval_admin_secret": "approval-test-secret", "approval_id": approval_id6, "approver": "ui"}).encode("utf-8"),
            headers={"Authorization": "Bearer admin-token", "Content-Type": "application/json"},
            method="POST",
        )
        http_result6 = json.loads(urllib.request.urlopen(req, timeout=5).read().decode("utf-8") or "{}")
    finally:
        server.shutdown()
        thread.join(timeout=5)
        os.environ.pop("GOOGLE_GOVERNANCE_API_TOKENS", None)
    if http_result6.get("status") != "executed" or http_result6.get("profile") != "daily-assistant" or not fake_session6.calls:
        raise SystemExit(f"HTTP approval-admin approve-and-execute failed: {http_result6} {fake_session6.calls}")
    if gateway._approval_state().get(approval_id6, {}).get("state") != "consumed":
        raise SystemExit(f"HTTP approval-admin request was not consumed: {gateway._approval_state().get(approval_id6)}")

    telegram_posts = []
    class FakeTelegramResponse:
        status_code = 200
        content = b'{"ok":true}'
        ok = True
        def json(self):
            return {"ok": True}
    def fake_telegram_post(url, **kwargs):
        telegram_posts.append((url, kwargs))
        return FakeTelegramResponse()
    old_requests_post = gateway.requests.post
    old_channel_rows = gateway._approval_channel_rows
    old_default_bot = gateway._approval_telegram_bot_token
    try:
        setattr(gateway.requests, "post", fake_telegram_post)
        setattr(gateway, "_approval_channel_rows", lambda profile: [{"chat_id": "12345", "label": "test-chat", "button_base_url": "", "bot_token": "bot-token"}])
        setattr(gateway, "_approval_telegram_bot_token", lambda: "bot-token")
        gateway._approval_notify_telegram({
            "approval_id": "gog-buttonfmt",
            "profile": "daily-assistant",
            "action": "gmail.send_gmail_message",
            "resource_alias": "gmail_send",
            "reason": "button formatting test",
            "expires_at": "2026-07-13T19:00:00+00:00",
            "safe_metadata": {"token_route": "default"},
        })
    finally:
        setattr(gateway.requests, "post", old_requests_post)
        setattr(gateway, "_approval_channel_rows", old_channel_rows)
        setattr(gateway, "_approval_telegram_bot_token", old_default_bot)
    send_payloads = [kwargs.get("json") or {} for url, kwargs in telegram_posts if url.endswith("/sendMessage")]
    if not send_payloads:
        raise SystemExit(f"telegram notification did not send: {telegram_posts}")
    keyboard = (send_payloads[-1].get("reply_markup") or {}).get("inline_keyboard") or []
    labels = [button.get("text") for row in keyboard for button in row]
    if labels != ["✅  Approve & Execute", "❌  Deny"]:
        raise SystemExit(f"telegram approval button labels wrong: {labels}")

    audit_rows = [json.loads(line) for line in gateway.AUDIT_PATH.read_text(encoding="utf-8").splitlines()]
    if not any(row.get("approval_id") == approval_id4 and row.get("status") == "ok" and row.get("action") == "gmail.send_gmail_message" for row in audit_rows):
        raise SystemExit("telegram callback execution audit row missing")

    print(json.dumps({"status": "PASS", "approval_id": approval_id, "approve_execute_id": approval_id2, "expired_id": approval_id3, "telegram_callback_id": approval_id4, "store": str(gateway.APPROVAL_STORE_PATH), "audit_rows": len(audit_rows)}, indent=2))


if __name__ == "__main__":
    main()
