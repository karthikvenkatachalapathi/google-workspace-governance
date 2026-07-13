#!/usr/bin/env python3
"""Approval workflow tests for the Google governance gateway.

Tests stay local/offline: no Google API call is made. The high-risk executor is
monkeypatched through _session with a fake requests-like object.
"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
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
    payload = {
        "profile": "reasoning",
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

    blocked = gateway._governance_blocked("reasoning", dict(payload))
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
        gateway._approval_decide("reasoning", {"approval_id": approval_id, "decision": "approve_once"})
    except PermissionError:
        pass
    else:
        raise SystemExit("approval decision succeeded without admin secret")

    decision = gateway._approval_decide(
        "reasoning",
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
    result = gateway._governance_execute_approved("reasoning", execute_payload)
    if result.get("status") != "executed":
        raise SystemExit(f"approved execution failed: {result}")
    if len(fake_session.calls) != 1 or fake_session.calls[0][0] != "POST" or "/messages/send" not in fake_session.calls[0][1]:
        raise SystemExit(f"unexpected fake session calls: {fake_session.calls}")

    try:
        gateway._governance_execute_approved("reasoning", execute_payload)
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
    blocked2 = gateway._governance_blocked("reasoning", dict(payload2))
    approval_id2 = blocked2.get("approval_id")
    if not approval_id2:
        raise SystemExit(f"approve-and-execute request did not create approval: {blocked2}")
    assert_no_raw_values(gateway.APPROVAL_STORE_PATH, "auto-exec@example.com", "Approve Execute test")
    fake_session2 = FakeSession()
    setattr(gateway, "_session", lambda profile, route=None: fake_session2)
    auto_result = gateway._approval_approve_and_execute(
        "reasoning",
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
    blocked3 = gateway._governance_blocked("reasoning", dict(payload3))
    approval_id3 = blocked3.get("approval_id")
    expired = gateway._approval_state().get(approval_id3, {})
    if expired.get("state") != "expired":
        raise SystemExit(f"expired approval did not render as expired: {expired}")
    try:
        gateway._approval_approve_and_execute(
            "reasoning",
            {"approval_admin_secret": "approval-test-secret", "approval_id": approval_id3, "approver": "legacy_admin"},
        )
    except ValueError:
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
    blocked4 = gateway._governance_blocked("reasoning", dict(payload4))
    approval_id4 = blocked4.get("approval_id")
    fake_session4 = FakeSession()
    setattr(gateway, "_session", lambda profile, route=None: fake_session4)
    cb_token = gateway._approval_callback_token(approval_id4, "approve_once")
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
    if callback_result.get("status") != "ok" or callback_result.get("result", {}).get("status") != "executed":
        raise SystemExit(f"telegram callback did not approve+execute: {callback_result}")
    if len(fake_session4.calls) != 1 or "/messages/send" not in fake_session4.calls[0][1]:
        raise SystemExit(f"unexpected telegram fake session calls: {fake_session4.calls}")

    audit_rows = [json.loads(line) for line in gateway.AUDIT_PATH.read_text(encoding="utf-8").splitlines()]
    if not any(row.get("approval_id") == approval_id4 and row.get("status") == "ok" and row.get("action") == "gmail.send_gmail_message" for row in audit_rows):
        raise SystemExit("telegram callback execution audit row missing")

    print(json.dumps({"status": "PASS", "approval_id": approval_id, "approve_execute_id": approval_id2, "expired_id": approval_id3, "telegram_callback_id": approval_id4, "store": str(gateway.APPROVAL_STORE_PATH), "audit_rows": len(audit_rows)}, indent=2))


if __name__ == "__main__":
    main()
