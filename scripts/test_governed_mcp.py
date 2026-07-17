#!/usr/bin/env python3
"""Governed Google MCP tests.

These tests avoid Gmail/calendar/Drive mutations. They verify:
- MCP stdio discovery exposes the complete governed Workspace schema.
- Dangerous/externalizing operations are represented by tools and wired to the
  approval-required helper instead of direct Google execution.
- A real agent-a Sheets read routes through the unified gateway.
- Gateway action classification covers Calendar, Gmail, Drive, Docs, Sheets,
  Slides, Contacts, and approval-blocked surfaces.
"""
from __future__ import annotations

import asyncio
import ast
import hashlib
import importlib.util
import json
import os
import sqlite3
import tempfile
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SCRIPT_DIR = Path(__file__).resolve().parent
if (SCRIPT_DIR / "governed_google_mcp.py").exists():
    # Runtime install: all executable modules are copied into one runtime dir.
    PROJECT_DIR = SCRIPT_DIR.parent
    MCP_SCRIPT = SCRIPT_DIR / "governed_google_mcp.py"
    GATEWAY_SCRIPT = SCRIPT_DIR / "unified_google_gateway.py"
    CATALOG_DIR = SCRIPT_DIR
else:
    # Source checkout: scripts live under <project>/scripts/.
    PROJECT_DIR = SCRIPT_DIR.parent
    MCP_SCRIPT = PROJECT_DIR / "scripts" / "governed_google_mcp.py"
    GATEWAY_SCRIPT = PROJECT_DIR / "scripts" / "unified_google_gateway.py"
    CATALOG_DIR = PROJECT_DIR / "scripts"
import sys
sys.path.insert(0, str(CATALOG_DIR))
from google_workspace_action_catalog import workspace_catalog_tool_names

LEGACY_GOOGLE_TOOLS = {
    "google_calendar_list",
    "google_calendar_get",
    "google_calendar_create",
    "google_calendar_update",
    "google_calendar_delete",
    "google_calendar_freebusy",
    "google_gmail_search",
    "google_gmail_get",
    "google_gmail_list_attachments",
    "google_gmail_get_attachment",
    "google_gmail_create_draft",
    "google_gmail_send_draft",
    "google_gmail_modify_labels",
    "google_drive_search",
    "google_drive_get",
    "google_drive_export",
    "google_drive_copy",
    "google_drive_upload_metadata",
    "google_drive_share",
    "google_drive_delete",
    "google_docs_get",
    "google_docs_create",
    "google_docs_batch_update",
    "google_docs_export",
    "google_sheets_get",
    "google_sheets_update",
    "google_sheets_append",
    "google_sheets_batch_update",
    "google_slides_get",
    "google_slides_create",
    "google_slides_batch_update",
    "google_slides_export",
    "google_contacts_search",
}
EXPECTED_TOOLS = set(workspace_catalog_tool_names())

ACTION_CASES = {
    ("GET", "https://www.googleapis.com/calendar/v3/calendars/primary/events/evt"): ("calendar.get", "calendar_primary"),
    ("PATCH", "https://www.googleapis.com/calendar/v3/calendars/primary/events/evt"): ("calendar.update", "calendar_primary"),
    ("POST", "https://www.googleapis.com/calendar/v3/freeBusy"): ("calendar.freebusy", "calendar_primary"),
    ("GET", "https://gmail.googleapis.com/gmail/v1/users/me/messages/msg"): ("gmail.get", "gmail_inbox"),
    ("GET", "https://gmail.googleapis.com/gmail/v1/users/me/messages/msg/attachments/att"): ("gmail.attachments.get", "gmail_inbox"),
    ("POST", "https://gmail.googleapis.com/gmail/v1/users/me/messages/msg/modify"): ("gmail.modify", "gmail_inbox"),
    ("POST", "https://www.googleapis.com/drive/v3/files/file/copy"): ("drive.copy", "drive_any"),
    ("POST", "https://www.googleapis.com/drive/v3/files"): ("drive.create", "drive_any"),
    ("POST", "https://docs.googleapis.com/v1/documents"): ("docs.create", "docs_unknown"),
    ("POST", "https://docs.googleapis.com/v1/documents/doc:batchUpdate"): ("docs.update", "docs_unknown"),
    ("POST", "https://sheets.googleapis.com/v4/spreadsheets/example-sheet-id:batchUpdate"): ("sheets.update", "sheet_example_tracker"),
    ("GET", "https://slides.googleapis.com/v1/presentations/pres"): ("slides.get", "slides_unknown"),
    ("POST", "https://slides.googleapis.com/v1/presentations"): ("slides.create", "slides_unknown"),
    ("POST", "https://slides.googleapis.com/v1/presentations/pres:batchUpdate"): ("slides.update", "slides_unknown"),
    ("GET", "https://people.googleapis.com/v1/people/me/connections"): ("contacts.search", "contacts_personal"),
}


def _load_gateway_module():
    import sys
    sys.path.insert(0, str(PROJECT_DIR / "scripts"))
    spec = importlib.util.spec_from_file_location("unified_google_gateway_for_test", GATEWAY_SCRIPT)
    if spec is None or spec.loader is None:
        raise SystemExit("could not load gateway module spec")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    setattr(module, "AUDIT_PATH", Path(tempfile.gettempdir()) / "google-workspace-governance-governed-test-audit.jsonl")
    setattr(module, "APPROVAL_STORE_PATH", Path(tempfile.gettempdir()) / "google-workspace-governance-governed-test-approvals.jsonl")
    return module


def _install_test_workspace_token_db(gateway) -> None:
    db_path = Path(tempfile.gettempdir()) / "google-workspace-governance-governed-test-tokens.sqlite"
    if db_path.exists():
        db_path.unlink()
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE workspace_tokens (
                id TEXT PRIMARY KEY,
                account_alias TEXT NOT NULL,
                bundle TEXT NOT NULL,
                email TEXT NOT NULL DEFAULT '',
                token_json TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}',
                scopes_json TEXT NOT NULL DEFAULT '[]',
                status TEXT NOT NULL DEFAULT 'connected',
                revoked_at TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            INSERT INTO workspace_tokens(id, account_alias, bundle, email, token_json, metadata_json, scopes_json, status, revoked_at)
            VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                "workspace-shared/workspace-full.json",
                "workspace-shared",
                "workspace-full.json",
                "workspace-shared@gmail.com",
                "{}",
                json.dumps({"token_label": "Shared Workspace", "account_label": "Shared Workspace"}),
                "[]",
                "connected",
                "",
            ),
        )
        conn.execute(
            """
            CREATE TABLE api_tokens (
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
            CREATE TABLE agent_tokens (
                id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                token_hash TEXT NOT NULL UNIQUE,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                created_by TEXT NOT NULL DEFAULT '',
                revoked_at TEXT NOT NULL DEFAULT '',
                last_used_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        conn.commit()
    setattr(gateway, "TOKEN_DB_PATH", db_path)
    policy_path = Path(tempfile.gettempdir()) / "google-workspace-governance-governed-test-policy.json"
    policy_path.write_text(json.dumps({
        "schema_version": 3,
        "mode": "enforce",
        "unknown_profile_default": "deny",
        "unknown_resource_default": "deny",
        "accounts": {
            "workspace-shared": {"current_profile_routes": {"agent-b": "agent-b/workspace-shared"}},
            "workspace-other": {"current_profile_routes": {"agent-a": "agent-a/workspace-other"}},
        },
        "profiles": {
            "agent-b": {"account_alias": "workspace-shared", "default_route_alias": "agent-b/workspace-shared", "connected_account_aliases": ["workspace-shared"]},
            "agent-a": {"account_alias": "workspace-other", "default_route_alias": "agent-a/workspace-other", "connected_account_aliases": ["workspace-other"]},
        },
        "profile_policy": {"agent-a": {"defaults": {}, "resource_overrides": {}}, "agent-b": {"defaults": {}, "resource_overrides": {}}},
        "operation_classes": {},
        "global_denies": [],
    }), encoding="utf-8")
    import governance_policy
    governance_policy.POLICY_PATH = policy_path
    governance_policy._POLICY_CACHE = None
    governance_policy._POLICY_MTIME = None


def _tool_decorated_function_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute) and decorator.func.attr == "tool":
                names.add(node.name)
            elif isinstance(decorator, ast.Attribute) and decorator.attr == "tool":
                names.add(node.name)
    return names


def assert_no_legacy_google_tools_exposed() -> None:
    tree = ast.parse(MCP_SCRIPT.read_text(encoding="utf-8"))
    exposed = _tool_decorated_function_names(tree)
    leaked = sorted(exposed & LEGACY_GOOGLE_TOOLS)
    if leaked:
        raise SystemExit(f"legacy google_* MCP tools are still exposed: {leaked}")


def assert_gateway_action_mapping() -> None:
    gateway = _load_gateway_module()
    _install_test_workspace_token_db(gateway)
    if gateway._dynamic_token_id("agent-b", "Shared Workspace") != "workspace-shared/workspace-full.json":
        raise SystemExit("token display name did not resolve to SQLite workspace token")
    if gateway._dynamic_token_id("agent-a", "Shared Workspace") is not None:
        raise SystemExit("agent-a resolved another tenant's Shared Workspace display name")
    if gateway._dynamic_token_id("agent-a", "agent-b/Shared Workspace") is not None:
        raise SystemExit("profile-qualified foreign route was accepted")
    if gateway._dynamic_token_id("agent-b", "agent-b/Shared Workspace") != "workspace-shared/workspace-full.json":
        raise SystemExit("profile-scoped token display name did not resolve to SQLite workspace token")
    route_payload = {"token_route": "Shared Workspace"}
    gateway._canonicalize_payload_token_route("agent-b", route_payload)
    if route_payload.get("token_route") != "agent-b/workspace-shared" or route_payload.get("token_route_requested") != "Shared Workspace":
        raise SystemExit(f"token route was not canonicalized from display name: {route_payload}")
    if gateway.resource_for("agent-b", "gmail.search_gmail_messages", route_payload) != "gmail_workspace_shared":
        raise SystemExit(f"canonical display-name route did not map to resource alias: {route_payload}")
    unknown_decision = gateway.classify("agent-b", "gmail.search_gmail_messages", "gmail_unmapped_workspace")
    if unknown_decision.get("decision") != "deny" or unknown_decision.get("decision_source") != "unknown_resource_default":
        raise SystemExit(f"unknown_resource_default did not deny unmapped resource before defaults/classes: {unknown_decision}")
    for case, expected in ACTION_CASES.items():
        got = gateway._google_request_action(*case)
        if got != expected:
            raise SystemExit(f"action mapping mismatch for {case}: got {got}, expected {expected}")
    route_cases = [
        ("agent-b", "gmail.search", {"token_route": "agent-b/workspace_shared"}, "gmail_workspace_shared"),
        ("agent-b", "docs.get", {"token_route": "agent-b/workspace-shared"}, "docs_workspace_shared_workspace"),
        ("agent-b", "sheets.get", {"token_route": "agent-b/workspace-shared"}, "sheets_workspace_shared_workspace"),
        ("agent-b", "calendar.list", {"token_route": "agent-b/workspace-shared"}, "calendar_workspace_shared_primary"),
        ("agent-b", "drive.search", {"token_route": "agent-b/workspace-shared"}, "drive_workspace_shared_workspace"),
        ("agent-b", "contacts.search", {"token_route": "agent-b/workspace-shared"}, "contacts_workspace_shared"),
    ]
    for profile, action, payload, expected in route_cases:
        got = gateway.resource_for(profile, action, payload)
        if got != expected:
            raise SystemExit(f"route resource mismatch for {(profile, action, payload)}: got {got}, expected {expected}")
    typed_policy_cases = [
        ("/v1/docs/get", "docs.get_doc_content", {"document_id": "doc", "token_route": "agent-b/workspace-shared"}, "docs_workspace_shared_workspace"),
        ("/v1/calendar/update", "calendar.manage_event", {"event_id": "evt", "token_route": "agent-b/workspace-shared"}, "calendar_workspace_shared_primary"),
        ("/v1/sheets/update", "sheets.modify_sheet_values", {"spreadsheet_id": "sheet", "range_a1": "A1", "token_route": "agent-b/workspace-shared"}, "sheets_workspace_shared_workspace"),
    ]
    for path, expected_action, payload, expected_resource in typed_policy_cases:
        policy_action, policy_resource = gateway._route_policy_context(path, "agent-b", payload)
        if (policy_action, policy_resource) != (expected_action, expected_resource):
            raise SystemExit(f"typed policy context mismatch for {path}: {(policy_action, policy_resource)}")
    blocked = gateway._governance_blocked(
        "agent-a",
        {"action": "drive.delete", "resource_alias": "drive_any", "reason": "test", "file_id_sha256": "abc", "request_id": "test-request"},
    )
    if blocked.get("status") != "approval_required" or blocked.get("action") != "drive.delete":
        raise SystemExit(f"blocked route returned unexpected payload: {blocked}")


def assert_gateway_two_token_identity() -> None:
    gateway = _load_gateway_module()
    _install_test_workspace_token_db(gateway)
    bridge_token = "bridge-test-token"
    agent_token = "agent-b-token"
    blocked_agent_token = "agent-c-token"
    bridge_hash = hashlib.sha256(bridge_token.encode("utf-8")).hexdigest()
    agent_hash = hashlib.sha256(agent_token.encode("utf-8")).hexdigest()
    blocked_agent_hash = hashlib.sha256(blocked_agent_token.encode("utf-8")).hexdigest()
    with sqlite3.connect(gateway.TOKEN_DB_PATH) as conn:
        conn.execute(
            "INSERT INTO api_tokens(id,label,token_hash,allowed_profiles_json) VALUES(?,?,?,?)",
            ("gat_test", "Bridge token", bridge_hash, json.dumps(["agent-b"])),
        )
        conn.execute(
            "INSERT INTO agent_tokens(id,agent_id,label,token_hash) VALUES(?,?,?,?)",
            ("agt_test", "agent-b", "Agent B", agent_hash),
        )
        conn.execute(
            "INSERT INTO agent_tokens(id,agent_id,label,token_hash) VALUES(?,?,?,?)",
            ("agt_blocked", "agent-c", "Agent C", blocked_agent_hash),
        )
        conn.commit()
    claims = gateway._verify_jwt(f"Bearer {bridge_token}")
    if claims.get("_profile") != "agent-b" or claims.get("_allowed_profiles") != ["agent-b"]:
        raise SystemExit(f"bridge claims did not preserve allowed agent scope: {claims}")
    profile, identity = gateway._resolve_agent_identity(
        {"X-Google-Governance-Agent-Token": agent_token},
        claims,
        {"profile": "agent-b"},
    )
    if profile != "agent-b" or identity.get("identity_mode") != "agent_token" or identity.get("agent_token_id") != "agt_test":
        raise SystemExit(f"agent token did not resolve canonical identity: {(profile, identity)}")
    try:
        gateway._resolve_agent_identity(
            {"X-Google-Governance-Agent-Token": blocked_agent_token},
            claims,
            {"profile": "agent-c"},
        )
    except PermissionError:
        pass
    else:
        raise SystemExit("bridge token was allowed to present an unauthorized agent token")
    try:
        gateway._resolve_agent_identity(
            {"X-Google-Governance-Agent-Token": agent_token},
            claims,
            {"profile": "agent-c"},
        )
    except ValueError:
        pass
    else:
        raise SystemExit("request body was allowed to spoof a different profile than the agent token")
    os.environ["GOOGLE_GOVERNANCE_AGENT_TOKEN_MODE"] = "strict"
    try:
        try:
            gateway._resolve_agent_identity({}, claims, {"profile": "agent-b"})
        except ValueError:
            pass
        else:
            raise SystemExit("strict mode accepted a request without an agent token")
    finally:
        os.environ.pop("GOOGLE_GOVERNANCE_AGENT_TOKEN_MODE", None)


def assert_gateway_upstream_payload_adapters() -> None:
    gateway = _load_gateway_module()
    calls: list[dict[str, object]] = []

    def fake_typed_google_request(profile, action, payload, method, url, *, params=None, json_body=None, data=None):
        call = {
            "profile": profile,
            "action": action,
            "payload": payload,
            "method": method,
            "url": url,
            "params": params or {},
            "json_body": json_body,
            "data": data,
        }
        calls.append(call)
        return call

    setattr(gateway, "_typed_google_request", fake_typed_google_request)
    setattr(gateway, "_session", lambda profile, route=None: object())

    delete_call = gateway._workspace_tool_execute("agent-a", "manage_event", {"action": "delete", "event_id": "evt-1", "calendar_id": "primary"})
    if delete_call["method"] != "DELETE" or not str(delete_call["url"]).endswith("/events/evt-1"):
        raise SystemExit(f"manage_event delete did not route to Calendar DELETE: {delete_call}")

    update_call = gateway._workspace_tool_execute("agent-a", "manage_event", {"action": "update", "event_id": "evt-2", "calendar_id": "primary", "start_time": "2026-07-12T10:00:00-05:00", "end_time": "2026-07-12T11:00:00-05:00", "summary": "Updated"})
    body = update_call.get("json_body") or {}
    if update_call["method"] != "PATCH" or body.get("start", {}).get("dateTime") != "2026-07-12T10:00:00-05:00" or body.get("end", {}).get("dateTime") != "2026-07-12T11:00:00-05:00":
        raise SystemExit(f"manage_event update did not adapt upstream start_time/end_time: {update_call}")

    sheet_get = gateway._workspace_tool_execute("agent-a", "read_sheet_values", {"spreadsheet_id": "sheet-1", "range_name": "Sheet1!A1:B2"})
    if sheet_get["method"] != "GET" or not str(sheet_get["url"]).endswith("/values/Sheet1%21A1%3AB2"):
        raise SystemExit(f"read_sheet_values did not adapt upstream range_name: {sheet_get}")

    sheet_clear = gateway._workspace_tool_execute("agent-a", "modify_sheet_values", {"spreadsheet_id": "sheet-1", "range_name": "Sheet1!A1", "clear_values": True})
    if sheet_clear["method"] != "POST" or not str(sheet_clear["url"]).endswith("/values/Sheet1%21A1:clear"):
        raise SystemExit(f"modify_sheet_values clear_values did not route to clear: {sheet_clear}")

    drive_revoke = gateway._workspace_tool_execute("agent-a", "manage_drive_access", {"file_id": "file-1", "action": "revoke", "permission_id": "perm-1"})
    if drive_revoke["method"] != "DELETE" or not str(drive_revoke["url"]).endswith("/permissions/perm-1"):
        raise SystemExit(f"manage_drive_access action=revoke did not route to permission DELETE: {drive_revoke}")


def assert_gateway_observability_fields() -> None:
    gateway = _load_gateway_module()
    _install_test_workspace_token_db(gateway)
    gateway.AUDIT_PATH.write_text("", encoding="utf-8")
    gateway._AUDIT_TOTAL.clear()
    gateway._AUDIT_DIM_TOTAL.clear()
    gateway._LATENCY_SUM_MS.clear()
    gateway._LATENCY_COUNT.clear()
    payload = {
        "request_id": "req-observe-1",
        "trace_id": "trace-observe-1",
        "token_route": "agent-b/workspace-shared",
        "agent_framework": "mcp",
        "principal_assertion": "raw-principal-assertion-must-not-appear",
        "session_id": "raw-session-id-must-not-appear",
    }
    gateway._audit_observed("agent-b", "gmail.send_gmail_message", "approval_required", payload, "gmail_workspace_shared")
    rows = [json.loads(line) for line in gateway.AUDIT_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(rows) != 1:
        raise SystemExit(f"expected one observability audit row, got {rows}")
    row = rows[0]
    required = {
        "timestamp", "agent", "framework", "gateway_principal", "google_account", "service", "operation", "resource",
        "requested_scopes", "granted_scopes", "policy", "decision", "decision_reason", "risk_level", "approval_requirement",
        "request_id", "trace_id", "principal_assertion_fingerprint", "session_id", "workspace_token_fingerprint",
    }
    missing = sorted(required - set(row))
    if missing:
        raise SystemExit(f"observability audit row missing fields: {missing}; row={row}")
    encoded = json.dumps(row, sort_keys=True)
    if "raw-principal-assertion" in encoded or "raw-session-id" in encoded:
        raise SystemExit(f"observability audit row leaked a raw assertion/session value: {row}")
    if row.get("framework") != "mcp" or row.get("google_account") != "workspace-shared" or row.get("risk_level") != "high":
        raise SystemExit(f"observability audit row had unexpected dimensions: {row}")
    metrics = gateway._metrics_text()
    for expected in ["google_workspace_governance_requests_total", 'framework="mcp"', 'google_account="workspace-shared"', 'risk_level="high"']:
        if expected not in metrics:
            raise SystemExit(f"observability metric missing {expected}: {metrics}")


def assert_mcp_module_static_shape() -> dict[str, object]:
    source = MCP_SCRIPT.read_text(encoding="utf-8")
    missing = [name for name in EXPECTED_TOOLS if f"def {name}" not in source and f"async def {name}" not in source]
    if missing:
        raise SystemExit(f"missing MCP tool definitions: {sorted(missing)}")
    if "gateway_post" not in source:
        raise SystemExit("MCP wrapper no longer appears to route through the gateway")
    if 'gateway_post("/v1/google/request"' in source or "return google_request(" in source:
        raise SystemExit("MCP wrapper still routes a tool through generic /v1/google/request")
    gateway_source = GATEWAY_SCRIPT.read_text(encoding="utf-8")
    route_missing = [name for name in workspace_catalog_tool_names() if f'"/v1/tools/{name}"' not in gateway_source]
    if route_missing:
        raise SystemExit(f"missing typed gateway routes for catalog tools: {route_missing[:20]}")
    return {"tools_static_checked": len(EXPECTED_TOOLS), "catalog_routes_checked": len(workspace_catalog_tool_names())}


async def main() -> None:
    assert_no_legacy_google_tools_exposed()
    assert_gateway_action_mapping()
    assert_gateway_two_token_identity()
    assert_gateway_upstream_payload_adapters()
    assert_gateway_observability_fields()
    static = assert_mcp_module_static_shape()
    print(json.dumps({"status": "PASS", "legacy_google_tools_exposed": 0, "action_mapping_cases": len(ACTION_CASES), **static}, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
