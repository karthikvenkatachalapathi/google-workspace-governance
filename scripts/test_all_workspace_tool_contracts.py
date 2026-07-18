#!/usr/bin/env python3
"""Contract tests for every governed Google Workspace MCP tool adapter.

The gateway intentionally exposes the upstream google_workspace_mcp-style tool
surface, but executes pinned Google REST endpoints after policy/audit checks.
This test calls every catalogued tool using only MCP-wrapper parameter names and
asserts that the source gateway can construct a typed request without falling
through to generic Google request or requiring gateway-internal field names.
"""
from __future__ import annotations

import ast
import importlib.util
import json
import sys
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_DIR = SCRIPT_DIR.parent
GATEWAY_SCRIPT = SCRIPT_DIR / "unified_google_gateway.py"
sys.path.insert(0, str(SCRIPT_DIR))
from google_workspace_action_catalog import workspace_catalog_tool_names

EXPECTED_FAILURES = {
    "start_google_auth": "OAuth setup is managed by the governance UI",
}


def _load_gateway_module():
    spec = importlib.util.spec_from_file_location("unified_google_gateway_all_tools_test", GATEWAY_SCRIPT)
    if spec is None or spec.loader is None:
        raise SystemExit("could not load gateway module spec")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    setattr(module, "AUDIT_PATH", Path(tempfile.gettempdir()) / "google-workspace-governance-all-tools-audit.jsonl")
    setattr(module, "APPROVAL_STORE_PATH", Path(tempfile.gettempdir()) / "google-workspace-governance-all-tools-approvals.jsonl")
    return module


def _tool_signatures() -> dict[str, list[str]]:
    tree = ast.parse((SCRIPT_DIR / "governed_google_mcp.py").read_text(encoding="utf-8"))
    out: dict[str, list[str]] = {}
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        is_tool = any(
            (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and d.func.attr == "tool")
            or (isinstance(d, ast.Attribute) and d.attr == "tool")
            for d in node.decorator_list
        )
        if is_tool:
            out[node.name] = [arg.arg for arg in node.args.args]
    return out


def _sample_value(name: str):
    lowered = name.lower()
    if lowered in {"token_route"}:
        return "agent-a/workspace-test"
    if lowered in {"action", "operation"}:
        return "create"
    if lowered in {"is_published", "is_accepting_responses", "send_notification", "include_signature", "include_forwarded_attachments", "quote_original", "detailed", "include_attachments", "include_items_from_all_drives", "include_organizers", "copy_requires_writer_permission", "writers_can_share", "clear_values", "bold", "italic", "underline", "strikethrough", "end_of_segment", "clear_link", "small_caps", "use_default_reminders", "guests_can_modify", "guests_can_invite_others", "guests_can_see_other_guests", "allow_file_discovery", "starred", "trashed"}:
        return True
    if lowered in {"page_size", "max_results", "max_members", "num", "start", "start_index", "end_index", "rows", "columns", "font_size", "font_weight", "insert_sheet_index", "rule_index", "group_expansion_max", "calendar_expansion_max"}:
        return 1
    if lowered.endswith("ids") or lowered in {"message_ids", "thread_ids", "calendar_ids", "add_label_ids", "remove_label_ids", "attachments", "requests", "values", "table_data", "recipients"}:
        if lowered == "requests":
            return [{"updateSheetProperties": {"properties": {"sheetId": 0, "title": "Renamed"}, "fields": "title"}}]
        if lowered == "values":
            return [["value"]]
        if lowered == "table_data":
            return ["A,B", "1,2"]
        return ["item-1"]
    if lowered in {"contacts", "updates"}:
        return [{"resourceName": "people/c1", "person": {"names": [{"givenName": "Test"}]}}]
    if lowered in {"criteria", "filter_action", "conference_data", "properties", "settings", "type", "gradient_points", "condition_values"}:
        return {"name": "value"}
    if lowered in {"files"}:
        return [{"name": "Code", "type": "SERVER_JS", "source": "function test(){}"}]
    if lowered in {"parameters"}:
        return []
    if lowered in {"sheet_names"}:
        return ["Sheet A", "Sheet B"]
    if "time" in lowered or lowered in {"due", "completed_min", "completed_max", "updated_min", "due_min", "due_max"}:
        return "2026-07-17T00:00:00Z"
    if "color" in lowered:
        return "#ffffff"
    if lowered in {"range_name", "range_a1"}:
        return "Sheet1!A1:B2"
    if lowered in {"email", "to", "cc", "bcc", "from_email", "share_with"}:
        return "user@example.com"
    if lowered in {"query", "q"}:
        return "test"
    if lowered in {"body", "content", "text", "description", "notes", "email_message", "markdown_text"}:
        return "test content"
    if lowered in {"body_format", "format", "export_format", "mime_type", "content_mime_type", "source_format"}:
        return "text/plain"
    if lowered in {"role"}:
        return "reader"
    if lowered in {"share_type"}:
        return "user"
    # stable IDs/names
    return {
        "spreadsheet_id": "spreadsheet-1",
        "document_id": "document-1",
        "presentation_id": "presentation-1",
        "page_object_id": "page-1",
        "page_id": "page-1",
        "form_id": "form-1",
        "response_id": "response-1",
        "script_id": "script-1",
        "deployment_id": "deployment-1",
        "task_list_id": "tasklist-1",
        "tasklist_id": "tasklist-1",
        "task_id": "task-1",
        "contact_id": "people/c1",
        "resource_name": "people/c1",
        "group_id": "contactGroups/g1",
        "space_id": "spaces/AAA",
        "space_name": "spaces/AAA",
        "message_id": "message-1",
        "thread_id": "thread-1",
        "attachment_id": "attachment-1",
        "attachment_name": "spaces/AAA/messages/m1/attachments/a1",
        "message_name": "spaces/AAA/messages/m1",
        "file_id": "file-1",
        "file_name": "file.txt",
        "folder_id": "root",
        "parent_folder_id": "root",
        "name": "Test Name",
        "new_name": "Copy Name",
        "folder_name": "Folder Name",
        "title": "Test Title",
        "subject": "Subject",
        "summary": "Summary",
        "calendar_id": "primary",
        "calendar": "primary",
        "event_id": "event-1",
        "function_name": "main",
        "emoji_unicode": "👍",
        "emoji": "👍",
        "permission_id": "perm-1",
        "table_id": "table-1",
        "sheet_name": "New Sheet",
        "search_engine_id": "cx-1",
        "cx": "cx-1",
    }.get(lowered, f"{name}-value")


def _sample_payload(tool: str, args: list[str]) -> dict[str, object]:
    payload = {arg: _sample_value(arg) for arg in args}
    # Prefer safe/read-friendly operations for multi-mode tools, but ensure each route builds a concrete request.
    if tool in {"manage_gmail_label", "manage_gmail_filter", "manage_drive_access", "manage_contact", "manage_contact_group", "manage_contacts_batch", "manage_task", "manage_task_list", "manage_deployment", "manage_document_comment", "manage_spreadsheet_comment", "manage_presentation_comment", "manage_event", "manage_out_of_office", "manage_focus_time"}:
        payload["action"] = "create"
    return payload


def main() -> None:
    gateway = _load_gateway_module()
    calls: list[dict[str, object]] = []

    def fake_typed_google_request(profile, action, payload, method, url, *, params=None, json_body=None, data=None, resource_alias=None):
        call = {"tool": payload.get("_tool_under_test"), "profile": profile, "action": action, "method": method, "url": url, "params": params or {}, "json_body": json_body, "data": data}
        calls.append(call)
        return call

    setattr(gateway, "_typed_google_request", fake_typed_google_request)
    setattr(gateway, "_session", lambda profile, route=None: object())

    signatures = _tool_signatures()
    catalog = workspace_catalog_tool_names()
    missing_signature = sorted(set(catalog) - set(signatures))
    if missing_signature:
        raise SystemExit(f"catalog tools missing MCP signatures: {missing_signature}")

    failures: dict[str, str] = {}
    successes: list[str] = []
    for tool in catalog:
        payload = _sample_payload(tool, signatures[tool])
        payload["_tool_under_test"] = tool
        try:
            result = gateway._workspace_tool_execute("agent-a", tool, payload)
            if tool in EXPECTED_FAILURES:
                failures[tool] = f"expected intentional failure but got {result}"
            else:
                successes.append(tool)
        except Exception as exc:  # noqa: BLE001 - tests report exact adapter failures.
            message = f"{type(exc).__name__}: {exc}"
            if tool in EXPECTED_FAILURES and EXPECTED_FAILURES[tool] in message:
                successes.append(tool)
            else:
                failures[tool] = message

    if failures:
        print(json.dumps({"status": "FAIL", "success_count": len(successes), "failure_count": len(failures), "failures": failures}, indent=2, sort_keys=True))
        raise SystemExit(1)
    print(json.dumps({"status": "PASS", "tools_checked": len(successes), "typed_requests_observed": len(calls), "expected_intentional_failures": sorted(EXPECTED_FAILURES)}, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
