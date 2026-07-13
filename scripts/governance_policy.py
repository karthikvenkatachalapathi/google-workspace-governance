#!/usr/bin/env python3
"""Google Workspace governance policy classifier.

Standard-library only: gateway services run in a minimal venv. The profile-first policy JSON is generated from the YAML artifacts and, by default, loaded from the install folder's `.google-governance/state/policy/profile_policy.json`.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

PROJECT_BASE = Path(os.getenv("GOOGLE_GOVERNANCE_PROJECT_DIR", str(Path(__file__).resolve().parents[1])))
STATE_BASE = Path(os.getenv("GOOGLE_GOVERNANCE_STATE_DIR", str(PROJECT_BASE / ".google-governance/state")))
POLICY_PATH = Path(os.getenv(
    "GOOGLE_GOVERNANCE_POLICY_JSON",
    str(STATE_BASE / "policy/profile_policy.json"),
))

ACTION_ALIASES: dict[str, str] = {
    # Legacy compatibility-route action names -> canonical MCP catalog actions.
    "calendar.list": "calendar.get_events",
    "calendar.get": "calendar.get_events",
    "calendar.create": "calendar.manage_event",
    "calendar.update": "calendar.manage_event",
    "calendar.delete": "calendar.manage_event",
    "calendar.freebusy": "calendar.query_freebusy",
    "gmail.search": "gmail.search_gmail_messages",
    "gmail.get": "gmail.get_gmail_message_content",
    "gmail.draft": "gmail.draft_gmail_message",
    "gmail.modify": "gmail.modify_gmail_message_labels",
    "gmail.send": "gmail.send_gmail_message",
    "drive.search": "drive.search_drive_files",
    "drive.get": "drive.get_drive_file_content",
    "drive.download": "drive.get_drive_file_download_url",
    "drive.create": "drive.create_drive_file",
    "drive.create_folder": "drive.create_drive_folder",
    "drive.copy": "drive.copy_drive_file",
    "drive.update": "drive.update_drive_file",
    "drive.share": "drive.manage_drive_access",
    "drive.delete": "drive.update_drive_file",
    "docs.get": "docs.get_doc_content",
    "docs.create": "docs.create_doc",
    "docs.update": "docs.batch_update_doc",
    "docs.append": "docs.modify_doc_text",
    "sheets.get": "sheets.read_sheet_values",
    "sheets.update": "sheets.modify_sheet_values",
    "sheets.append": "sheets.append_table_rows",
    "sheets.batch_update": "sheets.format_sheet_range",
    "slides.get": "slides.get_presentation",
    "slides.create": "slides.create_presentation",
    "slides.update": "slides.batch_update_presentation",
    "contacts.search": "contacts.search_contacts",
}


def _action_candidates(action: str) -> list[str]:
    """Return canonical action plus legacy aliases accepted for old policy rows."""
    canonical = ACTION_ALIASES.get(action, action)
    candidates = [canonical]
    if action != canonical:
        candidates.append(action)
    candidates.extend(old for old, new in ACTION_ALIASES.items() if new == canonical and old not in candidates)
    return candidates


DEFAULT_POLICY: dict[str, Any] = {
    "schema_version": 3,
    "mode": "observe_only",
    "unknown_profile_default": "ask",
    "unknown_resource_default": "ask",
    "workflow_intent_policy_role": "audit_metadata_only",
    "operation_classes": {
        "gmail_read": {"actions": ["gmail.search_gmail_messages", "gmail.get_gmail_message_content", "gmail.get_gmail_messages_content_batch", "gmail.get_gmail_thread_content", "gmail.get_gmail_threads_content_batch", "gmail.list_gmail_labels", "gmail.list_gmail_filters"], "default_decision": "ask"},
        "gmail_draft": {"actions": ["gmail.draft_gmail_message"], "default_decision": "ask"},
        "gmail_send": {"actions": ["gmail.send_gmail_message"], "default_decision": "deny"},
        "gmail_mutation": {"actions": ["gmail.modify_gmail_message_labels", "gmail.batch_modify_gmail_message_labels", "gmail.manage_gmail_label", "gmail.manage_gmail_filter"], "default_decision": "ask"},
        "calendar_read": {"actions": ["calendar.list_calendars", "calendar.get_events", "calendar.query_freebusy"], "default_decision": "ask"},
        "calendar_mutation": {"actions": ["calendar.manage_event", "calendar.create_calendar", "calendar.manage_out_of_office", "calendar.manage_focus_time"], "default_decision": "ask"},
        "sheets_read": {"actions": ["sheets.read_sheet_values", "sheets.get_spreadsheet_info", "sheets.list_sheet_tables", "sheets.list_spreadsheet_comments", "sheets.list_spreadsheets"], "default_decision": "ask"},
        "sheets_mutation": {"actions": ["sheets.modify_sheet_values", "sheets.format_sheet_range", "sheets.create_sheet", "sheets.create_spreadsheet", "sheets.move_sheet_rows", "sheets.append_table_rows", "sheets.manage_spreadsheet_comment", "sheets.manage_conditional_formatting"], "default_decision": "ask"},
        "drive_read": {"actions": ["drive.search_drive_files", "drive.get_drive_file_content", "drive.get_drive_file_download_url", "drive.get_drive_shareable_link", "drive.list_drive_items", "drive.get_drive_file_permissions", "drive.check_drive_file_public_access"], "default_decision": "ask"},
        "drive_mutation": {"actions": ["drive.create_drive_file", "drive.create_drive_folder", "drive.import_to_google_doc", "drive.import_to_google_slides", "drive.import_to_google_sheets", "drive.copy_drive_file", "drive.update_drive_file", "drive.manage_drive_access", "drive.set_drive_file_permissions"], "default_decision": "deny"},
        "docs_read": {"actions": ["docs.get_doc_content", "docs.search_docs", "docs.list_docs_in_folder", "docs.get_doc_as_markdown", "docs.inspect_doc_structure", "docs.export_doc_to_pdf", "docs.debug_table_structure", "docs.list_document_comments"], "default_decision": "ask"},
        "docs_mutation": {"actions": ["docs.create_doc", "docs.modify_doc_text", "docs.find_and_replace_doc", "docs.insert_doc_elements", "docs.update_paragraph_style", "docs.insert_doc_image", "docs.update_doc_headers_footers", "docs.batch_update_doc", "docs.create_table_with_data", "docs.manage_document_comment", "docs.manage_doc_tab"], "default_decision": "ask"},
        "slides_read": {"actions": ["slides.get_presentation", "slides.get_page", "slides.get_page_thumbnail", "slides.list_presentation_comments"], "default_decision": "ask"},
        "slides_mutation": {"actions": ["slides.create_presentation", "slides.batch_update_presentation", "slides.manage_presentation_comment"], "default_decision": "ask"},
        "contacts_read": {"actions": ["contacts.search_contacts", "contacts.get_contact", "contacts.list_contacts", "contacts.list_contact_groups", "contacts.get_contact_group"], "default_decision": "ask"},
        "contacts_mutation": {"actions": ["contacts.manage_contact", "contacts.manage_contacts_batch", "contacts.manage_contact_group"], "default_decision": "ask"},
        "forms": {"actions": ["forms.create_form", "forms.get_form", "forms.set_publish_settings", "forms.get_form_response", "forms.list_form_responses", "forms.batch_update_form"], "default_decision": "ask"},
        "tasks": {"actions": ["tasks.list_tasks", "tasks.get_task", "tasks.manage_task", "tasks.list_task_lists", "tasks.get_task_list", "tasks.manage_task_list"], "default_decision": "ask"},
        "chat": {"actions": ["chat.list_spaces", "chat.get_messages", "chat.send_message", "chat.search_messages", "chat.create_reaction", "chat.download_chat_attachment"], "default_decision": "ask"},
        "search": {"actions": ["search.search_custom", "search.get_search_engine_info"], "default_decision": "ask"},
        "apps_script": {"actions": ["apps_script.list_script_projects", "apps_script.get_script_project", "apps_script.get_script_content", "apps_script.create_script_project", "apps_script.update_script_content", "apps_script.run_script_function", "apps_script.list_deployments", "apps_script.manage_deployment", "apps_script.list_script_processes"], "default_decision": "ask"},
    },
    "profile_policy": {},
    "global_denies": [],
}

_POLICY_CACHE: dict[str, Any] | None = None
_POLICY_MTIME: float | None = None


def load_policy() -> dict[str, Any]:
    global _POLICY_CACHE, _POLICY_MTIME
    try:
        mtime = POLICY_PATH.stat().st_mtime
        if _POLICY_CACHE is not None and _POLICY_MTIME == mtime:
            return _POLICY_CACHE
        data = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("policy json root must be object")
        _POLICY_CACHE = data
        _POLICY_MTIME = mtime
        return data
    except FileNotFoundError:
        _POLICY_CACHE = DEFAULT_POLICY
        _POLICY_MTIME = None
        return DEFAULT_POLICY


def _matches(value: str, patterns: list[Any]) -> bool:
    return "*" in patterns or value in {str(p) for p in patterns}


def _class_default(policy: dict[str, Any], action: str) -> tuple[str, str]:
    for candidate in _action_candidates(action):
        for class_name, spec in (policy.get("operation_classes") or {}).items():
            if candidate in spec.get("actions", []):
                return str(spec.get("default_decision") or "ask"), f"operation_class:{class_name}"
    return "ask", "unknown_action_default"


def classify(profile: str, action: str, resource_alias: str | None = None, workflow_intent: str | None = None) -> dict[str, Any]:
    policy = load_policy()
    resource = resource_alias or "unknown"
    action_candidates = _action_candidates(action)

    for rule in policy.get("global_denies") or []:
        actions = rule.get("actions") or []
        profiles = rule.get("profiles") or []
        resources = rule.get("resources") or []
        if _matches(profile, profiles) and _matches(resource, resources) and any(_matches(candidate, actions) for candidate in action_candidates):
            return {
                "decision": str(rule.get("decision") or "deny"),
                "decision_source": f"global_denies:{rule.get('id', 'unnamed')}",
                "mode": policy.get("mode", "observe_only"),
                "profile": profile,
                "resource_alias": resource,
                "action": action,
                "workflow_intent": workflow_intent or "",
                "policy_schema_version": policy.get("schema_version"),
            }

    profile_spec = (policy.get("profile_policy") or {}).get(profile)
    if isinstance(profile_spec, dict):
        resource_decisions = ((profile_spec.get("resource_overrides") or {}).get(resource) or {})
        for candidate in action_candidates:
            if candidate in resource_decisions:
                return {
                    "decision": str(resource_decisions[candidate]),
                    "decision_source": f"profile_resource_override:{profile}.{resource}.{candidate}",
                    "mode": policy.get("mode", "observe_only"),
                    "profile": profile,
                    "resource_alias": resource,
                    "action": action,
                    "workflow_intent": workflow_intent or "",
                    "policy_schema_version": policy.get("schema_version"),
                }
        defaults = profile_spec.get("defaults") or {}
        for candidate in action_candidates:
            if candidate in defaults:
                return {
                    "decision": str(defaults[candidate]),
                    "decision_source": f"profile_default:{profile}.{candidate}",
                    "mode": policy.get("mode", "observe_only"),
                    "profile": profile,
                    "resource_alias": resource,
                    "action": action,
                    "workflow_intent": workflow_intent or "",
                    "policy_schema_version": policy.get("schema_version"),
                }
    else:
        return {
            "decision": str(policy.get("unknown_profile_default") or "ask"),
            "decision_source": "unknown_profile_default",
            "mode": policy.get("mode", "observe_only"),
            "profile": profile,
            "resource_alias": resource,
            "action": action,
            "workflow_intent": workflow_intent or "",
            "policy_schema_version": policy.get("schema_version"),
        }

    decision, source = _class_default(policy, action)
    return {
        "decision": decision,
        "decision_source": source,
        "mode": policy.get("mode", "observe_only"),
        "profile": profile,
        "resource_alias": resource,
        "action": action,
        "workflow_intent": workflow_intent or "",
        "policy_schema_version": policy.get("schema_version"),
    }


def _safe_alias(value: str) -> str:
    out = []
    last_sep = False
    for ch in str(value or "").strip().lower():
        if ch.isalnum():
            out.append(ch)
            last_sep = False
        elif not last_sep:
            out.append("_")
            last_sep = True
    return "".join(out).strip("_") or "unknown"


def _account_alias_for_route(profile: str, payload: dict[str, Any]) -> str:
    """Resolve the Google Workspace account alias for a profile-scoped route."""
    route = str(payload.get("token_route") or "").strip()
    if route and route != "default":
        if "/" in route:
            route_profile, account = route.split("/", 1)
            if route_profile == profile and account:
                return _safe_alias(account)
            if account:
                return _safe_alias(account)
        return _safe_alias(route)
    profile_meta = (load_policy().get("profiles") or {}).get(profile) or {}
    connected = profile_meta.get("connected_account_aliases") or []
    if connected:
        return _safe_alias(str(connected[0]))
    return ""


def _workspace_resource_alias(profile: str, payload: dict[str, Any], template: str, fallback: str) -> str:
    account = _account_alias_for_route(profile, payload)
    if account:
        return template.format(account=account)
    return str(payload.get("resource_alias") or fallback)


def resource_for(profile: str, action: str, payload: dict[str, Any] | None = None) -> str:
    payload = payload or {}
    explicit = payload.get("resource_alias")
    if explicit:
        return str(explicit)
    if action.startswith("gmail."):
        return _workspace_resource_alias(profile, payload, "gmail_{account}", "gmail_inbox")
    if action.startswith("calendar."):
        return _workspace_resource_alias(profile, payload, "calendar_{account}_primary", "calendar_primary")
    if action.startswith("sheets."):
        return _workspace_resource_alias(profile, payload, "sheets_{account}_workspace", "sheets_unknown")
    if action.startswith("docs."):
        return _workspace_resource_alias(profile, payload, "docs_{account}_workspace", "docs_unknown")
    if action.startswith("drive."):
        return _workspace_resource_alias(profile, payload, "drive_{account}_workspace", "drive_any")
    if action.startswith("slides."):
        return _workspace_resource_alias(profile, payload, "slides_{account}_workspace", "slides_unknown")
    if action.startswith("contacts."):
        return _workspace_resource_alias(profile, payload, "contacts_{account}", "contacts_default")
    return str(payload.get("resource_alias") or "unknown")
