#!/usr/bin/env python3
"""Focused decision-matrix tests for the Google governance policy classifier."""
from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_DIR / "scripts" / "governance_policy.py"


def load_policy_module():
    spec = importlib.util.spec_from_file_location("governance_policy_matrix_test", SCRIPT)
    if spec is None or spec.loader is None:
        raise SystemExit("could not load governance_policy")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def install_policy(module, policy: dict) -> Path:
    tmp = Path(tempfile.mkdtemp(prefix="google-gov-policy-matrix-"))
    policy_path = tmp / "profile_policy.json"
    policy_path.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    module.POLICY_PATH = policy_path
    module._POLICY_CACHE = None
    module._POLICY_MTIME = None
    return policy_path


def assert_decision(got: dict, expected_decision: str, expected_source_prefix: str, label: str) -> None:
    if got.get("decision") != expected_decision or not str(got.get("decision_source") or "").startswith(expected_source_prefix):
        raise SystemExit(f"{label}: got {got}, expected decision={expected_decision} source prefix={expected_source_prefix}")


def main() -> None:
    module = load_policy_module()
    policy_path = install_policy(module, {
        "schema_version": 3,
        "mode": "enforce",
        "unknown_profile_default": "deny",
        "unknown_resource_default": "deny",
        "workflow_intent_policy_role": "audit_metadata_only",
        "accounts": {"personal-primary": {}, "shared-workspace": {}},
        "profiles": {
            "reasoning": {"account_alias": "personal_primary", "connected_account_aliases": ["personal_primary"], "default_route_alias": "reasoning/personal_primary"},
            "airbnb": {"connected_account_aliases": ["shared_workspace"], "default_route_alias": "airbnb/shared_workspace"},
        },
        "operation_classes": {
            "read": {"actions": ["gmail.search_gmail_messages", "drive.search_drive_files", "sheets.read_sheet_values"], "default_decision": "ask"},
            "write": {"actions": ["gmail.send_gmail_message", "drive.manage_drive_access", "sheets.modify_sheet_values"], "default_decision": "deny"},
        },
        "profile_policy": {
            "reasoning": {
                "defaults": {
                    "gmail.search_gmail_messages": "allow",
                    "gmail.send_gmail_message": "ask",
                    "sheets.modify_sheet_values": "ask",
                },
                "resource_overrides": {
                    "gmail_personal_primary": {"gmail.send_gmail_message": "deny"},
                    "drive_personal_primary_workspace": {"drive.manage_drive_access": "allow"},
                    "sheets_personal_primary_workspace": {"sheets.modify_sheet_values": "allow"},
                },
            },
            "airbnb": {
                "defaults": {"gmail.search_gmail_messages": "allow"},
                "resource_overrides": {},
            },
        },
        "global_denies": [
            {"id": "no_drive_share", "profiles": ["*"], "resources": ["*"], "actions": ["drive.manage_drive_access"], "decision": "deny"},
            {"id": "block_reasoning_send", "profiles": ["reasoning"], "resources": ["gmail_personal_primary"], "actions": ["gmail.send_gmail_message"], "decision": "deny"},
        ],
    })

    cases = [
        ("profile default allow", module.classify("reasoning", "gmail.search_gmail_messages", "gmail_personal_primary"), "allow", "profile_default:"),
        ("resource override deny beats profile default ask", module.classify("reasoning", "gmail.send_gmail_message", "gmail_personal_primary"), "deny", "global_denies:block_reasoning_send"),
        ("global wildcard deny beats resource allow", module.classify("reasoning", "drive.manage_drive_access", "drive_personal_primary_workspace"), "deny", "global_denies:no_drive_share"),
        ("unknown profile default deny", module.classify("unknown-agent", "gmail.search_gmail_messages", "gmail_personal_primary"), "deny", "unknown_profile_default"),
        ("unknown resource default deny before action class", module.classify("reasoning", "sheets.modify_sheet_values", "sheets_unmapped"), "deny", "unknown_resource_default"),
        ("legacy action alias resolves to canonical default", module.classify("reasoning", "gmail.search", "gmail_personal_primary"), "allow", "profile_default:"),
        ("operation class default used for known profile with no explicit rule", module.classify("airbnb", "drive.search_drive_files", "drive_shared_workspace_workspace"), "ask", "operation_class:read"),
    ]
    for label, got, expected, source in cases:
        assert_decision(got, expected, source, label)

    resource_cases = [
        ("explicit resource wins", module.resource_for("reasoning", "gmail.search_gmail_messages", {"resource_alias": "explicit"}), "explicit"),
        ("default route maps gmail resource", module.resource_for("reasoning", "gmail.search_gmail_messages", {}), "gmail_personal_primary"),
        ("token route maps sheets resource", module.resource_for("airbnb", "sheets.modify_sheet_values", {"token_route": "airbnb/shared_workspace"}), "sheets_shared_workspace_workspace"),
        ("display/account route maps drive resource", module.resource_for("reasoning", "drive.search_drive_files", {"token_route": "reasoning/personal-primary"}), "drive_personal_primary_workspace"),
        ("unknown resource fallback", module.resource_for("unknown-agent", "contacts.search_contacts", {}), "contacts_default"),
    ]
    for label, got, expected in resource_cases:
        if got != expected:
            raise SystemExit(f"{label}: got {got}, expected {expected}")

    print(json.dumps({
        "status": "PASS",
        "policy": str(policy_path),
        "decision_cases": len(cases),
        "resource_cases": len(resource_cases),
    }, indent=2))


if __name__ == "__main__":
    main()
