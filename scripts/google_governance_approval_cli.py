#!/usr/bin/env python3
"""Operator helper for Google Workspace governance approvals.

This helper is intended to run on the governance host as an operator identity that
has access to the local install folder's `.google-governance/config` directory. It
uses a gateway API access token plus the approval admin secret and never exposes
Google OAuth tokens or JWT signing secrets.
"""
from __future__ import annotations

import argparse
import json
import os
import urllib.request
from pathlib import Path
from typing import Any

GATEWAY_URL = os.getenv("GOOGLE_GOVERNANCE_URL", os.getenv("HERMES_GOOGLE_GOVERNANCE_URL", "http://127.0.0.1:8768")).rstrip("/")
BASE = Path(os.getenv("GOOGLE_GOVERNANCE_PROJECT_DIR", str(Path(__file__).resolve().parents[1])))
CONFIG_BASE = Path(os.getenv("GOOGLE_GOVERNANCE_CONFIG_DIR", str(BASE / ".google-governance/config")))
APPROVAL_SECRET_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_APPROVAL_ADMIN_SECRET_PATH", str(CONFIG_BASE / "approval_admin_secret")))
PROFILE = os.getenv("GOOGLE_GOVERNANCE_PROFILE", os.getenv("AGENT_GOOGLE_GOVERNANCE_PROFILE", "agent-a"))
ACCESS_TOKEN = os.getenv("GOOGLE_GOVERNANCE_ACCESS_TOKEN") or os.getenv("AGENT_GOOGLE_GOVERNANCE_ACCESS_TOKEN")


def post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    if not ACCESS_TOKEN or not ACCESS_TOKEN.strip():
        raise RuntimeError("GOOGLE_GOVERNANCE_ACCESS_TOKEN or AGENT_GOOGLE_GOVERNANCE_ACCESS_TOKEN is required; filesystem JWT signing is disabled")
    payload = dict(payload)
    payload.setdefault("profile", PROFILE)
    payload.setdefault("workflow_intent", "operator.approval_cli")
    payload.setdefault("approval_admin_secret", APPROVAL_SECRET_PATH.read_text(encoding="utf-8").strip())
    req = urllib.request.Request(
        GATEWAY_URL + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {ACCESS_TOKEN.strip()}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8") or "{}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Manage Google Workspace governance approval queue")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_list = sub.add_parser("list", help="List approvals")
    p_list.add_argument("--state", default="pending", choices=["pending", "approve_once", "deny", "request_edit", "consumed", "all"])
    p_decide = sub.add_parser("decide", help="Approve, deny, or request edits")
    p_decide.add_argument("approval_id")
    p_decide.add_argument("decision", choices=["approve_once", "deny", "request_edit"])
    p_decide.add_argument("--reason", default="")
    p_decide.add_argument("--approver", default="admin")
    p_decide.add_argument("--ttl-seconds", type=int, default=900)
    args = parser.parse_args()

    if args.cmd == "list":
        result = post("/v1/governance/approvals/list", {"state": args.state})
    else:
        result = post(
            "/v1/governance/approvals/decide",
            {"approval_id": args.approval_id, "decision": args.decision, "reason": args.reason, "approver": args.approver, "ttl_seconds": args.ttl_seconds},
        )
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
