#!/usr/bin/env python3
"""Governed Google Workspace MCP server.

This MCP server exposes policy-shaped Google Workspace tools that call the
unified Google governance gateway. It does not import Google client libraries and
does not read OAuth tokens. All Google access is routed through the governed
gateway and audited there.

Transport modes:
- stdio (default): bridge mode for local MCP clients.
- streamable-http: remote/local HTTP MCP mode so agent runtime only needs a URL plus
  GOOGLE_GOVERNANCE_ACCESS_TOKEN; no local wrapper file is required on the
  agent host.

Safety model:
- Read/bounded update operations route to the gateway.
- Externalizing or destructive operations return structured approval-required responses until approved.
"""
from __future__ import annotations

import base64
import contextvars
import hashlib
import json
import os
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any, cast

from mcp.server.fastmcp import FastMCP
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings

MCP_NAME = "governed-google-workspace"
DEFAULT_GATEWAY_URL = "http://127.0.0.1:8768"
MCP_CLIENT_ID = "mcp_governed_google"
DEFAULT_MCP_HOST = "127.0.0.1"
DEFAULT_MCP_PORT = 8769
DEFAULT_MCP_PATH = "/mcp"
TOKEN_DB_PATH = Path(os.getenv("GOOGLE_GOVERNANCE_TOKEN_DB_PATH", os.getenv("GOOGLE_GOVERNANCE_CONTROL_USERS_DB_PATH", "")))
profile_header_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("google_governance_profile_header", default=None)
agent_token_header_var: contextvars.ContextVar[str | None] = contextvars.ContextVar("google_governance_agent_token_header", default=None)


def _csv_env(name: str) -> list[str]:
    value = os.getenv(name, "")
    return [item.strip() for item in value.split(",") if item.strip()]


def _hashes_env() -> dict[str, str]:
    """Return accepted API-token hashes for HTTP MCP bearer auth.

    Primary custody is SQLite api_tokens. Environment hashes are retained only
    as an explicit operator override for break-glass/testing; install_systemd.sh
    does not create a default client token.
    """
    token_map: dict[str, str] = {}
    raw = os.getenv("GOOGLE_GOVERNANCE_MCP_TOKEN_HASHES") or os.getenv("GOOGLE_GOVERNANCE_API_TOKEN_HASHES") or ""
    raw = raw.strip()
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise RuntimeError("GOOGLE_GOVERNANCE_MCP_TOKEN_HASHES is not valid JSON") from exc
        if not isinstance(data, dict):
            raise RuntimeError("GOOGLE_GOVERNANCE_MCP_TOKEN_HASHES JSON must be an object")
        token_map.update({str(k): str(v) for k, v in data.items()})
    elif raw:
        for item in _csv_env("GOOGLE_GOVERNANCE_MCP_TOKEN_HASHES") or _csv_env("GOOGLE_GOVERNANCE_API_TOKEN_HASHES"):
            token_map[item] = "*"
    try:
        if TOKEN_DB_PATH and TOKEN_DB_PATH.exists():
            with sqlite3.connect(TOKEN_DB_PATH) as conn:
                conn.row_factory = sqlite3.Row
                rows = conn.execute("SELECT token_hash,allowed_profiles_json FROM api_tokens WHERE revoked_at='' ").fetchall()
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
        if TOKEN_DB_PATH and TOKEN_DB_PATH.exists():
            with sqlite3.connect(TOKEN_DB_PATH) as conn:
                conn.execute("UPDATE api_tokens SET last_used_at=CURRENT_TIMESTAMP WHERE token_hash=? AND revoked_at=''", (token_hash,))
                conn.commit()
    except sqlite3.Error:
        pass

class Sha256BearerVerifier:
    """FastMCP bearer-token verifier backed by SHA-256 token hashes."""

    async def verify_token(self, token: str) -> AccessToken | None:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        accepted = _hashes_env()
        profile_scope = accepted.get(token_hash)
        if not profile_scope:
            return None
        _mark_api_token_used(token_hash)
        scopes = ["google-governance"]
        if profile_scope and profile_scope != "*":
            scopes.append(f"profile:{profile_scope}")
        return AccessToken(token=token, client_id=MCP_CLIENT_ID, scopes=scopes, expires_at=int(time.time()) + 3600)


class ProfileHeaderMiddleware:
    """Capture per-client profile identity from native HTTP MCP headers."""

    def __init__(self, app: Any):
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        header_profile = None
        header_agent_token = None
        if scope.get("type") == "http":
            for key, value in scope.get("headers") or []:
                lower_key = key.lower()
                if lower_key == b"x-google-governance-profile":
                    header_profile = value.decode("utf-8", "replace").strip()
                elif lower_key in {b"x-google-governance-agent-token", b"x-agent-token"}:
                    header_agent_token = value.decode("utf-8", "replace").strip()
        profile_token = profile_header_var.set(header_profile)
        agent_token = agent_token_header_var.set(header_agent_token)
        try:
            await self.app(scope, receive, send)
        finally:
            agent_token_header_var.reset(agent_token)
            profile_header_var.reset(profile_token)


def mcp_transport() -> str:
    return (os.getenv("GOOGLE_GOVERNANCE_MCP_TRANSPORT") or os.getenv("MCP_TRANSPORT") or "stdio").strip().lower()


def mcp_host() -> str:
    return os.getenv("GOOGLE_GOVERNANCE_MCP_HOST", DEFAULT_MCP_HOST)


def mcp_port() -> int:
    return int(os.getenv("GOOGLE_GOVERNANCE_MCP_PORT", str(DEFAULT_MCP_PORT)))


def mcp_path() -> str:
    path = os.getenv("GOOGLE_GOVERNANCE_MCP_PATH", DEFAULT_MCP_PATH).strip() or DEFAULT_MCP_PATH
    return path if path.startswith("/") else f"/{path}"


def mcp_external_url() -> str:
    return os.getenv("GOOGLE_GOVERNANCE_MCP_URL") or f"http://{mcp_host()}:{mcp_port()}{mcp_path()}"


def _build_mcp() -> FastMCP:
    if mcp_transport() == "streamable-http" and os.getenv("GOOGLE_GOVERNANCE_MCP_AUTH_DISABLED", "0") != "1":
        url = mcp_external_url()
        return FastMCP(
            MCP_NAME,
            host=mcp_host(),
            port=mcp_port(),
            streamable_http_path=mcp_path(),
            stateless_http=True,
            auth=AuthSettings(issuer_url=cast(Any, url), resource_server_url=cast(Any, url), required_scopes=["google-governance"]),
            token_verifier=Sha256BearerVerifier(),
        )
    return FastMCP(MCP_NAME, host=mcp_host(), port=mcp_port(), streamable_http_path=mcp_path(), stateless_http=True)


mcp = _build_mcp()


def gateway_url() -> str:
    """Return the governed gateway base URL without a trailing slash."""
    return (
        os.getenv("GOOGLE_GOVERNANCE_URL")
        or os.getenv("HERMES_GOOGLE_GOVERNANCE_URL")
        or DEFAULT_GATEWAY_URL
    ).rstrip("/")


def active_profile() -> str:
    header_profile = profile_header_var.get()
    if header_profile:
        return header_profile
    access = get_access_token()
    if access:
        for scope in access.scopes:
            if scope.startswith("profile:"):
                profile_from_token = scope.split(":", 1)[1].strip()
                if profile_from_token and profile_from_token != "*":
                    return profile_from_token
    profile = os.getenv("GOOGLE_GOVERNANCE_PROFILE") or os.getenv("AGENT_GOOGLE_GOVERNANCE_PROFILE") or os.getenv("HERMES_PROFILE")
    if profile:
        return profile
    profile_home = os.getenv("GOOGLE_GOVERNANCE_PROFILE_HOME") or os.getenv("HERMES_HOME", "")
    if profile_home:
        name = Path(profile_home).name
        if name in PROFILE_DEFAULTS:
            return name
    return "agent-a"


def default_token_route(profile: str) -> str | None:
    """Return only an explicitly configured default route.

    Do not bake profile-to-account assumptions into the MCP wrapper.  The
    gateway owns profile/account route resolution, and every tool also accepts
    an explicit `token_route` such as `agent-b/rani_gmail`.
    """
    return os.getenv("GOOGLE_GOVERNANCE_TOKEN_ROUTE") or os.getenv("HERMES_GOOGLE_GOVERNANCE_TOKEN_ROUTE")


def api_access_token() -> str | None:
    """Return an externally provisioned gateway access token if configured.

    Agents must never read a gateway-local JWT signing secret from the
    filesystem. Governance policy is API-token/token-exchange auth only, even
    for same-host clients.
    """
    token = os.getenv("GOOGLE_GOVERNANCE_ACCESS_TOKEN") or os.getenv("AGENT_GOOGLE_GOVERNANCE_ACCESS_TOKEN")
    return token.strip() if token and token.strip() else None


def auth_header(profile: str) -> str:
    access = get_access_token()
    if access and access.token:
        return f"Bearer {access.token}"
    token = api_access_token()
    if token:
        return f"Bearer {token}"
    raise RuntimeError(
        "Google Governance auth requires GOOGLE_GOVERNANCE_ACCESS_TOKEN "
        "or AGENT_GOOGLE_GOVERNANCE_ACCESS_TOKEN; filesystem JWT signing is disabled"
    )


def agent_token() -> str | None:
    header_token = agent_token_header_var.get()
    if header_token:
        return header_token
    token = os.getenv("GOOGLE_GOVERNANCE_AGENT_TOKEN") or os.getenv("AGENT_GOOGLE_GOVERNANCE_AGENT_TOKEN")
    return token.strip() if token and token.strip() else None



def gateway_post(path: str, payload: dict[str, Any]) -> Any:
    profile = active_profile()
    identity_token = agent_token()
    payload = dict(payload)
    if not identity_token:
        payload.setdefault("profile", profile)
    payload.setdefault("workflow_intent", "mcp.governed_google")
    payload.setdefault("request_id", str(uuid.uuid4()))
    payload.setdefault("client", MCP_CLIENT_ID)
    headers = {"Authorization": auth_header(profile), "Content-Type": "application/json"}
    if identity_token:
        headers["X-Google-Governance-Agent-Token"] = identity_token
    req = urllib.request.Request(gateway_url() + path, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            result = json.loads(resp.read().decode("utf-8") or "null")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Google governance gateway HTTP {exc.code}: {body}") from exc
    if isinstance(result, dict):
        result.setdefault("request_id", payload["request_id"])
        result.setdefault("governed_by", "google-workspace-governance")
        result.setdefault("audit_hint", {"profile": profile, "workflow_intent": payload["workflow_intent"]})
    return result


def governance_blocked(action: str, reason: str, resource_alias: str = "requires_approval", **metadata: Any) -> dict[str, Any]:
    profile = active_profile()
    return gateway_post("/v1/governance/blocked", {"action": action, "reason": reason, "resource_alias": resource_alias, "token_route": default_token_route(profile), **metadata})


def governance_execute_approved(action: str, approval_id: str, resource_alias: str = "requires_approval", **metadata: Any) -> dict[str, Any]:
    profile = active_profile()
    return gateway_post("/v1/governance/execute-approved", {"action": action, "approval_id": approval_id, "resource_alias": resource_alias, "token_route": default_token_route(profile), **metadata})


# Legacy google_* compatibility MCP tools were intentionally removed.
# Expose only canonical google_workspace_mcp tool names below.

def workspace_tool_route(tool: str, payload: dict[str, Any] | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Call one canonical google_workspace_mcp-compatible typed route through governance."""
    profile = active_profile()
    body = dict(payload or {})
    body["token_route"] = token_route or default_token_route(profile)
    return gateway_post(f"/v1/tools/{tool}", body)

# google_workspace_mcp mirrored tools — exact upstream tool names and typed payload schemas, governed by typed routes.

@mcp.tool()
def list_calendars(token_route: str | None = None) -> dict[str, Any]:
    """List accessible calendars (governed route: calendar.list_calendars)."""
    payload = {}
    return workspace_tool_route("list_calendars", payload, token_route)

@mcp.tool()
def get_events(calendar_id: str = "primary", event_id: str | None = None, time_min: str | None = None, time_max: str | None = None, max_results: int = 25, query: str | None = None, detailed: bool = False, include_attachments: bool = False, token_route: str | None = None) -> dict[str, Any]:
    """Retrieve events with time range filtering (governed route: calendar.get_events)."""
    payload = {k: v for k, v in {
        "calendar_id": calendar_id,
        "event_id": event_id,
        "time_min": time_min,
        "time_max": time_max,
        "max_results": max_results,
        "query": query,
        "detailed": detailed,
        "include_attachments": include_attachments,
    }.items() if v is not None}
    return workspace_tool_route("get_events", payload, token_route)

@mcp.tool()
def manage_event(action: str, summary: str | None = None, start_time: str | None = None, end_time: str | None = None, event_id: str | None = None, calendar_id: str = "primary", description: str | None = None, location: str | None = None, attendees: Any | None = None, timezone: str | None = None, attachments: list[str] | None = None, add_google_meet: bool | None = None, conference_data: dict[str, Any] | None = None, conference_provider: str | None = None, conference_uri: str | None = None, conference_passcode: str | None = None, conference_id: str | None = None, reminders: Any | None = None, use_default_reminders: bool | None = None, transparency: str | None = None, visibility: str | None = None, color_id: str | None = None, recurrence: list[str] | None = None, guests_can_modify: bool | None = None, guests_can_invite_others: bool | None = None, guests_can_see_other_guests: bool | None = None, response: str | None = None, rsvp_comment: str | None = None, send_updates: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Create, update, or delete calendar events (governed route: calendar.manage_event)."""
    payload = {k: v for k, v in {
        "action": action,
        "summary": summary,
        "start_time": start_time,
        "end_time": end_time,
        "event_id": event_id,
        "calendar_id": calendar_id,
        "description": description,
        "location": location,
        "attendees": attendees,
        "timezone": timezone,
        "attachments": attachments,
        "add_google_meet": add_google_meet,
        "conference_data": conference_data,
        "conference_provider": conference_provider,
        "conference_uri": conference_uri,
        "conference_passcode": conference_passcode,
        "conference_id": conference_id,
        "reminders": reminders,
        "use_default_reminders": use_default_reminders,
        "transparency": transparency,
        "visibility": visibility,
        "color_id": color_id,
        "recurrence": recurrence,
        "guests_can_modify": guests_can_modify,
        "guests_can_invite_others": guests_can_invite_others,
        "guests_can_see_other_guests": guests_can_see_other_guests,
        "response": response,
        "rsvp_comment": rsvp_comment,
        "send_updates": send_updates,
    }.items() if v is not None}
    return workspace_tool_route("manage_event", payload, token_route)

@mcp.tool()
def create_calendar(summary: str, description: str | None = None, timezone: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Create a new secondary Google Calendar (governed route: calendar.create_calendar)."""
    payload = {k: v for k, v in {
        "summary": summary,
        "description": description,
        "timezone": timezone,
    }.items() if v is not None}
    return workspace_tool_route("create_calendar", payload, token_route)

@mcp.tool()
def query_freebusy(time_min: str, time_max: str, calendar_ids: list[str] | None = None, group_expansion_max: int | None = None, calendar_expansion_max: int | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Query free/busy information for calendars (governed route: calendar.query_freebusy)."""
    payload = {k: v for k, v in {
        "time_min": time_min,
        "time_max": time_max,
        "calendar_ids": calendar_ids,
        "group_expansion_max": group_expansion_max,
        "calendar_expansion_max": calendar_expansion_max,
    }.items() if v is not None}
    return workspace_tool_route("query_freebusy", payload, token_route)

@mcp.tool()
def manage_out_of_office(action: str, start_time: str | None = None, end_time: str | None = None, summary: str | None = None, auto_decline_mode: str | None = None, decline_message: str | None = None, recurrence: list[str] | None = None, timezone: str | None = None, time_min: str | None = None, time_max: str | None = None, max_results: int = 10, event_id: str | None = None, calendar_id: str = "primary", token_route: str | None = None) -> dict[str, Any]:
    """Create, list, update, or delete Out of Office events (governed route: calendar.manage_out_of_office)."""
    payload = {k: v for k, v in {
        "action": action,
        "start_time": start_time,
        "end_time": end_time,
        "summary": summary,
        "auto_decline_mode": auto_decline_mode,
        "decline_message": decline_message,
        "recurrence": recurrence,
        "timezone": timezone,
        "time_min": time_min,
        "time_max": time_max,
        "max_results": max_results,
        "event_id": event_id,
        "calendar_id": calendar_id,
    }.items() if v is not None}
    return workspace_tool_route("manage_out_of_office", payload, token_route)

@mcp.tool()
def manage_focus_time(action: str, start_time: str | None = None, end_time: str | None = None, summary: str | None = None, description: str | None = None, auto_decline_mode: str | None = None, decline_message: str | None = None, chat_status: str | None = None, recurrence: list[str] | None = None, timezone: str | None = None, time_min: str | None = None, time_max: str | None = None, max_results: int = 10, event_id: str | None = None, calendar_id: str = "primary", token_route: str | None = None) -> dict[str, Any]:
    """Create, list, update, or delete Focus Time events (governed route: calendar.manage_focus_time)."""
    payload = {k: v for k, v in {
        "action": action,
        "start_time": start_time,
        "end_time": end_time,
        "summary": summary,
        "description": description,
        "auto_decline_mode": auto_decline_mode,
        "decline_message": decline_message,
        "chat_status": chat_status,
        "recurrence": recurrence,
        "timezone": timezone,
        "time_min": time_min,
        "time_max": time_max,
        "max_results": max_results,
        "event_id": event_id,
        "calendar_id": calendar_id,
    }.items() if v is not None}
    return workspace_tool_route("manage_focus_time", payload, token_route)

@mcp.tool()
def search_drive_files(query: str, page_size: int = 10, page_token: str | None = None, drive_id: str | None = None, include_items_from_all_drives: bool = True, corpora: str | None = None, file_type: str | None = None, detailed: bool = True, order_by: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Search files with query syntax (governed route: drive.search_drive_files)."""
    payload = {k: v for k, v in {
        "query": query,
        "page_size": page_size,
        "page_token": page_token,
        "drive_id": drive_id,
        "include_items_from_all_drives": include_items_from_all_drives,
        "corpora": corpora,
        "file_type": file_type,
        "detailed": detailed,
        "order_by": order_by,
    }.items() if v is not None}
    return workspace_tool_route("search_drive_files", payload, token_route)

@mcp.tool()
def get_drive_file_content(file_id: str, token_route: str | None = None) -> dict[str, Any]:
    """Read file content (Office, PDF, image) (governed route: drive.get_drive_file_content)."""
    payload = {k: v for k, v in {
        "file_id": file_id,
    }.items() if v is not None}
    return workspace_tool_route("get_drive_file_content", payload, token_route)

@mcp.tool()
def get_drive_file_download_url(file_id: str, export_format: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Download Drive files to local disk (governed route: drive.get_drive_file_download_url)."""
    payload = {k: v for k, v in {
        "file_id": file_id,
        "export_format": export_format,
    }.items() if v is not None}
    return workspace_tool_route("get_drive_file_download_url", payload, token_route)

@mcp.tool()
def create_drive_file(file_name: str, content: str | None = None, folder_id: str = "root", mime_type: str = "text/plain", fileUrl: str | None = None, base64_content: str | None = None, content_mime_type: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Create files or fetch from URLs (governed route: drive.create_drive_file)."""
    payload = {k: v for k, v in {
        "file_name": file_name,
        "content": content,
        "folder_id": folder_id,
        "mime_type": mime_type,
        "fileUrl": fileUrl,
        "base64_content": base64_content,
        "content_mime_type": content_mime_type,
    }.items() if v is not None}
    return workspace_tool_route("create_drive_file", payload, token_route)

@mcp.tool()
def create_drive_folder(folder_name: str, parent_folder_id: str = "root", token_route: str | None = None) -> dict[str, Any]:
    """Create empty folders in Drive or shared drives (governed route: drive.create_drive_folder)."""
    payload = {k: v for k, v in {
        "folder_name": folder_name,
        "parent_folder_id": parent_folder_id,
    }.items() if v is not None}
    return workspace_tool_route("create_drive_folder", payload, token_route)

@mcp.tool()
def import_to_google_doc(file_name: str, content: str | None = None, file_path: str | None = None, file_url: str | None = None, source_format: str | None = None, folder_id: str = "root", token_route: str | None = None) -> dict[str, Any]:
    """Import files (MD, DOCX, HTML, etc.) as Google Docs (governed route: drive.import_to_google_doc)."""
    payload = {k: v for k, v in {
        "file_name": file_name,
        "content": content,
        "file_path": file_path,
        "file_url": file_url,
        "source_format": source_format,
        "folder_id": folder_id,
    }.items() if v is not None}
    return workspace_tool_route("import_to_google_doc", payload, token_route)

@mcp.tool()
def import_to_google_slides(file_name: str, file_path: str | None = None, file_url: str | None = None, source_format: str | None = None, folder_id: str = "root", token_route: str | None = None) -> dict[str, Any]:
    """Import presentation files (PPTX, PPT, ODP) as Google Slides (governed route: drive.import_to_google_slides)."""
    payload = {k: v for k, v in {
        "file_name": file_name,
        "file_path": file_path,
        "file_url": file_url,
        "source_format": source_format,
        "folder_id": folder_id,
    }.items() if v is not None}
    return workspace_tool_route("import_to_google_slides", payload, token_route)

@mcp.tool()
def import_to_google_sheets(file_name: str, content: str | None = None, file_path: str | None = None, file_url: str | None = None, source_format: str | None = None, folder_id: str = "root", token_route: str | None = None) -> dict[str, Any]:
    """Import spreadsheet files (XLSX, CSV, TSV, etc.) as Google Sheets (governed route: drive.import_to_google_sheets)."""
    payload = {k: v for k, v in {
        "file_name": file_name,
        "content": content,
        "file_path": file_path,
        "file_url": file_url,
        "source_format": source_format,
        "folder_id": folder_id,
    }.items() if v is not None}
    return workspace_tool_route("import_to_google_sheets", payload, token_route)

@mcp.tool()
def get_drive_shareable_link(file_id: str, token_route: str | None = None) -> dict[str, Any]:
    """Get shareable links for a file (governed route: drive.get_drive_shareable_link)."""
    payload = {k: v for k, v in {
        "file_id": file_id,
    }.items() if v is not None}
    return workspace_tool_route("get_drive_shareable_link", payload, token_route)

@mcp.tool()
def list_drive_items(folder_id: str = "root", page_size: int = 100, page_token: str | None = None, drive_id: str | None = None, include_items_from_all_drives: bool = True, corpora: str | None = None, file_type: str | None = None, detailed: bool = True, order_by: str | None = None, resource_type: str = "items", query: str | None = None, include_organizers: bool = False, token_route: str | None = None) -> dict[str, Any]:
    """List folder contents or shared drives (governed route: drive.list_drive_items)."""
    payload = {k: v for k, v in {
        "folder_id": folder_id,
        "page_size": page_size,
        "page_token": page_token,
        "drive_id": drive_id,
        "include_items_from_all_drives": include_items_from_all_drives,
        "corpora": corpora,
        "file_type": file_type,
        "detailed": detailed,
        "order_by": order_by,
        "resource_type": resource_type,
        "query": query,
        "include_organizers": include_organizers,
    }.items() if v is not None}
    return workspace_tool_route("list_drive_items", payload, token_route)

@mcp.tool()
def copy_drive_file(file_id: str, new_name: str | None = None, parent_folder_id: str = "root", token_route: str | None = None) -> dict[str, Any]:
    """Copy existing files (templates) with optional renaming (governed route: drive.copy_drive_file)."""
    payload = {k: v for k, v in {
        "file_id": file_id,
        "new_name": new_name,
        "parent_folder_id": parent_folder_id,
    }.items() if v is not None}
    return workspace_tool_route("copy_drive_file", payload, token_route)

@mcp.tool()
def update_drive_file(file_id: str, name: str | None = None, description: str | None = None, mime_type: str | None = None, add_parents: str | None = None, remove_parents: str | None = None, starred: bool | None = None, trashed: bool | None = None, writers_can_share: bool | None = None, copy_requires_writer_permission: bool | None = None, properties: dict[str, Any] | None = None, content: str | None = None, file_path: str | None = None, file_url: str | None = None, source_format: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Update metadata, move files, or replace Google Apps content (governed route: drive.update_drive_file)."""
    payload = {k: v for k, v in {
        "file_id": file_id,
        "name": name,
        "description": description,
        "mime_type": mime_type,
        "add_parents": add_parents,
        "remove_parents": remove_parents,
        "starred": starred,
        "trashed": trashed,
        "writers_can_share": writers_can_share,
        "copy_requires_writer_permission": copy_requires_writer_permission,
        "properties": properties,
        "content": content,
        "file_path": file_path,
        "file_url": file_url,
        "source_format": source_format,
    }.items() if v is not None}
    return workspace_tool_route("update_drive_file", payload, token_route)

@mcp.tool()
def manage_drive_access(file_id: str, action: str, share_with: str | None = None, role: str | None = None, share_type: str = "user", permission_id: str | None = None, recipients: list[dict[str, Any]] | None = None, send_notification: bool = True, email_message: str | None = None, expiration_time: str | None = None, allow_file_discovery: bool | None = None, new_owner_email: str | None = None, move_to_new_owners_root: bool = False, token_route: str | None = None) -> dict[str, Any]:
    """Grant, update, revoke permissions, and transfer ownership (governed route: drive.manage_drive_access)."""
    payload = {k: v for k, v in {
        "file_id": file_id,
        "action": action,
        "share_with": share_with,
        "role": role,
        "share_type": share_type,
        "permission_id": permission_id,
        "recipients": recipients,
        "send_notification": send_notification,
        "email_message": email_message,
        "expiration_time": expiration_time,
        "allow_file_discovery": allow_file_discovery,
        "new_owner_email": new_owner_email,
        "move_to_new_owners_root": move_to_new_owners_root,
    }.items() if v is not None}
    return workspace_tool_route("manage_drive_access", payload, token_route)

@mcp.tool()
def set_drive_file_permissions(file_id: str, link_sharing: str | None = None, writers_can_share: bool | None = None, copy_requires_writer_permission: bool | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Set link sharing and file-level sharing settings (governed route: drive.set_drive_file_permissions)."""
    payload = {k: v for k, v in {
        "file_id": file_id,
        "link_sharing": link_sharing,
        "writers_can_share": writers_can_share,
        "copy_requires_writer_permission": copy_requires_writer_permission,
    }.items() if v is not None}
    return workspace_tool_route("set_drive_file_permissions", payload, token_route)

@mcp.tool()
def get_drive_file_permissions(file_id: str, token_route: str | None = None) -> dict[str, Any]:
    """Get file metadata, parents, and permissions (governed route: drive.get_drive_file_permissions)."""
    payload = {k: v for k, v in {
        "file_id": file_id,
    }.items() if v is not None}
    return workspace_tool_route("get_drive_file_permissions", payload, token_route)

@mcp.tool()
def check_drive_file_public_access(file_name: str, drive_id: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Check public sharing status (governed route: drive.check_drive_file_public_access)."""
    payload = {k: v for k, v in {
        "file_name": file_name,
        "drive_id": drive_id,
    }.items() if v is not None}
    return workspace_tool_route("check_drive_file_public_access", payload, token_route)

@mcp.tool()
def search_gmail_messages(query: str, page_size: int = 10, page_token: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Search with Gmail operators (governed route: gmail.search_gmail_messages)."""
    payload = {k: v for k, v in {
        "query": query,
        "page_size": page_size,
        "page_token": page_token,
    }.items() if v is not None}
    return workspace_tool_route("search_gmail_messages", payload, token_route)

@mcp.tool()
def get_gmail_message_content(message_id: str, body_format: Any = "text", token_route: str | None = None) -> dict[str, Any]:
    """Retrieve message content (governed route: gmail.get_gmail_message_content)."""
    payload = {k: v for k, v in {
        "message_id": message_id,
        "body_format": body_format,
    }.items() if v is not None}
    return workspace_tool_route("get_gmail_message_content", payload, token_route)

@mcp.tool()
def list_gmail_attachments(message_id: str, token_route: str | None = None) -> dict[str, Any]:
    """List attachment metadata for a Gmail message (governed route: gmail.list_gmail_attachments)."""
    payload = {k: v for k, v in {
        "message_id": message_id,
    }.items() if v is not None}
    return workspace_tool_route("list_gmail_attachments", payload, token_route)

@mcp.tool()
def get_gmail_attachment(message_id: str, attachment_id: str, filename: str | None = None, mime_type: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Retrieve a Gmail attachment as base64url data (governed route: gmail.get_gmail_attachment)."""
    payload = {k: v for k, v in {
        "message_id": message_id,
        "attachment_id": attachment_id,
        "filename": filename,
        "mime_type": mime_type,
    }.items() if v is not None}
    return workspace_tool_route("get_gmail_attachment", payload, token_route)

@mcp.tool()
def download_gmail_attachment(message_id: str, attachment_id: str, output_path: str | None = None, filename: str | None = None, mime_type: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Download a Gmail attachment to a governed local file path (governed route: gmail.download_gmail_attachment)."""
    payload = {k: v for k, v in {
        "message_id": message_id,
        "attachment_id": attachment_id,
        "output_path": output_path,
        "filename": filename,
        "mime_type": mime_type,
    }.items() if v is not None}
    return workspace_tool_route("download_gmail_attachment", payload, token_route)

@mcp.tool()
def get_gmail_messages_content_batch(message_ids: list[str], format: Any = "full", body_format: Any = "text", token_route: str | None = None) -> dict[str, Any]:
    """Batch retrieve message content (governed route: gmail.get_gmail_messages_content_batch)."""
    payload = {k: v for k, v in {
        "message_ids": message_ids,
        "format": format,
        "body_format": body_format,
    }.items() if v is not None}
    return workspace_tool_route("get_gmail_messages_content_batch", payload, token_route)

@mcp.tool()
def send_gmail_message(to: str, subject: str | None = None, body: str | None = None, body_format: Any = "plain", forward_message_id: str | None = None, include_forwarded_attachments: bool = True, cc: str | None = None, bcc: str | None = None, from_name: str | None = None, from_email: str | None = None, thread_id: str | None = None, in_reply_to: str | None = None, references: str | None = None, attachments: list[dict[str, Any]] | None = None, include_signature: bool = True, token_route: str | None = None) -> dict[str, Any]:
    """Send emails (governed route: gmail.send_gmail_message)."""
    payload = {k: v for k, v in {
        "to": to,
        "subject": subject,
        "body": body,
        "body_format": body_format,
        "forward_message_id": forward_message_id,
        "include_forwarded_attachments": include_forwarded_attachments,
        "cc": cc,
        "bcc": bcc,
        "from_name": from_name,
        "from_email": from_email,
        "thread_id": thread_id,
        "in_reply_to": in_reply_to,
        "references": references,
        "attachments": attachments,
        "include_signature": include_signature,
    }.items() if v is not None}
    return workspace_tool_route("send_gmail_message", payload, token_route)

@mcp.tool()
def get_gmail_thread_content(thread_id: str, body_format: Any = "text", include_analysis: bool = False, token_route: str | None = None) -> dict[str, Any]:
    """Get full thread content (governed route: gmail.get_gmail_thread_content)."""
    payload = {k: v for k, v in {
        "thread_id": thread_id,
        "body_format": body_format,
        "include_analysis": include_analysis,
    }.items() if v is not None}
    return workspace_tool_route("get_gmail_thread_content", payload, token_route)

@mcp.tool()
def modify_gmail_message_labels(message_id: str, add_label_ids: list[str] | None = None, remove_label_ids: list[str] | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Modify message labels (governed route: gmail.modify_gmail_message_labels)."""
    payload = {k: v for k, v in {
        "message_id": message_id,
        "add_label_ids": add_label_ids,
        "remove_label_ids": remove_label_ids,
    }.items() if v is not None}
    return workspace_tool_route("modify_gmail_message_labels", payload, token_route)

@mcp.tool()
def list_gmail_labels(token_route: str | None = None) -> dict[str, Any]:
    """List available labels (governed route: gmail.list_gmail_labels)."""
    payload = {}
    return workspace_tool_route("list_gmail_labels", payload, token_route)

@mcp.tool()
def list_gmail_filters(token_route: str | None = None) -> dict[str, Any]:
    """List Gmail filters (governed route: gmail.list_gmail_filters)."""
    payload = {}
    return workspace_tool_route("list_gmail_filters", payload, token_route)

@mcp.tool()
def manage_gmail_label(action: Any, name: str | None = None, label_id: str | None = None, label_list_visibility: Any = "labelShow", message_list_visibility: Any = "show", token_route: str | None = None) -> dict[str, Any]:
    """Create/update/delete labels (governed route: gmail.manage_gmail_label)."""
    payload = {k: v for k, v in {
        "action": action,
        "name": name,
        "label_id": label_id,
        "label_list_visibility": label_list_visibility,
        "message_list_visibility": message_list_visibility,
    }.items() if v is not None}
    return workspace_tool_route("manage_gmail_label", payload, token_route)

@mcp.tool()
def manage_gmail_filter(action: str, criteria: dict[str, Any] | None = None, filter_action: dict[str, Any] | None = None, filter_id: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Create or delete Gmail filters (governed route: gmail.manage_gmail_filter)."""
    payload = {k: v for k, v in {
        "action": action,
        "criteria": criteria,
        "filter_action": filter_action,
        "filter_id": filter_id,
    }.items() if v is not None}
    return workspace_tool_route("manage_gmail_filter", payload, token_route)

@mcp.tool()
def draft_gmail_message(subject: str, body: str, body_format: Any = "plain", to: str | None = None, cc: str | None = None, bcc: str | None = None, from_name: str | None = None, from_email: str | None = None, thread_id: str | None = None, in_reply_to: str | None = None, references: str | None = None, attachments: list[dict[str, Any]] | None = None, include_signature: bool = True, quote_original: bool = False, token_route: str | None = None) -> dict[str, Any]:
    """Create drafts (governed route: gmail.draft_gmail_message)."""
    payload = {k: v for k, v in {
        "subject": subject,
        "body": body,
        "body_format": body_format,
        "to": to,
        "cc": cc,
        "bcc": bcc,
        "from_name": from_name,
        "from_email": from_email,
        "thread_id": thread_id,
        "in_reply_to": in_reply_to,
        "references": references,
        "attachments": attachments,
        "include_signature": include_signature,
        "quote_original": quote_original,
    }.items() if v is not None}
    return workspace_tool_route("draft_gmail_message", payload, token_route)

@mcp.tool()
def get_gmail_threads_content_batch(thread_ids: list[str], body_format: Any = "text", token_route: str | None = None) -> dict[str, Any]:
    """Batch retrieve thread content (governed route: gmail.get_gmail_threads_content_batch)."""
    payload = {k: v for k, v in {
        "thread_ids": thread_ids,
        "body_format": body_format,
    }.items() if v is not None}
    return workspace_tool_route("get_gmail_threads_content_batch", payload, token_route)

@mcp.tool()
def batch_modify_gmail_message_labels(message_ids: list[str], add_label_ids: list[str] | None = None, remove_label_ids: list[str] | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Batch modify labels (governed route: gmail.batch_modify_gmail_message_labels)."""
    payload = {k: v for k, v in {
        "message_ids": message_ids,
        "add_label_ids": add_label_ids,
        "remove_label_ids": remove_label_ids,
    }.items() if v is not None}
    return workspace_tool_route("batch_modify_gmail_message_labels", payload, token_route)

@mcp.tool()
def start_google_auth(service_name: str, token_route: str | None = None) -> dict[str, Any]:
    """Legacy OAuth 2.0 auth (disabled when OAuth 2.1 is enabled) (governed route: gmail.start_google_auth)."""
    payload = {k: v for k, v in {
        "service_name": service_name,
    }.items() if v is not None}
    return workspace_tool_route("start_google_auth", payload, token_route)

@mcp.tool()
def get_doc_content(document_id: str, suggestions_view_mode: str = "DEFAULT_FOR_CURRENT_ACCESS", token_route: str | None = None) -> dict[str, Any]:
    """Extract document text (governed route: docs.get_doc_content)."""
    payload = {k: v for k, v in {
        "document_id": document_id,
        "suggestions_view_mode": suggestions_view_mode,
    }.items() if v is not None}
    return workspace_tool_route("get_doc_content", payload, token_route)

@mcp.tool()
def create_doc(title: str, content: str = "", token_route: str | None = None) -> dict[str, Any]:
    """Create new documents (governed route: docs.create_doc)."""
    payload = {k: v for k, v in {
        "title": title,
        "content": content,
    }.items() if v is not None}
    return workspace_tool_route("create_doc", payload, token_route)

@mcp.tool()
def modify_doc_text(document_id: str, start_index: int, end_index: int = None, text: str = None, tab_id: str = None, segment_id: str = None, end_of_segment: bool = False, bold: bool = None, italic: bool = None, underline: bool = None, strikethrough: bool = None, font_size: int = None, font_family: str = None, font_weight: int = None, text_color: str = None, background_color: str = None, link_url: str = None, clear_link: bool = None, baseline_offset: str = None, small_caps: bool = None, token_route: str | None = None) -> dict[str, Any]:
    """Insert, replace, and richly format text with tab/segment targeting, append-to-segment support, advanced typography, and link management (governed route: docs.modify_doc_text)."""
    payload = {k: v for k, v in {
        "document_id": document_id,
        "start_index": start_index,
        "end_index": end_index,
        "text": text,
        "tab_id": tab_id,
        "segment_id": segment_id,
        "end_of_segment": end_of_segment,
        "bold": bold,
        "italic": italic,
        "underline": underline,
        "strikethrough": strikethrough,
        "font_size": font_size,
        "font_family": font_family,
        "font_weight": font_weight,
        "text_color": text_color,
        "background_color": background_color,
        "link_url": link_url,
        "clear_link": clear_link,
        "baseline_offset": baseline_offset,
        "small_caps": small_caps,
    }.items() if v is not None}
    return workspace_tool_route("modify_doc_text", payload, token_route)

@mcp.tool()
def search_docs(query: str, page_size: int = 10, token_route: str | None = None) -> dict[str, Any]:
    """Find documents by name (governed route: docs.search_docs)."""
    payload = {k: v for k, v in {
        "query": query,
        "page_size": page_size,
    }.items() if v is not None}
    return workspace_tool_route("search_docs", payload, token_route)

@mcp.tool()
def find_and_replace_doc(document_id: str, find_text: str, replace_text: str, match_case: bool = False, tab_id: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Find and replace text (governed route: docs.find_and_replace_doc)."""
    payload = {k: v for k, v in {
        "document_id": document_id,
        "find_text": find_text,
        "replace_text": replace_text,
        "match_case": match_case,
        "tab_id": tab_id,
    }.items() if v is not None}
    return workspace_tool_route("find_and_replace_doc", payload, token_route)

@mcp.tool()
def list_docs_in_folder(folder_id: str = "root", page_size: int = 100, token_route: str | None = None) -> dict[str, Any]:
    """List docs in folder (governed route: docs.list_docs_in_folder)."""
    payload = {k: v for k, v in {
        "folder_id": folder_id,
        "page_size": page_size,
    }.items() if v is not None}
    return workspace_tool_route("list_docs_in_folder", payload, token_route)

@mcp.tool()
def insert_doc_elements(document_id: str, element_type: str, index: int, rows: int = None, columns: int = None, list_type: str = None, text: str = None, token_route: str | None = None) -> dict[str, Any]:
    """Add tables, lists, page breaks (governed route: docs.insert_doc_elements)."""
    payload = {k: v for k, v in {
        "document_id": document_id,
        "element_type": element_type,
        "index": index,
        "rows": rows,
        "columns": columns,
        "list_type": list_type,
        "text": text,
    }.items() if v is not None}
    return workspace_tool_route("insert_doc_elements", payload, token_route)

@mcp.tool()
def update_paragraph_style(document_id: str, start_index: int, end_index: int, heading_level: int = None, alignment: str = None, line_spacing: float = None, indent_first_line: float = None, indent_start: float = None, indent_end: float = None, space_above: float = None, space_below: float = None, named_style_type: str = None, tab_id: str = None, segment_id: str = None, direction: str = None, keep_lines_together: bool = None, keep_with_next: bool = None, avoid_widow_and_orphan: bool = None, page_break_before: bool = None, spacing_mode: str = None, shading_color: str = None, list_type: str = None, list_nesting_level: int = None, bullet_preset: str = None, token_route: str | None = None) -> dict[str, Any]:
    """Apply advanced paragraph styling including headings, spacing, direction, pagination controls, shading, and bulleted/numbered/checkbox lists with nesting (governed route: docs.update_paragraph_style)."""
    payload = {k: v for k, v in {
        "document_id": document_id,
        "start_index": start_index,
        "end_index": end_index,
        "heading_level": heading_level,
        "alignment": alignment,
        "line_spacing": line_spacing,
        "indent_first_line": indent_first_line,
        "indent_start": indent_start,
        "indent_end": indent_end,
        "space_above": space_above,
        "space_below": space_below,
        "named_style_type": named_style_type,
        "tab_id": tab_id,
        "segment_id": segment_id,
        "direction": direction,
        "keep_lines_together": keep_lines_together,
        "keep_with_next": keep_with_next,
        "avoid_widow_and_orphan": avoid_widow_and_orphan,
        "page_break_before": page_break_before,
        "spacing_mode": spacing_mode,
        "shading_color": shading_color,
        "list_type": list_type,
        "list_nesting_level": list_nesting_level,
        "bullet_preset": bullet_preset,
    }.items() if v is not None}
    return workspace_tool_route("update_paragraph_style", payload, token_route)

@mcp.tool()
def get_doc_as_markdown(document_id: str, include_comments: bool = True, comment_mode: str = "inline", include_resolved: bool = False, suggestions_view_mode: str = "DEFAULT_FOR_CURRENT_ACCESS", token_route: str | None = None) -> dict[str, Any]:
    """Export document as formatted Markdown with optional comments (governed route: docs.get_doc_as_markdown)."""
    payload = {k: v for k, v in {
        "document_id": document_id,
        "include_comments": include_comments,
        "comment_mode": comment_mode,
        "include_resolved": include_resolved,
        "suggestions_view_mode": suggestions_view_mode,
    }.items() if v is not None}
    return workspace_tool_route("get_doc_as_markdown", payload, token_route)

@mcp.tool()
def insert_doc_image(document_id: str, image_source: str, index: int, width: int = 0, height: int = 0, token_route: str | None = None) -> dict[str, Any]:
    """Insert images from Drive/URLs (governed route: docs.insert_doc_image)."""
    payload = {k: v for k, v in {
        "document_id": document_id,
        "image_source": image_source,
        "index": index,
        "width": width,
        "height": height,
    }.items() if v is not None}
    return workspace_tool_route("insert_doc_image", payload, token_route)

@mcp.tool()
def update_doc_headers_footers(document_id: str, section_type: str, content: str, header_footer_type: str = "DEFAULT", token_route: str | None = None) -> dict[str, Any]:
    """Create or update headers and footers with correct segment-aware writes (governed route: docs.update_doc_headers_footers)."""
    payload = {k: v for k, v in {
        "document_id": document_id,
        "section_type": section_type,
        "content": content,
        "header_footer_type": header_footer_type,
    }.items() if v is not None}
    return workspace_tool_route("update_doc_headers_footers", payload, token_route)

@mcp.tool()
def batch_update_doc(document_id: str, operations: Any, token_route: str | None = None) -> dict[str, Any]:
    """Execute atomic multi-step Docs API operations including named ranges, section breaks, document/section layout, header/footer creation, segment-aware inserts, images, tables, and rich formatting (governed route: docs.batch_update_doc)."""
    payload = {k: v for k, v in {
        "document_id": document_id,
        "operations": operations,
    }.items() if v is not None}
    return workspace_tool_route("batch_update_doc", payload, token_route)

@mcp.tool()
def inspect_doc_structure(document_id: str, detailed: bool = False, tab_id: str = None, token_route: str | None = None) -> dict[str, Any]:
    """Analyze document structure, including safe insertion points, tables, section breaks, headers/footers, and named ranges (governed route: docs.inspect_doc_structure)."""
    payload = {k: v for k, v in {
        "document_id": document_id,
        "detailed": detailed,
        "tab_id": tab_id,
    }.items() if v is not None}
    return workspace_tool_route("inspect_doc_structure", payload, token_route)

@mcp.tool()
def export_doc_to_pdf(document_id: str, pdf_filename: str = None, folder_id: str = None, token_route: str | None = None) -> dict[str, Any]:
    """Export document to PDF (governed route: docs.export_doc_to_pdf)."""
    payload = {k: v for k, v in {
        "document_id": document_id,
        "pdf_filename": pdf_filename,
        "folder_id": folder_id,
    }.items() if v is not None}
    return workspace_tool_route("export_doc_to_pdf", payload, token_route)

@mcp.tool()
def create_table_with_data(document_id: str, table_data: list[str], index: int, bold_headers: bool = True, tab_id: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Create data tables (governed route: docs.create_table_with_data)."""
    payload = {k: v for k, v in {
        "document_id": document_id,
        "table_data": table_data,
        "index": index,
        "bold_headers": bold_headers,
        "tab_id": tab_id,
    }.items() if v is not None}
    return workspace_tool_route("create_table_with_data", payload, token_route)

@mcp.tool()
def debug_table_structure(document_id: str, table_index: int = 0, token_route: str | None = None) -> dict[str, Any]:
    """Debug table issues (governed route: docs.debug_table_structure)."""
    payload = {k: v for k, v in {
        "document_id": document_id,
        "table_index": table_index,
    }.items() if v is not None}
    return workspace_tool_route("debug_table_structure", payload, token_route)

@mcp.tool()
def list_document_comments(document_id: str, token_route: str | None = None) -> dict[str, Any]:
    """List all document comments (governed route: docs.list_document_comments)."""
    payload = {k: v for k, v in {
        "document_id": document_id,
    }.items() if v is not None}
    return workspace_tool_route("list_document_comments", payload, token_route)

@mcp.tool()
def manage_document_comment(document_id: str, operation: str = "create", comment_id: str | None = None, content: str | None = None, text: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Create, reply to, or resolve comments (governed route: docs.manage_document_comment)."""
    payload = {k: v for k, v in {
        "document_id": document_id,
        "operation": operation,
        "comment_id": comment_id,
        "content": content,
        "text": text,
    }.items() if v is not None}
    return workspace_tool_route("manage_document_comment", payload, token_route)

@mcp.tool()
def manage_doc_tab(document_id: str, action: Any, tab_id: str | None = None, title: str | None = None, index: int | None = None, parent_tab_id: str | None = None, markdown_text: str | None = None, replace_existing: bool = True, token_route: str | None = None) -> dict[str, Any]:
    """Create, rename, delete, or populate tabs from markdown (governed route: docs.manage_doc_tab)."""
    payload = {k: v for k, v in {
        "document_id": document_id,
        "action": action,
        "tab_id": tab_id,
        "title": title,
        "index": index,
        "parent_tab_id": parent_tab_id,
        "markdown_text": markdown_text,
        "replace_existing": replace_existing,
    }.items() if v is not None}
    return workspace_tool_route("manage_doc_tab", payload, token_route)

@mcp.tool()
def read_sheet_values(spreadsheet_id: str, range_name: str = "A1:Z1000", include_hyperlinks: bool = False, include_notes: bool = False, include_formulas: bool = False, token_route: str | None = None) -> dict[str, Any]:
    """Read cell ranges (governed route: sheets.read_sheet_values)."""
    payload = {k: v for k, v in {
        "spreadsheet_id": spreadsheet_id,
        "range_name": range_name,
        "include_hyperlinks": include_hyperlinks,
        "include_notes": include_notes,
        "include_formulas": include_formulas,
    }.items() if v is not None}
    return workspace_tool_route("read_sheet_values", payload, token_route)

@mcp.tool()
def modify_sheet_values(spreadsheet_id: str, range_name: str, values: Any | None = None, value_input_option: str = "USER_ENTERED", clear_values: bool = False, token_route: str | None = None) -> dict[str, Any]:
    """Write/update/clear cells (governed route: sheets.modify_sheet_values)."""
    payload = {k: v for k, v in {
        "spreadsheet_id": spreadsheet_id,
        "range_name": range_name,
        "values": values,
        "value_input_option": value_input_option,
        "clear_values": clear_values,
    }.items() if v is not None}
    return workspace_tool_route("modify_sheet_values", payload, token_route)

@mcp.tool()
def create_spreadsheet(title: str, sheet_names: list[str] | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Create new spreadsheets (governed route: sheets.create_spreadsheet)."""
    payload = {k: v for k, v in {
        "title": title,
        "sheet_names": sheet_names,
    }.items() if v is not None}
    return workspace_tool_route("create_spreadsheet", payload, token_route)

@mcp.tool()
def list_spreadsheets(max_results: int = 25, token_route: str | None = None) -> dict[str, Any]:
    """List accessible spreadsheets (governed route: sheets.list_spreadsheets)."""
    payload = {k: v for k, v in {
        "max_results": max_results,
    }.items() if v is not None}
    return workspace_tool_route("list_spreadsheets", payload, token_route)

@mcp.tool()
def get_spreadsheet_info(spreadsheet_id: str, token_route: str | None = None) -> dict[str, Any]:
    """Get spreadsheet metadata (governed route: sheets.get_spreadsheet_info)."""
    payload = {k: v for k, v in {
        "spreadsheet_id": spreadsheet_id,
    }.items() if v is not None}
    return workspace_tool_route("get_spreadsheet_info", payload, token_route)

@mcp.tool()
def format_sheet_range(spreadsheet_id: str, range_name: str, background_color: str | None = None, text_color: str | None = None, number_format_type: str | None = None, number_format_pattern: str | None = None, wrap_strategy: str | None = None, horizontal_alignment: str | None = None, vertical_alignment: str | None = None, bold: bool | None = None, italic: bool | None = None, font_size: int | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Apply colors, number formats, text wrapping, alignment, bold/italic, font size (governed route: sheets.format_sheet_range)."""
    payload = {k: v for k, v in {
        "spreadsheet_id": spreadsheet_id,
        "range_name": range_name,
        "background_color": background_color,
        "text_color": text_color,
        "number_format_type": number_format_type,
        "number_format_pattern": number_format_pattern,
        "wrap_strategy": wrap_strategy,
        "horizontal_alignment": horizontal_alignment,
        "vertical_alignment": vertical_alignment,
        "bold": bold,
        "italic": italic,
        "font_size": font_size,
    }.items() if v is not None}
    return workspace_tool_route("format_sheet_range", payload, token_route)

@mcp.tool()
def list_sheet_tables(spreadsheet_id: str, token_route: str | None = None) -> dict[str, Any]:
    """List structured tables with IDs, names, ranges, and columns (governed route: sheets.list_sheet_tables)."""
    payload = {k: v for k, v in {
        "spreadsheet_id": spreadsheet_id,
    }.items() if v is not None}
    return workspace_tool_route("list_sheet_tables", payload, token_route)

@mcp.tool()
def create_sheet(spreadsheet_id: str, sheet_name: str | None = None, source_sheet_name: str | None = None, insert_sheet_index: int | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Add sheets to existing files (governed route: sheets.create_sheet)."""
    payload = {k: v for k, v in {
        "spreadsheet_id": spreadsheet_id,
        "sheet_name": sheet_name,
        "source_sheet_name": source_sheet_name,
        "insert_sheet_index": insert_sheet_index,
    }.items() if v is not None}
    return workspace_tool_route("create_sheet", payload, token_route)

@mcp.tool()
def move_sheet_rows(spreadsheet_id: str, source_sheet: str, start_row: int, end_row: int, destination_sheet: str, token_route: str | None = None) -> dict[str, Any]:
    """Move rows between sheets within a spreadsheet (governed route: sheets.move_sheet_rows)."""
    payload = {k: v for k, v in {
        "spreadsheet_id": spreadsheet_id,
        "source_sheet": source_sheet,
        "start_row": start_row,
        "end_row": end_row,
        "destination_sheet": destination_sheet,
    }.items() if v is not None}
    return workspace_tool_route("move_sheet_rows", payload, token_route)

@mcp.tool()
def append_table_rows(spreadsheet_id: str, table_id: str, values: Any, token_route: str | None = None) -> dict[str, Any]:
    """Append rows to a structured table, auto-extending the table range (governed route: sheets.append_table_rows)."""
    payload = {k: v for k, v in {
        "spreadsheet_id": spreadsheet_id,
        "table_id": table_id,
        "values": values,
    }.items() if v is not None}
    return workspace_tool_route("append_table_rows", payload, token_route)

@mcp.tool()
def list_spreadsheet_comments(spreadsheet_id: str, token_route: str | None = None) -> dict[str, Any]:
    """List all spreadsheet comments (governed route: sheets.list_spreadsheet_comments)."""
    payload = {k: v for k, v in {
        "spreadsheet_id": spreadsheet_id,
    }.items() if v is not None}
    return workspace_tool_route("list_spreadsheet_comments", payload, token_route)

@mcp.tool()
def manage_spreadsheet_comment(spreadsheet_id: str, operation: str = "create", comment_id: str | None = None, content: str | None = None, text: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Create, reply to, or resolve comments (governed route: sheets.manage_spreadsheet_comment)."""
    payload = {k: v for k, v in {
        "spreadsheet_id": spreadsheet_id,
        "operation": operation,
        "comment_id": comment_id,
        "content": content,
        "text": text,
    }.items() if v is not None}
    return workspace_tool_route("manage_spreadsheet_comment", payload, token_route)

@mcp.tool()
def manage_conditional_formatting(spreadsheet_id: str, action: str, range_name: str | None = None, condition_type: str | None = None, condition_values: Any | None = None, background_color: str | None = None, text_color: str | None = None, rule_index: int | None = None, gradient_points: Any | None = None, sheet_name: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Add, update, or delete conditional formatting rules (governed route: sheets.manage_conditional_formatting)."""
    payload = {k: v for k, v in {
        "spreadsheet_id": spreadsheet_id,
        "action": action,
        "range_name": range_name,
        "condition_type": condition_type,
        "condition_values": condition_values,
        "background_color": background_color,
        "text_color": text_color,
        "rule_index": rule_index,
        "gradient_points": gradient_points,
        "sheet_name": sheet_name,
    }.items() if v is not None}
    return workspace_tool_route("manage_conditional_formatting", payload, token_route)

@mcp.tool()
def create_presentation(title: str = "Untitled Presentation", token_route: str | None = None) -> dict[str, Any]:
    """Create new presentations (governed route: slides.create_presentation)."""
    payload = {k: v for k, v in {
        "title": title,
    }.items() if v is not None}
    return workspace_tool_route("create_presentation", payload, token_route)

@mcp.tool()
def get_presentation(presentation_id: str, token_route: str | None = None) -> dict[str, Any]:
    """Retrieve presentation details (governed route: slides.get_presentation)."""
    payload = {k: v for k, v in {
        "presentation_id": presentation_id,
    }.items() if v is not None}
    return workspace_tool_route("get_presentation", payload, token_route)

@mcp.tool()
def batch_update_presentation(presentation_id: str, requests: list[dict[str, Any]], token_route: str | None = None) -> dict[str, Any]:
    """Apply multiple updates (governed route: slides.batch_update_presentation)."""
    payload = {k: v for k, v in {
        "presentation_id": presentation_id,
        "requests": requests,
    }.items() if v is not None}
    return workspace_tool_route("batch_update_presentation", payload, token_route)

@mcp.tool()
def get_page(presentation_id: str, page_object_id: str, token_route: str | None = None) -> dict[str, Any]:
    """Get specific slide information (governed route: slides.get_page)."""
    payload = {k: v for k, v in {
        "presentation_id": presentation_id,
        "page_object_id": page_object_id,
    }.items() if v is not None}
    return workspace_tool_route("get_page", payload, token_route)

@mcp.tool()
def get_page_thumbnail(presentation_id: str, page_object_id: str, thumbnail_size: str = "MEDIUM", token_route: str | None = None) -> dict[str, Any]:
    """Generate slide thumbnails (governed route: slides.get_page_thumbnail)."""
    payload = {k: v for k, v in {
        "presentation_id": presentation_id,
        "page_object_id": page_object_id,
        "thumbnail_size": thumbnail_size,
    }.items() if v is not None}
    return workspace_tool_route("get_page_thumbnail", payload, token_route)

@mcp.tool()
def list_presentation_comments(presentation_id: str, token_route: str | None = None) -> dict[str, Any]:
    """List all presentation comments (governed route: slides.list_presentation_comments)."""
    payload = {k: v for k, v in {
        "presentation_id": presentation_id,
    }.items() if v is not None}
    return workspace_tool_route("list_presentation_comments", payload, token_route)

@mcp.tool()
def manage_presentation_comment(presentation_id: str, operation: str = "create", comment_id: str | None = None, content: str | None = None, text: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Create, reply to, or resolve comments (governed route: slides.manage_presentation_comment)."""
    payload = {k: v for k, v in {
        "presentation_id": presentation_id,
        "operation": operation,
        "comment_id": comment_id,
        "content": content,
        "text": text,
    }.items() if v is not None}
    return workspace_tool_route("manage_presentation_comment", payload, token_route)

@mcp.tool()
def create_form(title: str, description: str | None = None, document_title: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Create new forms (governed route: forms.create_form)."""
    payload = {k: v for k, v in {
        "title": title,
        "description": description,
        "document_title": document_title,
    }.items() if v is not None}
    return workspace_tool_route("create_form", payload, token_route)

@mcp.tool()
def get_form(form_id: str, token_route: str | None = None) -> dict[str, Any]:
    """Retrieve form details & URLs (governed route: forms.get_form)."""
    payload = {k: v for k, v in {
        "form_id": form_id,
    }.items() if v is not None}
    return workspace_tool_route("get_form", payload, token_route)

@mcp.tool()
def set_publish_settings(form_id: str, is_published: bool = True, is_accepting_responses: bool = True, token_route: str | None = None) -> dict[str, Any]:
    """Configure form settings (governed route: forms.set_publish_settings)."""
    payload = {k: v for k, v in {
        "form_id": form_id,
        "is_published": is_published,
        "is_accepting_responses": is_accepting_responses,
    }.items() if v is not None}
    return workspace_tool_route("set_publish_settings", payload, token_route)

@mcp.tool()
def get_form_response(form_id: str, response_id: str, token_route: str | None = None) -> dict[str, Any]:
    """Get individual responses (governed route: forms.get_form_response)."""
    payload = {k: v for k, v in {
        "form_id": form_id,
        "response_id": response_id,
    }.items() if v is not None}
    return workspace_tool_route("get_form_response", payload, token_route)

@mcp.tool()
def list_form_responses(form_id: str, page_size: int = 10, page_token: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """List all responses with pagination (governed route: forms.list_form_responses)."""
    payload = {k: v for k, v in {
        "form_id": form_id,
        "page_size": page_size,
        "page_token": page_token,
    }.items() if v is not None}
    return workspace_tool_route("list_form_responses", payload, token_route)

@mcp.tool()
def batch_update_form(form_id: str, requests: list[dict[str, Any]], token_route: str | None = None) -> dict[str, Any]:
    """Apply batch updates (questions, settings) (governed route: forms.batch_update_form)."""
    payload = {k: v for k, v in {
        "form_id": form_id,
        "requests": requests,
    }.items() if v is not None}
    return workspace_tool_route("batch_update_form", payload, token_route)

@mcp.tool()
def list_tasks(task_list_id: str, max_results: int = None, page_token: str | None = None, show_completed: bool = True, show_deleted: bool = False, show_hidden: bool = False, show_assigned: bool = False, completed_max: str | None = None, completed_min: str | None = None, due_max: str | None = None, due_min: str | None = None, updated_min: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """List tasks with filtering (governed route: tasks.list_tasks)."""
    payload = {k: v for k, v in {
        "task_list_id": task_list_id,
        "max_results": max_results,
        "page_token": page_token,
        "show_completed": show_completed,
        "show_deleted": show_deleted,
        "show_hidden": show_hidden,
        "show_assigned": show_assigned,
        "completed_max": completed_max,
        "completed_min": completed_min,
        "due_max": due_max,
        "due_min": due_min,
        "updated_min": updated_min,
    }.items() if v is not None}
    return workspace_tool_route("list_tasks", payload, token_route)

@mcp.tool()
def get_task(task_list_id: str, task_id: str, token_route: str | None = None) -> dict[str, Any]:
    """Retrieve task details (governed route: tasks.get_task)."""
    payload = {k: v for k, v in {
        "task_list_id": task_list_id,
        "task_id": task_id,
    }.items() if v is not None}
    return workspace_tool_route("get_task", payload, token_route)

@mcp.tool()
def manage_task(action: str, task_list_id: str, task_id: str | None = None, title: str | None = None, notes: str | None = None, status: str | None = None, due: str | None = None, parent: str | None = None, previous: str | None = None, destination_task_list: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Create, update, delete, or move tasks (governed route: tasks.manage_task)."""
    payload = {k: v for k, v in {
        "action": action,
        "task_list_id": task_list_id,
        "task_id": task_id,
        "title": title,
        "notes": notes,
        "status": status,
        "due": due,
        "parent": parent,
        "previous": previous,
        "destination_task_list": destination_task_list,
    }.items() if v is not None}
    return workspace_tool_route("manage_task", payload, token_route)

@mcp.tool()
def list_task_lists(max_results: int = 1000, page_token: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """List task lists (governed route: tasks.list_task_lists)."""
    payload = {k: v for k, v in {
        "max_results": max_results,
        "page_token": page_token,
    }.items() if v is not None}
    return workspace_tool_route("list_task_lists", payload, token_route)

@mcp.tool()
def get_task_list(task_list_id: str, token_route: str | None = None) -> dict[str, Any]:
    """Get task list details (governed route: tasks.get_task_list)."""
    payload = {k: v for k, v in {
        "task_list_id": task_list_id,
    }.items() if v is not None}
    return workspace_tool_route("get_task_list", payload, token_route)

@mcp.tool()
def manage_task_list(action: str, task_list_id: str | None = None, title: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Create, update, delete task lists, or clear completed tasks (governed route: tasks.manage_task_list)."""
    payload = {k: v for k, v in {
        "action": action,
        "task_list_id": task_list_id,
        "title": title,
    }.items() if v is not None}
    return workspace_tool_route("manage_task_list", payload, token_route)

@mcp.tool()
def search_contacts(query: str, page_size: int = 30, token_route: str | None = None) -> dict[str, Any]:
    """Search contacts by name, email, phone (governed route: contacts.search_contacts)."""
    payload = {k: v for k, v in {
        "query": query,
        "page_size": page_size,
    }.items() if v is not None}
    return workspace_tool_route("search_contacts", payload, token_route)

@mcp.tool()
def get_contact(contact_id: str, token_route: str | None = None) -> dict[str, Any]:
    """Retrieve detailed contact info (governed route: contacts.get_contact)."""
    payload = {k: v for k, v in {
        "contact_id": contact_id,
    }.items() if v is not None}
    return workspace_tool_route("get_contact", payload, token_route)

@mcp.tool()
def list_contacts(page_size: int = 100, page_token: str | None = None, sort_order: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """List contacts with pagination (governed route: contacts.list_contacts)."""
    payload = {k: v for k, v in {
        "page_size": page_size,
        "page_token": page_token,
        "sort_order": sort_order,
    }.items() if v is not None}
    return workspace_tool_route("list_contacts", payload, token_route)

@mcp.tool()
def manage_contact(action: Any, contact_id: str | None = None, given_name: str | None = None, family_name: str | None = None, phones: list[Any] | None = None, emails: list[Any] | None = None, organizations: list[Any] | None = None, nicknames: list[Any] | None = None, urls: list[Any] | None = None, user_defined: list[Any] | None = None, relations: list[Any] | None = None, notes: str | None = None, address: str | None = None, birthday: str | None = None, phones_mode: Any = "merge", emails_mode: Any = "merge", organizations_mode: Any = "merge", nicknames_mode: Any = "merge", urls_mode: Any = "merge", user_defined_mode: Any = "merge", relations_mode: Any = "merge", phone: str | None = None, email: str | None = None, organization: str | None = None, job_title: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Create, update, or delete contacts (governed route: contacts.manage_contact)."""
    payload = {k: v for k, v in {
        "action": action,
        "contact_id": contact_id,
        "given_name": given_name,
        "family_name": family_name,
        "phones": phones,
        "emails": emails,
        "organizations": organizations,
        "nicknames": nicknames,
        "urls": urls,
        "user_defined": user_defined,
        "relations": relations,
        "notes": notes,
        "address": address,
        "birthday": birthday,
        "phones_mode": phones_mode,
        "emails_mode": emails_mode,
        "organizations_mode": organizations_mode,
        "nicknames_mode": nicknames_mode,
        "urls_mode": urls_mode,
        "user_defined_mode": user_defined_mode,
        "relations_mode": relations_mode,
        "phone": phone,
        "email": email,
        "organization": organization,
        "job_title": job_title,
    }.items() if v is not None}
    return workspace_tool_route("manage_contact", payload, token_route)

@mcp.tool()
def list_contact_groups(page_size: int = 100, page_token: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """List contact groups/labels (governed route: contacts.list_contact_groups)."""
    payload = {k: v for k, v in {
        "page_size": page_size,
        "page_token": page_token,
    }.items() if v is not None}
    return workspace_tool_route("list_contact_groups", payload, token_route)

@mcp.tool()
def get_contact_group(group_id: str, max_members: int = 100, token_route: str | None = None) -> dict[str, Any]:
    """Get group details with members (governed route: contacts.get_contact_group)."""
    payload = {k: v for k, v in {
        "group_id": group_id,
        "max_members": max_members,
    }.items() if v is not None}
    return workspace_tool_route("get_contact_group", payload, token_route)

@mcp.tool()
def manage_contacts_batch(action: Any, contacts: list[Any] | None = None, updates: list[Any] | None = None, contact_ids: list[str] | None = None, field: Any | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Batch create, update, or delete contacts (governed route: contacts.manage_contacts_batch)."""
    payload = {k: v for k, v in {
        "action": action,
        "contacts": contacts,
        "updates": updates,
        "contact_ids": contact_ids,
        "field": field,
    }.items() if v is not None}
    return workspace_tool_route("manage_contacts_batch", payload, token_route)

@mcp.tool()
def manage_contact_group(action: str, group_id: str | None = None, name: str | None = None, delete_contacts: bool = False, add_contact_ids: list[str] | None = None, remove_contact_ids: list[str] | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Create, update, delete groups, or modify membership (governed route: contacts.manage_contact_group)."""
    payload = {k: v for k, v in {
        "action": action,
        "group_id": group_id,
        "name": name,
        "delete_contacts": delete_contacts,
        "add_contact_ids": add_contact_ids,
        "remove_contact_ids": remove_contact_ids,
    }.items() if v is not None}
    return workspace_tool_route("manage_contact_group", payload, token_route)

@mcp.tool()
def list_spaces(page_size: int = 100, space_type: str = "all", token_route: str | None = None) -> dict[str, Any]:
    """List chat spaces/rooms (governed route: chat.list_spaces)."""
    payload = {k: v for k, v in {
        "page_size": page_size,
        "space_type": space_type,
    }.items() if v is not None}
    return workspace_tool_route("list_spaces", payload, token_route)

@mcp.tool()
def get_messages(space_id: str, page_size: int = 50, order_by: str = "createTime desc", message_filter: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Retrieve space messages (governed route: chat.get_messages)."""
    payload = {k: v for k, v in {
        "space_id": space_id,
        "page_size": page_size,
        "order_by": order_by,
        "message_filter": message_filter,
    }.items() if v is not None}
    return workspace_tool_route("get_messages", payload, token_route)

@mcp.tool()
def send_message(space_id: str, message_text: str, thread_key: str | None = None, thread_name: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Send messages to spaces (governed route: chat.send_message)."""
    payload = {k: v for k, v in {
        "space_id": space_id,
        "message_text": message_text,
        "thread_key": thread_key,
        "thread_name": thread_name,
    }.items() if v is not None}
    return workspace_tool_route("send_message", payload, token_route)

@mcp.tool()
def search_messages(query: str | None = None, space_id: str | None = None, page_size: int = 25, time_filter: str | None = None, max_spaces: int = 10, token_route: str | None = None) -> dict[str, Any]:
    """Search across chat history (governed route: chat.search_messages)."""
    payload = {k: v for k, v in {
        "query": query,
        "space_id": space_id,
        "page_size": page_size,
        "time_filter": time_filter,
        "max_spaces": max_spaces,
    }.items() if v is not None}
    return workspace_tool_route("search_messages", payload, token_route)

@mcp.tool()
def create_reaction(message_id: str, emoji_unicode: str, token_route: str | None = None) -> dict[str, Any]:
    """Add emoji reaction to a message (governed route: chat.create_reaction)."""
    payload = {k: v for k, v in {
        "message_id": message_id,
        "emoji_unicode": emoji_unicode,
    }.items() if v is not None}
    return workspace_tool_route("create_reaction", payload, token_route)

@mcp.tool()
def download_chat_attachment(message_id: str, attachment_index: int = 0, token_route: str | None = None) -> dict[str, Any]:
    """Download attachment from a chat message (governed route: chat.download_chat_attachment)."""
    payload = {k: v for k, v in {
        "message_id": message_id,
        "attachment_index": attachment_index,
    }.items() if v is not None}
    return workspace_tool_route("download_chat_attachment", payload, token_route)

@mcp.tool()
def search_custom(q: str, num: int = 10, start: int = 1, safe: Any = "off", search_type: Any | None = None, site_search: str | None = None, site_search_filter: Any | None = None, date_restrict: str | None = None, file_type: str | None = None, language: str | None = None, country: str | None = None, sites: list[str] | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Perform web searches (supports site restrictions via sites parameter) (governed route: search.search_custom)."""
    payload = {k: v for k, v in {
        "q": q,
        "num": num,
        "start": start,
        "safe": safe,
        "search_type": search_type,
        "site_search": site_search,
        "site_search_filter": site_search_filter,
        "date_restrict": date_restrict,
        "file_type": file_type,
        "language": language,
        "country": country,
        "sites": sites,
    }.items() if v is not None}
    return workspace_tool_route("search_custom", payload, token_route)

@mcp.tool()
def get_search_engine_info(token_route: str | None = None) -> dict[str, Any]:
    """Retrieve search engine metadata (governed route: search.get_search_engine_info)."""
    payload = {}
    return workspace_tool_route("get_search_engine_info", payload, token_route)

@mcp.tool()
def list_script_projects(page_size: int = 50, page_token: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """List accessible Apps Script projects (governed route: apps_script.list_script_projects)."""
    payload = {k: v for k, v in {
        "page_size": page_size,
        "page_token": page_token,
    }.items() if v is not None}
    return workspace_tool_route("list_script_projects", payload, token_route)

@mcp.tool()
def get_script_project(script_id: str, token_route: str | None = None) -> dict[str, Any]:
    """Get complete project with all files (governed route: apps_script.get_script_project)."""
    payload = {k: v for k, v in {
        "script_id": script_id,
    }.items() if v is not None}
    return workspace_tool_route("get_script_project", payload, token_route)

@mcp.tool()
def get_script_content(script_id: str, file_name: str, token_route: str | None = None) -> dict[str, Any]:
    """Retrieve specific file content (governed route: apps_script.get_script_content)."""
    payload = {k: v for k, v in {
        "script_id": script_id,
        "file_name": file_name,
    }.items() if v is not None}
    return workspace_tool_route("get_script_content", payload, token_route)

@mcp.tool()
def create_script_project(title: str, parent_id: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Create new standalone or bound project (governed route: apps_script.create_script_project)."""
    payload = {k: v for k, v in {
        "title": title,
        "parent_id": parent_id,
    }.items() if v is not None}
    return workspace_tool_route("create_script_project", payload, token_route)

@mcp.tool()
def update_script_content(script_id: str, files: list[dict[str, Any]], token_route: str | None = None) -> dict[str, Any]:
    """Update or create script files (governed route: apps_script.update_script_content)."""
    payload = {k: v for k, v in {
        "script_id": script_id,
        "files": files,
    }.items() if v is not None}
    return workspace_tool_route("update_script_content", payload, token_route)

@mcp.tool()
def run_script_function(script_id: str, function_name: str, parameters: list[Any] | None = None, dev_mode: bool = False, token_route: str | None = None) -> dict[str, Any]:
    """Execute function with parameters (governed route: apps_script.run_script_function)."""
    payload = {k: v for k, v in {
        "script_id": script_id,
        "function_name": function_name,
        "parameters": parameters,
        "dev_mode": dev_mode,
    }.items() if v is not None}
    return workspace_tool_route("run_script_function", payload, token_route)

@mcp.tool()
def list_deployments(script_id: str, token_route: str | None = None) -> dict[str, Any]:
    """List all project deployments (governed route: apps_script.list_deployments)."""
    payload = {k: v for k, v in {
        "script_id": script_id,
    }.items() if v is not None}
    return workspace_tool_route("list_deployments", payload, token_route)

@mcp.tool()
def manage_deployment(action: str, script_id: str, deployment_id: str | None = None, description: str | None = None, version_description: str | None = None, version_number: int | None = None, token_route: str | None = None) -> dict[str, Any]:
    """Create, update, or delete script deployments (governed route: apps_script.manage_deployment)."""
    payload = {k: v for k, v in {
        "action": action,
        "script_id": script_id,
        "deployment_id": deployment_id,
        "description": description,
        "version_description": version_description,
        "version_number": version_number,
    }.items() if v is not None}
    return workspace_tool_route("manage_deployment", payload, token_route)

@mcp.tool()
def list_script_processes(page_size: int = 50, script_id: str | None = None, token_route: str | None = None) -> dict[str, Any]:
    """View recent executions and status (governed route: apps_script.list_script_processes)."""
    payload = {k: v for k, v in {
        "page_size": page_size,
        "script_id": script_id,
    }.items() if v is not None}
    return workspace_tool_route("list_script_processes", payload, token_route)


def main() -> None:
    transport = mcp_transport()
    if transport in {"streamable-http", "http"}:
        import uvicorn

        app = mcp.streamable_http_app()
        app.add_middleware(ProfileHeaderMiddleware)
        uvicorn.run(app, host=mcp_host(), port=mcp_port(), log_level="info")
        return
    mcp.run("stdio")


if __name__ == "__main__":
    main()
