#!/usr/bin/env python3
"""Offline tests for the protected Google governance control plane."""
from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import urllib.request
from pathlib import Path

PROJECT_DIR = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_DIR / "scripts" / "google_governance_control_plane.py"


def load_module():
    spec = importlib.util.spec_from_file_location("google_governance_control_plane_test", SCRIPT)
    if spec is None or spec.loader is None:
        raise SystemExit("could not load control plane")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    module = load_module()
    tmp = Path(tempfile.mkdtemp(prefix="google-gov-control-"))
    policy = tmp / "google-governance-policy.yaml"
    registry = tmp / "google-resource-registry.yaml"
    generated = tmp / "generated" / "profile_policy.json"
    runtime = tmp / "runtime" / "profile_policy.json"
    change_log = tmp / "policy-change-events.jsonl"
    approval_secret = tmp / "approval_admin_secret"
    control_users_json = tmp / "control_users.json"
    control_users_db = tmp / "control_users.sqlite"
    control_session_secret = tmp / "control_session_secret"
    gateway_audit = tmp / "unified-audit.jsonl"
    token_root = tmp / "tokens"
    oauth_root = tmp / "oauth"
    token_file = token_root / "accounts" / "workspace_primary" / "google_token.json"
    token_file.parent.mkdir(parents=True)
    token_file.write_text(json.dumps({"client_id": "test-client", "refresh_token": "refresh", "scopes": ["gmail", "drive"]}), encoding="utf-8")
    gateway_audit.write_text(
        json.dumps({"ts": "2026-01-01T00:00:00+00:00", "profile": "assistant", "action": "drive.share", "resource_alias": "drive_any", "decision": "deny", "status": "blocked", "request_id": "req-test"}) + "\n" +
        json.dumps({"ts": "2026-01-01T00:00:00+00:00", "profile": "assistant", "action": "drive.get", "resource_alias": "drive_any", "decision": "allow", "status": "ok", "request_id": "req-test-2"}) + "\n",
        encoding="utf-8",
    )
    approval_secret.write_text("approval-secret", encoding="utf-8")
    control_session_secret.write_text("session-secret", encoding="utf-8")
    control_users_json.write_text(json.dumps({"schema_version": 1, "users": {"legacy_admin": {"password_hash": module._password_hash("correct-horse")}}}), encoding="utf-8")
    policy.write_text(
        """schema_version: 2
mode: enforce
effective_behavior: acl_enforced
unknown_profile_default: ask
unknown_resource_default: ask
operation_classes: {}
profile_policy:
  operations:
    account_alias: workspace_primary
    defaults:
      gmail.search: allow
    resource_overrides: {}
  assistant:
    account_alias: workspace_primary
    defaults:
      drive.share: deny
    resource_overrides:
      drive_any:
        drive.share: deny
global_denies:
  - id: high_risk_global
    profiles: ['*']
    resources: ['*']
    actions: [drive.share]
    decision: deny
""",
        encoding="utf-8",
    )
    registry.write_text(
        """schema_version: 2
operation_risk:
  drive.share: high
resources:
  drive_any:
    title_hint: Any Drive file
    type: drive
    account_alias: workspace_primary
    sensitivity: high
    profile_scope: [assistant]
    allowed_operations: [share]
""",
        encoding="utf-8",
    )
    setattr(module, "POLICY_PATH", policy)
    setattr(module, "REGISTRY_PATH", registry)
    setattr(module, "GENERATED_POLICY_PATH", generated)
    setattr(module, "RUNTIME_POLICY_PATH", runtime)
    setattr(module, "CHANGE_LOG_PATH", change_log)
    setattr(module, "APPROVAL_SECRET_PATH", approval_secret)
    setattr(module, "CONTROL_USERS_JSON_PATH", control_users_json)
    setattr(module, "CONTROL_USERS_DB_PATH", control_users_db)
    setattr(module, "CONTROL_SESSION_SECRET_PATH", control_session_secret)
    setattr(module, "GATEWAY_AUDIT_LOG_PATH", gateway_audit)
    setattr(module, "GOOGLE_WORKSPACE_TOKEN_ROOT", token_root)
    setattr(module, "GOOGLE_OAUTH_STATE_ROOT", oauth_root)
    setattr(module, "RUNTIME_BACKUP_ROOT", tmp / "runtime-backups")
    setattr(module, "RUNTIME_BACKUP_CRON_PATH", tmp / "runtime-backup.cron")
    setattr(module, "INSTALLED_CONTROL_SOURCE_PATH", tmp / "installed" / "google_governance_control_plane.py")
    module.INSTALLED_CONTROL_SOURCE_PATH.parent.mkdir(parents=True)
    module.INSTALLED_CONTROL_SOURCE_PATH.write_text(SCRIPT.read_text(encoding="utf-8"), encoding="utf-8")
    setattr(module, "_systemctl_restart_gateway", lambda: {"service": "fake", "health": {"status": "ok"}})
    setattr(module, "_gateway_post", lambda path, payload: {"status": "ok", "approvals": [{"approval_id": "gog-test", "state": "pending", "action": "drive.share"}]})

    snap = module._snapshot()
    html = module.INDEX_HTML
    requirements_text = (PROJECT_DIR / "requirements.txt").read_text(encoding="utf-8")
    if "psycopg[binary]>=3.2.0" not in requirements_text:
        raise SystemExit("default install must include psycopg Postgres driver support")
    installer_text = (PROJECT_DIR / "scripts" / "install_systemd.sh").read_text(encoding="utf-8")
    if installer_text.count("GOOGLE_GOVERNANCE_DB_BACKEND=${GOOGLE_GOVERNANCE_DB_BACKEND:-sqlite}") < 3:
        raise SystemExit("installer must wire default-enabled database backend env into all services")
    if installer_text.count("GOOGLE_GOVERNANCE_DATABASE_URL=${GOOGLE_GOVERNANCE_DATABASE_URL:-}") < 3:
        raise SystemExit("installer must wire optional Postgres DATABASE_URL env into all services")

    required_ui = [
        'id="route"',
        'id="workspaceTab-auth"',
        '1. Configure new workspace',
        '2. Configure Agent Identity',
        '3. Configure Agent-Workspace Route',
        'class="contentTabs workspaceStepTabs"',
        'id="workspaceOverviewPane"',
        'class="loginHeroLogo"',
        'id="oauthTokenLabel"',
        'id="mapTokenPicker"',
        'id="mapProfilePicker"',
        'class="routePickPanel"',
        'token_ids,profiles',
        'writeRouteState()',
        'settingsMode=\'admin\'',
        'settings/admin/${settingsActive}',
        'User Management',
        'class="userCards userAdminCards"',
        'class="userCard adminUserCard"',
        "users:{key:'first_name',dir:1}",
        'class="userCardName"',
        'deleteUser',
        'No users found.',
        'data-sort="token_route"',
        'id="profilePhoto"',
        'resizeProfilePhoto(file)',
        'class="profileAvatarPreview hidden"',
        'id="mainNav" class="mainNav"',
        'const inSettings=active===\'settings\'',
        "$('mainNav').classList.toggle('hidden',inSettings)",
        '--hover:',
        'border-radius:50%',
        'width:72px;height:72px',
        'width:36px;height:36px',
        "['loginUser','loginPass','loginTotp']",
        'id="runtimeVersion"',
        'id="settingsNav-channels" data-icon="chat_bubble"',
        'id="adminNav-channels" class="setupSubItem" data-icon="chat_bubble"',
        '#settingsNav-channels::before,#adminNav-channels::before',
        'id="quickstartBtn"',
        'id="quickstartPanel"',
        'Get the gateway ready in three steps.',
        'Configure the MCP gateway token.',
        '<span class="quickstartIcon" aria-hidden="true">🚀</span>',
        'quickstartPanel{position:fixed',
        "#tab-gatewaySetup[data-icon]::before{content:'🚀'",
        '#quickstartPanel.quickstartPanel li b,#quickstartPanel.quickstartPanel li span',
        'rgba(34,34,36,.98)',
        'border:0!important;box-shadow:none!important;color:inherit',
        'rocket-border-final-reset',
        '#quickstartBtn,#quickstartBtn.quickstartBtn',
        'access-acl-button-visibility',
        '#accessView .accessHeader .refreshRow{padding-top:8px',
        '#rulesView #resetRulesFilters.resetFilters',
        'reset-filters-label-hardening',
        "content:'Reset filters'",
        '<span class="resetFiltersLabel">Reset filters</span>',
        'reset-filters-real-label',
        'reset-filters-bulkbar-blue',
        '#rulesView .bulkbar #resetRulesFilters.resetFilters',
        'reset-filters-single-blue-label',
        '#rulesView .bulkbar #resetRulesFilters.resetFilters::before',
        'approvalDecisionCell',
        'approvalDecisionWrap',
        'approvalActionButtons',
        'body.light .iconDecision.successBtn',
        'body.light .iconDecision.dangerBtn',
        'aria-label="Approve and execute ${raw}"',
        'approval-row-button-color-and-spacing-final',
        '#approvalsView .iconDecision{filter:none!important',
        '#approvalsView .iconDecision.successBtn',
        '#approvalsView .iconDecision.dangerBtn',
        'approvalDetailCell',
        'Authorize and link your Google Workspace to your agents.',
        'Configure notification channels for agent access approvals.',
        'id="channelBotToken" type="password" placeholder="Paste this user\'s governance bot token"',
        'governance bot',
        "bot_token:$('channelBotToken')?$('channelBotToken').value:''",
        'id="runtimeValidation"',
        'id="runtimeBackups"',
        'id="validateRuntime"',
        'id="createBackup"',
        'id="exportBackup"',
        'id="importBackup"',
        'id="runtimeBackupIo"',
        'id="runtimeUpgradeStatus"',
        'id="restartRuntime"',
        'control-ui',
        'id="apiTokenStatus"',
        'id="generateApiToken"',
        'id="apiTokenOutput"',
        'Gateway Setup',
        'ggovGatewaySetupExpandedDefaultV2',
        "gatewaySetupExpanded=localStorage.ggovGatewaySetupExpanded!=='0'",
        "document.querySelectorAll('.setupSubItem').forEach(b=>setVisible(b,admin&&gatewaySetupExpanded));",
        "setVisible($('tab-access'),admin);",
        "setVisible($('tab-approvals'),admin);",
        "if(!isAdmin())return; if(active==='settings'&&settingsMode==='admin'",
        'id="tab-gatewaySetup" class="navGroup" data-icon="rocket_launch">Gateway Setup</button>',
        'id="adminNav-tokens" class="setupSubItem" data-icon="vpn_key">MCP Authorization</button><button id="adminNav-workspace" class="setupSubItem" data-icon="cloud_sync">Workspace Configuration</button>',
        'id="settingsNav-tokens" class="navGroup" data-icon="vpn_key">MCP Authorization</button><button id="settingsNav-workspace"',
        'class="contentTabs credentialTabs"',
        'id="credentialTab-gateway" class="active" type="button"><span class="stepNum">1</span> Configure MCP Gateway</button>',
        'id="workspaceTab-agent" class="subItem">2. Configure Agent Identity</button>',
        'id="workspaceTop-agent"><span class="stepNum">2</span> Configure Agent Identity</button>',
        'id="workspaceAgentPane" class="hidden"',
        'id="workspaceNewConfig" class="panel relaxedDetails"',
        'Agent entity name',
        'Agent Identity',
        'class="apiTokenCreateGrid agentTokenCreateGrid"',
        '2. Workspace Name',
        'id="oauthTokenLabel" placeholder="Workspace name"',
        'Workspace Name is required',
        '>Workspace</th>',
        'global-sort-arrows-workspace-name',
        'routeTokenCheck,.routeProfileCheck',
        'id="profileAgentEntities"',
        'id="profileAgentEntityList"',
        'function renderProfileAgentEntities()',
        'data.agent_entity_options',
        'agent_entity_options',
        "const decision=admin?`<select",
        "async function saveRule(r,decision,btn){if(!isAdmin())return;",
        'id="generateAgentToken"',
        'Generate agent token',
        '<h4>Agent entity</h4>',
        'id="agentTokenOutput"',
        '/api/runtime/api-token/generate',
        '/api/runtime/agent-token/generate',
        '/api/runtime/agent-token/revoke',
        'currentUserSettingsNotice',
        'Manage your profile and security from the left menu.',
        'No agent entities are assigned to your user yet. Ask an admin to assign one under User Management.',
        '/api/runtime/status',
        '/api/runtime/validate',
        '/api/runtime/backup/create',
        '/api/runtime/backup/export',
        '/api/runtime/backup/import',
        '/api/runtime/postgres/plan',
        '/api/runtime/postgres/migrate',
        'database_backend',
        'postgres_driver_available',
        'Postgres backend support enabled',
        'id="postgresMigration"',
        'id="postgresDsn"',
        'id="planPostgresMigration"',
        'id="runPostgresMigration"',
        'id="postgresMigrationStatus"',
        '/api/runtime/restart',
        '/api/runtime/jwt-secret/rotate',
        '/api/runtime/jwt-secret/migrate',
    ]
    for marker in required_ui:
        if marker not in html:
            raise SystemExit(f"UI marker missing: {marker}")
    forbidden_ui = [
        "Import existing token files into SQLite",
        "archive files after import",
        "Live access log</span>",
        "ACL control</span>",
        "Workspace custody</span>",
        "Workspace authentication",
        "Workspace ↔ agent profiles",
        "agent entitys",
        "Gateway identity",
        "Gateway identities",
        "Gateway Configuration",
        "These are the current API tokens",
        "dual/legacy modes",
        "<b>Mode</b>",
        "2. Optional token name",
        'class="aclQuickLinks"',
        ">Token</a></th>",
        'aclHeadLink',
        'th[data-sort]::after',
        'id="workspaceAccess"',
        'id="mapProfileCards"',
        'renderMapProfileCards',
        "<span>v</span>",
        '<section id="loginView" class="authShell"',
        '<button id="settingsNav-users">Users</button>',
        'id="revealJwtSecret"',
        'id="jwtSecretReveal"',
        '/api/runtime/jwt-secret/reveal',
        'M7,7H5A2,2',
        '<span class="code">API</span>',
        'prompt(`Assign active agent entities',
    ]
    required_ui = [
        "setVisible(setupToggle,admin)",
        "setVisible($('tab-rules'),true)",
        "setVisible($('tab-access'),admin)",
        "setVisible($('tab-mcp'),admin)",
        "setVisible($('tab-approvals'),admin)",
        "document.querySelectorAll('.setupSubItem').forEach(b=>setVisible(b,admin&&gatewaySetupExpanded));",
        "if(!isAdmin())return; if(active==='settings'&&settingsMode==='admin'",
        "const adminGo=(section,sub)=>{if(!isAdmin())return;",
    ]
    for marker in required_ui:
        if marker not in html:
            raise SystemExit(f"multi-tenant RBAC UI marker missing: {marker}")
    for marker in forbidden_ui:
        if marker in html:
            raise SystemExit(f"obsolete UI marker still present: {marker}")
    if not module._verify_password("correct-horse", module._load_control_users()["admin"]["password_hash"]):
        raise SystemExit("password verification failed")
    users_store = module._load_control_store()
    users_store["users"]["admin"]["totp_secret"] = "JBSWY3DPEHPK3PXP"
    users_store["users"]["admin"]["totp_enabled"] = True
    module._save_control_store(users_store)
    login_result = module._login({"username": "admin", "password": "correct-horse"})
    if login_result.get("status") != "2fa_required" or "totp" not in login_result.get("methods", []):
        raise SystemExit(f"2FA login challenge missing: {login_result}")
    twofa_result = module._login_2fa({"challenge": login_result["challenge"], "method": "totp", "code": module._totp_now("JBSWY3DPEHPK3PXP")})
    if twofa_result.get("status") != "ok" or not twofa_result.get("user", {}).get("twofa_enabled"):
        raise SystemExit(f"2FA login failed: {twofa_result}")
    try:
        module._login({"username": "admin", "password": "wrong"})
    except PermissionError:
        pass
    else:
        raise SystemExit("invalid password accepted")
    changed = module._change_password({
        "current_password": "correct-horse",
        "new_password": "new-correct-horse",
        "confirm_password": "new-correct-horse",
    }, "admin")
    if changed.get("status") != "password_changed":
        raise SystemExit(f"bad password-change result: {changed}")
    changed_hash = module._load_control_users()["admin"]["password_hash"]
    if not module._verify_password("new-correct-horse", changed_hash) or module._verify_password("correct-horse", changed_hash):
        raise SystemExit("password change did not update hash")

    viewer_user = module._save_user({
        "username": "viewer-one",
        "first_name": "Viewer",
        "last_name": "One",
        "email": "viewer-one@example.com",
        "role": "viewer",
        "enabled": True,
        "password": "viewer-password-1",
    }, "admin")
    if viewer_user.get("user", {}).get("role") != "viewer":
        raise SystemExit(f"viewer user was not created cleanly: {viewer_user}")
    try:
        module._login({"username": "viewer-one", "password": "viewer-password-1"})
        raise SystemExit("viewer was allowed to sign into the admin control UI")
    except PermissionError:
        pass
    try:
        module._delete_user({"username": "admin"}, "admin")
    except ValueError as exc:
        if "current user" not in str(exc):
            raise SystemExit(f"self-delete guard returned wrong error: {exc}")
    else:
        raise SystemExit("admin self-delete was allowed")
    module._save_user({
        "username": "disabled-admin",
        "first_name": "Disabled",
        "last_name": "Admin",
        "email": "disabled-admin@example.com",
        "role": "admin",
        "enabled": False,
        "password": "disabled-admin-password-1",
    }, "admin")
    try:
        module._delete_user({"username": "admin"}, "disabled-admin")
    except ValueError as exc:
        if "last enabled admin" not in str(exc):
            raise SystemExit(f"last-admin delete guard returned wrong error: {exc}")
    else:
        raise SystemExit("last enabled admin deletion was allowed")
    agent_token = module._agent_token_generate({"agent_id": "agent-a"}, "admin")
    if agent_token.get("agent_id") != "agent-a":
        raise SystemExit(f"agent token not generated: {agent_token}")
    module._agent_token_generate({"agent_id": "agent-b"}, "admin")
    assigned_user = module._assign_user_agent_entities({"username": "viewer-one", "assigned_agent_entities": ["agent-a"]}, "admin")
    module._assign_user_agent_entities({"username": "admin", "assigned_agent_entities": ["agent-a"]}, "admin")
    if assigned_user.get("user", {}).get("assigned_agent_entities") != ["agent-a"]:
        raise SystemExit(f"agent entity assignment failed: {assigned_user}")
    with gateway_audit.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"ts": "2026-01-02T12:34:56+00:00", "profile": "agent-a", "persona": "Agent A", "action": "approval.list", "resource_alias": "approval_queue", "decision": "ask", "status": "ok", "request_id": "req-agent-a"}) + "\n")
    runtime_status = module._runtime_status()
    agent_inventory = runtime_status.get("agent_tokens", [])
    agent_row = next((x for x in agent_inventory if x.get("agent_id") == "agent-a"), {})
    if agent_row.get("last_used_at") != "2026-01-02T12:34:56+00:00" or agent_row.get("last_used_source") != "gateway_audit":
        raise SystemExit(f"agent last-used did not derive from gateway audit: {agent_row}")
    viewer_snapshot = module._snapshot("viewer-one")
    if "agent-a" not in viewer_snapshot.get("profile_options", []):
        raise SystemExit(f"viewer assigned agent entity missing from snapshot: {viewer_snapshot.get('profile_options')}")
    if set(viewer_snapshot.get("agent_entity_options") or []) != {"agent-a", "agent-b"}:
        raise SystemExit(f"viewer cannot see all active agent entities: {viewer_snapshot.get('agent_entity_options')}")
    if viewer_snapshot.get("assigned_agent_entities") != ["agent-a"]:
        raise SystemExit(f"viewer assigned agent entity list missing from snapshot: {viewer_snapshot.get('assigned_agent_entities')}")
    module._assign_user_agent_entities({"username": "viewer-one", "assigned_agent_entities": []}, "admin")
    if module._current_user_payload("viewer-one").get("assigned_agent_entities"):
        raise SystemExit("clearing assigned agent entities failed")
    module._assign_user_agent_entities({"username": "viewer-one", "assigned_agent_entities": ["agent-a"]}, "admin")
    module._store_workspace_token(
        "admin_workspace",
        "workspace-full.json",
        {"client_id": "admin-client", "refresh_token": "admin-refresh", "scopes": ["gmail"]},
        {"token_label": "Admin Workspace", "email": "admin@example.com", "owner_username": "admin"},
    )
    module._store_workspace_token(
        "viewer_workspace",
        "workspace-full.json",
        {"client_id": "viewer-client", "refresh_token": "viewer-refresh", "scopes": ["gmail"]},
        {"token_label": "Viewer Workspace", "email": "viewer-one@example.com", "owner_username": "viewer-one"},
    )
    admin_workspace_view = module._workspace_access_inventory(actor="admin")
    admin_all_workspace_view = module._workspace_access_inventory(actor="admin", include_all=True)
    viewer_workspace_view = module._workspace_access_inventory(actor="viewer-one")
    if {item.get("account_alias") for item in admin_workspace_view.get("items", [])} != {"admin_workspace", "workspace_primary"}:
        raise SystemExit(f"admin Gateway Setup inventory is not isolated to own/admin legacy profile: {admin_workspace_view}")
    if {item.get("account_alias") for item in admin_all_workspace_view.get("items", [])} < {"admin_workspace", "viewer_workspace"}:
        raise SystemExit(f"admin Control Plane inventory cannot see all users' configured workspaces: {admin_all_workspace_view}")
    if {item.get("account_alias") for item in viewer_workspace_view.get("items", [])} != {"viewer_workspace"}:
        raise SystemExit(f"viewer workspace inventory is not isolated to own profile: {viewer_workspace_view}")
    listed_users = {u["username"]: u for u in module._list_users("admin").get("users", [])}
    viewer_summary = listed_users.get("viewer-one") or {}
    if viewer_summary.get("workspace_count") != 1 or "Viewer Workspace" not in json.dumps(viewer_summary.get("workspaces", [])):
        raise SystemExit(f"admin user inventory does not summarize viewer workspace ownership: {viewer_summary}")
    viewer_token_id = next((item.get("id") for item in viewer_workspace_view.get("items", []) if item.get("account_alias") == "viewer_workspace"), "")
    try:
        module._workspace_access_map_profiles({"token_ids": [viewer_token_id], "profiles": ["agent-a"]}, "viewer-one")
        raise SystemExit("viewer was allowed to map Workspace routes")
    except PermissionError:
        pass
    reset_result = module._admin_reset_password({"username": "viewer-one", "new_password": "viewer-password-2"}, "admin")
    if reset_result.get("status") != "password_reset" or not module._verify_password("viewer-password-2", module._load_control_users()["viewer-one"]["password_hash"]):
        raise SystemExit(f"admin password reset failed: {reset_result}")
    try:
        module._admin_reset_password({"username": "admin", "new_password": "blocked-password"}, "viewer-one")
        raise SystemExit("viewer was allowed to reset another user's password")
    except PermissionError:
        pass

    module._approval_channel_save({"tenant_label": "Admin Approver", "owner_username": "viewer-one", "chat_id": "111", "telegram_user_id": "111", "scope": "profile", "profile": "agent-a", "enabled": True}, "admin")
    try:
        module._approval_channel_save({"tenant_label": "Viewer Approver", "chat_id": "222", "telegram_user_id": "222", "scope": "profile", "profile": "agent-a", "enabled": True}, "viewer-one")
        raise SystemExit("viewer was allowed to create approval channel")
    except PermissionError:
        pass
    admin_channels = module._approval_channels_list("admin").get("channels", [])
    try:
        module._approval_channels_list("viewer-one")
        raise SystemExit("viewer was allowed to view approval channels")
    except PermissionError:
        pass
    if {c.get("tenant_label") for c in admin_channels} != {"Admin Approver"}:
        raise SystemExit(f"admin channel setup inventory is not isolated to admin config: {admin_channels}")
    if any(c.get("owner_username") != "admin" for c in admin_channels):
        raise SystemExit(f"approval channel owner should derive from logged-in admin, not payload: {admin_channels}")
    admin_channel = next(c for c in admin_channels if c.get("tenant_label") == "Admin Approver")
    admin_tenant_id = str(admin_channel.get("tenant_id") or "")
    original_gateway_inventory = module._gateway_post_with_temp_api_token
    try:
        def fake_approval_inventory(path, payload, actor):
            return {"status": "ok", "approvals": [
                {"approval_id": "gog-admin-only", "state": "pending", "profile": "agent-a", "action": "gmail.send_gmail_message", "approval_targets": [{"tenant_id": admin_tenant_id, "tenant_label": "Admin Approver", "agent_ids": ["agent-a"]}]},
            ]}
        setattr(module, "_gateway_post_with_temp_api_token", fake_approval_inventory)
        admin_approval_ids = {row.get("approval_id") for row in module._approval_inventory({"state": "pending"}, "admin").get("approvals", [])}
        if admin_approval_ids != {"gog-admin-only"}:
            raise SystemExit(f"admin approval inventory did not show admin-routed requests: {admin_approval_ids}")
        try:
            module._approval_inventory({"state": "pending"}, "viewer-one")
            raise SystemExit("viewer was allowed to view approval inventory")
        except PermissionError:
            pass
    finally:
        setattr(module, "_gateway_post_with_temp_api_token", original_gateway_inventory)
    gateway_decisions = []
    try:
        def fake_approval_decision(path, payload, actor):
            gateway_decisions.append((path, dict(payload), actor))
            return {"status": "deny" if payload.get("decision") == "deny" else "ok", "approval_id": payload.get("approval_id"), "decision": payload.get("decision")}
        setattr(module, "_gateway_post_with_temp_api_token", fake_approval_decision)
        denied = module._approval_decide_ui({"approval_id": "gog-admin-only", "decision": "deny"}, "admin")
        if denied.get("source") != "gateway" or gateway_decisions[-1][0] != "/v1/governance/approvals/decide":
            raise SystemExit(f"UI denial did not delegate to gateway approval state: {denied}, {gateway_decisions}")
        if gateway_decisions[-1][1].get("decision_channel") != "control-ui":
            raise SystemExit(f"UI denial missing control-ui decision channel: {gateway_decisions[-1]}")
    finally:
        setattr(module, "_gateway_post_with_temp_api_token", original_gateway_inventory)
    try:
        module._approval_channel_delete({"tenant_id": admin_channel.get("tenant_id")}, "viewer-one")
        raise SystemExit("viewer was allowed to delete approval channel")
    except PermissionError:
        pass

    if snap["summary"]["rule_count"] != 0 or snap.get("profile_options"):
        raise SystemExit(f"ACL rows/agent identities should be empty before Agent Identity creates entities: {snap['summary']}, {snap.get('profile_options')}")
    if not snap["access_log"]:
        raise SystemExit(f"access log missing from initial snapshot: {snap}")
    if snap["access_log"][0].get("request_id") != "req-test":
        raise SystemExit(f"bad access log snapshot: {snap['access_log']}")
    if len(snap["access_log"]) != 1 or snap["access_log"][0].get("token_route") != "assistant/workspace_primary":
        raise SystemExit(f"access log did not consolidate and resolve ACL route: {snap['access_log']}")
    if snap["access_log"][0].get("_count") != 2 or "2 Google Workspace requests" not in snap["access_log"][0].get("actual_access", ""):
        raise SystemExit(f"access log did not summarize duplicate timestamp/profile/route rows: {snap['access_log']}")

    migrated = module._jwt_secret_migrate_to_db("admin")
    if migrated.get("status") != "disabled" or migrated.get("storage") != "disabled":
        raise SystemExit(f"JWT filesystem custody should be disabled: {migrated}")
    if "secret" in migrated or migrated.get("secrets_revealed") is not False:
        raise SystemExit(f"JWT disabled status leaked secret material: {migrated}")
    try:
        module._read_jwt_secret()
    except RuntimeError as exc:
        if "filesystem JWT signing is disabled" not in str(exc):
            raise
    else:
        raise SystemExit("JWT filesystem read unexpectedly succeeded")
    if hasattr(module, "_jwt_secret_reveal"):
        raise SystemExit("JWT reveal helper must not exist")
    rotated = module._jwt_secret_rotate({"length_bytes": 32}, "admin")
    if rotated.get("status") != "disabled" or "secret" in rotated:
        raise SystemExit(f"JWT rotation should be disabled and non-revealing: {rotated}")
    runtime_status = module._runtime_status()
    if runtime_status.get("jwt_secret", {}).get("storage") != "disabled":
        raise SystemExit(f"runtime status did not expose disabled JWT custody: {runtime_status.get('jwt_secret')}")
    db_backend = runtime_status.get("database_backend") or {}
    if db_backend.get("active_backend") != "sqlite" or db_backend.get("postgres_support_enabled") is not True:
        raise SystemExit(f"runtime status did not expose default-enabled Postgres backend support with SQLite active: {db_backend}")
    generated_api_token = module._api_token_generate({"label": "Test shared token"}, "admin")
    if generated_api_token.get("env_var") != "GOOGLE_GOVERNANCE_ACCESS_TOKEN" or not generated_api_token.get("access_token"):
        raise SystemExit(f"API token generation did not return the expected one-time token: {generated_api_token}")
    api_tokens = module._api_token_inventory()
    if not api_tokens or api_tokens[0].get("allowed_profiles") != ["*"]:
        raise SystemExit(f"API token inventory did not record shared-profile token: {api_tokens}")
    runtime_status = module._runtime_status()
    if not runtime_status.get("api_tokens"):
        raise SystemExit(f"runtime status did not include API token inventory: {runtime_status}")
    generated_agent_token = module._agent_token_generate({"agent_id": "agent-a"}, "admin")
    assistant_agent_token = module._agent_token_generate({"agent_id": "assistant"}, "admin")
    operations_agent_token = module._agent_token_generate({"agent_id": "operations"}, "admin")
    if generated_agent_token.get("env_var") != "GOOGLE_GOVERNANCE_AGENT_TOKEN" or generated_agent_token.get("agent_id") != "agent-a" or not generated_agent_token.get("agent_token"):
        raise SystemExit(f"Agent token generation did not return the expected one-time token: {generated_agent_token}")
    agent_tokens = module._agent_token_inventory()
    agent_ids = {x.get("agent_id") for x in agent_tokens if x.get("active")}
    if not {"agent-a", "assistant", "operations"}.issubset(agent_ids):
        raise SystemExit(f"Agent token inventory did not record generated system-agnostic tokens: {agent_tokens}")
    module._assign_user_agent_entities({"username": "viewer-one", "assigned_agent_entities": ["agent-a", "operations"]}, "admin")
    viewer_token_id = next((item.get("id") for item in viewer_workspace_view.get("items", []) if item.get("account_alias") == "viewer_workspace"), "")
    admin_viewer_map = module._workspace_access_map_profiles({"token_id": viewer_token_id, "profiles": ["operations"]}, "admin")
    if admin_viewer_map.get("status") != "mapped" or admin_viewer_map.get("routes", {}).get("operations") != "operations/viewer_workspace":
        raise SystemExit(f"admin could not map viewer-visible Workspace route: {admin_viewer_map}")
    viewer_snapshot = module._snapshot("viewer-one")
    viewer_rule_profiles = {row.get("profile") for row in viewer_snapshot.get("rules", [])}
    if not viewer_snapshot.get("rules") or "operations" not in viewer_rule_profiles or not viewer_rule_profiles <= {"operations", "agent-a"}:
        raise SystemExit(f"viewer snapshot did not expose only assigned-agent ACL rows: {viewer_snapshot.get('rules')}")
    admin_scoped_snapshot = module._snapshot("admin")
    admin_scoped_profiles = {row.get("profile") for row in admin_scoped_snapshot.get("rules", [])}
    if not admin_scoped_profiles <= {"agent-a"}:
        raise SystemExit(f"admin ACL view was not scoped to admin-owned/assigned ACL rows: {admin_scoped_snapshot.get('rules')}")
    admin_all_snapshot = module._snapshot("admin", include_all=True)
    admin_all_profiles = {row.get("profile") for row in admin_all_snapshot.get("rules", [])}
    if "operations" not in admin_all_profiles:
        raise SystemExit(f"admin all-user Control Plane snapshot did not preserve global ACL rows: {admin_all_snapshot.get('rules')}")
    viewer_acl_row = next((row for row in viewer_snapshot.get("rules", []) if row.get("profile") == "operations" and row.get("action") == "gmail.search_gmail_messages" and row.get("account_alias") == "viewer_workspace"), None)
    if not viewer_acl_row or viewer_acl_row.get("scope") != "override" or viewer_acl_row.get("resource_alias") in {"", "__profile_default__"}:
        raise SystemExit(f"viewer ACL rows must be route/resource scoped, not profile-default scoped: {viewer_acl_row}")
    try:
        module._apply_policy_change({"profile": viewer_acl_row["profile"], "scope": viewer_acl_row["scope"], "resource_alias": viewer_acl_row["resource_alias"], "action": viewer_acl_row["action"], "decision": "ask", "actor": "viewer-one", "reason": "viewer self-service"})
        raise SystemExit("viewer was allowed to edit route-scoped ACL row")
    except PermissionError:
        pass
    try:
        module._apply_bulk_policy_changes({"actor": "viewer-one", "reason": "viewer bulk self-service", "changes": [{"profile": viewer_acl_row["profile"], "scope": viewer_acl_row["scope"], "resource_alias": viewer_acl_row["resource_alias"], "action": viewer_acl_row["action"], "decision": "deny"}]})
        raise SystemExit("viewer was allowed to bulk edit ACL rows")
    except PermissionError:
        pass
    runtime_status = module._runtime_status()
    if not runtime_status.get("agent_tokens") or runtime_status.get("agent_token_mode") not in {"dual", "strict", "legacy"}:
        raise SystemExit(f"runtime status did not include agent token inventory/mode: {runtime_status}")
    if runtime_status.get("version", {}).get("source_sha256") != runtime_status.get("version", {}).get("installed_sha256"):
        raise SystemExit(f"runtime source status did not compare source and installed files: {runtime_status}")
    setattr(module, "_runtime_gateway_health", lambda: {"status": "ok"})
    applied_runtime = module._runtime_apply("admin")
    if applied_runtime.get("status") != "applied" or not runtime.exists():
        raise SystemExit(f"runtime apply failed before validation: {applied_runtime}")
    module._record_yaml_sync_event("admin", "ok", "runtime_yaml_synced_from_ui", {"test": True})
    validation = module._runtime_validate("admin")
    if validation.get("status") != "ok" or not validation.get("checks"):
        raise SystemExit(f"runtime validation failed: {validation}")
    backup = module._runtime_backup_create({"include_token_store": False}, "admin")
    if backup.get("status") != "created" or not Path(backup.get("archive", "")).exists():
        raise SystemExit(f"runtime backup was not created: {backup}")
    pg_plan = module._postgres_migration_plan({"dsn": "postgresql://user:pass@db.example/gov"}, "admin")
    if pg_plan.get("status") != "ready" or not pg_plan.get("tables") or pg_plan.get("requires_backup") is not True:
        raise SystemExit(f"Postgres migration plan did not enumerate SQLite state safely: {pg_plan}")
    pg_migration = module._postgres_migration_run({"dsn": "postgresql://user:pass@db.example/gov", "dry_run": True, "include_token_store": False}, "admin")
    if pg_migration.get("status") != "prepared" or not pg_migration.get("backup", {}).get("archive") or not Path(pg_migration.get("script_path", "")).exists():
        raise SystemExit(f"Postgres migration did not create backup and migration script: {pg_migration}")
    script_text = Path(pg_migration["script_path"]).read_text(encoding="utf-8")
    if "CREATE TABLE IF NOT EXISTS users" not in script_text or "INSERT INTO users" not in script_text or "COMMIT;" not in script_text:
        raise SystemExit("Postgres migration script is missing table DDL/data transaction markers")
    with module._control_db() as conn:
        if not conn.execute("SELECT COUNT(*) FROM runtime_backups").fetchone()[0]:
            raise SystemExit("runtime backup was not recorded in SQLite")
    post_backup_status = module._runtime_status()
    if not post_backup_status.get("backups"):
        raise SystemExit(f"runtime status did not include backup inventory: {post_backup_status}")
    schedule = module._runtime_backup_schedule({"enabled": True, "cron": "17 3 * * *", "include_token_store": False}, "admin")
    if schedule.get("status") != "prepared" or schedule.get("enabled") is not False or schedule.get("configured") is not True or schedule.get("installed") is not False:
        raise SystemExit(f"runtime backup schedule incorrectly reported active installation: {schedule}")
    schedule_status = module._runtime_backup_schedule_status()
    if schedule_status.get("enabled") is not False or schedule_status.get("configured") is not True or "operator" not in str(schedule_status.get("message") or "").lower():
        raise SystemExit(f"runtime backup schedule status did not distinguish prepared vs installed: {schedule_status}")
    installer_text = (PROJECT_DIR / "scripts" / "install_systemd.sh").read_text(encoding="utf-8")
    if "seed_state_file" not in installer_text or "if [[ ! -e \"$dest\" ]]" not in installer_text:
        raise SystemExit("systemd installer does not preserve existing UI-managed policy state")
    for destructive_seed in [
        'install -m 0660 -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "${PROJECT_DIR}/google-governance-policy.yaml"',
        'install -m 0640 -o "${SERVICE_USER}" -g "${SERVICE_GROUP}" "${PROJECT_DIR}/generated/profile_policy.json"',
    ]:
        if destructive_seed in installer_text:
            raise SystemExit(f"systemd installer still unconditionally overwrites UI state: {destructive_seed}")

    acl_sync = module._ensure_workspace_acl_resources(
        "new_workspace",
        ["assistant", "operations"],
        module._oauth_services_to_scopes(["gmail", "calendar"]),
        "new@example.com",
        "admin",
    )
    if acl_sync.get("status") != "synced" or not acl_sync.get("changed"):
        raise SystemExit(f"bad workspace ACL sync result: {acl_sync}")
    synced_snapshot = module._snapshot()
    synced_actions = {(row["profile"], row["action"], row.get("token_route")) for row in synced_snapshot["rules"] if row.get("account_alias") == "new_workspace"}
    if ("operations", "gmail.search_gmail_messages", "operations/new_workspace") not in synced_actions:
        raise SystemExit(f"selected operations profile did not get profile-level Gmail ACL rows: {synced_actions}")
    if ("assistant", "calendar.list_calendars", "assistant/new_workspace") not in synced_actions:
        raise SystemExit(f"selected assistant profile did not get profile-level Calendar ACL rows: {synced_actions}")
    synced_registry = module._load_yaml(registry)
    if "new_workspace" not in synced_registry.get("account_aliases", {}):
        raise SystemExit("new workspace account was not added to the registry")
    expected_routes = {"assistant": "assistant/new_workspace", "operations": "operations/new_workspace"}
    if synced_registry.get("account_aliases", {}).get("new_workspace", {}).get("current_profile_routes") != expected_routes:
        raise SystemExit(f"workspace routes were not account-specific: {synced_registry.get('account_aliases', {}).get('new_workspace', {}).get('current_profile_routes')}")
    if not any(row["profile"] == "assistant" and row.get("token_route") == "assistant/new_workspace" and row["action"] == "calendar.list_calendars" for row in synced_snapshot["rules"]):
        raise SystemExit("ACL rows do not expose the profile/token route")

    inventory = module._workspace_access_inventory()
    primary_items = [item for item in inventory.get("items", []) if item.get("account_alias") == "workspace_primary"]
    if len(primary_items) != 1 or not primary_items[0]["has_refresh_token"]:
        raise SystemExit(f"bad workspace access inventory: {inventory}")
    client_secret = {"installed": {"client_id": "oauth-client", "client_secret": "oauth-secret", "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth", "token_uri": "https://oauth2.googleapis.com/token", "redirect_uris": ["http://localhost"]}}
    for bad_secret in [
        {"installed": {"client_id": "oauth-client", "client_secret": "oauth-secret", "auth_uri": "http://127.0.0.1:9/authorize", "token_uri": "https://oauth2.googleapis.com/token", "redirect_uris": ["http://localhost"]}},
        {"installed": {"client_id": "oauth-client", "client_secret": "oauth-secret", "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth", "token_uri": "http://127.0.0.1:9/token", "redirect_uris": ["http://localhost"]}},
        {"web": {"client_id": "oauth-client", "client_secret": "oauth-secret", "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth", "token_uri": "https://oauth2.googleapis.com/token", "redirect_uris": ["https://example.test/callback"]}},
    ]:
        try:
            module._parse_client_secret(json.dumps(bad_secret))
        except ValueError:
            pass
        else:
            raise SystemExit(f"OAuth parser accepted unsafe/non-desktop client secret: {bad_secret}")
    try:
        module._workspace_access_create_request({"account_alias": "workspace_primary", "client_secret_json": json.dumps(client_secret)}, "admin")
        raise SystemExit("OAuth start accepted missing Workspace Name")
    except ValueError as exc:
        if "Workspace Name is required" not in str(exc):
            raise SystemExit(f"OAuth start missing-name error was unclear: {exc}")
    create_req = module._workspace_access_create_request({"account_alias": "workspace_primary", "client_secret_json": json.dumps(client_secret), "token_label": "Primary Workspace"}, "admin")
    if create_req.get("status") != "authorization_url_generated" or "authorization_url" not in create_req:
        raise SystemExit(f"bad workspace OAuth start: {create_req}")
    if "client_secret" in json.dumps(create_req):
        raise SystemExit("OAuth start leaked client secret")
    class FakeBodyHandler:
        def __init__(self, body: bytes):
            self.headers = {"Content-Length": str(len(body))}
            self.rfile = io.BytesIO(body)
    old_control_max_body = module.MAX_JSON_BODY_BYTES
    setattr(module, "MAX_JSON_BODY_BYTES", 8)
    try:
        try:
            module._read_json_body(FakeBodyHandler(b'{"too":"large"}'))
        except ValueError as exc:
            if "too large" not in str(exc):
                raise SystemExit(f"control request body limit failed with unclear error: {exc}")
        else:
            raise SystemExit("control request body limit accepted oversized JSON")
    finally:
        setattr(module, "MAX_JSON_BODY_BYTES", old_control_max_body)
    class FakeOidcTokenResponse:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return json.dumps({"id_token": "eyJhbGciOiJub25lIiwia2lkIjoiayJ9.eyJpc3MiOiJodHRwczovL29pZGMuZXhhbXBsZSIsImF1ZCI6Im9pZGMtY2xpZW50IiwiZXhwIjo5OTk5OTk5OTk5LCJlbWFpbCI6InVzZXJAZXhhbXBsZS5jb20iLCJub25jZSI6Im4ifQ."}).encode()
    old_oidc_urlopen = module.urllib.request.urlopen
    setattr(module.urllib.request, "urlopen", lambda req, timeout=20: FakeOidcTokenResponse())
    try:
        try:
            module._oidc_userinfo({"issuer_url": "https://oidc.example", "client_id": "oidc-client", "client_secret": "secret", "redirect_uri": "http://localhost/callback"}, {"issuer": "https://oidc.example", "token_endpoint": "https://oidc.example/token"}, "code", "n")
        except (ValueError, PermissionError):
            pass
        else:
            raise SystemExit("OIDC accepted an unsigned id_token fallback")
    finally:
        setattr(module.urllib.request, "urlopen", old_oidc_urlopen)
    if "Agent Identity-to-token ACL mapping" not in create_req.get("message", ""):
        raise SystemExit(f"OAuth start message missing Agent Identity mapping hint: {create_req}")
    if not {"openid", "email", "profile"}.issubset(set(create_req.get("scopes", []))):
        raise SystemExit(f"OAuth start did not request identity scopes for email discovery: {create_req.get('scopes')}")
    try:
        module._workspace_access_create_request({"account_alias": "viewer_oauth_workspace", "client_secret_json": json.dumps(client_secret), "token_label": "Viewer OAuth Workspace"}, "viewer-one")
        raise SystemExit("viewer was allowed to start Workspace OAuth setup")
    except PermissionError:
        pass
    if module._oauth_account_alias("", "Example Account") != "example_account":
        raise SystemExit("friendly token label was not used as email-missing account alias fallback")
    admin_token_id = next((item.get("id") for item in admin_workspace_view.get("items", []) if item.get("account_alias") == "admin_workspace"), "")
    mapped = module._workspace_access_map_profiles({"token_id": admin_token_id, "profiles": ["agent-a"]}, "admin")
    if mapped.get("status") != "mapped" or mapped.get("profiles") != ["agent-a"]:
        raise SystemExit(f"bad profile-token mapping result: {mapped}")
    if mapped.get("routes", {}).get("agent-a") != "agent-a/admin_workspace":
        raise SystemExit(f"profile-token mapping did not return the account route: {mapped}")
    mapped_snapshot = module._snapshot()
    admin_agent_row = next((row for row in mapped_snapshot["rules"] if row["profile"] == "agent-a" and row["action"] == "gmail.search_gmail_messages" and row.get("token_route") == "agent-a/admin_workspace"), None)
    if not admin_agent_row:
        raise SystemExit("profile-token mapping did not create route-scoped Gmail ACL row")
    if admin_agent_row.get("scope") != "override" or admin_agent_row.get("resource_alias") in {"", "__profile_default__"}:
        raise SystemExit(f"mapped ACL row was not route/resource scoped: {admin_agent_row}")
    if not any(route.get("profile") == "agent-a" and route.get("route") == "agent-a/admin_workspace" and route.get("account_alias") == "admin_workspace" for route in mapped_snapshot.get("workspace_routes", [])):
        raise SystemExit(f"profile-token mapping did not expose workspace route inventory: {mapped_snapshot.get('workspace_routes')}")
    admin_agent_apply = module._apply_policy_change({"profile": "agent-a", "scope": admin_agent_row["scope"], "resource_alias": admin_agent_row["resource_alias"], "action": admin_agent_row["action"], "decision": "allow", "actor": "admin", "reason": "admin route isolation"})
    if admin_agent_apply.get("status") != "applied":
        raise SystemExit(f"admin could not edit own route-scoped ACL row: {admin_agent_apply}")
    isolation_policy = json.loads(runtime.read_text(encoding="utf-8"))
    viewer_resource_alias = "gmail_viewer_workspace"
    if isolation_policy["profile_policy"]["agent-a"].get("defaults", {}).get("gmail.search_gmail_messages") == "allow":
        raise SystemExit("route-scoped admin edit incorrectly mutated agent-a profile defaults")
    if isolation_policy["profile_policy"]["agent-a"].get("resource_overrides", {}).get(viewer_resource_alias, {}).get("gmail.search_gmail_messages") == "allow":
        raise SystemExit("admin KTGmail route ACL edit leaked into viewer Family Gmail route")

    # google-auth is optional for the control plane token test; the stdlib refresh fallback should be used.
    calls = []
    class FakeRefreshResponse:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return json.dumps({"access_token": "fresh", "expires_in": 3600, "scope": "https://www.googleapis.com/auth/calendar"}).encode()
    def fake_urlopen(req, timeout=30):
        calls.append((req.full_url, timeout))
        return FakeRefreshResponse()
    setattr(module.urllib.request, "urlopen", fake_urlopen)
    test_status, updated_payload = module._refresh_google_token_payload({"client_id": "cid", "client_secret": "sec", "refresh_token": "refresh", "scopes": ["https://www.googleapis.com/auth/calendar"]})
    if test_status not in {"valid", "refreshed"} or updated_payload.get("access_token") != "fresh" or not calls:
        raise SystemExit(f"stdlib token refresh fallback failed: {test_status}, {updated_payload}, {calls}")

    result = module._apply_policy_change({
        "profile": "assistant",
        "scope": "override",
        "resource_alias": "drive_any",
        "action": "drive.share",
        "decision": "ask",
        "actor": "admin",
        "reason": "test change",
    })
    if result.get("status") != "applied" or result.get("previous") not in {"deny", None} or result.get("decision") != "ask":
        raise SystemExit(f"bad apply result: {result}")
    runtime_policy = json.loads(runtime.read_text(encoding="utf-8"))
    if runtime_policy["profile_policy"]["assistant"]["resource_overrides"]["drive_any"]["drive.share"] != "ask":
        raise SystemExit("runtime policy not updated")
    bulk = module._apply_bulk_policy_changes({
        "actor": "admin",
        "reason": "bulk test",
        "changes": [{"profile": "assistant", "scope": "default", "resource_alias": "__profile_default__", "action": "drive.share", "decision": "allow"}],
    })
    if bulk.get("count") != 1:
        raise SystemExit(f"bad bulk result: {bulk}")
    runtime_policy = json.loads(runtime.read_text(encoding="utf-8"))
    if runtime_policy.get("mode") != "enforce" or runtime_policy.get("effective_behavior") != "acl_enforced":
        raise SystemExit("runtime policy not enforcing")
    unmapped = module._workspace_access_unmap_profiles({"token_id": admin_token_id, "profiles": ["agent-a"]}, "admin")
    if unmapped.get("status") != "unmapped" or unmapped.get("profiles") != ["agent-a"]:
        raise SystemExit(f"bad profile-token unmapping result: {unmapped}")
    after_unmap = module._snapshot()
    if any(route.get("profile") == "agent-a" and route.get("account_alias") == "admin_workspace" for route in after_unmap.get("workspace_routes", [])):
        raise SystemExit("profile-token unmapping did not revoke the route relationship")
    if any(row.get("profile") == "agent-a" and row.get("account_alias") == "admin_workspace" for row in after_unmap.get("rules", [])):
        raise SystemExit("profile-token unmapping did not remove Workspace ACL rows for the revoked profile")
    assistant_revoke = module._agent_token_revoke({"id": assistant_agent_token["id"]}, "admin")
    if assistant_revoke.get("status") != "revoked" or assistant_revoke.get("remaining_active_tokens") != 0 or not assistant_revoke.get("identity_cleanup", {}).get("changed"):
        raise SystemExit(f"last assistant agent-token revoke did not deprovision its ACL identity: {assistant_revoke}")
    after_assistant_revoke = module._snapshot()
    if "assistant" in after_assistant_revoke.get("profile_options", []):
        raise SystemExit(f"revoked agent identity remained selectable: {after_assistant_revoke.get('profile_options')}")
    if any(row.get("profile") == "assistant" for row in after_assistant_revoke.get("rules", [])):
        raise SystemExit("revoked agent identity ACL rows remained visible")
    if any(route.get("profile") == "assistant" for route in after_assistant_revoke.get("workspace_routes", [])):
        raise SystemExit("revoked agent identity workspace routes remained visible")
    module._assign_user_agent_entities({"username": "admin", "assigned_agent_entities": ["agent-a", "operations"]}, "admin")
    module._store_workspace_token(
        "google-workspace",
        "workspace-full.json",
        {"client_id": "test-client", "refresh_token": "refresh2", "scopes": ["gmail"]},
        {"token_label": "Example Account", "email": "", "owner_username": "admin"},
    )
    promoted = module._workspace_access_map_profiles({"token_id": "google-workspace/workspace-full.json", "profiles": ["operations"]}, "admin")
    if promoted.get("account_alias") != "example_account" or promoted.get("routes", {}).get("operations") != "operations/example_account":
        raise SystemExit(f"generic token alias was not promoted from the friendly token label: {promoted}")
    promoted_inventory = module._workspace_access_inventory()
    if not any(item.get("account_alias") == "example_account" and item.get("label") == "Example Account" for item in promoted_inventory.get("items", [])):
        raise SystemExit(f"promoted token was not visible with friendly account metadata: {promoted_inventory}")
    disconnected = module._workspace_access_revoke({"token_id": "example_account/workspace-full.json"}, "admin")
    if disconnected.get("status") != "revoked" or disconnected.get("profiles_unmapped") != ["operations"]:
        raise SystemExit(f"disconnect did not remove route relationships for workspace: {disconnected}")
    after_disconnect = module._snapshot()
    if any(route.get("account_alias") == "example_account" for route in after_disconnect.get("workspace_routes", [])):
        raise SystemExit("disconnecting a workspace did not remove its workspace routes")
    if any(row.get("account_alias") == "example_account" for row in after_disconnect.get("rules", [])):
        raise SystemExit("disconnecting a workspace did not remove its ACL rows")

    captured_gateway_posts = []
    old_urlopen = module.urllib.request.urlopen
    old_gateway_token = getattr(module, "GATEWAY_ACCESS_TOKEN", None)
    setattr(module, "GATEWAY_ACCESS_TOKEN", "control-gateway-token")
    class FakeGatewayApprovalResponse:
        def __enter__(self): return self
        def __exit__(self, *args): return False
        def read(self): return json.dumps({"status": "executed", "approval_id": "gog-test", "execution": {"status": "executed", "result": {"id": "sent-test"}}}).encode()
    def fake_gateway_urlopen(req, timeout=180):
        captured_gateway_posts.append(json.loads(req.data.decode("utf-8")))
        return FakeGatewayApprovalResponse()
    setattr(module.urllib.request, "urlopen", fake_gateway_urlopen)
    try:
        approve_result = module._gateway_post_with_temp_api_token("/v1/governance/approve-and-execute", {"approval_id": "gog-test"}, "admin")
    finally:
        setattr(module.urllib.request, "urlopen", old_urlopen)
        setattr(module, "GATEWAY_ACCESS_TOKEN", old_gateway_token)
    if approve_result.get("status") != "executed" or not captured_gateway_posts or captured_gateway_posts[0].get("approval_admin_secret") != "approval-secret":
        raise SystemExit(f"control UI gateway approval call did not include admin secret: {approve_result} {captured_gateway_posts}")

    log_text = change_log.read_text(encoding="utf-8")
    if "policy_change_applied" not in log_text or "bulk_policy_change_applied" not in log_text:
        raise SystemExit("change log missing")
    revoke = module._workspace_access_revoke({"path": str(token_file)}, "admin")
    if revoke.get("status") != "revoked" or token_file.exists():
        raise SystemExit(f"bad workspace revoke: {revoke}")
    print(json.dumps({"status": "PASS", "tmp": str(tmp), "result": result, "bulk": bulk}, indent=2))


if __name__ == "__main__":
    main()
