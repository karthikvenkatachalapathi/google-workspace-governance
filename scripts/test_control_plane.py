#!/usr/bin/env python3
"""Offline tests for the protected Google governance control plane."""
from __future__ import annotations

import importlib.util
import json
import tempfile
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
    token_file = token_root / "accounts" / "personal_workspace" / "google_token.json"
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
    account_alias: personal_workspace
    defaults:
      gmail.search: allow
    resource_overrides: {}
  assistant:
    account_alias: personal_workspace
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
    account_alias: personal_workspace
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
    setattr(module, "INSTALLED_CONTROL_SOURCE_PATH", tmp / "installed" / "google_governance_control_plane.py")
    module.INSTALLED_CONTROL_SOURCE_PATH.parent.mkdir(parents=True)
    module.INSTALLED_CONTROL_SOURCE_PATH.write_text(SCRIPT.read_text(encoding="utf-8"), encoding="utf-8")
    setattr(module, "_systemctl_restart_gateway", lambda: {"service": "fake", "health": {"status": "ok"}})
    setattr(module, "_gateway_post", lambda path, payload: {"status": "ok", "approvals": [{"approval_id": "gog-test", "state": "pending", "action": "drive.share"}]})

    snap = module._snapshot()
    html = module.INDEX_HTML
    required_ui = [
        'id="route"',
        'id="workspaceTab-auth"',
        '1. Configure new workspace',
        '2. Configure workspace routes',
        '3. View configured workspaces',
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
        'id="adminNav-channels" class="adminSubItem" data-icon="chat_bubble"',
        '#settingsNav-channels::before,#adminNav-channels::before',
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
        '/api/runtime/api-token/generate',
        '/api/runtime/status',
        '/api/runtime/validate',
        '/api/runtime/backup/create',
        '/api/runtime/backup/export',
        '/api/runtime/backup/import',
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
    ]
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
    if snap["summary"]["rule_count"] != 1 or not snap["access_log"]:
        raise SystemExit(f"bad snapshot: {snap}")
    if snap["access_log"][0].get("request_id") != "req-test":
        raise SystemExit(f"bad access log snapshot: {snap['access_log']}")
    if len(snap["access_log"]) != 1 or snap["access_log"][0].get("token_route") != "assistant/personal_workspace":
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
    generated_api_token = module._api_token_generate({"label": "Test shared token"}, "admin")
    if generated_api_token.get("env_var") != "GOOGLE_GOVERNANCE_ACCESS_TOKEN" or not generated_api_token.get("access_token"):
        raise SystemExit(f"API token generation did not return the expected one-time token: {generated_api_token}")
    api_tokens = module._api_token_inventory()
    if not api_tokens or api_tokens[0].get("allowed_profiles") != ["*"]:
        raise SystemExit(f"API token inventory did not record shared-profile token: {api_tokens}")
    runtime_status = module._runtime_status()
    if not runtime_status.get("api_tokens"):
        raise SystemExit(f"runtime status did not include API token inventory: {runtime_status}")
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
    with module._control_db() as conn:
        if not conn.execute("SELECT COUNT(*) FROM runtime_backups").fetchone()[0]:
            raise SystemExit("runtime backup was not recorded in SQLite")
    post_backup_status = module._runtime_status()
    if not post_backup_status.get("backups"):
        raise SystemExit(f"runtime status did not include backup inventory: {post_backup_status}")

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
    if len(inventory.get("items", [])) != 1 or not inventory["items"][0]["has_refresh_token"]:
        raise SystemExit(f"bad workspace access inventory: {inventory}")
    client_secret = {"installed": {"client_id": "oauth-client", "client_secret": "oauth-secret", "auth_uri": "https://accounts.google.com/o/oauth2/v2/auth", "token_uri": "https://oauth2.googleapis.com/token", "redirect_uris": ["http://localhost"]}}
    create_req = module._workspace_access_create_request({"account_alias": "personal_workspace", "client_secret_json": json.dumps(client_secret)}, "admin")
    if create_req.get("status") != "authorization_url_generated" or "authorization_url" not in create_req:
        raise SystemExit(f"bad workspace OAuth start: {create_req}")
    if "client_secret" in json.dumps(create_req):
        raise SystemExit("OAuth start leaked client secret")
    if "Profile-to-token ACL mapping" not in create_req.get("message", ""):
        raise SystemExit(f"OAuth start did not explain post-connection profile mapping: {create_req}")
    if not {"openid", "email", "profile"}.issubset(set(create_req.get("scopes", []))):
        raise SystemExit(f"OAuth start did not request identity scopes for email discovery: {create_req.get('scopes')}")
    if module._oauth_account_alias("", "Example Account") != "example_account":
        raise SystemExit("friendly token label was not used as email-missing account alias fallback")
    mapped = module._workspace_access_map_profiles({"token_id": "personal_workspace/google_token.json", "profiles": ["assistant"]}, "admin")
    if mapped.get("status") != "mapped" or mapped.get("profiles") != ["assistant"]:
        raise SystemExit(f"bad profile-token mapping result: {mapped}")
    if mapped.get("routes", {}).get("assistant") != "assistant/personal_workspace":
        raise SystemExit(f"profile-token mapping did not return the account route: {mapped}")
    mapped_snapshot = module._snapshot()
    if not any(row["profile"] == "assistant" and row["action"] == "gmail.search_gmail_messages" and row.get("token_route") == "assistant/personal_workspace" for row in mapped_snapshot["rules"]):
        raise SystemExit("profile-token mapping did not create profile-level Gmail ACL row")
    if not any(route.get("profile") == "assistant" and route.get("route") == "assistant/personal_workspace" and route.get("account_alias") == "personal_workspace" for route in mapped_snapshot.get("workspace_routes", [])):
        raise SystemExit(f"profile-token mapping did not expose workspace route inventory: {mapped_snapshot.get('workspace_routes')}")

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
    unmapped = module._workspace_access_unmap_profiles({"token_id": "personal_workspace/google_token.json", "profiles": ["assistant"]}, "admin")
    if unmapped.get("status") != "unmapped" or unmapped.get("profiles") != ["assistant"]:
        raise SystemExit(f"bad profile-token unmapping result: {unmapped}")
    after_unmap = module._snapshot()
    if any(route.get("profile") == "assistant" and route.get("account_alias") == "personal_workspace" for route in after_unmap.get("workspace_routes", [])):
        raise SystemExit("profile-token unmapping did not revoke the route relationship")
    if any(row.get("profile") == "assistant" and row.get("account_alias") == "personal_workspace" for row in after_unmap.get("rules", [])):
        raise SystemExit("profile-token unmapping did not remove Workspace ACL rows for the revoked profile")
    module._store_workspace_token(
        "google-workspace",
        "workspace-full.json",
        {"client_id": "test-client", "refresh_token": "refresh2", "scopes": ["gmail"]},
        {"token_label": "Example Account", "email": ""},
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
    log_text = change_log.read_text(encoding="utf-8")
    if "policy_change_applied" not in log_text or "bulk_policy_change_applied" not in log_text:
        raise SystemExit("change log missing")
    revoke = module._workspace_access_revoke({"path": str(token_file)}, "admin")
    if revoke.get("status") != "revoked" or token_file.exists():
        raise SystemExit(f"bad workspace revoke: {revoke}")
    print(json.dumps({"status": "PASS", "tmp": str(tmp), "result": result, "bulk": bulk}, indent=2))


if __name__ == "__main__":
    main()
