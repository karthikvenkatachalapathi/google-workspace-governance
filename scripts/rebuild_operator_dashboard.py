#!/usr/bin/env python3
"""Rebuild Google Governance Ops as an operator audit console dashboard."""
from __future__ import annotations

import json
import os
import time
import urllib.parse
import urllib.request
from pathlib import Path

import yaml

PROM_UID = "d6948c6f-46de-4e8b-9734-52fd5d0d0093"
LOKI_UID = "f4aae18b-0c63-4887-98e9-c11a45fbbc8b"
FOLDER_UID = "homelab-observability"
DASH_UID = "google-workspace-governance-ops"
DASH_TITLE = "Google Governance Ops -- Operator View"
VAULT_PATH = Path("/home/hermes/Documents/Hermes-Obisidian-Vault/HomeLab/Project Ideas/Hermes Google Workspace Governance Gateway/grafana/google-workspace-governance-ops-dashboard.json")
REPO_PATH = Path("/home/hermes/google-workspace-governance/grafana/google-workspace-governance-ops-dashboard.json")
GITHUB_REPO_PATH = Path("/home/hermes/Documents/Hermes-Obisidian-Vault/HomeLab/Project Ideas/Google Workspace Governance Gateway - GitHub Repo/grafana/google-workspace-governance-ops-dashboard.json")
CFG_PATH = Path("/home/hermes/.hermes/config.yaml")

LOKI_AUDIT_SELECTOR = '{job=~"google-workspace-governance-gateway-audit|hermes-google-governance-gateway-audit|google-workspace-governance-control-audit|hermes-google-governance-control-audit"}'
AUDIT_FILTERS = '| json | profile=~"$profile" | token_route=~"$workspace" | service=~"$service" | decision=~"$decision" | status=~"$status"'
PROM_FILTERS = 'profile=~"$profile",decision=~"$decision",status=~"$status"'


def find_key(x, k):
    if isinstance(x, dict):
        if k in x:
            return x[k]
        for v in x.values():
            r = find_key(v, k)
            if r:
                return r
    elif isinstance(x, list):
        for v in x:
            r = find_key(v, k)
            if r:
                return r
    return None


def grafana_env():
    cfg = yaml.safe_load(CFG_PATH.read_text()) or {}
    url = (os.environ.get("GRAFANA_URL") or find_key(cfg, "GRAFANA_URL") or "http://127.0.0.1:3000").rstrip("/")
    key = os.environ.get("GRAFANA_API_KEY") or find_key(cfg, "GRAFANA_API_KEY")
    if not key or str(key).startswith("__"):
        raise SystemExit("GRAFANA_API_KEY missing or placeholder")
    os.environ["NO_PROXY"] = os.environ.get("NO_PROXY", "") + ",127.0.0.1,localhost,192.168.2.239,.home.karthikvenkat.us"
    os.environ["no_proxy"] = os.environ.get("no_proxy", "") + ",127.0.0.1,localhost,192.168.2.239,.home.karthikvenkat.us"
    return url, key


def api(url, key, path, data=None, method=None, timeout=60):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(
        url + path,
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json", "Accept": "application/json"},
        data=body,
        method=method,
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode()
        return json.loads(raw or "{}")


def prom_expr(expr: str, ref="A", instant=True):
    return {"refId": ref, "expr": expr, "instant": instant, "range": not instant, "datasource": {"type": "prometheus", "uid": PROM_UID}}


def loki_expr(expr: str, ref="A", query_type="range"):
    return {"refId": ref, "expr": expr, "queryType": query_type, "datasource": {"type": "loki", "uid": LOKI_UID}}


def stat(pid, title, x, y, w, h, expr, desc="", thresholds=None, unit="short"):
    thresholds = thresholds or [{"color": "green", "value": None}]
    return {
        "id": pid,
        "type": "stat",
        "title": title,
        "description": desc,
        "datasource": {"type": "prometheus", "uid": PROM_UID},
        "gridPos": {"x": x, "y": y, "w": w, "h": h},
        "targets": [prom_expr(expr)],
        "fieldConfig": {"defaults": {"unit": unit, "decimals": 0, "thresholds": {"mode": "absolute", "steps": thresholds}, "custom": {}}, "overrides": []},
        "options": {
            "reduceOptions": {"values": False, "calcs": ["lastNotNull"], "fields": ""},
            "orientation": "horizontal",
            "textMode": "auto",
            "colorMode": "background",
            "graphMode": "none",
            "justifyMode": "center",
        },
    }


def text_panel(pid, title, x, y, w, h, md):
    return {"id": pid, "type": "text", "title": title, "gridPos": {"x": x, "y": y, "w": w, "h": h}, "options": {"mode": "markdown", "content": md}}


def row(pid, title, y, collapsed=False):
    return {"id": pid, "type": "row", "title": title, "collapsed": collapsed, "gridPos": {"x": 0, "y": y, "w": 24, "h": 1}, "panels": []}


def audit_table(pid, title, y, h, expr, desc=""):
    return {
        "id": pid,
        "type": "table",
        "title": title,
        "description": desc,
        "datasource": {"type": "loki", "uid": LOKI_UID},
        "gridPos": {"x": 0, "y": y, "w": 24, "h": h},
        "targets": [loki_expr(expr)],
        "options": {"showHeader": True, "cellHeight": "md", "footer": {"show": False}, "sortBy": [{"displayName": "Time", "desc": True}]},
        "fieldConfig": {
            "defaults": {"custom": {"align": "auto", "cellOptions": {"type": "auto"}, "filterable": True}, "mappings": [], "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}]}},
            "overrides": [
                {"matcher": {"id": "byName", "options": "Profile / Agent"}, "properties": [{"id": "mappings", "value": [{"type": "value", "options": {"reasoning": {"index": 0, "text": "reasoning / Dumbledore"}, "airbnb": {"index": 1, "text": "airbnb / Hedwig"}, "daily-assistant": {"index": 2, "text": "daily-assistant / Hagrid"}, "default": {"index": 3, "text": "default / Hermione"}, "librarian": {"index": 4, "text": "librarian / Pince"}}}]}]},
                {"matcher": {"id": "byName", "options": "Decision"}, "properties": [{"id": "custom.cellOptions", "value": {"type": "color-background"}}, {"id": "mappings", "value": [{"options": {"allow": {"color": "green", "index": 0, "text": "APPROVED"}, "approved": {"color": "green", "index": 1, "text": "APPROVED"}, "ask": {"color": "yellow", "index": 2, "text": "ASK"}, "deny": {"color": "red", "index": 3, "text": "DENIED"}, "denied": {"color": "red", "index": 4, "text": "DENIED"}}, "type": "value"}]}]},
                {"matcher": {"id": "byName", "options": "Approval State"}, "properties": [{"id": "custom.cellOptions", "value": {"type": "color-background"}}]},
            ],
        },
        "transformations": [
            {"id": "extractFields", "options": {"source": "Line", "format": "json", "replace": True, "keepTime": True}},
            {"id": "organize", "options": {"excludeByName": {"__error__": True, "__error_details__": True, "detected_level": True, "filename": True, "gateway": True, "job": True, "operation": True, "ts": True, "unknown_resource": True, "high_risk_action": True, "latency_ms": True, "request_id": True}, "indexByName": {"Time": 0, "profile": 1, "token_route": 2, "service": 3, "action": 4, "resource_alias": 5, "decision": 6, "status": 7, "actor": 8}, "renameByName": {"profile": "Profile / Agent", "token_route": "Workspace", "service": "Service", "action": "Action", "resource_alias": "Resource", "decision": "Decision", "status": "Approval State", "actor": "Actor"}}},
        ],
    }


def lifecycle_table(pid, y):
    stages = [
        ("Inbound request received", f'sum(count_over_time({LOKI_AUDIT_SELECTOR} {AUDIT_FILTERS} [24h]))'),
        ("Policy evaluated", f'sum(count_over_time({LOKI_AUDIT_SELECTOR} {AUDIT_FILTERS} | decision=~"allow|approved|ask|deny|denied|blocked|policy-denied|auto-policy" [24h]))'),
        ("Auto-approved", f'sum(count_over_time({LOKI_AUDIT_SELECTOR} {AUDIT_FILTERS} | decision=~"allow|approved|auto-policy" | status!~"pending|waiting" [24h]))'),
        ("Asked Karthik", f'sum(count_over_time({LOKI_AUDIT_SELECTOR} {AUDIT_FILTERS} | decision=~"ask|approval_required" [24h]))'),
        ("Approved by Karthik", f'sum(count_over_time({LOKI_AUDIT_SELECTOR} {AUDIT_FILTERS} | action=~".*approval.*" | decision=~"allow|approved" [24h]))'),
        ("Denied by Karthik", f'sum(count_over_time({LOKI_AUDIT_SELECTOR} {AUDIT_FILTERS} | action=~".*approval.*" | decision=~"deny|denied" [24h]))'),
        ("Denied by policy", f'sum(count_over_time({LOKI_AUDIT_SELECTOR} {AUDIT_FILTERS} | decision=~"deny|denied|blocked|policy-denied" [24h]))'),
        ("Executed", f'sum(count_over_time({LOKI_AUDIT_SELECTOR} {AUDIT_FILTERS} | status=~"success|ok|executed|complete|completed" [24h]))'),
        ("Failed", f'sum(count_over_time({LOKI_AUDIT_SELECTOR} {AUDIT_FILTERS} | status=~"error|failed|failure" [24h]))'),
    ]
    targets = []
    for i, (stage, expr) in enumerate(stages):
        targets.append({"refId": chr(65 + i), "expr": expr, "legendFormat": stage, "instant": True, "range": False, "datasource": {"type": "prometheus", "uid": PROM_UID}})
    # NOTE: Prometheus datasource cannot evaluate Loki expressions; this panel intentionally uses Prometheus-compatible metric approximations below instead.
    stages_prom = [
        ("Inbound request received", f'(sum(increase(google_workspace_governance_audit_events_total{{{PROM_FILTERS}}}[24h]))) or vector(0)'),
        ("Policy evaluated", f'(sum(increase(google_workspace_governance_audit_events_total{{{PROM_FILTERS},decision=~"allow|approved|ask|deny|denied|blocked|policy-denied|auto-policy"}}[24h]))) or vector(0)'),
        ("Auto-approved", f'(sum(increase(google_workspace_governance_audit_events_total{{{PROM_FILTERS},decision=~"allow|approved|auto-policy",status!~"pending|waiting"}}[24h]))) or vector(0)'),
        ("Asked Karthik", f'(sum(increase(google_workspace_governance_audit_events_total{{{PROM_FILTERS},decision=~"ask|approval_required"}}[24h]))) or vector(0)'),
        ("Approved by Karthik", f'(sum(increase(google_workspace_governance_audit_events_total{{{PROM_FILTERS},action=~".*approval.*",decision=~"allow|approved"}}[24h]))) or vector(0)'),
        ("Denied by Karthik", f'(sum(increase(google_workspace_governance_audit_events_total{{{PROM_FILTERS},action=~".*approval.*",decision=~"deny|denied"}}[24h]))) or vector(0)'),
        ("Denied by policy", f'(sum(increase(google_workspace_governance_audit_events_total{{{PROM_FILTERS},decision=~"deny|denied|blocked|policy-denied"}}[24h]))) or vector(0)'),
        ("Executed", f'(sum(increase(google_workspace_governance_audit_events_total{{{PROM_FILTERS},status=~"success|ok|executed|complete|completed"}}[24h]))) or vector(0)'),
        ("Failed", f'(sum(increase(google_workspace_governance_audit_events_total{{{PROM_FILTERS},status=~"error|failed|failure"}}[24h]))) or vector(0)'),
    ]
    targets = [prom_expr(expr, chr(65+i)) | {"legendFormat": stage} for i, (stage, expr) in enumerate(stages_prom)]
    return {
        "id": pid,
        "type": "bargauge",
        "title": "Lifecycle stages -- last 24h",
        "description": "Plain-English lifecycle counts. The detailed row-level state is in the Action audit timeline above.",
        "datasource": {"type": "prometheus", "uid": PROM_UID},
        "gridPos": {"x": 0, "y": y, "w": 24, "h": 8},
        "targets": targets,
        "options": {"displayMode": "gradient", "orientation": "horizontal", "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}, "showUnfilled": True, "minVizWidth": 0, "minVizHeight": 10},
        "fieldConfig": {"defaults": {"unit": "short", "decimals": 0, "thresholds": {"mode": "absolute", "steps": [{"color": "green", "value": None}, {"color": "yellow", "value": 1}, {"color": "red", "value": 5}]}}, "overrides": []},
    }


def build_dashboard():
    panels = []
    pid = 1
    panels.append(text_panel(pid, "Operator readout", 0, 0, 24, 3, "## Google Governance Ops -- Operator View\nMain object: **action/event rows**. Summary cards are derived from those rows. Queries and debug labels stay out of the operator UI.")); pid += 1
    card_y = 3
    cards = [
        ("Actions last 24h", f'(sum(increase(google_workspace_governance_audit_events_total{{{PROM_FILTERS}}}[24h]))) or vector(0)', [{"color":"green","value":None}], "All governance action/audit rows in the last 24 hours."),
        ("Approved", f'(sum(increase(google_workspace_governance_audit_events_total{{{PROM_FILTERS},decision=~"allow|approved|auto-policy"}}[24h]))) or vector(0)', [{"color":"green","value":None}], "Allowed or auto-approved governance decisions."),
        ("Asked / waiting", f'(sum(increase(google_workspace_governance_audit_events_total{{{PROM_FILTERS},decision=~"ask|approval_required"}}[24h]))) or vector(0)', [{"color":"green","value":None},{"color":"yellow","value":1}], "Requests that required Karthik approval."),
        ("Denied", f'(sum(increase(google_workspace_governance_audit_events_total{{{PROM_FILTERS},decision=~"deny|denied|blocked|policy-denied"}}[24h]))) or vector(0)', [{"color":"green","value":None},{"color":"red","value":1}], "Operator-visible denied decisions."),
        ("Emergency overrides", f'(sum(increase(google_workspace_governance_audit_events_total{{{PROM_FILTERS},action=~".*emergency.*|.*override.*|.*break.*glass.*"}}[24h]))) or vector(0)', [{"color":"green","value":None},{"color":"red","value":1}], "Current: count in last 24h. Last seen and affected rows appear in Emergency override events below."),
        ("Policy errors", f'(sum(increase(google_workspace_governance_audit_events_total{{{PROM_FILTERS},status=~"policy_error|policy_failed|error|failed"}}[24h]))) or vector(0)', [{"color":"green","value":None},{"color":"red","value":1}], "Policy evaluation or execution failures."),
        ("Unknown workspace/profile", f'(sum(increase(google_workspace_governance_audit_events_total{{profile=~"unknown|$profile",decision=~"$decision",status=~"$status",action=~".*unknown.*"}}[24h]))) or vector(0)', [{"color":"green","value":None},{"color":"red","value":1}], "Unmapped profile/workspace/resource signals requiring cleanup."),
    ]
    positions = [(0,card_y,4,4),(4,card_y,4,4),(8,card_y,4,4),(12,card_y,4,4),(16,card_y,4,4),(20,card_y,4,4),(0,card_y+4,4,4)]
    for (title, expr, th, desc), (x,y,w,h) in zip(cards, positions):
        panels.append(stat(pid, title, x, y, w, h, expr, desc, th)); pid += 1
    panels.append(text_panel(pid, "Emergency override status", 4, card_y+4, 20, 4, "**Current:** shown in the Emergency overrides card.  \n**Last seen:** see the first row in **Emergency override events** below. If the table is empty, no override was seen in the selected time range.  \n**Affected profile/workspace:** visible in the event rows.")); pid += 1

    panels.append(row(pid, "Primary panel: Action audit timeline", 11)); pid += 1
    main_query = f'{LOKI_AUDIT_SELECTOR} {AUDIT_FILTERS}'
    panels.append(audit_table(pid, "Action audit timeline", 12, 14, main_query, "Full-width operator table: what came in, who/profile, which workspace/service/action/resource, the decision, approval state, and actor.")); pid += 1

    panels.append(row(pid, "Lifecycle panels", 26)); pid += 1
    panels.append(lifecycle_table(pid, 27)); pid += 1
    lifecycle_query = f'{LOKI_AUDIT_SELECTOR} {AUDIT_FILTERS}'
    panels.append(audit_table(pid, "Lifecycle event rows", 35, 10, lifecycle_query, "Same underlying events, kept as rows so lifecycle meaning is visible instead of hidden inside query text.")); pid += 1

    panels.append(row(pid, "Emergency override events", 45)); pid += 1
    emergency_query = f'{LOKI_AUDIT_SELECTOR} {AUDIT_FILTERS} |~ "(?i)(emergency|override|break.?glass)"'
    panels.append(audit_table(pid, "Emergency override events", 46, 9, emergency_query, "If this table is empty, that is the reassuring state. Any row here should be investigated immediately.")); pid += 1

    panels.append(row(pid, "Operator troubleshooting -- collapsed", 55, collapsed=True)); pid += 1
    panels.append(audit_table(pid, "Policy errors and unknown mappings", 56, 9, f'{LOKI_AUDIT_SELECTOR} {AUDIT_FILTERS} |~ "(?i)(policy_error|policy failed|unknown|unmapped|invalid route|workspace)"', "Only action rows requiring operator cleanup.")); pid += 1

    templating = {"list": [
        {"name":"profile","type":"query","datasource":{"type":"prometheus","uid":PROM_UID},"query":"label_values(google_workspace_governance_audit_events_total, profile)","includeAll":True,"multi":True,"allValue":".*","refresh":2,"current":{"selected":True,"text":"All","value":"$__all"}},
        {"name":"workspace","type":"textbox","query":".*","current":{"text":".*","value":".*"},"hide":0},
        {"name":"service","type":"textbox","query":".*","current":{"text":".*","value":".*"},"hide":0},
        {"name":"decision","type":"query","datasource":{"type":"prometheus","uid":PROM_UID},"query":"label_values(google_workspace_governance_audit_events_total, decision)","includeAll":True,"multi":True,"allValue":".*","refresh":2,"current":{"selected":True,"text":"All","value":"$__all"}},
        {"name":"status","type":"query","datasource":{"type":"prometheus","uid":PROM_UID},"query":"label_values(google_workspace_governance_audit_events_total, status)","includeAll":True,"multi":True,"allValue":".*","refresh":2,"current":{"selected":True,"text":"All","value":"$__all"}},
    ]}
    return {
        "annotations": {"list": []},
        "editable": True,
        "graphTooltip": 1,
        "links": [{"title":"Control UI","url":"http://127.0.0.1:8095/","targetBlank":True},{"title":"Explore governance audit logs","url":"/explore","targetBlank":True}],
        "panels": panels,
        "refresh": "30s",
        "schemaVersion": 39,
        "style": "dark",
        "tags": ["google-governance", "operator-view", "audit", "workspace"],
        "templating": templating,
        "time": {"from":"now-24h", "to":"now"},
        "timezone": "browser",
        "title": DASH_TITLE,
        "uid": DASH_UID,
        "version": None,
        "description": "Audit-console dashboard for Google Governance Ops. Primary object is the action/event row; summary cards derive from the row stream. No visible query/debug text in operator panels.",
    }


def validate_dashboard(dash):
    assert dash["uid"] == DASH_UID
    assert dash["title"] == DASH_TITLE
    assert any(p.get("title") == "Action audit timeline" and p.get("type") == "table" for p in dash["panels"])
    assert all("expr" not in (p.get("title", "") + p.get("description", "")) for p in dash["panels"])
    raw = json.dumps(dash)
    json.loads(raw)


def main():
    dash = build_dashboard()
    validate_dashboard(dash)
    for path in [VAULT_PATH, REPO_PATH, GITHUB_REPO_PATH]:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(dash, indent=2, sort_keys=False) + "\n")
        print("wrote", path)
    url, key = grafana_env()
    health = api(url, key, "/api/health")
    print("grafana health", health.get("database"), health.get("version"))
    res = api(url, key, "/api/dashboards/db", {"dashboard": dash, "folderUid": FOLDER_UID, "overwrite": True, "message": "Rebuild Google Governance Ops as operator audit console"}, "POST")
    print("published", res.get("url"), res.get("status"))
    fetched = api(url, key, f"/api/dashboards/uid/{DASH_UID}")
    got = fetched.get("dashboard", {})
    print("verified", got.get("title"), "panels", len(got.get("panels", [])), "folder", fetched.get("meta", {}).get("folderUid"))
    # Verify representative Prometheus expressions through the Grafana datasource proxy.
    for expr in [
        'sum(increase(google_workspace_governance_audit_events_total[24h])) or vector(0)',
        'sum(increase(google_workspace_governance_audit_events_total{decision=~"ask|approval_required"}[24h])) or vector(0)',
        'sum(increase(google_workspace_governance_audit_events_total{action=~".*emergency.*|.*override.*|.*break.*glass.*"}[24h])) or vector(0)',
    ]:
        qs = urllib.parse.urlencode({"query": expr, "time": str(time.time())})
        out = api(url, key, f"/api/datasources/proxy/uid/{PROM_UID}/api/v1/query?{qs}")
        print("prom_ok", out.get("status"), expr[:60])
    # Verify Loki parser/query shape; result may legitimately be empty.
    qs = urllib.parse.urlencode({"query": LOKI_AUDIT_SELECTOR + ' | json', "limit": "1", "direction": "BACKWARD"})
    out = api(url, key, f"/api/datasources/proxy/uid/{LOKI_UID}/loki/api/v1/query_range?{qs}")
    print("loki_ok", out.get("status"), "streams", len(out.get("data", {}).get("result", [])))


if __name__ == "__main__":
    main()
