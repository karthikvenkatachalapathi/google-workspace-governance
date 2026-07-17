#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from PIL import Image, ImageDraw, ImageFont

OUT = Path(__file__).resolve().parents[1] / "docs" / "assets" / "ui"
OUT.mkdir(parents=True, exist_ok=True)

W, H = 1440, 960
BG = (9, 13, 24)
RAIL = (15, 23, 39)
PANEL = (21, 31, 50)
PANEL2 = (27, 41, 64)
LINE = (43, 58, 84)
TEXT = (233, 238, 248)
MUTED = (159, 176, 202)
BLUE = (106, 168, 255)
GREEN = (74, 222, 128)
AMBER = (251, 191, 36)
RED = (251, 113, 133)
PURPLE = (183, 148, 244)

FONT_DIRS = [Path("/usr/share/fonts/truetype/dejavu"), Path("/usr/share/fonts/truetype/liberation2")]

def font(name: str, size: int) -> ImageFont.FreeTypeFont:
    candidates = [
        f"DejaVuSans{name}.ttf",
        f"LiberationSans{name}.ttf",
        "DejaVuSans.ttf",
    ]
    for d in FONT_DIRS:
        for c in candidates:
            p = d / c
            if p.exists():
                return ImageFont.truetype(str(p), size)
    return ImageFont.load_default()

F = font("", 22)
F_SM = font("", 17)
F_XS = font("", 14)
F_B = font("-Bold", 22)
F_H = font("-Bold", 42)
F_H2 = font("-Bold", 28)
F_METRIC = font("-Bold", 48)
F_MONO = font("Mono", 16)


def rounded(draw, xy, fill, outline=LINE, r=18, width=1):
    draw.rounded_rectangle(xy, radius=r, fill=fill, outline=outline, width=width)


def text(draw, xy, s, fill=TEXT, f=F, anchor=None):
    draw.text(xy, s, fill=fill, font=f, anchor=anchor)


def ellipsize(s: str, max_chars: int) -> str:
    return s if len(s) <= max_chars else s[: max_chars - 1] + "…"


def pill(draw, x, y, label, color):
    w = int(draw.textlength(label, font=F_XS)) + 24
    rounded(draw, (x, y, x + w, y + 28), fill=(color[0]//5, color[1]//5, color[2]//5), outline=(color[0]//2, color[1]//2, color[2]//2), r=14)
    text(draw, (x + 12, y + 7), label, color, F_XS)
    return w


def code(draw, x, y, label, max_chars=44):
    label = ellipsize(label, max_chars)
    w = int(draw.textlength(label, font=F_MONO)) + 20
    rounded(draw, (x, y, x + w, y + 28), fill=(15, 23, 39), outline=LINE, r=8)
    text(draw, (x + 10, y + 7), label, (200, 215, 243), F_MONO)
    return w


def base(active: str, title: str, subtitle: str):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    # soft diagonal gradient
    for y in range(H):
        c = int(12 + 26 * (1 - y / H))
        d.line((260, y, W, y), fill=(c, c + 8, c + 20))
    d.rectangle((0, 0, 260, H), fill=RAIL)
    d.line((260, 0, 260, H), fill=LINE, width=1)
    text(d, (28, 28), "Google", BLUE, font("-Bold", 30))
    text(d, (28, 62), "Workspace", (248, 113, 113), font("-Bold", 30))
    text(d, (28, 96), "Governance", AMBER, font("-Bold", 30))
    text(d, (28, 130), "Gateway", GREEN, font("-Bold", 30))
    items = [
        ("ACL rules", "acl"), ("Approvals", "approvals"), ("Access logs", "logs"), ("MCP tools", "mcp"),
        ("GATEWAY SETUP", "_g"), ("MCP Authorization", "setup"), ("Workspace Configuration", "workspace"), ("Channel Configuration", "channels"),
        ("RUNTIME", "_r"), ("Backups", "backups"),
    ]
    y = 200
    for label, key in items:
        if key.startswith("_"):
            text(d, (28, y + 10), label, (101, 119, 147), F_XS)
            y += 42
            continue
        fill = PANEL2 if key == active else RAIL
        rounded(d, (18, y, 242, y + 46), fill=fill, outline=fill, r=14)
        text(d, (34, y + 12), label, TEXT if key == active else MUTED, F_SM)
        y += 52
    text(d, (304, 44), "INTERACTIVE MOCK DEMO", BLUE, F_XS)
    text(d, (304, 70), title, TEXT, F_H)
    text(d, (304, 122), subtitle, MUTED, F)
    rounded(d, (1120, 50, 1390, 90), fill=(16, 24, 39), outline=LINE, r=20)
    text(d, (1140, 62), "🔒 Mock data only · no API calls", MUTED, F_SM)
    return img, d


def table(draw, x, y, w, headers, rows, col_widths):
    rounded(draw, (x, y, x + w, y + 54 + 54 * len(rows)), fill=PANEL, outline=LINE, r=18)
    cx = x
    draw.rounded_rectangle((x, y, x + w, y + 54), radius=18, fill=PANEL2)
    for h, cw in zip(headers, col_widths):
        text(draw, (cx + 14, y + 18), h.upper(), MUTED, F_XS)
        cx += cw
    yy = y + 54
    for row in rows:
        draw.line((x, yy, x + w, yy), fill=(255, 255, 255, 18), width=1)
        cx = x
        for cell, cw in zip(row, col_widths):
            if isinstance(cell, tuple) and cell[0] == "pill":
                pill(draw, cx + 14, yy + 13, cell[1], cell[2])
            elif isinstance(cell, tuple) and cell[0] == "code":
                code(draw, cx + 14, yy + 13, cell[1], max(12, cw // 10))
            else:
                text(draw, (cx + 14, yy + 17), ellipsize(str(cell), max(10, cw // 10)), TEXT, F_SM)
            cx += cw
        yy += 54


def card(draw, x, y, w, label, metric):
    rounded(draw, (x, y, x + w, y + 115), fill=PANEL, outline=LINE, r=20)
    text(draw, (x + 20, y + 18), label.upper(), MUTED, F_XS)
    text(draw, (x + 20, y + 45), str(metric), TEXT, F_METRIC)


def acl():
    img, d = base("acl", "ACL rules", "Edit allow/ask/deny decisions by agent identity, workspace route, action, and resource.")
    for i, (l, m) in enumerate([("Rules", 113), ("Profiles", 4), ("Ask", 21), ("Denied", 18)]):
        card(d, 304 + i * 268, 178, 248, l, m)
    rounded(d, (304, 318, 1390, 384), fill=PANEL, outline=LINE, r=18)
    for i, val in enumerate(["Search: drive.share", "All identities", "All workspaces", "Apply bulk change"]):
        rounded(d, (326 + i * 242, 333, 546 + i * 242, 369), fill=(15,23,39) if i < 3 else (59,130,246), outline=LINE, r=11)
        text(d, (340 + i * 242, 342), val, TEXT if i == 3 else MUTED, F_SM)
    table(d, 304, 420, 1086, ["Decision", "Agent identity", "Workspace", "Route", "Action", "Service"], [
        [("pill", "ask", AMBER), "agent-a", "Primary Workspace", ("code", "agent-a/workspace-primary"), "drive.share", "Drive"],
        [("pill", "allow", GREEN), "ops-automation", "Ops Workspace", ("code", "ops/workspace-ops"), "sheets.read", "Sheets"],
        [("pill", "deny", RED), "support-bot", "Shared Workspace", ("code", "support/workspace-shared"), "gmail.send", "Gmail"],
    ], [130, 185, 205, 265, 180, 120])
    img.save(OUT / "acl-rules.png")


def setup():
    img, d = base("workspace", "Workspace Configuration", "Connect Google accounts, create agent identities, and map those identities to workspace routes.")
    rounded(d, (304, 176, 1390, 360), fill=PANEL, outline=LINE, r=20)
    steps = [("Configure new workspace", "This links your Google accounts to the gateway."), ("Configure Agent Identity", "This creates the workload identity used for ACL enforcement."), ("Configure Agent-Workspace Route", "This maps an agent to the Google account route it may use.")]
    for i, (h, b) in enumerate(steps):
        x = 330 + i * 342
        rounded(d, (x, 212, x + 318, 324), fill=(16,24,39), outline=LINE, r=16)
        text(d, (x + 18, 232), h, TEXT, F_B)
        text(d, (x + 18, 268), b, MUTED, F_SM)
    table(d, 304, 410, 1086, ["Account alias", "Email", "Routes", "Status"], [
        ["workspace-primary", "owner@example.com", ("code", "agent-a/workspace-primary"), ("pill", "connected", GREEN)],
        ["workspace-shared", "team@example.com", ("code", "support/workspace-shared"), ("pill", "connected", GREEN)],
    ], [240, 260, 390, 196])
    img.save(OUT / "workspace-configuration.png")


def approvals():
    img, d = base("approvals", "Approvals", "Review high-risk Workspace actions before they execute.")
    table(d, 304, 182, 1086, ["Request", "Profile", "Action", "Resource", "Status", "Approver"], [
        ["gog-93f384", "agent-a", "drive.share", "Quarterly Board Deck", ("pill", "pending", AMBER), "Workspace Owner"],
        ["gog-d30adf", "ops-automation", "calendar.delete", "Ops Calendar", ("pill", "denied", RED), "Ops Admin"],
        ["gog-8a355c", "support-bot", "gmail.send", "External recipient", ("pill", "approved", GREEN), "Support Lead"],
    ], [170, 180, 190, 270, 130, 146])
    rounded(d, (304, 430, 1390, 660), fill=PANEL, outline=LINE, r=20)
    text(d, (330, 460), "Request details", TEXT, F_H2)
    text(d, (330, 508), "Agent requested Drive sharing. Policy requires a human decision because external file sharing can exfiltrate data.", MUTED, F)
    pill(d, 330, 570, "Approve once", GREEN); pill(d, 475, 570, "Deny", RED); pill(d, 555, 570, "Request edit", AMBER)
    img.save(OUT / "approvals.png")


def runtime_backups():
    img, d = base("backups", "Runtime backups", "Create, download, validate, and locate physical backup archives.")
    rounded(d, (304, 176, 1390, 288), fill=PANEL, outline=LINE, r=20)
    text(d, (330, 205), "Backup inventory", TEXT, F_H2)
    text(d, (330, 245), "The UI now shows both the archive file and extracted backup folder so operators can find physical files quickly.", MUTED, F_SM)
    table(d, 304, 330, 1086, ["Backup", "Archive file", "Extracted folder", "Size", "Source", "Action"], [
        ["runtime-20260717T015914Z", ("code", ".google-governance/backups/runtime-20260717T015914Z.tar.gz"), ("code", ".google-governance/backups/runtime-20260717T015914Z"), "248 KB", "database", "Download"],
        ["runtime-20260716T235937Z", ("code", ".google-governance/backups/runtime-20260716T235937Z.tar.gz"), ("code", ".google-governance/backups/runtime-20260716T235937Z"), "241 KB", "filesystem", "Download"],
    ], [215, 345, 330, 75, 80, 41])
    rounded(d, (304, 590, 1390, 750), fill=(16,24,39), outline=LINE, r=18)
    text(d, (330, 620), "File locations", TEXT, F_H2)
    code(d, 330, 670, "Backup root: .google-governance/backups", 72)
    code(d, 330, 710, "Latest archive: .google-governance/backups/runtime-20260717T015914Z.tar.gz", 86)
    img.save(OUT / "runtime-backups.png")


def access_logs():
    img, d = base("logs", "Access logs", "See every governed request in plain English with decision and route context.")
    rounded(d, (304, 176, 1390, 690), fill=PANEL, outline=LINE, r=20)
    text(d, (330, 208), "Live gateway access log", TEXT, F_H2)
    logs = [
        ("09:41:12", "agent-a requested drive.share on Primary Workspace", AMBER, "approval"),
        ("09:38:04", "ops-automation read sheets.values.get through ops/workspace-ops", GREEN, "allowed"),
        ("09:35:44", "support-bot attempted gmail.send on support/workspace-shared", RED, "denied"),
        ("09:31:20", "control-ui generated runtime policy from SQLite state", BLUE, "control-ui"),
    ]
    y = 270
    for ts, msg, color, status in logs:
        rounded(d, (330, y, 1365, y + 68), fill=(16,24,39), outline=LINE, r=14)
        text(d, (350, y + 23), ts, MUTED, F_SM)
        text(d, (500, y + 23), msg, TEXT, F_SM)
        pill(d, 1230, y + 20, status, color)
        y += 82
    img.save(OUT / "access-logs.png")


for fn in [acl, setup, approvals, runtime_backups, access_logs]:
    fn()
print("created", OUT)
