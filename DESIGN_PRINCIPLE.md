## Problem statement this gateways solves

Most Workspace MCP servers solve connectivity: they expose useful Google Workspace actions to an AI assistant or developer tool.

This gateway solves authority: it decides whether a specific agent should be allowed to perform a specific action against a specific Workspace resource.

| Area | Typical Google Workspace MCP server | Google Workspace Governance Gateway |
|---|---|---|
| Google token custody | Token lives beside the agent/MCP server | Gateway-owned token store, managed through control UI |
| Agent authentication | Often local trust or host-level config | Gateway client token plus separate agent identity token |
| Workspace routing | Usually one active Google token per server/profile | Multiple routes per agent, e.g. `agent-a/workspace-primary` |
| Policy model | Tool availability and OAuth scopes | `agent + resource + action => allow / ask / deny` |
| High-risk operations | Callable if tool and OAuth scope allow it | Approval path for externalizing/destructive actions |
| Auditability | Depends on local host logs | Gateway audit, control audit, request IDs, optional metrics/log dashboards |
| Operator workflow | Config files and tokens on disk | Admin-only browser UI for OAuth, route mapping, ACLs, approvals, and runtime apply |
| Google OAuth exposure | Agents may need refresh tokens | Agents receive only gateway URL, route, client token, and agent token |

The goal is not just “Google tools over MCP.” The goal is a governed Google access layer that can safely sit between multiple agents and multiple Google accounts.
