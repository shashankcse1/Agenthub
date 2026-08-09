# CTO / Platform One-Pager — Governed Velocity

**Role:** Make the control plane the only production path  
**Non-goal:** Another prompt library

---

## Architecture decision

```
Apps / Agents  →  AI CONTROL PLANE  →  Models / MCP / Data / Egress
                   identity · policy
                   tools · budgets
                   approvals · ledger
```

No production provider keys in app configs.  
No unmanaged MCP.  
No “we’ll add audit later.”

---

## Platform deliverables (90 days)

| Days | Engineering outcome |
|------|---------------------|
| 1–30 | Gateway as default SDK/path; key migration off apps; NHI inventory wired |
| 31–60 | Route input/output policies on tier-1 services; MCP registry enforced; budget hooks |
| 61–90 | Dual-approval on prod mutations; evidence export path tested; revoke runbook automated |

---

## Agency Contract → your backlog

| Clause | Build / enforce |
|--------|-----------------|
| Identity | Entitlements, JIT, key lifecycle, NHI hygiene APIs |
| Mandate | `input-data-policy` on critical routes |
| Toolbox | MCP allowlist + governed tool call |
| Escalation | Dual-approval headers / workflows in prod |
| Fence | Budgets, passthrough allowlists, rate limits |
| Ledger | Structured audit; compliance export; risk metadata |

---

## Engineering norms

- **Mediate before accelerate** — new agent features require on-plane path  
- **Least agency** — default deny on tools; expand with review  
- **Outcome tests** — red-team side effects, not only chat refusals  
- **SLOs that matter** — gateway coverage, revoke latency, export RTO  

---

## Phrase for product reviews

If it can act, it needs a contract.  
If it has a contract, it needs a ledger.  
If it has neither, it is not production.
