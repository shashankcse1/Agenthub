# Reference Architecture — AI Control Plane

**Status:** Normative with architecture principles P1–P10  
**Audience:** Platform architects, security engineering  

---

## Logical view

```text
Users / Apps / Agents
          │
          ▼
┌─────────────────────────────────────────┐
│         AI CONTROL PLANE (mediate)      │
│  identity · mandate · toolbox           │
│  escalation · fence · ledger            │
└─────────────────────────────────────────┘
          │
          ├─► Models (infer allow/deny)
          ├─► Tools / MCP (default deny)
          ├─► Memory / RAG (scoped writes)
          └─► Egress (default deny / allowlist)
                    │
                    ▼
            Ledger → SIEM / evidence export
```

## Supporting planes

| Plane | Contents |
|-------|----------|
| Identity | NHI, entitlements, TTL keys, JIT, dual approvers |
| Mandate | Input data policy, output guardrails, data classes |
| Toolbox | MCP registry, pre-exec checks, least agency |
| Fence | Budgets, rate limits, egress/passthrough, revoke |
| Ledger | allow/deny, approvals, revoke, export events |

## Trust boundaries

| Boundary | Rule |
|----------|------|
| Untrusted content | Never sole authority for irreversible acts |
| Tool plane | Default deny; registered servers only |
| Egress | Default deny; network is ground truth for exfil |
| Admin plane | Dual control for prod policy/tool expansion |
| Failure mode | Tier-1 fail closed |

## Data plane vs control plane

- **Data plane:** tokens, embeddings, retrieved chunks, tool payloads (redact in logs)  
- **Control plane:** decisions — allow/deny, approvals, budgets, revocations  

Chat UIs are presentation. The ledger is authoritative.

## Deployment patterns

1. **Central gateway** (preferred) — all prod SDKs point here  
2. **Sidecar / library** — still entitlement-checked; still central ledger  
3. **Forbidden** — app-embedded long-lived provider keys with local filters only  

## Mapping to epics

| Element | Epic |
|---------|------|
| Entitlements + SDK defaults | A |
| Input/output policy | B |
| MCP/tool gate | C |
| Dual approval / JIT | D |
| Budget + egress + revoke | E |
| Ledger + export + scorecard | F |
| Steward portal | G |

## ARB exit questions

Privilege expansion requires: Contract clause coverage, ledger fields, fail-closed behavior, and ≤15m revoke path (principles P1–P10).
