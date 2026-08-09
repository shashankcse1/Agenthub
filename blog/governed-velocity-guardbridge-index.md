# GuardBridge / Platform Edition — Kit → Product Map

**Purpose:** Operationalize doctrine on *this* codebase’s control surface without leading with features  
**Rule:** Customer/exec narrative still starts at Leader’s Brief — this file is for builders & SEs after doctrine lands  

---

## Contract clause → platform capability

| Clause | Platform anchors (inventory-backed) | Operator console |
|--------|-------------------------------------|------------------|
| Identity | Entitlements, JIT approve/deny, NHI inventory/hygiene, key lifecycle | Routing & Gateway · Governance |
| Mandate | Route `input-data-policy`, output-guardrails, PII/memory config | Routing & Gateway · Policies / Memory |
| Toolbox | `/gateway/mcp/servers*`, governed tool list/call | Routing & Gateway · Policies (MCP) |
| Escalation | Prod dual-approval headers, JIT, long-term memory dual-approval | Routing & Gateway · Security |
| Fence | `/cost/*` budgets, passthrough allowlists, browser risk policies, scans | Cost · Passthrough · Browser Security · Benchmark & Scan |
| Ledger | `/audit/events`, `/compliance/evidence*`, `risk_tier` on infer | Audit · Compliance · Gateway responses |

## SE demo sequence (doctrine-first)

1. State Contract + clocks (2 min)  
2. Show **deny** on tool/policy (not a happy-path only demo)  
3. Show dual-approval or JIT path  
4. Show audit/evidence export slice  
5. Optional: browser risk / NHI hygiene  
6. Never open with model beauty contest  

## Engineering epic mapping

| Epic | Likely surfaces |
|------|-----------------|
| A Chokepoint | Gateway routes, SDK defaults, entitlements |
| B Mandate | input-data-policy, output-guardrails |
| C Toolbox | MCP registry enforcement |
| D Escalation | Dual-approval, JIT |
| E Fence | Cost budgets, passthrough, revoke UX |
| F Ledger | Audit completeness, compliance export, scorecard feeds |
| G Steward UX | Contract/DoD templates in operator UI (future) |

## Honesty for product marketing

We do not claim prompt injection is solved.  
We claim mediation, least agency, dual control, budgets, and exportable evidence — **governed velocity**.

Use `governed-velocity-guardbridge.md` for prose; this index for mapping.
