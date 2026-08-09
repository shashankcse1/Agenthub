# GuardBridge Activation Sprint — Platform Edition

**Repo:** this control-plane codebase (GuardBridge / gateway operator surface)  
**Companion:** generic 7-day sprint · this file = *where to click / which API*  
**Rule:** Doctrine stays in Leader’s Brief. Here we only activate.

---

## Day 1 — Authority (docs → owners)

- [ ] Assign OACP Head; record in `STATUS.md`  
- [ ] Adopt (or schedule vote on) Constitution + AI-CTRL-001 + AI-RISK-001  
- [ ] Baseline Leader Readiness Score honestly  
- [ ] Decision log `GV-DEC-001` = activation started  

No product work today except naming who owns freeze.

---

## Day 2 — Inventory (use the plane)

| Hunt | How on this platform |
|------|----------------------|
| NHI / key sprawl | `GET /gateway/nhi/inventory` + `GET /gateway/nhi/hygiene` · UI: Routing & Gateway → Governance / NHI |
| Inference paths | List apps still calling providers with raw keys (off-plane) vs `/v1/chat/completions` · `/v1/responses` |
| Tool/MCP surface | `GET /gateway/mcp/servers` · list tools per server |
| Passthrough risk | Review `POST /v1/passthrough` allowlists + dual-approval usage |
| Browser shadow AI | Browser Security · `/browser/risk-policies*` |

**Exit:** Top 10 privilege graphs written (agent × tools × data).

---

## Day 3 — Chokepoint

| Action | Platform anchor |
|--------|-----------------|
| Force new prod inference on-plane | Clients use gateway `/v1/chat/completions` (and related) with entitlements — not app-held provider keys |
| Prove mediation | Successful call returns / logs `risk_tier` / audit evidence for the route |
| Entitlements | `/gateway/entitlements*` · JIT `/gateway/jit-requests*` for access pressure |
| Ban new god keys | Policy + key lifecycle; temporary budget increases only via guarded APIs |

**Exit:** One tier-1 workload on-plane end-to-end with audit visible in `GET /audit/events`.

---

## Day 4 — Clocks (non-negotiable)

### Revoke drill

1. Pick a test entitlement / key / JIT grant  
2. Start timer  
3. Revoke via key lifecycle / entitlement disable / JIT deny path  
4. Confirm subsequent infer/tool calls **deny**  
5. Record median in `STATUS.md` (target ≤ 15m)  

### Evidence export drill

1. Start timer  
2. `POST /compliance/evidence/export` (and/or control bundle `GET /compliance/evidence/{id}/bundle`) with scoped filters  
3. Confirm bundle integrity / usable event rows  
4. Record RTO in `STATUS.md` (target ≤ 60m)  

**Fail the day** if either number is “we’ll try later.”

---

## Day 5 — Gates (Contract teeth)

| Clause | Activate on platform |
|--------|----------------------|
| Mandate | `PUT .../input-data-policy` + `PUT .../output-guardrails` on a critical `route_policy_id` (prod dual-approval) |
| Toolbox | MCP registry only — `GET /gateway/mcp/servers`; no ad-hoc servers in prod |
| Escalation | Exercise dual-approval on a prod mutation (passthrough, memory, policy upsert, or JIT) |
| Fence | `POST /cost/budgets` for the tier-1 scope; review passthrough allowlist |
| Ledger | Confirm allow/deny for the above in `/audit/events` |

**Exit:** One launch deferred **or** one ≤90d exception filed — gate must hurt once.

---

## Day 6 — Rhythm

- [ ] Weekly glance owner + Monday slot  
- [ ] Coverage standup on calendar  
- [ ] Tabletop date (use timed script; prefer RT-01 path)  
- [ ] Game Day quarter/annual date  
- [ ] Steward cohort roster from app owners using gateway  

Consoles to bookmark: Routing & Gateway · Compliance · Security · Browser Security · Benchmark & Scan  

---

## Day 7 — Declare

- [ ] OS go-live checklist cleared or blockers named with dates  
- [ ] Internal declaration sent (CISO+CTO)  
- [ ] External “leader” claims frozen until readiness ≥ 32  
- [ ] `STATUS.md` → Active or Blocked  
- [ ] SE/demo rule: doctrine-first sequence from `guardbridge-index.md`  

---

## SE / demo honesty (post-activation only)

Show **deny** (policy/tool) → approval path → audit/export.  
Never open with model quality. Injection is unsolved; mediation is the product of leadership.
