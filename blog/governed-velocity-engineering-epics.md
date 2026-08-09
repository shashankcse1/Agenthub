# Control Plane — Engineering Epic Backlog

**Purpose:** Turn doctrine into a build sequence platforms can staff  
**Order:** Paved road first · prove clocks second · privilege expansion last  
**Maps to:** Architecture principles P1–P10 · Contract clauses

---

## Epic A — Chokepoint paved road

**Outcome:** Tier-1 inference cannot go to prod off-plane without detection  

| Story themes | Clause |
|--------------|--------|
| Official SDKs / sidecars default to gateway | Identity |
| Entitlement issuance + short TTL | Identity |
| Off-plane detection sensors + alerts | Ledger |
| Migration runbooks for top routes | — |

**Exit:** On-plane coverage measurable; unmanaged keys trending to 0  

---

## Epic B — Mandate & output policy

| Story themes | Clause |
|--------------|--------|
| Route input data policy UX + API | Mandate |
| Output guardrails allow/warn/block/transform | Mandate / Escalation |
| Redaction libraries for secrets/PII classes | Mandate |
| Policy change dual-approval in prod | Escalation |

**Exit:** 100% tier-1 routes with input+output policy  

---

## Epic C — Toolbox mediation

| Story themes | Clause |
|--------------|--------|
| MCP registry + allowlist enforcement | Toolbox |
| Pre-exec argument validation hooks | Toolbox |
| Tool catalog ownership + review workflow | Toolbox |
| Default-deny for browse/egress tools | Fence |

**Exit:** 100% prod tool calls on registered servers  

---

## Epic D — Escalation machinery

| Story themes | Clause |
|--------------|--------|
| Dual-approval header enforcement (not UI-only) | Escalation |
| JIT request approve/deny workflows | Escalation |
| Irreversible act taxonomy config | Escalation |
| Approval audit completeness | Ledger |

**Exit:** Scoped prod mutations 100% dual-covered  

---

## Epic E — Fence & kill

| Story themes | Clause |
|--------------|--------|
| Budgets soft/hard + anomaly hooks | Fence |
| Passthrough / egress allowlists | Fence |
| One-command revoke orchestration | Fence |
| Fail-closed modes for tier-1 | P2 |

**Exit:** Revoke drill ≤ 15m median; hard budget stops work  

---

## Epic F — Ledger & prove

| Story themes | Clause |
|--------------|--------|
| Event schema per instrumentation guide | Ledger |
| Evidence export API + filters | Ledger |
| Scorecard pipelines (auto cells) | Ledger |
| Red-team harness hooks | — |

**Exit:** Export RTO ≤ 60m; weekly scorecard auto-fill  

---

## Epic G — Steward experience

| Story themes |
|--------------|
| Contract + DoD templates in portal |
| Exception form + auto-expiry jobs |
| Onboarding T-14 checklist automation |
| Worked-example gallery |

**Exit:** Stewards file without PowerPoint contracts  

---

## Sequencing (suggested)

```
A → B+C (parallel) → D+E → F → G
Prove drills start as soon as A+E exist — do not wait for perfect UX.
```

## Definition of done for an epic

- [ ] Maps to Contract clause + scorecard metric  
- [ ] Fail-closed behavior documented  
- [ ] Ledger fields emitted  
- [ ] Revoke/disable path exists  
- [ ] Steward-facing docs updated  
