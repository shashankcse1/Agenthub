# Day-Zero — Production Agent Onboarding Runbook

**Owner:** App owner (R) · OACP (gate) · Security (A on prod)  
**Prerequisite:** Steward training complete · Policy AI-CTRL-001 in force  
**Rule:** No parallel “temporary” provider keys. On-plane from first prod token.

---

## Timeline (T-minus)

### T-14d — Intent

- [ ] Business purpose one-liner approved by business owner  
- [ ] Draft Agency Contract started (clone worked example structure)  
- [ ] Data classes + irreversible acts listed  
- [ ] OACP notified via intake form / ticket  

### T-10d — Design review

- [ ] Toolbox draft under least agency (remove before add)  
- [ ] Egress needs justified or set to deny  
- [ ] Architecture principles checklist (P1–P10) reviewed  
- [ ] Vendor paths covered by vendor questionnaire if third-party  

### T-7d — Build on plane

- [ ] Route + entitlements created in **non-prod** first  
- [ ] Input data policy + output guardrails attached  
- [ ] MCP/tools allowlisted in non-prod  
- [ ] Dual-approval paths verified where required  
- [ ] Budget + rate limits set  

### T-3d — Prove

- [ ] Definition of Done filled  
- [ ] Blast-radius paragraph written (hijack assumed)  
- [ ] Non-prod revoke dry-run for this identity class  
- [ ] Evidence query returns tool allow/deny for test traffic  
- [ ] RT micro-check: at least one concealment or egress abuse case attempted in non-prod  

### T-1d — Gate

- [ ] Security sign-off on DoD  
- [ ] Exception register empty **or** approved time-bounded exception filed  
- [ ] On-call knows kill switch runbook ID  
- [ ] Steward named + backup  

### T-0 — Go live

- [ ] Prod entitlements issued (short TTL)  
- [ ] First 24h enhanced monitoring watch  
- [ ] Scorecard hooks verified (agent appears in coverage)  
- [ ] Announce in OACP weekly (not a press release)  

### T+7d — Hypercare exit

- [ ] No P1/P2 open on this agent  
- [ ] Budget within envelope  
- [ ] Contract filed in system of record  
- [ ] Lessons → Contract revision if needed  

---

## Intake fields (minimum)

| Field | Value |
|-------|-------|
| Agent ID | |
| Owner / backup | |
| Tier (1/2/3) | |
| Purpose | |
| Go-live target | |
| Third-party components | |

## Fast reject reasons

- Raw provider key requested “just for launch”  
- `web.fetch` / send / pay tools without escalation design  
- Empty blast-radius paragraph  
- “We’ll add audit later”  
- Permanent exception requested  

**Close line for OACP:** If it can act on T-0, it is already under contract — or it does not ship.
