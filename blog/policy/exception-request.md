# Agency Contract — Exception Request Form

**Policy:** AI-CTRL-001  
**Rule:** Exceptions are time-bounded (≤ 90 days). Permanent exceptions are prohibited.  
**Accountable approver:** CISO (risk) + Business Owner (value)

---

## 1. Requester

| Field | Value |
|-------|-------|
| Date | |
| Requester name / team | |
| Business owner | |
| Agent / system name | |
| Environment | dev / stage / **prod** |

## 2. Exception sought

Clauses that cannot be met (check all that apply):

- [ ] Identity  
- [ ] Mandate  
- [ ] Toolbox  
- [ ] Escalation  
- [ ] Fence  
- [ ] Ledger  
- [ ] Control-plane mediation  
- [ ] Production Definition of Done item: ________

**Describe the gap in one paragraph:**

## 3. Business justification

**What breaks if we defer go-live?** (revenue, safety, legal deadline — be specific)

**Why is this not solvable within 30 days on-plane?**

## 4. Blast radius

| Question | Answer |
|----------|--------|
| Data classes reachable | |
| Tools / MCP reachable | |
| Egress possible? | |
| Irreversible acts possible? | |
| Worst-case impact if hijacked | |

## 5. Compensating controls (mandatory)

List controls that bound privilege until the gap closes (e.g., reduced toolbox, human-in-loop on all sends, IP allowlist, lower budget, shortened key TTL, enhanced monitoring).

1.  
2.  
3.  

## 6. Exit criteria & expiry

| Field | Value |
|-------|--------|
| Exception expiry (≤ 90 days) | |
| Remediation owner | |
| Remediation milestones | |
| Scorecard items impacted | |
| Auto-disable on expiry? (must be Yes for prod) | Yes / No |

## 7. Approvals

| Role | Name | Date | Decision |
|------|------|------|----------|
| Business owner | | | Accept risk / Withdraw |
| Platform | | | Feasible / Not feasible |
| Security engineering | | | Compensating OK / Not OK |
| **CISO (A)** | | | **Approve / Deny** |

## 8. Register entry

On approval, add to Exception Register: ID · agent · clauses · expiry · compensations · owners.  
On expiry without remediation: **automatic privilege reduction or disablement.**
