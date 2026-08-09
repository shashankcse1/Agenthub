# OACP — Role Profiles (hire / assign)

Minimum viable staffing for the Control Plane Era. Combine in small orgs; do not combine **risk acceptance** with **feature delivery ownership**.

---

## Head of AI Control Plane

**Reports to:** CTO · **Dotted line:** CISO  
**Mission:** Coverage, gates, freeze authority, scorecard integrity  

**Owns:** On-plane defaults · DoD gate · exception register ops · governance SLO reporting  
**Does not own:** Model quality · business use-case prioritization · risk acceptance (CISO)  

**Success (year 1):** Tier-1 coverage at target · unmanaged keys = 0 · drills routine · maturity ≥ L3 for tier-1  

---

## Control Plane Engineer

**Mission:** Make mediation fast, fail-closed, and enforceable  

**Owns:** Gateway policy features · MCP allowlist plumbing · budget hooks · dual-approval enforcement paths · mediation latency SLO  

**Success:** p95 overhead within SLO · zero silent bypass for tier-1 · paved road SDKs teams actually use  

---

## AI Security Engineer

**Mission:** Break agents on purpose; harden clauses that fail  

**Owns:** Red-team library execution · vendor questionnaire tech review · incident technical command support · input/output policy content standards  

**Success:** Quarterly RT-01+RT-02 · findings closed or risk-accepted with expiry · S1 contain within response SLO  

---

## Governance Analyst

**Mission:** Evidence, exceptions, and board-ready numbers without spin  

**Owns:** Scorecard data quality · evidence export drills · exception aging · transparency report draft · steward training logistics  

**Success:** Empty cells = 0 after day 30 · export RTO known · maturity worksheet current  

---

## Agency Contract Steward (federated, not central FTE)

**Mission:** Keep a production agent honest under the six clauses  

**Owns:** Contract file · DoD sign-off · blast-radius narrative · first call on anomalies for their agent  
**Trained via:** Steward curriculum · renewed yearly  

---

## Interview probes (leaders use these)

1. “Walk me through fail-closed vs fail-open for tier-1.”  
2. “Tool ran; chat looked fine. What do you pull first?”  
3. “How do you stop permanent exceptions?”  
4. “What KPI would you refuse to report to the board?”
