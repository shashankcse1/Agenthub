# Sample Day-90 Board Report — Governed Velocity

**Entity:** ExampleCo (illustrative)  
**Period:** Days 0–90 post Resolution YYYY-AI-01  
**Prepared by:** CISO · **Contributors:** CTO, OACP  
**Status:** Sample for packet formatting — replace with real numbers

---

## 1. Resolution response (required items)

| Item | Target | Result | Status |
|------|--------|--------|--------|
| Tier-1 on-plane coverage | ≥ 90% | **93%** | Green |
| Dual-approval coverage (scoped prod mutations) | 100% | **100%** of scoped classes | Green |
| Median time-to-revoke | ≤ 15m | **8m** (drill 2026-09-12) | Green |
| Evidence export RTO | ≤ 60m | **27m** (drill 2026-09-18) | Green |
| Open material red-team findings | Trend down; none silent | **1 P2** (MCP descriptor review) due 2026-10-15 | Amber |
| Unmanaged prod keys | 0 | **0** | Green |

## 2. Maturity

**Declared level: L3 — Under contract** (tier-1 estate).  
Not L4: recurring red team only one full cycle; transparency report not yet annualized.

## 3. Estate snapshot

| Metric | Day 0 | Day 90 |
|--------|-------|--------|
| Production agents under Contract | 4 | 19 |
| Active exceptions | n/a | 2 (expiry ≤ 45 days) |
| Exceptions past expiry | — | 0 |
| Agents deferred at DoD gate | — | 6 |

## 4. Assurance

- Red team: RT-01, RT-02, RT-03 executed in staging+limited prod-like  
- S1/S2 agent incidents: **0**  
- Vendor questionnaires: 11 completed · 2 Fail (blocked) · 3 Conditional  

## 5. Residual risk (plain language)

We still accept: (a) human operators approving polished but wrong drafts; (b) residual prompt-injection risk inside allowlisted tools; (c) two Conditional vendors under compensating controls until expiry.

We refuse: unmanaged keys, fail-open tier-1 mediation, permanent exceptions.

## 6. Ask of the Committee

1. Note progress against Resolution YYYY-AI-01  
2. Endorse continued freeze authority when Identity/Escalation/Ledger SLO is Red &gt; 7 days  
3. Schedule quarterly scorecard (not only day-90)  

## 7. Board paragraph (unchanged doctrine)

We will not slow AI to feel safe, and we will not ship autonomy without a control plane. Every production agent runs under an Agency Contract. Success is governed velocity: features shipped, privilege contained, decisions we can defend.

---

**Attachments:** Scorecard export · Exception register · Open findings · OACP charter status
