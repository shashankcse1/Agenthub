# Template — Exception Register

**Policy:** AI-CTRL-001 · Max duration 90 days · Permanent = prohibited  
**Owner:** OACP Governance Analyst · **Review:** Biweekly scrub

| ID | Agent / system | Clauses waived | Compensating controls | Expiry | Auto-disable? | Business owner | CISO accept date | Status |
|----|----------------|----------------|----------------------|--------|---------------|----------------|------------------|--------|
| EX-001 | | | | YYYY-MM-DD | Y/N | | | Active / Expired / Disabled |
| EX-002 | | | | | | | | |

## Status definitions

| Status | Meaning |
|--------|---------|
| Active | Within expiry; compensations verified |
| Expiring (&lt;14d) | Reminder sent; remediation or disable |
| Expired-privileged | **Incident** — privilege still on after expiry |
| Disabled | Privilege reduced/removed |
| Closed-remediated | Gap closed; Contract updated |

## Weekly job

1. Flag Expiring  
2. Page owners of Expired-privileged within 4 hours  
3. Report count of Active + Expired-privileged in scorecard email  
