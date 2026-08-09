# Governed Velocity — Day-90 Scorecard Template

**Owner:** CISO (reporting) · Platform (data)  
**Cadence:** Weekly internal · Day 30 / 60 / 90 executive  
**Rule:** Empty cells are findings. Do not paint green without a number.

---

## North-star question

> Who is acting, with what power, on what data, under what rule — and where is the proof?

If this scorecard cannot support that answer, the program is still Filter Era.

---

## Scoreboard

| Metric | Definition | Day 0 | Day 30 | Day 60 | Day 90 | Target (90) | Status |
|--------|------------|-------|--------|--------|--------|-------------|--------|
| Control-plane coverage | % production inference requests via gateway / control plane | | | | | ≥ 90% tier-1 | |
| Unmanaged prod keys | Count of shared/unowned provider keys in prod | | | | | 0 | |
| Dual-approval coverage | % prod mutations in scope requiring dual approval that enforce it | | | | | 100% scoped | |
| MCP allowlist coverage | % production tool calls to registered/approved servers | | | | | 100% | |
| Critical routes with input policy | Count / % of tier-1 routes with input data policy | | | | | 100% tier-1 | |
| Critical routes with output guardrails | Count / % of tier-1 routes with output policy | | | | | 100% tier-1 | |
| Egress / passthrough deny rate | Denies ÷ governed egress attempts (monitor trend, not vanity up) | | | | | Baseline set + reviewed | |
| Median time-to-revoke | Minutes from decision to key/entitlement/agent revoke | | | | | ≤ 15 min | |
| Evidence export RTO | Minutes to produce scoped compliance evidence bundle | | | | | ≤ 60 min | |
| Open red-team findings (P1/P2) | Count open from concealment + silent-egress tests | | | | | Trend down; none silent | |

---

## Qualitative gates (checkbox)

- [ ] Agency Contract published as policy (not a slide)  
- [ ] Shadow AI amnesty completed; inventory exists  
- [ ] Kill-switch runbook tested with stopwatch  
- [ ] Board / sponsor residual-risk page delivered in plain language  
- [ ] Permanent exceptions list is empty or time-bounded  

---

## Status legend

| Status | Meaning |
|--------|---------|
| Green | On or ahead of target; evidence attached |
| Amber | In motion; date-certain owner |
| Red | Missed; blocks scale of new agents |
| Gray | Not measured yet (treat as Red after day 30) |

---

## Narrative box (exec summary — 5 lines max)

**What improved:**  
**What is still unpriced privilege:**  
**What we are deferring (and why):**  
**Ask of leadership:**  
**Residual risk in one sentence:**  

---

## Attachment checklist for day 90

1. Export sample (redacted) from ledger  
2. Revoke drill log with timestamps  
3. Red-team scenario results (concealment + egress)  
4. Exception register with expiry dates  
