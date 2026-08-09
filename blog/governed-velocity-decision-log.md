# OACP Decision Log — Template

**Purpose:** Durable memory for freeze, exceptions, appetite, and epic cuts  
**Owner:** Governance Analyst · **Review:** each QBR  

---

## Log format (append-only)

| ID | Date | Decision | Context | Options | Chosen | A | Effective | Expiry / review |
|----|------|----------|---------|---------|--------|---|-----------|-----------------|
| GV-DEC-001 | | | | | | | | |

## Decision types (tag one)

- `freeze` · `unfreeze`  
- `exception-approve` · `exception-deny`  
- `appetite-tighten`  
- `epic-cut` · `slo-change`  
- `external-claim` (allow/deny narrative)  
- `vendor-fail`  
- `maturity-declare`  

## Required fields for freeze / unfreeze

- Scorecard metrics that triggered  
- Lift criteria (numeric)  
- Communication sent to app owners (link)  

## Required fields for external-claim

- Leader Readiness Score  
- Exact claim language approved  
- Channels allowed (keynote / web / sales)  

## Anti-pattern

Decisions only in Slack with no ID → treat as **non-decisions** under audit.
