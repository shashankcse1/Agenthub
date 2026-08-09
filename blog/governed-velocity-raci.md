# Governed Velocity — RACI

**R** = Responsible · **A** = Accountable · **C** = Consulted · **I** = Informed

One **A** per row. If two people argue they are A, you do not have governance yet.

---

## Doctrine & policy

| Activity | CISO | CTO | CRO/Risk | Platform | App owners | GTM/Comms | Board |
|----------|------|-----|----------|----------|------------|-----------|-------|
| Agency Contract policy adoption | A | R | C | C | I | I | I |
| Vocabulary / doctrine lock | A | C | C | C | I | R | I |
| Exception risk acceptance | A | C | C | C | R | I | I |
| Day-90 residual risk to board | R | C | A | C | I | C | I |

---

## Control plane & engineering

| Activity | CISO | CTO | Platform | App owners | Sec eng | FinOps |
|----------|------|-----|----------|------------|---------|--------|
| Control plane availability / defaults | C | A | R | C | C | I |
| Migrate prod inference on-plane | C | A | R | R | C | I |
| Route input/output policies | A | C | R | C | R | I |
| MCP allowlist | A | C | R | C | C | I |
| Dual-approval enforcement | A | C | R | C | R | I |
| Budgets / spend fences | C | A | R | C | I | R |
| NHI hygiene | A | C | R | C | R | I |

---

## Prove & respond

| Activity | CISO | Platform | Sec eng | Compliance | App owners | On-call |
|----------|------|----------|---------|------------|------------|---------|
| Scorecard data integrity | A | R | C | C | C | I |
| Evidence export drill | A | C | C | R | I | I |
| Revoke / kill-switch drill | A | R | R | I | C | R |
| IPI / silent-egress red team | A | C | R | I | C | I |
| S1/S2 agent incident command | A | C | R | C | C | R |
| Post-incident Contract revision | A | C | C | I | R | I |

---

## External

| Activity | CISO | CTO | Comms | GTM | Legal |
|----------|------|-----|-------|-----|-------|
| Public manifesto publish | C | C | A | C | C |
| Analyst brief | C | C | A | C | C |
| Customer doctrine-first narrative | C | C | C | A | C |
| Product claims accuracy | A | C | C | R | C |

---

## Escalation path

1. App owner → Platform (control gap)  
2. Platform → CISO (policy / risk accept)  
3. CISO → CRO / Board risk (residual risk, S1)  
4. CTO can halt new prod agents when scorecard Identity / Escalation / Ledger is Red  

---

## Meeting cadence

| Forum | Cadence | A |
|-------|---------|---|
| Scorecard review | Weekly (ops) · 30/60/90 (exec) | CISO |
| Exception review | Biweekly | CISO |
| Tabletop incident | Quarterly | CISO |
| Policy review | Quarterly | CISO |
