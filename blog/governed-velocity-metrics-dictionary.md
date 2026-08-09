# Metrics Dictionary — Governed Velocity

**Purpose:** One definition per metric so Finance, Sec, and Platform stop arguing about green  
**Owner:** OACP Governance Analyst · **Precision A:** Head of OACP  

---

## Coverage & identity

| Metric | Definition | Source | Cadence |
|--------|------------|--------|---------|
| On-plane coverage % | Tier-1 prod inference requests with valid control-plane `request_id` ÷ all tier-1 prod inference (incl. detected off-plane) | Gateway + off-plane sensors | Weekly |
| Unmanaged prod keys | Count of provider credentials that can call prod models/tools without control-plane entitlement binding | Secret scan + NHI inventory + provider consoles | Weekly |
| NHI with owner % | NHIs in AI estate with named human owner ÷ all AI NHIs | NHI inventory | Monthly |

## Contract enforcement

| Metric | Definition | Source | Cadence |
|--------|------------|--------|---------|
| Dual-approval coverage % | Prod mutations in scoped classes with valid dual-approval evidence ÷ all such mutations | Ledger | Weekly |
| MCP allowlist coverage % | Prod tool calls to registered servers ÷ all prod tool calls | Tool gateway | Weekly |
| Tier-1 routes with input policy % | Tier-1 routes with active input data policy ÷ tier-1 routes | Config inventory | Weekly |
| Tier-1 routes with output policy % | Same for output guardrails | Config inventory | Weekly |
| Exceptions past expiry | Privileged agents/tools still active after exception end timestamp | Exception register | Daily job |

## Clocks

| Metric | Definition | Source | Cadence |
|--------|------------|--------|---------|
| Time-to-revoke (median) | `t_effective − t_command` across drills + real S1/S2 revokes in window | Revoke orchestration logs | Per drill · quarterly rollup |
| Evidence export RTO | Wall time from export request to verified scoped bundle in drill | Export tool | Per drill · quarterly |
| Approval lag p95 | Time from approval request to grant/deny for dual paths | Ledger | Weekly |

## Fence

| Metric | Definition | Source | Cadence |
|--------|------------|--------|---------|
| Egress deny rate | Egress denies ÷ (allows+denies) for agent identities | Egress proxy / gateway | Weekly (interpret with volume) |
| Hard budget stops | Count of hard-stop budget events | Budget service | Weekly |
| Tool burst alerts | Alerts where tool allow rate &gt; N× baseline | SIEM | Weekly |

## Assurance

| Metric | Definition | Source | Cadence |
|--------|------------|--------|---------|
| Open RT P1/P2 | Findings from RT library not closed or risk-accepted with expiry | Finding tracker | Weekly |
| Tabletop completed | Boolean for quarter | OACP calendar | Quarterly |
| Vendor Fail count | Questionnaires dispositioned Fail in period | Vendor register | Quarterly |
| Leader Readiness Score | Sum per readiness rubric | Manual/attested | Quarterly |

## Forbidden vanity metrics (do not greenwash)

- Raw refusal / toxicity rate as primary governance KPI  
- “Number of agents deployed” without Contract coverage  
- Model benchmark scores as security posture  

## Change control

Metric definition changes require OACP Head approval and a changelog note in the next QBR.
