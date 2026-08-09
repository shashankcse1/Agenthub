# AI Control Plane — SLO / SLA Draft

**Owner:** Head of AI Control Plane (OACP) · **Sponsor:** CTO  
**Consumer:** App owners, CISO, Finance  
**Rule:** If we cannot measure it, it is not an SLO.

---

## Reliability (platform)

| SLO | Objective | Window | Note |
|-----|-----------|--------|------|
| Availability | 99.9% successful policy decision + forward on healthy deps | 30 days | Fail **closed** on policy engine hard failure for tier-1 prod |
| p95 mediation latency | ≤ 50ms policy overhead excluding provider time | 30 days | Track separately from model latency |
| Error budget policy | Burn → freeze new route policy changes | — | Protect prove cadence |

**Fail-closed definition:** When identity/policy store is unavailable, tier-1 production agency does not silently bypass — it denies or queues per runbook.

---

## Security & governance (contract SLOs)

| SLO | Objective | Measure |
|-----|-----------|---------|
| On-plane coverage | ≥ 90% of tier-1 prod inference via control plane | Gateway logs / app telemetry |
| Unmanaged prod keys | **0** | NHI + secret scan |
| Dual-approval enforce | 100% of scoped prod mutation classes | Audit: mutations w/ valid dual headers |
| MCP allowlist | 100% prod tool calls to registered servers | Tool gateway logs |
| Time-to-revoke (median) | ≤ 15 minutes from command to ineffective creds | Quarterly + incident drills |
| Evidence export RTO | ≤ 60 minutes for scoped 24h bundle | Quarterly drill |
| Exception hygiene | 0 exceptions past expiry still privileged | Exception register job |

---

## Response SLOs (incidents)

| Severity | Contain (revoke/disable in blast radius) | Exec update |
|----------|------------------------------------------|-------------|
| S1 | ≤ 15 minutes | ≤ 15 minutes |
| S2 | ≤ 30 minutes | ≤ 60 minutes |
| S3 | ≤ 1 business day | As needed |

Ground truth for egress incidents includes **network** evidence, not chat transcripts alone.

---

## Reporting

| Audience | Cadence | Content |
|----------|---------|---------|
| OACP standup | Weekly | Burn, coverage, blockers |
| CISO/CTO | 30/60/90 · quarterly | Contract SLOs + maturity |
| Board risk | Day 90 · quarterly | Residual risk + exceptions aged |

---

## Non-goals

- Model quality / hallucination SLOs (product owns)  
- Vendor model uptime (track, but separate)  
- “Toxicity score” as a governance SLO  

---

## Breach of governance SLO

1. Auto-notify CISO + CTO  
2. Freeze net-new prod agents if Identity, Escalation, or Ledger SLO breached for &gt; 7 days without plan  
3. Exception register review within 48 hours  
4. Board mention if S1 or freeze exceeds 14 days  
