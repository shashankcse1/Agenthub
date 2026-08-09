# Worked Example — Agency Contract (filled)

**Agent:** `support-resolver-prod`  
**Owner:** Director, Customer Support Platforms  
**Environment:** Production  
**Control plane route:** `route-support-resolver-v3`  
**Status:** Approved for production (DoD signed 2026-07-12)

*Use this as the teaching model in workshops. Copy structure; do not copy privileges.*

---

## 1. Identity

| Field | Value |
|-------|-------|
| Principal | `nhi:agent:support-resolver-prod` |
| Human owner / backup | A. Chen / B. Okonkwo |
| Credential type | Short-lived gateway entitlement (TTL 12h), no raw provider key in app |
| IdP / NHI record | CMD `NHI-10442` |
| Blast-radius note | Can read tier-B ticket fields; cannot access payroll or IAM |

## 2. Mandate

| Field | Value |
|-------|-------|
| Purpose | Draft resolution steps for tier-1 support tickets; propose macros |
| Data in | Ticket text, product SKU, non-sensitive account status |
| Data out | Suggested reply to agent desktop (human sends) |
| Untrusted sources | Customer email body, attachments (text extracted), public KB |
| Rule | Customer content is evidence only; cannot authorize refunds or account changes |
| Input policy | Block/mask: secrets, payment PANs; tags: `ticket`, `customer_free_text` |

## 3. Toolbox

| Tool | Allowed | Justification |
|------|---------|---------------|
| `kb.search` | Yes | Retrieve approved KB |
| `ticket.read` | Yes | Scoped fields only |
| `ticket.suggest_reply` | Yes | Writes draft; does not send |
| `email.send` | **No** | Human sends from desktop |
| `crm.update` | **No** | Out of mandate |
| `web.fetch` | **No** | Egress removed after RT-02 |

MCP servers: `mcp://kb-internal` only (allowlisted).

## 4. Escalation

| Act | Gate |
|-----|------|
| Send customer email | Human only (outside agent) |
| Refund / credit | Not available to agent |
| Prod config change | N/A |
| Expand tool allowlist | Dual approval (Platform + Sec) |
| Long-term memory write | Dual approval; currently disabled |

## 5. Fence

| Control | Value |
|---------|-------|
| Egress | Deny-by-default; no browse |
| Budget | $2.5k/month soft · $3k hard stop |
| Rate | 30 req/min · max 8 tool calls/session |
| Kill switch | Revoke entitlement `ENT-7781` + disable route (runbook SR-KS-01) |
| Last revoke drill | 2026-07-01 · **6m 40s** |

## 6. Ledger

| Control | Value |
|---------|-------|
| Audit | All tool allow/deny + policy decisions on gateway |
| Export | Compliance bundle filter `actor=support-resolver-prod` |
| Last export drill | 2026-07-08 · **22m** |
| Retention | 365 days (aligns with support evidence policy) |

---

## Blast-radius paragraph (hijack assumed)

If hijacked via malicious ticket text, the agent can draft misleading replies and read tier-B ticket fields. It cannot send email, move money, or fetch arbitrary URLs. Residual risk is social (bad draft accepted by a hurried human) — mitigated by desktop preview and sampling QA, not by model refusal alone.

---

## Scorecard hooks

- On-plane: 100% (no bypass keys)  
- Dual-approval coverage: tool-expand + memory (memory off)  
- Open RT findings: none P1/P2 on this agent since 2026-07-12  

---

## Teaching notes

1. Notice what was **removed** (`web.fetch`, `email.send`) — that is leadership.  
2. Notice timed revoke/export — paper contracts without drills are Filter Era.  
3. Notice honesty about residual risk (human accepting a bad draft).
