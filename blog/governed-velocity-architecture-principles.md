# AI Control Plane — Architecture Principles (ADR-style)

**Status:** Adopted with Policy AI-CTRL-001  
**Audience:** Platform, security engineering, architecture review  

---

## P1 — Mediate all production agency

Every production model call, tool call, and privileged egress path traverses the control plane. App-held long-lived provider keys for prod are defects.

## P2 — Fail closed on tier-1

If identity, policy, or allowlist systems cannot decide safely, tier-1 agency denies (or holds) — it does not bypass. Availability is recovered explicitly, not by disabling governance.

## P3 — Identity before intelligence

No model routing until a named principal, owner, and entitlement exist. Smart agents with anonymous privilege are forbidden.

## P4 — Least agency by default

Tool/MCP graphs are default-deny. Expansion is a change-managed event with dual approval in production, not a config convenience.

## P5 — Untrusted content never becomes authority

Email, tickets, docs, web, RAG chunks, and tool outputs are data. They must not independently authorize irreversible acts. Escalation clauses bind authority.

## P6 — Side effects are first-class events

Tool execution, egress, memory writes, and approvals emit ledger events suitable for export. Chat transcripts are not the system of record.

## P7 — Prove with clocks

Revoke and evidence export have numeric SLOs. A control without a last drill date is aspirational.

## P8 — Exceptions decay

Every exception has an expiry and auto-reduction path. Architecture must support disablement without heroics.

## P9 — Separation of duties

Risk acceptance (CISO) is not the same role as feature delivery (app owner) or chokepoint build (OACP). Dual approval is enforced in the plane, not only in UI.

## P10 — Doctrine before features

New gateway capabilities map to Agency Contract clauses and scorecard metrics. Features that increase privilege without clause coverage are rejected in architecture review.

---

## Review questions (ARB)

1. What new privilege does this introduce?  
2. Which Contract clause covers it?  
3. What is the deny behavior under dependency failure?  
4. What ledger fields are emitted?  
5. How is it revoked in ≤ 15 minutes?  
6. Does the worked-example pattern still hold (remove before add)?  
