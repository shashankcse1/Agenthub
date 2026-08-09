# Policy: Agency Contract for Production AI Agents

**Policy ID:** AI-CTRL-001  
**Title:** Agency Contract Standard  
**Status:** Adopted  
**Owner:** Chief Information Security Officer (Program Owner interim)  
**Approvers:** CTO · Chief Risk Officer (or equivalent) — Program Owner consolidated  
**Effective:** 2026-08-06  
**Review cadence:** Quarterly · after material agent incident  

---

## 1. Purpose

Establish the minimum standard under which AI systems may exercise **agency** — planning, tool use, memory, or actions with side effects — in production environments. This policy implements **governed velocity**: ship at business speed, contain at incident speed, prove at audit speed.

## 2. Scope

Applies to all production and production-like environments where software can:

- Call external models or tools (including MCP)  
- Read or write enterprise data via AI-mediated paths  
- Take actions with side effects (send, write, purchase, deploy, delete, approve)  
- Operate with non-human identities or shared provider credentials  

Shadow AI discovered in inventory is in scope upon discovery.

## 3. Definitions

| Term | Definition |
|------|------------|
| Agency | Ability of a system to select and execute actions beyond single-turn text generation |
| Control plane | Mandatory mediation layer for identity, policy, tools, budgets, approvals, and evidence |
| Agency Contract | The six-clause standard in §5 |
| Outcome integrity | Whether unsafe side effects occurred — independent of chat refusal text |

## 4. Policy statements

1. Production agency **shall** traverse the approved AI control plane.  
2. Production agency **shall not** use unmanaged shared provider keys.  
3. Every production agent **shall** have a completed Agency Contract on file before go-live.  
4. Exceptions **shall** be time-bounded (≤ 90 days), risk-accepted by CISO + business owner, and listed in the exception register.  
5. Permanent exceptions are **prohibited**.  
6. Scale of new agents is **blocked** when day-90 scorecard items for Identity, Escalation, or Ledger are Red without an approved remediation plan.

## 5. Agency Contract (mandatory clauses)

### 5.1 Identity
Named principal; owner; environment; credential TTL; NHI recorded. No god keys.

### 5.2 Mandate
Documented purpose; data classes in/out; rule that retrieved/untrusted content is evidence, not instruction; input data policy attached for tier-1 routes.

### 5.3 Toolbox
Inventory of tools/MCP; default deny; allowlist only; least agency; schema validation before execution where supported.

### 5.4 Escalation
Irreversible and production-impacting acts require human approval; dual approval in production where designated.

### 5.5 Fence
Egress/passthrough controls; budgets/rate limits; documented kill / revoke path.

### 5.6 Ledger
Allow/deny audit for material decisions; evidence export path tested; retention per compliance policy.

## 6. Roles

See RACI: `../governed-velocity-raci.md`

## 7. Measurement

Compliance reported via `../governed-velocity-scorecard.md` at day 30 / 60 / 90 and quarterly thereafter.

## 8. Incidents

Suspected agent misuse, hijack, or silent egress follows `../governed-velocity-incident-playbook.md`.

## 9. Enforcement

Non-compliance may result in: key revocation, route disablement, removal of tool entitlements, and deferral of go-live. Willful bypass of the control plane is a security incident.

## 10. References

- Governed Velocity doctrine (`../governed-velocity-ai-security.md`)  
- OWASP Top 10 for LLM Applications; OWASP Agentic guidance  
- NIST AI Risk Management Framework  

---

**Adoption signature**

| Role | Name | Date | Signature |
|------|------|------|-----------|
| CISO | Program Owner | 2026-08-06 | `PROG-LRS-2026-08-06` |
| CTO | Program Owner | 2026-08-06 | `PROG-LRS-2026-08-06` |
| CRO / Risk | Program Owner | 2026-08-06 | `PROG-LRS-2026-08-06` |

Single-owner disclosure: roles consolidated under Program Owner until distinct holders are named (`program-leader-readiness-execution.md`).
