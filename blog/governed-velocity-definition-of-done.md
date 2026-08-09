# Production Agent — Definition of Done

**Gate name:** Prove before scale  
**Rule:** If any box is unchecked, it is not production. It is a demo with credentials.

---

## Identity

- [ ] Named agent / system ID in inventory  
- [ ] Human owner + backup owner  
- [ ] Environment tagged (dev / stage / prod)  
- [ ] Credentials are scoped, short-lived, not shared across apps  
- [ ] NHI record exists; no unmanaged provider key in app config  

## Mandate

- [ ] One-sentence business purpose documented  
- [ ] Data classes in/out listed  
- [ ] Untrusted content sources listed (email, web, RAG, tools)  
- [ ] Tier-1: input data policy attached on control-plane route  
- [ ] “Retrieved content ≠ instruction” acknowledged by owner  

## Toolbox

- [ ] Full tool / MCP inventory attached  
- [ ] Each tool justified against purpose (least agency)  
- [ ] Unapproved tools unreachable in prod  
- [ ] Schema / argument validation enabled where platform supports it  

## Escalation

- [ ] Irreversible acts enumerated  
- [ ] Human approval path defined for each  
- [ ] Production dual-approval enforced where policy requires  
- [ ] No auto-approve for payment, delete, IAM, prod deploy, or customer egress  

## Fence

- [ ] Egress / passthrough allowlist defined  
- [ ] Budget and rate limits set  
- [ ] Kill / revoke path documented and owner-reachable  
- [ ] Blast-radius paragraph written (“if hijacked, what breaks?”)  

## Ledger

- [ ] Material allow/deny decisions audited on-plane  
- [ ] Evidence export path identified  
- [ ] Owner can state how to retrieve last 24h of tool calls  
- [ ] Retention aligns with compliance policy  

## Prove

- [ ] On control plane in prod (not bypass)  
- [ ] Revoke drill completed for this identity class (or covered by platform drill)  
- [ ] Red-team notes reviewed for this pattern (concealment / tool misuse)  
- [ ] Agency Contract filed; exception register empty or time-bounded  

---

## Sign-off

| Role | Name | Date |
|------|------|------|
| App owner (R) | | |
| Platform (C) | | |
| Security (A for prod gate) | | |

**Decision:** ☐ Approved for production · ☐ Deferred · ☐ Exception until ______
