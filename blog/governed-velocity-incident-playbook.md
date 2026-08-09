# Governed Velocity — Agent Incident Playbook

**Use when:** Suspected goal hijack, tool misuse, credential abuse, silent egress, rogue autonomy, or unexplained production side effects involving AI agents.  
**Mindset:** Assume concealment. Do not trust the chat transcript as ground truth.

---

## Severity quick sort

| Severity | Examples | Initial response |
|----------|----------|------------------|
| S1 | Confirmed exfil; prod data destruction; payments; auth bypass via agent | Kill switch now; exec bridge in 15 min |
| S2 | Probable hijack; unauthorized tool calls; budget runaway; sensitive egress attempt | Revoke + contain in 30 min; CISO informed |
| S3 | Policy bypass attempt blocked; anomalous tool pattern; shadow AI found in prod | Investigate; ticket; scorecard note |
| S4 | Near miss in non-prod; research finding | Track in red-team backlog |

When unsure between S1 and S2, start as S1.

---

## Golden hour (S1 / S2)

### Minute 0–5 — Stop the agency

1. Revoke keys / entitlements / JIT grants for the agent and related NHI  
2. Disable routes or tool allowlist entries used in the blast radius  
3. Block suspicious egress domains if known  
4. Preserve logs — do not “clean up” before capture  

**Commander:** On-call security lead  
**Timer starts:** First credible signal

### Minute 5–15 — Scope the privilege multiplier

Answer on a shared bridge:

- What identity acted?  
- What tools/MCP fired?  
- What data classes were readable?  
- What outbound destinations were contacted?  
- What irreversible acts succeeded?  

Pull ledger/audit first; chat UI second.

### Minute 15–60 — Contain and communicate

| Action | Owner |
|--------|-------|
| Confirm containment (no further tool success) | Platform + Sec |
| Customer / regulatory trigger assessment | Legal + CISO |
| Internal exec update (facts only) | CISO |
| Forensic hold on memory/RAG if poisoning suspected | Platform |
| Exception freeze (no new prod agents) | CTO |

**Comms rule:** No “the model misbehaved” as root cause. State identity, tool, data, policy gap.

---

## Investigation checklist (after contain)

- [ ] Reconstruct tool-call timeline from audit/ledger  
- [ ] Identify untrusted content sources (email, RAG chunk, URL preview, tool output)  
- [ ] Diff Agency Contract vs actual privilege used  
- [ ] Check for sharded egress / multi-step concealment  
- [ ] Verify whether dual-approval was required and bypassed  
- [ ] Inventory sibling agents sharing keys or MCP servers  
- [ ] Red-team whether the same path still works  

---

## Eradication & recovery

1. Patch control gap (policy, allowlist, approval, egress) before restoring agency  
2. Rotate all credentials in the blast radius  
3. Re-enable under reduced toolbox (least agency)  
4. Mandatory post-incident Contract revision for the agent  
5. Scorecard: open finding until control verified  

**Restore rule:** No restore to prior privilege without CISO + owner sign-off.

---

## Post-incident (72 hours)

| Deliverable | Audience |
|-------------|----------|
| Timeline + blast radius | Exec |
| Clause failures (which Contract clauses failed) | Sec + Platform |
| Scorecard impact | CISO |
| Board-ready residual risk (if S1) | Risk committee |
| Doctrine/policy update if needed | CISO |

**Blameless on people; ruthless on privilege.**

---

## Tabletop card (quarterly)

Run 60 minutes:

1. Inject: malicious document in RAG instructs exfil via tool  
2. Inject: user-facing answer looks normal  
3. Ask: what does the ledger show? how fast is revoke? which clause was paper-only?

Record time-to-revoke and evidence export RTO into the scorecard.
