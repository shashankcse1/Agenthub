# Crisis Communications — Agent Incident (External / Exec)

**Use with:** Incident playbook (technical)  
**Owner:** Comms · **Accuracy:** CISO · **Legal:** review S1  
**Rule:** No “the AI went rogue.” Name privilege, action, containment.

---

## Holding statement (T+30 to T+90 min, S1)

We are responding to an incident involving an AI-assisted system with access to [system class — e.g., support tooling]. We have revoked relevant credentials and disabled affected capabilities. We have no evidence at this time of [impact we can honestly rule out], and we are verifying [what remains under investigation]. We will update [customers/regulators] as facts stabilize.

**Do not include:** speculation on model vendors, blame on a single employee, “fully contained” unless revoke+egress verified.

---

## Customer email skeleton

**Subject:** Security incident update — AI system access contained  

1. What happened (one paragraph, side-effect language)  
2. What we did (revoke, disable, monitoring)  
3. What we know about customer impact (or “investigation ongoing”)  
4. What customers should do (if anything)  
5. Next update time  

---

## Internal all-hands (T+same day)

- Facts only · Contract clauses that failed · Freeze status on new agents  
- Gratitude for reporters · No rumor channel  
- Stewards: do not “test prod” during investigation  

---

## Regulator / insurer (if triggered)

Attach: timeline · identities revoked · data classes in scope · ledger excerpts counsel-approved · residual risk · corrective controls with dates  

---

## Post-incident external note (optional, after stabilize)

We treat AI agents as privileged systems. This incident reinforced our Governed Velocity controls: [specific clause strengthened]. We do not claim models cannot be manipulated; we claim privilege can be bounded and evidenced.

---

## Forbidden phrases

- Jailbreak-proof going forward  
- Human error only  
- No customers affected (unless verified)  
- Unrelated to our AI governance program  

## Approval chain

IR lead (facts) → CISO (accuracy) → Legal → Comms → CEO for S1 external
