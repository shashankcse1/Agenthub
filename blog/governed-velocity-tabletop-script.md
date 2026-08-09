# Timed Tabletop — Concealed Exfil (90 minutes)

**Scenario family:** RT-01 + incident golden hour  
**Players:** IR lead, OACP, steward (app owner), Comms, optional Legal  
**Facilitator:** AI Security Engineer  
**Success for facilitators:** Surface clause failures and clock times — not blame

---

## Prep (T-0)

- Pick a real-ish agent (or use worked example `support-resolver-prod` **with send tool hypothetically re-enabled** for stress)  
- Print desk card + incident playbook golden hour  
- Timer visible  
- Rule: chat transcripts are decoys  

---

## Inject timeline

### T+00:00 — Inject 1 (Signal)

SOC: “Customer reports odd draft content; also our egress proxy shows POST to unknown host from agent identity subnet.”

**Ask room:** What do you pull first — chat or ledger/egress?

**Facilitator note:** Award points for ledger/egress first.

### T+00:10 — Inject 2 (Concealment)

User-facing session log looks normal: “Here’s a summary of your ticket.”  
Tool log (reveal only if asked): `email.send` or `web.fetch` attempted.

**Ask:** Severity? S1 or S2? Who commands?

### T+00:20 — Inject 3 (Privilege graph)

Reveal toolbox includes an undocumented MCP server added last week “for debugging.”

**Ask:** Which Contract clauses failed? Who approved?

### T+00:35 — Inject 4 (Clock pressure)

Exec Slack: “Is this the model vendor’s fault? Can we reassure customers we are fully contained?”

**Comms must draft holding statement without “fully contained” unless revoke verified.

### T+00:50 — Inject 5 (Secondary agent)

Sibling agent shares a provider key (legacy). Same destination host sees traffic.

**Ask:** Blast radius expansion steps. Freeze net-new agents?

### T+01:05 — Inject 6 — Stabilize or fail

Facilitator reveals whether revoke actually disabled traffic (coin flip / pre-decide).  
If not: fail-open path existed — discuss P2 architecture principle.

### T+01:20 — Hotwash (10m)

Capture:

| Field | Result |
|-------|--------|
| Time to revoke command | |
| Time to ineffective creds | |
| Clauses failed | |
| Theater observed | |
| Corrective actions / owners / dates | |

Scorecard + findings backlog updated same day.

---

## Debrief questions (mandatory)

1. What would a Filter Era team have done wrong in the first 10 minutes?  
2. Which anti-pattern almost appeared in our language?  
3. What single toolbox removal would have bounded this?  

**Close:** Outcome integrity or it didn’t happen.
