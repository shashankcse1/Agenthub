# Governed Velocity — Half-Day Workshop

**Title:** Put Your Agent Under Contract  
**Length:** 3.5 hours  
**Audience:** App owners, platform, security, risk (8–20 people)  
**Outcome:** Each team leaves with a filled Agency Contract and a 30-day gap list

---

## Prep (facilitator)

- Print or share: Agency Contract clauses, CISO + CTO one-pagers  
- Pre-work (15 min): each team lists agents, tools/MCP, data classes, keys  
- Room rule: doctrine language only for first 90 minutes — no vendor debates  

---

## Agenda

### Block 1 — Era shift (25 min)

| Min | Activity |
|-----|----------|
| 0–5 | Cold open: privilege multiplier (use LinkedIn cut) |
| 5–15 | Filter Era vs Control Plane Era (two-column whiteboard) |
| 15–25 | Discussion: where are we still Filter Era today? |

**Capture:** sticky list of Filter Era habits in this org.

---

### Block 2 — Doctrine drill (35 min)

Walk six clauses. For each: *What would fail closed look like here?*

Facilitator prompts:

- Identity: Who is the agent as a principal?  
- Mandate: What content can rewrite goals today?  
- Toolbox: What is connected that is not approved?  
- Escalation: What irreversible acts are auto-allowed?  
- Fence: Where can this agent egress?  
- Ledger: Could we export evidence by Friday?

**Capture:** red / amber / green per clause per team (gut score).

---

### Block 3 — Contract workshop (60 min)

Teams fill the Contract Canvas:

| Field | Prompt |
|-------|--------|
| Agent / system name | What acts? |
| Business purpose | One sentence |
| Identity | Principal, key owner, TTL |
| Data classes in / out | PII, secrets, customer, public |
| Tools / MCP | List + justify each |
| Irreversible acts | List + approval path |
| Egress domains | Allowlist draft |
| Evidence today | What exists vs missing |
| Blast radius if hijacked | Honest paragraph |

Facilitator roams; kills scope creep (“we’ll secure it later”).

---

### Block 4 — Break (15 min)

---

### Block 5 — Red-team tabletop (40 min)

Two scenarios (pick both if time):

1. **Concealment** — malicious doc in RAG; agent emails data; user sees “summary complete.”  
2. **Silent egress** — malicious URL preview induces outbound leak.

For each: Which contract clause fails first? What control would have bounded it?

---

### Block 6 — 30-day commitments (30 min)

Each team states:

1. One path that moves on-plane  
2. One tool to disconnect or allowlist  
3. One dual-approval gap to close  
4. One metric they will report  

**Close line:** If it can act, it needs a contract. If it has a contract, it needs a ledger.

---

## Facilitation don’ts

- Don’t turn Block 2 into a model bake-off  
- Don’t accept “the vendor handles that” as a clause answer  
- Don’t leave without named owners and dates  

---

## Exit artifacts

1. Completed Contract Canvas per agent (photo or doc)  
2. Consolidated gap backlog → platform + security  
3. Attendance + commitment log for day-30 launch readout  
