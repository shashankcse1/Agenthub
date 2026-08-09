# War Room / Bridge Protocol — Agent Incident

**Use with:** Incident playbook (technical) · Crisis comms (external)  
**Trigger:** S1 or complex S2 spanning ≥2 agents / unknown egress  
**Rule:** One bridge. One commander. Ledger over chat.

---

## Stand-up (first 5 minutes)

**Commander:** IR lead (or CISO delegate)  
**Required seats:** OACP, Platform, Steward(s) of involved agents, Comms (listen-only until asked), optional Legal  

Commander script:

1. “This is an agent-privilege incident. Chat is secondary.”  
2. “Revoke targets: [identities]. Owner confirm when ineffective.”  
3. “Egress: blocklist / confirm deny. Network is ground truth.”  
4. “No prod ‘testing’ during investigation.”  
5. “Next update on this bridge in 15 minutes.”  

## Bridge hygiene

| Do | Do not |
|----|--------|
| Speak in identity / tool / destination | Debate model vendors |
| Paste ledger `request_id`s | Paste raw secrets/prompts |
| Track revoke clock aloud | Claim “fully contained” early |
| Assign single action owners | Parallel undocumented changes |

## Status board (shared doc)

| Field | Value |
|-------|-------|
| Severity | S1 / S2 |
| t0 signal | |
| Identities revoked | |
| t_revoke_command | |
| t_effective | |
| Destinations blocked | |
| Customer impact known? | Y/N/Unknown |
| Freeze net-new agents? | Y/N |
| Next update at | |

## Cadence

- S1: update every 15m until contained  
- S2: every 30–60m  
- Exec-only channel: facts from status board only (no speculation)

## Stand-down criteria

- [ ] No further tool success for revoked identities  
- [ ] Egress quiet / explained  
- [ ] Sibling-key blast radius checked  
- [ ] Freeze decision recorded  
- [ ] AAR scheduled ≤ 72h  
- [ ] Comms holding statement withdrawn or upgraded with verified facts  

## Handoff

Commander names overnight owner. War room channel stays read-only archive after stand-down.
