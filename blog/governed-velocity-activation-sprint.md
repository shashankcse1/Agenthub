# 7-Day Activation Sprint — Make It Real

**Purpose:** Move from folder → operating system in one week  
**Sponsor time:** CISO + CTO ~3 hours total  
**OACP / Sec / Platform:** full focus  
**Rule:** End of day 7 = OS go-live declaration **or** explicit blockers with owners  

This is the leadership enhancement. Not another white paper.

---

## Day 1 — Authority

| Action | Owner | Done |
|--------|-------|------|
| Walk Constitution + Leader’s Brief (30m) | CISO/CTO | [ ] _human_ |
| Schedule Risk Committee slot / interim exec adopt | CISO | [ ] _human_ |
| Name OACP Head (interim OK) | CTO | [ ] _human — reply to sprint_ |
| Baseline Leader Readiness Score (honest) | OACP | [x] **8/40 Theater** · `governed-velocity-readiness-baseline.md` |
| Create `STATUS.md` from template and fill Day-0 | OACP | [x] `STATUS.md` + `DECISIONS.md` GV-DEC-001/002 |

**Exit:** Named owner + readiness number written down.  
**Status 2026-08-02:** Readiness number done. **Blocked on human:** OACP name + adopt schedule.

## Day 2 — Inventory

| Action | Owner | Done |
|--------|-------|------|
| AI path inventory v0 (apps, scripts, browser, vendors) | OACP+Sec | [ ] |
| Provider key / NHI hunt — list unmanaged prod keys | Sec | [ ] |
| Top 10 agents by privilege (tools × data) | Platform | [ ] |
| Kickoff meeting (see kickoff agenda) | OACP | [ ] |

**Exit:** Ugly inventory exists. No green paint.

## Day 3 — Chokepoint

| Action | Owner | Done |
|--------|-------|------|
| Declare official on-plane path for new prod inference | Platform | [ ] |
| Ban new app-held prod keys (written) | CTO | [ ] |
| Emit infer allow/deny with `request_id` on at least one tier-1 path | Platform | [ ] |
| Draft freeze communication template | OACP | [ ] |

**Exit:** One real path mediated end-to-end.

## Day 4 — Clocks

| Action | Owner | Done |
|--------|-------|------|
| Revoke drill on a non-prod or low-risk prod identity | Sec+Platform | [ ] |
| Record median time-to-revoke in STATUS | OACP | [ ] |
| Evidence export drill (scoped 24h) | Compliance/Sec | [ ] |
| Record export RTO in STATUS | OACP | [ ] |

**Exit:** Two numbers exist. Theater ends.

## Day 5 — Gates

| Action | Owner | Done |
|--------|-------|------|
| Publish DoD + day-zero onboarding as required | OACP | [ ] |
| Stand up exception form + register (spreadsheet OK) | OACP | [ ] |
| Force one real gate moment (defer launch or time-boxed exception) | OACP+CTO | [ ] |
| MCP/tool default-deny decision for new agents | Platform | [ ] |

**Exit:** Gate has teeth.

## Day 6 — Rhythm & people

| Action | Owner | Done |
|--------|-------|------|
| Put weekly glance + coverage standup on calendar | OACP | [ ] |
| Schedule QBR + tabletop + Game Day (dates) | OACP | [ ] |
| Enroll steward cohort #1 (date + roster) | OACP | [ ] |
| Share truth-to-power + field manual with on-call | CISO | [ ] |

**Exit:** Calendar owns the program.

## Day 7 — Declare

| Action | Owner | Done |
|--------|-------|------|
| Complete OS go-live checklist (honest gaps listed) | CISO+CTO | [ ] |
| Send internal activation declaration | CISO+CTO | [ ] |
| Freeze external “leader” claims until readiness ≥ 32 | Comms | [ ] |
| Decision log: GV-DEC-001 program active | OACP | [ ] |
| Update STATUS.md → Active / Blocked | OACP | [ ] |

**Exit:** Program is Active — or Blocked with named fixes and dates (not “in progress forever”).

---

## Anti-sprint behaviors (disqualify the week)

- Rewriting the manifesto  
- Model bake-offs  
- Claiming L3 without binder evidence  
- Skipping revoke drill because “we know how”  
- Permanent exception for a strategic launch  

**Close:** Bounded privilege with a ledger — or it isn’t production.
