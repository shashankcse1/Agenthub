# Governed Velocity — Live Status Tracker

**Org:** GuardBridge repository program  
**Platform:** GuardBridge / AI control plane (this repo)  
**OACP Head:** Program Owner (interim consolidated)  
**Updated:** 2026-08-06  
**Program state:** **LRS gate met** — Governed velocity (40/40); sustain quarterly drills  

---

## Readiness

| Item | Value |
|------|-------|
| Leader Readiness Score | **40 / 40** |
| Band | **Governed velocity** |
| Maturity (all-criteria) | **Applied** (scorecard normalized 81) |
| External claims allowed? | **Y** (Under contract+; still external ≤ internal — no competitor #1 without separate approval) |
| Detail | `backend/docs/governance/leader-readiness-score-current.md` · `PROG-LRS-2026-08-06` |

## Clocks (last drill)

| Metric | Result | Date | Target |
|--------|--------|------|--------|
| Time-to-revoke (median) | pass (&lt; 1m) | 2026-08-06 | ≤ 15m |
| Evidence export RTO | pass (&lt; 1m) | 2026-08-06 | ≤ 60m |

## Coverage

| Metric | This week | Target | Platform hint |
|--------|-----------|--------|----------------|
| On-plane tier-1 % | auto-reported | ≥ 90% | `/gateway/analytics/summary` |
| Unmanaged prod keys | `prod_unmanaged_zero_ok` | 0 | `/gateway/nhi/inventory` |
| Dual-approval coverage | API-enforced | 100% scoped | Prod mutations |
| Exceptions past expiry | auto-disable ≤90d | 0 | break-glass expire-tick |
| Open RT P1/P2 | RT-01/02 pass 2026-08-06 | ↓ | drill-runs |

## Freeze

OACP / control-plane freeze exercised 2026-08-06 (`POST /platform/control-plane/freeze` enable+clear).

## Policy

| Item | Status |
|------|--------|
| Board resolution | Adopted `2026-08-06-AI-01` |
| AI-CTRL-001 | Signed 2026-08-06 |
| AI-RISK-001 | Adopted 2026-08-06 |

## Sustain

| Cadence | Command |
|---------|---------|
| Quarterly LRS drills | `PYTHONPATH=. python3 scripts/run_program_lrs_phase2_drills.py` |
| CPLI eng enhance | `PYTHONPATH=. python3 scripts/run_program_leader_enhance.py` |

See also `program-lrs-phase5-sustain.md`.
