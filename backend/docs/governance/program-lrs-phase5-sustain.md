# Program LRS — Phase 5 Sustain Cadence

**Purpose:** Keep LRS from aging out (RT ≤ 90d, tabletop ≤ 180d).  
**Runner:** `backend/scripts/run_program_lrs_phase2_drills.py`  
**Last sustain run:** 2026-08-08 (`last_sustain_on` on `PROG-LRS-2026-08-06`)  
**Next due:** 2026-09-06 · 2026-10-06 · 2026-11-06  
**Transparency note:** `evidence/qbr-transparency-note-2026-08-08.md`

## Explicitly blocked / out of scope

| Item | Status |
|------|--------|
| Distinct L6 role holders | Blocked — human; template `role-holder-roster.md` |
| Live npm/PyPI publish | Blocked — needs registry secrets; workflow `sdk-publish.yml` ready |
| Enterprise SaaS OAuth crawler / full IARA | Out of scope by design |

## Quarterly checklist

1. Re-run Clock-01 / Clock-02 / RT-01 / RT-02 / Tabletop via the program runner.
2. Confirm `GET /gateway/governance/qbr-snapshot` shows drills fresh within window.
3. Confirm LRS attestation still `formal_signoff_complete` and score ≥ 32.
4. If distinct Sec*/CISO holders are named, update `formal-signoff-packet.md` lines (do not invent).
5. Refuse competitor “#1” claims unless Honesty still allows (external ≤ internal).

## Command

```bash
set -a && . ./.runtime/local-dev.env && set +a
export PLANE_DRIFT_WATCHER_ENABLED=false
export PYTHONPATH="$PWD/backend${PYTHONPATH:+:$PYTHONPATH}"
cd backend && python3 scripts/run_program_lrs_phase2_drills.py
# Optional replay: PROGRAM_LRS_DRILL_DATE=YYYY-MM-DD
```
