# Leader Readiness Score — Current

**Rubric:** `blog/governed-velocity-leader-readiness.md` (max 40, gate ≥ 32, no zeros in Authority/Clocks)  
**Date:** 2026-08-06 (reconfirmed 2026-08-08 sustain)  
**Scorer:** Program Owner + SecArch (consolidated) — attestation `PROG-LRS-2026-08-06`  
**Machine attestation:** `leader-readiness-attestation.json` (`last_sustain_on=2026-08-08`)

### A. Authority (max 8) — **8**
| Item | Score | Note |
|------|------:|------|
| Board resolution | 2 | Adopted `2026-08-06-AI-01` — Technology Committee / Program Owner |
| Policy AI-CTRL-001 signed | 2 | `blog/policy/agency-contract-policy.md` effective 2026-08-06 |
| Risk appetite adopted | 2 | AI-RISK-001 adopted 2026-08-06 |
| OACP freeze authority | 2 | Exercised `POST /platform/control-plane/freeze` enable+clear 2026-08-06 |

### B. Clocks (max 8) — **8**
| Item | Score | Note |
|------|------:|------|
| Revoke median ≤ 15m | 2 | Clock-01 dated drill 2026-08-06; sustain re-run 2026-08-08 |
| Evidence export RTO ≤ 60m | 2 | Clock-02 CI + program runner 2026-08-06; sustain 2026-08-08 |
| On-plane % auto-reported | 2 | Analytics summary + Cost UI + SDK types |
| Unmanaged prod keys = 0 | 2 | `prod_unmanaged_zero_ok` on NHI hygiene |

### C. Gates (max 8) — **8**
| Item | Score | Note |
|------|------:|------|
| DoD blocks launches | 2 | Release gate + CPLI evaluate gate; live prod executor default-off |
| Exceptions ≤ 90d | 2 | Break-glass ≤90d cap + auto-disable expire-tick/health |
| Dual-approval enforced | 2 | API-enforced widely |
| MCP/tool default-deny prod | 2 | Empty allowlist denied outside local |

### D. Assurance (max 8) — **8**
| Item | Score | Note |
|------|------:|------|
| RT-01/02 last 90d | 2 | Dated drill-runs 2026-08-06; sustain 2026-08-08 |
| Tabletop last 180d | 2 | Tabletop drill-run 2026-08-06; sustain 2026-08-08 |
| Vendor fails block | 2 | Fail-closed + notification retry |
| QBR numbers-first | 2 | `qbr-snapshot` + `evidence/qbr-snapshot-2026-08-08.json` + transparency note |

### E. Honesty (max 8) — **8**
| Item | Score | Note |
|------|------:|------|
| Maturity all-criteria | 2 | Scorecard updated post-L6; all-criteria applied |
| Residual risk plain language | 2 | Register next-actions updated |
| Anti-pattern theater kill | 2 | Single-owner consolidation disclosed; MCP honesty retained |
| External ≤ internal | 2 | Claims gated by LRS attestation in QBR honesty block |

---

**Draft total: 40 / 40 · Band: Governed velocity**  
**Gate (≥32):** **MET** — no Authority/Clocks zeros; formal sign-off complete.

**Engineering companion (CPLI):** **20 / 20** (`leader_ready_engineering`) after Raise Leadership Score arms fail-closed=drift + isolation contract and reconciles. Live `APP_PLANE=control|data` still required for runtime process isolation. See `scripts/run_program_leader_enhance.py` and Overview **Raise Leadership Score**.

### Success checklist

- [x] Board resolution adopted (ID + date) — Authority board = 2
- [x] AI-CTRL-001 signed; risk appetite adopted; OACP freeze exercised
- [x] Clock-01 dated drill ≤ 15m median; registered in drill-runs
- [x] RT-01 + RT-02 in last 90d; tabletop in last 180d
- [x] QBR ran on `qbr-snapshot` with minutes
- [x] formal-signoff-packet all five roles Approve; AR-001/002 decided
- [x] LRS recomputed ≥ 32; Authority/Clocks zeros = 0
- [x] leadership-loop-state L6 = done; marketing claim allowed only then
