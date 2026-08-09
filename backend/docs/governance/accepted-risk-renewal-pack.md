# Accepted Risk Renewal Pack (AR-001 / AR-002)

**Status:** **Closed — both Retired** (CISO Delegate / Program Owner, 2026-08-06)  
**Prepared:** 2026-08-02 (Leadership Loop L2)  
**Decided:** 2026-08-06 under attestation `PROG-LRS-2026-08-06`  
**Engineering recommendation:** **Retire both** (fail-closed env constraints + `/health` posture make time-bound acceptance unnecessary)

---

## AR-001 — MFA optional flag (ties to RSK-002)

| Field | Value |
|-------|--------|
| Risk | MFA optional mode may reduce assurance for privileged workflows if misused |
| Current code posture | Effective only in `local`/`dev`/`test`; rejected at startup outside those envs (`security.py`); exposed on `GET /health` → `mfa_optional` |
| Compensating controls | CC-002, CC-009, CC-014; health posture; `test_validate_runtime_auth_guardrails_rejects_mfa_optional_in_non_dev`; `test_health_includes_mfa_optional_and_token_exposure_posture` |
| Decision | **Retire** — keep fail-closed outside allowed envs |

**Sign-off line:**  
CISO Delegate: Program Owner  Date: 2026-08-06  Decision: **Retire**

---

## AR-002 — Token exposure flag (workload identity)

| Field | Value |
|-------|--------|
| Risk | Token exposure flag in codepath could leak material if misconfigured |
| Current code posture | Disabled by default; force-disabled outside local/test; dual-approval on related runtime-config; exposed on `GET /health` → `token_exposure` |
| Compensating controls | CC-006 audit; runtime-config sensitive key gates; health posture |
| Decision | **Retire** — keep fail-closed |

**Sign-off line:**  
Cloud Security Lead: Program Owner  CISO Delegate: Program Owner  Date: 2026-08-06  Decision: **Retire**

---

## After signature

1. Update residual register AR-001/AR-002 status from Expired → **Retired**. — done  
2. Mark **RSK-002 Mitigated**. — done  
3. Record decision in `formal-signoff-packet.md`. — done  
4. Attach evidence under `docs/governance/evidence/` when drills run.  
