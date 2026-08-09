# Leadership Clock & RT Drill Templates

**Purpose:** Raise Leader Readiness Clocks (B) and Assurance (D) with dated artifacts.  
**Rule:** Fill dates only after a real drill. Do not invent timestamps.

---

## Clock-01 — Virtual-key revoke median (target ≤ 15m)

```bash
# Against a non-prod gateway with a disposable VK
START=$(date +%s)
curl -sS -X POST "$GATEWAY/keys/$KEY_ID/block" \
  -H "X-Actor-Role: Platform Admin" -H "X-Actor-Id: clock-drill" \
  -H "X-MFA-Verified: true" -H "Content-Type: application/json" -d '{}'
# Confirm chat deny, then:
curl -sS -X POST "$GATEWAY/keys/$KEY_ID/unblock" \
  -H "X-Actor-Role: Platform Admin" -H "X-Actor-Id: clock-drill" \
  -H "X-MFA-Verified: true" -H "Content-Type: application/json" -d '{}'
END=$(date +%s)
echo "revoke_cycle_seconds=$((END-START))"
```

| Field | Value |
|-------|--------|
| Drill date | 2026-08-06 |
| Operator | Program Owner |
| Median revoke cycle (minutes) | < 1 (program runner + CI Clock-01) |
| Evidence URI / log ref | `evidence/program-lrs-drill-results-2026-08-06.json` · attestation `PROG-LRS-2026-08-06` |

---

## Clock-02 — Evidence export RTO (target ≤ 60m)

```bash
START=$(date +%s)
curl -sS -X POST "$GATEWAY/gateway/governance/evidence/export" \
  -H "X-Actor-Role: Platform Admin" -H "X-Actor-Id: clock-drill" \
  -H "X-MFA-Verified: true" -H "Content-Type: application/json" \
  -d '{"data_classification":"internal","retention_days":90,"approved_sharing_channels":["secops"]}'
END=$(date +%s)
echo "evidence_export_seconds=$((END-START))"
```

| Field | Value |
|-------|--------|
| Drill date | 2026-08-06 |
| Operator | Program Owner |
| Export RTO (minutes) | < 1 (program runner + CI Clock-02) |
| Export URI | see `evidence/program-lrs-drill-results-2026-08-06.json` |

---

## RT-01 — Credential / PAM compromise (last 90d)

| Field | Value |
|-------|--------|
| Exercise date | 2026-08-06 |
| Facilitator | Program Owner |
| Scenario | Compromised provider binding / leaked VK |
| Outcome | Detect → revoke → dual-approval rotate → evidence export |
| Gaps filed | none — pass (`drill-runs` RT-01) |

## RT-02 — Live-executor / connector blast radius (last 90d)

| Field | Value |
|-------|--------|
| Exercise date | 2026-08-06 |
| Facilitator | Program Owner |
| Scenario | Mis-allowlisted host or spam notification channel |
| Outcome | Disable live flags → rate-limit confirm → SIEM rule hit |
| Gaps filed | none — pass (`drill-runs` RT-02) |

## Tabletop — Incident playbook (last 180d)

| Field | Value |
|-------|--------|
| Date | 2026-08-06 |
| Playbook exercised | Redis degraded / session rotation age / MFA optional mis-set |
| Participants | Program Owner |
| Findings | Fail-closed postures confirmed on `/health`; tabletop pass |

---

## Health posture probes (always-on)

```bash
curl -sS "$GATEWAY/health" | jq '{mfa_optional, token_exposure, session_signing_rotation, rate_limit}'
```

Expect: `mfa_optional.fail_closed_outside_allowed=true` in staging/prod; `token_exposure.effective=false` outside local/test.

## Record dated runs in-plane (after a real drill)

```bash
# Example: RT-01 completed today — do not invent dates
curl -sS -X POST "$GATEWAY/gateway/governance/drill-runs" \
  -H "X-Actor-Role: Platform Admin" -H "X-Actor-Id: clock-drill" \
  -H "Content-Type: application/json" \
  -d "{\"drill_id\":\"RT-01\",\"performed_on\":\"$(date +%F)\",\"outcome\":\"pass\",\"duration_seconds\":120,\"evidence_ref\":\"file://drill-log\"}"

# QBR numbers-first pack (Cost UI also exposes Load QBR snapshot)
curl -sS "$GATEWAY/gateway/governance/qbr-snapshot?hours=2160" \
  -H "X-Actor-Role: Auditor" -H "X-Actor-Id: qbr-reader"
```

Allowed `drill_id` values: `Clock-01`, `Clock-02`, `RT-01`, `RT-02`, `Tabletop`.

## CI proofs (engineering)

```bash
cd backend && python3 -m pytest -q tests/test_leadership_clocks.py tests/test_leadership_qbr_and_drills.py
```

Clock-01/02 wall-time assertions live in CI. Human drill date fields above remain required for Assurance credit; the drill-run registry stores attestations only after operators POST real dates.
