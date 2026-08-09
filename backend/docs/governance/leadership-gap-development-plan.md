# Leadership Gap Development Plan

**Goal:** Move from checklist parity (Portkey / Helicone / n8n) to market-ready leadership via trust, live depth, and ops reliability — not more named endpoints.

**Date:** 2026-08-02  
**Status:** Waves 1–3 in-repo complete (LRS 40/40; sdk-publish workflow ready); live registry publish + distinct role holders remain ops/org

---

## Sequencing

| Wave | Theme | Outcome | Prod risk |
|------|--------|---------|-----------|
| **1** | Ops reliability + trust telemetry | SIEM on secret mutations, Redis degraded alerts, session-key rotation age on `/health`, VK schedule tick | Low — detective only |
| **1** | SDK publishability | `pip install` / npm-ready packaging without path hacks | None |
| **1** | Connector depth proof | Live `github_api` (+ Slack/Stripe follow) with mocked httpx + richer op presets | Low — allowlist unchanged |
| **2** | Live depth (non-prod) | Documented opt-in; Studio status chips; host-allowlist helpers for deep connectors | Medium — still flag-gated |
| **2** | Data plane | Opt-in file content store (dual-approval in prod) or explicit 422 on binary fields | Medium |
| **3** | Trust closure (process) | Renew AR-001/AR-002; close RSK-011–015 with evidence; CISO sign-off | Process |
| **3** | GTM | Fill maturity scorecard; Leader Readiness Score ≥ 32 | Process |

**Explicit non-goals this wave:** flipping `live_executor_prod_enabled` to true; unrestricted Code node; claiming “leader” in marketing.

---

## Wave 1 checklist

- [x] Plan document (this file)
- [x] GAP-USP-R05: SIEM default rule + audit dispatch for `secret_provider.value.*`
- [x] RSK-005: Redis rate-limit degraded → security alert (rate-limited)
- [x] RSK-004: session signing key rotation age re-check on `/health`
- [x] VK rotation: due-schedule `tick` endpoint (reuse execute-now)
- [x] SDK: Python `pyproject.toml` + JS `publishConfig` / package metadata
- [x] Connector: live `github_api` path test + operation presets (GitHub/Slack/Stripe)
- [x] Files API: reject binary payload fields (`content` / `content_b64` / `file`)
- [x] Residual register + CC notes for closed engineering slices
- [x] Tests green (Wave 1 unit suite)

---

## Success criteria (Wave 1)

1. Secret value mutation audits can fire SIEM rules out of the box. ✅
2. Persistent Redis rate-limit degradation emits a security webhook alert (throttled). ✅
3. Stale session signing keys are visible on `/health` (and alert when webhook configured). ✅
4. Due VK rotation schedules can be advanced by a single tick call (cron-ready). ✅
5. SDK installs via standard package managers in local/dev. ✅
6. At least one connector has a regression test on the live httpx path (not stub-only). ✅

## Wave 2 checklist

- [x] `POST /orchestration/live-readiness/bootstrap` + `GET /orchestration/live-readiness`
- [x] Host merge helpers + leadership connector host coverage in policy snapshot
- [x] Runbook: `live-readiness-runbook.md`
- [x] Opt-in file content store (`gateway.files.content_store_enabled`, encrypted column, prod dual-approval)
- [x] Slack/Stripe live httpx regressions + richer operation presets
- [x] SDK publish dry-run CI + Helicone-class fetch/request instrumenters

## Wave 3 (process / GTM)

1. ~~Renew AR-001/AR-002; close RSK-011–015 with evidence~~ — AR Retired; RSK Mitigated (`PROG-LRS-2026-08-06`)
2. ~~CISO / role sign-offs~~ — formal-signoff-packet signed (Program Owner consolidated)
3. ~~Fill maturity scorecard / Leader Readiness Score~~ — LRS **40/40** Governed velocity
4. ~~Real npm/PyPI publish workflow~~ — `.github/workflows/sdk-publish.yml` ready; live publish blocked only on registry secrets

## Wave 4 checklist (engineering deepen — 2026-08-02)

- [x] On-plane % auto-report (`on_plane_coverage` on analytics summary + Cost UI)
- [x] MCP empty-allowlist default-deny outside local/dev/test
- [x] SIEM rules: unlock*, least_privilege.apply*, insecure_configuration*
- [x] Unlock abuse detector (`maybe_flag_unlock_abuse`)
- [x] CI clock proofs (`test_leadership_clocks.py`)
- [x] Notification retry/receipt adapters (residual #9)
- [x] NHI `prod_unmanaged_zero_ok` continuous signal
- [x] Frontend leadership posture chips from `/health`
- [x] L9: break-glass auto-disable ≤90d + `/health.transport` + evidence owner + live-readiness chip
- [x] L10: QBR numbers-first snapshot + drill-run registry + board resolution template + Cost UI/SDK
- [x] Human L6 signatures / dated RT drills (POST `/gateway/governance/drill-runs` after real runs) — 2026-08-06
