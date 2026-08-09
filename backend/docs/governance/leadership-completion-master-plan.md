# Leadership Completion Master Plan

**Purpose:** Close every remaining gap so this product can honestly claim market leadership vs Portkey / Helicone / n8n.  
**Mode:** Implemented in **loops** (work packages). Each loop is atomic: code/docs + tests + register update + scoreboard tick.  
**State file:** `backend/docs/governance/leadership-loop-state.json`  
**Do not claim “leader” in marketing until Loop L6 exit criteria pass.**  
**L6 status (2026-08-06):** **done** — attestation `PROG-LRS-2026-08-06`; LRS 40/40. External claims still must not exceed the scorecard (Honesty).

---

## Exit criteria (Definition of Done)

| # | Criterion | Owner |
|---|-----------|--------|
| E1 | RSK-011–015 status = Mitigated with evidence links | Eng + SecArch |
| E2 | AR-001 / AR-002 renewed or retired with dated owners | CISO Delegate |
| E3 | RSK-002 Mitigated after AR-001 decision | IAM |
| E4 | RSK-020 / CC-033 residual text accurate; list/due API tests green | Eng |
| E5 | Maturity scorecard filled for current release | SecArch |
| E6 | Leader Readiness Score computed ≥ 32 (rubric in `blog/governed-velocity-leader-readiness.md`) | Product + SecArch |
| E7 | Formal sign-off block: Security Architect, SecOps, SecEng, Vuln Mgmt, CISO | Process |
| E8 | SDK publish dry-run green in CI; publish runbook ready (tokens optional) | Eng |
| E9 | Prompt promote UI supports co-approver headers for prod | Eng |
| E10 | Live-readiness + connector depth + file content store (Waves 1–2) remain green | Eng |

---

## Loop cadence

```
while incomplete:
  1. Read leadership-loop-state.json
  2. Pick next WP with status=pending (priority order)
  3. Implement WP (code/docs/tests)
  4. Run WP verification command
  5. Update residual register / scorecard / state file
  6. Mark WP done; emit loop tick summary
  7. Stop only when all WPs done OR blocked on human sign-off (E2/E7)
```

**Agent loop interval:** every **12 minutes** until WPs L1–L5 complete; then pause for human sign-off (L6).

---

## Work packages (detailed)

### L1 — Residual closure evidence (RSK-011–015) + prompt UX
**Priority:** P0  
**Can auto-complete:** Yes (evidence + optional UI)

| Task | Detail | Verify |
|------|--------|--------|
| L1.1 | Flip RSK-011→015 to Mitigated citing CC-020–025 + test names | residual register |
| L1.2 | Add prompt promote co-approver fields + `X-Approver-*` in `frontend/app.js` / playground form | UI + unit/smoke |
| L1.3 | Evidence note file listing pytest node ids for each CC | `leadership-evidence-pack.md` |
| L1.4 | Update next-actions that still say “Open” for these risks | residual register |

### L2 — Accepted-risk renewals + maturity scorecard
**Priority:** P0  
**Can auto-complete:** Docs/templates yes; human signature no

| Task | Detail | Verify |
|------|--------|--------|
| L2.1 | Draft AR-001 / AR-002 renewal packages (scope, compensating controls, review cadence) | `accepted-risk-renewal-pack.md` |
| L2.2 | Fill `maturity-scorecard.md` release sheet with honest 0–4 scores + notes | scorecard |
| L2.3 | Compute Leader Readiness Score draft from blog rubric | `leader-readiness-score-current.md` |
| L2.4 | After human renews AR-001: mark RSK-002 Mitigated | blocked on human |

### L3 — IGA Partial → Mitigated (engineering)
**Priority:** P1

| Task | Detail | Verify |
|------|--------|--------|
| L3.1 | Fix CC-033 residual text (JIT/due UI shipped) | residual register |
| L3.2 | Add pytest for `GET /orchestration/jit-access-requests` + `GET /orchestration/access-certifications/due` | `test_orchestration_iga.py` |
| L3.3 | Mark RSK-020 Mitigated with accepted residual (time-bound JIT privilege) | residual register |

### L4 — SDK publish + instrumentation depth
**Priority:** P1

| Task | Detail | Verify |
|------|--------|--------|
| L4.1 | Ensure `sdk-publish-dry-run.yml` is complete | workflow |
| L4.2 | SDK publish runbook (npm/PyPI tokens, versioning) | `sdk/PUBLISH.md` |
| L4.3 | Wire instrumenter into AgentHubGateway optional ctor path | sdk tests |

### L5 — Connector / data-plane leadership depth
**Priority:** P1

| Task | Detail | Verify |
|------|--------|--------|
| L5.1 | Expand operation presets (GitHub/Slack/Stripe) + live httpx tests | competitive tests |
| L5.2 | Document prod live go-live checklist (still flag-gated) | runbook |
| L5.3 | RAG depth note: MCP-only accepted residual or adapter spike | docs |

### L6 — Human sign-off gate (blocking)
**Priority:** P0 process  
**Agent cannot complete alone**  
**Packet ready:** `formal-signoff-packet.md` · drills: `leadership-clock-and-rt-drills.md`

| Task | Detail |
|------|--------|
| L6.1 | Security Architect sign-off |
| L6.2 | SecOps Lead sign-off |
| L6.3 | Security Engineering Lead sign-off |
| L6.4 | Vulnerability Management Lead sign-off |
| L6.5 | CISO / Delegate sign-off (incl. RSK-016 PAM + AR-001/002 Retire/Renew) |
| L6.6 | Marketing may claim leader only after E1–E10 |
| L6_eng | `/health` MFA/token posture + drill templates (engineering; done) |

---

## Loop state machine

```json
{
  "active_loop": "L1",
  "loops": {
    "L1": "pending|in_progress|done|blocked",
    "L2": "...",
    "L3": "...",
    "L4": "...",
    "L5": "...",
    "L6": "blocked_human"
  }
}
```

---

## Verification matrix (run each loop)

```bash
# L1 / L3 engineering
python3 -m pytest -q \
  backend/tests/test_phase0_phase1.py -k "prompt_registry_promote or quality_triage or supported_model or external_callback or realtime" \
  backend/tests/test_orchestration_iga.py \
  backend/tests/test_competitive_hardening.py -k "live_ or files_ or readiness"

# L4
node --check sdk/js/src/index.js
# CI: sdk-publish-dry-run.yml
```

---

## Explicit non-goals (still)

- Enabling `orchestration.live_executor_prod_enabled` by default  
- Unrestricted Code node / JWT trust  
- Forging CISO signatures  
- Claiming market leadership before L6  
- **Hard dependency on Portkey / Helicone / n8n / LiteLLM / LangSmith** (or any competitor SaaS) for core operation — parity targets are benchmarks only (`external-product-independence.md`)
