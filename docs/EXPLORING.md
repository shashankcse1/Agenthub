# Exploring AgentHub

A 30-minute tour for new operators and contributors. Start the stack first:

```bash
./scripts/startlocal_detached.sh
# Login: http://127.0.0.1:4173/login.html
# API Base must be http://127.0.0.1:4173 (same origin)
```

## Minute 0–5 — Sign in and Overview

1. Sign in as Day-0 `admin` ([Day-0 hardening](../backend/docs/security/day0-password-and-secrets-hardening.md)).
2. Confirm sidebar **Plane online** (or healthy) after Overview loads.
3. Note **Readiness** chips and **Open Flow Studio** / **Gateway** / **Playground** shortcuts.

If cards show `--` or “session idle”, sign out and sign in again with same-origin API Base.

## Minute 5–12 — Flow Studio

1. Open **Flow Studio** from Overview or Operations nav.
2. Create or open a simple **Start → Ask AI → End** flow (or a template).
3. **Check** / validate, then **Run** in `dev` if credentials allow.
4. Open **History** / run detail to see ledgered steps.

Goal: see design → govern → run as one plane, not three tools.

## Minute 12–20 — Routing & Gateway

1. Open **Routing & Gateway**.
2. Skim **Routes** / priority and **Key Lifecycle**.
3. Open **Policies → Runtime Risk Policy** (default observe/disabled — safe to read).
4. Open the Cursor / OpenAI-compatible ops panels if present — note model pickers load from Providers.

Do not enable enforce-mode risk or prod dual-approval actions on a shared demo without intent.

## Minute 20–25 — Providers & Playground

1. **Providers** → Models / Secret Providers (read-only is fine).
2. **Playground** → send a small prompt if a live-ready model/binding exists; otherwise note the credential banner.

## Minute 25–30 — Evidence surfaces

1. **Audit** — recent events.
2. **Observability** — summary / traces if data exists.
3. **Cost** — spend chips (may be empty on a fresh DB).

## Where to go deeper

| Interest | Start here |
| -------- | ---------- |
| Architecture | [architecture-document.md](../architecture-document.md) §0 |
| API ↔ UI coverage | [api-inventory-and-ui-map.md](../backend/docs/governance/api-inventory-and-ui-map.md) |
| What “done” means | [product-completion-status.md](../backend/docs/governance/product-completion-status.md) |
| Contribute | [CONTRIBUTING.md](../CONTRIBUTING.md) |
| Small tasks | [GOOD_FIRST_ISSUES.md](./GOOD_FIRST_ISSUES.md) |
| Ops ports / prod | [operations-quickstart.md](../operations-quickstart.md) |

## Feedback

File a **Bug report** or **Feature request** with what confused you in the first 30 minutes — that feedback is high value for maturity.
