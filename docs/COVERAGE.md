# Test coverage strategy

## Honest scope

Requiring **99% line coverage on the entire `backend/app` tree in one change** is not a realistic single PR — the platform has 100+ test modules and a large service surface. AgentHub instead enforces:

| Gate | Target | Command |
| ---- | ------ | ------- |
| **Critical path (console auth spine)** | **≥ 99%** (currently **100%**) | `make coverage-critical` / `bash scripts/check_critical_coverage.sh` |
| Control-ID route mapping | 100% of API routes mapped | `python scripts/check_control_coverage.py` |
| Functional console E2E | Pass | `make test-functional-e2e` |
| Runtime smoke | Pass | `make smokee2e` + `frontend/scripts/functional_console_e2e_smoke.sh` |

### Critical-path modules (99% gate)

- `app/services/session_cookies.py`
- `app/services/csrf_protection.py`
- `app/services/runtime_env.py`

These modules power local same-origin login → Overview → logout. Expanding the gate means adding modules to `.coveragerc.critical` only after their dedicated tests reach ≥99%.

## Functional end-to-end

`tests/test_functional_e2e_console.py` covers:

1. `/health`
2. `POST /auth/login` (httpOnly session + CSRF cookies)
3. Cookie-authenticated Overview reads (`/orchestration/summary`, `/cost/live`, `/audit/events`, `/governance/ui-coverage`, `/platform/control-plane`, …)
4. `GET /auth/csrf` + cookie mutation (`POST /platform/feedback`)
5. `POST /auth/logout` then auth required again
6. Idle session → `AUTHN_SESSION_IDLE_TIMEOUT`

## Expanding toward monorepo 99%

Track module packs as good-first / help-wanted work:

1. Pick a service under `app/services/`
2. Add unit + abuse tests until `pytest --cov=that.module --cov-fail-under=99` passes
3. Append the module to `.coveragerc.critical` (or a new pack file)
4. Keep CI green

Do **not** lower `fail_under` to greenwash coverage.

## Local commands

```bash
cd backend
make coverage-critical
make test-functional-e2e
# With UI up:
REQUIRE_UI=1 bash ../frontend/scripts/functional_console_e2e_smoke.sh
```
