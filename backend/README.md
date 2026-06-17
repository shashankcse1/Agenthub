# Backend Development Bootstrap (Phase 0-2)

## Agent-Governed Delivery

Workspace-wide operations quickstart:

- ../operations-quickstart.md

This backend follows an agent-first governance model.

1. Delivery contract: AGENTS.md
2. Per-change checklist: docs/governance/agent-delivery-checklist.md
3. Risk register: docs/security/residual-and-accepted-risk-register.md
4. Release gates: docs/governance/release-gate-checklist.md
5. Maturity scorecard: docs/governance/maturity-scorecard.md
6. Admin guide: docs/governance/admin-guide.md
7. Operational guide: docs/governance/operational-guide.md
8. API inventory and UI coverage map: docs/governance/api-inventory-and-ui-map.md
9. Release evidence bundle script: ../scripts/release_evidence_bundle.sh
10. Day-0 password and secrets hardening: docs/security/day0-password-and-secrets-hardening.md
11. AWS integration and multi-cloud fallback design: docs/integrations/aws-integration-and-multicloud-model-fallback.md
12. Security risk closure tracker: docs/governance/security-risk-closure-plan.md
13. Multi-lens security architecture review template: docs/governance/multi-lens-security-architecture-review.md

All substantial changes should satisfy Security Architect, Audit Architect, CISO, AWS Engineer, Cloud Engineer, Frontend UI Expert, and Security Engineer Expert lenses before completion.

## What is implemented

Phase 0 foundations (registration, auth, audit) remain in place. For current module coverage, UI/API inventory, and operator workflows, see **Design and Use-Case Completion Status** below and `docs/governance/api-inventory-and-ui-map.md`.

Recent additions (2026-06-12):

- **Governance:** `app/routers/governance.py` — UI coverage gap reports from canonical inventory markdown.
- **Platform operator experience:** `app/routers/platform.py` — operational posture, operator feedback, analytics, triage actions.
- **Domain constants:** `app/domain_constants.py` — discovery, observability, platform UX defaults (runtime-config overrides in `app/runtime_constants.py`).
- **Services:** `app/services/ui_coverage.py`, `app/services/platform_operational.py`, `app/services/observability_summary.py`, `app/services/config_cache.py` (health posture).

## Run locally with PostgreSQL

1. Start PostgreSQL (Docker example):

   export POSTGRES_PASSWORD="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(24))
PY
)"
   docker run --name agenthub-postgres -e POSTGRES_PASSWORD="$POSTGRES_PASSWORD" -e POSTGRES_USER=postgres -e POSTGRES_DB=agenthub -p 5432:5432 -d postgres:16

2. Create and activate a virtual environment.
3. Install dependencies:

   pip install -r requirements.txt

4. Set database URL:

   export DATABASE_URL=postgresql+psycopg://$USER@localhost:5432/agenthub
   export SESSION_TOKEN_SECRET="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(32))
PY
)"

   Prefer using `PGPASSFILE`/`.pgpass` or secret-manager injection instead of inline URL passwords.

5. Validate Day-0 secrets and password posture:

   bash scripts/validate_day0_secrets.sh

6. Start API server (recommended):

   make up

   make up-clean

   This is an alias for `make dev`.

   `make up-clean` is an alias for `make dev-clean` (frees port 8000 first).

   make dev

   This starts the API with automatic port fallback if `8000` is busy.

   If you need a specific port:

   make dev-port PORT=8001

   Raw uvicorn is still supported, but helper targets are preferred to avoid bind conflicts.

7. Open API docs:

   http://127.0.0.1:8000/docs (or the port printed by `make dev`)

   Swagger tags **Platform** (feedback DB persistence, operational status) and **Governance** (UI coverage gaps) include summaries and error contracts. Machine-readable schema: `GET /openapi.json`.

Alternative infra bootstrapping:

- `make startinfra` now prefers Homebrew `postgresql@16` and falls back to Docker (`agenthub-postgres`) when Homebrew is unavailable.
- `make shutinfra` stops whichever managed infra backend is running.
- `make statusall` skips Docker daemon checks by default to avoid hangs when Docker is installed but not responsive. Set `SHOW_DOCKER_INFRA_STATUS=1` to include Docker container status.

Repository root stack controls:

- `./scripts/startall.sh` starts infra, backend, and UI together.
- `./scripts/shutdownall.sh` stops infra, backend, and UI together.
- `./scripts/statusall.sh` prints local infra/backend/UI status.
- `./scripts/stack.sh start backend|ui|infra|all|prod` starts a specific component, the full local stack, or the production compose stack.
- `./scripts/stack.sh stop backend|ui|infra|all|prod` stops a specific component, the full local stack, or the production compose stack.
- `./scripts/stack.sh status backend|ui|infra|all|prod` prints status for local components or the production compose stack.
- `./scripts/startprod.sh`, `./scripts/stopprod.sh`, and `./scripts/statusprod.sh` are convenience wrappers for production stack lifecycle.
- `./scripts/showstartup.sh` prints the current startup and shutdown commands plus default ports.
- `make showstartup` is the backend-folder shortcut for the same startup summary.

## One-command local start

Use the helper script to validate DB connectivity and start the API:

1. Make script executable:

   chmod +x scripts/run_local.sh

2. Start service:

   ./scripts/run_local.sh
   ./scripts/run_local.sh --port=8001
   ./scripts/run_local.sh --auto-port

You can override DB target by setting DATABASE_URL before running the script.
You can also override API port by setting API_PORT (default: 8000):

   API_PORT=8001 ./scripts/run_local.sh

Quick default command (auto-port enabled):

   make up

Quick stop command:

   make down

   make dev

If a stale listener exists and you want a clean restart path:

   make restartlocal-auto

## One-command local restart

Use this helper to stop any process bound to the API port and start the latest code:

1. Make script executable:

   chmod +x scripts/restart_local.sh

2. Restart on default port 8000:

   ./scripts/restart_local.sh

3. Optional usage:

   ./scripts/restart_local.sh --port=8001
   ./scripts/restart_local.sh --auto-port
   ./scripts/restart_local.sh --no-start

## Lifecycle command targets

The following Make targets are available exactly as requested:

1. startall

   make startall

2. shutdownall

   make shutdownall

3. startinfra

   make startinfra

4. shutinfra

   make shutinfra

5. statusall

   make statusall

6. checkall

   make checkall

   make checkall-port PORT=8001

7. smokee2e

   make smokee2e

   cd .. && ./scripts/smokee2e.sh

   RUNS=8 make test-repeat

   HEALTH_WAIT_SECONDS=30 make smokee2e

8. Port-aware lifecycle targets

   make startall-port PORT=8001
   make statusall-port PORT=8001
   make smokee2e-port PORT=8001
   make shutdownall-port PORT=8001

9. Local run targets

   make go
   make go-port PORT=8001
   make dev
   make dev-port PORT=8001
   make dev-clean
   make dev-clean-port PORT=8001
   make runlocal
   make runlocal-port PORT=8001
   make runlocal-auto
   make runlocal-auto-port PORT=8001
   make restartlocal
   make restartlocal-port PORT=8001
   make restartlocal-auto
   make restartlocal-auto-port PORT=8001
   make verify
   make verify-port PORT=8001
   RUNS=5 make verify

10. Port diagnostics

   make who-uses-port PORT=8000
   make stop-port PORT=8000
   make port-fix PORT=8000
   make free-8000
   make doctor-local
   make doctor-local-port PORT=8001
   ./scripts/doctor_local.sh --port=8001
   make help-local

11. Release evidence targets

   make release-evidence RELEASE_ID=rel-001 ENV=staging OWNER=ops
   make release-evidence-strict RELEASE_ID=rel-001 ENV=production OWNER=ops
   make release-evidence-auto ENV=staging OWNER=ops
   make release-evidence-auto-strict ENV=production OWNER=ops
   make release-evidence-ciso RELEASE_ID=rel-001 OWNER=ciso-review
   make release-evidence-ciso-auto OWNER=ciso-review
   make risk-closure-dashboard
   make pending-closure-report
   make release-decision-record RELEASE_ID=rel-001 ENV=staging OWNER=ops DECISION=TBD
   make release-risk-guardrails ENV=production DECISION=GO DECISION_RECORD=../artifacts/release-decision-rel-001.md
   RELEASE_DECISION=GO RELEASE_ACCEPTED_RISK_APPROVED=yes RELEASE_CISO_ACK=yes make release-evidence-strict RELEASE_ID=rel-001 ENV=production OWNER=ciso-review
   bash ../scripts/render_risk_closure_dashboard.sh --json
   bash ../scripts/render_risk_closure_dashboard.sh --strict-overdue
   bash ../scripts/generate_release_decision_record.sh --release-id rel-001 --env production --owner ciso-review --decision GO --accepted-risk yes --ciso-ack yes --impact-line 'All required review approvals completed' --impact-line 'Risk posture reviewed' --impact-line 'Residual items governed' --output ../artifacts/release-decision-rel-001.md
   bash ../scripts/validate_release_risk_guardrails.sh --env production --decision GO --decision-record ../artifacts/release-decision-rel-001.md

   These targets default `DATABASE_URL` to `postgresql+psycopg://$USER@localhost:5432/agenthub` when unset.
   Non-strict evidence runs treat migration validation as warning-level; strict runs require migration checks to pass.
   Release evidence bundles include a risk-closure dashboard snapshot at `metadata/risk_closure_dashboard.txt`.
   Release evidence bundles also include machine-readable risk data at `metadata/risk_closure_dashboard.json`.
   Release evidence bundles now include a generated decision record template at `metadata/release_decision_record.md`.
   Release evidence bundles include pending action summaries at `metadata/pending_closure_report.txt` and `metadata/pending_closure_report.json`.
   Optional strict production exceptions can be passed via `RISK_EXCEPTION_REF=<approved-id>` when invoking release evidence commands.
   For strict production GO runs, set `RELEASE_ACCEPTED_RISK_APPROVED=yes` and `RELEASE_CISO_ACK=yes` to avoid unresolved assertion fields.

12. Session token signing key rotation

   Configure versioned signing keys with rollover support:

   SESSION_TOKEN_SIGNING_KEYS="k2:<new-strong-secret>,k1:<previous-strong-secret>"

   The first key id signs new session tokens. Validation accepts key-id tokens and legacy two-part tokens during transition.

13. Distributed rate-limit deployment defaults

   RATE_LIMIT_BACKEND=redis
   RATE_LIMIT_REDIS_URL=redis://<host>:6379/0
   RATE_LIMIT_REDIS_PREFIX=rate-limit
   RATE_LIMIT_REDIS_RETRY_SECONDS=30
   RATE_LIMIT_DEGRADED_ALERT_ATTEMPTS=10

   The `/health` endpoint includes `rate_limit` runtime status with:
   - `configured_backend`
   - `active_backend`
   - `degraded`
   - recovery counters and `redis_last_error`

   Alert recommendation:
   - trigger warning when `degraded=true`
   - trigger high severity when `redis_recovery_attempts` exceeds `RATE_LIMIT_DEGRADED_ALERT_ATTEMPTS`

14. Rate-limit production cutover commands

   make rate-limit-cutover-check
   make rate-limit-cutover-probe PORT=8000
   make rate-limit-cutover-failover
   make rate-limit-cutover-rollback

15. Security monitoring setup checks

   make security-monitoring-check
   make architecture-posture-check

   Optional environment variables:

   SESSION_TOKEN_SIGNING_LAST_ROTATED_AT=<ISO-8601 timestamp>
   SESSION_TOKEN_ROTATION_MAX_DAYS=30
   SECURITY_ALERT_WEBHOOK_URL=https://siem.example.com/webhook
   RATE_LIMIT_429_WARN_PER_MIN=100
   RATE_LIMIT_REDIS_FALLBACK_WARN_PER_HOUR=5

16. Ingress security header validation

   make ingress-security-validate BASE_URL=https://api.example.com TEST_PATH=/health

17. Production environment template

   Example baseline config is provided in:

   .env.production.example

   Copy values into your deployment secret manager or environment-specific runtime config.

18. Containerized production deployment

   The repository root now includes production container artifacts:

   - `docker-compose.production.yml`
   - `.env.production.compose.example`
   - `DEPLOYMENT.md`

   Quick start from repository root:

   cp .env.production.compose.example .env.production
   # update secure values in .env.production
   docker compose --env-file .env.production -f docker-compose.production.yml up -d --build

`API_PORT` is respected by `run_local.sh`, `startall.sh`, `restart_local.sh`, `statusall.sh`, `shutdownall.sh`, and `smokee2e.sh`.

## Ports and Time Configuration Guide

Use this section as the single place to change ports and time/TTL-related behavior.

### A. Backend and UI Ports

1. Backend API port
   - Default: `8000`
   - Change via:
     - `API_PORT=8001 make startall`
     - `make dev-port PORT=8001`
     - `./scripts/run_local.sh --port=8001`

2. Frontend UI static port
   - Default: `4173`
   - Change via frontend helper:
     - `cd ../frontend && ./scripts/run_ui.sh --port=5173`
     - `UI_PORT=5173 ./scripts/run_ui.sh`

3. UI-to-backend mapping
   - In UI settings panel, set API Base URL to match backend port.
   - Example: backend on `8001` -> API Base `http://127.0.0.1:8001`

### B. Startup and Health Wait Timers

1. API startup health wait for lifecycle start scripts
   - Variable: `API_HEALTH_WAIT_SECONDS` (default `20`)
   - Used by: `scripts/startall.sh`

2. Smoke health wait
   - Variable: `HEALTH_WAIT_SECONDS` (default `15`)
   - Used by: `scripts/smokee2e.sh`

### C. Session and Auth Time Settings

1. Session issue TTL and idle timeout (request-level)
   - Endpoint: `POST /auth/sessions`
   - Fields:
     - `ttl_minutes`
     - `idle_timeout_minutes`

### D. Database Connection Pool Settings

1. DB connection health checks and recycle
   - `DB_POOL_PRE_PING` (default `true`)
   - `DB_POOL_RECYCLE_SECONDS` (default `1800`, minimum `60`)
   - `DB_POOL_SIZE` (default `10`, minimum `1`)
   - `DB_POOL_MAX_OVERFLOW` (default `20`, minimum `0`)
   - `DB_POOL_TIMEOUT_SECONDS` (default `30`, minimum `1`)

2. Security and reliability guidance
   - keep pre-ping enabled in production
   - align recycle interval with infrastructure connection idle timeouts
   - Schema bounds are enforced in `app/schemas.py`.

2. Session TTL and idle default/bounds (code-level)
   - File: `app/policy_constants.py`
   - Constants:
     - `DEFAULT_SESSION_TTL_MINUTES`
     - `DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES`
     - `MIN_SESSION_TTL_MINUTES`, `MAX_SESSION_TTL_MINUTES`
     - `MIN_SESSION_IDLE_TIMEOUT_MINUTES`, `MAX_SESSION_IDLE_TIMEOUT_MINUTES`

3. Privileged MFA re-auth window
   - Policy field: `privileged_mfa_reauth_minutes`
   - Manage via `GET/PATCH /auth/policies/session`
   - Default constant: `PRIVILEGED_MFA_REAUTH_MINUTES_DEFAULT`

4. Basic-auth fallback duration windows
   - Request field: `duration_minutes` (`POST /auth/basic/config/{id}/enable-temporary`)
   - Max config field: `max_enable_duration_minutes`
   - Defaults in `app/policy_constants.py`:
     - `DEFAULT_BASIC_AUTH_ENABLE_DURATION_MINUTES`
     - `DEFAULT_BASIC_AUTH_MAX_ENABLE_DURATION_MINUTES`

### D. Session Signing Key Rotation Timers

1. Last rotated timestamp
   - `SESSION_TOKEN_SIGNING_LAST_ROTATED_AT` (ISO-8601)

2. Maximum age threshold (days)
   - `SESSION_TOKEN_ROTATION_MAX_DAYS` (default `30`)

3. Validation helper
   - `make security-monitoring-check`
   - `make architecture-posture-check`

### E. Rate-Limit Timing Configuration

1. Distributed backend and key prefix
   - `RATE_LIMIT_BACKEND`
   - `RATE_LIMIT_REDIS_URL`
   - `RATE_LIMIT_REDIS_PREFIX`

2. Rule windows and thresholds
   - Defined in code: `app/services/rate_limit.py`
   - Update `UI_POLLING_RULES` and `WILDCARD_RULES` to tune window seconds and request caps.

## Database migrations (Alembic)

Migration tooling is configured and wired to application models.

1. Apply latest migrations:

   make migrate

2. Roll back one revision:

   make downgrade

3. Use explicit DB URL when needed:

   DATABASE_URL=postgresql+psycopg://$USER@localhost:5432/agenthub make migrate

4. Legacy Alembic version table compatibility (PostgreSQL):

   If older databases have `alembic_version.version_num` constrained to `VARCHAR(32)`,
   migration startup now widens it to `VARCHAR(255)` automatically before revision
   writes. This prevents upgrade failures when repository revision IDs are longer
   than 32 characters.

## Continuous Integration

Backend CI is defined in `.github/workflows/backend-ci.yml`.

It runs on push and pull request changes under `backend/**` and executes:

1. Python 3.11 setup and dependency install
2. PostgreSQL 16 service startup
3. `agenthub` database existence check/create
4. Alembic migrations (`python -m alembic upgrade head`)
5. Runtime API smoke (`bash ./scripts/smokee2e.sh`) against a started uvicorn process
6. Test suite (`python -m pytest -q`)
7. Flake check (`RUNS=3 make test-repeat`)
8. Release evidence bundle generation and artifact upload (`scripts/release_evidence_bundle.sh`)

This CI path intentionally uses a PostgreSQL service container instead of local Homebrew lifecycle scripts.

Each run uploads a release evidence artifact containing logs, governance snapshots, and a summary for audit traceability.

For `main`, `release/*`, and `hotfix/*` branch patterns, CI runs the release evidence bundle in strict mode (`--strict`) so warnings in the evidence gate fail the workflow.

## Design and Use-Case Completion Status

The backend implementation in this repository covers the core design and use-case modules defined in the architecture and product documents.

Implemented module coverage:

1. MOD-REG (registration and ownership)
   - Implemented via `app/routers/agents.py` and ownership history endpoints.

2. MOD-DISC (multi-source discovery)
   - Implemented via `app/routers/discovery.py` with sync, resolve, and promote flows.

3. MOD-RUNTIME and governance controls
   - Implemented via `app/routers/auth.py`, `app/routers/agentic.py`, and `app/security.py`.
   - Includes dual-approval checks, role enforcement, and break-glass controls.

4. MOD-COST (real-time cost intelligence)
   - Implemented via `app/routers/cost.py` with live cost, budgets, policy evaluate, and anomaly endpoints.

5. MOD-EXT (module lifecycle)
   - Implemented via `app/routers/modules.py` including registration, validation, and upgrade planning.

6. MOD-GATEWAY (gateway and key management)
   - Implemented via `app/routers/gateway.py`, `app/routers/providers.py`, and `app/routers/route_drafts.py`.
   - Includes governed MCP gateway workflows with DB-backed server registry and audited tool execution.

7. MOD-OBS and MOD-COMP (observability, audit, compliance)
   - Implemented via `app/routers/observability.py`, `app/routers/audit.py`, and `app/routers/compliance.py`.
   - Includes structured decision outcomes and policy version tracking.

8. MOD-GOV (UI coverage and platform operator experience)
   - Implemented via `app/routers/governance.py` (backend-vs-frontend gap reporting) and `app/routers/platform.py` (operational status, operator feedback, analytics, triage).
   - Health endpoint (`GET /health`) exposes rate-limiter and runtime config cache posture for cloud operators.

Completion verification gate:

1. Run the full end-to-end confidence pipeline:

   make verify

2. This runs:
   - `checkall` (infra + migrations + full tests)
   - `go` (doctor + restart + smoke)
   - `test-repeat` (stability runs)

Current validated baseline in this workspace:

1. Full suite: run `python3 -m pytest` (490+ tests collected; environment-dependent).
2. Focused governance/platform slice: `python3 -m pytest tests/test_ui_coverage.py tests/test_platform_feedback.py tests/test_health_runtime_config_cache.py -q`.
3. `make verify` passes end-to-end when local infra is available.

## Authn and actor context

Authn integration is available via bearer sessions:

- Issue a session: `POST /auth/sessions`
- Use token: `Authorization: Bearer <signed_session_token>`

Password login flow is available for directory-managed users:

- Login endpoint: `POST /auth/login`
- Directory user provisioning requires password on create: `POST /auth/directory/users`
- Failed login lockout policy keys (runtime config):
   - `auth.login.max_failed_attempts`
   - `auth.login.lockout_minutes`
- Admin unlock endpoint (admin role + MFA):
   - `POST /auth/directory/users/{user_id}/unlock`

Directory IAM API coverage:

- Users:
   - `POST /auth/directory/users` (password required on create)
   - `GET /auth/directory/users`
   - `PUT /auth/directory/users/{user_id}` (password optional for rotation)
   - `DELETE /auth/directory/users/{user_id}`
- Groups:
   - `POST /auth/directory/groups`
   - `GET /auth/directory/groups`
   - `PUT /auth/directory/groups/{group_id}`
   - `DELETE /auth/directory/groups/{group_id}`
- Teams:
   - `POST /auth/directory/teams`
   - `GET /auth/directory/teams`
   - `PUT /auth/directory/teams/{team_id}`
   - `DELETE /auth/directory/teams/{team_id}`
- Memberships:
   - `POST /auth/directory/groups/{group_id}/members/{user_id}`
   - `GET /auth/directory/groups/{group_id}/members`
   - `DELETE /auth/directory/groups/{group_id}/members/{user_id}`
   - `POST /auth/directory/teams/{team_id}/members/{user_id}`
   - `GET /auth/directory/teams/{team_id}/members`
   - `DELETE /auth/directory/teams/{team_id}/members/{user_id}`

Password storage and validation behavior:

- Passwords are never stored in plaintext.
- Directory users store salted password hashes in `directory_users.password_hash`.
- Failed login lockout state is persisted per user (`failed_login_attempts`, `locked_until`, `last_login_at`).

Dev troubleshooting: temporary local credential reset (dev-only):

Use this only in local/dev environments when a test/session account is locked out or has an unknown password.

1. Reset an existing directory user password via admin + MFA headers:

    curl -sS -X PUT \
       -H 'Content-Type: application/json' \
       -H 'X-Actor-Id: prod-operator' \
       -H 'X-Actor-Role: Super Admin' \
       -H 'X-MFA-Verified: true' \
       'http://127.0.0.1:8000/auth/directory/users/<user_id>' \
       -d '{"user_id":"<user_id>","display_name":"<display_name>","email":"<email>","role_name":"<role>","status":"active","password":"<NewStrongPass!234>"}'

2. Sign in again through `POST /auth/login` (or the login UI) using the new password.
3. Rotate the password again after troubleshooting if the account is shared.

## MCP gateway configuration (DB-backed)

MCP server registry and timeout controls are stored in runtime config (database-backed), not static code or process memory:

- `gateway.mcp.servers_json` (JSON array of approved MCP servers)
- `gateway.mcp.default_timeout_seconds` (float range `0.5..30.0`)

Security and governance controls:

1. `gateway.mcp.servers_json` is validated by `/runtime-config/validate` before write.
2. Writes to `gateway.mcp.servers_json` are sensitive runtime-config updates and require dual approval.
3. MCP prod tool calls require dual approval (`X-Approver-Id` + `X-Approver-Role`).
4. MCP tool calls enforce per-server allowlists/prefix constraints.
5. MCP list/call actions emit audit evidence (`gateway.mcp.servers.read`, `gateway.mcp.tools.list`, `gateway.mcp.tools.call`).

Gateway MCP endpoints:

- `GET /gateway/mcp/servers`
- `POST /gateway/mcp/servers/{server_id}/tools/list`
- `POST /gateway/mcp/servers/{server_id}/tools/call`

Runtime-config write endpoint for MCP registry:

- `PUT /runtime-config/gateway.mcp.servers_json`

Header-based actor simulation remains available for test and local compatibility:

- X-Actor-Id
- X-Actor-Role
- X-Approver-Id
- X-Approver-Role

For enabling basic-auth fallback, provide a Security Approver via approver headers.

Security event evidence for this area includes:

- `auth.login.password` (allow/deny outcomes)
- `auth.directory.user.unlock` (allow)

## Quick Troubleshooting: Port 8000 Already In Use

If you see this while starting uvicorn:

`[Errno 48] ... 127.0.0.1:8000: address already in use`

Use this sequence:

1. Check which process owns the port:

   make who-uses-port PORT=8000

2. Stop listeners on that port if needed:

   make stop-port PORT=8000

3. Start API with automatic port fallback:

   make runlocal-auto

4. Or restart with automatic port fallback:

   make restartlocal-auto
