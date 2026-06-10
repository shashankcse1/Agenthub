# Python Platform Scaffold (Deprecated)

This scaffold is deprecated and is not part of active release gates.

If you must run legacy python-platform checks locally, set:

- `ENABLE_PYTHON_PLATFORM_GATES=1`

This folder contains a historical clean-architecture Python implementation scaffold for the agentic browser security platform.

Detailed capabilities and browser setup guide:

- `python-platform/FUNCTIONALITIES_AND_BROWSER_SETUP.md`
- `docs/AI_AGENT_GOVERNANCE_ONE_PAGER.md` (stakeholder one-page summary)

## Modules

- `agent_platform.domain`
- `agent_platform.application`
- `agent_platform.adapters`
- `agent_platform.api`

## Security Defaults

- API endpoints are authenticated by default.
- Public health endpoint only: `/api/v1/health`.
- Policy decision previews require `Platform Admin` or `Security Approver` role.
- Bearer JWT authentication is supported with required claims: `sub`, `role`.
- Basic auth is development fallback only and should be disabled outside dev (`ALLOW_BASIC_AUTH=false`).
- Audit evidence uses PII-safe logging: actor and target values are fingerprinted, raw identifiers are not logged, and every audit record includes a human-readable decision description.
- Evidence APIs support signed export bundles and PII-safe audit event listing for investigation and CISO review.
- Evidence storage is durable append-only file backed (JSONL) with configurable retention and legal-hold controls.
- Evidence events include tamper-evident chain hashes (`prev_event_hash`, `event_hash`) and exports include a verifiable chain head.

## Agent-Friendly Commands

- Static architecture checks: `bash ../scripts/verify_python_clean_arch_structure.sh`
- API contract checks: `bash ../scripts/verify_python_api_contract_artifacts.sh`
- Full non-interactive gate: `bash ../scripts/run_agent_clean_arch_gates_python.sh`
- Run tests: `cd python-platform && python3 -m pytest`

## CI Enforcement

- Workflow: `.github/workflows/python-platform-agent-gates.yml`
- Trigger: changes in `python-platform/**` or python gate scripts
- Enforced checks:
  - Clean architecture static verifier
  - API contract verifier
  - Pytest suite
  - Integrated non-interactive gate
  - Docker-gated container fail-closed startup smoke (`python-platform/scripts/container_fail_closed_smoke.sh`)

## Container Deployment

- Dockerfile: `python-platform/Dockerfile`
- Compose stack: `python-platform/docker-compose.yml`
- Compose env template: `python-platform/.env.example`
- One-command deploy helper: `bash scripts/deploy_python_platform_container.sh`
- Container smoke check: `bash python-platform/scripts/container_smoke.sh`
- Container fail-closed startup smoke: `bash python-platform/scripts/container_fail_closed_smoke.sh`
- Kubernetes manifests:
  - `python-platform/k8s/deployment.yaml`
  - `python-platform/k8s/service.yaml`
  - `python-platform/k8s/secret.example.yaml`

Deployment smoke behavior:

- Verifies unauthenticated requests are denied.
- Generates a bearer JWT inside the running container for a valid authenticated request.
- Confirms container logs contain `audit_event=policy.preview` with a descriptive decision string.
- Confirms audit logs redact raw actor and target values and expose only safe fingerprints and scope fields.
- Confirms invalid `EVIDENCE_STORAGE_MODE` fails closed in container startup checks and valid `worm_json` mode initializes cleanly.

Evidence APIs:

- `GET /api/v1/evidence/events` lists recent PII-safe audit events for authorized roles.
- `POST /api/v1/evidence/export` returns a signed evidence bundle for investigation export workflows.
- `POST /api/v1/evidence/verify` verifies bundle signature and chain integrity for exported evidence.

Evidence storage controls:

- `EVIDENCE_STORAGE_MODE`: `append_jsonl` (default) or `worm_json` for write-once per-event artifact files.
- `EVIDENCE_STORE_PATH`: append-only JSONL path for audit events.
- `EVIDENCE_RETENTION_DAYS`: retention window for listing/export (default: 30).
- `EVIDENCE_LEGAL_HOLD_ENABLED`: when `true`, retention filtering is bypassed for investigation/legal hold workflows.
- `AUDIT_SIGNING_SECRET`: optional dedicated HMAC signing secret for evidence bundles (falls back to `JWT_SIGNING_SECRET`).

Startup safety: if `EVIDENCE_STORAGE_MODE` is set to any value other than `append_jsonl` or `worm_json`, the service fails fast during dependency initialization.

Security requirements for container deployment:

- Set a strong `JWT_SIGNING_SECRET` before production deployment.
- Set a strong `AUDIT_SIGNING_SECRET` before production deployment.
- Keep `ALLOW_BASIC_AUTH=false` outside dev.
- If `ALLOW_BASIC_AUTH=true`, inject `BASIC_AUTH_PLATFORM_ADMIN_PASSWORD`, `BASIC_AUTH_SECURITY_APPROVER_PASSWORD`, and `BASIC_AUTH_AUDITOR_PASSWORD` from a secret manager (no hardcoded defaults).
- Use bearer JWT authentication in production.
- Prefer secret injection from your container platform instead of inline compose values.
- `scripts/deploy_python_platform_container.sh` fails closed for non-dev environments when JWT or audit signing secrets are unset or left as placeholders.
- Docker daemon availability is required; deployment exits early when the daemon is not reachable.

Quick start:

1. Copy `python-platform/.env.example` to `python-platform/.env`.
2. Replace `JWT_SIGNING_SECRET` and `AUDIT_SIGNING_SECRET` with strong secrets.
3. Run `bash scripts/deploy_python_platform_container.sh`.
