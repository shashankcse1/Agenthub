# Python Platform Functionalities and Browser Setup

This document describes what the Python platform supports today and how to run and access it from a browser.

## 1. Supported Functionalities

### 1.1 API and Health

- Health endpoint: `GET /api/v1/health`
- FastAPI app with OpenAPI metadata (`Python Agentic Platform API`, version `0.1.0`)
- Policy and evidence routes are mounted under `/api/v1`

### 1.2 Policy Decision Preview

- Endpoint: `POST /api/v1/policy/preview`
- Request fields:
  - `trace_id`
  - `actor_id`
  - `actor_role`
  - `tenant_id`
  - `environment`
  - `action`
  - `target`
- Response fields:
  - `outcome`
  - `reason`
  - `policy_trace_id`
  - `policy_version`
- Role gate: `Platform Admin` or `Security Approver`

### 1.3 Evidence and Audit Workflows

- List events: `GET /api/v1/evidence/events`
- Export signed bundle: `POST /api/v1/evidence/export`
- Verify bundle integrity: `POST /api/v1/evidence/verify`
- Evidence capabilities:
  - Hash-chain fields per event (`prev_event_hash`, `event_hash`)
  - Signed exports (HMAC-SHA256)
  - Chain-head verification support
  - PII-safe logging with fingerprints and scope fields

### 1.4 Authentication and Authorization

- Bearer JWT auth is primary
- Basic auth is optional fallback (dev-focused), controlled by `ALLOW_BASIC_AUTH`
- Required JWT claims:
  - `sub`
  - `role`
- Optional JWT validation constraints if configured:
  - `iss` via `JWT_ISSUER`
  - `aud` via `JWT_AUDIENCE`
- Non-dev fail-safe:
  - App fails auth with server error if `JWT_SIGNING_SECRET` is left at insecure default

### 1.5 Storage and Safety Controls

- Evidence storage modes:
  - `append_jsonl`
  - `worm_json`
- Fail-closed startup on invalid `EVIDENCE_STORAGE_MODE`
- Retention and legal hold controls:
  - `EVIDENCE_RETENTION_DAYS`
  - `EVIDENCE_LEGAL_HOLD_ENABLED`

### 1.6 Deployment and Verification

- Local gate script: `bash scripts/run_agent_clean_arch_gates_python.sh`
- Container deploy helper: `bash scripts/deploy_python_platform_container.sh`
- Container smoke checks:
  - `bash python-platform/scripts/container_smoke.sh`
  - `bash python-platform/scripts/container_fail_closed_smoke.sh`

## 2. Install and Run for Browser Access

You can use the platform in browser in two ways:

- API docs and direct API testing in browser
- Full UI workflow through the frontend control surface

### 2.1 Prerequisites

- Python 3.11+
- Backend dependencies installable with pip
- One container runtime for container path:
  - Docker (default scripts)
  - Podman (fallback path)

### 2.2 Option A: Run API Locally and Open in Browser

1. Install Python package in editable mode:

```bash
cd python-platform
python3 -m pip install -e .
```

2. Start API server:

```bash
cd python-platform
python3 -m uvicorn agent_platform.api.main:app --host 127.0.0.1 --port 8080
```

3. Open browser endpoints:

- Health: `http://127.0.0.1:8080/api/v1/health`
- Swagger UI: `http://127.0.0.1:8080/docs`
- OpenAPI JSON: `http://127.0.0.1:8080/openapi.json`

### 2.3 Option B: Run in Container and Open in Browser

1. Configure env:

```bash
cp python-platform/.env.example python-platform/.env
```

2. Set strong values in `python-platform/.env`:

- `JWT_SIGNING_SECRET`
- `AUDIT_SIGNING_SECRET`

3. Start container:

```bash
bash scripts/deploy_python_platform_container.sh
```

4. Open browser endpoints:

- Health: `http://127.0.0.1:8080/api/v1/health`
- Swagger UI: `http://127.0.0.1:8080/docs`

### 2.4 Option C: Use Full Frontend UI in Browser

1. Start backend API (from repository backend service)
2. Start frontend static UI:

```bash
cd frontend
./scripts/run_ui.sh
```

3. Open UI in browser:

- `http://127.0.0.1:4173`

4. In the UI settings panel, set API base to your running backend URL (for example `http://127.0.0.1:8000`).

## 3. Production Notes

- Keep `ALLOW_BASIC_AUTH=false` outside development.
- Inject secrets from secret manager or CI/CD runtime, not from committed files.
- Use gate scripts before release:
  - `bash scripts/run_agent_clean_arch_gates_python.sh`
- For governance evidence workflows, run the release helper scripts from repository root.