# Operations Quickstart

This is the one-page runbook for local startup, port mapping, timeout tuning, and production environment handoff.

## 1) Backend Start and Stop

From backend folder:

```bash
cd backend
make up
```

For full-stack startup from the repo root, including infra, backend, and UI:

```bash
./scripts/startall.sh
```

To start a specific component instead of the whole stack:

```bash
./scripts/stack.sh start backend
./scripts/stack.sh start ui
./scripts/stack.sh start infra
./scripts/startprod.sh
```

If port 8000 is busy:

```bash
make dev-port PORT=8001
```

Stop services:

```bash
make down
```

To stop a specific component or the entire stack from the repo root:

```bash
./scripts/stack.sh stop backend
./scripts/stack.sh stop ui
./scripts/stack.sh stop infra
./scripts/shutdownall.sh
./scripts/stopprod.sh
```

Status checks:

```bash
./scripts/statusall.sh
./scripts/statusprod.sh
./scripts/stack.sh status all
```

If you just want a quick reminder of the available startup and shutdown commands:

```bash
./scripts/showstartup.sh
```

Or, from the backend folder:

```bash
make showstartup
```

## 2) Frontend Start

From frontend folder:

```bash
cd frontend
./scripts/run_ui.sh
```

From the repo root, the stack wrapper can also start only the UI:

```bash
./scripts/stack.sh start ui
```

Custom UI port/host:

```bash
./scripts/run_ui.sh --port=5173 --host=127.0.0.1
```

## 3) UI to Backend Port Mapping

1. Backend default API port: 8000.
2. Frontend default static port: 4173.
3. If backend port changes (for example 8001), open the UI settings panel and set API Base URL to:

```text
http://127.0.0.1:8001
```

## 4) Production Environment Setup

Use the production template as baseline:

- backend/.env.production.example

Minimum production security configuration:

1. Set strong session secrets/signing key ring.
2. Keep header actor auth disabled.
3. Keep MFA enforcement optional mode disabled.
4. Configure non-wildcard CORS allowlist.
5. Configure Redis-backed rate limiting.
6. Configure startup alert webhook routing.

Production lifecycle commands:

```bash
./scripts/startprod.sh
./scripts/statusprod.sh
./scripts/stopprod.sh
```

## 5) Time and TTL Knobs

### Script startup and health timers

1. API_HEALTH_WAIT_SECONDS (default 20): used by backend/scripts/startall.sh.
2. HEALTH_WAIT_SECONDS (default 15): used by backend/scripts/smokee2e.sh.

### Session and auth timing

1. POST /auth/sessions fields:
   - ttl_minutes
   - idle_timeout_minutes
2. Session defaults and bounds are in backend/app/policy_constants.py.
3. Privileged MFA reauth window is controlled by privileged_mfa_reauth_minutes in auth session policy.
4. Basic auth temporary enable duration is controlled by duration_minutes and max_enable_duration_minutes.

### Session key rotation timing

1. SESSION_TOKEN_SIGNING_LAST_ROTATED_AT (ISO-8601).
2. SESSION_TOKEN_ROTATION_MAX_DAYS (default 30).

## 6) Validation Commands

Run strict cross-discipline review:

```bash
bash scripts/full_stack_expert_review.sh --strict
```

Optional focused backend tests:

```bash
cd backend
python3 -m pytest -q tests/test_security_config_warnings.py tests/test_rate_limit_backend.py
```

Run end-to-end smoke from repo root (baseline + gateway pre-call/mirroring):

```bash
./scripts/smokee2e.sh
```

Optional: skip only the gateway pre-call/mirroring smoke layer:

```bash
SKIP_GATEWAY_PRECALL_MIRROR_SMOKE=1 ./scripts/smokee2e.sh

Release-governance automation (risk dashboard + pending closure + decision record + guardrails):

```bash
cd backend
make risk-closure-dashboard
make pending-closure-report
make release-decision-record RELEASE_ID=rel-001 ENV=staging OWNER=ops DECISION=TBD
make release-risk-guardrails ENV=staging DECISION=TBD DECISION_RECORD=../artifacts/release-decision-rel-001.md
```

Strict production evidence generation with explicit assertion inputs:

```bash
cd backend
RELEASE_DECISION=GO \
RELEASE_ACCEPTED_RISK_APPROVED=yes \
RELEASE_CISO_ACK=yes \
RELEASE_IMPACT_LINE_1='All required review approvals completed' \
RELEASE_IMPACT_LINE_2='Risk closure posture reviewed in latest dashboard' \
RELEASE_IMPACT_LINE_3='Residual items tracked with governance controls' \
make release-evidence-strict RELEASE_ID=rel-001 ENV=production OWNER=ciso-review
```

When overdue closure items exist for production GO, include approved exception reference:

```bash
cd backend
RISK_EXCEPTION_REF=EXC-123 \
RELEASE_DECISION=GO \
RELEASE_ACCEPTED_RISK_APPROVED=yes \
RELEASE_CISO_ACK=yes \
make release-evidence-strict RELEASE_ID=rel-001 ENV=production OWNER=ciso-review
```
```

## 7) Troubleshooting Fast Path

1. Backend fails to bind on 8000: run make dev-port PORT=8001, then update UI API Base URL.
2. API startup fails due env checks: verify production env vars against backend/.env.production.example.
3. Smoke test cannot reach health endpoint: increase HEALTH_WAIT_SECONDS and verify BASE_URL/API_PORT alignment.

## 8) Show Startup Info

Use this when you want a quick reminder of the available start and stop commands:

```bash
./scripts/showstartup.sh
```

You can also run:

```bash
make showstartup
```

## 9) Deep-Dive References

- backend/README.md
- frontend/README.md
- backend/docs/governance/release-gate-checklist.md
- backend/docs/governance/security-risk-closure-plan.md
- backend/docs/governance/multi-lens-security-architecture-review.md
- backend/docs/security/security-operations-runbook.md
- backend/docs/security/day0-password-and-secrets-hardening.md
- backend/docs/integrations/aws-integration-and-multicloud-model-fallback.md

## 10) Enable Providers and Agents

Use this sequence for each tenant and provider.

1. Configure tenant-scoped provider credentials via environment variables in backend/.env.production.example.
2. Create workload identity profile:

```bash
curl -s -X POST http://127.0.0.1:8000/auth/workload-identity/providers \
   -H 'Content-Type: application/json' \
   -H 'X-Actor-Role: Platform Admin' \
   -H 'X-Actor-Id: platform-admin' \
   -H 'X-MFA-Verified: true' \
   -d '{"tenant_id":"tenant-a","provider_type":"aws","audience":"aud-1","role_arn_or_equivalent":"arn:aws:iam::123456789012:role/agenthub","session_duration_seconds":900,"allowed_subject_patterns":"[""svc:*""]"}'
```

3. Validate trust and check health with the same tenant_id.
4. Configure route provider priority per tenant:

```bash
curl -s -X POST http://127.0.0.1:8000/gateway/routes/<route_policy_id>/providers/priority \
   -H 'Content-Type: application/json' \
   -H 'X-Actor-Role: AI Ops Approver' \
   -H 'X-Actor-Id: aiops-operator' \
   -d '{"tenant_id":"tenant-a","environment":"prod","priority_order":"[{""provider_id"":""aws-primary"",""priority"":1},{""provider_id"":""azure-secondary"",""priority"":2}]","global_timeout_ms":4500,"max_fallback_hops":2}'
```

5. Dry-run fallback:
    - POST /gateway/routes/{route_policy_id}/simulate-fallback
6. Execute fallback with per-hop telemetry:
    - POST /gateway/routes/{route_policy_id}/execute-fallback

## 11) Policy Inventory (Prod + Stage)

Use this inventory to quickly locate the currently seeded baseline policies.

### Production Baseline

1. Session policy
   - policy_id: `default`
   - description: `Production baseline session governance policy`
2. Route policy
   - route_policy_id: `1462e265-7b85-4ce5-bf62-503b4a7861b3`
   - route_name: `prod-default-route`
3. Cache policy
   - cache_policy_id: `2a1b5048-3644-453c-b2fb-bc9e90268d0e`
   - scope: `responses:prod`
4. Budget policy
   - budget_policy_id: `ded39826-699c-46d7-b9bf-163225feb280`
   - scope: `environment:prod`
5. Retention policy
   - policy_id: `66e8c627-5ea2-498c-ace0-424e197ef60b`
   - data_class: `audit_logs`
   - jurisdiction: `global`
6. Policy schedule
   - job_id: `sched-8dfb2d61-3549-4a84-a4b9-d8ce2f9bf06c`
   - name: `prod-nightly-policy-optimize`

### Stage Baseline

1. Route policy
   - route_policy_id: `b695d0fb-3985-4c74-92de-3c53ac389a80`
   - route_name: `stage-default-route`
2. Cache policy
   - cache_policy_id: `bbc1f1a7-e0a6-4066-836a-ced65533f807`
   - scope: `responses:stage`
3. Budget policy
   - budget_policy_id: `dac54096-5095-4861-bb55-9fe907114b55`
   - scope: `environment:stage`
4. Retention policy
   - policy_id: `c78143da-da5f-48c4-a3a9-7b992cb36faf`
   - data_class: `application_logs`
   - jurisdiction: `stage`
5. Policy schedule
   - job_id: `sched-a2620e8c-fa8f-4745-8a4f-e227565c7e19`
   - name: `stage-nightly-policy-optimize`

### Quick Verification

Use these commands to verify policies are still present and active:

```bash
curl -s http://127.0.0.1:8000/auth/policies/session -H 'X-Actor-Role: Master Admin' -H 'X-Actor-Id: ops-check' | jq
curl -s http://127.0.0.1:8000/gateway/routes -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: ops-check' | jq
curl -s http://127.0.0.1:8000/gateway/cache/policies -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: ops-check' | jq
curl -s http://127.0.0.1:8000/cost/budgets -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: ops-check' | jq
curl -s http://127.0.0.1:8000/compliance/retention/policies -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: ops-check' | jq
curl -s http://127.0.0.1:8000/agentic/policy/schedules -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: ops-check' | jq
```

## 11) Password Login Lockout Operations

Runtime-configurable policy keys:

1. `auth.login.max_failed_attempts` (default `5`, range `1..20`)
2. `auth.login.lockout_minutes` (default `15`, range `1..240`)

Validate a candidate value:

```bash
curl -s -X POST http://127.0.0.1:8000/runtime-config/validate \
   -H 'Content-Type: application/json' \
   -H 'X-Actor-Role: Platform Admin' \
   -H 'X-Actor-Id: platform-admin' \
   -d '{"config_key":"auth.login.max_failed_attempts","config_value":"5"}'
```

Unlock a user account (admin + MFA required):

```bash
curl -s -X POST http://127.0.0.1:8000/auth/directory/users/<user_id>/unlock \
   -H 'X-Actor-Role: Master Admin' \
   -H 'X-Actor-Id: platform-admin' \
   -H 'X-MFA-Verified: true'
```

Expected audit evidence:

1. `auth.login.password` with `decision_outcome=deny` for failed/locked logins.
2. `auth.directory.user.unlock` with `decision_outcome=allow` for successful unlock actions.

## 12) Directory IAM Operations (Users, Groups, Teams)

Directory management endpoints:

1. Users:
   - `POST /auth/directory/users`
   - `GET /auth/directory/users`
   - `PUT /auth/directory/users/{user_id}`
   - `DELETE /auth/directory/users/{user_id}`
2. Groups:
   - `POST /auth/directory/groups`
   - `GET /auth/directory/groups`
   - `PUT /auth/directory/groups/{group_id}`
   - `DELETE /auth/directory/groups/{group_id}`
3. Teams:
   - `POST /auth/directory/teams`
   - `GET /auth/directory/teams`
   - `PUT /auth/directory/teams/{team_id}`
   - `DELETE /auth/directory/teams/{team_id}`
4. Memberships:
   - `POST /auth/directory/groups/{group_id}/members/{user_id}`
   - `GET /auth/directory/groups/{group_id}/members`
   - `DELETE /auth/directory/groups/{group_id}/members/{user_id}`
   - `POST /auth/directory/teams/{team_id}/members/{user_id}`
   - `GET /auth/directory/teams/{team_id}/members`
   - `DELETE /auth/directory/teams/{team_id}/members/{user_id}`

Password handling notes:

1. User create requires `password` and stores only password hashes (no plaintext storage).
2. User update may include optional `password` to rotate credentials.
3. Password login endpoint is `POST /auth/login` and returns bearer session token on success.

## 13) MCP Gateway Configuration (DB-Backed)

MCP gateway configuration is stored in the runtime-config database key `gateway.mcp.servers_json`.

Primary runtime-config keys:

1. `gateway.mcp.servers_json` (JSON array of approved MCP servers)
2. `gateway.mcp.default_timeout_seconds` (default `8.0`, range `0.5..30.0`)

Validate candidate MCP server config before save:

```bash
curl -s -X POST http://127.0.0.1:8000/runtime-config/validate \
   -H 'Content-Type: application/json' \
   -H 'X-Actor-Role: Platform Admin' \
   -H 'X-Actor-Id: platform-admin' \
   -d '{
      "config_key":"gateway.mcp.servers_json",
      "config_value":"[{\"server_id\":\"docs-mcp\",\"base_url\":\"http://127.0.0.1:9100/mcp\",\"transport\":\"streamable_http\",\"enabled\":true,\"allowed_tools\":[\"docs.search\"]}]"
   }'
```

Persist MCP server config to DB (Platform Admin + Security Approver dual approval required):

```bash
curl -s -X PUT http://127.0.0.1:8000/runtime-config/gateway.mcp.servers_json \
   -H 'Content-Type: application/json' \
   -H 'X-Actor-Role: Platform Admin' \
   -H 'X-Actor-Id: platform-admin' \
   -H 'X-Approver-Role: Security Approver' \
   -H 'X-Approver-Id: sec-approver-1' \
   -d '{
      "config_value":"[{\"server_id\":\"docs-mcp\",\"base_url\":\"http://127.0.0.1:9100/mcp\",\"transport\":\"streamable_http\",\"enabled\":true,\"allowed_tools\":[\"docs.search\"]}]",
      "description":"Approved MCP server registry"
   }' | jq
```

Verify value is in runtime-config DB:

```bash
curl -s http://127.0.0.1:8000/runtime-config \
   -H 'X-Actor-Role: Platform Admin' \
   -H 'X-Actor-Id: platform-admin' | jq '.[] | select(.config_key=="gateway.mcp.servers_json")'
```

Verify gateway reads and exposes configured servers:

```bash
curl -s http://127.0.0.1:8000/gateway/mcp/servers \
   -H 'X-Actor-Role: Auditor' \
   -H 'X-Actor-Id: audit-reader' | jq
```

## Platform health, banners, and operator feedback

Check API and cache posture:

```bash
curl -s http://127.0.0.1:8000/health | jq
curl -s http://127.0.0.1:8000/platform/operational-status | jq
```

Enable maintenance banner (Runtime Config UI or API):

- `platform.maintenance_mode` = `true`
- `platform.maintenance_message` = operator-visible text

Tune slow-performance threshold:

- `platform.slow_response_threshold_ms` (default `2000`)

Operator feedback analytics (Auditor+):

```bash
curl -s 'http://127.0.0.1:8000/platform/feedback/analytics?since_hours=168' \
   -H 'X-Actor-Role: Auditor' \
   -H 'X-Actor-Id: audit-reader' | jq
```

Interactive API docs (Swagger UI): `http://127.0.0.1:8000/docs` — **Platform** and **Governance** tags include feedback persistence, audit notes, and error contracts. OpenAPI JSON: `GET /openapi.json`.

Full runbook: `backend/docs/governance/operational-guide.md`. UI/API map: `backend/docs/governance/api-inventory-and-ui-map.md`.
