# Frontend UI (No-Build)

This is a static SPA control surface for the backend API.

Workspace-wide operations quickstart:

- ../operations-quickstart.md

## Run locally

1. Start backend API (example):

   cd ../backend
   DATABASE_URL='postgresql+psycopg://sk@localhost:5432/agenthub' python3 -m uvicorn app.main:app --host 127.0.0.1 --port 8000

2. Serve frontend:

   cd ../frontend
   ./scripts/run_ui.sh

   Or from the repo root, start only the UI with the flexible stack wrapper:

   ./scripts/stack.sh start ui

   Or use the helper script with custom port/host:

   ./scripts/run_ui.sh
   ./scripts/run_ui.sh --port=5173
   UI_PORT=5173 ./scripts/run_ui.sh

3. Open:

   http://127.0.0.1:4173

## Notes

- API base URL and actor context can be changed from the left settings panel.
- UI server port can be changed with `UI_PORT` or `--port` in `scripts/run_ui.sh`.
- Backend API base can be changed per profile from the UI settings panel.
- UI provides pages for Overview, Agents, Playground, Benchmark & Scan, Routing & Gateway, Runtime Config, Providers, Modules, Agentic, Discovery, Cost, Audit, Compliance, Observability, and Security.
- UI includes a Providers view with list/filter tables for Workload Identity Providers (`/auth/workload-identity/providers`) and Secret Providers (`/secrets/providers`), plus token exchange (`/auth/workload-identity/token-exchange`) and key rotate-via-secret-provider (`/keys/{key_id}/rotate-via-secret-provider`) workflows.
- Providers view also includes trust validation (`/auth/workload-identity/providers/{provider_id}/validate-trust`), trust evidence drilldown via filtered audit events (`/audit/events`), workload identity health checks (`/auth/workload-identity/providers/{provider_id}/health`), secret lease inventory (`/secrets/providers/{provider_id}/leases`), secret lease renewal (`/secrets/providers/{provider_id}/leases/renew`), and secret provider health checks (`/secrets/providers/{provider_id}/health`).
- UI includes a Modules view for secure module lifecycle operations (`/modules/register`, `/modules`, `/modules/{module_id}/versions`, `/agents/{agent_id}/modules/validate`, `/agents/{agent_id}/modules/upgrade-plan`, and `/modules/{module_id}/deprecate`).
- UI includes an Agentic view for readiness and scheduling operations (`/agentic/readiness/report`, `/agentic/contracts/validate`, `/agentic/readiness/certifications/run`, `/agentic/readiness/certifications`, `/agentic/readiness/certifications/latest`, `/agentic/policy/auto-tune`, and `/agentic/policy/schedules*` actions).
- Agentic view also supports direct scheduled optimize execution (`/agentic/policy/scheduled-optimize`) and schedule summary/detail/update workflows (`/agentic/policy/schedules/summary`, `/agentic/policy/schedules/{job_id}`, `/agentic/policy/schedules/{job_id}` PATCH).
- Agentic advanced operations now include certification override/export (`/agentic/readiness/certifications/{certification_id}/override`, `/agentic/readiness/certifications/{certification_id}/export`), load-test run/latest (`/agentic/readiness/load-tests/run`, `/agentic/readiness/load-tests/latest`), and checkpoint create/list/resume (`/agentic/checkpoints`, `/agentic/checkpoints/{session_id}`, `/agentic/checkpoints/{checkpoint_id}/resume`).
- UI provides a Runtime Config page for database-backed operator settings such as gateway timeout and workload identity defaults.
- Runtime Config page includes a searchable Validation Rules table sourced from `/runtime-config/validation-rules`, plus key-specific inline hints in the save form.
- Each validation rule row includes a `Use Rule` action to prefill the runtime config form with a starter key/value for faster operator workflows.
- Each validation rule row also includes `Copy Template` to copy the example value to clipboard for paste/edit in the config value field.
- Each validation rule row includes `Validate Template` to run `/runtime-config/validate` before saving, so operators can verify template correctness early.
- Validation outcomes are shown inline per rule row as pass/fail status with timestamp in the `Last Check` column.
- `Clear Status` resets all `Last Check` badges, and statuses are automatically reset when context/profile changes or rules are reloaded.
- `Last Check` badge state is stored in `sessionStorage` and scoped by API base URL + environment profile, then restored after page refresh for that same target context.
- Runtime Config now shows a visible `Status scope` label (`profile @ apiBase`) so operators can confirm which context the `Last Check` badges belong to.
- Startup-critical secrets and boot parameters remain environment-driven; non-startup runtime tuning is managed in the database.
- Agents page includes an Agent Configuration Studio backed by the backend database (`/agent-configs` API) for persisted operator-managed settings.
- Agents page also includes ownership operations (`/owners/{owner_id}/agents`, `/agents/{agent_id}/owner`, `/agents/{agent_id}/ownership-history`) for end-to-end ownership governance coverage.
- Full UI/API/product coverage audit matrix is documented in `../backend/docs/governance/ui-api-design-coverage-map.md`.
- UI view visibility can be controlled from runtime config using `ui.feature.<view>.enabled` or environment-specific keys like `ui.feature.discovery.enabled.prod`.
- The same studio supports provider priority, fallback hops/timeouts, retry budget, and circuit-breaker thresholds per agent.
- Security review checks are available in the UI for AWS/cloud fallback posture, production safety thresholds, and fallback resilience.
- CISO/audit evidence bundle export is available as JSON and includes findings, reviewer context, and serialized config state.
- Agent configurations can be exported/imported as JSON for portable, reviewable change bundles.
- Backend endpoint access follows existing role checks; use appropriate actor role in the UI context.
- UI sign-in uses backend credential validation (`POST /auth/login`) and receives bearer session tokens.
- Backend enforces password-login lockout policy with runtime-configurable controls (`auth.login.max_failed_attempts`, `auth.login.lockout_minutes`).
- Playground Studio supports text prompts, voice/video attachments, microphone capture, live stream preview, judge/retry actions, route-draft creation, and run history browsing.
- Benchmark & Scan supports benchmark and scan execution, plus filtered history browsing and trend summaries backed by `/benchmarks/runs` and `/scans/runs`.
- Routing & Gateway supports route policy create/list, priority updates (including request-tag scoped priority), fallback simulation/execution (including request-tag based routing behavior), route optimization, route draft list/history browsing, draft lifecycle actions (submit/approve/reject/change-window/promote/rollback), and key lifecycle management.
- Route Priority now shows a Policy Scope indicator in the UI so operators can confirm whether the loaded policy is default or request-tag scoped.
- Routing & Gateway now includes adaptive load-balancing selection plus explicit lowest-cost, lowest-latency, and least-busy route strategies in route create workflows.
- Route Priority supports health-check routing and optional budget limits, and Fallback Execution supports request-priority tiers (`low|normal|high`).
- Route fallback policy JSON supports optional `routing_groups` with per-group strategy and `failover_weight` to model weighted failover between deployment groups.
- Route retry policy JSON supports `error_type_policies` with per-error `max_retries` and `cooldown_seconds`; execution enforces these controls and records cooldown-aware skip outcomes.
- Pre-Call Filters card supports route-scoped region/context-window guardrails via `PUT/GET /gateway/routes/{route_policy_id}/pre-call-filters` (including optional request-tag scoped policies).
- Traffic Mirroring card supports shadow/observe mirror target configuration via `PUT/GET /gateway/routes/{route_policy_id}/traffic-mirroring` (including optional request-tag scoped policies).
- Mirror Analytics card supports route-scoped mirroring summary and experiment reporting via `GET /gateway/routes/{route_policy_id}/traffic-mirroring/analytics-summary` and `GET /gateway/routes/{route_policy_id}/traffic-mirroring/experiment-report`.
- Gateway Entitlements card supports scoped action-grant list/filter and upsert workflows via `GET /gateway/entitlements` and `PUT /gateway/entitlements/{entitlement_id}`.
- NHI Inventory & Hygiene card supports machine-identity inventory and hygiene review via `GET /gateway/nhi/inventory` and `GET /gateway/nhi/hygiene`.
- Access Reviews & JIT card supports campaign create/read workflows via `POST /gateway/access-reviews/campaigns` and `GET /gateway/access-reviews/campaigns/{campaign_id}`, plus JIT request create/approve workflows via `POST /gateway/jit-requests` and `POST /gateway/jit-requests/{request_id}/approve`.
- Least-Privilege Recommendations card supports recommendation read/apply workflows via `GET /gateway/least-privilege/recommendations` and `POST /gateway/least-privilege/recommendations/{recommendation_id}/apply`.
- Gateway Governance Evidence card supports filtered gateway-governance evidence aggregation/export via `POST /gateway/governance/evidence/export`, with backend-generated JSON bundle metadata and action-level summaries.
- OpenAI-Compatible Gateway Ops card now supports governed `POST /v1/chat/completions`, responses lifecycle (`POST/GET/GET{id}/DELETE{id} /v1/responses`), and files metadata lifecycle (`POST/GET/GET{id}/DELETE{id} /v1/files`) workflows directly from the Routing & Gateway view, including server-backed list filters and client-side advanced filtering + bulk delete operations for responses/files records.
- OpenAI-compatible chat/responses create payloads now include risk-adaptive decision metadata (`risk_tier`, `risk_reasons`) so operators can quickly distinguish low/medium/high inference posture during review.
- Routing & Gateway OpenAI-compatible card now includes a Risk Summary panel that highlights the highest tier and reasons from chat/responses payloads (including response-list aggregation) for faster operator triage.
- Responses lifecycle table now supports local `risk_tier` filtering (`low|medium|high`) and per-row risk badges with reason tooltips to speed incident triage and review.
- Responses ops now includes `Export Filtered` to download the currently filtered response/risk dataset as JSON for audit and incident-evidence workflows.
- Responses ops also includes `Export Selected` to download only explicitly selected response rows as JSON when focused investigation scope is required.
- Responses/files lifecycle delete semantics are owner-or-admin with object-level scope checks; Agent Owner cross-owner deletes are fail-closed.
- For responses/files delete operations targeting `prod`, operators must provide dual-approval headers with a distinct Security Approver identity; denied attempts are audit logged.
- For Access Reviews, JIT approvals, entitlement updates, and least-privilege applies targeting `prod`, operators must provide dual-approval headers with a distinct Security Approver identity; these actions are audit logged.
- Least-Privilege apply workflow requires a human-authored decision reason in the UI to support CISO evidence standards and IAM governance traceability.
- Cloud/AWS operational best practice for these workflows is to keep tenant/environment scoping explicit (no wildcard scope assumptions) and prefer short-lived JIT windows over standing privileged grants.
- Provider Health Routing card supports update/read workflows for provider health states (`/gateway/routes/{route_policy_id}/providers/health`).
- Dedicated fallback policy management endpoints are available (`PUT/GET /gateway/routes/{route_policy_id}/fallbacks`) for controlled fallback updates and readback.
- Routing & Gateway also supports cache policy create/list workflows (`/gateway/cache/policies`) in addition to cache stats and compatibility checks.
- Routing & Gateway also supports cache health diagnostics (`/gateway/cache/health`) and audit-backed cache invalidate requests (`/gateway/cache/delete`).
- Routing & Gateway also supports MCP governance workflows: approved server registry readback (`/gateway/mcp/servers`), tool discovery per server (`/gateway/mcp/servers/{server_id}/tools/list`), and governed tool execution (`/gateway/mcp/servers/{server_id}/tools/call`).
- Routing & Gateway now also supports governed external callback workflows: callback registry list/create/update (`/gateway/external-callbacks`), simulated delivery tests (`/gateway/external-callbacks/{callback_id}/test-delivery`), and export evidence snapshots (`/gateway/external-callbacks/export`).
- Routing & Gateway now also supports explicit authorization explainability simulation via `POST /gateway/authz/explain` to show decision traces, allowed roles, and production dual-approval requirements.
- Routing & Gateway now also supports decision-trace evidence retrieval via `GET /gateway/decision-traces/{trace_id}` for audit/logging investigation of action timelines and decision outcomes.
- Routing & Gateway also supports provider-priority readback and audit-backed priority timeline history (`/gateway/routes/{route_policy_id}/providers/priority/timeline`), plus cache stats, endpoint compatibility checks, and transform-debug requests.
- Key Lifecycle now supports explicit block and unblock actions for virtual keys in addition to create, update, usage inspection, rotation, guardrail evaluation, temporary budget increase requests/readback, and rotation schedule create/list/update/execute actions.
- Cost console supports request-tagged spend tracking ingestion, pricing catalog and pricing calculator workflows (custom LLM token pricing simulation and provider/model discount simulation), budget lifecycle create/list/edit/delete workflows with advanced controls (expanded scope types, reset timezone/hour, temporary increases, soft-alert toggle, rate/session caps), policy evaluation with effective-budget and soft-alert output, aggregated limit evaluation including agent IDs and soft-alert scopes, anomaly review, and session/agent cost drilldown workflows.
- Discovery console supports source sync, discovered-agent browsing, conflict triage, alert review, and promotion actions.
- Compliance console supports control coverage, evidence generation, evidence freshness, mapping CRUD, retention policies, and legal hold actions.
- Observability console supports trace lookup, log explorer deep filters (limit/offset/time window/action/resource/actor/outcome/trace/search), redact mode, schema-health checks, and row-level log-to-trace drilldown actions.
- Security view now supports session policy governance, SSO provider lifecycle (create/update/test/scim), governed session issue/get/reauth, and break-glass basic-auth controls.
- Security view includes role-binding validation plus explainability matrix workflow (`/auth/roles/bindings/validate`) and evidence drilldown via filtered audit events (`/audit/events`).
- Security view supports directory user/group/team CRUD and group/team membership management workflows.
- Security view user create/update includes password fields aligned to backend requirements.
- Account unlock is available from the Security view and calls backend API (`POST /auth/directory/users/{user_id}/unlock`) for admin operators.

## Port Mapping Quick Reference

1. Backend API port defaults to `8000` (change via backend `API_PORT`).
2. Frontend UI static port defaults to `4173` (change via `UI_PORT`).
3. In UI, update API Base URL to match backend port (for example `http://127.0.0.1:8001`).

## Default Error Pages

- Not found: `404.html`
- Service incident: `500.html`

These pages provide public-facing fallback guidance for invalid routes and service degradation scenarios.

## Security Checks

- Security checklist: `security-checklist.md`
- Accessibility conformance report: `accessibility-conformance-wcag22aa.md`
- Automated smoke checks:

   cd ../frontend
   bash scripts/security_smoke.sh
   bash scripts/gateway_governance_evidence_smoke.sh
   bash scripts/openai_gateway_ops_smoke.sh
   RUN_API_CHECKS=1 API_BASE=http://127.0.0.1:8000 bash scripts/gateway_governance_evidence_smoke.sh
   RUN_API_CHECKS=1 API_BASE=http://127.0.0.1:8000 bash scripts/openai_gateway_ops_smoke.sh

## Production Container Serve

The frontend now includes deployment artifacts for production serving without nginx:

- `frontend/Dockerfile`
- `frontend/scripts/serve_static.py`

The root-level production stack (`docker-compose.production.yml`) builds this image and serves UI on port `4173` by default.
