# API Inventory and UI Coverage Map

## Purpose

This document is the authoritative router-by-router inventory for the platform API surface and its current frontend coverage.
Canonical hierarchy and sync policy are defined in `backend/docs/governance/documentation-source-of-truth.md`.

## UI Surfaces

The frontend currently exposes these primary workspaces:

1. Overview
2. Agents
3. Playground
4. Benchmark and Scan
5. Routing and Gateway
6. Runtime Config
7. Providers
8. Modules
9. Agentic
10. Discovery
11. Cost
12. Audit
13. Compliance
14. Observability
15. Security

## Coverage Legend

- Full: primary operator workflow exists in the UI.
- Partial: only a subset of the API is represented in the UI.
- Gap: no UI workflow exists yet.

## API Inventory

### `app/routers/agents.py`

| Method | Route | UI Coverage | Notes |
|---|---|---|---|
| POST | `/agents` | Full | Covered by Agents workspace create/register flows. |
| POST | `/agents/register` | Full | Covered by Agents workspace create/register flows. |
| PATCH | `/agents/{agent_id}/owner` | Full | Covered by owner transfer actions in Agents workspace. |
| GET | `/agents/{agent_id}/ownership-history` | Full | Covered by ownership history table. |
| GET | `/owners/{owner_id}/agents` | Full | Covered by owner-scoped list. |

### `app/routers/agent_configs.py`

| Method | Route | UI Coverage | Notes |
|---|---|---|---|
| GET | `/agent-configs` | Full | Agent Configuration Studio list. |
| PUT | `/agent-configs/{agent_key}` | Full | Agent Configuration Studio save/edit. |
| DELETE | `/agent-configs/{agent_key}` | Full | Agent Configuration Studio delete. |

### `app/routers/runtime_config.py`

| Method | Route | UI Coverage | Notes |
|---|---|---|---|
| POST | `/runtime-config/validate` | Full | Runtime Config validation tools. |
| GET | `/runtime-config/validation-rules` | Full | Rules table with templates and validation. |
| GET | `/runtime-config` | Full | Runtime Config list. |
| PUT | `/runtime-config/{config_key}` | Full | Runtime Config upsert. |
| DELETE | `/runtime-config/{config_key}` | Full | Runtime Config delete. |

### `app/routers/auth.py`

| Method | Route | UI Coverage | Notes |
|---|---|---|---|
| GET | `/auth/policies/session` | Full | Security governance panel supports policy readback. |
| PATCH | `/auth/policies/session` | Full | Security governance panel supports policy updates. |
| GET | `/auth/policies/session/revisions` | Full | Security governance panel lists policy revisions. |
| POST | `/auth/policies/session/rollback` | Full | Security governance panel supports revision rollback. |
| POST | `/auth/sso/providers` | Full | Security SSO lifecycle panel supports provider create. |
| PATCH | `/auth/sso/providers/{provider_id}` | Full | Security SSO lifecycle panel supports provider update. |
| POST | `/auth/sso/providers/{provider_id}/test` | Full | Security SSO lifecycle panel supports provider validation test. |
| POST | `/auth/sso/providers/{provider_id}/scim/sync` | Full | Security SSO lifecycle panel supports SCIM sync action. |
| GET | `/auth/sessions/{session_id}` | Full | Security session governance panel supports session lookup. |
| POST | `/auth/sessions` | Full | Security session governance panel supports governed session issuance. |
| POST | `/auth/sessions/{session_id}/reauth` | Full | Security session governance panel supports reauth action. |
| POST | `/auth/roles/bindings/validate` | Full | Security view includes role-binding validation plus explainability matrix workflow. |
| POST | `/auth/basic/config` | Full | Security break-glass panel supports config creation. |
| PATCH | `/auth/basic/config/{config_id}` | Full | Security break-glass panel supports config updates. |
| POST | `/auth/basic/config/{config_id}/enable-temporary` | Full | Security break-glass panel supports temporary enable action. |
| POST | `/auth/basic/config/{config_id}/disable` | Full | Security break-glass panel supports disable action. |
| POST | `/auth/login` | Partial | Supported by UI sign-in panel. |
| POST | `/auth/directory/users` | Partial | Supported by Security view. |
| GET | `/auth/directory/users` | Partial | Supported by Security view. |
| PUT | `/auth/directory/users/{user_id}` | Partial | Supported by Security view. |
| DELETE | `/auth/directory/users/{user_id}` | Partial | Supported by Security view. |
| POST | `/auth/directory/users/{user_id}/unlock` | Partial | Supported by the Security view unlock action. |
| POST | `/auth/directory/groups` | Partial | Supported by Security view. |
| GET | `/auth/directory/groups` | Partial | Supported by Security view. |
| PUT | `/auth/directory/groups/{group_id}` | Partial | Supported by Security view. |
| DELETE | `/auth/directory/groups/{group_id}` | Partial | Supported by Security view. |
| POST | `/auth/directory/teams` | Partial | Supported by Security view. |
| GET | `/auth/directory/teams` | Partial | Supported by Security view. |
| PUT | `/auth/directory/teams/{team_id}` | Partial | Supported by Security view. |
| DELETE | `/auth/directory/teams/{team_id}` | Partial | Supported by Security view. |
| POST | `/auth/directory/groups/{group_id}/members/{user_id}` | Partial | Supported by Security view. |
| GET | `/auth/directory/groups/{group_id}/members` | Partial | Supported by Security view. |
| DELETE | `/auth/directory/groups/{group_id}/members/{user_id}` | Partial | Supported by Security view. |
| POST | `/auth/directory/teams/{team_id}/members/{user_id}` | Partial | Supported by Security view. |
| GET | `/auth/directory/teams/{team_id}/members` | Partial | Supported by Security view. |
| DELETE | `/auth/directory/teams/{team_id}/members/{user_id}` | Partial | Supported by Security view. |

### `app/routers/providers.py`

| Method | Route | UI Coverage | Notes |
|---|---|---|---|
| POST | `/providers/tenants` | Full | Tenant directory support in Providers view. |
| GET | `/providers/tenants` | Full | Tenant directory support in Providers view. |
| PUT | `/providers/tenants/{tenant_id}` | Full | Tenant directory edit in Providers view. |
| POST | `/auth/workload-identity/providers` | Partial | Provider onboarding form supported. |
| GET | `/auth/workload-identity/providers` | Partial | Provider list/filter supported. |
| POST | `/auth/workload-identity/token-exchange` | Partial | Providers view includes token exchange workflow. |
| POST | `/auth/workload-identity/providers/{provider_id}/validate-trust` | Full | Providers view includes trust validation workflow with evidence drilldown support. |
| GET | `/auth/workload-identity/providers/{provider_id}/health` | Full | Providers view includes health check workflow. |
| POST | `/auth/workload-identity/providers/{provider_id}/test` | Partial | Test action available in Providers view. |
| POST | `/secrets/providers` | Partial | Secret provider onboarding supported. |
| GET | `/secrets/providers` | Partial | Secret provider list supported. |
| POST | `/secrets/providers/{provider_id}/test` | Partial | Secret provider test supported. |
| GET | `/secrets/providers/{provider_id}/leases` | Full | Providers view includes active lease inventory workflow. |
| POST | `/secrets/providers/{provider_id}/leases/renew` | Full | Providers view includes secret lease renew workflow. |
| GET | `/secrets/providers/{provider_id}/health` | Full | Providers view includes secret provider health workflow. |
| POST | `/keys/{key_id}/rotate-via-secret-provider` | Partial | Providers view includes rotate-via-secret-provider workflow. |
| POST | `/providers/models` | Partial | Model catalog supported. |
| GET | `/providers/models` | Partial | Model catalog supported. |
| PUT | `/providers/models/{supported_model_id}` | Partial | Model edit supported. |
| DELETE | `/providers/models/{supported_model_id}` | Partial | Model delete supported. |
| POST | `/providers/tenant-model-entitlements` | Partial | Entitlement CRUD supported. |
| GET | `/providers/tenant-model-entitlements` | Partial | Entitlement list supported. |
| PUT | `/providers/tenant-model-entitlements/{tenant_model_entitlement_id}` | Partial | Entitlement edit supported. |
| DELETE | `/providers/tenant-model-entitlements/{tenant_model_entitlement_id}` | Partial | Entitlement delete supported. |

### `app/routers/discovery.py`

| Method | Route | UI Coverage | Notes |
|---|---|---|---|
| GET | `/discovery/sources` | Full | Discovery source inventory and sync health cards. |
| POST | `/discovery/sources/{source_id}/sync` | Full | Sync actions exposed in the Discovery sources table. |
| GET | `/discovery/agents` | Full | Discovery discovered-agents table. |
| GET | `/discovery/conflicts` | Full | Discovery conflict triage table. |
| GET | `/discovery/alerts` | Full | Discovery alert table. |
| GET | `/discovery/promote-queue` | Full | Discovery promote queue table. |
| POST | `/discovery/resolve` | Full | Discovery approve/reject buttons. |
| POST | `/discovery/promote/{discovered_agent_id}` | Full | Discovery promote action button. |

### `app/routers/cost.py`

| Method | Route | UI Coverage | Notes |
|---|---|---|---|
| GET | `/cost/live` | Partial | Overview spend cards and live cost summaries. |
| GET | `/cost/breakdown` | Partial | Spend vs hours chart. |
| GET | `/cost/timeseries` | Partial | Cost trends visible in overview views. |
| GET | `/cost/sessions/{session_id}` | Full | Cost drilldown panel supports session-cost events. |
| GET | `/cost/agents/{agent_id}` | Full | Cost drilldown panel supports agent-cost events. |
| POST | `/cost/events` | Full | Spend Tracking form supports request-tagged spend event ingestion with scoped authorization checks. |
| GET | `/cost/pricing/catalog` | Full | Pricing Calculator card supports pricing/discount catalog readback for operator review. |
| POST | `/cost/pricing/calculate` | Full | Pricing Calculator card supports token-cost and discount simulation for custom LLM pricing workflows. |
| GET | `/cost/budgets` | Full | Budget policy table supports active policy filters and displays advanced controls (reset timezone/hour, temporary increase, soft alerts, rate/session limits, effective budget). |
| POST | `/cost/budgets` | Full | Budget policy form supports policy creation with extended scope types (user/team/group/owner/actor/agent/environment) and advanced budget controls. |
| PUT | `/cost/budgets/{budget_policy_id}` | Full | Budget policy form supports lifecycle updates and advanced control edits via selected policy. |
| DELETE | `/cost/budgets/{budget_policy_id}` | Full | Budget policy table supports governed delete action. |
| POST | `/cost/policies/evaluate` | Full | Policy evaluation panel supports scope evaluation and shows effective budget plus soft-limit alert state for operator actioning. |
| GET | `/cost/anomalies` | Full | Cost anomaly table supports anomaly review including team soft-budget alert events. |
| POST | `/cost/limits/evaluate` | Full | Aggregated limit evaluation supports actor/team/group/agent inputs and renders effective budgets plus soft-alert scopes for governance triage. |

### `app/routers/audit.py`

| Method | Route | UI Coverage | Notes |
|---|---|---|---|
| GET | `/audit/events` | Full | Audit view supports recent events; Providers trust evidence and Security role-binding evidence drilldowns use filtered audit queries. |

### `app/routers/compliance.py`

| Method | Route | UI Coverage | Notes |
|---|---|---|---|
| GET | `/compliance/controls` | Full | Compliance coverage and control status cards. |
| GET | `/compliance/evidence/{control_id}` | Full | Compliance evidence panel for the selected control. |
| GET | `/compliance/controls/mappings` | Full | Compliance mapping table. |
| GET | `/compliance/controls/coverage` | Full | Compliance route coverage summary. |
| GET | `/compliance/controls/evidence-freshness` | Full | Compliance freshness table. |
| PUT | `/compliance/controls/mappings/{control_id}` | Full | Compliance mapping form save/edit. |
| POST | `/compliance/evidence/{control_id}/generate` | Full | Compliance evidence generation action. |
| GET | `/compliance/evidence/{control_id}/bundle` | Full | Compliance evidence bundle export. |
| GET | `/compliance/retention/policies` | Full | Compliance retention policy table. |
| POST | `/compliance/retention/policies` | Full | Compliance retention policy save form. |
| PATCH | `/compliance/retention/policies/{policy_id}` | Full | Compliance retention policy edit action. |
| GET | `/compliance/legal-holds` | Full | Compliance legal hold table. |
| POST | `/compliance/legal-holds` | Full | Compliance legal hold placement form. |
| POST | `/compliance/legal-holds/{hold_id}/release` | Full | Compliance legal hold release action. |

### `app/routers/gateway.py`

| Method | Route | UI Coverage | Notes |
|---|---|---|---|
| POST | `/keys` | Full | Covered by Key Lifecycle console. |
| GET | `/keys` | Full | Covered by Key Lifecycle console. |
| PATCH | `/keys/{key_id}` | Full | Covered by Key Lifecycle console. |
| POST | `/keys/{key_id}/rotate` | Full | Covered by Key Lifecycle console. |
| POST | `/keys/{key_id}/block` | Full | Key Lifecycle table supports explicit block action for virtual keys. |
| POST | `/keys/{key_id}/unblock` | Full | Key Lifecycle table supports explicit unblock action for virtual keys. |
| GET | `/keys/{key_id}/usage` | Full | Covered by Key Lifecycle console. |
| POST | `/keys/{key_id}/guardrails/evaluate` | Full | Covered by Key Lifecycle guardrail evaluation workflow. |
| POST | `/keys/{key_id}/budget/increase-temporary` | Full | Key Lifecycle supports temporary budget increase requests with environment-aware guardrails. |
| GET | `/keys/{key_id}/budget/increase-temporary` | Full | Key Lifecycle supports temporary budget increase readback. |
| POST | `/keys/{key_id}/rotation-schedules` | Full | Key Lifecycle supports creating key rotation schedules. |
| GET | `/keys/{key_id}/rotation-schedules` | Full | Key Lifecycle supports listing key rotation schedules. |
| PATCH | `/keys/{key_id}/rotation-schedules/{schedule_id}` | Full | Key Lifecycle supports schedule update actions (interval, enabled state, reason). |
| POST | `/keys/{key_id}/rotation-schedules/{schedule_id}/execute-now` | Full | Key Lifecycle supports immediate scheduled rotation execution. |
| GET | `/gateway/entitlements` | Full | Routing & Gateway entitlement card supports scoped entitlement list/filter readback. |
| PUT | `/gateway/entitlements/{entitlement_id}` | Full | Routing & Gateway entitlement card supports scoped entitlement upsert with production dual-approval behavior. |
| GET | `/gateway/nhi/inventory` | Full | Routing & Gateway NHI card supports inventory readback with tenant/source/provider/staleness filters. |
| GET | `/gateway/nhi/hygiene` | Full | Routing & Gateway NHI card supports hygiene summary metrics (stale, missing owner, high-risk, source distribution). |
| POST | `/gateway/access-reviews/campaigns` | Full | Routing & Gateway Access Reviews & JIT card supports campaign creation from scoped entitlement sets. |
| GET | `/gateway/access-reviews/campaigns/{campaign_id}` | Full | Routing & Gateway Access Reviews & JIT card supports campaign summary and review-item readback. |
| POST | `/gateway/jit-requests` | Full | Routing & Gateway Access Reviews & JIT card supports JIT access request creation with duration and justification. |
| POST | `/gateway/jit-requests/{request_id}/approve` | Full | Routing & Gateway Access Reviews & JIT card supports approve/deny workflow with prod dual-approval behavior. |
| GET | `/gateway/least-privilege/recommendations` | Full | Routing & Gateway least-privilege card supports recommendation readback with scope/type/status filters. |
| POST | `/gateway/least-privilege/recommendations/{recommendation_id}/apply` | Full | Routing & Gateway least-privilege card supports governed recommendation apply workflow. |
| POST | `/gateway/governance/evidence/export` | Full | Routing & Gateway governance evidence card supports filtered action-level evidence aggregation and export metadata generation for security/CISO review bundles. |
| POST | `/v1/chat/completions` | Full | Routing & Gateway OpenAI-compatible operator card supports governed chat-completions execution with model/message, stop, max-tokens, response-format controls, and response risk metadata (`risk_tier`, `risk_reasons`). |
| POST | `/v1/responses` | Full | Routing & Gateway OpenAI-compatible operator card supports responses create workflow with role-gated and audit-backed behavior, stop/max-output-tokens handling, response format controls, deterministic tools/tool-choice semantics, and response risk metadata (`risk_tier`, `risk_reasons`). |
| GET | `/v1/responses` | Full | Routing & Gateway OpenAI-compatible operator card supports lifecycle list/readback over active response records with audit evidence, plus server-side list filters (`model_contains`, `output_contains`) and pagination controls. |
| GET | `/v1/responses/{response_id}` | Full | Routing & Gateway OpenAI-compatible operator card supports lifecycle retrieval for response traceability and governance review. |
| DELETE | `/v1/responses/{response_id}` | Full | Routing & Gateway OpenAI-compatible operator card supports owner-or-admin soft-delete with object-level scope enforcement and production dual-approval headers. |
| POST | `/v1/files` | Full | Routing & Gateway OpenAI-compatible operator card supports role-gated file-record creation (metadata lifecycle) with audit evidence. |
| GET | `/v1/files` | Full | Routing & Gateway OpenAI-compatible operator card supports role-gated metadata listing for governance and operational readback, plus server-side list filters (`filename_contains`, `purpose`, `status`) and pagination controls. |
| GET | `/v1/files/{file_id}` | Full | Routing & Gateway OpenAI-compatible operator card supports role-gated metadata retrieval with audit evidence. |
| DELETE | `/v1/files/{file_id}` | Full | Routing & Gateway OpenAI-compatible operator card supports owner-or-admin soft-delete with object-level scope enforcement and production dual-approval headers. |
| POST | `/gateway/routes` | Full | Covered by Routing & Gateway console, including least-busy strategy and optional grouped weighted-failover definitions inside fallback policy JSON. |
| GET | `/gateway/routes` | Full | Covered by Routing & Gateway console. |
| POST | `/gateway/routes/{route_policy_id}/providers/priority` | Full | Covered by Routing & Gateway console, including optional request-tag scoped priority updates. |
| GET | `/gateway/routes/{route_policy_id}/providers/priority` | Full | Route priority readback table is surfaced in Routing & Gateway, including optional request-tag scoped lookup. |
| PUT | `/gateway/routes/{route_policy_id}/fallbacks` | Full | Dedicated fallback-management endpoint for route-level fallback policy updates (timeouts, hops, health-check and budget controls). |
| GET | `/gateway/routes/{route_policy_id}/fallbacks` | Full | Dedicated fallback-management endpoint readback with optional request-tag scoped policy lookup. |
| PUT | `/gateway/routes/{route_policy_id}/pre-call-filters` | Full | Routing & Gateway supports route-scoped pre-call filter controls for region and context-window guardrails. |
| GET | `/gateway/routes/{route_policy_id}/pre-call-filters` | Full | Routing & Gateway supports pre-call filter readback with optional request-tag scoped lookup. |
| PUT | `/gateway/routes/{route_policy_id}/traffic-mirroring` | Full | Routing & Gateway supports governed traffic mirroring target configuration for shadow/observe experiments. |
| GET | `/gateway/routes/{route_policy_id}/traffic-mirroring` | Full | Routing & Gateway supports traffic mirroring policy readback with optional request-tag scoped lookup. |
| GET | `/gateway/routes/{route_policy_id}/traffic-mirroring/analytics-summary` | Full | Routing & Gateway mirror analytics card provides route-scoped summary distribution views (providers, modes, regions, and outcome comparison). |
| GET | `/gateway/routes/{route_policy_id}/traffic-mirroring/experiment-report` | Full | Routing & Gateway mirror analytics card provides event-level experiment report with pagination filters. |
| PUT | `/gateway/routes/{route_policy_id}/providers/health` | Full | Provider health-state management endpoint used for health-check driven routing. |
| GET | `/gateway/routes/{route_policy_id}/providers/health` | Full | Provider health-state readback endpoint with optional request-tag scoped lookup. |
| GET | `/gateway/routes/{route_policy_id}/providers/priority/timeline` | Full | Route priority timeline table is surfaced in Routing & Gateway with limit/offset filters. |
| POST | `/gateway/routes/{route_policy_id}/simulate-fallback` | Full | Covered by Routing & Gateway console, including optional request-tag scoped fallback simulation and grouped weighted-failover traversal. |
| POST | `/gateway/routes/{route_policy_id}/execute-fallback` | Full | Covered by Routing & Gateway console, including optional request-tag scoped provider selection during fallback execution, grouped weighted-failover traversal, and error-type retry/cooldown policy enforcement. |
| POST | `/gateway/routes/{route_policy_id}/optimize` | Full | Covered by Routing & Gateway console. |
| POST | `/gateway/cache/policies` | Full | Routing & Gateway includes cache policy create workflow. |
| GET | `/gateway/cache/policies` | Full | Routing & Gateway includes cache policy list/filter workflow. |
| GET | `/gateway/cache/stats` | Full | Gateway controls panel shows cache stats. |
| GET | `/gateway/cache/health` | Full | Gateway controls panel shows cache health diagnostics for the policy-managed cache surface. |
| POST | `/gateway/cache/delete` | Full | Routing & Gateway exposes audit-backed cache invalidate requests by scope or explicit cache keys. |
| GET | `/gateway/analytics/summary` | Full | Cost workspace gateway analytics card. |
| GET | `/gateway/endpoints/compatibility` | Full | Gateway controls panel shows compatibility status. |
| GET | `/gateway/mcp/servers` | Full | Routing & Gateway includes approved MCP server registry readback. |
| POST | `/gateway/mcp/servers/{server_id}/tools/list` | Full | Routing & Gateway includes MCP tool catalog listing per approved server. |
| POST | `/gateway/mcp/servers/{server_id}/tools/call` | Full | Routing & Gateway includes governed MCP tool execution workflow. |
| GET | `/gateway/external-callbacks` | Full | Routing & Gateway external callback registry list workflow. |
| POST | `/gateway/external-callbacks` | Full | Routing & Gateway supports governed callback registry create workflow with environment controls. |
| PATCH | `/gateway/external-callbacks/{callback_id}` | Full | Routing & Gateway supports callback update/toggle controls. |
| POST | `/gateway/external-callbacks/{callback_id}/test-delivery` | Full | Routing & Gateway supports simulated callback delivery tests with optional payload redaction. |
| POST | `/gateway/external-callbacks/export` | Full | Routing & Gateway supports callback evidence export summary workflow. |
| POST | `/gateway/authz/explain` | Full | Routing & Gateway exposes explicit authorization explainability for gateway action simulations (decision, trace, role and dual-approval requirements). |
| GET | `/gateway/decision-traces/{trace_id}` | Full | Routing & Gateway exposes trace-level audit evidence readback for operator/security investigations (event timeline with action, resource, outcome, and policy metadata). |
| POST | `/gateway/debug/transform-request` | Full | Gateway controls panel supports transform debug action. |

### `app/routers/modules.py`

| Method | Route | UI Coverage | Notes |
|---|---|---|---|
| POST | `/modules/register` | Full | Modules console supports secure module registration. |
| GET | `/modules` | Full | Modules console supports module catalog listing. |
| GET | `/modules/{module_id}/versions` | Full | Modules console supports version lookup workflow. |
| POST | `/agents/{agent_id}/modules/validate` | Full | Modules console supports agent-module validation workflow. |
| POST | `/agents/{agent_id}/modules/upgrade-plan` | Full | Modules console supports upgrade-plan workflow. |
| POST | `/modules/{module_id}/deprecate` | Full | Modules console supports governed module deprecation. |

### `app/routers/observability.py`

| Method | Route | UI Coverage | Notes |
|---|---|---|---|
| GET | `/observability/traces/{trace_id}` | Full | Trace lookup form supports direct trace investigation with summary/detail table. |
| GET | `/observability/logs` | Full | Log explorer supports deep filters (limit/offset/window/action/resource/actor/outcome/trace/search), redact mode, and row-level trace drilldown action. |
| GET | `/observability/logs/schema-status` | Full | Schema health summary and missing-field table are visible in Observability console. |

### `app/routers/playground.py`

| Method | Route | UI Coverage | Notes |
|---|---|---|---|
| POST | `/playground/runs` | Full | Covered by Playground Studio multimodal prompt runs. |
| GET | `/playground/runs` | Full | Covered by Playground run history browser. |
| GET | `/playground/runs/{run_id}` | Full | Covered by the selected run detail loader in Playground history. |
| POST | `/playground/compare` | Full | Covered by Judge Prompt. |
| POST | `/playground/runs/{run_id}/route-draft` | Full | Covered by Draft action from the latest run table. |
| GET | `/playground/test-sets` | Full | Covered by Load Test Sets. |

### `app/routers/benchmark_scan.py`

| Method | Route | UI Coverage | Notes |
|---|---|---|---|
| POST | `/benchmarks/run` | Full | Covered by Benchmark & Scan console. |
| GET | `/benchmarks/runs` | Full | Covered by Benchmark & Scan historical browser and trend summary workflow. |
| POST | `/scans/run` | Full | Covered by Benchmark & Scan console. |
| GET | `/scans/runs` | Full | Covered by Benchmark & Scan historical browser and trend summary workflow. |

### `app/routers/route_drafts.py`

| Method | Route | UI Coverage | Notes |
|---|---|---|---|
| GET | `/route-drafts` | Full | Covered by route draft list and filter workflow. |
| GET | `/route-drafts/{draft_id}/approval-history` | Full | Covered by approval and rollback history table. |
| POST | `/route-drafts/{draft_id}/submit` | Full | Covered by route draft action form. |
| POST | `/route-drafts/{draft_id}/approve` | Full | Covered by route draft action form. |
| POST | `/route-drafts/{draft_id}/reject` | Full | Covered by route draft action form. |
| POST | `/route-drafts/{draft_id}/approve-change-window` | Full | Covered by route draft action form. |
| POST | `/route-drafts/{draft_id}/promote` | Full | Covered by route draft action form. |
| POST | `/route-drafts/{draft_id}/rollback-to-draft` | Full | Covered by route draft action form. |
| POST | `/route-drafts/{draft_id}/rollback-last-good` | Full | Covered by route draft action form. |

### `app/routers/agentic.py`

| Method | Route | UI Coverage | Notes |
|---|---|---|---|
| POST | `/agentic/contracts/validate` | Full | Agentic console supports contract validation workflow. |
| GET | `/agentic/readiness/report` | Full | Agentic console supports readiness reporting workflow. |
| POST | `/agentic/readiness/certifications/run` | Full | Agentic console supports certification run workflow. |
| POST | `/agentic/readiness/certifications/{certification_id}/override` | Full | Agentic console supports certification override workflow. |
| GET | `/agentic/readiness/certifications/latest` | Full | Agentic console supports latest certification read. |
| GET | `/agentic/readiness/certifications` | Full | Agentic console supports certification listing. |
| GET | `/agentic/readiness/certifications/{certification_id}/export` | Full | Agentic console supports certification export workflow. |
| POST | `/agentic/checkpoints` | Full | Agentic console supports checkpoint creation workflow. |
| POST | `/agentic/readiness/load-tests/run` | Full | Agentic console supports scale load-test run workflow. |
| GET | `/agentic/readiness/load-tests/latest` | Full | Agentic console supports latest load-test readback. |
| GET | `/agentic/checkpoints/{session_id}` | Full | Agentic console supports checkpoint listing by session. |
| POST | `/agentic/checkpoints/{checkpoint_id}/resume` | Full | Agentic console supports checkpoint resume workflow. |
| POST | `/agentic/policy/auto-tune` | Full | Agentic console supports auto-tune run workflow. |
| POST | `/agentic/policy/scheduled-optimize` | Full | Agentic console supports scheduled-optimize execution workflow. |
| POST | `/agentic/policy/schedules` | Full | Agentic console supports schedule creation workflow. |
| GET | `/agentic/policy/schedules` | Full | Agentic console supports schedule listing workflow. |
| GET | `/agentic/policy/schedules/summary` | Full | Agentic console supports schedule summary filters/readback. |
| GET | `/agentic/policy/schedules/{job_id}` | Full | Agentic console supports schedule detail readback workflow. |
| GET | `/agentic/policy/schedules/{job_id}/status` | Full | Agentic console supports schedule status workflow. |
| PATCH | `/agentic/policy/schedules/{job_id}` | Full | Agentic console supports schedule update workflow. |
| POST | `/agentic/policy/schedules/{job_id}/enable` | Full | Agentic console supports schedule enable action. |
| POST | `/agentic/policy/schedules/{job_id}/disable` | Full | Agentic console supports schedule disable action. |
| POST | `/agentic/policy/schedules/{job_id}/approve` | Full | Agentic console supports schedule approval action. |
| POST | `/agentic/policy/schedules/{job_id}/execute-now` | Full | Agentic console supports schedule execute-now action. |
| GET | `/agentic/policy/schedules/{job_id}/history` | Full | Agentic console supports schedule history review. |
| DELETE | `/agentic/policy/schedules/{job_id}` | Full | Agentic console supports schedule delete action. |

## Summary of High-Coverage Areas

The UI is strongest today in these API groups:

1. Agent registration and ownership
2. Agent runtime config
3. Global runtime config
4. Providers and tenant/model administration
5. Modules lifecycle operations
6. Route draft approval and promotion workflows
7. Security sign-in and directory IAM workflows
8. Audit and observability summaries

## Summary of Gaps

The largest remaining UI gaps are:

1. Cost analytics historical trend depth
