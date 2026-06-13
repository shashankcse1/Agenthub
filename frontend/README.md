# Frontend UI (No-Build)

This is a static SPA control surface for the backend API.

## Architecture

The UI is split into a lightweight shell plus view/component modules (still no build step):

1. `index.html` — app shell (sidebar, header, session context, view mount)
2. `views/*.html` — one file per console view (`overview`, `routing-gateway`, `playground`, etc.)
3. `js/constants.js` — shared actor roles, API limits, view names, and UI coverage keys
4. `js/api-cache.js` — dedupes concurrent boot-time GETs for `/runtime-config` and `/governance/ui-coverage/inventory`
5. `js/api-client.js` — centralized request header construction and role normalization
6. `js/ui-coverage.js` — UI coverage inventory load, Gap endpoint gate, and Overview/Compliance render helpers
7. `js/platform-status.js` — operational posture polling; maintenance, downtime, and slow-performance banners
8. `js/operator-feedback.js` — feedback capture panel, analytics breakdowns, and report triage actions
9. `js/view-loader.js` — loads and mounts view partials into `#viewsRoot`
10. `js/ui-kit.js` — shared operator UI helpers (structured results, toasts, tab groups)
11. `styles/components.css` — component-level layout and result panel styling
12. `app.js` — API wiring, event bindings, and workflow logic (delegates to component modules above)

Routing & Gateway uses an internal console layout:

- **Workspace** — Cursor integration, token config, inference ops
- **Routes & Keys** — route policies, key lifecycle, drafts, fallback priority chain builder
- **Policies** — guardrails, mirroring, cache, MCP, callbacks
- **Memory & Context** — **Platform Configuration** card (memory TTL/limits, semantic cache defaults, vector store registry and **notification channel registry** via `/gateway/memory/config`, `/gateway/vector-stores*`, `/gateway/notification-channels*`, runtime config PUT; **PII classification** and **live probe** toggles); **RAG Ingest & Query** panel (`POST /rag/ingest`, `POST /rag/query` for mcp_bridge stores); semantic cache posture, short/long-term memory CRUD (`/gateway/memory/*`), checkpoints, realtime sessions, production long-term dual-approval on create/delete
- **Governance** — entitlements, NHI hygiene, access reviews, evidence

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

- Overview includes quick-start chips for priority consoles (Playground, Benchmark & Scan, Routing & Gateway, **Memory & Context**, Compliance, Observability).
- Each view shows a short subtitle under the page title to clarify the operator workflow.
- Session Context is collapsible in the sidebar; use **Save Context** after changing profile, API base, or actor settings (available while signed in).
- On mobile/tablet widths, open navigation with the header menu button; sidebar quick-find is hidden when header search is available.
- API base URL and actor context can be changed from the left settings panel.
- UI server port can be changed with `UI_PORT` or `--port` in `scripts/run_ui.sh`.
- Backend API base can be changed per profile from the UI settings panel.
- UI provides pages for Overview, Agents, Playground, Benchmark & Scan, Routing & Gateway, **Flow Orchestration**, Runtime Config, Providers, Modules, Agentic, Discovery, Cost, Audit, Compliance, Observability, Security, and Browser Security (GuardBridge).
- **Flow Orchestration** (Operations nav) covers `/orchestration/*` workflows in **Flow Studio**: guided workflow strip (Create → Build → Save → Check → Run), tabbed sidebar (**Flows** with search/scroll | **Toolkit** with drag/select), widget category chips, and an extensible catalog in `js/orchestration-registry.js`. Vertical **Start → widgets → End** lane canvas with **parallel groups** (fork/join, side-by-side branches, add/remove branch controls); canvas summary strip shows step and parallel counts. **If / else** and **Approval** inspectors support JSON-path fields from prior steps (config persisted; live runtime resolution is Phase 2). **Vector search** and **Vector ingest** widgets in the Memory & vectors toolkit category include a gateway registry picker (`GET /gateway/vector-stores`) with link to Routing & Gateway for store setup. **Send email** and **Send SMS** widgets in the **Notify** category use `GET /gateway/notification-channels` channel picker (Phase 1 simulated delivery). Settings panel with fieldsets, run history drawer, toolbar with zoom/save/check/test/run. Template picker for common flows. **Approvals** tab with Production queue shortcut and dual-approval co-sign. Backend validates and stub-executes `parallel_fork` / `parallel_join` graphs (2–5 branches, `asyncio.gather` in dry run), `vector_query` / `vector_ingest` / `rag_query` nodes against `gateway.vector_stores_json`, and `email_send` / `sms_send` against `gateway.notification_channels_json`. **Ask AI** (`llm_chat`) supports optional gateway route, prompt registry ref, max tokens, response format, and cache mode. Additional LiteLLM-aligned widgets: **Embeddings** (`embedding_create`), **RAG query** (`rag_query`), **Wait** (`wait_delay`), and **Guardrail check** (`guardrail_evaluate`) — Phase 1 stub execution only.
- Browser Security (GuardBridge) includes governed workflows for extension telemetry and policy operations: `/browser/extensions/events`, `/browser/extensions/sessions`, `/browser/extensions/shadow-ai/apps`, `/browser/risk-policies`, `/browser/extensions/risk/summary`, `/browser/analytics`, and `/browser/extensions/incidents/export`.
- Extension packaging scaffold for cross-browser GuardBridge builds lives under `../extensions/guardbridge/` (Chromium MV3, Firefox variant, Safari conversion notes).
- UI includes a tabbed **Providers Console** (Overview, Tenants, Workload Identity, Secret Providers, Models & Entitlements) with workflow guidance, field references, and live inventory summary counts.
- Providers covers tenant directory (`/providers/tenants`), including **Deactivate/Reactivate** via `status: inactive|active` (no hard delete), workload identity onboarding and trust (`/auth/workload-identity/*`), secret providers (`db`, Vault, AWS, Azure) with generic **Store Secret Value** for db providers (`PUT/GET/DELETE /secrets/providers/{id}/values`) including vendor ref templates (`gateway/cursor-token`, `providers/openai/api-key`, etc.), **Credential Setup Guide** (three-layer taxonomy: secret backend → AI provider → model ID), credential bindings (`/providers/credential-bindings`), gateway cursor secret binding (`/gateway/cursor-secret-binding`), lease/health (`/secrets/providers/*`), token exchange, key rotate-via-secret-provider (`/keys/{key_id}/rotate-via-secret-provider`), supported models catalog, and tenant model entitlements.
- UI separates **secret backend type** (`db`/Vault/AWS/Azure — where keys live) from **AI provider** (OpenAI/Anthropic/Cursor — who issues the API key) from **model ID** (e.g. `gpt-4o-mini` — registered in Models & Entitlements). Credential bindings and Store Secret Value use AI provider; Onboard Secret Provider uses secret backend type only.
- **Secret backend** pickers (Store Secret Value, Gateway Cursor binding, credential bindings, lease/health) are dropdowns (`data-secret-backend-select`) populated from `GET /secrets/providers?status=active` — operators never copy provider IDs from the table. Store Secret Value and credential bindings require **tenant selection first**; backends filter to that tenant. Auto-select applies only when exactly one backend matches.
- **Super Admin** and **Master Admin** can store secrets and save credential/gateway bindings without production dual-approval co-sign; the UI uses the signed-in session role (not a hardcoded Platform Admin). Platform Admin still requires Security Approver co-sign in prod; Security Approver may co-sign with Platform Admin or Super Admin.
- **Workload profile** pickers (credential bindings workload plane, trust/health/exchange forms) use `data-workload-profile-select` from `GET /auth/workload-identity/providers?status=active`, tenant-scoped the same way.
- **Credential Bindings** consumer key dropdown loads agents (`GET /agent-configs`), routes (`GET /gateway/routes`), or fixed gateway/platform keys by consumer type; secret path uses the same template list as Store Secret Value (with custom path option); environment is dev/staging/prod select.
- Workload identity onboarding documents AI vendor env injection (`{VENDOR}_WORKLOAD_IDENTITY_ACCESS_TOKEN`) vs db secret storage. Agents and Playground link to Providers credential setup and show gateway binding readiness.
- Providers view also includes trust validation (`/auth/workload-identity/providers/{provider_id}/validate-trust`), trust evidence drilldown via filtered audit events (`/audit/events`), workload identity health checks (`/auth/workload-identity/providers/{provider_id}/health`), secret lease inventory (`/secrets/providers/{provider_id}/leases`), secret lease renewal (`/secrets/providers/{provider_id}/leases/renew`), and secret provider health checks (`/secrets/providers/{provider_id}/health`).
- Each major console uses the **Providers-style runtime shell**: hero card, inventory summary, page Search/Clear toolbar, tabbed workspaces, and per-table Search/Clear controls (auto-injected via `frontend/js/table-search.js` where not already present).
- Tabbed consoles: Providers, Modules, Agents, Playground, Benchmark & Scan, Agentic, Discovery, Cost, Audit, Compliance, Runtime Config, Routing & Gateway, GuardBridge, Security, Observability.
- Modules Console covers secure module lifecycle operations (`/modules/register`, `/modules`, `/modules/{module_id}/versions`, `/agents/{agent_id}/modules/validate`, `/agents/{agent_id}/modules/upgrade-plan`, and `/modules/{module_id}/deprecate`).
- Modules Console hero search and per-table Search/Clear controls filter the module catalog and AI skills inventory.
- Modules view includes an AI Skills Registry (`GET /modules/skills`) for skill-focused module inventory (`ai_skill`/`skill`) and operator review.
- Modules view includes integration metadata fields (`integration_provider`, `integration_reference`, `integration_sync_status`, `integration_last_synced_at`) and a governed integration sync action (`POST /modules/{module_id}/integration/sync`) for integration-enabled modules.
- Cursor integration setup and security runbook is documented in `../docs/cursor-integration-operator-guide.md`.
- UI includes an Agentic view for readiness and scheduling operations (`/agentic/readiness/report`, `/agentic/contracts/validate`, `/agentic/readiness/certifications/run`, `/agentic/readiness/certifications`, `/agentic/readiness/certifications/latest`, `/agentic/policy/auto-tune`, and `/agentic/policy/schedules*` actions).
- Agentic view also supports direct scheduled optimize execution (`/agentic/policy/scheduled-optimize`) and schedule summary/detail/update workflows (`/agentic/policy/schedules/summary`, `/agentic/policy/schedules/{job_id}`, `/agentic/policy/schedules/{job_id}` PATCH).
- Agentic advanced operations now include certification override/export (`/agentic/readiness/certifications/{certification_id}/override`, `/agentic/readiness/certifications/{certification_id}/export`), load-test run/latest (`/agentic/readiness/load-tests/run`, `/agentic/readiness/load-tests/latest`), and checkpoint create/list/resume (`/agentic/checkpoints`, `/agentic/checkpoints/{session_id}`, `/agentic/checkpoints/{checkpoint_id}/resume`).
- UI provides a Runtime Config page for database-backed operator settings such as gateway timeout and workload identity defaults.
- Runtime Config page includes a searchable Rule Catalog table sourced from `/runtime-config/validation-rules`, plus key-specific inline hints in the save form.
- Super Admins can add, edit, or delete custom catalog rules via `POST/PUT/DELETE /runtime-config/validation-rules`; built-in rules can be updated but not deleted.
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
- Overview and Compliance expose live API UI coverage gap reports via `GET /governance/ui-coverage` (Partial/Gap/undocumented backend routes). The frontend loads `GET /governance/ui-coverage/inventory` at boot and blocks `api()` calls to inventory rows marked `Gap` until an operator workflow exists.
- **Platform operator experience:** global banners; **`POST /platform/feedback` saves to PostgreSQL `operator_feedback`** (audited); Overview loads list/analytics from DB; triage via `POST /platform/feedback/{id}/actions`. See `documentation-source-of-truth.md` § REST API Observability Standards for audit action types.
- **Lazy view loading:** only Overview is mounted at boot; other consoles hydrate on first nav visit (`view-loader.js`) to reduce startup API load and memory use.
- UI view visibility can be controlled from runtime config using `ui.feature.<view>.enabled` or environment-specific keys like `ui.feature.discovery.enabled.prod`.
- The same studio supports provider priority, fallback hops/timeouts, retry budget, and circuit-breaker thresholds per agent.
- Security review checks are available in the UI for AWS/cloud fallback posture, production safety thresholds, and fallback resilience.
- CISO/audit evidence bundle export is available as JSON and includes findings, reviewer context, and serialized config state.
- Agent configurations can be exported/imported as JSON for portable, reviewable change bundles.
- Backend endpoint access follows existing role checks; use appropriate actor role in the UI context.
- UI sign-in uses backend credential validation (`POST /auth/login`) and receives bearer session tokens.
- Backend enforces password-login lockout policy with runtime-configurable controls (`auth.login.max_failed_attempts`, `auth.login.lockout_minutes`).
- Playground Studio supports text prompts, voice/video attachments, microphone capture, live stream preview, prompt registry CRUD/version history/rollback, governed prompt promotion with render-preview validation (including production dual-approval headers), trace-linked run feedback, a quality triage queue for low-score outputs, long-window quality analytics rollups by provider/route/model, SLA-tracked quality escalation lifecycle (create/list/acknowledge/resolve/notify), judge/retry actions, route-draft creation, and run history browsing.
- Benchmark & Scan supports benchmark and scan execution, plus filtered history browsing and trend summaries backed by `/benchmarks/runs` and `/scans/runs`.
- Routing & Gateway supports route policy create/list, priority updates (including request-tag scoped priority), fallback simulation/execution (including request-tag based routing behavior), route optimization, route draft list/history browsing, draft lifecycle actions (submit/approve/reject/change-window/promote/rollback), and key lifecycle management.
- Routing & Gateway includes managed baseline system controls for OpenAI-compatible responses (`GET/PUT /gateway/system-instructions`, `GET/PUT /gateway/system-rules`) with scoped rule classification support (`global|user|team|group|owner|actor|agent`).
- Routing & Gateway includes a Cursor Gateway Integration hub with secret-binding status, operation-family matrix, and quick navigation across Core/Media/Transport/Lifecycle gateway ops panels.
- Routing & Gateway Cursor integration now points operators to **Providers → Secret Providers → Store Secret Value** for unified secret storage (`db` or external backends) and gateway binding (`GET/PUT/DELETE /gateway/cursor-secret-binding`). Legacy `/gateway/cursor-token` remains API-compatible but deprecated. Generic provider review: `backend/docs/governance/generic-provider-configuration-review-and-impact-analysis.md`. CISO gap analysis: `backend/docs/governance/unified-secret-provider-ciso-gap-analysis.md`.
- Cursor-backed gateway operation families are exposed in Routing & Gateway tabs: Core (`/v1/chat/completions`, `/v1/embeddings`, `/v1/responses`), Media (`/v1/audio/transcriptions`, `/v1/audio/translations`, `/v1/images`, `/v1/realtime`), Transport (`/v1/messages`, `/v1/a2a/messages`, `/v1/rerank`), and Lifecycle (`/v1/responses*`, `/v1/files*`, `/v1/realtime/sessions*`).
- Overview includes a **Cursor Gateway** quick-start chip that opens the integration hub directly.
- Cursor Gateway Integration hub includes copy-ready automation recipes (curl, Python, TypeScript OpenAI-client base URL) generated from current operator session context.
- OpenAI-Compatible Gateway Ops includes a **Cursor / configured model** picker; selecting a model applies it to all gateway ops model dropdowns on the active tab.
- OpenAI-Compatible Gateway Ops model fields and Playground selected/candidate models use **catalog-backed dropdowns** populated from the canonical platform register (`GET /providers/models/available`) on sign-in and via **Load Configured Models** in Routing & Gateway.
- Providers **Models** tab includes a **UI Model Availability Register** (policy echo + ranked model list) for verifying which models appear in all UI dropdowns; enable/disable models via Supported Models Catalog `status` (`active`/`beta` vs `disabled`/`deprecated`).
- Tenant ID fields across Routing & Gateway, Providers, Security, Agents, and Compliance now use catalog-backed dropdowns (`data-tenant-select`) populated from `GET /providers/tenants`; optional filters include an **All tenants** blank option. The Tenant Directory create/edit form keeps a free-text Tenant ID input for registering new tenants.
- Route Priority now shows a Policy Scope indicator in the UI so operators can confirm whether the loaded policy is default or request-tag scoped.
- Route Priority includes a visual fallback-chain builder: add/remove/reorder provider+model targets (priority 1, 2, 3…), provider datalist from workload/secret providers, **model dropdown from supported-model catalog**, live validation against backend `priority_order` schema, and optional advanced JSON editing.
- Route create includes an optional Initial Fallback Chain builder that embeds ordered targets into `fallback_policy.provider_priority` on submit.
- Routing & Gateway now includes adaptive load-balancing selection plus explicit lowest-cost, lowest-latency, and least-busy route strategies in route create workflows.
- Route Priority supports health-check routing and optional budget limits, and Fallback Execution supports request-priority tiers (`low|normal|high`).
- Route fallback policy JSON supports optional `routing_groups` with per-group strategy and `failover_weight` to model weighted failover between deployment groups.
- Route retry policy JSON supports `error_type_policies` with per-error `max_retries` and `cooldown_seconds`; execution enforces these controls and records cooldown-aware skip outcomes.
- Pre-Call Filters card supports route-scoped region/context-window guardrails via `PUT/GET /gateway/routes/{route_policy_id}/pre-call-filters` (including optional request-tag scoped policies).
- Input Data Policy card supports route-scoped input policy controls via `PUT/GET /gateway/routes/{route_policy_id}/input-data-policy` with `allow|warn|block|mask` modes, data-class policy classes (`standard|sensitive|pii|phi|secret`), pattern controls, optional request-tag scope, and production dual-approval semantics.
- Output Guardrails card supports route-scoped output policy controls via `PUT/GET /gateway/routes/{route_policy_id}/output-guardrails` with `allow|warn|block|transform` modes, phrase controls, token ceilings, optional request-tag scope, and production dual-approval semantics.
- Traffic Mirroring card supports shadow/observe mirror target configuration via `PUT/GET /gateway/routes/{route_policy_id}/traffic-mirroring` (including optional request-tag scoped policies).
- Canary Rollout Lifecycle card supports governed weighted canary configuration/readback and explicit stop/promote actions via `PUT/GET /gateway/routes/{route_policy_id}/canary-rollout`, `POST /gateway/routes/{route_policy_id}/canary-rollout/stop`, and `POST /gateway/routes/{route_policy_id}/canary-rollout/promote` (including optional request-tag scoped policies, cohort selectors, automatic success/failure gate controls, and production dual-approval semantics).
- Mirror Analytics card supports route-scoped mirroring summary and experiment reporting via `GET /gateway/routes/{route_policy_id}/traffic-mirroring/analytics-summary` and `GET /gateway/routes/{route_policy_id}/traffic-mirroring/experiment-report`.
- Gateway Entitlements card supports scoped action-grant list/filter and upsert workflows via `GET /gateway/entitlements` and `PUT /gateway/entitlements/{entitlement_id}`.
- NHI Inventory & Hygiene card supports machine-identity inventory and hygiene review via `GET /gateway/nhi/inventory` and `GET /gateway/nhi/hygiene`.
- Access Reviews & JIT card supports campaign create/read workflows via `POST /gateway/access-reviews/campaigns` and `GET /gateway/access-reviews/campaigns/{campaign_id}`, plus JIT request create/approve workflows via `POST /gateway/jit-requests` and `POST /gateway/jit-requests/{request_id}/approve`.
- Least-Privilege Recommendations card supports recommendation read/apply workflows via `GET /gateway/least-privilege/recommendations` and `POST /gateway/least-privilege/recommendations/{recommendation_id}/apply`.
- Gateway Governance Evidence card supports filtered gateway-governance evidence aggregation/export via `POST /gateway/governance/evidence/export`, with backend-generated JSON bundle metadata and action-level summaries.
- OpenAI-Compatible Gateway Ops card now supports governed `POST /v1/chat/completions`, `POST /v1/responses`, and `POST /v1/realtime` (with SSE streaming lifecycle visibility when `stream=true` plus stream policy controls for binary mode, max event bytes, and heartbeat interval), `POST /v1/embeddings`, responses lifecycle (`POST/GET/GET{id}/DELETE{id} /v1/responses`), and files metadata lifecycle (`POST/GET/GET{id}/DELETE{id} /v1/files`) workflows directly from the Routing & Gateway view, including server-backed list filters and client-side advanced filtering + bulk delete operations for responses/files records.
- OpenAI-Compatible Gateway Ops now includes dedicated realtime session lifecycle UI controls for `GET /v1/realtime/sessions`, `GET /v1/realtime/sessions/{session_id}`, `GET /v1/realtime/sessions/{session_id}/events`, `POST /v1/realtime/sessions/{session_id}/events`, and `POST /v1/realtime/sessions/{session_id}/close`, including owner-scope enforcement behavior, event timeline readback for investigations, session counters (`event_count`, `total_event_bytes`), stream policy checks (per-event and per-session limits), expired-session ingest blocking, and production dual-approval headers for inline-binary operations.
- Realtime stream policy controls now also include inline-binary governance depth: dedicated inline event byte cap, inline event-type allowlist, and optional correlation-id requirement for inline payloads, with enforcement on session-event ingest.
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
- Routing & Gateway also supports cache policy create/list workflows (`/gateway/cache/policies`) with exact/semantic mode, similarity-threshold controls, privacy-scope selection, and explicit non-cache data-class policy controls, in addition to cache stats and compatibility checks.
- Routing & Gateway also supports cache health diagnostics (`/gateway/cache/health`) and audit-backed cache invalidate requests (`/gateway/cache/delete`), including semantic-policy counts and average similarity threshold readback.
- Routing & Gateway also supports cache decision timeline readback (`/gateway/cache/decisions`) with trace/tenant/decision filters, hit/miss/bypass explanation fields, semantic similarity score, request fingerprints, and source-request provenance details for operator and security investigation.
- Routing & Gateway **Memory & Context** tab includes a **Platform Configuration** card to load/save tunable memory, semantic cache default, **inference short-circuit toggle** (`gateway.cache.inference_short_circuit_enabled`, default off, dual-approval to enable), **PII classification toggle** (`gateway.memory.pii_classification_enabled`, default off), **vector live probe toggle** (`gateway.vector_stores.live_probe_enabled`, default off), and vector store registry settings (`GET /gateway/memory/config`, runtime config keys under `gateway.memory.*`, `gateway.cache.default_*`, `gateway.vector_stores*`) with vector store health checks and **Apply Cache Defaults to Policy Form**; **RAG Ingest & Query** panel exercises `POST /rag/ingest` and `POST /rag/query` for mcp_bridge stores; also covers semantic cache posture plus short-term/long-term memory record CRUD (`/gateway/memory/overview`, `/gateway/memory/records*`) with 16 KiB content cap, per-scope limits, short-term TTL, Agent Owner scoping, and production long-term dual-approval on create/delete; checkpoint lookup by session (`/agentic/checkpoints/{session_id}`), realtime session list, and shortcuts to system rules and responses archives; **Verification Scenarios** card runs MC-* and CA-* suites in-console (including MC-06 platform config read and CA-08–CA-15 short-circuit scenarios when flag enabled).
- Routing & Gateway **Routes & Keys** tab includes **Fallback Verification** suite (FB-*) for chain validation, priority readback, and simulate-fallback when Route Policy ID is set.
- Operator test matrix: `backend/docs/governance/memory-cache-fallback-test-cases.md`; smoke script `frontend/scripts/gateway_memory_cache_fallback_smoke.sh`.
- Routing & Gateway also supports MCP governance workflows: approved server registry readback (`/gateway/mcp/servers`), tool discovery per server (`/gateway/mcp/servers/{server_id}/tools/list`), and governed tool execution (`/gateway/mcp/servers/{server_id}/tools/call`).
- Routing & Gateway now also supports governed external callback workflows: callback registry list/create/update (`/gateway/external-callbacks`), simulated delivery tests (`/gateway/external-callbacks/{callback_id}/test-delivery`), and export evidence snapshots (`/gateway/external-callbacks/export`).
- External callback workflows now include sink-specific routing metadata (`sink_type`, `sink_route_key`) and correlation presets (`trace_resource`, `tenant_environment`, `incident_minimal`, `none`) with test-delivery correlation-context preview and export distribution summaries for audit/CISO review.
- Routing & Gateway now also supports explicit authorization explainability simulation via `POST /gateway/authz/explain` to show decision traces, allowed roles, and production dual-approval requirements.
- Routing & Gateway now also supports decision-trace evidence retrieval via `GET /gateway/decision-traces/{trace_id}` for audit/logging investigation of action timelines and decision outcomes.
- Routing & Gateway also supports provider-priority readback and audit-backed priority timeline history (`/gateway/routes/{route_policy_id}/providers/priority/timeline`), plus cache stats, endpoint compatibility checks, and transform-debug requests.
- Key Lifecycle now supports explicit block and unblock actions for virtual keys in addition to create, update, usage inspection, rotation, guardrail evaluation, temporary budget increase requests/readback, and rotation schedule create/list/update/execute actions.
- Cost console supports request-tagged spend tracking ingestion, pricing catalog and pricing calculator workflows (custom LLM token pricing simulation and provider/model discount simulation), budget lifecycle create/list/edit/delete workflows with advanced controls (expanded scope types, reset timezone/hour, temporary increases, soft-alert toggle, rate/session caps), policy evaluation with effective-budget and soft-alert output, aggregated limit evaluation including agent IDs and soft-alert scopes, anomaly review, and session/agent cost drilldown workflows.
- Cost console also includes ranked model intelligence browsing for supported models using the current pricing data.
- Providers console now supports supported-model explainability and approval governance: recommendation rationale capture, approval/rejection actions with ticket and review note, environment selection (`dev`/`prod`), and approval/version visibility (`approval_status`, `metadata_version`, approver metadata).
- Cost console supports workspace dropdown navigation (Overview, Telemetry, Pricing, Budgets, Drilldown), live overview metrics, integrated spend-vs-hours chart, catalog-driven pricing calculator dropdowns, subsection selectors for pricing/budget workspaces, and cross-table search.
- Discovery console supports posture score ring, confidence distribution, auto-refresh, posture alert banner, clickable KPI metrics, horizontal-scroll topology map, **Agent Ops & Trace Sources** card (configure sources, Observability pivot), agent-ops functional labels, agent detail drawer, agents CSV export, `/discovery/summary` dashboard, source sync, live connections, duplicate/triage workflows, and resolve/promote actions.
- Discovery source sync controls cover agent-scoped cloud infra across AWS (`aws_s3`, `aws_iam`, `aws_ec2`), Azure (`azure_blob_storage`, `azure_managed_identity`, `azure_virtual_machines`), GCP (`gcp_cloud_storage`, `gcp_service_accounts`, `gcp_compute_engine`), and Oracle OCI (`oracle_oci_object_storage`, `oracle_oci_compute`); discovered-agent table also surfaces `promoted_to_agent_id` linkage.
- Compliance console supports control coverage with route-level drill-down, evidence generation, evidence freshness, mapping CRUD, retention policies, legal hold actions, and evidence bundle drill-down (artifact inventory, integrity status, latest artifact timestamp, and event-level evidence rows).
- Compliance evidence bundle retrieval is integrity-guarded: malformed artifact integrity hashes trigger a fail-closed 409 response and deny audit evidence (`compliance.evidence.bundle.retrieve`).
- Compliance evidence bundle retrieval supports scoped filters to reduce exposure (`since_hours`, `decision_outcome`, `action_type_prefix`, `tenant_id`, `environment`, source-type/source-id filters, and per-result limits) directly from the Compliance UI form.
- Compliance evidence panel now includes quick filter presets (Prod Forensics, Tenant Focus), one-click filter reset, bundle summary copy, and bundle JSON export for faster operator investigations.
- Compliance bundle drill-down tables now include row-level operator actions: prefill source filters from an artifact row, copy trace/event payload values, and securely open HTTP(S) artifact links.
- Compliance row actions now support optional auto-refresh and event-derived filter application (`source_type`, `source_id`, `trace_id`) when evidence event payloads expose recognizable fields.
- Compliance includes a CISO-focused investigation drawer that captures selected row context (trace/source/action/resource/outcome/integrity/artifact URI) and provides one-click pivots to Observability trace/log workflows and the Audit event feed.
- Investigation drawer updates are exposed through a live status message, auto-open on context selection, and an explicit clear-context action to support keyboard-driven operator and accessibility workflows.
- Compliance bundle export supports an explicit "include investigation context" mode so downloaded JSON can contain selected forensic context and pivot-availability metadata for CISO evidence handoffs.
- Observability console supports tabbed overview (selectable time window, auto-refresh, alert banners, clickable signal tiles, actor/action/recent-trace charts via `/observability/summary`), trace waterfall timeline, log explorer with saved views, CSV/JSON export, filter chips, pagination, log detail drawer, schema-health checks, and drilldown pivots.
- Security view now supports session policy governance, SSO provider lifecycle (create/update/test/scim), governed session issue/get/reauth, and break-glass basic-auth controls.
- Security view includes role-binding validation plus explainability matrix workflow (`/auth/roles/bindings/validate`, `/auth/authz/explain`) and evidence drilldown via filtered audit events (`/audit/events`).
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
   bash scripts/guardbridge_extension_smoke.sh
   bash scripts/gateway_governance_evidence_smoke.sh
   bash scripts/gateway_memory_cache_fallback_smoke.sh
   bash scripts/openai_gateway_ops_smoke.sh
   RUN_API_CHECKS=1 API_BASE=http://127.0.0.1:8000 bash scripts/gateway_governance_evidence_smoke.sh
   RUN_API_CHECKS=1 API_BASE=http://127.0.0.1:8000 bash scripts/gateway_memory_cache_fallback_smoke.sh
   RUN_API_CHECKS=1 API_BASE=http://127.0.0.1:8000 bash scripts/openai_gateway_ops_smoke.sh
   RUN_API_CHECKS=1 API_BASE=http://127.0.0.1:8000 bash scripts/guardbridge_extension_smoke.sh

   Extension packaging:
   bash ../scripts/package_guardbridge_extension.sh

   Browser compatibility matrix check:
   bash ../scripts/check_guardbridge_browser_compat.sh
   FINAL_GATES_STRICT_SAFARI=1 bash ../scripts/run_final_gates.sh --quick
   FINAL_GATES_STRICT_FIREFOX=1 bash ../scripts/run_final_gates.sh --quick
   FINAL_GATES_STRICT_SAFARI=1 FINAL_GATES_STRICT_FIREFOX=1 bash ../scripts/run_final_gates.sh --quick
   bash ../scripts/configure_xcode_for_safari_converter.sh

   Notes:
   - `gateway_governance_evidence_smoke.sh` now sends explicit auditor identity headers by default (`X-Actor-Role: Auditor`, `X-Actor-Id: smoke-gateway-auditor`) to match current auth requirements.
   - Override the default actor id with `AUDITOR_ID=<id>` when needed.

## Production Container Serve

The frontend now includes deployment artifacts for production serving without nginx:

- `frontend/Dockerfile`
- `frontend/scripts/serve_static.py`

The root-level production stack (`docker-compose.production.yml`) builds this image and serves UI on port `4173` by default.
