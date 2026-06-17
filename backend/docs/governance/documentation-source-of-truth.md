# Documentation Source of Truth

## Purpose

This document defines the canonical documentation hierarchy for implementation status, security controls, and UI/API coverage. Use it before updating frontend or backend surfaces.

## Canonical Order of Authority

1. `backend/docs/governance/documentation-source-of-truth.md` (this file): governance hierarchy and sync rules.
2. `backend/docs/governance/api-inventory-and-ui-map.md`: endpoint-level truth for route coverage status.
3. `backend/docs/governance/ui-api-design-coverage-map.md`: domain-level product intent and gap status.
4. `backend/docs/governance/litellm-parity-roadmap.md`: parity planning register for pending proxy/router feature deltas.
5. `backend/docs/governance/litellm-cache-parity-impact-analysis.md`: Phase 3 inference cache short-circuit implementation and deferred LiteLLM cache tracks.
6. `backend/docs/governance/litellm-rag-parity-impact-analysis.md`: Phase 4 RAG runtime (MCP-first), live probe, and PII hook partial closure.
6a. `backend/docs/governance/litellm-assistants-parity-impact-analysis.md` (GOV-LITELLM-ASSISTANTS-001): Assistants / fine-tuning / passthrough parity, auth explain, playground drill-down, compliance export, and Part 5 full impact analysis.
7. `backend/AGENTS.md`: security and role contract that implementation must preserve.
8. `backend/docs/governance/agent-delivery-checklist.md`: feature/fix-level implementation evidence template across all architecture lenses.
9. `backend/docs/security/residual-and-accepted-risk-register.md`: accepted risk and compensating controls.
10. `backend/docs/governance/security-risk-closure-plan.md`: owner-assigned closure tracker for residual risk and release-gate follow-through.
11. `backend/docs/governance/multi-lens-security-architecture-review.md`: required cross-discipline review template (Security Architect, Cloud Architect, Browser Architect, Cloud Security, AI Security, PAM, IAM Governance).
12. `frontend/README.md`: operator-facing UI capabilities and run instructions.
13. `backend/docs/governance/ai-gateway-identity-security-design.md`: AI Gateway target-state design and phased implementation plan.
14. `backend/docs/governance/ai-gateway-litellm-parity-gap-analysis.md`: competitive parity gap analysis focused on AI-gateway and LiteLLM-relevant features.
15. `docs/agentic-browser-security-design-and-product-review.md`: target-state design and product landscape review for secure agentic browser operations integrated with AI Gateway.
16. `backend/docs/governance/unified-secret-provider-ciso-gap-analysis.md`: unified secret provider gap analysis, control mapping, test matrix, and CISO review checklist for Cursor credential consolidation.
17. `backend/docs/governance/generic-provider-configuration-review-and-impact-analysis.md`: **Final v1.1 (GOV-GPC-FINAL-001)** — complete classification register, cross-console UI review, consolidated gap register (GAP-GPC + GAP-USP), **full impact analysis (Part 5 §5.1–§5.17)**, multi-lens review, P1 credential bindings design, and operator reference for all cloud AI provider configuration.
18. `backend/docs/governance/flow-orchestration-notification-impact-analysis.md`: Phase 1 notification channel registry (`gateway.notification_channels_json`), Flow Orchestration `email_send`/`sms_send` nodes, CISO go/no-go for stub vs live send (GOV-FLOW-NOTIFY-001).
19. `backend/docs/governance/flow-orchestration-iga-impact-analysis.md`: Advanced IGA for orchestration (SoD, staged approval, JIT, certification, entitlement bridge, approval events, explain/posture) (GOV-FLOW-IGA-001).

If two docs conflict, higher-ranked docs win and lower-ranked docs must be corrected in the same change.

## Synchronization Rules

- Update endpoint inventory and domain coverage map in the same PR whenever UI workflows change.
- Complete the agent delivery checklist in the same PR whenever behavior, controls, or runtime posture changes.
- Mark status conservatively:
  - `Full`: primary operator path exists end-to-end in UI.
  - `Partial`: workflow exists but is subset/read-only or missing key actions.
  - `Gap`: no UI workflow.
- When a `Gap` moves to `Partial` or `Full`, update:
  - governance inventory,
  - coverage map,
  - frontend README surface notes,
  - security docs when privileged actions or runtime-sensitive controls change.

## Delta Register (Current)

Implemented in current state:

- Route Drafts: submit/approve/reject/approve-change-window/promote/rollback actions are now exposed in Routing & Gateway.
- Gateway cache policies now expose exact/semantic mode and similarity-threshold controls in Routing & Gateway, with stats/health surfacing semantic-policy coverage.
- Providers: workload identity token exchange, trust validation with evidence drilldown, workload/secret health checks, secret lease renewal and inventory, and rotate-via-secret-provider key action are now exposed in Providers.
- Security: role-binding validation and explainability workflows are now exposed in Security.
- Modules: register/list/versions, agent validate/upgrade-plan, and deprecate workflows are now exposed in Modules.
- Agentic: readiness report, contract validation, certification run/list/latest/override/export, load-test run/latest, checkpoint create/list/resume, policy auto-tune/scheduled-optimize, and policy schedule create/list/summary/detail/update/status/approve/execute/history/enable/disable/delete workflows are now exposed in Agentic.
- Observability: trace lookup, deep log filtering/search, redact mode, schema health checks, and log-to-trace drilldown actions are now exposed in Observability.
- Routing & Gateway: route provider-priority timeline history is now exposed with limit/offset timeline controls and audit-backed events.
- Routing & Gateway: Route Priority and route create workflows now include a visual fallback-chain builder (ordered provider+model rows with up/down reorder, provider/model datalists, and backend schema validation) in addition to advanced JSON editing.
- Routing & Gateway: Memory & Context tab now exposes `/gateway/memory/*` overview and record CRUD workflows with short-term TTL, per-scope limits, 16 KiB content cap, Agent Owner scoping, and production long-term dual-approval on create/delete.
- Routing & Gateway: Memory & Context **Platform Configuration** tunes memory, semantic cache defaults, vector store registry (`/gateway/memory/config`, `gateway.vector_stores_json`) with secret-ref integration via Providers; **inference cache short-circuit** via `gateway.cache.inference_short_circuit_enabled` (default off, encrypted response store, dual-approval to enable in prod); **RAG data plane** via `POST /rag/ingest`, `POST /rag/query`, OpenAI-compatible `GET /v1/vector_stores*` (MCP bridge v1); **live probe** `gateway.vector_stores.live_probe_enabled`; **PII classification** `gateway.memory.pii_classification_enabled` (default off); impact analysis in `memory-context-vector-impact-analysis.md`, `litellm-cache-parity-impact-analysis.md`, and `litellm-rag-parity-impact-analysis.md`.
- Routing & Gateway: MCP server registry, tool list, and governed tool call workflows are now exposed in the console.
- Cost: budget policy lifecycle create/list/edit/delete workflows are now exposed in Cost.
- Routing & Gateway: gateway-governance PR-1 through PR-4 slices are now implemented (entitlements, NHI inventory/hygiene, access reviews + JIT, and least-privilege recommendations) with synchronized API/UI/docs coverage.
- Routing & Gateway: least-privilege recommendation apply flow now requires operator decision rationale in UI for stronger CISO/IAM evidence hygiene.
- Routing & Gateway: gateway governance evidence aggregation/export workflow is now exposed via `POST /gateway/governance/evidence/export`, producing filtered JSON bundles and action-level summaries for security/CISO review.
- Routing & Gateway: cache decision timeline readback is now exposed via `GET /gateway/cache/decisions` with trace/tenant/decision filters plus hit/miss/bypass explanation, semantic similarity score, request fingerprints, and source-request provenance details in the cache management console.
- Browser Security: GuardBridge console and `/browser/*` governance API surface are now exposed end-to-end, including sessions/events ingest and review, shadow AI inventory triage, risk policy CRUD, analytics breakdown, and incident evidence export with privacy-safe telemetry constraints.
- Routing & Gateway: OpenAI-compatible chat baseline endpoint is now exposed via `POST /v1/chat/completions` with role-gated and audit-backed behavior.
- Routing & Gateway: OpenAI-compatible embeddings baseline endpoint is now exposed via `POST /v1/embeddings` with role-gated and audit-backed behavior.
- Routing & Gateway: OpenAI-compatible responses baseline endpoint is now exposed via `POST /v1/responses` with role-gated and audit-backed behavior.
- Routing & Gateway: OpenAI-compatible responses lifecycle baseline now includes `GET /v1/responses`, `GET /v1/responses/{response_id}`, and `DELETE /v1/responses/{response_id}` with role-gated read, owner-or-admin delete semantics, and production dual-approval guardrails.
- Routing & Gateway: OpenAI-compatible files metadata baseline now includes `POST /v1/files`, `GET /v1/files`, `GET /v1/files/{file_id}`, and `DELETE /v1/files/{file_id}` with role-gated lifecycle behavior, owner-or-admin delete semantics, and production dual-approval guardrails.
- Routing & Gateway: dedicated OpenAI-Compatible Gateway Ops UI workflows are now exposed for `/v1/chat/completions`, `/v1/responses*`, and `/v1/files*`, with operator controls for lifecycle read/delete and optional production dual-approval headers; smoke coverage now includes `frontend/scripts/openai_gateway_ops_smoke.sh`.
- Routing & Gateway: explicit decision-trace evidence retrieval workflow is now exposed via `GET /gateway/decision-traces/{trace_id}` in Gateway Controls for audit/logging investigations.
- Routing & Gateway: OpenAI-compatible create responses now include risk-adaptive metadata (`risk_tier`, `risk_reasons`) for operator, AI-architect, and CISO posture review.
- Playground: prompt registry promotion governance endpoint is now exposed via `POST /playground/prompts/{prompt_registry_id}/promote`, with template render-preview validation and production dual-approval enforcement for release approvals.
- Playground: quality triage queue workflow is now exposed via `GET /playground/quality/triage`, enabling operator filtering and priority tagging for low-rating/low-quality feedback investigations.
- Playground: quality escalation lifecycle is now exposed via `POST /playground/quality/triage/{feedback_id}/escalate`, `GET /playground/quality/triage/escalations`, and escalation acknowledge/resolve actions with SLA tracking for trust-ops incident handling.
- Playground: quality escalation notifications are now exposed via `POST /playground/quality/triage/escalations/{escalation_id}/notify` with channel/destination metadata and audit-backed communication traceability.
- Playground: long-window quality analytics rollups are now exposed via `GET /playground/quality/analytics/rollups` with provider/route/model dimensional bucket views for trend analysis.
- Providers: supported-model catalog now includes explainability metadata (`recommendation_rationale`), explicit approval/rejection workflow (`POST /providers/models/{supported_model_id}/approve`), and metadata version progression for operator and security review traceability.
- Platform model availability: canonical UI register (`GET /providers/models/available`) unifies all operator model dropdowns; governed by `platform.ui_models.catalog_statuses`, `platform.ui_models.require_approval`, and `platform.ui_models.enforce_tenant_entitlements`. Impact analysis: `backend/docs/governance/model-availability-ui-impact-analysis.md` (GOV-MODEL-AVAIL-001).
- Routing & Gateway: external callback workflows now include sink-specific routing and correlation presets (`sink_type`, `sink_route_key`, `correlation_preset`) across create/update/test/export paths, with correlation-context preview and distribution metadata for CISO/audit evidence review.
- Routing & Gateway: realtime/media transport governance is now hardened with inline-binary stream policy controls (`stream_inline_max_event_bytes`, `stream_inline_allowed_event_types`, `stream_inline_require_correlation_id`) enforced during session event ingest in addition to existing prod dual-approval checks.
- OpenAPI/Swagger: high-risk mutation endpoints now include explicit summaries, governance-aware descriptions, and error response contracts across Auth, Gateway, and Providers (break-glass enable/disable, key block/unblock/rotate paths, route optimize/execute-fallback, cache invalidation, transform-request debug, authz explain, workload trust/test, and secret provider test/lease renew).
- OpenAPI/Swagger: **Platform** tag documents operational posture and operator feedback persistence (`POST /platform/feedback` → `operator_feedback`, audit `platform.feedback.*`) with request/response schemas and 403/404/422 contracts. **Governance** tag documents UI coverage gap inventory endpoints. Regenerate via `GET /openapi.json` or `/docs`.
- OpenAPI/Swagger: provider onboarding and gateway governance operations now also include explicit endpoint contracts (basic-auth config create, tenant catalog create/update, workload identity provider create, secret provider create, db secret value upsert/read/delete, gateway cursor secret binding, route create/provider-priority update, cache policy create, external callback create/test/export, and governance evidence export).
- Consolidated evidence artifact captured in `backend/docs/governance/agent-delivery-checklist-openai-gateway-consolidated.md` with role-lens validation, security checks, and regression outcomes.
- Discovery: dashboard posture and triage surface now includes healthy/stale source posture metrics, unified triage aggregation (conflicts/alerts/promote queue), and operator filter controls (`type`, `urgency`, `search`) with existing resolve/promote action paths.
- Discovery: source catalog includes 49 agent-scoped sources (platform internals plus well-known AI providers, dev platforms, cloud AI/infra across AWS/Azure/GCP/Oracle/CoreWeave, and agent-ops integrations). UI provides quick-connect presets (46 sources), live connection CRUD with edit/update, per-source and per-connection sync, cross-source duplicate triage with merge/dismiss workflows, and discovered-agent linkage via `promoted_to_agent_id`.
- Modules: AI Skills Registry is now exposed in Modules via `GET /modules/skills`, with skill inventory filtered to `ai_skill`/`skill` module types and operator UI readback.
- Modules: integration metadata and sync controls are now exposed for module inventory (`integration_provider`, `integration_reference`, `integration_sync_status`, `integration_last_synced_at`) with governed sync action via `POST /modules/{module_id}/integration/sync`.
- Routing & Gateway: baseline system-level instruction controls and scoped system-rules registry are now exposed via `GET/PUT /gateway/system-instructions` and `GET/PUT /gateway/system-rules`, with runtime application to OpenAI-compatible responses and scope classification aligned to existing owner/budget scope types plus agent scope.
- Providers: unified secret provider model now includes `db` provider type with encrypted value storage (`PUT/GET/DELETE /secrets/providers/{provider_id}/values*`), gateway cursor secret binding (`GET/PUT/DELETE /gateway/cursor-secret-binding`), and CISO gap analysis in `backend/docs/governance/unified-secret-provider-ciso-gap-analysis.md`. Legacy `/gateway/cursor-token` is deprecated.
- Governance: API UI coverage gap reporting is now exposed via `GET /governance/ui-coverage` and machine-readable inventory via `GET /governance/ui-coverage/inventory`, with Overview and Compliance operator surfaces plus frontend `Gap` endpoint gating.
- Frontend component modules: shared constants (`js/constants.js`), API client headers (`js/api-client.js`), boot-time GET dedupe (`js/api-cache.js`), and UI coverage component (`js/ui-coverage.js`) extracted from `app.js` with script load order before the main bundle.
- Platform operator experience: maintenance/downtime/slow-performance banners (`js/platform-status.js`), operator feedback persisted in PostgreSQL table `operator_feedback` via `POST /platform/feedback` (audited `platform.feedback.create`), analytics/triage via `/platform/feedback*`.
- Health: `GET /health` now exposes non-secret `runtime_config_cache` posture (`status`, `ttl_seconds`, `last_refresh`, backend mode, degraded flag) for cloud-operator diagnostics.
- Discovery UX: horizontal-scroll topology map, Agent Ops & Trace Sources card, functional agent-ops labels, Observability pivot from Discovery.
- Backend domain layer: `backend/app/domain_constants.py` for code defaults; `backend/app/services/platform_operational.py` for operational posture and feedback analytics; observability summary SQL aggregates in `backend/app/services/observability_summary.py`.
- Flow Orchestration: n8n-compatible flow definitions (`/orchestration/flows*`), node-type catalog, schema/security validation, prod dual-approval promotion, stub executor with run history, HTTP allowlist via `orchestration.http_allowed_hosts_json`, **email/SMS notification nodes** (`email_send`, `sms_send`) with channel registry (`gateway.notification_channels_json`, `GET /gateway/notification-channels*`), and operator console with step/chain builder (visual canvas Phase 2). Impact analysis: `flow-orchestration-impact-analysis.md` (GOV-FLOW-ORCH-001), `flow-orchestration-notification-impact-analysis.md` (GOV-FLOW-NOTIFY-001).
- **Assistants / fine-tuning / passthrough parity** (GOV-LITELLM-ASSISTANTS-001): OpenAI-compatible `/v1/assistants*`, `/v1/threads*`, `/v1/fine_tuning/jobs*`, and `POST /v1/passthrough` with owner scoping, prod dual-approval on delete/cancel/passthrough, path allowlist, CP-REF header sanitization, deny-path audit on authz failures, and `environment` on assistant/fine-tuning responses. Routing & Gateway Workspace cards: create/list/retrieve/delete assistants, thread/message/run workflow, fine-tuning create/list/retrieve/cancel, passthrough test with optional headers JSON. Auth explain: Security `POST /auth/authz/explain` (MFA); Gateway authz explain presets for `gateway.assistants.delete`, `gateway.fine_tuning.cancel`, `gateway.passthrough.execute`. Playground: `GET /playground/runs/{run_id}/detail` drill-down tabs. Compliance: `POST /compliance/evidence/export` with `investigation_context` embed and deny audit on missing control (no silent client fallback). Tests: `test_gateway_assistants.py`, `test_gateway_fine_tuning.py`, `test_gateway_passthrough.py`, `test_playground_run_detail.py`, `test_compliance_evidence_export.py` (29 cases). Impact analysis: `litellm-assistants-parity-impact-analysis.md`.

Remaining documented deltas:

1. Remote secret-provider key rotation execution (`POST /keys/{key_id}/rotate-via-secret-provider`) remains audit-delegated without full backend adapter execution.
2. Legacy `/gateway/cursor-token` API removal scheduled after operator migration window (see GAP-USP-R03 in unified secret provider CISO gap analysis).
3. Vector/RAG data plane Phase 4 implemented per `memory-context-vector-impact-analysis.md`, `litellm-rag-parity-impact-analysis.md`, and `litellm-cache-parity-impact-analysis.md` (MCP-first `/rag/*`, live probe flag, PII classification hook default off).
4. Assistants parity residual: live fine-tuning upstream wired (`gateway.fine_tuning.live_enabled`, default off — simulated completion when false; live OpenAI job create/sync/cancel when true). **Closed:** streaming assistant runs; thread/run retrieve UI; SIEM rules UI + dispatch (RSK-ASSIST-05); deferred console surfaces (cost timeseries Telemetry panel, orchestration test-query UI, console surface smoke) — see `deferred-console-parity-completion-plan.md`.

## REST API Observability Standards

All REST routers use shared helpers in `backend/app/api_errors.py` for operator-facing failures:

- `error_code`, `message`, `policy_version`, and `decision_trace_id` are required on structured errors.
- `AUTHZ_SCOPE_FORBIDDEN`, `RESOURCE_NOT_FOUND`, `VALIDATION_ERROR`, `RESOURCE_CONFLICT`, `AUTHN_INVALID_CREDENTIALS`, and `UPSTREAM_PROVIDER_ERROR` are the canonical codes.
- Request middleware in `backend/app/main.py` emits trace/info/error logs for every HTTP request.
- Mutating privileged flows must emit allow/deny audit evidence via `create_audit_event()` at request time when the decision is made (benchmark/scan cancel, agentic policy auto-tune apply, browser security mutations, platform feedback create/triage, **gateway assistant delete / fine-tuning cancel / passthrough execute dual-approval and scope denials**, **compliance evidence export missing-control deny**, and similar).

**Gateway Assistants / fine-tuning / passthrough — persistence and audit**

| Operation | API | Database | Audit `action_type` | Deny audit |
|---|---|---|---|---|
| Create assistant | `POST /v1/assistants` | `gateway_assistant_records` | `gateway.assistants.create` | — |
| Delete assistant | `DELETE /v1/assistants/{id}` | soft-delete status | `gateway.assistants.delete` | prod dual-approval + owner scope → `deny` |
| Thread message | `POST /v1/threads/{id}/messages` | `gateway_assistant_thread_message_records` | `gateway.threads.messages.create` | — |
| Thread run | `POST /v1/threads/{id}/runs` | `gateway_assistant_thread_run_records` | (via inference audit path) | 422 if no user message |
| Fine-tune cancel | `POST /v1/fine_tuning/jobs/{id}/cancel` | status → cancelled | `gateway.fine_tuning.cancel` | prod dual-approval + owner scope → `deny` |
| Passthrough | `POST /v1/passthrough` | none (proxy) | `gateway.passthrough.execute` | allowlist/scope/dual-approval → `deny` |
| Compliance export | `POST /compliance/evidence/export` | bundle read | `compliance.evidence.export` | missing control / bundle error → `deny` |

Models: `GatewayAssistant*`, `GatewayFineTuningJobRecord` in `backend/app/models.py`. Services: `gateway_assistants.py`, `gateway_fine_tuning.py`, `gateway_passthrough.py`. Schema bootstrap: `_upgrade_gateway_assistants_schema()` in `backend/app/main.py`.

**Platform operator feedback — persistence and audit (verified)**

| Operation | API | Database | Audit `action_type` |
|---|---|---|---|
| Submit feedback | `POST /platform/feedback` | Insert into `operator_feedback` | `platform.feedback.create` |
| Triage feedback | `POST /platform/feedback/{feedback_id}/actions` | Update `status`, `acted_by`, `acted_at`, `action_note` on `operator_feedback` | `platform.feedback.acknowledge`, `.resolve`, `.dismiss`, `.escalate` |
| List / analytics | `GET /platform/feedback`, `GET /platform/feedback/analytics` | Read-only SQL on `operator_feedback` | None (info logs only) |

Model: `OperatorFeedback` in `backend/app/models.py`. Schema bootstrap: `_upgrade_operator_feedback_schema()` in `backend/app/main.py`.

**Playground run feedback — persistence and audit (separate table)**

| Operation | API | Database | Audit `action_type` |
|---|---|---|---|
| Submit/update | `POST /playground/runs/{run_id}/feedback` | Upsert `playground_run_feedback` | `playground.run.feedback.create` / `.update` |
| List | `GET /playground/runs/{run_id}/feedback` | Read-only | None |

Intentional no-audit read/compute endpoints (non-mutating, no privileged decision):

- `GET /cost/pricing/calculate` — deterministic pricing math preview.
- `POST /discovery/connections/{connection_id}/test` — connectivity probe; failures are logged, not audited.
- `GET /observability/*` — diagnostic readback over existing audit/log data.
- `GET /governance/ui-coverage` and `GET /governance/ui-coverage/inventory` — read-only governance gap reports for CISO/compliance dashboards; structured info logs only (`governance_ui_coverage_*`), no audit spam.
- `GET /platform/operational-status` — read-only posture for maintenance/slow thresholds; no audit (banner driver only).
- `GET /platform/feedback/analytics` — read-only aggregate for operator reports; structured info logs (`platform_feedback_analytics_served`).

## Change Checklist

Before merge, verify:

1. `node --check frontend/app.js` passes for frontend changes.
2. `python3 -m pytest` passes for backend changes.
3. Coverage status changes in docs match actual UI controls and API calls.
4. Security-sensitive runtime changes include audit and risk-register updates.
5. Architecture-lens conformance (Security, CISO, AWS, Cloud, AI Architect, UI Expert, IAM, and Clean Architecture) is explicitly reflected in `ai-gateway-identity-security-design.md` when governance workflows change.
6. Audit/logging conformance is explicit for changed privileged flows (allow + deny evidence, correlation trace fields, and evidence export/readback paths).
7. Agent-friendly delivery artifacts are captured: scope slice notes, repeatable validation commands, and verification outcomes.
8. Agent-only governance validator passes for release candidates: `bash scripts/validate_agent_delivery_gates.sh`.
