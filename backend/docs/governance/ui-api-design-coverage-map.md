# UI, API, and Product Design Coverage Map

## Scope
This document maps implemented backend APIs to current UI coverage and product design intent.
Canonical hierarchy and update rules are defined in `backend/docs/governance/documentation-source-of-truth.md`.
Detailed requirement-to-API-to-UI verification evidence is tracked in `backend/docs/governance/e2e-requirement-api-ui-verification.md`.

## Legend
- `Full`: UI supports primary operator workflow for the endpoint set.
- `Partial`: UI supports read-only or subset workflow.
- `Gap`: API exists but has no UI workflow yet.

## Domain Coverage Matrix
| Domain | API Prefixes | Product Intent | UI Coverage | Status | Gaps |
|---|---|---|---|---|---|
| Agent Registry & Ownership | `/agents/*`, `/owners/*` | Register agents, transfer ownership, inspect history | Register + ownership list + transfer + history in Agents view | Full | None for core CRUD/ownership operations |
| Agent Runtime Config | `/agent-configs/*` | Configure per-agent runtime and fallback policy | Agent Configuration Studio (save/list/edit/delete/import/export) | Full | Bulk server-side import/export endpoint not present (UI handles local file workflows) |
| Global Runtime Config | `/runtime-config/*` | Tune non-startup defaults | Runtime Config Studio (save/list/edit/delete presets) | Full | Namespaced validation policy can be improved in backend |
| Discovery | `/discovery/*` | Source sync, triage conflicts/alerts, promote | Discovery console covers sources, discovered agents, conflicts, alerts, promote queue, sync, resolve, and promote actions | Full | Deeper merge or dedup workflows are still absent |
| Cost Governance | `/cost/*` | Spend telemetry, budgets, policy/limit eval, anomalies | Cost console now covers live telemetry, request-tagged spend tracking ingestion, advanced budget policy create/list/edit/delete lifecycle (scope expansion, timezone reset windows, temporary increases, soft alerts, rate/session caps), pricing catalog + pricing calculator workflows (custom model rates and provider discount simulation), anomaly review, policy evaluation with effective-budget and soft-alert outputs, aggregated limit evaluation with actor/team/group/agent inputs, and session/agent cost drilldowns | Full | Historical trend analysis can still be expanded |
| Audit | `/audit/events` | Evidence and action traceability | Recent events list | Full | No advanced filtering UI |
| Compliance | `/compliance/*` | Controls mapping, evidence, retention/legal hold lifecycle | Compliance console covers control coverage, evidence generation, evidence freshness, mapping CRUD, retention policies, and legal hold actions | Full | Route coverage report and evidence bundle drill-down can still be expanded |
| Auth & Session Governance | `/auth/*` | Session policy governance, SSO/SCIM, break-glass auth | Security view now covers session policy read/update/revisions/rollback, SSO provider lifecycle (create/update/test/sync), role-binding validation plus explainability matrix and evidence drilldown, governed session issue/get/reauth, break-glass basic-auth lifecycle, and directory operations | Partial | Backend explain endpoint is still not explicit; UI explainability is built from validation + audit evidence |
| Gateway & Keys | `/gateway/*`, `/keys/*`, `/v1/*` | Route policies, optimization, key lifecycle, key guardrail policy controls, MCP tool gateway workflows, and API-first OpenAI compatibility surfaces | Routing & Gateway now covers route create/list, adaptive/lowest-cost/lowest-latency/least-busy strategy selection, scoped gateway entitlement list/upsert workflows, NHI inventory/hygiene readback workflows, access-review campaign create/read workflows, JIT access request create/approve workflows, least-privilege recommendation read/apply workflows, gateway governance evidence aggregation/export via dedicated backend endpoint (`POST /gateway/governance/evidence/export`) for CISO/security review bundles, dedicated OpenAI-compatible operator workflows for `/v1/chat/completions`, `/v1/responses*`, and `/v1/files*` with risk-adaptive metadata (`risk_tier`, `risk_reasons`), priority read/write (including request-tag scoped policies), dedicated fallback management endpoints, provider-health management for health-check driven routing, grouped routing definitions with weighted failover semantics in fallback policy, fallback simulation/execution with request-priority tiers, budget-aware controls, error-type retry/cooldown policy enforcement, pre-call region/context-window filters, traffic mirroring policy controls plus route-scoped mirroring analytics/experiment reporting, optimization, cache policy create/list, cache stats, cache health diagnostics, audit-backed cache invalidation requests, endpoint compatibility, MCP server/tool list, MCP tool call, explicit gateway authz explainability, decision-trace evidence retrieval, transform debug, governed external callback registry/test/export workflows, key lifecycle management including block/unblock actions, temporary key budget increases, scheduled key rotation create/list/update/execute workflows, and key guardrail evaluation workflows | Full | None for core operator workflows |
| Providers & Secrets | `/auth/workload-identity/*`, `/secrets/*`, `/keys/*/rotate-via-secret-provider` | Identity federation and secret provider operations | Providers console covers tenant/workload/secret/model workflows including token exchange, trust validation, trust evidence drilldown, provider health, secret lease renew, secret lease inventory, secret health, and rotate-via-secret-provider action | Full | None for core operator workflows |
| Modules | `/modules/*`, `/agents/*/modules/*` | Module catalog and validation/upgrade workflows | Modules console covers register/list/versions, agent validation, upgrade planning, and deprecation | Full | Bulk module governance actions and policy templates can still be expanded |
| Route Drafts | `/route-drafts/*` | Draft approval, promotion, rollback workflows | Routing & Gateway route-draft console covers list/history plus submit, approve, reject, change-window, promote, and rollback actions | Full | Guided form validation and state-aware action affordances can still be improved |
| Playground | `/playground/*` | Run/compare/testing workflows | Playground Studio covers multimodal prompt runs, voice/video attachments, judge/retry, live preview, route-draft creation, and run history browsing | Full | Historical result drill-down is still limited to list/detail views |
| Observability | `/observability/*` | Trace/log diagnostics and schema health | Observability console covers trace lookup, deep log filtering/search, redact mode, schema status, and log-to-trace drilldown actions | Full | None for core observability workflows |
| Agentic Certification | `/agentic/*` | Readiness, certification, scheduling, checkpointing | Agentic console covers readiness report, contract validation, certification run/list/latest/override/export, load-test run/latest, checkpoint create/list/resume, policy auto-tune, scheduled-optimize direct run, and policy schedule create/list/summary/detail/update/status/approve/execute/history/enable/disable/delete workflows | Full | None for core agentic workflows |
| Benchmark & Scan | `/benchmarks/*`, `/scans/*` | Benchmarking and scanning workflows | Benchmark & Scan console covers benchmark and scan execution, filtered history browsing (`/benchmarks/runs`, `/scans/runs`), and aggregate trend summaries for operator review | Full | Bulk scheduling is not yet implemented |

## Functional CRUD Snapshot
- `Create`: covered in UI for `agents.register`, `agent-configs upsert`, `runtime-config upsert`.
- `Read`: covered in UI for `owners/{owner_id}/agents`, `agents/{agent_id}/ownership-history`, `agent-configs list`, `runtime-config list`, `discovery/agents`, `cost/live`, `audit/events`.
- `Update`: covered in UI for `agents/{agent_id}/owner`, `agent-configs upsert`, `runtime-config upsert`.
- `Delete`: covered in UI for `agent-configs delete`, `runtime-config delete`.

Auth/security workflow notes:

- UI now supports credential login via `POST /auth/login`.
- UI supports directory user lifecycle with password provisioning and backend lockout policy enforcement.
- UI supports directory group and team lifecycle workflows plus membership add/list/remove operations.
- UI supports directory unlock actions for locked or reset-needed users via `POST /auth/directory/users/{user_id}/unlock`.

## Product Design Alignment Notes
- Startup-critical security and boot config remains environment-managed by design.
- Non-startup tunables are database-backed and configurable from UI.
- Agent ownership governance now has explicit UI workflows aligned with API controls and audit trails.

## Prioritized Gaps to Close Next
1. Compliance evidence bundle drill-down: richer exploration workflows.
2. Security explainability follow-up: add a dedicated backend explain endpoint to replace inferred UI-only explainability assembly.
3. Compliance route-coverage UX follow-up: richer drill-down from summary status into control-level remediation context.
