# AI Gateway Identity Security Design

## Purpose

This document defines a security-first, cloud-ready, IAM-governed design for AI Gateway enhancements, aligned with the current AgentHub architecture and delivery contract, and explicitly reviewed through CISO, AWS architect, cloud architect, cloud security, Python architecture, frontend UI, and clean architecture lenses.

Scope is limited to AI Gateway and adjacent identity/governance controls (no unrelated product domains).

## Agent-First Delivery Profile (100% Agent-Centric)

This design is optimized for autonomous agent implementation with minimal ambiguity.

Agent execution principles:

1. Prefer additive endpoint and UI-card slices over broad refactors.
2. Each slice must be independently mergeable with tests and docs.
3. Keep one source of truth per capability in governance docs.
4. Use explicit acceptance checks so agents can self-verify completion.
5. Keep blast radius small: one backend capability + matching UI workflow per slice.

Agent-friendly delivery rules:

1. Every implementation slice must be named as a single capability, not a theme.
  - Example: `embeddings endpoint`, not `OpenAI parity`.
2. Every slice must have one falsifiable hypothesis and one cheap validation command before editing.
  - Example: prove an endpoint is missing, then add the endpoint and run the narrowest test.
3. Every slice must stay within one module boundary unless a dependency is unavoidable.
  - Prefer `MOD-GATEWAY`, `MOD-EXT`, `MOD-OBS`, or `MOD-COST` only.
4. Every slice must include its own rollback path or be purely additive.
  - Avoid cross-cutting refactors unless the change is required for correctness.
5. Every slice must produce machine-checkable evidence.
  - Code change, tests, docs, and validation command output must all be reproducible.
6. Every slice must preserve security and governance defaults.
  - No silent expansion of roles, scopes, logging, or retention behavior.
7. Every slice must be small enough to review in one pass.
  - If a feature requires more than 2-4 endpoints or multiple UI cards, split it.

Definition of done for each slice:

1. Backend endpoint(s) implemented with role/scope/audit controls.
2. UI card/form/readback implemented in Routing & Gateway (or Security when specified).
3. Regression tests added and passing.
4. Governance inventory + coverage map + frontend README updated.
5. Residual risk register updated when privilege/risk posture changes.
6. The change summary includes changed files, validation commands, and remaining risk.

Agent-oriented slice checklist:

1. Identify the nearest controlling abstraction.
2. Write the smallest change that tests the hypothesis.
3. Validate the changed slice before expanding scope.
4. Capture audit and security impacts in docs if the slice changes privilege, logging, or data retention.
5. Stop when the acceptance check passes; do not continue into adjacent features.

## Quick-Build Sequence (Fastest Path to Value)

Build in this exact order for fastest and safest agent throughput:

1. Explainability hardening (already started)
  - Extend `/gateway/authz/explain` with scope-level decisions and consistent reason taxonomy.
2. Entitlements MVP
  - `GET/PUT /gateway/entitlements` with scoped action grants and readback UI.
3. NHI inventory + hygiene MVP
  - `GET /gateway/nhi/inventory` and `GET /gateway/nhi/hygiene` with owner + credential-age indicators.
4. Access review + JIT MVP
  - Campaign create/read and JIT request/approve with expiry and audit evidence.
5. Least-privilege recommendations MVP
  - Read/apply recommendation workflow with explicit approval/audit behavior.
6. Gateway governance evidence export
  - Filtered audit-event aggregation and JSON evidence bundle export for entitlement/NHI/access-review/JIT/least-privilege governance actions.

Implementation pacing:

- One capability per PR.
- Prefer 2-4 endpoints per PR maximum.
- Keep UI additions as one card per capability.
- Keep each PR readable by a single reviewer without external context.
- Keep test coverage adjacent to the touched code instead of broad end-to-end expansion.
- Keep docs synchronized in the same change so agents never infer stale behavior.

Agent-safety constraints:

- Do not introduce speculative scaffolding for future features unless the current slice requires it.
- Do not widen role permissions to reduce implementation friction.
- Do not add hidden feature flags that change behavior without documentation.
- Do not merge unrelated endpoint families into one PR.
- Do not leave a partially implemented workflow without a clear operator-facing failure state.

Current implementation status:

- PR-1 through PR-4 are complete with backend/UI/tests/docs synchronization.
- Gateway governance evidence export workflow is now available in Routing & Gateway via `POST /gateway/governance/evidence/export`, with backend action-level evidence aggregation and export metadata for CISO/security bundles.
- OpenAI-compatible chat baseline endpoint is now available via `POST /v1/chat/completions` with role-gated access, deny/allow audit evidence, stop/max-tokens semantics, `response_format` contract support, and contract tests.
- OpenAI-compatible embeddings baseline endpoint is now available via `POST /v1/embeddings` with role-gated access, deny/allow audit evidence, tenant/model entitlement checks, and contract tests.
- OpenAI-compatible responses baseline endpoint is now available via `POST /v1/responses` with role-gated access, deny/allow audit evidence, stop/max-output-tokens semantics, `response_format` contract support, deterministic `tools`/`tool_choice` semantics, and strict function-only tool contract validation.
- OpenAI-compatible responses lifecycle baseline now includes `GET /v1/responses`, `GET /v1/responses/{response_id}`, and `DELETE /v1/responses/{response_id}` with role-gated access and soft-delete lifecycle behavior.
- OpenAI-compatible files metadata baseline now includes `POST /v1/files`, `GET /v1/files`, `GET /v1/files/{file_id}`, and `DELETE /v1/files/{file_id}` with role-gated access and soft-delete behavior.

## Alignment with Current Architecture

The design extends existing controls instead of creating a parallel control plane:

- Reuses `MOD-GATEWAY`, `MOD-EXT`, `MOD-OBS`, and `MOD-COST` module boundaries.
- Preserves role gates (`require_role`), MFA gates (`require_mfa`), and dual-approval controls (`require_dual_approval`) already used for production-sensitive operations.
- Preserves audit-first behavior through `create_audit_event` for allow/deny evidence.
- Preserves Routing & Gateway UI patterns in `frontend/index.html` and `frontend/app.js`.
- Keeps runtime-safe defaults and DB-backed tunables via existing runtime-config patterns.

Existing baseline (already in platform):

- Route policy management, fallback execution, retries/cooldowns, pre-call filters, traffic mirroring.
- Mirroring analytics summary and experiment reporting endpoints.
- Key lifecycle controls (block/unblock, rotation, temporary budget increase).
- Cache governance, callback governance, MCP governance.

## Design Goals

1. Enforce least privilege for model, tool, route, and key actions.
2. Improve explainability of authorization decisions for operators and auditors.
3. Strengthen non-human identity (NHI) posture for gateway credentials and service principals.
4. Enable review-request-remediate lifecycle for sensitive gateway entitlements.
5. Keep cloud deployment operable with explicit AWS guardrails.

## Veza Use-Case Coverage Map (AI Gateway Scope)

This section maps Veza-style outcomes to concrete AI Gateway capabilities in this repo.

1. Access Visibility (who can do what on what)
  - Gateway authz explain, scoped entitlements readback, and action-level policy mapping.

2. Access Intelligence (right-size and prioritize risk)
  - Least-privilege recommendations, risky grant prioritization, and high-risk action taxonomy.

3. Access Monitoring (continuous oversight)
  - Audit-backed decision traces, deny/allow evidence, and route/key/tool activity observability.

4. NHI Security (machine identity governance)
  - Service identity inventory, owner assignment, stale/expired credential hygiene, and remediation paths.

5. Access Reviews (certification campaigns)
  - Gateway entitlement review campaigns with reviewer decisions and evidence capture.

6. Access Requests / JIT
  - Time-bound privileged access request and approval with automatic expiry.

7. API-First Governance
  - All capabilities exposed as typed REST endpoints for integration and automation.

## Role-Lens Review Summary

### 1. Security Architect Lens

Design controls:

- Introduce action-level authorization matrix for gateway actions:
  - `gateway.model.invoke`
  - `gateway.tool.call`
  - `gateway.route.update`
  - `gateway.key.rotate`
  - `gateway.callback.update`
- Add scope constraints to each decision:
  - `tenant_id`, `environment`, `route_policy_id`, `request_tag`, `model_name`, `tool_name`.
- Add explicit deny reasons for policy explainability (`AUTHZ_SCOPE_FORBIDDEN`, `AUTHZ_MODEL_FORBIDDEN`, etc.).
- Keep prod write-paths behind MFA + dual approval where blast radius is high.

Abuse-case handling:

- Cross-tenant invocation attempts.
- Privilege escalation via wildcard model/tool patterns.
- Service identity reuse across environments.
- Callback exfiltration via over-broad event configuration.

### 2. Audit Architect Lens

Design controls:

- Add decision evidence for every gateway access decision:
  - allow, deny, warn outcomes.
- Add deterministic decision trace identifiers to support incident reconstruction.
- Add immutable linkage between:
  - entitlement state,
  - runtime decision,
  - remediation action.

Audit requirements:

- Deny-path auditing remains mandatory for privileged route/key/callback/tool mutations.
- New explainability endpoint must include policy version and effective scope chain.

### 3. CISO Lens

Business-risk outcomes:

- Reduces unauthorized AI tool/data access risk.
- Shrinks blast radius of compromised NHI credentials.
- Improves attestation quality for compliance and customer assurance.

Top risks (residual):

1. Mis-scoped legacy entitlements during migration to action-level controls.
2. Incomplete ownership metadata for existing keys/service identities.
3. Operational friction from stricter approvals in production.

Go/No-Go recommendation:

- **Go (phased)** with non-prod rollout first, observability burn-in, and explicit rollback controls.

### 4. AWS Architect Lens

Design controls:

- Enforce least-privilege IAM assumptions for STS role usage by gateway integrations.
- Require explicit region handling for external provider operations.
- Avoid plaintext secret exposure paths in non-local environments.
- Add guardrails for AWS role trust/policy drift detection and stale credential alerts.

AWS implementation notes:

- Keep KMS-backed secret storage assumptions unchanged.
- Prefer short-lived credentials and service-role boundaries.
- Separate dev/stage/prod trust boundaries and approver identities.

### 5. Cloud Architect Lens

Design controls:

- Safe defaults and feature flags via runtime config.
- Operationally reversible controls (dry-run mode before hard enforcement).
- Capacity-safe analytics queries with bounded `limit/offset` and time windows.
- SLO-oriented telemetry for authz latency and decision error rates.

Operational readiness:

- Include runbooks for policy rollout, exception workflow, and emergency disable.
- Include clear rollback for each migration and policy phase.

### 6. Cloud Security Lens

Design controls:

- Enforce secure transport and explicit trust boundaries for all gateway control-path and data-path integrations.
- Require strict deny-by-default behavior for unauthorized scope/action combinations.
- Ensure high-risk gateway controls remain protected by MFA and dual approval in production.
- Keep callback and tool invocation paths constrained by explicit allowlists and environment-aware guardrails.

Threat and control posture:

- Primary abuse cases: credential theft, cross-tenant data exfiltration, over-broad callback delivery, and tool-call privilege escalation.
- Compensating controls: immutable audit trails, deny-path evidence, scoped policy checks, and explicit remediation hints.

### 7. IAM and Governance Lens

Design controls:

- Entitlement lifecycle:
  - discover -> classify -> owner assign -> review -> approve/reject -> remediate.
- Access review campaigns for gateway-critical grants.
- Just-in-time privileged access with explicit expiry and reason code.
- Separation of duties for requester/approver/remediator.

Governance outcomes:

- Better ownership and certification for non-human identities.
- Reduced standing privilege in production gateway operations.

### 8. Python Architecture Lens

Implementation constraints:

- Keep API contracts explicit with typed Pydantic schemas and stable response models.
- Keep router logic cohesive and side effects explicit (authorization, auditing, persistence).
- Preserve compatibility with repository Python constraints and existing runtime behavior.
- Prefer deterministic, testable helper functions for policy and decision logic.

Code quality requirements:

- Add focused unit/integration tests for each new decision branch.
- Keep endpoint behavior backward-compatible where possible.
- Avoid introducing hidden implicit defaults for privileged behavior.

### 9. Clean Architecture Lens

Boundary guidance:

- Keep policy decision logic independent from presentation details.
- Keep gateway authorization, inventory, and review workflows separated by capability boundary.
- Keep persistence schema evolution isolated through Alembic-managed migrations.
- Ensure cross-module dependencies remain explicit and minimal (`MOD-GATEWAY`, `MOD-EXT`, `MOD-OBS`, `MOD-COST`).

Design discipline:

- Prefer additive changes and feature flags over disruptive rewrites.
- Maintain single responsibility per endpoint/workflow.
- Keep audit and security concerns first-class, not bolt-on behavior.

### 10. Frontend UI and Theme Lens

UI architecture requirements:

- Extend existing Routing & Gateway cards/forms/tables; do not introduce parallel visual systems.
- Keep interaction patterns consistent with existing control-center conventions (`Load`, `Save`, `Use`, inline result text, table readbacks).
- Ensure responsive behavior and accessibility parity with existing UI surfaces.

Theme consistency requirements:

- Preserve established visual language (card layout, mono evidence areas, ghost/primary button semantics).
- Keep new governance controls discoverable within current navigation without adding competing top-level views.
- Prefer incremental card additions in Routing & Gateway and Security views rather than novel page frameworks.

Current status:

- Gateway authorization explain simulation is now present in Routing & Gateway and follows existing theme/pattern conventions.
- PR-1 Entitlements MVP is implemented with `GET/PUT /gateway/entitlements`, UI card workflow, tests, Alembic migration, and impact analysis.
- PR-2 NHI inventory and hygiene MVP is implemented with `GET /gateway/nhi/inventory` and `GET /gateway/nhi/hygiene`, UI card workflow, tests, and Alembic migration.
- PR-3 Access Reviews + JIT MVP is implemented with campaign create/read and JIT request create/approve endpoints, Routing & Gateway UI workflows, tests, and Alembic migration.
- PR-4 Least-Privilege Recommendations MVP is implemented with recommendation read/apply endpoints, Routing & Gateway recommendation workflow, tests, and Alembic migration.

## Architecture and Security Conformance (Implemented)

The current implementation has been reviewed against required lenses and hardened with explicit operator and code-level guardrails.

### CISO and Security Architect Conformance

1. Production-sensitive mutation paths preserve dual-approval enforcement.
2. All governance workflow actions (entitlements, NHI, reviews/JIT, recommendations) emit audit evidence.
3. Least-privilege recommendation apply flow now requires operator decision reasoning in UI to improve evidence quality.
4. Gateway governance evidence export is role-gated (`GATEWAY_READ_ROLES`) and emits explicit `gateway.governance.evidence.export` audit evidence for attestation traceability.
5. OpenAI-compatible chat endpoint is fail-closed by role (`Platform Admin`, `AI Ops Approver`, `Agent Owner`) and deny decisions are audit-evidenced.

### Cloud and AWS Architect Conformance

1. Tenant/environment scoping remains explicit across governance endpoints and UI filters.
2. JIT remains time-bound with explicit expiry semantics to reduce standing privilege risk.
3. Recommendation workflows favor downscoping or disablement of unused grants rather than automatic privilege expansion.
4. Evidence export is bounded by per-action event limits and fixed action taxonomy, avoiding unbounded cross-domain evidence scans.
5. Chat endpoint baseline is non-streaming and deterministic to reduce uncontrolled execution-path complexity during phased rollout.

### IAM and Governance Conformance

1. Access lifecycle now supports discovery, review, JIT exception, and remediation flows.
2. Reviewer and approver actions are role-gated and audit-backed.
3. Entitlement and recommendation workflows preserve separation-of-duties controls for production operations.
4. Governance evidence export now centralizes attestation payload generation server-side to reduce client-side assembly drift and preserve consistent IAM evidence semantics.

### Clean Architecture and Delivery Conformance

1. Delivery remained additive and capability-scoped (PR-1 through PR-4).
2. Contracts are typed in schemas, persistence is Alembic-managed, and UI surfaces follow existing control-center patterns.
3. Endpoint changes, UI coverage maps, and operator docs are synchronized per documentation source-of-truth rules.
4. PR-5 evidence export remained additive with no schema migration, using existing `audit_events` data and typed gateway schema contracts.

## Impact Analysis (PR-5 Gateway Governance Evidence Export)

### Security and Governance Impact

1. Positive: Provides a deterministic, API-backed evidence bundle path for gateway governance attestation, reducing manual/fragmented evidence collection.
2. Positive: Enforces read-role authorization and emits explicit export audit events (`gateway.governance.evidence.export`) for oversight and forensic reconstruction.
3. Residual: Evidence bundles include actor and resource identifiers from audit records; least-privilege reviewer-role assignment and controlled export handling remain required.

### Backend and Data Impact

1. Added endpoint: `POST /gateway/governance/evidence/export`.
2. Added typed request/response schemas for filter context, action summaries, and event payload.
3. No new tables or Alembic migration required; endpoint reads bounded slices from existing `audit_events`.
4. Query bounds (`limit_per_action`) and fixed gateway action taxonomy reduce performance and abuse risk compared to unbounded audit scans.

### UI and Operator Workflow Impact

1. Routing & Gateway governance evidence card now uses the dedicated backend export endpoint for both summary load and JSON export.
2. Operators receive consistent action-level summary and bundle metadata (`export_id`, `export_uri`, `exported_at`) aligned with governance-review workflows.

### Test and Validation Impact

1. Added regression coverage for endpoint bundle generation and audit evidence emission.
2. Added regression coverage for `decision_outcome` filter contract behavior.
3. Frontend syntax and smoke checks continue to pass with endpoint-aware workflow assertions.

## Impact Analysis (PR-6 OpenAI-Compatible Chat Baseline)

### Security and Governance Impact

1. Positive: Introduces a first-class OpenAI-compatible inference entrypoint while preserving strict role-based access controls.
2. Positive: Both allow and deny paths emit `gateway.chat.completions` audit evidence for operational forensics and governance reporting.
3. Positive: Provider-prefixed model requests enforce tenant entitlement context (`tenant_id`) before execution path proceeds.
4. Provider-depth forwarding is now implemented for `/v1/chat/completions`, `/v1/responses`, `/v1/embeddings`, `/v1/messages`, `/v1/images*`, and `/v1/rerank` via `app/services/gateway_inference.py`, with credential resolution from agent bindings, catalog defaults, platform/gateway bindings, environment variables, and gateway cursor token fallback. Simulation mode remains available when `GATEWAY_INFERENCE_SIMULATION=true` (default) and no upstream credential is configured.

## Impact Analysis (PR-7 OpenAI-Compatible Responses Baseline)

### Security and Governance Impact

1. Positive: Adds a second OpenAI-compatible inference entrypoint while preserving fail-closed role checks and immutable audit evidence.
2. Positive: Both allow and deny paths emit `gateway.responses.create` audit events for governance and forensic traceability.
3. Positive: Provider-prefixed model requests preserve tenant entitlement enforcement requirements.
4. Provider-depth forwarding is now implemented for responses alongside chat completions; residual gap is full provider-specific edge-case parity (streaming tool deltas, audio binary ingest, realtime websocket transport).

### Backend and Data Impact

1. Added endpoint: `POST /v1/responses`.
2. Added typed gateway schemas for OpenAI-compatible responses request and response contracts.
3. Added cost telemetry persistence (`CostEvent` with `endpoint_family=responses`) for FinOps continuity.
4. No schema migration required (additive router/schema updates only).

### Test and Validation Impact

1. Added contract tests for `/v1/responses` success response shape and token-usage fields.
2. Added tests for `max_output_tokens` length finish-reason behavior.
3. Added tests for `tools` + `tool_choice` (string and object forms) tool-call behavior and invalid tool/tool-choice contract rejection.
4. Added deny-path audit test for forbidden role attempts.
5. Added provider-prefixed model tenant requirement test.

## Impact Analysis (PR-8 OpenAI-Compatible Lifecycle and Files Metadata Baseline)

### Security and IAM Impact

1. Positive: Responses lifecycle retrieval/list endpoints are role-gated to inference roles, and delete operations are restricted to admin roles for stronger least-privilege separation.
2. Positive: Files baseline stores metadata only (no binary payload persistence in this baseline), reducing immediate data-at-rest exposure and cloud storage blast radius.
3. Positive: New actions (`gateway.responses.retrieve/list/delete`, `gateway.files.create/retrieve/list/delete`) are audit-evidenced and included in governance evidence export coverage.
4. Positive: Agent Owner scope is now enforced at object level for responses/files lifecycle read paths: owners can access only records they created, while Auditor/Security/Platform roles retain governed cross-owner read capability.
5. Positive: Delete paths now support owner-or-admin semantics with object-level owner scope checks and production dual-approval guardrails (Security Approver co-sign) to reduce destructive-operation risk.

### Backend and Data Impact

1. Added response lifecycle persistence model for API-compatible response records.
2. Added files metadata persistence model for API-compatible file lifecycle tracking.
3. Added role-gated retrieval/list/delete endpoints for both response and file resources.

### Validation Impact

1. Added lifecycle tests for response retrieve/list/delete including post-delete 404 contract.
2. Added files lifecycle tests for create/list/retrieve/delete including forbidden-role delete guard.
3. Added scope-hardening tests for Agent Owner cross-owner deny behavior and audit deny evidence on `gateway.responses.retrieve` and `gateway.files.retrieve`.
4. Added delete hardening tests for owner cross-scope deny behavior and production dual-approval requirements on `/v1/responses/{response_id}` and `/v1/files/{file_id}`.

### Backend and Data Impact

1. Added endpoint: `POST /v1/chat/completions`.
2. Added typed gateway schemas for OpenAI-compatible request and response contracts.
3. Added cost telemetry persistence (`CostEvent` with `endpoint_family=chat.completions`) for AI FinOps traceability.
4. No schema migration required (additive router/schema changes only).

### Test and Validation Impact

1. Added contract test for success response shape and token-usage fields.
2. Added tests for `response_format` compatibility, `max_tokens` length finish-reason behavior, and invalid `stop` contract rejection.
3. Added deny-path audit test for forbidden role attempts.
4. Full backend regression baseline remains green after coverage-map alignment.

## Target Capability Set (AI Gateway Only)

### A. Authorization Explainability (Priority 1)

Add explicit backend explain endpoint for gateway decisions:

- `POST /gateway/authz/explain`
- Input: actor context, action, resource context.
- Output: effective role chain, scope checks, policy checks, final decision, remediation hints.

UI:

- Security or Routing panel action to run explain simulation before production changes.

### B. Action-Level Gateway Entitlements (Priority 1)

Add policy model to govern fine-grained gateway actions by scope.

- Enforce on write and execution endpoints.
- Keep backward-compatible default mapping for current roles.

### C. NHI Security for Gateway Credentials (Priority 1)

Add inventory and hygiene controls for service identities used by gateway:

- owner required,
- max credential age,
- stale/unused key detection,
- environment scoping.

### D. Access Reviews + JIT Access (Priority 2)

Add campaign workflow for high-risk gateway entitlements.

- review queue sorted by risk,
- time-bound JIT grant workflow,
- automatic expiry and audit evidence.

### E. Least-Privilege Recommendations (Priority 2)

Use observed gateway activity to suggest downscoping.

- remove unused model/tool permissions,
- reduce environment/tenant scope,
- recommend route/key privilege tightening.

## Proposed API Additions

1. `POST /gateway/authz/explain`
2. `GET /gateway/entitlements`
3. `PUT /gateway/entitlements/{entitlement_id}`
4. `GET /gateway/nhi/inventory`
5. `GET /gateway/nhi/hygiene`
6. `POST /gateway/access-reviews/campaigns`
7. `GET /gateway/access-reviews/campaigns/{campaign_id}`
8. `POST /gateway/jit-requests`
9. `POST /gateway/jit-requests/{request_id}/approve`
9a. `GET /gateway/jit-requests` / `GET /gateway/jit-requests/{request_id}` (implemented)
9b. `POST /gateway/jit-requests/{request_id}/revoke` / `POST /gateway/jit-requests/expire-tick` (implemented)
9c. `GET/PUT /gateway/jit-decision-notify/config` + `POST /gateway/jit-requests/{id}/notify` + `GET|POST /gateway/jit-actions/{token}` (email/external REST decide; implemented)
10. `GET /gateway/least-privilege/recommendations`
11. `POST /gateway/least-privilege/recommendations/{recommendation_id}/apply`

All production-affecting mutations remain guarded by:

- role + scope checks,
- MFA where required,
- dual approval for designated prod operations.

## Proposed Data Model Additions (Design Stage)

1. `gateway_entitlements`
- Stores action-level grants and scope boundaries.

2. `gateway_nhi_inventory`
- Service identity/key metadata, owner, lifecycle timestamps.

3. `gateway_access_review_campaigns`
- Campaign metadata and status.

4. `gateway_access_review_items`
- Per-entitlement review tasks and outcomes.

5. `gateway_jit_access_requests`
- Temporary grant requests, approver decisions, expiry, optional owner scope for minted credentials, and `issued_virtual_key_id` linkage.

6. `gateway_least_privilege_recommendations`
- Recommendation records, confidence, apply status.

7. `virtual_keys.jit_request_id` (implemented)
- Links short-lived virtual keys minted on JIT approve; inference auto-blocks when the grant or key expiry elapses.

## Agent Task Contract by Capability

Each capability should be delivered by agents using the same task template.

Task template:

1. Add schemas in `backend/app/schemas.py`.
2. Add endpoint logic in `backend/app/routers/gateway.py`.
3. Add/extend tests in `backend/tests/test_phase0_phase1.py`.
4. Add one Routing & Gateway card in `frontend/index.html`.
5. Add handlers/bindings in `frontend/app.js`.
6. Update docs:
  - `backend/docs/governance/api-inventory-and-ui-map.md`
  - `backend/docs/governance/ui-api-design-coverage-map.md`
  - `frontend/README.md`
7. Run validation:
  - `python3 -m pytest` (targeted then full when feasible)
  - `node --check frontend/app.js`

Acceptance checks (agent-verifiable):

1. Endpoint returns typed contract and expected decision/error semantics.
2. Role + scope + prod dual-approval behavior is test-covered.
3. Allow and deny audit evidence exists where relevant.
4. UI can create/read/update the capability without manual JSON patching in browser devtools.
5. Docs reflect the exact endpoint and UI workflow.

## Alembic-First Migration Plan (Mandatory)

If/when database schema changes are implemented, migration must follow Alembic (no direct schema drift).

### Migration Requirements

1. Create migration scripts for each new table/index/constraint.
2. Keep Alembic revision IDs <= 32 characters.
3. Make migrations idempotent where practical (repo startup may invoke `Base.metadata.create_all`).
4. Include explicit downgrade paths.
5. Validate migration on clean DB and existing DB states.

Agent migration checklist:

1. Generate migration for additive schema only.
2. Keep revisions short and deterministic.
3. Add existence guards for table/index creation where needed.
4. Add downgrade operations and test both directions.
5. Do not ship endpoint code that depends on schema not yet migrated.

### Recommended Migration Sequence

1. Add foundational tables (`gateway_entitlements`, `gateway_nhi_inventory`).
2. Add review + JIT workflow tables.
3. Add recommendation table and supporting indexes.
4. Add non-breaking backfill scripts.
5. Switch enforcement flags from observe to enforce in phased rollout.

### Rollback Strategy

- Phase flags to disable enforcement first.
- Revert app logic to legacy role-only checks if needed.
- Run Alembic downgrade only when required by incident plan.

## Security and Audit Control Changes

1. New `action_type` audit events for explain/review/JIT/recommendation flows.
2. Deny-path audit for all privileged mutation denials.
3. Decision trace IDs standardized for gateway authorization decisions.
4. Endpoint-level control-to-audit mapping documented in governance inventory.

## UI Theme and Consistency Plan (Pending Slices)

For remaining gateway governance slices (entitlements, NHI inventory/hygiene, access reviews/JIT, least-privilege recommendations):

1. Place operator workflows in existing Routing & Gateway section first; add Security view cross-links only when needed.
2. Reuse current table/action conventions (`Use`, `Approve`, `Reject`, `Apply`) and mono evidence outputs.
3. Keep forms compact and stateful with explicit load/save/readback cycles.
4. Keep error/success feedback style consistent with current result-message patterns.
5. Avoid introducing alternate design systems or inconsistent component semantics.

## Test Strategy

### Backend

- Unit tests for authz decision engine and scope matching.
- Integration tests for allow/deny and dual-approval paths.
- Migration tests for upgrade/downgrade and idempotence behavior.

### Frontend

- Form validation and error path tests for new gateway governance panels.
- Role-based visibility and action-state tests.

### Security Regression

- Cross-tenant access denial tests.
- Same actor/approver conflict tests.
- Stale credential and over-permission detection tests.

## Rollout Plan

Phase 0 (Observe):

- Explain endpoint + read-only entitlement views.
- No hard enforcement changes.

Phase 1 (Controlled Enforcement):

- Enforce action-level authz on selected high-risk operations in non-prod.
- Activate NHI hygiene alerts.

Phase 2 (Production Enforcement):

- Enforce across prod mutation paths with dual approval where required.
- Launch access reviews and JIT workflows.

Phase 3 (Optimization):

- Enable least-privilege recommendations and controlled auto-remediation.

## Minimal PR Blueprint (for Agents)

Use this blueprint to keep development quick and understandable:

1. PR-1: Entitlements read/update MVP
  - API: `GET/PUT /gateway/entitlements`
  - UI: Entitlements card
  - DB: `gateway_entitlements`

2. PR-2: NHI inventory/hygiene MVP
  - API: `GET /gateway/nhi/inventory`, `GET /gateway/nhi/hygiene`
  - UI: NHI inventory/hygiene card
  - DB: `gateway_nhi_inventory`

3. PR-3: Access reviews + JIT MVP
  - API: campaigns + JIT request/approve
  - UI: Reviews/JIT card
  - DB: `gateway_access_review_campaigns`, `gateway_access_review_items`, `gateway_jit_access_requests`

4. PR-4: Least-privilege recommendations MVP
  - API: recommendation read/apply
  - UI: Recommendations card
  - DB: `gateway_least_privilege_recommendations`

## Impact Analysis (PR-1 Entitlements MVP)

This section captures concrete impact for the first implementation slice (`GET/PUT /gateway/entitlements`).

### Security and Governance Impact

1. Positive:
  - Introduces explicit action-level entitlement records with scope boundaries (`tenant_id`, `environment`, optional route/tag/model/tool dimensions).
  - Keeps production-sensitive updates behind existing dual-approval controls by environment.
  - Adds auditable read/update activity events for entitlement operations.

2. Residual risk:
  - Endpoint currently manages entitlements; full runtime enforcement across all gateway execution paths is planned in subsequent slices.
  - Misconfigured allowed-role sets remain an operator risk, mitigated by role validation and audit visibility.

### Backend and Data Impact

1. New data surface:
  - Adds `gateway_entitlements` table with indexed lookup for action/scope and route/tag filtering.
  - Stores normalized role lists as JSON text for deterministic readback and diffing.

2. Runtime behavior:
  - No disruptive change to existing route execution behavior in PR-1.
  - Adds new gateway control-plane API paths with bounded list pagination and existing actor-context checks.

3. Migration posture:
  - Alembic-managed additive migration with idempotent table/index creation guards.
  - Explicit downgrade path removes indexes then table.

### UI and Operator Workflow Impact

1. Adds one new Routing & Gateway card for entitlement list/filter and save operations.
2. Reuses existing card/form/table patterns to minimize operator retraining.
3. Enables route-policy context reuse by pre-populating entitlement form/filter from selected route rows.

### Test and Validation Impact

1. Adds integration tests for entitlement upsert/readback and production dual-approval enforcement.
2. Requires ongoing regression validation with existing gateway authz/route workflow tests to detect policy drift.

## Open Decisions

1. Scope taxonomy granularity for model/tool entitlements.
2. Default reviewer assignment policy for access review campaigns.
3. Auto-apply threshold and approval requirements for recommendations.

## Acceptance Criteria

1. Explain endpoint returns complete decision trace for gateway actions.
2. Action-level entitlements can be managed and enforced by scope.
3. NHI inventory includes ownership and hygiene status for gateway identities.
4. Access review and JIT workflows are auditable end-to-end.
5. All DB changes are Alembic-managed with tested upgrade/downgrade scripts.
6. Governance docs remain synchronized per documentation source-of-truth.
