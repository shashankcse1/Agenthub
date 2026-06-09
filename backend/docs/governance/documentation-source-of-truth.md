# Documentation Source of Truth

## Purpose

This document defines the canonical documentation hierarchy for implementation status, security controls, and UI/API coverage. Use it before updating frontend or backend surfaces.

## Canonical Order of Authority

1. `backend/docs/governance/documentation-source-of-truth.md` (this file): governance hierarchy and sync rules.
2. `backend/docs/governance/api-inventory-and-ui-map.md`: endpoint-level truth for route coverage status.
3. `backend/docs/governance/ui-api-design-coverage-map.md`: domain-level product intent and gap status.
4. `backend/docs/governance/litellm-parity-roadmap.md`: parity planning register for pending proxy/router feature deltas.
5. `backend/AGENTS.md`: security and role contract that implementation must preserve.
6. `backend/docs/governance/agent-delivery-checklist.md`: feature/fix-level implementation evidence template across all architecture lenses.
7. `backend/docs/security/residual-and-accepted-risk-register.md`: accepted risk and compensating controls.
8. `frontend/README.md`: operator-facing UI capabilities and run instructions.
9. `backend/docs/governance/ai-gateway-identity-security-design.md`: AI Gateway target-state design and phased implementation plan.
10. `backend/docs/governance/ai-gateway-litellm-parity-gap-analysis.md`: competitive parity gap analysis focused on AI-gateway and LiteLLM-relevant features.

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
- Gateway cache policies: create/list workflows are now exposed in Routing & Gateway.
- Providers: workload identity token exchange, trust validation with evidence drilldown, workload/secret health checks, secret lease renewal and inventory, and rotate-via-secret-provider key action are now exposed in Providers.
- Security: role-binding validation and explainability workflows are now exposed in Security.
- Modules: register/list/versions, agent validate/upgrade-plan, and deprecate workflows are now exposed in Modules.
- Agentic: readiness report, contract validation, certification run/list/latest/override/export, load-test run/latest, checkpoint create/list/resume, policy auto-tune/scheduled-optimize, and policy schedule create/list/summary/detail/update/status/approve/execute/history/enable/disable/delete workflows are now exposed in Agentic.
- Observability: trace lookup, deep log filtering/search, redact mode, schema health checks, and log-to-trace drilldown actions are now exposed in Observability.
- Routing & Gateway: route provider-priority timeline history is now exposed with limit/offset timeline controls and audit-backed events.
- Routing & Gateway: MCP server registry, tool list, and governed tool call workflows are now exposed in the console.
- Cost: budget policy lifecycle create/list/edit/delete workflows are now exposed in Cost.
- Routing & Gateway: gateway-governance PR-1 through PR-4 slices are now implemented (entitlements, NHI inventory/hygiene, access reviews + JIT, and least-privilege recommendations) with synchronized API/UI/docs coverage.
- Routing & Gateway: least-privilege recommendation apply flow now requires operator decision rationale in UI for stronger CISO/IAM evidence hygiene.
- Routing & Gateway: gateway governance evidence aggregation/export workflow is now exposed via `POST /gateway/governance/evidence/export`, producing filtered JSON bundles and action-level summaries for security/CISO review.
- Routing & Gateway: OpenAI-compatible chat baseline endpoint is now exposed via `POST /v1/chat/completions` with role-gated and audit-backed behavior.
- Routing & Gateway: OpenAI-compatible responses baseline endpoint is now exposed via `POST /v1/responses` with role-gated and audit-backed behavior.
- Routing & Gateway: OpenAI-compatible responses lifecycle baseline now includes `GET /v1/responses`, `GET /v1/responses/{response_id}`, and `DELETE /v1/responses/{response_id}` with role-gated read, owner-or-admin delete semantics, and production dual-approval guardrails.
- Routing & Gateway: OpenAI-compatible files metadata baseline now includes `POST /v1/files`, `GET /v1/files`, `GET /v1/files/{file_id}`, and `DELETE /v1/files/{file_id}` with role-gated lifecycle behavior, owner-or-admin delete semantics, and production dual-approval guardrails.
- Routing & Gateway: dedicated OpenAI-Compatible Gateway Ops UI workflows are now exposed for `/v1/chat/completions`, `/v1/responses*`, and `/v1/files*`, with operator controls for lifecycle read/delete and optional production dual-approval headers; smoke coverage now includes `frontend/scripts/openai_gateway_ops_smoke.sh`.
- Routing & Gateway: explicit decision-trace evidence retrieval workflow is now exposed via `GET /gateway/decision-traces/{trace_id}` in Gateway Controls for audit/logging investigations.
- Routing & Gateway: OpenAI-compatible create responses now include risk-adaptive metadata (`risk_tier`, `risk_reasons`) for operator, AI-architect, and CISO posture review.
- OpenAPI/Swagger: high-risk mutation endpoints now include explicit summaries, governance-aware descriptions, and error response contracts across Auth, Gateway, and Providers (break-glass enable/disable, key block/unblock/rotate paths, route optimize/execute-fallback, cache invalidation, transform-request debug, authz explain, workload trust/test, and secret provider test/lease renew).
- OpenAPI/Swagger: provider onboarding and gateway governance operations now also include explicit endpoint contracts (basic-auth config create, tenant catalog create/update, workload identity provider create, secret provider create, route create/provider-priority update, cache policy create, external callback create/test/export, and governance evidence export).
- Consolidated evidence artifact captured in `backend/docs/governance/agent-delivery-checklist-openai-gateway-consolidated.md` with role-lens validation, security checks, and regression outcomes.

Remaining documented deltas:

1. Compliance evidence bundle drill-down depth remains partial.
2. Security explainability follow-up remains open for Auth domain: backend explicit Auth explain endpoint is still pending (Gateway explicit explain endpoint is now available at `/gateway/authz/explain`).

## Change Checklist

Before merge, verify:

1. `node --check frontend/app.js` passes for frontend changes.
2. `python3 -m pytest` passes for backend changes.
3. Coverage status changes in docs match actual UI controls and API calls.
4. Security-sensitive runtime changes include audit and risk-register updates.
5. Architecture-lens conformance (Security, CISO, AWS, Cloud, AI Architect, UI Expert, IAM, and Clean Architecture) is explicitly reflected in `ai-gateway-identity-security-design.md` when governance workflows change.
6. Audit/logging conformance is explicit for changed privileged flows (allow + deny evidence, correlation trace fields, and evidence export/readback paths).
7. Agent-friendly delivery artifacts are captured: scope slice notes, repeatable validation commands, and verification outcomes.
