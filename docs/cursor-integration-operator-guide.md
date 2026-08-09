# Cursor Integration Operator Guide

## Purpose

This guide explains how to configure, sync, validate, and audit Cursor integration for module records in the platform.

**Related agent workflows:** Competitor-gap SDLC work orders from **gateway-enhancement-agent** are implemented in this repo (TARGET_REPO). Read [AGENTS.md](../AGENTS.md) and [`.cursor/skills/gateway-competitor-sdlc/SKILL.md`](../.cursor/skills/gateway-competitor-sdlc/SKILL.md) before closing `inv-*` or `cmp-*` gaps. Module Cursor sync (below) is a separate, inventory-backed workflow.

| Workflow | Doc |
|----------|-----|
| Module register + integration sync | This guide |
| Enhancement agent work orders | [`.cursor/skills/gateway-competitor-sdlc/SKILL.md`](../.cursor/skills/gateway-competitor-sdlc/SKILL.md) |
| Agent commands / LaunchAgent | [`../gateway-enhancement-agent/docs/USAGE.md`](../gateway-enhancement-agent/docs/USAGE.md) |

## Design-Aligned Adoption Scope

Only adopt patterns that are already supported by current APIs, UI surfaces, and governance controls.

### In scope now (implement or extend)

1. Governed integration metadata and explicit sync
  - Existing support: `POST /modules/register`, `POST /modules/{module_id}/integration/sync`, `GET /modules`, `GET /modules/skills`.
  - Why in scope: already implemented with role checks and audit events.

2. Human-approved production mutations
  - Existing support: role-gated mutations and release/security approval flows in current governance model.
  - Why in scope: aligns with current dual-approval and release-gate posture.

3. Session timeline and checkpoint operations for agentic workflows
  - Existing support: Agentic certification/load-test/checkpoint flows in current UI and API inventory.
  - Why in scope: already part of operator workflows and evidence model.

4. Cost and operational visibility before execution
  - Existing support: cost catalog, pricing calculations, live cost views, route and policy safety checks.
  - Why in scope: aligned with existing cost/governance controls.

### Out of scope now (do not implement under current design)

1. Direct IDE takeover or unmanaged workstation control semantics.
2. Persistent external token storage in module metadata.
3. Non-audited autonomous write paths that bypass current approval and role gates.
4. New cross-tenant or cross-environment action channels without explicit inventory and governance coverage updates.

### Inheritance guardrails

- Reuse existing endpoints and controls before adding new API surface.
- Preserve role gating and audit evidence on every mutation.
- Keep Cursor references non-sensitive and scoped (`cursor://workspace/...`).
- Fail closed on unsupported providers, missing references, and unauthorized roles.

## Implementation Checklist (Current Design Only)

Use this checklist to implement and validate only design-aligned capabilities.

### Workstream A: Cursor module registration and governed sync

- [ ] Owner: Backend + Frontend Modules owners
- [ ] API surface:
  - `POST /modules/register`
  - `POST /modules/{module_id}/integration/sync`
  - `GET /modules`
  - `GET /modules/skills`
- [ ] UI controls:
  - Modules Register form fields `integration_provider` and `integration_reference`
  - Modules table `Sync Integration` action
  - AI Skills table integration status columns
- [ ] Security gates:
  - Admin-only mutation role enforcement on register and sync
  - Fail-closed provider allowlist validation
  - No secret material in `integration_reference`
- [ ] Audit gates:
  - `modules.register` event emitted
  - `modules.integration.sync` event emitted
  - trace id present for each mutation
- [ ] Validation commands:

```bash
cd backend && python3 -m pytest tests/test_phase0_phase1.py -k "modules_register_persists_integration_metadata_and_sync_updates_status or modules_integration_sync_requires_configured_provider or modules_read_endpoints_enforce_read_roles"
cd .. && node --check frontend/app.js
```

### Workstream B: Production mutation governance alignment

- [ ] Owner: Security + Release governance owners
- [ ] API/UI scope: existing production mutation role and approval controls only
- [ ] Security gates:
  - no new bypass path for approval-required production mutations
  - role separation maintained for mutation and approval actors
- [ ] Audit gates:
  - mutation outcomes remain queryable in audit evidence
- [ ] Validation commands:

```bash
cd backend && python3 -m pytest
```

### Workstream C: Agentic timeline/checkpoint reuse (no new external control plane)

- [ ] Owner: Agentic console owners
- [ ] API/UI scope: existing certification/load-test/checkpoint workflows only
- [ ] Security gates:
  - no cross-tenant checkpoint access path introduced
  - no unaudited resume or override paths introduced
- [ ] Audit gates:
  - evidence remains exportable and traceable for checkpoint actions
- [ ] Validation commands:

```bash
cd backend && python3 -m pytest
cd .. && node --check frontend/app.js
```

### Workstream D: Cost-aware operator decisions with existing controls

- [ ] Owner: Gateway + Cost console owners
- [ ] API/UI scope: existing cost catalog, pricing simulation, and spend visibility controls
- [ ] Security gates:
  - no sensitive token material exposed in cost telemetry
  - budget and policy enforcement remains fail-closed
- [ ] Audit gates:
  - cost mutation/evaluation events remain available for investigations
- [ ] Validation commands:

```bash
cd backend && python3 -m pytest
cd .. && node --check frontend/app.js
```

## Explicit Non-Goals for This Scope

- Do not add IDE session takeover capabilities.
- Do not add unmanaged workstation command execution paths.
- Do not persist external provider secrets in module metadata fields.
- Do not introduce new cross-tenant or cross-environment action channels without governance inventory updates first.

## Current Integration Model

Cursor integration is implemented as module metadata plus a governed sync action.

- Integration provider allowlist includes `cursor`.
- Integration state is stored on each module record.
- Sync is explicit and role-gated.
- Audit events are emitted for register and sync actions.

This flow does not store external access tokens in module metadata fields.

## Gateway Cursor Secret Configuration (Unified Secret Provider)

Configure Cursor credentials through **Providers → Secret Providers** instead of storing tokens in module metadata or the legacy Routing & Gateway cursor-token form.

Canonical endpoints:

- `POST /secrets/providers` — onboard secret provider (`db`, `vault`, `aws-secrets-manager`, `azure-key-vault`)
- `PUT /secrets/providers/{provider_id}/values` — store encrypted secret value (`db` providers only)
- `GET /secrets/providers/{provider_id}/values/{secret_ref}` — masked value status (no plaintext)
- `DELETE /secrets/providers/{provider_id}/values/{secret_ref}` — delete stored value (`db` providers)
- `GET/PUT/DELETE /gateway/cursor-secret-binding` — bind gateway to `secret_provider_id` + `secret_ref`

Deprecated compatibility endpoints (migrate off by 2026-09-01):

- `GET/PUT/DELETE /gateway/cursor-token` — returns `Deprecation: true`; writes migrate to v3 binding + db value storage

### Provider types

- `db` — platform-encrypted storage in `secret_provider_stored_values`; use secret refs like `gateway/cursor-token`
- `vault` / `aws-secrets-manager` / `azure-key-vault` — runtime fetch from external backend at `secret_ref`

### Security model

- Secret value writes require provider admin/security role and MFA.
- Gateway binding writes require gateway admin/security role; production requires dual approval.
- Plaintext secrets are never returned by read APIs (masked hints only).
- Gateway runtime config stores binding references only (v3 JSON), not token material.
- Audit events: `secret_provider.value.*`, `gateway.cursor_secret_binding.*`

### UI workflow

1. Open **Providers → Secret Providers**.
2. Create a secret provider (`db` for platform storage, or external backend type).
3. For `db` providers: use **Database Secret Values** to store the Cursor token at `gateway/cursor-token`.
4. Use **Gateway Cursor Secret Binding** to set provider ID + secret ref.
5. Verify binding status shows configured with masked hint only.
6. Use **Clear Binding** when rotating off or revoking gateway access.

CISO review evidence: `backend/docs/governance/unified-secret-provider-ciso-gap-analysis.md`

## Endpoints Used

Module metadata:

- `POST /modules/register`
- `GET /modules`
- `GET /modules/skills`
- `POST /modules/{module_id}/integration/sync`

Secret provider and gateway binding (canonical):

- `POST /secrets/providers`
- `PUT /secrets/providers/{provider_id}/values`
- `GET /secrets/providers/{provider_id}/values/{secret_ref}`
- `DELETE /secrets/providers/{provider_id}/values/{secret_ref}`
- `GET /gateway/cursor-secret-binding`
- `PUT /gateway/cursor-secret-binding`
- `DELETE /gateway/cursor-secret-binding`

Audit:

- `GET /audit/events`

## Role Requirements

- Register module: `MODULE_ADMIN_ROLES`
- Sync integration: `MODULE_ADMIN_ROLES`
- Read modules and skills: `MODULE_READ_ROLES`

In practical terms, Platform Admin or Super Admin roles are required for register and sync.

## Required Payload Rules

When registering a module:

- `artifact_signature` must start with `sig:`
- `provenance_ref` must start with `prov://`
- `integration_provider` must be in supported allowlist
- `integration_reference` is required when `integration_provider` is set
- when `integration_provider=cursor`, `integration_reference` must start with `cursor://workspace/`
- For `module_type` in `runtime`, `gateway`, `security`, `ai_skill`, `security_review_ticket` is required

## UI Workflow

1. Open the Modules workspace.
2. In Register Module:
   - Set Integration Provider to `cursor`.
   - Set Integration Reference to a scoped value such as `cursor://workspace/team-a/skills`.
3. Submit Register Module.
4. In the module table, click `Sync Integration` for the registered module.
5. Confirm fields update:
   - `integration_sync_status = synced`
   - `integration_last_synced_at` has a timestamp

## API Workflow

### 1) Register module with Cursor provider

```bash
curl -X POST "$API_BASE/modules/register" \
  -H "Content-Type: application/json" \
  -H "X-Actor-Role: Platform Admin" \
  -H "X-Actor-Id: ops-admin" \
  -d '{
    "module_name": "cursor-skill-pack",
    "module_type": "ai_skill",
    "version": "1.0.0",
    "contract_version": "v1",
    "owner_team": "platform-security",
    "compatibility_range": "*",
    "required_permissions": "[]",
    "artifact_signature": "sig:sha256:example",
    "provenance_ref": "prov://artifact/registry/cursor-skill-pack",
    "security_review_ticket": "SEC-12345",
    "integration_provider": "cursor",
    "integration_reference": "cursor://workspace/team-a/skills"
  }'
```

### 2) Sync integration

```bash
curl -X POST "$API_BASE/modules/<module_id>/integration/sync" \
  -H "Content-Type: application/json" \
  -H "X-Actor-Role: Platform Admin" \
  -H "X-Actor-Id: ops-admin" \
  -d '{
    "integration_reference": "cursor://workspace/team-a/skills"
  }'
```

### 3) Verify readback

```bash
curl -X GET "$API_BASE/modules" \
  -H "X-Actor-Role: Auditor" \
  -H "X-Actor-Id: audit-user"
```

## Expected Errors and Fixes

- `400 Unsupported integration_provider`
  - Fix: use supported provider value (`cursor`, `github`, `gitlab`, `aws`, `azure`, `gcp`).
- `400 integration_reference is required when integration_provider is set`
  - Fix: provide a non-empty `integration_reference`.
- `409 Integration provider is not configured for this module`
  - Fix: register or update module with `integration_provider` before sync.
- `403 Forbidden`
  - Fix: use an admin-equivalent role for register and sync operations.
- `400 integration_reference for cursor must start with 'cursor://workspace/'` during sync with no override
  - Cause: legacy invalid Cursor reference exists on module record.
  - Fix: re-run sync with a valid workspace-scoped `integration_reference`.

## Legacy Reference Handling

- For `integration_provider=cursor`, read APIs sanitize invalid legacy references by returning an empty `integration_reference` value.
- When a cursor legacy reference is invalid, `integration_sync_status` is returned as `invalid_reference` until corrected.
- Sync fails closed until a valid workspace-scoped Cursor reference is provided.
- In Modules UI, set a valid workspace-scoped Cursor reference in Register Module form (`integration_reference`), then click `Sync Integration` on the target row.
- For rows marked `invalid_reference (action required)`, use `Fix Cursor Reference` to prefill a workspace-scoped template in the Register Module form, review/edit it, and then click `Sync Integration`.

## Security and CISO Controls

- Least privilege:
  - Restrict register and sync operations to admin roles only.
- Data minimization:
  - Keep `integration_reference` free of secrets and tokens.
- Blast radius control:
  - Use team-scoped or workspace-scoped Cursor references, not global references.
- Auditability:
  - Verify audit events for `modules.register` and `modules.integration.sync`.

## Audit Verification

Use Audit view or API query to confirm:

- action type `modules.register`
- action type `modules.integration.sync`
- actor id and role
- resource id (`module_id`)
- trace id for correlation

## Validation Commands

Module integration slice:

```bash
cd backend && python3 -m pytest tests/test_phase0_phase1.py -k "modules_register_persists_integration_metadata_and_sync_updates_status or modules_integration_sync_requires_configured_provider or modules_read_endpoints_enforce_read_roles"
cd .. && node --check frontend/app.js
```

Enhancement agent cycle (after implementing `agent_work_order.md`):

```bash
cd "../gateway-enhancement-agent"
TARGET_REPO="$(pwd)/../new design" gateway-agent validate
```

Governance-only changes in TARGET_REPO skip agent `gateway_pytest` and `control_coverage` gates when all touched paths are under `backend/docs/governance/`.

## Operational Notes

- Integration sync currently marks metadata state as synced and records sync time.
- If future Cursor API connectivity checks are added, keep them behind role-gated, audited mutation or test endpoints.
