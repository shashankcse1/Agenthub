# Platform Model Availability — UI Unification Impact Analysis

**Document ID:** GOV-MODEL-AVAIL-001  
**Status:** Implemented  
**Related:** `generic-provider-configuration-review-and-impact-analysis.md` (GOV-GPC-FINAL-001), `api-inventory-and-ui-map.md`, `ui-api-design-coverage-map.md`

## Purpose

Define **one canonical register** for which AI models appear in **all operator UI dropdowns** across providers, and record the impact of replacing ad-hoc frontend merges with that register.

## Problem (before)

| Source | Used by | Risk |
|--------|---------|------|
| `GET /providers/models?status=active` | Agents, partial gateway | Catalog-only but not unified API |
| Cost catalog merge | Gateway ops loader | Non-catalog models appeared in UI |
| Runtime token rates merge | Gateway ops loader | Orphan model IDs in pickers |
| Key `allowed_models` merge | Gateway ops loader | Key scope leaked into global pickers |
| Route policy fallback merge | Gateway ops loader | Route-only models in unrelated forms |
| Client Cursor defaults seed | Gateway ops loader | Hardcoded models bypass governance |
| Per-form `loadSupportedModelOptions` | Agents, Agentic, Register | Duplicate fetch logic |

**Result:** Operators could not define “available models” in one place; UI lists diverged from catalog governance.

## Solution (after)

### Single source of truth

| Layer | Mechanism |
|-------|-----------|
| **Definition** | `SupportedModelCatalogEntry` — register models under **Providers → Models** with `status` (`active`, `beta`, `disabled`, `deprecated`) and optional **approval** workflow |
| **Policy** | Runtime keys `platform.ui_models.catalog_statuses`, `platform.ui_models.require_approval`, `platform.ui_models.enforce_tenant_entitlements` |
| **API** | `GET /providers/models/available` — canonical UI register with `model_ref` (`provider/model`), rank, policy echo, audit `platform.models.available.read` |
| **Frontend cache** | `loadPlatformAvailableModels()` → `platformAvailableModelsCache` → all `[data-gateway-model-select]` and `loadSupportedModelOptions()` |

### What was NOT duplicated

- Tenant entitlements CRUD — unchanged; optional filter when `enforce_tenant_entitlements=true`
- Gateway inference enforcement — unchanged (`_require_tenant_model_entitlement` in `gateway.py`)
- Cost catalog — still used for **pricing** views, not UI model pickers
- Supported model admin CRUD — still `GET/POST/PUT/DELETE /providers/models`

## UI surfaces unified

| Console | Controls | Data source (after) |
|---------|----------|---------------------|
| **Providers** | UI Model Availability Register | `GET /providers/models/available` |
| **Providers** | Supported Models Catalog (define enable/disable) | `POST/PUT /providers/models` (`status`) |
| **Providers** | Tenant Model Entitlements | Entitlements + optional UI policy flag |
| **Agents** | Model ID, bootstrap model | `loadSupportedModelOptions` → available API |
| **Agentic** | Contract model select | Same cache |
| **Playground** | Selected model, candidate models | `[data-gateway-model-select*]` |
| **Routing & Gateway** | All ops model selects, key allowed models, fallback chain model column, entitlements/fallback model fields | Same cache |
| **Cost** | Calculator model select | Unchanged (cost catalog); not merged into global picker |

## Operator workflow — enable / disable models globally

1. **Providers → Models → Supported Models Catalog**  
   - **Enable:** `status` = `active` or `beta`  
   - **Disable:** `status` = `disabled` or `deprecated`  
   - Optional: **Apply Approval Decision** when `platform.ui_models.require_approval=true`

2. **Providers → UI Model Availability Register → Load Availability**  
   - Verify model appears or is excluded per policy

3. **Refresh UI** — sign-in auto-load or **Load Configured Models** (Routing & Gateway)

## Runtime policy keys

| Key | Default | Effect |
|-----|---------|--------|
| `platform.ui_models.catalog_statuses` | `["active","beta"]` | Which catalog statuses appear in UI |
| `platform.ui_models.require_approval` | `false` | When `true`, only `approval_status=approved` models appear |
| `platform.ui_models.enforce_tenant_entitlements` | `false` | When `true`, UI list filters to tenant-active entitlements |

## Impact by role

| Lens | Impact | Risk |
|------|--------|------|
| **Operator** | One register; predictable dropdowns | Low — must register models before they appear |
| **Security** | No orphan models from cost/key/route merges in UI | Low |
| **Platform engineering** | Single service `platform_available_models.py` | Low |
| **CISO** | Approval gate available via runtime flag | Medium accepted — default off in dev |
| **Agent Owner** | Can read available models via expanded read roles | Low |

## Test matrix

| ID | Scenario | Command |
|----|----------|---------|
| MA-01 | Available API returns active, excludes disabled | `pytest tests/test_platform_available_models.py -q` |
| MA-02 | Agent Owner read access | `test_platform_available_models_auditor_can_read` |
| MA-03 | Frontend syntax | `node --check frontend/app.js` |
| MA-04 | UI register smoke | Providers → Load Availability |

## Deferred

- Auto-sync cost catalog models into supported catalog (still manual register)
- Per-console override pickers (intentionally removed)
- Runtime approval requirement default `true` in prod (operator config, not code default)

## Sign-off

| Role | Status |
|------|--------|
| Platform Engineering | Implemented |
| Security Architecture | Policy flags documented |
| CISO | Optional approval gate — enable in prod via runtime config |
