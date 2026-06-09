# Configuration and Control DB Migration Plan

## Objective
Move non-startup configuration and operational control from code/env defaults into database-backed runtime controls where safe.

## Deep Research Inventory

### Already DB-backed
- Auth session governance policy: `auth_policy_configs`, `auth_policy_config_revisions`.
- Runtime defaults: `runtime_config` (gateway timeout/fallback and workload identity defaults).
- Agent runtime settings: `agent_configs`.
- Compliance control mappings and evidence records.

### Newly moved in this change
- Rate-limit control rules are now DB-overridable via `runtime_config` keys:
  - `rate_limit.rules_exact_json`
  - `rate_limit.rules_wildcard_json`
  - `rate_limit.rules_refresh_seconds`
- Auth policy revisions default page size is now DB-overridable via `runtime_config` key:
  - `auth.policy.revisions_default_limit`
- Compliance control catalog metadata is now DB-overridable via `runtime_config` keys:
  - `compliance.control_catalog_json`
  - `compliance.default_control_mappings_json`
- Observability non-secret default tuning is now DB-overridable via `runtime_config` keys:
  - `observability.logs.default_limit`
  - `observability.schema.default_sample_size`
- Security CORS allow-origins policy is now DB-overridable via `runtime_config` key:
  - `security.cors_allow_origins_csv`
- Workload identity token exposure behavior is now DB-governed via sensitive `runtime_config` key (dual approval required):
  - `workload_identity.expose_access_token`
- UI view feature toggles are now DB-driven via `runtime_config` keys with optional environment suffix:
  - `ui.feature.<view>.enabled`
  - `ui.feature.<view>.enabled.<environment>`
- Middleware keeps safe in-code fallback defaults when DB values are missing/invalid.

### Keep environment/startup-only (by design)
- `DATABASE_URL` and DB connectivity bootstrap.
- Session signing secrets and key material (`SESSION_TOKEN_SECRET`, `SESSION_TOKEN_SIGNING_KEYS`).
- Runtime environment mode (`APP_ENV`/`ENVIRONMENT`) and security posture toggles tied to trust boundary.
- Redis connection wiring for distributed limiter backend.

## DB Control Patterns
- Principle: "DB first with secure fallback" for mutable operational controls.
- Pattern implemented:
  1. Load controls from DB with TTL cache.
  2. Validate and parse typed structure.
  3. On parse/read failure, keep prior in-memory controls or static defaults.
  4. Never break request path due to control read failure.

## Runtime Config Validation Hardening
- Added `POST /runtime-config/validate` for pre-save structured config checks.
- `PUT /runtime-config/{config_key}` now enforces validation server-side for supported structured keys.
- Added `GET /runtime-config/validation-rules` so UI/operators can discover enforced key constraints.
- Current validated key families:
  - `rate_limit.rules_exact_json`
  - `rate_limit.rules_wildcard_json`
  - `rate_limit.rules_refresh_seconds`
  - `gateway.default_global_timeout_ms`
  - `gateway.default_max_fallback_hops`
  - `workload_identity.default_expires_in_seconds`
  - `workload_identity.default_http_timeout_seconds`
  - `workload_identity.expose_access_token`
  - `security.cors_allow_origins_csv`
  - `auth.policy.revisions_default_limit`
  - `observability.logs.default_limit`
  - `observability.schema.default_sample_size`
  - `compliance.control_catalog_json`
  - `compliance.default_control_mappings_json`
  - `ui.feature.<view>.enabled[.<environment>]`

## Runtime Config Payload Examples

### `rate_limit.rules_exact_json`
```json
[
  {"method": "POST", "path": "/auth/sessions", "max_requests": 20, "window_seconds": 60},
  {"method": "GET", "path": "/cost/live", "max_requests": 30, "window_seconds": 10}
]
```

### `rate_limit.rules_wildcard_json`
```json
[
  {"method": "POST", "path_prefix": "/auth/basic/config/", "max_requests": 10, "window_seconds": 300},
  {"method": "POST", "path_prefix": "/keys/", "max_requests": 20, "window_seconds": 300}
]
```

### `rate_limit.rules_refresh_seconds`
```text
30
```

## Next Migration Candidates
1. Extend runtime-config validation coverage to additional structured keys as they are introduced.

## Guardrails
- Do not move secrets/private keys into DB runtime config unless encryption, rotation, and strict key management are in place.
- Keep bootstrap-critical controls in env to avoid startup deadlocks.
- Every DB-backed control should have schema/format validation and regression tests.
