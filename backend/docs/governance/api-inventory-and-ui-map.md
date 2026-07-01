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
16. Browser Security (GuardBridge)
17. Flow Orchestration

## Coverage Legend

- Full: primary operator workflow exists in the UI.
- Partial: only a subset of the API is represented in the UI.
- Gap: no UI workflow exists yet.

## API Inventory

### `app/routers/gateway.py`

| Method | Route                                  | UI Coverage | Notes                                                                      |
| ------ | -------------------------------------- | ----------- | -------------------------------------------------------------------------- |
| GET    | `/v1/vector_stores`                    | Partial     | No dedicated OpenAI Gateway Ops panel — Memory & Context Platform Configuration is control plane. |
| POST   | `/v1/vector_stores`                    | Partial     | No dedicated OpenAI Gateway Ops panel — Memory & Context Platform Configuration is control plane. |
| PATCH  | `/v1/vector_stores/{vector_store_id}`    | Partial     | No dedicated OpenAI Gateway Ops panel — Memory & Context Platform Configuration is control plane. |
| DELETE | `/v1/vector_stores/{vector_store_id}`   | Partial     | No dedicated OpenAI Gateway Ops panel — Memory & Context Platform Configuration is control plane. |

### `app/routers/agents.py`

| Method | Route                                  | UI Coverage | Notes                                                                      |
| ------ | -------------------------------------- | ----------- | -------------------------------------------------------------------------- |
| GET    | `/agents/register-options`             | Full        | Register tab loads enabled agent types from active provider configuration. |
| POST   | `/agents`                              | Full        | Covered by Agents workspace create/register flows.                         |
| POST   | `/agents/register`                     | Full        | Covered by Agents workspace create/register flows.                         |
| PATCH  | `/agents/{agent_id}/owner`             | Full        | Covered by owner transfer actions in Agents workspace.                     |
| GET    | `/agents/{agent_id}/ownership-history` | Full        | Covered by ownership history table.                                        |
| GET    | `/owners/{owner_id}/agents`            | Full        | Covered by owner-scoped list.                                              |

### `app/routers/agent_configs.py`

| Method | Route                                          | UI Coverage | Notes                                        |
| ------ | ---------------------------------------------- | ----------- | -------------------------------------------- |
| GET    | `/agent-configs`                               | Full        | Agent Configuration Studio list.             |
| GET    | `/agent-configs/{agent_key}/credential-status` | Full        | Agent credential binding readiness (masked). |
| PUT    | `/agent-configs/{agent_key}`                   | Full        | Agent Configuration Studio save/edit.        |
| DELETE | `/agent-configs/{agent_key}`                   | Full        | Agent Configuration Studio delete.           |

### `app/routers/runtime_config.py`

| Method | Route                                        | UI Coverage | Notes                                                 |
| ------ | -------------------------------------------- | ----------- | ----------------------------------------------------- |
| POST   | `/runtime-config/validate`                   | Full        | Runtime Config validation tools.                      |
| GET    | `/runtime-config/validation-rules`           | Full        | Rules table with templates and validation.            |
| POST   | `/runtime-config/validation-rules`           | Full        | Super Admin rule catalog create.                      |
| PUT    | `/runtime-config/validation-rules/{rule_id}` | Full        | Super Admin rule catalog update (built-in or custom). |
| DELETE | `/runtime-config/validation-rules/{rule_id}` | Full        | Super Admin custom rule delete.                       |
| GET    | `/runtime-config`                            | Full        | Runtime Config list.                                  |
| PUT    | `/runtime-config/{config_key}`               | Full        | Runtime Config upsert.                                |
| DELETE | `/runtime-config/{config_key}`               | Full        | Runtime Config delete.                                |

### `app/routers/auth.py`

| Method | Route                                                                | UI Coverage | Notes                                                                                                                             |
| ------ | -------------------------------------------------------------------- | ----------- | --------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/auth/policies/session`                                             | Full        | Security governance panel supports policy readback.                                                                               |
| PATCH  | `/auth/policies/session`                                             | Full        | Security governance panel supports policy updates.                                                                                |
| GET    | `/auth/policies/session/revisions`                                   | Full        | Security governance panel lists policy revisions.                                                                                 |
| POST   | `/auth/policies/session/rollback`                                    | Full        | Security governance panel supports revision rollback.                                                                             |
| POST   | `/auth/sso/providers`                                                | Full        | Security SSO lifecycle panel supports provider create.                                                                            |
| PATCH  | `/auth/sso/providers/{provider_id}`                                  | Full        | Security SSO lifecycle panel supports provider update.                                                                            |
| POST   | `/auth/sso/providers/{provider_id}/test`                ... [truncated]
