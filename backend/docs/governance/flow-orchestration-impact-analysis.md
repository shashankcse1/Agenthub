# Flow Orchestration Impact Analysis (GOV-FLOW-ORCH-001)

## Purpose

Documents the n8n-style Flow Orchestration domain: multi-step workflow definitions, governed execution, operator console, and role-lens controls for Phase 1 (step/chain builder; visual drag-drop canvas deferred to Phase 2).

## Scope

| Module | Impact |
|---|---|
| MOD-GATEWAY | LLM chat nodes invoke gateway chat completion; MCP tool nodes use MCP registry |
| MOD-RUNTIME | HTTP allowlist, max nodes, prod approval flags via runtime config |
| MOD-OBS | Run trace_id correlation, step_results_json, audit events |
| MOD-EXT | Webhook trigger path refs; HTTP outbound nodes |

## Supported Node Types (Phase 1)

| Type | Runtime | Notes |
|---|---|---|
| `llm_chat` | Simulated/stub when inference simulation enabled | Model from catalog; secrets via `binding_id` only; optional `route_id`, `prompt_registry_id`, `max_tokens`, `response_format` (`text`/`json_object`), `cache_mode` (`inherit`/`bypass`/`force`) |
| `mcp_tool` | Validated against MCP registry; stub execution | `server_id` + `tool_name` |
| `http_request` | Host allowlist enforced; no real outbound in dry_run | Default empty allowlist = deny all external |
| `condition` | Expression evaluation (safe subset) | Branch routing in stub executor; JSON path fields (`source_node_id`, `json_path`, `operator`, `compare_value`) stored in config; Studio builds `expression` for Phase 2 runtime |
| `schedule_trigger` | Cron stored in flow trigger; validated | Not a graph node in v1 execution |
| `webhook_trigger` | Signed token via binding ref | Trigger metadata only |
| `memory_read` / `memory_write` | Gateway memory scope validation | Stub read/write in executor |
| `vector_query` | Registry membership validated; stub search output | `store_id` must exist in `gateway.vector_stores_json`; Studio picker loads `GET /gateway/vector-stores` |
| `vector_ingest` | Registry membership validated; stub ingest output | `store_id` + `content_template`; optional `document_id`; no inline API keys |
| `embedding_create` | Stub embedding output | `model_id` + `input_template`; optional `binding_id`; LiteLLM-aligned gateway embedding parity |
| `rag_query` | Registry membership validated; stub RAG retrieval output | `store_id` + `query_template`; optional `top_k`, `binding_id`; `store_id` must exist in `gateway.vector_stores_json` |
| `wait_delay` | Stub wait output | `delay_seconds` integer 1–3600; control-flow timing node |
| `guardrail_evaluate` | Stub guardrail pass output | `key_id` + `input_template`; optional `guardrail_policy_id`; gateway key guardrail parity |
| `email_send` | Registry channel validated; stub simulated send | `channel_id` must exist in `gateway.notification_channels_json` (enabled + binding); Studio picker loads `GET /gateway/notification-channels`; see GOV-FLOW-NOTIFY-001 |
| `sms_send` | Registry channel validated; stub simulated send | Same as `email_send` without `subject_template`; recipient templates scanned for inline secrets |
| `human_approval` | Creates approval gate record | Prod requires dual-approval headers on run; optional `approver_role_json_path` / `approver_id_json_path` from prior step JSON (config only until Phase 2 runtime) |
| `parallel_fork` | Splits graph into parallel branches | Requires matching `parallel_join` with same `group_id`; 2–5 outgoing branches |
| `parallel_join` | Merges parallel branches | Must reference `fork_node_id`; all branch paths must reach join |

## Security Architect

### Authz and least privilege

- **Read** (`GET /orchestration/*`): Platform Admin, Super Admin, Master Admin, Auditor, AI Ops Approver.
- **Write** (`POST/PUT/DELETE /orchestration/flows*`): Platform Admin, Super Admin, Master Admin, Release Manager.
- **Run** (`POST .../run`): Platform Admin, Super Admin, Master Admin, AI Ops Approver.
- **Approve prod** (`POST .../approve`): Security Approver with production dual-approval headers.

### Secret handling

- Inline API keys, tokens, and passwords rejected at validate time.
- Allowed secret references: `binding_id`, `auth_binding_id`, `secret_provider_id`, `cp_ref` (credential path ref pattern).
- HTTP nodes cannot embed Authorization secrets in `headers_json`; use `auth_type` + `auth_binding_id` (Phase 2 runtime resolves via Providers credential bindings).

### HTTP outbound authentication (config contract)

| `auth_type` | Secret storage (Providers) | Runtime behavior (Phase 2) |
|---|---|---|
| `none` | — | No auth header added |
| `bearer` | Raw token in secret backend via credential binding (`secret_ref` plane) | `Authorization: Bearer {token}` |
| `basic` | JSON `{"username","password"}` in secret backend | `Authorization: Basic {base64(user:pass)}` |
| `api_key` | API key value in secret backend; `auth_header_name` in node config (e.g. `X-API-Key`) | Custom header injection |
| `oidc_client_credentials` | JSON with `client_id`, `client_secret`, `token_url`, optional `scope` | Token exchange then Bearer on outbound call |
| `workload_identity` | Credential binding with `credential_plane=workload_identity` | Federated/env-injected token (same pattern as agents) |

**MCP is not required for HTTP authentication** — reuse the existing three-layer model: secret backend → credential binding → `auth_binding_id` on the HTTP node. OIDC uses stored client credentials or workload identity, not inline tokens in flow JSON.

Flow Studio HTTP widget inspector exposes auth type + binding picker; validate rejects missing bindings and credential keys in `headers_json`.

### Abuse cases

| Abuse case | Control |
|---|---|
| Unbounded graph size | `orchestration.max_nodes_per_flow` (default 50) |
| SSRF via HTTP nodes | `orchestration.http_allowed_hosts_json` (default `[]`) |
| Prod execution without review | `approval_status=approved` required when env=prod |
| Privilege escalation via human_approval skip | Prod human_approval nodes require dual approval on run |
| Secret exfiltration in graph JSON | Schema scan rejects inline secret field names |

## CISO

### Blast radius

- Flows scoped by `environment` and optional `tenant_id`.
- Prod flows cannot run until explicitly approved; dual approval on approve and on prod runs with human_approval nodes.
- HTTP outbound default deny reduces lateral movement from compromised operator accounts.

### Prod dual-approval

- `POST /orchestration/flows/{flow_id}/approve` in prod requires Security Approver + `X-Approver-*` headers.
- Prod run with `human_approval` nodes requires dual approval at execution time.

### Residual risk

- Phase 1 executor is simulated/stub for several node types; production automation requires Phase 2 live runtime.
- Visual canvas not available; misconfiguration risk mitigated by validate endpoint and audit trail.

### Go/no-go (Phase 1)

**Go** for operator design, validation, approval workflow, audit evidence, and stub execution in non-prod.
**No-go** for unattended prod automation until Phase 2 live executor and canvas UX ship (tracked as RSK-018).

## Cloud Engineer

### Deployability

- Alembic migration `0035_orchestration_flows` + idempotent startup DDL in `main.py`.
- Runtime config keys seeded via `RUNTIME_CONFIG_DEFAULTS`.

### Observability

- Each run records `trace_id`, `step_results_json`, `error_summary`.
- Mutations emit `orchestration.flow.*` audit events with `action_context_json`.

### Rate limits

- Wildcard rules on `POST /orchestration/flows/` and `POST /orchestration/flows/*/run` (30 req / 300s per actor).

### Rollback

- Flow delete is soft-status `deprecated`; disable via `status=disabled`.
- Runtime config rollback via Runtime Config Studio restores allowlist and limits.

## Audit Architect

### Audit events

| Action | `action_type` |
|---|---|
| Flow create | `orchestration.flow.create` |
| Flow update | `orchestration.flow.update` |
| Flow delete | `orchestration.flow.delete` |
| Validate | `orchestration.flow.validate` |
| Approve | `orchestration.flow.approve` |
| Run | `orchestration.flow.run` |
| Deny (authz/validation) | `orchestration.flow.*` with `decision_outcome=deny` |

### Trace correlation

- `trace_id` on runs aligns with platform request tracing and Observability pivot.
- `action_context_json` includes `flow_name`, `trigger_type`, `environment`.

### Evidence export

- Flow runs list/detail readable by Auditor role; bundle with Compliance evidence export in Phase 2.

## Phase 2 Deferred

- Visual drag-drop canvas builder (current UI: step/chain builder only).
- **Live condition evaluation** against prior step outputs (`jsonPath(steps['node-id'].output, '$.path')` expression contract); Phase 1 stores config and simulates `matched: true`.
- **Dynamic approver resolution** from prior step JSON paths at run time (config fields exist; runtime resolver deferred).
- Live MCP/HTTP/LLM execution engine with queue workers and step output propagation.
- Webhook ingress router binding to flow triggers.

## Parallel execution (Phase 1 — shipped)

- Graph model uses `parallel_fork` / `parallel_join` control nodes with shared `group_id` in `graph_json`.
- Validation enforces fork/join pairing, 2–5 branches, and branch paths that reach the join node.
- Stub executor walks the edge graph; at each fork it runs branch subgraphs concurrently via `asyncio.gather` and records `execution_mode: parallel` in `step_results_json`.
- Flow Studio exposes **Add parallel group** on the lane canvas, side-by-side branch columns, fork/join indicators, and dissolve/add/remove branch controls.

## MCP Integration Assessment (GOV-FLOW-ORCH-001 addendum)

**Recommendation: MCP integration is not required for JSON-path conditions or approver selection from HTTP/LLM responses.**

| Capability | Built-in (HTTP / LLM / gateway) | MCP tool node |
|---|---|---|
| Prior-step JSON for conditions | Yes — Phase 2 executor reads `step_results_json` / in-memory `steps[node_id].output` from `http_request`, `llm_chat`, and gateway responses | Optional for tool-specific payloads only |
| Approver ID/role from response | Yes — same output map; no MCP hop needed | Only if approver metadata lives exclusively in an MCP tool result |
| External system actions | `http_request` to allowlisted hosts | `mcp_tool` when action is already registered in gateway MCP registry |

Use **MCP tool nodes** when the workflow must invoke a registered MCP server/tool (e.g. RAG query, governed external adapter). Use **HTTP + LLM nodes** for response-driven branching and approver extraction from REST or chat completion JSON. Do not add a dedicated MCP bridge for JSON parsing — implement a shared `jsonPath()` helper in the Phase 2 executor over normalized step outputs.

**Operator UI today:** Flow Studio condition and human-approval inspectors expose prior-step pickers and JSON path fields; expressions are persisted in flow config. Runs still use the Phase 1 stub executor until live runtime ships.

## Verification

```bash
python3 -m pytest backend/tests/test_orchestration_flows.py -q
node --check frontend/app.js
```
