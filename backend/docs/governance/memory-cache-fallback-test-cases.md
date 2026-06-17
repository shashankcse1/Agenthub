# Memory, Semantic Cache, and Fallback Priority — Test Cases

Operator and QA reference for the Memory & Context selling-point slice, semantic cache governance, and fallback priority chains.

**Related docs:** [e2e-requirement-api-ui-verification.md](./e2e-requirement-api-ui-verification.md), [api-inventory-and-ui-map.md](./api-inventory-and-ui-map.md)

**Automated smoke:** `frontend/scripts/gateway_memory_cache_fallback_smoke.sh`  
**Backend regression:** `backend/tests/test_gateway_memory.py`, `backend/tests/test_phase0_phase1.py` (cache + priority + simulate-fallback)

**Important:** When `gateway.cache.inference_short_circuit_enabled` is **false** (default), semantic cache records **hit/miss/bypass decisions for audit** only — it does **not** short-circuit upstream inference. When the flag is **true** and an active cache policy matches, `/v1/chat/completions` and `/v1/responses` return stored encrypted responses without provider calls.

---

## Inference Cache Short-Circuit (`gateway.cache.inference_short_circuit_enabled`)

| ID | Scenario | Steps (UI) | Expected | API / pytest |
|----|----------|------------|----------|--------------|
| CA-08 | Flag off — no short-circuit | Runtime default; repeat identical chat prompt | Provider called each time; no `cache_short_circuit: true` | `test_short_circuit_disabled_does_not_skip_inference` |
| CA-09 | Exact hit short-circuit | Enable flag + global exact policy → identical chat prompt twice | Second response has `cache_short_circuit: true`; one inference call | `test_exact_hit_short_circuits_without_provider_call` |
| CA-10 | Semantic hit short-circuit | Enable flag + semantic policy threshold 0.5 → similar prompts | Second response cached; similarity above threshold | `test_semantic_hit_above_threshold_short_circuits` |
| CA-11 | PII bypass — no store | Policy with `non_cache_data_classes: ["pii"]`; `request_tag: pii.*` | Decision bypass; no cache entry stored | `test_bypass_for_pii_data_class_does_not_store_entry` |
| CA-12 | Owner privacy scope | Owner-scoped policy; request without then with `owner_scope` | Bypass without scope; cache hit with matching owner | `test_owner_privacy_scope_requires_owner_context` |
| CA-13 | Cache entry list | Load cache entries after traffic | Metadata rows without response body | `GET /gateway/cache/entries` |
| CA-14 | Stats short-circuit fields | Load Cache Stats | `short_circuit_enabled`, `active_cache_entries` present | `test_cache_stats_includes_short_circuit_fields` |
| CA-15 | Invalidate purges entries | POST `/gateway/cache/delete` with scope | `purged_cache_entries` ≥ 0 | `test_cache_invalidate_purges_entries` |

## RAG Data Plane (`/rag/*`, `/v1/vector_stores*`)

| ID | Scenario | Steps (UI) | Expected | API / pytest |
|----|----------|------------|----------|--------------|
| RG-01 | OpenAI vector store list | API or Memory tab config load | `GET /v1/vector_stores` returns registry rows | `test_openai_vector_stores_list_and_get` |
| RG-02 | Registry POST read-only | `POST /v1/vector_stores` with store metadata | 409 `VECTOR_STORE_REGISTRY_READ_ONLY` | `test_openai_vector_store_register_is_read_only` |
| RG-03 | MCP bridge ingest/query | Configure mcp_bridge store + MCP server → RAG panel ingest then query | 200 with audit `gateway.rag.ingest` / `gateway.rag.query`; credentials not in response body | `test_rag_ingest_and_query_mcp_bridge` |
| RG-04 | RAG role gating | Auditor calls `POST /rag/query` | 403 forbidden | `test_rag_query_role_gating` |
| RG-05 | Live probe flag off | Health check without `live_probe_enabled` | No outbound HEAD/MCP probe; `live_probed` false/absent | `test_vector_store_live_probe_flag_off_skips_network` |
| RG-06 | Live probe flag on | Enable `gateway.vector_stores.live_probe_enabled` → health check custom_http | `live_probed` true, `live_reachable` true | `test_vector_store_live_probe_flag_on_custom_http` |
| RG-07 | PII classification block | Enable `gateway.memory.pii_classification_enabled` → create memory with pii metadata | 422 `MEMORY_DATA_CLASS_BLOCKED` | `test_gateway_memory_pii_classification_blocks_when_enabled` |

## Verification Commands

```bash
# Backend unit/integration
cd backend && python3 -m pytest tests/test_gateway_memory.py tests/test_gateway_response_cache.py tests/test_gateway_rag.py -q
cd backend && python3 -m pytest tests/test_phase0_phase1.py -k "cache_decision or provider_priority or simulate_fallback" -q

# Frontend wiring (+ optional live API)
bash frontend/scripts/gateway_memory_cache_fallback_smoke.sh
RUN_API_CHECKS=1 API_BASE=http://127.0.0.1:8000 bash frontend/scripts/gateway_memory_cache_fallback_smoke.sh

# UI syntax
node --check frontend/app.js
```

**UI in-console:** Routing & Gateway → **Memory & Context** → Verification Scenarios (Run Memory Suite).  
Routing & Gateway → **Routes & Keys** → Fallback Verification (Run Fallback Suite).

---

## Memory & Context (`/gateway/memory/*`)

| ID | Scenario | Steps (UI) | Expected | API / pytest |
|----|----------|------------|----------|--------------|
| MC-01 | Overview aggregates tiers | Memory tab → **Load Overview** or Run MC-01 | `semantic_cache`, `short_term`, `long_term`, TTL and scope limits present | `GET /gateway/memory/overview`; `test_gateway_memory_overview_returns_tier_summaries` |
| MC-02 | Short-term create/list/get | Short-Term form: scope `session`, dev env, content → Save → Load Records | Record appears with `expires_at`; list total ≥ 1 | `POST/GET /gateway/memory/records`; `test_gateway_memory_record_create_list_and_get` |
| MC-03 | Short-term TTL expiry | Seed expired row (test) or wait TTL; Load Records | Expired row not listed; status `expired` in DB | `test_gateway_memory_short_term_expires_on_list` |
| MC-04 | Prod long-term create denied | Long-Term: tier global, env **prod**, no approver headers → Save | 403, `AUTHZ_DUAL_APPROVAL_REQUIRED`, deny audit | `test_gateway_memory_create_prod_long_term_dual_approval_denied` |
| MC-05 | Prod long-term create allowed | Same as MC-04 + Approver Role/ID (Security Approver) | 200, audit `gateway.memory.record.create` | same test file (allowed branch) |
| MC-06 | Prod long-term delete dual approval | Create prod long-term (with approver) → Delete without approver | 403 dual approval | `test_gateway_memory_delete_prod_dual_approval` |
| MC-07 | Agent Owner scope | Agent Owner creates record; other Agent Owner reads by id | Cross-read 403 `AUTHZ_SCOPE_FORBIDDEN` | `test_gateway_memory_owner_scope_enforced` |
| MC-08 | Content size cap | POST content > 16 KiB | 422 validation error | schema `max_length=16384` |
| MC-09 | Scope limit | Exceed `gateway.memory.max_records_per_scope` active rows per scope | 409 `MEMORY_SCOPE_LIMIT_REACHED` | service `create_memory_record` |
| MC-10 | Checkpoints link | Short-Term scope ID = session → **Load Checkpoints** | Count or empty list (no 404 on valid session API) | `GET /agentic/checkpoints/{session_id}` |
| MC-11 | Realtime sessions link | **Load Realtime Sessions** | List object or empty `data` | `GET /v1/realtime/sessions` |

---

## Semantic Cache (`/gateway/cache/*`)

| ID | Scenario | Steps (UI) | Expected | API / pytest |
|----|----------|------------|----------|--------------|
| CA-01 | Cache stats readback | Policies tab or Memory → Load Cache Stats | Hit ratio, semantic policy count | `GET /gateway/cache/stats` |
| CA-02 | Cache health | Load Cache Health | `status`, `cache_backend: policy-managed` | `GET /gateway/cache/health` |
| CA-03 | Create semantic policy | Policies → Cache Policy Management → mode **semantic**, threshold 0.5 → Create | Policy row with mode semantic | `POST /gateway/cache/policies` |
| CA-04 | Decision timeline after traffic | Run `POST /v1/responses` or chat → Load Decisions | Rows with decision hit/miss/bypass, optional similarity score | `test_gateway_cache_decision_readback_returns_explanation_and_provenance` |
| CA-05 | PII bypass | Request with `request_tag` pii.* or policy `non_cache_data_classes` | Decision **bypass** with explanation | `test_gateway_cache_decision_bypasses_disallowed_data_class` |
| CA-06 | Decision read roles | Auditor/Admin can list; unauthorized role denied | 403 for forbidden role | `test_gateway_cache_decision_readback_enforces_read_roles` |
| CA-07 | Invalidate audit | Invalidate form with scope + reason | Audit `gateway.cache.invalidate` | `POST /gateway/cache/delete` |

---

## Fallback Priority (`/gateway/routes/*/providers/priority`)

| ID | Scenario | Steps (UI) | Expected | API / pytest |
|----|----------|------------|----------|--------------|
| FB-01 | Chain builder validation | Routes → Route Priority → Add Target without provider | Validation message; Save blocked or API 422 | UI `validateRoutePriorityEntries`; `test_gateway_route_provider_priority_rejects_non_contiguous_priorities` |
| FB-02 | Ordered save/readback | Add 2+ targets, Up/Down reorder → Save Priority → Load Priority | Table matches order; priorities 1..N | `test_gateway_route_provider_priority_update_and_read_flow` |
| FB-03 | Request-tag scoped chain | Set Request Tag → Save → Load with same tag | Scope label shows tag; readback differs from default | `test_gateway_route_provider_priority_tag_override_readback_flow` |
| FB-04 | Prod dual approval | Environment prod, Save without approver | 403 deny audit on priority update | `test_gateway_route_provider_priority_requires_dual_approval_in_prod` |
| FB-05 | Simulate fallback | Fallback Execution → Simulate with route id | Selected provider from chain; attempts ≥ 1 | `test_gateway_route_simulate_fallback_selects_next_priority_provider` |
| FB-06 | Simulate all fail | Simulate with fail provider ids covering chain | Failed outcome when all candidates fail | `test_gateway_route_simulate_fallback_returns_failed_when_all_candidates_fail` |
| FB-07 | Initial chain on route create | Create Route → Initial Fallback Chain → Create Route | `fallback_policy` contains `provider_priority.priority_order` | route create form + `POST /gateway/routes` |
| FB-08 | Priority timeline | Save Priority → Load Timeline | Audit rows for priority updates | `GET .../providers/priority/timeline` |

---

## Cross-Surface Integration

| ID | Scenario | Steps | Expected |
|----|----------|-------|----------|
| X-01 | Memory tab cache panel | Memory → Load Cache Stats/Health | Overview + stats + health strings in result |
| X-02 | Jump to policies | Memory → Open Cache Policies | Policies tab active; cache section visible |
| X-03 | Playground memory save | Playground Studio: session/conversation IDs → Save Prompt Context to Memory | Short-term record created via `POST /gateway/memory/records` | `savePlaygroundMemoryContext` in `frontend/app.js` |
| X-04 | CISO evidence bundle | Governance → Export evidence | Includes gateway memory / cache / route actions when present |

---

## Role Matrix (spot checks)

| Action | Platform Admin | AI Ops | Agent Owner | Auditor |
|--------|------------------|--------|-------------|---------|
| Memory overview/list | ✓ | ✓ (write roles) | ✓ own scope | ✓ read |
| Memory create | ✓ | ✓ | ✓ | ✗ |
| Prod long-term create/delete | ✓ + Security Approver | ✓ + approver | ✓ own + approver | ✗ |
| Cache policy create | ✓ | ✗ | ✗ | read only |
| Route priority save (prod) | ✓ + approver | ✓ + approver | ✗ | ✗ |

---

## Known Limitations (do not fail tests on these)

1. Short-circuit requires `gateway.cache.inference_short_circuit_enabled=true` (default false) plus active cache policy.
2. Streaming (`stream: true`) responses are not short-circuited.
3. No server-side multi-turn conversation store — `session_id` / `conversation_id` are correlation only unless using `/gateway/memory/records`.
3. Routing groups multi-group failover — JSON-only in UI (no visual builder yet).
4. Provider health editor — JSON textarea only.

---

## Last Updated

2026-06-12 — Memory & Context tab, fallback chain builder, gateway memory pytest suite, in-console verification scenarios.
