# Memory, Context, Vector Store — Impact Analysis

**Document ID:** GOV-MCV-IMPACT-001  
**Status:** Active  
**Related:** `memory-cache-fallback-test-cases.md`, `unified-secret-provider-ciso-gap-analysis.md`, `generic-provider-configuration-review-and-impact-analysis.md`, `api-inventory-and-ui-map.md`

## Purpose

Record what exists today, what must **not** be duplicated, and the phased path for closing functional gaps without violating the platform’s control-plane / data-plane separation or the unified secret-provider model.

## Existing Standards (do not bypass)

| Standard | Source | Implication |
|----------|--------|-------------|
| Unified secret provider (CP-REF) | `unified-secret-provider-ciso-gap-analysis.md` | Vector API keys use `secret_provider_id` + `api_key_secret_ref` only; no inline keys in runtime JSON |
| Gateway cache governance | `gateway.py` `_record_cache_decision_event` | Cache decisions are audit telemetry; separate from response payload storage |
| MCP gateway registry | `gateway.mcp.servers_json` | External tool/RAG integrations should prefer MCP bridge over a second HTTP client layer |
| Agent credential resolution | `credential_resolution.py`, `gateway_inference.py` | Inference credentials resolve via bindings/env; vector credentials are a **distinct** ref path on store records |
| UI coverage discipline | `AGENTS.md`, `documentation-source-of-truth.md` | Extend Routing & Gateway Memory tab and Runtime Config presets; do not add a second “Vector Console” nav item |
| Providers credential wizard | `providers.html` Credential Setup Guide | Deep-link to Store Secret Value; do not rebuild a parallel secret-store form under Gateway |

## Current State (control plane)

| Capability | Implementation | Duplication risk if we… |
|------------|----------------|-------------------------|
| Memory CRUD | `/gateway/memory/records*` + Memory tab | Add a second “notes” table in Playground only |
| Platform tuning | `/gateway/memory/config` + Platform Configuration card | Duplicate keys in a new `/gateway/settings` API |
| Vector registry | `gateway.vector_stores_json` + registry UI | Add per-vendor config screens outside Runtime Config |
| Secret storage | Providers → Store Secret Value | Add “paste API key” fields on vector rows |
| Cache policies | Policies tab + `/gateway/cache/policies` | Add second cache editor on Memory tab (keep link/defaults only) |
| Cache decisions | `/gateway/cache/decisions` + `_record_cache_decision_event` | Re-implement similarity in a new service |
| MCP tools | `/gateway/mcp/*` | Build parallel vector HTTP adapters for every vendor before MCP path is exhausted |

## Functional Gaps (data plane — deferred by design)

| Gap | Why not duplicated now | Target integration path |
|-----|------------------------|-------------------------|
| Live vector search / RAG | No `CachedResponse` or `/rag/*` runtime; architecture lists adapters only | Phase 2: MCP bridge store type + tool contract, or dedicated `gateway_rag.py` adapter port |
| Semantic cache short-circuit | `GatewayResponseCacheEntry` + opt-in `gateway.cache.inference_short_circuit_enabled` | Phase 3 **implemented** — see `litellm-cache-parity-impact-analysis.md` |
| Auto multi-turn memory | Explicit `/gateway/memory/records` only | Phase 2: optional hook from `/v1/responses` to append session scope (feature-flagged) |
| Live vector connectivity probe | Health check validates config + secret posture | Phase 2: provider-specific probe behind feature flag; reuse secret resolution from `gateway_vector_stores.py` |

## This Change Set (Phase 1 — operator closure, no new data plane)

| Change | Extends | Avoids duplicating |
|--------|---------|-------------------|
| Runtime Config presets for `gateway.memory.*`, `gateway.cache.default_*`, `gateway.vector_stores*` | Existing `RUNTIME_CONFIG_PRESETS` | New settings API |
| Overview **Memory & Context** quick-start chip | Existing quick-start + `activateGatewayConsoleTab` | New sidebar nav entry |
| `VIEW_DESCRIPTIONS` update for Routing & Gateway | Existing subtitle pattern | Duplicate help docs in HTML only |
| Platform Configuration card `id` for scroll target | Existing Memory tab | Second config page |
| Secret ref + Store Key on vector rows (prior PR) | Providers Store Secret Value | Inline credentials |
| Impact analysis (this doc) | GAP-GPC / CISO gap format | Ad-hoc README-only notes |

## Impact by Role

| Lens | Impact | Risk |
|------|--------|------|
| **Operator** | Faster discovery (Overview chip, presets); same Memory tab for tuning | Low — navigation only |
| **Security** | No new secret surfaces; presets are non-secret defaults | Low |
| **Platform engineering** | No new routers; docs clarify Phase 2/3 boundaries | Low |
| **CISO** | Explicit deferral of cache short-circuit and RAG until models + review | Medium accepted — documented |
| **Frontend** | ~50 lines preset + chip handler; reuses tab/scroll patterns | Low |

## Test & Validation Matrix

| ID | Scenario | Command / path |
|----|----------|----------------|
| MCV-IA-01 | Gateway memory tests green | `pytest tests/test_gateway_memory.py -q` |
| MCV-IA-02 | Frontend syntax | `node --check frontend/app.js` |
| MCV-IA-03 | Memory smoke (optional) | `RUN_API_CHECKS=1 frontend/scripts/gateway_memory_cache_fallback_smoke.sh` |
| MCV-IA-04 | Playground memory save | Playground → Save Prompt Context to Memory (X-03) |

## Phase 2 Recommendation (next engineering slice)

**Status (2026-06): Implemented** — cloud secret posture, MCP bridge validation, context bundle endpoint, session capture hook.

1. **`mcp_bridge` vector store** — document required MCP tool names; health check verifies server registry contains bridge server. **Done:** validation requires `mcp_server_id`; health/context expose MCP posture.
2. **`GET /gateway/vector-stores/{id}/context`** — read-only posture bundle (store + secret configured + default embedding model); **Done:** `build_vector_store_context()` + audit `gateway.vector_store.context.read`.
3. **Session capture from `/v1/responses`** — feature-flagged (`gateway.memory.session_capture_enabled`, default `false`); appends short-term session scope memory with audit `gateway.memory.session_capture`. **Done.**
4. **Cloud secret integration posture** — health/context expose `secret_backend_type`, `secret_integration_mode`, `cloud_integrated` for vault/AWS/Azure backends. **Done.**
5. Route consumer credential binding UI — extend existing Credential Bindings table filter; do not add gateway-only binding CRUD. **Deferred** (unchanged from Phase 2 plan).

## Phase 3 Recommendation (requires CISO + schema)

**Status (2026-06-12): Implemented** — see `litellm-cache-parity-impact-analysis.md` for full register.

1. `GatewayResponseCacheEntry` model + TTL + privacy_mode alignment with cache policies. **Done.**
2. Opt-in `gateway.cache.inference_short_circuit_enabled` (default `false`). **Done** — dual-approval required for prod enablement.
3. PII classification hook on memory create (RSK-017 closure). **Deferred Phase 3b.**

### Phase 3 Implementation Summary

| Area | Detail |
|------|--------|
| Data plane | Encrypted response bodies in `gateway_response_cache_entries`; exact + semantic lookup |
| Gateway paths | `POST /v1/chat/completions`, `POST /v1/responses` (non-stream) |
| Admin | `GET /gateway/cache/entries`; stats/health extended; delete purges entries |
| UI | Memory & Context Platform Configuration toggle + cache stats short-circuit fields |
| Tests | `test_gateway_response_cache.py` (exact/semantic hit, bypass, owner scope, flag off) |
| Not duplicated | Cache policies, decision timeline, secret provider, MCP registry |

### Phase 3 CISO Notes

- Response cache stores operator-visible inference output — classify via cache policy `non_cache_data_classes` and request tags.
- Enable short-circuit only after policy review; default remains telemetry-only until flag is set.
- Streaming responses are excluded from short-circuit (no partial-chunk cache today).

## Phase 4 Recommendation

**Status (2026-06-12): Implemented** — see `litellm-rag-parity-impact-analysis.md` for full register.

1. **`gateway_rag.py` service** — `rag_ingest` / `rag_query` resolve store from `gateway.vector_stores_json`, credentials via CP-REF, MCP bridge delegation (`vector.search`, `vector.upsert`, `vector.delete`). **Done.**
2. **OpenAI-compatible + platform endpoints** — `GET/POST /v1/vector_stores*`, `POST /rag/ingest`, `POST /rag/query` with role gating and audit. **Done.**
3. **Live vector connectivity probe** — `gateway.vector_stores.live_probe_enabled` (default `false`); extends `vector_store_health_check`. **Done.**
4. **Memory PII classification hook (Phase 3b)** — `gateway.memory.pii_classification_enabled` (default `false`); blocks pii/phi/secret on create; tags metadata. **Done** — partial RSK-017 closure.
5. **Frontend** — RAG Ingest/Query panel, live probe toggle, PII classification toggle in Platform Configuration. **Done.**

### Phase 4 Implementation Summary

| Area | Detail |
|------|--------|
| Data plane | MCP-first RAG via `mcp_bridge` stores; no per-vendor SDK adapters in v1 |
| Endpoints | `/v1/vector_stores`, `/rag/ingest`, `/rag/query`; registry POST is read-only (runtime config) |
| Probes | Optional live MCP tools/list + custom_http HEAD when `live_probe_enabled` |
| PII hook | Heuristic classification aligned with cache `data_class` in `gateway_memory.py` |
| Tests | `test_gateway_rag.py`, extended `test_gateway_memory.py` |
| Not duplicated | MCP gateway HTTP client, vector registry validation, secret provider storage |

### Phase 4 Deferred

- Assistants API, fine-tuning, passthrough endpoints — separate parity track
- Streaming cache short-circuit
- Per-vendor native adapters (Qdrant/Pinecone direct SDK) — MCP bridge is v1 path
- Non-MCP provider types for RAG ingest/query (qdrant, pinecone direct)

## Sign-off

| Role | Status |
|------|--------|
| Platform Engineering | Phase 4 implemented |
| Security Architecture | MCP-first + CP-REF + default-off probes/PII + audit |
| CISO | RSK-017 partial closure via opt-in PII hook; prod registry still dual-approval |
