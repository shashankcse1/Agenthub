# LiteLLM Cache Parity — Impact Analysis

**Document ID:** GOV-LITELLM-CACHE-001  
**Status:** Active  
**Related:** `memory-context-vector-impact-analysis.md`, `memory-cache-fallback-test-cases.md`, `api-inventory-and-ui-map.md`, `unified-secret-provider-ciso-gap-analysis.md`

## Purpose

Record Phase 3 inference cache short-circuit implementation, security posture, duplication boundaries, and deferred LiteLLM parity tracks.

## Phase 3 Implementation Status (2026-06-12)

| Component | Status | Notes |
|-----------|--------|-------|
| `GatewayResponseCacheEntry` model + migration | **Done** | Encrypted `response_body_encrypted`; TTL; privacy_scope alignment |
| `gateway.cache.inference_short_circuit_enabled` runtime key | **Done** | Default `false`; dual-approval in `SENSITIVE_RUNTIME_CONFIG_KEYS` |
| `gateway_response_cache.py` service | **Done** | lookup/store/purge; exact + semantic (Jaccard token similarity) |
| Gateway integration | **Done** | `POST /v1/chat/completions`, `POST /v1/responses` (non-stream) |
| Admin endpoints | **Done** | Extended `/gateway/cache/stats`, `/gateway/cache/health`; `GET /gateway/cache/entries`; `/gateway/cache/delete` purges entries |
| Frontend | **Done** | Memory & Context Platform Configuration toggle; stats display |
| Tests | **Done** | `backend/tests/test_gateway_response_cache.py` |

## CISO / Security Impact

| Control | Implementation |
|---------|----------------|
| Encrypted response storage | Fernet via `secret_crypto.encrypt_sensitive_value` (same pattern as `SecretProviderStoredValue`) |
| Default off | `gateway.cache.inference_short_circuit_enabled` defaults to `false` — no behavior change until enabled |
| Prod enablement | Key in `SENSITIVE_RUNTIME_CONFIG_KEYS` — requires dual approval via Runtime Config / Platform Configuration |
| TTL enforcement | `ttl_expires_at` from cache policy; expired entries excluded from lookup |
| Privacy scope | `tenant`, `owner`, `global` — owner policy requires `owner_scope` on request |
| Data-class bypass | `non_cache_data_classes` on policy; tag-based classification (`pii.*`, `secret.*`, keyword heuristics) |
| No inline secrets | CP-REF preserved — cache entries store inference responses only, never API keys |
| Audit | `gateway.cache.hit/miss/bypass`, `gateway.cache.entry.read`, `gateway.cache.invalidate`; `CacheDecisionEvent` timeline unchanged |
| Invalidation | `POST /gateway/cache/delete` marks entries `invalidated` + audit |

## Duplication Risks — What Was NOT Duplicated

| Avoided | Rationale |
|---------|-----------|
| Second cache policy editor | Reuses existing `/gateway/cache/policies` |
| Parallel similarity service | Reuses Jaccard token overlap from gateway cache telemetry |
| Inline API keys in cache rows | CP-REF secret model |
| New vector/RAG runtime | Phase 4 — see below |
| Assistants / fine-tuning / passthrough | Separate parity track — design-only in PDD |
| PII classification hook on memory create | Phase 3b — documented, not implemented |

## Phase 4 Status (2026-06-12)

**Implemented** — see `litellm-rag-parity-impact-analysis.md` and `memory-context-vector-impact-analysis.md` Phase 4 section.

- `/v1/vector_stores`, `/rag/ingest`, `/rag/query` runtime data plane (MCP-first)
- Live vector connectivity probes behind `gateway.vector_stores.live_probe_enabled`
- MCP-bridge RAG tool contract execution

## Phase 3b Status

- PII classification hook on `POST /gateway/memory/records` — **implemented** (partial RSK-017 closure; default off)
- Streaming cache short-circuit — **deferred** (SSE/chunk responses excluded today)

## Validation

```bash
cd backend && python3 -m pytest tests/test_gateway_response_cache.py tests/test_gateway_memory.py -q
node --check frontend/app.js
```

## Sign-off

| Role | Status |
|------|--------|
| Platform Engineering | Implemented |
| Security Architecture | Controls documented; encrypted storage + default-off |
| CISO | Prod enablement requires dual approval; residual RSK-017 for memory PII |
