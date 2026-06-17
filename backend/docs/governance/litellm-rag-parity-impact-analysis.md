# LiteLLM RAG Parity — Impact Analysis

**Document ID:** GOV-LITELLM-RAG-001  
**Status:** Active  
**Related:** `memory-context-vector-impact-analysis.md`, `litellm-cache-parity-impact-analysis.md`, `api-inventory-and-ui-map.md`, `unified-secret-provider-ciso-gap-analysis.md`

## Purpose

Record Phase 4 vector/RAG runtime implementation, MCP-first strategy, security posture, duplication boundaries, and deferred LiteLLM parity tracks.

## Phase 4 Implementation Status (2026-06-12)

| Component | Status | Notes |
|-----------|--------|-------|
| `gateway_rag.py` service | **Done** | `rag_ingest`, `rag_query`; MCP bridge tool delegation |
| `gateway_rag.py` router | **Done** | `/v1/vector_stores*`, `/rag/ingest`, `/rag/query` |
| Live probe flag | **Done** | `gateway.vector_stores.live_probe_enabled` default `false` |
| PII classification hook | **Done** | `gateway.memory.pii_classification_enabled` default `false` |
| Frontend RAG panel | **Done** | Memory & Context ingest/query forms + probe/PII toggles |
| Tests | **Done** | `backend/tests/test_gateway_rag.py` |

## CISO / Security Impact

| Control | Implementation |
|---------|----------------|
| MCP-first data plane | No duplicate HTTP clients per vector vendor; tools `vector.search`, `vector.upsert`, `vector.delete` |
| CP-REF only | `resolve_vector_store_api_key` via db/cloud secret backends; credentials passed to MCP tool args only |
| Default-off probes | `gateway.vector_stores.live_probe_enabled` — no outbound probe until enabled |
| Default-off PII hook | `gateway.memory.pii_classification_enabled` — blocks pii/phi/secret classes when enabled |
| Registry read-only POST | `/v1/vector_stores` POST returns 409; mutations via runtime config + dual approval |
| Audit | `gateway.rag.ingest`, `gateway.rag.query`, `gateway.vector_store.list/read/register_attempt` |
| Role gating | RAG write: Platform Admin / AI Ops / Agent Owner; read: + Auditor |

## Duplication Risks — What Was NOT Duplicated

| Avoided | Rationale |
|---------|-----------|
| Per-vendor vector SDK layer | MCP bridge exhausts v1 integration path |
| Second vector registry API | Reuses `gateway.vector_stores_json` + Platform Configuration |
| Inline API keys in RAG payloads | CP-REF secret model |
| Parallel MCP HTTP stack | Reuses `mcp_gateway.call_tool` |
| Assistants / fine-tuning / passthrough | Separate parity track — see `litellm-assistants-parity-impact-analysis.md` |

## Phase 4 Deferred

- Direct qdrant/pinecone/weaviate adapters (non-MCP)
- Streaming RAG / embedding pipeline orchestration

## Assistants Track Status (2026-06-14)

**Implemented** — see `litellm-assistants-parity-impact-analysis.md` (GOV-LITELLM-ASSISTANTS-001).

- OpenAI Assistants API runtime (`/v1/assistants*`, `/v1/threads*`)
- Fine-tuning jobs (`/v1/fine_tuning/jobs*`)
- Passthrough proxy (`POST /v1/passthrough`)
- Deny-path audit, `environment` on responses, 29 regression tests, full governance doc sync (2026-06-14 gap-closure)

## Phase 3b Partial Closure

- Memory PII classification hook implemented (heuristic, not ML classifier)
- Residual RSK-017: classification is keyword/tag heuristic only; operators must still follow data-handling policy for edge cases

## Validation

```bash
cd backend && python3 -m pytest tests/test_gateway_rag.py tests/test_gateway_memory.py tests/test_gateway_response_cache.py -q
node --check frontend/app.js
```

## Sign-off

| Role | Status |
|------|--------|
| Platform Engineering | Implemented |
| Security Architecture | MCP-first + CP-REF + default-off flags + audit |
| CISO | RSK-017 partial closure; enable PII hook after policy review |
