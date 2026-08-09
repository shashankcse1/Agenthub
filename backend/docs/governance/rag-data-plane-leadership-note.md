# RAG / Data-Plane Leadership Note (Loop L5.3)

**Date:** 2026-08-02  
**Status:** Accepted residual for market-leader claim until native adapter depth lands

## Current posture

- Governed surfaces exist: `/rag/*`, `/v1/vector_stores*`, memory store, MCP registry.
- Live vector probe is flag-gated; PII classification default-on for memory.
- Flow Studio connectors reach vector DBs via allowlisted HTTP presets (Pinecone/Weaviate/Qdrant), not native SDKs.

## Accepted residual

Claiming Helicone/Portkey-class **control-plane** leadership does **not** require shipping a full native RAG engine in this loop.  
Data-plane depth remains:

| Gap | Mitigation today | Follow-up |
|-----|------------------|-----------|
| Native embedding/index adapters | OpenAI-compatible embeddings + vector_store registry | Adapter spike per provider |
| Chunking/rerank pipeline | Orchestration nodes + MCP tools | Product backlog |
| Groundedness eval suite | Playground quality triage | Eval harness |

## Decision

**Accept MCP + allowlisted HTTP + registry as sufficient for Wave 3 engineering exit.**  
Do not block L1–L5 on a native RAG rewrite. Revisit only if a customer win requires a specific adapter.
