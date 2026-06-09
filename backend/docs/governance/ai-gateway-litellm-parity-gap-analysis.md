# AI Gateway Parity Gap Analysis (LiteLLM / Portkey / TrueFoundry)

## Scope

This analysis focuses only on AI-gateway and LiteLLM-relevant capabilities.
It excludes generic enterprise IT controls unless they directly affect LLM gateway behavior.

Sources compared:
- Internal implemented capabilities documented in governance inventory and frontend surface docs.
- Public docs/feature pages for LiteLLM, Portkey, and TrueFoundry.

## Current Internal Baseline (Implemented)

Based on current repo docs and endpoint inventory, the platform already provides:
- Route policy management, fallback simulation/execution, provider priority timeline, load-balancing strategies, retry/cooldown, and request-tag scoped routing.
- Traffic mirroring plus mirror analytics and experiment reporting.
- Cache policy create/list, cache health, cache invalidate, and cache stats.
- Key lifecycle, temporary budget increases, guardrail evaluation, and rotation scheduling.
- Entitlements, NHI inventory/hygiene, access reviews, JIT, least-privilege recommendations, and governance evidence export.
- MCP gateway server/tool listing and governed tool invocation.
- Benchmark/scan workflows and observability traces/logs.

## Competitive Parity Matrix (AI + LiteLLM Features)

Legend:
- Full: capability is present end-to-end in backend + UI workflows.
- Partial: some pieces exist, but key behavior is missing.
- Gap: capability not currently present as a first-class workflow.

| Capability | LiteLLM | Portkey | TrueFoundry | Current Platform | Status |
|---|---|---|---|---|---|
| Unified OpenAI-compatible chat gateway endpoint (/chat/completions style) | Yes | Yes | Yes | API-first `/v1/chat/completions` endpoint is implemented with audit and role controls, tenant-aware provider-prefix entitlement checks, cost telemetry persistence, and deeper semantics (`stop`, `max_tokens`, `response_format`); full provider-compatibility depth is still evolving | Partial |
| Multi-provider routing with fallback/retries/load balancing | Yes | Yes | Yes | Implemented route/fallback/retry/load-balancing controls | Full |
| Virtual keys + per-key/team/user budgets/rate limits | Yes | Yes | Yes | Implemented key lifecycle + budgets + limit evaluation workflows | Full |
| Semantic caching for prompts/responses | Mentioned in docs | Yes (simple + semantic cache) | Prompt caching support | Cache controls exist but semantic cache workflow not explicit | Partial |
| Prompt management studio (versioning, rollout/rollback, collaborative prompt registry) | Limited (router/config oriented) | Yes | Prompt-oriented API controls | Playground + route drafts exist, no dedicated prompt registry/version control product surface | Gap |
| Guardrails pipeline (input + output + policy modes + provider/plugin guardrails) | Yes | Yes | Yes | Pre-call filters + key guardrail evaluation + governed controls exist, but full input/output guardrail pipeline is not first-class | Partial |
| Quality eval/feedback loops (request/conversation feedback attached to traces) | Callback/observability primitives | Yes | Yes | Benchmark & scan exists, no explicit request-level feedback workflow | Partial |
| Canary/A-B experimentation for model/prompt releases | Router-level controls | Yes | Partial | Traffic mirroring + route drafts cover parts, no explicit canary split/experiment lifecycle card | Partial |
| Broad OpenAI API surface parity (responses/files/realtime/images/audio/batches) | Proxy supports broad compatibility | Broad support | Broad supported APIs matrix | `/v1/chat/completions`, responses create/retrieve/list/delete baseline, and files metadata create/retrieve/list/delete baseline are now implemented with governance controls; broader families (realtime/images/audio/batches and full binary file workflows) remain pending | Partial |
| Native auto-instrumentation ecosystem depth | Strong callback/integration model | Yes | Yes | Observability exists; auto-instrumentation ecosystem not explicit as first-class feature | Partial |

## Missing Features to Implement First (AI + LiteLLM Focus)

Priority is based on product parity impact and implementation risk.

### P0 (highest ROI)

1. Expand OpenAI-compatible gateway endpoint family
- Baseline `POST /v1/chat/completions` is now implemented.
- Incremental depth now includes `stop`, `max_tokens`, and `response_format` handling.
- Baseline `POST /v1/responses` is now implemented with governed role/audit/entitlement/cost controls and `stop`/`max_output_tokens`/`response_format` handling.
- Responses lifecycle baseline now includes list/retrieve/delete endpoints with audit-backed owner-or-admin deletion semantics and production dual-approval guardrails.
- Files metadata baseline now includes create/list/retrieve/delete endpoints with role-gated and soft-delete behavior.
- Next: add broader provider-compatibility semantics and additional OpenAI-style endpoint families (files/realtime coverage where applicable).
- Why: Full parity requires more than a single endpoint contract.
- Outcome: Existing SDK clients can point to gateway base URL with wider feature compatibility.

2. First-class semantic cache mode
- Extend existing cache policies with explicit semantic cache controls and hit/miss analytics.
- Why: Portkey and modern gateway users expect direct semantic caching controls for cost/latency reduction.
- Outcome: Better cache efficiency for near-duplicate prompts and measurable FinOps improvement.

3. Guardrails pipeline (input/output stages)
- Add request/response guardrail stages with enforce/audit behavior.
- Why: Competitive products expose this as a core production safety control.
- Outcome: Explicit model-safety pipeline beyond pre-call route constraints.

### P1 (next wave)

4. Canary and experiment release workflow
- Add explicit canary policy for weighted rollout and experiment lifecycle.
- Why: Portkey emphasizes canary testing; current mirroring is strong but not equivalent.
- Outcome: Safer model/prompt promotions with controlled exposure percentages.

5. Prompt registry with versioned deployment
- Add prompt templates, variables, versions, labels, and rollback controls.
- Why: Major parity gap against prompt management offerings.
- Outcome: Repeatable prompt governance and release management.

6. Request-level feedback and quality scoring loop
- Add feedback capture tied to traces/runs and quality dashboards.
- Why: Complements benchmark/scan with continuous production quality signal.
- Outcome: Stronger closed-loop optimization.

## Impact Analysis for the Missing-Feature Plan

### Architecture Impact
- Most P0 items are additive and can remain within current module boundaries.
- OpenAI-compatible endpoint family will require strict contract and provider adapter boundaries.

### Data Impact
- Semantic cache and prompt registry require new persistence entities.
- Canary experiments and feedback loops require event tables and retention policy decisions.

### Security/IAM Impact
- New inference and prompt APIs need existing role controls, tenant/environment scopes, and audit evidence.
- Guardrail policy updates for prod should preserve dual-approval behavior where blast radius is high.

### UI Impact
- Add dedicated cards/sections under Routing & Gateway and Playground.
- Preserve current control-center interaction pattern and avoid introducing parallel UI systems.

### Testing Impact
- Add contract tests for OpenAI compatibility (request/response shape and error mapping).
- Add deterministic tests for semantic cache matching behavior and guardrail pass/block paths.
- Add rollout safety tests for canary policy edge cases and rollback paths.

## Recommended Execution Sequence

1. P0.1 Expand OpenAI-compatible endpoint depth beyond chat baseline.
2. P0.2 Semantic cache mode with analytics.
3. P0.3 Input/output guardrails pipeline.
4. P1.1 Canary experiment workflow.
5. P1.2 Prompt registry and version rollout.
6. P1.3 Feedback loop and quality analytics.

This sequence preserves current architecture while closing the largest LiteLLM/Portkey/TrueFoundry parity gaps in AI-gateway functionality.
