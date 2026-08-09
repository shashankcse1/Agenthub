# AI Gateway Fine-Grain Parity Analysis (LiteLLM / Portkey / Kong / Cloudflare / Helicone / OpenRouter / TrueFoundry)

Date: 2026-06-09
Status: Current-state parity depth closed for the tracked backlog slices

## Purpose

This document provides a competitive parity view focused on AI-gateway and AI-ops capabilities.
It is a comparative analysis artifact, not the active backlog tracker.

Active sustainment tracking (parity backlog Closed):

1. `backend/docs/governance/litellm-parity-roadmap.md` (closure + sustainment)
2. `backend/docs/governance/api-inventory-and-ui-map.md`
3. `backend/docs/governance/ui-api-design-coverage-map.md`
4. `backend/docs/governance/product-completion-status.md` (designed-lane verdict)

## Current Outcome

Previously tracked parity-depth backlog slices are implemented in the current baseline:

1. Realtime/media binary transport governance depth:
- Inline-binary stream policy controls now include event allowlists, dedicated inline byte caps, and optional correlation-id requirements.
- Production inline-binary operations remain dual-approval guarded.

2. Prompt release governance depth:
- Promotion/review and validation controls are implemented.

3. Operator-grade quality operations depth:
- Quality triage queue, escalation lifecycle, and long-window rollups are implemented.

4. Model catalog governance depth:
- Recommendation explainability plus approval/version controls are implemented.

5. External observability sink productization depth:
- Sink routing metadata and correlation preset controls are implemented.

## Competitive Capability Matrix

Legend:

1. Full: implemented end-to-end with backend contract, operator UI workflow, and governance controls.
2. Partial: capability exists but strategic ecosystem depth can still be expanded.
3. Context: strategic comparison note, not a blocker.

| Capability | Market baseline | Current platform | Status |
|---|---|---|---|
| OpenAI-compatible chat/responses/files/realtime/audio/images/rerank/messages/A2A surface | LiteLLM, OpenRouter, Kong, Cloudflare | Implemented with role controls, owner-scope behavior, audit evidence, and cost telemetry. Realtime includes hardened inline-binary transport policy controls. | Full |
| Multi-provider routing, fallback, retries, policy controls | LiteLLM, Kong, Cloudflare | Implemented with route strategy controls, fallback simulation/execution, and scoped policy workflows. | Full |
| Virtual keys, budgets, and governance workflows | LiteLLM, Portkey, Kong | Implemented with lifecycle, temporary increases, rotation schedule workflows, and governance evidence posture. | Full |
| Prompt governance and release controls | Portkey, Kong | Implemented with registry lifecycle plus promotion/review validation depth. | Full |
| Quality triage and longitudinal analytics | Helicone, Portkey | Implemented with triage queue, escalation lifecycle, and rollup analytics. | Full |
| Catalog explainability and metadata governance | OpenRouter, Portkey | Implemented with recommendation rationale and approval/version controls. | Full |
| External callback sink routing and correlation presets | Portkey, Helicone, Cloudflare-style sink patterns | Implemented with sink routing metadata and correlation preset policies in callback workflows. | Full |
| Auto-instrumentation ecosystem breadth | Helicone, vendor SDK ecosystems | Internal observability is mature; ecosystem-specific turnkey auto-instrumentation breadth can still be expanded as an optimization track. | Partial |

## Security and CISO View

Current control posture:

1. Strong role-gating and owner-scope enforcement on privileged gateway paths.
2. Production dual-approval enforcement on high-blast-radius operations.
3. Explicit allow/deny audit evidence patterns across key governance mutations.
4. Residual risk coverage tracked in backend/docs/security/residual-and-accepted-risk-register.md.

Current risk characterization:

1. Parity-depth closure moved major risk from missing controls to sustainment quality.
2. Primary ongoing risk is drift risk (policy/test/doc drift), mitigated via governance sync and regression expectations.

## Post-Closure Focus (Optimization, not parity blocker)

The following are optimization themes, not open parity-depth blockers:

1. Realtime transport optimization and richer bidirectional channel semantics.
2. Additional sink templates and environment-tailored observability delivery profiles.
3. Deeper quality segmentation and recommendation UX optimization.
4. Broader turnkey instrumentation onboarding paths for external ecosystems.

## Validation Expectations for Future Changes

For any future work touching these areas:

1. Keep backend contract, UI workflow, and audit evidence aligned in one change slice.
2. Keep source-of-truth docs synchronized in the same PR.
3. Run focused regressions first, then broader validation as required by release gates.

Required minimum checks:

1. node --check frontend/app.js
2. python3 -m pytest (focused tests for touched slice)
3. Documentation sync across governance inventory, coverage map, source-of-truth, risk register, and frontend README.
