# LiteLLM Parity Roadmap

Date: 2026-06-14
Owner: Platform Engineering + Security Architecture

## Purpose

This roadmap is the canonical parity planning register referenced by governance source-of-truth documents.
It tracks in-scope AI gateway parity slices, closure state, and sustainment focus.

## Closure Summary

All previously tracked parity-depth backlog slices are now closed:

1. Realtime/media binary transport governance depth: Closed
2. Prompt promotion/review and render-validation depth: Closed
3. Operator-grade quality triage queue and escalation lifecycle: Closed
4. Long-window quality analytics rollups: Closed
5. Model catalog recommendation explainability + approval/version controls: Closed
6. External observability sink productization (routing + correlation presets): Closed
7. **Assistants / fine-tuning / passthrough proxy track** (GOV-LITELLM-ASSISTANTS-001): Closed — see `litellm-assistants-parity-impact-analysis.md`
8. **Playground historical drill-down** + **Compliance server evidence export** + **Auth explain extensions**: Closed (same track)

## Current Focus

With parity-depth slices closed, roadmap focus shifts to sustainment and optimization.

### Sustainment priorities

1. Maintain strict regression coverage and smoke checks for all closed slices.
2. Monitor deny-path and allow-path audit evidence quality across privileged mutations.
3. Keep governance inventory and UI coverage docs synchronized with any incremental behavior changes.

### Optional expansion priorities (not parity blockers)

1. Realtime transport optimization and richer bidirectional channel semantics.
2. Additional observability sink templates and environment-specific delivery profiles.
3. Deeper quality analytics segmentation and operator recommendation tooling.

## Validation Expectations

For any future changes in these areas, required minimum checks remain:

1. node --check frontend/app.js
2. python3 -m pytest (focused suite for touched slices)
3. Documentation sync across:
- backend/docs/governance/api-inventory-and-ui-map.md
- backend/docs/governance/ui-api-design-coverage-map.md
- backend/docs/governance/documentation-source-of-truth.md
- backend/docs/governance/litellm-assistants-parity-impact-analysis.md (when assistants/fine-tuning/passthrough/playground-drilldown/compliance-export surfaces change)
- backend/docs/security/residual-and-accepted-risk-register.md
- frontend/README.md
