# AGENTS Delivery Contract

This repository uses an agent-first delivery model. Every implementation must satisfy the role controls below before being marked complete.

## Role Lenses (Mandatory)

### 1. Security Architect
- Enforce secure-by-default design and trust boundaries.
- Validate authn/authz, least privilege, token lifecycle, and threat surface reduction.
- Require explicit threat assumptions and abuse-case handling.

### 2. Audit Architect
- Ensure auditable evidence exists for each critical action.
- Verify event completeness, decision traceability, and control-to-endpoint mapping.
- Require immutable and queryable records for approvals, denials, and exceptions.

### 3. CISO Lens
- Evaluate business impact, blast radius, and residual risk.
- Track accepted risk with expiry and compensating controls.
- Require go/no-go recommendation and top-risk summary.

### 4. AWS Engineer
- Validate IAM least privilege, STS boundaries, credential handling, and secret posture.
- Require production-safe defaults for env flags affecting token/identity exposure.
- Ensure service integrations are explicit about region, role, and failure behavior.

### 5. Cloud Engineer
- Validate deployability, runtime safety, rollback, observability, and SLO readiness.
- Require startup diagnostics, safe defaults, and operational runbook clarity.
- Ensure scaling, rate-limit, and incident telemetry controls are practical.

### 6. AI Architect
- Validate model, prompt, tool, and routing architecture decisions for quality and safety.
- Require explicit model-selection rationale, failure-mode behavior, and fallback strategy.
- Ensure responsible-AI controls are reflected in policies, tests, and operator workflows.

### 7. Frontend UI Expert
- Ensure UI architecture is clear, accessible, and maintainable.
- Validate UX flows for key operations and error paths.
- Enforce responsive behavior, usability, and consistency with product intent.

### 8. Security Engineer Expert
- Perform implementation-level security validation and abuse-case testing.
- Verify secure coding controls, input handling, and endpoint hardening.
- Ensure security regression tests are added for changed risk surfaces.

## Agent-First Completion Standard (100% via agents)

A task is considered complete only when all items are satisfied by agent-produced artifacts:

1. Code + tests + docs implemented in repository.
2. Security and quality controls reviewed under all eight role lenses.
3. Residual and accepted risks updated where applicable.
4. Regression suites pass (or documented blocker with impact and workaround).
5. No unresolved TODOs for the current scope.
6. Final summary includes changed files, verification results, and remaining risk (if any).
7. Agent-friendly evidence set is captured (machine-readable tests/results, policy decision traces, and release checklist deltas).

## Required Output Format for Agent Work

For every substantial change, include:

1. Scope and affected modules/endpoints.
2. Role-lens review summary:
- Security Architect
- Audit Architect
- CISO
- AWS Engineer
- Cloud Engineer
- AI Architect
- Frontend UI Expert
- Security Engineer Expert
3. Controls changed and why.
4. Tests run and results.
5. Audit/logging evidence reviewed (deny/allow mutation paths, traceability fields, and export/readback coverage).
6. Residual risk updates and approvals required.

## Non-Negotiable Gates

1. Security gates
- No production-unsafe default may be silently enabled.
- Token/secret exposure flags must be constrained by environment guardrails.

2. Audit gates
- Critical mutating operations must emit audit events.
- Deny-path decisions must be auditable when relevant.
- Logging fields for actor, action, resource, outcome, and trace correlation must be queryable for investigations.
- Evidence export/readback workflows must remain available for operator and audit review.

3. Cloud/AWS gates
- Secret and identity handling must avoid plaintext exposure paths in non-local environments.
- Rate-limit and operational safeguards must exist for sensitive endpoints.

4. Documentation gates
- Any risk-affecting change must update docs/security/residual-and-accepted-risk-register.md.
- New behavior must be documented for operators.

5. Agent-friendly delivery gates
- Changes should be decomposed into reviewable slices with explicit scope, controls, and verification outcomes.
- Test and smoke commands used for validation must be listed in docs or PR notes for repeatable agent execution.

## Module Alignment

Use module boundaries from product and architecture docs:
- MOD-REG, MOD-DISC, MOD-RUNTIME, MOD-GATEWAY, MOD-COST, MOD-EXT, MOD-OBS

All implementations should explicitly identify which modules are impacted.
