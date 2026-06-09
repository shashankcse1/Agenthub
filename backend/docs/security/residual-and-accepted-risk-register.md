# Residual Risk and Accepted Risk Register

## Scope
This register captures current security residual risks, accepted risks, and compensating controls for the backend service.

- Service: Enterprise Multi-Agent Platform API
- Repository area: backend/app
- Last updated: 2026-06-08
- Prepared by: Engineering Security Review (Architecture, SecOps, Security Engineering, Vulnerability, CISO lenses)

## Risk Rating Model
- Impact: Low | Medium | High | Critical
- Likelihood: Low | Medium | High
- Residual Risk: derived qualitative rating after compensating controls

## Current Pending Residual Risks

| Risk ID | Risk Statement | Impact | Likelihood | Residual Risk | Owner | Target Date | Status |
|---|---|---|---|---|---|---|---|
| RSK-001 | Header-based actor identity mode can be enabled in local/test contexts and may be unintentionally used in non-production-like deployments if environment management is weak. | High | Medium | Medium | Platform Security | 2026-06-21 | Open |
| RSK-002 | MFA optional mode exists for operational flexibility; misuse can reduce assurance for privileged workflows. | High | Medium | Medium | IAM / App Security | 2026-06-21 | Open |
| RSK-003 | Workload identity response can include raw token only when explicit flag is enabled in local/test; operator misuse could expose sensitive token material. | Critical | Low | Low | Cloud Security | 2026-06-06 | Mitigated |
| RSK-004 | Session signing now supports versioned key ids and rollover validation, but formal rotation cadence automation and alerting still require operational enforcement. | High | Medium | Low | Security Engineering | 2026-06-20 | In Progress |
| RSK-005 | Sensitive endpoint abuse protection now supports distributed Redis-backed enforcement with safe fallback, but production rollout coverage and monitoring baselines are still being finalized. | High | Medium | Low | SecOps | 2026-06-20 | In Progress |
| RSK-006 | App-level transport hardening controls (explicit HTTPS/HSTS/CORS policy assertions) are still deployment-assumed and not fully codified in service middleware. | High | Medium | Low | Platform / SecOps | 2026-06-05 | Mitigated |
| RSK-007 | Password-login endpoint could face repeated credential guessing attempts if account lockout controls are absent or misconfigured. | High | Medium | Low | IAM Engineering | 2026-06-06 | Mitigated |
| RSK-008 | Least-privilege recommendation apply actions can cause operational disruption if downscoping/disablement is applied without sufficient review evidence in sensitive environments. | High | Medium | Medium | Security Architecture + Cloud Operations | 2026-06-30 | Open |
| RSK-009 | Gateway governance evidence exports may contain sensitive operational identifiers from audit records if exported bundles are retained or shared without classification controls. | High | Medium | Medium | Security Architecture + Compliance Operations | 2026-07-08 | Open |
| RSK-010 | Newly introduced OpenAI-compatible chat endpoint could broaden gateway invocation surface if role scope, usage controls, and provider-depth safeguards are not enforced consistently during rollout. | High | Medium | Medium | Security Architecture + Platform Engineering | 2026-07-12 | Open |

## Accepted Risks

| Acceptance ID | Accepted Risk | Business Rationale | Expiry Date | Approver | Review Cadence | Renewal Required |
|---|---|---|---|---|---|---|
| AR-001 | Keeping MFA optional flag for controlled environments. | Required for controlled operational continuity during integration/testing windows. | 2026-07-15 | CISO Delegate + Security Architect | Weekly | Yes |
| AR-002 | Keeping token exposure flag in codepath but constrained by runtime-config dual approval and environment guardrails. | Needed for local/test interoperability troubleshooting; disabled by default and force-disabled outside local/test. | 2026-07-15 | Cloud Security Lead + CISO Delegate | Weekly | Yes |

## Compensating Controls

| Control ID | Control Description | Mapped Risks | Control Type | Evidence |
|---|---|---|---|---|
| CC-001 | Non-dev guardrails force header-based identity off regardless of override attempts. | RSK-001 | Preventive | Config logic and startup behavior in security module; test coverage in security config warning tests |
| CC-002 | Startup warnings explicitly log insecure settings at boot for operator visibility. | RSK-001, RSK-002, RSK-003 | Detective | Startup logs containing insecure_configuration_detected |
| CC-003 | Non-dev session secret validation blocks default value and too-short secret lengths. | RSK-004 | Preventive | Startup validation and tests covering reject/allow cases |
| CC-004 | Bearer token parser hardened with structural checks before signature comparison. | RSK-004 | Preventive | Security module token parsing logic and regression tests |
| CC-005 | Sensitive endpoint rate limits added for exact and wildcard path classes. | RSK-005 | Preventive | Rate limiter rules and dedicated rate-limit regression tests |
| CC-006 | Audit events and sanitized logs across critical flows provide forensic traceability. | RSK-001, RSK-002, RSK-003, RSK-005 | Detective | Audit events endpoints and log redaction utilities |
| CC-007 | Primary integration suite and dedicated security regression suites pass consistently. | All | Corrective/Assurance | Test suites: phase0_phase1, security config warnings, rate limit rules |
| CC-008 | Response middleware now enforces baseline transport security headers and non-dev CORS wildcard guardrails. | RSK-006 | Preventive | Middleware enforcement in app/main.py and transport header regression test |
| CC-009 | Security operations runbook defines break-glass controls, rollback steps, and evidence requirements. | RSK-001, RSK-002, RSK-003, RSK-006 | Corrective/Operational | docs/security/security-operations-runbook.md |
| CC-010 | Session tokens now include signing key id with backward-compatible validation for rollover windows. | RSK-004 | Preventive | app/security.py key-ring signing and token rotation tests |
| CC-011 | Rate limiter supports optional Redis distributed backend with automatic fallback to in-memory mode and operational cutover checks. | RSK-005 | Preventive | app/services/rate_limit.py, tests/test_rate_limit_backend.py, scripts/rate_limit_cutover.sh |
| CC-012 | Password-login flow enforces failed-attempt lockout with runtime-configured bounds and admin unlock controls backed by audit evidence. | RSK-007 | Preventive/Detective | auth login lockout state fields, runtime-config validation keys, `auth.login.password` and `auth.directory.user.unlock` audit events |
| CC-013 | Workload identity token-exposure behavior is DB-governed via `workload_identity.expose_access_token` (dual approval required), environment fail-closed outside local/test, and runtime-config audit evidence on validate/read/update/delete/cache invalidation. | RSK-003 | Preventive/Detective | runtime-config validation/audit tests, providers token-exchange tests, runtime-config audit event actions |
| CC-014 | Role authorization remains strict and case-sensitive for all roles except canonicalized `Master Admin`, preventing non-canonical privilege escalation through lowercase role headers. | RSK-001, RSK-002 | Preventive | role-forbidden regression tests in phase0/phase1 and master-admin canonicalization edge test |
| CC-015 | MCP gateway integration is constrained by approved server registry, per-server tool allowlists/prefix constraints, prod dual-approval enforcement for tool calls, and allow/deny audit events for MCP list/call actions. | RSK-001, RSK-002, RSK-005 | Preventive/Detective | `/gateway/mcp/*` endpoint controls, runtime-config validation for `gateway.mcp.servers_json`, and MCP gateway regression tests |
| CC-016 | Least-privilege recommendation apply workflow is role-gated, production dual-approval guarded, audit-backed, and UI-enforced with mandatory operator decision rationale to reduce unsafe privilege-removal actions. | RSK-008 | Preventive/Detective | `/gateway/least-privilege/recommendations/*` controls, UI decision-reason gate, and gateway recommendation regression tests |
| CC-017 | Gateway governance evidence export is constrained by read-role authorization, fixed gateway action taxonomy, bounded per-action query limits, and explicit export audit events to support accountable handling and review. | RSK-009 | Preventive/Detective | `POST /gateway/governance/evidence/export` controls, `gateway.governance.evidence.export` audit events, and gateway evidence export regression tests |
| CC-018 | OpenAI-compatible chat baseline endpoint is role-gated (Platform Admin/AI Ops Approver/Agent Owner), deny/allow audit-backed (`gateway.chat.completions`), and regression-tested for contract + forbidden-role behavior. | RSK-010 | Preventive/Detective | `POST /v1/chat/completions` control path and phase0/phase1 gateway chat completion tests |

## Required Next Actions

1. Add automated rotation cadence and expiration alerting for session signing keys.
2. Finalize production rollout monitoring and alerting thresholds for Redis-backed rate limiting.
3. Validate HTTPS termination and HSTS compatibility at ingress/load balancer level in staging/prod.
4. Configure SIEM webhook destination and alert routing for `insecure_configuration_detected` startup events.
5. Add operational alerting for repeated `auth.directory.user.unlock` events per actor and per user to detect abuse patterns.
6. Add monitoring for `gateway.least_privilege.apply*` event volume and failed post-apply operations to detect over-restrictive recommendation application.
7. Add retention and classification policy checks for gateway governance evidence bundles (owner, retention window, approved sharing channels).

## Decision Log

| Date | Decision | Decision Owner | Notes |
|---|---|---|---|
| 2026-06-05 | Keep operational flags with strict environment guardrails and startup warnings. | Security Architect + Engineering Lead | Accepted with time-bound review |
| 2026-06-05 | Track remaining posture gaps as residual risk with compensating controls. | CISO Delegate | Register created |
| 2026-06-05 | Codified transport security headers and non-dev CORS wildcard guardrails in service middleware. | Platform Security + SecOps | RSK-006 moved to mitigated |
| 2026-06-05 | Implemented versioned session signing key support with rollover-compatible token validation. | Security Engineering | RSK-004 residual lowered to Low and moved to In Progress |
| 2026-06-05 | Implemented Redis-capable distributed rate limiting with safe fallback and cutover automation. | SecOps + Platform Security | RSK-005 residual lowered to Low and moved to In Progress |
| 2026-06-06 | Implemented password-login lockout controls and privileged unlock endpoint with audit evidence. | IAM Engineering + Security Architecture | RSK-007 moved to mitigated with CC-012 coverage |
| 2026-06-06 | Moved workload identity token exposure governance to DB runtime-config with dual-approval control, fail-closed non-local behavior, and runtime-config audit trail hardening. | Cloud Security + Platform Security | RSK-003 moved to mitigated with CC-013 coverage |
| 2026-06-06 | Restored strict role case semantics (except canonical Master Admin alias) and validated full backend suite. | Security Engineering | Canonical role-bypass regression closed with CC-014 evidence |
| 2026-06-06 | Added governed MCP gateway workflows with runtime-configured approved server registry, allowlist enforcement, production dual approval, and explicit MCP audit actions. | Security Architecture + Cloud Engineering | Added CC-015 compensating control for new MCP integration surface |
| 2026-06-08 | Added least-privilege recommendation governance controls, including production dual-approval and UI decision-rationale requirement for apply operations. | Security Architecture + IAM Engineering | Added RSK-008 and CC-016 for recommendation-application safety posture |
| 2026-06-08 | Added dedicated gateway governance evidence export endpoint and role-gated, audit-backed bundle generation workflow. | Security Architecture + Compliance Operations | Added RSK-009 and CC-017 for evidence-handling posture |
| 2026-06-08 | Added OpenAI-compatible chat baseline endpoint with role-gated access and deny/allow audit evidence. | Security Architecture + Platform Engineering | Added RSK-010 and CC-018 for new inference-surface control posture |

## Sign-off

- Security Architect: Pending
- SecOps Lead: Pending
- Security Engineering Lead: Pending
- Vulnerability Management Lead: Pending
- CISO / Delegate: Pending
