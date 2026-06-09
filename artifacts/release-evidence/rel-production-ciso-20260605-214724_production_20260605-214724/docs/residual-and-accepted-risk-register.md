# Residual Risk and Accepted Risk Register

## Scope
This register captures current security residual risks, accepted risks, and compensating controls for the backend service.

- Service: Enterprise Multi-Agent Platform API
- Repository area: backend/app
- Last updated: 2026-06-05
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
| RSK-003 | Workload identity response can include raw token only when explicit flag is enabled in local/test; operator misuse could expose sensitive token material. | Critical | Low | Medium | Cloud Security | 2026-06-21 | Open |
| RSK-004 | Session signing now supports versioned key ids and rollover validation, but formal rotation cadence automation and alerting still require operational enforcement. | High | Medium | Low | Security Engineering | 2026-06-20 | In Progress |
| RSK-005 | Sensitive endpoint abuse protection now supports distributed Redis-backed enforcement with safe fallback, but production rollout coverage and monitoring baselines are still being finalized. | High | Medium | Low | SecOps | 2026-06-20 | In Progress |
| RSK-006 | App-level transport hardening controls (explicit HTTPS/HSTS/CORS policy assertions) are still deployment-assumed and not fully codified in service middleware. | High | Medium | Low | Platform / SecOps | 2026-06-05 | Mitigated |

## Accepted Risks

| Acceptance ID | Accepted Risk | Business Rationale | Expiry Date | Approver | Review Cadence | Renewal Required |
|---|---|---|---|---|---|---|
| AR-001 | Keeping MFA optional flag for controlled environments. | Required for controlled operational continuity during integration/testing windows. | 2026-07-15 | CISO Delegate + Security Architect | Weekly | Yes |
| AR-002 | Keeping token exposure flag in codepath but constrained by environment guardrails. | Needed for local/test interoperability troubleshooting; disabled by default outside local/test. | 2026-07-15 | Cloud Security Lead + CISO Delegate | Weekly | Yes |

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

## Required Next Actions

1. Add automated rotation cadence and expiration alerting for session signing keys.
2. Finalize production rollout monitoring and alerting thresholds for Redis-backed rate limiting.
3. Validate HTTPS termination and HSTS compatibility at ingress/load balancer level in staging/prod.
4. Add security operations runbook for insecure flag emergency usage and rollback.
5. Add SIEM alert for insecure_configuration_detected on non-local environments.

## Decision Log

| Date | Decision | Decision Owner | Notes |
|---|---|---|---|
| 2026-06-05 | Keep operational flags with strict environment guardrails and startup warnings. | Security Architect + Engineering Lead | Accepted with time-bound review |
| 2026-06-05 | Track remaining posture gaps as residual risk with compensating controls. | CISO Delegate | Register created |
| 2026-06-05 | Codified transport security headers and non-dev CORS wildcard guardrails in service middleware. | Platform Security + SecOps | RSK-006 moved to mitigated |
| 2026-06-05 | Implemented versioned session signing key support with rollover-compatible token validation. | Security Engineering | RSK-004 residual lowered to Low and moved to In Progress |
| 2026-06-05 | Implemented Redis-capable distributed rate limiting with safe fallback and cutover automation. | SecOps + Platform Security | RSK-005 residual lowered to Low and moved to In Progress |

## Sign-off

- Security Architect: Pending
- SecOps Lead: Pending
- Security Engineering Lead: Pending
- Vulnerability Management Lead: Pending
- CISO / Delegate: Pending
