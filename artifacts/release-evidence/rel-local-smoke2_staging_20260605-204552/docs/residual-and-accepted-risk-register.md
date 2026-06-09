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
| RSK-004 | Session signing secret policy enforces minimum length and non-default in non-dev, but does not yet enforce rotation cadence/versioning. | High | Medium | Medium | Security Engineering | 2026-07-05 | Open |
| RSK-005 | Sensitive endpoint abuse protection is improved with exact and wildcard rate limits, but not yet backed by distributed/shared state across multiple instances. | High | Medium | Medium | SecOps | 2026-07-12 | Open |
| RSK-006 | App-level transport hardening controls (explicit HTTPS/HSTS/CORS policy assertions) are still deployment-assumed and not fully codified in service middleware. | High | Medium | Medium | Platform / SecOps | 2026-07-19 | Open |

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

## Required Next Actions

1. Implement key rotation and versioned session signing keys with dual-key rollover window.
2. Add distributed rate-limiter backend (for example Redis) for multi-instance consistency.
3. Add explicit middleware/policy checks for HTTPS/HSTS/CORS assertions where applicable.
4. Add security operations runbook for insecure flag emergency usage and rollback.
5. Add SIEM alert for insecure_configuration_detected on non-local environments.

## Decision Log

| Date | Decision | Decision Owner | Notes |
|---|---|---|---|
| 2026-06-05 | Keep operational flags with strict environment guardrails and startup warnings. | Security Architect + Engineering Lead | Accepted with time-bound review |
| 2026-06-05 | Track remaining posture gaps as residual risk with compensating controls. | CISO Delegate | Register created |

## Sign-off

- Security Architect: Pending
- SecOps Lead: Pending
- Security Engineering Lead: Pending
- Vulnerability Management Lead: Pending
- CISO / Delegate: Pending
