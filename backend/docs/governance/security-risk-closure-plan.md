# Security Risk Closure Plan

Date: 2026-06-10
Scope: Backend + Gateway + Operator Workflows + Unified Secret Provider
Sources: docs/security/residual-and-accepted-risk-register.md, docs/governance/release-gate-checklist.md, docs/governance/unified-secret-provider-ciso-gap-analysis.md

## Purpose

This tracker converts residual-risk and release-gate pending actions into owner-assigned, evidence-backed closure tasks.

## Closure Tracker

| Item ID | Risk/Control Focus | Owner | Target Date | Required Evidence Artifact | Verification Command | Status |
|---|---|---|---|---|---|---|
| CL-001 | Session signing key rotation automation and expiration alerting (RSK-004) | Security Engineering | 2026-06-20 | Rotation policy artifact + alert rule export + test log evidence | python3 -m pytest -q backend/tests/test_security_config_warnings.py | In Progress |
| CL-002 | Redis-backed rate-limit rollout monitoring thresholds (RSK-005) | SecOps | 2026-06-20 | Threshold config, dashboard screenshot/export, alert test evidence | python3 -m pytest -q backend/tests/test_rate_limit_backend.py | In Progress |
| CL-003 | Ingress/load-balancer HTTPS + HSTS validation in stage/prod (RSK-006 operational carryover) | Platform / SecOps | 2026-06-21 | Ingress config snapshot + validation report | bash backend/scripts/validate_ingress_security_headers.sh | Open |
| CL-004 | SIEM routing for insecure startup posture events (CC-002 operationalization) | SecOps + Security Architecture | 2026-06-21 | Webhook config evidence + alert route test output | bash scripts/full_stack_expert_review.sh --strict | Open |
| CL-005 | Account-unlock abuse alerting per actor and target user (RSK-007 monitoring) | IAM Engineering + SecOps | 2026-06-24 | Detection query + alert policy evidence + sampled events | python3 -m pytest -q backend/tests/test_audit_events_api.py | Open |
| CL-006 | Least-privilege apply volume/failure anomaly monitoring (RSK-008) | Security Architecture + Cloud Operations | 2026-06-30 | Alert policy + dashboard panel + drilldown runbook section | python3 -m pytest -q backend/tests/test_gateway_least_privilege_recommendations.py | Open |
| CL-007 | Governance evidence retention/classification checks (RSK-009) | Security Architecture + Compliance Operations | 2026-07-08 | Data classification policy + retention rule set + evidence export review record | python3 -m pytest -q backend/tests/test_gateway_governance_evidence_export.py | Open |
| CL-008 | OpenAI-compatible endpoint control consistency across rollout stages (RSK-010) | Security Architecture + Platform Engineering | 2026-07-12 | Endpoint control matrix + role test evidence + deny/allow audit sample | python3 -m pytest -q backend/tests/test_openai_gateway_chat_completions.py backend/tests/test_openai_gateway_embeddings.py | Open |
| CL-009 | Unified secret provider CISO sign-off and legacy API sunset plan (RSK-016 / GAP-USP-R03) | CISO Delegate + IAM Governance | 2026-09-01 | Signed CISO gap analysis + deprecation removal PR | python3 -m pytest -q backend/tests/test_secret_provider_db_values.py | Open |
| CL-010 | Remote secret-provider rotation execution (GAP-USP-R01) | Security Engineering | 2026-07-15 | Adapter implementation evidence + rotation integration test | python3 -m pytest -q backend/tests/test_phase0_phase1.py -k rotate_via_secret_provider | Open |
| CL-011 | `SECRET_ENCRYPTION_KEY` rotation automation (GAP-USP-R04) | PAM Operations | 2026-07-30 | Key rotation runbook + re-encryption test evidence | bash backend/scripts/validate_day0_secrets.sh | Open |
| CL-012 | SIEM detection for anomalous `secret_provider.value.upsert` rates (GAP-USP-R05) | SecOps | 2026-07-15 | Alert rule export + sampled audit correlation | python3 -m pytest -q backend/tests/test_secret_provider_db_values.py | Open |
| CL-013 | Vault/AWS lease API integration depth (GAP-USP-R02) | Cloud Engineering | 2026-08-01 | Lease renew adapter design + integration test plan | python3 -m pytest -q backend/tests/test_phase0_phase1.py -k secret_provider_lease | Open |

## Release Gate Sign-off Tracker

| Sign-off Role | Required For | Owner | Status | Evidence Location |
|---|---|---|---|---|
| Security Architect | Staging + Production | Security Architecture | Pending | docs/security/residual-and-accepted-risk-register.md |
| SecOps Lead | Staging + Production | SecOps | Pending | docs/governance/release-gate-checklist.md |
| Security Engineering Lead | Staging + Production | Security Engineering | Pending | docs/governance/release-gate-checklist.md |
| Vulnerability Management Lead | Production | Vulnerability Management | Pending | docs/governance/release-gate-checklist.md |
| CISO / Delegate | Production | CISO Office | Pending | docs/security/residual-and-accepted-risk-register.md |
| Cloud Architect | Staging + Production | Cloud Architecture | Pending | docs/governance/multi-lens-security-architecture-review.md |
| Browser Architect | Staging + Production | Browser Architecture | Pending | docs/governance/multi-lens-security-architecture-review.md |
| Cloud Security | Staging + Production | Cloud Security | Pending | docs/governance/multi-lens-security-architecture-review.md |
| AI Security | Staging + Production | AI Security | Pending | docs/governance/multi-lens-security-architecture-review.md |
| PAM | Staging + Production | Identity Security | Pending | docs/governance/multi-lens-security-architecture-review.md |
| IAM Governance and Access Management | Staging + Production | IAM Governance | Pending | docs/governance/multi-lens-security-architecture-review.md |

## Weekly Closure Cadence

1. Update task status and evidence links every week before release window planning.
2. Re-run verification commands for tasks changed since last review.
3. Record drift or blockers with explicit owner and revised due date.
4. Confirm sign-off readiness against docs/governance/release-gate-checklist.md.

## Blocker Handling

If a closure item misses target date:

1. Open a time-bounded accepted-risk entry in docs/security/residual-and-accepted-risk-register.md.
2. Add compensating controls and monitoring plan.
3. Obtain CISO delegate review before production GO decision.
