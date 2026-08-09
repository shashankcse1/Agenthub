# Operational Guide

This guide defines run, monitor, and incident operations for the platform.

## 1. Operational Objectives

- Keep service available, secure, and observable.
- Detect and respond to incidents quickly.
- Ensure predictable release and rollback behavior.

## 2. Core Daily Operations

- Check system health endpoint and startup warnings.
- Review audit event flow for critical operations.
- Review recent cost and anomaly indicators.
- Confirm scheduled jobs and policy automations are healthy.

## 3. Standard Run Commands

Recommended review and verification commands:
- Full baseline review: `bash scripts/full_stack_expert_review.sh`
- Deep review: `bash scripts/full_stack_expert_review.sh --deep`
- Frontend security smoke: `bash frontend/scripts/security_smoke.sh`

Backend verification should follow the repository check scripts and make targets.

## 4. Monitoring and Alerting

Minimum monitoring set:
- API health and error rate (`GET /health` — includes `runtime_config_cache` and rate-limiter posture)
- Platform operational status (`GET /platform/operational-status` — maintenance mode, slow threshold, degraded components)
- Operator feedback volume and open count (`GET /platform/feedback/analytics` — custom action breakdowns by `context_action`)
- Authz/authn denial anomalies
- Rate-limit event spikes
- Token exchange failures
- Secret provider value upsert anomalies (`secret_provider.value.upsert` audit volume)
- Gateway cursor secret binding change events (`gateway.cursor_secret_binding.update`)
- DB readiness and migration failures

Alert priorities:
- P1: Outage or critical auth/control bypass risk
- P2: Major degradation or repeated failures in critical workflows
- P3: Non-critical errors and optimization backlog

## 5. Incident Response Runbook (High Level)

1. Detect and classify severity.
2. Stabilize service (limit blast radius).
3. Triage root cause and impacted surfaces.
4. Communicate status and expected next update.
5. Recover service and verify critical controls.
6. Complete post-incident review and action tracking.

## 6. Scenario Playbooks

### A. API fails to start
- Verify environment variables and database connectivity.
- Check migration state and dependency compatibility.
- For PostgreSQL legacy schemas, confirm `alembic_version.version_num` is not capped at 32 chars (env migration preflight now auto-expands to 255).
- Confirm no port conflict and restart with known-good command path.

### B. Dependency vulnerability alert
- Run deep review script.
- Identify direct versus transitive package path.
- Patch direct dependencies first.
- If blocked by ecosystem constraints, time-boxed exception with compensating controls.

### C. Frontend public incident
- Validate fallback pages and incident banner behavior (`#globalErrorBanner`, `#platformDowntimeBanner`, `#platformMaintenanceBanner`, `#platformSlowPerformanceBanner`).
- Enable maintenance mode via runtime config `platform.maintenance_mode=true` and optional `platform.maintenance_message` for operator-visible banner text.
- Review operator feedback reports in Overview (**Operator Feedback Reports**) or via `GET /platform/feedback`; triage with `POST /platform/feedback/{id}/actions`.
- Verify CSP and security smoke checks.
- Announce user-facing status and mitigation timeline.

### D. Login lockout or credential abuse spike
- Confirm deny-event trend from `auth.login.password` audit events.
- Validate runtime policy values for lockout controls:
	- `auth.login.max_failed_attempts`
	- `auth.login.lockout_minutes`
- Unlock affected users only through approved admin workflow:
	- `POST /auth/directory/users/{user_id}/unlock`
- Escalate repeated unlock requests for the same actor/user pair as potential abuse.

### E. Cursor credential / secret provider change
- Canonical operator path: **Providers → Secret Providers** (not Routing & Gateway legacy cursor-token form).
- Configure secret provider (`db`, Vault, AWS, or Azure), store db values at refs like `gateway/cursor-token`, then save gateway binding (`PUT /gateway/cursor-secret-binding`).
- Verify masked readback only (no plaintext in API responses).
- Review audit events: `secret_provider.value.*`, `gateway.cursor_secret_binding.*`.
- For incident rotation: update db secret value or external vault secret, then confirm binding still resolves.
- CISO evidence and gap tracking: `backend/docs/governance/unified-secret-provider-ciso-gap-analysis.md`.
- Regression validation: `python3 -m pytest backend/tests/test_secret_provider_db_values.py -q`.

## Platform runtime-config keys (operator UX)

| Key | Purpose |
|---|---|
| `platform.maintenance_mode` | Show global maintenance banner |
| `platform.maintenance_message` | Maintenance banner text |
| `platform.slow_response_threshold_ms` | Slow-performance banner threshold (client latency vs health probes) |
| `platform.feedback.enabled` | Enable/disable feedback submission |

### F. Operator feedback persistence and audit review

1. Confirm row exists after submit:
   ```bash
   curl -s 'http://127.0.0.1:8000/platform/feedback?limit=5' \
     -H 'X-Actor-Role: Auditor' -H 'X-Actor-Id: audit-reader' | jq
   ```
2. Confirm audit trail for mutations:
   ```bash
   curl -s 'http://127.0.0.1:8000/audit/events?limit=20&action_type_prefix=platform.feedback' \
     -H 'X-Actor-Role: Auditor' -H 'X-Actor-Id: audit-reader' | jq
   ```
3. Triage updates both `operator_feedback.status` and audit (`platform.feedback.acknowledge`, etc.).

Storage: PostgreSQL `operator_feedback` (not ephemeral). Playground run feedback uses separate table `playground_run_feedback`.

## 7. Backup and Recovery Expectations

- Define RPO and RTO per environment.
- Perform periodic restore validation drills.
- Record drill results and corrective actions.

## 8. Change and Rollback Operations

Before release:
- Complete release gate checklist and approvals.

After release:
- Verify health and critical user flows.
- Keep rollback path ready until stabilization window closes.

## 9. Operational KPIs

Track at minimum:
- Availability (monthly)
- Mean time to detect
- Mean time to recover
- Change failure rate
- Vulnerability SLA adherence

## 10. Documentation Maintenance

Update this guide when:
- New critical workflows are introduced (including secret provider model changes — sync `unified-secret-provider-ciso-gap-analysis.md`, API inventory, and frontend README).
- Incident process changes.
- Tooling or command paths change.
- Governance gates are revised.
