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
- API health and error rate
- Authz/authn denial anomalies
- Rate-limit event spikes
- Token exchange failures
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
- Confirm no port conflict and restart with known-good command path.

### B. Dependency vulnerability alert
- Run deep review script.
- Identify direct versus transitive package path.
- Patch direct dependencies first.
- If blocked by ecosystem constraints, time-boxed exception with compensating controls.

### C. Frontend public incident
- Validate fallback pages and incident banner behavior.
- Verify CSP and security smoke checks.
- Announce user-facing status and mitigation timeline.

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
- New critical workflows are introduced.
- Incident process changes.
- Tooling or command paths change.
- Governance gates are revised.
