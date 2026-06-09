# Product Maturity Scorecard

Use this scorecard each release cycle to measure readiness and identify gaps.

## Scoring Model

- Score each control from 0 to 4.
- 0: Not started
- 1: Ad hoc
- 2: Defined
- 3: Measured
- 4: Optimized

## Domains and Weights

- Reliability and Release Safety (25%)
- Security and Vulnerability Management (25%)
- Operations and Incident Readiness (20%)
- Product Quality and UX Accessibility (15%)
- Governance and Compliance Evidence (15%)

## Domain Controls

### 1. Reliability and Release Safety

- Canonical startup and shutdown workflow is documented and reproducible.
- API startup preflight checks validate database, ports, and required env vars.
- CI pipeline has required checks for tests and smoke gates.
- Release rollback process exists and is tested.
- Test flake rate is measured and controlled.

### 2. Security and Vulnerability Management

- Full-stack expert review script passes in deep mode.
- Dependency vulnerability scanning is run in release process.
- Security findings are triaged with SLA by severity.
- Secrets handling and token controls are documented and reviewed.
- Threat models are maintained for critical modules.

### 3. Operations and Incident Readiness

- Service level objectives (SLO) are defined and monitored.
- Incident severity matrix and paging/escalation paths exist.
- Runbooks exist for common outages and degradation cases.
- Backup and restore drills are executed with evidence.
- Mean time to recovery is tracked against target.

### 4. Product Quality and UX Accessibility

- Public-facing default error pages exist and are maintained.
- Accessibility conformance report is current and reviewed.
- Keyboard, focus, screen reader, and mobile behavior are verified.
- Error states and incident guidance are clear and actionable.
- Frontend security and resilience smoke checks are required.

### 5. Governance and Compliance Evidence

- Release gate checklist is completed with sign-offs.
- Residual risk register is updated for control exceptions.
- Audit trail for critical control changes is queryable.
- Admin and operational guides are current.
- Evidence package is archived per release.

## Release Scoring Sheet

- Release ID:
- Date:
- Reviewer:

| Domain | Weight | Raw Score (0-4) | Weighted Score |
| --- | --- | --- | --- |
| Reliability and Release Safety | 25 |  |  |
| Security and Vulnerability Management | 25 |  |  |
| Operations and Incident Readiness | 20 |  |  |
| Product Quality and UX Accessibility | 15 |  |  |
| Governance and Compliance Evidence | 15 |  |  |

- Total Weighted Score (0-400):
- Normalized Score (0-100):

## Maturity Bands

- 0-39: Early
- 40-59: Developing
- 60-79: Production-Capable
- 80-100: Mature

## Exit Criteria for Public-Facing Banking Use

- Normalized score >= 80.
- No open critical vulnerabilities outside SLA.
- Release gate checklist fully signed.
- Accessibility report updated in current cycle.
- Incident response runbook validation completed in current cycle.
