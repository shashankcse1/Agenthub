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
- Multi-cloud fallback policy is documented and validated for production agents.
- AWS-specific operational controls (token lifetime, timeout, retry, and budget guardrails) are reviewed.
- CISO sign-off evidence includes security findings summary and compensating controls.
- Password-login lockout policy is configured within approved bounds and periodically reviewed.
- Privileged account unlock operations are MFA-gated and auditable.

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
- UI-managed configuration exports include reviewer identity, timestamp, and integrity checksum.
- Audit evidence bundle includes cloud provider priority, fallback, and circuit-breaker policy snapshots.

## Release Scoring Sheet

- Release ID: `leadership-loop-2026-08-06`
- Date: 2026-08-06
- Reviewer: Program Owner + SecArch (consolidated attestation `PROG-LRS-2026-08-06`)

| Domain | Weight | Raw Score (0-4) | Weighted Score | Notes |
| --- | --- | ---: | ---: | --- |
| Reliability and Release Safety | 25 | 3 | 75 | CI + smoke gates + rollback docs; flake rate not continuously measured |
| Security and Vulnerability Management | 25 | 4 | 100 | Dual-approval, PAM, secret providers; L6 signed; AR-001/002 Retired |
| Operations and Incident Readiness | 20 | 3 | 60 | Runbooks + dated RT/Tabletop 2026-08-06; MTTR dashboards still maturing |
| Product Quality and UX Accessibility | 15 | 2 | 30 | Consoles/Studio mature; accessibility report not refreshed this cycle |
| Governance and Compliance Evidence | 15 | 4 | 60 | LRS 40/40; formal signatures complete; QBR + drill registry live |

- Total Weighted Score (0-400): **325**
- Normalized Score (0-100): **81** (Mature)
- Leadership blockers: none for LRS gate (sustain quarterly drills)

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
