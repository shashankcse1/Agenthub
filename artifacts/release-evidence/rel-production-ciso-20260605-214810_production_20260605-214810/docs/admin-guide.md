# Admin Guide

This guide is for platform administrators responsible for configuration, security posture, and release controls.

## 1. Responsibilities

- Manage environment configuration and service startup controls.
- Enforce role-based access requirements for sensitive operations.
- Review and sign release gates before production changes.
- Maintain security and governance documents.
- Coordinate with operations during incidents.

## 2. Access and Role Model

Primary operational roles:
- Platform Admin
- Security Approver
- Auditor
- Release Manager
- Agent Owner

Admin expectations:
- Use least privilege for day-to-day actions.
- Reserve elevated roles for approved windows.
- Ensure actor context used in tools is accurate and auditable.

## 3. Environment Configuration

Before startup:
- Ensure `DATABASE_URL` is set.
- Ensure session secret and auth security flags are valid for environment.
- Ensure non-local environments do not allow insecure dev-only settings.

Recommended startup pattern:
- Use make targets and local scripts documented by repository operations rather than ad hoc commands.

## 4. Security Governance Tasks

Per release cycle:
- Run deep full-stack review script.
- Confirm vulnerability scans and triage outcomes.
- Review residual risk register and update accepted risks.
- Confirm admin and operations guides are current.

Required documents:
- `docs/governance/release-gate-checklist.md`
- `docs/governance/maturity-scorecard.md`
- `docs/security/residual-and-accepted-risk-register.md`

## 5. Frontend Public-Facing Controls

- Verify default error pages are present and user-safe.
- Verify accessibility conformance report is current.
- Verify frontend smoke checks pass.

## 6. Release Approval Workflow

1. Confirm technical gates pass.
2. Review security and risk gates.
3. Validate operational readiness.
4. Collect required sign-offs.
5. Declare GO/NO-GO with constraints.

## 7. Post-Release Duties

- Validate health, cost, and audit visibility.
- Confirm no unexpected deny/allow drift in key audit paths.
- Track incidents and open follow-up work items.
- Update maturity scorecard with latest release status.

## 8. Audit Evidence Expectations

Store release evidence package with:
- Commands executed
- Test outputs
- Scan summaries
- Decision records and approvals
- Incident follow-up notes (if applicable)

## 9. Quarterly Admin Review

At least quarterly:
- Reassess role definitions and permissions.
- Revalidate security defaults and environment guardrails.
- Re-run maturity scorecard and publish trend.
- Update this guide for process or tooling changes.
