# Release Gate Checklist

Complete this checklist before any release to staging or production.

## A. Release Metadata

- Release ID:
- Environment: staging / production
- Date:
- Release Owner:
- Change Window:

## B. Required Technical Gates

- [ ] Release evidence bundle generated and archived: `make release-evidence RELEASE_ID=<id> ENV=<staging|production> OWNER=<name>`
- [ ] Auto-ID option acceptable for non-production trace bundles: `make release-evidence-auto ENV=staging OWNER=<name>`
- [ ] Strict evidence gate used for production candidate: `make release-evidence-strict RELEASE_ID=<id> ENV=production OWNER=<name>`
- [ ] DATABASE_URL configured for migration validation (defaults to local `postgresql+psycopg://$USER@localhost:5432/agenthub` if unset).
- [ ] Full-stack review script passes: `bash scripts/full_stack_expert_review.sh --deep`
- [ ] Day-0 secrets validation passes: `cd backend && bash scripts/validate_day0_secrets.sh`
- [ ] Backend test suite passes.
- [ ] Frontend security smoke checks pass.
- [ ] Database migrations validated for target environment.
- [ ] Control coverage checker passes.

## C. Security and Risk Gates

- [ ] No open critical vulnerabilities past SLA.
- [ ] High vulnerabilities have approved remediation or time-bounded exception.
- [ ] Residual risk register updated for accepted risks.
- [ ] Token/secret handling changes reviewed.
- [ ] Production mutation guardrails reviewed.

## D. Product and UX Gates

- [ ] Public error pages verified (404 and 500).
- [ ] Accessibility conformance report updated for current UI revision.
- [ ] Core user journeys validated for success and failure paths.
- [ ] Mobile and desktop sanity checks completed.

## E. Operational Readiness Gates

- [ ] SLO dashboard checked and within threshold.
- [ ] Alerting and on-call coverage confirmed.
- [ ] Rollback steps validated and documented.
- [ ] Incident communication template ready.
- [ ] Post-release verification commands defined.
- [ ] Release evidence bundle path recorded in change ticket.

## F. Approvals

- Security Architect: Name / Date / Approve-Deny
- Audit Architect: Name / Date / Approve-Deny
- CISO Delegate: Name / Date / Approve-Deny
- Cloud Operations: Name / Date / Approve-Deny
- Product Owner: Name / Date / Approve-Deny

## G. Final Decision

- Decision: GO / NO-GO
- Constraints:
- Follow-up actions and deadlines:
