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
- [ ] Alembic version table compatibility verified (legacy PostgreSQL schemas with `alembic_version.version_num` length 32 are auto-expanded to 255).
- [ ] Control coverage checker passes.
- [ ] Feature/fix-level agent delivery checklist completed and attached (`backend/docs/governance/agent-delivery-checklist.md`).

## C. Security and Risk Gates

- [ ] No open critical vulnerabilities past SLA.
- [ ] High vulnerabilities have approved remediation or time-bounded exception.
- [ ] Residual risk register updated for accepted risks.
- [ ] Token/secret handling changes reviewed.
- [ ] Production mutation guardrails reviewed.
- [ ] Password-login lockout runtime policy reviewed (`auth.login.max_failed_attempts`, `auth.login.lockout_minutes`).
- [ ] Unlock operation governance reviewed (`POST /auth/directory/users/{user_id}/unlock`, admin + MFA).
- [ ] Audit evidence verified for `auth.login.password` deny paths and `auth.directory.user.unlock` allow paths.
- [ ] Logging traceability verified for critical actions (actor_id, action_type, resource_type/resource_id, decision_outcome, trace_id).
- [ ] Evidence export/readback workflows validated for changed governance surfaces (for example gateway governance export or equivalent).

## D. Architecture Lens Gates

- [ ] Security Architect review completed.
- [ ] CISO delegate review completed with residual-risk decision.
- [ ] AWS Architect review completed (IAM/STS/secret posture and region-role assumptions).
- [ ] Cloud Architect review completed (deployability, rollback, SLO/operability).
- [ ] AI Architect review completed (model-routing safety, fallback behavior, and policy alignment).
- [ ] UI Expert review completed (accessibility, responsive behavior, error-state clarity, and operator workflow quality).

## E. Product and UX Gates

- [ ] Public error pages verified (404 and 500).
- [ ] Accessibility conformance report updated for current UI revision.
- [ ] Core user journeys validated for success and failure paths.
- [ ] Mobile and desktop sanity checks completed.
- [ ] UI export/report workflows validated for operator evidence usage where applicable.

## F. Operational Readiness Gates

- [ ] SLO dashboard checked and within threshold.
- [ ] Alerting and on-call coverage confirmed.
- [ ] Rollback steps validated and documented.
- [ ] Incident communication template ready.
- [ ] Post-release verification commands defined.
- [ ] Release evidence bundle path recorded in change ticket.

## G. Agent-Friendly Delivery Gates

- [ ] Scope is delivered in reviewable slices with clear control impact notes.
- [ ] Verification commands and outcomes are captured in release notes/PR summary.
- [ ] Updated documentation references are included for all changed workflows.

## H. Approvals

- Security Architect: Name / Date / Approve-Deny
- Audit Architect: Name / Date / Approve-Deny
- CISO Delegate: Name / Date / Approve-Deny
- AWS Architect: Name / Date / Approve-Deny
- Cloud Architect: Name / Date / Approve-Deny
- AI Architect: Name / Date / Approve-Deny
- UI Expert: Name / Date / Approve-Deny
- Cloud Operations: Name / Date / Approve-Deny
- Product Owner: Name / Date / Approve-Deny

## I. Final Decision

- Decision: GO / NO-GO
- Constraints:
- Follow-up actions and deadlines:
