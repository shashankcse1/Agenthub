# Agent Delivery Checklist

Use this checklist for each feature/fix to ensure completion through agent workflows.

## A. Task Metadata
- Change ID:
- Date:
- Owner:
- Modules impacted (MOD-*):
- Endpoints/files impacted:

## B. Role-Lens Review

### Security Architect
- [ ] Threat assumptions documented
- [ ] Authn/authz impact reviewed
- [ ] Token/secret handling reviewed
- [ ] Abuse paths and rate-limits reviewed

### Audit Architect
- [ ] Critical operations emit audit events
- [ ] Deny-path audit requirements reviewed
- [ ] Evidence/queryability confirmed

### CISO
- [ ] Business impact classification (L/M/H/C)
- [ ] Residual risk identified
- [ ] Accepted risk (if any) time-bounded
- [ ] Go/No-Go recommendation drafted

### AWS Engineer
- [ ] IAM/STS usage reviewed
- [ ] Secrets handling reviewed
- [ ] Env-flag safety for non-local environments reviewed

### Cloud Engineer
- [ ] Startup/runtime safety checks reviewed
- [ ] Observability/alerts impact reviewed
- [ ] Rollback/failure mode reviewed

### AI Architect
- [ ] Model and routing strategy reviewed for safety/quality trade-offs
- [ ] Prompt/tool constraints reviewed for policy compliance
- [ ] Fallback behavior reviewed for deterministic and fail-closed outcomes
- [ ] Evaluation signals defined or updated for changed AI behaviors

### Frontend UI Expert
- [ ] UX flows reviewed for happy and failure paths
- [ ] Accessibility basics validated (labels, keyboard, contrast)
- [ ] Responsive behavior validated for key screens
- [ ] Operator evidence/export workflows reviewed where applicable

### Security Engineer Expert
- [ ] Input validation and abuse paths reviewed
- [ ] Endpoint-level security controls reviewed
- [ ] Security regression tests added/updated
- [ ] Login lockout and unlock abuse controls reviewed (where auth scope is impacted)
- [ ] Structured logging fields verified for investigation readiness (actor/action/resource/outcome/trace)

## C. Engineering Completion
- [ ] Implementation complete
- [ ] Unit/integration tests added or updated
- [ ] Regression tests run and passing
- [ ] Docs updated
- [ ] Delivery split into reviewable agent-friendly slices with explicit scope and control impact

## D. Risk and Control Updates
- [ ] Residual risk register updated (if risk posture changed)
- [ ] Compensating controls documented
- [ ] Decision log entry added (if acceptance required)

## E. Verification Evidence
- Commands run:
- Test results:
- Key logs/screenshots/artifacts:
- Audit/logging evidence references (deny/allow paths + trace IDs):
- Evidence export/readback validation notes:

## F. Final Agent Completion Statement
- [ ] Scope fully completed by agent workflows
- [ ] No pending in-scope TODOs
- [ ] Remaining out-of-scope items explicitly listed
- [ ] Required approvals captured (Security, CISO, AWS, Cloud, AI, UI, Audit)
