# Security Operations Runbook

## Purpose
Operational runbook for security-sensitive configuration changes, emergency controls, and rollback actions.

## Scope
- Service: Enterprise Multi-Agent Platform API
- Environments: staging, production
- Owners: Platform Security, SecOps, Cloud Security, IAM Engineering

## Pre-Change Checklist
- Confirm active release gate owner and approver.
- Confirm current residual risk register entries and expiry dates.
- Confirm incident channel and on-call responders.
- Confirm rollback command set and database backup availability.

## Sensitive Runtime Flags
- ALLOW_HEADER_ACTOR_AUTH
: Must remain disabled outside dev/test/local.
- MFA_ENFORCEMENT_OPTIONAL
: Must remain disabled outside controlled break-glass windows.
- workload_identity.expose_access_token (runtime-config key)
: Sensitive DB-governed flag. Keep false by default; any temporary enablement requires dual approval and is fail-closed outside local/test.
- SESSION_TOKEN_SIGNING_KEYS
: Preferred for production token signing key rotation, using ordered key ids (`kid:secret,...`) with strongest/newest first.
- RATE_LIMIT_BACKEND
: Set to `redis` for distributed enforcement in multi-instance deployments; default is in-memory.
- RATE_LIMIT_REDIS_URL
: Redis connection URL for distributed rate limiting when RATE_LIMIT_BACKEND=redis.
- SECURITY_ALERT_WEBHOOK_URL
: Optional webhook endpoint for SIEM notifications when insecure startup configuration is detected.

## Break-Glass Procedure
1. Open an incident/change ticket with explicit expiration time.
2. Record risk acceptance approvers (CISO delegate + security lead).
3. Apply temporary flag change in deployment configuration.
4. Capture startup logs and audit evidence for the change window.
5. Restore secure defaults before the approved expiration time.
6. Verify post-restore with tests and strict review script.

## Session Signing Key Rotation Procedure
1. Generate a new 32+ character signing secret.
2. Prepend new key in SESSION_TOKEN_SIGNING_KEYS while keeping previous key(s) for rollover.
3. Deploy and verify newly issued session tokens include the new key id prefix.
4. Monitor token validation and auth failure metrics during rollover window.
5. Remove retired keys after expiry window for previously issued sessions.

## Password Login Lockout Operations
1. Validate lockout policy runtime settings before production rollout:
	- `auth.login.max_failed_attempts`
	- `auth.login.lockout_minutes`
2. Confirm failed login events are logged as `auth.login.password` with `decision_outcome=deny`.
3. Use admin unlock endpoint only under approved operator workflow:
	- `POST /auth/directory/users/{user_id}/unlock`
4. Unlock requires privileged actor role and MFA verification.
5. Confirm unlock emits `auth.directory.user.unlock` allow audit event.
6. Document any repeated unlock operations as potential credential abuse signals for IAM review.

## Distributed Rate-Limit Production Cutover Checklist
1. Set deployment configuration:
- `RATE_LIMIT_BACKEND=redis`
- `RATE_LIMIT_REDIS_URL=redis://<host>:6379/0`
- `RATE_LIMIT_REDIS_PREFIX=rate-limit`
2. Run preflight validation:
- `make rate-limit-cutover-check`
3. Verify live enforcement against API:
- `make rate-limit-cutover-probe PORT=8000`
4. Simulate backend outage fallback behavior:
- `make rate-limit-cutover-failover`
5. Record cutover evidence in release ticket and CISO packet.

## Distributed Rate-Limit Rollback Commands
1. Revert deployment env vars:
- `RATE_LIMIT_BACKEND=memory`
- unset `RATE_LIMIT_REDIS_URL`
2. Restart service rollout.
3. Validate rollback behavior:
- `make rate-limit-cutover-rollback`
- `python3 -m pytest -q`
- `bash scripts/full_stack_expert_review.sh --strict`

## Ingress HTTPS and HSTS Validation
1. Validate ingress/load-balancer headers against target endpoint:
- `make ingress-security-validate BASE_URL=https://api.example.com TEST_PATH=/health`
2. Confirm Strict-Transport-Security is present and compatible with ingress TLS termination.
3. Confirm wildcard CORS is not exposed by edge configuration.

## Rollback Procedure
1. Revert deployment configuration to secure defaults.
2. Restart service and validate startup checks pass.
3. Run:
- `python3 -m pytest -q`
- `bash scripts/full_stack_expert_review.sh --strict`
4. Verify no deny/allow audit drift on sensitive endpoints.
5. Update residual risk register decision log.

## Minimum Security Validation After Any Change
- Auth session policy endpoints enforce MFA + dual approval.
- Cost limit enforcement blocks spend-generating run creation when over budget.
- Response headers include HSTS, no-sniff, frame deny, strict referrer policy.
- CORS wildcard is rejected outside dev/test/local.

## Evidence to Archive
- Test report summary.
- Strict review script output.
- Audit evidence IDs for sensitive changes.
- Residual risk register update and sign-off status.
