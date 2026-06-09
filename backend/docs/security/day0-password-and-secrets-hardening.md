# Day-0 Password and Secrets Hardening

Use this guide for initial environment setup to reduce credential exposure risk.

## 1) Core Rules

- Never commit passwords, tokens, or secrets into source control.
- Avoid inline passwords in command history and shell commands.
- Prefer secret files with strict permissions or secret manager injection.
- Rotate any credential that has been exposed in command logs or chat history.

## 2) Database Password Handling (Recommended)

Preferred pattern:
- Store database password in `~/.pgpass` (or a dedicated file referenced by `PGPASSFILE`).
- Set file permission to `600`.
- Use a password-less `DATABASE_URL` user/host form.

Example:

```bash
cat > ~/.pgpass <<'EOF'
localhost:5432:agenthub:postgres:REPLACE_WITH_STRONG_PASSWORD
EOF
chmod 600 ~/.pgpass
export PGPASSFILE="$HOME/.pgpass"
export DATABASE_URL='postgresql+psycopg://postgres@localhost:5432/agenthub'
```

Avoid for persistent use:
- `DATABASE_URL` with inline password (`...://user:password@host/...`)
- long-lived `PGPASSWORD` exports

## 3) Session Token Secret and Signing Key Requirements

- Set `SESSION_TOKEN_SECRET` to a random string with at least 32 characters.
- Prefer production key-ring signing with `SESSION_TOKEN_SIGNING_KEYS`.
- Do not use defaults such as `secret`, `changeme`, or `dev-secret`.

Example generation:

```bash
python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(48))
PY
```

Example key-ring configuration for rollout/rotation:

```bash
export SESSION_TOKEN_SIGNING_KEYS='k2:<new-strong-secret-32-plus>,k1:<previous-strong-secret-32-plus>'
export SESSION_TOKEN_SIGNING_LAST_ROTATED_AT='2026-06-05T00:00:00Z'
export SESSION_TOKEN_ROTATION_MAX_DAYS=30
```

Notes:
- The first key id in `SESSION_TOKEN_SIGNING_KEYS` signs newly issued tokens.
- Older key ids remain valid during a controlled transition window.

## 4) Validate Setup

Run:

```bash
cd backend
bash scripts/validate_day0_secrets.sh
```

This checks:
- `SESSION_TOKEN_SECRET` presence/length/default pattern
- `SESSION_TOKEN_SIGNING_KEYS` format and minimum key quality (when configured)
- rotation metadata hygiene (`SESSION_TOKEN_SIGNING_LAST_ROTATED_AT`, `SESSION_TOKEN_ROTATION_MAX_DAYS`)
- `DATABASE_URL` inline-password exposure
- `PGPASSWORD` usage warning
- `PGPASSFILE` existence and permissions

## 5) CI and Release Evidence

Include day-0 secret validation in release evidence generation and archive logs for auditability.

## 6) DB Pool and Rate-Limit Degraded Controls

Set DB pool controls in environment:

```bash
export DB_POOL_PRE_PING=true
export DB_POOL_RECYCLE_SECONDS=1800
```

Set Redis degraded-mode controls for distributed rate limiting:

```bash
export RATE_LIMIT_BACKEND=redis
export RATE_LIMIT_REDIS_RETRY_SECONDS=30
export RATE_LIMIT_DEGRADED_ALERT_ATTEMPTS=10
```

Operational checks:
- Monitor `/health` -> `rate_limit.degraded` and treat `true` as warning state.
- Escalate when recovery attempts exceed `RATE_LIMIT_DEGRADED_ALERT_ATTEMPTS` without recovery.
