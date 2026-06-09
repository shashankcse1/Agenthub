#!/usr/bin/env bash
set -u

FAIL_COUNT=0
WARN_COUNT=0

pass() {
  echo "[PASS] $1"
}

warn() {
  WARN_COUNT=$((WARN_COUNT + 1))
  echo "[WARN] $1"
}

fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "[FAIL] $1"
}

finish() {
  echo
  echo "Summary: fails=$FAIL_COUNT warnings=$WARN_COUNT"
  if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
  fi
  exit 0
}

echo "Security monitoring setup validation"

APP_ENV_VALUE="${APP_ENV:-${ENVIRONMENT:-dev}}"
APP_ENV_VALUE="$(printf '%s' "$APP_ENV_VALUE" | tr '[:upper:]' '[:lower:]')"

ROTATION_MAX_DAYS="${SESSION_TOKEN_ROTATION_MAX_DAYS:-30}"
if [[ "$ROTATION_MAX_DAYS" =~ ^[0-9]+$ ]] && [[ "$ROTATION_MAX_DAYS" -gt 0 ]]; then
  pass "SESSION_TOKEN_ROTATION_MAX_DAYS is a positive integer"
else
  fail "SESSION_TOKEN_ROTATION_MAX_DAYS must be a positive integer"
fi

if [[ -n "${SESSION_TOKEN_SIGNING_LAST_ROTATED_AT:-}" ]]; then
  pass "SESSION_TOKEN_SIGNING_LAST_ROTATED_AT is set"
else
  warn "SESSION_TOKEN_SIGNING_LAST_ROTATED_AT is not set"
fi

if [[ "${RATE_LIMIT_BACKEND:-memory}" == "redis" ]]; then
  if [[ -n "${RATE_LIMIT_REDIS_URL:-}" ]]; then
    pass "RATE_LIMIT_REDIS_URL is set for redis backend"
  else
    fail "RATE_LIMIT_REDIS_URL is required when RATE_LIMIT_BACKEND=redis"
  fi
else
  warn "RATE_LIMIT_BACKEND is not redis; distributed enforcement is not active"
fi

RATE_LIMIT_429_WARN_PER_MIN="${RATE_LIMIT_429_WARN_PER_MIN:-}"
if [[ -n "$RATE_LIMIT_429_WARN_PER_MIN" && "$RATE_LIMIT_429_WARN_PER_MIN" =~ ^[0-9]+$ ]]; then
  pass "RATE_LIMIT_429_WARN_PER_MIN threshold is configured"
else
  warn "RATE_LIMIT_429_WARN_PER_MIN threshold is not configured"
fi

RATE_LIMIT_REDIS_FALLBACK_WARN_PER_HOUR="${RATE_LIMIT_REDIS_FALLBACK_WARN_PER_HOUR:-}"
if [[ -n "$RATE_LIMIT_REDIS_FALLBACK_WARN_PER_HOUR" && "$RATE_LIMIT_REDIS_FALLBACK_WARN_PER_HOUR" =~ ^[0-9]+$ ]]; then
  pass "RATE_LIMIT_REDIS_FALLBACK_WARN_PER_HOUR threshold is configured"
else
  warn "RATE_LIMIT_REDIS_FALLBACK_WARN_PER_HOUR threshold is not configured"
fi

if [[ -n "${SECURITY_ALERT_WEBHOOK_URL:-}" ]]; then
  pass "SECURITY_ALERT_WEBHOOK_URL is configured"
else
  if [[ "$APP_ENV_VALUE" == "prod" || "$APP_ENV_VALUE" == "production" ]]; then
    fail "SECURITY_ALERT_WEBHOOK_URL should be configured in production"
  else
    warn "SECURITY_ALERT_WEBHOOK_URL is not configured"
  fi
fi

finish
