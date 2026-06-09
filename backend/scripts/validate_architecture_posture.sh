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

is_true() {
  local value
  value="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  [[ "$value" == "1" || "$value" == "true" || "$value" == "yes" || "$value" == "on" ]]
}

is_false() {
  local value
  value="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  [[ "$value" == "0" || "$value" == "false" || "$value" == "no" || "$value" == "off" ]]
}

is_int_ge() {
  local raw="$1"
  local min="$2"
  [[ "$raw" =~ ^[0-9]+$ ]] && [[ "$raw" -ge "$min" ]]
}

run_child_check() {
  local title="$1"
  local script_path="$2"
  echo
  echo "-- $title --"
  if [[ ! -x "$script_path" ]]; then
    if [[ -f "$script_path" ]]; then
      bash "$script_path"
    else
      fail "$script_path not found"
      return
    fi
  else
    "$script_path"
  fi
  local rc=$?
  if [[ "$rc" -eq 0 ]]; then
    pass "$title passed"
  else
    fail "$title failed"
  fi
}

echo "Architecture posture validation"

APP_ENV_VALUE="${APP_ENV:-${ENVIRONMENT:-dev}}"
APP_ENV_VALUE="$(printf '%s' "$APP_ENV_VALUE" | tr '[:upper:]' '[:lower:]')"
IS_NON_LOCAL=0
if [[ "$APP_ENV_VALUE" != "dev" && "$APP_ENV_VALUE" != "test" && "$APP_ENV_VALUE" != "local" ]]; then
  IS_NON_LOCAL=1
fi

run_child_check "Day-0 secrets" "./scripts/validate_day0_secrets.sh"
run_child_check "Security monitoring" "./scripts/validate_security_monitoring_setup.sh"


echo

echo "-- Security Architect lens --"
if [[ "$IS_NON_LOCAL" -eq 1 ]]; then
  if is_true "${STARTUP_AUTO_CREATE_SCHEMA:-false}"; then
    fail "STARTUP_AUTO_CREATE_SCHEMA must be false outside dev/test/local"
  else
    pass "STARTUP_AUTO_CREATE_SCHEMA is disabled in non-local environment"
  fi

  if printf '%s' "${CORS_ALLOW_ORIGINS:-}" | grep -q '\*'; then
    fail "CORS_ALLOW_ORIGINS must not include '*' outside dev/test/local"
  else
    pass "CORS_ALLOW_ORIGINS wildcard check"
  fi
else
  warn "Security architect strict checks are relaxed in dev/test/local"
fi


echo

echo "-- Cloud Architect lens --"
if is_int_ge "${DB_POOL_SIZE:-0}" 1; then
  pass "DB_POOL_SIZE is valid"
else
  fail "DB_POOL_SIZE must be >= 1"
fi

if is_int_ge "${DB_POOL_MAX_OVERFLOW:-0}" 0; then
  pass "DB_POOL_MAX_OVERFLOW is valid"
else
  fail "DB_POOL_MAX_OVERFLOW must be >= 0"
fi

if is_int_ge "${DB_POOL_TIMEOUT_SECONDS:-0}" 1; then
  pass "DB_POOL_TIMEOUT_SECONDS is valid"
else
  fail "DB_POOL_TIMEOUT_SECONDS must be >= 1"
fi

if is_int_ge "${DB_POOL_RECYCLE_SECONDS:-0}" 60; then
  pass "DB_POOL_RECYCLE_SECONDS is valid"
else
  fail "DB_POOL_RECYCLE_SECONDS must be >= 60"
fi


echo

echo "-- PAM / IAM lens --"
if [[ "$IS_NON_LOCAL" -eq 1 ]]; then
  if is_false "${ALLOW_HEADER_ACTOR_AUTH:-false}"; then
    pass "ALLOW_HEADER_ACTOR_AUTH is disabled in non-local environment"
  else
    fail "ALLOW_HEADER_ACTOR_AUTH must be false outside dev/test/local"
  fi

  if is_false "${MFA_ENFORCEMENT_OPTIONAL:-false}"; then
    pass "MFA_ENFORCEMENT_OPTIONAL is disabled in non-local environment"
  else
    fail "MFA_ENFORCEMENT_OPTIONAL must be false outside dev/test/local"
  fi
fi

if [[ -n "${SESSION_TOKEN_SIGNING_KEYS:-}" ]]; then
  key_count=$(printf '%s' "${SESSION_TOKEN_SIGNING_KEYS}" | tr ',' '\n' | grep -Ec '.+')
  if [[ "$IS_NON_LOCAL" -eq 1 && "$key_count" -lt 2 ]]; then
    fail "SESSION_TOKEN_SIGNING_KEYS should contain at least 2 keys in non-local environments"
  else
    pass "SESSION_TOKEN_SIGNING_KEYS rotation readiness check"
  fi
else
  warn "SESSION_TOKEN_SIGNING_KEYS is not set"
fi


echo

echo "-- CISO / Vulnerability / Cloud Security lens --"
if [[ "$IS_NON_LOCAL" -eq 1 ]]; then
  if is_false "${EXPOSE_WORKLOAD_IDENTITY_ACCESS_TOKEN:-false}"; then
    pass "EXPOSE_WORKLOAD_IDENTITY_ACCESS_TOKEN is disabled in non-local environment"
  else
    fail "EXPOSE_WORKLOAD_IDENTITY_ACCESS_TOKEN must be false outside dev/test/local"
  fi
fi

if [[ -n "${SESSION_SECRET:-}" ]]; then
  warn "SESSION_SECRET is deprecated and should remain unset"
else
  pass "SESSION_SECRET deprecated alias is unset"
fi

if is_int_ge "${RATE_LIMIT_REDIS_RETRY_SECONDS:-0}" 5; then
  pass "RATE_LIMIT_REDIS_RETRY_SECONDS is valid"
else
  fail "RATE_LIMIT_REDIS_RETRY_SECONDS must be >= 5"
fi

if is_int_ge "${RATE_LIMIT_DEGRADED_ALERT_ATTEMPTS:-0}" 1; then
  pass "RATE_LIMIT_DEGRADED_ALERT_ATTEMPTS is valid"
else
  fail "RATE_LIMIT_DEGRADED_ALERT_ATTEMPTS must be >= 1"
fi


echo

echo "-- Compliance Architect lens --"
if is_int_ge "${SESSION_TOKEN_ROTATION_MAX_DAYS:-0}" 1; then
  if [[ "${SESSION_TOKEN_ROTATION_MAX_DAYS}" -gt 90 ]]; then
    warn "SESSION_TOKEN_ROTATION_MAX_DAYS is high (>90); review policy expectations"
  else
    pass "SESSION_TOKEN_ROTATION_MAX_DAYS policy check"
  fi
else
  fail "SESSION_TOKEN_ROTATION_MAX_DAYS must be >= 1"
fi

if [[ -n "${SESSION_TOKEN_SIGNING_LAST_ROTATED_AT:-}" ]]; then
  pass "SESSION_TOKEN_SIGNING_LAST_ROTATED_AT is set"
else
  warn "SESSION_TOKEN_SIGNING_LAST_ROTATED_AT is not set"
fi

echo
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  echo "Summary: fails=$FAIL_COUNT warnings=$WARN_COUNT"
  exit 1
fi

echo "Summary: fails=$FAIL_COUNT warnings=$WARN_COUNT"
exit 0
