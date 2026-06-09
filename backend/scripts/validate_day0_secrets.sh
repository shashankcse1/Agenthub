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

has_inline_password() {
  # Matches scheme://user:password@host
  printf "%s" "$1" | grep -Eq '^[a-zA-Z0-9+.-]+://[^/:@]+:[^@]+@'
}

print_summary_and_exit() {
  echo
  echo "Summary: fails=$FAIL_COUNT warnings=$WARN_COUNT"
  if [[ "$FAIL_COUNT" -gt 0 ]]; then
    exit 1
  fi
  exit 0
}

echo "Day-0 secrets and password validation"

SESSION_TOKEN_SIGNING_KEYS_VALUE="${SESSION_TOKEN_SIGNING_KEYS:-}"
SESSION_TOKEN_SECRET_VALUE="${SESSION_TOKEN_SECRET:-}"
if [[ -z "$SESSION_TOKEN_SECRET_VALUE" && -n "${SESSION_SECRET:-}" ]]; then
  warn "SESSION_SECRET is deprecated; use SESSION_TOKEN_SECRET"
  SESSION_TOKEN_SECRET_VALUE="$SESSION_SECRET"
fi

if [[ -n "$SESSION_TOKEN_SIGNING_KEYS_VALUE" ]]; then
  pass "SESSION_TOKEN_SIGNING_KEYS is set"
  if printf "%s" "$SESSION_TOKEN_SIGNING_KEYS_VALUE" | grep -Eq '^[^:,]+:[^,]+(,[^:,]+:[^,]+)*$'; then
    pass "SESSION_TOKEN_SIGNING_KEYS format check"
  else
    fail "SESSION_TOKEN_SIGNING_KEYS must use comma-separated kid:secret format"
  fi
fi

if [[ -z "$SESSION_TOKEN_SECRET_VALUE" && -z "$SESSION_TOKEN_SIGNING_KEYS_VALUE" ]]; then
  fail "SESSION_TOKEN_SECRET or SESSION_TOKEN_SIGNING_KEYS must be set"
else
  if [[ -n "$SESSION_TOKEN_SECRET_VALUE" ]]; then
    secret_len=${#SESSION_TOKEN_SECRET_VALUE}
    if [[ "$secret_len" -lt 32 ]]; then
      fail "SESSION_TOKEN_SECRET must be at least 32 characters"
    else
      pass "SESSION_TOKEN_SECRET length check"
    fi

    case "$SESSION_TOKEN_SECRET_VALUE" in
      changeme|change-me|default|dev-secret|secret|insecure|password)
        fail "SESSION_TOKEN_SECRET uses a known weak default"
        ;;
      *)
        pass "SESSION_TOKEN_SECRET default-pattern check"
        ;;
    esac
  else
    warn "SESSION_TOKEN_SECRET not set; relying on SESSION_TOKEN_SIGNING_KEYS only"
  fi
fi

if [[ -z "${DATABASE_URL:-}" ]]; then
  warn "DATABASE_URL is not set (set it explicitly for runtime checks)"
else
  pass "DATABASE_URL is set"
  if has_inline_password "$DATABASE_URL"; then
    warn "DATABASE_URL contains inline password. Prefer .pgpass/PGPASSFILE or secret store injection."
  else
    pass "DATABASE_URL does not expose inline password"
  fi
fi

if [[ -n "${PGPASSWORD:-}" ]]; then
  warn "PGPASSWORD is set in environment. Prefer PGPASSFILE or secret manager for long-lived usage."
else
  pass "PGPASSWORD not set in environment"
fi

if [[ -n "${PGPASSFILE:-}" ]]; then
  if [[ -f "$PGPASSFILE" ]]; then
    perm=$(stat -f "%A" "$PGPASSFILE" 2>/dev/null || true)
    if [[ "$perm" == "600" ]]; then
      pass "PGPASSFILE permission check (600)"
    else
      warn "PGPASSFILE permissions should be 600 (current: ${perm:-unknown})"
    fi
  else
    warn "PGPASSFILE is set but file not found"
  fi
else
  warn "PGPASSFILE not set; consider using it to avoid inline DB passwords"
fi

print_summary_and_exit
