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

usage() {
  cat <<'EOF'
Usage: ./scripts/validate_ingress_security_headers.sh [--url=<base_url>] [--path=<path>] [--expect-hsts=<true|false>]

Environment alternatives:
  INGRESS_BASE_URL   Base URL to validate (default http://127.0.0.1:8000)
  INGRESS_TEST_PATH  Path to test (default /health)
EOF
}

BASE_URL="${INGRESS_BASE_URL:-http://127.0.0.1:8000}"
TEST_PATH="${INGRESS_TEST_PATH:-/health}"
EXPECT_HSTS="true"

for arg in "$@"; do
  case "$arg" in
    --url=*)
      BASE_URL="${arg#*=}"
      ;;
    --path=*)
      TEST_PATH="${arg#*=}"
      ;;
    --expect-hsts=*)
      EXPECT_HSTS="${arg#*=}"
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unsupported option: $arg"
      usage
      exit 1
      ;;
  esac
done

EXPECT_HSTS_NORMALIZED="$(printf '%s' "$EXPECT_HSTS" | tr '[:upper:]' '[:lower:]')"

TARGET_URL="${BASE_URL%/}${TEST_PATH}"

echo "Ingress security header validation"
echo "Target: $TARGET_URL"

if ! command -v curl >/dev/null 2>&1; then
  fail "curl is required"
  echo
  echo "Summary: fails=$FAIL_COUNT warnings=$WARN_COUNT"
  exit 1
fi

HEADERS_RAW="$(curl -sS -D - -o /dev/null "$TARGET_URL" || true)"
if [[ -z "$HEADERS_RAW" ]]; then
  fail "Unable to retrieve headers from target URL"
  echo
  echo "Summary: fails=$FAIL_COUNT warnings=$WARN_COUNT"
  exit 1
fi

HEADER_TEXT="$(printf '%s' "$HEADERS_RAW" | tr -d '\r')"

contains_header() {
  local pattern="$1"
  printf '%s\n' "$HEADER_TEXT" | grep -Eiq "$pattern"
}

if contains_header '^X-Content-Type-Options:\s*nosniff$'; then
  pass "X-Content-Type-Options is nosniff"
else
  fail "X-Content-Type-Options nosniff header missing"
fi

if contains_header '^X-Frame-Options:\s*DENY$'; then
  pass "X-Frame-Options is DENY"
else
  fail "X-Frame-Options DENY header missing"
fi

if contains_header '^Referrer-Policy:\s*no-referrer$'; then
  pass "Referrer-Policy is no-referrer"
else
  fail "Referrer-Policy no-referrer header missing"
fi

if [[ "$EXPECT_HSTS_NORMALIZED" == "true" ]]; then
  if contains_header '^Strict-Transport-Security:\s*'; then
    pass "Strict-Transport-Security header is present"
  else
    fail "Strict-Transport-Security header missing"
  fi
else
  if contains_header '^Strict-Transport-Security:\s*'; then
    warn "Strict-Transport-Security header present while expectation is false"
  else
    pass "Strict-Transport-Security header not required and not present"
  fi
fi

if contains_header '^Access-Control-Allow-Origin:\s*\*$'; then
  fail "Access-Control-Allow-Origin wildcard is exposed"
else
  pass "No wildcard Access-Control-Allow-Origin header detected"
fi

echo
printf '%s\n' "Summary: fails=$FAIL_COUNT warnings=$WARN_COUNT"
if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi
exit 0
