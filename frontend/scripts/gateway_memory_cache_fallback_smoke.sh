#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
ROUTING_VIEW_FILE="$ROOT_DIR/views/routing-gateway.html"
APP_FILE="$ROOT_DIR/app.js"
TEST_CASE_DOC="$ROOT_DIR/../backend/docs/governance/memory-cache-fallback-test-cases.md"

API_BASE="${API_BASE:-http://127.0.0.1:8000}"
RUN_API_CHECKS="${RUN_API_CHECKS:-0}"
ADMIN_ID="${ADMIN_ID:-smoke-memory-admin}"
SEC_ID="${SEC_ID:-smoke-memory-sec}"

fail() {
  echo "[FAIL] $1"
  exit 1
}

pass() {
  echo "[PASS] $1"
}

require_file() {
  [[ -f "$1" ]] || fail "Missing file: $1"
}

require_token() {
  local token="$1"
  local file="$2"
  grep -F "$token" "$file" >/dev/null || fail "Missing token '$token' in $file"
}

request() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  shift 3 || true
  local curl_args=(-sS -X "$method" -H 'Content-Type: application/json' -H 'X-Actor-Role: Platform Admin' -H "X-Actor-Id: $ADMIN_ID")
  while [[ $# -gt 0 ]]; do
    curl_args+=(-H "$1")
    shift
  done
  if [[ -n "$body" ]]; then
    curl_args+=(-d "$body")
  fi
  curl "${curl_args[@]}" "$API_BASE$path"
}

json_extract() {
  python3 - "$1" "$2" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
key = sys.argv[2]
cur = payload
for part in key.split('.'):
    if isinstance(cur, dict):
        cur = cur.get(part)
    elif isinstance(cur, list) and part.isdigit():
        cur = cur[int(part)]
    else:
        cur = None
        break
if cur is None:
    print("")
elif isinstance(cur, (dict, list)):
    print(json.dumps(cur))
else:
    print(cur)
PY
}

assert_status() {
  local code="$1"
  local expected="$2"
  local label="$3"
  [[ "$code" == "$expected" ]] || fail "$label expected HTTP $expected got $code"
}

validate_ui_wiring() {
  require_file "$ROUTING_VIEW_FILE"
  require_file "$APP_FILE"
  require_file "$TEST_CASE_DOC"

  require_token 'data-gateway-console-tab="memory"' "$ROUTING_VIEW_FILE"
  require_token 'id="gatewayMemoryVerificationTable"' "$ROUTING_VIEW_FILE"
  require_token 'id="runGatewayMemoryVerificationSuite"' "$ROUTING_VIEW_FILE"
  require_token 'id="routePriorityChainTable"' "$ROUTING_VIEW_FILE"
  require_token 'id="gatewayFallbackVerificationTable"' "$ROUTING_VIEW_FILE"
  require_token 'id="runGatewayFallbackVerificationSuite"' "$ROUTING_VIEW_FILE"
  pass "Memory & fallback verification UI present in routing-gateway.html"

  require_token 'async function runGatewayMemoryVerificationSuite' "$APP_FILE"
  require_token 'async function runGatewayFallbackVerificationSuite' "$APP_FILE"
  require_token 'function validateRoutePriorityEntries' "$APP_FILE"
  require_token '"/gateway/memory/overview"' "$APP_FILE"
  pass "Verification suite handlers wired in app.js"

  grep -F 'MC-01' "$TEST_CASE_DOC" >/dev/null || fail "Test case doc missing MC-01"
  grep -F 'FB-05' "$TEST_CASE_DOC" >/dev/null || fail "Test case doc missing FB-05"
  pass "Test case document includes memory/cache/fallback scenarios"
}

validate_api_checks() {
  local response code body scope_id memory_id

  response="$(request GET '/gateway/memory/overview' '')"
  code="$(json_extract "$response" 'short_term_ttl_seconds')"
  [[ -n "$code" ]] || fail "Memory overview missing short_term_ttl_seconds"
  pass "MC-01 GET /gateway/memory/overview"

  scope_id="smoke-session-$(date +%s)"
  response="$(request POST '/gateway/memory/records' "{\"memory_tier\":\"short_term\",\"scope_type\":\"session\",\"scope_id\":\"$scope_id\",\"label\":\"smoke\",\"content\":\"Smoke short-term memory.\",\"environment\":\"dev\"}")"
  memory_id="$(json_extract "$response" 'memory_id')"
  [[ -n "$memory_id" ]] || fail "Short-term memory create did not return memory_id"
  pass "MC-02 POST /gateway/memory/records (short_term)"

  response="$(request GET "/gateway/memory/records?memory_tier=short_term&scope_id=$scope_id" '')"
  code="$(json_extract "$response" 'total')"
  [[ "${code:-0}" -ge 1 ]] || fail "Short-term list total should be >= 1"
  pass "MC-02 GET /gateway/memory/records"

  response="$(curl -sS -o /tmp/smoke_mem_deny.json -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' \
    -H 'X-Actor-Role: Platform Admin' \
    -H "X-Actor-Id: $ADMIN_ID" \
    -d '{"memory_tier":"long_term","scope_type":"global","scope_id":"platform","label":"smoke-prod","content":"deny check","environment":"prod"}' \
    "$API_BASE/gateway/memory/records")"
  assert_status "$response" "403" "MC-04 prod long-term create without approver"
  pass "MC-04 prod long-term dual-approval denial"

  response="$(request GET '/gateway/cache/stats' '')"
  [[ -n "$(json_extract "$response" 'hit_ratio')" ]] || fail "Cache stats missing hit_ratio"
  pass "CA-01 GET /gateway/cache/stats"

  response="$(request GET '/gateway/cache/health' '')"
  backend="$(json_extract "$response" 'cache_backend')"
  [[ "$backend" == "policy-managed" ]] || fail "Expected cache_backend policy-managed got '$backend'"
  pass "CA-02 GET /gateway/cache/health"

  response="$(request GET '/gateway/cache/policies?limit=5' '')"
  pass "CA-03 GET /gateway/cache/policies"

  request DELETE "/gateway/memory/records/$memory_id" '' >/dev/null || true
  pass "Cleanup short-term smoke record (best effort)"
}

echo "=== Gateway memory/cache/fallback smoke ==="
validate_ui_wiring

if [[ "$RUN_API_CHECKS" == "1" ]]; then
  echo "Running live API checks against $API_BASE"
  validate_api_checks
else
  echo "[INFO] Skipping live API checks. Set RUN_API_CHECKS=1 to validate endpoints."
fi

echo "Gateway memory/cache/fallback smoke checks completed successfully."
