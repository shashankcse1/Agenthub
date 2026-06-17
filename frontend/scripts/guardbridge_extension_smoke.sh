#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT_DIR/.." && pwd)"
EXT_DIR="$REPO_ROOT/extensions/guardbridge"

API_BASE="${API_BASE:-http://127.0.0.1:8000}"
RUN_API_CHECKS="${RUN_API_CHECKS:-0}"
ACTOR_ID="${ACTOR_ID:-smoke-guardbridge-sec}"

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
  local payload="${3:-}"
  shift 3 || true

  local body_file
  body_file="$(mktemp)"
  local code

  if [[ -n "$payload" ]]; then
    code="$(curl -sS -o "$body_file" -w "%{http_code}" -X "$method" \
      -H 'Content-Type: application/json' \
      "$@" \
      -d "$payload" \
      "$API_BASE$path")"
  else
    code="$(curl -sS -o "$body_file" -w "%{http_code}" -X "$method" \
      -H 'Content-Type: application/json' \
      "$@" \
      "$API_BASE$path")"
  fi

  local body
  body="$(cat "$body_file")"
  rm -f "$body_file"

  printf '%s\n%s\n' "$code" "$body"
}

json_extract() {
  local json="$1"
  local expr="$2"
  python3 - "$json" "$expr" <<'PY'
import json
import sys
payload = json.loads(sys.argv[1])
expr = sys.argv[2]
cur = payload
for part in expr.split('.') if expr else []:
    if isinstance(cur, dict):
        cur = cur.get(part)
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
  local actual="$1"
  local expected="$2"
  local context="$3"
  [[ "$actual" == "$expected" ]] || fail "$context expected status $expected but got $actual"
}

validate_files() {
  require_file "$EXT_DIR/manifest.json"
  require_file "$EXT_DIR/manifests/chromium/manifest.json"
  require_file "$EXT_DIR/manifests/firefox/manifest.json"
  require_file "$EXT_DIR/src/background.js"
  require_file "$EXT_DIR/src/content.js"
  require_file "$EXT_DIR/src/common.js"
  pass "GuardBridge extension scaffold files present"

  python3 -m json.tool "$EXT_DIR/manifest.json" >/dev/null
  python3 -m json.tool "$EXT_DIR/manifests/chromium/manifest.json" >/dev/null
  python3 -m json.tool "$EXT_DIR/manifests/firefox/manifest.json" >/dev/null
  pass "GuardBridge manifest JSON is valid"

  node --check "$EXT_DIR/src/background.js"
  node --check "$EXT_DIR/src/content.js"
  node --check "$EXT_DIR/src/common.js"
  pass "GuardBridge JS syntax is valid"

  require_token '"name": "GuardBridge Browser Security"' "$EXT_DIR/manifest.json"
  require_token '"manifest_version": 3' "$EXT_DIR/manifest.json"
  require_token '"manifest_version": 2' "$EXT_DIR/manifests/firefox/manifest.json"
  require_token '"guardbridge.emitEvent"' "$EXT_DIR/src/background.js"
    require_token '/browser/extensions/events' "$EXT_DIR/src/background.js"
    require_token '/browser/extensions/policies' "$EXT_DIR/src/background.js"
  pass "GuardBridge extension wiring tokens are present"
}

validate_api_checks() {
  local response
  local code
  local body
  local session_id

  response="$(request POST '/browser/extensions/sessions' '{"actor_id":"smoke-guardbridge-user","environment":"dev","browser_name":"chrome","browser_version":"124.0","extension_version":"0.1.0","os_name":"macos","os_version":"14.5","device_type":"desktop","device_managed":true,"user_agent_digest":"abcd1234","geo_country":"US","geo_region":"CA","geo_detail_level":"region","ip_hash":"deadbeef"}' -H 'X-Actor-Role: Security Approver' -H "X-Actor-Id: $ACTOR_ID")"
  code="$(printf '%s' "$response" | sed -n '1p')"
  body="$(printf '%s' "$response" | sed -n '2,$p')"
  assert_status "$code" "200" "Create extension session"
  session_id="$(json_extract "$body" 'session_id')"
  [[ -n "$session_id" ]] || fail "Session create missing session_id"
  pass "Browser extension session create"

  response="$(request POST '/browser/extensions/events' '{"trace_id":"gb-smoke-trace","actor_id":"smoke-guardbridge-user","environment":"dev","action_type":"prompt_send","destination_domain":"chatgpt.com","destination_app":"ChatGPT","page_url_host":"chatgpt.com","decision_outcome":"allow","risk_signals":["smoke"],"content_fingerprint":"fp-smoke","data_class":"standard","browser_name":"chrome","browser_version":"124.0","os_name":"macos","device_type":"desktop","geo_country":"US","geo_region":"CA"}' -H 'X-Actor-Role: Security Approver' -H "X-Actor-Id: $ACTOR_ID")"
  code="$(printf '%s' "$response" | sed -n '1p')"
  body="$(printf '%s' "$response" | sed -n '2,$p')"
  assert_status "$code" "200" "Ingest extension event"
  [[ -n "$(json_extract "$body" 'event_id')" ]] || fail "Event ingest missing event_id"
  pass "Browser extension event ingest"

  response="$(request GET '/browser/extensions/risk/summary?environment=dev' '' -H 'X-Actor-Role: Auditor' -H 'X-Actor-Id: smoke-guardbridge-aud')"
  code="$(printf '%s' "$response" | sed -n '1p')"
  body="$(printf '%s' "$response" | sed -n '2,$p')"
  assert_status "$code" "200" "Risk summary read"
  [[ -n "$(json_extract "$body" 'total_events_24h')" ]] || fail "Risk summary missing total_events_24h"
  pass "Browser extension risk summary read"
}

main() {
  validate_files

  if [[ "$RUN_API_CHECKS" == "1" ]]; then
    validate_api_checks
  else
    echo "[INFO] API checks skipped. Set RUN_API_CHECKS=1 to validate /browser endpoints."
  fi

  echo "GuardBridge extension smoke checks completed successfully."
}

main "$@"
