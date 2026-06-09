#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INDEX_FILE="$ROOT_DIR/index.html"
APP_FILE="$ROOT_DIR/app.js"

API_BASE="${API_BASE:-http://127.0.0.1:8000}"
RUN_API_CHECKS="${RUN_API_CHECKS:-0}"

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
parts = expr.split('.') if expr else []
cur = payload
for part in parts:
    if part.endswith(']') and '[' in part:
        name, index = part[:-1].split('[', 1)
        if name:
            cur = cur.get(name)
        cur = cur[int(index)]
    else:
        if isinstance(cur, dict):
            cur = cur.get(part)
        else:
            raise SystemExit(1)
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

validate_ui_wiring() {
  require_file "$INDEX_FILE"
  require_file "$APP_FILE"

  require_token 'id="gatewayOpenAiChatForm"' "$INDEX_FILE"
  require_token 'id="gatewayOpenAiResponsesCreateForm"' "$INDEX_FILE"
  require_token 'id="gatewayOpenAiResponsesOpsForm"' "$INDEX_FILE"
  require_token 'id="gatewayOpenAiFilesCreateForm"' "$INDEX_FILE"
  require_token 'id="gatewayOpenAiFilesOpsForm"' "$INDEX_FILE"
  require_token 'id="selectAllGatewayOpenAiResponses"' "$INDEX_FILE"
  require_token 'id="bulkDeleteGatewayOpenAiResponses"' "$INDEX_FILE"
  require_token 'id="applyGatewayOpenAiResponsesFilter"' "$INDEX_FILE"
  require_token 'id="selectAllGatewayOpenAiFiles"' "$INDEX_FILE"
  require_token 'id="bulkDeleteGatewayOpenAiFiles"' "$INDEX_FILE"
  require_token 'id="applyGatewayOpenAiFilesFilter"' "$INDEX_FILE"
  require_token 'id="gatewayOpenAiResponsesTable"' "$INDEX_FILE"
  require_token 'id="gatewayOpenAiFilesTable"' "$INDEX_FILE"
  pass "OpenAI-compatible gateway UI card is present"

  require_token 'async function runGatewayOpenAiChatCompletion' "$APP_FILE"
  require_token 'async function createGatewayOpenAiResponse' "$APP_FILE"
  require_token 'async function loadGatewayOpenAiResponses' "$APP_FILE"
  require_token 'async function loadGatewayOpenAiResponseById' "$APP_FILE"
  require_token 'async function deleteGatewayOpenAiResponseById' "$APP_FILE"
  require_token 'async function bulkDeleteGatewayOpenAiResponses' "$APP_FILE"
  require_token 'async function createGatewayOpenAiFile' "$APP_FILE"
  require_token 'async function loadGatewayOpenAiFiles' "$APP_FILE"
  require_token 'async function loadGatewayOpenAiFileById' "$APP_FILE"
  require_token 'async function deleteGatewayOpenAiFileById' "$APP_FILE"
  require_token 'async function bulkDeleteGatewayOpenAiFiles' "$APP_FILE"
  require_token '"/v1/chat/completions"' "$APP_FILE"
  require_token '"/v1/responses"' "$APP_FILE"
  require_token '"/v1/files"' "$APP_FILE"
  pass "OpenAI-compatible gateway handlers and API calls are wired"
}

validate_api_checks() {
  local response
  local code
  local body
  local response_id
  local prod_response_id
  local file_id
  local prod_file_id

  response="$(request POST '/v1/responses' '{"model":"gpt-4o-mini","input":"smoke dev response","stream":false,"environment":"dev"}' -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: smoke-openai-admin')"
  code="$(printf '%s' "$response" | sed -n '1p')"
  body="$(printf '%s' "$response" | sed -n '2,$p')"
  assert_status "$code" "200" "Create dev response"
  response_id="$(json_extract "$body" 'id')"
  [[ -n "$response_id" ]] || fail "Create dev response missing id"
  pass "Create dev response"

  response="$(request GET '/v1/responses?limit=20&offset=0' '' -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: smoke-openai-admin')"
  code="$(printf '%s' "$response" | sed -n '1p')"
  body="$(printf '%s' "$response" | sed -n '2,$p')"
  assert_status "$code" "200" "List responses"
  [[ "$(json_extract "$body" 'object')" == "list" ]] || fail "List responses object should be list"
  pass "List responses"

  response="$(request GET "/v1/responses/$response_id" '' -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: smoke-openai-admin')"
  code="$(printf '%s' "$response" | sed -n '1p')"
  body="$(printf '%s' "$response" | sed -n '2,$p')"
  assert_status "$code" "200" "Retrieve response"
  pass "Retrieve response"

  response="$(request POST '/v1/responses' '{"model":"gpt-4o-mini","input":"smoke prod response","stream":false,"environment":"prod"}' -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: smoke-openai-admin')"
  code="$(printf '%s' "$response" | sed -n '1p')"
  body="$(printf '%s' "$response" | sed -n '2,$p')"
  assert_status "$code" "200" "Create prod response"
  prod_response_id="$(json_extract "$body" 'id')"

  response="$(request DELETE "/v1/responses/$prod_response_id" '' -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: smoke-openai-admin')"
  code="$(printf '%s' "$response" | sed -n '1p')"
  body="$(printf '%s' "$response" | sed -n '2,$p')"
  assert_status "$code" "403" "Delete prod response without dual approval"
  [[ "$(json_extract "$body" 'detail.error_code')" == "AUTHZ_DUAL_APPROVAL_REQUIRED" ]] || fail "Prod response delete deny error code mismatch"
  pass "Prod response dual-approval deny path"

  response="$(request DELETE "/v1/responses/$prod_response_id" '' -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: smoke-openai-admin' -H 'X-Approver-Role: Security Approver' -H 'X-Approver-Id: smoke-openai-sec')"
  code="$(printf '%s' "$response" | sed -n '1p')"
  assert_status "$code" "200" "Delete prod response with dual approval"
  pass "Prod response dual-approval allow path"

  response="$(request DELETE "/v1/responses/$response_id" '' -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: smoke-openai-admin')"
  code="$(printf '%s' "$response" | sed -n '1p')"
  assert_status "$code" "200" "Delete dev response"
  pass "Delete dev response"

  response="$(request POST '/v1/responses' '{"model":"gpt-4o-mini","input":"forbidden role check","stream":false,"environment":"dev"}' -H 'X-Actor-Role: Auditor' -H 'X-Actor-Id: smoke-openai-auditor')"
  code="$(printf '%s' "$response" | sed -n '1p')"
  body="$(printf '%s' "$response" | sed -n '2,$p')"
  assert_status "$code" "403" "Auditor create response deny"
  [[ "$(json_extract "$body" 'detail.error_code')" == "AUTHZ_ROLE_FORBIDDEN" ]] || fail "Auditor response deny error code mismatch"
  pass "Response role-deny path"

  response="$(request POST '/v1/files' '{"filename":"smoke-dev.json","purpose":"assistants","bytes":128,"content_type":"application/json","metadata":{"source":"smoke"},"environment":"dev"}' -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: smoke-openai-admin')"
  code="$(printf '%s' "$response" | sed -n '1p')"
  body="$(printf '%s' "$response" | sed -n '2,$p')"
  assert_status "$code" "200" "Create dev file"
  file_id="$(json_extract "$body" 'id')"
  [[ -n "$file_id" ]] || fail "Create dev file missing id"
  pass "Create dev file"

  response="$(request GET '/v1/files?limit=20&offset=0' '' -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: smoke-openai-admin')"
  code="$(printf '%s' "$response" | sed -n '1p')"
  body="$(printf '%s' "$response" | sed -n '2,$p')"
  assert_status "$code" "200" "List files"
  [[ "$(json_extract "$body" 'object')" == "list" ]] || fail "List files object should be list"
  pass "List files"

  response="$(request GET "/v1/files/$file_id" '' -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: smoke-openai-admin')"
  code="$(printf '%s' "$response" | sed -n '1p')"
  assert_status "$code" "200" "Retrieve file"
  pass "Retrieve file"

  response="$(request POST '/v1/files' '{"filename":"smoke-prod.json","purpose":"assistants","bytes":129,"content_type":"application/json","environment":"prod"}' -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: smoke-openai-admin')"
  code="$(printf '%s' "$response" | sed -n '1p')"
  body="$(printf '%s' "$response" | sed -n '2,$p')"
  assert_status "$code" "200" "Create prod file"
  prod_file_id="$(json_extract "$body" 'id')"

  response="$(request DELETE "/v1/files/$prod_file_id" '' -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: smoke-openai-admin')"
  code="$(printf '%s' "$response" | sed -n '1p')"
  body="$(printf '%s' "$response" | sed -n '2,$p')"
  assert_status "$code" "403" "Delete prod file without dual approval"
  [[ "$(json_extract "$body" 'detail.error_code')" == "AUTHZ_DUAL_APPROVAL_REQUIRED" ]] || fail "Prod file delete deny error code mismatch"
  pass "Prod file dual-approval deny path"

  response="$(request DELETE "/v1/files/$prod_file_id" '' -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: smoke-openai-admin' -H 'X-Approver-Role: Security Approver' -H 'X-Approver-Id: smoke-openai-sec')"
  code="$(printf '%s' "$response" | sed -n '1p')"
  assert_status "$code" "200" "Delete prod file with dual approval"
  pass "Prod file dual-approval allow path"

  response="$(request DELETE "/v1/files/$file_id" '' -H 'X-Actor-Role: Platform Admin' -H 'X-Actor-Id: smoke-openai-admin')"
  code="$(printf '%s' "$response" | sed -n '1p')"
  assert_status "$code" "200" "Delete dev file"
  pass "Delete dev file"

  response="$(request POST '/v1/files' '{"filename":"forbidden-role.json","purpose":"assistants","bytes":130,"environment":"dev"}' -H 'X-Actor-Role: Auditor' -H 'X-Actor-Id: smoke-openai-auditor')"
  code="$(printf '%s' "$response" | sed -n '1p')"
  body="$(printf '%s' "$response" | sed -n '2,$p')"
  assert_status "$code" "403" "Auditor create file deny"
  [[ "$(json_extract "$body" 'detail.error_code')" == "AUTHZ_ROLE_FORBIDDEN" ]] || fail "Auditor file deny error code mismatch"
  pass "File role-deny path"
}

main() {
  validate_ui_wiring

  if [[ "$RUN_API_CHECKS" == "1" ]]; then
    validate_api_checks
  else
    echo "[INFO] API checks skipped. Set RUN_API_CHECKS=1 to validate live /v1 endpoint workflows."
  fi

  echo "OpenAI-compatible gateway operation smoke checks completed successfully."
}

main "$@"
