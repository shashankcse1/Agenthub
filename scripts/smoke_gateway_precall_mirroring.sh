#!/usr/bin/env bash
set -euo pipefail

API_PORT="${API_PORT:-8000}"
BASE_URL="${BASE_URL:-http://127.0.0.1:${API_PORT}}"
HEALTH_WAIT_SECONDS="${HEALTH_WAIT_SECONDS:-20}"

TMP_RESP="/tmp/gateway_precall_mirroring_smoke_resp.json"

wait_for_health() {
  local ready="false"
  for _ in $(seq 1 "${HEALTH_WAIT_SECONDS}"); do
    if curl -s --max-time 2 "${BASE_URL}/health" >/dev/null 2>&1; then
      ready="true"
      break
    fi
    sleep 1
  done

  if [[ "$ready" != "true" ]]; then
    echo "API not reachable at ${BASE_URL} after ${HEALTH_WAIT_SECONDS}s"
    echo "Start the stack first, for example: ./scripts/startall.sh"
    exit 1
  fi
}

request_as() {
  local method="$1"
  local path="$2"
  local actor_id="$3"
  local actor_role="$4"
  local data="${5:-}"

  local code
  if [[ -n "$data" ]]; then
    code="$(curl -s -o "$TMP_RESP" -w "%{http_code}" -X "$method" "${BASE_URL}${path}" \
      -H "Content-Type: application/json" \
      -H "X-Actor-Id: ${actor_id}" \
      -H "X-Actor-Role: ${actor_role}" \
      -d "$data")"
  else
    code="$(curl -s -o "$TMP_RESP" -w "%{http_code}" -X "$method" "${BASE_URL}${path}" \
      -H "X-Actor-Id: ${actor_id}" \
      -H "X-Actor-Role: ${actor_role}")"
  fi

  if [[ "$code" -lt 200 || "$code" -ge 300 ]]; then
    echo "Request failed: ${method} ${path} (HTTP ${code})"
    cat "$TMP_RESP" || true
    exit 1
  fi
}

json_value() {
  local key="$1"
  python3 - "$key" "$TMP_RESP" <<'PY'
import json
import sys

key = sys.argv[1]
path = sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)
value = data.get(key) if isinstance(data, dict) else None
if isinstance(value, bool):
    print("true" if value else "false")
elif value is None:
    print("")
else:
    print(str(value))
PY
}

assert_json_value_eq() {
  local key="$1"
  local expected="$2"
  local actual
  actual="$(json_value "$key")"
  if [[ "$actual" != "$expected" ]]; then
    echo "Assertion failed: expected ${key}=${expected}, got ${actual}"
    cat "$TMP_RESP" || true
    exit 1
  fi
}

assert_attempted_contains_outcome() {
  local expected_outcome="$1"
  python3 - "$expected_outcome" "$TMP_RESP" <<'PY'
import json
import sys

expected = sys.argv[1]
path = sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

attempted_raw = data.get("attempted_providers") if isinstance(data, dict) else None
if not isinstance(attempted_raw, str):
    print("attempted_providers missing")
    raise SystemExit(1)

try:
    attempted = json.loads(attempted_raw)
except Exception:
    print("attempted_providers is not valid JSON")
    raise SystemExit(1)

if not isinstance(attempted, list):
    print("attempted_providers is not a list")
    raise SystemExit(1)

if not any(isinstance(item, dict) and str(item.get("outcome", "")) == expected for item in attempted):
    print(f"Outcome {expected} not found in attempted_providers")
    raise SystemExit(1)
PY
}

assert_audit_has_actor() {
  local path="$1"
  local expected_actor_id="$2"
  request_as "GET" "$path" "aud-gateway-smoke" "Auditor"
  python3 - "$expected_actor_id" "$TMP_RESP" <<'PY'
import json
import sys

expected_actor_id = sys.argv[1]
path = sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

if not isinstance(data, list) or not data:
    print("Audit query returned no events")
    raise SystemExit(1)

if not any(isinstance(item, dict) and str(item.get("actor_id", "")) == expected_actor_id for item in data):
    print("Expected actor_id not found in audit events")
    raise SystemExit(1)
PY
}

wait_for_health

ROUTE_NAME="smoke-precall-mirror-$(date +%s)"
ACTOR_ID="smoke-script-operator"
TENANT_ID="tenant-smoke-precall-mirror"

echo "[1/7] Creating route policy ${ROUTE_NAME}"
request_as "POST" "/gateway/routes" "$ACTOR_ID" "Platform Admin" "{\"route_name\":\"${ROUTE_NAME}\"}"
ROUTE_POLICY_ID="$(json_value "route_policy_id")"
if [[ -z "$ROUTE_POLICY_ID" ]]; then
  echo "Failed to parse route_policy_id"
  cat "$TMP_RESP" || true
  exit 1
fi

echo "[2/7] Configuring provider priority for route ${ROUTE_POLICY_ID}"
request_as "POST" "/gateway/routes/${ROUTE_POLICY_ID}/providers/priority" "$ACTOR_ID" "AI Ops Approver" "{\"tenant_id\":\"${TENANT_ID}\",\"environment\":\"dev\",\"priority_order\":\"[{\\\"provider_id\\\":\\\"provider-primary\\\",\\\"priority\\\":1}]\",\"max_fallback_hops\":2}"

echo "[3/7] Saving pre-call filters"
request_as "PUT" "/gateway/routes/${ROUTE_POLICY_ID}/pre-call-filters" "$ACTOR_ID" "AI Ops Approver" "{\"tenant_id\":\"${TENANT_ID}\",\"environment\":\"dev\",\"allowed_regions\":\"[\\\"us-east-1\\\"]\",\"min_context_window_tokens\":50,\"max_context_window_tokens\":500,\"enforce\":true}"

echo "[4/7] Saving traffic mirroring"
request_as "PUT" "/gateway/routes/${ROUTE_POLICY_ID}/traffic-mirroring" "$ACTOR_ID" "AI Ops Approver" "{\"tenant_id\":\"${TENANT_ID}\",\"environment\":\"dev\",\"enabled\":true,\"mirror_targets\":\"[{\\\"provider_id\\\":\\\"mirror-shadow-a\\\",\\\"sample_percent\\\":100,\\\"mode\\\":\\\"shadow\\\"}]\"}"

echo "[5/7] Executing fallback with blocked region (expect blocked_pre_call_filter)"
request_as "POST" "/gateway/routes/${ROUTE_POLICY_ID}/execute-fallback" "$ACTOR_ID" "AI Ops Approver" "{\"tenant_id\":\"${TENANT_ID}\",\"environment\":\"dev\",\"agent_id\":\"agent-smoke-precall\",\"session_id\":\"sess-smoke-precall-blocked\",\"owner_scope\":\"team:platform\",\"requested_region\":\"eu-west-1\",\"input_tokens\":100,\"output_tokens\":60,\"simulate_fail_provider_ids\":\"[]\"}"
assert_json_value_eq "final_outcome" "blocked_pre_call_filter"

echo "[6/7] Executing fallback with allowed region (expect success + mirrored_simulated)"
request_as "POST" "/gateway/routes/${ROUTE_POLICY_ID}/execute-fallback" "$ACTOR_ID" "AI Ops Approver" "{\"tenant_id\":\"${TENANT_ID}\",\"environment\":\"dev\",\"agent_id\":\"agent-smoke-precall\",\"session_id\":\"sess-smoke-precall-allowed\",\"owner_scope\":\"team:platform\",\"requested_region\":\"us-east-1\",\"input_tokens\":80,\"output_tokens\":40,\"simulate_fail_provider_ids\":\"[]\"}"
assert_json_value_eq "final_outcome" "success"
assert_attempted_contains_outcome "mirrored_simulated"

echo "[7/7] Verifying audit evidence for deny and mirroring allow"
assert_audit_has_actor "/audit/events?action_type=gateway.route.execute_fallback&resource_type=route_policy&resource_id=${ROUTE_POLICY_ID}&decision_outcome=deny&limit=20" "$ACTOR_ID"
assert_audit_has_actor "/audit/events?action_type=gateway.route.traffic_mirroring.execute&resource_type=route_policy&resource_id=${ROUTE_POLICY_ID}&decision_outcome=allow&limit=20" "$ACTOR_ID"

echo "Smoke passed: pre-call filter and traffic mirroring workflows are healthy on route ${ROUTE_POLICY_ID}."
