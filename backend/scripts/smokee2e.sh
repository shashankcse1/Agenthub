#!/usr/bin/env bash
set -euo pipefail

API_PORT="${API_PORT:-8000}"
BASE_URL="${BASE_URL:-http://127.0.0.1:${API_PORT}}"
HEALTH_WAIT_SECONDS="${HEALTH_WAIT_SECONDS:-15}"

health_ready="false"
for _ in $(seq 1 "${HEALTH_WAIT_SECONDS}"); do
  if curl -s --max-time 2 "${BASE_URL}/health" >/dev/null 2>&1; then
    health_ready="true"
    break
  fi
  sleep 1
done

if [[ "$health_ready" != "true" ]]; then
  echo "API not reachable at ${BASE_URL} after ${HEALTH_WAIT_SECONDS}s."
  echo "Start the API first (for example: make startall or make startall-port PORT=${API_PORT})."
  exit 1
fi

request() {
  local method="$1"
  local path="$2"
  local data="${3:-}"
  local headers=(
    -H "X-Actor-Id: admin-e2e"
    -H "X-Actor-Role: Platform Admin"
    -H "X-MFA-Verified: true"
  )

  local code
  if [[ -n "$data" ]]; then
    code="$(curl -s -o /tmp/e2e_resp.json -w "%{http_code}" -X "$method" "${BASE_URL}${path}" -H "Content-Type: application/json" "${headers[@]}" -d "$data")"
  else
    code="$(curl -s -o /tmp/e2e_resp.json -w "%{http_code}" -X "$method" "${BASE_URL}${path}" "${headers[@]}")"
  fi

  if [[ "$code" -lt 200 || "$code" -ge 300 ]]; then
    echo "Request failed: ${method} ${path} (HTTP ${code})"
    cat /tmp/e2e_resp.json || true
    exit 1
  fi
}

request_expect_status() {
  local expected_code="$1"
  local method="$2"
  local path="$3"
  local data="${4:-}"

  local base_headers=(
    -H "X-Actor-Id: admin-e2e"
    -H "X-Actor-Role: Platform Admin"
    -H "X-MFA-Verified: true"
  )

  local code
  if [[ -n "$data" ]]; then
    code="$(curl -s -o /tmp/e2e_resp.json -w "%{http_code}" -X "$method" "${BASE_URL}${path}" -H "Content-Type: application/json" "${base_headers[@]}" -d "$data")"
  else
    code="$(curl -s -o /tmp/e2e_resp.json -w "%{http_code}" -X "$method" "${BASE_URL}${path}" "${base_headers[@]}")"
  fi

  if [[ "$code" != "$expected_code" ]]; then
    echo "Unexpected status for ${method} ${path}: expected ${expected_code}, got ${code}"
    cat /tmp/e2e_resp.json || true
    exit 1
  fi
}

request_expect_status_as() {
  local expected_code="$1"
  local method="$2"
  local path="$3"
  local actor_id="$4"
  local actor_role="$5"
  local data="${6:-}"

  local headers=(
    -H "X-Actor-Id: ${actor_id}"
    -H "X-Actor-Role: ${actor_role}"
    -H "X-MFA-Verified: true"
  )

  local code
  if [[ -n "$data" ]]; then
    code="$(curl -s -o /tmp/e2e_resp.json -w "%{http_code}" -X "$method" "${BASE_URL}${path}" -H "Content-Type: application/json" "${headers[@]}" -d "$data")"
  else
    code="$(curl -s -o /tmp/e2e_resp.json -w "%{http_code}" -X "$method" "${BASE_URL}${path}" "${headers[@]}")"
  fi

  if [[ "$code" != "$expected_code" ]]; then
    echo "Unexpected status for ${method} ${path}: expected ${expected_code}, got ${code}"
    cat /tmp/e2e_resp.json || true
    exit 1
  fi
}

json_field() {
  local field_name="$1"
  python3 - "$field_name" <<'PY'
import json
import sys

field = sys.argv[1]
with open('/tmp/e2e_resp.json', 'r', encoding='utf-8') as f:
    data = json.load(f)
value = data.get(field)
if isinstance(value, bool):
    print('true' if value else 'false')
elif value is None:
    print('')
else:
    print(str(value))
PY
}

json_detail_field() {
  local field_name="$1"
  python3 - "$field_name" <<'PY'
import json
import sys

field = sys.argv[1]
with open('/tmp/e2e_resp.json', 'r', encoding='utf-8') as f:
  data = json.load(f)

detail = data.get('detail', {}) if isinstance(data, dict) else {}
value = detail.get(field)
if isinstance(value, bool):
  print('true' if value else 'false')
elif value is None:
  print('')
else:
  print(str(value))
PY
}

json_len() {
  python3 - <<'PY'
import json

with open('/tmp/e2e_resp.json', 'r', encoding='utf-8') as f:
  data = json.load(f)

if isinstance(data, list):
  print(len(data))
else:
  print(0)
PY
}

json_any_match() {
  local field_name="$1"
  local expected_value="$2"
  python3 - "$field_name" "$expected_value" <<'PY'
import json
import sys

field = sys.argv[1]
expected = sys.argv[2]

with open('/tmp/e2e_resp.json', 'r', encoding='utf-8') as f:
    data = json.load(f)

if not isinstance(data, list):
    print('false')
    raise SystemExit(0)

print('true' if any(str(item.get(field, '')) == expected for item in data if isinstance(item, dict)) else 'false')
PY
}

assert_forbidden_role_detail() {
  local expected_actor_role="$1"
  local context_message="$2"

  if [[ "$(json_detail_field error_code)" != "AUTHZ_ROLE_FORBIDDEN" ]]; then
    echo "Expected AUTHZ_ROLE_FORBIDDEN for ${context_message}"
    cat /tmp/e2e_resp.json || true
    exit 1
  fi
  if [[ "$(json_detail_field actor_role)" != "$expected_actor_role" ]]; then
    echo "Expected actor_role ${expected_actor_role} for ${context_message}"
    cat /tmp/e2e_resp.json || true
    exit 1
  fi
  if [[ "$(json_detail_field decision_trace_id)" != "authz-role-check" ]]; then
    echo "Expected decision_trace_id authz-role-check for ${context_message}"
    cat /tmp/e2e_resp.json || true
    exit 1
  fi
}

# Health
request GET "/health"

# Core registration flow
request POST "/agents/register" '{"name":"e2e-agent","owner_id":"e2e-owner","owner_name":"E2E Owner","owner_team":"Platform","risk_tier":"medium"}'

# Discovery + module + gateway + cost
request POST "/discovery/sources/runtime_inventory/sync"
request POST "/modules/register" '{"module_name":"e2e-mod","module_type":"planner","version":"1.0.0","contract_version":"1.0","owner_team":"Platform","artifact_signature":"sig:e2e-mod-1.0.0","provenance_ref":"prov://e2e/mod/1.0.0"}'
request POST "/gateway/routes" '{"route_name":"e2e-route"}'
request POST "/cost/budgets" '{"scope_type":"team","scope_id":"Platform","budget_amount_cents":5000}'
request POST "/cost/policies/evaluate" '{"scope_type":"team","scope_id":"Platform"}'

# Route draft flow including promotion gates
DRAFT_ID="draft-e2e-$(date +%s)"

curl -s -o /tmp/e2e_resp.json -w "%{http_code}" -X POST "${BASE_URL}/route-drafts/${DRAFT_ID}/submit" \
  -H "Content-Type: application/json" -H "X-Actor-Id: owner-e2e" -H "X-Actor-Role: Agent Owner" -H "X-MFA-Verified: true" \
  -d '{"agent_id":"agent-a","route_policy_snapshot_id":"snap-e2e","environment":"staging"}' | grep -q '^2' || {
  echo "Route draft submit failed"; cat /tmp/e2e_resp.json; exit 1;
}

curl -s -o /tmp/e2e_resp.json -w "%{http_code}" -X POST "${BASE_URL}/route-drafts/${DRAFT_ID}/approve" \
  -H "Content-Type: application/json" -H "X-Actor-Id: sec-e2e" -H "X-Actor-Role: Security Approver" -H "X-MFA-Verified: true" \
  -d '{"reason_code":"ok"}' | grep -q '^2' || {
  echo "Security approval failed"; cat /tmp/e2e_resp.json; exit 1;
}

curl -s -o /tmp/e2e_resp.json -w "%{http_code}" -X POST "${BASE_URL}/route-drafts/${DRAFT_ID}/approve" \
  -H "Content-Type: application/json" -H "X-Actor-Id: aiops-e2e" -H "X-Actor-Role: AI Ops Approver" -H "X-MFA-Verified: true" \
  -d '{"reason_code":"ok"}' | grep -q '^2' || {
  echo "AI Ops approval failed"; cat /tmp/e2e_resp.json; exit 1;
}

curl -s -o /tmp/e2e_resp.json -w "%{http_code}" -X POST "${BASE_URL}/route-drafts/${DRAFT_ID}/approve-change-window" \
  -H "Content-Type: application/json" -H "X-Actor-Id: rel-e2e" -H "X-Actor-Role: Release Manager" -H "X-MFA-Verified: true" \
  -d '{"reason_code":"change-window-open"}' | grep -q '^2' || {
  echo "Change-window approval failed"; cat /tmp/e2e_resp.json; exit 1;
}

DRAFT_STATE_VERSION="$(json_field state_version)"
if [[ -z "$DRAFT_STATE_VERSION" ]]; then
  echo "Failed to parse route draft state_version after change-window approval"
  cat /tmp/e2e_resp.json || true
  exit 1
fi

curl -s -o /tmp/e2e_resp.json -w "%{http_code}" -X POST "${BASE_URL}/benchmarks/run" \
  -H "Content-Type: application/json" -H "X-Actor-Id: aiops-e2e" -H "X-Actor-Role: AI Ops Approver" -H "X-MFA-Verified: true" \
  -d '{"agent_id":"agent-a","benchmark_suite":"reliability-core","environment":"staging"}' | grep -q '^2' || {
  echo "Benchmark failed"; cat /tmp/e2e_resp.json; exit 1;
}

curl -s -o /tmp/e2e_resp.json -w "%{http_code}" -X POST "${BASE_URL}/scans/run" \
  -H "Content-Type: application/json" -H "X-Actor-Id: aiops-e2e" -H "X-Actor-Role: AI Ops Approver" -H "X-MFA-Verified: true" \
  -d '{"agent_id":"agent-a","scan_type":"security","environment":"staging"}' | grep -q '^2' || {
  echo "Scan failed"; cat /tmp/e2e_resp.json; exit 1;
}

curl -s -o /tmp/e2e_resp.json -w "%{http_code}" -X POST "${BASE_URL}/agentic/contracts/validate" \
  -H "Content-Type: application/json" -H "X-Actor-Id: rel-e2e" -H "X-Actor-Role: Release Manager" -H "X-MFA-Verified: true" \
  -d '{"agent_id":"agent-a","module_ids":["mod-1"],"route_policy_snapshot_id":"snap-e2e","required_capabilities":["observability"]}' | grep -q '^2' || {
  echo "Contract validation failed"; cat /tmp/e2e_resp.json; exit 1;
}

curl -s -o /tmp/e2e_resp.json -w "%{http_code}" -X POST "${BASE_URL}/route-drafts/${DRAFT_ID}/promote" \
  -H "Content-Type: application/json" -H "X-Actor-Id: rel-e2e" -H "X-Actor-Role: Release Manager" -H "X-Approver-Id: sec-e2e" -H "X-Approver-Role: Security Approver" -H "X-MFA-Verified: true" \
  -d "{\"target_environment\":\"prod\",\"expected_state_version\":${DRAFT_STATE_VERSION}}" | grep -q '^2' || {
  echo "Promotion failed"; cat /tmp/e2e_resp.json; exit 1;
}

# Schedule delete safety and idempotent behavior checks.
SCHEDULE_NAME="e2e-schedule-$(date +%s)"
request POST "/agentic/policy/schedules" "{\"name\":\"${SCHEDULE_NAME}\",\"environment\":\"staging\",\"optimize_for\":\"balanced\",\"max_routes\":10,\"window_start_hour_utc\":0,\"window_end_hour_utc\":0,\"max_changes_without_approval\":3,\"enabled\":true}"
SCHEDULE_JOB_ID="$(json_field job_id)"

if [[ -z "$SCHEDULE_JOB_ID" ]]; then
  echo "Failed to parse schedule job_id from create response"
  cat /tmp/e2e_resp.json || true
  exit 1
fi

request_expect_status_as 403 DELETE "/agentic/policy/schedules/${SCHEDULE_JOB_ID}" "owner-e2e" "Agent Owner"
assert_forbidden_role_detail "Agent Owner" "unauthorized existing schedule delete"
request GET "/agentic/policy/schedules/${SCHEDULE_JOB_ID}"

request GET "/audit/events?action_type=agentic.policy.schedule.delete&resource_type=policy_schedule&resource_id=${SCHEDULE_JOB_ID}&decision_outcome=deny&limit=50"
if [[ "$(json_any_match actor_id owner-e2e)" != "true" ]]; then
  echo "Expected deny delete audit event for actor owner-e2e on existing schedule"
  cat /tmp/e2e_resp.json || true
  exit 1
fi

request GET "/audit/events?action_type=agentic.policy.schedule.delete&resource_type=policy_schedule&resource_id=${SCHEDULE_JOB_ID}&decision_outcome=allow&limit=50"
if [[ "$(json_len)" -ne 0 ]]; then
  echo "Expected no allow delete audit events for unauthorized existing schedule delete"
  cat /tmp/e2e_resp.json || true
  exit 1
fi

MISSING_ID="missing-e2e-$(date +%s)"
request_expect_status 404 DELETE "/agentic/policy/schedules/${MISSING_ID}"
request_expect_status_as 403 DELETE "/agentic/policy/schedules/${MISSING_ID}?idempotent=true" "owner-e2e" "Agent Owner"
assert_forbidden_role_detail "Agent Owner" "unauthorized idempotent missing delete"

request GET "/audit/events?action_type=agentic.policy.schedule.delete&resource_type=policy_schedule&resource_id=${MISSING_ID}&decision_outcome=deny&limit=50"
if [[ "$(json_len)" -lt 1 ]]; then
  echo "Expected deny audit event for unauthorized idempotent missing delete"
  cat /tmp/e2e_resp.json || true
  exit 1
fi
if [[ "$(json_any_match actor_id owner-e2e)" != "true" ]]; then
  echo "Expected deny delete audit event for actor owner-e2e on missing idempotent delete"
  cat /tmp/e2e_resp.json || true
  exit 1
fi

request GET "/audit/events?action_type=agentic.policy.schedule.delete&resource_type=policy_schedule&resource_id=${MISSING_ID}&decision_outcome=allow&limit=50"
if [[ "$(json_len)" -ne 0 ]]; then
  echo "Expected no allow audit events for unauthorized idempotent missing delete"
  cat /tmp/e2e_resp.json || true
  exit 1
fi

request_expect_status 200 DELETE "/agentic/policy/schedules/${MISSING_ID}?idempotent=true"
if [[ "$(json_field deleted)" != "false" ]]; then
  echo "Expected deleted=false for idempotent missing delete"
  cat /tmp/e2e_resp.json || true
  exit 1
fi
if [[ "$(json_field job_id)" != "$MISSING_ID" ]]; then
  echo "Expected idempotent missing delete to echo job_id"
  cat /tmp/e2e_resp.json || true
  exit 1
fi

request_expect_status 200 DELETE "/agentic/policy/schedules/${SCHEDULE_JOB_ID}"
if [[ "$(json_field deleted)" != "true" ]]; then
  echo "Expected deleted=true for existing schedule delete"
  cat /tmp/e2e_resp.json || true
  exit 1
fi
if [[ "$(json_field job_id)" != "$SCHEDULE_JOB_ID" ]]; then
  echo "Expected delete response to echo schedule job_id"
  cat /tmp/e2e_resp.json || true
  exit 1
fi

echo "E2E smoke passed."
