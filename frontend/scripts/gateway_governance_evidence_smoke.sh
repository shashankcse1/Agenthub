#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INDEX_FILE="$ROOT_DIR/index.html"
ROUTING_VIEW_FILE="$ROOT_DIR/views/routing-gateway.html"
APP_FILE="$ROOT_DIR/app.js"

API_BASE="${API_BASE:-http://127.0.0.1:8000}"
RUN_API_CHECKS="${RUN_API_CHECKS:-0}"
AUDITOR_ID="${AUDITOR_ID:-smoke-gateway-auditor}"

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

validate_ui_wiring() {
  require_file "$INDEX_FILE"
  require_file "$ROUTING_VIEW_FILE"
  require_file "$APP_FILE"

  require_token 'id="viewsRoot"' "$INDEX_FILE"
  require_token 'id="loadGatewayGovernanceEvidence"' "$ROUTING_VIEW_FILE"
  require_token 'id="exportGatewayGovernanceEvidence"' "$ROUTING_VIEW_FILE"
  require_token 'id="gatewayGovernanceEvidenceForm"' "$ROUTING_VIEW_FILE"
  require_token 'id="gatewayGovernanceEvidenceTable"' "$ROUTING_VIEW_FILE"
  pass "Gateway governance evidence card exists in routing-gateway view"

  require_token 'function renderGatewayGovernanceEvidenceSummary' "$APP_FILE"
  require_token 'function getGatewayGovernanceEvidenceFilters' "$APP_FILE"
  require_token 'async function loadGatewayGovernanceEvidence' "$APP_FILE"
  require_token 'async function exportGatewayGovernanceEvidence' "$APP_FILE"
  require_token '"/gateway/governance/evidence/export"' "$APP_FILE"
  require_token 'addEventListener("submit", loadGatewayGovernanceEvidence)' "$APP_FILE"
  require_token 'addEventListener("click", exportGatewayGovernanceEvidence)' "$APP_FILE"
  pass "Gateway governance evidence logic and bindings exist in app.js"
}

query_audit_endpoint() {
  local action_type="$1"
  local response
  response="$(curl -sS -H 'X-Actor-Role: Auditor' -H "X-Actor-Id: $AUDITOR_ID" "$API_BASE/audit/events?action_type=${action_type}&limit=5")" || {
    fail "Audit query failed for action_type=${action_type}. Ensure backend is running at API_BASE=$API_BASE"
  }

  python3 - "$response" <<'PY'
import json
import sys
payload = json.loads(sys.argv[1])
if not isinstance(payload, list):
    raise SystemExit(1)
print(len(payload))
PY
}

query_governance_export_endpoint() {
  local response
  response="$(curl -sS -X POST \
    -H 'Content-Type: application/json' \
    -H 'X-Actor-Role: Auditor' \
    -H "X-Actor-Id: $AUDITOR_ID" \
    -d '{"decision_outcome":"allow","limit_per_action":20,"bundle_label":"smoke-gateway-gov"}' \
    "$API_BASE/gateway/governance/evidence/export")" || {
    fail "Gateway governance evidence export call failed. Ensure backend is running at API_BASE=$API_BASE"
  }

  python3 - "$response" <<'PY'
import json
import sys
payload = json.loads(sys.argv[1])
required = ["export_id", "export_uri", "event_count", "action_summaries", "events"]
if not isinstance(payload, dict) or not all(key in payload for key in required):
    raise SystemExit(1)
if not isinstance(payload["action_summaries"], list):
    raise SystemExit(1)
if not isinstance(payload["events"], list):
    raise SystemExit(1)
print(payload["event_count"])
PY
}

validate_api_queries() {
  local actions=(
    "gateway.entitlement.read"
    "gateway.entitlement.update"
    "gateway.nhi.inventory.read"
    "gateway.nhi.hygiene.read"
    "gateway.access_review.campaign.create"
    "gateway.access_review.campaign.read"
    "gateway.jit.request.create"
    "gateway.jit.request.approve"
    "gateway.jit.request.deny"
    "gateway.least_privilege.read"
    "gateway.least_privilege.apply"
  )

  for action in "${actions[@]}"; do
    count="$(query_audit_endpoint "$action")" || fail "Invalid audit payload for action=$action"
    echo "[PASS] action=$action returned JSON list (size=$count)"
  done

  evidence_count="$(query_governance_export_endpoint)" || fail "Invalid payload from /gateway/governance/evidence/export"
  echo "[PASS] gateway governance evidence export returned valid bundle payload (event_count=$evidence_count)"

  pass "Live audit endpoint checks passed"
}

main() {
  validate_ui_wiring

  if [[ "$RUN_API_CHECKS" == "1" ]]; then
    validate_api_queries
  else
    echo "[INFO] API checks skipped. Set RUN_API_CHECKS=1 to validate /audit/events responses."
  fi

  echo "Gateway governance evidence smoke checks completed successfully."
}

main "$@"
