#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
INDEX_FILE="$ROOT_DIR/index.html"
APP_FILE="$ROOT_DIR/app.js"
OBSERVABILITY_VIEW="$ROOT_DIR/views/observability.html"
OVERVIEW_VIEW="$ROOT_DIR/views/overview.html"
COST_VIEW="$ROOT_DIR/views/cost.html"
ORCHESTRATION_VIEW="$ROOT_DIR/views/orchestration.html"

fail() {
  echo "[FAIL] $1"
  exit 1
}

pass() {
  echo "[PASS] $1"
}

require_token() {
  local file="$1"
  local token="$2"
  local label="$3"
  grep -F "$token" "$file" >/dev/null || fail "${label}: missing token '${token}' in $(basename "$file")"
}

[[ -f "$INDEX_FILE" ]] || fail "Missing index.html"
[[ -f "$APP_FILE" ]] || fail "Missing app.js"
[[ -f "$OBSERVABILITY_VIEW" ]] || fail "Missing views/observability.html"
[[ -f "$OVERVIEW_VIEW" ]] || fail "Missing views/overview.html"
[[ -f "$COST_VIEW" ]] || fail "Missing views/cost.html"
[[ -f "$ORCHESTRATION_VIEW" ]] || fail "Missing views/orchestration.html"

require_token "$OBSERVABILITY_VIEW" 'id="observabilitySiemRulesTable"' "Observability SIEM Rules"
require_token "$OBSERVABILITY_VIEW" 'id="loadObservabilitySiemRules"' "Observability SIEM Rules load"
require_token "$APP_FILE" "loadObservabilitySiemRules" "Observability SIEM Rules handler"
pass "Observability → SIEM Rules surface present"

require_token "$OVERVIEW_VIEW" 'id="overviewOrchestrationSummary"' "Overview Flow Orchestration"
require_token "$APP_FILE" "loadOverviewOrchestrationSummary" "Overview orchestration summary handler"
pass "Overview → Flow Orchestration surface present"

require_token "$COST_VIEW" 'data-console-panel="telemetry"' "Cost Telemetry panel"
require_token "$COST_VIEW" 'id="costTimeseriesPanel"' "Cost timeseries panel"
require_token "$COST_VIEW" 'id="costTimeseriesTable"' "Cost timeseries table"
require_token "$COST_VIEW" 'id="costScopeBreakdownTable"' "Cost scope breakdown table"
require_token "$APP_FILE" "loadCostTimeseries" "Cost timeseries handler"
require_token "$APP_FILE" "loadCostScopeBreakdown" "Cost scope breakdown handler"
require_token "$APP_FILE" "prepareCostTelemetryPanel" "Cost telemetry panel bootstrap"
pass "Cost → Telemetry surfaces present"

require_token "$ORCHESTRATION_VIEW" 'id="orchestrationDataConnectionTestPanel"' "Orchestration data-connection test panel"
require_token "$ORCHESTRATION_VIEW" 'id="orchestrationDataConnectionTestTable"' "Orchestration data-connection test table"
require_token "$APP_FILE" "testOrchestrationDataConnection" "Orchestration data-connection test handler"
require_token "$APP_FILE" "loadOrchestrationDataConnectionsHint" "Orchestration data-connection registry loader"
pass "Flow Orchestration data-connection test-query surface present"

require_token "$ORCHESTRATION_VIEW" 'id="orchestrationDueCertQueueTable"' "Orchestration due certification queue"
require_token "$ORCHESTRATION_VIEW" 'id="orchestrationJitQueueTable"' "Orchestration JIT access queue"
require_token "$APP_FILE" "loadOrchestrationDueCertificationQueue" "Due certification queue handler"
require_token "$APP_FILE" "loadOrchestrationJitAccessQueue" "JIT access queue handler"
require_token "$APP_FILE" "submitOrchestrationJitReview" "JIT approve/deny handler"
pass "Flow Orchestration IGA approver queues present"

require_token "$APP_FILE" "renderGatewayFineTuningModeBadge" "Fine-tuning live mode badge"
require_token "$ROOT_DIR/views/routing-gateway.html" 'id="gatewayFineTuningModeBadge"' "Fine-tuning mode badge markup"
pass "Gateway fine-tuning live mode indicator present"

echo "Console surface smoke checks completed successfully."
