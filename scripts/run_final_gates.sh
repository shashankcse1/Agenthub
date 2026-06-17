#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
QUICK_MODE=0
API_BASE="${API_BASE:-http://127.0.0.1:8000}"

if [[ "${1:-}" == "--quick" ]]; then
  QUICK_MODE=1
fi

step() {
  echo
  echo "==> $1"
}

run_cmd() {
  local description="$1"
  shift
  step "$description"
  "$@"
}

has_live_api() {
  curl -fsS "$API_BASE/health" >/dev/null 2>&1
}

run_browser_compat_gate() {
  if [[ "${FINAL_GATES_STRICT_SAFARI:-0}" == "1" && "${FINAL_GATES_STRICT_FIREFOX:-0}" == "1" ]]; then
    run_cmd "GuardBridge browser compatibility (strict Safari + Firefox lint)" bash scripts/check_guardbridge_browser_compat.sh --strict-safari --strict-firefox-lint
  elif [[ "${FINAL_GATES_STRICT_SAFARI:-0}" == "1" ]]; then
    run_cmd "GuardBridge browser compatibility (strict Safari)" bash scripts/check_guardbridge_browser_compat.sh --strict-safari
  elif [[ "${FINAL_GATES_STRICT_FIREFOX:-0}" == "1" ]]; then
    run_cmd "GuardBridge browser compatibility (strict Firefox lint)" bash scripts/check_guardbridge_browser_compat.sh --strict-firefox-lint
  else
    run_cmd "GuardBridge browser compatibility" bash scripts/check_guardbridge_browser_compat.sh
  fi
}

cd "$ROOT_DIR"

run_cmd "Frontend syntax check" node --check frontend/app.js
run_browser_compat_gate
run_cmd "Frontend security smoke" bash frontend/scripts/security_smoke.sh
run_cmd "GuardBridge extension smoke (wiring mode)" bash -c "cd frontend && bash scripts/guardbridge_extension_smoke.sh"
run_cmd "GuardBridge extension package build" bash scripts/package_guardbridge_extension.sh
run_cmd "Agent-delivery governance validator" bash scripts/validate_agent_delivery_gates.sh

if has_live_api; then
  run_cmd "Gateway governance smoke (live API)" bash -c "cd frontend && RUN_API_CHECKS=1 API_BASE='$API_BASE' bash scripts/gateway_governance_evidence_smoke.sh"
  run_cmd "OpenAI gateway ops smoke (live API)" bash -c "cd frontend && RUN_API_CHECKS=1 API_BASE='$API_BASE' bash scripts/openai_gateway_ops_smoke.sh"
  run_cmd "GuardBridge extension smoke (live API)" bash -c "cd frontend && RUN_API_CHECKS=1 API_BASE='$API_BASE' bash scripts/guardbridge_extension_smoke.sh"
else
  run_cmd "Gateway governance smoke (UI wiring mode)" bash -c "cd frontend && bash scripts/gateway_governance_evidence_smoke.sh"
  run_cmd "OpenAI gateway ops smoke (UI wiring mode)" bash -c "cd frontend && bash scripts/openai_gateway_ops_smoke.sh"
fi

if [[ "$QUICK_MODE" == "1" ]]; then
  run_cmd "Backend focused governance tests" python3 -m pytest backend/tests/test_phase0_phase1.py -k "compliance or authz_explain or gateway"
else
  run_cmd "Backend full test suite" python3 -m pytest
fi

echo
echo "All final gates passed."
