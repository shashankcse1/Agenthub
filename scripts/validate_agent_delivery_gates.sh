#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

fail() {
  echo "[FAIL] $1"
  exit 1
}

pass() {
  echo "[PASS] $1"
}

require_file() {
  local path="$1"
  [[ -f "$path" ]] || fail "Missing required governance artifact: $path"
}

require_text() {
  local token="$1"
  local path="$2"
  grep -F "$token" "$path" >/dev/null || fail "Missing required token '$token' in $path"
}

check_required_artifacts() {
  require_file "AGENTS.md"
  require_file "backend/AGENTS.md"
  require_file "backend/docs/governance/documentation-source-of-truth.md"
  require_file "backend/docs/governance/api-inventory-and-ui-map.md"
  require_file "backend/docs/governance/ui-api-design-coverage-map.md"
  require_file "backend/docs/governance/release-gate-checklist.md"
  require_file "backend/docs/governance/ai-gateway-identity-security-design.md"
  require_file "backend/docs/security/residual-and-accepted-risk-register.md"
  require_file "frontend/README.md"
  require_file "frontend/accessibility-conformance-wcag22aa.md"
  pass "Required governance artifacts are present"
}

check_architecture_lenses() {
  require_text "Security Architect review completed" "backend/docs/governance/release-gate-checklist.md"
  require_text "CISO delegate review completed" "backend/docs/governance/release-gate-checklist.md"
  require_text "AWS Architect review completed" "backend/docs/governance/release-gate-checklist.md"
  require_text "Cloud Architect review completed" "backend/docs/governance/release-gate-checklist.md"
  require_text "UI Expert review completed" "backend/docs/governance/release-gate-checklist.md"
  require_text "IAM" "backend/docs/governance/ai-gateway-identity-security-design.md"
  pass "Security/CISO/AWS/Cloud/UI/IAM lens checks are documented"
}

check_certification_and_preventative_controls() {
  require_text "Agentic Certification" "backend/docs/governance/ui-api-design-coverage-map.md"
  require_text "guardrail" "backend/docs/governance/api-inventory-and-ui-map.md"
  require_text "/auth/policies/session" "backend/docs/governance/api-inventory-and-ui-map.md"
  require_text "/gateway/entitlements" "backend/docs/governance/api-inventory-and-ui-map.md"
  require_text "/gateway/jit-requests" "backend/docs/governance/api-inventory-and-ui-map.md"
  pass "Certification and preventative policy controls are documented in API/UI maps"
}

check_agent_delivery_attestation() {
  require_text "Agent-Friendly Delivery Gates" "backend/docs/governance/release-gate-checklist.md"
  require_text "Agent-Only Delivery Attestation" "backend/docs/governance/release-gate-checklist.md"
  require_text "Agent-friendly delivery artifacts are captured" "backend/docs/governance/documentation-source-of-truth.md"
  pass "Agent-only delivery attestation gates are present"
}

main() {
  check_required_artifacts
  check_architecture_lenses
  check_certification_and_preventative_controls
  check_agent_delivery_attestation
  echo "Agent delivery governance checks completed successfully."
}

main "$@"
