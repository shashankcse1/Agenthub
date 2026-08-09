#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_ROOT="$ROOT_DIR/artifacts/release-evidence"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RELEASE_ID=""
TARGET_ENV=""
RELEASE_OWNER=""
STRICT_MODE=0
RELEASE_DECISION_LABEL="${RELEASE_DECISION:-TBD}"
RISK_EXCEPTION_REF="${RISK_EXCEPTION_REF:-}"
RELEASE_ACCEPTED_RISK_APPROVED="${RELEASE_ACCEPTED_RISK_APPROVED:-UNSET}"
RELEASE_CISO_ACK="${RELEASE_CISO_ACK:-UNSET}"
RELEASE_IMPACT_LINE_1="${RELEASE_IMPACT_LINE_1:-not-provided}"
RELEASE_IMPACT_LINE_2="${RELEASE_IMPACT_LINE_2:-not-provided}"
RELEASE_IMPACT_LINE_3="${RELEASE_IMPACT_LINE_3:-not-provided}"
DEFAULT_DB_URL="postgresql+psycopg://${USER}@localhost:5432/agenthub"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release-id)
      RELEASE_ID="${2:-}"
      shift 2
      ;;
    --env)
      TARGET_ENV="${2:-}"
      shift 2
      ;;
    --owner)
      RELEASE_OWNER="${2:-}"
      shift 2
      ;;
    --strict)
      STRICT_MODE=1
      shift
      ;;
    --help|-h)
      cat <<'EOF'
Usage: bash scripts/release_evidence_bundle.sh --release-id <id> --env <staging|production> [--owner <name>] [--strict]

Creates a timestamped evidence bundle under artifacts/release-evidence/.
Runs and records release-relevant checks from governance gates.

Options:
  --release-id  Required release identifier
  --env         Required target environment (staging or production)
  --owner       Optional release owner label
  --strict      Fail when any warning is present
EOF
      exit 0
      ;;
    *)
      echo "Unknown argument: $1"
      exit 2
      ;;
  esac
done

if [[ -z "$RELEASE_ID" || -z "$TARGET_ENV" ]]; then
  echo "Missing required args. Use --release-id and --env."
  exit 2
fi

if [[ -z "${DATABASE_URL:-}" ]]; then
  export DATABASE_URL="$DEFAULT_DB_URL"
  echo "[INFO] DATABASE_URL not set; using default: $DATABASE_URL"
fi

BUNDLE_DIR="$OUT_ROOT/${RELEASE_ID}_${TARGET_ENV}_${TIMESTAMP}"
LOG_DIR="$BUNDLE_DIR/logs"
META_DIR="$BUNDLE_DIR/metadata"
DOCS_DIR="$BUNDLE_DIR/docs"

mkdir -p "$LOG_DIR" "$META_DIR" "$DOCS_DIR"

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

record_pass() {
  PASS_COUNT=$((PASS_COUNT + 1))
  echo "[PASS] $1"
}

record_warn() {
  WARN_COUNT=$((WARN_COUNT + 1))
  echo "[WARN] $1"
}

record_fail() {
  FAIL_COUNT=$((FAIL_COUNT + 1))
  echo "[FAIL] $1"
}

record_info() {
  echo "[INFO] $1"
}

run_check() {
  local name="$1"
  local logfile="$2"
  shift 2

  echo
  echo "--- Running: $name"
  if "$@" >"$logfile" 2>&1; then
    record_pass "$name"
  else
    record_fail "$name"
    echo "  See log: $logfile"
  fi
}

run_warn_check() {
  local name="$1"
  local logfile="$2"
  shift 2

  echo
  echo "--- Running (warning-only): $name"
  if "$@" >"$logfile" 2>&1; then
    record_pass "$name"
  else
    record_warn "$name"
    echo "  See log: $logfile"
  fi
}

echo "Release ID: $RELEASE_ID" > "$META_DIR/release_metadata.txt"
echo "Environment: $TARGET_ENV" >> "$META_DIR/release_metadata.txt"
echo "Owner: ${RELEASE_OWNER:-unknown}" >> "$META_DIR/release_metadata.txt"
echo "Generated At: $TIMESTAMP" >> "$META_DIR/release_metadata.txt"
echo "Workspace: $ROOT_DIR" >> "$META_DIR/release_metadata.txt"

# Copy governance docs as evidence snapshot.
cp "$ROOT_DIR/backend/docs/governance/release-gate-checklist.md" "$DOCS_DIR/" 2>/dev/null || true
cp "$ROOT_DIR/backend/docs/governance/maturity-scorecard.md" "$DOCS_DIR/" 2>/dev/null || true
cp "$ROOT_DIR/backend/docs/governance/admin-guide.md" "$DOCS_DIR/" 2>/dev/null || true
cp "$ROOT_DIR/backend/docs/governance/operational-guide.md" "$DOCS_DIR/" 2>/dev/null || true
cp "$ROOT_DIR/backend/docs/governance/security-risk-closure-plan.md" "$DOCS_DIR/" 2>/dev/null || true
cp "$ROOT_DIR/backend/docs/governance/multi-lens-security-architecture-review.md" "$DOCS_DIR/" 2>/dev/null || true
cp "$ROOT_DIR/backend/docs/security/residual-and-accepted-risk-register.md" "$DOCS_DIR/" 2>/dev/null || true
cp "$ROOT_DIR/frontend/accessibility-conformance-wcag22aa.md" "$DOCS_DIR/" 2>/dev/null || true

# Capture release-time risk closure dashboard values for CISO/security sign-off context.
if [[ -x "$ROOT_DIR/scripts/render_risk_closure_dashboard.sh" ]]; then
  if [[ "$STRICT_MODE" -eq 1 ]]; then
    run_check "Risk closure dashboard snapshot" "$LOG_DIR/risk_closure_dashboard.log" bash -lc "cd '$ROOT_DIR' && bash scripts/render_risk_closure_dashboard.sh --strict-overdue > '$META_DIR/risk_closure_dashboard.txt'"
    run_check "Risk closure dashboard JSON" "$LOG_DIR/risk_closure_dashboard_json.log" bash -lc "cd '$ROOT_DIR' && bash scripts/render_risk_closure_dashboard.sh --json > '$META_DIR/risk_closure_dashboard.json'"
  else
    run_warn_check "Risk closure dashboard snapshot" "$LOG_DIR/risk_closure_dashboard.log" bash -lc "cd '$ROOT_DIR' && bash scripts/render_risk_closure_dashboard.sh > '$META_DIR/risk_closure_dashboard.txt'"
    run_warn_check "Risk closure dashboard JSON" "$LOG_DIR/risk_closure_dashboard_json.log" bash -lc "cd '$ROOT_DIR' && bash scripts/render_risk_closure_dashboard.sh --json > '$META_DIR/risk_closure_dashboard.json'"
  fi
else
  record_warn "Risk closure dashboard snapshot (script missing or not executable)"
fi

# Capture a standardized release decision record template with live risk counters.
if [[ -x "$ROOT_DIR/scripts/generate_release_decision_record.sh" ]]; then
  DECISION_CMD="cd '$ROOT_DIR' && bash scripts/generate_release_decision_record.sh --release-id '$RELEASE_ID' --env '$TARGET_ENV' --owner '${RELEASE_OWNER:-unknown}' --decision '$RELEASE_DECISION_LABEL' --accepted-risk '$RELEASE_ACCEPTED_RISK_APPROVED' --ciso-ack '$RELEASE_CISO_ACK' --exception-ref '${RISK_EXCEPTION_REF:-none}' --impact-line '$RELEASE_IMPACT_LINE_1' --impact-line '$RELEASE_IMPACT_LINE_2' --impact-line '$RELEASE_IMPACT_LINE_3' --output '$META_DIR/release_decision_record.md'"
  if [[ "$STRICT_MODE" -eq 1 ]]; then
    run_check "Release decision record template" "$LOG_DIR/release_decision_record.log" bash -lc "$DECISION_CMD"
  else
    run_warn_check "Release decision record template" "$LOG_DIR/release_decision_record.log" bash -lc "$DECISION_CMD"
  fi
else
  record_warn "Release decision record template (script missing or not executable)"
fi

# Capture pending action report for closure items and sign-off posture.
if [[ -x "$ROOT_DIR/scripts/render_pending_closure_report.sh" ]]; then
  if [[ "$STRICT_MODE" -eq 1 ]]; then
    run_check "Pending closure report" "$LOG_DIR/pending_closure_report.log" bash -lc "cd '$ROOT_DIR' && bash scripts/render_pending_closure_report.sh > '$META_DIR/pending_closure_report.txt'"
    run_check "Pending closure report JSON" "$LOG_DIR/pending_closure_report_json.log" bash -lc "cd '$ROOT_DIR' && bash scripts/render_pending_closure_report.sh --json > '$META_DIR/pending_closure_report.json'"
  else
    run_warn_check "Pending closure report" "$LOG_DIR/pending_closure_report.log" bash -lc "cd '$ROOT_DIR' && bash scripts/render_pending_closure_report.sh > '$META_DIR/pending_closure_report.txt'"
    run_warn_check "Pending closure report JSON" "$LOG_DIR/pending_closure_report_json.log" bash -lc "cd '$ROOT_DIR' && bash scripts/render_pending_closure_report.sh --json > '$META_DIR/pending_closure_report.json'"
  fi
else
  record_warn "Pending closure report (script missing or not executable)"
fi

# Enforce risk guardrails for advanced release policy scenarios.
if [[ -x "$ROOT_DIR/scripts/validate_release_risk_guardrails.sh" ]]; then
  GUARDRAIL_CMD="cd '$ROOT_DIR' && bash scripts/validate_release_risk_guardrails.sh --plan backend/docs/governance/security-risk-closure-plan.md --env '$TARGET_ENV' --decision '$RELEASE_DECISION_LABEL' --decision-record '$META_DIR/release_decision_record.md'"
  if [[ -n "$RISK_EXCEPTION_REF" ]]; then
    GUARDRAIL_CMD+=" --allow-overdue-exception '$RISK_EXCEPTION_REF'"
  fi
  if [[ "$STRICT_MODE" -eq 1 ]]; then
    run_check "Release risk guardrails" "$LOG_DIR/release_risk_guardrails.log" bash -lc "$GUARDRAIL_CMD"
  else
    run_warn_check "Release risk guardrails" "$LOG_DIR/release_risk_guardrails.log" bash -lc "$GUARDRAIL_CMD"
  fi
else
  record_warn "Release risk guardrails (script missing or not executable)"
fi

# B. Required technical gates
run_check "Full-stack expert review (deep)" "$LOG_DIR/full_stack_expert_review.log" bash "$ROOT_DIR/scripts/full_stack_expert_review.sh" --deep
run_check "Backend test suite" "$LOG_DIR/backend_pytest.log" bash -lc "cd '$ROOT_DIR/backend' && python3 -m pytest -q"
run_check "Frontend security smoke" "$LOG_DIR/frontend_security_smoke.log" bash -lc "cd '$ROOT_DIR/frontend' && bash scripts/security_smoke.sh"
run_check "GuardBridge extension smoke (UI wiring mode)" "$LOG_DIR/guardbridge_extension_smoke.log" bash -lc "cd '$ROOT_DIR/frontend' && bash scripts/guardbridge_extension_smoke.sh"
if [[ "$STRICT_MODE" -eq 1 ]]; then
  run_check "GuardBridge browser compatibility (strict Safari + Firefox lint)" "$LOG_DIR/guardbridge_browser_compat.log" bash -lc "cd '$ROOT_DIR' && bash scripts/check_guardbridge_browser_compat.sh --strict-safari --strict-firefox-lint > '$META_DIR/guardbridge_browser_compat.txt'"
else
  run_warn_check "GuardBridge browser compatibility" "$LOG_DIR/guardbridge_browser_compat.log" bash -lc "cd '$ROOT_DIR' && bash scripts/check_guardbridge_browser_compat.sh > '$META_DIR/guardbridge_browser_compat.txt'"
fi
run_warn_check "GuardBridge extension package build" "$LOG_DIR/guardbridge_extension_package.log" bash -lc "cd '$ROOT_DIR' && bash scripts/package_guardbridge_extension.sh > '$META_DIR/guardbridge_extension_package.txt'"
run_check "Control coverage" "$LOG_DIR/control_coverage.log" bash -lc "cd '$ROOT_DIR/backend' && python3 scripts/check_control_coverage.py"

if [[ "$STRICT_MODE" -eq 1 ]]; then
  run_check "Day-0 secrets validation" "$LOG_DIR/day0_secrets_validation.log" bash -lc "cd '$ROOT_DIR/backend' && bash scripts/validate_day0_secrets.sh"
else
  run_warn_check "Day-0 secrets validation" "$LOG_DIR/day0_secrets_validation.log" bash -lc "cd '$ROOT_DIR/backend' && bash scripts/validate_day0_secrets.sh"
fi

# Migration validation is warning-level for non-strict local evidence runs and required in strict mode.
if [[ "$STRICT_MODE" -eq 1 ]]; then
  run_check "Alembic current migration state" "$LOG_DIR/alembic_current.log" bash -lc "cd '$ROOT_DIR/backend' && python3 -m alembic current"
  run_check "Alembic heads" "$LOG_DIR/alembic_heads.log" bash -lc "cd '$ROOT_DIR/backend' && python3 -m alembic heads"
else
  run_warn_check "Alembic current migration state" "$LOG_DIR/alembic_current.log" bash -lc "cd '$ROOT_DIR/backend' && python3 -m alembic current"
  run_warn_check "Alembic heads" "$LOG_DIR/alembic_heads.log" bash -lc "cd '$ROOT_DIR/backend' && python3 -m alembic heads"
fi

# Capture repository state evidence when available.
if git -C "$ROOT_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  run_warn_check "Git status snapshot" "$LOG_DIR/git_status.log" bash -lc "cd '$ROOT_DIR' && git status --short"
  run_warn_check "Git head snapshot" "$LOG_DIR/git_head.log" bash -lc "cd '$ROOT_DIR' && git rev-parse HEAD"
else
  record_info "Git snapshots skipped (workspace is not a git repository)"
fi

SUMMARY_FILE="$BUNDLE_DIR/summary.md"
{
  echo "# Release Evidence Bundle Summary"
  echo
  echo "- Release ID: $RELEASE_ID"
  echo "- Environment: $TARGET_ENV"
  echo "- Owner: ${RELEASE_OWNER:-unknown}"
  echo "- Timestamp: $TIMESTAMP"
  echo
  echo "## Results"
  echo
  echo "- Passes: $PASS_COUNT"
  echo "- Warnings: $WARN_COUNT"
  echo "- Fails: $FAIL_COUNT"
  echo
  echo "## Artifact Paths"
  echo
  echo "- Logs: logs/"
  echo "- Metadata: metadata/"
  echo "  - Risk closure dashboard snapshot: metadata/risk_closure_dashboard.txt"
  echo "  - Risk closure dashboard JSON: metadata/risk_closure_dashboard.json"
  echo "  - Release decision record template: metadata/release_decision_record.md"
  echo "  - Pending closure report: metadata/pending_closure_report.txt"
  echo "  - Pending closure report JSON: metadata/pending_closure_report.json"
  echo "  - GuardBridge browser compatibility report: metadata/guardbridge_browser_compat.txt"
  echo "  - GuardBridge extension package output: metadata/guardbridge_extension_package.txt"
  echo "- Doc snapshots: docs/"
} > "$SUMMARY_FILE"

echo
cat "$SUMMARY_FILE"

echo
echo "Bundle directory: $BUNDLE_DIR"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi

if [[ "$STRICT_MODE" -eq 1 && "$WARN_COUNT" -gt 0 ]]; then
  exit 2
fi

exit 0
