#!/usr/bin/env bash
set -u

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_ROOT="$ROOT_DIR/artifacts/release-evidence"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
RELEASE_ID=""
TARGET_ENV=""
RELEASE_OWNER=""
STRICT_MODE=0
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
cp "$ROOT_DIR/backend/docs/security/residual-and-accepted-risk-register.md" "$DOCS_DIR/" 2>/dev/null || true
cp "$ROOT_DIR/frontend/accessibility-conformance-wcag22aa.md" "$DOCS_DIR/" 2>/dev/null || true

# B. Required technical gates
run_check "Full-stack expert review (deep)" "$LOG_DIR/full_stack_expert_review.log" bash "$ROOT_DIR/scripts/full_stack_expert_review.sh" --deep
run_check "Backend test suite" "$LOG_DIR/backend_pytest.log" bash -lc "cd '$ROOT_DIR/backend' && python3 -m pytest -q"
run_check "Frontend security smoke" "$LOG_DIR/frontend_security_smoke.log" bash -lc "cd '$ROOT_DIR/frontend' && bash scripts/security_smoke.sh"
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
