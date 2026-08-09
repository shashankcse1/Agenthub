#!/usr/bin/env bash
set -euo pipefail

PLAN_PATH="backend/docs/governance/security-risk-closure-plan.md"
TARGET_ENV="staging"
DECISION="TBD"
DECISION_RECORD_PATH=""
ALLOW_OVERDUE_EXCEPTION=""

usage() {
  cat <<'EOF'
Usage: bash scripts/validate_release_risk_guardrails.sh [options]

Options:
  --plan <path>               Path to closure plan markdown.
  --env <staging|production>  Target environment.
  --decision <TBD|GO|NO-GO>   Release decision label.
  --decision-record <path>    Optional decision record markdown for assertion checks.
  --allow-overdue-exception <id>
                              Optional approved exception reference for overdue production GO.
  --help, -h                  Show this help message.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan)
      PLAN_PATH="${2:-}"
      shift 2
      ;;
    --env)
      TARGET_ENV="${2:-}"
      shift 2
      ;;
    --decision)
      DECISION="${2:-}"
      shift 2
      ;;
    --decision-record)
      DECISION_RECORD_PATH="${2:-}"
      shift 2
      ;;
    --allow-overdue-exception)
      ALLOW_OVERDUE_EXCEPTION="${2:-}"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -f "$ROOT_DIR/$PLAN_PATH" ]]; then
  PLAN_PATH="$ROOT_DIR/$PLAN_PATH"
fi

if [[ ! -f "$PLAN_PATH" ]]; then
  echo "[risk-guardrails] closure plan not found: $PLAN_PATH" >&2
  exit 1
fi

dashboard_json="$(bash "$ROOT_DIR/scripts/render_risk_closure_dashboard.sh" --plan "$PLAN_PATH" --json)"

extract_num() {
  local key="$1"
  echo "$dashboard_json" | sed -n "s/.*\"${key}\":\([0-9][0-9]*\).*/\1/p"
}

open_count="$(extract_num open)"
in_progress_count="$(extract_num in_progress)"
overdue_count="$(extract_num overdue)"

if [[ -z "$open_count" || -z "$in_progress_count" || -z "$overdue_count" ]]; then
  echo "[risk-guardrails] failed to parse dashboard JSON" >&2
  exit 1
fi

echo "[risk-guardrails] env=${TARGET_ENV} decision=${DECISION} open=${open_count} in_progress=${in_progress_count} overdue=${overdue_count}"

if [[ "$TARGET_ENV" == "production" && "$DECISION" == "GO" ]]; then
  if [[ "$overdue_count" -gt 0 && -z "$ALLOW_OVERDUE_EXCEPTION" ]]; then
    echo "[risk-guardrails] production GO blocked: overdue closure items=${overdue_count} and no exception reference provided" >&2
    exit 10
  fi

  if [[ -n "$DECISION_RECORD_PATH" ]]; then
    if [[ -f "$ROOT_DIR/$DECISION_RECORD_PATH" ]]; then
      DECISION_RECORD_PATH="$ROOT_DIR/$DECISION_RECORD_PATH"
    fi
    if [[ ! -f "$DECISION_RECORD_PATH" ]]; then
      echo "[risk-guardrails] decision record not found: $DECISION_RECORD_PATH" >&2
      exit 11
    fi

    if ! grep -Eqi "CISO delegate acknowledgment for unresolved production-impacting items:[[:space:]]*yes" "$DECISION_RECORD_PATH"; then
      echo "[risk-guardrails] production GO blocked: decision record missing explicit CISO delegate acknowledgment=Yes" >&2
      exit 12
    fi

    if grep -Eqi "Open items with approved time-bounded accepted risk:[[:space:]]*unset|CISO delegate acknowledgment for unresolved production-impacting items:[[:space:]]*unset" "$DECISION_RECORD_PATH"; then
      echo "[risk-guardrails] production GO blocked: unresolved assertion values (unset) in decision record" >&2
      exit 14
    fi

    if [[ "$open_count" -gt 0 ]]; then
      if ! grep -Eqi "Open items with approved time-bounded accepted risk:[[:space:]]*yes" "$DECISION_RECORD_PATH"; then
        echo "[risk-guardrails] production GO blocked: open closure items require approved accepted-risk assertion=yes" >&2
        exit 15
      fi
    fi

    if [[ "$overdue_count" -gt 0 ]]; then
      if ! grep -Eq "Exception reference ID\(s\) if applicable:[[:space:]]*[A-Za-z0-9._-]+" "$DECISION_RECORD_PATH"; then
        echo "[risk-guardrails] production GO blocked: overdue items require exception reference in decision record" >&2
        exit 13
      fi
    fi
  fi
fi

if [[ "$TARGET_ENV" == "production" && "$DECISION" == "TBD" ]]; then
  echo "[risk-guardrails] note: production decision is TBD; GO-specific assertions not yet enforced"
fi

echo "[risk-guardrails] checks passed"
exit 0
