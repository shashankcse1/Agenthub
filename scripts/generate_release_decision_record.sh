#!/usr/bin/env bash
set -euo pipefail

PLAN_PATH="backend/docs/governance/security-risk-closure-plan.md"
OUTPUT_PATH=""
RELEASE_ID=""
TARGET_ENV=""
OWNER=""
DECISION="TBD"
ACCEPTED_RISK_APPROVED="${RELEASE_ACCEPTED_RISK_APPROVED:-UNSET}"
CISO_ACK="${RELEASE_CISO_ACK:-UNSET}"
EXCEPTION_REF="${RELEASE_EXCEPTION_REF:-${RISK_EXCEPTION_REF:-none}}"
IMPACT_LINES=()

usage() {
  cat <<'EOF'
Usage: bash scripts/generate_release_decision_record.sh [options]

Options:
  --plan <path>        Path to security risk closure plan markdown.
  --release-id <id>    Release identifier.
  --env <name>         Target environment (staging|production).
  --owner <name>       Release owner.
  --decision <value>   Initial decision label (TBD|GO|NO-GO).
  --accepted-risk <value>
                       Whether open items have approved time-bounded accepted risk (yes|no).
  --ciso-ack <value>   Whether CISO delegate acknowledgment is present (yes|no).
  --exception-ref <id> Exception reference id(s) when applicable.
  --impact-line <text> Add release impact summary line (repeat up to 3 lines).
  --output <path>      Output markdown file path. If omitted, prints to stdout.
  --help, -h           Show help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan)
      PLAN_PATH="${2:-}"
      shift 2
      ;;
    --release-id)
      RELEASE_ID="${2:-}"
      shift 2
      ;;
    --env)
      TARGET_ENV="${2:-}"
      shift 2
      ;;
    --owner)
      OWNER="${2:-}"
      shift 2
      ;;
    --decision)
      DECISION="${2:-}"
      shift 2
      ;;
    --accepted-risk)
      ACCEPTED_RISK_APPROVED="${2:-}"
      shift 2
      ;;
    --ciso-ack)
      CISO_ACK="${2:-}"
      shift 2
      ;;
    --exception-ref)
      EXCEPTION_REF="${2:-}"
      shift 2
      ;;
    --impact-line)
      IMPACT_LINES+=("${2:-}")
      shift 2
      ;;
    --output)
      OUTPUT_PATH="${2:-}"
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

if [[ ! -f "$ROOT_DIR/$PLAN_PATH" && ! -f "$PLAN_PATH" ]]; then
  echo "[release-record] closure plan not found: $PLAN_PATH" >&2
  exit 1
fi

if [[ -f "$ROOT_DIR/$PLAN_PATH" ]]; then
  PLAN_PATH="$ROOT_DIR/$PLAN_PATH"
fi

json_output="$(bash "$ROOT_DIR/scripts/render_risk_closure_dashboard.sh" --plan "$PLAN_PATH" --json)"
pending_json="$(bash "$ROOT_DIR/scripts/render_pending_closure_report.sh" --plan "$PLAN_PATH" --json)"

extract_number() {
  local key="$1"
  echo "$json_output" | sed -n "s/.*\"${key}\":\([0-9][0-9]*\).*/\1/p"
}

extract_string() {
  local key="$1"
  echo "$json_output" | sed -n "s/.*\"${key}\":\"\([^\"]*\)\".*/\1/p"
}

today="$(date +%F)"
open_count="$(extract_number open)"
in_progress_count="$(extract_number in_progress)"
overdue_count="$(extract_number overdue)"
total_count="$(extract_number total)"
source_value="$(extract_string source)"
pending_signoffs="$(echo "$pending_json" | sed -n 's/.*"pending":\([0-9][0-9]*\).*/\1/p')"

if [[ -z "$open_count" || -z "$in_progress_count" || -z "$overdue_count" || -z "$total_count" || -z "$pending_signoffs" ]]; then
  echo "[release-record] failed to parse dashboard JSON output" >&2
  exit 1
fi

release_id_value="${RELEASE_ID:-<set-release-id>}"
env_value="${TARGET_ENV:-<staging-or-production>}"
owner_value="${OWNER:-<set-owner>}"

accepted_risk_value="$(echo "$ACCEPTED_RISK_APPROVED" | tr '[:upper:]' '[:lower:]')"
ciso_ack_value="$(echo "$CISO_ACK" | tr '[:upper:]' '[:lower:]')"
exception_ref_value="${EXCEPTION_REF:-none}"

impact_1="${IMPACT_LINES[0]:-not-provided}"
impact_2="${IMPACT_LINES[1]:-not-provided}"
impact_3="${IMPACT_LINES[2]:-not-provided}"

record="$(cat <<EOF
# Release Decision Record

Date: ${today}
Release ID: ${release_id_value}
Environment: ${env_value}
Owner: ${owner_value}
Decision: ${DECISION}

## Risk Closure Snapshot

- Source: ${source_value}
- Total closure items count: ${total_count}
- Open closure items count: ${open_count}
- In Progress closure items count: ${in_progress_count}
- Overdue closure items count: ${overdue_count}
- Pending sign-offs count: ${pending_signoffs}

## Required Assertions

- Open items with approved time-bounded accepted risk: ${accepted_risk_value}
- CISO delegate acknowledgment for unresolved production-impacting items: ${ciso_ack_value}
- Exception reference ID(s) if applicable: ${exception_ref_value}

## Release Impact Summary

1. ${impact_1}
2. ${impact_2}
3. ${impact_3}

## Final Decision Notes

- Constraints:
- Follow-up actions and deadlines:
- Approval references:

EOF
)"

if [[ -n "$OUTPUT_PATH" ]]; then
  mkdir -p "$(dirname "$OUTPUT_PATH")"
  printf "%s" "$record" > "$OUTPUT_PATH"
  echo "[release-record] wrote $OUTPUT_PATH"
else
  printf "%s" "$record"
fi
