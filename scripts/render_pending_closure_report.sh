#!/usr/bin/env bash
set -euo pipefail

PLAN_PATH="backend/docs/governance/security-risk-closure-plan.md"
OUTPUT_JSON=0

usage() {
  cat <<'EOF'
Usage: bash scripts/render_pending_closure_report.sh [options]

Options:
  --plan <path>  Path to closure plan markdown.
  --json         Output machine-readable JSON report.
  --help, -h     Show help.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --plan)
      PLAN_PATH="${2:-}"
      shift 2
      ;;
    --json)
      OUTPUT_JSON=1
      shift
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
  echo "[pending-report] closure plan not found: $PLAN_PATH" >&2
  exit 1
fi

today="$(date +%F)"

summary_line="$({
  awk -F '|' -v today="$today" '
    function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
    $0 ~ /^\| CL-[0-9]+ / {
      status = tolower(trim($8))
      target = trim($5)
      total++
      if (status == "open") open++
      if (status == "in progress") inprogress++
      if (target != "" && target < today && status != "closed" && status != "completed" && status != "mitigated") overdue++
    }
    $0 ~ /^\| [^|].*\| [^|].*\| [^|].*\| [^|].*\| [^|].*\|$/ && $0 !~ /^\|---/ && $0 !~ /^\| Sign-off Role / {
      # no-op: placeholder to keep awk stable across docs
    }
    END { printf "%d|%d|%d|%d\n", total + 0, open + 0, inprogress + 0, overdue + 0 }
  ' "$PLAN_PATH"
} )"

total_count="${summary_line%%|*}"
rest="${summary_line#*|}"
open_count="${rest%%|*}"
rest="${rest#*|}"
in_progress_count="${rest%%|*}"
overdue_count="${summary_line##*|}"

pending_signoff_count="$(awk -F '|' '
  function trim(s) { gsub(/^[ \t]+|[ \t]+$/, "", s); return s }
  $0 ~ /^\| [^|].*\| [^|].*\| [^|].*\| [^|].*\| [^|].*\|$/ && $0 !~ /^\|---/ {
    role = trim($2)
    status = tolower(trim($5))
    if (role != "" && role != "Sign-off Role" && status == "pending") pending++
  }
  END { print pending + 0 }
' "$PLAN_PATH")"

if [[ "$OUTPUT_JSON" -eq 1 ]]; then
  cat <<EOF
{"date":"${today}","source":"${PLAN_PATH}","closure":{"total":${total_count},"open":${open_count},"in_progress":${in_progress_count},"overdue":${overdue_count}},"signoffs":{"pending":${pending_signoff_count}}}
EOF
  exit 0
fi

cat <<EOF
Pending Closure Report
Date: ${today}
Source: ${PLAN_PATH}

Closure Items:
- Total: ${total_count}
- Open: ${open_count}
- In Progress: ${in_progress_count}
- Overdue: ${overdue_count}

Sign-off Items:
- Pending sign-offs: ${pending_signoff_count}

Operator Notes:
- Use this report with the risk dashboard and decision record during release GO/NO-GO reviews.
EOF
