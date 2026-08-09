#!/usr/bin/env bash
set -euo pipefail

PLAN_PATH="backend/docs/governance/security-risk-closure-plan.md"
OUTPUT_JSON=0
STRICT_OVERDUE=0
STRICT_OPEN=0
STRICT_EMPTY=0

print_usage() {
  cat <<'EOF'
Usage: bash scripts/render_risk_closure_dashboard.sh [plan_path] [options]

Options:
  --plan <path>        Path to closure plan markdown file.
  --json               Output machine-readable JSON instead of dashboard text.
  --strict-overdue     Exit non-zero when overdue closure items are present.
  --strict-open        Exit non-zero when open closure items are present.
  --strict-empty       Exit non-zero when no closure items are detected.
  --help, -h           Show this help message.

Notes:
  - Positional [plan_path] is accepted for backward compatibility.
  - Multiple strict flags can be combined.
EOF
}

POSITIONAL_PLAN_SET=0
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
    --strict-overdue)
      STRICT_OVERDUE=1
      shift
      ;;
    --strict-open)
      STRICT_OPEN=1
      shift
      ;;
    --strict-empty)
      STRICT_EMPTY=1
      shift
      ;;
    --help|-h)
      print_usage
      exit 0
      ;;
    -*)
      echo "[risk-dashboard] unknown option: $1" >&2
      print_usage >&2
      exit 2
      ;;
    *)
      if [[ "$POSITIONAL_PLAN_SET" -eq 0 ]]; then
        PLAN_PATH="$1"
        POSITIONAL_PLAN_SET=1
        shift
      else
        echo "[risk-dashboard] unexpected positional argument: $1" >&2
        exit 2
      fi
      ;;
  esac
done

if [[ ! -f "${PLAN_PATH}" ]]; then
  echo "[risk-dashboard] closure plan not found: ${PLAN_PATH}" >&2
  exit 1
fi

today="$(date +%F)"

read -r total_count open_count in_progress_count overdue_count < <(
  awk -F '|' -v today="${today}" '
    function trim(s) {
      gsub(/^[ \t]+|[ \t]+$/, "", s)
      return s
    }
    $0 ~ /^\| CL-[0-9]+ / {
      target = trim($5)
      status = trim($8)
      status_lc = tolower(status)
      total++

      if (status_lc == "open") {
        open++
      }
      if (status_lc == "in progress") {
        inprogress++
      }

      if (target != "" && target < today && status_lc != "closed" && status_lc != "completed" && status_lc != "mitigated") {
        overdue++
      }
    }
    END {
      printf "%d %d %d %d\n", total + 0, open + 0, inprogress + 0, overdue + 0
    }
  ' "${PLAN_PATH}"
)

exit_code=0
if [[ "$STRICT_EMPTY" -eq 1 && "$total_count" -eq 0 ]]; then
  echo "[risk-dashboard] strict-empty failed: no closure items found" >&2
  exit_code=3
fi
if [[ "$STRICT_OPEN" -eq 1 && "$open_count" -gt 0 ]]; then
  echo "[risk-dashboard] strict-open failed: open closure items=${open_count}" >&2
  exit_code=4
fi
if [[ "$STRICT_OVERDUE" -eq 1 && "$overdue_count" -gt 0 ]]; then
  echo "[risk-dashboard] strict-overdue failed: overdue closure items=${overdue_count}" >&2
  exit_code=5
fi

if [[ "$OUTPUT_JSON" -eq 1 ]]; then
  cat <<EOF
{"date":"${today}","source":"${PLAN_PATH}","total":${total_count},"open":${open_count},"in_progress":${in_progress_count},"overdue":${overdue_count}}
EOF
  exit "$exit_code"
fi

cat <<EOF
Risk Closure Status Dashboard
Date: ${today}
Source: ${PLAN_PATH}

- Total closure items count: ${total_count}
- Open closure items count: ${open_count}
- In Progress closure items count: ${in_progress_count}
- Overdue closure items count: ${overdue_count}
- Open items with approved time-bounded accepted risk: Yes / No (manual check)
- CISO delegate acknowledgment for unresolved production-impacting items: Yes / No (manual check)
- Release decision impact summary (1-3 lines):
EOF

exit "$exit_code"
