#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

API_PORT="${API_PORT:-8000}"

if [[ -f .runtime/api.pid ]]; then
  API_PID="$(cat .runtime/api.pid)"
  if [[ -n "$API_PID" ]] && kill -0 "$API_PID" >/dev/null 2>&1; then
    kill "$API_PID" >/dev/null 2>&1 || true
    echo "Stopped API process $API_PID"
  fi
  rm -f .runtime/api.pid
fi

PORT_PIDS="$(lsof -tiTCP:${API_PORT} -sTCP:LISTEN -n -P || true)"
if [[ -n "$PORT_PIDS" ]]; then
  kill $PORT_PIDS >/dev/null 2>&1 || true
  echo "Stopped API listener(s) on port ${API_PORT}: $PORT_PIDS"
fi

./scripts/shutinfra.sh

echo "All shutdown complete."
