#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PORT="${API_PORT:-8000}"
HEALTH_URL="http://127.0.0.1:${PORT}/health"

if ! command -v brew >/dev/null 2>&1 && [[ -x /opt/homebrew/bin/brew ]]; then
  brew() { /opt/homebrew/bin/brew "$@"; }
fi

echo "=== Infra ==="
if command -v brew >/dev/null 2>&1; then
  brew services list | grep postgresql@16 || echo "postgresql@16: not listed"
else
  echo "brew: unavailable"
fi

if [[ "${SHOW_DOCKER_INFRA_STATUS:-0}" == "1" ]]; then
  if command -v docker >/dev/null 2>&1; then
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -Fx "agenthub-postgres" >/dev/null 2>&1; then
      docker ps -a --filter "name=^/agenthub-postgres$" --format "docker agenthub-postgres: {{.Status}}" 2>/dev/null || true
    else
      echo "docker agenthub-postgres: not found"
    fi
  else
    echo "docker: unavailable"
  fi
else
  echo "docker infra status: skipped (set SHOW_DOCKER_INFRA_STATUS=1 to enable)"
fi

echo ""
echo "=== API Process ==="
if [[ -f .runtime/api.pid ]]; then
  API_PID="$(cat .runtime/api.pid)"
  if [[ -n "$API_PID" ]] && kill -0 "$API_PID" >/dev/null 2>&1; then
    echo "api.pid: running (PID ${API_PID})"
  else
    echo "api.pid: stale (${API_PID})"
    rm -f .runtime/api.pid
    echo "api.pid: removed stale pid file"
  fi
else
  echo "api.pid: not found"
fi

PORT_PIDS="$(lsof -tiTCP:${PORT} -sTCP:LISTEN -n -P || true)"
if [[ -n "$PORT_PIDS" ]]; then
  echo "port ${PORT}: listening by PID(s): ${PORT_PIDS}"
else
  echo "port ${PORT}: not listening"
fi

echo ""
echo "=== Health ==="
if curl -s --max-time 2 "$HEALTH_URL" >/dev/null 2>&1; then
  curl -s --max-time 2 "$HEALTH_URL"
  echo ""
else
  echo "health: unavailable (${HEALTH_URL})"
fi
