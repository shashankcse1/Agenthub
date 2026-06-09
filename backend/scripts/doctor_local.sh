#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

API_PORT="${API_PORT:-8000}"

for arg in "$@"; do
  case "$arg" in
    --port=*)
      API_PORT="${arg#*=}"
      ;;
    --help|-h)
      echo "Usage: ./scripts/doctor_local.sh [--port=<port>]"
      echo "Environment overrides: DATABASE_URL, API_PORT"
      exit 0
      ;;
    *)
      echo "Unsupported option: $arg"
      echo "Usage: ./scripts/doctor_local.sh [--port=<port>]"
      exit 1
      ;;
  esac
done

DEFAULT_DB_URL="postgresql+psycopg://${USER}@localhost:5432/agenthub"
DATABASE_URL="${DATABASE_URL:-$DEFAULT_DB_URL}"
PSQL_DATABASE_URL="${DATABASE_URL/postgresql+psycopg/postgresql}"
HEALTH_URL="http://127.0.0.1:${API_PORT}/health"

echo "=== Local Doctor ==="
echo "DATABASE_URL=${DATABASE_URL}"
echo "API_PORT=${API_PORT}"
echo ""

echo "[1/3] Database reachability"
if command -v psql >/dev/null 2>&1; then
  if psql "$PSQL_DATABASE_URL" -c 'select 1;' >/dev/null 2>&1; then
    echo "ok: database is reachable"
  else
    echo "warn: database is not reachable"
    echo "hint: run make startinfra"
  fi
else
  echo "warn: psql not found"
  echo "hint: install PostgreSQL client"
fi

echo ""
echo "[2/3] API port ownership"
PORT_PIDS="$(lsof -tiTCP:${API_PORT} -sTCP:LISTEN -n -P || true)"
if [[ -n "$PORT_PIDS" ]]; then
  echo "info: listener(s) on port ${API_PORT}: ${PORT_PIDS}"
  lsof -iTCP:${API_PORT} -sTCP:LISTEN -n -P || true
  echo "hint: run make stop-port PORT=${API_PORT} to free this port"
else
  echo "ok: no listener on port ${API_PORT}"
fi

echo ""
echo "[3/3] API health"
if curl -s --max-time 2 "$HEALTH_URL" >/dev/null 2>&1; then
  echo "ok: API health is reachable at ${HEALTH_URL}"
  curl -s --max-time 2 "$HEALTH_URL" || true
  echo ""
else
  echo "warn: API health is not reachable at ${HEALTH_URL}"
  echo "hint: run make runlocal-auto or make restartlocal-auto"
fi
