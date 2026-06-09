#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

PORT="${API_PORT:-8000}"
NO_START="false"
AUTO_PORT="false"

for arg in "$@"; do
  case "$arg" in
    --no-start)
      NO_START="true"
      ;;
    --port=*)
      PORT="${arg#*=}"
      ;;
    --auto-port)
      AUTO_PORT="true"
      ;;
    --help|-h)
      echo "Usage: ./scripts/restart_local.sh [--no-start] [--port=<port>] [--auto-port]"
      echo "Environment overrides: DATABASE_URL, API_PORT"
      exit 0
      ;;
    *)
      echo "Unsupported option: $arg"
      echo "Supported options: --no-start --port=<port> --auto-port"
      exit 1
      ;;
  esac
done

DEFAULT_DB_URL="postgresql+psycopg://${USER}@localhost:5432/agenthub"
export DATABASE_URL="${DATABASE_URL:-$DEFAULT_DB_URL}"
PSQL_DATABASE_URL="${DATABASE_URL/postgresql+psycopg/postgresql}"

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required"
  exit 1
fi

if ! command -v psql >/dev/null 2>&1; then
  echo "psql is required. Install PostgreSQL client first."
  exit 1
fi

if ! psql "$PSQL_DATABASE_URL" -c 'select 1;' >/dev/null 2>&1; then
  echo "Database is not reachable using DATABASE_URL=$DATABASE_URL"
  echo "Make sure PostgreSQL is running and database 'agenthub' exists."
  exit 1
fi

PIDS="$(lsof -tiTCP:${PORT} -sTCP:LISTEN -n -P || true)"
if [[ -n "$PIDS" ]]; then
  echo "Stopping process(es) on port ${PORT}: $PIDS"
  kill $PIDS || true
fi

if lsof -iTCP:${PORT} -sTCP:LISTEN -n -P >/dev/null 2>&1; then
  if [[ "$AUTO_PORT" == "true" ]]; then
    START_PORT="$PORT"
    for ((candidate = START_PORT + 1; candidate <= START_PORT + 100; candidate++)); do
      if ! lsof -iTCP:${candidate} -sTCP:LISTEN -n -P >/dev/null 2>&1; then
        PORT="$candidate"
        echo "Port ${START_PORT} is still busy; using available port ${PORT}."
        break
      fi
    done

    if lsof -iTCP:${PORT} -sTCP:LISTEN -n -P >/dev/null 2>&1; then
      echo "No available port found in range ${START_PORT}-$((${START_PORT} + 100))."
      exit 1
    fi
  else
    echo "Port ${PORT} is still in use after stop attempt. Use --auto-port or choose another --port."
    lsof -iTCP:${PORT} -sTCP:LISTEN -n -P
    exit 1
  fi
fi

if [[ "$NO_START" == "true" ]]; then
  echo "Restart pre-check complete. Server start skipped (--no-start)."
  exit 0
fi

echo "Starting API on port ${PORT} with DATABASE_URL=$DATABASE_URL"
echo "Health URL: http://127.0.0.1:${PORT}/health"
echo "Docs URL:   http://127.0.0.1:${PORT}/docs"
python3 -m uvicorn app.main:app --host 127.0.0.1 --port "$PORT" --reload
