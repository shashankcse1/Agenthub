#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

API_PORT="${API_PORT:-8000}"
AUTO_PORT="false"

for arg in "$@"; do
  case "$arg" in
    --port=*)
      API_PORT="${arg#*=}"
      ;;
    --auto-port)
      AUTO_PORT="true"
      ;;
    --help|-h)
      echo "Usage: ./scripts/run_local.sh [--port=<port>] [--auto-port]"
      echo "Environment overrides: DATABASE_URL, API_PORT"
      exit 0
      ;;
    *)
      echo "Unsupported option: $arg"
      echo "Usage: ./scripts/run_local.sh [--port=<port>] [--auto-port]"
      exit 1
      ;;
  esac
done

DEFAULT_DB_URL="postgresql+psycopg://${USER}@localhost:5432/agenthub"
export DATABASE_URL="${DATABASE_URL:-$DEFAULT_DB_URL}"
PSQL_DATABASE_URL="${DATABASE_URL/postgresql+psycopg/postgresql}"

redact_database_url() {
  # Redact URL passwords while preserving user/host/db for troubleshooting.
  printf "%s" "$1" | sed -E 's#(://[^:/@]+):[^@]+@#\1:***@#'
}

if ! command -v python3 >/dev/null 2>&1; then
  echo "python3 is required"
  exit 1
fi

if ! command -v psql >/dev/null 2>&1; then
  echo "psql is required. Install PostgreSQL client first."
  exit 1
fi

if ! psql "$PSQL_DATABASE_URL" -c 'select 1;' >/dev/null 2>&1; then
  echo "Database is not reachable using DATABASE_URL=$(redact_database_url "$DATABASE_URL")"
  echo "Make sure PostgreSQL is running and database 'agenthub' exists."
  exit 1
fi

if lsof -iTCP:${API_PORT} -sTCP:LISTEN -n -P >/dev/null 2>&1; then
  if [[ "$AUTO_PORT" == "true" ]]; then
    START_PORT="$API_PORT"
    for ((candidate = START_PORT + 1; candidate <= START_PORT + 100; candidate++)); do
      if ! lsof -iTCP:${candidate} -sTCP:LISTEN -n -P >/dev/null 2>&1; then
        API_PORT="$candidate"
        echo "Port ${START_PORT} is in use; using available port ${API_PORT}."
        break
      fi
    done

    if lsof -iTCP:${API_PORT} -sTCP:LISTEN -n -P >/dev/null 2>&1; then
      echo "No available port found in range ${START_PORT}-$((${START_PORT} + 100))."
      exit 1
    fi
  else
    echo "Port ${API_PORT} is already in use. Stop the running process, use --auto-port, or set API_PORT/--port to another value."
    lsof -iTCP:${API_PORT} -sTCP:LISTEN -n -P
    exit 1
  fi
fi

echo "Starting API on port ${API_PORT} with DATABASE_URL=$(redact_database_url "$DATABASE_URL")"
echo "Health URL: http://127.0.0.1:${API_PORT}/health"
echo "Docs URL:   http://127.0.0.1:${API_PORT}/docs"
python3 -m uvicorn app.main:app --host 127.0.0.1 --port "${API_PORT}" --reload
