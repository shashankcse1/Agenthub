#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

DEFAULT_DB_URL="postgresql+psycopg://${USER}@localhost:5432/agenthub"
export DATABASE_URL="${DATABASE_URL:-$DEFAULT_DB_URL}"
PSQL_DATABASE_URL="${DATABASE_URL/postgresql+psycopg/postgresql}"
API_PORT="${API_PORT:-8000}"
API_HEALTH_WAIT_SECONDS="${API_HEALTH_WAIT_SECONDS:-20}"
DB_NAME="${PSQL_DATABASE_URL##*/}"
DB_NAME="${DB_NAME%%\?*}"
ADMIN_DATABASE_URL="${PSQL_DATABASE_URL%/*}/postgres"

mkdir -p .runtime

./scripts/startinfra.sh

if command -v pg_isready >/dev/null 2>&1; then
  if ! pg_isready -h localhost -p 5432 -U "$USER" -t 30 >/dev/null 2>&1; then
    echo "PostgreSQL is not ready on localhost:5432"
    exit 1
  fi
fi

if ! command -v psql >/dev/null 2>&1; then
  echo "psql is required."
  exit 1
fi

if ! psql "$PSQL_DATABASE_URL" -c 'select 1;' >/dev/null 2>&1; then
  if psql "$ADMIN_DATABASE_URL" -c 'select 1;' >/dev/null 2>&1; then
    DB_EXISTS="$(psql "$ADMIN_DATABASE_URL" -tAc "select 1 from pg_database where datname='${DB_NAME}'" || true)"
    if [[ "$DB_EXISTS" != "1" ]]; then
      createdb -h localhost -U "$USER" "$DB_NAME"
      echo "Created database: $DB_NAME"
    fi
  fi

  if ! psql "$PSQL_DATABASE_URL" -c 'select 1;' >/dev/null 2>&1; then
    echo "Database is not reachable using DATABASE_URL=$DATABASE_URL"
    echo "You can inspect service status with: brew services list"
    exit 1
  fi
fi

if lsof -iTCP:${API_PORT} -sTCP:LISTEN -n -P >/dev/null 2>&1; then
  echo "API already running on port ${API_PORT}"
  lsof -iTCP:${API_PORT} -sTCP:LISTEN -n -P
  exit 0
fi

nohup python3 -m uvicorn app.main:app --host 127.0.0.1 --port "${API_PORT}" --reload > .runtime/api.log 2>&1 &
API_PID=$!
echo "$API_PID" > .runtime/api.pid

if command -v curl >/dev/null 2>&1; then
  for _ in $(seq 1 "$API_HEALTH_WAIT_SECONDS"); do
    if curl -s --max-time 2 "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1; then
      break
    fi
    sleep 1
  done

  if ! curl -s --max-time 2 "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1; then
    echo "API failed health check on port ${API_PORT} after ${API_HEALTH_WAIT_SECONDS}s"
    if kill -0 "$API_PID" >/dev/null 2>&1; then
      kill "$API_PID" || true
    fi
    rm -f .runtime/api.pid
    echo "Recent API logs:"
    tail -n 40 .runtime/api.log || true
    exit 1
  fi
fi

echo "All started on port ${API_PORT}. API PID: $API_PID"
echo "Logs: .runtime/api.log"
