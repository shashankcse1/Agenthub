#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ACTION="${1:-}"
TARGET="${2:-all}"
API_PORT="${API_PORT:-8000}"
UI_PORT="${UI_PORT:-4173}"
UI_HOST="${UI_HOST:-127.0.0.1}"
PROD_COMPOSE_FILE="${PROD_COMPOSE_FILE:-$ROOT_DIR/docker-compose.production.yml}"
PROD_ENV_FILE="${PROD_ENV_FILE:-$ROOT_DIR/.env.production}"

usage() {
  cat <<'EOF'
Usage:
  ./scripts/stack.sh start [all|backend|ui|infra|prod]
  ./scripts/stack.sh stop [all|backend|ui|infra|prod]
  ./scripts/stack.sh status [all|backend|ui|infra|prod]

Defaults to "all" when no component is provided.

Production compose controls use:
  PROD_ENV_FILE (default: .env.production)
  PROD_COMPOSE_FILE (default: docker-compose.production.yml)
EOF
}

ensure_production_prereqs() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required for production stack commands"
    exit 1
  fi
  if [[ ! -f "$PROD_COMPOSE_FILE" ]]; then
    echo "Missing compose file: $PROD_COMPOSE_FILE"
    exit 1
  fi
  if [[ ! -f "$PROD_ENV_FILE" ]]; then
    echo "Missing env file: $PROD_ENV_FILE"
    echo "Create it from .env.production.compose.example"
    exit 1
  fi
}

start_production_stack() {
  ensure_production_prereqs
  docker compose --env-file "$PROD_ENV_FILE" -f "$PROD_COMPOSE_FILE" up -d --build
}

stop_production_stack() {
  ensure_production_prereqs
  docker compose --env-file "$PROD_ENV_FILE" -f "$PROD_COMPOSE_FILE" down
}

status_production_stack() {
  ensure_production_prereqs
  docker compose --env-file "$PROD_ENV_FILE" -f "$PROD_COMPOSE_FILE" ps
}

start_infra() {
  bash "$ROOT_DIR/backend/scripts/startinfra.sh"
}

bootstrap_day0_admin_credentials() {
  bash "$ROOT_DIR/scripts/bootstrap_day0_admin_credentials.sh" >/dev/null
}

start_backend() {
  start_infra

  local pg_ready="false"
  if command -v pg_isready >/dev/null 2>&1; then
    for _ in $(seq 1 30); do
      if pg_isready -h localhost -p 5432 -U "${USER}" -t 2 >/dev/null 2>&1; then
        pg_ready="true"
        break
      fi
      sleep 1
    done
  fi

  if [[ "$pg_ready" != "true" ]] && command -v psql >/dev/null 2>&1; then
    DEFAULT_DB_URL="postgresql+psycopg://${USER}@localhost:5432/agenthub"
    PSQL_DATABASE_URL="${DATABASE_URL:-$DEFAULT_DB_URL}"
    PSQL_DATABASE_URL="${PSQL_DATABASE_URL/postgresql+psycopg/postgresql}"
    for _ in $(seq 1 30); do
      if psql "$PSQL_DATABASE_URL" -c 'select 1;' >/dev/null 2>&1; then
        pg_ready="true"
        break
      fi
      sleep 1
    done
  fi

  if [[ "$pg_ready" != "true" ]]; then
    echo "PostgreSQL is not ready on localhost:5432"
    exit 1
  fi

  bash "$ROOT_DIR/backend/scripts/startall.sh"
}

start_ui() {
  mkdir -p "$ROOT_DIR/.runtime"
  if lsof -iTCP:"$UI_PORT" -sTCP:LISTEN -n -P >/dev/null 2>&1; then
    echo "UI already running on port ${UI_PORT}"
    return 0
  fi

  echo "Starting frontend UI on http://${UI_HOST}:${UI_PORT}"
  nohup bash "$ROOT_DIR/frontend/scripts/run_ui.sh" --host="$UI_HOST" --port="$UI_PORT" > "$ROOT_DIR/.runtime/ui.log" 2>&1 &
  echo $! > "$ROOT_DIR/.runtime/ui.pid"
}

wait_for_ui() {
  if ! command -v curl >/dev/null 2>&1; then
    return 0
  fi

  for _ in $(seq 1 20); do
    if curl -s --max-time 2 "http://${UI_HOST}:${UI_PORT}/" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "UI failed to respond on port ${UI_PORT}"
  tail -n 40 "$ROOT_DIR/.runtime/ui.log" || true
  exit 1
}

wait_for_api() {
  if ! command -v curl >/dev/null 2>&1; then
    return 0
  fi

  for _ in $(seq 1 20); do
    if curl -s --max-time 2 "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done

  echo "API failed to respond on port ${API_PORT}"
  exit 1
}

stop_ui() {
  if [[ -f "$ROOT_DIR/.runtime/ui.pid" ]]; then
    UI_PID="$(cat "$ROOT_DIR/.runtime/ui.pid")"
    if [[ -n "$UI_PID" ]] && kill -0 "$UI_PID" >/dev/null 2>&1; then
      kill "$UI_PID" || true
      echo "Stopped UI process $UI_PID"
    fi
    rm -f "$ROOT_DIR/.runtime/ui.pid"
  fi

  UI_PORT_PIDS="$(lsof -tiTCP:${UI_PORT} -sTCP:LISTEN -n -P || true)"
  if [[ -n "$UI_PORT_PIDS" ]]; then
    kill $UI_PORT_PIDS || true
    echo "Stopped UI listener(s) on port ${UI_PORT}: $UI_PORT_PIDS"
  fi
}

stop_backend_and_infra() {
  bash "$ROOT_DIR/backend/scripts/shutdownall.sh"
}

status_backend_and_infra() {
  bash "$ROOT_DIR/backend/scripts/statusall.sh"
}

status_ui() {
  local ui_pid=""
  if [[ -f "$ROOT_DIR/.runtime/ui.pid" ]]; then
    ui_pid="$(cat "$ROOT_DIR/.runtime/ui.pid")"
  fi
  if [[ -n "$ui_pid" ]] && kill -0 "$ui_pid" >/dev/null 2>&1; then
    echo "UI pid: running ($ui_pid)"
  elif [[ -n "$ui_pid" ]]; then
    echo "UI pid: stale ($ui_pid)"
  else
    echo "UI pid: not found"
  fi

  local ui_pids=""
  ui_pids="$(lsof -tiTCP:${UI_PORT} -sTCP:LISTEN -n -P || true)"
  if [[ -n "$ui_pids" ]]; then
    echo "UI port ${UI_PORT}: listening by PID(s): $ui_pids"
  else
    echo "UI port ${UI_PORT}: not listening"
  fi
}

case "$ACTION" in
  start)
    case "$TARGET" in
      all)
        bootstrap_day0_admin_credentials
        echo "Starting infra, backend, and UI..."
        start_backend
        start_ui
        wait_for_ui
        wait_for_api
        echo "All three components are up: infra, backend on ${API_PORT}, UI on ${UI_PORT}"
        echo "UI logs: $ROOT_DIR/.runtime/ui.log"
        ;;
      backend)
        bootstrap_day0_admin_credentials
        start_backend
        wait_for_api
        echo "Backend is up on ${API_PORT}"
        ;;
      ui)
        bootstrap_day0_admin_credentials
        start_ui
        wait_for_ui
        echo "UI is up on ${UI_PORT}"
        ;;
      infra)
        bootstrap_day0_admin_credentials
        start_infra
        echo "Infra is up"
        ;;
      prod)
        echo "Starting production compose stack..."
        start_production_stack
        echo "Production stack is up"
        ;;
      *)
        usage
        exit 1
        ;;
    esac
    ;;
  stop)
    case "$TARGET" in
      all)
        stop_ui
        stop_backend_and_infra
        if command -v curl >/dev/null 2>&1; then
          if curl -s --max-time 2 "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1; then
            echo "Warning: API still responds on port ${API_PORT}"
          fi
          if curl -s --max-time 2 "http://127.0.0.1:${UI_PORT}/" >/dev/null 2>&1; then
            echo "Warning: UI still responds on port ${UI_PORT}"
          fi
        fi
        echo "All shutdown complete for infra, backend, and UI."
        ;;
      backend)
        bash "$ROOT_DIR/backend/scripts/shutdownall.sh"
        ;;
      ui)
        stop_ui
        echo "UI shutdown complete"
        ;;
      infra)
        bash "$ROOT_DIR/backend/scripts/shutinfra.sh"
        ;;
      prod)
        echo "Stopping production compose stack..."
        stop_production_stack
        echo "Production stack is down"
        ;;
      *)
        usage
        exit 1
        ;;
    esac
    ;;
  status)
    case "$TARGET" in
      all)
        status_backend_and_infra
        echo ""
        status_ui
        ;;
      backend)
        status_backend_and_infra
        ;;
      ui)
        status_ui
        ;;
      infra)
        status_backend_and_infra
        ;;
      prod)
        status_production_stack
        ;;
      *)
        usage
        exit 1
        ;;
    esac
    ;;
  *)
    usage
    exit 1
    ;;
esac