#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_PORT="${API_PORT:-8000}"
UI_PORT="${UI_PORT:-4173}"
UI_HOST="${UI_HOST:-127.0.0.1}"

cat <<EOF
Startup guide

Full stack:
  ./scripts/startall.sh

Component-level control:
  ./scripts/stack.sh start backend
  ./scripts/stack.sh start ui
  ./scripts/stack.sh start infra
  ./scripts/stack.sh start prod

Stop controls:
  ./scripts/shutdownall.sh
  ./scripts/stack.sh stop backend
  ./scripts/stack.sh stop ui
  ./scripts/stack.sh stop infra
  ./scripts/stack.sh stop prod

Status controls:
  ./scripts/statusall.sh
  ./scripts/stack.sh status backend
  ./scripts/stack.sh status ui
  ./scripts/stack.sh status infra
  ./scripts/stack.sh status prod

Current defaults:
  API_PORT=${API_PORT}
  UI_PORT=${UI_PORT}
  UI_HOST=${UI_HOST}

Useful references:
  Backend docs: ${ROOT_DIR}/backend/README.md
  Frontend docs: ${ROOT_DIR}/frontend/README.md
  Quickstart: ${ROOT_DIR}/operations-quickstart.md
EOF