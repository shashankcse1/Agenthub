#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

UI_PORT="${UI_PORT:-4173}"
UI_HOST="${UI_HOST:-127.0.0.1}"

for arg in "$@"; do
  case "$arg" in
    --port=*)
      UI_PORT="${arg#*=}"
      ;;
    --host=*)
      UI_HOST="${arg#*=}"
      ;;
    --help|-h)
      echo "Usage: ./scripts/run_ui.sh [--port=<port>] [--host=<host>]"
      echo "Environment overrides: UI_PORT, UI_HOST"
      exit 0
      ;;
    *)
      echo "Unsupported option: $arg"
      echo "Usage: ./scripts/run_ui.sh [--port=<port>] [--host=<host>]"
      exit 1
      ;;
  esac
done

echo "Starting frontend static UI on http://${UI_HOST}:${UI_PORT}"
python3 scripts/serve_static.py --host="${UI_HOST}" --port="${UI_PORT}" --web-root="${ROOT_DIR}"
