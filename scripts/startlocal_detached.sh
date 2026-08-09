#!/usr/bin/env bash
# Fully detach API + UI so they survive the launching shell exiting (macOS).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUNTIME_DIR="${ROOT_DIR}/.runtime"
BACKEND_DIR="${ROOT_DIR}/backend"
API_PORT="${API_PORT:-8000}"
UI_PORT="${UI_PORT:-4173}"
UI_HOST="${UI_HOST:-127.0.0.1}"

mkdir -p "$RUNTIME_DIR" "$BACKEND_DIR/.runtime"

if [[ -f "${RUNTIME_DIR}/local-dev.env" ]]; then
  set -a
  # shellcheck disable=SC1091
  . "${RUNTIME_DIR}/local-dev.env"
  set +a
fi
export PATH="/opt/homebrew/opt/libpq/bin:${PATH:-}"
export DATABASE_URL="${DATABASE_URL:-}"
export SESSION_TOKEN_SECRET="${SESSION_TOKEN_SECRET:-}"

docker start agenthub-postgres >/dev/null 2>&1 || true

# Free ports if stale listeners exist
if command -v lsof >/dev/null 2>&1; then
  lsof -tiTCP:"${API_PORT}" -sTCP:LISTEN | xargs kill -9 2>/dev/null || true
  lsof -tiTCP:"${UI_PORT}" -sTCP:LISTEN | xargs kill -9 2>/dev/null || true
  sleep 1
fi

python3 - <<'PY' "$ROOT_DIR" "$API_PORT" "$UI_PORT" "$UI_HOST"
import os
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
api_port = sys.argv[2]
ui_port = sys.argv[3]
ui_host = sys.argv[4]
backend = root / "backend"
runtime = root / ".runtime"
api_log = backend / ".runtime" / "api.log"
ui_log = runtime / "ui.log"
api_pid_path = backend / ".runtime" / "api.pid"
ui_pid_path = runtime / "ui.pid"

env = os.environ.copy()
env["PATH"] = f"/opt/homebrew/opt/libpq/bin:{env.get('PATH', '')}"


def daemonize_and_exec(cmd, cwd, log_path, pid_path):
    # Classic double-fork detach.
    if os.fork() > 0:
        return
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    with open(log_path, "ab", buffering=0) as log:
        os.dup2(log.fileno(), 1)
        os.dup2(log.fileno(), 2)
    with open("/dev/null", "rb") as devnull:
        os.dup2(devnull.fileno(), 0)
    os.chdir(str(cwd))
    pid_path.write_text(str(os.getpid()) + "\n")
    os.execvpe(cmd[0], cmd, env)


# Parent forks workers then exits immediately.
if os.fork() == 0:
    daemonize_and_exec(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", api_port],
        backend,
        api_log,
        api_pid_path,
    )
    os._exit(0)

if os.fork() == 0:
    daemonize_and_exec(
        [
            "/bin/bash",
            str(root / "frontend" / "scripts" / "run_ui.sh"),
            f"--host={ui_host}",
            f"--port={ui_port}",
        ],
        root,
        ui_log,
        ui_pid_path,
    )
    os._exit(0)

# Give children a moment to re-parent under launchd/init.
time.sleep(0.2)
print(f"Detached start requested for API :{api_port} and UI :{ui_port}")
PY

# Wait for readiness in the parent (children already detached)
for _ in $(seq 1 40); do
  if curl -sS -m 1 "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1 \
    && curl -sS -m 1 "http://127.0.0.1:${UI_PORT}/login.html" >/dev/null 2>&1; then
    echo "READY api=http://127.0.0.1:${API_PORT} ui=http://127.0.0.1:${UI_PORT}/login.html"
    exit 0
  fi
  sleep 1
done

echo "START_TIMEOUT — check logs:"
echo "  ${BACKEND_DIR}/.runtime/api.log"
echo "  ${RUNTIME_DIR}/ui.log"
exit 1
