#!/usr/bin/env bash
set -euo pipefail

if ! command -v docker >/dev/null 2>&1; then
  echo "[smoke] docker is required"
  exit 1
fi

if ! command -v docker compose >/dev/null 2>&1; then
  echo "[smoke] docker compose plugin is required"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "[smoke] docker daemon is not running"
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
pushd "${ROOT_DIR}" >/dev/null

echo "[smoke] building python-platform-api image"
docker compose build python-platform-api >/dev/null

echo "[smoke] asserting invalid evidence storage mode fails closed"
set +e
invalid_output="$(docker compose run --rm \
  -e EVIDENCE_STORAGE_MODE=invalid-mode \
  -e EVIDENCE_STORE_PATH=/tmp/agent_platform_evidence.jsonl \
  python-platform-api \
  python -c "import agent_platform.api.dependencies" 2>&1)"
invalid_rc=$?
set -e

if [[ ${invalid_rc} -eq 0 ]]; then
  echo "[smoke] expected non-zero exit for invalid mode"
  exit 1
fi

if [[ "${invalid_output}" != *"Unsupported EVIDENCE_STORAGE_MODE"* ]]; then
  echo "[smoke] expected unsupported mode error message"
  echo "${invalid_output}"
  exit 1
fi

echo "[smoke] invalid mode rejected as expected"

echo "[smoke] asserting worm_json mode initializes successfully"
docker compose run --rm \
  -e EVIDENCE_STORAGE_MODE=worm_json \
  -e EVIDENCE_STORE_PATH=/tmp/worm-events \
  python-platform-api \
  python -c "import agent_platform.api.dependencies" >/dev/null

echo "[smoke] fail-closed startup validation passed"
popd >/dev/null