#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY_DIR="${ROOT_DIR}/archive/python-platform"
ENV_FILE="${PY_DIR}/.env"
CONTAINER_NAME="python-platform-api"

if [[ ! -d "${PY_DIR}" ]]; then
  echo "[deploy] python-platform directory not found"
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "[deploy] docker is required"
  exit 1
fi

if ! command -v docker compose >/dev/null 2>&1; then
  echo "[deploy] docker compose plugin is required"
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "[deploy] docker daemon is not running or not reachable"
  echo "[deploy] start Docker Desktop (or your docker daemon) and retry"
  exit 1
fi

pushd "${PY_DIR}" >/dev/null

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "[deploy] .env not found, copying from .env.example"
  cp .env.example .env
  echo "[deploy] update archive/python-platform/.env with a strong JWT_SIGNING_SECRET before production use"
fi

app_env="$(grep -E '^APP_ENV=' "${ENV_FILE}" | tail -n 1 | cut -d '=' -f2- | tr -d '[:space:]' || true)"
jwt_secret="$(grep -E '^JWT_SIGNING_SECRET=' "${ENV_FILE}" | tail -n 1 | cut -d '=' -f2- || true)"
audit_secret="$(grep -E '^AUDIT_SIGNING_SECRET=' "${ENV_FILE}" | tail -n 1 | cut -d '=' -f2- || true)"

if [[ -z "${app_env}" ]]; then
  app_env="prod"
fi

if [[ "${app_env}" != "dev" ]]; then
  if [[ -z "${jwt_secret}" || "${jwt_secret}" == "replace-with-strong-secret" ]]; then
    echo "[deploy] insecure JWT_SIGNING_SECRET for APP_ENV=${app_env}; set a strong non-placeholder value in archive/python-platform/.env"
    popd >/dev/null
    exit 1
  fi
  if [[ -z "${audit_secret}" || "${audit_secret}" == "replace-with-strong-audit-secret" ]]; then
    echo "[deploy] insecure AUDIT_SIGNING_SECRET for APP_ENV=${app_env}; set a strong non-placeholder value in archive/python-platform/.env"
    popd >/dev/null
    exit 1
  fi
fi

echo "[deploy] building and starting python-platform-api container"
docker compose up -d --build

echo "[deploy] waiting for health endpoint"
for i in {1..20}; do
  if curl -fsS http://127.0.0.1:8080/api/v1/health >/dev/null; then
    echo "[deploy] python-platform-api is healthy"
    CONTAINER_NAME="${CONTAINER_NAME}" bash scripts/container_smoke.sh
    popd >/dev/null
    exit 0
  fi
  sleep 2
done

echo "[deploy] health check did not pass in time"
docker compose logs --tail=100
popd >/dev/null
exit 1
