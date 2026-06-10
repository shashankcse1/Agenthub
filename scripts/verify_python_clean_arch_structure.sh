#!/usr/bin/env bash
set -euo pipefail

if [[ "${ENABLE_PYTHON_PLATFORM_GATES:-0}" != "1" ]]; then
  echo "[verify] python-platform is deprecated; skipping clean architecture check"
  exit 0
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY_DIR="${ROOT_DIR}/archive/python-platform"

if [[ ! -d "${PY_DIR}" ]]; then
  echo "[verify] missing python-platform directory"
  exit 1
fi

DOMAIN_DIR="${PY_DIR}/src/agent_platform/domain"
APP_DIR="${PY_DIR}/src/agent_platform/application"

if rg -n "fastapi|pydantic" "${DOMAIN_DIR}" >/dev/null 2>&1; then
  echo "[verify] domain layer imports forbidden api/framework packages"
  exit 1
fi

if rg -n "agent_platform\.api|agent_platform\.adapters" "${APP_DIR}" >/dev/null 2>&1; then
  echo "[verify] application layer depends on api or adapters"
  exit 1
fi

echo "[verify] python clean architecture static checks passed"
