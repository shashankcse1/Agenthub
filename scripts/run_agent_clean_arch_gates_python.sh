#!/usr/bin/env bash
set -euo pipefail

if [[ "${ENABLE_PYTHON_PLATFORM_GATES:-0}" != "1" ]]; then
  echo "[gate] python-platform is deprecated; skipping (set ENABLE_PYTHON_PLATFORM_GATES=1 to run legacy gate)"
  exit 0
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY_DIR="${ROOT_DIR}/archive/python-platform"

if [[ ! -d "${PY_DIR}" ]]; then
  echo "[gate] missing python-platform directory"
  exit 1
fi

bash "${ROOT_DIR}/scripts/verify_python_clean_arch_structure.sh"
bash "${ROOT_DIR}/scripts/verify_python_api_contract_artifacts.sh"

pushd "${PY_DIR}" >/dev/null

echo "[gate] installing python-platform dependencies"
python3 -m pip install -q \
  "fastapi>=0.111.0" \
  "uvicorn>=0.30.0" \
  "pydantic>=2.7.0" \
  "PyJWT>=2.8.0" \
  "pytest>=8.0.0" \
  "httpx>=0.27.0"

echo "[gate] running python-platform tests"
python3 -m pytest -q

popd >/dev/null

echo "[gate] success"
