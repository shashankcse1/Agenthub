#!/usr/bin/env bash
set -euo pipefail

if [[ "${ENABLE_PYTHON_PLATFORM_GATES:-0}" != "1" ]]; then
  echo "[verify] python-platform is deprecated; skipping API contract artifact check"
  exit 0
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OPENAPI_FILE="${ROOT_DIR}/archive/python-platform/contracts/openapi/openapi.yaml"
SCHEMA_FILE="${ROOT_DIR}/archive/python-platform/schemas/policy-preview-request.schema.json"

for file in "${OPENAPI_FILE}" "${SCHEMA_FILE}"; do
  if [[ ! -f "${file}" ]]; then
    echo "[verify] missing required contract artifact: ${file}"
    exit 1
  fi
done

if ! rg -q "openapi:\s*3\.0\.3" "${OPENAPI_FILE}"; then
  echo "[verify] OpenAPI version 3.0.3 not found"
  exit 1
fi

if ! rg -q "DecisionPreviewRequest|DecisionPreviewResponse" "${OPENAPI_FILE}"; then
  echo "[verify] Decision preview schemas not found in OpenAPI"
  exit 1
fi

if ! rg -q '"required"\s*:\s*\[' "${SCHEMA_FILE}"; then
  echo "[verify] policy preview schema missing required fields"
  exit 1
fi

echo "[verify] python api contract artifacts checks passed"
