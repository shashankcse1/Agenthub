#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8080}"
CONTAINER_NAME="${CONTAINER_NAME:-python-platform-api}"

health_status="$(curl -fsS "${BASE_URL}/api/v1/health")"
echo "[smoke] health: ${health_status}"

unauth_code="$(curl -s -o /dev/null -w '%{http_code}' -X POST "${BASE_URL}/api/v1/policy/preview" -H 'Content-Type: application/json' -d '{"trace_id":"trace-1","actor_id":"actor-1","actor_role":"Platform Admin","tenant_id":"tenant-a","environment":"dev","action":"navigate","target":"https://example.com"}')"
if [[ "${unauth_code}" != "401" ]]; then
  echo "[smoke] expected 401 for unauthenticated preview, got ${unauth_code}"
  exit 1
fi

echo "[smoke] unauthenticated policy preview correctly denied"

token="$(docker exec "${CONTAINER_NAME}" python -c "import jwt, os; print(jwt.encode({'sub':'platform-admin','role':'Platform Admin'}, os.environ['JWT_SIGNING_SECRET'], algorithm='HS256'))")"

auth_code="$(curl -s -o /tmp/python-platform-preview.json -w '%{http_code}' -X POST "${BASE_URL}/api/v1/policy/preview" \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer ${token}" \
  -d '{"trace_id":"trace-smoke-auth","actor_id":"user@example.com","actor_role":"Platform Admin","tenant_id":"tenant-a","environment":"dev","action":"navigate","target":"https://example.com/account/12345"}')"
if [[ "${auth_code}" != "200" ]]; then
  echo "[smoke] expected 200 for authenticated preview, got ${auth_code}"
  cat /tmp/python-platform-preview.json
  exit 1
fi

audit_logs="$(docker logs "${CONTAINER_NAME}" 2>&1 | tail -n 200 | grep 'audit_event=policy.preview' | tail -n 1 || true)"
if [[ -z "${audit_logs}" ]]; then
  echo "[smoke] expected audit_event=policy.preview in container logs"
  exit 1
fi

if [[ "${audit_logs}" != *"decision_description=Policy preview allow decision"* ]]; then
  echo "[smoke] expected descriptive audit decision text in logs"
  echo "${audit_logs}"
  exit 1
fi

if [[ "${audit_logs}" != *"pii_redaction=enabled"* || "${audit_logs}" != *"actor_fingerprint="* || "${audit_logs}" != *"target_scope=example.com"* ]]; then
  echo "[smoke] expected PII-safe audit fields in logs"
  echo "${audit_logs}"
  exit 1
fi

if [[ "${audit_logs}" == *"user@example.com"* || "${audit_logs}" == *"https://example.com/account/12345"* ]]; then
  echo "[smoke] raw PII leaked into audit logs"
  echo "${audit_logs}"
  exit 1
fi

echo "[smoke] authenticated audit log is descriptive and PII-safe"
