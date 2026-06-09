#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

MODE="check"
API_PORT="${API_PORT:-8000}"
ACTOR_ID="${ACTOR_ID:-cutover-auditor}"

usage() {
  cat <<'EOF'
Usage: ./scripts/rate_limit_cutover.sh [--mode=<check|probe|failover|rollback>] [--port=<port>] [--actor-id=<id>]

Modes:
  check     Validate distributed rate-limit configuration and Redis reachability
  probe     Exercise live API rate limiting and assert HTTP 429 enforcement
  failover  Simulate Redis outage and verify automatic fallback to memory mode
  rollback  Verify memory backend rollback path for emergency operations

Environment:
  RATE_LIMIT_BACKEND      Expected backend mode (memory|redis)
  RATE_LIMIT_REDIS_URL    Redis URL when backend is redis
  RATE_LIMIT_REDIS_PREFIX Optional key prefix (default rate-limit)
EOF
}

for arg in "$@"; do
  case "$arg" in
    --mode=*)
      MODE="${arg#*=}"
      ;;
    --port=*)
      API_PORT="${arg#*=}"
      ;;
    --actor-id=*)
      ACTOR_ID="${arg#*=}"
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "Unsupported option: $arg"
      usage
      exit 1
      ;;
  esac
done

RATE_LIMIT_BACKEND="${RATE_LIMIT_BACKEND:-memory}"
RATE_LIMIT_REDIS_URL="${RATE_LIMIT_REDIS_URL:-redis://127.0.0.1:6379/0}"
RATE_LIMIT_REDIS_PREFIX="${RATE_LIMIT_REDIS_PREFIX:-rate-limit}"

check_mode() {
  echo "[rate-limit cutover] mode=check"
  echo "RATE_LIMIT_BACKEND=${RATE_LIMIT_BACKEND}"
  echo "RATE_LIMIT_REDIS_URL=${RATE_LIMIT_REDIS_URL}"
  echo "RATE_LIMIT_REDIS_PREFIX=${RATE_LIMIT_REDIS_PREFIX}"

  if [[ "$RATE_LIMIT_BACKEND" != "redis" ]]; then
    echo "warn: distributed mode not enabled (RATE_LIMIT_BACKEND=${RATE_LIMIT_BACKEND})"
    echo "hint: set RATE_LIMIT_BACKEND=redis for multi-instance enforcement"
    return 0
  fi

  python3 - <<'PY'
import os
import sys

redis_url = os.getenv("RATE_LIMIT_REDIS_URL", "")
try:
    import redis  # type: ignore
except Exception as exc:  # pragma: no cover
    print(f"fail: redis package unavailable: {exc}")
    sys.exit(1)

client = redis.from_url(redis_url, decode_responses=True)
try:
    pong = client.ping()
except Exception as exc:
    print(f"fail: redis connectivity check failed: {exc}")
    sys.exit(1)

if pong is True:
    print("pass: redis connectivity check succeeded")
else:
    print("fail: redis ping returned non-true response")
    sys.exit(1)
PY
}

probe_mode() {
  echo "[rate-limit cutover] mode=probe"
  health_url="http://127.0.0.1:${API_PORT}/health"
  target_url="http://127.0.0.1:${API_PORT}/observability/logs?limit=1"

  if ! curl -s --max-time 2 "$health_url" >/dev/null 2>&1; then
    echo "fail: API health endpoint is not reachable at ${health_url}"
    exit 1
  fi

  status=""
  for _ in $(seq 1 31); do
    status="$(curl -s -o /dev/null -w "%{http_code}" \
      -H "X-Actor-Role: Auditor" \
      -H "X-Actor-Id: ${ACTOR_ID}" \
      "$target_url")"
  done

  if [[ "$status" != "429" ]]; then
    echo "fail: expected HTTP 429 on threshold breach, got ${status}"
    exit 1
  fi

  echo "pass: rate limiter returned HTTP 429 on threshold breach"
}

failover_mode() {
  echo "[rate-limit cutover] mode=failover"
  python3 - <<'PY'
from app.services.rate_limit import SlidingWindowRateLimiter

limiter = SlidingWindowRateLimiter(backend="redis", redis_url="redis://127.0.0.1:6399/0")
allowed, _ = limiter.allow(actor_id="failover-check", method="POST", path="/auth/sessions")
if not allowed:
    raise SystemExit("fail: first request should be allowed even during fallback")
if limiter.backend_mode != "memory":
    raise SystemExit(f"fail: expected fallback to memory backend, got {limiter.backend_mode}")
print("pass: redis outage simulation fell back to memory backend")
PY
}

rollback_mode() {
  echo "[rate-limit cutover] mode=rollback"
  echo "Rollback command set:"
  echo "  export RATE_LIMIT_BACKEND=memory"
  echo "  unset RATE_LIMIT_REDIS_URL"
  echo "  restart service rollout"

  python3 - <<'PY'
from app.services.rate_limit import SlidingWindowRateLimiter

limiter = SlidingWindowRateLimiter(backend="memory")
if limiter.backend_mode != "memory":
    raise SystemExit(f"fail: expected memory backend, got {limiter.backend_mode}")
for _ in range(20):
    allowed, _ = limiter.allow(actor_id="rollback-check", method="POST", path="/auth/sessions")
    if not allowed:
        raise SystemExit("fail: request should be allowed before threshold")
blocked, retry_after = limiter.allow(actor_id="rollback-check", method="POST", path="/auth/sessions")
if blocked or retry_after != 60:
    raise SystemExit("fail: memory rollback enforcement check failed")
print("pass: memory backend rollback verification succeeded")
PY
}

case "$MODE" in
  check)
    check_mode
    ;;
  probe)
    probe_mode
    ;;
  failover)
    failover_mode
    ;;
  rollback)
    rollback_mode
    ;;
  *)
    echo "Unsupported mode: ${MODE}"
    usage
    exit 1
    ;;
esac
