from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable
from collections import defaultdict, deque
from dataclasses import dataclass
from threading import Lock
from time import monotonic, time
from uuid import uuid4

from app.database import SessionLocal
from app.logging_utils import get_logger, sanitize_fields
from app.models import RuntimeConfig
from app.runtime_constants import (
    RUNTIME_CONFIG_RATE_LIMIT_EXACT_RULES_JSON,
    RUNTIME_CONFIG_RATE_LIMIT_RULES_REFRESH_SECONDS,
    RUNTIME_CONFIG_RATE_LIMIT_WILDCARD_RULES_JSON,
)


@dataclass(frozen=True)
class RateLimitRule:
    max_requests: int
    window_seconds: int


logger = get_logger(__name__)


def _safe_retry_seconds(raw: str | None, default: int = 30) -> int:
    try:
        parsed = int((raw or str(default)).strip())
    except Exception:
        return max(5, default)
    return max(5, parsed)


def _safe_positive_int(raw: str | None, default: int, min_value: int = 1) -> int:
    try:
        parsed = int((raw or str(default)).strip())
    except Exception:
        return max(min_value, default)
    return max(min_value, parsed)


# Exact path rules fallback when DB overrides are unavailable.
DEFAULT_UI_POLLING_RULES: dict[tuple[str, str], RateLimitRule] = {
    ("GET", "/observability/logs"): RateLimitRule(max_requests=30, window_seconds=10),
    ("GET", "/cost/live"): RateLimitRule(max_requests=30, window_seconds=10),
    ("GET", "/discovery/agents"): RateLimitRule(max_requests=30, window_seconds=10),
    ("GET", "/agentic/policy/schedules/summary"): RateLimitRule(max_requests=30, window_seconds=10),
    ("GET", "/route-drafts"): RateLimitRule(max_requests=30, window_seconds=10),
    ("POST", "/auth/sessions"): RateLimitRule(max_requests=20, window_seconds=60),
    ("POST", "/auth/login"): RateLimitRule(max_requests=12, window_seconds=60),
    ("POST", "/auth/workload-identity/token-exchange"): RateLimitRule(max_requests=20, window_seconds=60),
    ("GET", "/gateway/runtime-risk/config"): RateLimitRule(max_requests=60, window_seconds=60),
    ("PUT", "/gateway/runtime-risk/config"): RateLimitRule(max_requests=10, window_seconds=300),
    ("POST", "/gateway/runtime-risk/evaluate"): RateLimitRule(max_requests=30, window_seconds=60),
}

# Prefix rules fallback for endpoints with path parameters.
DEFAULT_WILDCARD_RULES: dict[tuple[str, str], RateLimitRule] = {
    ("POST", "/auth/basic/config/"): RateLimitRule(max_requests=10, window_seconds=300),
    ("POST", "/keys/"): RateLimitRule(max_requests=20, window_seconds=300),
    ("POST", "/route-drafts/"): RateLimitRule(max_requests=30, window_seconds=300),
    ("POST", "/orchestration/flows/"): RateLimitRule(max_requests=30, window_seconds=300),
    ("POST", "/orchestration/flows"): RateLimitRule(max_requests=30, window_seconds=300),
    ("GET", "/gateway/jit-actions/"): RateLimitRule(max_requests=60, window_seconds=60),
    ("POST", "/gateway/jit-actions/"): RateLimitRule(max_requests=20, window_seconds=60),
}


class SlidingWindowRateLimiter:
    def __init__(
        self,
        backend: str | None = None,
        redis_url: str | None = None,
        redis_prefix: str | None = None,
        redis_client: object | None = None,
        now_fn: Callable[[], float] | None = None,
    ) -> None:
        self._buckets: dict[tuple[str, str, str], deque[float]] = defaultdict(deque)
        self._backend = (backend or os.getenv("RATE_LIMIT_BACKEND") or "memory").strip().lower()
        self._configured_backend = self._backend
        self._redis_url = (redis_url or os.getenv("RATE_LIMIT_REDIS_URL") or "redis://localhost:6379/0").strip()
        self._redis_prefix = (redis_prefix or os.getenv("RATE_LIMIT_REDIS_PREFIX") or "rate-limit").strip()
        self._redis = redis_client
        self._redis_retry_seconds = _safe_retry_seconds(os.getenv("RATE_LIMIT_REDIS_RETRY_SECONDS"), default=30)
        self._degraded_alert_attempts = _safe_positive_int(
            os.getenv("RATE_LIMIT_DEGRADED_ALERT_ATTEMPTS"),
            default=10,
            min_value=1,
        )
        self._next_redis_retry_monotonic = 0.0
        self._redis_recovery_attempts = 0
        self._redis_recovery_successes = 0
        self._redis_last_recovery_unix = 0.0
        self._redis_last_error = ""
        self._wall_clock = now_fn or time
        self._exact_rules: dict[tuple[str, str], RateLimitRule] = dict(DEFAULT_UI_POLLING_RULES)
        self._wildcard_rules: dict[tuple[str, str], RateLimitRule] = dict(DEFAULT_WILDCARD_RULES)
        self._rules_refresh_seconds = 30
        self._last_rules_refresh_monotonic = 0.0
        self._rules_lock = Lock()
        self._last_degraded_alert_unix = 0.0
        self._degraded_alert_min_interval_seconds = _safe_positive_int(
            os.getenv("RATE_LIMIT_REDIS_FALLBACK_WARN_PER_HOUR"),
            default=1,
            min_value=1,
        ) * 3600

        if self._backend not in {"memory", "redis"}:
            logger.warning(
                "rate_limiter_invalid_backend_fallback %s",
                sanitize_fields({"configured_backend": self._backend}),
            )
            self._backend = "memory"

        if self._backend == "redis" and self._redis is None:
            if not self._try_initialize_redis_client():
                self._backend = "memory"
                self._next_redis_retry_monotonic = monotonic() + self._redis_retry_seconds

            self._refresh_rules_if_needed(force=True)

    def _try_initialize_redis_client(self) -> bool:
        if self._redis is not None:
            return True
        try:
            import redis  # type: ignore

            self._redis = redis.from_url(self._redis_url, decode_responses=False)
            self._redis_last_error = ""
            return True
        except Exception as exc:
            logger.warning(
                "rate_limiter_redis_init_failed_fallback %s",
                sanitize_fields({"redis_url": self._redis_url}),
            )
            self._redis_last_error = type(exc).__name__
            self._redis = None
            return False

    def _try_recover_redis_backend(self) -> None:
        if self._configured_backend != "redis":
            return
        if self._backend == "redis" and self._redis is not None:
            return
        now = monotonic()
        if now < self._next_redis_retry_monotonic:
            return
        self._redis_recovery_attempts += 1
        if self._try_initialize_redis_client():
            self._backend = "redis"
            self._redis_recovery_successes += 1
            self._redis_last_recovery_unix = self._wall_clock()
            logger.info("rate_limiter_redis_recovered")
            return
        if self._redis_recovery_attempts % self._degraded_alert_attempts == 0:
            logger.error(
                "rate_limiter_redis_degraded_persistent %s",
                sanitize_fields(
                    {
                        "attempts": self._redis_recovery_attempts,
                        "retry_seconds": self._redis_retry_seconds,
                        "last_error": self._redis_last_error,
                    }
                ),
            )
        self._next_redis_retry_monotonic = now + self._redis_retry_seconds

    @property
    def backend_mode(self) -> str:
        return self._backend

    @property
    def configured_backend(self) -> str:
        return self._configured_backend

    def runtime_status(self) -> dict[str, object]:
        return {
            "configured_backend": self._configured_backend,
            "active_backend": self._backend,
            "degraded": self._configured_backend == "redis" and self._backend != "redis",
            "redis_retry_seconds": self._redis_retry_seconds,
            "degraded_alert_attempts": self._degraded_alert_attempts,
            "redis_recovery_attempts": self._redis_recovery_attempts,
            "redis_recovery_successes": self._redis_recovery_successes,
            "redis_last_recovery_unix": self._redis_last_recovery_unix,
            "redis_last_error": self._redis_last_error,
            "degraded_alert_min_interval_seconds": self._degraded_alert_min_interval_seconds,
            "last_degraded_alert_unix": self._last_degraded_alert_unix,
        }

    def maybe_emit_degraded_alert(self, emit_fn: Callable[[str], None] | None) -> bool:
        """Emit a throttled security alert while Redis rate-limit backend is degraded (RSK-005)."""
        if emit_fn is None:
            return False
        degraded = self._configured_backend == "redis" and self._backend != "redis"
        if not degraded:
            return False
        now = float(self._wall_clock())
        if self._last_degraded_alert_unix and (now - self._last_degraded_alert_unix) < self._degraded_alert_min_interval_seconds:
            return False
        warning = (
            "RATE_LIMIT_BACKEND=redis is degraded to in-memory fallback; "
            f"last_error={self._redis_last_error or 'unknown'} attempts={self._redis_recovery_attempts}"
        )
        emit_fn(warning)
        self._last_degraded_alert_unix = now
        return True

    @staticmethod
    def _stable_id(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]

    def _resolve_rule(self, method: str, path: str) -> RateLimitRule | None:
        exact = self._exact_rules.get((method, path))
        if exact is not None:
            return exact

        for (rule_method, path_prefix), rule in self._wildcard_rules.items():
            if rule_method == method and path.startswith(path_prefix):
                return rule
        return None

    @staticmethod
    def _parse_db_rules(raw_json: str, wildcard: bool) -> dict[tuple[str, str], RateLimitRule] | None:
        try:
            payload = json.loads(raw_json)
        except Exception:
            return None

        output: dict[tuple[str, str], RateLimitRule] = {}
        if isinstance(payload, list):
            for item in payload:
                if not isinstance(item, dict):
                    continue
                method = str(item.get("method") or "").strip().upper()
                path_field = "path_prefix" if wildcard else "path"
                path = str(item.get(path_field) or "").strip()
                max_requests = int(item.get("max_requests") or 0)
                window_seconds = int(item.get("window_seconds") or 0)
                if method and path and max_requests > 0 and window_seconds > 0:
                    output[(method, path)] = RateLimitRule(max_requests=max_requests, window_seconds=window_seconds)
            return output

        if isinstance(payload, dict):
            for composite, value in payload.items():
                if not isinstance(value, dict) or not isinstance(composite, str) or " " not in composite:
                    continue
                method, path = composite.split(" ", 1)
                method = method.strip().upper()
                path = path.strip()
                max_requests = int(value.get("max_requests") or 0)
                window_seconds = int(value.get("window_seconds") or 0)
                if method and path and max_requests > 0 and window_seconds > 0:
                    output[(method, path)] = RateLimitRule(max_requests=max_requests, window_seconds=window_seconds)
            return output

        return None

    def _read_db_rules(self) -> tuple[dict[tuple[str, str], RateLimitRule] | None, dict[tuple[str, str], RateLimitRule] | None, int | None]:
        db = SessionLocal()
        try:
            rows = (
                db.query(RuntimeConfig)
                .filter(
                    RuntimeConfig.config_key.in_(
                        {
                            RUNTIME_CONFIG_RATE_LIMIT_EXACT_RULES_JSON,
                            RUNTIME_CONFIG_RATE_LIMIT_WILDCARD_RULES_JSON,
                            RUNTIME_CONFIG_RATE_LIMIT_RULES_REFRESH_SECONDS,
                        }
                    )
                )
                .all()
            )
            values = {row.config_key: row.config_value for row in rows}

            exact_rules = None
            wildcard_rules = None
            refresh_seconds = None

            exact_raw = values.get(RUNTIME_CONFIG_RATE_LIMIT_EXACT_RULES_JSON)
            wildcard_raw = values.get(RUNTIME_CONFIG_RATE_LIMIT_WILDCARD_RULES_JSON)
            refresh_raw = values.get(RUNTIME_CONFIG_RATE_LIMIT_RULES_REFRESH_SECONDS)

            if exact_raw is not None:
                parsed = self._parse_db_rules(exact_raw, wildcard=False)
                if parsed is not None:
                    exact_rules = parsed

            if wildcard_raw is not None:
                parsed = self._parse_db_rules(wildcard_raw, wildcard=True)
                if parsed is not None:
                    wildcard_rules = parsed

            if refresh_raw is not None:
                parsed_refresh = int(str(refresh_raw).strip())
                if parsed_refresh > 0:
                    refresh_seconds = parsed_refresh

            return exact_rules, wildcard_rules, refresh_seconds
        except Exception:
            logger.warning("rate_limiter_db_rules_read_failed")
            return None, None, None
        finally:
            db.close()

    def _refresh_rules_if_needed(self, force: bool = False) -> None:
        now = monotonic()
        if not force and (now - self._last_rules_refresh_monotonic) < self._rules_refresh_seconds:
            return

        with self._rules_lock:
            now = monotonic()
            if not force and (now - self._last_rules_refresh_monotonic) < self._rules_refresh_seconds:
                return

            exact_rules, wildcard_rules, refresh_seconds = self._read_db_rules()
            # Merge DB overrides over defaults so empty/custom JSON cannot wipe
            # security-critical prefixes (auth login, JIT action links, etc.).
            if exact_rules is not None:
                self._exact_rules = {**DEFAULT_UI_POLLING_RULES, **exact_rules}
            if wildcard_rules is not None:
                self._wildcard_rules = {**DEFAULT_WILDCARD_RULES, **wildcard_rules}
            if refresh_seconds is not None:
                self._rules_refresh_seconds = max(5, refresh_seconds)
            self._last_rules_refresh_monotonic = monotonic()

    def allow(self, actor_id: str, method: str, path: str) -> tuple[bool, int]:
        logger.trace(
            "rate_limiter_check %s",
            sanitize_fields({"actor_id": actor_id, "method": method, "path": path}),
        )
        self._refresh_rules_if_needed()
        self._try_recover_redis_backend()
        rule = self._resolve_rule(method, path)
        if rule is None:
            return True, 0

        if self._backend == "redis" and self._redis is not None:
            try:
                return self._allow_redis(actor_id=actor_id, method=method, path=path, rule=rule)
            except Exception:
                logger.warning(
                    "rate_limiter_redis_runtime_failed_fallback %s",
                    sanitize_fields({"actor_id": actor_id, "method": method, "path": path}),
                )
                self._backend = "memory"
                self._redis = None
                self._redis_last_error = "runtime_failure"
                self._next_redis_retry_monotonic = monotonic() + self._redis_retry_seconds

        return self._allow_memory(actor_id=actor_id, method=method, path=path, rule=rule)

    def _allow_memory(self, actor_id: str, method: str, path: str, rule: RateLimitRule) -> tuple[bool, int]:
        now = monotonic()
        key = (actor_id, method, path)
        bucket = self._buckets[key]

        threshold = now - rule.window_seconds
        while bucket and bucket[0] <= threshold:
            bucket.popleft()

        if not bucket:
            self._buckets.pop(key, None)
            bucket = self._buckets[key]

        if len(bucket) >= rule.max_requests:
            logger.info(
                "rate_limiter_blocked %s",
                sanitize_fields({"actor_id": actor_id, "method": method, "path": path}),
            )
            return False, rule.window_seconds

        bucket.append(now)
        return True, 0

    def _allow_redis(self, actor_id: str, method: str, path: str, rule: RateLimitRule) -> tuple[bool, int]:
        if self._redis is None:
            raise RuntimeError("Redis client is unavailable for redis backend mode.")
        now = self._wall_clock()
        threshold = now - float(rule.window_seconds)
        redis_key = f"{self._redis_prefix}:{self._stable_id(actor_id)}:{method}:{self._stable_id(path)}"

        pipe = self._redis.pipeline()
        pipe.zremrangebyscore(redis_key, 0, threshold)
        pipe.zcard(redis_key)
        responses = pipe.execute()
        current_count = int(responses[1]) if len(responses) > 1 else 0

        if current_count >= rule.max_requests:
            logger.info(
                "rate_limiter_blocked %s",
                sanitize_fields({"actor_id": actor_id, "method": method, "path": path}),
            )
            return False, rule.window_seconds

        member = f"{int(now * 1_000_000)}-{uuid4()}"
        pipe = self._redis.pipeline()
        pipe.zadd(redis_key, {member: now})
        pipe.expire(redis_key, rule.window_seconds + 1)
        pipe.execute()
        return True, 0
