from __future__ import annotations

import os
from threading import Lock
from time import monotonic, time

from app.logging_utils import get_logger, sanitize_fields

logger = get_logger(__name__)


class RuntimeConfigCache:
    def __init__(
        self,
        backend: str | None = None,
        redis_url: str | None = None,
        redis_prefix: str | None = None,
        ttl_seconds: int | None = None,
        redis_client: object | None = None,
    ) -> None:
        self._backend = (backend or os.getenv("RUNTIME_CONFIG_CACHE_BACKEND") or "memory").strip().lower()
        self._configured_backend = self._backend
        self._redis_url = (
            redis_url
            or os.getenv("RUNTIME_CONFIG_CACHE_REDIS_URL")
            or os.getenv("RATE_LIMIT_REDIS_URL")
            or "redis://localhost:6379/0"
        ).strip()
        self._redis_prefix = (redis_prefix or os.getenv("RUNTIME_CONFIG_CACHE_REDIS_PREFIX") or "runtime-config").strip()
        self._ttl_seconds = max(5, _safe_positive_int(ttl_seconds, os.getenv("RUNTIME_CONFIG_CACHE_TTL_SECONDS"), 30))
        self._redis = redis_client
        self._redis_retry_seconds = _safe_positive_int(None, os.getenv("RUNTIME_CONFIG_CACHE_REDIS_RETRY_SECONDS"), 30)
        self._next_redis_retry_monotonic = 0.0
        self._redis_recovery_attempts = 0
        self._redis_recovery_successes = 0
        self._redis_last_recovery_unix = 0.0
        self._redis_last_error = ""
        self._last_touch_unix: float = 0.0
        self._memory: dict[str, tuple[str, float]] = {}
        self._memory_lock = Lock()

        if self._backend not in {"memory", "redis"}:
            logger.warning(
                "runtime_config_cache_invalid_backend_fallback %s",
                sanitize_fields({"configured_backend": self._backend}),
            )
            self._backend = "memory"

        if self._backend == "redis" and self._redis is None and not self._try_initialize_redis_client():
            self._backend = "memory"

    @property
    def configured_backend(self) -> str:
        return self._configured_backend

    @property
    def backend_mode(self) -> str:
        return self._backend

    @property
    def ttl_seconds(self) -> int:
        return self._ttl_seconds

    def runtime_status(self) -> dict[str, object]:
        degraded = self._configured_backend == "redis" and self._backend != "redis"
        return {
            "status": "degraded" if degraded else "ok",
            "configured_backend": self._configured_backend,
            "active_backend": self._backend,
            "ttl_seconds": self._ttl_seconds,
            "last_refresh": self._last_touch_unix or None,
            "degraded": degraded,
            "redis_retry_seconds": self._redis_retry_seconds,
            "redis_recovery_attempts": self._redis_recovery_attempts,
            "redis_recovery_successes": self._redis_recovery_successes,
            "redis_last_recovery_unix": self._redis_last_recovery_unix,
            "redis_last_error": self._redis_last_error,
        }

    def _touch(self) -> None:
        self._last_touch_unix = time()

    def _try_initialize_redis_client(self) -> bool:
        if self._redis is not None:
            return True
        try:
            import redis  # type: ignore

            self._redis = redis.from_url(self._redis_url, decode_responses=True)
            self._redis_last_error = ""
            return True
        except Exception as exc:
            logger.warning(
                "runtime_config_cache_redis_init_failed_fallback %s",
                sanitize_fields({"redis_url": self._redis_url}),
            )
            self._redis_last_error = type(exc).__name__
            self._redis = None
            return False

    def _degrade_to_memory(self, error_name: str) -> None:
        self._backend = "memory"
        self._redis = None
        self._redis_last_error = error_name
        self._next_redis_retry_monotonic = monotonic() + float(self._redis_retry_seconds)

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
            self._redis_last_recovery_unix = time()
            logger.info("runtime_config_cache_redis_recovered")
            return
        self._next_redis_retry_monotonic = now + float(self._redis_retry_seconds)

    def _redis_key(self, key: str) -> str:
        return f"{self._redis_prefix}:{key}"

    def get(self, key: str) -> str | None:
        self._try_recover_redis_backend()
        if self._backend == "redis":
            try:
                if self._redis is None:
                    raise RuntimeError("runtime config cache redis client unavailable")
                value = self._redis.get(self._redis_key(key))
                if value is None:
                    return None
                self._touch()
                return str(value)
            except Exception:
                logger.warning(
                    "runtime_config_cache_redis_get_failed_fallback %s",
                    sanitize_fields({"key": key}),
                )
                self._degrade_to_memory("redis_get_failure")

        now = monotonic()
        with self._memory_lock:
            entry = self._memory.get(key)
            if entry is None:
                return None
            value, expires_at = entry
            if expires_at <= now:
                self._memory.pop(key, None)
                return None
            self._touch()
            return value

    def set(self, key: str, value: str) -> None:
        self._try_recover_redis_backend()
        if self._backend == "redis":
            try:
                if self._redis is None:
                    raise RuntimeError("runtime config cache redis client unavailable")
                self._redis.setex(self._redis_key(key), self._ttl_seconds, value)
                self._touch()
                return
            except Exception:
                logger.warning(
                    "runtime_config_cache_redis_set_failed_fallback %s",
                    sanitize_fields({"key": key}),
                )
                self._degrade_to_memory("redis_set_failure")

        expires_at = monotonic() + float(self._ttl_seconds)
        with self._memory_lock:
            self._memory[key] = (value, expires_at)
        self._touch()

    def delete(self, key: str) -> None:
        self._try_recover_redis_backend()
        if self._backend == "redis":
            try:
                if self._redis is None:
                    raise RuntimeError("runtime config cache redis client unavailable")
                self._redis.delete(self._redis_key(key))
                self._touch()
            except Exception:
                logger.warning(
                    "runtime_config_cache_redis_delete_failed_fallback %s",
                    sanitize_fields({"key": key}),
                )
                self._degrade_to_memory("redis_delete_failure")

        with self._memory_lock:
            self._memory.pop(key, None)
        self._touch()



def _safe_positive_int(explicit: int | None, raw: str | None, default: int) -> int:
    if explicit is not None:
        return max(1, int(explicit))
    try:
        parsed = int((raw or str(default)).strip())
    except Exception:
        return max(1, default)
    return max(1, parsed)


runtime_config_cache = RuntimeConfigCache()
