from app.services.config_cache import RuntimeConfigCache


class _FakeRedis:
    def __init__(self):
        self.store: dict[str, str] = {}

    def get(self, key: str):
        return self.store.get(key)

    def setex(self, key: str, _ttl: int, value: str):
        self.store[key] = value

    def delete(self, key: str):
        self.store.pop(key, None)


class _FailingRedis:
    def get(self, _key: str):
        raise RuntimeError("redis unavailable")

    def setex(self, _key: str, _ttl: int, _value: str):
        raise RuntimeError("redis unavailable")

    def delete(self, _key: str):
        raise RuntimeError("redis unavailable")


def test_runtime_config_cache_falls_back_to_memory_when_redis_runtime_fails():
    cache = RuntimeConfigCache(backend="redis", redis_client=_FailingRedis())

    cache.set("feature.flag", "true")

    status = cache.runtime_status()
    assert status["configured_backend"] == "redis"
    assert status["active_backend"] == "memory"
    assert status["degraded"] is True


def test_runtime_config_cache_recovers_to_redis_after_degradation():
    cache = RuntimeConfigCache(backend="redis", redis_client=_FailingRedis())

    cache.set("feature.flag", "true")
    degraded = cache.runtime_status()
    assert degraded["active_backend"] == "memory"

    def _recover_client() -> bool:
        cache._redis = _FakeRedis()  # type: ignore[attr-defined]
        return True

    cache._try_initialize_redis_client = _recover_client  # type: ignore[method-assign]
    cache._next_redis_retry_monotonic = 0.0  # type: ignore[attr-defined]

    cache.set("feature.flag", "false")
    recovered = cache.runtime_status()
    assert recovered["active_backend"] == "redis"
    assert recovered["degraded"] is False
    assert recovered["redis_recovery_attempts"] >= 1
    assert recovered["redis_recovery_successes"] >= 1
