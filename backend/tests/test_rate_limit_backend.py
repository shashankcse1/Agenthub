from app.services.rate_limit import SlidingWindowRateLimiter


class _FakeRedisPipeline:
    def __init__(self, store: dict[str, list[float]]):
        self._store = store
        self._ops: list[tuple[str, tuple]] = []

    def zremrangebyscore(self, key: str, min_score: float, max_score: float):
        self._ops.append(("zremrangebyscore", (key, float(min_score), float(max_score))))
        return self

    def zcard(self, key: str):
        self._ops.append(("zcard", (key,)))
        return self

    def zadd(self, key: str, mapping: dict[str, float]):
        self._ops.append(("zadd", (key, mapping)))
        return self

    def expire(self, key: str, ttl: int):
        self._ops.append(("expire", (key, ttl)))
        return self

    def execute(self):
        responses: list[int] = []
        for op_name, args in self._ops:
            if op_name == "zremrangebyscore":
                key, _min_score, max_score = args
                values = self._store.get(key, [])
                filtered = [v for v in values if v > max_score]
                removed = len(values) - len(filtered)
                self._store[key] = filtered
                responses.append(removed)
            elif op_name == "zcard":
                (key,) = args
                responses.append(len(self._store.get(key, [])))
            elif op_name == "zadd":
                key, mapping = args
                values = self._store.setdefault(key, [])
                for score in mapping.values():
                    values.append(float(score))
                responses.append(len(mapping))
            elif op_name == "expire":
                responses.append(1)
        self._ops = []
        return responses


class _FakeRedisClient:
    def __init__(self):
        self._store: dict[str, list[float]] = {}

    def pipeline(self):
        return _FakeRedisPipeline(self._store)


def test_rate_limiter_uses_redis_backend_when_configured():
    fake_redis = _FakeRedisClient()
    limiter = SlidingWindowRateLimiter(backend="redis", redis_client=fake_redis, now_fn=lambda: 100.0)

    for _ in range(20):
        allowed, retry_after = limiter.allow(actor_id="actor-r", method="POST", path="/auth/sessions")
        assert allowed is True
        assert retry_after == 0

    blocked, retry_after = limiter.allow(actor_id="actor-r", method="POST", path="/auth/sessions")
    assert blocked is False
    assert retry_after == 60
    assert limiter.backend_mode == "redis"


class _FailingRedisClient:
    def pipeline(self):
        raise RuntimeError("redis unavailable")


def test_rate_limiter_falls_back_to_memory_when_redis_runtime_fails():
    limiter = SlidingWindowRateLimiter(backend="redis", redis_client=_FailingRedisClient())

    assert limiter.backend_mode == "redis"

    first_allowed, _ = limiter.allow(actor_id="actor-fallback", method="POST", path="/auth/sessions")
    assert first_allowed is True
    assert limiter.backend_mode == "memory"


def test_rate_limiter_degraded_status_and_recovery_telemetry():
    limiter = SlidingWindowRateLimiter(backend="redis", redis_client=_FailingRedisClient(), now_fn=lambda: 100.0)

    first_allowed, _ = limiter.allow(actor_id="actor-recovery", method="POST", path="/auth/sessions")
    assert first_allowed is True
    degraded = limiter.runtime_status()
    assert degraded["degraded"] is True
    assert degraded["active_backend"] == "memory"

    def _recover_client() -> bool:
        limiter._redis = _FakeRedisClient()  # type: ignore[attr-defined]
        return True

    limiter._try_initialize_redis_client = _recover_client  # type: ignore[method-assign]
    limiter._next_redis_retry_monotonic = 0.0  # type: ignore[attr-defined]

    second_allowed, _ = limiter.allow(actor_id="actor-recovery", method="POST", path="/auth/sessions")
    assert second_allowed is True
    recovered = limiter.runtime_status()
    assert recovered["degraded"] is False
    assert recovered["active_backend"] == "redis"
    assert recovered["redis_recovery_attempts"] >= 1
    assert recovered["redis_recovery_successes"] >= 1
