from app.services.rate_limit import RateLimitRule, SlidingWindowRateLimiter


def test_rate_limit_exact_rule_blocks_after_threshold():
    limiter = SlidingWindowRateLimiter()

    # /auth/sessions has max_requests=20 in 60s.
    for _ in range(20):
        allowed, retry_after = limiter.allow(actor_id="actor-a", method="POST", path="/auth/sessions")
        assert allowed is True
        assert retry_after == 0

    allowed, retry_after = limiter.allow(actor_id="actor-a", method="POST", path="/auth/sessions")
    assert allowed is False
    assert retry_after == 60


def test_rate_limit_wildcard_rule_blocks_parameterized_path():
    limiter = SlidingWindowRateLimiter()

    # /auth/basic/config/{id}/enable-temporary is matched by /auth/basic/config/ prefix rule (10/300s).
    path = "/auth/basic/config/cfg-123/enable-temporary"
    for _ in range(10):
        allowed, retry_after = limiter.allow(actor_id="actor-b", method="POST", path=path)
        assert allowed is True
        assert retry_after == 0

    allowed, retry_after = limiter.allow(actor_id="actor-b", method="POST", path=path)
    assert allowed is False
    assert retry_after == 300


def test_rate_limit_scopes_by_actor_identity():
    limiter = SlidingWindowRateLimiter()

    # Exhaust limit for actor-a only.
    path = "/auth/workload-identity/token-exchange"
    for _ in range(20):
        allowed, _ = limiter.allow(actor_id="actor-a", method="POST", path=path)
        assert allowed is True

    blocked, retry_after = limiter.allow(actor_id="actor-a", method="POST", path=path)
    assert blocked is False
    assert retry_after == 60

    # Different actor should still be allowed.
    allowed_other, retry_after_other = limiter.allow(actor_id="actor-other", method="POST", path=path)
    assert allowed_other is True
    assert retry_after_other == 0


def test_rate_limit_ignores_unconfigured_paths():
    limiter = SlidingWindowRateLimiter()

    for _ in range(200):
        allowed, retry_after = limiter.allow(actor_id="actor-c", method="GET", path="/health")
        assert allowed is True
        assert retry_after == 0


def test_rate_limit_db_refresh_can_override_exact_rules(monkeypatch):
    limiter = SlidingWindowRateLimiter()

    def _fake_read_db_rules():
        return {("GET", "/health"): RateLimitRule(max_requests=1, window_seconds=60)}, {}, 30

    monkeypatch.setattr(limiter, "_read_db_rules", _fake_read_db_rules)
    limiter._refresh_rules_if_needed(force=True)

    first_allowed, first_retry = limiter.allow(actor_id="actor-db", method="GET", path="/health")
    assert first_allowed is True
    assert first_retry == 0

    blocked, retry_after = limiter.allow(actor_id="actor-db", method="GET", path="/health")
    assert blocked is False
    assert retry_after == 60


def test_rate_limit_db_refresh_can_override_wildcard_rules(monkeypatch):
    limiter = SlidingWindowRateLimiter()

    def _fake_read_db_rules():
        return {}, {("POST", "/custom/"): RateLimitRule(max_requests=1, window_seconds=120)}, 30

    monkeypatch.setattr(limiter, "_read_db_rules", _fake_read_db_rules)
    limiter._refresh_rules_if_needed(force=True)

    first_allowed, _ = limiter.allow(actor_id="actor-db-wild", method="POST", path="/custom/a")
    assert first_allowed is True

    blocked, retry_after = limiter.allow(actor_id="actor-db-wild", method="POST", path="/custom/a")
    assert blocked is False
    assert retry_after == 120
