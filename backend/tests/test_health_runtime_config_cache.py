from app.services.config_cache import RuntimeConfigCache


def test_runtime_config_cache_runtime_status_includes_health_fields():
    cache = RuntimeConfigCache(backend="memory", ttl_seconds=45)
    status = cache.runtime_status()
    assert status["status"] == "ok"
    assert status["ttl_seconds"] == 45
    assert status["last_refresh"] is None
    assert status["active_backend"] == "memory"
    assert status["configured_backend"] == "memory"
    assert status["degraded"] is False


def test_runtime_config_cache_last_refresh_updates_on_touch():
    cache = RuntimeConfigCache(backend="memory", ttl_seconds=30)
    cache.set("health.probe.key", "value")
    status = cache.runtime_status()
    assert status["last_refresh"] is not None
    assert status["last_refresh"] > 0


def test_health_includes_runtime_config_cache_field():
    from fastapi.testclient import TestClient

    from app.main import app

    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    cache = payload["runtime_config_cache"]
    assert cache["status"] in {"ok", "degraded"}
    assert isinstance(cache["ttl_seconds"], int)
    assert cache["ttl_seconds"] >= 5
    assert "last_refresh" in cache
    assert "active_backend" in cache
    assert "configured_backend" in cache
    assert isinstance(cache["degraded"], bool)


def test_health_includes_mfa_optional_and_token_exposure_posture():
    from fastapi.testclient import TestClient

    from app.main import app
    from app.security import mfa_optional_posture, token_exposure_posture

    posture = mfa_optional_posture()
    assert "effective" in posture
    assert "fail_closed_outside_allowed" in posture
    assert isinstance(posture["allowed_environments"], list)

    token = token_exposure_posture()
    assert "effective" in token
    assert "raw_flag_set" in token

    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert "mfa_optional" in payload
    assert "token_exposure" in payload
    assert payload["mfa_optional"]["environment"]
    assert isinstance(payload["mfa_optional"]["effective"], bool)
    assert isinstance(payload["token_exposure"]["effective"], bool)
    assert "transport" in payload
    assert payload["transport"]["hsts_configured"] is True
    assert "exception_posture" in payload
    assert payload["exception_posture"]["auto_disable_supported"] is True
