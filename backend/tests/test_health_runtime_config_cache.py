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
