import importlib

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _reload_main(monkeypatch: pytest.MonkeyPatch, **env: str):
    keys = ["APP_ENV", "ENVIRONMENT", "CORS_ALLOW_ORIGINS"]
    for key in keys:
        if key in env:
            monkeypatch.setenv(key, env[key])
        else:
            monkeypatch.delenv(key, raising=False)

    import app.main as main_module

    return importlib.reload(main_module)


@pytest.fixture(autouse=True)
def _reset_main_after_test(monkeypatch: pytest.MonkeyPatch):
    yield
    for key in ["APP_ENV", "ENVIRONMENT", "CORS_ALLOW_ORIGINS"]:
        monkeypatch.delenv(key, raising=False)
    import app.main as main_module

    importlib.reload(main_module)


def test_health_response_includes_transport_security_headers():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("Referrer-Policy") == "no-referrer"
    assert response.headers.get("Permissions-Policy") == "camera=(), microphone=(), geolocation=()"
    assert response.headers.get("Strict-Transport-Security") == "max-age=63072000; includeSubDomains; preload"


def test_cors_preflight_allows_browser_put_for_supported_model_updates(monkeypatch: pytest.MonkeyPatch):
    main_module = _reload_main(
        monkeypatch,
        APP_ENV="local",
        CORS_ALLOW_ORIGINS="http://127.0.0.1:4173",
    )
    client = TestClient(main_module.app)

    response = client.options(
        "/providers/models/example-id",
        headers={
            "Origin": "http://127.0.0.1:4173",
            "Access-Control-Request-Method": "PUT",
            "Access-Control-Request-Headers": "content-type,x-actor-id,x-actor-role,x-mfa-verified",
        },
    )

    assert response.status_code == 200
    assert response.headers.get("Access-Control-Allow-Origin") == "http://127.0.0.1:4173"
    allow_methods = response.headers.get("Access-Control-Allow-Methods") or ""
    assert "PUT" in allow_methods
