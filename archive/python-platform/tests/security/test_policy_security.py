import jwt
import secrets
from fastapi.testclient import TestClient
import pytest

from agent_platform.api.app import app

client = TestClient(app)


VALID_PAYLOAD = {
    "trace_id": "trace-123",
    "actor_id": "actor-1",
    "actor_role": "Platform Admin",
    "tenant_id": "tenant-a",
    "environment": "dev",
    "action": "navigate",
    "target": "https://example.com",
}


def test_policy_preview_requires_authentication() -> None:
    response = client.post("/api/v1/policy/preview", json=VALID_PAYLOAD)
    assert response.status_code == 401


def test_policy_preview_forbidden_for_auditor() -> None:
    auditor_password = secrets.token_urlsafe(24)
    response = client.post(
        "/api/v1/policy/preview",
        json=VALID_PAYLOAD,
        auth=("auditor", auditor_password),
    )
    assert response.status_code == 503


def test_policy_preview_forbidden_for_auditor_with_configured_basic_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    auditor_password = secrets.token_urlsafe(24)
    monkeypatch.setenv("BASIC_AUTH_AUDITOR_PASSWORD", auditor_password)
    response = client.post(
        "/api/v1/policy/preview",
        json=VALID_PAYLOAD,
        auth=("auditor", auditor_password),
    )
    assert response.status_code == 403


def test_policy_preview_allows_platform_admin() -> None:
    admin_password = secrets.token_urlsafe(24)
    response = client.post(
        "/api/v1/policy/preview",
        json=VALID_PAYLOAD,
        auth=("platform-admin", admin_password),
    )
    assert response.status_code == 503


def test_policy_preview_allows_platform_admin_with_configured_basic_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    admin_password = secrets.token_urlsafe(24)
    monkeypatch.setenv("BASIC_AUTH_PLATFORM_ADMIN_PASSWORD", admin_password)
    response = client.post(
        "/api/v1/policy/preview",
        json=VALID_PAYLOAD,
        auth=("platform-admin", admin_password),
    )
    assert response.status_code == 200
    assert response.json()["outcome"] in {"ALLOW", "WARN", "CHALLENGE", "DENY"}


def test_policy_preview_allows_valid_bearer_token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JWT_SIGNING_SECRET", "test-secret-with-32-bytes-minimum!!")
    token = jwt.encode(
        {"sub": "platform-admin", "role": "Platform Admin"},
        "test-secret-with-32-bytes-minimum!!",
        algorithm="HS256",
    )
    response = client.post(
        "/api/v1/policy/preview",
        json=VALID_PAYLOAD,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200


def test_policy_preview_rejects_bearer_without_role_claim(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JWT_SIGNING_SECRET", "test-secret-with-32-bytes-minimum!!")
    token = jwt.encode(
        {"sub": "platform-admin"},
        "test-secret-with-32-bytes-minimum!!",
        algorithm="HS256",
    )
    response = client.post(
        "/api/v1/policy/preview",
        json=VALID_PAYLOAD,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 401


def test_policy_preview_rejects_basic_auth_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ALLOW_BASIC_AUTH", "false")
    monkeypatch.setenv("JWT_SIGNING_SECRET", "strong-prod-secret")
    monkeypatch.setenv("BASIC_AUTH_PLATFORM_ADMIN_PASSWORD", secrets.token_urlsafe(24))
    disabled_attempt_password = secrets.token_urlsafe(24)
    response = client.post(
        "/api/v1/policy/preview",
        json=VALID_PAYLOAD,
        auth=("platform-admin", disabled_attempt_password),
    )
    assert response.status_code == 403
