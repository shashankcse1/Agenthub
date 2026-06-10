import jwt
import secrets
from fastapi.testclient import TestClient
import pytest

from agent_platform.api.app import app

client = TestClient(app)

VALID_PAYLOAD = {
    "trace_id": "trace-export-1",
    "actor_id": "user@example.com",
    "actor_role": "Platform Admin",
    "tenant_id": "tenant-a",
    "environment": "dev",
    "action": "navigate",
    "target": "https://example.com/account/12345",
}


def test_evidence_export_forbidden_for_basic_auditor_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("APP_ENV", "prod")
    monkeypatch.setenv("ALLOW_BASIC_AUTH", "false")
    monkeypatch.setenv("JWT_SIGNING_SECRET", "strong-prod-secret-32-bytes-minimum!!")
    monkeypatch.setenv("BASIC_AUTH_AUDITOR_PASSWORD", secrets.token_urlsafe(24))
    disabled_attempt_password = secrets.token_urlsafe(24)
    response = client.post("/api/v1/evidence/export", auth=("auditor", disabled_attempt_password))
    assert response.status_code == 403


def test_evidence_export_returns_signed_pii_safe_bundle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JWT_SIGNING_SECRET", "strong-test-secret-32-bytes-minimum!")
    preview_token = jwt.encode(
        {"sub": "platform-admin", "role": "Platform Admin"},
        "strong-test-secret-32-bytes-minimum!",
        algorithm="HS256",
    )
    export_token = jwt.encode(
        {"sub": "auditor-user", "role": "Auditor"},
        "strong-test-secret-32-bytes-minimum!",
        algorithm="HS256",
    )

    preview_response = client.post(
        "/api/v1/policy/preview",
        json=VALID_PAYLOAD,
        headers={"Authorization": f"Bearer {preview_token}"},
    )
    assert preview_response.status_code == 200

    export_response = client.post(
        "/api/v1/evidence/export",
        headers={"Authorization": f"Bearer {export_token}"},
    )
    assert export_response.status_code == 200
    payload = export_response.json()
    assert payload["exported_by"] == "auditor-user"
    assert payload["exporter_role"] == "Auditor"
    assert payload["event_count"] >= 1
    assert payload["signature_algorithm"] == "HMAC-SHA256"
    assert payload["chain_head"]
    assert payload["signature"]
    event = payload["events"][-1]
    assert event["prev_event_hash"]
    assert event["event_hash"]
    assert event["event_type"] == "policy.preview"
    assert event["pii_redaction"] == "enabled"
    assert event["target_scope"] == "example.com"
    assert event["actor_fingerprint"]
    assert event["target_fingerprint"]
    assert event["decision_description"].startswith("Policy preview allow decision")
    assert "user@example.com" not in str(event)
    assert "https://example.com/account/12345" not in str(event)


def test_evidence_verify_endpoint_accepts_valid_bundle(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JWT_SIGNING_SECRET", "verify-test-secret-32-bytes-minimum!!")
    preview_token = jwt.encode(
        {"sub": "platform-admin", "role": "Platform Admin"},
        "verify-test-secret-32-bytes-minimum!!",
        algorithm="HS256",
    )
    auditor_token = jwt.encode(
        {"sub": "auditor-user", "role": "Auditor"},
        "verify-test-secret-32-bytes-minimum!!",
        algorithm="HS256",
    )

    client.post(
        "/api/v1/policy/preview",
        json=VALID_PAYLOAD,
        headers={"Authorization": f"Bearer {preview_token}"},
    )
    export_response = client.post(
        "/api/v1/evidence/export",
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    bundle = export_response.json()

    verify_response = client.post(
        "/api/v1/evidence/verify",
        json=bundle,
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert verify_response.status_code == 200
    assert verify_response.json()["valid"] is True


def test_evidence_verify_endpoint_rejects_tampered_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JWT_SIGNING_SECRET", "verify-test-secret-32-bytes-minimum!!")
    preview_token = jwt.encode(
        {"sub": "platform-admin", "role": "Platform Admin"},
        "verify-test-secret-32-bytes-minimum!!",
        algorithm="HS256",
    )
    auditor_token = jwt.encode(
        {"sub": "auditor-user", "role": "Auditor"},
        "verify-test-secret-32-bytes-minimum!!",
        algorithm="HS256",
    )

    client.post(
        "/api/v1/policy/preview",
        json=VALID_PAYLOAD,
        headers={"Authorization": f"Bearer {preview_token}"},
    )
    export_response = client.post(
        "/api/v1/evidence/export",
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    bundle = export_response.json()
    bundle["signature"] = "tampered-signature"

    verify_response = client.post(
        "/api/v1/evidence/verify",
        json=bundle,
        headers={"Authorization": f"Bearer {auditor_token}"},
    )
    assert verify_response.status_code == 200
    assert verify_response.json()["valid"] is False
