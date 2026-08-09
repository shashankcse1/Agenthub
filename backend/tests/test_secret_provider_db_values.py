import json

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database import engine
from app.main import app
from app.models import RuntimeConfig, SecretProviderStoredValue

client = TestClient(app)


def _ensure_tenant(tenant_id: str, actor_id: str) -> None:
    response = client.post(
        "/providers/tenants",
        json={
            "tenant_id": tenant_id,
            "tenant_name": tenant_id,
            "tenant_type": "internal",
            "description": "db secret provider test tenant",
            "status": "active",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id, "X-MFA-Verified": "true"},
    )
    assert response.status_code in {200, 409}


def test_db_secret_provider_store_value_and_gateway_binding_resolve():
    tenant_id = "tenant-db-secret-provider"
    _ensure_tenant(tenant_id, "admin-db-secret-provider")

    created = client.post(
        "/secrets/providers",
        json={
            "tenant_id": tenant_id,
            "provider_type": "db",
            "provider_address": "platform://database",
            "auth_method": "encrypted-at-rest",
            "role_or_mount": "platform",
            "secret_path_prefixes": '["gateway/"]',
            "lease_ttl_seconds": 3600,
            "auto_renew_enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-db-secret-provider", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    provider_id = created.json()["secret_provider_id"]

    stored = client.put(
        f"/secrets/providers/{provider_id}/values",
        json={"secret_ref": "gateway/cursor-token", "secret_value": "cursor-db-secret-token-abcdef"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-db-secret-value", "X-MFA-Verified": "true"},
    )
    assert stored.status_code == 200
    assert stored.json()["configured"] is True
    assert "cursor-db-secret-token-abcdef" not in str(stored.json())

    status = client.get(
        f"/secrets/providers/{provider_id}/values/gateway/cursor-token",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-db-secret-provider"},
    )
    assert status.status_code == 200
    assert status.json()["configured"] is True

    bound = client.put(
        "/gateway/cursor-secret-binding",
        json={"secret_provider_id": provider_id, "secret_ref": "gateway/cursor-token"},
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-db-secret-binding",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-db-secret-binding",
        },
    )
    assert bound.status_code == 200
    assert bound.json()["configured"] is True
    assert bound.json()["provider_type"] == "db"

    with Session(engine) as db:
        row = db.query(RuntimeConfig).filter_by(config_key="gateway.cursor_api_token").first()
        assert row is not None
        payload = json.loads(row.config_value)
        assert payload["version"] == "v3"
        assert payload["secret_provider_id"] == provider_id
        assert payload["secret_ref"] == "gateway/cursor-token"

        stored_row = (
            db.query(SecretProviderStoredValue)
            .filter_by(secret_provider_id=provider_id, secret_ref="gateway/cursor-token")
            .first()
        )
        assert stored_row is not None
        assert "cursor-db-secret-token-abcdef" not in stored_row.value_encrypted


def test_deprecated_cursor_token_put_migrates_to_v3_binding():
    tenant_id = "tenant-db-secret-legacy"
    _ensure_tenant(tenant_id, "admin-db-secret-legacy")

    updated = client.put(
        "/gateway/cursor-token",
        json={"storage_mode": "db", "token": "cursor-legacy-token-zzzzzz"},
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-cursor-legacy",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-cursor-legacy",
        },
    )
    assert updated.status_code == 200
    assert updated.json()["configured"] is True
    assert updated.headers.get("deprecation") == "true"

    with Session(engine) as db:
        row = db.query(RuntimeConfig).filter_by(config_key="gateway.cursor_api_token").first()
        assert row is not None
        payload = json.loads(row.config_value)
        assert payload["version"] == "v3"
        assert payload["secret_provider_id"]
        assert payload["secret_ref"] == "gateway/cursor-token"


def test_secret_provider_value_role_and_mfa_enforcement():
    tenant_id = "tenant-db-secret-rbac"
    _ensure_tenant(tenant_id, "admin-db-secret-rbac")

    created = client.post(
        "/secrets/providers",
        json={
            "tenant_id": tenant_id,
            "provider_type": "db",
            "provider_address": "platform://database",
            "auth_method": "encrypted-at-rest",
            "role_or_mount": "platform",
            "secret_path_prefixes": '["gateway/"]',
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-db-secret-rbac", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    provider_id = created.json()["secret_provider_id"]

    denied = client.put(
        f"/secrets/providers/{provider_id}/values",
        json={"secret_ref": "gateway/cursor-token", "secret_value": "denied-token-value"},
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-db-secret-rbac"},
    )
    assert denied.status_code == 403

    missing_mfa = client.put(
        f"/secrets/providers/{provider_id}/values",
        json={"secret_ref": "gateway/cursor-token", "secret_value": "missing-mfa-token"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-db-secret-rbac-no-mfa"},
    )
    assert missing_mfa.status_code == 403


def test_secret_provider_value_path_prefix_denied():
    tenant_id = "tenant-db-secret-prefix"
    _ensure_tenant(tenant_id, "admin-db-secret-prefix")

    created = client.post(
        "/secrets/providers",
        json={
            "tenant_id": tenant_id,
            "provider_type": "db",
            "provider_address": "platform://database",
            "auth_method": "encrypted-at-rest",
            "role_or_mount": "platform",
            "secret_path_prefixes": '["gateway/"]',
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-db-secret-prefix", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    provider_id = created.json()["secret_provider_id"]

    denied = client.put(
        f"/secrets/providers/{provider_id}/values",
        json={"secret_ref": "other/secret-path", "secret_value": "prefix-denied-token"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-db-secret-prefix", "X-MFA-Verified": "true"},
    )
    assert denied.status_code == 403


def test_gateway_cursor_secret_binding_role_and_audit():
    tenant_id = "tenant-db-secret-binding-rbac"
    _ensure_tenant(tenant_id, "admin-db-secret-binding-rbac")

    created = client.post(
        "/secrets/providers",
        json={
            "tenant_id": tenant_id,
            "provider_type": "db",
            "provider_address": "platform://database",
            "auth_method": "encrypted-at-rest",
            "role_or_mount": "platform",
            "secret_path_prefixes": '["gateway/"]',
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-db-secret-binding-rbac",
            "X-MFA-Verified": "true",
        },
    )
    assert created.status_code == 200
    provider_id = created.json()["secret_provider_id"]

    denied = client.put(
        "/gateway/cursor-secret-binding",
        json={"secret_provider_id": provider_id, "secret_ref": "gateway/cursor-token"},
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-db-secret-binding-rbac"},
    )
    assert denied.status_code == 403

    bound = client.put(
        "/gateway/cursor-secret-binding",
        json={"secret_provider_id": provider_id, "secret_ref": "gateway/cursor-token"},
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-db-secret-binding-rbac-save",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-db-secret-binding-rbac-save",
        },
    )
    assert bound.status_code == 200
    body = str(bound.json())
    assert "sk-" not in body

    audits = client.get(
        "/audit/events?action_type=gateway.cursor_secret_binding.update&resource_type=runtime_config&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-db-secret-binding-rbac-audit"},
    )
    assert audits.status_code == 200
    assert any(row["actor_id"] == "admin-db-secret-binding-rbac-save" for row in audits.json())
