import json
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database import engine
from app.main import app
from app.models import RuntimeConfig

client = TestClient(app)


def _ensure_tenant(tenant_id: str, actor_id: str) -> None:
    response = client.post(
        "/providers/tenants",
        json={
            "tenant_id": tenant_id,
            "tenant_name": tenant_id,
            "tenant_type": "internal",
            "description": "credential binding test tenant",
            "status": "active",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id, "X-MFA-Verified": "true"},
    )
    assert response.status_code in {200, 409}


def test_provider_credential_binding_secret_ref_and_gateway_sync():
    tenant_id = f"tenant-credential-binding-{uuid4().hex[:8]}"
    _ensure_tenant(tenant_id, "admin-credential-binding")

    provider_created = client.post(
        "/secrets/providers",
        json={
            "tenant_id": tenant_id,
            "provider_type": "db",
            "provider_address": "platform://database",
            "auth_method": "encrypted-at-rest",
            "role_or_mount": "platform",
            "secret_path_prefixes": '["gateway/","providers/"]',
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-credential-binding", "X-MFA-Verified": "true"},
    )
    assert provider_created.status_code == 200
    provider_id = provider_created.json()["secret_provider_id"]

    stored = client.put(
        f"/secrets/providers/{provider_id}/values",
        json={"secret_ref": "gateway/cursor-token", "secret_value": "cursor-binding-sync-token"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-credential-binding", "X-MFA-Verified": "true"},
    )
    assert stored.status_code == 200

    created = client.post(
        "/providers/credential-bindings",
        json={
            "tenant_id": tenant_id,
            "binding_name": "Gateway Cursor",
            "consumer_type": "gateway",
            "consumer_key": "cursor",
            "provider_type": "cursor",
            "credential_plane": "secret_ref",
            "secret_provider_id": provider_id,
            "secret_ref": "gateway/cursor-token",
            "environment": "dev",
            "status": "active",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-credential-binding", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    body = created.json()
    assert body["configured"] is True
    assert body["credential_plane"] == "secret_ref"
    assert "cursor-binding-sync-token" not in str(body)

    with Session(engine) as db:
        runtime = db.query(RuntimeConfig).filter_by(config_key="gateway.cursor_api_token").first()
        assert runtime is not None
        payload = json.loads(runtime.config_value)
        assert payload["version"] == "v3"
        assert payload["secret_provider_id"] == provider_id


def test_provider_credential_binding_role_and_list():
    tenant_id = "tenant-credential-binding-rbac"
    _ensure_tenant(tenant_id, "admin-credential-binding-rbac")

    denied = client.post(
        "/providers/credential-bindings",
        json={
            "tenant_id": tenant_id,
            "binding_name": "Denied",
            "consumer_type": "platform",
            "consumer_key": "default",
            "provider_type": "openai",
            "credential_plane": "workload_identity",
            "workload_identity_profile_id": "missing-profile",
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-credential-binding"},
    )
    assert denied.status_code == 403

    listed = client.get(
        f"/providers/credential-bindings?tenant_id={tenant_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-credential-binding-list"},
    )
    assert listed.status_code == 200
    assert isinstance(listed.json(), list)


def test_provider_credential_binding_super_admin_actor():
    tenant_id = f"tenant-credential-super-admin-{uuid4().hex[:8]}"
    _ensure_tenant(tenant_id, "super-admin-binding")

    provider_created = client.post(
        "/secrets/providers",
        json={
            "tenant_id": tenant_id,
            "provider_type": "db",
            "provider_address": "platform://database",
            "auth_method": "encrypted-at-rest",
            "role_or_mount": "platform",
            "secret_path_prefixes": '["gateway/"]',
        },
        headers={"X-Actor-Role": "Super Admin", "X-Actor-Id": "super-admin-binding", "X-MFA-Verified": "true"},
    )
    assert provider_created.status_code == 200
    provider_id = provider_created.json()["secret_provider_id"]

    stored = client.put(
        f"/secrets/providers/{provider_id}/values",
        json={"secret_ref": "gateway/cursor-token", "secret_value": "super-admin-token"},
        headers={"X-Actor-Role": "Super Admin", "X-Actor-Id": "super-admin-binding", "X-MFA-Verified": "true"},
    )
    assert stored.status_code == 200

    created = client.post(
        "/providers/credential-bindings",
        json={
            "tenant_id": tenant_id,
            "binding_name": "Super Admin Gateway Cursor",
            "consumer_type": "gateway",
            "consumer_key": "cursor",
            "provider_type": "cursor",
            "credential_plane": "secret_ref",
            "secret_provider_id": provider_id,
            "secret_ref": "gateway/cursor-token",
            "environment": "dev",
            "status": "active",
        },
        headers={"X-Actor-Role": "Super Admin", "X-Actor-Id": "super-admin-binding", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    assert created.json()["configured"] is True


def test_supported_model_credential_source_class():
    model_name = f"gpt-test-credential-class-{uuid4().hex[:8]}"
    created = client.post(
        "/providers/models",
        json={
            "provider_type": "openai",
            "model_name": model_name,
            "display_name": "GPT Test Credential Class",
            "credential_source_class": "cp_ref",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-model-credential-class", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    assert created.json()["credential_source_class"] == "cp_ref"
