from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _headers(role: str, actor_id: str, *, mfa: bool = False) -> dict[str, str]:
    headers = {
        "X-Actor-Role": role,
        "X-Actor-Id": actor_id,
    }
    if mfa:
        headers["X-MFA-Verified"] = "true"
    return headers


def _seed_tenant(tenant_id: str, admin_headers: dict[str, str]) -> None:
    response = client.post(
        "/providers/tenants",
        json={
            "tenant_id": tenant_id,
            "tenant_name": tenant_id.replace("-", " ").title(),
            "tenant_type": "enterprise",
            "description": f"Tenant {tenant_id}",
            "status": "active",
        },
        headers=admin_headers,
    )
    assert response.status_code in {200, 409}


def _seed_supported_model(provider_type: str, model_name: str, admin_headers: dict[str, str]) -> None:
    response = client.post(
        "/providers/models",
        json={
            "provider_type": provider_type,
            "model_name": model_name,
            "display_name": model_name.upper(),
            "context_window_tokens": 128000,
            "status": "active",
            "description": "entitlement test model",
        },
        headers=admin_headers,
    )
    assert response.status_code in {200, 409}


def test_tenant_model_entitlements_crud_and_supported_model_filtering():
    suffix = uuid4().hex[:8]
    tenant_id = f"tenant-ent-{suffix}"
    model_name = f"gpt-4o-mini-{suffix}"
    admin_headers = _headers("Platform Admin", f"admin-ent-{suffix}", mfa=True)
    auditor_headers = _headers("Auditor", f"auditor-ent-{suffix}")

    _seed_tenant(tenant_id, admin_headers)
    _seed_supported_model("openai", model_name, admin_headers)

    created = client.post(
        "/providers/tenant-model-entitlements",
        json={
            "tenant_id": tenant_id,
            "provider_type": "openai",
            "model_name": model_name,
            "status": "active",
        },
        headers=admin_headers,
    )
    assert created.status_code == 200
    entitlement_id = created.json()["tenant_model_entitlement_id"]

    listed = client.get(
        f"/providers/tenant-model-entitlements?tenant_id={tenant_id}&provider_type=openai&status=active",
        headers=auditor_headers,
    )
    assert listed.status_code == 200
    assert any(row["tenant_model_entitlement_id"] == entitlement_id for row in listed.json())

    tenant_scoped_models = client.get(
        f"/providers/models?tenant_id={tenant_id}&provider_type=openai&status=active",
        headers=auditor_headers,
    )
    assert tenant_scoped_models.status_code == 200
    tenant_models = tenant_scoped_models.json()
    assert any(row["model_name"] == model_name for row in tenant_models)

    updated = client.put(
        f"/providers/tenant-model-entitlements/{entitlement_id}",
        json={
            "tenant_id": tenant_id,
            "provider_type": "openai",
            "model_name": model_name,
            "status": "inactive",
        },
        headers=admin_headers,
    )
    assert updated.status_code == 200
    assert updated.json()["status"] == "inactive"

    tenant_scoped_after_disable = client.get(
        f"/providers/models?tenant_id={tenant_id}&provider_type=openai&status=active",
        headers=auditor_headers,
    )
    assert tenant_scoped_after_disable.status_code == 200
    assert all(row["model_name"] != model_name for row in tenant_scoped_after_disable.json())

    deleted = client.delete(
        f"/providers/tenant-model-entitlements/{entitlement_id}",
        headers=admin_headers,
    )
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True


def test_tenant_model_entitlements_write_requires_admin_and_mfa():
    suffix = uuid4().hex[:8]
    tenant_id = f"tenant-ent-authz-{suffix}"
    model_name = f"gpt-4o-mini-authz-{suffix}"
    admin_headers = _headers("Platform Admin", f"admin-ent-authz-{suffix}", mfa=True)

    _seed_tenant(tenant_id, admin_headers)
    _seed_supported_model("openai", model_name, admin_headers)

    forbidden = client.post(
        "/providers/tenant-model-entitlements",
        json={
            "tenant_id": tenant_id,
            "provider_type": "openai",
            "model_name": model_name,
            "status": "active",
        },
        headers=_headers("Auditor", f"auditor-ent-authz-{suffix}"),
    )
    assert forbidden.status_code == 403

    mfa_required = client.post(
        "/providers/tenant-model-entitlements",
        json={
            "tenant_id": tenant_id,
            "provider_type": "openai",
            "model_name": model_name,
            "status": "active",
        },
        headers=_headers("Platform Admin", f"admin-ent-authz-no-mfa-{suffix}"),
    )
    assert mfa_required.status_code == 403
    assert mfa_required.json()["detail"]["error_code"] == "AUTHZ_MFA_REQUIRED"
