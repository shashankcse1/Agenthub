from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import response_error_code, response_error_message

client = TestClient(app)


def _headers(role: str, actor_id: str, *, mfa: bool = False) -> dict[str, str]:
    headers = {
        "X-Actor-Role": role,
        "X-Actor-Id": actor_id,
    }
    if mfa:
        headers["X-MFA-Verified"] = "true"
    return headers


def test_tenant_catalog_crud_and_provider_list_enrichment():
    suffix = uuid4().hex[:8]
    tenant_id = f"tenant-{suffix}"
    admin_headers = _headers("Platform Admin", f"admin-tenant-{suffix}", mfa=True)
    auditor_headers = _headers("Auditor", f"auditor-tenant-{suffix}")

    created = client.post(
        "/providers/tenants",
        json={
            "tenant_id": tenant_id,
            "tenant_name": "Payments Platform",
            "tenant_type": "enterprise",
            "description": "Payments production tenant",
            "status": "active",
        },
        headers=admin_headers,
    )
    assert created.status_code == 200
    assert created.json()["tenant_name"] == "Payments Platform"

    listed = client.get(f"/providers/tenants?status=active&tenant_type=enterprise&limit=20", headers=auditor_headers)
    assert listed.status_code == 200
    rows = listed.json()
    assert any(row["tenant_id"] == tenant_id for row in rows)

    updated = client.put(
        f"/providers/tenants/{tenant_id}",
        json={
            "tenant_id": tenant_id,
            "tenant_name": "Payments Platform Updated",
            "tenant_type": "regulated",
            "description": "Payments production tenant with regulated controls",
            "status": "active",
        },
        headers=admin_headers,
    )
    assert updated.status_code == 200
    assert updated.json()["tenant_type"] == "regulated"

    created_provider = client.post(
        "/auth/workload-identity/providers",
        json={
            "tenant_id": tenant_id,
            "provider_type": "aws",
            "audience": "sts.amazonaws.com",
            "role_arn_or_equivalent": "arn:aws:iam::123456789012:role/app-role",
            "session_duration_seconds": 3600,
            "allowed_subject_patterns": "[]",
        },
        headers=admin_headers,
    )
    assert created_provider.status_code == 200

    provider_list = client.get(f"/auth/workload-identity/providers?tenant_id={tenant_id}", headers=auditor_headers)
    assert provider_list.status_code == 200
    payload = provider_list.json()
    assert payload[0]["tenant_name"] == "Payments Platform Updated"
    assert payload[0]["tenant_type"] == "regulated"
    assert payload[0]["tenant_description"] == "Payments production tenant with regulated controls"


def test_tenant_catalog_write_requires_admin_and_mfa():
    suffix = uuid4().hex[:8]
    tenant_id = f"tenant-write-{suffix}"

    forbidden = client.post(
        "/providers/tenants",
        json={
            "tenant_id": tenant_id,
            "tenant_name": "Forbidden Tenant",
            "tenant_type": "sandbox",
            "description": "forbidden",
            "status": "active",
        },
        headers=_headers("Auditor", f"auditor-tenant-{suffix}"),
    )
    assert forbidden.status_code == 403

    mfa_required = client.post(
        "/providers/tenants",
        json={
            "tenant_id": tenant_id,
            "tenant_name": "MFA Tenant",
            "tenant_type": "sandbox",
            "description": "mfa required",
            "status": "active",
        },
        headers=_headers("Platform Admin", f"admin-tenant-{suffix}"),
    )
    assert mfa_required.status_code == 403
    assert mfa_required.json()["detail"]["error_code"] == "AUTHZ_MFA_REQUIRED"


def test_provider_creation_requires_known_active_tenant_catalog_entry():
    suffix = uuid4().hex[:8]
    admin_headers = _headers("Platform Admin", f"admin-tenant-provider-{suffix}", mfa=True)

    missing_workload = client.post(
        "/auth/workload-identity/providers",
        json={
            "tenant_id": f"missing-tenant-{suffix}",
            "provider_type": "aws",
            "audience": "sts.amazonaws.com",
            "role_arn_or_equivalent": "arn:aws:iam::123456789012:role/app-role",
            "session_duration_seconds": 3600,
            "allowed_subject_patterns": "[]",
        },
        headers=admin_headers,
    )
    assert missing_workload.status_code == 404
    assert response_error_code(missing_workload) == "RESOURCE_NOT_FOUND"

    missing_secret = client.post(
        "/secrets/providers",
        json={
            "tenant_id": f"missing-tenant-{suffix}",
            "provider_type": "vault",
            "provider_address": "https://vault.example.internal",
            "auth_method": "approle",
            "role_or_mount": "approle/platform",
            "secret_path_prefixes": "[]",
            "lease_ttl_seconds": 3600,
            "auto_renew_enabled": True,
        },
        headers=admin_headers,
    )
    assert missing_secret.status_code == 404
    assert response_error_code(missing_secret) == "RESOURCE_NOT_FOUND"


def test_tenant_deactivate_blocks_new_provider_onboarding():
    suffix = uuid4().hex[:8]
    tenant_id = f"tenant-inactive-{suffix}"
    admin_headers = _headers("Platform Admin", f"admin-tenant-inactive-{suffix}", mfa=True)
    auditor_headers = _headers("Auditor", f"auditor-tenant-inactive-{suffix}")

    created = client.post(
        "/providers/tenants",
        json={
            "tenant_id": tenant_id,
            "tenant_name": "Retired Tenant",
            "tenant_type": "sandbox",
            "description": "to be deactivated",
            "status": "active",
        },
        headers=admin_headers,
    )
    assert created.status_code == 200

    deactivated = client.put(
        f"/providers/tenants/{tenant_id}",
        json={
            "tenant_id": tenant_id,
            "tenant_name": "Retired Tenant",
            "tenant_type": "sandbox",
            "description": "deactivated tenant",
            "status": "inactive",
        },
        headers=admin_headers,
    )
    assert deactivated.status_code == 200
    assert deactivated.json()["status"] == "inactive"

    inactive_list = client.get("/providers/tenants?status=inactive&limit=50", headers=auditor_headers)
    assert inactive_list.status_code == 200
    assert any(row["tenant_id"] == tenant_id for row in inactive_list.json())

    blocked_workload = client.post(
        "/auth/workload-identity/providers",
        json={
            "tenant_id": tenant_id,
            "provider_type": "aws",
            "audience": "sts.amazonaws.com",
            "role_arn_or_equivalent": "arn:aws:iam::123456789012:role/app-role",
            "session_duration_seconds": 3600,
            "allowed_subject_patterns": "[]",
        },
        headers=admin_headers,
    )
    assert blocked_workload.status_code == 400
    assert response_error_code(blocked_workload) == "VALIDATION_ERROR"
    assert "not active" in response_error_message(blocked_workload)

    blocked_secret = client.post(
        "/secrets/providers",
        json={
            "tenant_id": tenant_id,
            "provider_type": "vault",
            "provider_address": "https://vault.example.internal",
            "auth_method": "approle",
            "role_or_mount": "approle/platform",
            "secret_path_prefixes": "[]",
            "lease_ttl_seconds": 3600,
            "auto_renew_enabled": True,
        },
        headers=admin_headers,
    )
    assert blocked_secret.status_code == 400
    assert response_error_code(blocked_secret) == "VALIDATION_ERROR"
    assert "not active" in response_error_message(blocked_secret)

    reactivated = client.put(
        f"/providers/tenants/{tenant_id}",
        json={
            "tenant_id": tenant_id,
            "tenant_name": "Retired Tenant",
            "tenant_type": "sandbox",
            "description": "reactivated tenant",
            "status": "active",
        },
        headers=admin_headers,
    )
    assert reactivated.status_code == 200
    assert reactivated.json()["status"] == "active"
