from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import SecretProviderConfig, WorkloadIdentityFederationProfile

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


def test_provider_sensitive_fields_are_stored_encrypted_and_tests_are_non_synthetic():
    suffix = uuid4().hex[:8]
    tenant_id = f"tenant-provider-crypto-{suffix}"
    admin_headers = _headers("Platform Admin", f"admin-provider-crypto-{suffix}", mfa=True)
    _seed_tenant(tenant_id, admin_headers)

    workload_created = client.post(
        "/auth/workload-identity/providers",
        json={
            "tenant_id": tenant_id,
            "provider_type": "aws",
            "audience": "sts.amazonaws.com",
            "role_arn_or_equivalent": "arn:aws:iam::123456789012:role/crypto-test",
            "bootstrap_token": "bootstrap-token-workload",
            "session_duration_seconds": 3600,
            "allowed_subject_patterns": "[]",
        },
        headers=admin_headers,
    )
    assert workload_created.status_code == 200
    workload_id = workload_created.json()["workload_identity_profile_id"]

    secret_created = client.post(
        "/secrets/providers",
        json={
            "tenant_id": tenant_id,
            "provider_type": "vault",
            "provider_address": "https://vault.invalid.internal",
            "auth_method": "approle",
            "role_or_mount": "approle/platform",
            "bootstrap_token": "bootstrap-token-secret",
            "secret_path_prefixes": "[]",
            "lease_ttl_seconds": 3600,
            "auto_renew_enabled": True,
        },
        headers=admin_headers,
    )
    assert secret_created.status_code == 200
    secret_id = secret_created.json()["secret_provider_id"]

    db = SessionLocal()
    try:
        workload = db.query(WorkloadIdentityFederationProfile).filter_by(workload_identity_profile_id=workload_id).first()
        assert workload is not None
        assert workload.role_arn_or_equivalent == "[ENCRYPTED]"
        assert str(workload.role_arn_or_equivalent_encrypted or "").strip()

        secret = db.query(SecretProviderConfig).filter_by(secret_provider_id=secret_id).first()
        assert secret is not None
        assert secret.provider_address == "[ENCRYPTED]"
        assert secret.auth_method == "[ENCRYPTED]"
        assert secret.role_or_mount == "[ENCRYPTED]"
        assert str(secret.provider_address_encrypted or "").strip()
        assert str(secret.auth_method_encrypted or "").strip()
        assert str(secret.role_or_mount_encrypted or "").strip()
    finally:
        db.close()

    secret_test = client.post(f"/secrets/providers/{secret_id}/test", headers=admin_headers)
    assert secret_test.status_code == 200
    payload = secret_test.json()
    assert payload["test_status"] in {"passed", "failed"}
    assert isinstance(payload.get("detail"), str)
    assert "latency_ms" in payload

    workload_test = client.post(
        f"/auth/workload-identity/providers/{workload_id}/test?tenant_id={tenant_id}",
        headers=admin_headers,
    )
    assert workload_test.status_code == 200
    workload_payload = workload_test.json()
    assert workload_payload["test_status"] in {"passed", "failed"}
    assert isinstance(workload_payload.get("detail"), str)


def test_workload_provider_rejects_invalid_subject_patterns_json_with_example():
    suffix = uuid4().hex[:8]
    tenant_id = f"tenant-provider-patterns-{suffix}"
    admin_headers = _headers("Platform Admin", f"admin-provider-patterns-{suffix}", mfa=True)
    _seed_tenant(tenant_id, admin_headers)

    created = client.post(
        "/auth/workload-identity/providers",
        json={
            "tenant_id": tenant_id,
            "provider_type": "aws",
            "audience": "sts.amazonaws.com",
            "role_arn_or_equivalent": "arn:aws:iam::123456789012:role/pattern-test",
            "session_duration_seconds": 3600,
            "allowed_subject_patterns": '{"bad": true}',
        },
        headers=admin_headers,
    )

    assert created.status_code == 400
    detail = created.json().get("detail", "")
    assert "JSON array of strings" in detail
    assert "Example" in detail
