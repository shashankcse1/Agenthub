"""NHI IGA export + webhook delivery (GOV-AI-IDSEC-NHI-002)."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import SecretProviderConfig, WorkloadIdentityFederationProfile

client = TestClient(app)

ADMIN_HEADERS = {
    "X-Actor-Role": "Platform Admin",
    "X-Actor-Id": "admin-nhi-iga-1",
    "X-Approver-Role": "Security Approver",
    "X-Approver-Id": "sec-nhi-iga-1",
}
AUDITOR_HEADERS = {"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-nhi-iga-1"}
TENANT = "tenant-nhi-iga-export"


def _seed_identities() -> None:
    db = SessionLocal()
    try:
        workload_id = f"wif-{uuid4().hex[:10]}"
        secret_provider_id = f"sec-{uuid4().hex[:10]}"
        db.add(
            WorkloadIdentityFederationProfile(
                workload_identity_profile_id=workload_id,
                tenant_id=TENANT,
                provider_type="aws",
                audience="sts.amazonaws.com",
                role_arn_or_equivalent="arn:aws:iam::123456789012:role/nhi-iga",
                session_duration_seconds=3600,
                status="active",
                last_token_exchange_at=datetime.utcnow() - timedelta(days=200),
            )
        )
        db.add(
            SecretProviderConfig(
                secret_provider_id=secret_provider_id,
                tenant_id=TENANT,
                provider_type="vault",
                provider_address="https://vault.local",
                auth_method="approle",
                role_or_mount="ai-gateway",
                secret_path_prefixes='["kv/gateway/"]',
                lease_ttl_seconds=3600,
                auto_renew_enabled=True,
                status="active",
                last_health_check_at=datetime.utcnow(),
            )
        )
        db.commit()
    finally:
        db.close()


def test_nhi_export_iga_correlation_bundle():
    _seed_identities()
    response = client.post(
        "/gateway/nhi/export",
        json={
            "tenant_id": TENANT,
            "max_credential_age_days": 90,
            "profile": "iga_correlation",
            "target_system": "external_iga",
            "include_hygiene_summary": True,
            "deliver_webhook": False,
            "limit": 50,
        },
        headers=AUDITOR_HEADERS,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["schema_version"] == "guardbridge.nhi.iga_export.v1"
    assert payload["profile"] == "iga_correlation"
    assert payload["target_system"] == "external_iga"
    assert payload["plane"] == "inference_gateway"
    assert payload["record_count"] >= 2
    assert payload["hygiene_summary"]["total_identities"] >= 2
    sample = payload["identities"][0]
    assert sample["externalId"]
    assert sample["meta"]["resourceType"] == "GatewayNHI"
    assert "correlation_keys" in sample["meta"]
    assert payload["correlation_guide"]["match_on"]


def test_nhi_export_native_profile():
    response = client.post(
        "/gateway/nhi/export",
        json={
            "tenant_id": TENANT,
            "profile": "native",
            "target_system": "generic",
            "include_hygiene_summary": False,
            "limit": 20,
        },
        headers=AUDITOR_HEADERS,
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["profile"] == "native"
    assert payload.get("hygiene_summary") is None
    if payload["identities"]:
        assert "nhi_record_id" in payload["identities"][0]


def test_nhi_iga_export_config_requires_dual_approval():
    denied = client.put(
        "/gateway/nhi/iga-export/config",
        json={
            "enabled": True,
            "target_system": "external_iga",
            "webhook_url": "https://iga.example/hooks/nhi",
            "hmac_secret": "test-secret",
            "sign_requests": True,
            "include_hygiene_summary": True,
            "default_profile": "iga_correlation",
            "max_records": 100,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-nhi-iga-2"},
    )
    assert denied.status_code in {401, 403}, denied.text

    saved = client.put(
        "/gateway/nhi/iga-export/config",
        json={
            "enabled": True,
            "target_system": "external_iga",
            "webhook_url": "https://iga.example/hooks/nhi",
            "hmac_secret": "test-secret",
            "sign_requests": True,
            "include_hygiene_summary": True,
            "default_profile": "iga_correlation",
            "max_records": 100,
        },
        headers=ADMIN_HEADERS,
    )
    assert saved.status_code == 200, saved.text
    body = saved.json()
    assert body["enabled"] is True
    assert body["target_system"] == "external_iga"
    assert body["hmac_secret_configured"] is True
    assert body["hmac_secret"] == ""

    loaded = client.get("/gateway/nhi/iga-export/config", headers=AUDITOR_HEADERS)
    assert loaded.status_code == 200
    assert loaded.json()["hmac_secret"] == ""
    assert loaded.json()["hmac_secret_configured"] is True


def test_nhi_iga_export_test_delivery_dry_run():
    response = client.post(
        "/gateway/nhi/iga-export/test-delivery",
        json={"dry_run": True},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-nhi-iga-3"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["delivery"]["delivery_status"] == "delivered_simulated"
    assert payload["delivery"]["signed"] is True


def test_nhi_export_deliver_dry_run_uses_config():
    response = client.post(
        "/gateway/nhi/export",
        json={
            "tenant_id": TENANT,
            "profile": "iga_correlation",
            "target_system": "external_iga",
            "deliver_webhook": True,
            "dry_run_delivery": True,
            "limit": 10,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-nhi-iga-4"},
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["delivery"]["delivery_status"] == "delivered_simulated"
    assert payload["delivery"]["record_count"] == payload["record_count"]


def test_nhi_export_forbidden_for_agent_owner():
    response = client.post(
        "/gateway/nhi/export",
        json={"tenant_id": TENANT, "limit": 5},
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "agent-owner-nhi"},
    )
    assert response.status_code in {401, 403}, response.text
