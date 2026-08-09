"""NHI orphan remediation + IGA correlation + deny event history (GOV-AI-IDSEC-NHI-005)."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import WorkloadIdentityFederationProfile

client = TestClient(app)

ADMIN_HEADERS = {
    "X-Actor-Role": "Platform Admin",
    "X-Actor-Id": "admin-nhi-idsec005",
    "X-Approver-Role": "Security Approver",
    "X-Approver-Id": "sec-nhi-idsec005",
}
AUDITOR_HEADERS = {"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-nhi-idsec005"}


def _seed_orphan_wif() -> str:
    db = SessionLocal()
    try:
        workload_id = f"wif-orphan-{uuid4().hex[:10]}"
        db.add(
            WorkloadIdentityFederationProfile(
                workload_identity_profile_id=workload_id,
                tenant_id="tenant-nhi-idsec005",
                provider_type="aws",
                audience="sts.amazonaws.com",
                role_arn_or_equivalent="arn:aws:iam::123456789012:role/nhi-orphan",
                session_duration_seconds=3600,
                status="active",
                last_token_exchange_at=datetime.utcnow() - timedelta(days=120),
            )
        )
        db.commit()
        return workload_id
    finally:
        db.close()


def test_orphans_correlation_and_deny_events():
    _seed_orphan_wif()

    orphans = client.get(
        "/gateway/nhi/orphans?tenant_id=tenant-nhi-idsec005&limit=50",
        headers=AUDITOR_HEADERS,
    )
    assert orphans.status_code == 200, orphans.text
    body = orphans.json()
    assert body["orphan_count"] >= 1
    nhi_id = body["orphans"][0]["nhi_record_id"]

    corr = client.put(
        f"/gateway/nhi/{nhi_id}/correlation",
        json={
            "external_ref": "zuma-agent-corr-1",
            "iga_agent_id": "agent-corr-1",
            "source_system": "external_iga",
        },
        headers=ADMIN_HEADERS,
    )
    assert corr.status_code == 200, corr.text
    assert corr.json()["external_ref"] == "zuma-agent-corr-1"

    assigned = client.post(
        "/gateway/nhi/orphans/assign",
        json={
            "nhi_record_ids": [nhi_id],
            "owner_scope_type": "team",
            "owner_scope_id": "platform-eng-idsec005",
            "purpose": "orphan remediation",
        },
        headers=ADMIN_HEADERS,
    )
    assert assigned.status_code == 200, assigned.text
    assert assigned.json()["updated_count"] == 1

    orphans_after = client.get(
        "/gateway/nhi/orphans?tenant_id=tenant-nhi-idsec005&limit=50",
        headers=AUDITOR_HEADERS,
    )
    assert orphans_after.status_code == 200
    remaining_ids = {row["nhi_record_id"] for row in orphans_after.json().get("orphans") or []}
    assert nhi_id not in remaining_ids

    export = client.post(
        "/gateway/nhi/export",
        json={
            "tenant_id": "tenant-nhi-idsec005",
            "profile": "iga_correlation",
            "target_system": "external_iga",
            "limit": 50,
            "include_hygiene_summary": False,
        },
        headers=AUDITOR_HEADERS,
    )
    assert export.status_code == 200, export.text
    identities = export.json().get("identities") or []
    matched = [
        item
        for item in identities
        if (item.get("meta") or {}).get("correlation_keys", {}).get("nhi_record_id") == nhi_id
    ]
    assert matched, "exported identity should include correlated NHI"
    keys = matched[0]["meta"]["correlation_keys"]
    assert keys.get("external_ref") == "zuma-agent-corr-1"
    assert keys.get("iga_agent_id") == "agent-corr-1"

    saved = client.put(
        "/gateway/nhi/iga-deny/config",
        json={
            "enabled": True,
            "mode": "warn",
            "ingest_hmac_secret": "idsec005-deny-secret",
            "require_ingest_hmac": False,
            "default_ttl_seconds": 3600,
            "max_active_denies": 50,
            "allowed_source_systems": ["external_iga", "generic"],
        },
        headers=ADMIN_HEADERS,
    )
    assert saved.status_code == 200, saved.text

    ingest = client.post(
        "/gateway/nhi/iga-deny",
        json={
            "subject_type": "actor_id",
            "subject_id": "actor-idsec005-history",
            "reason": "history evidence test",
            "source_system": "external_iga",
            "external_ref": "zuma-evt-history-1",
            "ttl_seconds": 3600,
        },
        headers=ADMIN_HEADERS,
    )
    assert ingest.status_code == 200, ingest.text
    deny_id = ingest.json()["deny_id"]

    events = client.get("/gateway/nhi/iga-deny/events?limit=20", headers=AUDITOR_HEADERS)
    assert events.status_code == 200, events.text
    event_types = {row.get("event_type") for row in events.json().get("events") or []}
    assert "ingest" in event_types

    revoked = client.post(
        f"/gateway/nhi/iga-deny/{deny_id}/revoke",
        json={"reason": "cleanup"},
        headers=ADMIN_HEADERS,
    )
    assert revoked.status_code == 200, revoked.text

    events_after = client.get("/gateway/nhi/iga-deny/events?limit=20", headers=AUDITOR_HEADERS)
    assert events_after.status_code == 200
    types_after = {row.get("event_type") for row in events_after.json().get("events") or []}
    assert "revoke" in types_after

    # restore deny gate off for other suites
    client.put(
        "/gateway/nhi/iga-deny/config",
        json={
            "enabled": False,
            "mode": "off",
            "require_ingest_hmac": True,
            "default_ttl_seconds": 86400,
            "max_active_denies": 200,
            "allowed_source_systems": ["generic", "external_iga", "astrix", "oasis", "aembit"],
        },
        headers=ADMIN_HEADERS,
    )
