"""Gateway NHI Insights + lifecycle + intent-check (GOV-AI-IDSEC-NHI-004)."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import VirtualKey, WorkloadIdentityFederationProfile

client = TestClient(app)

ADMIN_HEADERS = {
    "X-Actor-Role": "Platform Admin",
    "X-Actor-Id": "admin-nhi-insights-1",
    "X-Approver-Role": "Security Approver",
    "X-Approver-Id": "sec-nhi-insights-1",
}
AUDITOR_HEADERS = {"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-nhi-insights-1"}


def _seed() -> tuple[str, str]:
    db = SessionLocal()
    try:
        workload_id = f"wif-{uuid4().hex[:10]}"
        key_id = f"vk-{uuid4().hex[:10]}"
        db.add(
            WorkloadIdentityFederationProfile(
                workload_identity_profile_id=workload_id,
                tenant_id="tenant-nhi-insights",
                provider_type="aws",
                audience="sts.amazonaws.com",
                role_arn_or_equivalent="arn:aws:iam::123456789012:role/nhi-insights",
                session_duration_seconds=3600,
                status="active",
                last_token_exchange_at=datetime.utcnow() - timedelta(days=200),
            )
        )
        db.add(
            VirtualKey(
                key_id=key_id,
                key_hash=f"hash-{key_id}",
                owner_scope_type="user",
                owner_scope_id="owner-insights-1",
                allowed_endpoint_families='["chat.completions"]',
                allowed_models='["gpt-4o-mini"]',
                status="active",
            )
        )
        db.commit()
        return workload_id, key_id
    finally:
        db.close()


def test_nhi_insights_access_map_timeline_and_lifecycle():
    _, key_id = _seed()
    insights = client.get(
        "/gateway/nhi/insights?tenant_id=tenant-nhi-insights&limit=20",
        headers=AUDITOR_HEADERS,
    )
    assert insights.status_code == 200, insights.text
    body = insights.json()
    assert body["total_identities"] >= 1
    assert "top_risks" in body
    assert body["risk_tier_counts"]

    inventory = client.get(
        f"/gateway/nhi/inventory?source_type=virtual_key&limit=50",
        headers=AUDITOR_HEADERS,
    )
    assert inventory.status_code == 200
    vk_rows = [row for row in inventory.json() if row.get("source_id") == key_id]
    assert vk_rows, "virtual key should sync into NHI inventory"
    nhi_id = vk_rows[0]["nhi_record_id"]

    access = client.get(f"/gateway/nhi/{nhi_id}/access-map", headers=AUDITOR_HEADERS)
    assert access.status_code == 200, access.text
    assert access.json()["path_count"] >= 1

    timeline = client.get(f"/gateway/nhi/{nhi_id}/timeline?limit=20", headers=AUDITOR_HEADERS)
    assert timeline.status_code == 200, timeline.text

    owned = client.put(
        f"/gateway/nhi/{nhi_id}/owner",
        json={
            "owner_scope_type": "team",
            "owner_scope_id": "platform-eng",
            "purpose": "playground agent inference",
        },
        headers=ADMIN_HEADERS,
    )
    assert owned.status_code == 200, owned.text
    assert owned.json()["owner_scope_id"] == "platform-eng"

    # Owner must survive inventory sync (VK is SoT — no dual-write clobber).
    inventory_after_owner = client.get(
        f"/gateway/nhi/inventory?source_type=virtual_key&limit=50",
        headers=AUDITOR_HEADERS,
    )
    assert inventory_after_owner.status_code == 200
    vk_after_owner = [row for row in inventory_after_owner.json() if row.get("source_id") == key_id]
    assert vk_after_owner and vk_after_owner[0]["owner_scope_id"] == "platform-eng"
    db = SessionLocal()
    try:
        vk = db.query(VirtualKey).filter_by(key_id=key_id).first()
        assert vk is not None
        assert vk.owner_scope_id == "platform-eng"
        assert vk.owner_scope_type == "team"
    finally:
        db.close()

    intents = client.put(
        f"/gateway/nhi/{nhi_id}/intents",
        json={"purpose": "playground agent inference", "approved_intents": ["summarize", "chat"]},
        headers=ADMIN_HEADERS,
    )
    assert intents.status_code == 200, intents.text
    assert "summarize" in intents.json()["approved_intents"]

    gov = client.put(
        "/gateway/nhi/governance/config",
        json={"intent_mode": "block", "record_count": 0},
        headers=ADMIN_HEADERS,
    )
    assert gov.status_code == 200, gov.text
    assert gov.json()["intent_mode"] == "block"

    allowed = client.post(
        "/gateway/nhi/intent-check",
        json={
            "nhi_record_id": nhi_id,
            "declared_intent": "summarize",
            "action": "chat.completions",
        },
        headers=AUDITOR_HEADERS,
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["decision"] == "allow"

    denied = client.post(
        "/gateway/nhi/intent-check",
        json={
            "nhi_record_id": nhi_id,
            "declared_intent": "exfiltrate",
            "action": "chat.completions",
        },
        headers=AUDITOR_HEADERS,
    )
    assert denied.status_code == 200, denied.text
    assert denied.json()["decision"] == "deny"
    assert denied.json()["allowed"] is False

    suspended = client.post(
        f"/gateway/nhi/{nhi_id}/lifecycle",
        json={"action": "suspend", "reason": "compromised credential"},
        headers=ADMIN_HEADERS,
    )
    assert suspended.status_code == 200, suspended.text
    assert suspended.json()["status"] == "suspended"

    # Suspended must survive sync while VK stays blocked (lifecycle annotation sticky).
    inventory_after_suspend = client.get(
        f"/gateway/nhi/inventory?source_type=virtual_key&limit=50",
        headers=AUDITOR_HEADERS,
    )
    assert inventory_after_suspend.status_code == 200
    vk_after_suspend = [row for row in inventory_after_suspend.json() if row.get("source_id") == key_id]
    assert vk_after_suspend and vk_after_suspend[0]["status"] == "suspended"
    db = SessionLocal()
    try:
        vk = db.query(VirtualKey).filter_by(key_id=key_id).first()
        assert vk is not None
        assert vk.status == "blocked"
    finally:
        db.close()

    # reset intent mode for other suites
    client.put(
        "/gateway/nhi/governance/config",
        json={"intent_mode": "off", "record_count": 0},
        headers=ADMIN_HEADERS,
    )


def test_nhi_lifecycle_retire_is_terminal():
    inventory = client.get("/gateway/nhi/inventory?limit=5", headers=AUDITOR_HEADERS)
    assert inventory.status_code == 200
    rows = inventory.json()
    if not rows:
        _seed()
        inventory = client.get("/gateway/nhi/inventory?limit=5", headers=AUDITOR_HEADERS)
        rows = inventory.json()
    nhi_id = rows[0]["nhi_record_id"]
    retired = client.post(
        f"/gateway/nhi/{nhi_id}/lifecycle",
        json={"action": "retire", "reason": "end of life"},
        headers=ADMIN_HEADERS,
    )
    assert retired.status_code == 200, retired.text
    assert retired.json()["status"] == "retired"
    reactivate = client.post(
        f"/gateway/nhi/{nhi_id}/lifecycle",
        json={"action": "reactivate", "reason": "oops"},
        headers=ADMIN_HEADERS,
    )
    assert reactivate.status_code == 409, reactivate.text
