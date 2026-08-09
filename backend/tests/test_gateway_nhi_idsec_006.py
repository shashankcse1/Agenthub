"""NHI evidence pack + correlation ingest + owner-scoped intent (GOV-AI-IDSEC-NHI-006)."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import VirtualKey

client = TestClient(app)

ADMIN_HEADERS = {
    "X-Actor-Role": "Platform Admin",
    "X-Actor-Id": "admin-nhi-idsec006",
    "X-Approver-Role": "Security Approver",
    "X-Approver-Id": "sec-nhi-idsec006",
}
AUDITOR_HEADERS = {"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-nhi-idsec006"}


def _sign(secret: str, body: bytes, *, timestamp: str = "", nonce: str = "") -> str:
    material = f"{str(timestamp or '').strip()}.{str(nonce or '').strip()}.".encode("utf-8") + body
    return hmac.new(secret.encode("utf-8"), material, hashlib.sha256).hexdigest()


def _seed_vk() -> str:
    db = SessionLocal()
    try:
        key_id = f"vk-idsec006-{uuid4().hex[:10]}"
        db.add(
            VirtualKey(
                key_id=key_id,
                key_hash=f"hash-{key_id}",
                owner_scope_type="user",
                owner_scope_id="owner-idsec006",
                allowed_endpoint_families='["chat.completions"]',
                allowed_models='["gpt-4o-mini"]',
                status="active",
                expires_at=datetime.utcnow() + timedelta(days=30),
            )
        )
        db.commit()
        return key_id
    finally:
        db.close()


def test_evidence_correlation_ingest_and_owner_intent():
    key_id = _seed_vk()

    # Sync via inventory
    inventory = client.get("/gateway/nhi/inventory?source_type=virtual_key&limit=100", headers=AUDITOR_HEADERS)
    assert inventory.status_code == 200
    vk_rows = [row for row in inventory.json() if row.get("source_id") == key_id]
    assert vk_rows
    nhi_id = vk_rows[0]["nhi_record_id"]

    gov = client.put(
        "/gateway/nhi/governance/config",
        json={
            "intent_mode": "block",
            "correlation_ingest_enabled": True,
            "require_correlation_ingest_hmac": True,
            "correlation_ingest_hmac_secret": "corr-secret-idsec006",
        },
        headers=ADMIN_HEADERS,
    )
    assert gov.status_code == 200, gov.text
    assert gov.json()["correlation_ingest_enabled"] is True
    assert gov.json()["correlation_ingest_hmac_secret"] == ""

    body = {
        "virtual_key_id": key_id,
        "external_ref": "zuma-agent-006",
        "iga_agent_id": "agent-006",
        "source_system": "external_iga",
    }
    raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
    bad = client.post(
        "/gateway/nhi/correlation/ingest",
        data=raw,
        headers={"Content-Type": "application/json", "X-Gateway-Nhi-Correlation-Signature": "nope"},
    )
    assert bad.status_code == 401, bad.text

    ok = client.post(
        "/gateway/nhi/correlation/ingest",
        data=raw,
        headers={
            "Content-Type": "application/json",
            "X-Gateway-Nhi-Correlation-Signature": _sign("corr-secret-idsec006", raw),
        },
    )
    assert ok.status_code == 200, ok.text
    assert ok.json()["external_ref"] == "zuma-agent-006"

    intents = client.put(
        f"/gateway/nhi/{nhi_id}/intents",
        json={"purpose": "support", "approved_intents": ["summarize"]},
        headers=ADMIN_HEADERS,
    )
    assert intents.status_code == 200, intents.text

    # Intent resolve by owner_scope_id (no VK / nhi id)
    check = client.post(
        "/gateway/nhi/intent-check",
        json={
            "owner_scope_id": "owner-idsec006",
            "declared_intent": "exfiltrate",
            "action": "chat.completions",
        },
        headers=AUDITOR_HEADERS,
    )
    assert check.status_code == 200, check.text
    assert check.json()["decision"] == "deny"
    assert check.json()["nhi_record_id"] == nhi_id

    evidence = client.post(
        "/gateway/nhi/evidence/export",
        json={"max_credential_age_days": 90},
        headers=AUDITOR_HEADERS,
    )
    assert evidence.status_code == 200, evidence.text
    pack = evidence.json()
    assert pack["schema_version"] == "guardbridge.nhi.evidence.v1"
    assert "summary" in pack
    assert pack["summary"]["correlated_count"] >= 1
    assert "hygiene_summary" in pack
    assert "iga_deny" in pack

    # reset governance for other suites
    client.put(
        "/gateway/nhi/governance/config",
        json={
            "intent_mode": "off",
            "correlation_ingest_enabled": False,
            "require_correlation_ingest_hmac": True,
            "correlation_ingest_hmac_secret": "",
        },
        headers=ADMIN_HEADERS,
    )
