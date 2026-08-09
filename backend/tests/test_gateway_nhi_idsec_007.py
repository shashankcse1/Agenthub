"""Gateway-native agents/access: agents + IARA-lite + shadow action (NHI-007)."""

from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import BrowserShadowAiApp, DiscoveryRecord

client = TestClient(app)

ADMIN_HEADERS = {
    "X-Actor-Role": "Platform Admin",
    "X-Actor-Id": "admin-nhi-idsec007",
    "X-Approver-Role": "Security Approver",
    "X-Approver-Id": "sec-nhi-idsec007",
}
AUDITOR_HEADERS = {"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-nhi-idsec007"}


def _seed() -> tuple[str, str]:
    db = SessionLocal()
    try:
        discovered_id = f"disc-{uuid4().hex[:10]}"
        shadow_id = f"shadow-{uuid4().hex[:10]}"
        db.add(
            DiscoveryRecord(
                discovered_agent_id=discovered_id,
                canonical_agent_key=f"canon-{discovered_id}",
                source_system="cursor",
                source_fingerprint=f"fp-{discovered_id}",
                discovery_confidence=80,
                discovery_status="discovered",
                last_discovered_at=datetime.utcnow(),
            )
        )
        db.add(
            BrowserShadowAiApp(
                app_id=shadow_id,
                domain=f"{shadow_id}.example.ai",
                app_name="Shadow Demo",
                category="generative-ai",
                risk_score=85,
                status="unsanctioned",
                active_user_count=3,
                data_upload_events=2,
            )
        )
        db.commit()
        return discovered_id, shadow_id
    finally:
        db.close()


def test_agents_access_policies_and_shadow_action():
    discovered_id, shadow_id = _seed()

    agents = client.get("/gateway/nhi/agents?limit=100", headers=AUDITOR_HEADERS)
    assert agents.status_code == 200, agents.text
    body = agents.json()
    assert body["agent_count"] >= 2
    source_ids = {row.get("source_id") for row in body.get("agents") or []}
    assert discovered_id in source_ids
    assert shadow_id in source_ids

    saved = client.put(
        "/gateway/nhi/access/config",
        json={
            "access_mode": "block",
            "access_policies": [
                {
                    "name": "deny-exfil",
                    "intent": "exfiltrate",
                    "resource": "model:*",
                    "action": "chat.completions",
                    "effect": "deny",
                    "enabled": True,
                },
                {
                    "name": "allow-summarize",
                    "intent": "summarize",
                    "resource": "model:*",
                    "action": "chat.completions",
                    "effect": "allow",
                    "enabled": True,
                },
            ],
            "policy_count": 2,
            "intent_mode": "off",
        },
        headers=ADMIN_HEADERS,
    )
    assert saved.status_code == 200, saved.text
    assert saved.json()["access_mode"] == "block"
    assert saved.json()["policy_count"] == 2

    denied = client.post(
        "/gateway/nhi/access/authorize",
        json={
            "declared_intent": "exfiltrate",
            "resource": "model:gpt-4o-mini",
            "action": "chat.completions",
        },
        headers=AUDITOR_HEADERS,
    )
    assert denied.status_code == 200, denied.text
    assert denied.json()["decision"] == "deny"

    allowed = client.post(
        "/gateway/nhi/access/authorize",
        json={
            "declared_intent": "summarize",
            "resource": "model:gpt-4o-mini",
            "action": "chat.completions",
        },
        headers=AUDITOR_HEADERS,
    )
    assert allowed.status_code == 200, allowed.text
    assert allowed.json()["decision"] == "allow"

    inventory = client.get(
        "/gateway/nhi/inventory?source_type=shadow_ai_app&limit=50",
        headers=AUDITOR_HEADERS,
    )
    assert inventory.status_code == 200
    shadow_rows = [row for row in inventory.json() if row.get("source_id") == shadow_id]
    assert shadow_rows
    nhi_id = shadow_rows[0]["nhi_record_id"]

    blocked = client.post(
        f"/gateway/nhi/{nhi_id}/shadow-action",
        json={"action": "block", "notes": "unsanctioned high risk"},
        headers=ADMIN_HEADERS,
    )
    assert blocked.status_code == 200, blocked.text
    assert blocked.json()["shadow_status"] == "blocked"
    assert blocked.json()["nhi_status"] == "suspended"

    # reset access mode for other suites
    client.put(
        "/gateway/nhi/access/config",
        json={"access_mode": "off", "access_policies": [], "policy_count": 0, "intent_mode": "off"},
        headers=ADMIN_HEADERS,
    )
