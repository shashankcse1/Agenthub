"""Leader Readiness L10: QBR snapshot + dated drill registry."""

from __future__ import annotations

from datetime import date, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app, _upgrade_browser_security_schema

client = TestClient(app)

ADMIN = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": "l10-admin"}
READER = {"X-Actor-Role": "Auditor", "X-Actor-Id": "l10-auditor"}


def test_qbr_snapshot_numbers_first():
    # Hermetic: clear any prior program attestation so default honesty stays blocked.
    from app.database import SessionLocal
    from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_LEADERSHIP_LRS_ATTESTATION_JSON
    from app.services.runtime_config import upsert_runtime_config_value

    db = SessionLocal()
    try:
        upsert_runtime_config_value(db, RUNTIME_CONFIG_GATEWAY_LEADERSHIP_LRS_ATTESTATION_JSON, "")
        db.commit()
    finally:
        db.close()

    response = client.get("/gateway/governance/qbr-snapshot?hours=24", headers=READER)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["purpose"] == "numbers_first_qbr"
    assert payload["honesty"]["leader_claim_allowed"] is False
    assert "spend" in payload and "clocks" in payload and "gates" in payload
    assert "drills" in payload
    assert payload["clocks"]["prod_unmanaged_zero_ok"] in (True, False)
    assert isinstance(payload["readiness_notes"], list)
    assert payload["gates"]["auto_disable_supported"] is True
    assert "program_leadership" in payload
    assert "cpli_score" in payload["program_leadership"]
    assert "unified_ready" in payload["program_leadership"]


def test_drill_run_rejects_future_and_unknown_id():
    from datetime import datetime

    # Service validates against UTC calendar day (avoid local/UTC edge cases).
    utc_tomorrow = (datetime.utcnow().date() + timedelta(days=1)).isoformat()
    bad_future = client.post(
        "/gateway/governance/drill-runs",
        json={"drill_id": "Clock-01", "performed_on": utc_tomorrow, "outcome": "pass"},
        headers=ADMIN,
    )
    assert bad_future.status_code == 400

    bad_id = client.post(
        "/gateway/governance/drill-runs",
        json={"drill_id": "Clock-99", "performed_on": datetime.utcnow().date().isoformat()},
        headers=ADMIN,
    )
    assert bad_id.status_code == 400


def test_drill_run_record_and_list_freshness():
    from datetime import datetime

    today = datetime.utcnow().date().isoformat()
    created = client.post(
        "/gateway/governance/drill-runs",
        json={
            "drill_id": "RT-01",
            "performed_on": today,
            "outcome": "pass",
            "duration_seconds": 120,
            "notes": f"ci-{uuid4().hex[:8]}",
            "evidence_ref": "ci://leadership-l10",
        },
        headers=ADMIN,
    )
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["drill_id"] == "RT-01"
    assert body["performed_on"] == today
    assert body["outcome"] == "pass"

    listed = client.get("/gateway/governance/drill-runs?drill_id=RT-01", headers=READER)
    assert listed.status_code == 200, listed.text
    listing = listed.json()
    assert any(item["run_id"] == body["run_id"] for item in listing["items"])
    assert listing["freshness"]["by_drill"]["RT-01"]["within_90d"] is True

    qbr = client.get("/gateway/governance/qbr-snapshot", headers=READER)
    assert qbr.status_code == 200
    assert qbr.json()["drills"]["by_drill"]["RT-01"]["recorded"] is True


def test_browser_security_schema_upgrade_idempotent_on_fresh_db():
    """Regression: ALTER DEFAULT must not fail when browser_type column is absent."""
    _upgrade_browser_security_schema()
    _upgrade_browser_security_schema()
