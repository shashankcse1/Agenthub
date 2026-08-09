"""CI proofs for Leader Readiness clock drills (revoke + evidence export)."""

from __future__ import annotations

import time
from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

ADMIN = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": "clock-admin"}
AUDITOR = {"X-Actor-Role": "Auditor", "X-Actor-Id": "clock-auditor"}


def test_clock01_virtual_key_revoke_cycle_under_15_minutes():
    started = time.perf_counter()
    created = client.post(
        "/keys",
        json={
            "owner_scope_type": "team",
            "owner_scope_id": "clock-revoke",
            "allowed_endpoint_families": '["responses"]',
            "allowed_models": '["gpt-test"]',
        },
        headers={**ADMIN, "X-Actor-Id": f"clock-admin-{uuid4().hex[:6]}"},
    )
    assert created.status_code == 200, created.text
    key_id = created.json()["key_id"]

    blocked = client.post(f"/keys/{key_id}/block", headers=ADMIN)
    assert blocked.status_code == 200
    assert blocked.json()["status"] == "blocked"

    unblocked = client.post(f"/keys/{key_id}/unblock", headers=ADMIN)
    assert unblocked.status_code == 200
    assert unblocked.json()["status"] == "active"

    elapsed_seconds = time.perf_counter() - started
    assert elapsed_seconds < 15 * 60
    # CI should complete in seconds; keep a tight soft bound for regressions.
    assert elapsed_seconds < 30


def test_clock02_governance_evidence_export_under_60_minutes():
    started = time.perf_counter()
    exported = client.post(
        "/gateway/governance/evidence/export",
        json={
            "decision_outcome": "allow",
            "limit_per_action": 50,
            "bundle_label": "leadership-clock02",
            "data_classification": "internal",
            "retention_days": 90,
            "classification_owner": "secops-clock-drill",
            "approved_sharing_channels": ["secops"],
        },
        headers=AUDITOR,
    )
    assert exported.status_code == 200, exported.text
    payload = exported.json()
    assert str(payload.get("export_uri") or "").startswith("evidence://")
    assert payload.get("classification_owner") == "secops-clock-drill"
    assert payload.get("data_classification") == "internal"
    elapsed_seconds = time.perf_counter() - started
    assert elapsed_seconds < 60 * 60
    assert elapsed_seconds < 30


def test_on_plane_coverage_helper_formula():
    from datetime import datetime, timedelta
    from unittest.mock import MagicMock

    from app.services.on_plane_coverage import _properties_mark_off_plane, compute_on_plane_coverage

    assert _properties_mark_off_plane('{"off_plane": true}') is True
    assert _properties_mark_off_plane('{"off_plane": false}') is False
    assert _properties_mark_off_plane("{}") is False

    db = MagicMock()
    cost_query = MagicMock()
    cost_query.filter.return_value = cost_query
    cost_query.count.return_value = 9
    cost_query.with_entities.return_value.limit.return_value.all.return_value = [
        ('{"off_plane": true}',),
        ("{}",),
    ]
    unmanaged_q = MagicMock()
    unmanaged_q.filter.return_value = unmanaged_q
    unmanaged_q.scalar.return_value = 1

    def _query(model):
        from app.models import CostEvent, DiscoveryRecord

        if model is CostEvent:
            return cost_query
        if model is DiscoveryRecord:
            return unmanaged_q
        return MagicMock()

    db.query.side_effect = _query
    coverage = compute_on_plane_coverage(
        db,
        window_start=datetime.utcnow() - timedelta(hours=24),
        environment=None,
    )
    assert coverage["on_plane_events"] == 9
    assert coverage["off_plane_tagged_cost_events"] == 1
    assert coverage["unmanaged_high_risk_discovered"] == 1
    assert coverage["off_plane_detected"] == 2
    assert coverage["on_plane_coverage_percent"] == round((9 / 11) * 100.0, 2)
