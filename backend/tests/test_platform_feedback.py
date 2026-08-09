from datetime import datetime, timezone
from uuid import uuid4

import importlib.util
from pathlib import Path

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.models import AuditEvent, OperatorFeedback


def _platform_test_client() -> TestClient:
    router_path = Path(__file__).resolve().parents[1] / "app" / "routers" / "platform.py"
    spec = importlib.util.spec_from_file_location("platform_router_under_test", router_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    app = FastAPI()
    app.state.rate_limiter = type("LimiterStub", (), {"runtime_status": lambda self: {"degraded": False}})()
    app.include_router(module.router)
    return TestClient(app)


def test_platform_operational_status_returns_posture_fields():
    client = _platform_test_client()
    response = client.get("/platform/operational-status")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] in {"ok", "degraded", "maintenance", "incident"}
    assert "maintenance" in payload
    assert "performance" in payload
    assert payload["performance"]["slow_response_threshold_ms"] >= 250
    assert isinstance(payload["feedback_enabled"], bool)


def test_create_operator_feedback_persists_and_audits():
    client = _platform_test_client()
    response = client.post(
        "/platform/feedback",
        json={
            "category": "performance",
            "severity": "high",
            "comment": "Overview load exceeded threshold.",
            "context_view": "overview",
            "context_action": "load_overview",
            "client_latency_ms": 4200,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-admin-1"},
    )
    assert response.status_code == 200
    payload = response.json()
    feedback_id = payload["feedback_id"]
    assert payload["category"] == "performance"
    assert payload["status"] == "open"
    assert payload["context_action"] == "load_overview"

    db: Session = SessionLocal()
    try:
        row = db.query(OperatorFeedback).filter_by(feedback_id=feedback_id).first()
        assert row is not None
        assert row.comment == "Overview load exceeded threshold."
        assert row.created_by == "platform-admin-1"
        audit = (
            db.query(AuditEvent)
            .filter_by(action_type="platform.feedback.create", resource_id=feedback_id)
            .first()
        )
        assert audit is not None
        assert audit.resource_type == "operator_feedback"
    finally:
        db.close()


def test_operator_feedback_analytics_groups_by_action():
    db: Session = SessionLocal()
    try:
        db.add(
            OperatorFeedback(
                feedback_id=str(uuid4()),
                category="ux",
                severity="medium",
                comment="Navigation lag on discovery tab.",
                context_view="discovery",
                context_action="switch_view",
                created_by="seed-user",
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc),
            )
        )
        db.commit()
    finally:
        db.close()

    client = _platform_test_client()
    response = client.get(
        "/platform/feedback/analytics?since_hours=168",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "auditor-1"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total_count"] >= 1
    assert any(row["label"] == "switch_view" for row in payload["by_context_action"])


def test_operator_feedback_action_requires_admin_role():
    feedback_id = str(uuid4())
    db: Session = SessionLocal()
    try:
        db.add(
            OperatorFeedback(
                feedback_id=feedback_id,
                category="bug",
                severity="low",
                comment="Minor layout issue.",
                context_view="overview",
                context_action="render_card",
                created_by="seed-user",
            )
        )
        db.commit()
    finally:
        db.close()

    client = _platform_test_client()
    denied = client.post(
        f"/platform/feedback/{feedback_id}/actions",
        json={"action": "acknowledge", "action_note": "Reviewing"},
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-1"},
    )
    assert denied.status_code == 403

    allowed = client.post(
        f"/platform/feedback/{feedback_id}/actions",
        json={"action": "acknowledge", "action_note": "Reviewing"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-1"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["status"] == "acknowledged"
