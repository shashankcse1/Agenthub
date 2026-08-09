from datetime import datetime, timedelta

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import AuditEvent, CostEvent, DiscoveryRecord
from app.services.audit import create_audit_event

client = TestClient(app)


def _auditor_headers(actor_id: str = "aud-obs-summary") -> dict[str, str]:
    return {"X-Actor-Role": "Auditor", "X-Actor-Id": actor_id}


def test_observability_summary_returns_red_metrics():
    db = SessionLocal()
    trace_id = "trace-obs-summary-test"
    try:
        for idx, outcome in enumerate(["allow", "allow", "deny", "warn"]):
            create_audit_event(
                db,
                actor_id="operator-summary",
                action_type=f"gateway.test.{idx}",
                resource_type="agent",
                resource_id=f"agent-{idx}",
                trace_id=trace_id,
                decision_outcome=outcome,
            )
        db.commit()

        response = client.get("/observability/summary?since_hours=24", headers=_auditor_headers())
        assert response.status_code == 200
        payload = response.json()
        assert payload["total_events"] >= 4
        assert payload["unique_traces"] >= 1
        assert payload["deny_count"] >= 1
        assert payload["warn_count"] >= 1
        assert payload["non_allow_rate_percent"] > 0
        assert any(item["label"] == "deny" for item in payload["outcome_breakdown"])
        assert payload["schema_conformance_percent"] is not None
        assert isinstance(payload.get("actor_breakdown"), list)
        assert isinstance(payload.get("recent_traces"), list)
    finally:
        db.query(AuditEvent).filter(AuditEvent.trace_id == trace_id).delete()
        db.commit()
        db.close()


def test_observability_trace_events_merges_audit_and_cost_timeline():
    db = SessionLocal()
    trace_id = "trace-obs-events-test"
    try:
        create_audit_event(
            db,
            actor_id="operator-events",
            action_type="agentic.run",
            resource_type="agent",
            resource_id="agent-events",
            trace_id=trace_id,
            decision_outcome="allow",
        )
        db.add(
            CostEvent(
                cost_event_id="cost-obs-events-1",
                timestamp=datetime.utcnow(),
                request_id="req-1",
                trace_id=trace_id,
                session_id="session-1",
                agent_id="agent-events",
                owner_scope="actor:operator-events",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                estimated_cost_cents=12,
            )
        )
        db.commit()

        response = client.get(f"/observability/traces/{trace_id}/events", headers=_auditor_headers("aud-obs-events"))
        assert response.status_code == 200
        payload = response.json()
        assert payload["trace_id"] == trace_id
        assert payload["event_count"] >= 2
        event_types = {event["event_type"] for event in payload["events"]}
        assert "audit" in event_types
        assert "cost" in event_types
    finally:
        db.query(CostEvent).filter(CostEvent.trace_id == trace_id).delete()
        db.query(AuditEvent).filter(AuditEvent.trace_id == trace_id).delete()
        db.commit()
        db.close()


def test_discovery_summary_returns_posture_snapshot():
    db = SessionLocal()
    discovered_agent_id = "discovered-summary-test"
    try:
        db.add(
            DiscoveryRecord(
                discovered_agent_id=discovered_agent_id,
                canonical_agent_key="prod-payment-bot",
                source_system="gateway_telemetry",
                source_fingerprint="fp-summary-test",
                discovery_confidence=90,
                discovery_status="discovered",
                last_discovered_at=datetime.utcnow(),
            )
        )
        db.commit()

        response = client.get("/discovery/summary", headers=_auditor_headers("aud-disc-summary"))
        assert response.status_code == 200
        payload = response.json()
        assert payload["discovered_agent_count"] >= 1
        assert "healthy_sources" in payload
        assert "conflict_count" in payload
        assert "high_alert_count" in payload
        assert isinstance(payload["categories"], list)
        assert isinstance(payload["topology"], list)
        assert isinstance(payload["urgent_triage"], list)
        assert "posture_score" in payload
        assert isinstance(payload.get("confidence_buckets"), list)
    finally:
        db.query(DiscoveryRecord).filter(DiscoveryRecord.discovered_agent_id == discovered_agent_id).delete()
        db.commit()
        db.close()
