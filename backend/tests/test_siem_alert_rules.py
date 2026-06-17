import os
from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import AuditEvent
from app.services.audit import create_audit_event
from app.services.siem_alert_rules import (
    DEFAULT_SIEM_ALERT_RULES,
    dispatch_siem_alerts_for_event,
    export_siem_rules_catalog,
    load_siem_alert_rules,
    match_siem_rules_for_event,
)

client = TestClient(app)


def _admin_headers():
    return {
        "X-Actor-Role": "Platform Admin",
        "X-Actor-Id": f"siem-admin-{uuid4().hex[:8]}",
    }


def _auditor_headers():
    return {
        "X-Actor-Role": "Auditor",
        "X-Actor-Id": f"siem-auditor-{uuid4().hex[:8]}",
    }


def test_default_siem_rules_include_assistants_parity_actions():
    rule_patterns = {row["action_type_pattern"] for row in DEFAULT_SIEM_ALERT_RULES}
    assert "gateway.assistants.*" in rule_patterns
    assert "gateway.threads.*" in rule_patterns
    assert "gateway.fine_tuning.*" in rule_patterns
    assert "gateway.passthrough.execute" in rule_patterns
    assert "compliance.evidence.export" in rule_patterns


def test_match_siem_rules_for_deny_outcome():
    event = AuditEvent(
        audit_event_id=str(uuid4()),
        actor_type="user",
        actor_id="actor-1",
        action_type="gateway.assistants.delete",
        resource_type="gateway_assistant",
        resource_id="asst_1",
        trace_id="trace-1",
        decision_outcome="deny",
        policy_version="v1",
    )
    matched = match_siem_rules_for_event(event, DEFAULT_SIEM_ALERT_RULES)
    assert any(row["rule_id"] == "siem-gateway-assistants-mutations" for row in matched)
    assert any(row["rule_id"] == "siem-gateway-privileged-deny" for row in matched)


def test_dispatch_siem_alert_emits_unrouted_warn_when_no_callbacks():
    db_session = SessionLocal()
    try:
        event = create_audit_event(
            db_session,
            actor_id="actor-1",
            action_type="compliance.evidence.export",
            resource_type="compliance_control",
            resource_id="CTRL-1",
            trace_id=f"trace-siem-{uuid4().hex[:8]}",
            decision_outcome="deny",
        )
        dispatches = dispatch_siem_alerts_for_event(db_session, event)
        db_session.commit()
        assert dispatches
        assert dispatches[0]["delivery_status"] == "unrouted"
    finally:
        db_session.close()


def test_observability_siem_rules_list_and_export_endpoints():
    listed = client.get("/observability/siem-rules", headers=_auditor_headers())
    assert listed.status_code == 200
    body = listed.json()
    assert body["rule_count"] >= len(DEFAULT_SIEM_ALERT_RULES)

    exported = client.post("/observability/siem-rules/export", headers=_auditor_headers())
    assert exported.status_code == 200
    export_body = exported.json()
    assert export_body["rule_count"] >= len(DEFAULT_SIEM_ALERT_RULES)
    assert "gateway-assistants" in {row["sink_route_key"] for row in export_body["rules"]}


def test_observability_siem_rules_evaluate_endpoint():
    with patch.dict(os.environ, {"GATEWAY_INFERENCE_SIMULATION": "true"}, clear=False):
        denied = client.post(
            "/v1/assistants",
            json={"name": "Denied", "model": "gpt-4o-mini", "instructions": "x", "environment": "dev"},
            headers={"X-Actor-Role": "Auditor", "X-Actor-Id": f"siem-deny-{uuid4().hex[:8]}"},
        )
        assert denied.status_code == 403

    evaluated = client.get(
        "/observability/siem-rules/evaluate?action_type_prefix=gateway.assistants.&decision_outcome=deny&limit=20",
        headers=_auditor_headers(),
    )
    assert evaluated.status_code == 200
    payload = evaluated.json()
    assert payload["evaluated_count"] >= 0


def test_export_siem_rules_catalog_structure():
    db_session = SessionLocal()
    try:
        bundle = export_siem_rules_catalog(db_session)
        assert bundle["rule_count"] == len(load_siem_alert_rules(db_session))
        assert bundle["rules"]
    finally:
        db_session.close()
