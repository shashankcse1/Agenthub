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
    assert "secret_provider.value.*" in rule_patterns
    assert "auth.directory.user.unlock*" in rule_patterns
    assert "gateway.least_privilege.apply*" in rule_patterns
    assert "security.insecure_configuration*" in rule_patterns


def test_unlock_and_least_privilege_match_default_siem_rules():
    unlock = AuditEvent(
        audit_event_id=str(uuid4()),
        actor_type="user",
        actor_id="actor-unlock-siem",
        action_type="auth.directory.user.unlock",
        resource_type="directory_user",
        resource_id="user-1",
        trace_id=f"trace-unlock-siem-{uuid4().hex[:8]}",
        decision_outcome="allow",
        policy_version="v1",
    )
    abuse = AuditEvent(
        audit_event_id=str(uuid4()),
        actor_type="user",
        actor_id="actor-unlock-siem",
        action_type="auth.directory.user.unlock.abuse_suspected",
        resource_type="directory_user",
        resource_id="user-1",
        trace_id=f"trace-unlock-abuse-{uuid4().hex[:8]}",
        decision_outcome="deny",
        policy_version="v1",
    )
    lp = AuditEvent(
        audit_event_id=str(uuid4()),
        actor_type="user",
        actor_id="actor-lp-siem",
        action_type="gateway.least_privilege.apply",
        resource_type="gateway_recommendation",
        resource_id="rec-1",
        trace_id=f"trace-lp-siem-{uuid4().hex[:8]}",
        decision_outcome="allow",
        policy_version="v1",
    )
    assert any(row["rule_id"] == "siem-directory-user-unlock" for row in match_siem_rules_for_event(unlock, DEFAULT_SIEM_ALERT_RULES))
    assert any(row["rule_id"] == "siem-directory-user-unlock" for row in match_siem_rules_for_event(abuse, DEFAULT_SIEM_ALERT_RULES))
    assert any(row["rule_id"] == "siem-least-privilege-apply" for row in match_siem_rules_for_event(lp, DEFAULT_SIEM_ALERT_RULES))


def test_secret_provider_value_audit_matches_default_siem_rule():
    event = AuditEvent(
        audit_event_id=str(uuid4()),
        actor_type="user",
        actor_id="actor-secret-siem",
        action_type="secret_provider.value.upsert",
        resource_type="secret_provider_value",
        resource_id="prov-1/kv/path",
        trace_id=f"trace-secret-siem-{uuid4().hex[:8]}",
        decision_outcome="allow",
        policy_version="v1",
    )
    matched = match_siem_rules_for_event(event, DEFAULT_SIEM_ALERT_RULES)
    assert any(row["rule_id"] == "siem-secret-provider-value-mutations" for row in matched)


def test_audit_create_evaluates_siem_for_secret_provider_value_prefix():
    """Ensure create_audit_event dispatches SIEM for secret_provider.value.* (not only denies)."""
    from unittest.mock import MagicMock

    from app.services import audit as audit_mod

    db = MagicMock()
    db.query.return_value.filter_by.return_value.first.return_value = None
    dispatched: list[object] = []

    with patch(
        "app.services.siem_alert_rules.dispatch_siem_alerts_for_event",
        side_effect=lambda *_a, **_k: dispatched.append(True) or [],
    ):
        audit_mod.create_audit_event(
            db,
            actor_id="actor-1",
            action_type="secret_provider.value.read",
            resource_type="secret_provider_value",
            resource_id="prov-1/ref",
            trace_id="trace-secret-prefix",
            decision_outcome="allow",
        )
    assert dispatched, "SIEM dispatch should run for secret_provider.value.* allow events"


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
