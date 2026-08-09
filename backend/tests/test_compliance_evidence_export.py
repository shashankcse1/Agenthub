from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _auditor_headers():
    return {"X-Actor-Role": "Auditor", "X-Actor-Id": f"aud-compliance-export-{uuid4().hex[:8]}"}


def test_compliance_evidence_export_creates_audit_event():
    control_id = "CTRL-AUDIT-IMMUTABLE"
    export_resp = client.post(
        "/compliance/evidence/export",
        json={
            "control_id": control_id,
            "since_hours": 24,
            "limit_events": 5,
            "limit_artifacts": 5,
        },
        headers=_auditor_headers(),
    )
    assert export_resp.status_code == 200
    body = export_resp.json()
    assert body["export_id"]
    assert body["control_id"] == control_id
    assert body["bundle"] is not None
    assert body["audit_event"]["action_type"] == "compliance.evidence.export"
    assert body["audit_event"]["decision_outcome"] == "allow"

    audit_resp = client.get(
        f"/audit/events?action_type=compliance.evidence.export&resource_id={control_id}&limit=10",
        headers=_auditor_headers(),
    )
    assert audit_resp.status_code == 200
    rows = audit_resp.json()
    assert any(row["action_type"] == "compliance.evidence.export" for row in rows)


def test_compliance_evidence_export_embeds_investigation_context_in_bundle():
    investigation_context = {
        "case_id": "INV-ASSISTANTS-001",
        "analyst": "aud-compliance-export",
        "scope": "assistants-parity-advanced",
    }
    export_resp = client.post(
        "/compliance/evidence/export",
        json={
            "control_id": "CTRL-AUDIT-IMMUTABLE",
            "since_hours": 24,
            "limit_events": 5,
            "limit_artifacts": 5,
            "investigation_context": investigation_context,
        },
        headers=_auditor_headers(),
    )
    assert export_resp.status_code == 200
    body = export_resp.json()
    assert body["investigation_context"] == investigation_context
    assert body["bundle"]["investigation_context"] == investigation_context


def test_compliance_evidence_export_missing_control_emits_deny_audit():
    export_resp = client.post(
        "/compliance/evidence/export",
        json={"control_id": "CTRL-DOES-NOT-EXIST-999", "since_hours": 24},
        headers=_auditor_headers(),
    )
    assert export_resp.status_code == 404

    audit_resp = client.get(
        "/audit/events?action_type=compliance.evidence.export&resource_id=CTRL-DOES-NOT-EXIST-999&limit=5",
        headers=_auditor_headers(),
    )
    assert audit_resp.status_code == 200
    assert any(row.get("decision_outcome") == "deny" for row in audit_resp.json())


def test_auth_explain_mfa_verified_field():
    denied = client.post(
        "/auth/authz/explain",
        json={
            "actor_role": "Platform Admin",
            "actor_id": "admin-mfa-explain",
            "action": "auth.policy.session.update",
            "resource_type": "auth_policy",
            "resource_id": "session-policy",
            "mfa_verified": False,
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": f"aud-mfa-explain-{uuid4().hex[:8]}"},
    )
    assert denied.status_code == 200
    denied_payload = denied.json()
    assert denied_payload["requires_mfa"] is True
    assert denied_payload["decision"] == "deny"
    assert "mfa_missing" in denied_payload["reasons"]

    allowed = client.post(
        "/auth/authz/explain",
        json={
            "actor_role": "Platform Admin",
            "actor_id": "admin-mfa-explain",
            "action": "auth.policy.session.update",
            "resource_type": "auth_policy",
            "resource_id": "session-policy",
            "mfa_verified": True,
            "approver_role": "Security Approver",
            "approver_id": "sec-mfa-explain",
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": f"aud-mfa-explain-2-{uuid4().hex[:8]}"},
    )
    assert allowed.status_code == 200
    allowed_payload = allowed.json()
    assert allowed_payload["requires_mfa"] is True
    assert "mfa_present" in allowed_payload["reasons"]
