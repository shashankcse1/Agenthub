import json
from datetime import datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.main import app
from app.models import GatewayEntitlement, OrchestrationFlowAccessCertification
from tests.conftest import response_error_code
from tests.test_orchestration_flows import (
    ADMIN_HEADERS,
    OPS_HEADERS,
    RELEASE_HEADERS,
    SECURITY_HEADERS,
    _create_flow,
    _sample_graph,
    client,
)


def _dual_headers(actor_id: str, *, actor_role: str = "Security Approver", approver_id: str = "platform-admin-1"):
    return {
        "X-Actor-Role": actor_role,
        "X-Actor-Id": actor_id,
        "X-Approver-Role": "Platform Admin",
        "X-Approver-Id": approver_id,
        "X-MFA-Verified": "true",
    }


def _put_policy(flow_id: str, policy: dict, headers: dict) -> dict:
    response = client.put(
        f"/orchestration/flows/{flow_id}",
        json={"access_policy_json": json.dumps(policy)},
        headers=headers,
    )
    assert response.status_code == 200, response.text
    return response.json()


def test_orchestration_iga_sod_blocks_creator_approving_prod():
    creator_id = f"orch-creator-{uuid4().hex[:8]}"
    other_approver = f"orch-other-appr-{uuid4().hex[:8]}"
    owner_headers = {**RELEASE_HEADERS, "X-Actor-Id": creator_id}
    flow = _create_flow(headers=owner_headers, environment="prod", graph_json=_sample_graph(include_http=False))
    policy = {
        "version": 1,
        "owners": {"users": [creator_id], "groups": [], "teams": [], "match": "any"},
        "runners": {"users": [creator_id], "groups": [], "teams": [], "match": "any"},
        "schedulers": {"users": [], "groups": [], "teams": [], "match": "any"},
        "approvers": {
            "match": "any",
            "clauses": [
                {"users": [creator_id], "groups": [], "teams": []},
                {"users": [other_approver], "groups": [], "teams": []},
            ],
        },
        "iga": {"sod": {"prevent_creator_as_approver": True, "require_dual_approval_prod": False}},
    }
    _put_policy(flow["flow_id"], policy, owner_headers)

    denied = client.post(
        f"/orchestration/flows/{flow['flow_id']}/approve",
        json={"decision": "approved"},
        headers={**SECURITY_HEADERS, "X-Actor-Id": creator_id},
    )
    assert denied.status_code == 403
    assert response_error_code(denied) == "AUTHZ_IGA_SOD_VIOLATION"


def test_orchestration_iga_staged_approval_requires_both_stages():
    owner_id = f"orch-stage-owner-{uuid4().hex[:8]}"
    security_id = f"orch-security-{uuid4().hex[:8]}"
    business_id = f"orch-business-{uuid4().hex[:8]}"
    owner_headers = {**RELEASE_HEADERS, "X-Actor-Id": owner_id}
    flow = _create_flow(headers=owner_headers, graph_json=_sample_graph(include_http=False))
    policy = {
        "version": 1,
        "owners": {"users": [owner_id], "groups": [], "teams": [], "match": "any"},
        "runners": {"users": [], "groups": [], "teams": [], "match": "any"},
        "schedulers": {"users": [], "groups": [], "teams": [], "match": "any"},
        "approvers": {
            "mode": "staged",
            "require_all_stages": True,
            "stages": [
                {
                    "stage_id": "security",
                    "label": "Security review",
                    "match": "any",
                    "clauses": [{"users": [security_id], "groups": [], "teams": []}],
                },
                {
                    "stage_id": "business",
                    "label": "Business owner",
                    "match": "any",
                    "clauses": [{"users": [business_id], "groups": [], "teams": []}],
                },
            ],
        },
        "iga": {"sod": {"require_dual_approval_prod": False}},
    }
    _put_policy(flow["flow_id"], policy, owner_headers)

    stage1 = client.post(
        f"/orchestration/flows/{flow['flow_id']}/approve",
        json={"decision": "approved", "stage_id": "security"},
        headers={**SECURITY_HEADERS, "X-Actor-Id": security_id},
    )
    assert stage1.status_code == 200
    assert stage1.json()["approval_status"] == "pending"

    stage2 = client.post(
        f"/orchestration/flows/{flow['flow_id']}/approve",
        json={"decision": "approved", "stage_id": "business"},
        headers={**SECURITY_HEADERS, "X-Actor-Id": business_id},
    )
    assert stage2.status_code == 200
    assert stage2.json()["approval_status"] == "approved"


def test_orchestration_iga_jit_grant_allows_run_after_policy_deny():
    owner_id = f"orch-jit-owner-{uuid4().hex[:8]}"
    requester_id = f"orch-jit-requester-{uuid4().hex[:8]}"
    approver_id = f"orch-jit-approver-{uuid4().hex[:8]}"
    owner_headers = {**RELEASE_HEADERS, "X-Actor-Id": owner_id}
    flow = _create_flow(headers=owner_headers, graph_json=_sample_graph(include_http=False))
    policy = {
        "version": 1,
        "owners": {"users": [owner_id], "groups": [], "teams": [], "match": "any"},
        "runners": {"users": [owner_id], "groups": [], "teams": [], "match": "any"},
        "schedulers": {"users": [], "groups": [], "teams": [], "match": "any"},
        "approvers": {"match": "any", "clauses": [{"users": [approver_id], "groups": [], "teams": []}]},
    }
    _put_policy(flow["flow_id"], policy, owner_headers)

    denied = client.post(
        f"/orchestration/flows/{flow['flow_id']}/run",
        json={"dry_run": True},
        headers={**OPS_HEADERS, "X-Actor-Id": requester_id},
    )
    assert denied.status_code == 403

    created = client.post(
        f"/orchestration/flows/{flow['flow_id']}/jit-access-requests",
        json={
            "requested_action": "run",
            "justification": "Emergency triage run",
            "requested_duration_minutes": 30,
        },
        headers={**OPS_HEADERS, "X-Actor-Id": requester_id},
    )
    assert created.status_code == 200
    request_id = created.json()["request_id"]

    approved = client.post(
        f"/orchestration/jit-access-requests/{request_id}/approve",
        json={"decision": "approve"},
        headers={**SECURITY_HEADERS, "X-Actor-Id": approver_id},
    )
    assert approved.status_code == 200

    allowed = client.post(
        f"/orchestration/flows/{flow['flow_id']}/run",
        json={"dry_run": True},
        headers={**OPS_HEADERS, "X-Actor-Id": requester_id},
    )
    assert allowed.status_code == 200


def test_orchestration_iga_expired_certification_blocks_prod_run():
    owner_id = f"orch-cert-owner-{uuid4().hex[:8]}"
    runner_id = f"orch-cert-runner-{uuid4().hex[:8]}"
    owner_headers = {**RELEASE_HEADERS, "X-Actor-Id": owner_id}
    flow = _create_flow(headers=owner_headers, environment="prod", graph_json=_sample_graph(include_http=False))
    policy = {
        "version": 1,
        "owners": {"users": [owner_id], "groups": [], "teams": [], "match": "any"},
        "runners": {"users": [runner_id], "groups": [], "teams": [], "match": "any"},
        "schedulers": {"users": [], "groups": [], "teams": [], "match": "any"},
        "approvers": {"match": "any", "clauses": []},
        "iga": {"sod": {"require_dual_approval_prod": False}},
    }
    _put_policy(flow["flow_id"], policy, owner_headers)

    approve = client.post(
        f"/orchestration/flows/{flow['flow_id']}/approve",
        json={"decision": "approved"},
        headers=_dual_headers(f"orch-cert-appr-{uuid4().hex[:6]}"),
    )
    assert approve.status_code == 200

    denied = client.post(
        f"/orchestration/flows/{flow['flow_id']}/run",
        json={"dry_run": True},
        headers={**OPS_HEADERS, "X-Actor-Id": runner_id},
    )
    assert denied.status_code == 403
    assert response_error_code(denied) == "AUTHZ_IGA_CERTIFICATION_EXPIRED"

    certify = client.post(
        f"/orchestration/flows/{flow['flow_id']}/access-policy/certify",
        json={"attestation_notes": "Quarterly attestation"},
        headers={**owner_headers, "X-Approver-Role": "Platform Admin", "X-Approver-Id": "platform-admin-certify", "X-MFA-Verified": "true"},
    )
    assert certify.status_code == 200

    allowed = client.post(
        f"/orchestration/flows/{flow['flow_id']}/run",
        json={"dry_run": True},
        headers={**OPS_HEADERS, "X-Actor-Id": runner_id},
    )
    assert allowed.status_code == 200


def test_orchestration_iga_entitlement_check_enforced():
    owner_id = f"orch-ent-owner-{uuid4().hex[:8]}"
    runner_id = f"orch-ent-runner-{uuid4().hex[:8]}"
    owner_headers = {**RELEASE_HEADERS, "X-Actor-Id": owner_id}
    flow = _create_flow(headers=owner_headers, graph_json=_sample_graph(include_http=False))

    db: Session = SessionLocal()
    entitlement_id = f"ent-orch-{uuid4().hex[:8]}"
    try:
        db.add(
            GatewayEntitlement(
                entitlement_id=entitlement_id,
                action="orchestration.run",
                tenant_id=None,
                environment="dev",
                allowed_roles=json.dumps(["Security Approver"]),
                enabled=True,
            )
        )
        db.commit()
    finally:
        db.close()

    policy = {
        "version": 1,
        "owners": {"users": [owner_id], "groups": [], "teams": [], "match": "any"},
        "runners": {"users": [runner_id], "groups": [], "teams": [], "match": "any"},
        "schedulers": {"users": [], "groups": [], "teams": [], "match": "any"},
        "approvers": {"match": "any", "clauses": []},
        "iga": {"entitlement_id": entitlement_id},
    }
    _put_policy(flow["flow_id"], policy, owner_headers)

    denied = client.post(
        f"/orchestration/flows/{flow['flow_id']}/run",
        json={"dry_run": True},
        headers={**OPS_HEADERS, "X-Actor-Id": runner_id},
    )
    assert denied.status_code == 403
    assert response_error_code(denied) == "AUTHZ_IGA_ENTITLEMENT_REQUIRED"

    db = SessionLocal()
    try:
        row = db.query(GatewayEntitlement).filter_by(entitlement_id=entitlement_id).first()
        assert row is not None
        row.allowed_roles = json.dumps(["AI Ops Approver"])
        db.commit()
    finally:
        db.close()

    allowed = client.post(
        f"/orchestration/flows/{flow['flow_id']}/run",
        json={"dry_run": True},
        headers={**OPS_HEADERS, "X-Actor-Id": runner_id},
    )
    assert allowed.status_code == 200


def test_orchestration_iga_posture_and_explain_endpoints():
    actor_id = f"orch-iga-posture-{uuid4().hex[:8]}"
    headers = {**ADMIN_HEADERS, "X-Actor-Id": actor_id}
    flow = _create_flow(headers={**RELEASE_HEADERS, "X-Actor-Id": actor_id})
    posture = client.get(
        f"/orchestration/flows/{flow['flow_id']}/iga/posture",
        headers=headers,
    )
    assert posture.status_code == 200
    body = posture.json()
    assert body["flow_id"] == flow["flow_id"]
    assert "sod" in body
    assert "certification" in body

    explain = client.post(
        f"/orchestration/flows/{flow['flow_id']}/iga/explain",
        json={"action": "run"},
        headers=headers,
    )
    assert explain.status_code == 200
    assert explain.json()["action"] == "run"
    assert "factors" in explain.json()


def test_orchestration_iga_superseded_certification_blocks_prod_run():
    owner_id = f"orch-cert2-owner-{uuid4().hex[:8]}"
    runner_id = f"orch-cert2-runner-{uuid4().hex[:8]}"
    owner_headers = {**RELEASE_HEADERS, "X-Actor-Id": owner_id}
    flow = _create_flow(headers=owner_headers, environment="prod", graph_json=_sample_graph(include_http=False))
    policy = {
        "version": 1,
        "owners": {"users": [owner_id], "groups": [], "teams": [], "match": "any"},
        "runners": {"users": [runner_id], "groups": [], "teams": [], "match": "any"},
        "schedulers": {"users": [], "groups": [], "teams": [], "match": "any"},
        "approvers": {"match": "any", "clauses": []},
        "iga": {"sod": {"require_dual_approval_prod": False}},
    }
    _put_policy(flow["flow_id"], policy, owner_headers)

    approve = client.post(
        f"/orchestration/flows/{flow['flow_id']}/approve",
        json={"decision": "approved"},
        headers=_dual_headers(f"orch-cert2-appr-{uuid4().hex[:6]}"),
    )
    assert approve.status_code == 200

    db: Session = SessionLocal()
    try:
        db.add(
            OrchestrationFlowAccessCertification(
                certification_id=f"ocert-expired-{uuid4().hex[:8]}",
                flow_id=flow["flow_id"],
                certified_by=owner_id,
                certified_at=datetime.utcnow() - timedelta(days=120),
                next_due_at=datetime.utcnow() - timedelta(days=1),
                attestation_notes="expired",
                status="active",
            )
        )
        db.commit()
    finally:
        db.close()

    denied = client.post(
        f"/orchestration/flows/{flow['flow_id']}/run",
        json={"dry_run": True},
        headers={**OPS_HEADERS, "X-Actor-Id": runner_id},
    )
    assert denied.status_code == 403
    assert response_error_code(denied) == "AUTHZ_IGA_CERTIFICATION_EXPIRED"


def test_orchestration_jit_access_requests_list_endpoint():
    owner_id = f"orch-jit-list-{uuid4().hex[:8]}"
    owner_headers = {**RELEASE_HEADERS, "X-Actor-Id": owner_id}
    flow = _create_flow(headers=owner_headers, graph_json=_sample_graph(include_http=False))
    created = client.post(
        f"/orchestration/flows/{flow['flow_id']}/jit-access-requests",
        json={
            "requested_actions": ["run"],
            "duration_minutes": 30,
            "justification": "leadership-loop-l3-list-coverage",
            "environment": "dev",
        },
        headers=owner_headers,
    )
    assert created.status_code == 200, created.text
    listed = client.get(
        "/orchestration/jit-access-requests",
        params={"flow_id": flow["flow_id"], "limit": 20},
        headers=ADMIN_HEADERS,
    )
    assert listed.status_code == 200, listed.text
    body = listed.json()
    assert body.get("total", 0) >= 1
    assert any(row.get("flow_id") == flow["flow_id"] for row in body.get("data") or [])


def test_orchestration_access_certifications_due_endpoint():
    owner_id = f"orch-due-list-{uuid4().hex[:8]}"
    owner_headers = {**RELEASE_HEADERS, "X-Actor-Id": owner_id}
    flow = _create_flow(headers=owner_headers, environment="prod", graph_json=_sample_graph(include_http=False))
    db: Session = SessionLocal()
    try:
        db.add(
            OrchestrationFlowAccessCertification(
                certification_id=f"ocert-due-{uuid4().hex[:8]}",
                flow_id=flow["flow_id"],
                certified_by=owner_id,
                certified_at=datetime.utcnow() - timedelta(days=100),
                next_due_at=datetime.utcnow() - timedelta(hours=1),
                attestation_notes="due for leadership loop",
                status="active",
            )
        )
        db.commit()
    finally:
        db.close()

    due = client.get("/orchestration/access-certifications/due", params={"limit": 200}, headers=ADMIN_HEADERS)
    assert due.status_code == 200, due.text
    body = due.json()
    assert body.get("total", 0) >= 1
    assert any(row.get("flow_id") == flow["flow_id"] for row in body.get("data") or [])
