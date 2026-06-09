from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _headers(actor_id: str, *, mfa: bool = True) -> dict[str, str]:
    headers = {
        "X-Actor-Role": "Master Admin",
        "X-Actor-Id": actor_id,
    }
    if mfa:
        headers["X-MFA-Verified"] = "true"
    return headers


def test_master_admin_can_access_provider_read_endpoints():
    actor_id = f"master-read-{uuid4().hex[:8]}"
    response = client.get("/providers/tenants?limit=5", headers=_headers(actor_id))
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_master_admin_can_update_auth_policy_without_dual_approval_headers():
    suffix = uuid4().hex[:8]
    actor_id = f"master-auth-{suffix}"
    payload = {
        "session_read_roles": ["Master Admin", "Platform Admin", "Auditor"],
        "session_issuer_roles": ["Master Admin", "Platform Admin", "Release Manager"],
        "issuable_session_roles": [
            "Master Admin",
            "Platform Admin",
            "Agent Owner",
            "Security Approver",
            "AI Ops Approver",
            "Release Manager",
            "Auditor",
        ],
        "cross_actor_dual_approval_roles": ["Master Admin", "Platform Admin", "Security Approver"],
        "dual_approval_required_approver_role": "Security Approver",
        "privileged_mfa_reauth_minutes": 15,
    }

    response = client.patch(
        "/auth/policies/session",
        json=payload,
        headers=_headers(actor_id, mfa=True),
    )

    assert response.status_code == 200
    body = response.json()
    assert "Master Admin" in body["session_read_roles"]
    assert "Master Admin" in body["session_issuer_roles"]
    assert "Master Admin" in body["issuable_session_roles"]


def test_master_admin_role_is_canonicalized_for_cost_timeseries_access():
    response = client.get(
        "/cost/timeseries?dimension=all&window_hours=24",
        headers={
            "X-Actor-Role": "master admin",
            "X-Actor-Id": f"master-cost-{uuid4().hex[:8]}",
            "X-MFA-Verified": "true",
        },
    )

    assert response.status_code == 200
