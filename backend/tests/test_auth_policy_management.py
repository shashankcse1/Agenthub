from fastapi.testclient import TestClient

from app.main import app
from app.policy_constants import (
    AUTH_POLICY_DEFAULT_ID,
    AUTH_SESSION_ISSUER_ROLES_DEFAULT,
    AUTH_SESSION_READ_ROLES_DEFAULT,
    CROSS_ACTOR_DUAL_APPROVAL_ROLES_DEFAULT,
    DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT,
    ISSUABLE_SESSION_ROLES_DEFAULT,
    PRIVILEGED_MFA_REAUTH_MINUTES_DEFAULT,
)

client = TestClient(app)


def _admin_headers(mfa: bool = True, with_approver: bool = True) -> dict[str, str]:
    headers = {
        "X-Actor-Role": "Platform Admin",
        "X-Actor-Id": "iam-admin-1",
        "X-MFA-Verified": "true" if mfa else "false",
    }
    if with_approver:
        headers["X-Approver-Role"] = "Security Approver"
        headers["X-Approver-Id"] = "iam-approver-1"
    return headers


def _default_policy_payload() -> dict:
    return {
        "session_read_roles": sorted(AUTH_SESSION_READ_ROLES_DEFAULT),
        "session_issuer_roles": sorted(AUTH_SESSION_ISSUER_ROLES_DEFAULT),
        "issuable_session_roles": sorted(ISSUABLE_SESSION_ROLES_DEFAULT),
        "cross_actor_dual_approval_roles": sorted(CROSS_ACTOR_DUAL_APPROVAL_ROLES_DEFAULT),
        "dual_approval_required_approver_role": DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT,
        "privileged_mfa_reauth_minutes": PRIVILEGED_MFA_REAUTH_MINUTES_DEFAULT,
    }


def test_get_auth_session_policy_returns_default_or_db_policy():
    resp = client.get(
        "/auth/policies/session",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "iam-admin-read"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["policy_id"] == AUTH_POLICY_DEFAULT_ID
    assert body["source"] in {"default", "database"}
    assert isinstance(body["session_read_roles"], list)
    assert isinstance(body["session_issuer_roles"], list)


def test_update_auth_session_policy_requires_mfa_and_dual_approval():
    missing_mfa = client.patch(
        "/auth/policies/session",
        json={"session_issuer_roles": ["Platform Admin"]},
        headers=_admin_headers(mfa=False, with_approver=True),
    )
    assert missing_mfa.status_code == 403
    assert missing_mfa.json()["detail"]["error_code"] == "AUTHZ_MFA_REQUIRED"

    missing_dual = client.patch(
        "/auth/policies/session",
        json={"session_issuer_roles": ["Platform Admin"]},
        headers=_admin_headers(mfa=True, with_approver=False),
    )
    assert missing_dual.status_code == 403
    assert missing_dual.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"


def test_update_auth_session_policy_can_restrict_release_manager_issuer_role_and_restore():
    original = client.get(
        "/auth/policies/session",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "iam-admin-read-2"},
    )
    assert original.status_code == 200
    original_policy = original.json()

    restrictive = {
        "session_read_roles": sorted(AUTH_SESSION_READ_ROLES_DEFAULT),
        "session_issuer_roles": ["Platform Admin"],
        "issuable_session_roles": sorted(ISSUABLE_SESSION_ROLES_DEFAULT),
        "cross_actor_dual_approval_roles": sorted(CROSS_ACTOR_DUAL_APPROVAL_ROLES_DEFAULT),
        "dual_approval_required_approver_role": DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT,
        "privileged_mfa_reauth_minutes": PRIVILEGED_MFA_REAUTH_MINUTES_DEFAULT,
    }

    try:
        updated = client.patch(
            "/auth/policies/session",
            json=restrictive,
            headers=_admin_headers(),
        )
        assert updated.status_code == 200
        assert updated.json()["session_issuer_roles"] == ["Platform Admin"]

        denied_issue = client.post(
            "/auth/sessions",
            json={
                "actor_id": "rm-policy-target",
                "actor_role": "Agent Owner",
                "ttl_minutes": 10,
            },
            headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "release-issuer"},
        )
        assert denied_issue.status_code == 403
        assert denied_issue.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"
    finally:
        restore_payload = {
            "session_read_roles": original_policy["session_read_roles"],
            "session_issuer_roles": original_policy["session_issuer_roles"],
            "issuable_session_roles": original_policy["issuable_session_roles"],
            "cross_actor_dual_approval_roles": original_policy["cross_actor_dual_approval_roles"],
            "dual_approval_required_approver_role": original_policy["dual_approval_required_approver_role"],
            "privileged_mfa_reauth_minutes": original_policy["privileged_mfa_reauth_minutes"],
        }
        restore = client.patch(
            "/auth/policies/session",
            json=restore_payload,
            headers=_admin_headers(),
        )
        assert restore.status_code == 200


def test_auth_policy_revision_history_and_rollback_flow():
    original = client.get(
        "/auth/policies/session",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "iam-admin-rev-read"},
    )
    assert original.status_code == 200
    original_policy = original.json()

    restrictive = {
        "session_read_roles": sorted(AUTH_SESSION_READ_ROLES_DEFAULT),
        "session_issuer_roles": ["Platform Admin"],
        "issuable_session_roles": sorted(ISSUABLE_SESSION_ROLES_DEFAULT),
        "cross_actor_dual_approval_roles": sorted(CROSS_ACTOR_DUAL_APPROVAL_ROLES_DEFAULT),
        "dual_approval_required_approver_role": DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT,
        "privileged_mfa_reauth_minutes": PRIVILEGED_MFA_REAUTH_MINUTES_DEFAULT,
    }

    try:
        update = client.patch(
            "/auth/policies/session",
            json=restrictive,
            headers=_admin_headers(),
        )
        assert update.status_code == 200

        revisions = client.get(
            "/auth/policies/session/revisions?limit=20",
            headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "iam-admin-rev-list"},
        )
        assert revisions.status_code == 200
        revision_items = revisions.json()
        assert len(revision_items) >= 1
        target_revision = next(
            (row for row in revision_items if row["session_issuer_roles"] == original_policy["session_issuer_roles"]),
            None,
        )
        assert target_revision is not None

        rollback = client.post(
            "/auth/policies/session/rollback",
            json={"revision_id": target_revision["revision_id"], "change_reason": "restore-default-issuer"},
            headers=_admin_headers(),
        )
        assert rollback.status_code == 200
        assert rollback.json()["session_issuer_roles"] == original_policy["session_issuer_roles"]
    finally:
        restore = client.patch(
            "/auth/policies/session",
            json={
                "session_read_roles": original_policy["session_read_roles"],
                "session_issuer_roles": original_policy["session_issuer_roles"],
                "issuable_session_roles": original_policy["issuable_session_roles"],
                "cross_actor_dual_approval_roles": original_policy["cross_actor_dual_approval_roles"],
                "dual_approval_required_approver_role": original_policy["dual_approval_required_approver_role"],
                "privileged_mfa_reauth_minutes": original_policy["privileged_mfa_reauth_minutes"],
            },
            headers=_admin_headers(),
        )
        assert restore.status_code == 200


def test_existing_session_issue_use_case_still_works_after_policy_updates():
    baseline = client.get(
        "/auth/policies/session",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "iam-admin-baseline"},
    )
    assert baseline.status_code == 200
    baseline_policy = baseline.json()

    try:
        keep_same = client.patch(
            "/auth/policies/session",
            json={
                "session_read_roles": baseline_policy["session_read_roles"],
                "session_issuer_roles": baseline_policy["session_issuer_roles"],
                "issuable_session_roles": baseline_policy["issuable_session_roles"],
                "cross_actor_dual_approval_roles": baseline_policy["cross_actor_dual_approval_roles"],
                "dual_approval_required_approver_role": baseline_policy["dual_approval_required_approver_role"],
                "privileged_mfa_reauth_minutes": baseline_policy["privileged_mfa_reauth_minutes"],
            },
            headers=_admin_headers(),
        )
        assert keep_same.status_code == 200

        issue = client.post(
            "/auth/sessions",
            json={"actor_id": "policy-existing-flow", "actor_role": "Agent Owner", "ttl_minutes": 15},
            headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-existing-flow"},
        )
        assert issue.status_code == 200
        assert issue.json()["token_type"] == "Bearer"
    finally:
        restore = client.patch(
            "/auth/policies/session",
            json={
                "session_read_roles": baseline_policy["session_read_roles"],
                "session_issuer_roles": baseline_policy["session_issuer_roles"],
                "issuable_session_roles": baseline_policy["issuable_session_roles"],
                "cross_actor_dual_approval_roles": baseline_policy["cross_actor_dual_approval_roles"],
                "dual_approval_required_approver_role": baseline_policy["dual_approval_required_approver_role"],
                "privileged_mfa_reauth_minutes": baseline_policy["privileged_mfa_reauth_minutes"],
            },
            headers=_admin_headers(),
        )
        assert restore.status_code == 200


def test_auth_policy_revisions_default_limit_can_be_db_configured():
    baseline = client.get(
        "/auth/policies/session",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "iam-admin-limit-read"},
    )
    assert baseline.status_code == 200
    policy = baseline.json()

    limit_key = "auth.policy.revisions_default_limit"
    admin_headers = _admin_headers()

    try:
        first = client.patch(
            "/auth/policies/session",
            json={
                "session_read_roles": policy["session_read_roles"],
                "session_issuer_roles": policy["session_issuer_roles"],
                "issuable_session_roles": policy["issuable_session_roles"],
                "cross_actor_dual_approval_roles": policy["cross_actor_dual_approval_roles"],
                "dual_approval_required_approver_role": policy["dual_approval_required_approver_role"],
                "privileged_mfa_reauth_minutes": policy["privileged_mfa_reauth_minutes"],
            },
            headers=admin_headers,
        )
        assert first.status_code == 200

        second = client.patch(
            "/auth/policies/session",
            json={
                "session_read_roles": policy["session_read_roles"],
                "session_issuer_roles": policy["session_issuer_roles"],
                "issuable_session_roles": policy["issuable_session_roles"],
                "cross_actor_dual_approval_roles": policy["cross_actor_dual_approval_roles"],
                "dual_approval_required_approver_role": policy["dual_approval_required_approver_role"],
                "privileged_mfa_reauth_minutes": policy["privileged_mfa_reauth_minutes"],
            },
            headers=admin_headers,
        )
        assert second.status_code == 200

        configured = client.put(
            f"/runtime-config/{limit_key}",
            json={"config_value": "1", "description": "test override"},
            headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "iam-admin-limit-override"},
        )
        assert configured.status_code == 200

        revisions = client.get(
            "/auth/policies/session/revisions",
            headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "iam-admin-limit-list"},
        )
        assert revisions.status_code == 200
        assert len(revisions.json()) == 1
    finally:
        client.delete(
            f"/runtime-config/{limit_key}",
            headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "iam-admin-limit-cleanup"},
        )
