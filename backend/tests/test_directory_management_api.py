from datetime import datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import AuditEvent, DirectoryUser

client = TestClient(app)


def _login_headers(suffix: str) -> dict[str, str]:
    return {"X-Actor-Id": f"login-attempt-{suffix}"}


def _headers(actor_id: str) -> dict[str, str]:
    return {
        "X-Actor-Role": "Master Admin",
        "X-Actor-Id": actor_id,
        "X-MFA-Verified": "true",
    }


def test_directory_user_group_team_management_and_memberships():
    suffix = uuid4().hex[:8]
    actor_id = f"master-directory-{suffix}"
    user_id = f"user-{suffix}"
    group_id = f"group-{suffix}"
    team_id = f"team-{suffix}"

    created_user = client.post(
        "/auth/directory/users",
        json={
            "user_id": user_id,
            "display_name": "Directory User",
            "email": f"{user_id}@example.com",
            "role_name": "Agent Owner",
            "status": "active",
            "password": "StrongPass!234",
        },
        headers=_headers(actor_id),
    )
    assert created_user.status_code == 200

    created_group = client.post(
        "/auth/directory/groups",
        json={
            "group_id": group_id,
            "display_name": "Directory Group",
            "description": "Group for identity tests",
            "status": "active",
        },
        headers=_headers(actor_id),
    )
    assert created_group.status_code == 200

    created_team = client.post(
        "/auth/directory/teams",
        json={
            "team_id": team_id,
            "display_name": "Directory Team",
            "description": "Team for identity tests",
            "status": "active",
        },
        headers=_headers(actor_id),
    )
    assert created_team.status_code == 200

    user_list = client.get("/auth/directory/users?status=active", headers=_headers(actor_id))
    assert user_list.status_code == 200
    assert any(row["user_id"] == user_id for row in user_list.json())

    group_member = client.post(
        f"/auth/directory/groups/{group_id}/members/{user_id}",
        headers=_headers(actor_id),
    )
    assert group_member.status_code == 200

    listed_group_members = client.get(
        f"/auth/directory/groups/{group_id}/members",
        headers=_headers(actor_id),
    )
    assert listed_group_members.status_code == 200
    assert any(row["user_id"] == user_id for row in listed_group_members.json())

    team_member = client.post(
        f"/auth/directory/teams/{team_id}/members/{user_id}",
        headers=_headers(actor_id),
    )
    assert team_member.status_code == 200

    listed_team_members = client.get(
        f"/auth/directory/teams/{team_id}/members",
        headers=_headers(actor_id),
    )
    assert listed_team_members.status_code == 200
    assert any(row["user_id"] == user_id for row in listed_team_members.json())

    removed_group_member = client.delete(
        f"/auth/directory/groups/{group_id}/members/{user_id}",
        headers=_headers(actor_id),
    )
    assert removed_group_member.status_code == 200

    removed_team_member = client.delete(
        f"/auth/directory/teams/{team_id}/members/{user_id}",
        headers=_headers(actor_id),
    )
    assert removed_team_member.status_code == 200

    updated_user = client.put(
        f"/auth/directory/users/{user_id}",
        json={
            "user_id": user_id,
            "display_name": "Directory User Updated",
            "email": f"{user_id}@example.com",
            "role_name": "AI Ops Approver",
            "status": "active",
        },
        headers=_headers(actor_id),
    )
    assert updated_user.status_code == 200
    assert updated_user.json()["role_name"] == "AI Ops Approver"

    deleted_user = client.delete(f"/auth/directory/users/{user_id}", headers=_headers(actor_id))
    assert deleted_user.status_code == 200
    deleted_group = client.delete(f"/auth/directory/groups/{group_id}", headers=_headers(actor_id))
    assert deleted_group.status_code == 200
    deleted_team = client.delete(f"/auth/directory/teams/{team_id}", headers=_headers(actor_id))
    assert deleted_team.status_code == 200

    db = SessionLocal()
    try:
        actions = {
            row.action_type
            for row in db.query(AuditEvent)
            .filter(
                AuditEvent.resource_id.in_([user_id, group_id, team_id]),
                AuditEvent.action_type.like("auth.directory.%"),
            )
            .all()
        }
    finally:
        db.close()

    assert "auth.directory.user.create" in actions
    assert "auth.directory.group.create" in actions
    assert "auth.directory.team.create" in actions



def test_security_approver_prod_operator_can_create_directory_user():
    suffix = uuid4().hex[:8]
    actor_id = "prod-operator"
    user_id = f"prod-user-{suffix}"

    created_user = client.post(
        "/auth/directory/users",
        json={
            "user_id": user_id,
            "display_name": "Prod Directory User",
            "email": f"{user_id}@example.com",
            "role_name": "Agent Owner",
            "status": "active",
            "password": "StrongPass!234",
        },
        headers={
            "X-Actor-Role": "Security Approver",
            "X-Actor-Id": actor_id,
            "X-MFA-Verified": "true",
        },
    )
    assert created_user.status_code == 200
    payload = created_user.json()
    assert payload["user_id"] == user_id
    assert payload["updated_by"] == actor_id


def test_password_login_issues_session_token():
    suffix = uuid4().hex[:8]
    actor_id = f"master-login-{suffix}"
    user_id = f"login-{suffix}"
    password = "AnotherStrong!234"

    created_user = client.post(
        "/auth/directory/users",
        json={
            "user_id": user_id,
            "display_name": "Login User",
            "email": f"{user_id}@example.com",
            "role_name": "Platform Admin",
            "status": "active",
            "password": password,
        },
        headers=_headers(actor_id),
    )
    assert created_user.status_code == 200

    login_ok = client.post(
        "/auth/login",
        json={
            "username": user_id,
            "password": password,
        },
        headers=_login_headers(suffix),
    )
    assert login_ok.status_code == 200
    body = login_ok.json()
    assert body["token_type"] == "Bearer"
    assert body["access_token"]
    assert body["actor_id"] == user_id
    assert body["actor_role"] == "Platform Admin"

    login_bad = client.post(
        "/auth/login",
        json={
            "username": user_id,
            "password": "WrongPass!999",
        },
        headers=_login_headers(suffix),
    )
    assert login_bad.status_code == 401


def test_password_login_lockout_after_repeated_failures_and_recovery():
    suffix = uuid4().hex[:8]
    actor_id = f"master-lockout-{suffix}"
    user_id = f"lockout-{suffix}"
    password = "LockoutStrong!234"

    created_user = client.post(
        "/auth/directory/users",
        json={
            "user_id": user_id,
            "display_name": "Lockout User",
            "email": f"{user_id}@example.com",
            "role_name": "Platform Admin",
            "status": "active",
            "password": password,
        },
        headers=_headers(actor_id),
    )
    assert created_user.status_code == 200

    for _ in range(5):
        failed = client.post(
            "/auth/login",
            json={"username": user_id, "password": "WrongPass!999"},
            headers=_login_headers(suffix),
        )
        assert failed.status_code == 401

    locked = client.post(
        "/auth/login",
        json={"username": user_id, "password": password},
        headers=_login_headers(suffix),
    )
    assert locked.status_code == 401

    unlocked = client.post(
        f"/auth/directory/users/{user_id}/unlock",
        headers=_headers(actor_id),
    )
    assert unlocked.status_code == 200
    assert unlocked.json()["unlocked"] is True

    recovered = client.post(
        "/auth/login",
        json={"username": user_id, "password": password},
        headers=_login_headers(suffix),
    )
    assert recovered.status_code == 200


def test_password_login_lockout_expires_without_manual_unlock():
    suffix = uuid4().hex[:8]
    actor_id = f"master-lockout-expiry-{suffix}"
    user_id = f"lockout-expiry-{suffix}"
    password = "LockoutStrong!234"

    created_user = client.post(
        "/auth/directory/users",
        json={
            "user_id": user_id,
            "display_name": "Lockout Expiry User",
            "email": f"{user_id}@example.com",
            "role_name": "Platform Admin",
            "status": "active",
            "password": password,
        },
        headers=_headers(actor_id),
    )
    assert created_user.status_code == 200

    for _ in range(5):
        failed = client.post(
            "/auth/login",
            json={"username": user_id, "password": "WrongPass!999"},
            headers=_login_headers(suffix),
        )
        assert failed.status_code == 401

    locked = client.post(
        "/auth/login",
        json={"username": user_id, "password": password},
        headers=_login_headers(suffix),
    )
    assert locked.status_code == 401

    db = SessionLocal()
    try:
        row = db.query(DirectoryUser).filter_by(user_id=user_id).first()
        assert row is not None
        assert row.locked_until is not None
        row.locked_until = datetime.utcnow() - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()

    recovered = client.post(
        "/auth/login",
        json={"username": user_id, "password": password},
        headers=_login_headers(suffix),
    )
    assert recovered.status_code == 200
