"""sec-000: dedicated abuse-case coverage for GET /auth/directory/users."""

from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import DirectoryUser
from app.security import hash_user_password

client = TestClient(app)


def _headers(actor_id: str, role: str, *, mfa: bool = True) -> dict[str, str]:
    headers = {
        "X-Actor-Role": role,
        "X-Actor-Id": actor_id,
    }
    if mfa:
        headers["X-MFA-Verified"] = "true"
    return headers


def _seed_user(*, user_id: str, role_name: str = "Agent Owner", status: str = "active") -> None:
    db = SessionLocal()
    try:
        existing = db.query(DirectoryUser).filter_by(user_id=user_id).first()
        if existing:
            existing.role_name = role_name
            existing.status = status
            existing.password_hash = hash_user_password("StrongPass!23456")
            existing.failed_login_attempts = 0
            existing.locked_until = None
        else:
            db.add(
                DirectoryUser(
                    user_id=user_id,
                    display_name=user_id,
                    email=f"{user_id}@example.com",
                    role_name=role_name,
                    status=status,
                    password_hash=hash_user_password("StrongPass!23456"),
                )
            )
        db.commit()
    finally:
        db.close()


def test_list_directory_users_denies_agent_owner_and_auditor():
    suffix = uuid4().hex[:8]
    _seed_user(user_id=f"dir-list-target-{suffix}")

    owner_denied = client.get(
        "/auth/directory/users?limit=50",
        headers=_headers(f"owner-{suffix}", "Agent Owner"),
    )
    assert owner_denied.status_code == 403, owner_denied.text
    assert owner_denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    auditor_denied = client.get(
        "/auth/directory/users?limit=50",
        headers=_headers(f"auditor-{suffix}", "Auditor"),
    )
    assert auditor_denied.status_code == 403, auditor_denied.text
    assert auditor_denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"


def test_list_directory_users_allows_security_and_admin_without_password_hash():
    suffix = uuid4().hex[:8]
    target_id = f"dir-list-visible-{suffix}"
    _seed_user(user_id=target_id, status="active")
    _seed_user(user_id=f"dir-list-inactive-{suffix}", status="inactive")

    allowed = client.get(
        f"/auth/directory/users?status=active&limit=500",
        headers=_headers(f"sec-{suffix}", "Security Approver"),
    )
    assert allowed.status_code == 200, allowed.text
    rows = allowed.json()
    assert isinstance(rows, list)
    match = next((row for row in rows if row.get("user_id") == target_id), None)
    assert match is not None
    assert "password_hash" not in match
    assert "password" not in match
    assert match.get("email") == f"{target_id}@example.com"
    assert all(row.get("status") == "active" for row in rows if row.get("user_id", "").startswith("dir-list-"))

    admin = client.get(
        "/auth/directory/users?limit=2&offset=0",
        headers=_headers(f"admin-{suffix}", "Platform Admin"),
    )
    assert admin.status_code == 200, admin.text
    assert len(admin.json()) <= 2


def test_list_directory_users_clamps_limit_bounds():
    suffix = uuid4().hex[:8]
    over = client.get(
        "/auth/directory/users?limit=9999",
        headers=_headers(f"clamp-{suffix}", "Master Admin"),
    )
    assert over.status_code == 200, over.text
    assert isinstance(over.json(), list)
    assert len(over.json()) <= 500
