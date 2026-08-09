"""Wave-4 (CC-046): httpOnly session cookies + second-session dual-approval co-sign."""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import DirectoryUser
from app.security import ActorContext, hash_user_password, require_dual_approval
from app.services.session_cookies import APPROVER_SESSION_COOKIE_NAME, SESSION_COOKIE_NAME

client = TestClient(app)


def _seed_user(*, user_id: str, role_name: str, password: str = "StrongPass!23456") -> None:
    db = SessionLocal()
    try:
        existing = db.query(DirectoryUser).filter_by(user_id=user_id).first()
        if existing:
            existing.role_name = role_name
            existing.status = "active"
            existing.password_hash = hash_user_password(password)
            existing.failed_login_attempts = 0
            existing.locked_until = None
        else:
            db.add(
                DirectoryUser(
                    user_id=user_id,
                    display_name=user_id,
                    email=f"{user_id}@example.com",
                    role_name=role_name,
                    status="active",
                    password_hash=hash_user_password(password),
                )
            )
        db.commit()
    finally:
        db.close()


def test_login_sets_httponly_session_cookie_and_cookie_auth_works():
    suffix = uuid4().hex[:8]
    user_id = f"cookie-user-{suffix}"
    password = "StrongPass!23456"
    _seed_user(user_id=user_id, role_name="Platform Admin", password=password)

    login = client.post(
        "/auth/login",
        json={
            "username": user_id,
            "password": password,
            "ttl_minutes": 60,
            "idle_timeout_minutes": 30,
        },
    )
    assert login.status_code == 200, login.text
    assert SESSION_COOKIE_NAME in login.cookies
    assert login.json().get("access_token")

    # Cookie-only auth (no Authorization header).
    bare = TestClient(app)
    bare.cookies.set(SESSION_COOKIE_NAME, login.cookies[SESSION_COOKIE_NAME])
    session_id = login.json()["session_id"]
    me = bare.get(f"/auth/sessions/{session_id}")
    assert me.status_code == 200, me.text
    assert me.json()["actor_id"] == user_id


def test_bearer_still_works_without_cookie():
    suffix = uuid4().hex[:8]
    user_id = f"bearer-user-{suffix}"
    password = "StrongPass!23456"
    _seed_user(user_id=user_id, role_name="Platform Admin", password=password)

    login = client.post(
        "/auth/login",
        json={
            "username": user_id,
            "password": password,
            "ttl_minutes": 60,
            "idle_timeout_minutes": 30,
        },
    )
    assert login.status_code == 200
    token = login.json()["access_token"]

    bare = TestClient(app)
    resp = bare.get(
        f"/auth/sessions/{login.json()['session_id']}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["actor_id"] == user_id


def test_prod_dual_approval_requires_second_session(monkeypatch):
    import app.security as security_mod

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setattr(security_mod, "_ALLOW_HEADER_ACTOR_AUTH", False)

    ctx = ActorContext(
        actor_id="admin-1",
        actor_role="Platform Admin",
        user_login=None,
        approver_id="sec-approver-1",
        approver_role="Security Approver",
        mfa_verified=True,
        approver_session_authenticated=False,
    )
    with pytest.raises(HTTPException) as exc:
        require_dual_approval(ctx)
    assert exc.value.status_code == 403
    detail = exc.value.detail if isinstance(exc.value.detail, dict) else {}
    assert detail.get("error_code") == "AUTHZ_DUAL_APPROVAL_SESSION_REQUIRED"


def test_prod_dual_approval_accepts_approver_bearer(monkeypatch):
    suffix = uuid4().hex[:8]
    actor_id = f"actor-{suffix}"
    approver_id = f"approver-{suffix}"
    password = "StrongPass!23456"
    _seed_user(user_id=actor_id, role_name="Platform Admin", password=password)
    _seed_user(user_id=approver_id, role_name="Security Approver", password=password)

    actor_login = client.post(
        "/auth/login",
        json={"username": actor_id, "password": password, "ttl_minutes": 60, "idle_timeout_minutes": 30},
    )
    assert actor_login.status_code == 200
    actor_token = actor_login.json()["access_token"]

    approver_login = client.post(
        "/auth/approver-session",
        json={"username": approver_id, "password": password, "ttl_minutes": 15, "idle_timeout_minutes": 15},
    )
    assert approver_login.status_code == 200, approver_login.text
    assert APPROVER_SESSION_COOKIE_NAME in approver_login.cookies
    approver_token = approver_login.json()["access_token"]

    import app.security as security_mod
    from app.security import get_actor_context
    from starlette.requests import Request

    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.setattr(security_mod, "_ALLOW_HEADER_ACTOR_AUTH", False)

    db = SessionLocal()
    try:
        scope = {
            "type": "http",
            "asgi": {"version": "3.0"},
            "http_version": "1.1",
            "method": "POST",
            "scheme": "http",
            "path": "/test",
            "raw_path": b"/test",
            "query_string": b"",
            "headers": [
                (b"authorization", f"Bearer {actor_token}".encode("utf-8")),
                (b"x-approver-authorization", f"Bearer {approver_token}".encode("utf-8")),
            ],
            "client": ("127.0.0.1", 123),
            "server": ("test", 80),
        }
        request = Request(scope)
        ctx = get_actor_context(
            request=request,
            x_actor_id=None,
            x_actor_role=None,
            x_approver_id=None,
            x_approver_role=None,
            x_approver_authorization=f"Bearer {approver_token}",
            x_mfa_verified="true",
            authorization=f"Bearer {actor_token}",
            db=db,
        )
        assert ctx.approver_session_authenticated is True
        assert ctx.approver_id == approver_id
        require_dual_approval(ctx)
    finally:
        db.close()
