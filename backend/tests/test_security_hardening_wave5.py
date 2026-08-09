"""Wave-5 (CC-047): CSRF double-submit + IP-pinned outbound HTTP (DNS-rebinding TOCTOU)."""

from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import DirectoryUser
from app.security import hash_user_password
from app.services.csrf_protection import CSRF_COOKIE_NAME, CSRF_HEADER_NAME
from app.services.pinned_outbound_http import resolve_pinned_target, resolve_public_ips
from app.services.session_cookies import SESSION_COOKIE_NAME

client = TestClient(app)


def _seed_user(*, user_id: str, role_name: str = "Platform Admin", password: str = "StrongPass!23456") -> None:
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


def test_login_issues_csrf_cookie_and_cookie_mutation_requires_header():
    suffix = uuid4().hex[:8]
    user_id = f"csrf-user-{suffix}"
    password = "StrongPass!23456"
    _seed_user(user_id=user_id, password=password)

    login = client.post(
        "/auth/login",
        json={"username": user_id, "password": password, "ttl_minutes": 60, "idle_timeout_minutes": 30},
    )
    assert login.status_code == 200, login.text
    assert CSRF_COOKIE_NAME in login.cookies
    assert SESSION_COOKIE_NAME in login.cookies
    csrf = login.cookies[CSRF_COOKIE_NAME]
    session = login.cookies[SESSION_COOKIE_NAME]

    bare = TestClient(app)
    bare.cookies.set(SESSION_COOKIE_NAME, session)
    bare.cookies.set(CSRF_COOKIE_NAME, csrf)

    # Cookie-authenticated mutation without CSRF header must fail.
    denied = bare.post(
        "/auth/logout",
        # logout is CSRF-exempt; use a non-exempt mutation path instead.
    )
    assert denied.status_code in {200, 403}

    # Reauth requires auth; use directory list mutation-like POST with cookie only.
    # Prefer CSRF endpoint itself is GET. Use a simple protected POST that exists:
    # POST /auth/sessions requires issuer role — exercise CSRF middleware with a dummy path
    # by hitting logout is exempt; instead call /auth/approver-logout is exempt.
    # Use POST /runtime-config validation? Safer: unit-style via middleware path /auth/directory/users
    missing = bare.post(
        "/auth/directory/users",
        json={
            "user_id": f"new-{suffix}",
            "display_name": "x",
            "email": f"new-{suffix}@example.com",
            "role_name": "Agent Owner",
            "status": "active",
            "password": "StrongPass!23456",
        },
    )
    assert missing.status_code == 403, missing.text
    detail = missing.json().get("detail") or {}
    if isinstance(detail, dict):
        assert detail.get("error_code") == "CSRF_VALIDATION_FAILED"

    ok = bare.post(
        "/auth/directory/users",
        json={
            "user_id": f"new2-{suffix}",
            "display_name": "y",
            "email": f"new2-{suffix}@example.com",
            "role_name": "Agent Owner",
            "status": "active",
            "password": "StrongPass!23456",
        },
        headers={CSRF_HEADER_NAME: csrf, "X-MFA-Verified": "true"},
    )
    # May be 200 or 403 role — but must not be CSRF failure.
    body = ok.json() if ok.headers.get("content-type", "").startswith("application/json") else {}
    detail = body.get("detail") if isinstance(body, dict) else {}
    if isinstance(detail, dict):
        assert detail.get("error_code") != "CSRF_VALIDATION_FAILED"
    assert ok.status_code != 403 or (isinstance(detail, dict) and detail.get("error_code") != "CSRF_VALIDATION_FAILED")


def test_bearer_mutation_skips_csrf():
    suffix = uuid4().hex[:8]
    user_id = f"csrf-bearer-{suffix}"
    password = "StrongPass!23456"
    _seed_user(user_id=user_id, role_name="Master Admin", password=password)
    login = client.post(
        "/auth/login",
        json={"username": user_id, "password": password, "ttl_minutes": 60, "idle_timeout_minutes": 30},
    )
    token = login.json()["access_token"]
    bare = TestClient(app)
    # Explicit Bearer without sending cookies.
    resp = bare.post(
        "/auth/directory/users",
        json={
            "user_id": f"bearer-new-{suffix}",
            "display_name": "z",
            "email": f"bearer-new-{suffix}@example.com",
            "role_name": "Agent Owner",
            "status": "active",
            "password": "StrongPass!23456",
        },
        headers={"Authorization": f"Bearer {token}", "X-MFA-Verified": "true"},
    )
    detail = (resp.json() or {}).get("detail") if resp.headers.get("content-type", "").startswith("application/json") else {}
    if isinstance(detail, dict):
        assert detail.get("error_code") != "CSRF_VALIDATION_FAILED"
    assert resp.status_code in {200, 400, 403, 409, 422}


def test_pinned_resolve_blocks_private_literal():
    with pytest.raises(HTTPException):
        resolve_pinned_target("http://127.0.0.1/hook")
    with pytest.raises(HTTPException):
        resolve_pinned_target("http://169.254.169.254/latest/meta-data/")


def test_pinned_resolve_public_ip_literal():
    target = resolve_pinned_target("https://1.1.1.1/cdn-cgi/trace")
    assert target.ip == "1.1.1.1"
    assert target.hostname == "1.1.1.1"
    assert target.scheme == "https"


def test_resolve_public_ips_blocks_mixed_private(monkeypatch):
    def fake_getaddrinfo(host, *args, **kwargs):
        return [
            (None, None, None, None, ("8.8.8.8", 0)),
            (None, None, None, None, ("10.0.0.5", 0)),
        ]

    import app.services.pinned_outbound_http as pinned_mod
    import app.services.url_ssrf_guard as ssrf_mod

    monkeypatch.setattr(pinned_mod.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(ssrf_mod.socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(HTTPException) as exc:
        resolve_public_ips("evil.example.com")
    assert "non-public" in str(exc.value.detail).lower()
