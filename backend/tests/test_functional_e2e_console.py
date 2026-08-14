"""Functional end-to-end: login → cookie session → Overview APIs → logout.

Mirrors the operator console path after same-origin UI proxy login.
"""

from __future__ import annotations

from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import DirectoryUser
from app.security import hash_user_password
from app.services.csrf_protection import CSRF_COOKIE_NAME, CSRF_HEADER_NAME
from app.services.session_cookies import SESSION_COOKIE_NAME


def _seed_user(*, user_id: str, role_name: str, password: str) -> None:
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


def test_functional_e2e_login_overview_logout_with_cookies():
    suffix = uuid4().hex[:8]
    user_id = f"e2e-console-{suffix}"
    password = "StrongPass!23456"
    _seed_user(user_id=user_id, role_name="Master Admin", password=password)

    # Fresh client = browser tab
    browser = TestClient(app)

    health = browser.get("/health")
    assert health.status_code == 200, health.text
    assert health.json().get("status") == "ok"

    login = browser.post(
        "/auth/login",
        json={
            "username": user_id,
            "password": password,
            "ttl_minutes": 60,
            "idle_timeout_minutes": 30,
        },
    )
    assert login.status_code == 200, login.text
    body = login.json()
    assert body.get("access_token")
    assert body.get("csrf_token") or CSRF_COOKIE_NAME in login.cookies
    assert SESSION_COOKIE_NAME in browser.cookies

    # Cookie session powers Overview-class reads (no Authorization header).
    overview_paths = [
        "/health",
        "/orchestration/summary",
        "/cost/live",
        "/audit/events?limit=10",
        "/governance/ui-coverage",
        "/platform/control-plane?window_hours=24&probe_peer=false",
        "/discovery/agents",
        "/gateway/governance/qbr-snapshot?hours=24",
    ]
    for path in overview_paths:
        resp = browser.get(path)
        assert resp.status_code == 200, f"{path} -> {resp.status_code} {resp.text[:300]}"

    # CSRF bootstrap for subsequent mutations
    csrf_resp = browser.get("/auth/csrf")
    assert csrf_resp.status_code == 200, csrf_resp.text
    csrf_token = csrf_resp.json().get("csrf_token") or browser.cookies.get(CSRF_COOKIE_NAME)
    assert csrf_token

    # Cookie-authenticated mutation with CSRF (feedback is a light Overview-adjacent write)
    feedback = browser.post(
        "/platform/feedback",
        headers={CSRF_HEADER_NAME: str(csrf_token)},
        json={
            "category": "ux",
            "severity": "low",
            "comment": f"e2e functional console check {suffix}",
            "console_view": "overview",
            "action_context": "functional_e2e",
        },
    )
    assert feedback.status_code in {200, 201}, feedback.text

    logout = browser.post("/auth/logout")
    assert logout.status_code == 200, logout.text

    # After logout, privileged Overview reads should require auth again
    denied = browser.get("/cost/live")
    assert denied.status_code in {401, 403}, denied.text


def test_functional_e2e_idle_session_forces_reauth():
    """Idle timeout returns AUTHN_SESSION_IDLE_TIMEOUT so the UI can bounce to login."""
    from datetime import datetime, timedelta

    from app.models import SessionRecord

    suffix = uuid4().hex[:8]
    user_id = f"e2e-idle-{suffix}"
    password = "StrongPass!23456"
    _seed_user(user_id=user_id, role_name="Platform Admin", password=password)

    browser = TestClient(app)
    login = browser.post(
        "/auth/login",
        json={
            "username": user_id,
            "password": password,
            "ttl_minutes": 60,
            "idle_timeout_minutes": 1,
        },
    )
    assert login.status_code == 200, login.text
    session_id = login.json()["session_id"]

    db = SessionLocal()
    try:
        row = db.query(SessionRecord).filter_by(session_id=session_id).first()
        assert row is not None
        row.last_activity_at = datetime.utcnow() - timedelta(minutes=5)
        row.idle_timeout_minutes = 1
        db.commit()
    finally:
        db.close()

    idle = browser.get("/cost/live")
    assert idle.status_code == 401, idle.text
    detail = idle.json().get("detail") or {}
    if isinstance(detail, dict):
        assert detail.get("error_code") == "AUTHN_SESSION_IDLE_TIMEOUT"
