"""Wave-2 security hardening: prod aliases, SSRF on JIT/callbacks, dual-approval directory gate."""

from __future__ import annotations

import os

import pytest
from fastapi import HTTPException

from app.services.runtime_env import is_prod_target_environment, is_production_runtime, runtime_environment
from app.services.url_ssrf_guard import assert_webhook_url_safe_for_delivery, validate_outbound_webhook_url


def test_runtime_env_recognizes_production_aliases(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("RUNTIME_ENVIRONMENT", raising=False)
    monkeypatch.delenv("ENVIRONMENT", raising=False)
    assert runtime_environment() == "production"
    assert is_production_runtime() is True
    monkeypatch.setenv("APP_ENV", "prod")
    assert is_production_runtime() is True
    monkeypatch.setenv("APP_ENV", "staging")
    assert is_production_runtime() is False
    assert is_prod_target_environment("production") is True
    assert is_prod_target_environment("prod") is True
    assert is_prod_target_environment("dev") is False


def test_callback_url_blocks_metadata_and_private_literals():
    with pytest.raises(HTTPException):
        validate_outbound_webhook_url(
            "http://169.254.169.254/latest/meta-data/",
            allow_empty=False,
            resolve_dns=False,
        )
    with pytest.raises(HTTPException):
        validate_outbound_webhook_url(
            "http://127.0.0.1:8080/hook",
            allow_empty=False,
            resolve_dns=False,
            allow_loopback_outside_prod=False,
        )
    ok = validate_outbound_webhook_url(
        "https://hooks.example.com/path",
        allow_empty=False,
        resolve_dns=False,
    )
    assert ok.startswith("https://hooks.example.com")


def test_assert_webhook_url_safe_for_delivery_blocks_loopback():
    with pytest.raises(HTTPException):
        assert_webhook_url_safe_for_delivery("http://localhost/callback")


def test_jit_post_external_rest_ssrf_blocked():
    from app.database import SessionLocal
    from app.services.gateway_jit_notifications import _post_external_rest

    db = SessionLocal()
    try:
        result = _post_external_rest(
            db,
            url="http://169.254.169.254/latest/meta-data/",
            payload={"event_type": "test", "request_id": "jit-ssrf"},
            sign_requests=True,
        )
        assert result.get("ok") is False
        assert "ssrf_blocked" in str(result.get("error") or "")
    finally:
        db.close()


def test_dual_approval_directory_gate_in_production(monkeypatch):
    from app.security import ActorContext, require_dual_approval

    monkeypatch.setenv("APP_ENV", "production")
    # Force header-actor off path (production always forces this in module load,
    # but require_dual_approval checks is_production_runtime + _ALLOW_HEADER_ACTOR_AUTH).
    import app.security as security_mod

    monkeypatch.setattr(security_mod, "_ALLOW_HEADER_ACTOR_AUTH", False)
    # Headers alone are insufficient in production (CC-046 second-session requirement).
    ctx = ActorContext(
        actor_id="admin-1",
        actor_role="Platform Admin",
        user_login=None,
        approver_id="nonexistent-approver-xyz",
        approver_role="Security Approver",
        mfa_verified=True,
        approver_session_authenticated=False,
    )
    with pytest.raises(HTTPException) as exc:
        require_dual_approval(ctx)
    assert exc.value.status_code == 403
    detail = exc.value.detail if isinstance(exc.value.detail, dict) else {}
    assert detail.get("error_code") == "AUTHZ_DUAL_APPROVAL_SESSION_REQUIRED"

    # With a second session asserted, unknown directory approver still fails closed.
    ctx_authed = ActorContext(
        actor_id="admin-1",
        actor_role="Platform Admin",
        user_login=None,
        approver_id="nonexistent-approver-xyz",
        approver_role="Security Approver",
        mfa_verified=True,
        approver_session_authenticated=True,
    )
    with pytest.raises(HTTPException) as exc2:
        require_dual_approval(ctx_authed)
    assert exc2.value.status_code == 403
    detail2 = exc2.value.detail if isinstance(exc2.value.detail, dict) else {}
    assert detail2.get("error_code") == "AUTHZ_DUAL_APPROVAL_APPROVER_UNKNOWN"
