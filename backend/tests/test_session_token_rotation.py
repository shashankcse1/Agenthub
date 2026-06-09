import hashlib
import hmac
import importlib

from fastapi import HTTPException
import pytest


SECURITY_ENV_KEYS = [
    "APP_ENV",
    "ENVIRONMENT",
    "SESSION_TOKEN_SECRET",
    "SESSION_TOKEN_SIGNING_KEYS",
    "ALLOW_HEADER_ACTOR_AUTH",
    "MFA_ENFORCEMENT_OPTIONAL",
    "EXPOSE_WORKLOAD_IDENTITY_ACCESS_TOKEN",
]


def _reload_security(monkeypatch: pytest.MonkeyPatch, **env: str):
    for key in SECURITY_ENV_KEYS:
        if key in env:
            monkeypatch.setenv(key, env[key])
        else:
            monkeypatch.delenv(key, raising=False)

    import app.security as security

    return importlib.reload(security)


@pytest.fixture(autouse=True)
def _reset_security_after_test(monkeypatch: pytest.MonkeyPatch):
    yield
    for key in SECURITY_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    import app.security as security

    importlib.reload(security)


def test_issue_session_token_uses_primary_key_id(monkeypatch: pytest.MonkeyPatch):
    security = _reload_security(
        monkeypatch,
        APP_ENV="dev",
        SESSION_TOKEN_SIGNING_KEYS="k2:abcdefghijklmnopqrstuvwxyz123456,k1:ZYXWVUTSRQPONMLKJIHGFEDCBA654321",
    )

    token = security.issue_session_bearer_token("session-rotation-primary")
    assert token.startswith("k2.")
    assert security.resolve_session_id_from_bearer_token(token) == "session-rotation-primary"


def test_legacy_two_part_token_still_valid_during_rollover(monkeypatch: pytest.MonkeyPatch):
    legacy_secret = "legacy-secret-abcdefghijklmnopqrstuvwxyz1234"
    security = _reload_security(
        monkeypatch,
        APP_ENV="dev",
        SESSION_TOKEN_SECRET=legacy_secret,
        SESSION_TOKEN_SIGNING_KEYS="k2:abcdefghijklmnopqrstuvwxyz123456,k1:ZYXWVUTSRQPONMLKJIHGFEDCBA654321",
    )

    session_id = "session-rotation-legacy"
    signature = hmac.new(legacy_secret.encode("utf-8"), session_id.encode("utf-8"), hashlib.sha256).hexdigest()
    legacy_token = f"{session_id}.{signature}"

    assert security.resolve_session_id_from_bearer_token(legacy_token) == session_id


def test_unknown_key_id_token_is_rejected(monkeypatch: pytest.MonkeyPatch):
    security = _reload_security(
        monkeypatch,
        APP_ENV="dev",
        SESSION_TOKEN_SIGNING_KEYS="k2:abcdefghijklmnopqrstuvwxyz123456,k1:ZYXWVUTSRQPONMLKJIHGFEDCBA654321",
    )

    with pytest.raises(HTTPException) as exc:
        security.resolve_session_id_from_bearer_token(
            "unknown.sessionid12345678.0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
    assert exc.value.status_code == 401
    assert exc.value.detail["error_code"] == "AUTHN_INVALID_TOKEN"
