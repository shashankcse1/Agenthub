import importlib

import pytest


SECURITY_ENV_KEYS = [
    "APP_ENV",
    "ENVIRONMENT",
    "SESSION_TOKEN_SECRET",
    "SESSION_TOKEN_SIGNING_KEYS",
    "SESSION_TOKEN_SIGNING_LAST_ROTATED_AT",
    "SESSION_TOKEN_ROTATION_MAX_DAYS",
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


def test_validate_session_secret_configuration_rejects_default_in_non_dev(monkeypatch: pytest.MonkeyPatch):
    security = _reload_security(monkeypatch, APP_ENV="prod")

    with pytest.raises(RuntimeError, match="non-default"):
        security.validate_session_secret_configuration()


def test_validate_session_secret_configuration_rejects_short_secret_in_non_dev(monkeypatch: pytest.MonkeyPatch):
    security = _reload_security(monkeypatch, APP_ENV="prod", SESSION_TOKEN_SECRET="short-secret")

    with pytest.raises(RuntimeError, match="at least 32"):
        security.validate_session_secret_configuration()


def test_validate_session_secret_configuration_allows_strong_secret_in_non_dev(monkeypatch: pytest.MonkeyPatch):
    security = _reload_security(
        monkeypatch,
        APP_ENV="prod",
        SESSION_TOKEN_SECRET="x" * 48,
    )

    security.validate_session_secret_configuration()


def test_validate_session_secret_configuration_allows_key_ring_in_non_dev(monkeypatch: pytest.MonkeyPatch):
    security = _reload_security(
        monkeypatch,
        APP_ENV="prod",
        SESSION_TOKEN_SIGNING_KEYS="k2:abcdefghijklmnopqrstuvwxyz123456,k1:ZYXWVUTSRQPONMLKJIHGFEDCBA654321",
    )

    security.validate_session_secret_configuration()


def test_validate_session_secret_configuration_rejects_short_key_ring_secret(monkeypatch: pytest.MonkeyPatch):
    security = _reload_security(
        monkeypatch,
        APP_ENV="prod",
        SESSION_TOKEN_SIGNING_KEYS="k1:short-secret",
    )

    with pytest.raises(RuntimeError, match="at least 32"):
        security.validate_session_secret_configuration()


def test_insecure_configuration_warnings_report_enabled_risky_flags(monkeypatch: pytest.MonkeyPatch):
    security = _reload_security(
        monkeypatch,
        APP_ENV="dev",
        ALLOW_HEADER_ACTOR_AUTH="true",
        MFA_ENFORCEMENT_OPTIONAL="true",
        EXPOSE_WORKLOAD_IDENTITY_ACCESS_TOKEN="true",
    )

    warnings = security.insecure_configuration_warnings()

    assert any("ALLOW_HEADER_ACTOR_AUTH" in warning for warning in warnings)
    assert any("MFA_ENFORCEMENT_OPTIONAL" in warning for warning in warnings)
    assert any("EXPOSE_WORKLOAD_IDENTITY_ACCESS_TOKEN" in warning for warning in warnings)
    assert any("SESSION_TOKEN_SECRET" in warning for warning in warnings)


def test_header_actor_auth_defaults_off_in_staging(monkeypatch: pytest.MonkeyPatch):
    security = _reload_security(
        monkeypatch,
        APP_ENV="staging",
        SESSION_TOKEN_SECRET="x" * 48,
    )

    assert security._ALLOW_HEADER_ACTOR_AUTH is False


def test_header_actor_auth_defaults_on_in_local_dev(monkeypatch: pytest.MonkeyPatch):
    security = _reload_security(
        monkeypatch,
        APP_ENV="dev",
        SESSION_TOKEN_SECRET="x" * 48,
    )

    assert security._ALLOW_HEADER_ACTOR_AUTH is True


def test_validate_runtime_auth_guardrails_rejects_header_actor_auth_in_staging_without_override(
    monkeypatch: pytest.MonkeyPatch,
):
    security = _reload_security(
        monkeypatch,
        APP_ENV="staging",
        SESSION_TOKEN_SECRET="x" * 48,
        ALLOW_HEADER_ACTOR_AUTH="true",
    )

    with pytest.raises(RuntimeError, match="ALLOW_HEADER_ACTOR_AUTH_STAGING_OVERRIDE"):
        security.validate_runtime_auth_guardrails()


def test_header_actor_auth_is_forced_off_in_prod(monkeypatch: pytest.MonkeyPatch):
    security = _reload_security(
        monkeypatch,
        APP_ENV="prod",
        SESSION_TOKEN_SECRET="x" * 48,
        ALLOW_HEADER_ACTOR_AUTH="true",
    )

    assert security._ALLOW_HEADER_ACTOR_AUTH is False


def test_validate_runtime_auth_guardrails_rejects_header_actor_auth_in_prod(monkeypatch: pytest.MonkeyPatch):
    security = _reload_security(
        monkeypatch,
        APP_ENV="prod",
        SESSION_TOKEN_SECRET="x" * 48,
        ALLOW_HEADER_ACTOR_AUTH="true",
    )

    with pytest.raises(RuntimeError, match="ALLOW_HEADER_ACTOR_AUTH"):
        security.validate_runtime_auth_guardrails()


def test_validate_runtime_auth_guardrails_rejects_mfa_optional_in_non_dev(monkeypatch: pytest.MonkeyPatch):
    security = _reload_security(
        monkeypatch,
        APP_ENV="prod",
        SESSION_TOKEN_SECRET="x" * 48,
        MFA_ENFORCEMENT_OPTIONAL="true",
    )

    assert security._MFA_ENFORCEMENT_OPTIONAL is False
    with pytest.raises(RuntimeError, match="MFA_ENFORCEMENT_OPTIONAL"):
        security.validate_runtime_auth_guardrails()


def test_rotation_age_warning_when_last_rotated_timestamp_missing(monkeypatch: pytest.MonkeyPatch):
    security = _reload_security(
        monkeypatch,
        APP_ENV="prod",
        SESSION_TOKEN_SIGNING_KEYS="k2:abcdefghijklmnopqrstuvwxyz123456,k1:ZYXWVUTSRQPONMLKJIHGFEDCBA654321",
        SESSION_TOKEN_ROTATION_MAX_DAYS="30",
    )

    warnings = security.insecure_configuration_warnings()
    assert any("SESSION_TOKEN_SIGNING_LAST_ROTATED_AT is not set" in warning for warning in warnings)


def test_rotation_age_warning_when_threshold_exceeded(monkeypatch: pytest.MonkeyPatch):
    security = _reload_security(
        monkeypatch,
        APP_ENV="prod",
        SESSION_TOKEN_SIGNING_KEYS="k2:abcdefghijklmnopqrstuvwxyz123456,k1:ZYXWVUTSRQPONMLKJIHGFEDCBA654321",
        SESSION_TOKEN_SIGNING_LAST_ROTATED_AT="2020-01-01T00:00:00Z",
        SESSION_TOKEN_ROTATION_MAX_DAYS="30",
    )

    warnings = security.insecure_configuration_warnings()
    assert any("rotation age exceeded configured threshold" in warning for warning in warnings)


def test_session_signing_rotation_status_reports_exceeded(monkeypatch: pytest.MonkeyPatch):
    security = _reload_security(
        monkeypatch,
        APP_ENV="prod",
        SESSION_TOKEN_SIGNING_KEYS="k2:abcdefghijklmnopqrstuvwxyz123456,k1:ZYXWVUTSRQPONMLKJIHGFEDCBA654321",
        SESSION_TOKEN_SIGNING_LAST_ROTATED_AT="2020-01-01T00:00:00Z",
        SESSION_TOKEN_ROTATION_MAX_DAYS="30",
    )
    status = security.session_signing_rotation_status()
    assert status["monitoring_enabled"] is True
    assert status["rotation_age_exceeded"] is True
    assert int(status["age_days"] or 0) > 30
    assert status["warnings"]
