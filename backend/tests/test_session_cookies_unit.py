"""Unit coverage for session cookie helpers (CC-046) — target 100% of module."""

from __future__ import annotations

from starlette.responses import Response

from app.services import session_cookies as sc


def test_cookie_secure_flag_forced_true(monkeypatch):
    monkeypatch.setenv("COOKIE_SECURE", "true")
    monkeypatch.setenv("APP_ENV", "dev")
    assert sc.cookie_secure_flag() is True


def test_cookie_secure_flag_forced_false(monkeypatch):
    monkeypatch.setenv("COOKIE_SECURE", "0")
    monkeypatch.setenv("APP_ENV", "production")
    assert sc.cookie_secure_flag() is False


def test_cookie_secure_flag_follows_non_local_env(monkeypatch):
    monkeypatch.delenv("COOKIE_SECURE", raising=False)
    monkeypatch.setenv("APP_ENV", "staging")
    assert sc.cookie_secure_flag() is True


def test_cookie_secure_flag_dev_default_insecure(monkeypatch):
    monkeypatch.delenv("COOKIE_SECURE", raising=False)
    monkeypatch.setenv("APP_ENV", "dev")
    assert sc.cookie_secure_flag() is False


def test_cookie_samesite_valid_and_fallback(monkeypatch):
    monkeypatch.setenv("COOKIE_SAMESITE", "strict")
    assert sc.cookie_samesite() == "strict"
    monkeypatch.setenv("COOKIE_SAMESITE", "bogus")
    assert sc.cookie_samesite() == "lax"


def test_attach_and_clear_session_cookie(monkeypatch):
    monkeypatch.setenv("COOKIE_SECURE", "false")
    monkeypatch.setenv("COOKIE_SAMESITE", "lax")
    response = Response()
    sc.attach_session_cookie(response, "tok-abc", max_age_seconds=120)
    set_cookie = response.headers.get("set-cookie", "")
    assert sc.SESSION_COOKIE_NAME in set_cookie
    assert "HttpOnly" in set_cookie
    sc.clear_session_cookie(response)
    # delete_cookie still emits Set-Cookie
    assert sc.SESSION_COOKIE_NAME in (response.headers.get("set-cookie") or "")


def test_read_session_cookie_empty_and_present():
    assert sc.read_session_cookie({}) is None
    assert sc.read_session_cookie({sc.SESSION_COOKIE_NAME: "  "}) is None
    assert sc.read_session_cookie({sc.SESSION_COOKIE_NAME: " abc "}) == "abc"
