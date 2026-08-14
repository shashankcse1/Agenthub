"""Unit coverage for CSRF helpers (CC-047) — close remaining branches."""

from __future__ import annotations

from typing import Optional

from starlette.requests import Request
from starlette.responses import Response

from app.services import csrf_protection as csrf
from app.services.session_cookies import SESSION_COOKIE_NAME


def _request(method: str, path: str, *, headers: Optional[dict] = None, cookies: Optional[dict] = None) -> Request:
    header_list = [(k.lower().encode(), str(v).encode()) for k, v in (headers or {}).items()]
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": header_list,
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
    }
    req = Request(scope)
    if cookies:
        # Starlette reads cookies from header
        cookie_header = "; ".join(f"{k}={v}" for k, v in cookies.items())
        scope["headers"] = list(scope["headers"]) + [(b"cookie", cookie_header.encode())]
        req = Request(scope)
    return req


def test_issue_and_attach_browser_auth_cookies(monkeypatch):
    monkeypatch.setenv("COOKIE_SECURE", "false")
    response = Response()
    token = csrf.attach_browser_auth_cookies(response, session_token="sess", max_age_seconds=60)
    assert token
    blob = str(response.headers.getlist("set-cookie"))
    assert SESSION_COOKIE_NAME in blob
    assert csrf.CSRF_COOKIE_NAME in blob


def test_clear_csrf_cookie(monkeypatch):
    monkeypatch.setenv("COOKIE_SECURE", "false")
    response = Response()
    csrf.attach_csrf_cookie(response, "abc", max_age_seconds=60)
    csrf.clear_csrf_cookie(response)
    assert csrf.CSRF_COOKIE_NAME in (response.headers.get("set-cookie") or "")


def test_csrf_not_required_for_safe_methods_and_exempt_paths():
    assert csrf.csrf_required_for_request(_request("GET", "/gateway/routes")) is False
    assert csrf.csrf_required_for_request(_request("POST", "/auth/login")) is False
    assert csrf.csrf_required_for_request(_request("POST", "/health")) is False


def test_csrf_not_required_with_bearer():
    req = _request(
        "POST",
        "/gateway/routes",
        headers={"Authorization": "Bearer tok"},
        cookies={SESSION_COOKIE_NAME: "sess"},
    )
    assert csrf.csrf_required_for_request(req) is False


def test_csrf_required_with_session_cookie_only():
    req = _request("POST", "/gateway/routes", cookies={SESSION_COOKIE_NAME: "sess"})
    assert csrf.csrf_required_for_request(req) is True


def test_validate_csrf_mismatch_and_match():
    bad = _request(
        "POST",
        "/gateway/routes",
        headers={csrf.CSRF_HEADER_NAME: "a"},
        cookies={SESSION_COOKIE_NAME: "sess", csrf.CSRF_COOKIE_NAME: "b"},
    )
    denied = csrf.validate_csrf(bad)
    assert denied is not None
    assert denied.status_code == 403

    good = _request(
        "POST",
        "/gateway/routes",
        headers={csrf.CSRF_HEADER_NAME: "same"},
        cookies={SESSION_COOKIE_NAME: "sess", csrf.CSRF_COOKIE_NAME: "same"},
    )
    assert csrf.validate_csrf(good) is None


def test_path_exempt_jit_actions_prefix():
    assert csrf.csrf_required_for_request(_request("POST", "/gateway/jit-actions/abc")) is False
