"""Double-submit CSRF protection for cookie-authenticated browser mutations (CC-047)."""

from __future__ import annotations

import hmac
import secrets
from typing import Optional

from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from app.services.session_cookies import (
    SESSION_COOKIE_NAME,
    attach_session_cookie,
    cookie_secure_flag,
    cookie_samesite,
    read_session_cookie,
)

CSRF_COOKIE_NAME = "gb_csrf"
CSRF_HEADER_NAME = "X-CSRF-Token"

_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})
_EXEMPT_PATH_PREFIXES = (
    "/health",
    "/ready",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/auth/login",
    "/auth/approver-session",
    "/auth/approver-logout",
    "/auth/logout",
    "/auth/csrf",
    "/gateway/jit-actions/",  # signed email action tokens (not cookie console)
)


def issue_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def attach_csrf_cookie(response: Response, token: str, *, max_age_seconds: int = 3600) -> None:
    """CSRF cookie is readable by JS (not HttpOnly) for double-submit header matching."""
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        max_age=max(60, int(max_age_seconds or 60)),
        httponly=False,
        secure=cookie_secure_flag(),
        samesite=cookie_samesite(),
        path="/",
    )


def clear_csrf_cookie(response: Response) -> None:
    response.delete_cookie(
        key=CSRF_COOKIE_NAME,
        path="/",
        secure=cookie_secure_flag(),
        samesite=cookie_samesite(),
    )


def attach_browser_auth_cookies(
    response: Response,
    *,
    session_token: str,
    max_age_seconds: int,
    session_cookie_name: str = SESSION_COOKIE_NAME,
) -> str:
    """Attach session + CSRF cookies; returns the CSRF token."""
    attach_session_cookie(
        response,
        session_token,
        max_age_seconds=max_age_seconds,
        cookie_name=session_cookie_name,
    )
    csrf = issue_csrf_token()
    attach_csrf_cookie(response, csrf, max_age_seconds=max_age_seconds)
    return csrf


def _path_is_exempt(path: str) -> bool:
    normalized = str(path or "")
    for prefix in _EXEMPT_PATH_PREFIXES:
        if normalized == prefix or normalized.startswith(prefix):
            return True
    return False


def _has_authorization_bearer(request: Request) -> bool:
    auth = (request.headers.get("Authorization") or "").strip()
    if not auth:
        return False
    scheme, _, token = auth.partition(" ")
    return scheme.lower() == "bearer" and bool(token.strip())


def csrf_required_for_request(request: Request) -> bool:
    """Require CSRF when the browser session cookie authenticates the mutation."""
    method = (request.method or "GET").upper()
    if method in _SAFE_METHODS:
        return False
    if _path_is_exempt(request.url.path):
        return False
    # Pure Bearer/API clients are not subject to cookie CSRF.
    if _has_authorization_bearer(request):
        return False
    session = read_session_cookie(request.cookies, cookie_name=SESSION_COOKIE_NAME)
    return bool(session)


def validate_csrf(request: Request) -> Optional[JSONResponse]:
    if not csrf_required_for_request(request):
        return None
    cookie_token = str(request.cookies.get(CSRF_COOKIE_NAME) or "").strip()
    header_token = str(request.headers.get(CSRF_HEADER_NAME) or "").strip()
    if not cookie_token or not header_token or not hmac.compare_digest(cookie_token, header_token):
        return JSONResponse(
            status_code=403,
            content={
                "detail": {
                    "error_code": "CSRF_VALIDATION_FAILED",
                    "message": "CSRF token missing or mismatched for cookie-authenticated mutation.",
                    "remediation_hint": (
                        f"Send header {CSRF_HEADER_NAME} matching the {CSRF_COOKIE_NAME} cookie "
                        "(issued at login or GET /auth/csrf)."
                    ),
                }
            },
        )
    return None
