"""HttpOnly session cookie helpers for browser console auth (CC-046)."""

from __future__ import annotations

import os
from typing import Optional

from starlette.responses import Response

from app.services.runtime_env import is_production_runtime, runtime_environment

SESSION_COOKIE_NAME = "gb_session"
APPROVER_SESSION_COOKIE_NAME = "gb_approver_session"


def cookie_secure_flag() -> bool:
    """Secure cookies outside local/dev/test, or when COOKIE_SECURE is forced on."""
    forced = (os.getenv("COOKIE_SECURE") or "").strip().lower()
    if forced in {"1", "true", "yes"}:
        return True
    if forced in {"0", "false", "no"}:
        return False
    return runtime_environment() not in {"local", "dev", "test"} or is_production_runtime()


def cookie_samesite() -> str:
    raw = (os.getenv("COOKIE_SAMESITE") or "lax").strip().lower()
    if raw in {"lax", "strict", "none"}:
        return raw
    return "lax"


def attach_session_cookie(
    response: Response,
    token: str,
    *,
    max_age_seconds: int,
    cookie_name: str = SESSION_COOKIE_NAME,
) -> None:
    response.set_cookie(
        key=cookie_name,
        value=token,
        max_age=max(60, int(max_age_seconds or 60)),
        httponly=True,
        secure=cookie_secure_flag(),
        samesite=cookie_samesite(),
        path="/",
    )


def clear_session_cookie(
    response: Response,
    *,
    cookie_name: str = SESSION_COOKIE_NAME,
) -> None:
    response.delete_cookie(
        key=cookie_name,
        path="/",
        httponly=True,
        secure=cookie_secure_flag(),
        samesite=cookie_samesite(),
    )


def read_session_cookie(cookies: dict, *, cookie_name: str = SESSION_COOKIE_NAME) -> Optional[str]:
    raw = cookies.get(cookie_name) if cookies else None
    if raw is None:
        return None
    token = str(raw).strip()
    return token or None
