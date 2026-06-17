from __future__ import annotations

from contextvars import ContextVar
from typing import Any, Optional

_actor_id_var: ContextVar[Optional[str]] = ContextVar("request_actor_id", default=None)
_user_login_var: ContextVar[Optional[str]] = ContextVar("request_user_login", default=None)
_actor_role_var: ContextVar[Optional[str]] = ContextVar("request_actor_role", default=None)


def set_request_actor(
    actor_id: Optional[str],
    user_login: Optional[str] = None,
    actor_role: Optional[str] = None,
) -> None:
    _actor_id_var.set(actor_id)
    _user_login_var.set(user_login)
    _actor_role_var.set(actor_role)


def get_request_actor_id() -> Optional[str]:
    return _actor_id_var.get()


def get_request_user_login() -> Optional[str]:
    return _user_login_var.get()


def get_request_actor_role() -> Optional[str]:
    return _actor_role_var.get()


def clear_request_actor() -> None:
    _actor_id_var.set(None)
    _user_login_var.set(None)
    _actor_role_var.set(None)


def inject_actor_log_fields(fields: dict[str, Any]) -> None:
    if not fields.get("actor_id"):
        actor_id = get_request_actor_id()
        if actor_id:
            fields["actor_id"] = actor_id
    if not fields.get("user_login"):
        user_login = get_request_user_login()
        if user_login:
            fields["user_login"] = user_login
