"""Shared runtime / target environment helpers for security gates."""

from __future__ import annotations

import os

_PROD_ALIASES = frozenset({"prod", "production"})


def runtime_environment() -> str:
    return (
        os.getenv("APP_ENV")
        or os.getenv("RUNTIME_ENVIRONMENT")
        or os.getenv("ENVIRONMENT")
        or "dev"
    ).strip().lower()


def is_production_runtime() -> bool:
    """True when the process itself is a production deployment."""
    return runtime_environment() in _PROD_ALIASES


def is_prod_target_environment(value: object) -> bool:
    """True when a request/resource environment targets production."""
    return str(value or "").strip().lower() in _PROD_ALIASES
