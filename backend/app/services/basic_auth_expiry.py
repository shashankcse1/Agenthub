"""Break-glass basic-auth exception auto-disable (Leader Readiness Gates: ≤90d)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models import BasicAuthFallbackConfig
from app.policy_constants import DEFAULT_BASIC_AUTH_MAX_ENABLE_DURATION_MINUTES

# Leader Readiness: exceptions ≤ 90 days.
MAX_BREAK_GLASS_DURATION_MINUTES = 90 * 24 * 60  # 129600


def clamp_max_enable_duration_minutes(value: int | None) -> int:
    raw = int(value if value is not None else DEFAULT_BASIC_AUTH_MAX_ENABLE_DURATION_MINUTES)
    return max(1, min(MAX_BREAK_GLASS_DURATION_MINUTES, raw))


def expire_stale_basic_auth_fallbacks(db: Session, *, now: datetime | None = None) -> int:
    """Disable enabled break-glass configs whose expires_at has passed. Returns count disabled."""
    ts = now or datetime.utcnow()
    rows = (
        db.query(BasicAuthFallbackConfig)
        .filter(
            BasicAuthFallbackConfig.enabled.is_(True),
            BasicAuthFallbackConfig.expires_at.isnot(None),
            BasicAuthFallbackConfig.expires_at <= ts,
        )
        .all()
    )
    disabled = 0
    for row in rows:
        row.enabled = False
        row.last_toggled_at = ts
        disabled += 1
    return disabled


def exception_posture(db: Session | None = None) -> dict[str, Any]:
    """Lightweight break-glass posture for /health (no secrets)."""
    posture: dict[str, Any] = {
        "max_duration_days_cap": 90,
        "max_duration_minutes_cap": MAX_BREAK_GLASS_DURATION_MINUTES,
        "active_break_glass": 0,
        "expired_still_marked_enabled": 0,
        "auto_disable_supported": True,
    }
    if db is None:
        return posture
    now = datetime.utcnow()
    active = (
        db.query(BasicAuthFallbackConfig)
        .filter(BasicAuthFallbackConfig.enabled.is_(True))
        .all()
    )
    posture["active_break_glass"] = len(active)
    posture["expired_still_marked_enabled"] = sum(
        1 for row in active if row.expires_at is not None and row.expires_at <= now
    )
    return posture
