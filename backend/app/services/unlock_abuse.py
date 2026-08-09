"""Detect repeated directory unlocks that may indicate abuse (residual next-action #5)."""

from __future__ import annotations

import os
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy.orm import Session

from app.logging_utils import get_logger, sanitize_fields
from app.models import AuditEvent
from app.services.audit import create_audit_event

logger = get_logger(__name__)


def _threshold() -> int:
    raw = (os.getenv("DIRECTORY_UNLOCK_ABUSE_THRESHOLD") or "5").strip()
    try:
        value = int(raw)
    except ValueError:
        return 5
    return max(2, min(value, 100))


def _window_minutes() -> int:
    raw = (os.getenv("DIRECTORY_UNLOCK_ABUSE_WINDOW_MINUTES") or "15").strip()
    try:
        value = int(raw)
    except ValueError:
        return 15
    return max(1, min(value, 1440))


def maybe_flag_unlock_abuse(
    db: Session,
    *,
    actor_id: str,
    user_id: str,
) -> Optional[dict]:
    """If actor or target user exceeds unlock threshold in window, emit audit + log."""
    since = datetime.utcnow() - timedelta(minutes=_window_minutes())
    threshold = _threshold()

    actor_count = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action_type == "auth.directory.user.unlock",
            AuditEvent.actor_id == actor_id,
            AuditEvent.timestamp >= since,
        )
        .count()
    )
    user_count = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action_type == "auth.directory.user.unlock",
            AuditEvent.resource_id == user_id,
            AuditEvent.timestamp >= since,
        )
        .count()
    )

    if actor_count < threshold and user_count < threshold:
        return None

    detail = {
        "actor_id": actor_id,
        "user_id": user_id,
        "actor_unlocks_in_window": actor_count,
        "user_unlocks_in_window": user_count,
        "threshold": threshold,
        "window_minutes": _window_minutes(),
    }
    logger.warning("directory_unlock_abuse_suspected %s", sanitize_fields(detail))
    create_audit_event(
        db,
        actor_id=actor_id,
        action_type="auth.directory.user.unlock.abuse_suspected",
        resource_type="directory_user",
        resource_id=user_id,
        trace_id=f"trace-directory-unlock-abuse-{user_id}",
        decision_outcome="deny",
        action_context=detail,
    )
    return detail
