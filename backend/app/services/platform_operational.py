from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.domain_constants import (
    PLATFORM_FEEDBACK_ANALYTICS_SINCE_HOURS_DEFAULT,
    PLATFORM_FEEDBACK_CATEGORIES,
    PLATFORM_FEEDBACK_SEVERITIES,
    PLATFORM_FEEDBACK_STATUSES,
    PLATFORM_SLOW_RESPONSE_THRESHOLD_MS_DEFAULT,
)
from app.models import OperatorFeedback
from app.runtime_constants import (
    RUNTIME_CONFIG_PLATFORM_FEEDBACK_ENABLED,
    RUNTIME_CONFIG_PLATFORM_MAINTENANCE_MESSAGE,
    RUNTIME_CONFIG_PLATFORM_MAINTENANCE_MODE,
    RUNTIME_CONFIG_PLATFORM_SLOW_RESPONSE_THRESHOLD_MS,
)
from app.services.config_cache import runtime_config_cache
from app.services.runtime_config import get_runtime_config, get_runtime_config_int


def _truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "enabled"}


def build_operational_status(db: Session, rate_limit_status: dict) -> dict:
    maintenance_active = _truthy(
        get_runtime_config(db, RUNTIME_CONFIG_PLATFORM_MAINTENANCE_MODE, "false")
    )
    maintenance_message = get_runtime_config(db, RUNTIME_CONFIG_PLATFORM_MAINTENANCE_MESSAGE, "").strip()
    slow_threshold = get_runtime_config_int(
        db,
        RUNTIME_CONFIG_PLATFORM_SLOW_RESPONSE_THRESHOLD_MS,
        PLATFORM_SLOW_RESPONSE_THRESHOLD_MS_DEFAULT,
    )
    feedback_enabled = _truthy(
        get_runtime_config(db, RUNTIME_CONFIG_PLATFORM_FEEDBACK_ENABLED, "true")
    )
    cache_status = runtime_config_cache.runtime_status()
    overall = "ok"
    if maintenance_active:
        overall = "maintenance"
    elif cache_status.get("degraded") or rate_limit_status.get("degraded"):
        overall = "degraded"
    return {
        "status": overall,
        "maintenance": {
            "active": maintenance_active,
            "message": maintenance_message,
        },
        "performance": {
            "slow_response_threshold_ms": max(250, slow_threshold),
        },
        "feedback_enabled": feedback_enabled,
        "runtime_config_cache": cache_status,
        "rate_limit": rate_limit_status,
    }


def normalize_feedback_category(value: str) -> str:
    normalized = str(value or "other").strip().lower()
    return normalized if normalized in PLATFORM_FEEDBACK_CATEGORIES else "other"


def normalize_feedback_severity(value: str) -> str:
    normalized = str(value or "medium").strip().lower()
    return normalized if normalized in PLATFORM_FEEDBACK_SEVERITIES else "medium"


def normalize_feedback_status(value: str) -> str:
    normalized = str(value or "open").strip().lower()
    return normalized if normalized in PLATFORM_FEEDBACK_STATUSES else "open"


def build_feedback_analytics(db: Session, since_hours: int) -> dict:
    window_hours = max(1, min(int(since_hours), 720))
    since = datetime.now(timezone.utc) - timedelta(hours=window_hours)
    base_query = db.query(OperatorFeedback).filter(OperatorFeedback.created_at >= since)
    total_count = base_query.count()
    open_count = base_query.filter(OperatorFeedback.status == "open").count()

    def bucket_rows(column_name: str, limit: int = 12) -> list[dict]:
        column = getattr(OperatorFeedback, column_name)
        rows = (
            db.query(column, func.count(OperatorFeedback.feedback_id))
            .filter(OperatorFeedback.created_at >= since)
            .group_by(column)
            .order_by(func.count(OperatorFeedback.feedback_id).desc())
            .limit(limit)
            .all()
        )
        return [{"label": str(label or "unknown"), "count": int(count)} for label, count in rows]

    return {
        "generated_at": datetime.now(timezone.utc),
        "since_hours": window_hours,
        "total_count": total_count,
        "open_count": open_count,
        "by_category": bucket_rows("category"),
        "by_severity": bucket_rows("severity", limit=8),
        "by_status": bucket_rows("status", limit=8),
        "by_context_view": bucket_rows("context_view"),
        "by_context_action": bucket_rows("context_action"),
    }
