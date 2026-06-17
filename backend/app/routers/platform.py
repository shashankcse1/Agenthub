from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.api_errors import validation_error as api_validation_error
from app.database import get_db
from app.domain_constants import (
    PLATFORM_FEEDBACK_ACTIONS,
    PLATFORM_FEEDBACK_ANALYTICS_SINCE_HOURS_DEFAULT,
    PLATFORM_FEEDBACK_QUERY_LIMIT_DEFAULT,
)
from app.logging_utils import get_logger, sanitize_fields
from app.models import OperatorFeedback
from app.router_constants import (
    PLATFORM_FEEDBACK_ACTION_ROLES,
    PLATFORM_FEEDBACK_READ_ROLES,
    PLATFORM_FEEDBACK_WRITE_ROLES,
)
from app.schemas import (
    OperatorFeedbackActionRequest,
    OperatorFeedbackAnalyticsResponse,
    OperatorFeedbackCreateRequest,
    OperatorFeedbackResponse,
    PlatformOperationalStatusResponse,
)
from app.security import ActorContext, get_actor_context, require_role
from app.services.audit import create_audit_event
from app.services.platform_operational import (
    build_feedback_analytics,
    build_operational_status,
    normalize_feedback_category,
    normalize_feedback_severity,
)

router = APIRouter()
logger = get_logger(__name__)

ACTION_STATUS_MAP = {
    "acknowledge": "acknowledged",
    "resolve": "resolved",
    "dismiss": "dismissed",
    "escalate": "open",
}

_PLATFORM_READ_FORBIDDEN = {
    403: {"description": "Actor role is not allowed for platform feedback read operations."},
}
_PLATFORM_WRITE_FORBIDDEN = {
    403: {"description": "Actor role is not allowed, or operator feedback capture is disabled by runtime policy (`platform.feedback.enabled=false`)."},
}
_PLATFORM_ACTION_FORBIDDEN = {
    403: {"description": "Actor role is not allowed for feedback triage actions."},
}
_PLATFORM_NOT_FOUND = {
    404: {"description": "Feedback record not found."},
}
_PLATFORM_VALIDATION = {
    422: {"description": "Validation error (missing comment, invalid action, etc.)."},
}


def _rate_limit_status(request: Request) -> dict:
    limiter = getattr(request.app.state, "rate_limiter", None)
    if limiter is None:
        return {}
    return limiter.runtime_status()


@router.get(
    "/platform/operational-status",
    response_model=PlatformOperationalStatusResponse,
    summary="Platform operational posture",
    description=(
        "Returns maintenance mode, slow-response threshold, feedback capture policy, and component health "
        "for operator banners. Reads runtime-config keys `platform.maintenance_mode`, "
        "`platform.maintenance_message`, `platform.slow_response_threshold_ms`, and `platform.feedback.enabled`. "
        "No authentication required."
    ),
    responses={
        200: {"description": "Operational posture for UI banners and monitoring."},
    },
)
def get_platform_operational_status(
    request: Request,
    db: Session = Depends(get_db),
):
    return build_operational_status(db, _rate_limit_status(request))


@router.post(
    "/platform/feedback",
    response_model=OperatorFeedbackResponse,
    summary="Submit operator feedback",
    description=(
        "Persists operator feedback to PostgreSQL table `operator_feedback`. "
        "Emits audit event `platform.feedback.create` (`resource_type=operator_feedback`). "
        "Requires a role in PLATFORM_FEEDBACK_WRITE_ROLES."
    ),
    responses={
        200: {"description": "Feedback saved; returns persisted record with `feedback_id`."},
        **_PLATFORM_WRITE_FORBIDDEN,
        **_PLATFORM_VALIDATION,
    },
)
def create_operator_feedback(
    payload: OperatorFeedbackCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_WRITE_ROLES)
    status = build_operational_status(db, {})
    if not status["feedback_enabled"]:
        raise HTTPException(status_code=403, detail="Operator feedback capture is disabled by runtime policy.")

    comment = payload.comment.strip()
    if not comment:
        raise api_validation_error("comment", "Comment is required.")

    feedback = OperatorFeedback(
        feedback_id=str(uuid4()),
        category=normalize_feedback_category(payload.category),
        severity=normalize_feedback_severity(payload.severity),
        comment=comment,
        context_view=str(payload.context_view or "overview").strip()[:64] or "overview",
        context_action=str(payload.context_action or "").strip()[:128].lower(),
        client_latency_ms=payload.client_latency_ms,
        trace_id=str(payload.trace_id).strip()[:128] if payload.trace_id else None,
        incident_ref=str(payload.incident_ref).strip()[:64] if payload.incident_ref else None,
        metadata_json=json.dumps(payload.metadata_json or {}),
        created_by=ctx.actor_id,
    )
    db.add(feedback)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="platform.feedback.create",
        resource_type="operator_feedback",
        resource_id=feedback.feedback_id,
        trace_id=feedback.trace_id or feedback.feedback_id,
    )
    db.commit()
    db.refresh(feedback)
    logger.info(
        "platform_feedback_created %s",
        sanitize_fields(
            {
                "feedback_id": feedback.feedback_id,
                "category": feedback.category,
                "severity": feedback.severity,
                "context_view": feedback.context_view,
                "context_action": feedback.context_action,
                "actor_id": ctx.actor_id,
            }
        ),
    )
    return feedback


@router.get(
    "/platform/feedback",
    response_model=list[OperatorFeedbackResponse],
    summary="List operator feedback",
    description=(
        "Returns persisted feedback rows from `operator_feedback` with optional filters. "
        "Read-only; no audit event. Requires COMPLIANCE_READ-equivalent roles "
        "(PLATFORM_FEEDBACK_READ_ROLES)."
    ),
    responses={
        200: {"description": "Matching feedback records ordered by newest first."},
        **_PLATFORM_READ_FORBIDDEN,
    },
)
def list_operator_feedback(
    limit: int = Query(default=50, ge=1, le=PLATFORM_FEEDBACK_QUERY_LIMIT_DEFAULT, description="Max rows to return."),
    status: Optional[str] = Query(default=None, description="Filter by status: open, acknowledged, resolved, dismissed."),
    category: Optional[str] = Query(default=None, description="Filter by category: performance, ux, bug, feature, incident, other."),
    context_view: Optional[str] = Query(default=None, description="Filter by console view name (e.g. overview, discovery)."),
    context_action: Optional[str] = Query(default=None, description="Filter by action context key (e.g. load_overview)."),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_READ_ROLES)
    query = db.query(OperatorFeedback)
    if status:
        query = query.filter(OperatorFeedback.status == status.strip().lower())
    if category:
        query = query.filter(OperatorFeedback.category == category.strip().lower())
    if context_view:
        query = query.filter(OperatorFeedback.context_view == context_view.strip().lower())
    if context_action:
        query = query.filter(OperatorFeedback.context_action == context_action.strip().lower())
    rows = query.order_by(OperatorFeedback.created_at.desc()).limit(limit).all()
    return rows


@router.get(
    "/platform/feedback/analytics",
    response_model=OperatorFeedbackAnalyticsResponse,
    summary="Operator feedback analytics",
    description=(
        "Aggregates persisted feedback from `operator_feedback` by category, severity, status, "
        "context view, and context action for custom operator reports. Read-only; structured info log only."
    ),
    responses={
        200: {"description": "Analytics buckets for the requested time window."},
        **_PLATFORM_READ_FORBIDDEN,
    },
)
def get_operator_feedback_analytics(
    since_hours: int = Query(
        default=PLATFORM_FEEDBACK_ANALYTICS_SINCE_HOURS_DEFAULT,
        ge=1,
        le=720,
        description="Rolling window in hours (1–720).",
    ),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_READ_ROLES)
    report = build_feedback_analytics(db, since_hours)
    logger.info(
        "platform_feedback_analytics_served %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "since_hours": report["since_hours"],
                "total_count": report["total_count"],
                "open_count": report["open_count"],
            }
        ),
    )
    return report


@router.post(
    "/platform/feedback/{feedback_id}/actions",
    response_model=OperatorFeedbackResponse,
    summary="Apply feedback triage action",
    description=(
        "Updates feedback status in `operator_feedback` and emits audit "
        "`platform.feedback.acknowledge|resolve|dismiss|escalate`. "
        "Requires PLATFORM_FEEDBACK_ACTION_ROLES (admin/compliance write)."
    ),
    responses={
        200: {"description": "Updated feedback record after triage."},
        **_PLATFORM_ACTION_FORBIDDEN,
        **_PLATFORM_NOT_FOUND,
        **_PLATFORM_VALIDATION,
    },
)
def apply_operator_feedback_action(
    feedback_id: str,
    payload: OperatorFeedbackActionRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_ACTION_ROLES)
    action = str(payload.action or "").strip().lower()
    if action not in PLATFORM_FEEDBACK_ACTIONS:
        raise api_validation_error("action", f"Unsupported action: {action}")

    feedback = db.query(OperatorFeedback).filter_by(feedback_id=feedback_id).first()
    if not feedback:
        raise HTTPException(status_code=404, detail="Feedback record not found")

    feedback.status = ACTION_STATUS_MAP[action]
    feedback.action_note = payload.action_note.strip() or None
    feedback.acted_by = ctx.actor_id
    feedback.acted_at = datetime.now(timezone.utc)
    feedback.updated_at = datetime.now(timezone.utc)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type=f"platform.feedback.{action}",
        resource_type="operator_feedback",
        resource_id=feedback.feedback_id,
        trace_id=feedback.trace_id or feedback.feedback_id,
    )
    db.commit()
    db.refresh(feedback)
    return feedback
