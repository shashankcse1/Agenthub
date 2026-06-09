from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import AuditEvent, CostEvent
from app.policy_constants import ROLE_AGENT_OWNER
from app.router_constants import ROLES_OBSERVABILITY_READ, ROLES_OBSERVABILITY_SCHEMA
from app.schemas import (
    ObservabilityLogResponse,
    ObservabilityLogSchemaStatusResponse,
    ObservabilityTraceResponse,
)
from app.security import ActorContext, get_actor_context, require_role
from app.services.runtime_config import get_runtime_config_int
from app.runtime_constants import (
    RUNTIME_CONFIG_OBSERVABILITY_LOGS_DEFAULT_LIMIT,
    RUNTIME_CONFIG_OBSERVABILITY_SCHEMA_DEFAULT_SAMPLE_SIZE,
)

router = APIRouter()
logger = get_logger(__name__)


REQUIRED_LOG_FIELDS = [
    "timestamp",
    "request_id",
    "actor_id",
    "action_type",
    "resource_type",
    "resource_id",
    "trace_id",
    "span_id",
    "session_id",
    "agent_id",
    "owner_scope",
    "environment",
    "policy_version",
    "decision_outcome",
]


def _mask_value(value: str) -> str:
    if not value:
        return "***"
    if len(value) <= 3:
        return "***"
    return f"***{value[-3:]}"


def _derive_agent_id(resource_type: str, resource_id: str) -> str:
    return resource_id if resource_type == "agent" else "unknown-agent"


def _to_log_record(event: AuditEvent) -> dict:
    return {
        "timestamp": event.timestamp,
        "request_id": event.trace_id,
        "actor_id": event.actor_id,
        "action_type": event.action_type,
        "resource_type": event.resource_type,
        "resource_id": event.resource_id,
        "trace_id": event.trace_id,
        "span_id": event.audit_event_id,
        "session_id": "unknown-session",
        "agent_id": _derive_agent_id(event.resource_type, event.resource_id),
        "owner_scope": f"actor:{event.actor_id}",
        "environment": "unknown",
        "policy_version": event.policy_version,
        "decision_outcome": event.decision_outcome,
    }


def _redact_log_record(log: dict) -> dict:
    redacted = dict(log)
    redacted["actor_id"] = _mask_value(str(log.get("actor_id", "")))
    redacted["resource_id"] = _mask_value(str(log.get("resource_id", "")))
    redacted["owner_scope"] = "masked"
    return redacted


@router.get("/observability/traces/{trace_id}", response_model=ObservabilityTraceResponse)
def get_trace(
    trace_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace("observability_get_trace_start %s", sanitize_fields({"actor_id": ctx.actor_id, "trace_id": trace_id}))
    require_role(ctx, ROLES_OBSERVABILITY_READ)

    audit_events = db.query(AuditEvent).filter_by(trace_id=trace_id).all()
    cost_events = db.query(CostEvent).filter_by(trace_id=trace_id).all()
    if not audit_events and not cost_events:
        logger.error("observability_trace_not_found %s", sanitize_fields({"trace_id": trace_id}))
        raise HTTPException(status_code=404, detail="Trace not found")
    if ctx.actor_role == ROLE_AGENT_OWNER:
        if not audit_events or any(event.actor_id != ctx.actor_id for event in audit_events):
            logger.error(
                "observability_trace_scope_denied %s",
                sanitize_fields({"actor_id": ctx.actor_id, "trace_id": trace_id}),
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                    "message": "Agent Owner can only access traces in own scope.",
                    "actor_role": ctx.actor_role,
                    "required_scope": "trace audit actors subset of requester actor_id",
                    "policy_version": "v1",
                    "decision_trace_id": "authz-observability-scope-check",
                    "remediation_hint": "Use Auditor or Platform Admin role for cross-owner trace access.",
                },
            )

    timestamps = [e.timestamp for e in audit_events] + [e.timestamp for e in cost_events]
    result = {
        "trace_id": trace_id,
        "event_count": len(audit_events) + len(cost_events),
        "cost_event_count": len(cost_events),
        "first_seen": min(timestamps),
        "last_seen": max(timestamps),
    }
    logger.info(
        "observability_get_trace_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "trace_id": trace_id, "event_count": result["event_count"]}),
    )
    return result


@router.get("/observability/logs", response_model=list[ObservabilityLogResponse])
def list_logs(
    limit: Optional[int] = None,
    offset: int = Query(default=0, ge=0),
    since_hours: int = Query(default=24, ge=1, le=720),
    trace_id: Optional[str] = None,
    action_type: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    decision_outcome: Optional[str] = None,
    search: Optional[str] = None,
    redact_sensitive: bool = Query(default=False),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    resolved_limit = (
        limit
        if limit is not None
        else get_runtime_config_int(db, RUNTIME_CONFIG_OBSERVABILITY_LOGS_DEFAULT_LIMIT, 50)
    )
    if resolved_limit < 1 or resolved_limit > 500:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 500")

    logger.trace(
        "observability_list_logs_start %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "limit": resolved_limit,
                "offset": offset,
                "since_hours": since_hours,
                "redact_sensitive": redact_sensitive,
            }
        ),
    )
    require_role(ctx, ROLES_OBSERVABILITY_READ)

    since = datetime.utcnow().replace(microsecond=0) - timedelta(hours=since_hours)
    query = db.query(AuditEvent).filter(AuditEvent.timestamp >= since)
    if ctx.actor_role == ROLE_AGENT_OWNER:
        if actor_id is not None and actor_id != ctx.actor_id:
            raise HTTPException(
                status_code=403,
                detail={
                    "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                    "message": "Agent Owner can only query own logs.",
                    "actor_role": ctx.actor_role,
                    "required_scope": "actor_id == requester actor_id",
                    "policy_version": "v1",
                    "decision_trace_id": "authz-observability-logs-scope-check",
                    "remediation_hint": "Remove actor_id filter or set it to your own actor id.",
                },
            )
        actor_id = ctx.actor_id

    if trace_id:
        query = query.filter(AuditEvent.trace_id == trace_id)
    if action_type:
        query = query.filter(AuditEvent.action_type == action_type)
    if resource_type:
        query = query.filter(AuditEvent.resource_type == resource_type)
    if resource_id:
        query = query.filter(AuditEvent.resource_id == resource_id)
    if actor_id:
        query = query.filter(AuditEvent.actor_id == actor_id)
    if decision_outcome:
        query = query.filter(AuditEvent.decision_outcome == decision_outcome)
    if search:
        token = f"%{search.strip()}%"
        query = query.filter(
            or_(
                AuditEvent.actor_id.ilike(token),
                AuditEvent.action_type.ilike(token),
                AuditEvent.resource_type.ilike(token),
                AuditEvent.resource_id.ilike(token),
                AuditEvent.trace_id.ilike(token),
                AuditEvent.decision_outcome.ilike(token),
            )
        )

    logs = query.order_by(AuditEvent.timestamp.desc()).offset(offset).limit(resolved_limit).all()
    mapped_logs = [_to_log_record(e) for e in logs]
    logger.info(
        "observability_list_logs_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "count": len(mapped_logs), "redact_sensitive": redact_sensitive}),
    )
    if redact_sensitive:
        return [_redact_log_record(log) for log in mapped_logs]
    return mapped_logs


@router.get("/observability/logs/schema-status", response_model=ObservabilityLogSchemaStatusResponse)
def get_log_schema_status(
    sample_size: Optional[int] = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_OBSERVABILITY_SCHEMA)

    resolved_sample_size = (
        sample_size
        if sample_size is not None
        else get_runtime_config_int(db, RUNTIME_CONFIG_OBSERVABILITY_SCHEMA_DEFAULT_SAMPLE_SIZE, 200)
    )
    if resolved_sample_size < 1 or resolved_sample_size > 1000:
        raise HTTPException(status_code=400, detail="sample_size must be between 1 and 1000")

    events = db.query(AuditEvent).order_by(AuditEvent.timestamp.desc()).limit(resolved_sample_size).all()
    logs = [_to_log_record(event) for event in events]

    missing_field_counts = {field: 0 for field in REQUIRED_LOG_FIELDS}
    valid_count = 0

    for log in logs:
        is_valid = True
        for field in REQUIRED_LOG_FIELDS:
            value = log.get(field)
            if value is None or value == "":
                missing_field_counts[field] += 1
                is_valid = False
        if is_valid:
            valid_count += 1

    sampled_count = len(logs)
    invalid_count = sampled_count - valid_count
    conformance_percent = 100.0
    if sampled_count > 0:
        conformance_percent = round((valid_count / sampled_count) * 100.0, 2)

    return {
        "generated_at": datetime.utcnow(),
        "required_fields": REQUIRED_LOG_FIELDS,
        "sampled_count": sampled_count,
        "valid_count": valid_count,
        "invalid_count": invalid_count,
        "conformance_percent": conformance_percent,
        "missing_field_counts": missing_field_counts,
    }
