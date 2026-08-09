import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import or_
from sqlalchemy.orm import Query as OrmQuery, Session

from app.database import get_db
from app.domain_constants import REQUIRED_OBSERVABILITY_LOG_FIELDS
from app.logging_utils import get_logger, sanitize_fields
from app.models import AuditEvent, CostEvent
from app.services.audit import create_audit_event, parse_audit_action_context
from app.services.audit_action_catalog import resolve_action_description
from app.policy_constants import ROLE_AGENT_OWNER
from app.router_constants import ROLES_OBSERVABILITY_READ, ROLES_OBSERVABILITY_SCHEMA
from app.runtime_constants import (
    RUNTIME_CONFIG_OBSERVABILITY_LOGS_DEFAULT_LIMIT,
    RUNTIME_CONFIG_OBSERVABILITY_SCHEMA_DEFAULT_SAMPLE_SIZE,
)
from app.schemas import (
    ObservabilityBreakdownItem,
    ObservabilityHourlyVolume,
    ObservabilityLogResponse,
    ObservabilityLogSchemaStatusResponse,
    ObservabilityRecentTraceResponse,
    ObservabilitySiemRuleEvaluationItem,
    ObservabilitySiemRuleEvaluationResponse,
    ObservabilitySiemRulesExportResponse,
    ObservabilitySiemRulesListResponse,
    ObservabilitySummaryResponse,
    ObservabilityTraceEventResponse,
    ObservabilityTraceEventsResponse,
    ObservabilityTraceResponse,
)
from app.security import ActorContext, get_actor_context, require_role
from app.services.observability_summary import build_observability_summary_aggregates, schema_status_from_logs
from app.services.runtime_config import get_runtime_config_int
from app.services.siem_alert_rules import (
    evaluate_siem_rules_against_events,
    export_siem_rules_catalog,
    load_siem_alert_rules,
)

router = APIRouter()
logger = get_logger(__name__)


REQUIRED_LOG_FIELDS = list(REQUIRED_OBSERVABILITY_LOG_FIELDS)


def _mask_value(value: str) -> str:
    if not value:
        return "***"
    if len(value) <= 3:
        return "***"
    return f"***{value[-3:]}"


def _derive_agent_id(resource_type: str, resource_id: str) -> str:
    return resource_id if resource_type == "agent" else "unknown-agent"


def _to_log_record(event: AuditEvent) -> dict:
    action_context = parse_audit_action_context(event.action_context_json)
    session_id = str(action_context.get("session_id") or "").strip() or "unknown-session"
    request_id = str(action_context.get("request_id") or event.trace_id or "").strip() or event.trace_id
    return {
        "timestamp": event.timestamp,
        "request_id": request_id,
        "actor_id": event.actor_id,
        "actor_login": event.actor_login or "unknown",
        "actor_role": event.actor_role or "unknown",
        "action_description": event.action_description or resolve_action_description(event.action_type),
        "action_type": event.action_type,
        "resource_type": event.resource_type,
        "resource_id": event.resource_id,
        "trace_id": event.trace_id,
        "span_id": event.audit_event_id,
        "session_id": session_id,
        "agent_id": _derive_agent_id(event.resource_type, event.resource_id),
        "owner_scope": f"actor:{event.actor_id}",
        "environment": event.environment or "unknown",
        "policy_version": event.policy_version,
        "decision_outcome": event.decision_outcome,
        "user_prompt": action_context.get("user_prompt"),
        "action_context": action_context,
    }


def _parse_cost_user_properties(raw: object) -> Optional[dict[str, object]]:
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    sanitized: dict[str, object] = {}
    for key, value in list(parsed.items())[:32]:
        normalized_key = str(key or "").strip()[:64]
        if not normalized_key:
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            sanitized[normalized_key] = value if not isinstance(value, str) else value[:256]
        else:
            sanitized[normalized_key] = str(value)[:256]
    return sanitized or None


def _redact_log_record(log: dict) -> dict:
    redacted = dict(log)
    redacted["actor_id"] = _mask_value(str(log.get("actor_id", "")))
    redacted["actor_login"] = _mask_value(str(log.get("actor_login", "")))
    redacted["resource_id"] = _mask_value(str(log.get("resource_id", "")))
    redacted["owner_scope"] = "masked"
    return redacted


def _assert_trace_scope(ctx: ActorContext, audit_events: list[AuditEvent], trace_id: str) -> None:
    if ctx.actor_role != ROLE_AGENT_OWNER:
        return
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


def _schema_status_from_logs(logs: list[dict]) -> ObservabilityLogSchemaStatusResponse:
    return schema_status_from_logs(logs)


def _scoped_audit_events_query(db: Session, since: datetime, ctx: ActorContext) -> OrmQuery:
    query = db.query(AuditEvent).filter(AuditEvent.timestamp >= since)
    if ctx.actor_role == ROLE_AGENT_OWNER:
        query = query.filter(AuditEvent.actor_id == ctx.actor_id)
    return query


@router.get("/observability/summary", response_model=ObservabilitySummaryResponse)
def get_observability_summary(
    since_hours: int = Query(default=24, ge=1, le=168),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_OBSERVABILITY_READ)
    since = datetime.utcnow().replace(microsecond=0) - timedelta(hours=since_hours)

    def scoped_query() -> OrmQuery:
        return _scoped_audit_events_query(db, since, ctx)

    aggregates = build_observability_summary_aggregates(db, scoped_query, _to_log_record)

    return ObservabilitySummaryResponse(
        generated_at=datetime.utcnow(),
        since_hours=since_hours,
        **aggregates,
    )


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
    _assert_trace_scope(ctx, audit_events, trace_id)

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


@router.get("/observability/traces/{trace_id}/events", response_model=ObservabilityTraceEventsResponse)
def get_trace_events(
    trace_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_OBSERVABILITY_READ)
    audit_events = (
        db.query(AuditEvent)
        .filter(AuditEvent.trace_id == trace_id)
        .order_by(AuditEvent.timestamp.asc())
        .all()
    )
    cost_events = (
        db.query(CostEvent)
        .filter(CostEvent.trace_id == trace_id)
        .order_by(CostEvent.timestamp.asc())
        .all()
    )
    if not audit_events and not cost_events:
        raise HTTPException(status_code=404, detail="Trace not found")
    _assert_trace_scope(ctx, audit_events, trace_id)

    timeline: list[ObservabilityTraceEventResponse] = []
    for event in audit_events:
        action_context = parse_audit_action_context(event.action_context_json)
        timeline.append(
            ObservabilityTraceEventResponse(
                timestamp=event.timestamp,
                event_type="audit",
                trace_id=event.trace_id or trace_id,
                span_id=event.audit_event_id or "",
                actor_id=event.actor_id or "",
                action_type=event.action_type or "",
                resource_type=event.resource_type or "",
                resource_id=event.resource_id or "",
                decision_outcome=event.decision_outcome or "allow",
                environment=event.environment or "unknown",
                session_id=str(action_context.get("session_id") or "").strip() or None,
                request_id=str(action_context.get("request_id") or event.trace_id or "").strip() or None,
            )
        )
    for event in cost_events:
        timeline.append(
            ObservabilityTraceEventResponse(
                timestamp=event.timestamp,
                event_type="cost",
                trace_id=event.trace_id or trace_id,
                span_id=event.cost_event_id or "",
                model_name=event.model_name or "",
                estimated_cost_cents=event.estimated_cost_cents,
                environment=event.environment or "",
                cache_hit=bool(getattr(event, "cache_hit", False)),
                session_id=str(event.session_id or "").strip() or None,
                request_id=str(event.request_id or "").strip() or None,
                user_properties=_parse_cost_user_properties(getattr(event, "properties_json", None)),
            )
        )
    timeline.sort(key=lambda item: item.timestamp)
    return ObservabilityTraceEventsResponse(
        trace_id=trace_id,
        event_count=len(timeline),
        events=timeline,
    )


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
                "user_login": ctx.user_login,
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
        action_token = action_type.strip()
        if action_token.endswith("."):
            query = query.filter(AuditEvent.action_type.ilike(f"{action_token}%"))
        else:
            query = query.filter(AuditEvent.action_type == action_token)
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
    return _schema_status_from_logs(logs)


def _csv_cell(value: object) -> str:
    text = str(value if value is not None else "")
    if any(char in text for char in [",", '"', "\n", "\r"]):
        return f'"{text.replace(chr(34), chr(34) + chr(34))}"'
    return text


@router.get("/observability/logs/export")
def export_observability_logs(
    format: Literal["csv", "json"] = Query(default="csv"),
    limit: int = Query(default=500, ge=1, le=2000),
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
    require_role(ctx, ROLES_OBSERVABILITY_READ)
    since = datetime.utcnow().replace(microsecond=0) - timedelta(hours=since_hours)
    query = db.query(AuditEvent).filter(AuditEvent.timestamp >= since)
    if ctx.actor_role == ROLE_AGENT_OWNER:
        actor_id = ctx.actor_id

    if trace_id:
        query = query.filter(AuditEvent.trace_id == trace_id)
    if action_type:
        action_token = action_type.strip()
        if action_token.endswith("."):
            query = query.filter(AuditEvent.action_type.ilike(f"{action_token}%"))
        else:
            query = query.filter(AuditEvent.action_type == action_token)
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

    events = query.order_by(AuditEvent.timestamp.desc()).offset(offset).limit(limit).all()
    mapped_logs = [_to_log_record(event) for event in events]
    if redact_sensitive:
        mapped_logs = [_redact_log_record(log) for log in mapped_logs]

    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    if format == "json":
        import json

        payload = json.dumps(mapped_logs, default=str)
        return Response(
            content=payload,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="observability-logs-{stamp}.json"'},
        )

    headers = [
        "timestamp",
        "actor_id",
        "actor_login",
        "action_type",
        "resource_type",
        "resource_id",
        "decision_outcome",
        "trace_id",
        "policy_version",
    ]
    lines = [",".join(headers)]
    for row in mapped_logs:
        lines.append(
            ",".join(_csv_cell(row.get(field)) for field in headers)
        )
    csv_body = "\n".join(lines)
    return Response(
        content=csv_body,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="observability-logs-{stamp}.csv"'},
    )


@router.get("/observability/siem-rules", response_model=ObservabilitySiemRulesListResponse)
def list_observability_siem_rules(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_OBSERVABILITY_READ)
    rules = load_siem_alert_rules(db)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="observability.siem_rules.list",
        resource_type="siem_alert_rule_catalog",
        resource_id="default",
        trace_id=f"trace-siem-rules-list-{datetime.utcnow().timestamp()}",
    )
    db.commit()
    return {"rule_count": len(rules), "rules": rules}


@router.post("/observability/siem-rules/export", response_model=ObservabilitySiemRulesExportResponse)
def export_observability_siem_rules(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_OBSERVABILITY_READ)
    bundle = export_siem_rules_catalog(db)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="observability.siem_rules.export",
        resource_type="siem_alert_rule_catalog",
        resource_id="export",
        trace_id=f"trace-siem-rules-export-{datetime.utcnow().timestamp()}",
    )
    db.commit()
    return {
        "exported_at": datetime.utcnow(),
        "rule_count": bundle["rule_count"],
        "siem_callback_count": bundle["siem_callback_count"],
        "rules": bundle["rules"],
        "default_rule_ids": bundle.get("default_rule_ids") or [],
        "siem_callbacks": bundle.get("siem_callbacks") or [],
    }


@router.get("/observability/siem-rules/evaluate", response_model=ObservabilitySiemRuleEvaluationResponse)
def evaluate_observability_siem_rules(
    limit: int = Query(default=100, ge=1, le=500),
    since_hours: int = Query(default=24, ge=1, le=720),
    action_type_prefix: Optional[str] = None,
    decision_outcome: Optional[str] = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_OBSERVABILITY_READ)
    since = datetime.utcnow().replace(microsecond=0) - timedelta(hours=since_hours)
    query = db.query(AuditEvent).filter(AuditEvent.timestamp >= since)
    if action_type_prefix and action_type_prefix.strip():
        query = query.filter(AuditEvent.action_type.like(f"{action_type_prefix.strip()}%"))
    if decision_outcome:
        query = query.filter(AuditEvent.decision_outcome == decision_outcome)
    events = query.order_by(AuditEvent.timestamp.desc()).limit(limit).all()
    matches = evaluate_siem_rules_against_events(db, events)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="observability.siem_rules.evaluate",
        resource_type="siem_alert_rule_catalog",
        resource_id="evaluate",
        trace_id=f"trace-siem-rules-evaluate-{datetime.utcnow().timestamp()}",
        action_context={"matched_count": len(matches), "evaluated_count": len(events)},
    )
    db.commit()
    return {
        "evaluated_count": len(events),
        "matched_count": len(matches),
        "matches": matches,
    }
