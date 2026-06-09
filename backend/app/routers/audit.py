from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import AuditEvent
from app.policy_constants import ROLE_AGENT_OWNER
from app.router_constants import AUDIT_READ_ROLES
from app.schemas import AuditEventResponse
from app.security import ActorContext, get_actor_context, require_role

router = APIRouter()
logger = get_logger(__name__)


@router.get("/audit/events", response_model=list[AuditEventResponse])
def list_audit_events(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    since_hours: int = Query(default=24, ge=1, le=720),
    action_type: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    decision_outcome: Optional[str] = None,
    response: Response = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "audit_events_list_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "limit": limit, "offset": offset}),
    )
    require_role(ctx, AUDIT_READ_ROLES)
    if ctx.actor_role == ROLE_AGENT_OWNER:
        if actor_id is not None and actor_id != ctx.actor_id:
            logger.error(
                "audit_events_scope_denied %s",
                sanitize_fields({"actor_id": ctx.actor_id, "requested_actor_id": actor_id}),
            )
            raise HTTPException(
                status_code=403,
                detail={
                    "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                    "message": "Agent Owner can only query own audit events.",
                    "actor_role": ctx.actor_role,
                    "required_scope": "actor_id == requester actor_id",
                    "policy_version": "v1",
                    "decision_trace_id": "authz-audit-scope-check",
                    "remediation_hint": "Query without actor_id or use your own actor id.",
                },
            )
        actor_id = ctx.actor_id

    since = datetime.utcnow().replace(microsecond=0) - timedelta(hours=since_hours)
    query = db.query(AuditEvent).filter(AuditEvent.timestamp >= since)
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

    total_count = query.count()
    if response is not None:
        response.headers["X-Total-Count"] = str(total_count)

    events = query.order_by(AuditEvent.timestamp.desc()).offset(offset).limit(limit).all()
    logger.info(
        "audit_events_list_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "returned_count": len(events), "total_count": total_count}),
    )
    return events
