from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import Agent, AuditEvent, DiscoveryRecord
from app.router_constants import DISCOVERY_READ_ROLES, DISCOVERY_WRITE_ROLES
from app.schemas import (
    DiscoveryAlertResponse,
    DiscoveryConflictResponse,
    DiscoveryPromoteQueueResponse,
    DiscoveryRecordResponse,
    DiscoveryResolveRequest,
    DiscoverySourceResponse,
)
from app.security import ActorContext, get_actor_context, require_role
from app.services.audit import create_audit_event

router = APIRouter()
logger = get_logger(__name__)


def _risk_tier_for_record(record: DiscoveryRecord) -> str:
    key = (record.canonical_agent_key or "").lower()
    source = (record.source_system or "").lower()
    if "prod" in key or "payment" in key or "security" in key or source == "gateway_telemetry":
        return "high"
    if record.discovery_confidence >= 80:
        return "medium"
    return "low"


@router.get("/discovery/sources", response_model=list[DiscoverySourceResponse])
def list_discovery_sources(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, DISCOVERY_READ_ROLES)
    source_ids = ["runtime_inventory", "code_metadata", "gateway_telemetry"]
    result = []
    now = datetime.utcnow()

    for source_id in source_ids:
        latest_sync = (
            db.query(AuditEvent)
            .filter(
                AuditEvent.action_type == "discovery.sync",
                AuditEvent.resource_type == "source",
                AuditEvent.resource_id == source_id,
            )
            .order_by(AuditEvent.timestamp.desc())
            .first()
        )
        discovered_count = (
            db.query(DiscoveryRecord)
            .filter(DiscoveryRecord.source_system == source_id)
            .count()
        )

        status = "healthy"
        sync_lag_minutes = None
        last_sync_at = latest_sync.timestamp if latest_sync else None
        if latest_sync:
            sync_lag_minutes = int((now - latest_sync.timestamp).total_seconds() // 60)
            if sync_lag_minutes > 1440:
                status = "degraded"
        else:
            status = "unknown"

        result.append(
            {
                "source_id": source_id,
                "status": status,
                "last_sync_at": last_sync_at,
                "sync_lag_minutes": sync_lag_minutes,
                "discovered_count": discovered_count,
            }
        )
    return result


@router.post("/discovery/sources/{source_id}/sync")
def sync_discovery_source(
    source_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "discovery_sync_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "source_id": source_id}),
    )
    require_role(ctx, DISCOVERY_WRITE_ROLES)
    dummy = DiscoveryRecord(
        discovered_agent_id=str(uuid4()),
        canonical_agent_key=f"{source_id}:sample-agent",
        source_system=source_id,
        source_fingerprint=str(uuid4()),
        discovery_confidence=80,
        discovery_status="discovered",
        last_discovered_at=datetime.utcnow(),
    )
    db.add(dummy)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="discovery.sync",
        resource_type="source",
        resource_id=source_id,
        trace_id=f"trace-{dummy.discovered_agent_id}",
    )
    db.commit()
    logger.info(
        "discovery_sync_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "source_id": source_id}),
    )
    return {"source_id": source_id, "sync_status": "completed"}


@router.get("/discovery/agents", response_model=list[DiscoveryRecordResponse])
def list_discovered_agents(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, DISCOVERY_READ_ROLES)
    return db.query(DiscoveryRecord).order_by(DiscoveryRecord.last_discovered_at.desc()).all()


@router.get("/discovery/conflicts", response_model=list[DiscoveryConflictResponse])
def list_discovery_conflicts(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, DISCOVERY_READ_ROLES)

    records = (
        db.query(DiscoveryRecord)
        .filter(
            DiscoveryRecord.discovery_status == "discovered",
            DiscoveryRecord.promoted_to_agent_id.is_(None),
            DiscoveryRecord.discovery_confidence >= 50,
            DiscoveryRecord.discovery_confidence < 85,
        )
        .order_by(DiscoveryRecord.discovery_confidence.desc(), DiscoveryRecord.last_discovered_at.desc())
        .limit(2000)
        .all()
    )
    return [
        {
            "discovered_agent_id": r.discovered_agent_id,
            "canonical_agent_key": r.canonical_agent_key,
            "source_system": r.source_system,
            "discovery_confidence": r.discovery_confidence,
            "discovery_status": r.discovery_status,
            "last_discovered_at": r.last_discovered_at,
            "conflict_reason": "medium_confidence_conflict",
            "review_priority": "high" if r.discovery_confidence >= 75 else "normal",
        }
        for r in records
    ]


@router.get("/discovery/alerts", response_model=list[DiscoveryAlertResponse])
def list_discovery_alerts(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, DISCOVERY_READ_ROLES)

    candidates = (
        db.query(DiscoveryRecord)
        .filter(
            DiscoveryRecord.discovery_status == "discovered",
            DiscoveryRecord.promoted_to_agent_id.is_(None),
            DiscoveryRecord.discovery_confidence >= 85,
        )
        .order_by(DiscoveryRecord.discovery_confidence.desc(), DiscoveryRecord.last_discovered_at.desc())
        .limit(2000)
        .all()
    )

    alerts = []
    for record in candidates:
        risk_tier = _risk_tier_for_record(record)
        if risk_tier != "high":
            continue
        alerts.append(
            {
                "alert_id": f"alert-{record.discovered_agent_id}",
                "discovered_agent_id": record.discovered_agent_id,
                "source_system": record.source_system,
                "discovery_confidence": record.discovery_confidence,
                "severity": "high",
                "alert_type": "unmanaged_high_risk_discovered_agent",
                "message": "High-risk discovered agent is unmanaged and requires review.",
                "last_discovered_at": record.last_discovered_at,
            }
        )
    return alerts


@router.get("/discovery/promote-queue", response_model=list[DiscoveryPromoteQueueResponse])
def list_discovery_promote_queue(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, DISCOVERY_READ_ROLES)

    records = (
        db.query(DiscoveryRecord)
        .filter(
            DiscoveryRecord.discovery_status == "discovered",
            DiscoveryRecord.promoted_to_agent_id.is_(None),
            DiscoveryRecord.discovery_confidence >= 85,
        )
        .order_by(DiscoveryRecord.discovery_confidence.desc(), DiscoveryRecord.last_discovered_at.desc())
        .limit(2000)
        .all()
    )
    return [
        {
            "discovered_agent_id": record.discovered_agent_id,
            "canonical_agent_key": record.canonical_agent_key,
            "source_system": record.source_system,
            "discovery_confidence": record.discovery_confidence,
            "discovery_status": record.discovery_status,
            "last_discovered_at": record.last_discovered_at,
            "queue_reason": "high_confidence_ready_for_promotion",
        }
        for record in records
    ]


@router.post("/discovery/resolve")
def resolve_discovery_record(
    payload: DiscoveryResolveRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "discovery_resolve_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "discovered_agent_id": payload.discovered_agent_id}),
    )
    require_role(ctx, DISCOVERY_WRITE_ROLES)
    record = db.query(DiscoveryRecord).filter_by(discovered_agent_id=payload.discovered_agent_id).first()
    if not record:
        logger.error(
            "discovery_resolve_not_found %s",
            sanitize_fields({"discovered_agent_id": payload.discovered_agent_id}),
        )
        raise HTTPException(status_code=404, detail="Discovery record not found")

    if payload.decision not in {"approve", "reject"}:
        logger.error("discovery_resolve_invalid_decision")
        raise HTTPException(status_code=400, detail="Decision must be approve or reject")

    record.discovery_status = "resolved" if payload.decision == "approve" else "rejected"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="discovery.resolve",
        resource_type="discovery_record",
        resource_id=record.discovered_agent_id,
        trace_id=f"trace-{record.discovered_agent_id}",
    )
    db.commit()
    logger.info(
        "discovery_resolve_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "discovered_agent_id": record.discovered_agent_id}),
    )
    return {"discovered_agent_id": record.discovered_agent_id, "status": record.discovery_status}


@router.post("/discovery/promote/{discovered_agent_id}")
def promote_discovered_agent(
    discovered_agent_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "discovery_promote_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "discovered_agent_id": discovered_agent_id}),
    )
    require_role(ctx, DISCOVERY_WRITE_ROLES)
    record = db.query(DiscoveryRecord).filter_by(discovered_agent_id=discovered_agent_id).first()
    if not record:
        logger.error("discovery_promote_not_found %s", sanitize_fields({"discovered_agent_id": discovered_agent_id}))
        raise HTTPException(status_code=404, detail="Discovery record not found")

    if record.promoted_to_agent_id:
        logger.info(
            "discovery_promote_already_promoted %s",
            sanitize_fields({"discovered_agent_id": discovered_agent_id, "agent_id": record.promoted_to_agent_id}),
        )
        return {"agent_id": record.promoted_to_agent_id, "status": "already_promoted"}

    agent = Agent(
        agent_id=str(uuid4()),
        name=record.canonical_agent_key,
        owner_id="discovery-owner",
        owner_name="Discovery Owner",
        owner_team="Platform",
        agent_type="other",
        description=f"Promoted from discovery source {record.source_system}",
        risk_tier="medium",
        status="active",
    )
    db.add(agent)
    record.promoted_to_agent_id = agent.agent_id
    record.discovery_status = "promoted"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="discovery.promote",
        resource_type="discovery_record",
        resource_id=record.discovered_agent_id,
        trace_id=f"trace-{record.discovered_agent_id}",
    )
    db.commit()
    logger.info(
        "discovery_promote_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "discovered_agent_id": discovered_agent_id, "agent_id": agent.agent_id}),
    )
    return {"agent_id": agent.agent_id, "status": "promoted"}
