from datetime import datetime, timezone
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api_errors import not_found_error, validation_error as api_validation_error
from app.database import get_db
from app.domain_constants import (
    DISCOVERY_CONFIDENCE_BUCKETS,
    DISCOVERY_CONFIDENCE_CONFLICT_MIN,
    DISCOVERY_CONFIDENCE_PROMOTE_MIN,
    DISCOVERY_CONFLICT_REASON_MEDIUM,
    DISCOVERY_QUERY_LIMIT_AGENTS,
    DISCOVERY_QUERY_LIMIT_CONFLICTS,
    DISCOVERY_QUERY_LIMIT_DUPLICATES,
    DISCOVERY_QUERY_LIMIT_PROMOTE,
    DISCOVERY_QUERY_LIMIT_SUMMARY_SCAN,
)
from app.discovery_connection_presets import (
    DISCOVERY_CONNECTION_PRESETS,
    DISCOVERY_PRIORITY_SOURCE_IDS,
    DISCOVERY_WELL_KNOWN_SOURCE_IDS,
    preset_for_source,
)
from app.discovery_sources import DISCOVERY_SOURCE_CATALOG, SUPPORTED_DISCOVERY_SOURCES
from app.logging_utils import get_logger, sanitize_fields
from app.models import Agent, AuditEvent, DiscoveryConnection, DiscoveryRecord
from app.router_constants import DISCOVERY_READ_ROLES, DISCOVERY_WRITE_ROLES
from app.runtime_constants import (
    RUNTIME_CONFIG_DISCOVERY_CONFIDENCE_CONFLICT_MIN,
    RUNTIME_CONFIG_DISCOVERY_CONFIDENCE_PROMOTE_MIN,
)
from app.schemas import (
    DiscoveryAlertResponse,
    DiscoveryConflictResponse,
    DiscoveryConnectionCreateRequest,
    DiscoveryConnectionPresetsResponse,
    DiscoveryConnectionPresetResponse,
    DiscoveryConnectionResponse,
    DiscoveryConnectionSyncResponse,
    DiscoveryConnectionTestResponse,
    DiscoveryConnectionUpdateRequest,
    DiscoveryDuplicateDismissRequest,
    DiscoveryDuplicateGroupResponse,
    DiscoveryDuplicateMergeRequest,
    DiscoveryDuplicateMergeResponse,
    DiscoveryPromoteQueueResponse,
    DiscoveryRecordResponse,
    DiscoveryResolveRequest,
    DiscoverySourceResponse,
    DiscoverySummaryCategoryResponse,
    DiscoverySummaryResponse,
    DiscoverySummaryTopologyNode,
    DiscoverySummaryTriageItem,
    DiscoveryConfidenceBucketResponse,
)
from app.security import ActorContext, get_actor_context, require_role
from app.services.audit import create_audit_event
from app.services.discovery_connection_service import (
    connection_response_payload,
    create_discovery_connection,
    update_discovery_connection,
)
from app.services.discovery_live_sync import sync_discovery_connection, sync_discovery_source_live
from app.services.discovery_connectors.registry import fetch_for_runtime
from app.services.discovery_connection_service import build_connection_runtime
from app.services.discovery_dedup import (
    build_duplicate_groups,
    dismiss_discovery_duplicate,
    merge_discovery_duplicate_group,
)
from app.services.runtime_config import get_runtime_config_int

router = APIRouter()
logger = get_logger(__name__)


def _discovery_confidence_thresholds(db: Session) -> tuple[int, int]:
    conflict_min = get_runtime_config_int(
        db,
        RUNTIME_CONFIG_DISCOVERY_CONFIDENCE_CONFLICT_MIN,
        DISCOVERY_CONFIDENCE_CONFLICT_MIN,
    )
    promote_min = get_runtime_config_int(
        db,
        RUNTIME_CONFIG_DISCOVERY_CONFIDENCE_PROMOTE_MIN,
        DISCOVERY_CONFIDENCE_PROMOTE_MIN,
    )
    return conflict_min, promote_min


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
    result = []
    now = datetime.utcnow()

    for definition in DISCOVERY_SOURCE_CATALOG:
        source_id = definition.source_id
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
        connection_count = (
            db.query(DiscoveryConnection)
            .filter(DiscoveryConnection.source_id == source_id)
            .count()
        )
        active_connection_count = (
            db.query(DiscoveryConnection)
            .filter(
                DiscoveryConnection.source_id == source_id,
                DiscoveryConnection.enabled.is_(True),
                DiscoveryConnection.status == "active",
            )
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
                "platform": definition.platform,
                "category": definition.category,
                "label": definition.label,
                "status": status,
                "last_sync_at": last_sync_at,
                "sync_lag_minutes": sync_lag_minutes,
                "discovered_count": discovered_count,
                "connection_count": connection_count,
                "active_connection_count": active_connection_count,
                "well_known": source_id in DISCOVERY_WELL_KNOWN_SOURCE_IDS,
                "priority": source_id in DISCOVERY_PRIORITY_SOURCE_IDS,
            }
        )
    return result


@router.get("/discovery/summary", response_model=DiscoverySummaryResponse)
def get_discovery_summary(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, DISCOVERY_READ_ROLES)
    conflict_min, promote_min = _discovery_confidence_thresholds(db)
    sources = list_discovery_sources(db=db, ctx=ctx)

    healthy_sources = sum(1 for source in sources if source["status"] == "healthy")
    stale_sources = sum(1 for source in sources if source["status"] == "degraded")
    unknown_sources = sum(1 for source in sources if source["status"] == "unknown")
    connection_count = sum(source["connection_count"] for source in sources)
    active_connection_count = sum(source["active_connection_count"] for source in sources)
    discovered_agent_count = (
        db.query(DiscoveryRecord)
        .filter(DiscoveryRecord.discovery_status == "discovered")
        .count()
    )

    category_map: dict[str, dict[str, int]] = {}
    topology: list[DiscoverySummaryTopologyNode] = []
    for source in sources:
        category = str(source.get("category") or "other")
        bucket = category_map.setdefault(
            category,
            {"source_count": 0, "discovered_count": 0, "healthy_count": 0, "stale_count": 0},
        )
        bucket["source_count"] += 1
        bucket["discovered_count"] += int(source.get("discovered_count") or 0)
        status = str(source.get("status") or "unknown")
        if status == "healthy":
            bucket["healthy_count"] += 1
        elif status == "degraded":
            bucket["stale_count"] += 1

        tone = "healthy" if status == "healthy" else "stale" if status == "degraded" else "neutral"
        if int(source.get("discovered_count") or 0) == 0 and status == "unknown":
            tone = "neutral"
        topology.append(
            DiscoverySummaryTopologyNode(
                node_id=str(source.get("source_id") or ""),
                label=str(source.get("label") or source.get("source_id") or ""),
                count=int(source.get("discovered_count") or 0),
                tone=tone,
            )
        )

    categories = [
        DiscoverySummaryCategoryResponse(
            category=category,
            source_count=values["source_count"],
            discovered_count=values["discovered_count"],
            healthy_count=values["healthy_count"],
            stale_count=values["stale_count"],
        )
        for category, values in sorted(category_map.items(), key=lambda item: item[0])
    ]

    conflict_records = (
        db.query(DiscoveryRecord)
        .filter(
            DiscoveryRecord.discovery_status == "discovered",
            DiscoveryRecord.promoted_to_agent_id.is_(None),
            DiscoveryRecord.discovery_confidence >= conflict_min,
            DiscoveryRecord.discovery_confidence < promote_min,
        )
        .order_by(DiscoveryRecord.discovery_confidence.desc(), DiscoveryRecord.last_discovered_at.desc())
        .limit(DISCOVERY_QUERY_LIMIT_CONFLICTS)
        .all()
    )
    conflict_count = len(conflict_records)

    alert_records = (
        db.query(DiscoveryRecord)
        .filter(
            DiscoveryRecord.discovery_status == "discovered",
            DiscoveryRecord.promoted_to_agent_id.is_(None),
            DiscoveryRecord.discovery_confidence >= promote_min,
        )
        .order_by(DiscoveryRecord.discovery_confidence.desc(), DiscoveryRecord.last_discovered_at.desc())
        .limit(DISCOVERY_QUERY_LIMIT_PROMOTE)
        .all()
    )
    high_alerts = [record for record in alert_records if _risk_tier_for_record(record) == "high"]
    high_alert_count = len(high_alerts)
    promote_ready_count = len(alert_records)

    duplicate_records = (
        db.query(DiscoveryRecord)
        .filter(
            DiscoveryRecord.discovery_status == "discovered",
            DiscoveryRecord.promoted_to_agent_id.is_(None),
        )
        .order_by(DiscoveryRecord.canonical_agent_key.asc(), DiscoveryRecord.discovery_confidence.desc())
        .limit(DISCOVERY_QUERY_LIMIT_DUPLICATES)
        .all()
    )
    duplicate_group_count = len(build_duplicate_groups(duplicate_records))

    urgent_triage: list[DiscoverySummaryTriageItem] = []
    for record in high_alerts[:3]:
        urgent_triage.append(
            DiscoverySummaryTriageItem(
                item_type="alert",
                discovered_agent_id=record.discovered_agent_id,
                detail=f"{record.source_system} · high-risk unmanaged agent",
                urgency="high",
                discovery_confidence=record.discovery_confidence,
            )
        )
    for record in conflict_records[:3]:
        urgent_triage.append(
            DiscoverySummaryTriageItem(
                item_type="conflict",
                discovered_agent_id=record.discovered_agent_id,
                detail=f"{record.source_system} · medium confidence conflict",
                urgency="high" if record.discovery_confidence >= 75 else "normal",
                discovery_confidence=record.discovery_confidence,
            )
        )
    for record in alert_records[:2]:
        urgent_triage.append(
            DiscoverySummaryTriageItem(
                item_type="promote",
                discovered_agent_id=record.discovered_agent_id,
                detail=f"{record.source_system} · ready for promotion",
                urgency="normal",
                discovery_confidence=record.discovery_confidence,
            )
        )
    urgent_triage.sort(
        key=lambda item: (
            0 if item.urgency == "high" else 1,
            -item.discovery_confidence,
        )
    )

    discovered_records = (
        db.query(DiscoveryRecord)
        .filter(DiscoveryRecord.discovery_status == "discovered")
        .limit(DISCOVERY_QUERY_LIMIT_SUMMARY_SCAN)
        .all()
    )
    confidence_buckets = []
    for label, low, high in DISCOVERY_CONFIDENCE_BUCKETS:
        count = sum(1 for record in discovered_records if low <= record.discovery_confidence <= high)
        confidence_buckets.append(DiscoveryConfidenceBucketResponse(label=label, count=count))

    posture_score = 100
    posture_score -= min(35, stale_sources * 6)
    posture_score -= min(30, high_alert_count * 4)
    posture_score -= min(20, conflict_count * 2)
    posture_score -= min(15, unknown_sources * 3)
    posture_score = max(0, posture_score)

    return DiscoverySummaryResponse(
        generated_at=datetime.now(timezone.utc),
        discovered_agent_count=discovered_agent_count,
        healthy_sources=healthy_sources,
        stale_sources=stale_sources,
        unknown_sources=unknown_sources,
        connection_count=connection_count,
        active_connection_count=active_connection_count,
        conflict_count=conflict_count,
        high_alert_count=high_alert_count,
        promote_ready_count=promote_ready_count,
        duplicate_group_count=duplicate_group_count,
        posture_score=posture_score,
        confidence_buckets=confidence_buckets,
        categories=categories,
        topology=topology[:12],
        urgent_triage=urgent_triage[:8],
    )


@router.get("/discovery/connection-presets", response_model=DiscoveryConnectionPresetsResponse)
def list_discovery_connection_presets(
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, DISCOVERY_READ_ROLES)
    presets = []
    for source_id in DISCOVERY_WELL_KNOWN_SOURCE_IDS:
        preset = preset_for_source(source_id)
        if preset:
            presets.append(
                DiscoveryConnectionPresetResponse(
                    source_id=source_id,
                    connection_name=str(preset.get("connection_name") or source_id),
                    secret_ref=str(preset.get("secret_ref") or ""),
                    base_url=str(preset.get("base_url") or ""),
                    connection_config=preset.get("connection_config") or {},
                )
            )
    return DiscoveryConnectionPresetsResponse(
        priority_source_ids=list(DISCOVERY_PRIORITY_SOURCE_IDS),
        well_known_source_ids=list(DISCOVERY_WELL_KNOWN_SOURCE_IDS),
        presets=presets,
    )


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
    if source_id not in SUPPORTED_DISCOVERY_SOURCES:
        raise api_validation_error("Unsupported discovery source", decision_trace_id="discovery-source-unsupported")
    discovered_count, connections_succeeded, connections_failed = sync_discovery_source_live(
        db,
        source_id,
        actor_id=ctx.actor_id,
    )
    trace_id = f"trace-{source_id}-{uuid4()}"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="discovery.sync",
        resource_type="source",
        resource_id=source_id,
        trace_id=trace_id,
    )
    db.commit()
    logger.info(
        "discovery_sync_completed %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "source_id": source_id,
                "discovered_count": discovered_count,
                "connections_succeeded": connections_succeeded,
                "connections_failed": connections_failed,
            }
        ),
    )
    return {
        "source_id": source_id,
        "sync_status": "completed",
        "discovered_count": discovered_count,
        "connections_succeeded": connections_succeeded,
        "connections_failed": connections_failed,
    }


@router.get("/discovery/connections", response_model=list[DiscoveryConnectionResponse])
def list_discovery_connections(
    source_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, DISCOVERY_READ_ROLES)
    query = db.query(DiscoveryConnection).order_by(DiscoveryConnection.connection_name.asc())
    if source_id:
        query = query.filter(DiscoveryConnection.source_id == source_id.strip())
    if tenant_id:
        query = query.filter(DiscoveryConnection.tenant_id == tenant_id.strip())
    rows = query.limit(500).all()
    return [connection_response_payload(row) for row in rows]


@router.get("/discovery/connections/{connection_id}", response_model=DiscoveryConnectionResponse)
def get_discovery_connection(
    connection_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, DISCOVERY_READ_ROLES)
    row = db.query(DiscoveryConnection).filter_by(connection_id=connection_id).first()
    if not row:
        raise not_found_error("discovery_connection", connection_id, decision_trace_id="discovery-connection-not-found")
    return connection_response_payload(row)


@router.post("/discovery/connections", response_model=DiscoveryConnectionResponse)
def create_discovery_connection_route(
    payload: DiscoveryConnectionCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, DISCOVERY_WRITE_ROLES)
    row = create_discovery_connection(
        db,
        payload=payload.model_dump(),
        actor_id=ctx.actor_id,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="discovery.connection.create",
        resource_type="discovery_connection",
        resource_id=row.connection_id,
        trace_id=f"trace-{row.connection_id}",
    )
    db.commit()
    db.refresh(row)
    return connection_response_payload(row)


@router.put("/discovery/connections/{connection_id}", response_model=DiscoveryConnectionResponse)
def update_discovery_connection_route(
    connection_id: str,
    payload: DiscoveryConnectionUpdateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, DISCOVERY_WRITE_ROLES)
    row = db.query(DiscoveryConnection).filter_by(connection_id=connection_id).first()
    if not row:
        raise not_found_error("discovery_connection", connection_id, decision_trace_id="discovery-connection-not-found")
    update_data = payload.model_dump(exclude_unset=True)
    update_discovery_connection(db, row, payload=update_data, actor_id=ctx.actor_id)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="discovery.connection.update",
        resource_type="discovery_connection",
        resource_id=row.connection_id,
        trace_id=f"trace-{row.connection_id}",
    )
    db.commit()
    db.refresh(row)
    return connection_response_payload(row)


@router.delete("/discovery/connections/{connection_id}")
def delete_discovery_connection_route(
    connection_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, DISCOVERY_WRITE_ROLES)
    row = db.query(DiscoveryConnection).filter_by(connection_id=connection_id).first()
    if not row:
        raise not_found_error("discovery_connection", connection_id, decision_trace_id="discovery-connection-not-found")
    db.delete(row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="discovery.connection.delete",
        resource_type="discovery_connection",
        resource_id=connection_id,
        trace_id=f"trace-{connection_id}",
    )
    db.commit()
    return {"connection_id": connection_id, "status": "deleted"}


@router.post("/discovery/connections/{connection_id}/test", response_model=DiscoveryConnectionTestResponse)
def test_discovery_connection_route(
    connection_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, DISCOVERY_WRITE_ROLES)
    row = db.query(DiscoveryConnection).filter_by(connection_id=connection_id).first()
    if not row:
        raise not_found_error("discovery_connection", connection_id, decision_trace_id="discovery-connection-not-found")
    try:
        runtime = build_connection_runtime(db, row)
        candidates = fetch_for_runtime(db, runtime)
        return DiscoveryConnectionTestResponse(
            connection_id=connection_id,
            test_status="success",
            message=f"Live fetch succeeded ({len(candidates)} sample resource(s)).",
            sample_count=len(candidates),
        )
    except Exception as exc:
        return DiscoveryConnectionTestResponse(
            connection_id=connection_id,
            test_status="failed",
            message=str(exc),
            sample_count=0,
        )


@router.post("/discovery/connections/{connection_id}/sync", response_model=DiscoveryConnectionSyncResponse)
def sync_discovery_connection_route(
    connection_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, DISCOVERY_WRITE_ROLES)
    row = db.query(DiscoveryConnection).filter_by(connection_id=connection_id).first()
    if not row:
        raise not_found_error("discovery_connection", connection_id, decision_trace_id="discovery-connection-not-found")
    count, error = sync_discovery_connection(db, row, actor_id=ctx.actor_id)
    db.commit()
    return DiscoveryConnectionSyncResponse(
        connection_id=connection_id,
        sync_status="failed" if error else "completed",
        discovered_count=count,
        error=error or "",
    )



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
            DiscoveryRecord.discovery_confidence >= DISCOVERY_CONFIDENCE_CONFLICT_MIN,
            DiscoveryRecord.discovery_confidence < DISCOVERY_CONFIDENCE_PROMOTE_MIN,
        )
        .order_by(DiscoveryRecord.discovery_confidence.desc(), DiscoveryRecord.last_discovered_at.desc())
        .limit(DISCOVERY_QUERY_LIMIT_CONFLICTS)
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
            "conflict_reason": DISCOVERY_CONFLICT_REASON_MEDIUM,
            "review_priority": "high" if r.discovery_confidence >= 75 else "normal",
        }
        for r in records
    ]


@router.get("/discovery/duplicates", response_model=list[DiscoveryDuplicateGroupResponse])
def list_discovery_duplicates(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, DISCOVERY_READ_ROLES)
    records = (
        db.query(DiscoveryRecord)
        .filter(
            DiscoveryRecord.discovery_status == "discovered",
            DiscoveryRecord.promoted_to_agent_id.is_(None),
        )
        .order_by(DiscoveryRecord.canonical_agent_key.asc(), DiscoveryRecord.discovery_confidence.desc())
        .limit(DISCOVERY_QUERY_LIMIT_DUPLICATES)
        .all()
    )
    return build_duplicate_groups(records)[:200]


@router.post("/discovery/duplicates/merge", response_model=DiscoveryDuplicateMergeResponse)
def merge_discovery_duplicates(
    payload: DiscoveryDuplicateMergeRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, DISCOVERY_WRITE_ROLES)
    result = merge_discovery_duplicate_group(
        db,
        canonical_discovered_agent_id=payload.canonical_discovered_agent_id.strip(),
        actor_id=ctx.actor_id,
        merge_discovered_agent_ids=payload.merge_discovered_agent_ids,
    )
    db.commit()
    return result


@router.post("/discovery/duplicates/dismiss")
def dismiss_discovery_duplicate_route(
    payload: DiscoveryDuplicateDismissRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, DISCOVERY_WRITE_ROLES)
    result = dismiss_discovery_duplicate(
        db,
        discovered_agent_id=payload.discovered_agent_id.strip(),
        actor_id=ctx.actor_id,
        reason=payload.reason,
    )
    db.commit()
    return result


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
            DiscoveryRecord.discovery_confidence >= DISCOVERY_CONFIDENCE_PROMOTE_MIN,
        )
        .order_by(DiscoveryRecord.discovery_confidence.desc(), DiscoveryRecord.last_discovered_at.desc())
        .limit(DISCOVERY_QUERY_LIMIT_PROMOTE)
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
            DiscoveryRecord.discovery_confidence >= DISCOVERY_CONFIDENCE_PROMOTE_MIN,
        )
        .order_by(DiscoveryRecord.discovery_confidence.desc(), DiscoveryRecord.last_discovered_at.desc())
        .limit(DISCOVERY_QUERY_LIMIT_PROMOTE)
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
        raise not_found_error("discovery_record", record_id, decision_trace_id="discovery-record-not-found")

    if payload.decision not in {"approve", "reject"}:
        logger.error("discovery_resolve_invalid_decision")
        raise api_validation_error("Decision must be approve or reject", decision_trace_id="discovery-decision-invalid")

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
        raise not_found_error("discovery_record", record_id, decision_trace_id="discovery-record-not-found")

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
