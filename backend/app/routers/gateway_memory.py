from __future__ import annotations

from datetime import datetime
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AgentMemoryRecord
from app.router_constants import (
    GATEWAY_ADMIN_OR_AI_OPS_ROLES,
    GATEWAY_INFERENCE_DELETE_ROLES,
    GATEWAY_READ_ROLES,
    ROLE_AGENT_OWNER,
)
from app.schemas import (
    GatewayMemoryOverviewResponse,
    GatewayMemoryPlatformConfigResponse,
    GatewayMemoryRecordCreateRequest,
    GatewayMemoryRecordDeleteResponse,
    GatewayMemoryRecordListResponse,
    GatewayMemoryRecordResponse,
    GatewayVectorStoreContextResponse,
    GatewayVectorStoreHealthResponse,
)
from app.security import ActorContext, get_actor_context, require_dual_approval, require_role
from app.services.audit import create_audit_event
from app.services.gateway_context_config import build_gateway_context_config
from app.services.gateway_memory import (
    build_gateway_memory_overview,
    create_memory_record,
    list_memory_records,
    serialize_memory_record,
)
from app.services.gateway_vector_stores import build_vector_store_context, list_vector_stores, vector_store_health_check
from app.services.gateway_notification_channels import (
    build_notification_channel_context,
    list_notification_channels,
)

router = APIRouter()

_MEMORY_READ_ROLES = set(GATEWAY_READ_ROLES) | {ROLE_AGENT_OWNER}
_MEMORY_WRITE_ROLES = set(GATEWAY_ADMIN_OR_AI_OPS_ROLES) | {ROLE_AGENT_OWNER}
_MEMORY_DELETE_ROLES = set(GATEWAY_INFERENCE_DELETE_ROLES)

_READ_FORBIDDEN = {
    403: {"description": "Actor role is not allowed for gateway memory read operations."},
}
_WRITE_FORBIDDEN = {
    403: {"description": "Actor role is not allowed for gateway memory write operations."},
}
_DELETE_FORBIDDEN = {
    403: {"description": "Actor role is not allowed, or production dual approval is missing."},
}
_NOT_FOUND = {
    404: {"description": "Memory record not found."},
}


def _is_prod_environment(value: str) -> bool:
    from app.services.runtime_env import is_prod_target_environment

    return is_prod_target_environment(value)


def _agent_owner_scope(actor_id: str) -> str:
    return actor_id


@router.get(
    "/gateway/memory/config",
    response_model=GatewayMemoryPlatformConfigResponse,
    summary="Gateway memory, cache, and vector store platform configuration",
    description=(
        "Returns tunable runtime-config values for short/long-term memory, semantic cache defaults, "
        "and vector store registry (provider types, connection metadata, search top-k, embedding model)."
    ),
    responses=_READ_FORBIDDEN,
)
def gateway_memory_platform_config(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _MEMORY_READ_ROLES)
    trace_id = f"trace-gateway-memory-config-read-{uuid4()}"
    payload = build_gateway_context_config(db)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.memory.config.read",
        resource_type="gateway_memory_config",
        resource_id="platform",
        trace_id=trace_id,
    )
    db.commit()
    return payload


@router.get(
    "/gateway/vector-stores",
    summary="List configured vector stores",
    description="Reads the vector store registry from runtime config `gateway.vector_stores_json`.",
    responses=_READ_FORBIDDEN,
)
def gateway_vector_stores_list(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _MEMORY_READ_ROLES)
    return {"object": "list", "data": list_vector_stores(db)}


@router.get(
    "/gateway/notification-channels",
    summary="List configured notification channels",
    description="Reads the notification channel registry from runtime config `gateway.notification_channels_json`.",
    responses=_READ_FORBIDDEN,
)
def gateway_notification_channels_list(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _MEMORY_READ_ROLES)
    return {"object": "list", "data": list_notification_channels(db, enabled_only=False)}


@router.get(
    "/gateway/notification-channels/{channel_id}/context",
    summary="Notification channel posture context bundle",
    description=(
        "Read-only bundle of channel configuration, credential binding posture, "
        "and Phase 1 stub-runtime notes for operator review."
    ),
    responses={**_READ_FORBIDDEN, 404: _NOT_FOUND[404]},
)
def gateway_notification_channel_context(
    channel_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _MEMORY_READ_ROLES)
    trace_id = f"trace-gateway-notification-channel-context-{uuid4()}"
    payload = build_notification_channel_context(db, channel_id)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.notification_channel.context.read",
        resource_type="notification_channel",
        resource_id=str(channel_id),
        trace_id=trace_id,
    )
    db.commit()
    return payload


@router.post(
    "/gateway/vector-stores/{store_id}/health",
    response_model=GatewayVectorStoreHealthResponse,
    summary="Vector store configuration health check",
    description="Validates store configuration posture. External connectivity may require MCP bridge integration.",
    responses={**_READ_FORBIDDEN, 404: _NOT_FOUND[404]},
)
def gateway_vector_store_health(
    store_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _MEMORY_READ_ROLES)
    trace_id = f"trace-gateway-vector-store-health-{uuid4()}"
    payload = vector_store_health_check(db, store_id)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.vector_store.health",
        resource_type="vector_store",
        resource_id=str(store_id),
        trace_id=trace_id,
    )
    db.commit()
    return payload


@router.get(
    "/gateway/vector-stores/{store_id}/context",
    response_model=GatewayVectorStoreContextResponse,
    summary="Vector store posture context bundle",
    description=(
        "Read-only bundle of store configuration, platform defaults, health posture, "
        "secret integration mode, and MCP bridge linkage for operator review."
    ),
    responses={**_READ_FORBIDDEN, 404: _NOT_FOUND[404]},
)
def gateway_vector_store_context(
    store_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _MEMORY_READ_ROLES)
    trace_id = f"trace-gateway-vector-store-context-{uuid4()}"
    payload = build_vector_store_context(db, store_id)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.vector_store.context.read",
        resource_type="vector_store",
        resource_id=str(store_id),
        trace_id=trace_id,
    )
    db.commit()
    return payload


@router.get(
    "/gateway/memory/overview",
    response_model=GatewayMemoryOverviewResponse,
    summary="Gateway memory and cache overview",
    description=(
        "Aggregates semantic cache policy posture, short-term memory counts (records, checkpoints, "
        "realtime sessions), and long-term memory counts (records, responses, files, system rules)."
    ),
    responses=_READ_FORBIDDEN,
)
def gateway_memory_overview(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _MEMORY_READ_ROLES)
    trace_id = f"trace-gateway-memory-overview-{uuid4()}"
    actor_filter = _agent_owner_scope(ctx.actor_id) if ctx.actor_role == ROLE_AGENT_OWNER else None
    payload = build_gateway_memory_overview(db, actor_id_filter=actor_filter)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.memory.overview.read",
        resource_type="gateway_memory",
        resource_id="overview",
        trace_id=trace_id,
    )
    db.commit()
    return payload


@router.post(
    "/gateway/memory/records",
    response_model=GatewayMemoryRecordResponse,
    summary="Create gateway memory record",
    description=(
        "Persists a short-term or long-term memory record scoped to session, conversation, agent, or global. "
        "Short-term records receive TTL from runtime config `gateway.memory.short_term_ttl_seconds`. "
        "Production long-term creates require Security Approver dual-approval headers. "
        "Emits audit event `gateway.memory.record.create`."
    ),
    responses={**_WRITE_FORBIDDEN, 409: {"description": "Scope record limit reached."}},
)
def gateway_memory_record_create(
    payload: GatewayMemoryRecordCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _MEMORY_WRITE_ROLES)
    trace_id = f"trace-gateway-memory-create-{uuid4()}"
    memory_id = f"mem-{uuid4().hex[:16]}"

    if payload.memory_tier == "long_term" and _is_prod_environment(payload.environment):
        try:
            require_dual_approval(ctx)
        except HTTPException as exc:
            create_audit_event(
                db,
                actor_id=ctx.actor_id,
                action_type="gateway.memory.record.create",
                resource_type="gateway_memory_record",
                resource_id=memory_id,
                trace_id=trace_id,
                decision_outcome="deny" if exc.status_code == 403 else "warn",
            )
            db.commit()
            raise

    row = create_memory_record(
        db,
        actor_id=ctx.actor_id,
        memory_tier=payload.memory_tier,
        scope_type=payload.scope_type,
        scope_id=payload.scope_id,
        label=payload.label,
        content=payload.content,
        metadata_json=payload.metadata_json,
        environment=payload.environment,
        memory_id=memory_id,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.memory.record.create",
        resource_type="gateway_memory_record",
        resource_id=row.memory_id,
        trace_id=trace_id,
    )
    db.commit()
    return serialize_memory_record(row)


@router.get(
    "/gateway/memory/records",
    response_model=GatewayMemoryRecordListResponse,
    summary="List gateway memory records",
    description=(
        "Lists active memory records with optional tier, scope, and actor filters. "
        "Auto-expires stale short-term records before listing."
    ),
    responses=_READ_FORBIDDEN,
)
def gateway_memory_records_list(
    memory_tier: Optional[str] = Query(default=None),
    scope_type: Optional[str] = Query(default=None),
    scope_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _MEMORY_READ_ROLES)
    trace_id = f"trace-gateway-memory-list-{uuid4()}"

    actor_filter = _agent_owner_scope(ctx.actor_id) if ctx.actor_role == ROLE_AGENT_OWNER else None
    rows, total = list_memory_records(
        db,
        memory_tier=memory_tier,
        scope_type=scope_type,
        scope_id=scope_id,
        actor_id_filter=actor_filter,
        limit=limit,
        offset=offset,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.memory.record.list",
        resource_type="gateway_memory",
        resource_id="records",
        trace_id=trace_id,
    )
    db.commit()
    return {
        "object": "list",
        "data": [serialize_memory_record(row) for row in rows],
        "total": total,
    }


@router.get(
    "/gateway/memory/records/{memory_id}",
    response_model=GatewayMemoryRecordResponse,
    summary="Get gateway memory record",
    description="Returns a single active memory record by id.",
    responses={**_READ_FORBIDDEN, **_NOT_FOUND},
)
def gateway_memory_record_get(
    memory_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _MEMORY_READ_ROLES)
    trace_id = f"trace-gateway-memory-get-{uuid4()}"

    row = (
        db.query(AgentMemoryRecord)
        .filter_by(memory_id=str(memory_id), status="active")
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Memory record not found")

    if ctx.actor_role == ROLE_AGENT_OWNER and row.actor_id != ctx.actor_id:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.memory.record.read",
            resource_type="gateway_memory_record",
            resource_id=memory_id,
            trace_id=trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only read own memory records.",
                "decision_trace_id": "authz-gateway-memory-read-scope",
            },
        )

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.memory.record.read",
        resource_type="gateway_memory_record",
        resource_id=memory_id,
        trace_id=trace_id,
    )
    db.commit()
    return serialize_memory_record(row)


@router.delete(
    "/gateway/memory/records/{memory_id}",
    response_model=GatewayMemoryRecordDeleteResponse,
    summary="Delete gateway memory record",
    description=(
        "Soft-deletes a memory record with audit evidence. Production long-term deletes require "
        "Security Approver dual-approval headers when record environment is prod."
    ),
    responses={**_DELETE_FORBIDDEN, **_NOT_FOUND},
)
def gateway_memory_record_delete(
    memory_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, _MEMORY_DELETE_ROLES)
    trace_id = f"trace-gateway-memory-delete-{uuid4()}"

    row = (
        db.query(AgentMemoryRecord)
        .filter_by(memory_id=str(memory_id), status="active")
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Memory record not found")

    if ctx.actor_role == ROLE_AGENT_OWNER and row.actor_id != ctx.actor_id:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.memory.record.delete",
            resource_type="gateway_memory_record",
            resource_id=memory_id,
            trace_id=trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only delete own memory records.",
                "decision_trace_id": "authz-gateway-memory-delete-scope",
            },
        )

    if row.memory_tier == "long_term" and _is_prod_environment(row.environment):
        try:
            require_dual_approval(ctx)
        except HTTPException as exc:
            create_audit_event(
                db,
                actor_id=ctx.actor_id,
                action_type="gateway.memory.record.delete",
                resource_type="gateway_memory_record",
                resource_id=memory_id,
                trace_id=trace_id,
                decision_outcome="deny" if exc.status_code == 403 else "warn",
            )
            db.commit()
            raise

    row.status = "deleted"
    row.deleted_at = datetime.utcnow()
    row.updated_at = datetime.utcnow()

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.memory.record.delete",
        resource_type="gateway_memory_record",
        resource_id=memory_id,
        trace_id=trace_id,
    )
    db.commit()
    return {
        "memory_id": row.memory_id,
        "object": "memory.deleted",
        "deleted": True,
        "trace_id": trace_id,
    }
