from datetime import datetime
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api_errors import not_found_error, validation_error
from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import AgentConfig
from app.router_constants import AGENT_CONFIG_READ_ROLES, AGENT_CONFIG_WRITE_ROLES
from app.schemas import AgentConfigCredentialStatusResponse, AgentConfigResponse, AgentConfigUpsertRequest
from app.security import ActorContext, get_actor_context, require_role
from app.services.audit import create_audit_event
from app.services.credential_resolution import load_active_binding_by_id, serialize_agent_credential_status

router = APIRouter()
logger = get_logger(__name__)


def _normalize_provider_priority(raw: Optional[str]) -> str:
    value = str(raw or "").strip().lower()
    if not value:
        return ""
    parts = [item.strip() for item in value.split(",") if item.strip()]
    return ",".join(parts)


@router.get("/agent-configs", response_model=list[AgentConfigResponse])
def list_agent_configs(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace("agent_config_list_start %s", sanitize_fields({"actor_id": ctx.actor_id}))
    require_role(ctx, AGENT_CONFIG_READ_ROLES)
    rows = db.query(AgentConfig).order_by(AgentConfig.updated_at.desc()).all()
    logger.info("agent_config_list_completed %s", sanitize_fields({"actor_id": ctx.actor_id, "count": len(rows)}))
    return rows


@router.put("/agent-configs/{agent_key}", response_model=AgentConfigResponse)
def upsert_agent_config(
    agent_key: str,
    payload: AgentConfigUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "agent_config_upsert_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "agent_key": agent_key}),
    )
    require_role(ctx, AGENT_CONFIG_WRITE_ROLES)
    normalized_key = agent_key.strip()
    if not normalized_key:
        raise validation_error("agent_key cannot be empty", decision_trace_id="agent-config-key-empty", status_code=422)

    payload_key = payload.agent_key.strip()
    if payload_key and payload_key != normalized_key:
        raise validation_error(
            "agent_key in path must match payload",
            decision_trace_id="agent-config-key-mismatch",
            status_code=422,
        )

    row = db.query(AgentConfig).filter_by(agent_key=normalized_key).first()
    config_id = payload.config_id.strip() if payload.config_id else (row.config_id if row else uuid4().hex[:32])
    now = datetime.utcnow()

    if not row:
        row = AgentConfig(
            config_id=config_id,
            agent_key=normalized_key,
            created_at=now,
        )
        db.add(row)

    row.display_name = payload.display_name.strip()
    row.provider = payload.provider.strip().lower()
    row.model = payload.model.strip()
    row.provider_priority = _normalize_provider_priority(payload.provider_priority)
    row.temperature = float(payload.temperature)
    row.max_tokens = int(payload.max_tokens)
    row.timeout_ms = int(payload.timeout_ms)
    row.fallback_enabled = bool(payload.fallback_enabled)
    row.max_fallback_hops = int(payload.max_fallback_hops)
    row.global_timeout_ms = int(payload.global_timeout_ms)
    row.retry_budget = int(payload.retry_budget)
    row.failure_threshold_percent = int(payload.failure_threshold_percent)
    row.cooldown_seconds = int(payload.cooldown_seconds)
    row.environment = payload.environment.strip().lower()
    row.enabled = bool(payload.enabled)
    row.notes = (payload.notes or "").strip()
    binding_id = str(payload.credential_binding_id or "").strip() or None
    if binding_id:
        binding = load_active_binding_by_id(db, binding_id)
        if str(binding.provider_type or "").strip().lower() != payload.provider.strip().lower():
            raise validation_error(
                "Credential binding provider_type must match agent provider",
                decision_trace_id="agent-config-binding-provider-mismatch",
                status_code=422,
            )
        if str(binding.status or "").strip().lower() != "active":
            raise validation_error(
                "Credential binding is not active",
                decision_trace_id="agent-config-binding-inactive",
            )
    row.credential_binding_id = binding_id
    row.updated_by = ctx.actor_id
    row.updated_at = now

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="agent_config.upsert",
        resource_type="agent_config",
        resource_id=normalized_key,
        trace_id=f"trace-agent-config-{normalized_key}",
    )
    db.commit()
    db.refresh(row)
    logger.info(
        "agent_config_upsert_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "agent_key": normalized_key}),
    )
    return row


@router.get("/agent-configs/{agent_key}/credential-status", response_model=AgentConfigCredentialStatusResponse)
def get_agent_config_credential_status(
    agent_key: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "agent_config_credential_status_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "agent_key": agent_key}),
    )
    require_role(ctx, AGENT_CONFIG_READ_ROLES)
    normalized_key = agent_key.strip()
    row = db.query(AgentConfig).filter_by(agent_key=normalized_key).first()
    if not row:
        raise not_found_error("agent_config", normalized_key, decision_trace_id="agent-config-not-found")
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="agent_config.credential_status.read",
        resource_type="agent_config",
        resource_id=normalized_key,
        trace_id=f"trace-agent-config-credential-{normalized_key}",
    )
    db.commit()
    logger.info(
        "agent_config_credential_status_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "agent_key": normalized_key}),
    )
    return serialize_agent_credential_status(db, row)


@router.delete("/agent-configs/{agent_key}")
def delete_agent_config(
    agent_key: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "agent_config_delete_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "agent_key": agent_key}),
    )
    require_role(ctx, AGENT_CONFIG_WRITE_ROLES)
    normalized_key = agent_key.strip()
    row = db.query(AgentConfig).filter_by(agent_key=normalized_key).first()
    if not row:
        raise not_found_error("agent_config", normalized_key, decision_trace_id="agent-config-delete-not-found")

    db.delete(row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="agent_config.delete",
        resource_type="agent_config",
        resource_id=normalized_key,
        trace_id=f"trace-agent-config-{normalized_key}",
    )
    db.commit()
    logger.info(
        "agent_config_delete_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "agent_key": normalized_key}),
    )
    return {"deleted": True, "agent_key": normalized_key}
