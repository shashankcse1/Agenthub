from datetime import datetime
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import AgentConfig
from app.policy_constants import ROLE_AUDITOR, ROLE_PLATFORM_ADMIN, ROLE_SECURITY_APPROVER, ROLE_SUPER_ADMIN
from app.schemas import AgentConfigResponse, AgentConfigUpsertRequest
from app.security import ActorContext, get_actor_context, require_role
from app.services.audit import create_audit_event

router = APIRouter()

AGENT_CONFIG_READ_ROLES = {ROLE_PLATFORM_ADMIN, ROLE_SUPER_ADMIN, ROLE_SECURITY_APPROVER, ROLE_AUDITOR}
AGENT_CONFIG_WRITE_ROLES = {ROLE_PLATFORM_ADMIN, ROLE_SUPER_ADMIN, ROLE_SECURITY_APPROVER}


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
    require_role(ctx, AGENT_CONFIG_READ_ROLES)
    return db.query(AgentConfig).order_by(AgentConfig.updated_at.desc()).all()


@router.put("/agent-configs/{agent_key}", response_model=AgentConfigResponse)
def upsert_agent_config(
    agent_key: str,
    payload: AgentConfigUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AGENT_CONFIG_WRITE_ROLES)
    normalized_key = agent_key.strip()
    if not normalized_key:
        raise HTTPException(status_code=422, detail="agent_key cannot be empty")

    payload_key = payload.agent_key.strip()
    if payload_key and payload_key != normalized_key:
        raise HTTPException(status_code=422, detail="agent_key in path must match payload")

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
    return row


@router.delete("/agent-configs/{agent_key}")
def delete_agent_config(
    agent_key: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AGENT_CONFIG_WRITE_ROLES)
    normalized_key = agent_key.strip()
    row = db.query(AgentConfig).filter_by(agent_key=normalized_key).first()
    if not row:
        raise HTTPException(status_code=404, detail="Agent config not found")

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
    return {"deleted": True, "agent_key": normalized_key}
