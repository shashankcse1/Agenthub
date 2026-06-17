from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import Agent, OwnershipEvent, SecretProviderConfig, WorkloadIdentityFederationProfile
from app.policy_constants import ROLE_AGENT_OWNER
from app.router_constants import OWNER_READ_ROLES, OWNER_WRITE_ROLES
from app.schemas import (
    AgentRegisterOptionsResponse,
    AgentRegisterRequest,
    AgentResponse,
    OwnershipEventResponse,
    OwnershipTransferRequest,
)
from app.security import ActorContext, get_actor_context, require_role
from app.services.audit import create_audit_event

router = APIRouter()
logger = get_logger(__name__)


def _normalize_agent_type(value: str) -> str:
    normalized = str(value or "").strip().lower()
    allowed = {"aws", "azure", "gcp", "onprem", "hybrid", "other"}
    if normalized in allowed:
        return normalized
    return "other"


def _provider_type_to_agent_type(provider_type: str) -> str:
    normalized = str(provider_type or "").strip().lower()
    if normalized in {"aws", "bedrock", "aws-secrets-manager"}:
        return "aws"
    if normalized in {"azure", "azure-openai", "azure-key-vault"}:
        return "azure"
    if normalized in {"google", "gcp", "vertex", "gcp-secret-manager"}:
        return "gcp"
    if normalized in {"onprem", "self-hosted", "vmware", "kubernetes"}:
        return "onprem"
    return "other"


def _allowed_agent_types_from_enabled_config(db: Session) -> set[str]:
    workload_rows = (
        db.query(WorkloadIdentityFederationProfile.provider_type)
        .filter(WorkloadIdentityFederationProfile.status == "active")
        .all()
    )
    secret_rows = db.query(SecretProviderConfig.provider_type).filter(SecretProviderConfig.status == "active").all()
    mapped = {
        _provider_type_to_agent_type(row[0])
        for row in [*workload_rows, *secret_rows]
        if row and str(row[0] or "").strip()
    }
    core = {item for item in mapped if item in {"aws", "azure", "gcp", "onprem"}}
    allowed = set(core)
    if len(core) >= 2:
        allowed.add("hybrid")
    if "other" in mapped or not allowed:
        allowed.add("other")
    return allowed


def _create_agent_record(
    payload: AgentRegisterRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "agents_register_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "owner_id": payload.owner_id}),
    )
    require_role(ctx, OWNER_WRITE_ROLES)
    if ctx.actor_role == ROLE_AGENT_OWNER and payload.owner_id != ctx.actor_id:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="agents.register",
            resource_type="agent",
            resource_id="scope-deny",
            trace_id=f"trace-agent-register-deny-{ctx.actor_id}",
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only register agents for their own owner_id.",
                "actor_role": ctx.actor_role,
                "required_scope": "payload.owner_id == requester actor_id",
                "policy_version": "v1",
                "decision_trace_id": "authz-agent-register-scope-check",
                "remediation_hint": "Use Platform Admin for cross-owner agent registration.",
            },
        )

    agent = Agent(
        agent_id=str(uuid4()),
        name=payload.name,
        owner_id=payload.owner_id,
        owner_name=payload.owner_name,
        owner_team=payload.owner_team,
        agent_type=_normalize_agent_type(payload.agent_type),
        description=str(payload.description or "").strip(),
        risk_tier=payload.risk_tier,
        status="active",
    )

    allowed_types = _allowed_agent_types_from_enabled_config(db)
    if agent.agent_type not in allowed_types:
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "AGENT_TYPE_NOT_ENABLED",
                "message": "agent_type is not enabled by active provider configuration.",
                "allowed_agent_types": sorted(allowed_types),
            },
        )

    db.add(agent)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="agents.register",
        resource_type="agent",
        resource_id=agent.agent_id,
        trace_id=f"trace-{agent.agent_id}",
    )
    db.commit()
    db.refresh(agent)
    logger.info(
        "agents_register_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "agent_id": agent.agent_id}),
    )
    return agent


@router.get("/agents/register-options", response_model=AgentRegisterOptionsResponse)
def get_agent_register_options(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, OWNER_READ_ROLES)
    allowed_types = sorted(_allowed_agent_types_from_enabled_config(db))
    return {
        "allowed_agent_types": allowed_types,
        "default_environment": "dev",
    }


@router.post("/agents", response_model=AgentResponse)
def create_agent(
    payload: AgentRegisterRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    return _create_agent_record(payload=payload, db=db, ctx=ctx)


@router.post("/agents/register", response_model=AgentResponse)
def register_agent(
    payload: AgentRegisterRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    return _create_agent_record(payload=payload, db=db, ctx=ctx)


@router.patch("/agents/{agent_id}/owner", response_model=AgentResponse)
def transfer_owner(
    agent_id: str,
    payload: OwnershipTransferRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "agents_transfer_owner_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "agent_id": agent_id}),
    )
    require_role(ctx, OWNER_WRITE_ROLES)

    agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
    if not agent:
        logger.error("agents_transfer_owner_not_found %s", sanitize_fields({"agent_id": agent_id}))
        raise HTTPException(status_code=404, detail="Agent not found")
    if ctx.actor_role == ROLE_AGENT_OWNER and agent.owner_id != ctx.actor_id:
        logger.error(
            "agents_transfer_owner_scope_denied %s",
            sanitize_fields({"actor_id": ctx.actor_id, "agent_id": agent_id}),
        )
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="agents.transfer_owner",
            resource_type="agent",
            resource_id=agent_id,
            trace_id=f"trace-owner-transfer-deny-{agent_id}",
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only transfer agents they own.",
                "actor_role": ctx.actor_role,
                "required_scope": "agent.owner_id == requester actor_id",
                "policy_version": "v1",
                "decision_trace_id": "authz-agent-owner-transfer-scope-check",
                "remediation_hint": "Use Platform Admin for cross-owner transfers.",
            },
        )

    event = OwnershipEvent(
        event_id=str(uuid4()),
        agent_id=agent.agent_id,
        old_owner_id=agent.owner_id,
        new_owner_id=payload.new_owner_id,
        changed_by=ctx.actor_id,
        reason=payload.reason,
        ticket_ref=payload.ticket_ref,
    )
    db.add(event)

    agent.owner_id = payload.new_owner_id
    agent.owner_name = payload.new_owner_name
    agent.owner_team = payload.new_owner_team

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="agents.transfer_owner",
        resource_type="agent",
        resource_id=agent.agent_id,
        trace_id=f"trace-{event.event_id}",
    )

    db.commit()
    db.refresh(agent)
    logger.info(
        "agents_transfer_owner_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "agent_id": agent.agent_id}),
    )
    return agent


@router.get("/agents/{agent_id}/ownership-history", response_model=list[OwnershipEventResponse])
def ownership_history(
    agent_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, OWNER_READ_ROLES)
    if ctx.actor_role == ROLE_AGENT_OWNER:
        agent = db.query(Agent).filter(Agent.agent_id == agent_id).first()
        if not agent or agent.owner_id != ctx.actor_id:
            raise HTTPException(
                status_code=403,
                detail={
                    "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                    "message": "Agent Owner can only access ownership history for own agents.",
                    "actor_role": ctx.actor_role,
                    "required_scope": "agent.owner_id == requester actor_id",
                    "policy_version": "v1",
                    "decision_trace_id": "authz-ownership-history-scope-check",
                    "remediation_hint": "Use a privileged role or access your own agent history.",
                },
            )
    events = (
        db.query(OwnershipEvent)
        .filter(OwnershipEvent.agent_id == agent_id)
        .order_by(OwnershipEvent.changed_at.desc())
        .all()
    )
    return events


@router.get("/owners/{owner_id}/agents", response_model=list[AgentResponse])
def owners_agents(
    owner_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, OWNER_READ_ROLES)
    if ctx.actor_role == ROLE_AGENT_OWNER and owner_id != ctx.actor_id:
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only access their own agents.",
                "actor_role": ctx.actor_role,
                "required_scope": "owner_id == requester actor_id",
                "policy_version": "v1",
                "decision_trace_id": "authz-owner-agents-scope-check",
                "remediation_hint": "Use a privileged role for cross-owner queries.",
            },
        )
    agents = db.query(Agent).filter(Agent.owner_id == owner_id).all()
    return agents
