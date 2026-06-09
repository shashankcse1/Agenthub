from datetime import datetime
import json
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import Agent, AgentModuleMapping, ModuleDefinition
from app.policy_constants import ROLE_AGENT_OWNER
from app.router_constants import (
    AGENT_OWNER_BLOCKED_PERMISSIONS,
    MODULE_ADMIN_ROLES,
    MODULE_READ_ROLES,
    MODULE_WRITE_ROLES,
    REVIEW_REQUIRED_MODULE_TYPES,
    SUPPORTED_MODULE_PERMISSIONS,
)
from app.schemas import AgentModuleActionRequest, ModuleDeprecateRequest, ModuleRegisterRequest, ModuleResponse
from app.security import ActorContext, get_actor_context, require_role
from app.services.audit import create_audit_event

router = APIRouter()
logger = get_logger(__name__)


def _parse_permissions(required_permissions: str) -> list[str]:
    try:
        parsed = json.loads(required_permissions or "[]")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="required_permissions must be valid JSON array") from exc
    if not isinstance(parsed, list) or any(not isinstance(item, str) for item in parsed):
        raise HTTPException(status_code=400, detail="required_permissions must be a JSON array of strings")
    unknown = sorted(set(parsed) - SUPPORTED_MODULE_PERMISSIONS)
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown module permissions: {', '.join(unknown)}")
    return parsed


def _validate_module_register_payload(payload: ModuleRegisterRequest) -> None:
    signature = payload.artifact_signature.strip()
    provenance = payload.provenance_ref.strip()
    review_ticket = payload.security_review_ticket.strip()

    if not signature.startswith("sig:"):
        raise HTTPException(status_code=400, detail="artifact_signature must start with 'sig:'")
    if not provenance.startswith("prov://"):
        raise HTTPException(status_code=400, detail="provenance_ref must start with 'prov://'")
    if payload.module_type.lower() in REVIEW_REQUIRED_MODULE_TYPES and not review_ticket:
        raise HTTPException(
            status_code=400,
            detail="security_review_ticket is required for runtime, gateway, and security modules",
        )
    _parse_permissions(payload.required_permissions)


def _is_version_compatible(pinned_version: str, compatibility_range: str) -> bool:
    if compatibility_range == "*":
        return True
    if compatibility_range.startswith("major:"):
        expected_major = compatibility_range.split(":", 1)[1]
        pinned_major = pinned_version.split(".", 1)[0]
        return pinned_major == expected_major
    return pinned_version == compatibility_range


def _enforce_agent_owner_scope(agent_id: str, ctx: ActorContext, db: Session) -> None:
    if ctx.actor_role != ROLE_AGENT_OWNER:
        return
    agent = db.query(Agent).filter_by(agent_id=agent_id).first()
    if agent and agent.owner_id != ctx.actor_id:
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only manage modules for owned agents.",
                "actor_role": ctx.actor_role,
                "required_scope": "agent.owner_id == requester actor_id",
                "policy_version": "v1",
                "decision_trace_id": "authz-modules-agent-scope-check",
                "remediation_hint": "Use Platform Admin for cross-owner module operations.",
            },
        )


@router.post("/modules/register", response_model=ModuleResponse)
def register_module(
    payload: ModuleRegisterRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "modules_register_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "module_name": payload.module_name, "module_type": payload.module_type}),
    )
    require_role(ctx, MODULE_ADMIN_ROLES)
    _validate_module_register_payload(payload)
    module = ModuleDefinition(
        module_id=str(uuid4()),
        module_name=payload.module_name,
        module_type=payload.module_type,
        version=payload.version,
        contract_version=payload.contract_version,
        owner_team=payload.owner_team,
        compatibility_range=payload.compatibility_range,
        required_permissions=payload.required_permissions,
        artifact_signature=payload.artifact_signature,
        provenance_ref=payload.provenance_ref,
        security_review_ticket=payload.security_review_ticket,
        status="active",
    )
    db.add(module)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="modules.register",
        resource_type="module",
        resource_id=module.module_id,
        trace_id=f"trace-{module.module_id}",
    )
    db.commit()
    db.refresh(module)
    logger.info(
        "modules_register_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "module_id": module.module_id}),
    )
    return module


@router.get("/modules", response_model=list[ModuleResponse])
def list_modules(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, MODULE_READ_ROLES)
    return db.query(ModuleDefinition).all()


@router.get("/modules/{module_id}/versions")
def module_versions(
    module_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, MODULE_READ_ROLES)
    module = db.query(ModuleDefinition).filter_by(module_id=module_id).first()
    if not module:
        raise HTTPException(status_code=404, detail="Module not found")
    return {"module_id": module_id, "versions": [module.version]}


@router.post("/agents/{agent_id}/modules/validate")
def validate_agent_module(
    agent_id: str,
    payload: AgentModuleActionRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "modules_validate_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "agent_id": agent_id, "module_id": payload.module_id}),
    )
    require_role(ctx, MODULE_WRITE_ROLES)
    _enforce_agent_owner_scope(agent_id, ctx, db)
    module = db.query(ModuleDefinition).filter_by(module_id=payload.module_id).first()
    if not module:
        logger.error("modules_validate_module_not_found %s", sanitize_fields({"module_id": payload.module_id}))
        raise HTTPException(status_code=404, detail="Module not found")
    if module.status == "deprecated":
        raise HTTPException(status_code=409, detail="Module is deprecated and cannot be newly validated")
    if payload.pinned_version != module.version:
        raise HTTPException(status_code=400, detail="Pinned version must match active module version")
    if not _is_version_compatible(payload.pinned_version, module.compatibility_range):
        raise HTTPException(status_code=400, detail="Pinned version violates module compatibility_range")
    module_permissions = set(_parse_permissions(module.required_permissions))
    blocked_permissions = sorted(module_permissions & AGENT_OWNER_BLOCKED_PERMISSIONS)
    if ctx.actor_role == ROLE_AGENT_OWNER and blocked_permissions:
        raise HTTPException(
            status_code=403,
            detail=f"Agent Owner cannot activate module requiring privileged permissions: {', '.join(blocked_permissions)}",
        )

    mapping = AgentModuleMapping(
        mapping_id=str(uuid4()),
        agent_id=agent_id,
        module_id=payload.module_id,
        pinned_version=payload.pinned_version,
        config_hash=payload.config_hash,
        validated_at=datetime.utcnow(),
        validation_status="valid",
    )
    db.add(mapping)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="modules.validate",
        resource_type="agent_module",
        resource_id=mapping.mapping_id,
        trace_id=f"trace-{mapping.mapping_id}",
    )
    db.commit()
    logger.info(
        "modules_validate_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "agent_id": agent_id, "module_id": payload.module_id}),
    )
    return {"agent_id": agent_id, "module_id": payload.module_id, "validation_status": "valid"}


@router.post("/agents/{agent_id}/modules/upgrade-plan")
def upgrade_plan(
    agent_id: str,
    payload: AgentModuleActionRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, MODULE_WRITE_ROLES)
    _enforce_agent_owner_scope(agent_id, ctx, db)
    module = db.query(ModuleDefinition).filter_by(module_id=payload.module_id).first()
    if not module:
        raise HTTPException(status_code=404, detail="Module not found")
    if not _is_version_compatible(payload.pinned_version, module.compatibility_range):
        raise HTTPException(status_code=400, detail="Current pinned version not compatible with module policy")
    if module.status == "deprecated":
        return {
            "agent_id": agent_id,
            "module_id": payload.module_id,
            "from_version": payload.pinned_version,
            "to_version": module.version,
            "plan_status": "migration_required",
            "replacement_module_id": module.replacement_module_id,
            "migration_guidance": module.migration_guidance,
            "deprecation_timeline": module.deprecation_timeline,
        }
    return {
        "agent_id": agent_id,
        "module_id": payload.module_id,
        "from_version": payload.pinned_version,
        "to_version": module.version,
        "plan_status": "ready",
    }


@router.post("/modules/{module_id}/deprecate", response_model=ModuleResponse)
def deprecate_module(
    module_id: str,
    payload: ModuleDeprecateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "modules_deprecate_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "module_id": module_id}),
    )
    require_role(ctx, MODULE_ADMIN_ROLES)
    module = db.query(ModuleDefinition).filter_by(module_id=module_id).first()
    if not module:
        logger.error("modules_deprecate_not_found %s", sanitize_fields({"module_id": module_id}))
        raise HTTPException(status_code=404, detail="Module not found")
    if module.status == "deprecated":
        raise HTTPException(status_code=409, detail="Module is already deprecated")
    replacement_id = payload.replacement_module_id
    if replacement_id:
        if replacement_id == module_id:
            raise HTTPException(status_code=400, detail="replacement_module_id must differ from module_id")
        replacement = db.query(ModuleDefinition).filter_by(module_id=replacement_id).first()
        if not replacement:
            raise HTTPException(status_code=404, detail="Replacement module not found")

    module.status = "deprecated"
    module.replacement_module_id = replacement_id
    module.migration_guidance = payload.migration_guidance
    module.deprecation_timeline = payload.deprecation_timeline
    module.deprecated_at = datetime.utcnow()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="modules.deprecate",
        resource_type="module",
        resource_id=module.module_id,
        trace_id=f"trace-{module.module_id}-deprecate",
    )
    db.commit()
    db.refresh(module)
    logger.info(
        "modules_deprecate_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "module_id": module.module_id}),
    )
    return module
