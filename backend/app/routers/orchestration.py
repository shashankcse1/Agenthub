import json
from datetime import datetime
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.api_errors import not_found_error, validation_error
from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import OrchestrationFlowDefinition, OrchestrationFlowRun
from app.policy_constants import ROLE_PLATFORM_ADMIN, ROLE_SECURITY_APPROVER
from app.router_constants import (
    ROLES_ORCHESTRATION_APPROVE,
    ROLES_ORCHESTRATION_READ,
    ROLES_ORCHESTRATION_RUN,
    ROLES_ORCHESTRATION_WRITE,
)
from app.schemas import (
    OrchestrationFlowApproveRequest,
    OrchestrationFlowCreateRequest,
    OrchestrationFlowListResponse,
    OrchestrationFlowResponse,
    OrchestrationFlowRunListResponse,
    OrchestrationFlowRunRequest,
    OrchestrationFlowRunResponse,
    OrchestrationFlowUpdateRequest,
    OrchestrationFlowValidateResponse,
    OrchestrationNodeTypesResponse,
)
from app.security import ActorContext, get_actor_context, require_dual_approval, require_role
from app.services.audit import create_audit_event, push_audit_action_context
from app.services.orchestration_flows import (
    APPROVAL_STATUSES,
    FLOW_ENVIRONMENTS,
    FLOW_STATUSES,
    execute_flow_stub,
    flow_has_human_approval_nodes,
    list_node_types,
    prod_run_requires_approval,
    security_policy_snapshot,
    serialize_flow,
    serialize_run,
    validate_flow_definition,
)

router = APIRouter()
logger = get_logger(__name__)


def _require_flow(db: Session, flow_id: str) -> OrchestrationFlowDefinition:
    row = db.query(OrchestrationFlowDefinition).filter_by(flow_id=flow_id).first()
    if row is None:
        raise not_found_error("orchestration_flow", flow_id, decision_trace_id="orchestration-flow-not-found")
    return row


def _audit_flow(
    db: Session,
    *,
    ctx: ActorContext,
    action_type: str,
    flow: OrchestrationFlowDefinition,
    decision_outcome: str = "allow",
    action_context: Optional[dict] = None,
) -> None:
    context = {
        "flow_name": flow.flow_name,
        "trigger_type": flow.trigger_type,
        "environment": flow.environment,
        "approval_status": flow.approval_status,
    }
    if action_context:
        context.update(action_context)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type=action_type,
        resource_type="orchestration_flow",
        resource_id=flow.flow_id,
        decision_outcome=decision_outcome,
        trace_id=f"trace-{flow.flow_id}",
        tenant_id=flow.tenant_id,
        environment=flow.environment,
        action_context=context,
    )


@router.get("/orchestration/node-types", response_model=OrchestrationNodeTypesResponse)
def get_orchestration_node_types(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    return {"node_types": list_node_types(), "policy": security_policy_snapshot(db)}


@router.get("/orchestration/flows", response_model=OrchestrationFlowListResponse)
def list_orchestration_flows(
    environment: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    query = db.query(OrchestrationFlowDefinition)
    if environment:
        query = query.filter_by(environment=str(environment).strip().lower())
    if status:
        query = query.filter_by(status=str(status).strip().lower())
    total = query.count()
    rows = query.order_by(OrchestrationFlowDefinition.updated_at.desc()).offset(offset).limit(limit).all()
    return {"total": total, "data": [serialize_flow(row) for row in rows]}


@router.post("/orchestration/flows", response_model=OrchestrationFlowResponse)
def create_orchestration_flow(
    payload: OrchestrationFlowCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_WRITE)
    env = str(payload.environment or "dev").strip().lower()
    if env not in FLOW_ENVIRONMENTS:
        raise validation_error(
            message=f"environment must be one of: {', '.join(sorted(FLOW_ENVIRONMENTS))}",
            decision_trace_id="orchestration-create-env",
        )
    status = str(payload.status or "draft").strip().lower()
    if status not in FLOW_STATUSES:
        raise validation_error(
            message=f"status must be one of: {', '.join(sorted(FLOW_STATUSES))}",
            decision_trace_id="orchestration-create-status",
        )

    validation = validate_flow_definition(
        db,
        trigger_type=payload.trigger_type,
        trigger_config_json=payload.trigger_config_json,
        graph_json=payload.graph_json,
        environment=env,
    )
    if not validation["valid"]:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="orchestration.flow.create",
            resource_type="orchestration_flow",
            resource_id="pending",
            decision_outcome="deny",
            trace_id="trace-orchestration-create-deny",
            environment=env,
            action_context={"flow_name": payload.flow_name, "errors": validation["errors"][:5]},
        )
        raise validation_error(
            message="Flow validation failed",
            decision_trace_id="orchestration-create-validation",
            errors=validation["errors"],
        )

    flow_id = str(uuid4())
    row = OrchestrationFlowDefinition(
        flow_id=flow_id,
        flow_name=payload.flow_name.strip(),
        description=(payload.description or "").strip(),
        status=status,
        environment=env,
        tenant_id=(payload.tenant_id or None),
        trigger_type=str(payload.trigger_type or "manual").strip().lower(),
        trigger_config_json=payload.trigger_config_json or "{}",
        graph_json=payload.graph_json or '{"nodes":[],"edges":[]}',
        approval_status="pending",
        metadata_version=1,
        created_by=ctx.actor_id,
        updated_by=ctx.actor_id,
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    _audit_flow(db, ctx=ctx, action_type="orchestration.flow.create", flow=row)
    db.commit()
    logger.info(
        "orchestration_flow_created %s",
        sanitize_fields({"flow_id": flow_id, "actor_id": ctx.actor_id, "environment": env}),
    )
    return serialize_flow(row)


@router.get("/orchestration/flows/{flow_id}", response_model=OrchestrationFlowResponse)
def get_orchestration_flow(
    flow_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    return serialize_flow(_require_flow(db, flow_id))


@router.put("/orchestration/flows/{flow_id}", response_model=OrchestrationFlowResponse)
def update_orchestration_flow(
    flow_id: str,
    payload: OrchestrationFlowUpdateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_WRITE)
    row = _require_flow(db, flow_id)

    if payload.flow_name is not None:
        row.flow_name = payload.flow_name.strip()
    if payload.description is not None:
        row.description = payload.description.strip()
    if payload.status is not None:
        status = payload.status.strip().lower()
        if status not in FLOW_STATUSES:
            raise validation_error(message=f"status must be one of: {', '.join(sorted(FLOW_STATUSES))}")
        row.status = status
    if payload.environment is not None:
        env = payload.environment.strip().lower()
        if env not in FLOW_ENVIRONMENTS:
            raise validation_error(message=f"environment must be one of: {', '.join(sorted(FLOW_ENVIRONMENTS))}")
        row.environment = env
    if payload.tenant_id is not None:
        row.tenant_id = payload.tenant_id or None
    if payload.trigger_type is not None:
        row.trigger_type = payload.trigger_type.strip().lower()
    if payload.trigger_config_json is not None:
        row.trigger_config_json = payload.trigger_config_json
    if payload.graph_json is not None:
        row.graph_json = payload.graph_json

    validation = validate_flow_definition(
        db,
        trigger_type=row.trigger_type,
        trigger_config_json=row.trigger_config_json,
        graph_json=row.graph_json,
        environment=row.environment,
    )
    if not validation["valid"]:
        _audit_flow(
            db,
            ctx=ctx,
            action_type="orchestration.flow.update",
            flow=row,
            decision_outcome="deny",
            action_context={"errors": validation["errors"][:5]},
        )
        db.commit()
        raise validation_error(
            message="Flow validation failed",
            decision_trace_id="orchestration-update-validation",
            errors=validation["errors"],
        )

    row.metadata_version = int(row.metadata_version or 1) + 1
    if row.environment == "prod" or payload.graph_json is not None or payload.trigger_type is not None:
        row.approval_status = "pending"
    row.updated_by = ctx.actor_id
    row.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(row)
    _audit_flow(db, ctx=ctx, action_type="orchestration.flow.update", flow=row)
    db.commit()
    return serialize_flow(row)


@router.delete("/orchestration/flows/{flow_id}", response_model=OrchestrationFlowResponse)
def delete_orchestration_flow(
    flow_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_WRITE)
    row = _require_flow(db, flow_id)
    row.status = "deprecated"
    row.updated_by = ctx.actor_id
    row.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(row)
    _audit_flow(db, ctx=ctx, action_type="orchestration.flow.delete", flow=row)
    db.commit()
    return serialize_flow(row)


@router.post("/orchestration/flows/{flow_id}/validate", response_model=OrchestrationFlowValidateResponse)
def validate_orchestration_flow(
    flow_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    row = _require_flow(db, flow_id)
    result = validate_flow_definition(
        db,
        trigger_type=row.trigger_type,
        trigger_config_json=row.trigger_config_json,
        graph_json=row.graph_json,
        environment=row.environment,
    )
    result["flow_id"] = flow_id
    result["policy"] = security_policy_snapshot(db)
    _audit_flow(
        db,
        ctx=ctx,
        action_type="orchestration.flow.validate",
        flow=row,
        decision_outcome="allow" if result["valid"] else "deny",
        action_context={"valid": result["valid"], "error_count": len(result["errors"])},
    )
    db.commit()
    return result


@router.post("/orchestration/flows/{flow_id}/approve", response_model=OrchestrationFlowResponse)
def approve_orchestration_flow(
    flow_id: str,
    payload: OrchestrationFlowApproveRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_APPROVE)
    row = _require_flow(db, flow_id)
    if row.environment == "prod":
        require_dual_approval(ctx, required_approver_role=ROLE_PLATFORM_ADMIN)

    validation = validate_flow_definition(
        db,
        trigger_type=row.trigger_type,
        trigger_config_json=row.trigger_config_json,
        graph_json=row.graph_json,
        environment=row.environment,
    )
    if not validation["valid"]:
        _audit_flow(
            db,
            ctx=ctx,
            action_type="orchestration.flow.approve",
            flow=row,
            decision_outcome="deny",
            action_context={"errors": validation["errors"][:5]},
        )
        db.commit()
        raise validation_error(
            message="Cannot approve invalid flow",
            decision_trace_id="orchestration-approve-validation",
            errors=validation["errors"],
        )

    decision = str(payload.decision or "approved").strip().lower()
    if decision not in {"approved", "rejected"}:
        raise validation_error(message="decision must be approved or rejected")
    row.approval_status = decision if decision in APPROVAL_STATUSES else "approved"
    if payload.approval_ticket_ref:
        push_audit_action_context(approval_ticket_ref=payload.approval_ticket_ref)
    row.status = "active" if row.approval_status == "approved" else row.status
    row.metadata_version = int(row.metadata_version or 1) + 1
    row.updated_by = ctx.actor_id
    row.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(row)
    _audit_flow(
        db,
        ctx=ctx,
        action_type="orchestration.flow.approve",
        flow=row,
        action_context={"decision": row.approval_status, "ticket_ref": payload.approval_ticket_ref},
    )
    db.commit()
    return serialize_flow(row)


@router.post("/orchestration/flows/{flow_id}/run", response_model=OrchestrationFlowRunResponse)
def run_orchestration_flow(
    flow_id: str,
    payload: OrchestrationFlowRunRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_RUN)
    row = _require_flow(db, flow_id)
    if row.status in {"disabled", "deprecated"}:
        _audit_flow(
            db,
            ctx=ctx,
            action_type="orchestration.flow.run",
            flow=row,
            decision_outcome="deny",
            action_context={"reason": "flow_disabled"},
        )
        db.commit()
        raise validation_error(
            message="Flow is disabled or deprecated",
            decision_trace_id="orchestration-run-disabled",
            status_code=409,
        )

    validation = validate_flow_definition(
        db,
        trigger_type=row.trigger_type,
        trigger_config_json=row.trigger_config_json,
        graph_json=row.graph_json,
        environment=row.environment,
    )
    if not validation["valid"]:
        _audit_flow(
            db,
            ctx=ctx,
            action_type="orchestration.flow.run",
            flow=row,
            decision_outcome="deny",
            action_context={"errors": validation["errors"][:5]},
        )
        db.commit()
        raise validation_error(
            message="Flow validation failed",
            decision_trace_id="orchestration-run-validation",
            errors=validation["errors"],
        )

    if row.environment == "prod" and prod_run_requires_approval(db) and row.approval_status != "approved":
        _audit_flow(
            db,
            ctx=ctx,
            action_type="orchestration.flow.run",
            flow=row,
            decision_outcome="deny",
            action_context={"reason": "prod_not_approved"},
        )
        db.commit()
        raise validation_error(
            message="Production flow runs require approval_status=approved",
            decision_trace_id="orchestration-run-prod-approval",
            status_code=403,
        )

    dry_run = bool(payload.dry_run)
    if row.environment == "prod" and flow_has_human_approval_nodes(row.graph_json) and not dry_run:
        require_dual_approval(ctx, required_approver_role=ROLE_SECURITY_APPROVER)

    trace_id = f"orch-run-{uuid4().hex[:16]}"
    run_status, step_results, error_summary = execute_flow_stub(
        flow_id=row.flow_id,
        graph_json=row.graph_json,
        dry_run=dry_run,
        trace_id=trace_id,
    )
    run_id = str(uuid4())
    finished_at = datetime.utcnow()
    run_row = OrchestrationFlowRun(
        run_id=run_id,
        flow_id=row.flow_id,
        status=run_status,
        started_at=finished_at,
        finished_at=finished_at,
        trace_id=trace_id,
        step_results_json=json.dumps(step_results),
        error_summary=error_summary,
    )
    db.add(run_row)
    db.commit()
    _audit_flow(
        db,
        ctx=ctx,
        action_type="orchestration.flow.run",
        flow=row,
        action_context={"run_id": run_id, "dry_run": dry_run, "trace_id": trace_id},
    )
    db.commit()
    db.refresh(run_row)
    return serialize_run(run_row)


@router.get("/orchestration/flows/{flow_id}/runs", response_model=OrchestrationFlowRunListResponse)
def list_orchestration_flow_runs(
    flow_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    _require_flow(db, flow_id)
    query = db.query(OrchestrationFlowRun).filter_by(flow_id=flow_id)
    total = query.count()
    rows = query.order_by(OrchestrationFlowRun.started_at.desc()).offset(offset).limit(limit).all()
    return {"total": total, "data": [serialize_run(row) for row in rows]}


@router.get("/orchestration/flows/{flow_id}/runs/{run_id}", response_model=OrchestrationFlowRunResponse)
def get_orchestration_flow_run(
    flow_id: str,
    run_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    _require_flow(db, flow_id)
    row = db.query(OrchestrationFlowRun).filter_by(flow_id=flow_id, run_id=run_id).first()
    if row is None:
        raise not_found_error("orchestration_flow_run", run_id, decision_trace_id="orchestration-run-not-found")
    return serialize_run(row)
