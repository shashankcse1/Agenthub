import json
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.orm import Session

from app.api_errors import not_found_error, validation_error
from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import (
    OrchestrationFlowDefinition,
    OrchestrationFlowRun,
    OrchestrationJitAccessRequest,
    OrchestrationFlowAccessCertification,
    OrchestrationRunApprovalGate,
)
from app.policy_constants import ROLE_PLATFORM_ADMIN, ROLE_SECURITY_APPROVER, ROLE_SUPER_ADMIN
from app.router_constants import (
    ROLES_ORCHESTRATION_APPROVE,
    ROLES_ORCHESTRATION_READ,
    ROLES_ORCHESTRATION_RUN,
    ROLES_ORCHESTRATION_WRITE,
)
from app.schemas import (
    OrchestrationAccessCertificationDueResponse,
    OrchestrationAccessCertificationResponse,
    OrchestrationAccessCertifyRequest,
    OrchestrationAccessPolicyResolveRequest,
    OrchestrationAccessPolicyResolveResponse,
    OrchestrationConsoleSummaryResponse,
    OrchestrationDataConnectionListResponse,
    OrchestrationDataConnectionResponse,
    OrchestrationDataConnectionTestQueryRequest,
    OrchestrationDataConnectionTestQueryResponse,
    OrchestrationFlowApprovalEventResponse,
    OrchestrationFlowApproveRequest,
    OrchestrationFlowCreateRequest,
    OrchestrationFlowListResponse,
    OrchestrationFlowResponse,
    OrchestrationFlowRunListResponse,
    OrchestrationFlowRunRequest,
    OrchestrationFlowRunResponse,
    OrchestrationRunApprovalGateDecideRequest,
    OrchestrationRunApprovalGateListResponse,
    OrchestrationRunApprovalGateResponse,
    OrchestrationFlowUpdateRequest,
    OrchestrationFlowValidateResponse,
    OrchestrationIgaExplainRequest,
    OrchestrationSchedulerTickResponse,
    OrchestrationWebhookTriggerRequest,
    OrchestrationIgaExplainResponse,
    OrchestrationIgaPostureResponse,
    OrchestrationJitAccessApproveRequest,
    OrchestrationJitAccessRequestCreateRequest,
    OrchestrationJitAccessRequestListResponse,
    OrchestrationJitAccessRequestResponse,
    OrchestrationNodeTypesResponse,
)
from app.security import ActorContext, get_actor_context, require_dual_approval, require_role
from app.services.audit import create_audit_event, push_audit_action_context
from app.services.orchestration_access import (
    FLOW_ACCESS_ACTION_APPROVE,
    FLOW_ACCESS_ACTION_MANAGE,
    FLOW_ACCESS_ACTION_READ,
    FLOW_ACCESS_ACTION_RUN,
    FLOW_ACCESS_ACTION_SCHEDULE,
    actor_can_read_flow,
    actor_matches_approver_policy,
    enforce_flow_access,
    merge_access_policy_on_create,
    parse_access_policy,
    platform_bypasses_flow_scope,
    resolve_actor_directory_scope,
    validate_access_policy,
)
from app.services.orchestration_data_connections import (
    get_data_connection,
    list_data_connections,
    execute_read_query,
)
from app.services.orchestration_triggers import poll_due_scheduled_flows, trigger_webhook_flow
from app.services.orchestration_scope_resolver import (
    build_template_context,
    preview_resolved_policy,
    validate_read_only_sql,
)
from app.services.orchestration_executor import execute_flow, live_executor_policy_snapshot
from app.services.orchestration_flows import (
    APPROVAL_STATUSES,
    FLOW_ENVIRONMENTS,
    FLOW_STATUSES,
    flow_has_human_approval_nodes,
    list_node_types,
    prod_run_requires_approval,
    security_policy_snapshot,
    serialize_flow,
    serialize_run,
    validate_flow_definition,
)
from app.services.orchestration_iga import (
    apply_stage_approval_decision,
    build_iga_posture,
    check_certification_current,
    compute_next_due_at,
    enforce_orchestration_entitlement,
    enforce_sod_on_approve,
    evaluate_staged_approval_outcome,
    explain_orchestration_access,
    flows_due_for_recertification,
    get_active_jit_grant,
    get_approval_stages,
    is_staged_approvers,
    parse_approval_stage_state,
    prod_run_requires_access_certification,
    record_approval_event,
    serialize_approval_stage_state,
    supersede_prior_certifications,
    validate_iga_policy,
)

router = APIRouter()
logger = get_logger(__name__)


def _require_run(db: Session, flow_id: str, run_id: str) -> OrchestrationFlowRun:
    row = db.query(OrchestrationFlowRun).filter_by(flow_id=flow_id, run_id=run_id).first()
    if row is None:
        raise not_found_error("orchestration_flow_run", run_id, decision_trace_id="orchestration-run-not-found")
    return row


def _serialize_approval_gate(row: OrchestrationRunApprovalGate) -> dict:
    return {
        "gate_id": row.gate_id,
        "run_id": row.run_id,
        "flow_id": row.flow_id,
        "node_id": row.node_id,
        "status": row.status,
        "approval_title": row.approval_title,
        "required_role": row.required_role,
        "resolved_approver_id": row.resolved_approver_id,
        "resolved_approver_role": row.resolved_approver_role,
        "decided_by": row.decided_by,
        "decided_at": row.decided_at,
        "metadata_json": row.metadata_json,
        "created_at": row.created_at,
    }


def _enforce_gate_decider(
    db: Session,
    ctx: ActorContext,
    flow: OrchestrationFlowDefinition,
    gate: OrchestrationRunApprovalGate,
) -> None:
    enforce_flow_access(db, ctx, flow, FLOW_ACCESS_ACTION_APPROVE)
    if platform_bypasses_flow_scope(ctx):
        return
    actor_id = str(ctx.actor_id or "").strip()
    actor_role = str(ctx.actor_role or "").strip().lower()
    resolved_id = str(gate.resolved_approver_id or "").strip()
    resolved_role = str(gate.resolved_approver_role or gate.required_role or "").strip().lower()
    if resolved_id and resolved_id == actor_id:
        return
    if resolved_role and resolved_role == actor_role:
        return
    if not resolved_id and not resolved_role:
        require_role(ctx, ROLES_ORCHESTRATION_APPROVE)
        return
    raise validation_error(
        message="Actor is not the resolved approver for this gate",
        decision_trace_id="orchestration-gate-decider-mismatch",
        status_code=403,
    )


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
    event_trace_id: Optional[str] = None,
) -> None:
    context = {
        "flow_name": flow.flow_name,
        "trigger_type": flow.trigger_type,
        "environment": flow.environment,
        "approval_status": flow.approval_status,
    }
    if action_context:
        context.update(action_context)
    resolved_trace_id = event_trace_id or (action_context or {}).get("trace_id") or f"trace-{flow.flow_id}"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type=action_type,
        resource_type="orchestration_flow",
        resource_id=flow.flow_id,
        decision_outcome=decision_outcome,
        trace_id=str(resolved_trace_id),
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
    policy = security_policy_snapshot(db)
    policy.update(live_executor_policy_snapshot(db))
    return {"node_types": list_node_types(), "policy": policy}


@router.get("/orchestration/summary", response_model=OrchestrationConsoleSummaryResponse)
def get_orchestration_summary(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    now = datetime.utcnow()
    flows = db.query(OrchestrationFlowDefinition).all()
    if not platform_bypasses_flow_scope(ctx):
        scope = resolve_actor_directory_scope(db, ctx.actor_id)
        flows = [
            row
            for row in flows
            if actor_can_read_flow(scope, parse_access_policy(getattr(row, "access_policy_json", None)), row)
        ]
    by_env: dict[str, int] = {}
    pending_prod = 0
    for row in flows:
        env = str(row.environment or "dev").strip().lower()
        by_env[env] = by_env.get(env, 0) + 1
        if env == "prod" and str(row.approval_status or "") == "pending":
            pending_prod += 1
    certifications_due = len(flows_due_for_recertification(db, limit=500))
    active_jit = (
        db.query(OrchestrationJitAccessRequest)
        .filter(OrchestrationJitAccessRequest.status == "approved")
        .filter(OrchestrationJitAccessRequest.expires_at.isnot(None))
        .filter(OrchestrationJitAccessRequest.expires_at > now)
        .count()
    )
    awaiting_runs = db.query(OrchestrationFlowRun).filter(OrchestrationFlowRun.status == "awaiting_approval").count()
    return {
        "flow_count": len(flows),
        "flows_by_environment": by_env,
        "pending_prod_approvals": pending_prod,
        "certifications_due": certifications_due,
        "active_jit_grants": active_jit,
        "runs_awaiting_approval": awaiting_runs,
    }


@router.get("/orchestration/data-connections", response_model=OrchestrationDataConnectionListResponse)
def list_orchestration_data_connections(
    enabled_only: bool = Query(default=True),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    rows = list_data_connections(db, enabled_only=enabled_only)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="orchestration.data_connection.list",
        resource_type="orchestration_data_connection",
        resource_id="registry",
        trace_id="orchestration-data-connection-list",
    )
    db.commit()
    return {"total": len(rows), "data": rows}


@router.get(
    "/orchestration/data-connections/{connection_id}",
    response_model=OrchestrationDataConnectionResponse,
)
def get_orchestration_data_connection(
    connection_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    row = get_data_connection(db, connection_id)
    return row


@router.post(
    "/orchestration/data-connections/{connection_id}/test-query",
    response_model=OrchestrationDataConnectionTestQueryResponse,
)
def test_orchestration_data_connection_query(
    connection_id: str,
    payload: OrchestrationDataConnectionTestQueryRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_WRITE)
    sql_error = validate_read_only_sql(payload.sql)
    if sql_error:
        raise validation_error(
            message=f"SQL validation failed: {sql_error}",
            decision_trace_id="orchestration-data-connection-test-query",
        )
    parameters = payload.parameters if isinstance(payload.parameters, dict) else {}
    rows = execute_read_query(
        db,
        connection_id=connection_id,
        sql=str(payload.sql).strip(),
        parameters=parameters,
    )
    preview_limit = int(payload.preview_limit)
    preview_rows = rows[:preview_limit]
    columns = sorted({key for row in preview_rows for key in row.keys()}) if preview_rows else []
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="orchestration.data_connection.test_query",
        resource_type="orchestration_data_connection",
        resource_id=connection_id,
        trace_id=f"orchestration-data-connection-test-{connection_id}",
        action_context={"row_count": len(rows), "preview_limit": preview_limit},
    )
    db.commit()
    return {
        "connection_id": connection_id,
        "row_count": len(rows),
        "columns": columns,
        "rows": preview_rows,
        "truncated": len(rows) > preview_limit,
    }


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
    if not platform_bypasses_flow_scope(ctx):
        scope = resolve_actor_directory_scope(db, ctx.actor_id)
        rows = [
            row
            for row in rows
            if actor_can_read_flow(scope, parse_access_policy(getattr(row, "access_policy_json", None)), row)
        ]
    return {"total": len(rows) if not platform_bypasses_flow_scope(ctx) else total, "data": [serialize_flow(row) for row in rows]}


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
    access_policy_json = merge_access_policy_on_create(payload.access_policy_json, ctx.actor_id)
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
        access_policy_json=access_policy_json,
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
    row = _require_flow(db, flow_id)
    enforce_flow_access(db, ctx, row, FLOW_ACCESS_ACTION_READ)
    return serialize_flow(row)


@router.put("/orchestration/flows/{flow_id}", response_model=OrchestrationFlowResponse)
def update_orchestration_flow(
    flow_id: str,
    payload: OrchestrationFlowUpdateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_WRITE)
    row = _require_flow(db, flow_id)
    enforce_flow_access(db, ctx, row, FLOW_ACCESS_ACTION_MANAGE)

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
    if payload.access_policy_json is not None:
        policy = parse_access_policy(payload.access_policy_json)
        errors = validate_access_policy(policy)
        errors.extend(validate_iga_policy(policy, row.environment, row.created_by))
        if errors:
            raise validation_error(
                message="access_policy_json validation failed",
                decision_trace_id="orchestration-access-policy-update",
                errors=errors,
            )
        row.access_policy_json = json.dumps(policy, separators=(",", ":"))

    next_trigger = str(payload.trigger_type or row.trigger_type or "manual").strip().lower()
    if next_trigger == "schedule" and (
        payload.trigger_type is not None or payload.trigger_config_json is not None
    ):
        enforce_flow_access(db, ctx, row, FLOW_ACCESS_ACTION_SCHEDULE)

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
    enforce_flow_access(db, ctx, row, FLOW_ACCESS_ACTION_MANAGE)
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
    enforce_flow_access(db, ctx, row, FLOW_ACCESS_ACTION_MANAGE)
    result = validate_flow_definition(
        db,
        trigger_type=row.trigger_type,
        trigger_config_json=row.trigger_config_json,
        graph_json=row.graph_json,
        environment=row.environment,
    )
    policy = parse_access_policy(getattr(row, "access_policy_json", None))
    iga_errors = validate_iga_policy(policy, row.environment, row.created_by)
    if iga_errors:
        result["valid"] = False
        result["errors"] = list(result.get("errors") or []) + iga_errors
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
    policy = parse_access_policy(getattr(row, "access_policy_json", None))
    staged = is_staged_approvers(policy)
    stage_id = str(payload.stage_id or "").strip() or None

    if staged:
        if not stage_id:
            raise validation_error(
                message="stage_id is required when access_policy.approvers.mode=staged",
                decision_trace_id="orchestration-approve-stage-required",
            )
        scope = resolve_actor_directory_scope(db, ctx.actor_id)
        if not actor_matches_approver_policy(scope, policy, db=db, ctx=ctx, flow=row, stage_id=stage_id):
            raise HTTPException(
                status_code=403,
                detail={
                    "error_code": "AUTHZ_FLOW_SCOPE_FORBIDDEN",
                    "message": f"Actor is not authorized for approval stage '{stage_id}'.",
                    "stage_id": stage_id,
                    "decision_trace_id": "orchestration-flow-stage-approve",
                },
            )
    else:
        enforce_flow_access(db, ctx, row, FLOW_ACCESS_ACTION_APPROVE)

    enforce_sod_on_approve(db, ctx, row, stage_id=stage_id)
    enforce_orchestration_entitlement(db, ctx, row, FLOW_ACCESS_ACTION_APPROVE)

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
    state_from = row.approval_status

    if staged and stage_id:
        stage_state = parse_approval_stage_state(getattr(row, "approval_stage_state_json", None))
        stage_state = apply_stage_approval_decision(
            policy=policy,
            stage_state=stage_state,
            stage_id=stage_id,
            decision=decision,
            ctx=ctx,
        )
        row.approval_stage_state_json = serialize_approval_stage_state(stage_state)
        outcome = evaluate_staged_approval_outcome(policy, stage_state)
        if outcome:
            row.approval_status = outcome if outcome in APPROVAL_STATUSES else row.approval_status
        elif decision == "rejected":
            row.approval_status = "rejected"
    else:
        row.approval_status = decision if decision in APPROVAL_STATUSES else "approved"

    if payload.approval_ticket_ref:
        push_audit_action_context(approval_ticket_ref=payload.approval_ticket_ref)
    row.status = "active" if row.approval_status == "approved" else row.status
    row.metadata_version = int(row.metadata_version or 1) + 1
    row.updated_by = ctx.actor_id
    row.updated_at = datetime.utcnow()
    record_approval_event(
        db,
        flow_id=row.flow_id,
        event_type="flow_promotion",
        action="approve",
        state_from=state_from,
        state_to=row.approval_status,
        ctx=ctx,
        decision=decision,
        stage_id=stage_id,
        ticket_ref=payload.approval_ticket_ref,
    )
    db.commit()
    db.refresh(row)
    _audit_flow(
        db,
        ctx=ctx,
        action_type="orchestration.flow.approve",
        flow=row,
        action_context={
            "decision": row.approval_status,
            "ticket_ref": payload.approval_ticket_ref,
            "stage_id": stage_id,
        },
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
    enforce_flow_access(db, ctx, row, FLOW_ACCESS_ACTION_RUN)
    enforce_orchestration_entitlement(db, ctx, row, FLOW_ACCESS_ACTION_RUN)
    jit_grant = get_active_jit_grant(db, flow_id=row.flow_id, actor_id=ctx.actor_id, action=FLOW_ACCESS_ACTION_RUN)
    if str(row.trigger_type or "") == "schedule":
        enforce_flow_access(db, ctx, row, FLOW_ACCESS_ACTION_SCHEDULE)
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

    if (
        row.environment == "prod"
        and prod_run_requires_access_certification(db)
        and not platform_bypasses_flow_scope(ctx)
        and not check_certification_current(db, row)
    ):
        _audit_flow(
            db,
            ctx=ctx,
            action_type="orchestration.flow.run",
            flow=row,
            decision_outcome="deny",
            action_context={"reason": "access_certification_expired"},
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_IGA_CERTIFICATION_EXPIRED",
                "message": "Production flow run requires current access policy certification.",
                "flow_id": row.flow_id,
                "decision_trace_id": "orchestration-run-certification",
                "remediation_hint": "Certify the flow access policy via POST /orchestration/flows/{flow_id}/access-policy/certify.",
            },
        )

    dry_run = bool(payload.dry_run)
    if row.environment == "prod" and flow_has_human_approval_nodes(row.graph_json) and not dry_run:
        require_dual_approval(ctx, required_approver_role=ROLE_SECURITY_APPROVER)

    trace_id = f"orch-run-{uuid4().hex[:16]}"
    run_id = str(uuid4())
    started_at = datetime.utcnow()
    run_status, step_results, error_summary, live_executor_used, execution_state = execute_flow(
        db,
        ctx,
        flow_id=row.flow_id,
        run_id=run_id,
        graph_json=row.graph_json,
        environment=row.environment,
        dry_run=dry_run,
        trace_id=trace_id,
        run_input=str(payload.run_input or ""),
    )
    finished_at = None if run_status == "awaiting_approval" else datetime.utcnow()
    run_row = OrchestrationFlowRun(
        run_id=run_id,
        flow_id=row.flow_id,
        status=run_status,
        started_at=started_at,
        finished_at=finished_at,
        trace_id=trace_id,
        step_results_json=json.dumps(step_results),
        error_summary=error_summary,
        execution_state_json=json.dumps(execution_state) if execution_state else None,
    )
    db.add(run_row)
    db.commit()
    _audit_flow(
        db,
        ctx=ctx,
        action_type="orchestration.flow.run",
        flow=row,
        event_trace_id=trace_id,
        action_context={
            "run_id": run_id,
            "dry_run": dry_run,
            "trace_id": trace_id,
            "live_executor": live_executor_used,
            "access_via_jit": jit_grant is not None,
            "jit_request_id": jit_grant.request_id if jit_grant else None,
        },
    )
    db.commit()
    db.refresh(run_row)
    return serialize_run(run_row)


@router.get("/orchestration/runs", response_model=OrchestrationFlowRunListResponse)
def list_orchestration_runs(
    flow_id: Optional[str] = Query(default=None),
    environment: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    query = db.query(OrchestrationFlowRun, OrchestrationFlowDefinition).join(
        OrchestrationFlowDefinition,
        OrchestrationFlowRun.flow_id == OrchestrationFlowDefinition.flow_id,
    )
    if flow_id:
        query = query.filter(OrchestrationFlowRun.flow_id == str(flow_id).strip())
    if environment:
        query = query.filter(OrchestrationFlowDefinition.environment == str(environment).strip().lower())
    total = query.count()
    rows = (
        query.order_by(OrchestrationFlowRun.started_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return {
        "total": total,
        "data": [serialize_run(run_row, flow_name=flow_def.flow_name) for run_row, flow_def in rows],
    }


@router.get("/orchestration/flows/{flow_id}/runs", response_model=OrchestrationFlowRunListResponse)
def list_orchestration_flow_runs(
    flow_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    flow_row = _require_flow(db, flow_id)
    query = db.query(OrchestrationFlowRun).filter_by(flow_id=flow_id)
    total = query.count()
    rows = query.order_by(OrchestrationFlowRun.started_at.desc()).offset(offset).limit(limit).all()
    return {"total": total, "data": [serialize_run(row, flow_name=flow_row.flow_name) for row in rows]}


@router.get(
    "/orchestration/flows/{flow_id}/runs/{run_id}/approval-gates",
    response_model=OrchestrationRunApprovalGateListResponse,
)
def list_orchestration_run_approval_gates(
    flow_id: str,
    run_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    flow_row = _require_flow(db, flow_id)
    enforce_flow_access(db, ctx, flow_row, FLOW_ACCESS_ACTION_READ)
    _require_run(db, flow_id, run_id)
    rows = (
        db.query(OrchestrationRunApprovalGate)
        .filter_by(flow_id=flow_id, run_id=run_id)
        .order_by(OrchestrationRunApprovalGate.created_at.asc())
        .all()
    )
    return {"total": len(rows), "data": [_serialize_approval_gate(row) for row in rows]}


@router.post(
    "/orchestration/flows/{flow_id}/runs/{run_id}/approval-gates/{gate_id}/decide",
    response_model=OrchestrationFlowRunResponse,
)
def decide_orchestration_run_approval_gate(
    flow_id: str,
    run_id: str,
    gate_id: str,
    payload: OrchestrationRunApprovalGateDecideRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_APPROVE)
    flow_row = _require_flow(db, flow_id)
    run_row = _require_run(db, flow_id, run_id)
    gate = (
        db.query(OrchestrationRunApprovalGate)
        .filter_by(flow_id=flow_id, run_id=run_id, gate_id=gate_id)
        .first()
    )
    if gate is None:
        raise not_found_error("orchestration_approval_gate", gate_id, decision_trace_id="orchestration-gate-not-found")
    if gate.status != "pending":
        raise validation_error(
            message=f"Approval gate is already {gate.status}",
            decision_trace_id="orchestration-gate-not-pending",
            status_code=409,
        )
    if run_row.status != "awaiting_approval":
        raise validation_error(
            message="Run is not awaiting approval",
            decision_trace_id="orchestration-run-not-awaiting",
            status_code=409,
        )

    _enforce_gate_decider(db, ctx, flow_row, gate)
    decision = str(payload.decision or "").strip().lower()
    if decision not in {"approved", "rejected"}:
        raise validation_error(message="decision must be approved or rejected")

    now = datetime.utcnow()
    gate.status = decision
    gate.decided_by = ctx.actor_id
    gate.decided_at = now
    metadata = {}
    try:
        metadata = json.loads(gate.metadata_json or "{}")
    except json.JSONDecodeError:
        metadata = {}
    if payload.comment:
        metadata["comment"] = payload.comment
    gate.metadata_json = json.dumps(metadata, separators=(",", ":"))

    if decision == "rejected":
        run_row.status = "failed"
        run_row.finished_at = now
        run_row.error_summary = payload.comment or "Approval gate rejected"
        run_row.execution_state_json = None
        db.commit()
        _audit_flow(
            db,
            ctx=ctx,
            action_type="orchestration.flow.approval_gate.decide",
            flow=flow_row,
            event_trace_id=run_row.trace_id,
            action_context={"run_id": run_id, "gate_id": gate_id, "decision": decision},
        )
        db.commit()
        db.refresh(run_row)
        return serialize_run(run_row)

    execution_state = {}
    try:
        execution_state = json.loads(run_row.execution_state_json or "{}")
    except json.JSONDecodeError:
        execution_state = {}

    prior_steps = list(execution_state.get("prior_steps") or [])
    pending_node_id = str(execution_state.get("pending_node_id") or gate.node_id)
    step_outputs = dict(execution_state.get("step_outputs") or {})
    completed_node_ids = list(execution_state.get("completed_node_ids") or [])

    approval_output = {
        "live": True,
        "simulated": False,
        "approval_gate_id": gate_id,
        "approval_title": gate.approval_title,
        "status": "approved",
        "decided_by": ctx.actor_id,
        "decided_at": now.isoformat(),
    }
    step_outputs[pending_node_id] = approval_output
    updated_steps = []
    for step in prior_steps:
        if str(step.get("node_id") or "") == pending_node_id:
            updated_steps.append(
                {
                    **step,
                    "status": "completed",
                    "output": approval_output,
                }
            )
        else:
            updated_steps.append(step)
    if not any(str(step.get("node_id") or "") == pending_node_id for step in updated_steps):
        updated_steps.append(
            {
                "node_id": pending_node_id,
                "node_type": "human_approval",
                "status": "completed",
                "trace_id": run_row.trace_id,
                "output": approval_output,
            }
        )

    completed_set = {str(node_id) for node_id in completed_node_ids if str(node_id)}
    completed_set.add(pending_node_id)
    resume_state = {
        "step_outputs": step_outputs,
        "completed_node_ids": sorted(completed_set),
        "prior_steps": updated_steps,
        "resume_from_node_id": pending_node_id,
    }

    run_status, step_results, error_summary, live_executor_used, new_execution_state = execute_flow(
        db,
        ctx,
        flow_id=flow_row.flow_id,
        run_id=run_id,
        graph_json=flow_row.graph_json,
        environment=flow_row.environment,
        dry_run=False,
        trace_id=run_row.trace_id,
        resume_state=resume_state,
    )
    run_row.status = run_status
    run_row.step_results_json = json.dumps(step_results)
    run_row.error_summary = error_summary
    run_row.execution_state_json = json.dumps(new_execution_state) if new_execution_state else None
    run_row.finished_at = None if run_status == "awaiting_approval" else now
    db.commit()
    _audit_flow(
        db,
        ctx=ctx,
        action_type="orchestration.flow.approval_gate.decide",
        flow=flow_row,
        event_trace_id=run_row.trace_id,
        action_context={
            "run_id": run_id,
            "gate_id": gate_id,
            "decision": decision,
            "live_executor": live_executor_used,
        },
    )
    db.commit()
    db.refresh(run_row)
    return serialize_run(run_row)


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


@router.get("/orchestration/flows/{flow_id}/iga/posture", response_model=OrchestrationIgaPostureResponse)
def get_orchestration_iga_posture(
    flow_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    row = _require_flow(db, flow_id)
    enforce_flow_access(db, ctx, row, FLOW_ACCESS_ACTION_READ)
    return build_iga_posture(db, ctx, row)


@router.post("/orchestration/flows/{flow_id}/iga/explain", response_model=OrchestrationIgaExplainResponse)
def explain_orchestration_iga_access(
    flow_id: str,
    payload: OrchestrationIgaExplainRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    row = _require_flow(db, flow_id)
    enforce_flow_access(db, ctx, row, FLOW_ACCESS_ACTION_READ)
    action = str(payload.action or "run").strip().lower()
    return explain_orchestration_access(db, ctx, row, action)


@router.post(
    "/orchestration/flows/{flow_id}/jit-access-requests",
    response_model=OrchestrationJitAccessRequestResponse,
)
def create_orchestration_jit_access_request(
    flow_id: str,
    payload: OrchestrationJitAccessRequestCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    row = _require_flow(db, flow_id)
    enforce_flow_access(db, ctx, row, FLOW_ACCESS_ACTION_READ)
    environment = str(payload.environment or row.environment or "dev").strip().lower()
    request = OrchestrationJitAccessRequest(
        request_id=f"ojit-{uuid4().hex[:16]}",
        flow_id=row.flow_id,
        requester_id=ctx.actor_id,
        requester_role=ctx.actor_role,
        requested_action=str(payload.requested_action or "run").strip().lower(),
        justification=str(payload.justification or "").strip(),
        environment=environment,
        requested_duration_minutes=int(payload.requested_duration_minutes),
        status="requested",
    )
    db.add(request)
    record_approval_event(
        db,
        flow_id=row.flow_id,
        event_type="jit_access",
        action="request",
        state_from="none",
        state_to="requested",
        ctx=ctx,
        decision="requested",
        reason_code=request.requested_action,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="orchestration.jit.request.create",
        resource_type="orchestration_jit_access_request",
        resource_id=request.request_id,
        trace_id=f"trace-orch-jit-create-{request.request_id}",
        tenant_id=row.tenant_id,
        environment=environment,
    )
    db.commit()
    db.refresh(request)
    return request


@router.get("/orchestration/jit-access-requests", response_model=OrchestrationJitAccessRequestListResponse)
def list_orchestration_jit_access_requests(
    flow_id: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    requester_id: Optional[str] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    query = db.query(OrchestrationJitAccessRequest)
    if flow_id:
        query = query.filter_by(flow_id=str(flow_id).strip())
    if status:
        query = query.filter_by(status=str(status).strip().lower())
    if requester_id:
        query = query.filter_by(requester_id=str(requester_id).strip())
    total = query.count()
    rows = query.order_by(OrchestrationJitAccessRequest.created_at.desc()).offset(offset).limit(limit).all()
    return {"total": total, "data": rows}


@router.post(
    "/orchestration/jit-access-requests/{request_id}/approve",
    response_model=OrchestrationJitAccessRequestResponse,
)
def approve_orchestration_jit_access_request(
    request_id: str,
    payload: OrchestrationJitAccessApproveRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_APPROVE)
    request = db.query(OrchestrationJitAccessRequest).filter_by(request_id=request_id).first()
    if request is None:
        raise not_found_error("orchestration_jit_access_request", request_id)
    flow = _require_flow(db, request.flow_id)
    enforce_flow_access(db, ctx, flow, FLOW_ACCESS_ACTION_APPROVE)
    if request.status != "requested":
        raise validation_error(message="JIT access request is not pending", status_code=409)

    decision = str(payload.decision or "approve").strip().lower()
    if decision == "approve" and str(request.environment or "").strip().lower() == "prod":
        require_dual_approval(ctx, required_approver_role=ROLE_PLATFORM_ADMIN)

    state_from = request.status
    request.status = "approved" if decision == "approve" else "denied"
    request.approved_by = ctx.actor_id
    request.approved_role = ctx.actor_role
    request.approved_at = datetime.utcnow()
    if decision == "approve":
        request.expires_at = datetime.utcnow() + timedelta(minutes=int(request.requested_duration_minutes or 60))
    else:
        request.expires_at = None

    record_approval_event(
        db,
        flow_id=flow.flow_id,
        event_type="jit_access",
        action="approve",
        state_from=state_from,
        state_to=request.status,
        ctx=ctx,
        decision=decision,
        reason_code=request.requested_action,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="orchestration.jit.request.approve" if decision == "approve" else "orchestration.jit.request.deny",
        resource_type="orchestration_jit_access_request",
        resource_id=request.request_id,
        trace_id=f"trace-orch-jit-approve-{request.request_id}",
        tenant_id=flow.tenant_id,
        environment=request.environment,
    )
    db.commit()
    db.refresh(request)
    return request


@router.post(
    "/orchestration/flows/{flow_id}/access-policy/certify",
    response_model=OrchestrationAccessCertificationResponse,
)
def certify_orchestration_flow_access_policy(
    flow_id: str,
    payload: OrchestrationAccessCertifyRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_WRITE)
    row = _require_flow(db, flow_id)
    enforce_flow_access(db, ctx, row, FLOW_ACCESS_ACTION_MANAGE)
    policy = parse_access_policy(getattr(row, "access_policy_json", None))
    iga_errors = validate_iga_policy(policy, row.environment, row.created_by)
    if iga_errors:
        raise validation_error(
            message="Cannot certify invalid access policy",
            decision_trace_id="orchestration-certify-policy",
            errors=iga_errors,
        )

    approver_id = str(payload.approver_id or ctx.approver_id or "").strip() or None
    if str(row.environment or "").strip().lower() == "prod":
        require_dual_approval(ctx, required_approver_role=ROLE_PLATFORM_ADMIN)
        if not approver_id:
            approver_id = ctx.approver_id

    now = datetime.utcnow()
    supersede_prior_certifications(db, row.flow_id)
    certification = OrchestrationFlowAccessCertification(
        certification_id=f"ocert-{uuid4().hex[:16]}",
        flow_id=row.flow_id,
        certified_by=ctx.actor_id,
        approver_id=approver_id,
        certified_at=now,
        next_due_at=compute_next_due_at(policy, from_time=now),
        attestation_notes=str(payload.attestation_notes or "").strip(),
        status="active",
    )
    db.add(certification)
    record_approval_event(
        db,
        flow_id=row.flow_id,
        event_type="access_certification",
        action="certify",
        state_from="uncertified",
        state_to="active",
        ctx=ctx,
        decision="certified",
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="orchestration.access_policy.certify",
        resource_type="orchestration_flow_access_certification",
        resource_id=certification.certification_id,
        trace_id=f"trace-orch-certify-{certification.certification_id}",
        tenant_id=row.tenant_id,
        environment=row.environment,
    )
    db.commit()
    db.refresh(certification)
    return certification


@router.post(
    "/orchestration/flows/{flow_id}/access-policy/resolve",
    response_model=OrchestrationAccessPolicyResolveResponse,
)
def resolve_orchestration_access_policy(
    flow_id: str,
    payload: OrchestrationAccessPolicyResolveRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    row = _require_flow(db, flow_id)
    enforce_flow_access(db, ctx, row, FLOW_ACCESS_ACTION_READ)
    if payload.access_policy_json is not None and str(payload.access_policy_json).strip():
        policy = parse_access_policy(payload.access_policy_json)
        policy_errors = validate_access_policy(policy)
        iga_errors = validate_iga_policy(policy, row.environment, row.created_by)
        if policy_errors or iga_errors:
            raise validation_error(
                message="access_policy_json validation failed",
                decision_trace_id="orchestration-access-policy-resolve-validate",
                errors=(policy_errors + iga_errors)[:10],
            )
    else:
        policy = parse_access_policy(getattr(row, "access_policy_json", None))
    resolved = preview_resolved_policy(db, ctx, row, policy)
    resolve_errors = [str(item) for item in (resolved.pop("_resolve_errors", None) or [])]
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="orchestration.access_policy.resolve",
        resource_type="orchestration_flow",
        resource_id=flow_id,
        trace_id=f"orchestration-access-policy-resolve-{flow_id}",
        action_context={"resolve_error_count": len(resolve_errors)},
    )
    db.commit()
    return {
        "flow_id": flow_id,
        "resolved_policy": resolved,
        "resolve_errors": resolve_errors,
        "template_context": build_template_context(ctx, row),
    }


@router.get(
    "/orchestration/access-certifications/due",
    response_model=OrchestrationAccessCertificationDueResponse,
)
def list_orchestration_access_certifications_due(
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    rows = flows_due_for_recertification(db, limit=limit)
    return {"total": len(rows), "data": rows}


@router.get(
    "/orchestration/flows/{flow_id}/approval-events",
    response_model=list[OrchestrationFlowApprovalEventResponse],
)
def list_orchestration_flow_approval_events(
    flow_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ORCHESTRATION_READ)
    row = _require_flow(db, flow_id)
    enforce_flow_access(db, ctx, row, FLOW_ACCESS_ACTION_READ)
    from app.models import OrchestrationFlowApprovalEvent

    events = (
        db.query(OrchestrationFlowApprovalEvent)
        .filter_by(flow_id=flow_id)
        .order_by(OrchestrationFlowApprovalEvent.occurred_at.asc())
        .all()
    )
    return events


@router.post(
    "/orchestration/webhooks/{webhook_token}/trigger",
    response_model=OrchestrationFlowRunResponse,
)
def trigger_orchestration_webhook(
    webhook_token: str,
    payload: OrchestrationWebhookTriggerRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
):
    require_role(ctx, ROLES_ORCHESTRATION_RUN)
    run_row = trigger_webhook_flow(
        db,
        ctx,
        webhook_token=webhook_token,
        authorization=authorization,
        run_input=str(payload.run_input or ""),
        dry_run=bool(payload.dry_run),
    )
    flow = _require_flow(db, run_row.flow_id)
    return serialize_run(run_row, flow_name=flow.flow_name)


@router.get("/orchestration/scheduler/tick", response_model=OrchestrationSchedulerTickResponse)
def orchestration_scheduler_tick(
    dry_run: bool = Query(default=False),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    if str(ctx.actor_role or "").strip() not in {ROLE_SUPER_ADMIN, ROLE_PLATFORM_ADMIN}:
        raise HTTPException(status_code=403, detail="Scheduler tick requires Platform Admin or Super Admin")
    triggered = poll_due_scheduled_flows(db, ctx, dry_run=dry_run)
    return {"tick_at": datetime.utcnow(), "triggered": triggered}
