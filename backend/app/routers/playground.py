from datetime import datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import PlaygroundRun, RouteDraft
from app.policy_constants import (
    COST_POLICY_DECISION_DENY,
    ROLE_AGENT_OWNER,
)
from app.router_constants import ROLES_PLAYGROUND_READ, ROLES_PLAYGROUND_WRITE
from app.schemas import (
    PlaygroundCompareRequest,
    PlaygroundCompareResponse,
    PlaygroundRouteDraftResponse,
    PlaygroundRunCreateRequest,
    PlaygroundRunResponse,
    PlaygroundTestSetResponse,
)
from app.security import ActorContext, get_actor_context, require_role
from app.services.audit import create_audit_event
from app.services.cost_limits import evaluate_actor_cost_limits

router = APIRouter()
logger = get_logger(__name__)
PLAYGROUND_DEFAULT_ESTIMATED_COST_CENTS = 25


@router.post("/playground/runs", response_model=PlaygroundRunResponse)
def create_playground_run(
    payload: PlaygroundRunCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace("playground_run_create_start %s", sanitize_fields({"actor_id": ctx.actor_id}))
    require_role(ctx, ROLES_PLAYGROUND_WRITE)

    projected_cost = (
        payload.projected_additional_cost_cents
        if payload.projected_additional_cost_cents is not None
        else PLAYGROUND_DEFAULT_ESTIMATED_COST_CENTS
    )
    cost_evaluation = evaluate_actor_cost_limits(
        db,
        actor_id=ctx.actor_id,
        team_ids=payload.team_ids,
        group_ids=payload.group_ids,
        window_type="daily",
        projected_additional_cost_cents=projected_cost,
    )
    if cost_evaluation.aggregated_decision == COST_POLICY_DECISION_DENY:
        trace_id = f"trace-playground-run-deny-{ctx.actor_id}"
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="playground.run.create",
            resource_type="playground_run",
            resource_id="pending",
            trace_id=trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "COST_LIMIT_EXCEEDED",
                "message": "Playground run blocked by cost governance limit.",
                "blocking_scopes": cost_evaluation.blocking_scopes,
                "decision_trace_id": trace_id,
                "policy_version": "v1",
                "remediation_hint": "Increase budget or reduce projected run cost for this actor/team/group.",
            },
        )

    run = PlaygroundRun(
        run_id=str(uuid4()),
        actor_id=ctx.actor_id,
        prompt_text=payload.prompt_text,
        candidate_models=payload.candidate_models,
        selected_model=payload.selected_model,
        status="completed",
        estimated_cost_cents=PLAYGROUND_DEFAULT_ESTIMATED_COST_CENTS,
        policy_decision="allow",
    )
    db.add(run)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="playground.run.create",
        resource_type="playground_run",
        resource_id=run.run_id,
        trace_id=f"trace-{run.run_id}",
    )
    db.commit()
    db.refresh(run)
    logger.info(
        "playground_run_create_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "run_id": run.run_id}),
    )
    return run


@router.get("/playground/runs", response_model=list[PlaygroundRunResponse])
def list_playground_runs(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    require_role(ctx, ROLES_PLAYGROUND_READ)
    query = db.query(PlaygroundRun).order_by(PlaygroundRun.created_at.desc())
    if ctx.actor_role == ROLE_AGENT_OWNER:
        query = query.filter_by(actor_id=ctx.actor_id)
    return query.offset(offset).limit(limit).all()


@router.get("/playground/runs/{run_id}", response_model=PlaygroundRunResponse)
def get_playground_run(
    run_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace("playground_run_get_start %s", sanitize_fields({"actor_id": ctx.actor_id, "run_id": run_id}))
    require_role(ctx, ROLES_PLAYGROUND_READ)
    run = db.query(PlaygroundRun).filter_by(run_id=run_id).first()
    if not run:
        logger.error("playground_run_not_found %s", sanitize_fields({"run_id": run_id}))
        raise HTTPException(status_code=404, detail="Playground run not found")
    if ctx.actor_role == ROLE_AGENT_OWNER and run.actor_id != ctx.actor_id:
        logger.error(
            "playground_run_scope_denied %s",
            sanitize_fields({"actor_id": ctx.actor_id, "run_id": run_id}),
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only access own playground runs.",
                "actor_role": ctx.actor_role,
                "required_scope": "playground_run.actor_id == actor_id",
                "policy_version": "v1",
                "decision_trace_id": "authz-scope-check",
                "remediation_hint": "Use a privileged role or access a run owned by your actor id.",
            },
        )
    logger.info("playground_run_get_completed %s", sanitize_fields({"actor_id": ctx.actor_id, "run_id": run_id}))
    return run


@router.post("/playground/compare", response_model=PlaygroundCompareResponse)
def compare_models(
    payload: PlaygroundCompareRequest,
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_WRITE)

    results = []
    for i, model_name in enumerate(payload.candidate_models):
        results.append(
            {
                "model_name": model_name,
                "estimated_latency_ms": 350 + (i * 40),
                "estimated_cost_cents": 12 + (i * 3),
                "quality_score": round(0.85 - (i * 0.03), 2),
            }
        )
    return {"results": results}


@router.post("/playground/runs/{run_id}/route-draft", response_model=PlaygroundRouteDraftResponse)
def create_route_draft_from_run(
    run_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "playground_route_draft_create_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "run_id": run_id}),
    )
    require_role(ctx, ROLES_PLAYGROUND_WRITE)
    run = db.query(PlaygroundRun).filter_by(run_id=run_id).first()
    if not run:
        logger.error("playground_route_draft_source_run_not_found %s", sanitize_fields({"run_id": run_id}))
        raise HTTPException(status_code=404, detail="Playground run not found")

    draft_id = str(uuid4())
    db.add(
        RouteDraft(
            draft_id=draft_id,
            agent_id="playground-agent",
            route_policy_snapshot_id=f"snapshot-{run_id}",
            environment="staging",
            status="draft",
            submitted_by=ctx.actor_id,
            submitted_at=datetime.utcnow(),
            approved_security=False,
            approved_ai_ops=False,
        )
    )
    run.route_policy_snapshot_id = f"snapshot-{run_id}"

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="playground.route_draft.create",
        resource_type="route_draft",
        resource_id=draft_id,
        trace_id=f"trace-{draft_id}",
    )
    db.commit()
    logger.info(
        "playground_route_draft_create_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "run_id": run_id, "draft_id": draft_id}),
    )

    return {"run_id": run_id, "draft_id": draft_id, "status": "draft"}


@router.get("/playground/test-sets", response_model=list[PlaygroundTestSetResponse])
def list_test_sets(
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_READ)
    return [
        {"test_set_id": "ts-regression", "name": "Regression Core", "case_count": 25},
        {"test_set_id": "ts-safety", "name": "Safety and Policy", "case_count": 40},
    ]
