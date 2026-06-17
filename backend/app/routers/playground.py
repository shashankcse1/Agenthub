import json
import re
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import (
    AuditEvent,
    PlaygroundQualityEscalationNotification,
    PlaygroundQualityEscalation,
    PlaygroundRun,
    PlaygroundRunFeedback,
    PromptRegistryItem,
    PromptRegistryVersion,
    RouteDraft,
)
from app.policy_constants import (
    COST_POLICY_DECISION_DENY,
    ROLE_AGENT_OWNER,
    ROLE_SECURITY_APPROVER,
)
from app.router_constants import ROLES_PLAYGROUND_READ, ROLES_PLAYGROUND_WRITE
from app.services.benchmark_scan_runner import list_test_set_catalog
from app.services.playground_judge import assess_playground_run_response, judge_candidate_models
from app.schemas import (
    PlaygroundCompareRequest,
    PlaygroundCompareResponse,
    PlaygroundRouteDraftResponse,
    PlaygroundRunCreateRequest,
    PlaygroundRunResponse,
    PlaygroundRunAssessRequest,
    PlaygroundRunAssessResponse,
    PlaygroundRunFeedbackCreateRequest,
    PlaygroundRunFeedbackResponse,
    PlaygroundRunDetailResponse,
    PlaygroundQualityEscalationCreateRequest,
    PlaygroundQualityEscalationNotifyRequest,
    PlaygroundQualityEscalationNotifyResponse,
    PlaygroundQualityEscalationQueueResponse,
    PlaygroundQualityEscalationResolveRequest,
    PlaygroundQualityEscalationResponse,
    PlaygroundQualityAnalyticsBucketResponse,
    PlaygroundQualityAnalyticsRollupResponse,
    PlaygroundQualityTriageQueueResponse,
    PlaygroundQualityTriageItemResponse,
    PlaygroundTestSetResponse,
    PromptRegistryCreateRequest,
    PromptRegistryItemResponse,
    PromptRegistryPromoteRequest,
    PromptRegistryPromoteResponse,
    PromptRegistryRollbackRequest,
    PromptRegistryUpdateRequest,
    PromptRegistryVersionResponse,
)
from app.security import ActorContext, get_actor_context, require_dual_approval, require_role
from app.services.audit import create_audit_event
from app.services.cost_limits import evaluate_actor_cost_limits
from app.services.escalation_notify import deliver_escalation_notification

router = APIRouter()
logger = get_logger(__name__)
PLAYGROUND_DEFAULT_ESTIMATED_COST_CENTS = 25
_PROMPT_TEMPLATE_VAR_PATTERN = re.compile(r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_\-\.]*)\s*\}\}")


def _is_prod_environment(environment: str) -> bool:
    return environment.strip().lower() in {"prod", "production"}


def _parse_prompt_registry_labels(raw_labels: str) -> list[str]:
    try:
        parsed = json.loads(raw_labels or "[]")
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Prompt registry labels must be valid JSON.")
    if not isinstance(parsed, list):
        raise HTTPException(status_code=400, detail="Prompt registry labels must be a JSON array.")
    return [str(item).strip() for item in parsed if str(item).strip()]


def _prompt_registry_item_response(item: PromptRegistryItem) -> PromptRegistryItemResponse:
    return PromptRegistryItemResponse.model_validate(item)


def _extract_prompt_template_variables(prompt_text: str) -> list[str]:
    return sorted({match.group(1).strip() for match in _PROMPT_TEMPLATE_VAR_PATTERN.finditer(prompt_text or "")})


def _render_prompt_template(prompt_text: str, variables: dict[str, str]) -> str:
    if "{{" in prompt_text and "}}" not in prompt_text:
        raise HTTPException(status_code=422, detail="Prompt template has unmatched opening braces.")
    if "}}" in prompt_text and "{{" not in prompt_text:
        raise HTTPException(status_code=422, detail="Prompt template has unmatched closing braces.")

    def _replace(match: re.Match[str]) -> str:
        key = match.group(1).strip()
        return str(variables.get(key, ""))

    return _PROMPT_TEMPLATE_VAR_PATTERN.sub(_replace, prompt_text)


def _extract_provider_id_from_model_name(model_name: str) -> str:
    normalized = str(model_name or "").strip().lower()
    if not normalized:
        return "unknown"
    if "/" in normalized:
        return normalized.split("/", 1)[0] or "unknown"
    if ":" in normalized:
        return normalized.split(":", 1)[0] or "unknown"
    return "unknown"


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
            user_login=ctx.user_login,
            action_context={
                "user_prompt": payload.prompt_text,
                "selected_model": payload.selected_model,
            },
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
        user_login=ctx.user_login,
        action_context={
            "user_prompt": payload.prompt_text,
            "selected_model": payload.selected_model,
            "candidate_models": payload.candidate_models,
        },
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


@router.get("/playground/runs/{run_id}/detail", response_model=PlaygroundRunDetailResponse)
def get_playground_run_detail(
    run_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_READ)
    run = db.query(PlaygroundRun).filter_by(run_id=run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Playground run not found")
    if ctx.actor_role == ROLE_AGENT_OWNER and run.actor_id != ctx.actor_id:
        raise HTTPException(status_code=403, detail="Agent Owner can only access own playground runs.")

    feedback_rows = (
        db.query(PlaygroundRunFeedback)
        .filter_by(run_id=run_id)
        .order_by(PlaygroundRunFeedback.created_at.desc())
        .all()
    )

    trace_id = f"trace-{run_id}"
    audit_rows = (
        db.query(AuditEvent)
        .filter(AuditEvent.trace_id == trace_id)
        .order_by(AuditEvent.timestamp.desc())
        .limit(50)
        .all()
    )
    if not audit_rows:
        audit_rows = (
            db.query(AuditEvent)
            .filter(AuditEvent.resource_id == run_id)
            .order_by(AuditEvent.timestamp.desc())
            .limit(50)
            .all()
        )

    latest_assessment = None
    assess_event = next((event for event in audit_rows if event.action_type == "playground.run.feedback.assess"), None)
    latest_feedback = feedback_rows[0] if feedback_rows else None
    if assess_event or (latest_feedback and float(latest_feedback.quality_score or 0) > 0):
        latest_assessment = PlaygroundRunAssessResponse(
            run_id=run_id,
            model_name=run.selected_model,
            trace_id=latest_feedback.trace_id if latest_feedback else trace_id,
            quality_score=float(latest_feedback.quality_score if latest_feedback else 0.0),
            quality_tier="fair",
            score_reason="Derived from stored feedback or latest assess audit event.",
            suggested_rating=int(latest_feedback.rating if latest_feedback else 3),
            suggested_comment=str(latest_feedback.comment if latest_feedback else ""),
            response_preview=str(run.prompt_text or "")[:240],
            response_text=str(run.prompt_text or ""),
            inference_ran=assess_event is not None,
        )

    route_draft = None
    snapshot_id = str(run.route_policy_snapshot_id or f"snapshot-{run_id}").strip()
    draft_row = db.query(RouteDraft).filter_by(route_policy_snapshot_id=snapshot_id).first()
    if draft_row:
        route_draft = {
            "draft_id": draft_row.draft_id,
            "status": draft_row.status,
            "environment": draft_row.environment,
            "submitted_by": draft_row.submitted_by,
            "submitted_at": draft_row.submitted_at,
        }

    escalation_row = (
        db.query(PlaygroundQualityEscalation)
        .filter_by(run_id=run_id)
        .order_by(PlaygroundQualityEscalation.created_at.desc())
        .first()
    )

    audit_events = [
        {
            "audit_event_id": event.audit_event_id,
            "timestamp": event.timestamp,
            "action_type": event.action_type,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
            "decision_outcome": event.decision_outcome,
            "trace_id": event.trace_id,
        }
        for event in audit_rows
    ]

    return {
        "run": run,
        "feedback": feedback_rows,
        "latest_assessment": latest_assessment,
        "audit_events": audit_events,
        "route_draft": route_draft,
        "quality_escalation": escalation_row,
    }


@router.post("/playground/compare", response_model=PlaygroundCompareResponse)
def compare_models(
    payload: PlaygroundCompareRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_WRITE)

    prompt_text = str(payload.prompt_text or "").strip()
    candidate_models = [str(model_name or "").strip() for model_name in payload.candidate_models if str(model_name or "").strip()]
    if not prompt_text:
        raise HTTPException(status_code=422, detail="prompt_text is required")
    if not candidate_models:
        raise HTTPException(status_code=422, detail="candidate_models must include at least one model")

    results = judge_candidate_models(
        db,
        prompt_text=prompt_text,
        candidate_models=candidate_models,
        environment="dev",
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="playground.compare",
        resource_type="playground_run",
        resource_id=f"compare-{uuid4()}",
        trace_id=f"trace-playground-compare-{uuid4()}",
        user_login=ctx.user_login,
        action_context={
            "user_prompt": prompt_text,
            "candidate_models": candidate_models,
        },
    )
    db.commit()
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
    return list_test_set_catalog()


@router.post("/playground/runs/{run_id}/assess", response_model=PlaygroundRunAssessResponse)
def assess_playground_run(
    run_id: str,
    payload: PlaygroundRunAssessRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_WRITE)
    run = db.query(PlaygroundRun).filter_by(run_id=run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Playground run not found")
    if ctx.actor_role == ROLE_AGENT_OWNER and run.actor_id != ctx.actor_id:
        raise HTTPException(status_code=403, detail="Agent Owner can only assess own playground runs.")

    environment = str(payload.environment or "dev").strip().lower() or "dev"
    try:
        assessment = assess_playground_run_response(
            db,
            prompt_text=run.prompt_text,
            model_name=run.selected_model,
            response_text=payload.response_text,
            environment=environment,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    trace_id = str(payload.trace_id or "").strip() or f"trace-{run_id}"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="playground.run.feedback.assess",
        resource_type="playground_run",
        resource_id=run_id,
        trace_id=trace_id,
    )
    db.commit()
    return PlaygroundRunAssessResponse(
        run_id=run_id,
        model_name=str(assessment["model_name"]),
        trace_id=trace_id,
        quality_score=float(assessment["quality_score"]),
        quality_tier=str(assessment["quality_tier"]),
        score_reason=str(assessment["score_reason"]),
        suggested_rating=int(assessment["suggested_rating"]),
        suggested_comment=str(assessment["suggested_comment"]),
        response_preview=str(assessment["response_preview"]),
        response_text=str(assessment["response_text"]),
        inference_ran=bool(assessment["inference_ran"]),
    )


@router.post("/playground/runs/{run_id}/feedback", response_model=PlaygroundRunFeedbackResponse)
def create_playground_run_feedback(
    run_id: str,
    payload: PlaygroundRunFeedbackCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_WRITE)
    run = db.query(PlaygroundRun).filter_by(run_id=run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Playground run not found")
    if ctx.actor_role == ROLE_AGENT_OWNER and run.actor_id != ctx.actor_id:
        raise HTTPException(status_code=403, detail="Agent Owner can only create feedback for own playground runs.")

    trace_id = str(payload.trace_id).strip()
    comment = payload.comment.strip()
    existing = (
        db.query(PlaygroundRunFeedback)
        .filter_by(run_id=run_id, trace_id=trace_id)
        .first()
    )
    if existing:
        existing.rating = int(payload.rating)
        existing.quality_score = float(payload.quality_score)
        existing.comment = comment
        feedback = existing
        action_type = "playground.run.feedback.update"
    else:
        feedback = PlaygroundRunFeedback(
            feedback_id=str(uuid4()),
            run_id=run_id,
            trace_id=trace_id,
            rating=int(payload.rating),
            quality_score=float(payload.quality_score),
            comment=comment,
            created_by=ctx.actor_id,
        )
        db.add(feedback)
        action_type = "playground.run.feedback.create"

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type=action_type,
        resource_type="playground_run",
        resource_id=run_id,
        trace_id=trace_id,
    )
    db.commit()
    db.refresh(feedback)
    return feedback


@router.get("/playground/runs/{run_id}/feedback", response_model=list[PlaygroundRunFeedbackResponse])
def list_playground_run_feedback(
    run_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_READ)
    run = db.query(PlaygroundRun).filter_by(run_id=run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Playground run not found")
    if ctx.actor_role == ROLE_AGENT_OWNER and run.actor_id != ctx.actor_id:
        raise HTTPException(status_code=403, detail="Agent Owner can only view feedback for own playground runs.")
    return (
        db.query(PlaygroundRunFeedback)
        .filter_by(run_id=run_id)
        .order_by(PlaygroundRunFeedback.created_at.desc())
        .all()
    )


@router.get("/playground/quality/triage", response_model=PlaygroundQualityTriageQueueResponse)
def list_playground_quality_triage_queue(
    max_quality_score: float = Query(default=0.8, ge=0, le=1),
    max_rating: int = Query(default=3, ge=1, le=5),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_READ)

    query = (
        db.query(PlaygroundRunFeedback, PlaygroundRun)
        .join(PlaygroundRun, PlaygroundRun.run_id == PlaygroundRunFeedback.run_id)
        .filter(
            or_(
                PlaygroundRunFeedback.quality_score <= max_quality_score,
                PlaygroundRunFeedback.rating <= max_rating,
            )
        )
    )

    if ctx.actor_role == ROLE_AGENT_OWNER:
        query = query.filter(PlaygroundRun.actor_id == ctx.actor_id)

    total = query.count()
    rows = (
        query.order_by(PlaygroundRunFeedback.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    items: list[PlaygroundQualityTriageItemResponse] = []
    for feedback, run in rows:
        if feedback.quality_score <= 0.4 or feedback.rating <= 2:
            priority_tag = "p0"
            triage_reason = "critical_quality_risk"
        elif feedback.quality_score <= 0.6 or feedback.rating <= 3:
            priority_tag = "p1"
            triage_reason = "elevated_quality_risk"
        else:
            priority_tag = "p2"
            triage_reason = "moderate_quality_risk"

        items.append(
            PlaygroundQualityTriageItemResponse(
                feedback_id=feedback.feedback_id,
                run_id=feedback.run_id,
                trace_id=feedback.trace_id,
                rating=feedback.rating,
                quality_score=float(feedback.quality_score),
                comment=feedback.comment,
                created_by=feedback.created_by,
                created_at=feedback.created_at,
                run_actor_id=run.actor_id,
                selected_model=run.selected_model,
                run_status=run.status,
                priority_tag=priority_tag,
                triage_reason=triage_reason,
            )
        )

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="playground.feedback.triage.read",
        resource_type="playground_feedback_triage",
        resource_id="queue",
        trace_id=f"trace-playground-triage-read-{ctx.actor_id}",
    )
    db.commit()
    return PlaygroundQualityTriageQueueResponse(total=total, items=items)


@router.get("/playground/quality/analytics/rollups", response_model=PlaygroundQualityAnalyticsRollupResponse)
def get_playground_quality_analytics_rollups(
    window_hours: int = Query(default=168, ge=24, le=2160),
    bucket_hours: int = Query(default=24, ge=1, le=168),
    provider_id: Optional[str] = Query(default=None),
    route_policy_id: Optional[str] = Query(default=None),
    model_name: Optional[str] = Query(default=None),
    limit: int = Query(default=500, ge=1, le=5000),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_READ)
    now = datetime.utcnow()
    since = now - timedelta(hours=window_hours)

    query = (
        db.query(PlaygroundRunFeedback, PlaygroundRun)
        .join(PlaygroundRun, PlaygroundRun.run_id == PlaygroundRunFeedback.run_id)
        .filter(PlaygroundRunFeedback.created_at >= since)
        .order_by(PlaygroundRunFeedback.created_at.desc())
    )

    if ctx.actor_role == ROLE_AGENT_OWNER:
        query = query.filter(PlaygroundRun.actor_id == ctx.actor_id)
    if route_policy_id:
        query = query.filter(PlaygroundRun.route_policy_snapshot_id == str(route_policy_id).strip())
    if model_name:
        query = query.filter(PlaygroundRun.selected_model == str(model_name).strip())

    rows = query.limit(limit).all()

    aggregates: dict[tuple[datetime, str, str, str], dict[str, float]] = {}
    total_samples = 0
    for feedback, run in rows:
        model = str(run.selected_model or "unknown").strip() or "unknown"
        derived_provider = _extract_provider_id_from_model_name(model)
        if provider_id and derived_provider != str(provider_id).strip().lower():
            continue

        created = feedback.created_at or now
        bucket_base = created.replace(minute=0, second=0, microsecond=0)
        hours_into_bucket = bucket_base.hour % bucket_hours
        bucket_start = bucket_base - timedelta(hours=hours_into_bucket)
        route_id = str(run.route_policy_snapshot_id or "none").strip() or "none"
        key = (bucket_start, derived_provider, route_id, model)

        if key not in aggregates:
            aggregates[key] = {
                "sample_count": 0,
                "quality_total": 0.0,
                "rating_total": 0.0,
                "critical_count": 0,
                "elevated_count": 0,
            }
        bucket = aggregates[key]
        bucket["sample_count"] += 1
        bucket["quality_total"] += float(feedback.quality_score)
        bucket["rating_total"] += float(feedback.rating)
        if float(feedback.quality_score) <= 0.4 or int(feedback.rating) <= 2:
            bucket["critical_count"] += 1
        elif float(feedback.quality_score) <= 0.6 or int(feedback.rating) <= 3:
            bucket["elevated_count"] += 1
        total_samples += 1

    buckets = []
    for (bucket_start, derived_provider, route_id, model), values in sorted(
        aggregates.items(), key=lambda item: item[0][0], reverse=True
    ):
        sample_count = int(values["sample_count"])
        buckets.append(
            PlaygroundQualityAnalyticsBucketResponse(
                bucket_start=bucket_start,
                bucket_end=bucket_start + timedelta(hours=bucket_hours),
                provider_id=derived_provider,
                route_policy_id=route_id,
                model_name=model,
                sample_count=sample_count,
                average_quality_score=(float(values["quality_total"]) / sample_count) if sample_count else 0.0,
                average_rating=(float(values["rating_total"]) / sample_count) if sample_count else 0.0,
                critical_count=int(values["critical_count"]),
                elevated_count=int(values["elevated_count"]),
            )
        )

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="playground.feedback.analytics.rollup.read",
        resource_type="playground_quality_analytics",
        resource_id="rollups",
        trace_id=f"trace-playground-quality-rollups-read-{ctx.actor_id}",
    )
    db.commit()
    return PlaygroundQualityAnalyticsRollupResponse(
        window_hours=window_hours,
        bucket_hours=bucket_hours,
        total_samples=total_samples,
        buckets=buckets,
    )


@router.post(
    "/playground/quality/triage/{feedback_id}/escalate",
    response_model=PlaygroundQualityEscalationResponse,
)
def escalate_playground_quality_triage_item(
    feedback_id: str,
    payload: PlaygroundQualityEscalationCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_WRITE | {ROLE_SECURITY_APPROVER})

    feedback = db.query(PlaygroundRunFeedback).filter_by(feedback_id=feedback_id).first()
    if feedback is None:
        raise HTTPException(status_code=404, detail="Playground feedback not found")
    run = db.query(PlaygroundRun).filter_by(run_id=feedback.run_id).first()
    if run is None:
        raise HTTPException(status_code=404, detail="Playground run not found")
    if ctx.actor_role == ROLE_AGENT_OWNER and run.actor_id != ctx.actor_id:
        raise HTTPException(status_code=403, detail="Agent Owner can only escalate own run feedback.")

    active_escalation = (
        db.query(PlaygroundQualityEscalation)
        .filter(
            PlaygroundQualityEscalation.feedback_id == feedback_id,
            PlaygroundQualityEscalation.status.in_(["open", "acknowledged"]),
        )
        .first()
    )
    if active_escalation is not None:
        raise HTTPException(status_code=409, detail="An active escalation already exists for this feedback item")

    now = datetime.utcnow()
    escalation = PlaygroundQualityEscalation(
        escalation_id=f"pqe-{uuid4().hex[:16]}",
        feedback_id=feedback.feedback_id,
        run_id=feedback.run_id,
        trace_id=feedback.trace_id,
        run_actor_id=run.actor_id,
        status="open",
        severity=str(payload.severity).strip().lower(),
        priority_tag=str(payload.priority_tag).strip().lower(),
        assigned_team=str(payload.assigned_team).strip(),
        escalation_channel=str(payload.escalation_channel).strip(),
        external_ticket_ref=(
            str(payload.external_ticket_ref).strip() if payload.external_ticket_ref is not None else None
        ),
        escalation_reason=str(payload.escalation_reason).strip(),
        sla_target_minutes=int(payload.sla_target_minutes),
        due_at=now + timedelta(minutes=int(payload.sla_target_minutes)),
        created_by=ctx.actor_id,
    )
    db.add(escalation)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="playground.feedback.triage.escalate",
        resource_type="playground_quality_escalation",
        resource_id=escalation.escalation_id,
        trace_id=f"trace-playground-triage-escalate-{escalation.escalation_id}",
    )
    db.commit()
    db.refresh(escalation)
    return escalation


@router.get(
    "/playground/quality/triage/escalations",
    response_model=PlaygroundQualityEscalationQueueResponse,
)
def list_playground_quality_escalations(
    status: Optional[str] = Query(default="open"),
    priority_tag: Optional[str] = Query(default=None),
    assigned_team: Optional[str] = Query(default=None),
    overdue_only: bool = Query(default=False),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_READ)
    now = datetime.utcnow()

    query = db.query(PlaygroundQualityEscalation)
    if status:
        query = query.filter(PlaygroundQualityEscalation.status == str(status).strip().lower())
    if priority_tag:
        query = query.filter(PlaygroundQualityEscalation.priority_tag == str(priority_tag).strip().lower())
    if assigned_team:
        query = query.filter(PlaygroundQualityEscalation.assigned_team == str(assigned_team).strip())
    if overdue_only:
        query = query.filter(
            PlaygroundQualityEscalation.status.in_(["open", "acknowledged"]),
            PlaygroundQualityEscalation.due_at < now,
        )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        query = query.filter(PlaygroundQualityEscalation.run_actor_id == ctx.actor_id)

    total = query.count()
    rows = query.order_by(PlaygroundQualityEscalation.created_at.desc()).offset(offset).limit(limit).all()
    overdue = 0
    for row in rows:
        if row.status in {"open", "acknowledged"} and row.due_at < now:
            overdue += 1

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="playground.feedback.triage.escalation.read",
        resource_type="playground_quality_escalation",
        resource_id="queue",
        trace_id=f"trace-playground-triage-escalation-read-{ctx.actor_id}",
    )
    db.commit()
    return PlaygroundQualityEscalationQueueResponse(total=total, overdue=overdue, items=rows)


@router.post(
    "/playground/quality/triage/escalations/{escalation_id}/acknowledge",
    response_model=PlaygroundQualityEscalationResponse,
)
def acknowledge_playground_quality_escalation(
    escalation_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_WRITE | {ROLE_SECURITY_APPROVER})
    escalation = db.query(PlaygroundQualityEscalation).filter_by(escalation_id=escalation_id).first()
    if escalation is None:
        raise HTTPException(status_code=404, detail="Quality escalation not found")
    if ctx.actor_role == ROLE_AGENT_OWNER and escalation.run_actor_id != ctx.actor_id:
        raise HTTPException(status_code=403, detail="Agent Owner can only acknowledge own escalation items.")
    if escalation.status not in {"open", "acknowledged"}:
        raise HTTPException(status_code=409, detail="Only open escalation records can be acknowledged")

    escalation.status = "acknowledged"
    escalation.acknowledged_by = ctx.actor_id
    escalation.acknowledged_at = datetime.utcnow()
    escalation.updated_at = datetime.utcnow()

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="playground.feedback.triage.escalation.acknowledge",
        resource_type="playground_quality_escalation",
        resource_id=escalation_id,
        trace_id=f"trace-playground-triage-escalation-ack-{escalation_id}",
    )
    db.commit()
    db.refresh(escalation)
    return escalation


@router.post(
    "/playground/quality/triage/escalations/{escalation_id}/resolve",
    response_model=PlaygroundQualityEscalationResponse,
)
def resolve_playground_quality_escalation(
    escalation_id: str,
    payload: PlaygroundQualityEscalationResolveRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_WRITE | {ROLE_SECURITY_APPROVER})
    escalation = db.query(PlaygroundQualityEscalation).filter_by(escalation_id=escalation_id).first()
    if escalation is None:
        raise HTTPException(status_code=404, detail="Quality escalation not found")
    if ctx.actor_role == ROLE_AGENT_OWNER and escalation.run_actor_id != ctx.actor_id:
        raise HTTPException(status_code=403, detail="Agent Owner can only resolve own escalation items.")
    if escalation.status == "resolved":
        raise HTTPException(status_code=409, detail="Escalation is already resolved")

    escalation.status = "resolved"
    escalation.resolved_by = ctx.actor_id
    escalation.resolved_at = datetime.utcnow()
    escalation.resolution_note = str(payload.resolution_note).strip()
    escalation.updated_at = datetime.utcnow()

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="playground.feedback.triage.escalation.resolve",
        resource_type="playground_quality_escalation",
        resource_id=escalation_id,
        trace_id=f"trace-playground-triage-escalation-resolve-{escalation_id}",
    )
    db.commit()
    db.refresh(escalation)
    return escalation


@router.post(
    "/playground/quality/triage/escalations/{escalation_id}/notify",
    response_model=PlaygroundQualityEscalationNotifyResponse,
)
def notify_playground_quality_escalation(
    escalation_id: str,
    payload: PlaygroundQualityEscalationNotifyRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_WRITE | {ROLE_SECURITY_APPROVER})
    escalation = db.query(PlaygroundQualityEscalation).filter_by(escalation_id=escalation_id).first()
    if escalation is None:
        raise HTTPException(status_code=404, detail="Quality escalation not found")
    if ctx.actor_role == ROLE_AGENT_OWNER and escalation.run_actor_id != ctx.actor_id:
        raise HTTPException(status_code=403, detail="Agent Owner can only notify own escalation items.")

    now = datetime.utcnow()
    overdue = escalation.status in {"open", "acknowledged"} and escalation.due_at < now
    message = (
        f"{str(payload.message_prefix).strip()}: {escalation.escalation_id} "
        f"[{escalation.priority_tag}/{escalation.severity}] status={escalation.status} "
        f"due_at={escalation.due_at.isoformat()} overdue={str(overdue).lower()}"
    )
    delivery = deliver_escalation_notification(
        channel=str(payload.channel).strip(),
        destination=str(payload.destination).strip(),
        message=message,
    )

    notification = PlaygroundQualityEscalationNotification(
        notification_id=f"pqen-{uuid4().hex[:16]}",
        escalation_id=escalation_id,
        channel=str(payload.channel).strip(),
        destination=str(payload.destination).strip(),
        payload_preview=message[:1024],
        receipt_id=delivery["receipt_id"],
        attempts=int(delivery["attempts"]),
        delivery_status=delivery["delivery_status"],
        error_message=delivery.get("error_message"),
        created_by=ctx.actor_id,
    )
    db.add(notification)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="playground.feedback.triage.escalation.notify",
        resource_type="playground_quality_escalation",
        resource_id=f"{escalation_id}:{str(payload.channel).strip()}",
        trace_id=f"trace-playground-triage-escalation-notify-{escalation_id}",
    )
    db.commit()
    return PlaygroundQualityEscalationNotifyResponse(
        escalation_id=escalation_id,
        notified=bool(delivery["delivered"]),
        channel=str(payload.channel).strip(),
        destination=str(payload.destination).strip(),
        notified_at=now,
        attempts=int(delivery["attempts"]),
        receipt_id=delivery["receipt_id"],
        delivery_status=delivery["delivery_status"],
        error_message=delivery.get("error_message"),
        message=message,
    )


@router.post("/playground/prompts", response_model=PromptRegistryItemResponse)
def create_prompt_registry_item(
    payload: PromptRegistryCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_WRITE)
    labels = json.dumps(_parse_prompt_registry_labels(payload.labels))
    prompt_registry_id = str(uuid4())
    item = PromptRegistryItem(
        prompt_registry_id=prompt_registry_id,
        name=payload.name.strip(),
        description=payload.description.strip(),
        prompt_text=payload.prompt_text.strip(),
        labels=labels,
        latest_version=1,
        status="active",
        created_by=ctx.actor_id,
        updated_by=ctx.actor_id,
    )
    db.add(item)
    db.add(
        PromptRegistryVersion(
            prompt_registry_version_id=str(uuid4()),
            prompt_registry_id=prompt_registry_id,
            version=1,
            prompt_text=payload.prompt_text.strip(),
            change_reason="created",
            created_by=ctx.actor_id,
        )
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="playground.prompt_registry.create",
        resource_type="prompt_registry_item",
        resource_id=prompt_registry_id,
        trace_id=f"trace-{prompt_registry_id}",
    )
    db.commit()
    db.refresh(item)
    return _prompt_registry_item_response(item)


@router.get("/playground/prompts", response_model=list[PromptRegistryItemResponse])
def list_prompt_registry_items(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    require_role(ctx, ROLES_PLAYGROUND_READ)
    query = db.query(PromptRegistryItem).order_by(PromptRegistryItem.updated_at.desc())
    if ctx.actor_role == ROLE_AGENT_OWNER:
        query = query.filter_by(created_by=ctx.actor_id)
    items = query.offset(offset).limit(limit).all()
    return [_prompt_registry_item_response(item) for item in items]


@router.get("/playground/prompts/{prompt_registry_id}", response_model=PromptRegistryItemResponse)
def get_prompt_registry_item(
    prompt_registry_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_READ)
    item = db.query(PromptRegistryItem).filter_by(prompt_registry_id=prompt_registry_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Prompt registry item not found")
    if ctx.actor_role == ROLE_AGENT_OWNER and item.created_by != ctx.actor_id:
        raise HTTPException(status_code=403, detail="Agent Owner can only access own prompt registry items.")
    return _prompt_registry_item_response(item)


@router.put("/playground/prompts/{prompt_registry_id}", response_model=PromptRegistryItemResponse)
def update_prompt_registry_item(
    prompt_registry_id: str,
    payload: PromptRegistryUpdateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_WRITE)
    item = db.query(PromptRegistryItem).filter_by(prompt_registry_id=prompt_registry_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Prompt registry item not found")
    if ctx.actor_role == ROLE_AGENT_OWNER and item.created_by != ctx.actor_id:
        raise HTTPException(status_code=403, detail="Agent Owner can only modify own prompt registry items.")

    next_version = item.latest_version + 1
    if payload.name is not None:
        item.name = payload.name.strip()
    if payload.description is not None:
        item.description = payload.description.strip()
    if payload.prompt_text is not None:
        item.prompt_text = payload.prompt_text.strip()
    if payload.labels is not None:
        item.labels = json.dumps(_parse_prompt_registry_labels(payload.labels))
    item.latest_version = next_version
    item.updated_by = ctx.actor_id

    db.add(
        PromptRegistryVersion(
            prompt_registry_version_id=str(uuid4()),
            prompt_registry_id=prompt_registry_id,
            version=next_version,
            prompt_text=item.prompt_text,
            change_reason=payload.change_reason.strip() or "updated",
            created_by=ctx.actor_id,
        )
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="playground.prompt_registry.update",
        resource_type="prompt_registry_item",
        resource_id=prompt_registry_id,
        trace_id=f"trace-{prompt_registry_id}",
    )
    db.commit()
    db.refresh(item)
    return _prompt_registry_item_response(item)


@router.delete("/playground/prompts/{prompt_registry_id}", response_model=PromptRegistryItemResponse)
def delete_prompt_registry_item(
    prompt_registry_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_WRITE)
    item = db.query(PromptRegistryItem).filter_by(prompt_registry_id=prompt_registry_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Prompt registry item not found")
    if ctx.actor_role == ROLE_AGENT_OWNER and item.created_by != ctx.actor_id:
        raise HTTPException(status_code=403, detail="Agent Owner can only delete own prompt registry items.")
    item.status = "deleted"
    item.updated_by = ctx.actor_id
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="playground.prompt_registry.delete",
        resource_type="prompt_registry_item",
        resource_id=prompt_registry_id,
        trace_id=f"trace-{prompt_registry_id}",
    )
    db.commit()
    db.refresh(item)
    return _prompt_registry_item_response(item)


@router.get("/playground/prompts/{prompt_registry_id}/versions", response_model=list[PromptRegistryVersionResponse])
def list_prompt_registry_versions(
    prompt_registry_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_READ)
    versions = (
        db.query(PromptRegistryVersion)
        .filter_by(prompt_registry_id=prompt_registry_id)
        .order_by(PromptRegistryVersion.version.desc())
        .all()
    )
    return versions


@router.post("/playground/prompts/{prompt_registry_id}/rollback", response_model=PromptRegistryItemResponse)
def rollback_prompt_registry_item(
    prompt_registry_id: str,
    payload: PromptRegistryRollbackRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_WRITE)
    item = db.query(PromptRegistryItem).filter_by(prompt_registry_id=prompt_registry_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Prompt registry item not found")
    if ctx.actor_role == ROLE_AGENT_OWNER and item.created_by != ctx.actor_id:
        raise HTTPException(status_code=403, detail="Agent Owner can only rollback own prompt registry items.")
    source_version = (
        db.query(PromptRegistryVersion)
        .filter_by(prompt_registry_id=prompt_registry_id, version=payload.version)
        .first()
    )
    if not source_version:
        raise HTTPException(status_code=404, detail="Prompt registry version not found")

    next_version = item.latest_version + 1
    item.prompt_text = source_version.prompt_text
    item.latest_version = next_version
    item.updated_by = ctx.actor_id
    db.add(
        PromptRegistryVersion(
            prompt_registry_version_id=str(uuid4()),
            prompt_registry_id=prompt_registry_id,
            version=next_version,
            prompt_text=source_version.prompt_text,
            change_reason=payload.reason.strip() or f"rollback to version {payload.version}",
            created_by=ctx.actor_id,
        )
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="playground.prompt_registry.rollback",
        resource_type="prompt_registry_item",
        resource_id=prompt_registry_id,
        trace_id=f"trace-{prompt_registry_id}",
    )
    db.commit()
    db.refresh(item)
    return _prompt_registry_item_response(item)


@router.post("/playground/prompts/{prompt_registry_id}/promote", response_model=PromptRegistryPromoteResponse)
def promote_prompt_registry_item(
    prompt_registry_id: str,
    payload: PromptRegistryPromoteRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_PLAYGROUND_WRITE)
    item = db.query(PromptRegistryItem).filter_by(prompt_registry_id=prompt_registry_id).first()
    if not item:
        raise HTTPException(status_code=404, detail="Prompt registry item not found")
    if ctx.actor_role == ROLE_AGENT_OWNER and item.created_by != ctx.actor_id:
        raise HTTPException(status_code=403, detail="Agent Owner can only promote own prompt registry items.")

    target_environment = str(payload.target_environment or "dev").strip().lower() or "dev"
    if _is_prod_environment(target_environment):
        require_dual_approval(ctx)

    detected_variables = _extract_prompt_template_variables(item.prompt_text)
    provided_variables = {
        str(key).strip(): str(value)
        for key, value in (payload.render_variables or {}).items()
        if str(key).strip()
    }
    missing_variables = [key for key in detected_variables if key not in provided_variables]
    if payload.require_render_validation and missing_variables:
        raise HTTPException(
            status_code=422,
            detail={
                "error_code": "PROMPT_RENDER_VALIDATION_FAILED",
                "message": "Prompt promotion blocked by missing template variables.",
                "missing_variables": missing_variables,
                "target_environment": target_environment,
                "remediation_hint": "Provide values for all template variables or disable strict render validation.",
            },
        )

    render_preview = _render_prompt_template(item.prompt_text, provided_variables)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="playground.prompt_registry.promote.validate",
        resource_type="prompt_registry_item",
        resource_id=prompt_registry_id,
        trace_id=f"trace-prompt-promote-validate-{prompt_registry_id}",
    )

    promotion_recorded = not payload.preview_only
    if promotion_recorded:
        next_version = item.latest_version + 1
        item.updated_by = ctx.actor_id
        item.latest_version = next_version
        db.add(
            PromptRegistryVersion(
                prompt_registry_version_id=str(uuid4()),
                prompt_registry_id=prompt_registry_id,
                version=next_version,
                prompt_text=item.prompt_text,
                change_reason=(
                    f"promote:{target_environment}:{payload.reason.strip()}"
                    + (f":ticket:{payload.approval_ticket.strip()}" if payload.approval_ticket else "")
                )[:1024],
                created_by=ctx.actor_id,
            )
        )
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="playground.prompt_registry.promote",
            resource_type="prompt_registry_item",
            resource_id=f"{prompt_registry_id}:{target_environment}",
            trace_id=f"trace-prompt-promote-{prompt_registry_id}",
        )

    db.commit()
    db.refresh(item)
    return PromptRegistryPromoteResponse(
        item=_prompt_registry_item_response(item),
        target_environment=target_environment,
        promotion_recorded=promotion_recorded,
        render_preview=render_preview,
        variables_detected=detected_variables,
        missing_variables=missing_variables,
        approval_required=_is_prod_environment(target_environment),
        approval_ticket=payload.approval_ticket.strip() if payload.approval_ticket else None,
    )
