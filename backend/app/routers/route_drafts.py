import json
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import Agent, AuditEvent, BenchmarkRun, RouteDraft, RouteDraftApprovalEvent, ScanRun
from app.policy_constants import ROLE_AGENT_OWNER, ROLE_AI_OPS_APPROVER, ROLE_MASTER_ADMIN, ROLE_SECURITY_APPROVER, ROLE_SUPER_ADMIN
from app.router_constants import (
    ROLES_ROUTE_DRAFT_APPROVE,
    ROLES_ROUTE_DRAFT_READ,
    ROLES_ROUTE_DRAFT_REJECT,
    ROLES_ROUTE_DRAFT_RELEASE,
    ROLES_ROUTE_DRAFT_ROLLBACK,
    ROLES_ROUTE_DRAFT_SUBMIT,
)
from app.schemas import (
    RouteDraftApproveRequest,
    RouteDraftApprovalEventResponse,
    RouteDraftChangeWindowApproveRequest,
    RouteDraftPromoteRequest,
    RouteDraftRejectRequest,
    RouteDraftRollbackLastGoodRequest,
    RouteDraftRollbackRequest,
    RouteDraftResponse,
    RouteDraftSubmitRequest,
)
from app.security import ActorContext, get_actor_context, require_dual_approval, require_mfa, require_role
from app.services.audit import create_audit_event

router = APIRouter()
logger = get_logger(__name__)

ROUTE_DRAFT_EXPIRY_DAYS = 14


def _evaluate_promotion_gates(db: Session, agent_id: str, target_environment: str) -> dict:
    normalized_environment = str(target_environment or "dev").strip().lower() or "dev"
    latest_benchmark = (
        db.query(BenchmarkRun)
        .filter_by(agent_id=agent_id, environment=normalized_environment)
        .order_by(BenchmarkRun.created_at.desc())
        .first()
    )
    if latest_benchmark is None:
        latest_benchmark = (
            db.query(BenchmarkRun)
            .filter_by(agent_id=agent_id)
            .order_by(BenchmarkRun.created_at.desc())
            .first()
        )
    latest_scan = (
        db.query(ScanRun)
        .filter_by(agent_id=agent_id, environment=normalized_environment)
        .order_by(ScanRun.created_at.desc())
        .first()
    )
    if latest_scan is None:
        latest_scan = (
            db.query(ScanRun)
            .filter_by(agent_id=agent_id)
            .order_by(ScanRun.created_at.desc())
            .first()
        )
    latest_contract_check = (
        db.query(AuditEvent)
        .filter_by(action_type="agentic.contract.validate", resource_id=agent_id)
        .order_by(AuditEvent.timestamp.desc())
        .first()
    )
    agent = db.query(Agent).filter_by(agent_id=agent_id).first()

    risk_tier = agent.risk_tier if agent else "medium"
    benchmark_threshold = 75
    if target_environment == "prod":
        benchmark_threshold = 80
    if risk_tier in {"high", "critical"}:
        benchmark_threshold += 5

    scan_fresh = False
    if latest_scan:
        scan_fresh = latest_scan.created_at >= (datetime.utcnow() - timedelta(days=7))

    benchmark_ok = bool(latest_benchmark and latest_benchmark.score >= benchmark_threshold)
    scan_ok = bool(
        latest_scan
        and latest_scan.status == "completed"
        and latest_scan.severity_high_count == 0
        and (target_environment != "prod" or scan_fresh)
    )
    contract_ok = bool(latest_contract_check and latest_contract_check.decision_outcome == "allow")

    return {
        "benchmark_ok": benchmark_ok,
        "scan_ok": scan_ok,
        "contract_ok": contract_ok,
        "risk_tier": risk_tier,
        "benchmark_threshold": benchmark_threshold,
        "scan_fresh": scan_fresh,
    }


def _record_approval_event(
    db: Session,
    draft_id: str,
    action: str,
    state_from: str,
    state_to: str,
    ctx: ActorContext,
    decision: str,
    reason_code: Optional[str] = None,
    evidence_refs: Optional[list[str]] = None,
    change_window_id: Optional[str] = None,
    risk_ticket_ref: Optional[str] = None,
) -> None:
    db.add(
        RouteDraftApprovalEvent(
            approval_event_id=str(uuid4()),
            draft_id=draft_id,
            action=action,
            state_from=state_from,
            state_to=state_to,
            actor_id=ctx.actor_id,
            actor_role=ctx.actor_role,
            decision=decision,
            reason_code=reason_code,
            evidence_refs=json.dumps(evidence_refs or []),
            change_window_id=change_window_id,
            risk_ticket_ref=risk_ticket_ref,
            policy_simulation_status="pass",
            permission_policy_version="v1",
        )
    )


def _expire_if_needed(draft: RouteDraft) -> bool:
    if draft.status == "promoted":
        return False
    if draft.submitted_at and draft.submitted_at < (datetime.utcnow() - timedelta(days=ROUTE_DRAFT_EXPIRY_DAYS)):
        draft.status = "expired"
        draft.state_version += 1
        return True
    return False


@router.post("/route-drafts/{draft_id}/submit", response_model=RouteDraftResponse)
def submit_route_draft(
    draft_id: str,
    payload: RouteDraftSubmitRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ROUTE_DRAFT_SUBMIT)
    require_mfa(ctx)

    if ctx.actor_role == ROLE_AGENT_OWNER:
        agent = db.query(Agent).filter_by(agent_id=payload.agent_id).first()
        if agent and agent.owner_id != ctx.actor_id:
            raise HTTPException(
                status_code=403,
                detail={
                    "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                    "message": "Agent Owner can only submit drafts for agents they own.",
                    "actor_role": ctx.actor_role,
                    "required_scope": "agent.owner_id == requester actor_id",
                    "policy_version": "v1",
                    "decision_trace_id": "authz-route-draft-submit-scope-check",
                    "remediation_hint": "Use Platform Admin or AI Ops Approver for cross-owner submission.",
                },
            )

    draft = db.query(RouteDraft).filter_by(draft_id=draft_id).first()
    state_from = "draft"
    if not draft:
        draft = RouteDraft(
            draft_id=draft_id,
            agent_id=payload.agent_id,
            route_policy_snapshot_id=payload.route_policy_snapshot_id,
            environment=payload.environment,
            status="submitted",
            submitted_by=ctx.actor_id,
            submitted_at=datetime.utcnow(),
            approved_security=False,
            approved_ai_ops=False,
            state_version=1,
        )
        db.add(draft)
    else:
        state_from = draft.status
        draft.status = "submitted"
        draft.submitted_by = ctx.actor_id
        draft.submitted_at = datetime.utcnow()
        draft.rejection_reason = None
        draft.approved_security = False
        draft.approved_ai_ops = False
        draft.state_version += 1

    _record_approval_event(
        db,
        draft_id=draft_id,
        action="submit",
        state_from=state_from,
        state_to="submitted",
        ctx=ctx,
        decision="submitted",
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="route_draft.submit",
        resource_type="route_draft",
        resource_id=draft_id,
        trace_id=f"trace-{draft_id}",
    )
    db.commit()
    db.refresh(draft)
    return draft


@router.post("/route-drafts/{draft_id}/approve", response_model=RouteDraftResponse)
def approve_route_draft(
    draft_id: str,
    payload: RouteDraftApproveRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ROUTE_DRAFT_APPROVE)
    require_mfa(ctx)

    draft = db.query(RouteDraft).filter_by(draft_id=draft_id).first()
    if not draft:
        raise HTTPException(status_code=404, detail="Route draft not found")

    if _expire_if_needed(draft):
        db.commit()
        raise HTTPException(status_code=400, detail="Route draft has expired")

    if draft.submitted_by == ctx.actor_id:
        raise HTTPException(status_code=400, detail="Submitter cannot approve their own draft")

    if ctx.actor_role in {ROLE_MASTER_ADMIN, ROLE_SUPER_ADMIN}:
        if draft.status == "submitted":
            state_from = draft.status
            draft.approved_security = True
            draft.status = "security_approved"
        elif draft.status == "security_approved":
            state_from = draft.status
            draft.approved_ai_ops = True
            draft.status = "aiops_approved"
        else:
            raise HTTPException(status_code=400, detail="Route draft is not in an approvable state")
    elif ctx.actor_role == ROLE_SECURITY_APPROVER:
        if draft.status != "submitted":
            raise HTTPException(status_code=400, detail="Security approval requires submitted state")
        state_from = draft.status
        draft.approved_security = True
        draft.status = "security_approved"
    elif ctx.actor_role == ROLE_AI_OPS_APPROVER:
        if draft.status != "security_approved":
            raise HTTPException(status_code=400, detail="AI Ops approval requires security_approved state")
        state_from = draft.status
        draft.approved_ai_ops = True
        draft.status = "aiops_approved"
    else:
        raise HTTPException(status_code=400, detail="Route draft is not in an approvable state")
    draft.state_version += 1

    _record_approval_event(
        db,
        draft_id=draft_id,
        action="approve",
        state_from=state_from,
        state_to=draft.status,
        ctx=ctx,
        decision="approved",
        reason_code=payload.reason_code,
        evidence_refs=payload.evidence_refs,
        risk_ticket_ref=payload.risk_ticket_ref,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="route_draft.approve",
        resource_type="route_draft",
        resource_id=draft_id,
        trace_id=f"trace-{draft_id}",
    )
    db.commit()
    db.refresh(draft)
    return draft


@router.post("/route-drafts/{draft_id}/reject", response_model=RouteDraftResponse)
def reject_route_draft(
    draft_id: str,
    payload: RouteDraftRejectRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ROUTE_DRAFT_REJECT)
    require_mfa(ctx)

    draft = db.query(RouteDraft).filter_by(draft_id=draft_id).first()
    if not draft:
        raise HTTPException(status_code=404, detail="Route draft not found")

    if _expire_if_needed(draft):
        db.commit()
        raise HTTPException(status_code=400, detail="Route draft has expired")

    if draft.submitted_by == ctx.actor_id:
        raise HTTPException(status_code=400, detail="Submitter cannot reject their own draft")

    state_from = draft.status
    draft.status = "rejected"
    draft.rejection_reason = payload.reason_code
    draft.state_version += 1

    _record_approval_event(
        db,
        draft_id=draft_id,
        action="reject",
        state_from=state_from,
        state_to="rejected",
        ctx=ctx,
        decision="rejected",
        reason_code=payload.reason_code,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="route_draft.reject",
        resource_type="route_draft",
        resource_id=draft_id,
        trace_id=f"trace-{draft_id}",
        decision_outcome="deny",
    )
    db.commit()
    db.refresh(draft)
    return draft


@router.post("/route-drafts/{draft_id}/approve-change-window", response_model=RouteDraftResponse)
def approve_change_window(
    draft_id: str,
    payload: RouteDraftChangeWindowApproveRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ROUTE_DRAFT_RELEASE)
    require_mfa(ctx)

    draft = db.query(RouteDraft).filter_by(draft_id=draft_id).first()
    if not draft:
        raise HTTPException(status_code=404, detail="Route draft not found")

    if _expire_if_needed(draft):
        db.commit()
        raise HTTPException(status_code=400, detail="Route draft has expired")

    if draft.submitted_by == ctx.actor_id:
        raise HTTPException(status_code=400, detail="Submitter cannot approve change window for own draft")

    if draft.status != "aiops_approved":
        raise HTTPException(status_code=400, detail="Change window approval requires aiops_approved state")

    state_from = draft.status
    draft.status = "change_window_approved"
    draft.state_version += 1
    _record_approval_event(
        db,
        draft_id=draft_id,
        action="approve_change_window",
        state_from=state_from,
        state_to="change_window_approved",
        ctx=ctx,
        decision="approved",
        reason_code=payload.reason_code,
        evidence_refs=payload.evidence_refs,
        change_window_id=payload.change_window_id,
        risk_ticket_ref=payload.risk_ticket_ref,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="route_draft.approve_change_window",
        resource_type="route_draft",
        resource_id=draft_id,
        trace_id=f"trace-{draft_id}",
    )
    db.commit()
    db.refresh(draft)
    return draft


@router.post("/route-drafts/{draft_id}/promote", response_model=RouteDraftResponse)
def promote_route_draft(
    draft_id: str,
    payload: RouteDraftPromoteRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "route_draft_promote_start %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "draft_id": draft_id,
                "target_environment": payload.target_environment,
            }
        ),
    )
    require_role(ctx, ROLES_ROUTE_DRAFT_RELEASE)
    require_mfa(ctx)

    draft = db.query(RouteDraft).filter_by(draft_id=draft_id).first()
    if not draft:
        logger.error("route_draft_not_found %s", sanitize_fields({"draft_id": draft_id}))
        raise HTTPException(status_code=404, detail="Route draft not found")

    if _expire_if_needed(draft):
        db.commit()
        raise HTTPException(status_code=400, detail="Route draft has expired")

    if draft.submitted_by == ctx.actor_id:
        raise HTTPException(status_code=400, detail="Submitter cannot promote their own draft")

    if payload.expected_state_version != draft.state_version:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Draft state version mismatch",
                "expected_state_version": payload.expected_state_version,
                "current_state_version": draft.state_version,
            },
        )

    if payload.target_environment.strip().lower() == "prod":
        require_dual_approval(ctx)

    if not (draft.approved_security and draft.approved_ai_ops and draft.status == "change_window_approved"):
        raise HTTPException(status_code=400, detail="Draft is missing required approvals")

    gates = _evaluate_promotion_gates(db, draft.agent_id, payload.target_environment)
    if not (gates["benchmark_ok"] and gates["scan_ok"] and gates["contract_ok"]):
        logger.error(
            "route_draft_promote_failed_gates %s",
            sanitize_fields({"draft_id": draft_id, "actor_id": ctx.actor_id}),
        )
        raise HTTPException(
            status_code=400,
            detail={
                "message": "Draft failed promotion readiness gates",
                "gates": gates,
            },
        )

    state_from = draft.status
    draft.status = "promoted"
    draft.environment = payload.target_environment
    draft.promoted_at = datetime.utcnow()
    draft.state_version += 1

    _record_approval_event(
        db,
        draft_id=draft_id,
        action="promote",
        state_from=state_from,
        state_to="promoted",
        ctx=ctx,
        decision="approved",
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="route_draft.promote",
        resource_type="route_draft",
        resource_id=draft_id,
        trace_id=f"trace-{draft_id}",
    )
    db.commit()
    db.refresh(draft)
    logger.info(
        "route_draft_promoted %s",
        sanitize_fields({"actor_id": ctx.actor_id, "draft_id": draft_id, "target_environment": payload.target_environment}),
    )
    return draft


@router.post("/route-drafts/{draft_id}/rollback-to-draft", response_model=RouteDraftResponse)
def rollback_route_draft(
    draft_id: str,
    payload: RouteDraftRollbackRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ROUTE_DRAFT_ROLLBACK)
    require_mfa(ctx)

    draft = db.query(RouteDraft).filter_by(draft_id=draft_id).first()
    if not draft:
        raise HTTPException(status_code=404, detail="Route draft not found")

    if draft.submitted_by == ctx.actor_id:
        raise HTTPException(status_code=400, detail="Submitter cannot rollback their own draft")

    state_from = draft.status
    draft.status = "draft"
    draft.approved_security = False
    draft.approved_ai_ops = False
    draft.rejection_reason = payload.reason_code
    draft.state_version += 1

    _record_approval_event(
        db,
        draft_id=draft_id,
        action="rollback_to_draft",
        state_from=state_from,
        state_to="draft",
        ctx=ctx,
        decision="approved",
        reason_code=payload.reason_code,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="route_draft.rollback_to_draft",
        resource_type="route_draft",
        resource_id=draft_id,
        trace_id=f"trace-{draft_id}",
        decision_outcome="warn",
    )
    db.commit()
    db.refresh(draft)
    return draft


@router.post("/route-drafts/{draft_id}/rollback-last-good", response_model=RouteDraftResponse)
def rollback_route_to_last_good_snapshot(
    draft_id: str,
    payload: RouteDraftRollbackLastGoodRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ROUTE_DRAFT_RELEASE)
    require_mfa(ctx)

    draft = db.query(RouteDraft).filter_by(draft_id=draft_id).first()
    if not draft:
        raise HTTPException(status_code=404, detail="Route draft not found")

    if payload.expected_state_version != draft.state_version:
        raise HTTPException(
            status_code=409,
            detail={
                "message": "Draft state version mismatch",
                "expected_state_version": payload.expected_state_version,
                "current_state_version": draft.state_version,
            },
        )

    if draft.status != "promoted":
        raise HTTPException(status_code=400, detail="Rollback-to-last-good requires promoted state")

    previous_promoted = (
        db.query(RouteDraft)
        .filter(
            RouteDraft.agent_id == draft.agent_id,
            RouteDraft.environment == draft.environment,
            RouteDraft.status == "promoted",
            RouteDraft.draft_id != draft_id,
            RouteDraft.promoted_at.is_not(None),
        )
        .order_by(RouteDraft.promoted_at.desc())
        .first()
    )
    if not previous_promoted:
        raise HTTPException(status_code=400, detail="No previous promoted snapshot found")

    state_from = draft.status
    draft.route_policy_snapshot_id = previous_promoted.route_policy_snapshot_id
    draft.rejection_reason = payload.reason_code
    draft.state_version += 1

    _record_approval_event(
        db,
        draft_id=draft_id,
        action="rollback_last_good",
        state_from=state_from,
        state_to="promoted",
        ctx=ctx,
        decision="approved",
        reason_code=payload.reason_code,
        evidence_refs=[
            f"previous_draft:{previous_promoted.draft_id}",
            f"previous_snapshot:{previous_promoted.route_policy_snapshot_id}",
        ],
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="route_draft.rollback_last_good",
        resource_type="route_draft",
        resource_id=draft_id,
        trace_id=f"trace-{draft_id}",
        decision_outcome="warn",
    )
    db.commit()
    db.refresh(draft)
    return draft


@router.get("/route-drafts/{draft_id}/approval-history", response_model=list[RouteDraftApprovalEventResponse])
def get_approval_history(
    draft_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ROUTE_DRAFT_READ)
    draft = db.query(RouteDraft).filter_by(draft_id=draft_id).first()
    if not draft:
        raise HTTPException(status_code=404, detail="Route draft not found")
    if ctx.actor_role == ROLE_AGENT_OWNER:
        agent = db.query(Agent).filter_by(agent_id=draft.agent_id).first()
        if not agent or agent.owner_id != ctx.actor_id:
            raise HTTPException(
                status_code=403,
                detail={
                    "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                    "message": "Agent Owner can only access approval history for own agents.",
                    "actor_role": ctx.actor_role,
                    "required_scope": "draft.agent.owner_id == requester actor_id",
                    "policy_version": "v1",
                    "decision_trace_id": "authz-route-draft-scope-check",
                    "remediation_hint": "Use a privileged role or access a draft owned by your actor id.",
                },
            )
    return db.query(RouteDraftApprovalEvent).filter_by(draft_id=draft_id).order_by(RouteDraftApprovalEvent.created_at.asc()).all()


@router.get("/route-drafts", response_model=list[RouteDraftResponse])
def list_route_drafts(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
):
    require_role(ctx, ROLES_ROUTE_DRAFT_READ)
    query = db.query(RouteDraft).order_by(RouteDraft.submitted_at.desc())
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = [row[0] for row in db.query(Agent.agent_id).filter_by(owner_id=ctx.actor_id).all()]
        query = query.filter(RouteDraft.agent_id.in_(owned_agent_ids or ["__no_owned_agents__"]))
    return query.offset(offset).limit(limit).all()
