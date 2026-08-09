from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy.orm import Session

from app.api_errors import validation_error as api_validation_error
from app.database import get_db
from app.domain_constants import (
    PLATFORM_FEEDBACK_ACTIONS,
    PLATFORM_FEEDBACK_ANALYTICS_SINCE_HOURS_DEFAULT,
    PLATFORM_FEEDBACK_QUERY_LIMIT_DEFAULT,
)
from app.logging_utils import get_logger, sanitize_fields
from app.models import OperatorFeedback
from app.router_constants import (
    PLATFORM_FEEDBACK_ACTION_ROLES,
    PLATFORM_FEEDBACK_READ_ROLES,
    PLATFORM_FEEDBACK_WRITE_ROLES,
)
from app.schemas import (
    ControlPlanePostureResponse,
    OperatorFeedbackActionRequest,
    OperatorFeedbackAnalyticsResponse,
    OperatorFeedbackCreateRequest,
    OperatorFeedbackResponse,
    PlatformOperationalStatusResponse,
)
from app.security import ActorContext, get_actor_context, require_role
from app.services.audit import create_audit_event
from app.plane_mode import build_plane_posture, resolve_app_plane
from app.services.control_plane_contract import (
    apply_control_plane_snapshot,
    build_control_plane_contract,
    build_control_plane_liveness,
    build_control_plane_readiness,
    build_control_plane_snapshot,
    build_desired_observed_status,
    build_peer_ack_status,
    record_peer_ack,
    resolve_control_readonly,
    rollback_to_last_known_good,
    set_control_plane_freeze,
)
from app.services.control_plane_leadership import (
    attest_control_plane_leadership,
    build_control_plane_evidence_pack,
    build_control_plane_leadership,
    build_control_plane_ops_summary,
    build_control_plane_release_gate,
    evaluate_control_plane_release_gate,
    verify_attestation_bundle,
)
from app.services.on_plane_coverage import compute_on_plane_coverage
from app.services.plane_reconcile import (
    build_reconcile_posture,
    list_drift_events,
    run_reconcile_and_record,
)
from app.services.platform_operational import (
    build_feedback_analytics,
    build_operational_status,
    normalize_feedback_category,
    normalize_feedback_severity,
)

router = APIRouter()
logger = get_logger(__name__)

ACTION_STATUS_MAP = {
    "acknowledge": "acknowledged",
    "resolve": "resolved",
    "dismiss": "dismissed",
    "escalate": "open",
}

_PLATFORM_READ_FORBIDDEN = {
    403: {"description": "Actor role is not allowed for platform feedback read operations."},
}
_PLATFORM_WRITE_FORBIDDEN = {
    403: {"description": "Actor role is not allowed, or operator feedback capture is disabled by runtime policy (`platform.feedback.enabled=false`)."},
}
_PLATFORM_ACTION_FORBIDDEN = {
    403: {"description": "Actor role is not allowed for feedback triage actions."},
}
_PLATFORM_NOT_FOUND = {
    404: {"description": "Feedback record not found."},
}
_PLATFORM_VALIDATION = {
    422: {"description": "Validation error (missing comment, invalid action, etc.)."},
}


def _rate_limit_status(request: Request) -> dict:
    limiter = getattr(request.app.state, "rate_limiter", None)
    if limiter is None:
        return {}
    return limiter.runtime_status()


def _reject_if_control_readonly(db: Session) -> None:
    if resolve_control_readonly(db):
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "PLANE_CONTROL_READONLY",
                "message": "Control-plane mutations are frozen (PLANE_CONTROL_READONLY or runtime freeze).",
                "hint": "Clear runtime freeze via POST /platform/control-plane/freeze, or unset PLANE_CONTROL_READONLY.",
            },
        )

@router.get(
    "/platform/operational-status",
    response_model=PlatformOperationalStatusResponse,
    summary="Platform operational posture",
    description=(
        "Returns maintenance mode, slow-response threshold, feedback capture policy, and component health "
        "for operator banners. Reads runtime-config keys `platform.maintenance_mode`, "
        "`platform.maintenance_message`, `platform.slow_response_threshold_ms`, and `platform.feedback.enabled`. "
        "No authentication required."
    ),
    responses={
        200: {"description": "Operational posture for UI banners and monitoring."},
    },
)
def get_platform_operational_status(
    request: Request,
    db: Session = Depends(get_db),
):
    return build_operational_status(db, _rate_limit_status(request))


@router.get(
    "/platform/control-plane",
    response_model=ControlPlanePostureResponse,
    summary="Control plane isolation posture",
    description=(
        "Returns APP_PLANE isolation mode (all|control|data), scheduler posture, architecture §12 "
        "target flags, policy-generation fingerprint, optional peer probe / drift status, "
        "plane-rejection counters, and on-plane inference coverage. "
        "Requires a platform feedback read role (admin/auditor)."
    ),
    responses={
        200: {"description": "Control/data plane posture including on-plane coverage and reconcile drift."},
        **_PLATFORM_READ_FORBIDDEN,
    },
)
def get_platform_control_plane(
    request: Request,
    environment: Optional[str] = Query(default=None, description="Optional CostEvent environment filter."),
    window_hours: int = Query(default=24, ge=1, le=720, description="Coverage window in hours."),
    probe_peer: bool = Query(
        default=True,
        description="When true, probe DATA_PLANE_PEER_URL / CONTROL_PLANE_PEER_URL and compare fingerprints.",
    ),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_READ_ROLES)
    plane = getattr(request.app.state, "app_plane", None) or resolve_app_plane()
    window_start = datetime.now(timezone.utc) - timedelta(hours=int(window_hours))
    coverage = compute_on_plane_coverage(db, window_start=window_start, environment=environment)
    reconcile = build_reconcile_posture(
        db,
        plane=plane,
        probe_peer=bool(probe_peer),
        on_plane_coverage=coverage,
    )
    posture = build_plane_posture(
        plane=plane,
        on_plane_coverage=coverage,
        policy_generation=reconcile.get("policy_generation"),
        published_policy_generation=reconcile.get("published_policy_generation"),
        peer=reconcile.get("peer"),
        drift_status=reconcile.get("drift_status"),
        rejection_stats=reconcile.get("rejection_stats"),
        gate=reconcile.get("gate"),
        last_reconcile=reconcile.get("last_reconcile"),
        drift_events_recent=reconcile.get("drift_events_recent"),
        slos=reconcile.get("slos"),
    )
    try:
        posture["desired_observed"] = build_desired_observed_status(
            db,
            policy_generation=reconcile.get("policy_generation"),
            published=reconcile.get("published_policy_generation"),
            drift_status=reconcile.get("drift_status"),
            peer=reconcile.get("peer"),
            gate=reconcile.get("gate"),
        )
        posture["contract"] = build_control_plane_contract(db)
        posture["control_readonly"] = resolve_control_readonly(db)
    except Exception:
        posture["desired_observed"] = None
        posture["contract"] = None
        posture["control_readonly"] = resolve_control_readonly(db)
    try:
        ops = build_control_plane_ops_summary(db)
        posture["leadership_summary"] = {
            "release_gate_last_passed": ops.get("release_gate_last_passed"),
            "gate_streak": ops.get("release_gate_streak"),
            "gate_streak_required": ops.get("release_gate_streak_required"),
            "attestation_fresh": ops.get("attestation_fresh"),
            "attestation_age_hours": ops.get("attestation_age_hours"),
            "last_evidence_pack_id": ops.get("last_evidence_pack_id"),
            "ready": ops.get("ready"),
            "control_readonly": ops.get("control_readonly"),
            "contract_version": ops.get("contract_version"),
            "last_known_good_fingerprint": ops.get("last_known_good_fingerprint"),
            "last_snapshot_id": ops.get("last_snapshot_id"),
            "alive": ops.get("alive"),
            "peer_ack_matches_published": ops.get("peer_ack_matches_published"),
            "last_rollback_id": ops.get("last_rollback_id"),
            "advisory": ops.get("advisory"),
            "marketing_claim_allowed": False,
        }
    except Exception:
        posture["leadership_summary"] = {
            "marketing_claim_allowed": False,
            "error": "unavailable",
        }
    logger.info(
        "platform_control_plane_posture_served %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "app_plane": posture.get("app_plane"),
                "isolation_mode": posture.get("isolation_mode"),
                "drift_status": posture.get("drift_status"),
                "policy_fingerprint": (posture.get("policy_generation") or {}).get("fingerprint"),
                "on_plane_coverage_percent": (posture.get("on_plane_coverage") or {}).get(
                    "on_plane_coverage_percent"
                ),
            }
        ),
    )
    return posture


@router.post(
    "/platform/control-plane/reconcile",
    response_model=ControlPlanePostureResponse,
    summary="Force control/data plane reconcile",
    description=(
        "Runs an immediate peer probe + policy-generation reconcile, records a drift event, "
        "updates the fail-closed gate, and returns full control-plane posture. "
        "Optional `attest=true` attests CPLI; optional `evaluate_gate=true` persists a release-gate "
        "evaluation. Audited as `platform.plane.reconcile` (+ attest/gate audits when requested). "
        "Requires PLATFORM_FEEDBACK_WRITE_ROLES."
    ),
    responses={
        200: {"description": "Reconcile completed; posture includes drift event and gate state."},
        **_PLATFORM_WRITE_FORBIDDEN,
    },
)
def post_platform_control_plane_reconcile(
    request: Request,
    environment: Optional[str] = Query(default=None, description="Optional CostEvent environment filter."),
    window_hours: int = Query(default=24, ge=1, le=720, description="Coverage window in hours."),
    attest: bool = Query(default=False, description="Also attest CPLI after reconcile."),
    evaluate_gate: bool = Query(
        default=False,
        description="Also persist an audited release-gate evaluation after reconcile.",
    ),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_WRITE_ROLES)
    _reject_if_control_readonly(db)
    plane = getattr(request.app.state, "app_plane", None) or resolve_app_plane()
    window_start = datetime.now(timezone.utc) - timedelta(hours=int(window_hours))
    coverage = compute_on_plane_coverage(db, window_start=window_start, environment=environment)
    reconcile = run_reconcile_and_record(
        db,
        plane=plane,
        probe_peer=True,
        source="api.reconcile",
        on_plane_coverage=coverage,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="platform.plane.reconcile",
        resource_type="control_plane",
        resource_id=str(plane),
        trace_id=f"plane-reconcile-{uuid4().hex[:12]}",
        decision_outcome="allow",
        policy_version="plane-v1",
        actor_role=ctx.actor_role,
        action_context={
            "drift_status": reconcile.get("drift_status"),
            "fingerprint": (reconcile.get("policy_generation") or {}).get("fingerprint"),
            "published_fingerprint": (reconcile.get("published_policy_generation") or {}).get(
                "fingerprint"
            ),
            "peer_reachable": (reconcile.get("peer") or {}).get("reachable"),
            "inference_allowed": (reconcile.get("gate") or {}).get("inference_allowed"),
            "slos_ok": (reconcile.get("slos") or {}).get("overall_within_slo"),
            "attest": bool(attest),
            "evaluate_gate": bool(evaluate_gate),
        },
    )
    attestation = None
    if attest:
        attestation = attest_control_plane_leadership(
            db,
            actor_id=ctx.actor_id,
            window_hours=window_hours,
            environment=environment,
            probe_peer=False,
        )
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="platform.plane.attest",
            resource_type="control_plane_attestation",
            resource_id=str(attestation.get("attestation_id") or "unknown"),
            trace_id=f"plane-attest-{uuid4().hex[:12]}",
            decision_outcome="allow",
            policy_version="plane-v1",
            actor_role=ctx.actor_role,
            action_context={
                "score": (attestation.get("scorecard") or {}).get("score"),
                "band": (attestation.get("scorecard") or {}).get("band"),
                "signed": (attestation.get("signature") or {}).get("signed"),
                "source": "reconcile_attest",
                "marketing_claim_allowed": False,
            },
        )
    release_gate = None
    if evaluate_gate:
        release_gate = evaluate_control_plane_release_gate(
            db,
            actor_id=ctx.actor_id,
            window_hours=window_hours,
            environment=environment,
            probe_peer=False,
        )
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="platform.plane.release_gate_evaluate",
            resource_type="control_plane_release_gate",
            resource_id=str(release_gate.get("evaluation_id") or "unknown"),
            trace_id=f"plane-gate-{uuid4().hex[:12]}",
            decision_outcome="allow" if release_gate.get("passed") else "deny",
            policy_version="plane-v1",
            actor_role=ctx.actor_role,
            action_context={
                "passed": release_gate.get("passed"),
                "failed_checks": release_gate.get("failed_checks"),
                "score": release_gate.get("score"),
                "ci_exit_code_hint": (release_gate.get("ci") or {}).get("exit_code_hint"),
                "source": "reconcile_evaluate_gate",
                "marketing_claim_allowed": False,
            },
        )
    db.commit()
    posture = build_plane_posture(
        plane=plane,
        on_plane_coverage=coverage,
        policy_generation=reconcile.get("policy_generation"),
        published_policy_generation=reconcile.get("published_policy_generation"),
        peer=reconcile.get("peer"),
        drift_status=reconcile.get("drift_status"),
        rejection_stats=reconcile.get("rejection_stats"),
        gate=reconcile.get("gate"),
        last_reconcile=reconcile,
        drift_events_recent=reconcile.get("drift_events_recent"),
        slos=reconcile.get("slos"),
    )
    try:
        posture["desired_observed"] = build_desired_observed_status(
            db,
            policy_generation=reconcile.get("policy_generation"),
            published=reconcile.get("published_policy_generation"),
            drift_status=reconcile.get("drift_status"),
            peer=reconcile.get("peer"),
            gate=reconcile.get("gate"),
        )
        posture["contract"] = build_control_plane_contract(db)
        posture["control_readonly"] = resolve_control_readonly(db)
    except Exception:
        posture["desired_observed"] = None
        posture["contract"] = None
        posture["control_readonly"] = resolve_control_readonly(db)
    if reconcile.get("last_known_good"):
        posture["last_known_good"] = reconcile.get("last_known_good")
    # Optional ceremony fields (ignored by response_model extras if strict; returned as dict overlay).
    if attestation is not None:
        posture["leadership_attestation"] = {
            "attestation_id": attestation.get("attestation_id"),
            "score": (attestation.get("scorecard") or {}).get("score"),
            "band": (attestation.get("scorecard") or {}).get("band"),
            "signed": (attestation.get("signature") or {}).get("signed"),
            "marketing_claim_allowed": False,
        }
    if release_gate is not None:
        posture["release_gate"] = {
            "evaluation_id": release_gate.get("evaluation_id"),
            "passed": release_gate.get("passed"),
            "failed_checks": release_gate.get("failed_checks"),
            "ci": release_gate.get("ci"),
            "marketing_claim_allowed": False,
        }
    logger.info(
        "platform_control_plane_reconcile %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "drift_status": posture.get("drift_status"),
                "fingerprint": (posture.get("policy_generation") or {}).get("fingerprint"),
                "attest": bool(attest),
                "evaluate_gate": bool(evaluate_gate),
            }
        ),
    )
    return posture


@router.get(
    "/platform/control-plane/drift-events",
    summary="List recent plane drift/reconcile events",
    description=(
        "Returns in-process drift event history (fingerprint changes, peer unreachable, operator reconcile). "
        "Requires PLATFORM_FEEDBACK_READ_ROLES."
    ),
    responses={
        200: {"description": "Recent drift events newest-first."},
        **_PLATFORM_READ_FORBIDDEN,
    },
)
def get_platform_control_plane_drift_events(
    limit: int = Query(default=20, ge=1, le=50),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_READ_ROLES)
    events = list_drift_events(limit, db=db)
    logger.info(
        "platform_control_plane_drift_events_served %s",
        sanitize_fields({"actor_id": ctx.actor_id, "count": len(events)}),
    )
    return {"events": events, "count": len(events)}


@router.get(
    "/platform/control-plane/leadership",
    summary="Control Plane Leadership Index (CPLI)",
    description=(
        "Engineering scorecard (max 20) for control-plane maturity: isolation, hot publish, "
        "durable drift, fail-closed, measured SLOs, active reconcile, honesty fence. "
        "Does not authorize marketing leadership claims. Requires PLATFORM_FEEDBACK_READ_ROLES."
    ),
    responses={
        200: {"description": "CPLI scorecard with dimensions, blockers, and last attestation."},
        **_PLATFORM_READ_FORBIDDEN,
    },
)
def get_platform_control_plane_leadership(
    environment: Optional[str] = Query(default=None),
    window_hours: int = Query(default=24, ge=1, le=720),
    probe_peer: bool = Query(default=False),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_READ_ROLES)
    scorecard = build_control_plane_leadership(
        db,
        window_hours=window_hours,
        environment=environment,
        probe_peer=bool(probe_peer),
    )
    logger.info(
        "platform_control_plane_leadership_served %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "score": scorecard.get("score"),
                "band": scorecard.get("band"),
            }
        ),
    )
    return scorecard


@router.post(
    "/platform/control-plane/attest",
    summary="Attest control-plane leadership posture",
    description=(
        "Builds a CPLI attestation bundle, HMAC-signs when SESSION_TOKEN_SIGNING_KEYS is set, "
        "persists to `plane.leadership_attestation_json`, and audits `platform.plane.attest`. "
        "Requires PLATFORM_FEEDBACK_WRITE_ROLES. Never sets marketing_claim_allowed=true."
    ),
    responses={
        200: {"description": "Attestation bundle with signature metadata."},
        **_PLATFORM_WRITE_FORBIDDEN,
    },
)
def post_platform_control_plane_attest(
    environment: Optional[str] = Query(default=None),
    window_hours: int = Query(default=24, ge=1, le=720),
    probe_peer: bool = Query(default=True),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_WRITE_ROLES)
    _reject_if_control_readonly(db)
    bundle = attest_control_plane_leadership(
        db,
        actor_id=ctx.actor_id,
        window_hours=window_hours,
        environment=environment,
        probe_peer=bool(probe_peer),
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="platform.plane.attest",
        resource_type="control_plane_attestation",
        resource_id=str(bundle.get("attestation_id") or "unknown"),
        trace_id=f"plane-attest-{uuid4().hex[:12]}",
        decision_outcome="allow",
        policy_version="plane-v1",
        actor_role=ctx.actor_role,
        action_context={
            "score": (bundle.get("scorecard") or {}).get("score"),
            "band": (bundle.get("scorecard") or {}).get("band"),
            "signed": (bundle.get("signature") or {}).get("signed"),
            "marketing_claim_allowed": False,
        },
    )
    db.commit()
    logger.info(
        "platform_control_plane_attested %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "attestation_id": bundle.get("attestation_id"),
                "score": (bundle.get("scorecard") or {}).get("score"),
            }
        ),
    )
    return bundle


@router.get(
    "/platform/control-plane/attest/verify",
    summary="Verify latest control-plane leadership attestation",
    description=(
        "Recomputes HMAC/content-hash over the latest `plane.leadership_attestation_json` bundle. "
        "Requires PLATFORM_FEEDBACK_READ_ROLES. Does not authorize marketing claims."
    ),
    responses={
        200: {"description": "Verification result for the latest attestation."},
        **_PLATFORM_READ_FORBIDDEN,
    },
)
def get_platform_control_plane_attest_verify(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_READ_ROLES)
    scorecard = build_control_plane_leadership(db, window_hours=24, probe_peer=False)
    last = scorecard.get("last_attestation")
    verification = scorecard.get("last_attestation_verification") or verify_attestation_bundle(
        last if isinstance(last, dict) else None
    )
    logger.info(
        "platform_control_plane_attest_verified %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "valid": verification.get("valid"),
                "attestation_id": verification.get("attestation_id"),
            }
        ),
    )
    return {
        "verification": verification,
        "attestation_id": (last or {}).get("attestation_id") if isinstance(last, dict) else None,
        "score": (last or {}).get("scorecard", {}).get("score") if isinstance(last, dict) else None,
        "band": (last or {}).get("scorecard", {}).get("band") if isinstance(last, dict) else None,
        "marketing_claim_allowed": False,
        "attestation_history": scorecard.get("attestation_history") or [],
    }


@router.get(
    "/platform/control-plane/release-gate",
    summary="Control-plane engineering release gate",
    description=(
        "Checklist for engineering release readiness: CPLI band, attestation present/valid/fresh, "
        "fingerprint alignment, drift, optional HMAC. Isolation is advisory on APP_PLANE=all. "
        "Never authorizes marketing claims. Requires PLATFORM_FEEDBACK_READ_ROLES."
    ),
    responses={
        200: {"description": "Release-gate checklist with pass/fail checks."},
        **_PLATFORM_READ_FORBIDDEN,
    },
)
def get_platform_control_plane_release_gate(
    environment: Optional[str] = Query(default=None),
    window_hours: int = Query(default=24, ge=1, le=720),
    probe_peer: bool = Query(default=False),
    require_hmac: Optional[bool] = Query(
        default=None,
        description="Override HMAC requirement; default uses PLANE_RELEASE_GATE_REQUIRE_HMAC env.",
    ),
    max_attestation_age_hours: int = Query(default=168, ge=1, le=720),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_READ_ROLES)
    gate = build_control_plane_release_gate(
        db,
        window_hours=window_hours,
        environment=environment,
        probe_peer=bool(probe_peer),
        require_hmac=require_hmac,
        max_attestation_age_hours=max_attestation_age_hours,
    )
    logger.info(
        "platform_control_plane_release_gate_served %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "passed": gate.get("passed"),
                "failed": gate.get("failed_checks"),
            }
        ),
    )
    return gate


@router.post(
    "/platform/control-plane/release-gate/evaluate",
    summary="Persist control-plane release-gate evaluation",
    description=(
        "Evaluates the engineering release gate, appends to `plane.release_gate_history_json`, "
        "and audits `platform.plane.release_gate_evaluate`. Returns CI go/no-go hints. "
        "Requires PLATFORM_FEEDBACK_WRITE_ROLES. Never authorizes marketing claims."
    ),
    responses={
        200: {"description": "Persisted release-gate evaluation with history and CI hints."},
        **_PLATFORM_WRITE_FORBIDDEN,
    },
)
def post_platform_control_plane_release_gate_evaluate(
    environment: Optional[str] = Query(default=None),
    window_hours: int = Query(default=24, ge=1, le=720),
    probe_peer: bool = Query(default=False),
    require_hmac: Optional[bool] = Query(default=None),
    max_attestation_age_hours: int = Query(default=168, ge=1, le=720),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_WRITE_ROLES)
    _reject_if_control_readonly(db)
    gate = evaluate_control_plane_release_gate(
        db,
        actor_id=ctx.actor_id,
        window_hours=window_hours,
        environment=environment,
        probe_peer=bool(probe_peer),
        require_hmac=require_hmac,
        max_attestation_age_hours=max_attestation_age_hours,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="platform.plane.release_gate_evaluate",
        resource_type="control_plane_release_gate",
        resource_id=str(gate.get("evaluation_id") or "unknown"),
        trace_id=f"plane-gate-{uuid4().hex[:12]}",
        decision_outcome="allow" if gate.get("passed") else "deny",
        policy_version="plane-v1",
        actor_role=ctx.actor_role,
        action_context={
            "passed": gate.get("passed"),
            "failed_checks": gate.get("failed_checks"),
            "score": gate.get("score"),
            "ci_exit_code_hint": (gate.get("ci") or {}).get("exit_code_hint"),
            "marketing_claim_allowed": False,
        },
    )
    db.commit()
    logger.info(
        "platform_control_plane_release_gate_evaluated %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "evaluation_id": gate.get("evaluation_id"),
                "passed": gate.get("passed"),
            }
        ),
    )
    return gate


@router.get(
    "/platform/control-plane/evidence-pack",
    summary="Export control-plane engineering evidence pack",
    description=(
        "Bundles CPLI scorecard, release-gate checks, last attestation (+ verify), history, and "
        "recent drift events for audit/release review. HMAC-signs when SESSION_TOKEN_SIGNING_KEYS "
        "is set. Never sets marketing_claim_allowed=true. Requires PLATFORM_FEEDBACK_READ_ROLES."
    ),
    responses={
        200: {"description": "Evidence pack JSON suitable for download/export."},
        **_PLATFORM_READ_FORBIDDEN,
    },
)
def get_platform_control_plane_evidence_pack(
    environment: Optional[str] = Query(default=None),
    window_hours: int = Query(default=24, ge=1, le=720),
    probe_peer: bool = Query(default=True),
    require_hmac: Optional[bool] = Query(default=None),
    max_attestation_age_hours: int = Query(default=168, ge=1, le=720),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_READ_ROLES)
    pack = build_control_plane_evidence_pack(
        db,
        window_hours=window_hours,
        environment=environment,
        probe_peer=bool(probe_peer),
        require_hmac=require_hmac,
        max_attestation_age_hours=max_attestation_age_hours,
        actor_id=ctx.actor_id,
        persist=False,
    )
    logger.info(
        "platform_control_plane_evidence_pack_served %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "pack_id": pack.get("pack_id"),
                "gate_passed": (pack.get("release_gate") or {}).get("passed"),
                "signed": (pack.get("signature") or {}).get("signed"),
            }
        ),
    )
    return pack


@router.post(
    "/platform/control-plane/evidence-pack",
    summary="Mint control-plane engineering evidence pack",
    description=(
        "Builds and persists an HMAC/hash-signed evidence pack for release ceremonies. "
        "Audits `platform.plane.evidence_pack`. Requires PLATFORM_FEEDBACK_WRITE_ROLES. "
        "Never authorizes marketing claims."
    ),
    responses={
        200: {"description": "Minted evidence pack with signature and promotion readiness."},
        **_PLATFORM_WRITE_FORBIDDEN,
    },
)
def post_platform_control_plane_evidence_pack(
    environment: Optional[str] = Query(default=None),
    window_hours: int = Query(default=24, ge=1, le=720),
    probe_peer: bool = Query(default=True),
    require_hmac: Optional[bool] = Query(default=None),
    max_attestation_age_hours: int = Query(default=168, ge=1, le=720),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_WRITE_ROLES)
    _reject_if_control_readonly(db)
    pack = build_control_plane_evidence_pack(
        db,
        window_hours=window_hours,
        environment=environment,
        probe_peer=bool(probe_peer),
        require_hmac=require_hmac,
        max_attestation_age_hours=max_attestation_age_hours,
        actor_id=ctx.actor_id,
        persist=True,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="platform.plane.evidence_pack",
        resource_type="control_plane_evidence_pack",
        resource_id=str(pack.get("pack_id") or "unknown"),
        trace_id=f"plane-pack-{uuid4().hex[:12]}",
        decision_outcome="allow",
        policy_version="plane-v1",
        actor_role=ctx.actor_role,
        action_context={
            "gate_passed": (pack.get("release_gate") or {}).get("passed"),
            "promotion_ready": (pack.get("promotion_readiness") or {}).get("ready"),
            "score": (pack.get("scorecard") or {}).get("score"),
            "signed": (pack.get("signature") or {}).get("signed"),
            "marketing_claim_allowed": False,
        },
    )
    db.commit()
    logger.info(
        "platform_control_plane_evidence_pack_minted %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "pack_id": pack.get("pack_id"),
                "promotion_ready": (pack.get("promotion_readiness") or {}).get("ready"),
            }
        ),
    )
    return pack


@router.get(
    "/platform/control-plane/promotion-readiness",
    summary="Control-plane engineering promotion readiness",
    description=(
        "Reports consecutive release-gate pass streak vs PLANE_RELEASE_GATE_STREAK_REQUIRED, "
        "plus live CPLI/attestation posture. Engineering-only; never authorizes marketing claims. "
        "Requires PLATFORM_FEEDBACK_READ_ROLES."
    ),
    responses={
        200: {"description": "Promotion readiness scorecard."},
        **_PLATFORM_READ_FORBIDDEN,
    },
)
def get_platform_control_plane_promotion_readiness(
    environment: Optional[str] = Query(default=None),
    window_hours: int = Query(default=24, ge=1, le=720),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_READ_ROLES)
    scorecard = build_control_plane_leadership(
        db,
        window_hours=window_hours,
        environment=environment,
        probe_peer=False,
    )
    readiness = scorecard.get("promotion_readiness") or {}
    logger.info(
        "platform_control_plane_promotion_readiness_served %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "ready": readiness.get("ready"),
                "streak": readiness.get("streak"),
            }
        ),
    )
    return {
        "generated_at": scorecard.get("generated_at"),
        "promotion_readiness": readiness,
        "score": scorecard.get("score"),
        "band": scorecard.get("band"),
        "release_gate_passed": (scorecard.get("release_gate") or {}).get("passed"),
        "ci": (scorecard.get("release_gate") or {}).get("ci"),
        "marketing_claim_allowed": False,
    }


@router.get(
    "/platform/control-plane/contract",
    summary="Control-plane contract and capabilities",
    description=(
        "Returns versioned control-plane contract, capability inventory, and best-practice guidance. "
        "Requires PLATFORM_FEEDBACK_READ_ROLES."
    ),
    responses={
        200: {"description": "Contract version, capabilities, and operator guidance."},
        **_PLATFORM_READ_FORBIDDEN,
    },
)
def get_platform_control_plane_contract(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_READ_ROLES)
    return build_control_plane_contract(db)


@router.get(
    "/platform/control-plane/ready",
    summary="Control-plane readiness probe",
    description=(
        "Kubernetes-style readiness for control-plane duties: policy generation, published state, "
        "gate availability, last-known-good. Returns HTTP 503 when not ready. "
        "Requires PLATFORM_FEEDBACK_READ_ROLES."
    ),
    responses={
        200: {"description": "Control plane ready."},
        503: {"description": "Control plane not ready."},
        **_PLATFORM_READ_FORBIDDEN,
    },
)
def get_platform_control_plane_ready(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_READ_ROLES)
    readiness = build_control_plane_readiness(db)
    if not readiness.get("ready"):
        raise HTTPException(status_code=503, detail=readiness)
    return readiness


@router.get(
    "/platform/control-plane/snapshot",
    summary="Export control-plane desired/observed snapshot",
    description=(
        "GitOps/audit snapshot of desired vs observed policy state, readiness, gate, and drift events. "
        "Requires PLATFORM_FEEDBACK_READ_ROLES. Never authorizes marketing claims."
    ),
    responses={
        200: {"description": "Control-plane snapshot JSON."},
        **_PLATFORM_READ_FORBIDDEN,
    },
)
def get_platform_control_plane_snapshot(
    persist_summary: bool = Query(default=False),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_READ_ROLES)
    return build_control_plane_snapshot(
        db,
        actor_id=ctx.actor_id,
        persist_summary=bool(persist_summary),
    )


@router.post(
    "/platform/control-plane/snapshot",
    summary="Mint control-plane snapshot (persisted summary)",
    description=(
        "Builds a control-plane snapshot and persists a summary to runtime_config. "
        "Audits `platform.plane.snapshot`. Blocked when PLANE_CONTROL_READONLY is set. "
        "Requires PLATFORM_FEEDBACK_WRITE_ROLES."
    ),
    responses={
        200: {"description": "Minted snapshot with canonical hash."},
        **_PLATFORM_WRITE_FORBIDDEN,
    },
)
def post_platform_control_plane_snapshot(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_WRITE_ROLES)
    _reject_if_control_readonly(db)
    snap = build_control_plane_snapshot(db, actor_id=ctx.actor_id, persist_summary=True)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="platform.plane.snapshot",
        resource_type="control_plane_snapshot",
        resource_id=str(snap.get("snapshot_id") or "unknown"),
        trace_id=f"plane-snap-{uuid4().hex[:12]}",
        decision_outcome="allow",
        policy_version="plane-v1",
        actor_role=ctx.actor_role,
        action_context={
            "fingerprint": (snap.get("policy_generation") or {}).get("fingerprint"),
            "ready": (snap.get("readiness") or {}).get("ready"),
            "canonical_sha256": snap.get("canonical_sha256"),
            "marketing_claim_allowed": False,
        },
    )
    db.commit()
    return snap


@router.post(
    "/platform/control-plane/snapshot/apply",
    summary="Apply pinned snapshot fence (GitOps restore)",
    description=(
        "Re-publishes a stored snapshot's policy generation fingerprint as the hot fence. "
        "Requires `canonical_sha256` when `PLANE_SNAPSHOT_APPLY_REQUIRE_HASH` is enabled (default). "
        "Audits `platform.plane.snapshot_apply`. Blocked by control-plane freeze. "
        "Requires PLATFORM_FEEDBACK_WRITE_ROLES. Never authorizes marketing claims."
    ),
    responses={
        200: {"description": "Snapshot fence applied."},
        **_PLATFORM_WRITE_FORBIDDEN,
    },
)
def post_platform_control_plane_snapshot_apply(
    snapshot_id: Optional[str] = Query(default=None, max_length=64),
    canonical_sha256: Optional[str] = Query(default=None, max_length=128),
    reason: str = Query(default="", max_length=500),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_WRITE_ROLES)
    _reject_if_control_readonly(db)
    if not (snapshot_id or "").strip() and not (canonical_sha256 or "").strip():
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "PLANE_SNAPSHOT_SELECTOR_REQUIRED",
                "message": "Provide snapshot_id and/or canonical_sha256.",
            },
        )
    result = apply_control_plane_snapshot(
        db,
        snapshot_id=snapshot_id,
        canonical_sha256=canonical_sha256,
        actor_id=ctx.actor_id,
        reason=reason,
    )
    if not result.get("ok"):
        code = str(result.get("error_code") or "")
        status = 409 if code.startswith("PLANE_SNAPSHOT_") else 400
        raise HTTPException(status_code=status, detail=result)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="platform.plane.snapshot_apply",
        resource_type="control_plane_snapshot",
        resource_id=str(result.get("snapshot_id") or result.get("apply_id") or "unknown"),
        trace_id=f"plane-snap-apply-{uuid4().hex[:12]}",
        decision_outcome="allow",
        policy_version="plane-v2",
        actor_role=ctx.actor_role,
        action_context={
            "apply_id": result.get("apply_id"),
            "from_fingerprint": result.get("from_fingerprint"),
            "to_fingerprint": result.get("to_fingerprint"),
            "canonical_sha256": result.get("canonical_sha256"),
            "hash_verified": result.get("hash_verified"),
            "reason": (reason or "")[:200],
            "marketing_claim_allowed": False,
        },
    )
    db.commit()
    return result


@router.get(
    "/platform/control-plane/live",
    summary="Control-plane liveness probe",
    description=(
        "Kubernetes-style liveness: process is up. Does not imply readiness for control-plane duties. "
        "Unauthenticated for probe scrapers (shared plane path)."
    ),
    responses={200: {"description": "Process alive."}},
)
def get_platform_control_plane_live():
    return build_control_plane_liveness()


@router.post(
    "/platform/control-plane/freeze",
    summary="Set audited control-plane change freeze",
    description=(
        "Enable/disable runtime change freeze (`plane.control_readonly`). "
        "Env `PLANE_CONTROL_READONLY` always overrides and blocks API unfreeze. "
        "Audits `platform.plane.freeze`. Requires PLATFORM_FEEDBACK_WRITE_ROLES."
    ),
    responses={
        200: {"description": "Freeze state updated (or env-blocked)."},
        **_PLATFORM_WRITE_FORBIDDEN,
    },
)
def post_platform_control_plane_freeze(
    enabled: bool = Query(..., description="True to freeze mutations; false to clear runtime freeze."),
    reason: str = Query(default="", max_length=500),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_WRITE_ROLES)
    result = set_control_plane_freeze(
        db,
        enabled=bool(enabled),
        actor_id=ctx.actor_id,
        reason=reason,
    )
    if not result.get("ok"):
        raise HTTPException(status_code=409, detail=result)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="platform.plane.freeze",
        resource_type="control_plane_freeze",
        resource_id="runtime",
        trace_id=f"plane-freeze-{uuid4().hex[:12]}",
        decision_outcome="allow",
        policy_version="plane-v2",
        actor_role=ctx.actor_role,
        action_context={
            "enabled": bool(enabled),
            "control_readonly": result.get("control_readonly"),
            "sources": result.get("control_readonly_sources"),
            "reason": (reason or "")[:200],
            "marketing_claim_allowed": False,
        },
    )
    db.commit()
    return result


@router.post(
    "/platform/control-plane/rollback-lkg",
    summary="Rollback published fence to last-known-good",
    description=(
        "Re-publishes the last-known-good fingerprint as the hot policy fence "
        "(data-plane continue-on-CP-degradation). Does not rewrite inventory. "
        "Audits `platform.plane.rollback_lkg`. Blocked by control-plane freeze. "
        "Requires PLATFORM_FEEDBACK_WRITE_ROLES."
    ),
    responses={
        200: {"description": "LKG fence republished."},
        **_PLATFORM_WRITE_FORBIDDEN,
    },
)
def post_platform_control_plane_rollback_lkg(
    reason: str = Query(default="", max_length=500),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_WRITE_ROLES)
    _reject_if_control_readonly(db)
    result = rollback_to_last_known_good(db, actor_id=ctx.actor_id, reason=reason)
    if not result.get("ok"):
        raise HTTPException(status_code=409, detail=result)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="platform.plane.rollback_lkg",
        resource_type="control_plane_rollback",
        resource_id=str(result.get("rollback_id") or "unknown"),
        trace_id=f"plane-lkg-{uuid4().hex[:12]}",
        decision_outcome="allow",
        policy_version="plane-v2",
        actor_role=ctx.actor_role,
        action_context={
            "from_fingerprint": result.get("from_fingerprint"),
            "to_fingerprint": result.get("to_fingerprint"),
            "desired_still_diverges": result.get("desired_still_diverges"),
            "reason": (reason or "")[:200],
            "marketing_claim_allowed": False,
        },
    )
    db.commit()
    return result


@router.get(
    "/platform/control-plane/peer-ack",
    summary="Latest data-plane peer ack status",
    description=(
        "Returns the latest peer acknowledgment of a published policy fingerprint. "
        "Requires PLATFORM_FEEDBACK_READ_ROLES."
    ),
    responses={
        200: {"description": "Peer ack status."},
        **_PLATFORM_READ_FORBIDDEN,
    },
)
def get_platform_control_plane_peer_ack(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_READ_ROLES)
    return build_peer_ack_status(db)


@router.post(
    "/platform/control-plane/peer-ack",
    summary="Record data-plane peer ack of published fingerprint",
    description=(
        "Records that a peer observed a policy generation fingerprint. "
        "Audits `platform.plane.peer_ack`. Blocked by control-plane freeze. "
        "Requires PLATFORM_FEEDBACK_WRITE_ROLES."
    ),
    responses={
        200: {"description": "Peer ack recorded."},
        **_PLATFORM_WRITE_FORBIDDEN,
    },
)
def post_platform_control_plane_peer_ack(
    fingerprint: str = Query(..., min_length=1, max_length=128),
    peer_url: str = Query(default="", max_length=512),
    note: str = Query(default="", max_length=500),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_WRITE_ROLES)
    _reject_if_control_readonly(db)
    result = record_peer_ack(
        db,
        fingerprint=fingerprint,
        peer_url=peer_url,
        actor_id=ctx.actor_id,
        note=note,
    )
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="platform.plane.peer_ack",
        resource_type="control_plane_peer_ack",
        resource_id=str(result.get("fingerprint") or "unknown")[:64],
        trace_id=f"plane-ack-{uuid4().hex[:12]}",
        decision_outcome="allow",
        policy_version="plane-v2",
        actor_role=ctx.actor_role,
        action_context={
            "fingerprint": result.get("fingerprint"),
            "matches_published": result.get("matches_published"),
            "peer_url": (peer_url or "")[:200],
            "marketing_claim_allowed": False,
        },
    )
    db.commit()
    return result


@router.post(
    "/platform/feedback",
    response_model=OperatorFeedbackResponse,
    summary="Submit operator feedback",
    description=(
        "Persists operator feedback to PostgreSQL table `operator_feedback`. "
        "Emits audit event `platform.feedback.create` (`resource_type=operator_feedback`). "
        "Requires a role in PLATFORM_FEEDBACK_WRITE_ROLES."
    ),
    responses={
        200: {"description": "Feedback saved; returns persisted record with `feedback_id`."},
        **_PLATFORM_WRITE_FORBIDDEN,
        **_PLATFORM_VALIDATION,
    },
)
def create_operator_feedback(
    payload: OperatorFeedbackCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_WRITE_ROLES)
    status = build_operational_status(db, {})
    if not status["feedback_enabled"]:
        raise HTTPException(status_code=403, detail="Operator feedback capture is disabled by runtime policy.")

    comment = payload.comment.strip()
    if not comment:
        raise api_validation_error("comment", "Comment is required.")

    feedback = OperatorFeedback(
        feedback_id=str(uuid4()),
        category=normalize_feedback_category(payload.category),
        severity=normalize_feedback_severity(payload.severity),
        comment=comment,
        context_view=str(payload.context_view or "overview").strip()[:64] or "overview",
        context_action=str(payload.context_action or "").strip()[:128].lower(),
        client_latency_ms=payload.client_latency_ms,
        trace_id=str(payload.trace_id).strip()[:128] if payload.trace_id else None,
        incident_ref=str(payload.incident_ref).strip()[:64] if payload.incident_ref else None,
        metadata_json=json.dumps(payload.metadata_json or {}),
        created_by=ctx.actor_id,
    )
    db.add(feedback)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="platform.feedback.create",
        resource_type="operator_feedback",
        resource_id=feedback.feedback_id,
        trace_id=feedback.trace_id or feedback.feedback_id,
    )
    db.commit()
    db.refresh(feedback)
    logger.info(
        "platform_feedback_created %s",
        sanitize_fields(
            {
                "feedback_id": feedback.feedback_id,
                "category": feedback.category,
                "severity": feedback.severity,
                "context_view": feedback.context_view,
                "context_action": feedback.context_action,
                "actor_id": ctx.actor_id,
            }
        ),
    )
    return feedback


@router.get(
    "/platform/feedback",
    response_model=list[OperatorFeedbackResponse],
    summary="List operator feedback",
    description=(
        "Returns persisted feedback rows from `operator_feedback` with optional filters. "
        "Read-only; no audit event. Requires COMPLIANCE_READ-equivalent roles "
        "(PLATFORM_FEEDBACK_READ_ROLES)."
    ),
    responses={
        200: {"description": "Matching feedback records ordered by newest first."},
        **_PLATFORM_READ_FORBIDDEN,
    },
)
def list_operator_feedback(
    limit: int = Query(default=50, ge=1, le=PLATFORM_FEEDBACK_QUERY_LIMIT_DEFAULT, description="Max rows to return."),
    status: Optional[str] = Query(default=None, description="Filter by status: open, acknowledged, resolved, dismissed."),
    category: Optional[str] = Query(default=None, description="Filter by category: performance, ux, bug, feature, incident, other."),
    context_view: Optional[str] = Query(default=None, description="Filter by console view name (e.g. overview, discovery)."),
    context_action: Optional[str] = Query(default=None, description="Filter by action context key (e.g. load_overview)."),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_READ_ROLES)
    query = db.query(OperatorFeedback)
    if status:
        query = query.filter(OperatorFeedback.status == status.strip().lower())
    if category:
        query = query.filter(OperatorFeedback.category == category.strip().lower())
    if context_view:
        query = query.filter(OperatorFeedback.context_view == context_view.strip().lower())
    if context_action:
        query = query.filter(OperatorFeedback.context_action == context_action.strip().lower())
    rows = query.order_by(OperatorFeedback.created_at.desc()).limit(limit).all()
    return rows


@router.get(
    "/platform/feedback/analytics",
    response_model=OperatorFeedbackAnalyticsResponse,
    summary="Operator feedback analytics",
    description=(
        "Aggregates persisted feedback from `operator_feedback` by category, severity, status, "
        "context view, and context action for custom operator reports. Read-only; structured info log only."
    ),
    responses={
        200: {"description": "Analytics buckets for the requested time window."},
        **_PLATFORM_READ_FORBIDDEN,
    },
)
def get_operator_feedback_analytics(
    since_hours: int = Query(
        default=PLATFORM_FEEDBACK_ANALYTICS_SINCE_HOURS_DEFAULT,
        ge=1,
        le=720,
        description="Rolling window in hours (1–720).",
    ),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_READ_ROLES)
    report = build_feedback_analytics(db, since_hours)
    logger.info(
        "platform_feedback_analytics_served %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "since_hours": report["since_hours"],
                "total_count": report["total_count"],
                "open_count": report["open_count"],
            }
        ),
    )
    return report


@router.post(
    "/platform/feedback/{feedback_id}/actions",
    response_model=OperatorFeedbackResponse,
    summary="Apply feedback triage action",
    description=(
        "Updates feedback status in `operator_feedback` and emits audit "
        "`platform.feedback.acknowledge|resolve|dismiss|escalate`. "
        "Requires PLATFORM_FEEDBACK_ACTION_ROLES (admin/compliance write)."
    ),
    responses={
        200: {"description": "Updated feedback record after triage."},
        **_PLATFORM_ACTION_FORBIDDEN,
        **_PLATFORM_NOT_FOUND,
        **_PLATFORM_VALIDATION,
    },
)
def apply_operator_feedback_action(
    feedback_id: str,
    payload: OperatorFeedbackActionRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_FEEDBACK_ACTION_ROLES)
    action = str(payload.action or "").strip().lower()
    if action not in PLATFORM_FEEDBACK_ACTIONS:
        raise api_validation_error("action", f"Unsupported action: {action}")

    feedback = db.query(OperatorFeedback).filter_by(feedback_id=feedback_id).first()
    if not feedback:
        raise HTTPException(status_code=404, detail="Feedback record not found")

    feedback.status = ACTION_STATUS_MAP[action]
    feedback.action_note = payload.action_note.strip() or None
    feedback.acted_by = ctx.actor_id
    feedback.acted_at = datetime.now(timezone.utc)
    feedback.updated_at = datetime.now(timezone.utc)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type=f"platform.feedback.{action}",
        resource_type="operator_feedback",
        resource_id=feedback.feedback_id,
        trace_id=feedback.trace_id or feedback.feedback_id,
    )
    db.commit()
    db.refresh(feedback)
    return feedback
