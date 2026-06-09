import hashlib
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import desc, func
from sqlalchemy.orm import Session

from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import (
    AuditEvent,
    BenchmarkRun,
    ComplianceEvidenceArtifact,
    CostEvent,
    ExecutionCheckpoint,
    PolicyScheduleJob,
    RoutePolicy,
    ScaleCertificationRun,
    ScaleLoadTestRun,
    ScanRun,
)
from app.policy_constants import ROLE_RELEASE_MANAGER, ROLE_SECURITY_APPROVER, ROLE_SUPER_ADMIN
from app.router_constants import (
    ROLES_ADMIN_RELEASE,
    ROLES_ADMIN_RELEASE_AUDITOR,
    ROLES_ADMIN_RELEASE_AUDITOR_SECURITY_AIOPS,
    ROLES_ADMIN_RELEASE_OWNER,
    ROLES_ADMIN_RELEASE_OWNER_AUDITOR,
    ROLES_SECURITY_AIOPS,
)
from app.schemas import (
    AgenticReadinessOverrideRequest,
    AgenticContractValidateRequest,
    AgenticContractValidateResponse,
    ExecutionCheckpointCreateRequest,
    ExecutionCheckpointResponse,
    ExecutionCheckpointResumeRequest,
    ScaleLoadTestRunRequest,
    ScaleLoadTestRunResponse,
    AgenticReadinessCertificationRequest,
    AgenticReadinessCertificationExportResponse,
    AgenticReadinessCertificationResponse,
    AgenticReadinessReportResponse,
    PolicyAutoTuneRequest,
    PolicyAutoTuneResponse,
    PolicyScheduleApproveRequest,
    PolicyScheduleApproveResponse,
    PolicyScheduleCreateRequest,
    PolicyScheduleDeleteResponse,
    PolicyScheduleExecuteNowRequest,
    PolicyScheduleJobResponse,
    PolicyScheduleStatusResponse,
    PolicyScheduleSummaryResponse,
    PolicyScheduleUpdateRequest,
    PolicyScheduledOptimizeRequest,
    PolicyScheduledOptimizeResponse,
    AuditEventResponse,
)
from app.security import ActorContext, get_actor_context, require_dual_approval, require_mfa, require_role
from app.services.audit import create_audit_event

router = APIRouter()
logger = get_logger(__name__)


def _cost_24h_for_environment(db: Session, environment: str) -> int:
    since = datetime.utcnow().replace(microsecond=0)
    return int(
        db.query(func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0))
        .filter(CostEvent.environment == environment, CostEvent.timestamp >= since.replace(hour=0, minute=0, second=0))
        .scalar()
        or 0
    )


def _recommend_strategy(optimize_for: str, controls_status: str, recent_cost: int) -> str:
    if controls_status != "pass":
        return "weighted"
    if optimize_for == "cost" or (optimize_for == "balanced" and recent_cost > 100000):
        return "lowest_cost"
    if optimize_for == "latency":
        return "lowest_latency"
    return "weighted"


def _is_within_change_window(now_hour_utc: int, start_hour_utc: int, end_hour_utc: int) -> bool:
    # Equal start/end is treated as full-day maintenance window.
    if start_hour_utc == end_hour_utc:
        return True
    if start_hour_utc < end_hour_utc:
        return start_hour_utc <= now_hour_utc < end_hour_utc
    return now_hour_utc >= start_hour_utc or now_hour_utc < end_hour_utc


def _has_dual_schedule_approval(db: Session, job_id: str) -> bool:
    since = datetime.utcnow().replace(microsecond=0) - timedelta(hours=24)
    sec = {
        row[0]
        for row in db.query(AuditEvent.actor_id)
        .filter(
            AuditEvent.resource_type == "policy_schedule",
            AuditEvent.resource_id == job_id,
            AuditEvent.action_type == "agentic.policy.schedule.approve.security",
            AuditEvent.timestamp >= since,
        )
        .distinct()
        .all()
    }
    ai_ops = {
        row[0]
        for row in db.query(AuditEvent.actor_id)
        .filter(
            AuditEvent.resource_type == "policy_schedule",
            AuditEvent.resource_id == job_id,
            AuditEvent.action_type == "agentic.policy.schedule.approve.ai_ops",
            AuditEvent.timestamp >= since,
        )
        .distinct()
        .all()
    }
    if not sec or not ai_ops:
        return False
    return any(sec_actor != ai_actor for sec_actor in sec for ai_actor in ai_ops)


def _schedule_approval_actions_last_24h(db: Session, job_id: str) -> list[str]:
    since = datetime.utcnow().replace(microsecond=0) - timedelta(hours=24)
    rows = (
        db.query(AuditEvent.action_type)
        .filter(
            AuditEvent.resource_type == "policy_schedule",
            AuditEvent.resource_id == job_id,
            AuditEvent.action_type.in_(
                ["agentic.policy.schedule.approve.security", "agentic.policy.schedule.approve.ai_ops"]
            ),
            AuditEvent.timestamp >= since,
        )
        .order_by(AuditEvent.timestamp.desc())
        .all()
    )
    return [row[0] for row in rows]


def _dual_approval_ready_job_ids(db: Session) -> set[str]:
    since = datetime.utcnow().replace(microsecond=0) - timedelta(hours=24)
    rows = (
        db.query(AuditEvent.resource_id, AuditEvent.action_type, AuditEvent.actor_id)
        .filter(
            AuditEvent.resource_type == "policy_schedule",
            AuditEvent.action_type.in_(
                ["agentic.policy.schedule.approve.security", "agentic.policy.schedule.approve.ai_ops"]
            ),
            AuditEvent.timestamp >= since,
        )
        .all()
    )

    sec_by_job: dict[str, set[str]] = {}
    ai_ops_by_job: dict[str, set[str]] = {}
    for resource_id, action_type, actor_id in rows:
        if action_type == "agentic.policy.schedule.approve.security":
            sec_by_job.setdefault(resource_id, set()).add(actor_id)
        elif action_type == "agentic.policy.schedule.approve.ai_ops":
            ai_ops_by_job.setdefault(resource_id, set()).add(actor_id)

    ready: set[str] = set()
    for job_id, sec_actors in sec_by_job.items():
        ai_actors = ai_ops_by_job.get(job_id, set())
        if ai_actors and any(sec_actor != ai_actor for sec_actor in sec_actors for ai_actor in ai_actors):
            ready.add(job_id)
    return ready


def _latest_approval_event(
    db: Session,
    job_id: str,
    approval_action: str,
) -> Optional[AuditEvent]:
    since = datetime.utcnow().replace(microsecond=0) - timedelta(hours=24)
    return (
        db.query(AuditEvent)
        .filter(
            AuditEvent.resource_type == "policy_schedule",
            AuditEvent.resource_id == job_id,
            AuditEvent.action_type == approval_action,
            AuditEvent.timestamp >= since,
        )
        .order_by(AuditEvent.timestamp.desc())
        .first()
    )


@router.post("/agentic/contracts/validate", response_model=AgenticContractValidateResponse)
def validate_contracts(
    payload: AgenticContractValidateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE)

    issues: list[str] = []
    checks_passed = 0

    if payload.agent_id:
        checks_passed += 1
    else:
        issues.append("agent_id is required")

    if payload.module_ids:
        checks_passed += 1
    else:
        issues.append("at least one module_id is required")

    if payload.route_policy_snapshot_id:
        checks_passed += 1
    else:
        issues.append("route_policy_snapshot_id is required")

    if payload.required_capabilities:
        checks_passed += 1
    else:
        issues.append("required_capabilities should include at least one capability")

    checks_failed = len(issues)
    status = "pass" if checks_failed == 0 else "fail"

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="agentic.contract.validate",
        resource_type="agent",
        resource_id=payload.agent_id,
        trace_id=f"trace-agentic-{payload.agent_id}",
        decision_outcome="allow" if status == "pass" else "deny",
    )
    db.commit()

    return {
        "agent_id": payload.agent_id,
        "status": status,
        "checks_passed": checks_passed,
        "checks_failed": checks_failed,
        "issues": issues,
    }


@router.get("/agentic/readiness/report", response_model=AgenticReadinessReportResponse)
def readiness_report(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_AUDITOR)

    benchmark_count = db.query(BenchmarkRun).count()
    scan_count = db.query(ScanRun).count()
    high_findings = db.query(ScanRun).filter(ScanRun.severity_high_count > 0).count()

    score = 100
    score -= max(0, 10 - benchmark_count)
    score -= max(0, 10 - scan_count)
    score -= high_findings * 10
    if score < 0:
        score = 0

    scale_benchmark_pass = (
        db.query(BenchmarkRun)
        .filter(BenchmarkRun.benchmark_suite == "scale-tier3-100k", BenchmarkRun.score >= 85)
        .count()
        > 0
    )

    controls_status = "pass" if high_findings == 0 else "needs_attention"
    scale_tier3_certified = bool(scale_benchmark_pass and high_findings == 0 and score >= 85)
    certified_user_capacity = 100000 if scale_tier3_certified else 10000
    recommendation = (
        "Ready for controlled promotion" if score >= 75 and high_findings == 0 else "Complete missing checks before promotion"
    )

    return {
        "generated_at": datetime.utcnow(),
        "readiness_score": score,
        "controls_status": controls_status,
        "benchmark_coverage": benchmark_count,
        "scan_coverage": scan_count,
        "open_high_findings": high_findings,
        "scale_tier3_certified": scale_tier3_certified,
        "certified_user_capacity": certified_user_capacity,
        "recommendation": recommendation,
    }


@router.post("/agentic/readiness/certifications/run", response_model=AgenticReadinessCertificationResponse)
def run_readiness_certification(
    payload: AgenticReadinessCertificationRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "agentic_readiness_certification_start %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "target_capacity": payload.target_capacity,
                "require_multi_region": payload.require_multi_region,
            }
        ),
    )
    require_role(ctx, ROLES_ADMIN_RELEASE_AUDITOR)
    require_mfa(ctx)

    benchmark_count = db.query(BenchmarkRun).count()
    scan_count = db.query(ScanRun).count()
    high_findings = db.query(ScanRun).filter(ScanRun.severity_high_count > 0).count()

    score = 100
    score -= max(0, 10 - benchmark_count)
    score -= max(0, 10 - scan_count)
    score -= high_findings * 10
    if score < 0:
        score = 0

    scale_benchmark_pass = (
        db.query(BenchmarkRun)
        .filter(BenchmarkRun.benchmark_suite == "scale-tier3-100k", BenchmarkRun.score >= 85)
        .count()
        > 0
    )
    security_scan_pass = high_findings == 0
    contract_validation_pass = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action_type == "agentic.contract.validate",
            AuditEvent.decision_outcome == "allow",
        )
        .count()
        > 0
    )

    latest_cost_event = db.query(CostEvent).order_by(CostEvent.timestamp.desc()).first()
    cost_freshness_pass = False
    if latest_cost_event is not None:
        age_seconds = (datetime.utcnow() - latest_cost_event.timestamp).total_seconds()
        cost_freshness_pass = age_seconds <= payload.cost_freshness_slo_seconds

    multi_region_pass = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.action_type.in_(["infra.multi_region.failover.drill", "infra.multi_region.certify"]),
            AuditEvent.decision_outcome == "allow",
        )
        .count()
        > 0
    )
    if not payload.require_multi_region:
        multi_region_pass = True

    certified = bool(
        scale_benchmark_pass
        and security_scan_pass
        and contract_validation_pass
        and cost_freshness_pass
        and multi_region_pass
        and score >= 85
        and payload.target_capacity <= 100000
    )
    certified_capacity = payload.target_capacity if certified else 10000

    summary = (
        f"score={score}; benchmark={scale_benchmark_pass}; scans={security_scan_pass}; "
        f"contracts={contract_validation_pass}; cost_fresh={cost_freshness_pass}; multi_region={multi_region_pass}"
    )
    integrity_hash = hashlib.sha256(summary.encode("utf-8")).hexdigest()
    signature = f"sig:{hashlib.sha256((ctx.actor_id + integrity_hash).encode('utf-8')).hexdigest()}"

    run = ScaleCertificationRun(
        certification_id=f"cert-{uuid4()}",
        target_capacity=payload.target_capacity,
        required_multi_region=payload.require_multi_region,
        cost_freshness_slo_seconds=payload.cost_freshness_slo_seconds,
        readiness_score=score,
        scale_benchmark_pass=scale_benchmark_pass,
        security_scan_pass=security_scan_pass,
        contract_validation_pass=contract_validation_pass,
        cost_freshness_pass=cost_freshness_pass,
        multi_region_pass=multi_region_pass,
        certified=certified,
        certified_user_capacity=certified_capacity,
        integrity_hash=f"sha256:{integrity_hash}",
        signature=signature,
        summary=summary,
        executed_by=ctx.actor_id,
    )
    db.add(run)

    db.add(
        ComplianceEvidenceArtifact(
            evidence_id=str(uuid4()),
            control_id="CTRL-READINESS-SIGNED",
            generated_by=ctx.actor_id,
            source_type="readiness_certification",
            source_id=run.certification_id,
            trace_id=f"trace-readiness-cert-{run.certification_id}",
            policy_version="v1",
            artifact_uri=f"evidence://readiness-certifications/{run.certification_id}/signed-report.json",
            integrity_hash=run.integrity_hash,
        )
    )

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="agentic.readiness.certification.run",
        resource_type="readiness_certification",
        resource_id=run.certification_id,
        trace_id=f"trace-readiness-cert-{run.certification_id}",
        decision_outcome="allow" if certified else "warn",
    )
    db.commit()
    db.refresh(run)
    logger.info(
        "agentic_readiness_certification_completed %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "certification_id": run.certification_id,
                "certified": run.certified,
            }
        ),
    )
    return run


@router.post(
    "/agentic/readiness/certifications/{certification_id}/override",
    response_model=AgenticReadinessCertificationResponse,
)
def override_readiness_certification(
    certification_id: str,
    payload: AgenticReadinessOverrideRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, {ROLE_RELEASE_MANAGER})
    require_mfa(ctx)
    require_dual_approval(ctx)

    run = db.query(ScaleCertificationRun).filter_by(certification_id=certification_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Readiness certification not found")

    run.override_applied = True
    run.override_reason = payload.reason_code
    run.override_by = ctx.actor_id
    run.override_at = datetime.utcnow()
    run.certified = True
    run.certified_user_capacity = max(run.certified_user_capacity, run.target_capacity)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="agentic.readiness.certification.override",
        resource_type="readiness_certification",
        resource_id=certification_id,
        trace_id=f"trace-readiness-cert-override-{certification_id}",
        decision_outcome="warn",
    )
    db.commit()
    db.refresh(run)
    return run


@router.get("/agentic/readiness/certifications/latest", response_model=AgenticReadinessCertificationResponse)
def get_latest_readiness_certification(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_AUDITOR)
    run = db.query(ScaleCertificationRun).order_by(ScaleCertificationRun.created_at.desc()).first()
    if not run:
        raise HTTPException(status_code=404, detail="No readiness certification run found")
    return run


@router.get("/agentic/readiness/certifications", response_model=list[AgenticReadinessCertificationResponse])
def list_readiness_certifications(
    limit: int = Query(default=20, ge=1, le=200),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_AUDITOR)
    return db.query(ScaleCertificationRun).order_by(ScaleCertificationRun.created_at.desc()).limit(limit).all()


@router.get(
    "/agentic/readiness/certifications/{certification_id}/export",
    response_model=AgenticReadinessCertificationExportResponse,
)
def export_readiness_certification_bundle(
    certification_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_AUDITOR)

    run = db.query(ScaleCertificationRun).filter_by(certification_id=certification_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Readiness certification not found")

    related_events = (
        db.query(AuditEvent)
        .filter(
            (AuditEvent.resource_type == "readiness_certification")
            | (AuditEvent.action_type.in_(
                [
                    "agentic.contract.validate",
                    "benchmark.run",
                    "scan.run",
                    "infra.multi_region.failover.drill",
                    "infra.multi_region.certify",
                ]
            ))
        )
        .order_by(AuditEvent.timestamp.desc())
        .limit(50)
        .all()
    )

    evidence_items = [
        f"{event.timestamp.isoformat()} {event.action_type} {event.resource_type}:{event.resource_id}"
        for event in related_events
    ]

    export_id = f"export-{uuid4()}"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="agentic.readiness.certification.export",
        resource_type="readiness_certification",
        resource_id=certification_id,
        trace_id=f"trace-readiness-cert-export-{certification_id}",
        decision_outcome="allow",
    )
    db.commit()

    return {
        "export_id": export_id,
        "exported_at": datetime.utcnow(),
        "export_uri": f"evidence://readiness-certifications/{certification_id}/{export_id}.json",
        "certification": run,
        "audit_event_count": len(related_events),
        "evidence_items": evidence_items,
    }


@router.post("/agentic/checkpoints", response_model=ExecutionCheckpointResponse)
def create_execution_checkpoint(
    payload: ExecutionCheckpointCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_OWNER)
    require_mfa(ctx)

    checkpoint = ExecutionCheckpoint(
        checkpoint_id=f"ckpt-{uuid4()}",
        session_id=payload.session_id,
        agent_id=payload.agent_id,
        stage_name=payload.stage_name,
        state_payload=payload.state_payload,
        status="active",
        created_by=ctx.actor_id,
    )
    db.add(checkpoint)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="agentic.checkpoint.create",
        resource_type="execution_checkpoint",
        resource_id=checkpoint.checkpoint_id,
        trace_id=f"trace-checkpoint-{checkpoint.checkpoint_id}",
        decision_outcome="allow",
    )
    db.commit()
    db.refresh(checkpoint)
    return checkpoint


@router.post("/agentic/readiness/load-tests/run", response_model=ScaleLoadTestRunResponse)
def run_scale_load_test(
    payload: ScaleLoadTestRunRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_AUDITOR)
    require_mfa(ctx)

    throughput_pass = (
        payload.observed_peak_concurrency >= payload.expected_concurrency
        and payload.observed_peak_rps >= payload.expected_rps
    )
    passed = bool(
        throughput_pass
        and payload.degradation_test_pass
        and payload.recovery_test_pass
        and payload.compliance_continuity_pass
    )
    summary = (
        f"tier={payload.tier}; throughput={throughput_pass}; degradation={payload.degradation_test_pass}; "
        f"recovery={payload.recovery_test_pass}; compliance_continuity={payload.compliance_continuity_pass}"
    )

    run = ScaleLoadTestRun(
        load_test_run_id=f"load-{uuid4()}",
        tier=payload.tier,
        target_capacity=payload.target_capacity,
        expected_concurrency=payload.expected_concurrency,
        expected_rps=payload.expected_rps,
        observed_peak_concurrency=payload.observed_peak_concurrency,
        observed_peak_rps=payload.observed_peak_rps,
        degradation_test_pass=payload.degradation_test_pass,
        recovery_test_pass=payload.recovery_test_pass,
        compliance_continuity_pass=payload.compliance_continuity_pass,
        passed=passed,
        summary=summary,
        executed_by=ctx.actor_id,
    )
    db.add(run)
    db.add(
        ComplianceEvidenceArtifact(
            evidence_id=str(uuid4()),
            control_id="CTRL-SCALE-CERT",
            generated_by=ctx.actor_id,
            source_type="scale_load_test",
            source_id=run.load_test_run_id,
            trace_id=f"trace-load-test-{run.load_test_run_id}",
            policy_version="v1",
            artifact_uri=f"evidence://scale-load-tests/{run.load_test_run_id}.json",
            integrity_hash=f"sha256:{hashlib.sha256(summary.encode('utf-8')).hexdigest()}",
        )
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="agentic.readiness.load_test.run",
        resource_type="scale_load_test",
        resource_id=run.load_test_run_id,
        trace_id=f"trace-load-test-{run.load_test_run_id}",
        decision_outcome="allow" if passed else "warn",
    )
    db.commit()
    db.refresh(run)
    return run


@router.get("/agentic/readiness/load-tests/latest", response_model=ScaleLoadTestRunResponse)
def get_latest_scale_load_test(
    tier: Optional[str] = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_AUDITOR)

    query = db.query(ScaleLoadTestRun)
    if tier is not None:
        query = query.filter(ScaleLoadTestRun.tier == tier)
    run = query.order_by(ScaleLoadTestRun.created_at.desc()).first()
    if not run:
        raise HTTPException(status_code=404, detail="No load test run found")
    return run


@router.get("/agentic/checkpoints/{session_id}", response_model=list[ExecutionCheckpointResponse])
def list_execution_checkpoints(
    session_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_OWNER_AUDITOR)
    return (
        db.query(ExecutionCheckpoint)
        .filter(ExecutionCheckpoint.session_id == session_id)
        .order_by(ExecutionCheckpoint.created_at.desc())
        .all()
    )


@router.post("/agentic/checkpoints/{checkpoint_id}/resume", response_model=ExecutionCheckpointResponse)
def resume_execution_checkpoint(
    checkpoint_id: str,
    payload: ExecutionCheckpointResumeRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE)
    require_mfa(ctx)

    checkpoint = db.query(ExecutionCheckpoint).filter_by(checkpoint_id=checkpoint_id).first()
    if not checkpoint:
        raise HTTPException(status_code=404, detail="Execution checkpoint not found")
    checkpoint.status = "resumed"
    checkpoint.resumed_by = ctx.actor_id
    checkpoint.resumed_at = datetime.utcnow()
    checkpoint.resume_count += 1

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="agentic.checkpoint.resume",
        resource_type="execution_checkpoint",
        resource_id=checkpoint_id,
        trace_id=f"trace-checkpoint-resume-{checkpoint_id}",
        decision_outcome="allow",
    )
    db.commit()
    db.refresh(checkpoint)
    return checkpoint


@router.post("/agentic/policy/auto-tune", response_model=PolicyAutoTuneResponse)
def auto_tune_policies(
    payload: PolicyAutoTuneRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE)

    high_findings = db.query(ScanRun).filter(ScanRun.severity_high_count > 0).count()
    controls_status = "pass" if high_findings == 0 else "needs_attention"
    recent_cost = _cost_24h_for_environment(db, payload.environment)

    recommended = _recommend_strategy(payload.optimize_for, controls_status, recent_cost)
    all_routes = db.query(RoutePolicy).filter_by(status="active").all()
    routes = sorted(
        all_routes,
        key=lambda route: (route.load_balancing_strategy == recommended, route.route_name),
    )[: payload.max_routes]

    changes = []
    changed_count = 0
    for route in routes:
        previous_strategy = route.load_balancing_strategy
        changed = previous_strategy != recommended
        if changed and not payload.dry_run:
            route.load_balancing_strategy = recommended
            changed_count += 1
        elif changed:
            changed_count += 1

        changes.append(
            {
                "route_policy_id": route.route_policy_id,
                "previous_strategy": previous_strategy,
                "recommended_strategy": recommended,
                "changed": changed,
            }
        )

    if not payload.dry_run:
        db.commit()

    return {
        "environment": payload.environment,
        "optimize_for": payload.optimize_for,
        "dry_run": payload.dry_run,
        "total_routes_evaluated": len(routes),
        "total_routes_changed": changed_count,
        "controls_status": controls_status,
        "changes": changes,
    }


@router.post("/agentic/policy/scheduled-optimize", response_model=PolicyScheduledOptimizeResponse)
def scheduled_optimize_policies(
    payload: PolicyScheduledOptimizeRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE)

    now_hour = datetime.utcnow().hour
    within_window = _is_within_change_window(now_hour, payload.window_start_hour_utc, payload.window_end_hour_utc)

    high_findings = db.query(ScanRun).filter(ScanRun.severity_high_count > 0).count()
    controls_status = "pass" if high_findings == 0 else "needs_attention"
    recent_cost = _cost_24h_for_environment(db, payload.environment)

    recommended = _recommend_strategy(payload.optimize_for, controls_status, recent_cost)
    all_routes = db.query(RoutePolicy).filter_by(status="active").all()
    routes = sorted(
        all_routes,
        key=lambda route: (route.load_balancing_strategy == recommended, route.route_name),
    )[: payload.max_routes]

    changes = []
    proposed_changes = 0
    for route in routes:
        previous_strategy = route.load_balancing_strategy
        changed = previous_strategy != recommended
        if changed:
            proposed_changes += 1
        changes.append(
            {
                "route_policy_id": route.route_policy_id,
                "previous_strategy": previous_strategy,
                "recommended_strategy": recommended,
                "changed": changed,
            }
        )

    approval_required = proposed_changes > payload.max_changes_without_approval
    approved = (not approval_required) or (payload.approval_token == "approved")

    executed = False
    execution_status = "deferred_window"
    applied_changes = 0

    if payload.dry_run:
        execution_status = "dry_run"
    elif not within_window:
        execution_status = "deferred_window"
    elif approval_required and not approved:
        execution_status = "waiting_approval"
    else:
        for route in routes:
            if route.load_balancing_strategy != recommended:
                route.load_balancing_strategy = recommended
                applied_changes += 1
        db.commit()
        executed = True
        execution_status = "applied"
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="agentic.policy.scheduled_optimize",
            resource_type="route_policy",
            resource_id=f"scheduled:{payload.environment}",
            trace_id=f"trace-scheduled-optimize-{payload.environment}",
            decision_outcome="allow",
        )
        db.commit()

    return {
        "environment": payload.environment,
        "optimize_for": payload.optimize_for,
        "dry_run": payload.dry_run,
        "current_hour_utc": now_hour,
        "within_change_window": within_window,
        "approval_required": approval_required,
        "approved": approved,
        "executed": executed,
        "execution_status": execution_status,
        "total_routes_evaluated": len(routes),
        "proposed_changes": proposed_changes,
        "applied_changes": applied_changes,
        "controls_status": controls_status,
        "changes": changes,
    }


@router.post("/agentic/policy/schedules", response_model=PolicyScheduleJobResponse)
def create_policy_schedule(
    payload: PolicyScheduleCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "agentic_policy_schedule_create_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "name": payload.name, "environment": payload.environment}),
    )
    require_role(ctx, ROLES_ADMIN_RELEASE)

    job_id = f"sched-{uuid4()}"
    job = PolicyScheduleJob(
        job_id=job_id,
        name=payload.name,
        environment=payload.environment,
        optimize_for=payload.optimize_for,
        max_routes=payload.max_routes,
        window_start_hour_utc=payload.window_start_hour_utc,
        window_end_hour_utc=payload.window_end_hour_utc,
        max_changes_without_approval=payload.max_changes_without_approval,
        enabled=payload.enabled,
    )
    db.add(job)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="agentic.policy.schedule.create",
        resource_type="policy_schedule",
        resource_id=job_id,
        trace_id=f"trace-policy-schedule-{job_id}",
        decision_outcome="allow",
    )
    db.commit()
    db.refresh(job)
    logger.info(
        "agentic_policy_schedule_create_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "job_id": job.job_id}),
    )
    return job


@router.get("/agentic/policy/schedules", response_model=list[PolicyScheduleJobResponse])
def list_policy_schedules(
    job_id: Optional[str] = None,
    name_prefix: Optional[str] = None,
    environment: Optional[str] = None,
    optimize_for: Optional[str] = None,
    enabled: Optional[bool] = None,
    dual_approval_ready: Optional[bool] = None,
    sort_by: str = Query(default="created_at"),
    sort_order: str = Query(default="asc"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    response: Response = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_AUDITOR)
    query = db.query(PolicyScheduleJob)

    if sort_by not in {"created_at", "last_run_at", "name"}:
        raise HTTPException(status_code=400, detail="Invalid sort_by")
    if sort_order not in {"asc", "desc"}:
        raise HTTPException(status_code=400, detail="Invalid sort_order")

    if job_id:
        query = query.filter(PolicyScheduleJob.job_id == job_id)
    if name_prefix:
        query = query.filter(PolicyScheduleJob.name.like(f"{name_prefix}%"))
    if environment:
        query = query.filter(PolicyScheduleJob.environment == environment)
    if optimize_for:
        query = query.filter(PolicyScheduleJob.optimize_for == optimize_for)
    if enabled is not None:
        query = query.filter(PolicyScheduleJob.enabled == enabled)

    sort_column = getattr(PolicyScheduleJob, sort_by)
    order_expr = sort_column if sort_order == "asc" else desc(sort_column)

    if dual_approval_ready is None:
        total_count = query.count()
        if response is not None:
            response.headers["X-Total-Count"] = str(total_count)
        return query.order_by(order_expr).offset(offset).limit(limit).all()

    ready_ids = _dual_approval_ready_job_ids(db)
    if dual_approval_ready:
        if not ready_ids:
            if response is not None:
                response.headers["X-Total-Count"] = "0"
            return []
        filtered_query = query.filter(PolicyScheduleJob.job_id.in_(ready_ids))
    else:
        if not ready_ids:
            total_count = query.count()
            if response is not None:
                response.headers["X-Total-Count"] = str(total_count)
            return query.order_by(order_expr).offset(offset).limit(limit).all()
        filtered_query = query.filter(~PolicyScheduleJob.job_id.in_(ready_ids))

    total_count = filtered_query.count()
    if response is not None:
        response.headers["X-Total-Count"] = str(total_count)
    return filtered_query.order_by(order_expr).offset(offset).limit(limit).all()


@router.get("/agentic/policy/schedules/summary", response_model=PolicyScheduleSummaryResponse)
def get_policy_schedule_summary(
    environment: Optional[str] = None,
    optimize_for: Optional[str] = None,
    enabled: Optional[bool] = None,
    dual_approval_ready: Optional[bool] = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_AUDITOR)
    base_query = db.query(PolicyScheduleJob)
    if environment:
        base_query = base_query.filter(PolicyScheduleJob.environment == environment)
    if optimize_for:
        base_query = base_query.filter(PolicyScheduleJob.optimize_for == optimize_for)
    if enabled is not None:
        base_query = base_query.filter(PolicyScheduleJob.enabled == enabled)

    ready_ids = _dual_approval_ready_job_ids(db)
    if dual_approval_ready is True:
        if not ready_ids:
            total = 0
            enabled_count = 0
            disabled_count = 0
            ready_count = 0
            pending_count = 0
            return {
                "total_schedules": total,
                "enabled_schedules": enabled_count,
                "disabled_schedules": disabled_count,
                "dual_approval_ready_schedules": ready_count,
                "pending_dual_approval_schedules": pending_count,
            }
        filtered_query = base_query.filter(PolicyScheduleJob.job_id.in_(ready_ids))
    elif dual_approval_ready is False:
        if not ready_ids:
            filtered_query = base_query
        else:
            filtered_query = base_query.filter(~PolicyScheduleJob.job_id.in_(ready_ids))
    else:
        filtered_query = base_query

    total = filtered_query.count()
    enabled_count = filtered_query.filter(PolicyScheduleJob.enabled == True).count()  # noqa: E712
    disabled_count = total - enabled_count

    if dual_approval_ready is True:
        ready_count = total
        pending_count = 0
    elif dual_approval_ready is False:
        ready_count = 0
        pending_count = filtered_query.filter(PolicyScheduleJob.max_changes_without_approval == 0).count()
    else:
        if not ready_ids:
            ready_count = 0
            pending_count = filtered_query.filter(PolicyScheduleJob.max_changes_without_approval == 0).count()
        else:
            ready_count = filtered_query.filter(PolicyScheduleJob.job_id.in_(ready_ids)).count()
            pending_count = filtered_query.filter(
                PolicyScheduleJob.max_changes_without_approval == 0,
                ~PolicyScheduleJob.job_id.in_(ready_ids),
            ).count()

    return {
        "total_schedules": total,
        "enabled_schedules": enabled_count,
        "disabled_schedules": disabled_count,
        "dual_approval_ready_schedules": ready_count,
        "pending_dual_approval_schedules": pending_count,
    }


@router.get("/agentic/policy/schedules/{job_id}", response_model=PolicyScheduleJobResponse)
def get_policy_schedule(
    job_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_AUDITOR)
    job = db.query(PolicyScheduleJob).filter_by(job_id=job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Policy schedule not found")
    return job


@router.get("/agentic/policy/schedules/{job_id}/status", response_model=PolicyScheduleStatusResponse)
def get_policy_schedule_status(
    job_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_AUDITOR_SECURITY_AIOPS)
    job = db.query(PolicyScheduleJob).filter_by(job_id=job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Policy schedule not found")

    approvals = _schedule_approval_actions_last_24h(db, job_id)
    latest_security = _latest_approval_event(db, job_id, "agentic.policy.schedule.approve.security")
    latest_ai_ops = _latest_approval_event(db, job_id, "agentic.policy.schedule.approve.ai_ops")
    dual_ready = _has_dual_schedule_approval(db, job_id)
    pending = job.max_changes_without_approval == 0 and not dual_ready

    return {
        "job_id": job.job_id,
        "enabled": job.enabled,
        "last_run_at": job.last_run_at,
        "approvals_last_24h": approvals,
        "latest_security_approval_by": latest_security.actor_id if latest_security else None,
        "latest_security_approval_at": latest_security.timestamp if latest_security else None,
        "latest_ai_ops_approval_by": latest_ai_ops.actor_id if latest_ai_ops else None,
        "latest_ai_ops_approval_at": latest_ai_ops.timestamp if latest_ai_ops else None,
        "dual_approval_ready": dual_ready,
        "pending_dual_approval": pending,
    }


@router.patch("/agentic/policy/schedules/{job_id}", response_model=PolicyScheduleJobResponse)
def update_policy_schedule(
    job_id: str,
    payload: PolicyScheduleUpdateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE)
    job = db.query(PolicyScheduleJob).filter_by(job_id=job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Policy schedule not found")

    update_map = payload.model_dump(exclude_unset=True)
    if not update_map:
        raise HTTPException(status_code=400, detail="No fields provided for update")
    for field, value in update_map.items():
        setattr(job, field, value)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="agentic.policy.schedule.update",
        resource_type="policy_schedule",
        resource_id=job_id,
        trace_id=f"trace-policy-schedule-update-{job_id}",
        decision_outcome="allow",
    )
    db.commit()
    db.refresh(job)
    return job


@router.post("/agentic/policy/schedules/{job_id}/enable", response_model=PolicyScheduleJobResponse)
def enable_policy_schedule(
    job_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE)
    job = db.query(PolicyScheduleJob).filter_by(job_id=job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Policy schedule not found")

    job.enabled = True
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="agentic.policy.schedule.enable",
        resource_type="policy_schedule",
        resource_id=job_id,
        trace_id=f"trace-policy-schedule-enable-{job_id}",
        decision_outcome="allow",
    )
    db.commit()
    db.refresh(job)
    return job


@router.post("/agentic/policy/schedules/{job_id}/disable", response_model=PolicyScheduleJobResponse)
def disable_policy_schedule(
    job_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE)
    job = db.query(PolicyScheduleJob).filter_by(job_id=job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Policy schedule not found")

    job.enabled = False
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="agentic.policy.schedule.disable",
        resource_type="policy_schedule",
        resource_id=job_id,
        trace_id=f"trace-policy-schedule-disable-{job_id}",
        decision_outcome="allow",
    )
    db.commit()
    db.refresh(job)
    return job


@router.post("/agentic/policy/schedules/{job_id}/approve", response_model=PolicyScheduleApproveResponse)
def approve_policy_schedule(
    job_id: str,
    payload: PolicyScheduleApproveRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_SECURITY_AIOPS)
    job = db.query(PolicyScheduleJob).filter_by(job_id=job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Policy schedule not found")

    role_suffix = "security" if ctx.actor_role == ROLE_SECURITY_APPROVER else "ai_ops"
    action_type = f"agentic.policy.schedule.approve.{role_suffix}"
    trace_suffix = payload.reason_code or "manual"

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type=action_type,
        resource_type="policy_schedule",
        resource_id=job_id,
        trace_id=f"trace-policy-schedule-approve-{job_id}-{trace_suffix}",
        decision_outcome="allow",
    )
    db.commit()

    return {
        "job_id": job_id,
        "approval_role": ctx.actor_role,
        "approved_by": ctx.actor_id,
        "approval_action": action_type,
        "approved_at": datetime.utcnow(),
    }


@router.post("/agentic/policy/schedules/{job_id}/execute-now", response_model=PolicyScheduledOptimizeResponse)
def execute_policy_schedule_now(
    job_id: str,
    payload: PolicyScheduleExecuteNowRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE)
    job = db.query(PolicyScheduleJob).filter_by(job_id=job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Policy schedule not found")
    if not job.enabled:
        raise HTTPException(status_code=400, detail="Policy schedule is disabled")

    effective_approval_token = payload.approval_token
    if not effective_approval_token and _has_dual_schedule_approval(db, job_id):
        effective_approval_token = "approved"

    result = scheduled_optimize_policies(
        PolicyScheduledOptimizeRequest(
            environment=job.environment,
            optimize_for=job.optimize_for,
            max_routes=job.max_routes,
            window_start_hour_utc=job.window_start_hour_utc,
            window_end_hour_utc=job.window_end_hour_utc,
            max_changes_without_approval=job.max_changes_without_approval,
            approval_token=effective_approval_token,
            dry_run=payload.dry_run,
        ),
        db,
        ctx,
    )

    execution_status = result.get("execution_status", "unknown")
    decision_outcome = "allow" if execution_status in {"applied", "dry_run"} else "deny"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="agentic.policy.schedule.execute_now",
        resource_type="policy_schedule",
        resource_id=job_id,
        trace_id=f"trace-policy-schedule-execute-now-{job_id}",
        decision_outcome=decision_outcome,
    )

    if execution_status in {"applied", "dry_run"}:
        job.last_run_at = datetime.utcnow()
    db.commit()
    return result


@router.get("/agentic/policy/schedules/{job_id}/history", response_model=list[AuditEventResponse])
def list_policy_schedule_history(
    job_id: str,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    action_type: Optional[str] = None,
    actor_id: Optional[str] = None,
    since_hours: int = Query(default=24, ge=1, le=720),
    response: Response = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_AUDITOR_SECURITY_AIOPS)
    since = datetime.utcnow().replace(microsecond=0) - timedelta(hours=since_hours)
    query = db.query(AuditEvent).filter(
        AuditEvent.resource_type == "policy_schedule",
        AuditEvent.resource_id == job_id,
        AuditEvent.timestamp >= since,
    )
    if action_type:
        query = query.filter(AuditEvent.action_type == action_type)
    if actor_id:
        query = query.filter(AuditEvent.actor_id == actor_id)

    # Preserve governance evidence for deleted schedules; only 404 if neither
    # an active schedule nor any matching audit history exists.
    schedule_exists = db.query(PolicyScheduleJob.job_id).filter_by(job_id=job_id).first() is not None
    history_exists = query.limit(1).first() is not None
    if not schedule_exists and not history_exists:
        raise HTTPException(status_code=404, detail="Policy schedule not found")

    total_count = query.count()
    if response is not None:
        response.headers["X-Total-Count"] = str(total_count)
    return query.order_by(AuditEvent.timestamp.desc()).offset(offset).limit(limit).all()


@router.delete(
    "/agentic/policy/schedules/{job_id}",
    response_model=PolicyScheduleDeleteResponse,
    responses={
        403: {"description": "Actor role is not allowed for this action."},
        404: {"description": "Policy schedule not found."},
    },
)
def delete_policy_schedule(
    job_id: str,
    idempotent: bool = Query(
        default=False,
        description="When true, deleting a non-existent schedule returns 200 with deleted=false instead of 404.",
    ),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "agentic_policy_schedule_delete_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "job_id": job_id, "idempotent": idempotent}),
    )
    allowed_roles = ROLES_ADMIN_RELEASE
    if ctx.actor_role not in allowed_roles:
        explicit_required_roles = sorted(role for role in allowed_roles if role != ROLE_SUPER_ADMIN)
        logger.error(
            "agentic_policy_schedule_delete_role_denied %s",
            sanitize_fields({"actor_id": ctx.actor_id, "job_id": job_id}),
        )
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="agentic.policy.schedule.delete",
            resource_type="policy_schedule",
            resource_id=job_id,
            trace_id=f"trace-policy-schedule-delete-{job_id}-forbidden-role",
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_ROLE_FORBIDDEN",
                "message": "Actor role is not allowed for this action.",
                "actor_role": ctx.actor_role,
                "required_role": ", ".join(explicit_required_roles),
                "policy_version": "v1",
                "decision_trace_id": "authz-role-check",
                "remediation_hint": "Use a role with required permissions.",
            },
        )

    job = db.query(PolicyScheduleJob).filter_by(job_id=job_id).first()
    if not job:
        logger.error("agentic_policy_schedule_delete_not_found %s", sanitize_fields({"job_id": job_id}))
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="agentic.policy.schedule.delete",
            resource_type="policy_schedule",
            resource_id=job_id,
            trace_id=f"trace-policy-schedule-delete-{job_id}-not-found",
            decision_outcome="allow" if idempotent else "deny",
        )
        db.commit()
        if idempotent:
            return {"deleted": False, "job_id": job_id}
        raise HTTPException(status_code=404, detail="Policy schedule not found")

    db.delete(job)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="agentic.policy.schedule.delete",
        resource_type="policy_schedule",
        resource_id=job_id,
        trace_id=f"trace-policy-schedule-delete-{job_id}",
        decision_outcome="allow",
    )
    db.commit()
    logger.info(
        "agentic_policy_schedule_delete_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "job_id": job_id}),
    )
    return {"deleted": True, "job_id": job_id}
