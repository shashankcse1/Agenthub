from uuid import uuid4
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import Agent, BenchmarkRun, ScanRun
from app.policy_constants import ROLE_AGENT_OWNER
from app.router_constants import ROLES_BENCHMARK_SCAN_READ, ROLES_BENCHMARK_SCAN_WRITE
from app.schemas import (
    BenchmarkCostEstimateResponse,
    BenchmarkRunRequest,
    BenchmarkRunResponse,
    BenchmarkScanCancelResponse,
    ScanCostEstimateResponse,
    ScanRunRequest,
    ScanRunResponse,
)
from app.api_errors import authz_scope_forbidden, conflict_error, not_found_error, validation_error
from app.security import ActorContext, get_actor_context, require_role
from app.services.audit import create_audit_event
from app.services.benchmark_scan_execution import (
    get_progress,
    is_active,
    request_cancel,
    spawn_benchmark_run,
    spawn_scan_run,
)
from app.services.benchmark_scan_runner import (
    BENCHMARK_SUITE_CASES,
    SECURITY_SCAN_PROBES,
    estimate_benchmark_cost,
    estimate_scan_cost,
)

router = APIRouter()
logger = get_logger(__name__)


def _agent_owner_can_access(agent_id: str, ctx: ActorContext, db: Session) -> bool:
    if ctx.actor_role != ROLE_AGENT_OWNER:
        return True
    agent = db.query(Agent).filter_by(agent_id=agent_id).first()
    return bool(agent and agent.owner_id == ctx.actor_id)


def _resolve_owner_scope(db: Session, agent_id: str, ctx: ActorContext) -> str:
    agent = db.query(Agent).filter_by(agent_id=agent_id).first()
    owner_id = str(agent.owner_id or "").strip() if agent else ""
    if owner_id:
        return f"owner:{owner_id}"
    return f"actor:{ctx.actor_id}"


def _benchmark_run_response(run: BenchmarkRun, result: Optional[dict[str, object]] = None) -> BenchmarkRunResponse:
    payload = BenchmarkRunResponse.model_validate(run)
    updates: dict[str, object] = {}
    if result:
        updates["estimated_cost_cents"] = int(result.get("estimated_cost_cents") or 0)
        updates["gateway_call_count"] = int(result.get("gateway_call_count") or 0)
    progress = get_progress(run.benchmark_run_id)
    if progress and str(run.status or "").lower() == "running":
        updates["progress_step"] = int(progress.get("step") or 0)
        updates["progress_total"] = int(progress.get("total") or 0)
        updates["progress_label"] = str(progress.get("label") or "")
    if updates:
        return payload.model_copy(update=updates)
    return payload


def _scan_run_response(run: ScanRun, result: Optional[dict[str, object]] = None) -> ScanRunResponse:
    payload = ScanRunResponse.model_validate(run)
    updates: dict[str, object] = {}
    if result:
        updates["estimated_cost_cents"] = int(result.get("estimated_cost_cents") or 0)
        updates["gateway_call_count"] = int(result.get("gateway_call_count") or 0)
    progress = get_progress(run.scan_run_id)
    if progress and str(run.status or "").lower() == "running":
        updates["progress_step"] = int(progress.get("step") or 0)
        updates["progress_total"] = int(progress.get("total") or 0)
        updates["progress_label"] = str(progress.get("label") or "")
    if updates:
        return payload.model_copy(update=updates)
    return payload


def _benchmark_suite_case_count(benchmark_suite: str) -> int:
    suite = str(benchmark_suite or "reliability-core").strip() or "reliability-core"
    cases = BENCHMARK_SUITE_CASES.get(suite, BENCHMARK_SUITE_CASES["reliability-core"])
    return len(cases)


def _scan_step_count(scan_type: str) -> int:
    normalized = str(scan_type or "security").strip().lower() or "security"
    if normalized == "compliance":
        return 1
    return len(SECURITY_SCAN_PROBES)


def _ensure_run_access(run_agent_id: str, ctx: ActorContext, db: Session) -> None:
    if not _agent_owner_can_access(run_agent_id, ctx, db):
        logger.error(
            "benchmark_scan_run_scope_denied %s",
            sanitize_fields({"actor_id": ctx.actor_id, "agent_id": run_agent_id}),
        )
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="benchmark_scan.run.access",
            resource_type="agent",
            resource_id=run_agent_id,
            trace_id=f"trace-benchmark-scan-access-deny-{run_agent_id}",
            decision_outcome="deny",
        )
        db.commit()
        raise authz_scope_forbidden(
            message="Agent Owner can only access runs for owned agents.",
            actor_role=ctx.actor_role,
            required_scope="agent.owner_id == requester actor_id",
            decision_trace_id="authz-benchmark-scan-run-access",
            remediation_hint="Use Platform Admin or AI Ops Approver for cross-owner run access.",
        )


def _scope_forbidden(agent_id: str, ctx: ActorContext, db: Session, *, action_type: str, trace_prefix: str) -> None:
    logger.error(
        "benchmark_scan_scope_denied %s",
        sanitize_fields({"actor_id": ctx.actor_id, "agent_id": agent_id, "action_type": action_type}),
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type=action_type,
        resource_type="agent",
        resource_id=agent_id,
        trace_id=f"{trace_prefix}-{agent_id}",
        decision_outcome="deny",
    )
    db.commit()
    raise authz_scope_forbidden(
        message="Agent Owner can only access resources for owned agents.",
        actor_role=ctx.actor_role,
        required_scope="agent.owner_id == requester actor_id",
        decision_trace_id=f"{trace_prefix}-scope-check",
        remediation_hint="Use Platform Admin, Security Approver, or AI Ops Approver for cross-owner access.",
    )


@router.get("/benchmarks/cost-estimate", response_model=BenchmarkCostEstimateResponse)
def get_benchmark_cost_estimate(
    agent_id: str = Query(..., min_length=1),
    benchmark_suite: str = Query(default="reliability-core"),
    environment: str = Query(default="dev"),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_BENCHMARK_SCAN_READ)
    normalized_agent = str(agent_id or "").strip()
    if not _agent_owner_can_access(normalized_agent, ctx, db):
        _scope_forbidden(
            normalized_agent,
            ctx,
            db,
            action_type="benchmark.cost_estimate",
            trace_prefix="trace-benchmark-cost-deny",
        )
    return estimate_benchmark_cost(
        db,
        agent_id=normalized_agent,
        benchmark_suite=benchmark_suite,
        environment=environment,
    )


@router.get("/scans/cost-estimate", response_model=ScanCostEstimateResponse)
def get_scan_cost_estimate(
    agent_id: str = Query(..., min_length=1),
    scan_type: str = Query(default="security"),
    environment: str = Query(default="dev"),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_BENCHMARK_SCAN_READ)
    normalized_agent = str(agent_id or "").strip()
    if not _agent_owner_can_access(normalized_agent, ctx, db):
        _scope_forbidden(
            normalized_agent,
            ctx,
            db,
            action_type="scan.cost_estimate",
            trace_prefix="trace-scan-cost-deny",
        )
    return estimate_scan_cost(
        db,
        agent_id=normalized_agent,
        scan_type=scan_type,
        environment=environment,
    )


@router.post("/benchmarks/run", response_model=BenchmarkRunResponse)
def run_benchmark(
    payload: BenchmarkRunRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "benchmark_run_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "agent_id": payload.agent_id, "environment": payload.environment}),
    )
    require_role(ctx, ROLES_BENCHMARK_SCAN_WRITE)
    if not _agent_owner_can_access(payload.agent_id, ctx, db):
        _scope_forbidden(
            payload.agent_id,
            ctx,
            db,
            action_type="benchmark.run",
            trace_prefix="trace-benchmark-deny",
        )

    normalized_agent = str(payload.agent_id or "").strip()
    if not normalized_agent:
        raise validation_error("agent_id is required", decision_trace_id="benchmark-run-validation", status_code=422)

    run_id = str(uuid4())
    total_steps = _benchmark_suite_case_count(payload.benchmark_suite)
    run = BenchmarkRun(
        benchmark_run_id=run_id,
        agent_id=normalized_agent,
        benchmark_suite=payload.benchmark_suite,
        environment=payload.environment,
        status="running",
        score=0,
        summary=f"Starting benchmark ({total_steps} gateway case(s))…",
    )
    db.add(run)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="benchmark.run",
        resource_type="benchmark_run",
        resource_id=run_id,
        trace_id=f"trace-benchmark-run-{run_id}",
        decision_outcome="allow",
        environment=payload.environment,
    )
    db.commit()
    db.refresh(run)

    owner_scope = _resolve_owner_scope(db, normalized_agent, ctx)
    spawn_benchmark_run(
        run_id=run_id,
        agent_id=normalized_agent,
        benchmark_suite=payload.benchmark_suite,
        environment=payload.environment,
        actor_id=ctx.actor_id,
        owner_scope=owner_scope,
        total_steps=total_steps,
    )
    logger.info(
        "benchmark_run_started %s",
        sanitize_fields({"actor_id": ctx.actor_id, "agent_id": payload.agent_id, "run_id": run_id}),
    )
    return _benchmark_run_response(run)


@router.get("/benchmarks/runs", response_model=list[BenchmarkRunResponse])
def list_benchmark_runs(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    agent_id: Optional[str] = None,
    environment: Optional[str] = None,
    benchmark_suite: Optional[str] = None,
    response: Response = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_BENCHMARK_SCAN_READ)

    query = db.query(BenchmarkRun)

    normalized_agent_id = str(agent_id or "").strip()
    if normalized_agent_id:
        if not _agent_owner_can_access(normalized_agent_id, ctx, db):
            raise authz_scope_forbidden(
                message="Agent Owner can only read benchmark runs for owned agents.",
                actor_role=ctx.actor_role,
                required_scope="agent.owner_id == requester actor_id",
                decision_trace_id="authz-benchmark-read-scope-check",
                remediation_hint="Use Platform Admin, Release Manager, Auditor, Security Approver, or AI Ops Approver for cross-owner benchmark history.",
            )
        query = query.filter(BenchmarkRun.agent_id == normalized_agent_id)

    if ctx.actor_role == ROLE_AGENT_OWNER and not normalized_agent_id:
        owned_agent_ids = db.query(Agent.agent_id).filter(Agent.owner_id == ctx.actor_id)
        query = query.filter(BenchmarkRun.agent_id.in_(owned_agent_ids))

    normalized_environment = str(environment or "").strip().lower()
    if normalized_environment:
        query = query.filter(BenchmarkRun.environment == normalized_environment)

    normalized_suite = str(benchmark_suite or "").strip()
    if normalized_suite:
        query = query.filter(BenchmarkRun.benchmark_suite == normalized_suite)

    total = query.count()
    if response is not None:
        response.headers["X-Total-Count"] = str(total)

    return query.order_by(BenchmarkRun.created_at.desc()).offset(offset).limit(limit).all()


@router.get("/benchmarks/runs/{run_id}", response_model=BenchmarkRunResponse)
def get_benchmark_run(
    run_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_BENCHMARK_SCAN_READ)
    normalized_run_id = str(run_id or "").strip()
    run = db.query(BenchmarkRun).filter_by(benchmark_run_id=normalized_run_id).first()
    if run is None:
        raise not_found_error("benchmark_run", normalized_run_id, decision_trace_id="benchmark-run-not-found")
    _ensure_run_access(run.agent_id, ctx, db)
    return _benchmark_run_response(run)


@router.post("/benchmarks/runs/{run_id}/cancel", response_model=BenchmarkScanCancelResponse)
def cancel_benchmark_run(
    run_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "benchmark_run_cancel_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "run_id": run_id}),
    )
    require_role(ctx, ROLES_BENCHMARK_SCAN_WRITE)
    normalized_run_id = str(run_id or "").strip()
    run = db.query(BenchmarkRun).filter_by(benchmark_run_id=normalized_run_id).first()
    if run is None:
        raise not_found_error("benchmark_run", normalized_run_id, decision_trace_id="benchmark-run-cancel-not-found")
    _ensure_run_access(run.agent_id, ctx, db)
    if str(run.status or "").lower() != "running":
        raise conflict_error(
            f"Benchmark run is not running (status={run.status}).",
            decision_trace_id="benchmark-run-cancel-not-running",
            remediation_hint="Only running benchmark runs can be cancelled.",
            status=run.status,
        )
    if not request_cancel(normalized_run_id) and not is_active(normalized_run_id):
        raise conflict_error(
            "Benchmark run is not active.",
            decision_trace_id="benchmark-run-cancel-not-active",
            remediation_hint="Refresh run status and retry if the run is still active.",
        )
    run.summary = "Cancellation requested…"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="benchmark.run.cancel",
        resource_type="benchmark_run",
        resource_id=normalized_run_id,
        trace_id=f"trace-benchmark-cancel-{normalized_run_id}",
        decision_outcome="allow",
    )
    db.commit()
    logger.info(
        "benchmark_run_cancel_requested %s",
        sanitize_fields({"actor_id": ctx.actor_id, "run_id": normalized_run_id}),
    )
    return {
        "run_id": normalized_run_id,
        "status": "cancelling",
        "message": "Stop requested. Execution halts after the current gateway call completes.",
    }


@router.post("/scans/run", response_model=ScanRunResponse)
def run_scan(
    payload: ScanRunRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "scan_run_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "agent_id": payload.agent_id, "environment": payload.environment}),
    )
    require_role(ctx, ROLES_BENCHMARK_SCAN_WRITE)
    if not _agent_owner_can_access(payload.agent_id, ctx, db):
        _scope_forbidden(
            payload.agent_id,
            ctx,
            db,
            action_type="scan.run",
            trace_prefix="trace-scan-deny",
        )

    normalized_agent = str(payload.agent_id or "").strip()
    if not normalized_agent:
        raise validation_error("agent_id is required", decision_trace_id="scan-run-validation", status_code=422)

    scan_type = str(payload.scan_type or "security").strip().lower() or "security"
    run_id = str(uuid4())
    total_steps = _scan_step_count(scan_type)
    run = ScanRun(
        scan_run_id=run_id,
        agent_id=normalized_agent,
        scan_type=scan_type,
        environment=payload.environment,
        status="running",
        findings_count=0,
        severity_high_count=0,
        summary=f"Starting {scan_type} scan…",
    )
    db.add(run)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="scan.run",
        resource_type="scan_run",
        resource_id=run_id,
        trace_id=f"trace-scan-run-{run_id}",
        decision_outcome="allow",
        environment=payload.environment,
    )
    db.commit()
    db.refresh(run)

    owner_scope = _resolve_owner_scope(db, normalized_agent, ctx)
    spawn_scan_run(
        run_id=run_id,
        agent_id=normalized_agent,
        scan_type=scan_type,
        environment=payload.environment,
        actor_id=ctx.actor_id,
        owner_scope=owner_scope,
        total_steps=total_steps,
    )
    logger.info(
        "scan_run_started %s",
        sanitize_fields({"actor_id": ctx.actor_id, "agent_id": payload.agent_id, "run_id": run_id}),
    )
    return _scan_run_response(run)


@router.get("/scans/runs", response_model=list[ScanRunResponse])
def list_scan_runs(
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    agent_id: Optional[str] = None,
    environment: Optional[str] = None,
    scan_type: Optional[str] = None,
    response: Response = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_BENCHMARK_SCAN_READ)

    query = db.query(ScanRun)

    normalized_agent_id = str(agent_id or "").strip()
    if normalized_agent_id:
        if not _agent_owner_can_access(normalized_agent_id, ctx, db):
            raise authz_scope_forbidden(
                message="Agent Owner can only read scan runs for owned agents.",
                actor_role=ctx.actor_role,
                required_scope="agent.owner_id == requester actor_id",
                decision_trace_id="authz-scan-read-scope-check",
                remediation_hint="Use Platform Admin, Release Manager, Auditor, Security Approver, or AI Ops Approver for cross-owner scan history.",
            )
        query = query.filter(ScanRun.agent_id == normalized_agent_id)

    if ctx.actor_role == ROLE_AGENT_OWNER and not normalized_agent_id:
        owned_agent_ids = db.query(Agent.agent_id).filter(Agent.owner_id == ctx.actor_id)
        query = query.filter(ScanRun.agent_id.in_(owned_agent_ids))

    normalized_environment = str(environment or "").strip().lower()
    if normalized_environment:
        query = query.filter(ScanRun.environment == normalized_environment)

    normalized_scan_type = str(scan_type or "").strip()
    if normalized_scan_type:
        query = query.filter(ScanRun.scan_type == normalized_scan_type)

    total = query.count()
    if response is not None:
        response.headers["X-Total-Count"] = str(total)

    return query.order_by(ScanRun.created_at.desc()).offset(offset).limit(limit).all()


@router.get("/scans/runs/{run_id}", response_model=ScanRunResponse)
def get_scan_run(
    run_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_BENCHMARK_SCAN_READ)
    normalized_run_id = str(run_id or "").strip()
    run = db.query(ScanRun).filter_by(scan_run_id=normalized_run_id).first()
    if run is None:
        raise not_found_error("scan_run", normalized_run_id, decision_trace_id="scan-run-not-found")
    _ensure_run_access(run.agent_id, ctx, db)
    return _scan_run_response(run)


@router.post("/scans/runs/{run_id}/cancel", response_model=BenchmarkScanCancelResponse)
def cancel_scan_run(
    run_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "scan_run_cancel_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "run_id": run_id}),
    )
    require_role(ctx, ROLES_BENCHMARK_SCAN_WRITE)
    normalized_run_id = str(run_id or "").strip()
    run = db.query(ScanRun).filter_by(scan_run_id=normalized_run_id).first()
    if run is None:
        raise not_found_error("scan_run", normalized_run_id, decision_trace_id="scan-run-cancel-not-found")
    _ensure_run_access(run.agent_id, ctx, db)
    if str(run.status or "").lower() != "running":
        raise conflict_error(
            f"Scan run is not running (status={run.status}).",
            decision_trace_id="scan-run-cancel-not-running",
            remediation_hint="Only running scan runs can be cancelled.",
            status=run.status,
        )
    if not request_cancel(normalized_run_id) and not is_active(normalized_run_id):
        raise conflict_error(
            "Scan run is not active.",
            decision_trace_id="scan-run-cancel-not-active",
            remediation_hint="Refresh run status and retry if the run is still active.",
        )
    run.summary = "Cancellation requested…"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="scan.run.cancel",
        resource_type="scan_run",
        resource_id=normalized_run_id,
        trace_id=f"trace-scan-cancel-{normalized_run_id}",
        decision_outcome="allow",
    )
    db.commit()
    logger.info(
        "scan_run_cancel_requested %s",
        sanitize_fields({"actor_id": ctx.actor_id, "run_id": normalized_run_id}),
    )
    return {
        "run_id": normalized_run_id,
        "status": "cancelling",
        "message": "Stop requested. Execution halts after the current gateway call completes.",
    }
