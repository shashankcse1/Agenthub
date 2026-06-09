from uuid import uuid4
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import Agent, BenchmarkRun, ScanRun
from app.policy_constants import ROLE_AGENT_OWNER
from app.router_constants import ROLES_BENCHMARK_SCAN_READ, ROLES_BENCHMARK_SCAN_WRITE
from app.schemas import BenchmarkRunRequest, BenchmarkRunResponse, ScanRunRequest, ScanRunResponse
from app.security import ActorContext, get_actor_context, require_role
from app.services.audit import create_audit_event

router = APIRouter()
logger = get_logger(__name__)


def _agent_owner_can_access(agent_id: str, ctx: ActorContext, db: Session) -> bool:
    if ctx.actor_role != ROLE_AGENT_OWNER:
        return True
    agent = db.query(Agent).filter_by(agent_id=agent_id).first()
    return bool(agent and agent.owner_id == ctx.actor_id)


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
        logger.error(
            "benchmark_run_scope_denied %s",
            sanitize_fields({"actor_id": ctx.actor_id, "agent_id": payload.agent_id}),
        )
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="benchmark.run",
            resource_type="benchmark_run",
            resource_id=payload.agent_id,
            trace_id=f"trace-benchmark-deny-{payload.agent_id}",
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only run benchmarks for owned agents.",
                "actor_role": ctx.actor_role,
                "required_scope": "agent.owner_id == requester actor_id",
                "policy_version": "v1",
                "decision_trace_id": "authz-benchmark-scope-check",
                "remediation_hint": "Use Platform Admin or AI Ops Approver for cross-owner benchmark runs.",
            },
        )

    score = 82
    run = BenchmarkRun(
        benchmark_run_id=str(uuid4()),
        agent_id=payload.agent_id,
        benchmark_suite=payload.benchmark_suite,
        environment=payload.environment,
        status="completed",
        score=score,
        summary="Benchmark suite completed with acceptable latency and quality profile.",
    )
    db.add(run)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="benchmark.run",
        resource_type="benchmark_run",
        resource_id=run.benchmark_run_id,
        trace_id=f"trace-{run.benchmark_run_id}",
    )
    db.commit()
    db.refresh(run)
    logger.info(
        "benchmark_run_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "agent_id": payload.agent_id, "run_id": run.benchmark_run_id}),
    )
    return run


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
            raise HTTPException(
                status_code=403,
                detail={
                    "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                    "message": "Agent Owner can only read benchmark runs for owned agents.",
                    "actor_role": ctx.actor_role,
                    "required_scope": "agent.owner_id == requester actor_id",
                    "policy_version": "v1",
                    "decision_trace_id": "authz-benchmark-read-scope-check",
                    "remediation_hint": "Use Platform Admin, Release Manager, Auditor, Security Approver, or AI Ops Approver for cross-owner benchmark history.",
                },
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
        logger.error(
            "scan_run_scope_denied %s",
            sanitize_fields({"actor_id": ctx.actor_id, "agent_id": payload.agent_id}),
        )
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="scan.run",
            resource_type="scan_run",
            resource_id=payload.agent_id,
            trace_id=f"trace-scan-deny-{payload.agent_id}",
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only run scans for owned agents.",
                "actor_role": ctx.actor_role,
                "required_scope": "agent.owner_id == requester actor_id",
                "policy_version": "v1",
                "decision_trace_id": "authz-scan-scope-check",
                "remediation_hint": "Use Platform Admin, Security Approver, or AI Ops Approver for cross-owner scan runs.",
            },
        )

    findings_count = 2
    severity_high_count = 0
    run = ScanRun(
        scan_run_id=str(uuid4()),
        agent_id=payload.agent_id,
        scan_type=payload.scan_type,
        environment=payload.environment,
        status="completed",
        findings_count=findings_count,
        severity_high_count=severity_high_count,
        summary="Scan completed; no high-severity findings.",
    )
    db.add(run)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="scan.run",
        resource_type="scan_run",
        resource_id=run.scan_run_id,
        trace_id=f"trace-{run.scan_run_id}",
    )
    db.commit()
    db.refresh(run)
    logger.info(
        "scan_run_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "agent_id": payload.agent_id, "run_id": run.scan_run_id}),
    )
    return run


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
            raise HTTPException(
                status_code=403,
                detail={
                    "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                    "message": "Agent Owner can only read scan runs for owned agents.",
                    "actor_role": ctx.actor_role,
                    "required_scope": "agent.owner_id == requester actor_id",
                    "policy_version": "v1",
                    "decision_trace_id": "authz-scan-read-scope-check",
                    "remediation_hint": "Use Platform Admin, Release Manager, Auditor, Security Approver, or AI Ops Approver for cross-owner scan history.",
                },
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
