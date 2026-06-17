from __future__ import annotations

import threading
from typing import Any, Callable, Optional

from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.logging_utils import get_logger, sanitize_fields
from app.models import BenchmarkRun, ScanRun
from app.services.audit import create_audit_event
from app.services.benchmark_scan_runner import (
    execute_benchmark_suite,
    execute_compliance_scan,
    execute_security_scan,
    persist_operation_cost_event,
)

logger = get_logger(__name__)

_lock = threading.Lock()
_cancel_requests: set[str] = set()
_active_runs: set[str] = set()
_progress: dict[str, dict[str, object]] = {}


def register_run(run_id: str, *, total_steps: int = 0, label: str = "starting") -> None:
    with _lock:
        _active_runs.add(run_id)
        _cancel_requests.discard(run_id)
        _progress[run_id] = {"step": 0, "total": max(0, int(total_steps)), "label": label}


def request_cancel(run_id: str) -> bool:
    with _lock:
        if run_id not in _active_runs:
            return False
        _cancel_requests.add(run_id)
        return True


def is_cancelled(run_id: str) -> bool:
    with _lock:
        return run_id in _cancel_requests


def is_active(run_id: str) -> bool:
    with _lock:
        return run_id in _active_runs


def clear_run(run_id: str) -> None:
    with _lock:
        _active_runs.discard(run_id)
        _cancel_requests.discard(run_id)
        _progress.pop(run_id, None)


def update_progress(run_id: str, *, step: int, total: int, label: str) -> None:
    with _lock:
        _progress[run_id] = {
            "step": max(0, int(step)),
            "total": max(0, int(total)),
            "label": str(label or "").strip() or "running",
        }


def get_progress(run_id: str) -> Optional[dict[str, object]]:
    with _lock:
        payload = _progress.get(run_id)
        return dict(payload) if payload else None


def _should_cancel(run_id: str) -> Callable[[], bool]:
    return lambda: is_cancelled(run_id)


def _progress_callback(run_id: str, db: Session, *, table: str) -> Callable[[int, int, str], None]:
    def callback(step: int, total: int, label: str) -> None:
        update_progress(run_id, step=step, total=total, label=label)
        summary = f"Running ({step}/{total}): {label}"
        if table == "benchmark":
            row = db.query(BenchmarkRun).filter_by(benchmark_run_id=run_id).first()
        else:
            row = db.query(ScanRun).filter_by(scan_run_id=run_id).first()
        if row is not None:
            row.summary = summary
            db.commit()

    return callback


def _finalize_benchmark_run(
    db: Session,
    *,
    run_id: str,
    result: dict[str, Any],
    actor_id: str,
    owner_scope: str,
    agent_id: str,
    environment: str,
) -> None:
    run = db.query(BenchmarkRun).filter_by(benchmark_run_id=run_id).first()
    if run is None:
        return
    run.status = str(result.get("status") or "completed")
    run.score = int(result.get("score") or 0)
    summary = str(result.get("summary") or "")
    cost_cents = int(result.get("estimated_cost_cents") or 0)
    if cost_cents > 0:
        summary = f"{summary} Spend: {cost_cents} cents ({int(result.get('gateway_call_count') or 0)} gateway calls)."
    run.summary = summary
    trace_id = f"trace-{run_id}"
    persist_operation_cost_event(
        db,
        agent_id=agent_id,
        environment=environment,
        model_name=str(result.get("model_name") or "unknown"),
        estimated_cost_cents=int(result.get("estimated_cost_cents") or 0),
        input_tokens=int(result.get("input_tokens") or 0),
        output_tokens=int(result.get("output_tokens") or 0),
        request_tag="benchmark.run",
        trace_id=trace_id,
        owner_scope=owner_scope,
        actor_id=actor_id,
    )
    action = "benchmark.run.cancel" if run.status == "cancelled" else "benchmark.run"
    create_audit_event(
        db,
        actor_id=actor_id,
        action_type=action,
        resource_type="benchmark_run",
        resource_id=run_id,
        trace_id=trace_id,
        decision_outcome="allow" if run.status != "failed" else "deny",
    )
    db.commit()


def _finalize_scan_run(
    db: Session,
    *,
    run_id: str,
    result: dict[str, Any],
    actor_id: str,
    owner_scope: str,
    agent_id: str,
    environment: str,
) -> None:
    run = db.query(ScanRun).filter_by(scan_run_id=run_id).first()
    if run is None:
        return
    run.status = str(result.get("status") or "completed")
    run.findings_count = int(result.get("findings_count") or 0)
    run.severity_high_count = int(result.get("severity_high_count") or 0)
    summary = str(result.get("summary") or "")
    cost_cents = int(result.get("estimated_cost_cents") or 0)
    if cost_cents > 0:
        summary = f"{summary} Spend: {cost_cents} cents ({int(result.get('gateway_call_count') or 0)} gateway calls)."
    run.summary = summary
    trace_id = f"trace-{run_id}"
    persist_operation_cost_event(
        db,
        agent_id=agent_id,
        environment=environment,
        model_name=str(result.get("model_name") or "unknown"),
        estimated_cost_cents=int(result.get("estimated_cost_cents") or 0),
        input_tokens=int(result.get("input_tokens") or 0),
        output_tokens=int(result.get("output_tokens") or 0),
        request_tag="scan.run",
        trace_id=trace_id,
        owner_scope=owner_scope,
        actor_id=actor_id,
    )
    action = "scan.run.cancel" if run.status == "cancelled" else "scan.run"
    create_audit_event(
        db,
        actor_id=actor_id,
        action_type=action,
        resource_type="scan_run",
        resource_id=run_id,
        trace_id=trace_id,
        decision_outcome="allow" if run.status != "failed" else "deny",
    )
    db.commit()


def run_benchmark_in_background(
    *,
    run_id: str,
    agent_id: str,
    benchmark_suite: str,
    environment: str,
    actor_id: str,
    owner_scope: str,
    total_steps: int,
) -> None:
    register_run(run_id, total_steps=total_steps, label="benchmark")
    db = SessionLocal()
    try:
        result = execute_benchmark_suite(
            db,
            agent_id=agent_id,
            benchmark_suite=benchmark_suite,
            environment=environment,
            should_cancel=_should_cancel(run_id),
            on_progress=_progress_callback(run_id, db, table="benchmark"),
        )
        _finalize_benchmark_run(
            db,
            run_id=run_id,
            result=result,
            actor_id=actor_id,
            owner_scope=owner_scope,
            agent_id=agent_id,
            environment=environment,
        )
        logger.info(
            "benchmark_run_background_completed %s",
            sanitize_fields({"run_id": run_id, "status": result.get("status")}),
        )
    except Exception as exc:
        logger.error(
            "benchmark_run_background_failed %s",
            sanitize_fields({"run_id": run_id, "error": str(exc)}),
        )
        run = db.query(BenchmarkRun).filter_by(benchmark_run_id=run_id).first()
        if run is not None:
            run.status = "failed"
            run.summary = f"Benchmark execution failed: {exc}"
            db.commit()
    finally:
        clear_run(run_id)
        db.close()


def run_scan_in_background(
    *,
    run_id: str,
    agent_id: str,
    scan_type: str,
    environment: str,
    actor_id: str,
    owner_scope: str,
    total_steps: int,
) -> None:
    register_run(run_id, total_steps=total_steps, label="scan")
    db = SessionLocal()
    try:
        if scan_type == "compliance":
            result = execute_compliance_scan(
                db,
                agent_id=agent_id,
                environment=environment,
                should_cancel=_should_cancel(run_id),
                on_progress=_progress_callback(run_id, db, table="scan"),
            )
        else:
            result = execute_security_scan(
                db,
                agent_id=agent_id,
                environment=environment,
                should_cancel=_should_cancel(run_id),
                on_progress=_progress_callback(run_id, db, table="scan"),
            )
        _finalize_scan_run(
            db,
            run_id=run_id,
            result=result,
            actor_id=actor_id,
            owner_scope=owner_scope,
            agent_id=agent_id,
            environment=environment,
        )
        logger.info(
            "scan_run_background_completed %s",
            sanitize_fields({"run_id": run_id, "status": result.get("status")}),
        )
    except Exception as exc:
        logger.error(
            "scan_run_background_failed %s",
            sanitize_fields({"run_id": run_id, "error": str(exc)}),
        )
        run = db.query(ScanRun).filter_by(scan_run_id=run_id).first()
        if run is not None:
            run.status = "failed"
            run.summary = f"Scan execution failed: {exc}"
            db.commit()
    finally:
        clear_run(run_id)
        db.close()


def spawn_benchmark_run(
    *,
    run_id: str,
    agent_id: str,
    benchmark_suite: str,
    environment: str,
    actor_id: str,
    owner_scope: str,
    total_steps: int,
) -> None:
    thread = threading.Thread(
        target=run_benchmark_in_background,
        kwargs={
            "run_id": run_id,
            "agent_id": agent_id,
            "benchmark_suite": benchmark_suite,
            "environment": environment,
            "actor_id": actor_id,
            "owner_scope": owner_scope,
            "total_steps": total_steps,
        },
        daemon=True,
        name=f"benchmark-run-{run_id[:8]}",
    )
    thread.start()


def spawn_scan_run(
    *,
    run_id: str,
    agent_id: str,
    scan_type: str,
    environment: str,
    actor_id: str,
    owner_scope: str,
    total_steps: int,
) -> None:
    thread = threading.Thread(
        target=run_scan_in_background,
        kwargs={
            "run_id": run_id,
            "agent_id": agent_id,
            "scan_type": scan_type,
            "environment": environment,
            "actor_id": actor_id,
            "owner_scope": owner_scope,
            "total_steps": total_steps,
        },
        daemon=True,
        name=f"scan-run-{run_id[:8]}",
    )
    thread.start()
