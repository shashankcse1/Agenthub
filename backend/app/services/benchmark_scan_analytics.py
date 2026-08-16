"""Historical trend analytics for benchmark and scan runs."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Iterable, Optional

from sqlalchemy.orm import Session, Query

from app.models import Agent, BenchmarkRun, ScanRun
from app.policy_constants import ROLE_AGENT_OWNER
from app.security import ActorContext

BENCHMARK_SEGMENT_VALUES = frozenset({"environment", "suite", "agent_id", "status"})
SCAN_SEGMENT_VALUES = frozenset({"environment", "scan_type", "agent_id", "status"})


def _bucket_start(created: datetime, *, bucket_hours: int, now: datetime) -> datetime:
    point = created or now
    base = point.replace(minute=0, second=0, microsecond=0)
    hours_into = base.hour % bucket_hours
    return base - timedelta(hours=hours_into)


def _apply_owner_scope(query: Query, *, model: Any, ctx: ActorContext, db: Session, agent_id: Optional[str]) -> Query:
    normalized_agent_id = str(agent_id or "").strip()
    if normalized_agent_id:
        query = query.filter(model.agent_id == normalized_agent_id)
    elif ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = db.query(Agent.agent_id).filter(Agent.owner_id == ctx.actor_id)
        query = query.filter(model.agent_id.in_(owned_agent_ids))
    return query


def _segment_value(row: Any, *, segment_by: str, kind: str) -> str:
    if segment_by == "environment":
        return str(getattr(row, "environment", "") or "unknown").strip() or "unknown"
    if segment_by == "agent_id":
        return str(getattr(row, "agent_id", "") or "unknown").strip() or "unknown"
    if segment_by == "status":
        return str(getattr(row, "status", "") or "unknown").strip().lower() or "unknown"
    if kind == "benchmark" and segment_by == "suite":
        return str(getattr(row, "benchmark_suite", "") or "unknown").strip() or "unknown"
    if kind == "scan" and segment_by == "scan_type":
        return str(getattr(row, "scan_type", "") or "unknown").strip() or "unknown"
    return "unknown"


def _aggregate_benchmark_rows(
    rows: Iterable[BenchmarkRun],
    *,
    segment_by: str,
    bucket_hours: int,
    now: datetime,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    time_buckets: dict[tuple[datetime, str], dict[str, float]] = {}
    segments: dict[str, dict[str, float]] = {}
    total = 0
    for row in rows:
        total += 1
        segment = _segment_value(row, segment_by=segment_by, kind="benchmark")
        score = float(row.score or 0)
        status = str(row.status or "").strip().lower()
        completed = 1.0 if status in {"completed", "passed", "success"} else 0.0
        failed = 1.0 if status in {"failed", "error", "cancelled", "canceled"} else 0.0
        start = _bucket_start(row.created_at or now, bucket_hours=bucket_hours, now=now)
        tkey = (start, segment)
        if tkey not in time_buckets:
            time_buckets[tkey] = {
                "run_count": 0,
                "score_total": 0.0,
                "completed_count": 0,
                "failed_count": 0,
                "min_score": score,
                "max_score": score,
            }
        tb = time_buckets[tkey]
        tb["run_count"] += 1
        tb["score_total"] += score
        tb["completed_count"] += completed
        tb["failed_count"] += failed
        tb["min_score"] = min(float(tb["min_score"]), score)
        tb["max_score"] = max(float(tb["max_score"]), score)

        if segment not in segments:
            segments[segment] = {
                "run_count": 0,
                "score_total": 0.0,
                "completed_count": 0,
                "failed_count": 0,
                "min_score": score,
                "max_score": score,
            }
        sg = segments[segment]
        sg["run_count"] += 1
        sg["score_total"] += score
        sg["completed_count"] += completed
        sg["failed_count"] += failed
        sg["min_score"] = min(float(sg["min_score"]), score)
        sg["max_score"] = max(float(sg["max_score"]), score)

    buckets_out = []
    for (start, segment), values in sorted(time_buckets.items(), key=lambda item: (item[0][0], item[0][1]), reverse=True):
        count = int(values["run_count"])
        buckets_out.append(
            {
                "bucket_start": start,
                "bucket_end": start + timedelta(hours=bucket_hours),
                "segment_by": segment_by,
                "segment_key": segment,
                "run_count": count,
                "average_score": round(float(values["score_total"]) / count, 2) if count else 0.0,
                "completed_count": int(values["completed_count"]),
                "failed_count": int(values["failed_count"]),
                "min_score": int(values["min_score"]),
                "max_score": int(values["max_score"]),
            }
        )

    segments_out = []
    for segment, values in sorted(segments.items(), key=lambda item: (-item[1]["run_count"], item[0])):
        count = int(values["run_count"])
        segments_out.append(
            {
                "segment_by": segment_by,
                "segment_key": segment,
                "run_count": count,
                "average_score": round(float(values["score_total"]) / count, 2) if count else 0.0,
                "completed_count": int(values["completed_count"]),
                "failed_count": int(values["failed_count"]),
                "min_score": int(values["min_score"]),
                "max_score": int(values["max_score"]),
                "total_findings": 0,
                "total_high_severity": 0,
            }
        )
    return buckets_out, segments_out, total


def _aggregate_scan_rows(
    rows: Iterable[ScanRun],
    *,
    segment_by: str,
    bucket_hours: int,
    now: datetime,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], int]:
    time_buckets: dict[tuple[datetime, str], dict[str, float]] = {}
    segments: dict[str, dict[str, float]] = {}
    total = 0
    for row in rows:
        total += 1
        segment = _segment_value(row, segment_by=segment_by, kind="scan")
        findings = float(row.findings_count or 0)
        high = float(row.severity_high_count or 0)
        status = str(row.status or "").strip().lower()
        completed = 1.0 if status in {"completed", "passed", "success"} else 0.0
        failed = 1.0 if status in {"failed", "error", "cancelled", "canceled"} else 0.0
        start = _bucket_start(row.created_at or now, bucket_hours=bucket_hours, now=now)
        tkey = (start, segment)
        if tkey not in time_buckets:
            time_buckets[tkey] = {
                "run_count": 0,
                "findings_total": 0.0,
                "high_total": 0.0,
                "completed_count": 0,
                "failed_count": 0,
            }
        tb = time_buckets[tkey]
        tb["run_count"] += 1
        tb["findings_total"] += findings
        tb["high_total"] += high
        tb["completed_count"] += completed
        tb["failed_count"] += failed

        if segment not in segments:
            segments[segment] = {
                "run_count": 0,
                "findings_total": 0.0,
                "high_total": 0.0,
                "completed_count": 0,
                "failed_count": 0,
            }
        sg = segments[segment]
        sg["run_count"] += 1
        sg["findings_total"] += findings
        sg["high_total"] += high
        sg["completed_count"] += completed
        sg["failed_count"] += failed

    buckets_out = []
    for (start, segment), values in sorted(time_buckets.items(), key=lambda item: (item[0][0], item[0][1]), reverse=True):
        count = int(values["run_count"])
        buckets_out.append(
            {
                "bucket_start": start,
                "bucket_end": start + timedelta(hours=bucket_hours),
                "segment_by": segment_by,
                "segment_key": segment,
                "run_count": count,
                "average_score": 0.0,
                "completed_count": int(values["completed_count"]),
                "failed_count": int(values["failed_count"]),
                "min_score": 0,
                "max_score": 0,
                "total_findings": int(values["findings_total"]),
                "total_high_severity": int(values["high_total"]),
                "average_findings": round(float(values["findings_total"]) / count, 2) if count else 0.0,
            }
        )

    segments_out = []
    for segment, values in sorted(segments.items(), key=lambda item: (-item[1]["run_count"], item[0])):
        count = int(values["run_count"])
        segments_out.append(
            {
                "segment_by": segment_by,
                "segment_key": segment,
                "run_count": count,
                "average_score": 0.0,
                "completed_count": int(values["completed_count"]),
                "failed_count": int(values["failed_count"]),
                "min_score": 0,
                "max_score": 0,
                "total_findings": int(values["findings_total"]),
                "total_high_severity": int(values["high_total"]),
            }
        )
    return buckets_out, segments_out, total


def build_benchmark_analytics(
    db: Session,
    *,
    ctx: ActorContext,
    window_hours: int,
    bucket_hours: int,
    segment_by: str,
    agent_id: Optional[str] = None,
    environment: Optional[str] = None,
    benchmark_suite: Optional[str] = None,
    limit: int = 2000,
) -> dict[str, Any]:
    normalized_segment = str(segment_by or "environment").strip().lower() or "environment"
    if normalized_segment not in BENCHMARK_SEGMENT_VALUES:
        raise ValueError(f"segment_by must be one of: {', '.join(sorted(BENCHMARK_SEGMENT_VALUES))}")

    now = datetime.utcnow()
    since = now - timedelta(hours=window_hours)
    query = db.query(BenchmarkRun).filter(BenchmarkRun.created_at >= since)
    query = _apply_owner_scope(query, model=BenchmarkRun, ctx=ctx, db=db, agent_id=agent_id)

    normalized_environment = str(environment or "").strip().lower()
    if normalized_environment:
        query = query.filter(BenchmarkRun.environment == normalized_environment)
    normalized_suite = str(benchmark_suite or "").strip()
    if normalized_suite:
        query = query.filter(BenchmarkRun.benchmark_suite == normalized_suite)

    rows = query.order_by(BenchmarkRun.created_at.desc()).limit(max(1, min(limit, 5000))).all()
    buckets, segments, total = _aggregate_benchmark_rows(
        rows, segment_by=normalized_segment, bucket_hours=bucket_hours, now=now
    )
    return {
        "kind": "benchmark",
        "window_hours": window_hours,
        "bucket_hours": bucket_hours,
        "segment_by": normalized_segment,
        "total_runs": total,
        "buckets": buckets,
        "segments": segments,
    }


def build_scan_analytics(
    db: Session,
    *,
    ctx: ActorContext,
    window_hours: int,
    bucket_hours: int,
    segment_by: str,
    agent_id: Optional[str] = None,
    environment: Optional[str] = None,
    scan_type: Optional[str] = None,
    limit: int = 2000,
) -> dict[str, Any]:
    normalized_segment = str(segment_by or "environment").strip().lower() or "environment"
    if normalized_segment not in SCAN_SEGMENT_VALUES:
        raise ValueError(f"segment_by must be one of: {', '.join(sorted(SCAN_SEGMENT_VALUES))}")

    now = datetime.utcnow()
    since = now - timedelta(hours=window_hours)
    query = db.query(ScanRun).filter(ScanRun.created_at >= since)
    query = _apply_owner_scope(query, model=ScanRun, ctx=ctx, db=db, agent_id=agent_id)

    normalized_environment = str(environment or "").strip().lower()
    if normalized_environment:
        query = query.filter(ScanRun.environment == normalized_environment)
    normalized_scan_type = str(scan_type or "").strip()
    if normalized_scan_type:
        query = query.filter(ScanRun.scan_type == normalized_scan_type)

    rows = query.order_by(ScanRun.created_at.desc()).limit(max(1, min(limit, 5000))).all()
    buckets, segments, total = _aggregate_scan_rows(
        rows, segment_by=normalized_segment, bucket_hours=bucket_hours, now=now
    )
    return {
        "kind": "scan",
        "window_hours": window_hours,
        "bucket_hours": bucket_hours,
        "segment_by": normalized_segment,
        "total_runs": total,
        "buckets": buckets,
        "segments": segments,
    }
