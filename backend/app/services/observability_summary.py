from __future__ import annotations

from collections import Counter
from datetime import datetime
from typing import Callable

from sqlalchemy import func
from sqlalchemy.orm import Query, Session

from app.domain_constants import (
    OBSERVABILITY_BREAKDOWN_TOP_ACTIONS,
    OBSERVABILITY_BREAKDOWN_TOP_ACTORS,
    OBSERVABILITY_DEFAULT_OUTCOME,
    OBSERVABILITY_SUMMARY_RECENT_TRACES_LIMIT,
    OBSERVABILITY_SUMMARY_SCHEMA_SAMPLE_SIZE,
    OBSERVABILITY_UNKNOWN_ACTION,
    OBSERVABILITY_UNKNOWN_ACTOR,
    REQUIRED_OBSERVABILITY_LOG_FIELDS,
)
from app.models import AuditEvent
from app.schemas import (
    ObservabilityBreakdownItem,
    ObservabilityHourlyVolume,
    ObservabilityLogSchemaStatusResponse,
    ObservabilityRecentTraceResponse,
)


def schema_status_from_logs(logs: list[dict]) -> ObservabilityLogSchemaStatusResponse:
    missing_field_counts = {field: 0 for field in REQUIRED_OBSERVABILITY_LOG_FIELDS}
    valid_count = 0
    for log in logs:
        is_valid = True
        for field in REQUIRED_OBSERVABILITY_LOG_FIELDS:
            value = log.get(field)
            if value is None or value == "":
                missing_field_counts[field] += 1
                is_valid = False
        if is_valid:
            valid_count += 1
    sampled_count = len(logs)
    invalid_count = sampled_count - valid_count
    conformance_percent = 100.0
    if sampled_count > 0:
        conformance_percent = round((valid_count / sampled_count) * 100.0, 2)
    return ObservabilityLogSchemaStatusResponse(
        generated_at=datetime.utcnow(),
        required_fields=list(REQUIRED_OBSERVABILITY_LOG_FIELDS),
        sampled_count=sampled_count,
        valid_count=valid_count,
        invalid_count=invalid_count,
        conformance_percent=conformance_percent,
        missing_field_counts=missing_field_counts,
    )


def _normalized_outcome(column):
    return func.coalesce(func.lower(column), OBSERVABILITY_DEFAULT_OUTCOME)


def _breakdown_items(counter: Counter[str], limit: int | None = None) -> list[ObservabilityBreakdownItem]:
    items = counter.most_common(limit) if limit else counter.most_common()
    return [ObservabilityBreakdownItem(label=label, count=count) for label, count in items]


def build_observability_summary_aggregates(
    db: Session,
    scoped_query: Callable[[], Query],
    to_log_record: Callable[[AuditEvent], dict],
) -> dict:
    """Aggregate observability summary metrics in SQL to avoid loading large event windows into memory."""

    total_events = scoped_query().count()
    unique_traces = (
        scoped_query()
        .with_entities(func.count(func.distinct(AuditEvent.trace_id)))
        .scalar()
        or 0
    )

    outcome_rows = (
        scoped_query()
        .with_entities(_normalized_outcome(AuditEvent.decision_outcome).label("label"), func.count().label("count"))
        .group_by("label")
        .all()
    )
    outcome_counter = Counter({str(label or OBSERVABILITY_DEFAULT_OUTCOME): int(count) for label, count in outcome_rows})

    action_rows = (
        scoped_query()
        .with_entities(AuditEvent.action_type.label("label"), func.count().label("count"))
        .group_by(AuditEvent.action_type)
        .order_by(func.count().desc())
        .limit(OBSERVABILITY_BREAKDOWN_TOP_ACTIONS)
        .all()
    )
    action_counter = Counter(
        {
            (str(label).strip() or OBSERVABILITY_UNKNOWN_ACTION): int(count)
            for label, count in action_rows
        }
    )

    actor_rows = (
        scoped_query()
        .with_entities(AuditEvent.actor_id.label("label"), func.count().label("count"))
        .group_by(AuditEvent.actor_id)
        .order_by(func.count().desc())
        .limit(OBSERVABILITY_BREAKDOWN_TOP_ACTORS)
        .all()
    )
    actor_counter = Counter(
        {
            (str(label).strip() or OBSERVABILITY_UNKNOWN_ACTOR): int(count)
            for label, count in actor_rows
        }
    )

    hour_bucket = func.date_trunc("hour", AuditEvent.timestamp)
    hourly_rows = (
        scoped_query()
        .with_entities(hour_bucket.label("hour_bucket"), func.count().label("count"))
        .group_by("hour_bucket")
        .order_by("hour_bucket")
        .all()
    )
    hourly_counter = Counter(
        {
            hour_bucket.strftime("%Y-%m-%dT%H:00Z"): int(count)
            for hour_bucket, count in hourly_rows
            if hour_bucket is not None
        }
    )

    trace_rows = (
        scoped_query()
        .with_entities(
            AuditEvent.trace_id.label("trace_id"),
            func.count().label("event_count"),
            func.max(AuditEvent.timestamp).label("last_seen"),
        )
        .group_by(AuditEvent.trace_id)
        .order_by(func.max(AuditEvent.timestamp).desc())
        .limit(OBSERVABILITY_SUMMARY_RECENT_TRACES_LIMIT)
        .all()
    )

    recent_traces: list[ObservabilityRecentTraceResponse] = []
    for trace_id, event_count, last_seen in trace_rows:
        if not trace_id or last_seen is None:
            continue
        latest_event = (
            scoped_query()
            .filter(AuditEvent.trace_id == trace_id, AuditEvent.timestamp == last_seen)
            .order_by(AuditEvent.audit_event_id.desc())
            .first()
        )
        primary_action = OBSERVABILITY_UNKNOWN_ACTION
        primary_outcome = OBSERVABILITY_DEFAULT_OUTCOME
        if latest_event:
            primary_action = str(latest_event.action_type or OBSERVABILITY_UNKNOWN_ACTION).strip() or OBSERVABILITY_UNKNOWN_ACTION
            primary_outcome = str(latest_event.decision_outcome or OBSERVABILITY_DEFAULT_OUTCOME).strip().lower() or OBSERVABILITY_DEFAULT_OUTCOME
        recent_traces.append(
            ObservabilityRecentTraceResponse(
                trace_id=str(trace_id),
                event_count=int(event_count),
                last_seen=last_seen,
                primary_action=primary_action,
                primary_outcome=primary_outcome,
            )
        )

    schema_logs = [
        to_log_record(event)
        for event in scoped_query()
        .order_by(AuditEvent.timestamp.desc())
        .limit(OBSERVABILITY_SUMMARY_SCHEMA_SAMPLE_SIZE)
        .all()
    ]
    schema_status = schema_status_from_logs(schema_logs) if schema_logs else None

    allow_count = outcome_counter.get("allow", 0)
    deny_count = outcome_counter.get("deny", 0)
    warn_count = outcome_counter.get("warn", 0)
    non_allow = deny_count + warn_count
    non_allow_rate = round((non_allow / total_events) * 100.0, 2) if total_events else 0.0

    return {
        "total_events": total_events,
        "unique_traces": unique_traces,
        "allow_count": allow_count,
        "deny_count": deny_count,
        "warn_count": warn_count,
        "non_allow_rate_percent": non_allow_rate,
        "outcome_breakdown": _breakdown_items(outcome_counter),
        "action_breakdown": _breakdown_items(action_counter),
        "actor_breakdown": _breakdown_items(actor_counter),
        "hourly_volume": [
            ObservabilityHourlyVolume(hour_utc=hour, count=count)
            for hour, count in sorted(hourly_counter.items())
        ],
        "schema_conformance_percent": schema_status.conformance_percent if schema_status else None,
        "recent_traces": recent_traces,
    }
