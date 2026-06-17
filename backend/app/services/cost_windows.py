from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional
from zoneinfo import ZoneInfo

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import BudgetPolicy, CostEvent

SUPPORTED_BUDGET_WINDOW_TYPES = frozenset({"realtime", "daily", "adhoc", "weekly", "monthly", "yearly"})
BUDGET_WINDOW_ALIASES = {"hourly": "realtime"}
SUPPORTED_COMPARISON_PERIODS = frozenset({"realtime", "daily", "weekly", "monthly", "yearly"})
COMPARISON_PERIOD_ALIASES = {
    "1d": "daily",
    "1w": "weekly",
    "1m": "monthly",
    "1y": "yearly",
    "last_month": "monthly",
    "last_year": "yearly",
    "current_month": "monthly",
    "current_year": "yearly",
}
SUPPORTED_COMPARISON_MODES = frozenset({"prior_period", "same_elapsed"})
REALTIME_WINDOW = timedelta(minutes=15)
HISTORICAL_PERIODS = 3


@dataclass
class CostWindowProjection:
    projected_window_spend_cents: int
    historical_window_spend_cents: int
    prior_periods_considered: int
    projection_basis: str
    linear_extrapolation_cents: int
    historical_average_cents: int


@dataclass
class PeriodSpendSnapshot:
    label: str
    start: datetime
    end: datetime
    spend_cents: int
    event_count: int


@dataclass
class CostPeriodComparison:
    comparison_period: str
    comparison_mode: str
    current: PeriodSpendSnapshot
    previous: PeriodSpendSnapshot
    delta_cents: int
    delta_percent: float
    trend: str


def normalize_comparison_period(period: str | None) -> str:
    normalized = str(period or "monthly").strip().lower()
    normalized = COMPARISON_PERIOD_ALIASES.get(normalized, normalized)
    if normalized not in SUPPORTED_COMPARISON_PERIODS:
        raise ValueError(
            f"comparison period must be one of: {', '.join(sorted(SUPPORTED_COMPARISON_PERIODS))}"
        )
    return normalized


def normalize_comparison_mode(mode: str | None) -> str:
    normalized = str(mode or "prior_period").strip().lower()
    if normalized not in SUPPORTED_COMPARISON_MODES:
        raise ValueError(
            f"comparison_mode must be one of: {', '.join(sorted(SUPPORTED_COMPARISON_MODES))}"
        )
    return normalized


def normalize_window_type(window_type: str | None) -> str:
    normalized = str(window_type or "daily").strip().lower()
    normalized = BUDGET_WINDOW_ALIASES.get(normalized, normalized)
    if normalized not in SUPPORTED_BUDGET_WINDOW_TYPES:
        raise ValueError(
            f"window_type must be one of: {', '.join(sorted(SUPPORTED_BUDGET_WINDOW_TYPES))}"
        )
    return normalized


def _resolve_timezone(name: str | None) -> ZoneInfo:
    try:
        return ZoneInfo(str(name or "UTC").strip() or "UTC")
    except Exception:
        return ZoneInfo("UTC")


def window_start_for_budget(
    budget: BudgetPolicy,
    window_type: str,
    *,
    now_utc: datetime | None = None,
) -> datetime | None:
    now_utc = now_utc or datetime.utcnow()
    resolved_window = normalize_window_type(window_type or budget.window_type)
    tz = _resolve_timezone(getattr(budget, "reset_timezone", "UTC"))
    local_now = now_utc.replace(tzinfo=ZoneInfo("UTC")).astimezone(tz)
    reset_hour = int(getattr(budget, "reset_hour_local", 0) or 0)

    if resolved_window == "realtime":
        return now_utc - REALTIME_WINDOW

    if resolved_window == "adhoc":
        created_at = getattr(budget, "created_at", None)
        return created_at.replace(tzinfo=None) if created_at else None

    if resolved_window == "daily":
        local_reset = local_now.replace(hour=reset_hour, minute=0, second=0, microsecond=0)
        if local_now < local_reset:
            local_reset = local_reset - timedelta(days=1)
        return local_reset.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

    if resolved_window == "weekly":
        local_reset = local_now.replace(hour=reset_hour, minute=0, second=0, microsecond=0)
        if local_now < local_reset:
            local_reset = local_reset - timedelta(days=1)
        local_reset = local_reset - timedelta(days=6)
        return local_reset.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

    if resolved_window == "monthly":
        local_reset = local_now.replace(day=1, hour=reset_hour, minute=0, second=0, microsecond=0)
        if local_now < local_reset:
            if local_now.month == 1:
                local_reset = local_reset.replace(year=local_now.year - 1, month=12)
            else:
                local_reset = local_reset.replace(month=local_now.month - 1)
        return local_reset.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

    if resolved_window == "yearly":
        local_reset = local_now.replace(month=1, day=1, hour=reset_hour, minute=0, second=0, microsecond=0)
        if local_now < local_reset:
            local_reset = local_reset.replace(year=local_now.year - 1)
        return local_reset.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

    return None


def window_end_for_budget(
    budget: BudgetPolicy,
    window_type: str,
    *,
    now_utc: datetime | None = None,
) -> datetime:
    now_utc = now_utc or datetime.utcnow()
    resolved_window = normalize_window_type(window_type or budget.window_type)
    tz = _resolve_timezone(getattr(budget, "reset_timezone", "UTC"))
    local_now = now_utc.replace(tzinfo=ZoneInfo("UTC")).astimezone(tz)
    reset_hour = int(getattr(budget, "reset_hour_local", 0) or 0)

    if resolved_window == "realtime":
        return now_utc

    if resolved_window == "adhoc":
        return now_utc

    if resolved_window == "daily":
        local_reset = local_now.replace(hour=reset_hour, minute=0, second=0, microsecond=0)
        if local_now >= local_reset:
            local_reset = local_reset + timedelta(days=1)
        return local_reset.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

    if resolved_window == "weekly":
        start = window_start_for_budget(budget, resolved_window, now_utc=now_utc)
        if start is None:
            return now_utc + timedelta(days=7)
        return start + timedelta(days=7)

    if resolved_window == "monthly":
        local_reset = local_now.replace(day=1, hour=reset_hour, minute=0, second=0, microsecond=0)
        if local_now.month == 12:
            next_reset = local_reset.replace(year=local_now.year + 1, month=1)
        else:
            next_reset = local_reset.replace(month=local_now.month + 1)
        return next_reset.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

    if resolved_window == "yearly":
        local_reset = local_now.replace(month=1, day=1, hour=reset_hour, minute=0, second=0, microsecond=0)
        next_reset = local_reset.replace(year=local_now.year + 1)
        return next_reset.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

    return now_utc


def window_duration_seconds(
    budget: BudgetPolicy,
    window_type: str,
    *,
    now_utc: datetime | None = None,
) -> int:
    now_utc = now_utc or datetime.utcnow()
    resolved_window = normalize_window_type(window_type or budget.window_type)
    if resolved_window == "realtime":
        return int(REALTIME_WINDOW.total_seconds())
    if resolved_window == "adhoc":
        start = window_start_for_budget(budget, resolved_window, now_utc=now_utc)
        if start is None:
            return 86400
        return max(int((now_utc - start).total_seconds()), 3600)
    start = window_start_for_budget(budget, resolved_window, now_utc=now_utc)
    end = window_end_for_budget(budget, resolved_window, now_utc=now_utc)
    return max(int((end - start).total_seconds()), 60)


def _sum_cost_between(
    db: Session,
    *,
    owner_scope: str,
    start_ts: datetime | None,
    end_ts: datetime | None,
) -> int:
    query = db.query(func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0)).filter(
        CostEvent.owner_scope == owner_scope
    )
    if start_ts is not None:
        query = query.filter(CostEvent.timestamp >= start_ts)
    if end_ts is not None:
        query = query.filter(CostEvent.timestamp < end_ts)
    return int(query.scalar() or 0)


def _previous_period_bounds(
    budget: BudgetPolicy,
    window_type: str,
    *,
    now_utc: datetime | None = None,
) -> tuple[datetime | None, datetime | None]:
    now_utc = now_utc or datetime.utcnow()
    resolved_window = normalize_window_type(window_type or budget.window_type)
    current_start = window_start_for_budget(budget, resolved_window, now_utc=now_utc)
    if current_start is None:
        return None, None

    if resolved_window == "realtime":
        previous_end = current_start
        previous_start = previous_end - REALTIME_WINDOW
        return previous_start, previous_end

    if resolved_window == "adhoc":
        return None, None

    if resolved_window == "daily":
        return current_start - timedelta(days=1), current_start

    if resolved_window == "weekly":
        return current_start - timedelta(days=7), current_start

    if resolved_window == "monthly":
        tz = _resolve_timezone(getattr(budget, "reset_timezone", "UTC"))
        local_start = current_start.replace(tzinfo=ZoneInfo("UTC")).astimezone(tz)
        if local_start.month == 1:
            previous_local = local_start.replace(year=local_start.year - 1, month=12)
        else:
            previous_local = local_start.replace(month=local_start.month - 1)
        previous_start = previous_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
        return previous_start, current_start

    if resolved_window == "yearly":
        tz = _resolve_timezone(getattr(budget, "reset_timezone", "UTC"))
        local_start = current_start.replace(tzinfo=ZoneInfo("UTC")).astimezone(tz)
        previous_local = local_start.replace(year=local_start.year - 1)
        previous_start = previous_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
        return previous_start, current_start

    return None, None


def _historical_window_spend(
    db: Session,
    *,
    owner_scope: str,
    budget: BudgetPolicy,
    window_type: str,
    now_utc: datetime | None = None,
) -> tuple[int, int]:
    now_utc = now_utc or datetime.utcnow()
    resolved_window = normalize_window_type(window_type or budget.window_type)

    if resolved_window == "adhoc":
        start = window_start_for_budget(budget, resolved_window, now_utc=now_utc)
        if start is None:
            return 0, 0
        lookback_start = max(start, now_utc - timedelta(days=7))
        total = _sum_cost_between(db, owner_scope=owner_scope, start_ts=lookback_start, end_ts=now_utc)
        days = max((now_utc - lookback_start).total_seconds() / 86400.0, 1.0)
        return int(total), 0

    samples: list[int] = []
    cursor_now = now_utc
    for _ in range(HISTORICAL_PERIODS):
        prev_start, prev_end = _previous_period_bounds(budget, resolved_window, now_utc=cursor_now)
        if prev_start is None or prev_end is None:
            break
        samples.append(_sum_cost_between(db, owner_scope=owner_scope, start_ts=prev_start, end_ts=prev_end))
        cursor_now = prev_start

    if not samples:
        return 0, 0
    return int(sum(samples)), len(samples)


def project_window_spend(
    db: Session,
    *,
    owner_scope: str,
    budget: BudgetPolicy,
    window_type: str,
    current_spend_cents: int,
    now_utc: datetime | None = None,
) -> CostWindowProjection:
    now_utc = now_utc or datetime.utcnow()
    resolved_window = normalize_window_type(window_type or budget.window_type)
    window_start = window_start_for_budget(budget, resolved_window, now_utc=now_utc)
    window_seconds = window_duration_seconds(budget, resolved_window, now_utc=now_utc)
    elapsed_seconds = max(int((now_utc - window_start).total_seconds()), 60) if window_start else 60

    linear_extrapolation = int(round(current_spend_cents * (window_seconds / elapsed_seconds)))
    historical_total, periods = _historical_window_spend(
        db,
        owner_scope=owner_scope,
        budget=budget,
        window_type=resolved_window,
        now_utc=now_utc,
    )

    if resolved_window == "adhoc":
        if periods == 0 and window_start:
            lookback_start = max(window_start, now_utc - timedelta(days=7))
            days = max((now_utc - lookback_start).total_seconds() / 86400.0, 1.0)
            daily_rate = historical_total / days
            projected = int(round(daily_rate * 30))
            return CostWindowProjection(
                projected_window_spend_cents=max(projected, current_spend_cents),
                historical_window_spend_cents=historical_total,
                prior_periods_considered=0,
                projection_basis="adhoc_daily_rate",
                linear_extrapolation_cents=linear_extrapolation,
                historical_average_cents=int(round(daily_rate * 30)),
            )
        return CostWindowProjection(
            projected_window_spend_cents=max(linear_extrapolation, current_spend_cents),
            historical_window_spend_cents=historical_total,
            prior_periods_considered=periods,
            projection_basis="linear_extrapolation",
            linear_extrapolation_cents=linear_extrapolation,
            historical_average_cents=0,
        )

    historical_average = int(round(historical_total / periods)) if periods else 0
    if periods and linear_extrapolation:
        projected = int(round((linear_extrapolation * 0.6) + (historical_average * 0.4)))
        basis = "blended"
    elif periods:
        projected = historical_average
        basis = "historical_average"
    else:
        projected = linear_extrapolation
        basis = "linear_extrapolation"

    return CostWindowProjection(
        projected_window_spend_cents=max(projected, current_spend_cents),
        historical_window_spend_cents=historical_average,
        prior_periods_considered=periods,
        projection_basis=basis,
        linear_extrapolation_cents=linear_extrapolation,
        historical_average_cents=historical_average,
    )


def _shift_local_month(local_dt, months: int):
    month_index = local_dt.year * 12 + (local_dt.month - 1) + months
    year = month_index // 12
    month = (month_index % 12) + 1
    return local_dt.replace(year=year, month=month)


def comparison_period_bounds(
    period: str,
    *,
    timezone: str = "UTC",
    reset_hour_local: int = 0,
    now_utc: datetime | None = None,
    comparison_mode: str = "prior_period",
    segment: str = "current",
) -> tuple[datetime, datetime, str]:
    now_utc = now_utc or datetime.utcnow()
    resolved_period = normalize_comparison_period(period)
    resolved_mode = normalize_comparison_mode(comparison_mode)
    tz = _resolve_timezone(timezone)
    local_now = now_utc.replace(tzinfo=ZoneInfo("UTC")).astimezone(tz)
    reset_hour = int(reset_hour_local or 0)

    if resolved_period == "realtime":
        if segment == "current":
            start = now_utc - REALTIME_WINDOW
            end = now_utc
            label = "current realtime window"
        else:
            end = now_utc - REALTIME_WINDOW
            start = end - REALTIME_WINDOW
            label = "previous realtime window"
        return start, end, label

    if resolved_period == "daily":
        local_start = local_now.replace(hour=reset_hour, minute=0, second=0, microsecond=0)
        if local_now < local_start:
            local_start = local_start - timedelta(days=1)
        if segment == "current":
            start = local_start.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            end = now_utc
            label = "today"
        elif resolved_mode == "same_elapsed":
            elapsed = now_utc - local_start.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            prev_start_local = local_start - timedelta(days=1)
            start = prev_start_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            end = start + elapsed
            label = "yesterday (same elapsed time)"
        else:
            prev_start_local = local_start - timedelta(days=1)
            start = prev_start_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            end = local_start.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            label = "yesterday (full day)"
        return start, end, label

    if resolved_period == "weekly":
        local_start = local_now.replace(hour=reset_hour, minute=0, second=0, microsecond=0)
        if local_now < local_start:
            local_start = local_start - timedelta(days=1)
        local_start = local_start - timedelta(days=6)
        if segment == "current":
            start = local_start.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            end = now_utc
            label = "current week"
        elif resolved_mode == "same_elapsed":
            elapsed = now_utc - local_start.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            prev_start_local = local_start - timedelta(days=7)
            start = prev_start_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            end = start + elapsed
            label = "previous week (same elapsed time)"
        else:
            prev_start_local = local_start - timedelta(days=7)
            start = prev_start_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            end = local_start.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            label = "previous week (full period)"
        return start, end, label

    if resolved_period == "monthly":
        local_start = local_now.replace(day=1, hour=reset_hour, minute=0, second=0, microsecond=0)
        if local_now < local_start:
            local_start = _shift_local_month(local_start, -1)
        if segment == "current":
            start = local_start.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            end = now_utc
            label = "current month"
        elif resolved_mode == "same_elapsed":
            elapsed = now_utc - local_start.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            prev_start_local = _shift_local_month(local_start, -1)
            start = prev_start_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            end = start + elapsed
            label = "last month (same elapsed time)"
        else:
            prev_start_local = _shift_local_month(local_start, -1)
            start = prev_start_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            end = local_start.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            label = "last month (full period)"
        return start, end, label

    if resolved_period == "yearly":
        local_start = local_now.replace(month=1, day=1, hour=reset_hour, minute=0, second=0, microsecond=0)
        if local_now < local_start:
            local_start = local_start.replace(year=local_now.year - 1)
        if segment == "current":
            start = local_start.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            end = now_utc
            label = "current year"
        elif resolved_mode == "same_elapsed":
            elapsed = now_utc - local_start.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            prev_start_local = local_start.replace(year=local_start.year - 1)
            start = prev_start_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            end = start + elapsed
            label = "last year (same elapsed time)"
        else:
            prev_start_local = local_start.replace(year=local_start.year - 1)
            start = prev_start_local.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            end = local_start.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)
            label = "last year (full period)"
        return start, end, label

    return now_utc, now_utc, "unknown"


def _sum_cost_events(
    db: Session,
    *,
    start_ts: datetime,
    end_ts: datetime,
    owner_scope: str | None = None,
    agent_ids: list[str] | None = None,
    dimension: str = "all",
    scope_filter: str | None = None,
) -> tuple[int, int]:
    query = db.query(CostEvent).filter(CostEvent.timestamp >= start_ts, CostEvent.timestamp < end_ts)

    if owner_scope:
        query = query.filter(CostEvent.owner_scope == owner_scope)
    if agent_ids is not None:
        if not agent_ids:
            return 0, 0
        query = query.filter(CostEvent.agent_id.in_(agent_ids))

    normalized_dimension = str(dimension or "all").strip().lower()
    scope_filter_text = str(scope_filter or "").strip().lower()
    spend_cents = 0
    event_count = 0

    for event in query.all():
        if normalized_dimension == "request_tag":
            normalized_tag = str(event.request_tag or "untagged").strip().lower()
            if scope_filter_text and scope_filter_text not in normalized_tag:
                continue
        elif normalized_dimension != "all":
            raw_scope = str(event.owner_scope or "")
            if ":" not in raw_scope:
                scope_type, scope_id = "all", raw_scope
            else:
                scope_type, scope_id = raw_scope.split(":", 1)
            if scope_type.strip().lower() != normalized_dimension:
                continue
            if scope_filter_text and scope_filter_text not in str(scope_id or "").strip().lower():
                continue
        spend_cents += int(event.estimated_cost_cents or 0)
        event_count += 1

    return spend_cents, event_count


def build_period_comparison(
    db: Session,
    *,
    period: str,
    comparison_mode: str = "prior_period",
    timezone: str = "UTC",
    reset_hour_local: int = 0,
    owner_scope: str | None = None,
    agent_ids: list[str] | None = None,
    dimension: str = "all",
    scope_filter: str | None = None,
    now_utc: datetime | None = None,
) -> CostPeriodComparison:
    resolved_period = normalize_comparison_period(period)
    resolved_mode = normalize_comparison_mode(comparison_mode)
    current_start, current_end, current_label = comparison_period_bounds(
        resolved_period,
        timezone=timezone,
        reset_hour_local=reset_hour_local,
        now_utc=now_utc,
        comparison_mode=resolved_mode,
        segment="current",
    )
    previous_start, previous_end, previous_label = comparison_period_bounds(
        resolved_period,
        timezone=timezone,
        reset_hour_local=reset_hour_local,
        now_utc=now_utc,
        comparison_mode=resolved_mode,
        segment="previous",
    )

    current_spend, current_events = _sum_cost_events(
        db,
        start_ts=current_start,
        end_ts=current_end,
        owner_scope=owner_scope,
        agent_ids=agent_ids,
        dimension=dimension,
        scope_filter=scope_filter,
    )
    previous_spend, previous_events = _sum_cost_events(
        db,
        start_ts=previous_start,
        end_ts=previous_end,
        owner_scope=owner_scope,
        agent_ids=agent_ids,
        dimension=dimension,
        scope_filter=scope_filter,
    )

    delta_cents = current_spend - previous_spend
    if previous_spend > 0:
        delta_percent = round((delta_cents / previous_spend) * 100.0, 2)
    elif current_spend > 0:
        delta_percent = 100.0
    else:
        delta_percent = 0.0

    if delta_cents > 0:
        trend = "up"
    elif delta_cents < 0:
        trend = "down"
    else:
        trend = "flat"

    return CostPeriodComparison(
        comparison_period=resolved_period,
        comparison_mode=resolved_mode,
        current=PeriodSpendSnapshot(
            label=current_label,
            start=current_start,
            end=current_end,
            spend_cents=current_spend,
            event_count=current_events,
        ),
        previous=PeriodSpendSnapshot(
            label=previous_label,
            start=previous_start,
            end=previous_end,
            spend_cents=previous_spend,
            event_count=previous_events,
        ),
        delta_cents=delta_cents,
        delta_percent=delta_percent,
        trend=trend,
    )

