from __future__ import annotations

from datetime import date, datetime, timedelta
import json
import re
from typing import Optional
from uuid import uuid4
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import Agent, BudgetPolicy, CostEvent, SessionRecord
from app.policy_constants import ROLE_AGENT_OWNER, SUPPORTED_BUDGET_SCOPE_TYPES, COST_SCOPE_AGENT, COST_SCOPE_GROUP, COST_SCOPE_TEAM
from app.router_constants import PLATFORM_ADMIN_EQUIVALENT_ROLES, ROLES_ADMIN_OWNER, ROLES_ADMIN_RELEASE_OWNER
from app.schemas import (
    BudgetPolicyCreateRequest,
    BudgetPolicyResponse,
    CostAnomalyResponse,
    CostBreakdownResponse,
    CostEventResponse,
    CostPricingCalculateRequest,
    CostPricingCalculateResponse,
    CostPricingCatalogResponse,
    CostLimitEvaluateRequest,
    CostLimitEvaluateResponse,
    CostLiveResponse,
    CostPolicyEvaluateRequest,
    CostPolicyEvaluateResponse,
    CostTrackSpendRequest,
    CostTimeseriesResponse,
)
from app.security import ActorContext, get_actor_context, require_role
from app.services.audit import create_audit_event
from app.services.cost_limits import evaluate_actor_cost_limits
from app.services.scope_registry import normalize_scope_id_list, normalize_scope_reference
from app.services.runtime_config import get_runtime_config, get_runtime_config_int
from app.models import DirectoryTeamMembership
from app.runtime_constants import (
    RUNTIME_CONFIG_COST_CLOUD_COMPONENT_MULTIPLIERS_JSON,
    RUNTIME_CONFIG_COST_MODEL_TOKEN_RATES_JSON,
    RUNTIME_CONFIG_COST_PROVIDER_DISCOUNTS_JSON,
)

router = APIRouter()
logger = get_logger(__name__)
REQUEST_TAG_PATTERN = re.compile(r"^[a-zA-Z0-9._:-]{1,64}$")


def _normalize_request_tag(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if not REQUEST_TAG_PATTERN.match(raw):
        raise HTTPException(status_code=422, detail="request_tag must match ^[a-zA-Z0-9._:-]{1,64}$")
    return raw


def _parse_runtime_json_object(raw: str, fallback: dict) -> dict:
    try:
        parsed = json.loads(raw)
    except Exception:
        return fallback
    return parsed if isinstance(parsed, dict) else fallback


def _parse_non_negative_float(value: object, default: float) -> float:
    try:
        parsed = float(value)
    except Exception:
        return default
    return parsed if parsed >= 0 else default


def _parse_positive_float(value: object, default: float) -> float:
    parsed = _parse_non_negative_float(value, default)
    return parsed if parsed > 0 else default


def _load_model_token_rates(db: Session) -> tuple[dict[str, dict[str, float]], dict[str, float]]:
    fallback_raw = '{"default":{"input_cents_per_1k":1.0,"output_cents_per_1k":2.0}}'
    raw = get_runtime_config(db, RUNTIME_CONFIG_COST_MODEL_TOKEN_RATES_JSON, fallback_raw)
    parsed = _parse_runtime_json_object(raw, {"default": {"input_cents_per_1k": 1.0, "output_cents_per_1k": 2.0}})

    default_block = parsed.get("default") if isinstance(parsed.get("default"), dict) else {}
    default_rates = {
        "input_cents_per_1k": _parse_non_negative_float(default_block.get("input_cents_per_1k"), 1.0),
        "output_cents_per_1k": _parse_non_negative_float(default_block.get("output_cents_per_1k"), 2.0),
    }

    model_blocks = parsed.get("models") if isinstance(parsed.get("models"), dict) else {}
    if not model_blocks:
        model_blocks = {key: value for key, value in parsed.items() if key not in {"default", "models"} and isinstance(value, dict)}

    normalized: dict[str, dict[str, float]] = {}
    for model_name, rate_block in model_blocks.items():
        key = str(model_name or "").strip().lower()
        if not key or not isinstance(rate_block, dict):
            continue
        normalized[key] = {
            "input_cents_per_1k": _parse_non_negative_float(
                rate_block.get("input_cents_per_1k"),
                default_rates["input_cents_per_1k"],
            ),
            "output_cents_per_1k": _parse_non_negative_float(
                rate_block.get("output_cents_per_1k"),
                default_rates["output_cents_per_1k"],
            ),
        }
    return normalized, default_rates


def _load_cloud_component_multipliers(db: Session) -> tuple[dict[str, float], dict[str, float]]:
    fallback_raw = '{"provider_type":{"aws":1.0,"azure":1.0,"gcp":1.0,"openai":1.0,"anthropic":1.0},"endpoint_family":{"responses":1.0}}'
    raw = get_runtime_config(db, RUNTIME_CONFIG_COST_CLOUD_COMPONENT_MULTIPLIERS_JSON, fallback_raw)
    parsed = _parse_runtime_json_object(raw, {"provider_type": {}, "endpoint_family": {}})

    provider_map: dict[str, float] = {}
    endpoint_map: dict[str, float] = {}

    provider_raw = parsed.get("provider_type") if isinstance(parsed.get("provider_type"), dict) else {}
    endpoint_raw = parsed.get("endpoint_family") if isinstance(parsed.get("endpoint_family"), dict) else {}

    for key, value in provider_raw.items():
        provider_map[str(key or "").strip().lower()] = _parse_positive_float(value, 1.0)
    for key, value in endpoint_raw.items():
        endpoint_map[str(key or "").strip().lower()] = _parse_positive_float(value, 1.0)

    return provider_map, endpoint_map


def _load_provider_discounts(db: Session) -> tuple[dict[str, float], dict[str, float]]:
    fallback_raw = '{"provider_type":{"aws":0.0,"azure":0.0,"gcp":0.0,"openai":0.0,"anthropic":0.0},"models":{}}'
    raw = get_runtime_config(db, RUNTIME_CONFIG_COST_PROVIDER_DISCOUNTS_JSON, fallback_raw)
    parsed = _parse_runtime_json_object(raw, {"provider_type": {}, "models": {}})

    provider_map_raw = parsed.get("provider_type") if isinstance(parsed.get("provider_type"), dict) else {}
    model_map_raw = parsed.get("models") if isinstance(parsed.get("models"), dict) else {}

    provider_map: dict[str, float] = {}
    model_map: dict[str, float] = {}

    for key, value in provider_map_raw.items():
        provider_map[str(key or "").strip().lower()] = max(0.0, min(95.0, _parse_non_negative_float(value, 0.0)))
    for key, value in model_map_raw.items():
        model_map[str(key or "").strip().lower()] = max(0.0, min(95.0, _parse_non_negative_float(value, 0.0)))

    return provider_map, model_map


def _calculate_estimated_cost_cents(
    *,
    input_tokens: int,
    output_tokens: int,
    model_name: str,
    provider_type: str,
    endpoint_family: str,
    model_rates: dict[str, dict[str, float]],
    default_model_rates: dict[str, float],
    provider_multipliers: dict[str, float],
    endpoint_multipliers: dict[str, float],
    provider_discounts: dict[str, float],
    model_discounts: dict[str, float],
    custom_input_rate: float | None = None,
    custom_output_rate: float | None = None,
    custom_discount_percent: float | None = None,
) -> CostPricingCalculateResponse:
    normalized_model = str(model_name or "").strip().lower()
    normalized_provider_type = str(provider_type or "").strip().lower()
    normalized_endpoint_family = str(endpoint_family or "").strip().lower()

    rates = model_rates.get(normalized_model, default_model_rates)
    input_rate = _parse_non_negative_float(rates.get("input_cents_per_1k"), default_model_rates["input_cents_per_1k"])
    output_rate = _parse_non_negative_float(rates.get("output_cents_per_1k"), default_model_rates["output_cents_per_1k"])
    if custom_input_rate is not None:
        input_rate = max(0.0, float(custom_input_rate))
    if custom_output_rate is not None:
        output_rate = max(0.0, float(custom_output_rate))

    provider_multiplier = _parse_positive_float(provider_multipliers.get(normalized_provider_type, 1.0), 1.0)
    endpoint_multiplier = _parse_positive_float(endpoint_multipliers.get(normalized_endpoint_family, 1.0), 1.0)
    provider_discount = max(0.0, min(95.0, _parse_non_negative_float(provider_discounts.get(normalized_provider_type, 0.0), 0.0)))
    model_discount = max(0.0, min(95.0, _parse_non_negative_float(model_discounts.get(normalized_model, 0.0), 0.0)))
    custom_discount = max(0.0, min(95.0, float(custom_discount_percent or 0.0)))
    applied_discount = min(95.0, provider_discount + model_discount + custom_discount)

    base_cost = ((max(0, input_tokens) / 1000.0) * input_rate) + ((max(0, output_tokens) / 1000.0) * output_rate)
    weighted = base_cost * provider_multiplier * endpoint_multiplier
    discounted = weighted * (1.0 - applied_discount / 100.0)

    base_cents = 0 if weighted <= 0 else max(1, int(round(weighted)))
    estimated_cents = 0 if discounted <= 0 else max(1, int(round(discounted)))

    return CostPricingCalculateResponse(
        provider_type=normalized_provider_type,
        model_name=str(model_name or "").strip(),
        endpoint_family=normalized_endpoint_family,
        input_tokens=max(0, int(input_tokens or 0)),
        output_tokens=max(0, int(output_tokens or 0)),
        input_cents_per_1k=input_rate,
        output_cents_per_1k=output_rate,
        provider_multiplier=provider_multiplier,
        endpoint_multiplier=endpoint_multiplier,
        provider_discount_percent=provider_discount,
        model_discount_percent=model_discount,
        custom_discount_percent=custom_discount,
        applied_discount_percent=applied_discount,
        base_cost_cents=base_cents,
        estimated_cost_cents=estimated_cents,
    )


def _sum_cost_cents(db: Session, after_ts: Optional[datetime] = None, **filters: str) -> int:
    query = db.query(func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0))
    if after_ts:
        query = query.filter(CostEvent.timestamp >= after_ts)
    for field, value in filters.items():
        query = query.filter(getattr(CostEvent, field) == value)
    return int(query.scalar() or 0)


def _owned_agent_ids(db: Session, actor_id: str) -> list[str]:
    return [row[0] for row in db.query(Agent.agent_id).filter(Agent.owner_id == actor_id).all()]


def _window_start(window_type: str) -> Optional[datetime]:
    now = datetime.utcnow()
    if window_type == "daily":
        return now - timedelta(days=1)
    if window_type == "monthly":
        return now - timedelta(days=30)
    return None


def _resolve_timezone(name: str | None) -> ZoneInfo:
    try:
        return ZoneInfo(str(name or "UTC").strip() or "UTC")
    except Exception:
        return ZoneInfo("UTC")


def _window_start_for_budget(budget: BudgetPolicy, window_type: str) -> Optional[datetime]:
    now_utc = datetime.utcnow()
    resolved_window = str(window_type or budget.window_type or "daily").strip().lower()
    tz = _resolve_timezone(getattr(budget, "reset_timezone", "UTC"))
    local_now = now_utc.replace(tzinfo=ZoneInfo("UTC")).astimezone(tz)
    reset_hour = int(getattr(budget, "reset_hour_local", 0) or 0)

    if resolved_window == "hourly":
        return now_utc - timedelta(hours=1)

    if resolved_window == "daily":
        local_reset = local_now.replace(hour=reset_hour, minute=0, second=0, microsecond=0)
        if local_now < local_reset:
            local_reset = local_reset - timedelta(days=1)
        return local_reset.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

    if resolved_window == "monthly":
        local_reset = local_now.replace(day=1, hour=reset_hour, minute=0, second=0, microsecond=0)
        if local_now < local_reset:
            if local_now.month == 1:
                local_reset = local_reset.replace(year=local_now.year - 1, month=12)
            else:
                local_reset = local_reset.replace(month=local_now.month - 1)
        return local_reset.astimezone(ZoneInfo("UTC")).replace(tzinfo=None)

    return _window_start(resolved_window)


def _effective_budget_cents(budget: BudgetPolicy) -> int:
    base = int(budget.budget_amount_cents or 0)
    extra = int(getattr(budget, "temporary_increase_cents", 0) or 0)
    expires_at = getattr(budget, "temporary_increase_expires_at", None)
    if extra <= 0:
        return base
    if expires_at is None or expires_at >= datetime.utcnow():
        return base + extra
    return base


def _is_jwt_team(team_id: str) -> bool:
    normalized = str(team_id or "").strip().lower()
    return normalized.startswith("jwt-") or normalized.startswith("jwt:")


def _ensure_default_jwt_team_budget(db: Session, team_id: str, actor_id: str) -> None:
    if not _is_jwt_team(team_id):
        return
    existing = (
        db.query(BudgetPolicy)
        .filter_by(scope_type=COST_SCOPE_TEAM, scope_id=team_id, status="active")
        .order_by(BudgetPolicy.created_at.desc())
        .first()
    )
    if existing:
        return

    default_budget_cents = get_runtime_config_int(db, "cost.jwt_team.default_budget_cents", 50000)
    default_soft_limit = get_runtime_config_int(db, "cost.jwt_team.default_soft_limit_percent", 80)
    default_hard_limit = get_runtime_config_int(db, "cost.jwt_team.default_hard_limit_percent", 100)

    policy = BudgetPolicy(
        budget_policy_id=str(uuid4()),
        scope_type=COST_SCOPE_TEAM,
        scope_id=team_id,
        budget_amount_cents=default_budget_cents,
        window_type="daily",
        soft_limit_percent=max(1, min(default_soft_limit, 100)),
        hard_limit_percent=max(1, min(default_hard_limit, 100)),
        action_on_soft_limit="warn",
        action_on_hard_limit="block",
        reset_timezone="UTC",
        reset_hour_local=0,
        status="active",
    )
    db.add(policy)
    create_audit_event(
        db,
        actor_id=actor_id,
        action_type="cost.budget.auto_create_jwt_team",
        resource_type="budget_policy",
        resource_id=policy.budget_policy_id,
        trace_id=f"trace-{policy.budget_policy_id}",
    )


def _is_budget_scope_manageable(db: Session, ctx: ActorContext, scope_type: str, scope_id: str) -> bool:
    if ctx.actor_role in PLATFORM_ADMIN_EQUIVALENT_ROLES:
        return True
    if ctx.actor_role != ROLE_AGENT_OWNER:
        return False
    if scope_type in {"user", "owner", "actor"}:
        return scope_id == ctx.actor_id
    if scope_type == COST_SCOPE_TEAM:
        return db.query(DirectoryTeamMembership).filter_by(team_id=scope_id, user_id=ctx.actor_id).first() is not None
    if scope_type == "agent":
        return db.query(Agent).filter_by(agent_id=scope_id, owner_id=ctx.actor_id).first() is not None
    return False


def _split_owner_scope(owner_scope: str) -> tuple[str, str]:
    raw = str(owner_scope or "").strip()
    if ":" not in raw:
        return "all", raw or "unscoped"
    scope_type, scope_id = raw.split(":", 1)
    return scope_type.strip().lower() or "all", scope_id.strip() or "unscoped"


def _floor_hour(value: datetime) -> datetime:
    return value.replace(minute=0, second=0, microsecond=0)


@router.get("/cost/live", response_model=CostLiveResponse)
def get_live_cost(db: Session = Depends(get_db), ctx: ActorContext = Depends(get_actor_context)):
    require_role(ctx, ROLES_ADMIN_OWNER)
    now = datetime.utcnow()
    hour_ts = now - timedelta(hours=1)
    day_ts = now - timedelta(days=1)

    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return {
                "spend_last_hour_cents": 0,
                "spend_last_day_cents": 0,
                "burn_rate_cents_per_hour": 0,
                "event_count_last_day": 0,
            }

        spend_last_hour = int(
            db.query(func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0))
            .filter(CostEvent.timestamp >= hour_ts, CostEvent.agent_id.in_(owned_agent_ids))
            .scalar()
            or 0
        )
        spend_last_day = int(
            db.query(func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0))
            .filter(CostEvent.timestamp >= day_ts, CostEvent.agent_id.in_(owned_agent_ids))
            .scalar()
            or 0
        )
        event_count_last_day = (
            db.query(func.count(CostEvent.cost_event_id))
            .filter(CostEvent.timestamp >= day_ts, CostEvent.agent_id.in_(owned_agent_ids))
            .scalar()
            or 0
        )
    else:
        spend_last_hour = _sum_cost_cents(db, after_ts=hour_ts)
        spend_last_day = _sum_cost_cents(db, after_ts=day_ts)
        event_count_last_day = (
            db.query(func.count(CostEvent.cost_event_id)).filter(CostEvent.timestamp >= day_ts).scalar() or 0
        )

    return {
        "spend_last_hour_cents": spend_last_hour,
        "spend_last_day_cents": spend_last_day,
        "burn_rate_cents_per_hour": spend_last_hour,
        "event_count_last_day": int(event_count_last_day),
    }


@router.get("/cost/breakdown", response_model=CostBreakdownResponse)
def get_cost_breakdown(
    dimension: str = "all",
    window_hours: int = 24,
    limit: int = 8,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)

    normalized_dimension = str(dimension or "all").strip().lower()
    allowed_dimensions = {"all", "user", "team", "group", "request_tag"}
    if normalized_dimension not in allowed_dimensions:
        raise HTTPException(status_code=400, detail="dimension must be one of: all, user, team, group, request_tag")

    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    bounded_limit = max(1, min(int(limit or 8), 50))
    since = datetime.utcnow() - timedelta(hours=bounded_hours)

    base_query = db.query(
        CostEvent.owner_scope,
        func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0),
        func.count(CostEvent.cost_event_id),
    ).filter(CostEvent.timestamp >= since)

    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return {
                "dimension": normalized_dimension,
                "window_hours": bounded_hours,
                "total_spend_cents": 0,
                "total_event_count": 0,
                "items": [],
            }
        base_query = base_query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    if normalized_dimension == "request_tag":
        grouped_rows = (
            db.query(
                CostEvent.request_tag,
                func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0),
                func.count(CostEvent.cost_event_id),
            )
            .filter(CostEvent.timestamp >= since)
            .group_by(CostEvent.request_tag)
            .all()
        )
        items = [
            {"label": str(row[0] or "untagged"), "spend_cents": int(row[1] or 0), "event_count": int(row[2] or 0)}
            for row in grouped_rows
        ]
        total_spend_cents = int(sum(item["spend_cents"] for item in items))
        total_event_count = int(sum(item["event_count"] for item in items))
        items.sort(key=lambda row: row["spend_cents"], reverse=True)
        items = items[:bounded_limit]
        return {
            "dimension": normalized_dimension,
            "window_hours": bounded_hours,
            "total_spend_cents": total_spend_cents,
            "total_event_count": total_event_count,
            "items": items,
        }

    grouped_rows = base_query.group_by(CostEvent.owner_scope).all()

    if normalized_dimension == "all":
        total_spend_cents = int(sum(int(row[1] or 0) for row in grouped_rows))
        total_event_count = int(sum(int(row[2] or 0) for row in grouped_rows))
        items = []
        if total_event_count > 0 or total_spend_cents > 0:
            items.append(
                {
                    "label": "All",
                    "spend_cents": total_spend_cents,
                    "event_count": total_event_count,
                }
            )
        return {
            "dimension": normalized_dimension,
            "window_hours": bounded_hours,
            "total_spend_cents": total_spend_cents,
            "total_event_count": total_event_count,
            "items": items,
        }

    buckets: dict[str, dict[str, int]] = {}
    for owner_scope, spend_cents, event_count in grouped_rows:
        scope_type, scope_id = _split_owner_scope(owner_scope)
        if scope_type != normalized_dimension:
            continue
        key = scope_id or "unscoped"
        if key not in buckets:
            buckets[key] = {"spend_cents": 0, "event_count": 0}
        buckets[key]["spend_cents"] += int(spend_cents or 0)
        buckets[key]["event_count"] += int(event_count or 0)

    items = [
        {
            "label": label,
            "spend_cents": values["spend_cents"],
            "event_count": values["event_count"],
        }
        for label, values in buckets.items()
    ]
    total_spend_cents = int(sum(item["spend_cents"] for item in items))
    total_event_count = int(sum(item["event_count"] for item in items))
    items.sort(key=lambda row: row["spend_cents"], reverse=True)
    items = items[:bounded_limit]

    return {
        "dimension": normalized_dimension,
        "window_hours": bounded_hours,
        "total_spend_cents": total_spend_cents,
        "total_event_count": total_event_count,
        "items": items,
    }


@router.get("/cost/timeseries", response_model=CostTimeseriesResponse)
def get_cost_timeseries(
    dimension: str = "all",
    window_hours: int = 24,
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
    start_datetime: Optional[datetime] = None,
    end_datetime: Optional[datetime] = None,
    scope_filter: Optional[str] = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)

    normalized_dimension = str(dimension or "all").strip().lower()
    allowed_dimensions = {"all", "user", "team", "group", "request_tag"}
    if normalized_dimension not in allowed_dimensions:
        raise HTTPException(status_code=400, detail="dimension must be one of: all, user, team, group, request_tag")

    scope_filter_text = str(scope_filter or "").strip().lower()

    if (start_datetime and not end_datetime) or (end_datetime and not start_datetime):
        raise HTTPException(status_code=400, detail="start_datetime and end_datetime must both be provided")

    if start_datetime and end_datetime:
        if end_datetime <= start_datetime:
            raise HTTPException(status_code=400, detail="end_datetime must be greater than start_datetime")
        selected_seconds = (end_datetime - start_datetime).total_seconds()
        if selected_seconds > 24 * 366 * 3600:
            raise HTTPException(status_code=400, detail="date/time range cannot exceed 1 year")
        start_hour = _floor_hour(start_datetime)
        end_hour = _floor_hour(end_datetime)
        bounded_hours = int(((end_hour - start_hour).total_seconds() // 3600) + 1)
        query_start_ts = start_datetime
        query_end_exclusive = end_datetime + timedelta(seconds=1)
    elif (start_date and not end_date) or (end_date and not start_date):
        raise HTTPException(status_code=400, detail="start_date and end_date must both be provided")
    elif start_date and end_date:
        if end_date < start_date:
            raise HTTPException(status_code=400, detail="end_date must be greater than or equal to start_date")
        start_hour = _floor_hour(datetime.combine(start_date, datetime.min.time()))
        end_hour = _floor_hour(datetime.combine(end_date + timedelta(days=1), datetime.min.time()) - timedelta(hours=1))
        bounded_hours = int(((end_hour - start_hour).total_seconds() // 3600) + 1)
        if bounded_hours > 24 * 366:
            raise HTTPException(status_code=400, detail="date range cannot exceed 1 year")
        query_start_ts = start_hour
        query_end_exclusive = end_hour + timedelta(hours=1)
    else:
        bounded_hours = max(1, min(int(window_hours or 24), 24 * 366))
        now = datetime.utcnow()
        end_hour = _floor_hour(now)
        start_hour = end_hour - timedelta(hours=bounded_hours - 1)
        query_start_ts = start_hour
        query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(CostEvent.timestamp, CostEvent.owner_scope, CostEvent.request_tag, CostEvent.estimated_cost_cents).filter(
        CostEvent.timestamp >= query_start_ts,
        CostEvent.timestamp < query_end_exclusive,
    )

    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return {
                "dimension": normalized_dimension,
                "window_hours": bounded_hours,
                "start_time": query_start_ts,
                "end_time": query_end_exclusive,
                "scope_filter": scope_filter_text or None,
                "total_spend_cents": 0,
                "total_event_count": 0,
                "points": [
                    {
                        "hour_start": start_hour + timedelta(hours=i),
                        "spend_cents": 0,
                        "event_count": 0,
                    }
                    for i in range(bounded_hours)
                ],
            }
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    raw_rows = query.all()

    buckets: dict[datetime, dict[str, int]] = {
        start_hour + timedelta(hours=i): {"spend_cents": 0, "event_count": 0}
        for i in range(bounded_hours)
    }

    for timestamp, owner_scope, request_tag, estimated_cost_cents in raw_rows:
        if normalized_dimension == "request_tag":
            normalized_tag = str(request_tag or "untagged").strip().lower()
            if scope_filter_text and scope_filter_text not in normalized_tag:
                continue
        else:
            scope_type, scope_id = _split_owner_scope(owner_scope)
            if normalized_dimension != "all" and scope_type != normalized_dimension:
                continue
            if scope_filter_text and normalized_dimension != "all":
                normalized_scope_id = str(scope_id or "").strip().lower()
                if scope_filter_text not in normalized_scope_id:
                    continue

        hour_bucket = _floor_hour(timestamp)
        if hour_bucket not in buckets:
            continue
        buckets[hour_bucket]["spend_cents"] += int(estimated_cost_cents or 0)
        buckets[hour_bucket]["event_count"] += 1

    points = [
        {
            "hour_start": hour,
            "spend_cents": data["spend_cents"],
            "event_count": data["event_count"],
        }
        for hour, data in sorted(buckets.items(), key=lambda item: item[0])
    ]

    total_spend_cents = int(sum(point["spend_cents"] for point in points))
    total_event_count = int(sum(point["event_count"] for point in points))

    return {
        "dimension": normalized_dimension,
        "window_hours": bounded_hours,
        "start_time": query_start_ts,
        "end_time": query_end_exclusive,
        "scope_filter": scope_filter_text or None,
        "total_spend_cents": total_spend_cents,
        "total_event_count": total_event_count,
        "points": points,
    }


@router.post("/cost/events", response_model=CostEventResponse)
def track_spend_event(
    payload: CostTrackSpendRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)
    scope_type, scope_id = normalize_scope_reference(
        db,
        scope_type=payload.scope_type,
        scope_id=payload.scope_id,
        allowed_scope_types=SUPPORTED_BUDGET_SCOPE_TYPES,
        resource_label="spend scope",
    )
    if not _is_budget_scope_manageable(db, ctx, scope_type, scope_id):
        raise HTTPException(status_code=403, detail="Spend scope is forbidden for this actor")

    if ctx.actor_role == ROLE_AGENT_OWNER:
        agent = db.query(Agent).filter_by(agent_id=payload.agent_id).first()
        if not agent or agent.owner_id != ctx.actor_id:
            raise HTTPException(status_code=403, detail="Agent scope is forbidden for this actor")

    event = CostEvent(
        cost_event_id=str(uuid4()),
        request_id=str(payload.request_id).strip(),
        trace_id=str(payload.trace_id or f"trace-{payload.request_id}").strip(),
        request_tag=_normalize_request_tag(payload.request_tag),
        session_id=str(payload.session_id).strip(),
        agent_id=str(payload.agent_id).strip(),
        owner_scope=f"{scope_type}:{scope_id}",
        environment=str(payload.environment or "dev").strip() or "dev",
        model_name=str(payload.model_name).strip(),
        endpoint_family=str(payload.endpoint_family).strip(),
        input_tokens=max(0, int(payload.input_tokens or 0)),
        output_tokens=max(0, int(payload.output_tokens or 0)),
        estimated_cost_cents=max(0, int(payload.estimated_cost_cents or 0)),
        currency=str(payload.currency or "USD").strip().upper() or "USD",
    )
    db.add(event)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.event.track",
        resource_type="cost_event",
        resource_id=event.cost_event_id,
        trace_id=str(event.trace_id),
    )
    db.commit()
    db.refresh(event)
    return event


@router.get("/cost/pricing/catalog", response_model=CostPricingCatalogResponse)
def get_pricing_catalog(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)
    model_rates, default_rates = _load_model_token_rates(db)
    provider_multipliers, endpoint_multipliers = _load_cloud_component_multipliers(db)
    provider_discounts, model_discounts = _load_provider_discounts(db)
    return {
        "default_model_rates": default_rates,
        "model_rates": model_rates,
        "provider_multipliers": provider_multipliers,
        "endpoint_multipliers": endpoint_multipliers,
        "provider_discounts": provider_discounts,
        "model_discounts": model_discounts,
    }


@router.post("/cost/pricing/calculate", response_model=CostPricingCalculateResponse)
def calculate_cost_pricing(
    payload: CostPricingCalculateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)
    model_rates, default_rates = _load_model_token_rates(db)
    provider_multipliers, endpoint_multipliers = _load_cloud_component_multipliers(db)
    provider_discounts, model_discounts = _load_provider_discounts(db)
    return _calculate_estimated_cost_cents(
        input_tokens=payload.input_tokens,
        output_tokens=payload.output_tokens,
        model_name=payload.model_name,
        provider_type=payload.provider_type,
        endpoint_family=payload.endpoint_family,
        model_rates=model_rates,
        default_model_rates=default_rates,
        provider_multipliers=provider_multipliers,
        endpoint_multipliers=endpoint_multipliers,
        provider_discounts=provider_discounts,
        model_discounts=model_discounts,
        custom_input_rate=payload.custom_input_cents_per_1k,
        custom_output_rate=payload.custom_output_cents_per_1k,
        custom_discount_percent=payload.custom_provider_discount_percent,
    )


@router.get("/cost/sessions/{session_id}", response_model=list[CostEventResponse])
def get_session_cost(
    session_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)
    if ctx.actor_role == ROLE_AGENT_OWNER:
        session = db.query(SessionRecord).filter_by(session_id=session_id).first()
        if not session or session.actor_id != ctx.actor_id:
            raise HTTPException(status_code=403, detail="Session scope is forbidden for this actor")
    return db.query(CostEvent).filter_by(session_id=session_id).order_by(CostEvent.timestamp.desc()).all()


@router.get("/cost/agents/{agent_id}", response_model=list[CostEventResponse])
def get_agent_cost(
    agent_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)
    if ctx.actor_role == ROLE_AGENT_OWNER:
        agent = db.query(Agent).filter_by(agent_id=agent_id).first()
        if not agent or agent.owner_id != ctx.actor_id:
            raise HTTPException(status_code=403, detail="Agent scope is forbidden for this actor")
    return db.query(CostEvent).filter_by(agent_id=agent_id).order_by(CostEvent.timestamp.desc()).all()


@router.post("/cost/budgets", response_model=BudgetPolicyResponse)
def create_budget_policy(
    payload: BudgetPolicyCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "cost_budget_create_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "scope_type": payload.scope_type, "scope_id": payload.scope_id}),
    )
    require_role(ctx, ROLES_ADMIN_RELEASE_OWNER)
    scope_type, scope_id = normalize_scope_reference(
        db,
        scope_type=payload.scope_type,
        scope_id=payload.scope_id,
        allowed_scope_types=SUPPORTED_BUDGET_SCOPE_TYPES,
        resource_label="budget scope",
    )
    if not _is_budget_scope_manageable(db, ctx, scope_type, scope_id):
        raise HTTPException(status_code=403, detail="Budget scope is forbidden for this actor")
    budget = BudgetPolicy(
        budget_policy_id=str(uuid4()),
        scope_type=scope_type,
        scope_id=scope_id,
        budget_amount_cents=payload.budget_amount_cents,
        window_type=payload.window_type,
        soft_limit_percent=payload.soft_limit_percent,
        hard_limit_percent=payload.hard_limit_percent,
        action_on_soft_limit=payload.action_on_soft_limit,
        action_on_hard_limit=payload.action_on_hard_limit,
        reset_timezone=str(payload.reset_timezone or "UTC").strip() or "UTC",
        reset_hour_local=payload.reset_hour_local,
        temporary_increase_cents=payload.temporary_increase_cents,
        temporary_increase_expires_at=payload.temporary_increase_expires_at,
        soft_alert_enabled=payload.soft_alert_enabled,
        rate_limit_tpm=payload.rate_limit_tpm,
        rate_limit_rpm=payload.rate_limit_rpm,
        session_iteration_cap=payload.session_iteration_cap,
        session_budget_cents=payload.session_budget_cents,
        status="active",
    )
    db.add(budget)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.budget.create",
        resource_type="budget_policy",
        resource_id=budget.budget_policy_id,
        trace_id=f"trace-{budget.budget_policy_id}",
    )
    db.commit()
    db.refresh(budget)
    logger.info(
        "cost_budget_create_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "budget_policy_id": budget.budget_policy_id}),
    )
    return budget


@router.get("/cost/budgets", response_model=list[BudgetPolicyResponse])
def list_budget_policies(
    status: Optional[str] = Query(default="active"),
    scope_type: Optional[str] = None,
    scope_id: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)

    query = db.query(BudgetPolicy)
    if status is not None and str(status).strip():
        query = query.filter(BudgetPolicy.status == str(status).strip())
    if scope_type:
        query = query.filter(BudgetPolicy.scope_type == str(scope_type).strip())
    if scope_id:
        query = query.filter(BudgetPolicy.scope_id == str(scope_id).strip())

    if ctx.actor_role == ROLE_AGENT_OWNER:
        team_ids = [
            row[0]
            for row in db.query(DirectoryTeamMembership.team_id)
            .filter(DirectoryTeamMembership.user_id == ctx.actor_id)
            .all()
        ]
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        query = query.filter(
            (BudgetPolicy.scope_type.in_(["owner", "actor", "user"]) & (BudgetPolicy.scope_id == ctx.actor_id))
            | (BudgetPolicy.scope_type == COST_SCOPE_TEAM) & (BudgetPolicy.scope_id.in_(team_ids if team_ids else ["__none__"]))
            | (BudgetPolicy.scope_type == "agent") & (BudgetPolicy.scope_id.in_(owned_agent_ids if owned_agent_ids else ["__none__"]))
        )

    return query.order_by(BudgetPolicy.created_at.desc()).offset(offset).limit(limit).all()


@router.put("/cost/budgets/{budget_policy_id}", response_model=BudgetPolicyResponse)
def update_budget_policy(
    budget_policy_id: str,
    payload: BudgetPolicyCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_OWNER)

    budget = db.query(BudgetPolicy).filter_by(budget_policy_id=budget_policy_id).first()
    if not budget:
        raise HTTPException(status_code=404, detail="Budget policy not found")
    if not _is_budget_scope_manageable(db, ctx, budget.scope_type, budget.scope_id):
        raise HTTPException(status_code=403, detail="Budget policy is forbidden for this actor")

    scope_type, scope_id = normalize_scope_reference(
        db,
        scope_type=payload.scope_type,
        scope_id=payload.scope_id,
        allowed_scope_types=SUPPORTED_BUDGET_SCOPE_TYPES,
        resource_label="budget scope",
    )

    budget.scope_type = scope_type
    budget.scope_id = scope_id
    if not _is_budget_scope_manageable(db, ctx, budget.scope_type, budget.scope_id):
        raise HTTPException(status_code=403, detail="Target budget scope is forbidden for this actor")
    budget.budget_amount_cents = payload.budget_amount_cents
    budget.window_type = payload.window_type
    budget.soft_limit_percent = payload.soft_limit_percent
    budget.hard_limit_percent = payload.hard_limit_percent
    budget.action_on_soft_limit = payload.action_on_soft_limit
    budget.action_on_hard_limit = payload.action_on_hard_limit
    budget.reset_timezone = str(payload.reset_timezone or "UTC").strip() or "UTC"
    budget.reset_hour_local = payload.reset_hour_local
    budget.temporary_increase_cents = payload.temporary_increase_cents
    budget.temporary_increase_expires_at = payload.temporary_increase_expires_at
    budget.soft_alert_enabled = payload.soft_alert_enabled
    budget.rate_limit_tpm = payload.rate_limit_tpm
    budget.rate_limit_rpm = payload.rate_limit_rpm
    budget.session_iteration_cap = payload.session_iteration_cap
    budget.session_budget_cents = payload.session_budget_cents
    if budget.status == "deleted":
        budget.status = "active"

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.budget.update",
        resource_type="budget_policy",
        resource_id=budget.budget_policy_id,
        trace_id=f"trace-{budget.budget_policy_id}",
    )
    db.commit()
    db.refresh(budget)
    return budget


@router.delete("/cost/budgets/{budget_policy_id}", response_model=BudgetPolicyResponse)
def delete_budget_policy(
    budget_policy_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_OWNER)

    budget = db.query(BudgetPolicy).filter_by(budget_policy_id=budget_policy_id).first()
    if not budget:
        raise HTTPException(status_code=404, detail="Budget policy not found")

    if not _is_budget_scope_manageable(db, ctx, budget.scope_type, budget.scope_id):
        raise HTTPException(status_code=403, detail="Budget policy is forbidden for this actor")

    budget.status = "deleted"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.budget.delete",
        resource_type="budget_policy",
        resource_id=budget.budget_policy_id,
        trace_id=f"trace-{budget.budget_policy_id}",
    )
    db.commit()
    db.refresh(budget)
    return budget


@router.post("/cost/policies/evaluate", response_model=CostPolicyEvaluateResponse)
def evaluate_budget_policy(
    payload: CostPolicyEvaluateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "cost_policy_evaluate_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "scope_type": payload.scope_type, "scope_id": payload.scope_id}),
    )
    require_role(ctx, ROLES_ADMIN_RELEASE_OWNER)
    scope_type, scope_id = normalize_scope_reference(
        db,
        scope_type=payload.scope_type,
        scope_id=payload.scope_id,
        allowed_scope_types=SUPPORTED_BUDGET_SCOPE_TYPES,
        resource_label="budget scope",
    )

    budget = (
        db.query(BudgetPolicy)
        .filter_by(scope_type=scope_type, scope_id=scope_id, status="active")
        .order_by(BudgetPolicy.created_at.desc())
        .first()
    )
    if not budget:
        logger.error(
            "cost_policy_evaluate_budget_not_found %s",
            sanitize_fields({"scope_type": scope_type, "scope_id": scope_id}),
        )
        raise HTTPException(status_code=404, detail="Active budget policy not found")

    if not _is_budget_scope_manageable(db, ctx, scope_type, scope_id):
        raise HTTPException(status_code=403, detail="Budget scope is forbidden for this actor")

    now = datetime.utcnow()
    after_ts = _window_start_for_budget(budget, payload.window_type)

    owner_scope = f"{scope_type}:{scope_id}"
    spend_cents = _sum_cost_cents(db, after_ts=after_ts, owner_scope=owner_scope)
    burn_rate_cents_per_hour = _sum_cost_cents(db, after_ts=now - timedelta(hours=1), owner_scope=owner_scope)
    projected_24h_spend_cents = int(spend_cents + (burn_rate_cents_per_hour * 24))

    effective_budget_cents = _effective_budget_cents(budget)
    utilization = 0.0
    if effective_budget_cents > 0:
        utilization = round((spend_cents / effective_budget_cents) * 100.0, 2)
    projected_utilization = 0.0
    if effective_budget_cents > 0:
        projected_utilization = round((projected_24h_spend_cents / effective_budget_cents) * 100.0, 2)

    if utilization >= float(budget.hard_limit_percent):
        decision = "deny"
        action = budget.action_on_hard_limit
        preemptive_throttle = False
    elif projected_utilization >= float(budget.hard_limit_percent):
        decision = "warn"
        action = "preemptive_throttle"
        preemptive_throttle = True
    elif utilization >= float(budget.soft_limit_percent):
        decision = "warn"
        action = budget.action_on_soft_limit
        preemptive_throttle = False
    else:
        decision = "allow"
        action = "none"
        preemptive_throttle = False

    soft_limit_alert = bool(budget.soft_alert_enabled) and decision == "warn"
    if soft_limit_alert and budget.last_soft_alert_at is None:
        budget.last_soft_alert_at = now

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.policy.evaluate",
        resource_type="budget_policy",
        resource_id=budget.budget_policy_id,
        trace_id=f"trace-{budget.budget_policy_id}",
        decision_outcome=decision,
    )
    db.commit()
    logger.info(
        "cost_policy_evaluate_completed %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "scope_type": scope_type,
                "scope_id": scope_id,
                "decision": decision,
            }
        ),
    )

    return {
        "scope_type": scope_type,
        "scope_id": scope_id,
        "spend_cents": spend_cents,
        "budget_cents": budget.budget_amount_cents,
        "effective_budget_cents": effective_budget_cents,
        "utilization_percent": utilization,
        "projected_24h_spend_cents": projected_24h_spend_cents,
        "projected_utilization_percent": projected_utilization,
        "decision": decision,
        "recommended_action": action,
        "preemptive_throttle": preemptive_throttle,
        "soft_limit_alert": soft_limit_alert,
    }


@router.get("/cost/anomalies", response_model=list[CostAnomalyResponse])
def list_cost_anomalies(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)
    anomalies: list[dict] = []
    now = datetime.utcnow()

    budgets = db.query(BudgetPolicy).filter_by(status="active").all()
    for budget in budgets:
        if ctx.actor_role == ROLE_AGENT_OWNER and not (
            budget.scope_type in {"owner", "actor"} and budget.scope_id == ctx.actor_id
        ):
            continue
        owner_scope = f"{budget.scope_type}:{budget.scope_id}"
        spend_cents = _sum_cost_cents(db, after_ts=_window_start_for_budget(budget, budget.window_type), owner_scope=owner_scope)
        effective_budget_cents = _effective_budget_cents(budget)
        threshold = int((effective_budget_cents * budget.soft_limit_percent) / 100)
        if spend_cents >= threshold:
            anomaly_type = "team_soft_budget_alert" if budget.scope_type == COST_SCOPE_TEAM else "budget_threshold_breach"
            anomalies.append(
                {
                    "anomaly_id": str(uuid4()),
                    "anomaly_type": anomaly_type,
                    "severity": "high" if spend_cents >= effective_budget_cents else "medium",
                    "scope_type": budget.scope_type,
                    "scope_id": budget.scope_id,
                    "observed_cost_cents": spend_cents,
                    "threshold_cents": threshold,
                    "detected_at": now,
                }
            )

    return anomalies


@router.post("/cost/limits/evaluate", response_model=CostLimitEvaluateResponse)
def evaluate_cost_limits(
    payload: CostLimitEvaluateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_OWNER)

    actor_id = (payload.actor_id or ctx.actor_id).strip()
    if not actor_id:
        raise HTTPException(status_code=400, detail="actor_id cannot be empty")

    team_ids = normalize_scope_id_list(db, scope_type=COST_SCOPE_TEAM, scope_ids=payload.team_ids)
    group_ids = normalize_scope_id_list(db, scope_type=COST_SCOPE_GROUP, scope_ids=payload.group_ids)

    for team_id in team_ids:
        _ensure_default_jwt_team_budget(db, team_id, ctx.actor_id)

    agent_ids = normalize_scope_id_list(db, scope_type=COST_SCOPE_AGENT, scope_ids=payload.agent_ids)

    evaluation = evaluate_actor_cost_limits(
        db,
        actor_id=actor_id,
        team_ids=team_ids,
        group_ids=group_ids,
        agent_ids=agent_ids,
        window_type=payload.window_type,
        projected_additional_cost_cents=payload.projected_additional_cost_cents,
    )

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.limit.evaluate",
        resource_type="cost_limit",
        resource_id=actor_id,
        trace_id=f"trace-cost-limit-{actor_id}",
        decision_outcome=evaluation.aggregated_decision,
    )
    db.commit()

    return {
        "actor_id": actor_id,
        "window_type": payload.window_type,
        "scopes_evaluated": evaluation.to_dict()["scopes_evaluated"],
        "aggregated_decision": evaluation.aggregated_decision,
        "blocking_scopes": evaluation.blocking_scopes,
        "soft_alert_scopes": evaluation.to_dict()["soft_alert_scopes"],
    }
