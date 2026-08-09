from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.models import BudgetPolicy, DirectoryGroupMembership, DirectoryTeamMembership
from app.policy_constants import (
    COST_SCOPE_ACTOR,
    COST_SCOPE_AGENT,
    COST_SCOPE_GROUP,
    COST_POLICY_DECISION_ALLOW,
    COST_POLICY_DECISION_DENY,
    COST_POLICY_DECISION_WARN,
    COST_SCOPE_OWNER,
    COST_SCOPE_TEAM,
    COST_SCOPE_USER,
)
from app.services.cost_windows import (
    normalize_window_type,
    project_window_spend,
    window_start_for_budget,
)

PERSON_SCOPE_ALIASES = (COST_SCOPE_USER, COST_SCOPE_ACTOR, COST_SCOPE_OWNER)


@dataclass
class CostLimitScopeResult:
    scope_type: str
    scope_id: str
    policy_id: str
    spend_cents: int
    budget_cents: int
    effective_budget_cents: int
    utilization_percent: float
    decision: str
    recommended_action: str
    soft_limit_alert: bool
    projected_window_spend_cents: int = 0
    historical_window_spend_cents: int = 0
    projection_basis: str = "blended"
    hours_spend_cents: int = 0


@dataclass
class CostLimitEvaluationResult:
    aggregated_decision: str
    blocking_scopes: list[str]
    soft_alert_scopes: list[str]
    scopes_evaluated: list[CostLimitScopeResult]

    def to_dict(self) -> dict:
        return {
            "aggregated_decision": self.aggregated_decision,
            "blocking_scopes": list(self.blocking_scopes),
            "soft_alert_scopes": list(self.soft_alert_scopes),
            "scopes_evaluated": [asdict(item) for item in self.scopes_evaluated],
        }


def _effective_budget_cents(budget: BudgetPolicy) -> int:
    base = int(budget.budget_amount_cents or 0)
    extra = int(getattr(budget, "temporary_increase_cents", 0) or 0)
    expires_at = getattr(budget, "temporary_increase_expires_at", None)
    if extra <= 0:
        return base
    if expires_at is None or expires_at >= datetime.utcnow():
        return base + extra
    return base


def temporary_increase_is_active(budget: BudgetPolicy, *, now_utc: datetime | None = None) -> bool:
    extra = int(getattr(budget, "temporary_increase_cents", 0) or 0)
    if extra <= 0:
        return False
    expires_at = getattr(budget, "temporary_increase_expires_at", None)
    now = now_utc or datetime.utcnow()
    return expires_at is None or expires_at >= now


def find_active_budget(db: Session, scope_type: str, scope_id: str) -> BudgetPolicy | None:
    """Resolve active budget, treating user/actor/owner as interchangeable person scopes."""
    normalized_type = str(scope_type or "").strip().lower()
    normalized_id = str(scope_id or "").strip()
    if not normalized_type or not normalized_id:
        return None
    type_order = (
        list(PERSON_SCOPE_ALIASES)
        if normalized_type in PERSON_SCOPE_ALIASES
        else [normalized_type]
    )
    for candidate_type in type_order:
        budget = (
            db.query(BudgetPolicy)
            .filter_by(scope_type=candidate_type, scope_id=normalized_id, status="active")
            .order_by(BudgetPolicy.created_at.desc())
            .first()
        )
        if budget is not None:
            return budget
    return None


def resolve_actor_directory_scopes(db: Session, actor_id: str) -> tuple[list[str], list[str]]:
    """Return directory team_ids and group_ids for an actor."""
    aid = str(actor_id or "").strip()
    if not aid:
        return [], []
    team_ids = [
        str(row[0])
        for row in db.query(DirectoryTeamMembership.team_id)
        .filter(DirectoryTeamMembership.user_id == aid)
        .all()
        if row and row[0]
    ]
    group_ids = [
        str(row[0])
        for row in db.query(DirectoryGroupMembership.group_id)
        .filter(DirectoryGroupMembership.user_id == aid)
        .all()
        if row and row[0]
    ]
    return team_ids, group_ids


def directory_member_ids_for_scope(db: Session, scope_type: str, scope_id: str) -> list[str]:
    """Return directory member user IDs for a team or group scope."""
    normalized_type = str(scope_type or "").strip().lower()
    normalized_id = str(scope_id or "").strip()
    if not normalized_type or not normalized_id:
        return []
    if normalized_type == COST_SCOPE_TEAM:
        return [
            str(row[0])
            for row in db.query(DirectoryTeamMembership.user_id)
            .filter(DirectoryTeamMembership.team_id == normalized_id)
            .limit(5000)
            .all()
            if row and row[0]
        ]
    if normalized_type == COST_SCOPE_GROUP:
        return [
            str(row[0])
            for row in db.query(DirectoryGroupMembership.user_id)
            .filter(DirectoryGroupMembership.group_id == normalized_id)
            .limit(5000)
            .all()
            if row and row[0]
        ]
    return []


def build_user_membership_index(db: Session) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Return user_id -> team_ids and user_id -> group_ids maps for analytics rollup."""
    user_teams: dict[str, list[str]] = {}
    for team_id, user_id in (
        db.query(DirectoryTeamMembership.team_id, DirectoryTeamMembership.user_id).limit(50_000).all()
    ):
        uid = str(user_id or "").strip()
        tid = str(team_id or "").strip()
        if not uid or not tid:
            continue
        user_teams.setdefault(uid, []).append(tid)
    user_groups: dict[str, list[str]] = {}
    for group_id, user_id in (
        db.query(DirectoryGroupMembership.group_id, DirectoryGroupMembership.user_id).limit(50_000).all()
    ):
        uid = str(user_id or "").strip()
        gid = str(group_id or "").strip()
        if not uid or not gid:
            continue
        user_groups.setdefault(uid, []).append(gid)
    return user_teams, user_groups


def hierarchy_attribution_keys(
    owner_scope: str,
    *,
    user_teams: dict[str, list[str]] | None = None,
    user_groups: dict[str, list[str]] | None = None,
) -> list[tuple[str, str]]:
    """Return (scope_type, scope_id) buckets an event contributes to under hierarchy rollup."""
    raw = str(owner_scope or "").strip()
    if not raw:
        return []
    if ":" not in raw:
        return [("owner", raw)]
    scope_type, scope_id = raw.split(":", 1)
    scope_type = scope_type.strip().lower()
    scope_id = scope_id.strip()
    if not scope_id:
        return []

    keys: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def _add(kind: str, value: str) -> None:
        item = (kind, value)
        if item in seen:
            return
        seen.add(item)
        keys.append(item)

    if scope_type in {COST_SCOPE_USER, COST_SCOPE_ACTOR, COST_SCOPE_OWNER}:
        _add(COST_SCOPE_USER, scope_id)
        if scope_type != COST_SCOPE_USER:
            _add(scope_type, scope_id)
        for team_id in (user_teams or {}).get(scope_id, []):
            _add(COST_SCOPE_TEAM, team_id)
        for group_id in (user_groups or {}).get(scope_id, []):
            _add(COST_SCOPE_GROUP, group_id)
        return keys

    if scope_type == COST_SCOPE_TEAM:
        _add(COST_SCOPE_TEAM, scope_id)
        return keys
    if scope_type == COST_SCOPE_GROUP:
        _add(COST_SCOPE_GROUP, scope_id)
        return keys
    _add(scope_type, scope_id)
    return keys


def event_matches_hierarchy_dimension(
    owner_scope: str,
    *,
    dimension: str,
    scope_filter: str | None = None,
    user_teams: dict[str, list[str]] | None = None,
    user_groups: dict[str, list[str]] | None = None,
) -> bool:
    """True when an event should count toward a hierarchy-aware analytics dimension filter."""
    normalized_dimension = str(dimension or "all").strip().lower()
    if normalized_dimension in {"", "all"}:
        return True
    if normalized_dimension not in {
        COST_SCOPE_USER,
        COST_SCOPE_TEAM,
        COST_SCOPE_GROUP,
        COST_SCOPE_ACTOR,
        COST_SCOPE_OWNER,
    }:
        # Non-hierarchy dimensions keep caller-side exact handling.
        return False
    filter_text = str(scope_filter or "").strip().lower()
    for scope_type, scope_id in hierarchy_attribution_keys(
        owner_scope,
        user_teams=user_teams,
        user_groups=user_groups,
    ):
        if scope_type != normalized_dimension:
            continue
        if filter_text and filter_text not in str(scope_id).lower():
            continue
        return True
    return False


def rollup_owner_scopes_for_scope(db: Session, scope_type: str, scope_id: str) -> list[str]:
    """Owner scopes counted toward a budget: tagged scope plus member user/actor aliases."""
    normalized_type = str(scope_type or "").strip().lower()
    normalized_id = str(scope_id or "").strip()
    if not normalized_type or not normalized_id:
        return []

    scopes: list[str] = [f"{normalized_type}:{normalized_id}"]
    seen = set(scopes)

    def _add(scope: str) -> None:
        if scope and scope not in seen:
            seen.add(scope)
            scopes.append(scope)

    if normalized_type in {COST_SCOPE_USER, COST_SCOPE_ACTOR, COST_SCOPE_OWNER}:
        _add(f"{COST_SCOPE_USER}:{normalized_id}")
        _add(f"{COST_SCOPE_ACTOR}:{normalized_id}")
        return scopes

    for member_id in directory_member_ids_for_scope(db, normalized_type, normalized_id):
        _add(f"{COST_SCOPE_USER}:{member_id}")
        _add(f"{COST_SCOPE_ACTOR}:{member_id}")
    return scopes


def member_spend_contributions(
    db: Session,
    *,
    scope_type: str,
    scope_id: str,
    after_ts: datetime | None = None,
    top_n: int = 5,
    environment: str | None = None,
) -> tuple[int, int, list[dict[str, object]]]:
    """Split tagged vs member-attributed spend and return top member contributors."""
    normalized_type = str(scope_type or "").strip().lower()
    normalized_id = str(scope_id or "").strip()
    tagged_scope = f"{normalized_type}:{normalized_id}"
    tagged_spend = _sum_cost_cents(
        db,
        after_ts=after_ts,
        owner_scope=tagged_scope,
        environment=environment,
    )

    contributions: list[dict[str, object]] = []
    member_spend_total = 0
    for member_id in directory_member_ids_for_scope(db, normalized_type, normalized_id):
        spend = _sum_cost_cents(
            db,
            after_ts=after_ts,
            owner_scopes=[f"{COST_SCOPE_USER}:{member_id}", f"{COST_SCOPE_ACTOR}:{member_id}"],
            environment=environment,
        )
        if spend <= 0:
            continue
        member_spend_total += spend
        contributions.append({"user_id": member_id, "spend_cents": spend})

    contributions.sort(key=lambda item: int(item.get("spend_cents") or 0), reverse=True)
    rollup_total = tagged_spend + member_spend_total
    bounded_top = max(1, min(int(top_n or 5), 50))
    top_members: list[dict[str, object]] = []
    for item in contributions[:bounded_top]:
        spend = int(item["spend_cents"])
        share = round((spend / rollup_total) * 100.0, 2) if rollup_total > 0 else 0.0
        top_members.append(
            {
                "user_id": item["user_id"],
                "spend_cents": spend,
                "share_percent": share,
            }
        )
    return tagged_spend, member_spend_total, top_members


def _sum_cost_cents(
    db: Session,
    after_ts: datetime | None = None,
    owner_scope: str | None = None,
    owner_scopes: list[str] | None = None,
    environment: str | None = None,
) -> int:
    from sqlalchemy import func

    from app.models import CostEvent

    query = db.query(func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0))
    if after_ts:
        query = query.filter(CostEvent.timestamp >= after_ts)
    env = str(environment or "").strip()
    if env:
        query = query.filter(CostEvent.environment == env)

    scopes = [str(item).strip() for item in (owner_scopes or []) if str(item).strip()]
    if not scopes and owner_scope:
        scopes = [str(owner_scope).strip()]
    if len(scopes) == 1:
        query = query.filter(CostEvent.owner_scope == scopes[0])
    elif len(scopes) > 1:
        query = query.filter(CostEvent.owner_scope.in_(scopes))
    return int(query.scalar() or 0)


def sum_scope_cost_cents(
    db: Session,
    *,
    scope_type: str,
    scope_id: str,
    after_ts: datetime | None = None,
    environment: str | None = None,
) -> int:
    """Sum spend for a budget scope including membership rollup."""
    return _sum_cost_cents(
        db,
        after_ts=after_ts,
        owner_scopes=rollup_owner_scopes_for_scope(db, scope_type, scope_id),
        environment=environment,
    )


def count_scope_requests_since(
    db: Session,
    *,
    scope_type: str | None = None,
    scope_id: str | None = None,
    owner_scope: str | None = None,
    after_ts: datetime | None = None,
    environment: str | None = None,
) -> int:
    """Count CostEvent rows for a scope including membership rollup aliases."""
    from sqlalchemy import func

    from app.models import CostEvent

    scopes = _resolve_rollup_scopes(
        db,
        scope_type=scope_type,
        scope_id=scope_id,
        owner_scope=owner_scope,
    )
    if not scopes:
        return 0
    query = db.query(func.count(CostEvent.cost_event_id))
    if after_ts is not None:
        query = query.filter(CostEvent.timestamp >= after_ts)
    env = str(environment or "").strip()
    if env:
        query = query.filter(CostEvent.environment == env)
    if len(scopes) == 1:
        query = query.filter(CostEvent.owner_scope == scopes[0])
    else:
        query = query.filter(CostEvent.owner_scope.in_(scopes))
    return int(query.scalar() or 0)


def sum_scope_tokens_since(
    db: Session,
    *,
    scope_type: str | None = None,
    scope_id: str | None = None,
    owner_scope: str | None = None,
    after_ts: datetime | None = None,
    environment: str | None = None,
) -> int:
    """Sum input+output tokens for a scope including membership rollup aliases."""
    from sqlalchemy import func

    from app.models import CostEvent

    scopes = _resolve_rollup_scopes(
        db,
        scope_type=scope_type,
        scope_id=scope_id,
        owner_scope=owner_scope,
    )
    if not scopes:
        return 0
    query = db.query(
        func.coalesce(func.sum(CostEvent.input_tokens + CostEvent.output_tokens), 0)
    )
    if after_ts is not None:
        query = query.filter(CostEvent.timestamp >= after_ts)
    env = str(environment or "").strip()
    if env:
        query = query.filter(CostEvent.environment == env)
    if len(scopes) == 1:
        query = query.filter(CostEvent.owner_scope == scopes[0])
    else:
        query = query.filter(CostEvent.owner_scope.in_(scopes))
    return int(query.scalar() or 0)


def _resolve_rollup_scopes(
    db: Session,
    *,
    scope_type: str | None = None,
    scope_id: str | None = None,
    owner_scope: str | None = None,
) -> list[str]:
    normalized_type = str(scope_type or "").strip().lower()
    normalized_id = str(scope_id or "").strip()
    if normalized_type and normalized_id:
        return rollup_owner_scopes_for_scope(db, normalized_type, normalized_id)
    raw = str(owner_scope or "").strip()
    if not raw:
        return []
    if ":" in raw:
        parsed_type, parsed_id = raw.split(":", 1)
        try:
            return rollup_owner_scopes_for_scope(db, parsed_type.strip().lower(), parsed_id.strip())
        except Exception:  # noqa: BLE001 — fall back to exact scope
            return [raw]
    return [raw]


def _budget_status_fields(
    db: Session,
    scope_type: str,
    scope_id: str,
    spend_cents: int,
    *,
    now_utc: datetime | None = None,
) -> dict[str, object]:
    budget = find_active_budget(db, scope_type, scope_id)
    if budget is None:
        return {
            "budget_policy_id": None,
            "budget_cents": None,
            "effective_budget_cents": None,
            "utilization_percent": None,
            "decision": None,
            "recommended_action": None,
            "soft_limit_percent": None,
            "hard_limit_percent": None,
            "window_type": None,
            "temporary_increase_cents": 0,
            "temporary_increase_active": False,
            "soft_alert_enabled": None,
            "session_budget_cents": None,
            "session_iteration_cap": None,
            "rate_limit_rpm": None,
            "rate_limit_tpm": None,
            "resolved_scope_type": None,
        }
    effective = _effective_budget_cents(budget)
    utilization = 0.0
    if effective > 0:
        utilization = round((spend_cents / effective) * 100.0, 2)
    if utilization >= float(budget.hard_limit_percent):
        decision = COST_POLICY_DECISION_DENY
        action = budget.action_on_hard_limit
    elif utilization >= float(budget.soft_limit_percent):
        decision = COST_POLICY_DECISION_WARN
        action = budget.action_on_soft_limit
    else:
        decision = COST_POLICY_DECISION_ALLOW
        action = "none"
    return {
        "budget_policy_id": budget.budget_policy_id,
        "budget_cents": budget.budget_amount_cents,
        "effective_budget_cents": effective,
        "utilization_percent": utilization,
        "decision": decision,
        "recommended_action": action,
        "soft_limit_percent": float(budget.soft_limit_percent),
        "hard_limit_percent": float(budget.hard_limit_percent),
        "window_type": str(budget.window_type or ""),
        "temporary_increase_cents": int(getattr(budget, "temporary_increase_cents", 0) or 0),
        "temporary_increase_active": temporary_increase_is_active(budget, now_utc=now_utc),
        "soft_alert_enabled": bool(getattr(budget, "soft_alert_enabled", True)),
        "session_budget_cents": getattr(budget, "session_budget_cents", None),
        "session_iteration_cap": getattr(budget, "session_iteration_cap", None),
        "rate_limit_rpm": getattr(budget, "rate_limit_rpm", None),
        "rate_limit_tpm": getattr(budget, "rate_limit_tpm", None),
        "resolved_scope_type": str(budget.scope_type),
        "budget": budget,
    }


def build_actor_cost_hierarchy(
    db: Session,
    *,
    actor_id: str,
    window_hours: int = 24,
    include_members: bool = True,
    top_members: int = 5,
    now_utc: datetime | None = None,
    window_mode: str = "hours",
    environment: str | None = None,
) -> dict[str, object]:
    """Build membership-aware hierarchy payload for an actor."""
    target_actor_id = str(actor_id or "").strip()
    bounded_hours = max(1, min(int(window_hours or 24), 720))
    bounded_top_members = max(1, min(int(top_members or 5), 50))
    now = now_utc or datetime.utcnow()
    hours_after_ts = now - timedelta(hours=bounded_hours)
    resolved_window_mode = "budget" if str(window_mode or "").strip().lower() == "budget" else "hours"
    env = str(environment or "").strip() or None
    team_ids, group_ids = resolve_actor_directory_scopes(db, target_actor_id)

    def _after_ts_for_scope(scope_type: str, scope_id: str) -> datetime:
        if resolved_window_mode != "budget":
            return hours_after_ts
        budget = find_active_budget(db, scope_type, scope_id)
        if budget is None:
            return hours_after_ts
        return window_start_for_budget(budget, budget.window_type, now_utc=now)

    user_after = _after_ts_for_scope(COST_SCOPE_USER, target_actor_id)
    user_hours_spend_cents = sum_scope_cost_cents(
        db,
        scope_type=COST_SCOPE_USER,
        scope_id=target_actor_id,
        after_ts=hours_after_ts,
        environment=env,
    )
    user_spend_cents = sum_scope_cost_cents(
        db,
        scope_type=COST_SCOPE_USER,
        scope_id=target_actor_id,
        after_ts=user_after,
        environment=env,
    )

    def _hierarchy_item(scope_type: str, scope_id: str) -> dict[str, object]:
        after_ts = _after_ts_for_scope(scope_type, scope_id)
        hours_spend_cents = sum_scope_cost_cents(
            db,
            scope_type=scope_type,
            scope_id=scope_id,
            after_ts=hours_after_ts,
            environment=env,
        )
        spend_cents = sum_scope_cost_cents(
            db,
            scope_type=scope_type,
            scope_id=scope_id,
            after_ts=after_ts,
            environment=env,
        )
        if scope_type == COST_SCOPE_TEAM:
            member_count = (
                db.query(DirectoryTeamMembership)
                .filter(DirectoryTeamMembership.team_id == scope_id)
                .count()
            )
        else:
            member_count = (
                db.query(DirectoryGroupMembership)
                .filter(DirectoryGroupMembership.group_id == scope_id)
                .count()
            )
        tagged_spend_cents = 0
        member_spend_cents = 0
        top_member_rows: list[dict[str, object]] = []
        if include_members:
            tagged_spend_cents, member_spend_cents, top_member_rows = member_spend_contributions(
                db,
                scope_type=scope_type,
                scope_id=scope_id,
                after_ts=after_ts,
                top_n=bounded_top_members,
                environment=env,
            )
        status = _budget_status_fields(db, scope_type, scope_id, spend_cents, now_utc=now)
        budget_window_spend_cents = None
        budget_obj = status.get("budget")
        if isinstance(budget_obj, BudgetPolicy):
            budget_window_spend_cents = sum_scope_cost_cents(
                db,
                scope_type=scope_type,
                scope_id=scope_id,
                after_ts=window_start_for_budget(budget_obj, budget_obj.window_type, now_utc=now),
                environment=env,
            )
        item: dict[str, object] = {
            "scope_type": scope_type,
            "scope_id": scope_id,
            "member_count": int(member_count or 0),
            "spend_cents": spend_cents,
            "hours_spend_cents": hours_spend_cents,
            "tagged_spend_cents": tagged_spend_cents,
            "member_spend_cents": member_spend_cents,
            "top_members": top_member_rows,
            "budget_policy_id": status["budget_policy_id"],
            "budget_cents": status["budget_cents"],
            "effective_budget_cents": status["effective_budget_cents"],
            "utilization_percent": status["utilization_percent"],
            "decision": status["decision"],
            "recommended_action": status["recommended_action"],
            "window_type": status["window_type"],
            "budget_window_spend_cents": budget_window_spend_cents,
            "temporary_increase_cents": status["temporary_increase_cents"],
            "temporary_increase_active": status["temporary_increase_active"],
            "resolved_budget_scope_type": status["resolved_scope_type"],
            "session_budget_cents": status["session_budget_cents"],
            "session_iteration_cap": status["session_iteration_cap"],
            "rate_limit_rpm": status["rate_limit_rpm"],
            "rate_limit_tpm": status["rate_limit_tpm"],
            "soft_alert_enabled": status["soft_alert_enabled"],
        }
        return item

    teams = [_hierarchy_item(COST_SCOPE_TEAM, team_id) for team_id in team_ids]
    groups = [_hierarchy_item(COST_SCOPE_GROUP, group_id) for group_id in group_ids]
    user_status = _budget_status_fields(db, COST_SCOPE_USER, target_actor_id, user_spend_cents, now_utc=now)
    user_budget = None
    if user_status.get("budget_policy_id"):
        budget_obj = user_status.get("budget")
        budget_window_spend_cents = None
        if isinstance(budget_obj, BudgetPolicy):
            budget_window_spend_cents = sum_scope_cost_cents(
                db,
                scope_type=COST_SCOPE_USER,
                scope_id=target_actor_id,
                after_ts=window_start_for_budget(budget_obj, budget_obj.window_type, now_utc=now),
                environment=env,
            )
        user_budget = {
            "budget_policy_id": user_status["budget_policy_id"],
            "budget_cents": user_status["budget_cents"],
            "effective_budget_cents": user_status["effective_budget_cents"],
            "utilization_percent": user_status["utilization_percent"],
            "decision": user_status["decision"],
            "recommended_action": user_status["recommended_action"],
            "window_type": user_status["window_type"],
            "budget_window_spend_cents": budget_window_spend_cents,
            "hours_spend_cents": user_hours_spend_cents,
            "temporary_increase_cents": user_status["temporary_increase_cents"],
            "temporary_increase_active": user_status["temporary_increase_active"],
            "resolved_budget_scope_type": user_status["resolved_scope_type"],
            "session_budget_cents": user_status["session_budget_cents"],
            "session_iteration_cap": user_status["session_iteration_cap"],
            "soft_alert_enabled": user_status["soft_alert_enabled"],
        }

    soft_alert_scopes: list[str] = []
    if (
        user_budget
        and user_budget.get("decision") == COST_POLICY_DECISION_WARN
        and user_budget.get("soft_alert_enabled", True)
    ):
        soft_alert_scopes.append(f"{COST_SCOPE_USER}:{target_actor_id}")
    soft_alert_scopes.extend(
        f"{item['scope_type']}:{item['scope_id']}"
        for item in [*teams, *groups]
        if item.get("decision") == COST_POLICY_DECISION_WARN and item.get("soft_alert_enabled", True)
    )

    blocking_scopes = []
    if user_budget and user_budget.get("decision") == COST_POLICY_DECISION_DENY:
        blocking_scopes.append(f"{COST_SCOPE_USER}:{target_actor_id}")
    blocking_scopes.extend(
        f"{item['scope_type']}:{item['scope_id']}"
        for item in [*teams, *groups]
        if item.get("decision") == COST_POLICY_DECISION_DENY
    )

    return {
        "actor_id": target_actor_id,
        "window_hours": bounded_hours,
        "window_mode": resolved_window_mode,
        "environment": env,
        "user_spend_cents": user_spend_cents,
        "user_hours_spend_cents": user_hours_spend_cents,
        "user_budget": user_budget,
        "teams": teams,
        "groups": groups,
        "soft_alert_scopes": soft_alert_scopes,
        "blocking_scopes": blocking_scopes,
    }


def explain_cost_hierarchy_scope(
    db: Session,
    *,
    scope_type: str,
    scope_id: str,
    window_hours: int = 24,
    top_members: int = 10,
    now_utc: datetime | None = None,
    window_mode: str = "hours",
    environment: str | None = None,
) -> dict[str, object]:
    """Explain rollup spend and budget posture for one hierarchy scope."""
    normalized_type = str(scope_type or "").strip().lower()
    normalized_id = str(scope_id or "").strip()
    bounded_hours = max(1, min(int(window_hours or 24), 720))
    now = now_utc or datetime.utcnow()
    resolved_window_mode = "budget" if str(window_mode or "").strip().lower() == "budget" else "hours"
    env = str(environment or "").strip() or None
    hours_after_ts = now - timedelta(hours=bounded_hours)
    budget = find_active_budget(db, normalized_type, normalized_id)
    if resolved_window_mode == "budget" and budget is not None:
        after_ts = window_start_for_budget(budget, budget.window_type, now_utc=now)
    else:
        after_ts = hours_after_ts
    spend_cents = sum_scope_cost_cents(
        db,
        scope_type=normalized_type,
        scope_id=normalized_id,
        after_ts=after_ts,
        environment=env,
    )
    hours_spend_cents = sum_scope_cost_cents(
        db,
        scope_type=normalized_type,
        scope_id=normalized_id,
        after_ts=hours_after_ts,
        environment=env,
    )
    tagged_spend_cents, member_spend_cents, top_members_rows = member_spend_contributions(
        db,
        scope_type=normalized_type,
        scope_id=normalized_id,
        after_ts=after_ts,
        top_n=top_members,
        environment=env,
    )
    status = _budget_status_fields(db, normalized_type, normalized_id, spend_cents, now_utc=now)
    member_ids = directory_member_ids_for_scope(db, normalized_type, normalized_id)
    dominant = top_members_rows[0] if top_members_rows else None
    projected_window_spend_cents = 0
    historical_window_spend_cents = 0
    projection_basis = None
    if budget is not None:
        owner_scopes = rollup_owner_scopes_for_scope(db, normalized_type, normalized_id)
        projection = project_window_spend(
            db,
            owner_scope=owner_scopes[0] if owner_scopes else f"{normalized_type}:{normalized_id}",
            budget=budget,
            window_type=normalize_window_type(budget.window_type),
            current_spend_cents=spend_cents if resolved_window_mode == "budget" else sum_scope_cost_cents(
                db,
                scope_type=normalized_type,
                scope_id=normalized_id,
                after_ts=window_start_for_budget(budget, budget.window_type, now_utc=now),
                environment=env,
            ),
            now_utc=now,
            owner_scopes=owner_scopes,
        )
        projected_window_spend_cents = projection.projected_window_spend_cents
        historical_window_spend_cents = projection.historical_window_spend_cents
        projection_basis = projection.projection_basis

    reasons: list[str] = []
    if status.get("decision") == COST_POLICY_DECISION_DENY:
        reasons.append("Hard budget utilization reached or exceeded.")
    elif status.get("decision") == COST_POLICY_DECISION_WARN:
        reasons.append("Soft budget utilization reached or exceeded.")
        if not status.get("soft_alert_enabled", True):
            reasons.append("Soft alert notifications are disabled for this policy.")
    elif status.get("budget_policy_id") is None:
        reasons.append("No active budget policy for this scope.")
    else:
        reasons.append("Spend is within soft and hard budget thresholds.")
    if member_spend_cents > tagged_spend_cents:
        reasons.append("Member-attributed spend dominates tagged scope events.")
    if dominant and float(dominant.get("share_percent") or 0) >= 40.0:
        reasons.append(
            f"Top contributor {dominant['user_id']} accounts for {dominant['share_percent']}% of rollup spend."
        )
    if status.get("temporary_increase_active"):
        reasons.append(
            f"Temporary increase of {status['temporary_increase_cents']}¢ is active on effective budget."
        )
    elif int(status.get("temporary_increase_cents") or 0) > 0:
        reasons.append("Temporary increase is configured but expired; effective budget excludes it.")
    if status.get("resolved_scope_type") and status["resolved_scope_type"] != normalized_type:
        reasons.append(
            f"Budget resolved via alias scope_type={status['resolved_scope_type']} for {normalized_type}:{normalized_id}."
        )
    if env:
        reasons.append(f"Spend filtered to environment={env}.")
    if resolved_window_mode == "budget":
        reasons.append("Spend/utilization use the policy budget window, not trailing wall-clock hours.")

    return {
        "scope_type": normalized_type,
        "scope_id": normalized_id,
        "window_hours": bounded_hours,
        "window_mode": resolved_window_mode,
        "environment": env,
        "member_count": len(member_ids),
        "spend_cents": spend_cents,
        "hours_spend_cents": hours_spend_cents,
        "tagged_spend_cents": tagged_spend_cents,
        "member_spend_cents": member_spend_cents,
        "top_members": top_members_rows,
        "budget_policy_id": status["budget_policy_id"],
        "budget_cents": status["budget_cents"],
        "effective_budget_cents": status["effective_budget_cents"],
        "utilization_percent": status["utilization_percent"],
        "decision": status["decision"],
        "recommended_action": status["recommended_action"],
        "soft_limit_percent": status["soft_limit_percent"],
        "hard_limit_percent": status["hard_limit_percent"],
        "window_type": status["window_type"],
        "temporary_increase_cents": status["temporary_increase_cents"],
        "temporary_increase_active": status["temporary_increase_active"],
        "resolved_budget_scope_type": status["resolved_scope_type"],
        "projected_window_spend_cents": projected_window_spend_cents,
        "historical_window_spend_cents": historical_window_spend_cents,
        "projection_basis": projection_basis,
        "session_budget_cents": status["session_budget_cents"],
        "session_iteration_cap": status["session_iteration_cap"],
        "rate_limit_rpm": status["rate_limit_rpm"],
        "rate_limit_tpm": status["rate_limit_tpm"],
        "reasons": reasons,
        "owner_scopes_counted": rollup_owner_scopes_for_scope(db, normalized_type, normalized_id)[:64],
    }


def _evaluate_scope_budget(
    db: Session,
    scope_type: str,
    scope_id: str,
    window_type: str,
    projected_additional_cost_cents: int,
    *,
    environment: str | None = None,
) -> CostLimitScopeResult | None:
    budget = find_active_budget(db, scope_type, scope_id)
    if not budget:
        return None

    resolved_window = normalize_window_type(window_type or budget.window_type)
    owner_scopes = rollup_owner_scopes_for_scope(db, scope_type, scope_id)
    primary_owner_scope = owner_scopes[0] if owner_scopes else f"{scope_type}:{scope_id}"
    spend_cents = _sum_cost_cents(
        db,
        after_ts=window_start_for_budget(budget, resolved_window),
        owner_scopes=owner_scopes,
        environment=environment,
    )
    hours_spend_cents = _sum_cost_cents(
        db,
        after_ts=datetime.utcnow() - timedelta(hours=24),
        owner_scopes=owner_scopes,
        environment=environment,
    )
    projection = project_window_spend(
        db,
        owner_scope=primary_owner_scope,
        budget=budget,
        window_type=resolved_window,
        current_spend_cents=spend_cents,
        owner_scopes=owner_scopes,
    )
    projected_spend = max(
        projection.projected_window_spend_cents,
        spend_cents + max(projected_additional_cost_cents, 0),
    )
    effective_budget_cents = _effective_budget_cents(budget)

    utilization = 0.0
    if effective_budget_cents > 0:
        utilization = round((projected_spend / effective_budget_cents) * 100.0, 2)

    if utilization >= float(budget.hard_limit_percent):
        decision = COST_POLICY_DECISION_DENY
        action = budget.action_on_hard_limit
    elif utilization >= float(budget.soft_limit_percent):
        decision = COST_POLICY_DECISION_WARN
        action = budget.action_on_soft_limit
    else:
        decision = COST_POLICY_DECISION_ALLOW
        action = "none"

    soft_limit_alert = bool(getattr(budget, "soft_alert_enabled", True)) and decision == COST_POLICY_DECISION_WARN

    return CostLimitScopeResult(
        scope_type=scope_type,
        scope_id=scope_id,
        policy_id=budget.budget_policy_id,
        spend_cents=projected_spend,
        hours_spend_cents=hours_spend_cents,
        budget_cents=budget.budget_amount_cents,
        effective_budget_cents=effective_budget_cents,
        utilization_percent=utilization,
        decision=decision,
        recommended_action=action,
        soft_limit_alert=soft_limit_alert,
        projected_window_spend_cents=projection.projected_window_spend_cents,
        historical_window_spend_cents=projection.historical_window_spend_cents,
        projection_basis=projection.projection_basis,
    )


def evaluate_budget_policy_by_id(
    db: Session,
    budget_policy_id: str,
    *,
    owner_scope: str | None = None,
    projected_additional_cost_cents: int = 0,
) -> CostLimitScopeResult | None:
    """Evaluate a specific BudgetPolicy by id (Portkey-style virtual-key budget binding)."""
    policy_id = str(budget_policy_id or "").strip()
    if not policy_id or policy_id.lower() in {"default", "none", "null"}:
        return None

    budget = db.query(BudgetPolicy).filter_by(budget_policy_id=policy_id).first()
    if budget is None or str(budget.status or "").strip().lower() != "active":
        return None

    resolved_window = normalize_window_type(budget.window_type)
    owner_scopes = rollup_owner_scopes_for_scope(db, str(budget.scope_type), str(budget.scope_id))
    if owner_scope and str(owner_scope).strip():
        # Keep explicit override as an additional attribution alias (legacy callers).
        override = str(owner_scope).strip()
        if override not in owner_scopes:
            owner_scopes = [*owner_scopes, override]
    primary_owner_scope = owner_scopes[0] if owner_scopes else f"{budget.scope_type}:{budget.scope_id}"
    spend_cents = _sum_cost_cents(
        db,
        after_ts=window_start_for_budget(budget, resolved_window),
        owner_scopes=owner_scopes,
    )
    projection = project_window_spend(
        db,
        owner_scope=primary_owner_scope,
        budget=budget,
        window_type=resolved_window,
        current_spend_cents=spend_cents,
        owner_scopes=owner_scopes,
    )
    projected_spend = max(
        projection.projected_window_spend_cents,
        spend_cents + max(int(projected_additional_cost_cents or 0), 0),
    )
    effective_budget_cents = _effective_budget_cents(budget)

    utilization = 0.0
    if effective_budget_cents > 0:
        utilization = round((projected_spend / effective_budget_cents) * 100.0, 2)

    if utilization >= float(budget.hard_limit_percent):
        decision = COST_POLICY_DECISION_DENY
        action = budget.action_on_hard_limit
    elif utilization >= float(budget.soft_limit_percent):
        decision = COST_POLICY_DECISION_WARN
        action = budget.action_on_soft_limit
    else:
        decision = COST_POLICY_DECISION_ALLOW
        action = "none"

    soft_limit_alert = bool(getattr(budget, "soft_alert_enabled", True)) and decision == COST_POLICY_DECISION_WARN

    return CostLimitScopeResult(
        scope_type=str(budget.scope_type),
        scope_id=str(budget.scope_id),
        policy_id=budget.budget_policy_id,
        spend_cents=projected_spend,
        budget_cents=budget.budget_amount_cents,
        effective_budget_cents=effective_budget_cents,
        utilization_percent=utilization,
        decision=decision,
        recommended_action=action,
        soft_limit_alert=soft_limit_alert,
        projected_window_spend_cents=projection.projected_window_spend_cents,
        historical_window_spend_cents=projection.historical_window_spend_cents,
        projection_basis=projection.projection_basis,
    )


def evaluate_actor_cost_limits(
    db: Session,
    actor_id: str,
    team_ids: list[str] | None = None,
    group_ids: list[str] | None = None,
    agent_ids: list[str] | None = None,
    window_type: str = "daily",
    projected_additional_cost_cents: int = 0,
    *,
    auto_resolve_directory_memberships: bool = True,
    environment: str | None = None,
) -> CostLimitEvaluationResult:
    resolved_team_ids = [team_id.strip() for team_id in (team_ids or []) if str(team_id).strip()]
    resolved_group_ids = [group_id.strip() for group_id in (group_ids or []) if str(group_id).strip()]
    if auto_resolve_directory_memberships and (not resolved_team_ids or not resolved_group_ids):
        directory_teams, directory_groups = resolve_actor_directory_scopes(db, actor_id)
        if not resolved_team_ids:
            resolved_team_ids = list(directory_teams)
        if not resolved_group_ids:
            resolved_group_ids = list(directory_groups)

    scope_candidates: list[tuple[str, str]] = [(COST_SCOPE_USER, actor_id)]
    scope_candidates.extend((COST_SCOPE_TEAM, team_id) for team_id in resolved_team_ids)
    scope_candidates.extend((COST_SCOPE_GROUP, group_id) for group_id in resolved_group_ids)
    scope_candidates.extend((COST_SCOPE_AGENT, agent_id) for agent_id in (agent_ids or []) if agent_id.strip())

    deduped_scopes: list[tuple[str, str]] = []
    seen_scopes: set[str] = set()
    for scope_type, scope_id in scope_candidates:
        normalized_scope_id = scope_id.strip()
        if not normalized_scope_id:
            continue
        key = f"{scope_type}:{normalized_scope_id}"
        if key in seen_scopes:
            continue
        seen_scopes.add(key)
        deduped_scopes.append((scope_type, normalized_scope_id))

    scope_decisions: list[CostLimitScopeResult] = []
    for scope_type, scope_id in deduped_scopes:
        decision = _evaluate_scope_budget(
            db,
            scope_type=scope_type,
            scope_id=scope_id,
            window_type=window_type,
            projected_additional_cost_cents=projected_additional_cost_cents,
            environment=environment,
        )
        if decision is not None:
            scope_decisions.append(decision)

    aggregated_decision = COST_POLICY_DECISION_ALLOW
    if any(item.decision == COST_POLICY_DECISION_DENY for item in scope_decisions):
        aggregated_decision = COST_POLICY_DECISION_DENY
    elif any(item.decision == COST_POLICY_DECISION_WARN for item in scope_decisions):
        aggregated_decision = COST_POLICY_DECISION_WARN

    blocking_scopes = [
        f"{item.scope_type}:{item.scope_id}" for item in scope_decisions if item.decision == COST_POLICY_DECISION_DENY
    ]
    soft_alert_scopes = [
        f"{item.scope_type}:{item.scope_id}" for item in scope_decisions if item.soft_limit_alert
    ]

    return CostLimitEvaluationResult(
        aggregated_decision=aggregated_decision,
        blocking_scopes=blocking_scopes,
        soft_alert_scopes=soft_alert_scopes,
        scopes_evaluated=scope_decisions,
    )


@dataclass
class SessionCostCapResult:
    decision: str
    session_id: str
    session_spend_cents: int
    session_event_count: int
    blocking_scopes: list[str]
    reasons: list[str]
    applied_policies: list[dict[str, object]]

    def to_dict(self) -> dict[str, object]:
        return {
            "decision": self.decision,
            "session_id": self.session_id,
            "session_spend_cents": self.session_spend_cents,
            "session_event_count": self.session_event_count,
            "blocking_scopes": list(self.blocking_scopes),
            "reasons": list(self.reasons),
            "applied_policies": list(self.applied_policies),
        }


def evaluate_session_cost_caps(
    db: Session,
    *,
    actor_id: str,
    session_id: str,
    projected_additional_cost_cents: int = 0,
    environment: str | None = None,
) -> SessionCostCapResult:
    """Enforce session_budget_cents / session_iteration_cap across hierarchy budgets."""
    from sqlalchemy import func

    from app.models import CostEvent

    sid = str(session_id or "").strip()
    aid = str(actor_id or "").strip()
    if not sid or not aid:
        return SessionCostCapResult(
            decision=COST_POLICY_DECISION_ALLOW,
            session_id=sid,
            session_spend_cents=0,
            session_event_count=0,
            blocking_scopes=[],
            reasons=[],
            applied_policies=[],
        )

    env = str(environment or "").strip() or None
    query = db.query(
        func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0),
        func.count(CostEvent.cost_event_id),
    ).filter(CostEvent.session_id == sid)
    if env:
        query = query.filter(CostEvent.environment == env)
    spend_row = query.one()
    session_spend = int(spend_row[0] or 0) + max(0, int(projected_additional_cost_cents or 0))
    # Include the in-flight request in iteration count.
    session_events = int(spend_row[1] or 0) + 1

    team_ids, group_ids = resolve_actor_directory_scopes(db, aid)
    candidates: list[tuple[str, str]] = [(COST_SCOPE_USER, aid)]
    candidates.extend((COST_SCOPE_TEAM, team_id) for team_id in team_ids)
    candidates.extend((COST_SCOPE_GROUP, group_id) for group_id in group_ids)

    blocking: list[str] = []
    reasons: list[str] = []
    applied: list[dict[str, object]] = []
    for scope_type, scope_id in candidates:
        budget = find_active_budget(db, scope_type, scope_id)
        if budget is None:
            continue
        session_budget = getattr(budget, "session_budget_cents", None)
        iteration_cap = getattr(budget, "session_iteration_cap", None)
        has_budget_cap = isinstance(session_budget, int) and session_budget > 0
        has_iter_cap = isinstance(iteration_cap, int) and iteration_cap > 0
        if not has_budget_cap and not has_iter_cap:
            continue
        applied.append(
            {
                "scope_type": scope_type,
                "scope_id": scope_id,
                "budget_policy_id": budget.budget_policy_id,
                "session_budget_cents": session_budget,
                "session_iteration_cap": iteration_cap,
            }
        )
        scope_key = f"{scope_type}:{scope_id}"
        if has_budget_cap and session_spend > int(session_budget):
            blocking.append(scope_key)
            reasons.append(
                f"{scope_key} session spend {session_spend}c exceeds session_budget_cents {session_budget}"
            )
        if has_iter_cap and session_events > int(iteration_cap):
            blocking.append(scope_key)
            reasons.append(
                f"{scope_key} session events {session_events} exceeds session_iteration_cap {iteration_cap}"
            )

    # Deduplicate blocking scopes while preserving order.
    seen: set[str] = set()
    unique_blocking: list[str] = []
    for item in blocking:
        if item in seen:
            continue
        seen.add(item)
        unique_blocking.append(item)

    return SessionCostCapResult(
        decision=COST_POLICY_DECISION_DENY if unique_blocking else COST_POLICY_DECISION_ALLOW,
        session_id=sid,
        session_spend_cents=session_spend,
        session_event_count=session_events,
        blocking_scopes=unique_blocking,
        reasons=reasons[:16],
        applied_policies=applied[:32],
    )
