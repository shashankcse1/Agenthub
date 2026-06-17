from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from app.models import BudgetPolicy
from app.policy_constants import (
    COST_SCOPE_AGENT,
    COST_POLICY_DECISION_ALLOW,
    COST_POLICY_DECISION_DENY,
    COST_POLICY_DECISION_WARN,
    COST_SCOPE_GROUP,
    COST_SCOPE_TEAM,
    COST_SCOPE_USER,
)
from app.services.cost_windows import (
    normalize_window_type,
    project_window_spend,
    window_start_for_budget,
)


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


def _sum_cost_cents(db: Session, after_ts: datetime | None = None, owner_scope: str | None = None) -> int:
    from sqlalchemy import func

    from app.models import CostEvent

    query = db.query(func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0))
    if after_ts:
        query = query.filter(CostEvent.timestamp >= after_ts)
    if owner_scope:
        query = query.filter(CostEvent.owner_scope == owner_scope)
    return int(query.scalar() or 0)


def _evaluate_scope_budget(
    db: Session,
    scope_type: str,
    scope_id: str,
    window_type: str,
    projected_additional_cost_cents: int,
) -> CostLimitScopeResult | None:
    budget = (
        db.query(BudgetPolicy)
        .filter_by(scope_type=scope_type, scope_id=scope_id, status="active")
        .order_by(BudgetPolicy.created_at.desc())
        .first()
    )
    if not budget:
        return None

    resolved_window = normalize_window_type(window_type or budget.window_type)
    owner_scope = f"{scope_type}:{scope_id}"
    spend_cents = _sum_cost_cents(
        db,
        after_ts=window_start_for_budget(budget, resolved_window),
        owner_scope=owner_scope,
    )
    projection = project_window_spend(
        db,
        owner_scope=owner_scope,
        budget=budget,
        window_type=resolved_window,
        current_spend_cents=spend_cents,
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
) -> CostLimitEvaluationResult:
    scope_candidates: list[tuple[str, str]] = [(COST_SCOPE_USER, actor_id)]
    scope_candidates.extend((COST_SCOPE_TEAM, team_id) for team_id in (team_ids or []) if team_id.strip())
    scope_candidates.extend((COST_SCOPE_GROUP, group_id) for group_id in (group_ids or []) if group_id.strip())
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
