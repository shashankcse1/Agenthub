from datetime import datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import CostEvent
from app.services.cost_windows import (
    normalize_window_type,
    project_window_spend,
    window_start_for_budget,
)

client = TestClient(app)


def _admin_headers(actor_id: str) -> dict[str, str]:
    return {"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id}


def test_normalize_window_type_accepts_realtime_daily_adhoc_weekly_monthly():
    assert normalize_window_type("realtime") == "realtime"
    assert normalize_window_type("daily") == "daily"
    assert normalize_window_type("adhoc") == "adhoc"
    assert normalize_window_type("weekly") == "weekly"
    assert normalize_window_type("monthly") == "monthly"
    assert normalize_window_type("hourly") == "realtime"


def test_invalid_window_type_rejected_on_budget_create():
    response = client.post(
        "/cost/budgets",
        json={
            "scope_type": "actor",
            "scope_id": f"actor-{uuid4()}",
            "budget_amount_cents": 1000,
            "window_type": "quarterly",
        },
        headers=_admin_headers("budget-window-invalid"),
    )
    assert response.status_code == 400


def test_realtime_window_excludes_older_spend():
    scope_id = f"user-{uuid4()}"
    created = client.post(
        "/cost/budgets",
        json={
            "scope_type": "user",
            "scope_id": scope_id,
            "budget_amount_cents": 1000,
            "window_type": "realtime",
            "soft_limit_percent": 80,
            "hard_limit_percent": 100,
        },
        headers=_admin_headers("budget-realtime-window"),
    )
    assert created.status_code == 200
    assert created.json()["window_type"] == "realtime"

    db = SessionLocal()
    try:
        budget = created.json()
        from app.models import BudgetPolicy

        policy = db.query(BudgetPolicy).filter_by(budget_policy_id=budget["budget_policy_id"]).first()
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                timestamp=datetime.utcnow() - timedelta(hours=1),
                request_id="req-realtime-old",
                trace_id="trace-realtime-old",
                session_id="session-realtime-old",
                agent_id="agent-realtime-old",
                owner_scope=f"user:{scope_id}",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=100,
                output_tokens=50,
                estimated_cost_cents=900,
                currency="USD",
            )
        )
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id="req-realtime-recent",
                trace_id="trace-realtime-recent",
                session_id="session-realtime-recent",
                agent_id="agent-realtime-recent",
                owner_scope=f"user:{scope_id}",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=100,
                output_tokens=50,
                estimated_cost_cents=150,
                currency="USD",
            )
        )
        db.commit()

        after_ts = window_start_for_budget(policy, "realtime")
        spend = (
            db.query(CostEvent)
            .filter(CostEvent.owner_scope == f"user:{scope_id}", CostEvent.timestamp >= after_ts)
            .with_entities(CostEvent.estimated_cost_cents)
            .all()
        )
        assert sum(row[0] for row in spend) == 150
    finally:
        db.close()


def test_adhoc_budget_projection_uses_historical_daily_rate():
    scope_id = f"user-{uuid4()}"
    created = client.post(
        "/cost/budgets",
        json={
            "scope_type": "user",
            "scope_id": scope_id,
            "budget_amount_cents": 5000,
            "window_type": "adhoc",
        },
        headers=_admin_headers("budget-adhoc-projection"),
    )
    assert created.status_code == 200

    db = SessionLocal()
    try:
        from app.models import BudgetPolicy

        policy = db.query(BudgetPolicy).filter_by(scope_id=scope_id).first()
        for day_offset in range(3):
            db.add(
                CostEvent(
                    cost_event_id=str(uuid4()),
                    timestamp=datetime.utcnow() - timedelta(days=day_offset),
                    request_id=f"req-adhoc-{day_offset}",
                    trace_id=f"trace-adhoc-{day_offset}",
                    session_id=f"session-adhoc-{day_offset}",
                    agent_id="agent-adhoc",
                    owner_scope=f"user:{scope_id}",
                    environment="dev",
                    model_name="gpt-test",
                    endpoint_family="responses",
                    input_tokens=100,
                    output_tokens=50,
                    estimated_cost_cents=200 * (day_offset + 1),
                    currency="USD",
                )
            )
        db.commit()

        projection = project_window_spend(
            db,
            owner_scope=f"user:{scope_id}",
            budget=policy,
            window_type="adhoc",
            current_spend_cents=600,
        )
        assert projection.projection_basis == "adhoc_daily_rate"
        assert projection.projected_window_spend_cents >= 600
        assert projection.historical_window_spend_cents > 0
    finally:
        db.close()


def test_policy_evaluate_returns_projection_metadata():
    scope_id = f"user-{uuid4()}"
    created = client.post(
        "/cost/budgets",
        json={
            "scope_type": "user",
            "scope_id": scope_id,
            "budget_amount_cents": 2000,
            "window_type": "daily",
        },
        headers=_admin_headers("budget-projection-meta"),
    )
    assert created.status_code == 200

    db = SessionLocal()
    try:
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                timestamp=datetime.utcnow() - timedelta(days=1, hours=2),
                request_id="req-prev-day",
                trace_id="trace-prev-day",
                session_id="session-prev-day",
                agent_id="agent-prev-day",
                owner_scope=f"user:{scope_id}",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=100,
                output_tokens=50,
                estimated_cost_cents=400,
                currency="USD",
            )
        )
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id="req-today",
                trace_id="trace-today",
                session_id="session-today",
                agent_id="agent-today",
                owner_scope=f"user:{scope_id}",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=100,
                output_tokens=50,
                estimated_cost_cents=100,
                currency="USD",
            )
        )
        db.commit()
    finally:
        db.close()

    evaluated = client.post(
        "/cost/policies/evaluate",
        json={"scope_type": "user", "scope_id": scope_id, "window_type": "daily"},
        headers=_admin_headers("budget-projection-eval"),
    )
    assert evaluated.status_code == 200
    body = evaluated.json()
    assert body["window_type"] == "daily"
    assert "projected_window_spend_cents" in body
    assert "projection_basis" in body
    assert "historical_window_spend_cents" in body
    assert body["prior_periods_considered"] >= 0
