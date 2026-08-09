from datetime import datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import CostEvent
from app.services.cost_windows import build_period_comparison, normalize_comparison_period

client = TestClient(app)


def _admin_headers(actor_id: str) -> dict[str, str]:
    return {"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id}


def test_normalize_comparison_period_aliases():
    assert normalize_comparison_period("1m") == "monthly"
    assert normalize_comparison_period("1y") == "yearly"
    assert normalize_comparison_period("last_month") == "monthly"
    assert normalize_comparison_period("last_year") == "yearly"


def test_cost_comparison_monthly_vs_last_month():
    db = SessionLocal()
    try:
        now = datetime.utcnow()
        current_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        previous_start = (current_start - timedelta(days=1)).replace(day=1)

        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id="req-current-month",
                trace_id="trace-current-month",
                session_id="session-current-month",
                agent_id="agent-comparison",
                owner_scope="user:comparison-user",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=10,
                output_tokens=5,
                estimated_cost_cents=300,
                currency="USD",
            )
        )
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                timestamp=previous_start + timedelta(days=5),
                request_id="req-last-month",
                trace_id="trace-last-month",
                session_id="session-last-month",
                agent_id="agent-comparison",
                owner_scope="user:comparison-user",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=10,
                output_tokens=5,
                estimated_cost_cents=500,
                currency="USD",
            )
        )
        db.commit()

        comparison = build_period_comparison(
            db,
            period="monthly",
            comparison_mode="prior_period",
        )
        assert comparison.current.spend_cents >= 300
        assert comparison.previous.spend_cents >= 500
        assert comparison.delta_cents == comparison.current.spend_cents - comparison.previous.spend_cents
    finally:
        db.close()


def test_cost_comparison_endpoint_year_over_year():
    db = SessionLocal()
    try:
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id="req-current-year",
                trace_id="trace-current-year",
                session_id="session-current-year",
                agent_id="agent-yoy",
                owner_scope="team:platform",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=10,
                output_tokens=5,
                estimated_cost_cents=120,
                currency="USD",
            )
        )
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                timestamp=datetime.utcnow() - timedelta(days=400),
                request_id="req-last-year",
                trace_id="trace-last-year",
                session_id="session-last-year",
                agent_id="agent-yoy",
                owner_scope="team:platform",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=10,
                output_tokens=5,
                estimated_cost_cents=800,
                currency="USD",
            )
        )
        db.commit()
    finally:
        db.close()

    response = client.get(
        "/cost/comparison?period=yearly&comparison_mode=prior_period",
        headers=_admin_headers("comparison-yoy"),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["comparison_period"] == "yearly"
    assert body["comparison_mode"] == "prior_period"
    assert "current" in body and "previous" in body
    assert body["previous"]["label"] == "last year (full period)"
    assert body["trend"] in {"up", "down", "flat"}


def test_cost_comparison_same_elapsed_mode():
    response = client.get(
        "/cost/comparison?period=monthly&comparison_mode=same_elapsed",
        headers=_admin_headers("comparison-same-elapsed"),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["comparison_mode"] == "same_elapsed"
    assert "same elapsed time" in body["previous"]["label"]
