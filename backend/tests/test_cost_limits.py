from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import CostEvent

client = TestClient(app)


def _admin_headers(actor_id: str) -> dict[str, str]:
    return {"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id}


def test_cost_limit_evaluate_aggregates_user_and_team_limits():
    actor_id = f"user-{uuid4()}"
    team_id = f"team-{uuid4()}"

    user_budget = client.post(
        "/cost/budgets",
        json={
            "scope_type": "user",
            "scope_id": actor_id,
            "budget_amount_cents": 1000,
            "window_type": "daily",
            "soft_limit_percent": 80,
            "hard_limit_percent": 100,
            "action_on_soft_limit": "warn",
            "action_on_hard_limit": "block",
        },
        headers=_admin_headers("budget-admin-1"),
    )
    assert user_budget.status_code == 200

    team_budget = client.post(
        "/cost/budgets",
        json={
            "scope_type": "team",
            "scope_id": team_id,
            "budget_amount_cents": 2000,
            "window_type": "daily",
            "soft_limit_percent": 80,
            "hard_limit_percent": 100,
            "action_on_soft_limit": "warn",
            "action_on_hard_limit": "block",
        },
        headers=_admin_headers("budget-admin-2"),
    )
    assert team_budget.status_code == 200

    db = SessionLocal()
    try:
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id="req-user-limit",
                trace_id="trace-user-limit",
                session_id="session-user-limit",
                agent_id="agent-user-limit",
                owner_scope=f"user:{actor_id}",
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
                request_id="req-team-limit",
                trace_id="trace-team-limit",
                session_id="session-team-limit",
                agent_id="agent-team-limit",
                owner_scope=f"team:{team_id}",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=100,
                output_tokens=50,
                estimated_cost_cents=1900,
                currency="USD",
            )
        )
        db.commit()
    finally:
        db.close()

    evaluate = client.post(
        "/cost/limits/evaluate",
        json={
            "actor_id": actor_id,
            "team_ids": [team_id],
            "projected_additional_cost_cents": 200,
            "window_type": "daily",
        },
        headers=_admin_headers("policy-evaluator-1"),
    )
    assert evaluate.status_code == 200
    body = evaluate.json()
    assert body["aggregated_decision"] == "deny"
    assert f"user:{actor_id}" in body["blocking_scopes"]
    assert f"team:{team_id}" in body["blocking_scopes"]


def test_cost_limit_evaluate_returns_allow_when_no_matching_limits():
    evaluate = client.post(
        "/cost/limits/evaluate",
        json={
            "actor_id": f"user-{uuid4()}",
            "team_ids": [f"team-{uuid4()}"],
            "group_ids": [f"group-{uuid4()}"],
            "window_type": "daily",
        },
        headers=_admin_headers("policy-evaluator-2"),
    )
    assert evaluate.status_code == 200
    body = evaluate.json()
    assert body["aggregated_decision"] == "allow"
    assert body["scopes_evaluated"] == []
    assert body["blocking_scopes"] == []


def test_playground_run_is_blocked_when_cost_limit_is_exceeded():
    actor_id = f"user-{uuid4()}"

    user_budget = client.post(
        "/cost/budgets",
        json={
            "scope_type": "user",
            "scope_id": actor_id,
            "budget_amount_cents": 100,
            "window_type": "daily",
            "soft_limit_percent": 80,
            "hard_limit_percent": 100,
            "action_on_soft_limit": "warn",
            "action_on_hard_limit": "block",
        },
        headers=_admin_headers("budget-admin-playground"),
    )
    assert user_budget.status_code == 200

    db = SessionLocal()
    try:
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id="req-playground-limit",
                trace_id="trace-playground-limit",
                session_id="session-playground-limit",
                agent_id="agent-playground-limit",
                owner_scope=f"user:{actor_id}",
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

    denied = client.post(
        "/playground/runs",
        json={
            "prompt_text": "blocked-by-budget",
            "candidate_models": '["model-a"]',
            "selected_model": "model-a",
            "projected_additional_cost_cents": 1,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id},
    )
    assert denied.status_code == 403
    detail = denied.json()["detail"]
    assert detail["error_code"] == "COST_LIMIT_EXCEEDED"
    assert f"user:{actor_id}" in detail["blocking_scopes"]


def test_budget_policy_lifecycle_list_update_delete():
    scope_id = f"actor-{uuid4()}"

    created = client.post(
        "/cost/budgets",
        json={
            "scope_type": "actor",
            "scope_id": scope_id,
            "budget_amount_cents": 3000,
            "window_type": "daily",
            "soft_limit_percent": 70,
            "hard_limit_percent": 90,
            "action_on_soft_limit": "notify",
            "action_on_hard_limit": "block",
        },
        headers=_admin_headers("budget-lifecycle-admin"),
    )
    assert created.status_code == 200
    created_body = created.json()
    budget_id = created_body["budget_policy_id"]

    listed = client.get(
        f"/cost/budgets?status=active&scope_type=actor&scope_id={scope_id}&limit=10&offset=0",
        headers=_admin_headers("budget-lifecycle-reader"),
    )
    assert listed.status_code == 200
    listed_rows = listed.json()
    assert any(row["budget_policy_id"] == budget_id for row in listed_rows)

    updated = client.put(
        f"/cost/budgets/{budget_id}",
        json={
            "scope_type": "actor",
            "scope_id": scope_id,
            "budget_amount_cents": 4500,
            "window_type": "weekly",
            "soft_limit_percent": 75,
            "hard_limit_percent": 95,
            "action_on_soft_limit": "throttle",
            "action_on_hard_limit": "block",
        },
        headers=_admin_headers("budget-lifecycle-admin"),
    )
    assert updated.status_code == 200
    updated_body = updated.json()
    assert updated_body["budget_amount_cents"] == 4500
    assert updated_body["window_type"] == "weekly"
    assert updated_body["action_on_soft_limit"] == "throttle"

    deleted = client.delete(
        f"/cost/budgets/{budget_id}",
        headers=_admin_headers("budget-lifecycle-admin"),
    )
    assert deleted.status_code == 200
    assert deleted.json()["status"] == "deleted"

    listed_after_delete = client.get(
        f"/cost/budgets?status=active&scope_type=actor&scope_id={scope_id}&limit=10&offset=0",
        headers=_admin_headers("budget-lifecycle-reader"),
    )
    assert listed_after_delete.status_code == 200
    assert all(row["budget_policy_id"] != budget_id for row in listed_after_delete.json())


def test_budget_policy_supports_temporary_increase_and_agent_controls():
    scope_id = f"agent-{uuid4()}"
    created = client.post(
        "/cost/budgets",
        json={
            "scope_type": "agent",
            "scope_id": scope_id,
            "budget_amount_cents": 1000,
            "window_type": "daily",
            "temporary_increase_cents": 500,
            "rate_limit_tpm": 12000,
            "rate_limit_rpm": 120,
            "session_iteration_cap": 20,
            "session_budget_cents": 1500,
        },
        headers=_admin_headers("budget-agent-controls"),
    )
    assert created.status_code == 200
    body = created.json()
    assert body["temporary_increase_cents"] == 500
    assert body["rate_limit_tpm"] == 12000
    assert body["rate_limit_rpm"] == 120
    assert body["session_iteration_cap"] == 20
    assert body["session_budget_cents"] == 1500
    assert body["effective_budget_cents"] == 1500


def test_budget_list_includes_effective_budget_cents():
    scope_id = f"actor-{uuid4()}"
    created = client.post(
        "/cost/budgets",
        json={
            "scope_type": "actor",
            "scope_id": scope_id,
            "budget_amount_cents": 2000,
            "window_type": "daily",
            "temporary_increase_cents": 250,
        },
        headers=_admin_headers("budget-effective-list"),
    )
    assert created.status_code == 200
    assert created.json()["effective_budget_cents"] == 2250

    listed = client.get(
        f"/cost/budgets?status=active&scope_type=actor&scope_id={scope_id}",
        headers=_admin_headers("budget-effective-list-reader"),
    )
    assert listed.status_code == 200
    row = next(item for item in listed.json() if item["scope_id"] == scope_id)
    assert row["effective_budget_cents"] == 2250


def test_weekly_budget_window_excludes_older_spend():
    from datetime import datetime, timedelta

    scope_id = f"user-{uuid4()}"
    created = client.post(
        "/cost/budgets",
        json={
            "scope_type": "user",
            "scope_id": scope_id,
            "budget_amount_cents": 1000,
            "window_type": "weekly",
            "soft_limit_percent": 80,
            "hard_limit_percent": 100,
        },
        headers=_admin_headers("budget-weekly-window"),
    )
    assert created.status_code == 200

    db = SessionLocal()
    try:
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                timestamp=datetime.utcnow() - timedelta(days=10),
                request_id="req-weekly-old",
                trace_id="trace-weekly-old",
                session_id="session-weekly-old",
                agent_id="agent-weekly-old",
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
                request_id="req-weekly-recent",
                trace_id="trace-weekly-recent",
                session_id="session-weekly-recent",
                agent_id="agent-weekly-recent",
                owner_scope=f"user:{scope_id}",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=100,
                output_tokens=50,
                estimated_cost_cents=200,
                currency="USD",
            )
        )
        db.commit()
    finally:
        db.close()

    evaluated = client.post(
        "/cost/policies/evaluate",
        json={"scope_type": "user", "scope_id": scope_id, "window_type": "weekly"},
        headers=_admin_headers("budget-weekly-eval"),
    )
    assert evaluated.status_code == 200
    body = evaluated.json()
    assert body["spend_cents"] == 200
    assert body["spend_cents"] < 900


def test_cost_live_returns_recent_session_and_agent_ids():
    session_id = f"session-live-{uuid4()}"
    agent_id = f"agent-live-{uuid4()}"

    db = SessionLocal()
    try:
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id="req-live-recent",
                trace_id="trace-live-recent",
                session_id=session_id,
                agent_id=agent_id,
                owner_scope="user:live-cost-reader",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=10,
                output_tokens=5,
                estimated_cost_cents=12,
                currency="USD",
            )
        )
        db.commit()
    finally:
        db.close()

    live = client.get("/cost/live", headers=_admin_headers("live-cost-reader"))
    assert live.status_code == 200
    body = live.json()
    assert session_id in body["recent_sessions"]
    assert agent_id in body["recent_agents"]


def test_cost_breakdown_request_tag_respects_agent_owner_scope():
    from app.models import Agent

    owner_id = f"owner-breakdown-{uuid4()}"
    owned_agent_id = f"agent-owned-{uuid4()}"
    foreign_agent_id = f"agent-foreign-{uuid4()}"

    db = SessionLocal()
    try:
        db.add_all(
            [
                Agent(
                    agent_id=owned_agent_id,
                    name="Owned Agent",
                    owner_id=owner_id,
                    owner_name="Owner",
                    owner_team="Team",
                    risk_tier="low",
                    status="active",
                ),
                Agent(
                    agent_id=foreign_agent_id,
                    name="Foreign Agent",
                    owner_id=f"other-{uuid4()}",
                    owner_name="Other",
                    owner_team="Other Team",
                    risk_tier="low",
                    status="active",
                ),
            ]
        )
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id="req-owned-tag",
                trace_id="trace-owned-tag",
                request_tag="owned-tag",
                session_id="session-owned-tag",
                agent_id=owned_agent_id,
                owner_scope=f"owner:{owner_id}",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=10,
                output_tokens=5,
                estimated_cost_cents=100,
                currency="USD",
            )
        )
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id="req-foreign-tag",
                trace_id="trace-foreign-tag",
                request_tag="foreign-tag",
                session_id="session-foreign-tag",
                agent_id=foreign_agent_id,
                owner_scope="owner:someone-else",
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
    finally:
        db.close()

    breakdown = client.get(
        "/cost/breakdown?dimension=request_tag&window_hours=24&limit=10",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": owner_id},
    )
    assert breakdown.status_code == 200
    body = breakdown.json()
    labels = {item["label"] for item in body["items"]}
    assert "owned-tag" in labels
    assert "foreign-tag" not in labels
    assert body["total_spend_cents"] == 100


def test_team_soft_budget_alert_is_emitted_in_anomalies():
    team_id = f"team-soft-alert-{uuid4()}"

    created = client.post(
        "/cost/budgets",
        json={
            "scope_type": "team",
            "scope_id": team_id,
            "budget_amount_cents": 1000,
            "soft_limit_percent": 80,
            "hard_limit_percent": 100,
            "soft_alert_enabled": True,
        },
        headers=_admin_headers("budget-team-soft-alert"),
    )
    assert created.status_code == 200

    db = SessionLocal()
    try:
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id="req-team-soft-alert",
                trace_id="trace-team-soft-alert",
                session_id="session-team-soft-alert",
                agent_id="agent-team-soft-alert",
                owner_scope=f"team:{team_id}",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=100,
                output_tokens=50,
                estimated_cost_cents=850,
                currency="USD",
            )
        )
        db.commit()
    finally:
        db.close()

    anomalies = client.get("/cost/anomalies", headers=_admin_headers("budget-team-soft-alert-reader"))
    assert anomalies.status_code == 200
    assert any(
        row["scope_type"] == "team" and row["scope_id"] == team_id and row["anomaly_type"] == "team_soft_budget_alert"
        for row in anomalies.json()
    )


def test_cost_limit_evaluate_auto_creates_default_budget_for_jwt_team():
    actor_id = f"jwt-actor-{uuid4()}"
    jwt_team_id = f"jwt-team-{uuid4()}"

    evaluate = client.post(
        "/cost/limits/evaluate",
        json={
            "actor_id": actor_id,
            "team_ids": [jwt_team_id],
            "window_type": "daily",
        },
        headers=_admin_headers("budget-jwt-default"),
    )
    assert evaluate.status_code == 200

    listed = client.get(
        f"/cost/budgets?status=active&scope_type=team&scope_id={jwt_team_id}&limit=10&offset=0",
        headers=_admin_headers("budget-jwt-default-reader"),
    )
    assert listed.status_code == 200
    assert any(row["scope_id"] == jwt_team_id for row in listed.json())


def test_agent_owner_budget_management_is_scope_limited():
    actor_id = f"owner-{uuid4()}"

    own_budget = client.post(
        "/cost/budgets",
        json={
            "scope_type": "actor",
            "scope_id": actor_id,
            "budget_amount_cents": 1500,
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": actor_id},
    )
    assert own_budget.status_code == 200

    forbidden_budget = client.post(
        "/cost/budgets",
        json={
            "scope_type": "actor",
            "scope_id": f"other-{uuid4()}",
            "budget_amount_cents": 1500,
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": actor_id},
    )
    assert forbidden_budget.status_code == 403


def test_budget_policy_timezone_reset_and_effective_budget_are_reported():
    scope_id = f"user-{uuid4()}"
    created = client.post(
        "/cost/budgets",
        json={
            "scope_type": "user",
            "scope_id": scope_id,
            "budget_amount_cents": 1000,
            "window_type": "daily",
            "reset_timezone": "America/New_York",
            "reset_hour_local": 6,
            "temporary_increase_cents": 300,
        },
        headers=_admin_headers("budget-timezone-reset"),
    )
    assert created.status_code == 200

    evaluated = client.post(
        "/cost/policies/evaluate",
        json={"scope_type": "user", "scope_id": scope_id, "window_type": "daily"},
        headers=_admin_headers("budget-timezone-eval"),
    )
    assert evaluated.status_code == 200
    body = evaluated.json()
    assert body["budget_cents"] == 1000
    assert body["effective_budget_cents"] == 1300
