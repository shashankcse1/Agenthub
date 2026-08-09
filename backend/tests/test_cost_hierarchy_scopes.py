from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import CostEvent
from app.routers.gateway import _resolve_inference_owner_scope
from app.services.cost_limits import (
    count_scope_requests_since,
    evaluate_actor_cost_limits,
    member_spend_contributions,
    rollup_owner_scopes_for_scope,
    sum_scope_cost_cents,
    sum_scope_tokens_since,
)

client = TestClient(app)


def _admin_headers(actor_id: str) -> dict[str, str]:
    return {"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id, "X-MFA-Verified": "true"}


def _master_headers(actor_id: str) -> dict[str, str]:
    return {"X-Actor-Role": "Master Admin", "X-Actor-Id": actor_id, "X-MFA-Verified": "true"}


def test_gateway_inference_owner_scope_defaults_to_user():
    db = SessionLocal()
    try:
        actor_id = f"actor-{uuid4().hex[:8]}"
        assert _resolve_inference_owner_scope(db, actor_id=actor_id, owner_scope=None) == f"user:{actor_id}"
        assert _resolve_inference_owner_scope(db, actor_id=actor_id, owner_scope="") == f"user:{actor_id}"
        assert (
            _resolve_inference_owner_scope(db, actor_id=actor_id, owner_scope=f"team:team-{uuid4().hex[:6]}")
            .startswith("team:")
        )
    finally:
        db.close()


def test_team_budget_rollups_member_user_spend_and_auto_resolves_membership():
    suffix = uuid4().hex[:8]
    admin_id = f"admin-rollup-{suffix}"
    actor_id = f"member-{suffix}"
    team_id = f"team-rollup-{suffix}"

    created_user = client.post(
        "/auth/directory/users",
        json={
            "user_id": actor_id,
            "display_name": "Rollup Member",
            "email": f"{actor_id}@example.com",
            "role_name": "Agent Owner",
            "status": "active",
            "password": "StrongPass!234",
        },
        headers=_master_headers(admin_id),
    )
    assert created_user.status_code == 200

    created_team = client.post(
        "/auth/directory/teams",
        json={"team_id": team_id, "display_name": "Rollup Team", "description": "rollup", "status": "active"},
        headers=_master_headers(admin_id),
    )
    assert created_team.status_code == 200

    membership = client.post(
        f"/auth/directory/teams/{team_id}/members/{actor_id}",
        headers=_master_headers(admin_id),
    )
    assert membership.status_code == 200

    team_budget = client.post(
        "/cost/budgets",
        json={
            "scope_type": "team",
            "scope_id": team_id,
            "budget_amount_cents": 500,
            "window_type": "daily",
            "soft_limit_percent": 80,
            "hard_limit_percent": 100,
            "action_on_soft_limit": "warn",
            "action_on_hard_limit": "block",
        },
        headers=_admin_headers(admin_id),
    )
    assert team_budget.status_code == 200

    db = SessionLocal()
    try:
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id=f"req-rollup-{suffix}",
                trace_id=f"trace-rollup-{suffix}",
                session_id=f"session-rollup-{suffix}",
                agent_id=f"agent-rollup-{suffix}",
                owner_scope=f"user:{actor_id}",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=10,
                output_tokens=5,
                estimated_cost_cents=480,
                currency="USD",
            )
        )
        db.commit()
        scopes = rollup_owner_scopes_for_scope(db, "team", team_id)
        assert f"team:{team_id}" in scopes
        assert f"user:{actor_id}" in scopes
        assert sum_scope_cost_cents(db, scope_type="team", scope_id=team_id) >= 480
        evaluation = evaluate_actor_cost_limits(
            db,
            actor_id=actor_id,
            team_ids=None,
            group_ids=[],
            window_type="daily",
            projected_additional_cost_cents=50,
            auto_resolve_directory_memberships=True,
        )
        assert evaluation.aggregated_decision == "deny"
        assert f"team:{team_id}" in evaluation.blocking_scopes
    finally:
        db.close()

    evaluate = client.post(
        "/cost/limits/evaluate",
        json={
            "actor_id": actor_id,
            "team_ids": [],
            "group_ids": [],
            "window_type": "daily",
            "projected_additional_cost_cents": 50,
        },
        headers=_admin_headers(f"eval-{suffix}"),
    )
    assert evaluate.status_code == 200
    body = evaluate.json()
    assert body["aggregated_decision"] == "deny"
    assert f"team:{team_id}" in body["blocking_scopes"]


def test_cost_hierarchy_endpoint_shape_and_group_budget_manage_authz():
    suffix = uuid4().hex[:8]
    admin_id = f"admin-hier-{suffix}"
    owner_id = f"owner-hier-{suffix}"
    group_id = f"group-hier-{suffix}"
    team_id = f"team-hier-{suffix}"

    created_user = client.post(
        "/auth/directory/users",
        json={
            "user_id": owner_id,
            "display_name": "Hierarchy Owner",
            "email": f"{owner_id}@example.com",
            "role_name": "Agent Owner",
            "status": "active",
            "password": "StrongPass!234",
        },
        headers=_master_headers(admin_id),
    )
    assert created_user.status_code == 200

    assert (
        client.post(
            "/auth/directory/groups",
            json={"group_id": group_id, "display_name": "Hierarchy Group", "description": "hier", "status": "active"},
            headers=_master_headers(admin_id),
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/auth/directory/teams",
            json={"team_id": team_id, "display_name": "Hierarchy Team", "description": "hier", "status": "active"},
            headers=_master_headers(admin_id),
        ).status_code
        == 200
    )
    assert client.post(f"/auth/directory/groups/{group_id}/members/{owner_id}", headers=_master_headers(admin_id)).status_code == 200
    assert client.post(f"/auth/directory/teams/{team_id}/members/{owner_id}", headers=_master_headers(admin_id)).status_code == 200

    group_budget = client.post(
        "/cost/budgets",
        json={
            "scope_type": "group",
            "scope_id": group_id,
            "budget_amount_cents": 2000,
            "window_type": "daily",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": owner_id},
    )
    assert group_budget.status_code == 200

    forbidden = client.post(
        "/cost/budgets",
        json={
            "scope_type": "group",
            "scope_id": f"group-other-{suffix}",
            "budget_amount_cents": 2000,
            "window_type": "daily",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": owner_id},
    )
    assert forbidden.status_code == 403

    db = SessionLocal()
    try:
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id=f"req-hier-{suffix}",
                trace_id=f"trace-hier-{suffix}",
                session_id=f"session-hier-{suffix}",
                agent_id=f"agent-hier-{suffix}",
                owner_scope=f"user:{owner_id}",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="chat.completions",
                input_tokens=5,
                output_tokens=5,
                estimated_cost_cents=75,
                currency="USD",
            )
        )
        db.commit()
    finally:
        db.close()

    hierarchy = client.get(
        f"/cost/hierarchy?actor_id={owner_id}&window_hours=24&include_members=true&top_members=5",
        headers=_admin_headers(admin_id),
    )
    assert hierarchy.status_code == 200
    body = hierarchy.json()
    assert body["actor_id"] == owner_id
    assert body["window_hours"] == 24
    assert body["user_spend_cents"] >= 75
    assert body.get("user_hours_spend_cents", body["user_spend_cents"]) >= 75
    assert any(item["scope_id"] == team_id for item in body["teams"])
    group_row = next(item for item in body["groups"] if item["scope_id"] == group_id)
    assert group_row["spend_cents"] >= 75
    assert group_row.get("hours_spend_cents", group_row["spend_cents"]) >= 75
    assert group_row["member_spend_cents"] >= 75
    assert any(member["user_id"] == owner_id and member["spend_cents"] >= 75 for member in group_row["top_members"])
    assert "soft_alert_scopes" in body
    assert "blocking_scopes" in body

    alerts = client.get(
        f"/cost/hierarchy/alerts?actor_id={owner_id}&window_hours=24",
        headers=_admin_headers(admin_id),
    )
    assert alerts.status_code == 200
    alerts_body = alerts.json()
    assert alerts_body["actor_id"] == owner_id
    assert "soft_alert_count" in alerts_body
    assert "blocking_count" in alerts_body
    assert isinstance(alerts_body.get("alerts"), list)
    for alert in alerts_body["alerts"]:
        assert alert.get("decision") in {"warn", "deny"}
        assert alert.get("severity") in {"critical", "high"}
        assert "spend_cents" in alert
        assert "hours_spend_cents" in alert
        assert "utilization_percent" in alert
        assert "effective_budget_cents" in alert
        assert "recommended_action" in alert
        assert "budget_policy_id" in alert
        assert "window_type" in alert

    explained = client.get(
        f"/cost/hierarchy/explain?scope_type=group&scope_id={group_id}&window_hours=24&top_members=5",
        headers=_admin_headers(admin_id),
    )
    assert explained.status_code == 200
    explain_body = explained.json()
    assert explain_body["scope_type"] == "group"
    assert explain_body["scope_id"] == group_id
    assert explain_body["spend_cents"] >= 75
    assert explain_body.get("hours_spend_cents", explain_body["spend_cents"]) >= 75
    assert explain_body["member_spend_cents"] >= 75
    assert isinstance(explain_body.get("reasons"), list)
    assert explain_body["reasons"]
    assert any(scope.startswith("user:") for scope in explain_body.get("owner_scopes_counted") or [])


def test_cost_breakdown_and_timeseries_roll_up_member_spend():
    suffix = uuid4().hex[:8]
    admin_id = f"admin-analytics-{suffix}"
    member_id = f"member-analytics-{suffix}"
    team_id = f"team-analytics-{suffix}"

    assert (
        client.post(
            "/auth/directory/users",
            json={
                "user_id": member_id,
                "display_name": "Analytics Member",
                "email": f"{member_id}@example.com",
                "role_name": "Agent Owner",
                "status": "active",
                "password": "StrongPass!234",
            },
            headers=_master_headers(admin_id),
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/auth/directory/teams",
            json={"team_id": team_id, "display_name": "Analytics Team", "description": "a", "status": "active"},
            headers=_master_headers(admin_id),
        ).status_code
        == 200
    )
    assert client.post(f"/auth/directory/teams/{team_id}/members/{member_id}", headers=_master_headers(admin_id)).status_code == 200

    db = SessionLocal()
    try:
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id=f"req-analytics-{suffix}",
                trace_id=f"trace-analytics-{suffix}",
                session_id=f"session-analytics-{suffix}",
                agent_id=f"agent-analytics-{suffix}",
                owner_scope=f"user:{member_id}",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=1,
                output_tokens=1,
                estimated_cost_cents=125,
                currency="USD",
            )
        )
        db.commit()
    finally:
        db.close()

    breakdown = client.get(
        f"/cost/breakdown?dimension=team&window_hours=24&limit=50",
        headers=_admin_headers(admin_id),
    )
    assert breakdown.status_code == 200
    team_items = [item for item in breakdown.json().get("items", []) if item.get("label") == team_id]
    assert team_items
    assert team_items[0]["spend_cents"] >= 125

    timeseries = client.get(
        f"/cost/timeseries?dimension=team&window_hours=24&scope_filter={team_id}",
        headers=_admin_headers(admin_id),
    )
    assert timeseries.status_code == 200
    assert timeseries.json()["total_spend_cents"] >= 125

    teams_series = client.get(
        f"/cost/teams/timeseries?window_hours=24&team_filter={team_id}",
        headers=_admin_headers(admin_id),
    )
    assert teams_series.status_code == 200
    assert teams_series.json()["total_spend_cents"] >= 125


def test_member_spend_contributions_split_tagged_and_member():
    from app.services.cost_limits import member_spend_contributions

    suffix = uuid4().hex[:8]
    admin_id = f"admin-contrib-{suffix}"
    member_id = f"member-contrib-{suffix}"
    team_id = f"team-contrib-{suffix}"

    assert (
        client.post(
            "/auth/directory/users",
            json={
                "user_id": member_id,
                "display_name": "Contributor",
                "email": f"{member_id}@example.com",
                "role_name": "Agent Owner",
                "status": "active",
                "password": "StrongPass!234",
            },
            headers=_master_headers(admin_id),
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/auth/directory/teams",
            json={"team_id": team_id, "display_name": "Contrib Team", "description": "c", "status": "active"},
            headers=_master_headers(admin_id),
        ).status_code
        == 200
    )
    assert client.post(f"/auth/directory/teams/{team_id}/members/{member_id}", headers=_master_headers(admin_id)).status_code == 200

    db = SessionLocal()
    try:
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id=f"req-tagged-{suffix}",
                trace_id=f"trace-tagged-{suffix}",
                session_id=f"session-tagged-{suffix}",
                agent_id=f"agent-tagged-{suffix}",
                owner_scope=f"team:{team_id}",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=1,
                output_tokens=1,
                estimated_cost_cents=40,
                currency="USD",
            )
        )
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id=f"req-member-{suffix}",
                trace_id=f"trace-member-{suffix}",
                session_id=f"session-member-{suffix}",
                agent_id=f"agent-member-{suffix}",
                owner_scope=f"user:{member_id}",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=1,
                output_tokens=1,
                estimated_cost_cents=60,
                currency="USD",
            )
        )
        db.commit()
        tagged, member_total, top = member_spend_contributions(db, scope_type="team", scope_id=team_id, top_n=3)
        assert tagged == 40
        assert member_total == 60
        assert top[0]["user_id"] == member_id
        assert top[0]["spend_cents"] == 60
        assert top[0]["share_percent"] == 60.0
    finally:
        db.close()


def test_budget_list_includes_rollup_spend_and_owners_filter_includes_members():
    suffix = uuid4().hex[:8]
    admin_id = f"admin-list-{suffix}"
    member_id = f"member-list-{suffix}"
    team_id = f"team-list-{suffix}"

    assert (
        client.post(
            "/auth/directory/users",
            json={
                "user_id": member_id,
                "display_name": "List Member",
                "email": f"{member_id}@example.com",
                "role_name": "Agent Owner",
                "status": "active",
                "password": "StrongPass!234",
            },
            headers=_master_headers(admin_id),
        ).status_code
        == 200
    )
    assert (
        client.post(
            "/auth/directory/teams",
            json={"team_id": team_id, "display_name": "List Team", "description": "list", "status": "active"},
            headers=_master_headers(admin_id),
        ).status_code
        == 200
    )
    assert client.post(f"/auth/directory/teams/{team_id}/members/{member_id}", headers=_master_headers(admin_id)).status_code == 200

    created = client.post(
        "/cost/budgets",
        json={
            "scope_type": "team",
            "scope_id": team_id,
            "budget_amount_cents": 1000,
            "window_type": "daily",
            "soft_limit_percent": 80,
            "hard_limit_percent": 100,
            "action_on_soft_limit": "warn",
            "action_on_hard_limit": "block",
        },
        headers=_admin_headers(admin_id),
    )
    assert created.status_code == 200

    db = SessionLocal()
    try:
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id=f"req-list-{suffix}",
                trace_id=f"trace-list-{suffix}",
                session_id=f"session-list-{suffix}",
                agent_id=f"agent-list-{suffix}",
                owner_scope=f"user:{member_id}",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=5,
                output_tokens=5,
                estimated_cost_cents=250,
                currency="USD",
            )
        )
        db.commit()
        assert count_scope_requests_since(db, scope_type="team", scope_id=team_id) >= 1
        assert sum_scope_tokens_since(db, scope_type="team", scope_id=team_id) == 10
    finally:
        db.close()

    listed = client.get("/cost/budgets", headers=_admin_headers(admin_id), params={"scope_id": team_id})
    assert listed.status_code == 200
    rows = [row for row in listed.json() if row.get("scope_id") == team_id]
    assert rows
    assert int(rows[0].get("current_spend_cents") or 0) == 250
    assert float(rows[0].get("utilization_percent") or 0) == 25.0

    owners = client.get(
        "/cost/owners/timeseries",
        headers=_admin_headers(admin_id),
        params={"owner_filter": f"team:{team_id}", "window_hours": 24},
    )
    assert owners.status_code == 200
    payload = owners.json()
    assert int(payload.get("total_spend_cents") or 0) >= 250
    assert any(str(item.get("owner_scope") or "").endswith(member_id) for item in payload.get("series") or [])


def test_track_spend_normalizes_actor_scope_to_user():
    suffix = uuid4().hex[:8]
    admin_id = f"admin-track-{suffix}"
    actor_id = f"actor-track-{suffix}"
    agent_id = f"agent-track-{suffix}"

    tracked = client.post(
        "/cost/events",
        json={
            "request_id": f"req-track-{suffix}",
            "trace_id": f"trace-track-{suffix}",
            "session_id": f"session-track-{suffix}",
            "agent_id": agent_id,
            "scope_type": "actor",
            "scope_id": actor_id,
            "environment": "dev",
            "model_name": "gpt-test",
            "endpoint_family": "responses",
            "input_tokens": 1,
            "output_tokens": 1,
            "estimated_cost_cents": 11,
            "currency": "USD",
            "request_tag": f"tag-{suffix}",
        },
        headers=_admin_headers(admin_id),
    )
    assert tracked.status_code == 200
    assert tracked.json().get("owner_scope") == f"user:{actor_id}"


def test_actor_budget_alias_resolves_for_user_hierarchy_and_session_caps():
    from app.services.cost_limits import evaluate_session_cost_caps, find_active_budget

    suffix = uuid4().hex[:8]
    admin_id = f"admin-adv-{suffix}"
    actor_id = f"user-adv-{suffix}"
    session_id = f"session-adv-{suffix}"

    assert (
        client.post(
            "/auth/directory/users",
            json={
                "user_id": actor_id,
                "display_name": "Adv User",
                "email": f"{actor_id}@example.com",
                "role_name": "Agent Owner",
                "status": "active",
                "password": "StrongPass!234",
            },
            headers=_master_headers(admin_id),
        ).status_code
        == 200
    )

    created = client.post(
        "/cost/budgets",
        json={
            "scope_type": "actor",
            "scope_id": actor_id,
            "budget_amount_cents": 100,
            "window_type": "daily",
            "soft_limit_percent": 50,
            "hard_limit_percent": 100,
            "action_on_soft_limit": "warn",
            "action_on_hard_limit": "block",
            "session_budget_cents": 40,
            "session_iteration_cap": 2,
            "soft_alert_enabled": True,
        },
        headers=_admin_headers(admin_id),
    )
    assert created.status_code == 200

    db = SessionLocal()
    try:
        budget = find_active_budget(db, "user", actor_id)
        assert budget is not None
        assert budget.scope_type == "actor"
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id=f"req-adv-{suffix}",
                trace_id=f"trace-adv-{suffix}",
                session_id=session_id,
                agent_id=f"agent-adv-{suffix}",
                owner_scope=f"user:{actor_id}",
                environment="prod",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=1,
                output_tokens=1,
                estimated_cost_cents=55,
                currency="USD",
            )
        )
        db.commit()
    finally:
        db.close()

    hierarchy = client.get(
        "/cost/hierarchy",
        headers=_admin_headers(admin_id),
        params={"actor_id": actor_id, "window_mode": "budget", "environment": "prod"},
    )
    assert hierarchy.status_code == 200
    body = hierarchy.json()
    assert body.get("window_mode") == "budget"
    assert body.get("environment") == "prod"
    assert body.get("user_budget") is not None
    assert body["user_budget"]["resolved_budget_scope_type"] == "actor"
    assert body["user_budget"]["decision"] in {"warn", "deny"}
    assert int(body.get("user_spend_cents") or 0) == 55

    explain = client.get(
        "/cost/hierarchy/explain",
        headers=_admin_headers(admin_id),
        params={
            "scope_type": "user",
            "scope_id": actor_id,
            "window_mode": "budget",
            "environment": "prod",
        },
    )
    assert explain.status_code == 200
    explain_body = explain.json()
    assert explain_body.get("resolved_budget_scope_type") == "actor"
    assert any("alias" in str(reason).lower() for reason in explain_body.get("reasons") or [])

    filtered_out = client.get(
        "/cost/hierarchy",
        headers=_admin_headers(admin_id),
        params={"actor_id": actor_id, "environment": "dev"},
    )
    assert filtered_out.status_code == 200
    assert int(filtered_out.json().get("user_spend_cents") or 0) == 0

    anomalies = client.get("/cost/anomalies", headers=_admin_headers(admin_id), params={"environment": "prod"})
    assert anomalies.status_code == 200
    assert any(
        row.get("scope_id") == actor_id and "soft" in str(row.get("anomaly_type") or "")
        for row in anomalies.json()
    )

    db = SessionLocal()
    try:
        caps = evaluate_session_cost_caps(
            db,
            actor_id=actor_id,
            session_id=session_id,
            projected_additional_cost_cents=0,
            environment="prod",
        )
        assert caps.decision == "deny"
        assert caps.session_spend_cents >= 55
        assert any("session_budget_cents" in reason for reason in caps.reasons)
    finally:
        db.close()


def test_users_analytics_falls_back_to_owner_scope_when_properties_missing():
    suffix = uuid4().hex[:8]
    admin_id = f"admin-users-{suffix}"
    member_id = f"member-users-{suffix}"

    db = SessionLocal()
    try:
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id=f"req-users-{suffix}",
                trace_id=f"trace-users-{suffix}",
                session_id=f"session-users-{suffix}",
                agent_id=f"agent-users-{suffix}",
                owner_scope=f"user:{member_id}",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=1,
                output_tokens=1,
                estimated_cost_cents=33,
                currency="USD",
                properties_json="{}",
            )
        )
        db.commit()
    finally:
        db.close()

    listed = client.get(
        "/cost/users",
        headers=_admin_headers(admin_id),
        params={"user_filter": member_id, "window_hours": 24},
    )
    assert listed.status_code == 200
    items = listed.json().get("items") or []
    assert any(item.get("user_id") == member_id and int(item.get("spend_cents") or 0) >= 33 for item in items)
