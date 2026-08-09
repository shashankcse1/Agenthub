from unittest.mock import MagicMock, patch

from app.services.gateway_leadership_pack16 import (
    apply_shadow_traffic_metadata,
    attribution_anomaly_detector,
    competitive_scorecard_delta,
    cost_quality_pareto_frontier,
    executive_leadership_brief,
    get_shadow_traffic_percent,
    pack16_manifest,
    put_canary_auto_rollback,
    put_shadow_traffic_percent,
    warmup_budget_remaining,
)


def test_pack16_manifest_and_shadow_metadata():
    assert pack16_manifest()["pack"] == 16
    assert pack16_manifest()["gov"] == "GOV-AI-MARKET-016"
    assert pack16_manifest()["items"] == list(range(221, 241))
    decision = apply_shadow_traffic_metadata(
        {"selected_model": "gpt-4o-mini"},
        {"enabled": True, "percent": 12.5},
    )
    assert decision["shadow_traffic"]["percent"] == 12.5
    assert decision["shadow_traffic"]["soft"] is True


def test_pack16_score_delta_and_shadow_controller():
    db = MagicMock()
    stored = {
        "gateway.leadership.history_json": [
            {"snapshot_id": "a", "score": 82, "band": "leader"},
            {"snapshot_id": "b", "score": 75, "band": "emerging"},
        ]
    }

    def fake_get(_db, key, default="{}"):
        return stored.get(key, [] if default == "[]" else {})

    def fake_set(_db, key, value, description=""):
        stored[key] = value

    with patch("app.services.gateway_leadership_pack16._rt_get", side_effect=fake_get), patch(
        "app.services.gateway_leadership_pack16._rt_set",
        side_effect=fake_set,
    ), patch(
        "app.services.gateway_leadership_pack16.record_ops_activity",
    ):
        delta = competitive_scorecard_delta(db)
        shadow = put_shadow_traffic_percent(db, percent=15, enabled=True)
        loaded = get_shadow_traffic_percent(db)
        canary = put_canary_auto_rollback(db, enabled=True, on_red_light=True, on_floor_fail=False)
    assert delta["score_delta"] == 7.0
    assert delta["direction"] == "up"
    assert shadow["percent"] == 15.0
    assert loaded["enabled"] is True
    assert canary["on_floor_fail"] is False


def test_pack16_anomalies_warmup_pareto_brief():
    db = MagicMock()
    with patch(
        "app.services.gateway_leadership_pack15.auto_route_audit_summary",
        return_value={
            "count": 10,
            "cache_hit_rate_percent": 96.0,
            "by_strategy": {"balanced": 9, "cost": 1},
        },
    ):
        anomalies = attribution_anomaly_detector(db)
    assert anomalies["anomaly_count"] >= 1

    with patch(
        "app.services.gateway_leadership_pack16.warmup_eligibility_probe",
        return_value={"allowed": True, "count": 1, "max_per_hour": 3, "message": "ok"},
    ):
        budget = warmup_budget_remaining(db)
    assert budget["remaining"] == 2

    with patch(
        "app.services.gateway_leadership.build_model_liquidity_ranking",
        return_value={
            "models": [
                {"model_name": "a", "score": 90, "avg_cost_cents": 10},
                {"model_name": "b", "score": 80, "avg_cost_cents": 5},
                {"model_name": "c", "score": 70, "avg_cost_cents": 20},
            ]
        },
    ):
        pareto = cost_quality_pareto_frontier(db)
    assert pareto["frontier_count"] >= 1

    with patch(
        "app.services.gateway_leadership_pack16.composite_go_no_go",
        return_value={
            "passed": True,
            "decision": "go",
            "traffic_light": {"light": "green", "score": 88},
        },
    ), patch(
        "app.services.gateway_leadership_pack16.competitive_scorecard_delta",
        return_value={"score_delta": 2.0},
    ), patch(
        "app.services.gateway_leadership_pack16.list_leadership_incidents",
        return_value={"count": 0, "incidents": []},
    ):
        brief = executive_leadership_brief(db)
    assert brief["decision"] == "go"
    assert "Executive brief" in brief["message"]
