import json
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.services.gateway_leadership_pack7 import (
    build_cache_auto_route_metrics,
    build_datadog_marketplace_notes,
    build_environment_diff_leadership,
    build_grafana_dashboard_json,
    build_otel_attribution_attributes,
    build_prometheus_leadership_metrics,
    build_qbr_leadership_embed,
    build_team_ranking_leaderboard,
    evaluate_and_queue_leadership_alerts,
    explain_canary_auto_route_interaction,
    recommend_route_draft_auto_route,
    sdk_auto_route_helper_contract,
    upsert_alert_channels,
    upsert_virtual_key_auto_route_policy,
)


def test_pack7_canary_and_route_draft_recommend():
    db = MagicMock()
    draft = SimpleNamespace(
        draft_id="draft-1",
        agent_id="agent-1",
        environment="dev",
        status="draft",
    )
    db.query.return_value.filter_by.return_value.first.return_value = draft
    with patch(
        "app.services.gateway_auto_router.build_auto_route_decision",
        return_value={
            "selected_model": "gpt-4o-mini",
            "complexity": {"tier": "simple", "score": 8},
            "rationale": "ok",
        },
    ), patch(
        "app.services.gateway_best_practices.suggest_readiness_aware_fallback_chain",
        return_value={"priority_order": [{"provider_id": "p1", "model_name": "gpt-4o-mini", "priority": 1}]},
    ):
        rec = recommend_route_draft_auto_route(db, draft_id="draft-1")
    assert rec["found"] is True
    assert rec["recommended_model"] == "gpt-4o-mini"

    route = SimpleNamespace(route_policy_id="rp-1", fallback_policy=json.dumps({"canary_rollout": {"enabled": True, "weight": 10}}))
    db.query.return_value.filter_by.return_value.first.return_value = route
    with patch(
        "app.services.gateway_auto_router.build_auto_route_decision",
        return_value={"selected_model": "gpt-4o", "complexity": {"tier": "standard"}, "strategy": "balanced"},
    ):
        explain = explain_canary_auto_route_interaction(db, route_policy_id="rp-1")
    assert explain["canary_enabled"] is True


def test_pack7_metrics_otel_grafana_datadog_sdk():
    db = MagicMock()
    index = {"score": 77, "band": "strong_challenger", "market_claim": "x", "next_actions": []}
    attribution = {
        "attribution_coverage_percent": 40.0,
        "auto_routed_events": 5,
        "switch_rate_percent": 12.0,
    }
    rankings = {"models": [{"model_name": "gpt-4o-mini", "score": 50}]}
    with patch(
        "app.services.gateway_leadership_pack7.build_gateway_leadership_index",
        return_value=index,
    ), patch(
        "app.services.gateway_leadership_pack7.build_attribution_analytics",
        return_value=attribution,
    ), patch(
        "app.services.gateway_leadership_pack7.build_model_liquidity_ranking",
        return_value=rankings,
    ):
        prom = build_prometheus_leadership_metrics(db)
        grafana = build_grafana_dashboard_json(db)
        qbr = build_qbr_leadership_embed(db)
    assert "agenthub_leadership_score 77" in prom["metrics_text"]
    assert grafana["dashboard"]["uid"] == "agenthub-leadership"
    assert qbr["score"] == 77
    notes = build_datadog_marketplace_notes()
    assert "agenthub.leadership.score" in notes["metrics"]
    otel = build_otel_attribution_attributes(
        intended_model="auto",
        actual_model="gpt-4o-mini",
        auto_route_tier="simple",
        strategy="balanced",
    )
    assert otel["span_attributes"]["agenthub.model.switched"] is True
    contract = sdk_auto_route_helper_contract()
    assert "auto_route_classify" in contract["python"]["methods"]


def test_pack7_team_boards_cache_alerts_vk_policy():
    events = [
        SimpleNamespace(
            owner_scope="team:platform",
            model_name="gpt-4o-mini",
            properties_json=json.dumps({"cache_hit": True, "auto_route_tier": "simple"}),
            timestamp=datetime.utcnow(),
        ),
        SimpleNamespace(
            owner_scope="team:platform",
            model_name="gpt-4o",
            properties_json=json.dumps({"mirrored": True, "mirror_mode": "shadow"}),
            timestamp=datetime.utcnow(),
        ),
    ]
    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events
    db.query.return_value.filter.return_value.limit.return_value.all.return_value = events
    boards = build_team_ranking_leaderboard(db, hours=24)
    assert boards["count"] >= 1
    cache = build_cache_auto_route_metrics(db, hours=24)
    assert cache["cache_hits"] >= 1

    with patch("app.services.runtime_config.upsert_runtime_config_value"), patch(
        "app.services.runtime_config.get_runtime_config",
        return_value="[]",
    ):
        db.query.return_value.filter_by.return_value.first.return_value = SimpleNamespace(key_id="vk-1")
        policy = upsert_virtual_key_auto_route_policy(db, virtual_key_id="vk-1", strategy="cost")
        channels = upsert_alert_channels(db, webhook_url="https://example.test/hook", enabled=True)
    assert policy["policy"]["strategy"] == "cost"
    assert channels["channels"]["webhook_url"]

    with patch(
        "app.services.gateway_leadership.build_leadership_alerts",
        return_value={"alert_count": 1, "alerts": [{"code": "leadership_below_floor"}]},
    ), patch(
        "app.services.gateway_leadership_pack7.get_alert_channels",
        return_value={"channels": {"webhook_url": "https://example.test/hook"}},
    ), patch("app.services.runtime_config.get_runtime_config", return_value="[]"), patch(
        "app.services.runtime_config.upsert_runtime_config_value"
    ):
        dispatch = evaluate_and_queue_leadership_alerts(db, dry_run=True)
    assert dispatch["dry_run"] is True
    assert dispatch["channels_configured"] is True

    with patch(
        "app.services.gateway_leadership_pack7.build_gateway_leadership_index",
        return_value={"score": 80, "band": "market_leader"},
    ), patch(
        "app.services.gateway_leadership_pack7.build_attribution_analytics",
        return_value={"attribution_coverage_percent": 50},
    ):
        env_diff = build_environment_diff_leadership(db, hours=24)
    assert "dev" in env_diff["environments"]
