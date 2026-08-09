import json
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.services.gateway_leadership import (
    build_attribution_analytics,
    build_gateway_leadership_index,
    build_model_liquidity_ranking,
    warmup_leadership_attribution,
)


def test_attribution_analytics_counts_switches():
    events = [
        SimpleNamespace(
            model_name="gpt-4o-mini",
            endpoint_family="chat.completions",
            estimated_cost_cents=10,
            properties_json=json.dumps(
                {
                    "intended_model": "auto",
                    "actual_model": "gpt-4o-mini",
                    "model_switched": True,
                    "auto_route_tier": "simple",
                }
            ),
            timestamp=datetime.utcnow(),
        ),
        SimpleNamespace(
            model_name="gpt-4o",
            endpoint_family="chat.completions",
            estimated_cost_cents=20,
            properties_json=json.dumps(
                {
                    "intended_model": "gpt-4o",
                    "actual_model": "gpt-4o",
                    "model_switched": False,
                }
            ),
            timestamp=datetime.utcnow(),
        ),
        SimpleNamespace(
            model_name="gpt-4o",
            endpoint_family="responses",
            estimated_cost_cents=5,
            properties_json="{}",
            timestamp=datetime.utcnow(),
        ),
    ]

    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events

    analytics = build_attribution_analytics(db, hours=24)
    assert analytics["total_events"] == 3
    assert analytics["attributed_events"] == 2
    assert analytics["switched_events"] == 1
    assert analytics["auto_routed_events"] == 1
    assert analytics["top_switch_pairs"][0]["actual_model"] == "gpt-4o-mini"
    assert analytics["leader_signal"] in {"emerging", "strong", "needs_traffic"}


def test_leadership_index_composites_components():
    db = MagicMock()
    posture = {
        "score": 90,
        "band": "market_leading",
        "checks": [{"id": "complexity_auto_router", "passed": True}],
        "top_gaps": [],
    }
    readiness = {"ready_providers": 3, "total_providers": 10}
    attribution = {
        "attributed_events": 12,
        "attribution_coverage_percent": 50.0,
        "switch_rate_percent": 10.0,
        "total_events": 24,
        "switched_events": 2,
        "auto_routed_events": 4,
        "cost_cents_switched": 10,
        "cost_cents_same_model": 40,
        "top_switch_pairs": [],
        "auto_route_tiers": [],
        "endpoint_families": [],
        "leader_signal": "strong",
        "hours": 24,
        "environment": None,
    }
    rankings = {
        "hours": 168,
        "environment": None,
        "models": [
            {"model_name": "gpt-4o-mini", "score": 50, "events": 8},
            {"model_name": "gpt-4o", "score": 40, "events": 5},
            {"model_name": "claude-3-5-sonnet-latest", "score": 30, "events": 3},
            {"model_name": "gemini-2.0-flash", "score": 20, "events": 2},
            {"model_name": "o4-mini", "score": 15, "events": 1},
        ],
        "score_by_model": {"gpt-4o-mini": 50.0},
        "sample_events": 20,
        "leader_signal": "strong",
    }

    with patch(
        "app.services.gateway_leadership.build_gateway_best_practices_posture",
        return_value=posture,
    ), patch(
        "app.services.gateway_leadership.build_inference_readiness",
        return_value=readiness,
    ), patch(
        "app.services.gateway_leadership.build_attribution_analytics",
        return_value=attribution,
    ), patch(
        "app.services.gateway_leadership.build_model_liquidity_ranking",
        return_value=rankings,
    ):
        index = build_gateway_leadership_index(db, hours=24)

    assert index["score"] >= 70
    assert index["band"] in {"market_leader", "strong_challenger", "production_capable"}
    assert index["components"]["auto_router"]["passed"] is True
    assert index["components"]["model_rankings"]["ranked_models"] == 5
    assert "telemetry model rankings" in index["market_claim"]


def test_model_liquidity_ranking_scores_stable_models():
    events = [
        SimpleNamespace(
            model_name="gpt-4o-mini",
            estimated_cost_cents=2,
            properties_json=json.dumps(
                {"intended_model": "gpt-4o-mini", "actual_model": "gpt-4o-mini", "model_switched": False, "latency_ms": 90}
            ),
            timestamp=datetime.utcnow(),
        ),
        SimpleNamespace(
            model_name="gpt-4o-mini",
            estimated_cost_cents=2,
            properties_json=json.dumps(
                {
                    "intended_model": "auto",
                    "actual_model": "gpt-4o-mini",
                    "model_switched": True,
                    "auto_route_tier": "simple",
                    "latency_ms": 100,
                }
            ),
            timestamp=datetime.utcnow(),
        ),
    ]
    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events
    ranking = build_model_liquidity_ranking(db, hours=24)
    assert ranking["models"][0]["model_name"] == "gpt-4o-mini"
    assert ranking["score_by_model"]["gpt-4o-mini"] > 0


def test_leadership_warmup_creates_events():
    db = MagicMock()
    with patch(
        "app.services.gateway_auto_router.build_auto_route_decision",
        return_value={
            "selected_model": "gpt-4o-mini",
            "strategy": "balanced",
            "complexity": {"tier": "simple", "score": 8},
        },
    ):
        result = warmup_leadership_attribution(db, samples=2, actor_id="actor-1", environment="dev")
    assert result["created_events"] == 2
    assert db.add.call_count == 2
    assert db.flush.called
