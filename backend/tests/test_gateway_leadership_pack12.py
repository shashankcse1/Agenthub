from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.services.gateway_leadership_pack12 import (
    budget_correlation_warning,
    compare_traffic_light_floors,
    get_decision_cache_stats,
    invalidate_decision_cache,
    leadership_posture_digest,
    pack12_manifest,
    readiness_leadership_delta,
    read_route_circuit_notes,
)


def test_pack12_manifest_and_cache_invalidate():
    assert pack12_manifest()["pack"] == 12
    assert pack12_manifest()["gov"] == "GOV-AI-MARKET-012"
    db = MagicMock()
    with patch("app.services.runtime_config.upsert_runtime_config_value") as upsert, patch(
        "app.services.gateway_leadership_pack12.record_ops_activity",
    ):
        result = invalidate_decision_cache(db)
    assert result["invalidated"] is True
    assert upsert.called


def test_pack12_cache_stats_and_floors():
    db = MagicMock()
    with patch(
        "app.services.gateway_leadership_pack12._rt_get",
        return_value={"hits": 3, "misses": 1, "hit_rate_percent": 75.0},
    ):
        stats = get_decision_cache_stats(db)
    assert stats["hits"] == 3
    assert stats["hit_rate_percent"] == 75.0

    with patch(
        "app.services.gateway_leadership_pack12.build_traffic_light",
        side_effect=lambda _db, hours=24, floor_score=70: {
            "light": "green" if floor_score <= 70 else "yellow",
            "score": 72,
        },
    ):
        floors = compare_traffic_light_floors(db, floors=[50, 70, 85])
    assert len(floors["comparisons"]) == 3


def test_pack12_delta_budget_posture_notes():
    db = MagicMock()
    db.query.return_value.filter_by.return_value.first.return_value = SimpleNamespace(
        route_policy_id="rp-1",
        fallback_policy='{"circuit_breaker_notes":{"recommendations":[{"id":1}]}}',
    )
    with patch(
        "app.services.gateway_leadership.build_gateway_leadership_index",
        return_value={"score": 80},
    ), patch(
        "app.services.inference_readiness.build_inference_readiness",
        return_value={"ready_providers": 2, "total_providers": 4},
    ):
        delta = readiness_leadership_delta(db)
    assert delta["readiness_percent"] == 50.0
    assert delta["delta"] == 30.0

    with patch(
        "app.services.gateway_leadership_pack12.correlate_budget_auto_route",
        return_value={"avg_auto_routed_cost_cents": 80.0, "auto_routed_events": 2},
    ):
        warn = budget_correlation_warning(db, warn_avg_cents=50)
    assert warn["warning"] is True

    with patch(
        "app.services.gateway_leadership_pack12.build_traffic_light",
        return_value={"light": "green", "score": 88},
    ), patch(
        "app.services.gateway_leadership_pack12.get_enforcement_flags",
        return_value={"flags": {"enforce_pii_bias": True, "enforce_adversarial_boost": True, "enforce_model_denylist": True, "use_decision_cache": True}},
    ), patch(
        "app.services.gateway_leadership_pack12.get_model_route_policy",
        return_value={"allowlist": [], "denylist": ["x"]},
    ), patch(
        "app.services.gateway_leadership_pack12.get_decision_cache_stats",
        return_value={"hit_rate_percent": 40},
    ), patch(
        "app.services.gateway_leadership_pack12.readiness_leadership_delta",
        return_value={"ready_providers": 2},
    ):
        digest = leadership_posture_digest(db)
    assert digest["denylist_count"] == 1
    assert digest["traffic_light"] == "green"

    notes = read_route_circuit_notes(db, route_policy_id="rp-1")
    assert notes["has_notes"] is True
