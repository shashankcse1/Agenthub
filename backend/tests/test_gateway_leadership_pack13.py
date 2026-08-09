from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.services.gateway_leadership_pack13 import (
    auto_route_policy_block_detail,
    detect_score_trend,
    enforcement_flags_diff,
    pack13_manifest,
    pack_capability_registry,
    route_health_score,
    shadow_compare_strategies,
    upsert_operator_checklist,
    warmup_eligibility_probe,
)


def test_pack13_manifest_and_registry():
    assert pack13_manifest()["pack"] == 13
    assert pack13_manifest()["gov"] == "GOV-AI-MARKET-013"
    registry = pack_capability_registry()
    assert registry["count"] >= 4
    assert {10, 11, 12, 13}.issubset({row["pack"] for row in registry["packs"]})


def test_pack13_policy_block_and_shadow_compare():
    detail = auto_route_policy_block_detail(
        {
            "catalog_policy": {"empty_after_policy": True, "catalog_before": 5, "catalog_after": 0},
            "rationale": "blocked",
        }
    )
    assert detail["code"] == "AUTO_ROUTE_CATALOG_EMPTY"

    db = MagicMock()
    with patch(
        "app.services.gateway_leadership_pack11.build_auto_route_with_pack11",
        side_effect=lambda *_a, **kwargs: {
            "selected_model": f"model-{kwargs.get('strategy')}",
            "complexity": {"tier": "simple", "score": 10},
        },
    ):
        compare = shadow_compare_strategies(db, prompt_text="hello")
    assert compare["divergence"] is True
    assert len(compare["comparisons"]) == 3


def test_pack13_trend_checklist_route_health_flags():
    db = MagicMock()
    with patch(
        "app.services.gateway_leadership_pack13.list_leadership_history",
        return_value={
            # newest-first storage; chronological after reverse => 90→80→70→60
            "snapshots": [
                {"score": 60},
                {"score": 70},
                {"score": 80},
                {"score": 90},
            ]
        },
    ):
        trend = detect_score_trend(db, points=4, decline_points=3)
    assert trend["alert"] is True

    stored = {}

    def fake_get(_db, key, default="{}"):
        return stored.get(key, {})

    def fake_set(_db, key, value, description=""):
        stored[key] = value

    with patch("app.services.gateway_leadership_pack13._rt_get", side_effect=fake_get), patch(
        "app.services.gateway_leadership_pack13._rt_set",
        side_effect=fake_set,
    ), patch(
        "app.services.gateway_leadership_pack13.record_ops_activity",
    ):
        checklist = upsert_operator_checklist(db, completed={"traffic_light": True})
    assert checklist["completed_count"] == 1

    db.query.return_value.filter_by.return_value.first.return_value = SimpleNamespace(
        route_policy_id="rp-1",
        fallback_policy='{"circuit_breaker_notes":{"recommendations":[{"a":1},{"b":2}]}}',
    )
    with patch(
        "app.services.gateway_leadership_pack13.build_inference_readiness",
        return_value={"ready_providers": 2, "total_providers": 2},
    ):
        health = route_health_score(db, route_policy_id="rp-1")
    assert health["found"] is True
    assert health["score"] == 90.0

    with patch(
        "app.services.gateway_leadership_pack13.get_enforcement_flags",
        return_value={"flags": {"use_decision_cache": False, "enforce_pii_bias": True, "enforce_adversarial_boost": True, "resolve_strategy_policies": True, "enforce_model_denylist": True, "decision_cache_ttl_seconds": 60}},
    ):
        diff = enforcement_flags_diff(db)
    assert diff["in_sync_with_defaults"] is False
    assert any(row["key"] == "use_decision_cache" for row in diff["diffs"])

    with patch(
        "app.services.gateway_leadership_pack13.guard_warmup_rate_limit",
        return_value={"allowed": True, "count": 1, "max_per_hour": 3, "window_hour": "x", "message": "ok"},
    ):
        probe = warmup_eligibility_probe(db)
    assert probe["eligible"] is True
