from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.services.gateway_leadership_pack11 import (
    build_auto_route_with_pack11,
    build_dashboard_summary,
    build_leadership_sparkline,
    evaluate_canary_promote_gate,
    get_enforcement_flags,
    pack11_manifest,
    upsert_enforcement_flags,
    upsert_model_route_policy,
)


def test_pack11_manifest_and_default_flags():
    assert pack11_manifest()["pack"] == 11
    assert pack11_manifest()["gov"] == "GOV-AI-MARKET-011"
    db = MagicMock()
    with patch(
        "app.services.gateway_leadership_pack11._rt_get",
        return_value={},
    ):
        flags = get_enforcement_flags(db)
    assert flags["flags"]["use_decision_cache"] is True
    assert flags["flags"]["enforce_model_denylist"] is True


def test_pack11_enforcement_flags_and_model_policy():
    db = MagicMock()
    stored = {}

    def fake_get(_db, key, default="{}"):
        return stored.get(key, {})

    def fake_set(_db, key, value, description=""):
        stored[key] = value

    with patch("app.services.gateway_leadership_pack11._rt_get", side_effect=fake_get), patch(
        "app.services.gateway_leadership_pack11._rt_set",
        side_effect=fake_set,
    ), patch(
        "app.services.gateway_leadership_pack11.record_ops_activity",
    ):
        upsert_enforcement_flags(db, flags={"use_decision_cache": False, "enforce_pii_bias": False})
        flags = get_enforcement_flags(db)
        assert flags["flags"]["use_decision_cache"] is False
        assert flags["flags"]["enforce_pii_bias"] is False
        policy = upsert_model_route_policy(db, allowlist=["gpt-4o-mini"], denylist=["bad-model"])
    assert "gpt-4o-mini" in policy["allowlist"]
    assert "bad-model" in policy["denylist"]


def test_pack11_auto_route_cache_hit_and_strategy_resolve():
    db = MagicMock()
    decision = {
        "selected_model": "gpt-4o-mini",
        "strategy": "cost",
        "complexity": {"tier": "simple", "score": 10},
        "constraints": {},
        "rationale": "cached-path",
    }
    with patch(
        "app.services.gateway_leadership_pack11.get_enforcement_flags",
        return_value={"flags": {
            "enforce_pii_bias": True,
            "enforce_adversarial_boost": True,
            "use_decision_cache": True,
            "resolve_strategy_policies": True,
            "enforce_model_denylist": True,
            "decision_cache_ttl_seconds": 60,
        }},
    ), patch(
        "app.services.gateway_leadership_pack10.resolve_strategy_policy",
        return_value={"strategy": "cost", "source": "request_tag"},
    ), patch(
        "app.services.gateway_leadership_pack10.get_cached_auto_route_decision",
        return_value=decision,
    ):
        result = build_auto_route_with_pack11(
            db,
            prompt_text="hello",
            strategy="balanced",
            request_tag="ops.chat",
            use_cache=True,
        )
    assert result["cache_hit"] is True
    assert result["strategy_policy"]["source"] == "request_tag"
    assert result["selected_model"] == "gpt-4o-mini"


def test_pack11_dashboard_sparkline_canary_gate():
    db = MagicMock()
    db.query.return_value.filter_by.return_value.first.return_value = SimpleNamespace(
        route_policy_id="rp-1"
    )
    with patch(
        "app.services.gateway_leadership_pack11.build_traffic_light",
        return_value={"light": "green", "score": 88},
    ), patch(
        "app.services.gateway_leadership_pack11.build_sla_burn_rate",
        return_value={"status": "healthy", "burn_rate_percent": 0},
    ), patch(
        "app.services.gateway_leadership_pack11.build_attribution_analytics",
        return_value={"attribution_coverage_percent": 90, "auto_routed_events": 12},
    ), patch(
        "app.services.gateway_leadership_pack11.build_model_liquidity_ranking",
        return_value={"models": [{"model_name": "gpt-4o-mini", "score": 91}]},
    ), patch(
        "app.services.gateway_leadership_pack11.build_inference_readiness",
        return_value={"ready_providers": 2},
    ), patch(
        "app.services.gateway_leadership_pack11.list_ops_activity",
        return_value={"activities": [{"action": "warmup"}]},
    ):
        summary = build_dashboard_summary(db)
    assert summary["traffic_light"]["light"] == "green"
    assert summary["auto_routed_events"] == 12

    with patch(
        "app.services.gateway_leadership_pack11.list_leadership_history",
        return_value={"snapshots": [{"recorded_at": "t1", "score": 70, "band": "x"}]},
    ):
        spark = build_leadership_sparkline(db, points=4)
    assert spark["count"] == 1

    with patch(
        "app.services.gateway_leadership_pack11.build_gateway_leadership_index",
        return_value={"score": 81},
    ):
        gate = evaluate_canary_promote_gate(db, route_policy_id="rp-1", floor_score=70)
    assert gate["passed"] is True
    assert gate["decision"] == "promote_allowed"
