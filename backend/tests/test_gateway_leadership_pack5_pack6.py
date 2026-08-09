import json
from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from app.services.gateway_auto_router import build_auto_route_decision, classify_prompt_complexity
from app.services.gateway_leadership import (
    batch_auto_route_classify,
    build_leadership_alerts,
    compare_auto_route_strategies,
    estimate_tier_savings,
    list_sdk_instrumentation_presets,
    ranking_aware_fallback_suggest,
    record_leadership_snapshot,
)
from app.services.gateway_leadership_pack6 import (
    advise_modality_models,
    build_attribution_timeseries,
    build_streaming_auto_route_frames,
    evaluate_fallback_quality_gate,
    explain_auto_route_decision,
    import_openrouter_liquidity,
    live_judge_refine,
)


def test_pack5_compare_and_batch_and_savings():
    db = MagicMock()
    decision = {
        "selected_model": "gpt-4o-mini",
        "selected_provider_type": "openai",
        "strategy": "balanced",
        "complexity": {"tier": "simple", "score": 10},
        "selected": {"source": "preferred_catalog:balanced"},
        "rationale": "ok",
    }
    with patch("app.services.gateway_auto_router.build_auto_route_decision", return_value=decision):
        compare = compare_auto_route_strategies(db, prompt_text="hello")
        batch = batch_auto_route_classify(db, prompts=["a", "b"], strategy="balanced")
    assert compare["distinct_model_count"] == 1
    assert batch["count"] == 2

    attribution = {
        "auto_route_tiers": [
            {"tier": "simple", "events": 10},
            {"tier": "standard", "events": 5},
            {"tier": "complex", "events": 1},
        ]
    }
    with patch(
        "app.services.gateway_leadership.build_attribution_analytics",
        return_value=attribution,
    ):
        savings = estimate_tier_savings(db, hours=24)
    assert savings["estimated_relative_savings_percent"] > 0
    presets = list_sdk_instrumentation_presets()
    assert len(presets["presets"]) >= 3


def test_pack5_ranked_fallback_and_snapshot_alerts():
    db = MagicMock()
    base = {
        "live_ready_count": 2,
        "priority_order": [
            {"provider_id": "p2", "model_name": "gpt-4o", "priority": 1},
            {"provider_id": "p1", "model_name": "gpt-4o-mini", "priority": 2},
        ],
        "targets": [
            {"provider_id": "p2", "model_name": "gpt-4o", "priority": 1},
            {"provider_id": "p1", "model_name": "gpt-4o-mini", "priority": 2},
        ],
        "rationale": "base",
    }
    rankings = {"score_by_model": {"gpt-4o-mini": 90.0, "gpt-4o": 10.0}}
    with patch(
        "app.services.gateway_best_practices.suggest_readiness_aware_fallback_chain",
        return_value=base,
    ), patch(
        "app.services.gateway_leadership.build_model_liquidity_ranking",
        return_value=rankings,
    ):
        ranked = ranking_aware_fallback_suggest(db, max_hops=3)
    assert ranked["ranking_applied"] is True
    assert ranked["priority_order"][0]["model_name"] == "gpt-4o-mini"

    index = {
        "score": 55,
        "band": "production_capable",
        "attribution": {"attributed_events": 1, "leader_signal": "needs_traffic"},
        "components": {"model_rankings": {"ranked_models": 1}},
    }
    with patch(
        "app.services.gateway_leadership.build_gateway_leadership_index",
        return_value=index,
    ), patch(
        "app.services.runtime_config.get_runtime_config",
        return_value="[]",
    ), patch(
        "app.services.runtime_config.upsert_runtime_config_value",
    ) as upsert:
        snap = record_leadership_snapshot(db, hours=24)
        assert snap["snapshot"]["score"] == 55
        assert upsert.called

    with patch(
        "app.services.gateway_leadership.build_gateway_leadership_index",
        return_value=index,
    ), patch(
        "app.services.gateway_leadership.list_leadership_history",
        return_value={"snapshots": []},
    ):
        alerts = build_leadership_alerts(db, hours=24, floor_score=70)
    assert alerts["alert_count"] >= 1
    assert any(row["code"] == "leadership_below_floor" for row in alerts["alerts"])


def test_pack6_live_judge_and_liquidity_and_timeseries():
    db = MagicMock()
    with patch(
        "app.services.gateway_leadership_pack6.build_inference_readiness",
        return_value={"simulation_enabled": True},
    ):
        judge = live_judge_refine(db, prompt_text="threat model architecture", force_live=False)
    assert judge["mode"] == "simulation_safe_heuristic"
    assert judge["live_attempted"] is False

    with patch("app.services.runtime_config.get_runtime_config", return_value="{}"), patch(
        "app.services.runtime_config.upsert_runtime_config_value"
    ):
        imported = import_openrouter_liquidity(db, use_seed=True)
    assert imported["count"] >= 5

    events = [
        SimpleNamespace(
            properties_json=json.dumps(
                {"intended_model": "auto", "actual_model": "gpt-4o-mini", "model_switched": True, "auto_route_tier": "simple"}
            ),
            timestamp=datetime.utcnow(),
        )
    ]
    db.query.return_value.filter.return_value.order_by.return_value.limit.return_value.all.return_value = events
    series = build_attribution_timeseries(db, hours=24)
    assert series["point_count"] >= 1


def test_pack6_quality_gate_explain_modality_and_frames():
    db = MagicMock()
    with patch(
        "app.services.gateway_best_practices.suggest_readiness_aware_fallback_chain",
        return_value={
            "live_ready_count": 3,
            "priority_order": [{"provider_id": "p1", "model_name": "gpt-4o-mini", "priority": 1}],
        },
    ), patch(
        "app.services.gateway_leadership.build_gateway_leadership_index",
        return_value={"score": 80},
    ):
        gate = evaluate_fallback_quality_gate(db)
    assert gate["passed"] is True

    with patch(
        "app.services.gateway_auto_router.build_auto_route_decision",
        return_value={
            "selected_model": "gpt-4o-mini",
            "rationale": "simple tier",
            "complexity": {"tier": "simple", "score": 12, "signals": []},
            "strategy": "balanced",
            "selected_provider_type": "openai",
            "tier_candidates": {},
        },
    ):
        explain = explain_auto_route_decision(
            db,
            prompt_text="hello",
            max_budget_tier="simple",
            attachment_types=["image"],
            tools_json=[{"function": {"name": "lookup", "parameters": {"properties": {"id": {}}}}}],
        )
        frames = build_streaming_auto_route_frames(db, prompt_text="hello")
    assert explain["selected_model"] == "gpt-4o-mini"
    assert frames["frame_count"] == 5

    db.query.return_value.filter.return_value.all.return_value = [
        SimpleNamespace(model_name="text-embedding-3-small", provider_type="openai", status="active")
    ]
    with patch(
        "app.services.gateway_leadership_pack6.build_inference_readiness",
        return_value={"providers": [{"provider_type": "openai", "live_ready": True}]},
    ):
        advice = advise_modality_models(db, modality="embeddings")
    assert advice["supported"] is True
    assert advice["recommendations"][0]["in_catalog"] is True


def test_auto_router_budget_and_multimodal_signals():
    complexity = classify_prompt_complexity(
        "short",
        attachment_types=["image", "pdf"],
        has_tools=True,
    )
    assert "multimodal_attachments" in " ".join(complexity["signals"])
    assert complexity["score"] >= 25

    db = MagicMock()
    db.query.return_value.filter.return_value.order_by.return_value.all.return_value = [
        ("openai", "gpt-4o-mini"),
        ("openai", "gpt-4o"),
        ("openai", "o4-mini"),
    ]
    with patch(
        "app.services.gateway_auto_router.build_inference_readiness",
        return_value={"providers": [{"provider_type": "openai", "live_ready": True}], "simulation_enabled": True},
    ), patch(
        "app.services.gateway_leadership.build_model_liquidity_ranking",
        return_value={"score_by_model": {}, "sample_events": 0, "leader_signal": "needs_traffic", "models": []},
    ):
        decision = build_auto_route_decision(
            db,
            prompt_text="Design a threat model and distributed architecture for production.",
            max_budget_tier="simple",
            latency_slo_ms=500,
            prefer_live_only=False,
        )
    assert decision["complexity"]["tier"] == "simple"
    assert decision["constraints"]["max_budget_tier"] == "simple"
