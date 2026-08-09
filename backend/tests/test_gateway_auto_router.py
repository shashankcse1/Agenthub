from unittest.mock import MagicMock, patch

from app.services.gateway_auto_router import (
    build_auto_route_decision,
    classify_prompt_complexity,
    refine_complexity_with_judge,
    should_auto_route,
)


def test_classify_simple_vs_complex():
    simple = classify_prompt_complexity("Say hello.")
    assert simple["tier"] == "simple"

    complex_prompt = (
        "Perform a security review and threat model for this distributed system. "
        "Reason carefully step by step. ```python\nprint(1)\n``` ```js\nconsole.log(2)\n``` "
        "Include OpenAPI schema and MCP tool call design. Why? How? What next?"
    )
    complex_result = classify_prompt_complexity(complex_prompt)
    assert complex_result["tier"] == "complex"
    assert complex_result["score"] >= 55


def test_should_auto_route_aliases():
    assert should_auto_route("auto") is True
    assert should_auto_route("gateway/auto") is True
    assert should_auto_route("gpt-4o-mini") is False
    assert should_auto_route("gpt-4o-mini", auto_route_flag=True) is True


def test_build_auto_route_decision_selects_tier_model():
    db = MagicMock()

    class _Query:
        def filter(self, *_args, **_kwargs):
            return self

        def order_by(self, *_args, **_kwargs):
            return self

        def all(self):
            return [
                ("openai", "gpt-4o-mini"),
                ("openai", "gpt-4o"),
                ("openai", "o4-mini"),
                ("anthropic", "claude-3-5-sonnet-latest"),
            ]

    db.query.return_value = _Query()

    readiness = {
        "ready_providers": 1,
        "providers": [
            {"provider_type": "openai", "live_ready": True},
            {"provider_type": "anthropic", "live_ready": False},
        ],
        "simulation_enabled": False,
    }

    with patch("app.services.gateway_auto_router.build_inference_readiness", return_value=readiness), patch(
        "app.services.gateway_leadership.build_model_liquidity_ranking",
        return_value={
            "models": [{"model_name": "gpt-4o-mini", "score": 40}],
            "score_by_model": {"gpt-4o-mini": 40.0, "gpt-4o": 10.0},
            "sample_events": 2,
            "leader_signal": "emerging",
        },
    ):
        decision = build_auto_route_decision(
            db,
            prompt_text="Say hello in one word.",
            prefer_live_only=True,
        )
        quality = build_auto_route_decision(
            db,
            prompt_text="Say hello in one word.",
            prefer_live_only=True,
            strategy="quality",
        )
        toolish = classify_prompt_complexity("short", has_tools=True, json_response_format=True)

    assert decision["complexity"]["tier"] == "simple"
    assert decision["selected_model"] == "gpt-4o-mini"
    assert decision["selected"]["live_ready"] is True
    assert "simple" in decision["tier_candidates"]
    assert quality["strategy"] == "quality"
    assert quality["selected_model"] in {"gpt-4o-mini", "gpt-4o", "o4-mini"}
    assert toolish["score"] > classify_prompt_complexity("short")["score"]


def test_judge_refine_bumps_near_boundary():
    base = classify_prompt_complexity("A short checklist with constraints.")
    # Force near-standard boundary and ensure judge can adjust.
    base["score"] = 24
    base["tier"] = "simple"
    refined = refine_complexity_with_judge(
        base,
        "Must follow constraints:\n- one\n- two\n- three\n- four\nExactly match production rules.",
    )
    assert refined["score"] > 24
    assert refined["judge_mode"] == "heuristic"
