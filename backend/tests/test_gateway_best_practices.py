from unittest.mock import MagicMock, patch

from app.services.gateway_best_practices import (
    BOOTSTRAP_ROUTE_NAME,
    apply_provider_priority_chain,
    bootstrap_best_practices_leadership,
    build_gateway_best_practices_posture,
    suggest_readiness_aware_fallback_chain,
)


def _fake_readiness(**overrides):
    base = {
        "simulation_enabled": False,
        "ready_providers": 2,
        "total_providers": 4,
        "catalog_models_total": 12,
        "providers": [
            {
                "provider_type": "openai",
                "label": "OpenAI",
                "catalog_models": 3,
                "invoke_supported": True,
                "env_credential_configured": True,
                "endpoint_configured": True,
                "live_ready": True,
                "status": "live_ready",
                "setup_hint": "",
            },
            {
                "provider_type": "aws",
                "label": "AWS Bedrock",
                "catalog_models": 4,
                "invoke_supported": True,
                "env_credential_configured": True,
                "endpoint_configured": True,
                "live_ready": True,
                "status": "live_ready",
                "setup_hint": "",
            },
            {
                "provider_type": "azure-openai",
                "label": "Azure OpenAI",
                "catalog_models": 2,
                "invoke_supported": True,
                "env_credential_configured": False,
                "endpoint_configured": False,
                "live_ready": False,
                "status": "needs_credentials",
                "setup_hint": "",
            },
        ],
    }
    base.update(overrides)
    return base


def test_best_practices_posture_scores_market_checklist():
    db = MagicMock()

    class _Route:
        def __init__(self, fallback_policy):
            self.status = "active"
            self.fallback_policy = fallback_policy

    route_with_chain = _Route(
        '{"provider_priority":{"priority_order":[{"provider_id":"openai:*","priority":1},'
        '{"provider_id":"aws:*","priority":2}],"health_check_enabled":true}}'
    )
    db.query.return_value.filter.return_value.all.return_value = [route_with_chain]
    db.query.return_value.count.return_value = 2
    db.query.return_value.filter.return_value.count.return_value = 1

    auto_route_sample = {
        "selected_model": "gpt-4o-mini",
        "tier_candidates": {
            "simple": [{"model_name": "gpt-4o-mini"}],
            "standard": [{"model_name": "gpt-4o"}],
            "complex": [],
        },
    }
    with patch(
        "app.services.gateway_best_practices.build_inference_readiness",
        return_value=_fake_readiness(),
    ), patch(
        "app.services.gateway_auto_router.build_auto_route_decision",
        return_value=auto_route_sample,
    ):
        posture = build_gateway_best_practices_posture(db)

    assert posture["score"] >= 65
    assert posture["band"] in {"production_capable", "market_leading"}
    by_id = {row["id"]: row for row in posture["checks"]}
    assert by_id["live_credential_readiness"]["passed"] is True
    assert by_id["multi_provider_catalog"]["passed"] is True
    assert by_id["complexity_auto_router"]["passed"] is True
    assert len(posture["market_trends"]) >= 3


def test_posture_accepts_legacy_top_level_priority_order():
    db = MagicMock()

    class _Route:
        def __init__(self, fallback_policy):
            self.status = "active"
            self.fallback_policy = fallback_policy

    legacy = _Route(
        '{"priority_order":[{"provider_id":"openai:*","priority":1},'
        '{"provider_id":"aws:*","priority":2}],"health_check_enabled":true}'
    )
    db.query.return_value.filter.return_value.all.return_value = [legacy]
    db.query.return_value.count.return_value = 1
    db.query.return_value.filter.return_value.count.return_value = 1

    with patch(
        "app.services.gateway_best_practices.build_inference_readiness",
        return_value=_fake_readiness(),
    ), patch(
        "app.services.gateway_auto_router.build_auto_route_decision",
        return_value={
            "selected_model": "gpt-4o-mini",
            "tier_candidates": {"simple": [{}], "standard": [{}], "complex": []},
        },
    ):
        posture = build_gateway_best_practices_posture(db)

    by_id = {row["id"]: row for row in posture["checks"]}
    assert by_id["ordered_fallback_chains"]["passed"] is True
    assert by_id["health_check_routing"]["passed"] is True


def test_fallback_suggest_prefers_live_ready_providers():
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
                ("aws", "amazon.nova-lite-v1:0"),
                ("azure-openai", "gpt-4o-mini"),
            ]

    db.query.return_value = _Query()

    with patch(
        "app.services.gateway_best_practices.build_inference_readiness",
        return_value=_fake_readiness(),
    ):
        suggestion = suggest_readiness_aware_fallback_chain(db, max_hops=3, prefer_live_only=True)

    assert suggestion["live_ready_count"] >= 2
    assert len(suggestion["priority_order"]) >= 2
    assert suggestion["priority_order"][0]["provider_id"].endswith(":*")
    assert suggestion["recommended"]["health_check_enabled"] is True
    provider_types = [row["provider_type"] for row in suggestion["targets"]]
    assert "openai" in provider_types
    assert "aws" in provider_types
    assert "azure-openai" not in provider_types


def test_apply_provider_priority_chain_writes_canonical_shape():
    class _Route:
        fallback_policy = "{}"

    route = _Route()
    payload = apply_provider_priority_chain(
        route,
        priority_order=[
            {"provider_id": "openai:*", "priority": 1},
            {"provider_id": "aws:*", "priority": 2},
        ],
        tenant_id="tenant-a",
        environment="dev",
    )
    assert payload["health_check_enabled"] is True
    assert '"provider_priority"' in route.fallback_policy
    import json

    parsed = json.loads(route.fallback_policy)
    assert isinstance(parsed.get("provider_priority"), dict)
    assert "priority_order" not in parsed
    assert len(parsed["provider_priority"]["priority_order"]) == 2


def test_bootstrap_best_practices_leadership_lifts_configurable_gaps():
    db = MagicMock()
    route_store: list = []
    cache_store: list = []

    class _CatalogQuery:
        def filter(self, *_a, **_k):
            return self

        def order_by(self, *_a, **_k):
            return self

        def all(self):
            return [
                ("openai", "gpt-4o-mini"),
                ("aws", "amazon.nova-lite-v1:0"),
                ("anthropic", "claude-3-5-haiku-latest"),
            ]

    class _RouteQuery:
        def filter(self, *_args, **_kwargs):
            return self

        def order_by(self, *_args, **_kwargs):
            return self

        def first(self):
            return None

        def all(self):
            return list(route_store)

        def count(self):
            return len(route_store)

    class _CacheQuery:
        def filter(self, *_args, **_kwargs):
            return self

        def order_by(self, *_args, **_kwargs):
            return self

        def first(self):
            return None

        def count(self):
            return len(cache_store)

    class _CountQuery:
        def count(self):
            return 1

    def _query(*models):
        names = " ".join(getattr(m, "__name__", str(m)) for m in models)
        if "SupportedModelCatalogEntry" in names or any(
            "provider_type" in str(m) or "model_name" in str(m) for m in models
        ):
            if len(models) >= 2 or "InstrumentedAttribute" in names or "provider_type" in names:
                return _CatalogQuery()
        if "SupportedModelCatalogEntry" in names:
            return _CatalogQuery()
        if "RoutePolicy" in names:
            return _RouteQuery()
        if "CachePolicy" in names:
            return _CacheQuery()
        if "BudgetPolicy" in names or "VirtualKey" in names:
            return _CountQuery()
        return _CountQuery()

    def _add(obj):
        name = type(obj).__name__
        if name == "RoutePolicy":
            route_store.append(obj)
        elif name == "CachePolicy":
            cache_store.append(obj)
        elif name == "BudgetPolicy":
            budget_store.append(obj)
        elif name == "VirtualKey":
            vk_store.append(obj)

    budget_store: list = []
    vk_store: list = []
    db.query.side_effect = _query
    db.add.side_effect = _add
    db.flush = MagicMock()

    # recount helpers that read .count() after inserts
    class _BudgetQuery(_CountQuery):
        def count(self):
            return len(budget_store)

    class _VkQuery(_CountQuery):
        def count(self):
            return len(vk_store)

    def _query2(*models):
        names = " ".join(getattr(m, "__name__", str(m)) for m in models)
        if "BudgetPolicy" in names:
            return _BudgetQuery()
        if "VirtualKey" in names:
            return _VkQuery()
        return _query(*models)

    db.query.side_effect = _query2

    auto_route_sample = {
        "selected_model": "gpt-4o-mini",
        "tier_candidates": {
            "simple": [{"model_name": "gpt-4o-mini"}],
            "standard": [{"model_name": "gpt-4o"}],
            "complex": [],
        },
    }

    with patch(
        "app.services.gateway_best_practices.build_inference_readiness",
        return_value=_fake_readiness(),
    ), patch(
        "app.services.gateway_auto_router.build_auto_route_decision",
        return_value=auto_route_sample,
    ):
        result = bootstrap_best_practices_leadership(db, environment="dev", max_hops=3)

    assert result["bootstrapped"] is True
    assert result["route_name"] == BOOTSTRAP_ROUTE_NAME
    assert result["delta"] >= 0
    assert any(a["action"] == "create_route" for a in result["actions"])
    assert any(a["action"] == "apply_fallback_chain" for a in result["actions"])
    assert any(a["action"] == "create_cache_policy" for a in result["actions"])
    assert any(a["action"] == "create_budget_policy" for a in result["actions"])
    assert any(a["action"] == "create_virtual_key" for a in result["actions"])
    assert route_store and "provider_priority" in route_store[0].fallback_policy
    after_checks = {c["id"]: c for c in (result["after"].get("checks") or [])}
    assert after_checks["ordered_fallback_chains"]["passed"] is True
    assert after_checks["health_check_routing"]["passed"] is True
    assert after_checks["inference_cache"]["passed"] is True
    assert after_checks["budget_guardrails"]["passed"] is True
    assert after_checks["virtual_keys"]["passed"] is True
