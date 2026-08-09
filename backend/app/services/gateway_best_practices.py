"""Market-aligned AI gateway best-practices posture and fallback suggestions.

Trends encoded here (2026 buyer guides + Datadog/Portkey/LiteLLM patterns):
1. Multi-provider catalog with live credential readiness
2. Ordered fallback chains across live-ready providers
3. Health-check / circuit-breaker style routing toggles
4. Virtual keys + budget guardrails
5. Inference cache short-circuit availability
6. Input / prompt-injection guardrails
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import BudgetPolicy, CachePolicy, RoutePolicy, VirtualKey
from app.services.inference_readiness import build_inference_readiness

BOOTSTRAP_ROUTE_NAME = "best-practices-leadership-bootstrap"
BOOTSTRAP_CACHE_SCOPE = "tenant:leadership-bootstrap"
BOOTSTRAP_TENANT_ID = "tenant-leadership-bootstrap"
BOOTSTRAP_VK_SCOPE_ID = "leadership-bootstrap"
BOOTSTRAP_BUDGET_SCOPE_ID = "leadership-bootstrap"


# Prefer hyperscaler / frontier diversity first for failover quality.
_PROVIDER_RANK: dict[str, int] = {
    "openai": 10,
    "anthropic": 20,
    "azure-openai": 30,
    "aws": 40,
    "google": 50,
    "vertex": 55,
    "groq": 60,
    "mistral": 70,
    "cohere": 80,
    "deepseek": 90,
    "xai": 100,
    "together": 110,
    "fireworks": 120,
    "perplexity": 130,
    "cursor": 140,
}

_PREFERRED_MODELS: dict[str, tuple[str, ...]] = {
    "openai": ("gpt-4o-mini", "gpt-4o", "gpt-4.1-mini", "o4-mini"),
    "anthropic": ("claude-sonnet-4-20250514", "claude-3-5-sonnet-latest", "claude-3-5-haiku-latest"),
    "azure-openai": ("gpt-4o-mini", "gpt-4o"),
    "aws": ("anthropic.claude-3-5-sonnet-20241022-v2:0", "amazon.nova-lite-v1:0", "amazon.titan-text-express-v1"),
    "google": ("gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"),
    "vertex": ("gemini-2.5-flash", "gemini-2.0-flash"),
    "groq": ("llama-3.3-70b-versatile", "llama-3.1-8b-instant"),
    "mistral": ("mistral-small-latest", "mistral-large-latest"),
    "cohere": ("command-r-plus", "command-r"),
    "deepseek": ("deepseek-chat", "deepseek-reasoner"),
    "xai": ("grok-3-mini", "grok-3"),
    "together": ("meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo",),
    "fireworks": ("accounts/fireworks/models/llama-v3p1-8b-instruct",),
    "perplexity": ("sonar", "sonar-pro"),
    "cursor": ("gpt-4o-mini",),
}


def _route_priority_blob(route: RoutePolicy) -> dict[str, Any]:
    """Resolve provider priority from canonical provider_priority or legacy top-level keys."""
    try:
        policy = json.loads(route.fallback_policy or "{}")
    except json.JSONDecodeError:
        return {}
    if not isinstance(policy, dict):
        return {}
    provider_priority = policy.get("provider_priority")
    if isinstance(provider_priority, dict):
        return provider_priority
    # Legacy pack10 apply wrote priority_order / health_check_enabled at fallback root.
    if isinstance(policy.get("priority_order"), list):
        return policy
    return {}


def _route_has_priority_chain(route: RoutePolicy) -> bool:
    order = _route_priority_blob(route).get("priority_order")
    return isinstance(order, list) and len(order) >= 2


def _route_health_check_enabled(route: RoutePolicy) -> bool:
    blob = _route_priority_blob(route)
    if bool(blob.get("health_check_enabled")):
        return True
    try:
        policy = json.loads(route.fallback_policy or "{}")
    except json.JSONDecodeError:
        return False
    return isinstance(policy, dict) and bool(policy.get("health_check_enabled"))


def _pick_model_for_provider(provider_type: str, catalog_models: list[str]) -> Optional[str]:
    preferred = _PREFERRED_MODELS.get(provider_type, ())
    catalog_set = {name.lower(): name for name in catalog_models}
    for candidate in preferred:
        hit = catalog_set.get(candidate.lower())
        if hit:
            return hit
    return catalog_models[0] if catalog_models else None


def build_gateway_best_practices_posture(db: Session) -> dict[str, Any]:
    readiness = build_inference_readiness(db)
    live_providers = [row for row in readiness.get("providers", []) if row.get("live_ready")]
    catalog_total = int(readiness.get("catalog_models_total") or 0)

    routes = db.query(RoutePolicy).filter(RoutePolicy.status == "active").all()
    routes_with_chain = sum(1 for route in routes if _route_has_priority_chain(route))
    routes_with_health = sum(1 for route in routes if _route_health_check_enabled(route))

    budget_count = db.query(BudgetPolicy).count()
    virtual_key_count = db.query(VirtualKey).count()
    cache_policy_count = db.query(CachePolicy).filter(CachePolicy.status == "active").count()

    checks: list[dict[str, Any]] = []

    def add_check(
        check_id: str,
        label: str,
        passed: bool,
        weight: int,
        detail: str,
        recommendation: str,
        market_refs: list[str],
    ) -> None:
        checks.append(
            {
                "id": check_id,
                "label": label,
                "status": "pass" if passed else "gap",
                "passed": passed,
                "weight": weight,
                "detail": detail,
                "recommendation": recommendation,
                "market_refs": market_refs,
            }
        )

    add_check(
        "multi_provider_catalog",
        "Multi-provider model catalog",
        catalog_total >= 10,
        12,
        f"{catalog_total} active/beta catalog models",
        "Seed trending + Bedrock/Azure/GCP packs, or run live cloud sync.",
        ["LiteLLM", "OpenRouter", "Portkey"],
    )
    add_check(
        "live_credential_readiness",
        "Live credential readiness (≥2 providers)",
        len(live_providers) >= 2,
        18,
        f"{len(live_providers)} live-ready providers",
        "Configure env/bindings for at least two vendors so failover is real, not simulated.",
        ["Datadog AI gateway practices", "Portkey", "Vercel AI Gateway"],
    )
    add_check(
        "ordered_fallback_chains",
        "Ordered multi-hop fallback chains",
        routes_with_chain >= 1,
        20,
        f"{routes_with_chain} active routes with ≥2 priority targets",
        "Use Suggest Live-Ready Chain on Route Priority, then save fallbacks with health checks on.",
        ["Datadog", "LiteLLM", "Kong AI Gateway"],
    )
    add_check(
        "health_check_routing",
        "Health-check / unhealthy ejection",
        routes_with_health >= 1,
        10,
        f"{routes_with_health} routes with health_check_enabled",
        "Enable Health Check Routing on production fallback policies.",
        ["Kong", "Datadog circuit-breaker pattern"],
    )
    add_check(
        "virtual_keys",
        "Virtual keys for team/agent blast-radius control",
        virtual_key_count >= 1,
        15,
        f"{virtual_key_count} virtual keys",
        "Mint virtual keys (or JIT-approved keys) instead of sharing raw provider credentials.",
        ["LiteLLM", "Portkey", "Datadog budgets"],
    )
    add_check(
        "budget_guardrails",
        "Budget policies / spend ceilings",
        budget_count >= 1,
        10,
        f"{budget_count} budget policies",
        "Create soft+hard budget policies per team/agent in Cost console.",
        ["Portkey", "LiteLLM", "TrueFoundry"],
    )
    add_check(
        "inference_cache",
        "Inference cache policy available",
        cache_policy_count >= 1,
        8,
        f"{cache_policy_count} active cache policies",
        "Define cache policies and optionally enable inference short-circuit for idempotent prompts.",
        ["Portkey semantic cache", "LiteLLM cache", "Cloudflare AI Gateway"],
    )

    # Auto-router is available when catalog can serve at least two complexity tiers.
    from app.services.gateway_auto_router import build_auto_route_decision

    sample = build_auto_route_decision(
        db,
        prompt_text="Classify this short prompt for routing.",
        prefer_live_only=False,
        max_candidates_per_tier=2,
    )
    tier_coverage = sum(1 for tier in ("simple", "standard", "complex") if sample.get("tier_candidates", {}).get(tier))
    add_check(
        "complexity_auto_router",
        "Complexity auto-router catalog coverage",
        tier_coverage >= 2 and bool(sample.get("selected_model")),
        7,
        f"{tier_coverage}/3 tiers have catalog candidates; selected={sample.get('selected_model') or 'none'}",
        "Seed trending/cloud packs so simple and complex tier models exist, then use model=auto or POST /gateway/best-practices/auto-route.",
        ["LiteLLM Auto Router", "OpenRouter"],
    )

    earned = sum(int(check["weight"]) for check in checks if check["passed"])
    possible = sum(int(check["weight"]) for check in checks)
    score = int(round((earned / possible) * 100)) if possible else 0
    if score >= 85:
        band = "market_leading"
    elif score >= 65:
        band = "production_capable"
    elif score >= 40:
        band = "developing"
    else:
        band = "early"

    top_gaps = [check for check in checks if not check["passed"]]
    top_gaps.sort(key=lambda row: int(row["weight"]), reverse=True)

    return {
        "score": score,
        "max_score": 100,
        "band": band,
        "earned_weight": earned,
        "possible_weight": possible,
        "checks": checks,
        "top_gaps": top_gaps[:5],
        "readiness": {
            "ready_providers": readiness.get("ready_providers"),
            "total_providers": readiness.get("total_providers"),
            "catalog_models_total": catalog_total,
            "simulation_enabled": readiness.get("simulation_enabled"),
            "live_provider_types": [row["provider_type"] for row in live_providers],
        },
        "market_trends": [
            {
                "id": "control_plane_not_proxy",
                "title": "Gateways are becoming agent control planes",
                "summary": "Buyers expect routing, budgets, guardrails, catalog sync, and eval—not only an OpenAI-compatible proxy.",
            },
            {
                "id": "live_catalog_readiness",
                "title": "Live model discovery + readiness before invoke",
                "summary": "Hyperscaler SKUs churn weekly; operators need discover/sync and live-ready signals before Playground/Gateway runs.",
            },
            {
                "id": "reliability_failover",
                "title": "Ordered multi-provider failover with health ejection",
                "summary": "Production agents require retries, fallback chains, and unhealthy target ejection configured centrally.",
            },
            {
                "id": "cost_virtual_keys",
                "title": "Virtual keys + token budgets as default blast-radius control",
                "summary": "Per-team keys with soft/hard ceilings stop runaway agent loops before provider billing does.",
            },
        ],
        "next_actions": [
            {
                "action": gap["recommendation"],
                "check_id": gap["id"],
                "weight": gap["weight"],
            }
            for gap in top_gaps[:3]
        ],
    }


def suggest_readiness_aware_fallback_chain(
    db: Session,
    *,
    max_hops: int = 3,
    prefer_live_only: bool = True,
) -> dict[str, Any]:
    readiness = build_inference_readiness(db)
    providers = list(readiness.get("providers") or [])
    providers.sort(
        key=lambda row: (
            0 if row.get("live_ready") else 1,
            _PROVIDER_RANK.get(str(row.get("provider_type") or ""), 500),
            str(row.get("provider_type") or ""),
        )
    )

    catalog_by_provider: dict[str, list[str]] = {}
    from app.models import SupportedModelCatalogEntry

    rows = (
        db.query(SupportedModelCatalogEntry.provider_type, SupportedModelCatalogEntry.model_name)
        .filter(SupportedModelCatalogEntry.status.in_(("active", "beta")))
        .order_by(SupportedModelCatalogEntry.model_name.asc())
        .all()
    )
    for provider_type, model_name in rows:
        key = str(provider_type or "").strip().lower()
        if not key:
            continue
        catalog_by_provider.setdefault(key, []).append(str(model_name))

    selected: list[dict[str, Any]] = []
    skipped: list[dict[str, str]] = []
    hop_limit = max(1, min(int(max_hops or 3), 8))

    for row in providers:
        provider_type = str(row.get("provider_type") or "").strip().lower()
        if not provider_type or provider_type == "cursor":
            # Cursor is local/dev-oriented; keep hyperscaler/public APIs for failover defaults.
            if provider_type == "cursor":
                skipped.append({"provider_type": provider_type, "reason": "skipped_dev_local_provider"})
            continue
        if prefer_live_only and not row.get("live_ready"):
            skipped.append({"provider_type": provider_type, "reason": "not_live_ready"})
            continue
        if not row.get("invoke_supported"):
            skipped.append({"provider_type": provider_type, "reason": "invoke_unsupported"})
            continue
        models = catalog_by_provider.get(provider_type) or []
        model_name = _pick_model_for_provider(provider_type, models)
        if not model_name:
            skipped.append({"provider_type": provider_type, "reason": "no_catalog_model"})
            continue
        selected.append(
            {
                "provider_id": f"{provider_type}:*",
                "provider_type": provider_type,
                "model_name": model_name,
                "priority": len(selected) + 1,
                "live_ready": bool(row.get("live_ready")),
            }
        )
        if len(selected) >= hop_limit:
            break

    if not selected:
        # Soften to catalog-backed invoke-supported providers when nothing is live.
        for row in providers:
            provider_type = str(row.get("provider_type") or "").strip().lower()
            if not provider_type or provider_type == "cursor" or not row.get("invoke_supported"):
                continue
            models = catalog_by_provider.get(provider_type) or []
            model_name = _pick_model_for_provider(provider_type, models)
            if not model_name:
                continue
            selected.append(
                {
                    "provider_id": f"{provider_type}:*",
                    "provider_type": provider_type,
                    "model_name": model_name,
                    "priority": len(selected) + 1,
                    "live_ready": bool(row.get("live_ready")),
                }
            )
            if len(selected) >= hop_limit:
                break

    priority_order = [
        {
            "provider_id": item["provider_id"],
            "model_name": item["model_name"],
            "priority": item["priority"],
        }
        for item in selected
    ]

    return {
        "priority_order": priority_order,
        "targets": selected,
        "skipped": skipped[:20],
        "recommended": {
            "health_check_enabled": True,
            "max_fallback_hops": max(0, len(priority_order) - 1),
            "global_timeout_ms": 4500,
        },
        "rationale": (
            "Ordered live-ready multi-provider chain (market reliability practice). "
            "Wildcard provider_id uses catalog models for the matching provider_type."
            if any(item.get("live_ready") for item in selected)
            else "No live-ready providers detected; suggested catalog-backed chain for dry-run configuration."
        ),
        "live_ready_count": sum(1 for item in selected if item.get("live_ready")),
    }


def apply_provider_priority_chain(
    route: RoutePolicy,
    *,
    priority_order: list[dict[str, Any]],
    tenant_id: str,
    environment: str = "dev",
    health_check_enabled: bool = True,
    max_fallback_hops: int = 2,
    global_timeout_ms: int = 4500,
) -> dict[str, Any]:
    """Persist priority_order under provider_priority (canonical shape for posture scoring)."""
    try:
        fallback = json.loads(route.fallback_policy or "{}")
    except json.JSONDecodeError:
        fallback = {}
    if not isinstance(fallback, dict):
        fallback = {}
    existing = fallback.get("provider_priority")
    if not isinstance(existing, dict):
        existing = {}
    next_payload = {
        **existing,
        "tenant_id": str(tenant_id or existing.get("tenant_id") or BOOTSTRAP_TENANT_ID).strip(),
        "environment": str(environment or existing.get("environment") or "dev").strip(),
        "priority_order": list(priority_order),
        "health_check_enabled": bool(health_check_enabled),
        "max_fallback_hops": int(max_fallback_hops),
        "global_timeout_ms": int(global_timeout_ms),
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    fallback["provider_priority"] = next_payload
    # Drop legacy top-level keys that confused operators after pack10 apply.
    fallback.pop("priority_order", None)
    route.fallback_policy = json.dumps(fallback, separators=(",", ":"))
    return next_payload


def bootstrap_best_practices_leadership(
    db: Session,
    *,
    tenant_id: str = BOOTSTRAP_TENANT_ID,
    environment: str = "dev",
    max_hops: int = 3,
) -> dict[str, Any]:
    """Idempotent local/dev bootstrap to close configurable posture gaps (chain, health, cache).

    Does **not** forge live credential readiness — that still requires real provider env/bindings.
    """
    before = build_gateway_best_practices_posture(db)
    actions: list[dict[str, Any]] = []
    env = str(environment or "dev").strip() or "dev"
    tenant = str(tenant_id or BOOTSTRAP_TENANT_ID).strip() or BOOTSTRAP_TENANT_ID
    hop_limit = max(2, min(int(max_hops or 3), 8))

    route = (
        db.query(RoutePolicy)
        .filter(RoutePolicy.route_name == BOOTSTRAP_ROUTE_NAME)
        .order_by(RoutePolicy.route_policy_id.asc())
        .first()
    )
    if not route:
        route = RoutePolicy(
            route_policy_id=str(uuid4()),
            route_name=BOOTSTRAP_ROUTE_NAME,
            candidate_deployments="[]",
            load_balancing_strategy="weighted",
            retry_policy="{}",
            fallback_policy="{}",
            timeout_policy="{}",
            status="active",
        )
        db.add(route)
        db.flush()
        actions.append(
            {
                "action": "create_route",
                "route_policy_id": route.route_policy_id,
                "route_name": BOOTSTRAP_ROUTE_NAME,
            }
        )
    elif str(route.status or "").lower() != "active":
        route.status = "active"
        actions.append(
            {
                "action": "reactivate_route",
                "route_policy_id": route.route_policy_id,
                "route_name": BOOTSTRAP_ROUTE_NAME,
            }
        )

    suggestion = suggest_readiness_aware_fallback_chain(
        db,
        max_hops=hop_limit,
        prefer_live_only=False,
    )
    priority_order = list(suggestion.get("priority_order") or [])
    if len(priority_order) >= 2:
        recommended = suggestion.get("recommended") or {}
        apply_provider_priority_chain(
            route,
            priority_order=priority_order,
            tenant_id=tenant,
            environment=env,
            health_check_enabled=bool(recommended.get("health_check_enabled", True)),
            max_fallback_hops=int(recommended.get("max_fallback_hops") or max(0, len(priority_order) - 1)),
            global_timeout_ms=int(recommended.get("global_timeout_ms") or 4500),
        )
        actions.append(
            {
                "action": "apply_fallback_chain",
                "route_policy_id": route.route_policy_id,
                "targets": len(priority_order),
                "health_check_enabled": True,
                "live_ready_count": int(suggestion.get("live_ready_count") or 0),
            }
        )
    else:
        actions.append(
            {
                "action": "skip_fallback_chain",
                "reason": "insufficient_catalog_or_readiness_targets",
                "targets": len(priority_order),
            }
        )

    cache_count = db.query(CachePolicy).filter(CachePolicy.status == "active").count()
    cache_policy_id: Optional[str] = None
    if cache_count < 1:
        existing_scope = (
            db.query(CachePolicy)
            .filter(CachePolicy.scope == BOOTSTRAP_CACHE_SCOPE)
            .order_by(CachePolicy.cache_policy_id.asc())
            .first()
        )
        if existing_scope:
            existing_scope.status = "active"
            existing_scope.ttl_seconds = max(int(existing_scope.ttl_seconds or 0), 120)
            cache_policy_id = existing_scope.cache_policy_id
            actions.append(
                {
                    "action": "reactivate_cache_policy",
                    "cache_policy_id": cache_policy_id,
                    "scope": BOOTSTRAP_CACHE_SCOPE,
                }
            )
        else:
            policy = CachePolicy(
                cache_policy_id=str(uuid4()),
                scope=BOOTSTRAP_CACHE_SCOPE,
                ttl_seconds=120,
                key_strategy="default",
                invalidation_strategy="ttl",
                privacy_mode="standard",
                privacy_scope="tenant",
                non_cache_data_classes="[]",
                cache_mode="exact",
                similarity_threshold=0.9,
                status="active",
            )
            db.add(policy)
            db.flush()
            cache_policy_id = policy.cache_policy_id
            actions.append(
                {
                    "action": "create_cache_policy",
                    "cache_policy_id": cache_policy_id,
                    "scope": BOOTSTRAP_CACHE_SCOPE,
                }
            )
    else:
        actions.append({"action": "skip_cache_policy", "reason": "active_cache_policy_exists", "count": cache_count})

    budget_count = db.query(BudgetPolicy).count()
    budget_policy_id: Optional[str] = None
    if budget_count < 1:
        budget = BudgetPolicy(
            budget_policy_id=str(uuid4()),
            scope_type="team",
            scope_id=BOOTSTRAP_BUDGET_SCOPE_ID,
            budget_amount_cents=50000,
            window_type="daily",
            soft_limit_percent=80,
            hard_limit_percent=100,
            action_on_soft_limit="warn",
            action_on_hard_limit="block",
            reset_timezone="UTC",
            reset_hour_local=0,
            status="active",
        )
        db.add(budget)
        db.flush()
        budget_policy_id = budget.budget_policy_id
        actions.append(
            {
                "action": "create_budget_policy",
                "budget_policy_id": budget_policy_id,
                "scope_id": BOOTSTRAP_BUDGET_SCOPE_ID,
            }
        )
    else:
        actions.append({"action": "skip_budget_policy", "reason": "budget_policy_exists", "count": budget_count})

    vk_count = db.query(VirtualKey).count()
    virtual_key_id: Optional[str] = None
    if vk_count < 1:
        token_material = f"bootstrap-{uuid4().hex}"
        key = VirtualKey(
            key_id=f"z{int(datetime.utcnow().timestamp() * 1000):013d}-{uuid4()}",
            key_hash=hashlib.sha256(token_material.encode("utf-8")).hexdigest(),
            owner_scope_type="team",
            owner_scope_id=BOOTSTRAP_VK_SCOPE_ID,
            allowed_endpoint_families='["chat","completions"]',
            allowed_models="[]",
            guardrail_policy="{}",
            budget_policy_id=(budget_policy_id or "default")[:64],
            rate_limit_policy_id="default",
            authn_method="token",
            status="active",
        )
        db.add(key)
        db.flush()
        virtual_key_id = key.key_id
        actions.append(
            {
                "action": "create_virtual_key",
                "key_id": virtual_key_id,
                "owner_scope_id": BOOTSTRAP_VK_SCOPE_ID,
            }
        )
    else:
        actions.append({"action": "skip_virtual_key", "reason": "virtual_key_exists", "count": vk_count})

    db.flush()
    after = build_gateway_best_practices_posture(db)
    before_score = int(before.get("score") or 0)
    after_score = int(after.get("score") or 0)
    remaining = [
        {
            "check_id": gap.get("id"),
            "label": gap.get("label"),
            "weight": gap.get("weight"),
            "recommendation": gap.get("recommendation"),
        }
        for gap in (after.get("top_gaps") or [])
    ]

    return {
        "bootstrapped": True,
        "route_policy_id": route.route_policy_id,
        "route_name": BOOTSTRAP_ROUTE_NAME,
        "cache_policy_id": cache_policy_id,
        "budget_policy_id": budget_policy_id,
        "virtual_key_id": virtual_key_id,
        "tenant_id": tenant,
        "environment": env,
        "before": {
            "score": before_score,
            "band": before.get("band"),
            "earned_weight": before.get("earned_weight"),
        },
        "after": {
            "score": after_score,
            "band": after.get("band"),
            "earned_weight": after.get("earned_weight"),
            "checks": after.get("checks"),
            "top_gaps": after.get("top_gaps"),
        },
        "delta": after_score - before_score,
        "actions": actions,
        "remaining_gaps": remaining,
        "suggestion_rationale": suggestion.get("rationale"),
        "note": (
            "Bootstrap closes configurable gaps (fallback, health-check, cache, virtual key, budget). "
            "Live credential readiness still needs ≥2 env keys or active secret bindings — not forged here."
        ),
        "virtual_key_count": db.query(VirtualKey).count(),
        "budget_policy_count": db.query(BudgetPolicy).count(),
    }


def raise_engineering_leadership_scores(
    db: Session,
    *,
    actor_id: str,
    tenant_id: str = BOOTSTRAP_TENANT_ID,
    environment: str = "dev",
    max_hops: int = 3,
    enhance_cpli: bool = True,
    probe_peer: bool = False,
) -> dict[str, Any]:
    """Best-practices bootstrap + optional Force Reconcile/attest to lift CPLI."""
    if enhance_cpli:
        from fastapi import HTTPException

        from app.services.control_plane_contract import resolve_control_readonly

        if resolve_control_readonly(db):
            raise HTTPException(
                status_code=403,
                detail={
                    "error_code": "PLANE_CONTROL_READONLY",
                    "message": "Control-plane mutations are frozen (PLANE_CONTROL_READONLY or runtime freeze).",
                    "hint": "Clear runtime freeze via POST /platform/control-plane/freeze, or unset PLANE_CONTROL_READONLY.",
                },
            )

    posture = bootstrap_best_practices_leadership(
        db,
        tenant_id=tenant_id,
        environment=environment,
        max_hops=max_hops,
    )
    cpli_block: dict[str, Any] = {
        "enhanced": False,
        "before": None,
        "after": None,
        "delta": 0,
        "attestation_id": None,
        "note": "CPLI enhance skipped.",
    }
    if enhance_cpli:
        from app.services.control_plane_leadership import (
            arm_plane_isolation_and_fail_closed,
            attest_control_plane_leadership,
            build_control_plane_leadership,
        )
        from app.services.on_plane_coverage import compute_on_plane_coverage
        from app.services.plane_reconcile import run_reconcile_and_record
        from datetime import timedelta, timezone

        before_cpli = build_control_plane_leadership(db, window_hours=24, probe_peer=probe_peer)
        armed = arm_plane_isolation_and_fail_closed(db, actor_id=str(actor_id or "leadership-bootstrap"))
        window_start = datetime.now(timezone.utc) - timedelta(hours=24)
        coverage = compute_on_plane_coverage(db, window_start=window_start, environment=None)
        run_reconcile_and_record(
            db,
            probe_peer=probe_peer,
            source="api.leadership_bootstrap",
            on_plane_coverage=coverage,
        )
        attestation = attest_control_plane_leadership(
            db,
            actor_id=str(actor_id or "leadership-bootstrap"),
            window_hours=24,
            probe_peer=probe_peer,
        )
        after_cpli = build_control_plane_leadership(db, window_hours=24, probe_peer=probe_peer)
        before_score = int(before_cpli.get("score") or 0)
        after_score = int(after_cpli.get("score") or 0)
        cpli_block = {
            "enhanced": True,
            "before": {
                "score": before_score,
                "max_score": before_cpli.get("max_score"),
                "band": before_cpli.get("band"),
                "engineering_leader_ready": before_cpli.get("engineering_leader_ready"),
            },
            "after": {
                "score": after_score,
                "max_score": after_cpli.get("max_score"),
                "band": after_cpli.get("band"),
                "engineering_leader_ready": after_cpli.get("engineering_leader_ready"),
                "dimensions": after_cpli.get("dimensions"),
                "blockers": after_cpli.get("blockers"),
            },
            "delta": after_score - before_score,
            "attestation_id": attestation.get("attestation_id"),
            "armed": armed,
            "note": (
                "Armed fail-closed=drift + isolation contract; reconciled and attested CPLI. "
                "Runtime process isolation still requires live APP_PLANE=control|data deploy."
            ),
        }
        posture["actions"] = list(posture.get("actions") or []) + [
            {
                "action": "cpli_arm_isolation_fail_closed",
                "fail_closed_mode": armed.get("fail_closed_mode"),
                "isolation_contract": True,
            },
            {"action": "cpli_reconcile_attest", "attestation_id": attestation.get("attestation_id")},
        ]

    posture["cpli"] = cpli_block
    return posture
