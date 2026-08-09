"""AI gateway leadership index + intended→actual attribution analytics."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import CostEvent
from app.services.gateway_best_practices import build_gateway_best_practices_posture
from app.services.inference_readiness import build_inference_readiness

_WARMUP_PROMPTS: tuple[str, ...] = (
    "Say hello in one sentence.",
    "Summarize gateway fallback in two bullets.",
    "Draft a short JSON schema for a route policy object.",
    "Step by step, design a multi-agent security review workflow with tool calls.",
    "Refactor this distributed system for PCI compliance and threat model the changes.",
    "Explain embeddings vs chat completions for operators.",
)


def _parse_properties(raw: str | None) -> dict[str, Any]:
    try:
        parsed = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


SDK_INSTRUMENTATION_PRESETS: tuple[dict[str, Any], ...] = (
    {
        "id": "console-ops",
        "label": "Control-center Gateway Ops",
        "session_path": "/gateway/ops/chat",
        "session_name": "gateway-ops-chat",
        "properties": {"sdk": "agenthub-console", "feature": "gateway-ops"},
    },
    {
        "id": "playground",
        "label": "Playground Studio",
        "session_path": "/playground/run",
        "session_name": "playground-studio",
        "properties": {"sdk": "agenthub-console", "feature": "playground"},
    },
    {
        "id": "python-sdk",
        "label": "Python SDK service",
        "session_path": "/sdk/python/service",
        "session_name": "python-sdk",
        "properties": {"sdk": "agenthub-python", "feature": "service"},
    },
    {
        "id": "js-sdk",
        "label": "JS SDK browser/app",
        "session_path": "/sdk/js/app",
        "session_name": "js-sdk",
        "properties": {"sdk": "agenthub-js", "feature": "app"},
    },
    {
        "id": "ci-eval",
        "label": "CI evaluation job",
        "session_path": "/ci/eval",
        "session_name": "ci-eval",
        "properties": {"sdk": "agenthub-ci", "feature": "eval"},
    },
)

_LEADERSHIP_HISTORY_KEY = "gateway.leadership.history_json"


def build_attribution_analytics(
    db: Session,
    *,
    hours: int = 24,
    environment: Optional[str] = None,
    limit_pairs: int = 10,
    exclude_warmup: bool = False,
) -> dict[str, Any]:
    window_hours = max(1, min(int(hours or 24), 168))
    window_start = datetime.utcnow() - timedelta(hours=window_hours)
    query = db.query(CostEvent).filter(CostEvent.timestamp >= window_start)
    if environment:
        query = query.filter(CostEvent.environment == str(environment).strip())

    events = query.order_by(CostEvent.timestamp.desc()).limit(5000).all()
    attributed = 0
    switched = 0
    auto_routed = 0
    cost_switched = 0
    cost_same = 0
    warmup_skipped = 0
    pair_counter: Counter[tuple[str, str]] = Counter()
    tier_counter: Counter[str] = Counter()
    endpoint_counter: Counter[str] = Counter()

    for event in events:
        props = _parse_properties(getattr(event, "properties_json", None))
        if exclude_warmup and props.get("leadership_warmup"):
            warmup_skipped += 1
            continue
        intended = str(props.get("intended_model") or "").strip()
        actual = str(props.get("actual_model") or event.model_name or "").strip()
        if not intended and not props.get("model_switched") and not props.get("auto_route_tier"):
            continue
        if not intended:
            intended = actual
        attributed += 1
        endpoint_counter[str(event.endpoint_family or "unknown")] += 1
        tier = str(props.get("auto_route_tier") or "").strip()
        if tier:
            auto_routed += 1
            tier_counter[tier] += 1
        did_switch = bool(props.get("model_switched")) or (
            intended and actual and intended.lower() != actual.lower()
        )
        cost = int(event.estimated_cost_cents or 0)
        if did_switch:
            switched += 1
            cost_switched += cost
            pair_counter[(intended, actual)] += 1
        else:
            cost_same += cost

    total_events = len(events)
    switch_rate = round((switched / attributed) * 100, 2) if attributed else 0.0
    attribution_coverage = round((attributed / total_events) * 100, 2) if total_events else 0.0
    top_pairs = [
        {
            "intended_model": intended,
            "actual_model": actual,
            "events": count,
        }
        for (intended, actual), count in pair_counter.most_common(max(1, min(int(limit_pairs or 10), 25)))
    ]

    return {
        "hours": window_hours,
        "environment": environment,
        "exclude_warmup": bool(exclude_warmup),
        "warmup_events_skipped": warmup_skipped,
        "total_events": total_events,
        "attributed_events": attributed,
        "attribution_coverage_percent": attribution_coverage,
        "switched_events": switched,
        "switch_rate_percent": switch_rate,
        "auto_routed_events": auto_routed,
        "cost_cents_switched": cost_switched,
        "cost_cents_same_model": cost_same,
        "top_switch_pairs": top_pairs,
        "auto_route_tiers": [
            {"tier": tier, "events": count} for tier, count in tier_counter.most_common()
        ],
        "endpoint_families": [
            {"endpoint_family": family, "events": count}
            for family, count in endpoint_counter.most_common(8)
        ],
        "leader_signal": (
            "strong"
            if attributed >= 10 and attribution_coverage >= 40
            else ("emerging" if attributed >= 1 else "needs_traffic")
        ),
    }


def build_model_liquidity_ranking(
    db: Session,
    *,
    hours: int = 168,
    environment: Optional[str] = None,
    limit: int = 20,
) -> dict[str, Any]:
    """OpenRouter-style liquidity ranking from local telemetry (not an external marketplace)."""
    window_hours = max(1, min(int(hours or 168), 168))
    window_start = datetime.utcnow() - timedelta(hours=window_hours)
    query = db.query(CostEvent).filter(CostEvent.timestamp >= window_start)
    if environment:
        query = query.filter(CostEvent.environment == str(environment).strip())
    events = query.order_by(CostEvent.timestamp.desc()).limit(5000).all()

    stats: dict[str, dict[str, float]] = defaultdict(
        lambda: {
            "events": 0.0,
            "cost_cents": 0.0,
            "stable_hits": 0.0,
            "switch_away": 0.0,
            "auto_route_hits": 0.0,
            "latency_ms_total": 0.0,
            "latency_samples": 0.0,
        }
    )

    for event in events:
        model = str(event.model_name or "").strip()
        if not model:
            continue
        props = _parse_properties(getattr(event, "properties_json", None))
        row = stats[model]
        row["events"] += 1
        row["cost_cents"] += float(event.estimated_cost_cents or 0)
        intended = str(props.get("intended_model") or "").strip()
        actual = str(props.get("actual_model") or model).strip()
        switched = bool(props.get("model_switched")) or (
            intended and actual and intended.lower() != actual.lower()
        )
        if props.get("auto_route_tier"):
            row["auto_route_hits"] += 1
        if switched and intended and intended.lower() != model.lower():
            # This event landed on `model` after a switch — count as liquidity for actual model.
            row["stable_hits"] += 0.5
        elif not switched:
            row["stable_hits"] += 1
        if switched and intended and intended.lower() == model.lower():
            row["switch_away"] += 1
        latency = props.get("latency_ms")
        if isinstance(latency, (int, float)) and latency >= 0:
            row["latency_ms_total"] += float(latency)
            row["latency_samples"] += 1

    ranked: list[dict[str, Any]] = []
    for model_name, row in stats.items():
        events_n = max(1.0, row["events"])
        avg_cost = row["cost_cents"] / events_n
        stability = row["stable_hits"] / events_n
        switch_penalty = row["switch_away"] / events_n
        avg_latency = (
            row["latency_ms_total"] / row["latency_samples"] if row["latency_samples"] else 500.0
        )
        # Higher is better: volume + stability + low relative cost/latency.
        # Pack 10 item 107: optional runtime ranking weights.
        volume_component = min(40.0, row["events"] * 2.0)
        stability_component = stability * 35.0 + min(15.0, row["auto_route_hits"] * 1.5)
        cost_component = max(0.0, 20.0 - min(20.0, avg_cost / 5.0))
        latency_component = max(0.0, 15.0 - min(15.0, avg_latency / 100.0))
        score = (
            volume_component
            + stability_component
            + cost_component
            + latency_component
            - switch_penalty * 10.0
        )
        ranked.append(
            {
                "model_name": model_name,
                "score": round(score, 2),
                "events": int(row["events"]),
                "avg_cost_cents": round(avg_cost, 2),
                "stability_rate": round(stability, 3),
                "auto_route_hits": int(row["auto_route_hits"]),
                "avg_latency_ms": round(avg_latency, 1),
                "_components": {
                    "volume": volume_component,
                    "stability": stability_component,
                    "cost": cost_component,
                    "latency": latency_component,
                },
            }
        )

    weights = {"volume": 0.35, "stability": 0.30, "cost": 0.20, "latency": 0.15}
    try:
        from app.services.gateway_leadership_pack8 import get_ranking_weights

        configured = get_ranking_weights(db).get("weights") or {}
        for key in weights:
            if key in configured:
                weights[key] = float(configured[key])
    except Exception:  # noqa: BLE001
        pass
    weight_sum = sum(weights.values()) or 1.0
    for item in ranked:
        comps = item.pop("_components", {}) or {}
        # Re-blend positive components by runtime weights, keep switch penalty effect via base score floor.
        blended = (
            float(comps.get("volume") or 0) * (weights["volume"] / weight_sum) * 4
            + float(comps.get("stability") or 0) * (weights["stability"] / weight_sum) * 4
            + float(comps.get("cost") or 0) * (weights["cost"] / weight_sum) * 4
            + float(comps.get("latency") or 0) * (weights["latency"] / weight_sum) * 4
        )
        item["score"] = round(blended, 2)
        item["weight_profile"] = weights

    ranked.sort(key=lambda item: (-float(item["score"]), -int(item["events"]), item["model_name"]))
    top = ranked[: max(1, min(int(limit or 20), 50))]
    score_map = {str(item["model_name"]).lower(): float(item["score"]) for item in ranked}
    return {
        "hours": window_hours,
        "environment": environment,
        "models": top,
        "score_by_model": score_map,
        "sample_events": len(events),
        "weights": weights,
        "leader_signal": "strong" if len(ranked) >= 5 else ("emerging" if ranked else "needs_traffic"),
    }


def warmup_leadership_attribution(
    db: Session,
    *,
    samples: int = 6,
    environment: str = "dev",
    actor_id: str,
    strategy: str = "balanced",
) -> dict[str, Any]:
    """Operator-triggered bootstrap of attributed CostEvents for leadership analytics."""
    from app.services.gateway_auto_router import build_auto_route_decision

    count = max(1, min(int(samples or 6), 12))
    env = str(environment or "dev").strip().lower() or "dev"
    created: list[dict[str, Any]] = []

    for index, prompt in enumerate(_WARMUP_PROMPTS[:count]):
        decision = build_auto_route_decision(
            db,
            prompt_text=prompt,
            prefer_live_only=False,
            strategy=strategy,
            message_count=2,
        )
        selected_model = str(decision.get("selected_model") or "").strip()
        if not selected_model:
            continue
        request_id = f"warmup-{uuid4().hex[:16]}"
        trace_id = f"trace-leadership-warmup-{uuid4()}"
        complexity = decision.get("complexity") or {}
        props = {
            "intended_model": "auto",
            "actual_model": selected_model,
            "model_switched": True,
            "auto_route_tier": complexity.get("tier"),
            "auto_route_score": complexity.get("score"),
            "auto_route_strategy": decision.get("strategy"),
            "leadership_warmup": True,
            "warmup_prompt_index": index,
            "session_path": "/leadership/warmup",
            "session_name": "leadership-warmup",
            "sdk": "agenthub-leadership-warmup",
            "latency_ms": 80 + index * 12,
        }
        db.add(
            CostEvent(
                cost_event_id=f"cost-{uuid4().hex[:24]}",
                request_id=request_id,
                trace_id=trace_id,
                request_tag="leadership.warmup",
                session_id=f"session-leadership-warmup-{actor_id}",
                agent_id="gateway-leadership-warmup",
                owner_scope=f"user:{actor_id}",
                environment=env,
                model_name=selected_model,
                endpoint_family="chat.completions",
                input_tokens=max(8, len(prompt.split())),
                output_tokens=24,
                estimated_cost_cents=1 + index,
                currency="USD",
                cache_hit=False,
                properties_json=json.dumps(props, separators=(",", ":")),
            )
        )
        created.append(
            {
                "request_id": request_id,
                "model_name": selected_model,
                "tier": complexity.get("tier"),
                "prompt_preview": prompt[:80],
            }
        )

    db.flush()
    return {
        "created_events": len(created),
        "environment": env,
        "strategy": strategy,
        "events": created,
        "message": (
            f"Created {len(created)} attributed warmup events for leadership analytics."
            if created
            else "No warmup events created; seed model catalog first."
        ),
    }


def build_gateway_leadership_index(
    db: Session,
    *,
    hours: int = 24,
    exclude_warmup: bool = False,
) -> dict[str, Any]:
    posture = build_gateway_best_practices_posture(db)
    readiness = build_inference_readiness(db)
    attribution = build_attribution_analytics(db, hours=hours, exclude_warmup=exclude_warmup)
    rankings = build_model_liquidity_ranking(db, hours=max(24, hours))

    posture_score = float(posture.get("score") or 0)
    ready = int(readiness.get("ready_providers") or 0)
    total = max(1, int(readiness.get("total_providers") or 1))
    readiness_score = min(100.0, (ready / total) * 100.0)

    coverage = float(attribution.get("attribution_coverage_percent") or 0.0)
    # Reward instrumentation; do not punish healthy zero-switch fleets.
    if attribution["attributed_events"] >= 10:
        attribution_score = min(100.0, 60.0 + coverage * 0.4)
    elif attribution["attributed_events"] >= 1:
        attribution_score = min(100.0, 40.0 + coverage * 0.4)
    else:
        attribution_score = 25.0 if ready >= 1 else 10.0

    auto_check = next(
        (row for row in posture.get("checks") or [] if row.get("id") == "complexity_auto_router"),
        None,
    )
    auto_score = 100.0 if auto_check and auto_check.get("passed") else 35.0
    ranked_n = len(rankings.get("models") or [])
    ranking_score = 100.0 if ranked_n >= 5 else (60.0 if ranked_n >= 2 else (30.0 if ranked_n else 10.0))

    composite = round(
        posture_score * 0.40
        + readiness_score * 0.22
        + attribution_score * 0.13
        + auto_score * 0.13
        + ranking_score * 0.12,
        1,
    )
    if composite >= 85:
        band = "market_leader"
    elif composite >= 70:
        band = "strong_challenger"
    elif composite >= 50:
        band = "production_capable"
    else:
        band = "developing"

    gaps = []
    if posture_score < 85:
        for gap in posture.get("top_gaps") or []:
            gaps.append(
                {
                    "area": "best_practices",
                    "action": gap.get("recommendation"),
                    "weight": gap.get("weight"),
                }
            )
    if ready < 2:
        gaps.append(
            {
                "area": "readiness",
                "action": "Configure live credentials for at least two providers.",
                "weight": 18,
            }
        )
    if attribution["attributed_events"] < 1:
        gaps.append(
            {
                "area": "attribution",
                "action": "Run chat with auto-route, execute fallback, or use Leadership Warmup to populate analytics.",
                "weight": 15,
            }
        )
    if ranked_n < 2:
        gaps.append(
            {
                "area": "model_rankings",
                "action": "Generate attributed traffic so telemetry model rankings can steer auto-route.",
                "weight": 12,
            }
        )

    return {
        "score": composite,
        "max_score": 100,
        "band": band,
        "components": {
            "best_practices": {"score": posture_score, "weight": 0.40},
            "live_readiness": {"score": round(readiness_score, 1), "weight": 0.22, "ready_providers": ready},
            "attribution_analytics": {
                "score": round(attribution_score, 1),
                "weight": 0.13,
                "attributed_events": attribution["attributed_events"],
                "switch_rate_percent": attribution["switch_rate_percent"],
            },
            "auto_router": {"score": auto_score, "weight": 0.13, "passed": bool(auto_check and auto_check.get("passed"))},
            "model_rankings": {
                "score": ranking_score,
                "weight": 0.12,
                "ranked_models": ranked_n,
                "leader_signal": rankings.get("leader_signal"),
            },
        },
        "attribution": attribution,
        "model_rankings": rankings,
        "posture_band": posture.get("band"),
        "next_actions": gaps[:4],
        "market_claim": (
            "Governance control plane with live readiness, reliability failover, "
            "complexity auto-routing, intended→actual attribution, and telemetry model rankings."
        ),
        "exclude_warmup": bool(exclude_warmup),
    }


def compare_auto_route_strategies(
    db: Session,
    *,
    prompt_text: str,
    prefer_live_only: bool = True,
    refine_with_judge: bool = True,
) -> dict[str, Any]:
    from app.services.gateway_auto_router import build_auto_route_decision

    strategies = ("balanced", "cost", "quality")
    comparisons = []
    for strategy in strategies:
        decision = build_auto_route_decision(
            db,
            prompt_text=prompt_text,
            prefer_live_only=prefer_live_only,
            strategy=strategy,
            refine_with_judge=refine_with_judge,
            use_telemetry_ranking=True,
        )
        comparisons.append(
            {
                "strategy": strategy,
                "selected_model": decision.get("selected_model"),
                "selected_provider_type": decision.get("selected_provider_type"),
                "tier": (decision.get("complexity") or {}).get("tier"),
                "score": (decision.get("complexity") or {}).get("score"),
                "source": (decision.get("selected") or {}).get("source"),
                "rationale": decision.get("rationale"),
            }
        )
    distinct_models = sorted({row["selected_model"] for row in comparisons if row.get("selected_model")})
    return {
        "prompt_preview": str(prompt_text or "")[:160],
        "comparisons": comparisons,
        "distinct_model_count": len(distinct_models),
        "distinct_models": distinct_models,
        "recommendation": (
            "Strategies diverge — review cost vs quality trade-off before pinning a route default."
            if len(distinct_models) > 1
            else "Strategies agree on the same model for this prompt."
        ),
    }


def batch_auto_route_classify(
    db: Session,
    *,
    prompts: list[str],
    strategy: str = "balanced",
    prefer_live_only: bool = True,
) -> dict[str, Any]:
    from app.services.gateway_auto_router import build_auto_route_decision

    rows = []
    for prompt in prompts[:25]:
        text = str(prompt or "").strip()
        if not text:
            continue
        decision = build_auto_route_decision(
            db,
            prompt_text=text,
            prefer_live_only=prefer_live_only,
            strategy=strategy,
        )
        rows.append(
            {
                "prompt_preview": text[:120],
                "tier": (decision.get("complexity") or {}).get("tier"),
                "score": (decision.get("complexity") or {}).get("score"),
                "selected_model": decision.get("selected_model"),
                "strategy": decision.get("strategy"),
            }
        )
    tier_counts = Counter(str(row.get("tier") or "unknown") for row in rows)
    return {
        "strategy": strategy,
        "count": len(rows),
        "results": rows,
        "tier_counts": dict(tier_counts),
    }


def estimate_tier_savings(db: Session, *, hours: int = 168) -> dict[str, Any]:
    attribution = build_attribution_analytics(db, hours=hours, exclude_warmup=False)
    tiers = {row["tier"]: int(row["events"]) for row in attribution.get("auto_route_tiers") or []}
    simple_n = tiers.get("simple", 0)
    standard_n = tiers.get("standard", 0)
    complex_n = tiers.get("complex", 0)
    # Relative unit costs for illustrative operator guidance (not billing truth).
    unit = {"simple": 1.0, "standard": 3.0, "complex": 8.0}
    actual = simple_n * unit["simple"] + standard_n * unit["standard"] + complex_n * unit["complex"]
    all_complex = (simple_n + standard_n + complex_n) * unit["complex"]
    saved_units = max(0.0, all_complex - actual)
    return {
        "hours": hours,
        "tier_events": {"simple": simple_n, "standard": standard_n, "complex": complex_n},
        "relative_cost_units_actual": round(actual, 2),
        "relative_cost_units_all_complex": round(all_complex, 2),
        "estimated_relative_savings_units": round(saved_units, 2),
        "estimated_relative_savings_percent": round((saved_units / all_complex) * 100, 2) if all_complex else 0.0,
        "note": "Relative units for operator guidance only; not provider invoice amounts.",
    }


def build_circuit_breaker_recommendations(db: Session, *, hours: int = 24) -> dict[str, Any]:
    window_start = datetime.utcnow() - timedelta(hours=max(1, min(hours, 168)))
    events = (
        db.query(CostEvent)
        .filter(CostEvent.timestamp >= window_start)
        .order_by(CostEvent.timestamp.desc())
        .limit(5000)
        .all()
    )
    fail_counter: Counter[str] = Counter()
    total_counter: Counter[str] = Counter()
    for event in events:
        props = _parse_properties(getattr(event, "properties_json", None))
        provider_id = str(props.get("selected_provider_id") or "").strip()
        if not provider_id:
            continue
        total_counter[provider_id] += 1
        outcome = str(props.get("outcome") or "").strip().lower()
        if outcome in {"failed_simulated", "failed_timeout", "budget_blocked", "retry_policy_blocked"}:
            fail_counter[provider_id] += 1

    recommendations = []
    for provider_id, total in total_counter.most_common(20):
        fails = fail_counter.get(provider_id, 0)
        rate = (fails / total) if total else 0.0
        if rate < 0.25 or total < 3:
            continue
        recommendations.append(
            {
                "provider_id": provider_id,
                "events": total,
                "failure_events": fails,
                "failure_rate": round(rate, 3),
                "action": "Enable health_check_enabled and lower max_fallback_hops priority for this provider.",
            }
        )
    return {
        "hours": hours,
        "recommendations": recommendations,
        "message": (
            f"{len(recommendations)} providers exceed failure threshold."
            if recommendations
            else "No circuit-breaker actions recommended from recent hop outcomes."
        ),
    }


def ranking_aware_fallback_suggest(db: Session, *, max_hops: int = 3) -> dict[str, Any]:
    from app.services.gateway_best_practices import suggest_readiness_aware_fallback_chain

    base = suggest_readiness_aware_fallback_chain(db, max_hops=max_hops, prefer_live_only=True)
    rankings = build_model_liquidity_ranking(db, hours=168, limit=50)
    score_by_model = rankings.get("score_by_model") or {}
    targets = list(base.get("targets") or [])
    targets.sort(
        key=lambda row: (
            -float(score_by_model.get(str(row.get("model_name") or "").lower(), 0.0)),
            int(row.get("priority") or 99),
        )
    )
    for index, row in enumerate(targets, start=1):
        row["priority"] = index
        row["telemetry_score"] = float(score_by_model.get(str(row.get("model_name") or "").lower(), 0.0))
    priority_order = [
        {
            "provider_id": row["provider_id"],
            "model_name": row["model_name"],
            "priority": row["priority"],
        }
        for row in targets
    ]
    return {
        **base,
        "priority_order": priority_order,
        "targets": targets,
        "ranking_applied": True,
        "rationale": (
            "Live-ready chain reordered by telemetry model rankings (liquidity/stability/cost). "
            + str(base.get("rationale") or "")
        ),
    }


def list_sdk_instrumentation_presets() -> dict[str, Any]:
    return {"presets": list(SDK_INSTRUMENTATION_PRESETS)}


def export_leadership_evidence_pack(
    db: Session,
    *,
    hours: int = 24,
    exclude_warmup: bool = True,
) -> dict[str, Any]:
    index = build_gateway_leadership_index(db, hours=hours, exclude_warmup=exclude_warmup)
    compare_sample = compare_auto_route_strategies(
        db,
        prompt_text="Summarize gateway fallback policy for operators.",
        prefer_live_only=False,
    )
    savings = estimate_tier_savings(db, hours=max(24, hours))
    breakers = build_circuit_breaker_recommendations(db, hours=hours)
    return {
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "hours": hours,
        "exclude_warmup": exclude_warmup,
        "leadership_index": index,
        "auto_route_compare_sample": compare_sample,
        "savings_estimate": savings,
        "circuit_breaker_recommendations": breakers,
        "sdk_presets": list_sdk_instrumentation_presets(),
        "backlog_ref": "backend/docs/governance/ai-gateway-leadership-capability-backlog-100.md",
    }


def record_leadership_snapshot(db: Session, *, hours: int = 24, exclude_warmup: bool = False) -> dict[str, Any]:
    from app.services.runtime_config import get_runtime_config, upsert_runtime_config_value

    index = build_gateway_leadership_index(db, hours=hours, exclude_warmup=exclude_warmup)
    snapshot = {
        "snapshot_id": f"lead-{uuid4().hex[:12]}",
        "recorded_at": datetime.utcnow().isoformat() + "Z",
        "score": index.get("score"),
        "band": index.get("band"),
        "attributed_events": (index.get("attribution") or {}).get("attributed_events"),
        "ranked_models": ((index.get("components") or {}).get("model_rankings") or {}).get("ranked_models"),
    }
    raw = get_runtime_config(db, _LEADERSHIP_HISTORY_KEY, "[]")
    try:
        history = json.loads(raw or "[]")
    except json.JSONDecodeError:
        history = []
    if not isinstance(history, list):
        history = []
    history.insert(0, snapshot)
    history = history[:50]
    upsert_runtime_config_value(
        db,
        _LEADERSHIP_HISTORY_KEY,
        json.dumps(history, separators=(",", ":")),
        description="Leadership index snapshot history",
    )
    return {"snapshot": snapshot, "history_count": len(history)}


def list_leadership_history(db: Session, *, limit: int = 20) -> dict[str, Any]:
    from app.services.runtime_config import get_runtime_config

    raw = get_runtime_config(db, _LEADERSHIP_HISTORY_KEY, "[]")
    try:
        history = json.loads(raw or "[]")
    except json.JSONDecodeError:
        history = []
    if not isinstance(history, list):
        history = []
    clipped = history[: max(1, min(int(limit or 20), 50))]
    return {"count": len(clipped), "snapshots": clipped}


def build_leadership_alerts(db: Session, *, hours: int = 24, floor_score: float = 70.0) -> dict[str, Any]:
    index = build_gateway_leadership_index(db, hours=hours, exclude_warmup=True)
    history = list_leadership_history(db, limit=5)
    alerts = []
    score = float(index.get("score") or 0)
    if score < float(floor_score):
        alerts.append(
            {
                "severity": "warning",
                "code": "leadership_below_floor",
                "message": f"Leadership score {score} is below floor {floor_score}.",
            }
        )
    if (index.get("attribution") or {}).get("leader_signal") == "needs_traffic":
        alerts.append(
            {
                "severity": "info",
                "code": "attribution_needs_traffic",
                "message": "Attribution analytics need traffic; run warmup or auto-routed chat.",
            }
        )
    snapshots = history.get("snapshots") or []
    if len(snapshots) >= 2:
        prev = float(snapshots[1].get("score") or 0)
        if score + 5 < prev:
            alerts.append(
                {
                    "severity": "warning",
                    "code": "leadership_score_drop",
                    "message": f"Leadership score dropped from {prev} to {score}.",
                }
            )
    return {
        "floor_score": floor_score,
        "current_score": score,
        "band": index.get("band"),
        "alerts": alerts,
        "alert_count": len(alerts),
    }
