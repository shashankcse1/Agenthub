"""Pack 6 leadership capabilities (backlog items 31–45).

Real operator APIs — no stub UIs. Simulation-safe defaults for live judge.
"""

from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import CostEvent, ProviderCredentialBinding, SupportedModelCatalogEntry
from app.services.gateway_leadership import build_circuit_breaker_recommendations
from app.services.inference_readiness import build_inference_readiness


_OPENROUTER_LIQUIDITY_KEY = "gateway.leadership.openrouter_liquidity_json"
_EXPERIMENT_KEY = "gateway.leadership.auto_route_experiments_json"

# Offline-safe seed liquidity (OpenRouter-style popularity proxies).
_OPENROUTER_SEED: tuple[dict[str, Any], ...] = (
    {"model_name": "openai/gpt-4o-mini", "liquidity_score": 92.0, "source": "seed"},
    {"model_name": "openai/gpt-4o", "liquidity_score": 88.0, "source": "seed"},
    {"model_name": "anthropic/claude-3.5-sonnet", "liquidity_score": 90.0, "source": "seed"},
    {"model_name": "google/gemini-2.0-flash-001", "liquidity_score": 85.0, "source": "seed"},
    {"model_name": "deepseek/deepseek-chat", "liquidity_score": 80.0, "source": "seed"},
    {"model_name": "meta-llama/llama-3.1-8b-instruct", "liquidity_score": 78.0, "source": "seed"},
    {"model_name": "mistralai/mistral-large", "liquidity_score": 76.0, "source": "seed"},
    {"model_name": "x-ai/grok-3-mini", "liquidity_score": 74.0, "source": "seed"},
)

_MODALITY_ADVISORS: dict[str, tuple[str, ...]] = {
    "embeddings": (
        "text-embedding-3-small",
        "text-embedding-3-large",
        "text-embedding-004",
        "amazon.titan-embed-text-v2:0",
    ),
    "rerank": ("rerank-english-v3.0", "rerank-multilingual-v3.0", "voyage-rerank-2"),
    "image": ("gpt-image-1", "dall-e-3", "imagen-3.0-generate-001", "stable-diffusion-xl"),
    "audio": ("whisper-1", "gpt-4o-transcribe", "gpt-4o-mini-tts"),
    "realtime": ("gpt-4o-realtime-preview", "gpt-4o-mini-realtime-preview"),
    "assistants": ("gpt-4o", "gpt-4o-mini", "claude-3-5-sonnet-latest"),
    "fine_tune": ("gpt-4o-mini-2024-07-18", "gpt-3.5-turbo", "gemini-1.5-flash"),
}


def _parse_props(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        data = json.loads(raw or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def live_judge_refine(
    db: Session,
    *,
    prompt_text: str,
    force_live: bool = False,
) -> dict[str, Any]:
    """Item 31: gated live LLM judge refine (simulation-safe by default)."""
    from app.services.gateway_auto_router import classify_prompt_complexity, refine_complexity_with_judge

    readiness = build_inference_readiness(db)
    simulation_enabled = bool(readiness.get("simulation_enabled"))
    env_live = str(os.getenv("GATEWAY_LIVE_JUDGE", "")).strip().lower() in {"1", "true", "yes", "on"}
    allow_live = force_live and env_live and not simulation_enabled

    base = classify_prompt_complexity(prompt_text)
    heuristic = refine_complexity_with_judge(base, prompt_text)

    if not allow_live:
        return {
            "mode": "simulation_safe_heuristic",
            "live_attempted": False,
            "complexity": heuristic,
            "message": (
                "Live LLM judge gated. Set GATEWAY_LIVE_JUDGE=1 and force_live=true "
                "outside simulation to enable; heuristic refine applied."
            ),
        }

    # Live path remains explicitly non-calling here: we record intent + heuristic
    # until a governed provider call path is approved (no silent outbound LLM).
    return {
        "mode": "live_gated_pending_provider_call",
        "live_attempted": True,
        "complexity": {**heuristic, "judge_mode": "live_gated"},
        "message": (
            "Live judge flag accepted; provider LLM judge call is not auto-invoked "
            "without dual-approval wiring. Heuristic refine returned."
        ),
    }


def import_openrouter_liquidity(
    db: Session,
    *,
    use_seed: bool = True,
    models: Optional[list[dict[str, Any]]] = None,
) -> dict[str, Any]:
    """Item 32: external OpenRouter-style liquidity import (offline seed by default)."""
    from app.services.runtime_config import get_runtime_config, upsert_runtime_config_value

    imported: list[dict[str, Any]] = []
    if models:
        for row in models[:100]:
            name = str(row.get("model_name") or row.get("id") or "").strip()
            if not name:
                continue
            imported.append(
                {
                    "model_name": name,
                    "liquidity_score": float(row.get("liquidity_score") or row.get("score") or 50.0),
                    "source": str(row.get("source") or "operator_import"),
                }
            )
    elif use_seed:
        imported = [dict(row) for row in _OPENROUTER_SEED]

    payload = {
        "imported_at": datetime.utcnow().isoformat() + "Z",
        "count": len(imported),
        "models": imported,
        "source": "operator_import" if models else "offline_seed",
    }
    upsert_runtime_config_value(
        db,
        _OPENROUTER_LIQUIDITY_KEY,
        json.dumps(payload, separators=(",", ":")),
        description="OpenRouter-style liquidity import for ranking bias",
    )
    # Merge into ranking view as overlay scores.
    overlay = {
        str(row["model_name"]).split("/")[-1].lower(): float(row["liquidity_score"])
        for row in imported
        if row.get("model_name")
    }
    existing_raw = get_runtime_config(db, _OPENROUTER_LIQUIDITY_KEY, "{}")
    return {**payload, "score_overlay": overlay, "persisted": True, "config_preview": existing_raw[:80]}


def get_openrouter_liquidity(db: Session) -> dict[str, Any]:
    from app.services.runtime_config import get_runtime_config

    raw = get_runtime_config(db, _OPENROUTER_LIQUIDITY_KEY, "")
    if not raw:
        return {"count": 0, "models": [], "source": "none"}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {"count": 0, "models": [], "source": "corrupt"}
    return data if isinstance(data, dict) else {"count": 0, "models": [], "source": "invalid"}


def build_binding_readiness_inventory(db: Session, *, tenant_id: Optional[str] = None) -> dict[str, Any]:
    """Item 33: per-tenant binding readiness inventory."""
    from app.services.provider_credential_bindings import binding_configured

    query = db.query(ProviderCredentialBinding)
    if tenant_id:
        query = query.filter(ProviderCredentialBinding.tenant_id == str(tenant_id).strip())
    bindings = query.order_by(ProviderCredentialBinding.tenant_id.asc()).limit(500).all()
    readiness = build_inference_readiness(db)
    live_types = {
        str(row.get("provider_type") or "").strip().lower()
        for row in readiness.get("providers") or []
        if row.get("live_ready")
    }

    rows = []
    by_tenant: dict[str, Counter] = defaultdict(Counter)
    for binding in bindings:
        configured = bool(binding_configured(db, binding))
        provider = str(binding.provider_type or "").strip().lower()
        live = provider in live_types
        status = "live_ready" if configured and live else ("configured" if configured else "needs_creds")
        rows.append(
            {
                "binding_id": binding.binding_id,
                "tenant_id": binding.tenant_id,
                "provider_type": provider,
                "environment": binding.environment,
                "status": binding.status,
                "configured": configured,
                "live_ready": live,
                "readiness": status,
            }
        )
        by_tenant[str(binding.tenant_id)][status] += 1

    return {
        "count": len(rows),
        "tenant_id": tenant_id,
        "bindings": rows,
        "by_tenant": {tid: dict(counter) for tid, counter in by_tenant.items()},
        "summary": {
            "live_ready": sum(1 for row in rows if row["readiness"] == "live_ready"),
            "configured": sum(1 for row in rows if row["readiness"] == "configured"),
            "needs_creds": sum(1 for row in rows if row["readiness"] == "needs_creds"),
        },
    }


def build_attribution_timeseries(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 34: intended→actual hourly timeseries."""
    window = max(1, min(int(hours or 24), 168))
    start = datetime.utcnow() - timedelta(hours=window)
    events = (
        db.query(CostEvent)
        .filter(CostEvent.timestamp >= start)
        .order_by(CostEvent.timestamp.asc())
        .limit(8000)
        .all()
    )
    buckets: dict[str, dict[str, int]] = defaultdict(
        lambda: {"total": 0, "attributed": 0, "switched": 0, "auto_routed": 0}
    )
    for event in events:
        ts = getattr(event, "timestamp", None) or datetime.utcnow()
        hour_key = ts.replace(minute=0, second=0, microsecond=0).isoformat() + "Z"
        props = _parse_props(getattr(event, "properties_json", None))
        buckets[hour_key]["total"] += 1
        if props.get("intended_model") or props.get("actual_model") or props.get("auto_route_tier"):
            buckets[hour_key]["attributed"] += 1
        if props.get("model_switched"):
            buckets[hour_key]["switched"] += 1
        if props.get("auto_route_tier"):
            buckets[hour_key]["auto_routed"] += 1

    series = [{"hour": key, **buckets[key]} for key in sorted(buckets.keys())]
    return {"hours": window, "points": series, "point_count": len(series)}


def create_auto_route_experiment(
    db: Session,
    *,
    name: str,
    strategies: list[str],
    traffic_split: Optional[dict[str, float]] = None,
) -> dict[str, Any]:
    """Item 35: auto-route A/B experiment records."""
    from app.services.runtime_config import get_runtime_config, upsert_runtime_config_value

    clean_strategies = [str(s).strip().lower() for s in strategies if str(s).strip()]
    clean_strategies = [s for s in clean_strategies if s in {"balanced", "cost", "quality"}] or ["balanced", "cost"]
    split = traffic_split or {s: round(1.0 / len(clean_strategies), 4) for s in clean_strategies}
    experiment = {
        "experiment_id": f"ab-{uuid4().hex[:10]}",
        "name": str(name or "auto-route-ab").strip()[:128],
        "strategies": clean_strategies,
        "traffic_split": split,
        "status": "active",
        "created_at": datetime.utcnow().isoformat() + "Z",
        "observations": 0,
    }
    raw = get_runtime_config(db, _EXPERIMENT_KEY, "[]")
    try:
        history = json.loads(raw or "[]")
    except json.JSONDecodeError:
        history = []
    if not isinstance(history, list):
        history = []
    history.insert(0, experiment)
    history = history[:50]
    upsert_runtime_config_value(
        db,
        _EXPERIMENT_KEY,
        json.dumps(history, separators=(",", ":")),
        description="Auto-route A/B experiment records",
    )
    return {"experiment": experiment, "count": len(history)}


def list_auto_route_experiments(db: Session, *, limit: int = 20) -> dict[str, Any]:
    from app.services.runtime_config import get_runtime_config

    raw = get_runtime_config(db, _EXPERIMENT_KEY, "[]")
    try:
        history = json.loads(raw or "[]")
    except json.JSONDecodeError:
        history = []
    if not isinstance(history, list):
        history = []
    clipped = history[: max(1, min(int(limit or 20), 50))]
    return {"count": len(clipped), "experiments": clipped}


def evaluate_fallback_quality_gate(
    db: Session,
    *,
    min_live_ready: int = 2,
    min_leadership_score: float = 60.0,
) -> dict[str, Any]:
    """Item 36: fallback quality gate before promote."""
    from app.services.gateway_leadership import build_gateway_leadership_index
    from app.services.gateway_best_practices import suggest_readiness_aware_fallback_chain

    suggestion = suggest_readiness_aware_fallback_chain(db, max_hops=3, prefer_live_only=True)
    index = build_gateway_leadership_index(db, hours=24, exclude_warmup=True)
    live_count = int(suggestion.get("live_ready_count") or len(suggestion.get("priority_order") or []))
    score = float(index.get("score") or 0)
    checks = [
        {
            "id": "min_live_ready",
            "passed": live_count >= int(min_live_ready),
            "actual": live_count,
            "threshold": min_live_ready,
        },
        {
            "id": "min_leadership_score",
            "passed": score >= float(min_leadership_score),
            "actual": score,
            "threshold": min_leadership_score,
        },
        {
            "id": "chain_nonempty",
            "passed": bool(suggestion.get("priority_order")),
            "actual": len(suggestion.get("priority_order") or []),
            "threshold": 1,
        },
    ]
    passed = all(row["passed"] for row in checks)
    return {
        "passed": passed,
        "decision": "promote_allowed" if passed else "hold",
        "checks": checks,
        "priority_order": suggestion.get("priority_order") or [],
        "leadership_score": score,
        "message": "Quality gate passed." if passed else "Quality gate blocked promote — resolve failed checks.",
    }


def build_provider_health_scores(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 37: provider health score from hop failures."""
    breakers = build_circuit_breaker_recommendations(db, hours=hours)
    window_start = datetime.utcnow() - timedelta(hours=max(1, min(hours, 168)))
    events = (
        db.query(CostEvent)
        .filter(CostEvent.timestamp >= window_start)
        .order_by(CostEvent.timestamp.desc())
        .limit(5000)
        .all()
    )
    totals: Counter[str] = Counter()
    fails: Counter[str] = Counter()
    for event in events:
        props = _parse_props(getattr(event, "properties_json", None))
        provider_id = str(props.get("selected_provider_id") or "").strip()
        if not provider_id:
            continue
        totals[provider_id] += 1
        outcome = str(props.get("outcome") or "").strip().lower()
        if outcome in {"failed_simulated", "failed_timeout", "budget_blocked", "retry_policy_blocked"}:
            fails[provider_id] += 1

    scores = []
    for provider_id, total in totals.most_common(30):
        fail_n = fails.get(provider_id, 0)
        success_rate = 1.0 - (fail_n / total if total else 0.0)
        score = round(max(0.0, min(100.0, success_rate * 100.0)), 2)
        scores.append(
            {
                "provider_id": provider_id,
                "events": total,
                "failure_events": fail_n,
                "health_score": score,
                "band": "healthy" if score >= 85 else ("watch" if score >= 70 else "degraded"),
            }
        )
    return {
        "hours": hours,
        "providers": scores,
        "circuit_breaker_recommendations": breakers.get("recommendations") or [],
    }


def build_streaming_auto_route_frames(
    db: Session,
    *,
    prompt_text: str,
    strategy: str = "balanced",
) -> dict[str, Any]:
    """Item 43: streaming auto-route metadata frames for progressive UI."""
    from app.services.gateway_auto_router import build_auto_route_decision

    frames = [
        {"frame": 1, "event": "classify.start", "data": {"prompt_preview": str(prompt_text or "")[:80]}},
    ]
    decision = build_auto_route_decision(
        db,
        prompt_text=prompt_text,
        strategy=strategy,
        prefer_live_only=True,
        use_telemetry_ranking=True,
    )
    frames.append(
        {
            "frame": 2,
            "event": "classify.complexity",
            "data": decision.get("complexity") or {},
        }
    )
    frames.append(
        {
            "frame": 3,
            "event": "route.candidates",
            "data": {"tier_candidates": decision.get("tier_candidates") or {}},
        }
    )
    frames.append(
        {
            "frame": 4,
            "event": "route.selected",
            "data": {
                "selected_model": decision.get("selected_model"),
                "selected_provider_type": decision.get("selected_provider_type"),
                "strategy": decision.get("strategy"),
                "rationale": decision.get("rationale"),
            },
        }
    )
    frames.append({"frame": 5, "event": "classify.done", "data": {"ok": True}})
    return {"frames": frames, "frame_count": len(frames), "decision": decision}


def advise_modality_models(db: Session, *, modality: str) -> dict[str, Any]:
    """Items 45–51 advisors (embeddings/rerank/image/audio/realtime/assistants/fine_tune)."""
    key = str(modality or "").strip().lower().replace("-", "_")
    aliases = {
        "embedding": "embeddings",
        "embeddings": "embeddings",
        "rerank": "rerank",
        "image": "image",
        "audio": "audio",
        "realtime": "realtime",
        "assistants": "assistants",
        "fine_tune": "fine_tune",
        "finetune": "fine_tune",
    }
    modality_key = aliases.get(key, key)
    preferred = _MODALITY_ADVISORS.get(modality_key)
    if not preferred:
        return {
            "modality": modality_key,
            "supported": False,
            "message": f"Unknown modality '{modality}'. Supported: {sorted(_MODALITY_ADVISORS)}",
            "recommendations": [],
        }

    catalog = {
        str(row.model_name or "").strip().lower(): str(row.provider_type or "").strip().lower()
        for row in db.query(SupportedModelCatalogEntry)
        .filter(SupportedModelCatalogEntry.status.in_(("active", "beta")))
        .all()
        if row.model_name
    }
    readiness = build_inference_readiness(db)
    live = {
        str(row.get("provider_type") or "").strip().lower()
        for row in readiness.get("providers") or []
        if row.get("live_ready")
    }
    recommendations = []
    for model in preferred:
        provider = catalog.get(model.lower())
        in_catalog = provider is not None
        recommendations.append(
            {
                "model_name": model,
                "provider_type": provider,
                "in_catalog": in_catalog,
                "live_ready": bool(provider and provider in live),
            }
        )
    return {
        "modality": modality_key,
        "supported": True,
        "recommendations": recommendations,
        "message": f"Advisor recommendations for {modality_key}.",
    }


def explain_auto_route_decision(
    db: Session,
    *,
    prompt_text: str,
    strategy: str = "balanced",
    max_budget_tier: Optional[str] = None,
    latency_slo_ms: Optional[int] = None,
    allowed_regions: Optional[list[str]] = None,
    tools_json: Optional[list[dict[str, Any]]] = None,
    attachment_types: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Items 38–42 + 77-lite: budget/latency/region/tool/multimodal aware explain card."""
    from app.services.gateway_auto_router import build_auto_route_decision

    has_tools = bool(tools_json)
    tool_schema_signals = []
    if tools_json:
        for tool in tools_json[:20]:
            name = str((tool or {}).get("function", {}).get("name") or (tool or {}).get("name") or "").strip()
            params = (tool or {}).get("function", {}).get("parameters") or (tool or {}).get("parameters")
            if name:
                tool_schema_signals.append(name)
            if isinstance(params, dict) and params.get("properties"):
                tool_schema_signals.append(f"schema:{name or 'anon'}")

    multimodal = [str(t).strip().lower() for t in (attachment_types or []) if str(t).strip()]
    decision = build_auto_route_decision(
        db,
        prompt_text=prompt_text,
        strategy=strategy,
        prefer_live_only=True,
        has_tools=has_tools or bool(tool_schema_signals),
        use_telemetry_ranking=True,
        max_budget_tier=max_budget_tier,
        latency_slo_ms=latency_slo_ms,
        allowed_regions=allowed_regions,
        attachment_types=multimodal,
    )
    complexity = dict(decision.get("complexity") or {})
    if tool_schema_signals:
        complexity["signals"] = list(complexity.get("signals") or []) + [
            f"tool_schema:{len(tool_schema_signals)}"
        ]
    if multimodal:
        complexity["signals"] = list(complexity.get("signals") or []) + [
            f"multimodal:{','.join(multimodal[:5])}"
        ]
    return {
        "why_this_model": decision.get("rationale"),
        "selected_model": decision.get("selected_model"),
        "complexity": complexity,
        "constraints": {
            "max_budget_tier": max_budget_tier,
            "latency_slo_ms": latency_slo_ms,
            "allowed_regions": allowed_regions or [],
            "tools": tool_schema_signals,
            "attachments": multimodal,
        },
        "decision": decision,
    }


def pack6_capability_manifest() -> dict[str, Any]:
    return {
        "pack": 6,
        "items": list(range(31, 46)),
        "endpoints": [
            "POST /gateway/best-practices/live-judge-refine",
            "POST /gateway/best-practices/openrouter-liquidity-import",
            "GET /gateway/best-practices/openrouter-liquidity",
            "GET /gateway/best-practices/binding-readiness-inventory",
            "GET /gateway/best-practices/attribution-timeseries",
            "POST /gateway/best-practices/auto-route-experiments",
            "GET /gateway/best-practices/auto-route-experiments",
            "POST /gateway/best-practices/fallback-quality-gate",
            "GET /gateway/best-practices/provider-health-scores",
            "POST /gateway/best-practices/auto-route-stream-frames",
            "POST /gateway/best-practices/auto-route-explain",
            "GET /gateway/best-practices/modality-advisor",
        ],
    }
