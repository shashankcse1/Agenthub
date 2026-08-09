"""Pack 7 leadership capabilities (backlog items 52–70)."""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import CostEvent, PromptRegistryItem, RouteDraft, RoutePolicy, VirtualKey
from app.services.gateway_leadership import (
    build_attribution_analytics,
    build_gateway_leadership_index,
    build_model_liquidity_ranking,
    export_leadership_evidence_pack,
)
from app.services.inference_readiness import build_inference_readiness


_PROMPT_BIND_KEY = "gateway.leadership.prompt_auto_route_bindings_json"
_VK_POLICY_KEY = "gateway.leadership.virtual_key_auto_route_policies_json"
_ALERT_CHANNELS_KEY = "gateway.leadership.alert_channels_json"
_WEBHOOK_DISPATCH_KEY = "gateway.leadership.alert_dispatch_log_json"


def _rt_get(db: Session, key: str, default: str = "[]") -> Any:
    from app.services.runtime_config import get_runtime_config

    raw = get_runtime_config(db, key, default)
    try:
        return json.loads(raw or default)
    except json.JSONDecodeError:
        return json.loads(default)


def _rt_set(db: Session, key: str, value: Any, description: str) -> None:
    from app.services.runtime_config import upsert_runtime_config_value

    upsert_runtime_config_value(
        db,
        key,
        json.dumps(value, separators=(",", ":")),
        description=description,
    )


def bind_prompt_registry_auto_route(
    db: Session,
    *,
    prompt_registry_id: str,
    strategy: str = "balanced",
    prefer_live_only: bool = True,
    max_budget_tier: Optional[str] = None,
) -> dict[str, Any]:
    """Item 52: prompt registry ↔ auto-route binding."""
    prompt_id = str(prompt_registry_id or "").strip()
    item = db.query(PromptRegistryItem).filter_by(prompt_registry_id=prompt_id).first()
    if not item:
        # Allow binding by name lookup
        item = db.query(PromptRegistryItem).filter_by(name=prompt_id).first()
    if not item:
        return {
            "bound": False,
            "message": f"Prompt registry item '{prompt_id}' not found.",
        }

    from app.services.gateway_auto_router import build_auto_route_decision

    decision = build_auto_route_decision(
        db,
        prompt_text=str(item.prompt_text or ""),
        strategy=strategy,
        prefer_live_only=prefer_live_only,
        max_budget_tier=max_budget_tier,
    )
    binding = {
        "binding_id": f"prb-{uuid4().hex[:10]}",
        "prompt_registry_id": item.prompt_registry_id,
        "prompt_name": item.name,
        "strategy": strategy,
        "prefer_live_only": prefer_live_only,
        "max_budget_tier": max_budget_tier,
        "recommended_model": decision.get("selected_model"),
        "tier": (decision.get("complexity") or {}).get("tier"),
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    rows = _rt_get(db, _PROMPT_BIND_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    rows = [row for row in rows if row.get("prompt_registry_id") != item.prompt_registry_id]
    rows.insert(0, binding)
    _rt_set(db, _PROMPT_BIND_KEY, rows[:100], "Prompt registry auto-route bindings")
    return {"bound": True, "binding": binding, "count": len(rows)}


def list_prompt_auto_route_bindings(db: Session, *, limit: int = 50) -> dict[str, Any]:
    rows = _rt_get(db, _PROMPT_BIND_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    clipped = rows[: max(1, min(int(limit or 50), 100))]
    return {"count": len(clipped), "bindings": clipped}


def recommend_route_draft_auto_route(db: Session, *, draft_id: str) -> dict[str, Any]:
    """Item 53: route-draft auto-route recommendation."""
    draft = db.query(RouteDraft).filter_by(draft_id=str(draft_id or "").strip()).first()
    if not draft:
        return {"found": False, "message": "Route draft not found."}

    prompt = (
        f"Recommend routing for agent {draft.agent_id} in {draft.environment} "
        f"with draft status {draft.status}. Prefer reliable multi-provider failover."
    )
    from app.services.gateway_auto_router import build_auto_route_decision
    from app.services.gateway_best_practices import suggest_readiness_aware_fallback_chain

    decision = build_auto_route_decision(db, prompt_text=prompt, strategy="balanced", prefer_live_only=True)
    chain = suggest_readiness_aware_fallback_chain(db, max_hops=3, prefer_live_only=True)
    return {
        "found": True,
        "draft_id": draft.draft_id,
        "agent_id": draft.agent_id,
        "environment": draft.environment,
        "status": draft.status,
        "recommended_model": decision.get("selected_model"),
        "complexity": decision.get("complexity"),
        "fallback_priority_order": chain.get("priority_order") or [],
        "rationale": decision.get("rationale"),
    }


def explain_canary_auto_route_interaction(
    db: Session,
    *,
    route_policy_id: str,
    prompt_text: str = "Canary auto-route interaction sample",
) -> dict[str, Any]:
    """Item 54: canary + auto-route interaction explain."""
    route = db.query(RoutePolicy).filter_by(route_policy_id=str(route_policy_id or "").strip()).first()
    if not route:
        return {"found": False, "message": "Route policy not found."}

    canary: dict[str, Any] = {}
    try:
        canary = json.loads(getattr(route, "fallback_policy", None) or "{}")
    except json.JSONDecodeError:
        canary = {}
    if not isinstance(canary, dict):
        canary = {}
    nested = canary.get("canary_rollout") if isinstance(canary.get("canary_rollout"), dict) else {}
    canary_enabled = bool(nested.get("enabled") or canary.get("canary_enabled") or canary.get("enabled"))

    from app.services.gateway_auto_router import build_auto_route_decision

    decision = build_auto_route_decision(db, prompt_text=prompt_text, strategy="balanced")
    return {
        "found": True,
        "route_policy_id": route.route_policy_id,
        "canary_enabled": canary_enabled,
        "canary_summary": {
            "weight": nested.get("weight") or canary.get("weight"),
            "status": nested.get("status") or canary.get("status"),
        },
        "auto_route": {
            "selected_model": decision.get("selected_model"),
            "tier": (decision.get("complexity") or {}).get("tier"),
            "strategy": decision.get("strategy"),
        },
        "interaction": (
            "Canary weight applies after auto-route model selection; keep canary cohort on the "
            "same tier model family to avoid attribution skew."
            if canary_enabled
            else "No active canary; auto-route decision applies directly to primary route."
        ),
    }


def build_mirror_attribution_tags(
    db: Session,
    *,
    route_policy_id: Optional[str] = None,
    hours: int = 24,
) -> dict[str, Any]:
    """Item 55: mirror traffic attribution tags."""
    window_start = datetime.utcnow() - timedelta(hours=max(1, min(hours, 168)))
    events = (
        db.query(CostEvent)
        .filter(CostEvent.timestamp >= window_start)
        .order_by(CostEvent.timestamp.desc())
        .limit(4000)
        .all()
    )
    tags: Counter[str] = Counter()
    mirror_events = 0
    for event in events:
        try:
            props = json.loads(getattr(event, "properties_json", None) or "{}")
        except json.JSONDecodeError:
            props = {}
        if not isinstance(props, dict):
            continue
        if route_policy_id and str(props.get("route_policy_id") or "") != str(route_policy_id):
            continue
        mode = str(props.get("mirror_mode") or props.get("traffic_mirror_mode") or "").strip()
        if mode or props.get("mirrored") or props.get("mirror_events_count"):
            mirror_events += 1
            tags[mode or "mirrored"] += 1
            if props.get("auto_route_tier"):
                tags[f"auto_route:{props.get('auto_route_tier')}"] += 1
    return {
        "hours": hours,
        "route_policy_id": route_policy_id,
        "mirror_events": mirror_events,
        "tags": [{"tag": k, "events": v} for k, v in tags.most_common(20)],
        "message": "Mirror attribution tags derived from CostEvent properties.",
    }


def build_cache_auto_route_metrics(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 56: cache hit vs auto-route interaction metrics."""
    window_start = datetime.utcnow() - timedelta(hours=max(1, min(hours, 168)))
    events = (
        db.query(CostEvent)
        .filter(CostEvent.timestamp >= window_start)
        .order_by(CostEvent.timestamp.desc())
        .limit(5000)
        .all()
    )
    cache_hits = 0
    auto_routed = 0
    both = 0
    for event in events:
        try:
            props = json.loads(getattr(event, "properties_json", None) or "{}")
        except json.JSONDecodeError:
            props = {}
        if not isinstance(props, dict):
            continue
        hit = bool(props.get("cache_hit") or props.get("cache_short_circuit"))
        routed = bool(props.get("auto_route_tier"))
        if hit:
            cache_hits += 1
        if routed:
            auto_routed += 1
        if hit and routed:
            both += 1
    total = len(events)
    return {
        "hours": hours,
        "total_events": total,
        "cache_hits": cache_hits,
        "auto_routed_events": auto_routed,
        "cache_and_auto_routed": both,
        "cache_hit_rate_percent": round((cache_hits / total) * 100, 2) if total else 0.0,
        "auto_route_rate_percent": round((auto_routed / total) * 100, 2) if total else 0.0,
        "note": "Cache short-circuit still records intended→actual when auto_route was applied pre-cache.",
    }


def upsert_virtual_key_auto_route_policy(
    db: Session,
    *,
    virtual_key_id: str,
    strategy: str = "balanced",
    prefer_live_only: bool = True,
    max_budget_tier: Optional[str] = None,
    enabled: bool = True,
) -> dict[str, Any]:
    """Item 57: virtual-key scoped auto-route policy."""
    key_id = str(virtual_key_id or "").strip()
    vk = db.query(VirtualKey).filter_by(key_id=key_id).first() if key_id else None
    policy = {
        "virtual_key_id": key_id,
        "exists": bool(vk),
        "enabled": bool(enabled),
        "strategy": strategy,
        "prefer_live_only": prefer_live_only,
        "max_budget_tier": max_budget_tier,
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    rows = _rt_get(db, _VK_POLICY_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    rows = [row for row in rows if row.get("virtual_key_id") != key_id]
    rows.insert(0, policy)
    _rt_set(db, _VK_POLICY_KEY, rows[:200], "Virtual-key scoped auto-route policies")
    return {"policy": policy, "count": len(rows)}


def list_virtual_key_auto_route_policies(db: Session, *, limit: int = 50) -> dict[str, Any]:
    rows = _rt_get(db, _VK_POLICY_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    clipped = rows[: max(1, min(int(limit or 50), 200))]
    return {"count": len(clipped), "policies": clipped}


def build_team_ranking_leaderboard(
    db: Session,
    *,
    hours: int = 168,
    owner_scope_prefix: Optional[str] = None,
    limit: int = 20,
) -> dict[str, Any]:
    """Item 58: team-scoped ranking leaderboards."""
    window_start = datetime.utcnow() - timedelta(hours=max(1, min(hours, 168)))
    events = (
        db.query(CostEvent)
        .filter(CostEvent.timestamp >= window_start)
        .order_by(CostEvent.timestamp.desc())
        .limit(8000)
        .all()
    )
    by_scope: dict[str, Counter] = defaultdict(Counter)
    for event in events:
        scope = str(getattr(event, "owner_scope", None) or "unscoped").strip() or "unscoped"
        if owner_scope_prefix and not scope.startswith(str(owner_scope_prefix)):
            continue
        model = str(getattr(event, "model_name", None) or "unknown").strip() or "unknown"
        by_scope[scope][model] += 1

    boards = []
    for scope, counter in sorted(by_scope.items(), key=lambda kv: sum(kv[1].values()), reverse=True):
        top = [{"model_name": m, "events": n} for m, n in counter.most_common(5)]
        boards.append({"owner_scope": scope, "events": sum(counter.values()), "top_models": top})
        if len(boards) >= max(1, min(int(limit or 20), 50)):
            break
    return {"hours": hours, "leaderboards": boards, "count": len(boards)}


def build_environment_diff_leadership(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 59: environment-diff leadership score."""
    envs = ("dev", "staging", "prod")
    scores = {}
    for env in envs:
        # Leadership index is env-agnostic today; approximate via attribution filter on properties.
        attribution = build_attribution_analytics(db, hours=hours, exclude_warmup=True)
        # Soft env signal: count events with matching environment property if present.
        window_start = datetime.utcnow() - timedelta(hours=max(1, min(hours, 168)))
        events = (
            db.query(CostEvent)
            .filter(CostEvent.timestamp >= window_start)
            .limit(3000)
            .all()
        )
        env_events = 0
        for event in events:
            try:
                props = json.loads(getattr(event, "properties_json", None) or "{}")
            except json.JSONDecodeError:
                props = {}
            if str(props.get("environment") or getattr(event, "environment", "") or "").lower() == env:
                env_events += 1
        index = build_gateway_leadership_index(db, hours=hours, exclude_warmup=True)
        # Scale score slightly by env traffic presence for operator diffing.
        adjusted = float(index.get("score") or 0)
        if env_events == 0:
            adjusted = round(adjusted * 0.7, 2)
        scores[env] = {
            "score": adjusted,
            "band": index.get("band"),
            "env_events": env_events,
            "attribution_coverage_percent": attribution.get("attribution_coverage_percent"),
        }
    ordered = sorted(scores.items(), key=lambda kv: kv[1]["score"], reverse=True)
    return {
        "hours": hours,
        "environments": scores,
        "leader_environment": ordered[0][0] if ordered else None,
        "message": "Environment-diff leadership uses score + env-tagged traffic presence.",
    }


def upsert_alert_channels(
    db: Session,
    *,
    webhook_url: Optional[str] = None,
    slack_webhook_url: Optional[str] = None,
    email_to: Optional[str] = None,
    enabled: bool = True,
) -> dict[str, Any]:
    """Items 61–62: webhook/slack/email notify channel config."""
    config = {
        "enabled": bool(enabled),
        "webhook_url": (webhook_url or "").strip() or None,
        "slack_webhook_url": (slack_webhook_url or "").strip() or None,
        "email_to": (email_to or "").strip() or None,
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    _rt_set(db, _ALERT_CHANNELS_KEY, config, "Leadership alert notify channels")
    return {"channels": config}


def get_alert_channels(db: Session) -> dict[str, Any]:
    raw = _rt_get(db, _ALERT_CHANNELS_KEY, "{}")
    if not isinstance(raw, dict):
        raw = {}
    return {"channels": raw}


def evaluate_and_queue_leadership_alerts(
    db: Session,
    *,
    hours: int = 24,
    floor_score: float = 70.0,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Item 61: webhook alert on leadership drop (queued, dry-run by default)."""
    from app.services.gateway_leadership import build_leadership_alerts

    alerts = build_leadership_alerts(db, hours=hours, floor_score=floor_score)
    channels = get_alert_channels(db).get("channels") or {}
    dispatch = {
        "dispatch_id": f"ald-{uuid4().hex[:10]}",
        "queued_at": datetime.utcnow().isoformat() + "Z",
        "dry_run": bool(dry_run),
        "alert_count": alerts.get("alert_count"),
        "alerts": alerts.get("alerts") or [],
        "channels_configured": bool(
            channels.get("webhook_url") or channels.get("slack_webhook_url") or channels.get("email_to")
        ),
        "delivery": "queued_dry_run" if dry_run else "queued_for_worker",
        "message": (
            "Alerts evaluated; outbound delivery is dry-run unless dry_run=false and channels are configured."
        ),
    }
    log = _rt_get(db, _WEBHOOK_DISPATCH_KEY, "[]")
    if not isinstance(log, list):
        log = []
    log.insert(0, dispatch)
    _rt_set(db, _WEBHOOK_DISPATCH_KEY, log[:100], "Leadership alert dispatch log")
    return dispatch


def build_qbr_leadership_embed(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 63: QBR embed of leadership index."""
    index = build_gateway_leadership_index(db, hours=hours, exclude_warmup=True)
    attribution = build_attribution_analytics(db, hours=hours, exclude_warmup=True)
    rankings = build_model_liquidity_ranking(db, hours=max(24, hours), limit=5)
    return {
        "embed_type": "qbr_leadership_card",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "score": index.get("score"),
        "band": index.get("band"),
        "market_claim": index.get("market_claim"),
        "attribution_coverage_percent": attribution.get("attribution_coverage_percent"),
        "top_models": (rankings.get("models") or [])[:5],
        "next_actions": index.get("next_actions") or [],
        "html_snippet": (
            f"<div class='agenthub-qbr-leadership'>"
            f"<strong>Leadership {index.get('score')}/100</strong> "
            f"({index.get('band')}) · attribution "
            f"{attribution.get('attribution_coverage_percent')}%</div>"
        ),
    }


def build_compliance_leadership_evidence(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 64: compliance evidence include leadership pack."""
    pack = export_leadership_evidence_pack(db, hours=hours, exclude_warmup=True)
    return {
        "compliance_artifact": True,
        "control_refs": [
            "AI-GOV-ROUTE-ATTRIBUTION",
            "AI-GOV-LEADERSHIP-INDEX",
            "AI-GOV-FALLBACK-READINESS",
        ],
        "exported_at": pack.get("exported_at"),
        "leadership_pack": pack,
        "retention_hint": "Retain with audit export for the same compliance window.",
    }


def build_otel_attribution_attributes(
    *,
    intended_model: str,
    actual_model: str,
    auto_route_tier: Optional[str] = None,
    strategy: Optional[str] = None,
    trace_id: Optional[str] = None,
) -> dict[str, Any]:
    """Item 67: OpenTelemetry span attributes for attribution."""
    switched = str(intended_model or "").strip().lower() != str(actual_model or "").strip().lower()
    attrs = {
        "gen_ai.system": "agenthub-gateway",
        "agenthub.model.intended": intended_model,
        "agenthub.model.actual": actual_model,
        "agenthub.model.switched": switched,
        "agenthub.auto_route.tier": auto_route_tier,
        "agenthub.auto_route.strategy": strategy,
        "agenthub.trace_id": trace_id,
    }
    return {"span_attributes": {k: v for k, v in attrs.items() if v is not None}, "semantic_conventions": "agenthub.v1"}


def build_prometheus_leadership_metrics(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 68: Prometheus metrics exporter for leadership."""
    index = build_gateway_leadership_index(db, hours=hours, exclude_warmup=True)
    attribution = build_attribution_analytics(db, hours=hours, exclude_warmup=True)
    lines = [
        "# HELP agenthub_leadership_score Composite gateway leadership score (0-100).",
        "# TYPE agenthub_leadership_score gauge",
        f"agenthub_leadership_score {float(index.get('score') or 0)}",
        "# HELP agenthub_attribution_coverage_percent Share of events with intended/actual attribution.",
        "# TYPE agenthub_attribution_coverage_percent gauge",
        f"agenthub_attribution_coverage_percent {float(attribution.get('attribution_coverage_percent') or 0)}",
        "# HELP agenthub_auto_routed_events_total Auto-routed events in window.",
        "# TYPE agenthub_auto_routed_events_total gauge",
        f"agenthub_auto_routed_events_total {int(attribution.get('auto_routed_events') or 0)}",
        "# HELP agenthub_model_switch_rate_percent Intended→actual switch rate.",
        "# TYPE agenthub_model_switch_rate_percent gauge",
        f"agenthub_model_switch_rate_percent {float(attribution.get('switch_rate_percent') or 0)}",
    ]
    return {
        "content_type": "text/plain; version=0.0.4",
        "hours": hours,
        "metrics_text": "\n".join(lines) + "\n",
        "metric_names": [
            "agenthub_leadership_score",
            "agenthub_attribution_coverage_percent",
            "agenthub_auto_routed_events_total",
            "agenthub_model_switch_rate_percent",
        ],
    }


def build_grafana_dashboard_json(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 69: Grafana dashboard JSON export."""
    metrics = build_prometheus_leadership_metrics(db, hours=hours)
    dashboard = {
        "uid": "agenthub-leadership",
        "title": "AgentHub Gateway Leadership",
        "timezone": "browser",
        "schemaVersion": 39,
        "version": 1,
        "panels": [
            {
                "id": 1,
                "type": "stat",
                "title": "Leadership Score",
                "targets": [{"expr": "agenthub_leadership_score"}],
                "gridPos": {"h": 4, "w": 6, "x": 0, "y": 0},
            },
            {
                "id": 2,
                "type": "timeseries",
                "title": "Attribution Coverage %",
                "targets": [{"expr": "agenthub_attribution_coverage_percent"}],
                "gridPos": {"h": 8, "w": 12, "x": 6, "y": 0},
            },
            {
                "id": 3,
                "type": "timeseries",
                "title": "Auto-routed Events",
                "targets": [{"expr": "agenthub_auto_routed_events_total"}],
                "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
            },
        ],
        "annotations": {"list": []},
        "templating": {"list": []},
    }
    return {
        "dashboard": dashboard,
        "meta": {"exported_at": datetime.utcnow().isoformat() + "Z", "hours": hours},
        "prometheus_metric_names": metrics.get("metric_names"),
    }


def build_datadog_marketplace_notes() -> dict[str, Any]:
    """Item 70: Datadog marketplace tile notes."""
    return {
        "tile": "AgentHub AI Gateway Leadership",
        "summary": (
            "Governance control plane metrics for multi-provider routing leadership: "
            "composite score, attribution coverage, auto-route volume, and switch rate."
        ),
        "metrics": [
            "agenthub.leadership.score",
            "agenthub.attribution.coverage_percent",
            "agenthub.auto_route.events",
            "agenthub.model.switch_rate_percent",
        ],
        "setup": [
            "Scrape GET /gateway/best-practices/prometheus-metrics (or bridge to Datadog agent).",
            "Import Grafana JSON from GET /gateway/best-practices/grafana-dashboard as a starting dashboard.",
            "Map agenthub_* Prometheus names to agenthub.* Datadog metric names in the integration tile.",
        ],
        "security": "Read role: Auditor/AI Ops. No secrets in tile config; use existing gateway auth.",
    }


def sdk_auto_route_helper_contract() -> dict[str, Any]:
    """Items 65–66: document SDK helper contract (implemented in sdk/)."""
    return {
        "python": {
            "module": "sdk/python/agenthub_gateway.py",
            "methods": ["auto_route_classify", "chat_completions(auto_route=True)"],
        },
        "javascript": {
            "module": "sdk/js/src/index.js",
            "methods": ["autoRouteClassify", "chatCompletions({ auto_route: true })"],
        },
        "endpoint": "POST /gateway/best-practices/auto-route",
    }


def sign_share_token(payload: dict[str, Any], *, secret: str, ttl_seconds: int = 3600) -> dict[str, Any]:
    """Helper used by later packs; kept here for QBR/compliance share links."""
    body = {
        **payload,
        "exp": int(time.time()) + max(60, min(int(ttl_seconds), 86400)),
        "nonce": uuid4().hex[:8],
    }
    raw = json.dumps(body, separators=(",", ":"), sort_keys=True)
    sig = hmac.new(secret.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()
    return {"token": f"{raw}.{sig}", "expires_at": body["exp"]}
