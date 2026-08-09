"""Pack 8–9 leadership capabilities (backlog items 71–100)."""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import json
import os
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import CostEvent, RoutePolicy, SupportedModelCatalogEntry
from app.services.gateway_leadership import (
    build_attribution_analytics,
    build_gateway_leadership_index,
    build_model_liquidity_ranking,
    export_leadership_evidence_pack,
    list_leadership_history,
    record_leadership_snapshot,
)
from app.services.inference_readiness import build_inference_readiness


_RANKING_WEIGHTS_KEY = "gateway.leadership.ranking_weights_json"
_JUDGE_THRESHOLDS_KEY = "gateway.leadership.judge_thresholds_json"
_ROUTE_STRATEGY_KEY = "gateway.leadership.route_strategy_policies_json"
_TAG_STRATEGY_KEY = "gateway.leadership.request_tag_strategy_policies_json"
_WARMUP_RETENTION_KEY = "gateway.leadership.warmup_retention_json"
_SHARE_LINKS_KEY = "gateway.leadership.auditor_share_links_json"
_SCORECARD_KEY = "gateway.leadership.competitive_scorecard_json"
_DEFAULT_SHARE_SECRET = "agenthub-leadership-share-dev-only"


def _rt_get(db: Session, key: str, default: str = "{}") -> Any:
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


def _parse_props(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    try:
        data = json.loads(raw or "{}")
    except (TypeError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def advise_model_deprecations(db: Session, *, hours: int = 168, min_events: int = 3) -> dict[str, Any]:
    """Item 71: model deprecation advisor from rankings."""
    rankings = build_model_liquidity_ranking(db, hours=hours, limit=100)
    models = list(rankings.get("models") or [])
    advice = []
    for row in models:
        events = int(row.get("events") or 0)
        score = float(row.get("score") or 0)
        if events < min_events:
            continue
        if score < 15:
            advice.append(
                {
                    "model_name": row.get("model_name"),
                    "score": score,
                    "events": events,
                    "action": "consider_deprecate_or_demote",
                    "reason": "Low liquidity/stability score relative to peers.",
                }
            )
    return {
        "hours": hours,
        "recommendations": advice[:25],
        "count": len(advice[:25]),
        "message": "Deprecation advice is advisory; operators confirm before catalog changes.",
    }


def validate_shadow_traffic_rankings(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 72: shadow-traffic ranking validation."""
    window_start = datetime.utcnow() - timedelta(hours=max(1, min(hours, 168)))
    events = (
        db.query(CostEvent)
        .filter(CostEvent.timestamp >= window_start)
        .order_by(CostEvent.timestamp.desc())
        .limit(5000)
        .all()
    )
    primary: Counter[str] = Counter()
    shadow: Counter[str] = Counter()
    for event in events:
        props = _parse_props(getattr(event, "properties_json", None))
        model = str(getattr(event, "model_name", None) or props.get("actual_model") or "").strip()
        if not model:
            continue
        if props.get("mirrored") or props.get("mirror_mode") or props.get("shadow"):
            shadow[model] += 1
        else:
            primary[model] += 1
    rankings = build_model_liquidity_ranking(db, hours=max(24, hours), limit=20)
    top = [str(row.get("model_name") or "") for row in (rankings.get("models") or [])[:5]]
    shadow_top = [m for m, _ in shadow.most_common(5)]
    overlap = sorted(set(top) & set(shadow_top))
    return {
        "hours": hours,
        "primary_top": [m for m, _ in primary.most_common(5)],
        "shadow_top": shadow_top,
        "ranking_top": top,
        "overlap_models": overlap,
        "validated": len(overlap) >= 1 or not shadow,
        "message": (
            "Shadow and ranking tops overlap."
            if overlap
            else "No shadow overlap yet — run mirror traffic or accept ranking-only validation."
        ),
    }


def apply_adversarial_tier_hard_boost(prompt_text: str, complexity: dict[str, Any]) -> dict[str, Any]:
    """Item 73: adversarial prompt tier hard-boost policy."""
    lower = str(prompt_text or "").lower()
    boosted = dict(complexity or {})
    signals = list(boosted.get("signals") or [])
    score = int(boosted.get("score") or 0)
    triggers = (
        "ignore previous",
        "jailbreak",
        "dan mode",
        "bypass safety",
        "exfiltrate",
        "system prompt",
    )
    hits = [t for t in triggers if t in lower]
    if hits:
        score = max(score, 55)
        signals.extend([f"adversarial_hard_boost:{h.replace(' ', '_')}" for h in hits[:3]])
        boosted.update({"tier": "complex", "score": score, "signals": signals, "adversarial_boost": True})
    else:
        boosted["adversarial_boost"] = False
    return boosted


def pii_aware_routing_bias(prompt_text: str) -> dict[str, Any]:
    """Item 74: PII-aware model routing bias."""
    text = str(prompt_text or "")
    signals = []
    if "@" in text and "." in text:
        signals.append("email_like")
    if any(ch.isdigit() for ch in text) and ("ssn" in text.lower() or "social security" in text.lower()):
        signals.append("ssn_like")
    if "passport" in text.lower() or "credit card" in text.lower():
        signals.append("sensitive_doc")
    bias = {
        "pii_detected": bool(signals),
        "signals": signals,
        "preferred_providers": ["azure-openai", "aws", "vertex", "google"] if signals else [],
        "avoid_providers": ["groq", "together", "fireworks"] if signals else [],
        "max_budget_tier": "standard" if signals else None,
        "message": "Prefer enterprise/hyperscaler endpoints when PII-like signals are present.",
    }
    return bias


def filter_models_by_residency(
    db: Session,
    *,
    allowed_regions: list[str],
) -> dict[str, Any]:
    """Item 75: data-residency model filter."""
    regions = [str(r).strip().lower() for r in allowed_regions if str(r).strip()]
    catalog = (
        db.query(SupportedModelCatalogEntry)
        .filter(SupportedModelCatalogEntry.status.in_(("active", "beta")))
        .limit(500)
        .all()
    )
    # Provider-to-region heuristic map for operator guidance.
    provider_regions = {
        "azure-openai": {"eastus", "westus", "westeurope", "northeurope"},
        "aws": {"us-east-1", "us-west-2", "eu-west-1", "eu-central-1"},
        "vertex": {"us-central1", "europe-west1", "asia-northeast1"},
        "google": {"us", "eu", "global"},
        "openai": {"us"},
        "anthropic": {"us"},
    }
    allowed = []
    blocked = []
    for row in catalog:
        provider = str(row.provider_type or "").strip().lower()
        model = str(row.model_name or "").strip()
        supported = provider_regions.get(provider, set())
        ok = (not regions) or (not supported) or bool(supported & set(regions)) or "global" in supported
        entry = {"provider_type": provider, "model_name": model}
        (allowed if ok else blocked).append(entry)
    return {
        "allowed_regions": regions,
        "allowed_count": len(allowed),
        "blocked_count": len(blocked),
        "allowed": allowed[:50],
        "blocked": blocked[:50],
        "message": "Residency filter is advisory against catalog providers; enforce via pre-call region filters too.",
    }


def correlate_cost_anomaly_model_switches(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 76: cost anomaly ↔ model switch correlation."""
    attribution = build_attribution_analytics(db, hours=hours, exclude_warmup=False)
    window_start = datetime.utcnow() - timedelta(hours=max(1, min(hours, 168)))
    events = (
        db.query(CostEvent)
        .filter(CostEvent.timestamp >= window_start)
        .order_by(CostEvent.timestamp.desc())
        .limit(5000)
        .all()
    )
    costs = [int(getattr(event, "estimated_cost_cents", 0) or 0) for event in events]
    avg = (sum(costs) / len(costs)) if costs else 0.0
    anomalies = []
    for event in events:
        cost = int(getattr(event, "estimated_cost_cents", 0) or 0)
        props = _parse_props(getattr(event, "properties_json", None))
        if avg and cost >= max(avg * 2.5, avg + 20):
            anomalies.append(
                {
                    "model_name": getattr(event, "model_name", None),
                    "cost_cents": cost,
                    "switched": bool(props.get("model_switched")),
                    "intended_model": props.get("intended_model"),
                    "actual_model": props.get("actual_model"),
                }
            )
    switched_anomalies = [row for row in anomalies if row.get("switched")]
    return {
        "hours": hours,
        "average_cost_cents": round(avg, 2),
        "anomaly_count": len(anomalies),
        "switched_anomaly_count": len(switched_anomalies),
        "correlation_rate_percent": round((len(switched_anomalies) / len(anomalies)) * 100, 2) if anomalies else 0.0,
        "samples": anomalies[:20],
        "switch_rate_percent": attribution.get("switch_rate_percent"),
    }


def replay_auto_route_alternate_strategy(
    db: Session,
    *,
    prompt_text: str,
    strategies: Optional[list[str]] = None,
) -> dict[str, Any]:
    """Item 78: replay request with alternate strategy."""
    from app.services.gateway_leadership import compare_auto_route_strategies

    compare = compare_auto_route_strategies(db, prompt_text=prompt_text, prefer_live_only=True)
    wanted = [str(s).strip().lower() for s in (strategies or ["balanced", "cost", "quality"]) if str(s).strip()]
    rows = [row for row in (compare.get("comparisons") or []) if row.get("strategy") in wanted]
    return {
        "prompt_preview": str(prompt_text or "")[:160],
        "replays": rows,
        "distinct_models": compare.get("distinct_models"),
        "recommendation": compare.get("recommendation"),
    }


def batch_csv_auto_route_classify(db: Session, *, csv_text: str, strategy: str = "balanced") -> dict[str, Any]:
    """Item 79: batch CSV upload classify."""
    from app.services.gateway_leadership import batch_auto_route_classify

    reader = csv.reader(io.StringIO(str(csv_text or "")))
    prompts: list[str] = []
    for row in reader:
        if not row:
            continue
        cell = str(row[0] or "").strip()
        if not cell or cell.lower() in {"prompt", "prompt_text", "text"}:
            continue
        prompts.append(cell)
        if len(prompts) >= 25:
            break
    result = batch_auto_route_classify(db, prompts=prompts, strategy=strategy, prefer_live_only=True)
    return {**result, "source": "csv_upload", "parsed_prompts": len(prompts)}


def run_nightly_leadership_snapshot(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 80: nightly leadership snapshot cron entrypoint."""
    result = record_leadership_snapshot(db, hours=hours, exclude_warmup=True)
    return {
        "job": "nightly_leadership_snapshot",
        "ran_at": datetime.utcnow().isoformat() + "Z",
        "result": result,
        "schedule_hint": "0 2 * * *  # daily 02:00 UTC",
    }


def upsert_warmup_retention_policy(db: Session, *, retain_hours: int = 168, max_events: int = 500) -> dict[str, Any]:
    """Item 81: retention policy for warmup events."""
    policy = {
        "retain_hours": max(1, min(int(retain_hours), 720)),
        "max_events": max(10, min(int(max_events), 5000)),
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    _rt_set(db, _WARMUP_RETENTION_KEY, policy, "Warmup event retention policy")
    return {"policy": policy}


def purge_warmup_events(db: Session, *, dry_run: bool = True) -> dict[str, Any]:
    """Item 82: warmup event purge API."""
    policy = _rt_get(db, _WARMUP_RETENTION_KEY, "{}")
    if not isinstance(policy, dict):
        policy = {}
    retain_hours = int(policy.get("retain_hours") or 168)
    cutoff = datetime.utcnow() - timedelta(hours=retain_hours)
    events = (
        db.query(CostEvent)
        .filter(CostEvent.timestamp < cutoff)
        .order_by(CostEvent.timestamp.asc())
        .limit(2000)
        .all()
    )
    victims = []
    for event in events:
        props = _parse_props(getattr(event, "properties_json", None))
        if props.get("leadership_warmup") or props.get("warmup") or str(props.get("source") or "") == "leadership_warmup":
            victims.append(event)
    deleted = 0
    if not dry_run:
        for event in victims:
            db.delete(event)
            deleted += 1
        if deleted:
            db.flush()
    return {
        "dry_run": dry_run,
        "retain_hours": retain_hours,
        "matched": len(victims),
        "deleted": deleted if not dry_run else 0,
        "message": "Dry-run only; set dry_run=false to delete matched warmup events." if dry_run else f"Purged {deleted} warmup events.",
    }


def upsert_ranking_weights(db: Session, *, weights: dict[str, float]) -> dict[str, Any]:
    """Item 83: ranking weight tuning runtime config."""
    clean = {
        "volume": float(weights.get("volume", 0.35)),
        "stability": float(weights.get("stability", 0.30)),
        "cost": float(weights.get("cost", 0.20)),
        "latency": float(weights.get("latency", 0.15)),
    }
    total = sum(clean.values()) or 1.0
    normalized = {k: round(v / total, 4) for k, v in clean.items()}
    payload = {**normalized, "updated_at": datetime.utcnow().isoformat() + "Z"}
    _rt_set(db, _RANKING_WEIGHTS_KEY, payload, "Leadership ranking weight tuning")
    return {"weights": payload}


def get_ranking_weights(db: Session) -> dict[str, Any]:
    raw = _rt_get(db, _RANKING_WEIGHTS_KEY, "{}")
    if not isinstance(raw, dict) or not raw:
        raw = {"volume": 0.35, "stability": 0.30, "cost": 0.20, "latency": 0.15}
    return {"weights": raw}


def upsert_judge_thresholds(db: Session, *, near_standard: list[int] | None = None, near_complex: list[int] | None = None) -> dict[str, Any]:
    """Item 84: judge threshold runtime config."""
    payload = {
        "near_standard": near_standard or [20, 30],
        "near_complex": near_complex or [50, 60],
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    _rt_set(db, _JUDGE_THRESHOLDS_KEY, payload, "Auto-route judge thresholds")
    return {"thresholds": payload}


def get_judge_thresholds(db: Session) -> dict[str, Any]:
    raw = _rt_get(db, _JUDGE_THRESHOLDS_KEY, "{}")
    if not isinstance(raw, dict) or not raw:
        raw = {"near_standard": [20, 30], "near_complex": [50, 60]}
    return {"thresholds": raw}


def upsert_route_strategy_policy(
    db: Session,
    *,
    route_policy_id: str,
    strategy: str = "balanced",
    prefer_live_only: bool = True,
) -> dict[str, Any]:
    """Item 85: strategy policy per route_policy_id."""
    route_id = str(route_policy_id or "").strip()
    exists = bool(db.query(RoutePolicy).filter_by(route_policy_id=route_id).first()) if route_id else False
    rows = _rt_get(db, _ROUTE_STRATEGY_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    policy = {
        "route_policy_id": route_id,
        "exists": exists,
        "strategy": strategy,
        "prefer_live_only": prefer_live_only,
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    rows = [row for row in rows if row.get("route_policy_id") != route_id]
    rows.insert(0, policy)
    _rt_set(db, _ROUTE_STRATEGY_KEY, rows[:200], "Per-route auto-route strategy policies")
    return {"policy": policy, "count": len(rows)}


def upsert_request_tag_strategy_policy(
    db: Session,
    *,
    request_tag: str,
    strategy: str = "balanced",
) -> dict[str, Any]:
    """Item 86: strategy policy per request_tag."""
    tag = str(request_tag or "").strip()
    rows = _rt_get(db, _TAG_STRATEGY_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    policy = {
        "request_tag": tag,
        "strategy": strategy,
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    rows = [row for row in rows if row.get("request_tag") != tag]
    rows.insert(0, policy)
    _rt_set(db, _TAG_STRATEGY_KEY, rows[:200], "Per-request-tag auto-route strategy policies")
    return {"policy": policy, "count": len(rows)}


def build_owner_scope_ranking_isolation(
    db: Session,
    *,
    owner_scope: str,
    hours: int = 168,
) -> dict[str, Any]:
    """Item 87: owner-scope ranking isolation."""
    scope = str(owner_scope or "").strip()
    window_start = datetime.utcnow() - timedelta(hours=max(1, min(hours, 168)))
    events = (
        db.query(CostEvent)
        .filter(CostEvent.timestamp >= window_start, CostEvent.owner_scope == scope)
        .order_by(CostEvent.timestamp.desc())
        .limit(3000)
        .all()
    )
    counter: Counter[str] = Counter()
    for event in events:
        counter[str(getattr(event, "model_name", None) or "unknown")] += 1
    models = [{"model_name": m, "events": n, "score": float(n)} for m, n in counter.most_common(20)]
    return {
        "owner_scope": scope,
        "hours": hours,
        "isolated": True,
        "models": models,
        "sample_events": len(events),
    }


def build_multi_tenant_ranking_federation(db: Session, *, hours: int = 168, limit: int = 10) -> dict[str, Any]:
    """Item 88: multi-tenant ranking federation."""
    window_start = datetime.utcnow() - timedelta(hours=max(1, min(hours, 168)))
    events = (
        db.query(CostEvent)
        .filter(CostEvent.timestamp >= window_start)
        .order_by(CostEvent.timestamp.desc())
        .limit(8000)
        .all()
    )
    by_tenant: dict[str, Counter] = defaultdict(Counter)
    for event in events:
        props = _parse_props(getattr(event, "properties_json", None))
        tenant = str(props.get("tenant_id") or getattr(event, "owner_scope", None) or "default").strip() or "default"
        by_tenant[tenant][str(getattr(event, "model_name", None) or "unknown")] += 1
    federation = []
    for tenant, counter in sorted(by_tenant.items(), key=lambda kv: sum(kv[1].values()), reverse=True)[: max(1, min(limit, 50))]:
        federation.append(
            {
                "tenant_id": tenant,
                "events": sum(counter.values()),
                "top_models": [{"model_name": m, "events": n} for m, n in counter.most_common(3)],
            }
        )
    return {"hours": hours, "tenants": federation, "count": len(federation)}


def enrich_model_cards_from_catalog(db: Session, *, limit: int = 50) -> dict[str, Any]:
    """Item 89: model card enrichment from catalog."""
    rankings = build_model_liquidity_ranking(db, hours=168, limit=limit)
    score_by = rankings.get("score_by_model") or {}
    rows = (
        db.query(SupportedModelCatalogEntry)
        .filter(SupportedModelCatalogEntry.status.in_(("active", "beta")))
        .order_by(SupportedModelCatalogEntry.model_name.asc())
        .limit(max(1, min(int(limit), 200)))
        .all()
    )
    cards = []
    for row in rows:
        name = str(row.model_name or "").strip()
        cards.append(
            {
                "model_name": name,
                "provider_type": row.provider_type,
                "status": row.status,
                "telemetry_score": float(score_by.get(name.lower(), 0.0)),
                "card": {
                    "summary": f"{name} via {row.provider_type}",
                    "governance_status": row.status,
                    "liquidity": "high" if score_by.get(name.lower(), 0) >= 40 else "emerging",
                },
            }
        )
    return {"count": len(cards), "cards": cards}


def overlay_provider_outages_on_rankings(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 90: provider outage overlay on rankings."""
    from app.services.gateway_leadership_pack6 import build_provider_health_scores

    health = build_provider_health_scores(db, hours=hours)
    rankings = build_model_liquidity_ranking(db, hours=max(24, hours), limit=30)
    degraded = {
        str(row.get("provider_id") or ""): row
        for row in (health.get("providers") or [])
        if str(row.get("band") or "") == "degraded"
    }
    overlay = []
    for model in rankings.get("models") or []:
        overlay.append(
            {
                **model,
                "outage_overlay": "watch" if degraded else "clear",
                "degraded_providers": list(degraded.keys())[:5],
            }
        )
    return {
        "hours": hours,
        "degraded_provider_count": len(degraded),
        "models": overlay,
        "message": "Rankings annotated with provider health/outage overlay.",
    }


def auto_apply_ranking_to_active_routes(db: Session, *, max_hops: int = 3) -> dict[str, Any]:
    """Item 91: auto apply ranking to all active routes (caller enforces dual-approval)."""
    from app.services.gateway_leadership import ranking_aware_fallback_suggest

    suggestion = ranking_aware_fallback_suggest(db, max_hops=max_hops)
    routes = db.query(RoutePolicy).filter(RoutePolicy.status == "active").limit(100).all()
    proposals = []
    for route in routes:
        proposals.append(
            {
                "route_policy_id": route.route_policy_id,
                "route_name": route.route_name,
                "proposed_priority_order": suggestion.get("priority_order") or [],
                "applied": False,
            }
        )
    return {
        "proposal_count": len(proposals),
        "proposals": proposals,
        "ranking_applied": True,
        "message": "Non-mutating proposals only. Persist via route priority APIs after dual-approval review.",
    }


def diff_leadership_snapshots(db: Session) -> dict[str, Any]:
    """Item 92: diff previous vs current leadership snapshot."""
    history = list_leadership_history(db, limit=5)
    snaps = history.get("snapshots") or []
    if len(snaps) < 2:
        return {"diffable": False, "message": "Need at least two snapshots.", "snapshots": snaps}
    current, previous = snaps[0], snaps[1]
    delta = float(current.get("score") or 0) - float(previous.get("score") or 0)
    return {
        "diffable": True,
        "current": current,
        "previous": previous,
        "score_delta": round(delta, 2),
        "band_changed": current.get("band") != previous.get("band"),
    }


def export_signed_leadership_evidence(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 93: signed leadership evidence pack."""
    pack = export_leadership_evidence_pack(db, hours=hours, exclude_warmup=True)
    secret = str(os.getenv("GATEWAY_EVIDENCE_SIGNING_SECRET") or _DEFAULT_SHARE_SECRET)
    body = json.dumps(pack, separators=(",", ":"), sort_keys=True)
    signature = hmac.new(secret.encode("utf-8"), body.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        "signed_at": datetime.utcnow().isoformat() + "Z",
        "algorithm": "HMAC-SHA256",
        "signature": signature,
        "pack": pack,
        "secret_source": "GATEWAY_EVIDENCE_SIGNING_SECRET" if os.getenv("GATEWAY_EVIDENCE_SIGNING_SECRET") else "dev_default",
    }


def create_auditor_share_link(
    db: Session,
    *,
    hours: int = 24,
    ttl_seconds: int = 3600,
) -> dict[str, Any]:
    """Item 94: external auditor share link (time-boxed)."""
    pack = export_leadership_evidence_pack(db, hours=hours, exclude_warmup=True)
    exp = int(time.time()) + max(60, min(int(ttl_seconds), 86400))
    token_body = {
        "share_id": f"share-{uuid4().hex[:10]}",
        "exp": exp,
        "score": (pack.get("leadership_index") or {}).get("score"),
        "hours": hours,
    }
    raw = json.dumps(token_body, separators=(",", ":"), sort_keys=True)
    secret = str(os.getenv("GATEWAY_EVIDENCE_SIGNING_SECRET") or _DEFAULT_SHARE_SECRET)
    sig = hmac.new(secret.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()
    token = f"{raw}.{sig}"
    rows = _rt_get(db, _SHARE_LINKS_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    record = {**token_body, "created_at": datetime.utcnow().isoformat() + "Z", "token_prefix": token[:24]}
    rows.insert(0, record)
    _rt_set(db, _SHARE_LINKS_KEY, rows[:50], "Time-boxed auditor share links")
    return {
        "share_id": token_body["share_id"],
        "expires_at": exp,
        "token": token,
        "path_hint": f"/gateway/best-practices/auditor-share/{token_body['share_id']}",
        "message": "Share token is time-boxed; verify signature before disclosing pack contents.",
    }


def browser_extension_instrumentation_preset() -> dict[str, Any]:
    """Item 95: browser extension instrumentation preset."""
    return {
        "id": "browser-extension",
        "label": "Browser extension",
        "headers": {
            "X-Session-Path": "/extension/page",
            "X-Session-Name": "browser-extension",
            "X-User": "extension-user",
        },
        "properties": {"sdk": "agenthub-extension", "feature": "page-assist"},
        "auto_route": True,
        "auto_route_strategy": "balanced",
    }


def evaluate_ci_leadership_floor(db: Session, *, floor_score: float = 70.0) -> dict[str, Any]:
    """Item 96: CI gate leadership score floor."""
    index = build_gateway_leadership_index(db, hours=24, exclude_warmup=True)
    score = float(index.get("score") or 0)
    passed = score >= float(floor_score)
    return {
        "gate": "ci_leadership_floor",
        "floor_score": floor_score,
        "score": score,
        "passed": passed,
        "exit_code": 0 if passed else 1,
        "message": "CI gate passed." if passed else f"Leadership score {score} below floor {floor_score}.",
    }


def attest_release_gate_leadership(db: Session, *, floor_score: float = 70.0) -> dict[str, Any]:
    """Item 97: release-gate leadership attestation."""
    gate = evaluate_ci_leadership_floor(db, floor_score=floor_score)
    attestation = {
        "attestation_id": f"att-{uuid4().hex[:12]}",
        "attested_at": datetime.utcnow().isoformat() + "Z",
        "gate": gate,
        "decision": "go" if gate["passed"] else "no-go",
    }
    return attestation


def run_chaos_provider_fail_drill(db: Session, *, provider_id: str = "chaos-provider") -> dict[str, Any]:
    """Item 98: chaos drill forced provider fail + attribution (simulated events)."""
    from app.models import CostEvent as CE

    created = []
    for idx in range(3):
        event = CE(
            cost_event_id=f"chaos-{uuid4().hex[:12]}",
            timestamp=datetime.utcnow(),
            request_id=f"chaos-req-{idx}",
            trace_id=f"chaos-trace-{idx}",
            session_id="chaos-drill",
            agent_id="chaos-agent",
            owner_scope="team:chaos",
            environment="dev",
            model_name="gpt-4o-mini",
            endpoint_family="chat.completions",
            input_tokens=10,
            output_tokens=5,
            estimated_cost_cents=1,
            properties_json=json.dumps(
                {
                    "intended_model": "auto",
                    "actual_model": "gpt-4o-mini",
                    "model_switched": True,
                    "auto_route_tier": "simple",
                    "selected_provider_id": provider_id,
                    "outcome": "failed_simulated",
                    "chaos_drill": True,
                }
            ),
        )
        db.add(event)
        created.append(event.cost_event_id)
    db.flush()
    return {
        "drill": "forced_provider_fail",
        "provider_id": provider_id,
        "created_events": len(created),
        "event_ids": created,
        "message": "Simulated failed hops recorded for attribution/circuit-breaker analytics.",
    }


def export_board_one_pager(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 99: board one-pager export (HTML)."""
    index = build_gateway_leadership_index(db, hours=hours, exclude_warmup=True)
    attribution = build_attribution_analytics(db, hours=hours, exclude_warmup=True)
    rankings = build_model_liquidity_ranking(db, hours=max(24, hours), limit=5)
    top = ", ".join(str(row.get("model_name")) for row in (rankings.get("models") or [])[:5])
    html = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>AgentHub Leadership One-Pager</title>
<style>body{{font-family:Georgia,serif;margin:2rem;color:#122}} h1{{font-size:1.8rem}} .score{{font-size:3rem}}</style>
</head><body>
<h1>AgentHub AI Gateway Leadership</h1>
<p class="score">{index.get('score')}/100 <small>({index.get('band')})</small></p>
<p>{index.get('market_claim') or ''}</p>
<ul>
<li>Attribution coverage: {attribution.get('attribution_coverage_percent')}%</li>
<li>Auto-routed events: {attribution.get('auto_routed_events')}</li>
<li>Top models: {top or 'n/a'}</li>
</ul>
<p>Generated {datetime.utcnow().isoformat()}Z</p>
</body></html>"""
    return {
        "format": "html",
        "filename_hint": f"agenthub-leadership-one-pager-{datetime.utcnow().strftime('%Y%m%d')}.html",
        "html": html,
        "score": index.get("score"),
        "band": index.get("band"),
    }


def refresh_competitive_scorecard(db: Session) -> dict[str, Any]:
    """Item 100: competitive scorecard refresh job (weekly)."""
    index = build_gateway_leadership_index(db, hours=168, exclude_warmup=True)
    posture_score = float(((index.get("components") or {}).get("posture") or {}).get("score") or index.get("score") or 0)
    card = {
        "refreshed_at": datetime.utcnow().isoformat() + "Z",
        "cadence": "weekly",
        "leadership_score": index.get("score"),
        "band": index.get("band"),
        "posture_component": posture_score,
        "competitors_benchmark_notes": [
            "Parity vs LiteLLM/OpenRouter: complexity auto-route + attribution analytics present.",
            "Parity vs Portkey/Helicone: session/user/properties + virtual-key policies present.",
            "Differentiator: governance dual-approval + compliance evidence pack + leadership index.",
        ],
        "next_refresh_hint": "0 3 * * 1  # Mondays 03:00 UTC",
    }
    _rt_set(db, _SCORECARD_KEY, card, "Competitive scorecard weekly refresh")
    return card


def get_competitive_scorecard(db: Session) -> dict[str, Any]:
    raw = _rt_get(db, _SCORECARD_KEY, "{}")
    if not isinstance(raw, dict) or not raw:
        return {"scorecard": None, "message": "No scorecard yet — run refresh."}
    return {"scorecard": raw}


def explain_why_this_model_card(
    db: Session,
    *,
    prompt_text: str,
    strategy: str = "balanced",
) -> dict[str, Any]:
    """Item 77: operator why-this-model explain card (rich)."""
    from app.services.gateway_leadership_pack6 import explain_auto_route_decision

    base = explain_auto_route_decision(db, prompt_text=prompt_text, strategy=strategy)
    adversarial = apply_adversarial_tier_hard_boost(prompt_text, base.get("complexity") or {})
    pii = pii_aware_routing_bias(prompt_text)
    return {
        **base,
        "card_title": "Why this model",
        "adversarial": adversarial.get("adversarial_boost"),
        "pii": pii,
        "operator_summary": (
            f"Selected {base.get('selected_model')} because {base.get('why_this_model')}"
        ),
    }
