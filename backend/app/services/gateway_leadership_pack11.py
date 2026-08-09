"""Pack 11 leadership deepeners (items 121–140)."""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import CostEvent, RoutePolicy
from app.services.gateway_leadership import (
    build_attribution_analytics,
    build_gateway_leadership_index,
    build_model_liquidity_ranking,
    list_leadership_history,
)
from app.services.gateway_leadership_pack10 import (
    build_sla_burn_rate,
    build_traffic_light,
    list_ops_activity,
    record_ops_activity,
)
from app.services.inference_readiness import build_inference_readiness


_FLAGS_KEY = "gateway.leadership.enforcement_flags_json"
_MODEL_POLICY_KEY = "gateway.leadership.model_route_policy_json"
_RETRY_QUEUE_KEY = "gateway.leadership.alert_retry_queue_json"
_HISTORY_ARCHIVE_KEY = "gateway.leadership.history_archive_json"


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


DEFAULT_FLAGS = {
    "enforce_pii_bias": True,
    "enforce_adversarial_boost": True,
    "use_decision_cache": True,
    "resolve_strategy_policies": True,
    "enforce_model_denylist": True,
    "decision_cache_ttl_seconds": 60,
}


def get_enforcement_flags(db: Session) -> dict[str, Any]:
    raw = _rt_get(db, _FLAGS_KEY, "{}")
    if not isinstance(raw, dict) or not raw:
        return {"flags": dict(DEFAULT_FLAGS)}
    merged = {**DEFAULT_FLAGS, **raw}
    return {"flags": merged}


def upsert_enforcement_flags(db: Session, *, flags: dict[str, Any]) -> dict[str, Any]:
    current = get_enforcement_flags(db)["flags"]
    for key, value in (flags or {}).items():
        if key in DEFAULT_FLAGS:
            current[key] = value
    current["updated_at"] = datetime.utcnow().isoformat() + "Z"
    _rt_set(db, _FLAGS_KEY, current, "Leadership enforcement feature flags")
    record_ops_activity(db, action="enforcement_flags_upsert", detail={"keys": list(flags.keys())})
    return {"flags": current}


def get_model_route_policy(db: Session) -> dict[str, Any]:
    raw = _rt_get(db, _MODEL_POLICY_KEY, "{}")
    if not isinstance(raw, dict):
        raw = {}
    return {
        "allowlist": list(raw.get("allowlist") or []),
        "denylist": list(raw.get("denylist") or []),
        "updated_at": raw.get("updated_at"),
    }


def upsert_model_route_policy(
    db: Session,
    *,
    allowlist: Optional[list[str]] = None,
    denylist: Optional[list[str]] = None,
) -> dict[str, Any]:
    policy = {
        "allowlist": [str(m).strip() for m in (allowlist or []) if str(m).strip()][:100],
        "denylist": [str(m).strip() for m in (denylist or []) if str(m).strip()][:100],
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    _rt_set(db, _MODEL_POLICY_KEY, policy, "Auto-route model allow/deny policy")
    record_ops_activity(db, action="model_route_policy_upsert", detail={"allow": len(policy["allowlist"]), "deny": len(policy["denylist"])})
    return policy


def build_auto_route_with_pack11(
    db: Session,
    *,
    prompt_text: str,
    strategy: str = "balanced",
    prefer_live_only: bool = True,
    max_candidates_per_tier: int = 3,
    has_tools: bool = False,
    json_response_format: bool = False,
    message_count: int = 0,
    refine_with_judge: bool = True,
    use_telemetry_ranking: bool = True,
    route_policy_id: Optional[str] = None,
    request_tag: Optional[str] = None,
    use_cache: Optional[bool] = None,
) -> dict[str, Any]:
    """Items 121–122/124/137: cached + policy-aware auto-route."""
    from app.services.gateway_auto_router import build_auto_route_decision
    from app.services.gateway_leadership_pack10 import (
        get_cached_auto_route_decision,
        put_cached_auto_route_decision,
        resolve_strategy_policy,
    )

    flags = get_enforcement_flags(db)["flags"]
    resolved = {"strategy": strategy, "source": "request"}
    if flags.get("resolve_strategy_policies"):
        resolved = resolve_strategy_policy(
            db,
            route_policy_id=route_policy_id,
            request_tag=request_tag,
            default_strategy=strategy,
        )
    effective_strategy = str(resolved.get("strategy") or strategy)

    cache_enabled = flags.get("use_decision_cache") if use_cache is None else bool(use_cache)
    if cache_enabled:
        cached = get_cached_auto_route_decision(db, prompt_text=prompt_text, strategy=effective_strategy)
        if cached:
            try:
                from app.services.gateway_leadership_pack12 import bump_decision_cache_stat

                bump_decision_cache_stat(db, hit=True)
            except Exception:  # noqa: BLE001
                pass
            cached_out = {
                **cached,
                "cache_hit": True,
                "strategy_policy": resolved,
                "enforcement_flags": {
                    "enforce_pii_bias": flags.get("enforce_pii_bias"),
                    "enforce_adversarial_boost": flags.get("enforce_adversarial_boost"),
                },
            }
            try:
                from app.services.gateway_leadership_pack14 import (
                    provider_diversity_score,
                    record_auto_route_audit,
                )

                cached_out["provider_diversity"] = provider_diversity_score(cached_out)
                record_auto_route_audit(db, decision=cached_out, source="cache")
            except Exception:  # noqa: BLE001
                pass
            try:
                from app.services.gateway_leadership_pack15 import (
                    apply_preferred_model_bias,
                    get_preferred_model_override,
                )

                cached_out = apply_preferred_model_bias(cached_out, get_preferred_model_override(db))
            except Exception:  # noqa: BLE001
                pass
            try:
                from app.services.gateway_leadership_pack16 import (
                    apply_shadow_traffic_metadata,
                    get_shadow_traffic_percent,
                )

                cached_out = apply_shadow_traffic_metadata(cached_out, get_shadow_traffic_percent(db))
            except Exception:  # noqa: BLE001
                pass
            return cached_out

    decision = build_auto_route_decision(
        db,
        prompt_text=prompt_text,
        prefer_live_only=prefer_live_only,
        max_candidates_per_tier=max_candidates_per_tier,
        strategy=effective_strategy,
        has_tools=has_tools,
        json_response_format=json_response_format,
        message_count=message_count,
        refine_with_judge=refine_with_judge,
        use_telemetry_ranking=use_telemetry_ranking,
    )

    # Soft-disable enforcement signals in response metadata when flags off.
    constraints = dict(decision.get("constraints") or {})
    if not flags.get("enforce_pii_bias"):
        constraints["pii_detected"] = False
    if not flags.get("enforce_adversarial_boost"):
        constraints["adversarial_boost"] = False
    decision["constraints"] = constraints
    decision["strategy_policy"] = resolved
    decision["cache_hit"] = False
    try:
        from app.services.gateway_leadership_pack12 import bump_decision_cache_stat

        bump_decision_cache_stat(db, hit=False)
    except Exception:  # noqa: BLE001
        pass
    try:
        from app.services.gateway_leadership_pack14 import (
            provider_diversity_score,
            record_auto_route_audit,
        )

        decision["provider_diversity"] = provider_diversity_score(decision)
        record_auto_route_audit(db, decision=decision, source="live")
    except Exception:  # noqa: BLE001
        pass
    try:
        from app.services.gateway_leadership_pack15 import (
            apply_preferred_model_bias,
            get_preferred_model_override,
        )

        decision = apply_preferred_model_bias(decision, get_preferred_model_override(db))
    except Exception:  # noqa: BLE001
        pass
    try:
        from app.services.gateway_leadership_pack16 import (
            apply_shadow_traffic_metadata,
            get_shadow_traffic_percent,
        )

        decision = apply_shadow_traffic_metadata(decision, get_shadow_traffic_percent(db))
    except Exception:  # noqa: BLE001
        pass

    if cache_enabled:
        put_cached_auto_route_decision(
            db,
            prompt_text=prompt_text,
            strategy=effective_strategy,
            decision=decision,
            ttl_seconds=int(flags.get("decision_cache_ttl_seconds") or 60),
        )
    return decision


def build_leadership_sparkline(db: Session, *, points: int = 12) -> dict[str, Any]:
    """Item 125: leadership sparkline from snapshot history + current score."""
    history = list_leadership_history(db, limit=max(2, min(int(points), 50)))
    snaps = list(reversed(history.get("snapshots") or []))
    series = [{"at": row.get("recorded_at"), "score": row.get("score"), "band": row.get("band")} for row in snaps]
    if not series:
        current = build_gateway_leadership_index(db, hours=24, exclude_warmup=True)
        series = [{"at": datetime.utcnow().isoformat() + "Z", "score": current.get("score"), "band": current.get("band")}]
    return {"points": series, "count": len(series)}


def export_operator_runbook(db: Session) -> dict[str, Any]:
    """Item 126: operator runbook export."""
    light = build_traffic_light(db)
    flags = get_enforcement_flags(db)["flags"]
    steps = [
        "1. Check GET /gateway/best-practices/traffic-light and /healthz.",
        "2. If red: run leadership-warmup (rate-limited) or fix credential warnings.",
        "3. Review attribution-analytics and model-rankings.",
        "4. Use fallback-suggest-ranked then apply-ranked-fallback for weak routes.",
        "5. Dispatch alerts dry-run, then deliver with allowlisted hosts.",
        "6. Export signed-evidence / board-one-pager for stakeholders.",
    ]
    return {
        "title": "AgentHub Leadership Operator Runbook",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "current_light": light.get("light"),
        "current_score": light.get("score"),
        "enforcement_flags": flags,
        "steps": steps,
        "markdown": "# Leadership Runbook\n\n" + "\n".join(steps) + f"\n\nCurrent light: **{light.get('light')}** ({light.get('score')})\n",
    }


def enqueue_alert_retry(db: Session, *, dispatch_id: str, host: str, error: str) -> dict[str, Any]:
    """Item 127: alert delivery retry queue."""
    rows = _rt_get(db, _RETRY_QUEUE_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    item = {
        "retry_id": f"rtry-{uuid4().hex[:10]}",
        "dispatch_id": dispatch_id,
        "host": host,
        "error": str(error)[:200],
        "attempts": 0,
        "status": "queued",
        "queued_at": datetime.utcnow().isoformat() + "Z",
    }
    rows.insert(0, item)
    _rt_set(db, _RETRY_QUEUE_KEY, rows[:100], "Leadership alert retry queue")
    return item


def list_alert_retries(db: Session, *, limit: int = 20) -> dict[str, Any]:
    rows = _rt_get(db, _RETRY_QUEUE_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    return {"count": min(len(rows), limit), "retries": rows[: max(1, min(limit, 100))]}


def process_alert_retry_queue(db: Session, *, dry_run: bool = True, limit: int = 5) -> dict[str, Any]:
    rows = _rt_get(db, _RETRY_QUEUE_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    processed = []
    for row in rows[: max(1, min(limit, 20))]:
        if row.get("status") not in {"queued", "failed"}:
            continue
        row["attempts"] = int(row.get("attempts") or 0) + 1
        if dry_run:
            row["status"] = "dry_run_processed"
        else:
            # Re-queue semantics only; actual HTTP send uses alert-deliver allowlist path.
            row["status"] = "requeued_for_deliver"
        row["processed_at"] = datetime.utcnow().isoformat() + "Z"
        processed.append(row)
    _rt_set(db, _RETRY_QUEUE_KEY, rows[:100], "Leadership alert retry queue")
    record_ops_activity(db, action="alert_retry_process", detail={"count": len(processed), "dry_run": dry_run})
    return {"processed": processed, "count": len(processed), "dry_run": dry_run}


def build_dashboard_summary(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 128: composite leadership dashboard summary."""
    light = build_traffic_light(db, hours=hours)
    burn = build_sla_burn_rate(db, hours=hours)
    attribution = build_attribution_analytics(db, hours=hours, exclude_warmup=True)
    rankings = build_model_liquidity_ranking(db, hours=max(24, hours), limit=5)
    readiness = build_inference_readiness(db)
    activity = list_ops_activity(db, limit=5)
    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "traffic_light": light,
        "sla": burn,
        "attribution_coverage_percent": attribution.get("attribution_coverage_percent"),
        "auto_routed_events": attribution.get("auto_routed_events"),
        "top_models": rankings.get("models") or [],
        "ready_providers": readiness.get("ready_providers"),
        "recent_activity": activity.get("activities") or [],
    }


def verify_failover_drill(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 129: failover drill verification from chaos/fail outcomes."""
    window_start = datetime.utcnow() - timedelta(hours=max(1, min(hours, 168)))
    events = (
        db.query(CostEvent)
        .filter(CostEvent.timestamp >= window_start)
        .order_by(CostEvent.timestamp.desc())
        .limit(3000)
        .all()
    )
    fail = 0
    attributed = 0
    chaos = 0
    for event in events:
        try:
            props = json.loads(getattr(event, "properties_json", None) or "{}")
        except json.JSONDecodeError:
            props = {}
        if not isinstance(props, dict):
            continue
        outcome = str(props.get("outcome") or "").lower()
        if outcome.startswith("failed") or outcome in {"budget_blocked", "retry_policy_blocked"}:
            fail += 1
            if props.get("intended_model") or props.get("actual_model"):
                attributed += 1
        if props.get("chaos_drill"):
            chaos += 1
    return {
        "hours": hours,
        "failed_events": fail,
        "attributed_failures": attributed,
        "chaos_events": chaos,
        "verified": attributed > 0 or chaos > 0,
        "message": (
            "Failover drill evidence present with attribution."
            if attributed or chaos
            else "No failover/chaos evidence in window — run chaos drill first."
        ),
    }


def build_latency_histogram(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 130: latency histogram for ranking telemetry."""
    window_start = datetime.utcnow() - timedelta(hours=max(1, min(hours, 168)))
    events = (
        db.query(CostEvent)
        .filter(CostEvent.timestamp >= window_start)
        .order_by(CostEvent.timestamp.desc())
        .limit(5000)
        .all()
    )
    buckets = Counter({"0-100": 0, "100-300": 0, "300-800": 0, "800-2000": 0, "2000+": 0})
    samples = 0
    for event in events:
        try:
            props = json.loads(getattr(event, "properties_json", None) or "{}")
        except json.JSONDecodeError:
            props = {}
        latency = props.get("latency_ms") if isinstance(props, dict) else None
        if not isinstance(latency, (int, float)):
            continue
        samples += 1
        if latency < 100:
            buckets["0-100"] += 1
        elif latency < 300:
            buckets["100-300"] += 1
        elif latency < 800:
            buckets["300-800"] += 1
        elif latency < 2000:
            buckets["800-2000"] += 1
        else:
            buckets["2000+"] += 1
    return {
        "hours": hours,
        "samples": samples,
        "buckets": [{"bucket": k, "count": buckets[k]} for k in ["0-100", "100-300", "300-800", "800-2000", "2000+"]],
    }


def archive_leadership_history(db: Session, *, keep: int = 20) -> dict[str, Any]:
    """Item 131: archive older leadership snapshots."""
    history = list_leadership_history(db, limit=50)
    snaps = history.get("snapshots") or []
    keep_n = max(5, min(int(keep), 40))
    keep_rows = snaps[:keep_n]
    archive_rows = snaps[keep_n:]
    archived = _rt_get(db, _HISTORY_ARCHIVE_KEY, "[]")
    if not isinstance(archived, list):
        archived = []
    archived = archive_rows + archived
    archived = archived[:200]
    from app.services.runtime_config import upsert_runtime_config_value

    upsert_runtime_config_value(
        db,
        "gateway.leadership.history_json",
        json.dumps(keep_rows, separators=(",", ":")),
        description="Leadership index snapshot history",
    )
    _rt_set(db, _HISTORY_ARCHIVE_KEY, archived, "Archived leadership snapshots")
    record_ops_activity(db, action="history_archive", detail={"kept": len(keep_rows), "archived": len(archive_rows)})
    return {"kept": len(keep_rows), "archived_now": len(archive_rows), "archive_total": len(archived)}


def correlate_budget_auto_route(db: Session, *, hours: int = 168) -> dict[str, Any]:
    """Item 132: budget spend vs auto-route correlation."""
    attribution = build_attribution_analytics(db, hours=hours, exclude_warmup=False)
    window_start = datetime.utcnow() - timedelta(hours=max(1, min(hours, 168)))
    events = (
        db.query(CostEvent)
        .filter(CostEvent.timestamp >= window_start)
        .limit(5000)
        .all()
    )
    routed_cost = 0
    other_cost = 0
    routed_n = 0
    other_n = 0
    for event in events:
        try:
            props = json.loads(getattr(event, "properties_json", None) or "{}")
        except json.JSONDecodeError:
            props = {}
        cost = int(getattr(event, "estimated_cost_cents", 0) or 0)
        if isinstance(props, dict) and props.get("auto_route_tier"):
            routed_cost += cost
            routed_n += 1
        else:
            other_cost += cost
            other_n += 1
    return {
        "hours": hours,
        "auto_routed_events": routed_n,
        "other_events": other_n,
        "auto_routed_cost_cents": routed_cost,
        "other_cost_cents": other_cost,
        "avg_auto_routed_cost_cents": round(routed_cost / routed_n, 2) if routed_n else 0.0,
        "avg_other_cost_cents": round(other_cost / other_n, 2) if other_n else 0.0,
        "switch_rate_percent": attribution.get("switch_rate_percent"),
    }


def evaluate_canary_promote_gate(
    db: Session,
    *,
    route_policy_id: str,
    floor_score: float = 70.0,
) -> dict[str, Any]:
    """Item 133: canary promote gate using leadership score."""
    route = db.query(RoutePolicy).filter_by(route_policy_id=str(route_policy_id or "").strip()).first()
    if not route:
        return {"found": False, "passed": False, "message": "Route not found."}
    index = build_gateway_leadership_index(db, hours=24, exclude_warmup=True)
    score = float(index.get("score") or 0)
    passed = score >= float(floor_score)
    return {
        "found": True,
        "route_policy_id": route.route_policy_id,
        "leadership_score": score,
        "floor_score": floor_score,
        "passed": passed,
        "decision": "promote_allowed" if passed else "hold",
        "message": "Canary promote gate passed." if passed else "Hold canary promote — leadership below floor.",
    }


def build_weekly_ops_report(db: Session) -> dict[str, Any]:
    """Item 139: leadership weekly ops report."""
    summary = build_dashboard_summary(db, hours=168)
    spark = build_leadership_sparkline(db, points=8)
    retries = list_alert_retries(db, limit=5)
    return {
        "report_id": f"wor-{uuid4().hex[:10]}",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "window_hours": 168,
        "summary": summary,
        "sparkline": spark,
        "alert_retries": retries.get("retries") or [],
        "markdown": (
            f"# Weekly Leadership Ops Report\n\n"
            f"- Light: {summary['traffic_light'].get('light')} ({summary['traffic_light'].get('score')})\n"
            f"- Auto-routed events: {summary.get('auto_routed_events')}\n"
            f"- Ready providers: {summary.get('ready_providers')}\n"
        ),
    }


def annotate_route_circuit_breaker_notes(db: Session, *, route_policy_id: str) -> dict[str, Any]:
    """Item 140: soft circuit-breaker health notes on route fallback_policy."""
    from app.services.gateway_leadership import build_circuit_breaker_recommendations

    route = db.query(RoutePolicy).filter_by(route_policy_id=str(route_policy_id or "").strip()).first()
    if not route:
        return {"annotated": False, "message": "Route not found."}
    recs = build_circuit_breaker_recommendations(db, hours=24)
    try:
        fallback = json.loads(route.fallback_policy or "{}")
    except json.JSONDecodeError:
        fallback = {}
    if not isinstance(fallback, dict):
        fallback = {}
    fallback["circuit_breaker_notes"] = {
        "updated_at": datetime.utcnow().isoformat() + "Z",
        "recommendations": (recs.get("recommendations") or [])[:10],
        "message": recs.get("message"),
    }
    route.fallback_policy = json.dumps(fallback, separators=(",", ":"))
    db.flush()
    record_ops_activity(db, action="circuit_breaker_annotate", detail={"route_policy_id": route_policy_id})
    return {
        "annotated": True,
        "route_policy_id": route.route_policy_id,
        "recommendation_count": len(fallback["circuit_breaker_notes"]["recommendations"]),
    }


def pack11_manifest() -> dict[str, Any]:
    return {
        "pack": 11,
        "items": list(range(121, 141)),
        "theme": "Live-path wiring + dashboard/ops deepeners",
        "gov": "GOV-AI-MARKET-011",
    }
