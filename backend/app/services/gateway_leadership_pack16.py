"""Pack 16 leadership deepeners (items 221–240): executive moat + operator excellence."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.services.gateway_leadership_pack10 import build_traffic_light, list_ops_activity, record_ops_activity
from app.services.gateway_leadership_pack13 import warmup_eligibility_probe
from app.services.gateway_leadership_pack14 import list_leadership_incidents
from app.services.gateway_leadership_pack15 import composite_go_no_go


_SHADOW_TRAFFIC_KEY = "gateway.leadership.shadow_traffic_percent_json"
_CANARY_ROLLBACK_KEY = "gateway.leadership.canary_auto_rollback_json"
_LATENCY_BUDGET_KEY = "gateway.leadership.latency_budget_ms_json"
_MODEL_CARD_FRESHNESS_KEY = "gateway.leadership.model_card_freshness_json"
_HISTORY_KEY = "gateway.leadership.history_json"


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


def executive_leadership_brief(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 221: one-page executive brief."""
    composite = composite_go_no_go(db, hours=hours)
    delta = competitive_scorecard_delta(db)
    incidents = list_leadership_incidents(db, limit=5, status="open")
    light = (composite.get("traffic_light") or {})
    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "decision": composite.get("decision"),
        "passed": composite.get("passed"),
        "traffic_light": light.get("light"),
        "score": light.get("score"),
        "score_delta": delta.get("score_delta"),
        "open_incidents": incidents.get("count"),
        "top_incidents": (incidents.get("incidents") or [])[:3],
        "message": (
            f"Executive brief: {composite.get('decision')} · light={light.get('light')} · "
            f"Δscore={delta.get('score_delta')} · open_incidents={incidents.get('count')}"
        ),
    }


def competitive_scorecard_delta(db: Session) -> dict[str, Any]:
    """Item 222: competitive scorecard delta vs prior snapshot."""
    history = _rt_get(db, _HISTORY_KEY, "[]")
    if not isinstance(history, list):
        history = []
    latest = history[0] if history else {}
    prior = history[1] if len(history) > 1 else {}
    latest_score = float(latest.get("score") or 0.0)
    prior_score = float(prior.get("score") or latest_score)
    delta = round(latest_score - prior_score, 2)
    return {
        "latest_score": latest_score,
        "prior_score": prior_score,
        "score_delta": delta,
        "latest_band": latest.get("band"),
        "prior_band": prior.get("band"),
        "latest_snapshot_id": latest.get("snapshot_id"),
        "direction": "up" if delta > 0 else "down" if delta < 0 else "flat",
        "message": f"Score delta {delta} ({'up' if delta > 0 else 'down' if delta < 0 else 'flat'}).",
    }


def get_shadow_traffic_percent(db: Session) -> dict[str, Any]:
    """Item 223: get shadow traffic percent controller."""
    cfg = _rt_get(db, _SHADOW_TRAFFIC_KEY, "{}")
    if not isinstance(cfg, dict):
        cfg = {}
    percent = float(cfg.get("percent") or 0.0)
    enabled = bool(cfg.get("enabled", percent > 0))
    return {
        "enabled": enabled,
        "percent": max(0.0, min(100.0, percent)),
        "updated_at": cfg.get("updated_at"),
        "message": f"Shadow traffic {'enabled' if enabled else 'disabled'} at {percent}%.",
    }


def put_shadow_traffic_percent(db: Session, *, percent: float, enabled: bool = True) -> dict[str, Any]:
    """Item 223: put shadow traffic percent controller."""
    pct = max(0.0, min(100.0, float(percent)))
    payload = {
        "enabled": bool(enabled) and pct > 0,
        "percent": pct,
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    _rt_set(db, _SHADOW_TRAFFIC_KEY, payload, "Shadow traffic percent controller")
    record_ops_activity(db, action="shadow_traffic_percent_put", detail=payload)
    return {**payload, "message": f"Shadow traffic set to {pct}% (enabled={payload['enabled']})."}


def get_canary_auto_rollback(db: Session) -> dict[str, Any]:
    """Item 224: get canary auto-rollback policy."""
    cfg = _rt_get(db, _CANARY_ROLLBACK_KEY, "{}")
    if not isinstance(cfg, dict):
        cfg = {}
    return {
        "enabled": bool(cfg.get("enabled", False)),
        "on_red_light": bool(cfg.get("on_red_light", True)),
        "on_floor_fail": bool(cfg.get("on_floor_fail", True)),
        "updated_at": cfg.get("updated_at"),
        "message": "Canary auto-rollback policy loaded.",
    }


def put_canary_auto_rollback(
    db: Session,
    *,
    enabled: bool = True,
    on_red_light: bool = True,
    on_floor_fail: bool = True,
) -> dict[str, Any]:
    """Item 224: put canary auto-rollback policy."""
    payload = {
        "enabled": bool(enabled),
        "on_red_light": bool(on_red_light),
        "on_floor_fail": bool(on_floor_fail),
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    _rt_set(db, _CANARY_ROLLBACK_KEY, payload, "Canary auto-rollback policy")
    record_ops_activity(db, action="canary_auto_rollback_put", detail=payload)
    return {**payload, "message": "Canary auto-rollback policy saved."}


def evaluate_canary_auto_rollback(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 224 helper: evaluate whether canary should auto-rollback now."""
    policy = get_canary_auto_rollback(db)
    if not policy.get("enabled"):
        return {"should_rollback": False, "reason": "policy_disabled", "policy": policy}
    composite = composite_go_no_go(db, hours=hours)
    light = str((composite.get("traffic_light") or {}).get("light") or "").lower()
    floor_failed = not bool((composite.get("floor") or {}).get("passed", True))
    reasons = []
    if policy.get("on_red_light") and light == "red":
        reasons.append("red_light")
    if policy.get("on_floor_fail") and floor_failed:
        reasons.append("floor_fail")
    should = bool(reasons)
    return {
        "should_rollback": should,
        "reasons": reasons,
        "policy": policy,
        "composite_decision": composite.get("decision"),
        "message": "Canary should auto-rollback." if should else "Canary rollback not required.",
    }


def attribution_anomaly_detector(db: Session, *, limit: int = 100) -> dict[str, Any]:
    """Item 225: detect strategy skew / cache cliff anomalies in audit trail."""
    from app.services.gateway_leadership_pack15 import auto_route_audit_summary

    summary = auto_route_audit_summary(db, limit=limit)
    by_strategy = summary.get("by_strategy") or {}
    total = int(summary.get("count") or 0)
    cache_rate = float(summary.get("cache_hit_rate_percent") or 0.0)
    dominant = max(by_strategy.items(), key=lambda kv: kv[1]) if by_strategy else ("none", 0)
    dominant_share = round(100.0 * dominant[1] / total, 2) if total else 0.0
    anomalies = []
    if total >= 5 and dominant_share >= 85.0:
        anomalies.append({"code": "strategy_skew", "detail": f"{dominant[0]}={dominant_share}%"})
    if total >= 5 and cache_rate >= 95.0:
        anomalies.append({"code": "cache_cliff", "detail": f"cache_hit_rate={cache_rate}%"})
    if total >= 5 and cache_rate <= 5.0:
        anomalies.append({"code": "cache_starvation", "detail": f"cache_hit_rate={cache_rate}%"})
    return {
        "count": total,
        "dominant_strategy": dominant[0],
        "dominant_share_percent": dominant_share,
        "cache_hit_rate_percent": cache_rate,
        "anomalies": anomalies,
        "anomaly_count": len(anomalies),
        "message": (
            f"Detected {len(anomalies)} attribution anomalies."
            if anomalies
            else "No attribution anomalies detected."
        ),
    }


def warmup_budget_remaining(db: Session, *, max_per_hour: int = 3) -> dict[str, Any]:
    """Item 226: warmup budget remaining without consuming quota."""
    probe = warmup_eligibility_probe(db, max_per_hour=max_per_hour)
    used = int(probe.get("count") or 0)
    cap = int(probe.get("max_per_hour") or max_per_hour)
    remaining = max(0, cap - used)
    return {
        **probe,
        "remaining": remaining,
        "used": used,
        "message": f"Warmup budget remaining {remaining}/{cap} this hour.",
    }


def latency_budget_guard(
    db: Session,
    *,
    observed_ms: Optional[float] = None,
    budget_ms: Optional[float] = None,
) -> dict[str, Any]:
    """Item 227: latency budget guard evaluation."""
    cfg = _rt_get(db, _LATENCY_BUDGET_KEY, "{}")
    if not isinstance(cfg, dict):
        cfg = {}
    budget = float(budget_ms if budget_ms is not None else cfg.get("budget_ms") or 2500.0)
    observed = float(observed_ms if observed_ms is not None else cfg.get("last_observed_ms") or 0.0)
    within = observed <= budget if observed > 0 else True
    payload = {
        "budget_ms": budget,
        "observed_ms": observed,
        "within_budget": within,
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    if observed_ms is not None or budget_ms is not None:
        store = {"budget_ms": budget, "last_observed_ms": observed, "updated_at": payload["updated_at"]}
        _rt_set(db, _LATENCY_BUDGET_KEY, store, "Latency budget guard")
        record_ops_activity(db, action="latency_budget_guard", detail=store)
    return {
        **payload,
        "message": (
            f"Latency within budget ({observed}ms ≤ {budget}ms)."
            if within
            else f"Latency exceeds budget ({observed}ms > {budget}ms)."
        ),
    }


def cost_quality_pareto_frontier(db: Session, *, limit: int = 12) -> dict[str, Any]:
    """Item 228: cost–quality Pareto frontier from model rankings."""
    from app.services.gateway_leadership import build_model_liquidity_ranking

    try:
        rankings = build_model_liquidity_ranking(db, hours=24, limit=max(5, min(int(limit), 50)))
    except Exception:  # noqa: BLE001
        rankings = {"ranked": []}
    models = rankings.get("ranked") or rankings.get("models") or rankings.get("rankings") or []
    if not isinstance(models, list):
        models = []
    points = []
    for row in models[: max(5, min(int(limit), 50))]:
        if not isinstance(row, dict):
            continue
        quality = float(row.get("quality_score") or row.get("score") or row.get("rank_score") or 0.0)
        cost = float(
            row.get("avg_cost_cents")
            or row.get("avg_cost")
            or row.get("cost_score")
            or row.get("unit_cost")
            or 0.0
        )
        points.append(
            {
                "model_name": row.get("model_name") or row.get("model"),
                "provider_type": row.get("provider_type") or row.get("provider"),
                "quality": quality,
                "cost": cost,
            }
        )
    # Simple 2D Pareto: keep points not dominated (higher quality, lower cost preferred).
    frontier = []
    for candidate in points:
        dominated = False
        for other in points:
            if other is candidate:
                continue
            if other["quality"] >= candidate["quality"] and other["cost"] <= candidate["cost"] and (
                other["quality"] > candidate["quality"] or other["cost"] < candidate["cost"]
            ):
                dominated = True
                break
        if not dominated:
            frontier.append(candidate)
    frontier.sort(key=lambda p: (-p["quality"], p["cost"]))
    return {
        "count": len(points),
        "frontier_count": len(frontier),
        "frontier": frontier[:12],
        "message": f"Pareto frontier size {len(frontier)} from {len(points)} ranked models.",
    }


def failover_simulation_report(db: Session, *, primary_provider: str = "openai") -> dict[str, Any]:
    """Item 229: failover simulation report using fallback posture + light."""
    from app.services.gateway_best_practices import build_gateway_best_practices_posture

    try:
        posture = build_gateway_best_practices_posture(db)
    except Exception:  # noqa: BLE001
        posture = {}
    light = build_traffic_light(db)
    primary = str(primary_provider or "openai").strip().lower()
    checks = posture.get("checks") or []
    fallback_check = next(
        (c for c in checks if isinstance(c, dict) and "fallback" in str(c.get("id") or "").lower()),
        None,
    )
    fallback_ready = bool(
        (fallback_check or {}).get("passed")
        or posture.get("fallback_ready")
        or int(posture.get("score") or 0) >= 50
    )
    report = {
        "simulated_primary_outage": primary,
        "fallback_ready": fallback_ready,
        "traffic_light": light.get("light"),
        "score": light.get("score"),
        "posture_score": posture.get("score") or posture.get("posture_score"),
        "recommendation": (
            "Failover path looks ready — keep ranked fallback chain warm."
            if fallback_ready and str(light.get("light") or "").lower() != "red"
            else "Harden fallback chain and resolve RED/floor gaps before drill."
        ),
        "simulation_id": f"failover-{uuid4()}",
        "generated_at": datetime.utcnow().isoformat() + "Z",
    }
    record_ops_activity(db, action="failover_simulation", detail={"primary": primary, "ready": fallback_ready})
    return {**report, "message": report["recommendation"]}


def model_card_freshness_gate(db: Session, *, max_age_days: int = 30) -> dict[str, Any]:
    """Item 230: model-card freshness gate using runtime marker."""
    cfg = _rt_get(db, _MODEL_CARD_FRESHNESS_KEY, "{}")
    if not isinstance(cfg, dict):
        cfg = {}
    refreshed_at = str(cfg.get("refreshed_at") or "")
    age_days = None
    fresh = False
    if refreshed_at:
        try:
            ts = datetime.fromisoformat(refreshed_at.replace("Z", ""))
            age_days = max(0, (datetime.utcnow() - ts).days)
            fresh = age_days <= int(max_age_days)
        except ValueError:
            fresh = False
    return {
        "passed": fresh,
        "fresh": fresh,
        "refreshed_at": refreshed_at or None,
        "age_days": age_days,
        "max_age_days": int(max_age_days),
        "message": (
            f"Model cards fresh ({age_days}d ≤ {max_age_days}d)."
            if fresh
            else "Model cards stale or never refreshed — refresh model cards."
        ),
    }


def refresh_model_card_freshness_marker(db: Session) -> dict[str, Any]:
    """Item 230 helper: mark model cards refreshed now."""
    payload = {"refreshed_at": datetime.utcnow().isoformat() + "Z"}
    _rt_set(db, _MODEL_CARD_FRESHNESS_KEY, payload, "Model card freshness marker")
    record_ops_activity(db, action="model_card_freshness_refresh", detail=payload)
    return {**payload, "message": "Model-card freshness marker updated."}


def composite_with_compliance_evidence(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 231: attach compliance evidence pointers to composite gate."""
    composite = composite_go_no_go(db, hours=hours)
    cards = model_card_freshness_gate(db)
    evidence = {
        "evidence_id": f"ev-lead-{uuid4()}",
        "composite_decision": composite.get("decision"),
        "traffic_light": (composite.get("traffic_light") or {}).get("light"),
        "model_cards_fresh": cards.get("fresh"),
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "bundle_refs": [
            "leadership-day-rollup.md",
            "auto-route-audit-export",
            "pack-registry.md",
        ],
    }
    return {
        **composite,
        "compliance_evidence": evidence,
        "message": (
            f"Composite {composite.get('decision')} with compliance evidence {evidence['evidence_id']}."
        ),
    }


def incident_timeline_markdown(db: Session, *, limit: int = 20) -> dict[str, Any]:
    """Item 232: incident timeline markdown export."""
    listed = list_leadership_incidents(db, limit=limit, status=None)
    rows = listed.get("incidents") or []
    lines = ["# Leadership Incident Timeline", ""]
    if not rows:
        lines.append("_No incidents recorded._")
    for row in rows:
        lines.append(
            f"- `{row.get('incident_id')}` · {row.get('status')} · "
            f"sev={row.get('severity')} · {row.get('opened_at') or row.get('created_at')} · "
            f"{row.get('title') or row.get('summary') or ''}"
        )
    md = "\n".join(lines) + "\n"
    return {
        "markdown": md,
        "filename": f"leadership-incident-timeline-{datetime.utcnow().strftime('%Y%m%d')}.md",
        "count": len(rows),
    }


def operator_session_activity_export(db: Session, *, limit: int = 40) -> dict[str, Any]:
    """Item 233: export recent operator leadership activity."""
    activity = list_ops_activity(db, limit=limit)
    rows = activity.get("activities") or activity.get("events") or activity.get("items") or []
    if not isinstance(rows, list):
        rows = []
    clipped = rows[: max(1, min(int(limit), 100))]
    return {
        "count": len(clipped),
        "events": clipped,
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "message": f"Exported {len(clipped)} ops activity events.",
    }


def cross_env_leadership_sync_dry_run(
    db: Session,
    *,
    source_env: str = "staging",
    target_env: str = "prod",
) -> dict[str, Any]:
    """Item 234: dry-run sync of leadership controls across envs (no apply)."""
    shadow = get_shadow_traffic_percent(db)
    canary = get_canary_auto_rollback(db)
    preferred = {}
    try:
        from app.services.gateway_leadership_pack15 import get_preferred_model_override

        preferred = get_preferred_model_override(db)
    except Exception:  # noqa: BLE001
        preferred = {}
    plan = {
        "source_env": source_env,
        "target_env": target_env,
        "dry_run": True,
        "would_sync": [
            {"key": "shadow_traffic_percent", "value": shadow},
            {"key": "canary_auto_rollback", "value": canary},
            {"key": "preferred_model", "value": preferred},
        ],
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "message": f"Dry-run sync plan {source_env} → {target_env} (not applied).",
    }
    record_ops_activity(
        db,
        action="cross_env_leadership_sync_dry_run",
        detail={"source_env": source_env, "target_env": target_env},
    )
    return plan


def playground_leadership_diagnose(db: Session) -> dict[str, Any]:
    """Item 235: one-shot playground diagnose bundle."""
    light = build_traffic_light(db)
    anomalies = attribution_anomaly_detector(db, limit=50)
    warmup = warmup_budget_remaining(db)
    preferred = {}
    try:
        from app.services.gateway_leadership_pack15 import get_preferred_model_override

        preferred = get_preferred_model_override(db)
    except Exception:  # noqa: BLE001
        preferred = {}
    red = str(light.get("light") or "").lower() == "red"
    return {
        "traffic_light": light.get("light"),
        "score": light.get("score"),
        "anomaly_count": anomalies.get("anomaly_count"),
        "warmup_remaining": warmup.get("remaining"),
        "preferred_model": preferred.get("model_name"),
        "preferred_enabled": preferred.get("enabled"),
        "warn": red or int(anomalies.get("anomaly_count") or 0) > 0,
        "message": (
            "Playground diagnose: RED or anomalies — review Routing Gateway leadership drawers."
            if red or int(anomalies.get("anomaly_count") or 0) > 0
            else "Playground diagnose: posture looks operable."
        ),
    }


def overview_executive_strip(db: Session) -> dict[str, Any]:
    """Item 236: compact payload for Overview executive chips."""
    brief = executive_leadership_brief(db)
    return {
        "traffic_light": brief.get("traffic_light"),
        "score": brief.get("score"),
        "decision": brief.get("decision"),
        "score_delta": brief.get("score_delta"),
        "open_incidents": brief.get("open_incidents"),
        "label": f"{str(brief.get('traffic_light') or '?').upper()} {brief.get('score') or ''} Δ{brief.get('score_delta')}".strip(),
        "message": brief.get("message"),
    }


def apply_shadow_traffic_metadata(decision: dict[str, Any], shadow_cfg: dict[str, Any]) -> dict[str, Any]:
    """Item 237: attach soft shadow-traffic metadata to an auto-route decision (non-mutating select)."""
    out = dict(decision or {})
    enabled = bool((shadow_cfg or {}).get("enabled"))
    percent = float((shadow_cfg or {}).get("percent") or 0.0)
    out["shadow_traffic"] = {
        "enabled": enabled,
        "percent": percent,
        "soft": True,
        "note": "Shadow percent is advisory metadata; live mirroring uses route traffic controls.",
    }
    return out


def pack16_manifest() -> dict[str, Any]:
    """Item 238: Pack 16 capability manifest."""
    return {
        "pack": 16,
        "items": list(range(221, 241)),
        "theme": "Executive moat + operator excellence",
        "gov": "GOV-AI-MARKET-016",
    }
