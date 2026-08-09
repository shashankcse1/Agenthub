"""Pack 12 leadership deepeners (items 141–160)."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models import RoutePolicy
from app.services.gateway_leadership_pack10 import (
    build_traffic_light,
    list_ops_activity,
    record_ops_activity,
)
from app.services.gateway_leadership_pack11 import (
    annotate_route_circuit_breaker_notes,
    correlate_budget_auto_route,
    evaluate_canary_promote_gate,
    export_operator_runbook,
    get_enforcement_flags,
    get_model_route_policy,
)


_CACHE_STATS_KEY = "gateway.leadership.decision_cache_stats_json"


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


def bump_decision_cache_stat(db: Session, *, hit: bool) -> None:
    """Item 146: decision cache hit-rate counter."""
    stats = _rt_get(db, _CACHE_STATS_KEY, "{}")
    if not isinstance(stats, dict):
        stats = {}
    stats["hits"] = int(stats.get("hits") or 0) + (1 if hit else 0)
    stats["misses"] = int(stats.get("misses") or 0) + (0 if hit else 1)
    total = int(stats["hits"]) + int(stats["misses"])
    stats["hit_rate_percent"] = round(100.0 * int(stats["hits"]) / total, 2) if total else 0.0
    stats["updated_at"] = datetime.utcnow().isoformat() + "Z"
    _rt_set(db, _CACHE_STATS_KEY, stats, "Auto-route decision cache hit stats")


def get_decision_cache_stats(db: Session) -> dict[str, Any]:
    stats = _rt_get(db, _CACHE_STATS_KEY, "{}")
    if not isinstance(stats, dict):
        stats = {}
    return {
        "hits": int(stats.get("hits") or 0),
        "misses": int(stats.get("misses") or 0),
        "hit_rate_percent": float(stats.get("hit_rate_percent") or 0),
        "updated_at": stats.get("updated_at"),
    }


def invalidate_decision_cache(db: Session) -> dict[str, Any]:
    """Item 141: flush auto-route decision TTL cache."""
    from app.services.runtime_config import upsert_runtime_config_value

    upsert_runtime_config_value(
        db,
        "gateway.leadership.auto_route_cache_json",
        "{}",
        description="Auto-route decision TTL cache",
    )
    record_ops_activity(db, action="decision_cache_invalidate", detail={})
    return {"invalidated": True, "message": "Auto-route decision cache cleared."}


def flush_cache_after_warmup(db: Session) -> dict[str, Any]:
    """Item 154: warmup companion cache flush."""
    result = invalidate_decision_cache(db)
    return {**result, "companion": "warmup", "message": "Decision cache flushed after warmup."}


def compare_traffic_light_floors(
    db: Session,
    *,
    floors: Optional[list[float]] = None,
    hours: int = 24,
) -> dict[str, Any]:
    """Item 149: multi-floor traffic light compare."""
    values = floors or [50.0, 70.0, 85.0]
    rows = []
    for floor in values[:5]:
        light = build_traffic_light(db, hours=hours, floor_score=float(floor))
        rows.append({"floor_score": float(floor), "light": light.get("light"), "score": light.get("score")})
    return {"hours": hours, "comparisons": rows}


def readiness_leadership_delta(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 150: readiness vs leadership score delta."""
    from app.services.gateway_leadership import build_gateway_leadership_index
    from app.services.inference_readiness import build_inference_readiness

    index = build_gateway_leadership_index(db, hours=hours, exclude_warmup=True)
    ready = build_inference_readiness(db)
    score = float(index.get("score") or 0)
    ready_n = int(ready.get("ready_providers") or 0)
    total_n = max(1, int(ready.get("provider_count") or ready.get("total_providers") or ready_n or 1))
    readiness_pct = round(100.0 * ready_n / total_n, 2)
    return {
        "hours": hours,
        "leadership_score": score,
        "ready_providers": ready_n,
        "readiness_percent": readiness_pct,
        "delta": round(score - readiness_pct, 2),
        "message": (
            "Leadership leads readiness."
            if score >= readiness_pct
            else "Readiness leads leadership — check attribution coverage."
        ),
    }


def filter_ops_activity(db: Session, *, action_prefix: str = "", limit: int = 20) -> dict[str, Any]:
    """Item 151: ops activity filter by action prefix."""
    activity = list_ops_activity(db, limit=100)
    rows = list(activity.get("activities") or [])
    prefix = str(action_prefix or "").strip().lower()
    if prefix:
        rows = [row for row in rows if str(row.get("action") or "").lower().startswith(prefix)]
    return {"count": min(len(rows), limit), "activities": rows[: max(1, min(limit, 100))], "action_prefix": prefix}


def budget_correlation_warning(db: Session, *, hours: int = 168, warn_avg_cents: float = 50.0) -> dict[str, Any]:
    """Item 152: budget correlation threshold warning."""
    corr = correlate_budget_auto_route(db, hours=hours)
    avg = float(corr.get("avg_auto_routed_cost_cents") or 0)
    warned = avg >= float(warn_avg_cents)
    return {
        **corr,
        "warn_avg_cents": warn_avg_cents,
        "warning": warned,
        "message": (
            f"Auto-routed avg cost {avg}¢ exceeds warn floor {warn_avg_cents}¢."
            if warned
            else f"Auto-routed avg cost {avg}¢ within warn floor {warn_avg_cents}¢."
        ),
    }


def canary_annotate_combo(
    db: Session,
    *,
    route_policy_id: str,
    floor_score: float = 70.0,
    annotate_if_passed: bool = True,
) -> dict[str, Any]:
    """Item 153: canary gate + optional circuit annotate."""
    gate = evaluate_canary_promote_gate(db, route_policy_id=route_policy_id, floor_score=floor_score)
    annotated = None
    if gate.get("passed") and annotate_if_passed:
        annotated = annotate_route_circuit_breaker_notes(db, route_policy_id=route_policy_id)
    return {
        "gate": gate,
        "annotated": annotated,
        "message": (
            "Canary passed; circuit notes annotated."
            if gate.get("passed") and annotated
            else gate.get("message")
        ),
    }


def read_route_circuit_notes(db: Session, *, route_policy_id: str) -> dict[str, Any]:
    """Item 148: surface circuit-breaker notes on route readback."""
    route = db.query(RoutePolicy).filter_by(route_policy_id=str(route_policy_id or "").strip()).first()
    if not route:
        return {"found": False, "notes": None, "message": "Route not found."}
    try:
        fallback = json.loads(route.fallback_policy or "{}")
    except json.JSONDecodeError:
        fallback = {}
    notes = fallback.get("circuit_breaker_notes") if isinstance(fallback, dict) else None
    return {
        "found": True,
        "route_policy_id": route.route_policy_id,
        "notes": notes,
        "has_notes": bool(notes),
    }


def leadership_posture_digest(db: Session) -> dict[str, Any]:
    """Item 159: compact leadership posture digest for Overview."""
    light = build_traffic_light(db, hours=24, floor_score=70)
    flags = get_enforcement_flags(db)["flags"]
    policy = get_model_route_policy(db)
    cache = get_decision_cache_stats(db)
    delta = readiness_leadership_delta(db)
    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "traffic_light": light.get("light"),
        "score": light.get("score"),
        "ready_providers": delta.get("ready_providers"),
        "cache_hit_rate_percent": cache.get("hit_rate_percent"),
        "denylist_count": len(policy.get("denylist") or []),
        "allowlist_count": len(policy.get("allowlist") or []),
        "enforcement": {
            "pii": flags.get("enforce_pii_bias"),
            "adversarial": flags.get("enforce_adversarial_boost"),
            "denylist": flags.get("enforce_model_denylist"),
            "cache": flags.get("use_decision_cache"),
        },
    }


def export_runbook_markdown(db: Session) -> dict[str, Any]:
    """Item 156: runbook markdown export payload."""
    runbook = export_operator_runbook(db)
    return {
        "filename": f"leadership-runbook-{datetime.utcnow().strftime('%Y%m%d')}.md",
        "content_type": "text/markdown",
        "markdown": runbook.get("markdown") or "",
        "current_light": runbook.get("current_light"),
        "current_score": runbook.get("current_score"),
    }


def pack12_manifest() -> dict[str, Any]:
    return {
        "pack": 12,
        "items": list(range(141, 161)),
        "theme": "Cache/ops residual close + posture digest",
        "gov": "GOV-AI-MARKET-012",
    }
