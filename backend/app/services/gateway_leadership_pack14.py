"""Pack 14 leadership deepeners (items 181–200)."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import RoutePolicy
from app.services.gateway_leadership_pack10 import record_ops_activity
from app.services.gateway_leadership_pack11 import (
    DEFAULT_FLAGS,
    correlate_budget_auto_route,
    get_enforcement_flags,
    upsert_enforcement_flags,
)
from app.services.gateway_leadership_pack12 import leadership_posture_digest
from app.services.gateway_leadership_pack13 import (
    detect_score_trend,
    get_operator_checklist,
    on_demand_leadership_snapshot,
    pack_capability_registry,
    route_health_score,
)


_AUDIT_KEY = "gateway.leadership.auto_route_audit_json"
_INCIDENT_KEY = "gateway.leadership.incidents_json"
_TREND_MUTE_KEY = "gateway.leadership.score_trend_mute_json"


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


def record_auto_route_audit(
    db: Session,
    *,
    decision: dict[str, Any],
    source: str = "preview",
) -> dict[str, Any]:
    """Item 181: persist auto-route decision audit trail."""
    rows = _rt_get(db, _AUDIT_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    entry = {
        "audit_id": f"ara-{uuid4().hex[:10]}",
        "recorded_at": datetime.utcnow().isoformat() + "Z",
        "source": str(source or "preview")[:64],
        "selected_model": decision.get("selected_model"),
        "strategy": decision.get("strategy"),
        "tier": (decision.get("complexity") or {}).get("tier"),
        "score": (decision.get("complexity") or {}).get("score"),
        "cache_hit": decision.get("cache_hit"),
        "strategy_policy_source": (decision.get("strategy_policy") or {}).get("source"),
        "catalog_after": (decision.get("catalog_policy") or {}).get("catalog_after"),
    }
    rows.insert(0, entry)
    _rt_set(db, _AUDIT_KEY, rows[:100], "Auto-route decision audit trail")
    return entry


def list_auto_route_audit(db: Session, *, limit: int = 20) -> dict[str, Any]:
    rows = _rt_get(db, _AUDIT_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    return {"count": min(len(rows), limit), "audits": rows[: max(1, min(limit, 100))]}


def open_leadership_incident(
    db: Session,
    *,
    title: str,
    severity: str = "warning",
    detail: Optional[str] = None,
) -> dict[str, Any]:
    """Item 182: open leadership incident."""
    rows = _rt_get(db, _INCIDENT_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    incident = {
        "incident_id": f"inc-{uuid4().hex[:10]}",
        "title": str(title or "leadership incident")[:200],
        "severity": str(severity or "warning")[:32],
        "detail": str(detail or "")[:500],
        "status": "open",
        "opened_at": datetime.utcnow().isoformat() + "Z",
        "closed_at": None,
    }
    rows.insert(0, incident)
    _rt_set(db, _INCIDENT_KEY, rows[:100], "Leadership incidents")
    record_ops_activity(db, action="leadership_incident_open", detail={"incident_id": incident["incident_id"]})
    return incident


def close_leadership_incident(db: Session, *, incident_id: str) -> dict[str, Any]:
    rows = _rt_get(db, _INCIDENT_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    target = str(incident_id or "").strip()
    for row in rows:
        if str(row.get("incident_id")) == target:
            row["status"] = "closed"
            row["closed_at"] = datetime.utcnow().isoformat() + "Z"
            _rt_set(db, _INCIDENT_KEY, rows[:100], "Leadership incidents")
            record_ops_activity(db, action="leadership_incident_close", detail={"incident_id": target})
            return {"closed": True, "incident": row}
    return {"closed": False, "message": "Incident not found."}


def list_leadership_incidents(db: Session, *, limit: int = 20, status: Optional[str] = None) -> dict[str, Any]:
    """Item 196: incident list/readback."""
    rows = _rt_get(db, _INCIDENT_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    if status:
        rows = [row for row in rows if str(row.get("status")) == str(status)]
    return {"count": min(len(rows), limit), "incidents": rows[: max(1, min(limit, 100))]}


def leadership_floor_gate(db: Session, *, floor_score: float = 70.0, hours: int = 24) -> dict[str, Any]:
    """Item 184: leadership floor gate for CI/benchmark."""
    from app.services.gateway_leadership import build_gateway_leadership_index

    index = build_gateway_leadership_index(db, hours=hours, exclude_warmup=True)
    score = float(index.get("score") or 0)
    passed = score >= float(floor_score)
    return {
        "passed": passed,
        "score": score,
        "floor_score": floor_score,
        "hours": hours,
        "band": index.get("band"),
        "decision": "go" if passed else "no-go",
        "message": "Leadership floor gate passed." if passed else "Leadership floor gate failed.",
    }


def pack_registry_markdown() -> dict[str, Any]:
    """Item 185: pack registry markdown export."""
    registry = pack_capability_registry()
    # Ensure pack14 included by caller after manifest exists.
    lines = ["# AgentHub Leadership Pack Registry", ""]
    for pack in registry.get("packs") or []:
        lines.append(f"- Pack {pack.get('pack')}: {pack.get('theme')} ({pack.get('gov')})")
    return {
        "markdown": "\n".join(lines) + "\n",
        "filename": f"leadership-pack-registry-{datetime.utcnow().strftime('%Y%m%d')}.md",
        "count": registry.get("count"),
    }


def estimate_auto_route_cost(db: Session, *, hours: int = 168) -> dict[str, Any]:
    """Item 186: auto-route cost estimate from correlation averages."""
    corr = correlate_budget_auto_route(db, hours=hours)
    return {
        "hours": hours,
        "estimated_avg_cost_cents": corr.get("avg_auto_routed_cost_cents"),
        "auto_routed_events": corr.get("auto_routed_events"),
        "other_avg_cost_cents": corr.get("avg_other_cost_cents"),
        "message": (
            f"Est. auto-route avg {corr.get('avg_auto_routed_cost_cents')}¢ "
            f"vs other {corr.get('avg_other_cost_cents')}¢ over {hours}h."
        ),
    }


def provider_diversity_score(decision: dict[str, Any]) -> dict[str, Any]:
    """Item 187: provider diversity across tier candidates."""
    candidates = decision.get("tier_candidates") or {}
    providers: set[str] = set()
    models = 0
    for rows in candidates.values():
        if not isinstance(rows, list):
            continue
        for row in rows:
            models += 1
            provider = str(row.get("provider_type") or "").strip().lower()
            if provider:
                providers.add(provider)
    score = round(100.0 * len(providers) / max(1, min(models, 8)), 2) if models else 0.0
    return {
        "provider_count": len(providers),
        "candidate_count": models,
        "diversity_score": min(100.0, score),
        "providers": sorted(providers),
    }


def mute_score_trend(db: Session, *, minutes: int = 60, reason: str = "") -> dict[str, Any]:
    """Item 188: mute score-trend alert temporarily."""
    until = datetime.utcnow() + timedelta(minutes=max(5, min(int(minutes), 24 * 60)))
    payload = {
        "muted_until": until.isoformat() + "Z",
        "reason": str(reason or "")[:200],
        "muted_at": datetime.utcnow().isoformat() + "Z",
    }
    _rt_set(db, _TREND_MUTE_KEY, payload, "Score-trend alert mute window")
    record_ops_activity(db, action="score_trend_mute", detail={"minutes": minutes})
    return payload


def score_trend_with_mute(db: Session, *, points: int = 6, decline_points: int = 3) -> dict[str, Any]:
    """Item 197: score trend including mute status."""
    trend = detect_score_trend(db, points=points, decline_points=decline_points)
    mute = _rt_get(db, _TREND_MUTE_KEY, "{}")
    if not isinstance(mute, dict):
        mute = {}
    muted = False
    muted_until = mute.get("muted_until")
    if muted_until:
        try:
            until = datetime.fromisoformat(str(muted_until).replace("Z", ""))
            muted = datetime.utcnow() < until
        except ValueError:
            muted = False
    effective_alert = bool(trend.get("alert")) and not muted
    return {
        **trend,
        "muted": muted,
        "muted_until": muted_until if muted else None,
        "effective_alert": effective_alert,
        "message": (
            "Score decline muted."
            if muted and trend.get("alert")
            else trend.get("message")
        ),
    }


def rollback_enforcement_flags(db: Session) -> dict[str, Any]:
    """Item 189: rollback enforcement flags to defaults."""
    result = upsert_enforcement_flags(db, flags=dict(DEFAULT_FLAGS))
    record_ops_activity(db, action="enforcement_flags_rollback", detail={})
    return {"rolled_back": True, **result}


def batch_route_health(db: Session, *, limit: int = 10) -> dict[str, Any]:
    """Item 190: batch route health scores."""
    routes = db.query(RoutePolicy).order_by(RoutePolicy.route_policy_id.asc()).limit(max(1, min(int(limit), 50))).all()
    rows = [route_health_score(db, route_policy_id=route.route_policy_id) for route in routes]
    return {"count": len(rows), "routes": rows}


def leadership_day_rollup(db: Session) -> dict[str, Any]:
    """Item 191: leadership day rollup."""
    digest = leadership_posture_digest(db)
    trend = score_trend_with_mute(db)
    incidents = list_leadership_incidents(db, limit=5, status="open")
    checklist = get_operator_checklist(db)
    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "posture": digest,
        "trend": {
            "alert": trend.get("effective_alert"),
            "scores": trend.get("scores"),
            "muted": trend.get("muted"),
        },
        "open_incidents": incidents.get("count"),
        "checklist_completion_percent": round(
            100.0 * int(checklist.get("completed_count") or 0) / max(1, int(checklist.get("total") or 1)),
            2,
        ),
    }


def checklist_completion_gate(db: Session, *, min_percent: float = 50.0) -> dict[str, Any]:
    """Item 193: checklist completion gate."""
    checklist = get_operator_checklist(db)
    pct = round(
        100.0 * int(checklist.get("completed_count") or 0) / max(1, int(checklist.get("total") or 1)),
        2,
    )
    passed = pct >= float(min_percent)
    return {
        "passed": passed,
        "completion_percent": pct,
        "min_percent": min_percent,
        "completed_count": checklist.get("completed_count"),
        "total": checklist.get("total"),
        "decision": "go" if passed else "hold",
        "message": "Checklist gate passed." if passed else "Checklist incomplete — hold promote/ops claim.",
    }


def decision_cache_inventory(db: Session) -> dict[str, Any]:
    """Item 194: decision cache entry count."""
    cache = _rt_get(db, "gateway.leadership.auto_route_cache_json", "{}")
    if not isinstance(cache, dict):
        cache = {}
    return {"entry_count": len(cache), "keys_sample": list(cache.keys())[:5]}


def nightly_trend_combo_report(db: Session) -> dict[str, Any]:
    """Item 195: on-demand snapshot + trend combo report."""
    snapshot = on_demand_leadership_snapshot(db, hours=24)
    trend = score_trend_with_mute(db)
    return {
        "report_id": f"ntr-{uuid4().hex[:10]}",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "snapshot": snapshot,
        "trend": trend,
        "markdown": (
            f"# Nightly+Trend Report\n\n"
            f"- Snapshot score: {snapshot.get('score')}\n"
            f"- Trend alert: {trend.get('effective_alert')}\n"
            f"- Scores: {', '.join(str(s) for s in (trend.get('scores') or []))}\n"
        ),
    }


def explain_snippet_from_decision(decision: dict[str, Any]) -> str:
    """Item 192 helper: short explain snippet for chat meta."""
    selected = decision.get("selected_model") or "none"
    tier = (decision.get("complexity") or {}).get("tier") or "?"
    strategy = decision.get("strategy") or "balanced"
    cache = "hit" if decision.get("cache_hit") else "miss"
    return f"{selected} tier={tier} strategy={strategy} cache={cache}"


def pack14_manifest() -> dict[str, Any]:
    return {
        "pack": 14,
        "items": list(range(181, 201)),
        "theme": "Decision audit + incident ops",
        "gov": "GOV-AI-MARKET-014",
    }


def pack_capability_registry_with_14() -> dict[str, Any]:
    base = pack_capability_registry()
    packs = list(base.get("packs") or [])
    if not any(row.get("pack") == 14 for row in packs):
        packs.append(pack14_manifest())
    return {"packs": packs, "count": len(packs)}
