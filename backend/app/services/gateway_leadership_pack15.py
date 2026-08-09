"""Pack 15 leadership deepeners (items 201–220)."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.services.gateway_leadership_pack10 import build_traffic_light, record_ops_activity
from app.services.gateway_leadership_pack14 import (
    checklist_completion_gate,
    leadership_day_rollup,
    leadership_floor_gate,
    list_auto_route_audit,
    list_leadership_incidents,
    open_leadership_incident,
    score_trend_with_mute,
)


_PREFERRED_MODEL_KEY = "gateway.leadership.preferred_model_override_json"
_AUDIT_KEY = "gateway.leadership.auto_route_audit_json"
_INCIDENT_KEY = "gateway.leadership.incidents_json"
_TREND_MUTE_KEY = "gateway.leadership.score_trend_mute_json"
_TAG_STRATEGY_KEY = "gateway.leadership.request_tag_strategy_policies_json"
_ROUTE_STRATEGY_KEY = "gateway.leadership.route_strategy_policies_json"


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


def composite_go_no_go(
    db: Session,
    *,
    floor_score: float = 70.0,
    checklist_min_percent: float = 50.0,
    hours: int = 24,
) -> dict[str, Any]:
    """Item 201: composite go/no-go from floor + checklist + traffic light."""
    floor = leadership_floor_gate(db, floor_score=floor_score, hours=hours)
    checklist = checklist_completion_gate(db, min_percent=checklist_min_percent)
    light = build_traffic_light(db, hours=hours, floor_score=floor_score)
    light_ok = str(light.get("light") or "").lower() != "red"
    passed = bool(floor.get("passed")) and bool(checklist.get("passed")) and light_ok
    return {
        "passed": passed,
        "decision": "go" if passed else "no-go",
        "floor": floor,
        "checklist": checklist,
        "traffic_light": light,
        "message": (
            "Composite leadership gate passed."
            if passed
            else "Composite leadership gate failed — review floor, checklist, and traffic light."
        ),
    }


def unmute_score_trend(db: Session) -> dict[str, Any]:
    """Item 202: clear score-trend mute."""
    _rt_set(db, _TREND_MUTE_KEY, {}, "Score-trend alert mute window")
    record_ops_activity(db, action="score_trend_unmute", detail={})
    return {"unmuted": True, "message": "Score-trend mute cleared."}


def auto_route_audit_summary(db: Session, *, limit: int = 100) -> dict[str, Any]:
    """Item 203: auto-route audit summary stats."""
    listed = list_auto_route_audit(db, limit=limit)
    rows = listed.get("audits") or []
    by_strategy: dict[str, int] = {}
    by_tier: dict[str, int] = {}
    cache_hits = 0
    for row in rows:
        strategy = str(row.get("strategy") or "unknown")
        tier = str(row.get("tier") or "unknown")
        by_strategy[strategy] = by_strategy.get(strategy, 0) + 1
        by_tier[tier] = by_tier.get(tier, 0) + 1
        if row.get("cache_hit"):
            cache_hits += 1
    return {
        "count": len(rows),
        "cache_hits": cache_hits,
        "cache_hit_rate_percent": round(100.0 * cache_hits / len(rows), 2) if rows else 0.0,
        "by_strategy": by_strategy,
        "by_tier": by_tier,
    }


def purge_auto_route_audit(db: Session, *, keep: int = 20) -> dict[str, Any]:
    """Item 204: purge older auto-route audit rows."""
    rows = _rt_get(db, _AUDIT_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    keep_n = max(0, min(int(keep), 100))
    kept = rows[:keep_n]
    purged = max(0, len(rows) - len(kept))
    _rt_set(db, _AUDIT_KEY, kept, "Auto-route decision audit trail")
    record_ops_activity(db, action="auto_route_audit_purge", detail={"kept": len(kept), "purged": purged})
    return {"kept": len(kept), "purged": purged}


def export_auto_route_audit(db: Session, *, limit: int = 50) -> dict[str, Any]:
    """Item 205: export auto-route audit JSON."""
    listed = list_auto_route_audit(db, limit=limit)
    return {
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "filename": f"auto-route-audit-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json",
        **listed,
    }


def escalate_leadership_incident(db: Session, *, incident_id: str, severity: str = "critical") -> dict[str, Any]:
    """Item 206: escalate incident severity."""
    rows = _rt_get(db, _INCIDENT_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    target = str(incident_id or "").strip()
    for row in rows:
        if str(row.get("incident_id")) == target:
            row["severity"] = str(severity or "critical")[:32]
            row["escalated_at"] = datetime.utcnow().isoformat() + "Z"
            _rt_set(db, _INCIDENT_KEY, rows[:100], "Leadership incidents")
            record_ops_activity(db, action="leadership_incident_escalate", detail={"incident_id": target})
            return {"escalated": True, "incident": row}
    return {"escalated": False, "message": "Incident not found."}


def bulk_close_open_incidents(db: Session, *, limit: int = 20) -> dict[str, Any]:
    """Item 207: bulk close open incidents."""
    rows = _rt_get(db, _INCIDENT_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    closed = []
    for row in rows:
        if row.get("status") != "open":
            continue
        if len(closed) >= max(1, min(int(limit), 50)):
            break
        row["status"] = "closed"
        row["closed_at"] = datetime.utcnow().isoformat() + "Z"
        closed.append(row.get("incident_id"))
    _rt_set(db, _INCIDENT_KEY, rows[:100], "Leadership incidents")
    record_ops_activity(db, action="leadership_incident_bulk_close", detail={"count": len(closed)})
    return {"closed_count": len(closed), "incident_ids": closed}


def floor_gate_with_auto_incident(
    db: Session,
    *,
    floor_score: float = 70.0,
    hours: int = 24,
    open_incident_on_fail: bool = True,
) -> dict[str, Any]:
    """Item 208: floor gate optionally opens incident on fail."""
    gate = leadership_floor_gate(db, floor_score=floor_score, hours=hours)
    incident = None
    if open_incident_on_fail and not gate.get("passed"):
        incident = open_leadership_incident(
            db,
            title="Leadership floor gate failed",
            severity="warning",
            detail=f"score={gate.get('score')} floor={floor_score}",
        )
    return {**gate, "incident": incident}


def probe_red_light_incident(db: Session, *, open_incident: bool = True) -> dict[str, Any]:
    """Item 209: probe RED traffic light and optionally open incident."""
    light = build_traffic_light(db, hours=24, floor_score=70)
    incident = None
    is_red = str(light.get("light") or "").lower() == "red"
    if is_red and open_incident:
        incident = open_leadership_incident(
            db,
            title="Leadership traffic light RED",
            severity="critical",
            detail=f"score={light.get('score')}",
        )
    return {
        "light": light.get("light"),
        "score": light.get("score"),
        "is_red": is_red,
        "incident": incident,
        "message": "RED probe opened incident." if incident else ("Traffic light not red." if not is_red else "RED detected; incident not opened."),
    }


def get_preferred_model_override(db: Session) -> dict[str, Any]:
    """Item 210: preferred-model soft override read."""
    raw = _rt_get(db, _PREFERRED_MODEL_KEY, "{}")
    if not isinstance(raw, dict):
        raw = {}
    return {
        "model_name": raw.get("model_name"),
        "provider_type": raw.get("provider_type"),
        "enabled": bool(raw.get("enabled")),
        "updated_at": raw.get("updated_at"),
    }


def upsert_preferred_model_override(
    db: Session,
    *,
    model_name: str,
    provider_type: Optional[str] = None,
    enabled: bool = True,
) -> dict[str, Any]:
    policy = {
        "model_name": str(model_name or "").strip(),
        "provider_type": str(provider_type or "").strip().lower() or None,
        "enabled": bool(enabled),
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    _rt_set(db, _PREFERRED_MODEL_KEY, policy, "Preferred model soft override")
    record_ops_activity(db, action="preferred_model_upsert", detail={"model": policy["model_name"]})
    return policy


def clear_preferred_model_override(db: Session) -> dict[str, Any]:
    """Item 212: clear preferred-model override."""
    _rt_set(db, _PREFERRED_MODEL_KEY, {}, "Preferred model soft override")
    record_ops_activity(db, action="preferred_model_clear", detail={})
    return {"cleared": True, "enabled": False, "model_name": None}


def apply_preferred_model_bias(decision: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Item 211 helper: soft-bias selected model when override enabled and present in candidates."""
    if not override.get("enabled"):
        return decision
    preferred = str(override.get("model_name") or "").strip()
    if not preferred:
        return decision
    tier = str((decision.get("complexity") or {}).get("tier") or "simple")
    candidates = list((decision.get("tier_candidates") or {}).get(tier) or [])
    match = next((row for row in candidates if str(row.get("model_name") or "") == preferred), None)
    if not match:
        decision["preferred_model_bias"] = {"applied": False, "reason": "preferred_not_in_candidates"}
        return decision
    provider_filter = str(override.get("provider_type") or "").strip().lower()
    if provider_filter and str(match.get("provider_type") or "").lower() != provider_filter:
        decision["preferred_model_bias"] = {"applied": False, "reason": "provider_mismatch"}
        return decision
    decision["selected"] = match
    decision["selected_model"] = match.get("model_name")
    decision["selected_provider_type"] = match.get("provider_type")
    decision["preferred_model_bias"] = {"applied": True, "model_name": preferred}
    decision["rationale"] = (
        str(decision.get("rationale") or "")
        + f" Preferred-model soft override applied ({preferred})."
    )
    return decision


def export_day_rollup_markdown(db: Session) -> dict[str, Any]:
    """Item 213: day-rollup markdown export."""
    rollup = leadership_day_rollup(db)
    posture = rollup.get("posture") or {}
    md = (
        f"# Leadership Day Rollup\n\n"
        f"- Generated: {rollup.get('generated_at')}\n"
        f"- Light: {posture.get('traffic_light')} ({posture.get('score')})\n"
        f"- Open incidents: {rollup.get('open_incidents')}\n"
        f"- Checklist completion: {rollup.get('checklist_completion_percent')}%\n"
        f"- Trend alert: {(rollup.get('trend') or {}).get('alert')}\n"
    )
    return {
        "markdown": md,
        "filename": f"leadership-day-rollup-{datetime.utcnow().strftime('%Y%m%d')}.md",
        "rollup": rollup,
    }


def delete_request_tag_strategy_policy(db: Session, *, request_tag: str) -> dict[str, Any]:
    """Item 215: delete request-tag strategy policy."""
    tag = str(request_tag or "").strip()
    rows = _rt_get(db, _TAG_STRATEGY_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    kept = [row for row in rows if str(row.get("request_tag") or "") != tag]
    removed = len(rows) - len(kept)
    _rt_set(db, _TAG_STRATEGY_KEY, kept[:200], "Per-request-tag auto-route strategy policies")
    record_ops_activity(db, action="request_tag_strategy_delete", detail={"request_tag": tag, "removed": removed})
    return {"removed": removed, "request_tag": tag}


def delete_route_strategy_policy(db: Session, *, route_policy_id: str) -> dict[str, Any]:
    """Item 216: delete route strategy policy."""
    route_id = str(route_policy_id or "").strip()
    rows = _rt_get(db, _ROUTE_STRATEGY_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    kept = [row for row in rows if str(row.get("route_policy_id") or "") != route_id]
    removed = len(rows) - len(kept)
    _rt_set(db, _ROUTE_STRATEGY_KEY, kept[:200], "Per-route auto-route strategy policies")
    record_ops_activity(db, action="route_strategy_delete", detail={"route_policy_id": route_id, "removed": removed})
    return {"removed": removed, "route_policy_id": route_id}


def leadership_digest_webhook_payload(db: Session, *, dry_run: bool = True) -> dict[str, Any]:
    """Item 217: leadership digest webhook dry-run payload."""
    composite = composite_go_no_go(db)
    rollup = leadership_day_rollup(db)
    trend = score_trend_with_mute(db)
    incidents = list_leadership_incidents(db, limit=5, status="open")
    payload = {
        "source": "agenthub-leadership-digest",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "composite_decision": composite.get("decision"),
        "traffic_light": (composite.get("traffic_light") or {}).get("light"),
        "score": (composite.get("traffic_light") or {}).get("score"),
        "open_incidents": incidents.get("count"),
        "checklist_completion_percent": rollup.get("checklist_completion_percent"),
        "trend_effective_alert": trend.get("effective_alert"),
    }
    return {
        "dry_run": bool(dry_run),
        "payload": payload,
        "message": "Dry-run digest payload prepared." if dry_run else "Digest payload ready for allowlisted delivery.",
    }


def pack15_manifest() -> dict[str, Any]:
    return {
        "pack": 15,
        "items": list(range(201, 221)),
        "theme": "Composite gates + audit hygiene",
        "gov": "GOV-AI-MARKET-015",
    }
