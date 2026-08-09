"""Pack 13 leadership deepeners (items 161–180)."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models import RoutePolicy
from app.services.gateway_leadership import (
    build_gateway_leadership_index,
    list_leadership_history,
    record_leadership_snapshot,
)
from app.services.gateway_leadership_pack10 import (
    build_traffic_light,
    guard_warmup_rate_limit,
    record_ops_activity,
)
from app.services.gateway_leadership_pack11 import (
    DEFAULT_FLAGS,
    build_latency_histogram,
    get_enforcement_flags,
    get_model_route_policy,
    upsert_model_route_policy,
)
from app.services.gateway_leadership_pack12 import leadership_posture_digest
from app.services.inference_readiness import build_inference_readiness


_CHECKLIST_KEY = "gateway.leadership.operator_checklist_json"


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


def explain_auto_route_decision(
    db: Session,
    *,
    prompt_text: str,
    strategy: str = "balanced",
    prefer_live_only: bool = True,
    request_tag: Optional[str] = None,
    route_policy_id: Optional[str] = None,
) -> dict[str, Any]:
    """Item 161: explain selected model and near alternatives."""
    from app.services.gateway_leadership_pack11 import build_auto_route_with_pack11

    decision = build_auto_route_with_pack11(
        db,
        prompt_text=prompt_text,
        strategy=strategy,
        prefer_live_only=prefer_live_only,
        request_tag=request_tag,
        route_policy_id=route_policy_id,
        use_cache=False,
    )
    tier = str((decision.get("complexity") or {}).get("tier") or "simple")
    candidates = list((decision.get("tier_candidates") or {}).get(tier) or [])
    selected = decision.get("selected_model")
    alternatives = [
        {
            "model_name": row.get("model_name"),
            "provider_type": row.get("provider_type"),
            "live_ready": row.get("live_ready"),
            "source": row.get("source"),
        }
        for row in candidates
        if row.get("model_name") and row.get("model_name") != selected
    ][:5]
    return {
        "selected_model": selected,
        "selected_provider_type": decision.get("selected_provider_type"),
        "tier": tier,
        "strategy": decision.get("strategy"),
        "strategy_policy": decision.get("strategy_policy"),
        "catalog_policy": decision.get("catalog_policy"),
        "rationale": decision.get("rationale"),
        "alternatives": alternatives,
        "why_not_alternatives": (
            f"Selected {selected} for tier={tier} strategy={decision.get('strategy')}; "
            f"{len(alternatives)} other candidate(s) ranked below or not preferred."
            if selected
            else "No model selected — check catalog seeding and model allow/deny policy."
        ),
    }


def shadow_compare_strategies(
    db: Session,
    *,
    prompt_text: str,
    prefer_live_only: bool = True,
) -> dict[str, Any]:
    """Item 162: run balanced/cost/quality shadow compare."""
    from app.services.gateway_leadership_pack11 import build_auto_route_with_pack11

    rows = []
    for strategy in ("balanced", "cost", "quality"):
        decision = build_auto_route_with_pack11(
            db,
            prompt_text=prompt_text,
            strategy=strategy,
            prefer_live_only=prefer_live_only,
            use_cache=False,
            refine_with_judge=False,
        )
        rows.append(
            {
                "strategy": strategy,
                "selected_model": decision.get("selected_model"),
                "tier": (decision.get("complexity") or {}).get("tier"),
                "score": (decision.get("complexity") or {}).get("score"),
            }
        )
    unique_models = {row["selected_model"] for row in rows if row.get("selected_model")}
    return {
        "prompt_chars": len(prompt_text or ""),
        "comparisons": rows,
        "divergence": len(unique_models) > 1,
        "message": (
            "Strategies disagree on model — review cost/quality tradeoffs."
            if len(unique_models) > 1
            else "All strategies converge on the same model."
        ),
    }


def detect_score_trend(db: Session, *, points: int = 6, decline_points: int = 3) -> dict[str, Any]:
    """Item 163: leadership score trend decline detector."""
    history = list_leadership_history(db, limit=max(3, min(int(points), 30)))
    snaps = list(reversed(history.get("snapshots") or []))
    scores = [float(row.get("score") or 0) for row in snaps if row.get("score") is not None]
    if len(scores) < 2:
        current = build_gateway_leadership_index(db, hours=24, exclude_warmup=True)
        scores = [float(current.get("score") or 0)]
    declining = 0
    for i in range(1, len(scores)):
        if scores[i] < scores[i - 1]:
            declining += 1
        else:
            declining = 0
    alert = declining >= max(1, min(int(decline_points), 10))
    return {
        "scores": scores[-max(2, min(int(points), 30)) :],
        "declining_streak": declining,
        "alert": alert,
        "message": "Leadership score declining." if alert else "No sustained score decline.",
    }


def reset_model_route_policy(db: Session) -> dict[str, Any]:
    """Item 164: reset model allow/deny policy."""
    policy = upsert_model_route_policy(db, allowlist=[], denylist=[])
    record_ops_activity(db, action="model_route_policy_reset", detail={})
    return {"reset": True, **policy}


def clear_model_denylist(db: Session) -> dict[str, Any]:
    """Item 178: clear denylist only."""
    current = get_model_route_policy(db)
    policy = upsert_model_route_policy(db, allowlist=current.get("allowlist") or [], denylist=[])
    record_ops_activity(db, action="model_denylist_clear", detail={})
    return {"cleared_denylist": True, **policy}


def export_posture_digest(db: Session) -> dict[str, Any]:
    """Item 165: export posture digest JSON payload."""
    digest = leadership_posture_digest(db)
    return {
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "digest": digest,
        "filename": f"leadership-posture-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}.json",
    }


def multi_window_leadership_summary(db: Session) -> dict[str, Any]:
    """Item 168: 24/72/168h leadership windows."""
    windows = []
    for hours in (24, 72, 168):
        light = build_traffic_light(db, hours=hours, floor_score=70)
        windows.append(
            {
                "hours": hours,
                "light": light.get("light"),
                "score": light.get("score"),
                "band": light.get("band"),
            }
        )
    return {"windows": windows, "generated_at": datetime.utcnow().isoformat() + "Z"}


def route_health_score(db: Session, *, route_policy_id: str) -> dict[str, Any]:
    """Item 169: route health combining circuit notes + readiness."""
    route = db.query(RoutePolicy).filter_by(route_policy_id=str(route_policy_id or "").strip()).first()
    if not route:
        return {"found": False, "score": 0, "message": "Route not found."}
    readiness = build_inference_readiness(db)
    ready = int(readiness.get("ready_providers") or 0)
    total = max(1, int(readiness.get("total_providers") or 1))
    try:
        fallback = json.loads(route.fallback_policy or "{}")
    except json.JSONDecodeError:
        fallback = {}
    notes = fallback.get("circuit_breaker_notes") if isinstance(fallback, dict) else None
    recs = len((notes or {}).get("recommendations") or []) if isinstance(notes, dict) else 0
    base = round(100.0 * ready / total, 2)
    penalty = min(40.0, recs * 5.0)
    score = max(0.0, round(base - penalty, 2))
    return {
        "found": True,
        "route_policy_id": route.route_policy_id,
        "score": score,
        "ready_providers": ready,
        "circuit_recommendation_count": recs,
        "band": "healthy" if score >= 70 else ("watch" if score >= 40 else "critical"),
        "message": f"Route health {score} ({'notes penalty ' + str(penalty) if penalty else 'no circuit penalty'}).",
    }


def get_operator_checklist(db: Session) -> dict[str, Any]:
    """Item 170: operator checklist read."""
    raw = _rt_get(db, _CHECKLIST_KEY, "{}")
    if not isinstance(raw, dict):
        raw = {}
    steps = [
        "traffic_light",
        "credential_warnings",
        "model_rankings",
        "fallback_ranked",
        "alerts_dry_run",
        "signed_evidence",
    ]
    completed = raw.get("completed") if isinstance(raw.get("completed"), dict) else {}
    return {
        "steps": [
            {"id": step, "done": bool(completed.get(step)), "label": step.replace("_", " ").title()}
            for step in steps
        ],
        "completed_count": sum(1 for step in steps if completed.get(step)),
        "total": len(steps),
        "updated_at": raw.get("updated_at"),
    }


def upsert_operator_checklist(db: Session, *, completed: dict[str, bool]) -> dict[str, Any]:
    current = get_operator_checklist(db)
    state = {row["id"]: row["done"] for row in current["steps"]}
    for key, value in (completed or {}).items():
        if key in state:
            state[key] = bool(value)
    payload = {"completed": state, "updated_at": datetime.utcnow().isoformat() + "Z"}
    _rt_set(db, _CHECKLIST_KEY, payload, "Leadership operator checklist")
    record_ops_activity(db, action="operator_checklist_upsert", detail={"done": sum(1 for v in state.values() if v)})
    return get_operator_checklist(db)


def estimate_auto_route_latency(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 171: latency estimate from histogram modal bucket."""
    hist = build_latency_histogram(db, hours=hours)
    buckets = hist.get("buckets") or []
    if not buckets or not hist.get("samples"):
        return {"hours": hours, "estimate_ms": None, "samples": 0, "message": "No latency samples yet."}
    top = max(buckets, key=lambda row: int(row.get("count") or 0))
    midpoints = {"0-100": 50, "100-300": 200, "300-800": 550, "800-2000": 1400, "2000+": 2500}
    estimate = midpoints.get(str(top.get("bucket")), None)
    return {
        "hours": hours,
        "samples": hist.get("samples"),
        "dominant_bucket": top.get("bucket"),
        "estimate_ms": estimate,
        "message": f"Dominant latency bucket {top.get('bucket')} (~{estimate}ms).",
    }


def pack_capability_registry() -> dict[str, Any]:
    """Item 172: pack capability registry."""
    from app.services.gateway_leadership_pack10 import pack10_manifest
    from app.services.gateway_leadership_pack11 import pack11_manifest
    from app.services.gateway_leadership_pack12 import pack12_manifest

    packs = [pack10_manifest(), pack11_manifest(), pack12_manifest(), pack13_manifest()]
    try:
        from app.services.gateway_leadership_pack14 import pack14_manifest

        packs.append(pack14_manifest())
    except Exception:  # noqa: BLE001
        pass
    try:
        from app.services.gateway_leadership_pack15 import pack15_manifest

        packs.append(pack15_manifest())
    except Exception:  # noqa: BLE001
        pass
    try:
        from app.services.gateway_leadership_pack16 import pack16_manifest

        packs.append(pack16_manifest())
    except Exception:  # noqa: BLE001
        pass
    return {"packs": packs, "count": len(packs)}


def on_demand_leadership_snapshot(db: Session, *, hours: int = 24) -> dict[str, Any]:
    """Item 173: on-demand leadership snapshot."""
    result = record_leadership_snapshot(db, hours=hours, exclude_warmup=True)
    snapshot = result.get("snapshot") or {}
    record_ops_activity(db, action="on_demand_snapshot", detail={"hours": hours, "score": snapshot.get("score")})
    return {
        **result,
        "score": snapshot.get("score"),
        "band": snapshot.get("band"),
        "snapshot_id": snapshot.get("snapshot_id"),
    }


def enforcement_flags_diff(db: Session) -> dict[str, Any]:
    """Item 174: enforcement flags vs defaults."""
    current = get_enforcement_flags(db)["flags"]
    diffs = []
    for key, default in DEFAULT_FLAGS.items():
        value = current.get(key, default)
        if value != default:
            diffs.append({"key": key, "default": default, "current": value})
    return {"diffs": diffs, "count": len(diffs), "in_sync_with_defaults": len(diffs) == 0}


def warmup_eligibility_probe(db: Session, *, max_per_hour: int = 3) -> dict[str, Any]:
    """Item 175: warmup eligibility without consuming quota."""
    guard = guard_warmup_rate_limit(db, max_per_hour=max_per_hour)
    return {
        "eligible": bool(guard.get("allowed")),
        "count": guard.get("count"),
        "max_per_hour": guard.get("max_per_hour"),
        "window_hour": guard.get("window_hour"),
        "message": guard.get("message"),
    }


def list_strategy_policies(db: Session) -> dict[str, Any]:
    """Item 176: list route/tag strategy policies."""
    tags = _rt_get(db, "gateway.leadership.request_tag_strategy_policies_json", "[]")
    routes = _rt_get(db, "gateway.leadership.route_strategy_policies_json", "[]")
    if not isinstance(tags, list):
        tags = []
    if not isinstance(routes, list):
        routes = []
    return {
        "request_tag_policies": tags[:100],
        "route_policies": routes[:100],
        "tag_count": len(tags),
        "route_count": len(routes),
    }


def auto_route_policy_block_detail(decision: dict[str, Any]) -> dict[str, Any]:
    """Item 167 helper: structured 422 detail when policy empties catalog."""
    policy = decision.get("catalog_policy") or {}
    return {
        "code": "AUTO_ROUTE_CATALOG_EMPTY",
        "message": (
            "auto-route could not select a catalog model because allow/deny policy removed all candidates"
            if policy.get("empty_after_policy")
            else "auto-route could not select a catalog model; seed models or disable auto_route"
        ),
        "catalog_policy": policy,
        "rationale": decision.get("rationale"),
    }


def pack13_manifest() -> dict[str, Any]:
    return {
        "pack": 13,
        "items": list(range(161, 181)),
        "theme": "Explainability + operator probes",
        "gov": "GOV-AI-MARKET-013",
    }
