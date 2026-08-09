"""Pack 10 leadership deepeners (items 101–120)."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
import time
from datetime import datetime, timedelta
from typing import Any, Optional
from urllib.parse import urlparse
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import CostEvent, ProviderCredentialBinding, RoutePolicy
from app.services.gateway_leadership import (
    build_gateway_leadership_index,
    export_leadership_evidence_pack,
    ranking_aware_fallback_suggest,
    warmup_leadership_attribution,
)
from app.services.gateway_leadership_pack7 import evaluate_and_queue_leadership_alerts, get_alert_channels
from app.services.inference_readiness import build_inference_readiness


_WARMUP_RATE_KEY = "gateway.leadership.warmup_rate_json"
_DECISION_CACHE_KEY = "gateway.leadership.auto_route_cache_json"
_ACTIVITY_KEY = "gateway.leadership.ops_activity_json"
_ALERT_HOST_ALLOWLIST_KEY = "gateway.leadership.alert_webhook_hosts_json"


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


def record_ops_activity(db: Session, *, action: str, detail: dict[str, Any] | None = None) -> None:
    rows = _rt_get(db, _ACTIVITY_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    rows.insert(
        0,
        {
            "activity_id": f"act-{uuid4().hex[:10]}",
            "action": action,
            "detail": detail or {},
            "at": datetime.utcnow().isoformat() + "Z",
        },
    )
    _rt_set(db, _ACTIVITY_KEY, rows[:100], "Leadership ops activity timeline")


def list_ops_activity(db: Session, *, limit: int = 30) -> dict[str, Any]:
    rows = _rt_get(db, _ACTIVITY_KEY, "[]")
    if not isinstance(rows, list):
        rows = []
    clipped = rows[: max(1, min(int(limit or 30), 100))]
    return {"count": len(clipped), "activities": clipped}


def build_traffic_light(db: Session, *, hours: int = 24, floor_score: float = 70.0) -> dict[str, Any]:
    """Item 102: leadership traffic-light status."""
    index = build_gateway_leadership_index(db, hours=hours, exclude_warmup=True)
    score = float(index.get("score") or 0)
    if score >= floor_score + 10:
        light = "green"
    elif score >= floor_score:
        light = "yellow"
    else:
        light = "red"
    return {
        "light": light,
        "score": score,
        "band": index.get("band"),
        "floor_score": floor_score,
        "hours": hours,
        "message": f"Leadership traffic light is {light}.",
    }


def leadership_healthz(db: Session) -> dict[str, Any]:
    """Item 103: lightweight probe for CI/k8s."""
    light = build_traffic_light(db, hours=24, floor_score=50.0)
    readiness = build_inference_readiness(db)
    return {
        "status": "ok" if light["light"] != "red" else "degraded",
        "light": light["light"],
        "score": light["score"],
        "ready_providers": readiness.get("ready_providers"),
        "checked_at": datetime.utcnow().isoformat() + "Z",
    }


def _host_is_public(hostname: str) -> tuple[bool, str]:
    host = str(hostname or "").strip().lower()
    if not host or host in {"localhost", "127.0.0.1", "::1"}:
        return False, "localhost blocked"
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False, "DNS resolution failed"
    for info in infos:
        ip_str = info[4][0]
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False, f"non-public IP {ip_str}"
    return True, "ok"


def upsert_alert_webhook_allowlist(db: Session, *, hosts: list[str]) -> dict[str, Any]:
    clean = sorted({str(h).strip().lower() for h in hosts if str(h).strip()})
    _rt_set(db, _ALERT_HOST_ALLOWLIST_KEY, clean, "Leadership alert webhook host allowlist")
    return {"hosts": clean, "count": len(clean)}


def get_alert_webhook_allowlist(db: Session) -> dict[str, Any]:
    raw = _rt_get(db, _ALERT_HOST_ALLOWLIST_KEY, "[]")
    hosts = raw if isinstance(raw, list) else []
    return {"hosts": hosts, "count": len(hosts)}


def deliver_leadership_alerts(
    db: Session,
    *,
    hours: int = 24,
    floor_score: float = 70.0,
    dry_run: bool = True,
) -> dict[str, Any]:
    """Item 101: allowlisted webhook alert delivery."""
    queued = evaluate_and_queue_leadership_alerts(
        db, hours=hours, floor_score=floor_score, dry_run=dry_run
    )
    channels = get_alert_channels(db).get("channels") or {}
    webhook = str(channels.get("webhook_url") or channels.get("slack_webhook_url") or "").strip()
    deliveries: list[dict[str, Any]] = []
    if not webhook:
        record_ops_activity(db, action="alert_delivery", detail={"status": "no_webhook"})
        return {**queued, "deliveries": [], "message": "No webhook configured."}

    parsed = urlparse(webhook)
    host = (parsed.hostname or "").lower()
    allow = get_alert_webhook_allowlist(db).get("hosts") or []
    if host not in allow and not any(str(host).endswith(f".{h}") for h in allow):
        return {
            **queued,
            "deliveries": [],
            "message": f"Host '{host}' not in leadership alert webhook allowlist.",
            "delivery_blocked": True,
        }
    ok, reason = _host_is_public(host)
    if not ok:
        return {**queued, "deliveries": [], "message": f"Webhook host blocked: {reason}", "delivery_blocked": True}

    payload = {
        "source": "agenthub-leadership",
        "dispatch_id": queued.get("dispatch_id"),
        "alert_count": queued.get("alert_count"),
        "alerts": queued.get("alerts") or [],
        "sent_at": datetime.utcnow().isoformat() + "Z",
    }
    if dry_run:
        deliveries.append({"url_host": host, "status": "dry_run", "payload_keys": list(payload.keys())})
        record_ops_activity(db, action="alert_delivery_dry_run", detail={"host": host})
        return {**queued, "deliveries": deliveries, "message": "Dry-run delivery prepared."}

    try:
        import httpx

        response = httpx.post(webhook, json=payload, timeout=10.0)
        deliveries.append({"url_host": host, "status_code": response.status_code, "ok": response.is_success})
        record_ops_activity(
            db,
            action="alert_delivery",
            detail={"host": host, "status_code": response.status_code},
        )
    except Exception as exc:  # noqa: BLE001 - surface delivery failure to operators
        deliveries.append({"url_host": host, "ok": False, "error": str(exc)[:200]})
        record_ops_activity(db, action="alert_delivery_error", detail={"host": host, "error": str(exc)[:120]})
        try:
            from app.services.gateway_leadership_pack11 import enqueue_alert_retry

            enqueue_alert_retry(
                db,
                dispatch_id=str(queued.get("dispatch_id") or ""),
                host=host,
                error=str(exc)[:200],
            )
        except Exception:  # noqa: BLE001
            pass
    else:
        for row in deliveries:
            if row.get("ok") is False:
                try:
                    from app.services.gateway_leadership_pack11 import enqueue_alert_retry

                    enqueue_alert_retry(
                        db,
                        dispatch_id=str(queued.get("dispatch_id") or ""),
                        host=host,
                        error=f"status_code={row.get('status_code')}",
                    )
                except Exception:  # noqa: BLE001
                    pass
    return {**queued, "deliveries": deliveries, "message": "Delivery attempt completed."}


def apply_ranked_fallback_to_route(
    db: Session,
    *,
    route_policy_id: str,
    max_hops: int = 3,
) -> dict[str, Any]:
    """Item 108: mutate one route fallback priority_order from ranked suggest."""
    route_id = str(route_policy_id or "").strip()
    route = db.query(RoutePolicy).filter_by(route_policy_id=route_id).first()
    if not route:
        return {"applied": False, "message": "Route policy not found."}
    suggestion = ranking_aware_fallback_suggest(db, max_hops=max_hops)
    order = suggestion.get("priority_order") or []
    if not order:
        return {"applied": False, "message": "No ranked priority_order available."}
    from app.services.gateway_best_practices import apply_provider_priority_chain

    try:
        fallback = json.loads(route.fallback_policy or "{}")
    except json.JSONDecodeError:
        fallback = {}
    existing_pp = fallback.get("provider_priority") if isinstance(fallback, dict) else {}
    tenant_id = "tenant-default"
    if isinstance(existing_pp, dict) and str(existing_pp.get("tenant_id") or "").strip():
        tenant_id = str(existing_pp.get("tenant_id")).strip()
    apply_provider_priority_chain(
        route,
        priority_order=order,
        tenant_id=tenant_id,
        environment=str((existing_pp or {}).get("environment") or "dev") if isinstance(existing_pp, dict) else "dev",
        health_check_enabled=True,
        max_fallback_hops=max_hops,
        global_timeout_ms=4500,
    )
    db.flush()
    record_ops_activity(
        db,
        action="apply_ranked_fallback",
        detail={"route_policy_id": route_id, "hops": len(order)},
    )
    return {
        "applied": True,
        "route_policy_id": route_id,
        "priority_order": order,
        "message": "Ranked fallback priority_order applied to route provider_priority.",
    }


def guard_warmup_rate_limit(db: Session, *, max_per_hour: int = 3) -> dict[str, Any]:
    """Item 109: warmup rate-limit guard."""
    state = _rt_get(db, _WARMUP_RATE_KEY, "{}")
    if not isinstance(state, dict):
        state = {}
    window = str(state.get("window_hour") or "")
    current_hour = datetime.utcnow().strftime("%Y%m%d%H")
    count = int(state.get("count") or 0)
    if window != current_hour:
        window = current_hour
        count = 0
    allowed = count < max(1, min(int(max_per_hour), 20))
    return {
        "allowed": allowed,
        "count": count,
        "max_per_hour": max_per_hour,
        "window_hour": window,
        "message": "Warmup allowed." if allowed else "Warmup rate limit exceeded for this hour.",
    }


def mark_warmup_attempt(db: Session) -> None:
    state = guard_warmup_rate_limit(db)
    _rt_set(
        db,
        _WARMUP_RATE_KEY,
        {"window_hour": state["window_hour"], "count": int(state["count"]) + 1},
        "Leadership warmup rate window",
    )


def get_cached_auto_route_decision(db: Session, *, prompt_text: str, strategy: str) -> Optional[dict[str, Any]]:
    """Item 110: auto-route decision TTL cache read."""
    cache = _rt_get(db, _DECISION_CACHE_KEY, "{}")
    if not isinstance(cache, dict):
        return None
    key = hashlib.sha256(f"{strategy}|{prompt_text}".encode("utf-8")).hexdigest()[:32]
    row = cache.get(key)
    if not isinstance(row, dict):
        return None
    exp = float(row.get("exp") or 0)
    if exp < time.time():
        return None
    return row.get("decision")


def put_cached_auto_route_decision(
    db: Session,
    *,
    prompt_text: str,
    strategy: str,
    decision: dict[str, Any],
    ttl_seconds: int = 60,
) -> dict[str, Any]:
    cache = _rt_get(db, _DECISION_CACHE_KEY, "{}")
    if not isinstance(cache, dict):
        cache = {}
    key = hashlib.sha256(f"{strategy}|{prompt_text}".encode("utf-8")).hexdigest()[:32]
    cache[key] = {
        "exp": time.time() + max(15, min(int(ttl_seconds), 300)),
        "decision": decision,
        "cached_at": datetime.utcnow().isoformat() + "Z",
    }
    # Cap cache size
    if len(cache) > 50:
        for old_key in list(cache.keys())[: len(cache) - 50]:
            cache.pop(old_key, None)
    _rt_set(db, _DECISION_CACHE_KEY, cache, "Auto-route decision TTL cache")
    return {"cached": True, "key": key}


def build_sla_burn_rate(db: Session, *, hours: int = 24, floor_score: float = 70.0) -> dict[str, Any]:
    """Item 111: leadership SLA burn-rate."""
    index = build_gateway_leadership_index(db, hours=hours, exclude_warmup=True)
    score = float(index.get("score") or 0)
    deficit = max(0.0, float(floor_score) - score)
    burn = round(deficit / float(floor_score) * 100, 2) if floor_score else 0.0
    return {
        "hours": hours,
        "floor_score": floor_score,
        "score": score,
        "deficit": round(deficit, 2),
        "burn_rate_percent": burn,
        "status": "burning" if deficit > 0 else "healthy",
    }


def cleanup_chaos_drill_events(db: Session, *, dry_run: bool = True) -> dict[str, Any]:
    """Item 112: chaos drill event cleanup."""
    events = (
        db.query(CostEvent)
        .order_by(CostEvent.timestamp.desc())
        .limit(3000)
        .all()
    )
    victims = []
    for event in events:
        try:
            props = json.loads(getattr(event, "properties_json", None) or "{}")
        except json.JSONDecodeError:
            props = {}
        if isinstance(props, dict) and props.get("chaos_drill"):
            victims.append(event)
    deleted = 0
    if not dry_run:
        for event in victims:
            db.delete(event)
            deleted += 1
        if deleted:
            db.flush()
    record_ops_activity(db, action="chaos_cleanup", detail={"matched": len(victims), "dry_run": dry_run})
    return {"dry_run": dry_run, "matched": len(victims), "deleted": deleted if not dry_run else 0}


def diff_evidence_packs(db: Session, *, hours_a: int = 24, hours_b: int = 168) -> dict[str, Any]:
    """Item 113: evidence pack A/B diff."""
    pack_a = export_leadership_evidence_pack(db, hours=hours_a, exclude_warmup=True)
    pack_b = export_leadership_evidence_pack(db, hours=hours_b, exclude_warmup=True)
    score_a = float((pack_a.get("leadership_index") or {}).get("score") or 0)
    score_b = float((pack_b.get("leadership_index") or {}).get("score") or 0)
    return {
        "hours_a": hours_a,
        "hours_b": hours_b,
        "score_a": score_a,
        "score_b": score_b,
        "score_delta": round(score_a - score_b, 2),
        "band_a": (pack_a.get("leadership_index") or {}).get("band"),
        "band_b": (pack_b.get("leadership_index") or {}).get("band"),
    }


def leadership_openapi_fragment() -> dict[str, Any]:
    """Item 114: OpenAPI fragment for leadership surfaces."""
    paths = {
        "/gateway/best-practices/leadership-index": {"get": {"summary": "Leadership index"}},
        "/gateway/best-practices/traffic-light": {"get": {"summary": "Traffic light"}},
        "/gateway/best-practices/healthz": {"get": {"summary": "Leadership healthz"}},
        "/gateway/best-practices/alert-deliver": {"post": {"summary": "Deliver alerts"}},
        "/gateway/best-practices/apply-ranked-fallback": {"post": {"summary": "Apply ranked fallback to route"}},
        "/gateway/best-practices/sla-burn-rate": {"get": {"summary": "SLA burn rate"}},
        "/gateway/best-practices/ops-activity": {"get": {"summary": "Ops activity timeline"}},
    }
    return {
        "openapi": "3.0.3",
        "info": {"title": "AgentHub Leadership APIs", "version": "pack10"},
        "paths": paths,
    }


def build_scorecard_digest(db: Session) -> dict[str, Any]:
    """Item 115: scorecard weekly digest artifact."""
    from app.services.gateway_leadership_pack8 import get_competitive_scorecard, refresh_competitive_scorecard

    current = get_competitive_scorecard(db)
    if not current.get("scorecard"):
        refresh_competitive_scorecard(db)
        current = get_competitive_scorecard(db)
    card = current.get("scorecard") or {}
    digest = {
        "digest_id": f"dig-{uuid4().hex[:10]}",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "subject": f"AgentHub leadership scorecard — {card.get('leadership_score')}/100",
        "body_text": (
            f"Leadership score {card.get('leadership_score')} ({card.get('band')}). "
            f"Notes: {'; '.join(card.get('competitors_benchmark_notes') or [])}"
        ),
        "scorecard": card,
    }
    record_ops_activity(db, action="scorecard_digest", detail={"digest_id": digest["digest_id"]})
    return digest


def credential_binding_warnings(db: Session) -> dict[str, Any]:
    """Item 116: credential binding readiness warnings."""
    from app.services.provider_credential_bindings import binding_configured

    readiness = build_inference_readiness(db)
    live = {
        str(row.get("provider_type") or "").lower()
        for row in readiness.get("providers") or []
        if row.get("live_ready")
    }
    bindings = db.query(ProviderCredentialBinding).limit(300).all()
    warnings = []
    for binding in bindings:
        configured = bool(binding_configured(db, binding))
        provider = str(binding.provider_type or "").lower()
        if binding.status != "active":
            warnings.append(
                {
                    "binding_id": binding.binding_id,
                    "severity": "info",
                    "message": f"Binding {binding.binding_id} status={binding.status}",
                }
            )
        elif not configured:
            warnings.append(
                {
                    "binding_id": binding.binding_id,
                    "severity": "warning",
                    "message": f"Binding for {provider} is not configured.",
                }
            )
        elif provider not in live:
            warnings.append(
                {
                    "binding_id": binding.binding_id,
                    "severity": "warning",
                    "message": f"Binding for {provider} configured but not live-ready.",
                }
            )
    return {"warning_count": len(warnings), "warnings": warnings[:50]}


def resolve_strategy_policy(
    db: Session,
    *,
    route_policy_id: Optional[str] = None,
    request_tag: Optional[str] = None,
    default_strategy: str = "balanced",
) -> dict[str, Any]:
    """Item 117: resolve route/tag strategy into auto-route."""
    # Keys must match gateway_leadership_pack8 persistence.
    tag_key = "gateway.leadership.request_tag_strategy_policies_json"
    route_key = "gateway.leadership.route_strategy_policies_json"

    strategy = default_strategy
    source = "default"
    if request_tag:
        tags = _rt_get(db, tag_key, "[]")
        if isinstance(tags, list):
            for row in tags:
                if str(row.get("request_tag") or "") == str(request_tag):
                    strategy = str(row.get("strategy") or strategy)
                    source = "request_tag"
                    break
    if route_policy_id and source == "default":
        routes = _rt_get(db, route_key, "[]")
        if isinstance(routes, list):
            for row in routes:
                if str(row.get("route_policy_id") or "") == str(route_policy_id):
                    strategy = str(row.get("strategy") or strategy)
                    source = "route_policy"
                    break
    return {"strategy": strategy, "source": source, "route_policy_id": route_policy_id, "request_tag": request_tag}


def simulation_live_judge_transcript(prompt_text: str, complexity: dict[str, Any]) -> dict[str, Any]:
    """Item 118: simulation-safe live-judge transcript refine."""
    base = dict(complexity or {})
    transcript = [
        {"role": "system", "content": "You are a routing complexity judge. Reply with tier and score."},
        {"role": "user", "content": str(prompt_text or "")[:2000]},
        {
            "role": "assistant",
            "content": (
                f"SIMULATED_JUDGE: tier={base.get('tier')} score={base.get('score')} "
                f"signals={','.join(list(base.get('signals') or [])[:5])}"
            ),
        },
    ]
    return {
        "mode": "simulation_transcript",
        "complexity": base,
        "transcript": transcript,
        "message": "Simulation transcript only — no external LLM call.",
    }


def pack10_manifest() -> dict[str, Any]:
    """Item 119."""
    return {
        "pack": 10,
        "items": list(range(101, 121)),
        "theme": "Enforcement deepeners + alert delivery + ops hardening",
        "gov": "GOV-AI-MARKET-010",
    }


def run_guarded_warmup(
    db: Session,
    *,
    samples: int = 6,
    environment: str = "dev",
    actor_id: str = "system",
    strategy: str = "balanced",
    max_per_hour: int = 3,
) -> dict[str, Any]:
    guard = guard_warmup_rate_limit(db, max_per_hour=max_per_hour)
    if not guard["allowed"]:
        return {"blocked": True, **guard}
    result = warmup_leadership_attribution(
        db,
        samples=samples,
        environment=environment,
        actor_id=actor_id,
        strategy=strategy,
    )
    mark_warmup_attempt(db)
    record_ops_activity(db, action="guarded_warmup", detail={"created_events": result.get("created_events")})
    try:
        from app.services.gateway_leadership_pack12 import flush_cache_after_warmup

        flush_cache_after_warmup(db)
    except Exception:  # noqa: BLE001
        pass
    return {"blocked": False, "guard": guard, "result": result}
