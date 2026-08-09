"""Control/data plane reconcile helpers: policy generation + peer probe.

Shared Postgres is the desired-state store today. Both planes compute the same
policy fingerprint from route/key/cache inventories. Control plane optionally
probes ``DATA_PLANE_PEER_URL`` (or vice versa) and reports generation drift.

Also tracks drift history, last reconcile snapshot, and optional fail-closed
gate state for data-plane inference (`PLANE_FAIL_CLOSED_MODE`).
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any, Optional
from urllib.parse import urljoin

import httpx
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.logging_utils import get_logger, sanitize_fields
from app.models import CachePolicy, RoutePolicy, VirtualKey
from app.plane_mode import AppPlane, resolve_app_plane

logger = get_logger(__name__)

DATA_PLANE_PEER_ENV = "DATA_PLANE_PEER_URL"
CONTROL_PLANE_PEER_ENV = "CONTROL_PLANE_PEER_URL"
PEER_PROBE_TIMEOUT_ENV = "PLANE_PEER_PROBE_TIMEOUT_SECONDS"
DEFAULT_PEER_TIMEOUT_SECONDS = 2.0

FAIL_CLOSED_ENV = "PLANE_FAIL_CLOSED_MODE"
WATCHER_ENABLED_ENV = "PLANE_DRIFT_WATCHER_ENABLED"
WATCHER_INTERVAL_ENV = "PLANE_DRIFT_WATCHER_INTERVAL_SECONDS"
VALID_FAIL_CLOSED_MODES = frozenset({"off", "peer_unreachable", "drift"})

# In-process rejection counters (exported via posture).
_rejection_total = 0
_rejection_by_path: dict[str, int] = {}
_rejection_last_audit_unix: dict[str, float] = {}
_REJECTION_AUDIT_COOLDOWN_SECONDS = 60.0

# Drift history + gate state (in-process; per worker).
_DRIFT_HISTORY_MAX = 50
_drift_events: list[dict[str, Any]] = []
_last_reconcile: Optional[dict[str, Any]] = None
_gate_state: dict[str, Any] = {
    "fail_closed_mode": "off",
    "inference_allowed": True,
    "block_reason": None,
    "drift_status": None,
    "updated_at_unix": None,
    "watcher_enabled": False,
    "watcher_ticks": 0,
}


def _peer_timeout_seconds() -> float:
    raw = (os.getenv(PEER_PROBE_TIMEOUT_ENV) or str(DEFAULT_PEER_TIMEOUT_SECONDS)).strip()
    try:
        value = float(raw)
    except ValueError:
        return DEFAULT_PEER_TIMEOUT_SECONDS
    return max(0.25, min(value, 10.0))


def resolve_peer_url(plane: Optional[AppPlane] = None) -> Optional[str]:
    """Peer URL for the opposite plane (control probes data, data probes control)."""
    resolved = plane if plane is not None else resolve_app_plane()
    if resolved == "control":
        return (os.getenv(DATA_PLANE_PEER_ENV) or "").strip() or None
    if resolved == "data":
        return (os.getenv(CONTROL_PLANE_PEER_ENV) or "").strip() or None
    return None


def resolve_fail_closed_mode(raw: Optional[str] = None, *, db: Optional[Session] = None) -> str:
    """Resolve fail-closed mode from explicit raw, env, or runtime_config override."""
    if raw is not None:
        value = str(raw).strip().lower()
    else:
        value = (os.getenv(FAIL_CLOSED_ENV) or "").strip().lower()
        if not value:
            try:
                from app.runtime_constants import RUNTIME_CONFIG_PLANE_FAIL_CLOSED_MODE
                from app.services.runtime_config import get_runtime_config

                if db is not None:
                    value = get_runtime_config(db, RUNTIME_CONFIG_PLANE_FAIL_CLOSED_MODE, "").strip().lower()
                else:
                    # Middleware / gate hot path: reuse last reconcile mode when present.
                    cached = str((_gate_state or {}).get("fail_closed_mode") or "").strip().lower()
                    if cached in VALID_FAIL_CLOSED_MODES:
                        return cached
                    from app.database import SessionLocal

                    session = SessionLocal()
                    try:
                        value = get_runtime_config(session, RUNTIME_CONFIG_PLANE_FAIL_CLOSED_MODE, "").strip().lower()
                    finally:
                        session.close()
            except Exception:  # noqa: BLE001
                value = ""
        if not value:
            value = "off"
    if value in {"1", "true", "yes", "on"}:
        return "drift"
    if value in VALID_FAIL_CLOSED_MODES:
        return value
    return "off"


def compute_policy_generation(db: Session) -> dict[str, Any]:
    """Deterministic fingerprint of control-state inventories (routes, keys, cache)."""
    route_count = int(db.query(func.count(RoutePolicy.route_policy_id)).scalar() or 0)
    key_count = int(db.query(func.count(VirtualKey.key_id)).scalar() or 0)
    cache_count = int(db.query(func.count(CachePolicy.cache_policy_id)).scalar() or 0)

    route_ids = [row[0] for row in db.query(RoutePolicy.route_policy_id).order_by(RoutePolicy.route_policy_id).all()]
    key_ids = [row[0] for row in db.query(VirtualKey.key_id).order_by(VirtualKey.key_id).all()]
    cache_ids = [
        row[0] for row in db.query(CachePolicy.cache_policy_id).order_by(CachePolicy.cache_policy_id).all()
    ]
    route_status = [
        f"{row[0]}:{row[1]}"
        for row in db.query(RoutePolicy.route_policy_id, RoutePolicy.status)
        .order_by(RoutePolicy.route_policy_id)
        .all()
    ]
    key_status = [
        f"{row[0]}:{row[1]}"
        for row in db.query(VirtualKey.key_id, VirtualKey.status).order_by(VirtualKey.key_id).all()
    ]
    material = "|".join(
        [
            f"routes={','.join(route_status) or ','.join(route_ids)}",
            f"keys={','.join(key_status) or ','.join(key_ids)}",
            f"cache={','.join(cache_ids)}",
            f"counts={route_count}:{key_count}:{cache_count}",
        ]
    )
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return {
        "fingerprint": digest[:16],
        "generation": digest[:12],
        "route_count": route_count,
        "key_count": key_count,
        "cache_policy_count": cache_count,
        "algorithm": "sha256(route_status|key_status|cache_ids|counts)[:16]",
    }


def record_plane_rejection(*, path: str, app_plane: str, path_plane: str) -> dict[str, Any]:
    global _rejection_total
    key = f"{app_plane}:{path_plane}:{path}"
    _rejection_total += 1
    _rejection_by_path[key] = int(_rejection_by_path.get(key) or 0) + 1
    return {
        "total": _rejection_total,
        "path_key": key,
        "path_count": _rejection_by_path[key],
    }


def rejection_stats_snapshot(limit: int = 20) -> dict[str, Any]:
    ranked = sorted(_rejection_by_path.items(), key=lambda item: item[1], reverse=True)[: max(1, limit)]
    return {
        "total": _rejection_total,
        "top_paths": [{"key": key, "count": count} for key, count in ranked],
    }


def should_audit_plane_rejection(path_key: str) -> bool:
    now = time.time()
    last = float(_rejection_last_audit_unix.get(path_key) or 0.0)
    if (now - last) < _REJECTION_AUDIT_COOLDOWN_SECONDS:
        return False
    _rejection_last_audit_unix[path_key] = now
    return True


def record_drift_event(
    *,
    drift_status: str,
    source: str,
    policy_generation: Optional[dict[str, Any]] = None,
    peer: Optional[dict[str, Any]] = None,
    published_fingerprint: Optional[str] = None,
    app_plane: str = "all",
    db: Optional[Session] = None,
) -> dict[str, Any]:
    now = time.time()
    event = {
        "event_id": f"drift-{int(now * 1000)}-{len(_drift_events) % 1000}",
        "recorded_at_unix": now,
        "app_plane": app_plane,
        "drift_status": drift_status,
        "source": source,
        "fingerprint": (policy_generation or {}).get("fingerprint"),
        "peer_fingerprint": (peer or {}).get("peer_fingerprint"),
        "peer_reachable": (peer or {}).get("reachable"),
        "peer_url": (peer or {}).get("peer_url"),
        "peer_latency_ms": (peer or {}).get("latency_ms"),
        "published_fingerprint": published_fingerprint,
    }
    _drift_events.append(event)
    while len(_drift_events) > _DRIFT_HISTORY_MAX:
        _drift_events.pop(0)

    if db is not None:
        try:
            from datetime import datetime

            from app.models import PlaneDriftEvent

            row = PlaneDriftEvent(
                event_id=str(event["event_id"]),
                recorded_at=datetime.utcnow(),
                app_plane=str(app_plane)[:32],
                drift_status=str(drift_status)[:64],
                source=str(source)[:64],
                fingerprint=(event.get("fingerprint") or None),
                peer_fingerprint=(event.get("peer_fingerprint") or None),
                peer_reachable=event.get("peer_reachable"),
                peer_url=(str(event.get("peer_url") or "")[:512] or None),
                peer_latency_ms=event.get("peer_latency_ms"),
                published_fingerprint=published_fingerprint,
                metadata_json="{}",
            )
            db.add(row)
            db.flush()
        except Exception as exc:  # noqa: BLE001 — in-memory history still retained
            logger.info(
                "plane_drift_event_persist_failed %s",
                sanitize_fields({"error": type(exc).__name__}),
            )
    return event


def list_drift_events(limit: int = 20, db: Optional[Session] = None) -> list[dict[str, Any]]:
    capped = max(1, min(int(limit or 20), _DRIFT_HISTORY_MAX))
    if db is not None:
        try:
            from app.models import PlaneDriftEvent

            rows = (
                db.query(PlaneDriftEvent)
                .order_by(PlaneDriftEvent.recorded_at.desc())
                .limit(capped)
                .all()
            )
            if rows:
                return [
                    {
                        "event_id": row.event_id,
                        "recorded_at_unix": row.recorded_at.timestamp() if row.recorded_at else None,
                        "app_plane": row.app_plane,
                        "drift_status": row.drift_status,
                        "source": row.source,
                        "fingerprint": row.fingerprint,
                        "peer_fingerprint": row.peer_fingerprint,
                        "peer_reachable": row.peer_reachable,
                        "peer_url": row.peer_url,
                        "peer_latency_ms": row.peer_latency_ms,
                        "published_fingerprint": row.published_fingerprint,
                        "durable": True,
                    }
                    for row in rows
                ]
        except Exception:
            pass
    return list(reversed(_drift_events[-capped:]))


def last_reconcile_snapshot() -> Optional[dict[str, Any]]:
    return dict(_last_reconcile) if _last_reconcile else None


def gate_state_snapshot() -> dict[str, Any]:
    return dict(_gate_state)


def mark_watcher_status(*, enabled: bool, tick: bool = False) -> None:
    _gate_state["watcher_enabled"] = bool(enabled)
    if tick:
        _gate_state["watcher_ticks"] = int(_gate_state.get("watcher_ticks") or 0) + 1


def _peer_probe_latency_slo_ms() -> float:
    raw = (os.getenv("PLANE_PEER_PROBE_LATENCY_SLO_MS") or "2000").strip()
    try:
        return max(100.0, float(raw))
    except ValueError:
        return 2000.0


def _generation_freshness_slo_seconds() -> float:
    raw = (os.getenv("PLANE_GENERATION_FRESHNESS_SLO_SECONDS") or "120").strip()
    try:
        return max(15.0, float(raw))
    except ValueError:
        return 120.0


def _on_plane_coverage_slo_percent() -> float:
    raw = (os.getenv("PLANE_ON_PLANE_COVERAGE_SLO_PERCENT") or "90").strip()
    try:
        return max(0.0, min(100.0, float(raw)))
    except ValueError:
        return 90.0


def build_plane_slos(
    *,
    peer: Optional[dict[str, Any]] = None,
    published: Optional[dict[str, Any]] = None,
    on_plane_coverage: Optional[dict[str, Any]] = None,
    drift_status: Optional[str] = None,
) -> dict[str, Any]:
    peer = peer or {}
    published = published or {}
    coverage = on_plane_coverage or {}
    latency = peer.get("latency_ms")
    latency_slo = _peer_probe_latency_slo_ms()
    freshness_slo = _generation_freshness_slo_seconds()
    coverage_slo = _on_plane_coverage_slo_percent()
    published_at = published.get("published_at_unix")
    age = (time.time() - float(published_at)) if published_at else None
    on_plane_pct = coverage.get("on_plane_coverage_percent")
    return {
        "peer_probe_latency_ms": latency,
        "peer_probe_latency_slo_ms": latency_slo,
        "peer_probe_within_slo": (latency is None) or (float(latency) <= latency_slo),
        "generation_publish_age_seconds": round(age, 2) if age is not None else None,
        "generation_freshness_slo_seconds": freshness_slo,
        "generation_within_slo": (age is None) or (age <= freshness_slo),
        "on_plane_coverage_percent": on_plane_pct,
        "on_plane_coverage_slo_percent": coverage_slo,
        "on_plane_within_slo": None
        if on_plane_pct is None
        else float(on_plane_pct) >= coverage_slo,
        "drift_status": drift_status,
        "overall_within_slo": all(
            [
                (latency is None) or (float(latency) <= latency_slo),
                (age is None) or (age <= freshness_slo),
                on_plane_pct is None or float(on_plane_pct) >= coverage_slo,
                drift_status not in {"drift_detected", "peer_unreachable"},
            ]
        ),
    }


def _update_gate_state(
    *,
    drift_status: str,
    fail_closed_mode: Optional[str] = None,
    published_mismatch: bool = False,
    db: Optional[Session] = None,
) -> dict[str, Any]:
    if fail_closed_mode is not None:
        mode = resolve_fail_closed_mode(fail_closed_mode, db=db)
    else:
        mode = resolve_fail_closed_mode(db=db)
    allowed = True
    reason = None
    if mode == "peer_unreachable" and drift_status == "peer_unreachable":
        allowed = False
        reason = "PLANE_FAIL_CLOSED_MODE=peer_unreachable and peer health probe failed"
    elif mode == "drift" and (
        drift_status in {"drift_detected", "peer_unreachable"} or published_mismatch
    ):
        allowed = False
        reason = (
            "PLANE_FAIL_CLOSED_MODE=drift and published fingerprint mismatch"
            if published_mismatch and drift_status not in {"drift_detected", "peer_unreachable"}
            else f"PLANE_FAIL_CLOSED_MODE=drift and drift_status={drift_status}"
        )
    _gate_state.update(
        {
            "fail_closed_mode": mode,
            "inference_allowed": allowed,
            "block_reason": reason,
            "drift_status": drift_status,
            "updated_at_unix": time.time(),
            "published_mismatch": published_mismatch,
        }
    )
    return gate_state_snapshot()


def inference_allowed_by_gate() -> tuple[bool, Optional[str]]:
    """Data-plane fail-closed check for inference paths."""
    mode = resolve_fail_closed_mode()
    if mode == "off":
        return True, None
    if _gate_state.get("inference_allowed", True):
        return True, None
    return False, str(_gate_state.get("block_reason") or "plane_gate_blocked")


def probe_peer_health(
    *,
    peer_url: str,
    local_generation: Optional[dict[str, Any]] = None,
    timeout_seconds: Optional[float] = None,
) -> dict[str, Any]:
    """GET peer /health and compare policy generation fingerprints when present."""
    base = peer_url.rstrip("/") + "/"
    health_url = urljoin(base, "health")
    timeout = timeout_seconds if timeout_seconds is not None else _peer_timeout_seconds()
    started = time.perf_counter()
    result: dict[str, Any] = {
        "configured": True,
        "peer_url": peer_url.rstrip("/"),
        "reachable": False,
        "latency_ms": None,
        "peer_app_plane": None,
        "peer_fingerprint": None,
        "local_fingerprint": (local_generation or {}).get("fingerprint"),
        "generation_in_sync": None,
        "error": None,
    }
    try:
        with httpx.Client(timeout=timeout) as client:
            response = client.get(health_url)
        result["latency_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
        if response.status_code != 200:
            result["error"] = f"HTTP {response.status_code}"
            return result
        payload = response.json() if response.content else {}
        result["reachable"] = True
        plane = payload.get("plane") if isinstance(payload, dict) else None
        if isinstance(plane, dict):
            result["peer_app_plane"] = plane.get("app_plane")
            peer_gen = plane.get("policy_generation") if isinstance(plane.get("policy_generation"), dict) else {}
            result["peer_fingerprint"] = peer_gen.get("fingerprint")
            local_fp = result.get("local_fingerprint")
            peer_fp = result.get("peer_fingerprint")
            if local_fp and peer_fp:
                result["generation_in_sync"] = local_fp == peer_fp
            elif local_fp or peer_fp:
                result["generation_in_sync"] = False
        return result
    except Exception as exc:  # noqa: BLE001 — probe must never raise into request path
        result["latency_ms"] = round((time.perf_counter() - started) * 1000.0, 2)
        result["error"] = type(exc).__name__
        logger.info(
            "plane_peer_probe_failed %s",
            sanitize_fields({"peer_url": peer_url, "error": type(exc).__name__}),
        )
        return result


def build_reconcile_posture(
    db: Session,
    *,
    plane: Optional[AppPlane] = None,
    probe_peer: bool = True,
    on_plane_coverage: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    from app.services.plane_policy_publish import read_published_policy_generation

    resolved = plane if plane is not None else resolve_app_plane()
    generation = compute_policy_generation(db)
    published = read_published_policy_generation(db)
    published_mismatch = bool(
        published
        and published.get("fingerprint")
        and generation.get("fingerprint")
        and published.get("fingerprint") != generation.get("fingerprint")
    )
    peer_url = resolve_peer_url(resolved)
    peer: dict[str, Any]
    if resolved == "all":
        peer = {
            "configured": False,
            "skipped": True,
            "reason": "APP_PLANE=all is combined; peer probe not required.",
            "generation_in_sync": True,
        }
    elif not peer_url:
        peer = {
            "configured": False,
            "skipped": True,
            "reason": (
                f"Set {DATA_PLANE_PEER_ENV if resolved == 'control' else CONTROL_PLANE_PEER_ENV} "
                "to enable peer health + generation drift checks."
            ),
            "generation_in_sync": None,
        }
    elif probe_peer:
        peer = probe_peer_health(peer_url=peer_url, local_generation=generation)
    else:
        peer = {
            "configured": True,
            "peer_url": peer_url.rstrip("/"),
            "reachable": None,
            "generation_in_sync": None,
            "skipped": True,
            "reason": "Peer probe disabled for this call.",
        }

    drift = "n/a"
    if resolved == "all" and not published_mismatch:
        drift = "none_combined"
    elif published_mismatch:
        drift = "drift_detected"
    elif peer.get("generation_in_sync") is True:
        drift = "in_sync"
    elif peer.get("generation_in_sync") is False:
        drift = "drift_detected"
    elif peer.get("configured") and peer.get("reachable") is False:
        drift = "peer_unreachable"
    elif not peer.get("configured"):
        drift = "peer_unconfigured"
    elif resolved == "all":
        drift = "none_combined"

    slos = build_plane_slos(
        peer=peer,
        published=published,
        on_plane_coverage=on_plane_coverage,
        drift_status=drift,
    )
    return {
        "policy_generation": generation,
        "published_policy_generation": published,
        "published_mismatch": published_mismatch,
        "peer": peer,
        "drift_status": drift,
        "rejection_stats": rejection_stats_snapshot(),
        "last_reconcile": last_reconcile_snapshot(),
        "gate": gate_state_snapshot(),
        "drift_events_recent": list_drift_events(5, db=db),
        "slos": slos,
    }


def run_reconcile_and_record(
    db: Session,
    *,
    plane: Optional[AppPlane] = None,
    probe_peer: bool = True,
    source: str = "api",
    on_plane_coverage: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Run reconcile, publish generation (control/all), persist drift, update gate."""
    global _last_reconcile
    from app.services.plane_policy_publish import publish_policy_generation

    resolved = plane if plane is not None else resolve_app_plane()
    posture = build_reconcile_posture(
        db,
        plane=resolved,
        probe_peer=probe_peer,
        on_plane_coverage=on_plane_coverage,
    )
    published = posture.get("published_policy_generation")
    # Control and combined planes own desired-state publish.
    if resolved in {"all", "control"}:
        try:
            published = publish_policy_generation(
                db,
                posture.get("policy_generation") or {},
                app_plane=resolved,
            )
            posture["published_policy_generation"] = published
            posture["published_mismatch"] = False
            if posture.get("drift_status") == "drift_detected" and not (
                (posture.get("peer") or {}).get("generation_in_sync") is False
                or (posture.get("peer") or {}).get("reachable") is False
            ):
                # Local publish healed published mismatch for this process.
                if resolved == "all":
                    posture["drift_status"] = "none_combined"
                elif (posture.get("peer") or {}).get("generation_in_sync") is True:
                    posture["drift_status"] = "in_sync"
        except Exception as exc:  # noqa: BLE001
            logger.info(
                "plane_policy_publish_failed %s",
                sanitize_fields({"error": type(exc).__name__}),
            )

    drift_status = str(posture.get("drift_status") or "n/a")
    previous = (_last_reconcile or {}).get("drift_status")
    event = None
    if source.startswith("api") or previous != drift_status or _last_reconcile is None:
        event = record_drift_event(
            drift_status=drift_status,
            source=source,
            policy_generation=posture.get("policy_generation"),
            peer=posture.get("peer"),
            published_fingerprint=(published or {}).get("fingerprint"),
            app_plane=resolved,
            db=db,
        )
    gate = _update_gate_state(
        drift_status=drift_status,
        published_mismatch=bool(posture.get("published_mismatch")),
        db=db,
    )
    posture["slos"] = build_plane_slos(
        peer=posture.get("peer"),
        published=published,
        on_plane_coverage=on_plane_coverage,
        drift_status=drift_status,
    )
    snapshot = {
        **posture,
        "recorded_at_unix": time.time(),
        "source": source,
        "gate": gate,
        "event": event,
        "drift_events_recent": list_drift_events(5, db=db),
    }
    try:
        from app.services.control_plane_contract import maybe_persist_last_known_good

        lkg = maybe_persist_last_known_good(
            db,
            drift_status=drift_status,
            policy_generation=posture.get("policy_generation"),
            published=published if isinstance(published, dict) else None,
            app_plane=resolved,
            source=source,
        )
        if lkg:
            snapshot["last_known_good"] = lkg
    except Exception as exc:  # noqa: BLE001
        logger.info(
            "plane_last_known_good_persist_skipped %s",
            sanitize_fields({"error": type(exc).__name__}),
        )
    _last_reconcile = snapshot
    logger.info(
        "plane_reconcile_recorded %s",
        sanitize_fields(
            {
                "source": source,
                "drift_status": drift_status,
                "fingerprint": (posture.get("policy_generation") or {}).get("fingerprint"),
                "published_fingerprint": (published or {}).get("fingerprint"),
                "inference_allowed": gate.get("inference_allowed"),
                "slos_ok": (snapshot.get("slos") or {}).get("overall_within_slo"),
            }
        ),
    )
    return snapshot