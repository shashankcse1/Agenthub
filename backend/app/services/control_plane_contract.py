"""Control-plane contract aligned to gateway CP/DP best practices.

Industry patterns reflected here (NGINX Gateway Fabric / API gateway split plane):
- Separate desired (spec) vs observed (status) state
- Last-known-good policy for data-plane continue-on-CP-degradation
- Explicit liveness vs readiness probes for the control plane process
- Optional read-only freeze (env + audited runtime) for change windows
- Rollback ceremony: re-publish last-known-good as fence fingerprint
- Peer ack of published generation
- Versioned contract + capability inventory for operators/CI
- Snapshot export for GitOps / audit backup

Never authorizes marketing leadership claims.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.logging_utils import get_logger, sanitize_fields
from app.plane_mode import resolve_app_plane
from app.services.plane_policy_publish import (
    publish_policy_generation,
    read_published_policy_generation,
)
from app.services.plane_reconcile import (
    compute_policy_generation,
    gate_state_snapshot,
    last_reconcile_snapshot,
    list_drift_events,
    resolve_fail_closed_mode,
)
from app.services.runtime_config import (
    get_runtime_config,
    invalidate_runtime_config_cache,
    upsert_runtime_config_value,
)

logger = get_logger(__name__)

PLANE_CONTRACT_VERSION = "plane-contract-v2"
RUNTIME_CONFIG_PLANE_LAST_KNOWN_GOOD_JSON = "plane.last_known_good_json"
RUNTIME_CONFIG_PLANE_SNAPSHOT_JSON = "plane.control_snapshot_summary_json"
RUNTIME_CONFIG_PLANE_SNAPSHOT_STORE_JSON = "plane.control_snapshot_store_json"
RUNTIME_CONFIG_PLANE_CONTROL_READONLY = "plane.control_readonly"
RUNTIME_CONFIG_PLANE_PEER_ACK_JSON = "plane.peer_ack_json"
RUNTIME_CONFIG_PLANE_ROLLBACK_JSON = "plane.rollback_summary_json"
CONTROL_READONLY_ENV = "PLANE_CONTROL_READONLY"
SNAPSHOT_APPLY_REQUIRE_HASH_ENV = "PLANE_SNAPSHOT_APPLY_REQUIRE_HASH"
SNAPSHOT_STORE_MAX = 10

# Drift statuses that qualify as healthy enough to promote last-known-good.
_LKG_HEALTHY_DRIFT = frozenset({"none_combined", "in_sync", "peer_unconfigured"})


def _truthy(raw: str | None) -> bool:
    return str(raw or "").strip().lower() in {"1", "true", "yes", "on"}


def resolve_control_readonly_env() -> bool:
    return _truthy(os.getenv(CONTROL_READONLY_ENV))


def resolve_control_readonly(db: Optional[Session] = None) -> bool:
    """Env hard-freeze OR audited runtime_config freeze (either freezes mutations)."""
    if resolve_control_readonly_env():
        return True
    if db is None:
        return False
    return _truthy(get_runtime_config(db, RUNTIME_CONFIG_PLANE_CONTROL_READONLY, "false"))


def control_readonly_sources(db: Optional[Session] = None) -> dict[str, Any]:
    env_on = resolve_control_readonly_env()
    runtime_on = False
    if db is not None:
        runtime_on = _truthy(get_runtime_config(db, RUNTIME_CONFIG_PLANE_CONTROL_READONLY, "false"))
    return {
        "frozen": env_on or runtime_on,
        "env": env_on,
        "runtime": runtime_on,
        "env_overrides_runtime": True,
        "unfreeze_via_api_allowed": not env_on,
    }


def control_plane_capabilities() -> dict[str, Any]:
    return {
        "process_isolation": True,
        "desired_observed_split": True,
        "active_reconcile": True,
        "hot_policy_publish": True,
        "durable_drift_events": True,
        "fail_closed_gate": True,
        "last_known_good": True,
        "lkg_rollback": True,
        "liveness_probe": True,
        "readiness_probe": True,
        "readonly_freeze": True,
        "audited_change_freeze": True,
        "peer_ack": True,
        "snapshot_export": True,
        "snapshot_apply": True,
        "leadership_index": True,
        "release_gate": True,
        "evidence_pack": True,
        "promotion_readiness": True,
    }


def build_control_plane_contract(db: Optional[Session] = None) -> dict[str, Any]:
    plane = resolve_app_plane()
    freeze = control_readonly_sources(db)
    return {
        "contract_version": PLANE_CONTRACT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "app_plane": plane,
        "isolation_mode": "combined" if plane == "all" else "process_isolated",
        "control_readonly": freeze["frozen"],
        "control_readonly_sources": freeze,
        "fail_closed_mode": resolve_fail_closed_mode(),
        "capabilities": control_plane_capabilities(),
        "best_practices": [
            "Deploy APP_PLANE=control|data (compose profile plane-split) for production isolation.",
            "Keep data plane on last-known-good policy when control plane is unreachable.",
            "Use POST /platform/control-plane/rollback-lkg when published fence must retreat.",
            "Use reconcile + release-gate evaluate as the promotion ceremony.",
            "Freeze via PLANE_CONTROL_READONLY or POST /platform/control-plane/freeze during incidents.",
            "Probe /platform/control-plane/live (liveness) and /ready (readiness) separately.",
            "Record peer ack after data-plane workers observe the published fingerprint.",
            "Export control-plane snapshots into GitOps / audit evidence stores.",
            "Apply a pinned snapshot fence via POST /platform/control-plane/snapshot/apply.",
        ],
        "marketing_claim_allowed": False,
    }


def build_control_plane_liveness() -> dict[str, Any]:
    """Kubernetes-style liveness — process is up (does not imply ready for CP duties)."""
    return {
        "alive": True,
        "app_plane": resolve_app_plane(),
        "contract_version": PLANE_CONTRACT_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "marketing_claim_allowed": False,
    }


def _load_last_known_good(db: Session) -> Optional[dict[str, Any]]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_PLANE_LAST_KNOWN_GOOD_JSON, "")
    if not raw.strip():
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def persist_last_known_good(
    db: Session,
    *,
    fingerprint: str,
    drift_status: str,
    app_plane: str,
    source: str,
    published: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Record last-known-good desired-state fingerprint for DP continue-on-CP-down."""
    bundle = {
        "fingerprint": fingerprint,
        "drift_status": drift_status,
        "app_plane": app_plane,
        "source": source,
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "recorded_at_unix": time.time(),
        "published_backends": (published or {}).get("publish_backends")
        or (published or {}).get("read_backend"),
        "contract_version": PLANE_CONTRACT_VERSION,
    }
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_PLANE_LAST_KNOWN_GOOD_JSON,
        json.dumps(bundle, separators=(",", ":"), ensure_ascii=True),
        description="Last-known-good policy generation fingerprint for data-plane fallback narrative.",
    )
    logger.info(
        "plane_last_known_good_recorded %s",
        sanitize_fields(
            {
                "fingerprint": fingerprint,
                "drift_status": drift_status,
                "app_plane": app_plane,
                "source": source,
            }
        ),
    )
    return bundle


def maybe_persist_last_known_good(
    db: Session,
    *,
    drift_status: str,
    policy_generation: Optional[dict[str, Any]],
    published: Optional[dict[str, Any]],
    app_plane: str,
    source: str,
) -> Optional[dict[str, Any]]:
    fingerprint = (policy_generation or {}).get("fingerprint") or (published or {}).get("fingerprint")
    if not fingerprint:
        return None
    if drift_status not in _LKG_HEALTHY_DRIFT:
        return None
    return persist_last_known_good(
        db,
        fingerprint=str(fingerprint),
        drift_status=drift_status,
        app_plane=app_plane,
        source=source,
        published=published if isinstance(published, dict) else None,
    )


def build_desired_observed_status(
    db: Session,
    *,
    policy_generation: Optional[dict[str, Any]] = None,
    published: Optional[dict[str, Any]] = None,
    drift_status: Optional[str] = None,
    peer: Optional[dict[str, Any]] = None,
    gate: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Split desired (spec) vs observed (status) — Kubernetes-style CP hygiene."""
    desired = policy_generation or compute_policy_generation(db)
    observed_published = published if published is not None else read_published_policy_generation(db)
    last = last_reconcile_snapshot() or {}
    gate_state = gate if gate is not None else gate_state_snapshot()
    lkg = _load_last_known_good(db)
    desired_fp = (desired or {}).get("fingerprint")
    observed_fp = (observed_published or {}).get("fingerprint")
    peer_fp = (peer or {}).get("peer_fingerprint") or (peer or {}).get("fingerprint")
    in_sync = bool(desired_fp) and desired_fp == observed_fp
    peer_ack = _load_peer_ack(db)
    peer_ack_match: Optional[bool] = None
    if peer_ack and observed_fp:
        peer_ack_match = peer_ack.get("fingerprint") == observed_fp
    return {
        "desired": {
            "fingerprint": desired_fp,
            "route_count": (desired or {}).get("route_count"),
            "key_count": (desired or {}).get("key_count"),
            "cache_policy_count": (desired or {}).get("cache_policy_count"),
            "computed_at": (desired or {}).get("computed_at"),
        },
        "observed": {
            "published_fingerprint": observed_fp,
            "drift_status": drift_status or last.get("drift_status") or gate_state.get("drift_status"),
            "peer_fingerprint": peer_fp,
            "peer_reachable": (peer or {}).get("reachable"),
            "inference_allowed": gate_state.get("inference_allowed"),
            "fail_closed_mode": gate_state.get("fail_closed_mode") or resolve_fail_closed_mode(),
            "last_reconcile_at_unix": last.get("recorded_at_unix"),
            "watcher_enabled": gate_state.get("watcher_enabled"),
            "watcher_ticks": gate_state.get("watcher_ticks"),
        },
        "last_known_good": lkg,
        "generation_in_sync": in_sync,
        "acked": bool(peer_ack_match) if peer_ack_match is not None else False,
        "peer_ack_matches_published": peer_ack_match,
        "contract_version": PLANE_CONTRACT_VERSION,
    }


def build_control_plane_readiness(db: Session) -> dict[str, Any]:
    """Kubernetes-style readiness for the control-plane process."""
    plane = resolve_app_plane()
    checks: list[dict[str, Any]] = []

    def add(check_id: str, label: str, passed: bool, detail: str, *, severity: str = "required") -> None:
        checks.append(
            {
                "id": check_id,
                "label": label,
                "passed": passed,
                "detail": detail,
                "severity": severity,
            }
        )

    # Shared / control processes should serve admin APIs; data plane readiness is different.
    add(
        "plane_role",
        "Process role allows control-plane duties",
        plane in {"all", "control"},
        f"APP_PLANE={plane}",
        severity="required" if plane != "data" else "advisory",
    )

    generation_ok = False
    fingerprint = None
    try:
        generation = compute_policy_generation(db)
        fingerprint = generation.get("fingerprint")
        generation_ok = bool(fingerprint)
        add("policy_generation", "Desired-state policy generation computable", generation_ok, fingerprint or "none")
    except Exception as exc:  # noqa: BLE001
        add("policy_generation", "Desired-state policy generation computable", False, type(exc).__name__)

    published = None
    try:
        published = read_published_policy_generation(db)
        add(
            "published_generation",
            "Published policy generation readable",
            bool(published and published.get("fingerprint")),
            (published or {}).get("fingerprint") or "none",
            severity="advisory" if plane == "data" else "required",
        )
    except Exception as exc:  # noqa: BLE001
        add("published_generation", "Published policy generation readable", False, type(exc).__name__)

    lkg = _load_last_known_good(db)
    add(
        "last_known_good",
        "Last-known-good fingerprint recorded",
        bool(lkg and lkg.get("fingerprint")),
        (lkg or {}).get("fingerprint") or "none",
        severity="advisory",
    )

    gate = gate_state_snapshot()
    add(
        "gate_state",
        "Fail-closed gate state available",
        isinstance(gate, dict) and "inference_allowed" in gate,
        f"mode={gate.get('fail_closed_mode') if isinstance(gate, dict) else 'n/a'}",
    )

    drift_events = list_drift_events(1, db=db)
    add(
        "drift_store",
        "Drift event store readable",
        True,
        f"recent={len(drift_events)}",
        severity="advisory",
    )

    readonly = resolve_control_readonly(db)
    add(
        "readonly_freeze",
        "Control-plane write freeze status",
        True,
        "on" if readonly else "off",
        severity="advisory",
    )

    required = [c for c in checks if c.get("severity") != "advisory"]
    # Data plane: only require gate_state + policy_generation attempt is advisory for role
    if plane == "data":
        required = [c for c in checks if c["id"] in {"gate_state"}]
    ready = all(bool(c.get("passed")) for c in required)
    freeze = control_readonly_sources(db)
    return {
        "ready": ready,
        "alive": True,
        "app_plane": plane,
        "control_readonly": readonly,
        "control_readonly_sources": freeze,
        "contract_version": PLANE_CONTRACT_VERSION,
        "checks": checks,
        "failed_checks": [c["id"] for c in required if not c.get("passed")],
        "fingerprint": fingerprint,
        "published_fingerprint": (published or {}).get("fingerprint") if isinstance(published, dict) else None,
        "last_known_good_fingerprint": (lkg or {}).get("fingerprint") if isinstance(lkg, dict) else None,
        "http_status_hint": 200 if ready else 503,
        "marketing_claim_allowed": False,
    }


def build_control_plane_snapshot(
    db: Session,
    *,
    actor_id: Optional[str] = None,
    persist_summary: bool = True,
    include_drift_events: int = 20,
) -> dict[str, Any]:
    """GitOps / audit snapshot of control-plane desired+observed state."""
    plane = resolve_app_plane()
    desired = compute_policy_generation(db)
    published = read_published_policy_generation(db)
    last = last_reconcile_snapshot()
    gate = gate_state_snapshot()
    status = build_desired_observed_status(
        db,
        policy_generation=desired,
        published=published,
        drift_status=(last or {}).get("drift_status"),
        gate=gate,
    )
    readiness = build_control_plane_readiness(db)
    contract = build_control_plane_contract(db)
    drift_events = list_drift_events(include_drift_events, db=db)
    snapshot_id = f"cpsnap-{uuid4().hex[:16]}"
    peer_ack = _load_peer_ack(db)
    last_rollback = _load_rollback_summary(db)
    body = {
        "snapshot_id": snapshot_id,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "generated_by": actor_id,
        "contract_version": PLANE_CONTRACT_VERSION,
        "app_plane": plane,
        "control_readonly": resolve_control_readonly(db),
        "control_readonly_sources": control_readonly_sources(db),
        "contract": contract,
        "desired_observed": status,
        "peer_ack": peer_ack,
        "last_rollback": last_rollback,
        "readiness": {
            "alive": True,
            "ready": readiness.get("ready"),
            "failed_checks": readiness.get("failed_checks"),
            "checks": readiness.get("checks"),
        },
        "policy_generation": desired,
        "published_policy_generation": published,
        "gate": gate,
        "last_reconcile": last,
        "drift_events_recent": drift_events,
        "marketing_claim_allowed": False,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    pack = {**body, "canonical_sha256": digest}
    if persist_summary:
        upsert_runtime_config_value(
            db,
            RUNTIME_CONFIG_PLANE_SNAPSHOT_JSON,
            json.dumps(
                {
                    "snapshot_id": snapshot_id,
                    "generated_at": body["generated_at"],
                    "fingerprint": (desired or {}).get("fingerprint"),
                    "ready": readiness.get("ready"),
                    "canonical_sha256": digest,
                },
                separators=(",", ":"),
                ensure_ascii=True,
            ),
            description="Latest control-plane snapshot summary for GitOps/audit.",
        )
        _persist_snapshot_store_entry(
            db,
            {
                "snapshot_id": snapshot_id,
                "generated_at": body["generated_at"],
                "canonical_sha256": digest,
                "fingerprint": (desired or {}).get("fingerprint"),
                "policy_generation": {
                    "fingerprint": (desired or {}).get("fingerprint"),
                    "generation": (desired or {}).get("generation"),
                    "route_count": (desired or {}).get("route_count"),
                    "key_count": (desired or {}).get("key_count"),
                    "cache_policy_count": (desired or {}).get("cache_policy_count"),
                    "algorithm": (desired or {}).get("algorithm"),
                },
            },
        )
    logger.info(
        "control_plane_snapshot_built %s",
        sanitize_fields(
            {
                "snapshot_id": snapshot_id,
                "fingerprint": (desired or {}).get("fingerprint"),
                "ready": readiness.get("ready"),
                "actor_id": actor_id,
            }
        ),
    )
    return pack


def _load_snapshot_store(db: Session) -> list[dict[str, Any]]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_PLANE_SNAPSHOT_STORE_JSON, "")
    if not raw.strip():
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def _persist_snapshot_store_entry(db: Session, entry: dict[str, Any]) -> None:
    store = [e for e in _load_snapshot_store(db) if e.get("snapshot_id") != entry.get("snapshot_id")]
    store.insert(0, entry)
    store = store[:SNAPSHOT_STORE_MAX]
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_PLANE_SNAPSHOT_STORE_JSON,
        json.dumps(store, separators=(",", ":"), ensure_ascii=True),
        description="Ring of recent control-plane snapshots eligible for fence apply.",
    )


def resolve_snapshot_apply_require_hash() -> bool:
    raw = (os.getenv(SNAPSHOT_APPLY_REQUIRE_HASH_ENV) or "true").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def find_snapshot_store_entry(
    db: Session,
    *,
    snapshot_id: Optional[str] = None,
    canonical_sha256: Optional[str] = None,
) -> Optional[dict[str, Any]]:
    sid = (snapshot_id or "").strip()
    sha = (canonical_sha256 or "").strip().lower()
    for entry in _load_snapshot_store(db):
        if sid and entry.get("snapshot_id") == sid:
            return entry
        if sha and str(entry.get("canonical_sha256") or "").lower() == sha:
            return entry
    # Fall back to latest summary if id/hash matches summary only (no generation → cannot apply).
    raw = get_runtime_config(db, RUNTIME_CONFIG_PLANE_SNAPSHOT_JSON, "")
    if raw.strip():
        try:
            summary = json.loads(raw)
        except json.JSONDecodeError:
            summary = None
        if isinstance(summary, dict):
            if sid and summary.get("snapshot_id") == sid:
                return summary
            if sha and str(summary.get("canonical_sha256") or "").lower() == sha:
                return summary
    return None


def apply_control_plane_snapshot(
    db: Session,
    *,
    snapshot_id: Optional[str] = None,
    canonical_sha256: Optional[str] = None,
    actor_id: Optional[str] = None,
    reason: str = "",
) -> dict[str, Any]:
    """Re-publish a pinned snapshot's policy generation as the hot fence (GitOps pin restore)."""
    require_hash = resolve_snapshot_apply_require_hash()
    sha = (canonical_sha256 or "").strip()
    if require_hash and not sha:
        return {
            "ok": False,
            "error_code": "PLANE_SNAPSHOT_HASH_REQUIRED",
            "message": f"canonical_sha256 is required when {SNAPSHOT_APPLY_REQUIRE_HASH_ENV} is enabled.",
            "marketing_claim_allowed": False,
        }
    entry = find_snapshot_store_entry(db, snapshot_id=snapshot_id, canonical_sha256=sha or None)
    if entry is None:
        return {
            "ok": False,
            "error_code": "PLANE_SNAPSHOT_NOT_FOUND",
            "message": "No stored snapshot matched snapshot_id / canonical_sha256. Mint a snapshot first.",
            "marketing_claim_allowed": False,
        }
    if sha and str(entry.get("canonical_sha256") or "").lower() != sha.lower():
        return {
            "ok": False,
            "error_code": "PLANE_SNAPSHOT_HASH_MISMATCH",
            "message": "Provided canonical_sha256 does not match the stored snapshot.",
            "marketing_claim_allowed": False,
        }
    generation = entry.get("policy_generation") if isinstance(entry.get("policy_generation"), dict) else None
    if not generation or not generation.get("fingerprint"):
        return {
            "ok": False,
            "error_code": "PLANE_SNAPSHOT_MISSING_GENERATION",
            "message": "Snapshot entry lacks policy_generation; re-mint snapshot after upgrade.",
            "marketing_claim_allowed": False,
        }
    plane = resolve_app_plane()
    published_before = read_published_policy_generation(db)
    published = publish_policy_generation(db, generation, app_plane=plane)
    apply_id = f"cpsap-{uuid4().hex[:16]}"
    result = {
        "ok": True,
        "apply_id": apply_id,
        "applied_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "actor_id": actor_id,
        "reason": (reason or "").strip()[:500],
        "snapshot_id": entry.get("snapshot_id"),
        "canonical_sha256": entry.get("canonical_sha256"),
        "from_fingerprint": (published_before or {}).get("fingerprint"),
        "to_fingerprint": published.get("fingerprint"),
        "published": published,
        "hash_verified": bool(sha),
        "contract_version": PLANE_CONTRACT_VERSION,
        "marketing_claim_allowed": False,
    }
    logger.info(
        "control_plane_snapshot_applied %s",
        sanitize_fields(
            {
                "apply_id": apply_id,
                "snapshot_id": entry.get("snapshot_id"),
                "to_fingerprint": published.get("fingerprint"),
                "actor_id": actor_id,
            }
        ),
    )
    return result


def _load_peer_ack(db: Session) -> Optional[dict[str, Any]]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_PLANE_PEER_ACK_JSON, "")
    if not raw.strip():
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _load_rollback_summary(db: Session) -> Optional[dict[str, Any]]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_PLANE_ROLLBACK_JSON, "")
    if not raw.strip():
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def set_control_plane_freeze(
    db: Session,
    *,
    enabled: bool,
    actor_id: Optional[str] = None,
    reason: str = "",
) -> dict[str, Any]:
    """Audited runtime change-freeze. Env PLANE_CONTROL_READONLY always wins."""
    sources_before = control_readonly_sources(db)
    if not enabled and sources_before["env"]:
        return {
            "ok": False,
            "error_code": "PLANE_CONTROL_READONLY_ENV",
            "message": "Cannot clear freeze while PLANE_CONTROL_READONLY env is set.",
            "control_readonly_sources": sources_before,
            "marketing_claim_allowed": False,
        }
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_PLANE_CONTROL_READONLY,
        "true" if enabled else "false",
        description="Audited control-plane change freeze (runtime). Env PLANE_CONTROL_READONLY overrides.",
    )
    db.flush()
    invalidate_runtime_config_cache(RUNTIME_CONFIG_PLANE_CONTROL_READONLY)
    sources = control_readonly_sources(db)
    result = {
        "ok": True,
        "enabled": bool(enabled),
        "reason": (reason or "").strip()[:500],
        "actor_id": actor_id,
        "changed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "control_readonly": sources["frozen"],
        "control_readonly_sources": sources,
        "contract_version": PLANE_CONTRACT_VERSION,
        "marketing_claim_allowed": False,
    }
    logger.info(
        "control_plane_freeze_set %s",
        sanitize_fields(
            {
                "enabled": enabled,
                "frozen": sources["frozen"],
                "actor_id": actor_id,
                "reason": result["reason"][:80],
            }
        ),
    )
    return result


def rollback_to_last_known_good(
    db: Session,
    *,
    actor_id: Optional[str] = None,
    reason: str = "",
) -> dict[str, Any]:
    """Re-publish LKG fingerprint as the hot fence (DP continue-on-CP-degradation ceremony).

    Does not mutate route/key inventory — only the published generation fence.
    Desired state may still diverge until a healthy reconcile promotes a new LKG.
    """
    lkg = _load_last_known_good(db)
    if not lkg or not lkg.get("fingerprint"):
        return {
            "ok": False,
            "error_code": "PLANE_LKG_MISSING",
            "message": "No last-known-good fingerprint recorded. Run a healthy reconcile first.",
            "marketing_claim_allowed": False,
        }
    plane = resolve_app_plane()
    published_before = read_published_policy_generation(db)
    desired = compute_policy_generation(db)
    generation = {
        "fingerprint": lkg["fingerprint"],
        "generation": lkg.get("generation") or lkg["fingerprint"],
        "route_count": lkg.get("route_count") or (desired or {}).get("route_count"),
        "key_count": lkg.get("key_count") or (desired or {}).get("key_count"),
        "cache_policy_count": lkg.get("cache_policy_count") or (desired or {}).get("cache_policy_count"),
        "algorithm": (desired or {}).get("algorithm") or "sha256",
    }
    published = publish_policy_generation(db, generation, app_plane=plane)
    rollback_id = f"cplkg-{uuid4().hex[:16]}"
    summary = {
        "rollback_id": rollback_id,
        "ok": True,
        "rolled_back_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "actor_id": actor_id,
        "reason": (reason or "").strip()[:500],
        "from_fingerprint": (published_before or {}).get("fingerprint"),
        "to_fingerprint": published.get("fingerprint"),
        "lkg": lkg,
        "published": published,
        "desired_fingerprint": (desired or {}).get("fingerprint"),
        "desired_still_diverges": (desired or {}).get("fingerprint") != published.get("fingerprint"),
        "contract_version": PLANE_CONTRACT_VERSION,
        "marketing_claim_allowed": False,
    }
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_PLANE_ROLLBACK_JSON,
        json.dumps(
            {
                "rollback_id": rollback_id,
                "rolled_back_at": summary["rolled_back_at"],
                "to_fingerprint": published.get("fingerprint"),
                "from_fingerprint": summary["from_fingerprint"],
                "actor_id": actor_id,
            },
            separators=(",", ":"),
            ensure_ascii=True,
        ),
        description="Latest control-plane LKG rollback ceremony summary.",
    )
    logger.info(
        "control_plane_lkg_rollback %s",
        sanitize_fields(
            {
                "rollback_id": rollback_id,
                "from_fingerprint": summary["from_fingerprint"],
                "to_fingerprint": published.get("fingerprint"),
                "actor_id": actor_id,
            }
        ),
    )
    return summary


def record_peer_ack(
    db: Session,
    *,
    fingerprint: str,
    peer_url: str = "",
    actor_id: Optional[str] = None,
    note: str = "",
) -> dict[str, Any]:
    """Record that a data-plane peer observed/acked a published fingerprint."""
    fp = (fingerprint or "").strip()
    if not fp:
        return {
            "ok": False,
            "error_code": "PLANE_PEER_ACK_FINGERPRINT_REQUIRED",
            "message": "fingerprint is required.",
            "marketing_claim_allowed": False,
        }
    published = read_published_policy_generation(db)
    published_fp = (published or {}).get("fingerprint")
    matches = bool(published_fp) and published_fp == fp
    ack = {
        "ok": True,
        "acked_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "acked_at_unix": time.time(),
        "fingerprint": fp,
        "peer_url": (peer_url or "").strip()[:512],
        "actor_id": actor_id,
        "note": (note or "").strip()[:500],
        "published_fingerprint": published_fp,
        "matches_published": matches,
        "contract_version": PLANE_CONTRACT_VERSION,
        "marketing_claim_allowed": False,
    }
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_PLANE_PEER_ACK_JSON,
        json.dumps(ack, separators=(",", ":"), ensure_ascii=True),
        description="Latest data-plane peer ack of published policy generation fingerprint.",
    )
    logger.info(
        "control_plane_peer_ack %s",
        sanitize_fields(
            {
                "fingerprint": fp,
                "matches_published": matches,
                "peer_url": ack["peer_url"][:80],
                "actor_id": actor_id,
            }
        ),
    )
    return ack


def build_peer_ack_status(db: Session) -> dict[str, Any]:
    ack = _load_peer_ack(db)
    published = read_published_policy_generation(db)
    published_fp = (published or {}).get("fingerprint")
    return {
        "peer_ack": ack,
        "published_fingerprint": published_fp,
        "matches_published": bool(ack and published_fp and ack.get("fingerprint") == published_fp),
        "contract_version": PLANE_CONTRACT_VERSION,
        "marketing_claim_allowed": False,
    }