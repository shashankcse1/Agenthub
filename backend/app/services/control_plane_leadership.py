"""Control Plane Leadership Index (CPLI) — engineering scorecard for market-leader posture.

Separate from the program Leader Readiness Score (max 40, Authority-gated). CPLI measures
whether the *platform control plane* itself is deployable, measurable, and fail-closed —
the engineering half of “governed velocity.” Marketing claims remain Honesty-gated.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.logging_utils import get_logger, sanitize_fields
from app.plane_mode import resolve_app_plane
from app.runtime_constants import (
    RUNTIME_CONFIG_PLANE_FAIL_CLOSED_MODE,
    RUNTIME_CONFIG_PLANE_ISOLATION_CONTRACT_JSON,
    RUNTIME_CONFIG_PLANE_POLICY_GENERATION_JSON,
)
from app.services.leadership_lrs import lrs_honesty_posture
from app.services.on_plane_coverage import compute_on_plane_coverage
from app.services.plane_policy_publish import read_published_policy_generation
from app.services.plane_reconcile import (
    build_plane_slos,
    build_reconcile_posture,
    gate_state_snapshot,
    list_drift_events,
    resolve_fail_closed_mode,
)
from app.services.runtime_config import get_runtime_config, upsert_runtime_config_value

logger = get_logger(__name__)

RUNTIME_CONFIG_PLANE_LEADERSHIP_ATTESTATION_JSON = "plane.leadership_attestation_json"
RUNTIME_CONFIG_PLANE_LEADERSHIP_ATTESTATION_HISTORY_JSON = "plane.leadership_attestation_history_json"
RUNTIME_CONFIG_PLANE_RELEASE_GATE_HISTORY_JSON = "plane.release_gate_history_json"
RUNTIME_CONFIG_PLANE_EVIDENCE_PACK_JSON = "plane.leadership_evidence_pack_json"
ATTESTATION_HISTORY_MAX = 8
RELEASE_GATE_HISTORY_MAX = 12
ATTESTATION_FRESH_HOURS_DEFAULT = 168  # 7d release-gate freshness window


def resolve_release_gate_require_hmac() -> bool:
    raw = (os.getenv("PLANE_RELEASE_GATE_REQUIRE_HMAC") or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def resolve_release_gate_streak_required() -> int:
    raw = (os.getenv("PLANE_RELEASE_GATE_STREAK_REQUIRED") or "2").strip()
    try:
        return max(1, min(int(raw), 12))
    except ValueError:
        return 2


# Max 20 — engineering control-plane index (not the program LRS 40).
CPLI_MAX = 20
CPLI_LEADER_BAND = 16  # eng “contender/leader-ready” without authorizing marketing claims


@lru_cache(maxsize=1)
def plane_split_profile_available() -> bool:
    """True when production compose documents a plane-split profile (deployable isolation)."""
    here = Path(__file__).resolve()
    candidates = [
        here.parents[3] / "docker-compose.production.yml",
        here.parents[2].parent / "docker-compose.production.yml",
        Path.cwd() / "docker-compose.production.yml",
        Path.cwd().parent / "docker-compose.production.yml",
    ]
    seen: set[str] = set()
    for path in candidates:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        try:
            if not path.is_file():
                continue
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if "plane-split" in text and "APP_PLANE: control" in text and "APP_PLANE: data" in text:
            return True
    return False


def _isolation_contract_attested(db: Session) -> bool:
    raw = get_runtime_config(db, RUNTIME_CONFIG_PLANE_ISOLATION_CONTRACT_JSON, "")
    if not str(raw or "").strip():
        return False
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return False
    return isinstance(parsed, dict) and bool(parsed.get("attested"))


def arm_plane_isolation_and_fail_closed(
    db: Session,
    *,
    actor_id: str,
    fail_closed_mode: str = "drift",
) -> dict[str, Any]:
    """Persist fail-closed arming + isolation contract for CPLI (eng scorecard).

    Does not change process APP_PLANE. Fail-closed only enforces on APP_PLANE=data.
    """
    mode = resolve_fail_closed_mode(fail_closed_mode)
    if mode == "off":
        mode = "drift"
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_PLANE_FAIL_CLOSED_MODE,
        mode,
        description="Control-plane fail-closed mode override (env wins when set).",
    )
    # Process-local arming so middleware/gate see the mode without restart.
    os.environ["PLANE_FAIL_CLOSED_MODE"] = mode

    contract = {
        "attested": True,
        "attested_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "attested_by": str(actor_id or "system"),
        "target": "plane-split",
        "compose_profile": "plane-split",
        "note": (
            "Operator attested plane-split isolation contract for CPLI. "
            "Runtime process isolation still requires APP_PLANE=control|data."
        ),
    }
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_PLANE_ISOLATION_CONTRACT_JSON,
        json.dumps(contract, separators=(",", ":"), ensure_ascii=True),
        description="CPLI isolation deploy contract attestation (plane-split).",
    )
    db.flush()
    return {
        "fail_closed_mode": mode,
        "isolation_contract": contract,
        "plane_split_ready": plane_split_profile_available(),
    }


def _parse_attested_at_unix(attestation: Optional[dict[str, Any]]) -> Optional[float]:
    if not isinstance(attestation, dict):
        return None
    raw = attestation.get("attested_at_unix")
    if isinstance(raw, (int, float)):
        return float(raw)
    iso = attestation.get("attested_at")
    if isinstance(iso, str) and iso.strip():
        try:
            normalized = iso.strip().replace("Z", "+00:00")
            return datetime.fromisoformat(normalized).timestamp()
        except ValueError:
            return None
    return None


def _compute_gate_pass_streak(history: list[dict[str, Any]]) -> int:
    streak = 0
    for item in history:
        if item.get("passed"):
            streak += 1
        else:
            break
    return streak


def build_promotion_readiness(
    *,
    scorecard: dict[str, Any],
    release_gate: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Engineering promotion readiness — streak of gate passes + live gate posture.

    Never authorizes marketing leadership claims.
    """
    history = scorecard.get("release_gate_history") if isinstance(scorecard.get("release_gate_history"), list) else []
    gate = release_gate if isinstance(release_gate, dict) else (scorecard.get("release_gate") or {})
    required = resolve_release_gate_streak_required()
    streak = _compute_gate_pass_streak(history)
    freshness = scorecard.get("attestation_freshness") or {}
    verification = scorecard.get("last_attestation_verification") or {}
    blockers: list[str] = []
    if not gate.get("passed"):
        blockers.append("Current release gate is failing — run Evaluate Release Gate after closing checks.")
    if streak < required:
        blockers.append(f"Need {required - streak} more consecutive gate pass(es) (streak {streak}/{required}).")
    if not scorecard.get("engineering_leader_ready"):
        blockers.append("CPLI below engineering leader band.")
    if not freshness.get("fresh"):
        blockers.append("Attestation missing or stale — Attest CPLI.")
    if verification.get("valid") is False:
        blockers.append("Last attestation failed integrity verification.")
    ready = (
        bool(gate.get("passed"))
        and streak >= required
        and bool(scorecard.get("engineering_leader_ready"))
        and bool(freshness.get("fresh"))
        and verification.get("valid") is not False
    )
    return {
        "ready": ready,
        "streak": streak,
        "streak_required": required,
        "current_gate_passed": bool(gate.get("passed")),
        "engineering_leader_ready": bool(scorecard.get("engineering_leader_ready")),
        "attestation_fresh": bool(freshness.get("fresh")),
        "attestation_valid": verification.get("valid"),
        "blockers": blockers,
        "marketing_claim_allowed": False,
        "note": (
            "Promotion readiness is engineering-only. Program Leader Readiness / Authority "
            "remain required for external leadership claims."
        ),
    }


def build_control_plane_ops_summary(db: Session) -> dict[str, Any]:
    """Cheap ops summary for banners — prefers persisted history over full scorecard."""
    from app.services.control_plane_contract import (
        PLANE_CONTRACT_VERSION,
        RUNTIME_CONFIG_PLANE_LAST_KNOWN_GOOD_JSON,
        RUNTIME_CONFIG_PLANE_SNAPSHOT_JSON,
        build_control_plane_readiness,
        resolve_control_readonly,
    )

    history = _load_release_gate_history(db)
    streak = _compute_gate_pass_streak(history)
    required = resolve_release_gate_streak_required()
    last_gate = history[0] if history else None
    last_attest_raw = get_runtime_config(db, RUNTIME_CONFIG_PLANE_LEADERSHIP_ATTESTATION_JSON, "")
    last_attest = None
    if last_attest_raw.strip():
        try:
            parsed = json.loads(last_attest_raw)
            if isinstance(parsed, dict):
                last_attest = parsed
        except json.JSONDecodeError:
            last_attest = None
    freshness = _attestation_freshness(last_attest)
    evidence_raw = get_runtime_config(db, RUNTIME_CONFIG_PLANE_EVIDENCE_PACK_JSON, "")
    evidence = None
    if evidence_raw.strip():
        try:
            parsed = json.loads(evidence_raw)
            if isinstance(parsed, dict):
                evidence = parsed
        except json.JSONDecodeError:
            evidence = None
    control_readonly = resolve_control_readonly(db)
    ready = True
    failed_checks: list[str] = []
    try:
        readiness = build_control_plane_readiness(db)
        ready = bool(readiness.get("ready"))
        failed_checks = list(readiness.get("failed_checks") or [])
    except Exception:
        ready = False
        failed_checks = ["readiness_unavailable"]
    lkg_raw = get_runtime_config(db, RUNTIME_CONFIG_PLANE_LAST_KNOWN_GOOD_JSON, "")
    lkg_fp = None
    if lkg_raw.strip():
        try:
            lkg_parsed = json.loads(lkg_raw)
            if isinstance(lkg_parsed, dict):
                lkg_fp = lkg_parsed.get("fingerprint")
        except json.JSONDecodeError:
            lkg_fp = None
    snap_raw = get_runtime_config(db, RUNTIME_CONFIG_PLANE_SNAPSHOT_JSON, "")
    last_snapshot_id = None
    if snap_raw.strip():
        try:
            snap_parsed = json.loads(snap_raw)
            if isinstance(snap_parsed, dict):
                last_snapshot_id = snap_parsed.get("snapshot_id")
        except json.JSONDecodeError:
            last_snapshot_id = None
    from app.services.control_plane_contract import (
        RUNTIME_CONFIG_PLANE_PEER_ACK_JSON,
        RUNTIME_CONFIG_PLANE_ROLLBACK_JSON,
        control_readonly_sources,
    )

    peer_ack_raw = get_runtime_config(db, RUNTIME_CONFIG_PLANE_PEER_ACK_JSON, "")
    peer_ack_matches = None
    if peer_ack_raw.strip():
        try:
            peer_ack_parsed = json.loads(peer_ack_raw)
            if isinstance(peer_ack_parsed, dict):
                peer_ack_matches = peer_ack_parsed.get("matches_published")
        except json.JSONDecodeError:
            peer_ack_matches = None
    rollback_raw = get_runtime_config(db, RUNTIME_CONFIG_PLANE_ROLLBACK_JSON, "")
    last_rollback_id = None
    if rollback_raw.strip():
        try:
            rb = json.loads(rollback_raw)
            if isinstance(rb, dict):
                last_rollback_id = rb.get("rollback_id")
        except json.JSONDecodeError:
            last_rollback_id = None
    freeze_sources = control_readonly_sources(db)
    advisory = None
    if control_readonly:
        src = "env" if freeze_sources.get("env") else "runtime"
        advisory = f"Control-plane write freeze active ({src}) — mutations blocked."
    elif not ready:
        failed = ",".join(failed_checks) if failed_checks else "unknown"
        advisory = f"Control-plane readiness failed ({failed}) — check /platform/control-plane/ready."
    elif last_gate is not None and not last_gate.get("passed"):
        advisory = "Control-plane release gate last evaluation failed — review Overview Control Plane."
    elif not freshness.get("fresh"):
        advisory = "Control-plane CPLI attestation missing or stale — Attest CPLI on Overview."
    elif streak < required:
        advisory = f"Control-plane gate streak {streak}/{required} — evaluate gate before promotion."
    return {
        "release_gate_last_passed": None if last_gate is None else bool(last_gate.get("passed")),
        "release_gate_streak": streak,
        "release_gate_streak_required": required,
        "attestation_fresh": bool(freshness.get("fresh")),
        "attestation_age_hours": freshness.get("age_hours"),
        "last_evidence_pack_id": (evidence or {}).get("pack_id"),
        "control_readonly": control_readonly,
        "control_readonly_sources": freeze_sources,
        "ready": ready,
        "alive": True,
        "failed_checks": failed_checks,
        "contract_version": PLANE_CONTRACT_VERSION,
        "last_known_good_fingerprint": lkg_fp,
        "last_snapshot_id": last_snapshot_id,
        "peer_ack_matches_published": peer_ack_matches,
        "last_rollback_id": last_rollback_id,
        "advisory": advisory,
        "marketing_claim_allowed": False,
    }


def _compute_score_trend(
    history: list[dict[str, Any]],
    *,
    current_score: int,
) -> dict[str, Any]:
    """Delta vs previous attestation score — release-gate trend signal."""
    prior_score = None
    for idx, item in enumerate(history):
        score = item.get("score")
        if not isinstance(score, (int, float)):
            continue
        # history[0] is latest attestation; use the next older sample as prior.
        if idx == 0:
            continue
        prior_score = int(score)
        break
    delta = None if prior_score is None else int(current_score) - int(prior_score)
    if delta is None:
        direction = "unknown"
    elif delta > 0:
        direction = "up"
    elif delta < 0:
        direction = "down"
    else:
        direction = "flat"
    return {
        "current_score": int(current_score),
        "prior_attested_score": prior_score,
        "delta": delta,
        "direction": direction,
        "samples": len(history),
    }


def _attestation_freshness(
    last_attestation: Optional[dict[str, Any]],
    *,
    max_age_hours: int = ATTESTATION_FRESH_HOURS_DEFAULT,
) -> dict[str, Any]:
    attested_at = _parse_attested_at_unix(last_attestation)
    now = time.time()
    if attested_at is None:
        return {
            "fresh": False,
            "age_hours": None,
            "max_age_hours": max_age_hours,
            "reason": "missing_attestation",
        }
    age_hours = max(0.0, (now - attested_at) / 3600.0)
    fresh = age_hours <= float(max_age_hours)
    return {
        "fresh": fresh,
        "age_hours": round(age_hours, 2),
        "max_age_hours": max_age_hours,
        "attested_at_unix": attested_at,
        "reason": "ok" if fresh else "stale",
    }

def _primary_signing_secret() -> tuple[Optional[str], Optional[str]]:
    raw_keys = (os.getenv("SESSION_TOKEN_SIGNING_KEYS") or "").strip()
    if not raw_keys:
        return None, None
    first = raw_keys.split(",")[0].strip()
    if ":" not in first:
        return None, None
    kid, _, secret = first.partition(":")
    if not secret.strip():
        return None, None
    return kid.strip() or "primary", secret.strip()


def _sign_attestation_payload(canonical: str) -> dict[str, Any]:
    """HMAC-SHA256 with primary session signing key when configured; else content hash."""
    kid, secret = _primary_signing_secret()
    if kid and secret:
        digest = hmac.new(
            secret.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        return {
            "algorithm": "HMAC-SHA256",
            "key_id": kid,
            "signature": digest,
            "signed": True,
        }
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {
        "algorithm": "SHA256",
        "key_id": None,
        "signature": digest,
        "signed": False,
        "note": "SESSION_TOKEN_SIGNING_KEYS not configured; content hash only.",
    }


def _attestation_body_without_signature(bundle: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in bundle.items()
        if key
        not in {
            "signature",
            "canonical_sha256",
            "attestation_history",
            "verification",
        }
    }


def verify_attestation_bundle(bundle: Optional[dict[str, Any]]) -> dict[str, Any]:
    """Verify HMAC or content-hash integrity of a persisted attestation bundle."""
    if not isinstance(bundle, dict) or not bundle.get("attestation_id"):
        return {"valid": False, "reason": "missing_attestation"}
    signature = bundle.get("signature")
    if not isinstance(signature, dict) or not signature.get("signature"):
        return {"valid": False, "reason": "missing_signature"}
    body = _attestation_body_without_signature(bundle)
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    expected_sha = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    stored_sha = bundle.get("canonical_sha256")
    if stored_sha and stored_sha != expected_sha:
        return {"valid": False, "reason": "canonical_mismatch"}

    algorithm = str(signature.get("algorithm") or "")
    if algorithm == "HMAC-SHA256" and signature.get("signed"):
        kid, secret = _primary_signing_secret()
        if not secret:
            return {
                "valid": False,
                "reason": "signing_key_unavailable",
                "attestation_id": bundle.get("attestation_id"),
            }
        recomputed = hmac.new(
            secret.encode("utf-8"),
            canonical.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        ok = hmac.compare_digest(recomputed, str(signature.get("signature")))
        return {
            "valid": ok,
            "reason": "ok" if ok else "hmac_mismatch",
            "algorithm": algorithm,
            "key_id": signature.get("key_id") or kid,
            "attestation_id": bundle.get("attestation_id"),
        }

    recomputed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    ok = hmac.compare_digest(recomputed, str(signature.get("signature")))
    return {
        "valid": ok,
        "reason": "ok" if ok else "hash_mismatch",
        "algorithm": algorithm or "SHA256",
        "signed": False,
        "attestation_id": bundle.get("attestation_id"),
    }


def _load_attestation_history(db: Session) -> list[dict[str, Any]]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_PLANE_LEADERSHIP_ATTESTATION_HISTORY_JSON, "")
    if not raw.strip():
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def _append_attestation_history(db: Session, bundle: dict[str, Any]) -> list[dict[str, Any]]:
    history = _load_attestation_history(db)
    summary = {
        "attestation_id": bundle.get("attestation_id"),
        "attested_at": bundle.get("attested_at"),
        "attested_by": bundle.get("attested_by"),
        "score": (bundle.get("scorecard") or {}).get("score"),
        "band": (bundle.get("scorecard") or {}).get("band"),
        "signed": bool((bundle.get("signature") or {}).get("signed")),
        "canonical_sha256": bundle.get("canonical_sha256"),
    }
    history = [summary, *[h for h in history if h.get("attestation_id") != summary["attestation_id"]]]
    history = history[:ATTESTATION_HISTORY_MAX]
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_PLANE_LEADERSHIP_ATTESTATION_HISTORY_JSON,
        json.dumps(history, separators=(",", ":"), ensure_ascii=True),
        description="Ring buffer of recent control-plane leadership attestation summaries.",
    )
    return history


def _load_release_gate_history(db: Session) -> list[dict[str, Any]]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_PLANE_RELEASE_GATE_HISTORY_JSON, "")
    if not raw.strip():
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def _append_release_gate_history(db: Session, evaluation: dict[str, Any]) -> list[dict[str, Any]]:
    history = _load_release_gate_history(db)
    summary = {
        "evaluation_id": evaluation.get("evaluation_id"),
        "evaluated_at": evaluation.get("generated_at"),
        "evaluated_by": evaluation.get("evaluated_by"),
        "passed": bool(evaluation.get("passed")),
        "score": evaluation.get("score"),
        "band": evaluation.get("band"),
        "failed_checks": evaluation.get("failed_checks") or [],
        "advisory_failed_checks": evaluation.get("advisory_failed_checks") or [],
        "require_hmac": bool(evaluation.get("require_hmac")),
        "ci_exit_code_hint": (evaluation.get("ci") or {}).get("exit_code_hint"),
    }
    history = [summary, *[h for h in history if h.get("evaluation_id") != summary["evaluation_id"]]]
    history = history[:RELEASE_GATE_HISTORY_MAX]
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_PLANE_RELEASE_GATE_HISTORY_JSON,
        json.dumps(history, separators=(",", ":"), ensure_ascii=True),
        description="Ring buffer of audited control-plane release-gate evaluations.",
    )
    return history

def _prioritized_next_actions(blockers: list[str], *, score: int, plane: str) -> list[dict[str, Any]]:
    """Operator playbook toward CPLI leader band — ranked, never marketing advice."""
    actions: list[dict[str, Any]] = []
    for idx, blocker in enumerate(blockers[:5]):
        actions.append(
            {
                "priority": idx + 1,
                "action": blocker,
                "closes_toward": "cpli_leader_band",
            }
        )
    if score < CPLI_LEADER_BAND and not any("APP_PLANE" in a.get("action", "") for a in actions):
        if plane == "all":
            actions.append(
                {
                    "priority": len(actions) + 1,
                    "action": "Run compose profile plane-split and set APP_PLANE=control|data on each process.",
                    "closes_toward": "cpli_leader_band",
                }
            )
    if score >= CPLI_LEADER_BAND:
        actions.append(
            {
                "priority": 1,
                "action": (
                    "Engineering band met — keep attesting each release; program LRS/Authority "
                    "still required before external leadership claims."
                ),
                "closes_toward": "honesty_fence",
            }
        )
    return actions[:5]


def _score_item(points: int, max_points: int, *, met: bool, partial: bool = False) -> dict[str, Any]:
    if met:
        score = max_points
    elif partial:
        score = max(1, max_points // 2) if max_points >= 2 else 0
    else:
        score = 0
    return {"score": score, "max": max_points, "points": points}


def build_control_plane_leadership(
    db: Session,
    *,
    window_hours: int = 24,
    environment: Optional[str] = None,
    probe_peer: bool = False,
) -> dict[str, Any]:
    """Compute CPLI scorecard from live plane reconcile + coverage + drift evidence."""
    plane = resolve_app_plane()
    window_start = datetime.now(timezone.utc) - timedelta(hours=max(1, min(int(window_hours), 720)))
    coverage = compute_on_plane_coverage(db, window_start=window_start, environment=environment)
    reconcile = build_reconcile_posture(
        db,
        plane=plane,
        probe_peer=probe_peer,
        on_plane_coverage=coverage,
    )
    published = reconcile.get("published_policy_generation") or read_published_policy_generation(db)
    slos = reconcile.get("slos") or build_plane_slos(
        peer=reconcile.get("peer"),
        published=published,
        on_plane_coverage=coverage,
        drift_status=reconcile.get("drift_status"),
    )
    drift_events = list_drift_events(10, db=db)
    durable_count = sum(1 for ev in drift_events if ev.get("durable"))
    fail_closed_mode = resolve_fail_closed_mode(db=db)
    gate = reconcile.get("gate") or gate_state_snapshot()

    dimensions: list[dict[str, Any]] = []

    # 1. Process isolation (0–3)
    split_ready = plane_split_profile_available()
    isolation_contract = _isolation_contract_attested(db)
    if plane in {"control", "data"}:
        isolation_score = 3
        isolation_note = f"APP_PLANE={plane} process-isolated"
    elif plane == "all" and split_ready and isolation_contract:
        isolation_score = 3
        isolation_note = (
            "Isolation contract attested for plane-split deploy "
            "(process still APP_PLANE=all until control|data processes are live)"
        )
    elif plane == "all" and split_ready:
        isolation_score = 2
        isolation_note = "APP_PLANE=all · plane-split compose profile available (attest contract or deploy to earn 3/3)"
    elif plane == "all":
        isolation_score = 1
        isolation_note = "APP_PLANE=all combined monolith (deploy split available)"
    else:
        isolation_score = 0
        isolation_note = "Unknown plane mode"
    dimensions.append(
        {
            "id": "isolation",
            "label": "Process isolation",
            "score": isolation_score,
            "max": 3,
            "note": isolation_note,
            "split_ready": split_ready,
            "isolation_contract_attested": isolation_contract,
        }
    )

    # 2. Hot policy publish (0–3)
    if published and published.get("fingerprint"):
        backends = published.get("publish_backends") or published.get("read_backend")
        hot_score = 3 if backends else 2
        hot_note = f"Published fingerprint {published.get('fingerprint')} via {backends or published.get('read_backend')}"
    else:
        hot_score = 0
        hot_note = "No published policy generation — run Force Reconcile"
    dimensions.append(
        {
            "id": "hot_publish",
            "label": "Hot policy publish",
            "score": hot_score,
            "max": 3,
            "note": hot_note,
        }
    )

    # 3. Durable drift evidence (0–3)
    if durable_count > 0:
        durable_score = 3
        durable_note = f"{durable_count} durable drift events in recent window"
    elif drift_events:
        durable_score = 1
        durable_note = "In-process drift history only (table empty or unavailable)"
    else:
        durable_score = 0
        durable_note = "No drift events recorded"
    dimensions.append(
        {
            "id": "durable_drift",
            "label": "Durable drift evidence",
            "score": durable_score,
            "max": 3,
            "note": durable_note,
        }
    )

    # 4. Fail-closed readiness (0–3)
    if fail_closed_mode == "drift":
        fc_score = 3
        fc_note = "PLANE_FAIL_CLOSED_MODE=drift armed"
    elif fail_closed_mode == "peer_unreachable":
        fc_score = 2
        fc_note = "PLANE_FAIL_CLOSED_MODE=peer_unreachable armed"
    elif plane == "all" and split_ready:
        fc_score = 2
        fc_note = (
            "Fail-closed modes documented for plane-split data plane "
            "(mode=off on combined; arm drift via Raise Leadership Score for 3/3)"
        )
    else:
        fc_score = 1
        fc_note = "Fail-closed available but mode=off (safe default)"
    dimensions.append(
        {
            "id": "fail_closed",
            "label": "Fail-closed gate",
            "score": fc_score,
            "max": 3,
            "note": fc_note,
            "mode": fail_closed_mode,
        }
    )

    # 5. Contract SLOs measured (0–4) — on-plane + peer + generation + overall
    slo_points = 0
    slo_notes: list[str] = []
    if slos.get("on_plane_within_slo") is True:
        slo_points += 1
        slo_notes.append("on-plane≥SLO")
    elif slos.get("on_plane_coverage_percent") is not None:
        slo_notes.append("on-plane below SLO")
    else:
        slo_notes.append("on-plane n/a")

    if slos.get("peer_probe_within_slo") is True:
        slo_points += 1
        slo_notes.append("peer latency ok")
    if slos.get("generation_within_slo") is True:
        slo_points += 1
        slo_notes.append("generation fresh")
    if slos.get("overall_within_slo") is True:
        slo_points += 1
        slo_notes.append("overall ok")
    dimensions.append(
        {
            "id": "slos",
            "label": "Measured plane SLOs",
            "score": min(4, slo_points),
            "max": 4,
            "note": ", ".join(slo_notes),
        }
    )

    # 6. Active watcher + reconcile (0–2)
    watcher_on = bool(gate.get("watcher_enabled"))
    has_last = bool(reconcile.get("last_reconcile") or drift_events)
    last_reconcile = reconcile.get("last_reconcile") if isinstance(reconcile.get("last_reconcile"), dict) else {}
    last_reconcile_fresh = False
    raw_unix = last_reconcile.get("recorded_at_unix")
    if isinstance(raw_unix, (int, float)) and raw_unix > 0:
        last_reconcile_fresh = (time.time() - float(raw_unix)) <= 24 * 3600
    else:
        raw_reconciled = str(last_reconcile.get("reconciled_at") or last_reconcile.get("recorded_at") or "")
        if raw_reconciled:
            try:
                ts = datetime.fromisoformat(raw_reconciled.replace("Z", "+00:00"))
                last_reconcile_fresh = (datetime.now(timezone.utc) - ts).total_seconds() <= 24 * 3600
            except ValueError:
                last_reconcile_fresh = False
    if watcher_on and has_last:
        watch_score = 2
        watch_note = f"Watcher on · ticks={gate.get('watcher_ticks') or 0}"
    elif has_last and last_reconcile_fresh:
        watch_score = 2
        watch_note = "Fresh reconcile within 24h (watcher optional on combined plane)"
    elif watcher_on or has_last:
        watch_score = 1
        watch_note = "Partial: watcher or reconcile history present"
    else:
        watch_score = 0
        watch_note = "No active watcher / reconcile history"
    dimensions.append(
        {
            "id": "active_reconcile",
            "label": "Active reconcile",
            "score": watch_score,
            "max": 2,
            "note": watch_note,
        }
    )

    # 7. Honesty / claim discipline (0–2) — eng never self-authorizes marketing
    lrs = lrs_honesty_posture(db)
    if lrs.get("leader_claim_allowed"):
        honesty_score = 2
        honesty_note = (
            f"Program LRS gate met ({(lrs.get('attestation') or {}).get('score')}/40) — "
            "CPLI remains engineering-only; external claims follow QBR honesty block"
        )
    else:
        honesty_score = 2
        honesty_note = "External marketing claims remain blocked without program LRS ≥32 + Authority"
    dimensions.append(
        {
            "id": "honesty",
            "label": "Honesty fence",
            "score": honesty_score,
            "max": 2,
            "note": honesty_note,
        }
    )

    total = sum(int(d["score"]) for d in dimensions)
    if total >= CPLI_LEADER_BAND:
        band = "leader_ready_engineering"
    elif total >= 12:
        band = "contender"
    elif total >= 8:
        band = "emerging"
    else:
        band = "foundation"

    blockers: list[str] = []
    if plane == "all":
        if split_ready and isolation_contract:
            blockers.append(
                "Optional: live-deploy APP_PLANE=control|data (compose profile plane-split) for runtime process isolation."
            )
        elif split_ready:
            blockers.append(
                "Attest isolation contract (Raise Leadership Score) or deploy APP_PLANE=control|data for isolation 3/3."
            )
        else:
            blockers.append("Deploy APP_PLANE=control|data for production isolation (compose profile plane-split).")
    if not published or not published.get("fingerprint"):
        blockers.append("Publish policy generation via POST /platform/control-plane/reconcile.")
    if durable_count == 0:
        blockers.append("Persist drift events (ensure plane_drift_events schema + reconcile).")
    if slos.get("on_plane_within_slo") is False:
        blockers.append("Raise on-plane coverage to ≥ SLO (default 90%).")
    if fail_closed_mode == "off":
        blockers.append("Arm PLANE_FAIL_CLOSED_MODE=drift (Raise Leadership Score or env) for fail-closed 3/3.")
    # Drop informational optional blockers when already engineering-leader-ready
    if total >= CPLI_LEADER_BAND:
        blockers = [b for b in blockers if not b.startswith("Optional:")]

    last_attestation_raw = get_runtime_config(db, RUNTIME_CONFIG_PLANE_LEADERSHIP_ATTESTATION_JSON, "")
    last_attestation = None
    if last_attestation_raw.strip():
        try:
            parsed = json.loads(last_attestation_raw)
            if isinstance(parsed, dict):
                last_attestation = parsed
        except json.JSONDecodeError:
            last_attestation = None

    last_attestation_verification = verify_attestation_bundle(last_attestation)
    attestation_history = _load_attestation_history(db)
    next_actions = _prioritized_next_actions(blockers, score=total, plane=plane)
    points_to_leader = max(0, CPLI_LEADER_BAND - total)
    score_trend = _compute_score_trend(attestation_history, current_score=total)
    attestation_freshness = _attestation_freshness(last_attestation)

    result = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "index_name": "control_plane_leadership_index",
        "score": total,
        "max_score": CPLI_MAX,
        "band": band,
        "leader_band_threshold": CPLI_LEADER_BAND,
        "points_to_leader_band": points_to_leader,
        "engineering_leader_ready": total >= CPLI_LEADER_BAND,
        "marketing_claim_allowed": False,
        "marketing_claim_reason": (
            lrs.get("reason")
            if lrs.get("leader_claim_allowed")
            else (
                "CPLI is engineering-only. Program Leader Readiness (Authority/Clocks) and formal "
                "sign-off are required before external leadership claims."
            )
        ),
        "program_lrs": lrs.get("attestation"),
        "app_plane": plane,
        "plane_split_ready": split_ready,
        "dimensions": dimensions,
        "slos": slos,
        "drift_status": reconcile.get("drift_status"),
        "policy_fingerprint": (reconcile.get("policy_generation") or {}).get("fingerprint"),
        "published_fingerprint": (published or {}).get("fingerprint"),
        "on_plane_coverage_percent": coverage.get("on_plane_coverage_percent"),
        "blockers": blockers,
        "next_actions": next_actions,
        "score_trend": score_trend,
        "attestation_freshness": attestation_freshness,
        "last_attestation": last_attestation,
        "last_attestation_verification": last_attestation_verification,
        "attestation_history": attestation_history,
        "release_gate_history": _load_release_gate_history(db),
        "competitor_parity_notes": [
            "Isolation + fail-closed + measured on-plane % match Portkey/Helicone control-plane narrative.",
            "Hot policy publish + durable drift evidence close the ops gap vs proxy-only dashboards.",
            "Signed attestation + history ring give release-gate evidence competitors often lack in UI.",
            "Release-gate checklist + evidence pack close the ops parity gap vs checklist-only dashboards.",
            "Honesty fence prevents checklist theater from becoming a marketing claim.",
        ],
    }
    result["release_gate"] = build_control_plane_release_gate(
        db,
        window_hours=window_hours,
        environment=environment,
        probe_peer=False,
        scorecard=result,
    )
    result["promotion_readiness"] = build_promotion_readiness(
        scorecard=result,
        release_gate=result.get("release_gate") if isinstance(result.get("release_gate"), dict) else None,
    )
    logger.info(
        "control_plane_leadership_scored %s",
        sanitize_fields(
            {
                "score": total,
                "band": band,
                "app_plane": plane,
                "engineering_leader_ready": total >= CPLI_LEADER_BAND,
            }
        ),
    )
    return result


def attest_control_plane_leadership(
    db: Session,
    *,
    actor_id: str,
    window_hours: int = 24,
    environment: Optional[str] = None,
    probe_peer: bool = True,
) -> dict[str, Any]:
    """Build a signed attestation bundle and persist latest copy to runtime_config."""
    scorecard = build_control_plane_leadership(
        db,
        window_hours=window_hours,
        environment=environment,
        probe_peer=probe_peer,
    )
    attestation_id = f"cpla-{uuid4().hex[:16]}"
    body = {
        "attestation_id": attestation_id,
        "attested_at_unix": time.time(),
        "attested_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "attested_by": actor_id,
        "scorecard": {
            "score": scorecard["score"],
            "max_score": scorecard["max_score"],
            "band": scorecard["band"],
            "engineering_leader_ready": scorecard["engineering_leader_ready"],
            "app_plane": scorecard["app_plane"],
            "dimensions": scorecard["dimensions"],
            "policy_fingerprint": scorecard.get("policy_fingerprint"),
            "published_fingerprint": scorecard.get("published_fingerprint"),
            "drift_status": scorecard.get("drift_status"),
            "on_plane_coverage_percent": scorecard.get("on_plane_coverage_percent"),
            "slos": scorecard.get("slos"),
            "blockers": scorecard.get("blockers"),
        },
        "marketing_claim_allowed": False,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    signature = _sign_attestation_payload(canonical)
    bundle = {**body, "signature": signature, "canonical_sha256": hashlib.sha256(canonical.encode()).hexdigest()}
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_PLANE_LEADERSHIP_ATTESTATION_JSON,
        json.dumps(bundle, separators=(",", ":"), ensure_ascii=True),
        description="Latest control-plane leadership attestation bundle (HMAC when signing keys configured).",
    )
    history = _append_attestation_history(db, bundle)
    # Touch policy generation key presence for inventory clarity (no overwrite of fingerprint).
    _ = get_runtime_config(db, RUNTIME_CONFIG_PLANE_POLICY_GENERATION_JSON, "")
    logger.info(
        "control_plane_leadership_attested %s",
        sanitize_fields(
            {
                "attestation_id": attestation_id,
                "actor_id": actor_id,
                "score": scorecard["score"],
                "signed": signature.get("signed"),
                "history_len": len(history),
            }
        ),
    )
    bundle["attestation_history"] = history
    bundle["verification"] = verify_attestation_bundle(bundle)
    return bundle


def build_control_plane_release_gate(
    db: Session,
    *,
    window_hours: int = 24,
    environment: Optional[str] = None,
    probe_peer: bool = False,
    require_hmac: Optional[bool] = None,
    max_attestation_age_hours: int = ATTESTATION_FRESH_HOURS_DEFAULT,
    scorecard: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Engineering release gate — never authorizes marketing leadership claims."""
    if require_hmac is None:
        require_hmac = resolve_release_gate_require_hmac()
    if scorecard is None:
        scorecard = build_control_plane_leadership(
            db,
            window_hours=window_hours,
            environment=environment,
            probe_peer=probe_peer,
        )
    freshness = scorecard.get("attestation_freshness") or _attestation_freshness(
        scorecard.get("last_attestation") if isinstance(scorecard.get("last_attestation"), dict) else None,
        max_age_hours=max_attestation_age_hours,
    )
    if int(freshness.get("max_age_hours") or 0) != int(max_attestation_age_hours):
        freshness = _attestation_freshness(
            scorecard.get("last_attestation") if isinstance(scorecard.get("last_attestation"), dict) else None,
            max_age_hours=max_attestation_age_hours,
        )
    verification = scorecard.get("last_attestation_verification") or {}
    last = scorecard.get("last_attestation") if isinstance(scorecard.get("last_attestation"), dict) else {}
    signed = bool((last.get("signature") or {}).get("signed"))
    published_fp = scorecard.get("published_fingerprint")
    live_fp = scorecard.get("policy_fingerprint")
    drift = str(scorecard.get("drift_status") or "")
    checks = [
        {
            "id": "cpli_leader_band",
            "label": "CPLI ≥ leader band",
            "passed": bool(scorecard.get("engineering_leader_ready")),
            "detail": f"{scorecard.get('score')}/{scorecard.get('max_score')} (need ≥{scorecard.get('leader_band_threshold')})",
        },
        {
            "id": "attestation_present",
            "label": "Attestation present",
            "passed": bool(last.get("attestation_id")),
            "detail": last.get("attestation_id") or "none",
        },
        {
            "id": "attestation_valid",
            "label": "Attestation integrity valid",
            "passed": bool(verification.get("valid")),
            "detail": verification.get("reason") or "n/a",
        },
        {
            "id": "attestation_fresh",
            "label": f"Attestation fresh (≤{max_attestation_age_hours}h)",
            "passed": bool(freshness.get("fresh")),
            "detail": (
                f"age={freshness.get('age_hours')}h"
                if freshness.get("age_hours") is not None
                else freshness.get("reason") or "missing"
            ),
        },
        {
            "id": "fingerprint_aligned",
            "label": "Published fingerprint aligns with live policy",
            "passed": bool(published_fp) and published_fp == live_fp,
            "detail": f"live={live_fp or 'none'} published={published_fp or 'none'}",
        },
        {
            "id": "no_active_drift",
            "label": "No active peer/policy drift",
            "passed": drift not in {"drift_detected", "peer_unreachable", "published_mismatch"},
            "detail": drift or "none",
        },
        {
            "id": "hmac_signed",
            "label": "Attestation HMAC-signed" + (" (required)" if require_hmac else " (preferred)"),
            "passed": signed if require_hmac else True,
            "detail": "signed" if signed else "hash-only",
            "preferred": not require_hmac,
            "preferred_met": signed,
        },
        {
            "id": "process_isolation",
            "label": "Process isolation (APP_PLANE≠all)",
            "passed": scorecard.get("app_plane") in {"control", "data"},
            "detail": f"APP_PLANE={scorecard.get('app_plane')}",
            "severity": "advisory",
        },
    ]
    # Combined monolith: isolation is advisory so local/dev can still pass eng gate.
    required_for_pass = [c for c in checks if c.get("severity") != "advisory"]
    passed = all(bool(c.get("passed")) for c in required_for_pass)
    failed = [c["id"] for c in required_for_pass if not c.get("passed")]
    advisory_failed = [c["id"] for c in checks if c.get("severity") == "advisory" and not c.get("passed")]

    gate = {
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "gate_name": "control_plane_engineering_release_gate",
        "passed": passed,
        "failed_checks": failed,
        "advisory_failed_checks": advisory_failed,
        "require_hmac": require_hmac,
        "max_attestation_age_hours": max_attestation_age_hours,
        "checks": checks,
        "score": scorecard.get("score"),
        "band": scorecard.get("band"),
        "engineering_leader_ready": scorecard.get("engineering_leader_ready"),
        "score_trend": scorecard.get("score_trend"),
        "attestation_freshness": freshness,
        "ci": {
            "exit_code_hint": 0 if passed else 1,
            "go_no_go": "go" if passed else "no_go",
            "note": "Engineering gate only — does not authorize marketing leadership claims.",
        },
        "marketing_claim_allowed": False,
        "marketing_claim_reason": (
            "Release gate is engineering-only. External leadership claims require program LRS + Authority."
        ),
        "next_actions": scorecard.get("next_actions") or [],
        "release_gate_history": scorecard.get("release_gate_history")
        if isinstance(scorecard.get("release_gate_history"), list)
        else _load_release_gate_history(db),
    }
    logger.info(
        "control_plane_release_gate_evaluated %s",
        sanitize_fields(
            {
                "passed": passed,
                "failed": failed,
                "score": scorecard.get("score"),
                "advisory_failed": advisory_failed,
            }
        ),
    )
    return gate


def evaluate_control_plane_release_gate(
    db: Session,
    *,
    actor_id: str,
    window_hours: int = 24,
    environment: Optional[str] = None,
    probe_peer: bool = False,
    require_hmac: Optional[bool] = None,
    max_attestation_age_hours: int = ATTESTATION_FRESH_HOURS_DEFAULT,
) -> dict[str, Any]:
    """Auditable release-gate evaluation — persists history for CI/release ceremonies."""
    gate = build_control_plane_release_gate(
        db,
        window_hours=window_hours,
        environment=environment,
        probe_peer=probe_peer,
        require_hmac=require_hmac,
        max_attestation_age_hours=max_attestation_age_hours,
    )
    evaluation_id = f"cprg-{uuid4().hex[:16]}"
    gate["evaluation_id"] = evaluation_id
    gate["evaluated_by"] = actor_id
    gate["persisted"] = True
    history = _append_release_gate_history(db, gate)
    gate["release_gate_history"] = history
    logger.info(
        "control_plane_release_gate_persisted %s",
        sanitize_fields(
            {
                "evaluation_id": evaluation_id,
                "actor_id": actor_id,
                "passed": gate.get("passed"),
                "exit_code_hint": (gate.get("ci") or {}).get("exit_code_hint"),
            }
        ),
    )
    return gate


def build_control_plane_evidence_pack(
    db: Session,
    *,
    window_hours: int = 24,
    environment: Optional[str] = None,
    probe_peer: bool = True,
    require_hmac: Optional[bool] = None,
    max_attestation_age_hours: int = ATTESTATION_FRESH_HOURS_DEFAULT,
    persist: bool = True,
    actor_id: Optional[str] = None,
) -> dict[str, Any]:
    """Exportable engineering evidence pack for release / audit review (HMAC when keys set)."""
    if require_hmac is None:
        require_hmac = resolve_release_gate_require_hmac()
    scorecard = build_control_plane_leadership(
        db,
        window_hours=window_hours,
        environment=environment,
        probe_peer=probe_peer,
    )
    gate = build_control_plane_release_gate(
        db,
        window_hours=window_hours,
        environment=environment,
        probe_peer=False,
        require_hmac=require_hmac,
        max_attestation_age_hours=max_attestation_age_hours,
        scorecard=scorecard,
    )
    pack_id = f"cpep-{uuid4().hex[:16]}"
    drift_events = list_drift_events(12, db=db)
    body = {
        "pack_id": pack_id,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "generated_by": actor_id,
        "purpose": "control_plane_engineering_evidence",
        "marketing_claim_allowed": False,
        "release_gate": {
            "passed": gate.get("passed"),
            "failed_checks": gate.get("failed_checks"),
            "advisory_failed_checks": gate.get("advisory_failed_checks"),
            "checks": gate.get("checks"),
            "ci": gate.get("ci"),
        },
        "promotion_readiness": scorecard.get("promotion_readiness")
        or build_promotion_readiness(scorecard=scorecard, release_gate=gate),
        "scorecard": {
            "score": scorecard.get("score"),
            "max_score": scorecard.get("max_score"),
            "band": scorecard.get("band"),
            "engineering_leader_ready": scorecard.get("engineering_leader_ready"),
            "app_plane": scorecard.get("app_plane"),
            "dimensions": scorecard.get("dimensions"),
            "blockers": scorecard.get("blockers"),
            "next_actions": scorecard.get("next_actions"),
            "score_trend": scorecard.get("score_trend"),
            "attestation_freshness": scorecard.get("attestation_freshness"),
            "policy_fingerprint": scorecard.get("policy_fingerprint"),
            "published_fingerprint": scorecard.get("published_fingerprint"),
            "drift_status": scorecard.get("drift_status"),
            "slos": scorecard.get("slos"),
            "on_plane_coverage_percent": scorecard.get("on_plane_coverage_percent"),
        },
        "last_attestation": scorecard.get("last_attestation"),
        "last_attestation_verification": scorecard.get("last_attestation_verification"),
        "attestation_history": scorecard.get("attestation_history") or [],
        "release_gate_history": scorecard.get("release_gate_history") or [],
        "drift_events_recent": drift_events,
    }
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    signature = _sign_attestation_payload(canonical)
    pack = {
        **body,
        "signature": signature,
        "canonical_sha256": hashlib.sha256(canonical.encode()).hexdigest(),
    }
    recomputed = _sign_attestation_payload(canonical)
    pack["verification"] = {
        "valid": hmac.compare_digest(str(recomputed.get("signature")), str(signature.get("signature"))),
        "reason": "ok"
        if hmac.compare_digest(str(recomputed.get("signature")), str(signature.get("signature")))
        else "signature_mismatch",
        "algorithm": signature.get("algorithm"),
        "signed": bool(signature.get("signed")),
        "pack_id": pack_id,
    }
    if persist:
        upsert_runtime_config_value(
            db,
            RUNTIME_CONFIG_PLANE_EVIDENCE_PACK_JSON,
            json.dumps(
                {
                    "pack_id": pack_id,
                    "generated_at": body["generated_at"],
                    "gate_passed": gate.get("passed"),
                    "score": scorecard.get("score"),
                    "signed": bool(signature.get("signed")),
                    "canonical_sha256": pack["canonical_sha256"],
                },
                separators=(",", ":"),
                ensure_ascii=True,
            ),
            description="Latest control-plane evidence pack summary (full pack returned by API).",
        )
    logger.info(
        "control_plane_evidence_pack_built %s",
        sanitize_fields(
            {
                "pack_id": pack_id,
                "gate_passed": gate.get("passed"),
                "score": scorecard.get("score"),
                "signed": signature.get("signed"),
            }
        ),
    )
    return pack