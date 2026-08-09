"""Leader Readiness QBR numbers-first snapshot (Assurance D).

Aggregates existing clocks/gates signals so quarterly reviews start from
measured numbers, not guessed status. Does not invent drill dates or
board signatures.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import CostEvent, GatewayNhiInventory
from app.security import mfa_optional_posture, token_exposure_posture, transport_posture
from app.services.control_plane_leadership import build_control_plane_leadership
from app.services.basic_auth_expiry import exception_posture
from app.services.leadership_drill_runs import drill_freshness_summary
from app.services.leadership_lrs import build_program_leadership_summary, lrs_honesty_posture
from app.services.on_plane_coverage import compute_on_plane_coverage
from app.plane_mode import resolve_app_plane
from app.services.plane_reconcile import (
    build_reconcile_posture,
    gate_state_snapshot,
    last_reconcile_snapshot,
)


def _nhi_unmanaged_prod_count(db: Session) -> tuple[int, bool]:
    rows = db.query(GatewayNhiInventory).filter(GatewayNhiInventory.environment == "prod").all()
    unmanaged = 0
    for row in rows:
        findings_raw = str(getattr(row, "findings", "") or "")
        findings: list[str] = []
        try:
            import json

            parsed = json.loads(findings_raw) if findings_raw.strip().startswith("[") else []
            if isinstance(parsed, list):
                findings = [str(item) for item in parsed]
        except Exception:
            findings = [part.strip() for part in findings_raw.split(",") if part.strip()]
        missing_owner = not str(getattr(row, "owner_scope_id", "") or "").strip()
        if missing_owner or "high_risk" in findings or "missing_owner" in findings:
            unmanaged += 1
    return unmanaged, unmanaged == 0


def build_qbr_snapshot(
    db: Session,
    *,
    hours: int = 24 * 90,
    environment: Optional[str] = None,
) -> dict[str, Any]:
    """Build a numbers-first QBR pack from live control-plane signals."""
    window_hours = max(1, min(int(hours or 2160), 24 * 180))
    window_start = datetime.utcnow() - timedelta(hours=window_hours)

    cost_q = db.query(CostEvent).filter(CostEvent.timestamp >= window_start)
    if environment:
        cost_q = cost_q.filter(CostEvent.environment == str(environment).strip())
    totals = cost_q.with_entities(
        func.count(CostEvent.cost_event_id),
        func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0),
        func.count(func.distinct(CostEvent.request_id)),
    ).first()

    coverage = compute_on_plane_coverage(db, window_start=window_start, environment=environment)
    unmanaged_prod, prod_unmanaged_zero_ok = _nhi_unmanaged_prod_count(db)
    exceptions = exception_posture(db)
    transport = transport_posture()
    mfa = mfa_optional_posture()
    token = token_exposure_posture()

    on_plane_pct = coverage.get("on_plane_coverage_percent")
    clocks = {
        "on_plane_coverage_percent": on_plane_pct,
        "on_plane_auto_reported": on_plane_pct is not None or int(coverage.get("on_plane_events") or 0) >= 0,
        "unmanaged_prod_identities": unmanaged_prod,
        "prod_unmanaged_zero_ok": prod_unmanaged_zero_ok,
    }
    gates = {
        "exceptions_max_days_cap": exceptions.get("max_duration_days_cap"),
        "active_break_glass": exceptions.get("active_break_glass"),
        "expired_still_marked_enabled": exceptions.get("expired_still_marked_enabled"),
        "auto_disable_supported": exceptions.get("auto_disable_supported"),
        "transport_expect_https": transport.get("expect_https"),
        "hsts_configured": transport.get("hsts_configured"),
        "mfa_optional_effective": mfa.get("effective"),
        "token_exposure_effective": token.get("effective"),
    }
    spend = {
        "window_hours": window_hours,
        "environment": environment,
        "total_events": int(totals[0] or 0),
        "distinct_requests": int(totals[2] or 0),
        "total_estimated_cost_cents": int(totals[1] or 0),
        "on_plane_events": int(coverage.get("on_plane_events") or 0),
        "off_plane_detected": int(coverage.get("off_plane_detected") or 0),
    }

    drills = drill_freshness_summary(db)
    plane = resolve_app_plane()
    try:
        plane_reconcile = build_reconcile_posture(db, plane=plane, probe_peer=False)
    except Exception:
        plane_reconcile = {
            "drift_status": (last_reconcile_snapshot() or {}).get("drift_status"),
            "policy_generation": None,
            "gate": gate_state_snapshot(),
        }
    plane_isolation = {
        "app_plane": plane,
        "drift_status": plane_reconcile.get("drift_status"),
        "fingerprint": (plane_reconcile.get("policy_generation") or {}).get("fingerprint"),
        "route_count": (plane_reconcile.get("policy_generation") or {}).get("route_count"),
        "key_count": (plane_reconcile.get("policy_generation") or {}).get("key_count"),
        "gate": plane_reconcile.get("gate") or gate_state_snapshot(),
        "last_reconcile_at_unix": (last_reconcile_snapshot() or {}).get("recorded_at_unix"),
    }
    try:
        cpli = build_control_plane_leadership(
            db,
            window_hours=min(window_hours, 168),
            environment=environment,
            probe_peer=False,
        )
        from app.services.control_plane_contract import (
            PLANE_CONTRACT_VERSION,
            resolve_control_readonly,
        )
        from app.services.control_plane_leadership import build_control_plane_ops_summary

        ops = build_control_plane_ops_summary(db)
        control_plane_leadership = {
            "score": cpli.get("score"),
            "max_score": cpli.get("max_score"),
            "band": cpli.get("band"),
            "engineering_leader_ready": cpli.get("engineering_leader_ready"),
            "marketing_claim_allowed": False,
            "points_to_leader_band": cpli.get("points_to_leader_band"),
            "leader_band_threshold": cpli.get("leader_band_threshold"),
            "plane_split_ready": cpli.get("plane_split_ready"),
            "blockers": cpli.get("blockers") or [],
            "next_actions": cpli.get("next_actions") or [],
            "policy_fingerprint": cpli.get("policy_fingerprint"),
            "last_attestation_id": (cpli.get("last_attestation") or {}).get("attestation_id"),
            "last_attestation_valid": (cpli.get("last_attestation_verification") or {}).get("valid"),
            "release_gate_passed": (cpli.get("release_gate") or {}).get("passed"),
            "score_trend": cpli.get("score_trend"),
            "attestation_fresh": (cpli.get("attestation_freshness") or {}).get("fresh"),
            "release_gate_evaluations": len(cpli.get("release_gate_history") or []),
            "promotion_ready": (cpli.get("promotion_readiness") or {}).get("ready"),
            "gate_streak": (cpli.get("promotion_readiness") or {}).get("streak"),
            "gate_streak_required": (cpli.get("promotion_readiness") or {}).get("streak_required"),
            "contract_version": ops.get("contract_version") or PLANE_CONTRACT_VERSION,
            "control_ready": ops.get("ready"),
            "control_readonly": ops.get("control_readonly", resolve_control_readonly()),
            "last_known_good_fingerprint": ops.get("last_known_good_fingerprint"),
        }
    except Exception:
        control_plane_leadership = {
            "score": None,
            "max_score": 20,
            "band": "unavailable",
            "engineering_leader_ready": False,
            "marketing_claim_allowed": False,
            "blockers": ["CPLI scorecard unavailable"],
        }
    readiness_notes: list[str] = []
    if not prod_unmanaged_zero_ok:
        readiness_notes.append("Unmanaged prod NHI identities > 0 — Clocks refuse-zero risk.")
    if int(exceptions.get("expired_still_marked_enabled") or 0) > 0:
        readiness_notes.append("Expired break-glass still marked enabled — run expire-tick.")
    if mfa.get("effective") or token.get("effective"):
        readiness_notes.append("Local-only MFA/token exposure flags are effective — confirm env.")
    if not drills.get("rt_01_02_within_90d"):
        readiness_notes.append("RT-01/RT-02 dated runs missing or older than 90d — record after real drills.")
    if not drills.get("tabletop_within_180d"):
        readiness_notes.append("Tabletop dated run missing or older than 180d.")
    if plane_isolation.get("drift_status") in {"drift_detected", "peer_unreachable"}:
        readiness_notes.append(
            f"Plane drift status is {plane_isolation.get('drift_status')} — run POST /platform/control-plane/reconcile."
        )
    if control_plane_leadership.get("engineering_leader_ready"):
        readiness_notes.append(
            f"CPLI {control_plane_leadership.get('score')}/{control_plane_leadership.get('max_score')} "
            f"({control_plane_leadership.get('band')}) — engineering leader-ready; check LRS honesty gate for marketing."
        )
    elif control_plane_leadership.get("score") is not None:
        readiness_notes.append(
            f"CPLI {control_plane_leadership.get('score')}/{control_plane_leadership.get('max_score')} "
            f"({control_plane_leadership.get('band')}) — close blockers via /platform/control-plane/leadership."
        )
    honesty = lrs_honesty_posture(db)
    if honesty.get("leader_claim_allowed"):
        readiness_notes.append(
            f"LRS attestation allows Under-contract+ claims: {honesty.get('reason')}"
        )
    else:
        readiness_notes.append(
            f"Leader claims blocked: {honesty.get('reason')}"
        )
    cpli = control_plane_leadership if isinstance(control_plane_leadership, dict) else {}
    program_leadership = build_program_leadership_summary(honesty=honesty, cpli=cpli)
    if program_leadership["unified_ready"]:
        readiness_notes.append(
            f"Unified leader posture: LRS gate + CPLI {cpli.get('score')}/{cpli.get('max_score')} engineering-ready."
        )
    elif honesty.get("leader_claim_allowed") and not cpli.get("engineering_leader_ready"):
        readiness_notes.append(
            f"Program LRS met; raise CPLI to ≥{cpli.get('leader_band_threshold') or 16} for engineering leader band."
        )

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "purpose": "numbers_first_qbr",
        "spend": spend,
        "clocks": clocks,
        "gates": gates,
        "drills": drills,
        "plane_isolation": plane_isolation,
        "control_plane_leadership": control_plane_leadership,
        "program_leadership": program_leadership,
        "on_plane_coverage": coverage,
        "transport": transport,
        "exception_posture": exceptions,
        "mfa_optional": mfa,
        "token_exposure": token,
        "readiness_notes": readiness_notes,
        "honesty": {
            "leader_claim_allowed": bool(honesty.get("leader_claim_allowed")),
            "reason": str(honesty.get("reason") or ""),
            "lrs": honesty.get("attestation"),
        },
    }
