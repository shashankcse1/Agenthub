"""Leader Readiness Score (LRS) attestation — Honesty-gated claim posture.

Stores a dated program attestation in runtime config. Marketing claims are allowed
only when score >= 32 with no Authority/Clocks zeros and formal sign-off recorded.
Does not invent board minutes; operators (or Program Owner attestation) must write
the attestation after real adoption + drills.
"""

from __future__ import annotations

import json
import os
from datetime import date, datetime
from pathlib import Path
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_LEADERSHIP_LRS_ATTESTATION_JSON
from app.services.runtime_config import get_runtime_config, upsert_runtime_config_value

LRS_GATE_MIN = 32
LRS_MAX = 40
GOVERNANCE_ATTESTATION_PATH = (
    Path(__file__).resolve().parents[2] / "docs" / "governance" / "leader-readiness-attestation.json"
)


def _parse_attestation(raw: str) -> Optional[dict[str, Any]]:
    text = str(raw or "").strip()
    if not text:
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _safe_int(value: Any, default: int = 0, *, minimum: int = 0, maximum: int = LRS_MAX) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, number))


def normalize_lrs_attestation(attestation: dict[str, Any]) -> dict[str, Any]:
    """Clamp/coerce attestation fields so honesty gates cannot be tripped by bad types."""
    if not isinstance(attestation, dict):
        raise ValueError("attestation must be an object")
    out = dict(attestation)
    out["attestation_id"] = str(out.get("attestation_id") or "").strip()[:128] or "LRS-UNKNOWN"
    out["score"] = _safe_int(out.get("score"), 0, minimum=0, maximum=LRS_MAX)
    out["max_score"] = _safe_int(out.get("max_score"), LRS_MAX, minimum=1, maximum=LRS_MAX)
    out["authority_zeros"] = _safe_int(out.get("authority_zeros"), 0, minimum=0, maximum=8)
    out["clocks_zeros"] = _safe_int(out.get("clocks_zeros"), 0, minimum=0, maximum=8)
    out["formal_signoff_complete"] = bool(out.get("formal_signoff_complete"))
    out["band"] = str(out.get("band") or "").strip()[:64]
    attested_on = str(out.get("attested_on") or "").strip()[:32]
    if attested_on:
        try:
            day = date.fromisoformat(attested_on[:10])
            if day > datetime.utcnow().date():
                raise ValueError("attested_on cannot be in the future")
            out["attested_on"] = day.isoformat()
        except ValueError as exc:
            raise ValueError(f"invalid attested_on: {exc}") from exc
    dims = out.get("dimensions")
    if isinstance(dims, dict):
        cleaned = {}
        for key in ("authority", "clocks", "gates", "assurance", "honesty"):
            if key in dims:
                cleaned[key] = _safe_int(dims.get(key), 0, minimum=0, maximum=8)
        out["dimensions"] = cleaned
    return out


def load_lrs_attestation_from_file() -> Optional[dict[str, Any]]:
    try:
        if not GOVERNANCE_ATTESTATION_PATH.is_file():
            return None
        parsed = _parse_attestation(GOVERNANCE_ATTESTATION_PATH.read_text(encoding="utf-8"))
        return normalize_lrs_attestation(parsed) if parsed else None
    except (OSError, ValueError):
        return None


def _in_pytest() -> bool:
    return bool(os.getenv("PYTEST_CURRENT_TEST"))


def get_lrs_attestation(db: Optional[Session] = None, *, hydrate: bool = True) -> Optional[dict[str, Any]]:
    if db is not None:
        raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_LEADERSHIP_LRS_ATTESTATION_JSON, "")
        from_db = _parse_attestation(raw)
        if from_db:
            try:
                return normalize_lrs_attestation(from_db)
            except ValueError:
                return None
        # Ops recovery: if runtime_config was cleared (e.g. by tests) but the
        # governance attestation file remains, hydrate outside pytest only.
        if hydrate and not _in_pytest():
            from_file = load_lrs_attestation_from_file()
            if from_file and from_file.get("formal_signoff_complete"):
                try:
                    upsert_lrs_attestation(db, from_file, write_governance_file=False)
                except Exception:
                    return from_file
                return from_file
        return None
    return load_lrs_attestation_from_file()


def upsert_lrs_attestation(
    db: Session,
    attestation: dict[str, Any],
    *,
    write_governance_file: bool = True,
) -> dict[str, Any]:
    normalized = normalize_lrs_attestation(attestation)
    payload = json.dumps(normalized, separators=(",", ":"), sort_keys=True)
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_GATEWAY_LEADERSHIP_LRS_ATTESTATION_JSON,
        payload,
        description="Leader Readiness Score program attestation (Honesty-gated)",
    )
    if write_governance_file:
        try:
            GOVERNANCE_ATTESTATION_PATH.parent.mkdir(parents=True, exist_ok=True)
            GOVERNANCE_ATTESTATION_PATH.write_text(
                json.dumps(normalized, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        except OSError:
            pass
    return normalized


def lrs_honesty_posture(db: Optional[Session] = None) -> dict[str, Any]:
    """Return QBR/Honesty claim gate from attestation (default: claims blocked)."""
    att = get_lrs_attestation(db)
    if not att:
        return {
            "leader_claim_allowed": False,
            "reason": "No LRS attestation — board resolution, drills, and L6 sign-off required",
            "attestation": None,
        }
    score = _safe_int(att.get("score"), 0)
    authority_zeros = _safe_int(att.get("authority_zeros"), 0, maximum=8)
    clocks_zeros = _safe_int(att.get("clocks_zeros"), 0, maximum=8)
    signed = bool(att.get("formal_signoff_complete"))
    band = str(att.get("band") or "")
    allowed = (
        score >= LRS_GATE_MIN
        and authority_zeros == 0
        and clocks_zeros == 0
        and signed
    )
    if allowed:
        reason = (
            f"LRS {score}/40 ({band}) with no Authority/Clocks zeros and formal sign-off complete "
            f"(attestation {att.get('attestation_id')})"
        )
    else:
        blockers = []
        if score < LRS_GATE_MIN:
            blockers.append(f"score {score} < {LRS_GATE_MIN}")
        if authority_zeros:
            blockers.append("Authority zeros present")
        if clocks_zeros:
            blockers.append("Clocks zeros present")
        if not signed:
            blockers.append("formal sign-off incomplete")
        reason = "LRS attestation present but gate not met: " + "; ".join(blockers)
    return {
        "leader_claim_allowed": allowed,
        "reason": reason,
        "attestation": {
            "attestation_id": att.get("attestation_id"),
            "score": score,
            "max_score": _safe_int(att.get("max_score"), LRS_MAX, minimum=1),
            "band": band,
            "attested_on": att.get("attested_on"),
            "formal_signoff_complete": signed,
            "authority_zeros": authority_zeros,
            "clocks_zeros": clocks_zeros,
        },
    }


def build_program_leadership_summary(
    *,
    honesty: dict[str, Any],
    cpli: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Unified LRS + CPLI posture for QBR / Overview / Cost."""
    card = cpli if isinstance(cpli, dict) else {}
    claim = bool(honesty.get("leader_claim_allowed"))
    eng_ready = bool(card.get("engineering_leader_ready"))
    return {
        "lrs": honesty.get("attestation"),
        "lrs_claim_allowed": claim,
        "lrs_reason": str(honesty.get("reason") or ""),
        "cpli_score": card.get("score"),
        "cpli_max": card.get("max_score") or 20,
        "cpli_band": card.get("band"),
        "cpli_engineering_leader_ready": eng_ready,
        "unified_ready": claim and eng_ready,
        "plane_split_ready": bool(card.get("plane_split_ready")),
        "leader_band_threshold": card.get("leader_band_threshold") or 16,
    }
