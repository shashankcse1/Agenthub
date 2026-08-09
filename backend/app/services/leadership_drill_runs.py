"""Record dated Leader Readiness Clock/RT drill runs (human-attested).

Engineering provides the registry; operators must only POST after a real drill.
Does not invent timestamps.
"""

from __future__ import annotations

import json
from datetime import date, datetime
from typing import Any
from uuid import uuid4

from sqlalchemy.orm import Session

from app.services.runtime_config import get_runtime_config, upsert_runtime_config_value

DRILL_RUNS_CONFIG_KEY = "gateway.leadership.drill_runs_json"
ALLOWED_DRILL_IDS = frozenset(
    {
        "Clock-01",
        "Clock-02",
        "RT-01",
        "RT-02",
        "Tabletop",
    }
)
MAX_STORED_RUNS = 200


def _parse_runs(raw: str) -> list[dict[str, Any]]:
    if not raw or not str(raw).strip():
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def list_drill_runs(db: Session, *, drill_id: str | None = None, limit: int = 50) -> list[dict[str, Any]]:
    runs = _parse_runs(get_runtime_config(db, DRILL_RUNS_CONFIG_KEY, "[]"))
    if drill_id:
        needle = str(drill_id).strip()
        runs = [row for row in runs if str(row.get("drill_id") or "") == needle]
    runs = sorted(runs, key=lambda row: str(row.get("performed_on") or ""), reverse=True)
    return runs[: max(1, min(int(limit or 50), 200))]


def _validate_performed_on(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError("performed_on is required (YYYY-MM-DD after a real drill)")
    try:
        performed = date.fromisoformat(text[:10])
    except ValueError as exc:
        raise ValueError("performed_on must be YYYY-MM-DD") from exc
    today = datetime.utcnow().date()
    if performed > today:
        raise ValueError("performed_on cannot be in the future")
    # Soft bound: reject ancient placeholders that look like theater.
    if (today - performed).days > 366:
        raise ValueError("performed_on older than 366 days is rejected; use a recent real drill")
    return performed.isoformat()


def record_drill_run(
    db: Session,
    *,
    drill_id: str,
    performed_on: str,
    recorded_by: str,
    duration_seconds: int | None = None,
    outcome: str = "pass",
    notes: str = "",
    evidence_ref: str = "",
) -> dict[str, Any]:
    normalized_id = str(drill_id or "").strip()
    if normalized_id not in ALLOWED_DRILL_IDS:
        raise ValueError(f"drill_id must be one of: {', '.join(sorted(ALLOWED_DRILL_IDS))}")
    day = _validate_performed_on(performed_on)
    outcome_norm = str(outcome or "pass").strip().lower() or "pass"
    if outcome_norm not in {"pass", "fail", "partial"}:
        raise ValueError("outcome must be pass|fail|partial")
    duration = None
    if duration_seconds is not None:
        duration = max(0, min(int(duration_seconds), 24 * 3600))

    record = {
        "run_id": f"ldr-{uuid4().hex[:16]}",
        "drill_id": normalized_id,
        "performed_on": day,
        "recorded_at": datetime.utcnow().isoformat() + "Z",
        "recorded_by": str(recorded_by or "unknown").strip()[:128] or "unknown",
        "duration_seconds": duration,
        "outcome": outcome_norm,
        "notes": str(notes or "").strip()[:2000],
        "evidence_ref": str(evidence_ref or "").strip()[:512],
    }
    runs = _parse_runs(get_runtime_config(db, DRILL_RUNS_CONFIG_KEY, "[]"))
    runs.insert(0, record)
    runs = runs[:MAX_STORED_RUNS]
    upsert_runtime_config_value(
        db,
        DRILL_RUNS_CONFIG_KEY,
        json.dumps(runs, separators=(",", ":")),
        description="Leader Readiness dated Clock/RT drill attestations",
    )
    return record


def drill_freshness_summary(db: Session, *, now: date | None = None) -> dict[str, Any]:
    """Summarize last run age per drill for QBR/Assurance chips."""
    today = now or datetime.utcnow().date()
    runs = list_drill_runs(db, limit=200)
    latest: dict[str, dict[str, Any]] = {}
    for row in runs:
        did = str(row.get("drill_id") or "")
        if did and did not in latest:
            latest[did] = row
    by_drill: dict[str, Any] = {}
    for did in sorted(ALLOWED_DRILL_IDS):
        row = latest.get(did)
        if not row:
            by_drill[did] = {"recorded": False, "days_since": None, "within_90d": False}
            continue
        try:
            performed = date.fromisoformat(str(row.get("performed_on"))[:10])
            days = (today - performed).days
        except ValueError:
            days = None
        by_drill[did] = {
            "recorded": True,
            "performed_on": row.get("performed_on"),
            "outcome": row.get("outcome"),
            "days_since": days,
            "within_90d": days is not None and days <= 90,
            "run_id": row.get("run_id"),
        }
    rt_ok = all(by_drill[d].get("within_90d") for d in ("RT-01", "RT-02"))
    tabletop_ok = bool(by_drill["Tabletop"].get("within_90d") or (
        by_drill["Tabletop"].get("days_since") is not None
        and by_drill["Tabletop"]["days_since"] <= 180
    ))
    return {
        "by_drill": by_drill,
        "rt_01_02_within_90d": rt_ok,
        "tabletop_within_180d": tabletop_ok,
    }
