"""Leader Readiness clock: on-plane inference coverage auto-report."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.domain_constants import DISCOVERY_CONFIDENCE_PROMOTE_MIN
from app.models import CostEvent, DiscoveryRecord


def _properties_mark_off_plane(raw: str | None) -> bool:
    if not raw:
        return False
    try:
        parsed = json.loads(raw)
    except Exception:
        return '"off_plane": true' in raw.lower().replace(" ", "") or '"off_plane":true' in raw.lower().replace(
            " ", ""
        )
    if not isinstance(parsed, dict):
        return False
    value = parsed.get("off_plane")
    if isinstance(value, bool):
        return value
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def compute_on_plane_coverage(
    db: Session,
    *,
    window_start: datetime,
    environment: Optional[str] = None,
) -> dict[str, Any]:
    """
    Coverage = on_plane / (on_plane + off_plane_detected).

    - on_plane: CostEvent rows in window (gateway-mediated spend)
    - off_plane_detected: CostEvents tagged properties.off_plane=true
      + unmanaged high-risk discovery records (not yet promoted)
    """
    cost_query = db.query(CostEvent).filter(CostEvent.timestamp >= window_start)
    if environment:
        cost_query = cost_query.filter(CostEvent.environment == environment)

    on_plane = int(cost_query.count() or 0)

    off_plane_tagged = 0
    # Cap scan for properties tags to avoid full-table JSON parse on huge windows.
    for row in cost_query.with_entities(CostEvent.properties_json).limit(5000).all():
        if _properties_mark_off_plane(row[0] if row else None):
            off_plane_tagged += 1

    unmanaged_q = db.query(func.count(DiscoveryRecord.discovered_agent_id)).filter(
        DiscoveryRecord.discovery_status == "discovered",
        DiscoveryRecord.promoted_to_agent_id.is_(None),
        DiscoveryRecord.discovery_confidence >= DISCOVERY_CONFIDENCE_PROMOTE_MIN,
    )
    unmanaged_high_risk = int(unmanaged_q.scalar() or 0)

    off_plane_detected = int(off_plane_tagged + unmanaged_high_risk)
    denominator = on_plane + off_plane_detected
    if denominator <= 0:
        coverage_percent = None
    else:
        coverage_percent = round((on_plane / denominator) * 100.0, 2)

    return {
        "on_plane_events": on_plane,
        "off_plane_detected": off_plane_detected,
        "off_plane_tagged_cost_events": off_plane_tagged,
        "unmanaged_high_risk_discovered": unmanaged_high_risk,
        "on_plane_coverage_percent": coverage_percent,
        "formula": "on_plane / (on_plane + off_plane_detected)",
        "sensor_notes": (
            "CostEvents are on-plane; off_plane_detected = properties.off_plane tags "
            "+ unmanaged high-confidence discovery records."
        ),
    }
