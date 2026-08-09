"""NHI coexistence evidence pack for auditors (GOV-AI-IDSEC-NHI-006)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import GatewayNhiInventory
from app.services.gateway_nhi_iga_deny import list_iga_deny_events, load_iga_deny_config
from app.services.gateway_nhi_insights import build_nhi_insights, list_nhi_orphans, load_nhi_governance


def build_nhi_evidence_pack(
    db: Session,
    *,
    rows: list[GatewayNhiInventory],
    hygiene: Optional[dict[str, Any]] = None,
    max_credential_age_days: int = 90,
    tenant_id: Optional[str] = None,
    environment: Optional[str] = None,
    actor_id: str = "unknown",
) -> dict[str, Any]:
    """Compose a single auditor-facing pack without inventing a second inventory store."""
    gov = load_nhi_governance(db)
    insights = build_nhi_insights(
        db, rows=rows, max_credential_age_days=max_credential_age_days, limit=25
    )
    orphans = list_nhi_orphans(
        db, rows=rows, max_credential_age_days=max_credential_age_days, limit=50
    )
    deny_cfg = load_iga_deny_config(db, reveal_secret=False)
    deny_events = list_iga_deny_events(db, limit=40)

    records = gov.get("records") if isinstance(gov.get("records"), dict) else {}
    correlated = 0
    for row in rows:
        meta = records.get(row.nhi_record_id) if isinstance(records.get(row.nhi_record_id), dict) else {}
        if meta.get("external_ref") or meta.get("iga_agent_id"):
            correlated += 1
    total = len(rows)
    correlation_coverage_pct = round((correlated / total) * 100.0, 1) if total else 0.0

    evidence_id = f"nhi-evidence-{uuid4().hex[:16]}"
    return {
        "evidence_id": evidence_id,
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "export_uri": f"evidence://gateway/nhi/{evidence_id}.json",
        "schema_version": "guardbridge.nhi.evidence.v1",
        "plane": "inference_gateway",
        "integration_intent": "complementary_iga_coexistence_audit",
        "exported_by": str(actor_id or "unknown"),
        "filters": {
            "tenant_id": tenant_id,
            "environment": environment,
            "max_credential_age_days": max_credential_age_days,
        },
        "summary": {
            "total_identities": total,
            "orphan_count": orphans.get("orphan_count") or 0,
            "correlated_count": correlated,
            "correlation_coverage_pct": correlation_coverage_pct,
            "intent_mode": gov.get("intent_mode") or "off",
            "iga_deny_mode": deny_cfg.get("mode") or "off",
            "iga_deny_enabled": bool(deny_cfg.get("enabled")),
            "active_deny_count": deny_cfg.get("active_deny_count") or 0,
            "deny_event_history_count": deny_cfg.get("event_history_count") or 0,
        },
        "hygiene_summary": hygiene,
        "insights": {
            "risk_tier_counts": insights.get("risk_tier_counts") or {},
            "top_risks": insights.get("top_risks") or [],
            "notes": insights.get("notes") or "",
        },
        "orphans": {
            "orphan_count": orphans.get("orphan_count") or 0,
            "orphans": orphans.get("orphans") or [],
            "notes": orphans.get("notes") or "",
        },
        "iga_deny": {
            "mode": deny_cfg.get("mode"),
            "enabled": bool(deny_cfg.get("enabled")),
            "active_deny_count": deny_cfg.get("active_deny_count") or 0,
            "active_denies": deny_cfg.get("active_denies") or [],
            "events": deny_events.get("events") or [],
        },
        "notes": (
            "Gateway-plane NHI coexistence evidence for auditors. Complements Saviynt Zuma / IGA "
            "control evidence; does not claim enterprise ISPM or full IARA coverage."
        ),
    }
