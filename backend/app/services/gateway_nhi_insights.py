"""Gateway-scoped NHI Insights + lifecycle + intent-check (GOV-AI-IDSEC-NHI-004)."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.models import AuditEvent, GatewayEntitlement, GatewayNhiInventory, RoutePolicy, VirtualKey
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_NHI_GOVERNANCE_JSON
from app.services.mcp_gateway import list_mcp_servers
from app.services.runtime_config import get_runtime_config, upsert_runtime_config_value

ALLOWED_LIFECYCLE_ACTIONS = frozenset({"suspend", "reactivate", "retire"})
ALLOWED_INTENT_MODES = frozenset({"off", "warn", "block"})
DEFAULT_GOVERNANCE: dict[str, Any] = {
    "intent_mode": "off",
    "records": {},
    "correlation_ingest_enabled": False,
    "correlation_ingest_hmac_secret": "",
    "require_correlation_ingest_hmac": True,
    "require_correlation_ingest_timestamp": False,
    "max_correlation_ingest_skew_seconds": 300,
    "seen_correlation_nonces": [],
    "access_mode": "off",
    "access_policies": [],
    "gate_events": [],
}

MAX_GATE_EVENTS = 200
MAX_CORRELATION_SEEN_NONCES = 500


def _is_production_runtime() -> bool:
    from app.services.runtime_env import is_production_runtime

    return is_production_runtime()


def blocking_nhi_modes(db: Session) -> dict[str, str]:
    """Return intent/access modes when either is block (caller must require declared_intent)."""
    gov = load_nhi_governance(db, reveal_secret=False)
    intent_mode = str(gov.get("intent_mode") or "off")
    access_mode = str(gov.get("access_mode") or "off")
    return {"intent_mode": intent_mode, "access_mode": access_mode}


def _parse_findings(raw: object) -> list[str]:
    if isinstance(raw, list):
        return [str(item) for item in raw]
    text = str(raw or "").strip()
    if not text:
        return []
    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            return [str(item) for item in parsed]
    except json.JSONDecodeError:
        pass
    return []


def _risk_score(row: GatewayNhiInventory, *, max_credential_age_days: int, now: datetime) -> dict[str, Any]:
    findings = _parse_findings(row.findings)
    missing_owner = not bool(str(row.owner_scope_id or "").strip())
    age_days = None
    if row.credential_last_rotated_at is not None:
        age_days = max(0, int((now - row.credential_last_rotated_at).total_seconds() // 86400))
    stale = age_days is None or age_days > max_credential_age_days
    if stale and "stale_credential" not in findings:
        findings.append("stale_credential")
    if missing_owner and "missing_owner" not in findings:
        findings.append("missing_owner")
    status = str(row.status or "").strip().lower()
    score = 0
    if "high_risk" in findings or (missing_owner and stale):
        score += 40
    if missing_owner:
        score += 25
    if stale:
        score += 20
    if status in {"suspended", "retired", "blocked", "inactive"}:
        score += 10
    if str(row.environment or "").lower() == "prod":
        score += 15
    if str(row.identity_type or "") in {"virtual_key", "workload_identity", "mcp_server"}:
        score += 5
    score = min(100, score)
    if score >= 70 or "high_risk" in findings:
        tier = "critical" if score >= 85 else "high"
    elif score >= 40:
        tier = "medium"
    else:
        tier = "low"
    return {
        "risk_score": score,
        "risk_tier": tier,
        "findings": sorted(set(findings)),
        "missing_owner": missing_owner,
        "stale_credential": stale,
        "credential_age_days": age_days,
        "business_impact": (
            "prod_unmanaged"
            if str(row.environment or "").lower() == "prod" and (missing_owner or "high_risk" in findings)
            else ("credential_hygiene" if stale or missing_owner else "monitored")
        ),
    }


def _load_governance_raw(db: Session) -> dict[str, Any]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_NHI_GOVERNANCE_JSON, "")
    try:
        parsed = json.loads(raw) if raw.strip() else dict(DEFAULT_GOVERNANCE)
    except json.JSONDecodeError:
        parsed = dict(DEFAULT_GOVERNANCE)
    if not isinstance(parsed, dict):
        parsed = dict(DEFAULT_GOVERNANCE)
    return parsed


def load_nhi_governance(db: Session, *, reveal_secret: bool = False) -> dict[str, Any]:
    parsed = _load_governance_raw(db)
    mode = str(parsed.get("intent_mode") or "off").strip().lower() or "off"
    if mode not in ALLOWED_INTENT_MODES:
        mode = "off"
    records = parsed.get("records") if isinstance(parsed.get("records"), dict) else {}
    secret = str(parsed.get("correlation_ingest_hmac_secret") or "")
    access_mode = str(parsed.get("access_mode") or "off").strip().lower() or "off"
    if access_mode not in {"off", "warn", "block"}:
        access_mode = "off"
    access_policies = parsed.get("access_policies") if isinstance(parsed.get("access_policies"), list) else []
    gate_events = [row for row in list(parsed.get("gate_events") or []) if isinstance(row, dict)]
    out = {
        "intent_mode": mode,
        "records": records,
        "record_count": len(records),
        "correlation_ingest_enabled": bool(parsed.get("correlation_ingest_enabled")),
        "require_correlation_ingest_hmac": bool(parsed.get("require_correlation_ingest_hmac", True)),
        "require_correlation_ingest_timestamp": bool(
            parsed.get("require_correlation_ingest_timestamp", False)
        ),
        "max_correlation_ingest_skew_seconds": max(
            30, min(3600, int(parsed.get("max_correlation_ingest_skew_seconds") or 300))
        ),
        "correlation_ingest_hmac_secret_configured": bool(secret.strip()),
        "access_mode": access_mode,
        "access_policies": access_policies,
        "policy_count": len(access_policies),
        "gate_event_count": len(gate_events),
    }
    if reveal_secret:
        out["correlation_ingest_hmac_secret"] = secret
    else:
        out["correlation_ingest_hmac_secret"] = ""
    return out


def save_nhi_governance(db: Session, payload: dict[str, Any], *, actor_id: str) -> dict[str, Any]:
    current = load_nhi_governance(db, reveal_secret=True)
    mode = str(payload.get("intent_mode") or current.get("intent_mode") or "off").strip().lower()
    if mode not in ALLOWED_INTENT_MODES:
        raise HTTPException(
            status_code=422,
            detail=f"intent_mode must be one of: {', '.join(sorted(ALLOWED_INTENT_MODES))}",
        )
    records = current.get("records") if isinstance(current.get("records"), dict) else {}
    if isinstance(payload.get("records"), dict):
        # merge, don't wipe unspecified keys unless explicitly replaced wholesale
        for key, value in payload["records"].items():
            if isinstance(value, dict):
                records[str(key)] = value
    secret = str(payload.get("correlation_ingest_hmac_secret") or "").strip()
    if not secret and current.get("correlation_ingest_hmac_secret"):
        secret = str(current.get("correlation_ingest_hmac_secret") or "")
    access_mode = str(payload.get("access_mode", current.get("access_mode") or "off")).strip().lower() or "off"
    if access_mode not in {"off", "warn", "block"}:
        raise HTTPException(status_code=422, detail="access_mode must be one of: off, warn, block")
    if "access_policies" in payload:
        access_policies = payload.get("access_policies") if isinstance(payload.get("access_policies"), list) else []
    else:
        access_policies = current.get("access_policies") if isinstance(current.get("access_policies"), list) else []
    raw_current = _load_governance_raw(db)
    gate_events = [row for row in list(raw_current.get("gate_events") or []) if isinstance(row, dict)]
    if isinstance(payload.get("gate_events"), list):
        gate_events = [row for row in payload["gate_events"] if isinstance(row, dict)][:MAX_GATE_EVENTS]
    corr_enabled = bool(
        payload.get("correlation_ingest_enabled", current.get("correlation_ingest_enabled"))
    )
    require_corr_hmac = bool(
        payload.get(
            "require_correlation_ingest_hmac",
            current.get("require_correlation_ingest_hmac", True),
        )
    )
    require_corr_ts = bool(
        payload.get(
            "require_correlation_ingest_timestamp",
            current.get("require_correlation_ingest_timestamp", False),
        )
    )
    if _is_production_runtime() and corr_enabled:
        require_corr_hmac = True
        require_corr_ts = True
        if not secret.strip():
            raise HTTPException(
                status_code=422,
                detail="correlation_ingest_hmac_secret is required when correlation ingest is enabled in production",
            )
    try:
        skew = int(
            payload.get(
                "max_correlation_ingest_skew_seconds",
                current.get("max_correlation_ingest_skew_seconds") or 300,
            )
        )
    except (TypeError, ValueError):
        skew = 300
    skew = max(30, min(3600, skew))
    seen_nonces = [
        str(item)
        for item in list(raw_current.get("seen_correlation_nonces") or [])
        if str(item)
    ][:MAX_CORRELATION_SEEN_NONCES]
    store = {
        "intent_mode": mode,
        "records": records,
        "correlation_ingest_enabled": corr_enabled,
        "require_correlation_ingest_hmac": require_corr_hmac,
        "require_correlation_ingest_timestamp": require_corr_ts,
        "max_correlation_ingest_skew_seconds": skew,
        "seen_correlation_nonces": seen_nonces,
        "correlation_ingest_hmac_secret": secret,
        "access_mode": access_mode,
        "access_policies": access_policies,
        "gate_events": gate_events[:MAX_GATE_EVENTS],
        "updated_by": str(actor_id or "unknown"),
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_GATEWAY_NHI_GOVERNANCE_JSON,
        json.dumps(store, separators=(",", ":")),
        description="NHI governance + native access (GOV-AI-IDSEC-NHI-004/006/007/008)",
    )
    return load_nhi_governance(db, reveal_secret=False)


def append_nhi_gate_event(db: Session, event: dict[str, Any], *, actor_id: str = "system") -> None:
    """Append intent/access gate decision to durable-ish runtime ring buffer."""
    raw = _load_governance_raw(db)
    history = [row for row in list(raw.get("gate_events") or []) if isinstance(row, dict)]
    row = {
        "event_id": f"nhi-gate-{uuid4().hex[:12]}",
        "at": datetime.utcnow().isoformat() + "Z",
        **{k: v for k, v in event.items() if v is not None},
    }
    history.insert(0, row)
    save_nhi_governance(db, {"gate_events": history[:MAX_GATE_EVENTS]}, actor_id=actor_id)


def list_nhi_gate_events(db: Session, *, limit: int = 50) -> dict[str, Any]:
    raw = _load_governance_raw(db)
    history = [row for row in list(raw.get("gate_events") or []) if isinstance(row, dict)]
    limit_n = max(1, min(200, int(limit or 50)))
    return {
        "event_count": len(history[:limit_n]),
        "total_events": len(history),
        "events": history[:limit_n],
        "notes": (
            "Ring-buffer intent/access gate decisions (warn/deny) for native NHI gates. "
            "Capped at 200 events in runtime config; not a full SIEM."
        ),
    }


def _record_governance(gov: dict[str, Any], nhi_record_id: str) -> dict[str, Any]:
    records = gov.get("records") if isinstance(gov.get("records"), dict) else {}
    row = records.get(nhi_record_id)
    return dict(row) if isinstance(row, dict) else {}


def _upsert_record_governance(
    db: Session,
    *,
    nhi_record_id: str,
    patch: dict[str, Any],
    actor_id: str,
) -> dict[str, Any]:
    gov = load_nhi_governance(db)
    records = dict(gov.get("records") or {})
    current = dict(records.get(nhi_record_id) or {})
    current.update({k: v for k, v in patch.items() if v is not None})
    history = list(current.get("lifecycle_history") or [])
    if patch.get("_history_event"):
        history.insert(0, patch["_history_event"])
        current.pop("_history_event", None)
        current["lifecycle_history"] = history[:50]
    records[nhi_record_id] = current
    save_nhi_governance(db, {"intent_mode": gov.get("intent_mode"), "records": records}, actor_id=actor_id)
    return current


def build_nhi_insights(
    db: Session,
    *,
    rows: list[GatewayNhiInventory],
    max_credential_age_days: int = 90,
    limit: int = 50,
) -> dict[str, Any]:
    now = datetime.utcnow()
    gov = load_nhi_governance(db)
    scored: list[dict[str, Any]] = []
    tier_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for row in rows:
        risk = _risk_score(row, max_credential_age_days=max_credential_age_days, now=now)
        meta = _record_governance(gov, row.nhi_record_id)
        tier_counts[risk["risk_tier"]] = tier_counts.get(risk["risk_tier"], 0) + 1
        scored.append(
            {
                "nhi_record_id": row.nhi_record_id,
                "source_type": row.source_type,
                "source_id": row.source_id,
                "identity_type": row.identity_type,
                "tenant_id": row.tenant_id,
                "environment": row.environment,
                "provider_type": row.provider_type,
                "status": row.status,
                "owner_scope_type": row.owner_scope_type,
                "owner_scope_id": row.owner_scope_id,
                "purpose": meta.get("purpose") or "",
                "approved_intents": list(meta.get("approved_intents") or []),
                **risk,
            }
        )
    scored.sort(key=lambda item: (-int(item["risk_score"]), str(item["nhi_record_id"])))
    top = scored[: max(1, min(100, int(limit)))]
    return {
        "generated_at": now.isoformat() + "Z",
        "total_identities": len(scored),
        "risk_tier_counts": tier_counts,
        "top_risks": top,
        "intent_mode": gov.get("intent_mode"),
        "notes": (
            "Gateway-plane Insights (not enterprise SaaS ISPM). "
            "Risk ranks WIF/secret/VK/MCP hygiene for inference control coexistence with external IGA."
        ),
    }


def build_nhi_access_map(db: Session, *, row: GatewayNhiInventory) -> dict[str, Any]:
    """Map gateway NHI → reachable routes / MCP tools / models (gateway plane)."""
    paths: list[dict[str, Any]] = []
    source_type = str(row.source_type or "")
    source_id = str(row.source_id or "")

    if source_type == "virtual_key":
        key = db.query(VirtualKey).filter_by(key_id=source_id).first()
        if key is not None:
            try:
                models = json.loads(key.allowed_models or "[]")
            except json.JSONDecodeError:
                models = []
            try:
                families = json.loads(key.allowed_endpoint_families or "[]")
            except json.JSONDecodeError:
                families = []
            paths.append(
                {
                    "hop": "virtual_key",
                    "resource": key.key_id,
                    "allowed_models": models if isinstance(models, list) else [],
                    "allowed_endpoint_families": families if isinstance(families, list) else [],
                    "status": key.status,
                    "owner_scope": f"{key.owner_scope_type}:{key.owner_scope_id}",
                }
            )

    if source_type == "mcp_server":
        for server in list_mcp_servers(db):
            if str(server.get("server_id")) == source_id:
                for tool in server.get("allowed_tools") or []:
                    paths.append(
                        {
                            "hop": "mcp_tool",
                            "resource": f"{source_id}/{tool}",
                            "server_id": source_id,
                            "tool": tool,
                            "enabled": bool(server.get("enabled")),
                        }
                    )
                break

    # Tenant-context only (not identity grants). Avoid duplicating Entitlements /
    # Route Policy consoles — labeled so operators do not confuse with grants.
    entitlements = (
        db.query(GatewayEntitlement)
        .filter(
            or_(
                GatewayEntitlement.tenant_id == row.tenant_id,
                GatewayEntitlement.tenant_id.is_(None),
            )
        )
        .limit(20)
        .all()
    )
    for ent in entitlements:
        paths.append(
            {
                "hop": "tenant_context_entitlement",
                "resource": ent.entitlement_id,
                "action": ent.action,
                "environment": ent.environment,
                "enabled": bool(ent.enabled),
                "grant": False,
            }
        )

    routes = db.query(RoutePolicy).limit(15).all()
    for route in routes:
        paths.append(
            {
                "hop": "tenant_context_route",
                "resource": route.route_policy_id,
                "route_name": route.route_name,
                "status": route.status,
                "grant": False,
            }
        )

    return {
        "nhi_record_id": row.nhi_record_id,
        "source_type": row.source_type,
        "source_id": row.source_id,
        "identity_type": row.identity_type,
        "plane": "inference_gateway",
        "path_count": len(paths),
        "paths": paths[:80],
        "notes": (
            "Identity hops: virtual_key allowlists and mcp_tool bindings. "
            "tenant_context_* hops are blast-radius context only (not grants)—use "
            "Entitlements / Route Policy consoles for authoritative config. "
            "Not an enterprise SaaS IARA / app-access map."
        ),
    }


def build_nhi_timeline(
    db: Session,
    *,
    row: GatewayNhiInventory,
    limit: int = 50,
) -> dict[str, Any]:
    limit_n = max(1, min(200, int(limit)))
    resource_ids = {row.nhi_record_id, row.source_id}
    events = (
        db.query(AuditEvent)
        .filter(
            or_(
                AuditEvent.resource_id.in_(list(resource_ids)),
                AuditEvent.action_type.like("gateway.nhi.%"),
            )
        )
        .order_by(AuditEvent.timestamp.desc())
        .limit(limit_n * 3)
        .all()
    )
    timeline: list[dict[str, Any]] = []
    for event in events:
        ctx = {}
        if event.action_context_json:
            try:
                parsed = json.loads(event.action_context_json)
                if isinstance(parsed, dict):
                    ctx = parsed
            except json.JSONDecodeError:
                ctx = {}
        related = (
            event.resource_id in resource_ids
            or str(ctx.get("nhi_record_id") or "") == row.nhi_record_id
            or str(ctx.get("source_id") or "") == row.source_id
            or str(ctx.get("subject_id") or "") in resource_ids
        )
        if not related and not str(event.action_type or "").startswith("gateway.nhi."):
            continue
        if not related and str(event.action_type or "").startswith("gateway.nhi."):
            # keep global nhi governance events lightly
            if event.resource_id not in {"config", "evaluate", "hygiene-summary", "catalog"} and event.resource_id not in resource_ids:
                continue
        timeline.append(
            {
                "timestamp": event.timestamp.isoformat() + "Z" if event.timestamp else None,
                "action_type": event.action_type,
                "decision_outcome": event.decision_outcome,
                "actor_id": event.actor_id,
                "resource_type": event.resource_type,
                "resource_id": event.resource_id,
                "trace_id": event.trace_id,
                "summary": event.action_description or event.action_type,
            }
        )
        if len(timeline) >= limit_n:
            break

    gov = _record_governance(load_nhi_governance(db), row.nhi_record_id)
    for item in list(gov.get("lifecycle_history") or [])[:20]:
        if isinstance(item, dict):
            timeline.append(
                {
                    "timestamp": item.get("at"),
                    "action_type": f"gateway.nhi.lifecycle.{item.get('action')}",
                    "decision_outcome": "allow",
                    "actor_id": item.get("by"),
                    "resource_type": "gateway_nhi_inventory",
                    "resource_id": row.nhi_record_id,
                    "trace_id": item.get("trace_id"),
                    "summary": item.get("reason") or item.get("action"),
                }
            )
    timeline.sort(key=lambda item: str(item.get("timestamp") or ""), reverse=True)
    return {
        "nhi_record_id": row.nhi_record_id,
        "event_count": len(timeline[:limit_n]),
        "events": timeline[:limit_n],
    }


def effective_nhi_status_from_source(
    *,
    source_status: str,
    lifecycle_status: Optional[str],
    source_type: Optional[str] = None,
) -> str:
    """Resolve inventory status without a second conflicting control plane.

    - Virtual-key runtime truth remains VirtualKey.status (active/blocked).
      NHI suspend/retire is sticky while the key stays blocked; key unblock
      clears the annotation so Key Lifecycle and NHI lifecycle stay aligned.
    - Non-VK sources (WIF/secret/MCP): operator lifecycle_status is sticky
      because those sources do not mirror block/unblock.
    """
    src = str(source_status or "active").strip().lower() or "active"
    op = str(lifecycle_status or "").strip().lower()
    st = str(source_type or "").strip().lower()
    if op in {"suspended", "retired"}:
        if st == "virtual_key" and src in {"active", ""}:
            return "active"
        return op
    return src


def assign_nhi_owner(
    db: Session,
    *,
    row: GatewayNhiInventory,
    owner_scope_type: str,
    owner_scope_id: str,
    purpose: Optional[str] = None,
    actor_id: str,
) -> GatewayNhiInventory:
    scope_type = str(owner_scope_type or "").strip().lower()
    scope_id = str(owner_scope_id or "").strip()
    if not scope_type or not scope_id:
        raise HTTPException(status_code=422, detail="owner_scope_type and owner_scope_id are required")
    if scope_type not in {"user", "team", "group", "owner", "actor", "service"}:
        raise HTTPException(status_code=422, detail="owner_scope_type is not supported")
    # Virtual keys: Key Lifecycle owner fields are the source of truth so sync
    # cannot clobber an NHI-only owner write (dedupe dual-write plane).
    if str(row.source_type or "") == "virtual_key":
        key = db.query(VirtualKey).filter_by(key_id=row.source_id).first()
        if key is None:
            raise HTTPException(status_code=404, detail="Virtual key not found for NHI owner assign")
        key.owner_scope_type = scope_type
        key.owner_scope_id = scope_id
    row.owner_scope_type = scope_type
    row.owner_scope_id = scope_id
    row.updated_by = actor_id
    row.updated_at = datetime.utcnow()
    patch: dict[str, Any] = {
        "_history_event": {
            "action": "assign_owner",
            "by": actor_id,
            "at": datetime.utcnow().isoformat() + "Z",
            "reason": f"{scope_type}:{scope_id}",
            "trace_id": f"trace-nhi-owner-{uuid4().hex[:10]}",
        }
    }
    if purpose is not None:
        patch["purpose"] = str(purpose).strip()[:512]
    _upsert_record_governance(db, nhi_record_id=row.nhi_record_id, patch=patch, actor_id=actor_id)
    return row


def apply_nhi_lifecycle(
    db: Session,
    *,
    row: GatewayNhiInventory,
    action: str,
    reason: str,
    actor_id: str,
) -> GatewayNhiInventory:
    action_n = str(action or "").strip().lower()
    if action_n not in ALLOWED_LIFECYCLE_ACTIONS:
        raise HTTPException(
            status_code=422,
            detail=f"action must be one of: {', '.join(sorted(ALLOWED_LIFECYCLE_ACTIONS))}",
        )
    current = str(row.status or "active").strip().lower()
    if action_n == "suspend":
        if current == "retired":
            raise HTTPException(status_code=409, detail="Retired identities cannot be suspended")
        row.status = "suspended"
    elif action_n == "reactivate":
        if current == "retired":
            raise HTTPException(status_code=409, detail="Retired identities cannot be reactivated; create a new identity")
        row.status = "active"
    elif action_n == "retire":
        row.status = "retired"
    row.updated_by = actor_id
    row.updated_at = datetime.utcnow()
    _upsert_record_governance(
        db,
        nhi_record_id=row.nhi_record_id,
        patch={
            "lifecycle_status": row.status,
            "_history_event": {
                "action": action_n,
                "by": actor_id,
                "at": datetime.utcnow().isoformat() + "Z",
                "reason": str(reason or action_n).strip()[:512],
                "trace_id": f"trace-nhi-lifecycle-{uuid4().hex[:10]}",
            },
        },
        actor_id=actor_id,
    )
    # Mirror VK block/unblock — Key Lifecycle block/unblock remains the runtime
    # control; NHI lifecycle is the Zuma-shaped operator facade over the same VK.
    if row.source_type == "virtual_key":
        key = db.query(VirtualKey).filter_by(key_id=row.source_id).first()
        if key is not None:
            if action_n in {"suspend", "retire"}:
                key.status = "blocked"
            elif action_n == "reactivate":
                key.status = "active"
    return row


def set_nhi_correlation(
    db: Session,
    *,
    row: GatewayNhiInventory,
    external_ref: Optional[str] = None,
    iga_agent_id: Optional[str] = None,
    source_system: Optional[str] = None,
    actor_id: str,
) -> dict[str, Any]:
    """Bind gateway NHI to an upstream IGA agent id (correlation only — not inventory sync)."""
    from app.services.gateway_nhi_iga_deny import canonicalize_source_system

    ext = str(external_ref or "").strip()[:256] or None
    agent = str(iga_agent_id or "").strip()[:256] or None
    source = canonicalize_source_system(source_system)[:64] or None
    if source == "":
        source = None
    if not ext and not agent:
        raise HTTPException(status_code=422, detail="external_ref or iga_agent_id is required")
    meta = _upsert_record_governance(
        db,
        nhi_record_id=row.nhi_record_id,
        patch={
            "external_ref": ext,
            "iga_agent_id": agent,
            "correlation_source_system": source,
            "_history_event": {
                "action": "set_correlation",
                "by": actor_id,
                "at": datetime.utcnow().isoformat() + "Z",
                "reason": f"ref={ext or '-'} agent={agent or '-'}",
                "trace_id": f"trace-nhi-corr-{uuid4().hex[:10]}",
            },
        },
        actor_id=actor_id,
    )
    return {
        "nhi_record_id": row.nhi_record_id,
        "external_ref": meta.get("external_ref"),
        "iga_agent_id": meta.get("iga_agent_id"),
        "correlation_source_system": meta.get("correlation_source_system"),
    }


def list_nhi_orphans(
    db: Session,
    *,
    rows: list[GatewayNhiInventory],
    max_credential_age_days: int = 90,
    limit: int = 100,
) -> dict[str, Any]:
    """Missing-owner remediation queue (Zuma Governance orphan workflow, gateway plane)."""
    now = datetime.utcnow()
    gov = load_nhi_governance(db)
    orphans: list[dict[str, Any]] = []
    for row in rows:
        if str(row.owner_scope_id or "").strip():
            continue
        risk = _risk_score(row, max_credential_age_days=max_credential_age_days, now=now)
        meta = _record_governance(gov, row.nhi_record_id)
        orphans.append(
            {
                "nhi_record_id": row.nhi_record_id,
                "source_type": row.source_type,
                "source_id": row.source_id,
                "identity_type": row.identity_type,
                "tenant_id": row.tenant_id,
                "environment": row.environment,
                "status": row.status,
                "risk_score": risk["risk_score"],
                "risk_tier": risk["risk_tier"],
                "external_ref": meta.get("external_ref"),
                "iga_agent_id": meta.get("iga_agent_id"),
                "purpose": meta.get("purpose") or "",
            }
        )
    orphans.sort(key=lambda item: (-int(item["risk_score"]), str(item["nhi_record_id"])))
    limit_n = max(1, min(200, int(limit or 100)))
    return {
        "orphan_count": len(orphans),
        "orphans": orphans[:limit_n],
        "notes": (
            "Orphans = missing owner_scope_id. Assign via PUT /gateway/nhi/{id}/owner or "
            "POST /gateway/nhi/orphans/assign (reuses owner plane — not a second store)."
        ),
    }


def bulk_assign_nhi_orphans(
    db: Session,
    *,
    nhi_record_ids: list[str],
    owner_scope_type: str,
    owner_scope_id: str,
    purpose: Optional[str] = None,
    actor_id: str,
) -> dict[str, Any]:
    ids = [str(item).strip() for item in (nhi_record_ids or []) if str(item).strip()][:50]
    if not ids:
        raise HTTPException(status_code=422, detail="nhi_record_ids is required")
    updated: list[str] = []
    skipped: list[dict[str, str]] = []
    for nhi_id in ids:
        row = db.query(GatewayNhiInventory).filter_by(nhi_record_id=nhi_id).first()
        if row is None:
            skipped.append({"nhi_record_id": nhi_id, "reason": "not_found"})
            continue
        assign_nhi_owner(
            db,
            row=row,
            owner_scope_type=owner_scope_type,
            owner_scope_id=owner_scope_id,
            purpose=purpose,
            actor_id=actor_id,
        )
        updated.append(nhi_id)
    return {
        "updated_count": len(updated),
        "updated": updated,
        "skipped": skipped,
        "owner_scope_type": str(owner_scope_type or "").strip().lower(),
        "owner_scope_id": str(owner_scope_id or "").strip(),
    }


def set_nhi_approved_intents(
    db: Session,
    *,
    row: GatewayNhiInventory,
    purpose: str,
    approved_intents: list[str],
    actor_id: str,
) -> dict[str, Any]:
    intents = [str(item).strip() for item in (approved_intents or []) if str(item).strip()][:40]
    meta = _upsert_record_governance(
        db,
        nhi_record_id=row.nhi_record_id,
        patch={
            "purpose": str(purpose or "").strip()[:512],
            "approved_intents": intents,
            "_history_event": {
                "action": "set_intents",
                "by": actor_id,
                "at": datetime.utcnow().isoformat() + "Z",
                "reason": f"intents={len(intents)}",
                "trace_id": f"trace-nhi-intent-{uuid4().hex[:10]}",
            },
        },
        actor_id=actor_id,
    )
    return {
        "nhi_record_id": row.nhi_record_id,
        "purpose": meta.get("purpose") or "",
        "approved_intents": list(meta.get("approved_intents") or []),
    }


def resolve_nhi_for_intent(
    db: Session,
    *,
    nhi_record_id: Optional[str] = None,
    virtual_key_id: Optional[str] = None,
    owner_scope_id: Optional[str] = None,
    actor_id: Optional[str] = None,
) -> Optional[GatewayNhiInventory]:
    """Resolve NHI for intent-check without requiring a virtual key (NHI-006)."""
    if nhi_record_id:
        row = db.query(GatewayNhiInventory).filter_by(nhi_record_id=str(nhi_record_id).strip()).first()
        if row is not None:
            return row
    if virtual_key_id:
        row = (
            db.query(GatewayNhiInventory)
            .filter_by(source_type="virtual_key", source_id=str(virtual_key_id).strip())
            .first()
        )
        if row is not None:
            return row
    owner = str(owner_scope_id or "").strip()
    if owner:
        row = (
            db.query(GatewayNhiInventory)
            .filter(GatewayNhiInventory.owner_scope_id == owner)
            .order_by(GatewayNhiInventory.updated_at.desc())
            .first()
        )
        if row is not None:
            return row
    actor = str(actor_id or "").strip()
    if actor:
        row = (
            db.query(GatewayNhiInventory)
            .filter(GatewayNhiInventory.owner_scope_id == actor)
            .order_by(GatewayNhiInventory.updated_at.desc())
            .first()
        )
        if row is not None:
            return row
    return None


def ingest_nhi_correlation(
    db: Session,
    *,
    source_type: Optional[str] = None,
    source_id: Optional[str] = None,
    nhi_record_id: Optional[str] = None,
    virtual_key_id: Optional[str] = None,
    external_ref: Optional[str] = None,
    iga_agent_id: Optional[str] = None,
    source_system: Optional[str] = None,
    actor_id: str = "iga-correlation-ingest",
) -> dict[str, Any]:
    """Bind upstream IGA agent ids onto an existing gateway NHI (not a discovery crawl)."""
    gov = load_nhi_governance(db, reveal_secret=False)
    if not gov.get("correlation_ingest_enabled"):
        raise HTTPException(status_code=400, detail="NHI correlation ingest is disabled")
    row = None
    if nhi_record_id:
        row = db.query(GatewayNhiInventory).filter_by(nhi_record_id=str(nhi_record_id).strip()).first()
    elif virtual_key_id:
        row = (
            db.query(GatewayNhiInventory)
            .filter_by(source_type="virtual_key", source_id=str(virtual_key_id).strip())
            .first()
        )
    elif source_type and source_id:
        row = (
            db.query(GatewayNhiInventory)
            .filter_by(
                source_type=str(source_type).strip().lower(),
                source_id=str(source_id).strip(),
            )
            .first()
        )
    if row is None:
        raise HTTPException(
            status_code=404,
            detail="NHI record not found for correlation ingest (sync inventory first)",
        )
    return set_nhi_correlation(
        db,
        row=row,
        external_ref=external_ref,
        iga_agent_id=iga_agent_id,
        source_system=source_system,
        actor_id=actor_id,
    )


def evaluate_nhi_intent(
    db: Session,
    *,
    nhi_record_id: Optional[str] = None,
    virtual_key_id: Optional[str] = None,
    owner_scope_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    declared_intent: str,
    action: str = "chat.completions",
    missing_ok: bool = False,
    enforce: bool = False,
) -> dict[str, Any]:
    gov = load_nhi_governance(db)
    mode = str(gov.get("intent_mode") or "off")
    intent = str(declared_intent or "").strip()
    if not intent:
        raise HTTPException(status_code=422, detail="declared_intent is required")

    row = resolve_nhi_for_intent(
        db,
        nhi_record_id=nhi_record_id,
        virtual_key_id=virtual_key_id,
        owner_scope_id=owner_scope_id,
        actor_id=actor_id,
    )
    if row is None:
        # Hardening (NHI-008): on inference enforce, intent_mode=block fails closed when unbound.
        if enforce and mode == "block":
            return {
                "allowed": False,
                "matched": False,
                "mode": mode,
                "reason": "no_nhi_binding_fail_closed",
                "nhi_record_id": "",
                "declared_intent": intent,
                "action": action,
                "approved_intents": [],
                "decision": "deny",
            }
        if missing_ok:
            return {
                "allowed": True,
                "matched": False,
                "mode": mode,
                "reason": "no_nhi_binding",
                "nhi_record_id": "",
                "declared_intent": intent,
                "action": action,
                "approved_intents": [],
                "decision": "allow",
            }
        raise HTTPException(status_code=404, detail="NHI record not found for intent check")

    meta = _record_governance(gov, row.nhi_record_id)
    approved = [str(item).strip() for item in (meta.get("approved_intents") or []) if str(item).strip()]
    status = str(row.status or "active").strip().lower()
    if status in {"suspended", "retired", "blocked"}:
        return {
            "allowed": False if mode == "block" else True,
            "matched": True,
            "mode": mode,
            "reason": f"identity_status_{status}",
            "nhi_record_id": row.nhi_record_id,
            "declared_intent": intent,
            "action": action,
            "approved_intents": approved,
            "decision": "deny" if mode == "block" else ("warn" if mode == "warn" else "allow"),
        }

    if mode == "off":
        return {
            "allowed": True,
            "matched": False,
            "mode": mode,
            "reason": "intent_mode_off",
            "nhi_record_id": row.nhi_record_id,
            "declared_intent": intent,
            "action": action,
            "approved_intents": approved,
            "decision": "allow",
        }

    ok = intent in approved or f"{action}:{intent}" in approved or "*" in approved
    if ok:
        decision = "allow"
    elif mode == "warn":
        decision = "warn"
    else:
        decision = "deny"
    return {
        "allowed": decision != "deny",
        "matched": True,
        "mode": mode,
        "reason": "intent_approved" if ok else "intent_not_approved",
        "nhi_record_id": row.nhi_record_id,
        "declared_intent": intent,
        "action": action,
        "approved_intents": approved,
        "purpose": meta.get("purpose") or "",
        "decision": decision,
    }
