"""Gateway-native Access (IARA-lite) + agent inventory helpers (GOV-AI-IDSEC-NHI-007)."""

from __future__ import annotations

import fnmatch
from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import BrowserShadowAiApp, GatewayNhiInventory
from app.services.gateway_nhi_insights import (
    _risk_score,
    _upsert_record_governance,
    load_nhi_governance,
    resolve_nhi_for_intent,
    save_nhi_governance,
)

ALLOWED_ACCESS_MODES = frozenset({"off", "warn", "block"})
ALLOWED_EFFECTS = frozenset({"allow", "deny"})
AGENT_SOURCE_TYPES = frozenset(
    {
        "discovered_agent",
        "shadow_ai_app",
        "mcp_server",
        "virtual_key",
        "workload_identity_profile",
    }
)
SHADOW_ACTIONS = frozenset({"sanction", "block", "review"})


def _match_pattern(pattern: str, value: str) -> bool:
    pat = str(pattern or "*").strip() or "*"
    val = str(value or "").strip()
    if pat == "*":
        return True
    return fnmatch.fnmatch(val.lower(), pat.lower())


def load_access_config(db: Session) -> dict[str, Any]:
    gov = load_nhi_governance(db, reveal_secret=False)
    mode = str(gov.get("access_mode") or "off").strip().lower() or "off"
    if mode not in ALLOWED_ACCESS_MODES:
        mode = "off"
    policies = []
    for row in gov.get("access_policies") or []:
        if not isinstance(row, dict):
            continue
        effect = str(row.get("effect") or "allow").strip().lower()
        if effect not in ALLOWED_EFFECTS:
            continue
        policies.append(
            {
                "policy_id": str(row.get("policy_id") or f"nhi-pol-{uuid4().hex[:10]}"),
                "name": str(row.get("name") or "policy").strip()[:128],
                "intent": str(row.get("intent") or "*").strip()[:128] or "*",
                "resource": str(row.get("resource") or "*").strip()[:256] or "*",
                "action": str(row.get("action") or "*").strip()[:128] or "*",
                "effect": effect,
                "enabled": bool(row.get("enabled", True)),
            }
        )
    return {
        "access_mode": mode,
        "policy_count": len(policies),
        "access_policies": policies,
        "intent_mode": gov.get("intent_mode") or "off",
    }


def save_access_config(db: Session, payload: dict[str, Any], *, actor_id: str) -> dict[str, Any]:
    mode = str(payload.get("access_mode") or "off").strip().lower() or "off"
    if mode not in ALLOWED_ACCESS_MODES:
        raise HTTPException(
            status_code=422,
            detail=f"access_mode must be one of: {', '.join(sorted(ALLOWED_ACCESS_MODES))}",
        )
    incoming = payload.get("access_policies")
    if incoming is None:
        policies = load_access_config(db).get("access_policies") or []
    else:
        if not isinstance(incoming, list):
            raise HTTPException(status_code=422, detail="access_policies must be a list")
        policies = []
        for row in incoming[:100]:
            if not isinstance(row, dict):
                continue
            effect = str(row.get("effect") or "allow").strip().lower()
            if effect not in ALLOWED_EFFECTS:
                raise HTTPException(status_code=422, detail="effect must be allow|deny")
            policies.append(
                {
                    "policy_id": str(row.get("policy_id") or f"nhi-pol-{uuid4().hex[:10]}")[:64],
                    "name": str(row.get("name") or "policy").strip()[:128],
                    "intent": str(row.get("intent") or "*").strip()[:128] or "*",
                    "resource": str(row.get("resource") or "*").strip()[:256] or "*",
                    "action": str(row.get("action") or "*").strip()[:128] or "*",
                    "effect": effect,
                    "enabled": bool(row.get("enabled", True)),
                }
            )
    save_nhi_governance(
        db,
        {"access_mode": mode, "access_policies": policies},
        actor_id=actor_id,
    )
    return load_access_config(db)


def authorize_nhi_access(
    db: Session,
    *,
    declared_intent: str,
    resource: str = "*",
    action: str = "chat.completions",
    nhi_record_id: Optional[str] = None,
    virtual_key_id: Optional[str] = None,
    owner_scope_id: Optional[str] = None,
    actor_id: Optional[str] = None,
    missing_ok: bool = True,
    enforce: bool = False,
) -> dict[str, Any]:
    """IARA-lite: intent + resource + action against gateway access policies."""
    cfg = load_access_config(db)
    mode = str(cfg.get("access_mode") or "off")
    intent = str(declared_intent or "").strip()
    if not intent:
        raise HTTPException(status_code=422, detail="declared_intent is required")
    resource_n = str(resource or "*").strip() or "*"
    action_n = str(action or "chat.completions").strip() or "chat.completions"

    row = resolve_nhi_for_intent(
        db,
        nhi_record_id=nhi_record_id,
        virtual_key_id=virtual_key_id,
        owner_scope_id=owner_scope_id,
        actor_id=actor_id,
    )
    if row is None:
        if enforce and mode == "block":
            return {
                "allowed": False,
                "decision": "deny",
                "mode": mode,
                "matched_policy_id": None,
                "reason": "no_nhi_binding_fail_closed",
                "declared_intent": intent,
                "resource": resource_n,
                "action": action_n,
                "nhi_record_id": "",
            }
        if not missing_ok:
            raise HTTPException(status_code=404, detail="NHI record not found for access authorize")

    if mode == "off":
        return {
            "allowed": True,
            "decision": "allow",
            "mode": mode,
            "matched_policy_id": None,
            "reason": "access_mode_off",
            "declared_intent": intent,
            "resource": resource_n,
            "action": action_n,
            "nhi_record_id": row.nhi_record_id if row else "",
        }

    # Hardening: access_mode=block with empty policy set denies all declared intents.
    if mode == "block" and (cfg.get("policy_count") or 0) == 0:
        return {
            "allowed": False,
            "decision": "deny",
            "mode": mode,
            "matched_policy_id": None,
            "reason": "empty_policy_set_fail_closed",
            "declared_intent": intent,
            "resource": resource_n,
            "action": action_n,
            "nhi_record_id": row.nhi_record_id if row else "",
        }

    matched_deny = None
    matched_allow = None
    for policy in cfg.get("access_policies") or []:
        if not policy.get("enabled", True):
            continue
        if not (
            _match_pattern(policy.get("intent") or "*", intent)
            and _match_pattern(policy.get("resource") or "*", resource_n)
            and _match_pattern(policy.get("action") or "*", action_n)
        ):
            continue
        if policy.get("effect") == "deny" and matched_deny is None:
            matched_deny = policy
        if policy.get("effect") == "allow" and matched_allow is None:
            matched_allow = policy

    if matched_deny is not None:
        decision = "deny" if mode == "block" else ("warn" if mode == "warn" else "allow")
        return {
            "allowed": decision != "deny",
            "decision": decision,
            "mode": mode,
            "matched_policy_id": matched_deny.get("policy_id"),
            "reason": "policy_deny",
            "declared_intent": intent,
            "resource": resource_n,
            "action": action_n,
            "nhi_record_id": row.nhi_record_id if row else "",
        }
    if matched_allow is not None:
        return {
            "allowed": True,
            "decision": "allow",
            "mode": mode,
            "matched_policy_id": matched_allow.get("policy_id"),
            "reason": "policy_allow",
            "declared_intent": intent,
            "resource": resource_n,
            "action": action_n,
            "nhi_record_id": row.nhi_record_id if row else "",
        }

    if mode == "block":
        return {
            "allowed": False,
            "decision": "deny",
            "mode": mode,
            "matched_policy_id": None,
            "reason": "no_matching_allow_policy",
            "declared_intent": intent,
            "resource": resource_n,
            "action": action_n,
            "nhi_record_id": row.nhi_record_id if row else "",
        }
    return {
        "allowed": True,
        "decision": "allow" if mode != "warn" else "warn",
        "mode": mode,
        "matched_policy_id": None,
        "reason": "default_allow",
        "declared_intent": intent,
        "resource": resource_n,
        "action": action_n,
        "nhi_record_id": row.nhi_record_id if row else "",
    }


def list_nhi_agents(
    db: Session,
    *,
    rows: list[GatewayNhiInventory],
    max_credential_age_days: int = 90,
    limit: int = 100,
) -> dict[str, Any]:
    now = datetime.utcnow()
    gov = load_nhi_governance(db)
    agents = []
    for row in rows:
        if str(row.source_type or "") not in AGENT_SOURCE_TYPES:
            continue
        risk = _risk_score(row, max_credential_age_days=max_credential_age_days, now=now)
        meta = (gov.get("records") or {}).get(row.nhi_record_id) if isinstance(gov.get("records"), dict) else {}
        if not isinstance(meta, dict):
            meta = {}
        agents.append(
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
                "external_ref": meta.get("external_ref"),
                "iga_agent_id": meta.get("iga_agent_id"),
                **risk,
            }
        )
    agents.sort(key=lambda item: (-int(item["risk_score"]), str(item["nhi_record_id"])))
    limit_n = max(1, min(200, int(limit or 100)))
    by_type: dict[str, int] = {}
    for item in agents:
        key = str(item.get("source_type") or "unknown")
        by_type[key] = by_type.get(key, 0) + 1
    return {
        "agent_count": len(agents),
        "source_type_counts": by_type,
        "agents": agents[:limit_n],
        "access_mode": load_access_config(db).get("access_mode"),
        "notes": (
            "Unified gateway-native agent inventory (Discovery + Shadow AI + MCP + VK + WIF). "
            "Inference-plane agent inventory — not an enterprise SaaS ISPM crawl."
        ),
    }


def apply_shadow_ai_action(
    db: Session,
    *,
    row: GatewayNhiInventory,
    action: str,
    actor_id: str,
    notes: str = "",
) -> dict[str, Any]:
    action_n = str(action or "").strip().lower()
    if action_n not in SHADOW_ACTIONS:
        raise HTTPException(
            status_code=422,
            detail=f"action must be one of: {', '.join(sorted(SHADOW_ACTIONS))}",
        )
    if str(row.source_type or "") != "shadow_ai_app":
        raise HTTPException(status_code=422, detail="Shadow actions apply only to shadow_ai_app NHIs")
    app = db.query(BrowserShadowAiApp).filter_by(app_id=row.source_id).first()
    if app is None:
        raise HTTPException(status_code=404, detail="Shadow AI app not found")
    if action_n == "sanction":
        app.status = "sanctioned"
        row.status = "active"
    elif action_n == "block":
        app.status = "blocked"
        row.status = "suspended"
    else:
        app.status = "reviewed"
    app.reviewed_by = actor_id
    app.reviewed_at = datetime.utcnow()
    if notes:
        app.notes = str(notes).strip()[:2000]
    _upsert_record_governance(
        db,
        nhi_record_id=row.nhi_record_id,
        patch={
            "lifecycle_status": row.status,
            "_history_event": {
                "action": f"shadow_{action_n}",
                "by": actor_id,
                "at": datetime.utcnow().isoformat() + "Z",
                "reason": str(notes or action_n).strip()[:512],
                "trace_id": f"trace-nhi-shadow-{uuid4().hex[:10]}",
            },
        },
        actor_id=actor_id,
    )
    return {
        "nhi_record_id": row.nhi_record_id,
        "source_id": row.source_id,
        "shadow_status": app.status,
        "nhi_status": row.status,
        "action": action_n,
    }
