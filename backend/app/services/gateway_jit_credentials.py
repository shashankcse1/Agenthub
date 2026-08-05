"""Mint and revoke short-lived virtual keys tied to gateway JIT grants."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Optional
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import GatewayEntitlement, GatewayJitAccessRequest, VirtualKey
from app.policy_constants import COST_SCOPE_USER
from app.services.audit import create_audit_event
from app.services.scope_registry import SUPPORTED_OWNER_SCOPE_TYPES, normalize_scope_reference


def _jit_guardrail_policy(environment: str) -> str:
    env = str(environment or "dev").strip().lower() or "dev"
    policy = {
        "allowed_environments": [env],
        "require_mfa_for_prod": env in {"prod", "production"},
    }
    return json.dumps(policy, separators=(",", ":"), sort_keys=True)


def _allowed_models_from_entitlement(entitlement: Optional[GatewayEntitlement]) -> str:
    if entitlement is None:
        return "[]"
    model_name = str(getattr(entitlement, "model_name", None) or "").strip()
    if not model_name:
        return "[]"
    return json.dumps([model_name], separators=(",", ":"))


def resolve_jit_owner_scope(
    db: Session,
    *,
    request: GatewayJitAccessRequest,
) -> tuple[str, str]:
    scope_type = str(getattr(request, "owner_scope_type", None) or COST_SCOPE_USER).strip().lower() or COST_SCOPE_USER
    scope_id = str(getattr(request, "owner_scope_id", None) or "").strip() or str(request.requester_id or "").strip()
    return normalize_scope_reference(
        db,
        scope_type=scope_type,
        scope_id=scope_id,
        allowed_scope_types=SUPPORTED_OWNER_SCOPE_TYPES,
        resource_label="JIT virtual key owner scope",
    )


def mint_virtual_key_for_jit_grant(
    db: Session,
    *,
    request: GatewayJitAccessRequest,
    entitlement: Optional[GatewayEntitlement],
    actor_id: str,
    expires_at: datetime,
) -> tuple[VirtualKey, str]:
    """Create an expiring virtual key for an approved JIT grant.

    Returns (key, bearer_token). The bearer token is the one-time secret (key_hash)
    and must only be returned on the approve response.
    """
    if expires_at <= datetime.utcnow():
        raise HTTPException(
            status_code=422,
            detail={
                "error_code": "JIT_GRANT_ALREADY_EXPIRED",
                "message": "Cannot mint a virtual key for an already-expired JIT grant.",
            },
        )

    owner_scope_type, owner_scope_id = resolve_jit_owner_scope(db, request=request)
    bearer_token = str(uuid4())
    key_id = f"zjit-{int(datetime.utcnow().timestamp() * 1000):013d}-{uuid4().hex[:12]}"
    key = VirtualKey(
        key_id=key_id,
        key_hash=bearer_token,
        owner_scope_type=owner_scope_type,
        owner_scope_id=owner_scope_id,
        allowed_endpoint_families="[]",
        allowed_models=_allowed_models_from_entitlement(entitlement),
        guardrail_policy=_jit_guardrail_policy(request.environment),
        budget_policy_id="default",
        rate_limit_policy_id="default",
        authn_method="token",
        expires_at=expires_at,
        status="active",
        jit_request_id=request.request_id,
    )
    db.add(key)
    request.issued_virtual_key_id = key.key_id

    create_audit_event(
        db,
        actor_id=actor_id,
        action_type="gateway.jit.virtual_key.mint",
        resource_type="virtual_key",
        resource_id=key.key_id,
        trace_id=f"trace-gateway-jit-mint-{request.request_id}",
        action_context={
            "jit_request_id": request.request_id,
            "entitlement_id": request.entitlement_id,
            "owner_scope_type": owner_scope_type,
            "owner_scope_id": owner_scope_id,
            "expires_at": expires_at.isoformat() + "Z",
        },
    )
    return key, bearer_token


def revoke_jit_virtual_key_if_needed(
    db: Session,
    *,
    key: VirtualKey,
    actor_id: str,
    trace_id: str,
    reason: str = "jit_grant_expired",
) -> bool:
    """Block a JIT-linked virtual key when its grant or key expiry has elapsed.

    Returns True when the key was blocked (or already blocked after expiry).
    """
    jit_request_id = str(getattr(key, "jit_request_id", None) or "").strip()
    if not jit_request_id:
        return False

    now = datetime.utcnow()
    expired = False
    expires_at = getattr(key, "expires_at", None)
    if expires_at is not None:
        try:
            expired = expires_at <= now
        except TypeError:
            expired = True

    grant = db.query(GatewayJitAccessRequest).filter_by(request_id=jit_request_id).first()
    if grant is not None:
        grant_status = str(grant.status or "").strip().lower()
        if grant_status != "approved":
            expired = True
            reason = "jit_grant_not_approved"
        elif grant.expires_at is not None:
            try:
                if grant.expires_at <= now:
                    expired = True
                    reason = "jit_grant_expired"
            except TypeError:
                expired = True
                reason = "jit_grant_expired"

    if not expired:
        return False

    previous_status = str(key.status or "").strip().lower()
    if previous_status != "blocked":
        key.status = "blocked"
        create_audit_event(
            db,
            actor_id=actor_id,
            action_type="gateway.jit.virtual_key.revoke",
            resource_type="virtual_key",
            resource_id=key.key_id,
            trace_id=trace_id,
            decision_outcome="deny",
            action_context={
                "reason": reason,
                "jit_request_id": jit_request_id,
                "previous_status": previous_status or "active",
                "expires_at": expires_at.isoformat() if hasattr(expires_at, "isoformat") else str(expires_at),
            },
        )
    return True


def should_mint_virtual_key_on_approve(
    request: GatewayJitAccessRequest,
    *,
    approve_override: Optional[bool] = None,
) -> bool:
    if approve_override is not None:
        return bool(approve_override)
    return bool(getattr(request, "mint_virtual_key", True))


def revoke_jit_grant(
    db: Session,
    *,
    request: GatewayJitAccessRequest,
    actor_id: str,
    reason: str = "operator_revoke",
) -> Optional[VirtualKey]:
    """Mark an approved JIT grant revoked and block any minted virtual key.

    Returns the blocked virtual key when one was linked; otherwise None.
    """
    status = str(request.status or "").strip().lower()
    if status not in {"approved", "requested"}:
        raise HTTPException(
            status_code=409,
            detail={
                "error_code": "JIT_REQUEST_NOT_REVOCABLE",
                "message": f"JIT request status '{request.status}' cannot be revoked.",
                "status": request.status,
            },
        )

    previous_status = status
    now = datetime.utcnow()
    request.status = "revoked"
    request.expires_at = now if previous_status == "approved" else None

    key: Optional[VirtualKey] = None
    key_id = str(getattr(request, "issued_virtual_key_id", None) or "").strip()
    if key_id:
        key = db.query(VirtualKey).filter_by(key_id=key_id).first()
        if key is not None:
            previous_key_status = str(key.status or "").strip().lower()
            if previous_key_status != "blocked":
                key.status = "blocked"
            create_audit_event(
                db,
                actor_id=actor_id,
                action_type="gateway.jit.virtual_key.revoke",
                resource_type="virtual_key",
                resource_id=key.key_id,
                trace_id=f"trace-gateway-jit-revoke-key-{request.request_id}",
                decision_outcome="deny",
                action_context={
                    "reason": reason,
                    "jit_request_id": request.request_id,
                    "previous_status": previous_key_status or "active",
                    "expires_at": key.expires_at.isoformat() if key.expires_at else None,
                },
            )

    create_audit_event(
        db,
        actor_id=actor_id,
        action_type="gateway.jit.request.revoke",
        resource_type="gateway_jit_access_request",
        resource_id=request.request_id,
        trace_id=f"trace-gateway-jit-revoke-{request.request_id}",
        action_context={
            "reason": reason,
            "previous_status": previous_status,
            "issued_virtual_key_id": key_id or None,
        },
    )
    return key


def expire_stale_jit_grants(
    db: Session,
    *,
    actor_id: str = "system",
    limit: int = 200,
) -> dict[str, int]:
    """Block VKs and mark approved grants past expires_at as expired.

    Returns counts for operator/scheduler tick evidence.
    """
    now = datetime.utcnow()
    rows = (
        db.query(GatewayJitAccessRequest)
        .filter(GatewayJitAccessRequest.status == "approved")
        .filter(GatewayJitAccessRequest.expires_at.isnot(None))
        .filter(GatewayJitAccessRequest.expires_at <= now)
        .order_by(GatewayJitAccessRequest.expires_at.asc())
        .limit(max(1, min(int(limit or 200), 1000)))
        .all()
    )
    expired_grants = 0
    blocked_keys = 0
    for request in rows:
        request.status = "expired"
        expired_grants += 1
        key_id = str(getattr(request, "issued_virtual_key_id", None) or "").strip()
        if key_id:
            key = db.query(VirtualKey).filter_by(key_id=key_id).first()
            if key is not None and str(key.status or "").strip().lower() != "blocked":
                key.status = "blocked"
                blocked_keys += 1
                create_audit_event(
                    db,
                    actor_id=actor_id,
                    action_type="gateway.jit.virtual_key.revoke",
                    resource_type="virtual_key",
                    resource_id=key.key_id,
                    trace_id=f"trace-gateway-jit-expire-key-{request.request_id}",
                    decision_outcome="deny",
                    action_context={
                        "reason": "jit_grant_expired_tick",
                        "jit_request_id": request.request_id,
                    },
                )
        create_audit_event(
            db,
            actor_id=actor_id,
            action_type="gateway.jit.request.expire",
            resource_type="gateway_jit_access_request",
            resource_id=request.request_id,
            trace_id=f"trace-gateway-jit-expire-{request.request_id}",
            action_context={"issued_virtual_key_id": key_id or None},
        )
    return {"expired_grants": expired_grants, "blocked_keys": blocked_keys, "scanned": len(rows)}
