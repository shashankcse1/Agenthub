"""Email + external REST notifications for gateway JIT approve/deny decisions."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta
from typing import Any, Optional
from urllib.parse import urlparse
from uuid import uuid4

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import GatewayJitAccessRequest
from app.runtime_constants import (
    RUNTIME_CONFIG_GATEWAY_EXTERNAL_CALLBACKS_JSON,
    RUNTIME_CONFIG_GATEWAY_JIT_DECISION_NOTIFY_JSON,
)
from app.services.audit import create_audit_event
from app.services.credential_resolution import load_active_binding_by_id, resolve_binding_for_runtime
from app.services.gateway_notification_delivery import deliver_email
from app.services.runtime_config import get_runtime_config, upsert_runtime_config_value

_DEFAULT_CONFIG: dict[str, Any] = {
    "enabled": False,
    "notify_on_create": True,
    "email_channel_id": "",
    "reviewer_emails": [],
    "public_base_url": "",
    "external_callback_ids": [],
    "external_rest_url": "",
    "external_rest_credential_binding_id": "",
    "action_token_ttl_minutes": 1440,
    "allow_prod_email_approve": False,
}


def _signing_secret() -> bytes:
    raw = (os.getenv("SESSION_TOKEN_SECRET") or "dev-session-secret-change-me").encode("utf-8")
    return hashlib.sha256(b"gateway-jit-action:" + raw).digest()


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + padding)


def default_jit_decision_notify_config() -> dict[str, Any]:
    return dict(_DEFAULT_CONFIG)


def normalize_jit_decision_notify_config(raw: object) -> dict[str, Any]:
    if isinstance(raw, str):
        try:
            raw = json.loads(raw or "{}")
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail="decision notify config must be valid JSON") from exc
    if not isinstance(raw, dict):
        raise HTTPException(status_code=422, detail="decision notify config must be an object")

    emails: list[str] = []
    for item in raw.get("reviewer_emails") or []:
        email = str(item or "").strip().lower()
        if email and "@" in email and email not in emails:
            emails.append(email[:320])

    callback_ids: list[str] = []
    for item in raw.get("external_callback_ids") or []:
        callback_id = str(item or "").strip()
        if callback_id and callback_id not in callback_ids:
            callback_ids.append(callback_id[:64])

    ttl = int(raw.get("action_token_ttl_minutes") or 1440)
    ttl = max(15, min(ttl, 10080))

    public_base = str(raw.get("public_base_url") or "").strip().rstrip("/")
    if public_base:
        parsed = urlparse(public_base)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise HTTPException(status_code=422, detail="public_base_url must be an absolute http(s) URL")

    external_rest_url = str(raw.get("external_rest_url") or "").strip()
    if external_rest_url:
        parsed = urlparse(external_rest_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise HTTPException(status_code=422, detail="external_rest_url must be an absolute http(s) URL")

    return {
        "enabled": bool(raw.get("enabled", False)),
        "notify_on_create": bool(raw.get("notify_on_create", True)),
        "email_channel_id": str(raw.get("email_channel_id") or "").strip()[:128],
        "reviewer_emails": emails[:50],
        "public_base_url": public_base[:2048],
        "external_callback_ids": callback_ids[:20],
        "external_rest_url": external_rest_url[:2048],
        "external_rest_credential_binding_id": str(raw.get("external_rest_credential_binding_id") or "").strip()[:64],
        "action_token_ttl_minutes": ttl,
        "allow_prod_email_approve": bool(raw.get("allow_prod_email_approve", False)),
    }


def load_jit_decision_notify_config(db: Session) -> dict[str, Any]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_JIT_DECISION_NOTIFY_JSON, "{}")
    try:
        parsed = json.loads(raw or "{}")
    except json.JSONDecodeError:
        parsed = {}
    merged = {**_DEFAULT_CONFIG, **(parsed if isinstance(parsed, dict) else {})}
    return normalize_jit_decision_notify_config(merged)


def save_jit_decision_notify_config(db: Session, payload: object, *, actor_id: str) -> dict[str, Any]:
    config = normalize_jit_decision_notify_config(payload)
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_GATEWAY_JIT_DECISION_NOTIFY_JSON,
        json.dumps(config, separators=(",", ":"), sort_keys=True),
        description="Gateway JIT email/external REST decision notification settings",
    )
    create_audit_event(
        db,
        actor_id=actor_id,
        action_type="gateway.jit.decision_notify.config.update",
        resource_type="gateway_jit_decision_notify",
        resource_id="config",
        trace_id=f"trace-gateway-jit-notify-config-{uuid4().hex[:12]}",
        action_context={
            "enabled": config["enabled"],
            "notify_on_create": config["notify_on_create"],
            "reviewer_count": len(config["reviewer_emails"]),
            "external_callback_count": len(config["external_callback_ids"]),
            "has_external_rest_url": bool(config["external_rest_url"]),
        },
    )
    return config


def mint_jit_action_token(
    *,
    request_id: str,
    decision: str,
    reviewer_email: str,
    ttl_minutes: int,
) -> str:
    choice = str(decision or "").strip().lower()
    if choice not in {"approve", "deny"}:
        raise HTTPException(status_code=422, detail="decision must be approve or deny")
    exp = int((datetime.utcnow() + timedelta(minutes=max(15, min(int(ttl_minutes), 10080)))).timestamp())
    payload = {
        "request_id": str(request_id).strip(),
        "decision": choice,
        "email": str(reviewer_email or "").strip().lower(),
        "exp": exp,
        "jti": uuid4().hex,
    }
    body = _b64url_encode(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = _b64url_encode(hmac.new(_signing_secret(), body.encode("ascii"), hashlib.sha256).digest())
    return f"{body}.{signature}"


def verify_jit_action_token(token: str) -> dict[str, Any]:
    raw = str(token or "").strip()
    if "." not in raw:
        raise HTTPException(status_code=401, detail={"error_code": "JIT_ACTION_TOKEN_INVALID", "message": "Action token is invalid."})
    body, _, signature = raw.partition(".")
    expected = _b64url_encode(hmac.new(_signing_secret(), body.encode("ascii"), hashlib.sha256).digest())
    if not hmac.compare_digest(signature, expected):
        raise HTTPException(status_code=401, detail={"error_code": "JIT_ACTION_TOKEN_INVALID", "message": "Action token signature is invalid."})
    try:
        payload = json.loads(_b64url_decode(body).decode("utf-8"))
    except Exception as exc:
        raise HTTPException(status_code=401, detail={"error_code": "JIT_ACTION_TOKEN_INVALID", "message": "Action token payload is invalid."}) from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=401, detail={"error_code": "JIT_ACTION_TOKEN_INVALID", "message": "Action token payload is invalid."})
    exp = int(payload.get("exp") or 0)
    if exp <= int(datetime.utcnow().timestamp()):
        raise HTTPException(status_code=401, detail={"error_code": "JIT_ACTION_TOKEN_EXPIRED", "message": "Action token has expired."})
    decision = str(payload.get("decision") or "").strip().lower()
    if decision not in {"approve", "deny"}:
        raise HTTPException(status_code=401, detail={"error_code": "JIT_ACTION_TOKEN_INVALID", "message": "Action token decision is invalid."})
    request_id = str(payload.get("request_id") or "").strip()
    if not request_id:
        raise HTTPException(status_code=401, detail={"error_code": "JIT_ACTION_TOKEN_INVALID", "message": "Action token request id is missing."})
    return {
        "request_id": request_id,
        "decision": decision,
        "email": str(payload.get("email") or "").strip().lower(),
        "exp": exp,
        "jti": str(payload.get("jti") or "").strip(),
    }


def _load_external_callbacks(db: Session) -> list[dict[str, Any]]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_EXTERNAL_CALLBACKS_JSON, "[]")
    try:
        rows = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    return rows if isinstance(rows, list) else []


def _post_external_rest(
    db: Session,
    *,
    url: str,
    payload: dict[str, Any],
    credential_binding_id: str = "",
) -> dict[str, Any]:
    headers = {"Content-Type": "application/json", "User-Agent": "agenthub-gateway-jit-notify/1.0"}
    binding_id = str(credential_binding_id or "").strip()
    if binding_id:
        binding = load_active_binding_by_id(db, binding_id)
        resolved = resolve_binding_for_runtime(db, binding)
        secret = str(resolved.secret_value or "").strip()
        if secret:
            headers["Authorization"] = f"Bearer {secret}"
    try:
        with httpx.Client(timeout=8.0) as client:
            response = client.post(url, json=payload, headers=headers)
        return {
            "url": url,
            "status_code": response.status_code,
            "ok": 200 <= response.status_code < 300,
        }
    except Exception as exc:
        return {"url": url, "status_code": 0, "ok": False, "error": str(exc)[:200]}


def _build_action_links(config: dict[str, Any], request: GatewayJitAccessRequest, reviewer_email: str) -> dict[str, str]:
    base = str(config.get("public_base_url") or "").strip().rstrip("/")
    if not base:
        return {"approve_url": "", "deny_url": ""}
    ttl = int(config.get("action_token_ttl_minutes") or 1440)
    approve_token = mint_jit_action_token(
        request_id=request.request_id,
        decision="approve",
        reviewer_email=reviewer_email,
        ttl_minutes=ttl,
    )
    deny_token = mint_jit_action_token(
        request_id=request.request_id,
        decision="deny",
        reviewer_email=reviewer_email,
        ttl_minutes=ttl,
    )
    # Dedicated path (not under /jit-requests/{id}) so token routes never collide with request_id.
    return {
        "approve_url": f"{base}/gateway/jit-actions/{approve_token}",
        "deny_url": f"{base}/gateway/jit-actions/{deny_token}",
    }


def notify_jit_request(
    db: Session,
    *,
    request: GatewayJitAccessRequest,
    actor_id: str,
    event_type: str = "gateway.jit.request.create",
) -> dict[str, Any]:
    config = load_jit_decision_notify_config(db)
    if not config.get("enabled"):
        return {"notified": False, "reason": "disabled", "emails_sent": 0, "webhooks": []}

    emails_sent = 0
    email_errors: list[str] = []
    channel_id = str(config.get("email_channel_id") or "").strip()
    reviewers = list(config.get("reviewer_emails") or [])
    if channel_id and reviewers and event_type == "gateway.jit.request.create":
        for email in reviewers:
            links = _build_action_links(config, request, email)
            body = (
                f"Gateway JIT access request requires review.\n\n"
                f"Request ID: {request.request_id}\n"
                f"Entitlement: {request.entitlement_id}\n"
                f"Environment: {request.environment}\n"
                f"Requester: {request.requester_id} ({request.requester_role})\n"
                f"Duration (minutes): {request.requested_duration_minutes}\n"
                f"Justification: {request.justification}\n\n"
                f"Approve: {links['approve_url'] or '(set public_base_url to enable email action links)'}\n"
                f"Deny: {links['deny_url'] or '(set public_base_url to enable email action links)'}\n"
            )
            try:
                deliver_email(
                    db,
                    channel_id=channel_id,
                    to=email,
                    subject=f"[JIT] Review {request.request_id} ({request.environment})",
                    body=body,
                )
                emails_sent += 1
            except Exception as exc:
                email_errors.append(f"{email}: {str(exc)[:160]}")

    webhook_results: list[dict[str, Any]] = []
    event_payload = {
        "event_type": event_type,
        "request_id": request.request_id,
        "entitlement_id": request.entitlement_id,
        "environment": request.environment,
        "status": request.status,
        "requester_id": request.requester_id,
        "requester_role": request.requester_role,
        "justification": request.justification,
        "requested_duration_minutes": request.requested_duration_minutes,
        "owner_scope_type": getattr(request, "owner_scope_type", "user"),
        "owner_scope_id": getattr(request, "owner_scope_id", None),
        "issued_virtual_key_id": getattr(request, "issued_virtual_key_id", None),
        "expires_at": request.expires_at.isoformat() + "Z" if request.expires_at else None,
        "occurred_at": datetime.utcnow().isoformat() + "Z",
    }

    callback_ids = set(str(item).strip() for item in (config.get("external_callback_ids") or []) if str(item).strip())
    if callback_ids:
        for row in _load_external_callbacks(db):
            callback_id = str(row.get("callback_id") or "").strip()
            if callback_id not in callback_ids:
                continue
            if not bool(row.get("enabled", True)):
                webhook_results.append({"callback_id": callback_id, "ok": False, "error": "disabled"})
                continue
            url = str(row.get("callback_url") or "").strip()
            if not url:
                continue
            events = row.get("event_types") or []
            if isinstance(events, list) and events and event_type not in events and "gateway.jit.*" not in events:
                # Still deliver when callback was explicitly selected in JIT notify config.
                pass
            result = _post_external_rest(db, url=url, payload={**event_payload, "callback_id": callback_id})
            result["callback_id"] = callback_id
            webhook_results.append(result)

    rest_url = str(config.get("external_rest_url") or "").strip()
    if rest_url:
        result = _post_external_rest(
            db,
            url=rest_url,
            payload=event_payload,
            credential_binding_id=str(config.get("external_rest_credential_binding_id") or ""),
        )
        result["callback_id"] = "external_rest_url"
        webhook_results.append(result)

    create_audit_event(
        db,
        actor_id=actor_id,
        action_type="gateway.jit.decision_notify.send",
        resource_type="gateway_jit_access_request",
        resource_id=request.request_id,
        trace_id=f"trace-gateway-jit-notify-{request.request_id}-{uuid4().hex[:8]}",
        action_context={
            "event_type": event_type,
            "emails_sent": emails_sent,
            "email_errors": email_errors[:5],
            "webhook_count": len(webhook_results),
            "webhook_ok": sum(1 for item in webhook_results if item.get("ok")),
        },
    )
    return {
        "notified": True,
        "emails_sent": emails_sent,
        "email_errors": email_errors,
        "webhooks": webhook_results,
        "event_type": event_type,
    }
