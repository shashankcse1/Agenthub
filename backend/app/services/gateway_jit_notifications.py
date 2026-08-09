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

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import GatewayJitAccessRequest
from app.runtime_constants import (
    RUNTIME_CONFIG_GATEWAY_EXTERNAL_CALLBACKS_JSON,
    RUNTIME_CONFIG_GATEWAY_JIT_ACTION_JTI_JSON,
    RUNTIME_CONFIG_GATEWAY_JIT_CONFIRM_NONCE_JSON,
    RUNTIME_CONFIG_GATEWAY_JIT_DECISION_NOTIFY_JSON,
)
from app.services.audit import create_audit_event
from app.services.credential_resolution import load_active_binding_by_id, resolve_binding_for_runtime
from app.services.gateway_notification_delivery import deliver_email
from app.services.runtime_config import get_runtime_config, invalidate_runtime_config_cache, upsert_runtime_config_value

_DEFAULT_CONFIG: dict[str, Any] = {
    "enabled": False,
    "notify_on_create": True,
    "notify_on_decide": True,
    "email_channel_id": "",
    "reviewer_emails": [],
    "decision_recipient_emails": [],
    "public_base_url": "",
    "external_callback_ids": [],
    "external_rest_url": "",
    "external_rest_credential_binding_id": "",
    "action_token_ttl_minutes": 1440,
    "allow_prod_email_approve": False,
    "expose_virtual_key_on_email_action": False,
    "email_virtual_key_to_recipients": True,
    "webhook_sign_requests": True,
    "include_action_links_in_webhooks": False,
    "min_notify_interval_minutes": 15,
    "webhook_payload_style": "standard",
    "auto_reminder_after_minutes": 0,
    "escalate_after_minutes": 0,
    "escalation_reviewer_emails": [],
    "max_auto_reminders": 3,
    "auto_retry_failed_webhooks_on_tick": False,
}

_MAX_USED_JTIS = 500
_MAX_NOTIFY_HISTORY = 20


def _signing_secret() -> bytes:
    raw = (os.getenv("SESSION_TOKEN_SECRET") or "dev-session-secret-change-me").encode("utf-8")
    return hashlib.sha256(b"gateway-jit-action:" + raw).digest()


def _webhook_signing_secret() -> bytes:
    raw = (os.getenv("SESSION_TOKEN_SECRET") or "dev-session-secret-change-me").encode("utf-8")
    return hashlib.sha256(b"gateway-jit-webhook:" + raw).digest()


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64url_decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode(raw + padding)


def _normalize_emails(raw_list: object, *, limit: int = 50) -> list[str]:
    emails: list[str] = []
    for item in raw_list or []:
        email = str(item or "").strip().lower()
        if email and "@" in email and email not in emails:
            emails.append(email[:320])
    return emails[:limit]


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

    emails = _normalize_emails(raw.get("reviewer_emails"))
    decision_emails = _normalize_emails(raw.get("decision_recipient_emails"))
    escalation_emails = _normalize_emails(raw.get("escalation_reviewer_emails"))

    callback_ids: list[str] = []
    for item in raw.get("external_callback_ids") or []:
        callback_id = str(item or "").strip()
        if callback_id and callback_id not in callback_ids:
            callback_ids.append(callback_id[:64])

    ttl = int(raw.get("action_token_ttl_minutes") or 1440)
    ttl = max(15, min(ttl, 10080))
    if "min_notify_interval_minutes" in raw and raw.get("min_notify_interval_minutes") is not None:
        interval = int(raw.get("min_notify_interval_minutes"))
    else:
        interval = 15
    interval = max(0, min(interval, 1440))
    style = str(raw.get("webhook_payload_style") or "standard").strip().lower()
    if style not in {"standard", "compact"}:
        style = "standard"

    if "auto_reminder_after_minutes" in raw and raw.get("auto_reminder_after_minutes") is not None:
        auto_reminder = int(raw.get("auto_reminder_after_minutes"))
    else:
        auto_reminder = 0
    auto_reminder = max(0, min(auto_reminder, 10080))
    if "escalate_after_minutes" in raw and raw.get("escalate_after_minutes") is not None:
        escalate_after = int(raw.get("escalate_after_minutes"))
    else:
        escalate_after = 0
    escalate_after = max(0, min(escalate_after, 10080))
    if "max_auto_reminders" in raw and raw.get("max_auto_reminders") is not None:
        max_reminders = int(raw.get("max_auto_reminders"))
    else:
        max_reminders = 3
    max_reminders = max(0, min(max_reminders, 20))

    public_base = str(raw.get("public_base_url") or "").strip().rstrip("/")
    if public_base:
        parsed = urlparse(public_base)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            raise HTTPException(status_code=422, detail="public_base_url must be an absolute http(s) URL")

    from app.services.runtime_env import is_production_runtime
    from app.services.url_ssrf_guard import validate_outbound_webhook_url

    external_rest_url = str(raw.get("external_rest_url") or "").strip()
    if external_rest_url:
        external_rest_url = validate_outbound_webhook_url(
            external_rest_url,
            allow_empty=False,
            resolve_dns=False,
            allow_loopback_outside_prod=True,
        )

    webhook_sign = bool(raw.get("webhook_sign_requests", True))
    if is_production_runtime() and bool(raw.get("enabled", False)):
        webhook_sign = True

    return {
        "enabled": bool(raw.get("enabled", False)),
        "notify_on_create": bool(raw.get("notify_on_create", True)),
        "notify_on_decide": bool(raw.get("notify_on_decide", True)),
        "email_channel_id": str(raw.get("email_channel_id") or "").strip()[:128],
        "reviewer_emails": emails,
        "decision_recipient_emails": decision_emails,
        "public_base_url": public_base[:2048],
        "external_callback_ids": callback_ids[:20],
        "external_rest_url": external_rest_url[:2048],
        "external_rest_credential_binding_id": str(raw.get("external_rest_credential_binding_id") or "").strip()[:64],
        "action_token_ttl_minutes": ttl,
        "allow_prod_email_approve": bool(raw.get("allow_prod_email_approve", False)),
        "expose_virtual_key_on_email_action": bool(raw.get("expose_virtual_key_on_email_action", False)),
        "email_virtual_key_to_recipients": bool(raw.get("email_virtual_key_to_recipients", True)),
        "webhook_sign_requests": webhook_sign,
        "include_action_links_in_webhooks": bool(raw.get("include_action_links_in_webhooks", False)),
        "min_notify_interval_minutes": interval,
        "webhook_payload_style": style,
        "auto_reminder_after_minutes": auto_reminder,
        "escalate_after_minutes": escalate_after,
        "escalation_reviewer_emails": escalation_emails,
        "max_auto_reminders": max_reminders,
        "auto_retry_failed_webhooks_on_tick": bool(raw.get("auto_retry_failed_webhooks_on_tick", False)),
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
            "notify_on_decide": config["notify_on_decide"],
            "reviewer_count": len(config["reviewer_emails"]),
            "decision_recipient_count": len(config["decision_recipient_emails"]),
            "external_callback_count": len(config["external_callback_ids"]),
            "has_external_rest_url": bool(config["external_rest_url"]),
            "webhook_sign_requests": config["webhook_sign_requests"],
            "expose_virtual_key_on_email_action": config["expose_virtual_key_on_email_action"],
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
    jti = str(payload.get("jti") or "").strip()
    if not jti:
        raise HTTPException(status_code=401, detail={"error_code": "JIT_ACTION_TOKEN_INVALID", "message": "Action token jti is missing."})
    return {
        "request_id": request_id,
        "decision": decision,
        "email": str(payload.get("email") or "").strip().lower(),
        "exp": exp,
        "jti": jti,
    }


def _load_confirm_nonce_store(db: Session) -> dict[str, Any]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_JIT_CONFIRM_NONCE_JSON, '{"nonces":{}}')
    try:
        parsed = json.loads(raw or "{}")
    except json.JSONDecodeError:
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}
    nonces = parsed.get("nonces")
    if not isinstance(nonces, dict):
        nonces = {}
    # Drop expired entries.
    now = int(datetime.utcnow().timestamp())
    kept = {
        str(k): v
        for k, v in nonces.items()
        if isinstance(v, dict) and int(v.get("exp") or 0) >= now
    }
    return {"nonces": kept}


def _save_confirm_nonce_store(db: Session, store: dict[str, Any]) -> None:
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_GATEWAY_JIT_CONFIRM_NONCE_JSON,
        json.dumps(store, separators=(",", ":"), sort_keys=True),
        description="One-time JIT email action confirm nonces (anti offline-derive)",
    )


def mint_confirm_nonce(
    db: Session,
    *,
    jti: str,
    decision: str,
    request_id: str,
    exp: int,
) -> str:
    """Issue a random one-time confirm nonce bound to jti (requires prior GET)."""
    import secrets

    token_id = str(jti or "").strip()
    if not token_id:
        raise HTTPException(status_code=401, detail="Action token jti is missing.")
    nonce = secrets.token_urlsafe(32)
    store = _load_confirm_nonce_store(db)
    store["nonces"][token_id] = {
        "nonce": nonce,
        "decision": str(decision or "").strip().lower(),
        "request_id": str(request_id or "").strip(),
        "exp": int(exp or 0),
    }
    # Cap store size.
    items = list(store["nonces"].items())
    if len(items) > 500:
        store["nonces"] = dict(items[-500:])
    _save_confirm_nonce_store(db, store)
    return nonce


def verify_confirm_nonce(
    db: Session,
    *,
    jti: str,
    decision: str,
    request_id: str,
    nonce: str,
) -> None:
    """Consume one-time confirm nonce. Not offline-derivable from the action token."""
    token_id = str(jti or "").strip()
    provided = str(nonce or "").strip()
    if not token_id or not provided:
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "JIT_ACTION_CONFIRM_INVALID",
                "message": "Confirmation nonce is invalid. Open the email link and submit the confirm form.",
            },
        )
    store = _load_confirm_nonce_store(db)
    row = store["nonces"].get(token_id)
    if not isinstance(row, dict):
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "JIT_ACTION_CONFIRM_INVALID",
                "message": "Confirmation nonce is missing or expired. Re-open the email link first.",
            },
        )
    expected = str(row.get("nonce") or "")
    if (
        not expected
        or not hmac.compare_digest(expected, provided)
        or str(row.get("decision") or "") != str(decision or "").strip().lower()
        or str(row.get("request_id") or "") != str(request_id or "").strip()
    ):
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "JIT_ACTION_CONFIRM_INVALID",
                "message": "Confirmation nonce is invalid. Open the email link and submit the confirm form.",
            },
        )
    store["nonces"].pop(token_id, None)
    _save_confirm_nonce_store(db, store)


def persist_last_notify(request: GatewayJitAccessRequest, result: dict[str, Any]) -> None:
    delivery_id = str(result.get("delivery_id") or f"del-{uuid4().hex[:16]}")
    summary = {
        "notified": bool(result.get("notified")),
        "tested": result.get("tested"),
        "event_type": result.get("event_type"),
        "emails_sent": int(result.get("emails_sent") or 0),
        "email_errors": list(result.get("email_errors") or [])[:5],
        "webhook_count": len(result.get("webhooks") or []),
        "webhook_ok": sum(1 for item in (result.get("webhooks") or []) if item.get("ok")),
        "webhooks": list(result.get("webhooks") or [])[:20],
        "reason": result.get("reason"),
        "probe_id": result.get("probe_id"),
        "delivery_id": delivery_id,
        "is_reminder": bool(result.get("is_reminder")),
        "is_retry": bool(result.get("is_retry")),
        "is_escalation": bool(result.get("is_escalation")),
        "occurred_at": datetime.utcnow().isoformat() + "Z",
    }
    request.last_notify_json = json.dumps(summary, separators=(",", ":"), sort_keys=True)

    history = parse_notify_history(request)
    history_entry = {
        "delivery_id": delivery_id,
        "event_type": summary.get("event_type"),
        "emails_sent": summary.get("emails_sent"),
        "webhook_count": summary.get("webhook_count"),
        "webhook_ok": summary.get("webhook_ok"),
        "is_reminder": summary.get("is_reminder"),
        "is_retry": summary.get("is_retry"),
        "is_escalation": summary.get("is_escalation"),
        "occurred_at": summary.get("occurred_at"),
        "reason": summary.get("reason"),
    }
    history.append(history_entry)
    request.notify_history_json = json.dumps(history[-_MAX_NOTIFY_HISTORY:], separators=(",", ":"))


def parse_last_notify(request: GatewayJitAccessRequest) -> Optional[dict[str, Any]]:
    raw = getattr(request, "last_notify_json", None)
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def parse_notify_history(request: GatewayJitAccessRequest) -> list[dict[str, Any]]:
    raw = getattr(request, "notify_history_json", None)
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)][-_MAX_NOTIFY_HISTORY:]


def enforce_notify_cooldown(
    request: GatewayJitAccessRequest,
    config: dict[str, Any],
    *,
    force: bool = False,
) -> None:
    if force:
        return
    interval = int(config.get("min_notify_interval_minutes") or 0)
    if interval <= 0:
        return
    last = parse_last_notify(request)
    if not last:
        return
    occurred = str(last.get("occurred_at") or "").strip().rstrip("Z")
    if not occurred:
        return
    try:
        last_at = datetime.fromisoformat(occurred)
    except ValueError:
        return
    elapsed = datetime.utcnow() - last_at
    if elapsed < timedelta(minutes=interval):
        remaining = int((timedelta(minutes=interval) - elapsed).total_seconds() // 60) + 1
        raise HTTPException(
            status_code=429,
            detail={
                "error_code": "JIT_NOTIFY_COOLDOWN",
                "message": f"Notify cooldown active. Retry in ~{remaining} minute(s) or pass force=true.",
                "min_notify_interval_minutes": interval,
                "retry_after_minutes": remaining,
            },
        )


def preview_jit_action_decision(db: Session, token: str) -> dict[str, Any]:
    """Validate token and return a non-mutating confirm payload (anti-prefetch)."""
    claims = verify_jit_action_token(token)
    request = db.query(GatewayJitAccessRequest).filter_by(request_id=claims["request_id"]).first()
    if request is None:
        raise HTTPException(status_code=404, detail="Gateway JIT request not found")
    nonce = mint_confirm_nonce(
        db,
        jti=str(claims["jti"]),
        decision=str(claims["decision"]),
        request_id=str(claims["request_id"]),
        exp=int(claims["exp"]),
    )
    return {
        "pending": str(request.status or "").strip().lower() == "requested",
        "confirm_required": True,
        "request_id": request.request_id,
        "status": request.status,
        "decision": claims["decision"],
        "reviewer_email": claims.get("email") or "",
        "entitlement_id": request.entitlement_id,
        "environment": request.environment,
        "requester_id": request.requester_id,
        "justification": request.justification,
        "requested_duration_minutes": int(request.requested_duration_minutes or 60),
        "expires_claim_unix": int(claims["exp"]),
        "confirm_nonce": nonce,
        "message": (
            f"Confirm {claims['decision']} for JIT request {request.request_id}. "
            "Email clients that prefetch links will not apply this decision until you submit the form."
        ),
    }


def consume_jit_action_jti(db: Session, *, jti: str, exp: int) -> None:
    """Mark an action token jti as used. Raises 409 if already consumed."""
    token_id = str(jti or "").strip()
    if not token_id:
        raise HTTPException(status_code=401, detail={"error_code": "JIT_ACTION_TOKEN_INVALID", "message": "Action token jti is missing."})

    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_JIT_ACTION_JTI_JSON, '{"items":[]}')
    try:
        parsed = json.loads(raw or '{"items":[]}')
    except json.JSONDecodeError:
        parsed = {"items": []}
    items = parsed.get("items") if isinstance(parsed, dict) else []
    if not isinstance(items, list):
        items = []

    now_ts = int(datetime.utcnow().timestamp())
    pruned: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        item_jti = str(item.get("jti") or "").strip()
        item_exp = int(item.get("exp") or 0)
        if not item_jti or item_exp <= now_ts:
            continue
        if item_jti == token_id:
            raise HTTPException(
                status_code=409,
                detail={
                    "error_code": "JIT_ACTION_TOKEN_REPLAY",
                    "message": "Action token has already been used.",
                },
            )
        pruned.append({"jti": item_jti, "exp": item_exp, "used_at": str(item.get("used_at") or "")[:40]})

    pruned.append({"jti": token_id, "exp": int(exp), "used_at": datetime.utcnow().isoformat() + "Z"})
    pruned = pruned[-_MAX_USED_JTIS:]
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_GATEWAY_JIT_ACTION_JTI_JSON,
        json.dumps({"items": pruned}, separators=(",", ":")),
        description="Consumed gateway JIT email action token ids (jti)",
    )
    invalidate_runtime_config_cache(RUNTIME_CONFIG_GATEWAY_JIT_ACTION_JTI_JSON)


def _load_external_callbacks(db: Session) -> list[dict[str, Any]]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_EXTERNAL_CALLBACKS_JSON, "[]")
    try:
        rows = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    return rows if isinstance(rows, list) else []


def sign_jit_webhook_body(body: bytes) -> str:
    digest = hmac.new(_webhook_signing_secret(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def _post_external_rest(
    db: Session,
    *,
    url: str,
    payload: dict[str, Any],
    credential_binding_id: str = "",
    sign_requests: bool = True,
    delivery_id: str = "",
) -> dict[str, Any]:
    from app.services.pinned_outbound_http import pinned_httpx_compatible_post
    from app.services.runtime_env import is_production_runtime

    must_sign = bool(sign_requests) or is_production_runtime()
    body_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    delivery = str(delivery_id or payload.get("delivery_id") or f"del-{uuid4().hex[:16]}")
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "agenthub-gateway-jit-notify/1.2",
        "X-Gateway-Event-Type": str(payload.get("event_type") or ""),
        "X-Gateway-Request-Id": str(payload.get("request_id") or ""),
        "X-Gateway-Delivery-Id": delivery,
        "Idempotency-Key": delivery,
    }
    if must_sign:
        headers["X-Gateway-Jit-Signature"] = sign_jit_webhook_body(body_bytes)
    binding_id = str(credential_binding_id or "").strip()
    if binding_id:
        binding = load_active_binding_by_id(db, binding_id)
        resolved = resolve_binding_for_runtime(db, binding)
        secret = str(resolved.secret_value or "").strip()
        if secret:
            headers["Authorization"] = f"Bearer {secret}"
    try:
        # Resolve-once + IP-pin connect (closes DNS-rebinding TOCTOU after SSRF check).
        response = pinned_httpx_compatible_post(url, content=body_bytes, headers=headers, timeout=8.0)
        return {
            "url": url,
            "status_code": response.status_code,
            "ok": 200 <= response.status_code < 300,
            "signed": bool(must_sign),
            "delivery_id": delivery,
        }
    except HTTPException as exc:
        return {
            "url": url,
            "status_code": 0,
            "ok": False,
            "error": f"ssrf_blocked:{exc.detail}"[:200],
            "signed": False,
            "delivery_id": delivery,
        }
    except Exception as exc:
        return {
            "url": url,
            "status_code": 0,
            "ok": False,
            "error": str(exc)[:200],
            "signed": bool(must_sign),
            "delivery_id": delivery,
        }


def build_action_links(config: dict[str, Any], request: GatewayJitAccessRequest, reviewer_email: str) -> dict[str, str]:
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
    return {
        "approve_url": f"{base}/gateway/jit-actions/{approve_token}",
        "deny_url": f"{base}/gateway/jit-actions/{deny_token}",
    }


# Back-compat alias used by older call sites / tests.
_build_action_links = build_action_links


def preview_jit_action_links(
    db: Session,
    *,
    request: GatewayJitAccessRequest,
    reviewer_email: str = "preview@example.com",
) -> dict[str, Any]:
    config = load_jit_decision_notify_config(db)
    email = str(reviewer_email or "preview@example.com").strip().lower()
    if "@" not in email:
        raise HTTPException(status_code=422, detail="reviewer_email must be a valid email")
    links = build_action_links(config, request, email)
    return {
        "request_id": request.request_id,
        "status": request.status,
        "reviewer_email": email,
        "public_base_url": config.get("public_base_url") or "",
        "action_token_ttl_minutes": int(config.get("action_token_ttl_minutes") or 1440),
        "approve_url": links["approve_url"],
        "deny_url": links["deny_url"],
        "links_ready": bool(links["approve_url"] and links["deny_url"]),
    }


def _event_payload(
    request: GatewayJitAccessRequest,
    *,
    event_type: str,
    action_links: Optional[dict[str, str]] = None,
    delivery_id: str = "",
    payload_style: str = "standard",
) -> dict[str, Any]:
    delivery = str(delivery_id or f"del-{uuid4().hex[:16]}")
    style = str(payload_style or "standard").strip().lower()
    if style == "compact":
        payload: dict[str, Any] = {
            "event_type": event_type,
            "request_id": request.request_id,
            "status": request.status,
            "environment": request.environment,
            "entitlement_id": request.entitlement_id,
            "delivery_id": delivery,
            "occurred_at": datetime.utcnow().isoformat() + "Z",
        }
    else:
        payload = {
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
            "delivery_id": delivery,
            "occurred_at": datetime.utcnow().isoformat() + "Z",
        }
    if action_links:
        payload["approve_url"] = action_links.get("approve_url") or ""
        payload["deny_url"] = action_links.get("deny_url") or ""
    return payload


def _deliver_webhooks(
    db: Session,
    *,
    config: dict[str, Any],
    event_payload: dict[str, Any],
) -> list[dict[str, Any]]:
    webhook_results: list[dict[str, Any]] = []
    sign_requests = bool(config.get("webhook_sign_requests", True))
    delivery_id = str(event_payload.get("delivery_id") or "")
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
            result = _post_external_rest(
                db,
                url=url,
                payload={**event_payload, "callback_id": callback_id},
                sign_requests=sign_requests,
                delivery_id=f"{delivery_id}:{callback_id}" if delivery_id else "",
            )
            result["callback_id"] = callback_id
            webhook_results.append(result)

    rest_url = str(config.get("external_rest_url") or "").strip()
    if rest_url:
        result = _post_external_rest(
            db,
            url=rest_url,
            payload=event_payload,
            credential_binding_id=str(config.get("external_rest_credential_binding_id") or ""),
            sign_requests=sign_requests,
            delivery_id=f"{delivery_id}:external_rest_url" if delivery_id else "",
        )
        result["callback_id"] = "external_rest_url"
        webhook_results.append(result)
    return webhook_results


def deliver_virtual_key_email(
    db: Session,
    *,
    request: GatewayJitAccessRequest,
    issued_virtual_key_token: str,
    actor_id: str,
) -> dict[str, Any]:
    """Email the one-time VK to configured decision recipients (never to arbitrary reviewers by default)."""
    config = load_jit_decision_notify_config(db)
    if not config.get("email_virtual_key_to_recipients"):
        return {"emails_sent": 0, "email_errors": [], "skipped": True, "reason": "email_virtual_key_to_recipients=false"}
    channel_id = str(config.get("email_channel_id") or "").strip()
    recipients = list(config.get("decision_recipient_emails") or [])
    if not channel_id or not recipients or not issued_virtual_key_token:
        return {
            "emails_sent": 0,
            "email_errors": [],
            "skipped": True,
            "reason": "missing channel, recipients, or token",
        }

    emails_sent = 0
    email_errors: list[str] = []
    for email in recipients:
        body = (
            f"Gateway JIT grant approved and a short-lived virtual key was minted.\n\n"
            f"Request ID: {request.request_id}\n"
            f"Virtual Key ID: {getattr(request, 'issued_virtual_key_id', None)}\n"
            f"Expires: {request.expires_at.isoformat() + 'Z' if request.expires_at else 'n/a'}\n\n"
            f"One-time bearer token (copy now; not re-readable):\n{issued_virtual_key_token}\n"
        )
        try:
            deliver_email(
                db,
                channel_id=channel_id,
                to=email,
                subject=f"[JIT] Virtual key for {request.request_id}",
                body=body,
            )
            emails_sent += 1
        except Exception as exc:
            email_errors.append(f"{email}: {str(exc)[:160]}")

    create_audit_event(
        db,
        actor_id=actor_id,
        action_type="gateway.jit.decision_notify.key_email",
        resource_type="gateway_jit_access_request",
        resource_id=request.request_id,
        trace_id=f"trace-gateway-jit-key-email-{request.request_id}-{uuid4().hex[:8]}",
        action_context={
            "emails_sent": emails_sent,
            "email_errors": email_errors[:5],
            "issued_virtual_key_id": getattr(request, "issued_virtual_key_id", None),
        },
    )
    return {"emails_sent": emails_sent, "email_errors": email_errors, "skipped": False}


def notify_jit_request(
    db: Session,
    *,
    request: GatewayJitAccessRequest,
    actor_id: str,
    event_type: str = "gateway.jit.request.create",
    reminder: bool = False,
    force: bool = False,
    escalate: bool = False,
) -> dict[str, Any]:
    config = load_jit_decision_notify_config(db)
    if not config.get("enabled"):
        return {"notified": False, "reason": "disabled", "emails_sent": 0, "webhooks": []}

    if escalate:
        effective_event = "gateway.jit.request.escalate"
    elif reminder:
        effective_event = "gateway.jit.request.reminder"
    else:
        effective_event = event_type
    if effective_event in {
        "gateway.jit.request.create",
        "gateway.jit.request.reminder",
        "gateway.jit.request.escalate",
    }:
        enforce_notify_cooldown(request, config, force=force)

    emails_sent = 0
    email_errors: list[str] = []
    channel_id = str(config.get("email_channel_id") or "").strip()
    if escalate:
        reviewers = list(config.get("escalation_reviewer_emails") or []) or list(config.get("reviewer_emails") or [])
    else:
        reviewers = list(config.get("reviewer_emails") or [])
    decision_recipients = list(config.get("decision_recipient_emails") or [])
    delivery_id = f"del-{uuid4().hex[:16]}"

    review_events = {
        "gateway.jit.request.create",
        "gateway.jit.request.reminder",
        "gateway.jit.request.escalate",
    }
    if channel_id and effective_event in review_events and reviewers:
        for email in reviewers:
            links = build_action_links(config, request, email)
            if escalate:
                subject_prefix = "[JIT ESCALATION]"
                lead = "escalated and still requires review"
            elif reminder:
                subject_prefix = "[JIT REMINDER]"
                lead = "reminder"
            else:
                subject_prefix = "[JIT]"
                lead = "requires review"
            body = (
                f"Gateway JIT access request {lead}.\n\n"
                f"Request ID: {request.request_id}\n"
                f"Entitlement: {request.entitlement_id}\n"
                f"Environment: {request.environment}\n"
                f"Requester: {request.requester_id} ({request.requester_role})\n"
                f"Duration (minutes): {request.requested_duration_minutes}\n"
                f"Justification: {request.justification}\n\n"
                f"Approve: {links['approve_url'] or '(set public_base_url to enable email action links)'}\n"
                f"Deny: {links['deny_url'] or '(set public_base_url to enable email action links)'}\n\n"
                f"Opening a link shows a confirmation page only. Submit the form to apply the decision "
                f"(email scanners that prefetch links will not approve or deny).\n"
            )
            try:
                deliver_email(
                    db,
                    channel_id=channel_id,
                    to=email,
                    subject=f"{subject_prefix} Review {request.request_id} ({request.environment})",
                    body=body,
                )
                emails_sent += 1
            except Exception as exc:
                email_errors.append(f"{email}: {str(exc)[:160]}")

    decide_events = {
        "gateway.jit.request.approve",
        "gateway.jit.request.deny",
        "gateway.jit.request.revoked",
        "gateway.jit.request.revoke",
    }
    if channel_id and config.get("notify_on_decide") and effective_event in decide_events and decision_recipients:
        for email in decision_recipients:
            body = (
                f"Gateway JIT request decision update.\n\n"
                f"Request ID: {request.request_id}\n"
                f"Status: {request.status}\n"
                f"Event: {effective_event}\n"
                f"Entitlement: {request.entitlement_id}\n"
                f"Environment: {request.environment}\n"
                f"Virtual Key ID: {getattr(request, 'issued_virtual_key_id', None) or 'n/a'}\n"
                f"Expires: {request.expires_at.isoformat() + 'Z' if request.expires_at else 'n/a'}\n"
            )
            try:
                deliver_email(
                    db,
                    channel_id=channel_id,
                    to=email,
                    subject=f"[JIT] {request.status} {request.request_id}",
                    body=body,
                )
                emails_sent += 1
            except Exception as exc:
                email_errors.append(f"{email}: {str(exc)[:160]}")

    action_links = None
    if config.get("include_action_links_in_webhooks") and effective_event in review_events:
        preview_email = (reviewers[0] if reviewers else "webhook@example.com")
        action_links = build_action_links(config, request, preview_email)

    event_payload = _event_payload(
        request,
        event_type=effective_event,
        action_links=action_links,
        delivery_id=delivery_id,
        payload_style=str(config.get("webhook_payload_style") or "standard"),
    )
    webhook_results = _deliver_webhooks(db, config=config, event_payload=event_payload)

    create_audit_event(
        db,
        actor_id=actor_id,
        action_type="gateway.jit.decision_notify.send",
        resource_type="gateway_jit_access_request",
        resource_id=request.request_id,
        trace_id=f"trace-gateway-jit-notify-{request.request_id}-{uuid4().hex[:8]}",
        action_context={
            "event_type": effective_event,
            "emails_sent": emails_sent,
            "email_errors": email_errors[:5],
            "webhook_count": len(webhook_results),
            "webhook_ok": sum(1 for item in webhook_results if item.get("ok")),
            "webhook_signed": bool(config.get("webhook_sign_requests", True)),
            "delivery_id": delivery_id,
            "is_reminder": bool(reminder) and not escalate,
            "is_escalation": bool(escalate),
            "force": bool(force),
        },
    )
    result = {
        "notified": True,
        "emails_sent": emails_sent,
        "email_errors": email_errors,
        "webhooks": webhook_results,
        "event_type": effective_event,
        "delivery_id": delivery_id,
        "is_reminder": bool(reminder) and not escalate,
        "is_escalation": bool(escalate),
    }
    persist_last_notify(request, result)
    return result


def _request_age_minutes(request: GatewayJitAccessRequest) -> int:
    created = getattr(request, "created_at", None)
    if created is None:
        return 0
    if getattr(created, "tzinfo", None) is not None:
        created = created.replace(tzinfo=None)
    elapsed = datetime.utcnow() - created
    return max(0, int(elapsed.total_seconds() // 60))


def _history_reminder_count(request: GatewayJitAccessRequest) -> int:
    return sum(
        1
        for item in parse_notify_history(request)
        if item.get("is_reminder") or str(item.get("event_type") or "") == "gateway.jit.request.reminder"
    )


def _history_was_escalated(request: GatewayJitAccessRequest) -> bool:
    for item in parse_notify_history(request):
        if item.get("is_escalation") or str(item.get("event_type") or "") == "gateway.jit.request.escalate":
            return True
    last = parse_last_notify(request) or {}
    return bool(last.get("is_escalation") or str(last.get("event_type") or "") == "gateway.jit.request.escalate")


def pending_jit_notify_summary(db: Session) -> dict[str, Any]:
    config = load_jit_decision_notify_config(db)
    rows = (
        db.query(GatewayJitAccessRequest)
        .filter(GatewayJitAccessRequest.status == "requested")
        .order_by(GatewayJitAccessRequest.created_at.asc())
        .limit(500)
        .all()
    )
    auto_reminder = int(config.get("auto_reminder_after_minutes") or 0)
    escalate_after = int(config.get("escalate_after_minutes") or 0)
    overdue_reminder = 0
    overdue_escalation = 0
    failed_webhooks = 0
    oldest_age = None
    for row in rows:
        age = _request_age_minutes(row)
        oldest_age = age if oldest_age is None else max(oldest_age, age)
        if auto_reminder > 0 and age >= auto_reminder and _history_reminder_count(row) < int(config.get("max_auto_reminders") or 0):
            overdue_reminder += 1
        if escalate_after > 0 and age >= escalate_after and not _history_was_escalated(row):
            overdue_escalation += 1
        last = parse_last_notify(row) or {}
        failed = [item for item in (last.get("webhooks") or []) if isinstance(item, dict) and not item.get("ok")]
        if failed:
            failed_webhooks += 1
    return {
        "enabled": bool(config.get("enabled")),
        "pending_count": len(rows),
        "overdue_reminder_count": overdue_reminder,
        "overdue_escalation_count": overdue_escalation,
        "failed_webhook_count": failed_webhooks,
        "oldest_pending_age_minutes": oldest_age,
        "auto_reminder_after_minutes": auto_reminder,
        "escalate_after_minutes": escalate_after,
        "max_auto_reminders": int(config.get("max_auto_reminders") or 0),
        "auto_retry_failed_webhooks_on_tick": bool(config.get("auto_retry_failed_webhooks_on_tick")),
    }


def run_jit_notify_tick(
    db: Session,
    *,
    actor_id: str,
    limit: int = 100,
) -> dict[str, Any]:
    config = load_jit_decision_notify_config(db)
    if not config.get("enabled"):
        return {
            "scanned": 0,
            "reminded": 0,
            "escalated": 0,
            "retried": 0,
            "skipped": 0,
            "items": [],
            "reason": "disabled",
        }

    rows = (
        db.query(GatewayJitAccessRequest)
        .filter(GatewayJitAccessRequest.status == "requested")
        .order_by(GatewayJitAccessRequest.created_at.asc())
        .limit(max(1, min(int(limit or 100), 500)))
        .all()
    )
    auto_reminder = int(config.get("auto_reminder_after_minutes") or 0)
    escalate_after = int(config.get("escalate_after_minutes") or 0)
    max_reminders = int(config.get("max_auto_reminders") or 0)
    auto_retry = bool(config.get("auto_retry_failed_webhooks_on_tick"))

    reminded = 0
    escalated = 0
    retried = 0
    skipped = 0
    items: list[dict[str, Any]] = []

    for row in rows:
        age = _request_age_minutes(row)
        actions: list[str] = []
        last = parse_last_notify(row) or {}
        failed = [item for item in (last.get("webhooks") or []) if isinstance(item, dict) and not item.get("ok")]

        if auto_retry and failed:
            retry_result = retry_failed_jit_webhooks(db, request=row, actor_id=actor_id)
            if retry_result.get("notified"):
                retried += 1
                actions.append("retry")
            else:
                actions.append(f"retry_skip:{retry_result.get('reason') or 'none'}")

        did_escalate = False
        if (
            escalate_after > 0
            and age >= escalate_after
            and not _history_was_escalated(row)
            and (config.get("escalation_reviewer_emails") or config.get("reviewer_emails") or config.get("external_rest_url") or config.get("external_callback_ids"))
        ):
            notify_jit_request(
                db,
                request=row,
                actor_id=actor_id,
                escalate=True,
                force=True,
            )
            escalated += 1
            did_escalate = True
            actions.append("escalate")

        if (
            not did_escalate
            and auto_reminder > 0
            and age >= auto_reminder
            and _history_reminder_count(row) < max_reminders
        ):
            notify_jit_request(
                db,
                request=row,
                actor_id=actor_id,
                reminder=True,
                force=True,
            )
            reminded += 1
            actions.append("remind")

        if not actions:
            skipped += 1
            actions.append("skip")

        items.append(
            {
                "request_id": row.request_id,
                "age_minutes": age,
                "actions": actions,
            }
        )

    create_audit_event(
        db,
        actor_id=actor_id,
        action_type="gateway.jit.decision_notify.tick",
        resource_type="gateway_jit_decision_notify",
        resource_id="notify-tick",
        trace_id=f"trace-gateway-jit-notify-tick-{uuid4().hex[:12]}",
        action_context={
            "scanned": len(rows),
            "reminded": reminded,
            "escalated": escalated,
            "retried": retried,
            "skipped": skipped,
        },
    )
    return {
        "scanned": len(rows),
        "reminded": reminded,
        "escalated": escalated,
        "retried": retried,
        "skipped": skipped,
        "items": items[:100],
    }


def retry_failed_jit_webhooks(
    db: Session,
    *,
    request: GatewayJitAccessRequest,
    actor_id: str,
) -> dict[str, Any]:
    config = load_jit_decision_notify_config(db)
    if not config.get("enabled"):
        return {"notified": False, "reason": "disabled", "emails_sent": 0, "webhooks": [], "is_retry": True}

    last = parse_last_notify(request) or {}
    failed = [item for item in (last.get("webhooks") or []) if isinstance(item, dict) and not item.get("ok")]
    if not failed:
        return {
            "notified": False,
            "reason": "no_failed_webhooks",
            "emails_sent": 0,
            "webhooks": [],
            "is_retry": True,
            "event_type": str(last.get("event_type") or "gateway.jit.request.create"),
        }

    delivery_id = f"del-retry-{uuid4().hex[:12]}"
    event_type = str(last.get("event_type") or "gateway.jit.request.create")
    base_payload = _event_payload(
        request,
        event_type=event_type,
        delivery_id=delivery_id,
        payload_style=str(config.get("webhook_payload_style") or "standard"),
    )
    sign_requests = bool(config.get("webhook_sign_requests", True))
    results: list[dict[str, Any]] = []
    for item in failed:
        url = str(item.get("url") or "").strip()
        callback_id = str(item.get("callback_id") or "").strip() or "retry"
        if not url:
            results.append({**item, "ok": False, "error": "missing_url", "retried": True})
            continue
        binding = ""
        if callback_id == "external_rest_url":
            binding = str(config.get("external_rest_credential_binding_id") or "")
        result = _post_external_rest(
            db,
            url=url,
            payload={**base_payload, "callback_id": callback_id, "retry_of": last.get("delivery_id")},
            credential_binding_id=binding,
            sign_requests=sign_requests,
            delivery_id=f"{delivery_id}:{callback_id}",
        )
        result["callback_id"] = callback_id
        result["retried"] = True
        results.append(result)

    create_audit_event(
        db,
        actor_id=actor_id,
        action_type="gateway.jit.decision_notify.retry",
        resource_type="gateway_jit_access_request",
        resource_id=request.request_id,
        trace_id=f"trace-gateway-jit-notify-retry-{request.request_id}-{uuid4().hex[:8]}",
        action_context={
            "delivery_id": delivery_id,
            "retried": len(results),
            "webhook_ok": sum(1 for item in results if item.get("ok")),
        },
    )
    result = {
        "notified": True,
        "emails_sent": 0,
        "email_errors": [],
        "webhooks": results,
        "event_type": event_type,
        "delivery_id": delivery_id,
        "is_retry": True,
    }
    persist_last_notify(request, result)
    return result


def test_jit_decision_notify_delivery(db: Session, *, actor_id: str) -> dict[str, Any]:
    """Send a synthetic webhook (+ optional probe email) using current config without mutating JIT rows."""
    config = load_jit_decision_notify_config(db)
    if not config.get("enabled"):
        return {"tested": False, "reason": "disabled", "emails_sent": 0, "webhooks": []}

    probe_id = f"gjit-probe-{uuid4().hex[:12]}"
    event_payload = {
        "event_type": "gateway.jit.notify.test",
        "request_id": probe_id,
        "entitlement_id": "ent-probe",
        "environment": "dev",
        "status": "requested",
        "requester_id": actor_id,
        "requester_role": "probe",
        "justification": "JIT decision notify test delivery",
        "requested_duration_minutes": 15,
        "owner_scope_type": "user",
        "owner_scope_id": actor_id,
        "issued_virtual_key_id": None,
        "expires_at": None,
        "occurred_at": datetime.utcnow().isoformat() + "Z",
        "probe": True,
    }
    webhook_results = _deliver_webhooks(db, config=config, event_payload=event_payload)

    emails_sent = 0
    email_errors: list[str] = []
    channel_id = str(config.get("email_channel_id") or "").strip()
    reviewers = list(config.get("reviewer_emails") or [])[:1]
    if channel_id and reviewers and config.get("public_base_url"):
        email = reviewers[0]
        links = {
            "approve_url": f"{config['public_base_url']}/gateway/jit-actions/(probe-token-not-valid)",
            "deny_url": f"{config['public_base_url']}/gateway/jit-actions/(probe-token-not-valid)",
        }
        try:
            deliver_email(
                db,
                channel_id=channel_id,
                to=email,
                subject=f"[JIT] Test delivery {probe_id}",
                body=(
                    "This is a test delivery from Gateway JIT decision notify config.\n\n"
                    f"Probe ID: {probe_id}\n"
                    f"Approve (invalid probe): {links['approve_url']}\n"
                    f"Deny (invalid probe): {links['deny_url']}\n"
                ),
            )
            emails_sent = 1
        except Exception as exc:
            email_errors.append(f"{email}: {str(exc)[:160]}")

    create_audit_event(
        db,
        actor_id=actor_id,
        action_type="gateway.jit.decision_notify.test",
        resource_type="gateway_jit_decision_notify",
        resource_id="test",
        trace_id=f"trace-gateway-jit-notify-test-{uuid4().hex[:12]}",
        action_context={
            "probe_id": probe_id,
            "emails_sent": emails_sent,
            "email_errors": email_errors[:5],
            "webhook_count": len(webhook_results),
            "webhook_ok": sum(1 for item in webhook_results if item.get("ok")),
        },
    )
    return {
        "tested": True,
        "probe_id": probe_id,
        "emails_sent": emails_sent,
        "email_errors": email_errors,
        "webhooks": webhook_results,
        "event_type": "gateway.jit.notify.test",
    }
