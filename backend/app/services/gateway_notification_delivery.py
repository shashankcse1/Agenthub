from __future__ import annotations

import base64
import json
import re
import threading
import time
from collections import defaultdict, deque
from typing import Any, Optional
from urllib.parse import urlparse
from uuid import uuid4

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.runtime_constants import (
    RUNTIME_CONFIG_GATEWAY_NOTIFICATION_MAX_RETRIES,
    RUNTIME_CONFIG_GATEWAY_NOTIFICATION_MAX_SENDS_PER_CHANNEL_PER_MINUTE,
    RUNTIME_CONFIG_GATEWAY_NOTIFICATION_RETRY_BACKOFF_MS,
)
from app.services.credential_resolution import load_active_binding_by_id, resolve_binding_for_runtime
from app.services.gateway_notification_channels import get_notification_channel_by_id
from app.services.runtime_config import get_runtime_config_int

E164_PATTERN = re.compile(r"^\+[1-9]\d{1,14}$")

_RATE_LOCK = threading.Lock()
_RATE_WINDOWS: dict[str, deque[float]] = defaultdict(deque)
_DEFAULT_MAX_SENDS_PER_MINUTE = 30
_DEFAULT_MAX_RETRIES = 2
_DEFAULT_RETRY_BACKOFF_MS = 200
_RETRYABLE_STATUS = {408, 429, 500, 502, 503, 504}


def _enforce_channel_rate_limit(db: Session, channel_id: str) -> None:
    """Per-channel send rate limit (closes RSK-019 vs n8n/Make notify abuse)."""
    normalized = str(channel_id or "").strip()
    if not normalized:
        return
    max_per_minute = get_runtime_config_int(
        db,
        RUNTIME_CONFIG_GATEWAY_NOTIFICATION_MAX_SENDS_PER_CHANNEL_PER_MINUTE,
        _DEFAULT_MAX_SENDS_PER_MINUTE,
    )
    max_per_minute = max(1, min(1000, int(max_per_minute or _DEFAULT_MAX_SENDS_PER_MINUTE)))
    now = time.time()
    window_start = now - 60.0
    with _RATE_LOCK:
        bucket = _RATE_WINDOWS[normalized]
        while bucket and bucket[0] < window_start:
            bucket.popleft()
        if len(bucket) >= max_per_minute:
            raise HTTPException(
                status_code=429,
                detail=(
                    f"Notification channel '{normalized}' exceeded "
                    f"{max_per_minute} sends/minute (gateway.notification.max_sends_per_channel_per_minute)"
                ),
            )
        bucket.append(now)


def _extract_email_domain(address: str) -> str:
    normalized = str(address or "").strip().lower()
    if "@" not in normalized:
        raise HTTPException(status_code=422, detail="Email recipient must contain @")
    return normalized.rsplit("@", 1)[1]


def _enforce_email_domain_allowlist(channel: dict[str, Any], to_address: str) -> None:
    allowlist = channel.get("default_recipient_domain_allowlist") or []
    if not allowlist:
        return
    domain = _extract_email_domain(to_address)
    allowed = {str(item).strip().lower() for item in allowlist if str(item).strip()}
    if domain not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Recipient domain '{domain}' is not in channel allowlist",
        )


def _enforce_sms_recipient(to_number: str) -> None:
    normalized = str(to_number or "").strip()
    if not E164_PATTERN.match(normalized):
        raise HTTPException(
            status_code=422,
            detail="SMS recipient must be E.164 format (e.g. +15551234567)",
        )


def _resolve_channel_credentials(db: Session, channel: dict[str, Any]) -> str:
    binding_id = str(channel.get("credential_binding_id") or "").strip()
    if not binding_id:
        raise HTTPException(status_code=422, detail="Notification channel credential_binding_id is required")
    binding = load_active_binding_by_id(db, binding_id)
    resolved = resolve_binding_for_runtime(db, binding)
    secret = str(resolved.secret_value or "").strip()
    if not secret:
        raise HTTPException(status_code=503, detail="Notification channel credential is empty")
    return secret


def _provider_base_url(channel: dict[str, Any], default: str) -> str:
    configured = str(channel.get("api_base_url") or "").strip()
    if configured:
        return configured.rstrip("/")
    return default.rstrip("/")


def _delivery_result(
    *,
    provider_type: str,
    channel_id: str,
    delivery_status: str,
    receipt_id: Optional[str] = None,
    error: Optional[str] = None,
    attempts: int = 1,
    retry_count: int = 0,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "live": True,
        "simulated": False,
        "delivery_status": delivery_status,
        "provider_type": provider_type,
        "channel_id": channel_id,
        "receipt_id": receipt_id or f"receipt-{uuid4().hex[:12]}",
        "attempts": max(1, int(attempts)),
        "retry_count": max(0, int(retry_count)),
    }
    if error:
        payload["error"] = error
    return payload


def _retry_policy(db: Optional[Session] = None) -> tuple[int, float]:
    """Return (max_retries, backoff_seconds) for outbound notification adapters."""
    if db is None:
        max_retries = _DEFAULT_MAX_RETRIES
        backoff_ms = _DEFAULT_RETRY_BACKOFF_MS
    else:
        max_retries = get_runtime_config_int(
            db, RUNTIME_CONFIG_GATEWAY_NOTIFICATION_MAX_RETRIES, _DEFAULT_MAX_RETRIES
        )
        backoff_ms = get_runtime_config_int(
            db, RUNTIME_CONFIG_GATEWAY_NOTIFICATION_RETRY_BACKOFF_MS, _DEFAULT_RETRY_BACKOFF_MS
        )
    max_retries = max(0, min(5, int(max_retries or 0)))
    backoff_ms = max(0, min(5000, int(backoff_ms or 0)))
    return max_retries, backoff_ms / 1000.0


def http_post_with_retry(
    *,
    url: str,
    headers: dict[str, str],
    max_retries: int = _DEFAULT_MAX_RETRIES,
    backoff_seconds: float = _DEFAULT_RETRY_BACKOFF_MS / 1000.0,
    json_body: Optional[dict[str, Any]] = None,
    data: Optional[dict[str, str]] = None,
    timeout: float = 30.0,
    sleep_fn=time.sleep,
    post_fn=None,
) -> tuple[Any, int]:
    """
    POST with bounded retries for transient provider failures.
    Returns (response, attempts). Does not raise on HTTP 4xx/5xx — caller inspects status.
    """
    post = post_fn or httpx.post
    attempts = 0
    last_response = None
    last_exc: Optional[Exception] = None
    total_tries = max(1, int(max_retries) + 1)
    for attempt_idx in range(total_tries):
        attempts += 1
        try:
            kwargs: dict[str, Any] = {"headers": headers, "timeout": timeout}
            if json_body is not None:
                kwargs["json"] = json_body
            if data is not None:
                kwargs["data"] = data
            last_response = post(url, **kwargs)
            last_exc = None
            status = int(getattr(last_response, "status_code", 0) or 0)
            if status < 400 or status not in _RETRYABLE_STATUS or attempt_idx >= total_tries - 1:
                return last_response, attempts
        except (httpx.TimeoutException, httpx.TransportError, httpx.HTTPError) as exc:
            last_exc = exc
            if attempt_idx >= total_tries - 1:
                break
        if backoff_seconds > 0:
            sleep_fn(backoff_seconds * (attempt_idx + 1))
    if last_response is not None:
        return last_response, attempts
    raise HTTPException(
        status_code=503,
        detail=f"Notification provider unreachable after {attempts} attempt(s): {last_exc}",
    )


def _send_sendgrid_email(
    *,
    channel: dict[str, Any],
    secret: str,
    to_address: str,
    subject: str,
    body: str,
    from_address: str,
    max_retries: int = _DEFAULT_MAX_RETRIES,
    backoff_seconds: float = _DEFAULT_RETRY_BACKOFF_MS / 1000.0,
) -> dict[str, Any]:
    base_url = _provider_base_url(channel, "https://api.sendgrid.com")
    url = f"{base_url}/v3/mail/send"
    payload = {
        "personalizations": [{"to": [{"email": to_address}]}],
        "from": {"email": from_address},
        "subject": subject,
        "content": [{"type": "text/plain", "value": body}],
    }
    headers = {"Authorization": f"Bearer {secret}", "Content-Type": "application/json"}
    response, attempts = http_post_with_retry(
        url=url,
        headers=headers,
        json_body=payload,
        max_retries=max_retries,
        backoff_seconds=backoff_seconds,
    )
    if response.status_code >= 400:
        return _delivery_result(
            provider_type="sendgrid",
            channel_id=channel["channel_id"],
            delivery_status="failed",
            error=f"SendGrid HTTP {response.status_code}: {response.text[:512]}",
            attempts=attempts,
            retry_count=max(0, attempts - 1),
        )
    receipt_id = response.headers.get("X-Message-Id") or f"sg-{uuid4().hex[:12]}"
    return _delivery_result(
        provider_type="sendgrid",
        channel_id=channel["channel_id"],
        delivery_status="sent",
        receipt_id=receipt_id,
        attempts=attempts,
        retry_count=max(0, attempts - 1),
    )


def _send_twilio_sms(
    *,
    channel: dict[str, Any],
    secret: str,
    to_number: str,
    body: str,
    from_number: str,
    max_retries: int = _DEFAULT_MAX_RETRIES,
    backoff_seconds: float = _DEFAULT_RETRY_BACKOFF_MS / 1000.0,
) -> dict[str, Any]:
    try:
        credentials = json.loads(secret)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=422,
            detail='Twilio credentials must be JSON: {"username":"AC...","password":"..."}',
        ) from exc
    if not isinstance(credentials, dict):
        raise HTTPException(status_code=422, detail="Twilio credentials must be a JSON object")
    username = str(credentials.get("username") or "").strip()
    password = str(credentials.get("password") or "").strip()
    if not username or not password:
        raise HTTPException(status_code=422, detail="Twilio credentials require username and password")

    base_url = _provider_base_url(channel, "https://api.twilio.com")
    url = f"{base_url}/2010-04-01/Accounts/{username}/Messages.json"
    auth = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    headers = {"Authorization": f"Basic {auth}", "Content-Type": "application/x-www-form-urlencoded"}
    data = {"To": to_number, "From": from_number, "Body": body}
    response, attempts = http_post_with_retry(
        url=url,
        headers=headers,
        data=data,
        max_retries=max_retries,
        backoff_seconds=backoff_seconds,
    )
    if response.status_code >= 400:
        return _delivery_result(
            provider_type="twilio",
            channel_id=channel["channel_id"],
            delivery_status="failed",
            error=f"Twilio HTTP {response.status_code}: {response.text[:512]}",
            attempts=attempts,
            retry_count=max(0, attempts - 1),
        )
    receipt_id = None
    try:
        receipt_id = str(response.json().get("sid") or "")
    except Exception:
        receipt_id = None
    return _delivery_result(
        provider_type="twilio",
        channel_id=channel["channel_id"],
        delivery_status="sent",
        receipt_id=receipt_id,
        attempts=attempts,
        retry_count=max(0, attempts - 1),
    )


def _send_http_webhook(
    *,
    channel: dict[str, Any],
    secret: str,
    provider_type: str,
    payload: dict[str, Any],
    max_retries: int = _DEFAULT_MAX_RETRIES,
    backoff_seconds: float = _DEFAULT_RETRY_BACKOFF_MS / 1000.0,
) -> dict[str, Any]:
    url = str(channel.get("api_base_url") or "").strip()
    if not url:
        raise HTTPException(status_code=422, detail=f"{provider_type} channel requires api_base_url")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=422, detail=f"{provider_type} api_base_url must be http(s)")
    headers = {"Authorization": f"Bearer {secret}", "Content-Type": "application/json"}
    response, attempts = http_post_with_retry(
        url=url,
        headers=headers,
        json_body=payload,
        max_retries=max_retries,
        backoff_seconds=backoff_seconds,
    )
    if response.status_code >= 400:
        return _delivery_result(
            provider_type=provider_type,
            channel_id=channel["channel_id"],
            delivery_status="failed",
            error=f"{provider_type} HTTP {response.status_code}: {response.text[:512]}",
            attempts=attempts,
            retry_count=max(0, attempts - 1),
        )
    return _delivery_result(
        provider_type=provider_type,
        channel_id=channel["channel_id"],
        delivery_status="sent",
        attempts=attempts,
        retry_count=max(0, attempts - 1),
    )


def deliver_email(
    db: Session,
    *,
    channel_id: str,
    to: str,
    subject: str,
    body: str,
    from_override: Optional[str] = None,
) -> dict[str, Any]:
    channel = get_notification_channel_by_id(db, channel_id)
    if not channel.get("enabled"):
        raise HTTPException(status_code=403, detail="Notification channel is disabled")
    _enforce_channel_rate_limit(db, channel_id)

    to_address = str(to or "").strip()
    if not to_address:
        raise HTTPException(status_code=422, detail="Email recipient is required")
    _enforce_email_domain_allowlist(channel, to_address)

    from_address = str(from_override or channel.get("from_address") or "").strip()
    if not from_address:
        raise HTTPException(status_code=422, detail="Email from address is required")

    provider_type = str(channel.get("provider_type") or "").strip().lower()
    secret = _resolve_channel_credentials(db, channel)
    max_retries, backoff_seconds = _retry_policy(db)

    if provider_type == "sendgrid":
        return _send_sendgrid_email(
            channel=channel,
            secret=secret,
            to_address=to_address,
            subject=str(subject or ""),
            body=str(body or ""),
            from_address=from_address,
            max_retries=max_retries,
            backoff_seconds=backoff_seconds,
        )
    if provider_type in {"smtp_webhook", "generic_http"}:
        return _send_http_webhook(
            channel=channel,
            secret=secret,
            provider_type=provider_type,
            payload={"to": to_address, "subject": str(subject or ""), "body": str(body or ""), "from": from_address},
            max_retries=max_retries,
            backoff_seconds=backoff_seconds,
        )
    raise HTTPException(status_code=422, detail=f"Provider type '{provider_type}' does not support email delivery")


def deliver_sms(
    db: Session,
    *,
    channel_id: str,
    to: str,
    body: str,
    from_override: Optional[str] = None,
) -> dict[str, Any]:
    channel = get_notification_channel_by_id(db, channel_id)
    if not channel.get("enabled"):
        raise HTTPException(status_code=403, detail="Notification channel is disabled")
    _enforce_channel_rate_limit(db, channel_id)

    to_number = str(to or "").strip()
    _enforce_sms_recipient(to_number)

    from_number = str(from_override or channel.get("from_address") or "").strip()
    if not from_number:
        raise HTTPException(status_code=422, detail="SMS from number is required")
    if not E164_PATTERN.match(from_number):
        raise HTTPException(status_code=422, detail="SMS from number must be E.164 format")

    provider_type = str(channel.get("provider_type") or "").strip().lower()
    secret = _resolve_channel_credentials(db, channel)
    max_retries, backoff_seconds = _retry_policy(db)

    if provider_type == "twilio":
        return _send_twilio_sms(
            channel=channel,
            secret=secret,
            to_number=to_number,
            body=str(body or ""),
            from_number=from_number,
            max_retries=max_retries,
            backoff_seconds=backoff_seconds,
        )
    if provider_type in {"smtp_webhook", "generic_http"}:
        return _send_http_webhook(
            channel=channel,
            secret=secret,
            provider_type=provider_type,
            payload={"to": to_number, "body": str(body or ""), "from": from_number},
            max_retries=max_retries,
            backoff_seconds=backoff_seconds,
        )
    raise HTTPException(status_code=422, detail=f"Provider type '{provider_type}' does not support SMS delivery")
