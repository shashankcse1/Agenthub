from __future__ import annotations

import json
import re
from typing import Any, Optional
from urllib.parse import urlparse

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_NOTIFICATION_CHANNELS_JSON
from app.services.runtime_config import get_runtime_config

ALLOWED_NOTIFICATION_PROVIDER_TYPES = {
    "sendgrid",
    "twilio",
    "smtp_webhook",
    "generic_http",
}

# Canonical secret paths — store values in Providers secret backend, reference via credential_binding_id only.
NOTIFICATION_PROVIDER_SECRET_REFS: dict[str, str] = {
    "sendgrid": "providers/sendgrid/api-key",
    "twilio": "providers/twilio/credentials",
    "smtp_webhook": "providers/notifications/smtp-webhook-token",
    "generic_http": "providers/notifications/http-bearer",
}

NOTIFICATION_PROVIDER_SECRET_FORMAT_HINTS: dict[str, str] = {
    "sendgrid": "Plain SendGrid API key (SG…)",
    "twilio": 'JSON for HTTP Basic auth: {"username":"ACxxxxxxxx","password":"your_auth_token"}',
    "smtp_webhook": "Bearer token or shared secret for SMTP relay webhook",
    "generic_http": "Bearer token or API key string for generic HTTP notification adapter",
}

ALLOWED_CHANNEL_ENVIRONMENTS = {"dev", "staging", "prod"}

INLINE_SECRET_FIELD_NAMES = frozenset(
    {"api_key", "api_key_secret", "password", "token", "secret", "credentials", "auth_token"}
)

RECIPIENT_SECRET_VALUE_PATTERN = re.compile(
    r"(?:^|\s)(?:sk-[a-z0-9]{10,}|bearer\s+[a-z0-9._-]{10,}|api[_-]?key\s*[:=])",
    re.IGNORECASE,
)


def _validate_recipient_domain(domain: str) -> bool:
    normalized = str(domain or "").strip().lower()
    if not normalized or len(normalized) > 253:
        return False
    if normalized.startswith(".") or normalized.endswith("."):
        return False
    return bool(re.match(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$", normalized))


def _validate_channel_record(record: dict, idx: int) -> tuple[bool, str]:
    channel_id = str(record.get("channel_id") or "").strip()
    provider_type = str(record.get("provider_type") or "").strip().lower()
    environment = str(record.get("environment") or "dev").strip().lower()
    credential_binding_id = str(record.get("credential_binding_id") or "").strip()
    api_base_url = str(record.get("api_base_url") or "").strip()
    from_address = str(record.get("from_address") or "").strip()

    for forbidden in INLINE_SECRET_FIELD_NAMES:
        if record.get(forbidden):
            return (
                False,
                f"gateway.notification_channels_json[{idx}] inline {forbidden} is not allowed; use credential_binding_id",
            )

    if not channel_id:
        return False, f"gateway.notification_channels_json[{idx}] missing channel_id"
    if not re.match(r"^[a-z0-9][a-z0-9._-]{0,127}$", channel_id):
        return False, f"gateway.notification_channels_json[{idx}] channel_id must be lowercase alphanumeric with ._-"

    if provider_type not in ALLOWED_NOTIFICATION_PROVIDER_TYPES:
        return (
            False,
            f"gateway.notification_channels_json[{idx}] unsupported provider_type "
            f"(allowed: {', '.join(sorted(ALLOWED_NOTIFICATION_PROVIDER_TYPES))})",
        )

    if environment not in ALLOWED_CHANNEL_ENVIRONMENTS:
        return (
            False,
            f"gateway.notification_channels_json[{idx}] environment must be dev, staging, or prod",
        )

    enabled = record.get("enabled", True)
    if not isinstance(enabled, bool):
        return False, f"gateway.notification_channels_json[{idx}] enabled must be boolean"

    allowlist = record.get("default_recipient_domain_allowlist")
    if allowlist is None:
        allowlist = []
    if not isinstance(allowlist, list):
        return False, f"gateway.notification_channels_json[{idx}] default_recipient_domain_allowlist must be an array"
    for domain_idx, domain in enumerate(allowlist):
        if not _validate_recipient_domain(str(domain)):
            return (
                False,
                f"gateway.notification_channels_json[{idx}] invalid domain at allowlist[{domain_idx}]",
            )

    metadata = record.get("metadata")
    if metadata is not None and not isinstance(metadata, dict):
        return False, f"gateway.notification_channels_json[{idx}] metadata must be a JSON object"

    if api_base_url:
        parsed = urlparse(api_base_url)
        if parsed.scheme not in {"http", "https"} or not parsed.netloc:
            return False, f"gateway.notification_channels_json[{idx}] api_base_url must be a valid http(s) URL"

    if enabled and not credential_binding_id:
        return (
            False,
            f"gateway.notification_channels_json[{idx}] credential_binding_id is required for enabled channels",
        )

    if provider_type in {"sendgrid", "smtp_webhook"} and enabled and not from_address:
        return (
            False,
            f"gateway.notification_channels_json[{idx}] from_address is required for enabled {provider_type} channels",
        )

    if provider_type == "twilio" and enabled and not from_address:
        return (
            False,
            f"gateway.notification_channels_json[{idx}] from_address is required for enabled twilio channels "
            "(E.164 sender phone number, e.g. +15551234567)",
        )

    return True, ""


def validate_notification_channels_json(raw: str) -> Optional[str]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return "gateway.notification_channels_json must be valid JSON"

    if not isinstance(parsed, list):
        return "gateway.notification_channels_json must be a JSON array"

    seen: set[str] = set()
    for idx, item in enumerate(parsed):
        if not isinstance(item, dict):
            return f"gateway.notification_channels_json[{idx}] must be a JSON object"
        valid, error = _validate_channel_record(item, idx)
        if not valid:
            return error
        channel_id = str(item.get("channel_id") or "").strip()
        if channel_id in seen:
            return f"gateway.notification_channels_json duplicate channel_id: {channel_id}"
        seen.add(channel_id)

    return None


def parse_notification_channels_json(raw: str) -> list[dict]:
    try:
        parsed = json.loads(raw or "[]")
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=500, detail="Invalid gateway.notification_channels_json runtime config"
        ) from exc
    if not isinstance(parsed, list):
        raise HTTPException(status_code=500, detail="gateway.notification_channels_json must be a JSON array")
    return [item for item in parsed if isinstance(item, dict)]


def _serialize_channel_item(item: dict) -> dict:
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    allowlist = item.get("default_recipient_domain_allowlist")
    if not isinstance(allowlist, list):
        allowlist = []
    return {
        "channel_id": str(item.get("channel_id") or "").strip(),
        "provider_type": str(item.get("provider_type") or "").strip().lower(),
        "enabled": bool(item.get("enabled", True)),
        "environment": str(item.get("environment") or "dev").strip().lower(),
        "from_address": str(item.get("from_address") or "").strip() or None,
        "default_recipient_domain_allowlist": [str(d).strip().lower() for d in allowlist if str(d).strip()],
        "credential_binding_id": str(item.get("credential_binding_id") or "").strip() or None,
        "api_base_url": str(item.get("api_base_url") or "").strip() or None,
        "metadata": metadata,
    }


def list_notification_channels(db: Session, *, enabled_only: bool = False) -> list[dict]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_NOTIFICATION_CHANNELS_JSON, "[]")
    channels = parse_notification_channels_json(raw)
    serialized = [_serialize_channel_item(item) for item in channels]
    if enabled_only:
        return [row for row in serialized if row.get("enabled")]
    return serialized


def get_notification_channel_by_id(db: Session, channel_id: str) -> dict:
    normalized = str(channel_id or "").strip()
    for channel in list_notification_channels(db):
        if channel["channel_id"] == normalized:
            return channel
    raise HTTPException(status_code=404, detail="Notification channel not found")


def notification_channel_exists_and_enabled(db: Session, channel_id: str) -> bool:
    normalized = str(channel_id or "").strip()
    if not normalized:
        return False
    for channel in list_notification_channels(db):
        if channel["channel_id"] == normalized and channel.get("enabled"):
            return bool(channel.get("credential_binding_id"))
    return False


def validate_recipient_template(template: str, *, field_name: str = "to_template") -> Optional[str]:
    value = str(template or "").strip()
    if not value:
        return None
    if RECIPIENT_SECRET_VALUE_PATTERN.search(value):
        return f"{field_name} must not contain inline secret or token material"
    lowered = value.lower()
    if lowered.startswith("sk-") or lowered.startswith("bearer "):
        return f"{field_name} must not contain inline secret or token material"
    return None


def build_notification_channel_context(db: Session, channel_id: str) -> dict:
    channel = get_notification_channel_by_id(db, channel_id)
    binding_configured = bool(channel.get("credential_binding_id"))
    posture = "configured" if channel.get("enabled") and binding_configured else "misconfigured"
    if not channel.get("enabled"):
        posture = "disabled"
    return {
        "channel": channel,
        "posture": posture,
        "credential_binding_configured": binding_configured,
        "recommended_secret_ref": NOTIFICATION_PROVIDER_SECRET_REFS.get(channel.get("provider_type") or ""),
        "secret_format_hint": NOTIFICATION_PROVIDER_SECRET_FORMAT_HINTS.get(channel.get("provider_type") or ""),
        "phase_1_runtime": "live_delivery_enabled",
        "operator_note": (
            "Store provider secrets in Providers → Database Secret Values at the recommended_secret_ref path, "
            "then create a credential binding (consumer platform/gateway) and reference its binding_id here. "
            "Never put Auth Tokens or API keys in gateway.notification_channels_json or flow JSON. "
            "Flow Orchestration email_send/sms_send nodes deliver via configured channels when the live executor is enabled."
        ),
        "supported_provider_types": sorted(ALLOWED_NOTIFICATION_PROVIDER_TYPES),
    }
