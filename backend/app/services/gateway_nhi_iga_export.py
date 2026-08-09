"""NHI inventory export + IGA/webhook delivery for complementary identity planes."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from typing import Any, Optional
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_NHI_IGA_EXPORT_JSON
from app.services.gateway_notification_delivery import http_post_with_retry
from app.services.runtime_config import get_runtime_config, upsert_runtime_config_value
from app.services.url_ssrf_guard import assert_webhook_url_safe_for_delivery, validate_outbound_webhook_url

ALLOWED_TARGET_SYSTEMS = frozenset(
    {"generic", "external_iga", "astrix", "oasis", "aembit"}
)
_LEGACY_TARGET_ALIASES = {"saviynt_zuma": "external_iga"}


def canonicalize_target_system(value: object) -> str:
    raw = str(value or "").strip().lower()
    return _LEGACY_TARGET_ALIASES.get(raw, raw)
ALLOWED_PROFILES = frozenset({"native", "iga_correlation"})

DEFAULT_CONFIG: dict[str, Any] = {
    "enabled": False,
    "target_system": "generic",
    "webhook_url": "",
    "hmac_secret": "",
    "sign_requests": True,
    "include_hygiene_summary": True,
    "default_profile": "iga_correlation",
    "max_records": 500,
}


def _clamp_max_records(value: object) -> int:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        parsed = 500
    return max(1, min(500, parsed))


def _validate_webhook_url(raw: str) -> str:
    return validate_outbound_webhook_url(raw, allow_empty=True, resolve_dns=False)


def normalize_config(raw: dict[str, Any] | None, *, reveal_secret: bool = False) -> dict[str, Any]:
    src = dict(DEFAULT_CONFIG)
    if isinstance(raw, dict):
        src.update(raw)
    target = canonicalize_target_system(src.get("target_system") or "generic") or "generic"
    if target not in ALLOWED_TARGET_SYSTEMS:
        raise HTTPException(
            status_code=422,
            detail=f"target_system must be one of: {', '.join(sorted(ALLOWED_TARGET_SYSTEMS))}",
        )
    profile = str(src.get("default_profile") or "iga_correlation").strip().lower() or "iga_correlation"
    if profile not in ALLOWED_PROFILES:
        raise HTTPException(
            status_code=422,
            detail=f"default_profile must be one of: {', '.join(sorted(ALLOWED_PROFILES))}",
        )
    from app.services.runtime_env import is_production_runtime

    secret = str(src.get("hmac_secret") or "")
    enabled = bool(src.get("enabled"))
    sign_requests = bool(src.get("sign_requests", True))
    if is_production_runtime() and enabled:
        sign_requests = True
        if not secret.strip():
            raise HTTPException(
                status_code=422,
                detail="hmac_secret is required when NHI IGA export is enabled in production",
            )
    out = {
        "enabled": enabled,
        "target_system": target,
        "webhook_url": _validate_webhook_url(str(src.get("webhook_url") or "")),
        "sign_requests": sign_requests,
        "include_hygiene_summary": bool(src.get("include_hygiene_summary", True)),
        "default_profile": profile,
        "max_records": _clamp_max_records(src.get("max_records")),
        "hmac_secret_configured": bool(secret.strip()),
    }
    if reveal_secret:
        out["hmac_secret"] = secret
    else:
        out["hmac_secret"] = ""
    return out


def load_nhi_iga_export_config(db: Session, *, reveal_secret: bool = False) -> dict[str, Any]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_NHI_IGA_EXPORT_JSON, "")
    parsed: dict[str, Any] = {}
    if raw.strip():
        try:
            loaded = json.loads(raw)
            if isinstance(loaded, dict):
                parsed = loaded
        except json.JSONDecodeError:
            parsed = {}
    return normalize_config(parsed, reveal_secret=reveal_secret)


def save_nhi_iga_export_config(db: Session, payload: dict[str, Any], *, actor_id: str) -> dict[str, Any]:
    current = load_nhi_iga_export_config(db, reveal_secret=True)
    incoming = dict(payload or {})
    # Preserve existing secret when client sends blank (mask round-trip).
    if not str(incoming.get("hmac_secret") or "").strip() and current.get("hmac_secret"):
        incoming["hmac_secret"] = current["hmac_secret"]
    normalized = normalize_config(incoming, reveal_secret=True)
    store = {
        "enabled": normalized["enabled"],
        "target_system": normalized["target_system"],
        "webhook_url": normalized["webhook_url"],
        "hmac_secret": str(normalized.get("hmac_secret") or ""),
        "sign_requests": normalized["sign_requests"],
        "include_hygiene_summary": normalized["include_hygiene_summary"],
        "default_profile": normalized["default_profile"],
        "max_records": normalized["max_records"],
        "updated_by": str(actor_id or "").strip() or "unknown",
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_GATEWAY_NHI_IGA_EXPORT_JSON,
        json.dumps(store, separators=(",", ":")),
        description="NHI IGA export webhook + correlation profile (GOV-AI-IDSEC-NHI-002)",
    )
    return normalize_config(store, reveal_secret=False)


def _record_to_dict(row: Any) -> dict[str, Any]:
    if hasattr(row, "model_dump"):
        data = row.model_dump()
    elif isinstance(row, dict):
        data = dict(row)
    else:
        data = {
            "nhi_record_id": getattr(row, "nhi_record_id", None),
            "source_type": getattr(row, "source_type", None),
            "source_id": getattr(row, "source_id", None),
            "identity_type": getattr(row, "identity_type", None),
            "tenant_id": getattr(row, "tenant_id", None),
            "environment": getattr(row, "environment", None),
            "provider_type": getattr(row, "provider_type", None),
            "owner_scope_type": getattr(row, "owner_scope_type", None),
            "owner_scope_id": getattr(row, "owner_scope_id", None),
            "credential_last_rotated_at": getattr(row, "credential_last_rotated_at", None),
            "credential_expires_at": getattr(row, "credential_expires_at", None),
            "last_used_at": getattr(row, "last_used_at", None),
            "findings": getattr(row, "findings", "[]"),
            "status": getattr(row, "status", None),
            "stale_credential": getattr(row, "stale_credential", False),
            "missing_owner": getattr(row, "missing_owner", False),
            "credential_age_days": getattr(row, "credential_age_days", None),
        }
    for key in ("credential_last_rotated_at", "credential_expires_at", "last_used_at"):
        value = data.get(key)
        if isinstance(value, datetime):
            data[key] = value.isoformat() + "Z"
    return data


def _iga_correlation_identity(record: dict[str, Any], *, target_system: str) -> dict[str, Any]:
    findings_raw = record.get("findings") or "[]"
    if isinstance(findings_raw, str):
        try:
            findings = json.loads(findings_raw)
        except json.JSONDecodeError:
            findings = []
    else:
        findings = list(findings_raw) if isinstance(findings_raw, list) else []
    owner = None
    if record.get("owner_scope_id"):
        owner = {
            "scope_type": record.get("owner_scope_type") or "unknown",
            "scope_id": record.get("owner_scope_id"),
        }
    risk_tier = "high" if ("high_risk" in findings or record.get("missing_owner")) else (
        "medium" if record.get("stale_credential") else "low"
    )
    return {
        "externalId": record.get("nhi_record_id"),
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User", "urn:guardbridge:params:nhi:1.0"],
        "userName": f"{record.get('source_type')}:{record.get('source_id')}",
        "displayName": f"gateway-nhi:{record.get('identity_type')}:{record.get('source_id')}",
        "active": str(record.get("status") or "").lower() == "active",
        "meta": {
            "resourceType": "GatewayNHI",
            "target_system_hint": target_system,
            "correlation_keys": {
                "nhi_record_id": record.get("nhi_record_id"),
                "source_type": record.get("source_type"),
                "source_id": record.get("source_id"),
                "tenant_id": record.get("tenant_id"),
                "environment": record.get("environment"),
                "provider_type": record.get("provider_type"),
                "external_ref": record.get("external_ref"),
                "iga_agent_id": record.get("iga_agent_id"),
            },
        },
        "urn:guardbridge:params:nhi:1.0": {
            "identity_type": record.get("identity_type"),
            "owner": owner,
            "findings": findings,
            "risk_tier": risk_tier,
            "stale_credential": bool(record.get("stale_credential")),
            "missing_owner": bool(record.get("missing_owner")),
            "credential_age_days": record.get("credential_age_days"),
            "credential_last_rotated_at": record.get("credential_last_rotated_at"),
            "credential_expires_at": record.get("credential_expires_at"),
            "last_used_at": record.get("last_used_at"),
            "external_ref": record.get("external_ref"),
            "iga_agent_id": record.get("iga_agent_id"),
            "correlation_source_system": record.get("correlation_source_system"),
            "plane": "inference_gateway",
            "complementary_to": "ai_identity_control_plane",
        },
    }


def build_nhi_export_bundle(
    *,
    records: list[Any],
    hygiene: Optional[dict[str, Any]] = None,
    profile: str = "iga_correlation",
    target_system: str = "generic",
    filters: Optional[dict[str, Any]] = None,
    actor_id: str = "unknown",
    include_hygiene_summary: bool = True,
) -> dict[str, Any]:
    norm_profile = str(profile or "iga_correlation").strip().lower() or "iga_correlation"
    if norm_profile not in ALLOWED_PROFILES:
        raise HTTPException(
            status_code=422,
            detail=f"profile must be one of: {', '.join(sorted(ALLOWED_PROFILES))}",
        )
    norm_target = canonicalize_target_system(target_system or "generic") or "generic"
    if norm_target not in ALLOWED_TARGET_SYSTEMS:
        raise HTTPException(
            status_code=422,
            detail=f"target_system must be one of: {', '.join(sorted(ALLOWED_TARGET_SYSTEMS))}",
        )

    native_records = [_record_to_dict(row) for row in records]
    # Optional IGA correlation enrichment from governance (NHI-005); caller may pre-set fields.
    for item in native_records:
        if "external_ref" not in item:
            item["external_ref"] = None
        if "iga_agent_id" not in item:
            item["iga_agent_id"] = None
    export_id = f"nhi-export-{uuid4().hex[:16]}"
    exported_at = datetime.utcnow().isoformat() + "Z"
    if norm_profile == "native":
        identities: list[dict[str, Any]] = native_records
    else:
        identities = [
            _iga_correlation_identity(row, target_system=norm_target) for row in native_records
        ]

    bundle: dict[str, Any] = {
        "export_id": export_id,
        "exported_at": exported_at,
        "export_uri": f"evidence://gateway/nhi/{export_id}.json",
        "schema_version": "guardbridge.nhi.iga_export.v1",
        "profile": norm_profile,
        "target_system": norm_target,
        "plane": "inference_gateway",
        "integration_intent": "complementary_correlation",
        "exported_by": str(actor_id or "unknown"),
        "filters": dict(filters or {}),
        "record_count": len(identities),
        "identities": identities,
        "correlation_guide": {
            "match_on": [
                "meta.correlation_keys.nhi_record_id",
                "meta.correlation_keys.source_id",
                "meta.correlation_keys.external_ref",
                "meta.correlation_keys.iga_agent_id",
            ],
            "owner_field": "urn:guardbridge:params:nhi:1.0.owner",
            "risk_field": "urn:guardbridge:params:nhi:1.0.risk_tier",
            "notes": (
                "Correlate gateway NHIs (virtual keys / WIF / secret providers) with "
                "enterprise AI identity / IGA planes. Set external_ref / "
                "iga_agent_id via PUT /gateway/nhi/{id}/correlation. This export does not "
                "replace IGA discovery or intent-aware app authorization."
            ),
        },
    }
    if include_hygiene_summary and hygiene is not None:
        bundle["hygiene_summary"] = hygiene
    return bundle


def sign_export_body(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def deliver_nhi_export_webhook(
    db: Session,
    *,
    bundle: dict[str, Any],
    dry_run: bool = False,
    post_fn=None,
) -> dict[str, Any]:
    config = load_nhi_iga_export_config(db, reveal_secret=True)
    if not config.get("enabled") and not dry_run:
        raise HTTPException(status_code=400, detail="NHI IGA export webhook is disabled")
    webhook_url = str(config.get("webhook_url") or "").strip()
    if not webhook_url:
        raise HTTPException(status_code=400, detail="webhook_url is not configured")

    delivery_id = f"nhi-del-{uuid4().hex[:12]}"
    payload = {
        "event_type": "gateway.nhi.iga_export",
        "delivery_id": delivery_id,
        "bundle": bundle,
    }
    body_bytes = json.dumps(payload, separators=(",", ":"), default=str).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "X-Gateway-Event-Type": "gateway.nhi.iga_export",
        "X-Gateway-Delivery-Id": delivery_id,
        "X-Gateway-Export-Id": str(bundle.get("export_id") or ""),
    }
    secret = str(config.get("hmac_secret") or "")
    if config.get("sign_requests"):
        if not secret.strip():
            raise HTTPException(
                status_code=422,
                detail="hmac_secret is required when sign_requests=true for NHI IGA export delivery",
            )
        headers["X-Gateway-Nhi-Signature"] = sign_export_body(secret, body_bytes)

    if dry_run:
        return {
            "delivery_id": delivery_id,
            "delivery_status": "delivered_simulated",
            "webhook_url": webhook_url,
            "signed": bool(headers.get("X-Gateway-Nhi-Signature")),
            "record_count": int(bundle.get("record_count") or 0),
            "attempts": 0,
        }

    def _post_signed(url: str, **kwargs: Any):
        if post_fn is not None:
            # Tests inject post_fn; still enforce SSRF validation before call.
            assert_webhook_url_safe_for_delivery(url)
            return post_fn(url, content=body_bytes, headers=headers, timeout=kwargs.get("timeout", 20.0))
        from app.services.pinned_outbound_http import pinned_httpx_compatible_post

        return pinned_httpx_compatible_post(
            url,
            content=body_bytes,
            headers=headers,
            timeout=float(kwargs.get("timeout", 20.0)),
        )

    response, attempts = http_post_with_retry(
        url=webhook_url,
        headers=headers,
        timeout=20.0,
        max_retries=1,
        backoff_seconds=0.2,
        post_fn=_post_signed,
    )

    status = int(getattr(response, "status_code", 0) or 0)
    ok = 200 <= status < 300
    return {
        "delivery_id": delivery_id,
        "delivery_status": "delivered" if ok else "failed",
        "http_status": status,
        "webhook_url": webhook_url,
        "signed": bool(headers.get("X-Gateway-Nhi-Signature")),
        "record_count": int(bundle.get("record_count") or 0),
        "attempts": attempts,
        "error": None if ok else f"HTTP {status}: {str(getattr(response, 'text', '') or '')[:256]}",
    }
