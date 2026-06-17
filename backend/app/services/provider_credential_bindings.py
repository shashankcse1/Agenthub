from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import (
    ProviderCredentialBinding,
    RuntimeConfig,
    SecretProviderConfig,
    WorkloadIdentityFederationProfile,
)
from app.services.secret_provider_values import (
    is_db_secret_provider,
    mask_secret_hint,
    read_db_secret_provider_value,
)
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN
from app.services.runtime_config import invalidate_runtime_config_cache

GATEWAY_CURSOR_SECRET_BINDING_VERSION = "v3"

CREDENTIAL_PLANE_SECRET_REF = "secret_ref"
CREDENTIAL_PLANE_WORKLOAD_IDENTITY = "workload_identity"
CREDENTIAL_PLANES = {CREDENTIAL_PLANE_SECRET_REF, CREDENTIAL_PLANE_WORKLOAD_IDENTITY}

CONSUMER_TYPES = {"gateway", "agent", "route", "platform"}
CREDENTIAL_SOURCE_CLASSES = {"cp_ref", "cp_wif", "cp_env", ""}


def normalize_credential_plane(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in CREDENTIAL_PLANES:
        raise HTTPException(
            status_code=422,
            detail="credential_plane must be one of: secret_ref, workload_identity",
        )
    return normalized


def normalize_consumer_type(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized not in CONSUMER_TYPES:
        raise HTTPException(
            status_code=422,
            detail="consumer_type must be one of: gateway, agent, route, platform",
        )
    return normalized


def normalize_credential_source_class(value: str | None) -> str:
    normalized = str(value or "").strip().lower()
    if normalized and normalized not in CREDENTIAL_SOURCE_CLASSES:
        raise HTTPException(
            status_code=422,
            detail="credential_source_class must be one of: cp_ref, cp_wif, cp_env",
        )
    return normalized


def _require_active_secret_provider(db: Session, secret_provider_id: str) -> SecretProviderConfig:
    provider = db.query(SecretProviderConfig).filter_by(secret_provider_id=secret_provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Secret provider not found")
    if str(provider.status or "").strip().lower() != "active":
        raise HTTPException(status_code=400, detail="Secret provider is not active")
    return provider


def _require_active_workload_profile(db: Session, profile_id: str, tenant_id: str) -> WorkloadIdentityFederationProfile:
    profile = (
        db.query(WorkloadIdentityFederationProfile)
        .filter_by(workload_identity_profile_id=profile_id)
        .first()
    )
    if not profile:
        raise HTTPException(status_code=404, detail="Workload identity profile not found")
    if str(profile.status or "").strip().lower() != "active":
        raise HTTPException(status_code=400, detail="Workload identity profile is not active")
    if str(profile.tenant_id or "").strip() != tenant_id:
        raise HTTPException(status_code=403, detail="Workload identity profile tenant scope mismatch")
    return profile


def validate_binding_references(
    db: Session,
    *,
    tenant_id: str,
    credential_plane: str,
    provider_type: str,
    secret_provider_id: str | None,
    secret_ref: str | None,
    workload_identity_profile_id: str | None,
) -> None:
    normalized_plane = normalize_credential_plane(credential_plane)
    normalized_provider_type = str(provider_type or "").strip().lower()
    if not normalized_provider_type:
        raise HTTPException(status_code=422, detail="provider_type is required")

    if normalized_plane == CREDENTIAL_PLANE_SECRET_REF:
        provider_id = str(secret_provider_id or "").strip()
        ref = str(secret_ref or "").strip()
        if not provider_id:
            raise HTTPException(status_code=422, detail="secret_provider_id is required for secret_ref plane")
        if not ref:
            raise HTTPException(status_code=422, detail="secret_ref is required for secret_ref plane")
        provider = _require_active_secret_provider(db, provider_id)
        if str(provider.tenant_id or "").strip() != tenant_id:
            raise HTTPException(status_code=403, detail="Secret provider tenant scope mismatch")
        return

    profile_id = str(workload_identity_profile_id or "").strip()
    if not profile_id:
        raise HTTPException(status_code=422, detail="workload_identity_profile_id is required for workload_identity plane")
    profile = _require_active_workload_profile(db, profile_id, tenant_id)
    if str(profile.provider_type or "").strip().lower() != normalized_provider_type:
        raise HTTPException(status_code=422, detail="workload identity provider_type must match binding provider_type")


def binding_masked_hint(db: Session, binding: ProviderCredentialBinding) -> str | None:
    plane = str(binding.credential_plane or "").strip().lower()
    if plane == CREDENTIAL_PLANE_WORKLOAD_IDENTITY:
        profile_id = str(binding.workload_identity_profile_id or "").strip()
        return f"wif:{profile_id[:4]}***{profile_id[-4:]}" if len(profile_id) > 8 else "wif:***"

    provider_id = str(binding.secret_provider_id or "").strip()
    secret_ref = str(binding.secret_ref or "").strip()
    if not provider_id or not secret_ref:
        return None

    provider = db.query(SecretProviderConfig).filter_by(secret_provider_id=provider_id).first()
    if not provider:
        return None

    if is_db_secret_provider(provider.provider_type):
        try:
            return mask_secret_hint(read_db_secret_provider_value(db, provider, secret_ref))
        except HTTPException:
            return None

    if len(secret_ref) <= 6:
        return "***"
    return f"{secret_ref[:3]}***{secret_ref[-3:]}"


def binding_configured(db: Session, binding: ProviderCredentialBinding) -> bool:
    plane = str(binding.credential_plane or "").strip().lower()
    if plane == CREDENTIAL_PLANE_WORKLOAD_IDENTITY:
        profile_id = str(binding.workload_identity_profile_id or "").strip()
        if not profile_id:
            return False
        profile = db.query(WorkloadIdentityFederationProfile).filter_by(workload_identity_profile_id=profile_id).first()
        return bool(profile and str(profile.status or "").strip().lower() == "active")

    provider_id = str(binding.secret_provider_id or "").strip()
    secret_ref = str(binding.secret_ref or "").strip()
    if not provider_id or not secret_ref:
        return False
    provider = db.query(SecretProviderConfig).filter_by(secret_provider_id=provider_id).first()
    if not provider or str(provider.status or "").strip().lower() != "active":
        return False
    if is_db_secret_provider(provider.provider_type):
        try:
            read_db_secret_provider_value(db, provider, secret_ref)
            return True
        except HTTPException:
            return False
    return True


def serialize_binding(db: Session, binding: ProviderCredentialBinding) -> dict:
    return {
        "binding_id": binding.binding_id,
        "tenant_id": binding.tenant_id,
        "binding_name": binding.binding_name,
        "consumer_type": binding.consumer_type,
        "consumer_key": binding.consumer_key,
        "provider_type": binding.provider_type,
        "credential_plane": binding.credential_plane,
        "secret_provider_id": binding.secret_provider_id,
        "secret_ref": binding.secret_ref,
        "workload_identity_profile_id": binding.workload_identity_profile_id,
        "environment": binding.environment,
        "status": binding.status,
        "configured": binding_configured(db, binding),
        "masked_hint": binding_masked_hint(db, binding),
        "updated_by": binding.updated_by,
        "created_at": binding.created_at,
        "updated_at": binding.updated_at,
    }


def upsert_provider_credential_binding(
    db: Session,
    *,
    binding_id: str | None,
    tenant_id: str,
    binding_name: str,
    consumer_type: str,
    consumer_key: str,
    provider_type: str,
    credential_plane: str,
    secret_provider_id: str | None,
    secret_ref: str | None,
    workload_identity_profile_id: str | None,
    environment: str,
    status: str,
    actor_id: str,
) -> ProviderCredentialBinding:
    normalized_tenant_id = str(tenant_id or "").strip()
    normalized_consumer_type = normalize_consumer_type(consumer_type)
    normalized_consumer_key = str(consumer_key or "").strip()
    normalized_binding_name = str(binding_name or "").strip()
    normalized_environment = str(environment or "dev").strip().lower() or "dev"
    normalized_status = str(status or "active").strip().lower() or "active"
    normalized_plane = normalize_credential_plane(credential_plane)
    normalized_provider_type = str(provider_type or "").strip().lower()

    if not normalized_tenant_id:
        raise HTTPException(status_code=422, detail="tenant_id is required")
    if not normalized_binding_name:
        raise HTTPException(status_code=422, detail="binding_name is required")
    if not normalized_consumer_key:
        raise HTTPException(status_code=422, detail="consumer_key is required")
    if normalized_status not in {"active", "inactive"}:
        raise HTTPException(status_code=422, detail="status must be active or inactive")

    validate_binding_references(
        db,
        tenant_id=normalized_tenant_id,
        credential_plane=normalized_plane,
        provider_type=normalized_provider_type,
        secret_provider_id=secret_provider_id,
        secret_ref=secret_ref,
        workload_identity_profile_id=workload_identity_profile_id,
    )

    existing_scope = (
        db.query(ProviderCredentialBinding)
        .filter_by(
            tenant_id=normalized_tenant_id,
            consumer_type=normalized_consumer_type,
            consumer_key=normalized_consumer_key,
            provider_type=normalized_provider_type,
            environment=normalized_environment,
        )
        .first()
    )

    now = datetime.utcnow()
    if binding_id:
        row = db.query(ProviderCredentialBinding).filter_by(binding_id=binding_id).first()
        if not row:
            raise HTTPException(status_code=404, detail="Credential binding not found")
        if existing_scope and existing_scope.binding_id != row.binding_id:
            raise HTTPException(status_code=409, detail="Credential binding scope already exists")
    else:
        if existing_scope:
            raise HTTPException(status_code=409, detail="Credential binding scope already exists")
        row = ProviderCredentialBinding(binding_id=str(uuid4()))
        row.created_at = now
        db.add(row)

    row.tenant_id = normalized_tenant_id
    row.binding_name = normalized_binding_name
    row.consumer_type = normalized_consumer_type
    row.consumer_key = normalized_consumer_key
    row.provider_type = normalized_provider_type
    row.credential_plane = normalized_plane
    row.environment = normalized_environment
    row.status = normalized_status
    row.updated_by = actor_id
    row.updated_at = now

    if normalized_plane == CREDENTIAL_PLANE_SECRET_REF:
        row.secret_provider_id = str(secret_provider_id or "").strip()
        row.secret_ref = str(secret_ref or "").strip()
        row.workload_identity_profile_id = None
    else:
        row.workload_identity_profile_id = str(workload_identity_profile_id or "").strip()
        row.secret_provider_id = None
        row.secret_ref = None

    if not binding_id:
        row.created_at = now
    return row


def _serialize_gateway_cursor_binding(secret_provider_id: str, secret_ref: str) -> str:
    import json

    return json.dumps(
        {
            "version": GATEWAY_CURSOR_SECRET_BINDING_VERSION,
            "secret_provider_id": str(secret_provider_id or "").strip(),
            "secret_ref": str(secret_ref or "").strip(),
        },
        separators=(",", ":"),
    )


def maybe_sync_gateway_cursor_binding(db: Session, binding: ProviderCredentialBinding, actor_id: str) -> None:
    if str(binding.consumer_type or "").strip().lower() != "gateway":
        return
    if str(binding.consumer_key or "").strip().lower() != "cursor":
        return
    if str(binding.credential_plane or "").strip().lower() != CREDENTIAL_PLANE_SECRET_REF:
        return
    if str(binding.status or "").strip().lower() != "active":
        return

    provider_id = str(binding.secret_provider_id or "").strip()
    secret_ref = str(binding.secret_ref or "").strip()
    if not provider_id or not secret_ref:
        return

    serialized_value = _serialize_gateway_cursor_binding(provider_id, secret_ref)
    row = db.query(RuntimeConfig).filter_by(config_key=RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN).first()
    if row:
        row.config_value = serialized_value
        row.updated_by = actor_id
        row.updated_at = datetime.utcnow()
    else:
        db.add(
            RuntimeConfig(
                config_key=RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN,
                config_value=serialized_value,
                description="Gateway cursor secret binding via secret provider",
                updated_by=actor_id,
            )
        )
    invalidate_runtime_config_cache(RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN)