from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import AgentConfig, ProviderCredentialBinding, SecretProviderConfig, WorkloadIdentityFederationProfile
from app.services.provider_crypto import decrypt_value
from app.services.provider_credential_bindings import (
    CREDENTIAL_PLANE_SECRET_REF,
    CREDENTIAL_PLANE_WORKLOAD_IDENTITY,
    binding_configured,
    binding_masked_hint,
)
from app.services.secret_provider_values import is_db_secret_provider, read_db_secret_provider_value

_RUNTIME_VENDOR_PREFIXES = {
    "openai": "OPENAI",
    "anthropic": "ANTHROPIC",
    "cohere": "COHERE",
    "mistral": "MISTRAL",
    "groq": "GROQ",
    "azure-openai": "AZURE_OPENAI",
    "azure_openai": "AZURE_OPENAI",
}


@dataclass(frozen=True)
class ResolvedAgentCredential:
    binding_id: str
    provider_type: str
    credential_plane: str
    configured: bool
    masked_hint: Optional[str]
    secret_value: Optional[str] = None
    workload_identity_profile_id: Optional[str] = None


def _require_active_secret_provider(db: Session, provider_id: str) -> SecretProviderConfig:
    row = db.query(SecretProviderConfig).filter_by(secret_provider_id=str(provider_id).strip()).first()
    if not row:
        raise HTTPException(status_code=404, detail="Secret provider not found")
    if str(row.status or "").strip().lower() != "active":
        raise HTTPException(status_code=400, detail="Secret provider is not active")
    return row


def _resolve_secret_provider_connection(provider: SecretProviderConfig) -> tuple[str, str]:
    address = (
        decrypt_value(provider.provider_address_encrypted)
        if str(provider.provider_address_encrypted or "").strip()
        else str(provider.provider_address or "").strip()
    )
    bootstrap_token = (
        decrypt_value(provider.bootstrap_token_encrypted)
        if str(provider.bootstrap_token_encrypted or "").strip()
        else ""
    )
    return address, bootstrap_token


def read_secret_provider_value_at_runtime(db: Session, secret_provider_id: str, secret_ref: str) -> str:
    provider = _require_active_secret_provider(db, secret_provider_id)
    provider_type = str(provider.provider_type or "").strip().lower()
    normalized_ref = str(secret_ref or "").strip()
    if not normalized_ref:
        raise HTTPException(status_code=422, detail="secret_ref is required")

    if is_db_secret_provider(provider_type):
        return read_db_secret_provider_value(db, provider, normalized_ref)

    address, bootstrap_token = _resolve_secret_provider_connection(provider)

    if provider_type == "vault":
        if not address:
            raise HTTPException(status_code=400, detail="Vault provider address is missing")
        headers = {}
        if bootstrap_token:
            headers["X-Vault-Token"] = bootstrap_token
        response = httpx.get(f"{address.rstrip('/')}/v1/{normalized_ref.lstrip('/')}", headers=headers, timeout=5.0)
        if response.status_code >= 400:
            raise HTTPException(status_code=502, detail="Vault secret read failed")
        payload = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        data = payload.get("data") if isinstance(payload, dict) else {}
        if isinstance(data, dict) and isinstance(data.get("data"), dict):
            data = data.get("data")
        if not isinstance(data, dict):
            raise HTTPException(status_code=502, detail="Vault secret payload is invalid")
        for key in ("token", "value", "secret"):
            candidate = str(data.get(key) or "").strip()
            if candidate:
                return candidate
        for value in data.values():
            candidate = str(value or "").strip()
            if candidate:
                return candidate
        raise HTTPException(status_code=502, detail="Vault secret payload does not contain a usable value")

    if provider_type in {"aws-secrets-manager", "aws_secrets_manager"}:
        try:
            import boto3  # type: ignore
        except ImportError as exc:
            raise HTTPException(status_code=503, detail="boto3 is required for AWS external secret reads") from exc
        try:
            client = boto3.client("secretsmanager")
            payload = client.get_secret_value(SecretId=normalized_ref)
        except Exception as exc:
            raise HTTPException(status_code=502, detail="AWS Secrets Manager secret read failed") from exc
        secret_string = str(payload.get("SecretString") or "").strip()
        if secret_string:
            return secret_string
        secret_binary = payload.get("SecretBinary")
        if secret_binary:
            try:
                return secret_binary.decode("utf-8") if isinstance(secret_binary, bytes) else str(secret_binary)
            except Exception:
                return str(secret_binary)
        raise HTTPException(status_code=502, detail="AWS secret payload does not contain a usable value")

    if provider_type in {"azure-key-vault", "azure_key_vault"}:
        if not address:
            raise HTTPException(status_code=400, detail="Azure Key Vault provider address is missing")
        if not bootstrap_token:
            raise HTTPException(status_code=400, detail="Azure Key Vault bootstrap token is missing")
        response = httpx.get(
            f"{address.rstrip('/')}/secrets/{normalized_ref}?api-version=7.4",
            headers={"Authorization": f"Bearer {bootstrap_token}"},
            timeout=5.0,
        )
        if response.status_code >= 400:
            raise HTTPException(status_code=502, detail="Azure Key Vault secret read failed")
        payload = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        value = str((payload or {}).get("value") or "").strip()
        if not value:
            raise HTTPException(status_code=502, detail="Azure Key Vault payload does not contain a usable value")
        return value

    raise HTTPException(status_code=400, detail="secret provider type is not supported for runtime reads")


def _runtime_vendor_env_token(provider_type: str) -> Optional[str]:
    normalized = str(provider_type or "").strip().lower()
    prefix = _RUNTIME_VENDOR_PREFIXES.get(normalized)
    if not prefix:
        return None
    return (os.getenv(f"{prefix}_WORKLOAD_IDENTITY_ACCESS_TOKEN") or "").strip() or None


def _resolve_workload_identity_runtime(
    db: Session,
    profile_id: str,
    provider_type: str,
) -> ResolvedAgentCredential:
    profile = db.query(WorkloadIdentityFederationProfile).filter_by(workload_identity_profile_id=profile_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Workload identity profile not found")
    if str(profile.status or "").strip().lower() != "active":
        raise HTTPException(status_code=400, detail="Workload identity profile is not active")

    cloud_types = {"aws", "azure", "gcp", "google", "nvidia"}
    normalized_provider = str(provider_type or "").strip().lower()
    if normalized_provider in cloud_types:
        raise HTTPException(
            status_code=503,
            detail="Cloud workload identity bindings require runtime token exchange; use secret_ref plane or env injection.",
        )

    env_token = _runtime_vendor_env_token(normalized_provider)
    if not env_token:
        prefix = _RUNTIME_VENDOR_PREFIXES.get(normalized_provider, normalized_provider.upper())
        raise HTTPException(
            status_code=503,
            detail=f"Agent credential binding requires {prefix}_WORKLOAD_IDENTITY_ACCESS_TOKEN runtime injection.",
        )

    return ResolvedAgentCredential(
        binding_id="",
        provider_type=normalized_provider,
        credential_plane=CREDENTIAL_PLANE_WORKLOAD_IDENTITY,
        configured=True,
        masked_hint=f"wif:{profile_id[:4]}***",
        secret_value=env_token,
        workload_identity_profile_id=profile_id,
    )


def resolve_binding_for_runtime(db: Session, binding: ProviderCredentialBinding) -> ResolvedAgentCredential:
    if str(binding.status or "").strip().lower() != "active":
        raise HTTPException(status_code=403, detail="Credential binding is not active")

    plane = str(binding.credential_plane or "").strip().lower()
    provider_type = str(binding.provider_type or "").strip().lower()
    binding_id = str(binding.binding_id or "").strip()

    if plane == CREDENTIAL_PLANE_SECRET_REF:
        provider_id = str(binding.secret_provider_id or "").strip()
        secret_ref = str(binding.secret_ref or "").strip()
        if not provider_id or not secret_ref:
            raise HTTPException(status_code=422, detail="Credential binding secret_ref plane is incomplete")
        secret_value = read_secret_provider_value_at_runtime(db, provider_id, secret_ref)
        if not secret_value:
            raise HTTPException(status_code=503, detail="Credential binding secret value is empty")
        return ResolvedAgentCredential(
            binding_id=binding_id,
            provider_type=provider_type,
            credential_plane=plane,
            configured=True,
            masked_hint=binding_masked_hint(db, binding),
            secret_value=secret_value,
        )

    if plane == CREDENTIAL_PLANE_WORKLOAD_IDENTITY:
        profile_id = str(binding.workload_identity_profile_id or "").strip()
        if not profile_id:
            raise HTTPException(status_code=422, detail="Credential binding workload_identity plane is incomplete")
        resolved = _resolve_workload_identity_runtime(db, profile_id, provider_type)
        return ResolvedAgentCredential(
            binding_id=binding_id,
            provider_type=provider_type,
            credential_plane=plane,
            configured=True,
            masked_hint=binding_masked_hint(db, binding),
            secret_value=resolved.secret_value,
            workload_identity_profile_id=profile_id,
        )

    raise HTTPException(status_code=422, detail="Unsupported credential plane for runtime resolution")


def load_active_binding_by_id(db: Session, binding_id: str) -> ProviderCredentialBinding:
    normalized_id = str(binding_id or "").strip()
    if not normalized_id:
        raise HTTPException(status_code=422, detail="credential_binding_id is required")
    row = db.query(ProviderCredentialBinding).filter_by(binding_id=normalized_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Credential binding not found")
    return row


def find_agent_binding_by_scope(
    db: Session,
    *,
    consumer_key: str,
    provider_type: str,
    environment: str,
) -> Optional[ProviderCredentialBinding]:
    normalized_key = str(consumer_key or "").strip()
    normalized_provider = str(provider_type or "").strip().lower()
    normalized_environment = str(environment or "dev").strip().lower() or "dev"
    if not normalized_key or not normalized_provider:
        return None
    return (
        db.query(ProviderCredentialBinding)
        .filter_by(
            consumer_type="agent",
            consumer_key=normalized_key,
            provider_type=normalized_provider,
            environment=normalized_environment,
            status="active",
        )
        .first()
    )


def resolve_agent_config_credential(
    db: Session,
    config: AgentConfig,
    *,
    environment: Optional[str] = None,
) -> Optional[ResolvedAgentCredential]:
    if not config.enabled:
        raise HTTPException(status_code=403, detail="Agent config is disabled")

    target_environment = str(environment or config.environment or "dev").strip().lower() or "dev"
    binding: Optional[ProviderCredentialBinding] = None

    binding_id = str(config.credential_binding_id or "").strip()
    if binding_id:
        binding = load_active_binding_by_id(db, binding_id)
    else:
        binding = find_agent_binding_by_scope(
            db,
            consumer_key=config.agent_key,
            provider_type=config.provider,
            environment=target_environment,
        )

    if not binding:
        return None

    if str(binding.provider_type or "").strip().lower() != str(config.provider or "").strip().lower():
        raise HTTPException(status_code=422, detail="Credential binding provider_type must match agent provider")

    if str(binding.environment or "dev").strip().lower() != target_environment:
        raise HTTPException(status_code=422, detail="Credential binding environment must match inference environment")

    if not binding_configured(db, binding):
        raise HTTPException(status_code=503, detail="Agent credential binding is not configured")

    return resolve_binding_for_runtime(db, binding)


def serialize_agent_credential_status(db: Session, config: AgentConfig) -> dict:
    binding_id = str(config.credential_binding_id or "").strip()
    binding = None
    if binding_id:
        binding = db.query(ProviderCredentialBinding).filter_by(binding_id=binding_id).first()
    if binding is None:
        binding = find_agent_binding_by_scope(
            db,
            consumer_key=config.agent_key,
            provider_type=config.provider,
            environment=config.environment,
        )

    if not binding:
        return {
            "agent_key": config.agent_key,
            "provider": config.provider,
            "environment": config.environment,
            "credential_binding_id": config.credential_binding_id,
            "configured": False,
            "credential_plane": None,
            "masked_hint": None,
            "provider_type": config.provider,
        }

    configured = binding_configured(db, binding)
    return {
        "agent_key": config.agent_key,
        "provider": config.provider,
        "environment": config.environment,
        "credential_binding_id": binding.binding_id,
        "configured": configured,
        "credential_plane": binding.credential_plane,
        "masked_hint": binding_masked_hint(db, binding),
        "provider_type": binding.provider_type,
        "secret_provider_id": binding.secret_provider_id,
        "secret_ref": binding.secret_ref,
        "workload_identity_profile_id": binding.workload_identity_profile_id,
    }
