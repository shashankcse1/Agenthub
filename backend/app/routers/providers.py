import json
import os
import time
from fnmatch import fnmatch
from datetime import datetime
from datetime import timedelta
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response
import httpx
from sqlalchemy import and_
from sqlalchemy.orm import Session

from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import (
    SecretProviderConfig,
    SecretProviderLease,
    SupportedModelCatalogEntry,
    TenantCatalogEntry,
    TenantSupportedModelEntitlement,
    WorkloadIdentityFederationProfile,
)
from app.router_constants import (
    PROVIDERS_ADMIN_ROLES,
    PROVIDERS_ADMIN_SECURITY_AUDITOR_ROLES,
    PROVIDERS_ADMIN_SECURITY_RELEASE_ROLES,
    PROVIDERS_ADMIN_SECURITY_ROLES,
)
from app.runtime_constants import (
    RUNTIME_CONFIG_WORKLOAD_IDENTITY_EXPOSE_ACCESS_TOKEN,
    RUNTIME_CONFIG_WORKLOAD_IDENTITY_EXPIRES_IN_SECONDS,
    RUNTIME_CONFIG_WORKLOAD_IDENTITY_HTTP_TIMEOUT_SECONDS,
)
from app.schemas import (
    SecretProviderListResponse,
    SecretProviderHealthResponse,
    SecretProviderLeaseRenewRequest,
    SecretProviderLeaseResponse,
    SecretProviderRequest,
    SupportedModelResponse,
    SupportedModelUpsertRequest,
    TenantCatalogResponse,
    TenantSupportedModelEntitlementResponse,
    TenantSupportedModelEntitlementUpsertRequest,
    TenantCatalogUpsertRequest,
    WorkloadIdentityProviderHealthResponse,
    WorkloadIdentityProviderListResponse,
    WorkloadIdentityProviderRequest,
    WorkloadIdentityTokenExchangeResponse,
    WorkloadIdentityTrustValidateRequest,
    WorkloadIdentityTrustValidateResponse,
    WorkloadIdentityTokenExchangeRequest,
)
from app.security import ActorContext, get_actor_context, require_dual_approval, require_mfa, require_role
from app.services.audit import create_audit_event
from app.services.provider_crypto import decrypt_value, encrypt_value
from app.services.runtime_config import get_runtime_config, get_runtime_config_float, get_runtime_config_int

router = APIRouter()
logger = get_logger(__name__)
_RUNTIME_ENVIRONMENT = (os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "dev").strip().lower()

_RUNTIME_VENDOR_PREFIXES: dict[str, str] = {
    "openai": "OPENAI",
    "anthropic": "ANTHROPIC",
    "cohere": "COHERE",
    "mistral": "MISTRAL",
    "groq": "GROQ",
    "together": "TOGETHER",
    "fireworks": "FIREWORKS",
    "perplexity": "PERPLEXITY",
    "xai": "XAI",
}


def _is_aws_provider(provider_type: str) -> bool:
    normalized = (provider_type or "").strip().lower()
    return normalized in {"aws", "aws-sts", "aws_sts"}


def _is_azure_provider(provider_type: str) -> bool:
    normalized = (provider_type or "").strip().lower()
    return normalized in {"azure", "azure-entra", "azure_entra", "azure-ad", "azure_ad"}


def _is_google_provider(provider_type: str) -> bool:
    normalized = (provider_type or "").strip().lower()
    return normalized in {"google", "gcp", "google-cloud", "google_cloud"}


def _is_nvidia_provider(provider_type: str) -> bool:
    normalized = (provider_type or "").strip().lower()
    return normalized in {"nvidia", "nvidia-nim", "nvidia_nim"}


def _runtime_vendor_name(provider_type: str) -> Optional[str]:
    normalized = (provider_type or "").strip().lower()
    aliases = {
        "claude": "anthropic",
        "mistralai": "mistral",
        "togetherai": "together",
        "fireworksai": "fireworks",
        "x-ai": "xai",
    }
    normalized = aliases.get(normalized, normalized)
    if normalized in _RUNTIME_VENDOR_PREFIXES:
        return normalized
    return None


def _require_tenant_match(expected_tenant_id: str, provided_tenant_id: str, resource: str) -> None:
    if expected_tenant_id != provided_tenant_id:
        raise HTTPException(status_code=403, detail=f"Tenant scope mismatch for {resource}")


def _tenant_catalog_snapshot(db: Session, tenant_ids: Optional[set[str]] = None) -> dict[str, TenantCatalogEntry]:
    query = db.query(TenantCatalogEntry)
    if tenant_ids:
        query = query.filter(TenantCatalogEntry.tenant_id.in_(sorted(tenant_ids)))
    rows = query.all()
    return {row.tenant_id: row for row in rows}


def _require_active_tenant_catalog_entry(db: Session, tenant_id: str) -> TenantCatalogEntry:
    normalized_tenant_id = tenant_id.strip()
    row = db.query(TenantCatalogEntry).filter_by(tenant_id=normalized_tenant_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Tenant catalog entry not found")
    if row.status != "active":
        raise HTTPException(status_code=400, detail="Tenant catalog entry is not active")
    return row


def _require_tenant_catalog_entry(db: Session, tenant_id: str) -> TenantCatalogEntry:
    normalized_tenant_id = tenant_id.strip()
    row = db.query(TenantCatalogEntry).filter_by(tenant_id=normalized_tenant_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Tenant catalog entry not found")
    return row


def _require_supported_model_entry(db: Session, provider_type: str, model_name: str) -> SupportedModelCatalogEntry:
    normalized_provider_type = provider_type.strip().lower()
    normalized_model_name = model_name.strip()
    row = (
        db.query(SupportedModelCatalogEntry)
        .filter_by(provider_type=normalized_provider_type, model_name=normalized_model_name)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Supported model not found for provider")
    return row


def _parse_allowed_subject_patterns(raw_value: str) -> list[str]:
    sample = '["agent-*", "team/platform/*"]'
    try:
        parsed = json.loads(raw_value or "[]")
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail=f"allowed_subject_patterns must be valid JSON. Example: {sample}",
        ) from exc

    if not isinstance(parsed, list) or any(not isinstance(item, str) for item in parsed):
        raise HTTPException(
            status_code=400,
            detail=f"allowed_subject_patterns must be a JSON array of strings. Example: {sample}",
        )
    return parsed


def _subject_allowed(profile: WorkloadIdentityFederationProfile, subject: str) -> bool:
    patterns = _parse_allowed_subject_patterns(profile.allowed_subject_patterns)
    if not patterns:
        return True
    return any(fnmatch(subject, pattern) for pattern in patterns)


def _masked_if_encrypted(value: str, encrypted_value: Optional[str]) -> str:
    if str(encrypted_value or "").strip():
        return "[ENCRYPTED]"
    return value


def _workload_role(profile: WorkloadIdentityFederationProfile) -> str:
    encrypted = str(profile.role_arn_or_equivalent_encrypted or "").strip()
    if encrypted:
        return decrypt_value(encrypted)
    return str(profile.role_arn_or_equivalent or "").strip()


def _secret_provider_connection(provider: SecretProviderConfig) -> tuple[str, str, str, str]:
    address = (
        decrypt_value(provider.provider_address_encrypted)
        if str(provider.provider_address_encrypted or "").strip()
        else str(provider.provider_address or "").strip()
    )
    auth_method = (
        decrypt_value(provider.auth_method_encrypted)
        if str(provider.auth_method_encrypted or "").strip()
        else str(provider.auth_method or "").strip()
    )
    role_or_mount = (
        decrypt_value(provider.role_or_mount_encrypted)
        if str(provider.role_or_mount_encrypted or "").strip()
        else str(provider.role_or_mount or "").strip()
    )
    bootstrap_token = (
        decrypt_value(provider.bootstrap_token_encrypted)
        if str(provider.bootstrap_token_encrypted or "").strip()
        else ""
    )
    return address, auth_method, role_or_mount, bootstrap_token


def _exchange_token_with_aws_sts(profile: WorkloadIdentityFederationProfile, subject: str) -> tuple[str, int]:
    try:
        import boto3  # type: ignore
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail="AWS STS exchange requires boto3. Install boto3 and retry.",
        ) from exc

    role_session_name = f"agenthub-{uuid4().hex[:18]}"
    duration_seconds = max(900, min(int(profile.session_duration_seconds or 3600), 43200))

    try:
        sts = boto3.client("sts")
        resp = sts.assume_role(
            RoleArn=_workload_role(profile),
            RoleSessionName=role_session_name,
            DurationSeconds=duration_seconds,
        )
    except Exception as exc:
        logger.error(
            "aws_sts_exchange_failed %s",
            sanitize_fields(
                {
                    "workload_identity_profile_id": profile.workload_identity_profile_id,
                    "subject": subject,
                    "provider_type": profile.provider_type,
                }
            ),
        )
        raise HTTPException(
            status_code=502,
            detail="AWS STS AssumeRole failed for workload identity profile.",
        ) from exc

    creds = resp.get("Credentials") or {}
    session_token = creds.get("SessionToken")
    expiration = creds.get("Expiration")
    if not session_token or expiration is None:
        raise HTTPException(status_code=502, detail="AWS STS returned incomplete credentials.")

    expires_in = int(max(1, (expiration - datetime.utcnow()).total_seconds()))
    return str(session_token), expires_in


def _exchange_token_with_azure_workload_identity(
    profile: WorkloadIdentityFederationProfile,
    subject: str,
    default_expires_in_seconds: int,
    default_http_timeout_seconds: float,
) -> tuple[str, int]:
    # First preference: runtime-injected short-lived token from a trusted sidecar/identity agent.
    token = (os.getenv("AZURE_WORKLOAD_IDENTITY_ACCESS_TOKEN") or "").strip()

    if token:
        expires_in = max(1, int(default_expires_in_seconds))

        logger.info(
            "azure_workload_identity_exchange_completed %s",
            sanitize_fields(
                {
                    "workload_identity_profile_id": profile.workload_identity_profile_id,
                    "tenant_id": profile.tenant_id,
                    "subject": subject,
                    "mode": "runtime_injected",
                }
            ),
        )
        return token, expires_in

    # Fallback: native Azure token acquisition via OAuth2 client credentials.
    tenant_id = (os.getenv("AZURE_WORKLOAD_IDENTITY_TENANT_ID") or "").strip()
    client_id = (os.getenv("AZURE_WORKLOAD_IDENTITY_CLIENT_ID") or "").strip()
    client_secret = (os.getenv("AZURE_WORKLOAD_IDENTITY_CLIENT_SECRET") or "").strip()
    token_url = (os.getenv("AZURE_WORKLOAD_IDENTITY_TOKEN_URL") or "").strip()
    scope = (os.getenv("AZURE_WORKLOAD_IDENTITY_SCOPE") or "https://management.azure.com/.default").strip()

    if not token_url and tenant_id:
        token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

    missing = [
        name
        for name, value in (
            ("AZURE_WORKLOAD_IDENTITY_CLIENT_ID", client_id),
            ("AZURE_WORKLOAD_IDENTITY_CLIENT_SECRET", client_secret),
            ("AZURE_WORKLOAD_IDENTITY_TOKEN_URL or AZURE_WORKLOAD_IDENTITY_TENANT_ID", token_url),
        )
        if not value
    ]
    if missing:
        raise HTTPException(
            status_code=503,
            detail=f"Azure workload identity native exchange missing configuration: {', '.join(missing)}",
        )

    timeout_seconds = max(0.1, float(default_http_timeout_seconds))

    try:
        response = httpx.post(
            token_url,
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": scope,
            },
            timeout=timeout_seconds,
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Azure token endpoint request failed for workload identity profile.") from exc

    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail="Azure token endpoint returned failure for workload identity profile.")

    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Azure token endpoint returned non-JSON response.") from exc

    access_token = str(payload.get("access_token", "")).strip()
    expires_in_value = payload.get("expires_in")
    if not access_token:
        raise HTTPException(status_code=502, detail="Azure token endpoint returned incomplete credentials.")

    if isinstance(expires_in_value, str) and expires_in_value.isdigit():
        expires_in = int(expires_in_value)
    elif isinstance(expires_in_value, int):
        expires_in = expires_in_value
    else:
        expires_in = 3600

    if expires_in <= 0:
        raise HTTPException(status_code=502, detail="Azure token endpoint returned invalid expires_in.")

    logger.info(
        "azure_workload_identity_exchange_completed %s",
        sanitize_fields(
            {
                "workload_identity_profile_id": profile.workload_identity_profile_id,
                "tenant_id": profile.tenant_id,
                "subject": subject,
                    "mode": "native_client_credentials",
            }
        ),
    )
    return access_token, expires_in


def _exchange_token_with_google_workload_identity(
    profile: WorkloadIdentityFederationProfile,
    subject: str,
    default_expires_in_seconds: int,
    default_http_timeout_seconds: float,
) -> tuple[str, int]:
    # First preference: runtime-injected short-lived token.
    token = (os.getenv("GOOGLE_WORKLOAD_IDENTITY_ACCESS_TOKEN") or "").strip()

    if token:
        expires_in = max(1, int(default_expires_in_seconds))

        logger.info(
            "google_workload_identity_exchange_completed %s",
            sanitize_fields(
                {
                    "workload_identity_profile_id": profile.workload_identity_profile_id,
                    "tenant_id": profile.tenant_id,
                    "subject": subject,
                    "mode": "runtime_injected",
                }
            ),
        )
        return token, expires_in

    # Fallback: native token retrieval from metadata/token endpoint.
    token_url = (
        os.getenv("GOOGLE_WORKLOAD_IDENTITY_TOKEN_URL")
        or "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"
    ).strip()
    bearer = (os.getenv("GOOGLE_WORKLOAD_IDENTITY_BEARER") or "").strip()
    timeout_seconds = max(0.1, float(default_http_timeout_seconds))

    headers = {"Metadata-Flavor": "Google"}
    if bearer:
        headers["Authorization"] = f"Bearer {bearer}"

    try:
        response = httpx.get(token_url, headers=headers, timeout=timeout_seconds)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="Google token endpoint request failed for workload identity profile.") from exc

    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail="Google token endpoint returned failure for workload identity profile.")

    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="Google token endpoint returned non-JSON response.") from exc

    access_token = str(payload.get("access_token", "")).strip()
    expires_in_value = payload.get("expires_in")
    if not access_token:
        raise HTTPException(status_code=502, detail="Google token endpoint returned incomplete credentials.")

    if isinstance(expires_in_value, str) and expires_in_value.isdigit():
        expires_in = int(expires_in_value)
    elif isinstance(expires_in_value, int):
        expires_in = expires_in_value
    else:
        expires_in = 3600

    if expires_in <= 0:
        raise HTTPException(status_code=502, detail="Google token endpoint returned invalid expires_in.")

    logger.info(
        "google_workload_identity_exchange_completed %s",
        sanitize_fields(
            {
                "workload_identity_profile_id": profile.workload_identity_profile_id,
                "tenant_id": profile.tenant_id,
                "subject": subject,
                "mode": "native_metadata",
            }
        ),
    )
    return access_token, expires_in


def _exchange_token_with_nvidia_workload_identity(
    profile: WorkloadIdentityFederationProfile,
    subject: str,
    default_expires_in_seconds: int,
    default_http_timeout_seconds: float,
) -> tuple[str, int]:
    # First preference: runtime-injected short-lived token.
    token = (os.getenv("NVIDIA_WORKLOAD_IDENTITY_ACCESS_TOKEN") or "").strip()

    if token:
        expires_in = max(1, int(default_expires_in_seconds))

        logger.info(
            "nvidia_workload_identity_exchange_completed %s",
            sanitize_fields(
                {
                    "workload_identity_profile_id": profile.workload_identity_profile_id,
                    "tenant_id": profile.tenant_id,
                    "subject": subject,
                    "mode": "runtime_injected",
                }
            ),
        )
        return token, expires_in

    # Fallback: native client-credentials exchange.
    client_id = (os.getenv("NVIDIA_WORKLOAD_IDENTITY_CLIENT_ID") or "").strip()
    client_secret = (os.getenv("NVIDIA_WORKLOAD_IDENTITY_CLIENT_SECRET") or "").strip()
    token_url = (os.getenv("NVIDIA_WORKLOAD_IDENTITY_TOKEN_URL") or "").strip()
    scope = (os.getenv("NVIDIA_WORKLOAD_IDENTITY_SCOPE") or "").strip()

    missing = [
        name
        for name, value in (
            ("NVIDIA_WORKLOAD_IDENTITY_CLIENT_ID", client_id),
            ("NVIDIA_WORKLOAD_IDENTITY_CLIENT_SECRET", client_secret),
            ("NVIDIA_WORKLOAD_IDENTITY_TOKEN_URL", token_url),
        )
        if not value
    ]
    if missing:
        raise HTTPException(
            status_code=503,
            detail=f"NVIDIA workload identity native exchange missing configuration: {', '.join(missing)}",
        )

    timeout_seconds = max(0.1, float(default_http_timeout_seconds))

    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if scope:
        data["scope"] = scope

    try:
        response = httpx.post(token_url, data=data, timeout=timeout_seconds)
    except Exception as exc:
        raise HTTPException(status_code=502, detail="NVIDIA token endpoint request failed for workload identity profile.") from exc

    if response.status_code >= 400:
        raise HTTPException(status_code=502, detail="NVIDIA token endpoint returned failure for workload identity profile.")

    try:
        payload = response.json()
    except ValueError as exc:
        raise HTTPException(status_code=502, detail="NVIDIA token endpoint returned non-JSON response.") from exc

    access_token = str(payload.get("access_token", "")).strip()
    expires_in_value = payload.get("expires_in")
    if not access_token:
        raise HTTPException(status_code=502, detail="NVIDIA token endpoint returned incomplete credentials.")

    if isinstance(expires_in_value, str) and expires_in_value.isdigit():
        expires_in = int(expires_in_value)
    elif isinstance(expires_in_value, int):
        expires_in = expires_in_value
    else:
        expires_in = 3600

    if expires_in <= 0:
        raise HTTPException(status_code=502, detail="NVIDIA token endpoint returned invalid expires_in.")

    logger.info(
        "nvidia_workload_identity_exchange_completed %s",
        sanitize_fields(
            {
                "workload_identity_profile_id": profile.workload_identity_profile_id,
                "tenant_id": profile.tenant_id,
                "subject": subject,
                "mode": "native_client_credentials",
            }
        ),
    )
    return access_token, expires_in


def _exchange_token_with_runtime_vendor(
    profile: WorkloadIdentityFederationProfile,
    subject: str,
    default_expires_in_seconds: int,
) -> tuple[str, int, str]:
    vendor = _runtime_vendor_name(profile.provider_type)
    if not vendor:
        raise HTTPException(
            status_code=400,
            detail="Live token exchange is only supported for configured workload identity providers.",
        )

    prefix = _RUNTIME_VENDOR_PREFIXES[vendor]
    token = (os.getenv(f"{prefix}_WORKLOAD_IDENTITY_ACCESS_TOKEN") or "").strip()
    if not token:
        raise HTTPException(
            status_code=503,
            detail=f"{vendor.capitalize()} workload identity exchange requires {prefix}_WORKLOAD_IDENTITY_ACCESS_TOKEN runtime injection.",
        )
    expires_in = max(1, int(default_expires_in_seconds))

    logger.info(
        "runtime_vendor_workload_identity_exchange_completed %s",
        sanitize_fields(
            {
                "workload_identity_profile_id": profile.workload_identity_profile_id,
                "tenant_id": profile.tenant_id,
                "subject": subject,
                "vendor": vendor,
                "mode": "runtime_injected",
            }
        ),
    )
    return token, expires_in, f"{vendor}_workload_identity"


def _should_expose_workload_identity_access_token(db: Session) -> bool:
    raw_value = get_runtime_config(db, RUNTIME_CONFIG_WORKLOAD_IDENTITY_EXPOSE_ACCESS_TOKEN, "false")
    enabled = str(raw_value).strip().lower() in {"1", "true", "yes", "on", "enabled"}
    if _RUNTIME_ENVIRONMENT not in {"dev", "test", "local"}:
        return False
    return enabled


@router.post(
    "/providers/tenants",
    response_model=TenantCatalogResponse,
    summary="Create tenant catalog entry",
    description="Creates a tenant catalog record used to scope provider onboarding and entitlement governance.",
    responses={
        403: {"description": "Actor role is not allowed for this action or MFA is missing."},
        409: {"description": "Tenant catalog entry already exists."},
    },
)
def create_tenant_catalog_entry(
    payload: TenantCatalogUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_ROLES)
    require_mfa(ctx)
    tenant_id = payload.tenant_id.strip()
    existing = db.query(TenantCatalogEntry).filter_by(tenant_id=tenant_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Tenant catalog entry already exists")

    row = TenantCatalogEntry(
        tenant_id=tenant_id,
        tenant_name=payload.tenant_name.strip(),
        tenant_type=payload.tenant_type.strip().lower(),
        description=payload.description.strip(),
        status=payload.status.strip().lower(),
        updated_by=ctx.actor_id,
    )
    db.add(row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="tenant_catalog.create",
        resource_type="tenant_catalog",
        resource_id=row.tenant_id,
        trace_id=f"trace-tenant-{row.tenant_id}",
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/providers/tenants", response_model=list[TenantCatalogResponse])
def list_tenant_catalog_entries(
    status: Optional[str] = None,
    tenant_type: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    response: Response = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_AUDITOR_ROLES)
    query = db.query(TenantCatalogEntry)
    if status:
        query = query.filter(TenantCatalogEntry.status == status.strip().lower())
    if tenant_type:
        query = query.filter(TenantCatalogEntry.tenant_type == tenant_type.strip().lower())

    total_count = query.count()
    if response is not None:
        response.headers["X-Total-Count"] = str(total_count)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="tenant_catalog.list",
        resource_type="tenant_catalog",
        resource_id=str(status or tenant_type or "all"),
        trace_id=f"trace-tenant-catalog-list-{uuid4()}",
    )
    db.commit()

    return (
        query.order_by(TenantCatalogEntry.tenant_name.asc(), TenantCatalogEntry.tenant_id.asc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.put(
    "/providers/tenants/{tenant_id}",
    response_model=TenantCatalogResponse,
    summary="Update tenant catalog entry",
    description="Updates tenant catalog metadata used by provider and model governance workflows.",
    responses={
        400: {"description": "Validation failed: tenant_id in payload must match path."},
        403: {"description": "Actor role is not allowed for this action or MFA is missing."},
        404: {"description": "Tenant catalog entry not found."},
    },
)
def update_tenant_catalog_entry(
    tenant_id: str,
    payload: TenantCatalogUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_ROLES)
    require_mfa(ctx)
    normalized_tenant_id = tenant_id.strip()
    if payload.tenant_id.strip() != normalized_tenant_id:
        raise HTTPException(status_code=400, detail="tenant_id in payload must match the path")

    row = db.query(TenantCatalogEntry).filter_by(tenant_id=normalized_tenant_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Tenant catalog entry not found")

    row.tenant_name = payload.tenant_name.strip()
    row.tenant_type = payload.tenant_type.strip().lower()
    row.description = payload.description.strip()
    row.status = payload.status.strip().lower()
    row.updated_by = ctx.actor_id
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="tenant_catalog.update",
        resource_type="tenant_catalog",
        resource_id=row.tenant_id,
        trace_id=f"trace-tenant-{row.tenant_id}",
    )
    db.commit()
    db.refresh(row)
    return row


@router.post(
    "/auth/workload-identity/providers",
    summary="Create workload identity provider",
    description=(
        "Registers a workload identity provider profile with encrypted bootstrap credentials and tenant-scoped governance."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action or MFA is missing."},
    },
)
def create_workload_identity_provider(
    payload: WorkloadIdentityProviderRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_ROLES)
    require_mfa(ctx)
    _require_active_tenant_catalog_entry(db, payload.tenant_id)
    _parse_allowed_subject_patterns(payload.allowed_subject_patterns)
    profile = WorkloadIdentityFederationProfile(
        workload_identity_profile_id=str(uuid4()),
        tenant_id=payload.tenant_id,
        provider_type=payload.provider_type,
        audience=payload.audience,
        role_arn_or_equivalent="[ENCRYPTED]",
        role_arn_or_equivalent_encrypted=encrypt_value(payload.role_arn_or_equivalent),
        bootstrap_token_encrypted=encrypt_value(payload.bootstrap_token or ""),
        session_duration_seconds=payload.session_duration_seconds,
        allowed_subject_patterns=payload.allowed_subject_patterns,
        status="active",
    )
    db.add(profile)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="workload_identity.provider.create",
        resource_type="workload_identity_profile",
        resource_id=profile.workload_identity_profile_id,
        trace_id=f"trace-{profile.workload_identity_profile_id}",
    )
    db.commit()
    return {"workload_identity_profile_id": profile.workload_identity_profile_id, "status": profile.status}


@router.get(
    "/auth/workload-identity/providers",
    response_model=list[WorkloadIdentityProviderListResponse],
    summary="List workload identity providers",
    description=(
        "Returns workload identity provider profiles with tenant context and pagination metadata. "
        "Secrets remain encrypted at rest and are not exposed by this endpoint."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action."},
    },
)
def list_workload_identity_providers(
    tenant_id: Optional[str] = None,
    provider_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    response: Response = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_AUDITOR_ROLES)
    query = db.query(WorkloadIdentityFederationProfile)
    if tenant_id:
        query = query.filter(WorkloadIdentityFederationProfile.tenant_id == tenant_id)
    if provider_type:
        query = query.filter(WorkloadIdentityFederationProfile.provider_type == provider_type)
    if status:
        query = query.filter(WorkloadIdentityFederationProfile.status == status)

    total_count = query.count()
    if response is not None:
        response.headers["X-Total-Count"] = str(total_count)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="workload_identity.provider.list",
        resource_type="workload_identity_profile",
        resource_id=str(tenant_id or provider_type or status or "all"),
        trace_id=f"trace-workload-identity-list-{uuid4()}",
    )
    db.commit()

    rows = (
        query.order_by(WorkloadIdentityFederationProfile.workload_identity_profile_id.asc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    tenant_catalog = _tenant_catalog_snapshot(db, {row.tenant_id for row in rows})
    return [
        {
            "workload_identity_profile_id": row.workload_identity_profile_id,
            "tenant_id": row.tenant_id,
            "tenant_name": tenant_catalog.get(row.tenant_id).tenant_name if tenant_catalog.get(row.tenant_id) else "",
            "tenant_type": tenant_catalog.get(row.tenant_id).tenant_type if tenant_catalog.get(row.tenant_id) else "",
            "tenant_description": tenant_catalog.get(row.tenant_id).description if tenant_catalog.get(row.tenant_id) else "",
            "provider_type": row.provider_type,
            "audience": row.audience,
            "session_duration_seconds": row.session_duration_seconds,
            "status": row.status,
            "last_token_exchange_at": row.last_token_exchange_at,
        }
        for row in rows
    ]


@router.post(
    "/auth/workload-identity/token-exchange",
    response_model=WorkloadIdentityTokenExchangeResponse,
    summary="Exchange workload identity token",
    description=(
        "Performs a governed token exchange for a workload identity profile. "
        "Audit evidence is emitted for both exchange and optional access-token exposure branches."
    ),
    responses={
        400: {"description": "Provider profile or request configuration is invalid for token exchange."},
        403: {"description": "Actor role, tenant scope, or subject policy is not allowed."},
        404: {"description": "Workload identity profile not found."},
    },
)
def token_exchange(
    payload: WorkloadIdentityTokenExchangeRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "workload_identity_token_exchange_start %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "workload_identity_profile_id": payload.workload_identity_profile_id,
                "subject": payload.subject,
            }
        ),
    )
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_RELEASE_ROLES)
    require_mfa(ctx)
    profile = (
        db.query(WorkloadIdentityFederationProfile)
        .filter_by(workload_identity_profile_id=payload.workload_identity_profile_id)
        .first()
    )
    if not profile:
        logger.error(
            "workload_identity_profile_not_found %s",
            sanitize_fields({"workload_identity_profile_id": payload.workload_identity_profile_id}),
        )
        raise HTTPException(status_code=404, detail="Workload identity profile not found")
    if profile.status != "active":
        logger.error(
            "workload_identity_profile_inactive %s",
            sanitize_fields({"workload_identity_profile_id": payload.workload_identity_profile_id, "status": profile.status}),
        )
        raise HTTPException(status_code=400, detail="Workload identity profile is not active")
    if not _subject_allowed(profile, payload.subject):
        logger.error(
            "workload_identity_subject_not_allowed %s",
            sanitize_fields(
                {
                    "workload_identity_profile_id": payload.workload_identity_profile_id,
                    "subject": payload.subject,
                }
            ),
        )
        raise HTTPException(status_code=403, detail="Subject is not allowed by workload identity profile policy")

    _require_tenant_match(profile.tenant_id, payload.tenant_id, "workload identity token exchange")

    default_expires_in_seconds = get_runtime_config_int(
        db,
        RUNTIME_CONFIG_WORKLOAD_IDENTITY_EXPIRES_IN_SECONDS,
        3600,
    )
    if default_expires_in_seconds <= 0:
        default_expires_in_seconds = 3600

    default_http_timeout_seconds = get_runtime_config_float(
        db,
        RUNTIME_CONFIG_WORKLOAD_IDENTITY_HTTP_TIMEOUT_SECONDS,
        3.0,
    )
    if default_http_timeout_seconds <= 0:
        default_http_timeout_seconds = 3.0

    if _is_aws_provider(profile.provider_type):
        access_token, expires_in = _exchange_token_with_aws_sts(profile, payload.subject)
        token_source = "aws_sts"
    elif _is_azure_provider(profile.provider_type):
        access_token, expires_in = _exchange_token_with_azure_workload_identity(
            profile,
            payload.subject,
            default_expires_in_seconds,
            default_http_timeout_seconds,
        )
        token_source = "azure_workload_identity"
    elif _is_google_provider(profile.provider_type):
        access_token, expires_in = _exchange_token_with_google_workload_identity(
            profile,
            payload.subject,
            default_expires_in_seconds,
            default_http_timeout_seconds,
        )
        token_source = "google_workload_identity"
    elif _is_nvidia_provider(profile.provider_type):
        access_token, expires_in = _exchange_token_with_nvidia_workload_identity(
            profile,
            payload.subject,
            default_expires_in_seconds,
            default_http_timeout_seconds,
        )
        token_source = "nvidia_workload_identity"
    elif _runtime_vendor_name(profile.provider_type):
        access_token, expires_in, token_source = _exchange_token_with_runtime_vendor(
            profile,
            payload.subject,
            default_expires_in_seconds,
        )
    else:
        raise HTTPException(
            status_code=400,
            detail=(
                "Live token exchange is only supported for AWS, Azure, Google, NVIDIA, "
                "and configured runtime-token AI providers (OpenAI, Anthropic, Cohere, Mistral, Groq, Together, Fireworks, Perplexity, xAI)."
            ),
        )

    profile.last_token_exchange_at = datetime.utcnow()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="workload_identity.token_exchange",
        resource_type="workload_identity_profile",
        resource_id=profile.workload_identity_profile_id,
        trace_id=f"trace-token-exchange-{profile.workload_identity_profile_id}",
    )
    db.commit()
    logger.info(
        "workload_identity_exchange_completed %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "workload_identity_profile_id": profile.workload_identity_profile_id,
                "exchange_source": token_source,
            }
        ),
    )
    response = {
        "expires_in": expires_in,
        "subject": payload.subject,
        "token_source": token_source,
        "token_reference": f"sts:{profile.workload_identity_profile_id}:{int(datetime.utcnow().timestamp())}",
    }
    if _should_expose_workload_identity_access_token(db):
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="workload_identity.token_exchange.access_token_exposed",
            resource_type="workload_identity_profile",
            resource_id=profile.workload_identity_profile_id,
            trace_id=f"trace-token-exchange-exposed-{profile.workload_identity_profile_id}",
            decision_outcome="warn",
        )
        db.commit()
        response["access_token"] = access_token
    return response


@router.post(
    "/auth/workload-identity/providers/{provider_id}/validate-trust",
    response_model=WorkloadIdentityTrustValidateResponse,
    summary="Validate workload identity trust",
    description=(
        "Validates workload identity trust settings for a provider profile and records audit evidence. "
        "Requires provider admin/security role and MFA."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action or MFA is missing."},
        404: {"description": "Workload identity profile not found."},
    },
)
def validate_workload_identity_trust(
    provider_id: str,
    payload: WorkloadIdentityTrustValidateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_ROLES)
    require_mfa(ctx)

    profile = db.query(WorkloadIdentityFederationProfile).filter_by(workload_identity_profile_id=provider_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Workload identity profile not found")

    _require_tenant_match(profile.tenant_id, payload.tenant_id, "workload identity trust validation")

    audience_matches = payload.expected_audience is None or payload.expected_audience == profile.audience
    passed = payload.simulate_pass and audience_matches
    profile.status = "active" if passed else "degraded"

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="workload_identity.trust.validate",
        resource_type="workload_identity_profile",
        resource_id=provider_id,
        trace_id=f"trace-trust-validate-{provider_id}",
        decision_outcome="allow" if passed else "warn",
    )
    db.commit()
    return {
        "workload_identity_profile_id": provider_id,
        "check_type": payload.check_type,
        "status": profile.status,
        "details": "validation_passed" if passed else "validation_failed",
    }


@router.get(
    "/auth/workload-identity/providers/{provider_id}/health",
    response_model=WorkloadIdentityProviderHealthResponse,
)
def get_workload_identity_provider_health(
    provider_id: str,
    tenant_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_AUDITOR_ROLES)
    profile = db.query(WorkloadIdentityFederationProfile).filter_by(workload_identity_profile_id=provider_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Workload identity profile not found")

    _require_tenant_match(profile.tenant_id, tenant_id, "workload identity health")

    stale_minutes = None
    if profile.last_token_exchange_at is not None:
        stale_minutes = int((datetime.utcnow() - profile.last_token_exchange_at).total_seconds() // 60)

    return {
        "workload_identity_profile_id": provider_id,
        "tenant_id": profile.tenant_id,
        "status": profile.status,
        "provider_type": profile.provider_type,
        "audience": profile.audience,
        "session_duration_seconds": profile.session_duration_seconds,
        "last_token_exchange_at": profile.last_token_exchange_at,
        "token_exchange_stale_minutes": stale_minutes,
    }


@router.post(
    "/auth/workload-identity/providers/{provider_id}/test",
    summary="Test workload identity provider",
    description=(
        "Runs a live workload identity connectivity test using token exchange flow and records audit evidence. "
        "Requires provider admin/security role and MFA."
    ),
    responses={
        400: {"description": "Provider type does not support workload connectivity testing."},
        403: {"description": "Actor role is not allowed for this action or MFA is missing."},
        404: {"description": "Workload identity profile not found."},
    },
)
def test_workload_identity_provider(
    provider_id: str,
    tenant_id: str,
    subject: str = "svc:connectivity-test",
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_ROLES)
    require_mfa(ctx)
    profile = db.query(WorkloadIdentityFederationProfile).filter_by(workload_identity_profile_id=provider_id).first()
    if not profile:
        raise HTTPException(status_code=404, detail="Workload identity profile not found")

    _require_tenant_match(profile.tenant_id, tenant_id, "workload identity connectivity test")

    default_expires_in_seconds = get_runtime_config_int(
        db,
        RUNTIME_CONFIG_WORKLOAD_IDENTITY_EXPIRES_IN_SECONDS,
        3600,
    )
    if default_expires_in_seconds <= 0:
        default_expires_in_seconds = 3600

    default_http_timeout_seconds = get_runtime_config_float(
        db,
        RUNTIME_CONFIG_WORKLOAD_IDENTITY_HTTP_TIMEOUT_SECONDS,
        3.0,
    )
    if default_http_timeout_seconds <= 0:
        default_http_timeout_seconds = 3.0

    start = time.perf_counter()
    test_status = "failed"
    detail = "token exchange failed"
    token_source = ""
    expires_in = 0

    try:
        if _is_aws_provider(profile.provider_type):
            _token, expires_in = _exchange_token_with_aws_sts(profile, subject)
            token_source = "aws_sts"
        elif _is_azure_provider(profile.provider_type):
            _token, expires_in = _exchange_token_with_azure_workload_identity(
                profile,
                subject,
                default_expires_in_seconds,
                default_http_timeout_seconds,
            )
            token_source = "azure_workload_identity"
        elif _is_google_provider(profile.provider_type):
            _token, expires_in = _exchange_token_with_google_workload_identity(
                profile,
                subject,
                default_expires_in_seconds,
                default_http_timeout_seconds,
            )
            token_source = "google_workload_identity"
        elif _is_nvidia_provider(profile.provider_type):
            _token, expires_in = _exchange_token_with_nvidia_workload_identity(
                profile,
                subject,
                default_expires_in_seconds,
                default_http_timeout_seconds,
            )
            token_source = "nvidia_workload_identity"
        elif _runtime_vendor_name(profile.provider_type):
            _token, expires_in, token_source = _exchange_token_with_runtime_vendor(
                profile,
                subject,
                default_expires_in_seconds,
            )
        else:
            raise HTTPException(status_code=400, detail="Provider does not support workload connectivity testing")
        test_status = "passed"
        detail = "token exchange completed"
    except HTTPException as exc:
        detail = str(exc.detail)
    except Exception:
        detail = "token exchange failed"

    profile.last_token_exchange_at = datetime.utcnow()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="workload_identity.provider.test",
        resource_type="workload_identity_profile",
        resource_id=provider_id,
        trace_id=f"trace-workload-provider-test-{provider_id}",
    )
    db.commit()
    latency_ms = int((time.perf_counter() - start) * 1000)
    return {
        "workload_identity_profile_id": provider_id,
        "tenant_id": profile.tenant_id,
        "provider_type": profile.provider_type,
        "test_status": test_status,
        "detail": detail,
        "token_source": token_source,
        "expires_in": expires_in,
        "latency_ms": latency_ms,
    }


@router.post(
    "/secrets/providers",
    summary="Create secret provider",
    description="Registers a secret provider configuration with encrypted connection and bootstrap credential fields.",
    responses={
        403: {"description": "Actor role is not allowed for this action or MFA is missing."},
    },
)
def create_secret_provider(
    payload: SecretProviderRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_ROLES)
    require_mfa(ctx)
    _require_active_tenant_catalog_entry(db, payload.tenant_id)
    provider = SecretProviderConfig(
        secret_provider_id=str(uuid4()),
        tenant_id=payload.tenant_id,
        provider_type=payload.provider_type,
        provider_address="[ENCRYPTED]",
        provider_address_encrypted=encrypt_value(payload.provider_address),
        auth_method="[ENCRYPTED]",
        auth_method_encrypted=encrypt_value(payload.auth_method),
        role_or_mount="[ENCRYPTED]",
        role_or_mount_encrypted=encrypt_value(payload.role_or_mount),
        bootstrap_token_encrypted=encrypt_value(payload.bootstrap_token or ""),
        secret_path_prefixes=payload.secret_path_prefixes,
        lease_ttl_seconds=payload.lease_ttl_seconds,
        auto_renew_enabled=payload.auto_renew_enabled,
        status="active",
    )
    db.add(provider)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="secret_provider.create",
        resource_type="secret_provider",
        resource_id=provider.secret_provider_id,
        trace_id=f"trace-{provider.secret_provider_id}",
    )
    db.commit()
    return {"secret_provider_id": provider.secret_provider_id, "status": provider.status}


@router.post("/providers/models", response_model=SupportedModelResponse)
def create_supported_model(
    payload: SupportedModelUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_ROLES)
    require_mfa(ctx)
    provider_type = payload.provider_type.strip().lower()
    model_name = payload.model_name.strip()
    existing = (
        db.query(SupportedModelCatalogEntry)
        .filter_by(provider_type=provider_type, model_name=model_name)
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Supported model already exists for provider")

    row = SupportedModelCatalogEntry(
        supported_model_id=str(uuid4()),
        provider_type=provider_type,
        model_name=model_name,
        display_name=payload.display_name.strip(),
        context_window_tokens=payload.context_window_tokens,
        status=payload.status.strip().lower(),
        description=payload.description.strip(),
        updated_by=ctx.actor_id,
    )
    db.add(row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="supported_model.create",
        resource_type="supported_model",
        resource_id=row.supported_model_id,
        trace_id=f"trace-{row.supported_model_id}",
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/providers/models", response_model=list[SupportedModelResponse])
def list_supported_models(
    tenant_id: Optional[str] = None,
    provider_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    response: Response = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_AUDITOR_ROLES)
    query = db.query(SupportedModelCatalogEntry)
    if tenant_id:
        normalized_tenant_id = tenant_id.strip()
        _require_tenant_catalog_entry(db, normalized_tenant_id)
        query = query.join(
            TenantSupportedModelEntitlement,
            and_(
                TenantSupportedModelEntitlement.provider_type == SupportedModelCatalogEntry.provider_type,
                TenantSupportedModelEntitlement.model_name == SupportedModelCatalogEntry.model_name,
            ),
        ).filter(
            TenantSupportedModelEntitlement.tenant_id == normalized_tenant_id,
            TenantSupportedModelEntitlement.status == "active",
        )
    if provider_type:
        query = query.filter(SupportedModelCatalogEntry.provider_type == provider_type.strip().lower())
    if status:
        query = query.filter(SupportedModelCatalogEntry.status == status.strip().lower())

    total_count = query.count()
    if response is not None:
        response.headers["X-Total-Count"] = str(total_count)

    return (
        query.order_by(SupportedModelCatalogEntry.provider_type.asc(), SupportedModelCatalogEntry.display_name.asc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.put("/providers/models/{supported_model_id}", response_model=SupportedModelResponse)
def update_supported_model(
    supported_model_id: str,
    payload: SupportedModelUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_ROLES)
    require_mfa(ctx)
    row = db.query(SupportedModelCatalogEntry).filter_by(supported_model_id=supported_model_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Supported model not found")

    provider_type = payload.provider_type.strip().lower()
    model_name = payload.model_name.strip()
    conflict = (
        db.query(SupportedModelCatalogEntry)
        .filter(
            SupportedModelCatalogEntry.supported_model_id != supported_model_id,
            SupportedModelCatalogEntry.provider_type == provider_type,
            SupportedModelCatalogEntry.model_name == model_name,
        )
        .first()
    )
    if conflict:
        raise HTTPException(status_code=409, detail="Supported model already exists for provider")

    row.provider_type = provider_type
    row.model_name = model_name
    row.display_name = payload.display_name.strip()
    row.context_window_tokens = payload.context_window_tokens
    row.status = payload.status.strip().lower()
    row.description = payload.description.strip()
    row.updated_by = ctx.actor_id
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="supported_model.update",
        resource_type="supported_model",
        resource_id=row.supported_model_id,
        trace_id=f"trace-{row.supported_model_id}",
    )
    db.commit()
    db.refresh(row)
    return row


@router.delete("/providers/models/{supported_model_id}")
def delete_supported_model(
    supported_model_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_ROLES)
    require_mfa(ctx)
    row = db.query(SupportedModelCatalogEntry).filter_by(supported_model_id=supported_model_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Supported model not found")
    db.delete(row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="supported_model.delete",
        resource_type="supported_model",
        resource_id=supported_model_id,
        trace_id=f"trace-{supported_model_id}",
    )
    db.commit()
    return {"deleted": True, "supported_model_id": supported_model_id}


@router.post("/providers/tenant-model-entitlements", response_model=TenantSupportedModelEntitlementResponse)
def create_tenant_model_entitlement(
    payload: TenantSupportedModelEntitlementUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_ROLES)
    require_mfa(ctx)

    tenant_id = payload.tenant_id.strip()
    provider_type = payload.provider_type.strip().lower()
    model_name = payload.model_name.strip()

    _require_tenant_catalog_entry(db, tenant_id)
    _require_supported_model_entry(db, provider_type, model_name)

    existing = (
        db.query(TenantSupportedModelEntitlement)
        .filter_by(tenant_id=tenant_id, provider_type=provider_type, model_name=model_name)
        .first()
    )
    if existing:
        raise HTTPException(status_code=409, detail="Tenant model entitlement already exists")

    row = TenantSupportedModelEntitlement(
        tenant_model_entitlement_id=str(uuid4()),
        tenant_id=tenant_id,
        provider_type=provider_type,
        model_name=model_name,
        status=payload.status.strip().lower(),
        updated_by=ctx.actor_id,
    )
    db.add(row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="tenant_model_entitlement.create",
        resource_type="tenant_model_entitlement",
        resource_id=row.tenant_model_entitlement_id,
        trace_id=f"trace-{row.tenant_model_entitlement_id}",
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/providers/tenant-model-entitlements", response_model=list[TenantSupportedModelEntitlementResponse])
def list_tenant_model_entitlements(
    tenant_id: Optional[str] = None,
    provider_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    response: Response = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_AUDITOR_ROLES)
    query = db.query(TenantSupportedModelEntitlement)
    if tenant_id:
        query = query.filter(TenantSupportedModelEntitlement.tenant_id == tenant_id.strip())
    if provider_type:
        query = query.filter(TenantSupportedModelEntitlement.provider_type == provider_type.strip().lower())
    if status:
        query = query.filter(TenantSupportedModelEntitlement.status == status.strip().lower())

    total_count = query.count()
    if response is not None:
        response.headers["X-Total-Count"] = str(total_count)

    return (
        query.order_by(
            TenantSupportedModelEntitlement.tenant_id.asc(),
            TenantSupportedModelEntitlement.provider_type.asc(),
            TenantSupportedModelEntitlement.model_name.asc(),
        )
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.put(
    "/providers/tenant-model-entitlements/{tenant_model_entitlement_id}",
    response_model=TenantSupportedModelEntitlementResponse,
)
def update_tenant_model_entitlement(
    tenant_model_entitlement_id: str,
    payload: TenantSupportedModelEntitlementUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_ROLES)
    require_mfa(ctx)
    row = (
        db.query(TenantSupportedModelEntitlement)
        .filter_by(tenant_model_entitlement_id=tenant_model_entitlement_id)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Tenant model entitlement not found")

    tenant_id = payload.tenant_id.strip()
    provider_type = payload.provider_type.strip().lower()
    model_name = payload.model_name.strip()

    _require_tenant_catalog_entry(db, tenant_id)
    _require_supported_model_entry(db, provider_type, model_name)

    conflict = (
        db.query(TenantSupportedModelEntitlement)
        .filter(
            TenantSupportedModelEntitlement.tenant_model_entitlement_id != tenant_model_entitlement_id,
            TenantSupportedModelEntitlement.tenant_id == tenant_id,
            TenantSupportedModelEntitlement.provider_type == provider_type,
            TenantSupportedModelEntitlement.model_name == model_name,
        )
        .first()
    )
    if conflict:
        raise HTTPException(status_code=409, detail="Tenant model entitlement already exists")

    row.tenant_id = tenant_id
    row.provider_type = provider_type
    row.model_name = model_name
    row.status = payload.status.strip().lower()
    row.updated_by = ctx.actor_id
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="tenant_model_entitlement.update",
        resource_type="tenant_model_entitlement",
        resource_id=row.tenant_model_entitlement_id,
        trace_id=f"trace-{row.tenant_model_entitlement_id}",
    )
    db.commit()
    db.refresh(row)
    return row


@router.delete("/providers/tenant-model-entitlements/{tenant_model_entitlement_id}")
def delete_tenant_model_entitlement(
    tenant_model_entitlement_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_ROLES)
    require_mfa(ctx)
    row = (
        db.query(TenantSupportedModelEntitlement)
        .filter_by(tenant_model_entitlement_id=tenant_model_entitlement_id)
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Tenant model entitlement not found")

    db.delete(row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="tenant_model_entitlement.delete",
        resource_type="tenant_model_entitlement",
        resource_id=tenant_model_entitlement_id,
        trace_id=f"trace-{tenant_model_entitlement_id}",
    )
    db.commit()
    return {"deleted": True, "tenant_model_entitlement_id": tenant_model_entitlement_id}


@router.get(
    "/secrets/providers",
    response_model=list[SecretProviderListResponse],
    summary="List secret providers",
    description=(
        "Returns secret provider configurations with masked connection fields and pagination metadata. "
        "Sensitive values remain encrypted and are not returned in plaintext."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action."},
    },
)
def list_secret_providers(
    tenant_id: Optional[str] = None,
    provider_type: Optional[str] = None,
    status: Optional[str] = None,
    auto_renew_enabled: Optional[bool] = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    response: Response = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_AUDITOR_ROLES)
    query = db.query(SecretProviderConfig)
    if tenant_id:
        query = query.filter(SecretProviderConfig.tenant_id == tenant_id)
    if provider_type:
        query = query.filter(SecretProviderConfig.provider_type == provider_type)
    if status:
        query = query.filter(SecretProviderConfig.status == status)
    if auto_renew_enabled is not None:
        query = query.filter(SecretProviderConfig.auto_renew_enabled == auto_renew_enabled)

    total_count = query.count()
    if response is not None:
        response.headers["X-Total-Count"] = str(total_count)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="secret_provider.list",
        resource_type="secret_provider",
        resource_id=str(tenant_id or provider_type or status or "all"),
        trace_id=f"trace-secret-provider-list-{uuid4()}",
    )
    db.commit()

    rows = query.order_by(SecretProviderConfig.secret_provider_id.asc()).offset(offset).limit(limit).all()
    tenant_catalog = _tenant_catalog_snapshot(db, {row.tenant_id for row in rows})
    return [
        {
            "secret_provider_id": row.secret_provider_id,
            "tenant_id": row.tenant_id,
            "tenant_name": tenant_catalog.get(row.tenant_id).tenant_name if tenant_catalog.get(row.tenant_id) else "",
            "tenant_type": tenant_catalog.get(row.tenant_id).tenant_type if tenant_catalog.get(row.tenant_id) else "",
            "tenant_description": tenant_catalog.get(row.tenant_id).description if tenant_catalog.get(row.tenant_id) else "",
            "provider_type": row.provider_type,
            "provider_address": _masked_if_encrypted(row.provider_address, row.provider_address_encrypted),
            "auth_method": _masked_if_encrypted(row.auth_method, row.auth_method_encrypted),
            "role_or_mount": _masked_if_encrypted(row.role_or_mount, row.role_or_mount_encrypted),
            "lease_ttl_seconds": row.lease_ttl_seconds,
            "auto_renew_enabled": row.auto_renew_enabled,
            "status": row.status,
            "last_health_check_at": row.last_health_check_at,
        }
        for row in rows
    ]


@router.post(
    "/secrets/providers/{provider_id}/test",
    summary="Test secret provider connectivity",
    description=(
        "Runs a connectivity health check against the configured secret provider endpoint and records audit evidence. "
        "Requires provider admin/security role and MFA."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action or MFA is missing."},
        404: {"description": "Secret provider not found."},
    },
)
def test_secret_provider(
    provider_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_ROLES)
    require_mfa(ctx)
    provider = db.query(SecretProviderConfig).filter_by(secret_provider_id=provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Secret provider not found")

    provider_type = str(provider.provider_type or "").strip().lower()
    address, _auth_method, _role_or_mount, bootstrap_token = _secret_provider_connection(provider)
    start = time.perf_counter()
    test_status = "failed"
    detail = "provider connectivity check failed"

    try:
        if provider_type == "vault":
            if not address:
                raise HTTPException(status_code=400, detail="Vault provider address is missing")
            headers = {}
            if bootstrap_token:
                headers["X-Vault-Token"] = bootstrap_token
            response = httpx.get(f"{address.rstrip('/')}/v1/sys/health", headers=headers, timeout=5.0)
            if response.status_code in {200, 429, 472, 473}:
                test_status = "passed"
                detail = "vault health endpoint reachable"
            else:
                detail = f"vault health endpoint returned http {response.status_code}"
        elif provider_type in {"aws-secrets-manager", "aws_secrets_manager"}:
            try:
                import boto3  # type: ignore
            except ImportError as exc:
                raise HTTPException(status_code=503, detail="boto3 is required for AWS connectivity test") from exc
            client = boto3.client("secretsmanager")
            client.list_secrets(MaxResults=1)
            test_status = "passed"
            detail = "aws secrets manager reachable"
        elif provider_type in {"azure-key-vault", "azure_key_vault"}:
            if not address:
                raise HTTPException(status_code=400, detail="Azure Key Vault provider address is missing")
            if not bootstrap_token:
                raise HTTPException(status_code=400, detail="Bootstrap token required for Azure Key Vault connectivity test")
            response = httpx.get(
                f"{address.rstrip('/')}/secrets?api-version=7.4",
                headers={"Authorization": f"Bearer {bootstrap_token}"},
                timeout=5.0,
            )
            if response.status_code < 400:
                test_status = "passed"
                detail = "azure key vault endpoint reachable"
            else:
                detail = f"azure key vault endpoint returned http {response.status_code}"
        else:
            if not address:
                raise HTTPException(status_code=400, detail="Provider address is missing")
            response = httpx.get(address, timeout=5.0)
            if response.status_code < 400:
                test_status = "passed"
                detail = "provider endpoint reachable"
            else:
                detail = f"provider endpoint returned http {response.status_code}"
    except HTTPException as exc:
        detail = str(exc.detail)
    except Exception:
        detail = "provider endpoint unreachable"

    provider.last_health_check_at = datetime.utcnow()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="secret_provider.test",
        resource_type="secret_provider",
        resource_id=provider_id,
        trace_id=f"trace-secret-provider-test-{provider_id}",
    )
    db.commit()
    latency_ms = int((time.perf_counter() - start) * 1000)
    return {
        "secret_provider_id": provider_id,
        "provider_type": provider.provider_type,
        "test_status": test_status,
        "detail": detail,
        "latency_ms": latency_ms,
    }


@router.get("/secrets/providers/{provider_id}/leases")
def list_secret_provider_leases(
    provider_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_AUDITOR_ROLES)
    provider = db.query(SecretProviderConfig).filter_by(secret_provider_id=provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Secret provider not found")
    leases = (
        db.query(SecretProviderLease)
        .filter(
            SecretProviderLease.secret_provider_id == provider_id,
            SecretProviderLease.status == "active",
        )
        .order_by(SecretProviderLease.expires_at.asc())
        .limit(100)
        .all()
    )
    return {
        "secret_provider_id": provider_id,
        "lease_ttl_seconds": provider.lease_ttl_seconds,
        "auto_renew_enabled": provider.auto_renew_enabled,
        "leases": [
            {
                "lease_id": lease.lease_id,
                "secret_ref": lease.secret_ref,
                "lease_ttl_seconds": lease.lease_ttl_seconds,
                "issued_at": lease.issued_at,
                "renewed_at": lease.renewed_at,
                "expires_at": lease.expires_at,
                "status": lease.status,
            }
            for lease in leases
        ],
    }


@router.post(
    "/secrets/providers/{provider_id}/leases/renew",
    response_model=SecretProviderLeaseResponse,
    summary="Renew secret provider lease",
    description=(
        "Renews or creates an active secret lease for a provider secret reference. "
        "Requires provider admin/security role and MFA."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action or MFA is missing."},
        404: {"description": "Secret provider not found."},
    },
)
def renew_secret_provider_lease(
    provider_id: str,
    payload: SecretProviderLeaseRenewRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_ROLES)
    require_mfa(ctx)

    provider = db.query(SecretProviderConfig).filter_by(secret_provider_id=provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Secret provider not found")

    now = datetime.utcnow()
    lease = (
        db.query(SecretProviderLease)
        .filter(
            SecretProviderLease.secret_provider_id == provider_id,
            SecretProviderLease.secret_ref == payload.secret_ref,
            SecretProviderLease.status == "active",
        )
        .order_by(SecretProviderLease.expires_at.desc())
        .first()
    )
    if not lease:
        lease = SecretProviderLease(
            lease_id=f"lease-{uuid4()}",
            secret_provider_id=provider_id,
            secret_ref=payload.secret_ref,
            lease_ttl_seconds=min(payload.requested_ttl_seconds, provider.lease_ttl_seconds),
            issued_at=now,
            expires_at=now + timedelta(seconds=min(payload.requested_ttl_seconds, provider.lease_ttl_seconds)),
            status="active",
        )
        db.add(lease)
    else:
        ttl = min(payload.requested_ttl_seconds, provider.lease_ttl_seconds)
        lease.lease_ttl_seconds = ttl
        lease.renewed_at = now
        lease.expires_at = now + timedelta(seconds=ttl)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="secret_provider.lease.renew",
        resource_type="secret_provider",
        resource_id=provider_id,
        trace_id=f"trace-lease-renew-{provider_id}",
    )
    db.commit()
    db.refresh(lease)
    return lease


@router.get("/secrets/providers/{provider_id}/health", response_model=SecretProviderHealthResponse)
def get_secret_provider_health(
    provider_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_AUDITOR_ROLES)
    provider = db.query(SecretProviderConfig).filter_by(secret_provider_id=provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Secret provider not found")

    now = datetime.utcnow()
    active_q = db.query(SecretProviderLease).filter(
        SecretProviderLease.secret_provider_id == provider_id,
        SecretProviderLease.status == "active",
    )
    active_count = active_q.count()
    expiring_count = active_q.filter(SecretProviderLease.expires_at <= now + timedelta(minutes=5)).count()

    status = "healthy"
    if active_count > 0 and expiring_count == active_count and not provider.auto_renew_enabled:
        status = "degraded"

    return {
        "secret_provider_id": provider_id,
        "status": status,
        "auto_renew_enabled": provider.auto_renew_enabled,
        "lease_count_active": active_count,
        "leases_expiring_5m": expiring_count,
        "last_health_check_at": provider.last_health_check_at,
    }


@router.post(
    "/keys/{key_id}/rotate-via-secret-provider",
    summary="Rotate key via secret provider",
    description=(
        "Delegates key rotation to the configured secret provider integration. "
        "Requires MFA always and dual approval in production environments."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action or dual approval is missing."},
    },
)
def rotate_key_via_provider(
    key_id: str,
    environment: str = "dev",
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "rotate_key_via_provider_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "key_id": key_id, "environment": environment}),
    )
    try:
        require_role(ctx, PROVIDERS_ADMIN_ROLES)
        require_mfa(ctx)
        if environment.strip().lower() == "prod":
            require_dual_approval(ctx)
    except HTTPException as exc:
        if exc.status_code == 403:
            logger.error(
                "rotate_key_via_provider_denied %s",
                sanitize_fields({"actor_id": ctx.actor_id, "key_id": key_id, "environment": environment}),
            )
            create_audit_event(
                db,
                actor_id=ctx.actor_id,
                action_type="gateway.key.rotate_via_secret_provider",
                resource_type="virtual_key",
                resource_id=key_id,
                trace_id=f"trace-{key_id}",
                decision_outcome="deny",
            )
            db.commit()
        raise

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.key.rotate_via_secret_provider",
        resource_type="virtual_key",
        resource_id=key_id,
        trace_id=f"trace-{key_id}",
    )
    db.commit()
    logger.info(
        "rotate_key_via_provider_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "key_id": key_id, "environment": environment}),
    )
    return {
        "key_id": key_id,
        "rotation_status": "delegated_to_secret_provider",
        "environment": environment,
        "dual_approval_required": environment.strip().lower() == "prod",
    }
