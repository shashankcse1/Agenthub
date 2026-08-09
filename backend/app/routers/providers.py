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

from app.api_errors import (
    api_error,
    authz_scope_forbidden,
    conflict_error,
    not_found_error,
    upstream_error,
    validation_error as api_validation_error,
)
from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import (
    ProviderCredentialBinding,
    SecretProviderConfig,
    SecretProviderLease,
    SecretProviderStoredValue,
    SupportedModelCatalogEntry,
    SupportedModelCatalogRevision,
    TenantCatalogEntry,
    TenantSupportedModelEntitlement,
    WorkloadIdentityFederationProfile,
)
from app.policy_constants import ROLE_MASTER_ADMIN, ROLE_PLATFORM_ADMIN, ROLE_SECURITY_APPROVER, ROLE_SUPER_ADMIN
from app.router_constants import (
    PLATFORM_AVAILABLE_MODEL_READ_ROLES,
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
    ProviderCredentialBindingResponse,
    ProviderCredentialBindingUpsertRequest,
    SecretProviderListResponse,
    SecretProviderHealthResponse,
    SecretProviderLeaseRenewRequest,
    SecretProviderLeaseResponse,
    SecretProviderRequest,
    SecretProviderValueResponse,
    SecretProviderValueUpsertRequest,
    SupportedModelApprovalRequest,
    SupportedModelCloudDiscoverRequest,
    SupportedModelCloudDiscoverResponse,
    SupportedModelCloudSyncRequest,
    SupportedModelCloudSyncResponse,
    SupportedModelResponse,
    SupportedModelSeedTrendingRequest,
    SupportedModelSeedTrendingResponse,
    SupportedModelUpsertRequest,
    InferenceReadinessResponse,
    PlatformAvailableModelsResponse,
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
from app.services.cloud_model_catalog import seed_model_catalog_specs
from app.services.cloud_model_discovery import discover_cloud_models
from app.services.inference_readiness import build_inference_readiness
from app.services.platform_available_models import list_platform_available_models
from app.services.provider_crypto import decrypt_value, encrypt_value
from app.services.provider_credential_bindings import (
    maybe_sync_gateway_cursor_binding,
    normalize_credential_source_class,
    serialize_binding,
    upsert_provider_credential_binding,
)
from app.services.trending_model_catalog import seed_trending_model_catalog
from app.services.secret_provider_values import (
    delete_db_secret_provider_value,
    is_db_secret_provider,
    mask_secret_hint,
    normalize_db_provider_defaults,
    read_db_secret_provider_value,
    upsert_db_secret_provider_value,
)
from app.services.secret_crypto import SecretCryptoError, decrypt_secret_value, encrypt_secret_value
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
    "deepseek": "DEEPSEEK",
    "google": "GOOGLE",
    "vertex": "VERTEX",
    "azure-openai": "AZURE_OPENAI",
    "azure_openai": "AZURE_OPENAI",
    "azure": "AZURE_OPENAI",
    "cursor": "CURSOR",
    "aws": "AWS_BEDROCK",
    "bedrock": "AWS_BEDROCK",
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


def _is_runtime_prod_environment() -> bool:
    from app.services.runtime_env import is_production_runtime

    return is_production_runtime()


def _required_binding_approver_role(ctx: ActorContext) -> Optional[str]:
    actor_role = str(ctx.actor_role or "").strip()
    if actor_role in {ROLE_PLATFORM_ADMIN, ROLE_SUPER_ADMIN, ROLE_MASTER_ADMIN}:
        return ROLE_SECURITY_APPROVER
    if actor_role == ROLE_SECURITY_APPROVER:
        return ROLE_PLATFORM_ADMIN
    return None


def _validate_default_binding_id(db: Session, binding_id: Optional[str], provider_type: str) -> None:
    normalized_binding_id = str(binding_id or "").strip()
    if not normalized_binding_id:
        return
    binding = db.query(ProviderCredentialBinding).filter_by(binding_id=normalized_binding_id).first()
    if not binding:
        raise not_found_error("provider_credential_binding", normalized_binding_id, decision_trace_id="providers-default-binding-not-found")
    if str(binding.provider_type or "").strip().lower() != str(provider_type or "").strip().lower():
        raise api_validation_error(
            "default_binding_id provider_type mismatch",
            decision_trace_id="providers-default-binding-type-mismatch",
            status_code=422,
        )


def _record_supported_model_revision(
    db: Session,
    row: SupportedModelCatalogEntry,
    *,
    changed_by: str,
    change_type: str,
) -> None:
    revision = SupportedModelCatalogRevision(
        revision_id=f"smr-{uuid4().hex[:16]}",
        supported_model_id=row.supported_model_id,
        metadata_version=int(row.metadata_version),
        change_type=str(change_type).strip().lower(),
        provider_type=row.provider_type,
        model_name=row.model_name,
        display_name=row.display_name,
        context_window_tokens=int(row.context_window_tokens),
        status=row.status,
        description=row.description,
        recommendation_rationale=row.recommendation_rationale,
        approval_status=row.approval_status,
        approval_ticket_ref=row.approval_ticket_ref,
        approved_by=row.approved_by,
        approved_at=row.approved_at,
        changed_by=changed_by,
    )
    db.add(revision)


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
        raise api_error(
            403,
            error_code="AUTHZ_SCOPE_FORBIDDEN",
            message=f"Tenant scope mismatch for {resource}.",
            decision_trace_id="providers-tenant-scope-mismatch",
            remediation_hint="Use the tenant identifier associated with the resource.",
            expected_tenant_id=expected_tenant_id,
            provided_tenant_id=provided_tenant_id,
        )


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
        raise not_found_error("tenant_catalog_entry", normalized_tenant_id, decision_trace_id="providers-tenant-catalog-not-found")
    if row.status != "active":
        raise api_validation_error("Tenant catalog entry is not active", decision_trace_id="providers-tenant-catalog-inactive")
    return row


def _require_tenant_catalog_entry(db: Session, tenant_id: str) -> TenantCatalogEntry:
    normalized_tenant_id = tenant_id.strip()
    row = db.query(TenantCatalogEntry).filter_by(tenant_id=normalized_tenant_id).first()
    if not row:
        raise not_found_error("tenant_catalog_entry", normalized_tenant_id, decision_trace_id="providers-tenant-catalog-not-found")
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
        raise not_found_error(
            "supported_model",
            f"{normalized_provider_type}:{normalized_model_name}",
            decision_trace_id="providers-supported-model-not-found",
        )
    return row


def _parse_allowed_subject_patterns(raw_value: str) -> list[str]:
    sample = '["agent-*", "team/platform/*"]'
    try:
        parsed = json.loads(raw_value or "[]")
    except json.JSONDecodeError as exc:
        raise api_validation_error(
            f"allowed_subject_patterns must be valid JSON. Example: {sample}",
            decision_trace_id="providers-subject-patterns-invalid-json",
        ) from exc

    if not isinstance(parsed, list) or any(not isinstance(item, str) for item in parsed):
        raise api_validation_error(
            f"allowed_subject_patterns must be a JSON array of strings. Example: {sample}",
            decision_trace_id="providers-subject-patterns-invalid-shape",
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
        raise api_error(
            503,
            error_code="SERVICE_UNAVAILABLE",
            message="AWS STS exchange requires boto3. Install boto3 and retry.",
            decision_trace_id="providers-aws-boto3-missing",
            remediation_hint="Install boto3 in the runtime environment.",
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
        raise upstream_error(
            "AWS STS AssumeRole failed for workload identity profile.",
            decision_trace_id="providers-aws-sts-assume-role-failed",
        ) from exc

    creds = resp.get("Credentials") or {}
    session_token = creds.get("SessionToken")
    expiration = creds.get("Expiration")
    if not session_token or expiration is None:
        raise upstream_error("AWS STS returned incomplete credentials.", decision_trace_id="providers-aws-sts-incomplete")

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
        raise api_error(
            503,
            error_code="SERVICE_UNAVAILABLE",
            message=f"Azure workload identity native exchange missing configuration: {', '.join(missing)}",
            decision_trace_id="providers-azure-native-config-missing",
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
        raise upstream_error(
            "Azure token endpoint request failed for workload identity profile.",
            decision_trace_id="providers-azure-token-request-failed",
        ) from exc

    if response.status_code >= 400:
        raise upstream_error(
            "Azure token endpoint returned failure for workload identity profile.",
            decision_trace_id="providers-azure-token-failure",
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise upstream_error(
            "Azure token endpoint returned non-JSON response.",
            decision_trace_id="providers-azure-token-non-json",
        ) from exc

    access_token = str(payload.get("access_token", "")).strip()
    expires_in_value = payload.get("expires_in")
    if not access_token:
        raise upstream_error(
            "Azure token endpoint returned incomplete credentials.",
            decision_trace_id="providers-azure-token-incomplete",
        )

    if isinstance(expires_in_value, str) and expires_in_value.isdigit():
        expires_in = int(expires_in_value)
    elif isinstance(expires_in_value, int):
        expires_in = expires_in_value
    else:
        expires_in = 3600

    if expires_in <= 0:
        raise upstream_error(
            "Azure token endpoint returned invalid expires_in.",
            decision_trace_id="providers-azure-token-invalid-expires",
        )

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
        raise upstream_error(
            "Google token endpoint request failed for workload identity profile.",
            decision_trace_id="providers-google-token-request-failed",
        ) from exc

    if response.status_code >= 400:
        raise upstream_error(
            "Google token endpoint returned failure for workload identity profile.",
            decision_trace_id="providers-google-token-failure",
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise upstream_error(
            "Google token endpoint returned non-JSON response.",
            decision_trace_id="providers-google-token-non-json",
        ) from exc

    access_token = str(payload.get("access_token", "")).strip()
    expires_in_value = payload.get("expires_in")
    if not access_token:
        raise upstream_error(
            "Google token endpoint returned incomplete credentials.",
            decision_trace_id="providers-google-token-incomplete",
        )

    if isinstance(expires_in_value, str) and expires_in_value.isdigit():
        expires_in = int(expires_in_value)
    elif isinstance(expires_in_value, int):
        expires_in = expires_in_value
    else:
        expires_in = 3600

    if expires_in <= 0:
        raise upstream_error(
            "Google token endpoint returned invalid expires_in.",
            decision_trace_id="providers-google-token-invalid-expires",
        )

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
        raise api_error(
            503,
            error_code="SERVICE_UNAVAILABLE",
            message=f"NVIDIA workload identity native exchange missing configuration: {', '.join(missing)}",
            decision_trace_id="providers-nvidia-native-config-missing",
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
        raise upstream_error(
            "NVIDIA token endpoint request failed for workload identity profile.",
            decision_trace_id="providers-nvidia-token-request-failed",
        ) from exc

    if response.status_code >= 400:
        raise upstream_error(
            "NVIDIA token endpoint returned failure for workload identity profile.",
            decision_trace_id="providers-nvidia-token-failure",
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise upstream_error(
            "NVIDIA token endpoint returned non-JSON response.",
            decision_trace_id="providers-nvidia-token-non-json",
        ) from exc

    access_token = str(payload.get("access_token", "")).strip()
    expires_in_value = payload.get("expires_in")
    if not access_token:
        raise upstream_error(
            "NVIDIA token endpoint returned incomplete credentials.",
            decision_trace_id="providers-nvidia-token-incomplete",
        )

    if isinstance(expires_in_value, str) and expires_in_value.isdigit():
        expires_in = int(expires_in_value)
    elif isinstance(expires_in_value, int):
        expires_in = expires_in_value
    else:
        expires_in = 3600

    if expires_in <= 0:
        raise upstream_error(
            "NVIDIA token endpoint returned invalid expires_in.",
            decision_trace_id="providers-nvidia-token-invalid-expires",
        )

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
        raise api_validation_error(
            "Live token exchange is only supported for configured workload identity providers.",
            decision_trace_id="providers-runtime-vendor-unsupported",
        )

    prefix = _RUNTIME_VENDOR_PREFIXES[vendor]
    token = (os.getenv(f"{prefix}_WORKLOAD_IDENTITY_ACCESS_TOKEN") or "").strip()
    if not token:
        raise api_error(
            503,
            error_code="SERVICE_UNAVAILABLE",
            message=f"{vendor.capitalize()} workload identity exchange requires {prefix}_WORKLOAD_IDENTITY_ACCESS_TOKEN runtime injection.",
            decision_trace_id="providers-runtime-vendor-token-missing",
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
        raise conflict_error("Tenant catalog entry already exists.", decision_trace_id="providers-tenant-catalog-exists")

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
        raise api_validation_error("tenant_id in payload must match the path", decision_trace_id="providers-tenant-id-mismatch")

    row = db.query(TenantCatalogEntry).filter_by(tenant_id=normalized_tenant_id).first()
    if not row:
        raise not_found_error("tenant_catalog_entry", normalized_tenant_id, decision_trace_id="providers-tenant-catalog-not-found")

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
        raise not_found_error(
            "workload_identity_profile",
            payload.workload_identity_profile_id,
            decision_trace_id="providers-workload-profile-not-found",
        )
    if profile.status != "active":
        logger.error(
            "workload_identity_profile_inactive %s",
            sanitize_fields({"workload_identity_profile_id": payload.workload_identity_profile_id, "status": profile.status}),
        )
        raise api_validation_error("Workload identity profile is not active", decision_trace_id="providers-workload-profile-inactive")
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
        raise authz_scope_forbidden(
            message="Subject is not allowed by workload identity profile policy.",
            actor_role=ctx.actor_role,
            required_scope="subject matches allowed_subject_patterns",
            decision_trace_id="providers-workload-subject-denied",
            remediation_hint="Use a subject that matches the profile allowed_subject_patterns.",
        )

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
        raise api_validation_error(
            (
                "Live token exchange is only supported for AWS, Azure, Google, NVIDIA, "
                "and configured runtime-token AI providers (OpenAI, Anthropic, Cohere, Mistral, Groq, Together, Fireworks, Perplexity, xAI)."
            ),
            decision_trace_id="providers-token-exchange-unsupported-provider",
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
        raise not_found_error(
            "workload_identity_profile",
            provider_id,
            decision_trace_id="providers-workload-profile-not-found",
        )

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
        raise not_found_error(
            "workload_identity_profile",
            provider_id,
            decision_trace_id="providers-workload-profile-not-found",
        )

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
        raise not_found_error(
            "workload_identity_profile",
            provider_id,
            decision_trace_id="providers-workload-profile-not-found",
        )

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
            raise api_validation_error(
                "Provider does not support workload connectivity testing",
                decision_trace_id="providers-workload-connectivity-unsupported",
            )
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
    provider_type = str(payload.provider_type or "").strip().lower()
    provider_address, auth_method, role_or_mount = normalize_db_provider_defaults(
        provider_type,
        payload.provider_address,
        payload.auth_method,
        payload.role_or_mount,
    )
    provider = SecretProviderConfig(
        secret_provider_id=str(uuid4()),
        tenant_id=payload.tenant_id,
        provider_type=provider_type,
        provider_address="[ENCRYPTED]",
        provider_address_encrypted=encrypt_value(provider_address),
        auth_method="[ENCRYPTED]",
        auth_method_encrypted=encrypt_value(auth_method),
        role_or_mount="[ENCRYPTED]",
        role_or_mount_encrypted=encrypt_value(role_or_mount),
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


@router.put(
    "/secrets/providers/{provider_id}/values",
    response_model=SecretProviderValueResponse,
    summary="Store secret value for db provider",
    description=(
        "Persists an encrypted secret value for a db-type secret provider. "
        "Plaintext is never returned on readback."
    ),
)
def upsert_secret_provider_value(
    provider_id: str,
    payload: SecretProviderValueUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_ROLES)
    require_mfa(ctx)
    provider = db.query(SecretProviderConfig).filter_by(secret_provider_id=provider_id).first()
    if not provider:
        raise not_found_error("secret_provider", provider_id, decision_trace_id="providers-secret-provider-not-found")
    if str(provider.status or "").strip().lower() != "active":
        raise api_validation_error("Secret provider is not active", decision_trace_id="providers-secret-provider-inactive")

    row = upsert_db_secret_provider_value(
        db,
        provider,
        secret_ref=payload.secret_ref,
        secret_value=payload.secret_value,
        actor_id=ctx.actor_id,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="secret_provider.value.upsert",
        resource_type="secret_provider",
        resource_id=provider_id,
        trace_id=f"trace-secret-provider-value-upsert-{provider_id}",
    )
    db.commit()
    db.refresh(row)
    return {
        "secret_provider_id": provider_id,
        "secret_ref": row.secret_ref,
        "configured": True,
        "masked_hint": mask_secret_hint(payload.secret_value),
        "updated_by": row.updated_by,
        "updated_at": row.updated_at,
    }


@router.get(
    "/secrets/providers/{provider_id}/values/{secret_ref:path}",
    response_model=SecretProviderValueResponse,
    summary="Read stored secret value status for db provider",
)
def get_secret_provider_value_status(
    provider_id: str,
    secret_ref: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_AUDITOR_ROLES)
    provider = db.query(SecretProviderConfig).filter_by(secret_provider_id=provider_id).first()
    if not provider:
        raise not_found_error("secret_provider", provider_id, decision_trace_id="providers-secret-provider-not-found")

    normalized_ref = str(secret_ref or "").strip()
    row = (
        db.query(SecretProviderStoredValue)
        .filter_by(secret_provider_id=provider_id, secret_ref=normalized_ref)
        .first()
    )
    configured = bool(row and str(row.value_encrypted or "").strip())
    masked_hint = None
    if configured:
        try:
            masked_hint = mask_secret_hint(read_db_secret_provider_value(db, provider, normalized_ref))
        except HTTPException:
            configured = False

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="secret_provider.value.read",
        resource_type="secret_provider",
        resource_id=provider_id,
        trace_id=f"trace-secret-provider-value-read-{provider_id}",
    )
    db.commit()
    return {
        "secret_provider_id": provider_id,
        "secret_ref": normalized_ref,
        "configured": configured,
        "masked_hint": masked_hint,
        "updated_by": row.updated_by if row else None,
        "updated_at": row.updated_at if row else None,
    }


@router.delete(
    "/secrets/providers/{provider_id}/values/{secret_ref:path}",
    response_model=SecretProviderValueResponse,
    summary="Delete stored secret value for db provider",
)
def delete_secret_provider_value(
    provider_id: str,
    secret_ref: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_ROLES)
    require_mfa(ctx)
    provider = db.query(SecretProviderConfig).filter_by(secret_provider_id=provider_id).first()
    if not provider:
        raise not_found_error("secret_provider", provider_id, decision_trace_id="providers-secret-provider-not-found")

    normalized_ref = str(secret_ref or "").strip()
    deleted = delete_db_secret_provider_value(db, provider, normalized_ref)
    if not deleted:
        raise not_found_error(
            "stored_secret_value",
            f"{provider_id}:{normalized_ref}",
            decision_trace_id="providers-stored-secret-not-found",
        )

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="secret_provider.value.delete",
        resource_type="secret_provider",
        resource_id=provider_id,
        trace_id=f"trace-secret-provider-value-delete-{provider_id}",
    )
    db.commit()
    return {
        "secret_provider_id": provider_id,
        "secret_ref": normalized_ref,
        "configured": False,
        "masked_hint": None,
        "updated_by": ctx.actor_id,
        "updated_at": datetime.utcnow(),
    }


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
        raise conflict_error("Supported model already exists for provider.", decision_trace_id="providers-supported-model-exists")

    row = SupportedModelCatalogEntry(
        supported_model_id=str(uuid4()),
        provider_type=provider_type,
        model_name=model_name,
        display_name=payload.display_name.strip(),
        context_window_tokens=payload.context_window_tokens,
        status=payload.status.strip().lower(),
        description=payload.description.strip(),
        recommendation_rationale=payload.recommendation_rationale.strip(),
        credential_source_class=normalize_credential_source_class(payload.credential_source_class),
        approval_status="pending",
        metadata_version=1,
        updated_by=ctx.actor_id,
    )
    _validate_default_binding_id(db, payload.default_binding_id, provider_type)
    row.default_binding_id = str(payload.default_binding_id or "").strip() or None
    db.add(row)
    _record_supported_model_revision(db, row, changed_by=ctx.actor_id, change_type="create")
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


@router.post(
    "/providers/models/seed-trending",
    response_model=SupportedModelSeedTrendingResponse,
    summary="Seed trending and cloud model packs",
    description=(
        "Upserts curated model packs. Default pack is `trending`. "
        "Pass packs=['bedrock','azure','gcp'] or packs=['all'] for hyperscaler catalogs "
        "(AWS Bedrock foundation IDs, Azure OpenAI/Foundry deployments, Google Gemini + Vertex). "
        "Existing rows are skipped unless overwrite=true. In production, new rows stay "
        "pending approval even when auto_approve is requested."
    ),
)
def seed_trending_supported_models(
    payload: SupportedModelSeedTrendingRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_ROLES)
    require_mfa(ctx)
    effective_auto_approve = bool(payload.auto_approve) and not _is_runtime_prod_environment()
    requested_packs = [str(item).strip().lower() for item in (payload.packs or ["trending"]) if str(item).strip()]
    if not requested_packs:
        requested_packs = ["trending"]
    try:
        summary = seed_trending_model_catalog(
            db,
            actor_id=ctx.actor_id,
            overwrite=bool(payload.overwrite),
            auto_approve=effective_auto_approve,
            packs=requested_packs,
        )
    except ValueError as exc:
        raise api_validation_error(str(exc), decision_trace_id="providers-seed-pack-invalid") from exc
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="supported_model.seed_trending",
        resource_type="supported_model_catalog",
        resource_id=",".join(summary.get("packs") or requested_packs) or "trending-pack",
        trace_id=f"trace-seed-trending-{uuid4()}",
        action_context=summary,
    )
    db.commit()
    return summary


@router.post(
    "/providers/models/discover-cloud",
    response_model=SupportedModelCloudDiscoverResponse,
    summary="Discover live cloud foundation/deployment models",
    description=(
        "Calls AWS Bedrock list_foundation_models / inference profiles, Azure OpenAI deployments, "
        "Google Gemini models.list, and/or Vertex publisher models using runtime credentials. "
        "Returns a preview without writing the catalog. Partial failures are returned per target."
    ),
)
def discover_cloud_supported_models(
    payload: SupportedModelCloudDiscoverRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_ROLES)
    require_mfa(ctx)
    try:
        discovered = discover_cloud_models(list(payload.targets or ["all"]), region=payload.region)
    except ValueError as exc:
        raise api_validation_error(str(exc), decision_trace_id="providers-discover-target-invalid") from exc
    models = list(discovered.get("models") or [])[: int(payload.limit)]
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="supported_model.discover_cloud",
        resource_type="supported_model_catalog",
        resource_id=",".join(discovered.get("targets") or []) or "cloud",
        trace_id=f"trace-discover-cloud-{uuid4()}",
        action_context={
            "targets": discovered.get("targets"),
            "total": discovered.get("total"),
            "returned": len(models),
            "errors": discovered.get("errors"),
            "results": discovered.get("results"),
        },
    )
    db.commit()
    return {
        "targets": discovered.get("targets") or [],
        "total": int(discovered.get("total") or 0),
        "models": models,
        "results": discovered.get("results") or [],
        "errors": discovered.get("errors") or [],
    }


@router.post(
    "/providers/models/sync-cloud",
    response_model=SupportedModelCloudSyncResponse,
    summary="Discover and upsert live cloud models into the catalog",
    description=(
        "Runs live cloud discovery then upserts discovered model IDs into the supported-model catalog. "
        "Existing rows are skipped unless overwrite=true. In production, new rows stay pending approval "
        "even when auto_approve is requested."
    ),
)
def sync_cloud_supported_models(
    payload: SupportedModelCloudSyncRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_ROLES)
    require_mfa(ctx)
    effective_auto_approve = bool(payload.auto_approve) and not _is_runtime_prod_environment()
    try:
        discovered = discover_cloud_models(list(payload.targets or ["all"]), region=payload.region)
    except ValueError as exc:
        raise api_validation_error(str(exc), decision_trace_id="providers-sync-target-invalid") from exc
    specs = discovered.get("specs") or []
    summary = seed_model_catalog_specs(
        db,
        specs,
        actor_id=ctx.actor_id,
        overwrite=bool(payload.overwrite),
        auto_approve=effective_auto_approve,
        packs_applied=list(discovered.get("targets") or []),
    )
    response_body = {
        "targets": discovered.get("targets") or [],
        "discovered": int(discovered.get("total") or 0),
        "created": int(summary.get("created") or 0),
        "updated": int(summary.get("updated") or 0),
        "skipped": int(summary.get("skipped") or 0),
        "pack_size": int(summary.get("pack_size") or 0),
        "overwrite": bool(payload.overwrite),
        "auto_approve": effective_auto_approve,
        "results": discovered.get("results") or [],
        "errors": discovered.get("errors") or [],
    }
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="supported_model.sync_cloud",
        resource_type="supported_model_catalog",
        resource_id=",".join(response_body["targets"]) or "cloud",
        trace_id=f"trace-sync-cloud-{uuid4()}",
        action_context=response_body,
    )
    db.commit()
    return response_body


@router.get(
    "/providers/models/inference-readiness",
    response_model=InferenceReadinessResponse,
    summary="AI / cloud inference readiness scorecard",
    description=(
        "Returns catalog counts and live credential/endpoint readiness for OpenAI, Anthropic, "
        "Cursor, Azure OpenAI, AWS Bedrock, Gemini, Vertex, and other configured vendors. "
        "Used by Playground and Providers to show whether selected models can invoke live."
    ),
)
def get_inference_readiness(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_AVAILABLE_MODEL_READ_ROLES)
    payload = build_inference_readiness(db)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="supported_model.inference_readiness.read",
        resource_type="supported_model_catalog",
        resource_id="inference-readiness",
        trace_id=f"trace-inference-readiness-{uuid4()}",
        action_context={
            "ready_providers": payload.get("ready_providers"),
            "catalog_models_total": payload.get("catalog_models_total"),
            "simulation_enabled": payload.get("simulation_enabled"),
        },
    )
    db.commit()
    return payload


@router.get(
    "/providers/models/available",
    response_model=PlatformAvailableModelsResponse,
    summary="Platform UI-available models (canonical register)",
    description=(
        "Returns the single canonical model list for all operator UI dropdowns. "
        "Filters by catalog status, optional approval policy, and optional tenant entitlements."
    ),
)
def list_platform_ui_available_models(
    tenant_id: Optional[str] = None,
    provider_type: Optional[str] = None,
    limit: int = Query(default=500, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PLATFORM_AVAILABLE_MODEL_READ_ROLES)
    if tenant_id:
        _require_tenant_catalog_entry(db, tenant_id.strip())
    rows, policy, total = list_platform_available_models(
        db,
        tenant_id=tenant_id,
        provider_type=provider_type,
        limit=limit,
        offset=offset,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="platform.models.available.read",
        resource_type="platform_model_availability",
        resource_id=tenant_id or "global",
        trace_id=f"trace-platform-models-available-{uuid4()}",
    )
    db.commit()
    return {
        "object": "list",
        "data": rows,
        "total": total,
        "policy": policy,
    }


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
        raise not_found_error("supported_model", supported_model_id, decision_trace_id="providers-supported-model-not-found")

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
        raise conflict_error("Supported model already exists for provider.", decision_trace_id="providers-supported-model-exists")

    row.provider_type = provider_type
    row.model_name = model_name
    row.display_name = payload.display_name.strip()
    row.context_window_tokens = payload.context_window_tokens
    row.status = payload.status.strip().lower()
    row.description = payload.description.strip()
    row.recommendation_rationale = payload.recommendation_rationale.strip()
    row.credential_source_class = normalize_credential_source_class(payload.credential_source_class)
    _validate_default_binding_id(db, payload.default_binding_id, provider_type)
    row.default_binding_id = str(payload.default_binding_id or "").strip() or None
    row.approval_status = "pending"
    row.approval_ticket_ref = None
    row.approved_by = None
    row.approved_at = None
    row.metadata_version = int(row.metadata_version or 1) + 1
    row.updated_by = ctx.actor_id
    _record_supported_model_revision(db, row, changed_by=ctx.actor_id, change_type="update")
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
        raise not_found_error("supported_model", supported_model_id, decision_trace_id="providers-supported-model-not-found")
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


@router.post("/providers/models/{supported_model_id}/approve", response_model=SupportedModelResponse)
def approve_supported_model(
    supported_model_id: str,
    payload: SupportedModelApprovalRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_ROLES)
    require_mfa(ctx)
    from app.services.runtime_env import is_prod_target_environment

    environment = str(payload.environment or "dev").strip().lower() or "dev"
    if is_prod_target_environment(environment):
        require_dual_approval(ctx)

    row = db.query(SupportedModelCatalogEntry).filter_by(supported_model_id=supported_model_id).first()
    if not row:
        raise not_found_error("supported_model", supported_model_id, decision_trace_id="providers-supported-model-not-found")

    decision = str(payload.decision).strip().lower()
    row.approval_status = "approved" if decision == "approve" else "rejected"
    row.approval_ticket_ref = payload.approval_ticket_ref.strip()
    row.approved_by = ctx.actor_id
    row.approved_at = datetime.utcnow()
    row.updated_by = ctx.actor_id
    row.metadata_version = int(row.metadata_version or 1) + 1

    if payload.approval_note.strip():
        note = payload.approval_note.strip()
        row.description = (f"{row.description.strip()}\nreview-note: {note}").strip()[:4000]

    _record_supported_model_revision(db, row, changed_by=ctx.actor_id, change_type=f"approval_{decision}")

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="supported_model.approve" if decision == "approve" else "supported_model.reject",
        resource_type="supported_model",
        resource_id=row.supported_model_id,
        trace_id=f"trace-{row.supported_model_id}-approval",
    )
    db.commit()
    db.refresh(row)
    return row


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
        raise conflict_error("Tenant model entitlement already exists.", decision_trace_id="providers-tenant-entitlement-exists")

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
        raise not_found_error(
            "tenant_model_entitlement",
            tenant_model_entitlement_id,
            decision_trace_id="providers-tenant-entitlement-not-found",
        )

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
        raise conflict_error("Tenant model entitlement already exists.", decision_trace_id="providers-tenant-entitlement-exists")

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
        raise not_found_error(
            "tenant_model_entitlement",
            tenant_model_entitlement_id,
            decision_trace_id="providers-tenant-entitlement-not-found",
        )

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
        raise not_found_error("secret_provider", provider_id, decision_trace_id="providers-secret-provider-not-found")

    provider_type = str(provider.provider_type or "").strip().lower()
    address, _auth_method, _role_or_mount, bootstrap_token = _secret_provider_connection(provider)
    start = time.perf_counter()
    test_status = "failed"
    detail = "provider connectivity check failed"

    try:
        if provider_type == "vault":
            if not address:
                raise api_validation_error("Vault provider address is missing", decision_trace_id="providers-vault-address-missing")
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
                raise api_error(
                    503,
                    error_code="SERVICE_UNAVAILABLE",
                    message="boto3 is required for AWS connectivity test",
                    decision_trace_id="providers-aws-boto3-connectivity-missing",
                ) from exc
            client = boto3.client("secretsmanager")
            client.list_secrets(MaxResults=1)
            test_status = "passed"
            detail = "aws secrets manager reachable"
        elif provider_type in {"azure-key-vault", "azure_key_vault"}:
            if not address:
                raise api_validation_error("Azure Key Vault provider address is missing", decision_trace_id="providers-azure-address-missing")
            if not bootstrap_token:
                raise api_validation_error(
                    "Bootstrap token required for Azure Key Vault connectivity test",
                    decision_trace_id="providers-azure-bootstrap-missing",
                )
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
        elif is_db_secret_provider(provider_type):
            try:
                encrypt_secret_value("connectivity-probe")
                decrypt_secret_value(encrypt_secret_value("connectivity-probe"))
            except SecretCryptoError as exc:
                raise api_error(
                    503,
                    error_code="SERVICE_UNAVAILABLE",
                    message="Database secret encryption is unavailable",
                    decision_trace_id="providers-db-encryption-unavailable",
                ) from exc
            stored_count = (
                db.query(SecretProviderStoredValue)
                .filter_by(secret_provider_id=provider_id)
                .count()
            )
            test_status = "passed"
            detail = f"database secret provider ready ({stored_count} stored value(s))"
        else:
            if not address:
                raise api_validation_error("Provider address is missing", decision_trace_id="providers-address-missing")
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
        raise not_found_error("secret_provider", provider_id, decision_trace_id="providers-secret-provider-not-found")
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
        raise not_found_error("secret_provider", provider_id, decision_trace_id="providers-secret-provider-not-found")

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
        raise not_found_error("secret_provider", provider_id, decision_trace_id="providers-secret-provider-not-found")

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
    from app.services.runtime_env import is_prod_target_environment

    try:
        require_role(ctx, PROVIDERS_ADMIN_ROLES)
        require_mfa(ctx)
        if is_prod_target_environment(environment):
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
        "dual_approval_required": is_prod_target_environment(environment),
    }


@router.post(
    "/providers/credential-bindings",
    response_model=ProviderCredentialBindingResponse,
    summary="Create provider credential binding",
)
def create_provider_credential_binding(
    payload: ProviderCredentialBindingUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_ROLES)
    require_mfa(ctx)
    from app.services.runtime_env import is_prod_target_environment

    if is_prod_target_environment(payload.environment) or _is_runtime_prod_environment():
        required_approver_role = _required_binding_approver_role(ctx)
        if required_approver_role:
            require_dual_approval(ctx, required_approver_role=required_approver_role)

    _require_active_tenant_catalog_entry(db, payload.tenant_id)
    row = upsert_provider_credential_binding(
        db,
        binding_id=None,
        tenant_id=payload.tenant_id,
        binding_name=payload.binding_name,
        consumer_type=payload.consumer_type,
        consumer_key=payload.consumer_key,
        provider_type=payload.provider_type,
        credential_plane=payload.credential_plane,
        secret_provider_id=payload.secret_provider_id,
        secret_ref=payload.secret_ref,
        workload_identity_profile_id=payload.workload_identity_profile_id,
        environment=payload.environment,
        status=payload.status,
        actor_id=ctx.actor_id,
    )
    maybe_sync_gateway_cursor_binding(db, row, ctx.actor_id)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="provider_credential_binding.create",
        resource_type="provider_credential_binding",
        resource_id=row.binding_id,
        trace_id=f"trace-provider-credential-binding-{row.binding_id}",
    )
    db.commit()
    db.refresh(row)
    return serialize_binding(db, row)


@router.get(
    "/providers/credential-bindings",
    response_model=list[ProviderCredentialBindingResponse],
    summary="List provider credential bindings",
)
def list_provider_credential_bindings(
    tenant_id: Optional[str] = Query(default=None),
    consumer_type: Optional[str] = Query(default=None),
    consumer_key: Optional[str] = Query(default=None),
    provider_type: Optional[str] = Query(default=None),
    environment: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default="active"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_AUDITOR_ROLES)
    query = db.query(ProviderCredentialBinding)
    if tenant_id:
        query = query.filter_by(tenant_id=tenant_id.strip())
    if consumer_type:
        query = query.filter_by(consumer_type=consumer_type.strip().lower())
    if consumer_key:
        query = query.filter_by(consumer_key=consumer_key.strip())
    if provider_type:
        query = query.filter_by(provider_type=provider_type.strip().lower())
    if environment:
        query = query.filter_by(environment=environment.strip().lower())
    if status:
        query = query.filter_by(status=status.strip().lower())
    rows = (
        query.order_by(ProviderCredentialBinding.updated_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="provider_credential_binding.list",
        resource_type="provider_credential_binding",
        resource_id=tenant_id or "all",
        trace_id=f"trace-provider-credential-binding-list-{uuid4()}",
    )
    db.commit()
    return [serialize_binding(db, row) for row in rows]


@router.get(
    "/providers/credential-bindings/{binding_id}",
    response_model=ProviderCredentialBindingResponse,
    summary="Read provider credential binding",
)
def get_provider_credential_binding(
    binding_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_AUDITOR_ROLES)
    row = db.query(ProviderCredentialBinding).filter_by(binding_id=binding_id.strip()).first()
    if not row:
        raise not_found_error("credential_binding", binding_id, decision_trace_id="providers-credential-binding-not-found")
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="provider_credential_binding.read",
        resource_type="provider_credential_binding",
        resource_id=row.binding_id,
        trace_id=f"trace-provider-credential-binding-read-{row.binding_id}",
    )
    db.commit()
    return serialize_binding(db, row)


@router.put(
    "/providers/credential-bindings/{binding_id}",
    response_model=ProviderCredentialBindingResponse,
    summary="Update provider credential binding",
)
def update_provider_credential_binding(
    binding_id: str,
    payload: ProviderCredentialBindingUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_ROLES)
    require_mfa(ctx)
    from app.services.runtime_env import is_prod_target_environment

    if is_prod_target_environment(payload.environment) or _is_runtime_prod_environment():
        required_approver_role = _required_binding_approver_role(ctx)
        if required_approver_role:
            require_dual_approval(ctx, required_approver_role=required_approver_role)

    _require_active_tenant_catalog_entry(db, payload.tenant_id)
    row = upsert_provider_credential_binding(
        db,
        binding_id=binding_id.strip(),
        tenant_id=payload.tenant_id,
        binding_name=payload.binding_name,
        consumer_type=payload.consumer_type,
        consumer_key=payload.consumer_key,
        provider_type=payload.provider_type,
        credential_plane=payload.credential_plane,
        secret_provider_id=payload.secret_provider_id,
        secret_ref=payload.secret_ref,
        workload_identity_profile_id=payload.workload_identity_profile_id,
        environment=payload.environment,
        status=payload.status,
        actor_id=ctx.actor_id,
    )
    maybe_sync_gateway_cursor_binding(db, row, ctx.actor_id)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="provider_credential_binding.update",
        resource_type="provider_credential_binding",
        resource_id=row.binding_id,
        trace_id=f"trace-provider-credential-binding-update-{row.binding_id}",
    )
    db.commit()
    db.refresh(row)
    return serialize_binding(db, row)


@router.delete(
    "/providers/credential-bindings/{binding_id}",
    response_model=ProviderCredentialBindingResponse,
    summary="Delete provider credential binding",
)
def delete_provider_credential_binding(
    binding_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, PROVIDERS_ADMIN_SECURITY_ROLES)
    require_mfa(ctx)
    if _is_runtime_prod_environment():
        required_approver_role = _required_binding_approver_role(ctx)
        if required_approver_role:
            require_dual_approval(ctx, required_approver_role=required_approver_role)

    row = db.query(ProviderCredentialBinding).filter_by(binding_id=binding_id.strip()).first()
    if not row:
        raise not_found_error("credential_binding", binding_id, decision_trace_id="providers-credential-binding-not-found")
    response = serialize_binding(db, row)
    db.delete(row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="provider_credential_binding.delete",
        resource_type="provider_credential_binding",
        resource_id=binding_id.strip(),
        trace_id=f"trace-provider-credential-binding-delete-{binding_id.strip()}",
    )
    db.commit()
    return response
