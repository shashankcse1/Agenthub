from __future__ import annotations

import json
from typing import Any, Optional

from sqlalchemy import and_
from sqlalchemy.orm import Session

from app.models import SupportedModelCatalogEntry, TenantSupportedModelEntitlement
from app.runtime_constants import (
    RUNTIME_CONFIG_PLATFORM_UI_MODELS_CATALOG_STATUSES,
    RUNTIME_CONFIG_PLATFORM_UI_MODELS_ENFORCE_TENANT_ENTITLEMENTS,
    RUNTIME_CONFIG_PLATFORM_UI_MODELS_REQUIRE_APPROVAL,
)
from app.services.runtime_config import get_runtime_config


def _parse_status_allowlist(raw: str) -> list[str]:
    default = ["active", "beta"]
    value = str(raw or "").strip()
    if not value:
        return default
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return default
    if not isinstance(parsed, list):
        return default
    normalized = [str(item).strip().lower() for item in parsed if str(item).strip()]
    return normalized or default


def _runtime_bool(raw: str, fallback: bool = False) -> bool:
    normalized = str(raw or "").strip().lower()
    if not normalized:
        return fallback
    return normalized in {"1", "true", "yes", "on", "enabled"}


def build_model_ref(provider_type: str, model_name: str) -> str:
    provider = str(provider_type or "").strip().lower()
    model = str(model_name or "").strip()
    if not model:
        return ""
    if not provider:
        return model
    if model.lower().startswith(f"{provider}/"):
        return model
    return f"{provider}/{model}"


def resolve_platform_model_availability_policy(db: Session) -> dict[str, Any]:
    return {
        "catalog_statuses": _parse_status_allowlist(
            get_runtime_config(db, RUNTIME_CONFIG_PLATFORM_UI_MODELS_CATALOG_STATUSES, '["active","beta"]')
        ),
        "require_approval": _runtime_bool(
            get_runtime_config(db, RUNTIME_CONFIG_PLATFORM_UI_MODELS_REQUIRE_APPROVAL, "false"),
            False,
        ),
        "enforce_tenant_entitlements": _runtime_bool(
            get_runtime_config(db, RUNTIME_CONFIG_PLATFORM_UI_MODELS_ENFORCE_TENANT_ENTITLEMENTS, "false"),
            False,
        ),
    }


def serialize_platform_available_model(row: SupportedModelCatalogEntry, *, priority_rank: int) -> dict[str, Any]:
    model_ref = build_model_ref(row.provider_type, row.model_name)
    return {
        "supported_model_id": row.supported_model_id,
        "provider_type": row.provider_type,
        "model_name": row.model_name,
        "model_ref": model_ref,
        "display_name": row.display_name,
        "status": row.status,
        "approval_status": row.approval_status,
        "context_window_tokens": int(row.context_window_tokens or 0),
        "ui_available": True,
        "ui_priority_rank": priority_rank,
    }


def list_platform_available_models(
    db: Session,
    *,
    tenant_id: Optional[str] = None,
    provider_type: Optional[str] = None,
    limit: int = 500,
    offset: int = 0,
) -> tuple[list[dict[str, Any]], dict[str, Any], int]:
    policy = resolve_platform_model_availability_policy(db)
    allowed_statuses = policy["catalog_statuses"]

    query = db.query(SupportedModelCatalogEntry).filter(
        SupportedModelCatalogEntry.status.in_(allowed_statuses)
    )
    if policy["require_approval"]:
        query = query.filter(SupportedModelCatalogEntry.approval_status == "approved")

    normalized_tenant_id = str(tenant_id or "").strip()
    if normalized_tenant_id and policy["enforce_tenant_entitlements"]:
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

    total_count = int(query.count())
    rows = (
        query.order_by(
            SupportedModelCatalogEntry.provider_type.asc(),
            SupportedModelCatalogEntry.display_name.asc(),
            SupportedModelCatalogEntry.model_name.asc(),
        )
        .offset(max(0, offset))
        .limit(max(1, min(limit, 500)))
        .all()
    )

    payload = [
        serialize_platform_available_model(row, priority_rank=index + 1 + offset)
        for index, row in enumerate(rows)
    ]
    return payload, policy, total_count
