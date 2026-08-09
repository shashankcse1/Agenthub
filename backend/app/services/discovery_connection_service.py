from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.discovery_sources import get_discovery_source
from app.models import DiscoveryConnection, SecretProviderConfig
from app.services.credential_resolution import load_active_binding_by_id, read_secret_provider_value_at_runtime, resolve_binding_for_runtime
from app.services.discovery_connectors.types import ConnectionCredentials, ConnectionRuntime


def parse_connection_config(raw: str) -> dict[str, Any]:
    text = str(raw or "").strip() or "{}"
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail="connection_config must be valid JSON") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="connection_config must be a JSON object")
    return payload


def serialize_connection_config(config: dict[str, Any]) -> str:
    return json.dumps(config or {}, sort_keys=True)


def connection_response_payload(row: DiscoveryConnection) -> dict[str, Any]:
    return {
        "connection_id": row.connection_id,
        "tenant_id": row.tenant_id,
        "source_id": row.source_id,
        "connection_name": row.connection_name,
        "status": row.status,
        "enabled": row.enabled,
        "sync_interval_minutes": row.sync_interval_minutes,
        "next_sync_at": row.next_sync_at,
        "last_sync_at": row.last_sync_at,
        "last_sync_status": row.last_sync_status,
        "last_sync_error": row.last_sync_error or "",
        "last_discovered_count": row.last_discovered_count,
        "credential_binding_id": row.credential_binding_id,
        "secret_provider_id": row.secret_provider_id,
        "secret_ref": row.secret_ref,
        "base_url": row.base_url or "",
        "connection_config": parse_connection_config(row.connection_config_json),
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "updated_by": row.updated_by,
    }


def _validate_source_id(source_id: str) -> None:
    if get_discovery_source(source_id) is None:
        raise HTTPException(status_code=400, detail="Unsupported discovery source")


def _validate_credentials_fields(
    *,
    credential_binding_id: Optional[str],
    secret_provider_id: Optional[str],
    secret_ref: Optional[str],
    source_id: str,
) -> None:
    from app.services.discovery_connectors.registry import INTERNAL_PLATFORM_SOURCES

    if source_id in INTERNAL_PLATFORM_SOURCES:
        return
    binding_id = str(credential_binding_id or "").strip()
    provider_id = str(secret_provider_id or "").strip()
    ref = str(secret_ref or "").strip()
    if binding_id:
        return
    if provider_id and ref:
        return
    raise HTTPException(
        status_code=422,
        detail="External discovery connections require credential_binding_id or secret_provider_id + secret_ref",
    )


def resolve_connection_credentials(db: Session, connection: DiscoveryConnection) -> ConnectionCredentials:
    binding_id = str(connection.credential_binding_id or "").strip()
    if binding_id:
        binding = load_active_binding_by_id(db, binding_id)
        resolved = resolve_binding_for_runtime(db, binding)
        return ConnectionCredentials(
            provider_type=resolved.provider_type,
            secret_value=resolved.secret_value,
            workload_identity_profile_id=resolved.workload_identity_profile_id,
            credential_binding_id=binding_id,
        )

    provider_id = str(connection.secret_provider_id or "").strip()
    secret_ref = str(connection.secret_ref or "").strip()
    if provider_id and secret_ref:
        secret_value = read_secret_provider_value_at_runtime(db, provider_id, secret_ref)
        provider = db.query(SecretProviderConfig).filter_by(secret_provider_id=provider_id).first()
        provider_type = str(provider.provider_type if provider else connection.source_id).strip().lower()
        return ConnectionCredentials(
            provider_type=provider_type,
            secret_value=secret_value,
        )

    from app.services.discovery_connectors.registry import INTERNAL_PLATFORM_SOURCES

    if connection.source_id in INTERNAL_PLATFORM_SOURCES:
        return ConnectionCredentials(provider_type="agenthub", secret_value=None)
    raise HTTPException(status_code=422, detail="Discovery connection credentials are not configured")


def build_connection_runtime(db: Session, connection: DiscoveryConnection) -> ConnectionRuntime:
    credentials = resolve_connection_credentials(db, connection)
    return ConnectionRuntime(
        connection_id=connection.connection_id,
        tenant_id=connection.tenant_id,
        source_id=connection.source_id,
        base_url=str(connection.base_url or "").strip(),
        config=parse_connection_config(connection.connection_config_json),
        credentials=credentials,
    )


def create_discovery_connection(
    db: Session,
    *,
    payload: dict[str, Any],
    actor_id: str,
) -> DiscoveryConnection:
    source_id = str(payload.get("source_id") or "").strip()
    _validate_source_id(source_id)
    _validate_credentials_fields(
        credential_binding_id=payload.get("credential_binding_id"),
        secret_provider_id=payload.get("secret_provider_id"),
        secret_ref=payload.get("secret_ref"),
        source_id=source_id,
    )
    now = datetime.utcnow()
    interval = int(payload.get("sync_interval_minutes") or 60)
    row = DiscoveryConnection(
        connection_id=f"dconn-{uuid4()}",
        tenant_id=str(payload.get("tenant_id") or "").strip(),
        source_id=source_id,
        connection_name=str(payload.get("connection_name") or "").strip(),
        status="active",
        enabled=bool(payload.get("enabled", True)),
        sync_interval_minutes=interval,
        next_sync_at=now,
        credential_binding_id=str(payload.get("credential_binding_id") or "").strip() or None,
        secret_provider_id=str(payload.get("secret_provider_id") or "").strip() or None,
        secret_ref=str(payload.get("secret_ref") or "").strip() or None,
        base_url=str(payload.get("base_url") or "").strip(),
        connection_config_json=serialize_connection_config(payload.get("connection_config") or {}),
        updated_by=actor_id,
    )
    if not row.tenant_id or not row.connection_name:
        raise HTTPException(status_code=422, detail="tenant_id and connection_name are required")
    db.add(row)
    return row


def update_discovery_connection(
    db: Session,
    connection: DiscoveryConnection,
    *,
    payload: dict[str, Any],
    actor_id: str,
) -> DiscoveryConnection:
    if payload.get("connection_name") is not None:
        connection.connection_name = str(payload.get("connection_name") or "").strip()
    if payload.get("enabled") is not None:
        connection.enabled = bool(payload.get("enabled"))
    if payload.get("status") is not None:
        connection.status = str(payload.get("status") or "").strip() or connection.status
    if payload.get("sync_interval_minutes") is not None:
        connection.sync_interval_minutes = int(payload.get("sync_interval_minutes"))
    if payload.get("credential_binding_id") is not None:
        connection.credential_binding_id = str(payload.get("credential_binding_id") or "").strip() or None
    if payload.get("secret_provider_id") is not None:
        connection.secret_provider_id = str(payload.get("secret_provider_id") or "").strip() or None
    if payload.get("secret_ref") is not None:
        connection.secret_ref = str(payload.get("secret_ref") or "").strip() or None
    if payload.get("base_url") is not None:
        connection.base_url = str(payload.get("base_url") or "").strip()
    if payload.get("connection_config") is not None:
        connection.connection_config_json = serialize_connection_config(payload.get("connection_config") or {})

    _validate_credentials_fields(
        credential_binding_id=connection.credential_binding_id,
        secret_provider_id=connection.secret_provider_id,
        secret_ref=connection.secret_ref,
        source_id=connection.source_id,
    )
    connection.updated_by = actor_id
    connection.updated_at = datetime.utcnow()
    return connection


def schedule_next_sync(connection: DiscoveryConnection, *, from_time: Optional[datetime] = None) -> None:
    anchor = from_time or datetime.utcnow()
    minutes = max(5, int(connection.sync_interval_minutes or 60))
    connection.next_sync_at = anchor + timedelta(minutes=minutes)
