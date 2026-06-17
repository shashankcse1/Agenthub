from __future__ import annotations

import json
from datetime import datetime
from fnmatch import fnmatch

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import SecretProviderConfig, SecretProviderStoredValue
from app.services.secret_crypto import SecretCryptoError, decrypt_secret_value, encrypt_secret_value

SECRET_PROVIDER_TYPE_DB = "db"
GATEWAY_CURSOR_DEFAULT_SECRET_REF = "gateway/cursor-token"


def is_db_secret_provider(provider_type: str) -> bool:
    return str(provider_type or "").strip().lower() == SECRET_PROVIDER_TYPE_DB


def normalize_db_provider_defaults(
    provider_type: str,
    provider_address: str,
    auth_method: str,
    role_or_mount: str,
) -> tuple[str, str, str]:
    if not is_db_secret_provider(provider_type):
        return provider_address, auth_method, role_or_mount
    return (
        str(provider_address or "").strip() or "platform://database",
        str(auth_method or "").strip() or "encrypted-at-rest",
        str(role_or_mount or "").strip() or "platform",
    )


def _secret_ref_allowed(secret_path_prefixes: str, secret_ref: str) -> bool:
    normalized_ref = str(secret_ref or "").strip()
    if not normalized_ref:
        return False
    raw = str(secret_path_prefixes or "").strip()
    if not raw or raw == "[]":
        return True
    try:
        prefixes = json.loads(raw)
    except json.JSONDecodeError:
        return False
    if not isinstance(prefixes, list) or not prefixes:
        return True
    return any(
        normalized_ref.startswith(str(prefix or "").strip())
        or fnmatch(normalized_ref, str(prefix or "").strip())
        for prefix in prefixes
    )


def require_db_secret_provider(provider: SecretProviderConfig) -> SecretProviderConfig:
    if not is_db_secret_provider(provider.provider_type):
        raise HTTPException(status_code=400, detail="Secret value operations require a db secret provider")
    return provider


def mask_secret_hint(secret_value: str) -> str | None:
    normalized = str(secret_value or "").strip()
    if not normalized:
        return None
    if len(normalized) <= 8:
        return "***"
    return f"{normalized[:4]}***{normalized[-4:]}"


def read_db_secret_provider_value(db: Session, provider: SecretProviderConfig, secret_ref: str) -> str:
    require_db_secret_provider(provider)
    normalized_ref = str(secret_ref or "").strip()
    if not normalized_ref:
        raise HTTPException(status_code=422, detail="secret_ref is required")
    if not _secret_ref_allowed(provider.secret_path_prefixes, normalized_ref):
        raise HTTPException(status_code=403, detail="secret_ref is outside allowed path prefixes")

    row = (
        db.query(SecretProviderStoredValue)
        .filter_by(secret_provider_id=provider.secret_provider_id, secret_ref=normalized_ref)
        .first()
    )
    if not row or not str(row.value_encrypted or "").strip():
        raise HTTPException(status_code=404, detail="Stored secret value not found")
    try:
        return decrypt_secret_value(row.value_encrypted).strip()
    except SecretCryptoError as exc:
        raise HTTPException(status_code=500, detail="Stored secret value is unreadable") from exc


def upsert_db_secret_provider_value(
    db: Session,
    provider: SecretProviderConfig,
    *,
    secret_ref: str,
    secret_value: str,
    actor_id: str,
) -> SecretProviderStoredValue:
    require_db_secret_provider(provider)
    normalized_ref = str(secret_ref or "").strip()
    normalized_value = str(secret_value or "").strip()
    if not normalized_ref:
        raise HTTPException(status_code=422, detail="secret_ref is required")
    if not normalized_value:
        raise HTTPException(status_code=422, detail="secret_value cannot be empty")
    if not _secret_ref_allowed(provider.secret_path_prefixes, normalized_ref):
        raise HTTPException(status_code=403, detail="secret_ref is outside allowed path prefixes")

    try:
        encrypted = encrypt_secret_value(normalized_value)
    except SecretCryptoError as exc:
        raise HTTPException(status_code=503, detail="Secret encryption is unavailable") from exc

    row = (
        db.query(SecretProviderStoredValue)
        .filter_by(secret_provider_id=provider.secret_provider_id, secret_ref=normalized_ref)
        .first()
    )
    now = datetime.utcnow()
    if row:
        row.value_encrypted = encrypted
        row.updated_by = actor_id
        row.updated_at = now
    else:
        row = SecretProviderStoredValue(
            secret_provider_id=provider.secret_provider_id,
            secret_ref=normalized_ref,
            value_encrypted=encrypted,
            updated_by=actor_id,
            updated_at=now,
        )
        db.add(row)
    return row


def delete_db_secret_provider_value(db: Session, provider: SecretProviderConfig, secret_ref: str) -> bool:
    require_db_secret_provider(provider)
    normalized_ref = str(secret_ref or "").strip()
    if not normalized_ref:
        raise HTTPException(status_code=422, detail="secret_ref is required")
    row = (
        db.query(SecretProviderStoredValue)
        .filter_by(secret_provider_id=provider.secret_provider_id, secret_ref=normalized_ref)
        .first()
    )
    if not row:
        return False
    db.delete(row)
    return True
