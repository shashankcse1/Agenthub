from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import RuntimeConfig
from app.runtime_constants import RUNTIME_CONFIG_DEFAULTS
from app.services.config_cache import runtime_config_cache


def get_runtime_config(db: Session, key: str, fallback: str | None = None) -> str:
    cached = runtime_config_cache.get(key)
    if cached is not None:
        return cached

    row = db.query(RuntimeConfig).filter_by(config_key=key).first()
    resolved = ""
    if row and row.config_value.strip() != "":
        resolved = row.config_value.strip()
    elif fallback is not None:
        resolved = fallback
    else:
        resolved = RUNTIME_CONFIG_DEFAULTS.get(key, "")

    runtime_config_cache.set(key, resolved)
    return resolved


def get_runtime_config_int(db: Session, key: str, fallback: int) -> int:
    value = get_runtime_config(db, key, str(fallback))
    try:
        return int(value)
    except ValueError:
        return fallback


def get_runtime_config_float(db: Session, key: str, fallback: float) -> float:
    value = get_runtime_config(db, key, str(fallback))
    try:
        return float(value)
    except ValueError:
        return fallback


def invalidate_runtime_config_cache(key: str) -> None:
    runtime_config_cache.delete(key)


def upsert_runtime_config_value(
    db: Session,
    key: str,
    value: str,
    *,
    description: str = "",
) -> RuntimeConfig:
    """Upsert a runtime config row, flush (autoflush may be off), and refresh cache."""
    normalized_key = str(key or "").strip()
    if not normalized_key:
        raise ValueError("config_key is required")
    normalized_value = str(value)
    row = db.query(RuntimeConfig).filter_by(config_key=normalized_key).first()
    if row is None:
        row = RuntimeConfig(
            config_key=normalized_key,
            config_value=normalized_value,
            description=str(description or ""),
        )
        db.add(row)
    else:
        row.config_value = normalized_value
        if description:
            row.description = str(description)
    # Sessions are created with autoflush=False; without flush, same-request
    # get_runtime_config() misses the pending row and re-caches the fallback.
    db.flush()
    runtime_config_cache.set(normalized_key, normalized_value.strip())
    return row