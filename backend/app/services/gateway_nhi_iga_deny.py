"""Inbound IGA deny signals (external IGA platforms) → optional inference gate."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_NHI_IGA_DENY_JSON
from app.services.runtime_config import get_runtime_config, upsert_runtime_config_value
from app.services.url_ssrf_guard import ingest_timestamp_skew_ok

ALLOWED_MODES = frozenset({"off", "warn", "block"})
ALLOWED_SUBJECT_TYPES = frozenset(
    {
        "actor_id",
        "virtual_key_id",
        "nhi_record_id",
        "source_id",
        "owner_scope_id",
        "tenant_id",
    }
)
ALLOWED_SOURCE_SYSTEMS = frozenset(
    {"generic", "external_iga", "astrix", "oasis", "aembit"}
)
# Legacy API token → canonical (stored configs / inbound webhooks).
_LEGACY_SOURCE_ALIASES = {"saviynt_zuma": "external_iga"}


def canonicalize_source_system(value: object) -> str:
    raw = str(value or "").strip().lower()
    return _LEGACY_SOURCE_ALIASES.get(raw, raw)

MAX_EVENT_HISTORY = 200
MAX_SEEN_NONCES = 500

DEFAULT_CONFIG: dict[str, Any] = {
    "enabled": False,
    "mode": "off",
    "ingest_hmac_secret": "",
    "require_ingest_hmac": True,
    "require_ingest_timestamp": False,
    "max_ingest_skew_seconds": 300,
    "default_ttl_seconds": 86400,
    "max_active_denies": 200,
    "allowed_source_systems": ["generic", "external_iga", "astrix", "oasis", "aembit"],
    "active_denies": [],
    "event_history": [],
    "seen_nonces": [],
}


def _app_env() -> str:
    from app.services.runtime_env import runtime_environment

    return runtime_environment()


def _is_production_runtime() -> bool:
    from app.services.runtime_env import is_production_runtime

    return is_production_runtime()


def _clamp_ttl(value: object) -> int:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        parsed = 86400
    return max(60, min(30 * 86400, parsed))


def _clamp_max_active(value: object) -> int:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        parsed = 200
    return max(1, min(500, parsed))


def _parse_dt(raw: object) -> Optional[datetime]:
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return raw
    text = str(raw or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(text).replace(tzinfo=None)
    except ValueError:
        return None


def _iso(dt: Optional[datetime]) -> Optional[str]:
    if dt is None:
        return None
    return dt.isoformat() + "Z"


def build_ingest_signing_material(
    body: bytes,
    *,
    timestamp: str = "",
    nonce: str = "",
) -> bytes:
    """Canonical HMAC material: `{timestamp}.{nonce}.{body}` (binds freshness headers)."""
    ts = str(timestamp or "").strip()
    n = str(nonce or "").strip()
    return f"{ts}.{n}.".encode("utf-8") + body


def sign_ingest_body(
    secret: str,
    body: bytes,
    *,
    timestamp: str = "",
    nonce: str = "",
) -> str:
    material = build_ingest_signing_material(body, timestamp=timestamp, nonce=nonce)
    return hmac.new(secret.encode("utf-8"), material, hashlib.sha256).hexdigest()


def verify_ingest_signature(
    *,
    secret: str,
    body: bytes,
    provided: str,
    timestamp: str = "",
    nonce: str = "",
    allow_legacy_body_only: bool = False,
) -> bool:
    got = str(provided or "").strip().lower()
    if not got:
        return False
    expected = sign_ingest_body(secret, body, timestamp=timestamp, nonce=nonce).lower()
    if hmac.compare_digest(expected, got):
        return True
    # Legacy body-only signatures (pre freshness-binding) — only when explicitly allowed
    # and no freshness headers were supplied.
    if allow_legacy_body_only and not str(timestamp or "").strip() and not str(nonce or "").strip():
        legacy = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest().lower()
        return hmac.compare_digest(legacy, got)
    return False


def _prune_denies(
    denies: list[dict[str, Any]],
    *,
    now: Optional[datetime] = None,
    expired_out: Optional[list[dict[str, Any]]] = None,
) -> list[dict[str, Any]]:
    current = now or datetime.utcnow()
    kept: list[dict[str, Any]] = []
    for row in denies:
        if not isinstance(row, dict):
            continue
        if str(row.get("status") or "active").strip().lower() != "active":
            continue
        expires_at = _parse_dt(row.get("expires_at"))
        if expires_at is not None and expires_at <= current:
            if expired_out is not None:
                expired_out.append(row)
            continue
        kept.append(row)
    return kept


def _append_deny_event(store: dict[str, Any], event: dict[str, Any]) -> None:
    history = list(store.get("event_history") or [])
    row = {
        "event_id": f"iga-deny-evt-{uuid4().hex[:12]}",
        "at": datetime.utcnow().isoformat() + "Z",
        **{k: v for k, v in event.items() if v is not None},
    }
    history.insert(0, row)
    store["event_history"] = history[:MAX_EVENT_HISTORY]


def _clamp_skew(value: object) -> int:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        parsed = 300
    return max(30, min(3600, parsed))


def verify_ingest_anti_replay(
    store: dict[str, Any],
    *,
    timestamp_header: Optional[str],
    nonce_header: Optional[str],
    require_timestamp: bool,
    max_skew_seconds: int,
    nonce_header_name: str = "X-Gateway-Iga-Nonce",
    nonce_store_key: str = "seen_nonces",
    failure_prefix: str = "IGA deny ingest freshness failed",
) -> None:
    """Fail closed on missing/stale timestamp or replayed nonce when required."""
    if require_timestamp:
        ok, reason = ingest_timestamp_skew_ok(
            timestamp_header,
            max_skew_seconds=max_skew_seconds,
        )
        if not ok:
            raise HTTPException(status_code=401, detail=f"{failure_prefix}: {reason}")
        nonce = str(nonce_header or "").strip()
        if not nonce:
            raise HTTPException(
                status_code=401,
                detail=f"{failure_prefix}: {nonce_header_name} is required",
            )
    elif timestamp_header:
        ok, reason = ingest_timestamp_skew_ok(
            timestamp_header,
            max_skew_seconds=max_skew_seconds,
        )
        if not ok:
            raise HTTPException(status_code=401, detail=f"{failure_prefix}: {reason}")

    nonce = str(nonce_header or "").strip()
    if not nonce:
        return
    if len(nonce) > 128:
        raise HTTPException(status_code=422, detail=f"{nonce_header_name} must be <= 128 chars")
    key = str(nonce_store_key or "seen_nonces").strip() or "seen_nonces"
    seen = [str(item) for item in list(store.get(key) or []) if str(item)]
    if nonce in seen:
        raise HTTPException(status_code=401, detail=f"{failure_prefix}: nonce replay detected")
    seen.insert(0, nonce)
    store[key] = seen[:MAX_SEEN_NONCES]


def list_iga_deny_events(db: Session, *, limit: int = 50) -> dict[str, Any]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_NHI_IGA_DENY_JSON, "")
    try:
        store = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        store = {}
    if not isinstance(store, dict):
        store = {}
    history = [row for row in list(store.get("event_history") or []) if isinstance(row, dict)]
    limit_n = max(1, min(200, int(limit or 50)))
    return {
        "event_count": len(history[:limit_n]),
        "total_events": len(history),
        "events": history[:limit_n],
        "notes": (
            "Ring-buffer deny lifecycle evidence (ingest/revoke/expire) for IGA coexistence audits. "
            "Not a durable enterprise SIEM; capped at 200 events in runtime config."
        ),
    }


def normalize_deny_config(raw: dict[str, Any] | None, *, reveal_secret: bool = False) -> dict[str, Any]:
    src = dict(DEFAULT_CONFIG)
    if isinstance(raw, dict):
        src.update(raw)
    mode = str(src.get("mode") or "off").strip().lower() or "off"
    if mode not in ALLOWED_MODES:
        raise HTTPException(status_code=422, detail=f"mode must be one of: {', '.join(sorted(ALLOWED_MODES))}")
    enabled = bool(src.get("enabled"))
    if not enabled:
        mode = "off"
    allowed_sources = src.get("allowed_source_systems") or list(ALLOWED_SOURCE_SYSTEMS)
    if not isinstance(allowed_sources, list):
        raise HTTPException(status_code=422, detail="allowed_source_systems must be a list")
    normalized_sources: list[str] = []
    for item in allowed_sources:
        value = canonicalize_source_system(item)
        if value not in ALLOWED_SOURCE_SYSTEMS:
            raise HTTPException(
                status_code=422,
                detail=f"allowed_source_systems entries must be one of: {', '.join(sorted(ALLOWED_SOURCE_SYSTEMS))}",
            )
        if value not in normalized_sources:
            normalized_sources.append(value)
    secret = str(src.get("ingest_hmac_secret") or "")
    active = _prune_denies(list(src.get("active_denies") or []))
    for row in active:
        if isinstance(row, dict) and row.get("source_system"):
            row["source_system"] = canonicalize_source_system(row.get("source_system"))
    history = [row for row in list(src.get("event_history") or []) if isinstance(row, dict)]
    for row in history:
        if isinstance(row, dict) and row.get("source_system"):
            row["source_system"] = canonicalize_source_system(row.get("source_system"))
    require_hmac = bool(src.get("require_ingest_hmac", True))
    if "require_ingest_timestamp" in src:
        require_ts = bool(src.get("require_ingest_timestamp"))
    else:
        require_ts = _is_production_runtime()
    if _is_production_runtime() and enabled:
        require_hmac = True
        require_ts = True
    out = {
        "enabled": enabled,
        "mode": mode,
        "require_ingest_hmac": require_hmac,
        "require_ingest_timestamp": require_ts,
        "max_ingest_skew_seconds": _clamp_skew(src.get("max_ingest_skew_seconds")),
        "default_ttl_seconds": _clamp_ttl(src.get("default_ttl_seconds")),
        "max_active_denies": _clamp_max_active(src.get("max_active_denies")),
        "allowed_source_systems": normalized_sources,
        "ingest_hmac_secret_configured": bool(secret.strip()),
        "active_deny_count": len(active),
        "event_history_count": len(history),
        "active_denies": [
            {
                "deny_id": row.get("deny_id"),
                "subject_type": row.get("subject_type"),
                "subject_id": row.get("subject_id"),
                "tenant_id": row.get("tenant_id"),
                "environment": row.get("environment"),
                "reason": row.get("reason"),
                "source_system": row.get("source_system"),
                "external_ref": row.get("external_ref"),
                "status": row.get("status") or "active",
                "created_at": row.get("created_at"),
                "expires_at": row.get("expires_at"),
            }
            for row in active
        ],
    }
    if reveal_secret:
        out["ingest_hmac_secret"] = secret
    else:
        out["ingest_hmac_secret"] = ""
    return out


def load_iga_deny_config(db: Session, *, reveal_secret: bool = False) -> dict[str, Any]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_NHI_IGA_DENY_JSON, "")
    parsed: dict[str, Any] = {}
    if raw.strip():
        try:
            loaded = json.loads(raw)
            if isinstance(loaded, dict):
                parsed = loaded
        except json.JSONDecodeError:
            parsed = {}
    return normalize_deny_config(parsed, reveal_secret=reveal_secret)


def _store_config(db: Session, store: dict[str, Any], *, actor_id: str) -> dict[str, Any]:
    store = dict(store)
    store["updated_by"] = str(actor_id or "").strip() or "unknown"
    store["updated_at"] = datetime.utcnow().isoformat() + "Z"
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_GATEWAY_NHI_IGA_DENY_JSON,
        json.dumps(store, separators=(",", ":"), default=str),
        description="NHI IGA inbound deny signals + inference gate (GOV-AI-IDSEC-NHI-003)",
    )
    return normalize_deny_config(store, reveal_secret=False)


def save_iga_deny_config(db: Session, payload: dict[str, Any], *, actor_id: str) -> dict[str, Any]:
    current = load_iga_deny_config(db, reveal_secret=True)
    incoming = dict(payload or {})
    if not str(incoming.get("ingest_hmac_secret") or "").strip() and current.get("ingest_hmac_secret"):
        incoming["ingest_hmac_secret"] = current["ingest_hmac_secret"]
    normalized = normalize_deny_config(incoming, reveal_secret=True)
    if normalized.get("enabled") and not str(normalized.get("ingest_hmac_secret") or "").strip():
        if normalized.get("require_ingest_hmac") or _is_production_runtime():
            raise HTTPException(
                status_code=422,
                detail="ingest_hmac_secret is required when IGA deny ingest is enabled with HMAC",
            )
    if _is_production_runtime() and normalized.get("enabled"):
        normalized["require_ingest_hmac"] = True
        normalized["require_ingest_timestamp"] = True
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_NHI_IGA_DENY_JSON, "")
    try:
        raw_obj = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        raw_obj = {}
    expired: list[dict[str, Any]] = []
    active = _prune_denies(list(raw_obj.get("active_denies") or []), expired_out=expired)
    history = [row for row in list(raw_obj.get("event_history") or []) if isinstance(row, dict)]
    store = {
        "enabled": normalized["enabled"],
        "mode": normalized["mode"],
        "ingest_hmac_secret": str(normalized.get("ingest_hmac_secret") or ""),
        "require_ingest_hmac": normalized["require_ingest_hmac"],
        "require_ingest_timestamp": normalized["require_ingest_timestamp"],
        "max_ingest_skew_seconds": normalized["max_ingest_skew_seconds"],
        "default_ttl_seconds": normalized["default_ttl_seconds"],
        "max_active_denies": normalized["max_active_denies"],
        "allowed_source_systems": normalized["allowed_source_systems"],
        "active_denies": active,
        "event_history": history[:MAX_EVENT_HISTORY],
        "seen_nonces": [str(item) for item in list(raw_obj.get("seen_nonces") or []) if str(item)][
            :MAX_SEEN_NONCES
        ],
    }
    for row in expired:
        _append_deny_event(
            store,
            {
                "event_type": "expire",
                "deny_id": row.get("deny_id"),
                "subject_type": row.get("subject_type"),
                "subject_id": row.get("subject_id"),
                "source_system": row.get("source_system"),
                "external_ref": row.get("external_ref"),
                "actor_id": "system:ttl_prune",
                "reason": "ttl_expired",
            },
        )
    return _store_config(db, store, actor_id=actor_id)


def ingest_iga_deny(
    db: Session,
    *,
    subject_type: str,
    subject_id: str,
    reason: str = "",
    source_system: str = "generic",
    tenant_id: Optional[str] = None,
    environment: Optional[str] = None,
    external_ref: Optional[str] = None,
    ttl_seconds: Optional[int] = None,
    expires_at: Optional[str] = None,
    actor_id: str = "iga-deny-ingest",
    timestamp_header: Optional[str] = None,
    nonce_header: Optional[str] = None,
    check_freshness: bool = False,
) -> dict[str, Any]:
    cfg = load_iga_deny_config(db, reveal_secret=True)
    if not cfg.get("enabled"):
        raise HTTPException(status_code=400, detail="IGA deny ingest is disabled")
    subject_type_n = str(subject_type or "").strip().lower()
    if subject_type_n not in ALLOWED_SUBJECT_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"subject_type must be one of: {', '.join(sorted(ALLOWED_SUBJECT_TYPES))}",
        )
    subject_id_n = str(subject_id or "").strip()
    if not subject_id_n:
        raise HTTPException(status_code=422, detail="subject_id is required")
    source = canonicalize_source_system(source_system or "generic") or "generic"
    if source not in cfg.get("allowed_source_systems") or []:
        raise HTTPException(status_code=422, detail=f"source_system '{source}' is not allowed")

    now = datetime.utcnow()
    exp = _parse_dt(expires_at)
    if exp is None:
        ttl = _clamp_ttl(ttl_seconds if ttl_seconds is not None else cfg.get("default_ttl_seconds"))
        exp = now + timedelta(seconds=ttl)
    if exp <= now:
        raise HTTPException(status_code=422, detail="expires_at must be in the future")

    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_NHI_IGA_DENY_JSON, "")
    try:
        store = json.loads(raw) if raw.strip() else dict(DEFAULT_CONFIG)
    except json.JSONDecodeError:
        store = dict(DEFAULT_CONFIG)
    if not isinstance(store, dict):
        store = dict(DEFAULT_CONFIG)

    if check_freshness:
        verify_ingest_anti_replay(
            store,
            timestamp_header=timestamp_header,
            nonce_header=nonce_header,
            require_timestamp=bool(cfg.get("require_ingest_timestamp")),
            max_skew_seconds=int(cfg.get("max_ingest_skew_seconds") or 300),
        )

    expired: list[dict[str, Any]] = []
    active = _prune_denies(list(store.get("active_denies") or []), now=now, expired_out=expired)
    for row in expired:
        _append_deny_event(
            store,
            {
                "event_type": "expire",
                "deny_id": row.get("deny_id"),
                "subject_type": row.get("subject_type"),
                "subject_id": row.get("subject_id"),
                "source_system": row.get("source_system"),
                "external_ref": row.get("external_ref"),
                "actor_id": "system:ttl_prune",
                "reason": "ttl_expired",
            },
        )
    # Upsert by external_ref or subject match
    ext = str(external_ref or "").strip()
    deny_id = None
    for row in active:
        if ext and str(row.get("external_ref") or "") == ext:
            deny_id = row.get("deny_id")
            row.update(
                {
                    "subject_type": subject_type_n,
                    "subject_id": subject_id_n,
                    "tenant_id": str(tenant_id or "").strip() or None,
                    "environment": str(environment or "").strip().lower() or None,
                    "reason": str(reason or "").strip()[:512],
                    "source_system": source,
                    "external_ref": ext or None,
                    "status": "active",
                    "expires_at": _iso(exp),
                    "updated_at": _iso(now),
                }
            )
            break
        if (
            str(row.get("subject_type")) == subject_type_n
            and str(row.get("subject_id")) == subject_id_n
            and str(row.get("source_system") or "") == source
        ):
            deny_id = row.get("deny_id")
            row["expires_at"] = _iso(exp)
            row["reason"] = str(reason or row.get("reason") or "").strip()[:512]
            row["tenant_id"] = str(tenant_id or row.get("tenant_id") or "").strip() or None
            row["environment"] = str(environment or row.get("environment") or "").strip().lower() or None
            row["updated_at"] = _iso(now)
            break

    if deny_id is None:
        deny_id = f"iga-deny-{uuid4().hex[:16]}"
        active.insert(
            0,
            {
                "deny_id": deny_id,
                "subject_type": subject_type_n,
                "subject_id": subject_id_n,
                "tenant_id": str(tenant_id or "").strip() or None,
                "environment": str(environment or "").strip().lower() or None,
                "reason": str(reason or "").strip()[:512],
                "source_system": source,
                "external_ref": ext or None,
                "status": "active",
                "created_at": _iso(now),
                "expires_at": _iso(exp),
                "created_by": str(actor_id or "iga-deny-ingest"),
            },
        )

    max_active = _clamp_max_active(cfg.get("max_active_denies"))
    store["active_denies"] = active[:max_active]
    # Keep config fields
    for key in (
        "enabled",
        "mode",
        "ingest_hmac_secret",
        "require_ingest_hmac",
        "require_ingest_timestamp",
        "max_ingest_skew_seconds",
        "default_ttl_seconds",
        "max_active_denies",
        "allowed_source_systems",
        "event_history",
        "seen_nonces",
    ):
        if key not in store:
            store[key] = cfg.get(key) if key != "ingest_hmac_secret" else cfg.get("ingest_hmac_secret")
    store["ingest_hmac_secret"] = str(cfg.get("ingest_hmac_secret") or "")
    store["enabled"] = bool(cfg.get("enabled"))
    store["mode"] = str(cfg.get("mode") or "off")
    store["require_ingest_hmac"] = bool(cfg.get("require_ingest_hmac", True))
    store["require_ingest_timestamp"] = bool(cfg.get("require_ingest_timestamp", True))
    store["max_ingest_skew_seconds"] = _clamp_skew(cfg.get("max_ingest_skew_seconds"))
    _append_deny_event(
        store,
        {
            "event_type": "ingest",
            "deny_id": deny_id,
            "subject_type": subject_type_n,
            "subject_id": subject_id_n,
            "source_system": source,
            "external_ref": ext or None,
            "actor_id": str(actor_id or "iga-deny-ingest"),
            "reason": str(reason or "").strip()[:512] or None,
            "expires_at": _iso(exp),
        },
    )
    _store_config(db, store, actor_id=actor_id)
    created = next((row for row in store["active_denies"] if row.get("deny_id") == deny_id), {})
    return {
        "deny_id": deny_id,
        "status": "active",
        "subject_type": subject_type_n,
        "subject_id": subject_id_n,
        "source_system": source,
        "expires_at": created.get("expires_at"),
        "mode": store.get("mode"),
        "active_deny_count": len(store["active_denies"]),
    }


def revoke_iga_deny(db: Session, *, deny_id: str, actor_id: str, reason: str = "") -> dict[str, Any]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_NHI_IGA_DENY_JSON, "")
    try:
        store = json.loads(raw) if raw.strip() else dict(DEFAULT_CONFIG)
    except json.JSONDecodeError:
        store = dict(DEFAULT_CONFIG)
    if not isinstance(store, dict):
        raise HTTPException(status_code=404, detail="IGA deny store not found")
    target_id = str(deny_id or "").strip()
    found = None
    remaining = []
    for row in list(store.get("active_denies") or []):
        if not isinstance(row, dict):
            continue
        if str(row.get("deny_id") or "") == target_id:
            found = row
            continue
        remaining.append(row)
    if found is None:
        raise HTTPException(status_code=404, detail="IGA deny not found")
    store["active_denies"] = _prune_denies(remaining)
    revoke_reason = str(reason or "operator_revoke").strip()[:512]
    _append_deny_event(
        store,
        {
            "event_type": "revoke",
            "deny_id": target_id,
            "subject_type": found.get("subject_type"),
            "subject_id": found.get("subject_id"),
            "source_system": found.get("source_system"),
            "external_ref": found.get("external_ref"),
            "actor_id": str(actor_id or "unknown"),
            "reason": revoke_reason,
        },
    )
    _store_config(db, store, actor_id=actor_id)
    return {
        "deny_id": target_id,
        "status": "revoked",
        "reason": revoke_reason,
        "active_deny_count": len(store["active_denies"]),
    }


def evaluate_iga_deny(
    db: Session,
    *,
    actor_id: Optional[str] = None,
    virtual_key_id: Optional[str] = None,
    nhi_record_id: Optional[str] = None,
    source_id: Optional[str] = None,
    owner_scope_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    environment: Optional[str] = None,
) -> dict[str, Any]:
    cfg = load_iga_deny_config(db, reveal_secret=False)
    mode = str(cfg.get("mode") or "off")
    if not cfg.get("enabled") or mode == "off":
        return {"matched": False, "mode": mode, "enabled": bool(cfg.get("enabled")), "deny": None}

    candidates = {
        "actor_id": str(actor_id or "").strip(),
        "virtual_key_id": str(virtual_key_id or "").strip(),
        "nhi_record_id": str(nhi_record_id or "").strip(),
        "source_id": str(source_id or "").strip(),
        "owner_scope_id": str(owner_scope_id or "").strip(),
        "tenant_id": str(tenant_id or "").strip(),
    }
    env = str(environment or "").strip().lower()
    now = datetime.utcnow()
    for row in cfg.get("active_denies") or []:
        st = str(row.get("subject_type") or "")
        sid = str(row.get("subject_id") or "")
        if not st or not sid or candidates.get(st) != sid:
            continue
        row_env = str(row.get("environment") or "").strip().lower()
        if row_env and env and row_env != env:
            continue
        row_tenant = str(row.get("tenant_id") or "").strip()
        if row_tenant and candidates.get("tenant_id") and row_tenant != candidates["tenant_id"]:
            continue
        expires_at = _parse_dt(row.get("expires_at"))
        if expires_at is not None and expires_at <= now:
            continue
        return {
            "matched": True,
            "mode": mode,
            "enabled": True,
            "deny": row,
        }
    return {"matched": False, "mode": mode, "enabled": True, "deny": None}


def _persist_enforce_event(
    db: Session,
    *,
    deny: dict[str, Any],
    mode: str,
    actor_id: Optional[str],
) -> None:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_NHI_IGA_DENY_JSON, "")
    try:
        store = json.loads(raw) if raw.strip() else dict(DEFAULT_CONFIG)
    except json.JSONDecodeError:
        store = dict(DEFAULT_CONFIG)
    if not isinstance(store, dict):
        store = dict(DEFAULT_CONFIG)
    _append_deny_event(
        store,
        {
            "event_type": "enforce",
            "deny_id": deny.get("deny_id"),
            "subject_type": deny.get("subject_type"),
            "subject_id": deny.get("subject_id"),
            "source_system": deny.get("source_system"),
            "external_ref": deny.get("external_ref"),
            "actor_id": str(actor_id or "unknown"),
            "reason": deny.get("reason"),
            "mode": mode,
            "decision": "deny" if mode == "block" else "warn",
        },
    )
    _store_config(db, store, actor_id=str(actor_id or "system:enforce"))


def resolve_iga_deny_subjects(
    db: Session,
    *,
    actor_id: Optional[str] = None,
    virtual_key_id: Optional[str] = None,
    owner_scope_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    nhi_record_id: Optional[str] = None,
    source_id: Optional[str] = None,
) -> dict[str, Optional[str]]:
    """Resolve NHI / VK / tenant context so deny subject types match on inference."""
    from app.models import GatewayNhiInventory

    vk = str(virtual_key_id or "").strip() or None
    owner = str(owner_scope_id or "").strip() or None
    tenant = str(tenant_id or "").strip() or None
    nhi = str(nhi_record_id or "").strip() or None
    src = str(source_id or "").strip() or vk
    row = None
    if nhi:
        row = db.query(GatewayNhiInventory).filter_by(nhi_record_id=nhi).first()
    elif vk:
        row = (
            db.query(GatewayNhiInventory)
            .filter_by(source_type="virtual_key", source_id=vk)
            .first()
        )
    elif owner:
        row = (
            db.query(GatewayNhiInventory)
            .filter(GatewayNhiInventory.owner_scope_id == owner)
            .order_by(GatewayNhiInventory.updated_at.desc())
            .first()
        )
    if row is not None:
        nhi = str(row.nhi_record_id or "").strip() or nhi
        src = str(row.source_id or "").strip() or src
        tenant = tenant or (str(row.tenant_id or "").strip() or None)
        owner = owner or (str(row.owner_scope_id or "").strip() or None)
    return {
        "actor_id": str(actor_id or "").strip() or None,
        "virtual_key_id": vk,
        "owner_scope_id": owner,
        "tenant_id": tenant,
        "nhi_record_id": nhi,
        "source_id": src,
    }


def enforce_iga_deny_or_raise(
    db: Session,
    *,
    actor_id: Optional[str] = None,
    virtual_key_id: Optional[str] = None,
    owner_scope_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    nhi_record_id: Optional[str] = None,
    source_id: Optional[str] = None,
    environment: Optional[str] = None,
    create_audit=None,
    audit_actor_id: Optional[str] = None,
    trace_id: Optional[str] = None,
) -> dict[str, Any]:
    """Return evaluation meta; raise 403 when mode=block and matched."""
    subjects = resolve_iga_deny_subjects(
        db,
        actor_id=actor_id,
        virtual_key_id=virtual_key_id,
        owner_scope_id=owner_scope_id,
        tenant_id=tenant_id,
        nhi_record_id=nhi_record_id,
        source_id=source_id,
    )
    result = evaluate_iga_deny(
        db,
        actor_id=subjects["actor_id"],
        virtual_key_id=subjects["virtual_key_id"],
        owner_scope_id=subjects["owner_scope_id"],
        tenant_id=subjects["tenant_id"],
        nhi_record_id=subjects["nhi_record_id"],
        source_id=subjects["source_id"],
        environment=environment,
    )
    if not result.get("matched"):
        return {"iga_deny": result}
    deny = result.get("deny") or {}
    mode = str(result.get("mode") or "off")
    try:
        _persist_enforce_event(
            db,
            deny=deny,
            mode=mode,
            actor_id=str(audit_actor_id or actor_id or "unknown"),
        )
    except Exception:
        # Enforcement must not fail open due to ring-buffer persistence issues.
        pass
    if create_audit is not None:
        create_audit(
            db,
            actor_id=str(audit_actor_id or actor_id or "unknown"),
            action_type="gateway.nhi.iga_deny.enforce",
            resource_type="gateway_nhi_iga_deny",
            resource_id=str(deny.get("deny_id") or "unknown"),
            trace_id=trace_id or f"trace-iga-deny-{uuid4()}",
            decision_outcome="deny" if mode == "block" else "allow",
            action_context={
                "mode": mode,
                "subject_type": deny.get("subject_type"),
                "subject_id": deny.get("subject_id"),
                "source_system": deny.get("source_system"),
                "reason": deny.get("reason"),
            },
        )
    if mode == "block":
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "IGA_DENY_SIGNAL",
                "message": (
                    f"Inference blocked by complementary IGA deny signal "
                    f"({deny.get('source_system') or 'iga'})."
                ),
                "deny_id": deny.get("deny_id"),
                "subject_type": deny.get("subject_type"),
                "subject_id": deny.get("subject_id"),
                "source_system": deny.get("source_system"),
                "reason": deny.get("reason"),
                "remediation_hint": (
                    "Revoke the deny via POST /gateway/nhi/iga-deny/{deny_id}/revoke "
                    "or wait for expiry; identity-plane owner should clear the upstream signal."
                ),
            },
        )
    return {"iga_deny": result}


