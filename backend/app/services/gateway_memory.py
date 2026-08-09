from __future__ import annotations

import json
import os
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models import (
    AgentMemoryRecord,
    AuditEvent,
    CachePolicy,
    ExecutionCheckpoint,
    OpenAIFileRecord,
    OpenAIResponseRecord,
    RealtimeSessionRecord,
)
from app.runtime_constants import (
    RUNTIME_CONFIG_GATEWAY_MEMORY_CONTENT_MAX_BYTES,
    RUNTIME_CONFIG_GATEWAY_MEMORY_LONG_TERM_ENABLED,
    RUNTIME_CONFIG_GATEWAY_MEMORY_LONG_TERM_TTL_DAYS,
    RUNTIME_CONFIG_GATEWAY_MEMORY_PII_CLASSIFICATION_ENABLED,
    RUNTIME_CONFIG_GATEWAY_MEMORY_SESSION_CAPTURE_ENABLED,
    RUNTIME_CONFIG_GATEWAY_MEMORY_MAX_RECORDS_PER_SCOPE,
    RUNTIME_CONFIG_GATEWAY_MEMORY_SHORT_TERM_TTL_SECONDS,
    RUNTIME_CONFIG_GATEWAY_SYSTEM_RULES_JSON,
)
from app.services.runtime_config import get_runtime_config, get_runtime_config_int
from app.services.audit import create_audit_event
from app.services.prompt_injection_guard import evaluate_prompt_injection_text, wrap_untrusted_retrieval_text

MEMORY_TIERS = {"short_term", "long_term"}
MEMORY_SCOPE_TYPES = {"session", "conversation", "agent", "global"}
MEMORY_CONTENT_MAX_LENGTH = 16384


def _memory_content_max_bytes(db: Session) -> int:
    return get_runtime_config_int(db, RUNTIME_CONFIG_GATEWAY_MEMORY_CONTENT_MAX_BYTES, MEMORY_CONTENT_MAX_LENGTH)


def _long_term_memory_enabled(db: Session) -> bool:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_MEMORY_LONG_TERM_ENABLED, "true")
    return str(raw).strip().lower() in {"true", "1", "yes", "on"}


def _session_capture_enabled(db: Session) -> bool:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_MEMORY_SESSION_CAPTURE_ENABLED, "false")
    return str(raw).strip().lower() in {"true", "1", "yes", "on"}


def _runtime_environment() -> str:
    return (os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "dev").strip().lower()


def _pii_classification_enabled(db: Session) -> bool:
    # Enterprise default: force PII classification outside local/dev/test (RSK-017).
    env = _runtime_environment()
    default = "true" if env not in {"dev", "test", "local"} else "false"
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_MEMORY_PII_CLASSIFICATION_ENABLED, default)
    return str(raw).strip().lower() in {"true", "1", "yes", "on"}


def _long_term_ttl_days(db: Session) -> int:
    return max(1, min(3650, get_runtime_config_int(db, RUNTIME_CONFIG_GATEWAY_MEMORY_LONG_TERM_TTL_DAYS, 365)))


BLOCKED_MEMORY_DATA_CLASSES = frozenset({"pii", "phi", "secret"})


def classify_memory_content_data_class(content: str, metadata_tag: Optional[str] = None) -> str:
    normalized_tag = str(metadata_tag or "").strip().lower()
    if normalized_tag.startswith("pii"):
        return "pii"
    if normalized_tag.startswith("phi"):
        return "phi"
    if normalized_tag.startswith("secret"):
        return "secret"
    lowered = str(content or "").lower()
    if any(token in lowered for token in ["password", "secret", "api key", "ssn", "token"]):
        return "sensitive"
    return "standard"


def _metadata_tag_from_json(metadata_json: str) -> Optional[str]:
    try:
        parsed = json.loads(metadata_json or "{}")
    except json.JSONDecodeError:
        return None
    if not isinstance(parsed, dict):
        return None
    for key in ("data_class", "request_tag", "classification"):
        value = parsed.get(key)
        if value:
            return str(value)
    return None


def _apply_memory_data_class_metadata(metadata_json: str, data_class: str) -> str:
    try:
        parsed = json.loads(metadata_json or "{}")
    except json.JSONDecodeError:
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}
    parsed["data_class"] = data_class
    return json.dumps(parsed, separators=(",", ":"), sort_keys=True)


def _parse_system_rules_count(db: Session) -> int:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_SYSTEM_RULES_JSON, "[]")
    try:
        parsed = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return 0
    return len(parsed) if isinstance(parsed, list) else 0


def _cache_hit_ratio(db: Session) -> tuple[float, int]:
    hit_count = int(
        db.query(func.count(AuditEvent.audit_event_id))
        .filter(
            AuditEvent.action_type == "gateway.cache.hit",
            AuditEvent.resource_type == "cache_policy",
        )
        .scalar()
        or 0
    )
    miss_count = int(
        db.query(func.count(AuditEvent.audit_event_id))
        .filter(
            AuditEvent.action_type == "gateway.cache.miss",
            AuditEvent.resource_type == "cache_policy",
        )
        .scalar()
        or 0
    )
    eligible = hit_count + miss_count
    ratio = float(hit_count / eligible) if eligible > 0 else 0.0
    return ratio, eligible


def expire_stale_memory_records(db: Session) -> int:
    now = datetime.utcnow()
    rows = (
        db.query(AgentMemoryRecord)
        .filter(
            AgentMemoryRecord.status == "active",
            AgentMemoryRecord.expires_at.isnot(None),
            AgentMemoryRecord.expires_at < now,
        )
        .all()
    )
    for row in rows:
        row.status = "expired"
        row.updated_at = now
    if rows:
        db.flush()
    return len(rows)


def expire_stale_short_term_records(db: Session) -> int:
    """Backward-compatible alias — expires any tier with expires_at past due."""
    return expire_stale_memory_records(db)


def build_gateway_memory_overview(db: Session, *, actor_id_filter: Optional[str] = None) -> dict[str, object]:
    expire_stale_short_term_records(db)

    semantic_policies = int(
        db.query(func.count(CachePolicy.cache_policy_id))
        .filter(CachePolicy.status == "active", CachePolicy.cache_mode == "semantic")
        .scalar()
        or 0
    )
    hit_ratio, _ = _cache_hit_ratio(db)

    now = datetime.utcnow()
    expiring_cutoff = now + timedelta(minutes=15)

    short_term_active_query = db.query(func.count(AgentMemoryRecord.memory_id)).filter(
        AgentMemoryRecord.memory_tier == "short_term",
        AgentMemoryRecord.status == "active",
    )
    if actor_id_filter:
        short_term_active_query = short_term_active_query.filter(
            AgentMemoryRecord.actor_id == actor_id_filter
        )
    short_term_active = int(short_term_active_query.scalar() or 0)

    short_term_expiring_query = db.query(func.count(AgentMemoryRecord.memory_id)).filter(
        AgentMemoryRecord.memory_tier == "short_term",
        AgentMemoryRecord.status == "active",
        AgentMemoryRecord.expires_at.isnot(None),
        AgentMemoryRecord.expires_at <= expiring_cutoff,
    )
    if actor_id_filter:
        short_term_expiring_query = short_term_expiring_query.filter(
            AgentMemoryRecord.actor_id == actor_id_filter
        )
    short_term_expiring = int(short_term_expiring_query.scalar() or 0)
    checkpoint_count = int(
        db.query(func.count(ExecutionCheckpoint.checkpoint_id))
        .filter(ExecutionCheckpoint.status == "active")
        .scalar()
        or 0
    )
    active_realtime = int(
        db.query(func.count(RealtimeSessionRecord.session_id))
        .filter(RealtimeSessionRecord.status == "active")
        .scalar()
        or 0
    )

    long_term_active_query = db.query(func.count(AgentMemoryRecord.memory_id)).filter(
        AgentMemoryRecord.memory_tier == "long_term",
        AgentMemoryRecord.status == "active",
    )
    if actor_id_filter:
        long_term_active_query = long_term_active_query.filter(
            AgentMemoryRecord.actor_id == actor_id_filter
        )
    long_term_active = int(long_term_active_query.scalar() or 0)
    response_records = int(
        db.query(func.count(OpenAIResponseRecord.response_id))
        .filter(OpenAIResponseRecord.status == "active")
        .scalar()
        or 0
    )
    file_records = int(
        db.query(func.count(OpenAIFileRecord.file_id))
        .filter(OpenAIFileRecord.status == "active")
        .scalar()
        or 0
    )
    system_rules = _parse_system_rules_count(db)

    ttl_seconds = get_runtime_config_int(db, RUNTIME_CONFIG_GATEWAY_MEMORY_SHORT_TERM_TTL_SECONDS, 3600)
    max_records = get_runtime_config_int(db, RUNTIME_CONFIG_GATEWAY_MEMORY_MAX_RECORDS_PER_SCOPE, 200)

    return {
        "semantic_cache": {
            "semantic_policies": semantic_policies,
            "hit_ratio": hit_ratio,
            "active_records": 0,
            "expiring_soon": 0,
            "checkpoints": 0,
            "active_realtime_sessions": 0,
            "response_records": 0,
            "file_records": 0,
            "system_rules": 0,
        },
        "short_term": {
            "active_records": short_term_active,
            "expiring_soon": short_term_expiring,
            "checkpoints": checkpoint_count,
            "active_realtime_sessions": active_realtime,
            "semantic_policies": 0,
            "hit_ratio": 0.0,
            "response_records": 0,
            "file_records": 0,
            "system_rules": 0,
        },
        "long_term": {
            "active_records": long_term_active,
            "response_records": response_records,
            "file_records": file_records,
            "system_rules": system_rules,
            "expiring_soon": 0,
            "checkpoints": 0,
            "active_realtime_sessions": 0,
            "semantic_policies": 0,
            "hit_ratio": 0.0,
        },
        "short_term_ttl_seconds": ttl_seconds,
        "max_records_per_scope": max_records,
    }


def serialize_memory_record(row: AgentMemoryRecord) -> dict[str, object]:
    return {
        "memory_id": row.memory_id,
        "memory_tier": row.memory_tier,
        "scope_type": row.scope_type,
        "scope_id": row.scope_id,
        "label": row.label,
        "content": row.content,
        "metadata_json": row.metadata_json,
        "actor_id": row.actor_id,
        "environment": row.environment,
        "status": row.status,
        "expires_at": row.expires_at,
        "created_at": row.created_at,
        "updated_at": row.updated_at,
        "deleted_at": row.deleted_at,
    }


def _validate_metadata_json(raw: Optional[str]) -> str:
    value = (raw or "{}").strip() or "{}"
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "error_code": "VALIDATION_ERROR",
                "message": f"metadata_json must be valid JSON: {exc}",
                "decision_trace_id": "gateway-memory-metadata-json",
            },
        ) from exc
    if not isinstance(parsed, dict):
        raise HTTPException(
            status_code=422,
            detail={
                "error_code": "VALIDATION_ERROR",
                "message": "metadata_json must be a JSON object.",
                "decision_trace_id": "gateway-memory-metadata-json-object",
            },
        )
    return json.dumps(parsed, separators=(",", ":"), sort_keys=True)


def create_memory_record(
    db: Session,
    *,
    actor_id: str,
    memory_tier: str,
    scope_type: str,
    scope_id: str,
    label: str,
    content: str,
    metadata_json: Optional[str],
    environment: str,
    memory_id: str,
) -> AgentMemoryRecord:
    tier = memory_tier.strip().lower()
    scope = scope_type.strip().lower()
    if tier not in MEMORY_TIERS:
        raise HTTPException(status_code=422, detail="memory_tier must be short_term or long_term")
    if tier == "long_term" and not _long_term_memory_enabled(db):
        raise HTTPException(
            status_code=409,
            detail={
                "error_code": "MEMORY_LONG_TERM_DISABLED",
                "message": "Long-term memory is disabled in gateway.memory.long_term_enabled.",
                "decision_trace_id": "gateway-memory-long-term-disabled",
            },
        )

    if scope not in MEMORY_SCOPE_TYPES:
        raise HTTPException(status_code=422, detail="scope_type must be session, conversation, agent, or global")

    normalized_scope_id = scope_id.strip()
    if not normalized_scope_id:
        raise HTTPException(status_code=422, detail="scope_id is required")

    normalized_content = content.strip()
    if not normalized_content:
        raise HTTPException(status_code=422, detail="content is required")
    content_max = _memory_content_max_bytes(db)
    if len(normalized_content) > content_max:
        raise HTTPException(
            status_code=422,
            detail={
                "error_code": "VALIDATION_ERROR",
                "message": f"content must not exceed {content_max} characters.",
                "decision_trace_id": "gateway-memory-content-max-length",
            },
        )

    injection = evaluate_prompt_injection_text(
        db,
        normalized_content,
        source="gateway.memory.create",
        raise_on_block=True,
    )
    if injection.get("decision") == "warn":
        normalized_content = wrap_untrusted_retrieval_text(normalized_content)
        if len(normalized_content) > content_max:
            raise HTTPException(
                status_code=422,
                detail={
                    "error_code": "VALIDATION_ERROR",
                    "message": (
                        f"content must not exceed {content_max} characters after "
                        "untrusted-content wrapping for prompt-injection warn hits."
                    ),
                    "decision_trace_id": "gateway-memory-content-max-length-wrapped",
                },
            )

    metadata = _validate_metadata_json(metadata_json)
    if injection.get("decision") == "warn":
        meta_obj = json.loads(metadata)
        meta_obj["prompt_injection_decision"] = "warn"
        meta_obj["prompt_injection_reasons"] = list(injection.get("reasons") or [])
        meta_obj["untrusted_content"] = True
        metadata = json.dumps(meta_obj, separators=(",", ":"), sort_keys=True)
    if _pii_classification_enabled(db):
        metadata_tag = _metadata_tag_from_json(metadata)
        data_class = classify_memory_content_data_class(normalized_content, metadata_tag)
        if data_class in BLOCKED_MEMORY_DATA_CLASSES:
            raise HTTPException(
                status_code=422,
                detail={
                    "error_code": "MEMORY_DATA_CLASS_BLOCKED",
                    "message": (
                        f"Memory content classified as {data_class} and blocked while "
                        "gateway.memory.pii_classification_enabled is true."
                    ),
                    "decision_trace_id": "gateway-memory-pii-blocked",
                    "data_class": data_class,
                },
            )
        metadata = _apply_memory_data_class_metadata(metadata, data_class)
    env = (environment or "dev").strip().lower() or "dev"

    max_records = get_runtime_config_int(db, RUNTIME_CONFIG_GATEWAY_MEMORY_MAX_RECORDS_PER_SCOPE, 200)
    active_count = (
        db.query(func.count(AgentMemoryRecord.memory_id))
        .filter(
            AgentMemoryRecord.memory_tier == tier,
            AgentMemoryRecord.scope_type == scope,
            AgentMemoryRecord.scope_id == normalized_scope_id,
            AgentMemoryRecord.status == "active",
        )
        .scalar()
        or 0
    )
    if int(active_count) >= max_records:
        raise HTTPException(
            status_code=409,
            detail={
                "error_code": "MEMORY_SCOPE_LIMIT_REACHED",
                "message": f"Scope limit reached ({max_records} active records).",
                "decision_trace_id": "gateway-memory-scope-limit",
            },
        )

    now = datetime.utcnow()
    expires_at: Optional[datetime] = None
    if tier == "short_term":
        ttl_seconds = get_runtime_config_int(db, RUNTIME_CONFIG_GATEWAY_MEMORY_SHORT_TERM_TTL_SECONDS, 3600)
        expires_at = now + timedelta(seconds=ttl_seconds)
    elif tier == "long_term":
        expires_at = now + timedelta(days=_long_term_ttl_days(db))

    row = AgentMemoryRecord(
        memory_id=memory_id,
        memory_tier=tier,
        scope_type=scope,
        scope_id=normalized_scope_id,
        label=(label or "").strip(),
        content=normalized_content,
        metadata_json=metadata,
        actor_id=actor_id,
        environment=env,
        status="active",
        expires_at=expires_at,
        created_at=now,
        updated_at=now,
    )
    db.add(row)
    db.flush()
    return row


def maybe_capture_response_session_memory(
    db: Session,
    *,
    actor_id: str,
    session_id: Optional[str],
    content: Optional[str],
    environment: str,
    trace_id: str,
    response_id: Optional[str] = None,
) -> Optional[AgentMemoryRecord]:
    if not _session_capture_enabled(db):
        return None

    normalized_session = str(session_id or "").strip()
    normalized_content = str(content or "").strip()
    if not normalized_session or not normalized_content:
        return None

    memory_id = f"mem-{uuid4().hex[:16]}"
    metadata_json = json.dumps(
        {"source": "responses_create", "response_id": str(response_id or "").strip()},
        separators=(",", ":"),
        sort_keys=True,
    )
    env = (environment or "dev").strip().lower() or "dev"

    try:
        row = create_memory_record(
            db,
            actor_id=actor_id,
            memory_tier="short_term",
            scope_type="session",
            scope_id=normalized_session,
            label="auto-session-capture",
            content=normalized_content,
            metadata_json=metadata_json,
            environment=env,
            memory_id=memory_id,
        )
    except HTTPException as exc:
        if exc.status_code == 409:
            return None
        raise

    create_audit_event(
        db,
        actor_id=actor_id,
        action_type="gateway.memory.session_capture",
        resource_type="gateway_memory_record",
        resource_id=row.memory_id,
        trace_id=trace_id,
    )
    return row


def list_memory_records(
    db: Session,
    *,
    memory_tier: Optional[str] = None,
    scope_type: Optional[str] = None,
    scope_id: Optional[str] = None,
    actor_id_filter: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[AgentMemoryRecord], int]:
    expire_stale_short_term_records(db)

    query = db.query(AgentMemoryRecord).filter(AgentMemoryRecord.status == "active")
    if memory_tier:
        query = query.filter(AgentMemoryRecord.memory_tier == memory_tier.strip().lower())
    if scope_type:
        query = query.filter(AgentMemoryRecord.scope_type == scope_type.strip().lower())
    if scope_id:
        query = query.filter(AgentMemoryRecord.scope_id == scope_id.strip())
    if actor_id_filter:
        query = query.filter(AgentMemoryRecord.actor_id == actor_id_filter)

    total = int(query.count())
    rows = query.order_by(AgentMemoryRecord.created_at.desc()).offset(offset).limit(limit).all()
    return rows, total
