from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import RuntimeConfigValidationRule
from app.runtime_constants import RUNTIME_CONFIG_SECURITY_CORS_ALLOW_ORIGINS_CSV
from app.runtime_constants import RUNTIME_CONFIG_WORKLOAD_IDENTITY_EXPOSE_ACCESS_TOKEN
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_MCP_SERVERS_JSON
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_MCP_DEFAULT_TIMEOUT_SECONDS
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_MEMORY_MAX_RECORDS_PER_SCOPE
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_MEMORY_SHORT_TERM_TTL_SECONDS
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_MEMORY_LONG_TERM_ENABLED
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_MEMORY_SESSION_CAPTURE_ENABLED
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_MEMORY_CONTENT_MAX_BYTES
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_CACHE_DEFAULT_MODE
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_CACHE_DEFAULT_SIMILARITY_THRESHOLD
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_CACHE_DEFAULT_TTL_SECONDS
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_CACHE_INFERENCE_SHORT_CIRCUIT_ENABLED
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_JSON
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_SEARCH_TOP_K
from app.runtime_constants import RUNTIME_CONFIG_COST_PROVIDER_DISCOUNTS_JSON
from app.runtime_constants import RUNTIME_CONFIG_ORCHESTRATION_HTTP_ALLOWED_HOSTS_JSON
from app.runtime_constants import RUNTIME_CONFIG_ORCHESTRATION_MAX_NODES_PER_FLOW
from app.runtime_constants import RUNTIME_CONFIG_ORCHESTRATION_PROD_RUN_REQUIRES_APPROVAL

BUILTIN_VALIDATION_RULES: list[dict[str, Any]] = [
    {"key": "rate_limit.rules_exact_json", "type": "json_list", "required_fields": ["method", "path", "max_requests", "window_seconds"]},
    {"key": "rate_limit.rules_wildcard_json", "type": "json_list", "required_fields": ["method", "path_prefix", "max_requests", "window_seconds"]},
    {"key": "rate_limit.rules_refresh_seconds", "type": "int", "min": 1, "max": 3600},
    {"key": "gateway.default_global_timeout_ms", "type": "int", "min": 100, "max": 120000},
    {"key": "gateway.default_max_fallback_hops", "type": "int", "min": 0, "max": 10},
    {"key": RUNTIME_CONFIG_GATEWAY_MEMORY_SHORT_TERM_TTL_SECONDS, "type": "int", "min": 60, "max": 604800},
    {"key": RUNTIME_CONFIG_GATEWAY_MEMORY_MAX_RECORDS_PER_SCOPE, "type": "int", "min": 1, "max": 10000},
    {"key": RUNTIME_CONFIG_GATEWAY_MEMORY_LONG_TERM_ENABLED, "type": "boolean_like"},
    {"key": RUNTIME_CONFIG_GATEWAY_MEMORY_SESSION_CAPTURE_ENABLED, "type": "boolean_like"},
    {"key": RUNTIME_CONFIG_GATEWAY_MEMORY_CONTENT_MAX_BYTES, "type": "int", "min": 1024, "max": 65536},
    {"key": RUNTIME_CONFIG_GATEWAY_CACHE_DEFAULT_TTL_SECONDS, "type": "int", "min": 60, "max": 86400},
    {"key": RUNTIME_CONFIG_GATEWAY_CACHE_DEFAULT_SIMILARITY_THRESHOLD, "type": "float", "min": 0.0, "max": 1.0},
    {"key": RUNTIME_CONFIG_GATEWAY_CACHE_DEFAULT_MODE, "type": "boolean_like"},
    {"key": RUNTIME_CONFIG_GATEWAY_CACHE_INFERENCE_SHORT_CIRCUIT_ENABLED, "type": "boolean_like"},
    {"key": "platform.ui_models.require_approval", "type": "boolean_like"},
    {"key": "platform.ui_models.enforce_tenant_entitlements", "type": "boolean_like"},
    {"key": RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_JSON, "type": "json_list", "required_fields": ["store_id", "provider_type", "collection_name"]},
    {"key": RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_SEARCH_TOP_K, "type": "int", "min": 1, "max": 100},
    {"key": RUNTIME_CONFIG_GATEWAY_MCP_SERVERS_JSON, "type": "json_list", "required_fields": ["server_id", "base_url"]},
    {"key": RUNTIME_CONFIG_GATEWAY_MCP_DEFAULT_TIMEOUT_SECONDS, "type": "float", "min": 0.5, "max": 30.0},
    {
        "key": "cost.model_token_rates_json",
        "type": "json_object",
        "required_fields": ["default"],
        "default_required_fields": ["input_cents_per_1k", "output_cents_per_1k"],
    },
    {
        "key": "cost.cloud_component_multipliers_json",
        "type": "json_object",
        "required_fields": ["provider_type", "endpoint_family"],
    },
    {
        "key": RUNTIME_CONFIG_COST_PROVIDER_DISCOUNTS_JSON,
        "type": "json_object",
        "required_fields": ["provider_type", "models"],
    },
    {"key": "workload_identity.default_expires_in_seconds", "type": "int", "min": 60, "max": 86400},
    {"key": "workload_identity.default_http_timeout_seconds", "type": "float", "min": 0.1, "max": 120.0},
    {"key": RUNTIME_CONFIG_WORKLOAD_IDENTITY_EXPOSE_ACCESS_TOKEN, "type": "boolean_like"},
    {"key": "auth.policy.revisions_default_limit", "type": "int", "min": 1, "max": 200},
    {"key": "auth.login.max_failed_attempts", "type": "int", "min": 1, "max": 20},
    {"key": "auth.login.lockout_minutes", "type": "int", "min": 1, "max": 240},
    {"key": RUNTIME_CONFIG_SECURITY_CORS_ALLOW_ORIGINS_CSV, "type": "csv_origins", "allow_wildcard": False},
    {"key": "observability.logs.default_limit", "type": "int", "min": 1, "max": 500},
    {"key": "observability.schema.default_sample_size", "type": "int", "min": 1, "max": 1000},
    {"key": "compliance.control_catalog_json", "type": "json_object", "value_type": "string"},
    {"key": "compliance.default_control_mappings_json", "type": "json_object", "value_type": "mapping_object"},
    {"key": RUNTIME_CONFIG_ORCHESTRATION_HTTP_ALLOWED_HOSTS_JSON, "type": "json_list", "required_fields": []},
    {"key": RUNTIME_CONFIG_ORCHESTRATION_MAX_NODES_PER_FLOW, "type": "int", "min": 1, "max": 200},
    {"key": RUNTIME_CONFIG_ORCHESTRATION_PROD_RUN_REQUIRES_APPROVAL, "type": "boolean_like"},
    {"key_pattern": r"^ui\.feature\.[a-z0-9-]+\.enabled(?:\.[a-z0-9-]+)?$", "type": "boolean_like"},
]

ALLOWED_RULE_TYPES = {
    "int",
    "float",
    "boolean_like",
    "json_list",
    "json_object",
    "csv_origins",
}


def rule_id_for(rule: dict[str, Any]) -> str:
    key = str(rule.get("key") or "").strip()
    if key:
        return f"key:{key}"
    pattern = str(rule.get("key_pattern") or "").strip()
    if pattern:
        digest = hashlib.sha256(pattern.encode("utf-8")).hexdigest()[:16]
        return f"pattern:{digest}"
    raise ValueError("Rule must include key or key_pattern")


def normalize_rule_payload(payload: dict[str, Any]) -> dict[str, Any]:
    key = str(payload.get("key") or "").strip() or None
    key_pattern = str(payload.get("key_pattern") or "").strip() or None
    if not key and not key_pattern:
        raise HTTPException(status_code=422, detail="Rule must include key or key_pattern")
    if key and key_pattern:
        raise HTTPException(status_code=422, detail="Rule cannot include both key and key_pattern")

    rule_type = str(payload.get("type") or "").strip().lower()
    if rule_type not in ALLOWED_RULE_TYPES:
        raise HTTPException(status_code=422, detail=f"Unsupported rule type: {rule_type}")

    normalized: dict[str, Any] = {"type": rule_type}
    if key:
        normalized["key"] = key
    if key_pattern:
        try:
            re.compile(key_pattern)
        except re.error as exc:
            raise HTTPException(status_code=422, detail=f"Invalid key_pattern regex: {exc}") from exc
        normalized["key_pattern"] = key_pattern

    for field in ("min", "max"):
        if payload.get(field) is not None and payload.get(field) != "":
            normalized[field] = payload[field]

    for field in ("required_fields", "default_required_fields"):
        value = payload.get(field)
        if value is None:
            continue
        if isinstance(value, list):
            normalized[field] = [str(item).strip() for item in value if str(item).strip()]
        elif isinstance(value, str) and value.strip():
            normalized[field] = [item.strip() for item in value.split(",") if item.strip()]

    for field in ("value_type", "description", "example_value"):
        value = payload.get(field)
        if value is not None and str(value).strip():
            normalized[field] = str(value).strip()

    if payload.get("allow_wildcard") is not None:
        normalized["allow_wildcard"] = bool(payload.get("allow_wildcard"))

    return normalized


def serialize_rule_row(row: RuntimeConfigValidationRule) -> dict[str, Any]:
    rule = json.loads(row.rule_json)
    return {
        "rule_id": row.rule_id,
        "source": row.source,
        "updated_by": row.updated_by,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
        **rule,
    }


def ensure_validation_rules_seeded(db: Session) -> None:
    existing_ids = {
        row.rule_id for row in db.query(RuntimeConfigValidationRule.rule_id).all()
    }
    now = datetime.utcnow()
    added = False
    for rule in BUILTIN_VALIDATION_RULES:
        normalized = normalize_rule_payload(rule)
        resolved_rule_id = rule_id_for(normalized)
        if resolved_rule_id in existing_ids:
            continue
        db.add(
            RuntimeConfigValidationRule(
                rule_id=resolved_rule_id,
                rule_json=json.dumps(normalized, separators=(",", ":"), sort_keys=True),
                source="builtin",
                updated_by="system",
                updated_at=now,
            )
        )
        added = True
    if added:
        db.commit()


def list_validation_rules(db: Session) -> list[dict[str, Any]]:
    ensure_validation_rules_seeded(db)
    rows = db.query(RuntimeConfigValidationRule).order_by(RuntimeConfigValidationRule.rule_id.asc()).all()
    return [serialize_rule_row(row) for row in rows]


def get_validation_rule(db: Session, rule_id: str) -> RuntimeConfigValidationRule:
    row = db.query(RuntimeConfigValidationRule).filter_by(rule_id=rule_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Validation rule not found")
    return row


def upsert_validation_rule(db: Session, rule_id: Optional[str], payload: dict[str, Any], actor_id: str) -> dict[str, Any]:
    normalized = normalize_rule_payload(payload)
    resolved_rule_id = rule_id or rule_id_for(normalized)
    if rule_id and rule_id != rule_id_for(normalized):
        raise HTTPException(status_code=400, detail="rule_id does not match key or key_pattern")

    row = db.query(RuntimeConfigValidationRule).filter_by(rule_id=resolved_rule_id).first()
    now = datetime.utcnow()
    if row:
        row.rule_json = json.dumps(normalized, separators=(",", ":"), sort_keys=True)
        row.updated_by = actor_id
        row.updated_at = now
    else:
        row = RuntimeConfigValidationRule(
            rule_id=resolved_rule_id,
            rule_json=json.dumps(normalized, separators=(",", ":"), sort_keys=True),
            source="custom",
            updated_by=actor_id,
            updated_at=now,
        )
        db.add(row)
    db.commit()
    db.refresh(row)
    return serialize_rule_row(row)


def delete_validation_rule(db: Session, rule_id: str) -> None:
    row = get_validation_rule(db, rule_id)
    if row.source != "custom":
        raise HTTPException(status_code=400, detail="Built-in validation rules cannot be deleted")
    db.delete(row)
    db.commit()


def find_rule_for_key(rules: list[dict[str, Any]], config_key: str) -> Optional[dict[str, Any]]:
    for rule in rules:
        if rule.get("key") == config_key:
            return rule
    for rule in rules:
        pattern = rule.get("key_pattern")
        if pattern and re.match(pattern, config_key):
            return rule
    return None
