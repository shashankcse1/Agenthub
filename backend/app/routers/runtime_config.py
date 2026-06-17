from datetime import datetime
import json
import re
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api_errors import not_found_error, validation_error as api_validation_error
from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import RuntimeConfig
from app.policy_constants import ROLE_PLATFORM_ADMIN, ROLE_SECURITY_APPROVER, ROLE_SUPER_ADMIN
from app.router_constants import RUNTIME_CONFIG_ADMIN_ROLES, RUNTIME_CONFIG_SUPER_ADMIN_ROLES
from app.runtime_constants import (
    RUNTIME_CONFIG_COST_PROVIDER_DISCOUNTS_JSON,
    RUNTIME_CONFIG_GATEWAY_CACHE_DEFAULT_MODE,
    RUNTIME_CONFIG_GATEWAY_MCP_DEFAULT_TIMEOUT_SECONDS,
    RUNTIME_CONFIG_GATEWAY_MCP_SERVERS_JSON,
    RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_JSON,
    RUNTIME_CONFIG_GATEWAY_NOTIFICATION_CHANNELS_JSON,
    RUNTIME_CONFIG_ORCHESTRATION_DATA_CONNECTIONS_JSON,
    RUNTIME_CONFIG_SECURITY_CORS_ALLOW_ORIGINS_CSV,
    RUNTIME_CONFIG_WORKLOAD_IDENTITY_EXPOSE_ACCESS_TOKEN,
    SENSITIVE_RUNTIME_CONFIG_KEYS,
)
from app.security import ActorContext, get_actor_context, require_dual_approval, require_role
from app.services.audit import create_audit_event
from app.services.mcp_gateway import validate_mcp_servers_json
from app.services.gateway_vector_stores import validate_vector_stores_json
from app.services.gateway_notification_channels import validate_notification_channels_json
from app.services.orchestration_data_connections import validate_data_connections_json
from app.services.runtime_config import invalidate_runtime_config_cache
from app.services.runtime_config_validation_rules import (
    BUILTIN_VALIDATION_RULES,
    delete_validation_rule,
    find_rule_for_key,
    list_validation_rules,
    upsert_validation_rule,
)

router = APIRouter()
logger = get_logger(__name__)


class RuntimeConfigUpsertRequest(BaseModel):
    config_value: str = Field(min_length=1, max_length=524288)
    description: Optional[str] = None


class RuntimeConfigValidateRequest(BaseModel):
    config_key: str = Field(min_length=1)
    config_value: str = Field(min_length=1, max_length=524288)


class RuntimeConfigValidationRuleUpsertRequest(BaseModel):
    key: Optional[str] = None
    key_pattern: Optional[str] = None
    type: str = Field(min_length=1)
    min: Optional[float] = None
    max: Optional[float] = None
    required_fields: Optional[list[str]] = None
    default_required_fields: Optional[list[str]] = None
    value_type: Optional[str] = None
    allow_wildcard: Optional[bool] = None
    example_value: Optional[str] = None
    description: Optional[str] = None


def _required_runtime_config_approver_role(ctx: ActorContext) -> Optional[str]:
    if ctx.actor_role in {ROLE_PLATFORM_ADMIN, ROLE_SUPER_ADMIN}:
        return ROLE_SECURITY_APPROVER
    if ctx.actor_role == ROLE_SECURITY_APPROVER:
        return ROLE_PLATFORM_ADMIN
    return None


def _require_sensitive_runtime_config_approval(ctx: ActorContext, config_key: str) -> None:
    if config_key not in SENSITIVE_RUNTIME_CONFIG_KEYS:
        return
    approver_role = _required_runtime_config_approver_role(ctx)
    if approver_role is None:
        return
    require_dual_approval(ctx, required_approver_role=approver_role)


def _parse_bool(value: str) -> Optional[bool]:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on", "enabled"}:
        return True
    if normalized in {"0", "false", "no", "off", "disabled"}:
        return False
    return None


def _validate_int_range(config_value: str, min_value: int, max_value: int, field_name: str) -> Optional[str]:
    try:
        parsed = int(config_value.strip())
    except Exception:
        return f"{field_name} must be an integer"
    if parsed < min_value or parsed > max_value:
        return f"{field_name} must be between {min_value} and {max_value}"
    return None


def _validate_float_range(config_value: str, min_value: float, max_value: float, field_name: str) -> Optional[str]:
    try:
        parsed = float(config_value.strip())
    except Exception:
        return f"{field_name} must be a number"
    if parsed < min_value or parsed > max_value:
        return f"{field_name} must be between {min_value} and {max_value}"
    return None


def _validate_rate_limit_rules(raw: str, wildcard: bool) -> Optional[str]:
    try:
        parsed = json.loads(raw)
    except Exception:
        return "config_value must be valid JSON"

    if not isinstance(parsed, list):
        return "config_value must be a JSON list"

    required_path_field = "path_prefix" if wildcard else "path"
    for item in parsed:
        if not isinstance(item, dict):
            return "each rule entry must be an object"
        method = str(item.get("method") or "").strip().upper()
        path_value = str(item.get(required_path_field) or "").strip()
        max_requests = item.get("max_requests")
        window_seconds = item.get("window_seconds")
        if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
            return "each rule method must be a valid HTTP verb"
        if not path_value:
            return f"each rule must include non-empty {required_path_field}"
        try:
            max_int = int(max_requests)
            window_int = int(window_seconds)
        except Exception:
            return "max_requests and window_seconds must be integers"
        if max_int < 1 or window_int < 1:
            return "max_requests and window_seconds must be greater than zero"
    return None


def _validate_control_catalog(raw: str) -> Optional[str]:
    try:
        parsed = json.loads(raw)
    except Exception:
        return "config_value must be valid JSON"
    if not isinstance(parsed, dict):
        return "config_value must be a JSON object"
    for key, value in parsed.items():
        if not isinstance(key, str) or not key.strip():
            return "control catalog keys must be non-empty strings"
        if not isinstance(value, str) or not value.strip():
            return "control catalog values must be non-empty strings"
    return None


def _validate_control_mappings(raw: str) -> Optional[str]:
    try:
        parsed = json.loads(raw)
    except Exception:
        return "config_value must be valid JSON"
    if not isinstance(parsed, dict):
        return "config_value must be a JSON object"

    required_fields = {
        "control_family",
        "requirement_text",
        "applicable_components",
        "required_evidence_types",
        "automation_status",
        "owner_team",
        "review_frequency",
    }
    for control_id, payload in parsed.items():
        if not isinstance(control_id, str) or not control_id.strip():
            return "mapping control ids must be non-empty strings"
        if not isinstance(payload, dict):
            return "each mapping value must be an object"
        missing = sorted(required_fields - set(payload.keys()))
        if missing:
            return f"mapping {control_id} missing required fields: {', '.join(missing)}"
        for field in required_fields:
            value = payload.get(field)
            if not isinstance(value, str) or not value.strip():
                return f"mapping {control_id} field {field} must be a non-empty string"
    return None


def _validate_cost_model_token_rates(raw: str) -> Optional[str]:
    try:
        parsed = json.loads(raw)
    except Exception:
        return "config_value must be valid JSON"

    if not isinstance(parsed, dict):
        return "config_value must be a JSON object"

    default_block = parsed.get("default")
    if not isinstance(default_block, dict):
        return "cost.model_token_rates_json must include object field default"

    for field in ("input_cents_per_1k", "output_cents_per_1k"):
        value = default_block.get(field)
        try:
            parsed_value = float(value)
        except Exception:
            return f"default.{field} must be a number"
        if parsed_value < 0:
            return f"default.{field} must be >= 0"

    models_block = parsed.get("models")
    if models_block is None:
        models_block = {
            key: value
            for key, value in parsed.items()
            if key not in {"default", "models"}
        }

    if not isinstance(models_block, dict):
        return "models must be a JSON object when provided"

    for model_name, rate_block in models_block.items():
        if not isinstance(model_name, str) or not model_name.strip():
            return "model keys must be non-empty strings"
        if not isinstance(rate_block, dict):
            return f"model {model_name} must map to an object"
        for field in ("input_cents_per_1k", "output_cents_per_1k"):
            value = rate_block.get(field)
            if value is None:
                continue
            try:
                parsed_value = float(value)
            except Exception:
                return f"model {model_name} field {field} must be a number"
            if parsed_value < 0:
                return f"model {model_name} field {field} must be >= 0"
    return None


def _validate_cost_cloud_component_multipliers(raw: str) -> Optional[str]:
    try:
        parsed = json.loads(raw)
    except Exception:
        return "config_value must be valid JSON"

    if not isinstance(parsed, dict):
        return "config_value must be a JSON object"

    provider_map = parsed.get("provider_type")
    endpoint_map = parsed.get("endpoint_family")
    if not isinstance(provider_map, dict):
        return "cost.cloud_component_multipliers_json.provider_type must be a JSON object"
    if not isinstance(endpoint_map, dict):
        return "cost.cloud_component_multipliers_json.endpoint_family must be a JSON object"

    for label, mapping in (("provider_type", provider_map), ("endpoint_family", endpoint_map)):
        for key, value in mapping.items():
            if not isinstance(key, str) or not key.strip():
                return f"{label} keys must be non-empty strings"
            try:
                parsed_value = float(value)
            except Exception:
                return f"{label}.{key} must be a number"
            if parsed_value <= 0:
                return f"{label}.{key} must be > 0"
    return None


def _validate_cost_provider_discounts(raw: str) -> Optional[str]:
    try:
        parsed = json.loads(raw)
    except Exception:
        return "config_value must be valid JSON"

    if not isinstance(parsed, dict):
        return "config_value must be a JSON object"

    provider_map = parsed.get("provider_type")
    model_map = parsed.get("models")
    if not isinstance(provider_map, dict):
        return "cost.provider_discounts_json.provider_type must be a JSON object"
    if not isinstance(model_map, dict):
        return "cost.provider_discounts_json.models must be a JSON object"

    for label, mapping in (("provider_type", provider_map), ("models", model_map)):
        for key, value in mapping.items():
            if not isinstance(key, str) or not key.strip():
                return f"{label} keys must be non-empty strings"
            try:
                parsed_value = float(value)
            except Exception:
                return f"{label}.{key} must be a number"
            if parsed_value < 0 or parsed_value > 95:
                return f"{label}.{key} must be between 0 and 95"
    return None


def _validate_cors_allow_origins_csv(raw: str) -> Optional[str]:
    origins = [item.strip() for item in raw.split(",") if item.strip()]
    if not origins:
        return "security.cors_allow_origins_csv must include at least one origin"

    for origin in origins:
        if "*" in origin:
            return "security.cors_allow_origins_csv must not include wildcard origins"
        parsed = urlparse(origin)
        if parsed.scheme not in {"http", "https"}:
            return f"Invalid origin scheme for {origin}; use http or https"
        if not parsed.netloc:
            return f"Invalid origin format for {origin}; host is required"
    return None


def _validate_mcp_default_timeout_seconds(raw: str) -> Optional[str]:
    return _validate_float_range(raw, 0.5, 30.0, "gateway.mcp.default_timeout_seconds")


def _validate_cache_default_mode(raw: str) -> Optional[str]:
    mode = raw.strip().lower()
    if mode not in {"exact", "semantic"}:
        return "gateway.cache.default_mode must be exact or semantic"
    return None


def _special_key_validators() -> dict:
    return {
        "rate_limit.rules_exact_json": lambda value: _validate_rate_limit_rules(value, wildcard=False),
        "rate_limit.rules_wildcard_json": lambda value: _validate_rate_limit_rules(value, wildcard=True),
        RUNTIME_CONFIG_GATEWAY_MCP_SERVERS_JSON: validate_mcp_servers_json,
        RUNTIME_CONFIG_GATEWAY_MCP_DEFAULT_TIMEOUT_SECONDS: _validate_mcp_default_timeout_seconds,
        RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_JSON: validate_vector_stores_json,
        RUNTIME_CONFIG_GATEWAY_NOTIFICATION_CHANNELS_JSON: validate_notification_channels_json,
        RUNTIME_CONFIG_ORCHESTRATION_DATA_CONNECTIONS_JSON: validate_data_connections_json,
        RUNTIME_CONFIG_GATEWAY_CACHE_DEFAULT_MODE: _validate_cache_default_mode,
        "cost.model_token_rates_json": _validate_cost_model_token_rates,
        "cost.cloud_component_multipliers_json": _validate_cost_cloud_component_multipliers,
        RUNTIME_CONFIG_COST_PROVIDER_DISCOUNTS_JSON: _validate_cost_provider_discounts,
        RUNTIME_CONFIG_SECURITY_CORS_ALLOW_ORIGINS_CSV: _validate_cors_allow_origins_csv,
        "compliance.control_catalog_json": _validate_control_catalog,
        "compliance.default_control_mappings_json": _validate_control_mappings,
    }


def _validate_using_catalog_rule(config_key: str, config_value: str, rule: dict) -> Optional[str]:
    special = _special_key_validators().get(config_key)
    if special:
        return special(config_value)

    rule_type = str(rule.get("type") or "").strip().lower()
    if rule_type == "int":
        return _validate_int_range(config_value, int(rule["min"]), int(rule["max"]), config_key)
    if rule_type == "float":
        return _validate_float_range(config_value, float(rule["min"]), float(rule["max"]), config_key)
    if rule_type == "boolean_like":
        if _parse_bool(config_value) is None:
            return f"{config_key} must be boolean-like (true/false/1/0)"
        return None
    if rule_type == "csv_origins":
        if rule.get("allow_wildcard") is False:
            return _validate_cors_allow_origins_csv(config_value)
        origins = [item.strip() for item in config_value.split(",") if item.strip()]
        if not origins:
            return f"{config_key} must include at least one origin"
        for origin in origins:
            parsed = urlparse(origin)
            if parsed.scheme not in {"http", "https"} or not parsed.netloc:
                return f"Invalid origin format for {origin}"
        return None
    return None


def validate_runtime_config_value(config_key: str, config_value: str, db: Optional[Session] = None) -> Optional[str]:
    key = config_key.strip()
    value = config_value.strip()

    if not key:
        return "config_key cannot be empty"
    if not value:
        return "config_value cannot be empty"

    rules = list_validation_rules(db) if db is not None else BUILTIN_VALIDATION_RULES
    rule = find_rule_for_key(rules, key)
    if rule:
        return _validate_using_catalog_rule(key, value, rule)

    special = _special_key_validators().get(key)
    if special:
        return special(value)

    return None


@router.post("/runtime-config/validate")
def validate_runtime_config(
    payload: RuntimeConfigValidateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, RUNTIME_CONFIG_ADMIN_ROLES)
    logger.trace(
        "runtime_config_validate_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "config_key": payload.config_key}),
    )
    normalized_key = payload.config_key.strip()
    error = validate_runtime_config_value(normalized_key, payload.config_value, db)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="runtime_config.validate",
        resource_type="runtime_config",
        resource_id=normalized_key or "runtime_config",
        trace_id=f"trace-runtime-config-validate-{normalized_key or 'unknown'}",
        decision_outcome="warn" if error else "allow",
    )
    db.commit()
    logger.info(
        "runtime_config_validate_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "config_key": normalized_key, "valid": error is None}),
    )
    if error:
        return {"valid": False, "error": error, "config_key": normalized_key}
    return {"valid": True, "error": None, "config_key": normalized_key}


@router.get("/runtime-config/validation-rules")
def get_runtime_config_validation_rules(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, RUNTIME_CONFIG_ADMIN_ROLES)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="runtime_config.validation_rules.read",
        resource_type="runtime_config",
        resource_id="validation_rules",
        trace_id="trace-runtime-config-validation-rules",
    )
    db.commit()
    return {"rules": list_validation_rules(db)}


@router.post("/runtime-config/validation-rules")
def create_runtime_config_validation_rule(
    payload: RuntimeConfigValidationRuleUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, RUNTIME_CONFIG_SUPER_ADMIN_ROLES)
    rule = upsert_validation_rule(db, None, payload.model_dump(exclude_none=True), ctx.actor_id)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="runtime_config.validation_rules.create",
        resource_type="runtime_config",
        resource_id=rule["rule_id"],
        trace_id=f"trace-runtime-config-validation-rule-create-{rule['rule_id']}",
    )
    db.commit()
    return rule


@router.put("/runtime-config/validation-rules/{rule_id}")
def update_runtime_config_validation_rule(
    rule_id: str,
    payload: RuntimeConfigValidationRuleUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, RUNTIME_CONFIG_SUPER_ADMIN_ROLES)
    rule = upsert_validation_rule(db, rule_id.strip(), payload.model_dump(exclude_none=True), ctx.actor_id)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="runtime_config.validation_rules.update",
        resource_type="runtime_config",
        resource_id=rule["rule_id"],
        trace_id=f"trace-runtime-config-validation-rule-update-{rule['rule_id']}",
    )
    db.commit()
    return rule


@router.delete("/runtime-config/validation-rules/{rule_id}")
def delete_runtime_config_validation_rule(
    rule_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, RUNTIME_CONFIG_SUPER_ADMIN_ROLES)
    normalized_rule_id = rule_id.strip()
    delete_validation_rule(db, normalized_rule_id)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="runtime_config.validation_rules.delete",
        resource_type="runtime_config",
        resource_id=normalized_rule_id,
        trace_id=f"trace-runtime-config-validation-rule-delete-{normalized_rule_id}",
    )
    db.commit()
    return {"deleted": True, "rule_id": normalized_rule_id}


@router.get("/runtime-config")
def list_runtime_config(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, RUNTIME_CONFIG_ADMIN_ROLES)
    rows = db.query(RuntimeConfig).order_by(RuntimeConfig.updated_at.desc()).all()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="runtime_config.read",
        resource_type="runtime_config",
        resource_id="all",
        trace_id="trace-runtime-config-list",
    )
    db.commit()
    return [
        {
            "config_key": row.config_key,
            "config_value": row.config_value,
            "description": row.description,
            "updated_at": row.updated_at,
            "updated_by": row.updated_by,
        }
        for row in rows
    ]


@router.put("/runtime-config/{config_key}")
def upsert_runtime_config(
    config_key: str,
    payload: RuntimeConfigUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, RUNTIME_CONFIG_ADMIN_ROLES)
    logger.trace(
        "runtime_config_upsert_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "config_key": config_key}),
    )
    normalized_key = config_key.strip()
    if not normalized_key:
        raise api_validation_error("config_key cannot be empty", decision_trace_id="runtime-config-key-empty", status_code=422)

    _require_sensitive_runtime_config_approval(ctx, normalized_key)

    validation_message = validate_runtime_config_value(normalized_key, payload.config_value, db)
    if validation_message:
        raise api_validation_error(validation_message, decision_trace_id="runtime-config-validation")

    row = db.query(RuntimeConfig).filter_by(config_key=normalized_key).first()
    if not row:
        row = RuntimeConfig(
            config_key=normalized_key,
            config_value=payload.config_value.strip(),
            description=(payload.description or "").strip(),
            updated_by=ctx.actor_id,
            updated_at=datetime.utcnow(),
        )
        db.add(row)
    else:
        row.config_value = payload.config_value.strip()
        if payload.description is not None:
            row.description = payload.description.strip()
        row.updated_by = ctx.actor_id
        row.updated_at = datetime.utcnow()

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="runtime_config.upsert",
        resource_type="runtime_config",
        resource_id=normalized_key,
        trace_id=f"trace-runtime-config-{normalized_key}",
    )
    invalidate_runtime_config_cache(normalized_key)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="runtime_config.cache_invalidate",
        resource_type="runtime_config",
        resource_id=normalized_key,
        trace_id=f"trace-runtime-config-cache-{normalized_key}",
    )
    db.commit()
    logger.info(
        "runtime_config_upsert_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "config_key": normalized_key}),
    )

    return {
        "config_key": row.config_key,
        "config_value": row.config_value,
        "description": row.description,
        "updated_by": row.updated_by,
        "updated_at": row.updated_at,
    }


@router.delete("/runtime-config/{config_key}")
def delete_runtime_config(
    config_key: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, RUNTIME_CONFIG_ADMIN_ROLES)
    logger.trace(
        "runtime_config_delete_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "config_key": config_key}),
    )
    normalized_key = config_key.strip()
    _require_sensitive_runtime_config_approval(ctx, normalized_key)
    row = db.query(RuntimeConfig).filter_by(config_key=normalized_key).first()
    if not row:
        raise not_found_error("runtime_config", normalized_key, decision_trace_id="runtime-config-not-found")

    db.delete(row)
    invalidate_runtime_config_cache(normalized_key)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="runtime_config.delete",
        resource_type="runtime_config",
        resource_id=normalized_key,
        trace_id=f"trace-runtime-config-{normalized_key}",
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="runtime_config.cache_invalidate",
        resource_type="runtime_config",
        resource_id=normalized_key,
        trace_id=f"trace-runtime-config-cache-{normalized_key}",
    )
    db.commit()
    return {"deleted": True, "config_key": normalized_key}
