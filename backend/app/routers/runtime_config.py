from datetime import datetime
import json
import re
from typing import Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database import get_db
from app.models import RuntimeConfig
from app.policy_constants import ROLE_PLATFORM_ADMIN, ROLE_SECURITY_APPROVER, ROLE_SUPER_ADMIN
from app.runtime_constants import RUNTIME_CONFIG_SECURITY_CORS_ALLOW_ORIGINS_CSV
from app.runtime_constants import RUNTIME_CONFIG_WORKLOAD_IDENTITY_EXPOSE_ACCESS_TOKEN
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_MCP_SERVERS_JSON
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_MCP_DEFAULT_TIMEOUT_SECONDS
from app.runtime_constants import RUNTIME_CONFIG_COST_PROVIDER_DISCOUNTS_JSON
from app.security import ActorContext, get_actor_context, require_dual_approval, require_role
from app.services.audit import create_audit_event
from app.services.mcp_gateway import validate_mcp_servers_json
from app.services.runtime_config import invalidate_runtime_config_cache

router = APIRouter()

RUNTIME_CONFIG_ADMIN_ROLES = {ROLE_PLATFORM_ADMIN, ROLE_SUPER_ADMIN, ROLE_SECURITY_APPROVER}

RUNTIME_CONFIG_VALIDATION_RULES = [
    {"key": "rate_limit.rules_exact_json", "type": "json_list", "required_fields": ["method", "path", "max_requests", "window_seconds"]},
    {"key": "rate_limit.rules_wildcard_json", "type": "json_list", "required_fields": ["method", "path_prefix", "max_requests", "window_seconds"]},
    {"key": "rate_limit.rules_refresh_seconds", "type": "int", "min": 1, "max": 3600},
    {"key": "gateway.default_global_timeout_ms", "type": "int", "min": 100, "max": 120000},
    {"key": "gateway.default_max_fallback_hops", "type": "int", "min": 0, "max": 10},
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
    {"key_pattern": r"^ui\.feature\.[a-z0-9-]+\.enabled(?:\.[a-z0-9-]+)?$", "type": "boolean_like"},
]


class RuntimeConfigUpsertRequest(BaseModel):
    config_value: str = Field(min_length=1, max_length=524288)
    description: Optional[str] = None


class RuntimeConfigValidateRequest(BaseModel):
    config_key: str = Field(min_length=1)
    config_value: str = Field(min_length=1, max_length=524288)


SENSITIVE_RUNTIME_CONFIG_KEYS = {
    "cost.model_token_rates_json",
    "cost.cloud_component_multipliers_json",
    RUNTIME_CONFIG_COST_PROVIDER_DISCOUNTS_JSON,
    "compliance.control_catalog_json",
    "compliance.default_control_mappings_json",
    RUNTIME_CONFIG_WORKLOAD_IDENTITY_EXPOSE_ACCESS_TOKEN,
    RUNTIME_CONFIG_GATEWAY_MCP_SERVERS_JSON,
}


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


def validate_runtime_config_value(config_key: str, config_value: str) -> Optional[str]:
    key = config_key.strip()
    value = config_value.strip()

    if not key:
        return "config_key cannot be empty"
    if not value:
        return "config_value cannot be empty"

    if key == "rate_limit.rules_exact_json":
        return _validate_rate_limit_rules(value, wildcard=False)
    if key == "rate_limit.rules_wildcard_json":
        return _validate_rate_limit_rules(value, wildcard=True)
    if key == "rate_limit.rules_refresh_seconds":
        return _validate_int_range(value, 1, 3600, "rate_limit.rules_refresh_seconds")
    if key == "gateway.default_global_timeout_ms":
        return _validate_int_range(value, 100, 120000, "gateway.default_global_timeout_ms")
    if key == "gateway.default_max_fallback_hops":
        return _validate_int_range(value, 0, 10, "gateway.default_max_fallback_hops")
    if key == RUNTIME_CONFIG_GATEWAY_MCP_SERVERS_JSON:
        return validate_mcp_servers_json(value)
    if key == RUNTIME_CONFIG_GATEWAY_MCP_DEFAULT_TIMEOUT_SECONDS:
        return _validate_mcp_default_timeout_seconds(value)
    if key == "cost.model_token_rates_json":
        return _validate_cost_model_token_rates(value)
    if key == "cost.cloud_component_multipliers_json":
        return _validate_cost_cloud_component_multipliers(value)
    if key == RUNTIME_CONFIG_COST_PROVIDER_DISCOUNTS_JSON:
        return _validate_cost_provider_discounts(value)
    if key == "workload_identity.default_expires_in_seconds":
        return _validate_int_range(value, 60, 86400, "workload_identity.default_expires_in_seconds")
    if key == "workload_identity.default_http_timeout_seconds":
        return _validate_float_range(value, 0.1, 120.0, "workload_identity.default_http_timeout_seconds")
    if key == RUNTIME_CONFIG_WORKLOAD_IDENTITY_EXPOSE_ACCESS_TOKEN:
        if _parse_bool(value) is None:
            return "workload_identity.expose_access_token must be boolean-like (true/false/1/0)"
        return None
    if key == "auth.policy.revisions_default_limit":
        return _validate_int_range(value, 1, 200, "auth.policy.revisions_default_limit")
    if key == "auth.login.max_failed_attempts":
        return _validate_int_range(value, 1, 20, "auth.login.max_failed_attempts")
    if key == "auth.login.lockout_minutes":
        return _validate_int_range(value, 1, 240, "auth.login.lockout_minutes")
    if key == RUNTIME_CONFIG_SECURITY_CORS_ALLOW_ORIGINS_CSV:
        return _validate_cors_allow_origins_csv(value)
    if key == "observability.logs.default_limit":
        return _validate_int_range(value, 1, 500, "observability.logs.default_limit")
    if key == "observability.schema.default_sample_size":
        return _validate_int_range(value, 1, 1000, "observability.schema.default_sample_size")
    if key == "compliance.control_catalog_json":
        return _validate_control_catalog(value)
    if key == "compliance.default_control_mappings_json":
        return _validate_control_mappings(value)

    if re.match(r"^ui\.feature\.[a-z0-9-]+\.enabled(?:\.[a-z0-9-]+)?$", key):
        if _parse_bool(value) is None:
            return "ui.feature.* values must be boolean-like (true/false/1/0)"
        return None

    return None


@router.post("/runtime-config/validate")
def validate_runtime_config(
    payload: RuntimeConfigValidateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, RUNTIME_CONFIG_ADMIN_ROLES)
    normalized_key = payload.config_key.strip()
    error = validate_runtime_config_value(normalized_key, payload.config_value)
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
    return {"rules": RUNTIME_CONFIG_VALIDATION_RULES}


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
    normalized_key = config_key.strip()
    if not normalized_key:
        raise HTTPException(status_code=422, detail="config_key cannot be empty")

    _require_sensitive_runtime_config_approval(ctx, normalized_key)

    validation_error = validate_runtime_config_value(normalized_key, payload.config_value)
    if validation_error:
        raise HTTPException(status_code=400, detail=validation_error)

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
    normalized_key = config_key.strip()
    _require_sensitive_runtime_config_approval(ctx, normalized_key)
    row = db.query(RuntimeConfig).filter_by(config_key=normalized_key).first()
    if not row:
        raise HTTPException(status_code=404, detail="Runtime config not found")

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
