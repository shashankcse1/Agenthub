"""Gateway runtime risk assessment + optional allow/warn/block enforcement."""

from __future__ import annotations

import json
from typing import Any, Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_RUNTIME_RISK_JSON
from app.services.audit import create_audit_event
from app.services.runtime_config import get_runtime_config, upsert_runtime_config_value
from app.services.runtime_env import is_prod_target_environment, is_production_runtime

ALLOWED_ACTIONS = frozenset({"allow", "warn", "block"})
ALLOWED_MODES = frozenset({"observe", "enforce"})
_MAX_ENFORCE_ENVIRONMENTS = 32
_LARGE_INPUT_CHARS = 100_000

# Endpoint families with elevated side-effect / exfil surface.
_HIGH_SIDE_EFFECT_FAMILIES = frozenset({"images", "realtime", "a2a"})
_ELEVATED_FAMILIES = frozenset({"audio.transcriptions", "audio.translations", "rerank", "messages"})

DEFAULT_CONFIG: dict[str, Any] = {
    "enabled": False,
    "mode": "observe",
    "high_action": "block",
    "medium_action": "warn",
    "low_action": "allow",
    "enforce_environments": ["prod", "production"],
    # When true, corrupt/unreadable policy fails closed in production if previously expected.
    "fail_closed_on_config_error": True,
}


def assess_inference_risk(
    *,
    model_name: str,
    environment: str,
    has_tool_calls: bool = False,
    selected_provider_id: Optional[str] = None,
    endpoint_family: str = "chat.completions",
    has_agent_id: bool = False,
    input_chars: int = 0,
) -> tuple[str, list[str]]:
    score = 0
    reasons: list[str] = []
    normalized_model = str(model_name or "").strip().lower()
    family = str(endpoint_family or "chat.completions").strip().lower()

    if is_prod_target_environment(environment):
        score += 2
        reasons.append("production_environment")

    if has_tool_calls:
        score += 2
        reasons.append("tool_call_execution_path")

    if family in _HIGH_SIDE_EFFECT_FAMILIES:
        score += 2
        reasons.append(f"elevated_endpoint_family:{family}")
    elif family in _ELEVATED_FAMILIES:
        score += 1
        reasons.append(f"elevated_endpoint_family:{family}")

    if has_agent_id:
        score += 1
        reasons.append("agent_scoped_request")

    if int(input_chars or 0) >= _LARGE_INPUT_CHARS:
        score += 1
        reasons.append("large_input_payload")

    if str(selected_provider_id or "").strip():
        score += 1
        reasons.append("provider_routed")

    if "/" in normalized_model:
        score += 1
        reasons.append("provider_prefixed_model")

    if normalized_model.startswith(("gpt-4", "claude", "gemini-", "o1", "o3", "dall-e", "gpt-image")):
        score += 1
        reasons.append("frontier_model_family")

    if score >= 4:
        risk_tier = "high"
    elif score >= 2:
        risk_tier = "medium"
    else:
        risk_tier = "low"

    if not reasons:
        reasons.append("baseline_policy_controls")

    return risk_tier, reasons


def normalize_config(raw: dict[str, Any] | None) -> dict[str, Any]:
    src = dict(DEFAULT_CONFIG)
    if isinstance(raw, dict):
        src.update(raw)
    mode = str(src.get("mode") or "observe").strip().lower() or "observe"
    if mode not in ALLOWED_MODES:
        raise HTTPException(status_code=422, detail=f"mode must be one of: {', '.join(sorted(ALLOWED_MODES))}")
    out: dict[str, Any] = {
        "enabled": bool(src.get("enabled")),
        "mode": mode,
        "fail_closed_on_config_error": bool(src.get("fail_closed_on_config_error", True)),
    }
    for key in ("high_action", "medium_action", "low_action"):
        action = str(src.get(key) or DEFAULT_CONFIG[key]).strip().lower()
        if action not in ALLOWED_ACTIONS:
            raise HTTPException(
                status_code=422,
                detail=f"{key} must be one of: {', '.join(sorted(ALLOWED_ACTIONS))}",
            )
        out[key] = action
    envs_raw = src.get("enforce_environments")
    if envs_raw is None:
        envs = list(DEFAULT_CONFIG["enforce_environments"])
    elif isinstance(envs_raw, list):
        envs = [str(item).strip().lower() for item in envs_raw if str(item).strip()]
    else:
        raise HTTPException(status_code=422, detail="enforce_environments must be a list of environment names")
    if len(envs) > _MAX_ENFORCE_ENVIRONMENTS:
        raise HTTPException(
            status_code=422,
            detail=f"enforce_environments supports at most {_MAX_ENFORCE_ENVIRONMENTS} entries",
        )
    # Deduplicate while preserving order.
    seen: set[str] = set()
    deduped: list[str] = []
    for item in envs:
        if item in seen:
            continue
        seen.add(item)
        deduped.append(item)
    out["enforce_environments"] = deduped
    return out


def load_runtime_risk_config(db: Session) -> dict[str, Any]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_RUNTIME_RISK_JSON, "")
    parsed: dict[str, Any] = {}
    if raw and str(raw).strip():
        try:
            loaded = json.loads(raw)
            if isinstance(loaded, dict):
                parsed = loaded
            else:
                raise ValueError("runtime risk config must be an object")
        except (json.JSONDecodeError, ValueError) as exc:
            if is_production_runtime() and bool(DEFAULT_CONFIG.get("fail_closed_on_config_error")):
                raise HTTPException(
                    status_code=503,
                    detail={
                        "error_code": "GATEWAY_RUNTIME_RISK_CONFIG_INVALID",
                        "message": "Runtime risk policy is corrupt; failing closed in production.",
                        "remediation_hint": "Repair gateway.runtime_risk_json via /gateway/runtime-risk/config.",
                    },
                ) from exc
            parsed = {}
    try:
        return normalize_config(parsed)
    except HTTPException:
        if is_production_runtime():
            raise
        return dict(DEFAULT_CONFIG)


def save_runtime_risk_config(db: Session, payload: dict[str, Any], *, actor_id: str) -> dict[str, Any]:
    del actor_id  # reserved for future attribution on the stored blob
    normalized = normalize_config(payload)
    upsert_runtime_config_value(
        db,
        RUNTIME_CONFIG_GATEWAY_RUNTIME_RISK_JSON,
        json.dumps(normalized, separators=(",", ":"), sort_keys=True),
        description="Gateway runtime risk allow/warn/block policy",
    )
    return normalized


def _action_for_tier(config: dict[str, Any], risk_tier: str) -> str:
    tier = str(risk_tier or "low").strip().lower()
    if tier == "high":
        return str(config.get("high_action") or "block")
    if tier == "medium":
        return str(config.get("medium_action") or "warn")
    return str(config.get("low_action") or "allow")


def _environment_in_enforce_scope(environment: str, config: dict[str, Any]) -> bool:
    scopes = [str(item).strip().lower() for item in (config.get("enforce_environments") or []) if str(item).strip()]
    if not scopes:
        return True
    env = str(environment or "").strip().lower()
    if env in scopes:
        return True
    if is_prod_target_environment(env) and any(is_prod_target_environment(item) for item in scopes):
        return True
    return False


def evaluate_runtime_risk(
    db: Session,
    *,
    model_name: str,
    environment: str,
    has_tool_calls: bool = False,
    selected_provider_id: Optional[str] = None,
    endpoint_family: str = "chat.completions",
    has_agent_id: bool = False,
    input_chars: int = 0,
) -> dict[str, Any]:
    """Dry-run assessment against current policy (no raise)."""
    risk_tier, risk_reasons = assess_inference_risk(
        model_name=model_name,
        environment=environment,
        has_tool_calls=has_tool_calls,
        selected_provider_id=selected_provider_id,
        endpoint_family=endpoint_family,
        has_agent_id=has_agent_id,
        input_chars=input_chars,
    )
    config = load_runtime_risk_config(db)
    action = _action_for_tier(config, risk_tier)
    in_scope = _environment_in_enforce_scope(environment, config)
    if not config.get("enabled"):
        decision = "allow"
        effective_mode = "off"
    elif not in_scope:
        decision = "allow"
        effective_mode = "out_of_scope"
    elif config.get("mode") == "observe":
        decision = "observe"
        effective_mode = "observe"
    else:
        decision = action
        effective_mode = "enforce"
    return {
        "risk_tier": risk_tier,
        "risk_reasons": risk_reasons,
        "configured_action": action,
        "decision": decision,
        "mode": effective_mode,
        "enabled": bool(config.get("enabled")),
        "would_block": decision == "block",
        "environment": str(environment or "").strip(),
        "model_name": str(model_name or "").strip(),
        "endpoint_family": str(endpoint_family or "").strip(),
    }


def assess_and_enforce_inference_risk(
    db: Session,
    *,
    actor_id: str,
    model_name: str,
    environment: str,
    has_tool_calls: bool,
    selected_provider_id: Optional[str],
    request_id: str,
    endpoint_family: str,
    trace_id: Optional[str] = None,
    has_agent_id: bool = False,
    input_chars: int = 0,
) -> dict[str, Any]:
    """
    Assess risk and optionally block before upstream inference.

    Returns metadata to attach on responses. Raises HTTP 403 when policy blocks.
    """
    risk_tier, risk_reasons = assess_inference_risk(
        model_name=model_name,
        environment=environment,
        has_tool_calls=has_tool_calls,
        selected_provider_id=selected_provider_id,
        endpoint_family=endpoint_family,
        has_agent_id=has_agent_id,
        input_chars=input_chars,
    )
    config = load_runtime_risk_config(db)
    action = _action_for_tier(config, risk_tier)
    meta = {
        "risk_tier": risk_tier,
        "risk_reasons": risk_reasons,
        "risk_policy_enabled": bool(config.get("enabled")),
        "risk_policy_mode": str(config.get("mode") or "observe"),
        "risk_policy_action": action,
        "risk_policy_decision": "allow",
        "risk_policy_endpoint_family": str(endpoint_family or ""),
    }
    if not config.get("enabled"):
        return meta
    if not _environment_in_enforce_scope(environment, config):
        meta["risk_policy_decision"] = "allow"
        meta["risk_policy_mode"] = "out_of_scope"
        return meta

    if config.get("mode") == "observe":
        meta["risk_policy_decision"] = "observe"
        create_audit_event(
            db,
            actor_id=actor_id,
            action_type="gateway.runtime_risk.observe",
            resource_type="gateway_inference",
            resource_id=str(model_name or "unknown")[:128],
            trace_id=trace_id or f"trace-runtime-risk-{request_id}",
            action_context={
                "risk_tier": risk_tier,
                "risk_reasons": risk_reasons[:12],
                "configured_action": action,
                "endpoint_family": endpoint_family,
                "environment": environment,
                "request_id": request_id,
            },
        )
        return meta

    meta["risk_policy_decision"] = action
    if action == "warn":
        create_audit_event(
            db,
            actor_id=actor_id,
            action_type="gateway.runtime_risk.warn",
            resource_type="gateway_inference",
            resource_id=str(model_name or "unknown")[:128],
            trace_id=trace_id or f"trace-runtime-risk-{request_id}",
            action_context={
                "risk_tier": risk_tier,
                "risk_reasons": risk_reasons[:12],
                "endpoint_family": endpoint_family,
                "environment": environment,
                "request_id": request_id,
            },
        )
        return meta

    if action == "block":
        create_audit_event(
            db,
            actor_id=actor_id,
            action_type="gateway.runtime_risk.block",
            resource_type="gateway_inference",
            resource_id=str(model_name or "unknown")[:128],
            trace_id=trace_id or f"trace-runtime-risk-{request_id}",
            decision_outcome="deny",
            action_context={
                "risk_tier": risk_tier,
                "risk_reasons": risk_reasons[:12],
                "endpoint_family": endpoint_family,
                "environment": environment,
                "request_id": request_id,
            },
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "GATEWAY_RUNTIME_RISK_BLOCKED",
                "message": f"Inference blocked by gateway runtime risk policy (tier={risk_tier}).",
                "risk_tier": risk_tier,
                "risk_reasons": risk_reasons,
                "endpoint_family": endpoint_family,
                "remediation_hint": (
                    "Lower risk factors, target a non-enforced environment, "
                    "or adjust /gateway/runtime-risk/config with dual-approval + MFA."
                ),
            },
        )

    return meta
