import json
from contextvars import ContextVar
from uuid import uuid4
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.logging_utils import get_logger, sanitize_fields
from app.models import AuditEvent
from app.request_context import get_request_actor_role, get_request_user_login
from app.security import resolve_actor_role_for_actor, resolve_user_login_for_actor
from app.services.audit_action_catalog import resolve_action_description


VALID_DECISION_OUTCOMES = {"allow", "deny", "warn"}
MAX_AUDIT_PROMPT_CHARS = 8192
logger = get_logger(__name__)

_audit_action_context_var: ContextVar[Optional[dict[str, Any]]] = ContextVar(
    "audit_action_context",
    default=None,
)


def set_audit_action_context(context: Optional[dict[str, Any]]) -> None:
    _audit_action_context_var.set(dict(context) if context else None)


def push_audit_action_context(**fields: Any) -> None:
    current = dict(_audit_action_context_var.get() or {})
    for key, value in fields.items():
        if value is not None and str(value).strip():
            current[key] = value
    _audit_action_context_var.set(current or None)


def clear_audit_action_context() -> None:
    _audit_action_context_var.set(None)


def get_audit_action_context() -> Optional[dict[str, Any]]:
    current = _audit_action_context_var.get()
    return dict(current) if current else None


def _normalize_decision_outcome(value: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized in VALID_DECISION_OUTCOMES:
        return normalized
    return "allow"


def _resolve_actor_login(
    db: Session,
    actor_id: str,
    user_login: Optional[str] = None,
) -> Optional[str]:
    explicit = (user_login or "").strip()
    if explicit:
        return explicit

    context_login = (get_request_user_login() or "").strip()
    if context_login:
        return context_login

    return resolve_user_login_for_actor(db, actor_id) or "unknown"


def _resolve_actor_role(
    db: Session,
    actor_id: str,
    actor_role: Optional[str] = None,
) -> str:
    explicit = (actor_role or "").strip()
    if explicit:
        return explicit

    context_role = (get_request_actor_role() or "").strip()
    if context_role:
        return context_role

    return resolve_actor_role_for_actor(db, actor_id)


def _truncate_prompt(value: Any) -> str:
    text = str(value or "").strip()
    if len(text) <= MAX_AUDIT_PROMPT_CHARS:
        return text
    return f"{text[:MAX_AUDIT_PROMPT_CHARS]}...[truncated,{len(text)} chars]"


def _normalize_action_context(action_context: Optional[dict[str, Any]]) -> Optional[str]:
    merged: dict[str, Any] = dict(_audit_action_context_var.get() or {})
    if action_context:
        merged.update(action_context)

    prompt_value = merged.pop("user_prompt", None)
    if prompt_value is None:
        prompt_value = merged.pop("prompt_text", None)
    if prompt_value is None:
        prompt_value = merged.pop("prompt_preview", None)
    if prompt_value is not None and str(prompt_value).strip():
        merged["user_prompt"] = _truncate_prompt(prompt_value)

    if not merged:
        return None
    return json.dumps(merged, separators=(",", ":"), ensure_ascii=True)


def parse_audit_action_context(raw: Optional[str]) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def serialize_audit_event(event: AuditEvent, db: Optional[Session] = None) -> dict[str, Any]:
    action_context = parse_audit_action_context(event.action_context_json)
    actor_login = (event.actor_login or "").strip()
    actor_role = (event.actor_role or "").strip()
    action_description = (event.action_description or "").strip()

    if db is not None:
        if not actor_login:
            actor_login = (resolve_user_login_for_actor(db, event.actor_id) or "").strip()
        if not actor_role:
            actor_role = resolve_actor_role_for_actor(db, event.actor_id)

    if not actor_login:
        actor_login = "unknown"
    if not actor_role:
        actor_role = "unknown"
    if not action_description:
        action_description = resolve_action_description(event.action_type)

    return {
        "audit_event_id": event.audit_event_id,
        "timestamp": event.timestamp,
        "actor_type": event.actor_type,
        "actor_id": event.actor_id,
        "actor_login": actor_login,
        "actor_role": actor_role,
        "action_description": action_description,
        "action_type": event.action_type,
        "resource_type": event.resource_type,
        "resource_id": event.resource_id,
        "trace_id": event.trace_id,
        "decision_outcome": event.decision_outcome,
        "policy_version": event.policy_version,
        "action_context": action_context,
        "user_prompt": action_context.get("user_prompt"),
    }


def create_audit_event(
    db: Session,
    actor_id: str,
    action_type: str,
    resource_type: str,
    resource_id: str,
    trace_id: str,
    decision_outcome: str = "allow",
    policy_version: str = "v1",
    tenant_id: Optional[str] = None,
    environment: Optional[str] = None,
    user_login: Optional[str] = None,
    actor_role: Optional[str] = None,
    action_context: Optional[dict[str, Any]] = None,
) -> AuditEvent:
    actor_login = _resolve_actor_login(db, actor_id, user_login=user_login)
    resolved_actor_role = _resolve_actor_role(db, actor_id, actor_role=actor_role)
    action_description = resolve_action_description(action_type)
    action_context_json = _normalize_action_context(action_context)
    logger.trace(
        "audit_event_create_start %s",
        sanitize_fields(
            {
                "actor_id": actor_id,
                "user_login": actor_login,
                "actor_role": resolved_actor_role,
                "action_type": action_type,
                "resource_type": resource_type,
                "resource_id": resource_id,
            }
        ),
    )
    normalized_outcome = _normalize_decision_outcome(decision_outcome)
    event = AuditEvent(
        audit_event_id=str(uuid4()),
        actor_type="user",
        actor_id=actor_id,
        actor_login=actor_login,
        actor_role=resolved_actor_role,
        action_description=action_description,
        action_type=action_type,
        resource_type=resource_type,
        resource_id=resource_id,
        tenant_id=(tenant_id.strip() if isinstance(tenant_id, str) and tenant_id.strip() else None),
        environment=(environment.strip() if isinstance(environment, str) and environment.strip() else None),
        trace_id=trace_id,
        decision_outcome=normalized_outcome,
        policy_version=policy_version,
        action_context_json=action_context_json,
    )
    db.add(event)
    db.flush()
    log_fields: dict[str, Any] = {
        "actor_id": actor_id,
        "user_login": actor_login,
        "actor_role": resolved_actor_role,
        "action_description": action_description,
        "action_type": action_type,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "decision_outcome": normalized_outcome,
        "tenant_id": tenant_id,
        "environment": environment,
    }
    if action_context_json:
        parsed = parse_audit_action_context(action_context_json)
        if parsed.get("user_prompt"):
            log_fields["user_prompt"] = parsed["user_prompt"]
    logger.info("audit_event_created %s", sanitize_fields(log_fields))

    matched_prefixes = (
        "gateway.assistants.",
        "gateway.threads.",
        "gateway.fine_tuning.",
        "gateway.passthrough.execute",
        "compliance.evidence.export",
    )
    should_evaluate_siem = not str(action_type or "").startswith("observability.siem.") and (
        normalized_outcome == "deny"
        or any(
            action_type == "gateway.passthrough.execute"
            or action_type == "compliance.evidence.export"
            or action_type.startswith(prefix)
            for prefix in matched_prefixes
        )
    )
    if should_evaluate_siem:
        try:
            from app.services.siem_alert_rules import dispatch_siem_alerts_for_event

            dispatch_siem_alerts_for_event(db, event)
        except Exception as exc:  # noqa: BLE001 — audit path must not fail on SIEM dispatch
            logger.error("siem_alert_dispatch_failed %s", sanitize_fields({"error": str(exc), "action_type": action_type}))

    return event
