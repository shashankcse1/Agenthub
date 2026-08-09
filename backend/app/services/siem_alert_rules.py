from __future__ import annotations

import json
import re
from datetime import datetime
from fnmatch import fnmatch
from typing import Any, Optional
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import AuditEvent
from app.runtime_constants import RUNTIME_CONFIG_OBSERVABILITY_SIEM_RULES_JSON
from app.services.audit import create_audit_event, serialize_audit_event
from app.services.runtime_config import get_runtime_config


DEFAULT_SIEM_ALERT_RULES: list[dict[str, Any]] = [
    {
        "rule_id": "siem-gateway-assistants-mutations",
        "name": "Gateway assistants lifecycle",
        "description": "Alert on gateway assistant create, retrieve, list, and delete audit events.",
        "action_type_pattern": "gateway.assistants.*",
        "decision_outcomes": ["allow", "deny"],
        "severity": "medium",
        "sink_route_key": "gateway-assistants",
        "enabled": True,
    },
    {
        "rule_id": "siem-gateway-threads-mutations",
        "name": "Gateway thread lifecycle",
        "description": "Alert on gateway thread create, retrieve, message, and run audit events.",
        "action_type_pattern": "gateway.threads.*",
        "decision_outcomes": ["allow", "deny"],
        "severity": "medium",
        "sink_route_key": "gateway-threads",
        "enabled": True,
    },
    {
        "rule_id": "siem-gateway-fine-tuning-mutations",
        "name": "Gateway fine-tuning lifecycle",
        "description": "Alert on fine-tuning job create, retrieve, list, and cancel audit events.",
        "action_type_pattern": "gateway.fine_tuning.*",
        "decision_outcomes": ["allow", "deny"],
        "severity": "medium",
        "sink_route_key": "gateway-fine-tuning",
        "enabled": True,
    },
    {
        "rule_id": "siem-gateway-passthrough-execute",
        "name": "Gateway passthrough execution",
        "description": "Alert on passthrough proxy execution including prod dual-approval denials.",
        "action_type_pattern": "gateway.passthrough.execute",
        "decision_outcomes": ["allow", "deny"],
        "severity": "high",
        "sink_route_key": "gateway-passthrough",
        "enabled": True,
    },
    {
        "rule_id": "siem-compliance-evidence-export",
        "name": "Compliance evidence export",
        "description": "Alert on compliance bundle export allow and missing-control deny outcomes.",
        "action_type_pattern": "compliance.evidence.export",
        "decision_outcomes": ["allow", "deny"],
        "severity": "high",
        "sink_route_key": "compliance-export",
        "enabled": True,
    },
    {
        "rule_id": "siem-gateway-privileged-deny",
        "name": "Gateway privileged deny outcomes",
        "description": "High-severity alert when privileged gateway actions are denied.",
        "action_type_pattern": "gateway.*",
        "decision_outcomes": ["deny"],
        "severity": "high",
        "sink_route_key": "gateway-deny",
        "enabled": True,
    },
    {
        "rule_id": "siem-secret-provider-value-mutations",
        "name": "Secret provider value mutations",
        "description": (
            "Alert on secret_provider.value.* audit events (read/upsert/delete) so SIEM can "
            "correlate volume spikes (GAP-USP-R05)."
        ),
        "action_type_pattern": "secret_provider.value.*",
        "decision_outcomes": ["allow", "deny"],
        "severity": "high",
        "sink_route_key": "secret-provider-values",
        "enabled": True,
    },
    {
        "rule_id": "siem-directory-user-unlock",
        "name": "Directory user unlock",
        "description": "Alert on privileged unlock operations to detect unlock abuse patterns.",
        "action_type_pattern": "auth.directory.user.unlock*",
        "decision_outcomes": ["allow", "deny"],
        "severity": "high",
        "sink_route_key": "directory-unlock",
        "enabled": True,
    },
    {
        "rule_id": "siem-least-privilege-apply",
        "name": "Least-privilege apply actions",
        "description": "Alert on gateway.least_privilege.apply* volume and denials for over-restrictive apply detection.",
        "action_type_pattern": "gateway.least_privilege.apply*",
        "decision_outcomes": ["allow", "deny"],
        "severity": "medium",
        "sink_route_key": "least-privilege-apply",
        "enabled": True,
    },
    {
        "rule_id": "siem-insecure-configuration-audit",
        "name": "Insecure configuration audit",
        "description": (
            "Alert when insecure configuration is audited (complements SECURITY_ALERT_WEBHOOK_URL "
            "startup/health webhook routing)."
        ),
        "action_type_pattern": "security.insecure_configuration*",
        "decision_outcomes": ["allow", "deny"],
        "severity": "high",
        "sink_route_key": "insecure-configuration",
        "enabled": True,
    },
]


def _normalize_rule(row: dict[str, Any]) -> dict[str, Any]:
    rule_id = str(row.get("rule_id") or "").strip()
    if not rule_id:
        raise ValueError("rule_id is required")
    pattern = str(row.get("action_type_pattern") or "").strip()
    if not pattern:
        raise ValueError(f"action_type_pattern is required for rule {rule_id}")
    outcomes_raw = row.get("decision_outcomes") or ["allow", "deny"]
    if not isinstance(outcomes_raw, list):
        raise ValueError(f"decision_outcomes must be a list for rule {rule_id}")
    outcomes = [str(item).strip().lower() for item in outcomes_raw if str(item).strip()]
    if not outcomes:
        outcomes = ["allow", "deny"]
    severity = str(row.get("severity") or "medium").strip().lower() or "medium"
    if severity not in {"low", "medium", "high", "critical"}:
        raise ValueError(f"invalid severity for rule {rule_id}")
    return {
        "rule_id": rule_id,
        "name": str(row.get("name") or rule_id).strip() or rule_id,
        "description": str(row.get("description") or "").strip(),
        "action_type_pattern": pattern,
        "decision_outcomes": outcomes,
        "severity": severity,
        "sink_route_key": str(row.get("sink_route_key") or rule_id).strip() or rule_id,
        "enabled": bool(row.get("enabled", True)),
    }


def _parse_runtime_rules(raw: str) -> list[dict[str, Any]]:
    text = str(raw or "").strip()
    if not text:
        return [_normalize_rule(row) for row in DEFAULT_SIEM_ALERT_RULES]
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("observability.siem_rules_json must be valid JSON") from exc
    if not isinstance(payload, list):
        raise ValueError("observability.siem_rules_json must be a JSON array")
    if not payload:
        return [_normalize_rule(row) for row in DEFAULT_SIEM_ALERT_RULES]
    return [_normalize_rule(row) for row in payload if isinstance(row, dict)]


def load_siem_alert_rules(db: Session) -> list[dict[str, Any]]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_OBSERVABILITY_SIEM_RULES_JSON, "[]")
    text = str(raw or "").strip()
    if not text or text == "[]":
        return [_normalize_rule(row) for row in DEFAULT_SIEM_ALERT_RULES]
    return _parse_runtime_rules(text)


def match_siem_rules_for_event(event: AuditEvent, rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    action_type = str(event.action_type or "").strip()
    outcome = str(event.decision_outcome or "allow").strip().lower() or "allow"
    matched: list[dict[str, Any]] = []
    for rule in rules:
        if not rule.get("enabled", True):
            continue
        pattern = str(rule.get("action_type_pattern") or "").strip()
        if not pattern:
            continue
        if not fnmatch(action_type, pattern):
            continue
        allowed_outcomes = rule.get("decision_outcomes") or ["allow", "deny"]
        if outcome not in allowed_outcomes:
            continue
        matched.append(rule)
    return matched


def _load_gateway_external_callbacks(db: Session) -> list[dict[str, Any]]:
    from app.routers.gateway import _load_gateway_external_callbacks

    return _load_gateway_external_callbacks(db)


def _resolve_siem_callbacks(db: Session, sink_route_key: str) -> list[dict[str, Any]]:
    normalized_key = str(sink_route_key or "").strip().lower()
    callbacks: list[dict[str, Any]] = []
    for row in _load_gateway_external_callbacks(db):
        sink_type = str(row.get("sink_type") or "generic_webhook").strip().lower()
        if sink_type != "siem":
            continue
        if not bool(row.get("enabled", True)):
            continue
        route_key = str(row.get("sink_route_key") or "").strip().lower()
        if normalized_key and route_key and route_key != normalized_key:
            continue
        callbacks.append(row)
    return callbacks


def build_siem_alert_payload(event: AuditEvent, rule: dict[str, Any]) -> dict[str, Any]:
    serialized = serialize_audit_event(event)
    return {
        "alert_id": f"siem-alert-{uuid4().hex[:16]}",
        "rule_id": rule.get("rule_id"),
        "rule_name": rule.get("name"),
        "severity": rule.get("severity"),
        "sink_route_key": rule.get("sink_route_key"),
        "dispatched_at": datetime.utcnow().isoformat() + "Z",
        "audit_event": serialized,
        "correlation": {
            "trace_id": event.trace_id,
            "action_type": event.action_type,
            "decision_outcome": event.decision_outcome,
            "resource_type": event.resource_type,
            "resource_id": event.resource_id,
        },
    }


def dispatch_siem_alerts_for_event(db: Session, event: AuditEvent) -> list[dict[str, Any]]:
    rules = load_siem_alert_rules(db)
    matched_rules = match_siem_rules_for_event(event, rules)
    if not matched_rules:
        return []

    dispatches: list[dict[str, Any]] = []
    for rule in matched_rules:
        callbacks = _resolve_siem_callbacks(db, str(rule.get("sink_route_key") or ""))
        payload = build_siem_alert_payload(event, rule)
        if not callbacks:
            create_audit_event(
                db,
                actor_id="system",
                action_type="observability.siem.alert.unrouted",
                resource_type="siem_alert_rule",
                resource_id=str(rule.get("rule_id") or ""),
                trace_id=f"trace-siem-unrouted-{uuid4().hex[:16]}",
                decision_outcome="warn",
                action_context={
                    "rule_id": rule.get("rule_id"),
                    "audit_event_id": event.audit_event_id,
                    "reason": "no_enabled_siem_callback_for_sink_route_key",
                },
            )
            dispatches.append(
                {
                    "rule_id": rule.get("rule_id"),
                    "delivery_status": "unrouted",
                    "callback_count": 0,
                    "payload_preview": payload,
                }
            )
            continue

        for callback in callbacks:
            callback_id = str(callback.get("callback_id") or "")
            trace_id = f"trace-siem-dispatch-{callback_id}-{uuid4().hex[:12]}"
            create_audit_event(
                db,
                actor_id="system",
                action_type="observability.siem.alert.dispatched",
                resource_type="gateway_external_callback",
                resource_id=callback_id or str(rule.get("rule_id") or ""),
                trace_id=trace_id,
                decision_outcome="allow",
                environment=event.environment,
                action_context={
                    "rule_id": rule.get("rule_id"),
                    "audit_event_id": event.audit_event_id,
                    "callback_id": callback_id,
                    "sink_type": "siem",
                    "sink_route_key": rule.get("sink_route_key"),
                    "delivery_status": "delivered_simulated",
                },
            )
            dispatches.append(
                {
                    "rule_id": rule.get("rule_id"),
                    "callback_id": callback_id,
                    "delivery_status": "delivered_simulated",
                    "trace_id": trace_id,
                    "payload_preview": payload,
                }
            )
    return dispatches


def export_siem_rules_catalog(db: Session, *, include_defaults: bool = True) -> dict[str, Any]:
    rules = load_siem_alert_rules(db)
    callbacks = [row for row in _load_gateway_external_callbacks(db) if str(row.get("sink_type") or "").lower() == "siem"]
    return {
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "rule_count": len(rules),
        "siem_callback_count": len(callbacks),
        "rules": rules,
        "default_rule_ids": [row["rule_id"] for row in DEFAULT_SIEM_ALERT_RULES] if include_defaults else [],
        "siem_callbacks": [
            {
                "callback_id": row.get("callback_id"),
                "sink_route_key": row.get("sink_route_key"),
                "enabled": row.get("enabled", True),
                "environment": row.get("environment"),
            }
            for row in callbacks
        ],
    }


def evaluate_siem_rules_against_events(
    db: Session,
    events: list[AuditEvent],
) -> list[dict[str, Any]]:
    rules = load_siem_alert_rules(db)
    evaluations: list[dict[str, Any]] = []
    for event in events:
        matched = match_siem_rules_for_event(event, rules)
        if not matched:
            continue
        evaluations.append(
            {
                "audit_event_id": event.audit_event_id,
                "action_type": event.action_type,
                "decision_outcome": event.decision_outcome,
                "trace_id": event.trace_id,
                "matched_rule_ids": [row.get("rule_id") for row in matched],
            }
        )
    return evaluations
