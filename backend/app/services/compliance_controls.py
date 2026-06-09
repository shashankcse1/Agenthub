from __future__ import annotations

import json
from typing import Optional

from sqlalchemy.orm import Session

from app.logging_utils import get_logger
from app.runtime_constants import (
    RUNTIME_CONFIG_COMPLIANCE_CONTROL_CATALOG_JSON,
    RUNTIME_CONFIG_COMPLIANCE_DEFAULT_CONTROL_MAPPINGS_JSON,
)
from app.services.runtime_config import get_runtime_config

logger = get_logger(__name__)

CONTROL_CATALOG = {
    "CTRL-AUDIT-IMMUTABLE": "Immutable audit trail coverage",
    "CTRL-AUTHZ-ROLE": "Role-based authorization enforcement",
    "CTRL-BUDGET-GUARD": "Budget policy guardrail enforcement",
    "CTRL-READINESS-SIGNED": "Readiness certification integrity and evidence signing",
    "CTRL-SCALE-CERT": "Scale and load certification evidence",
}

DEFAULT_CONTROL_MAPPINGS = {
    "CTRL-AUDIT-IMMUTABLE": {
        "control_family": "audit_governance",
        "requirement_text": "Immutable audit logs with trace lineage.",
        "applicable_components": "[\"audit\", \"observability\"]",
        "required_evidence_types": "[\"audit_events\", \"trace_events\"]",
        "automation_status": "automated",
        "owner_team": "platform-security",
        "review_frequency": "monthly",
    },
    "CTRL-AUTHZ-ROLE": {
        "control_family": "identity_access",
        "requirement_text": "Role-based authorization and separation-of-duties.",
        "applicable_components": "[\"auth\", \"route_drafts\", \"agentic\"]",
        "required_evidence_types": "[\"policy_decisions\", \"approval_events\"]",
        "automation_status": "automated",
        "owner_team": "platform-security",
        "review_frequency": "monthly",
    },
    "CTRL-BUDGET-GUARD": {
        "control_family": "cost_governance",
        "requirement_text": "Budget and anomaly control actions are enforced and auditable.",
        "applicable_components": "[\"cost\", \"gateway\"]",
        "required_evidence_types": "[\"cost_events\", \"policy_actions\"]",
        "automation_status": "automated",
        "owner_team": "platform-finops",
        "review_frequency": "monthly",
    },
    "CTRL-READINESS-SIGNED": {
        "control_family": "change_release",
        "requirement_text": "Readiness certifications are signed and exportable as evidence.",
        "applicable_components": "[\"agentic\"]",
        "required_evidence_types": "[\"readiness_certifications\", \"audit_events\"]",
        "automation_status": "automated",
        "owner_team": "platform-reliability",
        "review_frequency": "monthly",
    },
    "CTRL-SCALE-CERT": {
        "control_family": "change_release",
        "requirement_text": "Scale/load, degradation, and recovery certifications are tracked with evidence.",
        "applicable_components": "[\"agentic\", \"compliance\"]",
        "required_evidence_types": "[\"scale_load_tests\", \"evidence_artifacts\"]",
        "automation_status": "automated",
        "owner_team": "platform-reliability",
        "review_frequency": "monthly",
    },
}


def _parse_control_catalog(raw: str) -> Optional[dict[str, str]]:
    try:
        parsed = json.loads(raw)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None

    output: dict[str, str] = {}
    for key, value in parsed.items():
        if not isinstance(key, str) or not isinstance(value, str):
            continue
        normalized_key = key.strip()
        normalized_value = value.strip()
        if normalized_key and normalized_value:
            output[normalized_key] = normalized_value
    return output or None


def _parse_default_control_mappings(raw: str) -> Optional[dict[str, dict[str, str]]]:
    try:
        parsed = json.loads(raw)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None

    required_fields = {
        "control_family",
        "requirement_text",
        "applicable_components",
        "required_evidence_types",
        "automation_status",
        "owner_team",
        "review_frequency",
    }
    output: dict[str, dict[str, str]] = {}
    for control_id, payload in parsed.items():
        if not isinstance(control_id, str) or not isinstance(payload, dict):
            continue
        normalized_id = control_id.strip()
        if not normalized_id:
            continue

        normalized_payload: dict[str, str] = {}
        for field in required_fields:
            value = payload.get(field)
            if not isinstance(value, str):
                normalized_payload = {}
                break
            normalized_payload[field] = value.strip()
        if normalized_payload and all(normalized_payload.values()):
            output[normalized_id] = normalized_payload

    return output or None


def get_control_catalog(db: Session) -> dict[str, str]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_COMPLIANCE_CONTROL_CATALOG_JSON, "")
    if raw:
        parsed = _parse_control_catalog(raw)
        if parsed is not None:
            return parsed
        logger.warning("compliance_control_catalog_runtime_parse_failed")
    return CONTROL_CATALOG


def get_default_control_mappings(db: Session) -> dict[str, dict[str, str]]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_COMPLIANCE_DEFAULT_CONTROL_MAPPINGS_JSON, "")
    if raw:
        parsed = _parse_default_control_mappings(raw)
        if parsed is not None:
            return parsed
        logger.warning("compliance_default_control_mappings_runtime_parse_failed")
    return DEFAULT_CONTROL_MAPPINGS


def known_control_ids(db: Optional[Session] = None) -> set[str]:
    logger.trace("compliance_controls_known_ids")
    if db is None:
        return set(DEFAULT_CONTROL_MAPPINGS.keys())
    return set(get_default_control_mappings(db).keys())
