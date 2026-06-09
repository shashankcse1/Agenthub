from uuid import uuid4

from sqlalchemy.orm import Session

from app.logging_utils import get_logger, sanitize_fields
from app.models import AuditEvent


VALID_DECISION_OUTCOMES = {"allow", "deny", "warn"}
logger = get_logger(__name__)


def _normalize_decision_outcome(value: str) -> str:
    normalized = (value or "").strip().lower()
    if normalized in VALID_DECISION_OUTCOMES:
        return normalized
    return "allow"


def create_audit_event(
    db: Session,
    actor_id: str,
    action_type: str,
    resource_type: str,
    resource_id: str,
    trace_id: str,
    decision_outcome: str = "allow",
    policy_version: str = "v1",
) -> AuditEvent:
    logger.trace(
        "audit_event_create_start %s",
        sanitize_fields(
            {
                "actor_id": actor_id,
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
        action_type=action_type,
        resource_type=resource_type,
        resource_id=resource_id,
        trace_id=trace_id,
        decision_outcome=normalized_outcome,
        policy_version=policy_version,
    )
    db.add(event)
    db.flush()
    logger.info(
        "audit_event_created %s",
        sanitize_fields(
            {
                "actor_id": actor_id,
                "action_type": action_type,
                "resource_type": resource_type,
                "resource_id": resource_id,
                "decision_outcome": normalized_outcome,
            }
        ),
    )
    return event
