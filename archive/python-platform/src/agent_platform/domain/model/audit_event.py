from dataclasses import dataclass


@dataclass(frozen=True)
class AuditEvent:
    created_at: str
    prev_event_hash: str
    event_hash: str
    event_type: str
    decision_description: str
    trace_id: str
    actor_fingerprint: str
    tenant_id: str
    action: str
    target_scope: str
    target_fingerprint: str
    outcome: str
    reason: str
    policy_trace_id: str
    policy_version: str
    pii_redaction: str