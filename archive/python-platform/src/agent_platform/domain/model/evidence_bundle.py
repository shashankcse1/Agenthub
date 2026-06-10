from dataclasses import dataclass
from typing import List

from agent_platform.domain.model.audit_event import AuditEvent


@dataclass(frozen=True)
class EvidenceBundle:
    exported_by: str
    exporter_role: str
    event_count: int
    signature_algorithm: str
    chain_head: str
    signature: str
    events: List[AuditEvent]