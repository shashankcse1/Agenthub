from abc import ABC, abstractmethod
from typing import List

from agent_platform.domain.model.audit_event import AuditEvent
from agent_platform.domain.model.evidence_bundle import EvidenceBundle
from agent_platform.domain.model.policy_decision import PolicyDecision


class EvidencePort(ABC):
    @abstractmethod
    def write_decision_evidence(
        self,
        trace_id: str,
        actor_id: str,
        tenant_id: str,
        action: str,
        target: str,
        decision: PolicyDecision,
    ) -> None:
        raise NotImplementedError

    @abstractmethod
    def list_audit_events(self, limit: int = 100) -> List[AuditEvent]:
        raise NotImplementedError

    @abstractmethod
    def export_evidence_bundle(
        self,
        exported_by: str,
        exporter_role: str,
        limit: int = 100,
    ) -> EvidenceBundle:
        raise NotImplementedError

    @abstractmethod
    def verify_evidence_bundle(self, bundle: EvidenceBundle) -> bool:
        raise NotImplementedError
