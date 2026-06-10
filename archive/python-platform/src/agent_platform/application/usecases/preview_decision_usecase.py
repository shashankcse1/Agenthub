from agent_platform.application.ports.evidence_port import EvidencePort
from agent_platform.application.ports.policy_decision_port import PolicyDecisionPort
from agent_platform.domain.model.policy_decision import PolicyDecision


class PreviewDecisionUseCase:
    def __init__(self, policy_port: PolicyDecisionPort, evidence_port: EvidencePort) -> None:
        self._policy_port = policy_port
        self._evidence_port = evidence_port

    def execute(
        self,
        trace_id: str,
        actor_id: str,
        actor_role: str,
        tenant_id: str,
        environment: str,
        action: str,
        target: str,
    ) -> PolicyDecision:
        decision = self._policy_port.evaluate(
            actor_id=actor_id,
            actor_role=actor_role,
            tenant_id=tenant_id,
            environment=environment,
            action=action,
            target=target,
        )
        self._evidence_port.write_decision_evidence(
            trace_id=trace_id,
            actor_id=actor_id,
            tenant_id=tenant_id,
            action=action,
            target=target,
            decision=decision,
        )
        return decision
