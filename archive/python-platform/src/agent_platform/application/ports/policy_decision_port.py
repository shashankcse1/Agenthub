from abc import ABC, abstractmethod

from agent_platform.domain.model.policy_decision import PolicyDecision


class PolicyDecisionPort(ABC):
    @abstractmethod
    def evaluate(
        self,
        actor_id: str,
        actor_role: str,
        tenant_id: str,
        environment: str,
        action: str,
        target: str,
    ) -> PolicyDecision:
        raise NotImplementedError
