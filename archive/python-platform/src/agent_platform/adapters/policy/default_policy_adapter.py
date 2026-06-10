from agent_platform.application.ports.policy_decision_port import PolicyDecisionPort
from agent_platform.domain.decision.outcome import DecisionOutcome
from agent_platform.domain.model.policy_decision import PolicyDecision


class DefaultPolicyAdapter(PolicyDecisionPort):
    def evaluate(
        self,
        actor_id: str,
        actor_role: str,
        tenant_id: str,
        environment: str,
        action: str,
        target: str,
    ) -> PolicyDecision:
        if environment.lower() == "prod" and action.lower() == "export_data":
            return PolicyDecision(
                outcome=DecisionOutcome.CHALLENGE,
                reason="Production data export requires dual approval.",
                policy_trace_id="trace-policy-prod-export",
                policy_version="v1",
            )
        return PolicyDecision(
            outcome=DecisionOutcome.ALLOW,
            reason="Request matches baseline policy.",
            policy_trace_id="trace-policy-default",
            policy_version="v1",
        )
