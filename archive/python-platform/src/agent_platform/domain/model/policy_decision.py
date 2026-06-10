from dataclasses import dataclass

from agent_platform.domain.decision.outcome import DecisionOutcome


@dataclass(frozen=True)
class PolicyDecision:
    outcome: DecisionOutcome
    reason: str
    policy_trace_id: str
    policy_version: str
