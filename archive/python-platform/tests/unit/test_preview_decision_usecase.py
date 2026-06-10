from agent_platform.adapters.evidence.structured_evidence_adapter import StructuredEvidenceAdapter
from agent_platform.adapters.policy.default_policy_adapter import DefaultPolicyAdapter
from agent_platform.application.usecases.preview_decision_usecase import PreviewDecisionUseCase
from agent_platform.domain.decision.outcome import DecisionOutcome


def test_preview_decision_returns_challenge_for_prod_export() -> None:
    use_case = PreviewDecisionUseCase(DefaultPolicyAdapter(), StructuredEvidenceAdapter())
    decision = use_case.execute(
        trace_id="trace-1",
        actor_id="a1",
        actor_role="Platform Admin",
        tenant_id="tenant-a",
        environment="prod",
        action="export_data",
        target="dataset",
    )
    assert decision.outcome == DecisionOutcome.CHALLENGE


def test_preview_decision_returns_allow_for_regular_action() -> None:
    use_case = PreviewDecisionUseCase(DefaultPolicyAdapter(), StructuredEvidenceAdapter())
    decision = use_case.execute(
        trace_id="trace-2",
        actor_id="a2",
        actor_role="Platform Admin",
        tenant_id="tenant-a",
        environment="dev",
        action="navigate",
        target="https://example.com",
    )
    assert decision.outcome == DecisionOutcome.ALLOW
