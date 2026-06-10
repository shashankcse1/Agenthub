from agent_platform.adapters.evidence.structured_evidence_adapter import StructuredEvidenceAdapter
from agent_platform.adapters.policy.default_policy_adapter import DefaultPolicyAdapter
from agent_platform.api.security.auth import validate_auth_runtime_guardrails
from agent_platform.application.usecases.preview_decision_usecase import PreviewDecisionUseCase

validate_auth_runtime_guardrails()

evidence_adapter = StructuredEvidenceAdapter()
policy_adapter = DefaultPolicyAdapter()
preview_decision_use_case = PreviewDecisionUseCase(
    policy_port=policy_adapter,
    evidence_port=evidence_adapter,
)