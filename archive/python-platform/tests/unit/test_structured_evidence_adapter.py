import logging

from agent_platform.adapters.evidence.structured_evidence_adapter import StructuredEvidenceAdapter
from agent_platform.domain.decision.outcome import DecisionOutcome
from agent_platform.domain.model.policy_decision import PolicyDecision


def test_structured_evidence_redacts_pii_and_adds_description(caplog) -> None:
    adapter = StructuredEvidenceAdapter()
    decision = PolicyDecision(
        outcome=DecisionOutcome.ALLOW,
        reason="Request matches baseline policy.",
        policy_trace_id="trace-policy-default",
        policy_version="v1",
    )

    with caplog.at_level(logging.INFO, logger="platform.evidence"):
        adapter.write_decision_evidence(
            trace_id="trace-1",
            actor_id="user@example.com",
            tenant_id="tenant-a",
            action="navigate",
            target="https://example.com/account/12345",
            decision=decision,
        )

    message = caplog.records[0].getMessage()
    assert "audit_event=policy.preview" in message
    assert "decision_description=Policy preview allow decision" in message
    assert "actor_fingerprint=" in message
    assert "target_fingerprint=" in message
    assert "target_scope=example.com" in message
    assert "pii_redaction=enabled" in message
    assert "user@example.com" not in message
    assert "https://example.com/account/12345" not in message