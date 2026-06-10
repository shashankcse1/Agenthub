import json
from datetime import datetime, timedelta, timezone

from agent_platform.adapters.evidence.structured_evidence_adapter import StructuredEvidenceAdapter
from agent_platform.domain.decision.outcome import DecisionOutcome
from agent_platform.domain.model.policy_decision import PolicyDecision


def _old_timestamp(days_ago: int) -> str:
    ts = datetime.now(timezone.utc) - timedelta(days=days_ago)
    return ts.isoformat().replace("+00:00", "Z")


def test_retention_filters_old_events_without_legal_hold(monkeypatch, tmp_path) -> None:
    store_path = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("EVIDENCE_STORE_PATH", str(store_path))
    monkeypatch.setenv("EVIDENCE_RETENTION_DAYS", "7")
    monkeypatch.setenv("EVIDENCE_LEGAL_HOLD_ENABLED", "false")

    old_event = {
        "created_at": _old_timestamp(30),
        "prev_event_hash": "GENESIS",
        "event_hash": "old-event-hash",
        "event_type": "policy.preview",
        "decision_description": "old event",
        "trace_id": "trace-old",
        "actor_fingerprint": "abc123",
        "tenant_id": "tenant-a",
        "action": "navigate",
        "target_scope": "example.com",
        "target_fingerprint": "def456",
        "outcome": "ALLOW",
        "reason": "old",
        "policy_trace_id": "policy-old",
        "policy_version": "v1",
        "pii_redaction": "enabled",
    }
    store_path.write_text(json.dumps(old_event) + "\n", encoding="utf-8")

    adapter = StructuredEvidenceAdapter()
    decision = PolicyDecision(
        outcome=DecisionOutcome.ALLOW,
        reason="fresh event",
        policy_trace_id="policy-fresh",
        policy_version="v1",
    )
    adapter.write_decision_evidence(
        trace_id="trace-new",
        actor_id="actor-1",
        tenant_id="tenant-a",
        action="navigate",
        target="https://example.com",
        decision=decision,
    )

    events = adapter.list_audit_events(limit=10)
    assert len(events) == 1
    assert events[0].trace_id == "trace-new"


def test_legal_hold_preserves_old_events(monkeypatch, tmp_path) -> None:
    store_path = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("EVIDENCE_STORE_PATH", str(store_path))
    monkeypatch.setenv("EVIDENCE_RETENTION_DAYS", "7")
    monkeypatch.setenv("EVIDENCE_LEGAL_HOLD_ENABLED", "true")

    old_event = {
        "created_at": _old_timestamp(30),
        "prev_event_hash": "GENESIS",
        "event_hash": "old-event-hash",
        "event_type": "policy.preview",
        "decision_description": "old event",
        "trace_id": "trace-old",
        "actor_fingerprint": "abc123",
        "tenant_id": "tenant-a",
        "action": "navigate",
        "target_scope": "example.com",
        "target_fingerprint": "def456",
        "outcome": "ALLOW",
        "reason": "old",
        "policy_trace_id": "policy-old",
        "policy_version": "v1",
        "pii_redaction": "enabled",
    }
    store_path.write_text(json.dumps(old_event) + "\n", encoding="utf-8")

    adapter = StructuredEvidenceAdapter()
    events = adapter.list_audit_events(limit=10)
    assert len(events) == 1
    assert events[0].trace_id == "trace-old"


def test_worm_storage_mode_writes_immutable_event_files(monkeypatch, tmp_path) -> None:
    worm_dir = tmp_path / "worm-events"
    monkeypatch.setenv("EVIDENCE_STORAGE_MODE", "worm_json")
    monkeypatch.setenv("EVIDENCE_STORE_PATH", str(worm_dir))
    monkeypatch.setenv("EVIDENCE_LEGAL_HOLD_ENABLED", "true")

    adapter = StructuredEvidenceAdapter()
    decision = PolicyDecision(
        outcome=DecisionOutcome.ALLOW,
        reason="worm event",
        policy_trace_id="policy-worm",
        policy_version="v1",
    )
    adapter.write_decision_evidence(
        trace_id="trace-worm-1",
        actor_id="actor-1",
        tenant_id="tenant-a",
        action="navigate",
        target="https://example.com",
        decision=decision,
    )
    adapter.write_decision_evidence(
        trace_id="trace-worm-2",
        actor_id="actor-2",
        tenant_id="tenant-a",
        action="navigate",
        target="https://example.com/profile",
        decision=decision,
    )

    files = list(worm_dir.glob("*.json"))
    assert len(files) == 2

    events = adapter.list_audit_events(limit=10)
    assert len(events) == 2
    assert events[0].prev_event_hash == "GENESIS"
    assert events[1].prev_event_hash == events[0].event_hash


def test_invalid_storage_mode_fails_fast(monkeypatch, tmp_path) -> None:
    store_path = tmp_path / "evidence.jsonl"
    monkeypatch.setenv("EVIDENCE_STORE_PATH", str(store_path))
    monkeypatch.setenv("EVIDENCE_STORAGE_MODE", "invalid-mode")

    try:
        StructuredEvidenceAdapter()
        assert False, "Expected unsupported storage mode to fail"
    except ValueError as exc:
        assert "Unsupported EVIDENCE_STORAGE_MODE" in str(exc)
