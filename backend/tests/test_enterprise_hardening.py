"""Unit coverage for enterprise-grade hardening slices (no Postgres required)."""

from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import HTTPException

from app.services import gateway_memory


def test_pii_classification_forced_outside_local(monkeypatch):
    monkeypatch.setattr(gateway_memory, "_runtime_environment", lambda: "staging")
    db = MagicMock()
    with patch.object(gateway_memory, "get_runtime_config", return_value="true") as mocked:
        assert gateway_memory._pii_classification_enabled(db) is True
        mocked.assert_called()
        assert mocked.call_args.args[2] == "true"


def test_pii_classification_default_off_in_dev(monkeypatch):
    monkeypatch.setattr(gateway_memory, "_runtime_environment", lambda: "dev")
    db = MagicMock()
    with patch.object(gateway_memory, "get_runtime_config", return_value="false") as mocked:
        assert gateway_memory._pii_classification_enabled(db) is False
        assert mocked.call_args.args[2] == "false"


def test_long_term_memory_gets_ttl_days(monkeypatch):
    monkeypatch.setattr(gateway_memory, "_runtime_environment", lambda: "dev")
    monkeypatch.setattr(gateway_memory, "_long_term_memory_enabled", lambda _db: True)
    monkeypatch.setattr(gateway_memory, "_pii_classification_enabled", lambda _db: False)
    monkeypatch.setattr(gateway_memory, "_memory_content_max_bytes", lambda _db: 16384)
    monkeypatch.setattr(gateway_memory, "_long_term_ttl_days", lambda _db: 30)
    monkeypatch.setattr(gateway_memory, "get_runtime_config_int", lambda *_args, **_kwargs: 200)

    db = MagicMock()
    db.query.return_value.filter.return_value.scalar.return_value = 0

    row = gateway_memory.create_memory_record(
        db,
        actor_id="actor-1",
        memory_tier="long_term",
        scope_type="agent",
        scope_id="agent-1",
        label="note",
        content="enterprise retention content",
        metadata_json="{}",
        environment="staging",
        memory_id="mem-enterprise-1",
    )
    assert row.expires_at is not None
    assert row.expires_at > datetime.utcnow() + timedelta(days=29)


def test_expire_stale_memory_covers_long_term():
    now = datetime.utcnow()
    stale = SimpleNamespace(
        memory_tier="long_term",
        status="active",
        expires_at=now - timedelta(days=1),
        updated_at=now - timedelta(days=1),
    )
    db = MagicMock()
    db.query.return_value.filter.return_value.all.return_value = [stale]
    expired = gateway_memory.expire_stale_memory_records(db)
    assert expired == 1
    assert stale.status == "expired"


def test_governance_export_schema_includes_classification_fields():
    from app.schemas import GatewayGovernanceEvidenceExportRequest, GatewayGovernanceEvidenceExportResponse

    req = GatewayGovernanceEvidenceExportRequest(
        data_classification="restricted",
        retention_days=30,
        classification_owner="ciso-delegate",
        approved_sharing_channels=["ciso"],
        redact_actor_login=True,
    )
    assert req.data_classification == "restricted"
    assert req.retention_days == 30
    assert req.classification_owner == "ciso-delegate"
    fields = GatewayGovernanceEvidenceExportResponse.model_fields
    for key in (
        "data_classification",
        "classification_owner",
        "retention_days",
        "retain_until",
        "approved_sharing_channels",
        "redaction_applied",
    ):
        assert key in fields


def test_basic_auth_expiry_auto_disables_stale_windows():
    from app.services.basic_auth_expiry import (
        MAX_BREAK_GLASS_DURATION_MINUTES,
        clamp_max_enable_duration_minutes,
        expire_stale_basic_auth_fallbacks,
    )

    assert clamp_max_enable_duration_minutes(999999) == MAX_BREAK_GLASS_DURATION_MINUTES
    assert clamp_max_enable_duration_minutes(30) == 30

    now = datetime.utcnow()
    stale = SimpleNamespace(enabled=True, expires_at=now - timedelta(minutes=1), last_toggled_at=now - timedelta(hours=1))
    db = MagicMock()
    # Query already filters expires_at <= now; mock returns only stale matches.
    db.query.return_value.filter.return_value.all.return_value = [stale]
    disabled = expire_stale_basic_auth_fallbacks(db, now=now)
    assert disabled == 1
    assert stale.enabled is False


def test_transport_posture_exposes_hsts_policy():
    from app.security import transport_posture

    posture = transport_posture()
    assert posture["hsts_configured"] is True
    assert "max-age=" in str(posture["hsts_header_policy"])
    assert "expect_https" in posture


def test_least_privilege_apply_schema_requires_ticket_fields():
    from app.schemas import GatewayLeastPrivilegeRecommendationApplyRequest

    payload = GatewayLeastPrivilegeRecommendationApplyRequest(
        decision_reason="Right-size unused roles",
        change_ticket_id="CHG-1001",
        review_evidence_uri="evidence://review/1001",
    )
    assert payload.change_ticket_id == "CHG-1001"


def test_flow_revision_and_promote_schemas():
    from app.schemas import (
        OrchestrationFlowPromoteRequest,
        OrchestrationFlowRollbackRequest,
    )

    promote = OrchestrationFlowPromoteRequest(target_environment="prod", change_ticket_id="CHG-9")
    assert promote.target_environment == "prod"
    rollback = OrchestrationFlowRollbackRequest(version=2)
    assert rollback.version == 2


def test_snapshot_helper_builds_revision_row():
    from app.routers.orchestration import _serialize_flow_revision, _snapshot_flow_revision

    db = MagicMock()
    flow = SimpleNamespace(
        flow_id="flow-1",
        metadata_version=3,
        flow_name="Support triage",
        description="desc",
        status="active",
        environment="dev",
        trigger_type="manual",
        trigger_config_json="{}",
        graph_json='{"nodes":[],"edges":[]}',
        access_policy_json="{}",
    )
    revision = _snapshot_flow_revision(db, flow, actor_id="actor-1", change_reason="unit")
    db.add.assert_called_once()
    serialized = _serialize_flow_revision(revision)
    assert serialized["version"] == 3
    assert serialized["flow_id"] == "flow-1"
