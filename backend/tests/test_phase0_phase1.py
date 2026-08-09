from datetime import datetime, timedelta
import json
import os
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from sqlalchemy import inspect
from sqlalchemy.orm import Session
from uuid import uuid4

from app.database import engine
from app.models import CostEvent, RuntimeConfig, SecretProviderConfig, SessionRecord
from app.main import app
from tests.conftest import (
    post_benchmark_run_and_wait,
    post_scan_run_and_wait,
    response_error_code,
    response_error_message,
    wait_for_benchmark_run,
    wait_for_scan_run,
)

client = TestClient(app)


def ensure_tenant_catalog_entry(tenant_id: str, actor_id: str = "admin-tenant-seed") -> None:
    response = client.post(
        "/providers/tenants",
        json={
            "tenant_id": tenant_id,
            "tenant_name": tenant_id.replace("-", " ").title(),
            "tenant_type": "enterprise",
            "description": f"Seeded tenant catalog entry for {tenant_id}",
            "status": "active",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id, "X-MFA-Verified": "true"},
    )
    assert response.status_code in {200, 409}


def assert_role_forbidden_detail(payload: dict, actor_role: str = "Auditor") -> None:
    assert payload["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"
    assert payload["detail"]["actor_role"] == actor_role
    assert payload["detail"]["required_role"] == "Platform Admin, Release Manager"
    assert payload["detail"]["decision_trace_id"] == "authz-role-check"


def get_delete_audit_events(resource_id: str, decision_outcome: str, actor_id: str = "aud-delete-check") -> list[dict]:
    events_response = client.get(
        f"/audit/events?action_type=agentic.policy.schedule.delete&resource_type=policy_schedule&resource_id={resource_id}&decision_outcome={decision_outcome}&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": actor_id},
    )
    assert events_response.status_code == 200
    events = events_response.json()
    assert all(event["resource_id"] == resource_id for event in events)
    assert all(event["decision_outcome"] == decision_outcome for event in events)
    return events


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["status"] == "ok"
    assert "rate_limit" in payload
    assert "configured_backend" in payload["rate_limit"]
    assert "active_backend" in payload["rate_limit"]
    assert "degraded" in payload["rate_limit"]
    assert "redis_retry_seconds" in payload["rate_limit"]
    assert "degraded_alert_attempts" in payload["rate_limit"]


def test_agents_create_alias_matches_register_security_controls():
    payload = {
        "name": "agent-create-alias",
        "owner_id": "owner-alias-1",
        "owner_name": "Owner Alias",
        "owner_team": "Team Alias",
        "risk_tier": "medium",
    }

    created = client.post(
        "/agents",
        json=payload,
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-create-alias"},
    )
    assert created.status_code == 200
    assert created.json()["owner_id"] == payload["owner_id"]

    denied = client.post(
        "/agents",
        json={**payload, "owner_id": "different-owner"},
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": payload["owner_id"]},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"


def test_ui_polling_rate_limit_applies_to_observability_logs_endpoint():
    headers = {"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-rate-limit-logs"}
    for _ in range(30):
        ok = client.get("/observability/logs?limit=1", headers=headers)
        assert ok.status_code == 200

    throttled = client.get("/observability/logs?limit=1", headers=headers)
    assert throttled.status_code == 429
    detail = throttled.json()["detail"]
    assert detail["error_code"] == "RATE_LIMIT_EXCEEDED"
    assert detail["actor_id"] == "aud-rate-limit-logs"
    assert detail["path"] == "/observability/logs"


def test_gateway_analytics_summary_endpoint_returns_aggregates_for_authorized_roles():
    route = client.post(
        "/gateway/routes",
        json={
            "route_name": "analytics-route",
            "candidate_deployments": '["provider-a","provider-b"]',
            "load_balancing_strategy": "weighted",
            "retry_policy": "{}",
            "fallback_policy": "{}",
            "timeout_policy": "{}",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-gw-analytics"},
    )
    assert route.status_code == 200
    route_id = route.json()["route_policy_id"]

    priority = client.post(
        f"/gateway/routes/{route_id}/providers/priority",
        json={
            "tenant_id": "tenant-analytics",
            "environment": "dev",
            "priority_order": '[{"provider_id":"provider-a","priority":1},{"provider_id":"provider-b","priority":2}]',
            "global_timeout_ms": 4500,
            "max_fallback_hops": 2,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-gw-analytics"},
    )
    assert priority.status_code == 200

    executed = client.post(
        f"/gateway/routes/{route_id}/execute-fallback",
        json={
            "tenant_id": "tenant-analytics",
            "environment": "dev",
            "agent_id": "agent-analytics",
            "session_id": "session-analytics",
            "owner_scope": "team-analytics",
            "endpoint_family": "responses",
            "input_tokens": 120,
            "output_tokens": 60,
            "currency": "USD",
            "simulate_fail_provider_ids": "[]",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-gw-analytics"},
    )
    assert executed.status_code == 200

    denied = client.get(
        "/gateway/analytics/summary?environment=prod&hours=24",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-no-access"},
    )
    assert denied.status_code == 403

    summary = client.get(
        "/gateway/analytics/summary?environment=prod&hours=24",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-gw-analytics"},
    )
    assert summary.status_code == 200
    payload = summary.json()
    assert payload["environment"] == "prod"
    assert payload["hours"] == 24
    assert payload["total_events"] >= 1
    assert payload["distinct_requests"] >= 1
    assert payload["total_estimated_cost_cents"] >= 1
    assert isinstance(payload["top_models"], list)
    assert isinstance(payload["top_endpoint_families"], list)
    assert "on_plane_coverage_percent" in payload
    assert "on_plane_events" in payload
    assert "off_plane_detected" in payload
    assert isinstance(payload.get("on_plane_coverage"), dict)
    assert payload["on_plane_events"] >= 1
    assert payload["on_plane_coverage_percent"] is not None


def test_observability_logs_redact_sensitive_mode_masks_identity_fields():
    created = client.post(
        "/agents/register",
        json={
            "name": "agent-observability-redact",
            "owner_id": "owner-redact-12345",
            "owner_name": "Owner Redact",
            "owner_team": "Team Redact",
            "risk_tier": "low",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-redact-actor"},
    )
    assert created.status_code == 200

    logs = client.get(
        "/observability/logs?limit=20&redact_sensitive=true",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-redact"},
    )
    assert logs.status_code == 200
    payload = logs.json()
    assert isinstance(payload, list)
    assert len(payload) >= 1
    target = next((row for row in payload if row["action_type"] == "agents.register"), None)
    assert target is not None
    assert target["actor_id"].startswith("***")
    assert target["resource_id"].startswith("***")
    assert target["owner_scope"] == "masked"


def test_playground_run_get_enforces_agent_owner_scope():
    created = client.post(
        "/playground/runs",
        json={
            "prompt_text": "scope-check",
            "candidate_models": '["model-a"]',
            "selected_model": "model-a",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-scope-1"},
    )
    assert created.status_code == 200
    run_id = created.json()["run_id"]

    denied = client.get(
        f"/playground/runs/{run_id}",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-scope-2"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"

    allowed = client.get(
        f"/playground/runs/{run_id}",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-scope-1"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["run_id"] == run_id


def test_audit_events_enforce_roles_and_agent_owner_scope():
    run_owner_a = client.post(
        "/playground/runs",
        json={
            "prompt_text": "audit-scope-a",
            "candidate_models": '["model-a"]',
            "selected_model": "model-a",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-audit-a"},
    )
    assert run_owner_a.status_code == 200

    run_owner_b = client.post(
        "/playground/runs",
        json={
            "prompt_text": "audit-scope-b",
            "candidate_models": '["model-b"]',
            "selected_model": "model-b",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-audit-b"},
    )
    assert run_owner_b.status_code == 200

    forbidden_role = client.get(
        "/audit/events?limit=10",
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-audit-read"},
    )
    assert forbidden_role.status_code == 403
    assert forbidden_role.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    owner_filtered = client.get(
        "/audit/events?action_type=playground.run.create&limit=50",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-audit-a"},
    )
    assert owner_filtered.status_code == 200
    owner_payload = owner_filtered.json()
    assert len(owner_payload) >= 1
    assert all(evt["actor_id"] == "owner-audit-a" for evt in owner_payload)

    owner_override_denied = client.get(
        "/audit/events?action_type=playground.run.create&actor_id=owner-audit-b&limit=50",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-audit-a"},
    )
    assert owner_override_denied.status_code == 403
    assert owner_override_denied.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"


def test_observability_enforces_agent_owner_scope_for_logs_and_traces():
    owner_a_run = client.post(
        "/playground/runs",
        json={
            "prompt_text": "obs-scope-a",
            "candidate_models": '["model-a"]',
            "selected_model": "model-a",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-obs-a"},
    )
    assert owner_a_run.status_code == 200
    run_id_a = owner_a_run.json()["run_id"]

    owner_b_run = client.post(
        "/playground/runs",
        json={
            "prompt_text": "obs-scope-b",
            "candidate_models": '["model-b"]',
            "selected_model": "model-b",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-obs-b"},
    )
    assert owner_b_run.status_code == 200
    run_id_b = owner_b_run.json()["run_id"]

    owner_a_logs = client.get(
        "/observability/logs?limit=100",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-obs-a"},
    )
    assert owner_a_logs.status_code == 200
    logs_payload = owner_a_logs.json()
    assert len(logs_payload) >= 1
    assert all(row["actor_id"] == "owner-obs-a" for row in logs_payload)

    denied_trace = client.get(
        f"/observability/traces/trace-{run_id_b}",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-obs-a"},
    )
    assert denied_trace.status_code == 403
    assert denied_trace.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"

    allowed_trace = client.get(
        f"/observability/traces/trace-{run_id_a}",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-obs-a"},
    )
    assert allowed_trace.status_code == 200
    assert allowed_trace.json()["trace_id"] == f"trace-{run_id_a}"


def test_agent_registration_and_lookup():
    payload = {
        "name": "agent-a",
        "owner_id": "owner-1",
        "owner_name": "Owner One",
        "owner_team": "Team A",
        "risk_tier": "medium",
    }
    resp = client.post(
        "/agents/register",
        json=payload,
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-1"},
    )
    assert resp.status_code == 200
    agent = resp.json()

    lookup = client.get(
        f"/owners/{agent['owner_id']}/agents",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-owner-lookup"},
    )
    assert lookup.status_code == 200
    assert any(a["agent_id"] == agent["agent_id"] for a in lookup.json())


def test_agent_register_options_endpoint():
    resp = client.get(
        "/agents/register-options",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-register-options"},
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert isinstance(payload.get("allowed_agent_types"), list)
    assert payload.get("default_environment") == "dev"
    # Full catalog — not limited to the four cloud deployment types.
    for expected in (
        "assistant",
        "chatbot",
        "automation",
        "orchestrator",
        "aws",
        "azure",
        "gcp",
        "onprem",
        "hybrid",
        "other",
    ):
        assert expected in payload["allowed_agent_types"]
    assert len(payload["allowed_agent_types"]) >= 10
    assert isinstance(payload.get("provider_backed_agent_types"), list)


def test_agent_register_options_derives_types_from_active_providers():
    from app.database import SessionLocal
    from app.models import SecretProviderConfig

    suffix = uuid4().hex[:8]
    secret_provider_id = f"sec-aws-{suffix}"
    db = SessionLocal()
    try:
        db.add(
            SecretProviderConfig(
                secret_provider_id=secret_provider_id,
                tenant_id=f"tenant-{suffix}",
                provider_type="aws-secrets-manager",
                provider_address="https://secretsmanager.us-east-1.amazonaws.com",
                auth_method="iam_role",
                role_or_mount="arn:aws:iam::123456789012:role/agent-register-test",
                secret_path_prefixes='["agents/"]',
                status="active",
            )
        )
        db.commit()
    finally:
        db.close()

    resp = client.get(
        "/agents/register-options",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": f"aud-register-options-{suffix}"},
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert "aws" in payload["allowed_agent_types"]
    assert "assistant" in payload["allowed_agent_types"]
    assert "aws" in payload["provider_backed_agent_types"]


def test_agent_register_persists_inventory_without_auto_config_stub():
    payload = {
        "name": "agent-inventory-only",
        "owner_id": "owner-inventory",
        "owner_name": "Owner Inventory",
        "owner_team": "Platform Ops",
        "agent_type": "other",
        "risk_tier": "medium",
    }
    created = client.post(
        "/agents/register",
        json=payload,
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-inventory"},
    )
    assert created.status_code == 200
    agent_id = created.json()["agent_id"]

    configs = client.get("/agent-configs", headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-inventory"})
    assert configs.status_code == 200
    assert not any(row["agent_key"] == agent_id for row in configs.json())


def test_agent_owner_scoped_ownership_history_and_owner_listing():
    from app.database import SessionLocal
    from app.models import Agent

    db = SessionLocal()
    try:
        agent_a = Agent(
            agent_id=f"agent-scope-a-{uuid4()}",
            name="Agent Scope A",
            owner_id="owner-scope-1",
            owner_name="Owner Scope 1",
            owner_team="Team Scope 1",
            risk_tier="low",
            status="active",
        )
        agent_b = Agent(
            agent_id=f"agent-scope-b-{uuid4()}",
            name="Agent Scope B",
            owner_id="owner-scope-2",
            owner_name="Owner Scope 2",
            owner_team="Team Scope 2",
            risk_tier="low",
            status="active",
        )
        db.add_all([agent_a, agent_b])
        db.commit()
        agent_a_id = agent_a.agent_id
        agent_b_id = agent_b.agent_id
    finally:
        db.close()

    own_agents = client.get(
        f"/owners/owner-scope-1/agents",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-scope-1"},
    )
    assert own_agents.status_code == 200
    assert any(row["agent_id"] == agent_a_id for row in own_agents.json())
    assert all(row["owner_id"] == "owner-scope-1" for row in own_agents.json())

    cross_owner_agents = client.get(
        f"/owners/owner-scope-2/agents",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-scope-1"},
    )
    assert cross_owner_agents.status_code == 403
    assert cross_owner_agents.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"

    history_allowed = client.get(
        f"/agents/{agent_a_id}/ownership-history",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-scope-1"},
    )
    assert history_allowed.status_code == 200

    history_denied = client.get(
        f"/agents/{agent_b_id}/ownership-history",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-scope-1"},
    )
    assert history_denied.status_code == 403
    assert history_denied.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"


def test_agent_owner_transfer_scoped_to_owned_agents():
    from app.database import SessionLocal
    from app.models import Agent

    db = SessionLocal()
    try:
        owned = Agent(
            agent_id=f"agent-transfer-owned-{uuid4()}",
            name="Transfer Owned",
            owner_id="owner-transfer-a",
            owner_name="Owner Transfer A",
            owner_team="Team Transfer A",
            risk_tier="low",
            status="active",
        )
        cross = Agent(
            agent_id=f"agent-transfer-cross-{uuid4()}",
            name="Transfer Cross",
            owner_id="owner-transfer-b",
            owner_name="Owner Transfer B",
            owner_team="Team Transfer B",
            risk_tier="low",
            status="active",
        )
        db.add_all([owned, cross])
        db.commit()
        owned_id = owned.agent_id
        cross_id = cross.agent_id
    finally:
        db.close()

    allowed = client.patch(
        f"/agents/{owned_id}/owner",
        json={
            "new_owner_id": "owner-transfer-c",
            "new_owner_name": "Owner Transfer C",
            "new_owner_team": "Team Transfer C",
            "reason": "reassignment",
            "ticket_ref": "TICKET-1",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-transfer-a"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["owner_id"] == "owner-transfer-c"

    denied = client.patch(
        f"/agents/{cross_id}/owner",
        json={
            "new_owner_id": "owner-transfer-d",
            "new_owner_name": "Owner Transfer D",
            "new_owner_team": "Team Transfer D",
            "reason": "reassignment",
            "ticket_ref": "TICKET-2",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-transfer-a"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"


def test_sso_provider_create_and_test():
    payload = {
        "tenant_id": "tenant-1",
        "protocol_type": "OIDC",
        "issuer_or_entity_id": "issuer-1",
        "jwks_or_metadata_url": "https://example.com/jwks.json",
        "scim_base_url": "https://example.com/scim",
    }
    resp = client.post(
        "/auth/sso/providers",
        json=payload,
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-1"},
    )
    assert resp.status_code == 200
    provider_id = resp.json()["provider_id"]

    test_resp = client.post(
        f"/auth/sso/providers/{provider_id}/test",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-1"},
    )
    assert test_resp.status_code == 200
    assert test_resp.json()["test_status"] == "passed"


def test_sso_provider_test_and_scim_sync_require_platform_admin():
    payload = {
        "tenant_id": "tenant-authz-1",
        "protocol_type": "OIDC",
        "issuer_or_entity_id": "issuer-authz-1",
        "jwks_or_metadata_url": "https://example.com/jwks.json",
        "scim_base_url": "https://example.com/scim",
    }
    created = client.post(
        "/auth/sso/providers",
        json=payload,
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-authz"},
    )
    assert created.status_code == 200
    provider_id = created.json()["provider_id"]

    test_denied = client.post(
        f"/auth/sso/providers/{provider_id}/test",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-authz"},
    )
    assert test_denied.status_code == 403
    assert test_denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    sync_denied = client.post(
        f"/auth/sso/providers/{provider_id}/scim/sync",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-authz"},
    )
    assert sync_denied.status_code == 403
    assert sync_denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"


def test_auth_session_get_requires_read_roles_and_role_binding_validate_requires_admin():
    issued = client.post(
        "/auth/sessions",
        json={"actor_id": "sess-read-actor", "actor_role": "Agent Owner", "ttl_minutes": 30},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-session"},
    )
    assert issued.status_code == 200
    session_id = issued.json()["session_id"]

    forbidden = client.get(
        f"/auth/sessions/{session_id}",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-session"},
    )
    assert forbidden.status_code == 403
    assert forbidden.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    allowed_auditor = client.get(
        f"/auth/sessions/{session_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-session"},
    )
    assert allowed_auditor.status_code == 200
    assert allowed_auditor.json()["session_id"] == session_id

    role_binding_denied = client.post(
        "/auth/roles/bindings/validate",
        json={"role_name": "Agent Owner", "resource_pattern": "agents/*", "action": "read"},
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-bindings"},
    )
    assert role_binding_denied.status_code == 403
    assert role_binding_denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    role_binding_allowed = client.post(
        "/auth/roles/bindings/validate",
        json={"role_name": "Agent Owner", "resource_pattern": "agents/*", "action": "read"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-bindings"},
    )
    assert role_binding_allowed.status_code == 200
    assert role_binding_allowed.json()["valid"] is True


def test_auth_authz_explain_returns_decision_trace_and_dual_approval_requirements():
    denied = client.post(
        "/auth/authz/explain",
        json={
            "actor_role": "Release Manager",
            "actor_id": "rel-authz-explain",
            "action": "auth.session.issue",
            "resource_type": "session",
            "resource_id": "session-issue",
            "target_actor_id": "platform-admin-target",
            "target_actor_role": "Platform Admin",
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-authz-explain"},
    )
    assert denied.status_code == 200
    denied_payload = denied.json()
    assert denied_payload["decision"] == "deny"
    assert denied_payload["requires_dual_approval"] is True
    assert denied_payload["required_approver_role"] == "Security Approver"
    assert denied_payload["decision_trace_id"] == "authz-auth-explain-deny"

    allowed = client.post(
        "/auth/authz/explain",
        json={
            "actor_role": "Platform Admin",
            "actor_id": "admin-authz-explain",
            "action": "auth.session.issue",
            "resource_type": "session",
            "resource_id": "session-issue",
            "target_actor_id": "platform-admin-target",
            "target_actor_role": "Platform Admin",
            "approver_role": "Security Approver",
            "approver_id": "sec-authz-explain",
        },
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-authz-explain-reader"},
    )
    assert allowed.status_code == 200
    allowed_payload = allowed.json()
    assert allowed_payload["decision"] == "allow"
    assert allowed_payload["requires_dual_approval"] is True
    assert allowed_payload["decision_trace_id"] == "authz-auth-explain-allow"

    unknown_action = client.post(
        "/auth/authz/explain",
        json={
            "actor_role": "Platform Admin",
            "actor_id": "admin-authz-explain",
            "action": "auth.unknown.action",
            "resource_type": "auth_action",
            "resource_id": "auth.unknown.action",
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-authz-explain"},
    )
    assert unknown_action.status_code == 200
    assert unknown_action.json()["decision"] == "warn"
    assert unknown_action.json()["decision_trace_id"] == "authz-auth-explain-unknown-action"

    evidence = client.get(
        "/audit/events?action_type=auth.authz.explain&resource_type=session&resource_id=session-issue&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-authz-explain"},
    )
    assert evidence.status_code == 200
    events = evidence.json()
    assert any(evt["actor_id"] == "aud-authz-explain" and evt["decision_outcome"] == "deny" for evt in events)
    assert any(evt["actor_id"] == "sec-authz-explain-reader" and evt["decision_outcome"] == "allow" for evt in events)


def test_sso_provider_test_and_scim_sync_emit_allow_audit_events():
    payload = {
        "tenant_id": "tenant-audit-1",
        "protocol_type": "OIDC",
        "issuer_or_entity_id": "issuer-audit-1",
        "jwks_or_metadata_url": "https://example.com/jwks.json",
        "scim_base_url": "https://example.com/scim",
    }
    created = client.post(
        "/auth/sso/providers",
        json=payload,
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-audit-1"},
    )
    assert created.status_code == 200
    provider_id = created.json()["provider_id"]

    tested = client.post(
        f"/auth/sso/providers/{provider_id}/test",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-audit-1"},
    )
    assert tested.status_code == 200

    synced = client.post(
        f"/auth/sso/providers/{provider_id}/scim/sync",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-audit-1"},
    )
    assert synced.status_code == 200

    test_events = client.get(
        f"/audit/events?action_type=auth.sso.provider.test&resource_type=identity_provider&resource_id={provider_id}&decision_outcome=allow&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-audit-1"},
    )
    assert test_events.status_code == 200
    assert any(evt["actor_id"] == "admin-audit-1" for evt in test_events.json())

    scim_events = client.get(
        f"/audit/events?action_type=auth.sso.provider.scim_sync&resource_type=identity_provider&resource_id={provider_id}&decision_outcome=allow&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-audit-1"},
    )
    assert scim_events.status_code == 200
    assert any(evt["actor_id"] == "admin-audit-1" for evt in scim_events.json())


def test_auth_session_issue_and_bearer_context_access():
    issued = client.post(
        "/auth/sessions",
        json={
            "actor_id": "token-admin-1",
            "actor_role": "Platform Admin",
            "ttl_minutes": 60,
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-issuer",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-issuer",
        },
    )
    assert issued.status_code == 200
    token = issued.json()["access_token"]
    assert issued.json()["token_type"] == "Bearer"

    live = client.get(
        "/cost/live",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert live.status_code == 200


def test_auth_session_invalid_bearer_token_rejected():
    resp = client.get(
        "/cost/live",
        headers={"Authorization": "Bearer not-a-real-session"},
    )
    assert resp.status_code == 401
    detail = resp.json()["detail"]
    assert detail["error_code"] == "AUTHN_INVALID_TOKEN"


def test_auth_session_idle_timeout_and_reauth_flow():
    issued = client.post(
        "/auth/sessions",
        json={
            "actor_id": "token-idle-1",
            "actor_role": "Platform Admin",
            "ttl_minutes": 60,
            "idle_timeout_minutes": 1,
            "mfa_verified": False,
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-issuer",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-issuer",
        },
    )
    assert issued.status_code == 200
    token = issued.json()["access_token"]
    session_id = issued.json()["session_id"]

    from app.database import SessionLocal

    db = SessionLocal()
    try:
        session = db.query(SessionRecord).filter_by(session_id=session_id).first()
        assert session is not None
        session.last_activity_at = datetime.utcnow().replace(year=2020)
        db.commit()
    finally:
        db.close()

    idle = client.get("/cost/live", headers={"Authorization": f"Bearer {token}"})
    assert idle.status_code == 401
    assert idle.json()["detail"]["error_code"] == "AUTHN_SESSION_IDLE_TIMEOUT"

    reauth = client.post(
        f"/auth/sessions/{session_id}/reauth",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-issuer"},
    )
    assert reauth.status_code == 200


def test_workload_identity_token_exchange_requires_mfa():
    ensure_tenant_catalog_entry("tenant-token-exchange", "admin-provider-tenant-token-exchange")
    created = client.post(
        "/auth/workload-identity/providers",
        json={
            "tenant_id": "tenant-token-exchange",
            "provider_type": "aws",
            "audience": "aud-1",
            "role_arn_or_equivalent": "arn:aws:iam::123456789012:role/test",
            "session_duration_seconds": 900,
            "allowed_subject_patterns": "[]",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-provider", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    profile_id = created.json()["workload_identity_profile_id"]

    denied = client.post(
        "/auth/workload-identity/token-exchange",
        json={"tenant_id": "tenant-token-exchange", "workload_identity_profile_id": profile_id, "subject": "svc:test"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-provider"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_MFA_REQUIRED"


def test_workload_identity_trust_validation_health_and_degraded_exchange_block():
    ensure_tenant_catalog_entry("tenant-token-health", "admin-provider-tenant-token-health")
    created = client.post(
        "/auth/workload-identity/providers",
        json={
            "tenant_id": "tenant-token-health",
            "provider_type": "aws",
            "audience": "aud-health",
            "role_arn_or_equivalent": "arn:aws:iam::123456789012:role/health",
            "session_duration_seconds": 900,
            "allowed_subject_patterns": "[]",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-provider-health", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    profile_id = created.json()["workload_identity_profile_id"]

    trust_ok = client.post(
        f"/auth/workload-identity/providers/{profile_id}/validate-trust",
        json={
            "tenant_id": "tenant-token-health",
            "check_type": "trust_policy",
            "expected_audience": "aud-health",
            "simulate_pass": True,
        },
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-provider-health", "X-MFA-Verified": "true"},
    )
    assert trust_ok.status_code == 200
    assert trust_ok.json()["status"] == "active"

    exchanged = client.post(
        "/auth/workload-identity/token-exchange",
        json={"tenant_id": "tenant-token-health", "workload_identity_profile_id": profile_id, "subject": "svc:health"},
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-provider-health", "X-MFA-Verified": "true"},
    )
    assert exchanged.status_code in {200, 502, 503}
    if exchanged.status_code != 200:
        assert "AWS STS" in response_error_message(exchanged)

    health = client.get(
        f"/auth/workload-identity/providers/{profile_id}/health?tenant_id=tenant-token-health",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-provider-health"},
    )
    assert health.status_code == 200
    assert health.json()["status"] == "active"
    assert health.json()["tenant_id"] == "tenant-token-health"
    if exchanged.status_code == 200:
        assert health.json()["last_token_exchange_at"] is not None

    trust_fail = client.post(
        f"/auth/workload-identity/providers/{profile_id}/validate-trust",
        json={
            "tenant_id": "tenant-token-health",
            "check_type": "trust_policy",
            "expected_audience": "aud-health",
            "simulate_pass": False,
        },
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-provider-health", "X-MFA-Verified": "true"},
    )
    assert trust_fail.status_code == 200
    assert trust_fail.json()["status"] == "degraded"

    blocked_exchange = client.post(
        "/auth/workload-identity/token-exchange",
        json={"tenant_id": "tenant-token-health", "workload_identity_profile_id": profile_id, "subject": "svc:health"},
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-provider-health", "X-MFA-Verified": "true"},
    )
    assert blocked_exchange.status_code == 400
    assert response_error_code(blocked_exchange) == "VALIDATION_ERROR"
    assert "not active" in response_error_message(blocked_exchange)


def test_workload_identity_token_exchange_rejects_tenant_mismatch():
    ensure_tenant_catalog_entry("tenant-token-match", "admin-provider-tenant-token-match")
    created = client.post(
        "/auth/workload-identity/providers",
        json={
            "tenant_id": "tenant-token-match",
            "provider_type": "aws",
            "audience": "aud-match",
            "role_arn_or_equivalent": "arn:aws:iam::123456789012:role/test",
            "session_duration_seconds": 900,
            "allowed_subject_patterns": "[]",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-provider-match", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    profile_id = created.json()["workload_identity_profile_id"]

    mismatch = client.post(
        "/auth/workload-identity/token-exchange",
        json={"tenant_id": "tenant-other", "workload_identity_profile_id": profile_id, "subject": "svc:test"},
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-provider-match", "X-MFA-Verified": "true"},
    )
    assert mismatch.status_code == 403
    assert response_error_code(mismatch) == "AUTHZ_SCOPE_FORBIDDEN"
    assert "Tenant scope mismatch" in response_error_message(mismatch)


def test_workload_identity_token_exchange_supports_azure_runtime_injection():
    ensure_tenant_catalog_entry("tenant-azure-token", "admin-provider-tenant-azure-token")
    created = client.post(
        "/auth/workload-identity/providers",
        json={
            "tenant_id": "tenant-azure-token",
            "provider_type": "azure",
            "audience": "api://agenthub",
            "role_arn_or_equivalent": "azure-workload-identity",
            "session_duration_seconds": 1200,
            "allowed_subject_patterns": "[]",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-azure-provider", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    profile_id = created.json()["workload_identity_profile_id"]

    configured = client.put(
        "/runtime-config/workload_identity.default_expires_in_seconds",
        json={"config_value": "1800", "description": "test azure runtime injection expiry"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-azure-runtime-config"},
    )
    assert configured.status_code == 200

    original_token = os.environ.get("AZURE_WORKLOAD_IDENTITY_ACCESS_TOKEN")
    os.environ["AZURE_WORKLOAD_IDENTITY_ACCESS_TOKEN"] = "azure-test-token"

    try:
        exchanged = client.post(
            "/auth/workload-identity/token-exchange",
            json={
                "tenant_id": "tenant-azure-token",
                "workload_identity_profile_id": profile_id,
                "subject": "svc:azure",
            },
            headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-azure-provider", "X-MFA-Verified": "true"},
        )
    finally:
        client.delete(
            "/runtime-config/workload_identity.default_expires_in_seconds",
            headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-azure-runtime-config-cleanup"},
        )
        if original_token is None:
            os.environ.pop("AZURE_WORKLOAD_IDENTITY_ACCESS_TOKEN", None)
        else:
            os.environ["AZURE_WORKLOAD_IDENTITY_ACCESS_TOKEN"] = original_token

    assert exchanged.status_code == 200
    payload = exchanged.json()
    assert payload["token_source"] == "azure_workload_identity"
    assert payload["expires_in"] == 1800


def test_workload_identity_provider_health_rejects_tenant_mismatch():
    ensure_tenant_catalog_entry("tenant-health-scope", "admin-provider-tenant-health-scope")
    created = client.post(
        "/auth/workload-identity/providers",
        json={
            "tenant_id": "tenant-health-scope",
            "provider_type": "aws",
            "audience": "aud-health-scope",
            "role_arn_or_equivalent": "arn:aws:iam::123456789012:role/health",
            "session_duration_seconds": 900,
            "allowed_subject_patterns": "[]",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-provider-health-scope", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    profile_id = created.json()["workload_identity_profile_id"]

    mismatch = client.get(
        f"/auth/workload-identity/providers/{profile_id}/health?tenant_id=tenant-other-scope",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-provider-health-scope"},
    )
    assert mismatch.status_code == 403
    assert response_error_code(mismatch) == "AUTHZ_SCOPE_FORBIDDEN"
    assert "Tenant scope mismatch" in response_error_message(mismatch)


def test_workload_identity_provider_list_supports_filters_and_pagination():
    tenant = f"tenant-list-wi-{uuid4().hex[:8]}"
    ensure_tenant_catalog_entry(tenant, f"admin-provider-{tenant}")
    created_ids = []
    for idx in range(3):
        created = client.post(
            "/auth/workload-identity/providers",
            json={
                "tenant_id": tenant,
                "provider_type": "aws" if idx < 2 else "google",
                "audience": f"aud-list-{idx}",
                "role_arn_or_equivalent": f"arn:aws:iam::123456789012:role/list-{idx}",
                "session_duration_seconds": 900,
                "allowed_subject_patterns": "[]",
            },
            headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": f"admin-list-wi-{idx}", "X-MFA-Verified": "true"},
        )
        assert created.status_code == 200
        created_ids.append(created.json()["workload_identity_profile_id"])

    listed = client.get(
        f"/auth/workload-identity/providers?tenant_id={tenant}&provider_type=aws&status=active&limit=1&offset=0",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-list-wi"},
    )
    assert listed.status_code == 200
    assert listed.headers.get("x-total-count") == "2"
    rows = listed.json()
    assert len(rows) == 1
    assert rows[0]["tenant_id"] == tenant
    assert rows[0]["provider_type"] == "aws"
    assert rows[0]["status"] == "active"

    page_two = client.get(
        f"/auth/workload-identity/providers?tenant_id={tenant}&provider_type=aws&status=active&limit=1&offset=1",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-list-wi"},
    )
    assert page_two.status_code == 200
    assert page_two.headers.get("x-total-count") == "2"
    assert len(page_two.json()) == 1

    audits = client.get(
        "/audit/events?action_type=workload_identity.provider.list&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-list-wi"},
    )
    assert audits.status_code == 200
    assert any(row["actor_id"] == "aud-list-wi" for row in audits.json())


def test_secret_provider_list_supports_filters_and_pagination():
    tenant = f"tenant-list-sp-{uuid4().hex[:8]}"
    ensure_tenant_catalog_entry(tenant, f"admin-provider-{tenant}")
    for idx in range(3):
        created = client.post(
            "/secrets/providers",
            json={
                "tenant_id": tenant,
                "provider_type": "vault" if idx < 2 else "aws-secrets-manager",
                "provider_address": f"https://vault-list-{idx}.example.internal",
                "auth_method": "approle",
                "role_or_mount": f"role-list-{idx}",
                "secret_path_prefixes": "[\"kv/data/team\"]",
                "lease_ttl_seconds": 600,
                "auto_renew_enabled": idx != 1,
            },
            headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": f"admin-list-sp-{idx}", "X-MFA-Verified": "true"},
        )
        assert created.status_code == 200

    listed = client.get(
        f"/secrets/providers?tenant_id={tenant}&provider_type=vault&status=active&auto_renew_enabled=true&limit=10&offset=0",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-list-sp"},
    )
    assert listed.status_code == 200
    assert listed.headers.get("x-total-count") == "1"
    rows = listed.json()
    assert len(rows) == 1
    assert rows[0]["tenant_id"] == tenant
    assert rows[0]["provider_type"] == "vault"
    assert rows[0]["auto_renew_enabled"] is True

    audits = client.get(
        "/audit/events?action_type=secret_provider.list&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-list-sp"},
    )
    assert audits.status_code == 200
    assert any(row["actor_id"] == "aud-list-sp" for row in audits.json())


def test_workload_identity_token_exchange_supports_azure_native_client_credentials_fallback():
    ensure_tenant_catalog_entry("tenant-azure-native", "admin-provider-tenant-azure-native")
    created = client.post(
        "/auth/workload-identity/providers",
        json={
            "tenant_id": "tenant-azure-native",
            "provider_type": "azure",
            "audience": "api://agenthub",
            "role_arn_or_equivalent": "azure-workload-identity",
            "session_duration_seconds": 1200,
            "allowed_subject_patterns": "[]",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-azure-native", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    profile_id = created.json()["workload_identity_profile_id"]

    saved = {
        "AZURE_WORKLOAD_IDENTITY_ACCESS_TOKEN": os.environ.get("AZURE_WORKLOAD_IDENTITY_ACCESS_TOKEN"),
        "AZURE_WORKLOAD_IDENTITY_EXPIRES_IN": os.environ.get("AZURE_WORKLOAD_IDENTITY_EXPIRES_IN"),
        "AZURE_WORKLOAD_IDENTITY_TENANT_ID": os.environ.get("AZURE_WORKLOAD_IDENTITY_TENANT_ID"),
        "AZURE_WORKLOAD_IDENTITY_CLIENT_ID": os.environ.get("AZURE_WORKLOAD_IDENTITY_CLIENT_ID"),
        "AZURE_WORKLOAD_IDENTITY_CLIENT_SECRET": os.environ.get("AZURE_WORKLOAD_IDENTITY_CLIENT_SECRET"),
        "AZURE_WORKLOAD_IDENTITY_TOKEN_URL": os.environ.get("AZURE_WORKLOAD_IDENTITY_TOKEN_URL"),
        "AZURE_WORKLOAD_IDENTITY_SCOPE": os.environ.get("AZURE_WORKLOAD_IDENTITY_SCOPE"),
    }
    os.environ.pop("AZURE_WORKLOAD_IDENTITY_ACCESS_TOKEN", None)
    os.environ.pop("AZURE_WORKLOAD_IDENTITY_EXPIRES_IN", None)
    os.environ["AZURE_WORKLOAD_IDENTITY_TENANT_ID"] = "tenant-guid"
    os.environ["AZURE_WORKLOAD_IDENTITY_CLIENT_ID"] = "client-id"
    os.environ["AZURE_WORKLOAD_IDENTITY_CLIENT_SECRET"] = "client-secret"
    os.environ["AZURE_WORKLOAD_IDENTITY_TOKEN_URL"] = "https://login.microsoftonline.com/tenant-guid/oauth2/v2.0/token"
    os.environ["AZURE_WORKLOAD_IDENTITY_SCOPE"] = "https://management.azure.com/.default"

    mocked_response = Mock()
    mocked_response.status_code = 200
    mocked_response.json.return_value = {"access_token": "azure-native-token", "expires_in": 1200}

    try:
        with patch("app.routers.providers.httpx.post", return_value=mocked_response):
            exchanged = client.post(
                "/auth/workload-identity/token-exchange",
                json={
                    "tenant_id": "tenant-azure-native",
                    "workload_identity_profile_id": profile_id,
                    "subject": "svc:azure-native",
                },
                headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-azure-native", "X-MFA-Verified": "true"},
            )
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    assert exchanged.status_code == 200
    payload = exchanged.json()
    assert payload["token_source"] == "azure_workload_identity"
    assert payload["expires_in"] == 1200


def test_workload_identity_token_exchange_azure_native_missing_config_fails_closed():
    ensure_tenant_catalog_entry("tenant-azure-missing", "admin-provider-tenant-azure-missing")
    created = client.post(
        "/auth/workload-identity/providers",
        json={
            "tenant_id": "tenant-azure-missing",
            "provider_type": "azure",
            "audience": "api://agenthub",
            "role_arn_or_equivalent": "azure-workload-identity",
            "session_duration_seconds": 1200,
            "allowed_subject_patterns": "[]",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-azure-missing", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    profile_id = created.json()["workload_identity_profile_id"]

    saved = {
        "AZURE_WORKLOAD_IDENTITY_ACCESS_TOKEN": os.environ.get("AZURE_WORKLOAD_IDENTITY_ACCESS_TOKEN"),
        "AZURE_WORKLOAD_IDENTITY_EXPIRES_IN": os.environ.get("AZURE_WORKLOAD_IDENTITY_EXPIRES_IN"),
        "AZURE_WORKLOAD_IDENTITY_TENANT_ID": os.environ.get("AZURE_WORKLOAD_IDENTITY_TENANT_ID"),
        "AZURE_WORKLOAD_IDENTITY_CLIENT_ID": os.environ.get("AZURE_WORKLOAD_IDENTITY_CLIENT_ID"),
        "AZURE_WORKLOAD_IDENTITY_CLIENT_SECRET": os.environ.get("AZURE_WORKLOAD_IDENTITY_CLIENT_SECRET"),
        "AZURE_WORKLOAD_IDENTITY_TOKEN_URL": os.environ.get("AZURE_WORKLOAD_IDENTITY_TOKEN_URL"),
    }

    for key in saved:
        os.environ.pop(key, None)

    try:
        exchanged = client.post(
            "/auth/workload-identity/token-exchange",
            json={
                "tenant_id": "tenant-azure-missing",
                "workload_identity_profile_id": profile_id,
                "subject": "svc:azure-missing",
            },
            headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-azure-missing", "X-MFA-Verified": "true"},
        )
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    assert exchanged.status_code == 503
    assert response_error_code(exchanged) == "SERVICE_UNAVAILABLE"
    assert "Azure workload identity native exchange missing configuration" in response_error_message(exchanged)


def test_workload_identity_token_exchange_supports_google_native_metadata_fallback():
    ensure_tenant_catalog_entry("tenant-google-native", "admin-provider-tenant-google-native")
    created = client.post(
        "/auth/workload-identity/providers",
        json={
            "tenant_id": "tenant-google-native",
            "provider_type": "google",
            "audience": "https://iam.googleapis.com/",
            "role_arn_or_equivalent": "google-workload-identity",
            "session_duration_seconds": 1200,
            "allowed_subject_patterns": "[]",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-google-native", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    profile_id = created.json()["workload_identity_profile_id"]

    saved = {
        "GOOGLE_WORKLOAD_IDENTITY_ACCESS_TOKEN": os.environ.get("GOOGLE_WORKLOAD_IDENTITY_ACCESS_TOKEN"),
        "GOOGLE_WORKLOAD_IDENTITY_EXPIRES_IN": os.environ.get("GOOGLE_WORKLOAD_IDENTITY_EXPIRES_IN"),
        "GOOGLE_WORKLOAD_IDENTITY_TOKEN_URL": os.environ.get("GOOGLE_WORKLOAD_IDENTITY_TOKEN_URL"),
        "GOOGLE_WORKLOAD_IDENTITY_TIMEOUT_SECONDS": os.environ.get("GOOGLE_WORKLOAD_IDENTITY_TIMEOUT_SECONDS"),
        "GOOGLE_WORKLOAD_IDENTITY_BEARER": os.environ.get("GOOGLE_WORKLOAD_IDENTITY_BEARER"),
    }
    os.environ.pop("GOOGLE_WORKLOAD_IDENTITY_ACCESS_TOKEN", None)
    os.environ.pop("GOOGLE_WORKLOAD_IDENTITY_EXPIRES_IN", None)
    os.environ["GOOGLE_WORKLOAD_IDENTITY_TOKEN_URL"] = "https://metadata.google.internal/token"
    os.environ["GOOGLE_WORKLOAD_IDENTITY_TIMEOUT_SECONDS"] = "2.0"

    mocked_response = Mock()
    mocked_response.status_code = 200
    mocked_response.json.return_value = {"access_token": "google-native-token", "expires_in": 900}

    try:
        with patch("app.routers.providers.httpx.get", return_value=mocked_response):
            exchanged = client.post(
                "/auth/workload-identity/token-exchange",
                json={
                    "tenant_id": "tenant-google-native",
                    "workload_identity_profile_id": profile_id,
                    "subject": "svc:google-native",
                },
                headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-google-native", "X-MFA-Verified": "true"},
            )
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    assert exchanged.status_code == 200
    payload = exchanged.json()
    assert payload["token_source"] == "google_workload_identity"
    assert payload["expires_in"] == 900


def test_workload_identity_token_exchange_supports_nvidia_native_client_credentials_fallback():
    ensure_tenant_catalog_entry("tenant-nvidia-native", "admin-provider-tenant-nvidia-native")
    created = client.post(
        "/auth/workload-identity/providers",
        json={
            "tenant_id": "tenant-nvidia-native",
            "provider_type": "nvidia",
            "audience": "https://api.nvidia.com/",
            "role_arn_or_equivalent": "nvidia-workload-identity",
            "session_duration_seconds": 1200,
            "allowed_subject_patterns": "[]",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-nvidia-native", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    profile_id = created.json()["workload_identity_profile_id"]

    saved = {
        "NVIDIA_WORKLOAD_IDENTITY_ACCESS_TOKEN": os.environ.get("NVIDIA_WORKLOAD_IDENTITY_ACCESS_TOKEN"),
        "NVIDIA_WORKLOAD_IDENTITY_EXPIRES_IN": os.environ.get("NVIDIA_WORKLOAD_IDENTITY_EXPIRES_IN"),
        "NVIDIA_WORKLOAD_IDENTITY_CLIENT_ID": os.environ.get("NVIDIA_WORKLOAD_IDENTITY_CLIENT_ID"),
        "NVIDIA_WORKLOAD_IDENTITY_CLIENT_SECRET": os.environ.get("NVIDIA_WORKLOAD_IDENTITY_CLIENT_SECRET"),
        "NVIDIA_WORKLOAD_IDENTITY_TOKEN_URL": os.environ.get("NVIDIA_WORKLOAD_IDENTITY_TOKEN_URL"),
        "NVIDIA_WORKLOAD_IDENTITY_SCOPE": os.environ.get("NVIDIA_WORKLOAD_IDENTITY_SCOPE"),
    }
    os.environ.pop("NVIDIA_WORKLOAD_IDENTITY_ACCESS_TOKEN", None)
    os.environ.pop("NVIDIA_WORKLOAD_IDENTITY_EXPIRES_IN", None)
    os.environ["NVIDIA_WORKLOAD_IDENTITY_CLIENT_ID"] = "nvidia-client-id"
    os.environ["NVIDIA_WORKLOAD_IDENTITY_CLIENT_SECRET"] = "nvidia-client-secret"
    os.environ["NVIDIA_WORKLOAD_IDENTITY_TOKEN_URL"] = "https://auth.nvidia.example/token"
    os.environ["NVIDIA_WORKLOAD_IDENTITY_SCOPE"] = "nim.invoke"

    mocked_response = Mock()
    mocked_response.status_code = 200
    mocked_response.json.return_value = {"access_token": "nvidia-native-token", "expires_in": 1500}

    try:
        with patch("app.routers.providers.httpx.post", return_value=mocked_response):
            exchanged = client.post(
                "/auth/workload-identity/token-exchange",
                json={
                    "tenant_id": "tenant-nvidia-native",
                    "workload_identity_profile_id": profile_id,
                    "subject": "svc:nvidia-native",
                },
                headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-nvidia-native", "X-MFA-Verified": "true"},
            )
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    assert exchanged.status_code == 200
    payload = exchanged.json()
    assert payload["token_source"] == "nvidia_workload_identity"
    assert payload["expires_in"] == 1500


def test_workload_identity_token_exchange_supports_openai_runtime_injection():
    ensure_tenant_catalog_entry("tenant-openai-runtime", "admin-provider-tenant-openai-runtime")
    created = client.post(
        "/auth/workload-identity/providers",
        json={
            "tenant_id": "tenant-openai-runtime",
            "provider_type": "openai",
            "audience": "https://api.openai.com/",
            "role_arn_or_equivalent": "openai-workload-identity",
            "session_duration_seconds": 1800,
            "allowed_subject_patterns": "[]",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-openai-runtime", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    profile_id = created.json()["workload_identity_profile_id"]

    configured = client.put(
        "/runtime-config/workload_identity.default_expires_in_seconds",
        json={"config_value": "1800", "description": "test openai runtime injection expiry"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-openai-runtime-config"},
    )
    assert configured.status_code == 200

    original_token = os.environ.get("OPENAI_WORKLOAD_IDENTITY_ACCESS_TOKEN")
    os.environ["OPENAI_WORKLOAD_IDENTITY_ACCESS_TOKEN"] = "openai-runtime-token"

    try:
        exchanged = client.post(
            "/auth/workload-identity/token-exchange",
            json={
                "tenant_id": "tenant-openai-runtime",
                "workload_identity_profile_id": profile_id,
                "subject": "svc:openai-runtime",
            },
            headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-openai-runtime", "X-MFA-Verified": "true"},
        )
    finally:
        client.delete(
            "/runtime-config/workload_identity.default_expires_in_seconds",
            headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-openai-runtime-config-cleanup"},
        )
        if original_token is None:
            os.environ.pop("OPENAI_WORKLOAD_IDENTITY_ACCESS_TOKEN", None)
        else:
            os.environ["OPENAI_WORKLOAD_IDENTITY_ACCESS_TOKEN"] = original_token

    assert exchanged.status_code == 200
    payload = exchanged.json()
    assert payload["token_source"] == "openai_workload_identity"
    assert payload["expires_in"] == 1800


def test_gateway_can_execute_with_openai_labeled_provider_priority():
    ensure_tenant_catalog_entry("tenant-openai-gateway", "admin-provider-tenant-openai-gateway")
    created = client.post(
        "/auth/workload-identity/providers",
        json={
            "tenant_id": "tenant-openai-gateway",
            "provider_type": "openai",
            "audience": "https://api.openai.com/",
            "role_arn_or_equivalent": "openai-gateway-profile",
            "session_duration_seconds": 1800,
            "allowed_subject_patterns": "[]",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-openai-gateway", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200

    route = client.post(
        "/gateway/routes",
        json={"route_name": "openai-gateway-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-openai-gateway-route"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-openai-gateway",
            "environment": "dev",
            "priority_order": '[{"provider_id":"openai-primary","priority":1},{"provider_id":"openai-fallback","priority":2}]',
            "max_fallback_hops": 1,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-openai-gateway"},
    )
    assert configured.status_code == 200

    executed = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-openai-gateway",
            "environment": "dev",
            "agent_id": "agent-openai-gateway",
            "session_id": "sess-openai-gateway",
            "owner_scope": "team:platform",
            "endpoint_family": "responses",
            "input_tokens": 64,
            "output_tokens": 32,
            "simulate_fail_provider_ids": "[]",
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-openai-gateway"},
    )
    assert executed.status_code == 200
    payload = executed.json()
    assert payload["selected_provider_id"] == "openai-primary"
    assert payload["final_outcome"] == "success"
    assert payload["provider_attempts"] == 1


def test_workload_identity_token_exchange_anthropic_runtime_missing_config_fails_closed():
    ensure_tenant_catalog_entry("tenant-anthropic-runtime", "admin-provider-tenant-anthropic-runtime")
    created = client.post(
        "/auth/workload-identity/providers",
        json={
            "tenant_id": "tenant-anthropic-runtime",
            "provider_type": "anthropic",
            "audience": "https://api.anthropic.com/",
            "role_arn_or_equivalent": "anthropic-workload-identity",
            "session_duration_seconds": 1800,
            "allowed_subject_patterns": "[]",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-anthropic-runtime", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    profile_id = created.json()["workload_identity_profile_id"]

    original_token = os.environ.get("ANTHROPIC_WORKLOAD_IDENTITY_ACCESS_TOKEN")
    original_expires = os.environ.get("ANTHROPIC_WORKLOAD_IDENTITY_EXPIRES_IN")
    os.environ.pop("ANTHROPIC_WORKLOAD_IDENTITY_ACCESS_TOKEN", None)
    os.environ.pop("ANTHROPIC_WORKLOAD_IDENTITY_EXPIRES_IN", None)

    try:
        exchanged = client.post(
            "/auth/workload-identity/token-exchange",
            json={
                "tenant_id": "tenant-anthropic-runtime",
                "workload_identity_profile_id": profile_id,
                "subject": "svc:anthropic-runtime",
            },
            headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-anthropic-runtime", "X-MFA-Verified": "true"},
        )
    finally:
        if original_token is None:
            os.environ.pop("ANTHROPIC_WORKLOAD_IDENTITY_ACCESS_TOKEN", None)
        else:
            os.environ["ANTHROPIC_WORKLOAD_IDENTITY_ACCESS_TOKEN"] = original_token
        if original_expires is None:
            os.environ.pop("ANTHROPIC_WORKLOAD_IDENTITY_EXPIRES_IN", None)
        else:
            os.environ["ANTHROPIC_WORKLOAD_IDENTITY_EXPIRES_IN"] = original_expires

    assert exchanged.status_code == 503
    assert response_error_code(exchanged) == "SERVICE_UNAVAILABLE"
    assert "ANTHROPIC_WORKLOAD_IDENTITY_ACCESS_TOKEN" in response_error_message(exchanged)


def test_secret_provider_lease_renew_list_and_health():
    ensure_tenant_catalog_entry("tenant-secret-lease", "admin-provider-tenant-secret-lease")
    created = client.post(
        "/secrets/providers",
        json={
            "tenant_id": "tenant-secret-lease",
            "provider_type": "vault",
            "provider_address": "https://vault.example.com",
            "auth_method": "approle",
            "role_or_mount": "approle/platform",
            "secret_path_prefixes": "[\"kv/data/platform\"]",
            "lease_ttl_seconds": 600,
            "auto_renew_enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-secret", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    provider_id = created.json()["secret_provider_id"]

    tested = client.post(
        f"/secrets/providers/{provider_id}/test",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-secret", "X-MFA-Verified": "true"},
    )
    assert tested.status_code == 200

    renewed = client.post(
        f"/secrets/providers/{provider_id}/leases/renew",
        json={"secret_ref": "kv/data/platform/api-key", "requested_ttl_seconds": 300},
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-secret", "X-MFA-Verified": "true"},
    )
    assert renewed.status_code == 200
    lease_payload = renewed.json()
    assert lease_payload["secret_provider_id"] == provider_id
    assert lease_payload["secret_ref"] == "kv/data/platform/api-key"
    assert lease_payload["status"] == "active"

    listing = client.get(
        f"/secrets/providers/{provider_id}/leases",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-secret"},
    )
    assert listing.status_code == 200
    listing_payload = listing.json()
    assert listing_payload["secret_provider_id"] == provider_id
    assert any(l["lease_id"] == lease_payload["lease_id"] for l in listing_payload["leases"])

    test_events = client.get(
        f"/audit/events?action_type=secret_provider.test&resource_type=secret_provider&resource_id={provider_id}&decision_outcome=allow&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-secret"},
    )
    assert test_events.status_code == 200
    assert any(event["actor_id"] == "admin-secret" for event in test_events.json())

    renew_events = client.get(
        f"/audit/events?action_type=secret_provider.lease.renew&resource_type=secret_provider&resource_id={provider_id}&decision_outcome=allow&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-secret"},
    )
    assert renew_events.status_code == 200
    assert any(event["actor_id"] == "sec-secret" for event in renew_events.json())

    health = client.get(
        f"/secrets/providers/{provider_id}/health",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-secret"},
    )
    assert health.status_code == 200
    health_payload = health.json()
    assert health_payload["secret_provider_id"] == provider_id
    assert health_payload["lease_count_active"] >= 1


def test_secret_provider_lease_renew_requires_mfa():
    ensure_tenant_catalog_entry("tenant-secret-lease-mfa", "admin-provider-tenant-secret-lease-mfa")
    created = client.post(
        "/secrets/providers",
        json={
            "tenant_id": "tenant-secret-lease-mfa",
            "provider_type": "vault",
            "provider_address": "https://vault2.example.com",
            "auth_method": "approle",
            "role_or_mount": "approle/platform",
            "secret_path_prefixes": "[\"kv/data/platform\"]",
            "lease_ttl_seconds": 600,
            "auto_renew_enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-secret-mfa", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    provider_id = created.json()["secret_provider_id"]

    denied = client.post(
        f"/secrets/providers/{provider_id}/leases/renew",
        json={"secret_ref": "kv/data/platform/no-mfa", "requested_ttl_seconds": 300},
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-secret-mfa"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_MFA_REQUIRED"


def test_basic_auth_enable_requires_dual_approval():
    config = client.post(
        "/auth/basic/config",
        json={"tenant_id": "tenant-1", "environment": "prod"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-1"},
    )
    assert config.status_code == 200
    config_id = config.json()["basic_auth_config_id"]

    denied = client.post(
        f"/auth/basic/config/{config_id}/enable-temporary",
        json={"break_glass_reason": "incident", "duration_minutes": 10},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-1"},
    )
    assert denied.status_code == 403

    allowed = client.post(
        f"/auth/basic/config/{config_id}/enable-temporary",
        json={"break_glass_reason": "incident", "duration_minutes": 10},
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-1",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-1",
        },
    )
    assert allowed.status_code == 200
    assert allowed.json()["enabled"] is True


def test_basic_auth_enable_missing_dual_approval_emits_deny_audit_event():
    config = client.post(
        "/auth/basic/config",
        json={"tenant_id": "tenant-enable-deny-dual", "environment": "prod"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-enable-deny-dual"},
    )
    assert config.status_code == 200
    config_id = config.json()["basic_auth_config_id"]

    denied = client.post(
        f"/auth/basic/config/{config_id}/enable-temporary",
        json={"break_glass_reason": "incident", "duration_minutes": 10},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-enable-deny-dual"},
    )
    assert denied.status_code == 403
    detail = denied.json()["detail"]
    assert detail["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"
    assert detail["actor_role"] == "Platform Admin"
    assert detail["required_role"] == "Security Approver"
    assert detail["policy_version"] == "v1"
    assert detail["decision_trace_id"] == "authz-dual-approval"
    assert detail["remediation_hint"] == "Provide Security Approver identity headers."

    deny_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.enable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=deny&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-enable-deny-dual"},
    )
    assert deny_events.status_code == 200
    deny_payload = deny_events.json()
    assert any(event["actor_id"] == "admin-enable-deny-dual" for event in deny_payload)

    allow_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.enable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=allow&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-enable-deny-dual"},
    )
    assert allow_events.status_code == 200
    assert all(event["actor_id"] != "admin-enable-deny-dual" for event in allow_events.json())

    # Missing dual-approval must not change config state.
    current = client.patch(
        f"/auth/basic/config/{config_id}",
        json={},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-enable-deny-dual"},
    )
    assert current.status_code == 200
    assert current.json()["enabled"] is False


def test_basic_auth_enable_forbidden_role_emits_deny_audit_event():
    config = client.post(
        "/auth/basic/config",
        json={"tenant_id": "tenant-enable-deny-role", "environment": "prod"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-enable-deny-role"},
    )
    assert config.status_code == 200
    config_id = config.json()["basic_auth_config_id"]

    denied = client.post(
        f"/auth/basic/config/{config_id}/enable-temporary",
        json={"break_glass_reason": "incident", "duration_minutes": 10},
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-enable-deny-role"},
    )
    assert denied.status_code == 403
    detail = denied.json()["detail"]
    assert detail["error_code"] == "AUTHZ_ROLE_FORBIDDEN"
    assert detail["actor_role"] == "Agent Owner"
    assert detail["required_role"] == "Platform Admin"
    assert detail["policy_version"] == "v1"
    assert detail["decision_trace_id"] == "authz-role-check"
    assert detail["remediation_hint"] == "Use a role with required permissions."

    deny_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.enable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=deny&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-enable-deny-role"},
    )
    assert deny_events.status_code == 200
    deny_payload = deny_events.json()
    assert any(event["actor_id"] == "owner-enable-deny-role" for event in deny_payload)

    allow_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.enable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=allow&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-enable-deny-role"},
    )
    assert allow_events.status_code == 200
    assert all(event["actor_id"] != "owner-enable-deny-role" for event in allow_events.json())

    # Forbidden enable must not change config state.
    current = client.patch(
        f"/auth/basic/config/{config_id}",
        json={},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-enable-deny-role"},
    )
    assert current.status_code == 200
    assert current.json()["enabled"] is False


def test_basic_auth_enable_rejects_duration_over_limit_without_side_effects():
    config = client.post(
        "/auth/basic/config",
        json={
            "tenant_id": "tenant-enable-duration-limit",
            "environment": "prod",
            "max_enable_duration_minutes": 5,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-enable-duration-limit"},
    )
    assert config.status_code == 200
    config_id = config.json()["basic_auth_config_id"]

    rejected = client.post(
        f"/auth/basic/config/{config_id}/enable-temporary",
        json={"break_glass_reason": "incident", "duration_minutes": 10},
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-enable-duration-limit",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-enable-duration-limit",
        },
    )
    assert rejected.status_code == 400
    assert response_error_code(rejected) == "VALIDATION_ERROR"
    assert "max limit" in response_error_message(rejected)

    current = client.patch(
        f"/auth/basic/config/{config_id}",
        json={},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-enable-duration-limit"},
    )
    assert current.status_code == 200
    assert current.json()["enabled"] is False

    allow_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.enable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=allow&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-enable-duration-limit"},
    )
    assert allow_events.status_code == 200
    assert all(event["actor_id"] != "admin-enable-duration-limit" for event in allow_events.json())

    deny_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.enable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=deny&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-enable-duration-limit"},
    )
    assert deny_events.status_code == 200
    assert all(event["actor_id"] != "admin-enable-duration-limit" for event in deny_events.json())


def test_basic_auth_enable_missing_config_with_valid_approvals_has_no_audit_side_effects():
    missing_id = str(uuid4())
    missing = client.post(
        f"/auth/basic/config/{missing_id}/enable-temporary",
        json={"break_glass_reason": "incident", "duration_minutes": 10},
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-enable-missing",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-enable-missing",
        },
    )
    assert missing.status_code == 404
    assert response_error_code(missing) == "RESOURCE_NOT_FOUND"

    allow_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.enable&resource_type=basic_auth_config&resource_id={missing_id}&decision_outcome=allow&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-enable-missing"},
    )
    assert allow_events.status_code == 200
    assert all(event["actor_id"] != "admin-enable-missing" for event in allow_events.json())

    deny_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.enable&resource_type=basic_auth_config&resource_id={missing_id}&decision_outcome=deny&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-enable-missing"},
    )
    assert deny_events.status_code == 200
    assert all(event["actor_id"] != "admin-enable-missing" for event in deny_events.json())


def test_basic_auth_enable_missing_config_unauthorized_role_emits_deny_audit_event():
    missing_id = str(uuid4())
    denied = client.post(
        f"/auth/basic/config/{missing_id}/enable-temporary",
        json={"break_glass_reason": "incident", "duration_minutes": 10},
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-enable-missing-unauthorized"},
    )
    assert denied.status_code == 403
    detail = denied.json()["detail"]
    assert detail["error_code"] == "AUTHZ_ROLE_FORBIDDEN"
    assert detail["actor_role"] == "Agent Owner"
    assert detail["required_role"] == "Platform Admin"
    assert detail["policy_version"] == "v1"
    assert detail["decision_trace_id"] == "authz-role-check"
    assert detail["remediation_hint"] == "Use a role with required permissions."

    deny_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.enable&resource_type=basic_auth_config&resource_id={missing_id}&decision_outcome=deny&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-enable-missing-unauthorized"},
    )
    assert deny_events.status_code == 200
    deny_payload = deny_events.json()
    assert any(event["actor_id"] == "owner-enable-missing-unauthorized" for event in deny_payload)

    allow_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.enable&resource_type=basic_auth_config&resource_id={missing_id}&decision_outcome=allow&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-enable-missing-unauthorized"},
    )
    assert allow_events.status_code == 200
    assert all(event["actor_id"] != "owner-enable-missing-unauthorized" for event in allow_events.json())


def test_basic_auth_enable_accepts_whitespace_normalized_approver_headers():
    config = client.post(
        "/auth/basic/config",
        json={"tenant_id": "tenant-whitespace", "environment": "prod"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-whitespace"},
    )
    assert config.status_code == 200
    config_id = config.json()["basic_auth_config_id"]

    allowed = client.post(
        f"/auth/basic/config/{config_id}/enable-temporary",
        json={"break_glass_reason": "incident", "duration_minutes": 10},
        headers={
            "X-Actor-Role": "  Platform Admin  ",
            "X-Actor-Id": "  admin-whitespace  ",
            "X-Approver-Role": "  Security Approver  ",
            "X-Approver-Id": "  sec-whitespace  ",
        },
    )
    assert allowed.status_code == 200
    assert allowed.json()["enabled"] is True


def test_role_authorization_accepts_whitespace_normalized_actor_role_header():
    resp = client.get(
        "/cost/live",
        headers={"X-Actor-Role": "  Platform Admin  ", "X-Actor-Id": "  admin-role-whitespace  "},
    )
    assert resp.status_code == 200


def test_role_authorization_rejects_blank_actor_headers():
    resp = client.get(
        "/cost/live",
        headers={"X-Actor-Role": "   ", "X-Actor-Id": "   "},
    )
    assert resp.status_code == 401
    detail = resp.json()["detail"]
    assert detail["error_code"] == "AUTHN_REQUIRED"


def test_role_authorization_rejects_non_canonical_actor_role_case():
    resp = client.get(
        "/cost/live",
        headers={"X-Actor-Role": "platform admin", "X-Actor-Id": "admin-role-case"},
    )
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert detail["error_code"] == "AUTHZ_ROLE_FORBIDDEN"
    assert detail["actor_role"] == "platform admin"
    assert detail["required_role"] == "Agent Owner, Platform Admin"
    assert detail["decision_trace_id"] == "authz-role-check"


def test_basic_auth_enable_rejects_blank_approver_headers_after_normalization():
    config = client.post(
        "/auth/basic/config",
        json={"tenant_id": "tenant-blank-approver", "environment": "prod"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-blank-approver"},
    )
    assert config.status_code == 200
    config_id = config.json()["basic_auth_config_id"]

    denied = client.post(
        f"/auth/basic/config/{config_id}/enable-temporary",
        json={"break_glass_reason": "incident", "duration_minutes": 10},
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-blank-approver",
            "X-Approver-Role": "   ",
            "X-Approver-Id": "   ",
        },
    )
    assert denied.status_code == 403
    detail = denied.json()["detail"]
    assert detail["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"
    assert detail["actor_role"] == "Platform Admin"
    assert detail["required_role"] == "Security Approver"
    assert detail["policy_version"] == "v1"
    assert detail["decision_trace_id"] == "authz-dual-approval"
    assert detail["remediation_hint"] == "Provide Security Approver identity headers."

    current = client.patch(
        f"/auth/basic/config/{config_id}",
        json={},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-blank-approver"},
    )
    assert current.status_code == 200
    assert current.json()["enabled"] is False

    deny_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.enable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=deny&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-blank-approver"},
    )
    assert deny_events.status_code == 200
    deny_payload = deny_events.json()
    assert any(event["actor_id"] == "admin-blank-approver" for event in deny_payload)

    allow_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.enable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=allow&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-blank-approver"},
    )
    assert allow_events.status_code == 200
    assert all(event["actor_id"] != "admin-blank-approver" for event in allow_events.json())


def test_basic_auth_enable_rejects_same_actor_and_approver_after_normalization():
    config = client.post(
        "/auth/basic/config",
        json={"tenant_id": "tenant-same-identity", "environment": "prod"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-same-identity"},
    )
    assert config.status_code == 200
    config_id = config.json()["basic_auth_config_id"]

    denied = client.post(
        f"/auth/basic/config/{config_id}/enable-temporary",
        json={"break_glass_reason": "incident", "duration_minutes": 10},
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "  admin-same-identity  ",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "admin-same-identity",
        },
    )
    assert denied.status_code == 400
    assert response_error_code(denied) == "AUTHZ_DUAL_APPROVAL_IDENTITY_CONFLICT"

    # Same actor/approver identity rejection must not change config state.
    current = client.patch(
        f"/auth/basic/config/{config_id}",
        json={},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-same-identity"},
    )
    assert current.status_code == 200
    assert current.json()["enabled"] is False

    allow_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.enable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=allow&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-same-identity"},
    )
    assert allow_events.status_code == 200
    assert all(event["actor_id"] != "admin-same-identity" for event in allow_events.json())

    deny_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.enable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=deny&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-same-identity"},
    )
    assert deny_events.status_code == 200
    assert all(event["actor_id"] != "admin-same-identity" for event in deny_events.json())


def test_basic_auth_enable_rejects_approver_matching_defaulted_actor_identity():
    config = client.post(
        "/auth/basic/config",
        json={"tenant_id": "tenant-default-identity", "environment": "prod"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-default-identity"},
    )
    assert config.status_code == 200
    config_id = config.json()["basic_auth_config_id"]

    denied = client.post(
        f"/auth/basic/config/{config_id}/enable-temporary",
        json={"break_glass_reason": "incident", "duration_minutes": 10},
        headers={
            "X-Actor-Role": "   ",
            "X-Actor-Id": "   ",
            "X-Approver-Role": "  Security Approver  ",
            "X-Approver-Id": "system-user",
        },
    )
    assert denied.status_code == 401
    detail = denied.json()["detail"]
    assert detail["error_code"] == "AUTHN_REQUIRED"

    current = client.patch(
        f"/auth/basic/config/{config_id}",
        json={},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-default-identity"},
    )
    assert current.status_code == 200
    assert current.json()["enabled"] is False

    allow_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.enable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=allow&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-default-identity"},
    )
    assert allow_events.status_code == 200
    assert all(event["actor_id"] != "system-user" for event in allow_events.json())

    deny_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.enable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=deny&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-default-identity"},
    )
    assert deny_events.status_code == 200
    assert all(event["actor_id"] != "system-user" for event in deny_events.json())


def test_basic_auth_enable_rejects_non_canonical_approver_role_case():
    config = client.post(
        "/auth/basic/config",
        json={"tenant_id": "tenant-approver-case", "environment": "prod"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-approver-case"},
    )
    assert config.status_code == 200
    config_id = config.json()["basic_auth_config_id"]

    denied = client.post(
        f"/auth/basic/config/{config_id}/enable-temporary",
        json={"break_glass_reason": "incident", "duration_minutes": 10},
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-approver-case",
            "X-Approver-Role": "security approver",
            "X-Approver-Id": "sec-case-1",
        },
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"


def test_basic_auth_disable_allows_security_approver_role():
    config = client.post(
        "/auth/basic/config",
        json={"tenant_id": "tenant-disable-allowed", "environment": "prod"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-disable-allowed"},
    )
    assert config.status_code == 200
    config_id = config.json()["basic_auth_config_id"]

    disabled = client.post(
        f"/auth/basic/config/{config_id}/disable",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-disable-allowed"},
    )
    assert disabled.status_code == 200
    assert disabled.json()["basic_auth_config_id"] == config_id
    assert disabled.json()["enabled"] is False


def test_basic_auth_disable_allows_platform_admin_role():
    config = client.post(
        "/auth/basic/config",
        json={"tenant_id": "tenant-disable-admin-allowed", "environment": "prod"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-disable-admin-allowed"},
    )
    assert config.status_code == 200
    config_id = config.json()["basic_auth_config_id"]

    disabled = client.post(
        f"/auth/basic/config/{config_id}/disable",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-disable-admin-allowed"},
    )
    assert disabled.status_code == 200
    assert disabled.json()["basic_auth_config_id"] == config_id
    assert disabled.json()["enabled"] is False

    allow_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.disable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=allow&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-disable-admin-allowed"},
    )
    assert allow_events.status_code == 200
    payload = allow_events.json()
    assert any(event["actor_id"] == "admin-disable-admin-allowed" for event in payload)


def test_basic_auth_disable_rejects_unauthorized_actor_role():
    config = client.post(
        "/auth/basic/config",
        json={"tenant_id": "tenant-disable-forbidden", "environment": "prod"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-disable-forbidden"},
    )
    assert config.status_code == 200
    config_id = config.json()["basic_auth_config_id"]

    enabled = client.post(
        f"/auth/basic/config/{config_id}/enable-temporary",
        json={"break_glass_reason": "incident", "duration_minutes": 10},
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-disable-forbidden",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-disable-forbidden",
        },
    )
    assert enabled.status_code == 200
    assert enabled.json()["enabled"] is True

    denied = client.post(
        f"/auth/basic/config/{config_id}/disable",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-disable-forbidden"},
    )
    assert denied.status_code == 403
    detail = denied.json()["detail"]
    assert detail["error_code"] == "AUTHZ_ROLE_FORBIDDEN"
    assert detail["actor_role"] == "Agent Owner"
    assert detail["required_role"] == "Platform Admin, Security Approver"
    assert detail["policy_version"] == "v1"
    assert detail["decision_trace_id"] == "authz-role-check"
    assert detail["remediation_hint"] == "Use a role with required permissions."

    deny_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.disable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=deny&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-disable-forbidden"},
    )
    assert deny_events.status_code == 200
    deny_payload = deny_events.json()
    assert any(event["actor_id"] == "owner-disable-forbidden" for event in deny_payload)

    allow_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.disable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=allow&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-disable-forbidden"},
    )
    assert allow_events.status_code == 200
    assert all(event["actor_id"] != "owner-disable-forbidden" for event in allow_events.json())

    # Forbidden disable must not change config state.
    current = client.patch(
        f"/auth/basic/config/{config_id}",
        json={},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-disable-forbidden"},
    )
    assert current.status_code == 200
    assert current.json()["enabled"] is True


def test_basic_auth_disable_returns_404_for_missing_config():
    missing_id = str(uuid4())
    missing = client.post(
        f"/auth/basic/config/{missing_id}/disable",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-disable-missing"},
    )
    assert missing.status_code == 404
    assert response_error_code(missing) == "RESOURCE_NOT_FOUND"

    allow_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.disable&resource_type=basic_auth_config&resource_id={missing_id}&decision_outcome=allow&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-disable-missing"},
    )
    assert allow_events.status_code == 200
    assert all(event["actor_id"] != "admin-disable-missing" for event in allow_events.json())

    deny_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.disable&resource_type=basic_auth_config&resource_id={missing_id}&decision_outcome=deny&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-disable-missing"},
    )
    assert deny_events.status_code == 200
    assert all(event["actor_id"] != "admin-disable-missing" for event in deny_events.json())


def test_basic_auth_disable_missing_config_with_security_approver_has_no_audit_side_effects():
    missing_id = str(uuid4())
    missing = client.post(
        f"/auth/basic/config/{missing_id}/disable",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-disable-missing"},
    )
    assert missing.status_code == 404
    assert response_error_code(missing) == "RESOURCE_NOT_FOUND"

    allow_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.disable&resource_type=basic_auth_config&resource_id={missing_id}&decision_outcome=allow&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-disable-missing-sec"},
    )
    assert allow_events.status_code == 200
    assert all(event["actor_id"] != "sec-disable-missing" for event in allow_events.json())

    deny_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.disable&resource_type=basic_auth_config&resource_id={missing_id}&decision_outcome=deny&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-disable-missing-sec"},
    )
    assert deny_events.status_code == 200
    assert all(event["actor_id"] != "sec-disable-missing" for event in deny_events.json())


def test_basic_auth_disable_missing_config_unauthorized_role_emits_deny_audit_event():
    missing_id = str(uuid4())
    denied = client.post(
        f"/auth/basic/config/{missing_id}/disable",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-disable-missing-unauthorized"},
    )
    assert denied.status_code == 403
    detail = denied.json()["detail"]
    assert detail["error_code"] == "AUTHZ_ROLE_FORBIDDEN"
    assert detail["actor_role"] == "Agent Owner"
    assert detail["required_role"] == "Platform Admin, Security Approver"
    assert detail["policy_version"] == "v1"
    assert detail["decision_trace_id"] == "authz-role-check"
    assert detail["remediation_hint"] == "Use a role with required permissions."

    deny_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.disable&resource_type=basic_auth_config&resource_id={missing_id}&decision_outcome=deny&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-disable-missing-unauthorized"},
    )
    assert deny_events.status_code == 200
    deny_payload = deny_events.json()
    assert any(event["actor_id"] == "owner-disable-missing-unauthorized" for event in deny_payload)

    allow_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.disable&resource_type=basic_auth_config&resource_id={missing_id}&decision_outcome=allow&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-disable-missing-unauthorized"},
    )
    assert allow_events.status_code == 200
    assert all(event["actor_id"] != "owner-disable-missing-unauthorized" for event in allow_events.json())


def test_basic_auth_disable_rejects_non_canonical_security_approver_role_case():
    config = client.post(
        "/auth/basic/config",
        json={"tenant_id": "tenant-disable-role-case", "environment": "prod"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-disable-role-case"},
    )
    assert config.status_code == 200
    config_id = config.json()["basic_auth_config_id"]

    enabled = client.post(
        f"/auth/basic/config/{config_id}/enable-temporary",
        json={"break_glass_reason": "incident", "duration_minutes": 10},
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-disable-role-case",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-disable-role-case",
        },
    )
    assert enabled.status_code == 200
    assert enabled.json()["enabled"] is True

    denied = client.post(
        f"/auth/basic/config/{config_id}/disable",
        headers={"X-Actor-Role": "security approver", "X-Actor-Id": "sec-disable-role-case"},
    )
    assert denied.status_code == 403
    detail = denied.json()["detail"]
    assert detail["error_code"] == "AUTHZ_ROLE_FORBIDDEN"
    assert detail["actor_role"] == "security approver"
    assert detail["required_role"] == "Platform Admin, Security Approver"
    assert detail["policy_version"] == "v1"
    assert detail["decision_trace_id"] == "authz-role-check"
    assert detail["remediation_hint"] == "Use a role with required permissions."

    deny_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.disable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=deny&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-disable-role-case"},
    )
    assert deny_events.status_code == 200
    deny_payload = deny_events.json()
    assert any(event["actor_id"] == "sec-disable-role-case" for event in deny_payload)

    allow_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.disable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=allow&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-disable-role-case"},
    )
    assert allow_events.status_code == 200
    assert all(event["actor_id"] != "sec-disable-role-case" for event in allow_events.json())

    current = client.patch(
        f"/auth/basic/config/{config_id}",
        json={},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-disable-role-case"},
    )
    assert current.status_code == 200
    assert current.json()["enabled"] is True


def test_basic_auth_disable_accepts_whitespace_normalized_security_approver_role():
    config = client.post(
        "/auth/basic/config",
        json={"tenant_id": "tenant-disable-whitespace", "environment": "prod"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-disable-whitespace"},
    )
    assert config.status_code == 200
    config_id = config.json()["basic_auth_config_id"]

    enabled = client.post(
        f"/auth/basic/config/{config_id}/enable-temporary",
        json={"break_glass_reason": "incident", "duration_minutes": 10},
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-disable-whitespace",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-disable-whitespace",
        },
    )
    assert enabled.status_code == 200
    assert enabled.json()["enabled"] is True

    disabled = client.post(
        f"/auth/basic/config/{config_id}/disable",
        headers={"X-Actor-Role": "  Security Approver  ", "X-Actor-Id": "  sec-disable-whitespace  "},
    )
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False

    allow_events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.disable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=allow&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-disable-whitespace"},
    )
    assert allow_events.status_code == 200
    assert any(event["actor_id"] == "sec-disable-whitespace" for event in allow_events.json())


def test_basic_auth_disable_emits_allow_audit_event():
    config = client.post(
        "/auth/basic/config",
        json={"tenant_id": "tenant-disable-audit", "environment": "prod"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-disable-audit"},
    )
    assert config.status_code == 200
    config_id = config.json()["basic_auth_config_id"]

    disabled = client.post(
        f"/auth/basic/config/{config_id}/disable",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-disable-audit"},
    )
    assert disabled.status_code == 200

    events = client.get(
        f"/audit/events?action_type=auth.basic_fallback.disable&resource_type=basic_auth_config&resource_id={config_id}&decision_outcome=allow&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-disable-audit"},
    )
    assert events.status_code == 200
    payload = events.json()
    assert any(event["actor_id"] == "sec-disable-audit" for event in payload)
    assert any(event["action_type"] == "auth.basic_fallback.disable" for event in payload)
    assert all(event["resource_id"] == config_id for event in payload)


def test_discovery_sync_and_list():
    from app.database import SessionLocal
    from app.discovery_sources import SUPPORTED_DISCOVERY_SOURCES
    from app.models import AgentConfig

    db = SessionLocal()
    try:
        existing = db.query(AgentConfig).filter(AgentConfig.config_id == "discovery-sync-test").first()
        if not existing:
            config = AgentConfig(
                config_id="discovery-sync-test",
                agent_key="discovery-sync-agent",
                display_name="Discovery Sync Agent",
                provider="openai",
                model="gpt-4",
                environment="dev",
                enabled=True,
            )
            db.add(config)
            db.commit()
    finally:
        db.close()

    sources_before = client.get(
        "/discovery/sources",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-discovery-sources"},
    )
    assert sources_before.status_code == 200
    assert len(sources_before.json()) == len(SUPPORTED_DISCOVERY_SOURCES)

    sync = client.post(
        "/discovery/sources/runtime_inventory/sync",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-1"},
    )
    assert sync.status_code == 200
    sync_payload = sync.json()
    assert sync_payload["sync_status"] == "completed"
    assert sync_payload["discovered_count"] >= 1

    sources_after = client.get(
        "/discovery/sources",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-discovery-sources"},
    )
    assert sources_after.status_code == 200
    source_ids = {item["source_id"] for item in sources_after.json()}
    for expected_source in SUPPORTED_DISCOVERY_SOURCES:
        assert expected_source in source_ids
    runtime_source = next(s for s in sources_after.json() if s["source_id"] == "runtime_inventory")
    assert runtime_source["last_sync_at"] is not None
    assert runtime_source["discovered_count"] >= 1
    assert runtime_source["platform"] == "agenthub"
    assert runtime_source["category"] == "platform"
    assert runtime_source["label"] == "Agent Runtime Inventory"

    openai_source = next(s for s in sources_after.json() if s["source_id"] == "openai")
    assert openai_source["platform"] == "openai"
    assert openai_source["category"] == "ai_provider"

    records = client.get(
        "/discovery/agents",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-discovery-list"},
    )
    assert records.status_code == 200
    assert isinstance(records.json(), list)


def test_discovery_sync_rejects_unsupported_source():
    sync = client.post(
        "/discovery/sources/aws_unknown_product/sync",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-discovery-invalid"},
    )
    assert sync.status_code == 400
    assert response_error_code(sync) == "VALIDATION_ERROR"
    assert "Unsupported discovery source" in response_error_message(sync)


def test_discovery_conflicts_and_unmanaged_high_risk_alerts():
    from app.database import SessionLocal
    from app.models import DiscoveryRecord

    db = SessionLocal()
    try:
        high_risk_record = DiscoveryRecord(
            discovered_agent_id=str(uuid4()),
            canonical_agent_key="prod-payment-agent-unmanaged",
            source_system="gateway_telemetry",
            source_fingerprint=str(uuid4()),
            discovery_confidence=92,
            discovery_status="discovered",
            last_discovered_at=datetime.utcnow(),
        )
        conflict_record = DiscoveryRecord(
            discovered_agent_id=str(uuid4()),
            canonical_agent_key="staging-ops-agent",
            source_system="code_metadata",
            source_fingerprint=str(uuid4()),
            discovery_confidence=72,
            discovery_status="discovered",
            last_discovered_at=datetime.utcnow(),
        )
        db.add(high_risk_record)
        db.add(conflict_record)
        db.commit()
        high_risk_id = high_risk_record.discovered_agent_id
        conflict_id = conflict_record.discovered_agent_id
    finally:
        db.close()

    conflicts = client.get(
        "/discovery/conflicts",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-discovery"},
    )
    assert conflicts.status_code == 200
    conflict_ids = {item["discovered_agent_id"] for item in conflicts.json()}
    assert conflict_id in conflict_ids

    alerts = client.get(
        "/discovery/alerts",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-discovery"},
    )
    assert alerts.status_code == 200
    alert_ids = {item["discovered_agent_id"] for item in alerts.json()}
    assert high_risk_id in alert_ids

    promote_queue = client.get(
        "/discovery/promote-queue",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-discovery"},
    )
    assert promote_queue.status_code == 200
    promote_queue_ids = {item["discovered_agent_id"] for item in promote_queue.json()}
    assert high_risk_id in promote_queue_ids


def test_gateway_route_and_compatibility():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "default-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-1"},
    )
    assert route.status_code == 200

    compat = client.get(
        "/gateway/endpoints/compatibility",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-gateway-compat"},
    )
    assert compat.status_code == 200
    assert compat.json()["status"] == "pass"

    optimize_denied = client.post(
        f"/gateway/routes/{route.json()['route_policy_id']}/optimize",
        json={"optimize_for": "cost", "environment": "prod"},
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-1"},
    )
    assert optimize_denied.status_code == 403
    assert optimize_denied.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    optimize = client.post(
        f"/gateway/routes/{route.json()['route_policy_id']}/optimize",
        json={"optimize_for": "cost", "environment": "prod"},
        headers={
            "X-Actor-Role": "AI Ops Approver",
            "X-Actor-Id": "aiops-1",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-optimize-1",
        },
    )
    assert optimize.status_code == 200
    assert optimize.json()["recommended_strategy"] in {"lowest_cost", "weighted", "lowest_latency"}


def test_gateway_route_create_rejects_invalid_json_policies():
    invalid = client.post(
        "/gateway/routes",
        json={
            "route_name": "invalid-json-route",
            "candidate_deployments": "not-json",
            "retry_policy": "{}",
            "fallback_policy": "{}",
            "timeout_policy": "{}",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-invalid-json-route"},
    )
    assert invalid.status_code == 422
    assert invalid.json()["detail"] == "candidate_deployments must be valid JSON"


def test_gateway_route_list_supports_pagination_headers():
    for idx in range(3):
        created = client.post(
            "/gateway/routes",
            json={"route_name": f"paged-route-{idx}"},
            headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": f"admin-paged-route-{idx}"},
        )
        assert created.status_code == 200

    listed = client.get(
        "/gateway/routes?limit=2&offset=0",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-route-pagination"},
    )
    assert listed.status_code == 200
    assert len(listed.json()) == 2
    assert int(listed.headers.get("X-Total-Count", "0")) >= 3


def test_gateway_route_execute_fallback_requires_dual_approval_in_prod():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "execute-fallback-prod-approval-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-exec-fallback-prod"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-exec-fallback-prod",
            "environment": "dev",
            "priority_order": '[{"provider_id":"aws-primary","priority":1}]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-exec-fallback-prod"},
    )
    assert configured.status_code == 200

    denied = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-exec-fallback-prod",
            "environment": "prod",
            "agent_id": "agent-exec-fallback-prod",
            "session_id": "session-exec-fallback-prod",
            "owner_scope": "team:platform",
            "simulate_fail_provider_ids": "[]",
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-exec-fallback-prod"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    deny_events = client.get(
        f"/audit/events?action_type=gateway.route.execute_fallback&resource_type=route_policy&resource_id={route_policy_id}&decision_outcome=deny&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-exec-fallback-prod"},
    )
    assert deny_events.status_code == 200
    assert any(event["actor_id"] == "aiops-exec-fallback-prod" for event in deny_events.json())


def test_gateway_cache_stats_returns_operational_fields():
    created = client.post(
        "/gateway/cache/policies",
        json={"scope": "tenant:cache-stats", "ttl_seconds": 120, "key_strategy": "default", "cache_mode": "semantic", "similarity_threshold": 0.87},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-cache-stats"},
    )
    assert created.status_code == 200
    policy = created.json()
    assert policy["cache_mode"] == "semantic"
    assert policy["similarity_threshold"] == 0.87

    stats = client.get(
        "/gateway/cache/stats",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-cache-stats"},
    )
    assert stats.status_code == 200
    payload = stats.json()
    assert "hit_ratio" in payload
    assert "eligible_requests" in payload
    assert "hits" in payload
    assert "misses" in payload
    assert "active_policies" in payload
    assert "semantic_policies" in payload
    assert "avg_ttl_seconds" in payload
    assert "avg_similarity_threshold" in payload


def test_gateway_cache_health_and_invalidate_endpoints():
    created = client.post(
        "/gateway/cache/policies",
        json={"scope": "tenant:cache-health", "ttl_seconds": 180, "key_strategy": "request-hash", "cache_mode": "semantic"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-cache-health"},
    )
    assert created.status_code == 200

    health = client.get(
        "/gateway/cache/health",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-cache-health"},
    )
    assert health.status_code == 200
    health_payload = health.json()
    assert health_payload["status"] == "healthy"
    assert health_payload["cache_backend"] == "policy-managed"
    assert "semantic_policies" in health_payload
    assert "avg_similarity_threshold" in health_payload
    assert "invalidation_requests_last_24h" in health_payload

    invalidated = client.post(
        "/gateway/cache/delete",
        json={"scope": "tenant:cache-health", "reason": "operator test", "active_only": True},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-cache-health"},
    )
    assert invalidated.status_code == 200
    invalidate_payload = invalidated.json()
    assert invalidate_payload["status"] == "accepted"
    assert invalidate_payload["invalidated_scope"] == "tenant:cache-health"
    assert invalidate_payload["matching_policies"] >= 1

    deny = client.post(
        "/gateway/cache/delete",
        json={"scope": "tenant:cache-health"},
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-cache-health"},
    )
    assert deny.status_code == 403


def test_gateway_cache_decision_readback_returns_explanation_and_provenance():
    base_seed = uuid4().hex[:8]
    first_prompt = f"semantic cache evidence {base_seed} alpha"
    second_prompt = f"semantic cache evidence {base_seed} beta"
    policy_created = client.post(
        "/gateway/cache/policies",
        json={"scope": "global", "ttl_seconds": 120, "cache_mode": "semantic", "similarity_threshold": 0.5},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-cache-decision"},
    )
    assert policy_created.status_code == 200
    cache_policy_id = policy_created.json()["cache_policy_id"]

    created = client.post(
        "/v1/responses",
        json={"model": "gpt-4o-mini", "input": first_prompt},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-cache-decision"},
    )
    assert created.status_code == 200
    trace_id = created.json()["trace_id"]

    read = client.get(
        f"/gateway/cache/decisions?trace_id={trace_id}&limit=10",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-cache-decision"},
    )
    assert read.status_code == 200
    rows = read.json()
    assert len(rows) >= 1
    row = rows[0]
    assert row["trace_id"] == trace_id
    assert row["decision"] == "miss"
    assert row["match_score"] == 0.0
    assert "cache miss" in row["explanation"].lower()
    assert cache_policy_id == row["cache_policy_id"]
    assert "cache-policy:" in row["match_provenance"]

    second = client.post(
        "/v1/responses",
        json={"model": "gpt-4o-mini", "input": second_prompt},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-cache-decision"},
    )
    assert second.status_code == 200
    second_trace_id = second.json()["trace_id"]

    second_read = client.get(
        f"/gateway/cache/decisions?trace_id={second_trace_id}&limit=10",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-cache-decision"},
    )
    assert second_read.status_code == 200
    second_row = second_read.json()[0]
    assert second_row["decision"] == "hit"
    assert 0.5 <= second_row["match_score"] <= 1.0
    assert second_row["source_request_id"] == row["request_id"]
    assert second_row["request_fingerprint"] != row["request_fingerprint"]


def test_gateway_cache_decision_readback_enforces_read_roles():
    denied = client.get(
        "/gateway/cache/decisions?limit=5",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-cache-decision"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"


def test_gateway_cache_policy_privacy_scope_and_non_cache_data_classes():
    created = client.post(
        "/gateway/cache/policies",
        json={
            "scope": "tenant:cache-privacy",
            "ttl_seconds": 120,
            "privacy_mode": "strict",
            "privacy_scope": "owner",
            "non_cache_data_classes": '["pii","secret"]',
            "cache_mode": "semantic",
            "similarity_threshold": 0.8,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-cache-privacy"},
    )
    assert created.status_code == 200
    payload = created.json()
    assert payload["privacy_scope"] == "owner"
    assert "pii" in payload["non_cache_data_classes"]


def test_gateway_cache_decision_bypasses_disallowed_data_class():
    policy_created = client.post(
        "/gateway/cache/policies",
        json={
            "scope": "global",
            "ttl_seconds": 120,
            "privacy_mode": "strict",
            "privacy_scope": "tenant",
            "non_cache_data_classes": '["pii"]',
            "cache_mode": "semantic",
            "similarity_threshold": 0.5,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-cache-privacy-bypass"},
    )
    assert policy_created.status_code == 200

    created = client.post(
        "/v1/responses",
        json={"model": "gpt-4o-mini", "input": "Customer SSN is 123-45-6789", "request_tag": "pii.customer-profile"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-cache-privacy-bypass"},
    )
    assert created.status_code == 200
    trace_id = created.json()["trace_id"]

    read = client.get(
        f"/gateway/cache/decisions?trace_id={trace_id}&limit=10",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-cache-privacy-bypass"},
    )
    assert read.status_code == 200
    rows = read.json()
    assert len(rows) >= 1
    row = rows[0]
    assert row["decision"] == "bypass"
    assert row["data_class"] == "pii"
    assert "disallowed" in row["explanation"].lower()


def test_gateway_key_block_and_unblock_controls():
    key_created = client.post(
        "/keys",
        json={
            "owner_scope_type": "team",
            "owner_scope_id": "platform-block-test",
            "allowed_endpoint_families": '["responses"]',
            "allowed_models": '["gpt-test"]',
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-key-block"},
    )
    assert key_created.status_code == 200
    key_id = key_created.json()["key_id"]

    blocked = client.post(
        f"/keys/{key_id}/block",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-key-block"},
    )
    assert blocked.status_code == 200
    assert blocked.json()["status"] == "blocked"

    key_list = client.get(
        "/keys?limit=500&offset=0",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-key-block"},
    )
    assert key_list.status_code == 200
    blocked_row = [row for row in key_list.json() if row["key_id"] == key_id][0]
    assert blocked_row["status"] == "blocked"

    unblocked = client.post(
        f"/keys/{key_id}/unblock",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-key-block"},
    )
    assert unblocked.status_code == 200
    assert unblocked.json()["status"] == "active"

    deny = client.post(
        f"/keys/{key_id}/block",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-key-block"},
    )
    assert deny.status_code == 403


def test_gateway_key_rotation_requires_dual_approval_in_prod():
    key_created = client.post(
        "/keys",
        json={
            "owner_scope_type": "team",
            "owner_scope_id": "platform",
            "allowed_endpoint_families": '["responses"]',
            "allowed_models": '["gpt-test"]',
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-rotate"},
    )
    assert key_created.status_code == 200
    key_id = key_created.json()["key_id"]

    key_list = client.get(
        "/keys?limit=500&offset=0",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-key-list"},
    )
    assert key_list.status_code == 200
    assert any(row["key_id"] == key_id for row in key_list.json())

    denied = client.post(
        f"/keys/{key_id}/rotate?environment=prod",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-rotate"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    allowed = client.post(
        f"/keys/{key_id}/rotate?environment=prod",
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-rotate",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-rotate",
        },
    )
    assert allowed.status_code == 200
    assert allowed.json()["rotation_status"] == "rotated"


def test_gateway_key_temporary_budget_increase_workflow_with_prod_guardrail():
    created = client.post(
        "/keys",
        json={
            "owner_scope_type": "team",
            "owner_scope_id": "platform-budget-boost",
            "allowed_endpoint_families": '["responses"]',
            "allowed_models": '["gpt-test"]',
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-budget-boost"},
    )
    assert created.status_code == 200
    key_id = created.json()["key_id"]

    denied = client.post(
        f"/keys/{key_id}/budget/increase-temporary",
        json={
            "environment": "prod",
            "increase_cents": 5000,
            "duration_minutes": 120,
            "reason": "incident-response",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-budget-boost"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    allowed = client.post(
        f"/keys/{key_id}/budget/increase-temporary",
        json={
            "environment": "prod",
            "increase_cents": 5000,
            "duration_minutes": 120,
            "reason": "incident-response",
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-budget-boost",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-budget-boost",
        },
    )
    assert allowed.status_code == 200
    payload = allowed.json()
    assert payload["active"] is True
    assert payload["increase_cents"] == 5000

    readback = client.get(
        f"/keys/{key_id}/budget/increase-temporary",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-budget-boost"},
    )
    assert readback.status_code == 200
    assert readback.json()["increase_cents"] == 5000


def test_gateway_key_rotation_schedule_create_update_execute_flow():
    created = client.post(
        "/keys",
        json={
            "owner_scope_type": "team",
            "owner_scope_id": "platform-rotation-schedule",
            "allowed_endpoint_families": '["responses"]',
            "allowed_models": '["gpt-test"]',
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-rotation-schedule"},
    )
    assert created.status_code == 200
    key_id = created.json()["key_id"]

    schedule = client.post(
        f"/keys/{key_id}/rotation-schedules",
        json={
            "environment": "dev",
            "interval_hours": 24,
            "enabled": True,
            "reason": "daily-rotation",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-rotation-schedule"},
    )
    assert schedule.status_code == 200
    schedule_id = schedule.json()["schedule_id"]

    listed = client.get(
        f"/keys/{key_id}/rotation-schedules",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-rotation-schedule"},
    )
    assert listed.status_code == 200
    assert any(row["schedule_id"] == schedule_id for row in listed.json())

    updated = client.patch(
        f"/keys/{key_id}/rotation-schedules/{schedule_id}",
        json={"enabled": True, "interval_hours": 12, "reason": "twice-daily"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-rotation-schedule"},
    )
    assert updated.status_code == 200
    assert updated.json()["interval_hours"] == 12

    executed = client.post(
        f"/keys/{key_id}/rotation-schedules/{schedule_id}/execute-now",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-rotation-schedule"},
    )
    assert executed.status_code == 200
    assert executed.json()["rotation_status"] == "rotated"


def test_gateway_key_rotation_schedule_prod_requires_dual_approval():
    created = client.post(
        "/keys",
        json={
            "owner_scope_type": "team",
            "owner_scope_id": "platform-rotation-prod",
            "allowed_endpoint_families": '["responses"]',
            "allowed_models": '["gpt-test"]',
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-rotation-prod"},
    )
    assert created.status_code == 200
    key_id = created.json()["key_id"]

    denied_create = client.post(
        f"/keys/{key_id}/rotation-schedules",
        json={"environment": "prod", "interval_hours": 24, "enabled": True, "reason": "prod-rotation"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-rotation-prod"},
    )
    assert denied_create.status_code == 403
    assert denied_create.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    allowed_create = client.post(
        f"/keys/{key_id}/rotation-schedules",
        json={"environment": "prod", "interval_hours": 24, "enabled": True, "reason": "prod-rotation"},
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-rotation-prod",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-rotation-prod",
        },
    )
    assert allowed_create.status_code == 200
    schedule_id = allowed_create.json()["schedule_id"]

    denied_execute = client.post(
        f"/keys/{key_id}/rotation-schedules/{schedule_id}/execute-now",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-rotation-prod"},
    )
    assert denied_execute.status_code == 403
    assert denied_execute.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"


def test_gateway_external_callback_registry_and_export_flow():
    created = client.post(
        "/gateway/external-callbacks",
        json={
            "callback_url": "https://hooks.example.com/gateway-dev",
            "event_types": ["gateway.route.execute_fallback", "gateway.mcp.tools.call"],
            "environment": "dev",
            "sink_type": "siem",
            "sink_route_key": "soc.high-priority",
            "correlation_preset": "tenant_environment",
            "redact_sensitive": True,
            "enabled": True,
            "description": "dev callback",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-callback-dev"},
    )
    assert created.status_code == 200
    callback_id = created.json()["callback_id"]
    assert created.json()["sink_type"] == "siem"
    assert created.json()["sink_route_key"] == "soc.high-priority"
    assert created.json()["correlation_preset"] == "tenant_environment"

    listed = client.get(
        "/gateway/external-callbacks",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-callback-dev"},
    )
    assert listed.status_code == 200
    assert any(row["callback_id"] == callback_id for row in listed.json())

    tested = client.post(
        f"/gateway/external-callbacks/{callback_id}/test-delivery",
        json={
            "environment": "dev",
            "sample_payload": {
                "actor_id": "ops-user",
                "resource_id": "route-1",
                "tenant_id": "tenant-a",
                "trace_id": "trace-callback-dev-01",
                "description": "test payload",
            },
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-callback-dev"},
    )
    assert tested.status_code == 200
    payload = tested.json()
    assert payload["delivery_status"] == "delivered_simulated"
    assert payload["redaction_applied"] is True
    assert payload["sink_type"] == "siem"
    assert payload["sink_route_key"] == "soc.high-priority"
    assert payload["correlation_preset"] == "tenant_environment"
    assert payload["correlation_context"]["tenant_id"] == "tenant-a"
    assert payload["correlation_context"]["trace_id"] == "trace-callback-dev-01"
    assert str(payload["payload_preview"]["actor_id"]).startswith("fp:")

    exported = client.post(
        "/gateway/external-callbacks/export",
        json={"environment": None, "limit": 25},
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-callback-dev"},
    )
    assert exported.status_code == 200
    assert exported.json()["callback_count"] >= 1
    assert exported.json()["event_count"] >= 1
    assert "siem" in exported.json()["sink_distribution"]
    assert "tenant_environment" in exported.json()["correlation_preset_distribution"]


def test_gateway_external_callback_prod_requires_dual_approval():
    denied_create = client.post(
        "/gateway/external-callbacks",
        json={
            "callback_url": "https://hooks.example.com/gateway-prod",
            "event_types": ["gateway.route.execute_fallback"],
            "environment": "prod",
            "sink_type": "pagerduty",
            "sink_route_key": "oncall.primary",
            "correlation_preset": "incident_minimal",
            "redact_sensitive": True,
            "enabled": True,
            "description": "prod callback",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-callback-prod"},
    )
    assert denied_create.status_code == 403
    assert denied_create.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    allowed_create = client.post(
        "/gateway/external-callbacks",
        json={
            "callback_url": "https://hooks.example.com/gateway-prod",
            "event_types": ["gateway.route.execute_fallback"],
            "environment": "prod",
            "sink_type": "pagerduty",
            "sink_route_key": "oncall.primary",
            "correlation_preset": "incident_minimal",
            "redact_sensitive": True,
            "enabled": True,
            "description": "prod callback",
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-callback-prod",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-callback-prod",
        },
    )
    assert allowed_create.status_code == 200
    callback_id = allowed_create.json()["callback_id"]

    denied_test = client.post(
        f"/gateway/external-callbacks/{callback_id}/test-delivery",
        json={"environment": "prod", "sample_payload": {"actor_id": "ops-prod"}},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-callback-prod"},
    )
    assert denied_test.status_code == 403
    assert denied_test.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"


def test_gateway_governance_evidence_export_endpoint_returns_bundle_and_audit_evidence():
    entitlement_id = f"ent-gov-evidence-{uuid4()}"
    upserted = client.put(
        f"/gateway/entitlements/{entitlement_id}",
        json={
            "action": "gateway.route.update",
            "tenant_id": "tenant-gov-evidence",
            "environment": "dev",
            "allowed_roles": '["Platform Admin"]',
            "enabled": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-gov-evidence"},
    )
    assert upserted.status_code == 200

    exported = client.post(
        "/gateway/governance/evidence/export",
        json={"decision_outcome": "allow", "limit_per_action": 100, "bundle_label": "gateway-gov-evidence"},
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-gov-evidence"},
    )
    assert exported.status_code == 200
    payload = exported.json()
    assert payload["event_count"] >= 1
    assert payload["bundle_label"] == "gateway-gov-evidence"
    assert str(payload["export_uri"]).startswith("evidence://gateway/governance/")
    assert any(item["action_type"] == "gateway.entitlement.update" for item in payload["action_summaries"])

    audit_rows = client.get(
        "/audit/events?action_type=gateway.governance.evidence.export&decision_outcome=allow&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-gov-evidence"},
    )
    assert audit_rows.status_code == 200
    assert any(row["resource_type"] == "gateway_governance_evidence" for row in audit_rows.json())


def test_gateway_governance_evidence_export_decision_outcome_filter_contract():
    denied_only = client.post(
        "/gateway/governance/evidence/export",
        json={"decision_outcome": "deny", "limit_per_action": 100, "bundle_label": "gateway-gov-evidence-deny"},
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-gov-evidence-filter"},
    )
    assert denied_only.status_code == 200
    payload = denied_only.json()
    assert payload["event_count"] == len(payload["events"])
    assert all(row["decision_outcome"] == "deny" for row in payload["events"])


def test_gateway_openai_chat_completions_success_contract():
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": "You are a concise assistant."},
                {"role": "user", "content": "Explain fallback routing in one sentence."},
            ],
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-chat-completions"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert str(payload["id"]).startswith("chatcmpl-")
    assert payload["object"] == "chat.completion"
    assert payload["model"] == "gpt-4o-mini"
    assert payload["choices"][0]["message"]["role"] == "assistant"
    assert payload["usage"]["prompt_tokens"] >= 1
    assert payload["usage"]["completion_tokens"] >= 1
    assert payload["usage"]["total_tokens"] == payload["usage"]["prompt_tokens"] + payload["usage"]["completion_tokens"]
    assert payload["risk_tier"] == "low"
    assert "frontier_model_family" in payload["risk_reasons"]

    from app.database import SessionLocal
    from app.models import CostEvent

    db = SessionLocal()
    try:
        event = db.query(CostEvent).filter_by(trace_id=payload["trace_id"]).first()
        assert event is not None
        assert event.endpoint_family == "chat.completions"
        assert event.estimated_cost_cents >= 0
    finally:
        db.close()


def test_gateway_openai_chat_completions_supports_json_response_format_contract():
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "Summarize fallback routing."}],
            "response_format": {"type": "json_object"},
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-chat-json-format"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["choices"][0]["finish_reason"] == "stop"
    assert payload["choices"][0]["message"]["content"].startswith('{"answer":')
    assert payload["usage"]["total_tokens"] == payload["usage"]["prompt_tokens"] + payload["usage"]["completion_tokens"]


def test_gateway_openai_chat_completions_streaming_contract():
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "Stream fallback status."}],
            "stream": True,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-chat-stream"},
    )
    assert response.status_code == 200
    assert "text/event-stream" in str(response.headers.get("content-type", "")).lower()
    body = response.text
    assert "chat.completion.chunk" in body
    assert "data: [DONE]" in body


def test_gateway_openai_chat_completions_max_tokens_sets_length_finish_reason():
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "Summarize fallback routing in a concise way."}],
            "max_tokens": 1,
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-chat-max-tokens"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["choices"][0]["finish_reason"] == "length"
    assert payload["usage"]["completion_tokens"] <= 1


def test_gateway_openai_chat_completions_rejects_invalid_stop_contract():
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "hello"}],
            "stop": ["DONE", 2],
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-chat-stop-invalid"},
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "stop must be a string or list of strings"


def test_gateway_openai_chat_completions_provider_prefixed_model_requires_tenant():
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "openai/gpt-4o-mini",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-chat-no-tenant"},
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "tenant_id is required when model includes provider prefix"


def test_gateway_openai_chat_completions_cursor_provider_skips_catalog_entitlement():
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "cursor/composer-2.5",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": False,
            "environment": "dev",
            "tenant_id": "tenant-platform",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-chat-cursor-provider"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["model"] == "cursor/composer-2.5"
    assert payload["choices"][0]["message"]["content"]


def test_gateway_openai_chat_completions_forbidden_role_emits_deny_audit():
    denied = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "test"}],
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-chat-denied"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    audits = client.get(
        "/audit/events?action_type=gateway.chat.completions&decision_outcome=deny&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-chat-denied"},
    )
    assert audits.status_code == 200
    assert any(row["actor_id"] == "aud-chat-denied" for row in audits.json())


def test_gateway_openai_embeddings_success_contract():
    response = client.post(
        "/v1/embeddings",
        json={
            "model": "text-embedding-3-small",
            "input": "Summarize the current gateway policy posture.",
            "dimensions": 8,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-embeddings-create"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["object"] == "list"
    assert payload["model"] == "text-embedding-3-small"
    assert payload["data"][0]["object"] == "embedding"
    assert len(payload["data"][0]["embedding"]) == 8
    assert payload["usage"]["prompt_tokens"] >= 1
    assert payload["usage"]["total_tokens"] == payload["usage"]["prompt_tokens"]
    assert payload["risk_tier"] == "low"
    assert "frontier_model_family" not in payload["risk_reasons"]

    from app.database import SessionLocal
    from app.models import CostEvent

    db = SessionLocal()
    try:
        event = db.query(CostEvent).filter_by(trace_id=payload["trace_id"]).first()
        assert event is not None
        assert event.endpoint_family == "embeddings"
        assert event.estimated_cost_cents >= 0
    finally:
        db.close()


def test_gateway_openai_embeddings_forbidden_role_emits_deny_audit():
    denied = client.post(
        "/v1/embeddings",
        json={
            "model": "text-embedding-3-small",
            "input": "hello",
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-embeddings-denied"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    audits = client.get(
        "/audit/events?action_type=gateway.embeddings.create&decision_outcome=deny&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-embeddings-denied"},
    )
    assert audits.status_code == 200
    assert any(row["actor_id"] == "aud-embeddings-denied" for row in audits.json())


def test_gateway_openai_images_generation_success_contract():
    response = client.post(
        "/v1/images/generations",
        json={
            "model": "gpt-image-1",
            "prompt": "A transparent security shield over a gateway dashboard",
            "n": 2,
            "size": "1024x1024",
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-images-create"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["model"] == "gpt-image-1"
    assert len(payload["data"]) == 2
    assert payload["data"][0]["b64_json"].startswith("iVBORw0KGgo")
    assert payload["risk_tier"] == "low"

    from app.database import SessionLocal
    from app.models import CostEvent

    db = SessionLocal()
    try:
        event = db.query(CostEvent).filter_by(trace_id=payload["trace_id"]).first()
        assert event is not None
        assert event.endpoint_family == "images"
    finally:
        db.close()


def test_gateway_openai_images_generation_forbidden_role_emits_deny_audit():
    denied = client.post(
        "/v1/images",
        json={
            "model": "gpt-image-1",
            "prompt": "hello",
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-images-denied"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    audits = client.get(
        "/audit/events?action_type=gateway.images.generate&decision_outcome=deny&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-images-denied"},
    )
    assert audits.status_code == 200
    assert any(row["actor_id"] == "aud-images-denied" for row in audits.json())


def test_gateway_openai_audio_transcriptions_success_contract():
    response = client.post(
        "/v1/audio/transcriptions",
        json={
            "model": "gpt-audio-1",
            "input_text": "Security review recorded for the gateway rollout.",
            "language": "en",
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-audio-transcribe"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["model"] == "gpt-audio-1"
    assert "Security review" in payload["text"]
    assert payload["language"] == "en"
    assert payload["duration_seconds"] >= 1.0
    assert payload["risk_tier"] == "low"

    from app.database import SessionLocal
    from app.models import CostEvent

    db = SessionLocal()
    try:
        event = db.query(CostEvent).filter_by(trace_id=payload["trace_id"]).first()
        assert event is not None
        assert event.endpoint_family == "audio.transcriptions"
    finally:
        db.close()


def test_gateway_openai_audio_translations_forbidden_role_emits_deny_audit():
    denied = client.post(
        "/v1/audio/translations",
        json={
            "model": "gpt-audio-1",
            "input_text": "hello",
            "target_language": "fr",
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-audio-denied"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    audits = client.get(
        "/audit/events?action_type=gateway.audio.translations.create&decision_outcome=deny&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-audio-denied"},
    )
    assert audits.status_code == 200
    assert any(row["actor_id"] == "aud-audio-denied" for row in audits.json())


def test_gateway_openai_realtime_success_contract():
    response = client.post(
        "/v1/realtime",
        json={
            "model": "gpt-realtime-1",
            "session_label": "ops-realtime-check",
            "requested_modalities": ["text", "audio"],
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-create"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["object"] == "realtime.session"
    assert payload["status"] == "created"
    assert payload["model"] == "gpt-realtime-1"
    assert payload["requested_modalities"] == ["text", "audio"]
    assert payload["expires_at"] >= payload["created"] if "created" in payload else payload["expires_at"] > 0
    assert payload["risk_tier"] == "low"

    from app.database import SessionLocal
    from app.models import CostEvent

    db = SessionLocal()
    try:
        event = db.query(CostEvent).filter_by(trace_id=payload["trace_id"]).first()
        assert event is not None
        assert event.endpoint_family == "realtime"
    finally:
        db.close()


def test_gateway_openai_realtime_streaming_contract():
    response = client.post(
        "/v1/realtime",
        json={
            "model": "gpt-realtime-1",
            "session_label": "ops-realtime-stream",
            "requested_modalities": ["text", "audio"],
            "stream": True,
            "stream_binary_mode": "metadata_only",
            "stream_max_event_bytes": 32768,
            "stream_heartbeat_interval_seconds": 12,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-stream"},
    )
    assert response.status_code == 200
    assert "text/event-stream" in str(response.headers.get("content-type", "")).lower()
    body = response.text
    assert "realtime.session.event" in body
    assert "session.created" in body
    assert "session.policy" in body
    assert "session.keepalive" in body
    assert '"binary_mode":"metadata_only"' in body
    assert '"max_event_bytes":32768' in body
    assert '"heartbeat_interval_seconds":12' in body
    assert "data: [DONE]" in body


def test_gateway_openai_realtime_inline_binary_prod_requires_dual_approval():
    denied = client.post(
        "/v1/realtime",
        json={
            "model": "gpt-realtime-1",
            "requested_modalities": ["audio"],
            "stream": True,
            "stream_binary_mode": "inline_base64",
            "environment": "prod",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-inline-prod"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    allowed = client.post(
        "/v1/realtime",
        json={
            "model": "gpt-realtime-1",
            "requested_modalities": ["audio"],
            "stream": True,
            "stream_binary_mode": "inline_base64",
            "environment": "prod",
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-realtime-inline-prod",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-realtime-inline-prod",
        },
    )
    assert allowed.status_code == 200
    assert "text/event-stream" in str(allowed.headers.get("content-type", "")).lower()
    assert "data: [DONE]" in allowed.text


def test_gateway_openai_realtime_session_lifecycle_contract():
    created = client.post(
        "/v1/realtime",
        json={
            "model": "gpt-realtime-1",
            "session_label": "ops-lifecycle",
            "requested_modalities": ["text"],
            "stream_binary_mode": "metadata_only",
            "stream_max_event_bytes": 2048,
            "stream_heartbeat_interval_seconds": 10,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-lifecycle"},
    )
    assert created.status_code == 200
    session_id = created.json()["id"]

    read_before = client.get(
        f"/v1/realtime/sessions/{session_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-lifecycle"},
    )
    assert read_before.status_code == 200
    read_before_payload = read_before.json()
    assert read_before_payload["status"] == "active"
    assert read_before_payload["event_count"] == 0
    assert read_before_payload["stream_policy"]["max_event_bytes"] == 2048

    appended = client.post(
        f"/v1/realtime/sessions/{session_id}/events",
        json={
            "event_type": "input.audio.append",
            "binary_mode": "metadata_only",
            "event_bytes": 1024,
            "payload": {"chunk": 1},
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-lifecycle"},
    )
    assert appended.status_code == 200
    assert appended.json()["status"] == "accepted"

    events = client.get(
        f"/v1/realtime/sessions/{session_id}/events?limit=20&offset=0",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-lifecycle"},
    )
    assert events.status_code == 200
    event_rows = events.json()["data"]
    assert len(event_rows) >= 1
    assert event_rows[0]["session_id"] == session_id
    assert event_rows[0]["event_type"] == "input.audio.append"

    listed = client.get(
        "/v1/realtime/sessions?status=active&limit=20&offset=0",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-lifecycle"},
    )
    assert listed.status_code == 200
    assert any(row["id"] == session_id for row in listed.json()["data"])

    read_after = client.get(
        f"/v1/realtime/sessions/{session_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-lifecycle"},
    )
    assert read_after.status_code == 200
    read_after_payload = read_after.json()
    assert read_after_payload["event_count"] >= 1
    assert read_after_payload["last_event_type"] == "input.audio.append"

    closed = client.post(
        f"/v1/realtime/sessions/{session_id}/close",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-lifecycle"},
    )
    assert closed.status_code == 200
    assert closed.json()["status"] == "closed"
    assert closed.json()["event_count"] >= 1


def test_gateway_openai_realtime_session_event_inline_binary_prod_requires_dual_approval():
    created = client.post(
        "/v1/realtime",
        json={
            "model": "gpt-realtime-1",
            "requested_modalities": ["audio"],
            "stream_binary_mode": "inline_base64",
            "stream_max_event_bytes": 4096,
            "environment": "prod",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-event-prod"},
    )
    assert created.status_code == 200
    session_id = created.json()["id"]

    denied = client.post(
        f"/v1/realtime/sessions/{session_id}/events",
        json={
            "event_type": "input.audio.append",
            "binary_mode": "inline_base64",
            "event_bytes": 1024,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-event-prod"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    allowed = client.post(
        f"/v1/realtime/sessions/{session_id}/events",
        json={
            "event_type": "input.audio.append",
            "binary_mode": "inline_base64",
            "event_bytes": 1024,
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-realtime-event-prod",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-realtime-event-prod",
        },
    )
    assert allowed.status_code == 200
    assert allowed.json()["status"] == "accepted"


def test_gateway_openai_realtime_session_events_owner_scope_enforced():
    created = client.post(
        "/v1/realtime",
        json={
            "model": "gpt-realtime-1",
            "requested_modalities": ["text"],
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "agent-owner-a"},
    )
    assert created.status_code == 200
    session_id = created.json()["id"]

    denied = client.get(
        f"/v1/realtime/sessions/{session_id}/events?limit=20&offset=0",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "agent-owner-b"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"


def test_gateway_openai_realtime_session_expiry_blocks_event_append_and_persists_expired_status():
    created = client.post(
        "/v1/realtime",
        json={
            "model": "gpt-realtime-1",
            "requested_modalities": ["text"],
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-expiry"},
    )
    assert created.status_code == 200
    session_id = created.json()["id"]

    from app.database import SessionLocal
    from app.models import RealtimeSessionRecord
    from datetime import datetime, timedelta

    db = SessionLocal()
    try:
        row = db.query(RealtimeSessionRecord).filter_by(session_id=session_id).first()
        assert row is not None
        row.expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.commit()
    finally:
        db.close()

    denied = client.post(
        f"/v1/realtime/sessions/{session_id}/events",
        json={
            "event_type": "input.audio.append",
            "binary_mode": "metadata_only",
            "event_bytes": 100,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-expiry"},
    )
    assert denied.status_code == 409
    assert denied.json()["detail"] == "Realtime session has expired"

    read_back = client.get(
        f"/v1/realtime/sessions/{session_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-expiry"},
    )
    assert read_back.status_code == 200
    assert read_back.json()["status"] == "expired"


def test_gateway_openai_realtime_session_event_count_cap_enforced():
    created = client.post(
        "/v1/realtime",
        json={
            "model": "gpt-realtime-1",
            "requested_modalities": ["text"],
            "stream_max_event_bytes": 4096,
            "stream_max_session_events": 1,
            "stream_max_session_event_bytes": 4096,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-event-cap"},
    )
    assert created.status_code == 200
    session_id = created.json()["id"]

    first = client.post(
        f"/v1/realtime/sessions/{session_id}/events",
        json={
            "event_type": "input.audio.append",
            "binary_mode": "metadata_only",
            "event_bytes": 100,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-event-cap"},
    )
    assert first.status_code == 200

    second = client.post(
        f"/v1/realtime/sessions/{session_id}/events",
        json={
            "event_type": "input.audio.append",
            "binary_mode": "metadata_only",
            "event_bytes": 100,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-event-cap"},
    )
    assert second.status_code == 422
    assert second.json()["detail"] == "session event count exceeds stream policy max_session_events"


def test_gateway_openai_realtime_session_event_bytes_cap_enforced():
    created = client.post(
        "/v1/realtime",
        json={
            "model": "gpt-realtime-1",
            "requested_modalities": ["text"],
            "stream_max_event_bytes": 4096,
            "stream_max_session_events": 10,
            "stream_max_session_event_bytes": 1024,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-bytes-cap"},
    )
    assert created.status_code == 200
    session_id = created.json()["id"]

    first = client.post(
        f"/v1/realtime/sessions/{session_id}/events",
        json={
            "event_type": "input.audio.append",
            "binary_mode": "metadata_only",
            "event_bytes": 700,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-bytes-cap"},
    )
    assert first.status_code == 200

    second = client.post(
        f"/v1/realtime/sessions/{session_id}/events",
        json={
            "event_type": "input.audio.append",
            "binary_mode": "metadata_only",
            "event_bytes": 400,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-bytes-cap"},
    )
    assert second.status_code == 422
    assert second.json()["detail"] == "session event bytes exceed stream policy max_session_event_bytes"


def test_gateway_openai_realtime_inline_policy_enforces_event_allowlist_byte_cap_and_correlation_id():
    created = client.post(
        "/v1/realtime",
        json={
            "model": "gpt-realtime-1",
            "requested_modalities": ["audio", "video"],
            "stream_binary_mode": "inline_base64",
            "stream_inline_max_event_bytes": 1024,
            "stream_inline_allowed_event_types": ["input.audio.append"],
            "stream_inline_require_correlation_id": True,
            "stream_max_event_bytes": 4096,
            "stream_max_session_events": 10,
            "stream_max_session_event_bytes": 8192,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-inline-policy"},
    )
    assert created.status_code == 200
    session_id = created.json()["id"]

    disallowed_event_type = client.post(
        f"/v1/realtime/sessions/{session_id}/events",
        json={
            "event_type": "input.video.append",
            "binary_mode": "inline_base64",
            "event_bytes": 200,
            "payload": {"media_id": "media-video-1"},
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-inline-policy"},
    )
    assert disallowed_event_type.status_code == 422
    assert disallowed_event_type.json()["detail"] == "event_type is not allowed for inline_base64 under stream policy"

    exceeds_inline_bytes = client.post(
        f"/v1/realtime/sessions/{session_id}/events",
        json={
            "event_type": "input.audio.append",
            "binary_mode": "inline_base64",
            "event_bytes": 1500,
            "payload": {"media_id": "media-audio-1"},
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-inline-policy"},
    )
    assert exceeds_inline_bytes.status_code == 422
    assert exceeds_inline_bytes.json()["detail"] == "event_bytes exceeds stream policy inline_max_event_bytes"

    missing_correlation = client.post(
        f"/v1/realtime/sessions/{session_id}/events",
        json={
            "event_type": "input.audio.append",
            "binary_mode": "inline_base64",
            "event_bytes": 256,
            "payload": {"chunk": 1},
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-inline-policy"},
    )
    assert missing_correlation.status_code == 422
    assert missing_correlation.json()["detail"] == "inline_base64 events require payload correlation id under stream policy"

    accepted = client.post(
        f"/v1/realtime/sessions/{session_id}/events",
        json={
            "event_type": "input.audio.append",
            "binary_mode": "inline_base64",
            "event_bytes": 256,
            "payload": {"media_id": "media-audio-2", "chunk": 2},
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-realtime-inline-policy"},
    )
    assert accepted.status_code == 200
    assert accepted.json()["status"] == "accepted"


def test_gateway_openai_realtime_forbidden_role_emits_deny_audit():
    denied = client.post(
        "/v1/realtime",
        json={
            "model": "gpt-realtime-1",
            "requested_modalities": ["text"],
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-realtime-denied"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    audits = client.get(
        "/audit/events?action_type=gateway.realtime.create&decision_outcome=deny&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-realtime-denied"},
    )
    assert audits.status_code == 200
    assert any(row["actor_id"] == "aud-realtime-denied" for row in audits.json())


def test_gateway_openai_messages_success_contract():
    response = client.post(
        "/v1/messages",
        json={
            "model": "gpt-4o-mini",
            "input": "Summarize the gateway parity posture.",
            "conversation_id": "conv-gateway-ops",
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-messages-create"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["object"] == "message"
    assert payload["role"] == "assistant"
    assert payload["conversation_id"] == "conv-gateway-ops"
    assert payload["model"] == "gpt-4o-mini"
    assert payload["risk_tier"] == "low"

    from app.database import SessionLocal
    from app.models import CostEvent

    db = SessionLocal()
    try:
        event = db.query(CostEvent).filter_by(trace_id=payload["trace_id"]).first()
        assert event is not None
        assert event.endpoint_family == "messages"
    finally:
        db.close()


def test_gateway_openai_a2a_messages_forbidden_role_emits_deny_audit():
    denied = client.post(
        "/v1/a2a/messages",
        json={
            "from_agent_id": "agent-alpha",
            "to_agent_id": "agent-beta",
            "message": "handoff status",
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-a2a-denied"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    audits = client.get(
        "/audit/events?action_type=gateway.a2a.messages.create&decision_outcome=deny&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-a2a-denied"},
    )
    assert audits.status_code == 200
    assert any(row["actor_id"] == "aud-a2a-denied" for row in audits.json())


def test_gateway_openai_rerank_success_contract():
    response = client.post(
        "/v1/rerank",
        json={
            "model": "text-rerank-3-small",
            "query": "gateway policy posture",
            "documents": [
                "This document explains gateway policy posture and audit controls.",
                "A totally unrelated operational note.",
                {"text": "Policy posture review and gateway audit summary."},
            ],
            "top_n": 2,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-rerank-create"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["object"] == "list"
    assert payload["model"] == "text-rerank-3-small"
    assert len(payload["results"]) == 2
    assert payload["results"][0]["relevance_score"] >= payload["results"][1]["relevance_score"]
    assert payload["usage"]["prompt_tokens"] >= 1
    assert payload["usage"]["total_tokens"] == payload["usage"]["prompt_tokens"]
    assert payload["risk_tier"] == "low"

    from app.database import SessionLocal
    from app.models import CostEvent

    db = SessionLocal()
    try:
        event = db.query(CostEvent).filter_by(trace_id=payload["trace_id"]).first()
        assert event is not None
        assert event.endpoint_family == "rerank"
    finally:
        db.close()


def test_gateway_openai_rerank_forbidden_role_emits_deny_audit():
    denied = client.post(
        "/v1/rerank",
        json={
            "model": "text-rerank-3-small",
            "query": "hello",
            "documents": ["one", "two"],
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-rerank-denied"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    audits = client.get(
        "/audit/events?action_type=gateway.rerank.create&decision_outcome=deny&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-rerank-denied"},
    )
    assert audits.status_code == 200
    assert any(row["actor_id"] == "aud-rerank-denied" for row in audits.json())


def test_gateway_openai_responses_success_contract():
    response = client.post(
        "/v1/responses",
        json={
            "model": "gpt-4o-mini",
            "input": "Explain fallback routing in one sentence.",
            "response_format": {"type": "json_object"},
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-responses-create"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert str(payload["id"]).startswith("resp-")
    assert payload["object"] == "response"
    assert payload["model"] == "gpt-4o-mini"
    assert payload["output"][0]["role"] == "assistant"
    assert payload["output_text"].startswith('{"answer":')
    assert payload["usage"]["input_tokens"] >= 1
    assert payload["usage"]["output_tokens"] >= 1
    assert payload["usage"]["total_tokens"] == payload["usage"]["input_tokens"] + payload["usage"]["output_tokens"]
    assert payload["risk_tier"] == "low"
    assert "frontier_model_family" in payload["risk_reasons"]

    from app.database import SessionLocal
    from app.models import CostEvent

    db = SessionLocal()
    try:
        event = db.query(CostEvent).filter_by(trace_id=payload["trace_id"]).first()
        assert event is not None
        assert event.endpoint_family == "responses"
        assert event.estimated_cost_cents >= 0
    finally:
        db.close()


def test_gateway_openai_responses_streaming_contract():
    response = client.post(
        "/v1/responses",
        json={
            "model": "gpt-4o-mini",
            "input": "Stream response lifecycle status.",
            "stream": True,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-responses-stream"},
    )
    assert response.status_code == 200
    assert "text/event-stream" in str(response.headers.get("content-type", "")).lower()
    body = response.text
    assert "response.chunk" in body
    assert "data: [DONE]" in body


def test_gateway_openai_responses_max_output_tokens_sets_length_finish_reason():
    response = client.post(
        "/v1/responses",
        json={
            "model": "gpt-4o-mini",
            "input": "Summarize fallback routing behavior in concise terms.",
            "max_output_tokens": 1,
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-responses-max-output"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["output"][0]["finish_reason"] == "length"
    assert payload["usage"]["output_tokens"] <= 1


def test_gateway_openai_responses_prod_tool_call_path_sets_high_risk_tier():
    response = client.post(
        "/v1/responses",
        json={
            "model": "gpt-4o-mini",
            "input": "execute regulated action",
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "run_sensitive_op",
                        "description": "Execute sensitive operation",
                    },
                }
            ],
            "tool_choice": "required",
            "stream": False,
            "environment": "prod",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-responses-prod-tool-risk"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["output"][0]["type"] == "tool_call"
    assert payload["risk_tier"] == "high"
    assert "production_environment" in payload["risk_reasons"]
    assert "tool_call_execution_path" in payload["risk_reasons"]


def test_gateway_openai_responses_provider_prefixed_model_requires_tenant():
    response = client.post(
        "/v1/responses",
        json={
            "model": "openai/gpt-4o-mini",
            "input": "hello",
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-responses-no-tenant"},
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "tenant_id is required when model includes provider prefix"


def test_gateway_openai_responses_forbidden_role_emits_deny_audit():
    denied = client.post(
        "/v1/responses",
        json={
            "model": "gpt-4o-mini",
            "input": "test",
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-responses-denied"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    audits = client.get(
        "/audit/events?action_type=gateway.responses.create&decision_outcome=deny&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-responses-denied"},
    )
    assert audits.status_code == 200
    assert any(row["actor_id"] == "aud-responses-denied" for row in audits.json())


def test_gateway_openai_responses_external_cursor_runtime_read_failure_emits_warn_audit():
    ensure_tenant_catalog_entry("tenant-gateway-cursor-runtime-failure", "admin-provider-tenant-gateway-cursor-runtime-failure")
    provider_created = client.post(
        "/secrets/providers",
        json={
            "tenant_id": "tenant-gateway-cursor-runtime-failure",
            "provider_type": "vault",
            "provider_address": "https://vault.example.com",
            "auth_method": "approle",
            "role_or_mount": "approle/platform",
            "secret_path_prefixes": '["kv/data/gateway"]',
            "lease_ttl_seconds": 600,
            "auto_renew_enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-secret-runtime-failure", "X-MFA-Verified": "true"},
    )
    assert provider_created.status_code == 200
    provider_id = provider_created.json()["secret_provider_id"]

    configured = client.put(
        "/gateway/cursor-token",
        json={
            "storage_mode": "external",
            "external_provider_id": provider_id,
            "external_secret_ref": "kv/data/gateway/cursor_token_failure",
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-cursor-token-runtime-failure",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-cursor-token-runtime-failure",
        },
    )
    assert configured.status_code == 200

    try:
        with patch.dict(os.environ, {"GATEWAY_INFERENCE_SIMULATION": "false"}, clear=False):
            with patch("app.routers.gateway.httpx.get") as mock_get:
                mock_resp = Mock()
                mock_resp.status_code = 500
                mock_resp.headers = {"content-type": "application/json"}
                mock_resp.json.return_value = {"errors": ["vault unavailable"]}
                mock_get.return_value = mock_resp

                failed = client.post(
                    "/v1/responses",
                    json={
                        "model": "gpt-4o-mini",
                        "input": "runtime token failure check",
                        "stream": False,
                        "environment": "dev",
                    },
                    headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-runtime-token-failure-check"},
                )
                assert failed.status_code == 502
                assert failed.json()["detail"] == "Vault secret read failed"

        audits = client.get(
            "/audit/events?action_type=gateway.responses.create&decision_outcome=warn&limit=20",
            headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-runtime-token-failure-check"},
        )
        assert audits.status_code == 200
        assert any(row["actor_id"] == "admin-runtime-token-failure-check" for row in audits.json())
    finally:
        reset = client.put(
            "/gateway/cursor-token",
            json={"storage_mode": "db", "token": "cursor-token-reset-after-runtime-failure-test"},
            headers={
                "X-Actor-Role": "Platform Admin",
                "X-Actor-Id": "admin-cursor-token-runtime-failure-reset",
                "X-Approver-Role": "Security Approver",
                "X-Approver-Id": "sec-cursor-token-runtime-failure-reset",
            },
        )
        assert reset.status_code == 200


def test_gateway_openai_responses_required_tool_choice_returns_tool_call_output():
    response = client.post(
        "/v1/responses",
        json={
            "model": "gpt-4o-mini",
            "instructions": "Use a tool if needed.",
            "input": "Fetch latest routing health summary.",
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "get_route_health",
                        "description": "Retrieve route health snapshot",
                    },
                }
            ],
            "tool_choice": "required",
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-responses-tool-call"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["output"][0]["type"] == "tool_call"
    assert payload["output"][0]["finish_reason"] == "tool_calls"
    assert payload["output"][0]["content"][0]["name"] == "get_route_health"
    assert str(payload["output"][0]["content"][0]["arguments"]).startswith("{")


def test_gateway_system_rules_crud_and_role_enforcement():
    denied_update = client.put(
        "/gateway/system-rules",
        json={
            "rules": [
                {"rule_text": "Never expose secrets", "scope_type": "global"},
                {"rule_text": "Prefer least-privilege actions", "scope_type": "user", "scope_id": "aud-system-rules"},
            ]
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-system-rules"},
    )
    assert denied_update.status_code == 403

    updated = client.put(
        "/gateway/system-rules",
        json={
            "rules": [
                {"rule_text": "Never expose secrets", "scope_type": "global"},
                {"rule_text": "Prefer least-privilege actions", "scope_type": "user", "scope_id": "aud-system-rules"},
            ]
        },
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-system-rules"},
    )
    assert updated.status_code == 200
    payload = updated.json()
    assert payload["config_key"] == "gateway.system_rules_json"
    assert len(payload["rules"]) == 2
    assert payload["rules"][0]["scope_type"] == "global"
    assert payload["rules"][1]["scope_type"] == "user"

    fetched = client.get(
        "/gateway/system-rules",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-system-rules"},
    )
    assert fetched.status_code == 200
    assert len(fetched.json()["rules"]) == 2


def test_gateway_cursor_token_config_masks_readback_and_enforces_roles():
    denied_read = client.get(
        "/gateway/cursor-token",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-cursor-token-read"},
    )
    assert denied_read.status_code == 403

    denied_update = client.put(
        "/gateway/cursor-token",
        json={"token": "cursor-secret-token-123456"},
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-cursor-token-update"},
    )
    assert denied_update.status_code == 403

    no_approval_non_prod = client.put(
        "/gateway/cursor-token",
        json={"token": "cursor-secret-token-123456"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-cursor-token-missing-approval"},
    )
    assert no_approval_non_prod.status_code == 200

    updated = client.put(
        "/gateway/cursor-token",
        json={"token": "cursor-secret-token-123456"},
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-cursor-token",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-cursor-token",
        },
    )
    assert updated.status_code == 200
    update_payload = updated.json()
    assert update_payload["configured"] is True
    assert "cursor-secret-token-123456" not in str(update_payload)
    assert update_payload["masked_hint"] != "cursor-secret-token-123456"

    with Session(engine) as db:
        row = db.query(RuntimeConfig).filter_by(config_key="gateway.cursor_api_token").first()
        assert row is not None
        assert isinstance(row.config_value, str)
        stored = json.loads(row.config_value)
        assert stored["version"] == "v3"
        assert stored["secret_provider_id"]
        assert stored["secret_ref"] == "gateway/cursor-token"
        assert "cursor-secret-token-123456" not in row.config_value

    fetched = client.get(
        "/gateway/cursor-token",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-cursor-token-read"},
    )
    assert fetched.status_code == 200
    fetch_payload = fetched.json()
    assert fetch_payload["configured"] is True
    assert fetch_payload["storage_mode"] == "db"
    assert fetch_payload["external_provider_id"]
    assert fetch_payload["external_secret_ref"] == "gateway/cursor-token"
    assert "cursor-secret-token-123456" not in str(fetch_payload)
    assert fetch_payload["masked_hint"] and "***" in fetch_payload["masked_hint"]

    cleared = client.delete(
        "/gateway/cursor-token",
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-cursor-token",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-cursor-token",
        },
    )
    assert cleared.status_code == 200
    clear_payload = cleared.json()
    assert clear_payload["configured"] is False
    assert clear_payload["storage_mode"] == "db"
    assert clear_payload["masked_hint"] is None


def test_gateway_cursor_token_external_provider_mode_persists_reference_only():
    ensure_tenant_catalog_entry("tenant-gateway-cursor-ext", "admin-provider-tenant-gateway-cursor-ext")
    provider_created = client.post(
        "/secrets/providers",
        json={
            "tenant_id": "tenant-gateway-cursor-ext",
            "provider_type": "vault",
            "provider_address": "https://vault.example.com",
            "auth_method": "approle",
            "role_or_mount": "approle/platform",
            "secret_path_prefixes": '["kv/data/gateway"]',
            "lease_ttl_seconds": 600,
            "auto_renew_enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-secret-ext", "X-MFA-Verified": "true"},
    )
    assert provider_created.status_code == 200
    provider_id = provider_created.json()["secret_provider_id"]

    updated = client.put(
        "/gateway/cursor-token",
        json={
            "storage_mode": "external",
            "external_provider_id": provider_id,
            "external_secret_ref": "kv/data/gateway/cursor_token",
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-cursor-token-ext",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-cursor-token-ext",
        },
    )
    assert updated.status_code == 200
    payload = updated.json()
    assert payload["configured"] is True
    assert payload["storage_mode"] == "external"
    assert payload["external_provider_id"] == provider_id
    assert payload["external_secret_ref"] == "kv/data/gateway/cursor_token"

    with Session(engine) as db:
        row = db.query(RuntimeConfig).filter_by(config_key="gateway.cursor_api_token").first()
        assert row is not None
        stored = json.loads(row.config_value)
        assert stored["version"] == "v3"
        assert stored["secret_provider_id"] == provider_id
        assert stored["secret_ref"] == "kv/data/gateway/cursor_token"
        assert "cursor-secret-token" not in row.config_value

    fetched = client.get(
        "/gateway/cursor-token",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-cursor-token-ext-read"},
    )
    assert fetched.status_code == 200
    fetched_payload = fetched.json()
    assert fetched_payload["configured"] is True
    assert fetched_payload["storage_mode"] == "external"
    assert fetched_payload["external_provider_id"] == provider_id
    assert fetched_payload["external_secret_ref"] == "kv/data/gateway/cursor_token"

    reset = client.put(
        "/gateway/cursor-token",
        json={"storage_mode": "db", "token": "cursor-token-reset-after-external-reference-test"},
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-cursor-token-ext-reset",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-cursor-token-ext-reset",
        },
    )
    assert reset.status_code == 200


def test_gateway_cursor_token_external_provider_mode_rejects_inactive_provider():
    ensure_tenant_catalog_entry("tenant-gateway-cursor-ext-inactive", "admin-provider-tenant-gateway-cursor-ext-inactive")
    provider_created = client.post(
        "/secrets/providers",
        json={
            "tenant_id": "tenant-gateway-cursor-ext-inactive",
            "provider_type": "vault",
            "provider_address": "https://vault.example.com",
            "auth_method": "approle",
            "role_or_mount": "approle/platform",
            "secret_path_prefixes": '["kv/data/gateway"]',
            "lease_ttl_seconds": 600,
            "auto_renew_enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-secret-ext-inactive", "X-MFA-Verified": "true"},
    )
    assert provider_created.status_code == 200
    provider_id = provider_created.json()["secret_provider_id"]

    with Session(engine) as db:
        row = db.query(SecretProviderConfig).filter_by(secret_provider_id=provider_id).first()
        assert row is not None
        row.status = "inactive"
        db.commit()

    denied = client.put(
        "/gateway/cursor-token",
        json={
            "storage_mode": "external",
            "external_provider_id": provider_id,
            "external_secret_ref": "kv/data/gateway/cursor_token",
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-cursor-token-ext-inactive",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-cursor-token-ext-inactive",
        },
    )
    assert denied.status_code == 400
    assert denied.json()["detail"] == "External secret provider is not active"


def test_gateway_openai_responses_applies_gateway_system_rules():
    agent_suffix = uuid4().hex[:8]
    agent_id = f"agent-ops-{agent_suffix}"
    set_rules = client.put(
        "/gateway/system-rules",
        json={
            "rules": [
                {"rule_text": "Always provide concise answers", "scope_type": "global"},
                {"rule_text": "Never output credentials", "scope_type": "user", "scope_id": "ops-user-1"},
                {"rule_text": "Use agent-specific policy", "scope_type": "agent", "scope_id": agent_id},
                {"rule_text": "Apply team guardrails", "scope_type": "team", "scope_id": "platform-security"},
                {"rule_text": "Apply group guardrails", "scope_type": "group", "scope_id": "soc-operators"},
            ]
        },
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-system-rules-apply"},
    )
    assert set_rules.status_code == 200

    try:
        response = client.post(
            "/v1/responses",
            json={
                "model": "gpt-4o-mini",
                "input": "Summarize gateway posture.",
                "agent_id": agent_id,
                "owner_scope": "team:platform-security",
                "stream": False,
                "environment": "dev",
            },
            headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "ops-user-1"},
        )
        assert response.status_code == 200
        content = response.json()["output"][0]["content"][0]["text"]
        assert "Always provide concise answers" in content
        assert "Never output credentials" in content
        assert "Use agent-specific policy" in content
        assert "Apply team guardrails" in content
        assert "Apply group guardrails" not in content

        group_response = client.post(
            "/v1/responses",
            json={
                "model": "gpt-4o-mini",
                "input": "Summarize gateway posture for group.",
                "agent_id": agent_id,
                "owner_scope": "group:soc-operators",
                "stream": False,
                "environment": "dev",
            },
            headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "ops-user-1"},
        )
        assert group_response.status_code == 200
        group_content = group_response.json()["output"][0]["content"][0]["text"]
        assert "Apply group guardrails" in group_content
    finally:
        cleared = client.put(
            "/gateway/system-rules",
            json={"rules": []},
            headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-system-rules-cleanup"},
        )
        assert cleared.status_code == 200


def test_gateway_openai_responses_resolves_external_cursor_token_at_runtime():
    ensure_tenant_catalog_entry("tenant-gateway-cursor-runtime", "admin-provider-tenant-gateway-cursor-runtime")
    provider_created = client.post(
        "/secrets/providers",
        json={
            "tenant_id": "tenant-gateway-cursor-runtime",
            "provider_type": "vault",
            "provider_address": "https://vault.example.com",
            "auth_method": "approle",
            "role_or_mount": "approle/platform",
            "secret_path_prefixes": '["kv/data/gateway"]',
            "lease_ttl_seconds": 600,
            "auto_renew_enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-secret-runtime", "X-MFA-Verified": "true"},
    )
    assert provider_created.status_code == 200
    provider_id = provider_created.json()["secret_provider_id"]

    configured = client.put(
        "/gateway/cursor-token",
        json={
            "storage_mode": "external",
            "external_provider_id": provider_id,
            "external_secret_ref": "kv/data/gateway/cursor_token",
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-cursor-token-runtime",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-cursor-token-runtime",
        },
    )
    assert configured.status_code == 200

    try:
        with patch.dict(os.environ, {"GATEWAY_INFERENCE_SIMULATION": "false"}, clear=False):
            with patch("app.routers.gateway.httpx.get") as mock_get:
                mock_resp = Mock()
                mock_resp.status_code = 200
                mock_resp.headers = {"content-type": "application/json"}
                mock_resp.json.return_value = {"data": {"data": {"token": "cursor-runtime-token"}}}
                mock_get.return_value = mock_resp

                response = client.post(
                    "/v1/responses",
                    json={
                        "model": "gpt-4o-mini",
                        "input": "runtime token check",
                        "stream": False,
                        "environment": "dev",
                    },
                    headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-runtime-token-check"},
                )
                assert response.status_code == 200
                assert mock_get.called
    finally:
        reset = client.put(
            "/gateway/cursor-token",
            json={"storage_mode": "db", "token": "cursor-token-reset-after-runtime-test"},
            headers={
                "X-Actor-Role": "Platform Admin",
                "X-Actor-Id": "admin-cursor-token-runtime-reset",
                "X-Approver-Role": "Security Approver",
                "X-Approver-Id": "sec-cursor-token-runtime-reset",
            },
        )
        assert reset.status_code == 200


def test_gateway_openai_responses_rejects_invalid_tool_choice_contract():
    response = client.post(
        "/v1/responses",
        json={
            "model": "gpt-4o-mini",
            "input": "hello",
            "tools": [{"type": "function", "function": {"name": "get_route_health"}}],
            "tool_choice": "must_call",
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-responses-tool-invalid"},
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "tool_choice must be one of: auto, none, required"


def test_gateway_openai_responses_tool_choice_object_forces_named_tool_call():
    response = client.post(
        "/v1/responses",
        json={
            "model": "gpt-4o-mini",
            "input": "Get gateway cache status.",
            "tools": [
                {"type": "function", "function": {"name": "get_cache_health"}},
                {"type": "function", "function": {"name": "get_route_health"}},
            ],
            "tool_choice": {"type": "function", "function": {"name": "get_cache_health"}},
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-responses-tool-choice-object"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["output"][0]["type"] == "tool_call"
    assert payload["output"][0]["content"][0]["name"] == "get_cache_health"


def test_gateway_openai_responses_rejects_non_function_tool_type():
    response = client.post(
        "/v1/responses",
        json={
            "model": "gpt-4o-mini",
            "input": "hello",
            "tools": [{"type": "web_search", "function": {"name": "search_docs"}}],
            "tool_choice": "required",
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-responses-tool-type-invalid"},
    )
    assert response.status_code == 422
    assert response.json()["detail"] == "tools[].type must be function"


def test_gateway_openai_responses_lifecycle_retrieve_list_delete_contract():
    created = client.post(
        "/v1/responses",
        json={
            "model": "gpt-4o-mini",
            "input": "Summarize cloud IAM guardrails.",
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-responses-lifecycle"},
    )
    assert created.status_code == 200
    created_payload = created.json()
    response_id = created_payload["id"]

    retrieved = client.get(
        f"/v1/responses/{response_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-responses-lifecycle"},
    )
    assert retrieved.status_code == 200
    retrieved_payload = retrieved.json()
    assert retrieved_payload["id"] == response_id
    assert retrieved_payload["object"] == "response"

    listed = client.get(
        "/v1/responses?limit=50&offset=0",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-responses-lifecycle"},
    )
    assert listed.status_code == 200
    listed_payload = listed.json()
    assert listed_payload["object"] == "list"
    assert any(item["id"] == response_id for item in listed_payload["data"])

    deleted = client.delete(
        f"/v1/responses/{response_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-responses-lifecycle"},
    )
    assert deleted.status_code == 200
    deleted_payload = deleted.json()
    assert deleted_payload["id"] == response_id
    assert deleted_payload["deleted"] is True

    missing_after_delete = client.get(
        f"/v1/responses/{response_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-responses-lifecycle"},
    )
    assert missing_after_delete.status_code == 404


def test_gateway_openai_files_lifecycle_and_delete_role_guard():
    created = client.post(
        "/v1/files",
        json={
            "filename": "risk-evidence.json",
            "purpose": "assistants",
            "bytes": 2048,
            "content_type": "application/json",
            "metadata": {"classification": "internal"},
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-files-lifecycle"},
    )
    assert created.status_code == 200
    created_payload = created.json()
    file_id = created_payload["id"]
    assert created_payload["object"] == "file"
    assert created_payload["status"] == "uploaded"

    listed = client.get(
        "/v1/files?limit=50&offset=0",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-files-lifecycle"},
    )
    assert listed.status_code == 200
    listed_payload = listed.json()
    assert listed_payload["object"] == "list"
    assert any(item["id"] == file_id for item in listed_payload["data"])

    retrieved = client.get(
        f"/v1/files/{file_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-files-lifecycle"},
    )
    assert retrieved.status_code == 200
    assert retrieved.json()["id"] == file_id

    denied_delete = client.delete(
        f"/v1/files/{file_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-files-delete-denied"},
    )
    assert denied_delete.status_code == 403
    assert denied_delete.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    deleted = client.delete(
        f"/v1/files/{file_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-files-lifecycle"},
    )
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True

    missing_after_delete = client.get(
        f"/v1/files/{file_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-files-lifecycle"},
    )
    assert missing_after_delete.status_code == 404


def test_gateway_openai_batches_lifecycle_and_owner_scope_guard():
    created = client.post(
        "/v1/batches",
        json={
            "endpoint_family": "responses",
            "requests": [{"id": "req-1", "input": "batch payload"}],
            "metadata": {"request_tag": "billing.batch-01"},
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-batches-lifecycle"},
    )
    assert created.status_code == 200
    payload = created.json()
    batch_id = payload["id"]
    assert payload["object"] == "batch"
    assert payload["endpoint_family"] == "responses"
    assert payload["request_count"] == 1
    assert payload["status"] == "queued"

    retrieved = client.get(
        f"/v1/batches/{batch_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-batches-lifecycle"},
    )
    assert retrieved.status_code == 200
    assert retrieved.json()["id"] == batch_id

    owner_created = client.post(
        "/v1/batches",
        json={
            "endpoint_family": "responses",
            "requests": [{"id": "req-2", "input": "owner batch"}],
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-batch-a"},
    )
    assert owner_created.status_code == 200
    owner_batch_id = owner_created.json()["id"]

    owner_cross_read = client.get(
        f"/v1/batches/{owner_batch_id}",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-batch-b"},
    )
    assert owner_cross_read.status_code == 403
    assert owner_cross_read.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"

    deleted = client.delete(
        f"/v1/batches/{batch_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-batches-lifecycle"},
    )
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True

    missing_after_delete = client.get(
        f"/v1/batches/{batch_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-batches-lifecycle"},
    )
    assert missing_after_delete.status_code == 404


def test_gateway_openai_responses_list_supports_server_side_filters():
    alpha = client.post(
        "/v1/responses",
        json={
            "model": "gpt-4o-mini",
            "input": "alpha-route posture",
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-responses-filter"},
    )
    beta = client.post(
        "/v1/responses",
        json={
            "model": "claude-3-5-sonnet",
            "input": "beta-route posture",
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-responses-filter"},
    )
    assert alpha.status_code == 200
    assert beta.status_code == 200
    alpha_id = alpha.json()["id"]

    filtered_model = client.get(
        "/v1/responses?model_contains=gpt-4o&limit=50&offset=0",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-responses-filter"},
    )
    assert filtered_model.status_code == 200
    filtered_model_ids = [item["id"] for item in filtered_model.json()["data"]]
    assert alpha_id in filtered_model_ids
    assert all("gpt-4o" in str(item["model"]).lower() for item in filtered_model.json()["data"])

    filtered_output = client.get(
        "/v1/responses?output_contains=alpha-route&limit=50&offset=0",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-responses-filter"},
    )
    assert filtered_output.status_code == 200
    assert any(item["id"] == alpha_id for item in filtered_output.json()["data"])
    assert all("alpha-route" in str(item["output_text"]).lower() for item in filtered_output.json()["data"])


def test_gateway_openai_files_list_supports_server_side_filters():
    alpha = client.post(
        "/v1/files",
        json={
            "filename": "alpha-evidence.json",
            "purpose": "assistants",
            "bytes": 220,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-files-filter"},
    )
    beta = client.post(
        "/v1/files",
        json={
            "filename": "beta-batch.json",
            "purpose": "batch",
            "bytes": 221,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-files-filter"},
    )
    assert alpha.status_code == 200
    assert beta.status_code == 200
    alpha_id = alpha.json()["id"]

    filtered_name = client.get(
        "/v1/files?filename_contains=alpha&limit=50&offset=0",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-files-filter"},
    )
    assert filtered_name.status_code == 200
    assert any(item["id"] == alpha_id for item in filtered_name.json()["data"])
    assert all("alpha" in str(item["filename"]).lower() for item in filtered_name.json()["data"])

    filtered_purpose = client.get(
        "/v1/files?purpose=assistants&status=uploaded&limit=50&offset=0",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-files-filter"},
    )
    assert filtered_purpose.status_code == 200
    assert any(item["id"] == alpha_id for item in filtered_purpose.json()["data"])
    assert all(str(item["purpose"]) == "assistants" for item in filtered_purpose.json()["data"])
    assert all(str(item["status"]) == "uploaded" for item in filtered_purpose.json()["data"])


def test_gateway_openai_responses_agent_owner_scope_and_auditor_cross_owner_read():
    owner_a_created = client.post(
        "/v1/responses",
        json={
            "model": "gpt-4o-mini",
            "input": "owner-a response",
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-resp-a"},
    )
    assert owner_a_created.status_code == 200

    owner_b_created = client.post(
        "/v1/responses",
        json={
            "model": "gpt-4o-mini",
            "input": "owner-b response",
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-resp-b"},
    )
    assert owner_b_created.status_code == 200
    response_b_id = owner_b_created.json()["id"]

    owner_a_list = client.get(
        "/v1/responses?limit=50&offset=0",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-resp-a"},
    )
    assert owner_a_list.status_code == 200
    assert all(item["id"] != response_b_id for item in owner_a_list.json()["data"])

    owner_a_cross = client.get(
        f"/v1/responses/{response_b_id}",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-resp-a"},
    )
    assert owner_a_cross.status_code == 403
    assert owner_a_cross.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"

    auditor_cross = client.get(
        f"/v1/responses/{response_b_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-resp-cross"},
    )
    assert auditor_cross.status_code == 200
    assert auditor_cross.json()["id"] == response_b_id

    denied_audits = client.get(
        "/audit/events?action_type=gateway.responses.retrieve&decision_outcome=deny&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-resp-cross"},
    )
    assert denied_audits.status_code == 200
    assert any(row["actor_id"] == "owner-resp-a" for row in denied_audits.json())


def test_gateway_openai_files_agent_owner_scope_and_auditor_cross_owner_read():
    owner_a_file = client.post(
        "/v1/files",
        json={
            "filename": "owner-a.json",
            "purpose": "assistants",
            "bytes": 100,
            "content_type": "application/json",
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-file-a"},
    )
    assert owner_a_file.status_code == 200

    owner_b_file = client.post(
        "/v1/files",
        json={
            "filename": "owner-b.json",
            "purpose": "assistants",
            "bytes": 101,
            "content_type": "application/json",
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-file-b"},
    )
    assert owner_b_file.status_code == 200
    file_b_id = owner_b_file.json()["id"]

    owner_a_list = client.get(
        "/v1/files?limit=50&offset=0",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-file-a"},
    )
    assert owner_a_list.status_code == 200
    assert all(item["id"] != file_b_id for item in owner_a_list.json()["data"])

    owner_a_cross = client.get(
        f"/v1/files/{file_b_id}",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-file-a"},
    )
    assert owner_a_cross.status_code == 403
    assert owner_a_cross.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"

    auditor_cross = client.get(
        f"/v1/files/{file_b_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-file-cross"},
    )
    assert auditor_cross.status_code == 200
    assert auditor_cross.json()["id"] == file_b_id

    denied_audits = client.get(
        "/audit/events?action_type=gateway.files.retrieve&decision_outcome=deny&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-file-cross"},
    )
    assert denied_audits.status_code == 200
    assert any(row["actor_id"] == "owner-file-a" for row in denied_audits.json())


def test_gateway_openai_responses_delete_owner_scope_and_prod_dual_approval():
    owner_b_created = client.post(
        "/v1/responses",
        json={
            "model": "gpt-4o-mini",
            "input": "owner-b delete target",
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-resp-del-b"},
    )
    assert owner_b_created.status_code == 200
    response_id_b = owner_b_created.json()["id"]

    owner_a_cross_delete = client.delete(
        f"/v1/responses/{response_id_b}",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-resp-del-a"},
    )
    assert owner_a_cross_delete.status_code == 403
    assert owner_a_cross_delete.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"

    owner_deny_audits = client.get(
        "/audit/events?action_type=gateway.responses.delete&decision_outcome=deny&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-resp-del-scope"},
    )
    assert owner_deny_audits.status_code == 200
    assert any(row["actor_id"] == "owner-resp-del-a" for row in owner_deny_audits.json())

    prod_created = client.post(
        "/v1/responses",
        json={
            "model": "gpt-4o-mini",
            "input": "prod response delete guard",
            "stream": False,
            "environment": "prod",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-resp-del-prod"},
    )
    assert prod_created.status_code == 200
    prod_response_id = prod_created.json()["id"]

    denied_dual = client.delete(
        f"/v1/responses/{prod_response_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-resp-del-prod"},
    )
    assert denied_dual.status_code == 403
    assert denied_dual.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    allowed_dual = client.delete(
        f"/v1/responses/{prod_response_id}",
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-resp-del-prod",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-resp-del-prod",
        },
    )
    assert allowed_dual.status_code == 200
    assert allowed_dual.json()["deleted"] is True


def test_gateway_openai_files_delete_owner_scope_and_prod_dual_approval():
    owner_b_file = client.post(
        "/v1/files",
        json={
            "filename": "owner-b-delete.json",
            "purpose": "assistants",
            "bytes": 120,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-file-del-b"},
    )
    assert owner_b_file.status_code == 200
    file_id_b = owner_b_file.json()["id"]

    owner_a_cross_delete = client.delete(
        f"/v1/files/{file_id_b}",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-file-del-a"},
    )
    assert owner_a_cross_delete.status_code == 403
    assert owner_a_cross_delete.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"

    owner_deny_audits = client.get(
        "/audit/events?action_type=gateway.files.delete&decision_outcome=deny&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-file-del-scope"},
    )
    assert owner_deny_audits.status_code == 200
    assert any(row["actor_id"] == "owner-file-del-a" for row in owner_deny_audits.json())

    prod_file = client.post(
        "/v1/files",
        json={
            "filename": "prod-delete.json",
            "purpose": "assistants",
            "bytes": 121,
            "environment": "prod",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-file-del-prod"},
    )
    assert prod_file.status_code == 200
    prod_file_id = prod_file.json()["id"]

    denied_dual = client.delete(
        f"/v1/files/{prod_file_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-file-del-prod"},
    )
    assert denied_dual.status_code == 403
    assert denied_dual.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    allowed_dual = client.delete(
        f"/v1/files/{prod_file_id}",
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-file-del-prod",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-file-del-prod",
        },
    )
    assert allowed_dual.status_code == 200
    assert allowed_dual.json()["deleted"] is True


def test_gateway_route_pre_call_filters_roundtrip_and_execution_blocking():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "pre-call-filters-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-pre-call-filters"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-pre-call",
            "environment": "dev",
            "priority_order": '[{"provider_id":"provider-primary","priority":1}]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-pre-call-filters"},
    )
    assert configured.status_code == 200

    saved_filters = client.put(
        f"/gateway/routes/{route_policy_id}/pre-call-filters",
        json={
            "tenant_id": "tenant-pre-call",
            "environment": "dev",
            "allowed_regions": '["us-east-1"]',
            "min_context_window_tokens": 50,
            "max_context_window_tokens": 500,
            "enforce": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-pre-call-filters"},
    )
    assert saved_filters.status_code == 200

    read_filters = client.get(
        f"/gateway/routes/{route_policy_id}/pre-call-filters",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-pre-call-filters"},
    )
    assert read_filters.status_code == 200
    assert "us-east-1" in read_filters.json()["allowed_regions"]

    blocked = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-pre-call",
            "environment": "dev",
            "agent_id": "agent-pre-call",
            "requested_region": "eu-west-1",
            "session_id": "sess-pre-call",
            "owner_scope": "team:platform",
            "input_tokens": 100,
            "output_tokens": 60,
            "simulate_fail_provider_ids": "[]",
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-pre-call-filters"},
    )
    assert blocked.status_code == 200
    blocked_payload = blocked.json()
    assert blocked_payload["final_outcome"] == "blocked_pre_call_filter"
    assert blocked_payload["provider_attempts"] == 0

    allowed = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-pre-call",
            "environment": "dev",
            "agent_id": "agent-pre-call",
            "requested_region": "us-east-1",
            "session_id": "sess-pre-call-allowed",
            "owner_scope": "team:platform",
            "input_tokens": 80,
            "output_tokens": 40,
            "simulate_fail_provider_ids": "[]",
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-pre-call-filters"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["final_outcome"] == "success"


def test_gateway_route_output_guardrails_roundtrip_and_execution_enforcement():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "output-guardrails-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-output-guardrails"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-output-guardrails",
            "environment": "dev",
            "priority_order": '[{"provider_id":"provider-primary","priority":1}]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-output-guardrails"},
    )
    assert configured.status_code == 200

    saved_guardrails = client.put(
        f"/gateway/routes/{route_policy_id}/output-guardrails",
        json={
            "tenant_id": "tenant-output-guardrails",
            "environment": "dev",
            "policy_mode": "block",
            "blocked_phrases": '["forbidden"]',
            "redact_phrases": '["secret"]',
            "max_output_tokens": 64,
            "enforce": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-output-guardrails"},
    )
    assert saved_guardrails.status_code == 200

    read_guardrails = client.get(
        f"/gateway/routes/{route_policy_id}/output-guardrails",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-output-guardrails"},
    )
    assert read_guardrails.status_code == 200
    assert read_guardrails.json()["policy_mode"] == "block"
    assert "forbidden" in read_guardrails.json()["blocked_phrases"]

    blocked = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-output-guardrails",
            "environment": "dev",
            "agent_id": "agent-output-guardrails",
            "session_id": "sess-output-guardrails-block",
            "owner_scope": "team:platform",
            "input_tokens": 40,
            "output_tokens": 40,
            "simulated_output_text": "This output includes forbidden content.",
            "simulate_fail_provider_ids": "[]",
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-output-guardrails"},
    )
    assert blocked.status_code == 200
    blocked_payload = blocked.json()
    assert blocked_payload["final_outcome"] == "blocked_output_guardrail"
    assert blocked_payload["selected_provider_id"] is None

    set_warn_mode = client.put(
        f"/gateway/routes/{route_policy_id}/output-guardrails",
        json={
            "tenant_id": "tenant-output-guardrails",
            "environment": "dev",
            "policy_mode": "warn",
            "blocked_phrases": '["forbidden"]',
            "enforce": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-output-guardrails"},
    )
    assert set_warn_mode.status_code == 200

    warned = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-output-guardrails",
            "environment": "dev",
            "agent_id": "agent-output-guardrails",
            "session_id": "sess-output-guardrails-warn",
            "owner_scope": "team:platform",
            "input_tokens": 40,
            "output_tokens": 40,
            "simulated_output_text": "This output includes forbidden content.",
            "simulate_fail_provider_ids": "[]",
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-output-guardrails"},
    )
    assert warned.status_code == 200
    warned_payload = warned.json()
    assert warned_payload["final_outcome"] in {"success", "warn_output_guardrail", "transformed_output_guardrail"}
    warned_attempted = json.loads(warned_payload["attempted_providers"])
    assert any(row.get("outcome") == "warn_output_guardrail" for row in warned_attempted)


def test_gateway_route_output_guardrails_prod_requires_dual_approval():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "prod-output-guardrails-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-prod-output-guardrails"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    denied = client.put(
        f"/gateway/routes/{route_policy_id}/output-guardrails",
        json={
            "tenant_id": "tenant-prod-output-guardrails",
            "environment": "prod",
            "policy_mode": "block",
            "blocked_phrases": '["forbidden"]',
            "enforce": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-prod-output-guardrails"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"


def test_gateway_route_input_data_policy_roundtrip_and_execution_enforcement():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "input-data-policy-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-input-data-policy"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-input-data-policy",
            "environment": "dev",
            "priority_order": '[{"provider_id":"provider-primary","priority":1}]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-input-data-policy"},
    )
    assert configured.status_code == 200

    saved_policy = client.put(
        f"/gateway/routes/{route_policy_id}/input-data-policy",
        json={
            "tenant_id": "tenant-input-data-policy",
            "environment": "dev",
            "policy_mode": "block",
            "data_classes": '["pii"]',
            "block_patterns": '["ssn"]',
            "mask_token": "[MASKED]",
            "enforce": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-input-data-policy"},
    )
    assert saved_policy.status_code == 200

    read_policy = client.get(
        f"/gateway/routes/{route_policy_id}/input-data-policy",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-input-data-policy"},
    )
    assert read_policy.status_code == 200
    assert read_policy.json()["policy_mode"] == "block"
    assert "pii" in read_policy.json()["data_classes"]

    blocked = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-input-data-policy",
            "environment": "dev",
            "agent_id": "agent-input-data-policy",
            "request_tag": "pii.customer",
            "session_id": "sess-input-data-policy-block",
            "owner_scope": "team:platform",
            "simulated_input_text": "Customer SSN is 123-45-6789",
            "input_tokens": 40,
            "output_tokens": 40,
            "simulate_fail_provider_ids": "[]",
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-input-data-policy"},
    )
    assert blocked.status_code == 200
    blocked_payload = blocked.json()
    assert blocked_payload["final_outcome"] == "blocked_input_data_policy"
    assert blocked_payload["selected_provider_id"] is None

    set_warn_mode = client.put(
        f"/gateway/routes/{route_policy_id}/input-data-policy",
        json={
            "tenant_id": "tenant-input-data-policy",
            "environment": "dev",
            "policy_mode": "warn",
            "data_classes": '["pii"]',
            "enforce": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-input-data-policy"},
    )
    assert set_warn_mode.status_code == 200

    warned = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-input-data-policy",
            "environment": "dev",
            "agent_id": "agent-input-data-policy",
            "request_tag": "pii.customer",
            "session_id": "sess-input-data-policy-warn",
            "owner_scope": "team:platform",
            "simulated_input_text": "Sensitive customer profile",
            "input_tokens": 40,
            "output_tokens": 40,
            "simulate_fail_provider_ids": "[]",
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-input-data-policy"},
    )
    assert warned.status_code == 200
    warned_payload = warned.json()
    warned_attempted = json.loads(warned_payload["attempted_providers"])
    assert any(row.get("outcome") == "warn_input_data_policy" for row in warned_attempted)


def test_gateway_route_input_data_policy_prod_requires_dual_approval():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "prod-input-data-policy-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-prod-input-data-policy"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    denied = client.put(
        f"/gateway/routes/{route_policy_id}/input-data-policy",
        json={
            "tenant_id": "tenant-prod-input-data-policy",
            "environment": "prod",
            "policy_mode": "block",
            "data_classes": '["secret"]',
            "enforce": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-prod-input-data-policy"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"


def test_gateway_route_traffic_mirroring_roundtrip_and_execute():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "traffic-mirroring-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-traffic-mirroring"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-traffic-mirroring",
            "environment": "dev",
            "priority_order": '[{"provider_id":"provider-primary","priority":1}]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-traffic-mirroring"},
    )
    assert configured.status_code == 200

    saved_mirroring = client.put(
        f"/gateway/routes/{route_policy_id}/traffic-mirroring",
        json={
            "tenant_id": "tenant-traffic-mirroring",
            "environment": "dev",
            "enabled": True,
            "mirror_targets": '[{"provider_id":"mirror-shadow-a","sample_percent":100,"mode":"shadow"}]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-traffic-mirroring"},
    )
    assert saved_mirroring.status_code == 200

    read_mirroring = client.get(
        f"/gateway/routes/{route_policy_id}/traffic-mirroring",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-traffic-mirroring"},
    )
    assert read_mirroring.status_code == 200
    assert "mirror-shadow-a" in read_mirroring.json()["mirror_targets"]

    executed = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-traffic-mirroring",
            "environment": "dev",
            "agent_id": "agent-traffic-mirroring",
            "session_id": "sess-traffic-mirroring",
            "owner_scope": "team:platform",
            "simulate_fail_provider_ids": "[]",
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-traffic-mirroring"},
    )
    assert executed.status_code == 200
    payload = executed.json()
    assert payload["final_outcome"] == "success"
    attempted = json.loads(payload["attempted_providers"])
    assert any(row.get("outcome") == "mirrored_simulated" and row.get("provider_id") == "mirror-shadow-a" for row in attempted)


def test_gateway_route_traffic_mirroring_analytics_and_experiment_report():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "traffic-mirroring-analytics-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-traffic-mirroring-analytics"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-traffic-mirroring-analytics",
            "environment": "dev",
            "priority_order": '[{"provider_id":"provider-primary","priority":1}]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-traffic-mirroring-analytics"},
    )
    assert configured.status_code == 200

    saved_mirroring = client.put(
        f"/gateway/routes/{route_policy_id}/traffic-mirroring",
        json={
            "tenant_id": "tenant-traffic-mirroring-analytics",
            "environment": "dev",
            "enabled": True,
            "mirror_targets": '[{"provider_id":"mirror-observe-a","sample_percent":100,"mode":"observe"}]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-traffic-mirroring-analytics"},
    )
    assert saved_mirroring.status_code == 200

    for region in ["us-east-1", "eu-west-1"]:
        executed = client.post(
            f"/gateway/routes/{route_policy_id}/execute-fallback",
            json={
                "tenant_id": "tenant-traffic-mirroring-analytics",
                "environment": "dev",
                "agent_id": "agent-traffic-mirroring-analytics",
                "requested_region": region,
                "session_id": f"sess-traffic-mirroring-analytics-{region}",
                "owner_scope": "team:platform",
                "simulate_fail_provider_ids": "[]",
            },
            headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-traffic-mirroring-analytics"},
        )
        assert executed.status_code == 200
        assert executed.json()["final_outcome"] == "success"

    summary = client.get(
        f"/gateway/routes/{route_policy_id}/traffic-mirroring/analytics-summary?environment=dev&hours=24",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-traffic-mirroring-analytics"},
    )
    assert summary.status_code == 200
    summary_payload = summary.json()
    assert summary_payload["total_mirror_events"] >= 2
    assert summary_payload["mirrored_request_count"] >= 2
    assert any(item["key"] == "mirror-observe-a" for item in summary_payload["top_mirror_providers"])
    assert any(
        item["primary_outcome"] == "success" and item["mirror_outcome"] == "mirrored_simulated"
        for item in summary_payload["outcome_comparison"]
    )

    report = client.get(
        f"/gateway/routes/{route_policy_id}/traffic-mirroring/experiment-report?environment=dev&hours=24&limit=10&offset=0",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-traffic-mirroring-analytics"},
    )
    assert report.status_code == 200
    report_payload = report.json()
    assert report_payload["total_rows"] >= 2
    assert len(report_payload["rows"]) >= 2
    first_row = report_payload["rows"][0]
    assert first_row["primary_provider_id"] == "provider-primary"
    assert first_row["mirror_provider_id"] == "mirror-observe-a"


def test_gateway_route_canary_rollout_lifecycle():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "canary-rollout-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-canary-rollout"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    upsert = client.put(
        f"/gateway/routes/{route_policy_id}/canary-rollout",
        json={
            "tenant_id": "tenant-canary-rollout",
            "environment": "dev",
            "baseline_provider_id": "provider-primary",
            "canary_targets": '[{"provider_id":"provider-canary-a","traffic_percent":20}]',
            "cohort_request_tags": '["billing.batch-01"]',
            "cohort_owner_scopes": '["team:platform"]',
            "gate_min_requests": 2,
            "gate_max_failure_rate": 0.5,
            "enabled": True,
            "notes": "initial canary",
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-canary-rollout"},
    )
    assert upsert.status_code == 200
    upsert_payload = upsert.json()
    assert upsert_payload["status"] == "active"
    assert "provider-canary-a" in upsert_payload["canary_targets"]
    assert "billing.batch-01" in upsert_payload["cohort_request_tags"]
    assert upsert_payload["gate_min_requests"] == 2

    read = client.get(
        f"/gateway/routes/{route_policy_id}/canary-rollout",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-canary-rollout"},
    )
    assert read.status_code == 200
    assert read.json()["baseline_provider_id"] == "provider-primary"
    assert "team:platform" in read.json()["cohort_owner_scopes"]

    stopped = client.post(
        f"/gateway/routes/{route_policy_id}/canary-rollout/stop",
        json={"notes": "stop due to quality drift"},
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-canary-rollout"},
    )
    assert stopped.status_code == 200
    assert stopped.json()["status"] == "stopped"
    assert stopped.json()["enabled"] is False

    promoted = client.post(
        f"/gateway/routes/{route_policy_id}/canary-rollout/promote",
        json={"notes": "promote after successful validation"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-canary-rollout"},
    )
    assert promoted.status_code == 200
    assert promoted.json()["status"] == "promoted"
    assert promoted.json()["enabled"] is False


def test_gateway_route_canary_rollout_prod_requires_dual_approval():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "prod-canary-rollout-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-prod-canary-rollout"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    denied = client.put(
        f"/gateway/routes/{route_policy_id}/canary-rollout",
        json={
            "tenant_id": "tenant-prod-canary-rollout",
            "environment": "prod",
            "baseline_provider_id": "provider-primary",
            "canary_targets": '[{"provider_id":"provider-canary-a","traffic_percent":10}]',
            "enabled": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-prod-canary-rollout"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"


def test_gateway_route_canary_rollout_auto_failure_gate_stops_rollout():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "canary-auto-stop-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-canary-auto-stop"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-canary-auto-stop",
            "environment": "dev",
            "priority_order": '[{"provider_id":"provider-primary","priority":1}]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-canary-auto-stop"},
    )
    assert configured.status_code == 200

    saved = client.put(
        f"/gateway/routes/{route_policy_id}/canary-rollout",
        json={
            "tenant_id": "tenant-canary-auto-stop",
            "environment": "dev",
            "request_tag": "billing.batch-01",
            "baseline_provider_id": "provider-primary",
            "canary_targets": '[{"provider_id":"provider-canary-a","traffic_percent":100}]',
            "cohort_request_tags": '["billing.batch-01"]',
            "cohort_owner_scopes": '["team:platform"]',
            "gate_min_requests": 1,
            "gate_max_failure_rate": 0.0,
            "enabled": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-canary-auto-stop"},
    )
    assert saved.status_code == 200

    executed = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-canary-auto-stop",
            "environment": "dev",
            "agent_id": "agent-canary-auto-stop",
            "request_tag": "billing.batch-01",
            "session_id": "sess-canary-auto-stop",
            "owner_scope": "team:platform",
            "simulate_fail_provider_ids": '["provider-canary-a"]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-canary-auto-stop"},
    )
    assert executed.status_code == 200

    read = client.get(
        f"/gateway/routes/{route_policy_id}/canary-rollout?request_tag=billing.batch-01",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-canary-auto-stop"},
    )
    assert read.status_code == 200
    payload = read.json()
    assert payload["enabled"] is False
    assert payload["status"] == "auto_stopped_failure_gate"
    assert payload["gate_last_decision"] == "auto_stop"


def test_gateway_route_pre_call_and_mirroring_prod_require_dual_approval():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "prod-pre-call-mirror-guardrails-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-prod-pre-call-mirror"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    denied_pre_call = client.put(
        f"/gateway/routes/{route_policy_id}/pre-call-filters",
        json={
            "tenant_id": "tenant-prod-pre-call-mirror",
            "environment": "prod",
            "allowed_regions": '["us-east-1"]',
            "enforce": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-prod-pre-call-mirror"},
    )
    assert denied_pre_call.status_code == 403
    assert denied_pre_call.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    denied_mirroring = client.put(
        f"/gateway/routes/{route_policy_id}/traffic-mirroring",
        json={
            "tenant_id": "tenant-prod-pre-call-mirror",
            "environment": "prod",
            "enabled": True,
            "mirror_targets": '[{"provider_id":"mirror-shadow-a","sample_percent":100,"mode":"shadow"}]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-prod-pre-call-mirror"},
    )
    assert denied_mirroring.status_code == 403
    assert denied_mirroring.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"


def test_gateway_route_optimize_non_prod_does_not_require_dual_approval():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "non-prod-optimize-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-non-prod-opt"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    optimize = client.post(
        f"/gateway/routes/{route_policy_id}/optimize",
        json={"optimize_for": "latency", "environment": "dev"},
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-non-prod-opt"},
    )
    assert optimize.status_code == 200
    assert optimize.json()["updated"] in {True, False}


def test_gateway_prod_dual_approval_denials_emit_deny_audits():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "prod-deny-audit-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-deny-audit"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    denied_optimize = client.post(
        f"/gateway/routes/{route_policy_id}/optimize",
        json={"optimize_for": "cost", "environment": "prod"},
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-deny-audit"},
    )
    assert denied_optimize.status_code == 403
    assert denied_optimize.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    optimize_deny_events = client.get(
        f"/audit/events?action_type=gateway.route.optimize&resource_type=route_policy&resource_id={route_policy_id}&decision_outcome=deny&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-deny-audit"},
    )
    assert optimize_deny_events.status_code == 200
    assert any(event["actor_id"] == "aiops-deny-audit" for event in optimize_deny_events.json())

    key = client.post(
        "/keys",
        json={
            "owner_scope_type": "team",
            "owner_scope_id": "deny-audit-team",
            "allowed_endpoint_families": '["responses"]',
            "allowed_models": '["gpt-test"]',
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-deny-audit"},
    )
    assert key.status_code == 200
    key_id = key.json()["key_id"]

    denied_rotate = client.post(
        f"/keys/{key_id}/rotate?environment=prod",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-deny-audit"},
    )
    assert denied_rotate.status_code == 403
    assert denied_rotate.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    rotate_deny_events = client.get(
        f"/audit/events?action_type=gateway.key.rotate&resource_type=virtual_key&resource_id={key_id}&decision_outcome=deny&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-deny-audit"},
    )
    assert rotate_deny_events.status_code == 200
    assert any(event["actor_id"] == "admin-deny-audit" for event in rotate_deny_events.json())


def test_gateway_route_provider_priority_requires_dual_approval_in_prod():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "priority-prod-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-priority-prod"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    denied = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-priority-prod",
            "environment": "prod",
            "priority_order": '[{"provider_id":"aws-bedrock-1","priority":1}]',
            "global_timeout_ms": 5000,
            "max_fallback_hops": 1,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-priority-prod"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    deny_events = client.get(
        f"/audit/events?action_type=gateway.route.provider_priority.update&resource_type=route_policy&resource_id={route_policy_id}&decision_outcome=deny&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-priority-prod"},
    )
    assert deny_events.status_code == 200
    assert any(event["actor_id"] == "aiops-priority-prod" for event in deny_events.json())


def test_gateway_route_provider_priority_update_and_read_flow():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "priority-read-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-priority-read"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    update = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-priority-read",
            "environment": "prod",
            "priority_order": '[{"provider_id":"azure-openai-1","priority":2},{"provider_id":"aws-bedrock-1","priority":1}]',
            "global_timeout_ms": 4800,
            "max_fallback_hops": 2,
        },
        headers={
            "X-Actor-Role": "AI Ops Approver",
            "X-Actor-Id": "aiops-priority-read",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-priority-read",
        },
    )
    assert update.status_code == 200
    assert update.json()["updated"] is True

    fetched = client.get(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-priority-read"},
    )
    assert fetched.status_code == 200
    payload = fetched.json()
    assert payload["tenant_id"] == "tenant-priority-read"
    assert payload["environment"] == "prod"
    assert payload["global_timeout_ms"] == 4800
    assert payload["max_fallback_hops"] == 2
    assert payload["priority_order"] == '[{"provider_id":"aws-bedrock-1","priority":1},{"provider_id":"azure-openai-1","priority":2}]'


def test_gateway_route_provider_priority_tag_override_readback_flow():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "priority-tag-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-priority-tag"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    default_update = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-priority-tag",
            "environment": "dev",
            "priority_order": '[{"provider_id":"aws-default","priority":1},{"provider_id":"azure-default","priority":2}]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-priority-tag-default"},
    )
    assert default_update.status_code == 200

    tagged_update = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-priority-tag",
            "environment": "dev",
            "request_tag": "billing.batch-01",
            "priority_order": '[{"provider_id":"openai-tagged","priority":1},{"provider_id":"aws-default","priority":2}]',
            "max_fallback_hops": 1,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-priority-tag-tagged"},
    )
    assert tagged_update.status_code == 200
    assert tagged_update.json()["request_tag"] == "billing.batch-01"

    default_fetch = client.get(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-priority-tag"},
    )
    assert default_fetch.status_code == 200
    assert default_fetch.json()["request_tag"] is None
    assert default_fetch.json()["priority_order"] == '[{"provider_id":"aws-default","priority":1},{"provider_id":"azure-default","priority":2}]'

    tagged_fetch = client.get(
        f"/gateway/routes/{route_policy_id}/providers/priority?request_tag=billing.batch-01",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-priority-tag"},
    )
    assert tagged_fetch.status_code == 200
    assert tagged_fetch.json()["request_tag"] == "billing.batch-01"
    assert tagged_fetch.json()["priority_order"] == '[{"provider_id":"openai-tagged","priority":1},{"provider_id":"aws-default","priority":2}]'


def test_gateway_route_provider_priority_rejects_non_contiguous_priorities():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "priority-invalid-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-priority-invalid"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    invalid = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-priority-invalid",
            "environment": "dev",
            "priority_order": '[{"provider_id":"aws-bedrock-1","priority":1},{"provider_id":"azure-openai-1","priority":3}]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-priority-invalid"},
    )
    assert invalid.status_code == 422
    assert invalid.json()["detail"] == "priority_order priorities must be contiguous starting from 1"


def test_gateway_route_simulate_fallback_selects_next_priority_provider():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "simulate-fallback-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-simulate-fallback"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-simulate",
            "environment": "dev",
            "priority_order": '[{"provider_id":"aws-primary","priority":1},{"provider_id":"azure-secondary","priority":2}]',
            "global_timeout_ms": 4200,
            "max_fallback_hops": 2,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-simulate-fallback"},
    )
    assert configured.status_code == 200

    simulated = client.post(
        f"/gateway/routes/{route_policy_id}/simulate-fallback",
        json={"tenant_id": "tenant-simulate", "environment": "dev", "simulate_fail_provider_ids": '["aws-primary"]'},
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-simulate-fallback"},
    )
    assert simulated.status_code == 200
    payload = simulated.json()
    assert payload["tenant_id"] == "tenant-simulate"
    assert payload["selected_provider_id"] == "azure-secondary"
    assert payload["fallback_hops_used"] == 1


def test_gateway_route_simulate_fallback_least_busy_prefers_lower_inflight_provider():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "simulate-least-busy-route", "load_balancing_strategy": "least_busy"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-simulate-least-busy"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-least-busy",
            "environment": "dev",
            "priority_order": '[{"provider_id":"provider-busy","priority":1},{"provider_id":"provider-idle","priority":2}]',
            "health_check_enabled": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-simulate-least-busy"},
    )
    assert configured.status_code == 200

    health = client.put(
        f"/gateway/routes/{route_policy_id}/providers/health",
        json={
            "entries": [
                {
                    "provider_id": "provider-busy",
                    "status": "healthy",
                    "latency_ms": 80,
                    "inflight_requests": 42,
                    "rate_limit_remaining_percent": 10,
                },
                {
                    "provider_id": "provider-idle",
                    "status": "healthy",
                    "latency_ms": 120,
                    "inflight_requests": 2,
                    "rate_limit_remaining_percent": 70,
                },
            ]
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-simulate-least-busy"},
    )
    assert health.status_code == 200

    simulated = client.post(
        f"/gateway/routes/{route_policy_id}/simulate-fallback",
        json={"tenant_id": "tenant-least-busy", "environment": "dev", "simulate_fail_provider_ids": "[]"},
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-simulate-least-busy"},
    )
    assert simulated.status_code == 200
    payload = simulated.json()
    assert payload["selected_provider_id"] == "provider-idle"


def test_gateway_route_grouped_weighted_failover_simulate_and_execute():
    route = client.post(
        "/gateway/routes",
        json={
            "route_name": "grouped-weighted-failover-route",
            "fallback_policy": json.dumps(
                {
                    "group_selection_strategy": "weighted_failover",
                    "routing_groups": [
                        {
                            "group_id": "group-primary",
                            "tenant_id": "tenant-grouped",
                            "selection_strategy": "weighted",
                            "failover_weight": 100,
                            "priority_order": [{"provider_id": "provider-primary", "priority": 1}],
                        },
                        {
                            "group_id": "group-secondary",
                            "tenant_id": "tenant-grouped",
                            "selection_strategy": "weighted",
                            "failover_weight": 50,
                            "priority_order": [{"provider_id": "provider-secondary", "priority": 1}],
                        },
                    ],
                }
            ),
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-grouped-weighted"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    simulated = client.post(
        f"/gateway/routes/{route_policy_id}/simulate-fallback",
        json={
            "tenant_id": "tenant-grouped",
            "environment": "dev",
            "simulate_fail_provider_ids": '["provider-primary"]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-grouped-weighted"},
    )
    assert simulated.status_code == 200
    simulated_payload = simulated.json()
    assert simulated_payload["selected_group_id"] == "group-secondary"
    assert simulated_payload["selected_provider_id"] == "provider-secondary"

    executed = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-grouped",
            "environment": "dev",
            "agent_id": "agent-grouped",
            "session_id": "sess-grouped",
            "owner_scope": "team:platform",
            "endpoint_family": "responses",
            "input_tokens": 64,
            "output_tokens": 32,
            "simulate_fail_provider_ids": '["provider-primary"]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-grouped-weighted"},
    )
    assert executed.status_code == 200
    executed_payload = executed.json()
    assert executed_payload["selected_group_id"] == "group-secondary"
    assert executed_payload["selected_provider_id"] == "provider-secondary"


def test_gateway_route_execute_fallback_uses_request_tag_priority_override():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "execute-tag-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-execute-tag"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    default_priority = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-execute-tag",
            "environment": "dev",
            "priority_order": '[{"provider_id":"aws-default","priority":1},{"provider_id":"openai-tagged","priority":2}]',
            "max_fallback_hops": 2,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-execute-tag-default"},
    )
    assert default_priority.status_code == 200

    tagged_priority = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-execute-tag",
            "environment": "dev",
            "request_tag": "billing.batch-01",
            "priority_order": '[{"provider_id":"openai-tagged","priority":1},{"provider_id":"aws-default","priority":2}]',
            "max_fallback_hops": 2,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-execute-tag-tagged"},
    )
    assert tagged_priority.status_code == 200

    executed = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-execute-tag",
            "environment": "dev",
            "agent_id": "agent-execute-tag",
            "request_tag": "billing.batch-01",
            "session_id": "sess-execute-tag",
            "owner_scope": "team:platform",
            "endpoint_family": "responses",
            "input_tokens": 64,
            "output_tokens": 32,
            "simulate_fail_provider_ids": "[]",
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-execute-tag"},
    )
    assert executed.status_code == 200
    payload = executed.json()
    assert payload["selected_provider_id"] == "openai-tagged"
    assert payload["final_outcome"] == "success"
    assert payload["provider_attempts"] == 1
    assert payload["final_outcome"] == "success"


def test_gateway_route_fallback_management_endpoints_roundtrip():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "fallback-endpoint-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-fallback-endpoint"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    updated = client.put(
        f"/gateway/routes/{route_policy_id}/fallbacks",
        json={
            "tenant_id": "tenant-fallback-endpoint",
            "environment": "dev",
            "request_tag": "ops.batch",
            "priority_order": '[{"provider_id":"aws-primary","priority":1},{"provider_id":"azure-secondary","priority":2}]',
            "global_timeout_ms": 5000,
            "max_fallback_hops": 2,
            "health_check_enabled": True,
            "budget_limit_cents": 2000,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-fallback-endpoint"},
    )
    assert updated.status_code == 200

    fetched = client.get(
        f"/gateway/routes/{route_policy_id}/fallbacks?request_tag=ops.batch",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-fallback-endpoint"},
    )
    assert fetched.status_code == 200
    payload = fetched.json()
    assert payload["request_tag"] == "ops.batch"
    assert payload["health_check_enabled"] is True
    assert payload["budget_limit_cents"] == 2000


def test_gateway_route_execute_fallback_skips_unhealthy_provider_when_health_checks_enabled():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "health-check-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-health-check-route"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-health-check",
            "environment": "dev",
            "priority_order": '[{"provider_id":"aws-primary","priority":1},{"provider_id":"azure-secondary","priority":2}]',
            "health_check_enabled": True,
            "max_fallback_hops": 2,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-health-check-route"},
    )
    assert configured.status_code == 200

    provider_health = client.put(
        f"/gateway/routes/{route_policy_id}/providers/health",
        json={
            "entries": [
                {"provider_id": "aws-primary", "status": "unhealthy", "latency_ms": 5000},
                {"provider_id": "azure-secondary", "status": "healthy", "latency_ms": 120},
            ]
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-health-check-route"},
    )
    assert provider_health.status_code == 200

    executed = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-health-check",
            "environment": "dev",
            "agent_id": "agent-health-check",
            "session_id": "sess-health-check",
            "owner_scope": "team:platform",
            "endpoint_family": "responses",
            "input_tokens": 64,
            "output_tokens": 32,
            "simulate_fail_provider_ids": "[]",
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-health-check-route"},
    )
    assert executed.status_code == 200
    payload = executed.json()
    assert payload["selected_provider_id"] == "azure-secondary"
    assert payload["provider_attempts"] == 2




def test_gateway_route_execute_fallback_applies_error_type_cooldown_policy():
    route = client.post(
        "/gateway/routes",
        json={
            "route_name": "execute-retry-cooldown-route",
            "retry_policy": json.dumps(
                {
                    "error_type_policies": {
                        "failed_simulated": {"cooldown_seconds": 600, "max_retries": 5}
                    }
                }
            ),
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-execute-retry-cooldown"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-retry-cooldown",
            "environment": "dev",
            "priority_order": '[{"provider_id":"provider-primary","priority":1},{"provider_id":"provider-secondary","priority":2}]',
            "max_fallback_hops": 2,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-execute-retry-cooldown"},
    )
    assert configured.status_code == 200

    first = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-retry-cooldown",
            "environment": "dev",
            "agent_id": "agent-retry-cooldown",
            "session_id": "sess-retry-cooldown-1",
            "owner_scope": "team:platform",
            "simulate_fail_provider_ids": '["provider-primary"]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-execute-retry-cooldown"},
    )
    assert first.status_code == 200
    first_payload = first.json()
    assert first_payload["selected_provider_id"] == "provider-secondary"

    second = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-retry-cooldown",
            "environment": "dev",
            "agent_id": "agent-retry-cooldown",
            "session_id": "sess-retry-cooldown-2",
            "owner_scope": "team:platform",
            "simulate_fail_provider_ids": "[]",
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-execute-retry-cooldown"},
    )
    assert second.status_code == 200
    second_payload = second.json()
    assert second_payload["selected_provider_id"] == "provider-secondary"
    assert "skipped_cooldown" in second_payload["attempted_providers"]


def test_gateway_route_execute_fallback_enforces_max_retries_by_error_type():
    route = client.post(
        "/gateway/routes",
        json={
            "route_name": "execute-retry-limit-route",
            "retry_policy": json.dumps(
                {
                    "error_type_policies": {
                        "failed_simulated": {"max_retries": 0, "cooldown_seconds": 0}
                    }
                }
            ),
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-execute-retry-limit"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-retry-limit",
            "environment": "dev",
            "priority_order": '[{"provider_id":"provider-primary","priority":1},{"provider_id":"provider-secondary","priority":2}]',
            "max_fallback_hops": 2,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-execute-retry-limit"},
    )
    assert configured.status_code == 200

    executed = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-retry-limit",
            "environment": "dev",
            "agent_id": "agent-retry-limit",
            "session_id": "sess-retry-limit",
            "owner_scope": "team:platform",
            "simulate_fail_provider_ids": '["provider-primary"]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-execute-retry-limit"},
    )
    assert executed.status_code == 200
    payload = executed.json()
    assert payload["selected_provider_id"] is None
    assert payload["final_outcome"] == "failed_retry_policy"
    assert "retry_policy_blocked" in payload["attempted_providers"]
def test_gateway_route_execute_fallback_respects_budget_limit():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "budget-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-budget-route"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-budget-route",
            "environment": "dev",
            "priority_order": '[{"provider_id":"aws-primary","priority":1}]',
            "budget_limit_cents": 1,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-budget-route"},
    )
    assert configured.status_code == 200

    executed = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-budget-route",
            "environment": "dev",
            "agent_id": "agent-budget-route",
            "session_id": "sess-budget-route",
            "owner_scope": "team:platform",
            "endpoint_family": "responses",
            "input_tokens": 5000,
            "output_tokens": 5000,
            "simulate_fail_provider_ids": "[]",
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-budget-route"},
    )
    assert executed.status_code == 200
    payload = executed.json()
    assert payload["selected_provider_id"] is None
    assert payload["final_outcome"] == "failed_budget_limit"


def test_gateway_route_simulate_fallback_returns_failed_when_all_candidates_fail():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "simulate-fallback-all-fail-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-simulate-fallback-all-fail"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-simulate-all-fail",
            "environment": "dev",
            "priority_order": '[{"provider_id":"aws-primary","priority":1},{"provider_id":"azure-secondary","priority":2}]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-simulate-fallback-all-fail"},
    )
    assert configured.status_code == 200

    simulated = client.post(
        f"/gateway/routes/{route_policy_id}/simulate-fallback",
        json={
            "tenant_id": "tenant-simulate-all-fail",
            "environment": "dev",
            "simulate_fail_provider_ids": '["aws-primary","azure-secondary"]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-simulate-fallback-all-fail"},
    )
    assert simulated.status_code == 200
    payload = simulated.json()
    assert payload["selected_provider_id"] is None
    assert payload["fallback_hops_used"] == 2
    assert payload["provider_attempts"] == 2
    assert payload["final_outcome"] == "failed"


def test_gateway_route_simulate_fallback_requires_priority_configuration():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "simulate-fallback-no-priority-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-simulate-fallback-no-priority"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    simulated = client.post(
        f"/gateway/routes/{route_policy_id}/simulate-fallback",
        json={"tenant_id": "tenant-simulate-none", "environment": "dev", "simulate_fail_provider_ids": "[]"},
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-simulate-fallback-no-priority"},
    )
    assert simulated.status_code == 422
    assert simulated.json()["detail"] == "provider priority policy is not configured for this route"


def test_gateway_route_simulate_fallback_rejects_tenant_mismatch():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "simulate-fallback-tenant-mismatch-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-simulate-fallback-tenant"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-a",
            "environment": "dev",
            "priority_order": '[{"provider_id":"aws-primary","priority":1}]',
            "global_timeout_ms": 4500,
            "max_fallback_hops": 1,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-simulate-fallback-tenant"},
    )
    assert configured.status_code == 200

    mismatch = client.post(
        f"/gateway/routes/{route_policy_id}/simulate-fallback",
        json={"tenant_id": "tenant-b", "environment": "dev", "simulate_fail_provider_ids": "[]"},
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-simulate-fallback-tenant"},
    )
    assert mismatch.status_code == 403
    assert mismatch.json()["detail"] == "Tenant scope mismatch for route fallback simulation"


def test_gateway_route_execute_fallback_records_per_hop_telemetry_and_cost_events():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "execute-fallback-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-exec-fallback"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-exec",
            "environment": "dev",
            "priority_order": '[{"provider_id":"aws-primary","model_name":"gpt-4o-mini","priority":1},{"provider_id":"azure-secondary","model_name":"gpt-4o","priority":2}]',
            "max_fallback_hops": 2,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-exec-fallback"},
    )
    assert configured.status_code == 200

    executed = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-exec",
            "environment": "dev",
            "agent_id": "agent-exec-1",
            "session_id": "sess-exec-1",
            "owner_scope": "team:platform",
            "endpoint_family": "responses",
            "input_tokens": 120,
            "output_tokens": 80,
            "simulate_fail_provider_ids": '["aws-primary"]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-exec-fallback"},
    )
    assert executed.status_code == 200
    payload = executed.json()
    assert payload["selected_provider_id"] == "azure-secondary"
    assert payload["provider_attempts"] == 2
    assert payload["fallback_hops_used"] == 1
    assert payload["final_outcome"] == "success"
    assert payload["total_latency_ms"] > 0
    assert payload["total_estimated_cost_cents"] > 0

    from app.database import SessionLocal

    db = SessionLocal()
    try:
        events = db.query(CostEvent).filter_by(request_id=payload["request_id"]).all()
        assert len(events) == 2
        assert {event.model_name for event in events} == {"gpt-4o-mini", "gpt-4o"}
    finally:
        db.close()


def test_gateway_route_execute_fallback_rejects_tenant_mismatch():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "execute-fallback-tenant-mismatch-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-exec-tenant"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-a",
            "environment": "dev",
            "priority_order": '[{"provider_id":"aws-primary","priority":1}]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-exec-tenant"},
    )
    assert configured.status_code == 200

    mismatch = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-b",
            "environment": "dev",
            "agent_id": "agent-exec-tenant",
            "session_id": "sess-exec-tenant",
            "owner_scope": "team:platform",
            "simulate_fail_provider_ids": "[]",
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-exec-tenant"},
    )
    assert mismatch.status_code == 403
    assert mismatch.json()["detail"] == "Tenant scope mismatch for route fallback execution"


def test_gateway_route_execute_fallback_respects_max_fallback_hops_limit():
    route = client.post(
        "/gateway/routes",
        json={"route_name": "execute-fallback-hop-limit-route"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-exec-hop-limit"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    configured = client.post(
        f"/gateway/routes/{route_policy_id}/providers/priority",
        json={
            "tenant_id": "tenant-hop-limit",
            "environment": "dev",
            "priority_order": '[{"provider_id":"p1","priority":1},{"provider_id":"p2","priority":2},{"provider_id":"p3","priority":3}]',
            "max_fallback_hops": 1,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-exec-hop-limit"},
    )
    assert configured.status_code == 200

    executed = client.post(
        f"/gateway/routes/{route_policy_id}/execute-fallback",
        json={
            "tenant_id": "tenant-hop-limit",
            "environment": "dev",
            "agent_id": "agent-hop-limit",
            "session_id": "sess-hop-limit",
            "owner_scope": "team:platform",
            "simulate_fail_provider_ids": '["p1","p2","p3"]',
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-exec-hop-limit"},
    )
    assert executed.status_code == 200
    payload = executed.json()
    assert payload["provider_attempts"] == 2
    assert payload["selected_provider_id"] is None
    assert payload["final_outcome"] == "failed_hop_limit"


def test_rotate_via_secret_provider_prod_dual_approval_and_audit():
    key_created = client.post(
        "/keys",
        json={
            "owner_scope_type": "team",
            "owner_scope_id": "secret-rotate-team",
            "allowed_endpoint_families": '["responses"]',
            "allowed_models": '["gpt-test"]',
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-secret-rotate"},
    )
    assert key_created.status_code == 200
    key_id = key_created.json()["key_id"]

    denied = client.post(
        f"/keys/{key_id}/rotate-via-secret-provider?environment=prod",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-secret-rotate", "X-MFA-Verified": "true"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    deny_events = client.get(
        f"/audit/events?action_type=gateway.key.rotate_via_secret_provider&resource_type=virtual_key&resource_id={key_id}&decision_outcome=deny&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-secret-rotate"},
    )
    assert deny_events.status_code == 200
    assert any(evt["actor_id"] == "admin-secret-rotate" for evt in deny_events.json())

    allowed = client.post(
        f"/keys/{key_id}/rotate-via-secret-provider?environment=prod",
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-secret-rotate",
            "X-MFA-Verified": "true",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-secret-rotate",
        },
    )
    assert allowed.status_code == 200
    assert allowed.json()["rotation_status"] == "delegated_to_secret_provider"
    assert allowed.json()["dual_approval_required"] is True

    allow_events = client.get(
        f"/audit/events?action_type=gateway.key.rotate_via_secret_provider&resource_type=virtual_key&resource_id={key_id}&decision_outcome=allow&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-secret-rotate"},
    )
    assert allow_events.status_code == 200
    assert any(evt["actor_id"] == "admin-secret-rotate" for evt in allow_events.json())


def test_rotate_via_secret_provider_non_prod_no_dual_approval():
    key_created = client.post(
        "/keys",
        json={
            "owner_scope_type": "team",
            "owner_scope_id": "secret-rotate-dev-team",
            "allowed_endpoint_families": '["responses"]',
            "allowed_models": '["gpt-test"]',
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-secret-rotate-dev"},
    )
    assert key_created.status_code == 200
    key_id = key_created.json()["key_id"]

    allowed = client.post(
        f"/keys/{key_id}/rotate-via-secret-provider?environment=dev",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-secret-rotate-dev", "X-MFA-Verified": "true"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["dual_approval_required"] is False


def test_gateway_read_and_debug_endpoints_enforce_roles():
    key_created = client.post(
        "/keys",
        json={
            "owner_scope_type": "team",
            "owner_scope_id": "ops",
            "allowed_endpoint_families": '["responses"]',
            "allowed_models": '["gpt-test"]',
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-gw-authz"},
    )
    assert key_created.status_code == 200
    key_id = key_created.json()["key_id"]

    key_usage_denied = client.get(
        f"/keys/{key_id}/usage",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-gw-authz"},
    )
    assert key_usage_denied.status_code == 403
    assert key_usage_denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    key_usage_allowed = client.get(
        f"/keys/{key_id}/usage",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-gw-authz"},
    )
    assert key_usage_allowed.status_code == 200
    assert key_usage_allowed.json()["key_id"] == key_id

    compat_denied = client.get(
        "/gateway/endpoints/compatibility",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-gw-authz"},
    )
    assert compat_denied.status_code == 403
    assert compat_denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    compat_allowed = client.get(
        "/gateway/endpoints/compatibility",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-gw-authz"},
    )
    assert compat_allowed.status_code == 200
    assert compat_allowed.json()["status"] == "pass"

    debug_denied = client.post(
        "/gateway/debug/transform-request",
        json={"model": "gpt-test", "input": "hello"},
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-gw-authz"},
    )
    assert debug_denied.status_code == 403
    assert debug_denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    debug_allowed = client.post(
        "/gateway/debug/transform-request",
        json={"model": "gpt-test", "input": "hello"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-gw-authz"},
    )
    assert debug_allowed.status_code == 200
    assert debug_allowed.json()["status"] == "ok"


def test_gateway_authz_explain_returns_decision_trace_and_dual_approval_requirements():
    denied = client.post(
        "/gateway/authz/explain",
        json={
            "actor_role": "AI Ops Approver",
            "actor_id": "aiops-explain",
            "action": "gateway.route.execute_fallback",
            "environment": "prod",
            "resource_type": "route_policy",
            "resource_id": "route-prod-a",
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-gw-explain"},
    )
    assert denied.status_code == 200
    denied_payload = denied.json()
    assert denied_payload["decision"] == "deny"
    assert denied_payload["requires_dual_approval"] is True
    assert denied_payload["decision_trace_id"] == "authz-gateway-explain-deny"
    assert "dual_approval_missing" in denied_payload["reasons"]

    allowed = client.post(
        "/gateway/authz/explain",
        json={
            "actor_role": "AI Ops Approver",
            "actor_id": "aiops-explain",
            "action": "gateway.route.execute_fallback",
            "environment": "prod",
            "resource_type": "route_policy",
            "resource_id": "route-prod-a",
            "approver_role": "Security Approver",
            "approver_id": "sec-explain",
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-gw-explain"},
    )
    assert allowed.status_code == 200
    allowed_payload = allowed.json()
    assert allowed_payload["decision"] == "allow"
    assert allowed_payload["requires_dual_approval"] is True
    assert allowed_payload["decision_trace_id"] == "authz-gateway-explain-allow"
    assert "dual_approval_present" in allowed_payload["reasons"]

    unknown_action = client.post(
        "/gateway/authz/explain",
        json={
            "actor_role": "Platform Admin",
            "actor_id": "admin-explain",
            "action": "gateway.unknown.action",
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-gw-explain"},
    )
    assert unknown_action.status_code == 200
    assert unknown_action.json()["decision"] == "warn"
    assert unknown_action.json()["decision_trace_id"] == "authz-gateway-explain-unknown-action"


def test_gateway_decision_trace_retrieve_returns_audit_evidence():
    created = client.post(
        "/v1/responses",
        json={
            "model": "gpt-4o-mini",
            "input": "trace me",
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-trace-retrieve"},
    )
    assert created.status_code == 200
    trace_id = created.json()["trace_id"]

    retrieved = client.get(
        f"/gateway/decision-traces/{trace_id}?limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-trace-retrieve"},
    )
    assert retrieved.status_code == 200
    payload = retrieved.json()
    assert payload["trace_id"] == trace_id
    assert payload["event_count"] >= 1
    assert "gateway.responses.create" in payload["actions"]
    assert payload["outcomes"].get("allow", 0) >= 1
    assert any(event["action_type"] == "gateway.responses.create" for event in payload["events"])


def test_gateway_decision_trace_retrieve_enforces_role_and_missing_trace_contracts():
    denied = client.get(
        "/gateway/decision-traces/trace-missing-role-check",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-trace-retrieve"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    missing = client.get(
        "/gateway/decision-traces/trace-does-not-exist",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-trace-retrieve"},
    )
    assert missing.status_code == 404
    assert missing.json()["detail"] == "Decision trace not found"


def test_gateway_entitlements_upsert_and_filter_roundtrip():
    entitlement_id = f"ent-{uuid4().hex[:10]}"

    save_response = client.put(
        f"/gateway/entitlements/{entitlement_id}",
        json={
            "action": "gateway.route.execute_fallback",
            "tenant_id": "tenant-platform",
            "environment": "dev",
            "route_policy_id": "route-policy-dev",
            "request_tag": "billing.batch-01",
            "allowed_roles": '["Platform Admin","AI Ops Approver"]',
            "enabled": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-ent-dev"},
    )
    assert save_response.status_code == 200
    payload = save_response.json()
    assert payload["entitlement_id"] == entitlement_id
    assert payload["action"] == "gateway.route.execute_fallback"
    assert json.loads(payload["allowed_roles"]) == ["AI Ops Approver", "Platform Admin"]

    filtered = client.get(
        "/gateway/entitlements?action=gateway.route.execute_fallback&tenant_id=tenant-platform&environment=dev&enabled=true",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-ent-dev"},
    )
    assert filtered.status_code == 200
    rows = filtered.json()
    assert any(row["entitlement_id"] == entitlement_id for row in rows)


def test_gateway_entitlements_prod_upsert_requires_dual_approval():
    entitlement_id = f"ent-{uuid4().hex[:10]}"
    payload = {
        "action": "gateway.route.update",
        "tenant_id": "tenant-prod",
        "environment": "prod",
        "allowed_roles": '["AI Ops Approver"]',
        "enabled": True,
    }

    denied = client.put(
        f"/gateway/entitlements/{entitlement_id}",
        json=payload,
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-ent-prod"},
    )
    assert denied.status_code == 403
    denied_payload = denied.json()
    assert denied_payload["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    allowed = client.put(
        f"/gateway/entitlements/{entitlement_id}",
        json=payload,
        headers={
            "X-Actor-Role": "AI Ops Approver",
            "X-Actor-Id": "aiops-ent-prod",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-ent-prod",
        },
    )
    assert allowed.status_code == 200
    assert allowed.json()["environment"] == "prod"


def test_gateway_nhi_inventory_sync_and_filters():
    from app.database import SessionLocal
    from app.models import SecretProviderConfig, WorkloadIdentityFederationProfile

    db = SessionLocal()
    try:
        workload_id = f"wif-{uuid4().hex[:10]}"
        secret_provider_id = f"sec-{uuid4().hex[:10]}"
        db.add(
            WorkloadIdentityFederationProfile(
                workload_identity_profile_id=workload_id,
                tenant_id="tenant-nhi-dev",
                provider_type="aws",
                audience="sts.amazonaws.com",
                role_arn_or_equivalent="arn:aws:iam::123456789012:role/nhi-test",
                session_duration_seconds=3600,
                status="active",
                last_token_exchange_at=datetime.utcnow() - timedelta(days=180),
            )
        )
        db.add(
            SecretProviderConfig(
                secret_provider_id=secret_provider_id,
                tenant_id="tenant-nhi-dev",
                provider_type="vault",
                provider_address="https://vault.local",
                auth_method="approle",
                role_or_mount="ai-gateway",
                secret_path_prefixes='["kv/gateway/"]',
                lease_ttl_seconds=3600,
                auto_renew_enabled=True,
                status="active",
                last_health_check_at=datetime.utcnow(),
            )
        )
        db.commit()
    finally:
        db.close()

    inventory = client.get(
        "/gateway/nhi/inventory?tenant_id=tenant-nhi-dev&max_credential_age_days=90",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-nhi-1"},
    )
    assert inventory.status_code == 200
    rows = inventory.json()
    assert any(row["source_id"] == workload_id for row in rows)
    assert any(row["source_id"] == secret_provider_id for row in rows)

    stale_only = client.get(
        "/gateway/nhi/inventory?tenant_id=tenant-nhi-dev&stale_only=true&max_credential_age_days=90",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-nhi-1"},
    )
    assert stale_only.status_code == 200
    stale_rows = stale_only.json()
    assert any(row["source_id"] == workload_id for row in stale_rows)


def test_gateway_nhi_hygiene_summary_reports_findings():
    response = client.get(
        "/gateway/nhi/hygiene?tenant_id=tenant-nhi-dev&max_credential_age_days=90",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-nhi-2"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total_identities"] >= 2
    assert payload["stale_credentials"] >= 1
    assert payload["missing_owner"] >= 1
    assert payload["high_risk_identities"] >= 1
    assert "unmanaged_prod_identities" in payload
    assert "prod_unmanaged_zero_ok" in payload
    assert isinstance(payload["prod_unmanaged_zero_ok"], bool)
    assert any(item["key"] == "workload_identity_profile" for item in payload["source_distribution"])


def test_gateway_access_review_campaign_create_and_read():
    entitlement_id = f"ent-review-{uuid4().hex[:10]}"
    ent = client.put(
        f"/gateway/entitlements/{entitlement_id}",
        json={
            "action": "gateway.route.update",
            "tenant_id": "tenant-review-dev",
            "environment": "dev",
            "allowed_roles": '["Platform Admin"]',
            "enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-review-seed"},
    )
    assert ent.status_code == 200

    created = client.post(
        "/gateway/access-reviews/campaigns",
        json={
            "campaign_name": "Gateway Entitlement Review",
            "tenant_id": "tenant-review-dev",
            "environment": "dev",
            "include_disabled": False,
            "reviewer_role": "Security Approver",
        },
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-review-1"},
    )
    assert created.status_code == 200
    payload = created.json()
    assert payload["campaign_id"].startswith("garc-")
    assert payload["total_items"] >= 1
    assert any(item["entitlement_id"] == entitlement_id for item in payload["items"])

    loaded = client.get(
        f"/gateway/access-reviews/campaigns/{payload['campaign_id']}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-review-1"},
    )
    assert loaded.status_code == 200
    assert loaded.json()["campaign_id"] == payload["campaign_id"]


def test_gateway_jit_request_create_and_approve_with_prod_dual_approval():
    entitlement_id = f"ent-jit-{uuid4().hex[:10]}"
    ent = client.put(
        f"/gateway/entitlements/{entitlement_id}",
        json={
            "action": "gateway.route.execute_fallback",
            "tenant_id": "tenant-jit",
            "environment": "prod",
            "allowed_roles": '["AI Ops Approver"]',
            "enabled": True,
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-jit-seed",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-jit-seed",
        },
    )
    assert ent.status_code == 200

    requested = client.post(
        "/gateway/jit-requests",
        json={
            "entitlement_id": entitlement_id,
            "environment": "prod",
            "justification": "Need temporary fallback execution in production for active incident.",
            "requested_duration_minutes": 45,
            "owner_scope_type": "user",
            "mint_virtual_key": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-jit-1"},
    )
    assert requested.status_code == 200
    request_id = requested.json()["request_id"]
    assert requested.json()["mint_virtual_key"] is True
    assert requested.json()["owner_scope_type"] == "user"

    denied_approval = client.post(
        f"/gateway/jit-requests/{request_id}/approve",
        json={"decision": "approve", "decision_reason": "approving"},
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-jit-1"},
    )
    assert denied_approval.status_code == 403
    assert denied_approval.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    approved = client.post(
        f"/gateway/jit-requests/{request_id}/approve",
        json={"decision": "approve", "decision_reason": "change window and incident evidence validated"},
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-jit-approve",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-jit-2",
        },
    )
    assert approved.status_code == 200
    approved_payload = approved.json()
    assert approved_payload["status"] == "approved"
    assert approved_payload["expires_at"] is not None
    assert approved_payload["issued_virtual_key_id"]
    assert approved_payload["issued_virtual_key_token"]
    key_id = approved_payload["issued_virtual_key_id"]
    bearer = approved_payload["issued_virtual_key_token"]

    key_get = client.get(
        f"/keys/{key_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-jit-key"},
    )
    assert key_get.status_code == 200
    key_payload = key_get.json()
    assert key_payload["jit_request_id"] == request_id
    assert key_payload["owner_scope_type"] == "user"
    assert key_payload["owner_scope_id"] == "aiops-jit-1"
    assert key_payload["status"] == "active"
    assert key_payload["expires_at"] is not None
    assert "key_hash" not in key_payload

    from app.database import SessionLocal
    from app.models import VirtualKey
    from app.routers.gateway import _enforce_virtual_key_expiry

    db = SessionLocal()
    try:
        key = db.query(VirtualKey).filter_by(key_id=key_id).first()
        assert key is not None
        from app.services.virtual_key_secrets import hash_virtual_key_token

        assert key.key_hash == hash_virtual_key_token(bearer)
        assert key.key_hash != bearer
        key.expires_at = datetime.utcnow() - timedelta(minutes=1)
        db.commit()
        db.refresh(key)
        try:
            _enforce_virtual_key_expiry(
                db,
                key=key,
                actor_id="aiops-jit-1",
                trace_id=f"trace-jit-expire-{request_id}",
            )
            assert False, "expected VIRTUAL_KEY_EXPIRED"
        except Exception as exc:
            assert getattr(exc, "status_code", None) == 403
            assert exc.detail["error_code"] == "VIRTUAL_KEY_EXPIRED"
        db.refresh(key)
        assert key.status == "blocked"
    finally:
        db.close()


def test_gateway_jit_approve_can_skip_virtual_key_mint():
    entitlement_id = f"ent-jit-skip-{uuid4().hex[:10]}"
    ent = client.put(
        f"/gateway/entitlements/{entitlement_id}",
        json={
            "action": "gateway.route.execute_fallback",
            "tenant_id": "tenant-jit-skip",
            "environment": "dev",
            "allowed_roles": '["AI Ops Approver"]',
            "enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-skip-seed"},
    )
    assert ent.status_code == 200

    requested = client.post(
        "/gateway/jit-requests",
        json={
            "entitlement_id": entitlement_id,
            "environment": "dev",
            "justification": "Elevation without credential mint for role-only access window.",
            "requested_duration_minutes": 30,
            "mint_virtual_key": False,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-jit-skip"},
    )
    assert requested.status_code == 200
    request_id = requested.json()["request_id"]

    approved = client.post(
        f"/gateway/jit-requests/{request_id}/approve",
        json={"decision": "approve", "decision_reason": "role elevation only"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-skip-approve"},
    )
    assert approved.status_code == 200
    payload = approved.json()
    assert payload["status"] == "approved"
    assert payload["issued_virtual_key_id"] is None
    assert payload["issued_virtual_key_token"] is None


def test_gateway_jit_deny_does_not_mint_virtual_key():
    entitlement_id = f"ent-jit-deny-{uuid4().hex[:10]}"
    ent = client.put(
        f"/gateway/entitlements/{entitlement_id}",
        json={
            "action": "gateway.route.execute_fallback",
            "tenant_id": "tenant-jit-deny",
            "environment": "dev",
            "allowed_roles": '["AI Ops Approver"]',
            "enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-deny-seed"},
    )
    assert ent.status_code == 200

    requested = client.post(
        "/gateway/jit-requests",
        json={
            "entitlement_id": entitlement_id,
            "environment": "dev",
            "justification": "Request that should be denied without issuing credentials.",
            "requested_duration_minutes": 20,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-jit-deny"},
    )
    assert requested.status_code == 200
    request_id = requested.json()["request_id"]

    denied = client.post(
        f"/gateway/jit-requests/{request_id}/approve",
        json={"decision": "deny", "decision_reason": "insufficient incident evidence"},
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-jit-deny"},
    )
    assert denied.status_code == 200
    payload = denied.json()
    assert payload["status"] == "denied"
    assert payload["issued_virtual_key_id"] is None
    assert payload["issued_virtual_key_token"] is None
    assert payload["expires_at"] is None


def test_gateway_jit_list_get_revoke_and_bearer_inference():
    entitlement_id = f"ent-jit-flow-{uuid4().hex[:10]}"
    ent = client.put(
        f"/gateway/entitlements/{entitlement_id}",
        json={
            "action": "gateway.route.execute_fallback",
            "tenant_id": "tenant-jit-flow",
            "environment": "dev",
            "model_name": "gpt-4o-mini",
            "allowed_roles": '["AI Ops Approver"]',
            "enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-flow-seed"},
    )
    assert ent.status_code == 200

    requested = client.post(
        "/gateway/jit-requests",
        json={
            "entitlement_id": entitlement_id,
            "environment": "dev",
            "justification": "Need short-lived credential for governed chat completions during incident.",
            "requested_duration_minutes": 60,
            "owner_scope_type": "user",
            "mint_virtual_key": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-jit-flow"},
    )
    assert requested.status_code == 200
    request_id = requested.json()["request_id"]

    approved = client.post(
        f"/gateway/jit-requests/{request_id}/approve",
        json={"decision": "approve", "decision_reason": "incident window approved"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-flow-approve"},
    )
    assert approved.status_code == 200
    approved_payload = approved.json()
    bearer = approved_payload["issued_virtual_key_token"]
    key_id = approved_payload["issued_virtual_key_id"]
    assert bearer and key_id

    listed = client.get(
        f"/gateway/jit-requests?entitlement_id={entitlement_id}&status=approved&active_only=true",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-jit-list"},
    )
    assert listed.status_code == 200
    listed_payload = listed.json()
    assert listed_payload["total"] >= 1
    assert any(row["request_id"] == request_id for row in listed_payload["data"])

    fetched = client.get(
        f"/gateway/jit-requests/{request_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-jit-get"},
    )
    assert fetched.status_code == 200
    assert fetched.json()["issued_virtual_key_id"] == key_id
    assert fetched.json().get("issued_virtual_key_token") is None

    chat = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "JIT bearer smoke"}],
            "stream": False,
            "environment": "dev",
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-jit-chat",
            "Authorization": f"Bearer {bearer}",
        },
    )
    assert chat.status_code == 200, chat.text
    assert str(chat.json()["id"]).startswith("chatcmpl-")

    revoked = client.post(
        f"/gateway/jit-requests/{request_id}/revoke",
        json={"reason": "incident closed"},
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-jit-revoke"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    key_after = client.get(
        f"/keys/{key_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-jit-key-after"},
    )
    assert key_after.status_code == 200
    assert key_after.json()["status"] == "blocked"

    denied_chat = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "should fail after revoke"}],
            "stream": False,
            "environment": "dev",
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-jit-chat-denied",
            "Authorization": f"Bearer {bearer}",
        },
    )
    assert denied_chat.status_code == 403


def test_gateway_jit_expire_tick_marks_stale_grants():
    entitlement_id = f"ent-jit-expire-{uuid4().hex[:10]}"
    ent = client.put(
        f"/gateway/entitlements/{entitlement_id}",
        json={
            "action": "gateway.route.execute_fallback",
            "tenant_id": "tenant-jit-expire",
            "environment": "dev",
            "allowed_roles": '["AI Ops Approver"]',
            "enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-expire-seed"},
    )
    assert ent.status_code == 200

    requested = client.post(
        "/gateway/jit-requests",
        json={
            "entitlement_id": entitlement_id,
            "environment": "dev",
            "justification": "Seed grant that will be force-expired by tick.",
            "requested_duration_minutes": 60,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-jit-expire"},
    )
    assert requested.status_code == 200
    request_id = requested.json()["request_id"]
    approved = client.post(
        f"/gateway/jit-requests/{request_id}/approve",
        json={"decision": "approve", "decision_reason": "seed for expire tick"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-expire-approve"},
    )
    assert approved.status_code == 200
    key_id = approved.json()["issued_virtual_key_id"]

    from app.database import SessionLocal
    from app.models import GatewayJitAccessRequest

    db = SessionLocal()
    try:
        row = db.query(GatewayJitAccessRequest).filter_by(request_id=request_id).first()
        assert row is not None
        row.expires_at = datetime.utcnow() - timedelta(minutes=2)
        db.commit()
    finally:
        db.close()

    tick = client.post(
        "/gateway/jit-requests/expire-tick?limit=100",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-expire-tick"},
    )
    assert tick.status_code == 200
    assert tick.json()["expired_grants"] >= 1
    assert tick.json()["blocked_keys"] >= 1

    fetched = client.get(
        f"/gateway/jit-requests/{request_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-jit-expire-get"},
    )
    assert fetched.status_code == 200
    assert fetched.json()["status"] == "expired"

    key_after = client.get(
        f"/keys/{key_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-jit-expire-key"},
    )
    assert key_after.status_code == 200
    assert key_after.json()["status"] == "blocked"


def _confirm_jit_email_action(token: str, *, decision_reason=None):
    preview = client.get(
        f"/gateway/jit-actions/{token}",
        headers={"Accept": "application/json"},
    )
    assert preview.status_code == 200
    body = preview.json()
    assert body.get("confirm_required") is True
    assert body.get("confirm_nonce")
    return client.post(
        f"/gateway/jit-actions/{token}",
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        json={
            "confirm": True,
            "confirm_nonce": body["confirm_nonce"],
            "decision_reason": decision_reason if decision_reason is not None else "confirmed via test",
        },
    )


def test_gateway_jit_decision_notify_config_requires_dual_approval_and_email_action(monkeypatch):
    from app.services.gateway_jit_notifications import mint_jit_action_token

    monkeypatch.setattr(
        "app.services.gateway_jit_notifications._post_external_rest",
        lambda db, *, url, payload, credential_binding_id="", sign_requests=True, delivery_id="": {
            "url": url,
            "status_code": 204,
            "ok": True,
            "callback_id": "external_rest_url",
            "signed": bool(sign_requests),
            "delivery_id": delivery_id or payload.get("delivery_id"),
        },
    )

    entitlement_id = f"ent-jit-notify-{uuid4().hex[:10]}"
    ent = client.put(
        f"/gateway/entitlements/{entitlement_id}",
        json={
            "action": "gateway.route.execute_fallback",
            "tenant_id": "tenant-jit-notify",
            "environment": "dev",
            "allowed_roles": '["AI Ops Approver"]',
            "enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-notify-seed"},
    )
    assert ent.status_code == 200

    denied_cfg = client.put(
        "/gateway/jit-decision-notify/config",
        json={
            "enabled": True,
            "notify_on_create": True,
            "email_channel_id": "",
            "reviewer_emails": ["reviewer@example.com"],
            "public_base_url": "https://gateway.test.local",
            "external_callback_ids": [],
            "external_rest_url": "",
            "external_rest_credential_binding_id": "",
            "action_token_ttl_minutes": 60,
            "allow_prod_email_approve": False,
            "min_notify_interval_minutes": 0,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-notify-cfg"},
    )
    assert denied_cfg.status_code == 403

    saved = client.put(
        "/gateway/jit-decision-notify/config",
        json={
            "enabled": True,
            "notify_on_create": True,
            "email_channel_id": "",
            "reviewer_emails": ["reviewer@example.com"],
            "public_base_url": "https://gateway.test.local",
            "external_callback_ids": [],
            "external_rest_url": "https://hooks.test.local/jit",
            "external_rest_credential_binding_id": "",
            "action_token_ttl_minutes": 60,
            "allow_prod_email_approve": False,
            "min_notify_interval_minutes": 0,
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-jit-notify-cfg",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-jit-notify-cfg",
        },
    )
    assert saved.status_code == 200
    assert saved.json()["enabled"] is True
    assert saved.json()["external_rest_url"] == "https://hooks.test.local/jit"

    loaded = client.get(
        "/gateway/jit-decision-notify/config",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-jit-notify-cfg"},
    )
    assert loaded.status_code == 200
    assert loaded.json()["public_base_url"] == "https://gateway.test.local"

    requested = client.post(
        "/gateway/jit-requests",
        json={
            "entitlement_id": entitlement_id,
            "environment": "dev",
            "justification": "Need temporary access for notify/email-action test.",
            "requested_duration_minutes": 30,
            "mint_virtual_key": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-jit-notify-1"},
    )
    assert requested.status_code == 200
    request_id = requested.json()["request_id"]

    notify = client.post(
        f"/gateway/jit-requests/{request_id}/notify",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-notify-send"},
    )
    assert notify.status_code == 200
    assert notify.json()["notified"] is True
    assert any(item.get("callback_id") == "external_rest_url" for item in notify.json().get("webhooks") or [])

    approve_token = mint_jit_action_token(
        request_id=request_id,
        decision="approve",
        reviewer_email="reviewer@example.com",
        ttl_minutes=60,
    )
    # Prefetch must not approve.
    prefetch = client.get(f"/gateway/jit-actions/{approve_token}")
    assert prefetch.status_code == 200
    assert "confirm" in prefetch.text.lower()
    still_pending = client.get(
        f"/gateway/jit-requests/{request_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-jit-notify-prefetch"},
    )
    assert still_pending.status_code == 200
    assert still_pending.json()["status"] == "requested"
    assert still_pending.json().get("last_notify")

    decided = _confirm_jit_email_action(approve_token, decision_reason="approve after confirm")
    assert decided.status_code == 200
    assert decided.json()["status"] == "approved"
    assert decided.json()["issued_virtual_key_token"] is None

    replay = _confirm_jit_email_action(approve_token)
    assert replay.status_code == 409
    detail = replay.json().get("detail") or {}
    assert detail.get("error_code") in {"JIT_ACTION_TOKEN_REPLAY", "JIT_ALREADY_DECIDED"}

    fetched = client.get(
        f"/gateway/jit-requests/{request_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-jit-notify-get"},
    )
    assert fetched.status_code == 200
    assert fetched.json()["status"] == "approved"
    assert fetched.json()["issued_virtual_key_id"]
    assert str(fetched.json()["approved_by"]).startswith("email:")


def test_gateway_jit_decision_notify_preview_test_and_signed_webhook(monkeypatch):
    from app.services.gateway_jit_notifications import mint_jit_action_token, sign_jit_webhook_body

    captured = {}

    def _capture_post(db, *, url, payload, credential_binding_id="", sign_requests=True, delivery_id=""):
        import json as _json

        body = _json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        captured["url"] = url
        captured["payload"] = payload
        captured["signed"] = bool(sign_requests)
        captured["delivery_id"] = delivery_id or payload.get("delivery_id")
        captured["signature"] = sign_jit_webhook_body(body) if sign_requests else None
        return {
            "url": url,
            "status_code": 202,
            "ok": True,
            "signed": bool(sign_requests),
            "delivery_id": captured["delivery_id"],
        }

    monkeypatch.setattr("app.services.gateway_jit_notifications._post_external_rest", _capture_post)

    entitlement_id = f"ent-jit-enh-{uuid4().hex[:10]}"
    ent = client.put(
        f"/gateway/entitlements/{entitlement_id}",
        json={
            "action": "gateway.route.execute_fallback",
            "tenant_id": "tenant-jit-enh",
            "environment": "dev",
            "allowed_roles": '["AI Ops Approver"]',
            "enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-enh-seed"},
    )
    assert ent.status_code == 200

    saved = client.put(
        "/gateway/jit-decision-notify/config",
        json={
            "enabled": True,
            "notify_on_create": True,
            "notify_on_decide": True,
            "email_channel_id": "",
            "reviewer_emails": ["reviewer@example.com"],
            "decision_recipient_emails": ["ops@example.com"],
            "public_base_url": "https://gateway.test.local",
            "external_callback_ids": [],
            "external_rest_url": "https://hooks.test.local/jit-signed",
            "external_rest_credential_binding_id": "",
            "action_token_ttl_minutes": 60,
            "allow_prod_email_approve": False,
            "expose_virtual_key_on_email_action": False,
            "email_virtual_key_to_recipients": True,
            "webhook_sign_requests": True,
            "include_action_links_in_webhooks": True,
            "min_notify_interval_minutes": 0,
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-jit-enh-cfg",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-jit-enh-cfg",
        },
    )
    assert saved.status_code == 200
    assert saved.json()["webhook_sign_requests"] is True
    assert saved.json()["expose_virtual_key_on_email_action"] is False

    requested = client.post(
        "/gateway/jit-requests",
        json={
            "entitlement_id": entitlement_id,
            "environment": "dev",
            "justification": "Enhance notify preview/test coverage.",
            "requested_duration_minutes": 20,
            "mint_virtual_key": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-jit-enh-1"},
    )
    assert requested.status_code == 200
    request_id = requested.json()["request_id"]

    preview = client.post(
        f"/gateway/jit-requests/{request_id}/preview-action-links?reviewer_email=preview@example.com",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-enh-preview"},
    )
    assert preview.status_code == 200
    assert preview.json()["links_ready"] is True
    assert "/gateway/jit-actions/" in preview.json()["approve_url"]

    tested = client.post(
        "/gateway/jit-decision-notify/test-delivery",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-enh-test"},
    )
    assert tested.status_code == 200
    assert tested.json()["tested"] is True
    assert tested.json()["probe_id"]
    assert captured.get("signed") is True
    assert str(captured.get("signature") or "").startswith("sha256=")

    notify = client.post(
        f"/gateway/jit-requests/{request_id}/notify",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-enh-notify"},
    )
    assert notify.status_code == 200
    assert any(item.get("signed") for item in notify.json().get("webhooks") or [])
    assert captured.get("payload", {}).get("approve_url")

    approve_token = mint_jit_action_token(
        request_id=request_id,
        decision="approve",
        reviewer_email="reviewer@example.com",
        ttl_minutes=60,
    )
    decided = _confirm_jit_email_action(approve_token, decision_reason="signed webhook approve")
    assert decided.status_code == 200
    body = decided.json()
    assert body["status"] == "approved"
    assert body["issued_virtual_key_id"]
    assert body["issued_virtual_key_token"] is None
    assert body["virtual_key_emailed"] is False  # no email channel configured

    # Invalid signature / missing confirm abuse paths
    bad = client.post(
        "/gateway/jit-actions/not-a-valid-token",
        headers={"Content-Type": "application/json"},
        json={"confirm": True, "confirm_nonce": "x" * 16},
    )
    assert bad.status_code == 401

    expired = mint_jit_action_token(
        request_id=request_id,
        decision="deny",
        reviewer_email="reviewer@example.com",
        ttl_minutes=15,
    )
    # Force expiry by rewriting claims via consume path after already decided -> 409 already decided
    replay = _confirm_jit_email_action(approve_token)
    assert replay.status_code == 409
    assert expired  # token minted for coverage; decision already applied


def test_gateway_jit_email_action_deny_and_prod_approve_gate():
    from app.services.gateway_jit_notifications import mint_jit_action_token

    entitlement_id = f"ent-jit-email-{uuid4().hex[:10]}"
    for environment in ("dev", "prod"):
        ent = client.put(
            f"/gateway/entitlements/{entitlement_id}-{environment}",
            json={
                "action": "gateway.route.execute_fallback",
                "tenant_id": "tenant-jit-email",
                "environment": environment,
                "allowed_roles": '["AI Ops Approver"]',
                "enabled": True,
            },
            headers={
                "X-Actor-Role": "Platform Admin",
                "X-Actor-Id": "admin-jit-email-seed",
                **(
                    {
                        "X-Approver-Role": "Security Approver",
                        "X-Approver-Id": "sec-jit-email-seed",
                    }
                    if environment == "prod"
                    else {}
                ),
            },
        )
        assert ent.status_code == 200

    # Deny via email action (dev)
    requested = client.post(
        "/gateway/jit-requests",
        json={
            "entitlement_id": f"{entitlement_id}-dev",
            "environment": "dev",
            "justification": "Deny via email action link.",
            "requested_duration_minutes": 15,
            "mint_virtual_key": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-jit-email-deny"},
    )
    assert requested.status_code == 200
    deny_id = requested.json()["request_id"]
    deny_token = mint_jit_action_token(
        request_id=deny_id,
        decision="deny",
        reviewer_email="reviewer@example.com",
        ttl_minutes=30,
    )
    denied = _confirm_jit_email_action(deny_token, decision_reason="deny from email")
    assert denied.status_code == 200
    assert denied.json()["status"] == "denied"
    assert denied.json()["decision"] == "deny"
    assert denied.json()["issued_virtual_key_token"] is None

    # Prod approve blocked when allow_prod_email_approve=false
    client.put(
        "/gateway/jit-decision-notify/config",
        json={
            "enabled": True,
            "notify_on_create": False,
            "email_channel_id": "",
            "reviewer_emails": [],
            "public_base_url": "https://gateway.test.local",
            "external_callback_ids": [],
            "external_rest_url": "",
            "external_rest_credential_binding_id": "",
            "action_token_ttl_minutes": 60,
            "allow_prod_email_approve": False,
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-jit-email-cfg",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-jit-email-cfg",
        },
    )
    prod_req = client.post(
        "/gateway/jit-requests",
        json={
            "entitlement_id": f"{entitlement_id}-prod",
            "environment": "prod",
            "justification": "Prod email approve should be blocked by default.",
            "requested_duration_minutes": 15,
            "mint_virtual_key": True,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-jit-email-prod"},
    )
    assert prod_req.status_code == 200
    prod_id = prod_req.json()["request_id"]
    prod_token = mint_jit_action_token(
        request_id=prod_id,
        decision="approve",
        reviewer_email="reviewer@example.com",
        ttl_minutes=30,
    )
    blocked = _confirm_jit_email_action(prod_token)
    assert blocked.status_code == 403
    assert blocked.json()["detail"]["error_code"] == "JIT_EMAIL_PROD_APPROVE_DISABLED"


def test_gateway_jit_notify_cooldown_reminder_retry_and_history(monkeypatch):
    attempts = {"n": 0}

    def _flaky_post(db, *, url, payload, credential_binding_id="", sign_requests=True, delivery_id=""):
        attempts["n"] += 1
        ok = attempts["n"] >= 2
        return {
            "url": url,
            "status_code": 200 if ok else 502,
            "ok": ok,
            "callback_id": "external_rest_url",
            "signed": bool(sign_requests),
            "delivery_id": delivery_id or payload.get("delivery_id"),
            "error": None if ok else "upstream_502",
        }

    monkeypatch.setattr("app.services.gateway_jit_notifications._post_external_rest", _flaky_post)

    entitlement_id = f"ent-jit-hist-{uuid4().hex[:10]}"
    ent = client.put(
        f"/gateway/entitlements/{entitlement_id}",
        json={
            "action": "gateway.route.execute_fallback",
            "tenant_id": "tenant-jit-hist",
            "environment": "dev",
            "allowed_roles": '["AI Ops Approver"]',
            "enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-hist-seed"},
    )
    assert ent.status_code == 200

    saved = client.put(
        "/gateway/jit-decision-notify/config",
        json={
            "enabled": True,
            "notify_on_create": False,
            "email_channel_id": "",
            "reviewer_emails": ["reviewer@example.com"],
            "public_base_url": "https://gateway.test.local",
            "external_callback_ids": [],
            "external_rest_url": "https://hooks.test.local/jit-hist",
            "external_rest_credential_binding_id": "",
            "action_token_ttl_minutes": 60,
            "allow_prod_email_approve": False,
            "min_notify_interval_minutes": 30,
            "webhook_payload_style": "compact",
            "webhook_sign_requests": True,
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-jit-hist-cfg",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-jit-hist-cfg",
        },
    )
    assert saved.status_code == 200
    assert saved.json()["min_notify_interval_minutes"] == 30
    assert saved.json()["webhook_payload_style"] == "compact"

    requested = client.post(
        "/gateway/jit-requests",
        json={
            "entitlement_id": entitlement_id,
            "environment": "dev",
            "justification": "Cooldown reminder retry history coverage.",
            "requested_duration_minutes": 25,
            "mint_virtual_key": False,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-jit-hist-1"},
    )
    assert requested.status_code == 200
    request_id = requested.json()["request_id"]

    first = client.post(
        f"/gateway/jit-requests/{request_id}/notify",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-hist-notify"},
    )
    assert first.status_code == 200
    assert first.json()["notified"] is True
    assert first.json()["delivery_id"]
    assert first.json()["webhooks"][0]["ok"] is False

    cooled = client.post(
        f"/gateway/jit-requests/{request_id}/notify",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-hist-notify"},
    )
    assert cooled.status_code == 429
    assert cooled.json()["detail"]["error_code"] == "JIT_NOTIFY_COOLDOWN"

    reminder = client.post(
        f"/gateway/jit-requests/{request_id}/notify?reminder=true&force=true",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-hist-remind"},
    )
    assert reminder.status_code == 200
    assert reminder.json()["is_reminder"] is True
    assert reminder.json()["event_type"] == "gateway.jit.request.reminder"
    assert reminder.json()["webhooks"][0]["ok"] is True
    assert "delivery_id" in (reminder.json().get("webhooks") or [{}])[0]

    retried = client.post(
        f"/gateway/jit-requests/{request_id}/notify-retry",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-hist-retry"},
    )
    # Last notify was successful reminder — no failed hooks
    assert retried.status_code == 200
    assert retried.json()["is_retry"] is True
    assert retried.json().get("reason") == "no_failed_webhooks"

    # Force a failed delivery then retry
    attempts["n"] = 0
    forced = client.post(
        f"/gateway/jit-requests/{request_id}/notify?force=true",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-hist-force"},
    )
    assert forced.status_code == 200
    assert forced.json()["webhooks"][0]["ok"] is False
    retry_ok = client.post(
        f"/gateway/jit-requests/{request_id}/notify-retry",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-hist-retry2"},
    )
    assert retry_ok.status_code == 200
    assert retry_ok.json()["is_retry"] is True
    assert retry_ok.json()["notified"] is True
    assert retry_ok.json()["webhooks"][0]["ok"] is True
    assert retry_ok.json()["webhooks"][0].get("retried") is True

    history = client.get(
        f"/gateway/jit-requests/{request_id}/notify-history",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-jit-hist"},
    )
    assert history.status_code == 200
    assert history.json()["request_id"] == request_id
    assert history.json()["last_notify"]
    assert len(history.json()["history"]) >= 3
    assert any(item.get("is_reminder") for item in history.json()["history"])
    assert any(item.get("is_retry") for item in history.json()["history"])

    fetched = client.get(
        f"/gateway/jit-requests/{request_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-jit-hist-get"},
    )
    assert fetched.status_code == 200
    assert fetched.json().get("notify_history")
    assert fetched.json().get("last_notify", {}).get("delivery_id")


def test_gateway_jit_notify_tick_reminder_escalation_and_pending_summary(monkeypatch):
    from datetime import datetime, timedelta

    from app.database import SessionLocal
    from app.models import GatewayJitAccessRequest

    monkeypatch.setattr(
        "app.services.gateway_jit_notifications._post_external_rest",
        lambda db, *, url, payload, credential_binding_id="", sign_requests=True, delivery_id="": {
            "url": url,
            "status_code": 204,
            "ok": True,
            "callback_id": "external_rest_url",
            "signed": bool(sign_requests),
            "delivery_id": delivery_id or payload.get("delivery_id"),
        },
    )

    entitlement_id = f"ent-jit-tick-{uuid4().hex[:10]}"
    ent = client.put(
        f"/gateway/entitlements/{entitlement_id}",
        json={
            "action": "gateway.route.execute_fallback",
            "tenant_id": "tenant-jit-tick",
            "environment": "dev",
            "allowed_roles": '["AI Ops Approver"]',
            "enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-tick-seed"},
    )
    assert ent.status_code == 200

    saved = client.put(
        "/gateway/jit-decision-notify/config",
        json={
            "enabled": True,
            "notify_on_create": False,
            "email_channel_id": "",
            "reviewer_emails": ["reviewer@example.com"],
            "escalation_reviewer_emails": ["sec-lead@example.com"],
            "public_base_url": "https://gateway.test.local",
            "external_callback_ids": [],
            "external_rest_url": "https://hooks.test.local/jit-tick",
            "external_rest_credential_binding_id": "",
            "action_token_ttl_minutes": 60,
            "allow_prod_email_approve": False,
            "min_notify_interval_minutes": 0,
            "auto_reminder_after_minutes": 30,
            "escalate_after_minutes": 120,
            "max_auto_reminders": 2,
            "auto_retry_failed_webhooks_on_tick": True,
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "admin-jit-tick-cfg",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-jit-tick-cfg",
        },
    )
    assert saved.status_code == 200
    assert saved.json()["auto_reminder_after_minutes"] == 30
    assert saved.json()["escalate_after_minutes"] == 120

    remind_req = client.post(
        "/gateway/jit-requests",
        json={
            "entitlement_id": entitlement_id,
            "environment": "dev",
            "justification": "Pending long enough for auto reminder tick.",
            "requested_duration_minutes": 20,
            "mint_virtual_key": False,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-jit-tick-remind"},
    )
    assert remind_req.status_code == 200
    remind_id = remind_req.json()["request_id"]

    esc_req = client.post(
        "/gateway/jit-requests",
        json={
            "entitlement_id": entitlement_id,
            "environment": "dev",
            "justification": "Pending long enough for auto escalation tick.",
            "requested_duration_minutes": 20,
            "mint_virtual_key": False,
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-jit-tick-esc"},
    )
    assert esc_req.status_code == 200
    esc_id = esc_req.json()["request_id"]

    db = SessionLocal()
    try:
        remind_row = db.query(GatewayJitAccessRequest).filter_by(request_id=remind_id).first()
        esc_row = db.query(GatewayJitAccessRequest).filter_by(request_id=esc_id).first()
        assert remind_row is not None and esc_row is not None
        remind_row.created_at = datetime.utcnow() - timedelta(minutes=45)
        esc_row.created_at = datetime.utcnow() - timedelta(minutes=180)
        db.commit()
    finally:
        db.close()

    summary = client.get(
        "/gateway/jit-decision-notify/pending-summary",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-jit-tick-sum"},
    )
    assert summary.status_code == 200
    assert summary.json()["pending_count"] >= 2
    assert summary.json()["overdue_reminder_count"] >= 1
    assert summary.json()["overdue_escalation_count"] >= 1

    tick = client.post(
        "/gateway/jit-requests/notify-tick",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-tick-run"},
    )
    assert tick.status_code == 200
    body = tick.json()
    assert body["scanned"] >= 2
    assert body["reminded"] >= 1
    assert body["escalated"] >= 1
    actions_by_id = {item["request_id"]: item["actions"] for item in body.get("items") or []}
    assert "remind" in actions_by_id.get(remind_id, [])
    assert "escalate" in actions_by_id.get(esc_id, [])

    remind_hist = client.get(
        f"/gateway/jit-requests/{remind_id}/notify-history",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-jit-tick-hist"},
    )
    assert remind_hist.status_code == 200
    assert any(item.get("is_reminder") for item in remind_hist.json().get("history") or [])

    esc_hist = client.get(
        f"/gateway/jit-requests/{esc_id}/notify-history",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-jit-tick-hist2"},
    )
    assert esc_hist.status_code == 200
    assert any(
        item.get("is_escalation") or item.get("event_type") == "gateway.jit.request.escalate"
        for item in esc_hist.json().get("history") or []
    )

    # Second tick should not re-escalate the same request.
    tick2 = client.post(
        "/gateway/jit-requests/notify-tick",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-jit-tick-run2"},
    )
    assert tick2.status_code == 200
    actions2 = {item["request_id"]: item["actions"] for item in tick2.json().get("items") or []}
    assert "escalate" not in actions2.get(esc_id, [])


def test_gateway_least_privilege_recommendations_generate_role_rightsize_and_apply():
    from app.database import SessionLocal
    from app.models import GatewayJitAccessRequest

    entitlement_id = f"ent-lpr-role-{uuid4().hex[:10]}"
    created = client.put(
        f"/gateway/entitlements/{entitlement_id}",
        json={
            "action": "gateway.route.execute_fallback",
            "tenant_id": "tenant-lpr-dev",
            "environment": "dev",
            "allowed_roles": '["Platform Admin","AI Ops Approver"]',
            "enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-lpr-seed"},
    )
    assert created.status_code == 200

    db = SessionLocal()
    try:
        db.add(
            GatewayJitAccessRequest(
                request_id=f"gjit-seed-{uuid4().hex[:10]}",
                entitlement_id=entitlement_id,
                requester_id="aiops-usage-1",
                requester_role="AI Ops Approver",
                justification="seed approved usage",
                environment="dev",
                requested_duration_minutes=30,
                status="approved",
                approved_by="admin-lpr-seed",
                approved_role="Platform Admin",
                approved_at=datetime.utcnow(),
                expires_at=datetime.utcnow() + timedelta(minutes=30),
            )
        )
        db.commit()
    finally:
        db.close()

    recommendations = client.get(
        f"/gateway/least-privilege/recommendations?entitlement_id={entitlement_id}&status=pending",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-lpr-1"},
    )
    assert recommendations.status_code == 200
    rows = recommendations.json()
    role_row = next((row for row in rows if row["recommendation_type"] == "role_rightsize_observed"), None)
    assert role_row is not None
    assert "AI Ops Approver" in role_row["proposed_allowed_roles"]
    assert "Platform Admin" not in role_row["proposed_allowed_roles"]

    applied = client.post(
        f"/gateway/least-privilege/recommendations/{role_row['recommendation_id']}/apply",
        json={"decision_reason": "apply observed-role rightsize"},
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-lpr-apply"},
    )
    assert applied.status_code == 200
    assert applied.json()["status"] == "applied"

    entitlement = client.get(
        f"/gateway/entitlements?entitlement_id={entitlement_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-lpr-1"},
    )
    assert entitlement.status_code == 200
    matching = [row for row in entitlement.json() if row["entitlement_id"] == entitlement_id]
    assert matching
    assert json.loads(matching[0]["allowed_roles"]) == ["AI Ops Approver"]


def test_gateway_least_privilege_recommendation_disable_unused_apply():
    entitlement_id = f"ent-lpr-disable-{uuid4().hex[:10]}"
    created = client.put(
        f"/gateway/entitlements/{entitlement_id}",
        json={
            "action": "gateway.route.update",
            "tenant_id": "tenant-lpr-dev",
            "environment": "dev",
            "allowed_roles": '["Platform Admin"]',
            "enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-lpr-seed2"},
    )
    assert created.status_code == 200

    recommendations = client.get(
        f"/gateway/least-privilege/recommendations?entitlement_id={entitlement_id}&status=pending",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-lpr-2"},
    )
    assert recommendations.status_code == 200
    rows = recommendations.json()
    disable_row = next((row for row in rows if row["recommendation_type"] == "disable_unused_entitlement"), None)
    assert disable_row is not None
    assert disable_row["proposed_enabled"] is False

    applied = client.post(
        f"/gateway/least-privilege/recommendations/{disable_row['recommendation_id']}/apply",
        json={"decision_reason": "disable unused entitlement"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-lpr-apply2"},
    )
    assert applied.status_code == 200
    assert applied.json()["status"] == "applied"

    entitlement = client.get(
        f"/gateway/entitlements?entitlement_id={entitlement_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-lpr-2"},
    )
    assert entitlement.status_code == 200
    matching = [row for row in entitlement.json() if row["entitlement_id"] == entitlement_id]
    assert matching
    assert matching[0]["enabled"] is False


def test_lifespan_initializes_core_tables():
    # Entering TestClient context triggers FastAPI lifespan startup.
    with TestClient(app) as lifespan_client:
        resp = lifespan_client.get("/health")
        assert resp.status_code == 200

    table_names = set(inspect(engine).get_table_names())
    expected = {
        "agents",
        "audit_events",
        "budget_policies",
        "cost_events",
        "identity_provider_configs",
        "virtual_keys",
    }
    assert expected.issubset(table_names)


def test_cost_budget_and_evaluation_flow():
    budget_resp = client.post(
        "/cost/budgets",
        json={
            "scope_type": "team",
            "scope_id": "Team A",
            "budget_amount_cents": 1000,
            "window_type": "daily",
            "soft_limit_percent": 80,
            "hard_limit_percent": 100,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-1"},
    )
    assert budget_resp.status_code == 200

    # Seed one cost event to exercise budget evaluation and anomaly detection.
    from app.database import SessionLocal

    db = SessionLocal()
    try:
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id="req-1",
                trace_id="trace-1",
                session_id="sess-1",
                agent_id="agent-cost-1",
                owner_scope="team:Team A",
                environment="dev",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=100,
                output_tokens=50,
                estimated_cost_cents=900,
                currency="USD",
            )
        )
        db.commit()
    finally:
        db.close()

    eval_resp = client.post(
        "/cost/policies/evaluate",
        json={"scope_type": "team", "scope_id": "Team A", "window_type": "daily"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-1"},
    )
    assert eval_resp.status_code == 200
    assert eval_resp.json()["decision"] in {"warn", "deny", "allow"}
    assert "projected_24h_spend_cents" in eval_resp.json()
    assert "projected_utilization_percent" in eval_resp.json()
    assert "preemptive_throttle" in eval_resp.json()

    live_resp = client.get(
        "/cost/live",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-1"},
    )
    assert live_resp.status_code == 200
    assert "spend_last_day_cents" in live_resp.json()

    agent_resp = client.get(
        "/cost/agents/agent-cost-1",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-1"},
    )
    assert agent_resp.status_code == 200
    assert len(agent_resp.json()) >= 1

    anomalies_resp = client.get(
        "/cost/anomalies",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-1"},
    )
    assert anomalies_resp.status_code == 200
    assert isinstance(anomalies_resp.json(), list)


def test_route_draft_approval_and_promotion_flow():
    draft_id = f"draft-{uuid4()}"

    submit = client.post(
        f"/route-drafts/{draft_id}/submit",
        json={
            "agent_id": "agent-a",
            "route_policy_snapshot_id": "snapshot-1",
            "environment": "staging",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-1", "X-MFA-Verified": "true"},
    )
    assert submit.status_code == 200
    assert submit.json()["status"] == "submitted"

    sec_approve = client.post(
        f"/route-drafts/{draft_id}/approve",
        json={"reason_code": "security-check-pass"},
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-1", "X-MFA-Verified": "true"},
    )
    assert sec_approve.status_code == 200
    assert sec_approve.json()["status"] == "security_approved"

    ai_approve = client.post(
        f"/route-drafts/{draft_id}/approve",
        json={"reason_code": "ai-ops-check-pass"},
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-1", "X-MFA-Verified": "true"},
    )
    assert ai_approve.status_code == 200
    assert ai_approve.json()["status"] == "aiops_approved"

    change_window = client.post(
        f"/route-drafts/{draft_id}/approve-change-window",
        json={"reason_code": "change-window-open"},
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-1", "X-MFA-Verified": "true"},
    )
    assert change_window.status_code == 200
    assert change_window.json()["status"] == "change_window_approved"

    # Promotion readiness gates require benchmark, scan, and contract validation signals.
    post_benchmark_run_and_wait(
        client,
        {"agent_id": "agent-a", "benchmark_suite": "reliability-core", "environment": "staging"},
        {"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-1", "X-MFA-Verified": "true"},
    )
    post_scan_run_and_wait(
        client,
        {"agent_id": "agent-a", "scan_type": "security", "environment": "staging"},
        {"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-1", "X-MFA-Verified": "true"},
    )

    validate_resp = client.post(
        "/agentic/contracts/validate",
        json={
            "agent_id": "agent-a",
            "module_ids": ["mod-1"],
            "route_policy_snapshot_id": "snap-1",
            "required_capabilities": ["observability", "budget-control"],
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-1", "X-MFA-Verified": "true"},
    )
    assert validate_resp.status_code == 200
    assert validate_resp.json()["status"] == "pass"

    promote = client.post(
        f"/route-drafts/{draft_id}/promote",
        json={"target_environment": "prod", "expected_state_version": change_window.json()["state_version"]},
        headers={
            "X-Actor-Role": "Release Manager",
            "X-Actor-Id": "rel-1",
            "X-MFA-Verified": "true",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-promote-1",
        },
    )
    assert promote.status_code == 200
    assert promote.json()["status"] == "promoted"
    assert promote.json()["environment"] == "prod"

    history = client.get(
        f"/route-drafts/{draft_id}/approval-history",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-1"},
    )
    assert history.status_code == 200
    assert len(history.json()) >= 4

    listing = client.get(
        "/route-drafts",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-1"},
    )
    assert listing.status_code == 200
    assert any(d["draft_id"] == draft_id for d in listing.json())


def test_route_draft_promotion_fails_without_readiness_signals():
    draft_id = f"draft-fail-{uuid4()}"

    submit = client.post(
        f"/route-drafts/{draft_id}/submit",
        json={
            "agent_id": "agent-no-signal",
            "route_policy_snapshot_id": "snapshot-fail",
            "environment": "staging",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-1", "X-MFA-Verified": "true"},
    )
    assert submit.status_code == 200

    sec_approve = client.post(
        f"/route-drafts/{draft_id}/approve",
        json={"reason_code": "ok"},
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-1", "X-MFA-Verified": "true"},
    )
    assert sec_approve.status_code == 200

    ai_approve = client.post(
        f"/route-drafts/{draft_id}/approve",
        json={"reason_code": "ok"},
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-1", "X-MFA-Verified": "true"},
    )

    change_window = client.post(
        f"/route-drafts/{draft_id}/approve-change-window",
        json={"reason_code": "window-ok"},
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-1", "X-MFA-Verified": "true"},
    )
    assert change_window.status_code == 200
    assert ai_approve.status_code == 200

    promote = client.post(
        f"/route-drafts/{draft_id}/promote",
        json={"target_environment": "prod", "expected_state_version": change_window.json()["state_version"]},
        headers={
            "X-Actor-Role": "Release Manager",
            "X-Actor-Id": "rel-1",
            "X-MFA-Verified": "true",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-promote-2",
        },
    )
    assert promote.status_code == 400
    assert "gates" in promote.json()["detail"]
    assert promote.json()["detail"]["gates"]["benchmark_ok"] is False


def test_route_draft_submitter_cannot_approve_or_promote_own_draft():
    draft_id = f"draft-self-{uuid4()}"

    submit = client.post(
        f"/route-drafts/{draft_id}/submit",
        json={
            "agent_id": "agent-self",
            "route_policy_snapshot_id": "snapshot-self",
            "environment": "staging",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-self", "X-MFA-Verified": "true"},
    )
    assert submit.status_code == 200

    deny_self_approve = client.post(
        f"/route-drafts/{draft_id}/approve",
        json={"reason_code": "self-approve"},
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "owner-self", "X-MFA-Verified": "true"},
    )
    assert deny_self_approve.status_code == 400
    assert deny_self_approve.json()["detail"] == "Submitter cannot approve their own draft"

    sec_approve = client.post(
        f"/route-drafts/{draft_id}/approve",
        json={"reason_code": "ok"},
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-self", "X-MFA-Verified": "true"},
    )
    assert sec_approve.status_code == 200

    ai_approve = client.post(
        f"/route-drafts/{draft_id}/approve",
        json={"reason_code": "ok"},
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-self", "X-MFA-Verified": "true"},
    )
    assert ai_approve.status_code == 200

    change_window = client.post(
        f"/route-drafts/{draft_id}/approve-change-window",
        json={"reason_code": "window-ok"},
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "owner-self", "X-MFA-Verified": "true"},
    )
    assert change_window.status_code == 400
    assert change_window.json()["detail"] == "Submitter cannot approve change window for own draft"


def test_route_draft_rollback_to_draft_and_version_mismatch_guard():
    draft_id = f"draft-rollback-{uuid4()}"

    submit = client.post(
        f"/route-drafts/{draft_id}/submit",
        json={
            "agent_id": "agent-rollback",
            "route_policy_snapshot_id": "snapshot-rollback",
            "environment": "staging",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-rollback", "X-MFA-Verified": "true"},
    )
    assert submit.status_code == 200

    sec_approve = client.post(
        f"/route-drafts/{draft_id}/approve",
        json={"reason_code": "ok"},
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-rollback", "X-MFA-Verified": "true"},
    )
    assert sec_approve.status_code == 200

    ai_approve = client.post(
        f"/route-drafts/{draft_id}/approve",
        json={"reason_code": "ok"},
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-rollback", "X-MFA-Verified": "true"},
    )
    assert ai_approve.status_code == 200

    change_window = client.post(
        f"/route-drafts/{draft_id}/approve-change-window",
        json={"reason_code": "window-ok", "change_window_id": "cw-1", "evidence_refs": ["tryout:1"]},
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-rollback", "X-MFA-Verified": "true"},
    )
    assert change_window.status_code == 200

    stale_promote = client.post(
        f"/route-drafts/{draft_id}/promote",
        json={"target_environment": "prod", "expected_state_version": 1},
        headers={
            "X-Actor-Role": "Release Manager",
            "X-Actor-Id": "rel-rollback",
            "X-MFA-Verified": "true",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-promote-rollback",
        },
    )
    assert stale_promote.status_code == 409

    rollback = client.post(
        f"/route-drafts/{draft_id}/rollback-to-draft",
        json={"reason_code": "needs-rework"},
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-rollback", "X-MFA-Verified": "true"},
    )
    assert rollback.status_code == 200
    assert rollback.json()["status"] == "draft"


def test_route_draft_list_and_history_enforce_agent_owner_scope():
    from app.database import SessionLocal
    from app.models import Agent

    db = SessionLocal()
    try:
        db.add_all(
            [
                Agent(
                    agent_id=f"agent-owned-a-{uuid4()}",
                    name="Owned Agent A",
                    owner_id="owner-scope-a",
                    owner_name="Owner Scope A",
                    owner_team="Team A",
                    risk_tier="low",
                    status="active",
                ),
                Agent(
                    agent_id=f"agent-owned-b-{uuid4()}",
                    name="Owned Agent B",
                    owner_id="owner-scope-b",
                    owner_name="Owner Scope B",
                    owner_team="Team B",
                    risk_tier="low",
                    status="active",
                ),
            ]
        )
        db.commit()
        agent_a = db.query(Agent).filter_by(owner_id="owner-scope-a").order_by(Agent.created_at.desc()).first()
        agent_b = db.query(Agent).filter_by(owner_id="owner-scope-b").order_by(Agent.created_at.desc()).first()
        assert agent_a is not None
        assert agent_b is not None
    finally:
        db.close()

    lookup_db = SessionLocal()
    try:
        def owner_for_agent(agent_id: str):
            agent = lookup_db.query(Agent).filter_by(agent_id=agent_id).first()
            return agent.owner_id if agent else None

        draft_a = client.post(
            f"/route-drafts/draft-scope-a-{uuid4()}/submit",
            json={
                "agent_id": agent_a.agent_id,
                "route_policy_snapshot_id": "snapshot-scope-a",
                "environment": "staging",
            },
            headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-scope-a", "X-MFA-Verified": "true"},
        )
        assert draft_a.status_code == 200
        draft_a_id = draft_a.json()["draft_id"]

        draft_b = client.post(
            f"/route-drafts/draft-scope-b-{uuid4()}/submit",
            json={
                "agent_id": agent_b.agent_id,
                "route_policy_snapshot_id": "snapshot-scope-b",
                "environment": "staging",
            },
            headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-scope-b", "X-MFA-Verified": "true"},
        )
        assert draft_b.status_code == 200
        draft_b_id = draft_b.json()["draft_id"]

        list_allowed = client.get(
            "/route-drafts",
            headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-scope-a"},
        )
        assert list_allowed.status_code == 200
        assert any(d["draft_id"] == draft_a_id for d in list_allowed.json())
        for draft in list_allowed.json():
            assert owner_for_agent(draft["agent_id"]) == "owner-scope-a"

        list_scoped_b = client.get(
            "/route-drafts",
            headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-scope-b"},
        )
        assert list_scoped_b.status_code == 200
        assert any(d["draft_id"] == draft_b_id for d in list_scoped_b.json())
        for draft in list_scoped_b.json():
            assert owner_for_agent(draft["agent_id"]) == "owner-scope-b"

        history_allowed = client.get(
            f"/route-drafts/{draft_a_id}/approval-history",
            headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-scope-a"},
        )
        assert history_allowed.status_code == 200
        assert len(history_allowed.json()) >= 1

        history_denied = client.get(
            f"/route-drafts/{draft_b_id}/approval-history",
            headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-scope-a"},
        )
        assert history_denied.status_code == 403
        assert history_denied.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"
    finally:
        lookup_db.close()


def test_route_draft_rollback_last_good_restores_previous_snapshot():
    from app.database import SessionLocal
    from app.models import Agent, AgentConfig

    db = SessionLocal()
    try:
        agent = db.query(Agent).filter_by(agent_id="agent-rbg").first()
        if agent is None:
            db.add(
                Agent(
                    agent_id="agent-rbg",
                    name="Route Rollback Agent",
                    owner_id="owner-rbg",
                    owner_name="Owner RBG",
                    owner_team="Team RBG",
                    risk_tier="medium",
                    status="active",
                )
            )
        else:
            agent.owner_id = "owner-rbg"
            agent.status = "active"
            agent.risk_tier = "medium"
        if db.query(AgentConfig).filter_by(agent_key="agent-rbg").first() is None:
            db.add(
                AgentConfig(
                    config_id=f"cfg-rbg-{uuid4().hex[:8]}",
                    agent_key="agent-rbg",
                    display_name="Route Rollback Agent",
                    provider="openai",
                    model="gpt-4o-mini",
                    provider_priority="openai",
                    environment="prod",
                    enabled=True,
                )
            )
        db.commit()
    finally:
        db.close()

    first_draft_id = f"draft-rbg-1-{uuid4()}"
    second_draft_id = f"draft-rbg-2-{uuid4()}"

    for draft_id, snapshot in [(first_draft_id, "snapshot-old"), (second_draft_id, "snapshot-new")]:
        submit = client.post(
            f"/route-drafts/{draft_id}/submit",
            json={
                "agent_id": "agent-rbg",
                "route_policy_snapshot_id": snapshot,
                "environment": "prod",
            },
            headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-rbg", "X-MFA-Verified": "true"},
        )
        assert submit.status_code == 200

        sec_approve = client.post(
            f"/route-drafts/{draft_id}/approve",
            json={"reason_code": "ok"},
            headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": f"sec-{draft_id}", "X-MFA-Verified": "true"},
        )
        assert sec_approve.status_code == 200

        ai_approve = client.post(
            f"/route-drafts/{draft_id}/approve",
            json={"reason_code": "ok"},
            headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": f"aiops-{draft_id}", "X-MFA-Verified": "true"},
        )
        assert ai_approve.status_code == 200

        change_window = client.post(
            f"/route-drafts/{draft_id}/approve-change-window",
            json={"reason_code": "window-ok"},
            headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": f"rel-{draft_id}", "X-MFA-Verified": "true"},
        )
        assert change_window.status_code == 200

        post_benchmark_run_and_wait(
            client,
            {"agent_id": "agent-rbg", "benchmark_suite": "scale-tier3-100k", "environment": "prod"},
            {"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-rbg", "X-MFA-Verified": "true"},
        )
        post_scan_run_and_wait(
            client,
            {"agent_id": "agent-rbg", "scan_type": "security", "environment": "prod"},
            {"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-rbg", "X-MFA-Verified": "true"},
        )

        validate_resp = client.post(
            "/agentic/contracts/validate",
            json={
                "agent_id": "agent-rbg",
                "module_ids": ["mod-rbg"],
                "route_policy_snapshot_id": snapshot,
                "required_capabilities": ["observability"],
            },
            headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-rbg", "X-MFA-Verified": "true"},
        )
        assert validate_resp.status_code == 200

        promote = client.post(
            f"/route-drafts/{draft_id}/promote",
            json={"target_environment": "prod", "expected_state_version": change_window.json()["state_version"]},
            headers={
                "X-Actor-Role": "Release Manager",
                "X-Actor-Id": f"rel-promote-{draft_id}",
                "X-MFA-Verified": "true",
                "X-Approver-Role": "Security Approver",
                "X-Approver-Id": f"sec-promote-{draft_id}",
            },
        )
        assert promote.status_code == 200

    second_before = client.get(
        "/route-drafts",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-rbg"},
    )
    assert second_before.status_code == 200
    second_item = next(d for d in second_before.json() if d["draft_id"] == second_draft_id)
    assert second_item["route_policy_snapshot_id"] == "snapshot-new"

    rollback_last_good = client.post(
        f"/route-drafts/{second_draft_id}/rollback-last-good",
        json={"reason_code": "incident-rollback", "expected_state_version": second_item["state_version"]},
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-rbg-rollback", "X-MFA-Verified": "true"},
    )
    assert rollback_last_good.status_code == 200
    assert rollback_last_good.json()["status"] == "promoted"
    assert rollback_last_good.json()["route_policy_snapshot_id"] == "snapshot-old"


def test_route_draft_privileged_mutations_require_mfa_claim():
    draft_id = f"draft-mfa-{uuid4()}"

    submit = client.post(
        f"/route-drafts/{draft_id}/submit",
        json={
            "agent_id": "agent-mfa",
            "route_policy_snapshot_id": "snapshot-mfa",
            "environment": "staging",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-mfa", "X-MFA-Verified": "true"},
    )
    assert submit.status_code == 200

    no_mfa = client.post(
        f"/route-drafts/{draft_id}/approve",
        json={"reason_code": "ok"},
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-mfa"},
    )
    assert no_mfa.status_code == 403
    detail = no_mfa.json()["detail"]
    assert detail["error_code"] == "AUTHZ_MFA_REQUIRED"
    assert detail["decision_trace_id"] == "authz-mfa-check"


def test_observability_compliance_and_playground_flow():
    run_resp = client.post(
        "/playground/runs",
        json={
            "prompt_text": "Summarize incident timeline",
            "candidate_models": "[\"model-a\",\"model-b\"]",
            "selected_model": "model-a",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-1"},
    )
    assert run_resp.status_code == 200
    run_id = run_resp.json()["run_id"]

    run_list = client.get(
        "/playground/runs?limit=10&offset=0",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-1"},
    )
    assert run_list.status_code == 200
    assert any(row["run_id"] == run_id for row in run_list.json())

    get_run = client.get(
        f"/playground/runs/{run_id}",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-1"},
    )
    assert get_run.status_code == 200

    compare = client.post(
        "/playground/compare",
        json={"prompt_text": "classify", "candidate_models": ["model-a", "model-b"]},
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-1"},
    )
    assert compare.status_code == 200
    assert len(compare.json()["results"]) == 2

    draft_from_run = client.post(
        f"/playground/runs/{run_id}/route-draft",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-1"},
    )
    assert draft_from_run.status_code == 200
    draft_id = draft_from_run.json()["draft_id"]

    route_drafts = client.get(
        "/route-drafts?limit=10&offset=0",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-1"},
    )
    assert route_drafts.status_code == 200
    assert any(row["draft_id"] == draft_id for row in route_drafts.json())

    approval_history = client.get(
        f"/route-drafts/{draft_id}/approval-history",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-1"},
    )
    assert approval_history.status_code == 200
    assert isinstance(approval_history.json(), list)

    test_sets = client.get(
        "/playground/test-sets",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-1"},
    )
    assert test_sets.status_code == 200
    assert len(test_sets.json()) >= 1

    trace_id = f"trace-{run_id}"
    trace_resp = client.get(
        f"/observability/traces/{trace_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-1"},
    )
    assert trace_resp.status_code == 200

    logs_resp = client.get(
        "/observability/logs",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-1"},
    )
    assert logs_resp.status_code == 200


def test_playground_prompt_registry_crud_and_version_history():
    prompt_registry_name = f"prompt-registry-{uuid4()}"
    create_resp = client.post(
        "/playground/prompts",
        json={
            "name": prompt_registry_name,
            "description": "Initial governed prompt",
            "labels": "[\"support\",\"prod\"]",
            "prompt_text": "Summarize the customer issue and propose next steps.",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-prompt-1"},
    )
    assert create_resp.status_code == 200
    created = create_resp.json()
    prompt_registry_id = created["prompt_registry_id"]
    assert created["latest_version"] == 1

    list_resp = client.get(
        "/playground/prompts?limit=10&offset=0",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-prompt-1"},
    )
    assert list_resp.status_code == 200
    assert any(row["prompt_registry_id"] == prompt_registry_id for row in list_resp.json())

    get_resp = client.get(
        f"/playground/prompts/{prompt_registry_id}",
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-prompt-1"},
    )
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == prompt_registry_name

    update_resp = client.put(
        f"/playground/prompts/{prompt_registry_id}",
        json={
            "description": "Updated governed prompt",
            "labels": "[\"support\",\"prod\",\"v2\"]",
            "prompt_text": "Summarize the issue, note policy constraints, and propose next steps.",
            "change_reason": "add policy context",
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-prompt-1"},
    )
    assert update_resp.status_code == 200
    updated = update_resp.json()
    assert updated["latest_version"] == 2

    versions_resp = client.get(
        f"/playground/prompts/{prompt_registry_id}/versions",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-prompt-1"},
    )
    assert versions_resp.status_code == 200
    versions = versions_resp.json()
    assert [row["version"] for row in versions] == [2, 1]

    rollback_resp = client.post(
        f"/playground/prompts/{prompt_registry_id}/rollback",
        json={"version": 1, "reason": "restore baseline"},
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-prompt-1"},
    )
    assert rollback_resp.status_code == 200
    assert rollback_resp.json()["latest_version"] == 3

    delete_resp = client.delete(
        f"/playground/prompts/{prompt_registry_id}",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-prompt-1"},
    )
    assert delete_resp.status_code == 200
    assert delete_resp.json()["status"] == "deleted"

    schema_status = client.get(
        "/observability/logs/schema-status?sample_size=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-1"},
    )
    assert schema_status.status_code == 200
    schema_payload = schema_status.json()
    assert "request_id" in schema_payload["required_fields"]
    assert schema_payload["sampled_count"] >= 1
    assert schema_payload["valid_count"] >= 1
    assert schema_payload["conformance_percent"] >= 0
    assert schema_payload["conformance_percent"] <= 100


def test_playground_prompt_registry_promote_requires_render_variables_and_prod_dual_approval():
    create_resp = client.post(
        "/playground/prompts",
        json={
            "name": f"prompt-promo-{uuid4()}",
            "description": "Promotion validation test",
            "labels": "[\"ops\",\"prod\"]",
            "prompt_text": "Summarize {{ticket_id}} for {{customer_tier}} and propose next steps.",
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-promote-1"},
    )
    assert create_resp.status_code == 200
    prompt_registry_id = create_resp.json()["prompt_registry_id"]

    missing_vars = client.post(
        f"/playground/prompts/{prompt_registry_id}/promote",
        json={
            "target_environment": "staging",
            "reason": "promote for staging validation",
            "require_render_validation": True,
            "render_variables": {"ticket_id": "INC-42"},
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-promote-1"},
    )
    assert missing_vars.status_code == 422
    assert missing_vars.json()["detail"]["error_code"] == "PROMPT_RENDER_VALIDATION_FAILED"
    assert "customer_tier" in missing_vars.json()["detail"]["missing_variables"]

    prod_without_dual = client.post(
        f"/playground/prompts/{prompt_registry_id}/promote",
        json={
            "target_environment": "prod",
            "reason": "release to production",
            "approval_ticket": "CHG-991",
            "render_variables": {"ticket_id": "INC-42", "customer_tier": "gold"},
        },
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-promote-1"},
    )
    assert prod_without_dual.status_code == 403
    assert prod_without_dual.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    prod_with_dual = client.post(
        f"/playground/prompts/{prompt_registry_id}/promote",
        json={
            "target_environment": "prod",
            "reason": "release to production",
            "approval_ticket": "CHG-991",
            "render_variables": {"ticket_id": "INC-42", "customer_tier": "gold"},
        },
        headers={
            "X-Actor-Role": "AI Ops Approver",
            "X-Actor-Id": "aiops-promote-1",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-promote-1",
        },
    )
    assert prod_with_dual.status_code == 200
    promoted = prod_with_dual.json()
    assert promoted["promotion_recorded"] is True
    assert promoted["approval_required"] is True
    assert promoted["target_environment"] == "prod"
    assert promoted["item"]["latest_version"] == 2
    assert "INC-42" in promoted["render_preview"]


def test_key_guardrails_support_stage_pipeline_and_policy_modes():
    create_resp = client.post(
        "/keys",
        json={
            "owner_scope_type": "team",
            "owner_scope_id": "guardrail-team",
            "allowed_endpoint_families": '["responses"]',
            "allowed_models": '["gpt-4o-mini"]',
            "guardrail_policy": json.dumps(
                {
                    "allowed_environments": ["dev"],
                    "max_output_tokens": 10,
                    "policy_mode": "block",
                    "input_stages": ["input"],
                    "output_stages": ["output"],
                }
            ),
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "guardrail-admin"},
    )
    assert create_resp.status_code == 200
    key_id = create_resp.json()["key_id"]

    input_stage = client.post(
        f"/keys/{key_id}/guardrails/evaluate",
        json={
            "environment": "dev",
            "stage": "input",
            "policy_mode": "block",
            "requests_last_minute": 1,
            "input_tokens": 5,
            "output_tokens": 999,
            "mfa_verified": False,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "guardrail-admin"},
    )
    assert input_stage.status_code == 200
    assert input_stage.json()["decision"] == "allow"

    output_stage = client.post(
        f"/keys/{key_id}/guardrails/evaluate",
        json={
            "environment": "dev",
            "stage": "output",
            "policy_mode": "block",
            "requests_last_minute": 1,
            "input_tokens": 5,
            "output_tokens": 999,
            "mfa_verified": False,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "guardrail-admin"},
    )
    assert output_stage.status_code == 200
    assert output_stage.json()["decision"] == "deny"

    updated = client.patch(
        f"/keys/{key_id}",
        json={"guardrail_policy": json.dumps({"allowed_environments": ["dev"], "max_output_tokens": 10, "policy_mode": "warn", "output_stages": ["output"]})},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "guardrail-admin"},
    )
    assert updated.status_code == 200

    warn_stage = client.post(
        f"/keys/{key_id}/guardrails/evaluate",
        json={
            "environment": "dev",
            "stage": "output",
            "policy_mode": "warn",
            "requests_last_minute": 1,
            "input_tokens": 5,
            "output_tokens": 999,
            "mfa_verified": False,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "guardrail-admin"},
    )
    assert warn_stage.status_code == 200
    warn_payload = warn_stage.json()
    assert warn_payload["decision"] == "allow"
    assert any(reason.startswith("warning:") for reason in warn_payload["reasons"])


def test_playground_run_feedback_records_quality_scores():
    run_resp = client.post(
        "/playground/runs",
        json={
            "prompt_text": "Draft a support response",
            "candidate_models": '["gpt-4o-mini","gpt-4o"]',
            "selected_model": "gpt-4o-mini",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "feedback-owner"},
    )
    assert run_resp.status_code == 200
    run_id = run_resp.json()["run_id"]
    trace_id = f"trace-{run_id}"

    feedback_resp = client.post(
        f"/playground/runs/{run_id}/feedback",
        json={
            "trace_id": trace_id,
            "rating": 5,
            "quality_score": 0.92,
            "comment": "Accurate and actionable output.",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "feedback-owner"},
    )
    assert feedback_resp.status_code == 200
    assert feedback_resp.json()["quality_score"] == 0.92

    list_resp = client.get(
        f"/playground/runs/{run_id}/feedback",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "feedback-reviewer"},
    )
    assert list_resp.status_code == 200
    rows = list_resp.json()
    assert len(rows) == 1
    assert rows[0]["trace_id"] == trace_id
    assert rows[0]["rating"] == 5


def test_playground_run_feedback_updates_existing_comment_for_same_trace():
    actor_id = f"feedback-update-{uuid4().hex[:8]}"
    run_resp = client.post(
        "/playground/runs",
        json={
            "prompt_text": "Draft a support response",
            "candidate_models": '["gpt-4o-mini"]',
            "selected_model": "gpt-4o-mini",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": actor_id},
    )
    assert run_resp.status_code == 200
    run_id = run_resp.json()["run_id"]
    trace_id = f"trace-update-{uuid4().hex[:8]}"
    payload = {
        "trace_id": trace_id,
        "rating": 4,
        "quality_score": 0.75,
        "comment": "Initial operator note.",
    }
    first = client.post(
        f"/playground/runs/{run_id}/feedback",
        json=payload,
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": actor_id},
    )
    assert first.status_code == 200
    feedback_id = first.json()["feedback_id"]

    updated = client.post(
        f"/playground/runs/{run_id}/feedback",
        json={**payload, "comment": "Updated operator note with more detail."},
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": actor_id},
    )
    assert updated.status_code == 200
    body = updated.json()
    assert body["feedback_id"] == feedback_id
    assert body["comment"] == "Updated operator note with more detail."

    listed = client.get(
        f"/playground/runs/{run_id}/feedback",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": actor_id},
    )
    assert listed.status_code == 200
    assert len(listed.json()) == 1
    assert listed.json()[0]["comment"] == "Updated operator note with more detail."


def test_playground_quality_triage_queue_filters_and_owner_scope():
    owner_one = "triage-owner-1"
    owner_two = "triage-owner-2"

    run_one = client.post(
        "/playground/runs",
        json={
            "prompt_text": "Generate a customer response",
            "candidate_models": '["gpt-4o-mini"]',
            "selected_model": "gpt-4o-mini",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": owner_one},
    )
    assert run_one.status_code == 200
    run_one_id = run_one.json()["run_id"]

    run_two = client.post(
        "/playground/runs",
        json={
            "prompt_text": "Generate another response",
            "candidate_models": '["gpt-4o"]',
            "selected_model": "gpt-4o",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": owner_two},
    )
    assert run_two.status_code == 200
    run_two_id = run_two.json()["run_id"]

    poor_feedback = client.post(
        f"/playground/runs/{run_one_id}/feedback",
        json={
            "trace_id": f"trace-{run_one_id}",
            "rating": 2,
            "quality_score": 0.35,
            "comment": "Unsafe recommendation.",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": owner_one},
    )
    assert poor_feedback.status_code == 200

    neutral_feedback = client.post(
        f"/playground/runs/{run_two_id}/feedback",
        json={
            "trace_id": f"trace-{run_two_id}",
            "rating": 5,
            "quality_score": 0.95,
            "comment": "Great output.",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": owner_two},
    )
    assert neutral_feedback.status_code == 200

    admin_queue = client.get(
        "/playground/quality/triage?max_quality_score=0.8&max_rating=3",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "triage-sec-1"},
    )
    assert admin_queue.status_code == 200
    admin_payload = admin_queue.json()
    assert admin_payload["total"] >= 1
    assert any(item["run_id"] == run_one_id for item in admin_payload["items"])
    flagged = next(item for item in admin_payload["items"] if item["run_id"] == run_one_id)
    assert flagged["priority_tag"] == "p0"
    assert flagged["triage_reason"] == "critical_quality_risk"

    owner_one_queue = client.get(
        "/playground/quality/triage?max_quality_score=0.8&max_rating=3",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": owner_one},
    )
    assert owner_one_queue.status_code == 200
    owner_one_items = owner_one_queue.json()["items"]
    assert owner_one_items
    assert all(item["run_actor_id"] == owner_one for item in owner_one_items)


def test_playground_quality_triage_escalation_lifecycle_and_scope_controls():
    owner_one = "triage-escalation-owner-1"
    owner_two = "triage-escalation-owner-2"

    run_one = client.post(
        "/playground/runs",
        json={
            "prompt_text": "Generate a risky response",
            "candidate_models": '["gpt-4o-mini"]',
            "selected_model": "gpt-4o-mini",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": owner_one},
    )
    assert run_one.status_code == 200
    run_one_id = run_one.json()["run_id"]

    feedback = client.post(
        f"/playground/runs/{run_one_id}/feedback",
        json={
            "trace_id": f"trace-{run_one_id}",
            "rating": 1,
            "quality_score": 0.25,
            "comment": "Unsafe output requiring escalation.",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": owner_one},
    )
    assert feedback.status_code == 200
    feedback_id = feedback.json()["feedback_id"]

    escalate = client.post(
        f"/playground/quality/triage/{feedback_id}/escalate",
        json={
            "severity": "critical",
            "priority_tag": "p0",
            "assigned_team": "ai-trust-ops",
            "escalation_channel": "security-ops",
            "escalation_reason": "Potential harmful answer in customer workflow.",
            "external_ticket_ref": "INC-991",
            "sla_target_minutes": 30,
        },
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-escalation-1"},
    )
    assert escalate.status_code == 200
    escalation_payload = escalate.json()
    escalation_id = escalation_payload["escalation_id"]
    assert escalation_payload["status"] == "open"
    assert escalation_payload["priority_tag"] == "p0"
    assert escalation_payload["sla_target_minutes"] == 30
    assert escalation_payload["due_at"]

    duplicate = client.post(
        f"/playground/quality/triage/{feedback_id}/escalate",
        json={
            "severity": "high",
            "priority_tag": "p1",
            "assigned_team": "ai-trust-ops",
            "escalation_channel": "security-ops",
            "escalation_reason": "Duplicate should fail.",
            "sla_target_minutes": 60,
        },
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-escalation-1"},
    )
    assert duplicate.status_code == 409

    queue = client.get(
        "/playground/quality/triage/escalations?status=open",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-escalation-1"},
    )
    assert queue.status_code == 200
    assert any(item["escalation_id"] == escalation_id for item in queue.json()["items"])

    unauthorized_ack = client.post(
        f"/playground/quality/triage/escalations/{escalation_id}/acknowledge",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": owner_two},
    )
    assert unauthorized_ack.status_code == 403

    acknowledge = client.post(
        f"/playground/quality/triage/escalations/{escalation_id}/acknowledge",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-escalation-1"},
    )
    assert acknowledge.status_code == 200
    assert acknowledge.json()["status"] == "acknowledged"

    notify = client.post(
        f"/playground/quality/triage/escalations/{escalation_id}/notify",
        json={
            "channel": "security-ops",
            "destination": "pagerduty://ai-trust-ops",
            "message_prefix": "Escalation alert",
        },
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-escalation-1"},
    )
    assert notify.status_code == 200
    assert notify.json()["notified"] is True
    assert notify.json()["channel"] == "security-ops"
    assert notify.json()["attempts"] == 1
    assert str(notify.json()["receipt_id"]).startswith("rcpt-")
    assert notify.json()["delivery_status"] == "sent"
    assert escalation_id in notify.json()["message"]

    resolve = client.post(
        f"/playground/quality/triage/escalations/{escalation_id}/resolve",
        json={"resolution_note": "False positive confirmed after manual review."},
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-escalation-1"},
    )
    assert resolve.status_code == 200
    assert resolve.json()["status"] == "resolved"
    assert resolve.json()["resolution_note"] == "False positive confirmed after manual review."


def test_playground_quality_analytics_rollups_support_dimensions_and_owner_scope():
    owner_one = "rollup-owner-1"
    owner_two = "rollup-owner-2"

    run_one = client.post(
        "/playground/runs",
        json={
            "prompt_text": "Rollup scenario one",
            "candidate_models": '["openai/gpt-4o-mini"]',
            "selected_model": "openai/gpt-4o-mini",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": owner_one},
    )
    assert run_one.status_code == 200
    run_one_id = run_one.json()["run_id"]

    run_two = client.post(
        "/playground/runs",
        json={
            "prompt_text": "Rollup scenario two",
            "candidate_models": '["azure:gpt-4o"]',
            "selected_model": "azure:gpt-4o",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": owner_two},
    )
    assert run_two.status_code == 200
    run_two_id = run_two.json()["run_id"]

    fb_one = client.post(
        f"/playground/runs/{run_one_id}/feedback",
        json={
            "trace_id": f"trace-{run_one_id}",
            "rating": 2,
            "quality_score": 0.42,
            "comment": "Borderline answer quality.",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": owner_one},
    )
    assert fb_one.status_code == 200

    fb_two = client.post(
        f"/playground/runs/{run_two_id}/feedback",
        json={
            "trace_id": f"trace-{run_two_id}",
            "rating": 5,
            "quality_score": 0.95,
            "comment": "High-quality answer.",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": owner_two},
    )
    assert fb_two.status_code == 200

    sec_rollups = client.get(
        "/playground/quality/analytics/rollups?window_hours=168&bucket_hours=24",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "rollup-sec-1"},
    )
    assert sec_rollups.status_code == 200
    sec_payload = sec_rollups.json()
    assert sec_payload["total_samples"] >= 2
    assert any(bucket["provider_id"] == "openai" for bucket in sec_payload["buckets"])
    assert any(bucket["provider_id"] == "azure" for bucket in sec_payload["buckets"])

    owner_rollups = client.get(
        "/playground/quality/analytics/rollups?window_hours=168&bucket_hours=24",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": owner_one},
    )
    assert owner_rollups.status_code == 200
    owner_payload = owner_rollups.json()
    assert owner_payload["total_samples"] >= 1
    assert all(bucket["provider_id"] == "openai" for bucket in owner_payload["buckets"])


def test_cost_model_catalog_ranks_supported_models_using_pricing_data():
    headers = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": "model-catalog-admin", "X-MFA-Verified": "true"}
    fast_model_name = f"fast-{uuid4()}"
    deep_model_name = f"deep-{uuid4()}"

    fast_model = client.post(
        "/providers/models",
        json={
            "provider_type": "openai",
            "model_name": fast_model_name,
            "display_name": "Fast Model",
            "context_window_tokens": 64000,
            "status": "active",
            "description": "Fast ranking test model",
        },
        headers=headers,
    )
    assert fast_model.status_code == 200

    deep_model = client.post(
        "/providers/models",
        json={
            "provider_type": "openai",
            "model_name": deep_model_name,
            "display_name": "Deep Model",
            "context_window_tokens": 128000,
            "status": "active",
            "description": "Deep ranking test model",
        },
        headers=headers,
    )
    assert deep_model.status_code == 200

    catalog_resp = client.get(
        "/cost/models/catalog",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "model-catalog-admin"},
    )
    assert catalog_resp.status_code == 200
    catalog = catalog_resp.json()["catalog"]
    fast_row = next(row for row in catalog if row["model_name"] == fast_model_name)
    deep_row = next(row for row in catalog if row["model_name"] == deep_model_name)
    assert fast_row["estimated_average_cost_cents_per_1k"] > 0
    assert deep_row["estimated_average_cost_cents_per_1k"] > 0
    assert deep_row["ranking_score"] > fast_row["ranking_score"]


def test_supported_model_catalog_tracks_explainability_and_approval_versions():
    admin_headers = {
        "X-Actor-Role": "Platform Admin",
        "X-Actor-Id": "model-meta-admin",
        "X-MFA-Verified": "true",
    }
    model_name = f"governed-{uuid4()}"

    created = client.post(
        "/providers/models",
        json={
            "provider_type": "openai",
            "model_name": model_name,
            "display_name": "Governed Model",
            "context_window_tokens": 128000,
            "status": "active",
            "description": "Governed model for approvals",
            "recommendation_rationale": "Recommended for low-latency support workloads.",
        },
        headers=admin_headers,
    )
    assert created.status_code == 200
    created_body = created.json()
    supported_model_id = created_body["supported_model_id"]
    assert created_body["metadata_version"] == 1
    assert created_body["approval_status"] == "pending"

    updated = client.put(
        f"/providers/models/{supported_model_id}",
        json={
            "provider_type": "openai",
            "model_name": model_name,
            "display_name": "Governed Model",
            "context_window_tokens": 256000,
            "status": "beta",
            "description": "Governed model awaiting review",
            "recommendation_rationale": "Expanded context for retrieval-heavy operators.",
        },
        headers=admin_headers,
    )
    assert updated.status_code == 200
    updated_body = updated.json()
    assert updated_body["metadata_version"] == 2
    assert updated_body["approval_status"] == "pending"

    denied_prod = client.post(
        f"/providers/models/{supported_model_id}/approve",
        json={
            "decision": "approve",
            "approval_ticket_ref": "CHG-SM-001",
            "approval_note": "Production approval requires dual approval.",
            "environment": "prod",
        },
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-approver-1", "X-MFA-Verified": "true"},
    )
    assert denied_prod.status_code == 403
    assert denied_prod.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    approved = client.post(
        f"/providers/models/{supported_model_id}/approve",
        json={
            "decision": "approve",
            "approval_ticket_ref": "CHG-SM-001",
            "approval_note": "Risk reviewed; approve for controlled production use.",
            "environment": "prod",
        },
        headers={
            "X-Actor-Role": "Platform Admin",
            "X-Actor-Id": "platform-admin-1",
            "X-MFA-Verified": "true",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-approver-2",
        },
    )
    assert approved.status_code == 200
    approved_body = approved.json()
    assert approved_body["approval_status"] == "approved"
    assert approved_body["approval_ticket_ref"] == "CHG-SM-001"
    assert approved_body["approved_by"] == "platform-admin-1"
    assert approved_body["metadata_version"] == 3
    assert approved_body["recommendation_rationale"] == "Expanded context for retrieval-heavy operators."


def test_cost_pricing_catalog_and_calculate_support_discounts():
    catalog = client.get(
        "/cost/pricing/catalog",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "cost-pricing-admin"},
    )
    assert catalog.status_code == 200
    body = catalog.json()
    assert "default_model_rates" in body
    assert "provider_discounts" in body

    calculated = client.post(
        "/cost/pricing/calculate",
        json={
            "provider_type": "openai",
            "model_name": "gpt-4o-mini",
            "endpoint_family": "responses",
            "input_tokens": 2000,
            "output_tokens": 1000,
            "custom_provider_discount_percent": 10,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "cost-pricing-admin"},
    )
    assert calculated.status_code == 200
    payload = calculated.json()
    assert payload["base_cost_cents"] >= payload["estimated_cost_cents"]
    assert payload["applied_discount_percent"] >= 10


def test_cost_track_event_supports_request_tag_and_timeseries_dimension():
    session_id = f"session-tag-{uuid4()}"
    request_id = f"req-tag-{uuid4()}"
    request_tag = f"billing.batch-{str(uuid4())[:8]}"

    tracked = client.post(
        "/cost/events",
        json={
            "request_id": request_id,
            "trace_id": f"trace-{request_id}",
            "request_tag": request_tag,
            "session_id": session_id,
            "agent_id": "agent-tag-track",
            "scope_type": "actor",
            "scope_id": "cost-track-admin",
            "environment": "dev",
            "model_name": "gpt-4o-mini",
            "endpoint_family": "responses",
            "input_tokens": 100,
            "output_tokens": 50,
            "estimated_cost_cents": 25,
            "currency": "USD",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "cost-track-admin"},
    )
    assert tracked.status_code == 200
    event = tracked.json()
    assert event["request_tag"] == request_tag

    session_rows = client.get(
        f"/cost/sessions/{session_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "cost-track-admin"},
    )
    assert session_rows.status_code == 200
    assert any(row.get("request_tag") == request_tag for row in session_rows.json())

    timeseries = client.get(
        f"/cost/timeseries?dimension=request_tag&window_hours=24&scope_filter={request_tag}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "cost-track-admin"},
    )
    assert timeseries.status_code == 200
    timeseries_payload = timeseries.json()
    assert timeseries_payload["dimension"] == "request_tag"
    assert timeseries_payload["total_event_count"] >= 1


def test_compliance_retention_policy_and_legal_hold_lifecycle():
    policy_create = client.post(
        "/compliance/retention/policies",
        json={
            "data_class": "audit_logs",
            "jurisdiction": "us",
            "retention_days": 365,
            "deletion_mode": "soft_delete",
            "legal_hold_supported": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-retention"},
    )
    assert policy_create.status_code == 200
    policy_id = policy_create.json()["policy_id"]
    assert policy_create.json()["data_class"] == "audit_logs"

    policy_update = client.patch(
        f"/compliance/retention/policies/{policy_id}",
        json={"retention_days": 730, "status": "active"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-retention"},
    )
    assert policy_update.status_code == 200
    assert policy_update.json()["retention_days"] == 730

    policy_list = client.get(
        "/compliance/retention/policies",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-retention"},
    )
    assert policy_list.status_code == 200
    assert any(p["policy_id"] == policy_id for p in policy_list.json())

    hold_create = client.post(
        "/compliance/legal-holds",
        json={
            "data_class": "audit_logs",
            "jurisdiction": "us",
            "reason": "regulatory inquiry",
            "scope_ref": "tenant:tenant-1",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-legal-hold"},
    )
    assert hold_create.status_code == 200
    hold_id = hold_create.json()["hold_id"]
    assert hold_create.json()["status"] == "active"

    active_holds = client.get(
        "/compliance/legal-holds?status=active",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-legal-hold"},
    )
    assert active_holds.status_code == 200
    assert any(h["hold_id"] == hold_id for h in active_holds.json())

    release = client.post(
        f"/compliance/legal-holds/{hold_id}/release",
        json={"reason_code": "closure"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-legal-hold"},
    )
    assert release.status_code == 200
    assert release.json()["status"] == "released"
    assert release.json()["released_by"] == "admin-legal-hold"


def test_compliance_evidence_generation_and_bundle_lineage():
    controls_resp = client.get(
        "/compliance/controls",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-evidence"},
    )
    assert controls_resp.status_code == 200
    control_id = controls_resp.json()[0]["control_id"]

    from app.database import SessionLocal
    from app.models import ComplianceEvidenceArtifact

    db = SessionLocal()
    try:
        malformed_rows = db.query(ComplianceEvidenceArtifact).filter_by(control_id=control_id).all()
        for row in malformed_rows:
            if not str(row.integrity_hash or "").startswith("sha256:"):
                row.integrity_hash = f"sha256:normalized-{uuid4().hex}"
        db.commit()
    finally:
        db.close()

    generated = client.post(
        f"/compliance/evidence/{control_id}/generate",
        json={"source_type": "audit_events", "source_id": "window-last-24h"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-evidence"},
    )
    assert generated.status_code == 200
    generated_payload = generated.json()
    assert generated_payload["control_id"] == control_id
    assert generated_payload["source_type"] == "audit_events"
    assert generated_payload["policy_version"] == "v1"
    assert generated_payload["artifact_uri"].startswith("evidence://controls/")

    bundle = client.get(
        f"/compliance/evidence/{control_id}/bundle",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-evidence"},
    )
    assert bundle.status_code == 200
    bundle_payload = bundle.json()
    assert bundle_payload["control_id"] == control_id
    assert isinstance(bundle_payload["evidence_items"], list)
    assert any(a["evidence_id"] == generated_payload["evidence_id"] for a in bundle_payload["artifacts"])
    assert bundle_payload["artifact_count"] >= 1
    assert bundle_payload["latest_artifact_at"] is not None
    assert bundle_payload["integrity_status"] == "pass"

    bundle_audit = client.get(
        f"/audit/events?action_type=compliance.evidence.bundle.retrieve&resource_type=control&resource_id={control_id}&decision_outcome=allow&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-evidence"},
    )
    assert bundle_audit.status_code == 200
    assert any(evt["actor_id"] == "aud-evidence" for evt in bundle_audit.json())


def test_compliance_evidence_bundle_fail_closed_on_malformed_integrity_hash():
    controls_resp = client.get(
        "/compliance/controls",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-evidence-integrity"},
    )
    assert controls_resp.status_code == 200
    control_id = controls_resp.json()[0]["control_id"]

    generated = client.post(
        f"/compliance/evidence/{control_id}/generate",
        json={"source_type": "audit_events", "source_id": "window-last-24h"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-evidence-integrity"},
    )
    assert generated.status_code == 200
    evidence_id = generated.json()["evidence_id"]

    from app.database import SessionLocal
    from app.models import ComplianceEvidenceArtifact

    db = SessionLocal()
    original_hash = None
    try:
        artifact = db.query(ComplianceEvidenceArtifact).filter_by(evidence_id=evidence_id).first()
        assert artifact is not None
        original_hash = artifact.integrity_hash
        artifact.integrity_hash = "md5:broken"
        db.commit()
        bundle = client.get(
            f"/compliance/evidence/{control_id}/bundle",
            headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-evidence-integrity"},
        )
        assert bundle.status_code == 409
        assert response_error_code(bundle) == "RESOURCE_CONFLICT"
        assert "integrity check failed" in response_error_message(bundle)

        deny_audit = client.get(
            f"/audit/events?action_type=compliance.evidence.bundle.retrieve&resource_type=control&resource_id={control_id}&decision_outcome=deny&limit=20",
            headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-evidence-integrity"},
        )
        assert deny_audit.status_code == 200
        assert any(evt["actor_id"] == "aud-evidence-integrity" for evt in deny_audit.json())
    finally:
        artifact = db.query(ComplianceEvidenceArtifact).filter_by(evidence_id=evidence_id).first()
        if artifact is not None:
            artifact.integrity_hash = original_hash or f"sha256:restored-{uuid4().hex}"
            db.commit()
        db.close()


def test_compliance_evidence_bundle_supports_scoped_filters_and_limits():
    controls_resp = client.get(
        "/compliance/controls",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-evidence-scope"},
    )
    assert controls_resp.status_code == 200
    control_id = controls_resp.json()[0]["control_id"]

    gen_audit = client.post(
        f"/compliance/evidence/{control_id}/generate",
        json={"source_type": "audit_events", "source_id": "latest-audit"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-evidence-scope"},
    )
    assert gen_audit.status_code == 200

    gen_trace = client.post(
        f"/compliance/evidence/{control_id}/generate",
        json={"source_type": "trace_events", "source_id": "latest-trace"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-evidence-scope"},
    )
    assert gen_trace.status_code == 200

    from app.database import SessionLocal
    from app.services.audit import create_audit_event

    db = SessionLocal()
    try:
        create_audit_event(
            db,
            actor_id="admin-evidence-scope",
            action_type=f"compliance.scope.test.{uuid4().hex[:8]}",
            resource_type="control",
            resource_id=control_id,
            trace_id=f"trace-compliance-scope-{uuid4().hex[:8]}",
            decision_outcome="allow",
            tenant_id="tenant-scope-a",
            environment="prod",
        )
        create_audit_event(
            db,
            actor_id="admin-evidence-scope",
            action_type=f"compliance.scope.test.{uuid4().hex[:8]}",
            resource_type="control",
            resource_id=control_id,
            trace_id=f"trace-compliance-scope-{uuid4().hex[:8]}",
            decision_outcome="allow",
            tenant_id="tenant-scope-b",
            environment="dev",
        )
        db.commit()
    finally:
        db.close()

    scoped = client.get(
        f"/compliance/evidence/{control_id}/bundle?since_hours=24&decision_outcome=allow&action_type_prefix=compliance.scope.test.&tenant_id=tenant-scope-a&environment=prod&source_type=trace_events&source_id_prefix=latest-&limit_events=5&limit_artifacts=5",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-evidence-scope"},
    )
    assert scoped.status_code == 200
    payload = scoped.json()
    assert payload["artifact_count"] >= 1
    assert all(item["source_type"] == "trace_events" for item in payload["artifacts"])
    assert payload["evidence_items"]
    assert all("compliance.scope.test." in item for item in payload["evidence_items"])


def test_compliance_evidence_bundle_rejects_invalid_decision_outcome_filter():
    controls_resp = client.get(
        "/compliance/controls",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-evidence-invalid-filter"},
    )
    assert controls_resp.status_code == 200
    control_id = controls_resp.json()[0]["control_id"]

    invalid = client.get(
        f"/compliance/evidence/{control_id}/bundle?decision_outcome=blocked",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-evidence-invalid-filter"},
    )
    assert invalid.status_code == 400
    assert response_error_code(invalid) == "VALIDATION_ERROR"
    assert "decision_outcome must be one of" in response_error_message(invalid)


def test_benchmark_scan_and_agentic_readiness_flow():
    bench_payload = post_benchmark_run_and_wait(
        client,
        {"agent_id": "agent-a", "benchmark_suite": "reliability-core", "environment": "staging"},
        {"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-1"},
    )
    assert bench_payload["status"] == "completed"

    scan_payload = post_scan_run_and_wait(
        client,
        {"agent_id": "agent-a", "scan_type": "security", "environment": "staging"},
        {"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-1", "X-MFA-Verified": "true"},
    )
    assert scan_payload["status"] == "completed"

    validate_resp = client.post(
        "/agentic/contracts/validate",
        json={
            "agent_id": "agent-a",
            "module_ids": ["mod-1"],
            "route_policy_snapshot_id": "snap-1",
            "required_capabilities": ["observability", "budget-control"],
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-1"},
    )
    assert validate_resp.status_code == 200
    assert validate_resp.json()["status"] == "pass"

    readiness_resp = client.get(
        "/agentic/readiness/report",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-1"},
    )
    assert readiness_resp.status_code == 200
    assert "readiness_score" in readiness_resp.json()
    assert "scale_tier3_certified" in readiness_resp.json()
    assert "certified_user_capacity" in readiness_resp.json()


def test_benchmark_and_scan_enforce_agent_owner_scope():
    from app.database import SessionLocal
    from app.models import Agent

    db = SessionLocal()
    try:
        own_agent = Agent(
            agent_id=f"agent-owned-bench-{uuid4()}",
            name="Owned Benchmark Agent",
            owner_id="owner-bench-1",
            owner_name="Owner Bench 1",
            owner_team="Team Bench 1",
            risk_tier="low",
            status="active",
        )
        other_agent = Agent(
            agent_id=f"agent-owned-scan-{uuid4()}",
            name="Owned Scan Agent",
            owner_id="owner-bench-2",
            owner_name="Owner Bench 2",
            owner_team="Team Bench 2",
            risk_tier="low",
            status="active",
        )
        db.add_all([own_agent, other_agent])
        db.commit()
        own_agent_id = own_agent.agent_id
        other_agent_id = other_agent.agent_id
    finally:
        db.close()

    own_benchmark = client.post(
        "/benchmarks/run",
        json={"agent_id": own_agent_id, "benchmark_suite": "reliability-core", "environment": "staging"},
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-bench-1", "X-MFA-Verified": "true"},
    )
    assert own_benchmark.status_code == 200

    cross_benchmark = client.post(
        "/benchmarks/run",
        json={"agent_id": other_agent_id, "benchmark_suite": "reliability-core", "environment": "staging"},
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-bench-1", "X-MFA-Verified": "true"},
    )
    assert cross_benchmark.status_code == 403
    assert cross_benchmark.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"

    own_scan = client.post(
        "/scans/run",
        json={"agent_id": own_agent_id, "scan_type": "security", "environment": "staging"},
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-bench-1", "X-MFA-Verified": "true"},
    )
    assert own_scan.status_code == 200

    cross_scan = client.post(
        "/scans/run",
        json={"agent_id": other_agent_id, "scan_type": "security", "environment": "staging"},
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-bench-1", "X-MFA-Verified": "true"},
    )
    assert cross_scan.status_code == 403
    assert cross_scan.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"

    admin_scan = client.post(
        "/scans/run",
        json={"agent_id": other_agent_id, "scan_type": "security", "environment": "staging"},
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-bench-1", "X-MFA-Verified": "true"},
    )
    assert admin_scan.status_code == 200


def test_benchmark_scan_history_list_filters_and_pagination():
    history_headers = {"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-history-1"}
    bench_one = client.post(
        "/benchmarks/run",
        json={"agent_id": "agent-history-a", "benchmark_suite": "reliability-core", "environment": "dev"},
        headers=history_headers,
    )
    bench_two = client.post(
        "/benchmarks/run",
        json={"agent_id": "agent-history-a", "benchmark_suite": "latency-core", "environment": "prod"},
        headers=history_headers,
    )
    scan_one = client.post(
        "/scans/run",
        json={"agent_id": "agent-history-a", "scan_type": "security", "environment": "dev"},
        headers={**history_headers, "X-MFA-Verified": "true"},
    )
    scan_two = client.post(
        "/scans/run",
        json={"agent_id": "agent-history-a", "scan_type": "compliance", "environment": "prod"},
        headers={**history_headers, "X-MFA-Verified": "true"},
    )
    assert bench_one.status_code == 200
    assert bench_two.status_code == 200
    assert scan_one.status_code == 200
    assert scan_two.status_code == 200
    wait_for_benchmark_run(client, bench_one.json()["benchmark_run_id"], history_headers)
    wait_for_benchmark_run(client, bench_two.json()["benchmark_run_id"], history_headers)
    wait_for_scan_run(client, scan_one.json()["scan_run_id"], {**history_headers, "X-MFA-Verified": "true"})
    wait_for_scan_run(client, scan_two.json()["scan_run_id"], {**history_headers, "X-MFA-Verified": "true"})

    benchmark_history = client.get(
        "/benchmarks/runs?agent_id=agent-history-a&environment=dev&limit=10&offset=0",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-history-1"},
    )
    assert benchmark_history.status_code == 200
    assert "x-total-count" in benchmark_history.headers
    assert len(benchmark_history.json()) >= 1
    assert all(row["agent_id"] == "agent-history-a" for row in benchmark_history.json())
    assert all(row["environment"] == "dev" for row in benchmark_history.json())

    scan_history = client.get(
        "/scans/runs?agent_id=agent-history-a&scan_type=security&limit=10&offset=0",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-history-1"},
    )
    assert scan_history.status_code == 200
    assert "x-total-count" in scan_history.headers
    assert len(scan_history.json()) >= 1
    assert all(row["agent_id"] == "agent-history-a" for row in scan_history.json())
    assert all(row["scan_type"] == "security" for row in scan_history.json())


def test_benchmark_scan_history_agent_owner_scope_guard():
    from app.database import SessionLocal
    from app.models import Agent

    db = SessionLocal()
    try:
        owned_agent = Agent(
            agent_id=f"agent-history-owned-{uuid4()}",
            name="Owned History Agent",
            owner_id="owner-history-1",
            owner_name="Owner History 1",
            owner_team="Team History",
            risk_tier="low",
            status="active",
        )
        foreign_agent = Agent(
            agent_id=f"agent-history-foreign-{uuid4()}",
            name="Foreign History Agent",
            owner_id="owner-history-2",
            owner_name="Owner History 2",
            owner_team="Team Foreign",
            risk_tier="low",
            status="active",
        )
        db.add_all([owned_agent, foreign_agent])
        db.commit()
        owned_agent_id = owned_agent.agent_id
        foreign_agent_id = foreign_agent.agent_id
    finally:
        db.close()

    own_bench = client.post(
        "/benchmarks/run",
        json={"agent_id": owned_agent_id, "benchmark_suite": "reliability-core", "environment": "dev"},
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-history-1", "X-MFA-Verified": "true"},
    )
    own_scan = client.post(
        "/scans/run",
        json={"agent_id": owned_agent_id, "scan_type": "security", "environment": "dev"},
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-history-1", "X-MFA-Verified": "true"},
    )
    assert own_bench.status_code == 200
    assert own_scan.status_code == 200

    denied_bench = client.get(
        f"/benchmarks/runs?agent_id={foreign_agent_id}",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-history-1"},
    )
    denied_scan = client.get(
        f"/scans/runs?agent_id={foreign_agent_id}",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-history-1"},
    )
    assert denied_bench.status_code == 403
    assert denied_scan.status_code == 403
    assert denied_bench.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"
    assert denied_scan.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"


def test_agentic_readiness_certification_run_and_retrieval():
    post_benchmark_run_and_wait(
        client,
        {"agent_id": "agent-cert", "benchmark_suite": "scale-tier3-100k", "environment": "prod"},
        {"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-cert"},
    )
    post_scan_run_and_wait(
        client,
        {"agent_id": "agent-cert", "scan_type": "security", "environment": "prod"},
        {"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-cert", "X-MFA-Verified": "true"},
    )

    validate_resp = client.post(
        "/agentic/contracts/validate",
        json={
            "agent_id": "agent-cert",
            "module_ids": ["mod-cert"],
            "route_policy_snapshot_id": "snap-cert",
            "required_capabilities": ["observability"],
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-cert"},
    )
    assert validate_resp.status_code == 200

    from app.database import SessionLocal
    from app.models import BenchmarkRun, CostEvent
    from app.services.audit import create_audit_event

    db = SessionLocal()
    try:
        db.add(
            BenchmarkRun(
                benchmark_run_id=str(uuid4()),
                agent_id="agent-cert",
                benchmark_suite="scale-tier3-100k",
                environment="prod",
                status="completed",
                score=90,
                summary="Scale benchmark passed for tier-3 target.",
            )
        )
        db.add(
            CostEvent(
                cost_event_id=str(uuid4()),
                request_id="req-cert-1",
                trace_id="trace-cert-1",
                session_id="sess-cert-1",
                agent_id="agent-cert",
                owner_scope="team:cert",
                environment="prod",
                model_name="gpt-test",
                endpoint_family="responses",
                input_tokens=10,
                output_tokens=10,
                estimated_cost_cents=1,
                currency="USD",
            )
        )
        create_audit_event(
            db,
            actor_id="platform-cert",
            action_type="infra.multi_region.failover.drill",
            resource_type="infra",
            resource_id="us-east-to-eu-west",
            trace_id="trace-mr-cert",
            decision_outcome="allow",
        )
        db.commit()
    finally:
        db.close()

    cert_run = client.post(
        "/agentic/readiness/certifications/run",
        json={
            "target_capacity": 100000,
            "require_multi_region": True,
            "cost_freshness_slo_seconds": 60,
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-cert", "X-MFA-Verified": "true"},
    )
    assert cert_run.status_code == 200
    cert_payload = cert_run.json()
    assert cert_payload["target_capacity"] == 100000
    assert cert_payload["required_multi_region"] is True
    assert cert_payload["scale_benchmark_pass"] is True
    assert cert_payload["contract_validation_pass"] is True
    assert cert_payload["cost_freshness_pass"] is True
    assert cert_payload["multi_region_pass"] is True
    assert cert_payload["certified"] is True
    assert cert_payload["certified_user_capacity"] == 100000
    assert cert_payload["integrity_hash"].startswith("sha256:")
    assert cert_payload["signature"].startswith("sig:")

    latest = client.get(
        "/agentic/readiness/certifications/latest",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-cert"},
    )
    assert latest.status_code == 200
    assert latest.json()["certification_id"] == cert_payload["certification_id"]

    listing = client.get(
        "/agentic/readiness/certifications?limit=5",
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-cert"},
    )
    assert listing.status_code == 200
    assert any(run["certification_id"] == cert_payload["certification_id"] for run in listing.json())

    export_resp = client.get(
        f"/agentic/readiness/certifications/{cert_payload['certification_id']}/export",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-cert"},
    )
    assert export_resp.status_code == 200
    export_payload = export_resp.json()
    assert export_payload["certification"]["certification_id"] == cert_payload["certification_id"]
    assert export_payload["export_uri"].startswith("evidence://readiness-certifications/")
    assert export_payload["audit_event_count"] >= 1
    assert isinstance(export_payload["evidence_items"], list)

    override_resp = client.post(
        f"/agentic/readiness/certifications/{cert_payload['certification_id']}/override",
        json={"reason_code": "incident-override"},
        headers={
            "X-Actor-Role": "Release Manager",
            "X-Actor-Id": "rel-cert",
            "X-MFA-Verified": "true",
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-cert",
        },
    )
    assert override_resp.status_code == 200
    assert override_resp.json()["override_applied"] is True


def test_agentic_execution_checkpoint_create_list_and_resume():
    session_id = f"sess-ckpt-{uuid4()}"

    created = client.post(
        "/agentic/checkpoints",
        json={
            "session_id": session_id,
            "agent_id": "agent-ckpt",
            "stage_name": "tool-call-stage",
            "state_payload": '{"step": 3, "pending_tool": "search"}',
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-ckpt", "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    checkpoint_id = created.json()["checkpoint_id"]
    assert created.json()["status"] == "active"

    listing = client.get(
        f"/agentic/checkpoints/{session_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-ckpt"},
    )
    assert listing.status_code == 200
    assert any(row["checkpoint_id"] == checkpoint_id for row in listing.json())

    denied = client.post(
        f"/agentic/checkpoints/{checkpoint_id}/resume",
        json={"reason_code": "operator-retry"},
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-ckpt", "X-MFA-Verified": "true"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    resumed = client.post(
        f"/agentic/checkpoints/{checkpoint_id}/resume",
        json={"reason_code": "operator-retry"},
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-ckpt", "X-MFA-Verified": "true"},
    )
    assert resumed.status_code == 200
    assert resumed.json()["status"] == "resumed"
    assert resumed.json()["resume_count"] == 1
    assert resumed.json()["resumed_by"] == "rel-ckpt"


def test_modules_register_requires_signature_provenance_and_security_review():
    invalid_signature = client.post(
        "/modules/register",
        json={
            "module_name": "runtime-guard",
            "module_type": "runtime",
            "version": "1.2.0",
            "contract_version": "2026-06-01",
            "owner_team": "platform",
            "artifact_signature": "bad-signature",
            "provenance_ref": "prov://builds/runtime-guard/1.2.0",
            "security_review_ticket": "SEC-1200",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-mod"},
    )
    assert invalid_signature.status_code == 400

    missing_review = client.post(
        "/modules/register",
        json={
            "module_name": "runtime-guard",
            "module_type": "runtime",
            "version": "1.2.0",
            "contract_version": "2026-06-01",
            "owner_team": "platform",
            "artifact_signature": "sig:runtime-guard-1.2.0",
            "provenance_ref": "prov://builds/runtime-guard/1.2.0",
            "security_review_ticket": "",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-mod"},
    )
    assert missing_review.status_code == 400

    created = client.post(
        "/modules/register",
        json={
            "module_name": "runtime-guard",
            "module_type": "runtime",
            "version": "1.2.0",
            "contract_version": "2026-06-01",
            "owner_team": "platform",
            "compatibility_range": "major:1",
            "artifact_signature": "sig:runtime-guard-1.2.0",
            "provenance_ref": "prov://builds/runtime-guard/1.2.0",
            "security_review_ticket": "SEC-1200",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-mod"},
    )
    assert created.status_code == 200
    payload = created.json()
    assert payload["artifact_signature"].startswith("sig:")
    assert payload["provenance_ref"].startswith("prov://")
    assert payload["security_review_ticket"] == "SEC-1200"


def test_modules_validate_and_upgrade_plan_enforce_version_compatibility():
    created = client.post(
        "/modules/register",
        json={
            "module_name": "policy-engine",
            "module_type": "control-plane",
            "version": "2.4.1",
            "contract_version": "2026-06-01",
            "owner_team": "governance",
            "compatibility_range": "major:2",
            "artifact_signature": "sig:policy-engine-2.4.1",
            "provenance_ref": "prov://builds/policy-engine/2.4.1",
            "security_review_ticket": "",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-mod"},
    )
    assert created.status_code == 200
    module_id = created.json()["module_id"]

    mismatched_pin = client.post(
        "/agents/agent-42/modules/validate",
        json={"module_id": module_id, "pinned_version": "2.3.0", "config_hash": "cfg-42"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-mod"},
    )
    assert mismatched_pin.status_code == 400

    valid = client.post(
        "/agents/agent-42/modules/validate",
        json={"module_id": module_id, "pinned_version": "2.4.1", "config_hash": "cfg-42"},
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-42"},
    )
    assert valid.status_code == 200
    assert valid.json()["validation_status"] == "valid"

    incompatible_upgrade = client.post(
        "/agents/agent-42/modules/upgrade-plan",
        json={"module_id": module_id, "pinned_version": "1.9.9", "config_hash": "cfg-42"},
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-42"},
    )
    assert incompatible_upgrade.status_code == 400

    upgrade_ready = client.post(
        "/agents/agent-42/modules/upgrade-plan",
        json={"module_id": module_id, "pinned_version": "2.4.1", "config_hash": "cfg-42"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-mod"},
    )
    assert upgrade_ready.status_code == 200
    assert upgrade_ready.json()["plan_status"] == "ready"


def test_modules_deprecation_with_migration_guidance_and_timeline():
    replacement = client.post(
        "/modules/register",
        json={
            "module_name": "policy-engine-v3",
            "module_type": "control-plane",
            "version": "3.0.0",
            "contract_version": "2026-06-01",
            "owner_team": "governance",
            "compatibility_range": "major:3",
            "artifact_signature": "sig:policy-engine-v3-3.0.0",
            "provenance_ref": "prov://builds/policy-engine-v3/3.0.0",
            "security_review_ticket": "",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-mod"},
    )
    assert replacement.status_code == 200
    replacement_module_id = replacement.json()["module_id"]

    legacy = client.post(
        "/modules/register",
        json={
            "module_name": "policy-engine-v2",
            "module_type": "control-plane",
            "version": "2.9.0",
            "contract_version": "2026-06-01",
            "owner_team": "governance",
            "compatibility_range": "major:2",
            "artifact_signature": "sig:policy-engine-v2-2.9.0",
            "provenance_ref": "prov://builds/policy-engine-v2/2.9.0",
            "security_review_ticket": "",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-mod"},
    )
    assert legacy.status_code == 200
    legacy_module_id = legacy.json()["module_id"]

    deprecate = client.post(
        f"/modules/{legacy_module_id}/deprecate",
        json={
            "replacement_module_id": replacement_module_id,
            "migration_guidance": "Move to policy-engine-v3 and re-run compatibility validation.",
            "deprecation_timeline": "sunset-2026-12-31",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-mod"},
    )
    assert deprecate.status_code == 200
    payload = deprecate.json()
    assert payload["status"] == "deprecated"
    assert payload["replacement_module_id"] == replacement_module_id
    assert payload["migration_guidance"].startswith("Move to")
    assert payload["deprecation_timeline"] == "sunset-2026-12-31"
    assert payload["deprecated_at"] is not None

    validate_denied = client.post(
        "/agents/agent-99/modules/validate",
        json={"module_id": legacy_module_id, "pinned_version": "2.9.0", "config_hash": "cfg-99"},
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-99"},
    )
    assert validate_denied.status_code == 409

    migration_plan = client.post(
        "/agents/agent-99/modules/upgrade-plan",
        json={"module_id": legacy_module_id, "pinned_version": "2.9.0", "config_hash": "cfg-99"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-mod"},
    )
    assert migration_plan.status_code == 200
    plan_payload = migration_plan.json()
    assert plan_payload["plan_status"] == "migration_required"
    assert plan_payload["replacement_module_id"] == replacement_module_id
    assert plan_payload["deprecation_timeline"] == "sunset-2026-12-31"


def test_modules_register_rejects_unknown_permissions_manifest():
    unknown_perm = client.post(
        "/modules/register",
        json={
            "module_name": "unknown-perm-mod",
            "module_type": "control-plane",
            "version": "1.0.0",
            "contract_version": "2026-06-01",
            "owner_team": "platform",
            "required_permissions": '["tools.read", "capability.unknown"]',
            "artifact_signature": "sig:unknown-perm-mod-1.0.0",
            "provenance_ref": "prov://builds/unknown-perm-mod/1.0.0",
            "security_review_ticket": "",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-mod"},
    )
    assert unknown_perm.status_code == 400
    assert "Unknown module permissions" in unknown_perm.json()["detail"]


def test_modules_validate_blocks_agent_owner_for_privileged_permissions():
    created = client.post(
        "/modules/register",
        json={
            "module_name": "privileged-module",
            "module_type": "gateway",
            "version": "4.1.0",
            "contract_version": "2026-06-01",
            "owner_team": "security",
            "required_permissions": '["tools.execute", "gateway.route.update"]',
            "artifact_signature": "sig:privileged-module-4.1.0",
            "provenance_ref": "prov://builds/privileged-module/4.1.0",
            "security_review_ticket": "SEC-4310",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-mod"},
    )
    assert created.status_code == 200
    module_id = created.json()["module_id"]

    denied = client.post(
        "/agents/agent-priv/modules/validate",
        json={"module_id": module_id, "pinned_version": "4.1.0", "config_hash": "cfg-priv"},
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-priv"},
    )
    assert denied.status_code == 403
    assert "privileged permissions" in denied.json()["detail"]

    allowed = client.post(
        "/agents/agent-priv/modules/validate",
        json={"module_id": module_id, "pinned_version": "4.1.0", "config_hash": "cfg-priv"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-mod"},
    )
    assert allowed.status_code == 200
    assert allowed.json()["validation_status"] == "valid"


def test_modules_read_endpoints_enforce_read_roles():
    created = client.post(
        "/modules/register",
        json={
            "module_name": "read-access-module",
            "module_type": "control-plane",
            "version": "1.0.1",
            "contract_version": "2026-06-01",
            "owner_team": "platform",
            "artifact_signature": "sig:read-access-module-1.0.1",
            "provenance_ref": "prov://builds/read-access-module/1.0.1",
            "security_review_ticket": "",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-mod-read"},
    )
    assert created.status_code == 200
    module_id = created.json()["module_id"]

    list_allowed = client.get(
        "/modules",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-mod-read"},
    )
    assert list_allowed.status_code == 200
    assert any(row["module_id"] == module_id for row in list_allowed.json())

    versions_allowed = client.get(
        f"/modules/{module_id}/versions",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-mod-read"},
    )
    assert versions_allowed.status_code == 200
    assert versions_allowed.json()["module_id"] == module_id

    list_denied = client.get(
        "/modules",
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "aiops-mod-read"},
    )
    assert list_denied.status_code == 403
    assert list_denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    versions_denied = client.get(
        f"/modules/{module_id}/versions",
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-mod-read"},
    )
    assert versions_denied.status_code == 403
    assert versions_denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"


def test_modules_register_ai_skill_requires_security_review_ticket():
    missing_review = client.post(
        "/modules/register",
        json={
            "module_name": "contract-extractor-skill",
            "module_type": "ai_skill",
            "version": "1.0.0",
            "contract_version": "2026-06-01",
            "owner_team": "ai-platform",
            "required_permissions": '["tools.read", "models.invoke"]',
            "artifact_signature": "sig:contract-extractor-skill-1.0.0",
            "provenance_ref": "prov://builds/contract-extractor-skill/1.0.0",
            "security_review_ticket": "",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-ai-skill"},
    )
    assert missing_review.status_code == 400


def test_modules_skills_endpoint_returns_only_skill_types():
    skill_created = client.post(
        "/modules/register",
        json={
            "module_name": "doc-summarizer-skill",
            "module_type": "ai_skill",
            "version": "2.0.0",
            "contract_version": "2026-06-01",
            "owner_team": "ai-platform",
            "required_permissions": '["tools.read", "models.invoke"]',
            "artifact_signature": "sig:doc-summarizer-skill-2.0.0",
            "provenance_ref": "prov://builds/doc-summarizer-skill/2.0.0",
            "security_review_ticket": "SEC-9200",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-ai-skill"},
    )
    assert skill_created.status_code == 200

    non_skill_created = client.post(
        "/modules/register",
        json={
            "module_name": "ops-observer",
            "module_type": "observability",
            "version": "1.0.0",
            "contract_version": "2026-06-01",
            "owner_team": "platform-ops",
            "required_permissions": '["observability.emit"]',
            "artifact_signature": "sig:ops-observer-1.0.0",
            "provenance_ref": "prov://builds/ops-observer/1.0.0",
            "security_review_ticket": "",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-ai-skill"},
    )
    assert non_skill_created.status_code == 200

    skills = client.get(
        "/modules/skills",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-ai-skills"},
    )
    assert skills.status_code == 200
    payload = skills.json()
    assert any(item["module_type"] in {"ai_skill", "skill"} for item in payload)
    assert all(item["module_type"] in {"ai_skill", "skill"} for item in payload)


def test_modules_register_persists_integration_metadata_and_sync_updates_status():
    created = client.post(
        "/modules/register",
        json={
            "module_name": "integration-aware-module",
            "module_type": "observability",
            "version": "1.0.0",
            "contract_version": "2026-06-01",
            "owner_team": "platform-ops",
            "required_permissions": '["observability.emit"]',
            "artifact_signature": "sig:integration-aware-module-1.0.0",
            "provenance_ref": "prov://builds/integration-aware-module/1.0.0",
            "security_review_ticket": "",
            "integration_provider": "github",
            "integration_reference": "github://org/repo/workflows/module-sync",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-module-int"},
    )
    assert created.status_code == 200
    payload = created.json()
    assert payload["integration_provider"] == "github"
    assert payload["integration_reference"].startswith("github://")
    assert payload["integration_sync_status"] == "pending"
    assert payload["integration_last_synced_at"] is None

    module_id = payload["module_id"]
    synced = client.post(
        f"/modules/{module_id}/integration/sync",
        json={"integration_reference": "github://org/repo/workflows/module-sync/v2"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-module-int"},
    )
    assert synced.status_code == 200
    sync_payload = synced.json()
    assert sync_payload["module_id"] == module_id
    assert sync_payload["integration_provider"] == "github"
    assert sync_payload["integration_sync_status"] == "synced"
    assert sync_payload["integration_last_synced_at"] is not None
    assert sync_payload["integration_reference"].endswith("/v2")


def test_modules_integration_sync_requires_configured_provider():
    created = client.post(
        "/modules/register",
        json={
            "module_name": "module-without-integration",
            "module_type": "observability",
            "version": "1.0.0",
            "contract_version": "2026-06-01",
            "owner_team": "platform-ops",
            "required_permissions": '["observability.emit"]',
            "artifact_signature": "sig:module-without-integration-1.0.0",
            "provenance_ref": "prov://builds/module-without-integration/1.0.0",
            "security_review_ticket": "",
            "integration_provider": "",
            "integration_reference": "",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-module-int"},
    )
    assert created.status_code == 200
    module_id = created.json()["module_id"]

    denied = client.post(
        f"/modules/{module_id}/integration/sync",
        json={},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-module-int"},
    )
    assert denied.status_code == 409


def test_modules_register_cursor_integration_reference_requires_workspace_scope():
    invalid_ref = client.post(
        "/modules/register",
        json={
            "module_name": "cursor-skill-invalid-ref",
            "module_type": "ai_skill",
            "version": "1.0.0",
            "contract_version": "2026-06-01",
            "owner_team": "ai-platform",
            "required_permissions": '["tools.read", "models.invoke"]',
            "artifact_signature": "sig:cursor-skill-invalid-ref-1.0.0",
            "provenance_ref": "prov://builds/cursor-skill-invalid-ref/1.0.0",
            "security_review_ticket": "SEC-9301",
            "integration_provider": "cursor",
            "integration_reference": "cursor://tenant/global",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-module-int"},
    )
    assert invalid_ref.status_code == 400
    assert "cursor://workspace/" in str(invalid_ref.json()["detail"])


def test_modules_cursor_integration_sync_rejects_invalid_reference_update():
    created = client.post(
        "/modules/register",
        json={
            "module_name": "cursor-skill-valid-ref",
            "module_type": "ai_skill",
            "version": "1.0.0",
            "contract_version": "2026-06-01",
            "owner_team": "ai-platform",
            "required_permissions": '["tools.read", "models.invoke"]',
            "artifact_signature": "sig:cursor-skill-valid-ref-1.0.0",
            "provenance_ref": "prov://builds/cursor-skill-valid-ref/1.0.0",
            "security_review_ticket": "SEC-9302",
            "integration_provider": "cursor",
            "integration_reference": "cursor://workspace/team-a/skills",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-module-int"},
    )
    assert created.status_code == 200
    module_id = created.json()["module_id"]

    invalid_sync = client.post(
        f"/modules/{module_id}/integration/sync",
        json={"integration_reference": "cursor://tenant/global"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-module-int"},
    )
    assert invalid_sync.status_code == 400
    assert "cursor://workspace/" in str(invalid_sync.json()["detail"])


def test_modules_cursor_legacy_invalid_reference_is_sanitized_on_readback():
    created = client.post(
        "/modules/register",
        json={
            "module_name": "cursor-skill-legacy-sanitize",
            "module_type": "ai_skill",
            "version": "1.0.0",
            "contract_version": "2026-06-01",
            "owner_team": "ai-platform",
            "required_permissions": '["tools.read", "models.invoke"]',
            "artifact_signature": "sig:cursor-skill-legacy-sanitize-1.0.0",
            "provenance_ref": "prov://builds/cursor-skill-legacy-sanitize/1.0.0",
            "security_review_ticket": "SEC-9303",
            "integration_provider": "cursor",
            "integration_reference": "cursor://workspace/team-a/skills",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-module-int"},
    )
    assert created.status_code == 200
    module_id = created.json()["module_id"]

    from app.database import SessionLocal
    from app.models import ModuleDefinition

    db = SessionLocal()
    try:
        module = db.query(ModuleDefinition).filter_by(module_id=module_id).first()
        assert module is not None
        module.integration_reference = "cursor://tenant/global"
        module.integration_sync_status = "synced"
        db.commit()
    finally:
        db.close()

    listed = client.get(
        "/modules",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-module-int"},
    )
    assert listed.status_code == 200
    row = next(item for item in listed.json() if item["module_id"] == module_id)
    assert row["integration_provider"] == "cursor"
    assert row["integration_reference"] == ""
    assert row["integration_sync_status"] == "invalid_reference"


def test_modules_cursor_legacy_invalid_reference_blocks_sync_without_override():
    created = client.post(
        "/modules/register",
        json={
            "module_name": "cursor-skill-legacy-sync-block",
            "module_type": "ai_skill",
            "version": "1.0.0",
            "contract_version": "2026-06-01",
            "owner_team": "ai-platform",
            "required_permissions": '["tools.read", "models.invoke"]',
            "artifact_signature": "sig:cursor-skill-legacy-sync-block-1.0.0",
            "provenance_ref": "prov://builds/cursor-skill-legacy-sync-block/1.0.0",
            "security_review_ticket": "SEC-9304",
            "integration_provider": "cursor",
            "integration_reference": "cursor://workspace/team-a/skills",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-module-int"},
    )
    assert created.status_code == 200
    module_id = created.json()["module_id"]

    from app.database import SessionLocal
    from app.models import ModuleDefinition

    db = SessionLocal()
    try:
        module = db.query(ModuleDefinition).filter_by(module_id=module_id).first()
        assert module is not None
        module.integration_reference = "cursor://tenant/global"
        db.commit()
    finally:
        db.close()

    denied = client.post(
        f"/modules/{module_id}/integration/sync",
        json={},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-module-int"},
    )
    assert denied.status_code == 400
    assert "cursor://workspace/" in str(denied.json()["detail"])

    fixed = client.post(
        f"/modules/{module_id}/integration/sync",
        json={"integration_reference": "cursor://workspace/team-b/skills"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-module-int"},
    )
    assert fixed.status_code == 200
    assert fixed.json()["integration_reference"] == "cursor://workspace/team-b/skills"


def test_agentic_scale_load_test_run_and_latest():
    run_resp = client.post(
        "/agentic/readiness/load-tests/run",
        json={
            "tier": "tier3",
            "target_capacity": 100000,
            "expected_concurrency": 2000,
            "expected_rps": 5000,
            "observed_peak_concurrency": 2400,
            "observed_peak_rps": 5600,
            "degradation_test_pass": True,
            "recovery_test_pass": True,
            "compliance_continuity_pass": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-load", "X-MFA-Verified": "true"},
    )
    assert run_resp.status_code == 200
    payload = run_resp.json()
    assert payload["tier"] == "tier3"
    assert payload["passed"] is True
    assert payload["summary"]

    latest = client.get(
        "/agentic/readiness/load-tests/latest?tier=tier3",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-load"},
    )
    assert latest.status_code == 200
    assert latest.json()["load_test_run_id"] == payload["load_test_run_id"]


def test_agentic_scale_load_test_run_requires_mfa():
    denied = client.post(
        "/agentic/readiness/load-tests/run",
        json={
            "tier": "tier1",
            "target_capacity": 10000,
            "expected_concurrency": 200,
            "expected_rps": 500,
            "observed_peak_concurrency": 220,
            "observed_peak_rps": 540,
            "degradation_test_pass": True,
            "recovery_test_pass": True,
            "compliance_continuity_pass": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rel-load-no-mfa"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_MFA_REQUIRED"


def test_compliance_control_mapping_catalog_endpoints():
    listing = client.get(
        "/compliance/controls/mappings",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-control-map"},
    )
    assert listing.status_code == 200
    assert len(listing.json()) >= 1

    upsert = client.put(
        "/compliance/controls/mappings/CTRL-CUSTOM-TEST",
        json={
            "control_family": "custom",
            "requirement_text": "Custom control for testing",
            "applicable_components": "[\"agentic\"]",
            "required_evidence_types": "[\"audit_events\"]",
            "automation_status": "automated",
            "owner_team": "platform-security",
            "review_frequency": "monthly",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-control-map"},
    )
    assert upsert.status_code == 200
    assert upsert.json()["control_id"] == "CTRL-CUSTOM-TEST"


def test_compliance_control_coverage_report_endpoint():
    coverage = client.get(
        "/compliance/controls/coverage",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-coverage"},
    )
    assert coverage.status_code == 200
    payload = coverage.json()
    assert payload["total_routes"] >= 1
    assert payload["covered_routes"] >= 1
    assert payload["uncovered_routes"] == 0
    assert payload["unknown_control_ids"] == []
    assert isinstance(payload["items"], list)
    assert any(item["path"] == "/compliance/controls/coverage" for item in payload["items"])


def test_compliance_control_evidence_freshness_endpoint():
    controls_resp = client.get(
        "/compliance/controls",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-freshness"},
    )
    assert controls_resp.status_code == 200
    control_id = controls_resp.json()[0]["control_id"]

    generated = client.post(
        f"/compliance/evidence/{control_id}/generate",
        json={"source_type": "audit_events", "source_id": "freshness-window"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-freshness"},
    )
    assert generated.status_code == 200

    freshness = client.get(
        "/compliance/controls/evidence-freshness?freshness_slo_hours=24",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-freshness"},
    )
    assert freshness.status_code == 200
    payload = freshness.json()
    assert payload["total_controls"] >= 1
    assert payload["controls_passing"] >= 1
    assert payload["controls_missing"] >= 0
    assert isinstance(payload["items"], list)
    assert any(item["control_id"] == control_id for item in payload["items"])


def test_agentic_policy_auto_tune_dry_run_and_apply():
    route = client.post(
        "/gateway/routes",
        json={
            "route_name": "phase3-auto-tune",
            "selection_mode": "manual",
            "load_balancing_strategy": "weighted",
            "fallback_policy": "secondary",
            "timeout_policy": "2s",
            "status": "active",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert route.status_code == 200
    route_policy_id = route.json()["route_policy_id"]

    dry_run = client.post(
        "/agentic/policy/auto-tune",
        json={"environment": "prod", "optimize_for": "cost", "max_routes": 5, "dry_run": True},
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-1"},
    )
    assert dry_run.status_code == 200
    assert dry_run.json()["dry_run"] is True

    apply_run = client.post(
        "/agentic/policy/auto-tune",
        json={"environment": "prod", "optimize_for": "cost", "max_routes": 5, "dry_run": False},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert apply_run.status_code == 200
    assert apply_run.json()["dry_run"] is False
    assert apply_run.json()["total_routes_evaluated"] >= 1

    route_after = client.get(
        "/gateway/routes",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-gateway-routes"},
    )
    assert route_after.status_code == 200
    updated_route = [r for r in route_after.json() if r["route_policy_id"] == route_policy_id][0]
    assert updated_route["load_balancing_strategy"] in {"lowest_cost", "weighted", "lowest_latency"}


def test_agentic_policy_scheduled_optimize_window_and_approval_thresholds():
    route = client.post(
        "/gateway/routes",
        json={
            "route_name": "aaa-phase3-scheduled-optimize",
            "selection_mode": "manual",
            "load_balancing_strategy": "lowest_latency",
            "fallback_policy": "secondary",
            "timeout_policy": "2s",
            "status": "active",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert route.status_code == 200

    now_hour = datetime.utcnow().hour
    start_hour = (now_hour + 1) % 24
    end_hour = (now_hour + 2) % 24

    deferred = client.post(
        "/agentic/policy/scheduled-optimize",
        json={
            "environment": "prod",
            "optimize_for": "cost",
            "max_routes": 100,
            "window_start_hour_utc": start_hour,
            "window_end_hour_utc": end_hour,
            "max_changes_without_approval": 0,
            "dry_run": False,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-1"},
    )
    assert deferred.status_code == 200
    assert deferred.json()["executed"] is False
    assert deferred.json()["execution_status"] == "deferred_window"

    waiting = client.post(
        "/agentic/policy/scheduled-optimize",
        json={
            "environment": "prod",
            "optimize_for": "cost",
            "max_routes": 100,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 0,
            "dry_run": False,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert waiting.status_code == 200
    waiting_body = waiting.json()
    assert waiting_body["approval_required"] is (waiting_body["proposed_changes"] > 0)
    if waiting_body["approval_required"]:
        assert waiting_body["approved"] is False
        assert waiting_body["executed"] is False
        assert waiting_body["execution_status"] == "waiting_approval"
    else:
        assert waiting_body["approved"] is True
        assert waiting_body["executed"] is True
        assert waiting_body["execution_status"] == "applied"

    applied = client.post(
        "/agentic/policy/scheduled-optimize",
        json={
            "environment": "prod",
            "optimize_for": "cost",
            "max_routes": 100,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 0,
            "approval_token": "approved",
            "dry_run": False,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert applied.status_code == 200
    applied_body = applied.json()
    assert applied_body["approval_required"] is (applied_body["proposed_changes"] > 0)
    assert applied_body["approved"] is True
    assert applied_body["executed"] is True
    assert applied_body["execution_status"] == "applied"


def test_agentic_policy_schedule_create_list_and_execute_now():
    route = client.post(
        "/gateway/routes",
        json={
            "route_name": "aab-phase3-schedule-job",
            "selection_mode": "manual",
            "load_balancing_strategy": "weighted",
            "fallback_policy": "secondary",
            "timeout_policy": "2s",
            "status": "active",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert route.status_code == 200

    create_job = client.post(
        "/agentic/policy/schedules",
        json={
            "name": "prod-nightly-cost-opt",
            "environment": "prod",
            "optimize_for": "cost",
            "max_routes": 100,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 0,
            "enabled": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-1"},
    )
    assert create_job.status_code == 200
    job_id = create_job.json()["job_id"]

    update_job = client.patch(
        f"/agentic/policy/schedules/{job_id}",
        json={"max_routes": 51},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-audit-filter"},
    )
    assert update_job.status_code == 200

    list_jobs = client.get(
        f"/agentic/policy/schedules?job_id={job_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-1"},
    )
    assert list_jobs.status_code == 200
    assert "x-total-count" in list_jobs.headers
    assert any(job["job_id"] == job_id for job in list_jobs.json())

    get_job = client.get(
        f"/agentic/policy/schedules/{job_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-1"},
    )
    assert get_job.status_code == 200
    assert get_job.json()["job_id"] == job_id

    filtered_jobs = client.get(
        f"/agentic/policy/schedules?job_id={job_id}&environment=prod&optimize_for=cost&enabled=true&limit=50&offset=0",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-1"},
    )
    assert filtered_jobs.status_code == 200
    assert any(job["job_id"] == job_id for job in filtered_jobs.json())
    assert all(job["environment"] == "prod" for job in filtered_jobs.json())
    assert all(job["optimize_for"] == "cost" for job in filtered_jobs.json())
    assert all(job["enabled"] is True for job in filtered_jobs.json())

    execute_blocked = client.post(
        f"/agentic/policy/schedules/{job_id}/execute-now",
        json={"dry_run": False},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert execute_blocked.status_code == 200
    if execute_blocked.json()["approval_required"]:
        assert execute_blocked.json()["executed"] is False
        assert execute_blocked.json()["execution_status"] == "waiting_approval"
    else:
        assert execute_blocked.json()["executed"] is True
        assert execute_blocked.json()["execution_status"] == "applied"

    execute_approved = client.post(
        f"/agentic/policy/schedules/{job_id}/execute-now",
        json={"approval_token": "approved", "dry_run": False},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert execute_approved.status_code == 200
    assert execute_approved.json()["approved"] is True
    assert execute_approved.json()["executed"] is True


def test_agentic_policy_schedule_execute_now_updates_last_run_only_on_real_or_dry_execution():
    route = client.post(
        "/gateway/routes",
        json={
            "route_name": "aab-phase3-schedule-last-run",
            "selection_mode": "manual",
            "load_balancing_strategy": "weighted",
            "fallback_policy": "secondary",
            "timeout_policy": "2s",
            "status": "active",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert route.status_code == 200

    create_job = client.post(
        "/agentic/policy/schedules",
        json={
            "name": "prod-last-run-guard",
            "environment": "prod",
            "optimize_for": "cost",
            "max_routes": 100,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 0,
            "enabled": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-1"},
    )
    assert create_job.status_code == 200
    job_id = create_job.json()["job_id"]

    initial_status = client.get(
        f"/agentic/policy/schedules/{job_id}/status",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-1"},
    )
    assert initial_status.status_code == 200
    assert initial_status.json()["last_run_at"] is None

    execute_blocked = client.post(
        f"/agentic/policy/schedules/{job_id}/execute-now",
        json={"dry_run": False},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert execute_blocked.status_code == 200
    assert execute_blocked.json()["execution_status"] in {"waiting_approval", "applied"}

    blocked_status = client.get(
        f"/agentic/policy/schedules/{job_id}/status",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-1"},
    )
    assert blocked_status.status_code == 200
    if execute_blocked.json()["execution_status"] == "waiting_approval":
        assert blocked_status.json()["last_run_at"] is None
    else:
        assert blocked_status.json()["last_run_at"] is not None

    execute_approved = client.post(
        f"/agentic/policy/schedules/{job_id}/execute-now",
        json={"approval_token": "approved", "dry_run": False},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert execute_approved.status_code == 200
    assert execute_approved.json()["execution_status"] == "applied"

    approved_status = client.get(
        f"/agentic/policy/schedules/{job_id}/status",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-1"},
    )
    assert approved_status.status_code == 200
    assert approved_status.json()["last_run_at"] is not None


def test_agentic_policy_schedule_update_disable_enable_flow():
    create_job = client.post(
        "/agentic/policy/schedules",
        json={
            "name": "prod-update-toggle-job",
            "environment": "prod",
            "optimize_for": "balanced",
            "max_routes": 10,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 2,
            "enabled": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-1"},
    )
    assert create_job.status_code == 200
    job_id = create_job.json()["job_id"]

    updated = client.patch(
        f"/agentic/policy/schedules/{job_id}",
        json={"optimize_for": "latency", "max_routes": 25, "max_changes_without_approval": 1},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert updated.status_code == 200
    assert updated.json()["optimize_for"] == "latency"
    assert updated.json()["max_routes"] == 25
    assert updated.json()["max_changes_without_approval"] == 1

    empty_update = client.patch(
        f"/agentic/policy/schedules/{job_id}",
        json={},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert empty_update.status_code == 400

    disabled = client.post(
        f"/agentic/policy/schedules/{job_id}/disable",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False

    execute_disabled = client.post(
        f"/agentic/policy/schedules/{job_id}/execute-now",
        json={"dry_run": False},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert execute_disabled.status_code == 400

    enabled = client.post(
        f"/agentic/policy/schedules/{job_id}/enable",
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-1"},
    )
    assert enabled.status_code == 200
    assert enabled.json()["enabled"] is True

    execute_dry = client.post(
        f"/agentic/policy/schedules/{job_id}/execute-now",
        json={"dry_run": True},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert execute_dry.status_code == 200
    assert execute_dry.json()["execution_status"] == "dry_run"


def test_agentic_policy_schedule_audit_events_emitted():
    create_job = client.post(
        "/agentic/policy/schedules",
        json={
            "name": "prod-audit-job",
            "environment": "prod",
            "optimize_for": "cost",
            "max_routes": 100,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 0,
            "enabled": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-1"},
    )
    assert create_job.status_code == 200
    job_id = create_job.json()["job_id"]

    updated = client.patch(
        f"/agentic/policy/schedules/{job_id}",
        json={"optimize_for": "latency"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert updated.status_code == 200

    disabled = client.post(
        f"/agentic/policy/schedules/{job_id}/disable",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert disabled.status_code == 200

    enabled = client.post(
        f"/agentic/policy/schedules/{job_id}/enable",
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-1"},
    )
    assert enabled.status_code == 200

    executed = client.post(
        f"/agentic/policy/schedules/{job_id}/execute-now",
        json={"approval_token": "approved", "dry_run": False},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert executed.status_code == 200

    audit_events = client.get(
        "/audit/events?limit=300",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-audit-events"},
    )
    assert audit_events.status_code == 200
    assert "x-total-count" in audit_events.headers
    actions = [event["action_type"] for event in audit_events.json() if event["resource_id"] == job_id]

    assert "agentic.policy.schedule.create" in actions
    assert "agentic.policy.schedule.update" in actions
    assert "agentic.policy.schedule.disable" in actions
    assert "agentic.policy.schedule.enable" in actions
    assert "agentic.policy.schedule.execute_now" in actions


def test_audit_events_filters_by_action_resource_and_actor():
    create_job = client.post(
        "/agentic/policy/schedules",
        json={
            "name": "prod-audit-filter-job",
            "environment": "prod",
            "optimize_for": "cost",
            "max_routes": 50,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 2,
            "enabled": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-filter"},
    )
    assert create_job.status_code == 200
    job_id = create_job.json()["job_id"]

    filtered_by_resource = client.get(
        f"/audit/events?resource_type=policy_schedule&resource_id={job_id}&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-audit-filter"},
    )
    assert filtered_by_resource.status_code == 200
    assert "x-total-count" in filtered_by_resource.headers
    assert len(filtered_by_resource.json()) >= 1
    assert all(event["resource_type"] == "policy_schedule" for event in filtered_by_resource.json())
    assert all(event["resource_id"] == job_id for event in filtered_by_resource.json())

    filtered_by_action = client.get(
        "/audit/events?action_type=agentic.policy.schedule.create&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-audit-filter"},
    )
    assert filtered_by_action.status_code == 200
    assert len(filtered_by_action.json()) >= 1
    assert all(event["action_type"] == "agentic.policy.schedule.create" for event in filtered_by_action.json())

    filtered_by_actor = client.get(
        "/audit/events?actor_id=rm-filter&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-audit-filter"},
    )
    assert filtered_by_actor.status_code == 200
    assert len(filtered_by_actor.json()) >= 1
    assert all(event["actor_id"] == "rm-filter" for event in filtered_by_actor.json())

    filtered_by_outcome_and_window = client.get(
        "/audit/events?action_type=agentic.policy.schedule.create&decision_outcome=allow&since_hours=24&limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-audit-filter"},
    )
    assert filtered_by_outcome_and_window.status_code == 200
    assert len(filtered_by_outcome_and_window.json()) >= 1
    assert all(event["action_type"] == "agentic.policy.schedule.create" for event in filtered_by_outcome_and_window.json())
    assert all(event["decision_outcome"] == "allow" for event in filtered_by_outcome_and_window.json())

    page_1 = client.get(
        f"/audit/events?resource_type=policy_schedule&resource_id={job_id}&limit=1&offset=0",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-audit-filter"},
    )
    page_2 = client.get(
        f"/audit/events?resource_type=policy_schedule&resource_id={job_id}&limit=1&offset=1",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-audit-filter"},
    )
    assert page_1.status_code == 200
    assert page_2.status_code == 200
    assert len(page_1.json()) == 1
    total_for_resource = int(filtered_by_resource.headers.get("x-total-count", "0"))
    if total_for_resource >= 2:
        assert len(page_2.json()) == 1
        assert page_1.json()[0]["audit_event_id"] != page_2.json()[0]["audit_event_id"]
    else:
        assert len(page_2.json()) == 0


def test_audit_events_filters_by_action_type_prefix():
    filtered = client.get(
        "/audit/events?action_type_prefix=orchestration.flow&limit=50&since_hours=720",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-audit-prefix"},
    )
    assert filtered.status_code == 200
    rows = filtered.json()
    if rows:
        assert all(str(event["action_type"]).startswith("orchestration.flow") for event in rows)

    conflict = client.get(
        "/audit/events?action_type=orchestration.flow.run&action_type_prefix=orchestration.flow&limit=10",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-audit-prefix"},
    )
    assert conflict.status_code == 422


def test_schedule_execute_now_accepts_dual_role_approvals_without_token():
    route = client.post(
        "/gateway/routes",
        json={
            "route_name": "aac-phase3-dual-approval",
            "selection_mode": "manual",
            "load_balancing_strategy": "weighted",
            "fallback_policy": "secondary",
            "timeout_policy": "2s",
            "status": "active",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert route.status_code == 200

    create_job = client.post(
        "/agentic/policy/schedules",
        json={
            "name": "prod-dual-approval-job",
            "environment": "prod",
            "optimize_for": "cost",
            "max_routes": 100,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 0,
            "enabled": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-approval"},
    )
    assert create_job.status_code == 200
    job_id = create_job.json()["job_id"]

    blocked = client.post(
        f"/agentic/policy/schedules/{job_id}/execute-now",
        json={"dry_run": False},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert blocked.status_code == 200
    assert blocked.json()["execution_status"] == "waiting_approval"

    sec_approve = client.post(
        f"/agentic/policy/schedules/{job_id}/approve",
        json={"reason_code": "security-review-pass"},
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-approve-1"},
    )
    assert sec_approve.status_code == 200

    ai_approve = client.post(
        f"/agentic/policy/schedules/{job_id}/approve",
        json={"reason_code": "aiops-review-pass"},
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "ai-approve-1"},
    )
    assert ai_approve.status_code == 200

    executed = client.post(
        f"/agentic/policy/schedules/{job_id}/execute-now",
        json={"dry_run": False},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-1"},
    )
    assert executed.status_code == 200
    assert executed.json()["approved"] is True
    assert executed.json()["executed"] is True
    assert executed.json()["execution_status"] == "applied"


def test_policy_schedule_history_and_delete_flow():
    create_job = client.post(
        "/agentic/policy/schedules",
        json={
            "name": "prod-history-delete-job",
            "environment": "prod",
            "optimize_for": "balanced",
            "max_routes": 10,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 3,
            "enabled": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-history"},
    )
    assert create_job.status_code == 200
    job_id = create_job.json()["job_id"]

    disabled = client.post(
        f"/agentic/policy/schedules/{job_id}/disable",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-history"},
    )
    assert disabled.status_code == 200

    history = client.get(
        f"/agentic/policy/schedules/{job_id}/history?limit=50",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-history"},
    )
    assert history.status_code == 200
    assert "x-total-count" in history.headers
    actions = [event["action_type"] for event in history.json()]
    assert "agentic.policy.schedule.create" in actions
    assert "agentic.policy.schedule.disable" in actions

    history_create_only = client.get(
        f"/agentic/policy/schedules/{job_id}/history?limit=50&action_type=agentic.policy.schedule.create&since_hours=24",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-history"},
    )
    assert history_create_only.status_code == 200
    assert len(history_create_only.json()) >= 1
    assert all(event["action_type"] == "agentic.policy.schedule.create" for event in history_create_only.json())

    history_by_actor = client.get(
        f"/agentic/policy/schedules/{job_id}/history?limit=50&actor_id=platform-history&since_hours=24",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-history"},
    )
    assert history_by_actor.status_code == 200
    assert len(history_by_actor.json()) >= 1
    assert all(event["actor_id"] == "platform-history" for event in history_by_actor.json())

    history_page_1 = client.get(
        f"/agentic/policy/schedules/{job_id}/history?limit=1&offset=0",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-history"},
    )
    history_page_2 = client.get(
        f"/agentic/policy/schedules/{job_id}/history?limit=1&offset=1",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-history"},
    )
    assert history_page_1.status_code == 200
    assert history_page_2.status_code == 200
    assert len(history_page_1.json()) == 1
    assert len(history_page_2.json()) == 1
    assert history_page_1.json()[0]["audit_event_id"] != history_page_2.json()[0]["audit_event_id"]

    deleted = client.delete(
        f"/agentic/policy/schedules/{job_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-history"},
    )
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True

    get_deleted_history = client.get(
        f"/agentic/policy/schedules/{job_id}/history",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-history"},
    )
    assert get_deleted_history.status_code == 200
    assert any(event["action_type"] == "agentic.policy.schedule.delete" for event in get_deleted_history.json())

    missing_history = client.get(
        "/agentic/policy/schedules/sched-does-not-exist/history",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-history"},
    )
    assert missing_history.status_code == 404


def test_schedule_delete_does_not_impact_other_schedule_functionality():
    target = client.post(
        "/agentic/policy/schedules",
        json={
            "name": "delete-target-job",
            "environment": "prod",
            "optimize_for": "cost",
            "max_routes": 20,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 0,
            "enabled": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-del"},
    )
    survivor = client.post(
        "/agentic/policy/schedules",
        json={
            "name": "delete-survivor-job",
            "environment": "prod",
            "optimize_for": "cost",
            "max_routes": 20,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 0,
            "enabled": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-del"},
    )
    assert target.status_code == 200
    assert survivor.status_code == 200
    target_id = target.json()["job_id"]
    survivor_id = survivor.json()["job_id"]

    target_list_before = client.get(
        f"/agentic/policy/schedules?job_id={target_id}&limit=50&offset=0",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-del"},
    )
    survivor_list_before = client.get(
        f"/agentic/policy/schedules?job_id={survivor_id}&limit=50&offset=0",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-del"},
    )
    assert target_list_before.status_code == 200
    assert survivor_list_before.status_code == 200
    assert target_list_before.headers.get("x-total-count") == "1"
    assert survivor_list_before.headers.get("x-total-count") == "1"
    assert len(target_list_before.json()) == 1
    assert len(survivor_list_before.json()) == 1

    deleted = client.delete(
        f"/agentic/policy/schedules/{target_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-del"},
    )
    assert deleted.status_code == 200

    target_get = client.get(
        f"/agentic/policy/schedules/{target_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-del"},
    )
    assert target_get.status_code == 404

    target_list_after = client.get(
        f"/agentic/policy/schedules?job_id={target_id}&limit=50&offset=0",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-del"},
    )
    assert target_list_after.status_code == 200
    assert target_list_after.headers.get("x-total-count") == "0"
    assert len(target_list_after.json()) == 0

    survivor_get = client.get(
        f"/agentic/policy/schedules/{survivor_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-del"},
    )
    assert survivor_get.status_code == 200

    survivor_list_after = client.get(
        f"/agentic/policy/schedules?job_id={survivor_id}&limit=50&offset=0",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-del"},
    )
    assert survivor_list_after.status_code == 200
    assert survivor_list_after.headers.get("x-total-count") == "1"
    assert len(survivor_list_after.json()) == 1

    survivor_execute = client.post(
        f"/agentic/policy/schedules/{survivor_id}/execute-now",
        json={"approval_token": "approved", "dry_run": False},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-del"},
    )
    assert survivor_execute.status_code == 200
    assert survivor_execute.json()["executed"] is True


def test_delete_missing_schedule_emits_denied_audit_event():
    missing_job_id = f"sched-missing-{uuid4()}"

    deleted = client.delete(
        f"/agentic/policy/schedules/{missing_job_id}",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-del-missing"},
    )
    assert deleted.status_code == 404

    denied_delete_events = get_delete_audit_events(missing_job_id, "deny")
    assert len(denied_delete_events) >= 1


def test_delete_missing_schedule_idempotent_mode_returns_200_and_audits_allow():
    missing_job_id = f"sched-missing-idempotent-{uuid4()}"

    deleted = client.delete(
        f"/agentic/policy/schedules/{missing_job_id}?idempotent=true",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-del-idempotent"},
    )
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is False
    assert deleted.json()["job_id"] == missing_job_id

    allow_delete_events = get_delete_audit_events(missing_job_id, "allow")
    assert len(allow_delete_events) >= 1


def test_delete_existing_schedule_idempotent_mode_still_deletes():
    created = client.post(
        "/agentic/policy/schedules",
        json={
            "name": "delete-idempotent-existing-job",
            "environment": "prod",
            "optimize_for": "cost",
            "max_routes": 20,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 1,
            "enabled": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-del-idempotent-existing"},
    )
    assert created.status_code == 200
    job_id = created.json()["job_id"]

    deleted = client.delete(
        f"/agentic/policy/schedules/{job_id}?idempotent=true",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-del-idempotent-existing"},
    )
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True
    assert deleted.json()["job_id"] == job_id

    lookup = client.get(
        f"/agentic/policy/schedules/{job_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-del-idempotent-existing"},
    )
    assert lookup.status_code == 404


def test_delete_policy_schedule_rejects_unauthorized_role_without_side_effects():
    created = client.post(
        "/agentic/policy/schedules",
        json={
            "name": "delete-unauthorized-role-job",
            "environment": "prod",
            "optimize_for": "balanced",
            "max_routes": 10,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 1,
            "enabled": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-del-unauthorized"},
    )
    assert created.status_code == 200
    job_id = created.json()["job_id"]

    denied = client.delete(
        f"/agentic/policy/schedules/{job_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-del-unauthorized"},
    )
    assert denied.status_code == 403
    assert_role_forbidden_detail(denied.json())

    denied_delete_events = get_delete_audit_events(job_id, "deny", actor_id="aud-del-unauthorized")
    assert any(event["actor_id"] == "aud-del-unauthorized" for event in denied_delete_events)

    allow_delete_events = get_delete_audit_events(job_id, "allow", actor_id="aud-del-unauthorized")
    assert len(allow_delete_events) == 0

    lookup = client.get(
        f"/agentic/policy/schedules/{job_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-del-unauthorized"},
    )
    assert lookup.status_code == 200
    assert lookup.json()["job_id"] == job_id


def test_delete_missing_schedule_rejects_unauthorized_role_and_audits_deny():
    missing_job_id = f"sched-missing-unauthorized-{uuid4()}"

    denied = client.delete(
        f"/agentic/policy/schedules/{missing_job_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-del-missing-unauthorized"},
    )
    assert denied.status_code == 403
    assert_role_forbidden_detail(denied.json())

    denied_delete_events = get_delete_audit_events(missing_job_id, "deny", actor_id="aud-del-missing-unauthorized")
    assert len(denied_delete_events) >= 1
    assert all(event["actor_id"] == "aud-del-missing-unauthorized" for event in denied_delete_events)

    allow_delete_events = get_delete_audit_events(missing_job_id, "allow", actor_id="aud-del-missing-unauthorized")
    assert len(allow_delete_events) == 0


def test_delete_missing_schedule_idempotent_rejects_unauthorized_role_and_audits_deny():
    missing_job_id = f"sched-missing-unauthorized-idempotent-{uuid4()}"

    denied = client.delete(
        f"/agentic/policy/schedules/{missing_job_id}?idempotent=true",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-del-missing-unauthorized-idempotent"},
    )
    assert denied.status_code == 403
    assert_role_forbidden_detail(denied.json())

    denied_delete_events = get_delete_audit_events(
        missing_job_id,
        "deny",
        actor_id="aud-del-missing-unauthorized-idempotent",
    )
    assert len(denied_delete_events) >= 1
    assert all(event["actor_id"] == "aud-del-missing-unauthorized-idempotent" for event in denied_delete_events)

    allow_delete_events = get_delete_audit_events(
        missing_job_id,
        "allow",
        actor_id="aud-del-missing-unauthorized-idempotent",
    )
    assert len(allow_delete_events) == 0


def test_delete_existing_schedule_idempotent_rejects_unauthorized_role_and_audits_deny():
    created = client.post(
        "/agentic/policy/schedules",
        json={
            "name": "delete-existing-unauthorized-idempotent-job",
            "environment": "prod",
            "optimize_for": "balanced",
            "max_routes": 10,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 1,
            "enabled": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-del-existing-unauthorized-idempotent"},
    )
    assert created.status_code == 200
    job_id = created.json()["job_id"]

    denied = client.delete(
        f"/agentic/policy/schedules/{job_id}?idempotent=true",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-del-existing-unauthorized-idempotent"},
    )
    assert denied.status_code == 403
    assert_role_forbidden_detail(denied.json())

    denied_delete_events = get_delete_audit_events(
        job_id,
        "deny",
        actor_id="aud-del-existing-unauthorized-idempotent",
    )
    assert len(denied_delete_events) >= 1
    assert any(event["actor_id"] == "aud-del-existing-unauthorized-idempotent" for event in denied_delete_events)

    allow_delete_events = get_delete_audit_events(job_id, "allow", actor_id="aud-del-existing-unauthorized-idempotent")
    assert len(allow_delete_events) == 0

    lookup = client.get(
        f"/agentic/policy/schedules/{job_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-del-existing-unauthorized-idempotent"},
    )
    assert lookup.status_code == 200
    assert lookup.json()["job_id"] == job_id


def test_delete_policy_schedule_rejects_agent_owner_role_and_audits_deny():
    created = client.post(
        "/agentic/policy/schedules",
        json={
            "name": "delete-agent-owner-unauthorized-job",
            "environment": "prod",
            "optimize_for": "balanced",
            "max_routes": 10,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 1,
            "enabled": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-del-agent-owner-unauthorized"},
    )
    assert created.status_code == 200
    job_id = created.json()["job_id"]

    denied = client.delete(
        f"/agentic/policy/schedules/{job_id}",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-del-unauthorized"},
    )
    assert denied.status_code == 403
    assert_role_forbidden_detail(denied.json(), actor_role="Agent Owner")

    denied_delete_events = get_delete_audit_events(job_id, "deny", actor_id="owner-del-unauthorized")
    assert any(event["actor_id"] == "owner-del-unauthorized" for event in denied_delete_events)

    allow_delete_events = get_delete_audit_events(job_id, "allow", actor_id="owner-del-unauthorized")
    assert len(allow_delete_events) == 0

    lookup = client.get(
        f"/agentic/policy/schedules/{job_id}",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-del-agent-owner-unauthorized"},
    )
    assert lookup.status_code == 200
    assert lookup.json()["job_id"] == job_id


def test_openapi_documents_policy_schedule_delete_contract():
    openapi = client.get("/openapi.json")
    assert openapi.status_code == 200

    document = openapi.json()
    delete_operation = document["paths"]["/agentic/policy/schedules/{job_id}"]["delete"]

    idempotent_param = next(
        (param for param in delete_operation.get("parameters", []) if param.get("name") == "idempotent"),
        None,
    )
    assert idempotent_param is not None
    assert idempotent_param.get("in") == "query"
    assert idempotent_param.get("schema", {}).get("type") == "boolean"
    assert idempotent_param.get("schema", {}).get("default") is False
    assert "non-existent schedule" in (idempotent_param.get("description") or "")

    success_200 = delete_operation["responses"]["200"]
    content = success_200["content"]["application/json"]
    assert content["schema"]["$ref"].endswith("/PolicyScheduleDeleteResponse")
    assert "403" in delete_operation["responses"]
    assert "404" in delete_operation["responses"]
    assert delete_operation["responses"]["403"]["description"] == "Actor role is not allowed for this action."
    assert delete_operation["responses"]["404"]["description"] == "Policy schedule not found."


def test_openapi_documents_basic_auth_enable_temporary_contract():
    openapi = client.get("/openapi.json")
    assert openapi.status_code == 200

    document = openapi.json()
    operation = document["paths"]["/auth/basic/config/{config_id}/enable-temporary"]["post"]
    responses = operation["responses"]

    assert "200" in responses
    assert "400" in responses
    assert "403" in responses
    assert "404" in responses
    assert responses["400"]["description"] == "Validation failed: approver identity conflict or requested duration exceeds max limit."
    assert responses["403"]["description"] == "Actor role is not allowed for this action or dual approval is missing."
    assert responses["404"]["description"] == "Basic auth config not found."


def test_openapi_documents_basic_auth_disable_contract():
    openapi = client.get("/openapi.json")
    assert openapi.status_code == 200

    document = openapi.json()
    operation = document["paths"]["/auth/basic/config/{config_id}/disable"]["post"]
    responses = operation["responses"]

    assert "200" in responses
    assert "403" in responses
    assert "404" in responses
    assert responses["403"]["description"] == "Actor role is not allowed for this action."
    assert responses["404"]["description"] == "Basic auth config not found."


def test_openapi_documents_audit_decision_outcome_enum():
    openapi = client.get("/openapi.json")
    assert openapi.status_code == 200

    document = openapi.json()
    schema = document["components"]["schemas"]["AuditEventResponse"]
    decision_outcome = schema["properties"]["decision_outcome"]
    assert decision_outcome["type"] == "string"
    assert set(decision_outcome["enum"]) == {"allow", "deny", "warn"}


def test_openapi_exposes_swagger_security_schemes_and_tags():
    openapi = client.get("/openapi.json")
    assert openapi.status_code == 200

    document = openapi.json()
    security_schemes = document.get("components", {}).get("securitySchemes", {})
    assert "BearerAuth" in security_schemes
    assert security_schemes["BearerAuth"].get("type") == "http"
    assert security_schemes["BearerAuth"].get("scheme") == "bearer"
    assert "ActorIdHeader" in security_schemes
    assert "ActorRoleHeader" in security_schemes
    assert "MfaVerifiedHeader" in security_schemes

    tags = {row.get("name") for row in document.get("tags", [])}
    assert "Gateway and Keys" in tags
    assert "Providers" in tags
    assert "Auth and Security" in tags
    assert "Health" in tags


def test_openapi_documents_provider_swagger_contracts():
    openapi = client.get("/openapi.json")
    assert openapi.status_code == 200
    document = openapi.json()

    token_exchange = document["paths"]["/auth/workload-identity/token-exchange"]["post"]
    assert token_exchange["summary"] == "Exchange workload identity token"
    assert "audit evidence" in (token_exchange.get("description") or "").lower()
    assert "400" in token_exchange["responses"]
    assert "403" in token_exchange["responses"]
    assert "404" in token_exchange["responses"]

    wi_list = document["paths"]["/auth/workload-identity/providers"]["get"]
    assert wi_list["summary"] == "List workload identity providers"
    assert wi_list["responses"]["200"]["content"]["application/json"]["schema"]["type"] == "array"

    secret_list = document["paths"]["/secrets/providers"]["get"]
    assert secret_list["summary"] == "List secret providers"
    assert "masked" in (secret_list.get("description") or "").lower()

    create_tenant = document["paths"]["/providers/tenants"]["post"]
    assert create_tenant["summary"] == "Create tenant catalog entry"
    assert "409" in create_tenant["responses"]

    update_tenant = document["paths"]["/providers/tenants/{tenant_id}"]["put"]
    assert update_tenant["summary"] == "Update tenant catalog entry"
    assert "404" in update_tenant["responses"]

    create_wi_provider = document["paths"]["/auth/workload-identity/providers"]["post"]
    assert create_wi_provider["summary"] == "Create workload identity provider"

    create_secret_provider = document["paths"]["/secrets/providers"]["post"]
    assert create_secret_provider["summary"] == "Create secret provider"


def test_openapi_documents_high_risk_auth_and_gateway_swagger_contracts():
    openapi = client.get("/openapi.json")
    assert openapi.status_code == 200
    document = openapi.json()

    enable_basic = document["paths"]["/auth/basic/config/{config_id}/enable-temporary"]["post"]
    assert enable_basic["summary"] == "Enable break-glass basic auth temporarily"
    assert "dual-approval" in (enable_basic.get("description") or "").lower()

    create_basic = document["paths"]["/auth/basic/config"]["post"]
    assert create_basic["summary"] == "Create basic auth fallback config"

    disable_basic = document["paths"]["/auth/basic/config/{config_id}/disable"]["post"]
    assert disable_basic["summary"] == "Disable break-glass basic auth"

    rotate_key = document["paths"]["/keys/{key_id}/rotate"]["post"]
    assert rotate_key["summary"] == "Rotate virtual key"
    assert "403" in rotate_key["responses"]
    assert "404" in rotate_key["responses"]

    block_key = document["paths"]["/keys/{key_id}/block"]["post"]
    assert block_key["summary"] == "Block virtual key"
    assert "404" in block_key["responses"]

    unblock_key = document["paths"]["/keys/{key_id}/unblock"]["post"]
    assert unblock_key["summary"] == "Unblock virtual key"
    assert "404" in unblock_key["responses"]

    optimize = document["paths"]["/gateway/routes/{route_policy_id}/optimize"]["post"]
    assert optimize["summary"] == "Optimize route policy"
    assert "production" in (optimize.get("description") or "").lower()

    create_route = document["paths"]["/gateway/routes"]["post"]
    assert create_route["summary"] == "Create gateway route policy"

    provider_priority = document["paths"]["/gateway/routes/{route_policy_id}/providers/priority"]["post"]
    assert provider_priority["summary"] == "Upsert route provider priority"
    assert "404" in provider_priority["responses"]

    rotate_via_provider = document["paths"]["/keys/{key_id}/rotate-via-secret-provider"]["post"]
    assert rotate_via_provider["summary"] == "Rotate key via secret provider"
    assert "mfa" in (rotate_via_provider.get("description") or "").lower()

    execute_fallback = document["paths"]["/gateway/routes/{route_policy_id}/execute-fallback"]["post"]
    assert execute_fallback["summary"] == "Execute route fallback"
    assert "403" in execute_fallback["responses"]
    assert "404" in execute_fallback["responses"]

    cache_delete = document["paths"]["/gateway/cache/delete"]["post"]
    assert cache_delete["summary"] == "Invalidate gateway cache"
    assert "422" in cache_delete["responses"]

    cache_decisions = document["paths"]["/gateway/cache/decisions"]["get"]
    assert cache_decisions["summary"] == "List gateway cache decisions"
    assert "403" in cache_decisions["responses"]

    cache_create = document["paths"]["/gateway/cache/policies"]["post"]
    assert cache_create["summary"] == "Create gateway cache policy"

    transform_debug = document["paths"]["/gateway/debug/transform-request"]["post"]
    assert transform_debug["summary"] == "Run request transform debug"
    assert "audit" in (transform_debug.get("description") or "").lower()

    authz_explain = document["paths"]["/gateway/authz/explain"]["post"]
    assert authz_explain["summary"] == "Explain gateway authorization decision"
    assert "dual-approval" in (authz_explain.get("description") or "").lower()

    auth_domain_explain = document["paths"]["/auth/authz/explain"]["post"]
    assert auth_domain_explain["summary"] == "Explain auth authorization decision"
    assert "explainability" in (auth_domain_explain.get("description") or "").lower()

    callbacks_create = document["paths"]["/gateway/external-callbacks"]["post"]
    assert callbacks_create["summary"] == "Create gateway external callback"

    callbacks_test = document["paths"]["/gateway/external-callbacks/{callback_id}/test-delivery"]["post"]
    assert callbacks_test["summary"] == "Test gateway external callback delivery"
    assert "404" in callbacks_test["responses"]

    callbacks_export = document["paths"]["/gateway/external-callbacks/export"]["post"]
    assert callbacks_export["summary"] == "Export gateway external callback evidence"

    governance_export = document["paths"]["/gateway/governance/evidence/export"]["post"]
    assert governance_export["summary"] == "Export gateway governance evidence bundle"


def test_openapi_documents_provider_mutation_swagger_contracts():
    openapi = client.get("/openapi.json")
    assert openapi.status_code == 200
    document = openapi.json()

    validate_trust = document["paths"]["/auth/workload-identity/providers/{provider_id}/validate-trust"]["post"]
    assert validate_trust["summary"] == "Validate workload identity trust"
    assert "mfa" in (validate_trust.get("description") or "").lower()
    assert "403" in validate_trust["responses"]
    assert "404" in validate_trust["responses"]

    test_workload = document["paths"]["/auth/workload-identity/providers/{provider_id}/test"]["post"]
    assert test_workload["summary"] == "Test workload identity provider"
    assert "400" in test_workload["responses"]
    assert "403" in test_workload["responses"]

    test_secret = document["paths"]["/secrets/providers/{provider_id}/test"]["post"]
    assert test_secret["summary"] == "Test secret provider connectivity"
    assert "404" in test_secret["responses"]

    renew_lease = document["paths"]["/secrets/providers/{provider_id}/leases/renew"]["post"]
    assert renew_lease["summary"] == "Renew secret provider lease"
    assert "mfa" in (renew_lease.get("description") or "").lower()


def test_openapi_documents_compliance_bundle_integrity_contract():
    openapi = client.get("/openapi.json")
    assert openapi.status_code == 200
    document = openapi.json()

    bundle = document["paths"]["/compliance/evidence/{control_id}/bundle"]["get"]
    assert bundle["summary"] == "Retrieve compliance evidence bundle"
    assert "fails closed" in (bundle.get("description") or "").lower()
    assert "tenant/environment" in (bundle.get("description") or "").lower()
    assert "400" in bundle["responses"]
    assert "404" in bundle["responses"]
    assert "409" in bundle["responses"]


def test_policy_schedule_status_reports_dual_approval_readiness():
    baseline_summary = client.get(
        "/agentic/policy/schedules/summary",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-status"},
    )
    assert baseline_summary.status_code == 200

    create_job = client.post(
        "/agentic/policy/schedules",
        json={
            "name": "prod-status-job",
            "environment": "prod",
            "optimize_for": "cost",
            "max_routes": 20,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 0,
            "enabled": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-status"},
    )
    assert create_job.status_code == 200
    job_id = create_job.json()["job_id"]

    create_pending = client.post(
        "/agentic/policy/schedules",
        json={
            "name": "prod-status-job-pending",
            "environment": "prod",
            "optimize_for": "cost",
            "max_routes": 20,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 0,
            "enabled": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-status-pending"},
    )
    assert create_pending.status_code == 200
    pending_job_id = create_pending.json()["job_id"]

    pre_status = client.get(
        f"/agentic/policy/schedules/{job_id}/status",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-status"},
    )
    assert pre_status.status_code == 200
    assert pre_status.json()["dual_approval_ready"] is False
    assert pre_status.json()["pending_dual_approval"] is True
    assert pre_status.json()["latest_security_approval_by"] is None
    assert pre_status.json()["latest_ai_ops_approval_by"] is None

    sec_approve = client.post(
        f"/agentic/policy/schedules/{job_id}/approve",
        json={"reason_code": "security-status-pass"},
        headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": "sec-status-1"},
    )
    assert sec_approve.status_code == 200

    ai_approve = client.post(
        f"/agentic/policy/schedules/{job_id}/approve",
        json={"reason_code": "ai-status-pass"},
        headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": "ai-status-1"},
    )
    assert ai_approve.status_code == 200

    post_status = client.get(
        f"/agentic/policy/schedules/{job_id}/status",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-status"},
    )
    assert post_status.status_code == 200
    assert post_status.json()["dual_approval_ready"] is True
    assert post_status.json()["pending_dual_approval"] is False
    assert len(post_status.json()["approvals_last_24h"]) >= 2
    assert post_status.json()["latest_security_approval_by"] == "sec-status-1"
    assert post_status.json()["latest_ai_ops_approval_by"] == "ai-status-1"
    assert post_status.json()["latest_security_approval_at"] is not None
    assert post_status.json()["latest_ai_ops_approval_at"] is not None

    ready_list = client.get(
        f"/agentic/policy/schedules?job_id={job_id}&dual_approval_ready=true&limit=50&offset=0",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-status"},
    )
    assert ready_list.status_code == 200
    assert ready_list.headers.get("x-total-count") == "1"
    assert any(job["job_id"] == job_id for job in ready_list.json())

    pending_list = client.get(
        f"/agentic/policy/schedules?job_id={pending_job_id}&dual_approval_ready=false&limit=50&offset=0",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-status"},
    )
    assert pending_list.status_code == 200
    assert pending_list.headers.get("x-total-count") == "1"
    assert any(job["job_id"] == pending_job_id for job in pending_list.json())

    summary_after = client.get(
        "/agentic/policy/schedules/summary",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-status"},
    )
    assert summary_after.status_code == 200
    assert summary_after.json()["total_schedules"] >= baseline_summary.json()["total_schedules"] + 2
    assert summary_after.json()["dual_approval_ready_schedules"] >= baseline_summary.json()["dual_approval_ready_schedules"] + 1
    assert summary_after.json()["pending_dual_approval_schedules"] >= baseline_summary.json()["pending_dual_approval_schedules"] + 1

    ready_summary = client.get(
        "/agentic/policy/schedules/summary?environment=prod&optimize_for=cost&enabled=true&dual_approval_ready=true",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-status"},
    )
    assert ready_summary.status_code == 200
    assert ready_summary.json()["total_schedules"] >= 1
    assert ready_summary.json()["pending_dual_approval_schedules"] == 0

    pending_summary = client.get(
        "/agentic/policy/schedules/summary?environment=prod&optimize_for=cost&enabled=true&dual_approval_ready=false",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-status"},
    )
    assert pending_summary.status_code == 200
    assert pending_summary.json()["total_schedules"] >= 1


def test_policy_schedule_list_supports_name_prefix_and_sorting():
    first = client.post(
        "/agentic/policy/schedules",
        json={
            "name": "sort-check-a",
            "environment": "prod",
            "optimize_for": "latency",
            "max_routes": 5,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 3,
            "enabled": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-sort"},
    )
    assert first.status_code == 200

    second = client.post(
        "/agentic/policy/schedules",
        json={
            "name": "sort-check-b",
            "environment": "prod",
            "optimize_for": "latency",
            "max_routes": 5,
            "window_start_hour_utc": 0,
            "window_end_hour_utc": 0,
            "max_changes_without_approval": 3,
            "enabled": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-sort"},
    )
    assert second.status_code == 200

    sorted_resp = client.get(
        "/agentic/policy/schedules?name_prefix=sort-check-&environment=prod&optimize_for=latency&sort_by=name&sort_order=desc&limit=10&offset=0",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-sort"},
    )
    assert sorted_resp.status_code == 200
    names = [job["name"] for job in sorted_resp.json()]
    assert len(names) >= 2
    assert names == sorted(names, reverse=True)

    bad_sort = client.get(
        "/agentic/policy/schedules?sort_by=invalid_column",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-sort"},
    )
    assert bad_sort.status_code == 400

    missing_get = client.get(
        "/agentic/policy/schedules/sched-missing-id",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-sort"},
    )
    assert missing_get.status_code == 404


def test_policy_schedule_list_dual_approval_ready_pagination_and_counts():
    name_prefix = f"ready-page-{uuid4().hex[:8]}-"
    created_ids = []
    for idx in range(3):
        created = client.post(
            "/agentic/policy/schedules",
            json={
                "name": f"{name_prefix}{idx}",
                "environment": "prod",
                "optimize_for": "cost",
                "max_routes": 15,
                "window_start_hour_utc": 0,
                "window_end_hour_utc": 0,
                "max_changes_without_approval": 0,
                "enabled": True,
            },
            headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": f"rm-ready-page-{idx}"},
        )
        assert created.status_code == 200
        created_ids.append(created.json()["job_id"])

    for idx, job_id in enumerate(created_ids):
        sec = client.post(
            f"/agentic/policy/schedules/{job_id}/approve",
            json={"reason_code": f"sec-ready-{idx}"},
            headers={"X-Actor-Role": "Security Approver", "X-Actor-Id": f"sec-ready-{idx}"},
        )
        assert sec.status_code == 200
        ai = client.post(
            f"/agentic/policy/schedules/{job_id}/approve",
            json={"reason_code": f"ai-ready-{idx}"},
            headers={"X-Actor-Role": "AI Ops Approver", "X-Actor-Id": f"ai-ready-{idx}"},
        )
        assert ai.status_code == 200

    first_page = client.get(
        f"/agentic/policy/schedules?name_prefix={name_prefix}&dual_approval_ready=true&sort_by=name&sort_order=asc&limit=2&offset=0",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-ready-page"},
    )
    assert first_page.status_code == 200
    assert first_page.headers.get("x-total-count") == "3"
    assert len(first_page.json()) == 2

    second_page = client.get(
        f"/agentic/policy/schedules?name_prefix={name_prefix}&dual_approval_ready=true&sort_by=name&sort_order=asc&limit=2&offset=2",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-ready-page"},
    )
    assert second_page.status_code == 200
    assert second_page.headers.get("x-total-count") == "3"
    assert len(second_page.json()) == 1

    returned_ids = {job["job_id"] for job in first_page.json() + second_page.json()}
    assert returned_ids == set(created_ids)


def test_policy_schedule_payload_validation_rejects_invalid_values():
    invalid_create = client.post(
        "/agentic/policy/schedules",
        json={
            "name": "invalid-values-job",
            "environment": "prod",
            "optimize_for": "throughput",
            "max_routes": 0,
            "window_start_hour_utc": 24,
            "window_end_hour_utc": -1,
            "max_changes_without_approval": -1,
            "enabled": True,
        },
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-invalid"},
    )
    assert invalid_create.status_code == 422

    invalid_scheduled_optimize = client.post(
        "/agentic/policy/scheduled-optimize",
        json={
            "environment": "prod",
            "optimize_for": "throughput",
            "max_routes": 0,
            "window_start_hour_utc": 42,
            "window_end_hour_utc": 42,
            "max_changes_without_approval": -5,
            "dry_run": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-invalid"},
    )
    assert invalid_scheduled_optimize.status_code == 422


def test_pam_agent_owner_cannot_register_cross_owner_agent():
    denied = client.post(
        "/agents/register",
        json={
            "name": "agent-cross-owner-denied",
            "owner_id": "owner-other",
            "owner_name": "Owner Other",
            "owner_team": "Team Other",
            "risk_tier": "low",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-self"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"


def test_pam_cross_actor_platform_admin_session_requires_dual_approval():
    denied = client.post(
        "/auth/sessions",
        json={
            "actor_id": "platform-admin-target",
            "actor_role": "Platform Admin",
            "ttl_minutes": 30,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-admin-issuer"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"


def test_pam_discovery_agent_owner_forbidden_from_global_inventory():
    denied = client.get(
        "/discovery/agents",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-discovery"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"


def test_pam_compliance_evidence_agent_owner_forbidden():
    controls = client.get(
        "/compliance/controls",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-owner-evidence-deny"},
    )
    assert controls.status_code == 200
    control_id = controls.json()[0]["control_id"]

    denied = client.get(
        f"/compliance/evidence/{control_id}",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-evidence-deny"},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"
