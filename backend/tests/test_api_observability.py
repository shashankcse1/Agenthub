from uuid import uuid4

from fastapi.testclient import TestClient

from app.api_errors import (
    authz_scope_forbidden,
    conflict_error,
    not_found_error,
    unauthorized_error,
    upstream_error,
    validation_error,
)
from app.main import app

client = TestClient(app)


def test_api_error_helpers_include_policy_metadata():
    exc = validation_error("bad input", decision_trace_id="test-validation")
    assert exc.status_code == 400
    assert exc.detail["error_code"] == "VALIDATION_ERROR"
    assert exc.detail["policy_version"] == "v1"
    assert exc.detail["decision_trace_id"] == "test-validation"

    exc = not_found_error("widget", "w-1", decision_trace_id="test-not-found")
    assert exc.status_code == 404
    assert exc.detail["error_code"] == "RESOURCE_NOT_FOUND"
    assert exc.detail["resource_id"] == "w-1"

    exc = authz_scope_forbidden(
        message="denied",
        actor_role="Agent Owner",
        required_scope="agent.owner_id == requester actor_id",
        decision_trace_id="test-authz",
        remediation_hint="Use Platform Admin.",
    )
    assert exc.status_code == 403
    assert exc.detail["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"

    exc = unauthorized_error(decision_trace_id="test-authn")
    assert exc.status_code == 401
    assert exc.detail["error_code"] == "AUTHN_INVALID_CREDENTIALS"

    exc = conflict_error("already exists", decision_trace_id="test-conflict")
    assert exc.status_code == 409
    assert exc.detail["error_code"] == "RESOURCE_CONFLICT"

    exc = upstream_error("provider failed", decision_trace_id="test-upstream")
    assert exc.status_code == 502
    assert exc.detail["error_code"] == "UPSTREAM_PROVIDER_ERROR"


def test_auth_login_returns_structured_error():
    response = client.post(
        "/auth/login",
        json={"username": "missing-user", "password": "secret-password-12"},
    )
    assert response.status_code == 401
    detail = response.json()["detail"]
    assert detail["error_code"] == "AUTHN_INVALID_CREDENTIALS"
    assert detail["decision_trace_id"] == "auth-login-invalid-credentials"

    session = client.get(
        "/auth/sessions/nonexistent-session-id",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-1"},
    )
    assert session.status_code == 404
    detail = session.json()["detail"]
    assert detail["error_code"] == "RESOURCE_NOT_FOUND"
    assert detail["decision_trace_id"] == "auth-session-not-found"


def test_agentic_policy_auto_tune_apply_emits_audit_event():
    dry_run = client.post(
        "/agentic/policy/auto-tune",
        json={"environment": "prod", "optimize_for": "cost", "max_routes": 5, "dry_run": True},
        headers={"X-Actor-Role": "Release Manager", "X-Actor-Id": "rm-audit-1"},
    )
    assert dry_run.status_code == 200

    apply_run = client.post(
        "/agentic/policy/auto-tune",
        json={"environment": "prod", "optimize_for": "cost", "max_routes": 5, "dry_run": False},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "platform-audit-1"},
    )
    assert apply_run.status_code == 200

    audit = client.get(
        "/audit/events?action_type=agentic.policy.auto_tune&resource_type=route_policy&decision_outcome=allow&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-auto-tune"},
    )
    assert audit.status_code == 200
    events = audit.json()
    assert any(event["actor_id"] == "platform-audit-1" for event in events)


def test_benchmark_cancel_emits_request_time_audit_event():
    agent_id = f"audit-bench-cancel-{uuid4().hex[:8]}"
    headers = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": f"admin-{uuid4().hex[:8]}"}
    started = client.post(
        "/benchmarks/run",
        json={"agent_id": agent_id, "benchmark_suite": "reliability-core", "environment": "dev"},
        headers=headers,
    )
    assert started.status_code == 200
    run_id = started.json()["benchmark_run_id"]

    cancel = client.post(f"/benchmarks/runs/{run_id}/cancel", headers=headers)
    assert cancel.status_code == 200
    assert cancel.json()["status"] == "cancelling"

    audit = client.get(
        f"/audit/events?action_type=benchmark.run.cancel&resource_type=benchmark_run&resource_id={run_id}&decision_outcome=allow&limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-bench-cancel"},
    )
    assert audit.status_code == 200
    events = audit.json()
    assert any(event["resource_id"] == run_id for event in events)
