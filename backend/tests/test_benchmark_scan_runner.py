from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.services.benchmark_scan_execution import clear_run, is_cancelled, register_run, request_cancel
from app.services.benchmark_scan_runner import (
    BENCHMARK_SUITE_CASES,
    execute_benchmark_suite,
    execute_compliance_scan,
    execute_security_scan,
)
from tests.conftest import post_benchmark_run_and_wait, post_scan_run_and_wait

client = TestClient(app)


def test_execute_benchmark_suite_uses_gateway_scoring():
    db = SessionLocal()
    try:
        result = execute_benchmark_suite(
            db,
            agent_id=f"bench-agent-{uuid4().hex[:8]}",
            benchmark_suite="reliability-core",
            environment="dev",
        )
    finally:
        db.close()
    assert result["status"] == "completed"
    assert 0 <= int(result["score"]) <= 100
    assert "gateway" in result["summary"].lower() or "passed" in result["summary"].lower()
    assert len(BENCHMARK_SUITE_CASES["reliability-core"]) >= 3


def test_execute_security_scan_flags_missing_agent():
    db = SessionLocal()
    try:
        result = execute_security_scan(
            db,
            agent_id=f"missing-agent-{uuid4().hex[:8]}",
            environment="dev",
        )
    finally:
        db.close()
    assert result["status"] == "completed"
    assert result["findings_count"] >= 1


def test_execute_compliance_scan_reports_gaps():
    db = SessionLocal()
    try:
        result = execute_compliance_scan(
            db,
            agent_id=f"compliance-agent-{uuid4().hex[:8]}",
            environment="prod",
        )
    finally:
        db.close()
    assert result["status"] == "completed"
    assert result["findings_count"] >= 1


def test_benchmark_run_endpoint_returns_gateway_score():
    agent_id = f"api-bench-{uuid4().hex[:8]}"
    headers = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": f"admin-{uuid4().hex[:8]}"}
    payload = post_benchmark_run_and_wait(
        client,
        {
            "agent_id": agent_id,
            "benchmark_suite": "reliability-core",
            "environment": "dev",
        },
        headers,
    )
    assert payload["status"] == "completed"
    assert isinstance(payload["score"], int)
    assert payload["score"] > 0
    assert "gateway" in payload["summary"].lower() or "passed" in payload["summary"].lower()


def test_scan_run_endpoint_returns_findings():
    agent_id = f"api-scan-{uuid4().hex[:8]}"
    headers = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": f"admin-{uuid4().hex[:8]}"}
    payload = post_scan_run_and_wait(
        client,
        {"agent_id": agent_id, "scan_type": "security", "environment": "dev"},
        headers,
    )
    assert payload["status"] == "completed"
    assert payload["findings_count"] >= 1


def test_benchmark_cost_estimate_endpoint():
    agent_id = f"api-bench-est-{uuid4().hex[:8]}"
    response = client.get(
        "/benchmarks/cost-estimate",
        params={
            "agent_id": agent_id,
            "benchmark_suite": "reliability-core",
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": f"admin-{uuid4().hex[:8]}"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["gateway_call_count"] == len(BENCHMARK_SUITE_CASES["reliability-core"])
    assert payload["estimated_cost_cents"] >= 0


def test_scan_cost_estimate_endpoint_security_vs_compliance():
    agent_id = f"api-scan-est-{uuid4().hex[:8]}"
    headers = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": f"admin-{uuid4().hex[:8]}"}
    security = client.get(
        "/scans/cost-estimate",
        params={"agent_id": agent_id, "scan_type": "security", "environment": "dev"},
        headers=headers,
    )
    compliance = client.get(
        "/scans/cost-estimate",
        params={"agent_id": agent_id, "scan_type": "compliance", "environment": "dev"},
        headers=headers,
    )
    assert security.status_code == 200
    assert compliance.status_code == 200
    security_payload = security.json()
    compliance_payload = compliance.json()
    assert security_payload["gateway_call_count"] >= 1
    assert compliance_payload["gateway_call_count"] == 0
    assert compliance_payload["estimated_cost_cents"] == 0


def test_execute_benchmark_suite_honours_cancel():
    run_id = f"cancel-run-{uuid4().hex[:8]}"
    register_run(run_id, total_steps=3)
    request_cancel(run_id)
    db = SessionLocal()
    try:
        result = execute_benchmark_suite(
            db,
            agent_id=f"bench-cancel-{uuid4().hex[:8]}",
            benchmark_suite="reliability-core",
            environment="dev",
            should_cancel=lambda: is_cancelled(run_id),
        )
    finally:
        clear_run(run_id)
        db.close()
    assert result["status"] == "cancelled"
    assert result["gateway_call_count"] == 0


def test_benchmark_cancel_endpoint_rejects_completed_run():
    agent_id = f"api-bench-cancel-{uuid4().hex[:8]}"
    headers = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": f"admin-{uuid4().hex[:8]}"}
    payload = post_benchmark_run_and_wait(
        client,
        {"agent_id": agent_id, "benchmark_suite": "reliability-core", "environment": "dev"},
        headers,
    )
    cancel = client.post(f"/benchmarks/runs/{payload['benchmark_run_id']}/cancel", headers=headers)
    assert cancel.status_code == 409
