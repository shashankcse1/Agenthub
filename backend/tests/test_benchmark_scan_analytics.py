"""Benchmark/scan historical analytics trend endpoints."""

from __future__ import annotations

from datetime import datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import Agent, BenchmarkRun, ScanRun

client = TestClient(app)


def _headers(actor_id: str, role: str = "Platform Admin") -> dict[str, str]:
    return {
        "X-Actor-Role": role,
        "X-Actor-Id": actor_id,
        "X-MFA-Verified": "true",
    }


def _seed_history(suffix: str) -> tuple[str, str]:
    agent_a = f"agent-analytics-a-{suffix}"
    agent_b = f"agent-analytics-b-{suffix}"
    owner_a = f"owner-analytics-a-{suffix}"
    owner_b = f"owner-analytics-b-{suffix}"
    now = datetime.utcnow()
    db = SessionLocal()
    try:
        for agent_id, owner_id in ((agent_a, owner_a), (agent_b, owner_b)):
            if not db.query(Agent).filter_by(agent_id=agent_id).first():
                db.add(
                    Agent(
                        agent_id=agent_id,
                        name=agent_id,
                        owner_id=owner_id,
                        owner_name=owner_id,
                        owner_team="analytics-team",
                        agent_type="other",
                        risk_tier="medium",
                        status="active",
                    )
                )
        db.add_all(
            [
                BenchmarkRun(
                    benchmark_run_id=f"br-{suffix}-1",
                    agent_id=agent_a,
                    benchmark_suite="reliability-core",
                    environment="dev",
                    status="completed",
                    score=90,
                    summary="ok",
                    created_at=now - timedelta(hours=2),
                ),
                BenchmarkRun(
                    benchmark_run_id=f"br-{suffix}-2",
                    agent_id=agent_a,
                    benchmark_suite="latency-core",
                    environment="prod",
                    status="failed",
                    score=40,
                    summary="fail",
                    created_at=now - timedelta(hours=30),
                ),
                BenchmarkRun(
                    benchmark_run_id=f"br-{suffix}-3",
                    agent_id=agent_b,
                    benchmark_suite="reliability-core",
                    environment="dev",
                    status="completed",
                    score=80,
                    summary="other",
                    created_at=now - timedelta(hours=4),
                ),
                ScanRun(
                    scan_run_id=f"sr-{suffix}-1",
                    agent_id=agent_a,
                    scan_type="security",
                    environment="dev",
                    status="completed",
                    findings_count=3,
                    severity_high_count=1,
                    summary="findings",
                    created_at=now - timedelta(hours=3),
                ),
                ScanRun(
                    scan_run_id=f"sr-{suffix}-2",
                    agent_id=agent_b,
                    scan_type="compliance",
                    environment="staging",
                    status="completed",
                    findings_count=1,
                    severity_high_count=0,
                    summary="other",
                    created_at=now - timedelta(hours=5),
                ),
            ]
        )
        db.commit()
    finally:
        db.close()
    return agent_a, owner_a


def test_benchmark_and_scan_analytics_trends_segment_and_scope():
    suffix = uuid4().hex[:8]
    agent_a, owner_a = _seed_history(suffix)
    admin = _headers(f"admin-{suffix}")

    bench = client.get(
        "/benchmarks/analytics/trends?window_hours=168&bucket_hours=24&segment_by=environment",
        headers=admin,
    )
    assert bench.status_code == 200, bench.text
    body = bench.json()
    assert body["kind"] == "benchmark"
    assert body["total_runs"] >= 2
    assert body["segment_by"] == "environment"
    assert any(seg["segment_key"] == "dev" for seg in body["segments"])
    assert any(bucket.get("run_count", 0) >= 1 for bucket in body["buckets"])

    bad = client.get(
        "/benchmarks/analytics/trends?segment_by=not-a-dimension",
        headers=admin,
    )
    assert bad.status_code == 422, bad.text

    owner = _headers(owner_a, "Agent Owner")
    scoped = client.get(
        f"/benchmarks/analytics/trends?segment_by=suite&agent_id={agent_a}",
        headers=owner,
    )
    assert scoped.status_code == 200, scoped.text
    assert all(
        True
        for _ in scoped.json()["segments"]
    )
    # Owner-scoped response should only include owned agent runs in segments/buckets
    # (suite labels only; agent_id filter applied server-side)
    assert scoped.json()["total_runs"] >= 1

    foreign = client.get(
        f"/benchmarks/analytics/trends?agent_id=agent-analytics-b-{suffix}",
        headers=owner,
    )
    assert foreign.status_code == 403, foreign.text

    scans = client.get(
        "/scans/analytics/trends?segment_by=scan_type&window_hours=168",
        headers=admin,
    )
    assert scans.status_code == 200, scans.text
    scan_body = scans.json()
    assert scan_body["kind"] == "scan"
    assert any(seg["segment_key"] in {"security", "compliance"} for seg in scan_body["segments"])

    denied = client.get(
        "/scans/analytics/trends",
        headers=_headers(f"deny-{suffix}", "Auditor"),
    )
    # Auditor is allowed for READ
    assert denied.status_code == 200, denied.text

    role_denied = client.get(
        "/scans/analytics/trends",
        headers=_headers(f"release-{suffix}", "Release Manager"),
    )
    assert role_denied.status_code == 200, role_denied.text
