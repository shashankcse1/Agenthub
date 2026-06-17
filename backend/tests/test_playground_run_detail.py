from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_playground_run_detail_returns_aggregated_payload():
    created = client.post(
        "/playground/runs",
        json={
            "prompt_text": "detail aggregation check",
            "candidate_models": '["gpt-4o-mini"]',
            "selected_model": "gpt-4o-mini",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": f"pg-detail-{uuid4().hex[:8]}"},
    )
    assert created.status_code == 200
    run_id = created.json()["run_id"]

    detail = client.get(
        f"/playground/runs/{run_id}/detail",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": f"pg-detail-read-{uuid4().hex[:8]}"},
    )
    assert detail.status_code == 200
    payload = detail.json()
    assert payload["run"]["run_id"] == run_id
    assert isinstance(payload["feedback"], list)
    assert isinstance(payload["audit_events"], list)
    assert "latest_assessment" in payload
    assert "route_draft" in payload
    assert "quality_escalation" in payload


def test_playground_run_detail_enforces_agent_owner_scope():
    created = client.post(
        "/playground/runs",
        json={
            "prompt_text": "detail scope check",
            "candidate_models": '["gpt-4o-mini"]',
            "selected_model": "gpt-4o-mini",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-detail-a"},
    )
    assert created.status_code == 200
    run_id = created.json()["run_id"]

    denied = client.get(
        f"/playground/runs/{run_id}/detail",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-detail-b"},
    )
    assert denied.status_code == 403


def test_playground_run_detail_includes_feedback_and_assessment():
    actor_id = f"pg-populated-{uuid4().hex[:8]}"
    headers = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id}
    created = client.post(
        "/playground/runs",
        json={
            "prompt_text": "populated drill-down check",
            "candidate_models": '["gpt-4o-mini"]',
            "selected_model": "gpt-4o-mini",
        },
        headers=headers,
    )
    assert created.status_code == 200
    run_id = created.json()["run_id"]
    trace_id = f"trace-{run_id}"

    feedback_resp = client.post(
        f"/playground/runs/{run_id}/feedback",
        json={
            "trace_id": trace_id,
            "rating": 4,
            "quality_score": 0.82,
            "comment": "Good response quality",
        },
        headers=headers,
    )
    assert feedback_resp.status_code == 200

    detail = client.get(f"/playground/runs/{run_id}/detail", headers=headers)
    assert detail.status_code == 200
    payload = detail.json()
    assert len(payload["feedback"]) >= 1
    assert payload["latest_assessment"] is not None
    assert payload["latest_assessment"]["quality_score"] >= 0.82
