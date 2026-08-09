from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_playground_compare_ranks_factual_answer_highest():
    response = client.post(
        "/playground/compare",
        json={
            "prompt_text": "what is capital of russia",
            "candidate_models": ["gpt-4o-mini", "gpt-4o"],
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": f"admin-judge-{uuid4().hex[:8]}"},
    )
    assert response.status_code == 200
    results = response.json()["results"]
    assert len(results) == 2
    assert results[0]["quality_score"] >= results[1]["quality_score"]
    assert "Russia" in results[0]["response_preview"] or "Moscow" in results[0]["response_preview"]
    assert results[0]["estimated_latency_ms"] >= 1
    assert results[0]["estimated_cost_cents"] >= 1


def test_playground_compare_rejects_empty_candidates():
    response = client.post(
        "/playground/compare",
        json={"prompt_text": "hello", "candidate_models": []},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": f"admin-judge-empty-{uuid4().hex[:8]}"},
    )
    assert response.status_code == 422


def test_score_judge_response_prefers_factual_answer():
    from app.services.playground_judge import score_judge_response, score_judge_response_with_reason

    good = score_judge_response(
        prompt_text="what is capital of russia",
        model_name="gpt-4o-mini",
        response_text="The capital of Russia is Moscow.",
    )
    bad = score_judge_response(
        prompt_text="what is capital of russia",
        model_name="gpt-4o-mini",
        response_text="Simulated completion from gpt-4o-mini: what is capital of russia",
    )
    assert good > bad
    assert good >= 0.9

    score, tier, reason = score_judge_response_with_reason(
        prompt_text="what is capital of russia",
        model_name="gpt-4o-mini",
        response_text="The capital of Russia is Moscow.",
    )
    assert tier == "excellent"
    assert "Moscow" in reason


def test_playground_run_assess_scores_provided_response():
    actor_id = f"assess-owner-{uuid4().hex[:8]}"
    run_resp = client.post(
        "/playground/runs",
        json={
            "prompt_text": "## Multimodal Prompt Package\n\n## Prompt\nwhat is capital of russia",
            "candidate_models": '["gpt-4o-mini"]',
            "selected_model": "gpt-4o-mini",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": actor_id},
    )
    assert run_resp.status_code == 200
    run_id = run_resp.json()["run_id"]

    assess_resp = client.post(
        f"/playground/runs/{run_id}/assess",
        json={
            "response_text": "The capital of Russia is Moscow.",
            "trace_id": "trace-gateway-chat-completions-assess-test",
        },
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": actor_id},
    )
    assert assess_resp.status_code == 200
    payload = assess_resp.json()
    assert payload["quality_score"] >= 0.9
    assert payload["quality_tier"] == "excellent"
    assert payload["suggested_rating"] == 5
    assert payload["inference_ran"] is False
    assert "Moscow" in payload["score_reason"]


def test_playground_run_assess_re_infers_when_response_missing():
    actor_id = f"assess-admin-{uuid4().hex[:8]}"
    run_resp = client.post(
        "/playground/runs",
        json={
            "prompt_text": "what is capital of russia",
            "candidate_models": '["gpt-4o-mini"]',
            "selected_model": "gpt-4o-mini",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id},
    )
    assert run_resp.status_code == 200
    run_id = run_resp.json()["run_id"]

    assess_resp = client.post(
        f"/playground/runs/{run_id}/assess",
        json={"environment": "dev"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id},
    )
    assert assess_resp.status_code == 200
    payload = assess_resp.json()
    assert payload["inference_ran"] is True
    assert payload["quality_score"] >= 0.35
    assert payload["response_text"]
