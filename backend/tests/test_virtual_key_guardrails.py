import json

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _admin_headers(actor_id: str) -> dict[str, str]:
    return {
        "X-Actor-Role": "Platform Admin",
        "X-Actor-Id": actor_id,
    }


def test_create_key_with_guardrail_policy_and_evaluate_allow():
    created = client.post(
        "/keys",
        headers=_admin_headers("guardrail-admin-create"),
        json={
            "owner_scope_type": "team",
            "owner_scope_id": "platform",
            "allowed_endpoint_families": '["responses"]',
            "allowed_models": '["gpt-test"]',
            "guardrail_policy": json.dumps(
                {
                    "allowed_environments": ["dev", "prod"],
                    "max_requests_per_minute": 100,
                    "max_input_tokens": 4096,
                    "max_output_tokens": 2048,
                    "require_mfa_for_prod": True,
                }
            ),
        },
    )
    assert created.status_code == 200, created.text
    payload = created.json()
    key_id = payload["key_id"]

    evaluate = client.post(
        f"/keys/{key_id}/guardrails/evaluate",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "guardrail-aud-allow"},
        json={
            "environment": "dev",
            "requests_last_minute": 10,
            "input_tokens": 1024,
            "output_tokens": 512,
            "mfa_verified": False,
        },
    )
    assert evaluate.status_code == 200, evaluate.text
    decision = evaluate.json()
    assert decision["decision"] == "allow"
    assert decision["reasons"] == []


def test_key_guardrail_evaluate_denies_policy_violations():
    created = client.post(
        "/keys",
        headers=_admin_headers("guardrail-admin-deny"),
        json={
            "owner_scope_type": "team",
            "owner_scope_id": "platform",
            "allowed_endpoint_families": '["responses"]',
            "allowed_models": '["gpt-test"]',
            "guardrail_policy": json.dumps(
                {
                    "allowed_environments": ["prod"],
                    "max_requests_per_minute": 5,
                    "max_input_tokens": 100,
                    "max_output_tokens": 100,
                    "require_mfa_for_prod": True,
                    "blocked_owner_scope_ids": ["blocked-team"],
                }
            ),
        },
    )
    assert created.status_code == 200, created.text
    key_id = created.json()["key_id"]

    evaluate = client.post(
        f"/keys/{key_id}/guardrails/evaluate",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "guardrail-aud-deny"},
        json={
            "environment": "prod",
            "requests_last_minute": 8,
            "input_tokens": 120,
            "output_tokens": 140,
            "owner_scope_id": "blocked-team",
            "mfa_verified": False,
        },
    )
    assert evaluate.status_code == 200, evaluate.text
    decision = evaluate.json()
    assert decision["decision"] == "deny"
    assert any("exceeds" in reason for reason in decision["reasons"])
    assert any("blocked" in reason for reason in decision["reasons"])
    assert any("mfa" in reason for reason in decision["reasons"])


def test_create_key_rejects_invalid_guardrail_policy():
    created = client.post(
        "/keys",
        headers=_admin_headers("guardrail-admin-invalid"),
        json={
            "owner_scope_type": "team",
            "owner_scope_id": "platform",
            "allowed_endpoint_families": '["responses"]',
            "allowed_models": '["gpt-test"]',
            "guardrail_policy": json.dumps({"unsupported": True}),
        },
    )
    assert created.status_code == 422, created.text
    assert "unsupported keys" in created.json()["detail"]
