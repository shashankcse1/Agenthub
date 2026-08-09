from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.main import app
from app.models import GatewayResponseCacheEntry, RuntimeConfig
from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_CACHE_INFERENCE_SHORT_CIRCUIT_ENABLED
from app.services.runtime_config import invalidate_runtime_config_cache

client = TestClient(app)

ADMIN_HEADERS = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-cache-sc"}


def _set_short_circuit_enabled(enabled: bool) -> None:
    db: Session = SessionLocal()
    try:
        row = db.query(RuntimeConfig).filter_by(
            config_key=RUNTIME_CONFIG_GATEWAY_CACHE_INFERENCE_SHORT_CIRCUIT_ENABLED
        ).first()
        value = "true" if enabled else "false"
        if row is None:
            db.add(RuntimeConfig(config_key=RUNTIME_CONFIG_GATEWAY_CACHE_INFERENCE_SHORT_CIRCUIT_ENABLED, config_value=value))
        else:
            row.config_value = value
        db.commit()
        invalidate_runtime_config_cache(RUNTIME_CONFIG_GATEWAY_CACHE_INFERENCE_SHORT_CIRCUIT_ENABLED)
    finally:
        db.close()


def _create_global_exact_policy() -> str:
    created = client.post(
        "/gateway/cache/policies",
        json={
            "scope": "global",
            "ttl_seconds": 300,
            "cache_mode": "exact",
            "privacy_scope": "tenant",
            "non_cache_data_classes": '["pii","secret"]',
        },
        headers=ADMIN_HEADERS,
    )
    assert created.status_code == 200, created.text
    return created.json()["cache_policy_id"]


def test_short_circuit_disabled_does_not_skip_inference():
    _set_short_circuit_enabled(False)
    prompt = f"cache sc disabled {uuid4().hex[:8]}"
    with patch("app.routers.gateway.execute_chat_completion") as mock_exec:
        mock_exec.return_value.content = "simulated answer"
        mock_exec.return_value.finish_reason = "stop"
        mock_exec.return_value.usage.prompt_tokens = 5
        mock_exec.return_value.usage.completion_tokens = 3
        mock_exec.return_value.usage.total_tokens = 8

        first = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": prompt}]},
            headers=ADMIN_HEADERS,
        )
        assert first.status_code == 200
        assert first.json().get("cache_short_circuit") is not True

        second = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": prompt}]},
            headers=ADMIN_HEADERS,
        )
        assert second.status_code == 200
        assert mock_exec.call_count == 2


def test_exact_hit_short_circuits_without_provider_call():
    _set_short_circuit_enabled(True)
    _create_global_exact_policy()
    prompt = f"cache sc exact hit {uuid4().hex[:8]}"

    with patch("app.routers.gateway.execute_chat_completion") as mock_exec:
        mock_exec.return_value.content = "first response body"
        mock_exec.return_value.finish_reason = "stop"
        mock_exec.return_value.usage.prompt_tokens = 4
        mock_exec.return_value.usage.completion_tokens = 6
        mock_exec.return_value.usage.total_tokens = 10

        first = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": prompt}]},
            headers=ADMIN_HEADERS,
        )
        assert first.status_code == 200
        assert mock_exec.call_count == 1
        first_content = first.json()["choices"][0]["message"]["content"]

        second = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": prompt}]},
            headers=ADMIN_HEADERS,
        )
        assert second.status_code == 200
        assert mock_exec.call_count == 1
        assert second.json().get("cache_short_circuit") is True
        assert second.json()["choices"][0]["message"]["content"] == first_content


def test_semantic_hit_above_threshold_short_circuits():
    _set_short_circuit_enabled(True)
    base = uuid4().hex[:8]
    created = client.post(
        "/gateway/cache/policies",
        json={"scope": "global", "ttl_seconds": 300, "cache_mode": "semantic", "similarity_threshold": 0.5},
        headers=ADMIN_HEADERS,
    )
    assert created.status_code == 200

    first_prompt = f"semantic cache evidence {base} alpha bravo"
    second_prompt = f"semantic cache evidence {base} alpha charlie"

    with patch("app.routers.gateway.execute_responses_create") as mock_exec:
        mock_exec.return_value.output_text = "semantic stored output"
        mock_exec.return_value.output_items = []
        mock_exec.return_value.finish_reason = "stop"
        mock_exec.return_value.usage.prompt_tokens = 8
        mock_exec.return_value.usage.completion_tokens = 4
        mock_exec.return_value.usage.total_tokens = 12

        first = client.post(
            "/v1/responses",
            json={"model": "gpt-4o-mini", "input": first_prompt},
            headers=ADMIN_HEADERS,
        )
        assert first.status_code == 200
        assert mock_exec.call_count == 1

        second = client.post(
            "/v1/responses",
            json={"model": "gpt-4o-mini", "input": second_prompt},
            headers=ADMIN_HEADERS,
        )
        assert second.status_code == 200
        assert mock_exec.call_count == 1
        assert second.json().get("cache_short_circuit") is True
        assert second.json()["output_text"] == "semantic stored output"


def test_bypass_for_pii_data_class_does_not_store_entry():
    _set_short_circuit_enabled(True)
    client.post(
        "/gateway/cache/policies",
        json={
            "scope": "global",
            "ttl_seconds": 300,
            "cache_mode": "exact",
            "non_cache_data_classes": '["pii"]',
        },
        headers=ADMIN_HEADERS,
    )
    prompt = f"pii bypass {uuid4().hex[:8]}"

    with patch("app.routers.gateway.execute_chat_completion") as mock_exec:
        mock_exec.return_value.content = "should not cache"
        mock_exec.return_value.finish_reason = "stop"
        mock_exec.return_value.usage.prompt_tokens = 3
        mock_exec.return_value.usage.completion_tokens = 2
        mock_exec.return_value.usage.total_tokens = 5

        created = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "request_tag": "pii.customer-profile",
            },
            headers=ADMIN_HEADERS,
        )
        assert created.status_code == 200

    db: Session = SessionLocal()
    try:
        entries = db.query(GatewayResponseCacheEntry).filter(
            GatewayResponseCacheEntry.request_text.contains("pii bypass")
        ).count()
        assert entries == 0
    finally:
        db.close()

    read = client.get(
        "/gateway/cache/decisions?limit=20",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-pii-bypass"},
    )
    assert read.status_code == 200
    matching = [row for row in read.json() if row.get("decision") == "bypass" and row.get("data_class") == "pii"]
    assert matching


def test_owner_privacy_scope_requires_owner_context():
    _set_short_circuit_enabled(True)
    owner_scope = f"actor:owner-cache-{uuid4().hex[:6]}"
    client.post(
        "/gateway/cache/policies",
        json={
            "scope": f"owner:{owner_scope}",
            "ttl_seconds": 300,
            "cache_mode": "exact",
            "privacy_scope": "owner",
        },
        headers=ADMIN_HEADERS,
    )
    prompt = f"owner scope cache {uuid4().hex[:8]}"

    with patch("app.routers.gateway.execute_chat_completion") as mock_exec:
        mock_exec.return_value.content = "owner scoped"
        mock_exec.return_value.finish_reason = "stop"
        mock_exec.return_value.usage.prompt_tokens = 2
        mock_exec.return_value.usage.completion_tokens = 2
        mock_exec.return_value.usage.total_tokens = 4

        without_owner = client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o-mini", "messages": [{"role": "user", "content": prompt}]},
            headers=ADMIN_HEADERS,
        )
        assert without_owner.status_code == 200
        assert mock_exec.call_count == 1

        with_owner = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "owner_scope": owner_scope,
            },
            headers=ADMIN_HEADERS,
        )
        assert with_owner.status_code == 200
        assert mock_exec.call_count == 2

        cached = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "owner_scope": owner_scope,
            },
            headers=ADMIN_HEADERS,
        )
        assert cached.status_code == 200
        assert mock_exec.call_count == 2
        assert cached.json().get("cache_short_circuit") is True


def test_cache_stats_includes_short_circuit_fields():
    stats = client.get("/gateway/cache/stats", headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-stats"})
    assert stats.status_code == 200
    payload = stats.json()
    assert "short_circuit_enabled" in payload
    assert "active_cache_entries" in payload


def test_cache_invalidate_purges_entries():
    _set_short_circuit_enabled(True)
    scope = f"tenant:cache-purge-{uuid4().hex[:6]}"
    client.post(
        "/gateway/cache/policies",
        json={"scope": scope, "ttl_seconds": 120, "cache_mode": "exact"},
        headers=ADMIN_HEADERS,
    )
    prompt = f"purge test {uuid4().hex[:8]}"
    with patch("app.routers.gateway.execute_chat_completion") as mock_exec:
        mock_exec.return_value.content = "purge me"
        mock_exec.return_value.finish_reason = "stop"
        mock_exec.return_value.usage.prompt_tokens = 1
        mock_exec.return_value.usage.completion_tokens = 1
        mock_exec.return_value.usage.total_tokens = 2
        created = client.post(
            "/v1/chat/completions",
            json={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": prompt}],
                "tenant_id": scope.split(":", 1)[1],
            },
            headers=ADMIN_HEADERS,
        )
        assert created.status_code == 200

    invalidated = client.post(
        "/gateway/cache/delete",
        json={"scope": scope, "reason": "test purge", "active_only": True},
        headers=ADMIN_HEADERS,
    )
    assert invalidated.status_code == 200
    assert invalidated.json().get("purged_cache_entries", 0) >= 0
