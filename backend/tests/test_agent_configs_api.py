from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _headers(role: str, actor_id: str) -> dict[str, str]:
    return {
        "X-Actor-Role": role,
        "X-Actor-Id": actor_id,
    }


def _payload(agent_key: str, config_id: str) -> dict:
    return {
        "config_id": config_id,
        "agent_key": agent_key,
        "display_name": "DB Configured Agent",
        "provider": "aws",
        "model": "gpt-4o-mini",
        "provider_priority": "aws,azure,google",
        "temperature": 0.3,
        "max_tokens": 1024,
        "timeout_ms": 4500,
        "fallback_enabled": True,
        "max_fallback_hops": 2,
        "global_timeout_ms": 4500,
        "retry_budget": 1,
        "failure_threshold_percent": 40,
        "cooldown_seconds": 60,
        "environment": "dev",
        "enabled": True,
        "notes": "test fixture",
    }


def test_agent_configs_crud_and_read_roles():
    suffix = uuid4().hex[:10]
    agent_key = f"agent-config-test-{suffix}"
    config_id = f"cfg{uuid4().hex[:29]}"
    admin_headers = _headers("Platform Admin", f"admin-{suffix}")
    auditor_headers = _headers("Auditor", f"auditor-{suffix}")

    upsert = client.put(
        f"/agent-configs/{agent_key}",
        json=_payload(agent_key, config_id),
        headers=admin_headers,
    )
    assert upsert.status_code == 200
    body = upsert.json()
    assert body["agent_key"] == agent_key
    assert body["display_name"] == "DB Configured Agent"
    assert body["updated_by"] == admin_headers["X-Actor-Id"]

    listed_admin = client.get("/agent-configs", headers=admin_headers)
    assert listed_admin.status_code == 200
    listed_keys = {item["agent_key"] for item in listed_admin.json()}
    assert agent_key in listed_keys

    listed_auditor = client.get("/agent-configs", headers=auditor_headers)
    assert listed_auditor.status_code == 200
    auditor_keys = {item["agent_key"] for item in listed_auditor.json()}
    assert agent_key in auditor_keys

    deleted = client.delete(f"/agent-configs/{agent_key}", headers=admin_headers)
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True


def test_agent_configs_write_forbidden_for_auditor_and_read_forbidden_for_agent_owner():
    suffix = uuid4().hex[:10]
    agent_key = f"agent-config-rbac-{suffix}"
    config_id = f"cfg{uuid4().hex[:29]}"

    forbidden_write = client.put(
        f"/agent-configs/{agent_key}",
        json=_payload(agent_key, config_id),
        headers=_headers("Auditor", f"auditor-{suffix}"),
    )
    assert forbidden_write.status_code == 403
    assert forbidden_write.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"

    forbidden_read = client.get("/agent-configs", headers=_headers("Agent Owner", f"owner-{suffix}"))
    assert forbidden_read.status_code == 403
    assert forbidden_read.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"


def test_agent_configs_reject_path_payload_key_mismatch():
    suffix = uuid4().hex[:10]
    admin_headers = _headers("Platform Admin", f"admin-mismatch-{suffix}")

    mismatch = client.put(
        f"/agent-configs/agent-key-{suffix}",
        json=_payload(f"different-agent-{suffix}", f"cfg{uuid4().hex[:29]}"),
        headers=admin_headers,
    )
    assert mismatch.status_code == 422
    assert mismatch.json()["detail"] == "agent_key in path must match payload"
