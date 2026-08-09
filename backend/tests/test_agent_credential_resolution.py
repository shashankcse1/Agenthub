import json
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database import engine
from app.main import app

client = TestClient(app)


def _ensure_tenant(tenant_id: str, actor_id: str) -> None:
    response = client.post(
        "/providers/tenants",
        json={
            "tenant_id": tenant_id,
            "tenant_name": tenant_id,
            "tenant_type": "internal",
            "description": "agent credential resolution tenant",
            "status": "active",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id, "X-MFA-Verified": "true"},
    )
    assert response.status_code in {200, 409}


def _create_db_provider(tenant_id: str, actor_id: str) -> str:
    created = client.post(
        "/secrets/providers",
        json={
            "tenant_id": tenant_id,
            "provider_type": "db",
            "provider_address": "platform://database",
            "auth_method": "encrypted-at-rest",
            "role_or_mount": "platform",
            "secret_path_prefixes": '["gateway/","providers/"]',
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id, "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    return created.json()["secret_provider_id"]


def test_agent_runtime_credential_resolution_via_binding():
    suffix = uuid4().hex[:8]
    tenant_id = f"tenant-agent-runtime-{suffix}"
    actor_id = f"admin-agent-runtime-{suffix}"
    agent_key = f"agent-runtime-{suffix}"
    _ensure_tenant(tenant_id, actor_id)
    provider_id = _create_db_provider(tenant_id, actor_id)

    stored = client.put(
        f"/secrets/providers/{provider_id}/values",
        json={"secret_ref": "providers/cursor/api-key", "secret_value": "agent-runtime-cursor-token"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id, "X-MFA-Verified": "true"},
    )
    assert stored.status_code == 200

    binding = client.post(
        "/providers/credential-bindings",
        json={
            "tenant_id": tenant_id,
            "binding_name": f"Agent Cursor {suffix}",
            "consumer_type": "agent",
            "consumer_key": agent_key,
            "provider_type": "cursor",
            "credential_plane": "secret_ref",
            "secret_provider_id": provider_id,
            "secret_ref": "providers/cursor/api-key",
            "environment": "dev",
            "status": "active",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id, "X-MFA-Verified": "true"},
    )
    assert binding.status_code == 200
    binding_id = binding.json()["binding_id"]

    upsert = client.put(
        f"/agent-configs/{agent_key}",
        json={
            "agent_key": agent_key,
            "display_name": "Runtime Agent",
            "provider": "cursor",
            "model": "cursor-default",
            "environment": "dev",
            "enabled": True,
            "credential_binding_id": binding_id,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id},
    )
    assert upsert.status_code == 200

    status = client.get(
        f"/agent-configs/{agent_key}/credential-status",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": f"aud-{suffix}"},
    )
    assert status.status_code == 200
    status_body = status.json()
    assert status_body["configured"] is True
    assert status_body["credential_binding_id"] == binding_id
    assert "agent-runtime-cursor-token" not in json.dumps(status_body)

    inference = client.post(
        "/v1/chat/completions",
        json={
            "model": "cursor-default",
            "messages": [{"role": "user", "content": "hello"}],
            "agent_id": agent_key,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id},
    )
    assert inference.status_code == 200


def test_agent_runtime_credential_resolution_fails_when_binding_unconfigured():
    suffix = uuid4().hex[:8]
    tenant_id = f"tenant-agent-runtime-fail-{suffix}"
    actor_id = f"admin-agent-runtime-fail-{suffix}"
    agent_key = f"agent-runtime-fail-{suffix}"
    _ensure_tenant(tenant_id, actor_id)
    provider_id = _create_db_provider(tenant_id, actor_id)

    binding = client.post(
        "/providers/credential-bindings",
        json={
            "tenant_id": tenant_id,
            "binding_name": f"Agent Missing Secret {suffix}",
            "consumer_type": "agent",
            "consumer_key": agent_key,
            "provider_type": "cursor",
            "credential_plane": "secret_ref",
            "secret_provider_id": provider_id,
            "secret_ref": "providers/cursor/missing-key",
            "environment": "dev",
            "status": "active",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id, "X-MFA-Verified": "true"},
    )
    assert binding.status_code == 200
    binding_id = binding.json()["binding_id"]

    upsert = client.put(
        f"/agent-configs/{agent_key}",
        json={
            "agent_key": agent_key,
            "display_name": "Broken Agent",
            "provider": "cursor",
            "model": "cursor-default",
            "environment": "dev",
            "enabled": True,
            "credential_binding_id": binding_id,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id},
    )
    assert upsert.status_code == 200

    inference = client.post(
        "/v1/chat/completions",
        json={
            "model": "cursor-default",
            "messages": [{"role": "user", "content": "hello"}],
            "agent_id": agent_key,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id},
    )
    assert inference.status_code == 503


def test_agent_config_rejects_mismatched_binding_provider():
    suffix = uuid4().hex[:8]
    tenant_id = f"tenant-agent-bind-mismatch-{suffix}"
    actor_id = f"admin-agent-bind-mismatch-{suffix}"
    agent_key = f"agent-bind-mismatch-{suffix}"
    _ensure_tenant(tenant_id, actor_id)
    provider_id = _create_db_provider(tenant_id, actor_id)

    stored = client.put(
        f"/secrets/providers/{provider_id}/values",
        json={"secret_ref": "providers/openai/api-key", "secret_value": "sk-test"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id, "X-MFA-Verified": "true"},
    )
    assert stored.status_code == 200

    binding = client.post(
        "/providers/credential-bindings",
        json={
            "tenant_id": tenant_id,
            "binding_name": "OpenAI Binding",
            "consumer_type": "agent",
            "consumer_key": agent_key,
            "provider_type": "openai",
            "credential_plane": "secret_ref",
            "secret_provider_id": provider_id,
            "secret_ref": "providers/openai/api-key",
            "environment": "dev",
            "status": "active",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id, "X-MFA-Verified": "true"},
    )
    assert binding.status_code == 200
    binding_id = binding.json()["binding_id"]

    upsert = client.put(
        f"/agent-configs/{agent_key}",
        json={
            "agent_key": agent_key,
            "display_name": "Mismatch Agent",
            "provider": "cursor",
            "model": "cursor-default",
            "environment": "dev",
            "enabled": True,
            "credential_binding_id": binding_id,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id},
    )
    assert upsert.status_code == 422


def test_agent_scope_binding_resolved_without_explicit_binding_id():
    suffix = uuid4().hex[:8]
    tenant_id = f"tenant-agent-scope-{suffix}"
    actor_id = f"admin-agent-scope-{suffix}"
    agent_key = f"agent-scope-{suffix}"
    _ensure_tenant(tenant_id, actor_id)
    provider_id = _create_db_provider(tenant_id, actor_id)

    client.put(
        f"/secrets/providers/{provider_id}/values",
        json={"secret_ref": "providers/cursor/api-key", "secret_value": "scope-resolved-token"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id, "X-MFA-Verified": "true"},
    )

    client.post(
        "/providers/credential-bindings",
        json={
            "tenant_id": tenant_id,
            "binding_name": "Scoped Agent Cursor",
            "consumer_type": "agent",
            "consumer_key": agent_key,
            "provider_type": "cursor",
            "credential_plane": "secret_ref",
            "secret_provider_id": provider_id,
            "secret_ref": "providers/cursor/api-key",
            "environment": "dev",
            "status": "active",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id, "X-MFA-Verified": "true"},
    )

    upsert = client.put(
        f"/agent-configs/{agent_key}",
        json={
            "agent_key": agent_key,
            "display_name": "Scoped Agent",
            "provider": "cursor",
            "model": "cursor-default",
            "environment": "dev",
            "enabled": True,
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id},
    )
    assert upsert.status_code == 200

    status = client.get(
        f"/agent-configs/{agent_key}/credential-status",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": f"aud-scope-{suffix}"},
    )
    assert status.status_code == 200
    assert status.json()["configured"] is True

    inference = client.post(
        "/v1/chat/completions",
        json={
            "model": "cursor-default",
            "messages": [{"role": "user", "content": "hello"}],
            "agent_id": agent_key,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id},
    )
    assert inference.status_code == 200
