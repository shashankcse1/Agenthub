import json
from unittest.mock import Mock, patch
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from app.database import SessionLocal
from app.main import app
from app.models import DiscoveryConnection, SecretProviderConfig, SecretProviderStoredValue
from app.services.discovery_live_sync import sync_discovery_connection
from app.services.secret_crypto import encrypt_secret_value

client = TestClient(app)


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _seed_openai_secret(db):
    provider_id = f"sec-{uuid4().hex[:8]}"
    provider = SecretProviderConfig(
        secret_provider_id=provider_id,
        tenant_id="tenant-a",
        provider_type="db",
        provider_address="platform://database",
        auth_method="encrypted-at-rest",
        role_or_mount="platform",
        status="active",
    )
    db.add(provider)
    db.flush()
    db.add(
        SecretProviderStoredValue(
            secret_provider_id=provider_id,
            secret_ref="providers/openai/api-key",
            value_encrypted=encrypt_secret_value("sk-test-openai"),
            updated_by="test",
        )
    )
    db.commit()
    return provider_id


def test_discovery_connection_live_openai_sync(db):
    provider_id = _seed_openai_secret(db)
    connection = DiscoveryConnection(
        connection_id=f"dconn-{uuid4()}",
        tenant_id="tenant-a",
        source_id="openai",
        connection_name="OpenAI Prod",
        enabled=True,
        sync_interval_minutes=60,
        secret_provider_id=provider_id,
        secret_ref="providers/openai/api-key",
        connection_config_json="{}",
    )
    db.add(connection)
    db.commit()

    mock_response = Mock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/json"}
    mock_response.json.return_value = {"data": [{"id": "gpt-4o"}, {"id": "gpt-4o-mini"}]}
    mock_response.raise_for_status = Mock()

    with patch("app.services.discovery_connectors.http_utils.httpx.get", return_value=mock_response):
        count, error = sync_discovery_connection(db, connection, actor_id="test-admin")
        db.commit()

    assert error is None
    assert count == 2
    assert connection.last_sync_status == "success"

    list_resp = client.get(
        "/discovery/agents",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-live-discovery"},
    )
    assert list_resp.status_code == 200
    keys = {row["canonical_agent_key"] for row in list_resp.json()}
    assert "openai:gpt-4o" in keys


def test_discovery_connection_crud_and_test(db):
    provider_id = _seed_openai_secret(db)
    create = client.post(
        "/discovery/connections",
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-discovery-conn"},
        json={
            "tenant_id": "tenant-a",
            "source_id": "openai",
            "connection_name": "OpenAI Dev",
            "secret_provider_id": provider_id,
            "secret_ref": "providers/openai/api-key",
            "sync_interval_minutes": 30,
            "connection_config": {},
        },
    )
    assert create.status_code == 200
    connection_id = create.json()["connection_id"]

    mock_response = Mock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/json"}
    mock_response.json.return_value = {"data": [{"id": "gpt-4"}]}
    mock_response.raise_for_status = Mock()

    with patch("app.services.discovery_connectors.http_utils.httpx.get", return_value=mock_response):
        test = client.post(
            f"/discovery/connections/{connection_id}/test",
            headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-discovery-conn"},
        )
    assert test.status_code == 200
    assert test.json()["test_status"] == "success"
    assert test.json()["sample_count"] == 1

    listed = client.get(
        "/discovery/connections",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-discovery-conn"},
    )
    assert listed.status_code == 200
    assert any(row["connection_id"] == connection_id for row in listed.json())
