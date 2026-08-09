from unittest.mock import Mock, patch
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app

from app.models import DiscoveryConnection, SecretProviderConfig, SecretProviderStoredValue
from app.services.discovery_live_sync import sync_discovery_connection
from app.services.secret_crypto import encrypt_secret_value

client = TestClient(app)


@pytest.fixture
def db():
    from app.database import SessionLocal

    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def _seed_secret(db, *, secret_ref: str, value: str):
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
            secret_ref=secret_ref,
            value_encrypted=encrypt_secret_value(value),
            updated_by="test",
        )
    )
    db.commit()
    return provider_id


def test_discovery_connection_presets_endpoint():
    resp = client.get(
        "/discovery/connection-presets",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-presets"},
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert "openai" in payload["priority_source_ids"]
    assert len(payload["presets"]) >= 46
    source_ids = {row["source_id"] for row in payload["presets"]}
    assert {"anthropic", "github", "aws_bedrock", "huggingface", "snowflake"}.issubset(source_ids)


def test_discovery_connection_live_perplexity_sync(db):
    provider_id = _seed_secret(db, secret_ref="providers/perplexity/api-key", value="pplx-test-key")
    connection = DiscoveryConnection(
        connection_id=f"dconn-{uuid4()}",
        tenant_id="tenant-a",
        source_id="perplexity",
        connection_name="Perplexity Prod",
        enabled=True,
        sync_interval_minutes=60,
        secret_provider_id=provider_id,
        secret_ref="providers/perplexity/api-key",
        connection_config_json="{}",
    )
    db.add(connection)
    db.commit()

    mock_response = Mock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/json"}
    mock_response.json.return_value = {
        "data": [
            {"id": "sonar-pro"},
            {"id": "sonar-reasoning"},
            {"id": "llama-3.1-sonar-small-128k-online"},
        ]
    }
    mock_response.raise_for_status = Mock()

    with patch("app.services.discovery_connectors.http_utils.httpx.get", return_value=mock_response):
        count, error = sync_discovery_connection(db, connection, actor_id="test-admin")
        db.commit()

    assert error is None
    assert count >= 1
    assert connection.last_sync_status == "success"


def test_discovery_connection_live_cursor_sync(db):
    provider_id = _seed_secret(db, secret_ref="gateway/cursor-token", value="cursor-test-token")
    connection = DiscoveryConnection(
        connection_id=f"dconn-{uuid4()}",
        tenant_id="tenant-a",
        source_id="cursor",
        connection_name="Cursor Gateway",
        enabled=True,
        sync_interval_minutes=60,
        secret_provider_id=provider_id,
        secret_ref="gateway/cursor-token",
        connection_config_json='{"workspace":"team-a"}',
    )
    db.add(connection)
    db.commit()

    mock_response = Mock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/json"}
    mock_response.json.return_value = {
        "data": [{"id": "agent-skills-pack", "name": "skills-pack"}],
    }
    mock_response.raise_for_status = Mock()

    with patch("app.services.discovery_connectors.http_utils.httpx.get", return_value=mock_response):
        count, error = sync_discovery_connection(db, connection, actor_id="test-admin")
        db.commit()

    assert error is None
    assert count == 1
    assert connection.last_sync_status == "success"
