import json
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.main import app
from app.models import AuditEvent

client = TestClient(app)

ADMIN_HEADERS = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-rag-test"}
OWNER_HEADERS = {"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-rag-test"}
AUDITOR_HEADERS = {"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-rag-test"}


def _admin_with_approver(actor_id: str = "admin-rag-test") -> dict[str, str]:
    return {
        "X-Actor-Role": "Platform Admin",
        "X-Actor-Id": actor_id,
        "X-Approver-Role": "Security Approver",
        "X-Approver-Id": f"{actor_id}-approver",
    }


def _ensure_tenant(tenant_id: str, actor_id: str) -> None:
    response = client.post(
        "/providers/tenants",
        json={
            "tenant_id": tenant_id,
            "tenant_name": tenant_id,
            "tenant_type": "internal",
            "description": "rag test tenant",
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
            "secret_path_prefixes": '["providers/"]',
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id, "X-MFA-Verified": "true"},
    )
    assert created.status_code == 200
    return created.json()["secret_provider_id"]


def _upsert_mcp_servers(config_value: str) -> None:
    response = client.put(
        "/runtime-config/gateway.mcp.servers_json",
        headers=_admin_with_approver("mcp-rag-admin"),
        json={"config_value": config_value, "description": "rag mcp registry"},
    )
    assert response.status_code == 200, response.text


def _upsert_vector_stores(config_value: str) -> None:
    response = client.put(
        "/runtime-config/gateway.vector_stores_json",
        headers=_admin_with_approver("vector-rag-admin"),
        json={"config_value": config_value, "description": "rag vector stores"},
    )
    assert response.status_code == 200, response.text


def _seed_mcp_bridge_store(monkeypatch) -> str:
    suffix = uuid4().hex[:8]
    store_id = f"rag-mcp-{suffix}"
    mcp_server_id = f"vector-mcp-{suffix}"
    tenant_id = f"tenant-rag-{suffix}"
    actor_id = f"admin-rag-{suffix}"
    _ensure_tenant(tenant_id, actor_id)
    provider_id = _create_db_provider(tenant_id, actor_id)

    secret_ref = f"providers/vector/mcp/{store_id}/api-key"
    stored = client.put(
        f"/secrets/providers/{provider_id}/values",
        json={"secret_ref": secret_ref, "secret_value": "vector-test-api-key"},
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id, "X-MFA-Verified": "true"},
    )
    assert stored.status_code == 200

    _upsert_mcp_servers(
        json.dumps(
            [
                {
                    "server_id": mcp_server_id,
                    "base_url": "http://127.0.0.1:9400/mcp",
                    "transport": "streamable_http",
                    "enabled": True,
                    "allowed_tools": ["vector.search", "vector.upsert", "vector.delete"],
                }
            ]
        )
    )
    _upsert_vector_stores(
        json.dumps(
            [
                {
                    "store_id": store_id,
                    "provider_type": "mcp_bridge",
                    "collection_name": "docs",
                    "embedding_dimensions": 1536,
                    "similarity_metric": "cosine",
                    "enabled": True,
                    "mcp_server_id": mcp_server_id,
                    "secret_provider_id": provider_id,
                    "api_key_secret_ref": secret_ref,
                }
            ]
        )
    )
    return store_id


def test_openai_vector_stores_list_and_get():
    store_id = "rag-list-store"
    _upsert_vector_stores(
        json.dumps(
            [
                {
                    "store_id": store_id,
                    "provider_type": "qdrant",
                    "connection_url": "https://qdrant.local:6333",
                    "collection_name": "docs",
                    "embedding_dimensions": 1536,
                    "similarity_metric": "cosine",
                    "enabled": True,
                    "secret_provider_id": "sp-test",
                    "api_key_secret_ref": "providers/vector/qdrant/rag-list-store/api-key",
                }
            ]
        )
    )
    listed = client.get("/v1/vector_stores", headers=ADMIN_HEADERS)
    assert listed.status_code == 200
    data = listed.json()["data"]
    assert any(row["id"] == store_id for row in data)

    fetched = client.get(f"/v1/vector_stores/{store_id}", headers=ADMIN_HEADERS)
    assert fetched.status_code == 200
    assert fetched.json()["object"] == "vector_store"


def test_openai_vector_store_register_is_read_only():
    response = client.post(
        "/v1/vector_stores",
        json={
            "store_id": "new-store",
            "provider_type": "mcp_bridge",
            "collection_name": "docs",
        },
        headers=ADMIN_HEADERS,
    )
    assert response.status_code == 409
    assert response.json()["detail"]["error_code"] == "VECTOR_STORE_REGISTRY_READ_ONLY"


def test_rag_ingest_and_query_mcp_bridge(monkeypatch):
    store_id = _seed_mcp_bridge_store(monkeypatch)
    call_log: list[dict] = []

    class _FakeResponse:
        status_code = 200

        def __init__(self, payload):
            self._payload = payload

        def json(self):
            return self._payload

    def _fake_post(url, json=None, headers=None, timeout=None):
        payload = json or {}
        call_log.append(payload)
        method = payload.get("method")
        if method == "tools/call":
            tool_name = payload["params"]["name"]
            if tool_name == "vector.upsert":
                return _FakeResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": "rpc-upsert",
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": '{"ingested": 1, "status": "ok"}',
                                }
                            ]
                        },
                    }
                )
            if tool_name == "vector.search":
                return _FakeResponse(
                    {
                        "jsonrpc": "2.0",
                        "id": "rpc-search",
                        "result": {
                            "content": [
                                {
                                    "type": "text",
                                    "text": (
                                        '{"results": [{"id": "doc-1", "text": "hello world", "score": 0.91}]}'
                                    ),
                                }
                            ]
                        },
                    }
                )
        raise AssertionError(f"unexpected MCP method {method}")

    monkeypatch.setattr("app.services.mcp_gateway.httpx.post", _fake_post)

    ingest = client.post(
        "/rag/ingest",
        json={
            "store_id": store_id,
            "documents": [{"id": "doc-1", "text": "hello world", "metadata": {"source": "test"}}],
            "metadata": {"batch": "rag-test"},
        },
        headers=ADMIN_HEADERS,
    )
    assert ingest.status_code == 200, ingest.text
    ingest_payload = ingest.json()
    assert ingest_payload["ingested"] == 1
    assert ingest_payload["document_ids"] == ["doc-1"]
    assert call_log
    upsert_args = call_log[-1]["params"]["arguments"]
    assert upsert_args["credentials"]["api_key"] == "vector-test-api-key"
    assert "vector-test-api-key" not in ingest.text

    query = client.post(
        "/rag/query",
        json={"store_id": store_id, "query": "hello", "top_k": 3},
        headers=ADMIN_HEADERS,
    )
    assert query.status_code == 200, query.text
    query_payload = query.json()
    assert query_payload["match_count"] == 1
    assert query_payload["matches"][0]["id"] == "doc-1"

    db: Session = SessionLocal()
    try:
        ingest_audit = (
            db.query(AuditEvent)
            .filter_by(action_type="gateway.rag.ingest", resource_id=store_id)
            .first()
        )
        query_audit = (
            db.query(AuditEvent)
            .filter_by(action_type="gateway.rag.query", resource_id=store_id)
            .first()
        )
        assert ingest_audit is not None
        assert query_audit is not None
    finally:
        db.close()


def test_rag_query_role_gating():
    store_id = "rag-role-store"
    _upsert_vector_stores(
        json.dumps(
            [
                {
                    "store_id": store_id,
                    "provider_type": "mcp_bridge",
                    "collection_name": "docs",
                    "embedding_dimensions": 1536,
                    "similarity_metric": "cosine",
                    "enabled": True,
                    "mcp_server_id": "missing-mcp",
                }
            ]
        )
    )
    denied = client.post(
        "/rag/query",
        json={"store_id": store_id, "query": "test"},
        headers=AUDITOR_HEADERS,
    )
    assert denied.status_code == 403

    allowed_owner = client.post(
        "/rag/query",
        json={"store_id": store_id, "query": "test"},
        headers=OWNER_HEADERS,
    )
    assert allowed_owner.status_code != 403


def _custom_http_probe_store(store_id: str) -> str:
    return json.dumps(
        [
            {
                "store_id": store_id,
                "provider_type": "custom_http",
                "connection_url": "https://vector.example/health",
                "collection_name": "docs",
                "embedding_dimensions": 1536,
                "similarity_metric": "cosine",
                "enabled": True,
                "secret_provider_id": "sp-probe-test",
                "api_key_secret_ref": f"providers/vector/custom_http/{store_id}/api-key",
            }
        ]
    )


def test_vector_store_live_probe_flag_off_skips_network(monkeypatch):
    store_id = "probe-off-store"
    client.put(
        "/runtime-config/gateway.vector_stores.live_probe_enabled",
        json={"config_value": "false", "description": "disable live probe for test"},
        headers=ADMIN_HEADERS,
    )
    _upsert_vector_stores(_custom_http_probe_store(store_id))

    def _fail_head(*args, **kwargs):
        raise AssertionError("live probe should not run when flag is off")

    monkeypatch.setattr("httpx.head", _fail_head)

    health = client.post(f"/gateway/vector-stores/{store_id}/health", headers=ADMIN_HEADERS)
    assert health.status_code == 200
    payload = health.json()
    assert payload.get("live_probed") in {None, False}


def test_vector_store_live_probe_flag_on_custom_http(monkeypatch):
    store_id = "probe-on-store"
    _upsert_vector_stores(_custom_http_probe_store(store_id))
    client.put(
        "/runtime-config/gateway.vector_stores.live_probe_enabled",
        json={"config_value": "true", "description": "enable live probe for test"},
        headers=ADMIN_HEADERS,
    )

    class _FakeHeadResponse:
        status_code = 200

    monkeypatch.setattr("httpx.head", lambda *args, **kwargs: _FakeHeadResponse())

    health = client.post(f"/gateway/vector-stores/{store_id}/health", headers=ADMIN_HEADERS)
    assert health.status_code == 200
    payload = health.json()
    assert payload.get("live_probed") is True
    assert payload.get("live_reachable") is True
