import json
from datetime import datetime, timedelta
from uuid import uuid4

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.database import SessionLocal
from app.main import app
from app.models import AgentMemoryRecord, AuditEvent, SecretProviderConfig
from tests.conftest import response_error_code

client = TestClient(app)

ADMIN_HEADERS = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-memory-test"}
OWNER_HEADERS = {"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-memory-test"}


def test_gateway_memory_overview_returns_tier_summaries():
    response = client.get("/gateway/memory/overview", headers=ADMIN_HEADERS)
    assert response.status_code == 200
    payload = response.json()
    assert "semantic_cache" in payload
    assert "short_term" in payload
    assert "long_term" in payload
    assert payload["short_term_ttl_seconds"] >= 60
    assert payload["max_records_per_scope"] >= 1


def test_gateway_memory_record_create_list_and_get():
    scope_id = f"session-{uuid4().hex[:8]}"
    created = client.post(
        "/gateway/memory/records",
        json={
            "memory_tier": "short_term",
            "scope_type": "session",
            "scope_id": scope_id,
            "label": "operator-note",
            "content": "User prefers concise answers.",
            "metadata_json": '{"source":"test"}',
            "environment": "dev",
        },
        headers=ADMIN_HEADERS,
    )
    assert created.status_code == 200
    row = created.json()
    memory_id = row["memory_id"]
    assert row["memory_tier"] == "short_term"
    assert row["scope_id"] == scope_id
    assert row["expires_at"] is not None

    listed = client.get(
        f"/gateway/memory/records?memory_tier=short_term&scope_type=session&scope_id={scope_id}",
        headers=ADMIN_HEADERS,
    )
    assert listed.status_code == 200
    list_payload = listed.json()
    assert list_payload["total"] >= 1
    assert any(item["memory_id"] == memory_id for item in list_payload["data"])

    fetched = client.get(f"/gateway/memory/records/{memory_id}", headers=ADMIN_HEADERS)
    assert fetched.status_code == 200
    assert fetched.json()["content"] == "User prefers concise answers."

    db: Session = SessionLocal()
    try:
        audit = (
            db.query(AuditEvent)
            .filter_by(action_type="gateway.memory.record.create", resource_id=memory_id)
            .first()
        )
        assert audit is not None
    finally:
        db.close()


def test_gateway_memory_short_term_expires_on_list():
    db: Session = SessionLocal()
    memory_id = f"mem-exp-{uuid4().hex[:12]}"
    scope_id = f"exp-{uuid4().hex[:8]}"
    try:
        db.add(
            AgentMemoryRecord(
                memory_id=memory_id,
                memory_tier="short_term",
                scope_type="session",
                scope_id=scope_id,
                label="expired",
                content="stale context",
                metadata_json="{}",
                actor_id="admin-memory-test",
                environment="dev",
                status="active",
                expires_at=datetime.utcnow() - timedelta(minutes=5),
                created_at=datetime.utcnow() - timedelta(hours=2),
                updated_at=datetime.utcnow() - timedelta(hours=2),
            )
        )
        db.commit()
    finally:
        db.close()

    listed = client.get(
        f"/gateway/memory/records?memory_tier=short_term&scope_id={scope_id}",
        headers=ADMIN_HEADERS,
    )
    assert listed.status_code == 200
    assert all(item["memory_id"] != memory_id for item in listed.json()["data"])

    db = SessionLocal()
    try:
        row = db.query(AgentMemoryRecord).filter_by(memory_id=memory_id).first()
        assert row is not None
        assert row.status == "expired"
    finally:
        db.close()


def test_gateway_memory_create_prod_long_term_dual_approval_denied():
    denied = client.post(
        "/gateway/memory/records",
        json={
            "memory_tier": "long_term",
            "scope_type": "global",
            "scope_id": "platform",
            "label": "prod rule",
            "content": "Retain compliance baseline.",
            "environment": "prod",
        },
        headers=ADMIN_HEADERS,
    )
    assert denied.status_code == 403
    assert response_error_code(denied) == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    allowed = client.post(
        "/gateway/memory/records",
        json={
            "memory_tier": "long_term",
            "scope_type": "global",
            "scope_id": "platform",
            "label": "prod rule",
            "content": "Retain compliance baseline.",
            "environment": "prod",
        },
        headers={
            **ADMIN_HEADERS,
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-memory-create",
        },
    )
    assert allowed.status_code == 200
    memory_id = allowed.json()["memory_id"]

    db: Session = SessionLocal()
    try:
        audit = (
            db.query(AuditEvent)
            .filter_by(action_type="gateway.memory.record.create", resource_id=memory_id)
            .first()
        )
        assert audit is not None
    finally:
        db.close()


def test_gateway_memory_delete_prod_dual_approval():
    created = client.post(
        "/gateway/memory/records",
        json={
            "memory_tier": "long_term",
            "scope_type": "global",
            "scope_id": "platform",
            "label": "prod rule",
            "content": "Retain compliance baseline.",
            "environment": "prod",
        },
        headers={
            **ADMIN_HEADERS,
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-memory-create",
        },
    )
    assert created.status_code == 200
    memory_id = created.json()["memory_id"]

    denied = client.delete(f"/gateway/memory/records/{memory_id}", headers=ADMIN_HEADERS)
    assert denied.status_code == 403
    assert response_error_code(denied) == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    allowed = client.delete(
        f"/gateway/memory/records/{memory_id}",
        headers={
            **ADMIN_HEADERS,
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-memory-del",
        },
    )
    assert allowed.status_code == 200
    assert allowed.json()["deleted"] is True

    db: Session = SessionLocal()
    try:
        audit = (
            db.query(AuditEvent)
            .filter_by(action_type="gateway.memory.record.delete", resource_id=memory_id)
            .first()
        )
        assert audit is not None
    finally:
        db.close()


def test_gateway_memory_owner_scope_enforced():
    created = client.post(
        "/gateway/memory/records",
        json={
            "memory_tier": "short_term",
            "scope_type": "agent",
            "scope_id": "agent-a",
            "label": "owner note",
            "content": "private context",
        },
        headers=OWNER_HEADERS,
    )
    assert created.status_code == 200
    memory_id = created.json()["memory_id"]

    cross_read = client.get(
        f"/gateway/memory/records/{memory_id}",
        headers={"X-Actor-Role": "Agent Owner", "X-Actor-Id": "other-owner"},
    )
    assert cross_read.status_code == 403
    assert cross_read.json()["detail"]["error_code"] == "AUTHZ_SCOPE_FORBIDDEN"


def test_gateway_memory_platform_config_returns_tunable_sections():
    response = client.get("/gateway/memory/config", headers=ADMIN_HEADERS)
    assert response.status_code == 200
    payload = response.json()
    assert payload["memory"]["short_term_ttl_seconds"] >= 60
    assert payload["semantic_cache"]["default_mode"] in {"exact", "semantic"}
    assert "stores" in payload["vector_stores"]
    assert "runtime_config_keys" in payload


def test_gateway_vector_stores_list_and_health():
    stores_json = (
        '[{"store_id":"test-qdrant","provider_type":"qdrant","connection_url":"https://qdrant.local:6333",'
        '"collection_name":"docs","embedding_dimensions":1536,"similarity_metric":"cosine","enabled":true,'
        '"secret_provider_id":"sp-test-vector","api_key_secret_ref":"providers/vector/qdrant/test-qdrant/api-key"}]'
    )
    put = client.put(
        "/runtime-config/gateway.vector_stores_json",
        json={"config_value": stores_json, "description": "test vector stores"},
        headers={
            **ADMIN_HEADERS,
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-vector-stores-test",
        },
    )
    assert put.status_code == 200

    listed = client.get("/gateway/vector-stores", headers=ADMIN_HEADERS)
    assert listed.status_code == 200
    data = listed.json()["data"]
    assert any(row["store_id"] == "test-qdrant" for row in data)

    health = client.post("/gateway/vector-stores/test-qdrant/health", headers=ADMIN_HEADERS)
    assert health.status_code == 200
    assert health.json()["store_id"] == "test-qdrant"
    assert health.json()["status"] in {"configured", "disabled", "misconfigured"}


def test_gateway_vector_stores_json_validation_rejects_bad_provider():
    bad = '[{"store_id":"x","provider_type":"unknown","connection_url":"https://x","collection_name":"c"}]'
    validation = client.post(
        "/runtime-config/validate",
        json={"config_key": "gateway.vector_stores_json", "config_value": bad},
        headers=ADMIN_HEADERS,
    )
    assert validation.status_code == 200
    assert validation.json()["valid"] is False


def test_gateway_vector_stores_json_validation_rejects_inline_api_key():
    bad = (
        '[{"store_id":"x","provider_type":"qdrant","connection_url":"https://x","collection_name":"c",'
        '"api_key":"sk-live-inline","secret_provider_id":"sp-1","api_key_secret_ref":"providers/vector/qdrant/x/api-key"}]'
    )
    validation = client.post(
        "/runtime-config/validate",
        json={"config_key": "gateway.vector_stores_json", "config_value": bad},
        headers=ADMIN_HEADERS,
    )
    assert validation.status_code == 200
    assert validation.json()["valid"] is False
    assert "inline" in validation.json()["error"]


def test_gateway_vector_stores_json_validation_requires_secret_ref_for_qdrant():
    bad = (
        '[{"store_id":"x","provider_type":"qdrant","connection_url":"https://x","collection_name":"c",'
        '"enabled":true,"secret_provider_id":"sp-1"}]'
    )
    validation = client.post(
        "/runtime-config/validate",
        json={"config_key": "gateway.vector_stores_json", "config_value": bad},
        headers=ADMIN_HEADERS,
    )
    assert validation.status_code == 200
    assert validation.json()["valid"] is False
    assert "api_key_secret_ref" in validation.json()["error"]


def test_gateway_vector_stores_json_validation_requires_mcp_server_id_for_bridge():
    bad = (
        '[{"store_id":"mcp-bridge-1","provider_type":"mcp_bridge","collection_name":"docs",'
        '"enabled":true,"secret_provider_id":"sp-mcp","api_key_secret_ref":"providers/vector/mcp/mcp-bridge-1/api-key"}]'
    )
    validation = client.post(
        "/runtime-config/validate",
        json={"config_key": "gateway.vector_stores_json", "config_value": bad},
        headers=ADMIN_HEADERS,
    )
    assert validation.status_code == 200
    assert validation.json()["valid"] is False
    assert "mcp_server_id" in validation.json()["error"]


def test_gateway_vector_store_context_endpoint():
    stores_json = (
        '[{"store_id":"ctx-qdrant","provider_type":"qdrant","connection_url":"https://qdrant.local:6333",'
        '"collection_name":"docs","embedding_dimensions":1536,"similarity_metric":"cosine","enabled":true,'
        '"secret_provider_id":"sp-ctx-vector","api_key_secret_ref":"providers/vector/qdrant/ctx-qdrant/api-key"}]'
    )
    put = client.put(
        "/runtime-config/gateway.vector_stores_json",
        json={"config_value": stores_json, "description": "context endpoint test"},
        headers={
            **ADMIN_HEADERS,
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-vector-context-test",
        },
    )
    assert put.status_code == 200

    response = client.get("/gateway/vector-stores/ctx-qdrant/context", headers=ADMIN_HEADERS)
    assert response.status_code == 200
    payload = response.json()
    assert payload["store"]["store_id"] == "ctx-qdrant"
    assert payload["health"]["store_id"] == "ctx-qdrant"
    assert "search_top_k" in payload["platform"]
    assert "secret_integration" in payload

    db: Session = SessionLocal()
    try:
        audit = (
            db.query(AuditEvent)
            .filter_by(action_type="gateway.vector_store.context.read", resource_id="ctx-qdrant")
            .first()
        )
        assert audit is not None
    finally:
        db.close()


def test_gateway_memory_pii_classification_blocks_when_enabled():
    client.put(
        "/runtime-config/gateway.memory.pii_classification_enabled",
        json={"config_value": "true", "description": "enable pii classification test"},
        headers=ADMIN_HEADERS,
    )
    blocked = client.post(
        "/gateway/memory/records",
        json={
            "memory_tier": "short_term",
            "scope_type": "session",
            "scope_id": f"pii-{uuid4().hex[:8]}",
            "label": "pii test",
            "content": "Customer SSN is 123-45-6789",
            "metadata_json": '{"data_class":"pii.customer"}',
        },
        headers=ADMIN_HEADERS,
    )
    assert blocked.status_code == 422
    assert blocked.json()["detail"]["error_code"] == "MEMORY_DATA_CLASS_BLOCKED"

    allowed = client.post(
        "/gateway/memory/records",
        json={
            "memory_tier": "short_term",
            "scope_type": "session",
            "scope_id": f"ok-{uuid4().hex[:8]}",
            "label": "safe note",
            "content": "User prefers concise answers.",
        },
        headers=ADMIN_HEADERS,
    )
    assert allowed.status_code == 200
    metadata = json.loads(allowed.json()["metadata_json"])
    assert metadata.get("data_class") == "standard"

    client.put(
        "/runtime-config/gateway.memory.pii_classification_enabled",
        json={"config_value": "false", "description": "disable pii classification test"},
        headers=ADMIN_HEADERS,
    )


def test_gateway_vector_store_health_cloud_secret_posture_fields():
    suffix = uuid4().hex[:8]
    provider_id = f"sp-aws-vector-{suffix}"
    store_id = f"cloud-vector-{suffix}"
    db: Session = SessionLocal()
    try:
        db.add(
            SecretProviderConfig(
                secret_provider_id=provider_id,
                tenant_id=f"tenant-{suffix}",
                provider_type="aws-secrets-manager",
                provider_address="https://secretsmanager.us-east-1.amazonaws.com",
                auth_method="iam_role",
                role_or_mount="arn:aws:iam::123456789012:role/vector-test",
                secret_path_prefixes='["providers/"]',
                status="active",
            )
        )
        db.commit()
    finally:
        db.close()

    stores_json = (
        f'[{{"store_id":"{store_id}","provider_type":"qdrant","connection_url":"https://qdrant.local:6333",'
        f'"collection_name":"docs","embedding_dimensions":1536,"similarity_metric":"cosine","enabled":true,'
        f'"secret_provider_id":"{provider_id}","api_key_secret_ref":"providers/vector/qdrant/{store_id}/api-key"}}]'
    )
    put = client.put(
        "/runtime-config/gateway.vector_stores_json",
        json={"config_value": stores_json, "description": "cloud posture test"},
        headers={
            **ADMIN_HEADERS,
            "X-Approver-Role": "Security Approver",
            "X-Approver-Id": "sec-cloud-vector-test",
        },
    )
    assert put.status_code == 200

    health = client.post(f"/gateway/vector-stores/{store_id}/health", headers=ADMIN_HEADERS)
    assert health.status_code == 200
    payload = health.json()
    assert payload["secret_backend_type"] == "aws-secrets-manager"
    assert payload["cloud_integrated"] is True
    assert payload["secret_integration_mode"] == "aws_secrets_manager"
