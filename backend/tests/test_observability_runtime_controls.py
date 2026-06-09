from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _admin_headers(actor_id: str) -> dict[str, str]:
    return {"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id}


def _auditor_headers(actor_id: str) -> dict[str, str]:
    return {"X-Actor-Role": "Auditor", "X-Actor-Id": actor_id}


def test_observability_logs_default_limit_is_runtime_configurable():
    key = "observability.logs.default_limit"
    try:
        upsert = client.put(
            f"/runtime-config/{key}",
            json={"config_value": "1", "description": "test override"},
            headers=_admin_headers("admin-obs-limit"),
        )
        assert upsert.status_code == 200

        logs = client.get(
            "/observability/logs",
            headers=_auditor_headers("aud-obs-limit"),
        )
        assert logs.status_code == 200
        assert len(logs.json()) <= 1
    finally:
        client.delete(
            f"/runtime-config/{key}",
            headers=_admin_headers("admin-obs-limit-cleanup"),
        )


def test_observability_schema_default_sample_size_is_runtime_configurable():
    key = "observability.schema.default_sample_size"
    try:
        upsert = client.put(
            f"/runtime-config/{key}",
            json={"config_value": "1", "description": "test override"},
            headers=_admin_headers("admin-obs-schema"),
        )
        assert upsert.status_code == 200

        schema = client.get(
            "/observability/logs/schema-status",
            headers=_auditor_headers("aud-obs-schema"),
        )
        assert schema.status_code == 200
        assert schema.json()["sampled_count"] <= 1
    finally:
        client.delete(
            f"/runtime-config/{key}",
            headers=_admin_headers("admin-obs-schema-cleanup"),
        )
