from unittest.mock import patch
from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _headers(role: str, actor_id: str, *, mfa: bool = False) -> dict[str, str]:
    headers = {
        "X-Actor-Role": role,
        "X-Actor-Id": actor_id,
    }
    if mfa:
        headers["X-MFA-Verified"] = "true"
    return headers


def test_supported_models_crud_and_dropdown_read_roles():
    suffix = uuid4().hex[:8]
    admin_headers = _headers("Platform Admin", f"admin-model-{suffix}", mfa=True)
    auditor_headers = _headers("Auditor", f"auditor-model-{suffix}")

    created = client.post(
        "/providers/models",
        json={
            "provider_type": "openai",
            "model_name": f"gpt-4o-mini-{suffix}",
            "display_name": "GPT-4o Mini",
            "context_window_tokens": 128000,
            "status": "active",
            "description": "catalog test",
        },
        headers=admin_headers,
    )
    assert created.status_code == 200
    body = created.json()
    assert body["provider_type"] == "openai"
    assert body["display_name"] == "GPT-4o Mini"
    supported_model_id = body["supported_model_id"]

    listed = client.get("/providers/models?provider_type=openai&status=active", headers=auditor_headers)
    assert listed.status_code == 200
    rows = listed.json()
    assert any(row["supported_model_id"] == supported_model_id for row in rows)

    updated = client.put(
        f"/providers/models/{supported_model_id}",
        json={
            "provider_type": "openai",
            "model_name": f"gpt-4o-mini-{suffix}",
            "display_name": "GPT-4o Mini Updated",
            "context_window_tokens": 200000,
            "status": "beta",
            "description": "updated catalog test",
        },
        headers=admin_headers,
    )
    assert updated.status_code == 200
    assert updated.json()["display_name"] == "GPT-4o Mini Updated"
    assert updated.json()["status"] == "beta"

    deleted = client.delete(f"/providers/models/{supported_model_id}", headers=admin_headers)
    assert deleted.status_code == 200
    assert deleted.json()["deleted"] is True


def test_supported_models_write_requires_admin_and_mfa():
    suffix = uuid4().hex[:8]
    forbidden = client.post(
        "/providers/models",
        json={
            "provider_type": "aws",
            "model_name": f"bedrock-{suffix}",
            "display_name": "Bedrock Model",
            "context_window_tokens": 8000,
            "status": "active",
            "description": "forbidden test",
        },
        headers=_headers("Auditor", f"auditor-model-write-{suffix}"),
    )
    assert forbidden.status_code == 403

    mfa_required = client.post(
        "/providers/models",
        json={
            "provider_type": "aws",
            "model_name": f"bedrock-{suffix}",
            "display_name": "Bedrock Model",
            "context_window_tokens": 8000,
            "status": "active",
            "description": "mfa test",
        },
        headers=_headers("Platform Admin", f"admin-model-write-{suffix}"),
    )
    assert mfa_required.status_code == 403
    assert mfa_required.json()["detail"]["error_code"] == "AUTHZ_MFA_REQUIRED"


def test_seed_trending_supported_models_idempotent():
    suffix = uuid4().hex[:8]
    admin_headers = _headers("Platform Admin", f"admin-seed-{suffix}", mfa=True)

    first = client.post(
        "/providers/models/seed-trending",
        json={"overwrite": False, "auto_approve": True, "packs": ["trending"]},
        headers=admin_headers,
    )
    assert first.status_code == 200
    body = first.json()
    assert body["pack_size"] > 0
    assert body["created"] + body["updated"] + body["skipped"] == body["pack_size"]
    assert "trending" in (body.get("packs") or [])

    second = client.post(
        "/providers/models/seed-trending",
        json={"overwrite": False, "auto_approve": True, "packs": ["trending"]},
        headers=admin_headers,
    )
    assert second.status_code == 200
    assert second.json()["created"] == 0
    assert second.json()["skipped"] == body["pack_size"]

    listed = client.get("/providers/models?provider_type=deepseek&status=active", headers=_headers("Auditor", f"aud-seed-{suffix}"))
    assert listed.status_code == 200
    names = {row["model_name"] for row in listed.json()}
    assert "deepseek-chat" in names


def test_seed_cloud_packs_bedrock_azure_gcp():
    suffix = uuid4().hex[:8]
    admin_headers = _headers("Platform Admin", f"admin-cloud-seed-{suffix}", mfa=True)

    response = client.post(
        "/providers/models/seed-trending",
        json={"overwrite": False, "auto_approve": True, "packs": ["bedrock", "azure", "gcp"]},
        headers=admin_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["pack_size"] > 30
    assert body["created"] + body["updated"] + body["skipped"] == body["pack_size"]

    auditor = _headers("Auditor", f"aud-cloud-seed-{suffix}")
    bedrock = client.get("/providers/models?provider_type=aws&status=active&limit=500", headers=auditor)
    assert bedrock.status_code == 200
    bedrock_names = {row["model_name"] for row in bedrock.json()}
    assert "amazon.nova-pro-v1:0" in bedrock_names
    assert "anthropic.claude-3-5-sonnet-20241022-v2:0" in bedrock_names

    azure = client.get("/providers/models?provider_type=azure-openai&status=active&limit=500", headers=auditor)
    assert azure.status_code == 200
    azure_names = {row["model_name"] for row in azure.json()}
    assert "gpt-4o" in azure_names
    assert "o3-mini" in azure_names

    vertex = client.get("/providers/models?provider_type=vertex&status=active&limit=500", headers=auditor)
    assert vertex.status_code == 200
    vertex_names = {row["model_name"] for row in vertex.json()}
    assert "gemini-2.5-pro" in vertex_names


def test_discover_and_sync_cloud_models_endpoint(monkeypatch):
    from app.services.cloud_model_catalog import CloudModelSpec

    suffix = uuid4().hex[:8]
    admin_headers = _headers("Platform Admin", f"admin-discover-{suffix}", mfa=True)
    discovered = {
        "targets": ["bedrock"],
        "models": [
            {
                "provider_type": "aws",
                "model_name": f"amazon.nova-micro-live-{suffix}",
                "display_name": "Nova Micro Live",
                "context_window_tokens": 128000,
                "description": "live",
                "recommendation_rationale": "test",
                "status": "active",
            }
        ],
        "specs": [
            CloudModelSpec(
                "aws",
                f"amazon.nova-micro-live-{suffix}",
                "Nova Micro Live",
                128000,
                "live",
                "test",
            )
        ],
        "results": [{"provider": "aws", "total": 1, "source": "live"}],
        "errors": [],
        "total": 1,
    }

    with patch("app.routers.providers.discover_cloud_models", return_value=discovered):
        preview = client.post(
            "/providers/models/discover-cloud",
            json={"targets": ["bedrock"], "limit": 50},
            headers=admin_headers,
        )
        assert preview.status_code == 200, preview.text
        assert preview.json()["total"] == 1
        assert preview.json()["models"][0]["model_name"].endswith(suffix)

        synced = client.post(
            "/providers/models/sync-cloud",
            json={"targets": ["bedrock"], "overwrite": False, "auto_approve": True},
            headers=admin_headers,
        )
        assert synced.status_code == 200, synced.text
        assert synced.json()["discovered"] == 1
        assert synced.json()["created"] + synced.json()["updated"] + synced.json()["skipped"] == 1

    listed = client.get(
        f"/providers/models?provider_type=aws&status=active&limit=500",
        headers=_headers("Auditor", f"aud-discover-{suffix}"),
    )
    assert listed.status_code == 200
    names = {row["model_name"] for row in listed.json()}
    assert f"amazon.nova-micro-live-{suffix}" in names


def test_inference_readiness_endpoint_readable_by_auditor():
    suffix = uuid4().hex[:8]
    response = client.get(
        "/providers/models/inference-readiness",
        headers=_headers("Auditor", f"aud-ready-{suffix}"),
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert "providers" in body
    assert "ready_providers" in body
    assert any(row["provider_type"] == "openai" for row in body["providers"])
