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
