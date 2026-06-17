from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _headers(role: str, actor_id: str, *, mfa: bool = False) -> dict[str, str]:
    headers = {"X-Actor-Role": role, "X-Actor-Id": actor_id}
    if mfa:
        headers["X-MFA-Verified"] = "true"
    return headers


def _create_model(model_name: str, *, status: str = "active") -> str:
    suffix = uuid4().hex[:8]
    admin_headers = _headers("Platform Admin", f"admin-avail-{suffix}", mfa=True)
    response = client.post(
        "/providers/models",
        json={
            "provider_type": "openai",
            "model_name": model_name,
            "display_name": f"Display {model_name}",
            "context_window_tokens": 128000,
            "status": status,
            "description": "availability test",
        },
        headers=admin_headers,
    )
    assert response.status_code == 200, response.text
    return response.json()["supported_model_id"]


def test_platform_available_models_returns_active_catalog_entries():
    suffix = uuid4().hex[:8]
    active_name = f"gpt-avail-active-{suffix}"
    disabled_name = f"gpt-avail-disabled-{suffix}"
    _create_model(active_name, status="active")
    _create_model(disabled_name, status="disabled")

    reader_headers = _headers("Agent Owner", f"owner-avail-{suffix}")
    response = client.get("/providers/models/available?provider_type=openai&limit=500", headers=reader_headers)
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["object"] == "list"
    assert "policy" in payload
    refs = {row["model_ref"] for row in payload["data"]}
    assert f"openai/{active_name}" in refs
    assert f"openai/{disabled_name}" not in refs


def test_platform_available_models_auditor_can_read():
    suffix = uuid4().hex[:8]
    response = client.get("/providers/models/available?limit=10", headers=_headers("Auditor", f"aud-{suffix}"))
    assert response.status_code == 200, response.text
