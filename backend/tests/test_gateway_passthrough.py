from unittest.mock import MagicMock, patch
from uuid import uuid4

from fastapi.testclient import TestClient

from app.main import app
from app.services.gateway_passthrough import _sanitize_client_headers

client = TestClient(app)


def _admin_headers():
    return {
        "X-Actor-Role": "Platform Admin",
        "X-Actor-Id": f"passthrough-admin-{uuid4().hex[:8]}",
    }


def test_gateway_passthrough_simulation_allowlisted_path():
    response = client.post(
        "/v1/passthrough",
        json={
            "provider_id": "openai",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": {"Authorization": "Bearer client-should-be-stripped"},
            "body": {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hello"}]},
            "environment": "dev",
        },
        headers=_admin_headers(),
    )
    assert response.status_code == 200
    body = response.json()
    assert body["status_code"] == 200
    assert body["trace_id"]
    assert body["body"]["simulated"] is True


def test_gateway_passthrough_rejects_disallowed_path():
    response = client.post(
        "/v1/passthrough",
        json={
            "provider_id": "openai",
            "method": "POST",
            "path": "/v1/admin/secrets",
            "environment": "dev",
        },
        headers=_admin_headers(),
    )
    assert response.status_code == 403


def test_gateway_passthrough_denies_auditor():
    response = client.post(
        "/v1/passthrough",
        json={
            "provider_id": "openai",
            "method": "POST",
            "path": "/v1/chat/completions",
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": f"passthrough-auditor-{uuid4().hex[:8]}"},
    )
    assert response.status_code == 403


def test_gateway_passthrough_sanitize_client_headers_strips_authorization():
    sanitized = _sanitize_client_headers(
        {
            "Authorization": "Bearer client-should-be-stripped",
            "X-Custom": "keep-me",
            "x-api-key": "secret-key",
        }
    )
    assert "Authorization" not in sanitized
    assert "authorization" not in {key.lower() for key in sanitized}
    assert sanitized.get("X-Custom") == "keep-me"


@patch("app.services.gateway_passthrough.inference_simulation_enabled", return_value=False)
@patch("app.services.gateway_passthrough.httpx.request")
@patch("app.services.gateway_passthrough._resolve_provider_credential")
def test_gateway_passthrough_does_not_forward_client_authorization(
    mock_resolve_credential,
    mock_request,
    _mock_simulation,
):
    from app.services.gateway_inference import ResolvedInferenceCredential

    mock_resolve_credential.return_value = ResolvedInferenceCredential(
        provider_type="openai",
        api_key="platform-server-key",
        base_url="https://api.openai.com",
        upstream_model="gpt-4o-mini",
        credential_source="env:openai",
    )
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.headers = {"content-type": "application/json"}
    mock_response.json.return_value = {"ok": True}
    mock_request.return_value = mock_response

    response = client.post(
        "/v1/passthrough",
        json={
            "provider_id": "openai",
            "method": "POST",
            "path": "/v1/chat/completions",
            "headers": {"Authorization": "Bearer client-should-be-stripped", "X-Trace": "abc"},
            "body": {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hello"}]},
            "environment": "dev",
        },
        headers=_admin_headers(),
    )
    assert response.status_code == 200
    outbound_headers = mock_request.call_args.kwargs["headers"]
    assert outbound_headers["Authorization"] == "Bearer platform-server-key"
    assert "client-should-be-stripped" not in outbound_headers["Authorization"]
    assert outbound_headers.get("X-Trace") == "abc"

    audit_resp = client.get(
        "/audit/events?action_type=gateway.passthrough.execute&limit=5",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": f"aud-passthrough-{uuid4().hex[:8]}"},
    )
    assert audit_resp.status_code == 200
    audit_rows = audit_resp.json()
    assert audit_rows
    serialized = str(audit_rows)
    assert "client-should-be-stripped" not in serialized


def _dual_approval_headers(actor_id: str, approver_id: str) -> dict:
    return {
        "X-Actor-Role": "Platform Admin",
        "X-Actor-Id": actor_id,
        "X-Approver-Role": "Security Approver",
        "X-Approver-Id": approver_id,
    }


def test_gateway_passthrough_prod_requires_dual_approval():
    actor_id = f"admin-passthrough-prod-{uuid4().hex[:8]}"
    denied = client.post(
        "/v1/passthrough",
        json={
            "provider_id": "openai",
            "method": "POST",
            "path": "/v1/chat/completions",
            "body": {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hello"}]},
            "environment": "prod",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": actor_id},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["error_code"] == "AUTHZ_DUAL_APPROVAL_REQUIRED"

    audit_resp = client.get(
        "/audit/events?action_type=gateway.passthrough.execute&limit=5",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": f"aud-pt-deny-{uuid4().hex[:8]}"},
    )
    assert audit_resp.status_code == 200
    assert any(row.get("decision_outcome") == "deny" for row in audit_resp.json())

    allowed = client.post(
        "/v1/passthrough",
        json={
            "provider_id": "openai",
            "method": "POST",
            "path": "/v1/chat/completions",
            "body": {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hello"}]},
            "environment": "prod",
        },
        headers=_dual_approval_headers(actor_id, f"sec-passthrough-{uuid4().hex[:8]}"),
    )
    assert allowed.status_code == 200
    assert allowed.json()["status_code"] == 200
