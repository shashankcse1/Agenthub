import os
from unittest.mock import Mock, patch
from uuid import uuid4

import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.services.gateway_inference import (
    ResolvedInferenceCredential,
    execute_chat_completion,
    infer_provider_type_from_model,
    invoke_chat_completion,
    resolve_inference_credential,
    simulate_chat_completion,
)
from app.services.credential_resolution import ResolvedAgentCredential


client = TestClient(app)


def test_get_vector_stores_with_auth():
    mock_response = Mock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "vector_stores": [
            {"id": "1", "name": "Store 1"},
            {"id": "2", "name": "Store 2"}
        ]
    }

    with patch("app.services.gateway_inference.httpx.get", return_value=mock_response) as mock_get:
        response = client.get(
            "/v1/vector_stores",
            headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": f"admin-upstream-{uuid4().hex[:8]}"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert len(payload["vector_stores"]) == 2


def test_get_vector_stores_without_auth():
    mock_response = Mock(spec=httpx.Response)
    mock_response.status_code = 401

    with patch("app.services.gateway_inference.httpx.get", return_value=mock_response):
        response = client.get("/v1/vector_stores")

    assert response.status_code == 401
