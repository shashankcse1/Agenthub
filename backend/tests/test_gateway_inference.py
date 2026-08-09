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


def test_infer_provider_type_from_model_defaults():
    assert infer_provider_type_from_model("gpt-4o-mini") == ("openai", "gpt-4o-mini")
    assert infer_provider_type_from_model("claude-3-5-sonnet") == ("anthropic", "claude-3-5-sonnet")
    assert infer_provider_type_from_model("openai/gpt-4o") == ("openai", "gpt-4o")
    assert infer_provider_type_from_model("gemini-2.5-pro") == ("google", "gemini-2.5-pro")
    assert infer_provider_type_from_model("grok-4") == ("xai", "grok-4")
    assert infer_provider_type_from_model("deepseek-chat") == ("deepseek", "deepseek-chat")
    assert infer_provider_type_from_model("sonar-pro") == ("perplexity", "sonar-pro")
    assert infer_provider_type_from_model("azure/gpt-4o") == ("azure-openai", "gpt-4o")
    assert infer_provider_type_from_model("google/gemini-3.1-pro") == ("google", "gemini-3.1-pro")
    assert infer_provider_type_from_model("anthropic.claude-3-5-sonnet-20241022-v2:0") == (
        "aws",
        "anthropic.claude-3-5-sonnet-20241022-v2:0",
    )
    assert infer_provider_type_from_model("amazon.nova-pro-v1:0") == ("aws", "amazon.nova-pro-v1:0")
    assert infer_provider_type_from_model("us.anthropic.claude-sonnet-4-20250514-v1:0") == (
        "aws",
        "us.anthropic.claude-sonnet-4-20250514-v1:0",
    )
    assert infer_provider_type_from_model("publishers/google/models/gemini-2.5-pro") == (
        "vertex",
        "publishers/google/models/gemini-2.5-pro",
    )
    assert infer_provider_type_from_model("bedrock/amazon.nova-lite-v1:0") == ("aws", "amazon.nova-lite-v1:0")
    assert infer_provider_type_from_model("vertex/gemini-2.5-flash") == ("vertex", "gemini-2.5-flash")


def test_invoke_chat_completion_parses_openai_response():
    mock_response = Mock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [
            {
                "message": {"role": "assistant", "content": "Moscow"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
    }

    credential = ResolvedInferenceCredential(
        provider_type="openai",
        api_key="sk-test",
        base_url="https://api.openai.com/v1",
        upstream_model="gpt-4o-mini",
        credential_source="env:openai",
    )

    with patch("app.services.gateway_inference.httpx.post", return_value=mock_response) as mock_post:
        result = invoke_chat_completion(
            credential,
            messages=[{"role": "user", "content": "what is capital of russia"}],
        )

    assert result.content == "Moscow"
    assert result.usage.total_tokens == 12
    mock_post.assert_called_once()
    posted_url = mock_post.call_args.args[0]
    assert posted_url.endswith("/chat/completions")


def test_invoke_chat_completion_google_openai_compat_base():
    mock_response = Mock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [{"message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }
    credential = ResolvedInferenceCredential(
        provider_type="google",
        api_key="AIza-test",
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        upstream_model="gemini-2.5-flash",
        credential_source="env:google",
    )
    with patch("app.services.gateway_inference.httpx.post", return_value=mock_response) as mock_post:
        result = invoke_chat_completion(
            credential,
            messages=[{"role": "user", "content": "hi"}],
        )
    assert result.content == "ok"
    assert mock_post.call_args.args[0].endswith("/chat/completions")
    assert "generativelanguage.googleapis.com" in mock_post.call_args.args[0]


def test_invoke_chat_completion_azure_classic_deployment_url():
    mock_response = Mock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [{"message": {"role": "assistant", "content": "azure-ok"}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
    }
    credential = ResolvedInferenceCredential(
        provider_type="azure-openai",
        api_key="azure-key",
        base_url="https://myresource.openai.azure.com",
        upstream_model="gpt-4o",
        credential_source="env:azure",
    )
    with patch.dict(os.environ, {"AZURE_OPENAI_API_VERSION": "2024-10-21"}, clear=False):
        with patch("app.services.gateway_inference.httpx.post", return_value=mock_response) as mock_post:
            result = invoke_chat_completion(
                credential,
                messages=[{"role": "user", "content": "hi"}],
            )
    assert result.content == "azure-ok"
    posted_url = mock_post.call_args.args[0]
    assert "/openai/deployments/gpt-4o/chat/completions" in posted_url
    assert "api-version=2024-10-21" in posted_url
    body = mock_post.call_args.kwargs["json"]
    assert "model" not in body


def test_invoke_bedrock_chat_completion_converse():
    mock_client = Mock()
    mock_client.converse.return_value = {
        "output": {"message": {"role": "assistant", "content": [{"text": "bedrock-ok"}]}},
        "usage": {"inputTokens": 4, "outputTokens": 2},
        "stopReason": "end_turn",
    }
    credential = ResolvedInferenceCredential(
        provider_type="aws",
        api_key="aws-default",
        base_url="bedrock-runtime",
        upstream_model="amazon.nova-lite-v1:0",
        credential_source="env:aws",
    )
    with patch("app.services.gateway_inference._bedrock_client", return_value=mock_client):
        result = invoke_chat_completion(
            credential,
            messages=[
                {"role": "system", "content": "Be brief"},
                {"role": "user", "content": "hello"},
            ],
            max_tokens=64,
        )
    assert result.content == "bedrock-ok"
    assert result.usage.prompt_tokens == 4
    request = mock_client.converse.call_args.kwargs
    assert request["modelId"] == "amazon.nova-lite-v1:0"
    assert request["system"] == [{"text": "Be brief"}]
    assert request["messages"][0]["role"] == "user"


def test_execute_chat_completion_simulation_when_no_credential():
    with patch.dict(os.environ, {"GATEWAY_INFERENCE_SIMULATION": "true"}, clear=False):
        result = execute_chat_completion(
            None,  # type: ignore[arg-type]
            credential=None,
            model_name="gpt-4o-mini",
            messages=[{"role": "user", "content": "hello"}],
            prompt_preview="hello",
        )
    assert "Simulated completion" in result.content


def test_gateway_chat_completions_uses_upstream_when_openai_key_configured():
    mock_response = Mock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "choices": [
            {
                "message": {"role": "assistant", "content": "Moscow"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 8, "completion_tokens": 1, "total_tokens": 9},
    }

    with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test", "GATEWAY_INFERENCE_SIMULATION": "false"}, clear=False):
        with patch("app.services.gateway_inference.httpx.post", return_value=mock_response):
            response = client.post(
                "/v1/chat/completions",
                json={
                    "model": "gpt-4o-mini",
                    "messages": [{"role": "user", "content": "what is capital of russia"}],
                    "stream": False,
                    "environment": "dev",
                },
                headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": f"admin-upstream-{uuid4().hex[:8]}"},
            )

    assert response.status_code == 200
    payload = response.json()
    assert payload["choices"][0]["message"]["content"] == "Moscow"
    assert "Simulated completion" not in payload["choices"][0]["message"]["content"]


def test_resolve_inference_credential_finds_platform_default_openai_binding():
    from app.database import SessionLocal
    from app.models import ProviderCredentialBinding
    from uuid import uuid4

    suffix = uuid4().hex[:8]
    binding_id = f"bind-platform-openai-{suffix}"
    db = SessionLocal()
    try:
        db.add(
            ProviderCredentialBinding(
                binding_id=binding_id,
                tenant_id=f"tenant-{suffix}",
                binding_name="Platform OpenAI",
                consumer_type="platform",
                consumer_key="default",
                provider_type="openai",
                credential_plane="secret_ref",
                secret_provider_id="sp-missing",
                secret_ref="providers/openai/api-key",
                environment="dev",
                status="active",
            )
        )
        db.commit()

        with patch(
            "app.services.gateway_inference.resolve_binding_for_runtime",
            return_value=ResolvedAgentCredential(
                binding_id=binding_id,
                provider_type="openai",
                credential_plane="secret_ref",
                configured=True,
                masked_hint="sk-***",
                secret_value="sk-platform-test",
            ),
        ):
            credential = resolve_inference_credential(
                db,
                agent_id=None,
                environment="dev",
                model_name="gpt-4o-mini",
                resolve_gateway_cursor_token=lambda _db: "cursor-token-not-openai",
            )
        assert credential is not None
        assert credential.api_key == "sk-platform-test"
        assert credential.credential_source == f"binding:{binding_id}"
    finally:
        db.query(ProviderCredentialBinding).filter_by(binding_id=binding_id).delete()
        db.commit()
        db.close()


def test_resolve_inference_credential_prefers_env_openai_key():
    with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-env-test"}, clear=False):
        credential = resolve_inference_credential(
            None,  # type: ignore[arg-type]
            agent_id=None,
            environment="dev",
            model_name="gpt-4o-mini",
            resolve_gateway_cursor_token=lambda _db: "",
        )
    assert credential is not None
    assert credential.api_key == "sk-env-test"
    assert credential.provider_type == "openai"


def test_simulate_chat_completion_shape():
    text = simulate_chat_completion("gpt-4o-mini", "capital?")
    assert "gpt-4o-mini" in text
    assert "capital?" in text


def test_simulate_chat_completion_returns_moscow_for_russia_capital():
    text = simulate_chat_completion("gpt-4o-mini", "what is capital of russia")
    assert "Russia" in text
    assert "Moscow" in text


def test_simulate_chat_completion_p1_incident_template():
    text = simulate_chat_completion(
        "gpt-4o",
        "draft a p1 response format for incident",
    )
    assert "P1 Incident" in text
    assert "Pre-send checklist" in text
    assert "Simulated completion" not in text


def test_gateway_chat_completions_p1_incident_template():
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "draft a p1 response format for incident"}],
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": f"admin-p1-{uuid4().hex[:8]}"},
    )
    assert response.status_code == 200
    content = response.json()["choices"][0]["message"]["content"]
    assert "P1 Incident" in content
    assert "Simulated completion" not in content
    response = client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "what is capital of russia"}],
            "stream": False,
            "environment": "dev",
        },
        headers={"X-Actor-Role": "Platform Admin", "X-Actor-Id": f"admin-moscow-{uuid4().hex[:8]}"},
    )
    assert response.status_code == 200
    payload = response.json()
    content = payload["choices"][0]["message"]["content"]
    assert "Russia" in content
    assert "Moscow" in content
    assert "Simulated completion" not in content
