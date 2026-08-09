from unittest.mock import Mock, patch

from app.services.cloud_model_catalog import CloudModelSpec
from app.services.cloud_model_discovery import (
    discover_azure_openai_models,
    discover_bedrock_models,
    discover_cloud_models,
    discover_google_gemini_models,
)
from app.services.gateway_inference import (
    ResolvedInferenceCredential,
    invoke_embeddings,
)


def test_discover_bedrock_models_maps_foundation_and_profiles():
    import sys

    bedrock = Mock()
    bedrock.list_foundation_models.return_value = {
        "modelSummaries": [
            {
                "modelId": "amazon.nova-lite-v1:0",
                "modelName": "Nova Lite",
                "providerName": "Amazon",
                "inputModalities": ["TEXT"],
                "outputModalities": ["TEXT"],
            },
            {
                "modelId": "amazon.titan-embed-text-v2:0",
                "modelName": "Titan Embed",
                "providerName": "Amazon",
                "inputModalities": ["TEXT"],
                "outputModalities": ["EMBEDDING"],
            },
        ]
    }
    bedrock.list_inference_profiles.return_value = {
        "inferenceProfileSummaries": [
            {"inferenceProfileId": "us.anthropic.claude-sonnet-4-20250514-v1:0", "inferenceProfileName": "Claude Sonnet 4"},
            {"inferenceProfileId": "arn:aws:bedrock:us-east-1:123:inference-profile/skip", "inferenceProfileName": "skip-arn"},
        ]
    }
    fake_boto3 = Mock()
    fake_boto3.client.return_value = bedrock
    with patch.dict(sys.modules, {"boto3": fake_boto3}):
        specs, meta = discover_bedrock_models(region="us-east-1")
    ids = {spec.model_name for spec in specs}
    assert "amazon.nova-lite-v1:0" in ids
    assert "amazon.titan-embed-text-v2:0" in ids
    assert "us.anthropic.claude-sonnet-4-20250514-v1:0" in ids
    assert meta["source"] == "live"
    assert meta["total"] == 3


def test_discover_azure_and_google_models(monkeypatch):
    azure_response = Mock()
    azure_response.status_code = 200
    azure_response.json.return_value = {
        "data": [
            {"id": "gpt-4o-prod", "model": "gpt-4o"},
            {"id": "embed-large", "model": "text-embedding-3-large"},
        ]
    }
    google_response = Mock()
    google_response.status_code = 200
    google_response.json.return_value = {
        "models": [
            {
                "name": "models/gemini-2.5-flash",
                "displayName": "Gemini 2.5 Flash",
                "supportedGenerationMethods": ["generateContent"],
                "inputTokenLimit": 1000000,
            }
        ]
    }

    def fake_get(url, **kwargs):
        if "openai.azure.com" in str(url) or "/openai/deployments" in str(url):
            return azure_response
        return google_response

    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://demo.openai.azure.com")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "azure-key")
    monkeypatch.setenv("GOOGLE_API_KEY", "google-key")
    with patch("app.services.cloud_model_discovery.httpx.get", side_effect=fake_get):
        azure_specs, azure_meta = discover_azure_openai_models()
        google_specs, google_meta = discover_google_gemini_models()
    assert azure_meta["total"] == 2
    assert {spec.model_name for spec in azure_specs} == {"gpt-4o-prod", "embed-large"}
    assert google_meta["total"] == 1
    assert google_specs[0].model_name == "gemini-2.5-flash"


def test_discover_cloud_models_collects_partial_errors():
    with patch(
        "app.services.cloud_model_discovery.discover_bedrock_models",
        return_value=([CloudModelSpec("aws", "amazon.nova-lite-v1:0", "Nova Lite")], {"provider": "aws", "total": 1, "source": "live"}),
    ), patch(
        "app.services.cloud_model_discovery.discover_azure_openai_models",
        side_effect=RuntimeError("missing azure creds"),
    ), patch(
        "app.services.cloud_model_discovery.discover_google_gemini_models",
        side_effect=RuntimeError("missing google key"),
    ), patch(
        "app.services.cloud_model_discovery.discover_vertex_models",
        side_effect=RuntimeError("missing vertex"),
    ):
        payload = discover_cloud_models(["bedrock", "azure", "google", "vertex"])
    assert payload["total"] == 1
    assert len(payload["errors"]) == 3
    assert payload["models"][0]["model_name"] == "amazon.nova-lite-v1:0"


def test_invoke_bedrock_embeddings_titan():
    body = Mock()
    body.read.return_value = b'{"embedding":[0.1,0.2,0.3],"inputTextTokenCount":3}'
    mock_client = Mock()
    mock_client.invoke_model.return_value = {"body": body}
    credential = ResolvedInferenceCredential(
        provider_type="aws",
        api_key="aws-default",
        base_url="bedrock-runtime",
        upstream_model="amazon.titan-embed-text-v2:0",
        credential_source="env:aws",
    )
    with patch("app.services.gateway_inference._bedrock_client", return_value=mock_client):
        result = invoke_embeddings(credential, inputs=["hello world"])
    assert result.embeddings == [[0.1, 0.2, 0.3]]
    assert result.usage.prompt_tokens == 3
    assert mock_client.invoke_model.call_args.kwargs["modelId"] == "amazon.titan-embed-text-v2:0"
