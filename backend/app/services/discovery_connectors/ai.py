import hashlib
from typing import Any

from app.services.discovery_connectors.http_utils import bearer_headers, http_get_json
from app.services.discovery_connectors.types import ConnectionRuntime, DiscoveryCandidate

AI_PROVIDER_SPECS: dict[str, dict[str, str]] = {
    "openai": {"default_base": "https://api.openai.com/v1", "models_path": "/models"},
    "anthropic": {"default_base": "https://api.anthropic.com/v1", "models_path": "/models"},
    "cohere": {"default_base": "https://api.cohere.com/v1", "models_path": "/models"},
    "mistral": {"default_base": "https://api.mistral.ai/v1", "models_path": "/models"},
    "groq": {"default_base": "https://api.groq.com/openai/v1", "models_path": "/models"},
    "google": {"default_base": "https://generativelanguage.googleapis.com/v1", "models_path": "/models"},
    "perplexity": {"default_base": "https://api.perplexity.ai", "models_path": "/models"},
    "together": {"default_base": "https://api.together.xyz/v1", "models_path": "/models"},
    "fireworks": {"default_base": "https://api.fireworks.ai/inference/v1", "models_path": "/models"},
    "xai": {"default_base": "https://api.x.ai/v1", "models_path": "/models"},
    "nvidia": {"default_base": "https://integrate.api.nvidia.com/v1", "models_path": "/models"},
    "azure_openai": {"default_base": "", "models_path": "/openai/deployments"},
    "ibm_watson": {"default_base": "", "models_path": "/ml/v1/foundation_model_specs"},
}

# Models from these providers are always in scope for agent discovery sync.
AGENT_AI_MODEL_PREFIXES: tuple[str, ...] = (
    "gpt-",
    "o1",
    "o3",
    "o4",
    "text-embedding",
    "cursor",
    "sonar",
    "llama",
    "claude",
    "gemini",
    "mistral",
    "command",
)


def _fingerprint(*parts: str) -> str:
    payload = "|".join(str(part or "").strip() for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _is_agent_model_id(model_id: str) -> bool:
    lowered = str(model_id or "").strip().lower()
    if not lowered:
        return False
    return any(lowered.startswith(prefix) for prefix in AGENT_AI_MODEL_PREFIXES) or any(
        token in lowered for token in ("agent", "instruct", "chat", "embedding", "reasoning")
    )


def _extract_model_ids(payload: Any) -> list[str]:
    if isinstance(payload, dict):
        data = payload.get("data")
        if isinstance(data, list):
            ids = []
            for item in data:
                if isinstance(item, dict):
                    model_id = str(item.get("id") or item.get("name") or "").strip()
                    if model_id:
                        ids.append(model_id)
            if ids:
                return ids
        models = payload.get("models")
        if isinstance(models, list):
            return [str(item).strip() for item in models if str(item).strip()]
    if isinstance(payload, list):
        ids = []
        for item in payload:
            if isinstance(item, dict):
                model_id = str(item.get("name") or item.get("id") or "").strip()
                if model_id:
                    ids.append(model_id)
            elif isinstance(item, str) and item.strip():
                ids.append(item.strip())
        return ids
    return []


def fetch_ai_provider_inventory(runtime: ConnectionRuntime) -> list[DiscoveryCandidate]:
    token = str(runtime.credentials.secret_value or "").strip()
    if not token:
        raise ValueError("AI provider connection requires an API key via credential binding or secret ref")

    source_id = runtime.source_id
    spec = AI_PROVIDER_SPECS.get(source_id)
    if not spec:
        raise ValueError(f"No live connector spec for AI provider {source_id}")

    base = (runtime.base_url or spec["default_base"] or "").rstrip("/")
    if not base:
        deployment = str(runtime.config.get("azure_openai_deployment") or runtime.config.get("deployment") or "").strip()
        resource = str(runtime.config.get("resource_name") or runtime.config.get("azure_resource") or "").strip()
        api_version = str(runtime.config.get("api_version") or "2024-06-01").strip()
        if not resource:
            raise ValueError("azure_openai connection requires resource_name in connection_config")
        base = f"https://{resource}.openai.azure.com/openai"
        if deployment:
            url = f"{base}/deployments/{deployment}?api-version={api_version}"
            payload = http_get_json(
                url,
                headers={"api-key": token},
            )
            model_id = deployment
            if isinstance(payload, dict):
                model_id = str(payload.get("model") or payload.get("id") or deployment).strip() or deployment
            return [
                DiscoveryCandidate(
                    canonical_agent_key=f"{source_id}:{model_id}",
                    source_fingerprint=_fingerprint(runtime.connection_id, source_id, model_id),
                    confidence=92,
                    metadata={"live": True, "provider": source_id},
                )
            ]

    models_path = spec["models_path"]
    headers = bearer_headers(token)
    if source_id == "anthropic":
        headers["anthropic-version"] = str(runtime.config.get("anthropic_version") or "2023-06-01")

    params = None
    if source_id == "google":
        params = {"key": token}
        headers = {"Accept": "application/json"}
    elif source_id == "ibm_watson":
        project_id = str(runtime.config.get("project_id") or "").strip()
        region = str(runtime.config.get("region") or "us-south").strip()
        if not project_id:
            raise ValueError("ibm_watson connection requires project_id in connection_config")
        base = f"https://{region}.ml.cloud.ibm.com"
        url = f"{base}/ml/v1/foundation_model_specs?project_id={project_id}&version=2023-10-25"
        payload = http_get_json(
            url,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/json"},
        )
        model_ids = _extract_model_ids(payload)
        if not model_ids:
            raise ValueError("ibm_watson API returned no models")
        return [
            DiscoveryCandidate(
                canonical_agent_key=f"{source_id}:{model_id}",
                source_fingerprint=_fingerprint(runtime.connection_id, source_id, model_id),
                confidence=89,
                metadata={"live": True, "provider": source_id, "model_id": model_id},
            )
            for model_id in model_ids
        ]

    url = f"{base}{models_path}"
    payload = http_get_json(
        url,
        headers=headers,
        params=params,
    )
    model_ids = _extract_model_ids(payload)
    if source_id in {"openai", "perplexity"}:
        model_ids = [model_id for model_id in model_ids if _is_agent_model_id(model_id)]
    if not model_ids:
        raise ValueError(f"{source_id} API returned no models")

    return [
        DiscoveryCandidate(
            canonical_agent_key=f"{source_id}:{model_id}",
            source_fingerprint=_fingerprint(runtime.connection_id, source_id, model_id),
            confidence=90,
            metadata={"live": True, "provider": source_id, "model_id": model_id},
        )
        for model_id in model_ids
    ]
