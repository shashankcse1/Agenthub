"""Operator-facing inference readiness across AI / cloud providers."""

from __future__ import annotations

import os
from typing import Any

from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from app.models import ProviderCredentialBinding, SupportedModelCatalogEntry
from app.services.gateway_inference import (
    NATIVE_CHAT_PROVIDERS,
    OPENAI_COMPATIBLE_PROVIDERS,
    inference_simulation_enabled,
    normalize_inference_provider_type,
    provider_env_credential_configured,
)


_READINESS_PROVIDERS: tuple[tuple[str, str, str], ...] = (
    ("openai", "OpenAI", "Set OPENAI_API_KEY or bind platform/default openai."),
    ("anthropic", "Anthropic", "Set ANTHROPIC_API_KEY or bind anthropic credentials."),
    ("cursor", "Cursor", "Configure gateway Cursor secret binding (gateway/cursor-token)."),
    ("azure-openai", "Azure OpenAI", "Set AZURE_OPENAI_API_KEY + AZURE_OPENAI_API_BASE/ENDPOINT."),
    ("aws", "AWS Bedrock", "Use AWS default chain / AWS_BEDROCK_USE_DEFAULT_CHAIN or store bedrock JSON credentials."),
    ("google", "Google Gemini API", "Set GOOGLE_API_KEY (Gemini OpenAI-compatible API)."),
    ("vertex", "Google Vertex AI", "Set VERTEX_PROJECT + VERTEX_LOCATION + VERTEX_ACCESS_TOKEN/GOOGLE_API_KEY."),
    ("groq", "Groq", "Set GROQ_API_KEY."),
    ("mistral", "Mistral", "Set MISTRAL_API_KEY."),
    ("cohere", "Cohere", "Set COHERE_API_KEY."),
    ("deepseek", "DeepSeek", "Set DEEPSEEK_API_KEY."),
    ("xai", "xAI", "Set XAI_API_KEY."),
    ("together", "Together AI", "Set TOGETHER_API_KEY."),
    ("fireworks", "Fireworks AI", "Set FIREWORKS_API_KEY."),
    ("perplexity", "Perplexity", "Set PERPLEXITY_API_KEY."),
)


def _provider_invoke_supported(provider_type: str) -> bool:
    normalized = normalize_inference_provider_type(provider_type)
    return normalized in OPENAI_COMPATIBLE_PROVIDERS or normalized in NATIVE_CHAT_PROVIDERS or normalized == "anthropic"


def _azure_endpoint_configured() -> bool:
    return bool(
        str(
            os.getenv("AZURE_OPENAI_API_BASE")
            or os.getenv("AZURE_OPENAI_ENDPOINT")
            or os.getenv("AZURE_OPENAI_BASE_URL")
            or ""
        ).strip()
    )


def _vertex_endpoint_configured() -> bool:
    project = str(os.getenv("VERTEX_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT") or "").strip()
    return bool(project)


def _binding_ready_provider_types(db: Session) -> set[str]:
    """Active credential bindings with secret ref or workload identity count as configured."""
    rows = (
        db.query(ProviderCredentialBinding.provider_type)
        .filter(ProviderCredentialBinding.status == "active")
        .filter(
            or_(
                and_(
                    ProviderCredentialBinding.secret_provider_id.isnot(None),
                    ProviderCredentialBinding.secret_ref.isnot(None),
                    ProviderCredentialBinding.secret_provider_id != "",
                    ProviderCredentialBinding.secret_ref != "",
                ),
                and_(
                    ProviderCredentialBinding.workload_identity_profile_id.isnot(None),
                    ProviderCredentialBinding.workload_identity_profile_id != "",
                ),
            )
        )
        .distinct()
        .all()
    )
    ready: set[str] = set()
    for (provider_type,) in rows:
        normalized = normalize_inference_provider_type(str(provider_type or ""))
        if normalized:
            ready.add(normalized)
            # Legacy UI aliases stored on bindings.
            if normalized == "azure-openai":
                ready.add("azure")
            if normalized == "aws":
                ready.add("bedrock")
            if normalized == "google":
                ready.add("gcp")
    return ready


def build_inference_readiness(db: Session) -> dict[str, Any]:
    counts_rows = (
        db.query(
            SupportedModelCatalogEntry.provider_type,
            func.count(SupportedModelCatalogEntry.supported_model_id),
        )
        .filter(SupportedModelCatalogEntry.status.in_(("active", "beta")))
        .group_by(SupportedModelCatalogEntry.provider_type)
        .all()
    )
    catalog_counts: dict[str, int] = {}
    for provider_type, count in counts_rows:
        normalized = normalize_inference_provider_type(str(provider_type or ""))
        if not normalized:
            continue
        catalog_counts[normalized] = catalog_counts.get(normalized, 0) + int(count or 0)

    simulation = inference_simulation_enabled()
    binding_ready = _binding_ready_provider_types(db)
    providers: list[dict[str, Any]] = []
    ready_count = 0

    for provider_id, label, hint in _READINESS_PROVIDERS:
        env_key_present = provider_env_credential_configured(provider_id)
        binding_present = provider_id in binding_ready or (
            provider_id == "azure-openai" and "azure" in binding_ready
        ) or (provider_id == "aws" and "bedrock" in binding_ready) or (
            provider_id == "google" and "gcp" in binding_ready
        )
        credential_configured = bool(env_key_present or binding_present)
        endpoint_ok = True
        if provider_id == "azure-openai":
            endpoint_ok = _azure_endpoint_configured()
        elif provider_id == "vertex":
            endpoint_ok = _vertex_endpoint_configured()

        invoke_supported = _provider_invoke_supported(provider_id)
        live_ready = bool(invoke_supported and credential_configured and endpoint_ok)
        if provider_id == "cursor":
            # Cursor local default base is not live unless CURSOR_API_BASE is set; binding is checked in UI separately.
            configured_base = str(os.getenv("CURSOR_API_BASE") or os.getenv("CURSOR_BASE_URL") or "").strip()
            live_ready = credential_configured and bool(configured_base)

        status = "live_ready" if live_ready else ("simulation" if simulation else "needs_credentials")
        if live_ready:
            ready_count += 1

        providers.append(
            {
                "provider_type": provider_id,
                "label": label,
                "catalog_models": int(catalog_counts.get(provider_id, 0)),
                "invoke_supported": invoke_supported,
                "env_credential_configured": env_key_present,
                "binding_credential_configured": binding_present,
                "endpoint_configured": endpoint_ok,
                "live_ready": live_ready,
                "status": status,
                "setup_hint": hint,
            }
        )

    # Include any extra catalog providers not in the fixed list.
    known = {item[0] for item in _READINESS_PROVIDERS}
    for provider_type, count in sorted(catalog_counts.items()):
        if provider_type in known:
            continue
        env_key_present = provider_env_credential_configured(provider_type)
        binding_present = provider_type in binding_ready
        credential_configured = bool(env_key_present or binding_present)
        live_ready = bool(_provider_invoke_supported(provider_type) and credential_configured)
        providers.append(
            {
                "provider_type": provider_type,
                "label": provider_type,
                "catalog_models": int(count),
                "invoke_supported": _provider_invoke_supported(provider_type),
                "env_credential_configured": env_key_present,
                "binding_credential_configured": binding_present,
                "endpoint_configured": True,
                "live_ready": live_ready,
                "status": "catalog_only",
                "setup_hint": "Provider appears in catalog; configure credentials if invoke is required.",
            }
        )
        if live_ready:
            ready_count += 1

    return {
        "simulation_enabled": simulation,
        "ready_providers": ready_count,
        "total_providers": len(providers),
        "catalog_models_total": sum(catalog_counts.values()),
        "binding_ready_provider_types": sorted(binding_ready),
        "providers": providers,
    }
