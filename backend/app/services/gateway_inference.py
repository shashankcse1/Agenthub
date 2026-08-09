from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any, Callable, Generator, Iterable, Optional

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import AgentConfig, ProviderCredentialBinding, SupportedModelCatalogEntry
from app.services.credential_resolution import (
    ResolvedAgentCredential,
    resolve_agent_config_credential,
    resolve_binding_for_runtime,
)

OPENAI_COMPATIBLE_PROVIDERS = {
    "openai",
    "groq",
    "mistral",
    "cohere",
    "azure-openai",
    "azure_openai",
    "azure",
    "cursor",
    "google",
    "vertex",
    "xai",
    "deepseek",
    "together",
    "fireworks",
    "perplexity",
}

# Native (non-OpenAI-compatible) chat providers handled by dedicated invoke paths.
NATIVE_CHAT_PROVIDERS = {
    "anthropic",
    "aws",
    "bedrock",
    "aws-bedrock",
}

_PROVIDER_TYPE_ALIASES: dict[str, str] = {
    "azure": "azure-openai",
    "azure_openai": "azure-openai",
    "gcp": "google",
    "gemini": "google",
    "google-ai": "google",
    "google-cloud": "google",
    "x-ai": "xai",
    "grok": "xai",
    "bedrock": "aws",
    "aws-bedrock": "aws",
    "amazon-bedrock": "aws",
    "vertex-ai": "vertex",
    "vertex_ai": "vertex",
}

_PROVIDER_ENV_PREFIXES: dict[str, str] = {
    "openai": "OPENAI",
    "anthropic": "ANTHROPIC",
    "cohere": "COHERE",
    "mistral": "MISTRAL",
    "groq": "GROQ",
    "azure-openai": "AZURE_OPENAI",
    "azure_openai": "AZURE_OPENAI",
    "azure": "AZURE_OPENAI",
    "cursor": "CURSOR",
    "google": "GOOGLE",
    "vertex": "VERTEX",
    "xai": "XAI",
    "deepseek": "DEEPSEEK",
    "together": "TOGETHER",
    "fireworks": "FIREWORKS",
    "perplexity": "PERPLEXITY",
    "aws": "AWS_BEDROCK",
    "bedrock": "AWS_BEDROCK",
}

_PROVIDER_DEFAULT_BASE_URLS: dict[str, str] = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com/v1",
    "groq": "https://api.groq.com/openai/v1",
    "mistral": "https://api.mistral.ai/v1",
    "cohere": "https://api.cohere.com/v2",
    "cursor": "http://127.0.0.1:8765/v1",
    "google": "https://generativelanguage.googleapis.com/v1beta/openai",
    "vertex": "",  # Built dynamically from VERTEX_PROJECT / VERTEX_LOCATION
    "xai": "https://api.x.ai/v1",
    "deepseek": "https://api.deepseek.com/v1",
    "together": "https://api.together.xyz/v1",
    "fireworks": "https://api.fireworks.ai/inference/v1",
    "perplexity": "https://api.perplexity.ai",
    "azure-openai": "",  # Requires AZURE_OPENAI_API_BASE
    "aws": "bedrock-runtime",
}

_OPENAI_MODEL_PREFIXES = ("gpt-", "o1", "o2", "o3", "o4", "chatgpt", "text-embedding", "whisper", "tts-", "dall-e")
_ANTHROPIC_MODEL_PREFIXES = ("claude",)
_CURSOR_MODEL_PREFIXES = ("composer", "cursor-")
_GOOGLE_MODEL_PREFIXES = ("gemini-", "gemini", "text-embedding-004", "gemini-embedding", "imagen-")
_XAI_MODEL_PREFIXES = ("grok-", "grok")
_DEEPSEEK_MODEL_PREFIXES = ("deepseek-", "deepseek")
_COHERE_MODEL_PREFIXES = ("command-", "command")
_MISTRAL_MODEL_PREFIXES = ("mistral-", "codestral", "mixtral", "pixtral", "ministral")
_PERPLEXITY_MODEL_PREFIXES = ("sonar",)
_BEDROCK_FOUNDATION_PREFIXES = (
    "amazon.",
    "anthropic.",
    "meta.",
    "mistral.",
    "cohere.",
    "ai21.",
    "deepseek.",
    "stability.",
    "qwen.",
    "writer.",
    "nvidia.",
    "openai.gpt-oss",
)
_BEDROCK_PROFILE_PREFIXES = ("us.", "eu.", "ap.", "global.", "us-gov.")
_VERTEX_PUBLISHER_PREFIX = "publishers/"


def normalize_inference_provider_type(provider_type: str) -> str:
    normalized = str(provider_type or "").strip().lower()
    return _PROVIDER_TYPE_ALIASES.get(normalized, normalized)


def _looks_like_bedrock_model_id(model_id: str) -> bool:
    lower = str(model_id or "").strip().lower()
    if not lower:
        return False
    if any(lower.startswith(prefix) for prefix in _BEDROCK_PROFILE_PREFIXES):
        return True
    if any(lower.startswith(prefix) for prefix in _BEDROCK_FOUNDATION_PREFIXES):
        return True
    return False


def _looks_like_vertex_model_id(model_id: str) -> bool:
    lower = str(model_id or "").strip().lower()
    return lower.startswith(_VERTEX_PUBLISHER_PREFIX) or lower.startswith("projects/")

# Lightweight factual answers for simulation/dev when no upstream credential is configured.
_CAPITAL_ANSWERS: dict[str, str] = {
    "russia": "The capital of Russia is Moscow.",
    "france": "The capital of France is Paris.",
    "germany": "The capital of Germany is Berlin.",
    "japan": "The capital of Japan is Tokyo.",
    "india": "The capital of India is New Delhi.",
    "united states": "The capital of the United States is Washington, D.C.",
    "usa": "The capital of the United States is Washington, D.C.",
    "united kingdom": "The capital of the United Kingdom is London.",
    "uk": "The capital of the United Kingdom is London.",
    "canada": "The capital of Canada is Ottawa.",
    "australia": "The capital of Australia is Canberra.",
    "china": "The capital of China is Beijing.",
    "brazil": "The capital of Brazil is Brasília.",
    "italy": "The capital of Italy is Rome.",
    "spain": "The capital of Spain is Madrid.",
}

_P1_INCIDENT_RESPONSE_TEMPLATE = """# P1 Incident — Stakeholder Response Format

**Subject:** [P1] {service} — {impact_summary}

| Field | Value |
| --- | --- |
| Severity | P1 (Critical) |
| Status | Investigating |
| Incident Commander | {incident_commander} |
| Started (UTC) | {started_at_utc} |
| Next update (UTC) | {next_update_utc} |
| Affected scope | {affected_scope} |

## External / customer message (≤120 words)
We are investigating a critical issue affecting {affected_scope}. Customer impact: {customer_impact}. Engineering is actively engaged. Next update by {next_update_utc} UTC or sooner if status changes.

## Internal war-room update
- **Symptoms:** {symptoms}
- **Blast radius:** {blast_radius}
- **Current hypothesis:** {hypothesis}
- **Mitigation in progress:** {mitigation}
- **Escalation path:** On-call → Incident Commander → {executive_contact}

## Pre-send checklist
- [ ] Severity validated as P1 (major customer/revenue/security impact)
- [ ] On-call and IC notified in incident channel
- [ ] Status page / support macros updated (if external impact)
- [ ] Legal/comms looped when data exposure suspected
- [ ] Next checkpoint scheduled within 30 minutes

## Follow-up actions
1. Capture timeline entries in the incident ticket.
2. Attach logs/metrics snapshot links.
3. Schedule post-incident review within 5 business days.
"""

_SUPPORT_ESCALATION_TEMPLATE = """# Customer Escalation Response (Draft)

**Tone:** Empathetic, accountable, action-oriented.

## Opening
Thank you for raising this — I understand the urgency and the impact on your team.

## Acknowledgment
We have classified this as a priority escalation and assigned an owner.

## Actions taken
- Reproduced / validated the reported behavior
- Engaged the appropriate on-call engineer
- Started active investigation

## Next steps
- Provide a substantive update within {sla_minutes} minutes
- Share workaround if one exists
- Confirm expected resolution window once root cause is known

## Closing
We will keep you updated at each checkpoint until this is resolved.
"""


def lookup_structured_simulation(prompt: str) -> str | None:
    normalized = _normalize_prompt_for_facts(prompt)
    if not normalized:
        return None

    incident_terms = ("incident", "p1", "p2", "sev1", "sev 1", "outage", "war room", "warroom")
    format_terms = ("response", "format", "template", "draft", "communication", "comms", "message")
    has_incident = any(term in normalized for term in incident_terms)
    has_format = any(term in normalized for term in format_terms)

    if has_incident and has_format:
        return _P1_INCIDENT_RESPONSE_TEMPLATE.format(
            service="{service}",
            impact_summary="{one-line customer impact}",
            incident_commander="{name}",
            started_at_utc="{YYYY-MM-DD HH:MM UTC}",
            next_update_utc="{YYYY-MM-DD HH:MM UTC}",
            affected_scope="{product / region / tenant cohort}",
            customer_impact="{who is affected and how}",
            symptoms="{observable errors/latency/data loss}",
            blast_radius="{systems and tenants}",
            hypothesis="{leading theory}",
            mitigation="{rollback, failover, feature flag, hotfix}",
            executive_contact="{director / VP on-call}",
        )

    if "escalation" in normalized and any(term in normalized for term in ("support", "customer", "response", "draft")):
        return _SUPPORT_ESCALATION_TEMPLATE.format(sla_minutes="30")

    return None


@dataclass(frozen=True)
class ResolvedInferenceCredential:
    provider_type: str
    api_key: str
    base_url: str
    upstream_model: str
    credential_source: str


@dataclass(frozen=True)
class InferenceUsage:
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


@dataclass(frozen=True)
class ChatCompletionInferenceResult:
    content: str
    finish_reason: str
    usage: InferenceUsage
    tool_calls: list[dict[str, Any]] | None = None


@dataclass(frozen=True)
class EmbeddingsInferenceResult:
    embeddings: list[list[float]]
    usage: InferenceUsage


@dataclass(frozen=True)
class ResponsesInferenceResult:
    output_text: str
    output_items: list[dict[str, Any]]
    finish_reason: str
    usage: InferenceUsage
    has_tool_calls: bool = False


def split_provider_model(model: str) -> tuple[str | None, str]:
    raw = str(model or "").strip()
    if "/" not in raw:
        return None, raw
    provider, name = raw.split("/", 1)
    normalized_provider = provider.strip().lower() or None
    normalized_name = name.strip() or raw
    return normalized_provider, normalized_name


def _any_upstream_env_credential_configured() -> bool:
    for provider_type in _PROVIDER_ENV_PREFIXES:
        if _provider_env_api_key(provider_type):
            return True
    return False


def inference_simulation_enabled() -> bool:
    explicit = os.getenv("GATEWAY_INFERENCE_SIMULATION")
    if explicit is not None and str(explicit).strip():
        return str(explicit).strip().lower() in {"1", "true", "yes", "on"}
    if _any_upstream_env_credential_configured():
        return False
    return True


def _normalize_prompt_for_facts(text: str) -> str:
    normalized = re.sub(r"[^a-z0-9\s]", " ", str(text or "").lower())
    return " ".join(normalized.split())


def lookup_factual_answer(prompt: str) -> str | None:
    normalized = _normalize_prompt_for_facts(prompt)
    if not normalized or "capital" not in normalized:
        return None
    for country, capital in _CAPITAL_ANSWERS.items():
        if country in normalized:
            return capital
    return None


def inference_timeout_seconds() -> float:
    try:
        return max(5.0, float(os.getenv("GATEWAY_INFERENCE_TIMEOUT_SECONDS", "120")))
    except (TypeError, ValueError):
        return 120.0


def infer_provider_type_from_model(model_name: str) -> tuple[str, str]:
    raw = str(model_name or "").strip()
    # Vertex publisher / project resource paths contain slashes — do not split as provider/model.
    if _looks_like_vertex_model_id(raw):
        return "vertex", raw
    if _looks_like_bedrock_model_id(raw):
        return "aws", raw

    provider_prefix, normalized_model = split_provider_model(raw)
    if provider_prefix:
        return normalize_inference_provider_type(provider_prefix), normalized_model

    lower = normalized_model.lower()
    if any(lower.startswith(prefix) for prefix in _ANTHROPIC_MODEL_PREFIXES):
        return "anthropic", normalized_model
    if any(lower.startswith(prefix) for prefix in _CURSOR_MODEL_PREFIXES):
        return "cursor", normalized_model
    if any(lower.startswith(prefix) for prefix in _GOOGLE_MODEL_PREFIXES):
        return "google", normalized_model
    if any(lower.startswith(prefix) for prefix in _XAI_MODEL_PREFIXES):
        return "xai", normalized_model
    if any(lower.startswith(prefix) for prefix in _DEEPSEEK_MODEL_PREFIXES):
        return "deepseek", normalized_model
    if any(lower.startswith(prefix) for prefix in _COHERE_MODEL_PREFIXES):
        return "cohere", normalized_model
    if any(lower.startswith(prefix) for prefix in _MISTRAL_MODEL_PREFIXES):
        return "mistral", normalized_model
    if any(lower.startswith(prefix) for prefix in _PERPLEXITY_MODEL_PREFIXES):
        return "perplexity", normalized_model
    if any(lower.startswith(prefix) for prefix in _OPENAI_MODEL_PREFIXES):
        return "openai", normalized_model

    default_provider = normalize_inference_provider_type(
        str(os.getenv("GATEWAY_DEFAULT_INFERENCE_PROVIDER", "openai") or "openai")
    )
    return default_provider or "openai", normalized_model


def _vertex_default_base_url() -> str:
    project = str(os.getenv("VERTEX_PROJECT") or os.getenv("GOOGLE_CLOUD_PROJECT") or "").strip()
    location = str(os.getenv("VERTEX_LOCATION") or os.getenv("GOOGLE_CLOUD_LOCATION") or "us-central1").strip() or "us-central1"
    if not project:
        return ""
    return (
        f"https://{location}-aiplatform.googleapis.com/v1/"
        f"projects/{project}/locations/{location}/endpoints/openapi"
    )


def _provider_base_url(provider_type: str) -> str:
    normalized = normalize_inference_provider_type(provider_type)
    prefix = _PROVIDER_ENV_PREFIXES.get(normalized, normalized.upper().replace("-", "_"))
    env_key = f"{prefix}_API_BASE"
    configured = str(os.getenv(env_key) or os.getenv(f"{prefix}_BASE_URL") or "").strip()
    if configured:
        return configured.rstrip("/")
    if normalized == "vertex":
        return _vertex_default_base_url().rstrip("/")
    if normalized == "azure-openai":
        # Resource endpoint only; chat path is composed in invoke.
        return str(os.getenv("AZURE_OPENAI_ENDPOINT") or "").strip().rstrip("/")
    default = _PROVIDER_DEFAULT_BASE_URLS.get(normalized, "https://api.openai.com/v1")
    return str(default or "").rstrip("/")


def _provider_env_api_key(provider_type: str) -> str:
    normalized = normalize_inference_provider_type(provider_type)
    if normalized == "aws":
        # Prefer explicit Bedrock API key / bearer; otherwise signal default AWS chain.
        for env_key in ("AWS_BEDROCK_API_KEY", "BEDROCK_API_KEY", "AWS_BEARER_TOKEN_BEDROCK"):
            value = str(os.getenv(env_key) or "").strip()
            if value:
                return value
        if str(os.getenv("AWS_ACCESS_KEY_ID") or "").strip() or str(os.getenv("AWS_PROFILE") or "").strip():
            return "aws-default"
        # Still allow default chain (instance role / SSO) when operators opt in.
        if str(os.getenv("AWS_BEDROCK_USE_DEFAULT_CHAIN") or "").strip().lower() in {"1", "true", "yes", "on"}:
            return "aws-default"
        return ""
    if normalized == "vertex":
        for env_key in ("VERTEX_API_KEY", "GOOGLE_API_KEY", "VERTEX_ACCESS_TOKEN", "GOOGLE_OAUTH_ACCESS_TOKEN"):
            value = str(os.getenv(env_key) or "").strip()
            if value:
                return value
        return ""
    prefix = _PROVIDER_ENV_PREFIXES.get(normalized, normalized.upper().replace("-", "_"))
    for env_key in (f"{prefix}_API_KEY", f"{prefix}_WORKLOAD_IDENTITY_ACCESS_TOKEN"):
        value = str(os.getenv(env_key) or "").strip()
        if value:
            return value
    return ""


def provider_env_credential_configured(provider_type: str) -> bool:
    return bool(_provider_env_api_key(provider_type))


def _credential_from_binding(db: Session, binding: ProviderCredentialBinding) -> ResolvedInferenceCredential | None:
    try:
        resolved = resolve_binding_for_runtime(db, binding)
    except HTTPException:
        if inference_simulation_enabled() and str(binding.consumer_type or "").strip().lower() != "agent":
            return None
        raise
    if not resolved.secret_value:
        return None
    provider_type = normalize_inference_provider_type(
        str(binding.provider_type or resolved.provider_type or "")
    )
    return ResolvedInferenceCredential(
        provider_type=provider_type,
        api_key=resolved.secret_value,
        base_url=_provider_base_url(provider_type),
        upstream_model="",
        credential_source=f"binding:{binding.binding_id}",
    )


def _consumer_binding_lookup_order(provider_type: str) -> list[tuple[str, str]]:
    normalized = normalize_inference_provider_type(provider_type)
    ordered: list[tuple[str, str]] = [("platform", "default"), ("platform", normalized)]
    if normalized == "cursor":
        ordered.insert(0, ("gateway", "cursor"))
    else:
        ordered.append(("gateway", normalized))
        # Legacy UI id for Azure OpenAI bindings.
        if normalized == "azure-openai":
            ordered.append(("gateway", "azure"))
            ordered.append(("platform", "azure"))
        if normalized == "aws":
            ordered.append(("gateway", "bedrock"))
            ordered.append(("platform", "bedrock"))
        if normalized == "google":
            ordered.append(("gateway", "gcp"))
            ordered.append(("platform", "gcp"))
        if normalized == "vertex":
            ordered.append(("gateway", "google"))
            ordered.append(("platform", "google"))
    return ordered


def _find_scope_binding(
    db: Session,
    *,
    consumer_type: str,
    consumer_key: str,
    provider_type: str,
    environment: str,
) -> ProviderCredentialBinding | None:
    return (
        db.query(ProviderCredentialBinding)
        .filter_by(
            consumer_type=str(consumer_type or "").strip().lower(),
            consumer_key=str(consumer_key or "").strip(),
            provider_type=str(provider_type or "").strip().lower(),
            environment=str(environment or "dev").strip().lower() or "dev",
            status="active",
        )
        .first()
    )


def _lookup_catalog_binding(
    db: Session,
    *,
    provider_type: str,
    model_name: str,
    environment: str,
) -> ProviderCredentialBinding | None:
    entry = (
        db.query(SupportedModelCatalogEntry)
        .filter_by(
            provider_type=str(provider_type or "").strip().lower(),
            model_name=str(model_name or "").strip(),
            status="active",
        )
        .first()
    )
    if not entry:
        return None
    binding_id = str(entry.default_binding_id or "").strip()
    if not binding_id:
        return None
    binding = db.query(ProviderCredentialBinding).filter_by(binding_id=binding_id).first()
    if not binding or str(binding.status or "").strip().lower() != "active":
        return None
    if str(binding.environment or "dev").strip().lower() != str(environment or "dev").strip().lower():
        return None
    return binding


def should_attempt_upstream(credential: ResolvedInferenceCredential) -> bool:
    return _should_attempt_upstream(credential)


def _should_attempt_upstream(credential: ResolvedInferenceCredential) -> bool:
    provider = normalize_inference_provider_type(credential.provider_type)
    token = str(credential.api_key or "").strip()
    if provider == "aws":
        if token and token.lower() not in {"aws-default", "default", "use_default_chain"}:
            return True
        return token.lower() in {"aws-default", "default", "use_default_chain"} or bool(
            os.getenv("AWS_ACCESS_KEY_ID") or os.getenv("AWS_PROFILE") or os.getenv("AWS_BEDROCK_USE_DEFAULT_CHAIN")
        )
    if not token:
        return False
    if provider == "cursor":
        configured_base = str(os.getenv("CURSOR_API_BASE") or os.getenv("CURSOR_BASE_URL") or "").strip()
        if not configured_base and credential.base_url.startswith("http://127.0.0.1"):
            return False
    if provider == "openai" and credential.credential_source == "gateway_cursor_token":
        if not token.startswith("sk-"):
            return False
    if provider == "azure-openai" and not str(credential.base_url or "").strip():
        return False
    if provider == "vertex" and not str(credential.base_url or "").strip():
        return False
    return True


def _optional_credential_from_binding(
    db: Session,
    binding: ProviderCredentialBinding,
) -> ResolvedInferenceCredential | None:
    try:
        return _credential_from_binding(db, binding)
    except HTTPException:
        return None


def resolve_inference_credential(
    db: Session,
    *,
    agent_id: str | None,
    environment: str,
    model_name: str,
    tenant_id: str | None = None,
    selected_provider_id: str | None = None,
    resolve_gateway_cursor_token: Callable[[Session], str],
) -> ResolvedInferenceCredential | None:
    normalized_environment = str(environment or "dev").strip().lower() or "dev"
    provider_type, upstream_model = infer_provider_type_from_model(model_name)
    agent_key = str(agent_id or "").strip()

    # Flow Studio may pass a Providers credential binding id (binding_id override).
    if db is not None and agent_key:
        binding = db.query(ProviderCredentialBinding).filter_by(binding_id=agent_key).first()
        if binding is not None:
            credential = _optional_credential_from_binding(db, binding)
            if credential:
                return ResolvedInferenceCredential(
                    provider_type=credential.provider_type or provider_type,
                    api_key=credential.api_key,
                    base_url=credential.base_url or _provider_base_url(provider_type),
                    upstream_model=upstream_model,
                    credential_source=credential.credential_source,
                )

    if db is not None and agent_key and not agent_key.startswith("gateway-"):
        config = db.query(AgentConfig).filter_by(agent_key=agent_key).first()
        if config:
            resolved_agent = resolve_agent_config_credential(
                db,
                config,
                environment=normalized_environment,
            )
            if resolved_agent is not None:
                return _credential_from_agent(resolved_agent, upstream_model)
            if str(config.provider or "").strip().lower() == "cursor":
                cursor_token = str(resolve_gateway_cursor_token(db) or "").strip()
                if cursor_token:
                    return ResolvedInferenceCredential(
                        provider_type="cursor",
                        api_key=cursor_token,
                        base_url=_provider_base_url("cursor"),
                        upstream_model=upstream_model,
                        credential_source="gateway_cursor_token",
                    )

    if db is not None and selected_provider_id:
        route_binding = _find_scope_binding(
            db,
            consumer_type="route",
            consumer_key=str(selected_provider_id).strip(),
            provider_type=provider_type,
            environment=normalized_environment,
        )
        if route_binding:
            credential = _optional_credential_from_binding(db, route_binding)
            if credential:
                return ResolvedInferenceCredential(
                    provider_type=credential.provider_type,
                    api_key=credential.api_key,
                    base_url=credential.base_url,
                    upstream_model=upstream_model,
                    credential_source=credential.credential_source,
                )

    if db is not None:
        catalog_binding = _lookup_catalog_binding(
            db,
            provider_type=provider_type,
            model_name=upstream_model,
            environment=normalized_environment,
        )
        if catalog_binding:
            credential = _optional_credential_from_binding(db, catalog_binding)
            if credential:
                return ResolvedInferenceCredential(
                    provider_type=credential.provider_type,
                    api_key=credential.api_key,
                    base_url=credential.base_url,
                    upstream_model=upstream_model,
                    credential_source=credential.credential_source,
                )

        for consumer_type, consumer_key in _consumer_binding_lookup_order(provider_type):
            scoped_binding = _find_scope_binding(
                db,
                consumer_type=consumer_type,
                consumer_key=consumer_key,
                provider_type=provider_type,
                environment=normalized_environment,
            )
            if scoped_binding:
                credential = _optional_credential_from_binding(db, scoped_binding)
                if credential:
                    return ResolvedInferenceCredential(
                        provider_type=credential.provider_type,
                        api_key=credential.api_key,
                        base_url=credential.base_url,
                        upstream_model=upstream_model,
                        credential_source=credential.credential_source,
                    )

    env_api_key = _provider_env_api_key(provider_type)
    if env_api_key:
        return ResolvedInferenceCredential(
            provider_type=provider_type,
            api_key=env_api_key,
            base_url=_provider_base_url(provider_type),
            upstream_model=upstream_model,
            credential_source=f"env:{provider_type}",
        )

    if db is not None and provider_type in {"cursor", "openai"}:
        try:
            cursor_token = str(resolve_gateway_cursor_token(db) or "").strip()
        except HTTPException:
            cursor_token = ""
        if cursor_token:
            return ResolvedInferenceCredential(
                provider_type=provider_type,
                api_key=cursor_token,
                base_url=_provider_base_url(provider_type),
                upstream_model=upstream_model,
                credential_source="gateway_cursor_token",
            )

    return None


def _credential_from_agent(
    resolved: ResolvedAgentCredential,
    upstream_model: str,
) -> ResolvedInferenceCredential:
    provider_type = str(resolved.provider_type or "").strip().lower()
    return ResolvedInferenceCredential(
        provider_type=provider_type,
        api_key=str(resolved.secret_value or ""),
        base_url=_provider_base_url(provider_type),
        upstream_model=upstream_model,
        credential_source=f"agent_binding:{resolved.binding_id}",
    )


def simulate_chat_completion(model_name: str, prompt_preview: str) -> str:
    prompt = str(prompt_preview or "").strip()
    factual = lookup_factual_answer(prompt)
    if factual:
        return factual
    structured = lookup_structured_simulation(prompt)
    if structured:
        return structured
    if prompt:
        return f"Simulated completion from {model_name}: {prompt}"
    return f"Simulated completion from {model_name}."


def simulate_responses_output(model_name: str, effective_prompt: str) -> str:
    prompt = str(effective_prompt or "").strip()
    factual = lookup_factual_answer(prompt)
    if factual:
        return factual
    structured = lookup_structured_simulation(prompt)
    if structured:
        return structured
    if prompt:
        return f"Simulated response from {model_name}: {prompt}"
    return f"Simulated response from {model_name}."


def _auth_headers(credential: ResolvedInferenceCredential) -> dict[str, str]:
    provider_type = normalize_inference_provider_type(credential.provider_type)
    if provider_type == "anthropic":
        return {
            "x-api-key": credential.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
    if provider_type == "azure-openai":
        return {
            "api-key": credential.api_key,
            "Authorization": f"Bearer {credential.api_key}",
            "Content-Type": "application/json",
        }
    return {
        "Authorization": f"Bearer {credential.api_key}",
        "Content-Type": "application/json",
    }


def _azure_api_version() -> str:
    return str(os.getenv("AZURE_OPENAI_API_VERSION") or "2024-10-21").strip() or "2024-10-21"


def _chat_completions_url(credential: ResolvedInferenceCredential) -> str:
    provider = normalize_inference_provider_type(credential.provider_type)
    base = str(credential.base_url or "").rstrip("/")
    if provider != "azure-openai":
        return f"{base}/chat/completions"

    if not base:
        raise HTTPException(
            status_code=422,
            detail="Azure OpenAI requires AZURE_OPENAI_API_BASE or AZURE_OPENAI_ENDPOINT (resource URL).",
        )
    # Newer OpenAI v1-compatible Azure resource paths.
    if base.endswith("/v1") or "/openai/v1" in base:
        return f"{base}/chat/completions"
    api_version = _azure_api_version()
    deployment = str(credential.upstream_model or "").strip()
    if not deployment:
        raise HTTPException(status_code=422, detail="Azure OpenAI deployment (model) name is required.")
    # Classic deployment path: {endpoint}/openai/deployments/{deployment}/chat/completions?api-version=...
    root = base
    if root.endswith("/openai"):
        root = root[: -len("/openai")]
    return f"{root}/openai/deployments/{deployment}/chat/completions?api-version={api_version}"


def _parse_aws_bedrock_credentials(api_key: str) -> dict[str, Any]:
    raw = str(api_key or "").strip()
    if not raw or raw.lower() in {"aws-default", "default", "use_default_chain"}:
        return {}
    if raw.startswith("{"):
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail=f"Invalid AWS Bedrock credential JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=422, detail="AWS Bedrock credential JSON must be an object")
        return payload
    # Opaque bearer / API key for Bedrock (when configured by AWS).
    return {"bearer_token": raw}


def _bedrock_client(credential: ResolvedInferenceCredential):
    try:
        import boto3
        from botocore.config import Config as BotoConfig
    except ImportError as exc:  # pragma: no cover
        raise HTTPException(status_code=500, detail="boto3 is required for AWS Bedrock inference") from exc

    parsed = _parse_aws_bedrock_credentials(credential.api_key)
    region = str(
        parsed.get("region")
        or parsed.get("region_name")
        or os.getenv("AWS_BEDROCK_REGION")
        or os.getenv("AWS_REGION")
        or os.getenv("AWS_DEFAULT_REGION")
        or "us-east-1"
    ).strip() or "us-east-1"

    session_kwargs: dict[str, Any] = {}
    access_key = str(parsed.get("access_key_id") or parsed.get("aws_access_key_id") or "").strip()
    secret_key = str(parsed.get("secret_access_key") or parsed.get("aws_secret_access_key") or "").strip()
    session_token = str(parsed.get("session_token") or parsed.get("aws_session_token") or "").strip()
    profile = str(parsed.get("profile") or parsed.get("aws_profile") or "").strip()
    if access_key and secret_key:
        session_kwargs = {
            "aws_access_key_id": access_key,
            "aws_secret_access_key": secret_key,
        }
        if session_token:
            session_kwargs["aws_session_token"] = session_token
    elif profile:
        session_kwargs = {"profile_name": profile}

    session = boto3.Session(**session_kwargs) if session_kwargs else boto3.Session()
    return session.client(
        "bedrock-runtime",
        region_name=region,
        config=BotoConfig(retries={"max_attempts": 2, "mode": "standard"}),
    )


def _message_text_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                if item.get("type") == "text" or "text" in item:
                    parts.append(str(item.get("text") or ""))
                elif "content" in item:
                    parts.append(str(item.get("content") or ""))
        return "\n".join(part for part in parts if part).strip()
    return str(content or "")


def _invoke_bedrock_chat_completion(
    credential: ResolvedInferenceCredential,
    *,
    messages: list[dict[str, Any]],
    temperature: float | None = None,
    top_p: float | None = None,
    max_tokens: int | None = None,
    stop: list[str] | None = None,
) -> ChatCompletionInferenceResult:
    client = _bedrock_client(credential)
    system_blocks: list[dict[str, str]] = []
    converse_messages: list[dict[str, Any]] = []
    for message in messages:
        role = str(message.get("role") or "user").strip().lower()
        text = _message_text_content(message.get("content"))
        if not text:
            continue
        if role == "system":
            system_blocks.append({"text": text})
            continue
        mapped_role = "assistant" if role == "assistant" else "user"
        # Bedrock requires alternating user/assistant turns; merge consecutive same-role turns.
        if converse_messages and converse_messages[-1]["role"] == mapped_role:
            prev = converse_messages[-1]["content"][0]["text"]
            converse_messages[-1]["content"][0]["text"] = f"{prev}\n{text}".strip()
        else:
            converse_messages.append({"role": mapped_role, "content": [{"text": text}]})

    if not converse_messages:
        raise HTTPException(status_code=422, detail="Bedrock converse requires at least one user/assistant message")
    if converse_messages[0]["role"] != "user":
        converse_messages.insert(0, {"role": "user", "content": [{"text": "(continue)"}]})

    inference_config: dict[str, Any] = {}
    if max_tokens is not None:
        inference_config["maxTokens"] = int(max_tokens)
    if temperature is not None:
        inference_config["temperature"] = float(temperature)
    if top_p is not None:
        inference_config["topP"] = float(top_p)
    if stop:
        inference_config["stopSequences"] = [str(item) for item in stop[:4]]

    request: dict[str, Any] = {
        "modelId": credential.upstream_model,
        "messages": converse_messages,
    }
    if system_blocks:
        request["system"] = system_blocks
    if inference_config:
        request["inferenceConfig"] = inference_config

    try:
        response = client.converse(**request)
    except Exception as exc:  # noqa: BLE001 - surface AWS errors as 502
        raise HTTPException(status_code=502, detail=f"aws bedrock upstream error: {exc}") from exc

    output = response.get("output") if isinstance(response, dict) else {}
    message = output.get("message") if isinstance(output, dict) else {}
    content_blocks = message.get("content") if isinstance(message, dict) else []
    text_parts: list[str] = []
    if isinstance(content_blocks, list):
        for block in content_blocks:
            if isinstance(block, dict) and block.get("text"):
                text_parts.append(str(block["text"]))
    completion_text = "\n".join(part for part in text_parts if part).strip()
    usage_raw = response.get("usage") if isinstance(response, dict) else {}
    prompt_tokens = int((usage_raw or {}).get("inputTokens") or 1)
    completion_tokens = int((usage_raw or {}).get("outputTokens") or max(1, len(completion_text.split()) if completion_text else 1))
    stop_reason = str(response.get("stopReason") or "end_turn").strip() or "end_turn"
    finish_reason = "stop" if stop_reason in {"end_turn", "stop_sequence"} else stop_reason
    return ChatCompletionInferenceResult(
        content=completion_text,
        finish_reason=finish_reason,
        usage=InferenceUsage(
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=prompt_tokens + completion_tokens,
        ),
        tool_calls=None,
    )


def _parse_usage(raw_usage: object, *, prompt_fallback: int, completion_fallback: int) -> InferenceUsage:
    usage = raw_usage if isinstance(raw_usage, dict) else {}
    prompt_tokens = int(usage.get("prompt_tokens") or usage.get("input_tokens") or prompt_fallback)
    completion_tokens = int(usage.get("completion_tokens") or usage.get("output_tokens") or completion_fallback)
    total_tokens = int(usage.get("total_tokens") or (prompt_tokens + completion_tokens))
    return InferenceUsage(
        prompt_tokens=max(0, prompt_tokens),
        completion_tokens=max(0, completion_tokens),
        total_tokens=max(0, total_tokens),
    )


def _serialize_chat_messages(messages: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    serialized: list[dict[str, Any]] = []
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = str(message.get("role") or "user").strip() or "user"
        content = message.get("content")
        if content is None:
            content = ""
        serialized.append({"role": role, "content": content})
    return serialized


def _response_json(response: httpx.Response) -> dict[str, Any]:
    try:
        payload = response.json()
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _raise_upstream_http_error(response: httpx.Response, *, provider_type: str) -> None:
    detail = f"{provider_type} upstream request failed"
    try:
        payload = response.json()
        if isinstance(payload, dict):
            error_block = payload.get("error")
            if isinstance(error_block, dict):
                message = str(error_block.get("message") or "").strip()
                if message:
                    detail = f"{provider_type} upstream error: {message[:500]}"
            elif isinstance(error_block, str) and error_block.strip():
                detail = f"{provider_type} upstream error: {error_block.strip()[:500]}"
    except Exception:
        text = str(response.text or "").strip()
        if text:
            detail = f"{provider_type} upstream error: {text[:500]}"
    raise HTTPException(status_code=502, detail=detail)


def invoke_chat_completion(
    credential: ResolvedInferenceCredential,
    *,
    messages: list[dict[str, Any]],
    temperature: float | None = None,
    top_p: float | None = None,
    max_tokens: int | None = None,
    stop: list[str] | None = None,
    response_format: dict[str, object] | None = None,
) -> ChatCompletionInferenceResult:
    provider_type = normalize_inference_provider_type(credential.provider_type)
    if provider_type == "anthropic":
        return _invoke_anthropic_chat_completion(
            credential,
            messages=messages,
            temperature=temperature,
            top_p=top_p,
            max_tokens=max_tokens,
            stop=stop,
        )
    if provider_type == "aws":
        return _invoke_bedrock_chat_completion(
            credential,
            messages=messages,
            temperature=temperature,
            top_p=top_p,
            max_tokens=max_tokens,
            stop=stop,
        )

    if provider_type not in OPENAI_COMPATIBLE_PROVIDERS:
        raise HTTPException(status_code=422, detail=f"Unsupported inference provider_type: {credential.provider_type}")

    body: dict[str, Any] = {
        "model": credential.upstream_model,
        "messages": _serialize_chat_messages(messages),
    }
    # Classic Azure deployment path already encodes the deployment in the URL.
    if provider_type == "azure-openai":
        base = str(credential.base_url or "")
        if base and not (base.endswith("/v1") or "/openai/v1" in base):
            body.pop("model", None)
    if temperature is not None:
        body["temperature"] = temperature
    if top_p is not None:
        body["top_p"] = top_p
    if max_tokens is not None:
        body["max_tokens"] = max_tokens
    if stop:
        body["stop"] = stop
    if response_format:
        body["response_format"] = response_format

    response = httpx.post(
        _chat_completions_url(credential),
        headers=_auth_headers(credential),
        json=body,
        timeout=inference_timeout_seconds(),
    )
    if response.status_code >= 400:
        _raise_upstream_http_error(response, provider_type=credential.provider_type)

    payload = response.json()
    choices = payload.get("choices") if isinstance(payload, dict) else None
    if not isinstance(choices, list) or not choices:
        raise HTTPException(status_code=502, detail="Upstream chat completion returned no choices")

    first = choices[0] if isinstance(choices[0], dict) else {}
    message = first.get("message") if isinstance(first.get("message"), dict) else {}
    content = message.get("content")
    if isinstance(content, list):
        text_parts = [
            str(item.get("text") or "").strip()
            for item in content
            if isinstance(item, dict) and str(item.get("type") or "text") == "text"
        ]
        completion_text = " ".join(part for part in text_parts if part).strip()
    else:
        completion_text = str(content or "").strip()

    tool_calls = message.get("tool_calls") if isinstance(message.get("tool_calls"), list) else None
    finish_reason = str(first.get("finish_reason") or "stop").strip() or "stop"
    usage = _parse_usage(
        payload.get("usage") if isinstance(payload, dict) else {},
        prompt_fallback=1,
        completion_fallback=max(1, len(completion_text.split()) if completion_text else 1),
    )
    return ChatCompletionInferenceResult(
        content=completion_text,
        finish_reason=finish_reason,
        usage=usage,
        tool_calls=tool_calls,
    )


def _invoke_anthropic_chat_completion(
    credential: ResolvedInferenceCredential,
    *,
    messages: list[dict[str, Any]],
    temperature: float | None,
    top_p: float | None,
    max_tokens: int | None,
    stop: list[str] | None,
) -> ChatCompletionInferenceResult:
    system_parts: list[str] = []
    anthropic_messages: list[dict[str, str]] = []
    for message in _serialize_chat_messages(messages):
        role = str(message.get("role") or "user").strip().lower()
        content = message.get("content")
        text = content if isinstance(content, str) else json.dumps(content, separators=(",", ":"))
        if role == "system":
            system_parts.append(str(text or "").strip())
            continue
        mapped_role = "assistant" if role == "assistant" else "user"
        anthropic_messages.append({"role": mapped_role, "content": str(text or "")})

    if not anthropic_messages:
        anthropic_messages = [{"role": "user", "content": " " }]

    body: dict[str, Any] = {
        "model": credential.upstream_model,
        "max_tokens": int(max_tokens or 1024),
        "messages": anthropic_messages,
    }
    if system_parts:
        body["system"] = "\n\n".join(part for part in system_parts if part)
    if temperature is not None:
        body["temperature"] = temperature
    if top_p is not None:
        body["top_p"] = top_p
    if stop:
        body["stop_sequences"] = stop

    response = httpx.post(
        f"{credential.base_url}/messages",
        headers=_auth_headers(credential),
        json=body,
        timeout=inference_timeout_seconds(),
    )
    if response.status_code >= 400:
        _raise_upstream_http_error(response, provider_type="anthropic")

    payload = _response_json(response)
    text_parts: list[str] = []
    for block in payload.get("content") if isinstance(payload.get("content"), list) else []:
        if isinstance(block, dict) and str(block.get("type") or "") == "text":
            text_parts.append(str(block.get("text") or ""))
    completion_text = "".join(text_parts).strip()
    finish_reason = str(payload.get("stop_reason") or "stop").strip() or "stop"
    if finish_reason == "end_turn":
        finish_reason = "stop"
    usage = _parse_usage(
        payload.get("usage"),
        prompt_fallback=1,
        completion_fallback=max(1, len(completion_text.split()) if completion_text else 1),
    )
    return ChatCompletionInferenceResult(
        content=completion_text,
        finish_reason=finish_reason,
        usage=usage,
    )


def stream_chat_completion(
    credential: ResolvedInferenceCredential,
    *,
    messages: list[dict[str, Any]],
    temperature: float | None = None,
    top_p: float | None = None,
    max_tokens: int | None = None,
    stop: list[str] | None = None,
    response_format: dict[str, object] | None = None,
) -> Generator[str, None, None]:
    if credential.provider_type == "anthropic":
        result = _invoke_anthropic_chat_completion(
            credential,
            messages=messages,
            temperature=temperature,
            top_p=top_p,
            max_tokens=max_tokens,
            stop=stop,
        )
        yield result.content
        return

    body: dict[str, Any] = {
        "model": credential.upstream_model,
        "messages": _serialize_chat_messages(messages),
        "stream": True,
    }
    if temperature is not None:
        body["temperature"] = temperature
    if top_p is not None:
        body["top_p"] = top_p
    if max_tokens is not None:
        body["max_tokens"] = max_tokens
    if stop:
        body["stop"] = stop
    if response_format:
        body["response_format"] = response_format

    with httpx.stream(
        "POST",
        f"{credential.base_url}/chat/completions",
        headers=_auth_headers(credential),
        json=body,
        timeout=inference_timeout_seconds(),
    ) as response:
        if response.status_code >= 400:
            raw = response.read()
            detail = raw.decode("utf-8", errors="replace")[:500]
            raise HTTPException(status_code=502, detail=f"{credential.provider_type} upstream stream failed: {detail}")
        for line in response.iter_lines():
            if not line:
                continue
            if line.startswith("data:"):
                yield line[len("data:") :].strip()
            else:
                yield line


def invoke_embeddings(
    credential: ResolvedInferenceCredential,
    *,
    inputs: list[str],
    dimensions: int | None = None,
) -> EmbeddingsInferenceResult:
    provider = normalize_inference_provider_type(credential.provider_type)
    if provider == "aws":
        return _invoke_bedrock_embeddings(credential, inputs=inputs, dimensions=dimensions)
    if provider not in OPENAI_COMPATIBLE_PROVIDERS:
        raise HTTPException(status_code=422, detail=f"Embeddings unsupported for provider_type: {credential.provider_type}")

    body: dict[str, Any] = {
        "model": credential.upstream_model,
        "input": inputs if len(inputs) > 1 else (inputs[0] if inputs else ""),
    }
    if dimensions is not None:
        body["dimensions"] = dimensions

    # Classic Azure embeddings deployment path.
    url = f"{credential.base_url}/embeddings"
    if provider == "azure-openai":
        base = str(credential.base_url or "").rstrip("/")
        if base and not (base.endswith("/v1") or "/openai/v1" in base):
            api_version = _azure_api_version()
            deployment = str(credential.upstream_model or "").strip()
            root = base[:-len("/openai")] if base.endswith("/openai") else base
            url = f"{root}/openai/deployments/{deployment}/embeddings?api-version={api_version}"
            body.pop("model", None)

    response = httpx.post(
        url,
        headers=_auth_headers(credential),
        json=body,
        timeout=inference_timeout_seconds(),
    )
    if response.status_code >= 400:
        _raise_upstream_http_error(response, provider_type=credential.provider_type)

    payload = _response_json(response)
    data = payload.get("data") if isinstance(payload.get("data"), list) else []
    vectors: list[list[float]] = []
    for item in data:
        if isinstance(item, dict) and isinstance(item.get("embedding"), list):
            vectors.append([float(value) for value in item["embedding"]])
    usage = _parse_usage(payload.get("usage"), prompt_fallback=1, completion_fallback=0)
    return EmbeddingsInferenceResult(embeddings=vectors, usage=usage)


def _invoke_bedrock_embeddings(
    credential: ResolvedInferenceCredential,
    *,
    inputs: list[str],
    dimensions: int | None = None,
) -> EmbeddingsInferenceResult:
    client = _bedrock_client(credential)
    model_id = str(credential.upstream_model or "").strip()
    if not model_id:
        raise HTTPException(status_code=422, detail="Bedrock embedding modelId is required")

    vectors: list[list[float]] = []
    prompt_tokens = 0
    lower = model_id.lower()
    for text in inputs:
        body: dict[str, Any]
        if "cohere.embed" in lower:
            body = {"texts": [text], "input_type": "search_document"}
        elif "titan-embed" in lower or "amazon.titan-embed" in lower:
            body = {"inputText": text}
            if dimensions is not None:
                body["dimensions"] = int(dimensions)
        else:
            # Generic Bedrock embedding-style payload used by several providers.
            body = {"inputText": text}

        try:
            response = client.invoke_model(
                modelId=model_id,
                contentType="application/json",
                accept="application/json",
                body=json.dumps(body).encode("utf-8"),
            )
            raw = response.get("body")
            payload_bytes = raw.read() if hasattr(raw, "read") else raw
            payload = json.loads(payload_bytes.decode("utf-8") if isinstance(payload_bytes, (bytes, bytearray)) else payload_bytes)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"aws bedrock embeddings error: {exc}") from exc

        embedding: list[float] | None = None
        if isinstance(payload, dict):
            if isinstance(payload.get("embedding"), list):
                embedding = [float(v) for v in payload["embedding"]]
            elif isinstance(payload.get("embeddings"), list) and payload["embeddings"]:
                first = payload["embeddings"][0]
                if isinstance(first, list):
                    embedding = [float(v) for v in first]
                elif isinstance(first, dict) and isinstance(first.get("embedding"), list):
                    embedding = [float(v) for v in first["embedding"]]
            prompt_tokens += int(payload.get("inputTextTokenCount") or max(1, len(text.split())))
        if embedding is None:
            raise HTTPException(status_code=502, detail="Bedrock embeddings response missing embedding vector")
        vectors.append(embedding)

    return EmbeddingsInferenceResult(
        embeddings=vectors,
        usage=InferenceUsage(
            prompt_tokens=max(1, prompt_tokens),
            completion_tokens=0,
            total_tokens=max(1, prompt_tokens),
        ),
    )


def invoke_responses_create(
    credential: ResolvedInferenceCredential,
    *,
    request_body: dict[str, Any],
) -> ResponsesInferenceResult:
    if normalize_inference_provider_type(credential.provider_type) not in OPENAI_COMPATIBLE_PROVIDERS:
        raise HTTPException(status_code=422, detail=f"Responses API unsupported for provider_type: {credential.provider_type}")

    body = dict(request_body)
    body["model"] = credential.upstream_model
    body.pop("stream", None)

    response = httpx.post(
        f"{credential.base_url}/responses",
        headers=_auth_headers(credential),
        json=body,
        timeout=inference_timeout_seconds(),
    )
    if response.status_code >= 400:
        _raise_upstream_http_error(response, provider_type=credential.provider_type)

    payload = _response_json(response)
    output_text = str(payload.get("output_text") or "").strip()
    output_items = payload.get("output") if isinstance(payload.get("output"), list) else []
    if not output_text and output_items:
        text_parts: list[str] = []
        for item in output_items:
            if not isinstance(item, dict):
                continue
            for content in item.get("content") if isinstance(item.get("content"), list) else []:
                if isinstance(content, dict) and str(content.get("type") or "") in {"output_text", "text"}:
                    text_parts.append(str(content.get("text") or ""))
        output_text = "".join(text_parts).strip()

    has_tool_calls = any(
        isinstance(item, dict) and str(item.get("type") or "").strip().lower() == "tool_call" for item in output_items
    )
    finish_reason = "tool_calls" if has_tool_calls else "stop"
    usage = _parse_usage(payload.get("usage"), prompt_fallback=1, completion_fallback=max(1, len(output_text.split()) if output_text else 1))
    return ResponsesInferenceResult(
        output_text=output_text,
        output_items=[item for item in output_items if isinstance(item, dict)],
        finish_reason=finish_reason,
        usage=usage,
        has_tool_calls=has_tool_calls,
    )


def invoke_anthropic_messages(
    credential: ResolvedInferenceCredential,
    *,
    user_input: str,
    max_tokens: int | None = None,
) -> ChatCompletionInferenceResult:
    return _invoke_anthropic_chat_completion(
        credential,
        messages=[{"role": "user", "content": user_input}],
        temperature=None,
        top_p=None,
        max_tokens=max_tokens,
        stop=None,
    )


def invoke_image_generation(
    credential: ResolvedInferenceCredential,
    *,
    prompt: str,
    size: str | None,
    n: int,
) -> list[dict[str, Any]]:
    if normalize_inference_provider_type(credential.provider_type) not in OPENAI_COMPATIBLE_PROVIDERS:
        raise HTTPException(status_code=422, detail=f"Image generation unsupported for provider_type: {credential.provider_type}")

    body: dict[str, Any] = {
        "model": credential.upstream_model,
        "prompt": prompt,
        "n": n,
    }
    if size:
        body["size"] = size

    response = httpx.post(
        f"{credential.base_url}/images/generations",
        headers=_auth_headers(credential),
        json=body,
        timeout=inference_timeout_seconds(),
    )
    if response.status_code >= 400:
        _raise_upstream_http_error(response, provider_type=credential.provider_type)

    payload = _response_json(response)
    data = payload.get("data") if isinstance(payload.get("data"), list) else []
    return [item for item in data if isinstance(item, dict)]


def invoke_rerank(
    credential: ResolvedInferenceCredential,
    *,
    query: str,
    documents: list[str],
    top_n: int,
) -> list[dict[str, Any]]:
    provider_type = credential.provider_type
    if provider_type == "cohere":
        response = httpx.post(
            f"{credential.base_url}/rerank",
            headers={**_auth_headers(credential), "Content-Type": "application/json"},
            json={
                "model": credential.upstream_model,
                "query": query,
                "documents": documents,
                "top_n": top_n,
            },
            timeout=inference_timeout_seconds(),
        )
        if response.status_code >= 400:
            _raise_upstream_http_error(response, provider_type=provider_type)
        payload = _response_json(response)
        results = payload.get("results") if isinstance(payload.get("results"), list) else []
        normalized: list[dict[str, Any]] = []
        for item in results:
            if not isinstance(item, dict):
                continue
            index = int(item.get("index") or 0)
            normalized.append(
                {
                    "index": index,
                    "relevance_score": float(item.get("relevance_score") or 0.0),
                    "document": documents[index] if 0 <= index < len(documents) else "",
                }
            )
        return normalized

    raise HTTPException(status_code=422, detail=f"Rerank unsupported for provider_type: {provider_type}")


def execute_chat_completion(
    db: Session,
    *,
    credential: ResolvedInferenceCredential | None,
    model_name: str,
    messages: list[dict[str, Any]],
    prompt_preview: str,
    temperature: float | None = None,
    top_p: float | None = None,
    max_tokens: int | None = None,
    stop: list[str] | None = None,
    response_format: dict[str, object] | None = None,
) -> ChatCompletionInferenceResult:
    if credential is not None and credential.api_key.strip() and _should_attempt_upstream(credential):
        effective = ResolvedInferenceCredential(
            provider_type=credential.provider_type,
            api_key=credential.api_key,
            base_url=credential.base_url,
            upstream_model=credential.upstream_model or infer_provider_type_from_model(model_name)[1],
            credential_source=credential.credential_source,
        )
        return invoke_chat_completion(
            effective,
            messages=messages,
            temperature=temperature,
            top_p=top_p,
            max_tokens=max_tokens,
            stop=stop,
            response_format=response_format,
        )
    if inference_simulation_enabled():
        simulated = simulate_chat_completion(model_name, prompt_preview)
        usage = InferenceUsage(
            prompt_tokens=max(1, len(prompt_preview.split())),
            completion_tokens=max(1, len(simulated.split())),
            total_tokens=max(2, len(prompt_preview.split()) + len(simulated.split())),
        )
        return ChatCompletionInferenceResult(content=simulated, finish_reason="stop", usage=usage)
    raise HTTPException(status_code=503, detail="Inference credentials are not configured for this request")


def execute_responses_create(
    db: Session,
    *,
    credential: ResolvedInferenceCredential | None,
    model_name: str,
    effective_prompt: str,
    request_body: dict[str, Any],
) -> ResponsesInferenceResult:
    if credential is not None and credential.api_key.strip() and _should_attempt_upstream(credential):
        effective = ResolvedInferenceCredential(
            provider_type=credential.provider_type,
            api_key=credential.api_key,
            base_url=credential.base_url,
            upstream_model=credential.upstream_model or infer_provider_type_from_model(model_name)[1],
            credential_source=credential.credential_source,
        )
        return invoke_responses_create(effective, request_body=request_body)

    can_simulate = inference_simulation_enabled() or (
        credential is not None
        and credential.api_key.strip()
        and not _should_attempt_upstream(credential)
    )
    if can_simulate:
        simulated = simulate_responses_output(model_name, effective_prompt)
        usage = InferenceUsage(
            prompt_tokens=max(1, len(effective_prompt.split())),
            completion_tokens=max(1, len(simulated.split())),
            total_tokens=max(2, len(effective_prompt.split()) + len(simulated.split())),
        )
        return ResponsesInferenceResult(
            output_text=simulated,
            output_items=[
                {
                    "id": "resp-out-simulated",
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": simulated}],
                    "finish_reason": "stop",
                }
            ],
            finish_reason="stop",
            usage=usage,
            has_tool_calls=False,
        )
    raise HTTPException(status_code=503, detail="Inference credentials are not configured for this request")
