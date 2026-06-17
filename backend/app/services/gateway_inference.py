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
    "cursor",
}

_PROVIDER_ENV_PREFIXES: dict[str, str] = {
    "openai": "OPENAI",
    "anthropic": "ANTHROPIC",
    "cohere": "COHERE",
    "mistral": "MISTRAL",
    "groq": "GROQ",
    "azure-openai": "AZURE_OPENAI",
    "azure_openai": "AZURE_OPENAI",
    "cursor": "CURSOR",
}

_PROVIDER_DEFAULT_BASE_URLS: dict[str, str] = {
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com/v1",
    "groq": "https://api.groq.com/openai/v1",
    "mistral": "https://api.mistral.ai/v1",
    "cohere": "https://api.cohere.com/v2",
    "cursor": "http://127.0.0.1:8765/v1",
}

_OPENAI_MODEL_PREFIXES = ("gpt-", "o1", "o2", "o3", "o4", "chatgpt", "text-embedding", "whisper", "tts-", "dall-e")
_ANTHROPIC_MODEL_PREFIXES = ("claude",)
_CURSOR_MODEL_PREFIXES = ("composer", "cursor-")

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
    provider_prefix, normalized_model = split_provider_model(model_name)
    if provider_prefix:
        return provider_prefix, normalized_model

    lower = normalized_model.lower()
    if any(lower.startswith(prefix) for prefix in _ANTHROPIC_MODEL_PREFIXES):
        return "anthropic", normalized_model
    if any(lower.startswith(prefix) for prefix in _CURSOR_MODEL_PREFIXES):
        return "cursor", normalized_model
    if any(lower.startswith(prefix) for prefix in _OPENAI_MODEL_PREFIXES):
        return "openai", normalized_model

    default_provider = str(os.getenv("GATEWAY_DEFAULT_INFERENCE_PROVIDER", "openai") or "openai").strip().lower()
    return default_provider or "openai", normalized_model


def _provider_base_url(provider_type: str) -> str:
    normalized = str(provider_type or "").strip().lower()
    prefix = _PROVIDER_ENV_PREFIXES.get(normalized, normalized.upper().replace("-", "_"))
    env_key = f"{prefix}_API_BASE"
    configured = str(os.getenv(env_key) or os.getenv(f"{prefix}_BASE_URL") or "").strip()
    if configured:
        return configured.rstrip("/")
    return _PROVIDER_DEFAULT_BASE_URLS.get(normalized, "https://api.openai.com/v1").rstrip("/")


def _provider_env_api_key(provider_type: str) -> str:
    normalized = str(provider_type or "").strip().lower()
    prefix = _PROVIDER_ENV_PREFIXES.get(normalized, normalized.upper().replace("-", "_"))
    for env_key in (f"{prefix}_API_KEY", f"{prefix}_WORKLOAD_IDENTITY_ACCESS_TOKEN"):
        value = str(os.getenv(env_key) or "").strip()
        if value:
            return value
    return ""


def _credential_from_binding(db: Session, binding: ProviderCredentialBinding) -> ResolvedInferenceCredential | None:
    try:
        resolved = resolve_binding_for_runtime(db, binding)
    except HTTPException:
        if inference_simulation_enabled() and str(binding.consumer_type or "").strip().lower() != "agent":
            return None
        raise
    if not resolved.secret_value:
        return None
    provider_type = str(binding.provider_type or resolved.provider_type or "").strip().lower()
    return ResolvedInferenceCredential(
        provider_type=provider_type,
        api_key=resolved.secret_value,
        base_url=_provider_base_url(provider_type),
        upstream_model="",
        credential_source=f"binding:{binding.binding_id}",
    )


def _consumer_binding_lookup_order(provider_type: str) -> list[tuple[str, str]]:
    normalized = str(provider_type or "").strip().lower()
    ordered: list[tuple[str, str]] = [("platform", "default"), ("platform", normalized)]
    if normalized == "cursor":
        ordered.insert(0, ("gateway", "cursor"))
    else:
        ordered.append(("gateway", normalized))
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
    if not str(credential.api_key or "").strip():
        return False
    if credential.provider_type == "cursor":
        configured_base = str(os.getenv("CURSOR_API_BASE") or os.getenv("CURSOR_BASE_URL") or "").strip()
        if not configured_base and credential.base_url.startswith("http://127.0.0.1"):
            return False
    if credential.provider_type == "openai" and credential.credential_source == "gateway_cursor_token":
        token = str(credential.api_key or "").strip()
        if not token.startswith("sk-"):
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
    provider_type = credential.provider_type
    if provider_type == "anthropic":
        return {
            "x-api-key": credential.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }
    return {
        "Authorization": f"Bearer {credential.api_key}",
        "Content-Type": "application/json",
    }


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
    if credential.provider_type == "anthropic":
        return _invoke_anthropic_chat_completion(
            credential,
            messages=messages,
            temperature=temperature,
            top_p=top_p,
            max_tokens=max_tokens,
            stop=stop,
        )

    if credential.provider_type not in OPENAI_COMPATIBLE_PROVIDERS:
        raise HTTPException(status_code=422, detail=f"Unsupported inference provider_type: {credential.provider_type}")

    body: dict[str, Any] = {
        "model": credential.upstream_model,
        "messages": _serialize_chat_messages(messages),
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

    response = httpx.post(
        f"{credential.base_url}/chat/completions",
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
    if credential.provider_type not in OPENAI_COMPATIBLE_PROVIDERS:
        raise HTTPException(status_code=422, detail=f"Embeddings unsupported for provider_type: {credential.provider_type}")

    body: dict[str, Any] = {
        "model": credential.upstream_model,
        "input": inputs if len(inputs) > 1 else (inputs[0] if inputs else ""),
    }
    if dimensions is not None:
        body["dimensions"] = dimensions

    response = httpx.post(
        f"{credential.base_url}/embeddings",
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


def invoke_responses_create(
    credential: ResolvedInferenceCredential,
    *,
    request_body: dict[str, Any],
) -> ResponsesInferenceResult:
    if credential.provider_type not in OPENAI_COMPATIBLE_PROVIDERS:
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
    if credential.provider_type not in OPENAI_COMPATIBLE_PROVIDERS:
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
