"""Cloud hyperscaler model packs (AWS Bedrock, Azure OpenAI, GCP Gemini/Vertex).

These packs intentionally cover the broadly published foundation / deployment IDs
operators expect mid-2026 — not every private fine-tune or regional SKU. Operators
can still register additional IDs manually in Providers → Models.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Optional, Sequence
from uuid import uuid4

from sqlalchemy.orm import Session

from app.models import SupportedModelCatalogEntry, SupportedModelCatalogRevision


@dataclass(frozen=True)
class CloudModelSpec:
    provider_type: str
    model_name: str
    display_name: str
    context_window_tokens: int = 128000
    description: str = ""
    recommendation_rationale: str = ""
    status: str = "active"


def _m(
    provider: str,
    model_id: str,
    display: str,
    ctx: int = 128000,
    description: str = "",
    rationale: str = "",
) -> CloudModelSpec:
    return CloudModelSpec(provider, model_id, display, ctx, description, rationale or description)


# --- AWS Bedrock foundation + common inference-profile style IDs ---
BEDROCK_MODEL_PACK: tuple[CloudModelSpec, ...] = (
    # Amazon Nova
    _m("aws", "amazon.nova-premier-v1:0", "Amazon Nova Premier", 1000000, "Bedrock Nova Premier", "AWS frontier multimodal"),
    _m("aws", "amazon.nova-pro-v1:0", "Amazon Nova Pro", 300000, "Bedrock Nova Pro", "AWS balanced multimodal"),
    _m("aws", "amazon.nova-lite-v1:0", "Amazon Nova Lite", 300000, "Bedrock Nova Lite", "AWS fast multimodal"),
    _m("aws", "amazon.nova-micro-v1:0", "Amazon Nova Micro", 128000, "Bedrock Nova Micro", "AWS lowest-latency text"),
    _m("aws", "amazon.titan-text-premier-v1:0", "Titan Text Premier", 32000, "Amazon Titan Text Premier", "AWS Titan text"),
    _m("aws", "amazon.titan-text-express-v1", "Titan Text Express", 8000, "Amazon Titan Text Express", "AWS Titan express"),
    _m("aws", "amazon.titan-embed-text-v2:0", "Titan Embeddings V2", 8192, "Amazon Titan Embeddings V2", "AWS embeddings"),
    _m("aws", "amazon.titan-image-generator-v2:0", "Titan Image Generator V2", 1024, "Amazon Titan Image V2", "AWS image gen"),
    # Anthropic on Bedrock
    _m("aws", "anthropic.claude-opus-4-20250514-v1:0", "Claude Opus 4 (Bedrock)", 200000, "Anthropic Opus 4 on Bedrock", "Hard agents via AWS"),
    _m("aws", "anthropic.claude-sonnet-4-20250514-v1:0", "Claude Sonnet 4 (Bedrock)", 200000, "Anthropic Sonnet 4 on Bedrock", "Best-value Claude on AWS"),
    _m("aws", "anthropic.claude-3-7-sonnet-20250219-v1:0", "Claude 3.7 Sonnet (Bedrock)", 200000, "Claude 3.7 Sonnet on Bedrock", "Claude 3.7 via AWS"),
    _m("aws", "anthropic.claude-3-5-sonnet-20241022-v2:0", "Claude 3.5 Sonnet v2 (Bedrock)", 200000, "Claude 3.5 Sonnet v2", "Stable Claude on AWS"),
    _m("aws", "anthropic.claude-3-5-haiku-20241022-v1:0", "Claude 3.5 Haiku (Bedrock)", 200000, "Claude 3.5 Haiku on Bedrock", "Fast Claude on AWS"),
    _m("aws", "anthropic.claude-3-haiku-20240307-v1:0", "Claude 3 Haiku (Bedrock)", 200000, "Claude 3 Haiku on Bedrock", "Legacy fast Claude"),
    _m("aws", "us.anthropic.claude-sonnet-4-20250514-v1:0", "Claude Sonnet 4 (US profile)", 200000, "US inference profile Sonnet 4", "Cross-region US profile"),
    _m("aws", "us.anthropic.claude-opus-4-20250514-v1:0", "Claude Opus 4 (US profile)", 200000, "US inference profile Opus 4", "Cross-region US profile"),
    _m("aws", "eu.anthropic.claude-sonnet-4-20250514-v1:0", "Claude Sonnet 4 (EU profile)", 200000, "EU inference profile Sonnet 4", "Cross-region EU profile"),
    # Meta Llama on Bedrock
    _m("aws", "meta.llama3-3-70b-instruct-v1:0", "Llama 3.3 70B (Bedrock)", 128000, "Meta Llama 3.3 70B Instruct", "Open-weight on AWS"),
    _m("aws", "meta.llama3-2-90b-instruct-v1:0", "Llama 3.2 90B (Bedrock)", 128000, "Meta Llama 3.2 90B Instruct", "Vision-capable Llama"),
    _m("aws", "meta.llama3-2-11b-instruct-v1:0", "Llama 3.2 11B (Bedrock)", 128000, "Meta Llama 3.2 11B Instruct", "Compact multimodal Llama"),
    _m("aws", "meta.llama3-2-3b-instruct-v1:0", "Llama 3.2 3B (Bedrock)", 128000, "Meta Llama 3.2 3B Instruct", "Edge/small Llama"),
    _m("aws", "meta.llama3-2-1b-instruct-v1:0", "Llama 3.2 1B (Bedrock)", 128000, "Meta Llama 3.2 1B Instruct", "Tiny Llama"),
    _m("aws", "meta.llama3-1-405b-instruct-v1:0", "Llama 3.1 405B (Bedrock)", 128000, "Meta Llama 3.1 405B Instruct", "Largest Llama on AWS"),
    _m("aws", "meta.llama3-1-70b-instruct-v1:0", "Llama 3.1 70B (Bedrock)", 128000, "Meta Llama 3.1 70B Instruct", "Llama 3.1 mid"),
    _m("aws", "meta.llama3-1-8b-instruct-v1:0", "Llama 3.1 8B (Bedrock)", 128000, "Meta Llama 3.1 8B Instruct", "Llama 3.1 small"),
    _m("aws", "meta.llama4-scout-17b-instruct-v1:0", "Llama 4 Scout (Bedrock)", 10000000, "Meta Llama 4 Scout on Bedrock", "Long-context Llama 4"),
    _m("aws", "meta.llama4-maverick-17b-instruct-v1:0", "Llama 4 Maverick (Bedrock)", 1000000, "Meta Llama 4 Maverick on Bedrock", "Llama 4 multimodal"),
    # Mistral on Bedrock
    _m("aws", "mistral.mistral-large-2407-v1:0", "Mistral Large 24.07 (Bedrock)", 128000, "Mistral Large on Bedrock", "EU-friendly large"),
    _m("aws", "mistral.mistral-small-2402-v1:0", "Mistral Small (Bedrock)", 32000, "Mistral Small on Bedrock", "Cost-efficient Mistral"),
    _m("aws", "mistral.mixtral-8x7b-instruct-v0:1", "Mixtral 8x7B (Bedrock)", 32000, "Mixtral 8x7B Instruct", "MoE open model"),
    _m("aws", "mistral.pixtral-large-2502-v1:0", "Pixtral Large (Bedrock)", 128000, "Mistral Pixtral Large", "Vision Mistral"),
    # Cohere on Bedrock
    _m("aws", "cohere.command-r-plus-v1:0", "Command R+ (Bedrock)", 128000, "Cohere Command R+ on Bedrock", "RAG on AWS"),
    _m("aws", "cohere.command-r-v1:0", "Command R (Bedrock)", 128000, "Cohere Command R on Bedrock", "Cohere chat"),
    _m("aws", "cohere.command-a-03-2025-v1:0", "Command A (Bedrock)", 256000, "Cohere Command A on Bedrock", "Latest Cohere on AWS"),
    _m("aws", "cohere.embed-english-v3", "Cohere Embed English v3", 512, "Cohere Embed English v3", "AWS Cohere embeddings"),
    _m("aws", "cohere.embed-multilingual-v3", "Cohere Embed Multilingual v3", 512, "Cohere Embed Multilingual v3", "Multilingual embeddings"),
    # AI21 / DeepSeek / other
    _m("aws", "ai21.jamba-1-5-large-v1:0", "Jamba 1.5 Large (Bedrock)", 256000, "AI21 Jamba 1.5 Large", "Long-context Jamba"),
    _m("aws", "ai21.jamba-1-5-mini-v1:0", "Jamba 1.5 Mini (Bedrock)", 256000, "AI21 Jamba 1.5 Mini", "Compact Jamba"),
    _m("aws", "deepseek.r1-v1:0", "DeepSeek R1 (Bedrock)", 128000, "DeepSeek R1 on Bedrock", "Reasoning via AWS"),
    _m("aws", "deepseek.v3-v1:0", "DeepSeek V3 (Bedrock)", 128000, "DeepSeek V3 on Bedrock", "Chat via AWS"),
    _m("aws", "openai.gpt-oss-120b-1:0", "GPT-OSS 120B (Bedrock)", 128000, "OpenAI GPT-OSS on Bedrock", "Open-weight via AWS"),
    _m("aws", "openai.gpt-oss-20b-1:0", "GPT-OSS 20B (Bedrock)", 128000, "OpenAI GPT-OSS 20B on Bedrock", "Compact open-weight"),
    _m("aws", "qwen.qwen3-32b-v1:0", "Qwen3 32B (Bedrock)", 128000, "Qwen3 32B on Bedrock", "Qwen on AWS"),
    _m("aws", "writer.palmyra-x5-v1:0", "Palmyra X5 (Bedrock)", 128000, "Writer Palmyra X5", "Enterprise Writer model"),
)

# --- Azure OpenAI / Azure AI Foundry deployment-style IDs ---
AZURE_MODEL_PACK: tuple[CloudModelSpec, ...] = (
    _m("azure-openai", "gpt-5.5", "Azure GPT-5.5", 272000, "Azure OpenAI GPT-5.5 deployment", "Azure frontier"),
    _m("azure-openai", "gpt-5.5-mini", "Azure GPT-5.5 Mini", 128000, "Azure OpenAI GPT-5.5 Mini", "Azure cost frontier"),
    _m("azure-openai", "gpt-5", "Azure GPT-5", 128000, "Azure OpenAI GPT-5 deployment", "Azure GPT-5"),
    _m("azure-openai", "gpt-5-mini", "Azure GPT-5 Mini", 128000, "Azure OpenAI GPT-5 Mini", "Azure GPT-5 mini"),
    _m("azure-openai", "gpt-5-nano", "Azure GPT-5 Nano", 128000, "Azure OpenAI GPT-5 Nano", "Azure ultra-cheap"),
    _m("azure-openai", "gpt-4.1", "Azure GPT-4.1", 128000, "Azure OpenAI GPT-4.1", "Azure GPT-4.1"),
    _m("azure-openai", "gpt-4.1-mini", "Azure GPT-4.1 Mini", 128000, "Azure OpenAI GPT-4.1 Mini", "Azure GPT-4.1 mini"),
    _m("azure-openai", "gpt-4.1-nano", "Azure GPT-4.1 Nano", 128000, "Azure OpenAI GPT-4.1 Nano", "Azure GPT-4.1 nano"),
    _m("azure-openai", "gpt-4o", "Azure GPT-4o", 128000, "Azure OpenAI GPT-4o", "Azure multimodal default"),
    _m("azure-openai", "gpt-4o-mini", "Azure GPT-4o Mini", 128000, "Azure OpenAI GPT-4o Mini", "Azure high-volume"),
    _m("azure-openai", "gpt-4o-2024-11-20", "Azure GPT-4o (2024-11-20)", 128000, "Pinned GPT-4o snapshot", "Pinned Azure GPT-4o"),
    _m("azure-openai", "gpt-4-turbo", "Azure GPT-4 Turbo", 128000, "Azure OpenAI GPT-4 Turbo", "Legacy Azure GPT-4"),
    _m("azure-openai", "gpt-35-turbo", "Azure GPT-3.5 Turbo", 16385, "Azure OpenAI GPT-3.5 Turbo", "Legacy Azure chat"),
    _m("azure-openai", "gpt-35-turbo-16k", "Azure GPT-3.5 Turbo 16k", 16385, "Azure OpenAI GPT-3.5 16k", "Legacy Azure 16k"),
    _m("azure-openai", "o1", "Azure o1", 200000, "Azure OpenAI o1", "Azure reasoning"),
    _m("azure-openai", "o1-mini", "Azure o1 Mini", 128000, "Azure OpenAI o1 Mini", "Azure fast reasoning"),
    _m("azure-openai", "o1-preview", "Azure o1 Preview", 128000, "Azure OpenAI o1 Preview", "Azure o1 preview"),
    _m("azure-openai", "o3", "Azure o3", 200000, "Azure OpenAI o3", "Azure o3 reasoning"),
    _m("azure-openai", "o3-mini", "Azure o3 Mini", 200000, "Azure OpenAI o3 Mini", "Azure o3 mini"),
    _m("azure-openai", "o4-mini", "Azure o4 Mini", 200000, "Azure OpenAI o4 Mini", "Azure o4 mini"),
    _m("azure-openai", "text-embedding-3-large", "Azure Embedding 3 Large", 8191, "Azure text-embedding-3-large", "Azure RAG large"),
    _m("azure-openai", "text-embedding-3-small", "Azure Embedding 3 Small", 8191, "Azure text-embedding-3-small", "Azure RAG small"),
    _m("azure-openai", "text-embedding-ada-002", "Azure Ada Embedding", 8191, "Azure text-embedding-ada-002", "Legacy Azure embed"),
    _m("azure-openai", "whisper-1", "Azure Whisper", 1, "Azure Whisper transcription", "Azure speech-to-text"),
    _m("azure-openai", "tts-1", "Azure TTS", 1, "Azure text-to-speech", "Azure TTS"),
    _m("azure-openai", "tts-1-hd", "Azure TTS HD", 1, "Azure text-to-speech HD", "Azure TTS HD"),
    _m("azure-openai", "dall-e-3", "Azure DALL·E 3", 1, "Azure DALL·E 3 image gen", "Azure images"),
    _m("azure-openai", "gpt-realtime", "Azure GPT Realtime", 128000, "Azure realtime voice model", "Azure realtime"),
    _m("azure-openai", "gpt-4o-realtime-preview", "Azure GPT-4o Realtime", 128000, "Azure GPT-4o realtime preview", "Azure realtime preview"),
    # Azure AI Foundry / Model Catalog aliases commonly used as deployment names
    _m("azure-openai", "DeepSeek-R1", "Azure DeepSeek R1", 128000, "Azure AI Foundry DeepSeek R1", "Foundry DeepSeek"),
    _m("azure-openai", "DeepSeek-V3", "Azure DeepSeek V3", 128000, "Azure AI Foundry DeepSeek V3", "Foundry DeepSeek chat"),
    _m("azure-openai", "Llama-3.3-70B-Instruct", "Azure Llama 3.3 70B", 128000, "Azure AI Foundry Llama 3.3", "Foundry Llama"),
    _m("azure-openai", "Mistral-Large-2411", "Azure Mistral Large", 128000, "Azure AI Foundry Mistral Large", "Foundry Mistral"),
    _m("azure-openai", "Cohere-command-r-plus", "Azure Command R+", 128000, "Azure AI Foundry Command R+", "Foundry Cohere"),
    _m("azure-openai", "Phi-4", "Azure Phi-4", 128000, "Azure AI Foundry Phi-4", "Foundry Phi"),
    _m("azure-openai", "Phi-4-mini", "Azure Phi-4 Mini", 128000, "Azure AI Foundry Phi-4 Mini", "Foundry Phi mini"),
)

# --- Google Gemini API + Vertex AI model IDs ---
GCP_MODEL_PACK: tuple[CloudModelSpec, ...] = (
    # Gemini API / Google AI Studio (provider google)
    _m("google", "gemini-3.1-pro", "Gemini 3.1 Pro", 1000000, "Google Gemini 3.1 Pro", "GCP frontier"),
    _m("google", "gemini-3.1-pro-preview", "Gemini 3.1 Pro Preview", 1000000, "Google Gemini 3.1 Pro preview", "GCP preview frontier"),
    _m("google", "gemini-3.5-flash", "Gemini 3.5 Flash", 1000000, "Google Gemini 3.5 Flash", "GCP price/perf"),
    _m("google", "gemini-3-flash", "Gemini 3 Flash", 1000000, "Google Gemini 3 Flash", "GCP fast Gemini 3"),
    _m("google", "gemini-2.5-pro", "Gemini 2.5 Pro", 1000000, "Google Gemini 2.5 Pro", "Stable Gemini Pro"),
    _m("google", "gemini-2.5-flash", "Gemini 2.5 Flash", 1000000, "Google Gemini 2.5 Flash", "Stable Gemini Flash"),
    _m("google", "gemini-2.5-flash-lite", "Gemini 2.5 Flash-Lite", 1000000, "Google Gemini 2.5 Flash-Lite", "Ultra-cheap Gemini"),
    _m("google", "gemini-2.0-flash", "Gemini 2.0 Flash", 1000000, "Google Gemini 2.0 Flash", "Gemini 2.0 Flash"),
    _m("google", "gemini-2.0-flash-lite", "Gemini 2.0 Flash-Lite", 1000000, "Google Gemini 2.0 Flash-Lite", "Gemini 2.0 lite"),
    _m("google", "gemini-1.5-pro", "Gemini 1.5 Pro", 2000000, "Google Gemini 1.5 Pro", "Legacy long-context"),
    _m("google", "gemini-1.5-flash", "Gemini 1.5 Flash", 1000000, "Google Gemini 1.5 Flash", "Legacy Flash"),
    _m("google", "gemini-1.5-flash-8b", "Gemini 1.5 Flash-8B", 1000000, "Google Gemini 1.5 Flash-8B", "Legacy small Flash"),
    _m("google", "gemini-flash-latest", "Gemini Flash Latest", 1000000, "Google Gemini Flash alias", "Always-latest Flash"),
    _m("google", "gemini-pro-latest", "Gemini Pro Latest", 1000000, "Google Gemini Pro alias", "Always-latest Pro"),
    _m("google", "text-embedding-004", "Google Text Embedding 004", 2048, "Google text-embedding-004", "Gemini API embeddings"),
    _m("google", "gemini-embedding-001", "Gemini Embedding 001", 8192, "Google gemini-embedding-001", "Latest Gemini embeddings"),
    _m("google", "imagen-3.0-generate-002", "Imagen 3", 1, "Google Imagen 3", "Image generation"),
    _m("google", "imagen-4.0-generate-001", "Imagen 4", 1, "Google Imagen 4", "Latest Imagen"),
    # Vertex AI (provider vertex) — publisher model resource IDs / short names
    _m("vertex", "gemini-3.1-pro", "Vertex Gemini 3.1 Pro", 1000000, "Vertex AI Gemini 3.1 Pro", "Vertex frontier"),
    _m("vertex", "gemini-3.5-flash", "Vertex Gemini 3.5 Flash", 1000000, "Vertex AI Gemini 3.5 Flash", "Vertex price/perf"),
    _m("vertex", "gemini-2.5-pro", "Vertex Gemini 2.5 Pro", 1000000, "Vertex AI Gemini 2.5 Pro", "Vertex stable Pro"),
    _m("vertex", "gemini-2.5-flash", "Vertex Gemini 2.5 Flash", 1000000, "Vertex AI Gemini 2.5 Flash", "Vertex stable Flash"),
    _m("vertex", "gemini-2.5-flash-lite", "Vertex Gemini 2.5 Flash-Lite", 1000000, "Vertex AI Gemini 2.5 Flash-Lite", "Vertex cheap Flash"),
    _m("vertex", "gemini-2.0-flash-001", "Vertex Gemini 2.0 Flash", 1000000, "Vertex AI Gemini 2.0 Flash", "Vertex Gemini 2.0"),
    _m("vertex", "gemini-1.5-pro-002", "Vertex Gemini 1.5 Pro", 2000000, "Vertex AI Gemini 1.5 Pro", "Vertex legacy Pro"),
    _m("vertex", "gemini-1.5-flash-002", "Vertex Gemini 1.5 Flash", 1000000, "Vertex AI Gemini 1.5 Flash", "Vertex legacy Flash"),
    _m("vertex", "text-embedding-005", "Vertex Text Embedding 005", 2048, "Vertex text-embedding-005", "Vertex embeddings"),
    _m("vertex", "text-multilingual-embedding-002", "Vertex Multilingual Embedding", 2048, "Vertex multilingual embeddings", "Vertex multi-lang RAG"),
    _m("vertex", "textembedding-gecko@003", "Vertex Gecko Embedding 003", 3072, "Vertex gecko@003", "Legacy Vertex embed"),
    _m("vertex", "imagen-3.0-generate-002", "Vertex Imagen 3", 1, "Vertex Imagen 3", "Vertex image gen"),
    _m("vertex", "imagen-4.0-generate-001", "Vertex Imagen 4", 1, "Vertex Imagen 4", "Vertex latest Imagen"),
    _m("vertex", "publishers/google/models/gemini-2.5-pro", "Vertex publisher Gemini 2.5 Pro", 1000000, "Full publisher model path", "Publisher path Pro"),
    _m("vertex", "publishers/google/models/gemini-2.5-flash", "Vertex publisher Gemini 2.5 Flash", 1000000, "Full publisher model path", "Publisher path Flash"),
    _m("vertex", "publishers/meta/models/llama-3.3-70b-instruct", "Vertex Llama 3.3 70B", 128000, "Vertex Model Garden Llama", "Model Garden Llama"),
    _m("vertex", "publishers/mistralai/models/mistral-large-2411", "Vertex Mistral Large", 128000, "Vertex Model Garden Mistral", "Model Garden Mistral"),
    _m("vertex", "publishers/anthropic/models/claude-sonnet-4", "Vertex Claude Sonnet 4", 200000, "Vertex Model Garden Claude", "Model Garden Claude"),
    _m("vertex", "publishers/anthropic/models/claude-opus-4", "Vertex Claude Opus 4", 200000, "Vertex Model Garden Claude Opus", "Model Garden Opus"),
    _m("vertex", "publishers/deepseek-ai/models/deepseek-r1-0528", "Vertex DeepSeek R1", 128000, "Vertex Model Garden DeepSeek", "Model Garden DeepSeek"),
)

CLOUD_PACKS: dict[str, tuple[CloudModelSpec, ...]] = {
    "bedrock": BEDROCK_MODEL_PACK,
    "aws": BEDROCK_MODEL_PACK,
    "azure": AZURE_MODEL_PACK,
    "azure-openai": AZURE_MODEL_PACK,
    "gcp": GCP_MODEL_PACK,
    "google": GCP_MODEL_PACK,
    "vertex": tuple(spec for spec in GCP_MODEL_PACK if spec.provider_type == "vertex"),
}

VALID_SEED_PACKS = frozenset({"trending", "bedrock", "azure", "gcp", "all"})


def resolve_pack_specs(packs: Sequence[str], *, trending_specs: Iterable[Any] = ()) -> list[CloudModelSpec]:
    requested = [str(p or "").strip().lower() for p in packs if str(p or "").strip()]
    if not requested:
        requested = ["trending"]
    if "all" in requested:
        requested = ["trending", "bedrock", "azure", "gcp"]

    resolved: list[CloudModelSpec] = []
    seen: set[tuple[str, str]] = set()

    def _add(specs: Iterable[Any]) -> None:
        for spec in specs:
            provider = str(getattr(spec, "provider_type", "")).strip().lower()
            model = str(getattr(spec, "model_name", "")).strip()
            key = (provider, model)
            if not provider or not model or key in seen:
                continue
            seen.add(key)
            if isinstance(spec, CloudModelSpec):
                resolved.append(spec)
            else:
                resolved.append(
                    CloudModelSpec(
                        provider_type=provider,
                        model_name=model,
                        display_name=str(getattr(spec, "display_name", model)),
                        context_window_tokens=int(getattr(spec, "context_window_tokens", 128000) or 128000),
                        description=str(getattr(spec, "description", "") or ""),
                        recommendation_rationale=str(getattr(spec, "recommendation_rationale", "") or ""),
                        status=str(getattr(spec, "status", "active") or "active"),
                    )
                )

    for pack in requested:
        if pack == "trending":
            _add(trending_specs)
        elif pack in CLOUD_PACKS:
            _add(CLOUD_PACKS[pack])
        else:
            raise ValueError(f"Unknown model pack: {pack}")
    return resolved


def seed_model_catalog_specs(
    db: Session,
    specs: Sequence[CloudModelSpec],
    *,
    actor_id: str,
    overwrite: bool = False,
    auto_approve: bool = True,
    packs_applied: Optional[Sequence[str]] = None,
) -> dict[str, Any]:
    created = 0
    updated = 0
    skipped = 0
    now = datetime.utcnow()
    for spec in specs:
        row = (
            db.query(SupportedModelCatalogEntry)
            .filter_by(provider_type=spec.provider_type, model_name=spec.model_name)
            .first()
        )
        if row and not overwrite:
            skipped += 1
            continue
        if row:
            row.display_name = spec.display_name
            row.context_window_tokens = max(0, int(spec.context_window_tokens or 0))
            row.description = spec.description
            row.recommendation_rationale = spec.recommendation_rationale
            row.status = spec.status
            if auto_approve:
                row.approval_status = "approved"
                row.approved_by = actor_id
                row.approved_at = now
            row.metadata_version = int(row.metadata_version or 1) + 1
            row.updated_by = actor_id
            row.updated_at = now
            updated += 1
            change_type = "update"
        else:
            row = SupportedModelCatalogEntry(
                supported_model_id=str(uuid4()),
                provider_type=spec.provider_type,
                model_name=spec.model_name,
                display_name=spec.display_name,
                context_window_tokens=max(0, int(spec.context_window_tokens or 0)),
                status=spec.status,
                description=spec.description,
                recommendation_rationale=spec.recommendation_rationale,
                approval_status="approved" if auto_approve else "pending",
                approved_by=actor_id if auto_approve else None,
                approved_at=now if auto_approve else None,
                metadata_version=1,
                updated_by=actor_id,
            )
            db.add(row)
            created += 1
            change_type = "create"
        db.add(
            SupportedModelCatalogRevision(
                revision_id=f"smr-{uuid4().hex[:16]}",
                supported_model_id=row.supported_model_id,
                metadata_version=int(row.metadata_version or 1),
                change_type=change_type,
                provider_type=row.provider_type,
                model_name=row.model_name,
                display_name=row.display_name,
                context_window_tokens=row.context_window_tokens,
                status=row.status,
                description=row.description or "",
                recommendation_rationale=row.recommendation_rationale or "",
                approval_status=row.approval_status,
                approval_ticket_ref=row.approval_ticket_ref,
                approved_by=row.approved_by,
                approved_at=row.approved_at,
                changed_by=actor_id,
            )
        )
    return {
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "pack_size": len(specs),
        "overwrite": overwrite,
        "auto_approve": auto_approve,
        "packs": list(packs_applied or []),
    }
