"""Trending frontier model pack for the governed supported-model catalog.

Operators register models under Providers → Models. This pack upserts a curated
2026-oriented set so gateway/UI dropdowns include current major families without
hand-entering each ID. Existing rows are left intact (display/status refreshed
only when explicitly overwrite=True).

Cloud hyperscaler packs (Bedrock / Azure / GCP) live in cloud_model_catalog.py and
are selected via the same seed endpoint `packs` field.
"""

from __future__ import annotations

from typing import Any, Sequence

from sqlalchemy.orm import Session

from app.services.cloud_model_catalog import (
    CloudModelSpec,
    resolve_pack_specs,
    seed_model_catalog_specs,
)

# Curated mid-2026 frontier / value pack. IDs follow common public API naming;
# operators can edit or disable any row after seed.
TRENDING_MODEL_PACK: tuple[CloudModelSpec, ...] = (
    # OpenAI
    CloudModelSpec("openai", "gpt-5.5", "GPT-5.5", 272000, "Frontier general-purpose OpenAI chat/agents", "Default frontier OpenAI"),
    CloudModelSpec("openai", "gpt-5.5-mini", "GPT-5.5 Mini", 128000, "Cost-efficient GPT-5.5 tier", "High-volume OpenAI"),
    CloudModelSpec("openai", "gpt-5", "GPT-5", 128000, "GPT-5 family chat", "OpenAI GPT-5"),
    CloudModelSpec("openai", "gpt-4.1", "GPT-4.1", 128000, "Strong GPT-4.1 general model", "Stable OpenAI"),
    CloudModelSpec("openai", "gpt-4o", "GPT-4o", 128000, "Multimodal GPT-4o", "Broad OpenAI default"),
    CloudModelSpec("openai", "gpt-4o-mini", "GPT-4o Mini", 128000, "Fast low-cost OpenAI", "Dev/playground default"),
    CloudModelSpec("openai", "o3", "o3", 200000, "OpenAI reasoning (o-series)", "Hard reasoning"),
    CloudModelSpec("openai", "o3-mini", "o3 Mini", 200000, "Faster o-series reasoning", "Balanced reasoning"),
    CloudModelSpec("openai", "o4-mini", "o4 Mini", 200000, "Latest compact o-series", "Compact reasoning"),
    CloudModelSpec("openai", "text-embedding-3-large", "Embedding 3 Large", 8191, "OpenAI embeddings", "RAG / memory"),
    CloudModelSpec("openai", "text-embedding-3-small", "Embedding 3 Small", 8191, "OpenAI embeddings (compact)", "Cost-sensitive RAG"),
    # Anthropic
    CloudModelSpec("anthropic", "claude-opus-4-8", "Claude Opus 4.8", 200000, "Anthropic frontier Opus", "Hard coding / agents"),
    CloudModelSpec("anthropic", "claude-sonnet-5", "Claude Sonnet 5", 1000000, "Anthropic balanced Sonnet 5", "Best-value Anthropic"),
    CloudModelSpec("anthropic", "claude-sonnet-4-5", "Claude Sonnet 4.5", 200000, "Anthropic Sonnet 4.5", "Coding / writing"),
    CloudModelSpec("anthropic", "claude-haiku-4-5", "Claude Haiku 4.5", 200000, "Fast Anthropic Haiku", "High throughput"),
    # Google Gemini (OpenAI-compatible Gemini API)
    CloudModelSpec("google", "gemini-3.1-pro", "Gemini 3.1 Pro", 1000000, "Google frontier multimodal", "Reasoning / multimodal"),
    CloudModelSpec("google", "gemini-3.5-flash", "Gemini 3.5 Flash", 1000000, "Google fast multimodal", "Price/performance"),
    CloudModelSpec("google", "gemini-2.5-pro", "Gemini 2.5 Pro", 1000000, "Google Gemini 2.5 Pro", "Stable Gemini"),
    CloudModelSpec("google", "gemini-2.5-flash", "Gemini 2.5 Flash", 1000000, "Google Gemini 2.5 Flash", "Fast Gemini"),
    # xAI
    CloudModelSpec("xai", "grok-4", "Grok 4", 1000000, "xAI Grok 4", "Real-time / general"),
    CloudModelSpec("xai", "grok-4.5", "Grok 4.5", 1000000, "xAI Grok 4.5", "Frontier Grok"),
    CloudModelSpec("xai", "grok-3", "Grok 3", 131072, "xAI Grok 3", "Stable Grok"),
    # DeepSeek
    CloudModelSpec("deepseek", "deepseek-chat", "DeepSeek Chat", 128000, "DeepSeek chat (V-series API)", "Cost-efficient chat"),
    CloudModelSpec("deepseek", "deepseek-reasoner", "DeepSeek Reasoner", 128000, "DeepSeek reasoning mode", "Budget reasoning"),
    CloudModelSpec("deepseek", "deepseek-v4-pro", "DeepSeek V4 Pro", 1000000, "DeepSeek V4 Pro long-context", "Open-weight frontier value"),
    CloudModelSpec("deepseek", "deepseek-v4-flash", "DeepSeek V4 Flash", 1000000, "DeepSeek V4 Flash", "High-volume DeepSeek"),
    # Groq / Mistral / Cohere / Together / Fireworks / Perplexity
    CloudModelSpec("groq", "llama-3.3-70b-versatile", "Llama 3.3 70B (Groq)", 128000, "Groq-hosted Llama 3.3", "Low-latency open weights"),
    CloudModelSpec("groq", "openai/gpt-oss-120b", "GPT-OSS 120B (Groq)", 128000, "Groq open model tier", "Groq throughput"),
    CloudModelSpec("mistral", "mistral-large-latest", "Mistral Large", 128000, "Mistral flagship", "EU / Mistral stack"),
    CloudModelSpec("mistral", "codestral-latest", "Codestral", 256000, "Mistral coding model", "Code generation"),
    CloudModelSpec("cohere", "command-r-plus", "Command R+", 128000, "Cohere Command R+", "RAG / enterprise"),
    CloudModelSpec("cohere", "command-a-03-2025", "Command A", 256000, "Cohere Command A", "Latest Cohere chat"),
    CloudModelSpec("together", "meta-llama/Llama-4-Scout-17B-16E-Instruct", "Llama 4 Scout (Together)", 10000000, "Together-hosted Llama 4 Scout", "Open-weight long context"),
    CloudModelSpec("fireworks", "accounts/fireworks/models/llama-v3p3-70b-instruct", "Llama 3.3 70B (Fireworks)", 128000, "Fireworks-hosted Llama", "Fireworks throughput"),
    CloudModelSpec("perplexity", "sonar-pro", "Sonar Pro", 200000, "Perplexity Sonar Pro", "Search-grounded answers"),
    CloudModelSpec("perplexity", "sonar", "Sonar", 128000, "Perplexity Sonar", "Fast search answers"),
    # Azure OpenAI (same family IDs; binding selects Azure endpoint)
    CloudModelSpec("azure-openai", "gpt-4o", "Azure GPT-4o", 128000, "Azure OpenAI GPT-4o deployment name", "Azure enterprise"),
    CloudModelSpec("azure-openai", "gpt-4o-mini", "Azure GPT-4o Mini", 128000, "Azure OpenAI GPT-4o Mini", "Azure cost tier"),
    CloudModelSpec("azure-openai", "gpt-5", "Azure GPT-5", 128000, "Azure OpenAI GPT-5 deployment", "Azure frontier"),
)


def seed_trending_model_catalog(
    db: Session,
    *,
    actor_id: str,
    overwrite: bool = False,
    auto_approve: bool = True,
    packs: Sequence[str] | None = None,
) -> dict[str, Any]:
    requested = list(packs) if packs is not None else ["trending"]
    specs = resolve_pack_specs(requested, trending_specs=TRENDING_MODEL_PACK)
    return seed_model_catalog_specs(
        db,
        specs,
        actor_id=actor_id,
        overwrite=overwrite,
        auto_approve=auto_approve,
        packs_applied=requested if "all" not in [str(p).lower() for p in requested] else ["trending", "bedrock", "azure", "gcp"],
    )
