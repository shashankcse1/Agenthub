"""Heuristics for AI-agent-scoped discovery (agents, skills, LLM integrations)."""

from __future__ import annotations

from typing import Iterable

from app.models import Agent, AgentConfig, ModuleDefinition, ProviderCredentialBinding

# Text signals that a resource is agent / LLM related.
AGENT_TEXT_KEYWORDS: tuple[str, ...] = (
    "agent",
    "agents",
    "ai-agent",
    "ai_agent",
    "llm",
    "gpt",
    "copilot",
    "assistant",
    "chatbot",
    "bot",
    "langchain",
    "langgraph",
    "langsmith",
    "skill",
    "skills",
    "mcp",
    "tool-use",
    "autogen",
    "crewai",
    "bedrock",
    "vertex",
    "openai",
    "anthropic",
    "embedding",
    "rag",
    "prompt",
    "inference",
    "model-serving",
    "huggingface",
    "nim",
    "groq",
    "mistral",
    "gemini",
)

AGENT_MODULE_TYPES: frozenset[str] = frozenset(
    {
        "skill",
        "ai_skill",
        "agent",
        "tool",
        "mcp_server",
        "prompt_pack",
    }
)

AGENT_INTEGRATION_PROVIDERS: frozenset[str] = frozenset(
    {
        "cursor",
        "github",
        "gitlab",
        "bitbucket",
        "openai",
        "anthropic",
        "aws",
        "azure",
        "gcp",
        "google",
        "oracle",
        "oci",
        "coreweave",
        "nvidia",
        "ibm",
        "snowflake",
        "mongodb",
        "databricks",
    }
)

AGENT_CONSUMER_TYPES: frozenset[str] = frozenset({"agent", "gateway", "playground", "route"})


def is_agent_related_text(text: str, extra_keywords: Iterable[str] = ()) -> bool:
    lowered = str(text or "").lower()
    if not lowered.strip():
        return False
    keywords = (*AGENT_TEXT_KEYWORDS, *(k.lower() for k in extra_keywords))
    return any(keyword in lowered for keyword in keywords)


def is_agent_module(module: ModuleDefinition) -> bool:
    provider = str(module.integration_provider or "").strip().lower()
    if provider in AGENT_INTEGRATION_PROVIDERS:
        return True
    module_type = str(module.module_type or "").strip().lower()
    if module_type in AGENT_MODULE_TYPES:
        return True
    haystack = " ".join(
        [
            module.module_name,
            module.module_type,
            module.integration_reference,
            module.provenance_ref,
            module.owner_team,
        ]
    )
    return is_agent_related_text(haystack)


def is_agent_config(config: AgentConfig) -> bool:
    # Registered runtime configs are in scope for governed agent inventory.
    return bool(str(config.agent_key or "").strip())


KNOWN_GOVERNED_AGENT_TYPES: frozenset[str] = frozenset(
    {
        "assistant",
        "automation",
        "orchestrator",
        "chatbot",
        "aws",
        "azure",
        "gcp",
        "onprem",
        "hybrid",
    }
)


def is_governed_agent(agent: Agent) -> bool:
    agent_type = str(agent.agent_type or "").strip().lower()
    if agent_type in KNOWN_GOVERNED_AGENT_TYPES:
        return True
    if agent_type == "other":
        haystack = " ".join([agent.name, agent.description, agent.agent_type])
        return is_agent_related_text(haystack)
    return is_agent_related_text(" ".join([agent.name, agent.description, agent.agent_type]))


def is_agent_credential_binding(binding: ProviderCredentialBinding) -> bool:
    consumer_type = str(binding.consumer_type or "").strip().lower()
    if consumer_type in AGENT_CONSUMER_TYPES:
        return True
    haystack = " ".join([binding.binding_name, binding.consumer_type, binding.consumer_key])
    return is_agent_related_text(haystack)


# AWS resource signals for agent/AI integrations (S3 buckets, EC2 inference hosts).
AWS_AGENT_INSTANCE_PREFIXES: tuple[str, ...] = ("ml.", "trn", "inf", "g4", "g5", "p3", "p4")
AWS_AGENT_S3_KEYWORDS: tuple[str, ...] = (
    "model",
    "models",
    "embedding",
    "embeddings",
    "vector",
    "vectors",
    "rag",
    "dataset",
    "training",
    "inference",
    "prompt",
    "llm",
    "agent",
    "agents",
    "bedrock",
    "fine-tune",
    "finetune",
    "checkpoint",
    "huggingface",
    "langchain",
    "coreweave",
    "watson",
    "sagemaker",
    "einstein",
    "cortex",
    "atlas",
    "vector",
    "genai",
    "oci",
)

# Cross-cloud storage/compute signals for agent integrations.
CLOUD_AGENT_STORAGE_KEYWORDS: tuple[str, ...] = (
    *AWS_AGENT_S3_KEYWORDS,
    "checkpoint",
    "weights",
    "artifact",
    "artifacts",
    "vectorstore",
    "index",
    "genai",
    "watson",
    "cortex",
    "atlas",
)

CLOUD_AGENT_COMPUTE_PREFIXES: tuple[str, ...] = (
    "ml.",
    "trn",
    "inf",
    "g4",
    "g5",
    "p3",
    "p4",
    "nc",
    "nd",
    "nv",
    "a100",
    "h100",
    "gpu",
)

AGENT_SCOPED_STORAGE_SOURCES: frozenset[str] = frozenset(
    {
        "aws_s3",
        "azure_blob_storage",
        "gcp_cloud_storage",
        "oracle_oci_object_storage",
    }
)

AGENT_SCOPED_COMPUTE_SOURCES: frozenset[str] = frozenset(
    {
        "aws_ec2",
        "aws_sagemaker",
        "azure_virtual_machines",
        "gcp_compute_engine",
        "oracle_oci_compute",
        "coreweave_gpu",
    }
)

AGENT_SCOPED_IDENTITY_SOURCES: frozenset[str] = frozenset(
    {
        "aws_iam",
        "azure_managed_identity",
        "gcp_service_accounts",
    }
)


def _tag_text(tags: dict | list | None) -> str:
    if not tags:
        return ""
    if isinstance(tags, dict):
        return " ".join(f"{k} {v}" for k, v in tags.items())
    if isinstance(tags, list):
        parts = []
        for tag in tags:
            if isinstance(tag, dict):
                parts.append(f"{tag.get('Key', '')} {tag.get('Value', '')}")
        return " ".join(parts)
    return str(tags)


def is_agent_ec2_instance(instance: dict) -> bool:
    if not isinstance(instance, dict):
        return False
    tags = instance.get("Tags") or instance.get("TagSet") or []
    tag_map = {}
    if isinstance(tags, list):
        for tag in tags:
            if isinstance(tag, dict):
                key = str(tag.get("Key") or "").strip().lower()
                val = str(tag.get("Value") or "").strip()
                if key:
                    tag_map[key] = val
    name = tag_map.get("name", "")
    profile = instance.get("IamInstanceProfile") or {}
    profile_arn = str(profile.get("Arn") or "")
    instance_type = str(instance.get("InstanceType") or "").lower()
    haystack = " ".join(
        [
            name,
            _tag_text(tag_map),
            instance_type,
            profile_arn,
            str(instance.get("KeyName") or ""),
        ]
    )
    if is_agent_related_text(haystack):
        return True
    if instance_type.startswith(AWS_AGENT_INSTANCE_PREFIXES):
        return True
    return any(prefix in instance_type for prefix in ("g4", "g5", "p3", "p4"))


def is_agent_s3_bucket(name: str, tags: dict | list | None = None) -> bool:
    bucket_name = str(name or "").strip()
    if not bucket_name:
        return False
    if is_agent_related_text(bucket_name, AWS_AGENT_S3_KEYWORDS):
        return True
    return is_agent_related_text(_tag_text(tags), AWS_AGENT_S3_KEYWORDS)


def is_agent_aws_integration_ref(text: str) -> bool:
    lowered = str(text or "").lower()
    if not lowered.strip():
        return False
    if "s3://" in lowered or "arn:aws:s3" in lowered or "arn:aws:ec2" in lowered:
        return is_agent_related_text(lowered, AWS_AGENT_S3_KEYWORDS)
    return is_agent_related_text(lowered)


def is_agent_cloud_storage(name: str, tags: dict | list | None = None) -> bool:
    return is_agent_s3_bucket(name, tags) or is_agent_related_text(
        _tag_text(tags), CLOUD_AGENT_STORAGE_KEYWORDS
    )


def is_agent_cloud_compute(name: str, sku_or_type: str = "", tags: dict | list | None = None) -> bool:
    haystack = " ".join([name, sku_or_type, _tag_text(tags)])
    if is_agent_related_text(haystack, CLOUD_AGENT_COMPUTE_PREFIXES):
        return True
    sku = str(sku_or_type or "").lower()
    return sku.startswith(CLOUD_AGENT_COMPUTE_PREFIXES) or any(p in sku for p in ("gpu", "a100", "h100"))


def is_agent_cloud_identity(name: str, description: str = "") -> bool:
    return is_agent_related_text(" ".join([name, description]))


def is_agent_cloud_integration_ref(source_id: str, text: str) -> bool:
    lowered = str(text or "").lower()
    if not lowered.strip():
        return False
    if source_id in AGENT_SCOPED_STORAGE_SOURCES:
        return is_agent_cloud_storage(lowered) or is_agent_related_text(lowered, CLOUD_AGENT_STORAGE_KEYWORDS)
    if source_id in AGENT_SCOPED_COMPUTE_SOURCES:
        return is_agent_cloud_compute(lowered, lowered, None) or is_agent_aws_integration_ref(text)
    if source_id in AGENT_SCOPED_IDENTITY_SOURCES:
        return is_agent_cloud_identity(lowered)
    return is_agent_related_text(lowered) or is_agent_aws_integration_ref(text)


def is_agent_repo(repo: dict) -> bool:
    if not isinstance(repo, dict):
        return False
    topics = repo.get("topics") or repo.get("tag_list") or repo.get("topics") or []
    topic_text = " ".join(str(t) for t in topics) if isinstance(topics, list) else str(topics)
    haystack = " ".join(
        [
            str(repo.get("full_name") or repo.get("path_with_namespace") or repo.get("name") or ""),
            str(repo.get("description") or ""),
            str(repo.get("name") or ""),
            topic_text,
        ]
    )
    if is_agent_related_text(haystack):
        return True
    # Dev-platform integrations registered in connection config may target a known agent monorepo.
    return bool(str(repo.get("integration_provider") or "").strip())
