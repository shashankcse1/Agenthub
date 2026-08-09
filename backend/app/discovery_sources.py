from dataclasses import dataclass
from typing import Optional

from app.discovery_connection_presets import (
    DISCOVERY_CONNECTION_PRESETS,
    DISCOVERY_PRIORITY_SOURCE_IDS,
    DISCOVERY_WELL_KNOWN_SOURCE_IDS,
)


@dataclass(frozen=True)
class DiscoverySourceDefinition:
    source_id: str
    platform: str
    category: str
    label: str


# Agent-scoped discovery across governed runtime, major cloud AI platforms,
# AI providers, dev platforms, GPU clouds, and agent-ops tooling.
DISCOVERY_SOURCE_CATALOG: tuple[DiscoverySourceDefinition, ...] = (
    # Platform internal
    DiscoverySourceDefinition("runtime_inventory", "agenthub", "platform", "Agent Runtime Inventory"),
    DiscoverySourceDefinition("code_metadata", "agenthub", "platform", "Agent Modules & Skills"),
    DiscoverySourceDefinition("gateway_telemetry", "agenthub", "platform", "Agent Gateway Routes"),
    # AWS
    DiscoverySourceDefinition("aws_bedrock", "aws", "ai_cloud", "AWS Bedrock"),
    DiscoverySourceDefinition("aws_sagemaker", "aws", "ai_cloud", "AWS SageMaker (Agent Models)"),
    DiscoverySourceDefinition("aws_s3", "aws", "ai_cloud", "AWS S3 (Agent Integrations)"),
    DiscoverySourceDefinition("aws_ec2", "aws", "ai_cloud", "AWS EC2 (Agent Workloads)"),
    DiscoverySourceDefinition("aws_iam", "aws", "ai_cloud", "AWS IAM (Agent Roles)"),
    # Azure
    DiscoverySourceDefinition("azure_openai", "azure", "ai_cloud", "Azure OpenAI"),
    DiscoverySourceDefinition("azure_ml", "azure", "ai_cloud", "Azure ML Workspaces"),
    DiscoverySourceDefinition("azure_blob_storage", "azure", "ai_cloud", "Azure Blob (Agent Integrations)"),
    DiscoverySourceDefinition("azure_virtual_machines", "azure", "ai_cloud", "Azure VMs (Agent Workloads)"),
    DiscoverySourceDefinition("azure_managed_identity", "azure", "ai_cloud", "Azure Managed Identity (Agents)"),
    # Google Cloud
    DiscoverySourceDefinition("gcp_vertex_ai", "gcp", "ai_cloud", "GCP Vertex AI"),
    DiscoverySourceDefinition("gcp_cloud_storage", "gcp", "ai_cloud", "GCS (Agent Integrations)"),
    DiscoverySourceDefinition("gcp_compute_engine", "gcp", "ai_cloud", "GCE (Agent Workloads)"),
    DiscoverySourceDefinition("gcp_service_accounts", "gcp", "ai_cloud", "GCP Service Accounts (Agents)"),
    # Oracle Cloud
    DiscoverySourceDefinition("oracle_oci_genai", "oracle", "ai_cloud", "Oracle OCI Generative AI"),
    DiscoverySourceDefinition("oracle_oci_object_storage", "oracle", "ai_cloud", "OCI Object Storage (Agents)"),
    DiscoverySourceDefinition("oracle_oci_compute", "oracle", "ai_cloud", "OCI Compute (Agent Workloads)"),
    # GPU / specialized clouds
    DiscoverySourceDefinition("coreweave_gpu", "coreweave", "ai_cloud", "CoreWeave GPU Workloads"),
    DiscoverySourceDefinition("nvidia_cloud", "nvidia", "ai_cloud", "NVIDIA GPU Cloud / NIM"),
    # Dev platforms
    DiscoverySourceDefinition("cursor", "cursor", "dev_platform", "Cursor Agents"),
    DiscoverySourceDefinition("github", "github", "dev_platform", "GitHub Agent Repos"),
    DiscoverySourceDefinition("gitlab", "gitlab", "dev_platform", "GitLab Agent Repos"),
    DiscoverySourceDefinition("bitbucket", "bitbucket", "dev_platform", "Bitbucket Agent Repos"),
    # AI providers
    DiscoverySourceDefinition("openai", "openai", "ai_provider", "OpenAI"),
    DiscoverySourceDefinition("anthropic", "anthropic", "ai_provider", "Anthropic"),
    DiscoverySourceDefinition("cohere", "cohere", "ai_provider", "Cohere"),
    DiscoverySourceDefinition("mistral", "mistral", "ai_provider", "Mistral"),
    DiscoverySourceDefinition("groq", "groq", "ai_provider", "Groq"),
    DiscoverySourceDefinition("google", "google", "ai_provider", "Google Gemini"),
    DiscoverySourceDefinition("perplexity", "perplexity", "ai_provider", "Perplexity"),
    DiscoverySourceDefinition("together", "together", "ai_provider", "Together AI"),
    DiscoverySourceDefinition("fireworks", "fireworks", "ai_provider", "Fireworks AI"),
    DiscoverySourceDefinition("xai", "xai", "ai_provider", "xAI Grok"),
    DiscoverySourceDefinition("nvidia", "nvidia", "ai_provider", "NVIDIA NIM API"),
    DiscoverySourceDefinition("ibm_watson", "ibm", "ai_provider", "IBM watsonx"),
    # Agent ops / enterprise integrations
    DiscoverySourceDefinition("kubernetes", "kubernetes", "agent_ops", "Kubernetes Agent Workloads"),
    DiscoverySourceDefinition("langsmith", "langsmith", "agent_ops", "Agent Ops Traces"),
    DiscoverySourceDefinition("huggingface", "huggingface", "agent_ops", "Hugging Face Models"),
    DiscoverySourceDefinition("databricks", "databricks", "agent_ops", "Databricks ML Agents"),
    DiscoverySourceDefinition("snowflake", "snowflake", "agent_ops", "Snowflake AI / Cortex"),
    DiscoverySourceDefinition("mongodb_atlas", "mongodb", "agent_ops", "MongoDB Atlas Vector Search"),
    DiscoverySourceDefinition("slack", "slack", "agent_ops", "Slack AI Apps"),
    DiscoverySourceDefinition("servicenow", "servicenow", "agent_ops", "ServiceNow AI Agents"),
    DiscoverySourceDefinition("salesforce", "salesforce", "agent_ops", "Salesforce Einstein Agents"),
    DiscoverySourceDefinition("okta", "okta", "agent_ops", "Okta AI Identity"),
    DiscoverySourceDefinition("entra_id", "microsoft", "agent_ops", "Microsoft Entra ID (Agents)"),
)

SUPPORTED_DISCOVERY_SOURCES: tuple[str, ...] = tuple(item.source_id for item in DISCOVERY_SOURCE_CATALOG)

DISCOVERY_SOURCE_BY_ID: dict[str, DiscoverySourceDefinition] = {
    item.source_id: item for item in DISCOVERY_SOURCE_CATALOG
}


def get_discovery_source(source_id: str) -> Optional[DiscoverySourceDefinition]:
    return DISCOVERY_SOURCE_BY_ID.get(source_id)


