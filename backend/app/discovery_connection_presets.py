"""Connection presets aligned to Providers secret refs and catalog source ids."""

from __future__ import annotations

from typing import Any, Optional

# Operator shortcuts (shown first in UI).
DISCOVERY_PRIORITY_SOURCE_IDS: tuple[str, ...] = ("openai", "cursor", "perplexity")

# All catalog sources with a documented live-connection template.
DISCOVERY_WELL_KNOWN_SOURCE_IDS: tuple[str, ...] = (
    # Priority AI / dev
    "openai",
    "cursor",
    "perplexity",
    "anthropic",
    "cohere",
    "mistral",
    "groq",
    "google",
    "together",
    "fireworks",
    "xai",
    "nvidia",
    "nvidia_cloud",
    "ibm_watson",
    "github",
    "gitlab",
    "bitbucket",
    # Cloud AI
    "aws_bedrock",
    "aws_sagemaker",
    "aws_s3",
    "aws_ec2",
    "aws_iam",
    "azure_openai",
    "azure_ml",
    "azure_blob_storage",
    "azure_virtual_machines",
    "azure_managed_identity",
    "gcp_vertex_ai",
    "gcp_cloud_storage",
    "gcp_compute_engine",
    "gcp_service_accounts",
    "oracle_oci_genai",
    "oracle_oci_object_storage",
    "oracle_oci_compute",
    "coreweave_gpu",
    # Agent ops
    "kubernetes",
    "langsmith",
    "huggingface",
    "databricks",
    "snowflake",
    "mongodb_atlas",
    "slack",
    "servicenow",
    "salesforce",
    "okta",
    "entra_id",
)

DISCOVERY_CONNECTION_PRESETS: dict[str, dict[str, Any]] = {
    "openai": {
        "connection_name": "OpenAI Production",
        "secret_ref": "providers/openai/api-key",
        "base_url": "https://api.openai.com/v1",
        "connection_config": {},
    },
    "anthropic": {
        "connection_name": "Anthropic Production",
        "secret_ref": "providers/anthropic/api-key",
        "base_url": "https://api.anthropic.com/v1",
        "connection_config": {},
    },
    "cursor": {
        "connection_name": "Cursor Gateway",
        "secret_ref": "gateway/cursor-token",
        "base_url": "https://api.cursor.com",
        "connection_config": {"workspace": "default"},
    },
    "cohere": {
        "connection_name": "Cohere Production",
        "secret_ref": "providers/cohere/api-key",
        "base_url": "https://api.cohere.com/v1",
        "connection_config": {},
    },
    "mistral": {
        "connection_name": "Mistral Production",
        "secret_ref": "providers/mistral/api-key",
        "base_url": "https://api.mistral.ai/v1",
        "connection_config": {},
    },
    "groq": {
        "connection_name": "Groq Production",
        "secret_ref": "providers/groq/api-key",
        "base_url": "https://api.groq.com/openai/v1",
        "connection_config": {},
    },
    "google": {
        "connection_name": "Google Gemini",
        "secret_ref": "providers/google/api-key",
        "base_url": "https://generativelanguage.googleapis.com/v1",
        "connection_config": {},
    },
    "perplexity": {
        "connection_name": "Perplexity Production",
        "secret_ref": "providers/perplexity/api-key",
        "base_url": "https://api.perplexity.ai",
        "connection_config": {},
    },
    "together": {
        "connection_name": "Together AI",
        "secret_ref": "providers/together/api-key",
        "base_url": "https://api.together.xyz/v1",
        "connection_config": {},
    },
    "fireworks": {
        "connection_name": "Fireworks AI",
        "secret_ref": "providers/fireworks/api-key",
        "base_url": "https://api.fireworks.ai/inference/v1",
        "connection_config": {},
    },
    "xai": {
        "connection_name": "xAI Grok",
        "secret_ref": "providers/xai/api-key",
        "base_url": "https://api.x.ai/v1",
        "connection_config": {},
    },
    "nvidia": {
        "connection_name": "NVIDIA NIM",
        "secret_ref": "providers/nvidia/api-key",
        "base_url": "https://integrate.api.nvidia.com/v1",
        "connection_config": {},
    },
    "nvidia_cloud": {
        "connection_name": "NVIDIA GPU Cloud",
        "secret_ref": "providers/nvidia/api-key",
        "base_url": "https://integrate.api.nvidia.com/v1",
        "connection_config": {},
    },
    "ibm_watson": {
        "connection_name": "IBM watsonx",
        "secret_ref": "providers/ibm/watson-api-key",
        "base_url": "https://us-south.ml.cloud.ibm.com",
        "connection_config": {"project_id": "your-project-id"},
    },
    "github": {
        "connection_name": "GitHub Agent Repos",
        "secret_ref": "providers/github/token",
        "base_url": "https://api.github.com",
        "connection_config": {"org": "your-org"},
    },
    "gitlab": {
        "connection_name": "GitLab Agent Repos",
        "secret_ref": "providers/gitlab/token",
        "base_url": "https://gitlab.com/api/v4",
        "connection_config": {"group": "your-group"},
    },
    "bitbucket": {
        "connection_name": "Bitbucket Agent Repos",
        "secret_ref": "providers/bitbucket/token",
        "base_url": "https://api.bitbucket.org/2.0",
        "connection_config": {"workspace": "your-workspace"},
    },
    "aws_bedrock": {
        "connection_name": "AWS Bedrock",
        "secret_ref": "providers/aws/bedrock-credentials",
        "base_url": "",
        "connection_config": {"region": "us-east-1"},
    },
    "aws_sagemaker": {
        "connection_name": "AWS SageMaker",
        "secret_ref": "providers/aws/bedrock-credentials",
        "base_url": "",
        "connection_config": {"region": "us-east-1"},
    },
    "aws_s3": {
        "connection_name": "AWS S3 Agent Buckets",
        "secret_ref": "providers/aws/bedrock-credentials",
        "base_url": "",
        "connection_config": {"region": "us-east-1"},
    },
    "aws_ec2": {
        "connection_name": "AWS EC2 Agent Workloads",
        "secret_ref": "providers/aws/bedrock-credentials",
        "base_url": "",
        "connection_config": {"region": "us-east-1"},
    },
    "aws_iam": {
        "connection_name": "AWS IAM Agent Roles",
        "secret_ref": "providers/aws/bedrock-credentials",
        "base_url": "",
        "connection_config": {"region": "us-east-1"},
    },
    "azure_openai": {
        "connection_name": "Azure OpenAI",
        "secret_ref": "providers/azure/openai-key",
        "base_url": "",
        "connection_config": {
            "subscription_id": "your-subscription-id",
            "resource_name": "your-openai-resource",
        },
    },
    "azure_ml": {
        "connection_name": "Azure ML",
        "secret_ref": "providers/azure/openai-key",
        "base_url": "https://management.azure.com",
        "connection_config": {"subscription_id": "your-subscription-id"},
    },
    "azure_blob_storage": {
        "connection_name": "Azure Blob (Agent Integrations)",
        "secret_ref": "providers/azure/openai-key",
        "base_url": "https://management.azure.com",
        "connection_config": {"subscription_id": "your-subscription-id"},
    },
    "azure_virtual_machines": {
        "connection_name": "Azure VMs (Agent Workloads)",
        "secret_ref": "providers/azure/openai-key",
        "base_url": "https://management.azure.com",
        "connection_config": {"subscription_id": "your-subscription-id"},
    },
    "azure_managed_identity": {
        "connection_name": "Azure Managed Identity (Agents)",
        "secret_ref": "providers/azure/openai-key",
        "base_url": "https://management.azure.com",
        "connection_config": {"subscription_id": "your-subscription-id"},
    },
    "gcp_vertex_ai": {
        "connection_name": "GCP Vertex AI",
        "secret_ref": "providers/google/api-key",
        "base_url": "",
        "connection_config": {"project_id": "your-project-id", "location": "us-central1"},
    },
    "gcp_cloud_storage": {
        "connection_name": "GCS (Agent Integrations)",
        "secret_ref": "providers/google/api-key",
        "base_url": "",
        "connection_config": {"project_id": "your-project-id"},
    },
    "gcp_compute_engine": {
        "connection_name": "GCE (Agent Workloads)",
        "secret_ref": "providers/google/api-key",
        "base_url": "",
        "connection_config": {"project_id": "your-project-id", "zone": "us-central1-a"},
    },
    "gcp_service_accounts": {
        "connection_name": "GCP Service Accounts (Agents)",
        "secret_ref": "providers/google/api-key",
        "base_url": "",
        "connection_config": {"project_id": "your-project-id"},
    },
    "oracle_oci_genai": {
        "connection_name": "Oracle OCI Gen AI",
        "secret_ref": "providers/oracle/oci-api-key",
        "base_url": "",
        "connection_config": {"region": "us-chicago-1", "compartment_id": "ocid1.compartment..."},
    },
    "oracle_oci_object_storage": {
        "connection_name": "OCI Object Storage (Agents)",
        "secret_ref": "providers/oracle/oci-api-key",
        "base_url": "",
        "connection_config": {"region": "us-chicago-1", "namespace": "your-namespace"},
    },
    "oracle_oci_compute": {
        "connection_name": "OCI Compute (Agent Workloads)",
        "secret_ref": "providers/oracle/oci-api-key",
        "base_url": "",
        "connection_config": {"region": "us-chicago-1", "compartment_id": "ocid1.compartment..."},
    },
    "coreweave_gpu": {
        "connection_name": "CoreWeave GPU",
        "secret_ref": "providers/coreweave/api-key",
        "base_url": "https://api.coreweave.com",
        "connection_config": {},
    },
    "kubernetes": {
        "connection_name": "Kubernetes Agent Workloads",
        "secret_ref": "providers/kubernetes/cluster-token",
        "base_url": "https://your-cluster.example.com",
        "connection_config": {"namespace": "default"},
    },
    "langsmith": {
        "connection_name": "Agent Ops Traces",
        "secret_ref": "providers/langsmith/api-key",
        "base_url": "https://api.smith.langchain.com",
        "connection_config": {},
    },
    "huggingface": {
        "connection_name": "Hugging Face",
        "secret_ref": "providers/huggingface/token",
        "base_url": "https://huggingface.co/api",
        "connection_config": {"org": "your-org"},
    },
    "databricks": {
        "connection_name": "Databricks ML Agents",
        "secret_ref": "providers/databricks/token",
        "base_url": "https://your-workspace.cloud.databricks.com",
        "connection_config": {},
    },
    "snowflake": {
        "connection_name": "Snowflake Cortex",
        "secret_ref": "providers/snowflake/token",
        "base_url": "https://your-account.snowflakecomputing.com",
        "connection_config": {},
    },
    "mongodb_atlas": {
        "connection_name": "MongoDB Atlas Vector",
        "secret_ref": "providers/mongodb/atlas-api-key",
        "base_url": "https://cloud.mongodb.com/api/atlas/v1.0",
        "connection_config": {"group_id": "your-group-id"},
    },
    "slack": {
        "connection_name": "Slack AI Apps",
        "secret_ref": "providers/slack/bot-token",
        "base_url": "https://slack.com/api",
        "connection_config": {},
    },
    "servicenow": {
        "connection_name": "ServiceNow AI",
        "secret_ref": "providers/servicenow/token",
        "base_url": "https://your-instance.service-now.com",
        "connection_config": {},
    },
    "salesforce": {
        "connection_name": "Salesforce Einstein",
        "secret_ref": "providers/salesforce/token",
        "base_url": "https://your-instance.my.salesforce.com",
        "connection_config": {},
    },
    "okta": {
        "connection_name": "Okta AI Identity",
        "secret_ref": "providers/okta/api-token",
        "base_url": "",
        "connection_config": {"domain": "your-org.okta.com"},
    },
    "entra_id": {
        "connection_name": "Microsoft Entra ID",
        "secret_ref": "providers/azure/openai-key",
        "base_url": "https://graph.microsoft.com/v1.0",
        "connection_config": {"tenant_id": "your-tenant-id"},
    },
}


def preset_for_source(source_id: str) -> Optional[dict[str, Any]]:
    preset = DISCOVERY_CONNECTION_PRESETS.get(source_id)
    if preset is None:
        return None
    return {
        "source_id": source_id,
        **preset,
    }
