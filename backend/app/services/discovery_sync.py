import hashlib
from datetime import datetime
from typing import Iterable
from uuid import uuid4

from sqlalchemy.orm import Session

from app.discovery_sources import DiscoverySourceDefinition, get_discovery_source
from app.models import (
    Agent,
    AgentConfig,
    DiscoveryRecord,
    ModuleDefinition,
    ProviderCredentialBinding,
    RoutePolicy,
    SecretProviderConfig,
    SupportedModelCatalogEntry,
    WorkloadIdentityFederationProfile,
)
from app.services.agent_discovery_scope import (
    AGENT_SCOPED_COMPUTE_SOURCES,
    AGENT_SCOPED_IDENTITY_SOURCES,
    AGENT_SCOPED_STORAGE_SOURCES,
    is_agent_cloud_integration_ref,
    is_agent_config,
    is_agent_credential_binding,
    is_agent_module,
    is_agent_related_text,
    is_governed_agent,
)

AI_PROVIDER_ALIASES: dict[str, set[str]] = {
    "openai": {"openai"},
    "anthropic": {"anthropic", "claude"},
    "cohere": {"cohere"},
    "mistral": {"mistral"},
    "groq": {"groq"},
    "google": {"google", "gcp", "google-cloud", "google_cloud", "gemini"},
    "perplexity": {"perplexity"},
    "together": {"together", "togetherai", "together_ai"},
    "fireworks": {"fireworks", "fireworksai", "fireworks_ai"},
    "xai": {"xai", "grok"},
    "nvidia": {"nvidia", "nvidia-nim", "nvidia_nim"},
    "azure_openai": {"azure", "azure-openai", "azure_openai"},
    "ibm_watson": {"ibm", "watson", "watsonx"},
}

CLOUD_SOURCE_PROVIDER_TYPES: dict[str, set[str]] = {
    "aws_s3": {"aws", "aws-s3", "aws_s3"},
    "aws_iam": {"aws", "aws-iam", "aws_iam"},
    "aws_ec2": {"aws", "aws-ec2", "aws_ec2"},
    "aws_sagemaker": {"aws", "aws-sagemaker", "aws_sagemaker", "sagemaker"},
    "aws_bedrock": {"aws", "aws-bedrock", "aws_bedrock", "bedrock"},
    "azure_blob_storage": {"azure", "azure-blob", "azure_blob"},
    "azure_managed_identity": {"azure", "azure-entra", "azure_entra", "azure-managed-identity"},
    "azure_virtual_machines": {"azure", "azure-vm", "azure_vm"},
    "azure_ml": {"azure", "azure-ml", "azure_ml", "machinelearning"},
    "azure_openai": {"azure", "azure-openai", "azure_openai"},
    "gcp_cloud_storage": {"google", "gcp", "google-cloud", "gcp-cloud-storage"},
    "gcp_service_accounts": {"google", "gcp", "gcp-service-account", "gcp_service_accounts"},
    "gcp_compute_engine": {"google", "gcp", "gcp-compute", "gcp_compute_engine"},
    "gcp_vertex_ai": {"google", "gcp", "vertex", "vertex-ai", "gcp_vertex"},
    "oracle_oci_genai": {"oracle", "oci", "oracle-cloud", "genai"},
    "oracle_oci_object_storage": {"oracle", "oci", "object-storage"},
    "oracle_oci_compute": {"oracle", "oci", "compute"},
    "coreweave_gpu": {"coreweave", "gpu"},
    "nvidia_cloud": {"nvidia", "nvidia-nim", "nvidia_nim"},
}

MODULE_INTEGRATION_SOURCES = {"cursor", "github", "gitlab", "bitbucket"}

ENTERPRISE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "kubernetes": ("kubernetes", "k8s", "kube", "eks", "aks", "gke", "agent"),
    "langsmith": ("langsmith", "langchain"),
    "huggingface": ("huggingface", "hugging-face", "hf.co"),
    "slack": ("slack", "ai", "agent", "bot"),
    "databricks": ("databricks", "ml", "agent"),
    "snowflake": ("snowflake", "cortex", "agent", "ml"),
    "mongodb_atlas": ("mongodb", "atlas", "vector", "agent"),
    "servicenow": ("servicenow", "now assist", "agent", "ai"),
    "salesforce": ("salesforce", "einstein", "agent"),
    "okta": ("okta", "agent", "ai"),
    "entra_id": ("entra", "azure-ad", "azuread", "agent"),
}


def _fingerprint(*parts: str) -> str:
    payload = "|".join(str(part or "").strip() for part in parts)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _normalize_provider(value: str) -> str:
    return str(value or "").strip().lower().replace("_", "-")


def _upsert_candidate(
    db: Session,
    *,
    source_id: str,
    canonical_agent_key: str,
    source_fingerprint: str,
    confidence: int,
) -> DiscoveryRecord:
    now = datetime.utcnow()
    existing = (
        db.query(DiscoveryRecord)
        .filter(
            DiscoveryRecord.source_system == source_id,
            DiscoveryRecord.source_fingerprint == source_fingerprint,
        )
        .first()
    )
    if existing:
        existing.canonical_agent_key = canonical_agent_key
        existing.discovery_confidence = confidence
        existing.last_discovered_at = now
        return existing

    record = DiscoveryRecord(
        discovered_agent_id=str(uuid4()),
        canonical_agent_key=canonical_agent_key,
        source_system=source_id,
        source_fingerprint=source_fingerprint,
        discovery_confidence=confidence,
        discovery_status="discovered",
        last_discovered_at=now,
    )
    db.add(record)
    return record


def _sync_runtime_inventory(db: Session, source_id: str) -> list[DiscoveryRecord]:
    records: list[DiscoveryRecord] = []
    configs = db.query(AgentConfig).order_by(AgentConfig.updated_at.desc()).all()
    for config in configs:
        if not is_agent_config(config):
            continue
        fingerprint = _fingerprint("agent-config", config.config_id, config.agent_key)
        confidence = 92 if config.enabled else 70
        records.append(
            _upsert_candidate(
                db,
                source_id=source_id,
                canonical_agent_key=config.agent_key,
                source_fingerprint=fingerprint,
                confidence=confidence,
            )
        )

    known_keys = {config.agent_key for config in configs if is_agent_config(config)}
    agents = db.query(Agent).order_by(Agent.created_at.desc()).all()
    for agent in agents:
        if not is_governed_agent(agent):
            continue
        if agent.agent_id in known_keys or agent.name in known_keys:
            continue
        fingerprint = _fingerprint("agent", agent.agent_id)
        confidence = 88 if agent.status == "active" else 65
        records.append(
            _upsert_candidate(
                db,
                source_id=source_id,
                canonical_agent_key=agent.name or agent.agent_id,
                source_fingerprint=fingerprint,
                confidence=confidence,
            )
        )
    return records


def _sync_code_metadata(db: Session, source_id: str) -> list[DiscoveryRecord]:
    records: list[DiscoveryRecord] = []
    for module in db.query(ModuleDefinition).order_by(ModuleDefinition.module_id.asc()).all():
        if not is_agent_module(module):
            continue
        fingerprint = _fingerprint("module", module.module_id, module.version)
        confidence = 90 if module.status == "active" else 72
        records.append(
            _upsert_candidate(
                db,
                source_id=source_id,
                canonical_agent_key=f"{module.module_name}:{module.version}",
                source_fingerprint=fingerprint,
                confidence=confidence,
            )
        )
    return records


def _sync_gateway_telemetry(db: Session, source_id: str) -> list[DiscoveryRecord]:
    records: list[DiscoveryRecord] = []
    for route in db.query(RoutePolicy).filter(RoutePolicy.status == "active").all():
        fingerprint = _fingerprint("route", route.route_policy_id)
        records.append(
            _upsert_candidate(
                db,
                source_id=source_id,
                canonical_agent_key=route.route_name,
                source_fingerprint=fingerprint,
                confidence=86,
            )
        )
    return records


def _sync_module_integration(db: Session, source_id: str) -> list[DiscoveryRecord]:
    records: list[DiscoveryRecord] = []
    for module in db.query(ModuleDefinition).filter(ModuleDefinition.integration_provider == source_id).all():
        if not is_agent_module(module):
            continue
        fingerprint = _fingerprint("module-integration", module.module_id, module.integration_reference)
        confidence = 94 if module.integration_sync_status == "synced" else 82
        records.append(
            _upsert_candidate(
                db,
                source_id=source_id,
                canonical_agent_key=module.module_name or module.module_id,
                source_fingerprint=fingerprint,
                confidence=confidence,
            )
        )
    return records


def _binding_matches_dev_source(source_id: str, binding: ProviderCredentialBinding) -> bool:
    haystack = " ".join(
        [
            binding.binding_name,
            binding.consumer_type,
            binding.consumer_key,
            binding.provider_type,
        ]
    ).lower()
    if str(binding.provider_type or "").strip().lower() == source_id:
        return True
    if source_id in haystack or source_id.replace("_", "-") in haystack:
        return True
    if source_id == "cursor" and (binding.consumer_key == "cursor" or "cursor" in haystack):
        return True
    return False


def _sync_dev_platform(db: Session, source_id: str) -> list[DiscoveryRecord]:
    records = _sync_module_integration(db, source_id)
    seen = {record.source_fingerprint for record in records}
    for binding in db.query(ProviderCredentialBinding).filter(ProviderCredentialBinding.status == "active").all():
        if not _binding_matches_dev_source(source_id, binding):
            continue
        if not is_agent_credential_binding(binding):
            continue
        fingerprint = _fingerprint(f"{source_id}-binding", binding.binding_id)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        records.append(
            _upsert_candidate(
                db,
                source_id=source_id,
                canonical_agent_key=f"{source_id}:{binding.consumer_type}:{binding.consumer_key}",
                source_fingerprint=fingerprint,
                confidence=90,
            )
        )
    return records


def _provider_matches(source_id: str, provider_type: str) -> bool:
    normalized = _normalize_provider(provider_type)
    aliases = AI_PROVIDER_ALIASES.get(source_id) or CLOUD_SOURCE_PROVIDER_TYPES.get(source_id) or {source_id}
    return normalized in aliases or any(alias in normalized for alias in aliases)


def _sync_ai_provider(db: Session, source_id: str) -> list[DiscoveryRecord]:
    records: list[DiscoveryRecord] = []
    seen: set[str] = set()

    for config in db.query(AgentConfig).all():
        if not _provider_matches(source_id, config.provider):
            continue
        fingerprint = _fingerprint("agent-config-provider", config.config_id, config.model)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        records.append(
            _upsert_candidate(
                db,
                source_id=source_id,
                canonical_agent_key=f"{config.agent_key}:{config.model}",
                source_fingerprint=fingerprint,
                confidence=91,
            )
        )

    for model in db.query(SupportedModelCatalogEntry).filter(SupportedModelCatalogEntry.status == "active").all():
        if not _provider_matches(source_id, model.provider_type):
            continue
        fingerprint = _fingerprint("supported-model", model.supported_model_id)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        records.append(
            _upsert_candidate(
                db,
                source_id=source_id,
                canonical_agent_key=model.model_name,
                source_fingerprint=fingerprint,
                confidence=89,
            )
        )

    for binding in db.query(ProviderCredentialBinding).filter(ProviderCredentialBinding.status == "active").all():
        if not _provider_matches(source_id, binding.provider_type):
            continue
        if not is_agent_credential_binding(binding):
            continue
        fingerprint = _fingerprint("credential-binding", binding.binding_id)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        records.append(
            _upsert_candidate(
                db,
                source_id=source_id,
                canonical_agent_key=f"{binding.consumer_type}:{binding.consumer_key}",
                source_fingerprint=fingerprint,
                confidence=87,
            )
        )
    return records


def _sync_cloud_product(db: Session, source_id: str) -> list[DiscoveryRecord]:
    records: list[DiscoveryRecord] = []
    seen: set[str] = set()
    agent_scoped_infra = source_id in (
        AGENT_SCOPED_STORAGE_SOURCES | AGENT_SCOPED_COMPUTE_SOURCES | AGENT_SCOPED_IDENTITY_SOURCES
    )

    for profile in db.query(WorkloadIdentityFederationProfile).filter(
        WorkloadIdentityFederationProfile.status == "active"
    ).all():
        if not _provider_matches(source_id, profile.provider_type):
            continue
        haystack = " ".join(
            [
                profile.role_arn_or_equivalent or "",
                profile.workload_identity_profile_id,
                profile.provider_type,
            ]
        )
        if agent_scoped_infra and not is_agent_cloud_integration_ref(source_id, haystack):
            continue
        fingerprint = _fingerprint("workload-identity", profile.workload_identity_profile_id)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        records.append(
            _upsert_candidate(
                db,
                source_id=source_id,
                canonical_agent_key=profile.role_arn_or_equivalent or profile.workload_identity_profile_id,
                source_fingerprint=fingerprint,
                confidence=88,
            )
        )

    for provider in db.query(SecretProviderConfig).filter(SecretProviderConfig.status == "active").all():
        if not _provider_matches(source_id, provider.provider_type):
            continue
        haystack = " ".join(
            [
                provider.secret_provider_id,
                provider.provider_type,
                provider.provider_address or "",
                provider.role_or_mount or "",
            ]
        )
        if agent_scoped_infra and not is_agent_cloud_integration_ref(source_id, haystack):
            continue
        fingerprint = _fingerprint("secret-provider", provider.secret_provider_id)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        records.append(
            _upsert_candidate(
                db,
                source_id=source_id,
                canonical_agent_key=provider.secret_provider_id,
                source_fingerprint=fingerprint,
                confidence=85,
            )
        )

    if agent_scoped_infra:
        for module in db.query(ModuleDefinition).all():
            if not is_agent_module(module):
                continue
            ref = str(module.integration_reference or module.provenance_ref or "")
            if not is_agent_cloud_integration_ref(source_id, ref):
                continue
            fingerprint = _fingerprint("cloud-integration-module", module.module_id, ref)
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            records.append(
                _upsert_candidate(
                    db,
                    source_id=source_id,
                    canonical_agent_key=module.module_name or module.module_id,
                    source_fingerprint=fingerprint,
                    confidence=86,
                )
            )

    # Cloud AI runtimes also surface through agent configs and model catalog.
    records.extend(_sync_ai_provider(db, source_id))
    return records


def _text_matches_keywords(text: str, keywords: Iterable[str]) -> bool:
    lowered = str(text or "").lower()
    return any(keyword in lowered for keyword in keywords)


def _sync_enterprise_platform(db: Session, source_id: str) -> list[DiscoveryRecord]:
    keywords = ENTERPRISE_KEYWORDS.get(source_id, (source_id.replace("_", "-"),))
    records: list[DiscoveryRecord] = []
    seen: set[str] = set()

    for module in db.query(ModuleDefinition).all():
        haystack = " ".join(
            [
                module.module_name,
                module.integration_provider,
                module.integration_reference,
                module.provenance_ref,
                module.owner_team,
            ]
        )
        if not _text_matches_keywords(haystack, keywords):
            continue
        fingerprint = _fingerprint("enterprise-module", module.module_id)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        records.append(
            _upsert_candidate(
                db,
                source_id=source_id,
                canonical_agent_key=module.module_name or module.module_id,
                source_fingerprint=fingerprint,
                confidence=84,
            )
        )

    for binding in db.query(ProviderCredentialBinding).filter(ProviderCredentialBinding.status == "active").all():
        if not is_agent_credential_binding(binding):
            continue
        haystack = " ".join([binding.binding_name, binding.consumer_type, binding.consumer_key, binding.provider_type])
        if not _text_matches_keywords(haystack, keywords):
            continue
        fingerprint = _fingerprint("enterprise-binding", binding.binding_id)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        records.append(
            _upsert_candidate(
                db,
                source_id=source_id,
                canonical_agent_key=f"{binding.consumer_type}:{binding.consumer_key}",
                source_fingerprint=fingerprint,
                confidence=83,
            )
        )
    return records


def sync_discovery_source_records(db: Session, source_id: str) -> list[DiscoveryRecord]:
    definition = get_discovery_source(source_id)
    if definition is None:
        return []

    if source_id == "runtime_inventory":
        return _sync_runtime_inventory(db, source_id)
    if source_id == "code_metadata":
        return _sync_code_metadata(db, source_id)
    if source_id == "gateway_telemetry":
        return _sync_gateway_telemetry(db, source_id)
    if source_id in MODULE_INTEGRATION_SOURCES:
        return _sync_dev_platform(db, source_id)
    if source_id in CLOUD_SOURCE_PROVIDER_TYPES:
        return _sync_cloud_product(db, source_id)
    if source_id in AI_PROVIDER_ALIASES:
        return _sync_ai_provider(db, source_id)
    if source_id in ENTERPRISE_KEYWORDS:
        return _sync_enterprise_platform(db, source_id)
    return []


def discovery_source_metadata(source_id: str) -> DiscoverySourceDefinition:
    definition = get_discovery_source(source_id)
    if definition is None:
        raise KeyError(source_id)
    return definition
