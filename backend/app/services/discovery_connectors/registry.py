from sqlalchemy.orm import Session

from app.services import discovery_sync as internal_sync
from app.services.discovery_connectors.types import ConnectionRuntime, DiscoveryCandidate


INTERNAL_PLATFORM_SOURCES = {
    "runtime_inventory",
    "code_metadata",
    "gateway_telemetry",
}

AI_LIVE_SOURCES = {
    "openai",
    "anthropic",
    "cohere",
    "mistral",
    "groq",
    "google",
    "perplexity",
    "together",
    "fireworks",
    "xai",
    "nvidia",
    "nvidia_cloud",
    "ibm_watson",
    "azure_openai",
}

DEV_LIVE_SOURCES = {
    "github",
    "gitlab",
    "bitbucket",
    "cursor",
}

ENTERPRISE_LIVE_SOURCES = set(internal_sync.ENTERPRISE_KEYWORDS.keys())


def _to_candidates(records: list) -> list[DiscoveryCandidate]:
    return [
        DiscoveryCandidate(
            canonical_agent_key=record.canonical_agent_key,
            source_fingerprint=record.source_fingerprint,
            confidence=record.discovery_confidence,
            metadata={"live": False, "internal": True},
        )
        for record in records
    ]


def fetch_internal_platform_inventory(db: Session, source_id: str) -> list[DiscoveryCandidate]:
    if source_id not in INTERNAL_PLATFORM_SOURCES:
        raise ValueError(f"{source_id} is not an internal platform source")
    return _to_candidates(internal_sync.sync_discovery_source_records(db, source_id))


def fetch_internal_catalog_inventory(db: Session, source_id: str) -> list[DiscoveryCandidate]:
    return _to_candidates(internal_sync.sync_discovery_source_records(db, source_id))


def fetch_for_runtime(db: Session, runtime: ConnectionRuntime) -> list[DiscoveryCandidate]:
    from app.services.discovery_connectors.ai import fetch_ai_provider_inventory
    from app.services.discovery_connectors.cloud import (
        fetch_aws_inventory,
        fetch_azure_inventory,
        fetch_coreweave_inventory,
        fetch_gcp_inventory,
        fetch_oracle_inventory,
    )
    from app.services.discovery_connectors.dev import (
        fetch_bitbucket_inventory,
        fetch_cursor_inventory,
        fetch_github_inventory,
        fetch_gitlab_inventory,
    )
    from app.services.discovery_connectors.enterprise import fetch_enterprise_inventory

    source_id = runtime.source_id

    if source_id in INTERNAL_PLATFORM_SOURCES:
        return fetch_internal_platform_inventory(db, source_id)

    try:
        if source_id in AI_LIVE_SOURCES:
            if source_id == "nvidia_cloud":
                runtime = ConnectionRuntime(
                    connection_id=runtime.connection_id,
                    tenant_id=runtime.tenant_id,
                    source_id="nvidia",
                    base_url=runtime.base_url,
                    config=runtime.config,
                    credentials=runtime.credentials,
                )
            return fetch_ai_provider_inventory(runtime)

        dev_handlers = {
            "github": fetch_github_inventory,
            "gitlab": fetch_gitlab_inventory,
            "bitbucket": fetch_bitbucket_inventory,
            "cursor": fetch_cursor_inventory,
        }
        if source_id in dev_handlers:
            return dev_handlers[source_id](runtime)

        if source_id.startswith("aws_"):
            return fetch_aws_inventory(runtime)
        if source_id.startswith("azure_"):
            return fetch_azure_inventory(runtime)
        if source_id.startswith("gcp_"):
            return fetch_gcp_inventory(runtime)
        if source_id.startswith("oracle_"):
            return fetch_oracle_inventory(runtime)
        if source_id.startswith("coreweave_"):
            return fetch_coreweave_inventory(runtime)

        if source_id in ENTERPRISE_LIVE_SOURCES:
            return fetch_enterprise_inventory(runtime)
    except Exception:
        internal = fetch_internal_catalog_inventory(db, source_id)
        if internal:
            return internal
        raise

    internal = fetch_internal_catalog_inventory(db, source_id)
    if internal:
        return internal

    raise ValueError(f"No live connector registered for source {source_id}")
