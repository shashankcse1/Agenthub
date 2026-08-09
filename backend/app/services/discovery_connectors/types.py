from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class DiscoveryCandidate:
    canonical_agent_key: str
    source_fingerprint: str
    confidence: int
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ConnectionCredentials:
    provider_type: str
    secret_value: Optional[str] = None
    workload_identity_profile_id: Optional[str] = None
    credential_binding_id: Optional[str] = None


@dataclass(frozen=True)
class ConnectionRuntime:
    connection_id: str
    tenant_id: str
    source_id: str
    base_url: str
    config: dict[str, Any]
    credentials: ConnectionCredentials
