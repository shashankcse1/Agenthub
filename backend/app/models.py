from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base
from app.logging_utils import get_logger
from app.policy_constants import (
    AUTH_POLICY_DEFAULT_ID,
    AUTH_SESSION_ISSUER_ROLES_DEFAULT,
    AUTH_SESSION_READ_ROLES_DEFAULT,
    CROSS_ACTOR_DUAL_APPROVAL_ROLES_DEFAULT,
    DEFAULT_BASIC_AUTH_MAX_ENABLE_DURATION_MINUTES,
    DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES,
    DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT,
    ISSUABLE_SESSION_ROLES_DEFAULT,
    PRIVILEGED_MFA_REAUTH_MINUTES_DEFAULT,
)

logger = get_logger(__name__)


class Agent(Base):
    __tablename__ = "agents"

    agent_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    owner_id: Mapped[str] = mapped_column(String(128), nullable=False)
    owner_name: Mapped[str] = mapped_column(String(255), nullable=False)
    owner_team: Mapped[str] = mapped_column(String(255), nullable=False)
    agent_type: Mapped[str] = mapped_column(String(64), default="other")
    description: Mapped[str] = mapped_column(Text, default="")
    risk_tier: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(64), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AgentConfig(Base):
    __tablename__ = "agent_configs"
    __table_args__ = (Index("ix_agent_configs_agent_key", "agent_key", unique=True),)

    config_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_key: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str] = mapped_column(String(64), nullable=False)
    model: Mapped[str] = mapped_column(String(255), nullable=False)
    provider_priority: Mapped[str] = mapped_column(Text, default="")
    temperature: Mapped[float] = mapped_column(Float, default=0.3)
    max_tokens: Mapped[int] = mapped_column(Integer, default=1024)
    timeout_ms: Mapped[int] = mapped_column(Integer, default=4500)
    fallback_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    max_fallback_hops: Mapped[int] = mapped_column(Integer, default=2)
    global_timeout_ms: Mapped[int] = mapped_column(Integer, default=4500)
    retry_budget: Mapped[int] = mapped_column(Integer, default=1)
    failure_threshold_percent: Mapped[int] = mapped_column(Integer, default=40)
    cooldown_seconds: Mapped[int] = mapped_column(Integer, default=60)
    environment: Mapped[str] = mapped_column(String(64), default="dev")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    notes: Mapped[str] = mapped_column(Text, default="")
    updated_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class OwnershipEvent(Base):
    __tablename__ = "ownership_events"

    event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    old_owner_id: Mapped[str] = mapped_column(String(128), nullable=False)
    new_owner_id: Mapped[str] = mapped_column(String(128), nullable=False)
    changed_by: Mapped[str] = mapped_column(String(128), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    ticket_ref: Mapped[str] = mapped_column(String(128), nullable=False)
    changed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class IdentityProviderConfig(Base):
    __tablename__ = "identity_provider_configs"

    provider_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    protocol_type: Mapped[str] = mapped_column(String(32), nullable=False)
    issuer_or_entity_id: Mapped[str] = mapped_column(String(255), nullable=False)
    jwks_or_metadata_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    scim_base_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    role_mapping_rules: Mapped[str] = mapped_column(Text, default="{}")
    mfa_required_roles: Mapped[str] = mapped_column(Text, default="[]")
    session_policy_id: Mapped[str] = mapped_column(String(64), default="default")
    status: Mapped[str] = mapped_column(String(64), default="active")
    last_validated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class SessionRecord(Base):
    __tablename__ = "sessions"

    session_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_activity_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    idle_timeout_minutes: Mapped[int] = mapped_column(Integer, default=DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES)
    mfa_verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)


class BasicAuthFallbackConfig(Base):
    __tablename__ = "basic_auth_fallback_configs"

    basic_auth_config_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    environment: Mapped[str] = mapped_column(String(64), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    allowed_user_groups: Mapped[str] = mapped_column(Text, default="[]")
    ip_allowlist: Mapped[str] = mapped_column(Text, default="[]")
    max_enable_duration_minutes: Mapped[int] = mapped_column(Integer, default=DEFAULT_BASIC_AUTH_MAX_ENABLE_DURATION_MINUTES)
    enabled_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    break_glass_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_toggled_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        Index("ix_audit_events_resource_lookup", "resource_type", "resource_id", "timestamp"),
        Index("ix_audit_events_action_actor_time", "action_type", "actor_id", "timestamp"),
    )

    audit_event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    actor_type: Mapped[str] = mapped_column(String(64), default="user")
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    action_type: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(128), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(128), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    decision_outcome: Mapped[str] = mapped_column(String(64), default="allow")
    policy_version: Mapped[str] = mapped_column(String(64), default="v1")


class AuthPolicyConfig(Base):
    __tablename__ = "auth_policy_configs"

    policy_id: Mapped[str] = mapped_column(String(64), primary_key=True, default=AUTH_POLICY_DEFAULT_ID)
    session_read_roles: Mapped[str] = mapped_column(Text, default=lambda: ",".join(sorted(AUTH_SESSION_READ_ROLES_DEFAULT)))
    session_issuer_roles: Mapped[str] = mapped_column(Text, default=lambda: ",".join(sorted(AUTH_SESSION_ISSUER_ROLES_DEFAULT)))
    issuable_session_roles: Mapped[str] = mapped_column(Text, default=lambda: ",".join(sorted(ISSUABLE_SESSION_ROLES_DEFAULT)))
    cross_actor_dual_approval_roles: Mapped[str] = mapped_column(
        Text,
        default=lambda: ",".join(sorted(CROSS_ACTOR_DUAL_APPROVAL_ROLES_DEFAULT)),
    )
    dual_approval_required_approver_role: Mapped[str] = mapped_column(
        String(128),
        default=DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT,
    )
    description: Mapped[str] = mapped_column(Text, default="")
    privileged_mfa_reauth_minutes: Mapped[int] = mapped_column(Integer, default=PRIVILEGED_MFA_REAUTH_MINUTES_DEFAULT)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class AuthPolicyConfigRevision(Base):
    __tablename__ = "auth_policy_config_revisions"

    revision_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    policy_id: Mapped[str] = mapped_column(String(64), nullable=False, default=AUTH_POLICY_DEFAULT_ID)
    session_read_roles: Mapped[str] = mapped_column(Text, nullable=False)
    session_issuer_roles: Mapped[str] = mapped_column(Text, nullable=False)
    issuable_session_roles: Mapped[str] = mapped_column(Text, nullable=False)
    cross_actor_dual_approval_roles: Mapped[str] = mapped_column(Text, nullable=False)
    dual_approval_required_approver_role: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    privileged_mfa_reauth_minutes: Mapped[int] = mapped_column(Integer, nullable=False)
    changed_by: Mapped[str] = mapped_column(String(128), nullable=False)
    change_reason: Mapped[str] = mapped_column(Text, default="")
    source_revision_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class DiscoveryRecord(Base):
    __tablename__ = "discovery_records"

    discovered_agent_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    canonical_agent_key: Mapped[str] = mapped_column(String(255), nullable=False)
    source_system: Mapped[str] = mapped_column(String(128), nullable=False)
    source_fingerprint: Mapped[str] = mapped_column(String(255), nullable=False)
    discovery_confidence: Mapped[int] = mapped_column(Integer, default=50)
    discovery_status: Mapped[str] = mapped_column(String(64), default="discovered")
    last_discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    promoted_to_agent_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)


class ModuleDefinition(Base):
    __tablename__ = "module_definitions"

    module_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    module_name: Mapped[str] = mapped_column(String(255), nullable=False)
    module_type: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    contract_version: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_team: Mapped[str] = mapped_column(String(255), nullable=False)
    compatibility_range: Mapped[str] = mapped_column(String(128), default="*")
    required_permissions: Mapped[str] = mapped_column(Text, default="[]")
    artifact_signature: Mapped[str] = mapped_column(String(255), default="")
    provenance_ref: Mapped[str] = mapped_column(String(1024), default="")
    security_review_ticket: Mapped[str] = mapped_column(String(128), default="")
    replacement_module_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    migration_guidance: Mapped[str] = mapped_column(Text, default="")
    deprecation_timeline: Mapped[str] = mapped_column(String(255), default="")
    deprecated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(64), default="active")


class AgentModuleMapping(Base):
    __tablename__ = "agent_module_mappings"

    mapping_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    module_id: Mapped[str] = mapped_column(String(64), nullable=False)
    pinned_version: Mapped[str] = mapped_column(String(64), nullable=False)
    config_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    validated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    validation_status: Mapped[str] = mapped_column(String(64), default="valid")


class VirtualKey(Base):
    __tablename__ = "virtual_keys"

    key_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    owner_scope_type: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_scope_id: Mapped[str] = mapped_column(String(128), nullable=False)
    allowed_endpoint_families: Mapped[str] = mapped_column(Text, default="[]")
    allowed_models: Mapped[str] = mapped_column(Text, default="[]")
    guardrail_policy: Mapped[str] = mapped_column(Text, default="{}")
    budget_policy_id: Mapped[str] = mapped_column(String(64), default="default")
    rate_limit_policy_id: Mapped[str] = mapped_column(String(64), default="default")
    authn_method: Mapped[str] = mapped_column(String(64), default="token")
    status: Mapped[str] = mapped_column(String(64), default="active")
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class RoutePolicy(Base):
    __tablename__ = "route_policies"

    route_policy_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    route_name: Mapped[str] = mapped_column(String(255), nullable=False)
    candidate_deployments: Mapped[str] = mapped_column(Text, default="[]")
    load_balancing_strategy: Mapped[str] = mapped_column(String(64), default="weighted")
    retry_policy: Mapped[str] = mapped_column(Text, default="{}")
    fallback_policy: Mapped[str] = mapped_column(Text, default="{}")
    timeout_policy: Mapped[str] = mapped_column(Text, default="{}")
    status: Mapped[str] = mapped_column(String(64), default="active")


class CachePolicy(Base):
    __tablename__ = "cache_policies"

    cache_policy_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scope: Mapped[str] = mapped_column(String(128), nullable=False)
    ttl_seconds: Mapped[int] = mapped_column(Integer, default=60)
    key_strategy: Mapped[str] = mapped_column(String(128), default="default")
    invalidation_strategy: Mapped[str] = mapped_column(String(128), default="ttl")
    privacy_mode: Mapped[str] = mapped_column(String(64), default="standard")
    status: Mapped[str] = mapped_column(String(64), default="active")


class WorkloadIdentityFederationProfile(Base):
    __tablename__ = "workload_identity_federation_profiles"

    workload_identity_profile_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    provider_type: Mapped[str] = mapped_column(String(64), nullable=False)
    audience: Mapped[str] = mapped_column(String(255), nullable=False)
    role_arn_or_equivalent: Mapped[str] = mapped_column(String(255), nullable=False)
    role_arn_or_equivalent_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    bootstrap_token_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    session_duration_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    allowed_subject_patterns: Mapped[str] = mapped_column(Text, default="[]")
    status: Mapped[str] = mapped_column(String(64), default="active")
    last_token_exchange_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class SecretProviderConfig(Base):
    __tablename__ = "secret_provider_configs"

    secret_provider_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    provider_type: Mapped[str] = mapped_column(String(64), nullable=False)
    provider_address: Mapped[str] = mapped_column(String(1024), nullable=False)
    provider_address_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    auth_method: Mapped[str] = mapped_column(String(128), nullable=False)
    auth_method_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    role_or_mount: Mapped[str] = mapped_column(String(255), nullable=False)
    role_or_mount_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    bootstrap_token_encrypted: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    secret_path_prefixes: Mapped[str] = mapped_column(Text, default="[]")
    lease_ttl_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    auto_renew_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(64), default="active")
    last_health_check_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class TenantCatalogEntry(Base):
    __tablename__ = "tenant_catalog_entries"
    __table_args__ = (
        Index("ix_tenant_catalog_status_type", "status", "tenant_type"),
    )

    tenant_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    tenant_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tenant_type: Mapped[str] = mapped_column(String(64), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(64), default="active")
    updated_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SupportedModelCatalogEntry(Base):
    __tablename__ = "supported_model_catalog_entries"
    __table_args__ = (
        Index("ix_supported_models_provider_model", "provider_type", "model_name", unique=True),
        Index("ix_supported_models_status_provider", "status", "provider_type"),
    )

    supported_model_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    provider_type: Mapped[str] = mapped_column(String(64), nullable=False)
    model_name: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    context_window_tokens: Mapped[int] = mapped_column(Integer, default=128000)
    status: Mapped[str] = mapped_column(String(64), default="active")
    description: Mapped[str] = mapped_column(Text, default="")
    updated_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DirectoryUser(Base):
    __tablename__ = "directory_users"
    __table_args__ = (
        Index("ix_directory_users_status_role", "status", "role_name"),
    )

    user_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    role_name: Mapped[str] = mapped_column(String(128), nullable=False)
    password_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(64), default="active")
    updated_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DirectoryGroup(Base):
    __tablename__ = "directory_groups"
    __table_args__ = (
        Index("ix_directory_groups_status", "status"),
    )

    group_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(64), default="active")
    updated_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DirectoryTeam(Base):
    __tablename__ = "directory_teams"
    __table_args__ = (
        Index("ix_directory_teams_status", "status"),
    )

    team_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(String(64), default="active")
    updated_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class DirectoryGroupMembership(Base):
    __tablename__ = "directory_group_memberships"
    __table_args__ = (
        Index("ix_directory_group_membership_unique", "group_id", "user_id", unique=True),
    )

    membership_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    group_id: Mapped[str] = mapped_column(String(128), nullable=False)
    user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class DirectoryTeamMembership(Base):
    __tablename__ = "directory_team_memberships"
    __table_args__ = (
        Index("ix_directory_team_membership_unique", "team_id", "user_id", unique=True),
    )

    membership_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    team_id: Mapped[str] = mapped_column(String(128), nullable=False)
    user_id: Mapped[str] = mapped_column(String(128), nullable=False)
    created_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class TenantSupportedModelEntitlement(Base):
    __tablename__ = "tenant_supported_model_entitlements"
    __table_args__ = (
        Index("ix_tenant_model_entitlements_lookup", "tenant_id", "provider_type", "status"),
        Index("ix_tenant_model_entitlements_unique", "tenant_id", "provider_type", "model_name", unique=True),
    )

    tenant_model_entitlement_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    provider_type: Mapped[str] = mapped_column(String(64), nullable=False)
    model_name: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(64), default="active")
    updated_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class SecretProviderLease(Base):
    __tablename__ = "secret_provider_leases"
    __table_args__ = (
        Index("ix_secret_provider_leases_provider_expiry", "secret_provider_id", "expires_at"),
    )

    lease_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    secret_provider_id: Mapped[str] = mapped_column(String(64), nullable=False)
    secret_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    lease_ttl_seconds: Mapped[int] = mapped_column(Integer, default=3600)
    issued_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    renewed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active")


class CostEvent(Base):
    __tablename__ = "cost_events"

    cost_event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    request_tag: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_scope: Mapped[str] = mapped_column(String(128), nullable=False)
    environment: Mapped[str] = mapped_column(String(64), default="dev")
    model_name: Mapped[str] = mapped_column(String(255), nullable=False)
    endpoint_family: Mapped[str] = mapped_column(String(128), nullable=False)
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    estimated_cost_cents: Mapped[int] = mapped_column(Integer, default=0)
    currency: Mapped[str] = mapped_column(String(8), default="USD")


class RouteMirrorExperimentEvent(Base):
    __tablename__ = "route_mirror_experiment_events"
    __table_args__ = (
        Index("ix_route_mirror_events_route_time", "route_policy_id", "timestamp"),
        Index("ix_route_mirror_events_request", "request_id", "mirror_provider_id"),
    )

    mirror_event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    route_policy_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    environment: Mapped[str] = mapped_column(String(64), default="dev")
    request_tag: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    requested_region: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    primary_provider_id: Mapped[str] = mapped_column(String(128), nullable=False)
    primary_outcome: Mapped[str] = mapped_column(String(64), nullable=False)
    mirror_provider_id: Mapped[str] = mapped_column(String(128), nullable=False)
    mirror_mode: Mapped[str] = mapped_column(String(32), default="shadow")
    mirror_outcome: Mapped[str] = mapped_column(String(64), default="mirrored_simulated")
    sample_percent: Mapped[int] = mapped_column(Integer, default=100)


class GatewayEntitlement(Base):
    __tablename__ = "gateway_entitlements"
    __table_args__ = (
        Index("ix_gateway_entitlements_action_scope", "action", "tenant_id", "environment"),
        Index("ix_gateway_entitlements_route_tag", "route_policy_id", "request_tag"),
    )

    entitlement_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    action: Mapped[str] = mapped_column(String(128), nullable=False)
    tenant_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    environment: Mapped[str] = mapped_column(String(64), default="dev")
    route_policy_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    request_tag: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    model_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    tool_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    allowed_roles: Mapped[str] = mapped_column(Text, default="[]")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class GatewayNhiInventory(Base):
    __tablename__ = "gateway_nhi_inventory"
    __table_args__ = (
        Index("ix_gateway_nhi_inventory_scope", "tenant_id", "environment", "status"),
        Index("ix_gateway_nhi_inventory_owner", "owner_scope_type", "owner_scope_id"),
        Index("ix_gateway_nhi_inventory_source_unique", "source_type", "source_id", unique=True),
    )

    nhi_record_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    source_type: Mapped[str] = mapped_column(String(64), nullable=False)
    source_id: Mapped[str] = mapped_column(String(128), nullable=False)
    identity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False)
    environment: Mapped[str] = mapped_column(String(64), default="dev")
    provider_type: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_scope_type: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    owner_scope_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    credential_last_rotated_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    credential_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    findings: Mapped[str] = mapped_column(Text, default="[]")
    status: Mapped[str] = mapped_column(String(64), default="active")
    updated_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class GatewayAccessReviewCampaign(Base):
    __tablename__ = "gateway_access_review_campaigns"
    __table_args__ = (
        Index("ix_gateway_access_review_campaign_scope", "environment", "status", "tenant_id"),
    )

    campaign_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    campaign_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tenant_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    environment: Mapped[str] = mapped_column(String(64), default="dev")
    include_disabled: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(64), default="open")
    reviewer_role: Mapped[str] = mapped_column(String(128), default="Security Approver")
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class GatewayAccessReviewItem(Base):
    __tablename__ = "gateway_access_review_items"
    __table_args__ = (
        Index("ix_gateway_access_review_item_campaign", "campaign_id", "decision"),
        Index("ix_gateway_access_review_item_entitlement", "entitlement_id"),
    )

    review_item_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    campaign_id: Mapped[str] = mapped_column(String(64), nullable=False)
    entitlement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    decision: Mapped[str] = mapped_column(String(64), default="pending")
    decision_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    decided_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    decided_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class GatewayJitAccessRequest(Base):
    __tablename__ = "gateway_jit_access_requests"
    __table_args__ = (
        Index("ix_gateway_jit_request_status_env", "status", "environment"),
        Index("ix_gateway_jit_request_entitlement", "entitlement_id"),
    )

    request_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    entitlement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    requester_id: Mapped[str] = mapped_column(String(128), nullable=False)
    requester_role: Mapped[str] = mapped_column(String(128), nullable=False)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    environment: Mapped[str] = mapped_column(String(64), default="dev")
    requested_duration_minutes: Mapped[int] = mapped_column(Integer, default=60)
    status: Mapped[str] = mapped_column(String(64), default="requested")
    approved_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    approved_role: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class GatewayLeastPrivilegeRecommendation(Base):
    __tablename__ = "gateway_least_privilege_recommendations"
    __table_args__ = (
        Index("ix_gateway_lpr_scope_status", "tenant_id", "environment", "status"),
        Index("ix_gateway_lpr_entitlement_type", "entitlement_id", "recommendation_type"),
    )

    recommendation_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    entitlement_id: Mapped[str] = mapped_column(String(64), nullable=False)
    tenant_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    environment: Mapped[str] = mapped_column(String(64), default="dev")
    recommendation_type: Mapped[str] = mapped_column(String(64), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, default=0.5)
    current_allowed_roles: Mapped[str] = mapped_column(Text, default="[]")
    proposed_allowed_roles: Mapped[str] = mapped_column(Text, default="[]")
    proposed_enabled: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    status: Mapped[str] = mapped_column(String(64), default="pending")
    created_by: Mapped[str] = mapped_column(String(128), default="system")
    applied_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    applied_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class BudgetPolicy(Base):
    __tablename__ = "budget_policies"

    budget_policy_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scope_type: Mapped[str] = mapped_column(String(64), nullable=False)
    scope_id: Mapped[str] = mapped_column(String(128), nullable=False)
    budget_amount_cents: Mapped[int] = mapped_column(Integer, nullable=False)
    window_type: Mapped[str] = mapped_column(String(32), default="daily")
    soft_limit_percent: Mapped[int] = mapped_column(Integer, default=80)
    hard_limit_percent: Mapped[int] = mapped_column(Integer, default=100)
    action_on_soft_limit: Mapped[str] = mapped_column(String(64), default="warn")
    action_on_hard_limit: Mapped[str] = mapped_column(String(64), default="block")
    reset_timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    reset_hour_local: Mapped[int] = mapped_column(Integer, default=0)
    temporary_increase_cents: Mapped[int] = mapped_column(Integer, default=0)
    temporary_increase_expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    soft_alert_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    last_soft_alert_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    rate_limit_tpm: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    rate_limit_rpm: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    session_iteration_cap: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    session_budget_cents: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(String(64), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class RouteDraft(Base):
    __tablename__ = "route_drafts"

    draft_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    route_policy_snapshot_id: Mapped[str] = mapped_column(String(128), nullable=False)
    environment: Mapped[str] = mapped_column(String(32), default="dev")
    status: Mapped[str] = mapped_column(String(64), default="draft")
    submitted_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    submitted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    approved_security: Mapped[bool] = mapped_column(Boolean, default=False)
    approved_ai_ops: Mapped[bool] = mapped_column(Boolean, default=False)
    state_version: Mapped[int] = mapped_column(Integer, default=1)
    rejection_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    promoted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class RouteDraftApprovalEvent(Base):
    __tablename__ = "route_draft_approval_events"

    approval_event_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    draft_id: Mapped[str] = mapped_column(String(64), nullable=False)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    state_from: Mapped[str] = mapped_column(String(64), nullable=False)
    state_to: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_role: Mapped[str] = mapped_column(String(128), nullable=False)
    decision: Mapped[str] = mapped_column(String(64), nullable=False)
    reason_code: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    evidence_refs: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    change_window_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    risk_ticket_ref: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    policy_simulation_status: Mapped[str] = mapped_column(String(64), default="pass")
    permission_policy_version: Mapped[str] = mapped_column(String(64), default="v1")
    occurred_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class PlaygroundRun(Base):
    __tablename__ = "playground_runs"

    run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    prompt_text: Mapped[str] = mapped_column(Text, nullable=False)
    candidate_models: Mapped[str] = mapped_column(Text, default="[]")
    selected_model: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(64), default="completed")
    estimated_cost_cents: Mapped[int] = mapped_column(Integer, default=0)
    policy_decision: Mapped[str] = mapped_column(String(64), default="allow")
    route_policy_snapshot_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class BenchmarkRun(Base):
    __tablename__ = "benchmark_runs"

    benchmark_run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    benchmark_suite: Mapped[str] = mapped_column(String(128), nullable=False)
    environment: Mapped[str] = mapped_column(String(32), default="dev")
    status: Mapped[str] = mapped_column(String(64), default="completed")
    score: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ScanRun(Base):
    __tablename__ = "scan_runs"

    scan_run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(128), nullable=False)
    environment: Mapped[str] = mapped_column(String(32), default="dev")
    status: Mapped[str] = mapped_column(String(64), default="completed")
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    severity_high_count: Mapped[int] = mapped_column(Integer, default=0)
    summary: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class PolicyScheduleJob(Base):
    __tablename__ = "policy_schedule_jobs"
    __table_args__ = (
        Index(
            "ix_policy_schedule_jobs_filter",
            "environment",
            "optimize_for",
            "enabled",
            "created_at",
        ),
    )

    job_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    environment: Mapped[str] = mapped_column(String(32), default="prod")
    optimize_for: Mapped[str] = mapped_column(String(32), default="balanced")
    max_routes: Mapped[int] = mapped_column(Integer, default=10)
    window_start_hour_utc: Mapped[int] = mapped_column(Integer, default=0)
    window_end_hour_utc: Mapped[int] = mapped_column(Integer, default=0)
    max_changes_without_approval: Mapped[int] = mapped_column(Integer, default=3)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_run_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class ScaleCertificationRun(Base):
    __tablename__ = "scale_certification_runs"
    __table_args__ = (
        Index("ix_scale_certification_runs_created", "created_at"),
        Index("ix_scale_certification_runs_certified", "certified", "created_at"),
    )

    certification_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    target_capacity: Mapped[int] = mapped_column(Integer, nullable=False)
    required_multi_region: Mapped[bool] = mapped_column(Boolean, default=True)
    cost_freshness_slo_seconds: Mapped[int] = mapped_column(Integer, default=60)
    readiness_score: Mapped[int] = mapped_column(Integer, default=0)
    scale_benchmark_pass: Mapped[bool] = mapped_column(Boolean, default=False)
    security_scan_pass: Mapped[bool] = mapped_column(Boolean, default=False)
    contract_validation_pass: Mapped[bool] = mapped_column(Boolean, default=False)
    cost_freshness_pass: Mapped[bool] = mapped_column(Boolean, default=False)
    multi_region_pass: Mapped[bool] = mapped_column(Boolean, default=False)
    certified: Mapped[bool] = mapped_column(Boolean, default=False)
    certified_user_capacity: Mapped[int] = mapped_column(Integer, default=10000)
    integrity_hash: Mapped[str] = mapped_column(String(255), default="")
    signature: Mapped[str] = mapped_column(String(255), default="")
    override_applied: Mapped[bool] = mapped_column(Boolean, default=False)
    override_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    override_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    override_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    executed_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ExecutionCheckpoint(Base):
    __tablename__ = "execution_checkpoints"
    __table_args__ = (
        Index("ix_execution_checkpoints_session_created", "session_id", "created_at"),
    )

    checkpoint_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    session_id: Mapped[str] = mapped_column(String(128), nullable=False)
    agent_id: Mapped[str] = mapped_column(String(64), nullable=False)
    stage_name: Mapped[str] = mapped_column(String(128), nullable=False)
    state_payload: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="active")
    created_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    resumed_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    resumed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    resume_count: Mapped[int] = mapped_column(Integer, default=0)


class ScaleLoadTestRun(Base):
    __tablename__ = "scale_load_test_runs"
    __table_args__ = (
        Index("ix_scale_load_test_runs_tier_created", "tier", "created_at"),
    )

    load_test_run_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tier: Mapped[str] = mapped_column(String(16), nullable=False)
    target_capacity: Mapped[int] = mapped_column(Integer, nullable=False)
    expected_concurrency: Mapped[int] = mapped_column(Integer, nullable=False)
    expected_rps: Mapped[int] = mapped_column(Integer, nullable=False)
    observed_peak_concurrency: Mapped[int] = mapped_column(Integer, nullable=False)
    observed_peak_rps: Mapped[int] = mapped_column(Integer, nullable=False)
    degradation_test_pass: Mapped[bool] = mapped_column(Boolean, default=False)
    recovery_test_pass: Mapped[bool] = mapped_column(Boolean, default=False)
    compliance_continuity_pass: Mapped[bool] = mapped_column(Boolean, default=False)
    passed: Mapped[bool] = mapped_column(Boolean, default=False)
    summary: Mapped[str] = mapped_column(Text, default="")
    executed_by: Mapped[str] = mapped_column(String(128), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class ComplianceControlMapping(Base):
    __tablename__ = "compliance_control_mappings"
    __table_args__ = (
        Index("ix_compliance_control_mappings_family", "control_family", "owner_team"),
    )

    control_id: Mapped[str] = mapped_column(String(128), primary_key=True)
    control_family: Mapped[str] = mapped_column(String(128), nullable=False)
    requirement_text: Mapped[str] = mapped_column(Text, nullable=False)
    applicable_components: Mapped[str] = mapped_column(Text, default="[]")
    required_evidence_types: Mapped[str] = mapped_column(Text, default="[]")
    automation_status: Mapped[str] = mapped_column(String(64), default="manual")
    owner_team: Mapped[str] = mapped_column(String(255), nullable=False)
    review_frequency: Mapped[str] = mapped_column(String(64), default="quarterly")


class RetentionPolicy(Base):
    __tablename__ = "retention_policies"
    __table_args__ = (
        Index("ix_retention_policies_data_class_jurisdiction", "data_class", "jurisdiction"),
    )

    policy_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    data_class: Mapped[str] = mapped_column(String(128), nullable=False)
    jurisdiction: Mapped[str] = mapped_column(String(64), nullable=False)
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False)
    deletion_mode: Mapped[str] = mapped_column(String(64), default="soft_delete")
    legal_hold_supported: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(64), default="active")
    updated_by: Mapped[str] = mapped_column(String(128), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


class LegalHold(Base):
    __tablename__ = "legal_holds"
    __table_args__ = (
        Index("ix_legal_holds_status_created", "status", "placed_at"),
    )

    hold_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    data_class: Mapped[str] = mapped_column(String(128), nullable=False)
    jurisdiction: Mapped[str] = mapped_column(String(64), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    scope_ref: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(64), default="active")
    placed_by: Mapped[str] = mapped_column(String(128), nullable=False)
    placed_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    released_by: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    released_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class ComplianceEvidenceArtifact(Base):
    __tablename__ = "compliance_evidence_artifacts"
    __table_args__ = (
        Index("ix_compliance_evidence_control_created", "control_id", "generated_at"),
    )

    evidence_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    control_id: Mapped[str] = mapped_column(String(128), nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    generated_by: Mapped[str] = mapped_column(String(128), nullable=False)
    source_type: Mapped[str] = mapped_column(String(128), nullable=False)
    source_id: Mapped[str] = mapped_column(String(128), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), default="v1")
    artifact_uri: Mapped[str] = mapped_column(String(1024), nullable=False)
    integrity_hash: Mapped[str] = mapped_column(String(255), nullable=False)


class RuntimeConfig(Base):
    __tablename__ = "runtime_configs"

    config_key: Mapped[str] = mapped_column(String(255), primary_key=True)
    config_value: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, default="")
    updated_by: Mapped[str] = mapped_column(String(128), default="system")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class OpenAIResponseRecord(Base):
    __tablename__ = "openai_response_records"
    __table_args__ = (
        Index("ix_openai_response_records_actor_created", "actor_id", "created_at"),
        Index("ix_openai_response_records_status_created", "status", "created_at"),
    )

    response_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    environment: Mapped[str] = mapped_column(String(64), default="dev")
    model_name: Mapped[str] = mapped_column(String(255), nullable=False)
    output_payload: Mapped[str] = mapped_column(Text, nullable=False)
    output_text: Mapped[str] = mapped_column(Text, default="")
    input_tokens: Mapped[int] = mapped_column(Integer, default=0)
    output_tokens: Mapped[int] = mapped_column(Integer, default=0)
    total_tokens: Mapped[int] = mapped_column(Integer, default=0)
    selected_provider_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    route_policy_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class OpenAIFileRecord(Base):
    __tablename__ = "openai_file_records"
    __table_args__ = (
        Index("ix_openai_file_records_actor_created", "actor_id", "created_at"),
        Index("ix_openai_file_records_status_created", "status", "created_at"),
    )

    file_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    request_id: Mapped[str] = mapped_column(String(128), nullable=False)
    trace_id: Mapped[str] = mapped_column(String(128), nullable=False)
    actor_id: Mapped[str] = mapped_column(String(128), nullable=False)
    environment: Mapped[str] = mapped_column(String(64), default="dev")
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    purpose: Mapped[str] = mapped_column(String(128), nullable=False)
    bytes: Mapped[int] = mapped_column(Integer, default=0)
    content_type: Mapped[str] = mapped_column(String(128), default="application/octet-stream")
    metadata_json: Mapped[str] = mapped_column(Text, default="{}")
    status: Mapped[str] = mapped_column(String(32), default="uploaded")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    deleted_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
