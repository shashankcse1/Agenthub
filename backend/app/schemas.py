from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.logging_utils import get_logger
from app.policy_constants import (
    DEFAULT_BASIC_AUTH_ENABLE_DURATION_MINUTES,
    DEFAULT_BASIC_AUTH_MAX_ENABLE_DURATION_MINUTES,
    DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES,
    DEFAULT_SESSION_TTL_MINUTES,
    MAX_SESSION_IDLE_TIMEOUT_MINUTES,
    MAX_SESSION_TTL_MINUTES,
    MIN_SESSION_IDLE_TIMEOUT_MINUTES,
    MIN_SESSION_TTL_MINUTES,
)

logger = get_logger(__name__)


class ORMBase(BaseModel):
    model_config = {"from_attributes": True, "protected_namespaces": ()}


class AgentRegisterRequest(BaseModel):
    name: str
    owner_id: str
    owner_name: str
    owner_team: str
    agent_type: str = "other"
    description: str = ""
    risk_tier: str


class AgentResponse(ORMBase):
    agent_id: str
    name: str
    owner_id: str
    owner_name: str
    owner_team: str
    agent_type: str
    description: str
    risk_tier: str
    status: str
    created_at: datetime


class AgentRegisterOptionsResponse(BaseModel):
    allowed_agent_types: list[str]
    provider_backed_agent_types: list[str] = []
    default_environment: str = "dev"


class AgentConfigUpsertRequest(BaseModel):
    config_id: Optional[str] = None
    agent_key: str
    display_name: str
    provider: str
    model: str
    provider_priority: Optional[str] = ""
    temperature: float = 0.3
    max_tokens: int = 1024
    timeout_ms: int = 4500
    fallback_enabled: bool = True
    max_fallback_hops: int = 2
    global_timeout_ms: int = 4500
    retry_budget: int = 1
    failure_threshold_percent: int = 40
    cooldown_seconds: int = 60
    environment: str = "dev"
    enabled: bool = True
    notes: Optional[str] = ""
    credential_binding_id: Optional[str] = None


class AgentConfigResponse(ORMBase):
    config_id: str
    agent_key: str
    display_name: str
    provider: str
    model: str
    provider_priority: str
    temperature: float
    max_tokens: int
    timeout_ms: int
    fallback_enabled: bool
    max_fallback_hops: int
    global_timeout_ms: int
    retry_budget: int
    failure_threshold_percent: int
    cooldown_seconds: int
    environment: str
    enabled: bool
    notes: str
    credential_binding_id: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class AgentConfigCredentialStatusResponse(BaseModel):
    agent_key: str
    provider: str
    environment: str
    credential_binding_id: Optional[str] = None
    configured: bool
    credential_plane: Optional[str] = None
    masked_hint: Optional[str] = None
    provider_type: str
    secret_provider_id: Optional[str] = None
    secret_ref: Optional[str] = None
    workload_identity_profile_id: Optional[str] = None


class OwnershipTransferRequest(BaseModel):
    new_owner_id: str
    new_owner_name: str
    new_owner_team: str
    reason: str
    ticket_ref: str


class OwnershipEventResponse(ORMBase):
    event_id: str
    agent_id: str
    old_owner_id: str
    new_owner_id: str
    changed_by: str
    reason: str
    ticket_ref: str
    changed_at: datetime


class SSOProviderCreateRequest(BaseModel):
    tenant_id: str
    protocol_type: str = Field(pattern="^(OIDC|SAML)$")
    issuer_or_entity_id: str
    jwks_or_metadata_url: str
    scim_base_url: str
    role_mapping_rules: str = "{}"
    mfa_required_roles: str = "[]"
    session_policy_id: str = "default"


class SSOProviderUpdateRequest(BaseModel):
    jwks_or_metadata_url: Optional[str] = None
    scim_base_url: Optional[str] = None
    role_mapping_rules: Optional[str] = None
    mfa_required_roles: Optional[str] = None
    session_policy_id: Optional[str] = None
    status: Optional[str] = None


class RoleBindingValidateRequest(BaseModel):
    role_name: str
    resource_pattern: str
    action: str


class AuthAuthorizationExplainRequest(BaseModel):
    actor_role: str = Field(min_length=1)
    actor_id: str = Field(default="explain-actor", min_length=1)
    action: str = Field(min_length=1)
    resource_type: str = "auth_action"
    resource_id: Optional[str] = None
    target_actor_id: Optional[str] = None
    target_actor_role: Optional[str] = None
    approver_role: Optional[str] = None
    approver_id: Optional[str] = None
    mfa_verified: bool = False


class AuthAuthorizationExplainResponse(BaseModel):
    actor_role: str
    actor_id: str
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    decision: str
    decision_trace_id: str
    policy_version: str = "v1"
    allowed_roles: list[str]
    requires_mfa: bool
    requires_dual_approval: bool
    required_approver_role: Optional[str] = None
    reasons: list[str]
    remediation_hint: str


class DirectoryUserUpsertRequest(BaseModel):
    user_id: str
    display_name: str
    email: str
    role_name: str
    status: str = Field(default="active", pattern="^(active|inactive)$")
    password: Optional[str] = Field(default=None, min_length=12, max_length=256)


class DirectoryUserResponse(ORMBase):
    user_id: str
    display_name: str
    email: str
    role_name: str
    status: str
    failed_login_attempts: int = 0
    locked_until: Optional[datetime] = None
    last_login_at: Optional[datetime] = None
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class DirectoryUserUnlockResponse(BaseModel):
    user_id: str
    unlocked: bool


class DirectoryUserLockResponse(BaseModel):
    user_id: str
    locked: bool
    locked_until: Optional[datetime] = None


class DirectoryUserDisableResponse(BaseModel):
    user_id: str
    disabled: bool


class DirectoryUserEnableResponse(BaseModel):
    user_id: str
    enabled: bool


class DirectoryGroupUpsertRequest(BaseModel):
    group_id: str
    display_name: str
    description: str = Field(default="", max_length=500)
    status: str = Field(default="active", pattern="^(active|inactive)$")


class DirectoryGroupResponse(ORMBase):
    group_id: str
    display_name: str
    description: str
    status: str
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class DirectoryTeamUpsertRequest(BaseModel):
    team_id: str
    display_name: str
    description: str = Field(default="", max_length=500)
    status: str = Field(default="active", pattern="^(active|inactive)$")


class DirectoryTeamResponse(ORMBase):
    team_id: str
    display_name: str
    description: str
    status: str
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class DirectoryGroupMembershipResponse(ORMBase):
    membership_id: str
    group_id: str
    user_id: str
    created_by: Optional[str] = None
    created_at: datetime


class DirectoryTeamMembershipResponse(ORMBase):
    membership_id: str
    team_id: str
    user_id: str
    created_by: Optional[str] = None
    created_at: datetime


class AuthSessionPolicyConfigResponse(BaseModel):
    policy_id: str
    session_read_roles: list[str]
    session_issuer_roles: list[str]
    issuable_session_roles: list[str]
    cross_actor_dual_approval_roles: list[str]
    dual_approval_required_approver_role: str
    description: str = ""
    privileged_mfa_reauth_minutes: int
    source: Literal["default", "database"]


class AuthSessionPolicyConfigUpdateRequest(BaseModel):
    session_read_roles: Optional[list[str]] = None
    session_issuer_roles: Optional[list[str]] = None
    issuable_session_roles: Optional[list[str]] = None
    cross_actor_dual_approval_roles: Optional[list[str]] = None
    dual_approval_required_approver_role: Optional[str] = None
    description: Optional[str] = Field(default=None, max_length=500)
    privileged_mfa_reauth_minutes: Optional[int] = Field(default=None, ge=1, le=1440)


class AuthSessionPolicyRevisionResponse(BaseModel):
    revision_id: str
    policy_id: str
    session_read_roles: list[str]
    session_issuer_roles: list[str]
    issuable_session_roles: list[str]
    cross_actor_dual_approval_roles: list[str]
    dual_approval_required_approver_role: str
    description: str = ""
    privileged_mfa_reauth_minutes: int
    changed_by: str
    change_reason: str
    source_revision_id: Optional[str] = None
    created_at: datetime


class AuthSessionPolicyRollbackRequest(BaseModel):
    revision_id: str
    change_reason: str = Field(default="rollback")


class BasicAuthConfigCreateRequest(BaseModel):
    tenant_id: str
    environment: str
    allowed_user_groups: str = "[]"
    ip_allowlist: str = "[]"
    max_enable_duration_minutes: int = Field(
        default=DEFAULT_BASIC_AUTH_MAX_ENABLE_DURATION_MINUTES,
        ge=1,
        le=90 * 24 * 60,
    )


class BasicAuthConfigUpdateRequest(BaseModel):
    allowed_user_groups: Optional[str] = None
    ip_allowlist: Optional[str] = None
    max_enable_duration_minutes: Optional[int] = Field(default=None, ge=1, le=90 * 24 * 60)


class BasicAuthEnableRequest(BaseModel):
    break_glass_reason: str
    duration_minutes: int = Field(
        default=DEFAULT_BASIC_AUTH_ENABLE_DURATION_MINUTES,
        ge=1,
        le=90 * 24 * 60,
    )


class SessionCreateRequest(BaseModel):
    actor_id: str
    actor_role: str
    ttl_minutes: int = Field(default=DEFAULT_SESSION_TTL_MINUTES, ge=MIN_SESSION_TTL_MINUTES, le=MAX_SESSION_TTL_MINUTES)
    idle_timeout_minutes: int = Field(
        default=DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES,
        ge=MIN_SESSION_IDLE_TIMEOUT_MINUTES,
        le=MAX_SESSION_IDLE_TIMEOUT_MINUTES,
    )
    mfa_verified: bool = False


class SessionIssueResponse(BaseModel):
    session_id: str
    token_type: str
    access_token: str
    expires_at: datetime


class SessionLoginRequest(BaseModel):
    username: str
    password: str = Field(min_length=12, max_length=256)
    ttl_minutes: int = Field(default=DEFAULT_SESSION_TTL_MINUTES, ge=MIN_SESSION_TTL_MINUTES, le=MAX_SESSION_TTL_MINUTES)
    idle_timeout_minutes: int = Field(
        default=DEFAULT_SESSION_IDLE_TIMEOUT_MINUTES,
        ge=MIN_SESSION_IDLE_TIMEOUT_MINUTES,
        le=MAX_SESSION_IDLE_TIMEOUT_MINUTES,
    )


class SessionLoginResponse(SessionIssueResponse):
    actor_id: str
    actor_role: str
    csrf_token: Optional[str] = None


class SessionResponse(ORMBase):
    session_id: str
    actor_id: str
    actor_role: str
    created_at: datetime
    last_activity_at: datetime
    expires_at: datetime


class AuditEventResponse(ORMBase):
    audit_event_id: str
    timestamp: datetime
    actor_type: str
    actor_id: str
    actor_login: Optional[str] = None
    actor_role: Optional[str] = None
    action_description: Optional[str] = None
    action_type: str
    resource_type: str
    resource_id: str
    trace_id: str
    decision_outcome: Literal["allow", "deny", "warn"]
    policy_version: str
    action_context: dict[str, Any] = Field(default_factory=dict)
    user_prompt: Optional[str] = None


class DiscoverySourceResponse(BaseModel):
    source_id: str
    platform: str
    category: str
    label: str
    status: str
    last_sync_at: Optional[datetime] = None
    sync_lag_minutes: Optional[int] = None
    discovered_count: int = 0
    connection_count: int = 0
    active_connection_count: int = 0
    well_known: bool = False
    priority: bool = False


class DiscoveryConnectionPresetResponse(BaseModel):
    source_id: str
    connection_name: str
    secret_ref: str
    base_url: str = ""
    connection_config: dict = Field(default_factory=dict)


class DiscoveryConnectionPresetsResponse(BaseModel):
    priority_source_ids: list[str]
    well_known_source_ids: list[str]
    presets: list[DiscoveryConnectionPresetResponse]


class DiscoveryDuplicateMemberResponse(BaseModel):
    discovered_agent_id: str
    source_system: str
    discovery_confidence: int
    canonical_agent_key: str


class DiscoveryDuplicateGroupResponse(BaseModel):
    canonical_agent_key: str
    duplicate_count: int
    source_systems: list[str]
    discovered_agent_ids: list[str]
    max_confidence: int
    review_priority: str
    members: list[DiscoveryDuplicateMemberResponse] = Field(default_factory=list)


class DiscoveryDuplicateMergeRequest(BaseModel):
    canonical_discovered_agent_id: str
    merge_discovered_agent_ids: list[str] = Field(default_factory=list)


class DiscoveryDuplicateMergeResponse(BaseModel):
    canonical_discovered_agent_id: str
    canonical_agent_key: str
    merged_discovered_agent_ids: list[str]
    merged_count: int
    discovery_confidence: int
    status: str


class DiscoveryDuplicateDismissRequest(BaseModel):
    discovered_agent_id: str
    reason: str = ""


class DiscoveryConnectionCreateRequest(BaseModel):
    tenant_id: str
    source_id: str
    connection_name: str
    enabled: bool = True
    sync_interval_minutes: int = Field(default=60, ge=5, le=10080)
    credential_binding_id: Optional[str] = None
    secret_provider_id: Optional[str] = None
    secret_ref: Optional[str] = None
    base_url: str = ""
    connection_config: dict = Field(default_factory=dict)


class DiscoveryConnectionUpdateRequest(BaseModel):
    connection_name: Optional[str] = None
    enabled: Optional[bool] = None
    sync_interval_minutes: Optional[int] = Field(default=None, ge=5, le=10080)
    status: Optional[str] = None
    credential_binding_id: Optional[str] = None
    secret_provider_id: Optional[str] = None
    secret_ref: Optional[str] = None
    base_url: Optional[str] = None
    connection_config: Optional[dict] = None


class DiscoveryConnectionResponse(ORMBase):
    connection_id: str
    tenant_id: str
    source_id: str
    connection_name: str
    status: str
    enabled: bool
    sync_interval_minutes: int
    next_sync_at: datetime
    last_sync_at: Optional[datetime] = None
    last_sync_status: str
    last_sync_error: str = ""
    last_discovered_count: int = 0
    credential_binding_id: Optional[str] = None
    secret_provider_id: Optional[str] = None
    secret_ref: Optional[str] = None
    base_url: str = ""
    connection_config: dict = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
    updated_by: Optional[str] = None


class DiscoveryConnectionTestResponse(BaseModel):
    connection_id: str
    test_status: str
    message: str
    sample_count: int = 0


class DiscoveryConnectionSyncResponse(BaseModel):
    connection_id: str
    sync_status: str
    discovered_count: int = 0
    error: str = ""

class DiscoveryPromoteQueueResponse(BaseModel):
    discovered_agent_id: str
    canonical_agent_key: str
    source_system: str
    discovery_confidence: int
    discovery_status: str
    last_discovered_at: datetime
    queue_reason: str


class DiscoverySummaryCategoryResponse(BaseModel):
    category: str
    source_count: int
    discovered_count: int
    healthy_count: int
    stale_count: int


class DiscoverySummaryTopologyNode(BaseModel):
    node_id: str
    label: str
    count: int
    tone: str


class DiscoverySummaryTriageItem(BaseModel):
    item_type: Literal["conflict", "alert", "promote"]
    discovered_agent_id: str
    detail: str
    urgency: str
    discovery_confidence: int


class DiscoveryConfidenceBucketResponse(BaseModel):
    label: str
    count: int


class DiscoverySummaryResponse(BaseModel):
    generated_at: datetime
    discovered_agent_count: int
    healthy_sources: int
    stale_sources: int
    unknown_sources: int
    connection_count: int
    active_connection_count: int
    conflict_count: int
    high_alert_count: int
    promote_ready_count: int
    duplicate_group_count: int
    posture_score: int = 100
    confidence_buckets: list[DiscoveryConfidenceBucketResponse] = Field(default_factory=list)
    categories: list[DiscoverySummaryCategoryResponse]
    topology: list[DiscoverySummaryTopologyNode]
    urgent_triage: list[DiscoverySummaryTriageItem]


class DiscoveryRecordResponse(ORMBase):
    discovered_agent_id: str
    canonical_agent_key: str
    source_system: str
    source_fingerprint: str
    discovery_confidence: int
    discovery_status: str
    promoted_to_agent_id: Optional[str] = None
    merged_into_discovered_agent_id: Optional[str] = None
    last_discovered_at: datetime


class DiscoveryConflictResponse(BaseModel):
    discovered_agent_id: str
    canonical_agent_key: str
    source_system: str
    discovery_confidence: int
    discovery_status: str
    last_discovered_at: datetime
    conflict_reason: str
    review_priority: str


class DiscoveryAlertResponse(BaseModel):
    alert_id: str
    discovered_agent_id: str
    source_system: str
    discovery_confidence: int
    severity: str
    alert_type: str
    message: str
    last_discovered_at: datetime


class DiscoveryResolveRequest(BaseModel):
    discovered_agent_id: str
    decision: str


class ModuleRegisterRequest(BaseModel):
    module_name: str
    module_type: str
    version: str
    contract_version: str
    owner_team: str
    compatibility_range: str = "*"
    required_permissions: str = "[]"
    artifact_signature: str
    provenance_ref: str
    security_review_ticket: str = ""
    integration_provider: str = ""
    integration_reference: str = ""


class ModuleResponse(ORMBase):
    module_id: str
    module_name: str
    module_type: str
    version: str
    contract_version: str
    owner_team: str
    compatibility_range: str
    required_permissions: str
    artifact_signature: str
    provenance_ref: str
    security_review_ticket: str
    integration_provider: str
    integration_reference: str
    integration_sync_status: str
    integration_last_synced_at: Optional[datetime] = None
    replacement_module_id: Optional[str] = None
    migration_guidance: str
    deprecation_timeline: str
    deprecated_at: Optional[datetime] = None
    status: str


class AgentModuleActionRequest(BaseModel):
    module_id: str
    pinned_version: str
    config_hash: str


class ModuleDeprecateRequest(BaseModel):
    migration_guidance: str = Field(min_length=1)
    deprecation_timeline: str = Field(min_length=1)
    replacement_module_id: Optional[str] = None


class ModuleIntegrationSyncRequest(BaseModel):
    integration_reference: Optional[str] = None


class ModuleIntegrationSyncResponse(BaseModel):
    module_id: str
    integration_provider: str
    integration_reference: str
    integration_sync_status: str
    integration_last_synced_at: datetime


class KeyCreateRequest(BaseModel):
    owner_scope_type: str
    owner_scope_id: str
    allowed_endpoint_families: str = "[]"
    allowed_models: str = "[]"
    guardrail_policy: str = "{}"
    budget_policy_id: Optional[str] = Field(default="default", max_length=64)
    rate_limit_policy_id: Optional[str] = Field(default="default", max_length=64)
    expires_at: Optional[datetime] = Field(
        default=None,
        description="Portkey-style virtual key expiry (UTC). Null means no expiry.",
    )
    authn_method: Optional[str] = Field(default="token", max_length=64)


class KeyUpdateRequest(BaseModel):
    allowed_endpoint_families: Optional[str] = None
    allowed_models: Optional[str] = None
    guardrail_policy: Optional[str] = None
    status: Optional[str] = None
    budget_policy_id: Optional[str] = Field(default=None, max_length=64)
    rate_limit_policy_id: Optional[str] = Field(default=None, max_length=64)
    expires_at: Optional[datetime] = Field(
        default=None,
        description="Portkey-style virtual key expiry (UTC). Omit to leave unchanged.",
    )
    authn_method: Optional[str] = Field(default=None, max_length=64)


class KeyResponse(ORMBase):
    key_id: str
    owner_scope_type: str
    owner_scope_id: str
    allowed_endpoint_families: str
    allowed_models: str
    guardrail_policy: str
    budget_policy_id: str = "default"
    rate_limit_policy_id: str = "default"
    status: str
    expires_at: Optional[datetime] = None
    authn_method: str = "token"
    jit_request_id: Optional[str] = None


class KeyLifecycleActionResponse(BaseModel):
    key_id: str
    status: str
    action: str


class KeyBudgetIncreaseTemporaryRequest(BaseModel):
    environment: str = "dev"
    increase_cents: int = Field(ge=1, le=100000000)
    duration_minutes: int = Field(default=60, ge=1, le=10080)
    reason: str = Field(default="operator-request", min_length=3, max_length=256)


class KeyBudgetIncreaseTemporaryResponse(BaseModel):
    key_id: str
    environment: str
    increase_cents: int
    duration_minutes: int
    reason: str
    active: bool
    requested_by: str
    requested_at: str
    expires_at: str


class KeyRotationScheduleRequest(BaseModel):
    environment: str = "dev"
    interval_hours: int = Field(default=24, ge=1, le=720)
    enabled: bool = True
    reason: str = Field(default="scheduled-rotation", min_length=3, max_length=256)


class KeyRotationScheduleUpdateRequest(BaseModel):
    interval_hours: Optional[int] = Field(default=None, ge=1, le=720)
    enabled: Optional[bool] = None
    reason: Optional[str] = Field(default=None, min_length=3, max_length=256)


class KeyRotationScheduleResponse(BaseModel):
    key_id: str
    schedule_id: str
    environment: str
    interval_hours: int
    enabled: bool
    reason: str
    created_by: str
    created_at: str
    updated_at: str
    last_run_at: Optional[str] = None
    next_run_at: Optional[str] = None


class KeyRotationScheduleExecuteResponse(BaseModel):
    key_id: str
    schedule_id: str
    rotation_status: str
    environment: str
    executed_at: str
    next_run_at: str


class KeyRotationScheduleTickResponse(BaseModel):
    scanned_keys: int
    due_schedules: int
    executed: list[KeyRotationScheduleExecuteResponse]
    skipped_prod: int
    skipped_disabled: int
    executed_at: str


class KeyGuardrailEvaluateRequest(BaseModel):
    environment: str = "dev"
    stage: str = Field(default="input", pattern="^(input|output)$")
    policy_mode: str = Field(default="block", pattern="^(block|warn|monitor)$")
    requests_last_minute: int = Field(default=0, ge=0)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    owner_scope_id: Optional[str] = None
    mfa_verified: bool = False


class KeyGuardrailEvaluateResponse(BaseModel):
    key_id: str
    decision: str
    reasons: list[str]
    applied_guardrails: list[str]


class GuardrailConfigResponse(BaseModel):
    """Portkey-style guardrail config view (virtual-key policy; never exposes secrets)."""

    guardrail_id: str
    key_id: str
    status: str
    owner_scope_type: str
    owner_scope_id: str
    policy: dict[str, object] = Field(default_factory=dict)
    policy_mode: Optional[str] = None
    has_policy: bool = False


class PlaygroundRunFeedbackCreateRequest(BaseModel):
    trace_id: str
    rating: int = Field(ge=1, le=5)
    quality_score: float = Field(ge=0, le=1)
    comment: str = ""


class PlaygroundRunAssessRequest(BaseModel):
    response_text: Optional[str] = None
    environment: str = "dev"
    trace_id: Optional[str] = None


class PlaygroundRunAssessResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    run_id: str
    model_name: str
    trace_id: str
    quality_score: float
    quality_tier: str
    score_reason: str
    suggested_rating: int
    suggested_comment: str
    response_preview: str
    response_text: str
    inference_ran: bool


class PlaygroundRunFeedbackResponse(ORMBase):
    feedback_id: str
    run_id: str
    trace_id: str
    rating: int
    quality_score: float
    comment: str
    created_by: str
    created_at: datetime


class PlaygroundQualityTriageItemResponse(BaseModel):
    feedback_id: str
    run_id: str
    trace_id: str
    rating: int
    quality_score: float
    comment: str
    created_by: str
    created_at: datetime
    run_actor_id: str
    selected_model: str
    run_status: str
    priority_tag: str
    triage_reason: str


class PlaygroundQualityTriageQueueResponse(BaseModel):
    total: int
    items: list[PlaygroundQualityTriageItemResponse]


class PlaygroundQualityEscalationCreateRequest(BaseModel):
    severity: str = Field(default="high", pattern="^(low|medium|high|critical)$")
    priority_tag: str = Field(default="p1", pattern="^(p0|p1|p2)$")
    assigned_team: str = Field(default="ai-trust-ops", min_length=1, max_length=128)
    escalation_channel: str = Field(default="security-ops", min_length=1, max_length=128)
    escalation_reason: str = Field(min_length=1, max_length=2000)
    external_ticket_ref: Optional[str] = Field(default=None, max_length=128)
    sla_target_minutes: int = Field(default=60, ge=15, le=10080)


class PlaygroundQualityEscalationResolveRequest(BaseModel):
    resolution_note: str = Field(min_length=1, max_length=2000)


class PlaygroundQualityEscalationResponse(ORMBase):
    escalation_id: str
    feedback_id: str
    run_id: str
    trace_id: str
    run_actor_id: str
    status: str
    severity: str
    priority_tag: str
    assigned_team: str
    escalation_channel: str
    external_ticket_ref: Optional[str]
    escalation_reason: str
    sla_target_minutes: int
    due_at: datetime
    acknowledged_by: Optional[str]
    acknowledged_at: Optional[datetime]
    resolved_by: Optional[str]
    resolved_at: Optional[datetime]
    resolution_note: Optional[str]
    created_by: str
    created_at: datetime
    updated_at: datetime


class PlaygroundQualityEscalationQueueResponse(BaseModel):
    total: int
    overdue: int
    items: list[PlaygroundQualityEscalationResponse]


class PlaygroundQualityEscalationNotifyRequest(BaseModel):
    channel: str = Field(default="security-ops", min_length=1, max_length=128)
    destination: str = Field(min_length=1, max_length=255)
    message_prefix: str = Field(default="Playground quality escalation", min_length=1, max_length=255)


class PlaygroundQualityEscalationNotifyResponse(BaseModel):
    escalation_id: str
    notified: bool
    channel: str
    destination: str
    notified_at: datetime
    attempts: int
    receipt_id: str
    delivery_status: str
    error_message: Optional[str] = None
    message: str


class PlaygroundQualityAnalyticsBucketResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    bucket_start: datetime
    bucket_end: datetime
    provider_id: str
    route_policy_id: str
    model_name: str
    sample_count: int
    average_quality_score: float
    average_rating: float
    critical_count: int
    elevated_count: int


class PlaygroundQualityAnalyticsRollupResponse(BaseModel):
    window_hours: int
    bucket_hours: int
    total_samples: int
    buckets: list[PlaygroundQualityAnalyticsBucketResponse]


class CostModelCatalogItemResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    supported_model_id: str
    provider_type: str
    model_name: str
    display_name: str
    context_window_tokens: int
    status: str
    input_cents_per_1k: float
    output_cents_per_1k: float
    provider_multiplier: float
    endpoint_multiplier: float
    provider_discount_percent: float
    model_discount_percent: float
    estimated_average_cost_cents_per_1k: float
    ranking_score: float


class CostModelCatalogResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    catalog: list[CostModelCatalogItemResponse]
    default_model_rates: dict[str, float]
    provider_multipliers: dict[str, float]
    endpoint_multipliers: dict[str, float]
    provider_discounts: dict[str, float]
    model_discounts: dict[str, float]


class RoutePolicyRequest(BaseModel):
    route_name: str
    candidate_deployments: str = "[]"
    load_balancing_strategy: str = Field(default="weighted", pattern="^(weighted|lowest_cost|lowest_latency|adaptive|least_busy)$")
    retry_policy: str = "{}"
    fallback_policy: str = "{}"
    timeout_policy: str = "{}"


class RoutePolicyResponse(ORMBase):
    route_policy_id: str
    route_name: str
    candidate_deployments: str
    load_balancing_strategy: str
    retry_policy: str
    fallback_policy: str
    timeout_policy: str
    status: str


class GatewayOpenAIModelItem(BaseModel):
    id: str
    object: str = "model"
    owned_by: str
    created: int = 0


class GatewayOpenAIModelListResponse(BaseModel):
    object: str = "list"
    data: list[GatewayOpenAIModelItem]
    count: int


class RouteOptimizeRequest(BaseModel):
    optimize_for: str = Field(default="balanced", pattern="^(balanced|cost|latency)$")
    environment: str = "prod"


class RouteOptimizeResponse(BaseModel):
    route_policy_id: str
    optimize_for: str
    recommended_strategy: str
    estimated_latency_delta_percent: float
    estimated_cost_delta_percent: float
    updated: bool


class RouteProviderPriorityUpdateRequest(BaseModel):
    tenant_id: str
    environment: str = "prod"
    request_tag: Optional[str] = Field(default=None, max_length=64)
    priority_order: str = "[]"
    global_timeout_ms: int = Field(default=4500, ge=100, le=120000)
    max_fallback_hops: int = Field(default=2, ge=0, le=10)
    health_check_enabled: bool = False
    budget_limit_cents: Optional[int] = Field(default=None, ge=1)


class RouteProviderPriorityResponse(BaseModel):
    route_policy_id: str
    tenant_id: str
    environment: str
    request_tag: Optional[str] = None
    priority_order: str
    global_timeout_ms: int
    max_fallback_hops: int
    health_check_enabled: bool = False
    budget_limit_cents: Optional[int] = None
    updated: bool


class RouteProviderHealthEntry(BaseModel):
    provider_id: str
    status: str = Field(default="healthy", pattern="^(healthy|degraded|unhealthy)$")
    latency_ms: Optional[int] = Field(default=None, ge=0)
    error_rate_percent: Optional[float] = Field(default=None, ge=0, le=100)
    inflight_requests: Optional[int] = Field(default=None, ge=0)
    rate_limit_remaining_percent: Optional[float] = Field(default=None, ge=0, le=100)
    checked_at: Optional[str] = None


class RouteProviderHealthUpdateRequest(BaseModel):
    request_tag: Optional[str] = Field(default=None, max_length=64)
    entries: list[RouteProviderHealthEntry] = Field(default_factory=list)


class RouteProviderHealthResponse(BaseModel):
    route_policy_id: str
    request_tag: Optional[str] = None
    entries: list[RouteProviderHealthEntry]


class RouteFallbackPolicyRequest(BaseModel):
    tenant_id: str
    environment: str = "prod"
    request_tag: Optional[str] = Field(default=None, max_length=64)
    priority_order: str = "[]"
    global_timeout_ms: int = Field(default=4500, ge=100, le=120000)
    max_fallback_hops: int = Field(default=2, ge=0, le=10)
    health_check_enabled: bool = False
    budget_limit_cents: Optional[int] = Field(default=None, ge=1)


class RouteFallbackPolicyResponse(BaseModel):
    route_policy_id: str
    tenant_id: str
    environment: str
    request_tag: Optional[str] = None
    priority_order: str
    global_timeout_ms: int
    max_fallback_hops: int
    health_check_enabled: bool = False
    budget_limit_cents: Optional[int] = None


class RoutePreCallFiltersRequest(BaseModel):
    tenant_id: str
    environment: str = "prod"
    request_tag: Optional[str] = Field(default=None, max_length=64)
    allowed_regions: str = "[]"
    min_context_window_tokens: Optional[int] = Field(default=None, ge=0, le=2_000_000)
    max_context_window_tokens: Optional[int] = Field(default=None, ge=1, le=2_000_000)
    enforce: bool = True


class RoutePreCallFiltersResponse(BaseModel):
    route_policy_id: str
    tenant_id: str
    environment: str
    request_tag: Optional[str] = None
    allowed_regions: str
    min_context_window_tokens: Optional[int] = None
    max_context_window_tokens: Optional[int] = None
    enforce: bool = True


class RouteOutputGuardrailsRequest(BaseModel):
    tenant_id: str
    environment: str = "prod"
    request_tag: Optional[str] = Field(default=None, max_length=64)
    policy_mode: str = Field(default="warn", pattern="^(allow|warn|block|transform)$")
    blocked_phrases: str = "[]"
    redact_phrases: str = "[]"
    max_output_tokens: Optional[int] = Field(default=None, ge=0, le=2_000_000)
    enforce: bool = True


class RouteOutputGuardrailsResponse(BaseModel):
    route_policy_id: str
    tenant_id: str
    environment: str
    request_tag: Optional[str] = None
    policy_mode: str
    blocked_phrases: str
    redact_phrases: str
    max_output_tokens: Optional[int] = None
    enforce: bool = True


class RouteInputDataPolicyRequest(BaseModel):
    tenant_id: str
    environment: str = "prod"
    request_tag: Optional[str] = Field(default=None, max_length=64)
    policy_mode: str = Field(default="warn", pattern="^(allow|warn|block|mask)$")
    data_classes: str = "[]"
    block_patterns: str = "[]"
    mask_token: str = Field(default="[REDACTED]", min_length=1, max_length=64)
    prompt_injection_mode: str = Field(
        default="inherit",
        pattern="^(off|warn|block|inherit)$",
        description="Heuristic prompt-injection handling; inherit uses gateway.prompt_injection.default_mode.",
    )
    enforce: bool = True


class RouteInputDataPolicyResponse(BaseModel):
    route_policy_id: str
    tenant_id: str
    environment: str
    request_tag: Optional[str] = None
    policy_mode: str
    data_classes: str
    block_patterns: str
    mask_token: str
    prompt_injection_mode: str = "inherit"
    enforce: bool = True


class RouteTrafficMirroringRequest(BaseModel):
    tenant_id: str
    environment: str = "prod"
    request_tag: Optional[str] = Field(default=None, max_length=64)
    mirror_targets: str = "[]"
    enabled: bool = True
    max_live_attempts: int = Field(default=1, ge=0, le=3)


class RouteTrafficMirroringResponse(BaseModel):
    route_policy_id: str
    tenant_id: str
    environment: str
    request_tag: Optional[str] = None
    mirror_targets: str
    enabled: bool = True
    max_live_attempts: int = 1


class RouteCanaryRolloutRequest(BaseModel):
    tenant_id: str
    environment: str = "prod"
    request_tag: Optional[str] = Field(default=None, max_length=64)
    baseline_provider_id: str = Field(min_length=1, max_length=255)
    canary_targets: str = "[]"
    cohort_request_tags: str = "[]"
    cohort_owner_scopes: str = "[]"
    gate_min_requests: Optional[int] = Field(default=None, ge=1, le=100000)
    gate_max_failure_rate: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    gate_min_success_rate: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    enabled: bool = True
    notes: Optional[str] = Field(default=None, max_length=500)


class RouteCanaryRolloutResponse(BaseModel):
    route_policy_id: str
    tenant_id: str
    environment: str
    request_tag: Optional[str] = None
    baseline_provider_id: str
    canary_targets: str
    cohort_request_tags: str
    cohort_owner_scopes: str
    gate_min_requests: Optional[int] = None
    gate_max_failure_rate: Optional[float] = None
    gate_min_success_rate: Optional[float] = None
    gate_metrics: str
    gate_last_decision: Optional[str] = None
    enabled: bool = True
    status: str
    notes: Optional[str] = None
    created_at: str
    updated_at: str
    promoted_at: Optional[str] = None
    stopped_at: Optional[str] = None


class RouteCanaryRolloutActionRequest(BaseModel):
    notes: Optional[str] = Field(default=None, max_length=500)


class GatewayEntitlementUpsertRequest(BaseModel):
    model_config = {"protected_namespaces": ()}

    action: str = Field(min_length=1, max_length=128)
    tenant_id: Optional[str] = Field(default=None, max_length=128)
    environment: str = "dev"
    route_policy_id: Optional[str] = Field(default=None, max_length=64)
    request_tag: Optional[str] = Field(default=None, max_length=64)
    model_name: Optional[str] = Field(default=None, max_length=255)
    tool_name: Optional[str] = Field(default=None, max_length=255)
    allowed_roles: str = "[]"
    enabled: bool = True


class GatewayEntitlementResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    entitlement_id: str
    action: str
    tenant_id: Optional[str] = None
    environment: str
    route_policy_id: Optional[str] = None
    request_tag: Optional[str] = None
    model_name: Optional[str] = None
    tool_name: Optional[str] = None
    allowed_roles: str
    enabled: bool
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class GatewayNhiInventoryRecordResponse(BaseModel):
    nhi_record_id: str
    source_type: str
    source_id: str
    identity_type: str
    tenant_id: str
    environment: str
    provider_type: str
    owner_scope_type: Optional[str] = None
    owner_scope_id: Optional[str] = None
    credential_last_rotated_at: Optional[datetime] = None
    credential_expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    findings: str
    status: str
    stale_credential: bool
    missing_owner: bool
    credential_age_days: Optional[int] = None


class GatewayNhiHygieneResponse(BaseModel):
    max_credential_age_days: int
    total_identities: int
    stale_credentials: int
    missing_owner: int
    inactive_identities: int
    high_risk_identities: int
    unmanaged_prod_identities: int = 0
    prod_unmanaged_zero_ok: bool = True
    findings_distribution: list[dict[str, object]]
    source_distribution: list[dict[str, object]]


class GatewayNhiInsightItem(BaseModel):
    nhi_record_id: str
    source_type: str
    source_id: str
    identity_type: str
    tenant_id: str
    environment: str
    provider_type: str
    status: str
    owner_scope_type: Optional[str] = None
    owner_scope_id: Optional[str] = None
    purpose: str = ""
    approved_intents: list[str] = Field(default_factory=list)
    risk_score: int
    risk_tier: str
    findings: list[str] = Field(default_factory=list)
    missing_owner: bool = False
    stale_credential: bool = False
    credential_age_days: Optional[int] = None
    business_impact: str = "monitored"


class GatewayNhiInsightsResponse(BaseModel):
    generated_at: str
    total_identities: int
    risk_tier_counts: dict[str, int] = Field(default_factory=dict)
    top_risks: list[GatewayNhiInsightItem] = Field(default_factory=list)
    intent_mode: str = "off"
    notes: str = ""


class GatewayNhiAccessMapResponse(BaseModel):
    nhi_record_id: str
    source_type: str
    source_id: str
    identity_type: str
    plane: str = "inference_gateway"
    path_count: int = 0
    paths: list[dict[str, object]] = Field(default_factory=list)
    notes: str = ""


class GatewayNhiTimelineResponse(BaseModel):
    nhi_record_id: str
    event_count: int = 0
    events: list[dict[str, object]] = Field(default_factory=list)


class GatewayNhiOwnerUpdateRequest(BaseModel):
    owner_scope_type: str = Field(min_length=1, max_length=64)
    owner_scope_id: str = Field(min_length=1, max_length=128)
    purpose: Optional[str] = Field(default=None, max_length=512)


class GatewayNhiLifecycleRequest(BaseModel):
    action: str = Field(min_length=1, max_length=32)
    reason: str = Field(default="", max_length=512)


class GatewayNhiIntentsUpdateRequest(BaseModel):
    purpose: str = Field(default="", max_length=512)
    approved_intents: list[str] = Field(default_factory=list)


class GatewayNhiGovernanceConfig(BaseModel):
    intent_mode: str = Field(default="off", max_length=16)
    record_count: int = 0
    correlation_ingest_enabled: bool = False
    correlation_ingest_hmac_secret: str = Field(default="", max_length=512)
    correlation_ingest_hmac_secret_configured: bool = False
    require_correlation_ingest_hmac: bool = True
    access_mode: str = Field(default="off", max_length=16)
    policy_count: int = 0
    access_policies: list[dict[str, object]] = Field(default_factory=list)
    gate_event_count: int = 0


class GatewayNhiAgentsResponse(BaseModel):
    agent_count: int
    source_type_counts: dict[str, int] = Field(default_factory=dict)
    agents: list[dict[str, object]] = Field(default_factory=list)
    access_mode: str = "off"
    notes: str = ""


class GatewayNhiAccessConfig(BaseModel):
    access_mode: str = Field(default="off", max_length=16)
    policy_count: int = 0
    access_policies: list[dict[str, object]] = Field(default_factory=list)
    intent_mode: str = "off"


class GatewayRuntimeRiskConfig(BaseModel):
    enabled: bool = False
    mode: str = Field(default="observe", max_length=16)
    high_action: str = Field(default="block", max_length=16)
    medium_action: str = Field(default="warn", max_length=16)
    low_action: str = Field(default="allow", max_length=16)
    enforce_environments: list[str] = Field(default_factory=lambda: ["prod", "production"])
    fail_closed_on_config_error: bool = True


class GatewayRuntimeRiskEvaluateRequest(BaseModel):
    model_name: str = Field(min_length=1, max_length=256)
    environment: str = Field(default="dev", max_length=64)
    has_tool_calls: bool = False
    selected_provider_id: Optional[str] = Field(default=None, max_length=128)
    endpoint_family: str = Field(default="chat.completions", max_length=64)
    has_agent_id: bool = False
    input_chars: int = Field(default=0, ge=0, le=10_000_000)


class GatewayRuntimeRiskEvaluateResponse(BaseModel):
    risk_tier: str
    risk_reasons: list[str]
    configured_action: str
    decision: str
    mode: str
    enabled: bool
    would_block: bool
    environment: str
    model_name: str
    endpoint_family: str = "chat.completions"


class GatewayNhiAccessAuthorizeRequest(BaseModel):
    declared_intent: str = Field(min_length=1, max_length=128)
    resource: str = Field(default="*", max_length=256)
    action: str = Field(default="chat.completions", max_length=128)
    nhi_record_id: Optional[str] = Field(default=None, max_length=64)
    virtual_key_id: Optional[str] = Field(default=None, max_length=128)
    owner_scope_id: Optional[str] = Field(default=None, max_length=128)
    actor_id: Optional[str] = Field(default=None, max_length=128)


class GatewayNhiAccessAuthorizeResponse(BaseModel):
    allowed: bool
    decision: str
    mode: str
    matched_policy_id: Optional[str] = None
    reason: str
    declared_intent: str
    resource: str
    action: str
    nhi_record_id: str = ""


class GatewayNhiShadowActionRequest(BaseModel):
    action: str = Field(min_length=1, max_length=32)
    notes: str = Field(default="", max_length=2000)


class GatewayNhiShadowActionResponse(BaseModel):
    nhi_record_id: str
    source_id: str
    shadow_status: str
    nhi_status: str
    action: str


class GatewayNhiIntentCheckRequest(BaseModel):
    nhi_record_id: Optional[str] = Field(default=None, max_length=64)
    virtual_key_id: Optional[str] = Field(default=None, max_length=128)
    owner_scope_id: Optional[str] = Field(default=None, max_length=128)
    actor_id: Optional[str] = Field(default=None, max_length=128)
    declared_intent: str = Field(min_length=1, max_length=128)
    action: str = Field(default="chat.completions", max_length=128)


class GatewayNhiEvidenceExportRequest(BaseModel):
    tenant_id: Optional[str] = Field(default=None, max_length=128)
    environment: Optional[str] = Field(default=None, max_length=64)
    max_credential_age_days: int = Field(default=90, ge=1, le=3650)


class GatewayNhiEvidenceExportResponse(BaseModel):
    evidence_id: str
    exported_at: str
    export_uri: str
    schema_version: str
    plane: str
    integration_intent: str
    exported_by: str
    filters: dict[str, object] = Field(default_factory=dict)
    summary: dict[str, object] = Field(default_factory=dict)
    hygiene_summary: Optional[dict[str, object]] = None
    insights: dict[str, object] = Field(default_factory=dict)
    orphans: dict[str, object] = Field(default_factory=dict)
    iga_deny: dict[str, object] = Field(default_factory=dict)
    notes: str = ""


class GatewayNhiCorrelationIngestRequest(BaseModel):
    nhi_record_id: Optional[str] = Field(default=None, max_length=64)
    virtual_key_id: Optional[str] = Field(default=None, max_length=128)
    source_type: Optional[str] = Field(default=None, max_length=64)
    source_id: Optional[str] = Field(default=None, max_length=128)
    external_ref: Optional[str] = Field(default=None, max_length=256)
    iga_agent_id: Optional[str] = Field(default=None, max_length=256)
    source_system: Optional[str] = Field(default=None, max_length=64)


class GatewayNhiIntentCheckResponse(BaseModel):
    allowed: bool
    matched: bool
    mode: str
    reason: str
    nhi_record_id: str
    declared_intent: str
    action: str
    approved_intents: list[str] = Field(default_factory=list)
    purpose: str = ""
    decision: str = "allow"


class GatewayNhiIgaExportConfig(BaseModel):
    enabled: bool = False
    target_system: str = Field(default="generic", max_length=64)
    webhook_url: str = Field(default="", max_length=2048)
    hmac_secret: str = Field(default="", max_length=512)
    hmac_secret_configured: bool = False
    sign_requests: bool = True
    include_hygiene_summary: bool = True
    default_profile: str = Field(default="iga_correlation", max_length=64)
    max_records: int = Field(default=500, ge=1, le=500)


class GatewayNhiExportRequest(BaseModel):
    tenant_id: Optional[str] = Field(default=None, max_length=128)
    environment: Optional[str] = Field(default=None, max_length=64)
    source_type: Optional[str] = Field(default=None, max_length=64)
    provider_type: Optional[str] = Field(default=None, max_length=64)
    identity_type: Optional[str] = Field(default=None, max_length=64)
    status: Optional[str] = Field(default=None, max_length=64)
    stale_only: bool = False
    missing_owner_only: bool = False
    max_credential_age_days: int = Field(default=90, ge=1, le=3650)
    limit: int = Field(default=100, ge=1, le=500)
    offset: int = Field(default=0, ge=0)
    profile: Optional[str] = Field(default=None, max_length=64)
    target_system: Optional[str] = Field(default=None, max_length=64)
    include_hygiene_summary: Optional[bool] = None
    deliver_webhook: bool = False
    dry_run_delivery: bool = True


class GatewayNhiExportDeliveryResult(BaseModel):
    delivery_id: str
    delivery_status: str
    webhook_url: str = ""
    signed: bool = False
    record_count: int = 0
    attempts: int = 0
    http_status: Optional[int] = None
    error: Optional[str] = None


class GatewayNhiExportResponse(BaseModel):
    export_id: str
    exported_at: str
    export_uri: str
    schema_version: str
    profile: str
    target_system: str
    plane: str
    integration_intent: str
    exported_by: str
    filters: dict[str, object] = Field(default_factory=dict)
    record_count: int
    identities: list[dict[str, object]] = Field(default_factory=list)
    correlation_guide: dict[str, object] = Field(default_factory=dict)
    hygiene_summary: Optional[dict[str, object]] = None
    delivery: Optional[GatewayNhiExportDeliveryResult] = None


class GatewayNhiIgaExportTestRequest(BaseModel):
    dry_run: bool = True


class GatewayNhiIgaDenyConfig(BaseModel):
    enabled: bool = False
    mode: str = Field(default="off", max_length=16)
    ingest_hmac_secret: str = Field(default="", max_length=512)
    ingest_hmac_secret_configured: bool = False
    require_ingest_hmac: bool = True
    require_ingest_timestamp: bool = False
    max_ingest_skew_seconds: int = Field(default=300, ge=30, le=3600)
    default_ttl_seconds: int = Field(default=86400, ge=60, le=2592000)
    max_active_denies: int = Field(default=200, ge=1, le=500)
    allowed_source_systems: list[str] = Field(default_factory=list)
    active_deny_count: int = 0
    event_history_count: int = 0
    active_denies: list[dict[str, object]] = Field(default_factory=list)


class GatewayNhiIgaDenyEventsResponse(BaseModel):
    event_count: int
    total_events: int
    events: list[dict[str, object]] = Field(default_factory=list)
    notes: str = ""


class GatewayNhiCorrelationUpdateRequest(BaseModel):
    external_ref: Optional[str] = Field(default=None, max_length=256)
    iga_agent_id: Optional[str] = Field(default=None, max_length=256)
    source_system: Optional[str] = Field(default=None, max_length=64)


class GatewayNhiCorrelationResponse(BaseModel):
    nhi_record_id: str
    external_ref: Optional[str] = None
    iga_agent_id: Optional[str] = None
    correlation_source_system: Optional[str] = None


class GatewayNhiOrphanItem(BaseModel):
    nhi_record_id: str
    source_type: str
    source_id: str
    identity_type: str
    tenant_id: str
    environment: str
    status: str
    risk_score: int
    risk_tier: str
    external_ref: Optional[str] = None
    iga_agent_id: Optional[str] = None
    purpose: str = ""


class GatewayNhiOrphansResponse(BaseModel):
    orphan_count: int
    orphans: list[GatewayNhiOrphanItem] = Field(default_factory=list)
    notes: str = ""


class GatewayNhiOrphansAssignRequest(BaseModel):
    nhi_record_ids: list[str] = Field(default_factory=list, max_length=50)
    owner_scope_type: str = Field(min_length=1, max_length=64)
    owner_scope_id: str = Field(min_length=1, max_length=128)
    purpose: Optional[str] = Field(default=None, max_length=512)


class GatewayNhiOrphansAssignResponse(BaseModel):
    updated_count: int
    updated: list[str] = Field(default_factory=list)
    skipped: list[dict[str, str]] = Field(default_factory=list)
    owner_scope_type: str
    owner_scope_id: str


class GatewayNhiIgaDenyIngestRequest(BaseModel):
    subject_type: str = Field(min_length=1, max_length=64)
    subject_id: str = Field(min_length=1, max_length=256)
    reason: str = Field(default="", max_length=512)
    source_system: str = Field(default="generic", max_length=64)
    tenant_id: Optional[str] = Field(default=None, max_length=128)
    environment: Optional[str] = Field(default=None, max_length=64)
    external_ref: Optional[str] = Field(default=None, max_length=256)
    ttl_seconds: Optional[int] = Field(default=None, ge=60, le=2592000)
    expires_at: Optional[str] = Field(default=None, max_length=64)


class GatewayNhiIgaDenyIngestResponse(BaseModel):
    deny_id: str
    status: str
    subject_type: str
    subject_id: str
    source_system: str
    expires_at: Optional[str] = None
    mode: Optional[str] = None
    active_deny_count: int = 0


class GatewayNhiIgaDenyRevokeRequest(BaseModel):
    reason: str = Field(default="operator_revoke", max_length=512)


class GatewayNhiIgaDenyEvaluateRequest(BaseModel):
    actor_id: Optional[str] = Field(default=None, max_length=128)
    virtual_key_id: Optional[str] = Field(default=None, max_length=128)
    owner_scope_id: Optional[str] = Field(default=None, max_length=128)
    tenant_id: Optional[str] = Field(default=None, max_length=128)
    environment: Optional[str] = Field(default=None, max_length=64)


class GatewayNhiIgaDenyEvaluateResponse(BaseModel):
    matched: bool
    mode: str
    enabled: bool
    deny: Optional[dict[str, object]] = None


class GatewayAccessReviewCampaignCreateRequest(BaseModel):
    campaign_name: str = Field(min_length=1, max_length=255)
    tenant_id: Optional[str] = Field(default=None, max_length=128)
    environment: str = "dev"
    include_disabled: bool = False
    reviewer_role: str = Field(default="Security Approver", min_length=1, max_length=128)


class GatewayAccessReviewItemResponse(BaseModel):
    review_item_id: str
    campaign_id: str
    entitlement_id: str
    decision: str
    decision_reason: Optional[str] = None
    decided_by: Optional[str] = None
    decided_at: Optional[datetime] = None
    created_at: datetime


class GatewayAccessReviewCampaignResponse(BaseModel):
    campaign_id: str
    campaign_name: str
    tenant_id: Optional[str] = None
    environment: str
    include_disabled: bool
    status: str
    reviewer_role: str
    created_by: str
    created_at: datetime
    closed_at: Optional[datetime] = None
    total_items: int
    pending_items: int
    approved_items: int
    revoked_items: int
    items: list[GatewayAccessReviewItemResponse]


class GatewayJitAccessRequestCreateRequest(BaseModel):
    entitlement_id: str = Field(min_length=1, max_length=64)
    environment: str = "dev"
    justification: str = Field(min_length=8, max_length=2000)
    requested_duration_minutes: int = Field(default=60, ge=5, le=1440)
    owner_scope_type: str = Field(
        default="user",
        description="Principal scope for the minted virtual key (user|team|group|owner|actor).",
    )
    owner_scope_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Owner scope id. Defaults to the requester actor id when omitted.",
    )
    mint_virtual_key: bool = Field(
        default=True,
        description="When true, approve mints a short-lived virtual key bound to this grant.",
    )


class GatewayJitAccessApproveRequest(BaseModel):
    decision: str = Field(default="approve", pattern="^(approve|deny)$")
    decision_reason: Optional[str] = Field(default=None, max_length=512)
    mint_virtual_key: Optional[bool] = Field(
        default=None,
        description="Override request-time mint preference. Null keeps the request setting.",
    )


class GatewayJitAccessRequestResponse(BaseModel):
    request_id: str
    entitlement_id: str
    requester_id: str
    requester_role: str
    justification: str
    environment: str
    requested_duration_minutes: int
    status: str
    approved_by: Optional[str] = None
    approved_role: Optional[str] = None
    approved_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    owner_scope_type: str = "user"
    owner_scope_id: Optional[str] = None
    mint_virtual_key: bool = True
    issued_virtual_key_id: Optional[str] = None
    issued_virtual_key_token: Optional[str] = Field(
        default=None,
        description="One-time bearer token returned only on approve when a VK is minted. Never re-read.",
    )
    last_notify: Optional[dict[str, object]] = None
    notify_history: list[dict[str, object]] = Field(default_factory=list)
    created_at: datetime


class GatewayJitAccessRequestListResponse(BaseModel):
    total: int
    data: list[GatewayJitAccessRequestResponse]


class GatewayJitAccessRevokeRequest(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=512)


class GatewayJitExpireTickResponse(BaseModel):
    expired_grants: int
    blocked_keys: int
    scanned: int


class GatewayJitDecisionNotifyConfig(BaseModel):
    enabled: bool = False
    notify_on_create: bool = True
    notify_on_decide: bool = True
    email_channel_id: str = ""
    reviewer_emails: list[str] = Field(default_factory=list)
    decision_recipient_emails: list[str] = Field(default_factory=list)
    public_base_url: str = ""
    external_callback_ids: list[str] = Field(default_factory=list)
    external_rest_url: str = ""
    external_rest_credential_binding_id: str = ""
    action_token_ttl_minutes: int = Field(default=1440, ge=15, le=10080)
    allow_prod_email_approve: bool = False
    expose_virtual_key_on_email_action: bool = False
    email_virtual_key_to_recipients: bool = True
    webhook_sign_requests: bool = True
    include_action_links_in_webhooks: bool = False
    min_notify_interval_minutes: int = Field(default=15, ge=0, le=1440)
    webhook_payload_style: str = "standard"
    auto_reminder_after_minutes: int = Field(default=0, ge=0, le=10080)
    escalate_after_minutes: int = Field(default=0, ge=0, le=10080)
    escalation_reviewer_emails: list[str] = Field(default_factory=list)
    max_auto_reminders: int = Field(default=3, ge=0, le=20)
    auto_retry_failed_webhooks_on_tick: bool = False


class GatewayJitDecisionNotifyResult(BaseModel):
    notified: bool = False
    tested: Optional[bool] = None
    emails_sent: int = 0
    email_errors: list[str] = Field(default_factory=list)
    webhooks: list[dict[str, object]] = Field(default_factory=list)
    event_type: str = "gateway.jit.request.create"
    reason: Optional[str] = None
    probe_id: Optional[str] = None
    delivery_id: Optional[str] = None
    is_reminder: bool = False
    is_retry: bool = False
    is_escalation: bool = False


class GatewayJitNotifyTickResponse(BaseModel):
    scanned: int = 0
    reminded: int = 0
    escalated: int = 0
    retried: int = 0
    skipped: int = 0
    items: list[dict[str, object]] = Field(default_factory=list)
    reason: Optional[str] = None


class GatewayJitPendingNotifySummary(BaseModel):
    enabled: bool = False
    pending_count: int = 0
    overdue_reminder_count: int = 0
    overdue_escalation_count: int = 0
    failed_webhook_count: int = 0
    oldest_pending_age_minutes: Optional[int] = None
    auto_reminder_after_minutes: int = 0
    escalate_after_minutes: int = 0
    max_auto_reminders: int = 0
    auto_retry_failed_webhooks_on_tick: bool = False


class GatewayJitNotifyHistoryResponse(BaseModel):
    request_id: str
    last_notify: Optional[dict[str, object]] = None
    history: list[dict[str, object]] = Field(default_factory=list)


class GatewayJitActionLinksPreviewResponse(BaseModel):
    request_id: str
    status: str
    reviewer_email: str
    public_base_url: str = ""
    action_token_ttl_minutes: int = 1440
    approve_url: str = ""
    deny_url: str = ""
    links_ready: bool = False


class GatewayJitActionConfirmPreviewResponse(BaseModel):
    pending: bool
    confirm_required: bool = True
    request_id: str
    status: str
    decision: str
    reviewer_email: str = ""
    entitlement_id: str
    environment: str
    requester_id: str
    justification: str = ""
    requested_duration_minutes: int = 60
    expires_claim_unix: int
    confirm_nonce: str
    message: str


class GatewayJitActionDecideRequest(BaseModel):
    confirm: bool = True
    confirm_nonce: str = Field(..., min_length=8, max_length=256)
    decision_reason: Optional[str] = Field(default=None, max_length=512)


class GatewayJitActionDecideResponse(BaseModel):
    request_id: str
    status: str
    decision: str
    decided_by: str
    message: str
    issued_virtual_key_id: Optional[str] = None
    # One-time token only when expose_virtual_key_on_email_action is enabled.
    issued_virtual_key_token: Optional[str] = None
    virtual_key_emailed: bool = False
    key_email_recipients: int = 0


class GatewayLeastPrivilegeRecommendationResponse(BaseModel):
    recommendation_id: str
    entitlement_id: str
    tenant_id: Optional[str] = None
    environment: str
    recommendation_type: str
    rationale: str
    confidence_score: float
    current_allowed_roles: str
    proposed_allowed_roles: str
    proposed_enabled: Optional[bool] = None
    status: str
    created_by: str
    applied_by: Optional[str] = None
    applied_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class GatewayLeastPrivilegeRecommendationApplyRequest(BaseModel):
    decision_reason: Optional[str] = Field(default=None, max_length=512)
    change_ticket_id: Optional[str] = Field(default=None, max_length=128)
    review_evidence_uri: Optional[str] = Field(default=None, max_length=512)


class RouteProviderPriorityTimelineEventResponse(BaseModel):
    timestamp: datetime
    actor_id: str
    action_type: str
    decision_outcome: str
    trace_id: str
    policy_version: str


class RouteProviderPriorityTimelineResponse(BaseModel):
    route_policy_id: str
    limit: int
    offset: int
    events: list[RouteProviderPriorityTimelineEventResponse]


class RouteSimulateFallbackRequest(BaseModel):
    tenant_id: str
    environment: str = "prod"
    request_tag: Optional[str] = Field(default=None, max_length=64)
    requested_region: Optional[str] = Field(default=None, max_length=64)
    simulate_fail_provider_ids: str = "[]"


class RouteSimulateFallbackResponse(BaseModel):
    route_policy_id: str
    tenant_id: str
    environment: str
    attempted_providers: str
    selected_group_id: Optional[str] = None
    selected_provider_id: Optional[str] = None
    intended_model: Optional[str] = None
    actual_model: Optional[str] = None
    model_switched: Optional[bool] = None
    fallback_hops_used: int
    provider_attempts: int
    final_outcome: str


class RouteExecuteFallbackRequest(BaseModel):
    model_config = {"protected_namespaces": ()}

    tenant_id: str
    environment: str = "prod"
    agent_id: str
    request_tag: Optional[str] = Field(default=None, max_length=64)
    requested_region: Optional[str] = Field(default=None, max_length=64)
    request_priority: str = Field(default="normal", pattern="^(low|normal|high)$")
    model_name: Optional[str] = None
    session_id: str = "gateway-session"
    owner_scope: Optional[str] = None
    owner_scope_type: Optional[str] = None
    owner_scope_id: Optional[str] = None
    endpoint_family: str = "responses"
    input_tokens: int = Field(default=100, ge=0)
    output_tokens: int = Field(default=50, ge=0)
    simulated_input_text: Optional[str] = Field(default=None, max_length=4000)
    simulated_output_text: Optional[str] = Field(default=None, max_length=4000)
    currency: str = "USD"
    simulate_fail_provider_ids: str = "[]"


class RouteExecuteFallbackResponse(BaseModel):
    route_policy_id: str
    tenant_id: str
    environment: str
    request_id: str
    trace_id: str
    attempted_providers: str
    selected_group_id: Optional[str] = None
    selected_provider_id: Optional[str] = None
    intended_model: Optional[str] = None
    actual_model: Optional[str] = None
    model_switched: Optional[bool] = None
    fallback_hops_used: int
    provider_attempts: int
    total_latency_ms: int
    total_estimated_cost_cents: int
    final_outcome: str


class CachePolicyRequest(BaseModel):
    scope: str
    ttl_seconds: int = Field(default=60, ge=1, le=86400)
    key_strategy: str = "default"
    invalidation_strategy: str = "ttl"
    privacy_mode: str = "standard"
    privacy_scope: str = Field(default="tenant", pattern="^(global|tenant|owner|route)$")
    non_cache_data_classes: str = "[]"
    cache_mode: str = Field(default="exact", pattern="^(exact|semantic)$")
    similarity_threshold: float = Field(default=0.9, ge=0.0, le=1.0)


class CachePolicyResponse(ORMBase):
    cache_policy_id: str
    scope: str
    ttl_seconds: int
    key_strategy: str
    invalidation_strategy: str
    privacy_mode: str
    privacy_scope: str
    non_cache_data_classes: str
    cache_mode: str
    similarity_threshold: float
    status: str


class GatewayCacheHealthResponse(BaseModel):
    status: str
    cache_backend: str
    active_policies: int
    semantic_policies: int
    avg_ttl_seconds: float
    avg_similarity_threshold: float
    hit_ratio: float
    eligible_requests: int
    hits: int
    misses: int
    invalidation_requests_last_24h: int


class GatewayCacheInvalidateRequest(BaseModel):
    scope: Optional[str] = Field(default=None, max_length=128)
    cache_keys: list[str] = Field(default_factory=list)
    reason: Optional[str] = Field(default=None, max_length=256)
    active_only: bool = True


class GatewayCacheInvalidateResponse(BaseModel):
    status: str
    mode: str
    invalidated_scope: Optional[str] = None
    requested_keys: int
    matching_policies: int
    purged_cache_entries: int = 0
    active_only: bool


class GatewayCacheDecisionEventResponse(ORMBase):
    cache_decision_event_id: str
    timestamp: datetime
    trace_id: str
    request_id: str
    request_fingerprint: str
    request_text: str
    actor_id: str
    tenant_id: str
    environment: str
    route_policy_id: Optional[str] = None
    data_class: str
    cache_policy_id: Optional[str] = None
    cache_policy_scope: Optional[str] = None
    cache_mode: Optional[str] = None
    match_score: float
    decision: str
    explanation: str
    match_provenance: str
    source_request_id: Optional[str] = None


class GatewayResponseCacheEntryResponse(ORMBase):
    cache_entry_id: str
    cache_policy_id: str
    request_fingerprint: str
    request_text: str
    tenant_id: str
    environment: str
    route_policy_id: Optional[str] = None
    owner_scope: str
    data_class: str
    cache_mode: str
    match_score: float
    endpoint_family: str
    source_request_id: Optional[str] = None
    ttl_expires_at: datetime
    created_at: datetime
    status: str


class GatewayAnalyticsSummaryResponse(BaseModel):
    environment: Optional[str] = None
    hours: int
    total_events: int
    distinct_requests: int
    total_estimated_cost_cents: int
    avg_input_tokens: float
    avg_output_tokens: float
    top_models: list[dict[str, object]]
    top_endpoint_families: list[dict[str, object]]
    on_plane_events: int = 0
    off_plane_detected: int = 0
    on_plane_coverage_percent: Optional[float] = None
    on_plane_coverage: Optional[dict[str, object]] = None


class GatewayLeadershipQbrSnapshotResponse(BaseModel):
    generated_at: str
    purpose: str = "numbers_first_qbr"
    spend: dict[str, object]
    clocks: dict[str, object]
    gates: dict[str, object]
    drills: dict[str, object] = Field(default_factory=dict)
    plane_isolation: dict[str, object] = Field(
        default_factory=dict,
        description="APP_PLANE isolation, policy fingerprint, drift/gate posture for QBR.",
    )
    control_plane_leadership: dict[str, object] = Field(
        default_factory=dict,
        description="Control Plane Leadership Index (CPLI) engineering scorecard summary.",
    )
    program_leadership: dict[str, object] = Field(
        default_factory=dict,
        description="Unified LRS + CPLI posture (program gate + engineering leader band).",
    )
    on_plane_coverage: Optional[dict[str, object]] = None
    transport: dict[str, object] = Field(default_factory=dict)
    exception_posture: dict[str, object] = Field(default_factory=dict)
    mfa_optional: dict[str, object] = Field(default_factory=dict)
    token_exposure: dict[str, object] = Field(default_factory=dict)
    readiness_notes: list[str] = Field(default_factory=list)
    honesty: dict[str, object] = Field(default_factory=dict)


class GatewayLeadershipDrillRunCreateRequest(BaseModel):
    drill_id: str = Field(min_length=1, max_length=32)
    performed_on: str = Field(min_length=10, max_length=32, description="YYYY-MM-DD after a real drill")
    duration_seconds: Optional[int] = Field(default=None, ge=0, le=86400)
    outcome: str = Field(default="pass", max_length=16)
    notes: str = Field(default="", max_length=2000)
    evidence_ref: str = Field(default="", max_length=512)


class GatewayLeadershipDrillRunResponse(BaseModel):
    run_id: str
    drill_id: str
    performed_on: str
    recorded_at: str
    recorded_by: str
    duration_seconds: Optional[int] = None
    outcome: str
    notes: str = ""
    evidence_ref: str = ""


class GatewayLeadershipDrillRunListResponse(BaseModel):
    items: list[GatewayLeadershipDrillRunResponse]
    freshness: dict[str, object] = Field(default_factory=dict)


class GatewayAuthzExplainRequest(BaseModel):
    actor_role: str = Field(min_length=1)
    actor_id: str = Field(default="explain-actor", min_length=1)
    action: str = Field(min_length=1)
    environment: str = "dev"
    resource_type: str = "gateway_action"
    resource_id: Optional[str] = None
    approver_role: Optional[str] = None
    approver_id: Optional[str] = None


class GatewayAuthzExplainResponse(BaseModel):
    actor_role: str
    actor_id: str
    action: str
    environment: str
    resource_type: str
    resource_id: Optional[str] = None
    decision: str
    decision_trace_id: str
    policy_version: str = "v1"
    allowed_roles: list[str]
    requires_dual_approval: bool
    required_approver_role: Optional[str] = None
    reasons: list[str]
    remediation_hint: str


class GatewayDecisionTraceEvent(BaseModel):
    timestamp: datetime
    actor_id: str
    action_type: str
    resource_type: str
    resource_id: str
    decision_outcome: str
    policy_version: str


class GatewayDecisionTraceResponse(BaseModel):
    trace_id: str
    event_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    actions: list[str]
    outcomes: dict[str, int]
    events: list[GatewayDecisionTraceEvent]


class GatewayOpenAIChatMessage(BaseModel):
    role: str = Field(min_length=1)
    content: object


class GatewayOpenAIChatCompletionsRequest(BaseModel):
    model: str = Field(min_length=1)
    messages: list[GatewayOpenAIChatMessage] = Field(min_length=1)
    temperature: Optional[float] = Field(default=None, ge=0.0, le=2.0)
    top_p: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    max_tokens: Optional[int] = Field(default=None, ge=1, le=32768)
    frequency_penalty: Optional[float] = Field(default=None, ge=-2.0, le=2.0)
    presence_penalty: Optional[float] = Field(default=None, ge=-2.0, le=2.0)
    stop: Optional[object] = None
    response_format: Optional[dict[str, object]] = None
    stream: bool = False
    tenant_id: Optional[str] = None
    environment: str = "dev"
    route_policy_id: Optional[str] = None
    config_id: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Portkey-style config id (alias of route_policy_id)",
    )
    request_tag: Optional[str] = None
    session_id: Optional[str] = None
    owner_scope: Optional[str] = None
    agent_id: Optional[str] = None
    virtual_key_id: Optional[str] = Field(default=None, max_length=128)
    guardrail_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Portkey-style guardrail id (alias of virtual_key_id)",
    )
    user_properties: Optional[dict[str, object]] = None
    user: Optional[str] = Field(default=None, max_length=128, description="Helicone-style end-user id")
    properties: Optional[dict[str, object]] = Field(
        default=None,
        description="Helicone-style request properties for cost/observability drilldown",
    )
    prompt_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Portkey-style prompt registry id (alias of prompt_registry_id)",
    )
    prompt_registry_id: Optional[str] = Field(default=None, max_length=128)
    variables: Optional[dict[str, str]] = Field(
        default=None,
        description="Template variables for prompt registry {{var}} rendering",
    )
    session_path: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Helicone-style session path for request grouping",
    )
    session_name: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Helicone-style session display name",
    )
    metadata: Optional[dict[str, object]] = Field(
        default=None,
        description="Helicone-style custom metadata merged into cost/observability properties",
    )
    cache_mode: Optional[str] = Field(
        default="inherit",
        pattern="^(inherit|bypass|force)$",
        description="Portkey-style cache control: inherit (policy), bypass (skip read/write), force (skip hit, still store)",
    )
    auto_route: bool = Field(
        default=False,
        description="When true (or model is auto/gateway/auto), classify prompt complexity and select a tier model",
    )
    auto_route_strategy: str = Field(
        default="balanced",
        pattern="^(balanced|cost|quality)$",
        description="Auto-router selection strategy within the classified tier",
    )
    declared_intent: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Gateway-plane intent label for NHI intent-check / IARA-lite; enforced when intent_mode or access_mode is warn/block",
    )
    access_resource: Optional[str] = Field(
        default=None,
        max_length=256,
        description="IARA-lite resource label (e.g. model:gpt-4o, mcp:server/tool); used with access policies",
    )


class GatewayOpenAIChatChoiceMessage(BaseModel):
    role: str
    content: str


class GatewayOpenAIChatChoice(BaseModel):
    index: int
    message: GatewayOpenAIChatChoiceMessage
    finish_reason: str


class GatewayOpenAIChatUsage(BaseModel):
    prompt_tokens: int
    completion_tokens: int
    total_tokens: int


class GatewayOpenAIChatCompletionsResponse(BaseModel):
    id: str
    object: str
    created: int
    model: str
    choices: list[GatewayOpenAIChatChoice]
    usage: GatewayOpenAIChatUsage
    request_id: str
    trace_id: str
    risk_tier: str
    risk_reasons: list[str]
    selected_provider_id: Optional[str] = None
    route_policy_id: Optional[str] = None
    config_id: Optional[str] = None
    virtual_key_id: Optional[str] = None
    guardrail_id: Optional[str] = None
    cache_short_circuit: Optional[bool] = None
    cache_mode: Optional[str] = None
    fallback_hops_used: Optional[int] = None
    prompt_registry_id: Optional[str] = None
    canary_routing_decision: Optional[str] = None
    mirror_events_count: Optional[int] = None
    cost_hierarchy_limits: Optional[dict[str, object]] = None
    content_guard_decision: Optional[str] = None
    content_guard_reasons: Optional[list[str]] = None
    intended_model: Optional[str] = None
    actual_model: Optional[str] = None
    model_switched: Optional[bool] = None
    auto_route_tier: Optional[str] = None
    auto_route_score: Optional[int] = None
    auto_route_rationale: Optional[str] = None


class GatewayOpenAIEmbeddingsRequest(BaseModel):
    model: str = Field(min_length=1)
    input: object
    dimensions: Optional[int] = Field(default=16, ge=1, le=256)
    tenant_id: Optional[str] = None
    environment: str = "dev"
    route_policy_id: Optional[str] = None
    request_tag: Optional[str] = None
    session_id: Optional[str] = None
    owner_scope: Optional[str] = None
    agent_id: Optional[str] = None


class GatewayOpenAIEmbeddingData(BaseModel):
    object: str
    embedding: list[float]
    index: int


class GatewayOpenAIEmbeddingsUsage(BaseModel):
    prompt_tokens: int
    total_tokens: int


class GatewayOpenAIEmbeddingsResponse(BaseModel):
    object: str
    data: list[GatewayOpenAIEmbeddingData]
    model: str
    usage: GatewayOpenAIEmbeddingsUsage
    request_id: str
    trace_id: str
    risk_tier: str
    risk_reasons: list[str]
    selected_provider_id: Optional[str] = None
    route_policy_id: Optional[str] = None


class GatewayOpenAIRerankRequest(BaseModel):
    model: str = Field(min_length=1)
    query: str = Field(min_length=1)
    documents: list[object] = Field(min_length=1)
    top_n: Optional[int] = Field(default=None, ge=1, le=100)
    tenant_id: Optional[str] = None
    environment: str = "dev"
    request_tag: Optional[str] = None
    session_id: Optional[str] = None
    owner_scope: Optional[str] = None
    agent_id: Optional[str] = None


class GatewayOpenAIRerankResult(BaseModel):
    index: int
    relevance_score: float
    document: object


class GatewayOpenAIRerankUsage(BaseModel):
    prompt_tokens: int
    total_tokens: int


class GatewayOpenAIRerankResponse(BaseModel):
    object: str
    model: str
    results: list[GatewayOpenAIRerankResult]
    usage: GatewayOpenAIRerankUsage
    request_id: str
    trace_id: str
    risk_tier: str
    risk_reasons: list[str]
    selected_provider_id: Optional[str] = None
    route_policy_id: Optional[str] = None


class GatewayOpenAIImagesRequest(BaseModel):
    model: str = Field(min_length=1)
    prompt: str = Field(min_length=1)
    n: int = Field(default=1, ge=1, le=10)
    size: str = Field(default="1024x1024", min_length=1, max_length=32)
    response_format: str = Field(default="b64_json", min_length=1, max_length=16)
    user: Optional[str] = None
    tenant_id: Optional[str] = None
    environment: str = "dev"
    request_tag: Optional[str] = None
    session_id: Optional[str] = None
    owner_scope: Optional[str] = None
    agent_id: Optional[str] = None


class GatewayOpenAIImagesData(BaseModel):
    b64_json: str
    revised_prompt: Optional[str] = None
    index: int


class GatewayOpenAIImagesResponse(BaseModel):
    created: int
    data: list[GatewayOpenAIImagesData]
    model: str
    request_id: str
    trace_id: str
    risk_tier: str
    risk_reasons: list[str]
    selected_provider_id: Optional[str] = None
    route_policy_id: Optional[str] = None


class GatewayOpenAIAudioTranscriptionRequest(BaseModel):
    model: str = Field(min_length=1)
    input_text: str = Field(min_length=1)
    language: Optional[str] = Field(default=None, max_length=32)
    prompt: Optional[str] = Field(default=None, max_length=512)
    response_format: str = Field(default="json", min_length=1, max_length=16)
    tenant_id: Optional[str] = None
    environment: str = "dev"
    request_tag: Optional[str] = None
    session_id: Optional[str] = None
    owner_scope: Optional[str] = None
    agent_id: Optional[str] = None


class GatewayOpenAIAudioTranslationRequest(BaseModel):
    model: str = Field(min_length=1)
    input_text: str = Field(min_length=1)
    target_language: str = Field(min_length=1, max_length=32)
    language: Optional[str] = Field(default=None, max_length=32)
    prompt: Optional[str] = Field(default=None, max_length=512)
    response_format: str = Field(default="json", min_length=1, max_length=16)
    tenant_id: Optional[str] = None
    environment: str = "dev"
    request_tag: Optional[str] = None
    session_id: Optional[str] = None
    owner_scope: Optional[str] = None
    agent_id: Optional[str] = None


class GatewayOpenAIAudioResponse(BaseModel):
    text: str
    language: Optional[str] = None
    duration_seconds: float
    model: str
    request_id: str
    trace_id: str
    risk_tier: str
    risk_reasons: list[str]
    selected_provider_id: Optional[str] = None
    route_policy_id: Optional[str] = None


class GatewayOpenAIRealtimeRequest(BaseModel):
    model: str = Field(min_length=1)
    session_label: Optional[str] = Field(default=None, max_length=128)
    stream: bool = False
    stream_binary_mode: str = Field(default="metadata_only", max_length=32)
    stream_inline_max_event_bytes: int = Field(default=16384, ge=1024, le=262144)
    stream_inline_allowed_event_types: list[str] = Field(default_factory=lambda: ["input.audio.append", "input.video.append"])
    stream_inline_require_correlation_id: bool = False
    stream_max_event_bytes: int = Field(default=65536, ge=1024, le=1048576)
    stream_max_session_events: int = Field(default=500, ge=1, le=100000)
    stream_max_session_event_bytes: int = Field(default=5242880, ge=1024, le=104857600)
    stream_heartbeat_interval_seconds: int = Field(default=15, ge=5, le=120)
    tenant_id: Optional[str] = None
    environment: str = "dev"
    requested_modalities: list[str] = Field(default_factory=lambda: ["text"])
    request_tag: Optional[str] = None
    session_id: Optional[str] = None
    owner_scope: Optional[str] = None
    agent_id: Optional[str] = None


class GatewayOpenAIRealtimeResponse(BaseModel):
    id: str
    object: str
    status: str
    model: str
    session_label: Optional[str] = None
    requested_modalities: list[str]
    expires_at: int
    request_id: str
    trace_id: str
    risk_tier: str
    risk_reasons: list[str]
    selected_provider_id: Optional[str] = None
    route_policy_id: Optional[str] = None


class GatewayOpenAIRealtimeSessionEventCreateRequest(BaseModel):
    event_type: str = Field(min_length=1, max_length=64)
    payload: Optional[dict[str, object]] = None
    binary_mode: str = Field(default="metadata_only", max_length=32)
    event_bytes: int = Field(default=0, ge=0, le=1048576)


class GatewayOpenAIRealtimeSessionEventResponse(BaseModel):
    id: str
    object: str
    session_id: str
    event_type: str
    binary_mode: str
    event_bytes: int
    status: str
    request_id: str
    trace_id: str
    created_at: Optional[int] = None
    payload: Optional[dict[str, object]] = None


class GatewayOpenAIRealtimeSessionEventListResponse(BaseModel):
    object: str
    data: list[GatewayOpenAIRealtimeSessionEventResponse]


class GatewayOpenAIRealtimeSessionResponse(BaseModel):
    id: str
    object: str
    status: str
    model: str
    session_label: Optional[str] = None
    requested_modalities: list[str]
    stream_policy: dict[str, object]
    event_count: int
    total_event_bytes: int = 0
    last_event_type: Optional[str] = None
    created_at: int
    expires_at: int
    closed_at: Optional[int] = None
    request_id: str
    trace_id: str


class GatewayOpenAIRealtimeSessionListResponse(BaseModel):
    object: str
    data: list[GatewayOpenAIRealtimeSessionResponse]


class GatewayOpenAIRealtimeSessionCloseResponse(BaseModel):
    id: str
    object: str
    status: str
    closed_at: int
    event_count: int
    last_event_type: Optional[str] = None
    request_id: str
    trace_id: str


class GatewayOpenAIMessagesRequest(BaseModel):
    model: str = Field(min_length=1)
    input: str = Field(min_length=1)
    conversation_id: Optional[str] = Field(default=None, max_length=128)
    tenant_id: Optional[str] = None
    environment: str = "dev"
    request_tag: Optional[str] = None
    session_id: Optional[str] = None
    owner_scope: Optional[str] = None
    agent_id: Optional[str] = None


class GatewayOpenAIA2AMessageRequest(BaseModel):
    from_agent_id: str = Field(min_length=1, max_length=128)
    to_agent_id: str = Field(min_length=1, max_length=128)
    message: str = Field(min_length=1)
    model: str = Field(default="a2a-transport-v1", min_length=1)
    tenant_id: Optional[str] = None
    environment: str = "dev"
    request_tag: Optional[str] = None
    session_id: Optional[str] = None
    owner_scope: Optional[str] = None
    agent_id: Optional[str] = None


class GatewayOpenAIMessagesResponse(BaseModel):
    id: str
    object: str
    role: str
    content: str
    conversation_id: Optional[str] = None
    model: str
    request_id: str
    trace_id: str
    risk_tier: str
    risk_reasons: list[str]
    selected_provider_id: Optional[str] = None
    route_policy_id: Optional[str] = None


class GatewayOpenAIA2AMessageResponse(BaseModel):
    id: str
    object: str
    status: str
    from_agent_id: str
    to_agent_id: str
    content: str
    model: str
    request_id: str
    trace_id: str
    risk_tier: str
    risk_reasons: list[str]
    selected_provider_id: Optional[str] = None
    route_policy_id: Optional[str] = None


class GatewayOpenAIResponsesRequest(BaseModel):
    model: str = Field(min_length=1)
    input: object
    instructions: Optional[str] = None
    metadata: Optional[dict[str, object]] = Field(
        default=None,
        description="OpenAI Responses API metadata forwarded upstream (not Helicone cost props)",
    )
    temperature: Optional[float] = Field(default=None, ge=0.0, le=2.0)
    top_p: Optional[float] = Field(default=None, ge=0.0, le=1.0)
    max_output_tokens: Optional[int] = Field(default=None, ge=1, le=32768)
    stop: Optional[object] = None
    tools: Optional[list[dict[str, object]]] = None
    tool_choice: Optional[object] = None
    response_format: Optional[dict[str, object]] = None
    stream: bool = False
    tenant_id: Optional[str] = None
    environment: str = "dev"
    route_policy_id: Optional[str] = None
    config_id: Optional[str] = Field(
        default=None,
        max_length=64,
        description="Portkey-style config id (alias of route_policy_id)",
    )
    request_tag: Optional[str] = None
    session_id: Optional[str] = None
    owner_scope: Optional[str] = None
    agent_id: Optional[str] = None
    virtual_key_id: Optional[str] = Field(default=None, max_length=128)
    guardrail_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Portkey-style guardrail id (alias of virtual_key_id)",
    )
    user_properties: Optional[dict[str, object]] = None
    user: Optional[str] = Field(default=None, max_length=128, description="Helicone-style end-user id")
    properties: Optional[dict[str, object]] = Field(
        default=None,
        description="Helicone-style request properties for cost/observability drilldown",
    )
    session_path: Optional[str] = Field(
        default=None,
        max_length=256,
        description="Helicone-style session path for request grouping",
    )
    session_name: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Helicone-style session display name",
    )
    prompt_id: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Portkey-style prompt registry id (alias of prompt_registry_id)",
    )
    prompt_registry_id: Optional[str] = Field(default=None, max_length=128)
    variables: Optional[dict[str, str]] = Field(
        default=None,
        description="Template variables for prompt registry {{var}} rendering",
    )
    cache_mode: Optional[str] = Field(
        default="inherit",
        pattern="^(inherit|bypass|force)$",
        description="Portkey-style cache control: inherit (policy), bypass (skip read/write), force (skip hit, still store)",
    )
    auto_route: bool = Field(
        default=False,
        description="When true (or model=auto), classify prompt complexity and select a catalog model",
    )
    auto_route_strategy: str = Field(
        default="balanced",
        pattern="^(balanced|cost|quality)$",
        description="Auto-route strategy used when auto_route is enabled",
    )
    declared_intent: Optional[str] = Field(
        default=None,
        max_length=128,
        description="Gateway-plane intent label for NHI intent-check / IARA-lite; enforced when intent_mode or access_mode is warn/block",
    )
    access_resource: Optional[str] = Field(
        default=None,
        max_length=256,
        description="IARA-lite resource label (e.g. model:gpt-4o, mcp:server/tool); used with access policies",
    )


class GatewayOpenAIResponsesOutputContent(BaseModel):
    type: str
    text: Optional[str] = None
    name: Optional[str] = None
    arguments: Optional[str] = None
    call_id: Optional[str] = None


class GatewayOpenAIResponsesOutputItem(BaseModel):
    id: str
    type: str
    role: str
    content: list[GatewayOpenAIResponsesOutputContent]
    finish_reason: str


class GatewayOpenAIResponsesUsage(BaseModel):
    input_tokens: int
    output_tokens: int
    total_tokens: int


class GatewayOpenAIResponsesResponse(BaseModel):
    id: str
    object: str
    created_at: int
    model: str
    output: list[GatewayOpenAIResponsesOutputItem]
    output_text: str
    usage: GatewayOpenAIResponsesUsage
    request_id: str
    trace_id: str
    risk_tier: str
    risk_reasons: list[str]
    selected_provider_id: Optional[str] = None
    route_policy_id: Optional[str] = None
    config_id: Optional[str] = None
    virtual_key_id: Optional[str] = None
    guardrail_id: Optional[str] = None
    cache_short_circuit: Optional[bool] = None
    cache_mode: Optional[str] = None
    fallback_hops_used: Optional[int] = None
    canary_routing_decision: Optional[str] = None
    mirror_events_count: Optional[int] = None
    prompt_registry_id: Optional[str] = None
    cost_hierarchy_limits: Optional[dict[str, object]] = None
    auto_route_tier: Optional[str] = None
    auto_route_score: Optional[int] = None
    auto_route_rationale: Optional[str] = None


class GatewayOpenAIResponsesListResponse(BaseModel):
    object: str
    data: list[GatewayOpenAIResponsesResponse]


class GatewayOpenAIResponsesDeleteResponse(BaseModel):
    id: str
    object: str
    deleted: bool
    request_id: str
    trace_id: str


class GatewayOpenAIFileCreateRequest(BaseModel):
    filename: str = Field(min_length=1, max_length=255)
    purpose: str = Field(default="assistants", min_length=1, max_length=128)
    bytes: int = Field(ge=0, le=2_147_483_647)
    content_type: Optional[str] = Field(default="application/octet-stream", max_length=128)
    metadata: Optional[dict[str, object]] = None
    environment: str = "dev"
    # Opt-in encrypted content store (`gateway.files.content_store_enabled`); rejected in handler when off.
    content: Optional[str] = Field(default=None, max_length=400_000)
    content_b64: Optional[str] = Field(default=None, max_length=550_000)
    file: Optional[object] = Field(default=None, exclude=True)

    @model_validator(mode="after")
    def _reject_raw_file_object(self) -> "GatewayOpenAIFileCreateRequest":
        if self.file is not None:
            raise ValueError(
                "Multipart `file` uploads are not accepted; use content or content_b64 when "
                "gateway.files.content_store_enabled=true, otherwise register metadata only."
            )
        return self


class GatewayOpenAIFileResponse(BaseModel):
    id: str
    object: str
    filename: str
    purpose: str
    bytes: int
    content_type: str
    status: str
    created_at: int
    request_id: str
    trace_id: str
    content_stored: bool = False


class GatewayOpenAIFilesListResponse(BaseModel):
    object: str
    data: list[GatewayOpenAIFileResponse]


class GatewayOpenAIFileDeleteResponse(BaseModel):
    id: str
    object: str
    deleted: bool
    request_id: str
    trace_id: str


class GatewayOpenAIFileContentResponse(BaseModel):
    id: str
    object: str = "file.content"
    filename: str
    purpose: str
    bytes: int
    content_type: str
    # Registry-only files: binary payloads are never stored or returned.
    content_available: bool = False
    content: str = ""
    media_type: str = "application/json"
    request_id: str
    trace_id: str


class GatewayOpenAIBatchCreateRequest(BaseModel):
    endpoint_family: str = Field(default="responses", min_length=1, max_length=128)
    requests: list[dict[str, object]] = Field(min_length=1)
    metadata: Optional[dict[str, object]] = None
    environment: str = "dev"


class GatewayOpenAIBatchResponse(BaseModel):
    id: str
    object: str
    status: str
    endpoint_family: str
    request_count: int
    completed_count: int
    failed_count: int
    request_id: str
    trace_id: str
    created_at: int
    metadata: dict[str, object]


class GatewayOpenAIBatchesListResponse(BaseModel):
    object: str
    data: list[GatewayOpenAIBatchResponse]


class GatewayOpenAIBatchDeleteResponse(BaseModel):
    id: str
    object: str
    deleted: bool
    request_id: str
    trace_id: str


class GatewayOpenAIBatchCancelResponse(BaseModel):
    id: str
    object: str
    status: str
    request_id: str
    trace_id: str


class GatewayOpenAIBatchCompleteRequest(BaseModel):
    completed_count: Optional[int] = Field(default=None, ge=0)
    failed_count: Optional[int] = Field(default=None, ge=0)
    status: str = Field(default="completed", min_length=1, max_length=32)


class GatewayOpenAIBatchCompleteResponse(BaseModel):
    id: str
    object: str = "batch"
    status: str
    completed_count: int
    failed_count: int
    request_id: str
    trace_id: str


class GatewayOpenAIBatchExpireResponse(BaseModel):
    id: str
    object: str = "batch"
    status: str
    request_id: str
    trace_id: str


class GatewayOpenAIBatchResultItem(BaseModel):
    id: str
    custom_id: str
    status: str
    model: Optional[str] = None
    endpoint: Optional[str] = None
    error: Optional[str] = None


class GatewayOpenAIBatchResultsResponse(BaseModel):
    id: str
    object: str = "list"
    status: str
    format: str = "jsonl"
    count: int
    content: str
    data: list[GatewayOpenAIBatchResultItem] = Field(default_factory=list)
    request_id: str
    trace_id: str


class TrafficMirroringBreakdownItem(BaseModel):
    key: str
    events: int


class TrafficMirroringOutcomeComparisonItem(BaseModel):
    primary_outcome: str
    mirror_outcome: str
    events: int


class RouteTrafficMirroringAnalyticsSummaryResponse(BaseModel):
    route_policy_id: str
    environment: Optional[str] = None
    request_tag: Optional[str] = None
    hours: int
    total_mirror_events: int
    mirrored_request_count: int
    top_mirror_providers: list[TrafficMirroringBreakdownItem]
    primary_provider_distribution: list[TrafficMirroringBreakdownItem]
    mirror_mode_distribution: list[TrafficMirroringBreakdownItem]
    region_distribution: list[TrafficMirroringBreakdownItem]
    outcome_comparison: list[TrafficMirroringOutcomeComparisonItem]


class RouteTrafficMirroringExperimentRowResponse(BaseModel):
    timestamp: datetime
    request_id: str
    environment: str
    request_tag: Optional[str] = None
    requested_region: Optional[str] = None
    primary_provider_id: str
    primary_outcome: str
    mirror_provider_id: str
    mirror_mode: str
    mirror_outcome: str
    sample_percent: int


class RouteTrafficMirroringExperimentReportResponse(BaseModel):
    route_policy_id: str
    environment: Optional[str] = None
    request_tag: Optional[str] = None
    hours: int
    limit: int
    offset: int
    total_rows: int
    rows: list[RouteTrafficMirroringExperimentRowResponse]


class McpServerResponse(BaseModel):
    server_id: str
    base_url: str
    transport: str
    enabled: bool
    allowed_tools: list[str]


class McpToolListRequest(BaseModel):
    environment: str = "dev"


class McpToolListResponse(BaseModel):
    server_id: str
    tools: list[dict[str, object]]


class McpToolCallRequest(BaseModel):
    environment: str = "dev"
    tool_name: str = Field(min_length=1)
    arguments: dict[str, object] = Field(default_factory=dict)


class McpToolCallResponse(BaseModel):
    server_id: str
    tool_name: str
    result: object
    trace_id: str


class GatewaySystemInstructionsUpdateRequest(BaseModel):
    instructions: str = Field(default="", max_length=8000)


class GatewaySystemInstructionsResponse(BaseModel):
    config_key: str
    instructions: str
    updated_by: Optional[str] = None
    updated_at: Optional[datetime] = None


class GatewaySystemRulesUpdateRequest(BaseModel):
    rules: list[dict[str, object]] = Field(default_factory=list)


class GatewaySystemRulesResponse(BaseModel):
    config_key: str
    rules: list[dict[str, str]] = Field(default_factory=list)
    updated_by: Optional[str] = None
    updated_at: Optional[datetime] = None


class GatewayCursorTokenUpdateRequest(BaseModel):
    storage_mode: str = Field(default="db", pattern="^(db|external)$")
    token: Optional[str] = Field(default=None, min_length=1, max_length=8192)
    external_provider_id: Optional[str] = Field(default=None, min_length=3, max_length=128)
    external_secret_ref: Optional[str] = Field(default=None, min_length=1, max_length=1024)


class GatewayCursorTokenResponse(BaseModel):
    config_key: str
    configured: bool
    storage_mode: str = "db"
    external_provider_id: Optional[str] = None
    external_secret_ref: Optional[str] = None
    masked_hint: Optional[str] = None
    updated_by: Optional[str] = None
    updated_at: Optional[datetime] = None
    deprecated: bool = True
    migration_hint: str = (
        "Use Providers secret providers with provider_type=db or external backends, "
        "PUT /secrets/providers/{provider_id}/values for db secrets, and "
        "PUT /gateway/cursor-secret-binding for gateway resolution."
    )


class GatewayCursorSecretBindingUpdateRequest(BaseModel):
    secret_provider_id: str = Field(min_length=3, max_length=128)
    secret_ref: str = Field(min_length=1, max_length=1024)


class GatewayCursorSecretBindingResponse(BaseModel):
    config_key: str
    configured: bool
    secret_provider_id: Optional[str] = None
    secret_ref: Optional[str] = None
    provider_type: Optional[str] = None
    masked_hint: Optional[str] = None
    updated_by: Optional[str] = None
    updated_at: Optional[datetime] = None


class GatewayExternalCallbackCreateRequest(BaseModel):
    callback_url: str = Field(min_length=8, max_length=2048)
    event_types: list[str] = Field(default_factory=lambda: ["gateway.route.execute_fallback"]) 
    environment: str = "dev"
    sink_type: str = Field(default="generic_webhook", min_length=3, max_length=64)
    sink_route_key: Optional[str] = Field(default=None, max_length=128)
    correlation_preset: str = Field(default="trace_resource", min_length=3, max_length=64)
    redact_sensitive: bool = True
    enabled: bool = True
    description: Optional[str] = Field(default=None, max_length=500)


class GatewayExternalCallbackUpdateRequest(BaseModel):
    callback_url: Optional[str] = Field(default=None, min_length=8, max_length=2048)
    event_types: Optional[list[str]] = None
    environment: Optional[str] = None
    sink_type: Optional[str] = Field(default=None, min_length=3, max_length=64)
    sink_route_key: Optional[str] = Field(default=None, max_length=128)
    correlation_preset: Optional[str] = Field(default=None, min_length=3, max_length=64)
    redact_sensitive: Optional[bool] = None
    enabled: Optional[bool] = None
    description: Optional[str] = Field(default=None, max_length=500)


class GatewayExternalCallbackResponse(BaseModel):
    callback_id: str
    callback_url: str
    event_types: list[str]
    environment: str
    sink_type: str
    sink_route_key: Optional[str] = None
    correlation_preset: str
    redact_sensitive: bool
    enabled: bool
    description: Optional[str] = None
    created_by: str
    created_at: str
    updated_at: str


class GatewayExternalCallbackTestRequest(BaseModel):
    environment: str = "dev"
    sample_payload: dict[str, object] = Field(default_factory=dict)


class GatewayExternalCallbackTestResponse(BaseModel):
    callback_id: str
    callback_url: str
    environment: str
    sink_type: str
    sink_route_key: Optional[str] = None
    correlation_preset: str
    delivery_status: str
    trace_id: str
    delivered_at: str
    redaction_applied: bool
    correlation_context: dict[str, object]
    payload_preview: dict[str, object]


class GatewayExternalCallbackExportRequest(BaseModel):
    environment: Optional[str] = None
    limit: int = Field(default=50, ge=1, le=500)


class GatewayExternalCallbackExportResponse(BaseModel):
    export_id: str
    exported_at: str
    export_uri: str
    callback_count: int
    event_count: int
    sink_distribution: dict[str, int] = Field(default_factory=dict)
    correlation_preset_distribution: dict[str, int] = Field(default_factory=dict)


class GatewayGovernanceEvidenceExportRequest(BaseModel):
    decision_outcome: Optional[Literal["allow", "deny", "warn"]] = None
    limit_per_action: int = Field(default=100, ge=10, le=500)
    bundle_label: str = Field(default="gateway-governance-evidence", min_length=3, max_length=120)
    data_classification: Literal["internal", "confidential", "restricted"] = "confidential"
    retention_days: int = Field(default=90, ge=7, le=2555)
    classification_owner: str = Field(
        default="security-ops",
        min_length=2,
        max_length=120,
        description="Accountable owner for the evidence bundle (residual #7).",
    )
    approved_sharing_channels: list[str] = Field(
        default_factory=lambda: ["security-ops", "compliance-review"],
        min_length=1,
        max_length=12,
    )
    redact_actor_login: bool = False


class GatewayGovernanceEvidenceActionSummary(BaseModel):
    action_type: str
    event_count: int
    latest_timestamp: Optional[datetime] = None
    latest_trace_id: Optional[str] = None


class GatewayGovernanceEvidenceExportResponse(BaseModel):
    export_id: str
    exported_at: str
    export_uri: str
    bundle_label: str
    data_classification: str
    classification_owner: str
    retention_days: int
    retain_until: str
    approved_sharing_channels: list[str]
    redaction_applied: bool
    event_count: int
    action_summaries: list[GatewayGovernanceEvidenceActionSummary]
    events: list[AuditEventResponse]


class WorkloadIdentityProviderRequest(BaseModel):
    tenant_id: str
    provider_type: str
    audience: str
    role_arn_or_equivalent: str
    bootstrap_token: Optional[str] = None
    session_duration_seconds: int = 3600
    allowed_subject_patterns: str = Field(
        default="[]",
        description="JSON array of wildcard subject patterns.",
        examples=['["agent-*", "team/platform/*"]', '["service-account:build-*", "org/dev/*"]'],
    )


class WorkloadIdentityTokenExchangeRequest(BaseModel):
    tenant_id: str
    workload_identity_profile_id: str
    subject: str


class WorkloadIdentityTokenExchangeResponse(BaseModel):
    expires_in: int
    subject: str
    token_source: str
    token_reference: str
    access_token: Optional[str] = None


class WorkloadIdentityTrustValidateRequest(BaseModel):
    tenant_id: str
    check_type: str = "trust_policy"
    expected_audience: Optional[str] = None
    simulate_pass: bool = True


class WorkloadIdentityTrustValidateResponse(BaseModel):
    workload_identity_profile_id: str
    check_type: str
    status: str
    details: str


class WorkloadIdentityProviderHealthResponse(BaseModel):
    workload_identity_profile_id: str
    tenant_id: str
    status: str
    provider_type: str
    audience: str
    session_duration_seconds: int
    last_token_exchange_at: Optional[datetime]
    token_exchange_stale_minutes: Optional[int]


class WorkloadIdentityProviderListResponse(BaseModel):
    workload_identity_profile_id: str
    tenant_id: str
    tenant_name: str
    tenant_type: str
    tenant_description: str
    provider_type: str
    audience: str
    session_duration_seconds: int
    status: str
    last_token_exchange_at: Optional[datetime]


class SecretProviderRequest(BaseModel):
    tenant_id: str
    provider_type: str
    provider_address: str
    auth_method: str
    role_or_mount: str
    bootstrap_token: Optional[str] = None
    secret_path_prefixes: str = "[]"
    lease_ttl_seconds: int = 3600
    auto_renew_enabled: bool = True


class SecretProviderLeaseRenewRequest(BaseModel):
    secret_ref: str
    requested_ttl_seconds: int = Field(default=3600, ge=60, le=86400)


class SecretProviderLeaseResponse(BaseModel):
    lease_id: str
    secret_provider_id: str
    secret_ref: str
    lease_ttl_seconds: int
    issued_at: datetime
    renewed_at: Optional[datetime]
    expires_at: datetime
    status: str


class SecretProviderHealthResponse(BaseModel):
    secret_provider_id: str
    status: str
    auto_renew_enabled: bool
    lease_count_active: int
    leases_expiring_5m: int
    last_health_check_at: Optional[datetime]


class SecretProviderListResponse(BaseModel):
    secret_provider_id: str
    tenant_id: str
    tenant_name: str
    tenant_type: str
    tenant_description: str
    provider_type: str
    provider_address: str
    auth_method: str
    role_or_mount: str
    lease_ttl_seconds: int
    auto_renew_enabled: bool
    status: str
    last_health_check_at: Optional[datetime]


class SecretProviderValueUpsertRequest(BaseModel):
    secret_ref: str = Field(min_length=1, max_length=1024)
    secret_value: str = Field(min_length=1, max_length=8192)


class SecretProviderValueResponse(BaseModel):
    secret_provider_id: str
    secret_ref: str
    configured: bool
    masked_hint: Optional[str] = None
    updated_by: Optional[str] = None
    updated_at: Optional[datetime] = None


class TenantCatalogUpsertRequest(BaseModel):
    tenant_id: str
    tenant_name: str
    tenant_type: str
    description: str = ""
    status: str = Field(default="active", pattern="^(active|inactive)$")


class TenantCatalogResponse(ORMBase):
    tenant_id: str
    tenant_name: str
    tenant_type: str
    description: str
    status: str
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class SupportedModelUpsertRequest(BaseModel):
    model_config = {"protected_namespaces": ()}

    provider_type: str
    model_name: str
    display_name: str
    context_window_tokens: int = Field(default=128000, ge=1, le=10000000)
    status: str = Field(default="active", pattern="^(active|beta|deprecated|disabled)$")
    description: str = ""
    recommendation_rationale: str = ""
    credential_source_class: str = Field(default="", pattern="^(|cp_ref|cp_wif|cp_env)$")
    default_binding_id: Optional[str] = None


class SupportedModelSeedTrendingRequest(BaseModel):
    overwrite: bool = False
    auto_approve: bool = True
    packs: list[str] = Field(
        default_factory=lambda: ["trending"],
        description="Model packs to seed: trending, bedrock, azure, gcp, or all.",
    )


class SupportedModelSeedTrendingResponse(BaseModel):
    created: int
    updated: int
    skipped: int
    pack_size: int
    overwrite: bool
    auto_approve: bool
    packs: list[str] = Field(default_factory=list)


class SupportedModelCloudDiscoverRequest(BaseModel):
    targets: list[str] = Field(
        default_factory=lambda: ["all"],
        description="Discover targets: bedrock, azure, google, vertex, or all.",
    )
    region: Optional[str] = Field(default=None, max_length=64)
    limit: int = Field(default=200, ge=1, le=1000)


class SupportedModelCloudDiscoverModel(BaseModel):
    model_config = {"protected_namespaces": ()}

    provider_type: str
    model_name: str
    display_name: str
    context_window_tokens: int = 128000
    description: str = ""
    recommendation_rationale: str = ""
    status: str = "active"


class SupportedModelCloudDiscoverResponse(BaseModel):
    targets: list[str]
    total: int
    models: list[SupportedModelCloudDiscoverModel]
    results: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[dict[str, str]] = Field(default_factory=list)


class SupportedModelCloudSyncRequest(BaseModel):
    targets: list[str] = Field(
        default_factory=lambda: ["all"],
        description="Sync targets: bedrock, azure, google, vertex, or all.",
    )
    region: Optional[str] = Field(default=None, max_length=64)
    overwrite: bool = False
    auto_approve: bool = True


class SupportedModelCloudSyncResponse(BaseModel):
    targets: list[str]
    discovered: int
    created: int
    updated: int
    skipped: int
    pack_size: int
    overwrite: bool
    auto_approve: bool
    results: list[dict[str, Any]] = Field(default_factory=list)
    errors: list[dict[str, str]] = Field(default_factory=list)


class InferenceReadinessProvider(BaseModel):
    model_config = {"protected_namespaces": ()}

    provider_type: str
    label: str
    catalog_models: int = 0
    invoke_supported: bool = False
    env_credential_configured: bool = False
    endpoint_configured: bool = True
    live_ready: bool = False
    status: str
    setup_hint: str = ""


class InferenceReadinessResponse(BaseModel):
    simulation_enabled: bool
    ready_providers: int
    total_providers: int
    catalog_models_total: int
    providers: list[InferenceReadinessProvider]


class GatewayBestPracticesCheck(BaseModel):
    id: str
    label: str
    status: str
    passed: bool
    weight: int
    detail: str
    recommendation: str
    market_refs: list[str] = Field(default_factory=list)


class GatewayBestPracticesMarketTrend(BaseModel):
    id: str
    title: str
    summary: str


class GatewayBestPracticesNextAction(BaseModel):
    action: str
    check_id: str
    weight: int


class GatewayBestPracticesPostureResponse(BaseModel):
    score: int
    max_score: int = 100
    band: str
    earned_weight: int
    possible_weight: int
    checks: list[GatewayBestPracticesCheck]
    top_gaps: list[GatewayBestPracticesCheck] = Field(default_factory=list)
    readiness: dict
    market_trends: list[GatewayBestPracticesMarketTrend] = Field(default_factory=list)
    next_actions: list[GatewayBestPracticesNextAction] = Field(default_factory=list)


class GatewayFallbackSuggestRequest(BaseModel):
    max_hops: int = Field(default=3, ge=1, le=8)
    prefer_live_only: bool = True


class GatewayFallbackSuggestTarget(BaseModel):
    provider_id: str
    provider_type: str
    model_name: str
    priority: int
    live_ready: bool = False


class GatewayFallbackSuggestResponse(BaseModel):
    priority_order: list[dict]
    targets: list[GatewayFallbackSuggestTarget]
    skipped: list[dict] = Field(default_factory=list)
    recommended: dict
    rationale: str
    live_ready_count: int = 0


class GatewayLeadershipBootstrapRequest(BaseModel):
    tenant_id: str = Field(default="tenant-leadership-bootstrap", min_length=1, max_length=128)
    environment: str = Field(default="dev", min_length=1, max_length=32)
    max_hops: int = Field(default=3, ge=2, le=8)
    enhance_cpli: bool = True
    probe_peer: Optional[bool] = Field(
        default=None,
        description=(
            "When null, auto-enables peer probe for CPLI enhance on production APP_ENV "
            "or APP_PLANE=control|data. Explicit true/false overrides."
        ),
    )


class GatewayLeadershipBootstrapResponse(BaseModel):
    bootstrapped: bool = True
    route_policy_id: str
    route_name: str
    cache_policy_id: Optional[str] = None
    budget_policy_id: Optional[str] = None
    virtual_key_id: Optional[str] = None
    tenant_id: str
    environment: str
    before: dict
    after: dict
    delta: int
    actions: list[dict] = Field(default_factory=list)
    remaining_gaps: list[dict] = Field(default_factory=list)
    suggestion_rationale: Optional[str] = None
    note: str = ""
    virtual_key_count: int = 0
    budget_policy_count: int = 0
    cpli: Optional[dict] = None


class GatewayAutoRouteRequest(BaseModel):
    prompt_text: str = Field(min_length=1, max_length=20000)
    prefer_live_only: bool = True
    max_candidates_per_tier: int = Field(default=3, ge=1, le=8)
    strategy: str = Field(default="balanced", pattern="^(balanced|cost|quality)$")
    has_tools: bool = False
    json_response_format: bool = False
    message_count: int = Field(default=0, ge=0, le=500)
    refine_with_judge: bool = True
    use_telemetry_ranking: bool = True
    route_policy_id: Optional[str] = Field(default=None, max_length=128)
    request_tag: Optional[str] = Field(default=None, max_length=64)
    use_cache: Optional[bool] = None


class GatewayAutoRouteSelected(BaseModel):
    tier: str
    provider_type: str
    model_name: str
    live_ready: bool = False
    source: str = "preferred_catalog"
    strategy: Optional[str] = None


class GatewayAutoRouteResponse(BaseModel):
    complexity: dict
    selected: Optional[GatewayAutoRouteSelected] = None
    selected_model: Optional[str] = None
    selected_provider_type: Optional[str] = None
    tier_candidates: dict
    prefer_live_only: bool = True
    strategy: str = "balanced"
    refine_with_judge: bool = True
    telemetry_ranking: dict = Field(default_factory=dict)
    rationale: str
    readiness: dict = Field(default_factory=dict)


class GatewayModelRankingsResponse(BaseModel):
    hours: int
    environment: Optional[str] = None
    models: list[dict]
    score_by_model: dict
    sample_events: int
    leader_signal: str


class GatewayLeadershipWarmupRequest(BaseModel):
    samples: int = Field(default=6, ge=1, le=12)
    environment: str = Field(default="dev", min_length=1, max_length=32)
    strategy: str = Field(default="balanced", pattern="^(balanced|cost|quality)$")


class GatewayLeadershipWarmupResponse(BaseModel):
    created_events: int
    environment: str
    strategy: str
    events: list[dict]
    message: str


class GatewayAttributionAnalyticsResponse(BaseModel):
    hours: int
    environment: Optional[str] = None
    exclude_warmup: bool = False
    warmup_events_skipped: int = 0
    total_events: int
    attributed_events: int
    attribution_coverage_percent: float
    switched_events: int
    switch_rate_percent: float
    auto_routed_events: int
    cost_cents_switched: int
    cost_cents_same_model: int
    top_switch_pairs: list[dict]
    auto_route_tiers: list[dict]
    endpoint_families: list[dict]
    leader_signal: str


class GatewayLeadershipIndexResponse(BaseModel):
    score: float
    max_score: int = 100
    band: str
    components: dict
    attribution: dict
    model_rankings: Optional[dict] = None
    posture_band: Optional[str] = None
    next_actions: list[dict] = Field(default_factory=list)
    market_claim: str
    exclude_warmup: bool = False


class GatewayAutoRouteCompareRequest(BaseModel):
    prompt_text: str = Field(min_length=1, max_length=20000)
    prefer_live_only: bool = True
    refine_with_judge: bool = True


class GatewayAutoRouteBatchRequest(BaseModel):
    prompts: list[str] = Field(min_length=1, max_length=25)
    strategy: str = Field(default="balanced", pattern="^(balanced|cost|quality)$")
    prefer_live_only: bool = True


class GatewayLeadershipFloorQuery(BaseModel):
    floor_score: float = Field(default=70.0, ge=0, le=100)


class GatewayLiveJudgeRefineRequest(BaseModel):
    prompt_text: str = Field(min_length=1, max_length=20000)
    force_live: bool = False


class GatewayOpenRouterLiquidityImportRequest(BaseModel):
    use_seed: bool = True
    models: Optional[list[dict]] = None


class GatewayAutoRouteExperimentCreateRequest(BaseModel):
    name: str = Field(default="auto-route-ab", min_length=1, max_length=128)
    strategies: list[str] = Field(default_factory=lambda: ["balanced", "cost"], min_length=1, max_length=3)
    traffic_split: Optional[dict[str, float]] = None


class GatewayFallbackQualityGateRequest(BaseModel):
    min_live_ready: int = Field(default=2, ge=1, le=8)
    min_leadership_score: float = Field(default=60.0, ge=0, le=100)


class GatewayAutoRouteStreamFramesRequest(BaseModel):
    prompt_text: str = Field(min_length=1, max_length=20000)
    strategy: str = Field(default="balanced", pattern="^(balanced|cost|quality)$")


class GatewayAutoRouteExplainRequest(BaseModel):
    prompt_text: str = Field(min_length=1, max_length=20000)
    strategy: str = Field(default="balanced", pattern="^(balanced|cost|quality)$")
    max_budget_tier: Optional[str] = Field(default=None, pattern="^(simple|standard|complex)$")
    latency_slo_ms: Optional[int] = Field(default=None, ge=50, le=120000)
    allowed_regions: Optional[list[str]] = None
    tools_json: Optional[list[dict]] = None
    attachment_types: Optional[list[str]] = None


class GatewayPromptAutoRouteBindRequest(BaseModel):
    prompt_registry_id: str = Field(min_length=1, max_length=128)
    strategy: str = Field(default="balanced", pattern="^(balanced|cost|quality)$")
    prefer_live_only: bool = True
    max_budget_tier: Optional[str] = Field(default=None, pattern="^(simple|standard|complex)$")


class GatewayVirtualKeyAutoRoutePolicyRequest(BaseModel):
    virtual_key_id: str = Field(min_length=1, max_length=128)
    strategy: str = Field(default="balanced", pattern="^(balanced|cost|quality)$")
    prefer_live_only: bool = True
    max_budget_tier: Optional[str] = Field(default=None, pattern="^(simple|standard|complex)$")
    enabled: bool = True


class GatewayAlertChannelsRequest(BaseModel):
    webhook_url: Optional[str] = Field(default=None, max_length=512)
    slack_webhook_url: Optional[str] = Field(default=None, max_length=512)
    email_to: Optional[str] = Field(default=None, max_length=256)
    enabled: bool = True


class GatewayAlertDispatchRequest(BaseModel):
    hours: int = Field(default=24, ge=1, le=168)
    floor_score: float = Field(default=70.0, ge=0, le=100)
    dry_run: bool = True


class GatewayOtelAttributesRequest(BaseModel):
    intended_model: str = Field(min_length=1, max_length=255)
    actual_model: str = Field(min_length=1, max_length=255)
    auto_route_tier: Optional[str] = None
    strategy: Optional[str] = None
    trace_id: Optional[str] = None


class GatewayCanaryAutoRouteExplainRequest(BaseModel):
    route_policy_id: str = Field(min_length=1, max_length=128)
    prompt_text: str = Field(default="Canary auto-route interaction sample", min_length=1, max_length=20000)


class GatewayResidencyFilterRequest(BaseModel):
    allowed_regions: list[str] = Field(default_factory=list, max_length=32)


class GatewayReplayStrategyRequest(BaseModel):
    prompt_text: str = Field(min_length=1, max_length=20000)
    strategies: Optional[list[str]] = None


class GatewayCsvClassifyRequest(BaseModel):
    csv_text: str = Field(min_length=1, max_length=200000)
    strategy: str = Field(default="balanced", pattern="^(balanced|cost|quality)$")


class GatewayWarmupRetentionRequest(BaseModel):
    retain_hours: int = Field(default=168, ge=1, le=720)
    max_events: int = Field(default=500, ge=10, le=5000)


class GatewayWarmupPurgeRequest(BaseModel):
    dry_run: bool = True


class GatewayRankingWeightsRequest(BaseModel):
    volume: float = Field(default=0.35, ge=0, le=1)
    stability: float = Field(default=0.30, ge=0, le=1)
    cost: float = Field(default=0.20, ge=0, le=1)
    latency: float = Field(default=0.15, ge=0, le=1)


class GatewayJudgeThresholdsRequest(BaseModel):
    near_standard: list[int] = Field(default_factory=lambda: [20, 30], min_length=2, max_length=2)
    near_complex: list[int] = Field(default_factory=lambda: [50, 60], min_length=2, max_length=2)


class GatewayRouteStrategyPolicyRequest(BaseModel):
    route_policy_id: str = Field(min_length=1, max_length=128)
    strategy: str = Field(default="balanced", pattern="^(balanced|cost|quality)$")
    prefer_live_only: bool = True


class GatewayRequestTagStrategyPolicyRequest(BaseModel):
    request_tag: str = Field(min_length=1, max_length=64)
    strategy: str = Field(default="balanced", pattern="^(balanced|cost|quality)$")


class GatewayWhyModelCardRequest(BaseModel):
    prompt_text: str = Field(min_length=1, max_length=20000)
    strategy: str = Field(default="balanced", pattern="^(balanced|cost|quality)$")


class GatewayCiFloorRequest(BaseModel):
    floor_score: float = Field(default=70.0, ge=0, le=100)


class GatewayChaosDrillRequest(BaseModel):
    provider_id: str = Field(default="chaos-provider", min_length=1, max_length=128)


class GatewayShareLinkRequest(BaseModel):
    hours: int = Field(default=24, ge=1, le=168)
    ttl_seconds: int = Field(default=3600, ge=60, le=86400)


class GatewayAlertDeliverRequest(BaseModel):
    hours: int = Field(default=24, ge=1, le=168)
    floor_score: float = Field(default=70.0, ge=0, le=100)
    dry_run: bool = True


class GatewayAlertAllowlistRequest(BaseModel):
    hosts: list[str] = Field(default_factory=list, max_length=50)


class GatewayApplyRankedFallbackRequest(BaseModel):
    route_policy_id: str = Field(min_length=1, max_length=128)
    max_hops: int = Field(default=3, ge=1, le=8)
    environment: str = Field(default="dev", min_length=1, max_length=32)


class GatewayResolveStrategyRequest(BaseModel):
    route_policy_id: Optional[str] = Field(default=None, max_length=128)
    request_tag: Optional[str] = Field(default=None, max_length=64)
    default_strategy: str = Field(default="balanced", pattern="^(balanced|cost|quality)$")


class GatewaySimulationJudgeRequest(BaseModel):
    prompt_text: str = Field(min_length=1, max_length=20000)


class GatewayEvidenceDiffRequest(BaseModel):
    hours_a: int = Field(default=24, ge=1, le=168)
    hours_b: int = Field(default=168, ge=1, le=168)


class GatewayEnforcementFlagsRequest(BaseModel):
    enforce_pii_bias: Optional[bool] = None
    enforce_adversarial_boost: Optional[bool] = None
    use_decision_cache: Optional[bool] = None
    resolve_strategy_policies: Optional[bool] = None
    enforce_model_denylist: Optional[bool] = None
    decision_cache_ttl_seconds: Optional[int] = Field(default=None, ge=15, le=300)


class GatewayModelRoutePolicyRequest(BaseModel):
    allowlist: Optional[list[str]] = None
    denylist: Optional[list[str]] = None


class GatewayCanaryPromoteGateRequest(BaseModel):
    route_policy_id: str = Field(min_length=1, max_length=128)
    floor_score: float = Field(default=70.0, ge=0, le=100)


class GatewayCircuitAnnotateRequest(BaseModel):
    route_policy_id: str = Field(min_length=1, max_length=128)
    environment: str = Field(default="dev", min_length=1, max_length=32)


class GatewayCanaryAnnotateComboRequest(BaseModel):
    route_policy_id: str = Field(min_length=1, max_length=128)
    floor_score: float = Field(default=70.0, ge=0, le=100)
    annotate_if_passed: bool = True
    environment: str = Field(default="dev", min_length=1, max_length=32)


class GatewayAutoRouteExplainRequest(BaseModel):
    prompt_text: str = Field(min_length=1, max_length=20000)
    strategy: str = Field(default="balanced", pattern="^(balanced|cost|quality)$")
    prefer_live_only: bool = True
    route_policy_id: Optional[str] = Field(default=None, max_length=128)
    request_tag: Optional[str] = Field(default=None, max_length=64)


class GatewayShadowCompareRequest(BaseModel):
    prompt_text: str = Field(min_length=1, max_length=20000)
    prefer_live_only: bool = True


class GatewayOperatorChecklistRequest(BaseModel):
    completed: dict[str, bool] = Field(default_factory=dict)


class GatewayRouteHealthRequest(BaseModel):
    route_policy_id: str = Field(min_length=1, max_length=128)


class GatewayLeadershipIncidentRequest(BaseModel):
    title: str = Field(min_length=1, max_length=200)
    severity: str = Field(default="warning", max_length=32)
    detail: Optional[str] = Field(default=None, max_length=500)


class GatewayLeadershipIncidentCloseRequest(BaseModel):
    incident_id: str = Field(min_length=1, max_length=64)


class GatewayScoreTrendMuteRequest(BaseModel):
    minutes: int = Field(default=60, ge=5, le=1440)
    reason: str = Field(default="", max_length=200)


class GatewayLeadershipFloorGateRequest(BaseModel):
    floor_score: float = Field(default=70.0, ge=0, le=100)
    hours: int = Field(default=24, ge=1, le=168)


class GatewayCompositeGateRequest(BaseModel):
    floor_score: float = Field(default=70.0, ge=0, le=100)
    checklist_min_percent: float = Field(default=50.0, ge=0, le=100)
    hours: int = Field(default=24, ge=1, le=168)


class GatewayPreferredModelRequest(BaseModel):
    model_name: str = Field(min_length=1, max_length=128)
    provider_type: Optional[str] = Field(default=None, max_length=64)
    enabled: bool = True


class GatewayIncidentEscalateRequest(BaseModel):
    incident_id: str = Field(min_length=1, max_length=64)
    severity: str = Field(default="critical", max_length=32)


class GatewayDeleteTagStrategyRequest(BaseModel):
    request_tag: str = Field(min_length=1, max_length=64)


class GatewayDeleteRouteStrategyRequest(BaseModel):
    route_policy_id: str = Field(min_length=1, max_length=128)


class GatewayFloorGateAutoIncidentRequest(BaseModel):
    floor_score: float = Field(default=70.0, ge=0, le=100)
    hours: int = Field(default=24, ge=1, le=168)
    open_incident_on_fail: bool = True


class GatewayShadowTrafficRequest(BaseModel):
    percent: float = Field(default=0.0, ge=0, le=100)
    enabled: bool = True


class GatewayCanaryAutoRollbackRequest(BaseModel):
    enabled: bool = True
    on_red_light: bool = True
    on_floor_fail: bool = True


class GatewayLatencyBudgetRequest(BaseModel):
    observed_ms: Optional[float] = Field(default=None, ge=0, le=600000)
    budget_ms: Optional[float] = Field(default=None, ge=1, le=600000)


class GatewayFailoverSimulationRequest(BaseModel):
    primary_provider: str = Field(default="openai", min_length=1, max_length=64)


class GatewayCrossEnvSyncDryRunRequest(BaseModel):
    source_env: str = Field(default="staging", min_length=1, max_length=32)
    target_env: str = Field(default="prod", min_length=1, max_length=32)


class SupportedModelApprovalRequest(BaseModel):
    decision: str = Field(pattern="^(approve|reject)$")
    approval_ticket_ref: str = Field(min_length=1, max_length=128)
    approval_note: str = Field(min_length=3, max_length=2000)
    environment: str = Field(default="dev", min_length=1, max_length=32)


class SupportedModelResponse(ORMBase):
    supported_model_id: str
    provider_type: str
    model_name: str
    display_name: str
    context_window_tokens: int
    status: str
    description: str
    recommendation_rationale: str
    approval_status: str
    approval_ticket_ref: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    metadata_version: int
    credential_source_class: str = ""
    default_binding_id: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class PlatformModelAvailabilityPolicy(BaseModel):
    catalog_statuses: list[str]
    require_approval: bool
    enforce_tenant_entitlements: bool


class PlatformAvailableModelItem(BaseModel):
    model_config = {"protected_namespaces": ()}

    supported_model_id: str
    provider_type: str
    model_name: str
    model_ref: str
    display_name: str
    status: str
    approval_status: str
    context_window_tokens: int
    ui_available: bool = True
    ui_priority_rank: int


class PlatformAvailableModelsResponse(BaseModel):
    object: str = "list"
    data: list[PlatformAvailableModelItem]
    total: int
    policy: PlatformModelAvailabilityPolicy


class TenantSupportedModelEntitlementUpsertRequest(BaseModel):
    model_config = {"protected_namespaces": ()}

    tenant_id: str
    provider_type: str
    model_name: str
    status: str = Field(default="active", pattern="^(active|inactive)$")


class ProviderCredentialBindingUpsertRequest(BaseModel):
    binding_id: Optional[str] = None
    tenant_id: str = Field(min_length=1, max_length=128)
    binding_name: str = Field(min_length=1, max_length=255)
    consumer_type: str = Field(pattern="^(gateway|agent|route|platform)$")
    consumer_key: str = Field(min_length=1, max_length=255)
    provider_type: str = Field(min_length=1, max_length=64)
    credential_plane: str = Field(pattern="^(secret_ref|workload_identity)$")
    secret_provider_id: Optional[str] = None
    secret_ref: Optional[str] = None
    workload_identity_profile_id: Optional[str] = None
    environment: str = Field(default="dev", min_length=1, max_length=32)
    status: str = Field(default="active", pattern="^(active|inactive)$")


class ProviderCredentialBindingResponse(BaseModel):
    binding_id: str
    tenant_id: str
    binding_name: str
    consumer_type: str
    consumer_key: str
    provider_type: str
    credential_plane: str
    secret_provider_id: Optional[str] = None
    secret_ref: Optional[str] = None
    workload_identity_profile_id: Optional[str] = None
    environment: str
    status: str
    configured: bool
    masked_hint: Optional[str] = None
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class TenantSupportedModelEntitlementResponse(ORMBase):
    tenant_model_entitlement_id: str
    tenant_id: str
    provider_type: str
    model_name: str
    status: str
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class CostEventResponse(ORMBase):
    cost_event_id: str
    timestamp: datetime
    request_id: str
    trace_id: str
    request_tag: Optional[str] = None
    session_id: str
    agent_id: str
    owner_scope: str
    environment: str
    model_name: str
    endpoint_family: str
    input_tokens: int
    output_tokens: int
    estimated_cost_cents: int
    currency: str
    cache_hit: bool = False
    properties_json: str = "{}"


class CostSessionSummaryItem(BaseModel):
    session_id: str
    session_path: Optional[str] = None
    session_name: Optional[str] = None
    spend_cents: int
    event_count: int
    last_seen_at: datetime


class CostSessionListResponse(BaseModel):
    window_hours: int
    total_spend_cents: int
    total_event_count: int
    count: int
    items: list[CostSessionSummaryItem]


class CostSessionTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int


class CostSessionTimeseriesSeries(BaseModel):
    session_key: str
    session_id: str
    session_path: Optional[str] = None
    session_name: Optional[str] = None
    spend_cents: int
    event_count: int
    points: list[CostSessionTimeseriesPoint] = Field(default_factory=list)


class CostSessionTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    path_prefix: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostSessionTimeseriesSeries]


class GatewayLogExportCreateRequest(BaseModel):
    filters: Optional[dict[str, object]] = None
    requested_data: Optional[list[str]] = None
    description: Optional[str] = Field(default=None, max_length=512)
    workspace_id: Optional[str] = Field(default=None, max_length=128)


class GatewayLogExportResponse(BaseModel):
    id: str
    object: str = "logs.export"
    status: str
    description: str = ""
    workspace_id: Optional[str] = None
    # Use Any (not object): a field named `object` shadows the builtin in this class body.
    filters: dict[str, Any] = Field(default_factory=dict)
    requested_data: list[str] = Field(default_factory=list)
    row_count: int = 0
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class GatewayLogExportListResponse(BaseModel):
    object: str = "list"
    data: list[GatewayLogExportResponse]
    count: int


class GatewayLogExportDownloadResponse(BaseModel):
    id: str
    object: str = "logs.export.download"
    status: str
    row_count: int
    media_type: str = "application/x-ndjson"
    content: str
    # Auth-required API path (Portkey-style download locator).
    url: str = ""
    # Time-limited HMAC signed content path (exp+sig); metadata-only JSONL.
    signed_url: str = ""
    expires_at: Optional[int] = None


class GatewayLogExportCancelResponse(BaseModel):
    id: str
    object: str = "logs.export"
    status: str
    row_count: int = 0


class GatewayLogExportDeleteResponse(BaseModel):
    id: str
    object: str = "logs.export.deleted"
    deleted: bool = True


class CostTagTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostTagTimeseriesSeries(BaseModel):
    request_tag: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostTagTimeseriesPoint] = Field(default_factory=list)


class CostTagTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    tag_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostTagTimeseriesSeries]


class CostEndpointTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostEndpointTimeseriesSeries(BaseModel):
    endpoint_family: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostEndpointTimeseriesPoint] = Field(default_factory=list)


class CostEndpointTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    endpoint_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostEndpointTimeseriesSeries]


class CostAgentTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostAgentTimeseriesSeries(BaseModel):
    agent_id: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostAgentTimeseriesPoint] = Field(default_factory=list)


class CostAgentTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    agent_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostAgentTimeseriesSeries]


class CostEnvironmentTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostEnvironmentTimeseriesSeries(BaseModel):
    environment: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostEnvironmentTimeseriesPoint] = Field(default_factory=list)


class CostEnvironmentTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    environment_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostEnvironmentTimeseriesSeries]


class CostOwnerTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostOwnerTimeseriesSeries(BaseModel):
    owner_scope: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostOwnerTimeseriesPoint] = Field(default_factory=list)


class CostOwnerTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    owner_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostOwnerTimeseriesSeries]


class CostCurrencyTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostCurrencyTimeseriesSeries(BaseModel):
    currency: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostCurrencyTimeseriesPoint] = Field(default_factory=list)


class CostCurrencyTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    currency_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostCurrencyTimeseriesSeries]


class CostProviderTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostProviderTimeseriesSeries(BaseModel):
    provider: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostProviderTimeseriesPoint] = Field(default_factory=list)


class CostProviderTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    provider_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostProviderTimeseriesSeries]


class CostTeamTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostTeamTimeseriesSeries(BaseModel):
    team: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostTeamTimeseriesPoint] = Field(default_factory=list)


class CostTeamTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    team_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostTeamTimeseriesSeries]


class CostGroupTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostGroupTimeseriesSeries(BaseModel):
    group: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostGroupTimeseriesPoint] = Field(default_factory=list)


class CostGroupTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    group_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostGroupTimeseriesSeries]


class CostProjectTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostProjectTimeseriesSeries(BaseModel):
    project: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostProjectTimeseriesPoint] = Field(default_factory=list)


class CostProjectTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    project_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostProjectTimeseriesSeries]


class CostFeedbackTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostFeedbackTimeseriesSeries(BaseModel):
    feedback_state: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostFeedbackTimeseriesPoint] = Field(default_factory=list)


class CostFeedbackTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    feedback_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostFeedbackTimeseriesSeries]


class CostSessionPathTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostSessionPathTimeseriesSeries(BaseModel):
    session_path: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostSessionPathTimeseriesPoint] = Field(default_factory=list)


class CostSessionPathTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    path_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostSessionPathTimeseriesSeries]


class CostSessionNameTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostSessionNameTimeseriesSeries(BaseModel):
    session_name: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostSessionNameTimeseriesPoint] = Field(default_factory=list)


class CostSessionNameTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    name_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostSessionNameTimeseriesSeries]

class CostPromptIdTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostPromptIdTimeseriesSeries(BaseModel):
    prompt_id: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostPromptIdTimeseriesPoint] = Field(default_factory=list)


class CostPromptIdTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    prompt_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostPromptIdTimeseriesSeries]


class CostApplicationTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostApplicationTimeseriesSeries(BaseModel):
    application: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostApplicationTimeseriesPoint] = Field(default_factory=list)


class CostApplicationTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    application_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostApplicationTimeseriesSeries]


class CostCustomerTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostCustomerTimeseriesSeries(BaseModel):
    customer: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostCustomerTimeseriesPoint] = Field(default_factory=list)


class CostCustomerTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    customer_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostCustomerTimeseriesSeries]


class CostDepartmentTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostDepartmentTimeseriesSeries(BaseModel):
    department: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostDepartmentTimeseriesPoint] = Field(default_factory=list)


class CostDepartmentTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    department_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostDepartmentTimeseriesSeries]


class CostFeatureTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostFeatureTimeseriesSeries(BaseModel):
    feature: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostFeatureTimeseriesPoint] = Field(default_factory=list)


class CostFeatureTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    feature_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostFeatureTimeseriesSeries]


class CostRegionTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostRegionTimeseriesSeries(BaseModel):
    region: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostRegionTimeseriesPoint] = Field(default_factory=list)


class CostRegionTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    region_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostRegionTimeseriesSeries]


class CostWorkspaceTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostWorkspaceTimeseriesSeries(BaseModel):
    workspace: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostWorkspaceTimeseriesPoint] = Field(default_factory=list)


class CostWorkspaceTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    workspace_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostWorkspaceTimeseriesSeries]


class CostProductTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostProductTimeseriesSeries(BaseModel):
    product: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostProductTimeseriesPoint] = Field(default_factory=list)


class CostProductTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    product_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostProductTimeseriesSeries]


class CostServiceTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostServiceTimeseriesSeries(BaseModel):
    service: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostServiceTimeseriesPoint] = Field(default_factory=list)


class CostServiceTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    service_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostServiceTimeseriesSeries]


class CostTenantTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostTenantTimeseriesSeries(BaseModel):
    tenant: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostTenantTimeseriesPoint] = Field(default_factory=list)


class CostTenantTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    tenant_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostTenantTimeseriesSeries]


class CostChannelTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostChannelTimeseriesSeries(BaseModel):
    channel: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostChannelTimeseriesPoint] = Field(default_factory=list)


class CostChannelTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    channel_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostChannelTimeseriesSeries]


class CostCampaignTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostCampaignTimeseriesSeries(BaseModel):
    campaign: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostCampaignTimeseriesPoint] = Field(default_factory=list)


class CostCampaignTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    campaign_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostCampaignTimeseriesSeries]


class CostBrandTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostBrandTimeseriesSeries(BaseModel):
    brand: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostBrandTimeseriesPoint] = Field(default_factory=list)


class CostBrandTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    brand_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostBrandTimeseriesSeries]


class CostMarketTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostMarketTimeseriesSeries(BaseModel):
    market: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostMarketTimeseriesPoint] = Field(default_factory=list)


class CostMarketTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    market_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostMarketTimeseriesSeries]


class CostSegmentTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostSegmentTimeseriesSeries(BaseModel):
    segment: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostSegmentTimeseriesPoint] = Field(default_factory=list)


class CostSegmentTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    segment_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostSegmentTimeseriesSeries]


class CostAccountTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostAccountTimeseriesSeries(BaseModel):
    account: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostAccountTimeseriesPoint] = Field(default_factory=list)


class CostAccountTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    account_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostAccountTimeseriesSeries]


class CostOrgTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostOrgTimeseriesSeries(BaseModel):
    org: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostOrgTimeseriesPoint] = Field(default_factory=list)


class CostOrgTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    org_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostOrgTimeseriesSeries]


class CostCostCenterTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostCostCenterTimeseriesSeries(BaseModel):
    cost_center: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostCostCenterTimeseriesPoint] = Field(default_factory=list)


class CostCostCenterTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    cost_center_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostCostCenterTimeseriesSeries]


class CostBusinessUnitTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostBusinessUnitTimeseriesSeries(BaseModel):
    business_unit: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostBusinessUnitTimeseriesPoint] = Field(default_factory=list)


class CostBusinessUnitTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    business_unit_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostBusinessUnitTimeseriesSeries]


class CostSiteTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostSiteTimeseriesSeries(BaseModel):
    site: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostSiteTimeseriesPoint] = Field(default_factory=list)


class CostSiteTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    site_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostSiteTimeseriesSeries]


class CostSkuTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostSkuTimeseriesSeries(BaseModel):
    sku: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostSkuTimeseriesPoint] = Field(default_factory=list)


class CostSkuTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    sku_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostSkuTimeseriesSeries]


class CostLineTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostLineTimeseriesSeries(BaseModel):
    line: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostLineTimeseriesPoint] = Field(default_factory=list)


class CostLineTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    line_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostLineTimeseriesSeries]


class CostTierTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostTierTimeseriesSeries(BaseModel):
    tier: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostTierTimeseriesPoint] = Field(default_factory=list)


class CostTierTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    tier_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostTierTimeseriesSeries]


class CostStageTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostStageTimeseriesSeries(BaseModel):
    stage: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostStageTimeseriesPoint] = Field(default_factory=list)


class CostStageTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    stage_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostStageTimeseriesSeries]


class CostPlatformTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostPlatformTimeseriesSeries(BaseModel):
    platform: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostPlatformTimeseriesPoint] = Field(default_factory=list)


class CostPlatformTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    platform_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostPlatformTimeseriesSeries]


class CostDeviceTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostDeviceTimeseriesSeries(BaseModel):
    device: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostDeviceTimeseriesPoint] = Field(default_factory=list)


class CostDeviceTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    device_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostDeviceTimeseriesSeries]


class CostClientTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostClientTimeseriesSeries(BaseModel):
    client: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostClientTimeseriesPoint] = Field(default_factory=list)


class CostClientTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    client_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostClientTimeseriesSeries]


class CostBrowserTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostBrowserTimeseriesSeries(BaseModel):
    browser: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostBrowserTimeseriesPoint] = Field(default_factory=list)


class CostBrowserTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    browser_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostBrowserTimeseriesSeries]



class CostReleaseTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostReleaseTimeseriesSeries(BaseModel):
    release: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostReleaseTimeseriesPoint] = Field(default_factory=list)


class CostReleaseTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    release_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostReleaseTimeseriesSeries]



class CostLocaleTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostLocaleTimeseriesSeries(BaseModel):
    locale: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostLocaleTimeseriesPoint] = Field(default_factory=list)


class CostLocaleTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    locale_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostLocaleTimeseriesSeries]



class CostCountryTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostCountryTimeseriesSeries(BaseModel):
    country: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostCountryTimeseriesPoint] = Field(default_factory=list)


class CostCountryTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    country_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostCountryTimeseriesSeries]



class CostOsTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostOsTimeseriesSeries(BaseModel):
    os: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostOsTimeseriesPoint] = Field(default_factory=list)


class CostOsTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    os_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostOsTimeseriesSeries]



class CostTimezoneTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostTimezoneTimeseriesSeries(BaseModel):
    timezone: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostTimezoneTimeseriesPoint] = Field(default_factory=list)


class CostTimezoneTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    timezone_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostTimezoneTimeseriesSeries]



class CostLanguageTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostLanguageTimeseriesSeries(BaseModel):
    language: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostLanguageTimeseriesPoint] = Field(default_factory=list)


class CostLanguageTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    language_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostLanguageTimeseriesSeries]



class CostCityTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostCityTimeseriesSeries(BaseModel):
    city: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostCityTimeseriesPoint] = Field(default_factory=list)


class CostCityTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    city_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostCityTimeseriesSeries]



class CostContinentTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostContinentTimeseriesSeries(BaseModel):
    continent: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostContinentTimeseriesPoint] = Field(default_factory=list)


class CostContinentTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    continent_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostContinentTimeseriesSeries]



class CostIspTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostIspTimeseriesSeries(BaseModel):
    isp: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostIspTimeseriesPoint] = Field(default_factory=list)


class CostIspTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    isp_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostIspTimeseriesSeries]


class CostAsnTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostAsnTimeseriesSeries(BaseModel):
    asn: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostAsnTimeseriesPoint] = Field(default_factory=list)


class CostAsnTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    asn_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostAsnTimeseriesSeries]



class CostSdkTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostSdkTimeseriesSeries(BaseModel):
    sdk: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostSdkTimeseriesPoint] = Field(default_factory=list)


class CostSdkTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    sdk_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostSdkTimeseriesSeries]


class CostFrameworkTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostFrameworkTimeseriesSeries(BaseModel):
    framework: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostFrameworkTimeseriesPoint] = Field(default_factory=list)


class CostFrameworkTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    framework_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostFrameworkTimeseriesSeries]



class CostRuntimeTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostRuntimeTimeseriesSeries(BaseModel):
    runtime: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostRuntimeTimeseriesPoint] = Field(default_factory=list)


class CostRuntimeTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    runtime_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostRuntimeTimeseriesSeries]


class CostLibraryTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostLibraryTimeseriesSeries(BaseModel):
    library: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostLibraryTimeseriesPoint] = Field(default_factory=list)


class CostLibraryTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    library_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostLibraryTimeseriesSeries]



class CostHostTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostHostTimeseriesSeries(BaseModel):
    host: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostHostTimeseriesPoint] = Field(default_factory=list)


class CostHostTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    host_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostHostTimeseriesSeries]


class CostDatacenterTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostDatacenterTimeseriesSeries(BaseModel):
    datacenter: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostDatacenterTimeseriesPoint] = Field(default_factory=list)


class CostDatacenterTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    datacenter_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostDatacenterTimeseriesSeries]



class CostAzTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostAzTimeseriesSeries(BaseModel):
    az: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostAzTimeseriesPoint] = Field(default_factory=list)


class CostAzTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    az_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostAzTimeseriesSeries]


class CostEdgeTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostEdgeTimeseriesSeries(BaseModel):
    edge: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostEdgeTimeseriesPoint] = Field(default_factory=list)


class CostEdgeTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    edge_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostEdgeTimeseriesSeries]



class CostColoTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostColoTimeseriesSeries(BaseModel):
    colo: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostColoTimeseriesPoint] = Field(default_factory=list)


class CostColoTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    colo_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostColoTimeseriesSeries]




class CostClusterTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostClusterTimeseriesSeries(BaseModel):
    cluster: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostClusterTimeseriesPoint] = Field(default_factory=list)


class CostClusterTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    cluster_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostClusterTimeseriesSeries]


class CostPodTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostPodTimeseriesSeries(BaseModel):
    pod: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostPodTimeseriesPoint] = Field(default_factory=list)


class CostPodTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    pod_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostPodTimeseriesSeries]



class CostNamespaceTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostNamespaceTimeseriesSeries(BaseModel):
    namespace: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostNamespaceTimeseriesPoint] = Field(default_factory=list)


class CostNamespaceTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    namespace_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostNamespaceTimeseriesSeries]


class CostNodeTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostNodeTimeseriesSeries(BaseModel):
    node: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostNodeTimeseriesPoint] = Field(default_factory=list)


class CostNodeTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    node_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostNodeTimeseriesSeries]



class CostToolTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostToolTimeseriesSeries(BaseModel):
    tool: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostToolTimeseriesPoint] = Field(default_factory=list)


class CostToolTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    tool_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostToolTimeseriesSeries]


class CostWorkflowTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostWorkflowTimeseriesSeries(BaseModel):
    workflow: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostWorkflowTimeseriesPoint] = Field(default_factory=list)


class CostWorkflowTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    workflow_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostWorkflowTimeseriesSeries]


class CostExperimentTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostExperimentTimeseriesSeries(BaseModel):
    experiment: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostExperimentTimeseriesPoint] = Field(default_factory=list)


class CostExperimentTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    experiment_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostExperimentTimeseriesSeries]


class CostVariantTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostVariantTimeseriesSeries(BaseModel):
    variant: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostVariantTimeseriesPoint] = Field(default_factory=list)


class CostVariantTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    variant_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostVariantTimeseriesSeries]


class CostDeploymentTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostDeploymentTimeseriesSeries(BaseModel):
    deployment: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostDeploymentTimeseriesPoint] = Field(default_factory=list)


class CostDeploymentTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    deployment_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostDeploymentTimeseriesSeries]


class CostVersionTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostVersionTimeseriesSeries(BaseModel):
    version: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostVersionTimeseriesPoint] = Field(default_factory=list)


class CostVersionTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    version_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostVersionTimeseriesSeries]


class CostCanaryTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostCanaryTimeseriesSeries(BaseModel):
    canary: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostCanaryTimeseriesPoint] = Field(default_factory=list)


class CostCanaryTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    canary_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostCanaryTimeseriesSeries]


class CostShadowTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostShadowTimeseriesSeries(BaseModel):
    shadow: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostShadowTimeseriesPoint] = Field(default_factory=list)


class CostShadowTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    shadow_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostShadowTimeseriesSeries]


class CostRolloutTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostRolloutTimeseriesSeries(BaseModel):
    rollout: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostRolloutTimeseriesPoint] = Field(default_factory=list)


class CostRolloutTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    rollout_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostRolloutTimeseriesSeries]


class CostRouteTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostRouteTimeseriesSeries(BaseModel):
    route: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostRouteTimeseriesPoint] = Field(default_factory=list)


class CostRouteTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    route_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostRouteTimeseriesSeries]


class CostBatchTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostBatchTimeseriesSeries(BaseModel):
    batch: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostBatchTimeseriesPoint] = Field(default_factory=list)


class CostBatchTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    batch_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostBatchTimeseriesSeries]


class CostJobTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostJobTimeseriesSeries(BaseModel):
    job: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostJobTimeseriesPoint] = Field(default_factory=list)


class CostJobTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    job_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostJobTimeseriesSeries]



class CostQueueTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostQueueTimeseriesSeries(BaseModel):
    queue: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostQueueTimeseriesPoint] = Field(default_factory=list)


class CostQueueTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    queue_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostQueueTimeseriesSeries]


class CostTopicTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostTopicTimeseriesSeries(BaseModel):
    topic: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostTopicTimeseriesPoint] = Field(default_factory=list)


class CostTopicTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    topic_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostTopicTimeseriesSeries]


class CostPipelineTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostPipelineTimeseriesSeries(BaseModel):
    pipeline: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostPipelineTimeseriesPoint] = Field(default_factory=list)


class CostPipelineTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    pipeline_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostPipelineTimeseriesSeries]


class CostRunTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostRunTimeseriesSeries(BaseModel):
    run: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostRunTimeseriesPoint] = Field(default_factory=list)


class CostRunTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    run_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostRunTimeseriesSeries]


class CostWorkerTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostWorkerTimeseriesSeries(BaseModel):
    worker: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostWorkerTimeseriesPoint] = Field(default_factory=list)


class CostWorkerTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    worker_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostWorkerTimeseriesSeries]


class CostSlotTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostSlotTimeseriesSeries(BaseModel):
    slot: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostSlotTimeseriesPoint] = Field(default_factory=list)


class CostSlotTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    slot_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostSlotTimeseriesSeries]


class CostTaskTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostTaskTimeseriesSeries(BaseModel):
    task: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostTaskTimeseriesPoint] = Field(default_factory=list)


class CostTaskTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    task_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostTaskTimeseriesSeries]


class CostStepTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostStepTimeseriesSeries(BaseModel):
    step: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostStepTimeseriesPoint] = Field(default_factory=list)


class CostStepTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    step_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostStepTimeseriesSeries]


class CostReplicaTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostReplicaTimeseriesSeries(BaseModel):
    replica: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostReplicaTimeseriesPoint] = Field(default_factory=list)


class CostReplicaTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    replica_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostReplicaTimeseriesSeries]


class CostShardTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostShardTimeseriesSeries(BaseModel):
    shard: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostShardTimeseriesPoint] = Field(default_factory=list)


class CostShardTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    shard_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostShardTimeseriesSeries]


class CostPartitionTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostPartitionTimeseriesSeries(BaseModel):
    partition: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostPartitionTimeseriesPoint] = Field(default_factory=list)


class CostPartitionTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    partition_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostPartitionTimeseriesSeries]


class CostConsumerTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostConsumerTimeseriesSeries(BaseModel):
    consumer: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostConsumerTimeseriesPoint] = Field(default_factory=list)


class CostConsumerTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    consumer_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostConsumerTimeseriesSeries]


class CostProducerTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostProducerTimeseriesSeries(BaseModel):
    producer: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostProducerTimeseriesPoint] = Field(default_factory=list)


class CostProducerTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    producer_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostProducerTimeseriesSeries]


class CostGpuTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostGpuTimeseriesSeries(BaseModel):
    gpu: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostGpuTimeseriesPoint] = Field(default_factory=list)


class CostGpuTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    gpu_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostGpuTimeseriesSeries]


class CostAcceleratorTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostAcceleratorTimeseriesSeries(BaseModel):
    accelerator: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostAcceleratorTimeseriesPoint] = Field(default_factory=list)


class CostAcceleratorTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    accelerator_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostAcceleratorTimeseriesSeries]


class CostCellTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostCellTimeseriesSeries(BaseModel):
    cell: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostCellTimeseriesPoint] = Field(default_factory=list)


class CostCellTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    cell_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostCellTimeseriesSeries]


class CostZoneTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostZoneTimeseriesSeries(BaseModel):
    zone: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostZoneTimeseriesPoint] = Field(default_factory=list)


class CostZoneTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    zone_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostZoneTimeseriesSeries]


class CostRackTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostRackTimeseriesSeries(BaseModel):
    rack: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostRackTimeseriesPoint] = Field(default_factory=list)


class CostRackTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    rack_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostRackTimeseriesSeries]


class CostPoolTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostPoolTimeseriesSeries(BaseModel):
    pool: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostPoolTimeseriesPoint] = Field(default_factory=list)


class CostPoolTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    pool_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostPoolTimeseriesSeries]


class CostFleetTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostFleetTimeseriesSeries(BaseModel):
    fleet: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostFleetTimeseriesPoint] = Field(default_factory=list)


class CostFleetTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    fleet_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostFleetTimeseriesSeries]


class CostLeaseTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostLeaseTimeseriesSeries(BaseModel):
    lease: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostLeaseTimeseriesPoint] = Field(default_factory=list)


class CostLeaseTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    lease_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostLeaseTimeseriesSeries]


class CostQuotaTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostQuotaTimeseriesSeries(BaseModel):
    quota: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostQuotaTimeseriesPoint] = Field(default_factory=list)


class CostQuotaTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    quota_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostQuotaTimeseriesSeries]


class CostCapacityTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostCapacityTimeseriesSeries(BaseModel):
    capacity: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostCapacityTimeseriesPoint] = Field(default_factory=list)


class CostCapacityTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    capacity_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostCapacityTimeseriesSeries]


class CostReservationTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    total_tokens: int = 0


class CostReservationTimeseriesSeries(BaseModel):
    reservation: str
    spend_cents: int
    event_count: int
    total_tokens: int = 0
    points: list[CostReservationTimeseriesPoint] = Field(default_factory=list)


class CostReservationTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    reservation_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostReservationTimeseriesSeries]

class CostUserSummaryItem(BaseModel):
    user_id: str
    spend_cents: int
    event_count: int
    session_count: int
    last_seen_at: datetime


class CostUserListResponse(BaseModel):
    window_hours: int
    total_spend_cents: int
    total_event_count: int
    count: int
    items: list[CostUserSummaryItem]


class CostUserTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int
    session_count: int = 0


class CostUserTimeseriesSeries(BaseModel):
    user_id: str
    spend_cents: int
    event_count: int
    session_count: int = 0
    points: list[CostUserTimeseriesPoint] = Field(default_factory=list)


class CostUserTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    user_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostUserTimeseriesSeries]


class CostModelStatsItem(BaseModel):
    model_config = {"protected_namespaces": ()}

    model_name: str
    spend_cents: int
    event_count: int
    total_tokens: int
    last_seen_at: datetime


class CostModelStatsResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    window_hours: int
    total_spend_cents: int
    total_event_count: int
    count: int
    items: list[CostModelStatsItem]


class CostModelTimeseriesPoint(BaseModel):
    model_config = {"protected_namespaces": ()}

    hour_start: datetime
    spend_cents: int
    event_count: int
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0


class CostModelTimeseriesSeries(BaseModel):
    model_config = {"protected_namespaces": ()}

    model_name: str
    spend_cents: int
    event_count: int
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    points: list[CostModelTimeseriesPoint] = Field(default_factory=list)


class CostModelTimeseriesResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    window_hours: int
    start_time: datetime
    end_time: datetime
    model_filter: Optional[str] = None
    total_spend_cents: int
    total_tokens: int
    total_event_count: int
    count: int
    series: list[CostModelTimeseriesSeries]


class CostRequestItem(BaseModel):
    model_config = {"protected_namespaces": ()}

    request_id: str
    trace_id: Optional[str] = None
    session_id: Optional[str] = None
    model_name: str
    request_tag: Optional[str] = None
    estimated_cost_cents: int
    input_tokens: int = 0
    output_tokens: int = 0
    cache_hit: bool = False
    user_id: Optional[str] = None
    session_path: Optional[str] = None
    property_value: Optional[str] = None
    rating: Optional[int] = None
    timestamp: datetime


class CostRequestListResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    window_hours: int
    count: int
    total_spend_cents: int
    property_key: Optional[str] = None
    items: list[CostRequestItem]


class CostSessionTreeNode(BaseModel):
    path: str
    spend_cents: int
    event_count: int
    session_count: int
    children: list["CostSessionTreeNode"] = Field(default_factory=list)


class CostSessionTreeResponse(BaseModel):
    window_hours: int
    max_depth: int
    total_spend_cents: int
    total_event_count: int
    count: int
    items: list[CostSessionTreeNode]


class CostScoreStatsItem(BaseModel):
    key: str
    count: int
    avg: float
    min: float
    max: float
    spend_cents: int


class CostScoreStatsResponse(BaseModel):
    window_hours: int
    total_scored_events: int
    count: int
    items: list[CostScoreStatsItem]


class CostScoreTimeseriesPoint(BaseModel):
    hour_start: datetime
    avg: float
    count: int
    spend_cents: int


class CostScoreTimeseriesSeries(BaseModel):
    key: str
    count: int
    avg: float
    min: float
    max: float
    spend_cents: int
    points: list[CostScoreTimeseriesPoint] = Field(default_factory=list)


class CostScoreTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    score_key_filter: Optional[str] = None
    total_scored_events: int
    count: int
    series: list[CostScoreTimeseriesSeries]


class CostRatingTimeseriesPoint(BaseModel):
    hour_start: datetime
    avg: float
    count: int
    spend_cents: int


class CostRatingTimeseriesSeries(BaseModel):
    rating_label: str
    count: int
    avg: float
    spend_cents: int
    points: list[CostRatingTimeseriesPoint] = Field(default_factory=list)


class CostRatingTimeseriesResponse(BaseModel):
    window_hours: int
    start_time: datetime
    end_time: datetime
    rating_filter: Optional[str] = None
    total_rated_events: int
    count: int
    series: list[CostRatingTimeseriesSeries]


class CostLatencyTimeseriesPoint(BaseModel):
    model_config = {"protected_namespaces": ()}

    hour_start: datetime
    avg_ms: float
    p95_ms: float
    count: int
    spend_cents: int


class CostLatencyTimeseriesSeries(BaseModel):
    model_config = {"protected_namespaces": ()}

    model_name: str
    avg_ms: float
    p95_ms: float
    count: int
    spend_cents: int
    points: list[CostLatencyTimeseriesPoint] = Field(default_factory=list)


class CostLatencyTimeseriesResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    window_hours: int
    start_time: datetime
    end_time: datetime
    model_filter: Optional[str] = None
    total_events: int
    avg_ms: float
    p95_ms: float
    count: int
    series: list[CostLatencyTimeseriesSeries]


class CostCacheTimeseriesPoint(BaseModel):
    model_config = {"protected_namespaces": ()}

    hour_start: datetime
    hit_count: int
    miss_count: int
    hit_rate: float
    spend_cents: int


class CostCacheTimeseriesSeries(BaseModel):
    model_config = {"protected_namespaces": ()}

    model_name: str
    hit_count: int
    miss_count: int
    hit_rate: float
    spend_cents: int
    points: list[CostCacheTimeseriesPoint] = Field(default_factory=list)


class CostCacheTimeseriesResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    window_hours: int
    start_time: datetime
    end_time: datetime
    model_filter: Optional[str] = None
    total_events: int
    hit_count: int
    miss_count: int
    hit_rate: float
    count: int
    series: list[CostCacheTimeseriesSeries]


class CostPropertyStatsItem(BaseModel):
    value: str
    event_count: int
    spend_cents: int


class CostPropertyStatsResponse(BaseModel):
    window_hours: int
    property_key: str
    total_events_with_key: int
    count: int
    items: list[CostPropertyStatsItem]


class CostPropertyTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int


class CostPropertyTimeseriesSeries(BaseModel):
    value: str
    spend_cents: int
    event_count: int
    points: list[CostPropertyTimeseriesPoint] = Field(default_factory=list)


class CostPropertyTimeseriesResponse(BaseModel):
    property_key: str
    window_hours: int
    start_time: datetime
    end_time: datetime
    value_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    count: int
    series: list[CostPropertyTimeseriesSeries]


class CostLiveResponse(BaseModel):
    spend_last_hour_cents: int
    spend_last_day_cents: int
    burn_rate_cents_per_hour: int
    event_count_last_day: int
    recent_sessions: list[str] = Field(default_factory=list)
    recent_agents: list[str] = Field(default_factory=list)


class CostBreakdownItem(BaseModel):
    label: str
    spend_cents: int
    event_count: int


class CostBreakdownResponse(BaseModel):
    dimension: str
    window_hours: int
    total_spend_cents: int
    total_event_count: int
    items: list[CostBreakdownItem]


class CostTimeseriesPoint(BaseModel):
    hour_start: datetime
    spend_cents: int
    event_count: int


class CostTimeseriesResponse(BaseModel):
    dimension: str
    window_hours: int
    start_time: datetime
    end_time: datetime
    scope_filter: Optional[str] = None
    total_spend_cents: int
    total_event_count: int
    points: list[CostTimeseriesPoint]


class CostPeriodSpendSnapshot(BaseModel):
    label: str
    start: datetime
    end: datetime
    spend_cents: int
    event_count: int


class CostComparisonResponse(BaseModel):
    comparison_period: str
    comparison_mode: str
    dimension: str
    scope_filter: Optional[str] = None
    current: CostPeriodSpendSnapshot
    previous: CostPeriodSpendSnapshot
    delta_cents: int
    delta_percent: float
    trend: str


class CostTrackSpendRequest(BaseModel):
    model_config = {"protected_namespaces": ()}

    request_id: str = Field(min_length=1, max_length=128)
    trace_id: Optional[str] = Field(default=None, max_length=128)
    request_tag: Optional[str] = Field(default=None, max_length=64)
    session_id: str = Field(min_length=1, max_length=128)
    agent_id: str = Field(min_length=1, max_length=64)
    scope_type: str
    scope_id: str
    environment: str = "dev"
    model_name: str = Field(min_length=1, max_length=255)
    endpoint_family: str = Field(min_length=1, max_length=128)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    estimated_cost_cents: int = Field(default=0, ge=0)
    currency: str = Field(default="USD", min_length=1, max_length=8)
    cache_hit: bool = False
    user_properties: Optional[dict[str, object]] = None


class CostEventFeedbackRequest(BaseModel):
    """Helicone-style request feedback attached to cost events by request_id."""

    request_id: str = Field(min_length=1, max_length=128)
    trace_id: Optional[str] = Field(default=None, max_length=128)
    rating: Optional[int] = Field(default=None, ge=1, le=5)
    scores: Optional[dict[str, float]] = None
    comment: Optional[str] = Field(default=None, max_length=2048)


class CostEventFeedbackResponse(BaseModel):
    request_id: str
    trace_id: Optional[str] = None
    updated_events: int
    rating: Optional[int] = None
    scores: Optional[dict[str, float]] = None
    comment: Optional[str] = None


class CostEventFeedbackItem(BaseModel):
    cost_event_id: str
    request_id: str
    trace_id: Optional[str] = None
    rating: Optional[int] = None
    scores: Optional[dict[str, float]] = None
    comment: Optional[str] = None
    has_feedback: bool = False


class CostEventFeedbackLookupResponse(BaseModel):
    request_id: str
    trace_id: Optional[str] = None
    count: int
    has_feedback: bool = False
    rating: Optional[int] = None
    scores: Optional[dict[str, float]] = None
    comment: Optional[str] = None
    events: list[CostEventFeedbackItem] = []


class CostPricingCatalogResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    default_model_rates: dict[str, float]
    model_rates: dict[str, dict[str, float]]
    provider_multipliers: dict[str, float]
    endpoint_multipliers: dict[str, float]
    provider_discounts: dict[str, float]
    model_discounts: dict[str, float]


class CostPricingCalculateRequest(BaseModel):
    model_config = {"protected_namespaces": ()}

    provider_type: str = Field(min_length=1, max_length=64)
    model_name: str = Field(min_length=1, max_length=255)
    endpoint_family: str = Field(default="responses", min_length=1, max_length=128)
    input_tokens: int = Field(default=0, ge=0)
    output_tokens: int = Field(default=0, ge=0)
    custom_input_cents_per_1k: Optional[float] = Field(default=None, ge=0)
    custom_output_cents_per_1k: Optional[float] = Field(default=None, ge=0)
    custom_provider_discount_percent: Optional[float] = Field(default=None, ge=0, le=95)


class CostPricingCalculateResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    provider_type: str
    model_name: str
    endpoint_family: str
    input_tokens: int
    output_tokens: int
    input_cents_per_1k: float
    output_cents_per_1k: float
    provider_multiplier: float
    endpoint_multiplier: float
    provider_discount_percent: float
    model_discount_percent: float
    custom_discount_percent: float
    applied_discount_percent: float
    base_cost_cents: int
    estimated_cost_cents: int


class BudgetPolicyCreateRequest(BaseModel):
    scope_type: str
    scope_id: str
    budget_amount_cents: int = Field(ge=0)
    window_type: str = "daily"
    soft_limit_percent: int = Field(default=80, ge=1, le=100)
    hard_limit_percent: int = Field(default=100, ge=1, le=100)
    action_on_soft_limit: str = "warn"
    action_on_hard_limit: str = "block"
    reset_timezone: str = "UTC"
    reset_hour_local: int = Field(default=0, ge=0, le=23)
    temporary_increase_cents: int = Field(default=0, ge=0)
    temporary_increase_expires_at: Optional[datetime] = None
    soft_alert_enabled: bool = True
    rate_limit_tpm: Optional[int] = Field(default=None, ge=1)
    rate_limit_rpm: Optional[int] = Field(default=None, ge=1)
    session_iteration_cap: Optional[int] = Field(default=None, ge=1)
    session_budget_cents: Optional[int] = Field(default=None, ge=1)


class BudgetPolicyResponse(ORMBase):
    budget_policy_id: str
    scope_type: str
    scope_id: str
    budget_amount_cents: int
    window_type: str
    soft_limit_percent: int
    hard_limit_percent: int
    action_on_soft_limit: str
    action_on_hard_limit: str
    reset_timezone: str
    reset_hour_local: int
    temporary_increase_cents: int
    temporary_increase_expires_at: Optional[datetime] = None
    soft_alert_enabled: bool
    last_soft_alert_at: Optional[datetime] = None
    rate_limit_tpm: Optional[int] = None
    rate_limit_rpm: Optional[int] = None
    session_iteration_cap: Optional[int] = None
    session_budget_cents: Optional[int] = None
    status: str
    effective_budget_cents: int = 0
    current_spend_cents: int = 0
    hours_spend_cents: int = 0
    utilization_percent: float = 0.0
    decision: Optional[str] = None
    recommended_action: Optional[str] = None
    soft_alert_active: bool = False
    temporary_increase_active: bool = False


class BudgetPolicyTemporaryIncreaseRequest(BaseModel):
    increase_cents: int = Field(ge=1)
    duration_minutes: int = Field(default=60, ge=1, le=60 * 24 * 30)
    reason: Optional[str] = Field(default=None, max_length=512)


class BudgetPolicySoftAlertAcknowledgeRequest(BaseModel):
    reason: Optional[str] = Field(default=None, max_length=512)


class CostPolicyEvaluateRequest(BaseModel):
    scope_type: str
    scope_id: str
    window_type: str = "daily"
    environment: Optional[str] = None


class CostPolicyEvaluateResponse(BaseModel):
    scope_type: str
    scope_id: str
    window_type: str = "daily"
    environment: Optional[str] = None
    budget_policy_id: Optional[str] = None
    resolved_budget_scope_type: Optional[str] = None
    spend_cents: int
    hours_spend_cents: int = 0
    budget_cents: int
    effective_budget_cents: int
    utilization_percent: float
    projected_window_spend_cents: int
    projected_utilization_percent: float
    historical_window_spend_cents: int = 0
    projection_basis: str = "blended"
    prior_periods_considered: int = 0
    projected_24h_spend_cents: int
    decision: str
    recommended_action: str
    preemptive_throttle: bool
    soft_limit_alert: bool = False


class CostAnomalyResponse(BaseModel):
    anomaly_id: str
    anomaly_type: str
    severity: str
    scope_type: str
    scope_id: str
    observed_cost_cents: int
    threshold_cents: int
    detected_at: datetime
    budget_policy_id: Optional[str] = None
    effective_budget_cents: Optional[int] = None
    utilization_percent: Optional[float] = None
    recommended_action: Optional[str] = None
    window_type: Optional[str] = None
    soft_limit_percent: Optional[float] = None
    hard_limit_percent: Optional[float] = None
    hours_spend_cents: Optional[int] = None
    decision: Optional[str] = None


class CostLimitScopeDecision(BaseModel):
    scope_type: str
    scope_id: str
    policy_id: Optional[str] = None
    spend_cents: int
    hours_spend_cents: int = 0
    budget_cents: int
    effective_budget_cents: int
    utilization_percent: float
    decision: str
    recommended_action: str
    soft_limit_alert: bool = False
    projected_window_spend_cents: int = 0
    historical_window_spend_cents: int = 0
    projection_basis: str = "blended"


class CostLimitEvaluateRequest(BaseModel):
    actor_id: Optional[str] = None
    team_ids: list[str] = Field(default_factory=list)
    group_ids: list[str] = Field(default_factory=list)
    agent_ids: list[str] = Field(default_factory=list)
    window_type: str = "daily"
    projected_additional_cost_cents: int = 0
    environment: Optional[str] = None


class CostLimitEvaluateResponse(BaseModel):
    actor_id: str
    window_type: str
    environment: Optional[str] = None
    scopes_evaluated: list[CostLimitScopeDecision]
    aggregated_decision: str
    blocking_scopes: list[str]
    soft_alert_scopes: list[str] = Field(default_factory=list)


class CostHierarchyMemberContribution(BaseModel):
    user_id: str
    spend_cents: int = 0
    share_percent: float = 0.0


class CostHierarchyScopeItem(BaseModel):
    scope_type: str
    scope_id: str
    member_count: int = 0
    spend_cents: int = 0
    tagged_spend_cents: int = 0
    member_spend_cents: int = 0
    budget_policy_id: Optional[str] = None
    budget_cents: Optional[int] = None
    effective_budget_cents: Optional[int] = None
    utilization_percent: Optional[float] = None
    decision: Optional[str] = None
    recommended_action: Optional[str] = None
    window_type: Optional[str] = None
    budget_window_spend_cents: Optional[int] = None
    hours_spend_cents: Optional[int] = None
    temporary_increase_cents: int = 0
    temporary_increase_active: bool = False
    resolved_budget_scope_type: Optional[str] = None
    session_budget_cents: Optional[int] = None
    session_iteration_cap: Optional[int] = None
    rate_limit_rpm: Optional[int] = None
    rate_limit_tpm: Optional[int] = None
    soft_alert_enabled: Optional[bool] = None
    top_members: list[CostHierarchyMemberContribution] = Field(default_factory=list)


class CostHierarchyUserBudget(BaseModel):
    budget_policy_id: Optional[str] = None
    budget_cents: Optional[int] = None
    effective_budget_cents: Optional[int] = None
    utilization_percent: Optional[float] = None
    decision: Optional[str] = None
    recommended_action: Optional[str] = None
    window_type: Optional[str] = None
    budget_window_spend_cents: Optional[int] = None
    hours_spend_cents: Optional[int] = None
    temporary_increase_cents: int = 0
    temporary_increase_active: bool = False
    resolved_budget_scope_type: Optional[str] = None
    session_budget_cents: Optional[int] = None
    session_iteration_cap: Optional[int] = None
    soft_alert_enabled: Optional[bool] = None


class CostHierarchyResponse(BaseModel):
    actor_id: str
    window_hours: int
    window_mode: str = "hours"
    environment: Optional[str] = None
    user_spend_cents: int
    user_hours_spend_cents: Optional[int] = None
    user_budget: Optional[CostHierarchyUserBudget] = None
    teams: list[CostHierarchyScopeItem] = Field(default_factory=list)
    groups: list[CostHierarchyScopeItem] = Field(default_factory=list)
    soft_alert_scopes: list[str] = Field(default_factory=list)
    blocking_scopes: list[str] = Field(default_factory=list)


class CostHierarchyAlertItem(BaseModel):
    scope_type: str
    scope_id: str
    decision: str
    severity: Optional[str] = None
    spend_cents: int = 0
    hours_spend_cents: Optional[int] = None
    utilization_percent: Optional[float] = None
    effective_budget_cents: Optional[int] = None
    budget_policy_id: Optional[str] = None
    recommended_action: Optional[str] = None
    window_type: Optional[str] = None


class CostHierarchyAlertsResponse(BaseModel):
    actor_id: str
    window_hours: int
    window_mode: str = "hours"
    environment: Optional[str] = None
    soft_alert_count: int = 0
    blocking_count: int = 0
    soft_alert_scopes: list[str] = Field(default_factory=list)
    blocking_scopes: list[str] = Field(default_factory=list)
    alerts: list[CostHierarchyAlertItem] = Field(default_factory=list)


class CostHierarchyExplainResponse(BaseModel):
    scope_type: str
    scope_id: str
    window_hours: int
    window_mode: str = "hours"
    environment: Optional[str] = None
    member_count: int = 0
    spend_cents: int = 0
    hours_spend_cents: Optional[int] = None
    tagged_spend_cents: int = 0
    member_spend_cents: int = 0
    top_members: list[CostHierarchyMemberContribution] = Field(default_factory=list)
    budget_policy_id: Optional[str] = None
    budget_cents: Optional[int] = None
    effective_budget_cents: Optional[int] = None
    utilization_percent: Optional[float] = None
    decision: Optional[str] = None
    recommended_action: Optional[str] = None
    soft_limit_percent: Optional[float] = None
    hard_limit_percent: Optional[float] = None
    window_type: Optional[str] = None
    temporary_increase_cents: int = 0
    temporary_increase_active: bool = False
    resolved_budget_scope_type: Optional[str] = None
    projected_window_spend_cents: int = 0
    historical_window_spend_cents: int = 0
    projection_basis: Optional[str] = None
    session_budget_cents: Optional[int] = None
    session_iteration_cap: Optional[int] = None
    rate_limit_rpm: Optional[int] = None
    rate_limit_tpm: Optional[int] = None
    reasons: list[str] = Field(default_factory=list)
    owner_scopes_counted: list[str] = Field(default_factory=list)


class RouteDraftSubmitRequest(BaseModel):
    agent_id: str
    route_policy_snapshot_id: str = "snapshot-default"
    environment: str = "dev"


class RouteDraftApproveRequest(BaseModel):
    reason_code: Optional[str] = None
    evidence_refs: list[str] = []
    risk_ticket_ref: Optional[str] = None


class RouteDraftRejectRequest(BaseModel):
    reason_code: str


class RouteDraftPromoteRequest(BaseModel):
    target_environment: str = "prod"
    expected_state_version: int


class RouteDraftChangeWindowApproveRequest(BaseModel):
    reason_code: Optional[str] = None
    change_window_id: Optional[str] = None
    evidence_refs: list[str] = []
    risk_ticket_ref: Optional[str] = None


class RouteDraftRollbackRequest(BaseModel):
    reason_code: str


class RouteDraftRollbackLastGoodRequest(BaseModel):
    reason_code: str
    expected_state_version: int


class RouteDraftResponse(ORMBase):
    draft_id: str
    agent_id: str
    route_policy_snapshot_id: str
    environment: str
    status: str
    approved_security: bool
    approved_ai_ops: bool
    state_version: int


class RouteDraftApprovalEventResponse(ORMBase):
    approval_event_id: str
    draft_id: str
    action: str
    state_from: str
    state_to: str
    actor_id: str
    actor_role: str
    decision: str
    reason_code: Optional[str]
    evidence_refs: Optional[str]
    change_window_id: Optional[str]
    risk_ticket_ref: Optional[str]
    policy_simulation_status: str
    permission_policy_version: str
    occurred_at: datetime
    created_at: datetime


class ObservabilityTraceResponse(BaseModel):
    trace_id: str
    event_count: int
    cost_event_count: int
    first_seen: datetime
    last_seen: datetime


class ObservabilityLogResponse(BaseModel):
    timestamp: datetime
    request_id: str
    actor_id: str
    actor_login: Optional[str] = None
    actor_role: Optional[str] = None
    action_description: Optional[str] = None
    action_type: str
    resource_type: str
    resource_id: str
    trace_id: str
    span_id: str
    session_id: str
    agent_id: str
    owner_scope: str
    environment: str
    policy_version: str
    decision_outcome: Literal["allow", "deny", "warn"]
    user_prompt: Optional[str] = None
    action_context: dict[str, Any] = Field(default_factory=dict)


class ObservabilityLogSchemaStatusResponse(BaseModel):
    generated_at: datetime
    required_fields: list[str]
    sampled_count: int
    valid_count: int
    invalid_count: int
    conformance_percent: float
    missing_field_counts: dict[str, int]


class ObservabilitySiemRuleResponse(BaseModel):
    rule_id: str
    name: str
    description: str = ""
    action_type_pattern: str
    decision_outcomes: list[str]
    severity: str
    sink_route_key: str
    enabled: bool = True


class ObservabilitySiemRulesListResponse(BaseModel):
    rule_count: int
    rules: list[ObservabilitySiemRuleResponse]


class ObservabilitySiemRulesExportResponse(BaseModel):
    exported_at: datetime
    rule_count: int
    siem_callback_count: int
    rules: list[ObservabilitySiemRuleResponse]
    default_rule_ids: list[str] = Field(default_factory=list)
    siem_callbacks: list[dict[str, Any]] = Field(default_factory=list)


class ObservabilitySiemRuleEvaluationItem(BaseModel):
    audit_event_id: str
    action_type: str
    decision_outcome: str
    trace_id: str
    matched_rule_ids: list[str]


class ObservabilitySiemRuleEvaluationResponse(BaseModel):
    evaluated_count: int
    matched_count: int
    matches: list[ObservabilitySiemRuleEvaluationItem]


class ObservabilityBreakdownItem(BaseModel):
    label: str
    count: int


class ObservabilityHourlyVolume(BaseModel):
    hour_utc: str
    count: int


class ObservabilitySummaryResponse(BaseModel):
    generated_at: datetime
    since_hours: int
    total_events: int
    unique_traces: int
    allow_count: int
    deny_count: int
    warn_count: int
    non_allow_rate_percent: float
    outcome_breakdown: list[ObservabilityBreakdownItem]
    action_breakdown: list[ObservabilityBreakdownItem]
    actor_breakdown: list[ObservabilityBreakdownItem] = Field(default_factory=list)
    hourly_volume: list[ObservabilityHourlyVolume]
    schema_conformance_percent: Optional[float] = None
    recent_traces: list["ObservabilityRecentTraceResponse"] = Field(default_factory=list)


class ObservabilityRecentTraceResponse(BaseModel):
    trace_id: str
    event_count: int
    last_seen: datetime
    primary_action: str
    primary_outcome: str


class ObservabilityTraceEventResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    timestamp: datetime
    event_type: Literal["audit", "cost"]
    trace_id: str
    span_id: str
    actor_id: Optional[str] = None
    action_type: Optional[str] = None
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    decision_outcome: Optional[str] = None
    model_name: Optional[str] = None
    estimated_cost_cents: Optional[int] = None
    environment: Optional[str] = None
    cache_hit: Optional[bool] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    user_properties: Optional[dict[str, object]] = None


class ObservabilityTraceEventsResponse(BaseModel):
    trace_id: str
    event_count: int
    events: list[ObservabilityTraceEventResponse]


class ComplianceControlResponse(BaseModel):
    control_id: str
    title: str
    status: str
    evidence_count: int


class ComplianceControlMappingUpsertRequest(BaseModel):
    control_family: str
    requirement_text: str
    applicable_components: str = "[]"
    required_evidence_types: str = "[]"
    automation_status: str = "manual"
    owner_team: str
    review_frequency: str = "quarterly"


class ComplianceControlMappingResponse(ORMBase):
    control_id: str
    control_family: str
    requirement_text: str
    applicable_components: str
    required_evidence_types: str
    automation_status: str
    owner_team: str
    review_frequency: str


class ComplianceControlCoverageItemResponse(BaseModel):
    path: str
    methods: list[str]
    control_ids: list[str]
    covered: bool


class ComplianceControlCoverageSummaryResponse(BaseModel):
    generated_at: datetime
    total_routes: int
    covered_routes: int
    uncovered_routes: int
    unknown_control_ids: list[str]
    uncovered_paths: list[str]
    items: list[ComplianceControlCoverageItemResponse]


class ComplianceEvidenceResponse(BaseModel):
    control_id: str
    generated_at: datetime
    evidence_items: list[str]


class ComplianceEvidenceFreshnessItemResponse(BaseModel):
    control_id: str
    status: str
    freshness_slo_hours: int
    evidence_count: int
    last_evidence_at: Optional[datetime]
    age_hours: Optional[float]


class ComplianceEvidenceFreshnessSummaryResponse(BaseModel):
    generated_at: datetime
    freshness_slo_hours: int
    total_controls: int
    controls_passing: int
    controls_stale: int
    controls_missing: int
    items: list[ComplianceEvidenceFreshnessItemResponse]


class UiCoverageInventoryItemResponse(BaseModel):
    router_module: Optional[str] = None
    method: str
    route: str
    ui_coverage: str
    frontend_available: bool
    notes: str


class UiCoverageInventoryResponse(BaseModel):
    generated_at: datetime
    inventory_source: str
    items: list[UiCoverageInventoryItemResponse]


class UiCoverageReportResponse(BaseModel):
    generated_at: datetime
    inventory_source: str
    total_inventory_endpoints: int
    full_coverage_endpoints: int
    partial_coverage_endpoints: int
    gap_coverage_endpoints: int
    frontend_unavailable_endpoints: int
    undocumented_backend_routes: int
    stale_inventory_entries: int
    gap_items: list[UiCoverageInventoryItemResponse]
    partial_items: list[UiCoverageInventoryItemResponse]
    undocumented_items: list[UiCoverageInventoryItemResponse]
    stale_inventory_items: list[UiCoverageInventoryItemResponse]
    items: list[UiCoverageInventoryItemResponse]


class RetentionPolicyCreateRequest(BaseModel):
    data_class: str
    jurisdiction: str
    retention_days: int = Field(ge=1, le=36500)
    deletion_mode: str = "soft_delete"
    legal_hold_supported: bool = True


class RetentionPolicyUpdateRequest(BaseModel):
    retention_days: Optional[int] = Field(default=None, ge=1, le=36500)
    deletion_mode: Optional[str] = None
    legal_hold_supported: Optional[bool] = None
    status: Optional[str] = None


class RetentionPolicyResponse(ORMBase):
    policy_id: str
    data_class: str
    jurisdiction: str
    retention_days: int
    deletion_mode: str
    legal_hold_supported: bool
    status: str
    updated_by: str
    updated_at: datetime


class LegalHoldCreateRequest(BaseModel):
    data_class: str
    jurisdiction: str
    reason: str
    scope_ref: str


class LegalHoldReleaseRequest(BaseModel):
    reason_code: Optional[str] = None


class LegalHoldResponse(ORMBase):
    hold_id: str
    data_class: str
    jurisdiction: str
    reason: str
    scope_ref: str
    status: str
    placed_by: str
    placed_at: datetime
    released_by: Optional[str]
    released_at: Optional[datetime]


class ComplianceEvidenceGenerateRequest(BaseModel):
    source_type: str = "audit_events"
    source_id: str = "latest"


class ComplianceEvidenceArtifactResponse(ORMBase):
    evidence_id: str
    control_id: str
    generated_at: datetime
    generated_by: str
    source_type: str
    source_id: str
    trace_id: str
    policy_version: str
    artifact_uri: str
    integrity_hash: str


class ComplianceEvidenceBundleResponse(BaseModel):
    control_id: str
    generated_at: datetime
    evidence_items: list[str]
    artifacts: list[ComplianceEvidenceArtifactResponse]
    artifact_count: int
    latest_artifact_at: Optional[datetime] = None
    integrity_status: str
    investigation_context: Optional[dict] = None


class PlaygroundRunCreateRequest(BaseModel):
    prompt_text: str
    candidate_models: str = "[]"
    selected_model: str
    team_ids: list[str] = Field(default_factory=list)
    group_ids: list[str] = Field(default_factory=list)
    projected_additional_cost_cents: Optional[int] = Field(default=None, ge=0)


class PlaygroundRunResponse(ORMBase):
    run_id: str
    actor_id: str
    prompt_text: str
    candidate_models: str
    selected_model: str
    status: str
    estimated_cost_cents: int
    policy_decision: str
    route_policy_snapshot_id: Optional[str]
    created_at: datetime


class PlaygroundCompareRequest(BaseModel):
    prompt_text: str
    candidate_models: list[str]


class PlaygroundCompareResult(BaseModel):
    model_config = {"protected_namespaces": ()}

    model_name: str
    estimated_latency_ms: int
    estimated_cost_cents: int
    quality_score: float
    quality_tier: str = "fair"
    score_reason: str = ""
    response_preview: str = ""
    response_text: str = ""
    rank: int = 1


class PlaygroundCompareResponse(BaseModel):
    results: list[PlaygroundCompareResult]


class PlaygroundRouteDraftResponse(BaseModel):
    run_id: str
    draft_id: str
    status: str


class PromptRegistryCreateRequest(BaseModel):
    name: str
    prompt_text: str
    description: str = ""
    labels: str = "[]"


class PromptRegistryUpdateRequest(BaseModel):
    name: Optional[str] = None
    prompt_text: Optional[str] = None
    description: Optional[str] = None
    labels: Optional[str] = None
    change_reason: str = "updated"


class PromptRegistryRollbackRequest(BaseModel):
    version: int = Field(ge=1)
    reason: str = "rollback"


class PromptRegistryPromoteRequest(BaseModel):
    target_environment: str = Field(default="dev", min_length=1, max_length=32)
    reason: str = Field(default="promote", min_length=1, max_length=512)
    approval_ticket: Optional[str] = Field(default=None, max_length=128)
    require_render_validation: bool = True
    render_variables: dict[str, str] = Field(default_factory=dict)
    preview_only: bool = False


class PromptRegistryPromoteResponse(BaseModel):
    item: PromptRegistryItemResponse
    target_environment: str
    promotion_recorded: bool
    render_preview: str
    variables_detected: list[str]
    missing_variables: list[str]
    approval_required: bool
    approval_ticket: Optional[str] = None


class PromptRegistryRenderRequest(BaseModel):
    variables: dict[str, str] = Field(default_factory=dict)
    version: Optional[int] = Field(default=None, ge=1)
    require_all_variables: bool = True


class PromptRegistryRenderResponse(BaseModel):
    prompt_registry_id: str
    name: str
    version: int
    prompt_text: str
    rendered: str
    variables_detected: list[str]
    missing_variables: list[str]
    variables_applied: dict[str, str]


class PromptRegistryItemResponse(ORMBase):
    prompt_registry_id: str
    name: str
    description: str
    prompt_text: str
    labels: str
    latest_version: int
    status: str
    created_by: str
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class PromptRegistryVersionResponse(ORMBase):
    prompt_registry_version_id: str
    prompt_registry_id: str
    version: int
    prompt_text: str
    change_reason: str
    created_by: str
    created_at: datetime


class PlaygroundTestSetResponse(BaseModel):
    test_set_id: str
    name: str
    case_count: int


class BenchmarkRunRequest(BaseModel):
    agent_id: str
    benchmark_suite: str = "reliability-core"
    environment: str = "dev"


class BenchmarkRunResponse(ORMBase):
    benchmark_run_id: str
    agent_id: str
    benchmark_suite: str
    environment: str
    status: str
    score: int
    summary: str
    created_at: datetime
    estimated_cost_cents: Optional[int] = None
    gateway_call_count: Optional[int] = None
    progress_step: Optional[int] = None
    progress_total: Optional[int] = None
    progress_label: Optional[str] = None


class BenchmarkCostEstimateResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    agent_id: str
    benchmark_suite: str
    environment: str
    model_name: str
    gateway_call_count: int
    estimated_cost_cents: int
    currency: str = "USD"


class ScanRunRequest(BaseModel):
    agent_id: str
    scan_type: str = "security"
    environment: str = "dev"


class ScanRunResponse(ORMBase):
    scan_run_id: str
    agent_id: str
    scan_type: str
    environment: str
    status: str
    findings_count: int
    severity_high_count: int
    summary: str
    created_at: datetime
    estimated_cost_cents: Optional[int] = None
    gateway_call_count: Optional[int] = None
    progress_step: Optional[int] = None
    progress_total: Optional[int] = None
    progress_label: Optional[str] = None


class ScanCostEstimateResponse(BaseModel):
    model_config = {"protected_namespaces": ()}

    agent_id: str
    scan_type: str
    environment: str
    model_name: str
    gateway_call_count: int
    estimated_cost_cents: int
    currency: str = "USD"


class BenchmarkScanAnalyticsBucketResponse(BaseModel):
    bucket_start: datetime
    bucket_end: datetime
    segment_by: str
    segment_key: str
    run_count: int
    average_score: float = 0.0
    completed_count: int = 0
    failed_count: int = 0
    min_score: int = 0
    max_score: int = 0
    total_findings: int = 0
    total_high_severity: int = 0
    average_findings: float = 0.0


class BenchmarkScanAnalyticsSegmentResponse(BaseModel):
    segment_by: str
    segment_key: str
    run_count: int
    average_score: float = 0.0
    completed_count: int = 0
    failed_count: int = 0
    min_score: int = 0
    max_score: int = 0
    total_findings: int = 0
    total_high_severity: int = 0


class BenchmarkScanAnalyticsTrendsResponse(BaseModel):
    kind: str
    window_hours: int
    bucket_hours: int
    segment_by: str
    total_runs: int
    buckets: list[BenchmarkScanAnalyticsBucketResponse]
    segments: list[BenchmarkScanAnalyticsSegmentResponse]


class BenchmarkScanCancelResponse(BaseModel):
    run_id: str
    status: str
    message: str


class AgenticContractValidateRequest(BaseModel):
    agent_id: str
    module_ids: list[str]
    route_policy_snapshot_id: str
    required_capabilities: list[str] = []
    runtime_model: Optional[str] = None


class AgenticContractValidateResponse(BaseModel):
    agent_id: str
    status: str
    checks_passed: int
    checks_failed: int
    issues: list[str]


class AgenticReadinessReportResponse(BaseModel):
    generated_at: datetime
    readiness_score: int
    controls_status: str
    benchmark_coverage: int
    scan_coverage: int
    open_high_findings: int
    scale_tier3_certified: bool
    certified_user_capacity: int
    recommendation: str


class AgenticReadinessCertificationRequest(BaseModel):
    target_capacity: int = Field(default=100000, ge=10000, le=1000000)
    require_multi_region: bool = True
    cost_freshness_slo_seconds: int = Field(default=60, ge=1, le=3600)


class AgenticReadinessCertificationResponse(ORMBase):
    certification_id: str
    target_capacity: int
    required_multi_region: bool
    cost_freshness_slo_seconds: int
    readiness_score: int
    scale_benchmark_pass: bool
    security_scan_pass: bool
    contract_validation_pass: bool
    cost_freshness_pass: bool
    multi_region_pass: bool
    certified: bool
    certified_user_capacity: int
    integrity_hash: str
    signature: str
    override_applied: bool
    override_reason: Optional[str]
    override_by: Optional[str]
    override_at: Optional[datetime]
    summary: str
    executed_by: str
    created_at: datetime


class AgenticReadinessOverrideRequest(BaseModel):
    reason_code: str


class AgenticReadinessCertificationExportResponse(BaseModel):
    export_id: str
    exported_at: datetime
    export_uri: str
    certification: AgenticReadinessCertificationResponse
    audit_event_count: int
    evidence_items: list[str]


class ExecutionCheckpointCreateRequest(BaseModel):
    session_id: str
    agent_id: str
    stage_name: str
    state_payload: str


class ExecutionCheckpointResumeRequest(BaseModel):
    reason_code: str


class ExecutionCheckpointResponse(ORMBase):
    checkpoint_id: str
    session_id: str
    agent_id: str
    stage_name: str
    state_payload: str
    status: str
    created_by: str
    created_at: datetime
    resumed_by: Optional[str]
    resumed_at: Optional[datetime]
    resume_count: int


class ScaleLoadTestRunRequest(BaseModel):
    tier: Literal["tier1", "tier2", "tier3"]
    target_capacity: int = Field(ge=10000, le=1000000)
    expected_concurrency: int = Field(ge=1, le=200000)
    expected_rps: int = Field(ge=1, le=500000)
    observed_peak_concurrency: int = Field(ge=0, le=200000)
    observed_peak_rps: int = Field(ge=0, le=500000)
    degradation_test_pass: bool
    recovery_test_pass: bool
    compliance_continuity_pass: bool


class ScaleLoadTestRunResponse(ORMBase):
    load_test_run_id: str
    tier: str
    target_capacity: int
    expected_concurrency: int
    expected_rps: int
    observed_peak_concurrency: int
    observed_peak_rps: int
    degradation_test_pass: bool
    recovery_test_pass: bool
    compliance_continuity_pass: bool
    passed: bool
    summary: str
    executed_by: str
    created_at: datetime


class PolicyAutoTuneRequest(BaseModel):
    environment: str = "prod"
    optimize_for: str = Field(default="balanced", pattern="^(balanced|cost|latency)$")
    max_routes: int = 10
    dry_run: bool = True


class PolicyAutoTuneChange(BaseModel):
    route_policy_id: str
    previous_strategy: str
    recommended_strategy: str
    changed: bool


class PolicyAutoTuneResponse(BaseModel):
    environment: str
    optimize_for: str
    dry_run: bool
    total_routes_evaluated: int
    total_routes_changed: int
    controls_status: str
    changes: list[PolicyAutoTuneChange]


class PolicyScheduledOptimizeRequest(BaseModel):
    environment: str = "prod"
    optimize_for: str = Field(default="balanced", pattern="^(balanced|cost|latency)$")
    max_routes: int = Field(default=10, ge=1, le=1000)
    window_start_hour_utc: int = Field(default=0, ge=0, le=23)
    window_end_hour_utc: int = Field(default=0, ge=0, le=23)
    max_changes_without_approval: int = Field(default=3, ge=0, le=1000)
    approval_token: Optional[str] = None
    dry_run: bool = False


class PolicyScheduledOptimizeResponse(BaseModel):
    environment: str
    optimize_for: str
    dry_run: bool
    current_hour_utc: int
    within_change_window: bool
    approval_required: bool
    approved: bool
    executed: bool
    execution_status: str
    total_routes_evaluated: int
    proposed_changes: int
    applied_changes: int
    controls_status: str
    changes: list[PolicyAutoTuneChange]


class PolicyScheduleCreateRequest(BaseModel):
    name: str
    environment: str = "prod"
    optimize_for: str = Field(default="balanced", pattern="^(balanced|cost|latency)$")
    max_routes: int = Field(default=10, ge=1, le=1000)
    window_start_hour_utc: int = Field(default=0, ge=0, le=23)
    window_end_hour_utc: int = Field(default=0, ge=0, le=23)
    max_changes_without_approval: int = Field(default=3, ge=0, le=1000)
    enabled: bool = True


class PolicyScheduleUpdateRequest(BaseModel):
    name: Optional[str] = None
    environment: Optional[str] = None
    optimize_for: Optional[str] = Field(default=None, pattern="^(balanced|cost|latency)$")
    max_routes: Optional[int] = Field(default=None, ge=1, le=1000)
    window_start_hour_utc: Optional[int] = Field(default=None, ge=0, le=23)
    window_end_hour_utc: Optional[int] = Field(default=None, ge=0, le=23)
    max_changes_without_approval: Optional[int] = Field(default=None, ge=0, le=1000)
    enabled: Optional[bool] = None


class PolicyScheduleJobResponse(ORMBase):
    job_id: str
    name: str
    environment: str
    optimize_for: str
    max_routes: int
    window_start_hour_utc: int
    window_end_hour_utc: int
    max_changes_without_approval: int
    enabled: bool
    created_at: datetime
    last_run_at: Optional[datetime] = None


class PolicyScheduleExecuteNowRequest(BaseModel):
    approval_token: Optional[str] = None
    dry_run: bool = False


class PolicyScheduleApproveRequest(BaseModel):
    reason_code: Optional[str] = None


class PolicyScheduleApproveResponse(BaseModel):
    job_id: str
    approval_role: str
    approved_by: str
    approval_action: str
    approved_at: datetime


class PolicyScheduleStatusResponse(BaseModel):
    job_id: str
    enabled: bool
    last_run_at: Optional[datetime] = None
    approvals_last_24h: list[str]
    latest_security_approval_by: Optional[str] = None
    latest_security_approval_at: Optional[datetime] = None
    latest_ai_ops_approval_by: Optional[str] = None
    latest_ai_ops_approval_at: Optional[datetime] = None
    dual_approval_ready: bool
    pending_dual_approval: bool


class PolicyScheduleSummaryResponse(BaseModel):
    total_schedules: int
    enabled_schedules: int
    disabled_schedules: int
    dual_approval_ready_schedules: int
    pending_dual_approval_schedules: int


class PolicyScheduleDeleteResponse(BaseModel):
    deleted: bool
    job_id: str


class PlatformMaintenanceStatusResponse(BaseModel):
    active: bool
    message: str = ""


class PlatformPerformancePolicyResponse(BaseModel):
    slow_response_threshold_ms: int


class PlatformOperationalStatusResponse(BaseModel):
    status: Literal["ok", "degraded", "maintenance", "incident"] = Field(
        description="Overall platform posture for operator banners."
    )
    maintenance: PlatformMaintenanceStatusResponse
    performance: PlatformPerformancePolicyResponse
    feedback_enabled: bool = Field(description="When false, POST /platform/feedback returns 403.")
    runtime_config_cache: dict = Field(description="Non-secret runtime config cache posture.")
    rate_limit: dict = Field(description="Rate limiter backend posture.")
    control_plane: Optional[dict] = Field(
        default=None,
        description="Cheap CPLI/release-gate advisory for operator banners (engineering-only).",
    )

class ControlPlanePostureResponse(BaseModel):
    app_plane: Literal["all", "control", "data"] = Field(
        description="Process role from APP_PLANE env (all=monolith, control=admin, data=inference)."
    )
    isolation_mode: Literal["combined", "process_isolated"] = Field(
        description="combined when APP_PLANE=all; process_isolated when control or data."
    )
    control_schedulers_enabled: bool = Field(
        description="Whether discovery/orchestration poll loops are active on this process."
    )
    env_var: str = Field(description="Environment variable name controlling plane mode.")
    architecture_targets: dict = Field(description="Mapping of architecture §12 targets to current posture.")
    policy_generation: Optional[dict] = Field(
        default=None,
        description="Desired-state fingerprint of routes/keys/cache policies (shared Postgres).",
    )
    peer: Optional[dict] = Field(
        default=None,
        description="Opposite-plane peer probe result (DATA_PLANE_PEER_URL / CONTROL_PLANE_PEER_URL).",
    )
    drift_status: Optional[str] = Field(
        default=None,
        description="Reconcile status: none_combined|in_sync|drift_detected|peer_unreachable|peer_unconfigured|n/a.",
    )
    rejection_stats: Optional[dict] = Field(
        default=None,
        description="In-process counters for PLANE_ROUTE_REJECTED denials.",
    )
    gate: Optional[dict] = Field(
        default=None,
        description="Fail-closed gate state (PLANE_FAIL_CLOSED_MODE) for data-plane inference.",
    )
    last_reconcile: Optional[dict] = Field(
        default=None,
        description="Most recent reconcile snapshot including source and recorded_at_unix.",
    )
    drift_events_recent: Optional[list] = Field(
        default=None,
        description="Newest drift/reconcile events (durable DB + in-process fallback).",
    )
    published_policy_generation: Optional[dict] = Field(
        default=None,
        description="Hot-published desired-state fingerprint (Redis and/or plane.policy_generation_json).",
    )
    slos: Optional[dict] = Field(
        default=None,
        description="Plane SLO scorecard: peer probe latency, generation freshness, on-plane coverage.",
    )
    on_plane_coverage: Optional[dict] = Field(
        default=None,
        description="On-plane inference coverage scorecard (CostEvents vs off-plane signals).",
    )
    notes: str = Field(description="Operator guidance for deploy-time plane isolation.")
    leadership_summary: Optional[dict] = Field(
        default=None,
        description="Slim CPLI / release-gate / promotion-readiness summary (engineering-only).",
    )
    desired_observed: Optional[dict] = Field(
        default=None,
        description="Desired (spec) vs observed (status) policy generation split + last-known-good.",
    )
    contract: Optional[dict] = Field(
        default=None,
        description="Versioned control-plane contract and capability inventory.",
    )
    control_readonly: Optional[bool] = Field(
        default=None,
        description="True when PLANE_CONTROL_READONLY freezes control-plane mutations.",
    )
    last_known_good: Optional[dict] = Field(
        default=None,
        description="Last-known-good fingerprint recorded on healthy reconcile (continue-on-CP-down narrative).",
    )
    leadership_attestation: Optional[dict] = Field(
        default=None,
        description="Present when reconcile was called with attest=true (CPLI attestation summary).",
    )
    release_gate: Optional[dict] = Field(
        default=None,
        description="Present when reconcile was called with evaluate_gate=true (persisted gate summary).",
    )

class OperatorFeedbackCreateRequest(BaseModel):
    category: str = Field(
        default="other",
        description="Feedback category: performance, ux, bug, feature, incident, or other.",
        examples=["performance"],
    )
    severity: str = Field(default="medium", description="Severity: low, medium, or high.", examples=["high"])
    comment: str = Field(min_length=1, max_length=4000, description="Operator narrative (required).")
    context_view: str = Field(default="overview", description="Active console view when feedback was filed.")
    context_action: str = Field(default="", description="Action context key for custom reports (e.g. load_overview).")
    client_latency_ms: Optional[int] = Field(default=None, ge=0, le=600000, description="Observed client latency.")
    trace_id: Optional[str] = Field(default=None, description="Optional trace correlation ID.")
    incident_ref: Optional[str] = Field(default=None, description="Optional UI incident reference token.")
    metadata_json: dict = Field(default_factory=dict, description="Additional structured context (JSON object).")


class OperatorFeedbackActionRequest(BaseModel):
    action: str = Field(description="Triage action: acknowledge, resolve, dismiss, or escalate.")
    action_note: str = Field(default="", max_length=2000, description="Optional operator note for audit evidence.")


class OperatorFeedbackResponse(ORMBase):
    feedback_id: str = Field(description="Primary key; UUID string.")
    category: str
    severity: str
    comment: str
    context_view: str
    context_action: str
    client_latency_ms: Optional[int] = None
    trace_id: Optional[str] = None
    incident_ref: Optional[str] = None
    metadata_json: str = Field(description="JSON string of metadata captured at submit time.")
    status: str = Field(description="open, acknowledged, resolved, or dismissed.")
    action_note: Optional[str] = None
    acted_by: Optional[str] = None
    acted_at: Optional[datetime] = None
    created_by: str
    created_at: datetime
    updated_at: datetime


class OperatorFeedbackAnalyticsBucketResponse(BaseModel):
    label: str
    count: int


class OperatorFeedbackAnalyticsResponse(BaseModel):
    generated_at: datetime
    since_hours: int
    total_count: int
    open_count: int
    by_category: list[OperatorFeedbackAnalyticsBucketResponse]
    by_severity: list[OperatorFeedbackAnalyticsBucketResponse]
    by_status: list[OperatorFeedbackAnalyticsBucketResponse]
    by_context_view: list[OperatorFeedbackAnalyticsBucketResponse]
    by_context_action: list[OperatorFeedbackAnalyticsBucketResponse]


class GatewayMemoryRecordCreateRequest(BaseModel):
    memory_tier: str = Field(pattern="^(short_term|long_term)$")
    scope_type: str = Field(pattern="^(session|conversation|agent|global)$")
    scope_id: str = Field(min_length=1, max_length=128)
    label: str = Field(default="", max_length=256)
    content: str = Field(min_length=1, max_length=16384)
    metadata_json: Optional[str] = Field(default="{}")
    environment: str = Field(default="dev", max_length=64)


class GatewayMemoryRecordResponse(BaseModel):
    memory_id: str
    memory_tier: str
    scope_type: str
    scope_id: str
    label: str
    content: str
    metadata_json: str
    actor_id: str
    environment: str
    status: str
    expires_at: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime
    deleted_at: Optional[datetime] = None


class GatewayMemoryRecordListResponse(BaseModel):
    object: str = "list"
    data: list[GatewayMemoryRecordResponse]
    total: int


class GatewayMemoryRecordDeleteResponse(BaseModel):
    memory_id: str
    object: str = "memory.deleted"
    deleted: bool
    trace_id: str


class GatewayMemoryTierSummary(BaseModel):
    active_records: int = 0
    expiring_soon: int = 0
    checkpoints: int = 0
    active_realtime_sessions: int = 0
    semantic_policies: int = 0
    hit_ratio: float = 0.0
    response_records: int = 0
    file_records: int = 0
    system_rules: int = 0


class GatewayMemoryOverviewResponse(BaseModel):
    semantic_cache: GatewayMemoryTierSummary
    short_term: GatewayMemoryTierSummary
    long_term: GatewayMemoryTierSummary
    short_term_ttl_seconds: int
    max_records_per_scope: int


class GatewayMemoryConfigMemorySettings(BaseModel):
    pii_classification_enabled: bool = False
    short_term_ttl_seconds: int
    max_records_per_scope: int
    long_term_enabled: bool
    content_max_bytes: int
    session_capture_enabled: bool = False


class GatewayMemoryConfigSemanticCacheSettings(BaseModel):
    default_mode: str
    default_similarity_threshold: float
    default_ttl_seconds: int
    inference_short_circuit_enabled: bool = False
    note: str


class GatewayVectorStoreConfigItem(BaseModel):
    store_id: str
    provider_type: str
    enabled: bool
    connection_url: str
    collection_name: str
    embedding_dimensions: int
    similarity_metric: str
    secret_provider_id: Optional[str] = None
    api_key_secret_ref: Optional[str] = None
    mcp_server_id: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


class GatewayMemoryConfigVectorStoreSettings(BaseModel):
    default_store_id: str
    default_secret_provider_id: str = ""
    search_top_k: int
    embedding_model: str
    live_probe_enabled: bool = False
    stores: list[GatewayVectorStoreConfigItem]
    supported_provider_types: list[str]


class GatewayVectorStorePlatformContext(BaseModel):
    default_store_id: str
    default_secret_provider_id: str = ""
    search_top_k: int
    embedding_model: str


class GatewayMemoryPlatformConfigResponse(BaseModel):
    memory: GatewayMemoryConfigMemorySettings
    semantic_cache: GatewayMemoryConfigSemanticCacheSettings
    vector_stores: GatewayMemoryConfigVectorStoreSettings
    runtime_config_keys: dict[str, str]


class GatewayVectorStoreHealthResponse(BaseModel):
    store_id: str
    status: str
    reachable: bool
    message: str
    provider_type: Optional[str] = None
    connection_host: Optional[str] = None
    api_key_secret_ref: Optional[str] = None
    secret_configured: Optional[bool] = None
    secret_masked_hint: Optional[str] = None
    secret_backend_type: Optional[str] = None
    secret_integration_mode: Optional[str] = None
    cloud_integrated: Optional[bool] = None
    mcp_server_id: Optional[str] = None
    mcp_server_configured: Optional[bool] = None
    live_probed: Optional[bool] = None
    live_reachable: Optional[bool] = None


class GatewayRagDocumentInput(BaseModel):
    id: Optional[str] = None
    text: Optional[str] = None
    content: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


class GatewayRagIngestRequest(BaseModel):
    store_id: str = Field(min_length=1, max_length=128)
    documents: list[GatewayRagDocumentInput] = Field(min_length=1, max_length=100)
    metadata: dict = Field(default_factory=dict)


class GatewayRagIngestResponse(BaseModel):
    object: str
    store_id: str
    provider_type: str
    ingested: int
    document_ids: list[str]
    upstream: dict = Field(default_factory=dict)
    trace_id: str


class GatewayRagQueryRequest(BaseModel):
    store_id: str = Field(min_length=1, max_length=128)
    query: str = Field(min_length=1, max_length=8192)
    top_k: Optional[int] = Field(default=None, ge=1, le=100)


class GatewayRagQueryResponse(BaseModel):
    object: str
    store_id: str
    provider_type: str
    query: str
    top_k: int
    matches: list = Field(default_factory=list)
    match_count: int
    upstream: dict = Field(default_factory=dict)
    content_guard_decision: Optional[str] = None
    content_guard_reasons: Optional[list[str]] = None
    trace_id: str


class GatewayVectorStoreOpenAIResponse(BaseModel):
    id: str
    object: str
    name: str
    status: str
    provider_type: str
    embedding_dimensions: int
    similarity_metric: str
    mcp_server_id: Optional[str] = None
    metadata: dict = Field(default_factory=dict)


class GatewayVectorStoreOpenAIListResponse(BaseModel):
    object: str
    data: list[GatewayVectorStoreOpenAIResponse]


class GatewayVectorStoreRegisterRequest(BaseModel):
    store_id: str = Field(min_length=1, max_length=128)
    provider_type: str = Field(default="mcp_bridge")
    collection_name: str = Field(min_length=1, max_length=256)


class GatewayVectorStoreContextResponse(BaseModel):
    store: GatewayVectorStoreConfigItem
    platform: GatewayVectorStorePlatformContext
    health: GatewayVectorStoreHealthResponse
    secret_integration: dict = Field(default_factory=dict)
    mcp_bridge: Optional[dict] = None
    supported_mcp_tools_hint: list[str] = Field(default_factory=list)


class OrchestrationFlowCreateRequest(BaseModel):
    flow_name: str = Field(min_length=1, max_length=255)
    description: str = ""
    status: str = "draft"
    environment: str = "dev"
    tenant_id: Optional[str] = None
    trigger_type: str = "manual"
    trigger_config_json: str = "{}"
    graph_json: str = '{"nodes":[],"edges":[]}'
    access_policy_json: Optional[str] = None


class OrchestrationFlowUpdateRequest(BaseModel):
    flow_name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = None
    environment: Optional[str] = None
    tenant_id: Optional[str] = None
    trigger_type: Optional[str] = None
    trigger_config_json: Optional[str] = None
    graph_json: Optional[str] = None
    access_policy_json: Optional[str] = None


class OrchestrationFlowApproveRequest(BaseModel):
    decision: str = "approved"
    approval_ticket_ref: Optional[str] = None
    stage_id: Optional[str] = None


class OrchestrationFlowPromoteRequest(BaseModel):
    target_environment: str = Field(default="staging", pattern="^(dev|staging|prod)$")
    change_ticket_id: Optional[str] = Field(default=None, max_length=128)
    change_reason: str = Field(default="Environment promotion", max_length=512)


class OrchestrationFlowRevisionResponse(BaseModel):
    revision_id: str
    flow_id: str
    version: int
    flow_name: str
    description: str
    status: str
    environment: str
    trigger_type: str
    change_reason: str
    created_by: str
    created_at: datetime


class OrchestrationFlowRevisionListResponse(BaseModel):
    data: list[OrchestrationFlowRevisionResponse]


class OrchestrationFlowRollbackRequest(BaseModel):
    version: int = Field(ge=1)
    change_reason: str = Field(default="Rollback to prior revision", max_length=512)


class OrchestrationJitAccessRequestCreateRequest(BaseModel):
    requested_action: str = Field(default="run", pattern="^(run|approve|manage)$")
    justification: str = Field(min_length=1)
    environment: Optional[str] = None
    requested_duration_minutes: int = Field(default=60, ge=5, le=480)


class OrchestrationJitAccessApproveRequest(BaseModel):
    decision: str = "approve"


class OrchestrationJitAccessRequestResponse(BaseModel):
    request_id: str
    flow_id: str
    requester_id: str
    requester_role: str
    requested_action: str
    justification: str
    environment: str
    requested_duration_minutes: int
    status: str
    approved_by: Optional[str] = None
    approved_role: Optional[str] = None
    approved_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OrchestrationJitAccessRequestListResponse(BaseModel):
    total: int
    data: list[OrchestrationJitAccessRequestResponse]


class OrchestrationAccessCertifyRequest(BaseModel):
    attestation_notes: str = ""
    approver_id: Optional[str] = None


class OrchestrationAccessCertificationResponse(BaseModel):
    certification_id: str
    flow_id: str
    certified_by: str
    approver_id: Optional[str] = None
    certified_at: datetime
    next_due_at: datetime
    attestation_notes: str
    status: str

    model_config = ConfigDict(from_attributes=True)


class OrchestrationAccessCertificationDueItem(BaseModel):
    flow_id: str
    flow_name: str
    environment: str
    reason: str
    next_due_at: Optional[str] = None
    recertify_interval_days: int


class OrchestrationAccessCertificationDueResponse(BaseModel):
    total: int
    data: list[OrchestrationAccessCertificationDueItem]


class OrchestrationFlowApprovalEventResponse(BaseModel):
    approval_event_id: str
    flow_id: str
    event_type: str
    stage_id: Optional[str] = None
    action: str
    state_from: str
    state_to: str
    actor_id: str
    actor_role: str
    approver_id: Optional[str] = None
    decision: str
    reason_code: Optional[str] = None
    ticket_ref: Optional[str] = None
    occurred_at: datetime

    model_config = ConfigDict(from_attributes=True)


class OrchestrationIgaExplainRequest(BaseModel):
    action: str = Field(default="run", pattern="^(run|approve|manage)$")


class OrchestrationIgaExplainResponse(BaseModel):
    flow_id: str
    action: str
    decision: str
    allowed: bool
    error_code: Optional[str] = None
    factors: list[dict] = Field(default_factory=list)
    policy_version: int = 1
    decision_trace_id: str


class OrchestrationIgaPostureResponse(BaseModel):
    flow_id: str
    environment: str
    approval_status: str
    policy_version: int = 1
    sod: dict = Field(default_factory=dict)
    certification: dict = Field(default_factory=dict)
    staged_approval: dict = Field(default_factory=dict)
    active_jit_grants: list[dict] = Field(default_factory=list)
    entitlement: dict = Field(default_factory=dict)


class OrchestrationDataConnectionResponse(BaseModel):
    connection_id: str
    label: Optional[str] = None
    driver: str
    enabled: bool = True
    max_rows: int = 200
    credential_binding_id: Optional[str] = None


class OrchestrationDataConnectionListResponse(BaseModel):
    total: int
    data: list[OrchestrationDataConnectionResponse]


class OrchestrationDataConnectionTestQueryRequest(BaseModel):
    sql: str = Field(min_length=1, max_length=8000)
    parameters: dict = Field(default_factory=dict)
    preview_limit: int = Field(default=10, ge=1, le=50)


class OrchestrationDataConnectionTestQueryResponse(BaseModel):
    connection_id: str
    row_count: int
    columns: list[str] = Field(default_factory=list)
    rows: list[dict] = Field(default_factory=list)
    truncated: bool = False


class OrchestrationAccessPolicyResolveRequest(BaseModel):
    access_policy_json: Optional[str] = None


class OrchestrationAccessPolicyResolveResponse(BaseModel):
    flow_id: str
    resolved_policy: dict = Field(default_factory=dict)
    resolve_errors: list[str] = Field(default_factory=list)
    template_context: dict = Field(default_factory=dict)


class OrchestrationConsoleSummaryResponse(BaseModel):
    flow_count: int = 0
    flows_by_environment: dict = Field(default_factory=dict)
    pending_prod_approvals: int = 0
    certifications_due: int = 0
    active_jit_grants: int = 0
    runs_awaiting_approval: int = 0


class OrchestrationWebhookTriggerRequest(BaseModel):
    run_input: Optional[str] = ""
    dry_run: bool = False


class OrchestrationSchedulerTickResponse(BaseModel):
    tick_at: datetime
    triggered: list[dict] = Field(default_factory=list)


class GatewayTunnelConfigResponse(BaseModel):
    enabled: bool = False
    base_url: str = "/gateway/v1"
    openai_compatible_base: str = "/gateway/v1"
    snippets: dict = Field(default_factory=dict)


class OrchestrationFlowRunRequest(BaseModel):
    dry_run: bool = False
    run_input: Optional[str] = ""


class OrchestrationFlowResponse(BaseModel):
    flow_id: str
    flow_name: str
    description: str
    status: str
    environment: str
    tenant_id: Optional[str] = None
    trigger_type: str
    trigger_config_json: str
    graph_json: str
    access_policy_json: str = "{}"
    approval_stage_state_json: str = "{}"
    approval_status: str
    metadata_version: int
    created_by: str
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class OrchestrationFlowListResponse(BaseModel):
    total: int
    data: list[OrchestrationFlowResponse]


class OrchestrationFlowValidateResponse(BaseModel):
    flow_id: Optional[str] = None
    valid: bool
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    node_count: int = 0
    edge_count: int = 0
    max_nodes_per_flow: int = 50
    http_allowlist_configured: bool = False
    policy: dict = Field(default_factory=dict)


class OrchestrationFlowRunResponse(BaseModel):
    run_id: str
    flow_id: str
    flow_name: Optional[str] = None
    status: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    trace_id: str
    step_results_json: str
    error_summary: Optional[str] = None
    execution_state_json: Optional[str] = None
    webhook_response: Optional[dict] = None


class OrchestrationFlowRunListResponse(BaseModel):
    total: int
    data: list[OrchestrationFlowRunResponse]


class OrchestrationRunApprovalGateResponse(BaseModel):
    gate_id: str
    run_id: str
    flow_id: str
    node_id: str
    status: str
    approval_title: str
    required_role: Optional[str] = None
    resolved_approver_id: Optional[str] = None
    resolved_approver_role: Optional[str] = None
    decided_by: Optional[str] = None
    decided_at: Optional[datetime] = None
    metadata_json: str = "{}"
    created_at: datetime


class OrchestrationRunApprovalGateListResponse(BaseModel):
    total: int
    data: list[OrchestrationRunApprovalGateResponse]


class OrchestrationRunApprovalGateDecideRequest(BaseModel):
    decision: str
    comment: Optional[str] = None


class OrchestrationNodeTypeItem(BaseModel):
    type: str
    label: str
    description: str
    required_config_fields: list[str] = Field(default_factory=list)
    optional_config_fields: list[str] = Field(default_factory=list)


class OrchestrationNodeTypesResponse(BaseModel):
    node_types: list[OrchestrationNodeTypeItem]
    policy: dict = Field(default_factory=dict)


class OrchestrationLiveReadinessBootstrapRequest(BaseModel):
    seed_connector_hosts: bool = True
    enable_non_prod_live: bool = False


class OrchestrationLiveReadinessResponse(BaseModel):
    connector_hosts: dict = Field(default_factory=dict)
    live_executor: dict = Field(default_factory=dict)
    non_prod_live_ready: bool = False
    prod_live_enabled: bool = False
    recommendations: list[str] = Field(default_factory=list)
    actions_applied: list[str] = Field(default_factory=list)


# ── Gateway Assistants / Fine-tuning / Passthrough ────────────────────────────


class GatewayAssistantCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    model: str = Field(min_length=1, max_length=255)
    instructions: str = ""
    metadata: dict = Field(default_factory=dict)
    environment: str = "dev"


class GatewayAssistantResponse(BaseModel):
    id: str
    object: str = "assistant"
    created_at: int
    name: str
    model: str
    instructions: str
    metadata: dict = Field(default_factory=dict)
    environment: str = "dev"


class GatewayAssistantListResponse(BaseModel):
    object: str = "list"
    data: list[GatewayAssistantResponse]


class GatewayAssistantDeleteResponse(BaseModel):
    id: str
    object: str = "assistant.deleted"
    deleted: bool = True


class GatewayThreadCreateRequest(BaseModel):
    metadata: dict = Field(default_factory=dict)
    environment: str = "dev"


class GatewayThreadResponse(BaseModel):
    id: str
    object: str = "thread"
    created_at: int
    metadata: dict = Field(default_factory=dict)
    environment: str = "dev"


class GatewayThreadMessageCreateRequest(BaseModel):
    role: str = Field(default="user", min_length=1, max_length=32)
    content: str = Field(min_length=1)
    metadata: dict = Field(default_factory=dict)


class GatewayThreadMessageResponse(BaseModel):
    id: str
    object: str = "thread.message"
    created_at: int
    thread_id: str
    role: str
    content: list[dict] = Field(default_factory=list)
    metadata: dict = Field(default_factory=dict)


class GatewayThreadMessageListResponse(BaseModel):
    object: str = "list"
    data: list[GatewayThreadMessageResponse]


class GatewayThreadRunCreateRequest(BaseModel):
    assistant_id: str = Field(min_length=1)
    model: Optional[str] = None
    environment: str = "dev"
    additional_instructions: str = ""
    stream: bool = False


class GatewayThreadRunResponse(BaseModel):
    id: str
    object: str = "thread.run"
    created_at: int
    thread_id: str
    assistant_id: str
    status: str
    model: str
    completed_at: Optional[int] = None
    response_text: str = ""


class GatewayFineTuningJobCreateRequest(BaseModel):
    model: str = Field(min_length=1, max_length=255)
    training_file_id: str = Field(min_length=1, max_length=128)
    environment: str = "dev"
    metadata: dict = Field(default_factory=dict)


class GatewayFineTuningJobResponse(BaseModel):
    id: str
    object: str = "fine_tuning.job"
    created_at: int
    model: str
    training_file_id: str
    fine_tuned_model: Optional[str] = None
    status: str
    finished_at: Optional[int] = None
    environment: str = "dev"
    live_mode: bool = False
    upstream_job_id: Optional[str] = None


class GatewayFineTuningJobListResponse(BaseModel):
    object: str = "list"
    data: list[GatewayFineTuningJobResponse]


class GatewayFineTuningJobCancelResponse(BaseModel):
    id: str
    object: str = "fine_tuning.job"
    status: str = "cancelled"
    live_mode: bool = False


class GatewayPassthroughRequest(BaseModel):
    provider_id: str = Field(min_length=1, max_length=128)
    method: str = Field(default="POST", min_length=1, max_length=16)
    path: str = Field(min_length=1, max_length=512)
    headers: dict = Field(default_factory=dict)
    body: Optional[dict] = None
    environment: str = "dev"


class GatewayPassthroughResponse(BaseModel):
    status_code: int
    headers: dict = Field(default_factory=dict)
    body: object = None
    trace_id: str
    provider_id: str
    path: str


class PlaygroundRunDetailResponse(BaseModel):
    run: PlaygroundRunResponse
    feedback: list[PlaygroundRunFeedbackResponse] = Field(default_factory=list)
    latest_assessment: Optional[PlaygroundRunAssessResponse] = None
    audit_events: list[dict] = Field(default_factory=list)
    route_draft: Optional[dict] = None
    quality_escalation: Optional[PlaygroundQualityEscalationResponse] = None


class ComplianceEvidenceExportRequest(BaseModel):
    control_id: str = Field(min_length=1)
    since_hours: int = Field(default=24, ge=1, le=720)
    decision_outcome: Optional[str] = None
    action_type_prefix: Optional[str] = None
    tenant_id: Optional[str] = None
    environment: Optional[str] = None
    source_type: Optional[str] = None
    source_id_prefix: Optional[str] = None
    limit_events: int = Field(default=20, ge=1, le=200)
    limit_artifacts: int = Field(default=20, ge=1, le=200)
    investigation_context: Optional[dict] = None


class ComplianceEvidenceExportResponse(BaseModel):
    export_id: str
    exported_at: datetime
    control_id: str
    bundle: ComplianceEvidenceBundleResponse
    audit_event: dict
    investigation_context: Optional[dict] = None
