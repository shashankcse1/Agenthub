from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

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
    max_enable_duration_minutes: int = DEFAULT_BASIC_AUTH_MAX_ENABLE_DURATION_MINUTES


class BasicAuthConfigUpdateRequest(BaseModel):
    allowed_user_groups: Optional[str] = None
    ip_allowlist: Optional[str] = None
    max_enable_duration_minutes: Optional[int] = None


class BasicAuthEnableRequest(BaseModel):
    break_glass_reason: str
    duration_minutes: int = DEFAULT_BASIC_AUTH_ENABLE_DURATION_MINUTES


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


class KeyUpdateRequest(BaseModel):
    allowed_endpoint_families: Optional[str] = None
    allowed_models: Optional[str] = None
    guardrail_policy: Optional[str] = None
    status: Optional[str] = None


class KeyResponse(ORMBase):
    key_id: str
    owner_scope_type: str
    owner_scope_id: str
    allowed_endpoint_families: str
    allowed_models: str
    guardrail_policy: str
    status: str


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
    enforce: bool = True


class RouteTrafficMirroringRequest(BaseModel):
    tenant_id: str
    environment: str = "prod"
    request_tag: Optional[str] = Field(default=None, max_length=64)
    mirror_targets: str = "[]"
    enabled: bool = True


class RouteTrafficMirroringResponse(BaseModel):
    route_policy_id: str
    tenant_id: str
    environment: str
    request_tag: Optional[str] = None
    mirror_targets: str
    enabled: bool = True


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
    findings_distribution: list[dict[str, object]]
    source_distribution: list[dict[str, object]]


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


class GatewayJitAccessApproveRequest(BaseModel):
    decision: str = Field(default="approve", pattern="^(approve|deny)$")
    decision_reason: Optional[str] = Field(default=None, max_length=512)


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
    created_at: datetime


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
    request_tag: Optional[str] = None
    session_id: Optional[str] = None
    owner_scope: Optional[str] = None
    agent_id: Optional[str] = None


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
    cache_short_circuit: Optional[bool] = None


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
    metadata: Optional[dict[str, object]] = None
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
    request_tag: Optional[str] = None
    session_id: Optional[str] = None
    owner_scope: Optional[str] = None
    agent_id: Optional[str] = None


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
    cache_short_circuit: Optional[bool] = None


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
    bytes: int = Field(ge=1, le=2_147_483_647)
    content_type: Optional[str] = Field(default="application/octet-stream", max_length=128)
    metadata: Optional[dict[str, object]] = None
    environment: str = "dev"


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


class GatewayOpenAIFilesListResponse(BaseModel):
    object: str
    data: list[GatewayOpenAIFileResponse]


class GatewayOpenAIFileDeleteResponse(BaseModel):
    id: str
    object: str
    deleted: bool
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


class CostPolicyEvaluateRequest(BaseModel):
    scope_type: str
    scope_id: str
    window_type: str = "daily"


class CostPolicyEvaluateResponse(BaseModel):
    scope_type: str
    scope_id: str
    window_type: str = "daily"
    spend_cents: int
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


class CostLimitScopeDecision(BaseModel):
    scope_type: str
    scope_id: str
    policy_id: Optional[str] = None
    spend_cents: int
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


class CostLimitEvaluateResponse(BaseModel):
    actor_id: str
    window_type: str
    scopes_evaluated: list[CostLimitScopeDecision]
    aggregated_decision: str
    blocking_scopes: list[str]
    soft_alert_scopes: list[str] = Field(default_factory=list)


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


class OrchestrationFlowUpdateRequest(BaseModel):
    flow_name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None
    status: Optional[str] = None
    environment: Optional[str] = None
    tenant_id: Optional[str] = None
    trigger_type: Optional[str] = None
    trigger_config_json: Optional[str] = None
    graph_json: Optional[str] = None


class OrchestrationFlowApproveRequest(BaseModel):
    decision: str = "approved"
    approval_ticket_ref: Optional[str] = None


class OrchestrationFlowRunRequest(BaseModel):
    dry_run: bool = False


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
    status: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    trace_id: str
    step_results_json: str
    error_summary: Optional[str] = None


class OrchestrationFlowRunListResponse(BaseModel):
    total: int
    data: list[OrchestrationFlowRunResponse]


class OrchestrationNodeTypeItem(BaseModel):
    type: str
    label: str
    description: str
    required_config_fields: list[str] = Field(default_factory=list)
    optional_config_fields: list[str] = Field(default_factory=list)


class OrchestrationNodeTypesResponse(BaseModel):
    node_types: list[OrchestrationNodeTypeItem]
    policy: dict = Field(default_factory=dict)
