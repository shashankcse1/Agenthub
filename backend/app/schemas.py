from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field

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
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


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
    action_type: str
    resource_type: str
    resource_id: str
    trace_id: str
    decision_outcome: Literal["allow", "deny", "warn"]
    policy_version: str


class DiscoverySourceResponse(BaseModel):
    source_id: str
    status: str
    last_sync_at: Optional[datetime] = None
    sync_lag_minutes: Optional[int] = None
    discovered_count: int = 0


class DiscoveryPromoteQueueResponse(BaseModel):
    discovered_agent_id: str
    canonical_agent_key: str
    source_system: str
    discovery_confidence: int
    discovery_status: str
    last_discovered_at: datetime
    queue_reason: str


class DiscoveryRecordResponse(ORMBase):
    discovered_agent_id: str
    canonical_agent_key: str
    source_system: str
    source_fingerprint: str
    discovery_confidence: int
    discovery_status: str
    promoted_to_agent_id: Optional[str] = None
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


class CachePolicyResponse(ORMBase):
    cache_policy_id: str
    scope: str
    ttl_seconds: int
    key_strategy: str
    invalidation_strategy: str
    privacy_mode: str
    status: str


class GatewayCacheHealthResponse(BaseModel):
    status: str
    cache_backend: str
    active_policies: int
    avg_ttl_seconds: float
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
    active_only: bool


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


class GatewayExternalCallbackCreateRequest(BaseModel):
    callback_url: str = Field(min_length=8, max_length=2048)
    event_types: list[str] = Field(default_factory=lambda: ["gateway.route.execute_fallback"]) 
    environment: str = "dev"
    redact_sensitive: bool = True
    enabled: bool = True
    description: Optional[str] = Field(default=None, max_length=500)


class GatewayExternalCallbackUpdateRequest(BaseModel):
    callback_url: Optional[str] = Field(default=None, min_length=8, max_length=2048)
    event_types: Optional[list[str]] = None
    environment: Optional[str] = None
    redact_sensitive: Optional[bool] = None
    enabled: Optional[bool] = None
    description: Optional[str] = Field(default=None, max_length=500)


class GatewayExternalCallbackResponse(BaseModel):
    callback_id: str
    callback_url: str
    event_types: list[str]
    environment: str
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
    delivery_status: str
    trace_id: str
    delivered_at: str
    redaction_applied: bool
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


class SupportedModelResponse(ORMBase):
    supported_model_id: str
    provider_type: str
    model_name: str
    display_name: str
    context_window_tokens: int
    status: str
    description: str
    updated_by: Optional[str] = None
    created_at: datetime
    updated_at: datetime


class TenantSupportedModelEntitlementUpsertRequest(BaseModel):
    model_config = {"protected_namespaces": ()}

    tenant_id: str
    provider_type: str
    model_name: str
    status: str = Field(default="active", pattern="^(active|inactive)$")


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


class CostPolicyEvaluateRequest(BaseModel):
    scope_type: str
    scope_id: str
    window_type: str = "daily"


class CostPolicyEvaluateResponse(BaseModel):
    scope_type: str
    scope_id: str
    spend_cents: int
    budget_cents: int
    effective_budget_cents: int
    utilization_percent: float
    projected_24h_spend_cents: int
    projected_utilization_percent: float
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


class ObservabilityLogSchemaStatusResponse(BaseModel):
    generated_at: datetime
    required_fields: list[str]
    sampled_count: int
    valid_count: int
    invalid_count: int
    conformance_percent: float
    missing_field_counts: dict[str, int]


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


class PlaygroundCompareResponse(BaseModel):
    results: list[PlaygroundCompareResult]


class PlaygroundRouteDraftResponse(BaseModel):
    run_id: str
    draft_id: str
    status: str


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


class AgenticContractValidateRequest(BaseModel):
    agent_id: str
    module_ids: list[str]
    route_policy_snapshot_id: str
    required_capabilities: list[str] = []


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
