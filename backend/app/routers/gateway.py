from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy import and_, func
from sqlalchemy.orm import Session

from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import (
    AuditEvent,
    CachePolicy,
    CostEvent,
    GatewayAccessReviewCampaign,
    GatewayAccessReviewItem,
    GatewayEntitlement,
    GatewayJitAccessRequest,
    GatewayLeastPrivilegeRecommendation,
    GatewayNhiInventory,
    OpenAIFileRecord,
    OpenAIResponseRecord,
    RouteMirrorExperimentEvent,
    RoutePolicy,
    RuntimeConfig,
    SecretProviderConfig,
    SupportedModelCatalogEntry,
    TenantSupportedModelEntitlement,
    VirtualKey,
    WorkloadIdentityFederationProfile,
)
from app.router_constants import (
    GATEWAY_ADMIN_OR_AI_OPS_ROLES,
    GATEWAY_ADMIN_OR_SECURITY_ROLES,
    GATEWAY_ADMIN_ROLES,
    GATEWAY_READ_ROLES,
)
from app.runtime_constants import (
    RUNTIME_CONFIG_COST_CLOUD_COMPONENT_MULTIPLIERS_JSON,
    RUNTIME_CONFIG_COST_MODEL_TOKEN_RATES_JSON,
    RUNTIME_CONFIG_GATEWAY_DEFAULT_GLOBAL_TIMEOUT_MS,
    RUNTIME_CONFIG_GATEWAY_DEFAULT_MAX_FALLBACK_HOPS,
    RUNTIME_CONFIG_GATEWAY_EXTERNAL_CALLBACKS_JSON,
)
from app.schemas import (
    CachePolicyRequest,
    CachePolicyResponse,
    GatewayAuthzExplainRequest,
    GatewayAuthzExplainResponse,
    GatewayDecisionTraceResponse,
    GatewayOpenAIChatCompletionsRequest,
    GatewayOpenAIChatCompletionsResponse,
    GatewayOpenAIResponsesRequest,
    GatewayOpenAIResponsesListResponse,
    GatewayOpenAIResponsesDeleteResponse,
    GatewayOpenAIResponsesResponse,
    GatewayOpenAIFileCreateRequest,
    GatewayOpenAIFileDeleteResponse,
    GatewayOpenAIFileResponse,
    GatewayOpenAIFilesListResponse,
    GatewayEntitlementResponse,
    GatewayEntitlementUpsertRequest,
    GatewayAccessReviewCampaignCreateRequest,
    GatewayAccessReviewCampaignResponse,
    GatewayAccessReviewItemResponse,
    GatewayJitAccessApproveRequest,
    GatewayJitAccessRequestCreateRequest,
    GatewayJitAccessRequestResponse,
    GatewayLeastPrivilegeRecommendationApplyRequest,
    GatewayLeastPrivilegeRecommendationResponse,
    GatewayNhiHygieneResponse,
    GatewayNhiInventoryRecordResponse,
    GatewayAnalyticsSummaryResponse,
    GatewayExternalCallbackCreateRequest,
    GatewayExternalCallbackExportRequest,
    GatewayExternalCallbackExportResponse,
    GatewayGovernanceEvidenceExportRequest,
    GatewayGovernanceEvidenceExportResponse,
    GatewayExternalCallbackResponse,
    GatewayExternalCallbackTestRequest,
    GatewayExternalCallbackTestResponse,
    GatewayExternalCallbackUpdateRequest,
    GatewayCacheHealthResponse,
    GatewayCacheInvalidateRequest,
    GatewayCacheInvalidateResponse,
    McpServerResponse,
    McpToolCallRequest,
    McpToolCallResponse,
    McpToolListRequest,
    McpToolListResponse,
    KeyCreateRequest,
    KeyGuardrailEvaluateRequest,
    KeyGuardrailEvaluateResponse,
    KeyBudgetIncreaseTemporaryRequest,
    KeyBudgetIncreaseTemporaryResponse,
    KeyLifecycleActionResponse,
    KeyRotationScheduleExecuteResponse,
    KeyRotationScheduleRequest,
    KeyRotationScheduleResponse,
    KeyRotationScheduleUpdateRequest,
    KeyResponse,
    KeyUpdateRequest,
    RouteExecuteFallbackRequest,
    RouteExecuteFallbackResponse,
    RouteOptimizeRequest,
    RouteOptimizeResponse,
    RouteProviderPriorityResponse,
    RouteProviderPriorityTimelineResponse,
    RouteProviderPriorityUpdateRequest,
    RouteProviderHealthUpdateRequest,
    RouteProviderHealthResponse,
    RoutePreCallFiltersRequest,
    RoutePreCallFiltersResponse,
    RouteFallbackPolicyRequest,
    RouteFallbackPolicyResponse,
    RouteSimulateFallbackRequest,
    RouteSimulateFallbackResponse,
    RouteTrafficMirroringRequest,
    RouteTrafficMirroringAnalyticsSummaryResponse,
    RouteTrafficMirroringExperimentReportResponse,
    RouteTrafficMirroringResponse,
    RoutePolicyRequest,
    RoutePolicyResponse,
)
from app.security import ActorContext, get_actor_context, require_dual_approval, require_role
from app.policy_constants import DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT, ROLE_AGENT_OWNER, ROLE_MASTER_ADMIN, ROLE_SUPER_ADMIN, SUPPORTED_ACTOR_ROLES
from app.services.audit import create_audit_event
from app.services.runtime_config import get_runtime_config, get_runtime_config_int, invalidate_runtime_config_cache
from app.services.mcp_gateway import call_tool as mcp_call_tool
from app.services.mcp_gateway import list_mcp_servers, list_tools as mcp_list_tools, resolve_mcp_server
from app.services.scope_registry import normalize_owner_scope, normalize_scope_reference, SUPPORTED_OWNER_SCOPE_TYPES

router = APIRouter()
logger = get_logger(__name__)

REQUEST_TAG_PATTERN = re.compile(r"^[a-zA-Z0-9._:-]{1,64}$")
ALLOWED_ROUTE_STRATEGIES = {"weighted", "lowest_cost", "lowest_latency", "adaptive", "least_busy"}
ALLOWED_GROUP_SELECTION_STRATEGIES = {"weighted_failover"}
ALLOWED_EXTERNAL_CALLBACK_EVENTS = {
    "gateway.route.execute_fallback",
    "gateway.route.simulate_fallback",
    "gateway.cache.invalidate",
    "gateway.mcp.tools.call",
    "gateway.key.rotate",
}

GATEWAY_GOVERNANCE_EVIDENCE_ACTION_TYPES = [
    "gateway.entitlement.read",
    "gateway.entitlement.update",
    "gateway.nhi.inventory.read",
    "gateway.nhi.hygiene.read",
    "gateway.access_review.campaign.create",
    "gateway.access_review.campaign.read",
    "gateway.jit.request.create",
    "gateway.jit.request.approve",
    "gateway.jit.request.deny",
    "gateway.least_privilege.read",
    "gateway.least_privilege.apply",
    "gateway.responses.create",
    "gateway.responses.retrieve",
    "gateway.responses.list",
    "gateway.responses.delete",
    "gateway.files.create",
    "gateway.files.retrieve",
    "gateway.files.list",
    "gateway.files.delete",
]

GATEWAY_INFERENCE_ROLES = set(GATEWAY_ADMIN_OR_AI_OPS_ROLES) | {ROLE_AGENT_OWNER}
GATEWAY_INFERENCE_READ_ROLES = set(GATEWAY_READ_ROLES) | {ROLE_AGENT_OWNER}
GATEWAY_INFERENCE_DELETE_ROLES = set(GATEWAY_ADMIN_ROLES) | {ROLE_AGENT_OWNER}

GATEWAY_AUTHZ_ACTION_ROLE_MAP: dict[str, set[str]] = {
    "gateway.route.read": set(GATEWAY_READ_ROLES),
    "gateway.route.update": set(GATEWAY_ADMIN_OR_AI_OPS_ROLES),
    "gateway.route.execute_fallback": set(GATEWAY_ADMIN_OR_AI_OPS_ROLES),
    "gateway.route.optimize": set(GATEWAY_ADMIN_OR_AI_OPS_ROLES),
    "gateway.key.rotate": set(GATEWAY_ADMIN_ROLES),
    "gateway.key.update": set(GATEWAY_ADMIN_ROLES),
    "gateway.callback.update": set(GATEWAY_ADMIN_ROLES),
    "gateway.cache.invalidate": set(GATEWAY_ADMIN_ROLES),
    "gateway.tool.call": set(GATEWAY_ADMIN_OR_AI_OPS_ROLES),
    "gateway.debug.transform_request": set(GATEWAY_ADMIN_OR_SECURITY_ROLES),
}

GATEWAY_AUTHZ_PROD_DUAL_APPROVAL_ACTIONS = {
    "gateway.route.update",
    "gateway.route.execute_fallback",
    "gateway.route.optimize",
    "gateway.key.rotate",
    "gateway.callback.update",
    "gateway.cache.invalidate",
    "gateway.tool.call",
}


def _validate_callback_url(raw: str) -> str:
    value = str(raw or "").strip()
    parsed = urlparse(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise HTTPException(status_code=422, detail="callback_url must be an absolute http(s) URL")
    return value


def _normalize_callback_events(raw: object) -> list[str]:
    if not isinstance(raw, list) or not raw:
        raise HTTPException(status_code=422, detail="event_types must be a non-empty list")
    normalized: list[str] = []
    for item in raw:
        event = str(item or "").strip()
        if event not in ALLOWED_EXTERNAL_CALLBACK_EVENTS:
            allowed = ", ".join(sorted(ALLOWED_EXTERNAL_CALLBACK_EVENTS))
            raise HTTPException(status_code=422, detail=f"event_types entries must be one of: {allowed}")
        if event not in normalized:
            normalized.append(event)
    return normalized


def _parse_gateway_external_callbacks(raw_value: str) -> list[dict]:
    raw = str(raw_value or "[]").strip() or "[]"
    try:
        parsed = json.loads(raw)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="gateway external callback registry is invalid JSON") from exc
    if not isinstance(parsed, list):
        raise HTTPException(status_code=500, detail="gateway external callback registry must be a list")

    normalized_rows: list[dict] = []
    for row in parsed:
        if not isinstance(row, dict):
            continue
        callback_id = str(row.get("callback_id") or "").strip()
        callback_url = str(row.get("callback_url") or "").strip()
        if not callback_id or not callback_url:
            continue
        event_types = row.get("event_types") if isinstance(row.get("event_types"), list) else []
        filtered_event_types = [
            str(event).strip()
            for event in event_types
            if str(event).strip() in ALLOWED_EXTERNAL_CALLBACK_EVENTS
        ]
        normalized_rows.append(
            {
                "callback_id": callback_id,
                "callback_url": callback_url,
                "event_types": filtered_event_types or ["gateway.route.execute_fallback"],
                "environment": str(row.get("environment") or "dev").strip().lower() or "dev",
                "redact_sensitive": bool(row.get("redact_sensitive", True)),
                "enabled": bool(row.get("enabled", True)),
                "description": str(row.get("description") or "").strip() or None,
                "created_by": str(row.get("created_by") or "system-user"),
                "created_at": str(row.get("created_at") or datetime.utcnow().isoformat() + "Z"),
                "updated_at": str(row.get("updated_at") or datetime.utcnow().isoformat() + "Z"),
            }
        )
    return normalized_rows


def _load_gateway_external_callbacks(db: Session) -> list[dict]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_EXTERNAL_CALLBACKS_JSON, "[]")
    return _parse_gateway_external_callbacks(raw)


def _save_gateway_external_callbacks(db: Session, actor_id: str, rows: list[dict]) -> None:
    row = db.query(RuntimeConfig).filter_by(config_key=RUNTIME_CONFIG_GATEWAY_EXTERNAL_CALLBACKS_JSON).first()
    serialized = json.dumps(rows, separators=(",", ":"))
    if row:
        row.config_value = serialized
        row.updated_by = actor_id
        row.updated_at = datetime.utcnow()
    else:
        db.add(
            RuntimeConfig(
                config_key=RUNTIME_CONFIG_GATEWAY_EXTERNAL_CALLBACKS_JSON,
                config_value=serialized,
                description="Gateway external callback registry",
                updated_by=actor_id,
            )
        )
    invalidate_runtime_config_cache(RUNTIME_CONFIG_GATEWAY_EXTERNAL_CALLBACKS_JSON)


def _normalize_request_tag(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if not REQUEST_TAG_PATTERN.match(raw):
        raise HTTPException(status_code=422, detail="request_tag must match ^[a-zA-Z0-9._:-]{1,64}$")
    return raw


def _resolve_provider_priority_policy(
    fallback_policy: dict,
    request_tag: str | None,
) -> tuple[dict, str | None]:
    provider_priority = fallback_policy.get("provider_priority") if isinstance(fallback_policy, dict) else None
    if not isinstance(provider_priority, dict):
        provider_priority = {}

    normalized_tag = _normalize_request_tag(request_tag)
    if not normalized_tag:
        return provider_priority, None

    tagged = fallback_policy.get("provider_priority_by_tag") if isinstance(fallback_policy, dict) else None
    if not isinstance(tagged, dict):
        return provider_priority, None

    selected = tagged.get(normalized_tag)
    if not isinstance(selected, dict):
        return provider_priority, None
    return selected, normalized_tag


def _build_provider_health_map(fallback_policy: dict, request_tag: str | None) -> dict[str, dict]:
    normalized_tag = _normalize_request_tag(request_tag)
    if normalized_tag:
        tagged = fallback_policy.get("provider_health_by_tag") if isinstance(fallback_policy, dict) else None
        if isinstance(tagged, dict):
            selected = tagged.get(normalized_tag)
            if isinstance(selected, dict):
                return {str(k): v for k, v in selected.items() if isinstance(v, dict)}

    raw = fallback_policy.get("provider_health") if isinstance(fallback_policy, dict) else None
    if not isinstance(raw, dict):
        return {}
    return {str(k): v for k, v in raw.items() if isinstance(v, dict)}


def _parse_region_list(raw: str, field_name: str) -> list[str]:
    values = _parse_string_list(raw, field_name)
    normalized: list[str] = []
    for value in values:
        region = str(value or "").strip().lower()
        if not region:
            continue
        if region not in normalized:
            normalized.append(region)
    return normalized


def _normalize_requested_region(raw: str | None) -> str | None:
    value = str(raw or "").strip().lower()
    return value or None


def _parse_traffic_mirror_targets(raw: str) -> list[dict]:
    try:
        value = json.loads(raw or "[]")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail="mirror_targets must be valid JSON") from exc

    if not isinstance(value, list):
        raise HTTPException(status_code=422, detail="mirror_targets must be a JSON array")

    normalized: list[dict] = []
    for item in value:
        if not isinstance(item, dict):
            raise HTTPException(status_code=422, detail="mirror_targets entries must be JSON objects")
        provider_id = str(item.get("provider_id") or "").strip()
        if not provider_id:
            raise HTTPException(status_code=422, detail="mirror_targets entry missing provider_id")
        sample_percent_raw = item.get("sample_percent", 100)
        if not isinstance(sample_percent_raw, int) or sample_percent_raw < 1 or sample_percent_raw > 100:
            raise HTTPException(status_code=422, detail="mirror_targets.sample_percent must be an integer in [1, 100]")
        mode = str(item.get("mode") or "shadow").strip().lower() or "shadow"
        if mode not in {"shadow", "observe"}:
            raise HTTPException(status_code=422, detail="mirror_targets.mode must be one of: shadow, observe")
        normalized.append(
            {
                "provider_id": provider_id,
                "sample_percent": sample_percent_raw,
                "mode": mode,
            }
        )

    deduped: dict[str, dict] = {}
    for row in normalized:
        deduped[str(row["provider_id"])] = row
    return [deduped[key] for key in sorted(deduped.keys())]


def _resolve_pre_call_filters_policy(fallback_policy: dict, request_tag: str | None) -> tuple[dict, str | None]:
    policy = fallback_policy.get("pre_call_filters") if isinstance(fallback_policy, dict) else None
    if not isinstance(policy, dict):
        policy = {}

    normalized_tag = _normalize_request_tag(request_tag)
    if not normalized_tag:
        return policy, None

    tagged = fallback_policy.get("pre_call_filters_by_tag") if isinstance(fallback_policy, dict) else None
    if not isinstance(tagged, dict):
        return policy, None

    selected = tagged.get(normalized_tag)
    if not isinstance(selected, dict):
        return policy, None
    return selected, normalized_tag


def _resolve_traffic_mirroring_policy(fallback_policy: dict, request_tag: str | None) -> tuple[dict, str | None]:
    policy = fallback_policy.get("traffic_mirroring") if isinstance(fallback_policy, dict) else None
    if not isinstance(policy, dict):
        policy = {}

    normalized_tag = _normalize_request_tag(request_tag)
    if not normalized_tag:
        return policy, None

    tagged = fallback_policy.get("traffic_mirroring_by_tag") if isinstance(fallback_policy, dict) else None
    if not isinstance(tagged, dict):
        return policy, None

    selected = tagged.get(normalized_tag)
    if not isinstance(selected, dict):
        return policy, None
    return selected, normalized_tag


def _build_traffic_mirroring_breakdown(rows: list[tuple[object, object]]) -> list[dict[str, object]]:
    return [
        {
            "key": str(row[0] or "unknown"),
            "events": int(row[1] or 0),
        }
        for row in rows
    ]


def _evaluate_pre_call_filter_block(
    fallback_policy: dict,
    *,
    tenant_id: str,
    request_tag: str | None,
    requested_region: str | None,
    context_window_tokens: int,
    resource: str,
) -> str | None:
    filters, _ = _resolve_pre_call_filters_policy(fallback_policy, request_tag)
    if not isinstance(filters, dict) or not filters:
        return None

    filter_tenant_id = str(filters.get("tenant_id") or "").strip()
    if filter_tenant_id:
        _require_tenant_match(filter_tenant_id, tenant_id, resource)

    if not bool(filters.get("enforce", True)):
        return None

    allowed_regions_raw = filters.get("allowed_regions")
    allowed_regions = [
        str(region or "").strip().lower()
        for region in allowed_regions_raw
        if str(region or "").strip()
    ] if isinstance(allowed_regions_raw, list) else []
    normalized_region = _normalize_requested_region(requested_region)
    if allowed_regions:
        if not normalized_region:
            return "region_required"
        if normalized_region not in allowed_regions:
            return "region_not_allowed"

    min_tokens = filters.get("min_context_window_tokens")
    if isinstance(min_tokens, int) and context_window_tokens < min_tokens:
        return "context_window_below_minimum"

    max_tokens = filters.get("max_context_window_tokens")
    if isinstance(max_tokens, int) and context_window_tokens > max_tokens:
        return "context_window_exceeds_maximum"

    return None


def _expand_wildcard_priority_order(db: Session, normalized_priority_order: list[dict]) -> list[dict]:
    expanded: list[dict] = []
    for item in normalized_priority_order:
        provider_id = str(item.get("provider_id") or "").strip()
        if not provider_id.endswith(":*"):
            expanded.append(dict(item))
            continue

        provider_type = provider_id[:-2].strip().lower()
        if not provider_type:
            expanded.append(dict(item))
            continue

        discovered_ids: list[str] = []
        workload_ids = (
            db.query(WorkloadIdentityFederationProfile.workload_identity_profile_id)
            .filter(WorkloadIdentityFederationProfile.provider_type == provider_type)
            .all()
        )
        secret_ids = (
            db.query(SecretProviderConfig.secret_provider_id)
            .filter(SecretProviderConfig.provider_type == provider_type)
            .all()
        )
        discovered_ids.extend([str(row[0]) for row in workload_ids if row and row[0]])
        discovered_ids.extend([str(row[0]) for row in secret_ids if row and row[0]])

        deduped = sorted({item_id.strip() for item_id in discovered_ids if item_id and item_id.strip()})
        if not deduped:
            expanded.append(dict(item))
            continue

        for discovered_id in deduped:
            expanded_item = dict(item)
            expanded_item["provider_id"] = discovered_id
            expanded.append(expanded_item)

    return expanded


def _normalize_route_strategy(value: str | None, field_name: str) -> str:
    normalized = str(value or "weighted").strip().lower()
    if normalized not in ALLOWED_ROUTE_STRATEGIES:
        allowed = ", ".join(sorted(ALLOWED_ROUTE_STRATEGIES))
        raise HTTPException(status_code=422, detail=f"{field_name} must be one of: {allowed}")
    return normalized


def _normalize_request_tag_list(raw: object, field_name: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
        raise HTTPException(status_code=422, detail=f"{field_name} must be a JSON array of strings")

    normalized: list[str] = []
    for item in raw:
        tag = _normalize_request_tag(item)
        if tag and tag not in normalized:
            normalized.append(tag)
    return normalized


def _normalize_routing_group(group: object, *, field_name: str) -> dict:
    if not isinstance(group, dict):
        raise HTTPException(status_code=422, detail=f"{field_name} entries must be JSON objects")

    group_id = str(group.get("group_id") or "").strip()
    if not group_id:
        raise HTTPException(status_code=422, detail=f"{field_name}.group_id is required")

    tenant_id = str(group.get("tenant_id") or "").strip()
    if not tenant_id:
        raise HTTPException(status_code=422, detail=f"{field_name}.tenant_id is required")

    priority_order_raw = group.get("priority_order")
    if not isinstance(priority_order_raw, list) or not priority_order_raw:
        raise HTTPException(status_code=422, detail=f"{field_name}.priority_order must contain at least one provider")

    failover_weight = group.get("failover_weight", 100)
    if not isinstance(failover_weight, int) or failover_weight < 1:
        raise HTTPException(status_code=422, detail=f"{field_name}.failover_weight must be an integer >= 1")

    normalized = {
        "group_id": group_id,
        "tenant_id": tenant_id,
        "selection_strategy": _normalize_route_strategy(
            str(group.get("selection_strategy") or "weighted"),
            f"{field_name}.selection_strategy",
        ),
        "priority_order": _parse_priority_order(json.dumps(priority_order_raw)),
        "failover_weight": failover_weight,
    }

    request_tags = _normalize_request_tag_list(group.get("request_tags"), f"{field_name}.request_tags")
    if request_tags:
        normalized["request_tags"] = request_tags

    for name, minimum, maximum in (("global_timeout_ms", 100, 120000), ("max_fallback_hops", 0, 10)):
        value = group.get(name)
        if value is None:
            continue
        if not isinstance(value, int) or value < minimum or value > maximum:
            raise HTTPException(status_code=422, detail=f"{field_name}.{name} must be an integer in [{minimum}, {maximum}]")
        normalized[name] = value

    for name in ("health_check_enabled",):
        value = group.get(name)
        if value is None:
            continue
        if not isinstance(value, bool):
            raise HTTPException(status_code=422, detail=f"{field_name}.{name} must be a boolean")
        normalized[name] = value

    budget_limit_cents = group.get("budget_limit_cents")
    if budget_limit_cents is not None:
        if not isinstance(budget_limit_cents, int) or budget_limit_cents < 1:
            raise HTTPException(status_code=422, detail=f"{field_name}.budget_limit_cents must be an integer >= 1")
        normalized["budget_limit_cents"] = budget_limit_cents

    return normalized


def _normalize_route_fallback_policy(policy: dict) -> dict:
    normalized = dict(policy)
    routing_groups = normalized.get("routing_groups")
    if routing_groups is None:
        return normalized
    if not isinstance(routing_groups, list) or not routing_groups:
        raise HTTPException(status_code=422, detail="fallback_policy.routing_groups must contain at least one group")

    group_selection_strategy = str(normalized.get("group_selection_strategy") or "weighted_failover").strip().lower()
    if group_selection_strategy not in ALLOWED_GROUP_SELECTION_STRATEGIES:
        allowed = ", ".join(sorted(ALLOWED_GROUP_SELECTION_STRATEGIES))
        raise HTTPException(status_code=422, detail=f"fallback_policy.group_selection_strategy must be one of: {allowed}")

    seen_group_ids: set[str] = set()
    normalized_groups: list[dict] = []
    for index, group in enumerate(routing_groups, start=1):
        normalized_group = _normalize_routing_group(group, field_name=f"fallback_policy.routing_groups[{index}]")
        group_id = normalized_group["group_id"]
        if group_id in seen_group_ids:
            raise HTTPException(status_code=422, detail="fallback_policy.routing_groups group_id values must be unique")
        seen_group_ids.add(group_id)
        normalized_groups.append(normalized_group)

    normalized["group_selection_strategy"] = group_selection_strategy
    normalized["routing_groups"] = normalized_groups
    return normalized


def _resolve_grouped_routing_configs(
    db: Session,
    fallback_policy: dict,
    *,
    tenant_id: str,
    request_tag: str | None,
    default_strategy: str,
    resource: str,
) -> list[dict]:
    routing_groups = fallback_policy.get("routing_groups") if isinstance(fallback_policy, dict) else None
    if not isinstance(routing_groups, list) or not routing_groups:
        return []

    tenant_groups = [
        group for group in routing_groups if isinstance(group, dict) and str(group.get("tenant_id") or "").strip() == tenant_id
    ]
    if not tenant_groups:
        raise HTTPException(status_code=403, detail=f"Tenant scope mismatch for {resource}")

    normalized_tag = _normalize_request_tag(request_tag)
    if normalized_tag:
        tagged_groups = [group for group in tenant_groups if normalized_tag in (group.get("request_tags") or [])]
        if tagged_groups:
            tenant_groups = tagged_groups

    provider_health = _build_provider_health_map(fallback_policy, normalized_tag)
    configs: list[dict] = []
    for group in sorted(
        tenant_groups,
        key=lambda item: (-int(item.get("failover_weight") or 100), str(item.get("group_id") or "")),
    ):
        priority_order = group.get("priority_order")
        if not isinstance(priority_order, list) or not priority_order:
            continue
        expanded_priority_order = _expand_wildcard_priority_order(db, list(priority_order))
        group_strategy = _normalize_route_strategy(
            str(group.get("selection_strategy") or default_strategy),
            f"routing group {group.get('group_id') or 'unknown'} selection_strategy",
        )
        configs.append(
            {
                "group_id": str(group.get("group_id") or "default"),
                "tenant_id": tenant_id,
                "selection_strategy": group_strategy,
                "priority_order": _sort_priority_order_by_strategy(
                    expanded_priority_order,
                    strategy=group_strategy,
                    provider_health=provider_health,
                ),
                "health_check_enabled": bool(group.get("health_check_enabled", False)),
                "global_timeout_ms": group.get("global_timeout_ms"),
                "max_fallback_hops": group.get("max_fallback_hops"),
                "budget_limit_cents": group.get("budget_limit_cents"),
                "failover_weight": int(group.get("failover_weight") or 100),
            }
        )
    return configs


def _resolve_route_provider_configs(
    db: Session,
    fallback_policy: dict,
    *,
    tenant_id: str,
    request_tag: str | None,
    default_strategy: str,
    resource: str,
) -> list[dict]:
    grouped_configs = _resolve_grouped_routing_configs(
        db,
        fallback_policy,
        tenant_id=tenant_id,
        request_tag=request_tag,
        default_strategy=default_strategy,
        resource=resource,
    )
    if grouped_configs:
        return grouped_configs

    provider_priority, _ = _resolve_provider_priority_policy(fallback_policy, request_tag)
    if not isinstance(provider_priority, dict) or not provider_priority:
        raise HTTPException(status_code=422, detail="provider priority policy is not configured for this route")

    provider_priority_tenant_id = provider_priority.get("tenant_id")
    if not isinstance(provider_priority_tenant_id, str) or not provider_priority_tenant_id.strip():
        raise HTTPException(status_code=422, detail="provider priority policy is missing tenant_id")
    _require_tenant_match(provider_priority_tenant_id.strip(), tenant_id, resource)

    priority_order_raw = provider_priority.get("priority_order")
    if not isinstance(priority_order_raw, list) or not priority_order_raw:
        raise HTTPException(status_code=422, detail="provider priority policy is missing priority_order")

    normalized_priority_order = _parse_priority_order(json.dumps(priority_order_raw))
    expanded_priority_order = _expand_wildcard_priority_order(db, normalized_priority_order)
    provider_health = _build_provider_health_map(fallback_policy, request_tag)
    strategy = _normalize_route_strategy(default_strategy, "load_balancing_strategy")
    return [
        {
            "group_id": "default",
            "tenant_id": provider_priority_tenant_id.strip(),
            "selection_strategy": strategy,
            "priority_order": _sort_priority_order_by_strategy(
                expanded_priority_order,
                strategy=strategy,
                provider_health=provider_health,
            ),
            "health_check_enabled": bool(provider_priority.get("health_check_enabled", False)),
            "global_timeout_ms": provider_priority.get("global_timeout_ms"),
            "max_fallback_hops": provider_priority.get("max_fallback_hops"),
            "budget_limit_cents": provider_priority.get("budget_limit_cents"),
            "failover_weight": 100,
        }
    ]


def _sort_priority_order_by_strategy(
    priority_order: list[dict],
    *,
    strategy: str,
    provider_health: dict[str, dict],
) -> list[dict]:
    normalized_strategy = _normalize_route_strategy(strategy, "load_balancing_strategy")
    if normalized_strategy not in {"lowest_latency", "adaptive", "least_busy"}:
        return list(priority_order)

    def _latency(item: dict) -> int:
        provider_id = str(item.get("provider_id") or "")
        health = provider_health.get(provider_id, {})
        value = health.get("latency_ms")
        return int(value) if isinstance(value, int) and value >= 0 else 10_000

    if normalized_strategy == "least_busy":
        def _least_busy(item: dict) -> tuple[int, float, int]:
            provider_id = str(item.get("provider_id") or "")
            health = provider_health.get(provider_id, {})
            inflight = health.get("inflight_requests")
            inflight_value = int(inflight) if isinstance(inflight, int) and inflight >= 0 else 10_000
            rate_remaining = health.get("rate_limit_remaining_percent")
            if isinstance(rate_remaining, (int, float)) and 0 <= float(rate_remaining) <= 100:
                rate_remaining_value = -float(rate_remaining)
            else:
                rate_remaining_value = 0.0
            return inflight_value, rate_remaining_value, _latency(item)

        return sorted(priority_order, key=_least_busy)

    return sorted(priority_order, key=_latency)


def _message_content_to_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, dict):
                text_value = item.get("text")
                if isinstance(text_value, str) and text_value.strip():
                    parts.append(text_value.strip())
        return " ".join(parts).strip()
    if value is None:
        return ""
    return str(value)


def _estimate_token_count(text: str) -> int:
    value = str(text or "").strip()
    if not value:
        return 1
    return max(1, int(len(value.split()) * 1.3))


def _split_provider_model(model: str) -> tuple[str | None, str]:
    raw = str(model or "").strip()
    if "/" not in raw:
        return None, raw
    provider, name = raw.split("/", 1)
    normalized_provider = provider.strip().lower() or None
    normalized_name = name.strip() or raw
    return normalized_provider, normalized_name


def _normalize_stop_sequences(raw: object) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        value = raw.strip()
        return [value] if value else []
    if isinstance(raw, list):
        normalized: list[str] = []
        for item in raw:
            if not isinstance(item, str):
                raise HTTPException(status_code=422, detail="stop must be a string or list of strings")
            value = item.strip()
            if value and value not in normalized:
                normalized.append(value)
        return normalized
    raise HTTPException(status_code=422, detail="stop must be a string or list of strings")


def _apply_stop_sequences(text: str, stop_sequences: list[str]) -> tuple[str, bool]:
    if not stop_sequences:
        return text, False
    earliest_index: int | None = None
    for stop in stop_sequences:
        index = text.find(stop)
        if index >= 0 and (earliest_index is None or index < earliest_index):
            earliest_index = index
    if earliest_index is None:
        return text, False
    return text[:earliest_index], True


def _responses_input_to_text(value: object) -> str:
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, dict):
        content = value.get("content") if isinstance(value, dict) else None
        if content is not None:
            return _message_content_to_text(content)
        return str(value).strip()
    if isinstance(value, list):
        parts: list[str] = []
        for item in value:
            if isinstance(item, dict):
                if "content" in item:
                    text = _message_content_to_text(item.get("content"))
                    if text:
                        parts.append(text)
            elif isinstance(item, str):
                text = item.strip()
                if text:
                    parts.append(text)
        return "\n".join(parts).strip()
    if value is None:
        return ""
    return str(value).strip()


def _resolve_responses_tool_selection(tools_raw: object, tool_choice_raw: object) -> str | None:
    tools = tools_raw if tools_raw is not None else []
    if not isinstance(tools, list):
        raise HTTPException(status_code=422, detail="tools must be a list of tool definitions")

    tool_names: list[str] = []
    for item in tools:
        if not isinstance(item, dict):
            raise HTTPException(status_code=422, detail="tools must be a list of tool definitions")
        item_type = str(item.get("type") or "function").strip().lower()
        if item_type != "function":
            raise HTTPException(status_code=422, detail="tools[].type must be function")
        item_name = str(item.get("name") or "").strip()
        function_block = item.get("function")
        if not item_name and isinstance(function_block, dict):
            item_name = str(function_block.get("name") or "").strip()
        if item_name:
            tool_names.append(item_name)

    if tools and not tool_names:
        raise HTTPException(status_code=422, detail="tools entries must include a tool/function name")

    if tool_choice_raw is None:
        return None

    if isinstance(tool_choice_raw, str):
        mode = tool_choice_raw.strip().lower()
        if mode not in {"auto", "none", "required"}:
            raise HTTPException(status_code=422, detail="tool_choice must be one of: auto, none, required")
        if mode == "none":
            return None
        if mode == "required":
            if not tool_names:
                raise HTTPException(status_code=422, detail="tool_choice=required requires at least one named tool")
            return tool_names[0]
        return None

    if isinstance(tool_choice_raw, dict):
        raw_type = str(tool_choice_raw.get("type") or "").strip().lower()
        if raw_type and raw_type != "function":
            raise HTTPException(status_code=422, detail="tool_choice.type must be function when provided")
        function_block = tool_choice_raw.get("function")
        forced_name = ""
        if isinstance(function_block, dict):
            forced_name = str(function_block.get("name") or "").strip()
        if not forced_name:
            forced_name = str(tool_choice_raw.get("name") or "").strip()
        if not forced_name:
            raise HTTPException(status_code=422, detail="tool_choice object must include function.name or name")
        if not tool_names:
            raise HTTPException(status_code=422, detail="tool_choice requires at least one named tool")
        if forced_name not in tool_names:
            raise HTTPException(status_code=422, detail="tool_choice references an unknown tool name")
        return forced_name

    raise HTTPException(status_code=422, detail="tool_choice must be a string or object")


def _serialize_openai_response_record(record: OpenAIResponseRecord) -> dict[str, object]:
    try:
        output_payload = json.loads(record.output_payload or "[]")
    except Exception:
        output_payload = []
    if not isinstance(output_payload, list):
        output_payload = []
    has_tool_calls = any(str(item.get("type") or "").strip().lower() == "tool_call" for item in output_payload if isinstance(item, dict))
    risk_tier, risk_reasons = _assess_gateway_inference_risk(
        model_name=record.model_name,
        environment=record.environment,
        has_tool_calls=has_tool_calls,
        selected_provider_id=record.selected_provider_id,
    )
    return {
        "id": record.response_id,
        "object": "response",
        "created_at": int(record.created_at.timestamp()),
        "model": record.model_name,
        "output": output_payload,
        "output_text": record.output_text,
        "usage": {
            "input_tokens": int(record.input_tokens or 0),
            "output_tokens": int(record.output_tokens or 0),
            "total_tokens": int(record.total_tokens or 0),
        },
        "request_id": record.request_id,
        "trace_id": record.trace_id,
        "risk_tier": risk_tier,
        "risk_reasons": risk_reasons,
        "selected_provider_id": record.selected_provider_id,
        "route_policy_id": record.route_policy_id,
    }


def _serialize_openai_file_record(record: OpenAIFileRecord) -> dict[str, object]:
    return {
        "id": record.file_id,
        "object": "file",
        "filename": record.filename,
        "purpose": record.purpose,
        "bytes": int(record.bytes or 0),
        "content_type": record.content_type,
        "status": record.status,
        "created_at": int(record.created_at.timestamp()),
        "request_id": record.request_id,
        "trace_id": record.trace_id,
    }


def _is_prod_environment(value: str) -> bool:
    return value.strip().lower() == "prod"


def _assess_gateway_inference_risk(
    model_name: str,
    environment: str,
    has_tool_calls: bool,
    selected_provider_id: Optional[str],
) -> tuple[str, list[str]]:
    score = 0
    reasons: list[str] = []
    normalized_model = str(model_name or "").strip().lower()

    if _is_prod_environment(environment):
        score += 2
        reasons.append("production_environment")

    if has_tool_calls:
        score += 2
        reasons.append("tool_call_execution_path")

    if str(selected_provider_id or "").strip():
        score += 1
        reasons.append("provider_routed")

    if "/" in normalized_model:
        score += 1
        reasons.append("provider_prefixed_model")

    if normalized_model.startswith(("gpt-4", "claude", "gemini-", "o1", "o3")):
        score += 1
        reasons.append("frontier_model_family")

    if score >= 4:
        risk_tier = "high"
    elif score >= 2:
        risk_tier = "medium"
    else:
        risk_tier = "low"

    if not reasons:
        reasons.append("baseline_policy_controls")

    return risk_tier, reasons


def _parse_json_object(raw: str, field_name: str) -> dict:
    try:
        value = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"{field_name} must be valid JSON") from exc
    if not isinstance(value, dict):
        raise HTTPException(status_code=422, detail=f"{field_name} must be a JSON object")
    return value


def _parse_json_object_legacy_compatible(raw: str, field_name: str) -> dict:
    # Backward compatibility: older clients may send plain policy labels like
    # "secondary" or "2s" instead of JSON objects.
    text = str(raw or "").strip()
    if not text:
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {"value": text}

    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        return {"value": value.strip()}
    raise HTTPException(status_code=422, detail=f"{field_name} must be a JSON object")


def _parse_json_array(raw: str, field_name: str) -> list:
    try:
        value = json.loads(raw or "[]")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"{field_name} must be valid JSON") from exc
    if not isinstance(value, list):
        raise HTTPException(status_code=422, detail=f"{field_name} must be a JSON array")
    return value


def _parse_priority_order(raw: str) -> list[dict]:
    try:
        value = json.loads(raw or "[]")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail="priority_order must be valid JSON") from exc

    if not isinstance(value, list):
        raise HTTPException(status_code=422, detail="priority_order must be a JSON array")
    if not value:
        raise HTTPException(status_code=422, detail="priority_order must include at least one provider")

    normalized: list[dict] = []
    priorities: list[int] = []

    for item in value:
        if not isinstance(item, dict):
            raise HTTPException(status_code=422, detail="priority_order entries must be JSON objects")
        provider_id = str(item.get("provider_id", "")).strip()
        if not provider_id:
            raise HTTPException(status_code=422, detail="priority_order entry missing provider_id")

        model_name_raw = item.get("model_name")
        model_name = None
        if model_name_raw is not None:
            model_name = str(model_name_raw).strip()
            if not model_name:
                raise HTTPException(status_code=422, detail="priority_order entry model_name must be non-empty when provided")

        priority_raw = item.get("priority")
        if not isinstance(priority_raw, int) or priority_raw < 1:
            raise HTTPException(status_code=422, detail="priority_order entry priority must be an integer >= 1")

        priorities.append(priority_raw)
        normalized_item = {"provider_id": provider_id, "priority": priority_raw}
        if model_name:
            normalized_item["model_name"] = model_name
        normalized.append(normalized_item)

    if len(set(priorities)) != len(priorities):
        raise HTTPException(status_code=422, detail="priority_order priorities must be unique")

    expected = list(range(1, len(priorities) + 1))
    if sorted(priorities) != expected:
        raise HTTPException(status_code=422, detail="priority_order priorities must be contiguous starting from 1")

    return sorted(normalized, key=lambda row: row["priority"])


def _parse_string_list(raw: str, field_name: str) -> list[str]:
    try:
        value = json.loads(raw or "[]")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail=f"{field_name} must be valid JSON") from exc

    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise HTTPException(status_code=422, detail=f"{field_name} must be a JSON array of strings")

    return [item.strip() for item in value if item.strip()]


def _parse_entitlement_allowed_roles(raw: str) -> list[str]:
    roles = _parse_string_list(raw, "allowed_roles")
    if not roles:
        raise HTTPException(status_code=422, detail="allowed_roles must contain at least one role")

    deduped_sorted = sorted({role for role in roles})
    unsupported = [role for role in deduped_sorted if role not in SUPPORTED_ACTOR_ROLES]
    if unsupported:
        raise HTTPException(
            status_code=422,
            detail=f"allowed_roles contains unsupported roles: {', '.join(unsupported)}",
        )
    return deduped_sorted


def _days_since(value: Optional[datetime], now: datetime) -> Optional[int]:
    if value is None:
        return None
    return max(0, int((now - value).total_seconds() // 86400))


def _build_nhi_findings(
    *,
    owner_scope_id: Optional[str],
    status: str,
    credential_last_rotated_at: Optional[datetime],
    max_credential_age_days: int,
    now: datetime,
) -> list[str]:
    findings: list[str] = []
    if not owner_scope_id:
        findings.append("missing_owner")

    if str(status or "").strip().lower() != "active":
        findings.append("inactive_identity")

    age_days = _days_since(credential_last_rotated_at, now)
    if age_days is None or age_days > max_credential_age_days:
        findings.append("stale_credential")

    if "missing_owner" in findings and "stale_credential" in findings:
        findings.append("high_risk")
    return findings


def _upsert_gateway_nhi_record(
    *,
    db: Session,
    source_type: str,
    source_id: str,
    identity_type: str,
    tenant_id: str,
    environment: str,
    provider_type: str,
    credential_last_rotated_at: Optional[datetime],
    credential_expires_at: Optional[datetime],
    last_used_at: Optional[datetime],
    status: str,
    max_credential_age_days: int,
) -> GatewayNhiInventory:
    row = db.query(GatewayNhiInventory).filter_by(source_type=source_type, source_id=source_id).first()
    if row is None:
        row = GatewayNhiInventory(nhi_record_id=f"nhi-{uuid4().hex[:16]}", source_type=source_type, source_id=source_id)
        db.add(row)

    row.identity_type = str(identity_type or "service_identity").strip().lower() or "service_identity"
    row.tenant_id = str(tenant_id or "").strip() or "unknown"
    row.environment = str(environment or "dev").strip().lower() or "dev"
    row.provider_type = str(provider_type or "unknown").strip().lower() or "unknown"
    row.credential_last_rotated_at = credential_last_rotated_at
    row.credential_expires_at = credential_expires_at
    row.last_used_at = last_used_at
    row.status = str(status or "active").strip().lower() or "active"

    findings = _build_nhi_findings(
        owner_scope_id=row.owner_scope_id,
        status=row.status,
        credential_last_rotated_at=row.credential_last_rotated_at,
        max_credential_age_days=max_credential_age_days,
        now=datetime.utcnow(),
    )
    row.findings = json.dumps(findings, separators=(",", ":"))
    return row


def _sync_gateway_nhi_inventory(db: Session, max_credential_age_days: int) -> None:
    workload_profiles = db.query(WorkloadIdentityFederationProfile).all()
    for profile in workload_profiles:
        _upsert_gateway_nhi_record(
            db=db,
            source_type="workload_identity_profile",
            source_id=profile.workload_identity_profile_id,
            identity_type="workload_identity",
            tenant_id=profile.tenant_id,
            environment="prod" if "prod" in str(profile.tenant_id).lower() else "dev",
            provider_type=profile.provider_type,
            credential_last_rotated_at=profile.last_token_exchange_at,
            credential_expires_at=None,
            last_used_at=profile.last_token_exchange_at,
            status=profile.status,
            max_credential_age_days=max_credential_age_days,
        )

    provider_configs = db.query(SecretProviderConfig).all()
    for provider in provider_configs:
        _upsert_gateway_nhi_record(
            db=db,
            source_type="secret_provider",
            source_id=provider.secret_provider_id,
            identity_type="secret_provider",
            tenant_id=provider.tenant_id,
            environment="prod" if "prod" in str(provider.tenant_id).lower() else "dev",
            provider_type=provider.provider_type,
            credential_last_rotated_at=provider.last_health_check_at,
            credential_expires_at=None,
            last_used_at=provider.last_health_check_at,
            status=provider.status,
            max_credential_age_days=max_credential_age_days,
        )


def _gateway_nhi_record_to_response(
    row: GatewayNhiInventory,
    *,
    max_credential_age_days: int,
    now: datetime,
) -> GatewayNhiInventoryRecordResponse:
    age_days = _days_since(row.credential_last_rotated_at, now)
    missing_owner = not bool(str(row.owner_scope_id or "").strip())
    stale_credential = age_days is None or age_days > max_credential_age_days
    findings = [item for item in _parse_string_list(row.findings, "findings")]
    if stale_credential and "stale_credential" not in findings:
        findings.append("stale_credential")
    if missing_owner and "missing_owner" not in findings:
        findings.append("missing_owner")
    return GatewayNhiInventoryRecordResponse(
        nhi_record_id=row.nhi_record_id,
        source_type=row.source_type,
        source_id=row.source_id,
        identity_type=row.identity_type,
        tenant_id=row.tenant_id,
        environment=row.environment,
        provider_type=row.provider_type,
        owner_scope_type=row.owner_scope_type,
        owner_scope_id=row.owner_scope_id,
        credential_last_rotated_at=row.credential_last_rotated_at,
        credential_expires_at=row.credential_expires_at,
        last_used_at=row.last_used_at,
        findings=json.dumps(sorted(set(findings)), separators=(",", ":")),
        status=row.status,
        stale_credential=stale_credential,
        missing_owner=missing_owner,
        credential_age_days=age_days,
    )


def _campaign_item_response(item: GatewayAccessReviewItem) -> GatewayAccessReviewItemResponse:
    return GatewayAccessReviewItemResponse(
        review_item_id=item.review_item_id,
        campaign_id=item.campaign_id,
        entitlement_id=item.entitlement_id,
        decision=item.decision,
        decision_reason=item.decision_reason,
        decided_by=item.decided_by,
        decided_at=item.decided_at,
        created_at=item.created_at,
    )


def _build_campaign_response(db: Session, campaign: GatewayAccessReviewCampaign) -> GatewayAccessReviewCampaignResponse:
    items = db.query(GatewayAccessReviewItem).filter_by(campaign_id=campaign.campaign_id).all()
    pending_items = sum(1 for row in items if row.decision == "pending")
    approved_items = sum(1 for row in items if row.decision == "approved")
    revoked_items = sum(1 for row in items if row.decision == "revoked")
    return GatewayAccessReviewCampaignResponse(
        campaign_id=campaign.campaign_id,
        campaign_name=campaign.campaign_name,
        tenant_id=campaign.tenant_id,
        environment=campaign.environment,
        include_disabled=campaign.include_disabled,
        status=campaign.status,
        reviewer_role=campaign.reviewer_role,
        created_by=campaign.created_by,
        created_at=campaign.created_at,
        closed_at=campaign.closed_at,
        total_items=len(items),
        pending_items=pending_items,
        approved_items=approved_items,
        revoked_items=revoked_items,
        items=[_campaign_item_response(item) for item in items],
    )


def _upsert_pending_lpr(
    db: Session,
    *,
    entitlement: GatewayEntitlement,
    recommendation_type: str,
    rationale: str,
    confidence_score: float,
    current_allowed_roles: list[str],
    proposed_allowed_roles: list[str],
    proposed_enabled: Optional[bool],
) -> GatewayLeastPrivilegeRecommendation:
    row = (
        db.query(GatewayLeastPrivilegeRecommendation)
        .filter_by(
            entitlement_id=entitlement.entitlement_id,
            recommendation_type=recommendation_type,
            status="pending",
        )
        .first()
    )
    if row is None:
        row = GatewayLeastPrivilegeRecommendation(
            recommendation_id=f"glpr-{uuid4().hex[:16]}",
            entitlement_id=entitlement.entitlement_id,
            recommendation_type=recommendation_type,
            created_by="system",
            status="pending",
        )
        db.add(row)

    row.tenant_id = entitlement.tenant_id
    row.environment = entitlement.environment
    row.rationale = rationale
    row.confidence_score = float(max(0.0, min(1.0, confidence_score)))
    row.current_allowed_roles = json.dumps(sorted(set(current_allowed_roles)), separators=(",", ":"))
    row.proposed_allowed_roles = json.dumps(sorted(set(proposed_allowed_roles)), separators=(",", ":"))
    row.proposed_enabled = proposed_enabled
    return row


def _refresh_least_privilege_recommendations(db: Session) -> None:
    entitlements = db.query(GatewayEntitlement).all()
    for entitlement in entitlements:
        current_roles = _parse_entitlement_allowed_roles(entitlement.allowed_roles)
        jit_rows = (
            db.query(GatewayJitAccessRequest)
            .filter_by(entitlement_id=entitlement.entitlement_id, status="approved")
            .all()
        )
        observed_roles = sorted({str(row.requester_role or "").strip() for row in jit_rows if str(row.requester_role or "").strip()})

        if observed_roles:
            proposed_roles = [role for role in current_roles if role in set(observed_roles)]
            if proposed_roles and set(proposed_roles) != set(current_roles):
                _upsert_pending_lpr(
                    db,
                    entitlement=entitlement,
                    recommendation_type="role_rightsize_observed",
                    rationale="Approved JIT activity indicates a narrower role set can operate this entitlement.",
                    confidence_score=0.85,
                    current_allowed_roles=current_roles,
                    proposed_allowed_roles=proposed_roles,
                    proposed_enabled=True,
                )

        if entitlement.enabled and not jit_rows:
            _upsert_pending_lpr(
                db,
                entitlement=entitlement,
                recommendation_type="disable_unused_entitlement",
                rationale="No approved JIT usage observed for this entitlement; disable until operationally required.",
                confidence_score=0.62,
                current_allowed_roles=current_roles,
                proposed_allowed_roles=current_roles,
                proposed_enabled=False,
            )


def _parse_retry_error_policies(retry_policy_raw: str) -> dict[str, dict[str, int]]:
    try:
        retry_policy = _parse_json_object(retry_policy_raw, "retry_policy")
    except HTTPException:
        return {}

    raw_controls = retry_policy.get("error_type_policies")
    if not isinstance(raw_controls, dict):
        return {}

    normalized: dict[str, dict[str, int]] = {}
    for error_type, control in raw_controls.items():
        normalized_error_type = str(error_type or "").strip().lower()
        if not normalized_error_type or not isinstance(control, dict):
            continue

        max_retries = control.get("max_retries")
        if isinstance(max_retries, bool):
            max_retries = None
        if isinstance(max_retries, int) and max_retries >= 0:
            normalized_max_retries = max_retries
        else:
            normalized_max_retries = None

        cooldown_seconds = control.get("cooldown_seconds")
        if isinstance(cooldown_seconds, bool):
            cooldown_seconds = None
        if isinstance(cooldown_seconds, int) and cooldown_seconds >= 0:
            normalized_cooldown_seconds = cooldown_seconds
        else:
            normalized_cooldown_seconds = 0

        normalized[normalized_error_type] = {
            "cooldown_seconds": normalized_cooldown_seconds,
        }
        if normalized_max_retries is not None:
            normalized[normalized_error_type]["max_retries"] = normalized_max_retries

    return normalized


def _load_retry_cooldown_registry(fallback_policy: dict) -> dict[str, dict[str, datetime]]:
    raw_registry = fallback_policy.get("retry_cooldowns") if isinstance(fallback_policy, dict) else None
    if not isinstance(raw_registry, dict):
        return {}

    parsed_registry: dict[str, dict[str, datetime]] = {}
    for provider_id, error_map in raw_registry.items():
        provider_key = str(provider_id or "").strip()
        if not provider_key or not isinstance(error_map, dict):
            continue

        parsed_error_map: dict[str, datetime] = {}
        for error_type, until_raw in error_map.items():
            normalized_error_type = str(error_type or "").strip().lower()
            if not normalized_error_type:
                continue
            until_text = str(until_raw or "").strip()
            if not until_text:
                continue
            normalized_until_text = until_text.replace("Z", "+00:00")
            try:
                until_dt = datetime.fromisoformat(normalized_until_text)
                if until_dt.tzinfo is not None:
                    until_dt = until_dt.astimezone(timezone.utc).replace(tzinfo=None)
            except ValueError:
                continue
            parsed_error_map[normalized_error_type] = until_dt

        if parsed_error_map:
            parsed_registry[provider_key] = parsed_error_map

    return parsed_registry


def _serialize_retry_cooldown_registry(cooldown_registry: dict[str, dict[str, datetime]]) -> dict[str, dict[str, str]]:
    serialized: dict[str, dict[str, str]] = {}
    for provider_id, error_map in cooldown_registry.items():
        provider_key = str(provider_id or "").strip()
        if not provider_key or not isinstance(error_map, dict):
            continue
        serialized_map: dict[str, str] = {}
        for error_type, until_dt in error_map.items():
            normalized_error_type = str(error_type or "").strip().lower()
            if not normalized_error_type or not isinstance(until_dt, datetime):
                continue
            serialized_map[normalized_error_type] = until_dt.isoformat() + "Z"
        if serialized_map:
            serialized[provider_key] = serialized_map
    return serialized


def _active_cooldown_error_type(
    provider_id: str,
    *,
    now: datetime,
    retry_error_policies: dict[str, dict[str, int]],
    cooldown_registry: dict[str, dict[str, datetime]],
) -> str | None:
    provider_map = cooldown_registry.get(provider_id) or {}
    if not provider_map:
        return None
    for error_type in retry_error_policies.keys():
        until_dt = provider_map.get(error_type)
        if isinstance(until_dt, datetime) and until_dt > now:
            return error_type
    return None


def _apply_retry_policy_on_error(
    provider_id: str,
    *,
    error_type: str,
    now: datetime,
    retry_error_policies: dict[str, dict[str, int]],
    cooldown_registry: dict[str, dict[str, datetime]],
    per_request_error_counts: dict[str, int],
) -> tuple[bool, str | None]:
    normalized_error_type = str(error_type or "").strip().lower()
    policy = retry_error_policies.get(normalized_error_type)
    if not policy:
        return True, None

    cooldown_seconds = policy.get("cooldown_seconds")
    if isinstance(cooldown_seconds, int) and cooldown_seconds > 0:
        provider_map = cooldown_registry.get(provider_id)
        if not isinstance(provider_map, dict):
            provider_map = {}
            cooldown_registry[provider_id] = provider_map
        provider_map[normalized_error_type] = now + timedelta(seconds=cooldown_seconds)

    max_retries = policy.get("max_retries")
    if isinstance(max_retries, int):
        current_count = per_request_error_counts.get(normalized_error_type, 0) + 1
        per_request_error_counts[normalized_error_type] = current_count
        if current_count > max_retries:
            return False, normalized_error_type

    return True, None


def _parse_guardrail_policy(raw: str) -> dict:
    policy = _parse_json_object(raw, "guardrail_policy")

    normalized: dict[str, object] = {}

    def _read_optional_int(name: str, minimum: int, maximum: int) -> None:
        if name not in policy:
            return
        value = policy.get(name)
        if not isinstance(value, int) or isinstance(value, bool) or value < minimum or value > maximum:
            raise HTTPException(status_code=422, detail=f"guardrail_policy.{name} must be an integer in [{minimum}, {maximum}]")
        normalized[name] = value

    _read_optional_int("max_requests_per_minute", 1, 100000)
    _read_optional_int("max_input_tokens", 1, 1000000)
    _read_optional_int("max_output_tokens", 1, 1000000)

    if "deny_on_weekends" in policy:
        value = policy.get("deny_on_weekends")
        if not isinstance(value, bool):
            raise HTTPException(status_code=422, detail="guardrail_policy.deny_on_weekends must be a boolean")
        normalized["deny_on_weekends"] = value

    if "require_mfa_for_prod" in policy:
        value = policy.get("require_mfa_for_prod")
        if not isinstance(value, bool):
            raise HTTPException(status_code=422, detail="guardrail_policy.require_mfa_for_prod must be a boolean")
        normalized["require_mfa_for_prod"] = value

    if "allowed_environments" in policy:
        allowed = policy.get("allowed_environments")
        if not isinstance(allowed, list) or any(not isinstance(item, str) for item in allowed):
            raise HTTPException(status_code=422, detail="guardrail_policy.allowed_environments must be a JSON array of strings")
        normalized_environments = sorted({item.strip().lower() for item in allowed if item.strip()})
        if not normalized_environments:
            raise HTTPException(status_code=422, detail="guardrail_policy.allowed_environments cannot be empty when provided")
        normalized["allowed_environments"] = normalized_environments

    if "blocked_owner_scope_ids" in policy:
        blocked = policy.get("blocked_owner_scope_ids")
        if not isinstance(blocked, list) or any(not isinstance(item, str) for item in blocked):
            raise HTTPException(status_code=422, detail="guardrail_policy.blocked_owner_scope_ids must be a JSON array of strings")
        normalized_blocked = sorted({item.strip() for item in blocked if item.strip()})
        normalized["blocked_owner_scope_ids"] = normalized_blocked

    if "temporary_budget_increase" in policy:
        value = policy.get("temporary_budget_increase")
        if not isinstance(value, dict):
            raise HTTPException(status_code=422, detail="guardrail_policy.temporary_budget_increase must be a JSON object")
        normalized["temporary_budget_increase"] = value

    if "rotation_schedules" in policy:
        value = policy.get("rotation_schedules")
        if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
            raise HTTPException(status_code=422, detail="guardrail_policy.rotation_schedules must be a JSON array of objects")
        normalized["rotation_schedules"] = value

    unsupported_keys = sorted(set(policy.keys()) - set(normalized.keys()))
    if unsupported_keys:
        raise HTTPException(status_code=422, detail=f"guardrail_policy contains unsupported keys: {', '.join(unsupported_keys)}")

    return normalized


def _guardrail_decision(
    key: VirtualKey,
    policy: dict,
    payload: KeyGuardrailEvaluateRequest,
) -> tuple[str, list[str], list[str]]:
    reasons: list[str] = []
    applied: list[str] = []

    environment = str(payload.environment or "dev").strip().lower()
    owner_scope_id = str(payload.owner_scope_id or key.owner_scope_id or "").strip()

    allowed_environments = policy.get("allowed_environments")
    if isinstance(allowed_environments, list):
        applied.append("allowed_environments")
        if environment not in allowed_environments:
            reasons.append(f"environment '{environment}' is not allowed")

    blocked_owner_scope_ids = policy.get("blocked_owner_scope_ids")
    if isinstance(blocked_owner_scope_ids, list):
        applied.append("blocked_owner_scope_ids")
        if owner_scope_id and owner_scope_id in blocked_owner_scope_ids:
            reasons.append(f"owner scope '{owner_scope_id}' is blocked")

    max_requests_per_minute = policy.get("max_requests_per_minute")
    if isinstance(max_requests_per_minute, int):
        applied.append("max_requests_per_minute")
        if payload.requests_last_minute > max_requests_per_minute:
            reasons.append(
                f"requests_last_minute {payload.requests_last_minute} exceeds {max_requests_per_minute}"
            )

    max_input_tokens = policy.get("max_input_tokens")
    if isinstance(max_input_tokens, int):
        applied.append("max_input_tokens")
        if payload.input_tokens > max_input_tokens:
            reasons.append(f"input_tokens {payload.input_tokens} exceeds {max_input_tokens}")

    max_output_tokens = policy.get("max_output_tokens")
    if isinstance(max_output_tokens, int):
        applied.append("max_output_tokens")
        if payload.output_tokens > max_output_tokens:
            reasons.append(f"output_tokens {payload.output_tokens} exceeds {max_output_tokens}")

    require_mfa_for_prod = bool(policy.get("require_mfa_for_prod", False))
    if require_mfa_for_prod:
        applied.append("require_mfa_for_prod")
        if environment == "prod" and not payload.mfa_verified:
            reasons.append("mfa must be verified for prod usage")

    deny_on_weekends = bool(policy.get("deny_on_weekends", False))
    if deny_on_weekends:
        applied.append("deny_on_weekends")
        if datetime.utcnow().weekday() >= 5:
            reasons.append("weekend traffic is blocked by policy")

    return ("allow" if not reasons else "deny", reasons, applied)


def _load_key_policy_state(key: VirtualKey) -> dict:
    raw = str(key.guardrail_policy or "{}").strip()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _save_key_policy_state(key: VirtualKey, policy_state: dict) -> None:
    key.guardrail_policy = json.dumps(policy_state, separators=(",", ":"), sort_keys=True)


def _parse_iso_utc_timestamp(raw: object) -> datetime | None:
    text = str(raw or "").strip()
    if not text:
        return None
    normalized = text.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _normalize_rotation_schedule_entry(entry: object) -> dict | None:
    if not isinstance(entry, dict):
        return None

    schedule_id = str(entry.get("schedule_id") or "").strip()
    if not schedule_id:
        return None

    environment = str(entry.get("environment") or "dev").strip().lower() or "dev"
    interval_hours = entry.get("interval_hours")
    if not isinstance(interval_hours, int) or interval_hours < 1:
        interval_hours = 24

    enabled = bool(entry.get("enabled", True))
    reason = str(entry.get("reason") or "scheduled-rotation").strip() or "scheduled-rotation"
    created_by = str(entry.get("created_by") or "system-user").strip() or "system-user"

    created_at_dt = _parse_iso_utc_timestamp(entry.get("created_at")) or datetime.utcnow()
    updated_at_dt = _parse_iso_utc_timestamp(entry.get("updated_at")) or created_at_dt
    last_run_at_dt = _parse_iso_utc_timestamp(entry.get("last_run_at"))
    next_run_at_dt = _parse_iso_utc_timestamp(entry.get("next_run_at"))
    if next_run_at_dt is None:
        anchor = last_run_at_dt or updated_at_dt
        next_run_at_dt = anchor + timedelta(hours=interval_hours)

    normalized = {
        "schedule_id": schedule_id,
        "environment": environment,
        "interval_hours": interval_hours,
        "enabled": enabled,
        "reason": reason,
        "created_by": created_by,
        "created_at": created_at_dt.isoformat() + "Z",
        "updated_at": updated_at_dt.isoformat() + "Z",
        "next_run_at": next_run_at_dt.isoformat() + "Z",
    }
    if last_run_at_dt is not None:
        normalized["last_run_at"] = last_run_at_dt.isoformat() + "Z"
    return normalized


def _get_rotation_schedules(policy_state: dict) -> list[dict]:
    raw = policy_state.get("rotation_schedules") if isinstance(policy_state, dict) else None
    if not isinstance(raw, list):
        return []
    schedules: list[dict] = []
    seen_ids: set[str] = set()
    for item in raw:
        normalized = _normalize_rotation_schedule_entry(item)
        if not normalized:
            continue
        schedule_id = normalized["schedule_id"]
        if schedule_id in seen_ids:
            continue
        seen_ids.add(schedule_id)
        schedules.append(normalized)
    return sorted(schedules, key=lambda row: row.get("created_at", ""), reverse=True)


def _require_tenant_match(expected_tenant_id: str, provided_tenant_id: str, resource: str) -> None:
    if expected_tenant_id != provided_tenant_id:
        raise HTTPException(
            status_code=403,
            detail=f"Tenant scope mismatch for {resource}",
        )


def _parse_runtime_json_object(raw: str, fallback: dict) -> dict:
    try:
        parsed = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return dict(fallback)
    if not isinstance(parsed, dict):
        return dict(fallback)
    return parsed


def _parse_non_negative_float(value: object, fallback: float) -> float:
    try:
        parsed = float(value)
        return parsed if parsed >= 0 else fallback
    except (TypeError, ValueError):
        return fallback


def _parse_positive_float(value: object, fallback: float) -> float:
    try:
        parsed = float(value)
        return parsed if parsed > 0 else fallback
    except (TypeError, ValueError):
        return fallback


def _resolve_provider_type(db: Session, provider_id: str) -> str:
    provider = (
        db.query(WorkloadIdentityFederationProfile)
        .filter_by(workload_identity_profile_id=provider_id)
        .first()
    )
    if provider and str(provider.provider_type or "").strip():
        return str(provider.provider_type).strip().lower()

    secret_provider = db.query(SecretProviderConfig).filter_by(secret_provider_id=provider_id).first()
    if secret_provider and str(secret_provider.provider_type or "").strip():
        return str(secret_provider.provider_type).strip().lower()

    return "unknown"


def _require_tenant_model_entitlement(
    db: Session,
    *,
    tenant_id: str,
    provider_type: str,
    model_name: str,
) -> None:
    normalized_tenant_id = str(tenant_id or "").strip()
    normalized_provider_type = str(provider_type or "").strip().lower()
    normalized_model_name = str(model_name or "").strip()

    if not normalized_tenant_id or not normalized_provider_type or not normalized_model_name:
        raise HTTPException(status_code=422, detail="tenant, provider type, and model name are required for entitlement validation")

    supported = (
        db.query(SupportedModelCatalogEntry)
        .filter(
            SupportedModelCatalogEntry.provider_type == normalized_provider_type,
            SupportedModelCatalogEntry.model_name == normalized_model_name,
            SupportedModelCatalogEntry.status.in_(["active", "beta"]),
        )
        .first()
    )
    if not supported:
        raise HTTPException(status_code=403, detail="Model is not supported for provider")

    entitlement = (
        db.query(TenantSupportedModelEntitlement)
        .filter(
            and_(
                TenantSupportedModelEntitlement.tenant_id == normalized_tenant_id,
                TenantSupportedModelEntitlement.provider_type == normalized_provider_type,
                TenantSupportedModelEntitlement.model_name == normalized_model_name,
                TenantSupportedModelEntitlement.status == "active",
            )
        )
        .first()
    )
    if not entitlement:
        raise HTTPException(status_code=403, detail="Model is not entitled for tenant")


def _load_model_token_rates(db: Session) -> tuple[dict[str, dict[str, float]], dict[str, float]]:
    fallback_raw = '{"default":{"input_cents_per_1k":1.0,"output_cents_per_1k":2.0}}'
    raw = get_runtime_config(db, RUNTIME_CONFIG_COST_MODEL_TOKEN_RATES_JSON, fallback_raw)
    parsed = _parse_runtime_json_object(raw, {"default": {"input_cents_per_1k": 1.0, "output_cents_per_1k": 2.0}})

    default_block = parsed.get("default") if isinstance(parsed.get("default"), dict) else {}
    default_rates = {
        "input_cents_per_1k": _parse_non_negative_float(default_block.get("input_cents_per_1k"), 1.0),
        "output_cents_per_1k": _parse_non_negative_float(default_block.get("output_cents_per_1k"), 2.0),
    }

    model_blocks = parsed.get("models") if isinstance(parsed.get("models"), dict) else {}
    if not model_blocks:
        model_blocks = {
            key: value
            for key, value in parsed.items()
            if key not in {"default", "models"} and isinstance(value, dict)
        }

    normalized: dict[str, dict[str, float]] = {}
    for model_name, rate_block in model_blocks.items():
        key = str(model_name or "").strip().lower()
        if not key or not isinstance(rate_block, dict):
            continue
        normalized[key] = {
            "input_cents_per_1k": _parse_non_negative_float(
                rate_block.get("input_cents_per_1k"),
                default_rates["input_cents_per_1k"],
            ),
            "output_cents_per_1k": _parse_non_negative_float(
                rate_block.get("output_cents_per_1k"),
                default_rates["output_cents_per_1k"],
            ),
        }
    return normalized, default_rates


def _load_cloud_component_multipliers(db: Session) -> tuple[dict[str, float], dict[str, float]]:
    fallback_raw = '{"provider_type":{"aws":1.0,"azure":1.0,"gcp":1.0,"openai":1.0,"anthropic":1.0},"endpoint_family":{"responses":1.0}}'
    raw = get_runtime_config(db, RUNTIME_CONFIG_COST_CLOUD_COMPONENT_MULTIPLIERS_JSON, fallback_raw)
    parsed = _parse_runtime_json_object(raw, {"provider_type": {}, "endpoint_family": {}})

    provider_map: dict[str, float] = {}
    endpoint_map: dict[str, float] = {}

    provider_raw = parsed.get("provider_type") if isinstance(parsed.get("provider_type"), dict) else {}
    endpoint_raw = parsed.get("endpoint_family") if isinstance(parsed.get("endpoint_family"), dict) else {}

    for key, value in provider_raw.items():
        provider_map[str(key or "").strip().lower()] = _parse_positive_float(value, 1.0)
    for key, value in endpoint_raw.items():
        endpoint_map[str(key or "").strip().lower()] = _parse_positive_float(value, 1.0)

    return provider_map, endpoint_map


def _estimate_hop_cost_cents(
    *,
    input_tokens: int,
    output_tokens: int,
    model_name: str,
    provider_type: str,
    endpoint_family: str,
    model_rates: dict[str, dict[str, float]],
    default_model_rates: dict[str, float],
    provider_multipliers: dict[str, float],
    endpoint_multipliers: dict[str, float],
) -> int:
    normalized_model = str(model_name or "").strip().lower()
    normalized_provider_type = str(provider_type or "").strip().lower()
    normalized_endpoint_family = str(endpoint_family or "").strip().lower()

    rates = model_rates.get(normalized_model, default_model_rates)
    input_rate = _parse_non_negative_float(rates.get("input_cents_per_1k"), default_model_rates["input_cents_per_1k"])
    output_rate = _parse_non_negative_float(rates.get("output_cents_per_1k"), default_model_rates["output_cents_per_1k"])
    provider_multiplier = _parse_positive_float(provider_multipliers.get(normalized_provider_type, 1.0), 1.0)
    endpoint_multiplier = _parse_positive_float(endpoint_multipliers.get(normalized_endpoint_family, 1.0), 1.0)

    base_cost = ((max(0, input_tokens) / 1000.0) * input_rate) + ((max(0, output_tokens) / 1000.0) * output_rate)
    estimated = base_cost * provider_multiplier * endpoint_multiplier
    if estimated <= 0:
        return 0
    return max(1, int(round(estimated)))


@router.post("/keys", response_model=KeyResponse)
def create_key(
    payload: KeyCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_ROLES)
    _parse_string_list(payload.allowed_endpoint_families, "allowed_endpoint_families")
    _parse_string_list(payload.allowed_models, "allowed_models")
    normalized_guardrail_policy = _parse_guardrail_policy(payload.guardrail_policy)
    owner_scope_type, owner_scope_id = normalize_scope_reference(
        db,
        scope_type=payload.owner_scope_type,
        scope_id=payload.owner_scope_id,
        allowed_scope_types=SUPPORTED_OWNER_SCOPE_TYPES,
        resource_label="key owner scope",
    )
    key_id = f"z{int(datetime.utcnow().timestamp() * 1000):013d}-{uuid4()}"
    key = VirtualKey(
        key_id=key_id,
        key_hash=str(uuid4()),
        owner_scope_type=owner_scope_type,
        owner_scope_id=owner_scope_id,
        allowed_endpoint_families=payload.allowed_endpoint_families,
        allowed_models=payload.allowed_models,
        guardrail_policy=json.dumps(normalized_guardrail_policy, separators=(",", ":"), sort_keys=True),
        status="active",
    )
    db.add(key)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.key.create",
        resource_type="virtual_key",
        resource_id=key.key_id,
        trace_id=f"trace-{key.key_id}",
    )
    db.commit()
    db.refresh(key)
    return key


@router.get("/keys", response_model=list[KeyResponse])
def list_keys(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    return (
        db.query(VirtualKey)
        .order_by(VirtualKey.key_id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )


@router.patch("/keys/{key_id}", response_model=KeyResponse)
def update_key(
    key_id: str,
    payload: KeyUpdateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_ROLES)
    key = db.query(VirtualKey).filter_by(key_id=key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    updates = payload.model_dump(exclude_none=True)

    if "allowed_endpoint_families" in updates:
        _parse_string_list(str(updates["allowed_endpoint_families"]), "allowed_endpoint_families")
    if "allowed_models" in updates:
        _parse_string_list(str(updates["allowed_models"]), "allowed_models")
    if "guardrail_policy" in updates:
        normalized_policy = _parse_guardrail_policy(str(updates["guardrail_policy"]))
        updates["guardrail_policy"] = json.dumps(normalized_policy, separators=(",", ":"), sort_keys=True)

    for field, value in updates.items():
        setattr(key, field, value)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.key.update",
        resource_type="virtual_key",
        resource_id=key.key_id,
        trace_id=f"trace-{key.key_id}",
    )
    db.commit()
    db.refresh(key)
    return key


@router.post(
    "/keys/{key_id}/block",
    response_model=KeyLifecycleActionResponse,
    summary="Block virtual key",
    description="Blocks a virtual key from serving traffic and records audit evidence.",
    responses={
        403: {"description": "Actor role is not allowed for this action."},
        404: {"description": "Key not found."},
    },
)
def block_key(
    key_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_ROLES)
    key = db.query(VirtualKey).filter_by(key_id=key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    key.status = "blocked"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.key.block",
        resource_type="virtual_key",
        resource_id=key.key_id,
        trace_id=f"trace-{key.key_id}",
    )
    db.commit()
    return {"key_id": key.key_id, "status": key.status, "action": "blocked"}


@router.post(
    "/keys/{key_id}/unblock",
    response_model=KeyLifecycleActionResponse,
    summary="Unblock virtual key",
    description="Restores a blocked virtual key to active status and records audit evidence.",
    responses={
        403: {"description": "Actor role is not allowed for this action."},
        404: {"description": "Key not found."},
    },
)
def unblock_key(
    key_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_ROLES)
    key = db.query(VirtualKey).filter_by(key_id=key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    key.status = "active"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.key.unblock",
        resource_type="virtual_key",
        resource_id=key.key_id,
        trace_id=f"trace-{key.key_id}",
    )
    db.commit()
    return {"key_id": key.key_id, "status": key.status, "action": "unblocked"}


@router.post(
    "/keys/{key_id}/rotate",
    summary="Rotate virtual key",
    description=(
        "Rotates a virtual key hash and records audit evidence. "
        "Production rotations require dual approval by policy."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action or dual approval is missing."},
        404: {"description": "Key not found."},
    },
)
def rotate_key(
    key_id: str,
    environment: str = "dev",
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "gateway_rotate_key_start %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "key_id": key_id,
                "environment": environment,
                "description": "Start virtual key rotation flow and enforce environment-specific authorization controls.",
            }
        ),
    )
    try:
        require_role(ctx, GATEWAY_ADMIN_ROLES)
        if _is_prod_environment(environment):
            require_dual_approval(ctx)
    except HTTPException as exc:
        if exc.status_code == 403:
            logger.error(
                "gateway_rotate_key_denied %s",
                sanitize_fields(
                    {
                        "actor_id": ctx.actor_id,
                        "key_id": key_id,
                        "environment": environment,
                        "description": "Virtual key rotation denied due to role or dual-approval policy checks.",
                    }
                ),
            )
            create_audit_event(
                db,
                actor_id=ctx.actor_id,
                action_type="gateway.key.rotate",
                resource_type="virtual_key",
                resource_id=key_id,
                trace_id=f"trace-{key_id}",
                decision_outcome="deny",
            )
            db.commit()
        raise

    key = db.query(VirtualKey).filter_by(key_id=key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    key.key_hash = str(uuid4())
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.key.rotate",
        resource_type="virtual_key",
        resource_id=key.key_id,
        trace_id=f"trace-{key.key_id}",
    )
    db.commit()
    logger.info(
        "gateway_rotate_key_completed %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "key_id": key_id,
                "environment": environment,
                "description": "Virtual key rotation completed and a fresh key hash is now active.",
            }
        ),
    )
    return {"key_id": key_id, "rotation_status": "rotated"}


@router.post(
    "/keys/{key_id}/budget/increase-temporary",
    response_model=KeyBudgetIncreaseTemporaryResponse,
)
def increase_key_budget_temporary(
    key_id: str,
    payload: KeyBudgetIncreaseTemporaryRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_ROLES)
    if _is_prod_environment(payload.environment):
        require_dual_approval(ctx)

    key = db.query(VirtualKey).filter_by(key_id=key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    now = datetime.utcnow()
    expires_at = now + timedelta(minutes=payload.duration_minutes)
    policy_state = _load_key_policy_state(key)
    policy_state["temporary_budget_increase"] = {
        "environment": str(payload.environment or "dev").strip().lower() or "dev",
        "increase_cents": int(payload.increase_cents),
        "duration_minutes": int(payload.duration_minutes),
        "reason": str(payload.reason or "operator-request").strip() or "operator-request",
        "requested_by": ctx.actor_id,
        "requested_at": now.isoformat() + "Z",
        "expires_at": expires_at.isoformat() + "Z",
    }
    _save_key_policy_state(key, policy_state)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.key.budget_increase_temporary",
        resource_type="virtual_key",
        resource_id=key.key_id,
        trace_id=f"trace-{key.key_id}",
    )
    db.commit()

    record = policy_state["temporary_budget_increase"]
    return {
        "key_id": key.key_id,
        "environment": record["environment"],
        "increase_cents": record["increase_cents"],
        "duration_minutes": record["duration_minutes"],
        "reason": record["reason"],
        "active": True,
        "requested_by": record["requested_by"],
        "requested_at": record["requested_at"],
        "expires_at": record["expires_at"],
    }


@router.get(
    "/keys/{key_id}/budget/increase-temporary",
    response_model=KeyBudgetIncreaseTemporaryResponse,
)
def get_key_budget_increase_temporary(
    key_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    key = db.query(VirtualKey).filter_by(key_id=key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    policy_state = _load_key_policy_state(key)
    record = policy_state.get("temporary_budget_increase")
    if not isinstance(record, dict):
        raise HTTPException(status_code=404, detail="Temporary budget increase not configured")

    now = datetime.utcnow()
    expires_at_dt = _parse_iso_utc_timestamp(record.get("expires_at"))
    active = bool(expires_at_dt and expires_at_dt > now)
    return {
        "key_id": key.key_id,
        "environment": str(record.get("environment") or "dev"),
        "increase_cents": int(record.get("increase_cents") or 0),
        "duration_minutes": int(record.get("duration_minutes") or 0),
        "reason": str(record.get("reason") or "operator-request"),
        "active": active,
        "requested_by": str(record.get("requested_by") or "system-user"),
        "requested_at": str(record.get("requested_at") or ""),
        "expires_at": str(record.get("expires_at") or ""),
    }


@router.post(
    "/keys/{key_id}/rotation-schedules",
    response_model=KeyRotationScheduleResponse,
)
def create_key_rotation_schedule(
    key_id: str,
    payload: KeyRotationScheduleRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_ROLES)
    if _is_prod_environment(payload.environment):
        require_dual_approval(ctx)

    key = db.query(VirtualKey).filter_by(key_id=key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    now = datetime.utcnow()
    schedule = {
        "schedule_id": str(uuid4()),
        "environment": str(payload.environment or "dev").strip().lower() or "dev",
        "interval_hours": int(payload.interval_hours),
        "enabled": bool(payload.enabled),
        "reason": str(payload.reason or "scheduled-rotation").strip() or "scheduled-rotation",
        "created_by": ctx.actor_id,
        "created_at": now.isoformat() + "Z",
        "updated_at": now.isoformat() + "Z",
        "next_run_at": (now + timedelta(hours=int(payload.interval_hours))).isoformat() + "Z",
    }

    policy_state = _load_key_policy_state(key)
    schedules = _get_rotation_schedules(policy_state)
    schedules.append(schedule)
    policy_state["rotation_schedules"] = schedules
    _save_key_policy_state(key, policy_state)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.key.rotation_schedule.create",
        resource_type="virtual_key",
        resource_id=key.key_id,
        trace_id=f"trace-{key.key_id}",
    )
    db.commit()
    return {"key_id": key.key_id, **schedule}


@router.get(
    "/keys/{key_id}/rotation-schedules",
    response_model=list[KeyRotationScheduleResponse],
)
def list_key_rotation_schedules(
    key_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    key = db.query(VirtualKey).filter_by(key_id=key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    policy_state = _load_key_policy_state(key)
    schedules = _get_rotation_schedules(policy_state)
    return [{"key_id": key.key_id, **item} for item in schedules]


@router.patch(
    "/keys/{key_id}/rotation-schedules/{schedule_id}",
    response_model=KeyRotationScheduleResponse,
)
def update_key_rotation_schedule(
    key_id: str,
    schedule_id: str,
    payload: KeyRotationScheduleUpdateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_ROLES)
    key = db.query(VirtualKey).filter_by(key_id=key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    policy_state = _load_key_policy_state(key)
    schedules = _get_rotation_schedules(policy_state)
    target = next((row for row in schedules if row.get("schedule_id") == schedule_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Rotation schedule not found")

    if _is_prod_environment(str(target.get("environment") or "dev")):
        require_dual_approval(ctx)

    now = datetime.utcnow()
    if payload.interval_hours is not None:
        target["interval_hours"] = int(payload.interval_hours)
        anchor = _parse_iso_utc_timestamp(target.get("last_run_at")) or now
        target["next_run_at"] = (anchor + timedelta(hours=int(payload.interval_hours))).isoformat() + "Z"
    if payload.enabled is not None:
        target["enabled"] = bool(payload.enabled)
    if payload.reason is not None:
        target["reason"] = str(payload.reason).strip() or target.get("reason") or "scheduled-rotation"
    target["updated_at"] = now.isoformat() + "Z"

    policy_state["rotation_schedules"] = schedules
    _save_key_policy_state(key, policy_state)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.key.rotation_schedule.update",
        resource_type="virtual_key",
        resource_id=key.key_id,
        trace_id=f"trace-{key.key_id}",
    )
    db.commit()
    return {"key_id": key.key_id, **target}


@router.post(
    "/keys/{key_id}/rotation-schedules/{schedule_id}/execute-now",
    response_model=KeyRotationScheduleExecuteResponse,
)
def execute_key_rotation_schedule_now(
    key_id: str,
    schedule_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_ROLES)
    key = db.query(VirtualKey).filter_by(key_id=key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    policy_state = _load_key_policy_state(key)
    schedules = _get_rotation_schedules(policy_state)
    target = next((row for row in schedules if row.get("schedule_id") == schedule_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="Rotation schedule not found")
    if not bool(target.get("enabled", True)):
        raise HTTPException(status_code=400, detail="Rotation schedule is disabled")

    environment = str(target.get("environment") or "dev").strip().lower() or "dev"
    if _is_prod_environment(environment):
        require_dual_approval(ctx)

    now = datetime.utcnow()
    key.key_hash = str(uuid4())
    target["last_run_at"] = now.isoformat() + "Z"
    target["next_run_at"] = (now + timedelta(hours=int(target.get("interval_hours") or 24))).isoformat() + "Z"
    target["updated_at"] = now.isoformat() + "Z"

    policy_state["rotation_schedules"] = schedules
    _save_key_policy_state(key, policy_state)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.key.rotation_schedule.execute",
        resource_type="virtual_key",
        resource_id=key.key_id,
        trace_id=f"trace-{key.key_id}",
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.key.rotate",
        resource_type="virtual_key",
        resource_id=key.key_id,
        trace_id=f"trace-{key.key_id}",
    )
    db.commit()
    return {
        "key_id": key.key_id,
        "schedule_id": schedule_id,
        "rotation_status": "rotated",
        "environment": environment,
        "executed_at": now.isoformat() + "Z",
        "next_run_at": target["next_run_at"],
    }


@router.get("/keys/{key_id}/usage")
def key_usage(
    key_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    key = db.query(VirtualKey).filter_by(key_id=key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    window_start = datetime.utcnow() - timedelta(hours=24)
    requests_last_24h = int(
        db.query(func.count(AuditEvent.audit_event_id))
        .filter(
            AuditEvent.resource_type == "virtual_key",
            AuditEvent.resource_id == key_id,
            AuditEvent.action_type == "gateway.key.guardrails.evaluate",
            AuditEvent.timestamp >= window_start,
        )
        .scalar()
        or 0
    )
    return {"key_id": key_id, "requests_last_24h": requests_last_24h, "status": key.status}


@router.post("/keys/{key_id}/guardrails/evaluate", response_model=KeyGuardrailEvaluateResponse)
def evaluate_key_guardrails(
    key_id: str,
    payload: KeyGuardrailEvaluateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    key = db.query(VirtualKey).filter_by(key_id=key_id).first()
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")

    policy = _parse_guardrail_policy(key.guardrail_policy or "{}")
    decision, reasons, applied_guardrails = _guardrail_decision(key, policy, payload)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.key.guardrails.evaluate",
        resource_type="virtual_key",
        resource_id=key_id,
        trace_id=f"trace-{key_id}",
        decision_outcome=decision,
    )
    db.commit()

    return KeyGuardrailEvaluateResponse(
        key_id=key_id,
        decision=decision,
        reasons=reasons,
        applied_guardrails=applied_guardrails,
    )


@router.post(
    "/gateway/routes",
    response_model=RoutePolicyResponse,
    summary="Create gateway route policy",
    description="Creates a route policy with normalized fallback, retry, and timeout governance configuration.",
    responses={
        403: {"description": "Actor role is not allowed for this action."},
    },
)
def create_route(
    payload: RoutePolicyRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_ROLES)

    normalized_candidate_deployments = json.dumps(
        _parse_json_array(payload.candidate_deployments, "candidate_deployments"),
        separators=(",", ":"),
    )
    normalized_retry_policy = json.dumps(
        _parse_json_object_legacy_compatible(payload.retry_policy, "retry_policy"),
        separators=(",", ":"),
    )
    normalized_fallback_policy = json.dumps(
        _normalize_route_fallback_policy(
            _parse_json_object_legacy_compatible(payload.fallback_policy, "fallback_policy")
        ),
        separators=(",", ":"),
    )
    normalized_timeout_policy = json.dumps(
        _parse_json_object_legacy_compatible(payload.timeout_policy, "timeout_policy"),
        separators=(",", ":"),
    )

    route = RoutePolicy(
        route_policy_id=str(uuid4()),
        route_name=payload.route_name,
        candidate_deployments=normalized_candidate_deployments,
        load_balancing_strategy=_normalize_route_strategy(payload.load_balancing_strategy, "load_balancing_strategy"),
        retry_policy=normalized_retry_policy,
        fallback_policy=normalized_fallback_policy,
        timeout_policy=normalized_timeout_policy,
        status="active",
    )
    db.add(route)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.route.create",
        resource_type="route_policy",
        resource_id=route.route_policy_id,
        trace_id=f"trace-{route.route_policy_id}",
    )
    db.commit()
    db.refresh(route)
    return route


@router.get("/gateway/routes", response_model=list[RoutePolicyResponse])
def list_routes(
    limit: Optional[int] = Query(default=None, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    response: Response = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    query = db.query(RoutePolicy)
    total_count = query.count()
    if response is not None:
        response.headers["X-Total-Count"] = str(total_count)
    ordered_query = query.order_by(RoutePolicy.route_policy_id.asc()).offset(offset)
    if limit is not None:
        ordered_query = ordered_query.limit(limit)
    return ordered_query.all()


@router.post(
    "/gateway/routes/{route_policy_id}/providers/priority",
    response_model=RouteProviderPriorityResponse,
    summary="Upsert route provider priority",
    description=(
        "Updates tenant-scoped provider priority and fallback behavior for a route. "
        "Production updates require dual approval."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action or dual approval is missing."},
        404: {"description": "Route policy not found."},
    },
)
def upsert_route_provider_priority(
    route_policy_id: str,
    payload: RouteProviderPriorityUpdateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "gateway_route_provider_priority_update_start %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "route_policy_id": route_policy_id,
                "environment": payload.environment,
                "description": "Start update of route provider-priority policy with tenant-scoped fallback order settings.",
            }
        ),
    )

    try:
        require_role(ctx, GATEWAY_ADMIN_OR_AI_OPS_ROLES)
        if _is_prod_environment(payload.environment):
            require_dual_approval(ctx)
    except HTTPException as exc:
        if exc.status_code == 403:
            logger.error(
                "gateway_route_provider_priority_update_denied %s",
                sanitize_fields(
                    {
                        "actor_id": ctx.actor_id,
                        "route_policy_id": route_policy_id,
                        "environment": payload.environment,
                        "description": "Route provider-priority update denied by role or production dual-approval requirements.",
                    }
                ),
            )
            create_audit_event(
                db,
                actor_id=ctx.actor_id,
                action_type="gateway.route.provider_priority.update",
                resource_type="route_policy",
                resource_id=route_policy_id,
                trace_id=f"trace-provider-priority-{route_policy_id}",
                decision_outcome="deny",
            )
            db.commit()
        raise

    route = db.query(RoutePolicy).filter_by(route_policy_id=route_policy_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Route policy not found")

    current_fallback = _parse_json_object(route.fallback_policy, "fallback_policy")
    existing_provider_priority = current_fallback.get("provider_priority") if isinstance(current_fallback, dict) else None
    if isinstance(existing_provider_priority, dict):
        existing_tenant_id = existing_provider_priority.get("tenant_id")
        if isinstance(existing_tenant_id, str) and existing_tenant_id.strip():
            _require_tenant_match(existing_tenant_id.strip(), payload.tenant_id, "route provider priority")

    normalized_priority_order = _parse_priority_order(payload.priority_order)

    normalized_request_tag = _normalize_request_tag(payload.request_tag)
    next_priority_payload = {
        "tenant_id": payload.tenant_id,
        "environment": payload.environment,
        "priority_order": normalized_priority_order,
        "global_timeout_ms": payload.global_timeout_ms,
        "max_fallback_hops": payload.max_fallback_hops,
        "health_check_enabled": bool(payload.health_check_enabled),
        "budget_limit_cents": payload.budget_limit_cents,
        "updated_at": datetime.utcnow().isoformat(),
    }

    if normalized_request_tag:
        tagged = current_fallback.get("provider_priority_by_tag") if isinstance(current_fallback, dict) else None
        if not isinstance(tagged, dict):
            tagged = {}
        tagged[normalized_request_tag] = next_priority_payload
        current_fallback["provider_priority_by_tag"] = tagged
    else:
        current_fallback["provider_priority"] = next_priority_payload

    route.fallback_policy = json.dumps(current_fallback, separators=(",", ":"))

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.route.provider_priority.update",
        resource_type="route_policy",
        resource_id=route_policy_id,
        trace_id=f"trace-provider-priority-{route_policy_id}",
    )
    db.commit()

    logger.info(
        "gateway_route_provider_priority_update_completed %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "route_policy_id": route_policy_id,
                "environment": payload.environment,
                "description": "Route provider-priority policy updated and persisted successfully.",
            }
        ),
    )

    return {
        "route_policy_id": route_policy_id,
        "tenant_id": payload.tenant_id,
        "environment": payload.environment,
        "request_tag": normalized_request_tag,
        "priority_order": json.dumps(normalized_priority_order, separators=(",", ":")),
        "global_timeout_ms": payload.global_timeout_ms,
        "max_fallback_hops": payload.max_fallback_hops,
        "health_check_enabled": bool(payload.health_check_enabled),
        "budget_limit_cents": payload.budget_limit_cents,
        "updated": True,
    }


@router.get(
    "/gateway/routes/{route_policy_id}/providers/priority",
    response_model=RouteProviderPriorityResponse,
)
def get_route_provider_priority(
    route_policy_id: str,
    request_tag: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)

    route = db.query(RoutePolicy).filter_by(route_policy_id=route_policy_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Route policy not found")

    fallback = _parse_json_object(route.fallback_policy, "fallback_policy")
    provider_priority, selected_request_tag = _resolve_provider_priority_policy(fallback, request_tag)

    priority_order = provider_priority.get("priority_order")
    if not isinstance(priority_order, list):
        priority_order = []

    default_global_timeout_ms = get_runtime_config_int(
        db,
        RUNTIME_CONFIG_GATEWAY_DEFAULT_GLOBAL_TIMEOUT_MS,
        4500,
    )
    default_max_fallback_hops = get_runtime_config_int(
        db,
        RUNTIME_CONFIG_GATEWAY_DEFAULT_MAX_FALLBACK_HOPS,
        2,
    )

    global_timeout_ms = provider_priority.get("global_timeout_ms")
    if not isinstance(global_timeout_ms, int):
        global_timeout_ms = default_global_timeout_ms

    max_fallback_hops = provider_priority.get("max_fallback_hops")
    if not isinstance(max_fallback_hops, int):
        max_fallback_hops = default_max_fallback_hops

    health_check_enabled = bool(provider_priority.get("health_check_enabled", False))
    budget_limit_cents = provider_priority.get("budget_limit_cents")
    if not isinstance(budget_limit_cents, int) or budget_limit_cents < 1:
        budget_limit_cents = None

    environment = provider_priority.get("environment")
    if not isinstance(environment, str) or not environment.strip():
        environment = "prod"

    tenant_id = provider_priority.get("tenant_id")
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        tenant_id = "unscoped"

    return {
        "route_policy_id": route_policy_id,
        "tenant_id": tenant_id,
        "environment": environment,
        "request_tag": selected_request_tag,
        "priority_order": json.dumps(priority_order, separators=(",", ":")),
        "global_timeout_ms": global_timeout_ms,
        "max_fallback_hops": max_fallback_hops,
        "health_check_enabled": health_check_enabled,
        "budget_limit_cents": budget_limit_cents,
        "updated": False,
    }


@router.put(
    "/gateway/routes/{route_policy_id}/fallbacks",
    response_model=RouteFallbackPolicyResponse,
)
def upsert_route_fallbacks(
    route_policy_id: str,
    payload: RouteFallbackPolicyRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    translated = RouteProviderPriorityUpdateRequest(
        tenant_id=payload.tenant_id,
        environment=payload.environment,
        request_tag=payload.request_tag,
        priority_order=payload.priority_order,
        global_timeout_ms=payload.global_timeout_ms,
        max_fallback_hops=payload.max_fallback_hops,
        health_check_enabled=payload.health_check_enabled,
        budget_limit_cents=payload.budget_limit_cents,
    )
    result = upsert_route_provider_priority(route_policy_id=route_policy_id, payload=translated, db=db, ctx=ctx)
    return RouteFallbackPolicyResponse(**result)


@router.get(
    "/gateway/routes/{route_policy_id}/fallbacks",
    response_model=RouteFallbackPolicyResponse,
)
def get_route_fallbacks(
    route_policy_id: str,
    request_tag: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    result = get_route_provider_priority(route_policy_id=route_policy_id, request_tag=request_tag, db=db, ctx=ctx)
    return RouteFallbackPolicyResponse(**result)


@router.put(
    "/gateway/routes/{route_policy_id}/pre-call-filters",
    response_model=RoutePreCallFiltersResponse,
)
def upsert_route_pre_call_filters(
    route_policy_id: str,
    payload: RoutePreCallFiltersRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_AI_OPS_ROLES)
    if _is_prod_environment(payload.environment):
        require_dual_approval(ctx)

    route = db.query(RoutePolicy).filter_by(route_policy_id=route_policy_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Route policy not found")

    fallback = _parse_json_object(route.fallback_policy, "fallback_policy")
    normalized_request_tag = _normalize_request_tag(payload.request_tag)
    allowed_regions = _parse_region_list(payload.allowed_regions, "allowed_regions")

    min_tokens = payload.min_context_window_tokens
    max_tokens = payload.max_context_window_tokens
    if min_tokens is not None and max_tokens is not None and min_tokens > max_tokens:
        raise HTTPException(status_code=422, detail="min_context_window_tokens cannot exceed max_context_window_tokens")

    normalized = {
        "tenant_id": payload.tenant_id,
        "environment": payload.environment,
        "allowed_regions": allowed_regions,
        "min_context_window_tokens": min_tokens,
        "max_context_window_tokens": max_tokens,
        "enforce": bool(payload.enforce),
        "updated_at": datetime.utcnow().isoformat(),
    }

    if normalized_request_tag:
        tagged = fallback.get("pre_call_filters_by_tag") if isinstance(fallback, dict) else None
        if not isinstance(tagged, dict):
            tagged = {}
        tagged[normalized_request_tag] = normalized
        fallback["pre_call_filters_by_tag"] = tagged
    else:
        fallback["pre_call_filters"] = normalized

    route.fallback_policy = json.dumps(fallback, separators=(",", ":"))
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.route.pre_call_filters.update",
        resource_type="route_policy",
        resource_id=route_policy_id,
        trace_id=f"trace-route-pre-call-filters-{route_policy_id}",
    )
    db.commit()

    return {
        "route_policy_id": route_policy_id,
        "tenant_id": payload.tenant_id,
        "environment": payload.environment,
        "request_tag": normalized_request_tag,
        "allowed_regions": json.dumps(allowed_regions, separators=(",", ":")),
        "min_context_window_tokens": min_tokens,
        "max_context_window_tokens": max_tokens,
        "enforce": bool(payload.enforce),
    }


@router.get(
    "/gateway/routes/{route_policy_id}/pre-call-filters",
    response_model=RoutePreCallFiltersResponse,
)
def get_route_pre_call_filters(
    route_policy_id: str,
    request_tag: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)

    route = db.query(RoutePolicy).filter_by(route_policy_id=route_policy_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Route policy not found")

    fallback = _parse_json_object(route.fallback_policy, "fallback_policy")
    policy, selected_request_tag = _resolve_pre_call_filters_policy(fallback, request_tag)

    tenant_id = str(policy.get("tenant_id") or "unscoped")
    environment = str(policy.get("environment") or "prod")
    allowed_regions = policy.get("allowed_regions") if isinstance(policy.get("allowed_regions"), list) else []
    min_tokens = policy.get("min_context_window_tokens") if isinstance(policy.get("min_context_window_tokens"), int) else None
    max_tokens = policy.get("max_context_window_tokens") if isinstance(policy.get("max_context_window_tokens"), int) else None

    return {
        "route_policy_id": route_policy_id,
        "tenant_id": tenant_id,
        "environment": environment,
        "request_tag": selected_request_tag,
        "allowed_regions": json.dumps(allowed_regions, separators=(",", ":")),
        "min_context_window_tokens": min_tokens,
        "max_context_window_tokens": max_tokens,
        "enforce": bool(policy.get("enforce", True)),
    }


@router.put(
    "/gateway/routes/{route_policy_id}/traffic-mirroring",
    response_model=RouteTrafficMirroringResponse,
)
def upsert_route_traffic_mirroring(
    route_policy_id: str,
    payload: RouteTrafficMirroringRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_AI_OPS_ROLES)
    if _is_prod_environment(payload.environment):
        require_dual_approval(ctx)

    route = db.query(RoutePolicy).filter_by(route_policy_id=route_policy_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Route policy not found")

    fallback = _parse_json_object(route.fallback_policy, "fallback_policy")
    normalized_request_tag = _normalize_request_tag(payload.request_tag)
    mirror_targets = _parse_traffic_mirror_targets(payload.mirror_targets)

    normalized = {
        "tenant_id": payload.tenant_id,
        "environment": payload.environment,
        "enabled": bool(payload.enabled),
        "mirror_targets": mirror_targets,
        "updated_at": datetime.utcnow().isoformat(),
    }

    if normalized_request_tag:
        tagged = fallback.get("traffic_mirroring_by_tag") if isinstance(fallback, dict) else None
        if not isinstance(tagged, dict):
            tagged = {}
        tagged[normalized_request_tag] = normalized
        fallback["traffic_mirroring_by_tag"] = tagged
    else:
        fallback["traffic_mirroring"] = normalized

    route.fallback_policy = json.dumps(fallback, separators=(",", ":"))
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.route.traffic_mirroring.update",
        resource_type="route_policy",
        resource_id=route_policy_id,
        trace_id=f"trace-route-traffic-mirroring-{route_policy_id}",
    )
    db.commit()

    return {
        "route_policy_id": route_policy_id,
        "tenant_id": payload.tenant_id,
        "environment": payload.environment,
        "request_tag": normalized_request_tag,
        "mirror_targets": json.dumps(mirror_targets, separators=(",", ":")),
        "enabled": bool(payload.enabled),
    }


@router.get(
    "/gateway/routes/{route_policy_id}/traffic-mirroring",
    response_model=RouteTrafficMirroringResponse,
)
def get_route_traffic_mirroring(
    route_policy_id: str,
    request_tag: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)

    route = db.query(RoutePolicy).filter_by(route_policy_id=route_policy_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Route policy not found")

    fallback = _parse_json_object(route.fallback_policy, "fallback_policy")
    policy, selected_request_tag = _resolve_traffic_mirroring_policy(fallback, request_tag)
    tenant_id = str(policy.get("tenant_id") or "unscoped")
    environment = str(policy.get("environment") or "prod")
    mirror_targets = policy.get("mirror_targets") if isinstance(policy.get("mirror_targets"), list) else []
    enabled = bool(policy.get("enabled", False))

    return {
        "route_policy_id": route_policy_id,
        "tenant_id": tenant_id,
        "environment": environment,
        "request_tag": selected_request_tag,
        "mirror_targets": json.dumps(mirror_targets, separators=(",", ":")),
        "enabled": enabled,
    }


@router.get(
    "/gateway/routes/{route_policy_id}/traffic-mirroring/analytics-summary",
    response_model=RouteTrafficMirroringAnalyticsSummaryResponse,
)
def get_route_traffic_mirroring_analytics_summary(
    route_policy_id: str,
    request_tag: Optional[str] = Query(default=None),
    environment: Optional[str] = Query(default=None),
    hours: int = Query(default=24, ge=1, le=168),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)

    route = db.query(RoutePolicy).filter_by(route_policy_id=route_policy_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Route policy not found")

    normalized_request_tag = _normalize_request_tag(request_tag)
    normalized_environment = str(environment or "").strip().lower() or None
    window_start = datetime.utcnow() - timedelta(hours=hours)

    query = db.query(RouteMirrorExperimentEvent).filter(
        RouteMirrorExperimentEvent.route_policy_id == route_policy_id,
        RouteMirrorExperimentEvent.timestamp >= window_start,
    )
    if normalized_request_tag:
        query = query.filter(RouteMirrorExperimentEvent.request_tag == normalized_request_tag)
    if normalized_environment:
        query = query.filter(RouteMirrorExperimentEvent.environment == normalized_environment)

    total_mirror_events = int(query.count())
    mirrored_request_count = int(
        query.with_entities(func.count(func.distinct(RouteMirrorExperimentEvent.request_id))).scalar() or 0
    )

    top_mirror_provider_rows = (
        query.with_entities(
            RouteMirrorExperimentEvent.mirror_provider_id,
            func.count(RouteMirrorExperimentEvent.mirror_event_id),
        )
        .group_by(RouteMirrorExperimentEvent.mirror_provider_id)
        .order_by(func.count(RouteMirrorExperimentEvent.mirror_event_id).desc())
        .limit(10)
        .all()
    )
    primary_provider_rows = (
        query.with_entities(
            RouteMirrorExperimentEvent.primary_provider_id,
            func.count(RouteMirrorExperimentEvent.mirror_event_id),
        )
        .group_by(RouteMirrorExperimentEvent.primary_provider_id)
        .order_by(func.count(RouteMirrorExperimentEvent.mirror_event_id).desc())
        .limit(10)
        .all()
    )
    mirror_mode_rows = (
        query.with_entities(
            RouteMirrorExperimentEvent.mirror_mode,
            func.count(RouteMirrorExperimentEvent.mirror_event_id),
        )
        .group_by(RouteMirrorExperimentEvent.mirror_mode)
        .order_by(func.count(RouteMirrorExperimentEvent.mirror_event_id).desc())
        .all()
    )
    region_rows = (
        query.with_entities(
            func.coalesce(RouteMirrorExperimentEvent.requested_region, "unknown"),
            func.count(RouteMirrorExperimentEvent.mirror_event_id),
        )
        .group_by(RouteMirrorExperimentEvent.requested_region)
        .order_by(func.count(RouteMirrorExperimentEvent.mirror_event_id).desc())
        .limit(10)
        .all()
    )
    outcome_rows = (
        query.with_entities(
            RouteMirrorExperimentEvent.primary_outcome,
            RouteMirrorExperimentEvent.mirror_outcome,
            func.count(RouteMirrorExperimentEvent.mirror_event_id),
        )
        .group_by(RouteMirrorExperimentEvent.primary_outcome, RouteMirrorExperimentEvent.mirror_outcome)
        .order_by(func.count(RouteMirrorExperimentEvent.mirror_event_id).desc())
        .all()
    )

    return {
        "route_policy_id": route_policy_id,
        "environment": normalized_environment,
        "request_tag": normalized_request_tag,
        "hours": hours,
        "total_mirror_events": total_mirror_events,
        "mirrored_request_count": mirrored_request_count,
        "top_mirror_providers": _build_traffic_mirroring_breakdown(top_mirror_provider_rows),
        "primary_provider_distribution": _build_traffic_mirroring_breakdown(primary_provider_rows),
        "mirror_mode_distribution": _build_traffic_mirroring_breakdown(mirror_mode_rows),
        "region_distribution": _build_traffic_mirroring_breakdown(region_rows),
        "outcome_comparison": [
            {
                "primary_outcome": str(row[0] or "unknown"),
                "mirror_outcome": str(row[1] or "unknown"),
                "events": int(row[2] or 0),
            }
            for row in outcome_rows
        ],
    }


@router.get(
    "/gateway/routes/{route_policy_id}/traffic-mirroring/experiment-report",
    response_model=RouteTrafficMirroringExperimentReportResponse,
)
def get_route_traffic_mirroring_experiment_report(
    route_policy_id: str,
    request_tag: Optional[str] = Query(default=None),
    environment: Optional[str] = Query(default=None),
    hours: int = Query(default=24, ge=1, le=168),
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)

    route = db.query(RoutePolicy).filter_by(route_policy_id=route_policy_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Route policy not found")

    normalized_request_tag = _normalize_request_tag(request_tag)
    normalized_environment = str(environment or "").strip().lower() or None
    window_start = datetime.utcnow() - timedelta(hours=hours)

    query = db.query(RouteMirrorExperimentEvent).filter(
        RouteMirrorExperimentEvent.route_policy_id == route_policy_id,
        RouteMirrorExperimentEvent.timestamp >= window_start,
    )
    if normalized_request_tag:
        query = query.filter(RouteMirrorExperimentEvent.request_tag == normalized_request_tag)
    if normalized_environment:
        query = query.filter(RouteMirrorExperimentEvent.environment == normalized_environment)

    total_rows = int(query.count())
    rows = query.order_by(RouteMirrorExperimentEvent.timestamp.desc()).offset(offset).limit(limit).all()

    return {
        "route_policy_id": route_policy_id,
        "environment": normalized_environment,
        "request_tag": normalized_request_tag,
        "hours": hours,
        "limit": limit,
        "offset": offset,
        "total_rows": total_rows,
        "rows": rows,
    }


@router.put(
    "/gateway/routes/{route_policy_id}/providers/health",
    response_model=RouteProviderHealthResponse,
)
def upsert_route_provider_health(
    route_policy_id: str,
    payload: RouteProviderHealthUpdateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_AI_OPS_ROLES)

    route = db.query(RoutePolicy).filter_by(route_policy_id=route_policy_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Route policy not found")

    fallback = _parse_json_object(route.fallback_policy, "fallback_policy")
    normalized_request_tag = _normalize_request_tag(payload.request_tag)
    normalized_entries: dict[str, dict] = {}
    for entry in payload.entries:
        provider_id = str(entry.provider_id or "").strip()
        if not provider_id:
            continue
        normalized_entries[provider_id] = {
            "status": str(entry.status or "healthy").strip().lower(),
            "latency_ms": entry.latency_ms,
            "error_rate_percent": entry.error_rate_percent,
            "inflight_requests": entry.inflight_requests,
            "rate_limit_remaining_percent": entry.rate_limit_remaining_percent,
            "checked_at": str(entry.checked_at or datetime.utcnow().isoformat()).strip(),
        }

    if normalized_request_tag:
        tagged = fallback.get("provider_health_by_tag") if isinstance(fallback, dict) else None
        if not isinstance(tagged, dict):
            tagged = {}
        tagged[normalized_request_tag] = normalized_entries
        fallback["provider_health_by_tag"] = tagged
    else:
        fallback["provider_health"] = normalized_entries

    route.fallback_policy = json.dumps(fallback, separators=(",", ":"))
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.route.provider_health.update",
        resource_type="route_policy",
        resource_id=route_policy_id,
        trace_id=f"trace-provider-health-{route_policy_id}",
    )
    db.commit()

    entries = [
        {
            "provider_id": provider_id,
            "status": state.get("status") or "healthy",
            "latency_ms": state.get("latency_ms"),
            "error_rate_percent": state.get("error_rate_percent"),
            "inflight_requests": state.get("inflight_requests"),
            "rate_limit_remaining_percent": state.get("rate_limit_remaining_percent"),
            "checked_at": state.get("checked_at"),
        }
        for provider_id, state in sorted(normalized_entries.items(), key=lambda row: row[0])
    ]
    return {
        "route_policy_id": route_policy_id,
        "request_tag": normalized_request_tag,
        "entries": entries,
    }


@router.get(
    "/gateway/routes/{route_policy_id}/providers/health",
    response_model=RouteProviderHealthResponse,
)
def get_route_provider_health(
    route_policy_id: str,
    request_tag: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)

    route = db.query(RoutePolicy).filter_by(route_policy_id=route_policy_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Route policy not found")

    fallback = _parse_json_object(route.fallback_policy, "fallback_policy")
    provider_health = _build_provider_health_map(fallback, request_tag)
    normalized_request_tag = _normalize_request_tag(request_tag)
    entries = [
        {
            "provider_id": provider_id,
            "status": state.get("status") or "healthy",
            "latency_ms": state.get("latency_ms"),
            "error_rate_percent": state.get("error_rate_percent"),
            "inflight_requests": state.get("inflight_requests"),
            "rate_limit_remaining_percent": state.get("rate_limit_remaining_percent"),
            "checked_at": state.get("checked_at"),
        }
        for provider_id, state in sorted(provider_health.items(), key=lambda row: row[0])
    ]
    return {
        "route_policy_id": route_policy_id,
        "request_tag": normalized_request_tag,
        "entries": entries,
    }


@router.get(
    "/gateway/routes/{route_policy_id}/providers/priority/timeline",
    response_model=RouteProviderPriorityTimelineResponse,
)
def get_route_provider_priority_timeline(
    route_policy_id: str,
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)

    events = (
        db.query(AuditEvent)
        .filter(
            AuditEvent.resource_type == "route_policy",
            AuditEvent.resource_id == route_policy_id,
            AuditEvent.action_type == "gateway.route.provider_priority.update",
        )
        .order_by(AuditEvent.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    return {
        "route_policy_id": route_policy_id,
        "limit": limit,
        "offset": offset,
        "events": [
            {
                "timestamp": event.timestamp,
                "actor_id": event.actor_id,
                "action_type": event.action_type,
                "decision_outcome": event.decision_outcome,
                "trace_id": event.trace_id,
                "policy_version": event.policy_version,
            }
            for event in events
        ],
    }


@router.post(
    "/gateway/routes/{route_policy_id}/simulate-fallback",
    response_model=RouteSimulateFallbackResponse,
)
def simulate_route_fallback(
    route_policy_id: str,
    payload: RouteSimulateFallbackRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_AI_OPS_ROLES)

    route = db.query(RoutePolicy).filter_by(route_policy_id=route_policy_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Route policy not found")

    fallback = _parse_json_object(route.fallback_policy, "fallback_policy")
    pre_call_block_reason = _evaluate_pre_call_filter_block(
        fallback,
        tenant_id=payload.tenant_id,
        request_tag=payload.request_tag,
        requested_region=payload.requested_region,
        context_window_tokens=0,
        resource="route fallback simulation",
    )
    if pre_call_block_reason is not None:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.route.simulate_fallback",
            resource_type="route_policy",
            resource_id=route_policy_id,
            trace_id=f"trace-route-simulate-fallback-{route_policy_id}",
            decision_outcome="deny",
        )
        db.commit()
        return {
            "route_policy_id": route_policy_id,
            "tenant_id": payload.tenant_id,
            "environment": payload.environment,
            "attempted_providers": json.dumps(
                [
                    {
                        "outcome": "blocked_pre_call_filter",
                        "reason": pre_call_block_reason,
                        "requested_region": _normalize_requested_region(payload.requested_region),
                    }
                ],
                separators=(",", ":"),
            ),
            "selected_group_id": None,
            "selected_provider_id": None,
            "fallback_hops_used": 0,
            "provider_attempts": 0,
            "final_outcome": "blocked_pre_call_filter",
        }

    strategy = _normalize_route_strategy(route.load_balancing_strategy or "weighted", "load_balancing_strategy")
    provider_configs = _resolve_route_provider_configs(
        db,
        fallback,
        tenant_id=payload.tenant_id,
        request_tag=payload.request_tag,
        default_strategy=strategy,
        resource="route fallback simulation",
    )
    fail_provider_ids = set(_parse_string_list(payload.simulate_fail_provider_ids, "simulate_fail_provider_ids"))
    retry_error_policies = _parse_retry_error_policies(route.retry_policy or "{}")
    cooldown_registry = _load_retry_cooldown_registry(fallback)
    now = datetime.utcnow()

    attempted: list[dict] = []
    selected_group_id: str | None = None
    selected_provider_id: str | None = None
    fallback_hops_used = 0

    provider_health = _build_provider_health_map(fallback, payload.request_tag)
    for config in provider_configs:
        group_id = str(config.get("group_id") or "default")
        ordered_priority = list(config.get("priority_order") or [])
        if not ordered_priority:
            continue
        max_fallback_hops = config.get("max_fallback_hops")
        if not isinstance(max_fallback_hops, int):
            max_fallback_hops = len(ordered_priority) - 1
        max_attempts = min(len(ordered_priority), max_fallback_hops + 1)
        health_check_enabled = bool(config.get("health_check_enabled", False))

        for item in ordered_priority[:max_attempts]:
            provider_id = item["provider_id"]
            cooldown_error_type = _active_cooldown_error_type(
                provider_id,
                now=now,
                retry_error_policies=retry_error_policies,
                cooldown_registry=cooldown_registry,
            )
            if cooldown_error_type:
                attempted.append(
                    {
                        "group_id": group_id,
                        "provider_id": provider_id,
                        "outcome": "skipped_cooldown",
                        "error_type": cooldown_error_type,
                    }
                )
                fallback_hops_used += 1
                continue
            health_state = provider_health.get(provider_id, {})
            health_status = str(health_state.get("status") or "healthy").strip().lower()
            if health_check_enabled and health_status == "unhealthy":
                attempted.append({"group_id": group_id, "provider_id": provider_id, "outcome": "skipped_unhealthy"})
                fallback_hops_used += 1
                continue
            if provider_id in fail_provider_ids:
                attempted.append({"group_id": group_id, "provider_id": provider_id, "outcome": "failed_simulated"})
                fallback_hops_used += 1
                continue

            selected_group_id = group_id
            selected_provider_id = provider_id
            attempted.append({"group_id": group_id, "provider_id": provider_id, "outcome": "selected"})
            break

        if selected_provider_id is not None:
            break

    final_outcome = "success" if selected_provider_id is not None else "failed"

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.route.simulate_fallback",
        resource_type="route_policy",
        resource_id=route_policy_id,
        trace_id=f"trace-route-simulate-fallback-{route_policy_id}",
    )
    db.commit()

    return {
        "route_policy_id": route_policy_id,
        "tenant_id": payload.tenant_id,
        "environment": payload.environment,
        "attempted_providers": json.dumps(attempted, separators=(",", ":")),
        "selected_group_id": selected_group_id,
        "selected_provider_id": selected_provider_id,
        "fallback_hops_used": fallback_hops_used,
        "provider_attempts": len(attempted),
        "final_outcome": final_outcome,
    }


@router.post(
    "/gateway/routes/{route_policy_id}/execute-fallback",
    response_model=RouteExecuteFallbackResponse,
    summary="Execute route fallback",
    description=(
        "Executes governed provider fallback for a route and records latency and cost telemetry. "
        "Production execution requires dual approval and emits audit evidence."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action or dual approval is missing."},
        404: {"description": "Route policy not found."},
    },
)
def execute_route_with_fallback(
    route_policy_id: str,
    payload: RouteExecuteFallbackRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    try:
        require_role(ctx, GATEWAY_ADMIN_OR_AI_OPS_ROLES)
        if _is_prod_environment(payload.environment):
            require_dual_approval(ctx)
    except HTTPException as exc:
        if exc.status_code == 403:
            create_audit_event(
                db,
                actor_id=ctx.actor_id,
                action_type="gateway.route.execute_fallback",
                resource_type="route_policy",
                resource_id=route_policy_id,
                trace_id=f"trace-route-execute-fallback-{route_policy_id}",
                decision_outcome="deny",
            )
            db.commit()
        raise

    logger.trace(
        "gateway_execute_fallback_start %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "route_policy_id": route_policy_id,
                "tenant_id": payload.tenant_id,
                "environment": payload.environment,
                "description": "Execute gateway provider fallback and estimate cost using model token rates plus cloud component multipliers.",
            }
        ),
    )

    route = db.query(RoutePolicy).filter_by(route_policy_id=route_policy_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Route policy not found")

    fallback = _parse_json_object(route.fallback_policy, "fallback_policy")
    request_tag = _normalize_request_tag(payload.request_tag)
    request_id = f"gw-exec-{uuid4()}"
    trace_id = f"trace-gw-exec-{route_policy_id}-{uuid4()}"

    pre_call_block_reason = _evaluate_pre_call_filter_block(
        fallback,
        tenant_id=payload.tenant_id,
        request_tag=request_tag,
        requested_region=payload.requested_region,
        context_window_tokens=int(payload.input_tokens + payload.output_tokens),
        resource="route fallback execution",
    )
    if pre_call_block_reason is not None:
        attempted = [
            {
                "outcome": "blocked_pre_call_filter",
                "reason": pre_call_block_reason,
                "requested_region": _normalize_requested_region(payload.requested_region),
                "context_window_tokens": int(payload.input_tokens + payload.output_tokens),
            }
        ]
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.route.execute_fallback",
            resource_type="route_policy",
            resource_id=route_policy_id,
            trace_id=trace_id,
            decision_outcome="deny",
        )
        db.commit()
        return {
            "route_policy_id": route_policy_id,
            "tenant_id": payload.tenant_id,
            "environment": payload.environment,
            "request_id": request_id,
            "trace_id": trace_id,
            "attempted_providers": json.dumps(attempted, separators=(",", ":")),
            "selected_group_id": None,
            "selected_provider_id": None,
            "fallback_hops_used": 0,
            "provider_attempts": 0,
            "total_latency_ms": 0,
            "total_estimated_cost_cents": 0,
            "final_outcome": "blocked_pre_call_filter",
        }

    strategy = _normalize_route_strategy(route.load_balancing_strategy or "weighted", "load_balancing_strategy")
    provider_configs = _resolve_route_provider_configs(
        db,
        fallback,
        tenant_id=payload.tenant_id,
        request_tag=request_tag,
        default_strategy=strategy,
        resource="route fallback execution",
    )
    provider_health = _build_provider_health_map(fallback, request_tag)
    fail_provider_ids = set(_parse_string_list(payload.simulate_fail_provider_ids, "simulate_fail_provider_ids"))

    default_max_fallback_hops = get_runtime_config_int(
        db,
        RUNTIME_CONFIG_GATEWAY_DEFAULT_MAX_FALLBACK_HOPS,
        2,
    )
    default_global_timeout_ms = get_runtime_config_int(db, RUNTIME_CONFIG_GATEWAY_DEFAULT_GLOBAL_TIMEOUT_MS, 4500)

    request_priority = str(payload.request_priority or "normal").strip().lower()
    fallback_hop_delta = {"low": -1, "normal": 0, "high": 1}.get(request_priority, 0)
    attempted: list[dict] = []
    selected_group_id: str | None = None
    selected_provider_id: str | None = None
    fallback_hops_used = 0
    total_latency_ms = 0
    total_estimated_cost_cents = 0
    model_name = str(payload.model_name or "").strip()
    _, _, owner_scope = normalize_owner_scope(
        db,
        owner_scope=payload.owner_scope,
        owner_scope_type=payload.owner_scope_type,
        owner_scope_id=payload.owner_scope_id,
    )
    model_rates, default_model_rates = _load_model_token_rates(db)
    provider_multipliers, endpoint_multipliers = _load_cloud_component_multipliers(db)
    provider_type_cache: dict[str, str] = {}
    retry_error_policies = _parse_retry_error_policies(route.retry_policy or "{}")
    cooldown_registry = _load_retry_cooldown_registry(fallback)
    per_request_error_counts: dict[str, int] = {}
    retry_policy_blocked_error_type: str | None = None
    now = datetime.utcnow()

    budget_candidates = [
        int(config.get("budget_limit_cents"))
        for config in provider_configs
        if isinstance(config.get("budget_limit_cents"), int) and int(config.get("budget_limit_cents")) >= 1
    ]
    budget_limit_cents = min(budget_candidates) if budget_candidates else None

    spent_last_24h = 0
    if budget_limit_cents is not None:
        spent_last_24h = int(
            db.query(func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0))
            .filter(
                CostEvent.owner_scope == owner_scope,
                CostEvent.environment == payload.environment,
                CostEvent.timestamp >= datetime.utcnow() - timedelta(hours=24),
            )
            .scalar()
            or 0
        )

    used_group_hop_limit = False
    for config in provider_configs:
        group_id = str(config.get("group_id") or "default")
        ordered_priority = list(config.get("priority_order") or [])
        if not ordered_priority:
            continue

        group_budget_limit_cents = config.get("budget_limit_cents")
        if not isinstance(group_budget_limit_cents, int) or group_budget_limit_cents < 1:
            group_budget_limit_cents = None
        budget_limit_cents = group_budget_limit_cents

        group_global_timeout_ms = config.get("global_timeout_ms")
        if not isinstance(group_global_timeout_ms, int) or group_global_timeout_ms < 100:
            group_global_timeout_ms = default_global_timeout_ms

        max_fallback_hops = config.get("max_fallback_hops")
        if not isinstance(max_fallback_hops, int):
            max_fallback_hops = default_max_fallback_hops
        max_fallback_hops = max(0, max_fallback_hops + fallback_hop_delta)
        max_attempts = min(len(ordered_priority), max_fallback_hops + 1)
        if len(ordered_priority) > max_attempts:
            used_group_hop_limit = True

        health_check_enabled = bool(config.get("health_check_enabled", False))

        for index, item in enumerate(ordered_priority[:max_attempts], start=1):
            provider_id = item["provider_id"]
            cooldown_error_type = _active_cooldown_error_type(
                provider_id,
                now=now,
                retry_error_policies=retry_error_policies,
                cooldown_registry=cooldown_registry,
            )
            if cooldown_error_type:
                attempted.append(
                    {
                        "group_id": group_id,
                        "hop": index,
                        "provider_id": provider_id,
                        "outcome": "skipped_cooldown",
                        "error_type": cooldown_error_type,
                    }
                )
                fallback_hops_used += 1
                continue
            health_state = provider_health.get(provider_id, {})
            health_status = str(health_state.get("status") or "healthy").strip().lower()
            if health_check_enabled and health_status == "unhealthy":
                attempted.append(
                    {
                        "group_id": group_id,
                        "hop": index,
                        "provider_id": provider_id,
                        "outcome": "skipped_unhealthy",
                    }
                )
                fallback_hops_used += 1
                continue

            simulated_latency_ms = 120 + index * 25
            if request_priority == "high":
                simulated_latency_ms = max(50, simulated_latency_ms - 35)
            elif request_priority == "low":
                simulated_latency_ms = simulated_latency_ms + 35

            total_latency_ms += simulated_latency_ms
            if total_latency_ms > group_global_timeout_ms:
                attempted.append(
                    {
                        "group_id": group_id,
                        "hop": index,
                        "provider_id": provider_id,
                        "outcome": "failed_timeout",
                        "latency_ms": simulated_latency_ms,
                    }
                )
                fallback_hops_used += 1
                should_continue, blocked_error_type = _apply_retry_policy_on_error(
                    provider_id,
                    error_type="failed_timeout",
                    now=now,
                    retry_error_policies=retry_error_policies,
                    cooldown_registry=cooldown_registry,
                    per_request_error_counts=per_request_error_counts,
                )
                if not should_continue:
                    retry_policy_blocked_error_type = blocked_error_type
                break

            provider_type = provider_type_cache.get(provider_id)
            if provider_type is None:
                provider_type = _resolve_provider_type(db, provider_id)
                provider_type_cache[provider_id] = provider_type

            resolved_model_name = model_name or str(item.get("model_name") or "").strip() or provider_id

            explicit_model_requested = bool(model_name)
            if explicit_model_requested:
                _require_tenant_model_entitlement(
                    db,
                    tenant_id=payload.tenant_id,
                    provider_type=provider_type,
                    model_name=resolved_model_name,
                )

            hop_cost_cents = _estimate_hop_cost_cents(
                input_tokens=payload.input_tokens,
                output_tokens=payload.output_tokens,
                model_name=resolved_model_name,
                provider_type=provider_type,
                endpoint_family=payload.endpoint_family,
                model_rates=model_rates,
                default_model_rates=default_model_rates,
                provider_multipliers=provider_multipliers,
                endpoint_multipliers=endpoint_multipliers,
            )
            if budget_limit_cents is not None and spent_last_24h + total_estimated_cost_cents + hop_cost_cents > budget_limit_cents:
                attempted.append(
                    {
                        "group_id": group_id,
                        "hop": index,
                        "provider_id": provider_id,
                        "provider_type": provider_type,
                        "model_name": resolved_model_name,
                        "outcome": "budget_blocked",
                        "latency_ms": simulated_latency_ms,
                        "estimated_cost_cents": hop_cost_cents,
                    }
                )
                fallback_hops_used += 1
                should_continue, blocked_error_type = _apply_retry_policy_on_error(
                    provider_id,
                    error_type="budget_blocked",
                    now=now,
                    retry_error_policies=retry_error_policies,
                    cooldown_registry=cooldown_registry,
                    per_request_error_counts=per_request_error_counts,
                )
                if not should_continue:
                    retry_policy_blocked_error_type = blocked_error_type
                break

            if provider_id in fail_provider_ids:
                outcome = "failed_simulated"
                fallback_hops_used += 1
                hop_cost_cents = max(1, hop_cost_cents // 2)
                should_continue, blocked_error_type = _apply_retry_policy_on_error(
                    provider_id,
                    error_type="failed_simulated",
                    now=now,
                    retry_error_policies=retry_error_policies,
                    cooldown_registry=cooldown_registry,
                    per_request_error_counts=per_request_error_counts,
                )
                if not should_continue:
                    retry_policy_blocked_error_type = blocked_error_type
            else:
                outcome = "selected"
                selected_group_id = group_id
                selected_provider_id = provider_id

            attempted.append(
                {
                    "group_id": group_id,
                    "hop": index,
                    "provider_id": provider_id,
                    "provider_type": provider_type,
                    "model_name": resolved_model_name,
                    "outcome": outcome,
                    "latency_ms": simulated_latency_ms,
                    "estimated_cost_cents": hop_cost_cents,
                }
            )
            total_estimated_cost_cents += hop_cost_cents

            db.add(
                CostEvent(
                    cost_event_id=str(uuid4()),
                    request_id=request_id,
                    trace_id=trace_id,
                    request_tag=request_tag,
                    session_id=payload.session_id,
                    agent_id=payload.agent_id,
                    owner_scope=owner_scope,
                    environment=payload.environment,
                    model_name=resolved_model_name,
                    endpoint_family=payload.endpoint_family,
                    input_tokens=payload.input_tokens,
                    output_tokens=payload.output_tokens,
                    estimated_cost_cents=hop_cost_cents,
                    currency=payload.currency,
                )
            )

            if selected_provider_id is not None:
                break

            if retry_policy_blocked_error_type is not None:
                attempted.append(
                    {
                        "group_id": group_id,
                        "hop": index,
                        "provider_id": provider_id,
                        "outcome": "retry_policy_blocked",
                        "error_type": retry_policy_blocked_error_type,
                    }
                )
                break

        if retry_policy_blocked_error_type is not None:
            break

        if selected_provider_id is not None:
            break

    if attempted and attempted[-1].get("outcome") == "retry_policy_blocked":
        final_outcome = "failed_retry_policy"
    elif attempted and attempted[-1].get("outcome") == "budget_blocked":
        final_outcome = "failed_budget_limit"
    elif attempted and attempted[-1].get("outcome") == "failed_timeout":
        final_outcome = "failed_timeout"
    elif selected_provider_id is None and used_group_hop_limit:
        final_outcome = "failed_hop_limit"
    elif selected_provider_id is None:
        final_outcome = "failed"
    else:
        final_outcome = "success"

    traffic_mirroring_policy, _ = _resolve_traffic_mirroring_policy(fallback, request_tag)
    if selected_provider_id is not None and bool(traffic_mirroring_policy.get("enabled", False)):
        mirror_tenant_id = str(traffic_mirroring_policy.get("tenant_id") or "").strip()
        if mirror_tenant_id:
            _require_tenant_match(mirror_tenant_id, payload.tenant_id, "route traffic mirroring")
        mirror_targets = traffic_mirroring_policy.get("mirror_targets")
        if isinstance(mirror_targets, list):
            mirror_events = 0
            for target in mirror_targets:
                if not isinstance(target, dict):
                    continue
                target_provider_id = str(target.get("provider_id") or "").strip()
                if not target_provider_id or target_provider_id == selected_provider_id:
                    continue
                sample_percent = target.get("sample_percent")
                if not isinstance(sample_percent, int) or sample_percent < 1 or sample_percent > 100:
                    sample_percent = 100
                mode = str(target.get("mode") or "shadow").strip().lower() or "shadow"
                if mode not in {"shadow", "observe"}:
                    mode = "shadow"
                sample_bucket = (abs(hash(f"{request_id}:{target_provider_id}")) % 100) + 1
                if sample_bucket > sample_percent:
                    continue
                attempted.append(
                    {
                        "group_id": selected_group_id or "default",
                        "provider_id": target_provider_id,
                        "outcome": "mirrored_simulated",
                        "mirror_mode": mode,
                        "sample_percent": sample_percent,
                    }
                )
                db.add(
                    RouteMirrorExperimentEvent(
                        mirror_event_id=str(uuid4()),
                        route_policy_id=route_policy_id,
                        tenant_id=payload.tenant_id,
                        environment=str(payload.environment or "dev").strip().lower() or "dev",
                        request_tag=request_tag,
                        request_id=request_id,
                        trace_id=trace_id,
                        requested_region=_normalize_requested_region(payload.requested_region),
                        primary_provider_id=selected_provider_id,
                        primary_outcome=final_outcome,
                        mirror_provider_id=target_provider_id,
                        mirror_mode=mode,
                        mirror_outcome="mirrored_simulated",
                        sample_percent=sample_percent,
                    )
                )
                mirror_events += 1
            if mirror_events:
                create_audit_event(
                    db,
                    actor_id=ctx.actor_id,
                    action_type="gateway.route.traffic_mirroring.execute",
                    resource_type="route_policy",
                    resource_id=route_policy_id,
                    trace_id=trace_id,
                )

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.route.execute_fallback",
        resource_type="route_policy",
        resource_id=route_policy_id,
        trace_id=trace_id,
    )
    fallback["retry_cooldowns"] = _serialize_retry_cooldown_registry(cooldown_registry)
    route.fallback_policy = json.dumps(fallback, separators=(",", ":"))
    db.commit()
    logger.info(
        "gateway_execute_fallback_completed %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "route_policy_id": route_policy_id,
                "tenant_id": payload.tenant_id,
                "provider_attempts": len(attempted),
                "fallback_hops_used": fallback_hops_used,
                "selected_provider_id": selected_provider_id,
                "total_estimated_cost_cents": total_estimated_cost_cents,
                "description": "Gateway fallback execution recorded cost events with model-aware and cloud-aware pricing.",
            }
        ),
    )

    return {
        "route_policy_id": route_policy_id,
        "tenant_id": payload.tenant_id,
        "environment": payload.environment,
        "request_id": request_id,
        "trace_id": trace_id,
        "attempted_providers": json.dumps(attempted, separators=(",", ":")),
        "selected_group_id": selected_group_id,
        "selected_provider_id": selected_provider_id,
        "fallback_hops_used": fallback_hops_used,
        "provider_attempts": len(attempted),
        "total_latency_ms": total_latency_ms,
        "total_estimated_cost_cents": total_estimated_cost_cents,
        "final_outcome": final_outcome,
    }


@router.post(
    "/gateway/routes/{route_policy_id}/optimize",
    response_model=RouteOptimizeResponse,
    summary="Optimize route policy",
    description=(
        "Runs governed route optimization for cost, latency, reliability, or balanced objectives. "
        "Production optimization requires dual approval and emits audit evidence."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action or dual approval is missing."},
        404: {"description": "Route policy not found."},
    },
)
def optimize_route_policy(
    route_policy_id: str,
    payload: RouteOptimizeRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "gateway_optimize_route_start %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "route_policy_id": route_policy_id,
                "environment": payload.environment,
                "optimize_for": payload.optimize_for,
                "description": "Start route optimization workflow using strategy goal and environment governance checks.",
            }
        ),
    )
    try:
        require_role(ctx, GATEWAY_ADMIN_OR_AI_OPS_ROLES)
        if _is_prod_environment(payload.environment):
            require_dual_approval(ctx)
    except HTTPException as exc:
        if exc.status_code == 403:
            logger.error(
                "gateway_optimize_route_denied %s",
                sanitize_fields(
                    {
                        "actor_id": ctx.actor_id,
                        "route_policy_id": route_policy_id,
                        "environment": payload.environment,
                        "description": "Route optimization denied by authorization guardrails or missing dual approval in production.",
                    }
                ),
            )
            create_audit_event(
                db,
                actor_id=ctx.actor_id,
                action_type="gateway.route.optimize",
                resource_type="route_policy",
                resource_id=route_policy_id,
                trace_id=f"trace-{route_policy_id}",
                decision_outcome="deny",
            )
            db.commit()
        raise

    route = db.query(RoutePolicy).filter_by(route_policy_id=route_policy_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Route policy not found")

    recent_cost = int(
        db.query(func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0)).filter_by(environment=payload.environment).scalar()
        or 0
    )

    recommended_strategy = "weighted"
    latency_delta = -3.0
    cost_delta = -3.0

    if payload.optimize_for == "cost":
        recommended_strategy = "lowest_cost"
        latency_delta = 2.5
        cost_delta = -12.0
    elif payload.optimize_for == "latency":
        recommended_strategy = "lowest_latency"
        latency_delta = -11.0
        cost_delta = 4.0
    elif payload.optimize_for == "balanced":
        if recent_cost > 100000:
            recommended_strategy = "lowest_cost"
            latency_delta = 1.5
            cost_delta = -9.0
        else:
            recommended_strategy = "weighted"
            latency_delta = -4.0
            cost_delta = -2.0

    updated = route.load_balancing_strategy != recommended_strategy
    route.load_balancing_strategy = recommended_strategy

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.route.optimize",
        resource_type="route_policy",
        resource_id=route.route_policy_id,
        trace_id=f"trace-{route.route_policy_id}",
    )
    db.commit()
    logger.info(
        "gateway_optimize_route_completed %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "route_policy_id": route.route_policy_id,
                "environment": payload.environment,
                "updated": updated,
                "description": "Route optimization completed with a recommended load-balancing strategy and persisted outcome.",
            }
        ),
    )

    return {
        "route_policy_id": route.route_policy_id,
        "optimize_for": payload.optimize_for,
        "recommended_strategy": recommended_strategy,
        "estimated_latency_delta_percent": latency_delta,
        "estimated_cost_delta_percent": cost_delta,
        "updated": updated,
    }


@router.post(
    "/gateway/cache/policies",
    response_model=CachePolicyResponse,
    summary="Create gateway cache policy",
    description="Creates a cache policy for gateway response handling with privacy and invalidation controls.",
    responses={
        403: {"description": "Actor role is not allowed for this action."},
    },
)
def create_cache_policy(
    payload: CachePolicyRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_ROLES)
    policy = CachePolicy(
        cache_policy_id=str(uuid4()),
        scope=payload.scope,
        ttl_seconds=payload.ttl_seconds,
        key_strategy=payload.key_strategy,
        invalidation_strategy=payload.invalidation_strategy,
        privacy_mode=payload.privacy_mode,
        status="active",
    )
    db.add(policy)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.cache_policy.create",
        resource_type="cache_policy",
        resource_id=policy.cache_policy_id,
        trace_id=f"trace-{policy.cache_policy_id}",
    )
    db.commit()
    db.refresh(policy)
    return policy


@router.get("/gateway/cache/policies", response_model=list[CachePolicyResponse])
def list_cache_policies(
    scope: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    response: Response = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    query = db.query(CachePolicy)
    if scope:
        query = query.filter(CachePolicy.scope == scope.strip())
    if status:
        query = query.filter(CachePolicy.status == status.strip())

    total_count = query.count()
    if response is not None:
        response.headers["X-Total-Count"] = str(total_count)

    return query.order_by(CachePolicy.cache_policy_id.asc()).offset(offset).limit(limit).all()


@router.get("/gateway/cache/stats")
def cache_stats(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)

    active_policies = int(db.query(func.count(CachePolicy.cache_policy_id)).filter(CachePolicy.status == "active").scalar() or 0)
    avg_ttl_seconds = float(
        db.query(func.coalesce(func.avg(CachePolicy.ttl_seconds), 0.0)).filter(CachePolicy.status == "active").scalar() or 0.0
    )
    hit_count = int(
        db.query(func.count(AuditEvent.audit_event_id))
        .filter(
            AuditEvent.action_type == "gateway.cache.hit",
            AuditEvent.resource_type == "cache_policy",
        )
        .scalar()
        or 0
    )
    miss_count = int(
        db.query(func.count(AuditEvent.audit_event_id))
        .filter(
            AuditEvent.action_type == "gateway.cache.miss",
            AuditEvent.resource_type == "cache_policy",
        )
        .scalar()
        or 0
    )
    eligible_requests = hit_count + miss_count
    hit_ratio = float(hit_count / eligible_requests) if eligible_requests > 0 else 0.0

    return {
        "hit_ratio": hit_ratio,
        "eligible_requests": eligible_requests,
        "hits": hit_count,
        "misses": miss_count,
        "active_policies": active_policies,
        "avg_ttl_seconds": avg_ttl_seconds,
    }


@router.get("/gateway/cache/health", response_model=GatewayCacheHealthResponse)
def cache_health(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)

    active_policies = int(db.query(func.count(CachePolicy.cache_policy_id)).filter(CachePolicy.status == "active").scalar() or 0)
    avg_ttl_seconds = float(
        db.query(func.coalesce(func.avg(CachePolicy.ttl_seconds), 0.0)).filter(CachePolicy.status == "active").scalar() or 0.0
    )
    hit_count = int(
        db.query(func.count(AuditEvent.audit_event_id))
        .filter(
            AuditEvent.action_type == "gateway.cache.hit",
            AuditEvent.resource_type == "cache_policy",
        )
        .scalar()
        or 0
    )
    miss_count = int(
        db.query(func.count(AuditEvent.audit_event_id))
        .filter(
            AuditEvent.action_type == "gateway.cache.miss",
            AuditEvent.resource_type == "cache_policy",
        )
        .scalar()
        or 0
    )
    invalidation_requests_last_24h = int(
        db.query(func.count(AuditEvent.audit_event_id))
        .filter(
            AuditEvent.action_type == "gateway.cache.invalidate",
            AuditEvent.timestamp >= datetime.utcnow() - timedelta(hours=24),
        )
        .scalar()
        or 0
    )
    eligible_requests = hit_count + miss_count
    hit_ratio = float(hit_count / eligible_requests) if eligible_requests > 0 else 0.0

    return {
        "status": "healthy",
        "cache_backend": "policy-managed",
        "active_policies": active_policies,
        "avg_ttl_seconds": avg_ttl_seconds,
        "hit_ratio": hit_ratio,
        "eligible_requests": eligible_requests,
        "hits": hit_count,
        "misses": miss_count,
        "invalidation_requests_last_24h": invalidation_requests_last_24h,
    }


@router.post(
    "/gateway/cache/delete",
    response_model=GatewayCacheInvalidateResponse,
    summary="Invalidate gateway cache",
    description=(
        "Invalidates gateway cache entries by scope or explicit key list and records an audit-backed invalidation request. "
        "Reserved for gateway administrators."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action."},
        422: {"description": "Validation failed: scope or cache_keys is required."},
    },
)
def invalidate_cache(
    payload: GatewayCacheInvalidateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_ROLES)

    scope = str(payload.scope or "").strip() or None
    cache_keys = [str(item).strip() for item in payload.cache_keys if str(item).strip()]
    if scope is None and not cache_keys:
        raise HTTPException(status_code=422, detail="Either scope or cache_keys must be provided")

    query = db.query(CachePolicy)
    if scope is not None:
        query = query.filter(CachePolicy.scope == scope)
    if payload.active_only:
        query = query.filter(CachePolicy.status == "active")
    matching_policies = int(query.count())

    resource_id = scope or (cache_keys[0] if len(cache_keys) == 1 else "explicit-keys")
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.cache.invalidate",
        resource_type="cache_policy",
        resource_id=resource_id,
        trace_id=f"trace-gateway-cache-invalidate-{uuid4()}",
        decision_outcome="allow",
    )
    db.commit()

    return {
        "status": "accepted",
        "mode": "audit-backed",
        "invalidated_scope": scope,
        "requested_keys": len(cache_keys),
        "matching_policies": matching_policies,
        "active_only": payload.active_only,
    }


@router.get("/gateway/analytics/summary", response_model=GatewayAnalyticsSummaryResponse)
def gateway_analytics_summary(
    environment: Optional[str] = Query(default=None),
    hours: int = Query(default=24, ge=1, le=168),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)

    window_start = datetime.utcnow() - timedelta(hours=hours)
    base_query = db.query(CostEvent).filter(CostEvent.timestamp >= window_start)
    filtered_query = base_query
    if environment:
        filtered_query = filtered_query.filter(CostEvent.environment == environment)
        # Backward compatibility: if no events exist for a requested environment,
        # return window totals rather than an empty analytics payload.
        if not db.query(filtered_query.exists()).scalar():
            filtered_query = base_query

    totals = filtered_query.with_entities(
        func.count(CostEvent.cost_event_id),
        func.count(func.distinct(CostEvent.request_id)),
        func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0),
        func.coalesce(func.avg(CostEvent.input_tokens), 0.0),
        func.coalesce(func.avg(CostEvent.output_tokens), 0.0),
    ).first()

    model_rows = (
        filtered_query.with_entities(
            CostEvent.model_name,
            func.count(CostEvent.cost_event_id).label("events"),
            func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0).label("cost_cents"),
        )
        .group_by(CostEvent.model_name)
        .order_by(func.count(CostEvent.cost_event_id).desc())
        .limit(5)
        .all()
    )

    endpoint_rows = (
        filtered_query.with_entities(
            CostEvent.endpoint_family,
            func.count(CostEvent.cost_event_id).label("events"),
            func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0).label("cost_cents"),
        )
        .group_by(CostEvent.endpoint_family)
        .order_by(func.count(CostEvent.cost_event_id).desc())
        .limit(5)
        .all()
    )

    return {
        "environment": environment,
        "hours": hours,
        "total_events": int(totals[0] or 0),
        "distinct_requests": int(totals[1] or 0),
        "total_estimated_cost_cents": int(totals[2] or 0),
        "avg_input_tokens": float(totals[3] or 0.0),
        "avg_output_tokens": float(totals[4] or 0.0),
        "top_models": [
            {
                "model_name": row[0],
                "events": int(row[1] or 0),
                "cost_cents": int(row[2] or 0),
            }
            for row in model_rows
        ],
        "top_endpoint_families": [
            {
                "endpoint_family": row[0],
                "events": int(row[1] or 0),
                "cost_cents": int(row[2] or 0),
            }
            for row in endpoint_rows
        ],
    }


@router.get("/gateway/endpoints/compatibility")
def endpoint_compatibility(ctx: ActorContext = Depends(get_actor_context)):
    require_role(ctx, GATEWAY_READ_ROLES)
    return {
        "status": "pass",
        "supported_families": [
            "chat.completions",
            "responses",
            "embeddings",
            "images",
            "audio",
            "batches",
            "rerank",
            "messages",
            "a2a",
            "mcp",
        ],
    }


@router.post("/v1/chat/completions", response_model=GatewayOpenAIChatCompletionsResponse)
def gateway_openai_chat_completions(
    payload: GatewayOpenAIChatCompletionsRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-chat-completions-{uuid4()}"
    model_name = str(payload.model or "").strip() or "unknown"
    request_id = f"gw-chat-{uuid4().hex[:16]}"
    selected_provider_id: str | None = None
    selected_route_policy_id: str | None = None

    try:
        require_role(ctx, GATEWAY_INFERENCE_ROLES)
        if bool(payload.stream):
            raise HTTPException(status_code=422, detail="stream=true is not supported by this endpoint yet")

        environment = str(payload.environment or "dev").strip().lower() or "dev"
        request_tag = _normalize_request_tag(payload.request_tag)
        stop_sequences = _normalize_stop_sequences(payload.stop)

        tenant_id = str(payload.tenant_id or "").strip()
        provider_type_from_model, normalized_model_name = _split_provider_model(model_name)

        if payload.route_policy_id:
            route_policy_id = str(payload.route_policy_id).strip()
            route = db.query(RoutePolicy).filter_by(route_policy_id=route_policy_id).first()
            if route is None:
                raise HTTPException(status_code=404, detail="Route policy not found")
            if not tenant_id:
                raise HTTPException(status_code=422, detail="tenant_id is required when route_policy_id is provided")

            fallback = _parse_json_object(route.fallback_policy, "fallback_policy")
            configs = _resolve_route_provider_configs(
                db,
                fallback,
                tenant_id=tenant_id,
                request_tag=request_tag,
                default_strategy=route.load_balancing_strategy or "weighted",
                resource="chat completions",
            )
            if not configs or not configs[0].get("priority_order"):
                raise HTTPException(status_code=422, detail="route policy does not contain provider priority configuration")

            selected = configs[0]["priority_order"][0]
            selected_provider_id = str(selected.get("provider_id") or "").strip() or None
            selected_route_policy_id = route_policy_id
            model_name = str(selected.get("model_name") or model_name).strip() or model_name

            if selected_provider_id:
                provider_type = _resolve_provider_type(db, selected_provider_id)
                _, route_model_name = _split_provider_model(model_name)
                _require_tenant_model_entitlement(
                    db,
                    tenant_id=tenant_id,
                    provider_type=provider_type,
                    model_name=route_model_name,
                )
        elif provider_type_from_model:
            if not tenant_id:
                raise HTTPException(status_code=422, detail="tenant_id is required when model includes provider prefix")
            _require_tenant_model_entitlement(
                db,
                tenant_id=tenant_id,
                provider_type=provider_type_from_model,
                model_name=normalized_model_name,
            )

        user_messages = [
            _message_content_to_text(message.content)
            for message in payload.messages
            if str(message.role or "").strip().lower() == "user"
        ]
        prompt_preview = next((item for item in reversed(user_messages) if item.strip()), "")
        completion_text = (
            f"Simulated completion from {model_name}: {prompt_preview.strip()}"
            if prompt_preview.strip()
            else f"Simulated completion from {model_name}."
        )

        response_format_type = str((payload.response_format or {}).get("type") or "").strip().lower()
        if response_format_type and response_format_type not in {"json_object", "text"}:
            raise HTTPException(status_code=422, detail="response_format.type must be one of: json_object, text")
        if response_format_type == "json_object":
            completion_text = json.dumps({"answer": completion_text}, separators=(",", ":"))

        completion_text, stopped = _apply_stop_sequences(completion_text, stop_sequences)
        finish_reason = "stop"

        if payload.max_tokens is not None:
            words = completion_text.split()
            if len(words) > int(payload.max_tokens):
                completion_text = " ".join(words[: int(payload.max_tokens)]).strip()
                finish_reason = "length"
            elif stopped:
                finish_reason = "stop"

        prompt_tokens = _estimate_token_count("\n".join(_message_content_to_text(item.content) for item in payload.messages))
        completion_tokens = _estimate_token_count(completion_text)
        if payload.max_tokens is not None:
            completion_tokens = min(completion_tokens, int(payload.max_tokens))
        total_tokens = prompt_tokens + completion_tokens

        provider_type_for_cost = "unknown"
        resolved_provider_type_from_model, resolved_model_name = _split_provider_model(model_name)
        if selected_provider_id:
            provider_type_for_cost = _resolve_provider_type(db, selected_provider_id)
        elif resolved_provider_type_from_model:
            provider_type_for_cost = resolved_provider_type_from_model
        cost_model_name = resolved_model_name if resolved_provider_type_from_model else model_name
        model_rates, default_model_rates = _load_model_token_rates(db)
        provider_multipliers, endpoint_multipliers = _load_cloud_component_multipliers(db)
        estimated_cost_cents = _estimate_hop_cost_cents(
            input_tokens=prompt_tokens,
            output_tokens=completion_tokens,
            model_name=cost_model_name,
            provider_type=provider_type_for_cost,
            endpoint_family="chat.completions",
            model_rates=model_rates,
            default_model_rates=default_model_rates,
            provider_multipliers=provider_multipliers,
            endpoint_multipliers=endpoint_multipliers,
        )

        db.add(
            CostEvent(
                cost_event_id=f"cost-{uuid4().hex[:24]}",
                request_id=request_id,
                trace_id=trace_id,
                request_tag=request_tag,
                session_id=str(payload.session_id or f"session-gateway-chat-{ctx.actor_id}").strip(),
                agent_id=str(payload.agent_id or "gateway-openai-chat").strip() or "gateway-openai-chat",
                owner_scope=str(payload.owner_scope or f"actor:{ctx.actor_id}").strip() or f"actor:{ctx.actor_id}",
                environment=environment,
                model_name=model_name,
                endpoint_family="chat.completions",
                input_tokens=prompt_tokens,
                output_tokens=completion_tokens,
                estimated_cost_cents=estimated_cost_cents,
                currency="USD",
            )
        )

        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.chat.completions",
            resource_type="gateway_inference",
            resource_id=model_name,
            trace_id=trace_id,
        )
        db.commit()

        risk_tier, risk_reasons = _assess_gateway_inference_risk(
            model_name=model_name,
            environment=environment,
            has_tool_calls=False,
            selected_provider_id=selected_provider_id,
        )

        return {
            "id": f"chatcmpl-{uuid4().hex[:24]}",
            "object": "chat.completion",
            "created": int(datetime.utcnow().timestamp()),
            "model": model_name,
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": completion_text},
                    "finish_reason": finish_reason,
                }
            ],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
            },
            "request_id": request_id,
            "trace_id": trace_id,
            "risk_tier": risk_tier,
            "risk_reasons": risk_reasons,
            "selected_provider_id": selected_provider_id,
            "route_policy_id": selected_route_policy_id,
        }
    except HTTPException as exc:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.chat.completions",
            resource_type="gateway_inference",
            resource_id=model_name,
            trace_id=trace_id,
            decision_outcome="deny" if exc.status_code == 403 else "warn",
        )
        db.commit()
        raise


@router.post("/v1/responses", response_model=GatewayOpenAIResponsesResponse)
def gateway_openai_responses_create(
    payload: GatewayOpenAIResponsesRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-responses-{uuid4()}"
    model_name = str(payload.model or "").strip() or "unknown"
    request_id = f"gw-resp-{uuid4().hex[:16]}"
    selected_provider_id: str | None = None
    selected_route_policy_id: str | None = None

    try:
        require_role(ctx, GATEWAY_INFERENCE_ROLES)
        if bool(payload.stream):
            raise HTTPException(status_code=422, detail="stream=true is not supported by this endpoint yet")

        environment = str(payload.environment or "dev").strip().lower() or "dev"
        request_tag = _normalize_request_tag(payload.request_tag)
        stop_sequences = _normalize_stop_sequences(payload.stop)
        selected_tool_name = _resolve_responses_tool_selection(payload.tools, payload.tool_choice)

        tenant_id = str(payload.tenant_id or "").strip()
        provider_type_from_model, normalized_model_name = _split_provider_model(model_name)

        if payload.route_policy_id:
            route_policy_id = str(payload.route_policy_id).strip()
            route = db.query(RoutePolicy).filter_by(route_policy_id=route_policy_id).first()
            if route is None:
                raise HTTPException(status_code=404, detail="Route policy not found")
            if not tenant_id:
                raise HTTPException(status_code=422, detail="tenant_id is required when route_policy_id is provided")

            fallback = _parse_json_object(route.fallback_policy, "fallback_policy")
            configs = _resolve_route_provider_configs(
                db,
                fallback,
                tenant_id=tenant_id,
                request_tag=request_tag,
                default_strategy=route.load_balancing_strategy or "weighted",
                resource="responses",
            )
            if not configs or not configs[0].get("priority_order"):
                raise HTTPException(status_code=422, detail="route policy does not contain provider priority configuration")

            selected = configs[0]["priority_order"][0]
            selected_provider_id = str(selected.get("provider_id") or "").strip() or None
            selected_route_policy_id = route_policy_id
            model_name = str(selected.get("model_name") or model_name).strip() or model_name

            if selected_provider_id:
                provider_type = _resolve_provider_type(db, selected_provider_id)
                _, route_model_name = _split_provider_model(model_name)
                _require_tenant_model_entitlement(
                    db,
                    tenant_id=tenant_id,
                    provider_type=provider_type,
                    model_name=route_model_name,
                )
        elif provider_type_from_model:
            if not tenant_id:
                raise HTTPException(status_code=422, detail="tenant_id is required when model includes provider prefix")
            _require_tenant_model_entitlement(
                db,
                tenant_id=tenant_id,
                provider_type=provider_type_from_model,
                model_name=normalized_model_name,
            )

        prompt_preview = _responses_input_to_text(payload.input)
        instruction_text = str(payload.instructions or "").strip()
        effective_prompt = "\n".join(part for part in [instruction_text, prompt_preview] if part).strip()
        output_text = (
            f"Simulated response from {model_name}: {effective_prompt}"
            if effective_prompt
            else f"Simulated response from {model_name}."
        )

        response_format_type = str((payload.response_format or {}).get("type") or "").strip().lower()
        if response_format_type and response_format_type not in {"json_object", "text"}:
            raise HTTPException(status_code=422, detail="response_format.type must be one of: json_object, text")
        if response_format_type == "json_object":
            output_text = json.dumps({"answer": output_text}, separators=(",", ":"))

        output_items: list[dict[str, object]]
        finish_reason = "stop"

        if selected_tool_name:
            call_id = f"call-{uuid4().hex[:12]}"
            tool_arguments = json.dumps({"input": effective_prompt or prompt_preview}, separators=(",", ":"))
            output_text = f"Tool call requested: {selected_tool_name}"
            finish_reason = "tool_calls"
            output_items = [
                {
                    "id": f"resp-out-{uuid4().hex[:16]}",
                    "type": "tool_call",
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_call",
                            "name": selected_tool_name,
                            "arguments": tool_arguments,
                            "call_id": call_id,
                        }
                    ],
                    "finish_reason": finish_reason,
                }
            ]
        else:
            output_text, stopped = _apply_stop_sequences(output_text, stop_sequences)
            if payload.max_output_tokens is not None:
                words = output_text.split()
                if len(words) > int(payload.max_output_tokens):
                    output_text = " ".join(words[: int(payload.max_output_tokens)]).strip()
                    finish_reason = "length"
                elif stopped:
                    finish_reason = "stop"
            output_items = [
                {
                    "id": f"resp-out-{uuid4().hex[:16]}",
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": output_text}],
                    "finish_reason": finish_reason,
                }
            ]

        input_tokens = _estimate_token_count(effective_prompt or _responses_input_to_text(payload.input))
        output_tokens = _estimate_token_count(output_text)
        if payload.max_output_tokens is not None and not selected_tool_name:
            output_tokens = min(output_tokens, int(payload.max_output_tokens))
        total_tokens = input_tokens + output_tokens

        provider_type_for_cost = "unknown"
        resolved_provider_type_from_model, resolved_model_name = _split_provider_model(model_name)
        if selected_provider_id:
            provider_type_for_cost = _resolve_provider_type(db, selected_provider_id)
        elif resolved_provider_type_from_model:
            provider_type_for_cost = resolved_provider_type_from_model
        cost_model_name = resolved_model_name if resolved_provider_type_from_model else model_name

        model_rates, default_model_rates = _load_model_token_rates(db)
        provider_multipliers, endpoint_multipliers = _load_cloud_component_multipliers(db)
        estimated_cost_cents = _estimate_hop_cost_cents(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            model_name=cost_model_name,
            provider_type=provider_type_for_cost,
            endpoint_family="responses",
            model_rates=model_rates,
            default_model_rates=default_model_rates,
            provider_multipliers=provider_multipliers,
            endpoint_multipliers=endpoint_multipliers,
        )

        db.add(
            CostEvent(
                cost_event_id=f"cost-{uuid4().hex[:24]}",
                request_id=request_id,
                trace_id=trace_id,
                request_tag=request_tag,
                session_id=str(payload.session_id or f"session-gateway-responses-{ctx.actor_id}").strip(),
                agent_id=str(payload.agent_id or "gateway-openai-responses").strip() or "gateway-openai-responses",
                owner_scope=str(payload.owner_scope or f"actor:{ctx.actor_id}").strip() or f"actor:{ctx.actor_id}",
                environment=environment,
                model_name=model_name,
                endpoint_family="responses",
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                estimated_cost_cents=estimated_cost_cents,
                currency="USD",
            )
        )

        response_id = f"resp-{uuid4().hex[:24]}"

        db.add(
            OpenAIResponseRecord(
                response_id=response_id,
                request_id=request_id,
                trace_id=trace_id,
                actor_id=ctx.actor_id,
                environment=environment,
                model_name=model_name,
                output_payload=json.dumps(output_items, separators=(",", ":")),
                output_text=output_text,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=total_tokens,
                selected_provider_id=selected_provider_id,
                route_policy_id=selected_route_policy_id,
                status="active",
            )
        )

        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.responses.create",
            resource_type="gateway_inference_response",
            resource_id=response_id,
            trace_id=trace_id,
        )
        db.commit()

        risk_tier, risk_reasons = _assess_gateway_inference_risk(
            model_name=model_name,
            environment=environment,
            has_tool_calls=bool(selected_tool_name),
            selected_provider_id=selected_provider_id,
        )

        return {
            "id": response_id,
            "object": "response",
            "created_at": int(datetime.utcnow().timestamp()),
            "model": model_name,
            "output": output_items,
            "output_text": output_text,
            "usage": {
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": total_tokens,
            },
            "request_id": request_id,
            "trace_id": trace_id,
            "risk_tier": risk_tier,
            "risk_reasons": risk_reasons,
            "selected_provider_id": selected_provider_id,
            "route_policy_id": selected_route_policy_id,
        }
    except HTTPException as exc:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.responses.create",
            resource_type="gateway_inference_response",
            resource_id=model_name,
            trace_id=trace_id,
            decision_outcome="deny" if exc.status_code == 403 else "warn",
        )
        db.commit()
        raise


@router.get("/v1/responses/{response_id}", response_model=GatewayOpenAIResponsesResponse)
def gateway_openai_responses_retrieve(
    response_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-responses-retrieve-{uuid4()}"
    require_role(ctx, GATEWAY_INFERENCE_READ_ROLES)

    row = db.query(OpenAIResponseRecord).filter_by(response_id=str(response_id), status="active").first()
    if row is None:
        raise HTTPException(status_code=404, detail="Response not found")
    if ctx.actor_role == ROLE_AGENT_OWNER and row.actor_id != ctx.actor_id:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.responses.retrieve",
            resource_type="gateway_inference_response",
            resource_id=row.response_id,
            trace_id=trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only access own response records.",
                "actor_role": ctx.actor_role,
                "required_scope": "response.actor_id == requester actor_id",
                "policy_version": "v1",
                "decision_trace_id": "authz-gateway-responses-retrieve-scope-check",
                "remediation_hint": "Use your own response id or use Auditor/Platform Admin role for cross-owner access.",
            },
        )

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.responses.retrieve",
        resource_type="gateway_inference_response",
        resource_id=row.response_id,
        trace_id=trace_id,
    )
    db.commit()
    return _serialize_openai_response_record(row)


@router.get("/v1/responses", response_model=GatewayOpenAIResponsesListResponse)
def gateway_openai_responses_list(
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    model_contains: Optional[str] = Query(default=None),
    output_contains: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-responses-list-{uuid4()}"
    require_role(ctx, GATEWAY_INFERENCE_READ_ROLES)

    query = db.query(OpenAIResponseRecord).filter_by(status="active")
    if ctx.actor_role == ROLE_AGENT_OWNER:
        query = query.filter(OpenAIResponseRecord.actor_id == ctx.actor_id)

    model_contains_value = str(model_contains or "").strip()
    if model_contains_value:
        query = query.filter(OpenAIResponseRecord.model_name.ilike(f"%{model_contains_value}%"))

    output_contains_value = str(output_contains or "").strip()
    if output_contains_value:
        query = query.filter(OpenAIResponseRecord.output_text.ilike(f"%{output_contains_value}%"))

    rows = query.order_by(OpenAIResponseRecord.created_at.desc()).offset(offset).limit(limit).all()

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.responses.list",
        resource_type="gateway_inference_response",
        resource_id="responses",
        trace_id=trace_id,
    )
    db.commit()
    return {"object": "list", "data": [_serialize_openai_response_record(row) for row in rows]}


@router.delete("/v1/responses/{response_id}", response_model=GatewayOpenAIResponsesDeleteResponse)
def gateway_openai_responses_delete(
    response_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-responses-delete-{uuid4()}"
    require_role(ctx, GATEWAY_INFERENCE_DELETE_ROLES)

    row = db.query(OpenAIResponseRecord).filter_by(response_id=str(response_id), status="active").first()
    if row is None:
        raise HTTPException(status_code=404, detail="Response not found")

    if ctx.actor_role == ROLE_AGENT_OWNER and row.actor_id != ctx.actor_id:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.responses.delete",
            resource_type="gateway_inference_response",
            resource_id=row.response_id,
            trace_id=trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only delete own response records.",
                "actor_role": ctx.actor_role,
                "required_scope": "response.actor_id == requester actor_id",
                "policy_version": "v1",
                "decision_trace_id": "authz-gateway-responses-delete-scope-check",
                "remediation_hint": "Delete your own response id or use Platform Admin role for cross-owner deletion.",
            },
        )

    if _is_prod_environment(row.environment):
        try:
            require_dual_approval(ctx)
        except HTTPException as exc:
            create_audit_event(
                db,
                actor_id=ctx.actor_id,
                action_type="gateway.responses.delete",
                resource_type="gateway_inference_response",
                resource_id=row.response_id,
                trace_id=trace_id,
                decision_outcome="deny" if exc.status_code == 403 else "warn",
            )
            db.commit()
            raise

    row.status = "deleted"
    row.deleted_at = datetime.utcnow()

    request_id = f"gw-resp-del-{uuid4().hex[:16]}"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.responses.delete",
        resource_type="gateway_inference_response",
        resource_id=row.response_id,
        trace_id=trace_id,
    )
    db.commit()
    return {
        "id": row.response_id,
        "object": "response.deleted",
        "deleted": True,
        "request_id": request_id,
        "trace_id": trace_id,
    }


@router.post("/v1/files", response_model=GatewayOpenAIFileResponse)
def gateway_openai_files_create(
    payload: GatewayOpenAIFileCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-files-create-{uuid4()}"
    request_id = f"gw-file-{uuid4().hex[:16]}"
    require_role(ctx, GATEWAY_INFERENCE_ROLES)

    environment = str(payload.environment or "dev").strip().lower() or "dev"
    file_id = f"file-{uuid4().hex[:24]}"
    content_type = str(payload.content_type or "application/octet-stream").strip() or "application/octet-stream"
    metadata_json = json.dumps(payload.metadata or {}, separators=(",", ":"))

    record = OpenAIFileRecord(
        file_id=file_id,
        request_id=request_id,
        trace_id=trace_id,
        actor_id=ctx.actor_id,
        environment=environment,
        filename=str(payload.filename).strip(),
        purpose=str(payload.purpose).strip(),
        bytes=int(payload.bytes),
        content_type=content_type,
        metadata_json=metadata_json,
        status="uploaded",
    )
    db.add(record)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.files.create",
        resource_type="gateway_file",
        resource_id=file_id,
        trace_id=trace_id,
    )
    db.commit()
    return _serialize_openai_file_record(record)


@router.get("/v1/files", response_model=GatewayOpenAIFilesListResponse)
def gateway_openai_files_list(
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    filename_contains: Optional[str] = Query(default=None),
    purpose: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-files-list-{uuid4()}"
    require_role(ctx, GATEWAY_INFERENCE_READ_ROLES)

    query = db.query(OpenAIFileRecord).filter(OpenAIFileRecord.status != "deleted")
    if ctx.actor_role == ROLE_AGENT_OWNER:
        query = query.filter(OpenAIFileRecord.actor_id == ctx.actor_id)

    filename_contains_value = str(filename_contains or "").strip()
    if filename_contains_value:
        query = query.filter(OpenAIFileRecord.filename.ilike(f"%{filename_contains_value}%"))

    purpose_value = str(purpose or "").strip()
    if purpose_value:
        query = query.filter(OpenAIFileRecord.purpose == purpose_value)

    status_value = str(status or "").strip()
    if status_value:
        query = query.filter(OpenAIFileRecord.status == status_value)

    rows = query.order_by(OpenAIFileRecord.created_at.desc()).offset(offset).limit(limit).all()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.files.list",
        resource_type="gateway_file",
        resource_id="files",
        trace_id=trace_id,
    )
    db.commit()
    return {"object": "list", "data": [_serialize_openai_file_record(row) for row in rows]}


@router.get("/v1/files/{file_id}", response_model=GatewayOpenAIFileResponse)
def gateway_openai_files_retrieve(
    file_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-files-retrieve-{uuid4()}"
    require_role(ctx, GATEWAY_INFERENCE_READ_ROLES)

    row = db.query(OpenAIFileRecord).filter_by(file_id=str(file_id)).first()
    if row is None or row.status == "deleted":
        raise HTTPException(status_code=404, detail="File not found")
    if ctx.actor_role == ROLE_AGENT_OWNER and row.actor_id != ctx.actor_id:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.files.retrieve",
            resource_type="gateway_file",
            resource_id=row.file_id,
            trace_id=trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only access own file records.",
                "actor_role": ctx.actor_role,
                "required_scope": "file.actor_id == requester actor_id",
                "policy_version": "v1",
                "decision_trace_id": "authz-gateway-files-retrieve-scope-check",
                "remediation_hint": "Use your own file id or use Auditor/Platform Admin role for cross-owner access.",
            },
        )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.files.retrieve",
        resource_type="gateway_file",
        resource_id=row.file_id,
        trace_id=trace_id,
    )
    db.commit()
    return _serialize_openai_file_record(row)


@router.delete("/v1/files/{file_id}", response_model=GatewayOpenAIFileDeleteResponse)
def gateway_openai_files_delete(
    file_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-files-delete-{uuid4()}"
    request_id = f"gw-file-del-{uuid4().hex[:16]}"
    require_role(ctx, GATEWAY_INFERENCE_DELETE_ROLES)

    row = db.query(OpenAIFileRecord).filter_by(file_id=str(file_id)).first()
    if row is None or row.status == "deleted":
        raise HTTPException(status_code=404, detail="File not found")

    if ctx.actor_role == ROLE_AGENT_OWNER and row.actor_id != ctx.actor_id:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.files.delete",
            resource_type="gateway_file",
            resource_id=row.file_id,
            trace_id=trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only delete own file records.",
                "actor_role": ctx.actor_role,
                "required_scope": "file.actor_id == requester actor_id",
                "policy_version": "v1",
                "decision_trace_id": "authz-gateway-files-delete-scope-check",
                "remediation_hint": "Delete your own file id or use Platform Admin role for cross-owner deletion.",
            },
        )

    if _is_prod_environment(row.environment):
        try:
            require_dual_approval(ctx)
        except HTTPException as exc:
            create_audit_event(
                db,
                actor_id=ctx.actor_id,
                action_type="gateway.files.delete",
                resource_type="gateway_file",
                resource_id=row.file_id,
                trace_id=trace_id,
                decision_outcome="deny" if exc.status_code == 403 else "warn",
            )
            db.commit()
            raise

    row.status = "deleted"
    row.deleted_at = datetime.utcnow()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.files.delete",
        resource_type="gateway_file",
        resource_id=row.file_id,
        trace_id=trace_id,
    )
    db.commit()
    return {
        "id": row.file_id,
        "object": "file.deleted",
        "deleted": True,
        "request_id": request_id,
        "trace_id": trace_id,
    }


@router.get("/gateway/mcp/servers", response_model=list[McpServerResponse])
def get_gateway_mcp_servers(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    rows = list_mcp_servers(db)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.mcp.servers.read",
        resource_type="gateway_mcp",
        resource_id="servers",
        trace_id="trace-gateway-mcp-servers-read",
    )
    db.commit()
    return rows


@router.post("/gateway/mcp/servers/{server_id}/tools/list", response_model=McpToolListResponse)
def list_gateway_mcp_tools(
    server_id: str,
    payload: McpToolListRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    trace_id = f"trace-gateway-mcp-tools-list-{server_id}-{uuid4()}"
    try:
        server = resolve_mcp_server(db, server_id)
        tools = mcp_list_tools(db, server)
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.mcp.tools.list",
            resource_type="gateway_mcp",
            resource_id=server_id,
            trace_id=trace_id,
        )
        db.commit()
        return {"server_id": server_id, "tools": tools}
    except HTTPException as exc:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.mcp.tools.list",
            resource_type="gateway_mcp",
            resource_id=server_id,
            trace_id=trace_id,
            decision_outcome="deny" if exc.status_code == 403 else "warn",
        )
        db.commit()
        raise


@router.post("/gateway/mcp/servers/{server_id}/tools/call", response_model=McpToolCallResponse)
def call_gateway_mcp_tool(
    server_id: str,
    payload: McpToolCallRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-mcp-tools-call-{server_id}-{uuid4()}"
    try:
        require_role(ctx, GATEWAY_ADMIN_OR_AI_OPS_ROLES)
        if _is_prod_environment(payload.environment):
            require_dual_approval(ctx)

        server = resolve_mcp_server(db, server_id)
        result = mcp_call_tool(db, server, payload.tool_name, payload.arguments)
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.mcp.tools.call",
            resource_type="gateway_mcp",
            resource_id=server_id,
            trace_id=trace_id,
        )
        db.commit()
        return {
            "server_id": server_id,
            "tool_name": payload.tool_name,
            "result": result,
            "trace_id": trace_id,
        }
    except HTTPException as exc:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.mcp.tools.call",
            resource_type="gateway_mcp",
            resource_id=server_id,
            trace_id=trace_id,
            decision_outcome="deny" if exc.status_code == 403 else "warn",
        )
        db.commit()
        raise


@router.get("/gateway/external-callbacks", response_model=list[GatewayExternalCallbackResponse])
def list_gateway_external_callbacks(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    rows = _load_gateway_external_callbacks(db)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.external_callback.read",
        resource_type="gateway_external_callback",
        resource_id="registry",
        trace_id=f"trace-gateway-external-callbacks-read-{uuid4()}",
    )
    db.commit()
    return rows


@router.get("/gateway/entitlements", response_model=list[GatewayEntitlementResponse])
def list_gateway_entitlements(
    entitlement_id: Optional[str] = Query(default=None),
    action: Optional[str] = Query(default=None),
    tenant_id: Optional[str] = Query(default=None),
    environment: Optional[str] = Query(default=None),
    route_policy_id: Optional[str] = Query(default=None),
    request_tag: Optional[str] = Query(default=None),
    enabled: Optional[bool] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)

    query = db.query(GatewayEntitlement)
    if entitlement_id:
        query = query.filter(GatewayEntitlement.entitlement_id == str(entitlement_id).strip())
    if action:
        query = query.filter(GatewayEntitlement.action == str(action).strip().lower())
    if tenant_id:
        query = query.filter(GatewayEntitlement.tenant_id == str(tenant_id).strip())
    if environment:
        query = query.filter(GatewayEntitlement.environment == str(environment).strip().lower())
    if route_policy_id:
        query = query.filter(GatewayEntitlement.route_policy_id == str(route_policy_id).strip())
    normalized_tag = _normalize_request_tag(request_tag)
    if normalized_tag:
        query = query.filter(GatewayEntitlement.request_tag == normalized_tag)
    if enabled is not None:
        query = query.filter(GatewayEntitlement.enabled == bool(enabled))

    rows = query.order_by(GatewayEntitlement.updated_at.desc()).offset(offset).limit(limit).all()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.entitlement.read",
        resource_type="gateway_entitlement",
        resource_id="catalog",
        trace_id=f"trace-gateway-entitlement-read-{uuid4()}",
    )
    db.commit()
    return rows


@router.put("/gateway/entitlements/{entitlement_id}", response_model=GatewayEntitlementResponse)
def upsert_gateway_entitlement(
    entitlement_id: str,
    payload: GatewayEntitlementUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_AI_OPS_ROLES)
    normalized_environment = str(payload.environment or "dev").strip().lower() or "dev"
    if _is_prod_environment(normalized_environment):
        require_dual_approval(ctx)

    normalized_entitlement_id = str(entitlement_id or "").strip()
    if not normalized_entitlement_id:
        raise HTTPException(status_code=422, detail="entitlement_id is required")

    normalized_action = str(payload.action or "").strip().lower()
    if not normalized_action:
        raise HTTPException(status_code=422, detail="action is required")

    allowed_roles = _parse_entitlement_allowed_roles(payload.allowed_roles)
    normalized_request_tag = _normalize_request_tag(payload.request_tag)

    row = db.query(GatewayEntitlement).filter_by(entitlement_id=normalized_entitlement_id).first()
    if row is None:
        row = GatewayEntitlement(entitlement_id=normalized_entitlement_id)
        db.add(row)

    row.action = normalized_action
    row.tenant_id = str(payload.tenant_id).strip() if payload.tenant_id is not None and str(payload.tenant_id).strip() else None
    row.environment = normalized_environment
    row.route_policy_id = (
        str(payload.route_policy_id).strip() if payload.route_policy_id is not None and str(payload.route_policy_id).strip() else None
    )
    row.request_tag = normalized_request_tag
    row.model_name = str(payload.model_name).strip() if payload.model_name is not None and str(payload.model_name).strip() else None
    row.tool_name = str(payload.tool_name).strip() if payload.tool_name is not None and str(payload.tool_name).strip() else None
    row.allowed_roles = json.dumps(allowed_roles, separators=(",", ":"))
    row.enabled = bool(payload.enabled)
    row.updated_by = ctx.actor_id

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.entitlement.update",
        resource_type="gateway_entitlement",
        resource_id=normalized_entitlement_id,
        trace_id=f"trace-gateway-entitlement-update-{normalized_entitlement_id}",
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/gateway/nhi/inventory", response_model=list[GatewayNhiInventoryRecordResponse])
def list_gateway_nhi_inventory(
    tenant_id: Optional[str] = Query(default=None),
    environment: Optional[str] = Query(default=None),
    source_type: Optional[str] = Query(default=None),
    provider_type: Optional[str] = Query(default=None),
    identity_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    stale_only: bool = Query(default=False),
    missing_owner_only: bool = Query(default=False),
    max_credential_age_days: int = Query(default=90, ge=1, le=3650),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    _sync_gateway_nhi_inventory(db, max_credential_age_days=max_credential_age_days)
    db.flush()

    query = db.query(GatewayNhiInventory)
    if tenant_id:
        query = query.filter(GatewayNhiInventory.tenant_id == str(tenant_id).strip())
    if environment:
        query = query.filter(GatewayNhiInventory.environment == str(environment).strip().lower())
    if source_type:
        query = query.filter(GatewayNhiInventory.source_type == str(source_type).strip().lower())
    if provider_type:
        query = query.filter(GatewayNhiInventory.provider_type == str(provider_type).strip().lower())
    if identity_type:
        query = query.filter(GatewayNhiInventory.identity_type == str(identity_type).strip().lower())
    if status:
        query = query.filter(GatewayNhiInventory.status == str(status).strip().lower())

    rows = query.order_by(GatewayNhiInventory.updated_at.desc()).offset(offset).limit(limit).all()
    now = datetime.utcnow()
    result_rows = [
        _gateway_nhi_record_to_response(row, max_credential_age_days=max_credential_age_days, now=now)
        for row in rows
    ]
    if stale_only:
        result_rows = [row for row in result_rows if row.stale_credential]
    if missing_owner_only:
        result_rows = [row for row in result_rows if row.missing_owner]

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.nhi.inventory.read",
        resource_type="gateway_nhi_inventory",
        resource_id="catalog",
        trace_id=f"trace-gateway-nhi-inventory-read-{uuid4()}",
    )
    db.commit()
    return result_rows


@router.get("/gateway/nhi/hygiene", response_model=GatewayNhiHygieneResponse)
def get_gateway_nhi_hygiene(
    max_credential_age_days: int = Query(default=90, ge=1, le=3650),
    tenant_id: Optional[str] = Query(default=None),
    environment: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    _sync_gateway_nhi_inventory(db, max_credential_age_days=max_credential_age_days)
    db.flush()

    query = db.query(GatewayNhiInventory)
    if tenant_id:
        query = query.filter(GatewayNhiInventory.tenant_id == str(tenant_id).strip())
    if environment:
        query = query.filter(GatewayNhiInventory.environment == str(environment).strip().lower())

    rows = query.all()
    now = datetime.utcnow()
    response_rows = [
        _gateway_nhi_record_to_response(row, max_credential_age_days=max_credential_age_days, now=now)
        for row in rows
    ]
    findings_counter: dict[str, int] = {}
    source_counter: dict[str, int] = {}
    stale_count = 0
    missing_owner_count = 0
    inactive_count = 0
    high_risk_count = 0

    for row in response_rows:
        source_counter[row.source_type] = source_counter.get(row.source_type, 0) + 1
        if row.stale_credential:
            stale_count += 1
        if row.missing_owner:
            missing_owner_count += 1
        if str(row.status or "").strip().lower() != "active":
            inactive_count += 1
        findings = _parse_string_list(row.findings, "findings")
        if "high_risk" in findings:
            high_risk_count += 1
        for finding in findings:
            findings_counter[finding] = findings_counter.get(finding, 0) + 1

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.nhi.hygiene.read",
        resource_type="gateway_nhi_inventory",
        resource_id="hygiene-summary",
        trace_id=f"trace-gateway-nhi-hygiene-read-{uuid4()}",
    )
    db.commit()
    return GatewayNhiHygieneResponse(
        max_credential_age_days=max_credential_age_days,
        total_identities=len(response_rows),
        stale_credentials=stale_count,
        missing_owner=missing_owner_count,
        inactive_identities=inactive_count,
        high_risk_identities=high_risk_count,
        findings_distribution=[
            {"key": key, "count": count} for key, count in sorted(findings_counter.items(), key=lambda item: item[0])
        ],
        source_distribution=[
            {"key": key, "count": count} for key, count in sorted(source_counter.items(), key=lambda item: item[0])
        ],
    )


@router.post("/gateway/access-reviews/campaigns", response_model=GatewayAccessReviewCampaignResponse)
def create_gateway_access_review_campaign(
    payload: GatewayAccessReviewCampaignCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_SECURITY_ROLES)
    environment = str(payload.environment or "dev").strip().lower() or "dev"
    if _is_prod_environment(environment):
        require_dual_approval(ctx)

    campaign = GatewayAccessReviewCampaign(
        campaign_id=f"garc-{uuid4().hex[:16]}",
        campaign_name=str(payload.campaign_name or "").strip(),
        tenant_id=str(payload.tenant_id).strip() if payload.tenant_id is not None and str(payload.tenant_id).strip() else None,
        environment=environment,
        include_disabled=bool(payload.include_disabled),
        status="open",
        reviewer_role=str(payload.reviewer_role or "Security Approver").strip() or "Security Approver",
        created_by=ctx.actor_id,
    )
    db.add(campaign)
    db.flush()

    query = db.query(GatewayEntitlement)
    if campaign.tenant_id:
        query = query.filter(GatewayEntitlement.tenant_id == campaign.tenant_id)
    query = query.filter(GatewayEntitlement.environment == campaign.environment)
    if not campaign.include_disabled:
        query = query.filter(GatewayEntitlement.enabled.is_(True))

    entitlements = query.order_by(GatewayEntitlement.updated_at.desc()).all()
    for entitlement in entitlements:
        db.add(
            GatewayAccessReviewItem(
                review_item_id=f"gari-{uuid4().hex[:16]}",
                campaign_id=campaign.campaign_id,
                entitlement_id=entitlement.entitlement_id,
                decision="pending",
            )
        )

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.access_review.campaign.create",
        resource_type="gateway_access_review_campaign",
        resource_id=campaign.campaign_id,
        trace_id=f"trace-gateway-access-review-create-{campaign.campaign_id}",
    )
    db.commit()
    db.refresh(campaign)
    return _build_campaign_response(db, campaign)


@router.get("/gateway/access-reviews/campaigns/{campaign_id}", response_model=GatewayAccessReviewCampaignResponse)
def get_gateway_access_review_campaign(
    campaign_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    campaign = db.query(GatewayAccessReviewCampaign).filter_by(campaign_id=campaign_id).first()
    if campaign is None:
        raise HTTPException(status_code=404, detail="Access review campaign not found")

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.access_review.campaign.read",
        resource_type="gateway_access_review_campaign",
        resource_id=campaign_id,
        trace_id=f"trace-gateway-access-review-read-{campaign_id}",
    )
    db.commit()
    return _build_campaign_response(db, campaign)


@router.post("/gateway/jit-requests", response_model=GatewayJitAccessRequestResponse)
def create_gateway_jit_access_request(
    payload: GatewayJitAccessRequestCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_AI_OPS_ROLES)
    entitlement = db.query(GatewayEntitlement).filter_by(entitlement_id=payload.entitlement_id).first()
    if entitlement is None:
        raise HTTPException(status_code=404, detail="Gateway entitlement not found")

    environment = str(payload.environment or entitlement.environment or "dev").strip().lower() or "dev"
    request = GatewayJitAccessRequest(
        request_id=f"gjit-{uuid4().hex[:16]}",
        entitlement_id=entitlement.entitlement_id,
        requester_id=ctx.actor_id,
        requester_role=ctx.actor_role,
        justification=str(payload.justification or "").strip(),
        environment=environment,
        requested_duration_minutes=int(payload.requested_duration_minutes),
        status="requested",
    )
    db.add(request)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.jit.request.create",
        resource_type="gateway_jit_access_request",
        resource_id=request.request_id,
        trace_id=f"trace-gateway-jit-create-{request.request_id}",
    )
    db.commit()
    db.refresh(request)
    return request


@router.post("/gateway/jit-requests/{request_id}/approve", response_model=GatewayJitAccessRequestResponse)
def approve_gateway_jit_access_request(
    request_id: str,
    payload: GatewayJitAccessApproveRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_SECURITY_ROLES)
    request = db.query(GatewayJitAccessRequest).filter_by(request_id=request_id).first()
    if request is None:
        raise HTTPException(status_code=404, detail="Gateway JIT request not found")
    if request.status != "requested":
        raise HTTPException(status_code=409, detail="Gateway JIT request is not pending")

    decision = str(payload.decision or "approve").strip().lower()
    if decision == "approve" and _is_prod_environment(request.environment):
        require_dual_approval(ctx)

    request.status = "approved" if decision == "approve" else "denied"
    request.approved_by = ctx.actor_id
    request.approved_role = ctx.actor_role
    request.approved_at = datetime.utcnow()
    if decision == "approve":
        request.expires_at = datetime.utcnow() + timedelta(minutes=int(request.requested_duration_minutes or 60))
    else:
        request.expires_at = None

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.jit.request.approve" if decision == "approve" else "gateway.jit.request.deny",
        resource_type="gateway_jit_access_request",
        resource_id=request.request_id,
        trace_id=f"trace-gateway-jit-approve-{request.request_id}",
    )
    db.commit()
    db.refresh(request)
    return request


@router.get("/gateway/least-privilege/recommendations", response_model=list[GatewayLeastPrivilegeRecommendationResponse])
def list_gateway_least_privilege_recommendations(
    tenant_id: Optional[str] = Query(default=None),
    environment: Optional[str] = Query(default=None),
    entitlement_id: Optional[str] = Query(default=None),
    recommendation_type: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default="pending"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    _refresh_least_privilege_recommendations(db)
    db.flush()

    query = db.query(GatewayLeastPrivilegeRecommendation)
    if tenant_id:
        query = query.filter(GatewayLeastPrivilegeRecommendation.tenant_id == str(tenant_id).strip())
    if environment:
        query = query.filter(GatewayLeastPrivilegeRecommendation.environment == str(environment).strip().lower())
    if entitlement_id:
        query = query.filter(GatewayLeastPrivilegeRecommendation.entitlement_id == str(entitlement_id).strip())
    if recommendation_type:
        query = query.filter(
            GatewayLeastPrivilegeRecommendation.recommendation_type == str(recommendation_type).strip().lower()
        )
    if status:
        query = query.filter(GatewayLeastPrivilegeRecommendation.status == str(status).strip().lower())

    rows = query.order_by(GatewayLeastPrivilegeRecommendation.updated_at.desc()).offset(offset).limit(limit).all()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.least_privilege.read",
        resource_type="gateway_least_privilege_recommendation",
        resource_id="catalog",
        trace_id=f"trace-gateway-lpr-read-{uuid4()}",
    )
    db.commit()
    return rows


@router.post(
    "/gateway/least-privilege/recommendations/{recommendation_id}/apply",
    response_model=GatewayLeastPrivilegeRecommendationResponse,
)
def apply_gateway_least_privilege_recommendation(
    recommendation_id: str,
    payload: GatewayLeastPrivilegeRecommendationApplyRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_AI_OPS_ROLES)
    recommendation = (
        db.query(GatewayLeastPrivilegeRecommendation)
        .filter_by(recommendation_id=recommendation_id)
        .first()
    )
    if recommendation is None:
        raise HTTPException(status_code=404, detail="Least-privilege recommendation not found")
    if recommendation.status != "pending":
        raise HTTPException(status_code=409, detail="Recommendation is not pending")

    entitlement = db.query(GatewayEntitlement).filter_by(entitlement_id=recommendation.entitlement_id).first()
    if entitlement is None:
        raise HTTPException(status_code=404, detail="Gateway entitlement not found")
    if _is_prod_environment(entitlement.environment):
        require_dual_approval(ctx)

    if recommendation.recommendation_type == "role_rightsize_observed":
        proposed_roles = _parse_entitlement_allowed_roles(recommendation.proposed_allowed_roles)
        entitlement.allowed_roles = json.dumps(proposed_roles, separators=(",", ":"))
    elif recommendation.recommendation_type == "disable_unused_entitlement":
        entitlement.enabled = False
    else:
        raise HTTPException(status_code=422, detail="Unsupported recommendation type")

    recommendation.status = "applied"
    recommendation.applied_by = ctx.actor_id
    recommendation.applied_at = datetime.utcnow()
    recommendation.updated_at = datetime.utcnow()

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.least_privilege.apply",
        resource_type="gateway_least_privilege_recommendation",
        resource_id=recommendation_id,
        trace_id=f"trace-gateway-lpr-apply-{recommendation_id}",
    )
    if payload.decision_reason:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.least_privilege.apply.reason",
            resource_type="gateway_least_privilege_recommendation",
            resource_id=f"{recommendation_id}:{str(payload.decision_reason).strip()[:64]}",
            trace_id=f"trace-gateway-lpr-apply-reason-{recommendation_id}",
        )
    db.commit()
    db.refresh(recommendation)
    return recommendation


@router.post(
    "/gateway/external-callbacks",
    response_model=GatewayExternalCallbackResponse,
    summary="Create gateway external callback",
    description=(
        "Registers an outbound callback target for gateway governance events. "
        "Production callbacks require dual approval."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action or dual approval is missing."},
    },
)
def create_gateway_external_callback(
    payload: GatewayExternalCallbackCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_ROLES)
    environment = str(payload.environment or "dev").strip().lower() or "dev"
    if _is_prod_environment(environment):
        require_dual_approval(ctx)

    row = {
        "callback_id": f"cb-{uuid4()}",
        "callback_url": _validate_callback_url(payload.callback_url),
        "event_types": _normalize_callback_events(payload.event_types),
        "environment": environment,
        "redact_sensitive": bool(payload.redact_sensitive),
        "enabled": bool(payload.enabled),
        "description": str(payload.description or "").strip() or None,
        "created_by": ctx.actor_id,
        "created_at": datetime.utcnow().isoformat() + "Z",
        "updated_at": datetime.utcnow().isoformat() + "Z",
    }
    rows = _load_gateway_external_callbacks(db)
    rows.append(row)
    _save_gateway_external_callbacks(db, ctx.actor_id, rows)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.external_callback.create",
        resource_type="gateway_external_callback",
        resource_id=row["callback_id"],
        trace_id=f"trace-gateway-external-callback-create-{row['callback_id']}",
    )
    db.commit()
    return row


@router.patch("/gateway/external-callbacks/{callback_id}", response_model=GatewayExternalCallbackResponse)
def update_gateway_external_callback(
    callback_id: str,
    payload: GatewayExternalCallbackUpdateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_ROLES)
    rows = _load_gateway_external_callbacks(db)
    target = next((row for row in rows if row.get("callback_id") == callback_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="External callback not found")

    next_environment = str(payload.environment if payload.environment is not None else target.get("environment") or "dev").strip().lower() or "dev"
    if _is_prod_environment(next_environment):
        require_dual_approval(ctx)

    if payload.callback_url is not None:
        target["callback_url"] = _validate_callback_url(payload.callback_url)
    if payload.event_types is not None:
        target["event_types"] = _normalize_callback_events(payload.event_types)
    if payload.environment is not None:
        target["environment"] = next_environment
    if payload.redact_sensitive is not None:
        target["redact_sensitive"] = bool(payload.redact_sensitive)
    if payload.enabled is not None:
        target["enabled"] = bool(payload.enabled)
    if payload.description is not None:
        target["description"] = str(payload.description).strip() or None
    target["updated_at"] = datetime.utcnow().isoformat() + "Z"

    _save_gateway_external_callbacks(db, ctx.actor_id, rows)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.external_callback.update",
        resource_type="gateway_external_callback",
        resource_id=callback_id,
        trace_id=f"trace-gateway-external-callback-update-{callback_id}",
    )
    db.commit()
    return target


@router.post(
    "/gateway/external-callbacks/{callback_id}/test-delivery",
    response_model=GatewayExternalCallbackTestResponse,
    summary="Test gateway external callback delivery",
    description=(
        "Runs a simulated callback delivery with optional redacted payload preview. "
        "Production test deliveries require dual approval."
    ),
    responses={
        400: {"description": "External callback is disabled."},
        403: {"description": "Actor role is not allowed for this action or dual approval is missing."},
        404: {"description": "External callback not found."},
    },
)
def test_gateway_external_callback_delivery(
    callback_id: str,
    payload: GatewayExternalCallbackTestRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_ROLES)
    rows = _load_gateway_external_callbacks(db)
    target = next((row for row in rows if row.get("callback_id") == callback_id), None)
    if not target:
        raise HTTPException(status_code=404, detail="External callback not found")
    if not bool(target.get("enabled", True)):
        raise HTTPException(status_code=400, detail="External callback is disabled")

    environment = str(payload.environment or target.get("environment") or "dev").strip().lower() or "dev"
    if _is_prod_environment(environment):
        require_dual_approval(ctx)

    delivered_at = datetime.utcnow().isoformat() + "Z"
    sample = payload.sample_payload if isinstance(payload.sample_payload, dict) else {}
    payload_preview = sanitize_fields(sample) if bool(target.get("redact_sensitive", True)) else dict(sample)
    trace_id = f"trace-gateway-external-callback-test-{callback_id}-{uuid4()}"

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.external_callback.test_delivery",
        resource_type="gateway_external_callback",
        resource_id=callback_id,
        trace_id=trace_id,
    )
    db.commit()
    return {
        "callback_id": callback_id,
        "callback_url": str(target.get("callback_url") or ""),
        "environment": environment,
        "delivery_status": "delivered_simulated",
        "trace_id": trace_id,
        "delivered_at": delivered_at,
        "redaction_applied": bool(target.get("redact_sensitive", True)),
        "payload_preview": payload_preview,
    }


@router.post(
    "/gateway/external-callbacks/export",
    response_model=GatewayExternalCallbackExportResponse,
    summary="Export gateway external callback evidence",
    description="Exports callback registry and related gateway audit event evidence for operator review.",
    responses={
        403: {"description": "Actor role is not allowed for this action."},
    },
)
def export_gateway_external_callbacks(
    payload: GatewayExternalCallbackExportRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    callbacks = _load_gateway_external_callbacks(db)

    query = db.query(AuditEvent).filter(AuditEvent.action_type.like("gateway.%")).order_by(AuditEvent.timestamp.desc())
    if payload.environment:
        env = str(payload.environment).strip().lower()
        query = query.filter(AuditEvent.resource_id.like(f"%{env}%"))
    events = query.limit(int(payload.limit)).all()

    export_id = f"export-{uuid4()}"
    exported_at = datetime.utcnow().isoformat() + "Z"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.external_callback.export",
        resource_type="gateway_external_callback",
        resource_id=export_id,
        trace_id=f"trace-gateway-external-callback-export-{export_id}",
    )
    db.commit()
    return {
        "export_id": export_id,
        "exported_at": exported_at,
        "export_uri": f"evidence://gateway/external-callbacks/{export_id}.json",
        "callback_count": len(callbacks),
        "event_count": len(events),
    }


@router.post(
    "/gateway/governance/evidence/export",
    response_model=GatewayGovernanceEvidenceExportResponse,
    summary="Export gateway governance evidence bundle",
    description="Builds an action-scoped governance evidence bundle from gateway audit events.",
    responses={
        403: {"description": "Actor role is not allowed for this action."},
    },
)
def export_gateway_governance_evidence(
    payload: GatewayGovernanceEvidenceExportRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)

    action_summaries: list[dict[str, object]] = []
    merged_events: dict[str, dict[str, object]] = {}

    for action_type in GATEWAY_GOVERNANCE_EVIDENCE_ACTION_TYPES:
        query = db.query(AuditEvent).filter(AuditEvent.action_type == action_type)
        if payload.decision_outcome:
            query = query.filter(AuditEvent.decision_outcome == payload.decision_outcome)
        rows = query.order_by(AuditEvent.timestamp.desc()).limit(int(payload.limit_per_action)).all()

        latest = rows[0] if rows else None
        action_summaries.append(
            {
                "action_type": action_type,
                "event_count": len(rows),
                "latest_timestamp": latest.timestamp if latest else None,
                "latest_trace_id": latest.trace_id if latest else None,
            }
        )

        for row in rows:
            merged_events[row.audit_event_id] = {
                "audit_event_id": row.audit_event_id,
                "timestamp": row.timestamp,
                "actor_type": row.actor_type,
                "actor_id": row.actor_id,
                "action_type": row.action_type,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
                "trace_id": row.trace_id,
                "decision_outcome": row.decision_outcome,
                "policy_version": row.policy_version,
            }

    sorted_events = sorted(
        merged_events.values(),
        key=lambda item: (item.get("timestamp") or datetime.min),
        reverse=True,
    )
    sorted_action_summaries = sorted(action_summaries, key=lambda item: str(item.get("action_type") or ""))

    export_id = f"export-{uuid4()}"
    exported_at = datetime.utcnow().isoformat() + "Z"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.governance.evidence.export",
        resource_type="gateway_governance_evidence",
        resource_id=export_id,
        trace_id=f"trace-gateway-governance-evidence-export-{export_id}",
    )
    db.commit()

    return {
        "export_id": export_id,
        "exported_at": exported_at,
        "export_uri": f"evidence://gateway/governance/{export_id}.json",
        "bundle_label": payload.bundle_label,
        "event_count": len(sorted_events),
        "action_summaries": sorted_action_summaries,
        "events": sorted_events,
    }


@router.post(
    "/gateway/debug/transform-request",
    summary="Run request transform debug",
    description=(
        "Runs a debug-only request transformation preview with audit evidence. "
        "Reserved for gateway admin and security roles."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action."},
    },
)
def transform_debug(
    request_payload: dict,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_SECURITY_ROLES)
    trace_id = f"trace-transform-{uuid4()}"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.debug.transform_request",
        resource_type="gateway_debug",
        resource_id="transform-request",
        trace_id=trace_id,
    )
    db.commit()
    return {
        "received_at": datetime.utcnow().isoformat(),
        "status": "ok",
        "transformed": request_payload,
        "redaction_applied": True,
    }


@router.post(
    "/gateway/authz/explain",
    response_model=GatewayAuthzExplainResponse,
    summary="Explain gateway authorization decision",
    description=(
        "Simulates gateway authorization evaluation and returns role, dual-approval, and remediation context. "
        "Used for explainability and audit investigations."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action."},
    },
)
def explain_gateway_authorization(
    payload: GatewayAuthzExplainRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)

    action = str(payload.action or "").strip().lower()
    actor_role = str(payload.actor_role or "").strip()
    actor_id = str(payload.actor_id or "explain-actor").strip() or "explain-actor"
    environment = str(payload.environment or "dev").strip().lower() or "dev"
    resource_type = str(payload.resource_type or "gateway_action").strip() or "gateway_action"
    resource_id = str(payload.resource_id or "").strip() or None

    allowed_roles = sorted(GATEWAY_AUTHZ_ACTION_ROLE_MAP.get(action, set()))
    reasons: list[str] = []

    if not allowed_roles:
        decision = "warn"
        decision_trace_id = "authz-gateway-explain-unknown-action"
        reasons.append("action_not_mapped")
        remediation_hint = "Use a supported gateway action key or extend policy mapping."
        requires_dual_approval = False
        required_approver_role = None
    else:
        role_allowed = actor_role in set(allowed_roles) or actor_role in {ROLE_MASTER_ADMIN, ROLE_SUPER_ADMIN}
        if role_allowed:
            reasons.append("role_allowed")
        else:
            reasons.append("role_not_allowed")

        requires_dual_approval = _is_prod_environment(environment) and action in GATEWAY_AUTHZ_PROD_DUAL_APPROVAL_ACTIONS
        required_approver_role = DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT if requires_dual_approval else None

        dual_approval_ok = True
        if requires_dual_approval:
            approver_role = str(payload.approver_role or "").strip()
            approver_id = str(payload.approver_id or "").strip()
            dual_approval_ok = (
                approver_role == DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT
                and bool(approver_id)
                and approver_id != actor_id
            )
            reasons.append("dual_approval_present" if dual_approval_ok else "dual_approval_missing")

        if role_allowed and dual_approval_ok:
            decision = "allow"
            decision_trace_id = "authz-gateway-explain-allow"
            remediation_hint = "No remediation required."
        else:
            decision = "deny"
            decision_trace_id = "authz-gateway-explain-deny"
            if not role_allowed:
                remediation_hint = "Use one of the allowed roles for this action scope."
            else:
                remediation_hint = "Provide Security Approver co-sign headers for prod-sensitive action simulation."

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.authz.explain",
        resource_type=resource_type,
        resource_id=resource_id or action,
        trace_id=f"trace-gateway-authz-explain-{uuid4()}",
        decision_outcome=decision if decision in {"allow", "deny", "warn"} else "warn",
    )
    db.commit()

    return {
        "actor_role": actor_role,
        "actor_id": actor_id,
        "action": action,
        "environment": environment,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "decision": decision,
        "decision_trace_id": decision_trace_id,
        "policy_version": "v1",
        "allowed_roles": allowed_roles,
        "requires_dual_approval": requires_dual_approval,
        "required_approver_role": required_approver_role,
        "reasons": reasons,
        "remediation_hint": remediation_hint,
    }


@router.get("/gateway/decision-traces/{trace_id}", response_model=GatewayDecisionTraceResponse)
def get_gateway_decision_trace(
    trace_id: str,
    limit: int = Query(default=200, ge=1, le=1000),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)

    normalized_trace_id = str(trace_id or "").strip()
    if not normalized_trace_id:
        raise HTTPException(status_code=422, detail="trace_id is required")

    rows = (
        db.query(AuditEvent)
        .filter(AuditEvent.trace_id == normalized_trace_id)
        .order_by(AuditEvent.timestamp.asc())
        .limit(limit)
        .all()
    )
    if not rows:
        raise HTTPException(status_code=404, detail="Decision trace not found")

    outcomes: dict[str, int] = {}
    actions_seen: set[str] = set()
    serialized_events: list[dict[str, object]] = []

    for row in rows:
        outcome = str(row.decision_outcome or "allow").strip().lower() or "allow"
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
        action = str(row.action_type or "").strip()
        if action:
            actions_seen.add(action)
        serialized_events.append(
            {
                "timestamp": row.timestamp,
                "actor_id": row.actor_id,
                "action_type": row.action_type,
                "resource_type": row.resource_type,
                "resource_id": row.resource_id,
                "decision_outcome": outcome,
                "policy_version": str(row.policy_version or "v1"),
            }
        )

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.trace.retrieve",
        resource_type="gateway_trace",
        resource_id=normalized_trace_id,
        trace_id=f"trace-gateway-trace-retrieve-{uuid4()}",
    )
    db.commit()

    return {
        "trace_id": normalized_trace_id,
        "event_count": len(serialized_events),
        "first_seen_at": rows[0].timestamp,
        "last_seen_at": rows[-1].timestamp,
        "actions": sorted(actions_seen),
        "outcomes": outcomes,
        "events": serialized_events,
    }
