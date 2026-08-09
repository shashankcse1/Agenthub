from __future__ import annotations

from datetime import date, datetime, timedelta
import csv
import hashlib
import hmac
import io
import json
import os
import re
import time
from typing import Optional
from urllib.parse import quote
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.api_errors import authz_scope_forbidden, not_found_error, validation_error as api_validation_error
from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import (
    Agent,
    BudgetPolicy,
    CostEvent,
    GatewayLogExportJob,
    SessionRecord,
    SupportedModelCatalogEntry,
)
from app.policy_constants import ROLE_AGENT_OWNER, SUPPORTED_BUDGET_SCOPE_TYPES, COST_SCOPE_AGENT, COST_SCOPE_GROUP, COST_SCOPE_TEAM, COST_SCOPE_USER
from app.router_constants import PLATFORM_ADMIN_EQUIVALENT_ROLES, ROLES_ADMIN_OWNER, ROLES_ADMIN_RELEASE_OWNER
from app.schemas import (
    BudgetPolicyCreateRequest,
    BudgetPolicyResponse,
    BudgetPolicySoftAlertAcknowledgeRequest,
    BudgetPolicyTemporaryIncreaseRequest,
    CostAnomalyResponse,
    CostBreakdownResponse,
    CostComparisonResponse,
    CostEventFeedbackItem,
    CostEventFeedbackLookupResponse,
    CostEventFeedbackRequest,
    CostEventFeedbackResponse,
    CostEventResponse,
    CostPricingCalculateRequest,
    CostPricingCalculateResponse,
    CostPricingCatalogResponse,
    CostLimitEvaluateRequest,
    CostLimitEvaluateResponse,
    CostHierarchyResponse,
    CostHierarchyAlertsResponse,
    CostHierarchyExplainResponse,
    CostLiveResponse,
    CostModelCatalogItemResponse,
    CostModelCatalogResponse,
    CostModelStatsItem,
    CostModelStatsResponse,
    CostModelTimeseriesPoint,
    CostModelTimeseriesResponse,
    CostModelTimeseriesSeries,
    CostRequestItem,
    CostRequestListResponse,
    CostPolicyEvaluateRequest,
    CostPolicyEvaluateResponse,
    CostPropertyStatsItem,
    CostPropertyStatsResponse,
    CostPropertyTimeseriesPoint,
    CostPropertyTimeseriesResponse,
    CostPropertyTimeseriesSeries,
    CostLatencyTimeseriesPoint,
    CostLatencyTimeseriesResponse,
    CostLatencyTimeseriesSeries,
    CostCacheTimeseriesPoint,
    CostCacheTimeseriesResponse,
    CostCacheTimeseriesSeries,
    CostRatingTimeseriesPoint,
    CostRatingTimeseriesResponse,
    CostRatingTimeseriesSeries,
    CostScoreStatsItem,
    CostScoreStatsResponse,
    CostScoreTimeseriesPoint,
    CostScoreTimeseriesResponse,
    CostScoreTimeseriesSeries,
    CostSessionListResponse,
    CostSessionSummaryItem,
    CostSessionTimeseriesPoint,
    CostSessionTimeseriesResponse,
    CostSessionTimeseriesSeries,
    CostSessionTreeNode,
    CostSessionTreeResponse,
    CostUserListResponse,
    CostUserSummaryItem,
    CostUserTimeseriesPoint,
    CostUserTimeseriesResponse,
    CostUserTimeseriesSeries,
    GatewayLogExportCancelResponse,
    GatewayLogExportCreateRequest,
    GatewayLogExportDeleteResponse,
    GatewayLogExportDownloadResponse,
    GatewayLogExportListResponse,
    GatewayLogExportResponse,
    CostAgentTimeseriesPoint,
    CostAgentTimeseriesResponse,
    CostAgentTimeseriesSeries,
    CostEnvironmentTimeseriesPoint,
    CostEnvironmentTimeseriesResponse,
    CostEnvironmentTimeseriesSeries,
    CostEndpointTimeseriesPoint,
    CostEndpointTimeseriesResponse,
    CostEndpointTimeseriesSeries,
    CostCurrencyTimeseriesPoint,
    CostCurrencyTimeseriesResponse,
    CostCurrencyTimeseriesSeries,
    CostProviderTimeseriesPoint,
    CostProviderTimeseriesResponse,
    CostProviderTimeseriesSeries,
    CostTeamTimeseriesPoint,
    CostTeamTimeseriesResponse,
    CostTeamTimeseriesSeries,
    CostGroupTimeseriesPoint,
    CostGroupTimeseriesResponse,
    CostGroupTimeseriesSeries,
    CostProjectTimeseriesPoint,
    CostProjectTimeseriesResponse,
    CostProjectTimeseriesSeries,
    CostFeedbackTimeseriesPoint,
    CostFeedbackTimeseriesResponse,
    CostFeedbackTimeseriesSeries,
    CostSessionPathTimeseriesPoint,
    CostSessionPathTimeseriesResponse,
    CostSessionPathTimeseriesSeries,
    CostSessionNameTimeseriesPoint,
    CostSessionNameTimeseriesResponse,
    CostSessionNameTimeseriesSeries,
    CostPromptIdTimeseriesPoint,
    CostPromptIdTimeseriesResponse,
    CostPromptIdTimeseriesSeries,
    CostApplicationTimeseriesPoint,
    CostApplicationTimeseriesResponse,
    CostApplicationTimeseriesSeries,
    CostCustomerTimeseriesPoint,
    CostCustomerTimeseriesResponse,
    CostCustomerTimeseriesSeries,
    CostDepartmentTimeseriesPoint,
    CostDepartmentTimeseriesResponse,
    CostDepartmentTimeseriesSeries,
    CostFeatureTimeseriesPoint,
    CostFeatureTimeseriesResponse,
    CostFeatureTimeseriesSeries,
    CostRegionTimeseriesPoint,
    CostRegionTimeseriesResponse,
    CostRegionTimeseriesSeries,
    CostWorkspaceTimeseriesPoint,
    CostWorkspaceTimeseriesResponse,
    CostWorkspaceTimeseriesSeries,
    CostProductTimeseriesPoint,
    CostProductTimeseriesResponse,
    CostProductTimeseriesSeries,
    CostServiceTimeseriesPoint,
    CostServiceTimeseriesResponse,
    CostServiceTimeseriesSeries,
    CostTenantTimeseriesPoint,
    CostTenantTimeseriesResponse,
    CostTenantTimeseriesSeries,
    CostChannelTimeseriesPoint,
    CostChannelTimeseriesResponse,
    CostChannelTimeseriesSeries,
    CostCampaignTimeseriesPoint,
    CostCampaignTimeseriesResponse,
    CostCampaignTimeseriesSeries,
    CostBrandTimeseriesPoint,
    CostBrandTimeseriesResponse,
    CostBrandTimeseriesSeries,
    CostMarketTimeseriesPoint,
    CostMarketTimeseriesResponse,
    CostMarketTimeseriesSeries,
    CostSegmentTimeseriesPoint,
    CostSegmentTimeseriesResponse,
    CostSegmentTimeseriesSeries,
    CostAccountTimeseriesPoint,
    CostAccountTimeseriesResponse,
    CostAccountTimeseriesSeries,
    CostOrgTimeseriesPoint,
    CostOrgTimeseriesResponse,
    CostOrgTimeseriesSeries,
    CostCostCenterTimeseriesPoint,
    CostCostCenterTimeseriesResponse,
    CostCostCenterTimeseriesSeries,
    CostBusinessUnitTimeseriesPoint,
    CostBusinessUnitTimeseriesResponse,
    CostBusinessUnitTimeseriesSeries,
    CostSiteTimeseriesPoint,
    CostSiteTimeseriesResponse,
    CostSiteTimeseriesSeries,
    CostSkuTimeseriesPoint,
    CostSkuTimeseriesResponse,
    CostSkuTimeseriesSeries,
    CostLineTimeseriesPoint,
    CostLineTimeseriesResponse,
    CostLineTimeseriesSeries,
    CostTierTimeseriesPoint,
    CostTierTimeseriesResponse,
    CostTierTimeseriesSeries,
    CostStageTimeseriesPoint,
    CostStageTimeseriesResponse,
    CostStageTimeseriesSeries,
    CostPlatformTimeseriesPoint,
    CostPlatformTimeseriesResponse,
    CostPlatformTimeseriesSeries,
    CostDeviceTimeseriesPoint,
    CostDeviceTimeseriesResponse,
    CostDeviceTimeseriesSeries,
    CostClientTimeseriesPoint,
    CostClientTimeseriesResponse,
    CostClientTimeseriesSeries,
    CostBrowserTimeseriesPoint,
    CostBrowserTimeseriesResponse,
    CostBrowserTimeseriesSeries,
    CostReleaseTimeseriesPoint,
    CostReleaseTimeseriesResponse,
    CostReleaseTimeseriesSeries,
    CostLocaleTimeseriesPoint,
    CostLocaleTimeseriesResponse,
    CostLocaleTimeseriesSeries,
    CostCountryTimeseriesPoint,
    CostCountryTimeseriesResponse,
    CostCountryTimeseriesSeries,
    CostTimezoneTimeseriesPoint,
    CostTimezoneTimeseriesResponse,
    CostTimezoneTimeseriesSeries,
    CostLanguageTimeseriesPoint,
    CostLanguageTimeseriesResponse,
    CostLanguageTimeseriesSeries,
    CostCityTimeseriesPoint,
    CostCityTimeseriesResponse,
    CostCityTimeseriesSeries,
    CostContinentTimeseriesPoint,
    CostContinentTimeseriesResponse,
    CostContinentTimeseriesSeries,
    CostIspTimeseriesPoint,
    CostIspTimeseriesResponse,
    CostIspTimeseriesSeries,
    CostAsnTimeseriesPoint,
    CostAsnTimeseriesResponse,
    CostAsnTimeseriesSeries,
    CostSdkTimeseriesPoint,
    CostSdkTimeseriesResponse,
    CostSdkTimeseriesSeries,
    CostFrameworkTimeseriesPoint,
    CostFrameworkTimeseriesResponse,
    CostFrameworkTimeseriesSeries,
    CostRuntimeTimeseriesPoint,
    CostRuntimeTimeseriesResponse,
    CostRuntimeTimeseriesSeries,
    CostLibraryTimeseriesPoint,
    CostLibraryTimeseriesResponse,
    CostLibraryTimeseriesSeries,
    CostHostTimeseriesPoint,
    CostHostTimeseriesResponse,
    CostHostTimeseriesSeries,
    CostDatacenterTimeseriesPoint,
    CostDatacenterTimeseriesResponse,
    CostDatacenterTimeseriesSeries,
    CostAzTimeseriesPoint,
    CostAzTimeseriesResponse,
    CostAzTimeseriesSeries,
    CostEdgeTimeseriesPoint,
    CostEdgeTimeseriesResponse,
    CostEdgeTimeseriesSeries,
    CostColoTimeseriesPoint,
    CostColoTimeseriesResponse,
    CostColoTimeseriesSeries,
    CostClusterTimeseriesPoint,
    CostClusterTimeseriesResponse,
    CostClusterTimeseriesSeries,
    CostPodTimeseriesPoint,
    CostPodTimeseriesResponse,
    CostPodTimeseriesSeries,
    CostNamespaceTimeseriesPoint,
    CostNamespaceTimeseriesResponse,
    CostNamespaceTimeseriesSeries,
    CostNodeTimeseriesPoint,
    CostNodeTimeseriesResponse,
    CostNodeTimeseriesSeries,
    CostToolTimeseriesPoint,
    CostToolTimeseriesResponse,
    CostToolTimeseriesSeries,
    CostWorkflowTimeseriesPoint,
    CostWorkflowTimeseriesResponse,
    CostWorkflowTimeseriesSeries,
    CostExperimentTimeseriesPoint,
    CostExperimentTimeseriesResponse,
    CostExperimentTimeseriesSeries,
    CostVariantTimeseriesPoint,
    CostVariantTimeseriesResponse,
    CostVariantTimeseriesSeries,
    CostDeploymentTimeseriesPoint,
    CostDeploymentTimeseriesResponse,
    CostDeploymentTimeseriesSeries,
    CostVersionTimeseriesPoint,
    CostVersionTimeseriesResponse,
    CostVersionTimeseriesSeries,
    CostCanaryTimeseriesPoint,
    CostCanaryTimeseriesResponse,
    CostCanaryTimeseriesSeries,
    CostShadowTimeseriesPoint,
    CostShadowTimeseriesResponse,
    CostShadowTimeseriesSeries,
    CostRolloutTimeseriesPoint,
    CostRolloutTimeseriesResponse,
    CostRolloutTimeseriesSeries,
    CostRouteTimeseriesPoint,
    CostRouteTimeseriesResponse,
    CostRouteTimeseriesSeries,
    CostBatchTimeseriesPoint,
    CostBatchTimeseriesResponse,
    CostBatchTimeseriesSeries,
    CostJobTimeseriesPoint,
    CostJobTimeseriesResponse,
    CostJobTimeseriesSeries,
    CostQueueTimeseriesPoint,
    CostQueueTimeseriesResponse,
    CostQueueTimeseriesSeries,
    CostTopicTimeseriesPoint,
    CostTopicTimeseriesResponse,
    CostTopicTimeseriesSeries,
    CostPipelineTimeseriesPoint,
    CostPipelineTimeseriesResponse,
    CostPipelineTimeseriesSeries,
    CostRunTimeseriesPoint,
    CostRunTimeseriesResponse,
    CostRunTimeseriesSeries,
    CostWorkerTimeseriesPoint,
    CostWorkerTimeseriesResponse,
    CostWorkerTimeseriesSeries,
    CostSlotTimeseriesPoint,
    CostSlotTimeseriesResponse,
    CostSlotTimeseriesSeries,
    CostTaskTimeseriesPoint,
    CostTaskTimeseriesResponse,
    CostTaskTimeseriesSeries,
    CostStepTimeseriesPoint,
    CostStepTimeseriesResponse,
    CostStepTimeseriesSeries,
    CostReplicaTimeseriesPoint,
    CostReplicaTimeseriesResponse,
    CostReplicaTimeseriesSeries,
    CostShardTimeseriesPoint,
    CostShardTimeseriesResponse,
    CostShardTimeseriesSeries,
    CostPartitionTimeseriesPoint,
    CostPartitionTimeseriesResponse,
    CostPartitionTimeseriesSeries,
    CostConsumerTimeseriesPoint,
    CostConsumerTimeseriesResponse,
    CostConsumerTimeseriesSeries,
    CostProducerTimeseriesPoint,
    CostProducerTimeseriesResponse,
    CostProducerTimeseriesSeries,
    CostGpuTimeseriesPoint,
    CostGpuTimeseriesResponse,
    CostGpuTimeseriesSeries,
    CostAcceleratorTimeseriesPoint,
    CostAcceleratorTimeseriesResponse,
    CostAcceleratorTimeseriesSeries,
    CostCellTimeseriesPoint,
    CostCellTimeseriesResponse,
    CostCellTimeseriesSeries,
    CostZoneTimeseriesPoint,
    CostZoneTimeseriesResponse,
    CostZoneTimeseriesSeries,
    CostRackTimeseriesPoint,
    CostRackTimeseriesResponse,
    CostRackTimeseriesSeries,
    CostPoolTimeseriesPoint,
    CostPoolTimeseriesResponse,
    CostPoolTimeseriesSeries,
    CostFleetTimeseriesPoint,
    CostFleetTimeseriesResponse,
    CostFleetTimeseriesSeries,
    CostLeaseTimeseriesPoint,
    CostLeaseTimeseriesResponse,
    CostLeaseTimeseriesSeries,
    CostQuotaTimeseriesPoint,
    CostQuotaTimeseriesResponse,
    CostQuotaTimeseriesSeries,
    CostCapacityTimeseriesPoint,
    CostCapacityTimeseriesResponse,
    CostCapacityTimeseriesSeries,
    CostReservationTimeseriesPoint,
    CostReservationTimeseriesResponse,
    CostReservationTimeseriesSeries,
    CostOsTimeseriesPoint,
    CostOsTimeseriesResponse,
    CostOsTimeseriesSeries,
    CostOwnerTimeseriesPoint,
    CostOwnerTimeseriesResponse,
    CostOwnerTimeseriesSeries,
    CostTagTimeseriesPoint,
    CostTagTimeseriesResponse,
    CostTagTimeseriesSeries,
    CostTrackSpendRequest,
    CostTimeseriesResponse,
)
from app.security import ActorContext, get_actor_context, require_role
from app.services.audit import create_audit_event
from app.services.cost_limits import (
    build_actor_cost_hierarchy,
    build_user_membership_index,
    evaluate_actor_cost_limits,
    event_matches_hierarchy_dimension,
    explain_cost_hierarchy_scope,
    find_active_budget,
    hierarchy_attribution_keys,
    resolve_actor_directory_scopes,
    rollup_owner_scopes_for_scope,
    sum_scope_cost_cents,
    temporary_increase_is_active,
)
from app.services.cost_windows import (
    build_period_comparison,
    normalize_window_type,
    project_window_spend,
    window_start_for_budget,
)
from app.services.gateway_inference import infer_provider_type_from_model
from app.services.scope_registry import normalize_scope_id_list, normalize_scope_reference
from app.services.runtime_config import get_runtime_config, get_runtime_config_int
from app.models import DirectoryGroupMembership, DirectoryTeamMembership
from app.runtime_constants import (
    RUNTIME_CONFIG_COST_CLOUD_COMPONENT_MULTIPLIERS_JSON,
    RUNTIME_CONFIG_COST_MODEL_TOKEN_RATES_JSON,
    RUNTIME_CONFIG_COST_PROVIDER_DISCOUNTS_JSON,
)

router = APIRouter()
logger = get_logger(__name__)
REQUEST_TAG_PATTERN = re.compile(r"^[a-zA-Z0-9._:-]{1,64}$")
LOG_EXPORT_SIGNED_URL_TTL_SECONDS = 15 * 60
LOG_EXPORT_SIGNED_URL_TTL_MAX_SECONDS = 60 * 60


def _log_export_signing_secret() -> bytes:
    raw = (
        os.getenv("GATEWAY_LOG_EXPORT_SIGNING_SECRET")
        or os.getenv("SESSION_TOKEN_SECRET")
        or "dev-session-secret-change-me"
    )
    return str(raw).encode("utf-8")


def _sign_log_export_download(*, export_id: str, actor_id: str, exp: int) -> str:
    message = f"{export_id}|{actor_id}|{int(exp)}".encode("utf-8")
    return hmac.new(_log_export_signing_secret(), message, hashlib.sha256).hexdigest()


def _build_signed_log_export_url(
    *,
    export_id: str,
    actor_id: str,
    ttl_seconds: int = LOG_EXPORT_SIGNED_URL_TTL_SECONDS,
) -> tuple[str, int]:
    bounded_ttl = max(60, min(int(ttl_seconds or LOG_EXPORT_SIGNED_URL_TTL_SECONDS), LOG_EXPORT_SIGNED_URL_TTL_MAX_SECONDS))
    exp = int(time.time()) + bounded_ttl
    sig = _sign_log_export_download(export_id=str(export_id), actor_id=str(actor_id), exp=exp)
    path = f"/v1/logs/exports/{quote(str(export_id), safe='')}/content"
    return f"{path}?exp={exp}&sig={sig}", exp


def _verify_signed_log_export(*, export_id: str, actor_id: str, exp: int, sig: str) -> bool:
    try:
        exp_value = int(exp)
    except (TypeError, ValueError):
        return False
    now = int(time.time())
    if exp_value < now:
        return False
    # Reject absurdly far-future expiries (clock skew + max TTL buffer).
    if exp_value > now + LOG_EXPORT_SIGNED_URL_TTL_MAX_SECONDS + 120:
        return False
    expected = _sign_log_export_download(export_id=str(export_id), actor_id=str(actor_id), exp=exp_value)
    provided = str(sig or "").strip().lower()
    if not provided or len(provided) != len(expected):
        return False
    return hmac.compare_digest(expected, provided)


def _normalize_request_tag(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if not REQUEST_TAG_PATTERN.match(raw):
        raise api_validation_error(
            "request_tag must match ^[a-zA-Z0-9._:-]{1,64}$",
            decision_trace_id="cost-request-tag-invalid",
            status_code=422,
        )
    return raw


def _parse_runtime_json_object(raw: str, fallback: dict) -> dict:
    try:
        parsed = json.loads(raw)
    except Exception:
        return fallback
    return parsed if isinstance(parsed, dict) else fallback


def _parse_non_negative_float(value: object, default: float) -> float:
    try:
        parsed = float(value)
    except Exception:
        return default
    return parsed if parsed >= 0 else default


def _parse_positive_float(value: object, default: float) -> float:
    parsed = _parse_non_negative_float(value, default)
    return parsed if parsed > 0 else default


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
        model_blocks = {key: value for key, value in parsed.items() if key not in {"default", "models"} and isinstance(value, dict)}

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


def _load_provider_discounts(db: Session) -> tuple[dict[str, float], dict[str, float]]:
    fallback_raw = '{"provider_type":{"aws":0.0,"azure":0.0,"gcp":0.0,"openai":0.0,"anthropic":0.0},"models":{}}'
    raw = get_runtime_config(db, RUNTIME_CONFIG_COST_PROVIDER_DISCOUNTS_JSON, fallback_raw)
    parsed = _parse_runtime_json_object(raw, {"provider_type": {}, "models": {}})

    provider_map_raw = parsed.get("provider_type") if isinstance(parsed.get("provider_type"), dict) else {}
    model_map_raw = parsed.get("models") if isinstance(parsed.get("models"), dict) else {}

    provider_map: dict[str, float] = {}
    model_map: dict[str, float] = {}

    for key, value in provider_map_raw.items():
        provider_map[str(key or "").strip().lower()] = max(0.0, min(95.0, _parse_non_negative_float(value, 0.0)))
    for key, value in model_map_raw.items():
        model_map[str(key or "").strip().lower()] = max(0.0, min(95.0, _parse_non_negative_float(value, 0.0)))

    return provider_map, model_map


def _calculate_estimated_cost_cents(
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
    provider_discounts: dict[str, float],
    model_discounts: dict[str, float],
    custom_input_rate: float | None = None,
    custom_output_rate: float | None = None,
    custom_discount_percent: float | None = None,
) -> CostPricingCalculateResponse:
    normalized_model = str(model_name or "").strip().lower()
    normalized_provider_type = str(provider_type or "").strip().lower()
    normalized_endpoint_family = str(endpoint_family or "").strip().lower()

    rates = model_rates.get(normalized_model, default_model_rates)
    input_rate = _parse_non_negative_float(rates.get("input_cents_per_1k"), default_model_rates["input_cents_per_1k"])
    output_rate = _parse_non_negative_float(rates.get("output_cents_per_1k"), default_model_rates["output_cents_per_1k"])
    if custom_input_rate is not None:
        input_rate = max(0.0, float(custom_input_rate))
    if custom_output_rate is not None:
        output_rate = max(0.0, float(custom_output_rate))

    provider_multiplier = _parse_positive_float(provider_multipliers.get(normalized_provider_type, 1.0), 1.0)
    endpoint_multiplier = _parse_positive_float(endpoint_multipliers.get(normalized_endpoint_family, 1.0), 1.0)
    provider_discount = max(0.0, min(95.0, _parse_non_negative_float(provider_discounts.get(normalized_provider_type, 0.0), 0.0)))
    model_discount = max(0.0, min(95.0, _parse_non_negative_float(model_discounts.get(normalized_model, 0.0), 0.0)))
    custom_discount = max(0.0, min(95.0, float(custom_discount_percent or 0.0)))
    applied_discount = min(95.0, provider_discount + model_discount + custom_discount)

    base_cost = ((max(0, input_tokens) / 1000.0) * input_rate) + ((max(0, output_tokens) / 1000.0) * output_rate)
    weighted = base_cost * provider_multiplier * endpoint_multiplier
    discounted = weighted * (1.0 - applied_discount / 100.0)

    base_cents = 0 if weighted <= 0 else max(1, int(round(weighted)))
    estimated_cents = 0 if discounted <= 0 else max(1, int(round(discounted)))

    return CostPricingCalculateResponse(
        provider_type=normalized_provider_type,
        model_name=str(model_name or "").strip(),
        endpoint_family=normalized_endpoint_family,
        input_tokens=max(0, int(input_tokens or 0)),
        output_tokens=max(0, int(output_tokens or 0)),
        input_cents_per_1k=input_rate,
        output_cents_per_1k=output_rate,
        provider_multiplier=provider_multiplier,
        endpoint_multiplier=endpoint_multiplier,
        provider_discount_percent=provider_discount,
        model_discount_percent=model_discount,
        custom_discount_percent=custom_discount,
        applied_discount_percent=applied_discount,
        base_cost_cents=base_cents,
        estimated_cost_cents=estimated_cents,
    )


def _sum_cost_cents(db: Session, after_ts: Optional[datetime] = None, **filters: str) -> int:
    query = db.query(func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0))
    if after_ts:
        query = query.filter(CostEvent.timestamp >= after_ts)
    for field, value in filters.items():
        query = query.filter(getattr(CostEvent, field) == value)
    return int(query.scalar() or 0)


def _owned_agent_ids(db: Session, actor_id: str) -> list[str]:
    return [row[0] for row in db.query(Agent.agent_id).filter(Agent.owner_id == actor_id).all()]


def _effective_budget_cents(budget: BudgetPolicy) -> int:
    base = int(budget.budget_amount_cents or 0)
    extra = int(getattr(budget, "temporary_increase_cents", 0) or 0)
    expires_at = getattr(budget, "temporary_increase_expires_at", None)
    if extra <= 0:
        return base
    if expires_at is None or expires_at >= datetime.utcnow():
        return base + extra
    return base


def _validate_window_type(window_type: str) -> str:
    try:
        return normalize_window_type(window_type)
    except ValueError as exc:
        raise api_validation_error(str(exc), decision_trace_id="cost-window-type-invalid") from exc


def _cost_scope_forbidden(ctx: ActorContext, message: str, decision_trace_id: str) -> None:
    raise authz_scope_forbidden(
        message=message,
        actor_role=ctx.actor_role,
        required_scope="cost scope manageable by actor",
        decision_trace_id=decision_trace_id,
        remediation_hint="Use Platform Admin or scope owner permissions for this cost operation.",
    )


def _serialize_budget_policy(
    budget: BudgetPolicy,
    db: Session | None = None,
    *,
    environment: str | None = None,
) -> dict:
    payload = BudgetPolicyResponse.model_validate(budget).model_dump()
    payload["effective_budget_cents"] = _effective_budget_cents(budget)
    spend_cents = 0
    hours_spend_cents = 0
    utilization = 0.0
    env = str(environment or "").strip() or None
    if db is not None:
        after_ts = window_start_for_budget(budget, budget.window_type)
        hours_after = datetime.utcnow() - timedelta(hours=24)
        spend_cents = sum_scope_cost_cents(
            db,
            scope_type=str(budget.scope_type),
            scope_id=str(budget.scope_id),
            after_ts=after_ts,
            environment=env,
        )
        hours_spend_cents = sum_scope_cost_cents(
            db,
            scope_type=str(budget.scope_type),
            scope_id=str(budget.scope_id),
            after_ts=hours_after,
            environment=env,
        )
        effective = int(payload["effective_budget_cents"] or 0)
        if effective > 0:
            utilization = round((spend_cents / effective) * 100.0, 2)
    payload["current_spend_cents"] = spend_cents
    payload["hours_spend_cents"] = hours_spend_cents
    payload["utilization_percent"] = utilization
    payload["temporary_increase_active"] = temporary_increase_is_active(budget)
    soft_enabled = bool(getattr(budget, "soft_alert_enabled", True))
    if utilization >= float(budget.hard_limit_percent or 100):
        payload["decision"] = "deny"
        payload["recommended_action"] = budget.action_on_hard_limit
        payload["soft_alert_active"] = False
    elif utilization >= float(budget.soft_limit_percent or 100):
        payload["decision"] = "warn"
        payload["recommended_action"] = budget.action_on_soft_limit if soft_enabled else "none"
        payload["soft_alert_active"] = soft_enabled
    else:
        payload["decision"] = "allow"
        payload["recommended_action"] = "none"
        payload["soft_alert_active"] = False
    return payload


def _recent_cost_identifiers(
    db: Session,
    *,
    agent_ids: Optional[list[str]] = None,
    limit: int = 20,
) -> tuple[list[str], list[str]]:
    since = datetime.utcnow() - timedelta(days=7)
    query = (
        db.query(CostEvent.session_id, CostEvent.agent_id)
        .filter(CostEvent.timestamp >= since)
        .order_by(CostEvent.timestamp.desc())
        .limit(500)
    )
    if agent_ids is not None:
        if not agent_ids:
            return [], []
        query = query.filter(CostEvent.agent_id.in_(agent_ids))

    sessions: list[str] = []
    agents: list[str] = []
    seen_sessions: set[str] = set()
    seen_agents: set[str] = set()
    for session_id, agent_id in query.all():
        session_text = str(session_id or "").strip()
        agent_text = str(agent_id or "").strip()
        if session_text and session_text not in seen_sessions:
            seen_sessions.add(session_text)
            sessions.append(session_text)
        if agent_text and agent_text not in seen_agents:
            seen_agents.add(agent_text)
            agents.append(agent_text)
        if len(sessions) >= limit and len(agents) >= limit:
            break
    return sessions[:limit], agents[:limit]


def _is_jwt_team(team_id: str) -> bool:
    normalized = str(team_id or "").strip().lower()
    return normalized.startswith("jwt-") or normalized.startswith("jwt:")


def _ensure_default_jwt_team_budget(db: Session, team_id: str, actor_id: str) -> None:
    if not _is_jwt_team(team_id):
        return
    existing = (
        db.query(BudgetPolicy)
        .filter_by(scope_type=COST_SCOPE_TEAM, scope_id=team_id, status="active")
        .order_by(BudgetPolicy.created_at.desc())
        .first()
    )
    if existing:
        return

    default_budget_cents = get_runtime_config_int(db, "cost.jwt_team.default_budget_cents", 50000)
    default_soft_limit = get_runtime_config_int(db, "cost.jwt_team.default_soft_limit_percent", 80)
    default_hard_limit = get_runtime_config_int(db, "cost.jwt_team.default_hard_limit_percent", 100)

    policy = BudgetPolicy(
        budget_policy_id=str(uuid4()),
        scope_type=COST_SCOPE_TEAM,
        scope_id=team_id,
        budget_amount_cents=default_budget_cents,
        window_type="daily",
        soft_limit_percent=max(1, min(default_soft_limit, 100)),
        hard_limit_percent=max(1, min(default_hard_limit, 100)),
        action_on_soft_limit="warn",
        action_on_hard_limit="block",
        reset_timezone="UTC",
        reset_hour_local=0,
        status="active",
    )
    db.add(policy)
    create_audit_event(
        db,
        actor_id=actor_id,
        action_type="cost.budget.auto_create_jwt_team",
        resource_type="budget_policy",
        resource_id=policy.budget_policy_id,
        trace_id=f"trace-{policy.budget_policy_id}",
    )


def _is_budget_scope_manageable(db: Session, ctx: ActorContext, scope_type: str, scope_id: str) -> bool:
    if ctx.actor_role in PLATFORM_ADMIN_EQUIVALENT_ROLES:
        return True
    if ctx.actor_role != ROLE_AGENT_OWNER:
        return False
    if scope_type in {"user", "owner", "actor"}:
        return scope_id == ctx.actor_id
    if scope_type == COST_SCOPE_TEAM:
        return db.query(DirectoryTeamMembership).filter_by(team_id=scope_id, user_id=ctx.actor_id).first() is not None
    if scope_type == COST_SCOPE_GROUP:
        return (
            db.query(DirectoryGroupMembership).filter_by(group_id=scope_id, user_id=ctx.actor_id).first() is not None
        )
    if scope_type == "agent":
        return db.query(Agent).filter_by(agent_id=scope_id, owner_id=ctx.actor_id).first() is not None
    return False


def _split_owner_scope(owner_scope: str) -> tuple[str, str]:
    raw = str(owner_scope or "").strip()
    if ":" not in raw:
        return "all", raw or "unscoped"
    scope_type, scope_id = raw.split(":", 1)
    return scope_type.strip().lower() or "all", scope_id.strip() or "unscoped"


def _floor_hour(value: datetime) -> datetime:
    return value.replace(minute=0, second=0, microsecond=0)


@router.get("/cost/live", response_model=CostLiveResponse)
def get_live_cost(db: Session = Depends(get_db), ctx: ActorContext = Depends(get_actor_context)):
    require_role(ctx, ROLES_ADMIN_OWNER)
    now = datetime.utcnow()
    hour_ts = now - timedelta(hours=1)
    day_ts = now - timedelta(days=1)

    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return {
                "spend_last_hour_cents": 0,
                "spend_last_day_cents": 0,
                "burn_rate_cents_per_hour": 0,
                "event_count_last_day": 0,
                "recent_sessions": [],
                "recent_agents": [],
            }

        spend_last_hour = int(
            db.query(func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0))
            .filter(CostEvent.timestamp >= hour_ts, CostEvent.agent_id.in_(owned_agent_ids))
            .scalar()
            or 0
        )
        spend_last_day = int(
            db.query(func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0))
            .filter(CostEvent.timestamp >= day_ts, CostEvent.agent_id.in_(owned_agent_ids))
            .scalar()
            or 0
        )
        event_count_last_day = (
            db.query(func.count(CostEvent.cost_event_id))
            .filter(CostEvent.timestamp >= day_ts, CostEvent.agent_id.in_(owned_agent_ids))
            .scalar()
            or 0
        )
        recent_sessions, recent_agents = _recent_cost_identifiers(db, agent_ids=owned_agent_ids)
    else:
        spend_last_hour = _sum_cost_cents(db, after_ts=hour_ts)
        spend_last_day = _sum_cost_cents(db, after_ts=day_ts)
        event_count_last_day = (
            db.query(func.count(CostEvent.cost_event_id)).filter(CostEvent.timestamp >= day_ts).scalar() or 0
        )
        recent_sessions, recent_agents = _recent_cost_identifiers(db)

    return {
        "spend_last_hour_cents": spend_last_hour,
        "spend_last_day_cents": spend_last_day,
        "burn_rate_cents_per_hour": spend_last_hour,
        "event_count_last_day": int(event_count_last_day),
        "recent_sessions": recent_sessions,
        "recent_agents": recent_agents,
    }


@router.get("/cost/breakdown", response_model=CostBreakdownResponse)
def get_cost_breakdown(
    dimension: str = "all",
    window_hours: int = 24,
    limit: int = 8,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)

    normalized_dimension = str(dimension or "all").strip().lower()
    allowed_dimensions = {
        "all",
        "user",
        "team",
        "group",
        "request_tag",
        "cache_hit",
        "session_path",
        "has_feedback",
        "user_id",
        "scores",
        "rating",
    }
    if normalized_dimension not in allowed_dimensions:
        raise api_validation_error(
            "dimension must be one of: all, user, team, group, request_tag, cache_hit, session_path, has_feedback, user_id, scores, rating",
            decision_trace_id="cost-breakdown-dimension-invalid",
        )

    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    bounded_limit = max(1, min(int(limit or 8), 50))
    since = datetime.utcnow() - timedelta(hours=bounded_hours)

    owned_agent_ids: Optional[list[str]] = None
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return {
                "dimension": normalized_dimension,
                "window_hours": bounded_hours,
                "total_spend_cents": 0,
                "total_event_count": 0,
                "items": [],
            }

    base_query = db.query(
        CostEvent.owner_scope,
        func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0),
        func.count(CostEvent.cost_event_id),
    ).filter(CostEvent.timestamp >= since)

    if owned_agent_ids is not None:
        base_query = base_query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    if normalized_dimension == "session_path":
        path_query = db.query(CostEvent.properties_json, CostEvent.estimated_cost_cents).filter(
            CostEvent.timestamp >= since
        )
        if owned_agent_ids is not None:
            path_query = path_query.filter(CostEvent.agent_id.in_(owned_agent_ids))
        aggregates: dict[str, dict[str, int]] = {}
        for properties_json, estimated_cost_cents in path_query.limit(10_000).all():
            label = "unknown-session-path"
            try:
                parsed = json.loads(properties_json or "{}")
            except json.JSONDecodeError:
                parsed = {}
            if isinstance(parsed, dict):
                path_value = str(parsed.get("session_path") or "").strip()
                if path_value:
                    label = path_value[:128]
            bucket = aggregates.setdefault(label, {"spend_cents": 0, "event_count": 0})
            bucket["spend_cents"] += int(estimated_cost_cents or 0)
            bucket["event_count"] += 1
        items = [
            {"label": label, "spend_cents": data["spend_cents"], "event_count": data["event_count"]}
            for label, data in aggregates.items()
        ]
        total_spend_cents = int(sum(item["spend_cents"] for item in items))
        total_event_count = int(sum(item["event_count"] for item in items))
        items.sort(key=lambda row: row["spend_cents"], reverse=True)
        items = items[:bounded_limit]
        return {
            "dimension": normalized_dimension,
            "window_hours": bounded_hours,
            "total_spend_cents": total_spend_cents,
            "total_event_count": total_event_count,
            "items": items,
        }

    if normalized_dimension == "cache_hit":
        hit_query = db.query(
            CostEvent.cache_hit,
            func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0),
            func.count(CostEvent.cost_event_id),
        ).filter(CostEvent.timestamp >= since)
        if owned_agent_ids is not None:
            hit_query = hit_query.filter(CostEvent.agent_id.in_(owned_agent_ids))
        grouped_rows = hit_query.group_by(CostEvent.cache_hit).all()
        items = [
            {
                "label": "cache_hit" if bool(row[0]) else "cache_miss",
                "spend_cents": int(row[1] or 0),
                "event_count": int(row[2] or 0),
            }
            for row in grouped_rows
        ]
        total_spend_cents = int(sum(item["spend_cents"] for item in items))
        total_event_count = int(sum(item["event_count"] for item in items))
        items.sort(key=lambda row: row["spend_cents"], reverse=True)
        items = items[:bounded_limit]
        return {
            "dimension": normalized_dimension,
            "window_hours": bounded_hours,
            "total_spend_cents": total_spend_cents,
            "total_event_count": total_event_count,
            "items": items,
        }

    if normalized_dimension == "has_feedback":
        feedback_query = db.query(CostEvent.properties_json, CostEvent.estimated_cost_cents).filter(
            CostEvent.timestamp >= since
        )
        if owned_agent_ids is not None:
            feedback_query = feedback_query.filter(CostEvent.agent_id.in_(owned_agent_ids))
        aggregates: dict[str, dict[str, int]] = {
            "has_feedback": {"spend_cents": 0, "event_count": 0},
            "no_feedback": {"spend_cents": 0, "event_count": 0},
        }
        for properties_json, estimated_cost_cents in feedback_query.limit(10_000).all():
            label = "has_feedback" if bool(_feedback_fields_from_properties(properties_json).get("has_feedback")) else "no_feedback"
            bucket = aggregates[label]
            bucket["spend_cents"] += int(estimated_cost_cents or 0)
            bucket["event_count"] += 1
        items = [
            {"label": label, "spend_cents": data["spend_cents"], "event_count": data["event_count"]}
            for label, data in aggregates.items()
            if data["event_count"] > 0
        ]
        total_spend_cents = int(sum(item["spend_cents"] for item in items))
        total_event_count = int(sum(item["event_count"] for item in items))
        items.sort(key=lambda row: row["spend_cents"], reverse=True)
        items = items[:bounded_limit]
        return {
            "dimension": normalized_dimension,
            "window_hours": bounded_hours,
            "total_spend_cents": total_spend_cents,
            "total_event_count": total_event_count,
            "items": items,
        }

    if normalized_dimension == "rating":
        rating_query = db.query(CostEvent.properties_json, CostEvent.estimated_cost_cents).filter(
            CostEvent.timestamp >= since
        )
        if owned_agent_ids is not None:
            rating_query = rating_query.filter(CostEvent.agent_id.in_(owned_agent_ids))
        aggregates = {}
        for properties_json, estimated_cost_cents in rating_query.limit(10_000).all():
            rating_value = _feedback_fields_from_properties(properties_json).get("rating")
            label = f"rating:{int(rating_value)}" if rating_value is not None else "no_rating"
            bucket = aggregates.setdefault(label, {"spend_cents": 0, "event_count": 0})
            bucket["spend_cents"] += int(estimated_cost_cents or 0)
            bucket["event_count"] += 1
        items = [
            {"label": label, "spend_cents": data["spend_cents"], "event_count": data["event_count"]}
            for label, data in aggregates.items()
        ]
        total_spend_cents = int(sum(item["spend_cents"] for item in items))
        total_event_count = int(sum(item["event_count"] for item in items))
        items.sort(key=lambda row: row["spend_cents"], reverse=True)
        items = items[:bounded_limit]
        return {
            "dimension": normalized_dimension,
            "window_hours": bounded_hours,
            "total_spend_cents": total_spend_cents,
            "total_event_count": total_event_count,
            "items": items,
        }

    if normalized_dimension == "user_id":
        user_query = db.query(CostEvent.properties_json, CostEvent.estimated_cost_cents).filter(
            CostEvent.timestamp >= since
        )
        if owned_agent_ids is not None:
            user_query = user_query.filter(CostEvent.agent_id.in_(owned_agent_ids))
        aggregates = {}
        for properties_json, estimated_cost_cents in user_query.limit(10_000).all():
            label = _user_id_from_properties(properties_json) or "unknown-user"
            bucket = aggregates.setdefault(label, {"spend_cents": 0, "event_count": 0})
            bucket["spend_cents"] += int(estimated_cost_cents or 0)
            bucket["event_count"] += 1
        items = [
            {"label": label, "spend_cents": data["spend_cents"], "event_count": data["event_count"]}
            for label, data in aggregates.items()
        ]
        total_spend_cents = int(sum(item["spend_cents"] for item in items))
        total_event_count = int(sum(item["event_count"] for item in items))
        items.sort(key=lambda row: row["spend_cents"], reverse=True)
        items = items[:bounded_limit]
        return {
            "dimension": normalized_dimension,
            "window_hours": bounded_hours,
            "total_spend_cents": total_spend_cents,
            "total_event_count": total_event_count,
            "items": items,
        }

    if normalized_dimension == "scores":
        score_query = db.query(CostEvent.properties_json, CostEvent.estimated_cost_cents).filter(
            CostEvent.timestamp >= since
        )
        if owned_agent_ids is not None:
            score_query = score_query.filter(CostEvent.agent_id.in_(owned_agent_ids))
        score_totals: dict[str, dict[str, float]] = {}
        for properties_json, estimated_cost_cents in score_query.limit(10_000).all():
            fields = _feedback_fields_from_properties(properties_json)
            scores = fields.get("scores") if isinstance(fields.get("scores"), dict) else {}
            if not scores:
                continue
            for score_key, score_value in list(scores.items())[:16]:
                bucket = score_totals.setdefault(
                    str(score_key)[:64],
                    {"spend_cents": 0.0, "event_count": 0.0, "score_sum": 0.0},
                )
                bucket["spend_cents"] += int(estimated_cost_cents or 0)
                bucket["event_count"] += 1
                try:
                    bucket["score_sum"] += float(score_value)
                except (TypeError, ValueError):
                    pass
        items = []
        for label, data in score_totals.items():
            count = int(data["event_count"] or 0)
            avg = (data["score_sum"] / count) if count else 0.0
            items.append(
                {
                    "label": f"{label} (avg={avg:.3f})",
                    "spend_cents": int(data["spend_cents"]),
                    "event_count": count,
                }
            )
        total_spend_cents = int(sum(item["spend_cents"] for item in items))
        total_event_count = int(sum(item["event_count"] for item in items))
        items.sort(key=lambda row: row["spend_cents"], reverse=True)
        items = items[:bounded_limit]
        return {
            "dimension": normalized_dimension,
            "window_hours": bounded_hours,
            "total_spend_cents": total_spend_cents,
            "total_event_count": total_event_count,
            "items": items,
        }

    if normalized_dimension == "request_tag":
        tag_query = db.query(
            CostEvent.request_tag,
            func.coalesce(func.sum(CostEvent.estimated_cost_cents), 0),
            func.count(CostEvent.cost_event_id),
        ).filter(CostEvent.timestamp >= since)
        if owned_agent_ids is not None:
            tag_query = tag_query.filter(CostEvent.agent_id.in_(owned_agent_ids))
        grouped_rows = tag_query.group_by(CostEvent.request_tag).all()
        items = [
            {"label": str(row[0] or "untagged"), "spend_cents": int(row[1] or 0), "event_count": int(row[2] or 0)}
            for row in grouped_rows
        ]
        total_spend_cents = int(sum(item["spend_cents"] for item in items))
        total_event_count = int(sum(item["event_count"] for item in items))
        items.sort(key=lambda row: row["spend_cents"], reverse=True)
        items = items[:bounded_limit]
        return {
            "dimension": normalized_dimension,
            "window_hours": bounded_hours,
            "total_spend_cents": total_spend_cents,
            "total_event_count": total_event_count,
            "items": items,
        }

    grouped_rows = base_query.group_by(CostEvent.owner_scope).all()

    if normalized_dimension == "all":
        total_spend_cents = int(sum(int(row[1] or 0) for row in grouped_rows))
        total_event_count = int(sum(int(row[2] or 0) for row in grouped_rows))
        items = []
        if total_event_count > 0 or total_spend_cents > 0:
            items.append(
                {
                    "label": "All",
                    "spend_cents": total_spend_cents,
                    "event_count": total_event_count,
                }
            )
        return {
            "dimension": normalized_dimension,
            "window_hours": bounded_hours,
            "total_spend_cents": total_spend_cents,
            "total_event_count": total_event_count,
            "items": items,
        }

    buckets: dict[str, dict[str, int]] = {}
    user_teams: dict[str, list[str]] | None = None
    user_groups: dict[str, list[str]] | None = None
    if normalized_dimension in {"user", "team", "group", "actor", "owner"}:
        user_teams, user_groups = build_user_membership_index(db)

    for owner_scope, spend_cents, event_count in grouped_rows:
        if normalized_dimension in {"user", "team", "group", "actor", "owner"}:
            attribution_keys = hierarchy_attribution_keys(
                str(owner_scope or ""),
                user_teams=user_teams,
                user_groups=user_groups,
            )
            for scope_type, scope_id in attribution_keys:
                if scope_type != normalized_dimension:
                    continue
                key = scope_id or "unscoped"
                if key not in buckets:
                    buckets[key] = {"spend_cents": 0, "event_count": 0}
                buckets[key]["spend_cents"] += int(spend_cents or 0)
                buckets[key]["event_count"] += int(event_count or 0)
            continue

        scope_type, scope_id = _split_owner_scope(owner_scope)
        if scope_type != normalized_dimension:
            continue
        key = scope_id or "unscoped"
        if key not in buckets:
            buckets[key] = {"spend_cents": 0, "event_count": 0}
        buckets[key]["spend_cents"] += int(spend_cents or 0)
        buckets[key]["event_count"] += int(event_count or 0)

    items = [
        {
            "label": label,
            "spend_cents": values["spend_cents"],
            "event_count": values["event_count"],
        }
        for label, values in buckets.items()
    ]
    total_spend_cents = int(sum(item["spend_cents"] for item in items))
    total_event_count = int(sum(item["event_count"] for item in items))
    items.sort(key=lambda row: row["spend_cents"], reverse=True)
    items = items[:bounded_limit]

    return {
        "dimension": normalized_dimension,
        "window_hours": bounded_hours,
        "total_spend_cents": total_spend_cents,
        "total_event_count": total_event_count,
        "items": items,
    }


@router.get("/cost/timeseries", response_model=CostTimeseriesResponse)
def get_cost_timeseries(
    dimension: str = "all",
    window_hours: int = 24,
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
    start_datetime: Optional[datetime] = None,
    end_datetime: Optional[datetime] = None,
    scope_filter: Optional[str] = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)

    normalized_dimension = str(dimension or "all").strip().lower()
    allowed_dimensions = {
        "all",
        "user",
        "team",
        "group",
        "request_tag",
        "cache_hit",
        "session_path",
        "has_feedback",
        "user_id",
        "scores",
        "rating",
    }
    if normalized_dimension not in allowed_dimensions:
        raise api_validation_error(
            "dimension must be one of: all, user, team, group, request_tag, cache_hit, session_path, has_feedback, user_id, scores, rating",
            decision_trace_id="cost-breakdown-dimension-invalid",
        )

    scope_filter_text = str(scope_filter or "").strip().lower()

    if (start_datetime and not end_datetime) or (end_datetime and not start_datetime):
        raise api_validation_error(
            "start_datetime and end_datetime must both be provided",
            decision_trace_id="cost-timeseries-datetime-pair-required",
        )

    if start_datetime and end_datetime:
        if end_datetime <= start_datetime:
            raise api_validation_error(
                "end_datetime must be greater than start_datetime",
                decision_trace_id="cost-timeseries-datetime-order",
            )
        selected_seconds = (end_datetime - start_datetime).total_seconds()
        if selected_seconds > 24 * 366 * 3600:
            raise api_validation_error(
                "date/time range cannot exceed 1 year",
                decision_trace_id="cost-timeseries-range-too-large",
            )
        start_hour = _floor_hour(start_datetime)
        end_hour = _floor_hour(end_datetime)
        bounded_hours = int(((end_hour - start_hour).total_seconds() // 3600) + 1)
        query_start_ts = start_datetime
        query_end_exclusive = end_datetime + timedelta(seconds=1)
    elif (start_date and not end_date) or (end_date and not start_date):
        raise api_validation_error(
            "start_date and end_date must both be provided",
            decision_trace_id="cost-timeseries-date-pair-required",
        )
    elif start_date and end_date:
        if end_date < start_date:
            raise api_validation_error(
                "end_date must be greater than or equal to start_date",
                decision_trace_id="cost-timeseries-date-order",
            )
        start_hour = _floor_hour(datetime.combine(start_date, datetime.min.time()))
        end_hour = _floor_hour(datetime.combine(end_date + timedelta(days=1), datetime.min.time()) - timedelta(hours=1))
        bounded_hours = int(((end_hour - start_hour).total_seconds() // 3600) + 1)
        if bounded_hours > 24 * 366:
            raise api_validation_error(
                "date range cannot exceed 1 year",
                decision_trace_id="cost-timeseries-date-range-too-large",
            )
        query_start_ts = start_hour
        query_end_exclusive = end_hour + timedelta(hours=1)
    else:
        bounded_hours = max(1, min(int(window_hours or 24), 24 * 366))
        now = datetime.utcnow()
        end_hour = _floor_hour(now)
        start_hour = end_hour - timedelta(hours=bounded_hours - 1)
        query_start_ts = start_hour
        query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.owner_scope,
        CostEvent.request_tag,
        CostEvent.estimated_cost_cents,
        CostEvent.properties_json,
        CostEvent.cache_hit,
    ).filter(
        CostEvent.timestamp >= query_start_ts,
        CostEvent.timestamp < query_end_exclusive,
    )

    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return {
                "dimension": normalized_dimension,
                "window_hours": bounded_hours,
                "start_time": query_start_ts,
                "end_time": query_end_exclusive,
                "scope_filter": scope_filter_text or None,
                "total_spend_cents": 0,
                "total_event_count": 0,
                "points": [
                    {
                        "hour_start": start_hour + timedelta(hours=i),
                        "spend_cents": 0,
                        "event_count": 0,
                    }
                    for i in range(bounded_hours)
                ],
            }
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    raw_rows = query.all()
    user_teams: dict[str, list[str]] | None = None
    user_groups: dict[str, list[str]] | None = None
    if normalized_dimension in {"user", "team", "group", "actor", "owner"}:
        user_teams, user_groups = build_user_membership_index(db)

    buckets: dict[datetime, dict[str, int]] = {
        start_hour + timedelta(hours=i): {"spend_cents": 0, "event_count": 0}
        for i in range(bounded_hours)
    }

    for timestamp, owner_scope, request_tag, estimated_cost_cents, properties_json, cache_hit in raw_rows:
        if normalized_dimension == "request_tag":
            normalized_tag = str(request_tag or "untagged").strip().lower()
            if scope_filter_text and scope_filter_text not in normalized_tag:
                continue
        elif normalized_dimension == "cache_hit":
            label = "cache_hit" if bool(cache_hit) else "cache_miss"
            if scope_filter_text and scope_filter_text not in label:
                continue
        elif normalized_dimension == "session_path":
            path_label = "unknown-session-path"
            try:
                parsed = json.loads(properties_json or "{}")
            except json.JSONDecodeError:
                parsed = {}
            if isinstance(parsed, dict):
                path_value = str(parsed.get("session_path") or "").strip()
                if path_value:
                    path_label = path_value[:128]
            if scope_filter_text and scope_filter_text not in path_label.lower():
                continue
        elif normalized_dimension == "has_feedback":
            label = (
                "has_feedback"
                if bool(_feedback_fields_from_properties(properties_json).get("has_feedback"))
                else "no_feedback"
            )
            if scope_filter_text and scope_filter_text not in label:
                continue
        elif normalized_dimension == "rating":
            rating_value = _feedback_fields_from_properties(properties_json).get("rating")
            label = f"rating:{int(rating_value)}" if rating_value is not None else "no_rating"
            if scope_filter_text and scope_filter_text not in label:
                continue
        elif normalized_dimension == "user_id":
            label = (_user_id_from_properties(properties_json) or "unknown-user").lower()
            if scope_filter_text and scope_filter_text not in label:
                continue
        elif normalized_dimension == "scores":
            fields = _feedback_fields_from_properties(properties_json)
            scores = fields.get("scores") if isinstance(fields.get("scores"), dict) else {}
            if not scores:
                continue
            if scope_filter_text and not any(scope_filter_text in str(key).lower() for key in scores):
                continue
        else:
            if normalized_dimension in {"user", "team", "group", "actor", "owner"}:
                if not event_matches_hierarchy_dimension(
                    str(owner_scope or ""),
                    dimension=normalized_dimension,
                    scope_filter=scope_filter_text or None,
                    user_teams=user_teams,
                    user_groups=user_groups,
                ):
                    continue
            else:
                scope_type, scope_id = _split_owner_scope(owner_scope)
                if normalized_dimension != "all" and scope_type != normalized_dimension:
                    continue
                if scope_filter_text and normalized_dimension != "all":
                    normalized_scope_id = str(scope_id or "").strip().lower()
                    if scope_filter_text not in normalized_scope_id:
                        continue

        hour_bucket = _floor_hour(timestamp)
        if hour_bucket not in buckets:
            continue
        buckets[hour_bucket]["spend_cents"] += int(estimated_cost_cents or 0)
        buckets[hour_bucket]["event_count"] += 1

    points = [
        {
            "hour_start": hour,
            "spend_cents": data["spend_cents"],
            "event_count": data["event_count"],
        }
        for hour, data in sorted(buckets.items(), key=lambda item: item[0])
    ]

    total_spend_cents = int(sum(point["spend_cents"] for point in points))
    total_event_count = int(sum(point["event_count"] for point in points))

    return {
        "dimension": normalized_dimension,
        "window_hours": bounded_hours,
        "start_time": query_start_ts,
        "end_time": query_end_exclusive,
        "scope_filter": scope_filter_text or None,
        "total_spend_cents": total_spend_cents,
        "total_event_count": total_event_count,
        "points": points,
    }


@router.get("/cost/comparison", response_model=CostComparisonResponse)
def get_cost_comparison(
    period: str = Query(default="monthly"),
    comparison_mode: str = Query(default="prior_period"),
    dimension: str = Query(default="all"),
    scope_filter: Optional[str] = None,
    timezone: str = Query(default="UTC"),
    reset_hour_local: int = Query(default=0, ge=0, le=23),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)

    normalized_dimension = str(dimension or "all").strip().lower()
    allowed_dimensions = {
        "all",
        "user",
        "team",
        "group",
        "request_tag",
        "cache_hit",
        "session_path",
        "has_feedback",
        "user_id",
        "scores",
        "rating",
    }
    if normalized_dimension not in allowed_dimensions:
        raise api_validation_error(
            "dimension must be one of: all, user, team, group, request_tag, cache_hit, session_path, has_feedback, user_id, scores, rating",
            decision_trace_id="cost-breakdown-dimension-invalid",
        )

    try:
        comparison = build_period_comparison(
            db,
            period=period,
            comparison_mode=comparison_mode,
            timezone=str(timezone or "UTC").strip() or "UTC",
            reset_hour_local=reset_hour_local,
            dimension=normalized_dimension,
            scope_filter=str(scope_filter or "").strip() or None,
            agent_ids=_owned_agent_ids(db, ctx.actor_id) if ctx.actor_role == ROLE_AGENT_OWNER else None,
        )
    except ValueError as exc:
        raise api_validation_error(str(exc), decision_trace_id="cost-comparison-invalid") from exc

    return {
        "comparison_period": comparison.comparison_period,
        "comparison_mode": comparison.comparison_mode,
        "dimension": normalized_dimension,
        "scope_filter": str(scope_filter or "").strip() or None,
        "current": {
            "label": comparison.current.label,
            "start": comparison.current.start,
            "end": comparison.current.end,
            "spend_cents": comparison.current.spend_cents,
            "event_count": comparison.current.event_count,
        },
        "previous": {
            "label": comparison.previous.label,
            "start": comparison.previous.start,
            "end": comparison.previous.end,
            "spend_cents": comparison.previous.spend_cents,
            "event_count": comparison.previous.event_count,
        },
        "delta_cents": comparison.delta_cents,
        "delta_percent": comparison.delta_percent,
        "trend": comparison.trend,
    }


def _session_path_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    return str(parsed.get("session_path") or "").strip()[:128]


def _session_name_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    return str(parsed.get("session_name") or "").strip()[:128]


def _prompt_id_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    return str(parsed.get("prompt_id") or parsed.get("prompt_registry_id") or "").strip()[:128]


def _application_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("application", "app", "app_name", "app_id"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _customer_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("customer_id", "customer", "customer_name", "account_id"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _department_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("department", "dept", "org_unit", "cost_center"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _feature_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("feature", "feature_flag", "feature_name", "feature_id"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _region_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("region", "aws_region", "country", "geo", "location"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _workspace_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("workspace", "workspace_id", "workspace_name", "org", "organization"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _product_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("product", "product_id", "product_name", "sku", "sku_id"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _service_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("service", "service_name", "service_id", "microservice", "svc"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _tenant_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("tenant", "tenant_id", "tenant_name", "account", "account_id"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _channel_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("channel", "channel_id", "channel_name", "source_channel", "utm_source"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _campaign_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("campaign", "campaign_id", "campaign_name", "utm_campaign", "promo"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _brand_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("brand", "brand_id", "brand_name", "label", "sku_brand"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _market_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("market", "market_id", "market_code", "region_market", "geo_market"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _segment_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("segment", "segment_id", "segment_name", "audience", "cohort"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _account_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("account", "account_id", "account_name", "billing_account", "org_account"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _org_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("org", "org_id", "organization", "organization_id", "org_name"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _cost_center_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("cost_center", "cost_center_id", "costcenter", "cc", "charge_code"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _business_unit_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("business_unit", "business_unit_id", "bu", "bu_id", "division"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _site_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("site", "site_id", "site_name", "location", "facility"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _sku_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("sku", "sku_id", "sku_code", "product_sku", "plan_sku"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _line_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("line", "line_id", "line_of_business", "lob", "product_line"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _tier_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("tier", "tier_id", "plan_tier", "pricing_tier", "service_tier"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _stage_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("stage", "stage_id", "pipeline_stage", "lifecycle_stage", "funnel_stage"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _platform_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("platform", "platform_id", "platform_name", "runtime_platform", "host_platform"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _device_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("device", "device_id", "device_type", "client_device", "device_name"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _client_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("client", "client_id", "client_name", "app_client", "sdk_client"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _browser_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("browser", "browser_name", "user_agent_browser", "ua_browser", "client_browser"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _release_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("release", "release_id", "release_version", "app_release", "version"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _locale_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("locale", "locale_code", "language_locale", "accept_language", "lang"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _country_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("country", "country_code", "geo_country", "user_country", "billing_country"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _os_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("os", "os_name", "operating_system", "platform_os", "client_os"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _timezone_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("timezone", "time_zone", "tz", "user_timezone", "client_timezone"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _language_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("language", "lang_code", "spoken_language", "content_language", "ui_language"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _city_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("city", "city_name", "geo_city", "user_city", "billing_city"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _continent_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("continent", "continent_code", "geo_continent", "region_continent"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _isp_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("isp", "isp_name", "network_isp", "asn_org", "carrier"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _asn_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("asn", "asn_number", "network_asn", "autonomous_system", "as_number"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _sdk_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("sdk", "sdk_name", "client_sdk", "helicone_sdk", "user_agent_sdk"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _framework_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("framework", "framework_name", "ml_framework", "ai_framework", "lib_framework"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _runtime_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("runtime", "runtime_name", "execution_runtime", "lang_runtime", "node_runtime"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _library_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("library", "library_name", "client_library", "sdk_library", "package_name"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _host_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("host", "hostname", "host_name", "server_host", "instance_host"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _datacenter_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("datacenter", "data_center", "dc", "datacenter_name", "colo"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _az_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("az", "availability_zone", "zone", "aws_az", "zone_id"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _edge_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("edge", "edge_location", "edge_pop", "cdn_edge", "pop"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _colo_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("colo", "colo_name", "colocation", "colo_id", "facility"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _cluster_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("cluster", "cluster_name", "k8s_cluster", "cluster_id", "eks_cluster"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _pod_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("pod", "pod_name", "k8s_pod", "pod_id", "workload"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _namespace_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("namespace", "k8s_namespace", "namespace_name", "ns"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _node_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("node", "node_name", "k8s_node", "kubernetes_node", "node_id"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""




def _tool_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("tool", "tool_name", "tool_id", "function_name", "function"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _workflow_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("workflow", "workflow_id", "flow_id", "orchestration_flow_id", "pipeline"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _experiment_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("experiment", "experiment_id", "experiment_name", "ab_test", "ab_test_id"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _variant_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("variant", "variant_id", "variant_name", "treatment", "arm"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _deployment_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("deployment", "deployment_id", "deployment_name", "model_deployment", "endpoint_deployment"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _version_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("version", "version_id", "app_version", "model_version", "prompt_version", "semver"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _canary_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("canary", "canary_id", "canary_name", "canary_group", "rollout_canary"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _shadow_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("shadow", "shadow_id", "shadow_name", "mirror", "traffic_mirror"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""



def _rollout_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("rollout", "rollout_id", "rollout_name", "release_rollout", "feature_rollout"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _route_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("route", "route_id", "route_name", "route_policy_id", "config_id"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _batch_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("batch", "batch_id", "batch_name", "job_batch", "batch_job"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _job_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("job", "job_id", "job_name", "pipeline_job", "workflow_job"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _queue_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("queue", "queue_id", "queue_name", "sqs_queue", "message_queue"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _topic_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("topic", "topic_id", "topic_name", "sns_topic", "kafka_topic"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _pipeline_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("pipeline", "pipeline_id", "pipeline_name", "etl_pipeline", "data_pipeline"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _run_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("run", "run_id", "run_name", "pipeline_run", "job_run"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _worker_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("worker", "worker_id", "worker_name", "worker_pool", "compute_worker"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _slot_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("slot", "slot_id", "slot_name", "capacity_slot", "scheduler_slot"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _task_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("task", "task_id", "task_name", "workflow_task", "job_task"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _step_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("step", "step_id", "step_name", "pipeline_step", "workflow_step"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _replica_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("replica", "replica_id", "replica_name", "db_replica", "service_replica"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _shard_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("shard", "shard_id", "shard_name", "data_shard", "partition_shard"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _partition_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("partition", "partition_id", "partition_name", "kafka_partition", "table_partition"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _consumer_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("consumer", "consumer_id", "consumer_name", "consumer_group", "queue_consumer"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _producer_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("producer", "producer_id", "producer_name", "kafka_producer", "event_producer"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _gpu_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("gpu", "gpu_id", "gpu_name", "accelerator_gpu", "device_gpu"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _accelerator_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("accelerator", "accelerator_id", "accelerator_name", "ml_accelerator", "inferentia"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _cell_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("cell", "cell_id", "cell_name", "availability_cell", "routing_cell"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _zone_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("zone", "zone_id", "zone_name", "availability_zone", "failure_zone"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _rack_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("rack", "rack_id", "rack_name", "server_rack", "colo_rack"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _pool_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("pool", "pool_id", "pool_name", "worker_pool", "resource_pool"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _fleet_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("fleet", "fleet_id", "fleet_name", "compute_fleet", "device_fleet"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _lease_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("lease", "lease_id", "lease_name", "capacity_lease", "resource_lease"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _quota_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("quota", "quota_id", "quota_name", "service_quota", "usage_quota"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _capacity_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("capacity", "capacity_id", "capacity_name", "reserved_capacity", "compute_capacity"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _reservation_from_properties(properties_json: object) -> str:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("reservation", "reservation_id", "reservation_name", "capacity_reservation", "ri_reservation"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""

def _user_id_from_properties(properties_json: object) -> str:
    """Helicone end-user id from properties (user / user_id), not owner_scope."""
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    for key in ("user_id", "user", "helicone_user"):
        value = str(parsed.get(key) or "").strip()
        if value:
            return value[:128]
    return ""


def _user_id_from_event(
    event: object | None = None,
    *,
    properties_json: object | None = None,
    owner_scope: object | None = None,
) -> str:
    """Prefer Helicone properties, then gateway owner_scope user/actor/owner tags."""
    props = properties_json
    scope = owner_scope
    if event is not None:
        if props is None:
            props = getattr(event, "properties_json", None)
        if scope is None:
            scope = getattr(event, "owner_scope", None)
    from_props = _user_id_from_properties(props)
    if from_props:
        return from_props
    raw = str(scope or "").strip()
    if ":" not in raw:
        return ""
    scope_type, scope_id = raw.split(":", 1)
    if scope_type.strip().lower() in {COST_SCOPE_USER, "actor", "owner"} and scope_id.strip():
        return scope_id.strip()[:128]
    return ""

@router.get("/cost/export")
def export_cost_events(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    dimension: str = Query(default="all"),
    scope_filter: Optional[str] = Query(default=None),
    property_key: Optional[str] = Query(default=None, max_length=64),
    property_value: Optional[str] = Query(default=None, max_length=256),
    limit: int = Query(default=1000, ge=1, le=5000),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style CSV export of cost events, including session_path / feedback drilldown."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    normalized_dimension = str(dimension or "all").strip().lower()
    allowed_dimensions = {
        "all",
        "user",
        "team",
        "group",
        "request_tag",
        "cache_hit",
        "session_path",
        "has_feedback",
        "user_id",
        "scores",
        "rating",
    }
    if normalized_dimension not in allowed_dimensions:
        raise api_validation_error(
            "dimension must be one of: all, user, team, group, request_tag, cache_hit, session_path, has_feedback, user_id, scores, rating",
            decision_trace_id="cost-export-dimension-invalid",
        )
    scope_filter_text = str(scope_filter or "").strip().lower()
    export_property_key = str(property_key or "").strip()
    if export_property_key and export_property_key in {"helicone_feedback", "scores", "metadata"}:
        raise api_validation_error(
            "property_key must be a flat custom property (not helicone_feedback/scores/metadata)",
            decision_trace_id="cost-export-property-key-invalid",
        )
    property_value_filter = str(property_value or "").strip().lower()
    if property_value_filter and not export_property_key:
        raise api_validation_error(
            "property_value requires property_key",
            decision_trace_id="cost-export-property-value-without-key",
        )
    since = datetime.utcnow() - timedelta(hours=int(window_hours))
    query = db.query(CostEvent).filter(CostEvent.timestamp >= since).order_by(CostEvent.timestamp.desc())
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            query = query.filter(CostEvent.cost_event_id == "__none__")
        else:
            query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    rows: list[CostEvent] = []
    export_user_teams: dict[str, list[str]] | None = None
    export_user_groups: dict[str, list[str]] | None = None
    if normalized_dimension in {"user", "team", "group", "actor", "owner"}:
        export_user_teams, export_user_groups = build_user_membership_index(db)
    for event in query.limit(min(int(limit) * 3, 15_000)).all():
        if normalized_dimension == "request_tag":
            label = str(event.request_tag or "untagged").strip().lower()
            if scope_filter_text and scope_filter_text not in label:
                continue
        elif normalized_dimension == "cache_hit":
            label = "cache_hit" if bool(event.cache_hit) else "cache_miss"
            if scope_filter_text and scope_filter_text not in label:
                continue
        elif normalized_dimension == "session_path":
            label = _session_path_from_properties(event.properties_json).lower() or "unknown-session-path"
            if scope_filter_text and scope_filter_text not in label:
                continue
        elif normalized_dimension == "has_feedback":
            label = (
                "has_feedback"
                if bool(_feedback_fields_from_properties(event.properties_json).get("has_feedback"))
                else "no_feedback"
            )
            if scope_filter_text and scope_filter_text not in label:
                continue
        elif normalized_dimension == "rating":
            rating_value = _feedback_fields_from_properties(event.properties_json).get("rating")
            label = f"rating:{int(rating_value)}" if rating_value is not None else "no_rating"
            if scope_filter_text and scope_filter_text not in label:
                continue
        elif normalized_dimension == "user_id":
            label = (_user_id_from_properties(event.properties_json) or "unknown-user").lower()
            if scope_filter_text and scope_filter_text not in label:
                continue
        elif normalized_dimension == "scores":
            fields = _feedback_fields_from_properties(event.properties_json)
            scores = fields.get("scores") if isinstance(fields.get("scores"), dict) else {}
            if not scores:
                continue
            if scope_filter_text and not any(scope_filter_text in str(key).lower() for key in scores):
                continue
        elif normalized_dimension != "all":
            if normalized_dimension in {"user", "team", "group", "actor", "owner"}:
                if not event_matches_hierarchy_dimension(
                    str(event.owner_scope or ""),
                    dimension=normalized_dimension,
                    scope_filter=scope_filter_text or None,
                    user_teams=export_user_teams,
                    user_groups=export_user_groups,
                ):
                    continue
            else:
                raw_scope = str(event.owner_scope or "")
                if ":" not in raw_scope:
                    scope_type, scope_id = "all", raw_scope
                else:
                    scope_type, scope_id = raw_scope.split(":", 1)
                if scope_type.strip().lower() != normalized_dimension:
                    continue
                if scope_filter_text and scope_filter_text not in str(scope_id or "").strip().lower():
                    continue
        if export_property_key:
            prop_value = _flat_property_value_for_stats(event.properties_json, export_property_key)
            if not prop_value:
                continue
            if property_value_filter and property_value_filter not in prop_value.lower():
                continue
        rows.append(event)
        if len(rows) >= int(limit):
            break

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    header = [
        "timestamp",
        "cost_event_id",
        "request_id",
        "trace_id",
        "session_id",
        "session_path",
        "user_id",
        "request_tag",
        "owner_scope",
        "environment",
        "model_name",
        "endpoint_family",
        "input_tokens",
        "output_tokens",
        "estimated_cost_cents",
        "currency",
        "cache_hit",
        "has_feedback",
        "rating",
        "score_keys",
    ]
    if export_property_key:
        header.extend(["property_key", "property_value"])
    writer.writerow(header)
    for event in rows:
        feedback = _feedback_fields_from_properties(event.properties_json)
        scores = feedback.get("scores") if isinstance(feedback.get("scores"), dict) else {}
        row = [
            event.timestamp.isoformat() if event.timestamp else "",
            event.cost_event_id,
            event.request_id,
            event.trace_id,
            event.session_id,
            _session_path_from_properties(event.properties_json),
            _user_id_from_properties(event.properties_json),
            event.request_tag or "",
            event.owner_scope,
            event.environment,
            event.model_name,
            event.endpoint_family,
            event.input_tokens,
            event.output_tokens,
            event.estimated_cost_cents,
            event.currency,
            "true" if bool(event.cache_hit) else "false",
            "true" if bool(feedback.get("has_feedback")) else "false",
            feedback.get("rating") if feedback.get("rating") is not None else "",
            ",".join(str(key) for key in list(scores.keys())[:16]),
        ]
        if export_property_key:
            row.extend(
                [
                    export_property_key,
                    _flat_property_value_for_stats(event.properties_json, export_property_key),
                ]
            )
        writer.writerow(row)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.events.export",
        resource_type="cost_export",
        resource_id=f"window-{window_hours}h",
        trace_id=f"trace-cost-export-{uuid4().hex[:12]}",
        action_context={
            "dimension": normalized_dimension,
            "scope_filter": scope_filter_text or None,
            "property_key": export_property_key or None,
            "property_value": property_value_filter or None,
            "row_count": len(rows),
            "window_hours": int(window_hours),
        },
    )
    db.commit()
    filename = f"cost-export-{normalized_dimension}-{int(window_hours)}h.csv"
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _sanitize_feedback_scores(raw: object) -> dict[str, float]:
    if not isinstance(raw, dict):
        return {}
    sanitized: dict[str, float] = {}
    for key, value in list(raw.items())[:16]:
        normalized_key = str(key or "").strip()[:64]
        if not normalized_key:
            continue
        try:
            number = float(value)
        except (TypeError, ValueError):
            continue
        if number != number or number in (float("inf"), float("-inf")):  # NaN/Inf guard
            continue
        sanitized[normalized_key] = round(max(-1_000_000.0, min(1_000_000.0, number)), 6)
    return sanitized


def _feedback_fields_from_properties(properties_json: object) -> dict[str, object]:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        parsed = {}
    if not isinstance(parsed, dict):
        parsed = {}
    rating = parsed.get("rating")
    try:
        rating_int = int(rating) if rating is not None else None
    except (TypeError, ValueError):
        rating_int = None
    if rating_int is not None and (rating_int < 1 or rating_int > 5):
        rating_int = None
    scores = _sanitize_feedback_scores(parsed.get("scores"))
    comment = str(parsed.get("feedback_comment") or "").strip()[:2048] or None
    blob = parsed.get("helicone_feedback")
    if isinstance(blob, dict):
        if rating_int is None and blob.get("rating") is not None:
            try:
                rating_int = int(blob.get("rating"))
            except (TypeError, ValueError):
                rating_int = None
        if not scores and isinstance(blob.get("scores"), dict):
            scores = _sanitize_feedback_scores(blob.get("scores"))
        if not comment and blob.get("comment"):
            comment = str(blob.get("comment") or "").strip()[:2048] or None
    has_feedback = bool(rating_int is not None or scores or comment or isinstance(blob, dict))
    return {
        "rating": rating_int,
        "scores": scores or None,
        "comment": comment,
        "has_feedback": has_feedback,
    }


@router.get("/cost/events/feedback", response_model=CostEventFeedbackLookupResponse)
@router.get("/v1/feedback", response_model=CostEventFeedbackLookupResponse, include_in_schema=True)
def get_cost_event_feedback(
    request_id: str = Query(..., min_length=1, max_length=128),
    trace_id: Optional[str] = Query(default=None, max_length=128),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Read Helicone-style feedback previously attached to cost events."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    normalized_request_id = str(request_id or "").strip()
    if not normalized_request_id:
        raise api_validation_error("request_id is required", decision_trace_id="cost-feedback-get-request-id")
    query = db.query(CostEvent).filter(CostEvent.request_id == normalized_request_id)
    normalized_trace = str(trace_id or "").strip()
    if normalized_trace:
        query = query.filter(CostEvent.trace_id == normalized_trace)
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            raise not_found_error("cost_event", normalized_request_id, decision_trace_id="cost-feedback-get-not-found")
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))
    events = query.order_by(CostEvent.timestamp.desc()).limit(50).all()
    if not events:
        raise not_found_error("cost_event", normalized_request_id, decision_trace_id="cost-feedback-get-not-found")

    items: list[CostEventFeedbackItem] = []
    latest_rating = None
    latest_scores = None
    latest_comment = None
    any_feedback = False
    for event in events:
        fields = _feedback_fields_from_properties(event.properties_json)
        item = CostEventFeedbackItem(
            cost_event_id=event.cost_event_id,
            request_id=event.request_id,
            trace_id=event.trace_id,
            rating=fields.get("rating"),  # type: ignore[arg-type]
            scores=fields.get("scores"),  # type: ignore[arg-type]
            comment=fields.get("comment"),  # type: ignore[arg-type]
            has_feedback=bool(fields.get("has_feedback")),
        )
        items.append(item)
        if item.has_feedback:
            any_feedback = True
            if latest_rating is None and item.rating is not None:
                latest_rating = item.rating
            if latest_scores is None and item.scores:
                latest_scores = item.scores
            if latest_comment is None and item.comment:
                latest_comment = item.comment

    return CostEventFeedbackLookupResponse(
        request_id=normalized_request_id,
        trace_id=normalized_trace or None,
        count=len(items),
        has_feedback=any_feedback,
        rating=latest_rating,
        scores=latest_scores,
        comment=latest_comment,
        events=items,
    )


@router.post("/cost/events/feedback", response_model=CostEventFeedbackResponse)
@router.post("/v1/feedback", response_model=CostEventFeedbackResponse, include_in_schema=True)
def submit_cost_event_feedback(
    payload: CostEventFeedbackRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style feedback/scores attached to matching cost events by request_id."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    request_id = str(payload.request_id or "").strip()
    if not request_id:
        raise api_validation_error("request_id is required", decision_trace_id="cost-feedback-request-id")
    if payload.rating is None and not payload.scores and not str(payload.comment or "").strip():
        raise api_validation_error(
            "Provide at least one of rating, scores, or comment",
            decision_trace_id="cost-feedback-empty",
        )

    scores = _sanitize_feedback_scores(payload.scores)
    comment = str(payload.comment or "").strip()[:2048] or None
    query = db.query(CostEvent).filter(CostEvent.request_id == request_id)
    trace_id = str(payload.trace_id or "").strip()
    if trace_id:
        query = query.filter(CostEvent.trace_id == trace_id)
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            raise not_found_error("cost_event", request_id, decision_trace_id="cost-feedback-not-found")
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    events = query.order_by(CostEvent.timestamp.desc()).limit(50).all()
    if not events:
        raise not_found_error("cost_event", request_id, decision_trace_id="cost-feedback-not-found")

    updated = 0
    for event in events:
        try:
            props = json.loads(event.properties_json or "{}")
        except json.JSONDecodeError:
            props = {}
        if not isinstance(props, dict):
            props = {}
        feedback_blob: dict[str, object] = {
            "updated_at": datetime.utcnow().isoformat() + "Z",
            "actor_id": ctx.actor_id,
        }
        if payload.rating is not None:
            props["rating"] = int(payload.rating)
            feedback_blob["rating"] = int(payload.rating)
        if scores:
            props["scores"] = scores
            feedback_blob["scores"] = scores
        if comment:
            props["feedback_comment"] = comment
            feedback_blob["comment"] = comment
        props["helicone_feedback"] = feedback_blob
        try:
            event.properties_json = json.dumps(props, separators=(",", ":"), ensure_ascii=True)[:4000]
        except (TypeError, ValueError):
            continue
        updated += 1

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.event.feedback",
        resource_type="cost_event",
        resource_id=request_id,
        trace_id=trace_id or f"trace-cost-feedback-{request_id[:24]}",
        action_context={
            "updated_events": updated,
            "rating": payload.rating,
            "score_keys": list(scores.keys())[:16],
            "has_comment": bool(comment),
        },
    )
    db.commit()
    return CostEventFeedbackResponse(
        request_id=request_id,
        trace_id=trace_id or None,
        updated_events=updated,
        rating=payload.rating,
        scores=scores or None,
        comment=comment,
    )


@router.post("/cost/events", response_model=CostEventResponse)
def track_spend_event(
    payload: CostTrackSpendRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)
    scope_type, scope_id = normalize_scope_reference(
        db,
        scope_type=payload.scope_type,
        scope_id=payload.scope_id,
        allowed_scope_types=SUPPORTED_BUDGET_SCOPE_TYPES,
        resource_label="spend scope",
    )
    if not _is_budget_scope_manageable(db, ctx, scope_type, scope_id):
        _cost_scope_forbidden(ctx, "Spend scope is forbidden for this actor", "cost-spend-scope-forbidden")

    if ctx.actor_role == ROLE_AGENT_OWNER:
        agent = db.query(Agent).filter_by(agent_id=payload.agent_id).first()
        if not agent or agent.owner_id != ctx.actor_id:
            _cost_scope_forbidden(ctx, "Agent scope is forbidden for this actor", "cost-agent-scope-forbidden")

    properties = payload.user_properties if isinstance(payload.user_properties, dict) else {}
    try:
        properties_json = json.dumps(properties, separators=(",", ":"), ensure_ascii=True)[:4000]
    except (TypeError, ValueError):
        properties_json = "{}"
    # Align manual spend tags with gateway attribution: actor/owner aliases → user:{id}.
    attribution_type = COST_SCOPE_USER if scope_type in {"actor", "owner", COST_SCOPE_USER} else scope_type
    event = CostEvent(
        cost_event_id=str(uuid4()),
        request_id=str(payload.request_id).strip(),
        trace_id=str(payload.trace_id or f"trace-{payload.request_id}").strip(),
        request_tag=_normalize_request_tag(payload.request_tag),
        session_id=str(payload.session_id).strip(),
        agent_id=str(payload.agent_id).strip(),
        owner_scope=f"{attribution_type}:{scope_id}",
        environment=str(payload.environment or "dev").strip() or "dev",
        model_name=str(payload.model_name).strip(),
        endpoint_family=str(payload.endpoint_family).strip(),
        input_tokens=max(0, int(payload.input_tokens or 0)),
        output_tokens=max(0, int(payload.output_tokens or 0)),
        estimated_cost_cents=max(0, int(payload.estimated_cost_cents or 0)),
        currency=str(payload.currency or "USD").strip().upper() or "USD",
        cache_hit=bool(payload.cache_hit),
        properties_json=properties_json or "{}",
    )
    db.add(event)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.event.track",
        resource_type="cost_event",
        resource_id=event.cost_event_id,
        trace_id=str(event.trace_id),
    )
    db.commit()
    db.refresh(event)
    return event


@router.get("/cost/pricing/catalog", response_model=CostPricingCatalogResponse)
def get_pricing_catalog(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)
    model_rates, default_rates = _load_model_token_rates(db)
    provider_multipliers, endpoint_multipliers = _load_cloud_component_multipliers(db)
    provider_discounts, model_discounts = _load_provider_discounts(db)
    return {
        "default_model_rates": default_rates,
        "model_rates": model_rates,
        "provider_multipliers": provider_multipliers,
        "endpoint_multipliers": endpoint_multipliers,
        "provider_discounts": provider_discounts,
        "model_discounts": model_discounts,
    }


@router.get("/cost/models/catalog", response_model=CostModelCatalogResponse)
def get_model_catalog(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)
    model_rates, default_rates = _load_model_token_rates(db)
    provider_multipliers, endpoint_multipliers = _load_cloud_component_multipliers(db)
    provider_discounts, model_discounts = _load_provider_discounts(db)

    catalog_rows = []
    for row in db.query(SupportedModelCatalogEntry).order_by(SupportedModelCatalogEntry.provider_type.asc(), SupportedModelCatalogEntry.model_name.asc()).all():
        normalized_model = str(row.model_name or "").strip().lower()
        normalized_provider = str(row.provider_type or "").strip().lower()
        rates = model_rates.get(normalized_model, default_rates)
        input_rate = _parse_non_negative_float(rates.get("input_cents_per_1k"), default_rates["input_cents_per_1k"])
        output_rate = _parse_non_negative_float(rates.get("output_cents_per_1k"), default_rates["output_cents_per_1k"])
        provider_multiplier = _parse_positive_float(provider_multipliers.get(normalized_provider, 1.0), 1.0)
        endpoint_multiplier = _parse_positive_float(endpoint_multipliers.get("responses", 1.0), 1.0)
        provider_discount = max(0.0, min(95.0, _parse_non_negative_float(provider_discounts.get(normalized_provider, 0.0), 0.0)))
        model_discount = max(0.0, min(95.0, _parse_non_negative_float(model_discounts.get(normalized_model, 0.0), 0.0)))
        applied_discount = min(95.0, provider_discount + model_discount)
        estimated_average = ((input_rate + output_rate) / 2.0) * provider_multiplier * endpoint_multiplier * (1.0 - applied_discount / 100.0)
        ranking_score = float(row.context_window_tokens or 0) / max(1.0, estimated_average)
        catalog_rows.append(
            CostModelCatalogItemResponse(
                supported_model_id=row.supported_model_id,
                provider_type=row.provider_type,
                model_name=row.model_name,
                display_name=row.display_name,
                context_window_tokens=row.context_window_tokens,
                status=row.status,
                input_cents_per_1k=input_rate,
                output_cents_per_1k=output_rate,
                provider_multiplier=provider_multiplier,
                endpoint_multiplier=endpoint_multiplier,
                provider_discount_percent=provider_discount,
                model_discount_percent=model_discount,
                estimated_average_cost_cents_per_1k=round(estimated_average, 4),
                ranking_score=round(ranking_score, 4),
            )
        )

    catalog_rows.sort(key=lambda item: (-item.ranking_score, item.estimated_average_cost_cents_per_1k, item.model_name))
    return {
        "catalog": catalog_rows,
        "default_model_rates": default_rates,
        "provider_multipliers": provider_multipliers,
        "endpoint_multipliers": endpoint_multipliers,
        "provider_discounts": provider_discounts,
        "model_discounts": model_discounts,
    }


@router.post("/cost/pricing/calculate", response_model=CostPricingCalculateResponse)
def calculate_cost_pricing(
    payload: CostPricingCalculateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)
    model_rates, default_rates = _load_model_token_rates(db)
    provider_multipliers, endpoint_multipliers = _load_cloud_component_multipliers(db)
    provider_discounts, model_discounts = _load_provider_discounts(db)
    return _calculate_estimated_cost_cents(
        input_tokens=payload.input_tokens,
        output_tokens=payload.output_tokens,
        model_name=payload.model_name,
        provider_type=payload.provider_type,
        endpoint_family=payload.endpoint_family,
        model_rates=model_rates,
        default_model_rates=default_rates,
        provider_multipliers=provider_multipliers,
        endpoint_multipliers=endpoint_multipliers,
        provider_discounts=provider_discounts,
        model_discounts=model_discounts,
        custom_input_rate=payload.custom_input_cents_per_1k,
        custom_output_rate=payload.custom_output_cents_per_1k,
        custom_discount_percent=payload.custom_provider_discount_percent,
    )


def _property_value_from_json(properties_json: object, property_key: str) -> str:
    key = str(property_key or "").strip()
    if not key:
        return ""
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    value = parsed.get(key)
    if value is None:
        return ""
    return str(value).strip()[:256]


@router.get("/cost/sessions", response_model=CostSessionListResponse)
def list_cost_sessions(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    path_prefix: Optional[str] = Query(default=None, max_length=256),
    property_key: Optional[str] = Query(default=None, max_length=64),
    property_value: Optional[str] = Query(default=None, max_length=256),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style session drilldown: aggregate spend by session_id + session_path."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    since = datetime.utcnow() - timedelta(hours=int(window_hours))
    query = db.query(CostEvent).filter(CostEvent.timestamp >= since)
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostSessionListResponse(
                window_hours=int(window_hours),
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                items=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    prefix = str(path_prefix or "").strip().lower()
    prop_key = str(property_key or "").strip()
    prop_value = str(property_value or "").strip().lower()
    aggregates: dict[str, dict[str, object]] = {}
    for event in query.order_by(CostEvent.timestamp.desc()).limit(10_000).all():
        session_id = str(event.session_id or "").strip() or "unknown-session"
        session_path = _session_path_from_properties(event.properties_json)
        session_name = _session_name_from_properties(event.properties_json)
        if prefix and prefix not in session_path.lower() and prefix not in session_id.lower():
            continue
        if prop_key:
            actual = _property_value_from_json(event.properties_json, prop_key).lower()
            if prop_value:
                if prop_value not in actual:
                    continue
            elif not actual:
                continue
        key = f"{session_id}|{session_path}"
        bucket = aggregates.setdefault(
            key,
            {
                "session_id": session_id,
                "session_path": session_path or None,
                "session_name": session_name or None,
                "spend_cents": 0,
                "event_count": 0,
                "last_seen_at": event.timestamp,
            },
        )
        bucket["spend_cents"] = int(bucket["spend_cents"] or 0) + int(event.estimated_cost_cents or 0)
        bucket["event_count"] = int(bucket["event_count"] or 0) + 1
        if event.timestamp and (
            bucket.get("last_seen_at") is None or event.timestamp > bucket["last_seen_at"]  # type: ignore[operator]
        ):
            bucket["last_seen_at"] = event.timestamp
            if session_name:
                bucket["session_name"] = session_name

    items = [
        CostSessionSummaryItem(
            session_id=str(data["session_id"]),
            session_path=data.get("session_path"),  # type: ignore[arg-type]
            session_name=data.get("session_name"),  # type: ignore[arg-type]
            spend_cents=int(data["spend_cents"] or 0),
            event_count=int(data["event_count"] or 0),
            last_seen_at=data["last_seen_at"],  # type: ignore[arg-type]
        )
        for data in aggregates.values()
    ]
    items.sort(key=lambda row: row.spend_cents, reverse=True)
    items = items[: int(limit)]
    return CostSessionListResponse(
        window_hours=int(window_hours),
        total_spend_cents=int(sum(item.spend_cents for item in items)),
        total_event_count=int(sum(item.event_count for item in items)),
        count=len(items),
        items=items,
    )


def _build_session_timeseries_series(
    events: list[tuple[datetime, str, str, str, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_sessions: int,
) -> list[CostSessionTimeseriesSeries]:
    """Build hour-bucketed spend series for top sessions by spend.

    Event tuple: (timestamp, session_id, session_path, session_name, spend_cents).
    """
    session_totals: dict[str, dict[str, object]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, session_id, session_path, session_name, spend in events:
        key = f"{session_id}|{session_path}"
        bucket = session_totals.setdefault(
            key,
            {
                "session_id": session_id,
                "session_path": session_path or None,
                "session_name": session_name or None,
                "spend_cents": 0,
                "event_count": 0,
            },
        )
        bucket["spend_cents"] = int(bucket["spend_cents"] or 0) + int(spend or 0)
        bucket["event_count"] = int(bucket["event_count"] or 0) + 1
        if session_name:
            bucket["session_name"] = session_name
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(key, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1

    ranked = sorted(
        session_totals.items(),
        key=lambda item: (int(item[1]["spend_cents"] or 0), int(item[1]["event_count"] or 0)),
        reverse=True,
    )[: max(1, min(int(top_sessions or 1), 20))]

    series: list[CostSessionTimeseriesSeries] = []
    for key, totals in ranked:
        hours = hour_buckets.get(key) or {}
        cursor = start_hour
        points: list[CostSessionTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0}
            points.append(
                CostSessionTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"] or 0),
                    event_count=int(point["event_count"] or 0),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostSessionTimeseriesSeries(
                session_key=key,
                session_id=str(totals["session_id"]),
                session_path=totals.get("session_path"),  # type: ignore[arg-type]
                session_name=totals.get("session_name"),  # type: ignore[arg-type]
                spend_cents=int(totals["spend_cents"] or 0),
                event_count=int(totals["event_count"] or 0),
                points=points,
            )
        )
    return series


@router.get("/cost/sessions/timeseries", response_model=CostSessionTimeseriesResponse)
def get_cost_sessions_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    path_prefix: Optional[str] = Query(default=None, max_length=256),
    top_sessions: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly session spend charts from session_id / session_path."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.session_id,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostSessionTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                path_prefix=str(path_prefix or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    prefix = str(path_prefix or "").strip().lower()
    events: list[tuple[datetime, str, str, str, int]] = []
    for ts, session_id, properties_json, estimated_cost_cents in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        sid = str(session_id or "").strip() or "unknown-session"
        session_path = _session_path_from_properties(properties_json)
        session_name = _session_name_from_properties(properties_json)
        if prefix and prefix not in session_path.lower() and prefix not in sid.lower():
            continue
        events.append(
            (
                ts,
                sid,
                session_path,
                session_name,
                int(estimated_cost_cents or 0),
            )
        )

    series = _build_session_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_sessions=top_sessions,
    )
    return CostSessionTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        path_prefix=prefix or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


@router.get("/cost/users", response_model=CostUserListResponse)
def list_cost_users(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    user_filter: Optional[str] = Query(default=None, max_length=128),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style user spend analytics from cost event properties (`user` / `user_id`)."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    since = datetime.utcnow() - timedelta(hours=int(window_hours))
    query = db.query(CostEvent).filter(CostEvent.timestamp >= since)
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostUserListResponse(
                window_hours=int(window_hours),
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                items=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(user_filter or "").strip().lower()
    aggregates: dict[str, dict[str, object]] = {}
    for event in query.order_by(CostEvent.timestamp.desc()).limit(10_000).all():
        user_id = _user_id_from_event(event) or "unknown-user"
        if filter_text and filter_text not in user_id.lower():
            continue
        bucket = aggregates.setdefault(
            user_id,
            {
                "user_id": user_id,
                "spend_cents": 0,
                "event_count": 0,
                "sessions": set(),
                "last_seen_at": event.timestamp,
            },
        )
        bucket["spend_cents"] = int(bucket["spend_cents"] or 0) + int(event.estimated_cost_cents or 0)
        bucket["event_count"] = int(bucket["event_count"] or 0) + 1
        sessions = bucket["sessions"]
        if isinstance(sessions, set):
            sessions.add(str(event.session_id or "").strip() or "unknown-session")
        if event.timestamp and (
            bucket.get("last_seen_at") is None or event.timestamp > bucket["last_seen_at"]  # type: ignore[operator]
        ):
            bucket["last_seen_at"] = event.timestamp

    items = [
        CostUserSummaryItem(
            user_id=str(data["user_id"]),
            spend_cents=int(data["spend_cents"] or 0),
            event_count=int(data["event_count"] or 0),
            session_count=len(data["sessions"]) if isinstance(data.get("sessions"), set) else 0,
            last_seen_at=data["last_seen_at"],  # type: ignore[arg-type]
        )
        for data in aggregates.values()
    ]
    items.sort(key=lambda row: row.spend_cents, reverse=True)
    items = items[: int(limit)]
    return CostUserListResponse(
        window_hours=int(window_hours),
        total_spend_cents=int(sum(item.spend_cents for item in items)),
        total_event_count=int(sum(item.event_count for item in items)),
        count=len(items),
        items=items,
    )


def _build_user_timeseries_series(
    events: list[tuple[datetime, str, int, str]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_users: int,
) -> list[CostUserTimeseriesSeries]:
    """Build hour-bucketed spend series for top users by spend."""
    user_totals: dict[str, dict[str, object]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, object]]] = {}
    for ts, user_id, spend, session_id in events:
        bucket = user_totals.setdefault(
            user_id,
            {"spend_cents": 0, "event_count": 0, "sessions": set()},
        )
        bucket["spend_cents"] = int(bucket["spend_cents"] or 0) + int(spend or 0)
        bucket["event_count"] = int(bucket["event_count"] or 0) + 1
        sessions = bucket["sessions"]
        if isinstance(sessions, set):
            sessions.add(str(session_id or "").strip() or "unknown-session")
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(user_id, {})
        point = hours.setdefault(
            hour,
            {"spend_cents": 0, "event_count": 0, "sessions": set()},
        )
        point["spend_cents"] = int(point["spend_cents"] or 0) + int(spend or 0)
        point["event_count"] = int(point["event_count"] or 0) + 1
        point_sessions = point["sessions"]
        if isinstance(point_sessions, set):
            point_sessions.add(str(session_id or "").strip() or "unknown-session")

    ranked = sorted(
        user_totals.items(),
        key=lambda item: (int(item[1]["spend_cents"] or 0), int(item[1]["event_count"] or 0)),
        reverse=True,
    )[: max(1, min(int(top_users or 1), 20))]

    series: list[CostUserTimeseriesSeries] = []
    for user_id, totals in ranked:
        hours = hour_buckets.get(user_id) or {}
        cursor = start_hour
        points: list[CostUserTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "sessions": set()}
            point_sessions = point.get("sessions")
            points.append(
                CostUserTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"] or 0),
                    event_count=int(point["event_count"] or 0),
                    session_count=len(point_sessions) if isinstance(point_sessions, set) else 0,
                )
            )
            cursor += timedelta(hours=1)
        total_sessions = totals.get("sessions")
        series.append(
            CostUserTimeseriesSeries(
                user_id=user_id,
                spend_cents=int(totals["spend_cents"] or 0),
                event_count=int(totals["event_count"] or 0),
                session_count=len(total_sessions) if isinstance(total_sessions, set) else 0,
                points=points,
            )
        )
    return series


@router.get("/cost/users/timeseries", response_model=CostUserTimeseriesResponse)
def get_cost_users_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    user_filter: Optional[str] = Query(default=None, max_length=128),
    top_users: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly user spend charts from cost event `user` / `user_id` properties."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.owner_scope,
        CostEvent.estimated_cost_cents,
        CostEvent.session_id,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostUserTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                user_filter=str(user_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(user_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, str]] = []
    for ts, properties_json, owner_scope, estimated_cost_cents, session_id in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        user_id = (
            _user_id_from_event(properties_json=properties_json, owner_scope=owner_scope) or "unknown-user"
        )
        if filter_text and filter_text not in user_id.lower():
            continue
        events.append(
            (
                ts,
                user_id,
                int(estimated_cost_cents or 0),
                str(session_id or "").strip() or "unknown-session",
            )
        )

    series = _build_user_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_users=top_users,
    )
    return CostUserTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        user_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


@router.get("/cost/models/stats", response_model=CostModelStatsResponse)
def list_cost_model_stats(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    model_filter: Optional[str] = Query(default=None, max_length=128),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style model spend analytics from cost events."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    since = datetime.utcnow() - timedelta(hours=int(window_hours))
    query = db.query(CostEvent).filter(CostEvent.timestamp >= since)
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostModelStatsResponse(
                window_hours=int(window_hours),
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                items=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(model_filter or "").strip().lower()
    aggregates: dict[str, dict[str, object]] = {}
    for event in query.order_by(CostEvent.timestamp.desc()).limit(10_000).all():
        model_name = str(event.model_name or "").strip() or "unknown-model"
        if filter_text and filter_text not in model_name.lower():
            continue
        bucket = aggregates.setdefault(
            model_name,
            {
                "model_name": model_name,
                "spend_cents": 0,
                "event_count": 0,
                "total_tokens": 0,
                "last_seen_at": event.timestamp,
            },
        )
        bucket["spend_cents"] = int(bucket["spend_cents"] or 0) + int(event.estimated_cost_cents or 0)
        bucket["event_count"] = int(bucket["event_count"] or 0) + 1
        bucket["total_tokens"] = (
            int(bucket["total_tokens"] or 0)
            + int(event.input_tokens or 0)
            + int(event.output_tokens or 0)
        )
        if event.timestamp and (
            bucket.get("last_seen_at") is None or event.timestamp > bucket["last_seen_at"]  # type: ignore[operator]
        ):
            bucket["last_seen_at"] = event.timestamp

    items = [
        CostModelStatsItem(
            model_name=str(data["model_name"]),
            spend_cents=int(data["spend_cents"] or 0),
            event_count=int(data["event_count"] or 0),
            total_tokens=int(data["total_tokens"] or 0),
            last_seen_at=data["last_seen_at"],  # type: ignore[arg-type]
        )
        for data in aggregates.values()
    ]
    items.sort(key=lambda row: row.spend_cents, reverse=True)
    items = items[: int(limit)]
    return CostModelStatsResponse(
        window_hours=int(window_hours),
        total_spend_cents=int(sum(item.spend_cents for item in items)),
        total_event_count=int(sum(item.event_count for item in items)),
        count=len(items),
        items=items,
    )


def _build_model_timeseries_series(
    events: list[tuple[datetime, str, int, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_models: int,
) -> list[CostModelTimeseriesSeries]:
    """Build hour-bucketed series for the top models by spend."""
    model_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, model_name, spend, input_tokens, output_tokens in events:
        bucket = model_totals.setdefault(
            model_name,
            {
                "spend_cents": 0,
                "event_count": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
            },
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["input_tokens"] += int(input_tokens or 0)
        bucket["output_tokens"] += int(output_tokens or 0)
        bucket["total_tokens"] += int(input_tokens or 0) + int(output_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(model_name, {})
        point = hours.setdefault(
            hour,
            {
                "spend_cents": 0,
                "event_count": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
            },
        )
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["input_tokens"] += int(input_tokens or 0)
        point["output_tokens"] += int(output_tokens or 0)
        point["total_tokens"] += int(input_tokens or 0) + int(output_tokens or 0)

    ranked = sorted(
        model_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_models or 1), 20))]

    series: list[CostModelTimeseriesSeries] = []
    for model_name, totals in ranked:
        hours = hour_buckets.get(model_name) or {}
        cursor = start_hour
        points: list[CostModelTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {
                "spend_cents": 0,
                "event_count": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
            }
            points.append(
                CostModelTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    input_tokens=int(point["input_tokens"]),
                    output_tokens=int(point["output_tokens"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostModelTimeseriesSeries(
                model_name=model_name,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                input_tokens=int(totals["input_tokens"]),
                output_tokens=int(totals["output_tokens"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/models/timeseries", response_model=CostModelTimeseriesResponse)
def get_cost_model_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    model_filter: Optional[str] = Query(default=None, max_length=128),
    top_models: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top models by spend."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.model_name,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostModelTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                model_filter=str(model_filter or "").strip() or None,
                total_spend_cents=0,
                total_tokens=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(model_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int, int]] = []
    for ts, model_name, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        name = str(model_name or "").strip() or "unknown-model"
        if filter_text and filter_text not in name.lower():
            continue
        events.append(
            (
                ts,
                name,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0),
                int(output_tokens or 0),
            )
        )

    series = _build_model_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_models=top_models,
    )
    return CostModelTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        model_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_tokens=int(sum(item.total_tokens for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_tag_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_tags: int,
) -> list[CostTagTimeseriesSeries]:
    """Build hour-bucketed spend series for top request tags.

    Event tuple: (timestamp, request_tag, spend_cents, total_tokens).
    """
    tag_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, request_tag, spend, total_tokens in events:
        bucket = tag_totals.setdefault(
            request_tag,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(request_tag, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        tag_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_tags or 1), 20))]

    series: list[CostTagTimeseriesSeries] = []
    for request_tag, totals in ranked:
        hours = hour_buckets.get(request_tag) or {}
        cursor = start_hour
        points: list[CostTagTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostTagTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostTagTimeseriesSeries(
                request_tag=request_tag,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/tags/timeseries", response_model=CostTagTimeseriesResponse)
def get_cost_tags_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    tag_filter: Optional[str] = Query(default=None, max_length=64),
    top_tags: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top request tags."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.request_tag,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostTagTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                tag_filter=str(tag_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(tag_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, request_tag, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        tag = str(request_tag or "").strip() or "untagged"
        if filter_text and filter_text not in tag.lower():
            continue
        events.append(
            (
                ts,
                tag,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_tag_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_tags=top_tags,
    )
    return CostTagTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        tag_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_endpoint_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_endpoints: int,
) -> list[CostEndpointTimeseriesSeries]:
    """Build hour-bucketed spend series for top endpoint families.

    Event tuple: (timestamp, endpoint_family, spend_cents, total_tokens).
    """
    endpoint_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, endpoint_family, spend, total_tokens in events:
        bucket = endpoint_totals.setdefault(
            endpoint_family,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(endpoint_family, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        endpoint_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_endpoints or 1), 20))]

    series: list[CostEndpointTimeseriesSeries] = []
    for endpoint_family, totals in ranked:
        hours = hour_buckets.get(endpoint_family) or {}
        cursor = start_hour
        points: list[CostEndpointTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostEndpointTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostEndpointTimeseriesSeries(
                endpoint_family=endpoint_family,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/endpoints/timeseries", response_model=CostEndpointTimeseriesResponse)
def get_cost_endpoints_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    endpoint_filter: Optional[str] = Query(default=None, max_length=128),
    top_endpoints: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top endpoint families."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.endpoint_family,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostEndpointTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                endpoint_filter=str(endpoint_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(endpoint_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, endpoint_family, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        family = str(endpoint_family or "").strip() or "unknown"
        if filter_text and filter_text not in family.lower():
            continue
        events.append(
            (
                ts,
                family,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_endpoint_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_endpoints=top_endpoints,
    )
    return CostEndpointTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        endpoint_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_agent_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_agents: int,
) -> list[CostAgentTimeseriesSeries]:
    """Build hour-bucketed spend series for top agents.

    Event tuple: (timestamp, agent_id, spend_cents, total_tokens).
    """
    agent_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, agent_id, spend, total_tokens in events:
        bucket = agent_totals.setdefault(
            agent_id,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(agent_id, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        agent_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_agents or 1), 20))]

    series: list[CostAgentTimeseriesSeries] = []
    for agent_id, totals in ranked:
        hours = hour_buckets.get(agent_id) or {}
        cursor = start_hour
        points: list[CostAgentTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostAgentTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostAgentTimeseriesSeries(
                agent_id=agent_id,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/agents/timeseries", response_model=CostAgentTimeseriesResponse)
def get_cost_agents_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    agent_filter: Optional[str] = Query(default=None, max_length=64),
    top_agents: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top agents."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.agent_id,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    owned_agent_ids: Optional[list[str]] = None
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostAgentTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                agent_filter=str(agent_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(agent_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, agent_id, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        agent = str(agent_id or "").strip() or "unknown"
        if filter_text and filter_text not in agent.lower():
            continue
        events.append(
            (
                ts,
                agent,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_agent_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_agents=top_agents,
    )
    return CostAgentTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        agent_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_environment_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_environments: int,
) -> list[CostEnvironmentTimeseriesSeries]:
    """Build hour-bucketed spend series for top environments.

    Event tuple: (timestamp, environment, spend_cents, total_tokens).
    """
    env_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, environment, spend, total_tokens in events:
        bucket = env_totals.setdefault(
            environment,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(environment, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        env_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_environments or 1), 20))]

    series: list[CostEnvironmentTimeseriesSeries] = []
    for environment, totals in ranked:
        hours = hour_buckets.get(environment) or {}
        cursor = start_hour
        points: list[CostEnvironmentTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostEnvironmentTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostEnvironmentTimeseriesSeries(
                environment=environment,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/environments/timeseries", response_model=CostEnvironmentTimeseriesResponse)
def get_cost_environments_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    environment_filter: Optional[str] = Query(default=None, max_length=64),
    top_environments: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top environments."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.environment,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostEnvironmentTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                environment_filter=str(environment_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(environment_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, environment, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        env = str(environment or "").strip() or "dev"
        if filter_text and filter_text not in env.lower():
            continue
        events.append(
            (
                ts,
                env,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_environment_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_environments=top_environments,
    )
    return CostEnvironmentTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        environment_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_owner_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_owners: int,
) -> list[CostOwnerTimeseriesSeries]:
    """Build hour-bucketed spend series for top owner scopes.

    Event tuple: (timestamp, owner_scope, spend_cents, total_tokens).
    """
    owner_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, owner_scope, spend, total_tokens in events:
        bucket = owner_totals.setdefault(
            owner_scope,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(owner_scope, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        owner_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_owners or 1), 20))]

    series: list[CostOwnerTimeseriesSeries] = []
    for owner_scope, totals in ranked:
        hours = hour_buckets.get(owner_scope) or {}
        cursor = start_hour
        points: list[CostOwnerTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostOwnerTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostOwnerTimeseriesSeries(
                owner_scope=owner_scope,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


def _owner_filter_rollup_scopes(db: Session, owner_filter: str | None) -> set[str] | None:
    """When filter is type:id for a hierarchy scope, return membership rollup set (lowercased)."""
    filter_text = str(owner_filter or "").strip()
    if ":" not in filter_text:
        return None
    scope_type, scope_id = filter_text.split(":", 1)
    normalized_type = scope_type.strip().lower()
    normalized_id = scope_id.strip()
    if normalized_type not in {
        COST_SCOPE_USER,
        COST_SCOPE_TEAM,
        COST_SCOPE_GROUP,
        "actor",
        "owner",
    }:
        return None
    if not normalized_id:
        return None
    return {scope.lower() for scope in rollup_owner_scopes_for_scope(db, normalized_type, normalized_id)}


@router.get("/cost/owners/timeseries", response_model=CostOwnerTimeseriesResponse)
def get_cost_owners_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    owner_filter: Optional[str] = Query(default=None, max_length=128),
    top_owners: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top owner scopes."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.owner_scope,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostOwnerTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                owner_filter=str(owner_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(owner_filter or "").strip().lower()
    rollup_scopes = _owner_filter_rollup_scopes(db, owner_filter)
    events: list[tuple[datetime, str, int, int]] = []
    for ts, owner_scope, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        owner = str(owner_scope or "").strip() or "unknown"
        owner_lower = owner.lower()
        if rollup_scopes is not None:
            if owner_lower not in rollup_scopes:
                continue
        elif filter_text and filter_text not in owner_lower:
            continue
        events.append(
            (
                ts,
                owner,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_owner_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_owners=top_owners,
    )
    return CostOwnerTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        owner_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_currency_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_currencies: int,
) -> list[CostCurrencyTimeseriesSeries]:
    """Build hour-bucketed spend series for top currencies.

    Event tuple: (timestamp, currency, spend_cents, total_tokens).
    """
    currency_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, currency, spend, total_tokens in events:
        bucket = currency_totals.setdefault(
            currency,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(currency, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        currency_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_currencies or 1), 20))]

    series: list[CostCurrencyTimeseriesSeries] = []
    for currency, totals in ranked:
        hours = hour_buckets.get(currency) or {}
        cursor = start_hour
        points: list[CostCurrencyTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostCurrencyTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostCurrencyTimeseriesSeries(
                currency=currency,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/currencies/timeseries", response_model=CostCurrencyTimeseriesResponse)
def get_cost_currencies_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    currency_filter: Optional[str] = Query(default=None, max_length=8),
    top_currencies: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top currencies."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.currency,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostCurrencyTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                currency_filter=str(currency_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(currency_filter or "").strip().upper()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, currency, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        code = str(currency or "").strip().upper() or "USD"
        if filter_text and filter_text not in code:
            continue
        events.append(
            (
                ts,
                code,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_currency_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_currencies=top_currencies,
    )
    return CostCurrencyTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        currency_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_provider_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_providers: int,
) -> list[CostProviderTimeseriesSeries]:
    """Build hour-bucketed spend series for top inferred providers.

    Event tuple: (timestamp, provider, spend_cents, total_tokens).
    """
    provider_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, provider, spend, total_tokens in events:
        bucket = provider_totals.setdefault(
            provider,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(provider, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        provider_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_providers or 1), 20))]

    series: list[CostProviderTimeseriesSeries] = []
    for provider, totals in ranked:
        hours = hour_buckets.get(provider) or {}
        cursor = start_hour
        points: list[CostProviderTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostProviderTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostProviderTimeseriesSeries(
                provider=provider,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/providers/timeseries", response_model=CostProviderTimeseriesResponse)
def get_cost_providers_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    provider_filter: Optional[str] = Query(default=None, max_length=64),
    top_providers: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top providers (inferred from model_name)."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.model_name,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostProviderTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                provider_filter=str(provider_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(provider_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, model_name, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        provider, _ = infer_provider_type_from_model(str(model_name or ""))
        provider = str(provider or "").strip().lower() or "unknown"
        if filter_text and filter_text not in provider:
            continue
        events.append(
            (
                ts,
                provider,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_provider_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_providers=top_providers,
    )
    return CostProviderTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        provider_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _team_from_owner_scope(owner_scope: object) -> str:
    """Extract Helicone-style team id from `team:...` owner scopes."""
    text = str(owner_scope or "").strip()
    if not text:
        return ""
    lower = text.lower()
    if lower.startswith("team:"):
        return text.split(":", 1)[1].strip() or "unknown-team"
    if lower.startswith("team/"):
        return text.split("/", 1)[1].strip() or "unknown-team"
    return ""


def _build_team_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_teams: int,
) -> list[CostTeamTimeseriesSeries]:
    """Build hour-bucketed spend series for top teams.

    Event tuple: (timestamp, team, spend_cents, total_tokens).
    """
    team_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, team, spend, total_tokens in events:
        bucket = team_totals.setdefault(
            team,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(team, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        team_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_teams or 1), 20))]

    series: list[CostTeamTimeseriesSeries] = []
    for team, totals in ranked:
        hours = hour_buckets.get(team) or {}
        cursor = start_hour
        points: list[CostTeamTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostTeamTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostTeamTimeseriesSeries(
                team=team,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/teams/timeseries", response_model=CostTeamTimeseriesResponse)
def get_cost_teams_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    team_filter: Optional[str] = Query(default=None, max_length=128),
    top_teams: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top teams (tagged `team:` plus member rollup)."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.owner_scope,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostTeamTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                team_filter=str(team_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(team_filter or "").strip().lower()
    user_teams, _user_groups = build_user_membership_index(db)
    events: list[tuple[datetime, str, int, int]] = []
    for ts, owner_scope, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        teams: list[str] = []
        tagged = _team_from_owner_scope(owner_scope)
        if tagged:
            teams.append(tagged)
        for scope_type, scope_id in hierarchy_attribution_keys(
            str(owner_scope or ""),
            user_teams=user_teams,
            user_groups=None,
        ):
            if scope_type == "team" and scope_id not in teams:
                teams.append(scope_id)
        if not teams:
            continue
        for team in teams:
            if filter_text and filter_text not in team.lower():
                continue
            events.append(
                (
                    ts,
                    team,
                    int(estimated_cost_cents or 0),
                    int(input_tokens or 0) + int(output_tokens or 0),
                )
            )

    series = _build_team_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_teams=top_teams,
    )
    return CostTeamTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        team_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _group_from_owner_scope(owner_scope: object) -> str:
    """Extract Helicone-style group id from `group:...` owner scopes."""
    text = str(owner_scope or "").strip()
    if not text:
        return ""
    lower = text.lower()
    if lower.startswith("group:"):
        return text.split(":", 1)[1].strip() or "unknown-group"
    if lower.startswith("group/"):
        return text.split("/", 1)[1].strip() or "unknown-group"
    return ""


def _build_group_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_groups: int,
) -> list[CostGroupTimeseriesSeries]:
    """Build hour-bucketed spend series for top groups.

    Event tuple: (timestamp, group, spend_cents, total_tokens).
    """
    group_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, group, spend, total_tokens in events:
        bucket = group_totals.setdefault(
            group,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(group, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        group_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_groups or 1), 20))]

    series: list[CostGroupTimeseriesSeries] = []
    for group, totals in ranked:
        hours = hour_buckets.get(group) or {}
        cursor = start_hour
        points: list[CostGroupTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostGroupTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostGroupTimeseriesSeries(
                group=group,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/groups/timeseries", response_model=CostGroupTimeseriesResponse)
def get_cost_groups_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    group_filter: Optional[str] = Query(default=None, max_length=128),
    top_groups: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top groups (tagged `group:` plus member rollup)."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.owner_scope,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostGroupTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                group_filter=str(group_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(group_filter or "").strip().lower()
    _user_teams, user_groups = build_user_membership_index(db)
    events: list[tuple[datetime, str, int, int]] = []
    for ts, owner_scope, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        groups: list[str] = []
        tagged = _group_from_owner_scope(owner_scope)
        if tagged:
            groups.append(tagged)
        for scope_type, scope_id in hierarchy_attribution_keys(
            str(owner_scope or ""),
            user_teams=None,
            user_groups=user_groups,
        ):
            if scope_type == "group" and scope_id not in groups:
                groups.append(scope_id)
        if not groups:
            continue
        for group in groups:
            if filter_text and filter_text not in group.lower():
                continue
            events.append(
                (
                    ts,
                    group,
                    int(estimated_cost_cents or 0),
                    int(input_tokens or 0) + int(output_tokens or 0),
                )
            )

    series = _build_group_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_groups=top_groups,
    )
    return CostGroupTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        group_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _project_from_properties(properties_json: object) -> str:
    """Extract Helicone-style project id from flat cost properties."""
    for key in (
        "project",
        "project_id",
        "Helicone-Project-Id",
        "helicone-project-id",
        "helicone_project_id",
    ):
        value = _flat_property_value_for_stats(properties_json, key)
        if value:
            return value[:128]
    return ""


def _build_project_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_projects: int,
) -> list[CostProjectTimeseriesSeries]:
    """Build hour-bucketed spend series for top projects.

    Event tuple: (timestamp, project, spend_cents, total_tokens).
    """
    project_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, project, spend, total_tokens in events:
        bucket = project_totals.setdefault(
            project,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(project, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        project_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_projects or 1), 20))]

    series: list[CostProjectTimeseriesSeries] = []
    for project, totals in ranked:
        hours = hour_buckets.get(project) or {}
        cursor = start_hour
        points: list[CostProjectTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostProjectTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostProjectTimeseriesSeries(
                project=project,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/projects/timeseries", response_model=CostProjectTimeseriesResponse)
def get_cost_projects_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    project_filter: Optional[str] = Query(default=None, max_length=128),
    top_projects: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top projects (from cost properties)."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostProjectTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                project_filter=str(project_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(project_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        project = _project_from_properties(properties_json)
        if not project:
            continue
        if filter_text and filter_text not in project.lower():
            continue
        events.append(
            (
                ts,
                project,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_project_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_projects=top_projects,
    )
    return CostProjectTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        project_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_feedback_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
) -> list[CostFeedbackTimeseriesSeries]:
    """Build hour-bucketed spend series for feedback presence.

    Event tuple: (timestamp, feedback_state, spend_cents, total_tokens).
    feedback_state is `has_feedback` or `no_feedback`.
    """
    state_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, feedback_state, spend, total_tokens in events:
        bucket = state_totals.setdefault(
            feedback_state,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(feedback_state, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    order = {"has_feedback": 0, "no_feedback": 1}
    ranked = sorted(
        state_totals.items(),
        key=lambda item: (order.get(item[0], 9), -item[1]["spend_cents"], -item[1]["event_count"]),
    )

    series: list[CostFeedbackTimeseriesSeries] = []
    for feedback_state, totals in ranked:
        hours = hour_buckets.get(feedback_state) or {}
        cursor = start_hour
        points: list[CostFeedbackTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostFeedbackTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostFeedbackTimeseriesSeries(
                feedback_state=feedback_state,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/feedback/timeseries", response_model=CostFeedbackTimeseriesResponse)
def get_cost_feedback_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    feedback_filter: Optional[str] = Query(default=None, max_length=32),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for feedback presence (`has_feedback` / `no_feedback`)."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostFeedbackTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                feedback_filter=str(feedback_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(feedback_filter or "").strip().lower()
    if filter_text in {"true", "1", "yes", "has", "has_feedback"}:
        filter_text = "has_feedback"
    elif filter_text in {"false", "0", "no", "none", "no_feedback"}:
        filter_text = "no_feedback"
    elif filter_text and filter_text not in {"has_feedback", "no_feedback"}:
        filter_text = ""

    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        state = (
            "has_feedback"
            if bool(_feedback_fields_from_properties(properties_json).get("has_feedback"))
            else "no_feedback"
        )
        if filter_text and state != filter_text:
            continue
        events.append(
            (
                ts,
                state,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_feedback_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
    )
    return CostFeedbackTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        feedback_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_session_path_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_paths: int,
) -> list[CostSessionPathTimeseriesSeries]:
    """Build hour-bucketed spend series for top session_path values.

    Event tuple: (timestamp, session_path, spend_cents, total_tokens).
    """
    path_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, session_path, spend, total_tokens in events:
        bucket = path_totals.setdefault(
            session_path,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(session_path, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        path_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_paths or 1), 20))]

    series: list[CostSessionPathTimeseriesSeries] = []
    for session_path, totals in ranked:
        hours = hour_buckets.get(session_path) or {}
        cursor = start_hour
        points: list[CostSessionPathTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostSessionPathTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostSessionPathTimeseriesSeries(
                session_path=session_path,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/session-paths/timeseries", response_model=CostSessionPathTimeseriesResponse)
def get_cost_session_paths_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    path_filter: Optional[str] = Query(default=None, max_length=128),
    top_paths: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top session_path property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostSessionPathTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                path_filter=str(path_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(path_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        session_path = _session_path_from_properties(properties_json)
        if not session_path:
            continue
        if filter_text and filter_text not in session_path.lower():
            continue
        events.append(
            (
                ts,
                session_path,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_session_path_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_paths=top_paths,
    )
    return CostSessionPathTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        path_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_session_name_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_names: int,
) -> list[CostSessionNameTimeseriesSeries]:
    """Build hour-bucketed spend series for top session_name values.

    Event tuple: (timestamp, session_name, spend_cents, total_tokens).
    """
    name_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, session_name, spend, total_tokens in events:
        bucket = name_totals.setdefault(
            session_name,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(session_name, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        name_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_names or 1), 20))]

    series: list[CostSessionNameTimeseriesSeries] = []
    for session_name, totals in ranked:
        hours = hour_buckets.get(session_name) or {}
        cursor = start_hour
        points: list[CostSessionNameTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostSessionNameTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostSessionNameTimeseriesSeries(
                session_name=session_name,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/session-names/timeseries", response_model=CostSessionNameTimeseriesResponse)
def get_cost_session_names_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    name_filter: Optional[str] = Query(default=None, max_length=128),
    top_names: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top session_name property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostSessionNameTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                name_filter=str(name_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(name_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        session_name = _session_name_from_properties(properties_json)
        if not session_name:
            continue
        if filter_text and filter_text not in session_name.lower():
            continue
        events.append(
            (
                ts,
                session_name,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_session_name_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_names=top_names,
    )
    return CostSessionNameTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        name_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_prompt_id_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_prompts: int,
) -> list[CostPromptIdTimeseriesSeries]:
    """Build hour-bucketed spend series for top prompt_id values.

    Event tuple: (timestamp, prompt_id, spend_cents, total_tokens).
    """
    prompt_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, prompt_id, spend, total_tokens in events:
        bucket = prompt_totals.setdefault(
            prompt_id,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(prompt_id, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        prompt_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_prompts or 1), 20))]

    series: list[CostPromptIdTimeseriesSeries] = []
    for prompt_id, totals in ranked:
        hours = hour_buckets.get(prompt_id) or {}
        cursor = start_hour
        points: list[CostPromptIdTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostPromptIdTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostPromptIdTimeseriesSeries(
                prompt_id=prompt_id,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/prompt-ids/timeseries", response_model=CostPromptIdTimeseriesResponse)
def get_cost_prompt_ids_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    prompt_filter: Optional[str] = Query(default=None, max_length=128),
    top_prompts: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone/Portkey-style hourly burn charts for top prompt_id property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostPromptIdTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                prompt_filter=str(prompt_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(prompt_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        prompt_id = _prompt_id_from_properties(properties_json)
        if not prompt_id:
            continue
        if filter_text and filter_text not in prompt_id.lower():
            continue
        events.append(
            (
                ts,
                prompt_id,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_prompt_id_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_prompts=top_prompts,
    )
    return CostPromptIdTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        prompt_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_application_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_applications: int,
) -> list[CostApplicationTimeseriesSeries]:
    """Build hour-bucketed spend series for top application property values.

    Event tuple: (timestamp, application, spend_cents, total_tokens).
    """
    app_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, application, spend, total_tokens in events:
        bucket = app_totals.setdefault(
            application,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(application, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        app_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_applications or 1), 20))]

    series: list[CostApplicationTimeseriesSeries] = []
    for application, totals in ranked:
        hours = hour_buckets.get(application) or {}
        cursor = start_hour
        points: list[CostApplicationTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostApplicationTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostApplicationTimeseriesSeries(
                application=application,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/applications/timeseries", response_model=CostApplicationTimeseriesResponse)
def get_cost_applications_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    application_filter: Optional[str] = Query(default=None, max_length=128),
    top_applications: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top application/app property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostApplicationTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                application_filter=str(application_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(application_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        application = _application_from_properties(properties_json)
        if not application:
            continue
        if filter_text and filter_text not in application.lower():
            continue
        events.append(
            (
                ts,
                application,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_application_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_applications=top_applications,
    )
    return CostApplicationTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        application_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_customer_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_customers: int,
) -> list[CostCustomerTimeseriesSeries]:
    """Build hour-bucketed spend series for top customer property values.

    Event tuple: (timestamp, customer, spend_cents, total_tokens).
    """
    customer_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, customer, spend, total_tokens in events:
        bucket = customer_totals.setdefault(
            customer,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(customer, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        customer_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_customers or 1), 20))]

    series: list[CostCustomerTimeseriesSeries] = []
    for customer, totals in ranked:
        hours = hour_buckets.get(customer) or {}
        cursor = start_hour
        points: list[CostCustomerTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostCustomerTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostCustomerTimeseriesSeries(
                customer=customer,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/customers/timeseries", response_model=CostCustomerTimeseriesResponse)
def get_cost_customers_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    customer_filter: Optional[str] = Query(default=None, max_length=128),
    top_customers: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top customer_id/customer property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostCustomerTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                customer_filter=str(customer_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(customer_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        customer = _customer_from_properties(properties_json)
        if not customer:
            continue
        if filter_text and filter_text not in customer.lower():
            continue
        events.append(
            (
                ts,
                customer,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_customer_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_customers=top_customers,
    )
    return CostCustomerTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        customer_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_department_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_departments: int,
) -> list[CostDepartmentTimeseriesSeries]:
    """Build hour-bucketed spend series for top department property values.

    Event tuple: (timestamp, department, spend_cents, total_tokens).
    """
    dept_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, department, spend, total_tokens in events:
        bucket = dept_totals.setdefault(
            department,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(department, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        dept_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_departments or 1), 20))]

    series: list[CostDepartmentTimeseriesSeries] = []
    for department, totals in ranked:
        hours = hour_buckets.get(department) or {}
        cursor = start_hour
        points: list[CostDepartmentTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostDepartmentTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostDepartmentTimeseriesSeries(
                department=department,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/departments/timeseries", response_model=CostDepartmentTimeseriesResponse)
def get_cost_departments_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    department_filter: Optional[str] = Query(default=None, max_length=128),
    top_departments: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top department/dept/cost_center property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostDepartmentTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                department_filter=str(department_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(department_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        department = _department_from_properties(properties_json)
        if not department:
            continue
        if filter_text and filter_text not in department.lower():
            continue
        events.append(
            (
                ts,
                department,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_department_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_departments=top_departments,
    )
    return CostDepartmentTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        department_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_feature_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_features: int,
) -> list[CostFeatureTimeseriesSeries]:
    """Build hour-bucketed spend series for top feature property values.

    Event tuple: (timestamp, feature, spend_cents, total_tokens).
    """
    feature_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, feature, spend, total_tokens in events:
        bucket = feature_totals.setdefault(
            feature,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(feature, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        feature_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_features or 1), 20))]

    series: list[CostFeatureTimeseriesSeries] = []
    for feature, totals in ranked:
        hours = hour_buckets.get(feature) or {}
        cursor = start_hour
        points: list[CostFeatureTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostFeatureTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostFeatureTimeseriesSeries(
                feature=feature,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/features/timeseries", response_model=CostFeatureTimeseriesResponse)
def get_cost_features_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    feature_filter: Optional[str] = Query(default=None, max_length=128),
    top_features: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top feature/feature_flag property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostFeatureTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                feature_filter=str(feature_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(feature_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        feature = _feature_from_properties(properties_json)
        if not feature:
            continue
        if filter_text and filter_text not in feature.lower():
            continue
        events.append(
            (
                ts,
                feature,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_feature_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_features=top_features,
    )
    return CostFeatureTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        feature_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_region_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_regions: int,
) -> list[CostRegionTimeseriesSeries]:
    """Build hour-bucketed spend series for top region property values.

    Event tuple: (timestamp, region, spend_cents, total_tokens).
    """
    region_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, region, spend, total_tokens in events:
        bucket = region_totals.setdefault(
            region,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(region, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        region_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_regions or 1), 20))]

    series: list[CostRegionTimeseriesSeries] = []
    for region, totals in ranked:
        hours = hour_buckets.get(region) or {}
        cursor = start_hour
        points: list[CostRegionTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostRegionTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostRegionTimeseriesSeries(
                region=region,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/regions/timeseries", response_model=CostRegionTimeseriesResponse)
def get_cost_regions_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    region_filter: Optional[str] = Query(default=None, max_length=128),
    top_regions: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top region/country/geo property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostRegionTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                region_filter=str(region_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(region_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        region = _region_from_properties(properties_json)
        if not region:
            continue
        if filter_text and filter_text not in region.lower():
            continue
        events.append(
            (
                ts,
                region,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_region_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_regions=top_regions,
    )
    return CostRegionTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        region_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_workspace_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_workspaces: int,
) -> list[CostWorkspaceTimeseriesSeries]:
    """Build hour-bucketed spend series for top workspace property values.

    Event tuple: (timestamp, workspace, spend_cents, total_tokens).
    """
    workspace_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, workspace, spend, total_tokens in events:
        bucket = workspace_totals.setdefault(
            workspace,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(workspace, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        workspace_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_workspaces or 1), 20))]

    series: list[CostWorkspaceTimeseriesSeries] = []
    for workspace, totals in ranked:
        hours = hour_buckets.get(workspace) or {}
        cursor = start_hour
        points: list[CostWorkspaceTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostWorkspaceTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostWorkspaceTimeseriesSeries(
                workspace=workspace,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/workspaces/timeseries", response_model=CostWorkspaceTimeseriesResponse)
def get_cost_workspaces_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    workspace_filter: Optional[str] = Query(default=None, max_length=128),
    top_workspaces: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top workspace/org property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostWorkspaceTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                workspace_filter=str(workspace_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(workspace_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        workspace = _workspace_from_properties(properties_json)
        if not workspace:
            continue
        if filter_text and filter_text not in workspace.lower():
            continue
        events.append(
            (
                ts,
                workspace,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_workspace_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_workspaces=top_workspaces,
    )
    return CostWorkspaceTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        workspace_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_product_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_products: int,
) -> list[CostProductTimeseriesSeries]:
    """Build hour-bucketed spend series for top product property values.

    Event tuple: (timestamp, product, spend_cents, total_tokens).
    """
    product_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, product, spend, total_tokens in events:
        bucket = product_totals.setdefault(
            product,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(product, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        product_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_products or 1), 20))]

    series: list[CostProductTimeseriesSeries] = []
    for product, totals in ranked:
        hours = hour_buckets.get(product) or {}
        cursor = start_hour
        points: list[CostProductTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostProductTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostProductTimeseriesSeries(
                product=product,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/products/timeseries", response_model=CostProductTimeseriesResponse)
def get_cost_products_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    product_filter: Optional[str] = Query(default=None, max_length=128),
    top_products: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top product/sku property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostProductTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                product_filter=str(product_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(product_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        product = _product_from_properties(properties_json)
        if not product:
            continue
        if filter_text and filter_text not in product.lower():
            continue
        events.append(
            (
                ts,
                product,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_product_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_products=top_products,
    )
    return CostProductTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        product_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_service_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_services: int,
) -> list[CostServiceTimeseriesSeries]:
    """Build hour-bucketed spend series for top service property values.

    Event tuple: (timestamp, service, spend_cents, total_tokens).
    """
    service_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, service, spend, total_tokens in events:
        bucket = service_totals.setdefault(
            service,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(service, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        service_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_services or 1), 20))]

    series: list[CostServiceTimeseriesSeries] = []
    for service, totals in ranked:
        hours = hour_buckets.get(service) or {}
        cursor = start_hour
        points: list[CostServiceTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostServiceTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostServiceTimeseriesSeries(
                service=service,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/services/timeseries", response_model=CostServiceTimeseriesResponse)
def get_cost_services_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    service_filter: Optional[str] = Query(default=None, max_length=128),
    top_services: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top service/microservice property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostServiceTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                service_filter=str(service_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(service_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        service = _service_from_properties(properties_json)
        if not service:
            continue
        if filter_text and filter_text not in service.lower():
            continue
        events.append(
            (
                ts,
                service,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_service_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_services=top_services,
    )
    return CostServiceTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        service_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_tenant_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_tenants: int,
) -> list[CostTenantTimeseriesSeries]:
    """Build hour-bucketed spend series for top tenant property values.

    Event tuple: (timestamp, tenant, spend_cents, total_tokens).
    """
    tenant_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, tenant, spend, total_tokens in events:
        bucket = tenant_totals.setdefault(
            tenant,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(tenant, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        tenant_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_tenants or 1), 20))]

    series: list[CostTenantTimeseriesSeries] = []
    for tenant, totals in ranked:
        hours = hour_buckets.get(tenant) or {}
        cursor = start_hour
        points: list[CostTenantTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostTenantTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostTenantTimeseriesSeries(
                tenant=tenant,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/tenants/timeseries", response_model=CostTenantTimeseriesResponse)
def get_cost_tenants_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    tenant_filter: Optional[str] = Query(default=None, max_length=128),
    top_tenants: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top tenant/account property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostTenantTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                tenant_filter=str(tenant_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(tenant_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        tenant = _tenant_from_properties(properties_json)
        if not tenant:
            continue
        if filter_text and filter_text not in tenant.lower():
            continue
        events.append(
            (
                ts,
                tenant,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_tenant_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_tenants=top_tenants,
    )
    return CostTenantTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        tenant_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_channel_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_channels: int,
) -> list[CostChannelTimeseriesSeries]:
    """Build hour-bucketed spend series for top channel property values.

    Event tuple: (timestamp, channel, spend_cents, total_tokens).
    """
    channel_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, channel, spend, total_tokens in events:
        bucket = channel_totals.setdefault(
            channel,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(channel, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        channel_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_channels or 1), 20))]

    series: list[CostChannelTimeseriesSeries] = []
    for channel, totals in ranked:
        hours = hour_buckets.get(channel) or {}
        cursor = start_hour
        points: list[CostChannelTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostChannelTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostChannelTimeseriesSeries(
                channel=channel,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/channels/timeseries", response_model=CostChannelTimeseriesResponse)
def get_cost_channels_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    channel_filter: Optional[str] = Query(default=None, max_length=128),
    top_channels: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top channel/source property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostChannelTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                channel_filter=str(channel_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(channel_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        channel = _channel_from_properties(properties_json)
        if not channel:
            continue
        if filter_text and filter_text not in channel.lower():
            continue
        events.append(
            (
                ts,
                channel,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_channel_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_channels=top_channels,
    )
    return CostChannelTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        channel_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_campaign_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_campaigns: int,
) -> list[CostCampaignTimeseriesSeries]:
    """Build hour-bucketed spend series for top campaign property values.

    Event tuple: (timestamp, campaign, spend_cents, total_tokens).
    """
    campaign_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, campaign, spend, total_tokens in events:
        bucket = campaign_totals.setdefault(
            campaign,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(campaign, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        campaign_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_campaigns or 1), 20))]

    series: list[CostCampaignTimeseriesSeries] = []
    for campaign, totals in ranked:
        hours = hour_buckets.get(campaign) or {}
        cursor = start_hour
        points: list[CostCampaignTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostCampaignTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostCampaignTimeseriesSeries(
                campaign=campaign,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/campaigns/timeseries", response_model=CostCampaignTimeseriesResponse)
def get_cost_campaigns_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    campaign_filter: Optional[str] = Query(default=None, max_length=128),
    top_campaigns: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top campaign/utm_campaign property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostCampaignTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                campaign_filter=str(campaign_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(campaign_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        campaign = _campaign_from_properties(properties_json)
        if not campaign:
            continue
        if filter_text and filter_text not in campaign.lower():
            continue
        events.append(
            (
                ts,
                campaign,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_campaign_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_campaigns=top_campaigns,
    )
    return CostCampaignTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        campaign_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_brand_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_brands: int,
) -> list[CostBrandTimeseriesSeries]:
    """Build hour-bucketed spend series for top brand property values.

    Event tuple: (timestamp, brand, spend_cents, total_tokens).
    """
    brand_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, brand, spend, total_tokens in events:
        bucket = brand_totals.setdefault(
            brand,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(brand, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        brand_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_brands or 1), 20))]

    series: list[CostBrandTimeseriesSeries] = []
    for brand, totals in ranked:
        hours = hour_buckets.get(brand) or {}
        cursor = start_hour
        points: list[CostBrandTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostBrandTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostBrandTimeseriesSeries(
                brand=brand,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/brands/timeseries", response_model=CostBrandTimeseriesResponse)
def get_cost_brands_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    brand_filter: Optional[str] = Query(default=None, max_length=128),
    top_brands: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top brand/label property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostBrandTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                brand_filter=str(brand_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(brand_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        brand = _brand_from_properties(properties_json)
        if not brand:
            continue
        if filter_text and filter_text not in brand.lower():
            continue
        events.append(
            (
                ts,
                brand,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_brand_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_brands=top_brands,
    )
    return CostBrandTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        brand_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_market_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_markets: int,
) -> list[CostMarketTimeseriesSeries]:
    """Build hour-bucketed spend series for top market property values.

    Event tuple: (timestamp, market, spend_cents, total_tokens).
    """
    market_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, market, spend, total_tokens in events:
        bucket = market_totals.setdefault(
            market,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(market, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        market_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_markets or 1), 20))]

    series: list[CostMarketTimeseriesSeries] = []
    for market, totals in ranked:
        hours = hour_buckets.get(market) or {}
        cursor = start_hour
        points: list[CostMarketTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostMarketTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostMarketTimeseriesSeries(
                market=market,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/markets/timeseries", response_model=CostMarketTimeseriesResponse)
def get_cost_markets_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    market_filter: Optional[str] = Query(default=None, max_length=128),
    top_markets: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top market property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostMarketTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                market_filter=str(market_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(market_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        market = _market_from_properties(properties_json)
        if not market:
            continue
        if filter_text and filter_text not in market.lower():
            continue
        events.append(
            (
                ts,
                market,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_market_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_markets=top_markets,
    )
    return CostMarketTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        market_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_segment_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_segments: int,
) -> list[CostSegmentTimeseriesSeries]:
    """Build hour-bucketed spend series for top segment property values.

    Event tuple: (timestamp, segment, spend_cents, total_tokens).
    """
    segment_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, segment, spend, total_tokens in events:
        bucket = segment_totals.setdefault(
            segment,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(segment, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        segment_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_segments or 1), 20))]

    series: list[CostSegmentTimeseriesSeries] = []
    for segment, totals in ranked:
        hours = hour_buckets.get(segment) or {}
        cursor = start_hour
        points: list[CostSegmentTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostSegmentTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostSegmentTimeseriesSeries(
                segment=segment,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/segments/timeseries", response_model=CostSegmentTimeseriesResponse)
def get_cost_segments_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    segment_filter: Optional[str] = Query(default=None, max_length=128),
    top_segments: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top segment/audience property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostSegmentTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                segment_filter=str(segment_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(segment_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        segment = _segment_from_properties(properties_json)
        if not segment:
            continue
        if filter_text and filter_text not in segment.lower():
            continue
        events.append(
            (
                ts,
                segment,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_segment_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_segments=top_segments,
    )
    return CostSegmentTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        segment_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_account_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_accounts: int,
) -> list[CostAccountTimeseriesSeries]:
    """Build hour-bucketed spend series for top account property values.

    Event tuple: (timestamp, account, spend_cents, total_tokens).
    """
    account_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, account, spend, total_tokens in events:
        bucket = account_totals.setdefault(
            account,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(account, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        account_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_accounts or 1), 20))]

    series: list[CostAccountTimeseriesSeries] = []
    for account, totals in ranked:
        hours = hour_buckets.get(account) or {}
        cursor = start_hour
        points: list[CostAccountTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostAccountTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostAccountTimeseriesSeries(
                account=account,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/accounts/timeseries", response_model=CostAccountTimeseriesResponse)
def get_cost_accounts_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    account_filter: Optional[str] = Query(default=None, max_length=128),
    top_accounts: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top account property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostAccountTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                account_filter=str(account_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(account_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        account = _account_from_properties(properties_json)
        if not account:
            continue
        if filter_text and filter_text not in account.lower():
            continue
        events.append(
            (
                ts,
                account,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_account_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_accounts=top_accounts,
    )
    return CostAccountTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        account_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_org_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_orgs: int,
) -> list[CostOrgTimeseriesSeries]:
    """Build hour-bucketed spend series for top org property values.

    Event tuple: (timestamp, org, spend_cents, total_tokens).
    """
    org_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, org, spend, total_tokens in events:
        bucket = org_totals.setdefault(
            org,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(org, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        org_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_orgs or 1), 20))]

    series: list[CostOrgTimeseriesSeries] = []
    for org, totals in ranked:
        hours = hour_buckets.get(org) or {}
        cursor = start_hour
        points: list[CostOrgTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostOrgTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostOrgTimeseriesSeries(
                org=org,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/orgs/timeseries", response_model=CostOrgTimeseriesResponse)
def get_cost_orgs_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    org_filter: Optional[str] = Query(default=None, max_length=128),
    top_orgs: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top org/organization property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostOrgTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                org_filter=str(org_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(org_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        org = _org_from_properties(properties_json)
        if not org:
            continue
        if filter_text and filter_text not in org.lower():
            continue
        events.append(
            (
                ts,
                org,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_org_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_orgs=top_orgs,
    )
    return CostOrgTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        org_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_cost_center_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_cost_centers: int,
) -> list[CostCostCenterTimeseriesSeries]:
    """Build hour-bucketed spend series for top cost-center property values.

    Event tuple: (timestamp, cost_center, spend_cents, total_tokens).
    """
    center_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, cost_center, spend, total_tokens in events:
        bucket = center_totals.setdefault(
            cost_center,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(cost_center, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        center_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_cost_centers or 1), 20))]

    series: list[CostCostCenterTimeseriesSeries] = []
    for cost_center, totals in ranked:
        hours = hour_buckets.get(cost_center) or {}
        cursor = start_hour
        points: list[CostCostCenterTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostCostCenterTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostCostCenterTimeseriesSeries(
                cost_center=cost_center,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/cost-centers/timeseries", response_model=CostCostCenterTimeseriesResponse)
def get_cost_cost_centers_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    cost_center_filter: Optional[str] = Query(default=None, max_length=128),
    top_cost_centers: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top cost-center property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostCostCenterTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                cost_center_filter=str(cost_center_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(cost_center_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        cost_center = _cost_center_from_properties(properties_json)
        if not cost_center:
            continue
        if filter_text and filter_text not in cost_center.lower():
            continue
        events.append(
            (
                ts,
                cost_center,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_cost_center_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_cost_centers=top_cost_centers,
    )
    return CostCostCenterTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        cost_center_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_business_unit_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_business_units: int,
) -> list[CostBusinessUnitTimeseriesSeries]:
    """Build hour-bucketed spend series for top business-unit property values.

    Event tuple: (timestamp, business_unit, spend_cents, total_tokens).
    """
    bu_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, business_unit, spend, total_tokens in events:
        bucket = bu_totals.setdefault(
            business_unit,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(business_unit, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        bu_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_business_units or 1), 20))]

    series: list[CostBusinessUnitTimeseriesSeries] = []
    for business_unit, totals in ranked:
        hours = hour_buckets.get(business_unit) or {}
        cursor = start_hour
        points: list[CostBusinessUnitTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostBusinessUnitTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostBusinessUnitTimeseriesSeries(
                business_unit=business_unit,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/business-units/timeseries", response_model=CostBusinessUnitTimeseriesResponse)
def get_cost_business_units_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    business_unit_filter: Optional[str] = Query(default=None, max_length=128),
    top_business_units: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top business-unit property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostBusinessUnitTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                business_unit_filter=str(business_unit_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(business_unit_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        business_unit = _business_unit_from_properties(properties_json)
        if not business_unit:
            continue
        if filter_text and filter_text not in business_unit.lower():
            continue
        events.append(
            (
                ts,
                business_unit,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_business_unit_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_business_units=top_business_units,
    )
    return CostBusinessUnitTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        business_unit_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_site_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_sites: int,
) -> list[CostSiteTimeseriesSeries]:
    """Build hour-bucketed spend series for top site property values.

    Event tuple: (timestamp, site, spend_cents, total_tokens).
    """
    site_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, site, spend, total_tokens in events:
        bucket = site_totals.setdefault(
            site,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(site, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        site_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_sites or 1), 20))]

    series: list[CostSiteTimeseriesSeries] = []
    for site, totals in ranked:
        hours = hour_buckets.get(site) or {}
        cursor = start_hour
        points: list[CostSiteTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostSiteTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostSiteTimeseriesSeries(
                site=site,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/sites/timeseries", response_model=CostSiteTimeseriesResponse)
def get_cost_sites_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    site_filter: Optional[str] = Query(default=None, max_length=128),
    top_sites: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top site/location property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostSiteTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                site_filter=str(site_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(site_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        site = _site_from_properties(properties_json)
        if not site:
            continue
        if filter_text and filter_text not in site.lower():
            continue
        events.append(
            (
                ts,
                site,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_site_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_sites=top_sites,
    )
    return CostSiteTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        site_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_sku_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_skus: int,
) -> list[CostSkuTimeseriesSeries]:
    """Build hour-bucketed spend series for top SKU property values.

    Event tuple: (timestamp, sku, spend_cents, total_tokens).
    """
    sku_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, sku, spend, total_tokens in events:
        bucket = sku_totals.setdefault(
            sku,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(sku, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        sku_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_skus or 1), 20))]

    series: list[CostSkuTimeseriesSeries] = []
    for sku, totals in ranked:
        hours = hour_buckets.get(sku) or {}
        cursor = start_hour
        points: list[CostSkuTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostSkuTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostSkuTimeseriesSeries(
                sku=sku,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/skus/timeseries", response_model=CostSkuTimeseriesResponse)
def get_cost_skus_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    sku_filter: Optional[str] = Query(default=None, max_length=128),
    top_skus: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top SKU property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostSkuTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                sku_filter=str(sku_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(sku_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        sku = _sku_from_properties(properties_json)
        if not sku:
            continue
        if filter_text and filter_text not in sku.lower():
            continue
        events.append(
            (
                ts,
                sku,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_sku_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_skus=top_skus,
    )
    return CostSkuTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        sku_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_line_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_lines: int,
) -> list[CostLineTimeseriesSeries]:
    """Build hour-bucketed spend series for top line-of-business property values.

    Event tuple: (timestamp, line, spend_cents, total_tokens).
    """
    line_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, line, spend, total_tokens in events:
        bucket = line_totals.setdefault(
            line,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(line, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        line_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_lines or 1), 20))]

    series: list[CostLineTimeseriesSeries] = []
    for line, totals in ranked:
        hours = hour_buckets.get(line) or {}
        cursor = start_hour
        points: list[CostLineTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostLineTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostLineTimeseriesSeries(
                line=line,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/lines/timeseries", response_model=CostLineTimeseriesResponse)
def get_cost_lines_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    line_filter: Optional[str] = Query(default=None, max_length=128),
    top_lines: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top line-of-business property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostLineTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                line_filter=str(line_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(line_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        line = _line_from_properties(properties_json)
        if not line:
            continue
        if filter_text and filter_text not in line.lower():
            continue
        events.append(
            (
                ts,
                line,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_line_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_lines=top_lines,
    )
    return CostLineTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        line_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_tier_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_tiers: int,
) -> list[CostTierTimeseriesSeries]:
    """Build hour-bucketed spend series for top tier/plan property values.

    Event tuple: (timestamp, tier, spend_cents, total_tokens).
    """
    tier_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, tier, spend, total_tokens in events:
        bucket = tier_totals.setdefault(
            tier,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(tier, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        tier_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_tiers or 1), 20))]

    series: list[CostTierTimeseriesSeries] = []
    for tier, totals in ranked:
        hours = hour_buckets.get(tier) or {}
        cursor = start_hour
        points: list[CostTierTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostTierTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostTierTimeseriesSeries(
                tier=tier,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/tiers/timeseries", response_model=CostTierTimeseriesResponse)
def get_cost_tiers_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    tier_filter: Optional[str] = Query(default=None, max_length=128),
    top_tiers: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top tier/plan property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostTierTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                tier_filter=str(tier_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(tier_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        tier = _tier_from_properties(properties_json)
        if not tier:
            continue
        if filter_text and filter_text not in tier.lower():
            continue
        events.append(
            (
                ts,
                tier,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_tier_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_tiers=top_tiers,
    )
    return CostTierTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        tier_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_stage_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_stages: int,
) -> list[CostStageTimeseriesSeries]:
    """Build hour-bucketed spend series for top stage property values.

    Event tuple: (timestamp, stage, spend_cents, total_tokens).
    """
    stage_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, stage, spend, total_tokens in events:
        bucket = stage_totals.setdefault(
            stage,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(stage, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        stage_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_stages or 1), 20))]

    series: list[CostStageTimeseriesSeries] = []
    for stage, totals in ranked:
        hours = hour_buckets.get(stage) or {}
        cursor = start_hour
        points: list[CostStageTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostStageTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostStageTimeseriesSeries(
                stage=stage,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/stages/timeseries", response_model=CostStageTimeseriesResponse)
def get_cost_stages_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    stage_filter: Optional[str] = Query(default=None, max_length=128),
    top_stages: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top pipeline/lifecycle stage property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostStageTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                stage_filter=str(stage_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(stage_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        stage = _stage_from_properties(properties_json)
        if not stage:
            continue
        if filter_text and filter_text not in stage.lower():
            continue
        events.append(
            (
                ts,
                stage,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_stage_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_stages=top_stages,
    )
    return CostStageTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        stage_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_platform_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_platforms: int,
) -> list[CostPlatformTimeseriesSeries]:
    """Build hour-bucketed spend series for top platform property values.

    Event tuple: (timestamp, platform, spend_cents, total_tokens).
    """
    platform_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, platform, spend, total_tokens in events:
        bucket = platform_totals.setdefault(
            platform,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(platform, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        platform_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_platforms or 1), 20))]

    series: list[CostPlatformTimeseriesSeries] = []
    for platform, totals in ranked:
        hours = hour_buckets.get(platform) or {}
        cursor = start_hour
        points: list[CostPlatformTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostPlatformTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostPlatformTimeseriesSeries(
                platform=platform,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/platforms/timeseries", response_model=CostPlatformTimeseriesResponse)
def get_cost_platforms_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    platform_filter: Optional[str] = Query(default=None, max_length=128),
    top_platforms: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top platform property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostPlatformTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                platform_filter=str(platform_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(platform_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        platform = _platform_from_properties(properties_json)
        if not platform:
            continue
        if filter_text and filter_text not in platform.lower():
            continue
        events.append(
            (
                ts,
                platform,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_platform_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_platforms=top_platforms,
    )
    return CostPlatformTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        platform_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_device_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_devices: int,
) -> list[CostDeviceTimeseriesSeries]:
    """Build hour-bucketed spend series for top device property values.

    Event tuple: (timestamp, device, spend_cents, total_tokens).
    """
    device_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, device, spend, total_tokens in events:
        bucket = device_totals.setdefault(
            device,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(device, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        device_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_devices or 1), 20))]

    series: list[CostDeviceTimeseriesSeries] = []
    for device, totals in ranked:
        hours = hour_buckets.get(device) or {}
        cursor = start_hour
        points: list[CostDeviceTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostDeviceTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostDeviceTimeseriesSeries(
                device=device,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/devices/timeseries", response_model=CostDeviceTimeseriesResponse)
def get_cost_devices_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    device_filter: Optional[str] = Query(default=None, max_length=128),
    top_devices: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top device property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostDeviceTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                device_filter=str(device_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(device_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        device = _device_from_properties(properties_json)
        if not device:
            continue
        if filter_text and filter_text not in device.lower():
            continue
        events.append(
            (
                ts,
                device,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_device_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_devices=top_devices,
    )
    return CostDeviceTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        device_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_client_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_clients: int,
) -> list[CostClientTimeseriesSeries]:
    """Build hour-bucketed spend series for top client property values.

    Event tuple: (timestamp, client, spend_cents, total_tokens).
    """
    client_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, client, spend, total_tokens in events:
        bucket = client_totals.setdefault(
            client,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(client, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        client_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_clients or 1), 20))]

    series: list[CostClientTimeseriesSeries] = []
    for client, totals in ranked:
        hours = hour_buckets.get(client) or {}
        cursor = start_hour
        points: list[CostClientTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostClientTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostClientTimeseriesSeries(
                client=client,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/clients/timeseries", response_model=CostClientTimeseriesResponse)
def get_cost_clients_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    client_filter: Optional[str] = Query(default=None, max_length=128),
    top_clients: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top client property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostClientTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                client_filter=str(client_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(client_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        client = _client_from_properties(properties_json)
        if not client:
            continue
        if filter_text and filter_text not in client.lower():
            continue
        events.append(
            (
                ts,
                client,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_client_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_clients=top_clients,
    )
    return CostClientTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        client_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_browser_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_browsers: int,
) -> list[CostBrowserTimeseriesSeries]:
    """Build hour-bucketed spend series for top browser property values.

    Event tuple: (timestamp, browser, spend_cents, total_tokens).
    """
    browser_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, browser, spend, total_tokens in events:
        bucket = browser_totals.setdefault(
            browser,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(browser, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        browser_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_browsers or 1), 20))]

    series: list[CostBrowserTimeseriesSeries] = []
    for browser, totals in ranked:
        hours = hour_buckets.get(browser) or {}
        cursor = start_hour
        points: list[CostBrowserTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostBrowserTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostBrowserTimeseriesSeries(
                browser=browser,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/browsers/timeseries", response_model=CostBrowserTimeseriesResponse)
def get_cost_browsers_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    browser_filter: Optional[str] = Query(default=None, max_length=128),
    top_browsers: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top browser property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostBrowserTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                browser_filter=str(browser_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(browser_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        browser = _browser_from_properties(properties_json)
        if not browser:
            continue
        if filter_text and filter_text not in browser.lower():
            continue
        events.append(
            (
                ts,
                browser,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_browser_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_browsers=top_browsers,
    )
    return CostBrowserTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        browser_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_release_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_releases: int,
) -> list[CostReleaseTimeseriesSeries]:
    """Build hour-bucketed spend series for top release property values.

    Event tuple: (timestamp, release, spend_cents, total_tokens).
    """
    release_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, release, spend, total_tokens in events:
        bucket = release_totals.setdefault(
            release,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(release, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        release_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_releases or 1), 20))]

    series: list[CostReleaseTimeseriesSeries] = []
    for release, totals in ranked:
        hours = hour_buckets.get(release) or {}
        cursor = start_hour
        points: list[CostReleaseTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostReleaseTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostReleaseTimeseriesSeries(
                release=release,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/releases/timeseries", response_model=CostReleaseTimeseriesResponse)
def get_cost_releases_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    release_filter: Optional[str] = Query(default=None, max_length=128),
    top_releases: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top release property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostReleaseTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                release_filter=str(release_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(release_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        release = _release_from_properties(properties_json)
        if not release:
            continue
        if filter_text and filter_text not in release.lower():
            continue
        events.append(
            (
                ts,
                release,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_release_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_releases=top_releases,
    )
    return CostReleaseTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        release_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_locale_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_locales: int,
) -> list[CostLocaleTimeseriesSeries]:
    """Build hour-bucketed spend series for top locale property values.

    Event tuple: (timestamp, locale, spend_cents, total_tokens).
    """
    locale_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, locale, spend, total_tokens in events:
        bucket = locale_totals.setdefault(
            locale,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(locale, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        locale_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_locales or 1), 20))]

    series: list[CostLocaleTimeseriesSeries] = []
    for locale, totals in ranked:
        hours = hour_buckets.get(locale) or {}
        cursor = start_hour
        points: list[CostLocaleTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostLocaleTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostLocaleTimeseriesSeries(
                locale=locale,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/locales/timeseries", response_model=CostLocaleTimeseriesResponse)
def get_cost_locales_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    locale_filter: Optional[str] = Query(default=None, max_length=128),
    top_locales: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top locale property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostLocaleTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                locale_filter=str(locale_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(locale_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        locale = _locale_from_properties(properties_json)
        if not locale:
            continue
        if filter_text and filter_text not in locale.lower():
            continue
        events.append(
            (
                ts,
                locale,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_locale_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_locales=top_locales,
    )
    return CostLocaleTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        locale_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_country_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_countries: int,
) -> list[CostCountryTimeseriesSeries]:
    """Build hour-bucketed spend series for top country property values.

    Event tuple: (timestamp, country, spend_cents, total_tokens).
    """
    country_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, country, spend, total_tokens in events:
        bucket = country_totals.setdefault(
            country,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(country, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        country_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_countries or 1), 20))]

    series: list[CostCountryTimeseriesSeries] = []
    for country, totals in ranked:
        hours = hour_buckets.get(country) or {}
        cursor = start_hour
        points: list[CostCountryTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostCountryTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostCountryTimeseriesSeries(
                country=country,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/countries/timeseries", response_model=CostCountryTimeseriesResponse)
def get_cost_countries_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    country_filter: Optional[str] = Query(default=None, max_length=128),
    top_countries: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top country property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostCountryTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                country_filter=str(country_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(country_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        country = _country_from_properties(properties_json)
        if not country:
            continue
        if filter_text and filter_text not in country.lower():
            continue
        events.append(
            (
                ts,
                country,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_country_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_countries=top_countries,
    )
    return CostCountryTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        country_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_os_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_os: int,
) -> list[CostOsTimeseriesSeries]:
    """Build hour-bucketed spend series for top os property values.

    Event tuple: (timestamp, os, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(
            value,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_os or 1), 20))]

    series: list[CostOsTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostOsTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostOsTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostOsTimeseriesSeries(
                os=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/os/timeseries", response_model=CostOsTimeseriesResponse)
def get_cost_os_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    os_filter: Optional[str] = Query(default=None, max_length=128),
    top_os: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top os property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostOsTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                os_filter=str(os_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(os_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _os_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append(
            (
                ts,
                value,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_os_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_os=top_os,
    )
    return CostOsTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        os_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_timezone_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_timezones: int,
) -> list[CostTimezoneTimeseriesSeries]:
    """Build hour-bucketed spend series for top timezone property values.

    Event tuple: (timestamp, timezone, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(
            value,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_timezones or 1), 20))]

    series: list[CostTimezoneTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostTimezoneTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostTimezoneTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostTimezoneTimeseriesSeries(
                timezone=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/timezones/timeseries", response_model=CostTimezoneTimeseriesResponse)
def get_cost_timezones_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    timezone_filter: Optional[str] = Query(default=None, max_length=128),
    top_timezones: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top timezone property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostTimezoneTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                timezone_filter=str(timezone_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(timezone_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _timezone_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append(
            (
                ts,
                value,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_timezone_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_timezones=top_timezones,
    )
    return CostTimezoneTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        timezone_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_language_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_languages: int,
) -> list[CostLanguageTimeseriesSeries]:
    """Build hour-bucketed spend series for top language property values.

    Event tuple: (timestamp, language, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(
            value,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_languages or 1), 20))]

    series: list[CostLanguageTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostLanguageTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostLanguageTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostLanguageTimeseriesSeries(
                language=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/languages/timeseries", response_model=CostLanguageTimeseriesResponse)
def get_cost_languages_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    language_filter: Optional[str] = Query(default=None, max_length=128),
    top_languages: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top language property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostLanguageTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                language_filter=str(language_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(language_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _language_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append(
            (
                ts,
                value,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_language_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_languages=top_languages,
    )
    return CostLanguageTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        language_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_city_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_cities: int,
) -> list[CostCityTimeseriesSeries]:
    """Build hour-bucketed spend series for top city property values.

    Event tuple: (timestamp, city, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(
            value,
            {"spend_cents": 0, "event_count": 0, "total_tokens": 0},
        )
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_cities or 1), 20))]

    series: list[CostCityTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostCityTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostCityTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostCityTimeseriesSeries(
                city=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/cities/timeseries", response_model=CostCityTimeseriesResponse)
def get_cost_cities_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    city_filter: Optional[str] = Query(default=None, max_length=128),
    top_cities: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top city property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostCityTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                city_filter=str(city_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(city_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _city_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append(
            (
                ts,
                value,
                int(estimated_cost_cents or 0),
                int(input_tokens or 0) + int(output_tokens or 0),
            )
        )

    series = _build_city_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_cities=top_cities,
    )
    return CostCityTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        city_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_continent_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_continents: int,
) -> list[CostContinentTimeseriesSeries]:
    """Build hour-bucketed spend series for top continent property values.

    Event tuple: (timestamp, continent, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_continents or 1), 20))]

    series: list[CostContinentTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostContinentTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostContinentTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostContinentTimeseriesSeries(
                continent=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/continents/timeseries", response_model=CostContinentTimeseriesResponse)
def get_cost_continents_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    continent_filter: Optional[str] = Query(default=None, max_length=128),
    top_continents: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top continent property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostContinentTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                continent_filter=str(continent_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(continent_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _continent_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_continent_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_continents=top_continents,
    )
    return CostContinentTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        continent_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_isp_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_isps: int,
) -> list[CostIspTimeseriesSeries]:
    """Build hour-bucketed spend series for top isp property values.

    Event tuple: (timestamp, isp, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_isps or 1), 20))]

    series: list[CostIspTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostIspTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostIspTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostIspTimeseriesSeries(
                isp=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/isps/timeseries", response_model=CostIspTimeseriesResponse)
def get_cost_isps_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    isp_filter: Optional[str] = Query(default=None, max_length=128),
    top_isps: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top isp property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostIspTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                isp_filter=str(isp_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(isp_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _isp_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_isp_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_isps=top_isps,
    )
    return CostIspTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        isp_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_asn_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_asns: int,
) -> list[CostAsnTimeseriesSeries]:
    """Build hour-bucketed spend series for top asn property values.

    Event tuple: (timestamp, asn, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_asns or 1), 20))]

    series: list[CostAsnTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostAsnTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostAsnTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostAsnTimeseriesSeries(
                asn=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/asns/timeseries", response_model=CostAsnTimeseriesResponse)
def get_cost_asns_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    asn_filter: Optional[str] = Query(default=None, max_length=128),
    top_asns: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top asn property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostAsnTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                asn_filter=str(asn_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(asn_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _asn_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_asn_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_asns=top_asns,
    )
    return CostAsnTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        asn_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_sdk_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_sdks: int,
) -> list[CostSdkTimeseriesSeries]:
    """Build hour-bucketed spend series for top sdk property values.

    Event tuple: (timestamp, sdk, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_sdks or 1), 20))]

    series: list[CostSdkTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostSdkTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostSdkTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostSdkTimeseriesSeries(
                sdk=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/sdks/timeseries", response_model=CostSdkTimeseriesResponse)
def get_cost_sdks_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    sdk_filter: Optional[str] = Query(default=None, max_length=128),
    top_sdks: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top sdk property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostSdkTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                sdk_filter=str(sdk_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(sdk_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _sdk_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_sdk_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_sdks=top_sdks,
    )
    return CostSdkTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        sdk_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_framework_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_frameworks: int,
) -> list[CostFrameworkTimeseriesSeries]:
    """Build hour-bucketed spend series for top framework property values.

    Event tuple: (timestamp, framework, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_frameworks or 1), 20))]

    series: list[CostFrameworkTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostFrameworkTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostFrameworkTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostFrameworkTimeseriesSeries(
                framework=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/frameworks/timeseries", response_model=CostFrameworkTimeseriesResponse)
def get_cost_frameworks_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    framework_filter: Optional[str] = Query(default=None, max_length=128),
    top_frameworks: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top framework property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostFrameworkTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                framework_filter=str(framework_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(framework_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _framework_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_framework_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_frameworks=top_frameworks,
    )
    return CostFrameworkTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        framework_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_runtime_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_runtimes: int,
) -> list[CostRuntimeTimeseriesSeries]:
    """Build hour-bucketed spend series for top runtime property values.

    Event tuple: (timestamp, runtime, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_runtimes or 1), 20))]

    series: list[CostRuntimeTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostRuntimeTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostRuntimeTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostRuntimeTimeseriesSeries(
                runtime=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/runtimes/timeseries", response_model=CostRuntimeTimeseriesResponse)
def get_cost_runtimes_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    runtime_filter: Optional[str] = Query(default=None, max_length=128),
    top_runtimes: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top runtime property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostRuntimeTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                runtime_filter=str(runtime_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(runtime_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _runtime_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_runtime_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_runtimes=top_runtimes,
    )
    return CostRuntimeTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        runtime_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_library_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_libraries: int,
) -> list[CostLibraryTimeseriesSeries]:
    """Build hour-bucketed spend series for top library property values.

    Event tuple: (timestamp, library, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_libraries or 1), 20))]

    series: list[CostLibraryTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostLibraryTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostLibraryTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostLibraryTimeseriesSeries(
                library=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/libraries/timeseries", response_model=CostLibraryTimeseriesResponse)
def get_cost_libraries_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    library_filter: Optional[str] = Query(default=None, max_length=128),
    top_libraries: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top library property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostLibraryTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                library_filter=str(library_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(library_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _library_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_library_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_libraries=top_libraries,
    )
    return CostLibraryTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        library_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_host_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_hosts: int,
) -> list[CostHostTimeseriesSeries]:
    """Build hour-bucketed spend series for top host property values.

    Event tuple: (timestamp, host, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_hosts or 1), 20))]

    series: list[CostHostTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostHostTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostHostTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostHostTimeseriesSeries(
                host=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/hosts/timeseries", response_model=CostHostTimeseriesResponse)
def get_cost_hosts_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    host_filter: Optional[str] = Query(default=None, max_length=128),
    top_hosts: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top host property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostHostTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                host_filter=str(host_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(host_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _host_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_host_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_hosts=top_hosts,
    )
    return CostHostTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        host_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_datacenter_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_datacenters: int,
) -> list[CostDatacenterTimeseriesSeries]:
    """Build hour-bucketed spend series for top datacenter property values.

    Event tuple: (timestamp, datacenter, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_datacenters or 1), 20))]

    series: list[CostDatacenterTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostDatacenterTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostDatacenterTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostDatacenterTimeseriesSeries(
                datacenter=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/datacenters/timeseries", response_model=CostDatacenterTimeseriesResponse)
def get_cost_datacenters_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    datacenter_filter: Optional[str] = Query(default=None, max_length=128),
    top_datacenters: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top datacenter property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostDatacenterTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                datacenter_filter=str(datacenter_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(datacenter_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _datacenter_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_datacenter_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_datacenters=top_datacenters,
    )
    return CostDatacenterTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        datacenter_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_az_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_azs: int,
) -> list[CostAzTimeseriesSeries]:
    """Build hour-bucketed spend series for top az property values.

    Event tuple: (timestamp, az, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_azs or 1), 20))]

    series: list[CostAzTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostAzTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostAzTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostAzTimeseriesSeries(
                az=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/azs/timeseries", response_model=CostAzTimeseriesResponse)
def get_cost_azs_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    az_filter: Optional[str] = Query(default=None, max_length=128),
    top_azs: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top az property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostAzTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                az_filter=str(az_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(az_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _az_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_az_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_azs=top_azs,
    )
    return CostAzTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        az_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_edge_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_edges: int,
) -> list[CostEdgeTimeseriesSeries]:
    """Build hour-bucketed spend series for top edge property values.

    Event tuple: (timestamp, edge, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_edges or 1), 20))]

    series: list[CostEdgeTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostEdgeTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostEdgeTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostEdgeTimeseriesSeries(
                edge=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/edges/timeseries", response_model=CostEdgeTimeseriesResponse)
def get_cost_edges_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    edge_filter: Optional[str] = Query(default=None, max_length=128),
    top_edges: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top edge property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostEdgeTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                edge_filter=str(edge_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(edge_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _edge_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_edge_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_edges=top_edges,
    )
    return CostEdgeTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        edge_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_colo_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_colos: int,
) -> list[CostColoTimeseriesSeries]:
    """Build hour-bucketed spend series for top colo property values.

    Event tuple: (timestamp, colo, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_colos or 1), 20))]

    series: list[CostColoTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostColoTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostColoTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostColoTimeseriesSeries(
                colo=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/colos/timeseries", response_model=CostColoTimeseriesResponse)
def get_cost_colos_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    colo_filter: Optional[str] = Query(default=None, max_length=128),
    top_colos: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top colo property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostColoTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                colo_filter=str(colo_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(colo_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _colo_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_colo_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_colos=top_colos,
    )
    return CostColoTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        colo_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_cluster_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_clusters: int,
) -> list[CostClusterTimeseriesSeries]:
    """Build hour-bucketed spend series for top cluster property values.

    Event tuple: (timestamp, cluster, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_clusters or 1), 20))]

    series: list[CostClusterTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostClusterTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostClusterTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostClusterTimeseriesSeries(
                cluster=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/clusters/timeseries", response_model=CostClusterTimeseriesResponse)
def get_cost_clusters_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    cluster_filter: Optional[str] = Query(default=None, max_length=128),
    top_clusters: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top cluster property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostClusterTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                cluster_filter=str(cluster_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(cluster_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _cluster_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_cluster_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_clusters=top_clusters,
    )
    return CostClusterTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        cluster_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_pod_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_pods: int,
) -> list[CostPodTimeseriesSeries]:
    """Build hour-bucketed spend series for top pod property values.

    Event tuple: (timestamp, pod, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_pods or 1), 20))]

    series: list[CostPodTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostPodTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostPodTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostPodTimeseriesSeries(
                pod=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/pods/timeseries", response_model=CostPodTimeseriesResponse)
def get_cost_pods_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    pod_filter: Optional[str] = Query(default=None, max_length=128),
    top_pods: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top pod property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostPodTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                pod_filter=str(pod_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(pod_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _pod_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_pod_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_pods=top_pods,
    )
    return CostPodTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        pod_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_namespace_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_namespaces: int,
) -> list[CostNamespaceTimeseriesSeries]:
    """Build hour-bucketed spend series for top namespace property values.

    Event tuple: (timestamp, namespace, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_namespaces or 1), 20))]

    series: list[CostNamespaceTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostNamespaceTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostNamespaceTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostNamespaceTimeseriesSeries(
                namespace=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/namespaces/timeseries", response_model=CostNamespaceTimeseriesResponse)
def get_cost_namespaces_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    namespace_filter: Optional[str] = Query(default=None, max_length=128),
    top_namespaces: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top namespace property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostNamespaceTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                namespace_filter=str(namespace_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(namespace_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _namespace_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_namespace_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_namespaces=top_namespaces,
    )
    return CostNamespaceTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        namespace_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_node_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_nodes: int,
) -> list[CostNodeTimeseriesSeries]:
    """Build hour-bucketed spend series for top node property values.

    Event tuple: (timestamp, node, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_nodes or 1), 20))]

    series: list[CostNodeTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostNodeTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostNodeTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostNodeTimeseriesSeries(
                node=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/nodes/timeseries", response_model=CostNodeTimeseriesResponse)
def get_cost_nodes_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    node_filter: Optional[str] = Query(default=None, max_length=128),
    top_nodes: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top node property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostNodeTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                node_filter=str(node_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(node_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _node_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_node_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_nodes=top_nodes,
    )
    return CostNodeTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        node_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_tool_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_tools: int,
) -> list[CostToolTimeseriesSeries]:
    """Build hour-bucketed spend series for top tool property values.

    Event tuple: (timestamp, tool, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_tools or 1), 20))]

    series: list[CostToolTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostToolTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostToolTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostToolTimeseriesSeries(
                tool=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/tools/timeseries", response_model=CostToolTimeseriesResponse)
def get_cost_tools_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    tool_filter: Optional[str] = Query(default=None, max_length=128),
    top_tools: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top tool property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostToolTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                tool_filter=str(tool_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(tool_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _tool_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_tool_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_tools=top_tools,
    )
    return CostToolTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        tool_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_workflow_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_workflows: int,
) -> list[CostWorkflowTimeseriesSeries]:
    """Build hour-bucketed spend series for top workflow property values.

    Event tuple: (timestamp, workflow, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_workflows or 1), 20))]

    series: list[CostWorkflowTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostWorkflowTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostWorkflowTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostWorkflowTimeseriesSeries(
                workflow=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/workflows/timeseries", response_model=CostWorkflowTimeseriesResponse)
def get_cost_workflows_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    workflow_filter: Optional[str] = Query(default=None, max_length=128),
    top_workflows: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top workflow property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostWorkflowTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                workflow_filter=str(workflow_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(workflow_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _workflow_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_workflow_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_workflows=top_workflows,
    )
    return CostWorkflowTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        workflow_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_experiment_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_experiments: int,
) -> list[CostExperimentTimeseriesSeries]:
    """Build hour-bucketed spend series for top experiment property values.

    Event tuple: (timestamp, experiment, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_experiments or 1), 20))]

    series: list[CostExperimentTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostExperimentTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostExperimentTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostExperimentTimeseriesSeries(
                experiment=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/experiments/timeseries", response_model=CostExperimentTimeseriesResponse)
def get_cost_experiments_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    experiment_filter: Optional[str] = Query(default=None, max_length=128),
    top_experiments: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top experiment property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostExperimentTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                experiment_filter=str(experiment_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(experiment_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _experiment_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_experiment_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_experiments=top_experiments,
    )
    return CostExperimentTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        experiment_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_variant_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_variants: int,
) -> list[CostVariantTimeseriesSeries]:
    """Build hour-bucketed spend series for top variant property values.

    Event tuple: (timestamp, variant, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_variants or 1), 20))]

    series: list[CostVariantTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostVariantTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostVariantTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostVariantTimeseriesSeries(
                variant=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/variants/timeseries", response_model=CostVariantTimeseriesResponse)
def get_cost_variants_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    variant_filter: Optional[str] = Query(default=None, max_length=128),
    top_variants: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top variant property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostVariantTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                variant_filter=str(variant_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(variant_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _variant_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_variant_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_variants=top_variants,
    )
    return CostVariantTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        variant_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_deployment_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_deployments: int,
) -> list[CostDeploymentTimeseriesSeries]:
    """Build hour-bucketed spend series for top deployment property values.

    Event tuple: (timestamp, deployment, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_deployments or 1), 20))]

    series: list[CostDeploymentTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostDeploymentTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostDeploymentTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostDeploymentTimeseriesSeries(
                deployment=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/deployments/timeseries", response_model=CostDeploymentTimeseriesResponse)
def get_cost_deployments_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    deployment_filter: Optional[str] = Query(default=None, max_length=128),
    top_deployments: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top deployment property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostDeploymentTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                deployment_filter=str(deployment_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(deployment_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _deployment_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_deployment_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_deployments=top_deployments,
    )
    return CostDeploymentTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        deployment_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_version_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_versions: int,
) -> list[CostVersionTimeseriesSeries]:
    """Build hour-bucketed spend series for top version property values.

    Event tuple: (timestamp, version, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_versions or 1), 20))]

    series: list[CostVersionTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostVersionTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostVersionTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostVersionTimeseriesSeries(
                version=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/versions/timeseries", response_model=CostVersionTimeseriesResponse)
def get_cost_versions_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    version_filter: Optional[str] = Query(default=None, max_length=128),
    top_versions: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top version property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostVersionTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                version_filter=str(version_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(version_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _version_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_version_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_versions=top_versions,
    )
    return CostVersionTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        version_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_canary_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_canaries: int,
) -> list[CostCanaryTimeseriesSeries]:
    """Build hour-bucketed spend series for top canary property values.

    Event tuple: (timestamp, canary, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_canaries or 1), 20))]

    series: list[CostCanaryTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostCanaryTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostCanaryTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostCanaryTimeseriesSeries(
                canary=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/canaries/timeseries", response_model=CostCanaryTimeseriesResponse)
def get_cost_canaries_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    canary_filter: Optional[str] = Query(default=None, max_length=128),
    top_canaries: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top canary property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostCanaryTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                canary_filter=str(canary_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(canary_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _canary_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_canary_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_canaries=top_canaries,
    )
    return CostCanaryTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        canary_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_shadow_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_shadows: int,
) -> list[CostShadowTimeseriesSeries]:
    """Build hour-bucketed spend series for top shadow property values.

    Event tuple: (timestamp, shadow, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_shadows or 1), 20))]

    series: list[CostShadowTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostShadowTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostShadowTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostShadowTimeseriesSeries(
                shadow=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/shadows/timeseries", response_model=CostShadowTimeseriesResponse)
def get_cost_shadows_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    shadow_filter: Optional[str] = Query(default=None, max_length=128),
    top_shadows: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top shadow property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostShadowTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                shadow_filter=str(shadow_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(shadow_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _shadow_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_shadow_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_shadows=top_shadows,
    )
    return CostShadowTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        shadow_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_rollout_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_rollouts: int,
) -> list[CostRolloutTimeseriesSeries]:
    """Build hour-bucketed spend series for top rollout property values.

    Event tuple: (timestamp, rollout, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_rollouts or 1), 20))]

    series: list[CostRolloutTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostRolloutTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostRolloutTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostRolloutTimeseriesSeries(
                rollout=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/rollouts/timeseries", response_model=CostRolloutTimeseriesResponse)
def get_cost_rollouts_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    rollout_filter: Optional[str] = Query(default=None, max_length=128),
    top_rollouts: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top rollout property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostRolloutTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                rollout_filter=str(rollout_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(rollout_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _rollout_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_rollout_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_rollouts=top_rollouts,
    )
    return CostRolloutTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        rollout_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_route_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_routes: int,
) -> list[CostRouteTimeseriesSeries]:
    """Build hour-bucketed spend series for top route property values.

    Event tuple: (timestamp, route, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_routes or 1), 20))]

    series: list[CostRouteTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostRouteTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostRouteTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostRouteTimeseriesSeries(
                route=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/routes/timeseries", response_model=CostRouteTimeseriesResponse)
def get_cost_routes_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    route_filter: Optional[str] = Query(default=None, max_length=128),
    top_routes: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top route property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostRouteTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                route_filter=str(route_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(route_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _route_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_route_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_routes=top_routes,
    )
    return CostRouteTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        route_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )




def _build_batch_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_batches: int,
) -> list[CostBatchTimeseriesSeries]:
    """Build hour-bucketed spend series for top batch property values.

    Event tuple: (timestamp, batch, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_batches or 1), 20))]

    series: list[CostBatchTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostBatchTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostBatchTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostBatchTimeseriesSeries(
                batch=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/batches/timeseries", response_model=CostBatchTimeseriesResponse)
def get_cost_batches_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    batch_filter: Optional[str] = Query(default=None, max_length=128),
    top_batches: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top batch property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostBatchTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                batch_filter=str(batch_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(batch_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _batch_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_batch_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_batches=top_batches,
    )
    return CostBatchTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        batch_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _build_job_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_jobs: int,
) -> list[CostJobTimeseriesSeries]:
    """Build hour-bucketed spend series for top job property values.

    Event tuple: (timestamp, job, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_jobs or 1), 20))]

    series: list[CostJobTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostJobTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostJobTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostJobTimeseriesSeries(
                job=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/jobs/timeseries", response_model=CostJobTimeseriesResponse)
def get_cost_jobs_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    job_filter: Optional[str] = Query(default=None, max_length=128),
    top_jobs: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top job property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostJobTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                job_filter=str(job_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(job_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _job_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_job_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_jobs=top_jobs,
    )
    return CostJobTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        job_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_queue_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_queues: int,
) -> list[CostQueueTimeseriesSeries]:
    """Build hour-bucketed spend series for top queue property values.

    Event tuple: (timestamp, queue, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_queues or 1), 20))]

    series: list[CostQueueTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostQueueTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostQueueTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostQueueTimeseriesSeries(
                queue=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/queues/timeseries", response_model=CostQueueTimeseriesResponse)
def get_cost_queues_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    queue_filter: Optional[str] = Query(default=None, max_length=128),
    top_queues: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top queue property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostQueueTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                queue_filter=str(queue_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(queue_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _queue_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_queue_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_queues=top_queues,
    )
    return CostQueueTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        queue_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_topic_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_topics: int,
) -> list[CostTopicTimeseriesSeries]:
    """Build hour-bucketed spend series for top topic property values.

    Event tuple: (timestamp, topic, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_topics or 1), 20))]

    series: list[CostTopicTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostTopicTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostTopicTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostTopicTimeseriesSeries(
                topic=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/topics/timeseries", response_model=CostTopicTimeseriesResponse)
def get_cost_topics_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    topic_filter: Optional[str] = Query(default=None, max_length=128),
    top_topics: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top topic property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostTopicTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                topic_filter=str(topic_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(topic_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _topic_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_topic_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_topics=top_topics,
    )
    return CostTopicTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        topic_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_pipeline_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_pipelines: int,
) -> list[CostPipelineTimeseriesSeries]:
    """Build hour-bucketed spend series for top pipeline property values.

    Event tuple: (timestamp, pipeline, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_pipelines or 1), 20))]

    series: list[CostPipelineTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostPipelineTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostPipelineTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostPipelineTimeseriesSeries(
                pipeline=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/pipelines/timeseries", response_model=CostPipelineTimeseriesResponse)
def get_cost_pipelines_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    pipeline_filter: Optional[str] = Query(default=None, max_length=128),
    top_pipelines: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top pipeline property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostPipelineTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                pipeline_filter=str(pipeline_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(pipeline_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _pipeline_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_pipeline_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_pipelines=top_pipelines,
    )
    return CostPipelineTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        pipeline_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_run_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_runs: int,
) -> list[CostRunTimeseriesSeries]:
    """Build hour-bucketed spend series for top run property values.

    Event tuple: (timestamp, run, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_runs or 1), 20))]

    series: list[CostRunTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostRunTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostRunTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostRunTimeseriesSeries(
                run=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/runs/timeseries", response_model=CostRunTimeseriesResponse)
def get_cost_runs_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    run_filter: Optional[str] = Query(default=None, max_length=128),
    top_runs: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top run property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostRunTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                run_filter=str(run_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(run_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _run_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_run_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_runs=top_runs,
    )
    return CostRunTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        run_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_worker_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_workers: int,
) -> list[CostWorkerTimeseriesSeries]:
    """Build hour-bucketed spend series for top worker property values.

    Event tuple: (timestamp, worker, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_workers or 1), 20))]

    series: list[CostWorkerTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostWorkerTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostWorkerTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostWorkerTimeseriesSeries(
                worker=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/workers/timeseries", response_model=CostWorkerTimeseriesResponse)
def get_cost_workers_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    worker_filter: Optional[str] = Query(default=None, max_length=128),
    top_workers: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top worker property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostWorkerTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                worker_filter=str(worker_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(worker_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _worker_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_worker_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_workers=top_workers,
    )
    return CostWorkerTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        worker_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_slot_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_slots: int,
) -> list[CostSlotTimeseriesSeries]:
    """Build hour-bucketed spend series for top slot property values.

    Event tuple: (timestamp, slot, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_slots or 1), 20))]

    series: list[CostSlotTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostSlotTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostSlotTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostSlotTimeseriesSeries(
                slot=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/slots/timeseries", response_model=CostSlotTimeseriesResponse)
def get_cost_slots_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    slot_filter: Optional[str] = Query(default=None, max_length=128),
    top_slots: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top slot property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostSlotTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                slot_filter=str(slot_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(slot_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _slot_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_slot_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_slots=top_slots,
    )
    return CostSlotTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        slot_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_task_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_tasks: int,
) -> list[CostTaskTimeseriesSeries]:
    """Build hour-bucketed spend series for top task property values.

    Event tuple: (timestamp, task, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_tasks or 1), 20))]

    series: list[CostTaskTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostTaskTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostTaskTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostTaskTimeseriesSeries(
                task=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/tasks/timeseries", response_model=CostTaskTimeseriesResponse)
def get_cost_tasks_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    task_filter: Optional[str] = Query(default=None, max_length=128),
    top_tasks: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top task property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostTaskTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                task_filter=str(task_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(task_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _task_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_task_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_tasks=top_tasks,
    )
    return CostTaskTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        task_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_step_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_steps: int,
) -> list[CostStepTimeseriesSeries]:
    """Build hour-bucketed spend series for top step property values.

    Event tuple: (timestamp, step, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_steps or 1), 20))]

    series: list[CostStepTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostStepTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostStepTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostStepTimeseriesSeries(
                step=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/steps/timeseries", response_model=CostStepTimeseriesResponse)
def get_cost_steps_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    step_filter: Optional[str] = Query(default=None, max_length=128),
    top_steps: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top step property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostStepTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                step_filter=str(step_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(step_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _step_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_step_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_steps=top_steps,
    )
    return CostStepTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        step_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_replica_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_replicas: int,
) -> list[CostReplicaTimeseriesSeries]:
    """Build hour-bucketed spend series for top replica property values.

    Event tuple: (timestamp, replica, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_replicas or 1), 20))]

    series: list[CostReplicaTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostReplicaTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostReplicaTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostReplicaTimeseriesSeries(
                replica=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/replicas/timeseries", response_model=CostReplicaTimeseriesResponse)
def get_cost_replicas_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    replica_filter: Optional[str] = Query(default=None, max_length=128),
    top_replicas: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top replica property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostReplicaTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                replica_filter=str(replica_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(replica_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _replica_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_replica_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_replicas=top_replicas,
    )
    return CostReplicaTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        replica_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_shard_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_shards: int,
) -> list[CostShardTimeseriesSeries]:
    """Build hour-bucketed spend series for top shard property values.

    Event tuple: (timestamp, shard, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_shards or 1), 20))]

    series: list[CostShardTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostShardTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostShardTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostShardTimeseriesSeries(
                shard=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/shards/timeseries", response_model=CostShardTimeseriesResponse)
def get_cost_shards_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    shard_filter: Optional[str] = Query(default=None, max_length=128),
    top_shards: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top shard property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostShardTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                shard_filter=str(shard_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(shard_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _shard_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_shard_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_shards=top_shards,
    )
    return CostShardTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        shard_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_partition_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_partitions: int,
) -> list[CostPartitionTimeseriesSeries]:
    """Build hour-bucketed spend series for top partition property values.

    Event tuple: (timestamp, partition, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_partitions or 1), 20))]

    series: list[CostPartitionTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostPartitionTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostPartitionTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostPartitionTimeseriesSeries(
                partition=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/partitions/timeseries", response_model=CostPartitionTimeseriesResponse)
def get_cost_partitions_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    partition_filter: Optional[str] = Query(default=None, max_length=128),
    top_partitions: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top partition property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostPartitionTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                partition_filter=str(partition_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(partition_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _partition_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_partition_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_partitions=top_partitions,
    )
    return CostPartitionTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        partition_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_consumer_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_consumers: int,
) -> list[CostConsumerTimeseriesSeries]:
    """Build hour-bucketed spend series for top consumer property values.

    Event tuple: (timestamp, consumer, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_consumers or 1), 20))]

    series: list[CostConsumerTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostConsumerTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostConsumerTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostConsumerTimeseriesSeries(
                consumer=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/consumers/timeseries", response_model=CostConsumerTimeseriesResponse)
def get_cost_consumers_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    consumer_filter: Optional[str] = Query(default=None, max_length=128),
    top_consumers: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top consumer property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostConsumerTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                consumer_filter=str(consumer_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(consumer_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _consumer_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_consumer_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_consumers=top_consumers,
    )
    return CostConsumerTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        consumer_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_producer_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_producers: int,
) -> list[CostProducerTimeseriesSeries]:
    """Build hour-bucketed spend series for top producer property values.

    Event tuple: (timestamp, producer, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_producers or 1), 20))]

    series: list[CostProducerTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostProducerTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostProducerTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostProducerTimeseriesSeries(
                producer=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/producers/timeseries", response_model=CostProducerTimeseriesResponse)
def get_cost_producers_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    producer_filter: Optional[str] = Query(default=None, max_length=128),
    top_producers: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top producer property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostProducerTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                producer_filter=str(producer_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(producer_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _producer_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_producer_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_producers=top_producers,
    )
    return CostProducerTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        producer_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_gpu_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_gpus: int,
) -> list[CostGpuTimeseriesSeries]:
    """Build hour-bucketed spend series for top gpu property values.

    Event tuple: (timestamp, gpu, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_gpus or 1), 20))]

    series: list[CostGpuTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostGpuTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostGpuTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostGpuTimeseriesSeries(
                gpu=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/gpus/timeseries", response_model=CostGpuTimeseriesResponse)
def get_cost_gpus_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    gpu_filter: Optional[str] = Query(default=None, max_length=128),
    top_gpus: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top gpu property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostGpuTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                gpu_filter=str(gpu_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(gpu_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _gpu_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_gpu_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_gpus=top_gpus,
    )
    return CostGpuTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        gpu_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_accelerator_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_accelerators: int,
) -> list[CostAcceleratorTimeseriesSeries]:
    """Build hour-bucketed spend series for top accelerator property values.

    Event tuple: (timestamp, accelerator, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_accelerators or 1), 20))]

    series: list[CostAcceleratorTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostAcceleratorTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostAcceleratorTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostAcceleratorTimeseriesSeries(
                accelerator=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/accelerators/timeseries", response_model=CostAcceleratorTimeseriesResponse)
def get_cost_accelerators_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    accelerator_filter: Optional[str] = Query(default=None, max_length=128),
    top_accelerators: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top accelerator property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostAcceleratorTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                accelerator_filter=str(accelerator_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(accelerator_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _accelerator_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_accelerator_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_accelerators=top_accelerators,
    )
    return CostAcceleratorTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        accelerator_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_cell_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_cells: int,
) -> list[CostCellTimeseriesSeries]:
    """Build hour-bucketed spend series for top cell property values.

    Event tuple: (timestamp, cell, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_cells or 1), 20))]

    series: list[CostCellTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostCellTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostCellTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostCellTimeseriesSeries(
                cell=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/cells/timeseries", response_model=CostCellTimeseriesResponse)
def get_cost_cells_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    cell_filter: Optional[str] = Query(default=None, max_length=128),
    top_cells: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top cell property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostCellTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                cell_filter=str(cell_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(cell_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _cell_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_cell_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_cells=top_cells,
    )
    return CostCellTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        cell_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_zone_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_zones: int,
) -> list[CostZoneTimeseriesSeries]:
    """Build hour-bucketed spend series for top zone property values.

    Event tuple: (timestamp, zone, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_zones or 1), 20))]

    series: list[CostZoneTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostZoneTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostZoneTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostZoneTimeseriesSeries(
                zone=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/zones/timeseries", response_model=CostZoneTimeseriesResponse)
def get_cost_zones_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    zone_filter: Optional[str] = Query(default=None, max_length=128),
    top_zones: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top zone property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostZoneTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                zone_filter=str(zone_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(zone_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _zone_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_zone_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_zones=top_zones,
    )
    return CostZoneTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        zone_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_rack_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_racks: int,
) -> list[CostRackTimeseriesSeries]:
    """Build hour-bucketed spend series for top rack property values.

    Event tuple: (timestamp, rack, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_racks or 1), 20))]

    series: list[CostRackTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostRackTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostRackTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostRackTimeseriesSeries(
                rack=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/racks/timeseries", response_model=CostRackTimeseriesResponse)
def get_cost_racks_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    rack_filter: Optional[str] = Query(default=None, max_length=128),
    top_racks: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top rack property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostRackTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                rack_filter=str(rack_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(rack_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _rack_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_rack_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_racks=top_racks,
    )
    return CostRackTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        rack_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_pool_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_pools: int,
) -> list[CostPoolTimeseriesSeries]:
    """Build hour-bucketed spend series for top pool property values.

    Event tuple: (timestamp, pool, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_pools or 1), 20))]

    series: list[CostPoolTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostPoolTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostPoolTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostPoolTimeseriesSeries(
                pool=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/pools/timeseries", response_model=CostPoolTimeseriesResponse)
def get_cost_pools_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    pool_filter: Optional[str] = Query(default=None, max_length=128),
    top_pools: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top pool property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostPoolTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                pool_filter=str(pool_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(pool_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _pool_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_pool_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_pools=top_pools,
    )
    return CostPoolTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        pool_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_fleet_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_fleets: int,
) -> list[CostFleetTimeseriesSeries]:
    """Build hour-bucketed spend series for top fleet property values.

    Event tuple: (timestamp, fleet, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_fleets or 1), 20))]

    series: list[CostFleetTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostFleetTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostFleetTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostFleetTimeseriesSeries(
                fleet=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/fleets/timeseries", response_model=CostFleetTimeseriesResponse)
def get_cost_fleets_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    fleet_filter: Optional[str] = Query(default=None, max_length=128),
    top_fleets: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top fleet property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostFleetTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                fleet_filter=str(fleet_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(fleet_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _fleet_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_fleet_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_fleets=top_fleets,
    )
    return CostFleetTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        fleet_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_lease_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_leases: int,
) -> list[CostLeaseTimeseriesSeries]:
    """Build hour-bucketed spend series for top lease property values.

    Event tuple: (timestamp, lease, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_leases or 1), 20))]

    series: list[CostLeaseTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostLeaseTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostLeaseTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostLeaseTimeseriesSeries(
                lease=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/leases/timeseries", response_model=CostLeaseTimeseriesResponse)
def get_cost_leases_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    lease_filter: Optional[str] = Query(default=None, max_length=128),
    top_leases: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top lease property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostLeaseTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                lease_filter=str(lease_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(lease_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _lease_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_lease_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_leases=top_leases,
    )
    return CostLeaseTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        lease_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_quota_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_quotas: int,
) -> list[CostQuotaTimeseriesSeries]:
    """Build hour-bucketed spend series for top quota property values.

    Event tuple: (timestamp, quota, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_quotas or 1), 20))]

    series: list[CostQuotaTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostQuotaTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostQuotaTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostQuotaTimeseriesSeries(
                quota=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/quotas/timeseries", response_model=CostQuotaTimeseriesResponse)
def get_cost_quotas_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    quota_filter: Optional[str] = Query(default=None, max_length=128),
    top_quotas: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top quota property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostQuotaTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                quota_filter=str(quota_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(quota_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _quota_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_quota_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_quotas=top_quotas,
    )
    return CostQuotaTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        quota_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_capacity_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_capacities: int,
) -> list[CostCapacityTimeseriesSeries]:
    """Build hour-bucketed spend series for top capacity property values.

    Event tuple: (timestamp, capacity, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_capacities or 1), 20))]

    series: list[CostCapacityTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostCapacityTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostCapacityTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostCapacityTimeseriesSeries(
                capacity=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/capacities/timeseries", response_model=CostCapacityTimeseriesResponse)
def get_cost_capacities_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    capacity_filter: Optional[str] = Query(default=None, max_length=128),
    top_capacities: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top capacity property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostCapacityTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                capacity_filter=str(capacity_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(capacity_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _capacity_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_capacity_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_capacities=top_capacities,
    )
    return CostCapacityTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        capacity_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )



def _build_reservation_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_reservations: int,
) -> list[CostReservationTimeseriesSeries]:
    """Build hour-bucketed spend series for top reservation property values.

    Event tuple: (timestamp, reservation, spend_cents, total_tokens).
    """
    totals_map: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend, total_tokens in events:
        bucket = totals_map.setdefault(value, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        bucket["total_tokens"] += int(total_tokens or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0, "total_tokens": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1
        point["total_tokens"] += int(total_tokens or 0)

    ranked = sorted(
        totals_map.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_reservations or 1), 20))]

    series: list[CostReservationTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostReservationTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0, "total_tokens": 0}
            points.append(
                CostReservationTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                    total_tokens=int(point["total_tokens"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostReservationTimeseriesSeries(
                reservation=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                total_tokens=int(totals["total_tokens"]),
                points=points,
            )
        )
    return series


@router.get("/cost/reservations/timeseries", response_model=CostReservationTimeseriesResponse)
def get_cost_reservations_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    reservation_filter: Optional[str] = Query(default=None, max_length=128),
    top_reservations: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top reservation property values."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
        CostEvent.input_tokens,
        CostEvent.output_tokens,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostReservationTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                reservation_filter=str(reservation_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(reservation_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    for ts, properties_json, estimated_cost_cents, input_tokens, output_tokens in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        value = _reservation_from_properties(properties_json)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0), int(input_tokens or 0) + int(output_tokens or 0)))

    series = _build_reservation_timeseries_series(
        events, start_hour=start_hour, end_hour=end_hour, top_reservations=top_reservations,
    )
    return CostReservationTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        reservation_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


def _cost_request_item_from_event(
    event: CostEvent,
    *,
    property_key: str = "",
) -> CostRequestItem:
    """Build a metadata-only request/log item from a CostEvent (no prompt bodies)."""
    model_name = str(event.model_name or "").strip() or "unknown-model"
    event_user = _user_id_from_properties(event.properties_json) or ""
    feedback = _feedback_fields_from_properties(event.properties_json)
    prop_value = ""
    if property_key:
        prop_value = _flat_property_value_for_stats(event.properties_json, property_key)
    rating_raw = feedback.get("rating")
    rating_value: Optional[int] = None
    if rating_raw is not None:
        try:
            rating_value = int(rating_raw)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            rating_value = None
    return CostRequestItem(
        request_id=str(event.request_id or ""),
        trace_id=str(event.trace_id or "") or None,
        session_id=str(event.session_id or "") or None,
        model_name=model_name,
        request_tag=str(event.request_tag or "") or None,
        estimated_cost_cents=int(event.estimated_cost_cents or 0),
        input_tokens=int(event.input_tokens or 0),
        output_tokens=int(event.output_tokens or 0),
        cache_hit=bool(event.cache_hit),
        user_id=event_user or None,
        session_path=_session_path_from_properties(event.properties_json) or None,
        property_value=prop_value or None,
        rating=rating_value,
        timestamp=event.timestamp or datetime.utcnow(),
    )


def _collect_cost_request_items(
    db: Session,
    *,
    ctx: ActorContext,
    window_hours: int,
    user_id: Optional[str],
    model: Optional[str],
    property_key: Optional[str],
    property_value: Optional[str],
    cache_hit: Optional[bool],
    has_feedback: Optional[bool],
    limit: int,
) -> tuple[list[CostRequestItem], str]:
    """Shared Helicone-style request search used by list + CSV export."""
    since = datetime.utcnow() - timedelta(hours=int(window_hours))
    query = db.query(CostEvent).filter(CostEvent.timestamp >= since)
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return [], ""
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    user_filter = str(user_id or "").strip().lower()
    model_filter = str(model or "").strip().lower()
    prop_key = str(property_key or "").strip()
    if prop_key and prop_key in {"helicone_feedback", "scores", "metadata"}:
        raise api_validation_error(
            "property_key must be a flat custom property (not helicone_feedback/scores/metadata)",
            decision_trace_id="cost-requests-property-key-invalid",
        )
    prop_value_filter = str(property_value or "").strip().lower()
    if prop_value_filter and not prop_key:
        raise api_validation_error(
            "property_value requires property_key",
            decision_trace_id="cost-requests-property-value-without-key",
        )

    items: list[CostRequestItem] = []
    for event in query.order_by(CostEvent.timestamp.desc()).limit(10_000).all():
        model_name = str(event.model_name or "").strip() or "unknown-model"
        if model_filter and model_filter not in model_name.lower():
            continue
        event_user = _user_id_from_properties(event.properties_json) or ""
        if user_filter and user_filter not in event_user.lower():
            continue
        if cache_hit is not None and bool(event.cache_hit) is not bool(cache_hit):
            continue
        feedback = _feedback_fields_from_properties(event.properties_json)
        if has_feedback is not None and bool(feedback.get("has_feedback")) is not bool(has_feedback):
            continue
        prop_value = ""
        if prop_key:
            prop_value = _flat_property_value_for_stats(event.properties_json, prop_key)
            if not prop_value:
                continue
            if prop_value_filter and prop_value_filter not in prop_value.lower():
                continue
        items.append(_cost_request_item_from_event(event, property_key=prop_key))
        if len(items) >= int(limit):
            break
    return items, prop_key


@router.get("/cost/requests", response_model=CostRequestListResponse)
def list_cost_requests(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    user_id: Optional[str] = Query(default=None, max_length=128),
    model: Optional[str] = Query(default=None, max_length=128),
    property_key: Optional[str] = Query(default=None, max_length=64),
    property_value: Optional[str] = Query(default=None, max_length=256),
    cache_hit: Optional[bool] = Query(default=None),
    has_feedback: Optional[bool] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style request search (datasets-lite metadata + spend; no prompt bodies)."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    items, prop_key = _collect_cost_request_items(
        db,
        ctx=ctx,
        window_hours=int(window_hours),
        user_id=user_id,
        model=model,
        property_key=property_key,
        property_value=property_value,
        cache_hit=cache_hit,
        has_feedback=has_feedback,
        limit=int(limit),
    )
    return CostRequestListResponse(
        window_hours=int(window_hours),
        count=len(items),
        total_spend_cents=int(sum(item.estimated_cost_cents for item in items)),
        property_key=prop_key or None,
        items=items,
    )


@router.get("/v1/logs", response_model=CostRequestListResponse)
def list_gateway_logs(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    user_id: Optional[str] = Query(default=None, max_length=128),
    model: Optional[str] = Query(default=None, max_length=128),
    property_key: Optional[str] = Query(default=None, max_length=64),
    property_value: Optional[str] = Query(default=None, max_length=256),
    cache_hit: Optional[bool] = Query(default=None),
    has_feedback: Optional[bool] = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Portkey-style request logs (metadata-only alias of `/cost/requests`)."""
    return list_cost_requests(
        window_hours=window_hours,
        user_id=user_id,
        model=model,
        property_key=property_key,
        property_value=property_value,
        cache_hit=cache_hit,
        has_feedback=has_feedback,
        limit=limit,
        db=db,
        ctx=ctx,
    )


@router.get("/v1/logs/export")
def export_gateway_logs(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    user_id: Optional[str] = Query(default=None, max_length=128),
    model: Optional[str] = Query(default=None, max_length=128),
    property_key: Optional[str] = Query(default=None, max_length=64),
    property_value: Optional[str] = Query(default=None, max_length=256),
    cache_hit: Optional[bool] = Query(default=None),
    has_feedback: Optional[bool] = Query(default=None),
    limit: int = Query(default=1000, ge=1, le=5000),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Portkey-style logs CSV export (metadata-only alias of `/cost/requests/export`)."""
    response = export_cost_requests(
        window_hours=window_hours,
        user_id=user_id,
        model=model,
        property_key=property_key,
        property_value=property_value,
        cache_hit=cache_hit,
        has_feedback=has_feedback,
        limit=limit,
        db=db,
        ctx=ctx,
    )
    # Keep Portkey-friendly filename while reusing the same metadata-only CSV body.
    if isinstance(response, Response):
        response.headers["Content-Disposition"] = (
            f'attachment; filename="gateway-logs-{int(window_hours)}h.csv"'
        )
    return response


LOG_EXPORT_ALLOWED_FIELDS = {
    "id",
    "request_id",
    "trace_id",
    "created_at",
    "ai_model",
    "model",
    "cost",
    "cache_hit",
    "user_id",
    "session_id",
    "session_path",
    "request_tag",
    "input_tokens",
    "output_tokens",
    "rating",
}
LOG_EXPORT_BODY_FIELDS = {"request", "response", "completion", "prompt", "messages"}
LOG_EXPORT_DEFAULT_FIELDS = [
    "id",
    "request_id",
    "trace_id",
    "created_at",
    "ai_model",
    "cost",
    "cache_hit",
    "user_id",
    "session_id",
    "session_path",
    "request_tag",
    "input_tokens",
    "output_tokens",
    "rating",
]


def _normalize_log_export_requested_data(raw: Optional[list[str]]) -> list[str]:
    selected: list[str] = []
    for item in raw or LOG_EXPORT_DEFAULT_FIELDS:
        field = str(item or "").strip().lower()
        if not field or field in LOG_EXPORT_BODY_FIELDS:
            continue
        if field not in LOG_EXPORT_ALLOWED_FIELDS:
            continue
        if field == "model":
            field = "ai_model"
        if field not in selected:
            selected.append(field)
    return selected or list(LOG_EXPORT_DEFAULT_FIELDS)


def _normalize_log_export_filters(raw: Optional[dict[str, object]]) -> dict[str, object]:
    source = raw if isinstance(raw, dict) else {}
    window_hours = 24
    try:
        window_hours = int(source.get("window_hours") or 24)
    except (TypeError, ValueError):
        window_hours = 24
    window_hours = max(1, min(window_hours, 24 * 30))
    limit = 1000
    try:
        limit = int(source.get("limit") or 1000)
    except (TypeError, ValueError):
        limit = 1000
    limit = max(1, min(limit, 5000))
    filters: dict[str, object] = {"window_hours": window_hours, "limit": limit}
    for key in ("user_id", "model", "property_key", "property_value"):
        value = str(source.get(key) or "").strip()
        if value:
            filters[key] = value
    for key in ("cache_hit", "has_feedback"):
        if key not in source or source.get(key) is None:
            continue
        raw_bool = source.get(key)
        if isinstance(raw_bool, bool):
            filters[key] = raw_bool
        else:
            text = str(raw_bool).strip().lower()
            if text in {"true", "1", "yes"}:
                filters[key] = True
            elif text in {"false", "0", "no"}:
                filters[key] = False
    return filters


def _serialize_log_export_job(job: GatewayLogExportJob) -> GatewayLogExportResponse:
    try:
        filters = json.loads(str(job.filters_json or "{}"))
    except json.JSONDecodeError:
        filters = {}
    try:
        requested = json.loads(str(job.requested_data_json or "[]"))
    except json.JSONDecodeError:
        requested = []
    return GatewayLogExportResponse(
        id=str(job.export_id),
        status=str(job.status or "pending"),
        description=str(job.description or ""),
        workspace_id=str(job.workspace_id or "") or None,
        filters=filters if isinstance(filters, dict) else {},
        requested_data=[str(item) for item in requested] if isinstance(requested, list) else [],
        row_count=int(job.row_count or 0),
        created_at=job.created_at or datetime.utcnow(),
        started_at=job.started_at,
        completed_at=job.completed_at,
    )


def _log_export_row(item: CostRequestItem, fields: list[str]) -> dict[str, object]:
    mapping: dict[str, object] = {
        "id": item.request_id,
        "request_id": item.request_id,
        "trace_id": item.trace_id or "",
        "created_at": item.timestamp.isoformat() if item.timestamp else "",
        "ai_model": item.model_name,
        "cost": item.estimated_cost_cents,
        "cache_hit": bool(item.cache_hit),
        "user_id": item.user_id or "",
        "session_id": item.session_id or "",
        "session_path": item.session_path or "",
        "request_tag": item.request_tag or "",
        "input_tokens": item.input_tokens,
        "output_tokens": item.output_tokens,
        "rating": item.rating if item.rating is not None else None,
    }
    return {field: mapping.get(field) for field in fields}


def _get_log_export_job_or_404(
    db: Session,
    *,
    ctx: ActorContext,
    export_id: str,
    allow_deleted: bool = False,
) -> GatewayLogExportJob:
    normalized = str(export_id or "").strip()
    if not normalized:
        raise api_validation_error("export_id is required", decision_trace_id="gateway-logs-export-id")
    job = db.query(GatewayLogExportJob).filter_by(export_id=normalized).first()
    if job is None or (not allow_deleted and str(job.status or "").strip().lower() == "deleted"):
        raise not_found_error("logs_export", normalized, decision_trace_id="gateway-logs-export-not-found")
    if ctx.actor_role == ROLE_AGENT_OWNER and job.actor_id != ctx.actor_id:
        raise authz_scope_forbidden(
            message="Agent Owner can only access own log export jobs.",
            actor_role=ctx.actor_role,
            required_scope="export.actor_id == requester actor_id",
            decision_trace_id="authz-gateway-logs-export-scope",
            remediation_hint="Use your own export id or Platform Admin for cross-owner access.",
        )
    return job


@router.post("/v1/logs/exports", response_model=GatewayLogExportResponse)
def create_gateway_log_export(
    payload: GatewayLogExportCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Portkey-style async log export job create (metadata-only; no prompt bodies)."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    filters = _normalize_log_export_filters(payload.filters)
    requested = _normalize_log_export_requested_data(payload.requested_data)
    job = GatewayLogExportJob(
        export_id=f"lexp-{uuid4().hex[:20]}",
        actor_id=ctx.actor_id,
        description=str(payload.description or "").strip()[:512],
        workspace_id=str(payload.workspace_id or "").strip() or None,
        status="pending",
        filters_json=json.dumps(filters, separators=(",", ":")),
        requested_data_json=json.dumps(requested, separators=(",", ":")),
        row_count=0,
        content_jsonl="",
    )
    db.add(job)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.logs.export.create",
        resource_type="gateway_log_export",
        resource_id=job.export_id,
        trace_id=f"trace-logs-export-create-{uuid4().hex[:12]}",
        action_context={"filters": filters, "requested_data": requested},
    )
    db.commit()
    db.refresh(job)
    return _serialize_log_export_job(job)


@router.get("/v1/logs/exports", response_model=GatewayLogExportListResponse)
def list_gateway_log_exports(
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = Query(default=None, max_length=32),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """List Portkey-style log export jobs for the current actor scope."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    query = db.query(GatewayLogExportJob).filter(GatewayLogExportJob.status != "deleted")
    if ctx.actor_role == ROLE_AGENT_OWNER:
        query = query.filter(GatewayLogExportJob.actor_id == ctx.actor_id)
    status_filter = str(status or "").strip().lower()
    if status_filter:
        query = query.filter(GatewayLogExportJob.status == status_filter)
    rows = query.order_by(GatewayLogExportJob.created_at.desc()).offset(offset).limit(limit).all()
    data = [_serialize_log_export_job(row) for row in rows]
    return GatewayLogExportListResponse(data=data, count=len(data))


@router.get("/v1/logs/exports/{export_id}", response_model=GatewayLogExportResponse)
def get_gateway_log_export(
    export_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Retrieve a Portkey-style log export job status."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    job = _get_log_export_job_or_404(db, ctx=ctx, export_id=export_id)
    return _serialize_log_export_job(job)


@router.post("/v1/logs/exports/{export_id}/start", response_model=GatewayLogExportResponse)
def start_gateway_log_export(
    export_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Start (and synchronously complete) a metadata-only log export job."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    job = _get_log_export_job_or_404(db, ctx=ctx, export_id=export_id)
    status_value = str(job.status or "").strip().lower()
    if status_value in {"completed", "failed"}:
        return _serialize_log_export_job(job)
    if status_value in {"cancelled", "deleted"}:
        raise api_validation_error(
            f"Export job status '{status_value}' cannot be started.",
            decision_trace_id="gateway-logs-export-start-terminal",
        )

    try:
        raw_filters = json.loads(str(job.filters_json or "{}") or "{}")
    except json.JSONDecodeError:
        raw_filters = {}
    try:
        raw_requested = json.loads(str(job.requested_data_json or "[]") or "[]")
    except json.JSONDecodeError:
        raw_requested = []
    filters = _normalize_log_export_filters(raw_filters if isinstance(raw_filters, dict) else {})
    requested = _normalize_log_export_requested_data(
        raw_requested if isinstance(raw_requested, list) else None
    )
    now = datetime.utcnow()
    job.status = "processing"
    job.started_at = now
    db.commit()

    items, _prop_key = _collect_cost_request_items(
        db,
        ctx=ctx,
        window_hours=int(filters.get("window_hours") or 24),
        user_id=str(filters.get("user_id") or "") or None,
        model=str(filters.get("model") or "") or None,
        property_key=str(filters.get("property_key") or "") or None,
        property_value=str(filters.get("property_value") or "") or None,
        cache_hit=filters.get("cache_hit") if isinstance(filters.get("cache_hit"), bool) else None,
        has_feedback=filters.get("has_feedback") if isinstance(filters.get("has_feedback"), bool) else None,
        limit=int(filters.get("limit") or 1000),
    )
    lines = [json.dumps(_log_export_row(item, requested), separators=(",", ":")) for item in items]
    job.content_jsonl = "\n".join(lines) + ("\n" if lines else "")
    job.row_count = len(items)
    job.status = "completed"
    job.completed_at = datetime.utcnow()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.logs.export.start",
        resource_type="gateway_log_export",
        resource_id=job.export_id,
        trace_id=f"trace-logs-export-start-{uuid4().hex[:12]}",
        action_context={"row_count": job.row_count, "status": job.status},
    )
    db.commit()
    db.refresh(job)
    return _serialize_log_export_job(job)


@router.post("/v1/logs/exports/{export_id}/cancel", response_model=GatewayLogExportCancelResponse)
def cancel_gateway_log_export(
    export_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Cancel a pending/processing Portkey-style log export job."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    job = _get_log_export_job_or_404(db, ctx=ctx, export_id=export_id)
    status_value = str(job.status or "").strip().lower()
    if status_value == "deleted":
        raise not_found_error("logs_export", export_id, decision_trace_id="gateway-logs-export-cancel-deleted")
    if status_value == "cancelled":
        return GatewayLogExportCancelResponse(
            id=str(job.export_id),
            status="cancelled",
            row_count=int(job.row_count or 0),
        )
    if status_value in {"completed", "failed"}:
        raise api_validation_error(
            f"Export job status '{status_value}' cannot be cancelled.",
            decision_trace_id="gateway-logs-export-cancel-terminal",
        )
    job.status = "cancelled"
    job.content_jsonl = ""
    job.row_count = 0
    job.completed_at = datetime.utcnow()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.logs.export.cancel",
        resource_type="gateway_log_export",
        resource_id=job.export_id,
        trace_id=f"trace-logs-export-cancel-{uuid4().hex[:12]}",
        action_context={"status": job.status},
    )
    db.commit()
    db.refresh(job)
    return GatewayLogExportCancelResponse(
        id=str(job.export_id),
        status=str(job.status),
        row_count=int(job.row_count or 0),
    )


@router.delete("/v1/logs/exports/{export_id}", response_model=GatewayLogExportDeleteResponse)
def delete_gateway_log_export(
    export_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Soft-delete a Portkey-style log export job and clear stored JSONL."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    job = _get_log_export_job_or_404(db, ctx=ctx, export_id=export_id, allow_deleted=True)
    if str(job.status or "").strip().lower() == "deleted":
        return GatewayLogExportDeleteResponse(id=str(job.export_id), deleted=True)
    job.status = "deleted"
    job.content_jsonl = ""
    job.row_count = 0
    job.completed_at = job.completed_at or datetime.utcnow()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.logs.export.delete",
        resource_type="gateway_log_export",
        resource_id=job.export_id,
        trace_id=f"trace-logs-export-delete-{uuid4().hex[:12]}",
        action_context={"status": "deleted"},
    )
    db.commit()
    return GatewayLogExportDeleteResponse(id=str(job.export_id), deleted=True)


@router.get("/v1/logs/exports/{export_id}/download", response_model=GatewayLogExportDownloadResponse)
def download_gateway_log_export(
    export_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Download completed log export JSONL (inline content; metadata-only)."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    job = _get_log_export_job_or_404(db, ctx=ctx, export_id=export_id)
    if str(job.status or "") != "completed":
        raise api_validation_error(
            "Export job is not completed yet",
            decision_trace_id="gateway-logs-export-not-ready",
        )
    signed_url, expires_at = _build_signed_log_export_url(
        export_id=str(job.export_id),
        actor_id=str(job.actor_id),
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.logs.export.download",
        resource_type="gateway_log_export",
        resource_id=job.export_id,
        trace_id=f"trace-logs-export-download-{uuid4().hex[:12]}",
        action_context={"row_count": int(job.row_count or 0), "expires_at": expires_at},
    )
    db.commit()
    return GatewayLogExportDownloadResponse(
        id=str(job.export_id),
        status=str(job.status),
        row_count=int(job.row_count or 0),
        content=str(job.content_jsonl or ""),
        url=f"/v1/logs/exports/{job.export_id}/download",
        signed_url=signed_url,
        expires_at=expires_at,
    )


@router.get("/v1/logs/exports/{export_id}/content")
def download_signed_gateway_log_export_content(
    export_id: str,
    exp: int = Query(..., ge=1),
    sig: str = Query(..., min_length=16, max_length=128),
    db: Session = Depends(get_db),
):
    """Portkey-style time-limited HMAC signed download of metadata-only JSONL.

    Auth is the signature (export_id + owning actor_id + exp). No session actor required.
    """
    normalized = str(export_id or "").strip()
    if not normalized:
        raise api_validation_error("export_id is required", decision_trace_id="gateway-logs-export-signed-id")
    job = db.query(GatewayLogExportJob).filter_by(export_id=normalized).first()
    if job is None or str(job.status or "") != "completed":
        raise not_found_error("logs_export", normalized, decision_trace_id="gateway-logs-export-signed-not-found")
    if not _verify_signed_log_export(
        export_id=str(job.export_id),
        actor_id=str(job.actor_id),
        exp=exp,
        sig=sig,
    ):
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "LOG_EXPORT_SIGNED_URL_INVALID",
                "message": "Signed export URL is invalid or expired.",
                "decision_trace_id": "gateway-logs-export-signed-invalid",
            },
        )
    create_audit_event(
        db,
        actor_id=str(job.actor_id),
        action_type="gateway.logs.export.signed_download",
        resource_type="gateway_log_export",
        resource_id=job.export_id,
        trace_id=f"trace-logs-export-signed-{uuid4().hex[:12]}",
        action_context={"row_count": int(job.row_count or 0), "exp": int(exp)},
    )
    db.commit()
    body = str(job.content_jsonl or "").encode("utf-8")
    return Response(
        content=body,
        media_type="application/x-ndjson",
        headers={
            "Content-Disposition": f'attachment; filename="{job.export_id}.jsonl"',
            "X-Export-Row-Count": str(int(job.row_count or 0)),
        },
    )


@router.get("/v1/logs/{request_id}", response_model=CostRequestItem)
def get_gateway_log(
    request_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Portkey-style single request log lookup (metadata + spend; no prompt bodies)."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    normalized_request_id = str(request_id or "").strip()
    if not normalized_request_id:
        raise api_validation_error("request_id is required", decision_trace_id="gateway-logs-get-request-id")
    query = db.query(CostEvent).filter(CostEvent.request_id == normalized_request_id)
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            raise not_found_error("cost_event", normalized_request_id, decision_trace_id="gateway-logs-get-not-found")
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))
    event = query.order_by(CostEvent.timestamp.desc()).first()
    if event is None:
        raise not_found_error("cost_event", normalized_request_id, decision_trace_id="gateway-logs-get-not-found")
    return _cost_request_item_from_event(event)


@router.get("/cost/requests/export")
def export_cost_requests(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    user_id: Optional[str] = Query(default=None, max_length=128),
    model: Optional[str] = Query(default=None, max_length=128),
    property_key: Optional[str] = Query(default=None, max_length=64),
    property_value: Optional[str] = Query(default=None, max_length=256),
    cache_hit: Optional[bool] = Query(default=None),
    has_feedback: Optional[bool] = Query(default=None),
    limit: int = Query(default=1000, ge=1, le=5000),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style CSV export of request search results (metadata + spend only)."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    items, prop_key = _collect_cost_request_items(
        db,
        ctx=ctx,
        window_hours=int(window_hours),
        user_id=user_id,
        model=model,
        property_key=property_key,
        property_value=property_value,
        cache_hit=cache_hit,
        has_feedback=has_feedback,
        limit=int(limit),
    )
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    header = [
        "timestamp",
        "request_id",
        "trace_id",
        "session_id",
        "session_path",
        "user_id",
        "request_tag",
        "model_name",
        "input_tokens",
        "output_tokens",
        "estimated_cost_cents",
        "cache_hit",
        "rating",
    ]
    if prop_key:
        header.extend(["property_key", "property_value"])
    writer.writerow(header)
    for item in items:
        row = [
            item.timestamp.isoformat() if item.timestamp else "",
            item.request_id,
            item.trace_id or "",
            item.session_id or "",
            item.session_path or "",
            item.user_id or "",
            item.request_tag or "",
            item.model_name,
            item.input_tokens,
            item.output_tokens,
            item.estimated_cost_cents,
            "true" if item.cache_hit else "false",
            item.rating if item.rating is not None else "",
        ]
        if prop_key:
            row.extend([prop_key, item.property_value or ""])
        writer.writerow(row)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.requests.export",
        resource_type="cost_request_export",
        resource_id=f"window-{window_hours}h",
        trace_id=f"trace-cost-requests-export-{uuid4().hex[:12]}",
        action_context={
            "row_count": len(items),
            "window_hours": int(window_hours),
            "property_key": prop_key or None,
            "cache_hit": cache_hit,
            "has_feedback": has_feedback,
        },
    )
    db.commit()
    filename = f"cost-requests-{int(window_hours)}h.csv"
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _normalize_session_path(session_path: object) -> str:
    raw = str(session_path or "").strip()
    if not raw:
        return ""
    parts = [part.strip() for part in raw.replace("\\", "/").split("/") if part.strip()]
    if not parts:
        return ""
    return "/" + "/".join(parts[:16])


def _session_path_prefixes(session_path: str, max_depth: int) -> list[str]:
    normalized = _normalize_session_path(session_path)
    if not normalized:
        return []
    parts = [part for part in normalized.split("/") if part]
    depth = max(1, min(int(max_depth or 1), 16))
    prefixes: list[str] = []
    for index in range(1, min(len(parts), depth) + 1):
        prefixes.append("/" + "/".join(parts[:index]))
    return prefixes


def _build_session_path_tree(
    aggregates: dict[str, dict[str, object]],
    *,
    max_depth: int,
    limit: int,
) -> list[CostSessionTreeNode]:
    """Build a Helicone-style path tree from prefix aggregates."""
    depth = max(1, min(int(max_depth or 1), 16))
    node_cap = max(1, min(int(limit or 1), 200))

    def child_paths(parent: str) -> list[str]:
        prefix = parent.rstrip("/") + "/"
        children = [
            path
            for path in aggregates
            if path.startswith(prefix)
            and path.count("/") == parent.count("/") + 1
            and path.count("/") <= depth
        ]
        children.sort(
            key=lambda path: (
                -int(aggregates[path].get("spend_cents") or 0),
                path,
            )
        )
        return children[:node_cap]

    def build_node(path: str) -> CostSessionTreeNode:
        data = aggregates.get(path) or {}
        return CostSessionTreeNode(
            path=path,
            spend_cents=int(data.get("spend_cents") or 0),
            event_count=int(data.get("event_count") or 0),
            session_count=len(data.get("sessions") or set()),  # type: ignore[arg-type]
            children=[build_node(child) for child in child_paths(path)],
        )

    roots = [
        path
        for path in aggregates
        if path.count("/") == 1 and path.count("/") <= depth
    ]
    roots.sort(
        key=lambda path: (
            -int(aggregates[path].get("spend_cents") or 0),
            path,
        )
    )
    return [build_node(path) for path in roots[:node_cap]]


@router.get("/cost/sessions/tree", response_model=CostSessionTreeResponse)
def list_cost_session_tree(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    path_prefix: Optional[str] = Query(default=None, max_length=256),
    max_depth: int = Query(default=4, ge=1, le=16),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style session path tree: aggregate spend by path prefixes."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    since = datetime.utcnow() - timedelta(hours=int(window_hours))
    query = db.query(CostEvent).filter(CostEvent.timestamp >= since)
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostSessionTreeResponse(
                window_hours=int(window_hours),
                max_depth=int(max_depth),
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                items=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    prefix_filter = _normalize_session_path(path_prefix).lower()
    aggregates: dict[str, dict[str, object]] = {}
    for event in query.order_by(CostEvent.timestamp.desc()).limit(10_000).all():
        session_id = str(event.session_id or "").strip() or "unknown-session"
        session_path = _normalize_session_path(_session_path_from_properties(event.properties_json))
        if not session_path:
            continue
        if prefix_filter and not session_path.lower().startswith(prefix_filter):
            continue
        spend = int(event.estimated_cost_cents or 0)
        for path in _session_path_prefixes(session_path, max_depth):
            bucket = aggregates.setdefault(
                path,
                {"spend_cents": 0, "event_count": 0, "sessions": set()},
            )
            bucket["spend_cents"] = int(bucket["spend_cents"] or 0) + spend
            bucket["event_count"] = int(bucket["event_count"] or 0) + 1
            sessions = bucket["sessions"]
            if isinstance(sessions, set):
                sessions.add(session_id)

    items = _build_session_path_tree(aggregates, max_depth=max_depth, limit=limit)
    return CostSessionTreeResponse(
        window_hours=int(window_hours),
        max_depth=int(max_depth),
        total_spend_cents=int(sum(item.spend_cents for item in items)),
        total_event_count=int(sum(item.event_count for item in items)),
        count=len(items),
        items=items,
    )


_COST_PROPERTY_STATS_SKIP_KEYS = {
    "helicone_feedback",
    "scores",
    "metadata",
    "user_properties",
}


def _flat_property_value_for_stats(properties_json: object, property_key: str) -> str:
    """Return a scalar property value for Helicone-style property stats (skip nested blobs)."""
    key = str(property_key or "").strip()
    if not key or key.lower() in _COST_PROPERTY_STATS_SKIP_KEYS:
        return ""
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return ""
    if not isinstance(parsed, dict):
        return ""
    value = parsed.get(key)
    if value is None or isinstance(value, (dict, list)):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    text = str(value).strip()
    return text[:256]


@router.get("/cost/properties/stats", response_model=CostPropertyStatsResponse)
def get_cost_property_stats(
    property_key: str = Query(..., min_length=1, max_length=64),
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style aggregation of custom cost property values (spend + event count)."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    key = str(property_key or "").strip()
    if not key or key.lower() in _COST_PROPERTY_STATS_SKIP_KEYS:
        raise HTTPException(
            status_code=422,
            detail="property_key must be a flat custom property (not helicone_feedback/scores/metadata)",
        )
    since = datetime.utcnow() - timedelta(hours=int(window_hours))
    query = db.query(CostEvent.properties_json, CostEvent.estimated_cost_cents).filter(
        CostEvent.timestamp >= since
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostPropertyStatsResponse(
                window_hours=int(window_hours),
                property_key=key,
                total_events_with_key=0,
                count=0,
                items=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    totals: dict[str, dict[str, int]] = {}
    matched_events = 0
    for properties_json, estimated_cost_cents in query.limit(10_000).all():
        value = _flat_property_value_for_stats(properties_json, key)
        if not value:
            continue
        matched_events += 1
        bucket = totals.setdefault(value, {"event_count": 0, "spend_cents": 0})
        bucket["event_count"] += 1
        bucket["spend_cents"] += int(estimated_cost_cents or 0)

    items = [
        CostPropertyStatsItem(
            value=value,
            event_count=int(data["event_count"]),
            spend_cents=int(data["spend_cents"]),
        )
        for value, data in totals.items()
    ]
    items.sort(key=lambda row: (row.spend_cents, row.event_count), reverse=True)
    items = items[: int(limit)]
    return CostPropertyStatsResponse(
        window_hours=int(window_hours),
        property_key=key,
        total_events_with_key=matched_events,
        count=len(items),
        items=items,
    )


def _build_property_timeseries_series(
    events: list[tuple[datetime, str, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_values: int,
) -> list[CostPropertyTimeseriesSeries]:
    """Build hour-bucketed series for the top property values by spend."""
    value_totals: dict[str, dict[str, int]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, int]]] = {}
    for ts, value, spend in events:
        bucket = value_totals.setdefault(value, {"spend_cents": 0, "event_count": 0})
        bucket["spend_cents"] += int(spend or 0)
        bucket["event_count"] += 1
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(value, {})
        point = hours.setdefault(hour, {"spend_cents": 0, "event_count": 0})
        point["spend_cents"] += int(spend or 0)
        point["event_count"] += 1

    ranked = sorted(
        value_totals.items(),
        key=lambda item: (item[1]["spend_cents"], item[1]["event_count"]),
        reverse=True,
    )[: max(1, min(int(top_values or 1), 20))]

    series: list[CostPropertyTimeseriesSeries] = []
    for value, totals in ranked:
        hours = hour_buckets.get(value) or {}
        cursor = start_hour
        points: list[CostPropertyTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"spend_cents": 0, "event_count": 0}
            points.append(
                CostPropertyTimeseriesPoint(
                    hour_start=cursor,
                    spend_cents=int(point["spend_cents"]),
                    event_count=int(point["event_count"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostPropertyTimeseriesSeries(
                value=value,
                spend_cents=int(totals["spend_cents"]),
                event_count=int(totals["event_count"]),
                points=points,
            )
        )
    return series


@router.get("/cost/properties/timeseries", response_model=CostPropertyTimeseriesResponse)
def get_cost_property_timeseries(
    property_key: str = Query(..., min_length=1, max_length=64),
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    value_filter: Optional[str] = Query(default=None, max_length=256),
    top_values: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly burn charts for top values of a custom cost property."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    key = str(property_key or "").strip()
    if not key or key.lower() in _COST_PROPERTY_STATS_SKIP_KEYS:
        raise HTTPException(
            status_code=422,
            detail="property_key must be a flat custom property (not helicone_feedback/scores/metadata)",
        )

    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostPropertyTimeseriesResponse(
                property_key=key,
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                value_filter=str(value_filter or "").strip() or None,
                total_spend_cents=0,
                total_event_count=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(value_filter or "").strip().lower()
    events: list[tuple[datetime, str, int]] = []
    for ts, properties_json, estimated_cost_cents in query.order_by(CostEvent.timestamp.desc()).limit(10_000).all():
        value = _flat_property_value_for_stats(properties_json, key)
        if not value:
            continue
        if filter_text and filter_text not in value.lower():
            continue
        events.append((ts, value, int(estimated_cost_cents or 0)))

    series = _build_property_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_values=top_values,
    )
    return CostPropertyTimeseriesResponse(
        property_key=key,
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        value_filter=filter_text or None,
        total_spend_cents=int(sum(item.spend_cents for item in series)),
        total_event_count=int(sum(item.event_count for item in series)),
        count=len(series),
        series=series,
    )


@router.get("/cost/scores/stats", response_model=CostScoreStatsResponse)
def get_cost_score_stats(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    score_key: Optional[str] = Query(default=None, max_length=64),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style structured score aggregation (avg/min/max/count per score key)."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    since = datetime.utcnow() - timedelta(hours=int(window_hours))
    query = db.query(CostEvent.properties_json, CostEvent.estimated_cost_cents).filter(
        CostEvent.timestamp >= since
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostScoreStatsResponse(
                window_hours=int(window_hours),
                total_scored_events=0,
                count=0,
                items=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_key = str(score_key or "").strip().lower()
    totals: dict[str, dict[str, float]] = {}
    scored_events = 0
    for properties_json, estimated_cost_cents in query.limit(10_000).all():
        fields = _feedback_fields_from_properties(properties_json)
        scores = fields.get("scores") if isinstance(fields.get("scores"), dict) else {}
        if not scores:
            continue
        scored_events += 1
        for raw_key, raw_value in list(scores.items())[:16]:
            key = str(raw_key or "").strip()[:64]
            if not key:
                continue
            if filter_key and filter_key not in key.lower():
                continue
            try:
                value = float(raw_value)
            except (TypeError, ValueError):
                continue
            if value != value:  # NaN
                continue
            bucket = totals.setdefault(
                key,
                {"count": 0.0, "sum": 0.0, "min": value, "max": value, "spend_cents": 0.0},
            )
            bucket["count"] += 1
            bucket["sum"] += value
            bucket["min"] = min(float(bucket["min"]), value)
            bucket["max"] = max(float(bucket["max"]), value)
            bucket["spend_cents"] += int(estimated_cost_cents or 0)

    items = [
        CostScoreStatsItem(
            key=key,
            count=int(data["count"]),
            avg=round(float(data["sum"]) / float(data["count"]), 4) if data["count"] else 0.0,
            min=float(data["min"]),
            max=float(data["max"]),
            spend_cents=int(data["spend_cents"]),
        )
        for key, data in totals.items()
    ]
    items.sort(key=lambda row: row.count, reverse=True)
    items = items[: int(limit)]
    return CostScoreStatsResponse(
        window_hours=int(window_hours),
        total_scored_events=scored_events,
        count=len(items),
        items=items,
    )


def _build_score_timeseries_series(
    events: list[tuple[datetime, str, float, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_keys: int,
) -> list[CostScoreTimeseriesSeries]:
    """Build hour-bucketed avg/count/spend series for the top score keys."""
    key_totals: dict[str, dict[str, float]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, float]]] = {}
    for ts, key, value, spend in events:
        bucket = key_totals.setdefault(
            key,
            {"count": 0.0, "sum": 0.0, "min": value, "max": value, "spend_cents": 0.0},
        )
        bucket["count"] += 1
        bucket["sum"] += value
        bucket["min"] = min(float(bucket["min"]), value)
        bucket["max"] = max(float(bucket["max"]), value)
        bucket["spend_cents"] += int(spend or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(key, {})
        point = hours.setdefault(hour, {"count": 0.0, "sum": 0.0, "spend_cents": 0.0})
        point["count"] += 1
        point["sum"] += value
        point["spend_cents"] += int(spend or 0)

    ranked = sorted(
        key_totals.items(),
        key=lambda item: (item[1]["count"], item[1]["spend_cents"]),
        reverse=True,
    )[: max(1, min(int(top_keys or 1), 20))]

    series: list[CostScoreTimeseriesSeries] = []
    for key, totals in ranked:
        hours = hour_buckets.get(key) or {}
        cursor = start_hour
        points: list[CostScoreTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"count": 0.0, "sum": 0.0, "spend_cents": 0.0}
            count = float(point["count"])
            points.append(
                CostScoreTimeseriesPoint(
                    hour_start=cursor,
                    avg=round(float(point["sum"]) / count, 4) if count else 0.0,
                    count=int(count),
                    spend_cents=int(point["spend_cents"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostScoreTimeseriesSeries(
                key=key,
                count=int(totals["count"]),
                avg=round(float(totals["sum"]) / float(totals["count"]), 4) if totals["count"] else 0.0,
                min=float(totals["min"]),
                max=float(totals["max"]),
                spend_cents=int(totals["spend_cents"]),
                points=points,
            )
        )
    return series


@router.get("/cost/scores/timeseries", response_model=CostScoreTimeseriesResponse)
def get_cost_score_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    score_key: Optional[str] = Query(default=None, max_length=64),
    top_keys: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly score quality charts (avg/count/spend per score key)."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostScoreTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                score_key_filter=str(score_key or "").strip() or None,
                total_scored_events=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_key = str(score_key or "").strip().lower()
    events: list[tuple[datetime, str, float, int]] = []
    scored_events = 0
    for ts, properties_json, estimated_cost_cents in query.order_by(CostEvent.timestamp.desc()).limit(10_000).all():
        fields = _feedback_fields_from_properties(properties_json)
        scores = fields.get("scores") if isinstance(fields.get("scores"), dict) else {}
        if not scores:
            continue
        scored_events += 1
        spend = int(estimated_cost_cents or 0)
        for raw_key, raw_value in list(scores.items())[:16]:
            key = str(raw_key or "").strip()[:64]
            if not key:
                continue
            if filter_key and filter_key not in key.lower():
                continue
            try:
                value = float(raw_value)
            except (TypeError, ValueError):
                continue
            if value != value:  # NaN
                continue
            events.append((ts, key, value, spend))

    series = _build_score_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_keys=top_keys,
    )
    return CostScoreTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        score_key_filter=filter_key or None,
        total_scored_events=scored_events,
        count=len(series),
        series=series,
    )


def _build_rating_timeseries_series(
    events: list[tuple[datetime, str, float, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_labels: int,
) -> list[CostRatingTimeseriesSeries]:
    """Build hour-bucketed series for feedback rating labels (rating:1..5 / no_rating)."""
    label_totals: dict[str, dict[str, float]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, float]]] = {}
    for ts, label, rating_value, spend in events:
        bucket = label_totals.setdefault(label, {"count": 0.0, "sum": 0.0, "spend_cents": 0.0})
        bucket["count"] += 1
        bucket["sum"] += float(rating_value)
        bucket["spend_cents"] += int(spend or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(label, {})
        point = hours.setdefault(hour, {"count": 0.0, "sum": 0.0, "spend_cents": 0.0})
        point["count"] += 1
        point["sum"] += float(rating_value)
        point["spend_cents"] += int(spend or 0)

    ranked = sorted(
        label_totals.items(),
        key=lambda item: (item[1]["count"], item[1]["spend_cents"]),
        reverse=True,
    )[: max(1, min(int(top_labels or 1), 20))]

    series: list[CostRatingTimeseriesSeries] = []
    for label, totals in ranked:
        hours = hour_buckets.get(label) or {}
        cursor = start_hour
        points: list[CostRatingTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"count": 0.0, "sum": 0.0, "spend_cents": 0.0}
            count = float(point["count"])
            points.append(
                CostRatingTimeseriesPoint(
                    hour_start=cursor,
                    avg=round(float(point["sum"]) / count, 4) if count else 0.0,
                    count=int(count),
                    spend_cents=int(point["spend_cents"]),
                )
            )
            cursor += timedelta(hours=1)
        series.append(
            CostRatingTimeseriesSeries(
                rating_label=label,
                count=int(totals["count"]),
                avg=round(float(totals["sum"]) / float(totals["count"]), 4) if totals["count"] else 0.0,
                spend_cents=int(totals["spend_cents"]),
                points=points,
            )
        )
    return series


@router.get("/cost/ratings/timeseries", response_model=CostRatingTimeseriesResponse)
def get_cost_rating_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    rating_filter: Optional[str] = Query(default=None, max_length=32),
    top_labels: int = Query(default=6, ge=1, le=20),
    include_unrated: bool = Query(default=False),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly charts for feedback ratings (1–5) and optional unrated spend."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostRatingTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                rating_filter=str(rating_filter or "").strip() or None,
                total_rated_events=0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(rating_filter or "").strip().lower()
    events: list[tuple[datetime, str, float, int]] = []
    rated_events = 0
    for ts, properties_json, estimated_cost_cents in query.order_by(CostEvent.timestamp.desc()).limit(10_000).all():
        fields = _feedback_fields_from_properties(properties_json)
        rating_value = fields.get("rating")
        if rating_value is None:
            if not include_unrated:
                continue
            label = "no_rating"
            numeric = 0.0
        else:
            try:
                numeric = float(int(rating_value))  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue
            if numeric < 1 or numeric > 5:
                continue
            label = f"rating:{int(numeric)}"
            rated_events += 1
        if filter_text and filter_text not in label.lower():
            continue
        events.append((ts, label, numeric, int(estimated_cost_cents or 0)))

    series = _build_rating_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_labels=top_labels,
    )
    return CostRatingTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        rating_filter=filter_text or None,
        total_rated_events=rated_events,
        count=len(series),
        series=series,
    )


def _latency_ms_from_properties(properties_json: object) -> Optional[int]:
    try:
        parsed = json.loads(properties_json or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(parsed, dict):
        return None
    raw = parsed.get("latency_ms")
    try:
        value = int(raw)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if value < 0 or value > 600_000:
        return None
    return value


def _percentile_ms(values: list[int], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    if len(ordered) == 1:
        return float(ordered[0])
    rank = max(0, min(len(ordered) - 1, int(round((len(ordered) - 1) * percentile))))
    return float(ordered[rank])


def _build_latency_timeseries_series(
    events: list[tuple[datetime, str, int, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_models: int,
) -> list[CostLatencyTimeseriesSeries]:
    """Build hour-bucketed avg/p95 latency series for top models by event count."""
    model_totals: dict[str, dict[str, object]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, object]]] = {}
    for ts, model_name, latency_ms, spend in events:
        bucket = model_totals.setdefault(
            model_name,
            {"latencies": [], "spend_cents": 0, "count": 0},
        )
        latencies = bucket["latencies"]
        assert isinstance(latencies, list)
        latencies.append(int(latency_ms))
        bucket["spend_cents"] = int(bucket["spend_cents"] or 0) + int(spend or 0)
        bucket["count"] = int(bucket["count"] or 0) + 1
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(model_name, {})
        point = hours.setdefault(hour, {"latencies": [], "spend_cents": 0, "count": 0})
        point_latencies = point["latencies"]
        assert isinstance(point_latencies, list)
        point_latencies.append(int(latency_ms))
        point["spend_cents"] = int(point["spend_cents"] or 0) + int(spend or 0)
        point["count"] = int(point["count"] or 0) + 1

    ranked = sorted(
        model_totals.items(),
        key=lambda item: (int(item[1]["count"] or 0), int(item[1]["spend_cents"] or 0)),
        reverse=True,
    )[: max(1, min(int(top_models or 1), 20))]

    series: list[CostLatencyTimeseriesSeries] = []
    for model_name, totals in ranked:
        total_latencies = [int(v) for v in totals["latencies"]]  # type: ignore[index]
        hours = hour_buckets.get(model_name) or {}
        cursor = start_hour
        points: list[CostLatencyTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"latencies": [], "spend_cents": 0, "count": 0}
            point_latencies = [int(v) for v in point["latencies"]]  # type: ignore[index]
            count = int(point["count"] or 0)
            points.append(
                CostLatencyTimeseriesPoint(
                    hour_start=cursor,
                    avg_ms=round(sum(point_latencies) / count, 2) if count else 0.0,
                    p95_ms=_percentile_ms(point_latencies, 0.95),
                    count=count,
                    spend_cents=int(point["spend_cents"] or 0),
                )
            )
            cursor += timedelta(hours=1)
        total_count = int(totals["count"] or 0)
        series.append(
            CostLatencyTimeseriesSeries(
                model_name=model_name,
                avg_ms=round(sum(total_latencies) / total_count, 2) if total_count else 0.0,
                p95_ms=_percentile_ms(total_latencies, 0.95),
                count=total_count,
                spend_cents=int(totals["spend_cents"] or 0),
                points=points,
            )
        )
    return series


@router.get("/cost/latency/timeseries", response_model=CostLatencyTimeseriesResponse)
def get_cost_latency_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    model_filter: Optional[str] = Query(default=None, max_length=128),
    top_models: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly latency charts from cost event `latency_ms` properties."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.model_name,
        CostEvent.properties_json,
        CostEvent.estimated_cost_cents,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostLatencyTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                model_filter=str(model_filter or "").strip() or None,
                total_events=0,
                avg_ms=0.0,
                p95_ms=0.0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(model_filter or "").strip().lower()
    events: list[tuple[datetime, str, int, int]] = []
    all_latencies: list[int] = []
    for ts, model_name, properties_json, estimated_cost_cents in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        latency = _latency_ms_from_properties(properties_json)
        if latency is None:
            continue
        name = str(model_name or "").strip() or "unknown-model"
        if filter_text and filter_text not in name.lower():
            continue
        events.append((ts, name, latency, int(estimated_cost_cents or 0)))
        all_latencies.append(latency)

    series = _build_latency_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_models=top_models,
    )
    total_events = len(all_latencies)
    return CostLatencyTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        model_filter=filter_text or None,
        total_events=total_events,
        avg_ms=round(sum(all_latencies) / total_events, 2) if total_events else 0.0,
        p95_ms=_percentile_ms(all_latencies, 0.95),
        count=len(series),
        series=series,
    )


def _cache_hit_rate(hit_count: int, miss_count: int) -> float:
    total = int(hit_count or 0) + int(miss_count or 0)
    if total <= 0:
        return 0.0
    return round(float(hit_count or 0) / float(total), 4)


def _build_cache_timeseries_series(
    events: list[tuple[datetime, str, bool, int]],
    *,
    start_hour: datetime,
    end_hour: datetime,
    top_models: int,
) -> list[CostCacheTimeseriesSeries]:
    """Build hour-bucketed cache hit-rate series for top models by event count."""
    model_totals: dict[str, dict[str, object]] = {}
    hour_buckets: dict[str, dict[datetime, dict[str, object]]] = {}
    for ts, model_name, is_hit, spend in events:
        bucket = model_totals.setdefault(
            model_name,
            {"hit_count": 0, "miss_count": 0, "spend_cents": 0},
        )
        if is_hit:
            bucket["hit_count"] = int(bucket["hit_count"] or 0) + 1
        else:
            bucket["miss_count"] = int(bucket["miss_count"] or 0) + 1
        bucket["spend_cents"] = int(bucket["spend_cents"] or 0) + int(spend or 0)
        hour = _floor_hour(ts)
        if hour < start_hour or hour > end_hour:
            continue
        hours = hour_buckets.setdefault(model_name, {})
        point = hours.setdefault(hour, {"hit_count": 0, "miss_count": 0, "spend_cents": 0})
        if is_hit:
            point["hit_count"] = int(point["hit_count"] or 0) + 1
        else:
            point["miss_count"] = int(point["miss_count"] or 0) + 1
        point["spend_cents"] = int(point["spend_cents"] or 0) + int(spend or 0)

    ranked = sorted(
        model_totals.items(),
        key=lambda item: (
            int(item[1]["hit_count"] or 0) + int(item[1]["miss_count"] or 0),
            int(item[1]["spend_cents"] or 0),
        ),
        reverse=True,
    )[: max(1, min(int(top_models or 1), 20))]

    series: list[CostCacheTimeseriesSeries] = []
    for model_name, totals in ranked:
        hours = hour_buckets.get(model_name) or {}
        cursor = start_hour
        points: list[CostCacheTimeseriesPoint] = []
        while cursor <= end_hour:
            point = hours.get(cursor) or {"hit_count": 0, "miss_count": 0, "spend_cents": 0}
            hit_count = int(point["hit_count"] or 0)
            miss_count = int(point["miss_count"] or 0)
            points.append(
                CostCacheTimeseriesPoint(
                    hour_start=cursor,
                    hit_count=hit_count,
                    miss_count=miss_count,
                    hit_rate=_cache_hit_rate(hit_count, miss_count),
                    spend_cents=int(point["spend_cents"] or 0),
                )
            )
            cursor += timedelta(hours=1)
        total_hits = int(totals["hit_count"] or 0)
        total_misses = int(totals["miss_count"] or 0)
        series.append(
            CostCacheTimeseriesSeries(
                model_name=model_name,
                hit_count=total_hits,
                miss_count=total_misses,
                hit_rate=_cache_hit_rate(total_hits, total_misses),
                spend_cents=int(totals["spend_cents"] or 0),
                points=points,
            )
        )
    return series


@router.get("/cost/cache/timeseries", response_model=CostCacheTimeseriesResponse)
def get_cost_cache_timeseries(
    window_hours: int = Query(default=24, ge=1, le=24 * 30),
    model_filter: Optional[str] = Query(default=None, max_length=128),
    top_models: int = Query(default=8, ge=1, le=20),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    """Helicone-style hourly cache hit-rate charts from CostEvent.cache_hit."""
    require_role(ctx, ROLES_ADMIN_OWNER)
    bounded_hours = max(1, min(int(window_hours or 24), 24 * 30))
    end_hour = _floor_hour(datetime.utcnow())
    start_hour = end_hour - timedelta(hours=bounded_hours - 1)
    query_end_exclusive = end_hour + timedelta(hours=1)

    query = db.query(
        CostEvent.timestamp,
        CostEvent.model_name,
        CostEvent.cache_hit,
        CostEvent.estimated_cost_cents,
    ).filter(
        CostEvent.timestamp >= start_hour,
        CostEvent.timestamp < query_end_exclusive,
    )
    if ctx.actor_role == ROLE_AGENT_OWNER:
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        if not owned_agent_ids:
            return CostCacheTimeseriesResponse(
                window_hours=bounded_hours,
                start_time=start_hour,
                end_time=end_hour,
                model_filter=str(model_filter or "").strip() or None,
                total_events=0,
                hit_count=0,
                miss_count=0,
                hit_rate=0.0,
                count=0,
                series=[],
            )
        query = query.filter(CostEvent.agent_id.in_(owned_agent_ids))

    filter_text = str(model_filter or "").strip().lower()
    events: list[tuple[datetime, str, bool, int]] = []
    total_hits = 0
    total_misses = 0
    for ts, model_name, cache_hit, estimated_cost_cents in (
        query.order_by(CostEvent.timestamp.desc()).limit(10_000).all()
    ):
        name = str(model_name or "").strip() or "unknown-model"
        if filter_text and filter_text not in name.lower():
            continue
        is_hit = bool(cache_hit)
        if is_hit:
            total_hits += 1
        else:
            total_misses += 1
        events.append((ts, name, is_hit, int(estimated_cost_cents or 0)))

    series = _build_cache_timeseries_series(
        events,
        start_hour=start_hour,
        end_hour=end_hour,
        top_models=top_models,
    )
    return CostCacheTimeseriesResponse(
        window_hours=bounded_hours,
        start_time=start_hour,
        end_time=end_hour,
        model_filter=filter_text or None,
        total_events=total_hits + total_misses,
        hit_count=total_hits,
        miss_count=total_misses,
        hit_rate=_cache_hit_rate(total_hits, total_misses),
        count=len(series),
        series=series,
    )


@router.get("/cost/sessions/{session_id}", response_model=list[CostEventResponse])
def get_session_cost(
    session_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)
    if ctx.actor_role == ROLE_AGENT_OWNER:
        session = db.query(SessionRecord).filter_by(session_id=session_id).first()
        if not session or session.actor_id != ctx.actor_id:
            _cost_scope_forbidden(ctx, "Session scope is forbidden for this actor", "cost-session-scope-forbidden")
    return db.query(CostEvent).filter_by(session_id=session_id).order_by(CostEvent.timestamp.desc()).all()


@router.get("/cost/agents/{agent_id}", response_model=list[CostEventResponse])
def get_agent_cost(
    agent_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)
    if ctx.actor_role == ROLE_AGENT_OWNER:
        agent = db.query(Agent).filter_by(agent_id=agent_id).first()
        if not agent or agent.owner_id != ctx.actor_id:
            _cost_scope_forbidden(ctx, "Agent scope is forbidden for this actor", "cost-agent-scope-forbidden")
    return db.query(CostEvent).filter_by(agent_id=agent_id).order_by(CostEvent.timestamp.desc()).all()


@router.post("/cost/budgets", response_model=BudgetPolicyResponse)
def create_budget_policy(
    payload: BudgetPolicyCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "cost_budget_create_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "scope_type": payload.scope_type, "scope_id": payload.scope_id}),
    )
    require_role(ctx, ROLES_ADMIN_RELEASE_OWNER)
    scope_type, scope_id = normalize_scope_reference(
        db,
        scope_type=payload.scope_type,
        scope_id=payload.scope_id,
        allowed_scope_types=SUPPORTED_BUDGET_SCOPE_TYPES,
        resource_label="budget scope",
    )
    if not _is_budget_scope_manageable(db, ctx, scope_type, scope_id):
        _cost_scope_forbidden(ctx, "Budget scope is forbidden for this actor", "cost-budget-scope-forbidden")
    validated_window = _validate_window_type(payload.window_type)
    budget = BudgetPolicy(
        budget_policy_id=str(uuid4()),
        scope_type=scope_type,
        scope_id=scope_id,
        budget_amount_cents=payload.budget_amount_cents,
        window_type=validated_window,
        soft_limit_percent=payload.soft_limit_percent,
        hard_limit_percent=payload.hard_limit_percent,
        action_on_soft_limit=payload.action_on_soft_limit,
        action_on_hard_limit=payload.action_on_hard_limit,
        reset_timezone=str(payload.reset_timezone or "UTC").strip() or "UTC",
        reset_hour_local=payload.reset_hour_local,
        temporary_increase_cents=payload.temporary_increase_cents,
        temporary_increase_expires_at=payload.temporary_increase_expires_at,
        soft_alert_enabled=payload.soft_alert_enabled,
        rate_limit_tpm=payload.rate_limit_tpm,
        rate_limit_rpm=payload.rate_limit_rpm,
        session_iteration_cap=payload.session_iteration_cap,
        session_budget_cents=payload.session_budget_cents,
        status="active",
    )
    db.add(budget)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.budget.create",
        resource_type="budget_policy",
        resource_id=budget.budget_policy_id,
        trace_id=f"trace-{budget.budget_policy_id}",
    )
    db.commit()
    db.refresh(budget)
    logger.info(
        "cost_budget_create_completed %s",
        sanitize_fields({"actor_id": ctx.actor_id, "budget_policy_id": budget.budget_policy_id}),
    )
    return _serialize_budget_policy(budget, db)


@router.get("/cost/budgets", response_model=list[BudgetPolicyResponse])
def list_budget_policies(
    status: Optional[str] = Query(default="active"),
    scope_type: Optional[str] = None,
    scope_id: Optional[str] = None,
    environment: Optional[str] = Query(default=None, max_length=64),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)

    query = db.query(BudgetPolicy)
    if status is not None and str(status).strip():
        query = query.filter(BudgetPolicy.status == str(status).strip())
    if scope_type:
        query = query.filter(BudgetPolicy.scope_type == str(scope_type).strip())
    if scope_id:
        query = query.filter(BudgetPolicy.scope_id == str(scope_id).strip())

    if ctx.actor_role == ROLE_AGENT_OWNER:
        team_ids = [
            row[0]
            for row in db.query(DirectoryTeamMembership.team_id)
            .filter(DirectoryTeamMembership.user_id == ctx.actor_id)
            .all()
        ]
        group_ids = [
            row[0]
            for row in db.query(DirectoryGroupMembership.group_id)
            .filter(DirectoryGroupMembership.user_id == ctx.actor_id)
            .all()
        ]
        owned_agent_ids = _owned_agent_ids(db, ctx.actor_id)
        query = query.filter(
            (BudgetPolicy.scope_type.in_(["owner", "actor", "user"]) & (BudgetPolicy.scope_id == ctx.actor_id))
            | (BudgetPolicy.scope_type == COST_SCOPE_TEAM)
            & (BudgetPolicy.scope_id.in_(team_ids if team_ids else ["__none__"]))
            | (BudgetPolicy.scope_type == COST_SCOPE_GROUP)
            & (BudgetPolicy.scope_id.in_(group_ids if group_ids else ["__none__"]))
            | (BudgetPolicy.scope_type == "agent")
            & (BudgetPolicy.scope_id.in_(owned_agent_ids if owned_agent_ids else ["__none__"]))
        )

    env = str(environment or "").strip() or None
    return [
        _serialize_budget_policy(row, db, environment=env)
        for row in query.order_by(BudgetPolicy.created_at.desc()).offset(offset).limit(limit).all()
    ]


@router.put("/cost/budgets/{budget_policy_id}", response_model=BudgetPolicyResponse)
def update_budget_policy(
    budget_policy_id: str,
    payload: BudgetPolicyCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_OWNER)

    budget = db.query(BudgetPolicy).filter_by(budget_policy_id=budget_policy_id).first()
    if not budget:
        raise not_found_error("budget_policy", budget_policy_id, decision_trace_id="cost-budget-not-found")
    if not _is_budget_scope_manageable(db, ctx, budget.scope_type, budget.scope_id):
        _cost_scope_forbidden(ctx, "Budget policy is forbidden for this actor", "cost-budget-policy-forbidden")

    scope_type, scope_id = normalize_scope_reference(
        db,
        scope_type=payload.scope_type,
        scope_id=payload.scope_id,
        allowed_scope_types=SUPPORTED_BUDGET_SCOPE_TYPES,
        resource_label="budget scope",
    )

    budget.scope_type = scope_type
    budget.scope_id = scope_id
    if not _is_budget_scope_manageable(db, ctx, budget.scope_type, budget.scope_id):
        _cost_scope_forbidden(ctx, "Target budget scope is forbidden for this actor", "cost-budget-target-scope-forbidden")
    budget.budget_amount_cents = payload.budget_amount_cents
    budget.window_type = _validate_window_type(payload.window_type)
    budget.soft_limit_percent = payload.soft_limit_percent
    budget.hard_limit_percent = payload.hard_limit_percent
    budget.action_on_soft_limit = payload.action_on_soft_limit
    budget.action_on_hard_limit = payload.action_on_hard_limit
    budget.reset_timezone = str(payload.reset_timezone or "UTC").strip() or "UTC"
    budget.reset_hour_local = payload.reset_hour_local
    budget.temporary_increase_cents = payload.temporary_increase_cents
    budget.temporary_increase_expires_at = payload.temporary_increase_expires_at
    budget.soft_alert_enabled = payload.soft_alert_enabled
    budget.rate_limit_tpm = payload.rate_limit_tpm
    budget.rate_limit_rpm = payload.rate_limit_rpm
    budget.session_iteration_cap = payload.session_iteration_cap
    budget.session_budget_cents = payload.session_budget_cents
    if budget.status == "deleted":
        budget.status = "active"

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.budget.update",
        resource_type="budget_policy",
        resource_id=budget.budget_policy_id,
        trace_id=f"trace-{budget.budget_policy_id}",
    )
    db.commit()
    db.refresh(budget)
    return _serialize_budget_policy(budget, db)


@router.delete("/cost/budgets/{budget_policy_id}", response_model=BudgetPolicyResponse)
def delete_budget_policy(
    budget_policy_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_OWNER)

    budget = db.query(BudgetPolicy).filter_by(budget_policy_id=budget_policy_id).first()
    if not budget:
        raise not_found_error("budget_policy", budget_policy_id, decision_trace_id="cost-budget-not-found")

    if not _is_budget_scope_manageable(db, ctx, budget.scope_type, budget.scope_id):
        _cost_scope_forbidden(ctx, "Budget policy is forbidden for this actor", "cost-budget-policy-forbidden")

    budget.status = "deleted"
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.budget.delete",
        resource_type="budget_policy",
        resource_id=budget.budget_policy_id,
        trace_id=f"trace-{budget.budget_policy_id}",
    )
    db.commit()
    db.refresh(budget)
    return _serialize_budget_policy(budget, db)


@router.post("/cost/budgets/{budget_policy_id}/increase-temporary", response_model=BudgetPolicyResponse)
def increase_budget_policy_temporary(
    budget_policy_id: str,
    payload: BudgetPolicyTemporaryIncreaseRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_OWNER)
    budget = db.query(BudgetPolicy).filter_by(budget_policy_id=budget_policy_id).first()
    if not budget or budget.status == "deleted":
        raise not_found_error("budget_policy", budget_policy_id, decision_trace_id="cost-budget-not-found")
    if not _is_budget_scope_manageable(db, ctx, budget.scope_type, budget.scope_id):
        _cost_scope_forbidden(ctx, "Budget policy is forbidden for this actor", "cost-budget-temp-increase-forbidden")

    now = datetime.utcnow()
    budget.temporary_increase_cents = int(payload.increase_cents)
    budget.temporary_increase_expires_at = now + timedelta(minutes=int(payload.duration_minutes))
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.budget.increase_temporary",
        resource_type="budget_policy",
        resource_id=budget.budget_policy_id,
        trace_id=f"trace-{budget.budget_policy_id}",
        decision_outcome="allow",
        action_context={
            "increase_cents": payload.increase_cents,
            "duration_minutes": payload.duration_minutes,
            "reason": str(payload.reason or "").strip() or None,
            "expires_at": budget.temporary_increase_expires_at.isoformat() + "Z",
        },
    )
    db.commit()
    db.refresh(budget)
    return _serialize_budget_policy(budget, db)


@router.post("/cost/budgets/{budget_policy_id}/increase-temporary/clear", response_model=BudgetPolicyResponse)
def clear_budget_policy_temporary_increase(
    budget_policy_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_OWNER)
    budget = db.query(BudgetPolicy).filter_by(budget_policy_id=budget_policy_id).first()
    if not budget or budget.status == "deleted":
        raise not_found_error("budget_policy", budget_policy_id, decision_trace_id="cost-budget-not-found")
    if not _is_budget_scope_manageable(db, ctx, budget.scope_type, budget.scope_id):
        _cost_scope_forbidden(ctx, "Budget policy is forbidden for this actor", "cost-budget-temp-clear-forbidden")

    budget.temporary_increase_cents = 0
    budget.temporary_increase_expires_at = None
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.budget.clear_temporary_increase",
        resource_type="budget_policy",
        resource_id=budget.budget_policy_id,
        trace_id=f"trace-{budget.budget_policy_id}",
        decision_outcome="allow",
    )
    db.commit()
    db.refresh(budget)
    return _serialize_budget_policy(budget, db)


@router.post("/cost/budgets/{budget_policy_id}/soft-alert/acknowledge", response_model=BudgetPolicyResponse)
def acknowledge_budget_soft_alert(
    budget_policy_id: str,
    payload: Optional[BudgetPolicySoftAlertAcknowledgeRequest] = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_OWNER)
    budget = db.query(BudgetPolicy).filter_by(budget_policy_id=budget_policy_id).first()
    if not budget or budget.status == "deleted":
        raise not_found_error("budget_policy", budget_policy_id, decision_trace_id="cost-budget-not-found")
    if not _is_budget_scope_manageable(db, ctx, budget.scope_type, budget.scope_id):
        _cost_scope_forbidden(ctx, "Budget policy is forbidden for this actor", "cost-budget-soft-ack-forbidden")

    now = datetime.utcnow()
    budget.last_soft_alert_at = now
    reason = str((payload.reason if payload else None) or "").strip() or None
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.budget.soft_alert_acknowledge",
        resource_type="budget_policy",
        resource_id=budget.budget_policy_id,
        trace_id=f"trace-{budget.budget_policy_id}",
        decision_outcome="allow",
        action_context={"reason": reason},
    )
    db.commit()
    db.refresh(budget)
    return _serialize_budget_policy(budget, db)


@router.post("/cost/policies/evaluate", response_model=CostPolicyEvaluateResponse)
def evaluate_budget_policy(
    payload: CostPolicyEvaluateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "cost_policy_evaluate_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "scope_type": payload.scope_type, "scope_id": payload.scope_id}),
    )
    require_role(ctx, ROLES_ADMIN_RELEASE_OWNER)
    scope_type, scope_id = normalize_scope_reference(
        db,
        scope_type=payload.scope_type,
        scope_id=payload.scope_id,
        allowed_scope_types=SUPPORTED_BUDGET_SCOPE_TYPES,
        resource_label="budget scope",
    )
    env = str(payload.environment or "").strip() or None

    budget = find_active_budget(db, scope_type, scope_id)
    if not budget:
        logger.error(
            "cost_policy_evaluate_budget_not_found %s",
            sanitize_fields({"scope_type": scope_type, "scope_id": scope_id}),
        )
        raise not_found_error("budget_policy", scope_id, decision_trace_id="cost-active-budget-not-found")

    if not _is_budget_scope_manageable(db, ctx, scope_type, scope_id):
        _cost_scope_forbidden(ctx, "Budget scope is forbidden for this actor", "cost-budget-scope-forbidden")

    resolved_window = _validate_window_type(payload.window_type or budget.window_type)
    now = datetime.utcnow()
    after_ts = window_start_for_budget(budget, resolved_window, now_utc=now)
    hours_after = now - timedelta(hours=24)

    spend_cents = sum_scope_cost_cents(
        db, scope_type=scope_type, scope_id=scope_id, after_ts=after_ts, environment=env
    )
    hours_spend_cents = sum_scope_cost_cents(
        db, scope_type=scope_type, scope_id=scope_id, after_ts=hours_after, environment=env
    )
    owner_scopes = rollup_owner_scopes_for_scope(db, scope_type, scope_id)
    owner_scope = owner_scopes[0] if owner_scopes else f"{scope_type}:{scope_id}"
    projection = project_window_spend(
        db,
        owner_scope=owner_scope,
        budget=budget,
        window_type=resolved_window,
        current_spend_cents=spend_cents,
        now_utc=now,
        owner_scopes=owner_scopes,
    )

    effective_budget_cents = _effective_budget_cents(budget)
    utilization = 0.0
    if effective_budget_cents > 0:
        utilization = round((spend_cents / effective_budget_cents) * 100.0, 2)
    projected_utilization = 0.0
    if effective_budget_cents > 0:
        projected_utilization = round(
            (projection.projected_window_spend_cents / effective_budget_cents) * 100.0, 2
        )

    if utilization >= float(budget.hard_limit_percent):
        decision = "deny"
        action = budget.action_on_hard_limit
        preemptive_throttle = False
    elif projected_utilization >= float(budget.hard_limit_percent):
        decision = "warn"
        action = "preemptive_throttle"
        preemptive_throttle = True
    elif utilization >= float(budget.soft_limit_percent):
        decision = "warn"
        action = budget.action_on_soft_limit
        preemptive_throttle = False
    else:
        decision = "allow"
        action = "none"
        preemptive_throttle = False

    soft_limit_alert = bool(budget.soft_alert_enabled) and decision == "warn"
    if decision == "warn" and not bool(budget.soft_alert_enabled) and not preemptive_throttle:
        action = "none"
    if soft_limit_alert and budget.last_soft_alert_at is None:
        budget.last_soft_alert_at = now

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.policy.evaluate",
        resource_type="budget_policy",
        resource_id=budget.budget_policy_id,
        trace_id=f"trace-{budget.budget_policy_id}",
        decision_outcome=decision,
        action_context={"environment": env, "resolved_budget_scope_type": budget.scope_type},
    )
    db.commit()
    logger.info(
        "cost_policy_evaluate_completed %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "scope_type": scope_type,
                "scope_id": scope_id,
                "decision": decision,
                "environment": env,
            }
        ),
    )

    return {
        "scope_type": scope_type,
        "scope_id": scope_id,
        "window_type": resolved_window,
        "environment": env,
        "budget_policy_id": budget.budget_policy_id,
        "resolved_budget_scope_type": str(budget.scope_type),
        "spend_cents": spend_cents,
        "hours_spend_cents": hours_spend_cents,
        "budget_cents": budget.budget_amount_cents,
        "effective_budget_cents": effective_budget_cents,
        "utilization_percent": utilization,
        "projected_window_spend_cents": projection.projected_window_spend_cents,
        "projected_utilization_percent": projected_utilization,
        "historical_window_spend_cents": projection.historical_window_spend_cents,
        "projection_basis": projection.projection_basis,
        "prior_periods_considered": projection.prior_periods_considered,
        "projected_24h_spend_cents": projection.projected_window_spend_cents,
        "decision": decision,
        "recommended_action": action,
        "preemptive_throttle": preemptive_throttle,
        "soft_limit_alert": soft_limit_alert,
    }


@router.get("/cost/anomalies", response_model=list[CostAnomalyResponse])
def list_cost_anomalies(
    environment: Optional[str] = Query(default=None, max_length=64),
    severity: Optional[str] = Query(default=None, max_length=32),
    scope_type: Optional[str] = Query(default=None, max_length=32),
    min_utilization: Optional[float] = Query(default=None, ge=0, le=1000),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_OWNER)
    anomalies: list[dict] = []
    now = datetime.utcnow()
    env = str(environment or "").strip() or None
    severity_filter = str(severity or "").strip().lower() or None
    scope_type_filter = str(scope_type or "").strip().lower() or None
    min_util = float(min_utilization) if min_utilization is not None else None

    budgets = db.query(BudgetPolicy).filter_by(status="active").all()
    for budget in budgets:
        if ctx.actor_role == ROLE_AGENT_OWNER:
            owns_self = budget.scope_type in {"owner", "actor", "user"} and budget.scope_id == ctx.actor_id
            owns_team = budget.scope_type == COST_SCOPE_TEAM and (
                db.query(DirectoryTeamMembership)
                .filter_by(team_id=budget.scope_id, user_id=ctx.actor_id)
                .first()
                is not None
            )
            owns_group = budget.scope_type == COST_SCOPE_GROUP and (
                db.query(DirectoryGroupMembership)
                .filter_by(group_id=budget.scope_id, user_id=ctx.actor_id)
                .first()
                is not None
            )
            if not (owns_self or owns_team or owns_group):
                continue
        if scope_type_filter and str(budget.scope_type).lower() != scope_type_filter:
            if not (
                scope_type_filter == "user"
                and str(budget.scope_type).lower() in {"user", "actor", "owner"}
            ):
                continue
        spend_cents = sum_scope_cost_cents(
            db,
            scope_type=str(budget.scope_type),
            scope_id=str(budget.scope_id),
            after_ts=window_start_for_budget(budget, budget.window_type),
            environment=env,
        )
        hours_spend_cents = sum_scope_cost_cents(
            db,
            scope_type=str(budget.scope_type),
            scope_id=str(budget.scope_id),
            after_ts=now - timedelta(hours=24),
            environment=env,
        )
        effective_budget_cents = _effective_budget_cents(budget)
        soft_threshold = int((effective_budget_cents * budget.soft_limit_percent) / 100)
        hard_threshold = int((effective_budget_cents * budget.hard_limit_percent) / 100)
        soft_enabled = bool(getattr(budget, "soft_alert_enabled", True))
        window_start = window_start_for_budget(budget, budget.window_type, now_utc=now)
        soft_acked_this_window = bool(
            getattr(budget, "last_soft_alert_at", None)
            and budget.last_soft_alert_at >= window_start
        )

        def _anomaly_type(kind: str) -> str:
            if budget.scope_type == COST_SCOPE_TEAM:
                return f"team_{kind}_budget_alert"
            if budget.scope_type == COST_SCOPE_GROUP:
                return f"group_{kind}_budget_alert"
            if budget.scope_type == COST_SCOPE_USER or budget.scope_type in {"actor", "owner"}:
                return f"user_{kind}_budget_alert"
            if budget.scope_type == "agent":
                return f"agent_{kind}_budget_alert"
            return f"budget_{kind}_threshold_breach"

        if spend_cents >= hard_threshold and effective_budget_cents > 0:
            utilization = round((spend_cents / effective_budget_cents) * 100.0, 2) if effective_budget_cents else 0.0
            anomalies.append(
                {
                    "anomaly_id": f"{budget.budget_policy_id}:hard",
                    "anomaly_type": _anomaly_type("hard"),
                    "severity": "critical",
                    "scope_type": budget.scope_type,
                    "scope_id": budget.scope_id,
                    "observed_cost_cents": spend_cents,
                    "threshold_cents": hard_threshold,
                    "detected_at": now,
                    "budget_policy_id": budget.budget_policy_id,
                    "effective_budget_cents": effective_budget_cents,
                    "utilization_percent": utilization,
                    "recommended_action": budget.action_on_hard_limit,
                    "window_type": budget.window_type,
                    "soft_limit_percent": float(budget.soft_limit_percent),
                    "hard_limit_percent": float(budget.hard_limit_percent),
                    "hours_spend_cents": hours_spend_cents,
                    "decision": "deny",
                }
            )
        elif (
            soft_enabled
            and not soft_acked_this_window
            and spend_cents >= soft_threshold
            and effective_budget_cents > 0
        ):
            utilization = round((spend_cents / effective_budget_cents) * 100.0, 2) if effective_budget_cents else 0.0
            anomalies.append(
                {
                    "anomaly_id": f"{budget.budget_policy_id}:soft",
                    "anomaly_type": _anomaly_type("soft"),
                    "severity": "high" if spend_cents >= effective_budget_cents else "medium",
                    "scope_type": budget.scope_type,
                    "scope_id": budget.scope_id,
                    "observed_cost_cents": spend_cents,
                    "threshold_cents": soft_threshold,
                    "detected_at": now,
                    "budget_policy_id": budget.budget_policy_id,
                    "effective_budget_cents": effective_budget_cents,
                    "utilization_percent": utilization,
                    "recommended_action": budget.action_on_soft_limit,
                    "window_type": budget.window_type,
                    "soft_limit_percent": float(budget.soft_limit_percent),
                    "hard_limit_percent": float(budget.hard_limit_percent),
                    "hours_spend_cents": hours_spend_cents,
                    "decision": "warn",
                }
            )

    if severity_filter:
        anomalies = [row for row in anomalies if str(row.get("severity") or "").lower() == severity_filter]
    if min_util is not None:
        anomalies = [row for row in anomalies if float(row.get("utilization_percent") or 0) >= min_util]

    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    anomalies.sort(
        key=lambda row: (
            severity_rank.get(str(row.get("severity") or "").lower(), 9),
            -float(row.get("utilization_percent") or 0),
            str(row.get("scope_type") or ""),
            str(row.get("scope_id") or ""),
        )
    )
    return anomalies


@router.get("/cost/hierarchy", response_model=CostHierarchyResponse)
def get_cost_hierarchy(
    window_hours: int = 24,
    actor_id: Optional[str] = None,
    include_members: bool = True,
    top_members: int = 5,
    window_mode: str = Query(default="hours", pattern="^(hours|budget)$"),
    environment: Optional[str] = Query(default=None, max_length=64),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_OWNER)
    target_actor_id = str(actor_id or ctx.actor_id or "").strip()
    if not target_actor_id:
        raise api_validation_error("actor_id cannot be empty", decision_trace_id="cost-hierarchy-actor-empty")
    if ctx.actor_role == ROLE_AGENT_OWNER and target_actor_id != ctx.actor_id:
        _cost_scope_forbidden(ctx, "Hierarchy actor is forbidden for this actor", "cost-hierarchy-actor-forbidden")

    payload = build_actor_cost_hierarchy(
        db,
        actor_id=target_actor_id,
        window_hours=window_hours,
        include_members=include_members,
        top_members=top_members,
        window_mode=window_mode,
        environment=environment,
    )

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.hierarchy.read",
        resource_type="cost_hierarchy",
        resource_id=target_actor_id,
        trace_id=f"trace-cost-hierarchy-{target_actor_id}",
        decision_outcome="allow",
        action_context={
            "window_hours": payload["window_hours"],
            "window_mode": payload.get("window_mode"),
            "environment": payload.get("environment"),
            "team_count": len(payload.get("teams") or []),
            "group_count": len(payload.get("groups") or []),
            "include_members": bool(include_members),
            "soft_alert_scopes": payload.get("soft_alert_scopes") or [],
            "blocking_scopes": payload.get("blocking_scopes") or [],
        },
    )
    db.commit()
    return payload


@router.get("/cost/hierarchy/alerts", response_model=CostHierarchyAlertsResponse)
def get_cost_hierarchy_alerts(
    window_hours: int = 24,
    actor_id: Optional[str] = None,
    window_mode: str = Query(default="budget", pattern="^(hours|budget)$"),
    environment: Optional[str] = Query(default=None, max_length=64),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_OWNER)
    target_actor_id = str(actor_id or ctx.actor_id or "").strip()
    if not target_actor_id:
        raise api_validation_error("actor_id cannot be empty", decision_trace_id="cost-hierarchy-alerts-actor-empty")
    if ctx.actor_role == ROLE_AGENT_OWNER and target_actor_id != ctx.actor_id:
        _cost_scope_forbidden(ctx, "Hierarchy actor is forbidden for this actor", "cost-hierarchy-alerts-forbidden")

    hierarchy = build_actor_cost_hierarchy(
        db,
        actor_id=target_actor_id,
        window_hours=window_hours,
        include_members=False,
        top_members=1,
        window_mode=window_mode,
        environment=environment,
    )
    alerts: list[dict] = []
    if hierarchy.get("user_budget") and hierarchy["user_budget"].get("decision") in {"warn", "deny"}:
        ub = hierarchy["user_budget"]
        decision = ub["decision"]
        alerts.append(
            {
                "scope_type": COST_SCOPE_USER,
                "scope_id": target_actor_id,
                "decision": decision,
                "severity": "critical" if decision == "deny" else "high",
                "spend_cents": hierarchy["user_spend_cents"],
                "hours_spend_cents": hierarchy.get("user_hours_spend_cents"),
                "utilization_percent": ub.get("utilization_percent"),
                "effective_budget_cents": ub.get("effective_budget_cents"),
                "budget_policy_id": ub.get("budget_policy_id"),
                "recommended_action": ub.get("recommended_action"),
                "window_type": ub.get("window_type"),
            }
        )
    for item in [*(hierarchy.get("teams") or []), *(hierarchy.get("groups") or [])]:
        if item.get("decision") not in {"warn", "deny"}:
            continue
        decision = item["decision"]
        alerts.append(
            {
                "scope_type": item["scope_type"],
                "scope_id": item["scope_id"],
                "decision": decision,
                "severity": "critical" if decision == "deny" else "high",
                "spend_cents": item.get("spend_cents") or 0,
                "hours_spend_cents": item.get("hours_spend_cents"),
                "utilization_percent": item.get("utilization_percent"),
                "effective_budget_cents": item.get("effective_budget_cents"),
                "budget_policy_id": item.get("budget_policy_id"),
                "recommended_action": item.get("recommended_action"),
                "window_type": item.get("window_type"),
            }
        )
    alerts.sort(
        key=lambda row: (
            0 if row.get("decision") == "deny" else 1,
            -float(row.get("utilization_percent") or 0),
            str(row.get("scope_type") or ""),
            str(row.get("scope_id") or ""),
        )
    )

    soft_alert_scopes = list(hierarchy.get("soft_alert_scopes") or [])
    blocking_scopes = list(hierarchy.get("blocking_scopes") or [])
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.hierarchy.alerts",
        resource_type="cost_hierarchy",
        resource_id=target_actor_id,
        trace_id=f"trace-cost-hierarchy-alerts-{target_actor_id}",
        decision_outcome="allow",
        action_context={
            "soft_alert_count": len(soft_alert_scopes),
            "blocking_count": len(blocking_scopes),
            "window_mode": hierarchy.get("window_mode"),
            "environment": hierarchy.get("environment"),
        },
    )
    db.commit()
    return {
        "actor_id": target_actor_id,
        "window_hours": hierarchy["window_hours"],
        "window_mode": hierarchy.get("window_mode") or window_mode,
        "environment": hierarchy.get("environment"),
        "soft_alert_count": len(soft_alert_scopes),
        "blocking_count": len(blocking_scopes),
        "soft_alert_scopes": soft_alert_scopes,
        "blocking_scopes": blocking_scopes,
        "alerts": alerts,
    }


@router.get("/cost/hierarchy/explain", response_model=CostHierarchyExplainResponse)
def get_cost_hierarchy_explain(
    scope_type: str,
    scope_id: str,
    window_hours: int = 24,
    top_members: int = 10,
    window_mode: str = Query(default="hours", pattern="^(hours|budget)$"),
    environment: Optional[str] = Query(default=None, max_length=64),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_OWNER)
    normalized_type, normalized_id = normalize_scope_reference(
        db,
        scope_type=scope_type,
        scope_id=scope_id,
        allowed_scope_types={COST_SCOPE_USER, COST_SCOPE_TEAM, COST_SCOPE_GROUP, "actor", "owner"},
        resource_label="hierarchy explain scope",
    )
    if not _is_budget_scope_manageable(db, ctx, normalized_type, normalized_id):
        _cost_scope_forbidden(ctx, "Hierarchy explain scope is forbidden for this actor", "cost-hierarchy-explain-forbidden")

    explanation = explain_cost_hierarchy_scope(
        db,
        scope_type=normalized_type,
        scope_id=normalized_id,
        window_hours=window_hours,
        top_members=top_members,
        window_mode=window_mode,
        environment=environment,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.hierarchy.explain",
        resource_type="cost_hierarchy",
        resource_id=f"{normalized_type}:{normalized_id}",
        trace_id=f"trace-cost-hierarchy-explain-{normalized_type}-{normalized_id}",
        decision_outcome=str(explanation.get("decision") or "allow"),
        action_context={
            "window_hours": explanation.get("window_hours"),
            "window_mode": explanation.get("window_mode"),
            "environment": explanation.get("environment"),
            "reasons": explanation.get("reasons"),
        },
    )
    db.commit()
    return explanation


@router.post("/cost/limits/evaluate", response_model=CostLimitEvaluateResponse)
def evaluate_cost_limits(
    payload: CostLimitEvaluateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, ROLES_ADMIN_RELEASE_OWNER)

    actor_id = (payload.actor_id or ctx.actor_id).strip()
    if not actor_id:
        raise api_validation_error("actor_id cannot be empty", decision_trace_id="cost-limit-eval-actor-empty")

    team_ids = normalize_scope_id_list(db, scope_type=COST_SCOPE_TEAM, scope_ids=payload.team_ids)
    group_ids = normalize_scope_id_list(db, scope_type=COST_SCOPE_GROUP, scope_ids=payload.group_ids)
    if not team_ids or not group_ids:
        directory_teams, directory_groups = resolve_actor_directory_scopes(db, actor_id)
        if not team_ids:
            team_ids = normalize_scope_id_list(db, scope_type=COST_SCOPE_TEAM, scope_ids=directory_teams)
        if not group_ids:
            group_ids = normalize_scope_id_list(db, scope_type=COST_SCOPE_GROUP, scope_ids=directory_groups)

    for team_id in team_ids:
        _ensure_default_jwt_team_budget(db, team_id, ctx.actor_id)

    agent_ids = normalize_scope_id_list(db, scope_type=COST_SCOPE_AGENT, scope_ids=payload.agent_ids)

    evaluation = evaluate_actor_cost_limits(
        db,
        actor_id=actor_id,
        team_ids=team_ids,
        group_ids=group_ids,
        agent_ids=agent_ids,
        window_type=payload.window_type,
        projected_additional_cost_cents=payload.projected_additional_cost_cents,
        auto_resolve_directory_memberships=False,
        environment=str(payload.environment or "").strip() or None,
    )

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="cost.limit.evaluate",
        resource_type="cost_limit",
        resource_id=actor_id,
        trace_id=f"trace-cost-limit-{actor_id}",
        decision_outcome=evaluation.aggregated_decision,
        action_context={"environment": str(payload.environment or "").strip() or None},
    )
    db.commit()

    return {
        "actor_id": actor_id,
        "window_type": payload.window_type,
        "environment": str(payload.environment or "").strip() or None,
        "scopes_evaluated": evaluation.to_dict()["scopes_evaluated"],
        "aggregated_decision": evaluation.aggregated_decision,
        "blocking_scopes": evaluation.blocking_scopes,
        "soft_alert_scopes": evaluation.to_dict()["soft_alert_scopes"],
    }
