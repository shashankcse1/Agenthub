from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import urlparse
from uuid import uuid4

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import and_, func
from sqlalchemy.orm import Session

from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import (
    AgentConfig,
    AuditEvent,
    CacheDecisionEvent,
    CachePolicy,
    GatewayAssistantRecord,
    GatewayResponseCacheEntry,
    CostEvent,
    GatewayAccessReviewCampaign,
    GatewayAccessReviewItem,
    GatewayEntitlement,
    GatewayJitAccessRequest,
    GatewayLeastPrivilegeRecommendation,
    GatewayNhiInventory,
    OpenAIBatchRecord,
    OpenAIFileRecord,
    OpenAIResponseRecord,
    GatewayFineTuningJobRecord,
    RealtimeSessionEventRecord,
    RealtimeSessionRecord,
    RouteMirrorExperimentEvent,
    RoutePolicy,
    RuntimeConfig,
    SecretProviderConfig,
    TenantCatalogEntry,
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
    RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN,
    RUNTIME_CONFIG_GATEWAY_DEFAULT_GLOBAL_TIMEOUT_MS,
    RUNTIME_CONFIG_GATEWAY_DEFAULT_MAX_FALLBACK_HOPS,
    RUNTIME_CONFIG_GATEWAY_EXTERNAL_CALLBACKS_JSON,
    RUNTIME_CONFIG_GATEWAY_SYSTEM_INSTRUCTIONS,
    RUNTIME_CONFIG_GATEWAY_SYSTEM_RULES_JSON,
    RUNTIME_CONFIG_GATEWAY_TUNNEL_BASE_URL,
    RUNTIME_CONFIG_GATEWAY_TUNNEL_ENABLED,
)
from app.schemas import (
    CachePolicyRequest,
    CachePolicyResponse,
    GatewayCacheDecisionEventResponse,
    GatewayResponseCacheEntryResponse,
    GatewayAuthzExplainRequest,
    GatewayAuthzExplainResponse,
    GatewayDecisionTraceResponse,
    GatewayOpenAIChatCompletionsRequest,
    GatewayOpenAIChatCompletionsResponse,
    GatewayOpenAIEmbeddingsRequest,
    GatewayOpenAIEmbeddingsResponse,
    GatewaySystemInstructionsResponse,
    GatewaySystemInstructionsUpdateRequest,
    GatewayCursorSecretBindingResponse,
    GatewayCursorSecretBindingUpdateRequest,
    GatewayCursorTokenResponse,
    GatewayCursorTokenUpdateRequest,
    GatewaySystemRulesResponse,
    GatewaySystemRulesUpdateRequest,
    GatewayOpenAIRerankRequest,
    GatewayOpenAIRerankResponse,
    GatewayOpenAIImagesRequest,
    GatewayOpenAIImagesResponse,
    GatewayOpenAIAudioTranscriptionRequest,
    GatewayOpenAIAudioTranslationRequest,
    GatewayOpenAIAudioResponse,
    GatewayOpenAIRealtimeRequest,
    GatewayOpenAIRealtimeResponse,
    GatewayOpenAIRealtimeSessionCloseResponse,
    GatewayOpenAIRealtimeSessionEventCreateRequest,
    GatewayOpenAIRealtimeSessionEventListResponse,
    GatewayOpenAIRealtimeSessionEventResponse,
    GatewayOpenAIRealtimeSessionListResponse,
    GatewayOpenAIRealtimeSessionResponse,
    GatewayOpenAIMessagesRequest,
    GatewayOpenAIMessagesResponse,
    GatewayOpenAIA2AMessageRequest,
    GatewayOpenAIA2AMessageResponse,
    GatewayOpenAIResponsesRequest,
    GatewayOpenAIResponsesListResponse,
    GatewayOpenAIResponsesDeleteResponse,
    GatewayOpenAIResponsesResponse,
    GatewayOpenAIBatchCreateRequest,
    GatewayOpenAIBatchDeleteResponse,
    GatewayOpenAIBatchResponse,
    GatewayOpenAIBatchesListResponse,
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
    GatewayTunnelConfigResponse,
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
    RouteCanaryRolloutActionRequest,
    RouteCanaryRolloutRequest,
    RouteCanaryRolloutResponse,
    RouteProviderHealthUpdateRequest,
    RouteProviderHealthResponse,
    RoutePreCallFiltersRequest,
    RoutePreCallFiltersResponse,
    RouteInputDataPolicyRequest,
    RouteInputDataPolicyResponse,
    RouteOutputGuardrailsRequest,
    RouteOutputGuardrailsResponse,
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
    GatewayAssistantCreateRequest,
    GatewayAssistantResponse,
    GatewayAssistantListResponse,
    GatewayAssistantDeleteResponse,
    GatewayThreadCreateRequest,
    GatewayThreadResponse,
    GatewayThreadMessageCreateRequest,
    GatewayThreadMessageResponse,
    GatewayThreadMessageListResponse,
    GatewayThreadRunCreateRequest,
    GatewayThreadRunResponse,
    GatewayFineTuningJobCreateRequest,
    GatewayFineTuningJobResponse,
    GatewayFineTuningJobListResponse,
    GatewayFineTuningJobCancelResponse,
    GatewayPassthroughRequest,
    GatewayPassthroughResponse,
)
from app.security import ActorContext, get_actor_context, require_dual_approval, require_role, resolve_actor_role_for_actor
from app.policy_constants import (
    COST_SCOPE_ACTOR,
    COST_SCOPE_AGENT,
    COST_SCOPE_GROUP,
    COST_SCOPE_OWNER,
    COST_SCOPE_TEAM,
    COST_SCOPE_USER,
    DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT,
    ROLE_AGENT_OWNER,
    ROLE_MASTER_ADMIN,
    ROLE_PLATFORM_ADMIN,
    ROLE_SECURITY_APPROVER,
    ROLE_SUPER_ADMIN,
    SUPPORTED_ACTOR_ROLES,
)
from app.services.audit import create_audit_event, push_audit_action_context
from app.services.audit_action_catalog import resolve_action_description
from app.services.credential_resolution import resolve_agent_config_credential
from app.services.gateway_assistants import (
    create_assistant,
    create_and_execute_thread_run,
    iter_thread_run_sse_chunks,
    create_thread,
    create_thread_message,
    delete_assistant,
    get_assistant,
    get_thread,
    get_thread_run,
    list_assistants,
    list_thread_messages,
)
from app.services.gateway_fine_tuning import (
    cancel_fine_tuning_job,
    create_fine_tuning_job,
    get_fine_tuning_job,
    list_fine_tuning_jobs,
)
from app.services.gateway_passthrough import execute_passthrough
from app.services.gateway_inference import (
    ResolvedInferenceCredential,
    _provider_env_api_key,
    execute_chat_completion,
    execute_responses_create,
    infer_provider_type_from_model,
    inference_simulation_enabled,
    invoke_anthropic_messages,
    invoke_embeddings,
    invoke_image_generation,
    invoke_rerank,
    invoke_responses_create,
    resolve_inference_credential,
    should_attempt_upstream,
    stream_chat_completion,
)
from app.services.gateway_memory import maybe_capture_response_session_memory
from app.services.gateway_response_cache import (
    cache_entry_stats,
    evaluate_pre_inference_cache,
    finalize_post_inference_cache,
    purge_cache_entries,
)
from app.services.provider_crypto import decrypt_value, encrypt_value
from app.services.secret_crypto import SecretCryptoError, decrypt_sensitive_value, encrypt_sensitive_value
from app.services.secret_provider_values import (
    GATEWAY_CURSOR_DEFAULT_SECRET_REF,
    is_db_secret_provider,
    normalize_db_provider_defaults,
    read_db_secret_provider_value,
    upsert_db_secret_provider_value,
)
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

ALLOWED_EXTERNAL_CALLBACK_SINK_TYPES = {
    "generic_webhook",
    "siem",
    "pagerduty",
    "slack",
}

ALLOWED_EXTERNAL_CALLBACK_CORRELATION_PRESETS = {
    "none",
    "trace_resource",
    "tenant_environment",
    "incident_minimal",
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
    "gateway.embeddings.create",
    "gateway.responses.create",
    "gateway.responses.retrieve",
    "gateway.responses.list",
    "gateway.responses.delete",
    "gateway.files.create",
    "gateway.files.retrieve",
    "gateway.files.list",
    "gateway.files.delete",
    "gateway.route.input_data_policy.update",
    "gateway.route.input_data_policy.enforce",
    "gateway.route.output_guardrails.update",
    "gateway.route.output_guardrails.enforce",
]

GATEWAY_SYSTEM_RULE_SCOPE_GLOBAL = "global"
ALLOWED_GATEWAY_SYSTEM_RULE_SCOPE_TYPES = {
    GATEWAY_SYSTEM_RULE_SCOPE_GLOBAL,
    COST_SCOPE_USER,
    COST_SCOPE_TEAM,
    COST_SCOPE_GROUP,
    COST_SCOPE_OWNER,
    COST_SCOPE_ACTOR,
    COST_SCOPE_AGENT,
}

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
    "gateway.assistants.delete": set(GATEWAY_INFERENCE_DELETE_ROLES),
    "gateway.fine_tuning.cancel": set(GATEWAY_INFERENCE_DELETE_ROLES),
    "gateway.passthrough.execute": set(GATEWAY_INFERENCE_ROLES),
}

GATEWAY_AUTHZ_PROD_DUAL_APPROVAL_ACTIONS = {
    "gateway.route.update",
    "gateway.route.execute_fallback",
    "gateway.route.optimize",
    "gateway.key.rotate",
    "gateway.callback.update",
    "gateway.cache.invalidate",
    "gateway.tool.call",
    "gateway.assistants.delete",
    "gateway.fine_tuning.cancel",
    "gateway.passthrough.execute",
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


def _normalize_callback_sink_type(raw: object) -> str:
    sink_type = str(raw or "generic_webhook").strip().lower() or "generic_webhook"
    if sink_type not in ALLOWED_EXTERNAL_CALLBACK_SINK_TYPES:
        allowed = ", ".join(sorted(ALLOWED_EXTERNAL_CALLBACK_SINK_TYPES))
        raise HTTPException(status_code=422, detail=f"sink_type must be one of: {allowed}")
    return sink_type


def _normalize_callback_correlation_preset(raw: object) -> str:
    preset = str(raw or "trace_resource").strip().lower() or "trace_resource"
    if preset not in ALLOWED_EXTERNAL_CALLBACK_CORRELATION_PRESETS:
        allowed = ", ".join(sorted(ALLOWED_EXTERNAL_CALLBACK_CORRELATION_PRESETS))
        raise HTTPException(status_code=422, detail=f"correlation_preset must be one of: {allowed}")
    return preset


def _normalize_sink_route_key(raw: object) -> str | None:
    value = str(raw or "").strip()
    return value[:128] if value else None


def _build_callback_correlation_context(
    sample: dict[str, object],
    *,
    callback_id: str,
    sink_type: str,
    sink_route_key: str | None,
    correlation_preset: str,
    trace_id: str,
    environment: str,
) -> dict[str, object]:
    base = {
        "callback_id": callback_id,
        "sink_type": sink_type,
        "sink_route_key": sink_route_key,
        "environment": environment,
        "correlation_preset": correlation_preset,
        "trace_id": str(sample.get("trace_id") or trace_id),
    }
    if correlation_preset == "none":
        return base
    if correlation_preset == "tenant_environment":
        base["tenant_id"] = str(sample.get("tenant_id") or "")
        base["resource_type"] = str(sample.get("resource_type") or "")
        base["resource_id"] = str(sample.get("resource_id") or "")
        return base
    if correlation_preset == "incident_minimal":
        base["actor_id"] = str(sample.get("actor_id") or "")
        base["action_type"] = str(sample.get("action_type") or "")
        base["decision_outcome"] = str(sample.get("decision_outcome") or "")
        return base

    base["resource_type"] = str(sample.get("resource_type") or "")
    base["resource_id"] = str(sample.get("resource_id") or "")
    base["actor_id"] = str(sample.get("actor_id") or "")
    return base


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
                "sink_type": _normalize_callback_sink_type(row.get("sink_type")),
                "sink_route_key": _normalize_sink_route_key(row.get("sink_route_key")),
                "correlation_preset": _normalize_callback_correlation_preset(row.get("correlation_preset")),
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


def _load_gateway_system_instructions(db: Session) -> str:
    return str(get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_SYSTEM_INSTRUCTIONS, "") or "").strip()


GATEWAY_SECRET_ENC_PREFIX = "enc:v1:"
GATEWAY_CURSOR_SECRET_BINDING_VERSION = "v3"
GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB = "db"
GATEWAY_CURSOR_TOKEN_STORAGE_MODE_EXTERNAL = "external"
GATEWAY_CURSOR_TOKEN_STORAGE_MODES = {
    GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB,
    GATEWAY_CURSOR_TOKEN_STORAGE_MODE_EXTERNAL,
}
PLATFORM_GATEWAY_TENANT_ID = "platform-gateway-secrets"
GATEWAY_CURSOR_TOKEN_DEPRECATION = (
    "Deprecated: configure secrets via Providers (provider_type=db|vault|aws-secrets-manager|azure-key-vault) "
    "and bind gateway resolution with PUT /gateway/cursor-secret-binding."
)


def _load_gateway_cursor_api_token_legacy(raw_value: str) -> str:
    stored_value = str(raw_value or "").strip()
    if not stored_value:
        return ""
    if stored_value.startswith(GATEWAY_SECRET_ENC_PREFIX):
        encrypted_value = stored_value[len(GATEWAY_SECRET_ENC_PREFIX) :].strip()
        try:
            return decrypt_sensitive_value(encrypted_value).strip()
        except SecretCryptoError as exc:
            raise HTTPException(status_code=500, detail="gateway cursor token storage is unreadable") from exc
    return stored_value


def _serialize_gateway_cursor_secret_binding(secret_provider_id: str, secret_ref: str) -> str:
    return json.dumps(
        {
            "version": GATEWAY_CURSOR_SECRET_BINDING_VERSION,
            "secret_provider_id": str(secret_provider_id or "").strip(),
            "secret_ref": str(secret_ref or "").strip(),
        },
        separators=(",", ":"),
    )


def _load_gateway_cursor_secret_binding(db: Session) -> dict[str, str]:
    stored_value = str(get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN, "") or "").strip()
    if not stored_value:
        return {
            "binding_version": "",
            "secret_provider_id": "",
            "secret_ref": "",
            "provider_type": "",
        }

    if stored_value.startswith("{"):
        try:
            payload = json.loads(stored_value)
        except Exception as exc:
            raise HTTPException(status_code=500, detail="gateway cursor secret binding format is invalid") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=500, detail="gateway cursor secret binding format must be an object")

        if str(payload.get("version") or "").strip() == GATEWAY_CURSOR_SECRET_BINDING_VERSION:
            secret_provider_id = str(payload.get("secret_provider_id") or "").strip()
            secret_ref = str(payload.get("secret_ref") or "").strip()
            provider_type = ""
            if secret_provider_id:
                provider = db.query(SecretProviderConfig).filter_by(secret_provider_id=secret_provider_id).first()
                provider_type = str(provider.provider_type or "").strip().lower() if provider else ""
            return {
                "binding_version": GATEWAY_CURSOR_SECRET_BINDING_VERSION,
                "secret_provider_id": secret_provider_id,
                "secret_ref": secret_ref,
                "provider_type": provider_type,
            }

    return {
        "binding_version": "",
        "secret_provider_id": "",
        "secret_ref": "",
        "provider_type": "",
    }


def _load_gateway_cursor_token_config(db: Session) -> dict[str, str]:
    binding = _load_gateway_cursor_secret_binding(db)
    if binding.get("binding_version") == GATEWAY_CURSOR_SECRET_BINDING_VERSION:
        provider_type = str(binding.get("provider_type") or "").strip().lower()
        storage_mode = (
            GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB
            if is_db_secret_provider(provider_type)
            else GATEWAY_CURSOR_TOKEN_STORAGE_MODE_EXTERNAL
        )
        return {
            "binding_version": GATEWAY_CURSOR_SECRET_BINDING_VERSION,
            "storage_mode": storage_mode,
            "token": "",
            "external_provider_id": str(binding.get("secret_provider_id") or "").strip(),
            "external_secret_ref": str(binding.get("secret_ref") or "").strip(),
            "secret_provider_id": str(binding.get("secret_provider_id") or "").strip(),
            "secret_ref": str(binding.get("secret_ref") or "").strip(),
            "provider_type": provider_type,
        }

    stored_value = str(get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN, "") or "").strip()
    if not stored_value:
        return {
            "binding_version": "v2",
            "storage_mode": GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB,
            "token": "",
            "external_provider_id": "",
            "external_secret_ref": "",
            "secret_provider_id": "",
            "secret_ref": "",
            "provider_type": "",
        }

    if stored_value.startswith("{"):
        try:
            payload = json.loads(stored_value)
        except Exception as exc:
            raise HTTPException(status_code=500, detail="gateway cursor token storage format is invalid") from exc
        if not isinstance(payload, dict):
            raise HTTPException(status_code=500, detail="gateway cursor token storage format must be an object")

        storage_mode = str(payload.get("storage_mode") or GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB).strip().lower()
        if storage_mode not in GATEWAY_CURSOR_TOKEN_STORAGE_MODES:
            raise HTTPException(status_code=500, detail="gateway cursor token storage mode is unsupported")

        if storage_mode == GATEWAY_CURSOR_TOKEN_STORAGE_MODE_EXTERNAL:
            return {
                "binding_version": "v2",
                "storage_mode": storage_mode,
                "token": "",
                "external_provider_id": str(payload.get("external_provider_id") or "").strip(),
                "external_secret_ref": str(payload.get("external_secret_ref") or "").strip(),
                "secret_provider_id": str(payload.get("external_provider_id") or "").strip(),
                "secret_ref": str(payload.get("external_secret_ref") or "").strip(),
                "provider_type": "",
            }

        encrypted_token = str(payload.get("token_encrypted") or "").strip()
        token_value = _load_gateway_cursor_api_token_legacy(encrypted_token)
        return {
            "binding_version": "v2",
            "storage_mode": GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB,
            "token": token_value,
            "external_provider_id": "",
            "external_secret_ref": "",
            "secret_provider_id": "",
            "secret_ref": "",
            "provider_type": GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB,
        }

    token_value = _load_gateway_cursor_api_token_legacy(stored_value)
    return {
        "binding_version": "legacy",
        "storage_mode": GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB,
        "token": token_value,
        "external_provider_id": "",
        "external_secret_ref": "",
        "secret_provider_id": "",
        "secret_ref": "",
        "provider_type": GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB,
    }


def _serialize_gateway_cursor_api_token(secret_value: str) -> str:
    normalized = str(secret_value or "").strip()
    if not normalized:
        return ""
    try:
        encrypted = encrypt_sensitive_value(normalized)
    except SecretCryptoError as exc:
        raise HTTPException(status_code=503, detail="gateway cursor token encryption is unavailable") from exc
    return f"{GATEWAY_SECRET_ENC_PREFIX}{encrypted}"


def _serialize_gateway_cursor_token_config_db(secret_value: str) -> str:
    return json.dumps(
        {
            "version": "v2",
            "storage_mode": GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB,
            "token_encrypted": _serialize_gateway_cursor_api_token(secret_value),
        },
        separators=(",", ":"),
    )


def _serialize_gateway_cursor_token_config_external(external_provider_id: str, external_secret_ref: str) -> str:
    return json.dumps(
        {
            "version": "v2",
            "storage_mode": GATEWAY_CURSOR_TOKEN_STORAGE_MODE_EXTERNAL,
            "external_provider_id": external_provider_id,
            "external_secret_ref": external_secret_ref,
        },
        separators=(",", ":"),
    )


def _mask_gateway_secret_hint(secret_value: str) -> str | None:
    normalized = str(secret_value or "").strip()
    if not normalized:
        return None
    if len(normalized) <= 8:
        return "***"
    return f"{normalized[:4]}***{normalized[-4:]}"


def _mask_gateway_external_secret_ref(secret_ref: str) -> str | None:
    normalized = str(secret_ref or "").strip()
    if not normalized:
        return None
    if len(normalized) <= 6:
        return "***"
    return f"{normalized[:3]}***{normalized[-3:]}"


def _require_active_secret_provider_config(db: Session, provider_id: str) -> SecretProviderConfig:
    row = db.query(SecretProviderConfig).filter_by(secret_provider_id=str(provider_id).strip()).first()
    if not row:
        raise HTTPException(status_code=404, detail="External secret provider not found")
    if str(row.status or "").strip().lower() != "active":
        raise HTTPException(status_code=400, detail="External secret provider is not active")
    return row


def _resolve_secret_provider_connection(provider: SecretProviderConfig) -> tuple[str, str]:
    address = (
        decrypt_value(provider.provider_address_encrypted)
        if str(provider.provider_address_encrypted or "").strip()
        else str(provider.provider_address or "").strip()
    )
    bootstrap_token = (
        decrypt_value(provider.bootstrap_token_encrypted)
        if str(provider.bootstrap_token_encrypted or "").strip()
        else ""
    )
    return address, bootstrap_token


def _read_external_secret_value(db: Session, external_provider_id: str, external_secret_ref: str) -> str:
    provider = _require_active_secret_provider_config(db, external_provider_id)
    provider_type = str(provider.provider_type or "").strip().lower()
    secret_ref = str(external_secret_ref or "").strip()
    address, bootstrap_token = _resolve_secret_provider_connection(provider)

    if not secret_ref:
        raise HTTPException(status_code=422, detail="external_secret_ref is required")

    if provider_type == "vault":
        if not address:
            raise HTTPException(status_code=400, detail="Vault provider address is missing")
        headers = {}
        if bootstrap_token:
            headers["X-Vault-Token"] = bootstrap_token
        response = httpx.get(f"{address.rstrip('/')}/v1/{secret_ref.lstrip('/')}", headers=headers, timeout=5.0)
        if response.status_code >= 400:
            raise HTTPException(status_code=502, detail="Vault secret read failed")
        payload = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        data = payload.get("data") if isinstance(payload, dict) else {}
        if isinstance(data, dict) and isinstance(data.get("data"), dict):
            data = data.get("data")
        if not isinstance(data, dict):
            raise HTTPException(status_code=502, detail="Vault secret payload is invalid")
        for key in ("token", "value", "secret"):
            candidate = str(data.get(key) or "").strip()
            if candidate:
                return candidate
        for value in data.values():
            candidate = str(value or "").strip()
            if candidate:
                return candidate
        raise HTTPException(status_code=502, detail="Vault secret payload does not contain a usable value")

    if provider_type in {"aws-secrets-manager", "aws_secrets_manager"}:
        try:
            import boto3  # type: ignore
        except ImportError as exc:
            raise HTTPException(status_code=503, detail="boto3 is required for AWS external secret reads") from exc
        try:
            client = boto3.client("secretsmanager")
            payload = client.get_secret_value(SecretId=secret_ref)
        except Exception as exc:
            raise HTTPException(status_code=502, detail="AWS Secrets Manager secret read failed") from exc
        secret_string = str(payload.get("SecretString") or "").strip()
        if secret_string:
            return secret_string
        secret_binary = payload.get("SecretBinary")
        if secret_binary:
            try:
                return secret_binary.decode("utf-8") if isinstance(secret_binary, bytes) else str(secret_binary)
            except Exception:
                return str(secret_binary)
        raise HTTPException(status_code=502, detail="AWS secret payload does not contain a usable value")

    if provider_type in {"azure-key-vault", "azure_key_vault"}:
        if not address:
            raise HTTPException(status_code=400, detail="Azure Key Vault provider address is missing")
        if not bootstrap_token:
            raise HTTPException(status_code=400, detail="Azure Key Vault bootstrap token is missing")
        response = httpx.get(
            f"{address.rstrip('/')}/secrets/{secret_ref}?api-version=7.4",
            headers={"Authorization": f"Bearer {bootstrap_token}"},
            timeout=5.0,
        )
        if response.status_code >= 400:
            raise HTTPException(status_code=502, detail="Azure Key Vault secret read failed")
        payload = response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
        value = str((payload or {}).get("value") or "").strip()
        if not value:
            raise HTTPException(status_code=502, detail="Azure Key Vault payload does not contain a usable value")
        return value

    if is_db_secret_provider(provider_type):
        return read_db_secret_provider_value(db, provider, secret_ref)

    raise HTTPException(status_code=400, detail="secret provider type is not supported for runtime reads")


def _ensure_platform_gateway_tenant(db: Session, actor_id: str) -> None:
    row = db.query(TenantCatalogEntry).filter_by(tenant_id=PLATFORM_GATEWAY_TENANT_ID).first()
    if row:
        return
    db.add(
        TenantCatalogEntry(
            tenant_id=PLATFORM_GATEWAY_TENANT_ID,
            tenant_name="Platform Gateway Secrets",
            tenant_type="internal",
            description="System tenant for platform-managed db secret providers",
            status="active",
            updated_by=actor_id,
        )
    )


def _get_or_create_platform_db_secret_provider(db: Session, actor_id: str) -> SecretProviderConfig:
    existing = (
        db.query(SecretProviderConfig)
        .filter_by(tenant_id=PLATFORM_GATEWAY_TENANT_ID, provider_type="db", status="active")
        .order_by(SecretProviderConfig.secret_provider_id.asc())
        .first()
    )
    if existing:
        return existing

    _ensure_platform_gateway_tenant(db, actor_id)
    provider_address, auth_method, role_or_mount = normalize_db_provider_defaults("db", "", "", "gateway-default")
    provider = SecretProviderConfig(
        secret_provider_id=str(uuid4()),
        tenant_id=PLATFORM_GATEWAY_TENANT_ID,
        provider_type="db",
        provider_address="[ENCRYPTED]",
        provider_address_encrypted=encrypt_value(provider_address),
        auth_method="[ENCRYPTED]",
        auth_method_encrypted=encrypt_value(auth_method),
        role_or_mount="[ENCRYPTED]",
        role_or_mount_encrypted=encrypt_value(role_or_mount),
        bootstrap_token_encrypted="",
        secret_path_prefixes='["gateway/"]',
        lease_ttl_seconds=3600,
        auto_renew_enabled=True,
        status="active",
    )
    db.add(provider)
    db.flush()
    return provider


def _persist_gateway_cursor_secret_binding(
    db: Session,
    *,
    secret_provider_id: str,
    secret_ref: str,
    actor_id: str,
) -> RuntimeConfig:
    _require_active_secret_provider_config(db, secret_provider_id)
    serialized_value = _serialize_gateway_cursor_secret_binding(secret_provider_id, secret_ref)
    row = db.query(RuntimeConfig).filter_by(config_key=RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN).first()
    if row:
        row.config_value = serialized_value
        row.updated_by = actor_id
        row.updated_at = datetime.utcnow()
    else:
        row = RuntimeConfig(
            config_key=RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN,
            config_value=serialized_value,
            description="Gateway cursor secret binding via secret provider",
            updated_by=actor_id,
        )
        db.add(row)
    invalidate_runtime_config_cache(RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN)
    return row


def _resolve_gateway_cursor_api_token(db: Session) -> str:
    binding = _load_gateway_cursor_secret_binding(db)
    if binding.get("binding_version") == GATEWAY_CURSOR_SECRET_BINDING_VERSION:
        secret_provider_id = str(binding.get("secret_provider_id") or "").strip()
        secret_ref = str(binding.get("secret_ref") or "").strip()
        if secret_provider_id and secret_ref:
            return _read_external_secret_value(db, secret_provider_id, secret_ref)
        return ""

    config = _load_gateway_cursor_token_config(db)
    storage_mode = str(config.get("storage_mode") or GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB).strip().lower()
    if storage_mode == GATEWAY_CURSOR_TOKEN_STORAGE_MODE_EXTERNAL:
        return _read_external_secret_value(
            db,
            str(config.get("external_provider_id") or "").strip(),
            str(config.get("external_secret_ref") or "").strip(),
        )
    return str(config.get("token") or "").strip()


def _ensure_inference_credentials(
    db: Session,
    *,
    agent_id: Optional[str],
    environment: str,
    model_name: str,
) -> None:
    agent_key = str(agent_id or "").strip()
    if inference_simulation_enabled() and not agent_key:
        return

    normalized_environment = str(environment or "dev").strip().lower() or "dev"
    provider_type_from_model, _ = _split_provider_model(str(model_name or "").strip())

    if agent_key and not agent_key.startswith("gateway-"):
        config = db.query(AgentConfig).filter_by(agent_key=agent_key).first()
        if config:
            resolved = resolve_agent_config_credential(
                db,
                config,
                environment=normalized_environment,
            )
            if resolved is not None:
                return
            if str(config.provider or "").strip().lower() == "cursor":
                _resolve_gateway_cursor_api_token(db)
                return
            return

    inferred_provider, _ = infer_provider_type_from_model(model_name)
    if _provider_env_api_key(inferred_provider):
        return

    if inferred_provider in {"cursor", "openai"}:
        _resolve_gateway_cursor_api_token(db)


def _required_gateway_secret_approver_role(ctx: ActorContext) -> str | None:
    actor_role = str(ctx.actor_role or "").strip()
    if actor_role in {ROLE_PLATFORM_ADMIN, ROLE_SUPER_ADMIN, ROLE_MASTER_ADMIN}:
        return ROLE_SECURITY_APPROVER
    if actor_role == ROLE_SECURITY_APPROVER:
        return ROLE_PLATFORM_ADMIN
    return None


def _normalize_gateway_system_rule_entry(
    item: object,
    *,
    strict: bool,
) -> dict[str, str] | None:
    if isinstance(item, str):
        rule_text = item.strip()
        if not rule_text:
            return None
        if len(rule_text) > 500:
            if strict:
                raise HTTPException(status_code=422, detail="gateway system rule text must be <= 500 chars")
            return None
        return {"rule_text": rule_text, "scope_type": GATEWAY_SYSTEM_RULE_SCOPE_GLOBAL, "scope_id": ""}

    if not isinstance(item, dict):
        if strict:
            raise HTTPException(status_code=422, detail="gateway system rules entries must be objects")
        return None

    rule_text = str(item.get("rule_text") or item.get("rule") or item.get("text") or "").strip()
    if not rule_text:
        if strict:
            raise HTTPException(status_code=422, detail="gateway system rule requires rule_text")
        return None
    if len(rule_text) > 500:
        raise HTTPException(status_code=422, detail="gateway system rule text must be <= 500 chars")

    scope_type = str(item.get("scope_type") or GATEWAY_SYSTEM_RULE_SCOPE_GLOBAL).strip().lower() or GATEWAY_SYSTEM_RULE_SCOPE_GLOBAL
    if scope_type not in ALLOWED_GATEWAY_SYSTEM_RULE_SCOPE_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"gateway system rule scope_type must be one of: {', '.join(sorted(ALLOWED_GATEWAY_SYSTEM_RULE_SCOPE_TYPES))}",
        )
    scope_id = str(item.get("scope_id") or "").strip()
    if scope_type != GATEWAY_SYSTEM_RULE_SCOPE_GLOBAL and not scope_id:
        raise HTTPException(status_code=422, detail="gateway system rule scope_id is required for non-global scope")
    if scope_type == GATEWAY_SYSTEM_RULE_SCOPE_GLOBAL:
        scope_id = ""
    return {"rule_text": rule_text, "scope_type": scope_type, "scope_id": scope_id}


def _parse_gateway_system_rules(raw_value: str) -> list[dict[str, str]]:
    raw = str(raw_value or "[]").strip() or "[]"
    try:
        parsed = json.loads(raw)
    except Exception as exc:
        raise HTTPException(status_code=500, detail="gateway system rules registry is invalid JSON") from exc
    if not isinstance(parsed, list):
        raise HTTPException(status_code=500, detail="gateway system rules registry must be a list")

    normalized_rules: list[dict[str, str]] = []
    for item in parsed:
        normalized = _normalize_gateway_system_rule_entry(item, strict=False)
        if normalized:
            normalized_rules.append(normalized)
    return normalized_rules


def _normalize_gateway_system_rules(rules: list[dict[str, object]]) -> list[dict[str, str]]:
    normalized_rules: list[dict[str, str]] = []
    for item in rules:
        normalized = _normalize_gateway_system_rule_entry(item, strict=True)
        if normalized:
            normalized_rules.append(normalized)
    if len(normalized_rules) > 100:
        raise HTTPException(status_code=422, detail="gateway system rules supports at most 100 entries")
    return normalized_rules


def _load_gateway_system_rules(db: Session) -> list[dict[str, str]]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_SYSTEM_RULES_JSON, "[]")
    return _parse_gateway_system_rules(raw)


def _resolve_gateway_system_rules_for_responses(
    db: Session,
    *,
    payload: GatewayOpenAIResponsesRequest,
    ctx: ActorContext,
) -> list[dict[str, str]]:
    rules = _load_gateway_system_rules(db)
    if not rules:
        return []

    normalized_agent_id = str(payload.agent_id or "").strip()
    normalized_actor_id = str(ctx.actor_id or "").strip()

    owner_scope_type = ""
    owner_scope_id = ""
    raw_owner_scope = str(payload.owner_scope or "").strip()
    if raw_owner_scope:
        try:
            owner_scope_type, owner_scope_id, _ = normalize_owner_scope(db, owner_scope=raw_owner_scope)
        except HTTPException:
            owner_scope_type = ""
            owner_scope_id = ""

    matched_rules: list[dict[str, str]] = []
    for rule in rules:
        scope_type = str(rule.get("scope_type") or GATEWAY_SYSTEM_RULE_SCOPE_GLOBAL).strip().lower()
        scope_id = str(rule.get("scope_id") or "").strip()
        if scope_type == GATEWAY_SYSTEM_RULE_SCOPE_GLOBAL:
            matched_rules.append(rule)
            continue
        if scope_type in {COST_SCOPE_USER, COST_SCOPE_ACTOR} and normalized_actor_id and scope_id == normalized_actor_id:
            matched_rules.append(rule)
            continue
        if scope_type == COST_SCOPE_AGENT and normalized_agent_id and scope_id == normalized_agent_id:
            matched_rules.append(rule)
            continue
        if scope_type in {COST_SCOPE_TEAM, COST_SCOPE_GROUP, COST_SCOPE_OWNER}:
            if owner_scope_type == scope_type and owner_scope_id and scope_id == owner_scope_id:
                matched_rules.append(rule)

    return matched_rules


def _normalize_request_tag(value: str | None) -> str | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    if not REQUEST_TAG_PATTERN.match(raw):
        raise HTTPException(status_code=422, detail="request_tag must match ^[a-zA-Z0-9._:-]{1,64}$")
    return raw


def _fingerprint_cache_request(parts: list[str]) -> str:
    normalized = "|".join(str(part or "").strip() for part in parts)
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]


def _normalize_cache_request_text(value: str | None) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def _semantic_similarity_score(left_text: str | None, right_text: str | None) -> float:
    left_tokens = set(re.findall(r"[a-z0-9]+", _normalize_cache_request_text(left_text)))
    right_tokens = set(re.findall(r"[a-z0-9]+", _normalize_cache_request_text(right_text)))
    if not left_tokens or not right_tokens:
        return 0.0
    overlap = len(left_tokens & right_tokens)
    union = len(left_tokens | right_tokens)
    return round(overlap / union, 4) if union else 0.0


def _resolve_cache_policy_for_request(
    db: Session,
    tenant_id: str,
    route_policy_id: str | None,
    owner_scope: str | None,
) -> CachePolicy | None:
    normalized_tenant = str(tenant_id or "").strip()
    normalized_route = str(route_policy_id or "").strip()
    normalized_owner_scope = str(owner_scope or "").strip()
    scopes: list[str] = ["global"]
    if normalized_tenant:
        scopes.append(f"tenant:{normalized_tenant}")
    if normalized_route:
        scopes.append(f"route:{normalized_route}")
    if normalized_owner_scope:
        scopes.append(f"owner:{normalized_owner_scope}")

    rows = (
        db.query(CachePolicy)
        .filter(CachePolicy.status == "active")
        .filter(CachePolicy.scope.in_(scopes))
        .all()
    )
    by_scope = {str(row.scope): row for row in rows}
    if normalized_route and by_scope.get(f"route:{normalized_route}"):
        return by_scope[f"route:{normalized_route}"]
    if normalized_owner_scope and by_scope.get(f"owner:{normalized_owner_scope}"):
        return by_scope[f"owner:{normalized_owner_scope}"]
    if normalized_tenant and by_scope.get(f"tenant:{normalized_tenant}"):
        return by_scope[f"tenant:{normalized_tenant}"]
    return by_scope.get("global")


def _classify_cache_data_class(request_tag: str | None, request_text: str) -> str:
    normalized_tag = str(request_tag or "").strip().lower()
    if normalized_tag.startswith("pii"):
        return "pii"
    if normalized_tag.startswith("phi"):
        return "phi"
    if normalized_tag.startswith("secret"):
        return "secret"
    lowered = str(request_text or "").lower()
    if any(token in lowered for token in ["password", "secret", "api key", "ssn", "token"]):
        return "sensitive"
    return "standard"


def _record_cache_decision_event(
    db: Session,
    actor_id: str,
    trace_id: str,
    request_id: str,
    request_fingerprint: str,
    request_text: str,
    tenant_id: str,
    environment: str,
    route_policy_id: str | None,
    request_tag: str | None,
    owner_scope: str | None,
) -> None:
    matched_policy = _resolve_cache_policy_for_request(
        db,
        tenant_id=tenant_id,
        route_policy_id=route_policy_id,
        owner_scope=owner_scope,
    )
    data_class = _classify_cache_data_class(request_tag, request_text)
    decision = "bypass"
    explanation = "cache bypassed: no active policy for request scope"
    provenance = "cache-policy:none"
    cache_mode: str | None = None
    cache_policy_id: str | None = None
    cache_policy_scope: str | None = None
    source_request_id: str | None = None
    match_score = 0.0
    request_text_normalized = _normalize_cache_request_text(request_text)

    if matched_policy is not None:
        privacy_scope = str(matched_policy.privacy_scope or "tenant").strip().lower() or "tenant"
        non_cache_data_classes = _parse_string_list(
            str(matched_policy.non_cache_data_classes or "[]"),
            "non_cache_data_classes",
        )
        normalized_non_cache = {str(item).strip().lower() for item in non_cache_data_classes}
        if data_class in normalized_non_cache:
            decision = "bypass"
            explanation = f"cache bypassed: data_class {data_class} is disallowed by policy"
            provenance += f";privacy_scope:{privacy_scope};data_class:{data_class};policy_action:no_cache"
            create_audit_event(
                db,
                actor_id=actor_id,
                action_type="gateway.cache.bypass",
                resource_type="cache_policy",
                resource_id=matched_policy.cache_policy_id,
                trace_id=trace_id,
                decision_outcome="allow",
            )
        elif privacy_scope == "owner" and not str(owner_scope or "").strip():
            decision = "bypass"
            explanation = "cache bypassed: owner-scoped policy requires owner scope context"
            provenance += f";privacy_scope:{privacy_scope};data_class:{data_class};policy_action:owner_scope_required"
            create_audit_event(
                db,
                actor_id=actor_id,
                action_type="gateway.cache.bypass",
                resource_type="cache_policy",
                resource_id=matched_policy.cache_policy_id,
                trace_id=trace_id,
                decision_outcome="allow",
            )
        else:
            cache_mode = str(matched_policy.cache_mode or "exact").strip() or "exact"
            cache_policy_id = matched_policy.cache_policy_id
            cache_policy_scope = matched_policy.scope
            provenance = f"cache-policy:{matched_policy.cache_policy_id};scope:{matched_policy.scope};mode:{cache_mode};privacy_scope:{privacy_scope};data_class:{data_class}"
            if cache_mode == "semantic":
                provenance += f";threshold:{matched_policy.similarity_threshold}"

            if cache_mode == "semantic":
                candidates = (
                    db.query(CacheDecisionEvent)
                    .filter(CacheDecisionEvent.cache_policy_id == matched_policy.cache_policy_id)
                    .filter(CacheDecisionEvent.request_id != request_id)
                    .filter(CacheDecisionEvent.request_text != "")
                    .order_by(CacheDecisionEvent.timestamp.desc())
                    .all()
                )
                best_event: CacheDecisionEvent | None = None
                best_score = 0.0
                for candidate in candidates:
                    candidate_score = _semantic_similarity_score(request_text_normalized, candidate.request_text)
                    if candidate_score > best_score:
                        best_score = candidate_score
                        best_event = candidate
                match_score = best_score
                if best_event is not None:
                    source_request_id = best_event.request_id
                    provenance += f";match_score:{match_score};source_request_id:{source_request_id}"
                if best_score >= float(matched_policy.similarity_threshold):
                    decision = "hit"
                    explanation = (
                        f"semantic cache hit: similarity score {match_score} met threshold {matched_policy.similarity_threshold}"
                    )
                    create_audit_event(
                        db,
                        actor_id=actor_id,
                        action_type="gateway.cache.hit",
                        resource_type="cache_policy",
                        resource_id=matched_policy.cache_policy_id,
                        trace_id=trace_id,
                        decision_outcome="allow",
                    )
                else:
                    decision = "miss"
                    explanation = (
                        f"semantic cache miss: similarity score {match_score} below threshold {matched_policy.similarity_threshold}"
                    )
                    create_audit_event(
                        db,
                        actor_id=actor_id,
                        action_type="gateway.cache.miss",
                        resource_type="cache_policy",
                        resource_id=matched_policy.cache_policy_id,
                        trace_id=trace_id,
                        decision_outcome="allow",
                    )
            else:
                exact_event = (
                    db.query(CacheDecisionEvent)
                    .filter(CacheDecisionEvent.request_fingerprint == request_fingerprint)
                    .filter(CacheDecisionEvent.cache_policy_id.isnot(None))
                    .order_by(CacheDecisionEvent.timestamp.desc())
                    .first()
                )
                if exact_event is not None:
                    decision = "hit"
                    match_score = 1.0
                    source_request_id = str(exact_event.request_id)
                    explanation = "exact cache hit: repeated request fingerprint matched prior cached response"
                    provenance += f";match_score:{match_score};source_request_id:{source_request_id}"
                    create_audit_event(
                        db,
                        actor_id=actor_id,
                        action_type="gateway.cache.hit",
                        resource_type="cache_policy",
                        resource_id=matched_policy.cache_policy_id,
                        trace_id=trace_id,
                        decision_outcome="allow",
                    )
                else:
                    decision = "miss"
                    explanation = "exact cache miss: no prior response for request hash"
                    create_audit_event(
                        db,
                        actor_id=actor_id,
                        action_type="gateway.cache.miss",
                        resource_type="cache_policy",
                        resource_id=matched_policy.cache_policy_id,
                        trace_id=trace_id,
                        decision_outcome="allow",
                    )

    db.add(
        CacheDecisionEvent(
            cache_decision_event_id=str(uuid4()),
            trace_id=trace_id,
            request_id=request_id,
            request_fingerprint=request_fingerprint,
            request_text=request_text_normalized,
            actor_id=actor_id,
            tenant_id=str(tenant_id or "").strip(),
            environment=str(environment or "dev").strip().lower() or "dev",
            route_policy_id=str(route_policy_id or "").strip() or None,
            data_class=data_class,
            cache_policy_id=cache_policy_id,
            cache_policy_scope=cache_policy_scope,
            cache_mode=cache_mode,
            match_score=match_score,
            decision=decision,
            explanation=explanation,
            match_provenance=provenance,
            source_request_id=source_request_id,
        )
    )


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


def _parse_canary_targets(raw: str) -> list[dict]:
    try:
        value = json.loads(raw or "[]")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail="canary_targets must be valid JSON") from exc

    if not isinstance(value, list):
        raise HTTPException(status_code=422, detail="canary_targets must be a JSON array")

    normalized: list[dict] = []
    for item in value:
        if not isinstance(item, dict):
            raise HTTPException(status_code=422, detail="canary_targets entries must be JSON objects")
        provider_id = str(item.get("provider_id") or "").strip()
        if not provider_id:
            raise HTTPException(status_code=422, detail="canary_targets entry missing provider_id")
        traffic_percent_raw = item.get("traffic_percent")
        if not isinstance(traffic_percent_raw, int) or traffic_percent_raw < 1 or traffic_percent_raw > 100:
            raise HTTPException(status_code=422, detail="canary_targets.traffic_percent must be an integer in [1, 100]")
        normalized.append(
            {
                "provider_id": provider_id,
                "traffic_percent": traffic_percent_raw,
            }
        )

    deduped: dict[str, dict] = {}
    for row in normalized:
        deduped[str(row["provider_id"])] = row

    rows = [deduped[key] for key in sorted(deduped.keys())]
    total_percent = sum(int(row.get("traffic_percent", 0)) for row in rows)
    if total_percent > 100:
        raise HTTPException(status_code=422, detail="canary_targets total traffic_percent must be <= 100")
    return rows


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


def _resolve_output_guardrails_policy(fallback_policy: dict, request_tag: str | None) -> tuple[dict, str | None]:
    policy = fallback_policy.get("output_guardrails") if isinstance(fallback_policy, dict) else None
    if not isinstance(policy, dict):
        policy = {}

    normalized_tag = _normalize_request_tag(request_tag)
    if not normalized_tag:
        return policy, None

    tagged = fallback_policy.get("output_guardrails_by_tag") if isinstance(fallback_policy, dict) else None
    if not isinstance(tagged, dict):
        return policy, None

    selected = tagged.get(normalized_tag)
    if not isinstance(selected, dict):
        return policy, None
    return selected, normalized_tag


def _resolve_input_data_policy(fallback_policy: dict, request_tag: str | None) -> tuple[dict, str | None]:
    policy = fallback_policy.get("input_data_policy") if isinstance(fallback_policy, dict) else None
    if not isinstance(policy, dict):
        policy = {}

    normalized_tag = _normalize_request_tag(request_tag)
    if not normalized_tag:
        return policy, None

    tagged = fallback_policy.get("input_data_policy_by_tag") if isinstance(fallback_policy, dict) else None
    if not isinstance(tagged, dict):
        return policy, None

    selected = tagged.get(normalized_tag)
    if not isinstance(selected, dict):
        return policy, None
    return selected, normalized_tag


def _parse_input_data_classes(raw: object, field_name: str) -> list[str]:
    allowed = {"standard", "sensitive", "pii", "phi", "secret"}
    if isinstance(raw, list):
        source = raw
    else:
        source = _parse_string_list(str(raw or "[]"), field_name)
    normalized: list[str] = []
    for item in source:
        value = str(item or "").strip().lower()
        if not value:
            continue
        if value not in allowed:
            raise HTTPException(status_code=422, detail=f"{field_name} contains unsupported class: {value}")
        if value not in normalized:
            normalized.append(value)
    return normalized


def _evaluate_input_data_policy(
    fallback_policy: dict,
    *,
    tenant_id: str,
    request_tag: str | None,
    input_text: str,
    resource: str,
) -> tuple[str, list[str], str, str]:
    policy, _ = _resolve_input_data_policy(fallback_policy, request_tag)
    normalized_input_text = str(input_text or "")
    data_class = _classify_cache_data_class(request_tag, normalized_input_text)
    if not isinstance(policy, dict) or not policy:
        return "allow", [], normalized_input_text, data_class

    policy_tenant_id = str(policy.get("tenant_id") or "").strip()
    if policy_tenant_id:
        _require_tenant_match(policy_tenant_id, tenant_id, resource)

    if not bool(policy.get("enforce", True)):
        return "allow", [], normalized_input_text, data_class

    mode = str(policy.get("policy_mode") or "warn").strip().lower() or "warn"
    if mode not in {"allow", "warn", "block", "mask"}:
        mode = "warn"

    classes = _parse_input_data_classes(policy.get("data_classes", []), "data_classes")
    patterns = _parse_output_guardrail_phrases(policy.get("block_patterns", []), "block_patterns")
    matched_patterns = [pattern for pattern in patterns if pattern and pattern in normalized_input_text.lower()]

    reasons: list[str] = []
    if classes and data_class in classes:
        reasons.append("data_class_match")
    if matched_patterns:
        reasons.append("pattern_match")

    if not reasons:
        return "allow", [], normalized_input_text, data_class

    if mode == "block":
        return "block", reasons, normalized_input_text, data_class

    if mode == "mask":
        transformed = normalized_input_text
        mask_token = str(policy.get("mask_token") or "[REDACTED]").strip() or "[REDACTED]"
        if matched_patterns:
            for pattern in matched_patterns:
                transformed = re.sub(re.escape(pattern), mask_token, transformed, flags=re.IGNORECASE)
        elif transformed:
            transformed = mask_token
        return "mask", reasons, transformed, data_class

    if mode == "warn":
        return "warn", reasons, normalized_input_text, data_class

    return "allow", reasons, normalized_input_text, data_class


def _parse_output_guardrail_phrases(raw: object, field_name: str) -> list[str]:
    if isinstance(raw, list):
        source = raw
    else:
        source = _parse_string_list(str(raw or "[]"), field_name)
    normalized: list[str] = []
    for item in source:
        phrase = str(item or "").strip().lower()
        if not phrase:
            continue
        if phrase not in normalized:
            normalized.append(phrase)
    return normalized


def _evaluate_output_guardrails(
    fallback_policy: dict,
    *,
    tenant_id: str,
    request_tag: str | None,
    output_tokens: int,
    output_text: str,
    resource: str,
) -> tuple[str, list[str], str | None]:
    policy, _ = _resolve_output_guardrails_policy(fallback_policy, request_tag)
    if not isinstance(policy, dict) or not policy:
        return "allow", [], None

    guardrail_tenant_id = str(policy.get("tenant_id") or "").strip()
    if guardrail_tenant_id:
        _require_tenant_match(guardrail_tenant_id, tenant_id, resource)

    if not bool(policy.get("enforce", True)):
        return "allow", [], None

    mode = str(policy.get("policy_mode") or "warn").strip().lower() or "warn"
    if mode not in {"allow", "warn", "block", "transform"}:
        mode = "warn"

    reasons: list[str] = []
    max_output_tokens = policy.get("max_output_tokens")
    if isinstance(max_output_tokens, int) and output_tokens > max_output_tokens:
        reasons.append("output_tokens_exceeds_maximum")

    normalized_output_text = str(output_text or "")
    output_text_lower = normalized_output_text.lower()
    blocked_phrases = _parse_output_guardrail_phrases(policy.get("blocked_phrases", []), "blocked_phrases")
    matched_blocked_phrases = [phrase for phrase in blocked_phrases if phrase and phrase in output_text_lower]
    if matched_blocked_phrases:
        reasons.append("blocked_phrase_match")

    if not reasons:
        return "allow", [], None

    if mode == "block":
        return "block", reasons, None

    if mode == "transform":
        redact_phrases = _parse_output_guardrail_phrases(policy.get("redact_phrases", []), "redact_phrases")
        phrases_to_redact = redact_phrases or matched_blocked_phrases
        transformed = normalized_output_text
        for phrase in phrases_to_redact:
            transformed = re.sub(re.escape(phrase), "[REDACTED]", transformed, flags=re.IGNORECASE)
        return "transform", reasons, transformed

    if mode == "warn":
        return "warn", reasons, None

    return "allow", reasons, None


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


def _resolve_canary_rollout_policy(fallback_policy: dict, request_tag: str | None) -> tuple[dict, str | None]:
    policy = fallback_policy.get("canary_rollout") if isinstance(fallback_policy, dict) else None
    if not isinstance(policy, dict):
        policy = {}

    normalized_tag = _normalize_request_tag(request_tag)
    if not normalized_tag:
        return policy, None

    tagged = fallback_policy.get("canary_rollout_by_tag") if isinstance(fallback_policy, dict) else None
    if not isinstance(tagged, dict):
        return policy, None

    selected = tagged.get(normalized_tag)
    if not isinstance(selected, dict):
        return policy, None
    return selected, normalized_tag


def _set_canary_rollout_policy(fallback_policy: dict, request_tag: str | None, policy: dict) -> None:
    if request_tag:
        tagged = fallback_policy.get("canary_rollout_by_tag") if isinstance(fallback_policy, dict) else None
        if not isinstance(tagged, dict):
            tagged = {}
        tagged[request_tag] = policy
        fallback_policy["canary_rollout_by_tag"] = tagged
        return
    fallback_policy["canary_rollout"] = policy


def _parse_canary_cohort_values(raw: object, field_name: str) -> list[str]:
    if isinstance(raw, list):
        source = raw
    else:
        source = _parse_string_list(str(raw or "[]"), field_name)
    normalized: list[str] = []
    for item in source:
        value = str(item or "").strip()
        if not value:
            continue
        if value not in normalized:
            normalized.append(value)
    return normalized


def _matches_canary_cohort(policy: dict, *, request_tag: str | None, owner_scope: str | None) -> bool:
    cohort_request_tags = _parse_canary_cohort_values(policy.get("cohort_request_tags", []), "cohort_request_tags")
    cohort_owner_scopes = _parse_canary_cohort_values(policy.get("cohort_owner_scopes", []), "cohort_owner_scopes")

    if cohort_request_tags:
        normalized_request_tag = _normalize_request_tag(request_tag)
        if not normalized_request_tag or normalized_request_tag not in cohort_request_tags:
            return False

    if cohort_owner_scopes:
        normalized_owner_scope = str(owner_scope or "").strip().lower()
        if not normalized_owner_scope:
            return False
        allowed = [str(item).strip().lower() for item in cohort_owner_scopes if str(item).strip()]
        if not any(normalized_owner_scope.startswith(candidate) for candidate in allowed):
            return False

    return True


def _apply_canary_rollout_to_provider_configs(
    provider_configs: list[dict],
    *,
    fallback_policy: dict,
    request_tag: str | None,
    tenant_id: str,
    environment: str,
    owner_scope: str | None,
    request_id: str,
) -> tuple[list[dict], dict | None, str | None, str]:
    canary_policy, selected_tag = _resolve_canary_rollout_policy(fallback_policy, request_tag)
    if not canary_policy:
        return provider_configs, None, selected_tag, "none"

    if not bool(canary_policy.get("enabled", False)):
        return provider_configs, canary_policy, selected_tag, "disabled"

    canary_tenant_id = str(canary_policy.get("tenant_id") or "").strip()
    canary_environment = str(canary_policy.get("environment") or "dev").strip().lower() or "dev"
    if canary_tenant_id and canary_tenant_id != str(tenant_id or "").strip():
        return provider_configs, canary_policy, selected_tag, "tenant_mismatch"
    if canary_environment != str(environment or "dev").strip().lower():
        return provider_configs, canary_policy, selected_tag, "environment_mismatch"

    if not _matches_canary_cohort(canary_policy, request_tag=request_tag, owner_scope=owner_scope):
        return provider_configs, canary_policy, selected_tag, "cohort_mismatch"

    canary_targets = canary_policy.get("canary_targets") if isinstance(canary_policy.get("canary_targets"), list) else []
    if not canary_targets:
        return provider_configs, canary_policy, selected_tag, "missing_targets"

    bucket = (abs(hash(f"{request_id}:{selected_tag or 'global'}")) % 100) + 1
    cumulative = 0
    selected_canary_provider_id: str | None = None
    for target in canary_targets:
        if not isinstance(target, dict):
            continue
        provider_id = str(target.get("provider_id") or "").strip()
        traffic_percent = target.get("traffic_percent")
        if not provider_id or not isinstance(traffic_percent, int) or traffic_percent < 1 or traffic_percent > 100:
            continue
        cumulative += traffic_percent
        if bucket <= cumulative:
            selected_canary_provider_id = provider_id
            break

    if not selected_canary_provider_id:
        return provider_configs, canary_policy, selected_tag, "baseline_routed"

    baseline_provider_id = str(canary_policy.get("baseline_provider_id") or "").strip()
    updated_configs: list[dict] = []
    for config in provider_configs:
        cloned = dict(config)
        raw_order = config.get("priority_order") if isinstance(config.get("priority_order"), list) else []
        filtered = [
            dict(item)
            for item in raw_order
            if isinstance(item, dict) and str(item.get("provider_id") or "").strip() not in {selected_canary_provider_id, baseline_provider_id}
        ]
        injected = [{"provider_id": selected_canary_provider_id, "priority": 1}]
        if baseline_provider_id:
            injected.append({"provider_id": baseline_provider_id, "priority": 2})
        cloned["priority_order"] = injected + filtered
        updated_configs.append(cloned)

    return updated_configs, canary_policy, selected_tag, "canary_selected"


def _evaluate_canary_gate_transition(policy: dict, *, final_outcome: str) -> str:
    metrics = policy.get("gate_metrics") if isinstance(policy.get("gate_metrics"), dict) else {}
    evaluated_requests = int(metrics.get("evaluated_requests") or 0) + 1
    success_count = int(metrics.get("success_count") or 0)
    failure_count = int(metrics.get("failure_count") or 0)

    if final_outcome == "success":
        success_count += 1
    else:
        failure_count += 1

    policy["gate_metrics"] = {
        "evaluated_requests": evaluated_requests,
        "success_count": success_count,
        "failure_count": failure_count,
        "updated_at": datetime.utcnow().isoformat(),
    }

    min_requests = policy.get("gate_min_requests") if isinstance(policy.get("gate_min_requests"), int) else None
    if min_requests is None or evaluated_requests < min_requests:
        return "insufficient_samples"

    success_rate = float(success_count / evaluated_requests) if evaluated_requests > 0 else 0.0
    failure_rate = float(failure_count / evaluated_requests) if evaluated_requests > 0 else 0.0

    max_failure_rate = policy.get("gate_max_failure_rate")
    if isinstance(max_failure_rate, (int, float)) and failure_rate > float(max_failure_rate):
        policy["enabled"] = False
        policy["status"] = "auto_stopped_failure_gate"
        policy["stopped_at"] = datetime.utcnow().isoformat()
        policy["updated_at"] = datetime.utcnow().isoformat()
        return "auto_stop"

    min_success_rate = policy.get("gate_min_success_rate")
    if isinstance(min_success_rate, (int, float)) and success_rate >= float(min_success_rate):
        policy["enabled"] = False
        policy["status"] = "auto_promoted_success_gate"
        policy["promoted_at"] = datetime.utcnow().isoformat()
        policy["updated_at"] = datetime.utcnow().isoformat()
        return "auto_promote"

    return "hold"


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


def _serialize_openai_batch_record(record: OpenAIBatchRecord) -> dict[str, object]:
    return {
        "id": record.batch_id,
        "object": "batch",
        "status": record.status,
        "endpoint_family": record.endpoint_family,
        "request_count": int(record.request_count or 0),
        "completed_count": int(record.completed_count or 0),
        "failed_count": int(record.failed_count or 0),
        "request_id": record.request_id,
        "trace_id": record.trace_id,
        "created_at": int(record.created_at.timestamp()),
        "metadata": _parse_json_object(str(record.metadata_json or "{}"), "metadata"),
    }


def _serialize_realtime_session_record(record: RealtimeSessionRecord) -> dict[str, object]:
    requested_modalities = _parse_json_array(str(record.requested_modalities_json or "[]"), "requested_modalities")
    stream_policy = _parse_json_object(str(record.stream_policy_json or "{}"), "stream_policy")
    closed_at = int(record.closed_at.timestamp()) if record.closed_at is not None else None
    return {
        "id": record.session_id,
        "object": "realtime.session",
        "status": record.status,
        "model": record.model_name,
        "session_label": record.session_label,
        "requested_modalities": [str(item).strip() for item in requested_modalities if str(item).strip()],
        "stream_policy": stream_policy,
        "event_count": int(record.event_count or 0),
        "total_event_bytes": int(record.total_event_bytes or 0),
        "last_event_type": record.last_event_type,
        "created_at": int(record.created_at.timestamp()),
        "expires_at": int(record.expires_at.timestamp()),
        "closed_at": closed_at,
        "request_id": record.request_id,
        "trace_id": record.trace_id,
    }


def _is_prod_environment(value: str) -> bool:
    return value.strip().lower() == "prod"


def _require_prod_dual_approval_audited(
    db: Session,
    ctx: ActorContext,
    *,
    environment: str,
    action_type: str,
    resource_type: str,
    resource_id: str,
    trace_prefix: str,
) -> None:
    if not _is_prod_environment(environment):
        return
    trace_id = f"{trace_prefix}-{uuid4()}"
    try:
        require_dual_approval(ctx)
    except HTTPException as exc:
        if exc.status_code == 403:
            create_audit_event(
                db,
                actor_id=ctx.actor_id,
                action_type=action_type,
                resource_type=resource_type,
                resource_id=resource_id,
                trace_id=trace_id,
                decision_outcome="deny",
                environment=environment,
            )
            db.commit()
        raise


def _reraise_gateway_authz_denial_with_audit(
    db: Session,
    ctx: ActorContext,
    exc: HTTPException,
    *,
    action_type: str,
    resource_type: str,
    resource_id: str,
    environment: str | None = None,
    trace_prefix: str = "trace-gateway-authz-deny",
) -> None:
    detail = exc.detail if isinstance(exc.detail, dict) else {}
    error_code = str(detail.get("error_code") or "").strip()
    if exc.status_code == 403 and error_code in {"AUTHZ_SCOPE_FORBIDDEN", "AUTHZ_DUAL_APPROVAL_REQUIRED"}:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type=action_type,
            resource_type=resource_type,
            resource_id=resource_id,
            trace_id=f"{trace_prefix}-{uuid4()}",
            decision_outcome="deny",
            environment=environment,
        )
        db.commit()
    raise exc


def _is_runtime_prod_environment() -> bool:
    runtime_env = (os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "dev").strip().lower()
    return runtime_env in {"prod", "production"}


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

    if "policy_mode" in policy:
        value = str(policy.get("policy_mode") or "").strip().lower()
        if value not in {"block", "warn", "monitor"}:
            raise HTTPException(status_code=422, detail="guardrail_policy.policy_mode must be block, warn, or monitor")
        normalized["policy_mode"] = value

    for stage_key in ("input_stages", "output_stages"):
        if stage_key in policy:
            stage_values = policy.get(stage_key)
            if not isinstance(stage_values, list) or any(not isinstance(item, str) for item in stage_values):
                raise HTTPException(status_code=422, detail=f"guardrail_policy.{stage_key} must be a JSON array of strings")
            normalized[stage_key] = sorted({item.strip().lower() for item in stage_values if item.strip()})

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
    stage = str(payload.stage or "input").strip().lower()
    policy_mode = str(policy.get("policy_mode") or payload.policy_mode or "block").strip().lower()
    owner_scope_id = str(payload.owner_scope_id or key.owner_scope_id or "").strip()
    input_stages = {str(item).strip().lower() for item in policy.get("input_stages", []) if str(item).strip()}
    output_stages = {str(item).strip().lower() for item in policy.get("output_stages", []) if str(item).strip()}

    def stage_allowed(stage_name: str) -> bool:
        if stage_name == "input" and input_stages:
            return stage in input_stages
        if stage_name == "output" and output_stages:
            return stage in output_stages
        return True

    allowed_environments = policy.get("allowed_environments")
    if isinstance(allowed_environments, list) and stage_allowed("input"):
        applied.append("allowed_environments")
        if environment not in allowed_environments:
            reasons.append(f"environment '{environment}' is not allowed")

    blocked_owner_scope_ids = policy.get("blocked_owner_scope_ids")
    if isinstance(blocked_owner_scope_ids, list) and stage_allowed("input"):
        applied.append("blocked_owner_scope_ids")
        if owner_scope_id and owner_scope_id in blocked_owner_scope_ids:
            reasons.append(f"owner scope '{owner_scope_id}' is blocked")

    max_requests_per_minute = policy.get("max_requests_per_minute")
    if isinstance(max_requests_per_minute, int) and stage_allowed("input"):
        applied.append("max_requests_per_minute")
        if payload.requests_last_minute > max_requests_per_minute:
            reasons.append(
                f"requests_last_minute {payload.requests_last_minute} exceeds {max_requests_per_minute}"
            )

    max_input_tokens = policy.get("max_input_tokens")
    if isinstance(max_input_tokens, int) and stage_allowed("input"):
        applied.append("max_input_tokens")
        if payload.input_tokens > max_input_tokens:
            reasons.append(f"input_tokens {payload.input_tokens} exceeds {max_input_tokens}")

    max_output_tokens = policy.get("max_output_tokens")
    if isinstance(max_output_tokens, int) and stage_allowed("output"):
        applied.append("max_output_tokens")
        if payload.output_tokens > max_output_tokens:
            reasons.append(f"output_tokens {payload.output_tokens} exceeds {max_output_tokens}")

    require_mfa_for_prod = bool(policy.get("require_mfa_for_prod", False))
    if require_mfa_for_prod and stage_allowed("input"):
        applied.append("require_mfa_for_prod")
        if environment == "prod" and not payload.mfa_verified:
            reasons.append("mfa must be verified for prod usage")

    deny_on_weekends = bool(policy.get("deny_on_weekends", False))
    if deny_on_weekends and stage_allowed("input"):
        applied.append("deny_on_weekends")
        if datetime.utcnow().weekday() >= 5:
            reasons.append("weekend traffic is blocked by policy")

    if policy_mode in {"warn", "monitor"}:
        applied.append(f"policy_mode:{policy_mode}")
        if reasons:
            if policy_mode == "warn":
                reasons = [f"warning: {reason}" for reason in reasons]
            return ("allow", reasons, applied)
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


def _should_enforce_tenant_model_entitlement(provider_type: str) -> bool:
    normalized_provider_type = str(provider_type or "").strip().lower()
    # Cursor-backed gateway inference resolves credentials server-side and does not
    # use the supported-model catalog entitlement matrix.
    return normalized_provider_type not in {"", "cursor"}


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

    if not _should_enforce_tenant_model_entitlement(normalized_provider_type):
        return

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


def _normalize_embedding_inputs(raw_input: object) -> list[str]:
    inputs: list[str] = []
    if isinstance(raw_input, str):
        inputs = [raw_input]
    elif isinstance(raw_input, list):
        for item in raw_input:
            if isinstance(item, str):
                inputs.append(item)
            elif isinstance(item, dict):
                content = item.get("content") if "content" in item else item.get("text")
                inputs.append(_message_content_to_text(content))
            else:
                inputs.append(str(item))
    else:
        inputs = [_message_content_to_text(raw_input)]

    normalized = [item.strip() for item in inputs if str(item).strip()]
    if not normalized:
        raise HTTPException(status_code=422, detail="input must contain at least one non-empty string")
    return normalized


def _build_embedding_vector(text: str, dimensions: int) -> list[float]:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    vector: list[float] = []
    for index in range(max(1, dimensions)):
        byte_value = digest[index % len(digest)]
        vector.append(round((byte_value / 255.0) * 2.0 - 1.0, 6))
    return vector


def _document_to_text(raw_document: object) -> str:
    if isinstance(raw_document, str):
        return raw_document.strip()
    if isinstance(raw_document, dict):
        for key in ("text", "content", "document", "input"):
            value = raw_document.get(key)
            if value is not None:
                return _message_content_to_text(value).strip()
        return json.dumps(raw_document, sort_keys=True, separators=(",", ":"))
    return _message_content_to_text(raw_document).strip()


def _build_tiny_png_b64(prompt: str, size: str, index: int) -> str:
    # Deterministic placeholder image payload for governed compatibility testing.
    base = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO3ZL2cAAAAASUVORK5CYII="
    return base


def _normalize_audio_text(text: str) -> str:
    return " ".join(str(text or "").split()).strip()


def _normalize_modalities(raw_modalities: list[str]) -> list[str]:
    normalized = [str(item).strip().lower() for item in raw_modalities if str(item).strip()]
    if not normalized:
        return ["text"]
    deduped: list[str] = []
    for item in normalized:
        if item not in deduped:
            deduped.append(item)
    return deduped


def _normalize_realtime_inline_event_types(raw_event_types: object) -> list[str]:
    if not isinstance(raw_event_types, list):
        return ["input.audio.append", "input.video.append"]
    normalized: list[str] = []
    for raw in raw_event_types:
        value = str(raw or "").strip().lower()
        if not value:
            continue
        if value not in normalized:
            normalized.append(value)
    return normalized or ["input.audio.append", "input.video.append"]


def _payload_has_correlation_id(payload: object) -> bool:
    if not isinstance(payload, dict):
        return False
    for key in ("trace_id", "media_id", "chunk_id", "correlation_id"):
        value = payload.get(key)
        if str(value or "").strip():
            return True
    return False


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
    "/gateway/routes/{route_policy_id}/input-data-policy",
    response_model=RouteInputDataPolicyResponse,
)
def upsert_route_input_data_policy(
    route_policy_id: str,
    payload: RouteInputDataPolicyRequest,
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
    normalized = {
        "tenant_id": payload.tenant_id,
        "environment": payload.environment,
        "policy_mode": str(payload.policy_mode or "warn").strip().lower() or "warn",
        "data_classes": _parse_input_data_classes(payload.data_classes, "data_classes"),
        "block_patterns": _parse_output_guardrail_phrases(payload.block_patterns, "block_patterns"),
        "mask_token": str(payload.mask_token or "[REDACTED]").strip() or "[REDACTED]",
        "enforce": bool(payload.enforce),
        "updated_at": datetime.utcnow().isoformat(),
    }

    if normalized_request_tag:
        tagged = fallback.get("input_data_policy_by_tag") if isinstance(fallback, dict) else None
        if not isinstance(tagged, dict):
            tagged = {}
        tagged[normalized_request_tag] = normalized
        fallback["input_data_policy_by_tag"] = tagged
    else:
        fallback["input_data_policy"] = normalized

    route.fallback_policy = json.dumps(fallback, separators=(",", ":"))
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.route.input_data_policy.update",
        resource_type="route_policy",
        resource_id=route_policy_id,
        trace_id=f"trace-route-input-data-policy-{route_policy_id}",
    )
    db.commit()

    return {
        "route_policy_id": route_policy_id,
        "tenant_id": payload.tenant_id,
        "environment": payload.environment,
        "request_tag": normalized_request_tag,
        "policy_mode": normalized["policy_mode"],
        "data_classes": json.dumps(normalized["data_classes"], separators=(",", ":")),
        "block_patterns": json.dumps(normalized["block_patterns"], separators=(",", ":")),
        "mask_token": normalized["mask_token"],
        "enforce": bool(payload.enforce),
    }


@router.get(
    "/gateway/routes/{route_policy_id}/input-data-policy",
    response_model=RouteInputDataPolicyResponse,
)
def get_route_input_data_policy(
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
    policy, selected_request_tag = _resolve_input_data_policy(fallback, request_tag)
    tenant_id = str(policy.get("tenant_id") or "unscoped")
    environment = str(policy.get("environment") or "prod")
    policy_mode = str(policy.get("policy_mode") or "warn").strip().lower() or "warn"
    data_classes = policy.get("data_classes") if isinstance(policy.get("data_classes"), list) else []
    block_patterns = policy.get("block_patterns") if isinstance(policy.get("block_patterns"), list) else []
    mask_token = str(policy.get("mask_token") or "[REDACTED]").strip() or "[REDACTED]"

    return {
        "route_policy_id": route_policy_id,
        "tenant_id": tenant_id,
        "environment": environment,
        "request_tag": selected_request_tag,
        "policy_mode": policy_mode,
        "data_classes": json.dumps(data_classes, separators=(",", ":")),
        "block_patterns": json.dumps(block_patterns, separators=(",", ":")),
        "mask_token": mask_token,
        "enforce": bool(policy.get("enforce", True)),
    }


@router.put(
    "/gateway/routes/{route_policy_id}/output-guardrails",
    response_model=RouteOutputGuardrailsResponse,
)
def upsert_route_output_guardrails(
    route_policy_id: str,
    payload: RouteOutputGuardrailsRequest,
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
    normalized = {
        "tenant_id": payload.tenant_id,
        "environment": payload.environment,
        "policy_mode": str(payload.policy_mode or "warn").strip().lower() or "warn",
        "blocked_phrases": _parse_output_guardrail_phrases(payload.blocked_phrases, "blocked_phrases"),
        "redact_phrases": _parse_output_guardrail_phrases(payload.redact_phrases, "redact_phrases"),
        "max_output_tokens": payload.max_output_tokens,
        "enforce": bool(payload.enforce),
        "updated_at": datetime.utcnow().isoformat(),
    }

    if normalized_request_tag:
        tagged = fallback.get("output_guardrails_by_tag") if isinstance(fallback, dict) else None
        if not isinstance(tagged, dict):
            tagged = {}
        tagged[normalized_request_tag] = normalized
        fallback["output_guardrails_by_tag"] = tagged
    else:
        fallback["output_guardrails"] = normalized

    route.fallback_policy = json.dumps(fallback, separators=(",", ":"))
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.route.output_guardrails.update",
        resource_type="route_policy",
        resource_id=route_policy_id,
        trace_id=f"trace-route-output-guardrails-{route_policy_id}",
    )
    db.commit()

    return {
        "route_policy_id": route_policy_id,
        "tenant_id": payload.tenant_id,
        "environment": payload.environment,
        "request_tag": normalized_request_tag,
        "policy_mode": normalized["policy_mode"],
        "blocked_phrases": json.dumps(normalized["blocked_phrases"], separators=(",", ":")),
        "redact_phrases": json.dumps(normalized["redact_phrases"], separators=(",", ":")),
        "max_output_tokens": payload.max_output_tokens,
        "enforce": bool(payload.enforce),
    }


@router.get(
    "/gateway/routes/{route_policy_id}/output-guardrails",
    response_model=RouteOutputGuardrailsResponse,
)
def get_route_output_guardrails(
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
    policy, selected_request_tag = _resolve_output_guardrails_policy(fallback, request_tag)
    tenant_id = str(policy.get("tenant_id") or "unscoped")
    environment = str(policy.get("environment") or "prod")
    policy_mode = str(policy.get("policy_mode") or "warn").strip().lower() or "warn"
    blocked_phrases = policy.get("blocked_phrases") if isinstance(policy.get("blocked_phrases"), list) else []
    redact_phrases = policy.get("redact_phrases") if isinstance(policy.get("redact_phrases"), list) else []
    max_output_tokens = policy.get("max_output_tokens") if isinstance(policy.get("max_output_tokens"), int) else None

    return {
        "route_policy_id": route_policy_id,
        "tenant_id": tenant_id,
        "environment": environment,
        "request_tag": selected_request_tag,
        "policy_mode": policy_mode,
        "blocked_phrases": json.dumps(blocked_phrases, separators=(",", ":")),
        "redact_phrases": json.dumps(redact_phrases, separators=(",", ":")),
        "max_output_tokens": max_output_tokens,
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


@router.put(
    "/gateway/routes/{route_policy_id}/canary-rollout",
    response_model=RouteCanaryRolloutResponse,
)
def upsert_route_canary_rollout(
    route_policy_id: str,
    payload: RouteCanaryRolloutRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_AI_OPS_ROLES)
    if _is_prod_environment(payload.environment):
        require_dual_approval(ctx)

    route = db.query(RoutePolicy).filter_by(route_policy_id=route_policy_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Route policy not found")

    normalized_request_tag = _normalize_request_tag(payload.request_tag)
    canary_targets = _parse_canary_targets(payload.canary_targets)
    baseline_provider_id = str(payload.baseline_provider_id or "").strip()
    if any(str(item.get("provider_id") or "").strip() == baseline_provider_id for item in canary_targets):
        raise HTTPException(status_code=422, detail="canary_targets provider_id cannot match baseline_provider_id")

    fallback = _parse_json_object(route.fallback_policy, "fallback_policy")
    existing_policy, _ = _resolve_canary_rollout_policy(fallback, normalized_request_tag)
    now_iso = datetime.utcnow().isoformat()
    created_at = str(existing_policy.get("created_at") or now_iso)
    status = "active" if payload.enabled else "paused"

    policy = {
        "tenant_id": payload.tenant_id,
        "environment": payload.environment,
        "baseline_provider_id": baseline_provider_id,
        "canary_targets": canary_targets,
        "cohort_request_tags": _parse_canary_cohort_values(payload.cohort_request_tags, "cohort_request_tags"),
        "cohort_owner_scopes": _parse_canary_cohort_values(payload.cohort_owner_scopes, "cohort_owner_scopes"),
        "gate_min_requests": payload.gate_min_requests,
        "gate_max_failure_rate": payload.gate_max_failure_rate,
        "gate_min_success_rate": payload.gate_min_success_rate,
        "gate_metrics": existing_policy.get("gate_metrics") if isinstance(existing_policy.get("gate_metrics"), dict) else {},
        "gate_last_decision": existing_policy.get("gate_last_decision"),
        "enabled": bool(payload.enabled),
        "status": status,
        "notes": payload.notes,
        "created_at": created_at,
        "updated_at": now_iso,
        "promoted_at": existing_policy.get("promoted_at"),
        "stopped_at": None if payload.enabled else existing_policy.get("stopped_at"),
    }

    _set_canary_rollout_policy(fallback, normalized_request_tag, policy)
    route.fallback_policy = json.dumps(fallback, separators=(",", ":"))

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.route.canary.update",
        resource_type="route_policy",
        resource_id=route_policy_id,
        trace_id=f"trace-route-canary-update-{route_policy_id}",
    )
    db.commit()

    return {
        "route_policy_id": route_policy_id,
        "tenant_id": payload.tenant_id,
        "environment": payload.environment,
        "request_tag": normalized_request_tag,
        "baseline_provider_id": baseline_provider_id,
        "canary_targets": json.dumps(canary_targets, separators=(",", ":")),
        "cohort_request_tags": json.dumps(policy.get("cohort_request_tags") or [], separators=(",", ":")),
        "cohort_owner_scopes": json.dumps(policy.get("cohort_owner_scopes") or [], separators=(",", ":")),
        "gate_min_requests": policy.get("gate_min_requests"),
        "gate_max_failure_rate": policy.get("gate_max_failure_rate"),
        "gate_min_success_rate": policy.get("gate_min_success_rate"),
        "gate_metrics": json.dumps(policy.get("gate_metrics") or {}, separators=(",", ":")),
        "gate_last_decision": str(policy.get("gate_last_decision")) if policy.get("gate_last_decision") else None,
        "enabled": bool(payload.enabled),
        "status": status,
        "notes": payload.notes,
        "created_at": created_at,
        "updated_at": now_iso,
        "promoted_at": policy.get("promoted_at"),
        "stopped_at": policy.get("stopped_at"),
    }


@router.get(
    "/gateway/routes/{route_policy_id}/canary-rollout",
    response_model=RouteCanaryRolloutResponse,
)
def get_route_canary_rollout(
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
    policy, selected_request_tag = _resolve_canary_rollout_policy(fallback, request_tag)
    if not policy:
        raise HTTPException(status_code=404, detail="Canary rollout not found")

    canary_targets = policy.get("canary_targets") if isinstance(policy.get("canary_targets"), list) else []
    cohort_request_tags = policy.get("cohort_request_tags") if isinstance(policy.get("cohort_request_tags"), list) else []
    cohort_owner_scopes = policy.get("cohort_owner_scopes") if isinstance(policy.get("cohort_owner_scopes"), list) else []
    return {
        "route_policy_id": route_policy_id,
        "tenant_id": str(policy.get("tenant_id") or "unscoped"),
        "environment": str(policy.get("environment") or "prod"),
        "request_tag": selected_request_tag,
        "baseline_provider_id": str(policy.get("baseline_provider_id") or ""),
        "canary_targets": json.dumps(canary_targets, separators=(",", ":")),
        "cohort_request_tags": json.dumps(cohort_request_tags, separators=(",", ":")),
        "cohort_owner_scopes": json.dumps(cohort_owner_scopes, separators=(",", ":")),
        "gate_min_requests": policy.get("gate_min_requests") if isinstance(policy.get("gate_min_requests"), int) else None,
        "gate_max_failure_rate": float(policy.get("gate_max_failure_rate")) if isinstance(policy.get("gate_max_failure_rate"), (int, float)) else None,
        "gate_min_success_rate": float(policy.get("gate_min_success_rate")) if isinstance(policy.get("gate_min_success_rate"), (int, float)) else None,
        "gate_metrics": json.dumps(policy.get("gate_metrics") if isinstance(policy.get("gate_metrics"), dict) else {}, separators=(",", ":")),
        "gate_last_decision": str(policy.get("gate_last_decision")) if policy.get("gate_last_decision") else None,
        "enabled": bool(policy.get("enabled", False)),
        "status": str(policy.get("status") or "unknown"),
        "notes": str(policy.get("notes")) if policy.get("notes") is not None else None,
        "created_at": str(policy.get("created_at") or ""),
        "updated_at": str(policy.get("updated_at") or ""),
        "promoted_at": str(policy.get("promoted_at")) if policy.get("promoted_at") else None,
        "stopped_at": str(policy.get("stopped_at")) if policy.get("stopped_at") else None,
    }


@router.post(
    "/gateway/routes/{route_policy_id}/canary-rollout/stop",
    response_model=RouteCanaryRolloutResponse,
)
def stop_route_canary_rollout(
    route_policy_id: str,
    payload: RouteCanaryRolloutActionRequest,
    request_tag: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_AI_OPS_ROLES)

    route = db.query(RoutePolicy).filter_by(route_policy_id=route_policy_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Route policy not found")

    fallback = _parse_json_object(route.fallback_policy, "fallback_policy")
    policy, selected_request_tag = _resolve_canary_rollout_policy(fallback, request_tag)
    if not policy:
        raise HTTPException(status_code=404, detail="Canary rollout not found")

    if _is_prod_environment(str(policy.get("environment") or "prod")):
        require_dual_approval(ctx)

    now_iso = datetime.utcnow().isoformat()
    policy["enabled"] = False
    policy["status"] = "stopped"
    policy["updated_at"] = now_iso
    policy["stopped_at"] = now_iso
    if payload.notes is not None:
        policy["notes"] = payload.notes

    _set_canary_rollout_policy(fallback, selected_request_tag, policy)
    route.fallback_policy = json.dumps(fallback, separators=(",", ":"))

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.route.canary.stop",
        resource_type="route_policy",
        resource_id=route_policy_id,
        trace_id=f"trace-route-canary-stop-{route_policy_id}",
    )
    db.commit()

    canary_targets = policy.get("canary_targets") if isinstance(policy.get("canary_targets"), list) else []
    cohort_request_tags = policy.get("cohort_request_tags") if isinstance(policy.get("cohort_request_tags"), list) else []
    cohort_owner_scopes = policy.get("cohort_owner_scopes") if isinstance(policy.get("cohort_owner_scopes"), list) else []
    return {
        "route_policy_id": route_policy_id,
        "tenant_id": str(policy.get("tenant_id") or "unscoped"),
        "environment": str(policy.get("environment") or "prod"),
        "request_tag": selected_request_tag,
        "baseline_provider_id": str(policy.get("baseline_provider_id") or ""),
        "canary_targets": json.dumps(canary_targets, separators=(",", ":")),
        "cohort_request_tags": json.dumps(cohort_request_tags, separators=(",", ":")),
        "cohort_owner_scopes": json.dumps(cohort_owner_scopes, separators=(",", ":")),
        "gate_min_requests": policy.get("gate_min_requests") if isinstance(policy.get("gate_min_requests"), int) else None,
        "gate_max_failure_rate": float(policy.get("gate_max_failure_rate")) if isinstance(policy.get("gate_max_failure_rate"), (int, float)) else None,
        "gate_min_success_rate": float(policy.get("gate_min_success_rate")) if isinstance(policy.get("gate_min_success_rate"), (int, float)) else None,
        "gate_metrics": json.dumps(policy.get("gate_metrics") if isinstance(policy.get("gate_metrics"), dict) else {}, separators=(",", ":")),
        "gate_last_decision": str(policy.get("gate_last_decision")) if policy.get("gate_last_decision") else None,
        "enabled": bool(policy.get("enabled", False)),
        "status": str(policy.get("status") or "stopped"),
        "notes": str(policy.get("notes")) if policy.get("notes") is not None else None,
        "created_at": str(policy.get("created_at") or ""),
        "updated_at": str(policy.get("updated_at") or now_iso),
        "promoted_at": str(policy.get("promoted_at")) if policy.get("promoted_at") else None,
        "stopped_at": str(policy.get("stopped_at")) if policy.get("stopped_at") else None,
    }


@router.post(
    "/gateway/routes/{route_policy_id}/canary-rollout/promote",
    response_model=RouteCanaryRolloutResponse,
)
def promote_route_canary_rollout(
    route_policy_id: str,
    payload: RouteCanaryRolloutActionRequest,
    request_tag: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_AI_OPS_ROLES)

    route = db.query(RoutePolicy).filter_by(route_policy_id=route_policy_id).first()
    if not route:
        raise HTTPException(status_code=404, detail="Route policy not found")

    fallback = _parse_json_object(route.fallback_policy, "fallback_policy")
    policy, selected_request_tag = _resolve_canary_rollout_policy(fallback, request_tag)
    if not policy:
        raise HTTPException(status_code=404, detail="Canary rollout not found")

    if _is_prod_environment(str(policy.get("environment") or "prod")):
        require_dual_approval(ctx)

    now_iso = datetime.utcnow().isoformat()
    policy["enabled"] = False
    policy["status"] = "promoted"
    policy["updated_at"] = now_iso
    policy["promoted_at"] = now_iso
    if payload.notes is not None:
        policy["notes"] = payload.notes

    _set_canary_rollout_policy(fallback, selected_request_tag, policy)
    route.fallback_policy = json.dumps(fallback, separators=(",", ":"))

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.route.canary.promote",
        resource_type="route_policy",
        resource_id=route_policy_id,
        trace_id=f"trace-route-canary-promote-{route_policy_id}",
    )
    db.commit()

    canary_targets = policy.get("canary_targets") if isinstance(policy.get("canary_targets"), list) else []
    cohort_request_tags = policy.get("cohort_request_tags") if isinstance(policy.get("cohort_request_tags"), list) else []
    cohort_owner_scopes = policy.get("cohort_owner_scopes") if isinstance(policy.get("cohort_owner_scopes"), list) else []
    return {
        "route_policy_id": route_policy_id,
        "tenant_id": str(policy.get("tenant_id") or "unscoped"),
        "environment": str(policy.get("environment") or "prod"),
        "request_tag": selected_request_tag,
        "baseline_provider_id": str(policy.get("baseline_provider_id") or ""),
        "canary_targets": json.dumps(canary_targets, separators=(",", ":")),
        "cohort_request_tags": json.dumps(cohort_request_tags, separators=(",", ":")),
        "cohort_owner_scopes": json.dumps(cohort_owner_scopes, separators=(",", ":")),
        "gate_min_requests": policy.get("gate_min_requests") if isinstance(policy.get("gate_min_requests"), int) else None,
        "gate_max_failure_rate": float(policy.get("gate_max_failure_rate")) if isinstance(policy.get("gate_max_failure_rate"), (int, float)) else None,
        "gate_min_success_rate": float(policy.get("gate_min_success_rate")) if isinstance(policy.get("gate_min_success_rate"), (int, float)) else None,
        "gate_metrics": json.dumps(policy.get("gate_metrics") if isinstance(policy.get("gate_metrics"), dict) else {}, separators=(",", ":")),
        "gate_last_decision": str(policy.get("gate_last_decision")) if policy.get("gate_last_decision") else None,
        "enabled": bool(policy.get("enabled", False)),
        "status": str(policy.get("status") or "promoted"),
        "notes": str(policy.get("notes")) if policy.get("notes") is not None else None,
        "created_at": str(policy.get("created_at") or ""),
        "updated_at": str(policy.get("updated_at") or now_iso),
        "promoted_at": str(policy.get("promoted_at")) if policy.get("promoted_at") else None,
        "stopped_at": str(policy.get("stopped_at")) if policy.get("stopped_at") else None,
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
    simulated_input_text = str(payload.simulated_input_text or "")

    input_policy_decision, input_policy_reasons, transformed_input_text, input_data_class = _evaluate_input_data_policy(
        fallback,
        tenant_id=payload.tenant_id,
        request_tag=request_tag,
        input_text=simulated_input_text,
        resource="route input data policy",
    )

    if input_policy_decision == "block":
        attempted = [
            {
                "outcome": "blocked_input_data_policy",
                "reasons": input_policy_reasons,
                "data_class": input_data_class,
            }
        ]
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.route.input_data_policy.enforce",
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
            "final_outcome": "blocked_input_data_policy",
        }

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
    provider_configs, active_canary_policy, active_canary_request_tag, canary_routing_decision = _apply_canary_rollout_to_provider_configs(
        provider_configs,
        fallback_policy=fallback,
        request_tag=request_tag,
        tenant_id=payload.tenant_id,
        environment=payload.environment,
        owner_scope=owner_scope,
        request_id=request_id,
    )
    selected_canary_provider_id = None
    if canary_routing_decision == "canary_selected" and provider_configs:
        first_order = provider_configs[0].get("priority_order") if isinstance(provider_configs[0], dict) else None
        if isinstance(first_order, list) and first_order and isinstance(first_order[0], dict):
            selected_canary_provider_id = str(first_order[0].get("provider_id") or "").strip() or None
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

    if input_policy_decision == "warn":
        attempted.append(
            {
                "group_id": selected_group_id or "default",
                "provider_id": selected_provider_id,
                "outcome": "warn_input_data_policy",
                "reasons": input_policy_reasons,
                "data_class": input_data_class,
            }
        )
    elif input_policy_decision == "mask":
        attempted.append(
            {
                "group_id": selected_group_id or "default",
                "provider_id": selected_provider_id,
                "outcome": "masked_input_data_policy",
                "reasons": input_policy_reasons,
                "data_class": input_data_class,
                "masked_input_preview": str(transformed_input_text or "")[:256],
            }
        )

    simulated_output_text = str(payload.simulated_output_text or f"Simulated response from {selected_provider_id or 'no-provider'}")
    output_guardrail_decision = "allow"
    if selected_provider_id is not None and final_outcome == "success":
        output_guardrail_decision, output_guardrail_reasons, transformed_output_text = _evaluate_output_guardrails(
            fallback,
            tenant_id=payload.tenant_id,
            request_tag=request_tag,
            output_tokens=payload.output_tokens,
            output_text=simulated_output_text,
            resource="route output guardrails",
        )
        if output_guardrail_decision == "block":
            attempted.append(
                {
                    "group_id": selected_group_id or "default",
                    "provider_id": selected_provider_id,
                    "outcome": "blocked_output_guardrail",
                    "reasons": output_guardrail_reasons,
                }
            )
            selected_group_id = None
            selected_provider_id = None
            final_outcome = "blocked_output_guardrail"
        elif output_guardrail_decision == "transform":
            attempted.append(
                {
                    "group_id": selected_group_id or "default",
                    "provider_id": selected_provider_id,
                    "outcome": "transformed_output_guardrail",
                    "reasons": output_guardrail_reasons,
                    "transformed_output_preview": str(transformed_output_text or simulated_output_text)[:256],
                }
            )
            final_outcome = "transformed_output_guardrail"
        elif output_guardrail_decision == "warn":
            attempted.append(
                {
                    "group_id": selected_group_id or "default",
                    "provider_id": selected_provider_id,
                    "outcome": "warn_output_guardrail",
                    "reasons": output_guardrail_reasons,
                }
            )

    if output_guardrail_decision != "allow":
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.route.output_guardrails.enforce",
            resource_type="route_policy",
            resource_id=route_policy_id,
            trace_id=trace_id,
            decision_outcome="deny" if output_guardrail_decision == "block" else "allow",
        )

    if input_policy_decision in {"warn", "mask"}:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.route.input_data_policy.enforce",
            resource_type="route_policy",
            resource_id=route_policy_id,
            trace_id=trace_id,
            decision_outcome="allow",
        )

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

    if active_canary_policy is not None and canary_routing_decision == "canary_selected" and selected_canary_provider_id:
        successful_outcomes = {"success", "warn_output_guardrail", "transformed_output_guardrail"}
        canary_success = selected_provider_id == selected_canary_provider_id and final_outcome in successful_outcomes
        gate_decision = _evaluate_canary_gate_transition(
            active_canary_policy,
            final_outcome="success" if canary_success else "failed",
        )
        active_canary_policy["gate_last_decision"] = gate_decision
        _set_canary_rollout_policy(fallback, active_canary_request_tag, active_canary_policy)

        if gate_decision == "auto_stop":
            create_audit_event(
                db,
                actor_id=ctx.actor_id,
                action_type="gateway.route.canary.auto_stop",
                resource_type="route_policy",
                resource_id=route_policy_id,
                trace_id=trace_id,
                decision_outcome="deny",
            )
        elif gate_decision == "auto_promote":
            create_audit_event(
                db,
                actor_id=ctx.actor_id,
                action_type="gateway.route.canary.auto_promote",
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
    parsed_non_cache_classes = _parse_string_list(payload.non_cache_data_classes, "non_cache_data_classes")
    canonical_non_cache_classes = sorted({str(item).strip().lower() for item in parsed_non_cache_classes if str(item).strip()})
    policy = CachePolicy(
        cache_policy_id=str(uuid4()),
        scope=payload.scope,
        ttl_seconds=payload.ttl_seconds,
        key_strategy=payload.key_strategy,
        invalidation_strategy=payload.invalidation_strategy,
        privacy_mode=payload.privacy_mode,
        privacy_scope=payload.privacy_scope,
        non_cache_data_classes=json.dumps(canonical_non_cache_classes),
        cache_mode=payload.cache_mode,
        similarity_threshold=payload.similarity_threshold,
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
    semantic_policies = int(
        db.query(func.count(CachePolicy.cache_policy_id))
        .filter(CachePolicy.status == "active")
        .filter(CachePolicy.cache_mode == "semantic")
        .scalar()
        or 0
    )
    avg_ttl_seconds = float(
        db.query(func.coalesce(func.avg(CachePolicy.ttl_seconds), 0.0)).filter(CachePolicy.status == "active").scalar() or 0.0
    )
    avg_similarity_threshold = float(
        db.query(func.coalesce(func.avg(CachePolicy.similarity_threshold), 0.0)).filter(CachePolicy.status == "active").scalar() or 0.0
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
    entry_stats = cache_entry_stats(db)

    return {
        "hit_ratio": hit_ratio,
        "eligible_requests": eligible_requests,
        "hits": hit_count,
        "misses": miss_count,
        "active_policies": active_policies,
        "semantic_policies": semantic_policies,
        "avg_ttl_seconds": avg_ttl_seconds,
        "avg_similarity_threshold": avg_similarity_threshold,
        **entry_stats,
    }


@router.get("/gateway/cache/health", response_model=GatewayCacheHealthResponse)
def cache_health(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)

    active_policies = int(db.query(func.count(CachePolicy.cache_policy_id)).filter(CachePolicy.status == "active").scalar() or 0)
    semantic_policies = int(
        db.query(func.count(CachePolicy.cache_policy_id))
        .filter(CachePolicy.status == "active")
        .filter(CachePolicy.cache_mode == "semantic")
        .scalar()
        or 0
    )
    avg_ttl_seconds = float(
        db.query(func.coalesce(func.avg(CachePolicy.ttl_seconds), 0.0)).filter(CachePolicy.status == "active").scalar() or 0.0
    )
    avg_similarity_threshold = float(
        db.query(func.coalesce(func.avg(CachePolicy.similarity_threshold), 0.0)).filter(CachePolicy.status == "active").scalar() or 0.0
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
    entry_stats = cache_entry_stats(db)

    return {
        "status": "healthy",
        "cache_backend": "policy-managed",
        "active_policies": active_policies,
        "semantic_policies": semantic_policies,
        "avg_ttl_seconds": avg_ttl_seconds,
        "avg_similarity_threshold": avg_similarity_threshold,
        "hit_ratio": hit_ratio,
        "eligible_requests": eligible_requests,
        "hits": hit_count,
        "misses": miss_count,
        "invalidation_requests_last_24h": invalidation_requests_last_24h,
        **entry_stats,
    }


@router.get("/gateway/tunnel/config", response_model=GatewayTunnelConfigResponse)
def gateway_tunnel_config(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    enabled_raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_TUNNEL_ENABLED, "false").strip().lower()
    base_url = str(get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_TUNNEL_BASE_URL, "/gateway/v1") or "/gateway/v1").strip()
    if not base_url.startswith("/"):
        base_url = f"/{base_url}"
    openai_base = base_url if base_url.endswith("/v1") else f"{base_url.rstrip('/')}/v1"
    return {
        "enabled": enabled_raw in {"1", "true", "yes", "on"},
        "base_url": base_url,
        "openai_compatible_base": openai_base,
        "snippets": {
            "curl_chat": (
                f'curl -sS "{openai_base}/chat/completions" '
                '-H "Content-Type: application/json" '
                '-H "Authorization: Bearer $GATEWAY_KEY" '
                '-d \'{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Hello"}]}\''
            ),
            "openai_python": (
                "from openai import OpenAI\n"
                f'client = OpenAI(base_url="https://YOUR_HOST{openai_base}", api_key="YOUR_GATEWAY_KEY")\n'
                'response = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"user","content":"Hello"}])'
            ),
        },
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
    purged_entries = purge_cache_entries(
        db,
        scope=scope,
        cache_keys=cache_keys,
        active_only=payload.active_only,
    )

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
        "purged_cache_entries": purged_entries,
        "active_only": payload.active_only,
    }


@router.get(
    "/gateway/cache/entries",
    response_model=list[GatewayResponseCacheEntryResponse],
    summary="List gateway response cache entries",
    description=(
        "Returns metadata for stored inference cache entries (encrypted response bodies are not returned). "
        "Requires gateway read roles."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action."},
    },
)
def list_cache_entries(
    tenant_id: Optional[str] = Query(default=None),
    cache_policy_id: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default="active"),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    response: Response = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    query = db.query(GatewayResponseCacheEntry)
    if tenant_id:
        query = query.filter(GatewayResponseCacheEntry.tenant_id == tenant_id.strip())
    if cache_policy_id:
        query = query.filter(GatewayResponseCacheEntry.cache_policy_id == cache_policy_id.strip())
    if status:
        query = query.filter(GatewayResponseCacheEntry.status == status.strip().lower())

    total_count = query.count()
    if response is not None:
        response.headers["X-Total-Count"] = str(total_count)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.cache.entry.read",
        resource_type="gateway_response_cache_entry",
        resource_id=cache_policy_id.strip() if cache_policy_id else "cache-entry-query",
        trace_id=f"trace-gateway-cache-entry-read-{uuid4()}",
    )
    db.commit()

    return query.order_by(GatewayResponseCacheEntry.created_at.desc()).offset(offset).limit(limit).all()


@router.get(
    "/gateway/cache/decisions",
    response_model=list[GatewayCacheDecisionEventResponse],
    summary="List gateway cache decisions",
    description=(
        "Returns recent cache decision records (miss/bypass) with explanation and match provenance for operator, "
        "security, and audit investigation workflows."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action."},
    },
)
def list_cache_decisions(
    decision: Optional[str] = Query(default=None),
    tenant_id: Optional[str] = Query(default=None),
    trace_id: Optional[str] = Query(default=None),
    cache_policy_id: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    response: Response = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    query = db.query(CacheDecisionEvent)
    if decision:
        query = query.filter(CacheDecisionEvent.decision == decision.strip().lower())
    if tenant_id:
        query = query.filter(CacheDecisionEvent.tenant_id == tenant_id.strip())
    if trace_id:
        query = query.filter(CacheDecisionEvent.trace_id == trace_id.strip())
    if cache_policy_id:
        query = query.filter(CacheDecisionEvent.cache_policy_id == cache_policy_id.strip())

    total_count = query.count()
    if response is not None:
        response.headers["X-Total-Count"] = str(total_count)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.cache.decision.read",
        resource_type="cache_decision_event",
        resource_id=trace_id.strip() if trace_id else "cache-decision-query",
        trace_id=f"trace-gateway-cache-decision-read-{uuid4()}",
    )
    db.commit()

    return query.order_by(CacheDecisionEvent.timestamp.desc()).offset(offset).limit(limit).all()


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
    completion_id = f"chatcmpl-{uuid4().hex[:24]}"
    selected_provider_id: str | None = None
    selected_route_policy_id: str | None = None

    try:
        require_role(ctx, GATEWAY_INFERENCE_ROLES)
        _ensure_inference_credentials(
            db,
            agent_id=str(getattr(payload, "agent_id", None) or "").strip() or None,
            environment=str(payload.environment or "dev").strip().lower() or "dev",
            model_name=model_name,
        )

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
        push_audit_action_context(
            user_prompt=prompt_preview,
            model=model_name,
            endpoint_family="chat.completions",
        )
        serialized_messages = [
            {"role": str(message.role or "user").strip(), "content": message.content}
            for message in payload.messages
        ]

        owner_scope = str(payload.owner_scope or f"actor:{ctx.actor_id}").strip() or f"actor:{ctx.actor_id}"
        request_fingerprint = _fingerprint_cache_request([
            environment,
            tenant_id,
            selected_route_policy_id or "",
            model_name,
            request_tag or "",
            prompt_preview,
            "chat.completions",
        ])
        cache_pre = None
        if not bool(payload.stream):
            cache_pre = evaluate_pre_inference_cache(
                db,
                actor_id=ctx.actor_id,
                trace_id=trace_id,
                request_id=request_id,
                request_fingerprint=request_fingerprint,
                request_text=prompt_preview,
                tenant_id=tenant_id,
                environment=environment,
                route_policy_id=selected_route_policy_id,
                request_tag=request_tag,
                owner_scope=owner_scope,
                endpoint_family="chat.completions",
            )
            if cache_pre.cached_response is not None:
                risk_tier, risk_reasons = _assess_gateway_inference_risk(
                    model_name=model_name,
                    environment=environment,
                    has_tool_calls=False,
                    selected_provider_id=selected_provider_id,
                )
                refreshed = dict(cache_pre.cached_response)
                refreshed["request_id"] = request_id
                refreshed["trace_id"] = trace_id
                refreshed["cache_short_circuit"] = True
                refreshed["risk_tier"] = risk_tier
                refreshed["risk_reasons"] = risk_reasons
                refreshed["selected_provider_id"] = selected_provider_id
                refreshed["route_policy_id"] = selected_route_policy_id
                create_audit_event(
                    db,
                    actor_id=ctx.actor_id,
                    action_type="gateway.chat.completions",
                    resource_type="gateway_inference",
                    resource_id=model_name,
                    trace_id=trace_id,
                )
                db.commit()
                return refreshed

        response_format_type = str((payload.response_format or {}).get("type") or "").strip().lower()
        if response_format_type and response_format_type not in {"json_object", "text"}:
            raise HTTPException(status_code=422, detail="response_format.type must be one of: json_object, text")

        inference_credential = resolve_inference_credential(
            db,
            agent_id=str(getattr(payload, "agent_id", None) or "").strip() or None,
            environment=environment,
            model_name=model_name,
            tenant_id=tenant_id or None,
            selected_provider_id=selected_provider_id,
            resolve_gateway_cursor_token=_resolve_gateway_cursor_api_token,
        )

        if bool(payload.stream) and inference_credential is not None and should_attempt_upstream(inference_credential):
            effective_credential = ResolvedInferenceCredential(
                provider_type=inference_credential.provider_type,
                api_key=inference_credential.api_key,
                base_url=inference_credential.base_url,
                upstream_model=inference_credential.upstream_model
                or (_split_provider_model(model_name)[1] or model_name),
                credential_source=inference_credential.credential_source,
            )

            def _upstream_stream_chunks():
                created_ts = int(datetime.utcnow().timestamp())
                try:
                    for chunk in stream_chat_completion(
                        effective_credential,
                        messages=serialized_messages,
                        temperature=payload.temperature,
                        top_p=payload.top_p,
                        max_tokens=payload.max_tokens,
                        stop=stop_sequences or None,
                        response_format=payload.response_format,
                    ):
                        if chunk == "[DONE]":
                            yield "data: [DONE]\n\n"
                            continue
                        try:
                            parsed = json.loads(chunk)
                        except json.JSONDecodeError:
                            continue
                        if isinstance(parsed, dict):
                            parsed.setdefault("id", completion_id)
                            parsed.setdefault("object", "chat.completion.chunk")
                            parsed.setdefault("created", created_ts)
                            parsed.setdefault("model", model_name)
                            yield f"data: {json.dumps(parsed, separators=(',', ':'))}\n\n"
                except HTTPException as exc:
                    error_chunk = {
                        "id": completion_id,
                        "object": "chat.completion.chunk",
                        "created": created_ts,
                        "model": model_name,
                        "choices": [
                            {
                                "index": 0,
                                "delta": {},
                                "finish_reason": "error",
                            }
                        ],
                        "error": {"message": str(exc.detail)},
                    }
                    yield f"data: {json.dumps(error_chunk, separators=(',', ':'))}\n\n"
                yield "data: [DONE]\n\n"

            create_audit_event(
                db,
                actor_id=ctx.actor_id,
                action_type="gateway.chat.completions",
                resource_type="gateway_inference",
                resource_id=model_name,
                trace_id=trace_id,
            )
            db.commit()
            return StreamingResponse(_upstream_stream_chunks(), media_type="text/event-stream")

        inference_result = execute_chat_completion(
            db,
            credential=inference_credential,
            model_name=model_name,
            messages=serialized_messages,
            prompt_preview=prompt_preview,
            temperature=payload.temperature,
            top_p=payload.top_p,
            max_tokens=payload.max_tokens,
            stop=stop_sequences or None,
            response_format=payload.response_format,
        )
        completion_text = inference_result.content
        finish_reason = inference_result.finish_reason
        used_upstream = inference_credential is not None and should_attempt_upstream(inference_credential)

        if response_format_type == "json_object" and not used_upstream:
            completion_text = json.dumps({"answer": completion_text}, separators=(",", ":"))

        completion_text, stopped = _apply_stop_sequences(completion_text, stop_sequences)
        if stopped and finish_reason == "stop":
            finish_reason = "stop"

        if payload.max_tokens is not None and not used_upstream:
            words = completion_text.split()
            if len(words) > int(payload.max_tokens):
                completion_text = " ".join(words[: int(payload.max_tokens)]).strip()
                finish_reason = "length"

        prompt_tokens = inference_result.usage.prompt_tokens
        completion_tokens = inference_result.usage.completion_tokens
        if payload.max_tokens is not None and not used_upstream:
            completion_tokens = min(completion_tokens, int(payload.max_tokens))
        total_tokens = inference_result.usage.total_tokens

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

        if cache_pre is not None and cache_pre.short_circuit_active:
            pass
        else:
            _record_cache_decision_event(
                db,
                actor_id=ctx.actor_id,
                trace_id=trace_id,
                request_id=request_id,
                request_fingerprint=request_fingerprint,
                request_text=prompt_preview,
                tenant_id=tenant_id,
                environment=environment,
                route_policy_id=selected_route_policy_id,
                request_tag=request_tag,
                owner_scope=owner_scope,
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

        created_ts = int(datetime.utcnow().timestamp())
        if bool(payload.stream):
            def _stream_chunks():
                first_chunk = {
                    "id": completion_id,
                    "object": "chat.completion.chunk",
                    "created": created_ts,
                    "model": model_name,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {"role": "assistant", "content": completion_text},
                            "finish_reason": None,
                        }
                    ],
                }
                final_chunk = {
                    "id": completion_id,
                    "object": "chat.completion.chunk",
                    "created": created_ts,
                    "model": model_name,
                    "choices": [
                        {
                            "index": 0,
                            "delta": {},
                            "finish_reason": finish_reason,
                        }
                    ],
                }
                yield f"data: {json.dumps(first_chunk, separators=(',', ':'))}\n\n"
                yield f"data: {json.dumps(final_chunk, separators=(',', ':'))}\n\n"
                yield "data: [DONE]\n\n"

            return StreamingResponse(_stream_chunks(), media_type="text/event-stream")

        response_body = {
            "id": completion_id,
            "object": "chat.completion",
            "created": created_ts,
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
        if cache_pre is not None and cache_pre.short_circuit_active:
            finalize_post_inference_cache(
                db,
                pre=cache_pre,
                actor_id=ctx.actor_id,
                trace_id=trace_id,
                request_id=request_id,
                tenant_id=tenant_id,
                environment=environment,
                route_policy_id=selected_route_policy_id,
                response_body=response_body,
                endpoint_family="chat.completions",
                owner_scope=owner_scope,
            )
            db.commit()
        return response_body
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


@router.post("/v1/embeddings", response_model=GatewayOpenAIEmbeddingsResponse)
def gateway_openai_embeddings(
    payload: GatewayOpenAIEmbeddingsRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-embeddings-{uuid4()}"
    model_name = str(payload.model or "").strip() or "unknown"
    request_id = f"gw-emb-{uuid4().hex[:16]}"
    selected_provider_id: str | None = None
    selected_route_policy_id: str | None = None

    try:
        require_role(ctx, GATEWAY_INFERENCE_ROLES)
        _ensure_inference_credentials(
            db,
            agent_id=str(getattr(payload, "agent_id", None) or "").strip() or None,
            environment=str(payload.environment or "dev").strip().lower() or "dev",
            model_name=model_name,
        )

        environment = str(payload.environment or "dev").strip().lower() or "dev"
        request_tag = _normalize_request_tag(payload.request_tag)
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
                resource="embeddings",
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

        normalized_inputs = _normalize_embedding_inputs(payload.input)
        effective_prompt = "\n".join(normalized_inputs)
        prompt_preview = next((item for item in reversed(normalized_inputs) if item.strip()), "")
        instruction_text = ""
        dimensions = int(payload.dimensions or 16)

        inference_credential = resolve_inference_credential(
            db,
            agent_id=str(getattr(payload, "agent_id", None) or "").strip() or None,
            environment=environment,
            model_name=model_name,
            tenant_id=tenant_id or None,
            selected_provider_id=selected_provider_id,
            resolve_gateway_cursor_token=_resolve_gateway_cursor_api_token,
        )

        if inference_credential is not None and should_attempt_upstream(inference_credential):
            effective_credential = ResolvedInferenceCredential(
                provider_type=inference_credential.provider_type,
                api_key=inference_credential.api_key,
                base_url=inference_credential.base_url,
                upstream_model=inference_credential.upstream_model
                or (_split_provider_model(model_name)[1] or model_name),
                credential_source=inference_credential.credential_source,
            )
            embedding_result = invoke_embeddings(
                effective_credential,
                inputs=normalized_inputs,
                dimensions=dimensions if payload.dimensions is not None else None,
            )
            embeddings = [
                {
                    "object": "embedding",
                    "embedding": vector,
                    "index": index,
                }
                for index, vector in enumerate(embedding_result.embeddings)
            ]
            prompt_tokens = embedding_result.usage.prompt_tokens
        elif inference_simulation_enabled():
            embeddings = [
                {
                    "object": "embedding",
                    "embedding": _build_embedding_vector(f"{model_name}:{index}:{text}", dimensions),
                    "index": index,
                }
                for index, text in enumerate(normalized_inputs)
            ]
            prompt_tokens = _estimate_token_count(effective_prompt)
        else:
            raise HTTPException(status_code=503, detail="Inference credentials are not configured for this request")
        model_rates, default_model_rates = _load_model_token_rates(db)
        provider_multipliers, endpoint_multipliers = _load_cloud_component_multipliers(db)
        provider_type_for_cost = "unknown"
        resolved_provider_type_from_model, resolved_model_name = _split_provider_model(model_name)
        if selected_provider_id:
            provider_type_for_cost = _resolve_provider_type(db, selected_provider_id)
        elif resolved_provider_type_from_model:
            provider_type_for_cost = resolved_provider_type_from_model
        cost_model_name = resolved_model_name if resolved_provider_type_from_model else model_name
        estimated_cost_cents = _estimate_hop_cost_cents(
            input_tokens=prompt_tokens,
            output_tokens=0,
            model_name=cost_model_name,
            provider_type=provider_type_for_cost,
            endpoint_family="embeddings",
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
                session_id=str(payload.session_id or f"session-gateway-embeddings-{ctx.actor_id}").strip(),
                agent_id=str(payload.agent_id or "gateway-openai-embeddings").strip() or "gateway-openai-embeddings",
                owner_scope=str(payload.owner_scope or f"actor:{ctx.actor_id}").strip() or f"actor:{ctx.actor_id}",
                environment=environment,
                model_name=model_name,
                endpoint_family="embeddings",
                input_tokens=prompt_tokens,
                output_tokens=0,
                estimated_cost_cents=estimated_cost_cents,
                currency="USD",
            )
        )

        request_fingerprint = _fingerprint_cache_request([
            environment,
            tenant_id,
            selected_route_policy_id or "",
            model_name,
            request_tag or "",
            prompt_preview,
            instruction_text,
        ])

        _record_cache_decision_event(
            db,
            actor_id=ctx.actor_id,
            trace_id=trace_id,
            request_id=request_id,
            request_fingerprint=request_fingerprint,
            request_text=effective_prompt or prompt_preview,
            tenant_id=tenant_id,
            environment=environment,
            route_policy_id=selected_route_policy_id,
            request_tag=request_tag,
            owner_scope=str(payload.owner_scope or f"actor:{ctx.actor_id}").strip() or f"actor:{ctx.actor_id}",
        )

        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.embeddings.create",
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
            "object": "list",
            "data": embeddings,
            "model": model_name,
            "usage": {
                "prompt_tokens": prompt_tokens,
                "total_tokens": prompt_tokens,
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
            action_type="gateway.embeddings.create",
            resource_type="gateway_inference",
            resource_id=model_name,
            trace_id=trace_id,
            decision_outcome="deny" if exc.status_code == 403 else "warn",
        )
        db.commit()
        raise


@router.post("/v1/audio/transcriptions", response_model=GatewayOpenAIAudioResponse)
def gateway_openai_audio_transcriptions(
    payload: GatewayOpenAIAudioTranscriptionRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-audio-transcriptions-{uuid4()}"
    model_name = str(payload.model or "").strip() or "unknown"
    request_id = f"gw-aud-tr-{uuid4().hex[:16]}"
    selected_provider_id: str | None = None
    selected_route_policy_id: str | None = None

    try:
        require_role(ctx, GATEWAY_INFERENCE_ROLES)
        _ensure_inference_credentials(
            db,
            agent_id=str(getattr(payload, "agent_id", None) or "").strip() or None,
            environment=str(payload.environment or "dev").strip().lower() or "dev",
            model_name=model_name,
        )

        environment = str(payload.environment or "dev").strip().lower() or "dev"
        request_tag = _normalize_request_tag(payload.request_tag)
        tenant_id = str(payload.tenant_id or "").strip()
        provider_type_from_model, normalized_model_name = _split_provider_model(model_name)

        if provider_type_from_model and not tenant_id:
            raise HTTPException(status_code=422, detail="tenant_id is required when model includes provider prefix")
        if provider_type_from_model:
            _require_tenant_model_entitlement(
                db,
                tenant_id=tenant_id,
                provider_type=provider_type_from_model,
                model_name=normalized_model_name,
            )

        audio_text = _normalize_audio_text(payload.input_text)
        prompt_text = _normalize_audio_text(payload.prompt or "")
        transcript = audio_text
        duration_seconds = max(1.0, round(len(audio_text) / 12.0, 2))
        if prompt_text:
            transcript = f"{prompt_text}: {audio_text}".strip()

        prompt_tokens = _estimate_token_count(audio_text + "\n" + prompt_text)
        model_rates, default_model_rates = _load_model_token_rates(db)
        provider_multipliers, endpoint_multipliers = _load_cloud_component_multipliers(db)
        provider_type_for_cost = "unknown"
        resolved_provider_type_from_model, resolved_model_name = _split_provider_model(model_name)
        if selected_provider_id:
            provider_type_for_cost = _resolve_provider_type(db, selected_provider_id)
        elif resolved_provider_type_from_model:
            provider_type_for_cost = resolved_provider_type_from_model
        cost_model_name = resolved_model_name if resolved_provider_type_from_model else model_name
        estimated_cost_cents = _estimate_hop_cost_cents(
            input_tokens=prompt_tokens,
            output_tokens=0,
            model_name=cost_model_name,
            provider_type=provider_type_for_cost,
            endpoint_family="audio.transcriptions",
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
                session_id=str(payload.session_id or f"session-gateway-audio-transcriptions-{ctx.actor_id}").strip(),
                agent_id=str(payload.agent_id or "gateway-openai-audio-transcriptions").strip() or "gateway-openai-audio-transcriptions",
                owner_scope=str(payload.owner_scope or f"actor:{ctx.actor_id}").strip() or f"actor:{ctx.actor_id}",
                environment=environment,
                model_name=model_name,
                endpoint_family="audio.transcriptions",
                input_tokens=prompt_tokens,
                output_tokens=0,
                estimated_cost_cents=estimated_cost_cents,
                currency="USD",
            )
        )

        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.audio.transcriptions.create",
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
            "text": transcript,
            "language": payload.language,
            "duration_seconds": duration_seconds,
            "model": model_name,
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
            action_type="gateway.audio.transcriptions.create",
            resource_type="gateway_inference",
            resource_id=model_name,
            trace_id=trace_id,
            decision_outcome="deny" if exc.status_code == 403 else "warn",
        )
        db.commit()
        raise


@router.post("/v1/audio/translations", response_model=GatewayOpenAIAudioResponse)
def gateway_openai_audio_translations(
    payload: GatewayOpenAIAudioTranslationRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-audio-translations-{uuid4()}"
    model_name = str(payload.model or "").strip() or "unknown"
    request_id = f"gw-aud-tl-{uuid4().hex[:16]}"
    selected_provider_id: str | None = None
    selected_route_policy_id: str | None = None

    try:
        require_role(ctx, GATEWAY_INFERENCE_ROLES)
        _ensure_inference_credentials(
            db,
            agent_id=str(getattr(payload, "agent_id", None) or "").strip() or None,
            environment=str(payload.environment or "dev").strip().lower() or "dev",
            model_name=model_name,
        )

        environment = str(payload.environment or "dev").strip().lower() or "dev"
        request_tag = _normalize_request_tag(payload.request_tag)
        tenant_id = str(payload.tenant_id or "").strip()
        provider_type_from_model, normalized_model_name = _split_provider_model(model_name)

        if provider_type_from_model and not tenant_id:
            raise HTTPException(status_code=422, detail="tenant_id is required when model includes provider prefix")
        if provider_type_from_model:
            _require_tenant_model_entitlement(
                db,
                tenant_id=tenant_id,
                provider_type=provider_type_from_model,
                model_name=normalized_model_name,
            )

        source_text = _normalize_audio_text(payload.input_text)
        prompt_text = _normalize_audio_text(payload.prompt or "")
        translated_text = f"[{payload.target_language}] {source_text}"
        if prompt_text:
            translated_text = f"{prompt_text}: {translated_text}"
        duration_seconds = max(1.0, round(len(source_text) / 12.0, 2))

        prompt_tokens = _estimate_token_count(source_text + "\n" + prompt_text + "\n" + payload.target_language)
        model_rates, default_model_rates = _load_model_token_rates(db)
        provider_multipliers, endpoint_multipliers = _load_cloud_component_multipliers(db)
        provider_type_for_cost = "unknown"
        resolved_provider_type_from_model, resolved_model_name = _split_provider_model(model_name)
        if selected_provider_id:
            provider_type_for_cost = _resolve_provider_type(db, selected_provider_id)
        elif resolved_provider_type_from_model:
            provider_type_for_cost = resolved_provider_type_from_model
        cost_model_name = resolved_model_name if resolved_provider_type_from_model else model_name
        estimated_cost_cents = _estimate_hop_cost_cents(
            input_tokens=prompt_tokens,
            output_tokens=0,
            model_name=cost_model_name,
            provider_type=provider_type_for_cost,
            endpoint_family="audio.translations",
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
                session_id=str(payload.session_id or f"session-gateway-audio-translations-{ctx.actor_id}").strip(),
                agent_id=str(payload.agent_id or "gateway-openai-audio-translations").strip() or "gateway-openai-audio-translations",
                owner_scope=str(payload.owner_scope or f"actor:{ctx.actor_id}").strip() or f"actor:{ctx.actor_id}",
                environment=environment,
                model_name=model_name,
                endpoint_family="audio.translations",
                input_tokens=prompt_tokens,
                output_tokens=0,
                estimated_cost_cents=estimated_cost_cents,
                currency="USD",
            )
        )

        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.audio.translations.create",
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
            "text": translated_text,
            "language": payload.target_language,
            "duration_seconds": duration_seconds,
            "model": model_name,
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
            action_type="gateway.audio.translations.create",
            resource_type="gateway_inference",
            resource_id=model_name,
            trace_id=trace_id,
            decision_outcome="deny" if exc.status_code == 403 else "warn",
        )
        db.commit()
        raise


@router.post("/v1/images/generations", response_model=GatewayOpenAIImagesResponse)
@router.post("/v1/images", response_model=GatewayOpenAIImagesResponse)
def gateway_openai_images_generate(
    payload: GatewayOpenAIImagesRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-images-{uuid4()}"
    model_name = str(payload.model or "").strip() or "unknown"
    request_id = f"gw-img-{uuid4().hex[:16]}"
    selected_provider_id: str | None = None
    selected_route_policy_id: str | None = None

    try:
        require_role(ctx, GATEWAY_INFERENCE_ROLES)
        _ensure_inference_credentials(
            db,
            agent_id=str(getattr(payload, "agent_id", None) or "").strip() or None,
            environment=str(payload.environment or "dev").strip().lower() or "dev",
            model_name=model_name,
        )

        environment = str(payload.environment or "dev").strip().lower() or "dev"
        request_tag = _normalize_request_tag(payload.request_tag)
        tenant_id = str(payload.tenant_id or "").strip()
        provider_type_from_model, normalized_model_name = _split_provider_model(model_name)

        if provider_type_from_model and not tenant_id:
            raise HTTPException(status_code=422, detail="tenant_id is required when model includes provider prefix")
        if provider_type_from_model:
            _require_tenant_model_entitlement(
                db,
                tenant_id=tenant_id,
                provider_type=provider_type_from_model,
                model_name=normalized_model_name,
            )

        prompt_text = str(payload.prompt or "").strip()
        created_at = int(datetime.utcnow().timestamp())

        inference_credential = resolve_inference_credential(
            db,
            agent_id=str(getattr(payload, "agent_id", None) or "").strip() or None,
            environment=environment,
            model_name=model_name,
            tenant_id=tenant_id or None,
            selected_provider_id=selected_provider_id,
            resolve_gateway_cursor_token=_resolve_gateway_cursor_api_token,
        )

        if inference_credential is not None and should_attempt_upstream(inference_credential):
            effective_credential = ResolvedInferenceCredential(
                provider_type=inference_credential.provider_type,
                api_key=inference_credential.api_key,
                base_url=inference_credential.base_url,
                upstream_model=inference_credential.upstream_model
                or (_split_provider_model(model_name)[1] or model_name),
                credential_source=inference_credential.credential_source,
            )
            upstream_data = invoke_image_generation(
                effective_credential,
                prompt=prompt_text,
                size=str(payload.size or "").strip() or None,
                n=int(payload.n or 1),
            )
            data = [
                {
                    "b64_json": str(item.get("b64_json") or ""),
                    "revised_prompt": str(item.get("revised_prompt") or prompt_text),
                    "index": index,
                }
                for index, item in enumerate(upstream_data)
            ]
        elif inference_simulation_enabled():
            data = [
                {
                    "b64_json": _build_tiny_png_b64(prompt_text, payload.size, index),
                    "revised_prompt": prompt_text,
                    "index": index,
                }
                for index in range(int(payload.n or 1))
            ]
        else:
            raise HTTPException(status_code=503, detail="Inference credentials are not configured for this request")

        prompt_tokens = _estimate_token_count(prompt_text)
        model_rates, default_model_rates = _load_model_token_rates(db)
        provider_multipliers, endpoint_multipliers = _load_cloud_component_multipliers(db)
        provider_type_for_cost = "unknown"
        resolved_provider_type_from_model, resolved_model_name = _split_provider_model(model_name)
        if selected_provider_id:
            provider_type_for_cost = _resolve_provider_type(db, selected_provider_id)
        elif resolved_provider_type_from_model:
            provider_type_for_cost = resolved_provider_type_from_model
        cost_model_name = resolved_model_name if resolved_provider_type_from_model else model_name
        estimated_cost_cents = _estimate_hop_cost_cents(
            input_tokens=prompt_tokens,
            output_tokens=0,
            model_name=cost_model_name,
            provider_type=provider_type_for_cost,
            endpoint_family="images",
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
                session_id=str(payload.session_id or f"session-gateway-images-{ctx.actor_id}").strip(),
                agent_id=str(payload.agent_id or "gateway-openai-images").strip() or "gateway-openai-images",
                owner_scope=str(payload.owner_scope or f"actor:{ctx.actor_id}").strip() or f"actor:{ctx.actor_id}",
                environment=environment,
                model_name=model_name,
                endpoint_family="images",
                input_tokens=prompt_tokens,
                output_tokens=0,
                estimated_cost_cents=estimated_cost_cents,
                currency="USD",
            )
        )

        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.images.generate",
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
            "created": created_at,
            "data": data,
            "model": model_name,
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
            action_type="gateway.images.generate",
            resource_type="gateway_inference",
            resource_id=model_name,
            trace_id=trace_id,
            decision_outcome="deny" if exc.status_code == 403 else "warn",
        )
        db.commit()
        raise


@router.post("/v1/rerank", response_model=GatewayOpenAIRerankResponse)
def gateway_openai_rerank(
    payload: GatewayOpenAIRerankRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-rerank-{uuid4()}"
    model_name = str(payload.model or "").strip() or "unknown"
    request_id = f"gw-rerank-{uuid4().hex[:16]}"
    selected_provider_id: str | None = None
    selected_route_policy_id: str | None = None

    try:
        require_role(ctx, GATEWAY_INFERENCE_ROLES)
        _ensure_inference_credentials(
            db,
            agent_id=str(getattr(payload, "agent_id", None) or "").strip() or None,
            environment=str(payload.environment or "dev").strip().lower() or "dev",
            model_name=model_name,
        )

        environment = str(payload.environment or "dev").strip().lower() or "dev"
        request_tag = _normalize_request_tag(payload.request_tag)
        tenant_id = str(payload.tenant_id or "").strip()
        provider_type_from_model, normalized_model_name = _split_provider_model(model_name)

        if provider_type_from_model and not tenant_id:
            raise HTTPException(status_code=422, detail="tenant_id is required when model includes provider prefix")
        if provider_type_from_model:
            _require_tenant_model_entitlement(
                db,
                tenant_id=tenant_id,
                provider_type=provider_type_from_model,
                model_name=normalized_model_name,
            )

        query_text = str(payload.query or "").strip()
        documents = list(payload.documents or [])
        normalized_documents = [_document_to_text(document) for document in documents]

        inference_credential = resolve_inference_credential(
            db,
            agent_id=str(getattr(payload, "agent_id", None) or "").strip() or None,
            environment=environment,
            model_name=model_name,
            tenant_id=tenant_id or None,
            selected_provider_id=selected_provider_id,
            resolve_gateway_cursor_token=_resolve_gateway_cursor_api_token,
        )

        if inference_credential is not None and should_attempt_upstream(inference_credential):
            effective_credential = ResolvedInferenceCredential(
                provider_type=inference_credential.provider_type,
                api_key=inference_credential.api_key,
                base_url=inference_credential.base_url,
                upstream_model=inference_credential.upstream_model
                or (_split_provider_model(model_name)[1] or model_name),
                credential_source=inference_credential.credential_source,
            )
            try:
                results = invoke_rerank(
                    effective_credential,
                    query=query_text,
                    documents=normalized_documents,
                    top_n=int(payload.top_n or len(normalized_documents)),
                )
            except HTTPException as exc:
                if exc.status_code != 422 or inference_simulation_enabled():
                    if exc.status_code == 422 and inference_simulation_enabled():
                        results = []
                    else:
                        raise
                else:
                    raise
        else:
            results = []

        if not results:
            if not inference_simulation_enabled() and inference_credential is not None:
                raise HTTPException(status_code=422, detail="Rerank is not supported for the configured provider")
            scored_documents: list[dict[str, object]] = []
            query_terms = {term for term in re.findall(r"[A-Za-z0-9]+", query_text.lower()) if term}

            for index, document in enumerate(normalized_documents):
                document_terms = {term for term in re.findall(r"[A-Za-z0-9]+", document.lower()) if term}
                overlap = len(query_terms & document_terms)
                query_bonus = 1 if query_text and query_text.lower() in document.lower() else 0
                length_penalty = max(0.0, min(len(document) / 5000.0, 0.15))
                score = round(min(1.0, (overlap * 0.15) + (query_bonus * 0.35) + (1.0 / (1.0 + length_penalty))), 6)
                scored_documents.append(
                    {
                        "index": index,
                        "relevance_score": score,
                        "document": documents[index],
                        "_sort": (score, -index),
                    }
                )

            scored_documents.sort(key=lambda item: item["_sort"], reverse=True)
            top_n = int(payload.top_n or len(scored_documents))
            results = [
                {
                    "index": int(item["index"]),
                    "relevance_score": float(item["relevance_score"]),
                    "document": item["document"],
                }
                for item in scored_documents[:top_n]
            ]

        prompt_tokens = _estimate_token_count(query_text + "\n" + "\n".join(normalized_documents))
        model_rates, default_model_rates = _load_model_token_rates(db)
        provider_multipliers, endpoint_multipliers = _load_cloud_component_multipliers(db)
        provider_type_for_cost = "unknown"
        resolved_provider_type_from_model, resolved_model_name = _split_provider_model(model_name)
        if selected_provider_id:
            provider_type_for_cost = _resolve_provider_type(db, selected_provider_id)
        elif resolved_provider_type_from_model:
            provider_type_for_cost = resolved_provider_type_from_model
        cost_model_name = resolved_model_name if resolved_provider_type_from_model else model_name
        estimated_cost_cents = _estimate_hop_cost_cents(
            input_tokens=prompt_tokens,
            output_tokens=0,
            model_name=cost_model_name,
            provider_type=provider_type_for_cost,
            endpoint_family="rerank",
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
                session_id=str(payload.session_id or f"session-gateway-rerank-{ctx.actor_id}").strip(),
                agent_id=str(payload.agent_id or "gateway-openai-rerank").strip() or "gateway-openai-rerank",
                owner_scope=str(payload.owner_scope or f"actor:{ctx.actor_id}").strip() or f"actor:{ctx.actor_id}",
                environment=environment,
                model_name=model_name,
                endpoint_family="rerank",
                input_tokens=prompt_tokens,
                output_tokens=0,
                estimated_cost_cents=estimated_cost_cents,
                currency="USD",
            )
        )

        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.rerank.create",
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
            "object": "list",
            "model": model_name,
            "results": results,
            "usage": {
                "prompt_tokens": prompt_tokens,
                "total_tokens": prompt_tokens,
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
            action_type="gateway.rerank.create",
            resource_type="gateway_inference",
            resource_id=model_name,
            trace_id=trace_id,
            decision_outcome="deny" if exc.status_code == 403 else "warn",
        )
        db.commit()
        raise


@router.post("/v1/realtime", response_model=GatewayOpenAIRealtimeResponse)
def gateway_openai_realtime(
    payload: GatewayOpenAIRealtimeRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-realtime-{uuid4()}"
    model_name = str(payload.model or "").strip() or "unknown"
    request_id = f"gw-rt-{uuid4().hex[:16]}"
    selected_provider_id: str | None = None
    selected_route_policy_id: str | None = None

    try:
        require_role(ctx, GATEWAY_INFERENCE_ROLES)
        _ensure_inference_credentials(
            db,
            agent_id=str(getattr(payload, "agent_id", None) or "").strip() or None,
            environment=str(payload.environment or "dev").strip().lower() or "dev",
            model_name=model_name,
        )

        environment = str(payload.environment or "dev").strip().lower() or "dev"
        request_tag = _normalize_request_tag(payload.request_tag)
        tenant_id = str(payload.tenant_id or "").strip()
        provider_type_from_model, normalized_model_name = _split_provider_model(model_name)
        requested_modalities = _normalize_modalities(list(payload.requested_modalities or ["text"]))
        stream_binary_mode = str(payload.stream_binary_mode or "metadata_only").strip().lower() or "metadata_only"
        stream_inline_max_event_bytes = int(payload.stream_inline_max_event_bytes or 16384)
        stream_inline_allowed_event_types = _normalize_realtime_inline_event_types(payload.stream_inline_allowed_event_types)
        stream_inline_require_correlation_id = bool(payload.stream_inline_require_correlation_id)
        stream_max_event_bytes = int(payload.stream_max_event_bytes or 65536)
        stream_max_session_events = int(payload.stream_max_session_events or 500)
        stream_max_session_event_bytes = int(payload.stream_max_session_event_bytes or 5242880)
        stream_heartbeat_interval_seconds = int(payload.stream_heartbeat_interval_seconds or 15)

        if stream_binary_mode not in {"metadata_only", "inline_base64"}:
            raise HTTPException(status_code=422, detail="stream_binary_mode must be one of: metadata_only, inline_base64")
        if stream_inline_max_event_bytes > stream_max_event_bytes:
            stream_inline_max_event_bytes = stream_max_event_bytes
        if bool(payload.stream) and stream_binary_mode == "inline_base64" and _is_prod_environment(environment):
            require_dual_approval(ctx)

        if provider_type_from_model and not tenant_id:
            raise HTTPException(status_code=422, detail="tenant_id is required when model includes provider prefix")
        if provider_type_from_model:
            _require_tenant_model_entitlement(
                db,
                tenant_id=tenant_id,
                provider_type=provider_type_from_model,
                model_name=normalized_model_name,
            )

        session_label = str(payload.session_label or "").strip() or None
        session_identifier = f"realtime-{uuid4().hex[:24]}"
        expires_at_dt = datetime.utcnow() + timedelta(minutes=15)
        expires_at = int(expires_at_dt.timestamp())

        prompt_tokens = _estimate_token_count(" ".join([model_name, session_label or "", " ".join(requested_modalities)]))
        model_rates, default_model_rates = _load_model_token_rates(db)
        provider_multipliers, endpoint_multipliers = _load_cloud_component_multipliers(db)
        provider_type_for_cost = "unknown"
        resolved_provider_type_from_model, resolved_model_name = _split_provider_model(model_name)
        if selected_provider_id:
            provider_type_for_cost = _resolve_provider_type(db, selected_provider_id)
        elif resolved_provider_type_from_model:
            provider_type_for_cost = resolved_provider_type_from_model
        cost_model_name = resolved_model_name if resolved_provider_type_from_model else model_name
        estimated_cost_cents = _estimate_hop_cost_cents(
            input_tokens=prompt_tokens,
            output_tokens=0,
            model_name=cost_model_name,
            provider_type=provider_type_for_cost,
            endpoint_family="realtime",
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
                session_id=str(payload.session_id or f"session-gateway-realtime-{ctx.actor_id}").strip(),
                agent_id=str(payload.agent_id or "gateway-openai-realtime").strip() or "gateway-openai-realtime",
                owner_scope=str(payload.owner_scope or f"actor:{ctx.actor_id}").strip() or f"actor:{ctx.actor_id}",
                environment=environment,
                model_name=model_name,
                endpoint_family="realtime",
                input_tokens=prompt_tokens,
                output_tokens=0,
                estimated_cost_cents=estimated_cost_cents,
                currency="USD",
            )
        )

        stream_policy_json = json.dumps(
            {
                "binary_mode": stream_binary_mode,
                "inline_max_event_bytes": stream_inline_max_event_bytes,
                "inline_allowed_event_types": stream_inline_allowed_event_types,
                "inline_require_correlation_id": stream_inline_require_correlation_id,
                "max_event_bytes": stream_max_event_bytes,
                "max_session_events": stream_max_session_events,
                "max_session_event_bytes": stream_max_session_event_bytes,
                "heartbeat_interval_seconds": stream_heartbeat_interval_seconds,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        db.add(
            RealtimeSessionRecord(
                session_id=session_identifier,
                request_id=request_id,
                trace_id=trace_id,
                actor_id=ctx.actor_id,
                environment=environment,
                model_name=model_name,
                session_label=session_label,
                requested_modalities_json=json.dumps(requested_modalities, separators=(",", ":")),
                stream_policy_json=stream_policy_json,
                event_count=0,
                total_event_bytes=0,
                last_event_type=None,
                status="active",
                expires_at=expires_at_dt,
            )
        )

        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.realtime.create",
            resource_type="gateway_inference",
            resource_id=session_identifier,
            trace_id=trace_id,
        )
        db.commit()

        risk_tier, risk_reasons = _assess_gateway_inference_risk(
            model_name=model_name,
            environment=environment,
            has_tool_calls=False,
            selected_provider_id=selected_provider_id,
        )

        created_ts = int(datetime.utcnow().timestamp())
        if bool(payload.stream):
            def _stream_chunks():
                stream_policy = {
                    "binary_mode": stream_binary_mode,
                    "inline_max_event_bytes": stream_inline_max_event_bytes,
                    "inline_allowed_event_types": stream_inline_allowed_event_types,
                    "inline_require_correlation_id": stream_inline_require_correlation_id,
                    "max_event_bytes": stream_max_event_bytes,
                    "max_session_events": stream_max_session_events,
                    "max_session_event_bytes": stream_max_session_event_bytes,
                    "heartbeat_interval_seconds": stream_heartbeat_interval_seconds,
                }
                session_created = {
                    "id": session_identifier,
                    "object": "realtime.session.event",
                    "type": "session.created",
                    "created_at": created_ts,
                    "model": model_name,
                    "status": "created",
                    "requested_modalities": requested_modalities,
                    "expires_at": expires_at,
                    "stream_policy": stream_policy,
                }
                session_policy = {
                    "id": session_identifier,
                    "object": "realtime.session.event",
                    "type": "session.policy",
                    "created_at": created_ts,
                    "stream_policy": stream_policy,
                }
                session_keepalive = {
                    "id": session_identifier,
                    "object": "realtime.session.event",
                    "type": "session.keepalive",
                    "created_at": created_ts,
                    "status": "active",
                    "expires_at": expires_at,
                    "heartbeat_interval_seconds": stream_heartbeat_interval_seconds,
                }
                yield f"data: {json.dumps(session_created, separators=(',', ':'))}\n\n"
                yield f"data: {json.dumps(session_policy, separators=(',', ':'))}\n\n"
                yield f"data: {json.dumps(session_keepalive, separators=(',', ':'))}\n\n"
                yield "data: [DONE]\n\n"

            return StreamingResponse(_stream_chunks(), media_type="text/event-stream")

        return {
            "id": session_identifier,
            "object": "realtime.session",
            "status": "created",
            "model": model_name,
            "session_label": session_label,
            "requested_modalities": requested_modalities,
            "expires_at": expires_at,
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
            action_type="gateway.realtime.create",
            resource_type="gateway_inference",
            resource_id=model_name,
            trace_id=trace_id,
            decision_outcome="deny" if exc.status_code == 403 else "warn",
        )
        db.commit()
        raise


@router.get("/v1/realtime/sessions/{session_id}", response_model=GatewayOpenAIRealtimeSessionResponse)
def gateway_openai_realtime_session_retrieve(
    session_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-realtime-session-retrieve-{uuid4()}"
    require_role(ctx, GATEWAY_INFERENCE_READ_ROLES)

    row = db.query(RealtimeSessionRecord).filter_by(session_id=str(session_id)).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Realtime session not found")

    if ctx.actor_role == ROLE_AGENT_OWNER and row.actor_id != ctx.actor_id:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.realtime.session.retrieve",
            resource_type="gateway_realtime_session",
            resource_id=row.session_id,
            trace_id=trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only access own realtime sessions.",
                "actor_role": ctx.actor_role,
                "required_scope": "session.actor_id == requester actor_id",
                "policy_version": "v1",
                "decision_trace_id": "authz-gateway-realtime-session-retrieve-scope-check",
                "remediation_hint": "Use your own session id or use Auditor/Platform Admin role for cross-owner access.",
            },
        )

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.realtime.session.retrieve",
        resource_type="gateway_realtime_session",
        resource_id=row.session_id,
        trace_id=trace_id,
    )
    db.commit()
    return _serialize_realtime_session_record(row)


@router.get("/v1/realtime/sessions", response_model=GatewayOpenAIRealtimeSessionListResponse)
def gateway_openai_realtime_sessions_list(
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-realtime-sessions-list-{uuid4()}"
    require_role(ctx, GATEWAY_INFERENCE_READ_ROLES)

    query = db.query(RealtimeSessionRecord)
    if ctx.actor_role == ROLE_AGENT_OWNER:
        query = query.filter(RealtimeSessionRecord.actor_id == ctx.actor_id)

    status_value = str(status or "").strip().lower()
    if status_value:
        query = query.filter(RealtimeSessionRecord.status == status_value)

    rows = query.order_by(RealtimeSessionRecord.created_at.desc()).offset(offset).limit(limit).all()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.realtime.session.list",
        resource_type="gateway_realtime_session",
        resource_id="realtime_sessions",
        trace_id=trace_id,
    )
    db.commit()
    return {"object": "list", "data": [_serialize_realtime_session_record(row) for row in rows]}


@router.post("/v1/realtime/sessions/{session_id}/events", response_model=GatewayOpenAIRealtimeSessionEventResponse)
def gateway_openai_realtime_session_event_create(
    session_id: str,
    payload: GatewayOpenAIRealtimeSessionEventCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-realtime-session-event-{uuid4()}"
    request_id = f"gw-rt-evt-{uuid4().hex[:16]}"
    require_role(ctx, GATEWAY_INFERENCE_ROLES)

    row = db.query(RealtimeSessionRecord).filter_by(session_id=str(session_id)).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Realtime session not found")

    if ctx.actor_role == ROLE_AGENT_OWNER and row.actor_id != ctx.actor_id:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.realtime.event.create",
            resource_type="gateway_realtime_session",
            resource_id=row.session_id,
            trace_id=trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only append events to own realtime sessions.",
                "actor_role": ctx.actor_role,
                "required_scope": "session.actor_id == requester actor_id",
                "policy_version": "v1",
                "decision_trace_id": "authz-gateway-realtime-event-create-scope-check",
                "remediation_hint": "Use your own realtime session id or use Platform Admin role for cross-owner workflows.",
            },
        )

    if row.status != "active":
        raise HTTPException(status_code=409, detail="Realtime session is not active")
    if row.expires_at <= datetime.utcnow():
        row.status = "expired"
        row.closed_at = datetime.utcnow()
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.realtime.event.create",
            resource_type="gateway_realtime_session",
            resource_id=row.session_id,
            trace_id=trace_id,
            decision_outcome="warn",
        )
        db.commit()
        raise HTTPException(status_code=409, detail="Realtime session has expired")

    event_type = str(payload.event_type or "").strip().lower()
    if not event_type:
        raise HTTPException(status_code=422, detail="event_type is required")

    binary_mode = str(payload.binary_mode or "metadata_only").strip().lower() or "metadata_only"
    if binary_mode not in {"metadata_only", "inline_base64"}:
        raise HTTPException(status_code=422, detail="binary_mode must be one of: metadata_only, inline_base64")

    policy = _parse_json_object(str(row.stream_policy_json or "{}"), "stream_policy")
    max_event_bytes = int(policy.get("max_event_bytes") or 65536)
    inline_max_event_bytes = int(policy.get("inline_max_event_bytes") or max_event_bytes)
    inline_allowed_event_types = _normalize_realtime_inline_event_types(policy.get("inline_allowed_event_types"))
    inline_require_correlation_id = bool(policy.get("inline_require_correlation_id", False))
    max_session_events = int(policy.get("max_session_events") or 500)
    max_session_event_bytes = int(policy.get("max_session_event_bytes") or 5242880)
    event_bytes = int(payload.event_bytes or 0)
    if event_bytes > max_event_bytes:
        raise HTTPException(status_code=422, detail="event_bytes exceeds stream policy max_event_bytes")
    if int(row.event_count or 0) >= max_session_events:
        raise HTTPException(status_code=422, detail="session event count exceeds stream policy max_session_events")
    projected_total_event_bytes = int(row.total_event_bytes or 0) + event_bytes
    if projected_total_event_bytes > max_session_event_bytes:
        raise HTTPException(status_code=422, detail="session event bytes exceed stream policy max_session_event_bytes")
    if binary_mode == "inline_base64" and event_type not in inline_allowed_event_types:
        raise HTTPException(status_code=422, detail="event_type is not allowed for inline_base64 under stream policy")
    if binary_mode == "inline_base64" and event_bytes > inline_max_event_bytes:
        raise HTTPException(status_code=422, detail="event_bytes exceeds stream policy inline_max_event_bytes")
    if binary_mode == "inline_base64" and inline_require_correlation_id and not _payload_has_correlation_id(payload.payload):
        raise HTTPException(status_code=422, detail="inline_base64 events require payload correlation id under stream policy")
    if binary_mode == "inline_base64" and _is_prod_environment(row.environment):
        require_dual_approval(ctx)

    event_id = f"rt-evt-{uuid4().hex[:20]}"
    db.add(
        RealtimeSessionEventRecord(
            event_id=event_id,
            session_id=row.session_id,
            request_id=request_id,
            trace_id=trace_id,
            actor_id=ctx.actor_id,
            event_type=event_type,
            binary_mode=binary_mode,
            event_bytes=event_bytes,
            payload_json=json.dumps(payload.payload or {}, separators=(",", ":")),
            status="accepted",
        )
    )
    row.event_count = int(row.event_count or 0) + 1
    row.total_event_bytes = projected_total_event_bytes
    row.last_event_type = event_type

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.realtime.event.create",
        resource_type="gateway_realtime_session",
        resource_id=row.session_id,
        trace_id=trace_id,
    )
    db.commit()
    return {
        "id": event_id,
        "object": "realtime.session.event",
        "session_id": row.session_id,
        "event_type": event_type,
        "binary_mode": binary_mode,
        "event_bytes": event_bytes,
        "status": "accepted",
        "request_id": request_id,
        "trace_id": trace_id,
        "created_at": int(datetime.utcnow().timestamp()),
        "payload": payload.payload or {},
    }


@router.get("/v1/realtime/sessions/{session_id}/events", response_model=GatewayOpenAIRealtimeSessionEventListResponse)
def gateway_openai_realtime_session_events_list(
    session_id: str,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-realtime-session-events-list-{uuid4()}"
    require_role(ctx, GATEWAY_INFERENCE_READ_ROLES)

    session_row = db.query(RealtimeSessionRecord).filter_by(session_id=str(session_id)).first()
    if session_row is None:
        raise HTTPException(status_code=404, detail="Realtime session not found")

    if ctx.actor_role == ROLE_AGENT_OWNER and session_row.actor_id != ctx.actor_id:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.realtime.event.list",
            resource_type="gateway_realtime_session",
            resource_id=session_row.session_id,
            trace_id=trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only list events for own realtime sessions.",
                "actor_role": ctx.actor_role,
                "required_scope": "session.actor_id == requester actor_id",
                "policy_version": "v1",
                "decision_trace_id": "authz-gateway-realtime-event-list-scope-check",
                "remediation_hint": "Use your own realtime session id or use Auditor/Platform Admin role for cross-owner workflows.",
            },
        )

    rows = (
        db.query(RealtimeSessionEventRecord)
        .filter_by(session_id=session_row.session_id)
        .order_by(RealtimeSessionEventRecord.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    data: list[dict[str, object]] = []
    for row in rows:
        data.append(
            {
                "id": row.event_id,
                "object": "realtime.session.event",
                "session_id": row.session_id,
                "event_type": row.event_type,
                "binary_mode": row.binary_mode,
                "event_bytes": int(row.event_bytes or 0),
                "status": row.status,
                "request_id": row.request_id,
                "trace_id": row.trace_id,
                "created_at": int(row.created_at.timestamp()),
                "payload": _parse_json_object(str(row.payload_json or "{}"), "payload"),
            }
        )

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.realtime.event.list",
        resource_type="gateway_realtime_session",
        resource_id=session_row.session_id,
        trace_id=trace_id,
    )
    db.commit()
    return {"object": "list", "data": data}


@router.post("/v1/realtime/sessions/{session_id}/close", response_model=GatewayOpenAIRealtimeSessionCloseResponse)
def gateway_openai_realtime_session_close(
    session_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-realtime-session-close-{uuid4()}"
    request_id = f"gw-rt-close-{uuid4().hex[:16]}"
    require_role(ctx, GATEWAY_INFERENCE_ROLES)

    row = db.query(RealtimeSessionRecord).filter_by(session_id=str(session_id)).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Realtime session not found")

    if ctx.actor_role == ROLE_AGENT_OWNER and row.actor_id != ctx.actor_id:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.realtime.session.close",
            resource_type="gateway_realtime_session",
            resource_id=row.session_id,
            trace_id=trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only close own realtime sessions.",
                "actor_role": ctx.actor_role,
                "required_scope": "session.actor_id == requester actor_id",
                "policy_version": "v1",
                "decision_trace_id": "authz-gateway-realtime-session-close-scope-check",
                "remediation_hint": "Use your own realtime session id or use Platform Admin role for cross-owner workflows.",
            },
        )

    stream_policy = _parse_json_object(str(row.stream_policy_json or "{}"), "stream_policy")
    if _is_prod_environment(row.environment) and str(stream_policy.get("binary_mode") or "") == "inline_base64":
        require_dual_approval(ctx)

    if row.status != "closed":
        row.status = "closed"
        row.closed_at = datetime.utcnow()

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.realtime.session.close",
        resource_type="gateway_realtime_session",
        resource_id=row.session_id,
        trace_id=trace_id,
    )
    db.commit()
    return {
        "id": row.session_id,
        "object": "realtime.session",
        "status": row.status,
        "closed_at": int((row.closed_at or datetime.utcnow()).timestamp()),
        "event_count": int(row.event_count or 0),
        "last_event_type": row.last_event_type,
        "request_id": request_id,
        "trace_id": trace_id,
    }


@router.post("/v1/messages", response_model=GatewayOpenAIMessagesResponse)
def gateway_openai_messages(
    payload: GatewayOpenAIMessagesRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-messages-{uuid4()}"
    model_name = str(payload.model or "").strip() or "unknown"
    request_id = f"gw-msg-{uuid4().hex[:16]}"
    selected_provider_id: str | None = None
    selected_route_policy_id: str | None = None

    try:
        require_role(ctx, GATEWAY_INFERENCE_ROLES)
        _ensure_inference_credentials(
            db,
            agent_id=str(getattr(payload, "agent_id", None) or "").strip() or None,
            environment=str(payload.environment or "dev").strip().lower() or "dev",
            model_name=model_name,
        )

        environment = str(payload.environment or "dev").strip().lower() or "dev"
        request_tag = _normalize_request_tag(payload.request_tag)
        tenant_id = str(payload.tenant_id or "").strip()
        provider_type_from_model, normalized_model_name = _split_provider_model(model_name)
        if provider_type_from_model and not tenant_id:
            raise HTTPException(status_code=422, detail="tenant_id is required when model includes provider prefix")
        if provider_type_from_model:
            _require_tenant_model_entitlement(
                db,
                tenant_id=tenant_id,
                provider_type=provider_type_from_model,
                model_name=normalized_model_name,
            )

        content = _normalize_audio_text(payload.input)
        conversation_id = str(payload.conversation_id or "").strip() or f"conv-{uuid4().hex[:16]}"

        inference_credential = resolve_inference_credential(
            db,
            agent_id=str(getattr(payload, "agent_id", None) or "").strip() or None,
            environment=environment,
            model_name=model_name,
            tenant_id=tenant_id or None,
            selected_provider_id=selected_provider_id,
            resolve_gateway_cursor_token=_resolve_gateway_cursor_api_token,
        )

        if inference_credential is not None and should_attempt_upstream(inference_credential):
            effective_credential = ResolvedInferenceCredential(
                provider_type=inference_credential.provider_type,
                api_key=inference_credential.api_key,
                base_url=inference_credential.base_url,
                upstream_model=inference_credential.upstream_model
                or (_split_provider_model(model_name)[1] or model_name),
                credential_source=inference_credential.credential_source,
            )
            if effective_credential.provider_type == "anthropic":
                message_result = invoke_anthropic_messages(effective_credential, user_input=content)
            else:
                message_result = execute_chat_completion(
                    db,
                    credential=effective_credential,
                    model_name=model_name,
                    messages=[{"role": "user", "content": content}],
                    prompt_preview=content,
                )
            assistant_content = message_result.content
            prompt_tokens = message_result.usage.prompt_tokens
        elif inference_simulation_enabled():
            assistant_content = content
            prompt_tokens = _estimate_token_count(content)
        else:
            raise HTTPException(status_code=503, detail="Inference credentials are not configured for this request")
        model_rates, default_model_rates = _load_model_token_rates(db)
        provider_multipliers, endpoint_multipliers = _load_cloud_component_multipliers(db)
        provider_type_for_cost = "unknown"
        resolved_provider_type_from_model, resolved_model_name = _split_provider_model(model_name)
        if selected_provider_id:
            provider_type_for_cost = _resolve_provider_type(db, selected_provider_id)
        elif resolved_provider_type_from_model:
            provider_type_for_cost = resolved_provider_type_from_model
        cost_model_name = resolved_model_name if resolved_provider_type_from_model else model_name
        estimated_cost_cents = _estimate_hop_cost_cents(
            input_tokens=prompt_tokens,
            output_tokens=0,
            model_name=cost_model_name,
            provider_type=provider_type_for_cost,
            endpoint_family="messages",
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
                session_id=str(payload.session_id or f"session-gateway-messages-{ctx.actor_id}").strip(),
                agent_id=str(payload.agent_id or "gateway-openai-messages").strip() or "gateway-openai-messages",
                owner_scope=str(payload.owner_scope or f"actor:{ctx.actor_id}").strip() or f"actor:{ctx.actor_id}",
                environment=environment,
                model_name=model_name,
                endpoint_family="messages",
                input_tokens=prompt_tokens,
                output_tokens=0,
                estimated_cost_cents=estimated_cost_cents,
                currency="USD",
            )
        )

        message_id = f"msg-{uuid4().hex[:24]}"
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.messages.create",
            resource_type="gateway_inference",
            resource_id=message_id,
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
            "id": message_id,
            "object": "message",
            "role": "assistant",
            "content": assistant_content,
            "conversation_id": conversation_id,
            "model": model_name,
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
            action_type="gateway.messages.create",
            resource_type="gateway_inference",
            resource_id=model_name,
            trace_id=trace_id,
            decision_outcome="deny" if exc.status_code == 403 else "warn",
        )
        db.commit()
        raise


@router.post("/v1/a2a/messages", response_model=GatewayOpenAIA2AMessageResponse)
def gateway_openai_a2a_messages(
    payload: GatewayOpenAIA2AMessageRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-a2a-{uuid4()}"
    model_name = str(payload.model or "a2a-transport-v1").strip() or "a2a-transport-v1"
    request_id = f"gw-a2a-{uuid4().hex[:16]}"
    selected_provider_id: str | None = None
    selected_route_policy_id: str | None = None

    try:
        require_role(ctx, GATEWAY_INFERENCE_ROLES)
        _ensure_inference_credentials(
            db,
            agent_id=str(getattr(payload, "agent_id", None) or "").strip() or None,
            environment=str(payload.environment or "dev").strip().lower() or "dev",
            model_name=model_name,
        )
        environment = str(payload.environment or "dev").strip().lower() or "dev"
        request_tag = _normalize_request_tag(payload.request_tag)
        content = _normalize_audio_text(payload.message)
        prompt_tokens = _estimate_token_count(content + " " + payload.from_agent_id + " " + payload.to_agent_id)

        model_rates, default_model_rates = _load_model_token_rates(db)
        provider_multipliers, endpoint_multipliers = _load_cloud_component_multipliers(db)
        estimated_cost_cents = _estimate_hop_cost_cents(
            input_tokens=prompt_tokens,
            output_tokens=0,
            model_name=model_name,
            provider_type="unknown",
            endpoint_family="a2a",
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
                session_id=str(payload.session_id or f"session-gateway-a2a-{ctx.actor_id}").strip(),
                agent_id=str(payload.agent_id or payload.from_agent_id).strip() or payload.from_agent_id,
                owner_scope=str(payload.owner_scope or f"actor:{ctx.actor_id}").strip() or f"actor:{ctx.actor_id}",
                environment=environment,
                model_name=model_name,
                endpoint_family="a2a",
                input_tokens=prompt_tokens,
                output_tokens=0,
                estimated_cost_cents=estimated_cost_cents,
                currency="USD",
            )
        )

        message_id = f"a2a-{uuid4().hex[:24]}"
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.a2a.messages.create",
            resource_type="gateway_inference",
            resource_id=message_id,
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
            "id": message_id,
            "object": "a2a.message",
            "status": "delivered",
            "from_agent_id": payload.from_agent_id,
            "to_agent_id": payload.to_agent_id,
            "content": content,
            "model": model_name,
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
            action_type="gateway.a2a.messages.create",
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
    response_id = f"resp-{uuid4().hex[:24]}"
    selected_provider_id: str | None = None
    selected_route_policy_id: str | None = None

    try:
        require_role(ctx, GATEWAY_INFERENCE_ROLES)
        _ensure_inference_credentials(
            db,
            agent_id=str(getattr(payload, "agent_id", None) or "").strip() or None,
            environment=str(payload.environment or "dev").strip().lower() or "dev",
            model_name=model_name,
        )

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
        matched_system_rules = _resolve_gateway_system_rules_for_responses(db, payload=payload, ctx=ctx)
        system_rules_text = "\n".join(
            f"- {str(rule.get('rule_text') or '').strip()}"
            for rule in matched_system_rules
            if str(rule.get("rule_text") or "").strip()
        )
        system_instruction_text = _load_gateway_system_instructions(db)
        request_instruction_text = str(payload.instructions or "").strip()
        instruction_text = "\n".join(
            part for part in [system_rules_text, system_instruction_text, request_instruction_text] if part
        ).strip()
        effective_prompt = "\n".join(part for part in [instruction_text, prompt_preview] if part).strip()
        push_audit_action_context(
            user_prompt=effective_prompt or prompt_preview,
            model=model_name,
            endpoint_family="responses",
        )

        owner_scope = str(payload.owner_scope or f"actor:{ctx.actor_id}").strip() or f"actor:{ctx.actor_id}"
        request_fingerprint = _fingerprint_cache_request([
            environment,
            tenant_id,
            selected_route_policy_id or "",
            model_name,
            request_tag or "",
            prompt_preview,
            instruction_text,
            "responses",
        ])
        cache_pre = evaluate_pre_inference_cache(
            db,
            actor_id=ctx.actor_id,
            trace_id=trace_id,
            request_id=request_id,
            request_fingerprint=request_fingerprint,
            request_text=effective_prompt or prompt_preview,
            tenant_id=tenant_id,
            environment=environment,
            route_policy_id=selected_route_policy_id,
            request_tag=request_tag,
            owner_scope=owner_scope,
            endpoint_family="responses",
        )
        if cache_pre.cached_response is not None:
            risk_tier, risk_reasons = _assess_gateway_inference_risk(
                model_name=model_name,
                environment=environment,
                has_tool_calls=False,
                selected_provider_id=selected_provider_id,
            )
            refreshed = dict(cache_pre.cached_response)
            refreshed["request_id"] = request_id
            refreshed["trace_id"] = trace_id
            refreshed["cache_short_circuit"] = True
            refreshed["risk_tier"] = risk_tier
            refreshed["risk_reasons"] = risk_reasons
            refreshed["selected_provider_id"] = selected_provider_id
            refreshed["route_policy_id"] = selected_route_policy_id
            create_audit_event(
                db,
                actor_id=ctx.actor_id,
                action_type="gateway.responses.create",
                resource_type="gateway_inference_response",
                resource_id=str(refreshed.get("id") or response_id),
                trace_id=trace_id,
            )
            db.commit()
            return refreshed

        response_format_type = str((payload.response_format or {}).get("type") or "").strip().lower()
        if response_format_type and response_format_type not in {"json_object", "text"}:
            raise HTTPException(status_code=422, detail="response_format.type must be one of: json_object, text")

        inference_credential = resolve_inference_credential(
            db,
            agent_id=str(getattr(payload, "agent_id", None) or "").strip() or None,
            environment=environment,
            model_name=model_name,
            tenant_id=tenant_id or None,
            selected_provider_id=selected_provider_id,
            resolve_gateway_cursor_token=_resolve_gateway_cursor_api_token,
        )

        upstream_request_body = {
            "input": payload.input,
            "instructions": payload.instructions,
            "metadata": payload.metadata,
            "temperature": payload.temperature,
            "top_p": payload.top_p,
            "max_output_tokens": payload.max_output_tokens,
            "stop": payload.stop,
            "tools": payload.tools,
            "tool_choice": payload.tool_choice,
            "response_format": payload.response_format,
        }
        upstream_request_body = {
            key: value for key, value in upstream_request_body.items() if value is not None
        }

        if inference_credential is not None and should_attempt_upstream(inference_credential) and not selected_tool_name:
            effective_credential = ResolvedInferenceCredential(
                provider_type=inference_credential.provider_type,
                api_key=inference_credential.api_key,
                base_url=inference_credential.base_url,
                upstream_model=inference_credential.upstream_model
                or (_split_provider_model(model_name)[1] or model_name),
                credential_source=inference_credential.credential_source,
            )
            upstream_result = invoke_responses_create(
                effective_credential,
                request_body=upstream_request_body,
            )
            output_text = upstream_result.output_text
            output_items = upstream_result.output_items
            finish_reason = upstream_result.finish_reason
            input_tokens = upstream_result.usage.prompt_tokens
            output_tokens = upstream_result.usage.completion_tokens
            total_tokens = upstream_result.usage.total_tokens
            has_upstream_tool_calls = upstream_result.has_tool_calls
        else:
            has_upstream_tool_calls = False
            inference_result = execute_responses_create(
                db,
                credential=inference_credential,
                model_name=model_name,
                effective_prompt=effective_prompt,
                request_body=upstream_request_body,
            )
            output_text = inference_result.output_text
            output_items = inference_result.output_items
            finish_reason = inference_result.finish_reason
            input_tokens = inference_result.usage.prompt_tokens
            output_tokens = inference_result.usage.completion_tokens
            total_tokens = inference_result.usage.total_tokens

            if response_format_type == "json_object" and not has_upstream_tool_calls and not (
                inference_credential is not None and should_attempt_upstream(inference_credential)
            ):
                output_text = json.dumps({"answer": output_text}, separators=(",", ":"))

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
                if payload.max_output_tokens is not None and not (
                    inference_credential is not None and should_attempt_upstream(inference_credential)
                ):
                    max_out = int(payload.max_output_tokens)
                    words = output_text.split()
                    if len(words) > max_out:
                        output_text = " ".join(words[:max_out]).strip()
                    finish_reason = "length"
                    output_tokens = min(output_tokens, max_out)
                    for item in output_items:
                        if str(item.get("type") or "").strip() == "message":
                            item["finish_reason"] = finish_reason
                            content = item.get("content")
                            if isinstance(content, list) and content:
                                first = content[0]
                                if isinstance(first, dict) and first.get("type") == "output_text":
                                    first["text"] = output_text
                elif stopped:
                    finish_reason = "stop"
                if not output_items:
                    output_items = [
                        {
                            "id": f"resp-out-{uuid4().hex[:16]}",
                            "type": "message",
                            "role": "assistant",
                            "content": [{"type": "output_text", "text": output_text}],
                            "finish_reason": finish_reason,
                        }
                    ]
                if payload.max_output_tokens is not None and not selected_tool_name and not (
                    inference_credential is not None and should_attempt_upstream(inference_credential)
                ):
                    output_tokens = min(output_tokens, int(payload.max_output_tokens))

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

        if cache_pre.short_circuit_active:
            pass
        else:
            _record_cache_decision_event(
                db,
                actor_id=ctx.actor_id,
                trace_id=trace_id,
                request_id=request_id,
                request_fingerprint=request_fingerprint,
                request_text=effective_prompt or prompt_preview,
                tenant_id=tenant_id,
                environment=environment,
                route_policy_id=selected_route_policy_id,
                request_tag=request_tag,
                owner_scope=owner_scope,
            )

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
        maybe_capture_response_session_memory(
            db,
            actor_id=ctx.actor_id,
            session_id=str(payload.session_id or "").strip() or None,
            content=output_text,
            environment=environment,
            trace_id=trace_id,
            response_id=response_id,
        )
        db.commit()

        risk_tier, risk_reasons = _assess_gateway_inference_risk(
            model_name=model_name,
            environment=environment,
            has_tool_calls=bool(selected_tool_name) or has_upstream_tool_calls,
            selected_provider_id=selected_provider_id,
        )

        created_ts = int(datetime.utcnow().timestamp())
        if bool(payload.stream):
            def _stream_chunks():
                first_chunk = {
                    "id": response_id,
                    "object": "response.chunk",
                    "created_at": created_ts,
                    "model": model_name,
                    "output": output_items,
                    "output_text": output_text,
                }
                final_chunk = {
                    "id": response_id,
                    "object": "response.chunk",
                    "created_at": created_ts,
                    "model": model_name,
                    "done": True,
                }
                yield f"data: {json.dumps(first_chunk, separators=(',', ':'))}\n\n"
                yield f"data: {json.dumps(final_chunk, separators=(',', ':'))}\n\n"
                yield "data: [DONE]\n\n"

            return StreamingResponse(_stream_chunks(), media_type="text/event-stream")

        response_body = {
            "id": response_id,
            "object": "response",
            "created_at": created_ts,
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
        if cache_pre.short_circuit_active:
            finalize_post_inference_cache(
                db,
                pre=cache_pre,
                actor_id=ctx.actor_id,
                trace_id=trace_id,
                request_id=request_id,
                tenant_id=tenant_id,
                environment=environment,
                route_policy_id=selected_route_policy_id,
                response_body=response_body,
                endpoint_family="responses",
                owner_scope=owner_scope,
            )
            db.commit()
        return response_body
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


@router.get("/gateway/system-instructions", response_model=GatewaySystemInstructionsResponse)
def get_gateway_system_instructions(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    instructions = _load_gateway_system_instructions(db)
    row = db.query(RuntimeConfig).filter_by(config_key=RUNTIME_CONFIG_GATEWAY_SYSTEM_INSTRUCTIONS).first()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.system_instructions.read",
        resource_type="runtime_config",
        resource_id=RUNTIME_CONFIG_GATEWAY_SYSTEM_INSTRUCTIONS,
        trace_id=f"trace-gateway-system-instructions-read-{uuid4()}",
    )
    db.commit()
    return {
        "config_key": RUNTIME_CONFIG_GATEWAY_SYSTEM_INSTRUCTIONS,
        "instructions": instructions,
        "updated_by": row.updated_by if row else None,
        "updated_at": row.updated_at if row else None,
    }


@router.put("/gateway/system-instructions", response_model=GatewaySystemInstructionsResponse)
def update_gateway_system_instructions(
    payload: GatewaySystemInstructionsUpdateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_SECURITY_ROLES)
    normalized_instructions = str(payload.instructions or "").strip()

    row = db.query(RuntimeConfig).filter_by(config_key=RUNTIME_CONFIG_GATEWAY_SYSTEM_INSTRUCTIONS).first()
    if row:
        row.config_value = normalized_instructions
        row.updated_by = ctx.actor_id
        row.updated_at = datetime.utcnow()
    else:
        row = RuntimeConfig(
            config_key=RUNTIME_CONFIG_GATEWAY_SYSTEM_INSTRUCTIONS,
            config_value=normalized_instructions,
            description="Gateway baseline system instructions applied to responses API requests",
            updated_by=ctx.actor_id,
        )
        db.add(row)

    invalidate_runtime_config_cache(RUNTIME_CONFIG_GATEWAY_SYSTEM_INSTRUCTIONS)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.system_instructions.update",
        resource_type="runtime_config",
        resource_id=RUNTIME_CONFIG_GATEWAY_SYSTEM_INSTRUCTIONS,
        trace_id=f"trace-gateway-system-instructions-update-{uuid4()}",
    )
    db.commit()
    db.refresh(row)
    return {
        "config_key": row.config_key,
        "instructions": str(row.config_value or "").strip(),
        "updated_by": row.updated_by,
        "updated_at": row.updated_at,
    }


@router.get("/gateway/system-rules", response_model=GatewaySystemRulesResponse)
def get_gateway_system_rules(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_READ_ROLES)
    rules = _load_gateway_system_rules(db)
    row = db.query(RuntimeConfig).filter_by(config_key=RUNTIME_CONFIG_GATEWAY_SYSTEM_RULES_JSON).first()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.system_rules.read",
        resource_type="runtime_config",
        resource_id=RUNTIME_CONFIG_GATEWAY_SYSTEM_RULES_JSON,
        trace_id=f"trace-gateway-system-rules-read-{uuid4()}",
    )
    db.commit()
    return {
        "config_key": RUNTIME_CONFIG_GATEWAY_SYSTEM_RULES_JSON,
        "rules": rules,
        "updated_by": row.updated_by if row else None,
        "updated_at": row.updated_at if row else None,
    }


@router.put("/gateway/system-rules", response_model=GatewaySystemRulesResponse)
def update_gateway_system_rules(
    payload: GatewaySystemRulesUpdateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_SECURITY_ROLES)
    normalized_rules = _normalize_gateway_system_rules(payload.rules)
    serialized_rules = json.dumps(normalized_rules, separators=(",", ":"))

    row = db.query(RuntimeConfig).filter_by(config_key=RUNTIME_CONFIG_GATEWAY_SYSTEM_RULES_JSON).first()
    if row:
        row.config_value = serialized_rules
        row.updated_by = ctx.actor_id
        row.updated_at = datetime.utcnow()
    else:
        row = RuntimeConfig(
            config_key=RUNTIME_CONFIG_GATEWAY_SYSTEM_RULES_JSON,
            config_value=serialized_rules,
            description="Gateway baseline system rules applied to responses API requests",
            updated_by=ctx.actor_id,
        )
        db.add(row)

    invalidate_runtime_config_cache(RUNTIME_CONFIG_GATEWAY_SYSTEM_RULES_JSON)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.system_rules.update",
        resource_type="runtime_config",
        resource_id=RUNTIME_CONFIG_GATEWAY_SYSTEM_RULES_JSON,
        trace_id=f"trace-gateway-system-rules-update-{uuid4()}",
    )
    db.commit()
    db.refresh(row)
    return {
        "config_key": row.config_key,
        "rules": normalized_rules,
        "updated_by": row.updated_by,
        "updated_at": row.updated_at,
    }


def _gateway_cursor_binding_response(db: Session, row: RuntimeConfig | None) -> dict:
    binding = _load_gateway_cursor_secret_binding(db)
    secret_provider_id = str(binding.get("secret_provider_id") or "").strip()
    secret_ref = str(binding.get("secret_ref") or "").strip()
    provider_type = str(binding.get("provider_type") or "").strip().lower()
    configured = bool(secret_provider_id and secret_ref)
    masked_hint = _mask_gateway_external_secret_ref(secret_ref)
    if configured and is_db_secret_provider(provider_type):
        try:
            provider = _require_active_secret_provider_config(db, secret_provider_id)
            token_value = read_db_secret_provider_value(db, provider, secret_ref)
            masked_hint = _mask_gateway_secret_hint(token_value)
        except HTTPException:
            configured = False
            masked_hint = None
    return {
        "config_key": RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN,
        "configured": configured,
        "secret_provider_id": secret_provider_id or None,
        "secret_ref": secret_ref or None,
        "provider_type": provider_type or None,
        "masked_hint": masked_hint,
        "updated_by": row.updated_by if row else None,
        "updated_at": row.updated_at if row else None,
    }


@router.get("/gateway/cursor-secret-binding", response_model=GatewayCursorSecretBindingResponse)
def get_gateway_cursor_secret_binding(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_SECURITY_ROLES)
    row = db.query(RuntimeConfig).filter_by(config_key=RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN).first()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.cursor_secret_binding.read",
        resource_type="runtime_config",
        resource_id=RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN,
        trace_id=f"trace-gateway-cursor-binding-read-{uuid4()}",
    )
    db.commit()
    return _gateway_cursor_binding_response(db, row)


@router.put("/gateway/cursor-secret-binding", response_model=GatewayCursorSecretBindingResponse)
def update_gateway_cursor_secret_binding(
    payload: GatewayCursorSecretBindingUpdateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_SECURITY_ROLES)
    required_approver_role = _required_gateway_secret_approver_role(ctx) if _is_runtime_prod_environment() else None
    if required_approver_role:
        require_dual_approval(ctx, required_approver_role=required_approver_role)

    secret_provider_id = str(payload.secret_provider_id or "").strip()
    secret_ref = str(payload.secret_ref or "").strip()
    if not secret_provider_id:
        raise HTTPException(status_code=422, detail="secret_provider_id is required")
    if not secret_ref:
        raise HTTPException(status_code=422, detail="secret_ref is required")

    row = _persist_gateway_cursor_secret_binding(
        db,
        secret_provider_id=secret_provider_id,
        secret_ref=secret_ref,
        actor_id=ctx.actor_id,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.cursor_secret_binding.update",
        resource_type="runtime_config",
        resource_id=RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN,
        trace_id=f"trace-gateway-cursor-binding-update-{uuid4()}",
    )
    db.commit()
    db.refresh(row)
    return _gateway_cursor_binding_response(db, row)


@router.delete("/gateway/cursor-secret-binding", response_model=GatewayCursorSecretBindingResponse)
def clear_gateway_cursor_secret_binding(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_SECURITY_ROLES)
    required_approver_role = _required_gateway_secret_approver_role(ctx) if _is_runtime_prod_environment() else None
    if required_approver_role:
        require_dual_approval(ctx, required_approver_role=required_approver_role)

    row = db.query(RuntimeConfig).filter_by(config_key=RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN).first()
    if row:
        row.config_value = ""
        row.updated_by = ctx.actor_id
        row.updated_at = datetime.utcnow()
    else:
        row = RuntimeConfig(
            config_key=RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN,
            config_value="",
            description="Gateway cursor secret binding via secret provider",
            updated_by=ctx.actor_id,
        )
        db.add(row)
    invalidate_runtime_config_cache(RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.cursor_secret_binding.clear",
        resource_type="runtime_config",
        resource_id=RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN,
        trace_id=f"trace-gateway-cursor-binding-clear-{uuid4()}",
    )
    db.commit()
    db.refresh(row)
    return _gateway_cursor_binding_response(db, row)


@router.get("/gateway/cursor-token", response_model=GatewayCursorTokenResponse, deprecated=True)
def get_gateway_cursor_token_config(
    response: Response,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_SECURITY_ROLES)
    response.headers["Deprecation"] = "true"
    response.headers["Link"] = '</gateway/cursor-secret-binding>; rel="successor-version"'
    row = db.query(RuntimeConfig).filter_by(config_key=RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN).first()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.cursor_token.read",
        resource_type="runtime_config",
        resource_id=RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN,
        trace_id=f"trace-gateway-cursor-token-read-{uuid4()}",
    )
    db.commit()
    binding_payload = _gateway_cursor_binding_response(db, row)
    if binding_payload.get("configured"):
        provider_type = str(binding_payload.get("provider_type") or "").strip().lower()
        storage_mode = (
            GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB
            if is_db_secret_provider(provider_type)
            else GATEWAY_CURSOR_TOKEN_STORAGE_MODE_EXTERNAL
        )
        return {
            "config_key": RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN,
            "configured": True,
            "storage_mode": storage_mode,
            "external_provider_id": binding_payload.get("secret_provider_id"),
            "external_secret_ref": binding_payload.get("secret_ref"),
            "masked_hint": binding_payload.get("masked_hint"),
            "updated_by": binding_payload.get("updated_by"),
            "updated_at": binding_payload.get("updated_at"),
        }

    token_config = _load_gateway_cursor_token_config(db)
    storage_mode = str(token_config.get("storage_mode") or GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB).strip().lower()
    token_value = str(token_config.get("token") or "").strip()
    external_provider_id = str(token_config.get("external_provider_id") or "").strip()
    external_secret_ref = str(token_config.get("external_secret_ref") or "").strip()
    configured = bool(token_value) if storage_mode == GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB else bool(external_provider_id and external_secret_ref)
    masked_hint = (
        _mask_gateway_secret_hint(token_value)
        if storage_mode == GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB
        else _mask_gateway_external_secret_ref(external_secret_ref)
    )
    row = db.query(RuntimeConfig).filter_by(config_key=RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN).first()
    return {
        "config_key": RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN,
        "configured": configured,
        "storage_mode": storage_mode,
        "external_provider_id": external_provider_id or None,
        "external_secret_ref": external_secret_ref or None,
        "masked_hint": masked_hint,
        "updated_by": row.updated_by if row else None,
        "updated_at": row.updated_at if row else None,
    }


@router.put("/gateway/cursor-token", response_model=GatewayCursorTokenResponse, deprecated=True)
def update_gateway_cursor_token_config(
    payload: GatewayCursorTokenUpdateRequest,
    response: Response,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_ADMIN_OR_SECURITY_ROLES)
    response.headers["Deprecation"] = "true"
    response.headers["Link"] = '</gateway/cursor-secret-binding>; rel="successor-version"'
    required_approver_role = _required_gateway_secret_approver_role(ctx) if _is_runtime_prod_environment() else None
    if required_approver_role:
        require_dual_approval(ctx, required_approver_role=required_approver_role)

    storage_mode = str(payload.storage_mode or GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB).strip().lower()
    if storage_mode not in GATEWAY_CURSOR_TOKEN_STORAGE_MODES:
        raise HTTPException(status_code=422, detail="storage_mode must be one of: db, external")

    normalized_token = str(payload.token or "").strip()
    external_provider_id = str(payload.external_provider_id or "").strip()
    external_secret_ref = str(payload.external_secret_ref or "").strip()

    if storage_mode == GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB:
        if not normalized_token:
            raise HTTPException(status_code=422, detail="cursor token cannot be empty for db storage mode")
        provider = _get_or_create_platform_db_secret_provider(db, ctx.actor_id)
        upsert_db_secret_provider_value(
            db,
            provider,
            secret_ref=GATEWAY_CURSOR_DEFAULT_SECRET_REF,
            secret_value=normalized_token,
            actor_id=ctx.actor_id,
        )
        secret_provider_id = provider.secret_provider_id
        secret_ref = GATEWAY_CURSOR_DEFAULT_SECRET_REF
    else:
        if not external_provider_id:
            raise HTTPException(status_code=422, detail="external_provider_id is required for external storage mode")
        if not external_secret_ref:
            raise HTTPException(status_code=422, detail="external_secret_ref is required for external storage mode")
        secret_provider_id = external_provider_id
        secret_ref = external_secret_ref

    row = _persist_gateway_cursor_secret_binding(
        db,
        secret_provider_id=secret_provider_id,
        secret_ref=secret_ref,
        actor_id=ctx.actor_id,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.cursor_token.update",
        resource_type="runtime_config",
        resource_id=RUNTIME_CONFIG_GATEWAY_CURSOR_API_TOKEN,
        trace_id=f"trace-gateway-cursor-token-update-{uuid4()}",
    )
    db.commit()
    db.refresh(row)
    provider = _require_active_secret_provider_config(db, secret_provider_id)
    resolved_storage_mode = (
        GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB
        if is_db_secret_provider(provider.provider_type)
        else GATEWAY_CURSOR_TOKEN_STORAGE_MODE_EXTERNAL
    )
    return {
        "config_key": row.config_key,
        "configured": True,
        "storage_mode": resolved_storage_mode,
        "external_provider_id": secret_provider_id,
        "external_secret_ref": secret_ref,
        "masked_hint": (
            _mask_gateway_secret_hint(normalized_token)
            if resolved_storage_mode == GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB
            else _mask_gateway_external_secret_ref(secret_ref)
        ),
        "updated_by": row.updated_by,
        "updated_at": row.updated_at,
    }


@router.delete("/gateway/cursor-token", response_model=GatewayCursorTokenResponse, deprecated=True)
def clear_gateway_cursor_token_config(
    response: Response,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    response.headers["Deprecation"] = "true"
    response.headers["Link"] = '</gateway/cursor-secret-binding>; rel="successor-version"'
    binding_payload = clear_gateway_cursor_secret_binding(db=db, ctx=ctx)
    return {
        "config_key": binding_payload["config_key"],
        "configured": False,
        "storage_mode": GATEWAY_CURSOR_TOKEN_STORAGE_MODE_DB,
        "external_provider_id": None,
        "external_secret_ref": None,
        "masked_hint": None,
        "updated_by": binding_payload.get("updated_by"),
        "updated_at": binding_payload.get("updated_at"),
    }


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


@router.post("/v1/batches", response_model=GatewayOpenAIBatchResponse)
def gateway_openai_batches_create(
    payload: GatewayOpenAIBatchCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-batches-create-{uuid4()}"
    request_id = f"gw-batch-{uuid4().hex[:16]}"
    require_role(ctx, GATEWAY_INFERENCE_ROLES)

    endpoint_family = str(payload.endpoint_family or "responses").strip().lower() or "responses"
    batch = OpenAIBatchRecord(
        batch_id=f"batch-{uuid4().hex[:24]}",
        request_id=request_id,
        trace_id=trace_id,
        actor_id=ctx.actor_id,
        environment=str(payload.environment or "dev").strip().lower() or "dev",
        endpoint_family=endpoint_family,
        request_count=len(payload.requests),
        completed_count=0,
        failed_count=0,
        metadata_json=json.dumps(payload.metadata or {}, separators=(",", ":")),
        status="queued",
    )
    db.add(batch)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.batches.create",
        resource_type="gateway_batch",
        resource_id=batch.batch_id,
        trace_id=trace_id,
    )
    db.commit()
    db.refresh(batch)
    return _serialize_openai_batch_record(batch)


@router.get("/v1/batches", response_model=GatewayOpenAIBatchesListResponse)
def gateway_openai_batches_list(
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = Query(default=None),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-batches-list-{uuid4()}"
    require_role(ctx, GATEWAY_INFERENCE_READ_ROLES)

    query = db.query(OpenAIBatchRecord).filter(OpenAIBatchRecord.status != "deleted")
    if ctx.actor_role == ROLE_AGENT_OWNER:
        query = query.filter(OpenAIBatchRecord.actor_id == ctx.actor_id)

    status_value = str(status or "").strip()
    if status_value:
        query = query.filter(OpenAIBatchRecord.status == status_value)

    rows = query.order_by(OpenAIBatchRecord.created_at.desc()).offset(offset).limit(limit).all()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.batches.list",
        resource_type="gateway_batch",
        resource_id="batches",
        trace_id=trace_id,
    )
    db.commit()
    return {"object": "list", "data": [_serialize_openai_batch_record(row) for row in rows]}


@router.get("/v1/batches/{batch_id}", response_model=GatewayOpenAIBatchResponse)
def gateway_openai_batches_retrieve(
    batch_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-batches-retrieve-{uuid4()}"
    require_role(ctx, GATEWAY_INFERENCE_READ_ROLES)

    row = db.query(OpenAIBatchRecord).filter_by(batch_id=str(batch_id)).first()
    if row is None or row.status == "deleted":
        raise HTTPException(status_code=404, detail="Batch not found")
    if ctx.actor_role == ROLE_AGENT_OWNER and row.actor_id != ctx.actor_id:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.batches.retrieve",
            resource_type="gateway_batch",
            resource_id=row.batch_id,
            trace_id=trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only access own batch records.",
                "actor_role": ctx.actor_role,
                "required_scope": "batch.actor_id == requester actor_id",
                "policy_version": "v1",
                "decision_trace_id": "authz-gateway-batches-retrieve-scope-check",
                "remediation_hint": "Use your own batch id or use Auditor/Platform Admin role for cross-owner access.",
            },
        )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.batches.retrieve",
        resource_type="gateway_batch",
        resource_id=row.batch_id,
        trace_id=trace_id,
    )
    db.commit()
    return _serialize_openai_batch_record(row)


@router.delete("/v1/batches/{batch_id}", response_model=GatewayOpenAIBatchDeleteResponse)
def gateway_openai_batches_delete(
    batch_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    trace_id = f"trace-gateway-batches-delete-{uuid4()}"
    request_id = f"gw-batch-del-{uuid4().hex[:16]}"
    require_role(ctx, GATEWAY_INFERENCE_DELETE_ROLES)

    row = db.query(OpenAIBatchRecord).filter_by(batch_id=str(batch_id)).first()
    if row is None or row.status == "deleted":
        raise HTTPException(status_code=404, detail="Batch not found")

    if ctx.actor_role == ROLE_AGENT_OWNER and row.actor_id != ctx.actor_id:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.batches.delete",
            resource_type="gateway_batch",
            resource_id=row.batch_id,
            trace_id=trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_SCOPE_FORBIDDEN",
                "message": "Agent Owner can only delete own batch records.",
                "actor_role": ctx.actor_role,
                "required_scope": "batch.actor_id == requester actor_id",
                "policy_version": "v1",
                "decision_trace_id": "authz-gateway-batches-delete-scope-check",
                "remediation_hint": "Delete your own batch id or use Platform Admin role for cross-owner deletion.",
            },
        )

    if _is_prod_environment(row.environment):
        try:
            require_dual_approval(ctx)
        except HTTPException as exc:
            create_audit_event(
                db,
                actor_id=ctx.actor_id,
                action_type="gateway.batches.delete",
                resource_type="gateway_batch",
                resource_id=row.batch_id,
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
        action_type="gateway.batches.delete",
        resource_type="gateway_batch",
        resource_id=row.batch_id,
        trace_id=trace_id,
    )
    db.commit()
    return {
        "id": row.batch_id,
        "object": "batch.deleted",
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
        "sink_type": _normalize_callback_sink_type(payload.sink_type),
        "sink_route_key": _normalize_sink_route_key(payload.sink_route_key),
        "correlation_preset": _normalize_callback_correlation_preset(payload.correlation_preset),
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
    if payload.sink_type is not None:
        target["sink_type"] = _normalize_callback_sink_type(payload.sink_type)
    if payload.sink_route_key is not None:
        target["sink_route_key"] = _normalize_sink_route_key(payload.sink_route_key)
    if payload.correlation_preset is not None:
        target["correlation_preset"] = _normalize_callback_correlation_preset(payload.correlation_preset)
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
    sink_type = _normalize_callback_sink_type(target.get("sink_type"))
    sink_route_key = _normalize_sink_route_key(target.get("sink_route_key"))
    correlation_preset = _normalize_callback_correlation_preset(target.get("correlation_preset"))
    correlation_context = _build_callback_correlation_context(
        sample,
        callback_id=callback_id,
        sink_type=sink_type,
        sink_route_key=sink_route_key,
        correlation_preset=correlation_preset,
        trace_id=trace_id,
        environment=environment,
    )

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
        "sink_type": sink_type,
        "sink_route_key": sink_route_key,
        "correlation_preset": correlation_preset,
        "delivery_status": "delivered_simulated",
        "trace_id": trace_id,
        "delivered_at": delivered_at,
        "redaction_applied": bool(target.get("redact_sensitive", True)),
        "correlation_context": correlation_context,
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
    sink_distribution: dict[str, int] = {}
    correlation_preset_distribution: dict[str, int] = {}
    for callback in callbacks:
        sink = _normalize_callback_sink_type(callback.get("sink_type"))
        preset = _normalize_callback_correlation_preset(callback.get("correlation_preset"))
        sink_distribution[sink] = sink_distribution.get(sink, 0) + 1
        correlation_preset_distribution[preset] = correlation_preset_distribution.get(preset, 0) + 1

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
        "sink_distribution": sink_distribution,
        "correlation_preset_distribution": correlation_preset_distribution,
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
                "actor_login": row.actor_login or "unknown",
                "actor_role": row.actor_role or resolve_actor_role_for_actor(db, row.actor_id),
                "action_description": row.action_description or resolve_action_description(row.action_type),
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


# ── Assistants API (OpenAI-compatible MVP) ─────────────────────────────────────


@router.post("/v1/assistants", response_model=GatewayAssistantResponse)
def gateway_assistants_create(
    payload: GatewayAssistantCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_INFERENCE_ROLES)
    trace_id = f"trace-gateway-assistant-create-{uuid4()}"
    environment = str(payload.environment or "dev").strip().lower() or "dev"
    result = create_assistant(
        db,
        actor_id=ctx.actor_id,
        name=payload.name,
        model=payload.model,
        instructions=payload.instructions,
        metadata=payload.metadata,
        environment=environment,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.assistants.create",
        resource_type="gateway_assistant",
        resource_id=result["id"],
        trace_id=trace_id,
        environment=environment,
    )
    db.commit()
    return result


@router.get("/v1/assistants", response_model=GatewayAssistantListResponse)
def gateway_assistants_list(
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_INFERENCE_READ_ROLES)
    data = list_assistants(db, actor_id=ctx.actor_id, actor_role=ctx.actor_role, limit=limit, offset=offset)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.assistants.list",
        resource_type="gateway_assistant",
        resource_id="assistants",
        trace_id=f"trace-gateway-assistant-list-{uuid4()}",
    )
    db.commit()
    return {"object": "list", "data": data}


@router.get("/v1/assistants/{assistant_id}", response_model=GatewayAssistantResponse)
def gateway_assistants_retrieve(
    assistant_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_INFERENCE_READ_ROLES)
    result = get_assistant(db, assistant_id=assistant_id, actor_id=ctx.actor_id, actor_role=ctx.actor_role)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.assistants.retrieve",
        resource_type="gateway_assistant",
        resource_id=assistant_id,
        trace_id=f"trace-gateway-assistant-retrieve-{uuid4()}",
    )
    db.commit()
    return result


@router.delete("/v1/assistants/{assistant_id}", response_model=GatewayAssistantDeleteResponse)
def gateway_assistants_delete(
    assistant_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_INFERENCE_DELETE_ROLES)
    record = db.query(GatewayAssistantRecord).filter_by(assistant_id=assistant_id).first()
    if record is None or record.status == "deleted":
        raise HTTPException(status_code=404, detail="Assistant not found")
    _require_prod_dual_approval_audited(
        db,
        ctx,
        environment=record.environment,
        action_type="gateway.assistants.delete",
        resource_type="gateway_assistant",
        resource_id=assistant_id,
        trace_prefix="trace-gateway-assistant-delete-deny",
    )
    try:
        result = delete_assistant(db, assistant_id=assistant_id, actor_id=ctx.actor_id, actor_role=ctx.actor_role)
    except HTTPException as exc:
        _reraise_gateway_authz_denial_with_audit(
            db,
            ctx,
            exc,
            action_type="gateway.assistants.delete",
            resource_type="gateway_assistant",
            resource_id=assistant_id,
            environment=record.environment,
            trace_prefix="trace-gateway-assistant-delete-scope",
        )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.assistants.delete",
        resource_type="gateway_assistant",
        resource_id=assistant_id,
        trace_id=f"trace-gateway-assistant-delete-{uuid4()}",
        environment=record.environment,
    )
    db.commit()
    return result


@router.post("/v1/threads", response_model=GatewayThreadResponse)
def gateway_threads_create(
    payload: GatewayThreadCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_INFERENCE_ROLES)
    environment = str(payload.environment or "dev").strip().lower() or "dev"
    result = create_thread(db, actor_id=ctx.actor_id, metadata=payload.metadata, environment=environment)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.threads.create",
        resource_type="gateway_thread",
        resource_id=result["id"],
        trace_id=f"trace-gateway-thread-create-{uuid4()}",
        environment=environment,
    )
    db.commit()
    return result


@router.get("/v1/threads/{thread_id}", response_model=GatewayThreadResponse)
def gateway_threads_retrieve(
    thread_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_INFERENCE_READ_ROLES)
    result = get_thread(db, thread_id=thread_id, actor_id=ctx.actor_id, actor_role=ctx.actor_role)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.threads.retrieve",
        resource_type="gateway_thread",
        resource_id=thread_id,
        trace_id=f"trace-gateway-thread-retrieve-{uuid4()}",
    )
    db.commit()
    return result


@router.post("/v1/threads/{thread_id}/messages", response_model=GatewayThreadMessageResponse)
def gateway_thread_messages_create(
    thread_id: str,
    payload: GatewayThreadMessageCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_INFERENCE_ROLES)
    result = create_thread_message(
        db,
        thread_id=thread_id,
        actor_id=ctx.actor_id,
        actor_role=ctx.actor_role,
        role=payload.role,
        content=payload.content,
        metadata=payload.metadata,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.threads.messages.create",
        resource_type="gateway_thread_message",
        resource_id=result["id"],
        trace_id=f"trace-gateway-thread-message-{uuid4()}",
    )
    db.commit()
    return result


@router.get("/v1/threads/{thread_id}/messages", response_model=GatewayThreadMessageListResponse)
def gateway_thread_messages_list(
    thread_id: str,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_INFERENCE_READ_ROLES)
    data = list_thread_messages(
        db,
        thread_id=thread_id,
        actor_id=ctx.actor_id,
        actor_role=ctx.actor_role,
        limit=limit,
        offset=offset,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.threads.messages.list",
        resource_type="gateway_thread",
        resource_id=thread_id,
        trace_id=f"trace-gateway-thread-messages-list-{uuid4()}",
    )
    db.commit()
    return {"object": "list", "data": data}


@router.post("/v1/threads/{thread_id}/runs", response_model=GatewayThreadRunResponse)
def gateway_thread_runs_create(
    thread_id: str,
    payload: GatewayThreadRunCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_INFERENCE_ROLES)
    environment = str(payload.environment or "dev").strip().lower() or "dev"
    if bool(payload.stream):
        def _stream_chunks():
            try:
                for chunk in iter_thread_run_sse_chunks(
                    db,
                    thread_id=thread_id,
                    assistant_id=payload.assistant_id,
                    actor_id=ctx.actor_id,
                    actor_role=ctx.actor_role,
                    environment=environment,
                    model_override=payload.model,
                    additional_instructions=payload.additional_instructions,
                    ensure_inference_credentials=_ensure_inference_credentials,
                ):
                    yield chunk
                create_audit_event(
                    db,
                    actor_id=ctx.actor_id,
                    action_type="gateway.threads.runs.create",
                    resource_type="gateway_thread_run",
                    resource_id=thread_id,
                    trace_id=f"trace-gateway-thread-run-stream-{uuid4()}",
                    environment=environment,
                    action_context={"stream": True},
                )
                db.commit()
            except HTTPException as exc:
                db.rollback()
                error_payload = {
                    "object": "error",
                    "message": str(exc.detail),
                    "type": "invalid_request_error",
                }
                yield f"data: {json.dumps(error_payload, separators=(',', ':'))}\n\n"
                yield "data: [DONE]\n\n"

        return StreamingResponse(_stream_chunks(), media_type="text/event-stream")

    result = create_and_execute_thread_run(
        db,
        thread_id=thread_id,
        assistant_id=payload.assistant_id,
        actor_id=ctx.actor_id,
        actor_role=ctx.actor_role,
        environment=environment,
        model_override=payload.model,
        additional_instructions=payload.additional_instructions,
        ensure_inference_credentials=_ensure_inference_credentials,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.threads.runs.create",
        resource_type="gateway_thread_run",
        resource_id=result["id"],
        trace_id=f"trace-gateway-thread-run-{result['id']}",
        environment=environment,
    )
    db.commit()
    return result


@router.get("/v1/threads/{thread_id}/runs/{run_id}", response_model=GatewayThreadRunResponse)
def gateway_thread_runs_retrieve(
    thread_id: str,
    run_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_INFERENCE_READ_ROLES)
    result = get_thread_run(
        db,
        thread_id=thread_id,
        run_id=run_id,
        actor_id=ctx.actor_id,
        actor_role=ctx.actor_role,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.threads.runs.retrieve",
        resource_type="gateway_thread_run",
        resource_id=run_id,
        trace_id=f"trace-gateway-thread-run-retrieve-{uuid4()}",
    )
    db.commit()
    return result


# ── Fine-tuning API MVP ────────────────────────────────────────────────────────


@router.post("/v1/fine_tuning/jobs", response_model=GatewayFineTuningJobResponse)
def gateway_fine_tuning_jobs_create(
    payload: GatewayFineTuningJobCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_INFERENCE_ROLES)
    environment = str(payload.environment or "dev").strip().lower() or "dev"
    result = create_fine_tuning_job(
        db,
        actor_id=ctx.actor_id,
        actor_role=ctx.actor_role,
        model=payload.model,
        training_file_id=payload.training_file_id,
        environment=environment,
        metadata=payload.metadata,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.fine_tuning.create",
        resource_type="gateway_fine_tuning_job",
        resource_id=result["id"],
        trace_id=f"trace-gateway-fine-tuning-create-{uuid4()}",
        environment=environment,
    )
    db.commit()
    return result


@router.get("/v1/fine_tuning/jobs", response_model=GatewayFineTuningJobListResponse)
def gateway_fine_tuning_jobs_list(
    limit: int = Query(default=20, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_INFERENCE_READ_ROLES)
    data = list_fine_tuning_jobs(
        db,
        actor_id=ctx.actor_id,
        actor_role=ctx.actor_role,
        limit=limit,
        offset=offset,
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.fine_tuning.list",
        resource_type="gateway_fine_tuning_job",
        resource_id="jobs",
        trace_id=f"trace-gateway-fine-tuning-list-{uuid4()}",
    )
    db.commit()
    return {"object": "list", "data": data}


@router.get("/v1/fine_tuning/jobs/{job_id}", response_model=GatewayFineTuningJobResponse)
def gateway_fine_tuning_jobs_retrieve(
    job_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_INFERENCE_READ_ROLES)
    result = get_fine_tuning_job(db, job_id=job_id, actor_id=ctx.actor_id, actor_role=ctx.actor_role)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.fine_tuning.retrieve",
        resource_type="gateway_fine_tuning_job",
        resource_id=job_id,
        trace_id=f"trace-gateway-fine-tuning-retrieve-{uuid4()}",
    )
    db.commit()
    return result


@router.post("/v1/fine_tuning/jobs/{job_id}/cancel", response_model=GatewayFineTuningJobCancelResponse)
def gateway_fine_tuning_jobs_cancel(
    job_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_INFERENCE_ROLES)
    job_record = db.query(GatewayFineTuningJobRecord).filter_by(job_id=job_id).first()
    if job_record is None:
        raise HTTPException(status_code=404, detail="Fine-tuning job not found")
    _require_prod_dual_approval_audited(
        db,
        ctx,
        environment=job_record.environment,
        action_type="gateway.fine_tuning.cancel",
        resource_type="gateway_fine_tuning_job",
        resource_id=job_id,
        trace_prefix="trace-gateway-fine-tuning-cancel-deny",
    )
    try:
        result = cancel_fine_tuning_job(db, job_id=job_id, actor_id=ctx.actor_id, actor_role=ctx.actor_role)
    except HTTPException as exc:
        _reraise_gateway_authz_denial_with_audit(
            db,
            ctx,
            exc,
            action_type="gateway.fine_tuning.cancel",
            resource_type="gateway_fine_tuning_job",
            resource_id=job_id,
            environment=job_record.environment,
            trace_prefix="trace-gateway-fine-tuning-cancel-scope",
        )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.fine_tuning.cancel",
        resource_type="gateway_fine_tuning_job",
        resource_id=job_id,
        trace_id=f"trace-gateway-fine-tuning-cancel-{uuid4()}",
        environment=job_record.environment,
    )
    db.commit()
    return result


# ── Passthrough proxy MVP ──────────────────────────────────────────────────────


@router.post("/v1/passthrough", response_model=GatewayPassthroughResponse)
def gateway_passthrough_proxy(
    payload: GatewayPassthroughRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, GATEWAY_INFERENCE_ROLES)
    trace_id = f"trace-gateway-passthrough-{uuid4()}"
    environment = str(payload.environment or "dev").strip().lower() or "dev"
    _require_prod_dual_approval_audited(
        db,
        ctx,
        environment=environment,
        action_type="gateway.passthrough.execute",
        resource_type="gateway_passthrough",
        resource_id=payload.path,
        trace_prefix="trace-gateway-passthrough-deny",
    )
    try:
        result = execute_passthrough(
            db,
            provider_id=payload.provider_id,
            method=payload.method,
            path=payload.path,
            headers=payload.headers,
            body=payload.body,
            environment=environment,
        )
    except HTTPException as exc:
        create_audit_event(
            db,
            actor_id=ctx.actor_id,
            action_type="gateway.passthrough.execute",
            resource_type="gateway_passthrough",
            resource_id=payload.path,
            trace_id=trace_id,
            decision_outcome="deny" if exc.status_code in {403, 422} else "warn",
            environment=environment,
        )
        db.commit()
        raise

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="gateway.passthrough.execute",
        resource_type="gateway_passthrough",
        resource_id=payload.path,
        trace_id=trace_id,
        decision_outcome="allow",
        environment=environment,
    )
    db.commit()
    return {
        "status_code": result["status_code"],
        "headers": result["headers"],
        "body": result["body"],
        "trace_id": trace_id,
        "provider_id": payload.provider_id,
        "path": payload.path,
    }
