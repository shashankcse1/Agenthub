import os
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.database import Base, SessionLocal, engine
from app.logging_utils import configure_logging, get_logger, sanitize_fields
from app.models import RuntimeConfig, RuntimeConfigValidationRule
from app.request_context import clear_request_actor, get_request_actor_id, get_request_user_login, set_request_actor
from app.services.audit import clear_audit_action_context
from app.routers import (
    agentic,
    agent_configs,
    agents,
    audit,
    auth,
    benchmark_scan,
    browser_security,
    compliance,
    cost,
    discovery,
    gateway,
    gateway_memory,
    gateway_rag,
    governance,
    modules,
    observability,
    orchestration,
    playground,
    platform,
    providers,
    runtime_config,
    route_drafts,
)
from app.runtime_constants import RUNTIME_CONFIG_SECURITY_CORS_ALLOW_ORIGINS_CSV
from app.services.config_cache import runtime_config_cache
from app.services.rate_limit import SlidingWindowRateLimiter
from app.services.discovery_scheduler import start_discovery_scheduler, stop_discovery_scheduler
from app.services.orchestration_scheduler import start_orchestration_scheduler, stop_orchestration_scheduler
from app.services.provider_crypto import provider_encryption_warnings, validate_provider_encryption_configuration
from app.security import (
    insecure_configuration_warnings,
    resolve_request_actor_identity,
    resolve_session_id_from_bearer_token,
    validate_runtime_auth_guardrails,
    validate_session_secret_configuration,
)

configure_logging()
logger = get_logger(__name__)
_SECURITY_ALERT_WEBHOOK_URL = (os.getenv("SECURITY_ALERT_WEBHOOK_URL") or "").strip()


def _security_alert_webhook_timeout_seconds() -> float:
    raw = (os.getenv("SECURITY_ALERT_WEBHOOK_TIMEOUT_SECONDS") or "2.0").strip()
    try:
        parsed = float(raw)
    except ValueError:
        logger.warning(
            "invalid_security_alert_webhook_timeout_seconds %s",
            sanitize_fields({"value": raw, "fallback_seconds": 2.0}),
        )
        return 2.0
    if parsed <= 0:
        logger.warning(
            "non_positive_security_alert_webhook_timeout_seconds %s",
            sanitize_fields({"value": raw, "fallback_seconds": 2.0}),
        )
        return 2.0
    return parsed


_SECURITY_ALERT_WEBHOOK_TIMEOUT_SECONDS = _security_alert_webhook_timeout_seconds()


def _runtime_environment() -> str:
    return (os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "dev").strip().lower()


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _should_auto_create_schema_on_startup() -> bool:
    env = _runtime_environment()
    if env not in {"dev", "test", "local"}:
        if _env_bool("STARTUP_AUTO_CREATE_SCHEMA", False):
            logger.warning(
                "startup_schema_auto_create_ignored_non_local %s",
                sanitize_fields({"environment": env}),
            )
        return False

    return _env_bool("STARTUP_AUTO_CREATE_SCHEMA", True)


def _cors_allow_origins() -> list[str]:
    db = SessionLocal()
    try:
        row = db.query(RuntimeConfig).filter_by(config_key=RUNTIME_CONFIG_SECURITY_CORS_ALLOW_ORIGINS_CSV).first()
        if row and row.config_value.strip():
            origins = [item.strip() for item in row.config_value.split(",") if item.strip()]
            if _runtime_environment() not in {"dev", "test", "local"} and "*" in origins:
                raise RuntimeError("security.cors_allow_origins_csv cannot include '*' outside dev/test/local.")
            if _runtime_environment() not in {"prod", "production"} and "null" not in origins:
                origins.append("null")
            return origins
    except Exception:
        logger.info(
            "runtime_config_cors_lookup_skipped %s",
            sanitize_fields({"environment": _runtime_environment()}),
        )
    finally:
        db.close()

    raw = (os.getenv("CORS_ALLOW_ORIGINS") or "").strip()
    if not raw:
        if _runtime_environment() not in {"prod", "production"}:
            ui_port = (os.getenv("UI_PORT") or "4173").strip() or "4173"
            # Local defaults keep browser-based operator workflows working without extra env setup.
            return [
                "null",
                f"http://127.0.0.1:{ui_port}",
                f"http://localhost:{ui_port}",
            ]
        return []
    origins = [item.strip() for item in raw.split(",") if item.strip()]
    if _runtime_environment() not in {"dev", "test", "local"} and "*" in origins:
        raise RuntimeError("CORS_ALLOW_ORIGINS cannot include '*' outside dev/test/local.")
    if _runtime_environment() not in {"prod", "production"} and "null" not in origins:
        origins.append("null")
    return origins


def _emit_security_alert(warning: str) -> None:
    if not _SECURITY_ALERT_WEBHOOK_URL:
        return
    payload = {
        "event_type": "insecure_configuration_detected",
        "environment": _runtime_environment(),
        "warning": warning,
    }
    try:
        with httpx.Client(timeout=_SECURITY_ALERT_WEBHOOK_TIMEOUT_SECONDS) as client:
            client.post(_SECURITY_ALERT_WEBHOOK_URL, json=payload)
    except Exception:
        logger.error(
            "security_alert_webhook_failed %s",
            sanitize_fields({"warning": warning, "environment": _runtime_environment()}),
        )


def _upgrade_agent_table_schema() -> None:
    statements = [
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS agent_type VARCHAR(64) NOT NULL DEFAULT 'other'",
        "ALTER TABLE agents ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT ''",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_provider_table_schema() -> None:
    statements = [
        "ALTER TABLE workload_identity_federation_profiles ADD COLUMN IF NOT EXISTS role_arn_or_equivalent_encrypted TEXT",
        "ALTER TABLE workload_identity_federation_profiles ADD COLUMN IF NOT EXISTS bootstrap_token_encrypted TEXT",
        "ALTER TABLE secret_provider_configs ADD COLUMN IF NOT EXISTS provider_address_encrypted TEXT",
        "ALTER TABLE secret_provider_configs ADD COLUMN IF NOT EXISTS auth_method_encrypted TEXT",
        "ALTER TABLE secret_provider_configs ADD COLUMN IF NOT EXISTS role_or_mount_encrypted TEXT",
        "ALTER TABLE secret_provider_configs ADD COLUMN IF NOT EXISTS bootstrap_token_encrypted TEXT",
        "ALTER TABLE supported_model_catalog_entries ADD COLUMN IF NOT EXISTS recommendation_rationale TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE supported_model_catalog_entries ADD COLUMN IF NOT EXISTS approval_status VARCHAR(32) NOT NULL DEFAULT 'pending'",
        "ALTER TABLE supported_model_catalog_entries ADD COLUMN IF NOT EXISTS approval_ticket_ref VARCHAR(128)",
        "ALTER TABLE supported_model_catalog_entries ADD COLUMN IF NOT EXISTS approved_by VARCHAR(128)",
        "ALTER TABLE supported_model_catalog_entries ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP",
        "ALTER TABLE supported_model_catalog_entries ADD COLUMN IF NOT EXISTS metadata_version INTEGER NOT NULL DEFAULT 1",
        "CREATE TABLE IF NOT EXISTS supported_model_catalog_revisions ("
        "revision_id VARCHAR(64) PRIMARY KEY,"
        "supported_model_id VARCHAR(64) NOT NULL,"
        "metadata_version INTEGER NOT NULL,"
        "change_type VARCHAR(32) NOT NULL DEFAULT 'update',"
        "provider_type VARCHAR(64) NOT NULL,"
        "model_name VARCHAR(255) NOT NULL,"
        "display_name VARCHAR(255) NOT NULL,"
        "context_window_tokens INTEGER NOT NULL DEFAULT 128000,"
        "status VARCHAR(64) NOT NULL DEFAULT 'active',"
        "description TEXT NOT NULL DEFAULT '',"
        "recommendation_rationale TEXT NOT NULL DEFAULT '',"
        "approval_status VARCHAR(32) NOT NULL DEFAULT 'pending',"
        "approval_ticket_ref VARCHAR(128),"
        "approved_by VARCHAR(128),"
        "approved_at TIMESTAMP,"
        "changed_by VARCHAR(128) NOT NULL,"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_supported_model_revisions_model_version ON supported_model_catalog_revisions (supported_model_id, metadata_version)",
        "CREATE INDEX IF NOT EXISTS ix_supported_model_revisions_status_time ON supported_model_catalog_revisions (approval_status, created_at)",
        "ALTER TABLE supported_model_catalog_entries ADD COLUMN IF NOT EXISTS credential_source_class VARCHAR(32) NOT NULL DEFAULT ''",
        "ALTER TABLE supported_model_catalog_entries ADD COLUMN IF NOT EXISTS default_binding_id VARCHAR(64)",
        "ALTER TABLE agent_configs ADD COLUMN IF NOT EXISTS credential_binding_id VARCHAR(64)",
        "CREATE TABLE IF NOT EXISTS provider_credential_bindings ("
        "binding_id VARCHAR(64) PRIMARY KEY,"
        "tenant_id VARCHAR(128) NOT NULL,"
        "binding_name VARCHAR(255) NOT NULL,"
        "consumer_type VARCHAR(64) NOT NULL,"
        "consumer_key VARCHAR(255) NOT NULL,"
        "provider_type VARCHAR(64) NOT NULL,"
        "credential_plane VARCHAR(32) NOT NULL,"
        "secret_provider_id VARCHAR(64),"
        "secret_ref VARCHAR(255),"
        "workload_identity_profile_id VARCHAR(64),"
        "environment VARCHAR(32) NOT NULL DEFAULT 'dev',"
        "status VARCHAR(32) NOT NULL DEFAULT 'active',"
        "updated_by VARCHAR(128),"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_provider_credential_bindings_scope ON provider_credential_bindings (tenant_id, consumer_type, consumer_key, provider_type, environment)",
        "CREATE INDEX IF NOT EXISTS ix_provider_credential_bindings_tenant_status ON provider_credential_bindings (tenant_id, status)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_directory_identity_schema() -> None:
    statements = [
        "ALTER TABLE directory_users ADD COLUMN IF NOT EXISTS password_hash TEXT",
        "ALTER TABLE directory_users ADD COLUMN IF NOT EXISTS failed_login_attempts INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE directory_users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP",
        "ALTER TABLE directory_users ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMP",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_auth_policy_schema() -> None:
    statements = [
        "ALTER TABLE auth_policy_configs ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE auth_policy_config_revisions ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT ''",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_module_definition_schema() -> None:
    statements = [
        "ALTER TABLE IF EXISTS module_definitions ADD COLUMN IF NOT EXISTS integration_provider VARCHAR(64) NOT NULL DEFAULT ''",
        "ALTER TABLE IF EXISTS module_definitions ADD COLUMN IF NOT EXISTS integration_reference VARCHAR(255) NOT NULL DEFAULT ''",
        "ALTER TABLE IF EXISTS module_definitions ADD COLUMN IF NOT EXISTS integration_sync_status VARCHAR(32) NOT NULL DEFAULT 'not_configured'",
        "ALTER TABLE IF EXISTS module_definitions ADD COLUMN IF NOT EXISTS integration_last_synced_at TIMESTAMP",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_cost_event_schema() -> None:
    statements = [
        "ALTER TABLE cost_events ADD COLUMN IF NOT EXISTS request_tag VARCHAR(64)",
        "CREATE INDEX IF NOT EXISTS ix_cost_events_request_tag ON cost_events (request_tag)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_cache_policy_schema() -> None:
    statements = [
        "ALTER TABLE IF EXISTS cache_policies ADD COLUMN IF NOT EXISTS cache_mode VARCHAR(64) NOT NULL DEFAULT 'exact'",
        "ALTER TABLE IF EXISTS cache_policies ADD COLUMN IF NOT EXISTS similarity_threshold DOUBLE PRECISION NOT NULL DEFAULT 0.9",
        "ALTER TABLE IF EXISTS cache_policies ADD COLUMN IF NOT EXISTS privacy_scope VARCHAR(64) NOT NULL DEFAULT 'tenant'",
        "ALTER TABLE IF EXISTS cache_policies ADD COLUMN IF NOT EXISTS non_cache_data_classes TEXT NOT NULL DEFAULT '[]'",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_cache_decision_event_schema() -> None:
    statements = [
        "ALTER TABLE IF EXISTS cache_decision_events ADD COLUMN IF NOT EXISTS request_fingerprint VARCHAR(128) NOT NULL DEFAULT ''",
        "ALTER TABLE IF EXISTS cache_decision_events ADD COLUMN IF NOT EXISTS request_text TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE IF EXISTS cache_decision_events ADD COLUMN IF NOT EXISTS source_request_id VARCHAR(64)",
        "ALTER TABLE IF EXISTS cache_decision_events ADD COLUMN IF NOT EXISTS match_score DOUBLE PRECISION NOT NULL DEFAULT 0.0",
        "ALTER TABLE IF EXISTS cache_decision_events ADD COLUMN IF NOT EXISTS data_class VARCHAR(64) NOT NULL DEFAULT 'standard'",
        "CREATE INDEX IF NOT EXISTS ix_cache_decision_trace_time ON cache_decision_events (trace_id, timestamp)",
        "CREATE INDEX IF NOT EXISTS ix_cache_decision_policy_time ON cache_decision_events (cache_policy_id, timestamp)",
        "CREATE INDEX IF NOT EXISTS ix_cache_decision_fingerprint_time ON cache_decision_events (request_fingerprint, timestamp)",
        "CREATE INDEX IF NOT EXISTS ix_cache_decision_data_class_time ON cache_decision_events (data_class, timestamp)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_gateway_response_cache_schema() -> None:
    statements = [
        "CREATE TABLE IF NOT EXISTS gateway_response_cache_entries ("
        "cache_entry_id VARCHAR(64) PRIMARY KEY,"
        "cache_policy_id VARCHAR(64) NOT NULL,"
        "request_fingerprint VARCHAR(128) NOT NULL,"
        "request_text TEXT NOT NULL DEFAULT '',"
        "response_body_encrypted TEXT NOT NULL,"
        "tenant_id VARCHAR(128) NOT NULL DEFAULT '',"
        "environment VARCHAR(64) NOT NULL DEFAULT 'dev',"
        "route_policy_id VARCHAR(64),"
        "owner_scope VARCHAR(128) NOT NULL DEFAULT '',"
        "data_class VARCHAR(64) NOT NULL DEFAULT 'standard',"
        "cache_mode VARCHAR(64) NOT NULL DEFAULT 'exact',"
        "match_score DOUBLE PRECISION NOT NULL DEFAULT 1.0,"
        "endpoint_family VARCHAR(64) NOT NULL DEFAULT 'chat.completions',"
        "source_request_id VARCHAR(64),"
        "ttl_expires_at TIMESTAMP NOT NULL,"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "status VARCHAR(64) NOT NULL DEFAULT 'active'"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_gw_cache_entry_fingerprint ON gateway_response_cache_entries (request_fingerprint, cache_policy_id)",
        "CREATE INDEX IF NOT EXISTS ix_gw_cache_entry_policy_expires ON gateway_response_cache_entries (cache_policy_id, ttl_expires_at)",
        "CREATE INDEX IF NOT EXISTS ix_gw_cache_entry_tenant_env ON gateway_response_cache_entries (tenant_id, environment)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_prompt_registry_schema() -> None:
    statements = [
        "CREATE TABLE IF NOT EXISTS prompt_registry_items ("
        "prompt_registry_id VARCHAR(64) PRIMARY KEY,"
        "name VARCHAR(255) NOT NULL,"
        "description TEXT NOT NULL DEFAULT '',"
        "prompt_text TEXT NOT NULL,"
        "labels TEXT NOT NULL DEFAULT '[]',"
        "latest_version INTEGER NOT NULL DEFAULT 1,"
        "status VARCHAR(64) NOT NULL DEFAULT 'active',"
        "created_by VARCHAR(128) NOT NULL,"
        "updated_by VARCHAR(128),"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_prompt_registry_items_name ON prompt_registry_items (name)",
        "CREATE TABLE IF NOT EXISTS prompt_registry_versions ("
        "prompt_registry_version_id VARCHAR(64) PRIMARY KEY,"
        "prompt_registry_id VARCHAR(64) NOT NULL,"
        "version INTEGER NOT NULL,"
        "prompt_text TEXT NOT NULL,"
        "change_reason TEXT NOT NULL DEFAULT '',"
        "created_by VARCHAR(128) NOT NULL,"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_prompt_registry_versions_item_version ON prompt_registry_versions (prompt_registry_id, version)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_operator_feedback_schema() -> None:
    statements = [
        "CREATE TABLE IF NOT EXISTS operator_feedback ("
        "feedback_id VARCHAR(64) PRIMARY KEY,"
        "category VARCHAR(32) NOT NULL DEFAULT 'other',"
        "severity VARCHAR(16) NOT NULL DEFAULT 'medium',"
        "comment TEXT NOT NULL DEFAULT '',"
        "context_view VARCHAR(64) NOT NULL DEFAULT 'overview',"
        "context_action VARCHAR(128) NOT NULL DEFAULT '',"
        "client_latency_ms INTEGER,"
        "trace_id VARCHAR(128),"
        "incident_ref VARCHAR(64),"
        "metadata_json TEXT NOT NULL DEFAULT '{}',"
        "status VARCHAR(32) NOT NULL DEFAULT 'open',"
        "action_note TEXT,"
        "acted_by VARCHAR(128),"
        "acted_at TIMESTAMP,"
        "created_by VARCHAR(128) NOT NULL,"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_operator_feedback_status_created ON operator_feedback (status, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_operator_feedback_category_view ON operator_feedback (category, context_view)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_agent_memory_schema() -> None:
    statements = [
        "CREATE TABLE IF NOT EXISTS agent_memory_records ("
        "memory_id VARCHAR(64) PRIMARY KEY,"
        "memory_tier VARCHAR(32) NOT NULL,"
        "scope_type VARCHAR(32) NOT NULL,"
        "scope_id VARCHAR(128) NOT NULL,"
        "label VARCHAR(256) NOT NULL DEFAULT '',"
        "content TEXT NOT NULL,"
        "metadata_json TEXT NOT NULL DEFAULT '{}',"
        "actor_id VARCHAR(128) NOT NULL,"
        "environment VARCHAR(64) NOT NULL DEFAULT 'dev',"
        "status VARCHAR(32) NOT NULL DEFAULT 'active',"
        "expires_at TIMESTAMP,"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "deleted_at TIMESTAMP"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_agent_memory_records_tier_scope_created ON agent_memory_records (memory_tier, scope_type, scope_id, created_at)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_playground_feedback_schema() -> None:
    statements = [
        "CREATE TABLE IF NOT EXISTS playground_run_feedback ("
        "feedback_id VARCHAR(64) PRIMARY KEY,"
        "run_id VARCHAR(64) NOT NULL,"
        "trace_id VARCHAR(128) NOT NULL,"
        "rating INTEGER NOT NULL DEFAULT 3,"
        "quality_score FLOAT NOT NULL DEFAULT 0.0,"
        "comment TEXT NOT NULL DEFAULT '',"
        "created_by VARCHAR(128) NOT NULL,"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_playground_run_feedback_run_trace ON playground_run_feedback (run_id, trace_id)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_playground_quality_escalation_schema() -> None:
    statements = [
        "CREATE TABLE IF NOT EXISTS playground_quality_escalations ("
        "escalation_id VARCHAR(64) PRIMARY KEY,"
        "feedback_id VARCHAR(64) NOT NULL,"
        "run_id VARCHAR(64) NOT NULL,"
        "trace_id VARCHAR(128) NOT NULL,"
        "run_actor_id VARCHAR(128) NOT NULL,"
        "status VARCHAR(32) NOT NULL DEFAULT 'open',"
        "severity VARCHAR(32) NOT NULL DEFAULT 'high',"
        "priority_tag VARCHAR(8) NOT NULL DEFAULT 'p1',"
        "assigned_team VARCHAR(128) NOT NULL DEFAULT 'ai-trust-ops',"
        "escalation_channel VARCHAR(128) NOT NULL DEFAULT 'security-ops',"
        "external_ticket_ref VARCHAR(128),"
        "escalation_reason TEXT NOT NULL,"
        "sla_target_minutes INTEGER NOT NULL DEFAULT 60,"
        "due_at TIMESTAMP NOT NULL,"
        "acknowledged_by VARCHAR(128),"
        "acknowledged_at TIMESTAMP,"
        "resolved_by VARCHAR(128),"
        "resolved_at TIMESTAMP,"
        "resolution_note TEXT,"
        "created_by VARCHAR(128) NOT NULL,"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_playground_quality_escalations_status_due ON playground_quality_escalations (status, due_at)",
        "CREATE INDEX IF NOT EXISTS ix_playground_quality_escalations_feedback ON playground_quality_escalations (feedback_id)",
        "CREATE TABLE IF NOT EXISTS playground_quality_escalation_notifications ("
        "notification_id VARCHAR(64) PRIMARY KEY,"
        "escalation_id VARCHAR(64) NOT NULL,"
        "channel VARCHAR(128) NOT NULL,"
        "destination VARCHAR(255) NOT NULL,"
        "payload_preview TEXT NOT NULL DEFAULT '',"
        "receipt_id VARCHAR(64) NOT NULL,"
        "attempts INTEGER NOT NULL DEFAULT 1,"
        "delivery_status VARCHAR(32) NOT NULL DEFAULT 'sent',"
        "error_message TEXT,"
        "created_by VARCHAR(128) NOT NULL,"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_pqen_escalation_created ON playground_quality_escalation_notifications (escalation_id, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_pqen_status_created ON playground_quality_escalation_notifications (delivery_status, created_at)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_realtime_session_schema() -> None:
    statements = [
        "CREATE TABLE IF NOT EXISTS realtime_session_records ("
        "session_id VARCHAR(64) PRIMARY KEY,"
        "request_id VARCHAR(128) NOT NULL,"
        "trace_id VARCHAR(128) NOT NULL,"
        "actor_id VARCHAR(128) NOT NULL,"
        "environment VARCHAR(64) NOT NULL DEFAULT 'dev',"
        "model_name VARCHAR(255) NOT NULL,"
        "session_label VARCHAR(128),"
        "requested_modalities_json TEXT NOT NULL DEFAULT '[]',"
        "stream_policy_json TEXT NOT NULL DEFAULT '{}',"
        "event_count INTEGER NOT NULL DEFAULT 0,"
        "total_event_bytes INTEGER NOT NULL DEFAULT 0,"
        "last_event_type VARCHAR(64),"
        "status VARCHAR(32) NOT NULL DEFAULT 'active',"
        "expires_at TIMESTAMP NOT NULL,"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "closed_at TIMESTAMP"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_realtime_session_records_actor_created ON realtime_session_records (actor_id, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_realtime_session_records_status_created ON realtime_session_records (status, created_at)",
        "ALTER TABLE IF EXISTS realtime_session_records ADD COLUMN IF NOT EXISTS total_event_bytes INTEGER NOT NULL DEFAULT 0",
        "CREATE TABLE IF NOT EXISTS realtime_session_event_records ("
        "event_id VARCHAR(64) PRIMARY KEY,"
        "session_id VARCHAR(64) NOT NULL,"
        "request_id VARCHAR(128) NOT NULL,"
        "trace_id VARCHAR(128) NOT NULL,"
        "actor_id VARCHAR(128) NOT NULL,"
        "event_type VARCHAR(64) NOT NULL,"
        "binary_mode VARCHAR(32) NOT NULL DEFAULT 'metadata_only',"
        "event_bytes INTEGER NOT NULL DEFAULT 0,"
        "payload_json TEXT NOT NULL DEFAULT '{}',"
        "status VARCHAR(32) NOT NULL DEFAULT 'accepted',"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_realtime_session_event_records_session_created ON realtime_session_event_records (session_id, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_realtime_session_event_records_actor_created ON realtime_session_event_records (actor_id, created_at)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_discovery_record_schema() -> None:
    statements = [
        "ALTER TABLE IF EXISTS discovery_records ADD COLUMN IF NOT EXISTS merged_into_discovered_agent_id VARCHAR(64)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_audit_event_schema() -> None:
    statements = [
        "ALTER TABLE IF EXISTS audit_events ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(128)",
        "ALTER TABLE IF EXISTS audit_events ADD COLUMN IF NOT EXISTS environment VARCHAR(64)",
        "ALTER TABLE IF EXISTS audit_events ADD COLUMN IF NOT EXISTS actor_login VARCHAR(255)",
        "ALTER TABLE IF EXISTS audit_events ADD COLUMN IF NOT EXISTS actor_role VARCHAR(128)",
        "ALTER TABLE IF EXISTS audit_events ADD COLUMN IF NOT EXISTS action_description VARCHAR(512)",
        "ALTER TABLE IF EXISTS audit_events ADD COLUMN IF NOT EXISTS action_context_json TEXT",
        "CREATE INDEX IF NOT EXISTS ix_audit_events_tenant_env_time ON audit_events (tenant_id, environment, timestamp)",
        "CREATE INDEX IF NOT EXISTS ix_audit_events_actor_login_time ON audit_events (actor_login, timestamp)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_gateway_assistants_schema() -> None:
    statements = [
        "CREATE TABLE IF NOT EXISTS gateway_assistant_records ("
        "assistant_id VARCHAR(64) PRIMARY KEY,"
        "actor_id VARCHAR(128) NOT NULL,"
        "environment VARCHAR(64) NOT NULL DEFAULT 'dev',"
        "name VARCHAR(255) NOT NULL,"
        "model VARCHAR(255) NOT NULL,"
        "instructions TEXT NOT NULL DEFAULT '',"
        "metadata_json TEXT NOT NULL DEFAULT '{}',"
        "status VARCHAR(32) NOT NULL DEFAULT 'active',"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "deleted_at TIMESTAMP"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_gateway_assistant_records_actor_created ON gateway_assistant_records (actor_id, created_at)",
        "CREATE TABLE IF NOT EXISTS gateway_assistant_thread_records ("
        "thread_id VARCHAR(64) PRIMARY KEY,"
        "actor_id VARCHAR(128) NOT NULL,"
        "environment VARCHAR(64) NOT NULL DEFAULT 'dev',"
        "metadata_json TEXT NOT NULL DEFAULT '{}',"
        "status VARCHAR(32) NOT NULL DEFAULT 'active',"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_gateway_assistant_threads_actor_created ON gateway_assistant_thread_records (actor_id, created_at)",
        "CREATE TABLE IF NOT EXISTS gateway_assistant_thread_message_records ("
        "message_id VARCHAR(64) PRIMARY KEY,"
        "thread_id VARCHAR(64) NOT NULL,"
        "actor_id VARCHAR(128) NOT NULL,"
        "role VARCHAR(32) NOT NULL,"
        "content TEXT NOT NULL,"
        "metadata_json TEXT NOT NULL DEFAULT '{}',"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_gateway_assistant_thread_messages_thread_created ON gateway_assistant_thread_message_records (thread_id, created_at)",
        "CREATE TABLE IF NOT EXISTS gateway_assistant_thread_run_records ("
        "run_id VARCHAR(64) PRIMARY KEY,"
        "thread_id VARCHAR(64) NOT NULL,"
        "assistant_id VARCHAR(64) NOT NULL,"
        "actor_id VARCHAR(128) NOT NULL,"
        "environment VARCHAR(64) NOT NULL DEFAULT 'dev',"
        "model VARCHAR(255) NOT NULL,"
        "status VARCHAR(32) NOT NULL DEFAULT 'queued',"
        "response_text TEXT NOT NULL DEFAULT '',"
        "trace_id VARCHAR(128) NOT NULL,"
        "metadata_json TEXT NOT NULL DEFAULT '{}',"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "completed_at TIMESTAMP"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_gateway_assistant_thread_runs_thread_created ON gateway_assistant_thread_run_records (thread_id, created_at)",
        "CREATE TABLE IF NOT EXISTS gateway_fine_tuning_job_records ("
        "job_id VARCHAR(64) PRIMARY KEY,"
        "actor_id VARCHAR(128) NOT NULL,"
        "environment VARCHAR(64) NOT NULL DEFAULT 'dev',"
        "model VARCHAR(255) NOT NULL,"
        "training_file_id VARCHAR(128) NOT NULL,"
        "fine_tuned_model VARCHAR(255),"
        "status VARCHAR(32) NOT NULL DEFAULT 'queued',"
        "metadata_json TEXT NOT NULL DEFAULT '{}',"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "finished_at TIMESTAMP"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_gateway_fine_tuning_jobs_actor_created ON gateway_fine_tuning_job_records (actor_id, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_gateway_fine_tuning_jobs_status_created ON gateway_fine_tuning_job_records (status, created_at)",
        "ALTER TABLE gateway_assistant_records ADD COLUMN IF NOT EXISTS model VARCHAR(255) NOT NULL DEFAULT 'gpt-4o-mini'",
        "ALTER TABLE gateway_assistant_records ADD COLUMN IF NOT EXISTS instructions TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE gateway_assistant_records ADD COLUMN IF NOT EXISTS metadata_json TEXT NOT NULL DEFAULT '{}'",
        "ALTER TABLE gateway_assistant_records ADD COLUMN IF NOT EXISTS status VARCHAR(32) NOT NULL DEFAULT 'active'",
        "ALTER TABLE gateway_assistant_records ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMP",
        "ALTER TABLE gateway_fine_tuning_job_records ADD COLUMN IF NOT EXISTS model VARCHAR(255) NOT NULL DEFAULT 'gpt-4o-mini'",
        "ALTER TABLE gateway_fine_tuning_job_records ADD COLUMN IF NOT EXISTS training_file_id VARCHAR(128) NOT NULL DEFAULT ''",
        "ALTER TABLE gateway_fine_tuning_job_records ADD COLUMN IF NOT EXISTS fine_tuned_model VARCHAR(255)",
        "ALTER TABLE gateway_fine_tuning_job_records ADD COLUMN IF NOT EXISTS status VARCHAR(32) NOT NULL DEFAULT 'queued'",
        "ALTER TABLE gateway_fine_tuning_job_records ADD COLUMN IF NOT EXISTS metadata_json TEXT NOT NULL DEFAULT '{}'",
        "ALTER TABLE gateway_fine_tuning_job_records ADD COLUMN IF NOT EXISTS finished_at TIMESTAMP",
    ]
    legacy_statements = [
        "UPDATE gateway_assistant_records SET model = model_name WHERE model_name IS NOT NULL AND (model IS NULL OR model = 'gpt-4o-mini')",
        "ALTER TABLE gateway_assistant_records ALTER COLUMN model_name DROP NOT NULL",
        "ALTER TABLE gateway_assistant_records DROP COLUMN IF EXISTS model_name",
        "ALTER TABLE gateway_assistant_records DROP COLUMN IF EXISTS tools_json",
        "UPDATE gateway_fine_tuning_job_records SET model = model_name WHERE model_name IS NOT NULL AND (model IS NULL OR model = 'gpt-4o-mini')",
        "ALTER TABLE gateway_fine_tuning_job_records ALTER COLUMN model_name DROP NOT NULL",
        "ALTER TABLE gateway_fine_tuning_job_records ALTER COLUMN trace_id DROP NOT NULL",
        "ALTER TABLE gateway_fine_tuning_job_records DROP COLUMN IF EXISTS model_name",
        "ALTER TABLE gateway_fine_tuning_job_records DROP COLUMN IF EXISTS trace_id",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))
        for statement in legacy_statements:
            try:
                connection.execute(text(statement))
            except Exception as exc:
                logger.debug("gateway_assistants_legacy_migration_skipped %s", exc)


def _upgrade_orchestration_schema() -> None:
    statements = [
        "CREATE TABLE IF NOT EXISTS orchestration_flow_definitions ("
        "flow_id VARCHAR(64) PRIMARY KEY,"
        "flow_name VARCHAR(255) NOT NULL,"
        "description TEXT NOT NULL DEFAULT '',"
        "status VARCHAR(32) NOT NULL DEFAULT 'draft',"
        "environment VARCHAR(32) NOT NULL DEFAULT 'dev',"
        "tenant_id VARCHAR(128),"
        "trigger_type VARCHAR(32) NOT NULL DEFAULT 'manual',"
        "trigger_config_json TEXT NOT NULL DEFAULT '{}',"
        "graph_json TEXT NOT NULL DEFAULT '{\"nodes\":[],\"edges\":[]}',"
        "approval_status VARCHAR(32) NOT NULL DEFAULT 'pending',"
        "metadata_version INTEGER NOT NULL DEFAULT 1,"
        "created_by VARCHAR(128) NOT NULL,"
        "updated_by VARCHAR(128),"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        "ALTER TABLE orchestration_flow_definitions ADD COLUMN IF NOT EXISTS access_policy_json TEXT NOT NULL DEFAULT '{}'",
        "ALTER TABLE orchestration_flow_definitions ADD COLUMN IF NOT EXISTS approval_stage_state_json TEXT NOT NULL DEFAULT '{}'",
        "CREATE INDEX IF NOT EXISTS ix_orchestration_flows_env_status ON orchestration_flow_definitions (environment, status)",
        "CREATE INDEX IF NOT EXISTS ix_orchestration_flows_tenant_env ON orchestration_flow_definitions (tenant_id, environment)",
        "CREATE TABLE IF NOT EXISTS orchestration_flow_runs ("
        "run_id VARCHAR(64) PRIMARY KEY,"
        "flow_id VARCHAR(64) NOT NULL,"
        "status VARCHAR(32) NOT NULL DEFAULT 'running',"
        "started_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "finished_at TIMESTAMP,"
        "trace_id VARCHAR(128) NOT NULL,"
        "step_results_json TEXT NOT NULL DEFAULT '[]',"
        "error_summary TEXT,"
        "execution_state_json TEXT"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_orchestration_flow_runs_flow_started ON orchestration_flow_runs (flow_id, started_at)",
        "ALTER TABLE orchestration_flow_runs ADD COLUMN IF NOT EXISTS execution_state_json TEXT",
        "CREATE TABLE IF NOT EXISTS orchestration_run_approval_gates ("
        "gate_id VARCHAR(64) PRIMARY KEY,"
        "run_id VARCHAR(64) NOT NULL,"
        "flow_id VARCHAR(64) NOT NULL,"
        "node_id VARCHAR(128) NOT NULL,"
        "status VARCHAR(32) NOT NULL DEFAULT 'pending',"
        "approval_title VARCHAR(512) NOT NULL,"
        "required_role VARCHAR(128),"
        "resolved_approver_id VARCHAR(128),"
        "resolved_approver_role VARCHAR(128),"
        "decided_by VARCHAR(128),"
        "decided_at TIMESTAMP,"
        "metadata_json TEXT NOT NULL DEFAULT '{}',"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_orchestration_approval_gates_run_status ON orchestration_run_approval_gates (run_id, status)",
        "CREATE INDEX IF NOT EXISTS ix_orchestration_approval_gates_flow_run ON orchestration_run_approval_gates (flow_id, run_id)",
        "CREATE TABLE IF NOT EXISTS orchestration_jit_access_requests ("
        "request_id VARCHAR(64) PRIMARY KEY,"
        "flow_id VARCHAR(64) NOT NULL,"
        "requester_id VARCHAR(128) NOT NULL,"
        "requester_role VARCHAR(128) NOT NULL,"
        "requested_action VARCHAR(32) NOT NULL,"
        "justification TEXT NOT NULL,"
        "environment VARCHAR(64) NOT NULL DEFAULT 'dev',"
        "requested_duration_minutes INTEGER NOT NULL DEFAULT 60,"
        "status VARCHAR(64) NOT NULL DEFAULT 'requested',"
        "approved_by VARCHAR(128),"
        "approved_role VARCHAR(128),"
        "approved_at TIMESTAMP,"
        "expires_at TIMESTAMP,"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_orchestration_jit_status_env ON orchestration_jit_access_requests (status, environment)",
        "CREATE INDEX IF NOT EXISTS ix_orchestration_jit_flow_requester ON orchestration_jit_access_requests (flow_id, requester_id)",
        "CREATE TABLE IF NOT EXISTS orchestration_flow_access_certifications ("
        "certification_id VARCHAR(64) PRIMARY KEY,"
        "flow_id VARCHAR(64) NOT NULL,"
        "certified_by VARCHAR(128) NOT NULL,"
        "approver_id VARCHAR(128),"
        "certified_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "next_due_at TIMESTAMP NOT NULL,"
        "attestation_notes TEXT NOT NULL DEFAULT '',"
        "status VARCHAR(32) NOT NULL DEFAULT 'active'"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_orchestration_cert_flow_status ON orchestration_flow_access_certifications (flow_id, status)",
        "CREATE INDEX IF NOT EXISTS ix_orchestration_cert_next_due ON orchestration_flow_access_certifications (next_due_at, status)",
        "CREATE TABLE IF NOT EXISTS orchestration_flow_approval_events ("
        "approval_event_id VARCHAR(64) PRIMARY KEY,"
        "flow_id VARCHAR(64) NOT NULL,"
        "event_type VARCHAR(64) NOT NULL,"
        "stage_id VARCHAR(128),"
        "action VARCHAR(64) NOT NULL,"
        "state_from VARCHAR(64) NOT NULL,"
        "state_to VARCHAR(64) NOT NULL,"
        "actor_id VARCHAR(128) NOT NULL,"
        "actor_role VARCHAR(128) NOT NULL,"
        "approver_id VARCHAR(128),"
        "decision VARCHAR(64) NOT NULL,"
        "reason_code VARCHAR(255),"
        "ticket_ref VARCHAR(128),"
        "occurred_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_orchestration_approval_events_flow ON orchestration_flow_approval_events (flow_id, occurred_at)",
    ]
    with engine.begin() as connection:
        for statement in statements:
            connection.execute(text(statement))


def _upgrade_browser_security_schema() -> None:
    """Idempotent DDL for GuardBridge browser security tables.

    Strategy: CREATE TABLE IF NOT EXISTS with minimal base columns, then
    ADD COLUMN IF NOT EXISTS for every analytics column. This handles both
    fresh installs and upgrades from pre-existing tables.

    Privacy guarantees enforced at DDL level:
    - geo_city column deliberately omitted (stripped at ingest layer).
    - No raw_ip, raw_ua, or prompt_text columns exist in any table.
    """
    base_statements = [
        # ── Browser extension sessions (base) ─────────────────────────────────
        "CREATE TABLE IF NOT EXISTS browser_extension_sessions ("
        "session_id VARCHAR(64) PRIMARY KEY,"
        "actor_id VARCHAR(128) NOT NULL,"
        "status VARCHAR(32) NOT NULL DEFAULT 'active',"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        # Analytics columns — added via ALTER so upgrades are safe
        "ALTER TABLE browser_extension_sessions ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(128)",
        "ALTER TABLE browser_extension_sessions ADD COLUMN IF NOT EXISTS environment VARCHAR(64) NOT NULL DEFAULT 'dev'",
        "ALTER TABLE browser_extension_sessions ADD COLUMN IF NOT EXISTS browser_name VARCHAR(64) NOT NULL DEFAULT 'unknown'",
        # Backwards-compat: old browser_type / platform columns get defaults so they no longer block inserts
        "ALTER TABLE browser_extension_sessions ALTER COLUMN browser_type SET DEFAULT 'unknown'",
        "ALTER TABLE browser_extension_sessions ALTER COLUMN platform SET DEFAULT 'unknown'",
        "ALTER TABLE browser_extension_sessions ADD COLUMN IF NOT EXISTS browser_version VARCHAR(64) NOT NULL DEFAULT ''",
        "ALTER TABLE browser_extension_sessions ADD COLUMN IF NOT EXISTS extension_version VARCHAR(64) NOT NULL DEFAULT ''",
        "ALTER TABLE browser_extension_sessions ADD COLUMN IF NOT EXISTS os_name VARCHAR(64) NOT NULL DEFAULT 'unknown'",
        "ALTER TABLE browser_extension_sessions ADD COLUMN IF NOT EXISTS os_version VARCHAR(64) NOT NULL DEFAULT ''",
        "ALTER TABLE browser_extension_sessions ADD COLUMN IF NOT EXISTS device_type VARCHAR(32) NOT NULL DEFAULT 'unknown'",
        "ALTER TABLE browser_extension_sessions ADD COLUMN IF NOT EXISTS device_managed BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE browser_extension_sessions ADD COLUMN IF NOT EXISTS user_agent_digest VARCHAR(64) NOT NULL DEFAULT ''",
        "ALTER TABLE browser_extension_sessions ADD COLUMN IF NOT EXISTS geo_country VARCHAR(8) NOT NULL DEFAULT ''",
        "ALTER TABLE browser_extension_sessions ADD COLUMN IF NOT EXISTS geo_region VARCHAR(128) NOT NULL DEFAULT ''",
        # geo_city intentionally absent — stripped server-side at ingest
        "ALTER TABLE browser_extension_sessions ADD COLUMN IF NOT EXISTS geo_detail_level VARCHAR(32) NOT NULL DEFAULT 'country'",
        "ALTER TABLE browser_extension_sessions ADD COLUMN IF NOT EXISTS ip_hash VARCHAR(64) NOT NULL DEFAULT ''",
        "ALTER TABLE browser_extension_sessions ADD COLUMN IF NOT EXISTS last_heartbeat_at TIMESTAMP",
        "ALTER TABLE browser_extension_sessions ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP",
        "CREATE INDEX IF NOT EXISTS ix_browser_ext_sessions_actor_created ON browser_extension_sessions (actor_id, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_browser_ext_sessions_status_created ON browser_extension_sessions (status, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_browser_ext_sessions_browser ON browser_extension_sessions (browser_name)",
        "CREATE INDEX IF NOT EXISTS ix_browser_ext_sessions_geo_country ON browser_extension_sessions (geo_country)",
        # ── Browser security events (base) ────────────────────────────────────
        "CREATE TABLE IF NOT EXISTS browser_security_events ("
        "event_id VARCHAR(64) PRIMARY KEY,"
        "trace_id VARCHAR(128) NOT NULL,"
        "actor_id VARCHAR(128) NOT NULL,"
        "action_type VARCHAR(64) NOT NULL,"
        "decision_outcome VARCHAR(32) NOT NULL,"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        "ALTER TABLE browser_security_events ADD COLUMN IF NOT EXISTS ext_session_id VARCHAR(64)",
        "ALTER TABLE browser_security_events ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(128)",
        "ALTER TABLE browser_security_events ADD COLUMN IF NOT EXISTS environment VARCHAR(64) NOT NULL DEFAULT 'dev'",
        "ALTER TABLE browser_security_events ADD COLUMN IF NOT EXISTS destination_domain VARCHAR(255) NOT NULL DEFAULT ''",
        "ALTER TABLE browser_security_events ADD COLUMN IF NOT EXISTS destination_app VARCHAR(128) NOT NULL DEFAULT ''",
        "ALTER TABLE browser_security_events ADD COLUMN IF NOT EXISTS page_url_host VARCHAR(255) NOT NULL DEFAULT ''",
        "ALTER TABLE browser_security_events ADD COLUMN IF NOT EXISTS policy_rule_id VARCHAR(128)",
        "ALTER TABLE browser_security_events ADD COLUMN IF NOT EXISTS risk_signals TEXT NOT NULL DEFAULT '[]'",
        "ALTER TABLE browser_security_events ADD COLUMN IF NOT EXISTS content_fingerprint VARCHAR(128) NOT NULL DEFAULT ''",
        "ALTER TABLE browser_security_events ADD COLUMN IF NOT EXISTS data_class VARCHAR(64) NOT NULL DEFAULT 'standard'",
        "ALTER TABLE browser_security_events ADD COLUMN IF NOT EXISTS browser_name VARCHAR(64) NOT NULL DEFAULT 'unknown'",
        # Backwards-compat: old browser_type column (NOT NULL no default) gets a default so it no longer blocks inserts
        "ALTER TABLE browser_security_events ALTER COLUMN browser_type SET DEFAULT 'unknown'",
        "ALTER TABLE browser_security_events ADD COLUMN IF NOT EXISTS browser_version VARCHAR(64) NOT NULL DEFAULT ''",
        "ALTER TABLE browser_security_events ADD COLUMN IF NOT EXISTS os_name VARCHAR(64) NOT NULL DEFAULT 'unknown'",
        "ALTER TABLE browser_security_events ADD COLUMN IF NOT EXISTS device_type VARCHAR(32) NOT NULL DEFAULT 'unknown'",
        "ALTER TABLE browser_security_events ADD COLUMN IF NOT EXISTS geo_country VARCHAR(8) NOT NULL DEFAULT ''",
        "ALTER TABLE browser_security_events ADD COLUMN IF NOT EXISTS geo_region VARCHAR(128) NOT NULL DEFAULT ''",
        "CREATE INDEX IF NOT EXISTS ix_browser_sec_events_actor_created ON browser_security_events (actor_id, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_browser_sec_events_decision_created ON browser_security_events (decision_outcome, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_browser_sec_events_domain_created ON browser_security_events (destination_domain, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_browser_sec_events_action_created ON browser_security_events (action_type, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_browser_sec_events_browser_created ON browser_security_events (browser_name, created_at)",
        "CREATE INDEX IF NOT EXISTS ix_browser_sec_events_geo_decision ON browser_security_events (geo_country, decision_outcome)",
        # ── Shadow AI app inventory ────────────────────────────────────────────
        "CREATE TABLE IF NOT EXISTS browser_shadow_ai_apps ("
        "app_id VARCHAR(64) PRIMARY KEY,"
        "domain VARCHAR(255) NOT NULL UNIQUE,"
        "app_name VARCHAR(255) NOT NULL DEFAULT '',"
        "category VARCHAR(128) NOT NULL DEFAULT 'generative-ai',"
        "risk_score INTEGER NOT NULL DEFAULT 50,"
        "status VARCHAR(32) NOT NULL DEFAULT 'unsanctioned',"
        "first_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "last_seen_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "active_user_count INTEGER NOT NULL DEFAULT 0,"
        "data_upload_events INTEGER NOT NULL DEFAULT 0,"
        "notes TEXT NOT NULL DEFAULT '',"
        "reviewed_by VARCHAR(128),"
        "reviewed_at TIMESTAMP"
        ")",
        "CREATE INDEX IF NOT EXISTS ix_browser_shadow_ai_status ON browser_shadow_ai_apps (status)",
        # ── Browser risk policies ──────────────────────────────────────────────
        "CREATE TABLE IF NOT EXISTS browser_risk_policies ("
        "policy_id VARCHAR(64) PRIMARY KEY,"
        "name VARCHAR(255) NOT NULL,"
        "created_by VARCHAR(128) NOT NULL,"
        "created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,"
        "updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        "ALTER TABLE browser_risk_policies ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE browser_risk_policies ADD COLUMN IF NOT EXISTS scope_type VARCHAR(64) NOT NULL DEFAULT 'global'",
        "ALTER TABLE browser_risk_policies ADD COLUMN IF NOT EXISTS scope_value VARCHAR(255) NOT NULL DEFAULT ''",
        "ALTER TABLE browser_risk_policies ADD COLUMN IF NOT EXISTS action_type_pattern VARCHAR(128) NOT NULL DEFAULT '*'",
        "ALTER TABLE browser_risk_policies ADD COLUMN IF NOT EXISTS domain_pattern VARCHAR(255) NOT NULL DEFAULT '*'",
        "ALTER TABLE browser_risk_policies ADD COLUMN IF NOT EXISTS data_class_filter VARCHAR(128) NOT NULL DEFAULT '*'",
        "ALTER TABLE browser_risk_policies ADD COLUMN IF NOT EXISTS decision_mode VARCHAR(32) NOT NULL DEFAULT 'warn'",
        "ALTER TABLE browser_risk_policies ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT TRUE",
        "ALTER TABLE browser_risk_policies ADD COLUMN IF NOT EXISTS environment VARCHAR(64) NOT NULL DEFAULT 'dev'",
        "ALTER TABLE browser_risk_policies ADD COLUMN IF NOT EXISTS geo_collection_enabled BOOLEAN NOT NULL DEFAULT FALSE",
        "ALTER TABLE browser_risk_policies ADD COLUMN IF NOT EXISTS geo_detail_level VARCHAR(32) NOT NULL DEFAULT 'country'",
        "ALTER TABLE browser_risk_policies ADD COLUMN IF NOT EXISTS analytics_retention_days INTEGER NOT NULL DEFAULT 90",
        "ALTER TABLE browser_risk_policies ADD COLUMN IF NOT EXISTS updated_by VARCHAR(128)",
        "CREATE INDEX IF NOT EXISTS ix_browser_risk_policy_enabled ON browser_risk_policies (enabled)",
        "CREATE INDEX IF NOT EXISTS ix_browser_risk_policy_scope ON browser_risk_policies (scope_type)",
        "CREATE INDEX IF NOT EXISTS ix_browser_risk_policy_env ON browser_risk_policies (environment)",
        # ── Analytics summaries ───────────────────────────────────────────────
        "CREATE TABLE IF NOT EXISTS browser_analytics_summaries ("
        "summary_id VARCHAR(64) PRIMARY KEY,"
        "bucket_date VARCHAR(16) NOT NULL,"
        "environment VARCHAR(64) NOT NULL DEFAULT 'dev',"
        "computed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP"
        ")",
        "ALTER TABLE browser_analytics_summaries ADD COLUMN IF NOT EXISTS tenant_id VARCHAR(128)",
        "ALTER TABLE browser_analytics_summaries ADD COLUMN IF NOT EXISTS browser_name VARCHAR(64) NOT NULL DEFAULT 'all'",
        "ALTER TABLE browser_analytics_summaries ADD COLUMN IF NOT EXISTS os_name VARCHAR(64) NOT NULL DEFAULT 'all'",
        "ALTER TABLE browser_analytics_summaries ADD COLUMN IF NOT EXISTS device_type VARCHAR(32) NOT NULL DEFAULT 'all'",
        "ALTER TABLE browser_analytics_summaries ADD COLUMN IF NOT EXISTS geo_country VARCHAR(8) NOT NULL DEFAULT ''",
        "ALTER TABLE browser_analytics_summaries ADD COLUMN IF NOT EXISTS geo_region VARCHAR(128) NOT NULL DEFAULT ''",
        "ALTER TABLE browser_analytics_summaries ADD COLUMN IF NOT EXISTS total_events INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE browser_analytics_summaries ADD COLUMN IF NOT EXISTS allow_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE browser_analytics_summaries ADD COLUMN IF NOT EXISTS warn_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE browser_analytics_summaries ADD COLUMN IF NOT EXISTS challenge_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE browser_analytics_summaries ADD COLUMN IF NOT EXISTS deny_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE browser_analytics_summaries ADD COLUMN IF NOT EXISTS mask_count INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE browser_analytics_summaries ADD COLUMN IF NOT EXISTS unique_actors INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE browser_analytics_summaries ADD COLUMN IF NOT EXISTS unique_domains INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE browser_analytics_summaries ADD COLUMN IF NOT EXISTS shadow_ai_hits INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE browser_analytics_summaries ADD COLUMN IF NOT EXISTS pii_events INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE browser_analytics_summaries ADD COLUMN IF NOT EXISTS credentials_events INTEGER NOT NULL DEFAULT 0",
        "CREATE INDEX IF NOT EXISTS ix_browser_analytics_date_env ON browser_analytics_summaries (bucket_date, environment)",
        "CREATE INDEX IF NOT EXISTS ix_browser_analytics_browser ON browser_analytics_summaries (browser_name)",
        "CREATE INDEX IF NOT EXISTS ix_browser_analytics_geo ON browser_analytics_summaries (geo_country)",
    ]
    with engine.begin() as connection:
        for statement in base_statements:
            connection.execute(text(statement))


@asynccontextmanager
async def lifespan(_: FastAPI):
    validate_session_secret_configuration()
    validate_runtime_auth_guardrails()
    validate_provider_encryption_configuration()
    for warning in [*insecure_configuration_warnings(), *provider_encryption_warnings()]:
        logger.warning("insecure_configuration_detected %s", sanitize_fields({"warning": warning}))
        _emit_security_alert(warning)
    if _should_auto_create_schema_on_startup():
        Base.metadata.create_all(bind=engine)
        _upgrade_agent_table_schema()
        _upgrade_provider_table_schema()
        _upgrade_directory_identity_schema()
        _upgrade_auth_policy_schema()
        _upgrade_module_definition_schema()
        _upgrade_cost_event_schema()
        _upgrade_cache_policy_schema()
        _upgrade_cache_decision_event_schema()
        _upgrade_gateway_response_cache_schema()
        _upgrade_prompt_registry_schema()
        _upgrade_module_definition_schema()
        _upgrade_playground_feedback_schema()
        _upgrade_playground_quality_escalation_schema()
        _upgrade_realtime_session_schema()
        _upgrade_audit_event_schema()
        _upgrade_discovery_record_schema()
        _upgrade_browser_security_schema()
        _upgrade_operator_feedback_schema()
        _upgrade_agent_memory_schema()
        _upgrade_gateway_assistants_schema()
        _upgrade_orchestration_schema()
    else:
        _upgrade_cache_policy_schema()
        _upgrade_cache_decision_event_schema()
        _upgrade_gateway_response_cache_schema()
        _upgrade_prompt_registry_schema()
        _upgrade_playground_feedback_schema()
        _upgrade_playground_quality_escalation_schema()
        _upgrade_realtime_session_schema()
        _upgrade_audit_event_schema()
        _upgrade_discovery_record_schema()
        _upgrade_browser_security_schema()
        _upgrade_operator_feedback_schema()
        _upgrade_agent_memory_schema()
        _upgrade_gateway_assistants_schema()
        _upgrade_orchestration_schema()
        logger.info(
            "startup_schema_auto_create_skipped %s",
            sanitize_fields({"environment": _runtime_environment()}),
        )
    start_discovery_scheduler()
    start_orchestration_scheduler()
    try:
        yield
    finally:
        stop_orchestration_scheduler()
        stop_discovery_scheduler()


app = FastAPI(
    title="Enterprise Multi-Agent Platform API",
    description=(
        "Security-first multi-agent platform API with audited control-plane workflows, "
        "role-based authorization, dual-approval guardrails for sensitive production actions, "
        "and OpenAI-compatible gateway operations."
    ),
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_tags=[
        {"name": "Health", "description": "Service readiness and runtime status endpoints."},
        {"name": "Benchmark and Scan", "description": "Benchmark and security scan execution/history workflows."},
        {"name": "Agents", "description": "Agent registration and ownership workflows."},
        {"name": "Agent Config", "description": "Persisted runtime agent configuration controls."},
        {"name": "Auth and Security", "description": "AuthN/AuthZ, session, and governance controls."},
        {"name": "Audit", "description": "Audit evidence querying and traceability endpoints."},
        {"name": "Discovery", "description": "Source sync and discovered-agent governance workflows."},
        {"name": "Modules", "description": "Module lifecycle, validation, upgrade, and deprecation workflows."},
        {"name": "Gateway and Keys", "description": "Routing, key lifecycle, OpenAI-compatible APIs, and gateway governance."},
        {"name": "Providers", "description": "Tenant, identity federation, and secret provider management workflows."},
        {"name": "Runtime Config", "description": "Runtime configuration read/validate/write governance endpoints."},
        {"name": "Cost", "description": "Cost telemetry, budgets, anomaly, and policy evaluation workflows."},
        {"name": "Route Drafts", "description": "Route draft approval, promote, and rollback workflows."},
        {"name": "Observability", "description": "Trace and log observability endpoints with schema diagnostics."},
        {"name": "Compliance", "description": "Control coverage, mappings, evidence, and retention workflows."},
        {"name": "Governance", "description": "API UI coverage gap reporting and inventory sync for backend-vs-frontend operator workflows."},
        {"name": "Platform", "description": "Operational posture banners, operator feedback persistence (`operator_feedback`), analytics, and triage."},
        {"name": "Playground", "description": "Interactive prompt execution and governed run workflows."},
        {"name": "Agentic", "description": "Readiness, certification, checkpoint, and policy automation workflows."},
        {"name": "Browser Security", "description": "GuardBridge browser extension governance: session tracking, interaction event telemetry, shadow-AI discovery, risk policies, analytics, and incident evidence export. GuardBridge is a separate extension identity compatible with Chrome, Firefox, Safari, Edge, Opera, Brave, Arc, Vivaldi, and Samsung Internet. Data minimization is enforced by design: raw IPs, raw UA strings, and raw prompt content are never stored."},
    ],
    lifespan=lifespan,
)


def _custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=app.openapi_tags,
    )

    components = openapi_schema.setdefault("components", {})
    security_schemes = components.setdefault("securitySchemes", {})
    security_schemes["BearerAuth"] = {
        "type": "http",
        "scheme": "bearer",
        "bearerFormat": "JWT",
        "description": "Signed session bearer token issued by /auth/sessions.",
    }
    security_schemes["ActorIdHeader"] = {
        "type": "apiKey",
        "in": "header",
        "name": "X-Actor-Id",
        "description": "Header-based actor identity for local/dev/test compatibility only.",
    }
    security_schemes["ActorRoleHeader"] = {
        "type": "apiKey",
        "in": "header",
        "name": "X-Actor-Role",
        "description": "Header-based actor role for local/dev/test compatibility only.",
    }
    security_schemes["MfaVerifiedHeader"] = {
        "type": "apiKey",
        "in": "header",
        "name": "X-MFA-Verified",
        "description": "Optional header required by privileged endpoints that enforce MFA.",
    }

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = _custom_openapi

cors_allow_origins = _cors_allow_origins()
if cors_allow_origins:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cors_allow_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
    )

rate_limiter = SlidingWindowRateLimiter()
app.state.rate_limiter = rate_limiter


def _rate_limit_actor_identity(request: Request) -> str:
    auth_header = (request.headers.get("Authorization") or "").strip()
    if auth_header:
        scheme, _, token = auth_header.partition(" ")
        if scheme.lower() == "bearer" and token.strip():
            try:
                session_id = resolve_session_id_from_bearer_token(token.strip())
                return f"session:{session_id}"
            except Exception:
                logger.trace("rate_limiter_invalid_bearer_fallback_to_ip")

    # Keep header identity trust available in non-production while blocking it in production.
    if _runtime_environment() not in {"prod", "production"}:
        header_actor = (request.headers.get("X-Actor-Id") or "").strip()
        if header_actor:
            return header_actor

    client_ip = request.client.host if request.client and request.client.host else "unknown"
    return f"ip:{client_ip}"


@app.middleware("http")
async def ui_polling_rate_limit_middleware(request: Request, call_next):
    actor_id = _rate_limit_actor_identity(request)
    request_actor_id = actor_id
    request_user_login = None
    request_actor_role = None
    db = SessionLocal()
    try:
        request_actor_id, request_user_login, request_actor_role = resolve_request_actor_identity(request, db)
        set_request_actor(request_actor_id, request_user_login, request_actor_role)
    finally:
        db.close()

    logger.trace(
        "request_received %s",
        sanitize_fields(
            {
                "method": request.method,
                "path": request.url.path,
                "actor_id": request_actor_id,
                "user_login": request_user_login,
            }
        ),
    )
    allowed, retry_after = rate_limiter.allow(
        actor_id=actor_id,
        method=request.method,
        path=request.url.path,
    )
    if not allowed:
        logger.error(
            "rate_limit_exceeded %s",
            sanitize_fields(
                {
                    "actor_id": request_actor_id,
                    "user_login": request_user_login,
                    "path": request.url.path,
                    "retry_after_seconds": retry_after,
                }
            ),
        )
        clear_request_actor()
        clear_audit_action_context()
        return JSONResponse(
            status_code=429,
            content={
                "detail": {
                    "error_code": "RATE_LIMIT_EXCEEDED",
                    "message": "Too many requests for this endpoint. Reduce UI polling frequency.",
                    "actor_id": request_actor_id,
                    "path": request.url.path,
                    "retry_after_seconds": retry_after,
                }
            },
            headers={"Retry-After": str(retry_after)},
        )
    try:
        response = await call_next(request)
    except Exception:
        logger.error(
            "request_failed %s",
            sanitize_fields(
                {
                    "method": request.method,
                    "path": request.url.path,
                    "actor_id": get_request_actor_id() or request_actor_id,
                    "user_login": get_request_user_login() or request_user_login,
                }
            ),
        )
        clear_request_actor()
        clear_audit_action_context()
        raise
    logger.info(
        "request_completed %s",
        sanitize_fields(
            {
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "actor_id": get_request_actor_id() or request_actor_id,
                "user_login": get_request_user_login() or request_user_login,
            }
        ),
    )
    clear_request_actor()
    clear_audit_action_context()
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    # Allow mic/camera on same origin for Playground voice/video capture; geolocation stays off.
    response.headers.setdefault("Permissions-Policy", "camera=(self), microphone=(self), geolocation=()")
    response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
    return response


app.include_router(benchmark_scan.router, tags=["Benchmark and Scan"])
app.include_router(browser_security.router, tags=["Browser Security"])
app.include_router(agents.router, tags=["Agents"])
app.include_router(agent_configs.router, tags=["Agent Config"])
app.include_router(auth.router, tags=["Auth and Security"])
app.include_router(audit.router, tags=["Audit"])
app.include_router(discovery.router, tags=["Discovery"])
app.include_router(modules.router, tags=["Modules"])
app.include_router(gateway.router, tags=["Gateway and Keys"])
app.include_router(gateway_memory.router, tags=["Gateway and Keys"])
app.include_router(gateway_rag.router, tags=["Gateway and Keys"])
app.include_router(providers.router, tags=["Providers"])
app.include_router(runtime_config.router, tags=["Runtime Config"])
app.include_router(cost.router, tags=["Cost"])
app.include_router(route_drafts.router, tags=["Route Drafts"])
app.include_router(observability.router, tags=["Observability"])
app.include_router(compliance.router, tags=["Compliance"])
app.include_router(governance.router, tags=["Governance"])
app.include_router(platform.router, tags=["Platform"])
app.include_router(playground.router, tags=["Playground"])
app.include_router(orchestration.router, tags=["Flow Orchestration"])
app.include_router(agentic.router, tags=["Agentic"])


@app.get(
    "/health",
    tags=["Health"],
    summary="Service health",
    description=(
        "Returns API health status, rate-limiter runtime status, and runtime config cache posture "
        "(`status`, `ttl_seconds`, `last_refresh`, `active_backend`, `configured_backend`, `degraded`). "
        "No secrets are exposed."
    ),
    responses={200: {"description": "Service is reachable; includes dependency posture fields."}},
)
def health():
    cache_status = runtime_config_cache.runtime_status()
    return {
        "status": "ok",
        "rate_limit": rate_limiter.runtime_status(),
        "runtime_config_cache": {
            "status": cache_status["status"],
            "ttl_seconds": cache_status["ttl_seconds"],
            "last_refresh": cache_status["last_refresh"],
            "active_backend": cache_status["active_backend"],
            "configured_backend": cache_status["configured_backend"],
            "degraded": cache_status["degraded"],
        },
    }
