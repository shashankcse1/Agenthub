from __future__ import annotations

from sqlalchemy.orm import Session

from app.runtime_constants import (
    RUNTIME_CONFIG_GATEWAY_CACHE_DEFAULT_MODE,
    RUNTIME_CONFIG_GATEWAY_CACHE_DEFAULT_SIMILARITY_THRESHOLD,
    RUNTIME_CONFIG_GATEWAY_CACHE_DEFAULT_TTL_SECONDS,
    RUNTIME_CONFIG_GATEWAY_CACHE_INFERENCE_SHORT_CIRCUIT_ENABLED,
    RUNTIME_CONFIG_GATEWAY_MEMORY_CONTENT_MAX_BYTES,
    RUNTIME_CONFIG_GATEWAY_MEMORY_LONG_TERM_ENABLED,
    RUNTIME_CONFIG_GATEWAY_MEMORY_MAX_RECORDS_PER_SCOPE,
    RUNTIME_CONFIG_GATEWAY_MEMORY_PII_CLASSIFICATION_ENABLED,
    RUNTIME_CONFIG_GATEWAY_MEMORY_SESSION_CAPTURE_ENABLED,
    RUNTIME_CONFIG_GATEWAY_MEMORY_SHORT_TERM_TTL_SECONDS,
    RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_DEFAULT_STORE_ID,
    RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_EMBEDDING_MODEL,
    RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_DEFAULT_SECRET_PROVIDER_ID,
    RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_JSON,
    RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_LIVE_PROBE_ENABLED,
    RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_SEARCH_TOP_K,
    RUNTIME_CONFIG_GATEWAY_NOTIFICATION_CHANNELS_JSON,
)
from app.services.gateway_vector_stores import list_vector_stores, vector_store_settings
from app.services.gateway_notification_channels import list_notification_channels
from app.services.runtime_config import get_runtime_config, get_runtime_config_int


def _parse_bool(raw: str, default: bool = True) -> bool:
    value = (raw or "").strip().lower()
    if value in {"true", "1", "yes", "on"}:
        return True
    if value in {"false", "0", "no", "off"}:
        return False
    return default


def build_gateway_context_config(db: Session) -> dict:
    memory_ttl = get_runtime_config_int(db, RUNTIME_CONFIG_GATEWAY_MEMORY_SHORT_TERM_TTL_SECONDS, 3600)
    max_records = get_runtime_config_int(db, RUNTIME_CONFIG_GATEWAY_MEMORY_MAX_RECORDS_PER_SCOPE, 200)
    content_max = get_runtime_config_int(db, RUNTIME_CONFIG_GATEWAY_MEMORY_CONTENT_MAX_BYTES, 16384)
    long_term_enabled = _parse_bool(get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_MEMORY_LONG_TERM_ENABLED, "true"), True)
    session_capture_enabled = _parse_bool(
        get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_MEMORY_SESSION_CAPTURE_ENABLED, "false"),
        False,
    )
    pii_classification_enabled = _parse_bool(
        get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_MEMORY_PII_CLASSIFICATION_ENABLED, "false"),
        False,
    )
    live_probe_enabled = _parse_bool(
        get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_LIVE_PROBE_ENABLED, "false"),
        False,
    )

    cache_mode = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_CACHE_DEFAULT_MODE, "exact").strip().lower()
    if cache_mode not in {"exact", "semantic"}:
        cache_mode = "exact"
    cache_threshold_raw = get_runtime_config(
        db, RUNTIME_CONFIG_GATEWAY_CACHE_DEFAULT_SIMILARITY_THRESHOLD, "0.9"
    )
    try:
        cache_threshold = float(cache_threshold_raw)
    except ValueError:
        cache_threshold = 0.9
    cache_threshold = max(0.0, min(1.0, cache_threshold))
    cache_ttl = get_runtime_config_int(db, RUNTIME_CONFIG_GATEWAY_CACHE_DEFAULT_TTL_SECONDS, 300)
    short_circuit_enabled = _parse_bool(
        get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_CACHE_INFERENCE_SHORT_CIRCUIT_ENABLED, "false"),
        False,
    )

    vector_settings = vector_store_settings(db)
    stores = list_vector_stores(db)
    notification_channels = list_notification_channels(db)

    runtime_keys = {
        RUNTIME_CONFIG_GATEWAY_MEMORY_SHORT_TERM_TTL_SECONDS: str(memory_ttl),
        RUNTIME_CONFIG_GATEWAY_MEMORY_MAX_RECORDS_PER_SCOPE: str(max_records),
        RUNTIME_CONFIG_GATEWAY_MEMORY_LONG_TERM_ENABLED: "true" if long_term_enabled else "false",
        RUNTIME_CONFIG_GATEWAY_MEMORY_CONTENT_MAX_BYTES: str(content_max),
        RUNTIME_CONFIG_GATEWAY_MEMORY_SESSION_CAPTURE_ENABLED: "true" if session_capture_enabled else "false",
        RUNTIME_CONFIG_GATEWAY_MEMORY_PII_CLASSIFICATION_ENABLED: "true" if pii_classification_enabled else "false",
        RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_LIVE_PROBE_ENABLED: "true" if live_probe_enabled else "false",
        RUNTIME_CONFIG_GATEWAY_CACHE_DEFAULT_MODE: cache_mode,
        RUNTIME_CONFIG_GATEWAY_CACHE_DEFAULT_SIMILARITY_THRESHOLD: str(cache_threshold),
        RUNTIME_CONFIG_GATEWAY_CACHE_DEFAULT_TTL_SECONDS: str(cache_ttl),
        RUNTIME_CONFIG_GATEWAY_CACHE_INFERENCE_SHORT_CIRCUIT_ENABLED: "true" if short_circuit_enabled else "false",
        RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_JSON: get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_JSON, "[]"),
        RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_DEFAULT_STORE_ID: vector_settings["default_store_id"],
        RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_DEFAULT_SECRET_PROVIDER_ID: vector_settings["default_secret_provider_id"],
        RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_SEARCH_TOP_K: str(vector_settings["search_top_k"]),
        RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_EMBEDDING_MODEL: vector_settings["embedding_model"],
        RUNTIME_CONFIG_GATEWAY_NOTIFICATION_CHANNELS_JSON: get_runtime_config(
            db, RUNTIME_CONFIG_GATEWAY_NOTIFICATION_CHANNELS_JSON, "[]"
        ),
    }

    return {
        "memory": {
            "short_term_ttl_seconds": memory_ttl,
            "max_records_per_scope": max_records,
            "long_term_enabled": long_term_enabled,
            "content_max_bytes": content_max,
            "session_capture_enabled": session_capture_enabled,
            "pii_classification_enabled": pii_classification_enabled,
        },
        "semantic_cache": {
            "default_mode": cache_mode,
            "default_similarity_threshold": cache_threshold,
            "default_ttl_seconds": cache_ttl,
            "inference_short_circuit_enabled": short_circuit_enabled,
            "note": (
                "When inference short-circuit is enabled, matching requests return stored encrypted responses "
                "without provider calls; otherwise decisions are audit telemetry only."
            ),
        },
        "vector_stores": {
            **vector_settings,
            "live_probe_enabled": live_probe_enabled,
            "stores": stores,
            "supported_provider_types": sorted(
                {
                    "pgvector",
                    "qdrant",
                    "pinecone",
                    "mongodb_atlas",
                    "weaviate",
                    "chroma",
                    "redis",
                    "custom_http",
                    "mcp_bridge",
                }
            ),
        },
        "notification_channels": {
            "channels": notification_channels,
            "supported_provider_types": sorted({"sendgrid", "twilio", "smtp_webhook", "generic_http"}),
            "runtime_config_key": RUNTIME_CONFIG_GATEWAY_NOTIFICATION_CHANNELS_JSON,
            "note": (
                "Credential bindings only — no inline API keys. Flow Orchestration email_send/sms_send nodes "
                "reference channel_id; Phase 1 executor simulates delivery."
            ),
        },
        "runtime_config_keys": runtime_keys,
    }
