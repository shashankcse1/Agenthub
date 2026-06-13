from __future__ import annotations

import json
import os
import re
from typing import Any, Optional
from urllib.parse import urlparse

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import SecretProviderConfig, SecretProviderStoredValue
from app.runtime_constants import (
    RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_DEFAULT_SECRET_PROVIDER_ID,
    RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_DEFAULT_STORE_ID,
    RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_EMBEDDING_MODEL,
    RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_JSON,
    RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_LIVE_PROBE_ENABLED,
    RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_SEARCH_TOP_K,
)
from app.services.mcp_gateway import list_mcp_servers, list_tools as mcp_list_tools, resolve_mcp_server
from app.services.runtime_config import get_runtime_config, get_runtime_config_int
from app.services.secret_provider_values import is_db_secret_provider, mask_secret_hint, read_db_secret_provider_value

ALLOWED_VECTOR_STORE_PROVIDER_TYPES = {
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

ALLOWED_SIMILARITY_METRICS = {"cosine", "dot", "euclidean", "l2"}

VECTOR_STORE_AUTH_OPTIONAL_TYPES = {"pgvector", "mcp_bridge"}

CLOUD_SECRET_BACKEND_TYPES = {
    "vault",
    "aws-secrets-manager",
    "aws_secrets_manager",
    "azure-key-vault",
    "azure_key_vault",
}

SECRET_REF_PATTERN = re.compile(r"^[a-z0-9][a-z0-9/_-]{0,254}$")

INLINE_SECRET_FIELD_NAMES = frozenset(
    {"api_key", "api_key_secret", "password", "token", "secret", "credentials"}
)


def _is_localish_environment() -> bool:
    value = (os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "dev").strip().lower()
    return value in {"dev", "test", "local"}


def _validate_secret_ref(secret_ref: str) -> bool:
    normalized = str(secret_ref or "").strip()
    if not normalized or not SECRET_REF_PATTERN.match(normalized):
        return False
    if normalized.startswith(("providers/", "gateway/")):
        return True
    return False


def _resolve_default_secret_provider_id(db: Session) -> str:
    return get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_DEFAULT_SECRET_PROVIDER_ID, "").strip()


def _normalize_mcp_server_id(record: dict) -> str:
    metadata = record.get("metadata") if isinstance(record.get("metadata"), dict) else {}
    return str(record.get("mcp_server_id") or metadata.get("mcp_server_id") or "").strip()


def _resolve_secret_provider_id(db: Session, store: dict) -> str:
    return (
        str(store.get("secret_provider_id") or "").strip()
        or _resolve_default_secret_provider_id(db)
    )


def _secret_provider_posture(db: Session, store: dict) -> dict[str, Any]:
    provider_id = _resolve_secret_provider_id(db, store)
    secret_ref = str(store.get("api_key_secret_ref") or "").strip()
    if not provider_id:
        return {
            "secret_provider_id": None,
            "secret_backend_type": None,
            "cloud_integrated": False,
            "integration_mode": "unconfigured",
            "operator_note": "Set secret_provider_id on the store row or gateway.vector_stores.default_secret_provider_id.",
        }

    provider = db.query(SecretProviderConfig).filter_by(secret_provider_id=provider_id).first()
    if not provider:
        return {
            "secret_provider_id": provider_id,
            "secret_backend_type": None,
            "cloud_integrated": False,
            "integration_mode": "provider_missing",
            "operator_note": "Secret provider id not found. Register backend under Providers → Secrets.",
        }

    backend_type = str(provider.provider_type or "").strip().lower()
    cloud = backend_type in CLOUD_SECRET_BACKEND_TYPES
    if is_db_secret_provider(backend_type):
        mode = "platform_db"
        note = "Store API key via Providers → Store Secret Value (encrypted at rest)."
    elif backend_type == "vault":
        mode = "hashicorp_vault"
        note = f"Store secret at Vault path matching ref `{secret_ref}`; platform reads at runtime via configured address/token."
    elif backend_type in {"aws-secrets-manager", "aws_secrets_manager"}:
        mode = "aws_secrets_manager"
        note = f"Store secret in AWS Secrets Manager as `{secret_ref}`; platform reads via IAM/task role."
    elif backend_type in {"azure-key-vault", "azure_key_vault"}:
        mode = "azure_key_vault"
        note = f"Store secret in Azure Key Vault as `{secret_ref}`; platform reads via managed identity/bootstrap token."
    else:
        mode = backend_type or "unknown"
        note = "Configure secret material in the registered backend using the secret ref path."

    return {
        "secret_provider_id": provider_id,
        "secret_backend_type": backend_type,
        "cloud_integrated": cloud,
        "integration_mode": mode,
        "operator_note": note,
        "secret_ref": secret_ref or None,
    }


def _live_probe_enabled(db: Session) -> bool:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_LIVE_PROBE_ENABLED, "false")
    return str(raw).strip().lower() in {"true", "1", "yes", "on"}


def resolve_vector_store_api_key(db: Session, store: dict) -> Optional[str]:
    secret_ref = str(store.get("api_key_secret_ref") or "").strip()
    if not secret_ref:
        return None

    provider_id = _resolve_secret_provider_id(db, store)
    if not provider_id:
        return None

    provider = db.query(SecretProviderConfig).filter_by(secret_provider_id=provider_id).first()
    if not provider or str(provider.status or "").strip().lower() != "active":
        return None

    backend_type = str(provider.provider_type or "").strip().lower()
    try:
        if is_db_secret_provider(backend_type):
            return read_db_secret_provider_value(db, provider, secret_ref)
        from app.services.credential_resolution import read_secret_provider_value_at_runtime

        return read_secret_provider_value_at_runtime(db, provider_id, secret_ref)
    except HTTPException:
        return None


def _probe_mcp_bridge_live(db: Session, store: dict) -> tuple[bool, str]:
    mcp_server_id = str(store.get("mcp_server_id") or "").strip()
    if not mcp_server_id:
        return False, "mcp_server_id missing for live probe."
    try:
        server = resolve_mcp_server(db, mcp_server_id)
        tools = mcp_list_tools(db, server)
        tool_names = {str(tool.get("name") or "").strip() for tool in tools if isinstance(tool, dict)}
        expected = {"vector.search", "vector.upsert", "vector.delete"}
        missing = sorted(expected - tool_names)
        if missing:
            return False, f"MCP server reachable; missing tools: {', '.join(missing)}"
        return True, f"MCP server reachable with RAG tools ({len(tools)} listed)."
    except HTTPException as exc:
        return False, str(exc.detail)


def _probe_custom_http_live(connection_url: str) -> tuple[bool, str]:
    import httpx

    url = str(connection_url or "").strip()
    if not url:
        return False, "connection_url missing for live probe."
    try:
        resp = httpx.head(url, timeout=5.0, follow_redirects=True)
        if resp.status_code >= 400:
            return False, f"HEAD {url} returned HTTP {resp.status_code}"
        return True, f"HEAD {url} returned HTTP {resp.status_code}"
    except httpx.TimeoutException:
        return False, f"HEAD {url} timed out"
    except httpx.HTTPError as exc:
        return False, f"HEAD {url} failed: {exc}"


def _secret_status_for_store(db: Session, store: dict) -> tuple[Optional[bool], Optional[str], Optional[str]]:
    secret_ref = str(store.get("api_key_secret_ref") or "").strip()
    if not secret_ref:
        return None, None, None

    provider_id = _resolve_secret_provider_id(db, store)
    if not provider_id:
        return False, None, None

    provider = db.query(SecretProviderConfig).filter_by(secret_provider_id=provider_id).first()
    if not provider or str(provider.status or "").strip().lower() != "active":
        return False, None, str(provider.provider_type if provider else "")

    backend_type = str(provider.provider_type or "").strip().lower()

    if is_db_secret_provider(backend_type):
        row = (
            db.query(SecretProviderStoredValue)
            .filter_by(secret_provider_id=provider_id, secret_ref=secret_ref)
            .first()
        )
        if not row or not str(row.value_encrypted or "").strip():
            return False, None, backend_type
        try:
            plaintext = read_db_secret_provider_value(db, provider, secret_ref)
            return True, mask_secret_hint(plaintext), backend_type
        except HTTPException:
            return False, None, backend_type

    try:
        from app.services.credential_resolution import read_secret_provider_value_at_runtime

        plaintext = read_secret_provider_value_at_runtime(db, provider_id, secret_ref)
        return bool(str(plaintext or "").strip()), mask_secret_hint(plaintext), backend_type
    except HTTPException:
        return False, None, backend_type


def _mcp_bridge_posture(db: Session, store: dict) -> dict[str, Any]:
    mcp_server_id = store.get("mcp_server_id") or ""
    if not mcp_server_id:
        return {
            "mcp_server_id": None,
            "mcp_server_configured": False,
            "mcp_server_enabled": False,
            "message": "mcp_server_id is required for mcp_bridge vector stores.",
        }
    servers = {row["server_id"]: row for row in list_mcp_servers(db)}
    server = servers.get(mcp_server_id)
    if not server:
        return {
            "mcp_server_id": mcp_server_id,
            "mcp_server_configured": False,
            "mcp_server_enabled": False,
            "message": f"MCP server `{mcp_server_id}` not found in gateway.mcp.servers_json.",
        }
    return {
        "mcp_server_id": mcp_server_id,
        "mcp_server_configured": True,
        "mcp_server_enabled": bool(server.get("enabled")),
        "mcp_base_url": server.get("base_url"),
        "allowed_tools": server.get("allowed_tools") or [],
        "message": "MCP bridge store linked to gateway MCP registry.",
    }


def _validate_store_record(record: dict, idx: int) -> tuple[bool, str]:
    store_id = str(record.get("store_id") or "").strip()
    provider_type = str(record.get("provider_type") or "").strip().lower()
    connection_url = str(record.get("connection_url") or "").strip()
    mcp_server_id = _normalize_mcp_server_id(record)

    for forbidden in INLINE_SECRET_FIELD_NAMES:
        if record.get(forbidden):
            return (
                False,
                f"gateway.vector_stores_json[{idx}] inline {forbidden} is not allowed; use api_key_secret_ref",
            )

    if not store_id:
        return False, f"gateway.vector_stores_json[{idx}] missing store_id"
    if provider_type not in ALLOWED_VECTOR_STORE_PROVIDER_TYPES:
        return False, (
            f"gateway.vector_stores_json[{idx}] unsupported provider_type "
            f"(allowed: {', '.join(sorted(ALLOWED_VECTOR_STORE_PROVIDER_TYPES))})"
        )

    if provider_type == "mcp_bridge":
        if not mcp_server_id:
            return False, f"gateway.vector_stores_json[{idx}] mcp_server_id is required for mcp_bridge"
    elif not connection_url:
        return False, f"gateway.vector_stores_json[{idx}] missing connection_url"

    if connection_url and not _is_localish_environment():
        parsed = urlparse(connection_url)
        if parsed.scheme not in {"https", "postgres", "postgresql"} or not parsed.netloc:
            if parsed.scheme not in {"https", "postgres", "postgresql"}:
                return False, f"gateway.vector_stores_json[{idx}] connection_url must use https outside local/test/dev"

    enabled = record.get("enabled", True)
    if not isinstance(enabled, bool):
        return False, f"gateway.vector_stores_json[{idx}] enabled must be boolean"

    collection_name = str(record.get("collection_name") or record.get("index_name") or "").strip()
    if not collection_name:
        return False, f"gateway.vector_stores_json[{idx}] collection_name or index_name is required"

    dimensions = record.get("embedding_dimensions", 1536)
    if not isinstance(dimensions, int) or dimensions < 1 or dimensions > 8192:
        return False, f"gateway.vector_stores_json[{idx}] embedding_dimensions must be 1-8192"

    metric = str(record.get("similarity_metric") or "cosine").strip().lower()
    if metric not in ALLOWED_SIMILARITY_METRICS:
        return False, f"gateway.vector_stores_json[{idx}] invalid similarity_metric"

    secret_ref = str(record.get("api_key_secret_ref") or "").strip()
    secret_provider_id = str(record.get("secret_provider_id") or "").strip()

    if secret_ref and not _validate_secret_ref(secret_ref):
        return (
            False,
            f"gateway.vector_stores_json[{idx}] api_key_secret_ref must be a providers/ or gateway/ path",
        )

    if enabled and provider_type not in VECTOR_STORE_AUTH_OPTIONAL_TYPES:
        if not secret_ref:
            return (
                False,
                f"gateway.vector_stores_json[{idx}] api_key_secret_ref is required for enabled {provider_type} stores",
            )
        if not secret_provider_id:
            return (
                False,
                f"gateway.vector_stores_json[{idx}] secret_provider_id is required when api_key_secret_ref is set",
            )

    return True, ""


def validate_vector_stores_json(raw: str) -> Optional[str]:
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return "gateway.vector_stores_json must be valid JSON"

    if not isinstance(parsed, list):
        return "gateway.vector_stores_json must be a JSON array"

    seen: set[str] = set()
    for idx, item in enumerate(parsed):
        if not isinstance(item, dict):
            return f"gateway.vector_stores_json[{idx}] must be a JSON object"
        valid, error = _validate_store_record(item, idx)
        if not valid:
            return error
        store_id = str(item.get("store_id") or "").strip()
        if store_id in seen:
            return f"gateway.vector_stores_json duplicate store_id: {store_id}"
        seen.add(store_id)

    return None


def parse_vector_stores_json(raw: str) -> list[dict]:
    try:
        parsed = json.loads(raw or "[]")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="Invalid gateway.vector_stores_json runtime config") from exc
    if not isinstance(parsed, list):
        raise HTTPException(status_code=500, detail="gateway.vector_stores_json must be a JSON array")
    return [item for item in parsed if isinstance(item, dict)]


def _serialize_store_item(item: dict) -> dict:
    metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
    mcp_server_id = _normalize_mcp_server_id(item) or None
    return {
        "store_id": str(item.get("store_id") or "").strip(),
        "provider_type": str(item.get("provider_type") or "").strip().lower(),
        "enabled": bool(item.get("enabled", True)),
        "connection_url": str(item.get("connection_url") or "").strip(),
        "collection_name": str(item.get("collection_name") or item.get("index_name") or "").strip(),
        "embedding_dimensions": int(item.get("embedding_dimensions") or 1536),
        "similarity_metric": str(item.get("similarity_metric") or "cosine").strip().lower(),
        "secret_provider_id": str(item.get("secret_provider_id") or "").strip() or None,
        "api_key_secret_ref": str(item.get("api_key_secret_ref") or "").strip() or None,
        "mcp_server_id": mcp_server_id,
        "metadata": metadata,
    }


def list_vector_stores(db: Session) -> list[dict]:
    raw = get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_JSON, "[]")
    stores = parse_vector_stores_json(raw)
    return [_serialize_store_item(item) for item in stores]


def get_vector_store_by_id(db: Session, store_id: str) -> dict:
    normalized = str(store_id or "").strip()
    for store in list_vector_stores(db):
        if store["store_id"] == normalized:
            return store
    raise HTTPException(status_code=404, detail="Vector store not found")


def vector_store_health_check(db: Session, store_id: str) -> dict:
    store = get_vector_store_by_id(db, store_id)
    secret_ref = store.get("api_key_secret_ref")
    secret_configured, secret_masked_hint, secret_backend_type = _secret_status_for_store(db, store)
    secret_integration = _secret_provider_posture(db, store)

    base = {
        "api_key_secret_ref": secret_ref,
        "secret_configured": secret_configured,
        "secret_masked_hint": secret_masked_hint,
        "secret_backend_type": secret_backend_type,
        "secret_integration_mode": secret_integration.get("integration_mode"),
        "cloud_integrated": secret_integration.get("cloud_integrated"),
    }

    if not store.get("enabled"):
        return {
            "store_id": store["store_id"],
            "status": "disabled",
            "reachable": False,
            "message": "Store is disabled in configuration.",
            **base,
        }

    if store["provider_type"] == "mcp_bridge":
        mcp = _mcp_bridge_posture(db, store)
        ok = mcp.get("mcp_server_configured") and mcp.get("mcp_server_enabled")
        if secret_configured is False and secret_ref:
            ok = False
        message = mcp.get("message") or "MCP bridge posture unknown."
        if secret_configured is True:
            message = f"{message} Secret ref configured ({secret_backend_type}: {secret_masked_hint or '***'})."
        elif secret_ref and secret_configured is False:
            message = f"{message} Secret ref not readable from configured backend."
        live_probed = False
        live_reachable: Optional[bool] = None
        if _live_probe_enabled(db):
            live_probed = True
            live_reachable, live_message = _probe_mcp_bridge_live(db, store)
            message = f"{message} Live probe: {live_message}"
            if live_reachable is False:
                ok = False
        return {
            "store_id": store["store_id"],
            "provider_type": "mcp_bridge",
            "status": "configured" if ok else "misconfigured",
            "reachable": bool(ok),
            "message": message,
            "mcp_server_id": mcp.get("mcp_server_id"),
            "mcp_server_configured": mcp.get("mcp_server_configured"),
            "live_probed": live_probed,
            "live_reachable": live_reachable,
            **base,
        }

    connection_url = str(store.get("connection_url") or "").strip()
    if not connection_url:
        return {
            "store_id": store["store_id"],
            "status": "misconfigured",
            "reachable": False,
            "message": "connection_url is required for health checks.",
            **base,
        }

    live_probed = False
    live_reachable: Optional[bool] = None
    live_message = ""
    if _live_probe_enabled(db) and store["provider_type"] == "custom_http":
        live_probed = True
        live_reachable, live_message = _probe_custom_http_live(connection_url)

    if store["provider_type"] not in VECTOR_STORE_AUTH_OPTIONAL_TYPES:
        if secret_configured is False:
            cloud_hint = "cloud" if secret_integration.get("cloud_integrated") else "platform"
            message = (
                f"api_key_secret_ref is set but secret is not readable from {cloud_hint} backend "
                f"({secret_backend_type or 'unknown'})."
            )
            if live_probed:
                message = f"{message} Live probe: {live_message}"
            return {
                "store_id": store["store_id"],
                "provider_type": store["provider_type"],
                "status": "misconfigured",
                "reachable": False,
                "message": message,
                "connection_host": urlparse(connection_url).netloc or connection_url,
                "live_probed": live_probed,
                "live_reachable": live_reachable,
                **base,
            }

    message = (
        "Configuration validated. Live vector connectivity probes run at integration time; "
        "use MCP bridge for tool-mediated search."
    )
    if secret_configured is True:
        backend_label = secret_backend_type or "secret backend"
        message = f"{message} Secret configured via {backend_label} (masked: {secret_masked_hint or '***'})."
    elif secret_integration.get("cloud_integrated"):
        message = (
            f"{message} Cloud backend ({secret_backend_type}) registered; ensure secret exists at `{secret_ref}`."
        )

    if live_probed:
        message = f"{message} Live probe: {live_message}"
        if live_reachable is False:
            return {
                "store_id": store["store_id"],
                "provider_type": store["provider_type"],
                "status": "misconfigured",
                "reachable": False,
                "message": message,
                "connection_host": urlparse(connection_url).netloc or connection_url,
                "live_probed": live_probed,
                "live_reachable": live_reachable,
                **base,
            }

    return {
        "store_id": store["store_id"],
        "provider_type": store["provider_type"],
        "status": "configured",
        "reachable": True,
        "message": message,
        "connection_host": urlparse(connection_url).netloc or connection_url,
        "live_probed": live_probed,
        "live_reachable": live_reachable,
        **base,
    }


def build_vector_store_context(db: Session, store_id: str) -> dict:
    store = get_vector_store_by_id(db, store_id)
    settings = vector_store_settings(db)
    health = vector_store_health_check(db, store_id)
    secret_integration = _secret_provider_posture(db, store)
    mcp_posture = _mcp_bridge_posture(db, store) if store["provider_type"] == "mcp_bridge" else None
    return {
        "store": store,
        "platform": settings,
        "health": health,
        "secret_integration": secret_integration,
        "mcp_bridge": mcp_posture,
        "supported_mcp_tools_hint": ["vector.search", "vector.upsert", "vector.delete"]
        if store["provider_type"] == "mcp_bridge"
        else [],
    }


def vector_store_settings(db: Session) -> dict:
    return {
        "default_store_id": get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_DEFAULT_STORE_ID, ""),
        "default_secret_provider_id": _resolve_default_secret_provider_id(db),
        "search_top_k": get_runtime_config_int(db, RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_SEARCH_TOP_K, 8),
        "embedding_model": get_runtime_config(db, RUNTIME_CONFIG_GATEWAY_VECTOR_STORES_EMBEDDING_MODEL, "text-embedding-3-small"),
    }
