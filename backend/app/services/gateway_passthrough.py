from __future__ import annotations

import json
from typing import Any

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.runtime_constants import RUNTIME_CONFIG_GATEWAY_PASSTHROUGH_ALLOWED_PATHS_JSON
from app.services.gateway_inference import (
    _provider_base_url,
    _provider_env_api_key,
    inference_simulation_enabled,
    resolve_inference_credential,
)
from app.services.runtime_config import get_runtime_config


def _resolve_gateway_cursor_token(db: Session) -> str:
    from app.routers.gateway import _resolve_gateway_cursor_api_token

    return _resolve_gateway_cursor_api_token(db)

BLOCKED_HEADER_NAMES = {
    "authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-amz-security-token",
    "proxy-authorization",
}


def _load_allowed_paths(db: Session) -> list[str]:
    raw = get_runtime_config(
        db,
        RUNTIME_CONFIG_GATEWAY_PASSTHROUGH_ALLOWED_PATHS_JSON,
        '["/v1/chat/completions","/v1/embeddings","/v1/responses"]',
    )
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        parsed = ["/v1/chat/completions"]
    if not isinstance(parsed, list):
        return ["/v1/chat/completions"]
    normalized = [str(item).strip() for item in parsed if str(item).strip()]
    return normalized or ["/v1/chat/completions"]


def _normalize_path(path: str) -> str:
    value = str(path or "").strip()
    if not value.startswith("/"):
        value = f"/{value}"
    return value


def _path_allowed(db: Session, path: str) -> bool:
    normalized = _normalize_path(path)
    allowed = _load_allowed_paths(db)
    return any(normalized == item or normalized.startswith(f"{item.rstrip('/')}/") for item in allowed)


def _sanitize_client_headers(headers: dict) -> dict:
    sanitized: dict[str, str] = {}
    for key, value in (headers or {}).items():
        if str(key or "").strip().lower() in BLOCKED_HEADER_NAMES:
            continue
        sanitized[str(key)] = str(value)
    return sanitized


def _resolve_provider_credential(db: Session, provider_id: str, environment: str):
    provider_type = str(provider_id or "").strip().lower()
    if not provider_type:
        raise HTTPException(status_code=422, detail="provider_id is required")

    if inference_simulation_enabled():
        from app.services.gateway_inference import ResolvedInferenceCredential

        return ResolvedInferenceCredential(
            provider_type=provider_type,
            api_key="simulated",
            base_url=_provider_base_url(provider_type),
            upstream_model="passthrough-proxy",
            credential_source="simulation",
        )

    credential = resolve_inference_credential(
        db,
        model_name=f"{provider_type}/passthrough-proxy",
        environment=environment,
        agent_id=None,
        resolve_gateway_cursor_token=_resolve_gateway_cursor_token,
    )
    if credential is not None and str(credential.api_key or "").strip():
        return credential

    env_key = _provider_env_api_key(provider_type)
    if env_key:
        from app.services.gateway_inference import ResolvedInferenceCredential

        return ResolvedInferenceCredential(
            provider_type=provider_type,
            api_key=env_key,
            base_url=_provider_base_url(provider_type),
            upstream_model="passthrough-proxy",
            credential_source=f"env:{provider_type}",
        )

    raise HTTPException(status_code=503, detail="Provider credentials are not configured for passthrough")


def execute_passthrough(
    db: Session,
    *,
    provider_id: str,
    method: str,
    path: str,
    headers: dict,
    body: Any,
    environment: str,
) -> dict:
    normalized_path = _normalize_path(path)
    if not _path_allowed(db, normalized_path):
        raise HTTPException(status_code=403, detail="Passthrough path is not allowlisted")

    normalized_method = str(method or "POST").strip().upper()
    if normalized_method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise HTTPException(status_code=422, detail="method must be GET, POST, PUT, PATCH, or DELETE")

    credential = _resolve_provider_credential(db, provider_id, environment)
    outbound_headers = _sanitize_client_headers(headers)
    outbound_headers.setdefault("Content-Type", "application/json")

    if credential.credential_source != "simulation":
        if credential.provider_type == "anthropic":
            outbound_headers["x-api-key"] = credential.api_key
            outbound_headers["anthropic-version"] = outbound_headers.get("anthropic-version", "2023-06-01")
        else:
            outbound_headers["Authorization"] = f"Bearer {credential.api_key}"

    base_url = str(credential.base_url or _provider_base_url(credential.provider_type)).rstrip("/")
    target_url = f"{base_url}{normalized_path}"

    if credential.credential_source == "simulation":
        simulated_body = {
            "simulated": True,
            "provider_id": provider_id,
            "path": normalized_path,
            "method": normalized_method,
            "request": body,
        }
        return {
            "status_code": 200,
            "headers": {"content-type": "application/json"},
            "body": simulated_body,
        }

    try:
        response = httpx.request(
            normalized_method,
            target_url,
            headers=outbound_headers,
            json=body if body is not None and normalized_method != "GET" else None,
            timeout=30.0,
        )
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"Passthrough upstream request failed: {exc}") from exc

    response_headers = {
        key: value
        for key, value in response.headers.items()
        if key.lower() not in {"authorization", "set-cookie"}
    }
    try:
        response_body: Any = response.json()
    except ValueError:
        response_body = response.text

    return {
        "status_code": response.status_code,
        "headers": response_headers,
        "body": response_body,
    }
