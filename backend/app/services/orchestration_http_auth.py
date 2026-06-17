from __future__ import annotations

import base64
import json
from typing import Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.services.credential_resolution import load_active_binding_by_id, resolve_binding_for_runtime

SUPPORTED_AUTH_TYPES = {"none", "bearer", "basic", "api_key", "oidc_client_credentials", "workload_identity"}


def apply_http_auth_headers(
    db: Session,
    *,
    auth_type: str,
    auth_binding_id: Optional[str],
    auth_header_name: Optional[str] = None,
) -> dict[str, str]:
    normalized_type = str(auth_type or "none").strip().lower()
    if normalized_type in {"", "none"}:
        return {}
    if normalized_type not in SUPPORTED_AUTH_TYPES:
        raise HTTPException(
            status_code=422,
            detail=f"http_request auth_type must be one of: {', '.join(sorted(SUPPORTED_AUTH_TYPES - {'none'}))}",
        )

    binding_id = str(auth_binding_id or "").strip()
    if not binding_id:
        raise HTTPException(status_code=422, detail="http_request requires config.auth_binding_id when auth_type is set")

    binding = load_active_binding_by_id(db, binding_id)
    resolved = resolve_binding_for_runtime(db, binding)
    secret = str(resolved.secret_value or "").strip()
    if not secret:
        raise HTTPException(status_code=503, detail="HTTP auth binding secret is empty")

    if normalized_type == "bearer":
        return {"Authorization": f"Bearer {secret}"}

    if normalized_type == "basic":
        username = secret
        password = ""
        try:
            parsed = json.loads(secret)
            if isinstance(parsed, dict):
                username = str(parsed.get("username") or "").strip()
                password = str(parsed.get("password") or "").strip()
        except json.JSONDecodeError:
            if ":" in secret:
                username, password = secret.split(":", 1)
        if not username:
            raise HTTPException(
                status_code=422,
                detail='basic auth binding secret must be JSON {"username":"...","password":"..."} or user:pass',
            )
        encoded = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {encoded}"}

    if normalized_type == "api_key":
        header_name = str(auth_header_name or "X-API-Key").strip()
        if not header_name:
            raise HTTPException(status_code=422, detail="http_request api_key auth requires config.auth_header_name")
        return {header_name: secret}

    if normalized_type in {"oidc_client_credentials", "workload_identity"}:
        token = secret
        try:
            parsed = json.loads(secret)
            if isinstance(parsed, dict):
                token = str(
                    parsed.get("access_token")
                    or parsed.get("token")
                    or parsed.get("bearer")
                    or ""
                ).strip() or secret
        except json.JSONDecodeError:
            pass
        if not token:
            raise HTTPException(
                status_code=422,
                detail=f"{normalized_type} binding must resolve to a bearer token secret",
            )
        return {"Authorization": f"Bearer {token}"}

    return {}
