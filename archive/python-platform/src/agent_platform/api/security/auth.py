from dataclasses import dataclass
import hmac
import os
from typing import Dict

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import (
    HTTPAuthorizationCredentials,
    HTTPBasic,
    HTTPBasicCredentials,
    HTTPBearer,
)

basic_security = HTTPBasic(auto_error=False)
bearer_security = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Principal:
    username: str
    role: str


ALLOWED_POLICY_ROLES = {"Platform Admin", "Security Approver"}
ALLOWED_EVIDENCE_ROLES = {"Platform Admin", "Security Approver", "Auditor"}


def _runtime_environment() -> str:
    return os.getenv("APP_ENV", "dev").lower()


def _configured_basic_users() -> Dict[str, Dict[str, str]]:
    users: Dict[str, Dict[str, str]] = {}
    mapping = {
        "platform-admin": ("BASIC_AUTH_PLATFORM_ADMIN_PASSWORD", "Platform Admin"),
        "security-approver": ("BASIC_AUTH_SECURITY_APPROVER_PASSWORD", "Security Approver"),
        "auditor": ("BASIC_AUTH_AUDITOR_PASSWORD", "Auditor"),
    }
    for username, (env_name, role) in mapping.items():
        password = os.getenv(env_name, "")
        if password:
            users[username] = {"password": password, "role": role}
    return users


def _is_basic_auth_allowed() -> bool:
    app_env = _runtime_environment()
    default_value = "true" if app_env == "dev" else "false"
    return os.getenv("ALLOW_BASIC_AUTH", default_value).lower() == "true"


def validate_auth_runtime_guardrails() -> None:
    app_env = _runtime_environment()
    if app_env in {"dev", "test", "local"}:
        return

    allow_basic_auth = os.getenv("ALLOW_BASIC_AUTH", "false").lower() == "true"
    if allow_basic_auth:
        raise RuntimeError("ALLOW_BASIC_AUTH must remain disabled outside dev/test/local.")


def _decode_bearer_token(token: str) -> Principal:
    app_env = os.getenv("APP_ENV", "dev").lower()
    secret = os.getenv("JWT_SIGNING_SECRET", "dev-insecure-secret")
    issuer = os.getenv("JWT_ISSUER", "")
    audience = os.getenv("JWT_AUDIENCE", "")

    if app_env != "dev" and secret == "dev-insecure-secret":
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="JWT signing secret is not configured for non-dev environment",
        )

    options = {
        "verify_aud": bool(audience),
        "verify_iss": bool(issuer),
    }

    try:
        payload = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            audience=audience or None,
            issuer=issuer or None,
            options=options,
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc

    username = str(payload.get("sub") or "")
    role = str(payload.get("role") or "")
    if not username or not role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token missing required claims",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return Principal(username=username, role=role)


def require_authenticated_principal(
    basic_credentials: HTTPBasicCredentials = Depends(basic_security),
    bearer_credentials: HTTPAuthorizationCredentials = Depends(bearer_security),
) -> Principal:
    if bearer_credentials is not None:
        return _decode_bearer_token(bearer_credentials.credentials)

    if basic_credentials is not None:
        if not _is_basic_auth_allowed():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Basic authentication is disabled",
            )

        users = _configured_basic_users()
        if not users:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Basic authentication is enabled but credentials are not configured",
            )

        user = users.get(basic_credentials.username)
        if not user or not hmac.compare_digest(basic_credentials.password, user["password"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Basic"},
            )
        return Principal(username=basic_credentials.username, role=user["role"])

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer, Basic"},
    )


def require_policy_role(principal: Principal = Depends(require_authenticated_principal)) -> Principal:
    if principal.role not in ALLOWED_POLICY_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Role is not authorized for policy preview",
        )
    return principal


def require_evidence_role(principal: Principal = Depends(require_authenticated_principal)) -> Principal:
    if principal.role not in ALLOWED_EVIDENCE_ROLES:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Role is not authorized for evidence access",
        )
    return principal
