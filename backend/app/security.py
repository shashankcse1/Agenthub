from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import string
import base64
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import DirectoryUser, SessionRecord, VirtualKey
from app.request_context import set_request_actor
from app.policy_constants import (
    DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT,
    ROLE_AGENT_OWNER,
    ROLE_MASTER_ADMIN,
    ROLE_PLATFORM_ADMIN,
    ROLE_SUPER_ADMIN,
    SUPPORTED_ACTOR_ROLES,
)
from app.services.policy_config import get_auth_policy

logger = get_logger(__name__)
_SESSION_TOKEN_SECRET = (os.getenv("SESSION_TOKEN_SECRET") or "dev-session-secret-change-me").encode("utf-8")
_SESSION_TOKEN_SIGNING_KEYS_RAW = (os.getenv("SESSION_TOKEN_SIGNING_KEYS") or "").strip()
_SESSION_TOKEN_SIGNING_LAST_ROTATED_AT_RAW = (os.getenv("SESSION_TOKEN_SIGNING_LAST_ROTATED_AT") or "").strip()
_SESSION_TOKEN_ROTATION_MAX_DAYS_RAW = (os.getenv("SESSION_TOKEN_ROTATION_MAX_DAYS") or "30").strip()
_MFA_ENFORCEMENT_OPTIONAL_RAW = (os.getenv("MFA_ENFORCEMENT_OPTIONAL") or "false").strip().lower() in {
    "1",
    "true",
    "yes",
}

_RUNTIME_ENVIRONMENT = (os.getenv("APP_ENV") or os.getenv("ENVIRONMENT") or "dev").strip().lower()
_MFA_ENFORCEMENT_OPTIONAL = _MFA_ENFORCEMENT_OPTIONAL_RAW and _RUNTIME_ENVIRONMENT in {"dev", "test", "local"}
_ALLOW_HEADER_ACTOR_AUTH_RAW = (os.getenv("ALLOW_HEADER_ACTOR_AUTH") or "").strip().lower()
# Enterprise default: header-asserted identity only in local/dev/test.
# Staging/prod require session tokens unless explicitly opted in (staging only).
if _ALLOW_HEADER_ACTOR_AUTH_RAW:
    _ALLOW_HEADER_ACTOR_AUTH = _ALLOW_HEADER_ACTOR_AUTH_RAW in {"1", "true", "yes"}
else:
    _ALLOW_HEADER_ACTOR_AUTH = _RUNTIME_ENVIRONMENT in {"dev", "test", "local"}

# Never permit header-asserted identities in production — even with explicit env override.
if _RUNTIME_ENVIRONMENT in {"prod", "production"}:
    _ALLOW_HEADER_ACTOR_AUTH = False

_PASSWORD_HASH_VERSION = "v1"
_PASSWORD_PBKDF2_ITERATIONS = 600000
_PASSWORD_PBKDF2_DKLEN = 32


def _password_hash_parts(password_hash: str) -> tuple[str, int, bytes, bytes]:
    parts = password_hash.split("$")
    if len(parts) != 5 or parts[0] != "pbkdf2_sha256":
        raise ValueError("Unsupported password hash format")
    if parts[1] != _PASSWORD_HASH_VERSION:
        raise ValueError("Unsupported password hash version")

    iterations = int(parts[2])
    salt = base64.urlsafe_b64decode(parts[3].encode("ascii"))
    digest = base64.urlsafe_b64decode(parts[4].encode("ascii"))
    return parts[1], iterations, salt, digest


def hash_user_password(password: str) -> str:
    normalized = password or ""
    if len(normalized) < 12:
        raise HTTPException(status_code=400, detail="password must be at least 12 characters")
    if len(normalized) > 256:
        raise HTTPException(status_code=400, detail="password is too long")

    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        normalized.encode("utf-8"),
        salt,
        _PASSWORD_PBKDF2_ITERATIONS,
        dklen=_PASSWORD_PBKDF2_DKLEN,
    )
    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii")
    digest_b64 = base64.urlsafe_b64encode(digest).decode("ascii")
    return f"pbkdf2_sha256${_PASSWORD_HASH_VERSION}${_PASSWORD_PBKDF2_ITERATIONS}${salt_b64}${digest_b64}"


def verify_user_password(password: str, password_hash: Optional[str]) -> bool:
    if not password_hash:
        return False
    try:
        _, iterations, salt, expected = _password_hash_parts(password_hash)
    except Exception:
        return False

    candidate = hashlib.pbkdf2_hmac(
        "sha256",
        (password or "").encode("utf-8"),
        salt,
        iterations,
        dklen=len(expected),
    )
    return hmac.compare_digest(candidate, expected)


def _parse_session_signing_keys(raw: str) -> list[tuple[str, bytes]]:
    if not raw:
        return []

    parsed: list[tuple[str, bytes]] = []
    seen_kids: set[str] = set()
    for item in raw.split(","):
        token = item.strip()
        if not token:
            continue
        kid, sep, secret = token.partition(":")
        kid = kid.strip()
        secret = secret.strip()
        if not sep or not kid or not secret:
            raise RuntimeError("SESSION_TOKEN_SIGNING_KEYS must use 'kid:secret' comma-separated format.")
        if kid in seen_kids:
            raise RuntimeError("SESSION_TOKEN_SIGNING_KEYS contains duplicate key id values.")
        seen_kids.add(kid)
        parsed.append((kid, secret.encode("utf-8")))
    return parsed


_SESSION_TOKEN_SIGNING_KEYS = _parse_session_signing_keys(_SESSION_TOKEN_SIGNING_KEYS_RAW)
if _SESSION_TOKEN_SIGNING_KEYS:
    _PRIMARY_SESSION_TOKEN_KEY_ID = _SESSION_TOKEN_SIGNING_KEYS[0][0]
else:
    _PRIMARY_SESSION_TOKEN_KEY_ID = "legacy"

try:
    _SESSION_TOKEN_ROTATION_MAX_DAYS = int(_SESSION_TOKEN_ROTATION_MAX_DAYS_RAW)
except ValueError as exc:
    raise RuntimeError("SESSION_TOKEN_ROTATION_MAX_DAYS must be an integer value.") from exc


def _parse_rotation_timestamp(value: str) -> Optional[datetime]:
    if not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise RuntimeError("SESSION_TOKEN_SIGNING_LAST_ROTATED_AT must be ISO-8601 timestamp.") from exc
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(tz=None).replace(tzinfo=None)
    return parsed


_SESSION_TOKEN_SIGNING_LAST_ROTATED_AT = _parse_rotation_timestamp(_SESSION_TOKEN_SIGNING_LAST_ROTATED_AT_RAW)


def _session_signing_secret_candidates() -> list[bytes]:
    candidates = [secret for _, secret in _SESSION_TOKEN_SIGNING_KEYS]
    if _SESSION_TOKEN_SECRET not in candidates:
        candidates.append(_SESSION_TOKEN_SECRET)
    return candidates


def _session_signing_secret_for_kid(kid: str) -> Optional[bytes]:
    for configured_kid, secret in _SESSION_TOKEN_SIGNING_KEYS:
        if configured_kid == kid:
            return secret
    if kid == "legacy":
        return _SESSION_TOKEN_SECRET
    return None


def validate_session_secret_configuration() -> None:
    in_non_dev = _RUNTIME_ENVIRONMENT not in {"dev", "test", "local"}
    if not in_non_dev:
        return

    if _SESSION_TOKEN_SIGNING_KEYS:
        for _, secret in _SESSION_TOKEN_SIGNING_KEYS:
            if secret == b"dev-session-secret-change-me":
                raise RuntimeError(
                    "SESSION_TOKEN_SIGNING_KEYS must not include development default secret outside dev/test/local."
                )
            if len(secret) < 32:
                raise RuntimeError(
                    "Each SESSION_TOKEN_SIGNING_KEYS secret must be at least 32 characters outside dev/test/local."
                )
    else:
        if _SESSION_TOKEN_SECRET == b"dev-session-secret-change-me":
            raise RuntimeError("SESSION_TOKEN_SECRET must be set to a non-default value outside dev/test/local.")
        if len(_SESSION_TOKEN_SECRET) < 32:
            raise RuntimeError("SESSION_TOKEN_SECRET must be at least 32 characters outside dev/test/local.")


def validate_runtime_auth_guardrails() -> None:
    if _RUNTIME_ENVIRONMENT in {"prod", "production"}:
        if _ALLOW_HEADER_ACTOR_AUTH_RAW in {"1", "true", "yes"}:
            raise RuntimeError("ALLOW_HEADER_ACTOR_AUTH must remain disabled in production.")
        if _MFA_ENFORCEMENT_OPTIONAL_RAW:
            raise RuntimeError("MFA_ENFORCEMENT_OPTIONAL cannot be enabled outside dev/test/local.")
        return

    # Staging-like environments: reject accidental header-auth enablement unless
    # operators also set ALLOW_HEADER_ACTOR_AUTH_STAGING_OVERRIDE=true (migration bridge).
    if _RUNTIME_ENVIRONMENT not in {"dev", "test", "local"}:
        staging_override = (os.getenv("ALLOW_HEADER_ACTOR_AUTH_STAGING_OVERRIDE") or "").strip().lower() in {
            "1",
            "true",
            "yes",
        }
        if _ALLOW_HEADER_ACTOR_AUTH_RAW in {"1", "true", "yes"} and not staging_override:
            raise RuntimeError(
                "ALLOW_HEADER_ACTOR_AUTH is not permitted outside local/dev/test without "
                "ALLOW_HEADER_ACTOR_AUTH_STAGING_OVERRIDE=true."
            )
        if _MFA_ENFORCEMENT_OPTIONAL_RAW:
            raise RuntimeError("MFA_ENFORCEMENT_OPTIONAL cannot be enabled outside dev/test/local.")


def insecure_configuration_warnings() -> list[str]:
    warnings: list[str] = []
    in_non_dev = _RUNTIME_ENVIRONMENT not in {"dev", "test", "local"}

    if _ALLOW_HEADER_ACTOR_AUTH:
        warnings.append(
            "ALLOW_HEADER_ACTOR_AUTH is enabled; header-asserted identity is insecure and should be limited to local/test usage."
        )

    if _MFA_ENFORCEMENT_OPTIONAL:
        warnings.append(
            "MFA_ENFORCEMENT_OPTIONAL is enabled; privileged operations may proceed without MFA."
        )
    elif _MFA_ENFORCEMENT_OPTIONAL_RAW and _RUNTIME_ENVIRONMENT not in {"dev", "test", "local"}:
        warnings.append(
            "MFA_ENFORCEMENT_OPTIONAL is set but ignored outside dev/test/local."
        )

    expose_token_flag = (os.getenv("EXPOSE_WORKLOAD_IDENTITY_ACCESS_TOKEN") or "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    if expose_token_flag:
        warnings.append(
            "EXPOSE_WORKLOAD_IDENTITY_ACCESS_TOKEN is enabled; workload identity exchange may expose sensitive token material."
        )

    if _SESSION_TOKEN_SECRET == b"dev-session-secret-change-me":
        warnings.append(
            "SESSION_TOKEN_SECRET is using default development value; use a strong, unique secret in managed environments."
        )
    elif len(_SESSION_TOKEN_SECRET) < 32:
        warnings.append("SESSION_TOKEN_SECRET is shorter than recommended minimum length (32 characters).")

    if _SESSION_TOKEN_SIGNING_KEYS and len(_SESSION_TOKEN_SIGNING_KEYS) < 2:
        warnings.append(
            "SESSION_TOKEN_SIGNING_KEYS is configured with a single key; configure multiple keys for rollover-ready rotation."
        )

    if in_non_dev and _SESSION_TOKEN_SIGNING_KEYS:
        if _SESSION_TOKEN_ROTATION_MAX_DAYS <= 0:
            warnings.append("SESSION_TOKEN_ROTATION_MAX_DAYS should be greater than zero.")
        elif _SESSION_TOKEN_SIGNING_LAST_ROTATED_AT is None:
            warnings.append(
                "SESSION_TOKEN_SIGNING_LAST_ROTATED_AT is not set; key rotation age monitoring is disabled."
            )
        else:
            key_age_days = (datetime.utcnow() - _SESSION_TOKEN_SIGNING_LAST_ROTATED_AT).days
            if key_age_days > _SESSION_TOKEN_ROTATION_MAX_DAYS:
                warnings.append(
                    "SESSION_TOKEN_SIGNING_KEYS rotation age exceeded configured threshold; rotate signing keys immediately."
                )

    return warnings


def session_signing_rotation_status() -> dict[str, object]:
    """Runtime posture for session signing key rotation age (RSK-004 /health re-check)."""
    in_non_dev = _RUNTIME_ENVIRONMENT not in {"dev", "test", "local"}
    key_ring_configured = bool(_SESSION_TOKEN_SIGNING_KEYS)
    last_rotated = _SESSION_TOKEN_SIGNING_LAST_ROTATED_AT
    max_days = int(_SESSION_TOKEN_ROTATION_MAX_DAYS)
    age_days: int | None = None
    exceeded = False
    monitoring_enabled = bool(in_non_dev and key_ring_configured and last_rotated is not None and max_days > 0)
    if last_rotated is not None:
        age_days = max(0, (datetime.utcnow() - last_rotated).days)
        if monitoring_enabled and age_days > max_days:
            exceeded = True
    warnings = [
        warning
        for warning in insecure_configuration_warnings()
        if "SESSION_TOKEN_SIGNING" in warning or "SESSION_TOKEN_ROTATION" in warning
    ]
    return {
        "environment": _RUNTIME_ENVIRONMENT,
        "key_ring_configured": key_ring_configured,
        "monitoring_enabled": monitoring_enabled,
        "max_age_days": max_days,
        "age_days": age_days,
        "last_rotated_at": last_rotated.isoformat() + "Z" if last_rotated is not None else None,
        "rotation_age_exceeded": exceeded,
        "warnings": warnings,
    }


def mfa_optional_posture() -> dict[str, object]:
    """RSK-002 / AR-001: expose MFA-optional flag posture on /health (no secrets)."""
    allowed_envs = {"dev", "test", "local"}
    return {
        "environment": _RUNTIME_ENVIRONMENT,
        "raw_flag_set": bool(_MFA_ENFORCEMENT_OPTIONAL_RAW),
        "effective": bool(_MFA_ENFORCEMENT_OPTIONAL),
        "allowed_environments": sorted(allowed_envs),
        "fail_closed_outside_allowed": _RUNTIME_ENVIRONMENT not in allowed_envs,
        "warnings": [
            warning for warning in insecure_configuration_warnings() if "MFA_ENFORCEMENT_OPTIONAL" in warning
        ],
    }


def token_exposure_posture() -> dict[str, object]:
    """AR-002: expose workload-identity token exposure flag posture on /health (no secrets)."""
    expose_token_flag = (os.getenv("EXPOSE_WORKLOAD_IDENTITY_ACCESS_TOKEN") or "").strip().lower() in {
        "1",
        "true",
        "yes",
    }
    allowed_envs = {"dev", "test", "local"}
    effective = expose_token_flag and _RUNTIME_ENVIRONMENT in allowed_envs
    return {
        "environment": _RUNTIME_ENVIRONMENT,
        "raw_flag_set": bool(expose_token_flag),
        "effective": bool(effective),
        "allowed_environments": sorted(allowed_envs),
        "fail_closed_outside_allowed": _RUNTIME_ENVIRONMENT not in allowed_envs,
        "warnings": [
            warning
            for warning in insecure_configuration_warnings()
            if "EXPOSE_WORKLOAD_IDENTITY_ACCESS_TOKEN" in warning
        ],
    }


def transport_posture() -> dict[str, object]:
    """Residual #3: HTTPS/HSTS app-side posture for /health (ingress still operator-owned)."""
    expect_https = _RUNTIME_ENVIRONMENT not in {"dev", "test", "local"}
    expect_https_env = (os.getenv("EXPECT_HTTPS") or "").strip().lower() in {"1", "true", "yes"}
    if expect_https_env:
        expect_https = True
    return {
        "environment": _RUNTIME_ENVIRONMENT,
        "expect_https": bool(expect_https),
        "hsts_header_policy": "max-age=63072000; includeSubDomains; preload",
        "hsts_configured": True,
        "notes": (
            "App middleware always sets Strict-Transport-Security. "
            "Ingress/load-balancer TLS termination must still be validated in staging/prod."
        ),
    }


@dataclass
class ActorContext:
    actor_id: str
    actor_role: str
    user_login: Optional[str]
    approver_id: Optional[str]
    approver_role: Optional[str]
    mfa_verified: bool


def resolve_user_login_for_actor(db: Session, actor_id: str) -> Optional[str]:
    normalized_actor = (actor_id or "").strip()
    if not normalized_actor:
        return None
    if normalized_actor.startswith("ip:") or normalized_actor.startswith("session:"):
        return None
    if normalized_actor in {"system-user", "unknown"}:
        return None

    directory_user = db.query(DirectoryUser).filter_by(user_id=normalized_actor).first()
    if directory_user:
        email = (directory_user.email or "").strip()
        if email:
            return email
        display_name = (directory_user.display_name or "").strip()
        if display_name:
            return display_name
    return normalized_actor


def resolve_actor_role_for_actor(db: Session, actor_id: str) -> str:
    normalized_actor = (actor_id or "").strip()
    if not normalized_actor:
        return "unknown"
    if normalized_actor.startswith("ip:") or normalized_actor.startswith("session:"):
        return "unknown"
    if normalized_actor in {"system-user", "unknown", "system"}:
        return "unknown"

    directory_user = db.query(DirectoryUser).filter_by(user_id=normalized_actor).first()
    if directory_user:
        directory_role = _canonicalize_role(directory_user.role_name)
        if directory_role:
            return directory_role

    session = (
        db.query(SessionRecord)
        .filter_by(actor_id=normalized_actor)
        .order_by(SessionRecord.last_activity_at.desc())
        .first()
    )
    if session:
        session_role = _canonicalize_role(session.actor_role)
        if session_role:
            return session_role

    return "unknown"


def resolve_request_actor_identity(request, db: Session) -> tuple[str, Optional[str], Optional[str]]:
    auth_header = _normalize_header_value(request.headers.get("Authorization"))
    if auth_header:
        scheme, _, token = auth_header.partition(" ")
        if scheme.lower() == "bearer" and token.strip():
            try:
                session_id = resolve_session_id_from_bearer_token(token.strip())
                session = db.query(SessionRecord).filter_by(session_id=session_id).first()
                if session:
                    user_login = resolve_user_login_for_actor(db, session.actor_id)
                    actor_role = _canonicalize_role(session.actor_role)
                    directory_user = db.query(DirectoryUser).filter_by(user_id=session.actor_id).first()
                    if directory_user and str(directory_user.role_name or "").strip():
                        directory_role = _canonicalize_role(directory_user.role_name)
                        if directory_role:
                            actor_role = directory_role
                    return session.actor_id, user_login, actor_role
            except HTTPException:
                pass

    if _ALLOW_HEADER_ACTOR_AUTH:
        header_actor = _normalize_header_value(request.headers.get("X-Actor-Id"))
        if header_actor:
            user_login = resolve_user_login_for_actor(db, header_actor)
            header_role = _canonicalize_role(request.headers.get("X-Actor-Role"))
            if not header_role:
                header_role = resolve_actor_role_for_actor(db, header_actor)
            return header_actor, user_login, header_role

    client_ip = request.client.host if request.client and request.client.host else "unknown"
    return f"ip:{client_ip}", None, None


def _normalize_header_value(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    normalized = value.strip()
    return normalized if normalized else None


def _canonicalize_role(raw_role: Optional[str]) -> Optional[str]:
    normalized = _normalize_header_value(raw_role)
    if not normalized:
        return None
    if normalized.lower() == ROLE_MASTER_ADMIN.lower():
        return ROLE_MASTER_ADMIN
    if normalized.lower() == ROLE_SUPER_ADMIN.lower():
        return ROLE_SUPER_ADMIN
    return normalized


def _session_token_signature(secret: bytes, session_id: str) -> str:
    return hmac.new(secret, session_id.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_session_bearer_token(session_id: str) -> str:
    secret = _session_signing_secret_for_kid(_PRIMARY_SESSION_TOKEN_KEY_ID) or _SESSION_TOKEN_SECRET
    return f"{_PRIMARY_SESSION_TOKEN_KEY_ID}.{session_id}.{_session_token_signature(secret, session_id)}"


def resolve_session_id_from_bearer_token(token: str) -> str:
    parts = token.split(".")
    key_id: Optional[str] = None
    session_id = ""
    provided_sig = ""

    if len(parts) == 3:
        key_id, session_id, provided_sig = parts
    elif len(parts) == 2:
        session_id, provided_sig = parts
    else:
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "AUTHN_INVALID_TOKEN",
                "message": "Session token format is invalid.",
                "remediation_hint": "Issue a new session using /auth/sessions and retry.",
            },
        )

    # Basic structural hardening prevents malformed token abuse before signature checks.
    if len(session_id) < 16 or len(provided_sig) != 64 or not all(c in string.hexdigits for c in provided_sig):
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "AUTHN_INVALID_TOKEN",
                "message": "Session token format is invalid.",
                "remediation_hint": "Issue a new session using /auth/sessions and retry.",
            },
        )

    if key_id:
        secret = _session_signing_secret_for_kid(key_id)
        if not secret:
            raise HTTPException(
                status_code=401,
                detail={
                    "error_code": "AUTHN_INVALID_TOKEN",
                    "message": "Session token signature is invalid.",
                    "remediation_hint": "Issue a new session using /auth/sessions and retry.",
                },
            )
        expected_sig = _session_token_signature(secret, session_id)
        if hmac.compare_digest(provided_sig, expected_sig):
            return session_id
    else:
        for secret in _session_signing_secret_candidates():
            expected_sig = _session_token_signature(secret, session_id)
            if hmac.compare_digest(provided_sig, expected_sig):
                return session_id

    raise HTTPException(
        status_code=401,
        detail={
            "error_code": "AUTHN_INVALID_TOKEN",
            "message": "Session token signature is invalid.",
            "remediation_hint": "Issue a new session using /auth/sessions and retry.",
        },
    )


def get_actor_context(
    x_actor_id: Optional[str] = Header(default=None),
    x_actor_role: Optional[str] = Header(default=None),
    x_approver_id: Optional[str] = Header(default=None),
    x_approver_role: Optional[str] = Header(default=None),
    x_mfa_verified: Optional[str] = Header(default=None),
    authorization: Optional[str] = Header(default=None),
    db: Session = Depends(get_db),
) -> ActorContext:
    logger.trace("auth_context_start")
    actor_id = _normalize_header_value(x_actor_id)
    actor_role = _canonicalize_role(x_actor_role)
    approver_id = _normalize_header_value(x_approver_id)
    approver_role = _canonicalize_role(x_approver_role)

    mfa_verified = (_normalize_header_value(x_mfa_verified) or "false").lower() in {
        "1",
        "true",
        "yes",
    }

    auth_header = _normalize_header_value(authorization)
    auth_policy = get_auth_policy(db)
    if not auth_header and (not actor_id or not actor_role):
        logger.error("auth_missing_identity")
        raise HTTPException(
            status_code=401,
            detail={
                "error_code": "AUTHN_REQUIRED",
                "message": "Provide Authorization bearer token or explicit actor identity headers.",
                "remediation_hint": "Use Bearer session token or provide X-Actor-Id and X-Actor-Role.",
            },
        )

    if auth_header:
        scheme, _, token = auth_header.partition(" ")
        if scheme.lower() != "bearer" or not token.strip():
            logger.error("auth_invalid_header")
            raise HTTPException(
                status_code=401,
                detail={
                    "error_code": "AUTHN_INVALID_TOKEN",
                    "message": "Authorization header must be Bearer <token>.",
                    "remediation_hint": "Provide a valid bearer session token.",
                },
            )

        bearer_token = token.strip()
        session: Optional[SessionRecord] = None
        try:
            session_id = resolve_session_id_from_bearer_token(bearer_token)
            session = db.query(SessionRecord).filter_by(session_id=session_id).first()
        except HTTPException:
            session = None

        if session is None:
            # Portkey-style virtual key bearer: allow inference with the minted key hash.
            virtual_key = db.query(VirtualKey).filter_by(key_hash=bearer_token).first()
            if virtual_key is None:
                raise HTTPException(
                    status_code=401,
                    detail={
                        "error_code": "AUTHN_INVALID_TOKEN",
                        "message": "Session token format is invalid.",
                        "remediation_hint": "Issue a new session using /auth/sessions and retry.",
                    },
                )
            key_status = str(virtual_key.status or "").strip().lower()
            if key_status == "blocked":
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error_code": "VIRTUAL_KEY_BLOCKED",
                        "message": f"Virtual key '{virtual_key.key_id}' is blocked.",
                        "key_id": virtual_key.key_id,
                    },
                )
            expires_at = getattr(virtual_key, "expires_at", None)
            if expires_at is not None:
                try:
                    expired = expires_at <= datetime.utcnow()
                except TypeError:
                    expired = True
                if expired:
                    raise HTTPException(
                        status_code=403,
                        detail={
                            "error_code": "VIRTUAL_KEY_EXPIRED",
                            "message": f"Virtual key '{virtual_key.key_id}' has expired.",
                            "key_id": virtual_key.key_id,
                        },
                    )
            # Prefer explicit operator headers in local/dev; otherwise authenticate as agent-owner of the key scope.
            if _ALLOW_HEADER_ACTOR_AUTH and actor_id and actor_role:
                pass
            else:
                owner_type = str(virtual_key.owner_scope_type or "user").strip().lower() or "user"
                owner_id = str(virtual_key.owner_scope_id or virtual_key.key_id).strip()
                actor_id = f"{owner_type}:{owner_id}"
                actor_role = ROLE_AGENT_OWNER
            logger.info(
                "auth_virtual_key_validated %s",
                sanitize_fields(
                    {
                        "actor_id": actor_id,
                        "actor_role": actor_role,
                        "key_id": virtual_key.key_id,
                        "jit_request_id": getattr(virtual_key, "jit_request_id", None),
                    }
                ),
            )
        else:
            if session.expires_at < datetime.utcnow():
                logger.error(
                    "auth_session_expired %s",
                    sanitize_fields({"session_id": bearer_token, "actor_id": actor_id}),
                )
                raise HTTPException(
                    status_code=401,
                    detail={
                        "error_code": "AUTHN_SESSION_EXPIRED",
                        "message": "Session token has expired.",
                        "remediation_hint": "Issue a new session and retry.",
                    },
                )

            if session.last_activity_at < datetime.utcnow() - timedelta(minutes=session.idle_timeout_minutes):
                logger.error(
                    "auth_session_idle_timeout %s",
                    sanitize_fields({"session_id": bearer_token, "actor_id": actor_id}),
                )
                raise HTTPException(
                    status_code=401,
                    detail={
                        "error_code": "AUTHN_SESSION_IDLE_TIMEOUT",
                        "message": "Session is idle and requires re-authentication.",
                        "remediation_hint": "Issue a new session token and retry.",
                    },
                )

            actor_id = session.actor_id
            actor_role = _canonicalize_role(session.actor_role)
            directory_user = db.query(DirectoryUser).filter_by(user_id=actor_id).first()
            if directory_user and str(directory_user.role_name or "").strip():
                directory_role = _canonicalize_role(directory_user.role_name)
                if directory_role and directory_role != actor_role:
                    session.actor_role = directory_role
                    actor_role = directory_role
            session.last_activity_at = datetime.utcnow()

            mfa_verified = bool(
                session.mfa_verified_at
                and session.mfa_verified_at
                >= datetime.utcnow() - timedelta(minutes=auth_policy.privileged_mfa_reauth_minutes)
            )
            db.commit()
            logger.info(
                "auth_session_validated %s",
                sanitize_fields({"actor_id": actor_id, "actor_role": actor_role, "user_login": resolve_user_login_for_actor(db, actor_id)}),
            )
    else:
        if not _ALLOW_HEADER_ACTOR_AUTH:
            logger.error("auth_header_identity_disabled")
            raise HTTPException(
                status_code=401,
                detail={
                    "error_code": "AUTHN_REQUIRED",
                    "message": "Header-based identity is disabled in this environment.",
                    "remediation_hint": "Use a bearer session token from /auth/sessions.",
                },
            )
        actor_id = actor_id or "system-user"
        actor_role = _canonicalize_role(actor_role) or "unknown"

    user_login = resolve_user_login_for_actor(db, actor_id)
    set_request_actor(actor_id, user_login, actor_role)

    logger.trace(
        "auth_context_ready %s",
        sanitize_fields({"actor_id": actor_id, "actor_role": actor_role, "user_login": user_login, "mfa_verified": mfa_verified}),
    )
    return ActorContext(
        actor_id=actor_id,
        actor_role=actor_role,
        user_login=user_login,
        approver_id=approver_id,
        approver_role=approver_role,
        mfa_verified=mfa_verified,
    )


def require_role(ctx: ActorContext, allowed_roles: set[str]) -> None:
    if ctx.actor_role in {ROLE_MASTER_ADMIN, ROLE_SUPER_ADMIN}:
        return
    if ctx.actor_role not in allowed_roles:
        explicit_required_roles = sorted(role for role in allowed_roles if role != ROLE_SUPER_ADMIN)
        logger.error(
            "authz_role_forbidden %s",
            sanitize_fields({"actor_id": ctx.actor_id, "actor_role": ctx.actor_role}),
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_ROLE_FORBIDDEN",
                "message": "Actor role is not allowed for this action.",
                "actor_role": ctx.actor_role,
                "required_role": ", ".join(explicit_required_roles),
                "policy_version": "v1",
                "decision_trace_id": "authz-role-check",
                "remediation_hint": "Use a role with required permissions.",
            },
        )


_PLATFORM_ADMIN_EQUIVALENT_APPROVER_ROLES = {ROLE_PLATFORM_ADMIN, ROLE_SUPER_ADMIN}


def approver_role_satisfies(required_approver_role: str, approver_role: Optional[str]) -> bool:
    actual = str(approver_role or "").strip()
    if not actual:
        return False
    if actual == required_approver_role:
        return True
    if required_approver_role == ROLE_PLATFORM_ADMIN and actual in _PLATFORM_ADMIN_EQUIVALENT_APPROVER_ROLES:
        return True
    return False


def require_dual_approval(
    ctx: ActorContext,
    required_approver_role: str = DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT,
) -> None:
    if ctx.actor_role in {ROLE_MASTER_ADMIN, ROLE_SUPER_ADMIN}:
        return
    if not approver_role_satisfies(required_approver_role, ctx.approver_role) or not ctx.approver_id:
        logger.error(
            "authz_dual_approval_missing %s",
            sanitize_fields({"actor_id": ctx.actor_id, "approver_id": ctx.approver_id}),
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_DUAL_APPROVAL_REQUIRED",
                "message": "Security approver co-sign is required.",
                "actor_role": ctx.actor_role,
                "required_role": required_approver_role,
                "policy_version": "v1",
                "decision_trace_id": "authz-dual-approval",
                "remediation_hint": f"Provide {required_approver_role} identity headers.",
            },
        )

    if ctx.approver_id == ctx.actor_id:
        logger.error(
            "authz_dual_approval_identity_conflict %s",
            sanitize_fields({"actor_id": ctx.actor_id, "approver_id": ctx.approver_id}),
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error_code": "AUTHZ_DUAL_APPROVAL_IDENTITY_CONFLICT",
                "message": "Approver must be different from actor.",
                "policy_version": "v1",
                "decision_trace_id": "authz-dual-approval-identity",
                "remediation_hint": "Use a different approver identity header.",
            },
        )


def require_mfa(ctx: ActorContext) -> None:
    if _MFA_ENFORCEMENT_OPTIONAL:
        logger.trace(
            "authz_mfa_optional_skip %s",
            sanitize_fields({"actor_id": ctx.actor_id, "actor_role": ctx.actor_role}),
        )
        return
    if not ctx.mfa_verified:
        logger.error(
            "authz_mfa_required %s",
            sanitize_fields({"actor_id": ctx.actor_id, "actor_role": ctx.actor_role}),
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_MFA_REQUIRED",
                "message": "MFA verification is required for this action.",
                "actor_role": ctx.actor_role,
                "policy_version": "v1",
                "decision_trace_id": "authz-mfa-check",
                "remediation_hint": "Provide X-MFA-Verified: true for verified sessions.",
            },
        )
