from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from app.models import AuthPolicyConfig
from app.policy_constants import (
    AUTH_POLICY_DEFAULT_ID,
    AUTH_SESSION_ISSUER_ROLES_DEFAULT,
    AUTH_SESSION_READ_ROLES_DEFAULT,
    CROSS_ACTOR_DUAL_APPROVAL_ROLES_DEFAULT,
    DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT,
    ISSUABLE_SESSION_ROLES_DEFAULT,
    PRIVILEGED_MFA_REAUTH_MINUTES_DEFAULT,
    ROLE_MASTER_ADMIN,
)


@dataclass(frozen=True)
class AuthPolicy:
    session_read_roles: set[str]
    session_issuer_roles: set[str]
    issuable_session_roles: set[str]
    cross_actor_dual_approval_roles: set[str]
    dual_approval_required_approver_role: str
    privileged_mfa_reauth_minutes: int


def _parse_roles(raw_roles: str, fallback: set[str]) -> set[str]:
    parsed = {item.strip() for item in raw_roles.split(",") if item.strip()}
    return parsed or set(fallback)


def _with_master_admin(roles: set[str]) -> set[str]:
    return {*(roles or set()), ROLE_MASTER_ADMIN}


def get_auth_policy(db: Session) -> AuthPolicy:
    config = db.query(AuthPolicyConfig).filter_by(policy_id=AUTH_POLICY_DEFAULT_ID).first()
    if not config:
        return AuthPolicy(
            session_read_roles=_with_master_admin(set(AUTH_SESSION_READ_ROLES_DEFAULT)),
            session_issuer_roles=_with_master_admin(set(AUTH_SESSION_ISSUER_ROLES_DEFAULT)),
            issuable_session_roles=_with_master_admin(set(ISSUABLE_SESSION_ROLES_DEFAULT)),
            cross_actor_dual_approval_roles=_with_master_admin(set(CROSS_ACTOR_DUAL_APPROVAL_ROLES_DEFAULT)),
            dual_approval_required_approver_role=DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT,
            privileged_mfa_reauth_minutes=PRIVILEGED_MFA_REAUTH_MINUTES_DEFAULT,
        )

    return AuthPolicy(
        session_read_roles=_with_master_admin(_parse_roles(config.session_read_roles, AUTH_SESSION_READ_ROLES_DEFAULT)),
        session_issuer_roles=_with_master_admin(_parse_roles(config.session_issuer_roles, AUTH_SESSION_ISSUER_ROLES_DEFAULT)),
        issuable_session_roles=_with_master_admin(_parse_roles(config.issuable_session_roles, ISSUABLE_SESSION_ROLES_DEFAULT)),
        cross_actor_dual_approval_roles=_with_master_admin(_parse_roles(
            config.cross_actor_dual_approval_roles,
            CROSS_ACTOR_DUAL_APPROVAL_ROLES_DEFAULT,
        )),
        dual_approval_required_approver_role=(
            config.dual_approval_required_approver_role.strip()
            if config.dual_approval_required_approver_role.strip()
            else DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT
        ),
        privileged_mfa_reauth_minutes=(
            config.privileged_mfa_reauth_minutes
            if config.privileged_mfa_reauth_minutes > 0
            else PRIVILEGED_MFA_REAUTH_MINUTES_DEFAULT
        ),
    )
