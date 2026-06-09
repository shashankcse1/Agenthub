from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database import get_db
from app.logging_utils import get_logger, sanitize_fields
from app.models import (
    AuthPolicyConfig,
    AuthPolicyConfigRevision,
    BasicAuthFallbackConfig,
    DirectoryGroup,
    DirectoryGroupMembership,
    DirectoryTeam,
    DirectoryTeamMembership,
    DirectoryUser,
    IdentityProviderConfig,
    SessionRecord,
)
from app.policy_constants import (
    AUTH_POLICY_DEFAULT_ID,
    AUTH_SESSION_ISSUER_ROLES_DEFAULT,
    AUTH_SESSION_READ_ROLES_DEFAULT,
    CROSS_ACTOR_DUAL_APPROVAL_ROLES_DEFAULT,
    DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT,
    ISSUABLE_SESSION_ROLES_DEFAULT,
    PRIVILEGED_MFA_REAUTH_MINUTES_DEFAULT,
    ROLE_MASTER_ADMIN,
    ROLE_PLATFORM_ADMIN,
    ROLE_RELEASE_MANAGER,
    ROLE_SECURITY_APPROVER,
    SUPPORTED_ACTOR_ROLES,
)
from app.router_constants import (
    AUTH_ADMIN_OR_SECURITY_ROLES,
    AUTH_ADMIN_ROLES,
    AUTH_POLICY_REVISIONS_DEFAULT_LIMIT,
    AUTH_SESSION_REAUTH_ROLES,
)
from app.schemas import (
    AuthSessionPolicyConfigResponse,
    AuthSessionPolicyRevisionResponse,
    AuthSessionPolicyRollbackRequest,
    AuthSessionPolicyConfigUpdateRequest,
    BasicAuthConfigCreateRequest,
    BasicAuthConfigUpdateRequest,
    BasicAuthEnableRequest,
    DirectoryGroupMembershipResponse,
    DirectoryGroupResponse,
    DirectoryGroupUpsertRequest,
    DirectoryUserDisableResponse,
    DirectoryUserLockResponse,
    DirectoryTeamMembershipResponse,
    DirectoryTeamResponse,
    DirectoryTeamUpsertRequest,
    DirectoryUserUnlockResponse,
    DirectoryUserResponse,
    DirectoryUserUpsertRequest,
    RoleBindingValidateRequest,
    SessionCreateRequest,
    SessionIssueResponse,
    SessionLoginRequest,
    SessionLoginResponse,
    SSOProviderCreateRequest,
    SSOProviderUpdateRequest,
    SessionResponse,
)
from app.security import (
    ActorContext,
    get_actor_context,
    hash_user_password,
    issue_session_bearer_token,
    require_dual_approval,
    require_mfa,
    require_role,
    verify_user_password,
)
from app.services.audit import create_audit_event
from app.services.policy_config import AuthPolicy, get_auth_policy
from app.services.runtime_config import get_runtime_config_int
from app.runtime_constants import (
    RUNTIME_CONFIG_AUTH_LOGIN_LOCKOUT_MINUTES,
    RUNTIME_CONFIG_AUTH_LOGIN_MAX_FAILED_ATTEMPTS,
    RUNTIME_CONFIG_AUTH_POLICY_REVISIONS_DEFAULT_LIMIT,
)

router = APIRouter()
logger = get_logger(__name__)


def _normalize_roles(raw_roles: list[str]) -> list[str]:
    return sorted({role.strip() for role in raw_roles if role and role.strip()})


def _validate_supported_roles(field_name: str, roles: list[str]) -> None:
    unknown_roles = sorted(set(roles) - SUPPORTED_ACTOR_ROLES)
    if unknown_roles:
        raise HTTPException(
            status_code=400,
            detail=f"{field_name} has unsupported roles: {', '.join(unknown_roles)}",
        )


def _serialize_roles(roles: list[str], field_name: str) -> str:
    normalized = _normalize_roles(roles)
    if not normalized:
        raise HTTPException(status_code=400, detail=f"{field_name} cannot be empty")
    _validate_supported_roles(field_name, normalized)
    return ",".join(normalized)


def _roles_from_csv(raw: str, fallback: set[str]) -> list[str]:
    parsed = [item.strip() for item in raw.split(",") if item.strip()]
    if not parsed:
        return sorted(fallback)
    return sorted(set(parsed))


def _auth_policy_to_response(config: AuthPolicyConfig | None) -> AuthSessionPolicyConfigResponse:
    if not config:
        return {
            "policy_id": AUTH_POLICY_DEFAULT_ID,
            "session_read_roles": sorted(AUTH_SESSION_READ_ROLES_DEFAULT),
            "session_issuer_roles": sorted(AUTH_SESSION_ISSUER_ROLES_DEFAULT),
            "issuable_session_roles": sorted(ISSUABLE_SESSION_ROLES_DEFAULT),
            "cross_actor_dual_approval_roles": sorted(CROSS_ACTOR_DUAL_APPROVAL_ROLES_DEFAULT),
            "dual_approval_required_approver_role": DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT,
            "description": "",
            "privileged_mfa_reauth_minutes": PRIVILEGED_MFA_REAUTH_MINUTES_DEFAULT,
            "source": "default",
        }

    return {
        "policy_id": config.policy_id,
        "session_read_roles": _roles_from_csv(config.session_read_roles, AUTH_SESSION_READ_ROLES_DEFAULT),
        "session_issuer_roles": _roles_from_csv(config.session_issuer_roles, AUTH_SESSION_ISSUER_ROLES_DEFAULT),
        "issuable_session_roles": _roles_from_csv(config.issuable_session_roles, ISSUABLE_SESSION_ROLES_DEFAULT),
        "cross_actor_dual_approval_roles": _roles_from_csv(
            config.cross_actor_dual_approval_roles,
            CROSS_ACTOR_DUAL_APPROVAL_ROLES_DEFAULT,
        ),
        "dual_approval_required_approver_role": (
            config.dual_approval_required_approver_role.strip() or DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT
        ),
        "description": (config.description or "").strip(),
        "privileged_mfa_reauth_minutes": (
            config.privileged_mfa_reauth_minutes
            if config.privileged_mfa_reauth_minutes > 0
            else PRIVILEGED_MFA_REAUTH_MINUTES_DEFAULT
        ),
        "source": "database",
    }


def _revision_to_response(revision: AuthPolicyConfigRevision) -> AuthSessionPolicyRevisionResponse:
    return {
        "revision_id": revision.revision_id,
        "policy_id": revision.policy_id,
        "session_read_roles": _roles_from_csv(revision.session_read_roles, AUTH_SESSION_READ_ROLES_DEFAULT),
        "session_issuer_roles": _roles_from_csv(revision.session_issuer_roles, AUTH_SESSION_ISSUER_ROLES_DEFAULT),
        "issuable_session_roles": _roles_from_csv(revision.issuable_session_roles, ISSUABLE_SESSION_ROLES_DEFAULT),
        "cross_actor_dual_approval_roles": _roles_from_csv(
            revision.cross_actor_dual_approval_roles,
            CROSS_ACTOR_DUAL_APPROVAL_ROLES_DEFAULT,
        ),
        "dual_approval_required_approver_role": revision.dual_approval_required_approver_role,
        "description": (revision.description or "").strip(),
        "privileged_mfa_reauth_minutes": revision.privileged_mfa_reauth_minutes,
        "changed_by": revision.changed_by,
        "change_reason": revision.change_reason,
        "source_revision_id": revision.source_revision_id,
        "created_at": revision.created_at,
    }


def _record_auth_policy_revision(
    db: Session,
    config: AuthPolicyConfig,
    changed_by: str,
    change_reason: str,
    source_revision_id: str | None = None,
) -> AuthPolicyConfigRevision:
    revision = AuthPolicyConfigRevision(
        revision_id=f"apr-{uuid4()}",
        policy_id=config.policy_id,
        session_read_roles=config.session_read_roles,
        session_issuer_roles=config.session_issuer_roles,
        issuable_session_roles=config.issuable_session_roles,
        cross_actor_dual_approval_roles=config.cross_actor_dual_approval_roles,
        dual_approval_required_approver_role=config.dual_approval_required_approver_role,
        description=config.description,
        privileged_mfa_reauth_minutes=config.privileged_mfa_reauth_minutes,
        changed_by=changed_by,
        change_reason=change_reason,
        source_revision_id=source_revision_id,
    )
    db.add(revision)
    return revision

def _enforce_session_issue_policy(payload: SessionCreateRequest, ctx: ActorContext, policy: AuthPolicy) -> None:
    if ctx.actor_role == ROLE_MASTER_ADMIN:
        return
    if payload.actor_role not in policy.issuable_session_roles:
        raise HTTPException(status_code=400, detail="Requested actor_role is not supported")

    if ctx.actor_role == ROLE_RELEASE_MANAGER and payload.actor_role == ROLE_PLATFORM_ADMIN:
        raise HTTPException(status_code=403, detail="Release Manager cannot issue Platform Admin sessions")

    if payload.actor_id != ctx.actor_id and payload.actor_role in policy.cross_actor_dual_approval_roles:
        require_dual_approval(ctx, required_approver_role=policy.dual_approval_required_approver_role)


@router.get("/auth/policies/session", response_model=AuthSessionPolicyConfigResponse)
def get_auth_session_policy(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_OR_SECURITY_ROLES)
    config = db.query(AuthPolicyConfig).filter_by(policy_id=AUTH_POLICY_DEFAULT_ID).first()
    return _auth_policy_to_response(config)


@router.patch("/auth/policies/session", response_model=AuthSessionPolicyConfigResponse)
def update_auth_session_policy(
    payload: AuthSessionPolicyConfigUpdateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_OR_SECURITY_ROLES)
    require_mfa(ctx)
    require_dual_approval(ctx)

    config = db.query(AuthPolicyConfig).filter_by(policy_id=AUTH_POLICY_DEFAULT_ID).first()
    if not config:
        config = AuthPolicyConfig(policy_id=AUTH_POLICY_DEFAULT_ID)
        db.add(config)

    if payload.session_read_roles is not None:
        config.session_read_roles = _serialize_roles(payload.session_read_roles, "session_read_roles")
    if payload.session_issuer_roles is not None:
        config.session_issuer_roles = _serialize_roles(payload.session_issuer_roles, "session_issuer_roles")
    if payload.issuable_session_roles is not None:
        config.issuable_session_roles = _serialize_roles(payload.issuable_session_roles, "issuable_session_roles")
    if payload.cross_actor_dual_approval_roles is not None:
        config.cross_actor_dual_approval_roles = _serialize_roles(
            payload.cross_actor_dual_approval_roles,
            "cross_actor_dual_approval_roles",
        )
    if payload.dual_approval_required_approver_role is not None:
        approver_role = payload.dual_approval_required_approver_role.strip()
        if not approver_role:
            raise HTTPException(status_code=400, detail="dual_approval_required_approver_role cannot be empty")
        if approver_role not in SUPPORTED_ACTOR_ROLES:
            raise HTTPException(status_code=400, detail="dual_approval_required_approver_role is not supported")
        config.dual_approval_required_approver_role = approver_role
    if payload.description is not None:
        config.description = payload.description.strip()
    if payload.privileged_mfa_reauth_minutes is not None:
        config.privileged_mfa_reauth_minutes = payload.privileged_mfa_reauth_minutes

    issuer_roles = set(_roles_from_csv(config.session_issuer_roles, AUTH_SESSION_ISSUER_ROLES_DEFAULT))
    issuable_roles = set(_roles_from_csv(config.issuable_session_roles, ISSUABLE_SESSION_ROLES_DEFAULT))
    if not issuer_roles.issubset(issuable_roles):
        invalid_issuer_roles = sorted(issuer_roles - issuable_roles)
        raise HTTPException(
            status_code=400,
            detail=f"session_issuer_roles must be a subset of issuable_session_roles: {', '.join(invalid_issuer_roles)}",
        )

    dual_approval_roles = set(_roles_from_csv(config.cross_actor_dual_approval_roles, CROSS_ACTOR_DUAL_APPROVAL_ROLES_DEFAULT))
    required_approver = config.dual_approval_required_approver_role.strip() or DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT
    if required_approver in dual_approval_roles and required_approver not in issuable_roles:
        raise HTTPException(
            status_code=400,
            detail="dual_approval_required_approver_role must be included in issuable_session_roles when used in cross_actor_dual_approval_roles",
        )

    _record_auth_policy_revision(
        db,
        config=config,
        changed_by=ctx.actor_id,
        change_reason="policy_update",
    )

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.session_policy.update",
        resource_type="auth_policy_config",
        resource_id=AUTH_POLICY_DEFAULT_ID,
        trace_id=f"trace-auth-policy-{AUTH_POLICY_DEFAULT_ID}",
    )
    db.commit()
    db.refresh(config)
    return _auth_policy_to_response(config)


@router.get("/auth/policies/session/revisions", response_model=list[AuthSessionPolicyRevisionResponse])
def list_auth_session_policy_revisions(
    limit: Optional[int] = None,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    resolved_limit = (
        limit
        if limit is not None
        else get_runtime_config_int(
            db,
            RUNTIME_CONFIG_AUTH_POLICY_REVISIONS_DEFAULT_LIMIT,
            AUTH_POLICY_REVISIONS_DEFAULT_LIMIT,
        )
    )
    if resolved_limit < 1 or resolved_limit > 200:
        raise HTTPException(status_code=400, detail="limit must be between 1 and 200")

    revisions = (
        db.query(AuthPolicyConfigRevision)
        .filter_by(policy_id=AUTH_POLICY_DEFAULT_ID)
        .order_by(AuthPolicyConfigRevision.created_at.desc())
        .limit(resolved_limit)
        .all()
    )
    return [_revision_to_response(revision) for revision in revisions]


@router.post("/auth/policies/session/rollback", response_model=AuthSessionPolicyConfigResponse)
def rollback_auth_session_policy(
    payload: AuthSessionPolicyRollbackRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    require_mfa(ctx)
    require_dual_approval(ctx)

    target_revision = (
        db.query(AuthPolicyConfigRevision)
        .filter_by(policy_id=AUTH_POLICY_DEFAULT_ID, revision_id=payload.revision_id)
        .first()
    )
    if not target_revision:
        raise HTTPException(status_code=404, detail="Policy revision not found")

    config = db.query(AuthPolicyConfig).filter_by(policy_id=AUTH_POLICY_DEFAULT_ID).first()
    if not config:
        config = AuthPolicyConfig(policy_id=AUTH_POLICY_DEFAULT_ID)
        db.add(config)

    config.session_read_roles = target_revision.session_read_roles
    config.session_issuer_roles = target_revision.session_issuer_roles
    config.issuable_session_roles = target_revision.issuable_session_roles
    config.cross_actor_dual_approval_roles = target_revision.cross_actor_dual_approval_roles
    config.dual_approval_required_approver_role = target_revision.dual_approval_required_approver_role
    config.description = target_revision.description
    config.privileged_mfa_reauth_minutes = target_revision.privileged_mfa_reauth_minutes

    rollback_reason = payload.change_reason.strip() or "rollback"
    _record_auth_policy_revision(
        db,
        config=config,
        changed_by=ctx.actor_id,
        change_reason=rollback_reason,
        source_revision_id=target_revision.revision_id,
    )

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.session_policy.rollback",
        resource_type="auth_policy_config",
        resource_id=AUTH_POLICY_DEFAULT_ID,
        trace_id=f"trace-auth-policy-rollback-{payload.revision_id}",
    )

    db.commit()
    db.refresh(config)
    return _auth_policy_to_response(config)


@router.post("/auth/sso/providers")
def create_sso_provider(
    payload: SSOProviderCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace("sso_provider_create_start %s", sanitize_fields({"actor_id": ctx.actor_id, "tenant_id": payload.tenant_id}))
    require_role(ctx, AUTH_ADMIN_ROLES)

    provider = IdentityProviderConfig(
        provider_id=str(uuid4()),
        tenant_id=payload.tenant_id,
        protocol_type=payload.protocol_type,
        issuer_or_entity_id=payload.issuer_or_entity_id,
        jwks_or_metadata_url=payload.jwks_or_metadata_url,
        scim_base_url=payload.scim_base_url,
        role_mapping_rules=payload.role_mapping_rules,
        mfa_required_roles=payload.mfa_required_roles,
        session_policy_id=payload.session_policy_id,
        status="active",
    )
    db.add(provider)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.sso.provider.create",
        resource_type="identity_provider",
        resource_id=provider.provider_id,
        trace_id=f"trace-{provider.provider_id}",
    )
    db.commit()
    logger.info(
        "sso_provider_created %s",
        sanitize_fields({"actor_id": ctx.actor_id, "provider_id": provider.provider_id}),
    )
    return {"provider_id": provider.provider_id, "status": provider.status}


@router.patch("/auth/sso/providers/{provider_id}")
def update_sso_provider(
    provider_id: str,
    payload: SSOProviderUpdateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    provider = db.query(IdentityProviderConfig).filter_by(provider_id=provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")

    updates = payload.model_dump(exclude_none=True)
    for key, value in updates.items():
        setattr(provider, key, value)

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.sso.provider.update",
        resource_type="identity_provider",
        resource_id=provider.provider_id,
        trace_id=f"trace-{provider.provider_id}",
    )
    db.commit()
    return {"provider_id": provider.provider_id, "status": provider.status}


@router.post("/auth/sso/providers/{provider_id}/test")
def test_sso_provider(
    provider_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    provider = db.query(IdentityProviderConfig).filter_by(provider_id=provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")

    provider.last_validated_at = datetime.utcnow()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.sso.provider.test",
        resource_type="identity_provider",
        resource_id=provider.provider_id,
        trace_id=f"trace-{provider.provider_id}",
    )
    db.commit()
    return {"provider_id": provider_id, "test_status": "passed"}


@router.post("/auth/sso/providers/{provider_id}/scim/sync")
def scim_sync(
    provider_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace("sso_scim_sync_start %s", sanitize_fields({"actor_id": ctx.actor_id, "provider_id": provider_id}))
    require_role(ctx, AUTH_ADMIN_ROLES)
    provider = db.query(IdentityProviderConfig).filter_by(provider_id=provider_id).first()
    if not provider:
        logger.error("sso_scim_sync_provider_not_found %s", sanitize_fields({"provider_id": provider_id}))
        raise HTTPException(status_code=404, detail="Provider not found")

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.sso.provider.scim_sync",
        resource_type="identity_provider",
        resource_id=provider.provider_id,
        trace_id=f"trace-{provider.provider_id}",
    )
    db.commit()
    logger.info("sso_scim_sync_completed %s", sanitize_fields({"actor_id": ctx.actor_id, "provider_id": provider_id}))
    return {"provider_id": provider_id, "synced_groups": 0, "synced_users": 0}


@router.get("/auth/sessions/{session_id}", response_model=SessionResponse)
def get_session(
    session_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    policy = get_auth_policy(db)
    require_role(ctx, policy.session_read_roles)
    session = db.query(SessionRecord).filter_by(session_id=session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@router.post("/auth/sessions", response_model=SessionIssueResponse)
def issue_session(
    payload: SessionCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    logger.trace(
        "session_issue_start %s",
        sanitize_fields({"actor_id": ctx.actor_id, "target_actor_id": payload.actor_id, "target_role": payload.actor_role}),
    )
    policy = get_auth_policy(db)
    require_role(ctx, policy.session_issuer_roles)
    _enforce_session_issue_policy(payload, ctx, policy)

    session = _create_session(
        db,
        actor_id=payload.actor_id,
        actor_role=payload.actor_role,
        ttl_minutes=payload.ttl_minutes,
        idle_timeout_minutes=payload.idle_timeout_minutes,
        mfa_verified=bool(payload.mfa_verified),
    )
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.session.issue",
        resource_type="session",
        resource_id=session.session_id,
        trace_id=f"trace-{session.session_id}",
    )
    db.commit()
    logger.info(
        "session_issued %s",
        sanitize_fields({"actor_id": ctx.actor_id, "issued_session_id": session.session_id}),
    )
    return {
        "session_id": session.session_id,
        "token_type": "Bearer",
        "access_token": issue_session_bearer_token(session.session_id),
        "expires_at": session.expires_at,
    }


@router.post("/auth/sessions/{session_id}/reauth")
def reauth_session(
    session_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_SESSION_REAUTH_ROLES)
    session = db.query(SessionRecord).filter_by(session_id=session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    session.mfa_verified_at = datetime.utcnow()
    session.last_activity_at = datetime.utcnow()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.session.reauth",
        resource_type="session",
        resource_id=session.session_id,
        trace_id=f"trace-reauth-{session.session_id}",
    )
    db.commit()
    return {"session_id": session_id, "reauthenticated": True, "mfa_verified_at": session.mfa_verified_at}


@router.post("/auth/roles/bindings/validate")
def validate_role_binding(
    payload: RoleBindingValidateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, {ROLE_PLATFORM_ADMIN})
    supported_roles = SUPPORTED_ACTOR_ROLES
    is_valid = payload.role_name in supported_roles and len(payload.action) > 0
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.role_binding.validate",
        resource_type="role_binding",
        resource_id=payload.role_name,
        trace_id=f"trace-role-binding-{payload.role_name}",
        decision_outcome="allow" if is_valid else "warn",
    )
    db.commit()
    return {"valid": is_valid, "role": payload.role_name}


@router.post(
    "/auth/basic/config",
    summary="Create basic auth fallback config",
    description="Creates a disabled basic-auth fallback policy for break-glass operations under platform-admin control.",
    responses={
        403: {"description": "Actor role is not allowed for this action."},
    },
)
def create_basic_auth_config(
    payload: BasicAuthConfigCreateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, {ROLE_PLATFORM_ADMIN})
    config = BasicAuthFallbackConfig(
        basic_auth_config_id=str(uuid4()),
        tenant_id=payload.tenant_id,
        environment=payload.environment,
        enabled=False,
        allowed_user_groups=payload.allowed_user_groups,
        ip_allowlist=payload.ip_allowlist,
        max_enable_duration_minutes=payload.max_enable_duration_minutes,
    )
    db.add(config)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.basic_fallback.config.create",
        resource_type="basic_auth_config",
        resource_id=config.basic_auth_config_id,
        trace_id=f"trace-{config.basic_auth_config_id}",
    )
    db.commit()
    return {"basic_auth_config_id": config.basic_auth_config_id, "enabled": config.enabled}


@router.patch("/auth/basic/config/{config_id}")
def update_basic_auth_config(
    config_id: str,
    payload: BasicAuthConfigUpdateRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, {ROLE_PLATFORM_ADMIN})
    config = db.query(BasicAuthFallbackConfig).filter_by(basic_auth_config_id=config_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="Basic auth config not found")

    updates = payload.model_dump(exclude_none=True)
    for key, value in updates.items():
        setattr(config, key, value)

    config.last_toggled_at = datetime.utcnow()
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.basic_fallback.config.update",
        resource_type="basic_auth_config",
        resource_id=config.basic_auth_config_id,
        trace_id=f"trace-{config.basic_auth_config_id}",
    )
    db.commit()
    return {"basic_auth_config_id": config_id, "enabled": config.enabled}


@router.post(
    "/auth/basic/config/{config_id}/enable-temporary",
    summary="Enable break-glass basic auth temporarily",
    description=(
        "Temporarily enables basic-auth fallback for a specific configuration with dual-approval guardrails. "
        "Use only for emergency access during incidents and capture a break-glass reason."
    ),
    responses={
        400: {"description": "Validation failed: approver identity conflict or requested duration exceeds max limit."},
        403: {"description": "Actor role is not allowed for this action or dual approval is missing."},
        404: {"description": "Basic auth config not found."},
    },
)
def enable_basic_auth_temporary(
    config_id: str,
    payload: BasicAuthEnableRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    try:
        require_role(ctx, {ROLE_PLATFORM_ADMIN})
        require_dual_approval(ctx)
    except HTTPException as exc:
        if exc.status_code == 403:
            create_audit_event(
                db,
                actor_id=ctx.actor_id,
                action_type="auth.basic_fallback.enable",
                resource_type="basic_auth_config",
                resource_id=config_id,
                trace_id=f"trace-{config_id}",
                decision_outcome="deny",
            )
            db.commit()
        raise

    config = db.query(BasicAuthFallbackConfig).filter_by(basic_auth_config_id=config_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="Basic auth config not found")

    if payload.duration_minutes > config.max_enable_duration_minutes:
        raise HTTPException(status_code=400, detail="Requested duration exceeds max limit")

    config.enabled = True
    config.enabled_by = ctx.actor_id
    config.break_glass_reason = payload.break_glass_reason
    config.expires_at = datetime.utcnow() + timedelta(minutes=payload.duration_minutes)
    config.last_toggled_at = datetime.utcnow()

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.basic_fallback.enable",
        resource_type="basic_auth_config",
        resource_id=config.basic_auth_config_id,
        trace_id=f"trace-{config.basic_auth_config_id}",
    )

    db.commit()
    return {
        "basic_auth_config_id": config_id,
        "enabled": True,
        "expires_at": config.expires_at,
    }


@router.post(
    "/auth/basic/config/{config_id}/disable",
    summary="Disable break-glass basic auth",
    description=(
        "Disables basic-auth fallback for the target configuration. "
        "Use this to close emergency-access windows after incident mitigation."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action."},
        404: {"description": "Basic auth config not found."},
    },
)
def disable_basic_auth(
    config_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    try:
        require_role(ctx, AUTH_ADMIN_OR_SECURITY_ROLES)
    except HTTPException as exc:
        if exc.status_code == 403:
            create_audit_event(
                db,
                actor_id=ctx.actor_id,
                action_type="auth.basic_fallback.disable",
                resource_type="basic_auth_config",
                resource_id=config_id,
                trace_id=f"trace-{config_id}",
                decision_outcome="deny",
            )
            db.commit()
        raise

    config = db.query(BasicAuthFallbackConfig).filter_by(basic_auth_config_id=config_id).first()
    if not config:
        raise HTTPException(status_code=404, detail="Basic auth config not found")

    config.enabled = False
    config.expires_at = datetime.utcnow()
    config.last_toggled_at = datetime.utcnow()

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.basic_fallback.disable",
        resource_type="basic_auth_config",
        resource_id=config.basic_auth_config_id,
        trace_id=f"trace-{config.basic_auth_config_id}",
    )

    db.commit()
    return {"basic_auth_config_id": config_id, "enabled": False}


def _normalize_status(value: Optional[str], default: str = "active") -> str:
    normalized = str(value or default).strip().lower()
    if normalized not in {"active", "inactive"}:
        raise HTTPException(status_code=400, detail="status must be active or inactive")
    return normalized


def _create_session(
    db: Session,
    actor_id: str,
    actor_role: str,
    ttl_minutes: int,
    idle_timeout_minutes: int,
    mfa_verified: Optional[bool],
) -> SessionRecord:
    session = SessionRecord(
        session_id=str(uuid4()),
        actor_id=actor_id,
        actor_role=actor_role,
        created_at=datetime.utcnow(),
        last_activity_at=datetime.utcnow(),
        idle_timeout_minutes=idle_timeout_minutes,
        mfa_verified_at=datetime.utcnow() if bool(mfa_verified) else None,
        expires_at=datetime.utcnow() + timedelta(minutes=ttl_minutes),
    )
    db.add(session)
    return session


def _login_max_failed_attempts(db: Session) -> int:
    configured = get_runtime_config_int(db, RUNTIME_CONFIG_AUTH_LOGIN_MAX_FAILED_ATTEMPTS, fallback=5)
    return max(1, min(configured, 20))


def _login_lockout_minutes(db: Session) -> int:
    configured = get_runtime_config_int(db, RUNTIME_CONFIG_AUTH_LOGIN_LOCKOUT_MINUTES, fallback=15)
    return max(1, min(configured, 240))


def _record_failed_password_login(db: Session, user: DirectoryUser) -> None:
    attempts = max(0, int(user.failed_login_attempts or 0)) + 1
    max_attempts = _login_max_failed_attempts(db)
    if attempts >= max_attempts:
        user.failed_login_attempts = 0
        user.locked_until = datetime.utcnow() + timedelta(minutes=_login_lockout_minutes(db))
    else:
        user.failed_login_attempts = attempts
    db.flush()


@router.post("/auth/login", response_model=SessionLoginResponse)
def login_with_password(
    payload: SessionLoginRequest,
    db: Session = Depends(get_db),
):
    username = payload.username.strip()
    if not username:
        raise HTTPException(status_code=400, detail="username cannot be empty")

    now = datetime.utcnow()
    login_trace_id = f"trace-login-{uuid4()}"
    user = db.query(DirectoryUser).filter_by(user_id=username).first()
    if not user or user.status != "active":
        create_audit_event(
            db,
            actor_id=username,
            action_type="auth.login.password",
            resource_type="directory_user",
            resource_id=username,
            trace_id=login_trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if user.locked_until and user.locked_until > now:
        create_audit_event(
            db,
            actor_id=user.user_id,
            action_type="auth.login.password",
            resource_type="directory_user",
            resource_id=user.user_id,
            trace_id=login_trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    if user.locked_until and user.locked_until <= now:
        user.locked_until = None

    if not verify_user_password(payload.password, user.password_hash):
        _record_failed_password_login(db, user)
        create_audit_event(
            db,
            actor_id=user.user_id,
            action_type="auth.login.password",
            resource_type="directory_user",
            resource_id=user.user_id,
            trace_id=login_trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise HTTPException(status_code=401, detail="Invalid username or password")

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now

    session = _create_session(
        db,
        actor_id=user.user_id,
        actor_role=user.role_name,
        ttl_minutes=payload.ttl_minutes,
        idle_timeout_minutes=payload.idle_timeout_minutes,
        # Never trust client-side MFA claims at login time.
        mfa_verified=False,
    )
    create_audit_event(
        db,
        actor_id=user.user_id,
        action_type="auth.login.password",
        resource_type="directory_user",
        resource_id=user.user_id,
        trace_id=f"trace-login-{session.session_id}",
    )
    create_audit_event(
        db,
        actor_id=user.user_id,
        action_type="auth.session.issue",
        resource_type="session",
        resource_id=session.session_id,
        trace_id=f"trace-{session.session_id}",
    )
    db.commit()
    return {
        "session_id": session.session_id,
        "token_type": "Bearer",
        "access_token": issue_session_bearer_token(session.session_id),
        "expires_at": session.expires_at,
        "actor_id": user.user_id,
        "actor_role": user.role_name,
    }


@router.post("/auth/directory/users", response_model=DirectoryUserResponse)
def create_directory_user(
    payload: DirectoryUserUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_OR_SECURITY_ROLES)
    require_mfa(ctx)

    user_id = payload.user_id.strip()
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id cannot be empty")
    if payload.role_name.strip() not in SUPPORTED_ACTOR_ROLES:
        raise HTTPException(status_code=400, detail="role_name is not supported")
    if not payload.password:
        raise HTTPException(status_code=400, detail="password is required for creating a directory user")

    existing = db.query(DirectoryUser).filter_by(user_id=user_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Directory user already exists")

    row = DirectoryUser(
        user_id=user_id,
        display_name=payload.display_name.strip(),
        email=payload.email.strip().lower(),
        role_name=payload.role_name.strip(),
        password_hash=hash_user_password(payload.password),
        status=_normalize_status(payload.status),
        updated_by=ctx.actor_id,
    )
    db.add(row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.directory.user.create",
        resource_type="directory_user",
        resource_id=row.user_id,
        trace_id=f"trace-directory-user-{row.user_id}",
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/auth/directory/users", response_model=list[DirectoryUserResponse])
def list_directory_users(
    status: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_OR_SECURITY_ROLES)

    query = db.query(DirectoryUser)
    if status:
        query = query.filter(DirectoryUser.status == _normalize_status(status))
    return query.order_by(DirectoryUser.user_id.asc()).offset(max(0, offset)).limit(max(1, min(limit, 500))).all()


@router.put("/auth/directory/users/{user_id}", response_model=DirectoryUserResponse)
def update_directory_user(
    user_id: str,
    payload: DirectoryUserUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    require_mfa(ctx)

    normalized_user_id = user_id.strip()
    if payload.user_id.strip() != normalized_user_id:
        raise HTTPException(status_code=400, detail="user_id in payload must match path")
    if payload.role_name.strip() not in SUPPORTED_ACTOR_ROLES:
        raise HTTPException(status_code=400, detail="role_name is not supported")

    row = db.query(DirectoryUser).filter_by(user_id=normalized_user_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Directory user not found")

    row.display_name = payload.display_name.strip()
    row.email = payload.email.strip().lower()
    row.role_name = payload.role_name.strip()
    if payload.password:
        row.password_hash = hash_user_password(payload.password)
        row.failed_login_attempts = 0
        row.locked_until = None
    row.status = _normalize_status(payload.status)
    row.updated_by = ctx.actor_id
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.directory.user.update",
        resource_type="directory_user",
        resource_id=row.user_id,
        trace_id=f"trace-directory-user-{row.user_id}",
    )
    db.commit()
    db.refresh(row)
    return row


@router.delete("/auth/directory/users/{user_id}")
def delete_directory_user(
    user_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    require_mfa(ctx)

    row = db.query(DirectoryUser).filter_by(user_id=user_id.strip()).first()
    if not row:
        raise HTTPException(status_code=404, detail="Directory user not found")

    db.query(DirectoryGroupMembership).filter_by(user_id=row.user_id).delete()
    db.query(DirectoryTeamMembership).filter_by(user_id=row.user_id).delete()
    db.delete(row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.directory.user.delete",
        resource_type="directory_user",
        resource_id=user_id,
        trace_id=f"trace-directory-user-{user_id}",
    )
    db.commit()
    return {"deleted": True, "user_id": user_id}


@router.post("/auth/directory/users/{user_id}/unlock", response_model=DirectoryUserUnlockResponse)
def unlock_directory_user(
    user_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    require_mfa(ctx)

    row = db.query(DirectoryUser).filter_by(user_id=user_id.strip()).first()
    if not row:
        raise HTTPException(status_code=404, detail="Directory user not found")

    row.failed_login_attempts = 0
    row.locked_until = None
    row.updated_by = ctx.actor_id
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.directory.user.unlock",
        resource_type="directory_user",
        resource_id=row.user_id,
        trace_id=f"trace-directory-user-unlock-{row.user_id}",
    )
    db.commit()
    return {"user_id": row.user_id, "unlocked": True}


@router.post("/auth/directory/users/{user_id}/lock", response_model=DirectoryUserLockResponse)
def lock_directory_user(
    user_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    require_mfa(ctx)

    row = db.query(DirectoryUser).filter_by(user_id=user_id.strip()).first()
    if not row:
        raise HTTPException(status_code=404, detail="Directory user not found")

    lock_minutes = _login_lockout_minutes(db)
    row.locked_until = datetime.utcnow() + timedelta(minutes=lock_minutes)
    row.failed_login_attempts = _login_max_failed_attempts(db)
    row.updated_by = ctx.actor_id
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.directory.user.lock",
        resource_type="directory_user",
        resource_id=row.user_id,
        trace_id=f"trace-directory-user-lock-{row.user_id}",
    )
    db.commit()
    return {"user_id": row.user_id, "locked": True, "locked_until": row.locked_until}


@router.post("/auth/directory/users/{user_id}/disable", response_model=DirectoryUserDisableResponse)
def disable_directory_user(
    user_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    require_mfa(ctx)

    row = db.query(DirectoryUser).filter_by(user_id=user_id.strip()).first()
    if not row:
        raise HTTPException(status_code=404, detail="Directory user not found")

    row.status = "inactive"
    row.updated_by = ctx.actor_id
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.directory.user.disable",
        resource_type="directory_user",
        resource_id=row.user_id,
        trace_id=f"trace-directory-user-disable-{row.user_id}",
    )
    db.commit()
    return {"user_id": row.user_id, "disabled": True}


@router.post("/auth/directory/groups", response_model=DirectoryGroupResponse)
def create_directory_group(
    payload: DirectoryGroupUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    require_mfa(ctx)

    group_id = payload.group_id.strip()
    if not group_id:
        raise HTTPException(status_code=400, detail="group_id cannot be empty")
    existing = db.query(DirectoryGroup).filter_by(group_id=group_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Directory group already exists")

    row = DirectoryGroup(
        group_id=group_id,
        display_name=payload.display_name.strip(),
        description=payload.description.strip(),
        status=_normalize_status(payload.status),
        updated_by=ctx.actor_id,
    )
    db.add(row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.directory.group.create",
        resource_type="directory_group",
        resource_id=row.group_id,
        trace_id=f"trace-directory-group-{row.group_id}",
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/auth/directory/groups", response_model=list[DirectoryGroupResponse])
def list_directory_groups(
    status: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_OR_SECURITY_ROLES)

    query = db.query(DirectoryGroup)
    if status:
        query = query.filter(DirectoryGroup.status == _normalize_status(status))
    return query.order_by(DirectoryGroup.group_id.asc()).offset(max(0, offset)).limit(max(1, min(limit, 500))).all()


@router.put("/auth/directory/groups/{group_id}", response_model=DirectoryGroupResponse)
def update_directory_group(
    group_id: str,
    payload: DirectoryGroupUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    require_mfa(ctx)

    normalized_group_id = group_id.strip()
    if payload.group_id.strip() != normalized_group_id:
        raise HTTPException(status_code=400, detail="group_id in payload must match path")

    row = db.query(DirectoryGroup).filter_by(group_id=normalized_group_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Directory group not found")

    row.display_name = payload.display_name.strip()
    row.description = payload.description.strip()
    row.status = _normalize_status(payload.status)
    row.updated_by = ctx.actor_id
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.directory.group.update",
        resource_type="directory_group",
        resource_id=row.group_id,
        trace_id=f"trace-directory-group-{row.group_id}",
    )
    db.commit()
    db.refresh(row)
    return row


@router.delete("/auth/directory/groups/{group_id}")
def delete_directory_group(
    group_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    require_mfa(ctx)

    row = db.query(DirectoryGroup).filter_by(group_id=group_id.strip()).first()
    if not row:
        raise HTTPException(status_code=404, detail="Directory group not found")

    db.query(DirectoryGroupMembership).filter_by(group_id=row.group_id).delete()
    db.delete(row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.directory.group.delete",
        resource_type="directory_group",
        resource_id=group_id,
        trace_id=f"trace-directory-group-{group_id}",
    )
    db.commit()
    return {"deleted": True, "group_id": group_id}


@router.post("/auth/directory/teams", response_model=DirectoryTeamResponse)
def create_directory_team(
    payload: DirectoryTeamUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    require_mfa(ctx)

    team_id = payload.team_id.strip()
    if not team_id:
        raise HTTPException(status_code=400, detail="team_id cannot be empty")
    existing = db.query(DirectoryTeam).filter_by(team_id=team_id).first()
    if existing:
        raise HTTPException(status_code=409, detail="Directory team already exists")

    row = DirectoryTeam(
        team_id=team_id,
        display_name=payload.display_name.strip(),
        description=payload.description.strip(),
        status=_normalize_status(payload.status),
        updated_by=ctx.actor_id,
    )
    db.add(row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.directory.team.create",
        resource_type="directory_team",
        resource_id=row.team_id,
        trace_id=f"trace-directory-team-{row.team_id}",
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/auth/directory/teams", response_model=list[DirectoryTeamResponse])
def list_directory_teams(
    status: Optional[str] = None,
    limit: int = 200,
    offset: int = 0,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_OR_SECURITY_ROLES)

    query = db.query(DirectoryTeam)
    if status:
        query = query.filter(DirectoryTeam.status == _normalize_status(status))
    return query.order_by(DirectoryTeam.team_id.asc()).offset(max(0, offset)).limit(max(1, min(limit, 500))).all()


@router.put("/auth/directory/teams/{team_id}", response_model=DirectoryTeamResponse)
def update_directory_team(
    team_id: str,
    payload: DirectoryTeamUpsertRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    require_mfa(ctx)

    normalized_team_id = team_id.strip()
    if payload.team_id.strip() != normalized_team_id:
        raise HTTPException(status_code=400, detail="team_id in payload must match path")

    row = db.query(DirectoryTeam).filter_by(team_id=normalized_team_id).first()
    if not row:
        raise HTTPException(status_code=404, detail="Directory team not found")

    row.display_name = payload.display_name.strip()
    row.description = payload.description.strip()
    row.status = _normalize_status(payload.status)
    row.updated_by = ctx.actor_id
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.directory.team.update",
        resource_type="directory_team",
        resource_id=row.team_id,
        trace_id=f"trace-directory-team-{row.team_id}",
    )
    db.commit()
    db.refresh(row)
    return row


@router.delete("/auth/directory/teams/{team_id}")
def delete_directory_team(
    team_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    require_mfa(ctx)

    row = db.query(DirectoryTeam).filter_by(team_id=team_id.strip()).first()
    if not row:
        raise HTTPException(status_code=404, detail="Directory team not found")

    db.query(DirectoryTeamMembership).filter_by(team_id=row.team_id).delete()
    db.delete(row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.directory.team.delete",
        resource_type="directory_team",
        resource_id=team_id,
        trace_id=f"trace-directory-team-{team_id}",
    )
    db.commit()
    return {"deleted": True, "team_id": team_id}


@router.post("/auth/directory/groups/{group_id}/members/{user_id}", response_model=DirectoryGroupMembershipResponse)
def add_user_to_group(
    group_id: str,
    user_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    require_mfa(ctx)

    group = db.query(DirectoryGroup).filter_by(group_id=group_id.strip()).first()
    user = db.query(DirectoryUser).filter_by(user_id=user_id.strip()).first()
    if not group or not user:
        raise HTTPException(status_code=404, detail="Directory group or user not found")

    existing = db.query(DirectoryGroupMembership).filter_by(group_id=group.group_id, user_id=user.user_id).first()
    if existing:
        return existing

    row = DirectoryGroupMembership(
        membership_id=str(uuid4()),
        group_id=group.group_id,
        user_id=user.user_id,
        created_by=ctx.actor_id,
    )
    db.add(row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.directory.group.member.add",
        resource_type="directory_group",
        resource_id=group.group_id,
        trace_id=f"trace-directory-group-member-{row.membership_id}",
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/auth/directory/groups/{group_id}/members", response_model=list[DirectoryGroupMembershipResponse])
def list_group_memberships(
    group_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_OR_SECURITY_ROLES)

    group = db.query(DirectoryGroup).filter_by(group_id=group_id.strip()).first()
    if not group:
        raise HTTPException(status_code=404, detail="Directory group not found")
    return (
        db.query(DirectoryGroupMembership)
        .filter_by(group_id=group.group_id)
        .order_by(DirectoryGroupMembership.created_at.desc())
        .all()
    )


@router.delete("/auth/directory/groups/{group_id}/members/{user_id}")
def remove_user_from_group(
    group_id: str,
    user_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    require_mfa(ctx)

    row = (
        db.query(DirectoryGroupMembership)
        .filter_by(group_id=group_id.strip(), user_id=user_id.strip())
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Directory group membership not found")

    db.delete(row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.directory.group.member.remove",
        resource_type="directory_group",
        resource_id=group_id,
        trace_id=f"trace-directory-group-member-remove-{group_id}-{user_id}",
    )
    db.commit()
    return {"deleted": True, "group_id": group_id, "user_id": user_id}


@router.post("/auth/directory/teams/{team_id}/members/{user_id}", response_model=DirectoryTeamMembershipResponse)
def add_user_to_team(
    team_id: str,
    user_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    require_mfa(ctx)

    team = db.query(DirectoryTeam).filter_by(team_id=team_id.strip()).first()
    user = db.query(DirectoryUser).filter_by(user_id=user_id.strip()).first()
    if not team or not user:
        raise HTTPException(status_code=404, detail="Directory team or user not found")

    existing = db.query(DirectoryTeamMembership).filter_by(team_id=team.team_id, user_id=user.user_id).first()
    if existing:
        return existing

    row = DirectoryTeamMembership(
        membership_id=str(uuid4()),
        team_id=team.team_id,
        user_id=user.user_id,
        created_by=ctx.actor_id,
    )
    db.add(row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.directory.team.member.add",
        resource_type="directory_team",
        resource_id=team.team_id,
        trace_id=f"trace-directory-team-member-{row.membership_id}",
    )
    db.commit()
    db.refresh(row)
    return row


@router.get("/auth/directory/teams/{team_id}/members", response_model=list[DirectoryTeamMembershipResponse])
def list_team_memberships(
    team_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_OR_SECURITY_ROLES)

    team = db.query(DirectoryTeam).filter_by(team_id=team_id.strip()).first()
    if not team:
        raise HTTPException(status_code=404, detail="Directory team not found")
    return (
        db.query(DirectoryTeamMembership)
        .filter_by(team_id=team.team_id)
        .order_by(DirectoryTeamMembership.created_at.desc())
        .all()
    )


@router.delete("/auth/directory/teams/{team_id}/members/{user_id}")
def remove_user_from_team(
    team_id: str,
    user_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    require_mfa(ctx)

    row = (
        db.query(DirectoryTeamMembership)
        .filter_by(team_id=team_id.strip(), user_id=user_id.strip())
        .first()
    )
    if not row:
        raise HTTPException(status_code=404, detail="Directory team membership not found")

    db.delete(row)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.directory.team.member.remove",
        resource_type="directory_team",
        resource_id=team_id,
        trace_id=f"trace-directory-team-member-remove-{team_id}-{user_id}",
    )
    db.commit()
    return {"deleted": True, "team_id": team_id, "user_id": user_id}
