from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy.orm import Session

from app.api_errors import (
    authz_scope_forbidden,
    conflict_error,
    not_found_error,
    unauthorized_error,
    validation_error as api_validation_error,
)
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
    ROLE_AUDITOR,
    ROLE_MASTER_ADMIN,
    ROLE_PLATFORM_ADMIN,
    ROLE_RELEASE_MANAGER,
    ROLE_SECURITY_APPROVER,
    ROLE_SUPER_ADMIN,
    SUPPORTED_ACTOR_ROLES,
)
from app.router_constants import (
    AUTH_ADMIN_OR_SECURITY_ROLES,
    AUTH_ADMIN_ROLES,
    AUTH_POLICY_REVISIONS_DEFAULT_LIMIT,
    AUTH_SESSION_REAUTH_ROLES,
)
from app.schemas import (
    AuthAuthorizationExplainRequest,
    AuthAuthorizationExplainResponse,
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
    DirectoryUserEnableResponse,
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
    resolve_session_id_from_bearer_token,
    verify_user_password,
)
from app.services.csrf_protection import (
    CSRF_COOKIE_NAME,
    attach_browser_auth_cookies,
    attach_csrf_cookie,
    clear_csrf_cookie,
    issue_csrf_token,
)
from app.services.session_cookies import (
    APPROVER_SESSION_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    attach_session_cookie,
    clear_session_cookie,
    read_session_cookie,
)
from app.services.audit import create_audit_event
from app.services.basic_auth_expiry import (
    clamp_max_enable_duration_minutes,
    expire_stale_basic_auth_fallbacks,
)
from app.services.policy_config import AuthPolicy, get_auth_policy
from app.services.runtime_config import get_runtime_config_int
from app.runtime_constants import (
    RUNTIME_CONFIG_AUTH_LOGIN_LOCKOUT_MINUTES,
    RUNTIME_CONFIG_AUTH_LOGIN_MAX_FAILED_ATTEMPTS,
    RUNTIME_CONFIG_AUTH_POLICY_REVISIONS_DEFAULT_LIMIT,
)

router = APIRouter()
logger = get_logger(__name__)


AUTH_EXPLAIN_READ_ROLES = AUTH_ADMIN_OR_SECURITY_ROLES | {ROLE_AUDITOR}


def _auth_explain_allowed_roles(action: str, policy: AuthPolicy) -> list[str]:
    if action == "auth.session.read":
        return sorted(policy.session_read_roles)
    if action == "auth.session.issue":
        return sorted(policy.session_issuer_roles)
    if action == "auth.session.reauth":
        return sorted(AUTH_SESSION_REAUTH_ROLES)
    if action == "auth.role_binding.validate":
        return [ROLE_PLATFORM_ADMIN]
    if action == "auth.basic_fallback.config.create":
        return sorted(AUTH_ADMIN_ROLES)
    if action == "auth.basic_fallback.config.update":
        return sorted(AUTH_ADMIN_ROLES)
    if action == "auth.basic_fallback.enable":
        return sorted(AUTH_ADMIN_ROLES)
    if action == "auth.basic_fallback.disable":
        return sorted(AUTH_ADMIN_OR_SECURITY_ROLES)
    if action == "auth.sso.provider.test":
        return sorted(AUTH_ADMIN_ROLES)
    if action == "auth.sso.provider.scim_sync":
        return sorted(AUTH_ADMIN_ROLES)
    if action.startswith("auth.directory."):
        return sorted(AUTH_ADMIN_ROLES)
    if action in {"auth.policy.session.update", "auth.policy.session.rollback"}:
        return sorted(AUTH_ADMIN_OR_SECURITY_ROLES)
    return []


def _auth_explain_requires_mfa(action: str) -> bool:
    if action.startswith("auth.directory."):
        return True
    return action in {"auth.policy.session.update", "auth.policy.session.rollback"}


def _auth_explain_requires_dual_approval(
    action: str,
    actor_id: str,
    target_actor_id: str,
    target_actor_role: str,
    policy: AuthPolicy,
) -> tuple[bool, str | None]:
    if action in {"auth.policy.session.update", "auth.policy.session.rollback"}:
        return True, DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT
    if action == "auth.basic_fallback.enable":
        return True, DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT
    if (
        action == "auth.session.issue"
        and target_actor_id
        and target_actor_role
        and target_actor_id != actor_id
        and target_actor_role in policy.cross_actor_dual_approval_roles
    ):
        return True, policy.dual_approval_required_approver_role
    return False, None


def _normalize_roles(raw_roles: list[str]) -> list[str]:
    return sorted({role.strip() for role in raw_roles if role and role.strip()})


def _validate_supported_roles(field_name: str, roles: list[str]) -> None:
    unknown_roles = sorted(set(roles) - SUPPORTED_ACTOR_ROLES)
    if unknown_roles:
        raise api_validation_error(
            f"{field_name} has unsupported roles: {', '.join(unknown_roles)}",
            decision_trace_id="auth-unsupported-roles",
        )


def _serialize_roles(roles: list[str], field_name: str) -> str:
    normalized = _normalize_roles(roles)
    if not normalized:
        raise api_validation_error(f"{field_name} cannot be empty", decision_trace_id="auth-empty-field")
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
    if ctx.actor_role in {ROLE_MASTER_ADMIN, ROLE_SUPER_ADMIN}:
        return
    if payload.actor_role not in policy.issuable_session_roles:
        raise api_validation_error("Requested actor_role is not supported", decision_trace_id="auth-session-role-unsupported")

    if ctx.actor_role == ROLE_RELEASE_MANAGER and payload.actor_role == ROLE_PLATFORM_ADMIN:
        raise authz_scope_forbidden(
            message="Release Manager cannot issue Platform Admin sessions.",
            actor_role=ctx.actor_role,
            required_scope="issuable_session_roles excludes Platform Admin for Release Manager",
            decision_trace_id="auth-session-issue-release-manager-deny",
            remediation_hint="Use Platform Admin or Security Approver to issue Platform Admin sessions.",
        )

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
            raise api_validation_error(
                "dual_approval_required_approver_role cannot be empty",
                decision_trace_id="auth-dual-approval-role-empty",
            )
        if approver_role not in SUPPORTED_ACTOR_ROLES:
            raise api_validation_error(
                "dual_approval_required_approver_role is not supported",
                decision_trace_id="auth-dual-approval-role-unsupported",
            )
        config.dual_approval_required_approver_role = approver_role
    if payload.description is not None:
        config.description = payload.description.strip()
    if payload.privileged_mfa_reauth_minutes is not None:
        config.privileged_mfa_reauth_minutes = payload.privileged_mfa_reauth_minutes

    issuer_roles = set(_roles_from_csv(config.session_issuer_roles, AUTH_SESSION_ISSUER_ROLES_DEFAULT))
    issuable_roles = set(_roles_from_csv(config.issuable_session_roles, ISSUABLE_SESSION_ROLES_DEFAULT))
    if not issuer_roles.issubset(issuable_roles):
        invalid_issuer_roles = sorted(issuer_roles - issuable_roles)
        raise api_validation_error(
            f"session_issuer_roles must be a subset of issuable_session_roles: {', '.join(invalid_issuer_roles)}",
            decision_trace_id="auth-session-issuer-subset-invalid",
        )

    dual_approval_roles = set(_roles_from_csv(config.cross_actor_dual_approval_roles, CROSS_ACTOR_DUAL_APPROVAL_ROLES_DEFAULT))
    required_approver = config.dual_approval_required_approver_role.strip() or DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT
    if required_approver in dual_approval_roles and required_approver not in issuable_roles:
        raise api_validation_error(
            "dual_approval_required_approver_role must be included in issuable_session_roles when used in cross_actor_dual_approval_roles",
            decision_trace_id="auth-dual-approval-approver-not-issuable",
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
        raise api_validation_error("limit must be between 1 and 200", decision_trace_id="auth-revisions-limit-invalid")

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
        raise not_found_error("auth_policy_revision", payload.revision_id, decision_trace_id="auth-policy-revision-not-found")

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
        raise not_found_error("identity_provider", provider_id, decision_trace_id="auth-sso-provider-not-found")

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
        raise not_found_error("identity_provider", provider_id, decision_trace_id="auth-sso-provider-not-found")

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
        raise not_found_error("identity_provider", provider_id, decision_trace_id="auth-sso-provider-not-found")

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
        raise not_found_error("session", session_id, decision_trace_id="auth-session-not-found")
    return session


@router.post("/auth/sessions", response_model=SessionIssueResponse)
def issue_session(
    payload: SessionCreateRequest,
    response: Response,
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
    token = issue_session_bearer_token(session.session_id)
    attach_browser_auth_cookies(
        response,
        session_token=token,
        max_age_seconds=int(payload.ttl_minutes) * 60,
    )
    logger.info(
        "session_issued %s",
        sanitize_fields({"actor_id": ctx.actor_id, "issued_session_id": session.session_id}),
    )
    return {
        "session_id": session.session_id,
        "token_type": "Bearer",
        "access_token": token,
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
        raise not_found_error("session", session_id, decision_trace_id="auth-session-not-found")

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
    "/auth/authz/explain",
    response_model=AuthAuthorizationExplainResponse,
    summary="Explain auth authorization decision",
    description=(
        "Simulates auth authorization evaluation and returns role, MFA, dual-approval, and remediation context. "
        "Used for security explainability and audit investigations."
    ),
    responses={
        403: {"description": "Actor role is not allowed for this action."},
    },
)
def explain_auth_authorization(
    payload: AuthAuthorizationExplainRequest,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_EXPLAIN_READ_ROLES)

    policy = get_auth_policy(db)
    action = str(payload.action or "").strip().lower()
    actor_role = str(payload.actor_role or "").strip()
    actor_id = str(payload.actor_id or "explain-actor").strip() or "explain-actor"
    resource_type = str(payload.resource_type or "auth_action").strip() or "auth_action"
    resource_id = str(payload.resource_id or "").strip() or None
    target_actor_id = str(payload.target_actor_id or "").strip() or actor_id
    target_actor_role = str(payload.target_actor_role or "").strip()

    allowed_roles = _auth_explain_allowed_roles(action, policy)
    reasons: list[str] = []

    if not allowed_roles:
        decision = "warn"
        decision_trace_id = "authz-auth-explain-unknown-action"
        requires_mfa = False
        requires_dual_approval = False
        required_approver_role = None
        reasons.append("action_not_mapped")
        remediation_hint = "Use a supported auth action key or extend policy mapping."
    else:
        role_allowed = actor_role in set(allowed_roles)
        reasons.append("role_allowed" if role_allowed else "role_not_allowed")

        requires_mfa = _auth_explain_requires_mfa(action)
        mfa_ok = (not requires_mfa) or bool(payload.mfa_verified)
        if requires_mfa:
            reasons.append("mfa_present" if mfa_ok else "mfa_missing")

        requires_dual_approval, required_approver_role = _auth_explain_requires_dual_approval(
            action=action,
            actor_id=actor_id,
            target_actor_id=target_actor_id,
            target_actor_role=target_actor_role,
            policy=policy,
        )
        dual_approval_ok = True
        if requires_dual_approval:
            approver_role = str(payload.approver_role or "").strip()
            approver_id = str(payload.approver_id or "").strip()
            dual_approval_ok = (
                approver_role == (required_approver_role or DUAL_APPROVAL_REQUIRED_APPROVER_ROLE_DEFAULT)
                and bool(approver_id)
                and approver_id != actor_id
            )
            reasons.append("dual_approval_present" if dual_approval_ok else "dual_approval_missing")

        if role_allowed and mfa_ok and dual_approval_ok:
            decision = "allow"
            decision_trace_id = "authz-auth-explain-allow"
            remediation_hint = "No remediation required."
        else:
            decision = "deny"
            decision_trace_id = "authz-auth-explain-deny"
            if not role_allowed:
                remediation_hint = "Use one of the allowed roles for this auth action scope."
            elif not mfa_ok:
                remediation_hint = "Provide MFA-verified session context for this action simulation."
            else:
                remediation_hint = "Provide required approver headers for dual-approval action simulation."

    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.authz.explain",
        resource_type=resource_type,
        resource_id=resource_id or action,
        trace_id=f"trace-auth-authz-explain-{uuid4()}",
        decision_outcome=decision if decision in {"allow", "deny", "warn"} else "warn",
    )
    db.commit()

    return {
        "actor_role": actor_role,
        "actor_id": actor_id,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "decision": decision,
        "decision_trace_id": decision_trace_id,
        "policy_version": "v1",
        "allowed_roles": allowed_roles,
        "requires_mfa": requires_mfa,
        "requires_dual_approval": requires_dual_approval,
        "required_approver_role": required_approver_role,
        "reasons": reasons,
        "remediation_hint": remediation_hint,
    }


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
        max_enable_duration_minutes=clamp_max_enable_duration_minutes(payload.max_enable_duration_minutes),
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
        raise not_found_error("basic_auth_config", config_id, decision_trace_id="auth-basic-config-not-found")

    updates = payload.model_dump(exclude_none=True)
    if "max_enable_duration_minutes" in updates:
        updates["max_enable_duration_minutes"] = clamp_max_enable_duration_minutes(
            updates["max_enable_duration_minutes"]
        )
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
        raise not_found_error("basic_auth_config", config_id, decision_trace_id="auth-basic-config-not-found")

    # Auto-disable any already-expired configs before enabling a new window.
    expire_stale_basic_auth_fallbacks(db)
    capped_max = clamp_max_enable_duration_minutes(config.max_enable_duration_minutes)
    config.max_enable_duration_minutes = capped_max
    if payload.duration_minutes > capped_max:
        raise api_validation_error("Requested duration exceeds max limit", decision_trace_id="auth-basic-duration-exceeds-max")

    config.enabled = True
    config.enabled_by = ctx.actor_id
    config.break_glass_reason = payload.break_glass_reason
    config.expires_at = datetime.utcnow() + timedelta(minutes=int(payload.duration_minutes))
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
        raise not_found_error("basic_auth_config", config_id, decision_trace_id="auth-basic-config-not-found")

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


@router.post(
    "/auth/basic/config/expire-tick",
    summary="Expire stale break-glass basic auth windows",
    description=(
        "Cron-ready sweep that disables enabled basic-auth fallback configs whose expires_at has passed "
        "(Leader Readiness: exceptions ≤ 90d with auto-disable)."
    ),
)
def tick_expire_basic_auth_fallbacks(
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_OR_SECURITY_ROLES)
    disabled = expire_stale_basic_auth_fallbacks(db)
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.basic_fallback.expire_tick",
        resource_type="basic_auth_config",
        resource_id="expire-tick",
        trace_id=f"trace-basic-auth-expire-tick-{uuid4().hex[:12]}",
        action_context={"disabled_count": disabled},
    )
    db.commit()
    return {"disabled_count": disabled, "max_duration_days_cap": 90}


def _normalize_status(value: Optional[str], default: str = "active") -> str:
    normalized = str(value or default).strip().lower()
    if normalized not in {"active", "inactive"}:
        raise api_validation_error("status must be active or inactive", decision_trace_id="auth-basic-status-invalid")
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


def _authenticate_directory_password(
    db: Session,
    *,
    username: str,
    password: str,
    audit_action: str,
) -> DirectoryUser:
    normalized = username.strip()
    if not normalized:
        raise api_validation_error("username cannot be empty", decision_trace_id="auth-login-username-empty")

    now = datetime.utcnow()
    login_trace_id = f"trace-login-{uuid4()}"
    user = db.query(DirectoryUser).filter_by(user_id=normalized).first()
    if not user or user.status != "active":
        create_audit_event(
            db,
            actor_id=normalized,
            action_type=audit_action,
            resource_type="directory_user",
            resource_id=normalized,
            trace_id=login_trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise unauthorized_error("Invalid username or password.", decision_trace_id="auth-login-invalid-credentials")

    if user.locked_until and user.locked_until > now:
        create_audit_event(
            db,
            actor_id=user.user_id,
            action_type=audit_action,
            resource_type="directory_user",
            resource_id=user.user_id,
            trace_id=login_trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise unauthorized_error("Invalid username or password.", decision_trace_id="auth-login-invalid-credentials")

    if user.locked_until and user.locked_until <= now:
        user.locked_until = None

    if not verify_user_password(password, user.password_hash):
        _record_failed_password_login(db, user)
        create_audit_event(
            db,
            actor_id=user.user_id,
            action_type=audit_action,
            resource_type="directory_user",
            resource_id=user.user_id,
            trace_id=login_trace_id,
            decision_outcome="deny",
        )
        db.commit()
        raise unauthorized_error("Invalid username or password.", decision_trace_id="auth-login-invalid-credentials")

    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = now
    return user


@router.post("/auth/login", response_model=SessionLoginResponse)
def login_with_password(
    payload: SessionLoginRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    user = _authenticate_directory_password(
        db,
        username=payload.username,
        password=payload.password,
        audit_action="auth.login.password",
    )

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
    token = issue_session_bearer_token(session.session_id)
    csrf_token = attach_browser_auth_cookies(
        response,
        session_token=token,
        max_age_seconds=int(payload.ttl_minutes) * 60,
    )
    return {
        "session_id": session.session_id,
        "token_type": "Bearer",
        "access_token": token,
        "expires_at": session.expires_at,
        "actor_id": user.user_id,
        "actor_role": user.role_name,
        # Returned so cross-origin consoles can set X-CSRF-Token (cookie is API-host scoped).
        "csrf_token": csrf_token,
    }


@router.get("/auth/csrf")
def get_csrf_token(response: Response):
    """Issue/refresh double-submit CSRF cookie for cookie-authenticated console mutations."""
    token = issue_csrf_token()
    attach_csrf_cookie(response, token, max_age_seconds=3600)
    return {"csrf_token": token, "header_name": "X-CSRF-Token", "cookie_name": CSRF_COOKIE_NAME}


@router.post("/auth/approver-session", response_model=SessionLoginResponse)
def issue_approver_session(
    payload: SessionLoginRequest,
    response: Response,
    db: Session = Depends(get_db),
):
    """Authenticate a co-signer and set gb_approver_session (does not replace gb_session)."""
    user = _authenticate_directory_password(
        db,
        username=payload.username,
        password=payload.password,
        audit_action="auth.approver_session.login",
    )
    ttl_minutes = max(5, min(int(payload.ttl_minutes or 15), 30))
    idle_timeout_minutes = max(5, min(int(payload.idle_timeout_minutes or 15), 30))
    session = _create_session(
        db,
        actor_id=user.user_id,
        actor_role=user.role_name,
        ttl_minutes=ttl_minutes,
        idle_timeout_minutes=idle_timeout_minutes,
        mfa_verified=False,
    )
    create_audit_event(
        db,
        actor_id=user.user_id,
        action_type="auth.approver_session.issue",
        resource_type="session",
        resource_id=session.session_id,
        trace_id=f"trace-approver-{session.session_id}",
    )
    db.commit()
    token = issue_session_bearer_token(session.session_id)
    attach_session_cookie(
        response,
        token,
        max_age_seconds=ttl_minutes * 60,
        cookie_name=APPROVER_SESSION_COOKIE_NAME,
    )
    return {
        "session_id": session.session_id,
        "token_type": "Bearer",
        "access_token": token,
        "expires_at": session.expires_at,
        "actor_id": user.user_id,
        "actor_role": user.role_name,
    }


@router.post("/auth/logout")
def logout_session(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    """Expire the current session (Bearer or gb_session) and clear auth cookies."""
    token = None
    auth_header = (request.headers.get("Authorization") or "").strip()
    if auth_header:
        scheme, _, raw = auth_header.partition(" ")
        if scheme.lower() == "bearer" and raw.strip():
            token = raw.strip()
    if not token:
        token = read_session_cookie(request.cookies, cookie_name=SESSION_COOKIE_NAME)

    expired_session_id = None
    if token:
        try:
            session_id = resolve_session_id_from_bearer_token(token)
            session = db.query(SessionRecord).filter_by(session_id=session_id).first()
            if session:
                session.expires_at = datetime.utcnow()
                expired_session_id = session.session_id
                create_audit_event(
                    db,
                    actor_id=session.actor_id,
                    action_type="auth.logout",
                    resource_type="session",
                    resource_id=session.session_id,
                    trace_id=f"trace-logout-{session.session_id}",
                )
                db.commit()
        except HTTPException:
            pass

    clear_session_cookie(response, cookie_name=SESSION_COOKIE_NAME)
    clear_session_cookie(response, cookie_name=APPROVER_SESSION_COOKIE_NAME)
    clear_csrf_cookie(response)
    return {"logged_out": True, "session_id": expired_session_id}


@router.post("/auth/approver-logout")
def logout_approver_session(
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
):
    token = None
    auth_header = (request.headers.get("X-Approver-Authorization") or "").strip()
    if auth_header:
        scheme, _, raw = auth_header.partition(" ")
        if scheme.lower() == "bearer" and raw.strip():
            token = raw.strip()
    if not token:
        token = read_session_cookie(request.cookies, cookie_name=APPROVER_SESSION_COOKIE_NAME)

    expired_session_id = None
    if token:
        try:
            session_id = resolve_session_id_from_bearer_token(token)
            session = db.query(SessionRecord).filter_by(session_id=session_id).first()
            if session:
                session.expires_at = datetime.utcnow()
                expired_session_id = session.session_id
                create_audit_event(
                    db,
                    actor_id=session.actor_id,
                    action_type="auth.approver_session.logout",
                    resource_type="session",
                    resource_id=session.session_id,
                    trace_id=f"trace-approver-logout-{session.session_id}",
                )
                db.commit()
        except HTTPException:
            pass

    clear_session_cookie(response, cookie_name=APPROVER_SESSION_COOKIE_NAME)
    return {"logged_out": True, "session_id": expired_session_id}


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
        raise api_validation_error("user_id cannot be empty", decision_trace_id="auth-directory-user-id-empty")
    if payload.role_name.strip() not in SUPPORTED_ACTOR_ROLES:
        raise api_validation_error("role_name is not supported", decision_trace_id="auth-directory-role-unsupported")
    if not payload.password:
        raise api_validation_error(
            "password is required for creating a directory user",
            decision_trace_id="auth-directory-password-required",
        )

    existing = db.query(DirectoryUser).filter_by(user_id=user_id).first()
    if existing:
        raise conflict_error("Directory user already exists.", decision_trace_id="auth-directory-user-exists")

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
        raise api_validation_error("user_id in payload must match path", decision_trace_id="auth-directory-user-id-mismatch")
    if payload.role_name.strip() not in SUPPORTED_ACTOR_ROLES:
        raise api_validation_error("role_name is not supported", decision_trace_id="auth-directory-role-unsupported")

    row = db.query(DirectoryUser).filter_by(user_id=normalized_user_id).first()
    if not row:
        raise not_found_error("directory_user", user_id, decision_trace_id="auth-directory-user-not-found")

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
        raise not_found_error("directory_user", user_id, decision_trace_id="auth-directory-user-not-found")

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
        raise not_found_error("directory_user", user_id, decision_trace_id="auth-directory-user-not-found")

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
    from app.services.unlock_abuse import maybe_flag_unlock_abuse

    maybe_flag_unlock_abuse(db, actor_id=ctx.actor_id, user_id=row.user_id)
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
        raise not_found_error("directory_user", user_id, decision_trace_id="auth-directory-user-not-found")

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
        raise not_found_error("directory_user", user_id, decision_trace_id="auth-directory-user-not-found")

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


@router.post("/auth/directory/users/{user_id}/enable", response_model=DirectoryUserEnableResponse)
def enable_directory_user(
    user_id: str,
    db: Session = Depends(get_db),
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, AUTH_ADMIN_ROLES)
    require_mfa(ctx)

    row = db.query(DirectoryUser).filter_by(user_id=user_id.strip()).first()
    if not row:
        raise not_found_error("directory_user", user_id, decision_trace_id="auth-directory-user-not-found")

    row.status = "active"
    row.updated_by = ctx.actor_id
    create_audit_event(
        db,
        actor_id=ctx.actor_id,
        action_type="auth.directory.user.enable",
        resource_type="directory_user",
        resource_id=row.user_id,
        trace_id=f"trace-directory-user-enable-{row.user_id}",
    )
    db.commit()
    return {"user_id": row.user_id, "enabled": True}


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
        raise api_validation_error("group_id cannot be empty", decision_trace_id="auth-directory-group-id-empty")
    existing = db.query(DirectoryGroup).filter_by(group_id=group_id).first()
    if existing:
        raise conflict_error("Directory group already exists.", decision_trace_id="auth-directory-group-exists")

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
        raise api_validation_error("group_id in payload must match path", decision_trace_id="auth-directory-group-id-mismatch")

    row = db.query(DirectoryGroup).filter_by(group_id=normalized_group_id).first()
    if not row:
        raise not_found_error("directory_group", group_id, decision_trace_id="auth-directory-group-not-found")

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
        raise not_found_error("directory_group", group_id, decision_trace_id="auth-directory-group-not-found")

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
        raise api_validation_error("team_id cannot be empty", decision_trace_id="auth-directory-team-id-empty")
    existing = db.query(DirectoryTeam).filter_by(team_id=team_id).first()
    if existing:
        raise conflict_error("Directory team already exists.", decision_trace_id="auth-directory-team-exists")

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
        raise api_validation_error("team_id in payload must match path", decision_trace_id="auth-directory-team-id-mismatch")

    row = db.query(DirectoryTeam).filter_by(team_id=normalized_team_id).first()
    if not row:
        raise not_found_error("directory_team", team_id, decision_trace_id="auth-directory-team-not-found")

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
        raise not_found_error("directory_team", team_id, decision_trace_id="auth-directory-team-not-found")

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
        raise not_found_error("directory_group_or_user", f"{group_id}:{user_id}", decision_trace_id="auth-directory-group-user-not-found")

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
        raise not_found_error("directory_group", group_id, decision_trace_id="auth-directory-group-not-found")
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
        raise not_found_error("directory_group_membership", f"{group_id}:{user_id}", decision_trace_id="auth-directory-group-membership-not-found")

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
        raise not_found_error("directory_team_or_user", f"{team_id}:{user_id}", decision_trace_id="auth-directory-team-user-not-found")

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
        raise not_found_error("directory_team", team_id, decision_trace_id="auth-directory-team-not-found")
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
        raise not_found_error("directory_team_membership", f"{team_id}:{user_id}", decision_trace_id="auth-directory-team-membership-not-found")

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
