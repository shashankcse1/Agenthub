from __future__ import annotations

import json
from datetime import datetime, timedelta
from typing import Any, Optional
from uuid import uuid4

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import (
    GatewayEntitlement,
    OrchestrationFlowAccessCertification,
    OrchestrationFlowApprovalEvent,
    OrchestrationFlowDefinition,
    OrchestrationJitAccessRequest,
)
from app.policy_constants import ROLE_MASTER_ADMIN, ROLE_PLATFORM_ADMIN, ROLE_SUPER_ADMIN
from app.runtime_constants import RUNTIME_CONFIG_ORCHESTRATION_PROD_RUN_REQUIRES_ACCESS_CERTIFICATION
from app.security import ActorContext, require_dual_approval
from app.services.orchestration_access import (
    FLOW_ACCESS_ACTION_APPROVE,
    FLOW_ACCESS_ACTION_MANAGE,
    FLOW_ACCESS_ACTION_RUN,
    actor_matches_approver_policy,
    actor_matches_scope_spec,
    parse_access_policy,
    platform_bypasses_flow_scope,
    resolve_actor_directory_scope,
    validate_access_policy,
)
from app.services.runtime_config import get_runtime_config

DEFAULT_SOD_RULES_PROD: dict[str, bool] = {
    "prevent_self_approval": True,
    "prevent_creator_as_approver": True,
    "prevent_runner_as_approver_prod": True,
    "prevent_owner_as_sole_approver": True,
    "require_dual_approval_prod": True,
}

DEFAULT_RECERTIFY_INTERVAL_DAYS = 90

ORCHESTRATION_ENTITLEMENT_ACTIONS = {
    FLOW_ACCESS_ACTION_RUN: "orchestration.run",
    FLOW_ACCESS_ACTION_APPROVE: "orchestration.approve",
    FLOW_ACCESS_ACTION_MANAGE: "orchestration.manage",
}


def get_iga_config(policy: dict[str, Any]) -> dict[str, Any]:
    block = policy.get("iga")
    return block if isinstance(block, dict) else {}


def get_sod_rules(policy: dict[str, Any], environment: str) -> dict[str, bool]:
    iga = get_iga_config(policy)
    sod = iga.get("sod") if isinstance(iga.get("sod"), dict) else {}
    env = str(environment or "dev").strip().lower()
    if env == "prod":
        merged = dict(DEFAULT_SOD_RULES_PROD)
        for key, value in sod.items():
            if key in DEFAULT_SOD_RULES_PROD:
                merged[key] = bool(value)
        return merged
    return {key: bool(value) for key, value in sod.items()}


def get_recertify_interval_days(policy: dict[str, Any]) -> int:
    iga = get_iga_config(policy)
    certification = iga.get("certification") if isinstance(iga.get("certification"), dict) else {}
    raw = certification.get("recertify_interval_days", DEFAULT_RECERTIFY_INTERVAL_DAYS)
    try:
        return max(1, int(raw))
    except (TypeError, ValueError):
        return DEFAULT_RECERTIFY_INTERVAL_DAYS


def is_staged_approvers(policy: dict[str, Any]) -> bool:
    approvers = policy.get("approvers") if isinstance(policy.get("approvers"), dict) else {}
    mode = str(approvers.get("mode") or "simple").strip().lower()
    return mode == "staged"


def get_approval_stages(policy: dict[str, Any]) -> list[dict[str, Any]]:
    approvers = policy.get("approvers") if isinstance(policy.get("approvers"), dict) else {}
    if not is_staged_approvers(policy):
        return []
    stages = approvers.get("stages")
    if not isinstance(stages, list):
        return []
    result: list[dict[str, Any]] = []
    for index, stage in enumerate(stages):
        if not isinstance(stage, dict):
            continue
        stage_id = str(stage.get("stage_id") or f"stage-{index + 1}").strip()
        if not stage_id:
            continue
        result.append(
            {
                "stage_id": stage_id,
                "label": str(stage.get("label") or stage_id).strip(),
                "match": str(stage.get("match") or "any").strip().lower(),
                "clauses": stage.get("clauses") if isinstance(stage.get("clauses"), list) else [],
            }
        )
    return result


def parse_approval_stage_state(raw: Optional[str]) -> dict[str, Any]:
    if not raw or not str(raw).strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def serialize_approval_stage_state(state: dict[str, Any]) -> str:
    return json.dumps(state, separators=(",", ":"))


def actor_matches_stage(
    scope: Any,
    stage: dict[str, Any],
    *,
    db: Session,
    ctx: ActorContext,
    flow: OrchestrationFlowDefinition,
) -> bool:
    clauses = stage.get("clauses") if isinstance(stage.get("clauses"), list) else []
    if not clauses:
        return True
    combination = str(stage.get("match") or "any").strip().lower()
    results = [
        actor_matches_scope_spec(scope, clause, db=db, ctx=ctx, flow=flow)
        for clause in clauses
        if isinstance(clause, dict)
    ]
    if not results:
        return True
    if combination == "all":
        return all(results)
    return any(results)


def _collect_approver_users(policy: dict[str, Any]) -> set[str]:
    users: set[str] = set()
    approvers = policy.get("approvers") if isinstance(policy.get("approvers"), dict) else {}
    if is_staged_approvers(policy):
        for stage in get_approval_stages(policy):
            for clause in stage.get("clauses") or []:
                if isinstance(clause, dict):
                    users.update(str(item).strip() for item in (clause.get("users") or []) if str(item).strip())
        return users
    clauses = approvers.get("clauses") if isinstance(approvers.get("clauses"), list) else []
    if clauses:
        for clause in clauses:
            if isinstance(clause, dict):
                users.update(str(item).strip() for item in (clause.get("users") or []) if str(item).strip())
    else:
        users.update(str(item).strip() for item in (approvers.get("users") or []) if str(item).strip())
    return users


def _owner_users(policy: dict[str, Any]) -> set[str]:
    owners = policy.get("owners") if isinstance(policy.get("owners"), dict) else {}
    return {str(item).strip() for item in (owners.get("users") or []) if str(item).strip()}


def _runner_users(policy: dict[str, Any]) -> set[str]:
    runners = policy.get("runners") if isinstance(policy.get("runners"), dict) else {}
    return {str(item).strip() for item in (runners.get("users") or []) if str(item).strip()}


def validate_staged_approvers(policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if not is_staged_approvers(policy):
        return errors
    stages = get_approval_stages(policy)
    if not stages:
        errors.append("access_policy.approvers.stages must contain at least one stage when mode=staged")
        return errors
    seen: set[str] = set()
    for index, stage in enumerate(stages):
        if stage["stage_id"] in seen:
            errors.append(f"access_policy.approvers.stages[{index}].stage_id must be unique")
        seen.add(stage["stage_id"])
        if stage["match"] not in {"any", "all"}:
            errors.append(f"access_policy.approvers.stages[{index}].match must be any or all")
        for clause_index, clause in enumerate(stage.get("clauses") or []):
            if not isinstance(clause, dict):
                errors.append(f"access_policy.approvers.stages[{index}].clauses[{clause_index}] must be an object")
    return errors


def validate_iga_policy(policy: dict[str, Any], flow_environment: str, created_by: str) -> list[str]:
    errors: list[str] = []
    iga = get_iga_config(policy)
    if iga:
        sod = iga.get("sod")
        if sod is not None and not isinstance(sod, dict):
            errors.append("access_policy.iga.sod must be an object")
        certification = iga.get("certification")
        if certification is not None and not isinstance(certification, dict):
            errors.append("access_policy.iga.certification must be an object")
        entitlement_id = iga.get("entitlement_id")
        if entitlement_id is not None and not str(entitlement_id).strip():
            errors.append("access_policy.iga.entitlement_id must be a non-empty string when set")

    errors.extend(validate_staged_approvers(policy))

    env = str(flow_environment or "dev").strip().lower()
    sod_rules = get_sod_rules(policy, env)
    if env == "prod" and sod_rules.get("prevent_owner_as_sole_approver"):
        owner_users = _owner_users(policy)
        approver_users = _collect_approver_users(policy)
        if owner_users and approver_users and owner_users == approver_users:
            errors.append(
                "access_policy.approvers: flow owner cannot be the sole approver in production (SoD prevent_owner_as_sole_approver)"
            )
        if owner_users and len(approver_users) == 1 and next(iter(approver_users)) in owner_users:
            errors.append(
                "access_policy.approvers: flow owner cannot be the sole approver in production (SoD prevent_owner_as_sole_approver)"
            )

    if is_staged_approvers(policy) and env == "prod" and sod_rules.get("prevent_owner_as_sole_approver"):
        for stage in get_approval_stages(policy):
            stage_users: set[str] = set()
            for clause in stage.get("clauses") or []:
                if isinstance(clause, dict):
                    stage_users.update(str(item).strip() for item in (clause.get("users") or []) if str(item).strip())
            owner_users = _owner_users(policy)
            if owner_users and stage_users and owner_users == stage_users:
                errors.append(
                    f"access_policy.approvers.stages[{stage['stage_id']}]: owner cannot be sole approver in production"
                )

    if created_by and env == "prod" and sod_rules.get("prevent_creator_as_approver"):
        approver_users = _collect_approver_users(policy)
        if str(created_by).strip() in approver_users and len(approver_users) <= 1:
            errors.append("access_policy.approvers: flow creator cannot be sole approver in production")

    return errors


def validate_access_policy_with_iga(
    policy: dict[str, Any],
    *,
    flow_environment: str = "dev",
    created_by: str = "",
) -> list[str]:
    errors = validate_access_policy(policy)
    errors.extend(validate_iga_policy(policy, flow_environment, created_by))
    return errors


def enforce_sod_on_approve(
    db: Session,
    ctx: ActorContext,
    flow: OrchestrationFlowDefinition,
    *,
    stage_id: Optional[str] = None,
) -> None:
    if platform_bypasses_flow_scope(ctx):
        return

    policy = parse_access_policy(getattr(flow, "access_policy_json", None))
    sod_rules = get_sod_rules(policy, flow.environment)

    if sod_rules.get("prevent_self_approval") and ctx.approver_id and ctx.approver_id == ctx.actor_id:
        _raise_sod_violation("prevent_self_approval", "Approver must differ from actor.")

    if sod_rules.get("prevent_creator_as_approver") and ctx.actor_id == str(flow.created_by or "").strip():
        _raise_sod_violation("prevent_creator_as_approver", "Flow creator cannot approve promotion.")

    if (
        str(flow.environment or "").strip().lower() == "prod"
        and sod_rules.get("prevent_runner_as_approver_prod")
        and ctx.actor_id in _runner_users(policy)
    ):
        _raise_sod_violation("prevent_runner_as_approver_prod", "Runners cannot approve production flows.")

    if (
        str(flow.environment or "").strip().lower() == "prod"
        and sod_rules.get("require_dual_approval_prod")
    ):
        require_dual_approval(ctx, required_approver_role=ROLE_PLATFORM_ADMIN)


def _raise_sod_violation(rule: str, message: str) -> None:
    raise HTTPException(
        status_code=403,
        detail={
            "error_code": "AUTHZ_IGA_SOD_VIOLATION",
            "message": message,
            "sod_rule": rule,
            "policy_version": "v1",
            "decision_trace_id": "orchestration-iga-sod",
            "remediation_hint": "Use a different approver identity or update access_policy.iga.sod configuration.",
        },
    )


def prod_run_requires_access_certification(db: Session) -> bool:
    raw = get_runtime_config(
        db,
        RUNTIME_CONFIG_ORCHESTRATION_PROD_RUN_REQUIRES_ACCESS_CERTIFICATION,
        "true",
    ).strip().lower()
    return raw not in {"0", "false", "no"}


def get_active_certification(db: Session, flow_id: str) -> Optional[OrchestrationFlowAccessCertification]:
    now = datetime.utcnow()
    return (
        db.query(OrchestrationFlowAccessCertification)
        .filter_by(flow_id=flow_id, status="active")
        .filter(OrchestrationFlowAccessCertification.next_due_at > now)
        .order_by(OrchestrationFlowAccessCertification.certified_at.desc())
        .first()
    )


def check_certification_current(db: Session, flow: OrchestrationFlowDefinition) -> bool:
    return get_active_certification(db, flow.flow_id) is not None


def get_active_jit_grant(
    db: Session,
    *,
    flow_id: str,
    actor_id: str,
    action: str,
) -> Optional[OrchestrationJitAccessRequest]:
    now = datetime.utcnow()
    normalized_action = str(action or "").strip().lower()
    return (
        db.query(OrchestrationJitAccessRequest)
        .filter_by(flow_id=flow_id, requester_id=actor_id, requested_action=normalized_action, status="approved")
        .filter(OrchestrationJitAccessRequest.expires_at.isnot(None))
        .filter(OrchestrationJitAccessRequest.expires_at > now)
        .order_by(OrchestrationJitAccessRequest.expires_at.desc())
        .first()
    )


def list_active_jit_grants(db: Session, flow_id: str) -> list[OrchestrationJitAccessRequest]:
    now = datetime.utcnow()
    return (
        db.query(OrchestrationJitAccessRequest)
        .filter_by(flow_id=flow_id, status="approved")
        .filter(OrchestrationJitAccessRequest.expires_at.isnot(None))
        .filter(OrchestrationJitAccessRequest.expires_at > now)
        .order_by(OrchestrationJitAccessRequest.expires_at.asc())
        .all()
    )


def _parse_entitlement_allowed_roles(raw: str) -> list[str]:
    try:
        parsed = json.loads(raw or "[]")
    except json.JSONDecodeError:
        return []
    if not isinstance(parsed, list):
        return []
    return [str(item).strip() for item in parsed if str(item).strip()]


def check_orchestration_entitlement(
    db: Session,
    ctx: ActorContext,
    flow: OrchestrationFlowDefinition,
    action: str,
) -> tuple[bool, Optional[str], Optional[str]]:
    policy = parse_access_policy(getattr(flow, "access_policy_json", None))
    iga = get_iga_config(policy)
    entitlement_id = str(iga.get("entitlement_id") or "").strip()
    if not entitlement_id:
        return True, None, None

    entitlement_action = ORCHESTRATION_ENTITLEMENT_ACTIONS.get(action)
    if not entitlement_action:
        return True, entitlement_id, None

    row = db.query(GatewayEntitlement).filter_by(entitlement_id=entitlement_id).first()
    if row is None or not row.enabled:
        return False, entitlement_id, "entitlement_missing_or_disabled"

    if str(row.action or "").strip() != entitlement_action:
        return False, entitlement_id, "entitlement_action_mismatch"

    env = str(flow.environment or "dev").strip().lower()
    if str(row.environment or "dev").strip().lower() not in {env, "*"}:
        return False, entitlement_id, "entitlement_environment_mismatch"

    if flow.tenant_id and row.tenant_id and str(row.tenant_id).strip() not in {str(flow.tenant_id).strip(), "*"}:
        return False, entitlement_id, "entitlement_tenant_mismatch"

    allowed_roles = _parse_entitlement_allowed_roles(row.allowed_roles)
    if allowed_roles and ctx.actor_role not in allowed_roles:
        if ctx.actor_role not in {ROLE_MASTER_ADMIN, ROLE_SUPER_ADMIN, ROLE_PLATFORM_ADMIN}:
            return False, entitlement_id, "entitlement_role_not_allowed"

    return True, entitlement_id, None


def enforce_orchestration_entitlement(
    db: Session,
    ctx: ActorContext,
    flow: OrchestrationFlowDefinition,
    action: str,
) -> None:
    if platform_bypasses_flow_scope(ctx):
        return
    ok, entitlement_id, reason = check_orchestration_entitlement(db, ctx, flow, action)
    if ok:
        return
    raise HTTPException(
        status_code=403,
        detail={
            "error_code": "AUTHZ_IGA_ENTITLEMENT_REQUIRED",
            "message": "Configured gateway entitlement is not satisfied for this action.",
            "entitlement_id": entitlement_id,
            "reason": reason,
            "required_action": action,
            "flow_id": flow.flow_id,
            "decision_trace_id": "orchestration-iga-entitlement",
            "remediation_hint": "Link a valid enabled GatewayEntitlement or remove access_policy.iga.entitlement_id.",
        },
    )


def record_approval_event(
    db: Session,
    *,
    flow_id: str,
    event_type: str,
    action: str,
    state_from: str,
    state_to: str,
    ctx: ActorContext,
    decision: str,
    stage_id: Optional[str] = None,
    reason_code: Optional[str] = None,
    ticket_ref: Optional[str] = None,
) -> OrchestrationFlowApprovalEvent:
    row = OrchestrationFlowApprovalEvent(
        approval_event_id=f"orch-appr-{uuid4().hex[:16]}",
        flow_id=flow_id,
        event_type=event_type,
        stage_id=stage_id,
        action=action,
        state_from=state_from,
        state_to=state_to,
        actor_id=ctx.actor_id,
        actor_role=ctx.actor_role,
        approver_id=ctx.approver_id,
        decision=decision,
        reason_code=reason_code,
        ticket_ref=ticket_ref,
        occurred_at=datetime.utcnow(),
    )
    db.add(row)
    return row


def evaluate_staged_approval_outcome(
    policy: dict[str, Any],
    stage_state: dict[str, Any],
) -> Optional[str]:
    stages = get_approval_stages(policy)
    if not stages:
        return None
    approvers = policy.get("approvers") if isinstance(policy.get("approvers"), dict) else {}
    require_all = bool(approvers.get("require_all_stages", True))

    statuses = []
    for stage in stages:
        entry = stage_state.get(stage["stage_id"]) if isinstance(stage_state.get(stage["stage_id"]), dict) else {}
        statuses.append(str(entry.get("status") or "pending").strip().lower())

    if any(status == "rejected" for status in statuses):
        return "rejected"
    if require_all and all(status == "approved" for status in statuses):
        return "approved"
    if not require_all and any(status == "approved" for status in statuses):
        return "approved"
    return None


def apply_stage_approval_decision(
    *,
    policy: dict[str, Any],
    stage_state: dict[str, Any],
    stage_id: str,
    decision: str,
    ctx: ActorContext,
) -> dict[str, Any]:
    normalized = str(decision or "approved").strip().lower()
    status = "approved" if normalized == "approved" else "rejected"
    stage_state[str(stage_id).strip()] = {
        "status": status,
        "decided_by": ctx.actor_id,
        "decided_at": datetime.utcnow().isoformat(),
        "approver_id": ctx.approver_id or ctx.actor_id,
    }
    return stage_state


def build_sod_status(policy: dict[str, Any], environment: str) -> dict[str, Any]:
    rules = get_sod_rules(policy, environment)
    return {
        "environment": environment,
        "rules": rules,
        "defaults_enforced_in_prod": str(environment).strip().lower() == "prod",
    }


def build_certification_status(db: Session, flow: OrchestrationFlowDefinition, policy: dict[str, Any]) -> dict[str, Any]:
    active = get_active_certification(db, flow.flow_id)
    interval_days = get_recertify_interval_days(policy)
    latest = (
        db.query(OrchestrationFlowAccessCertification)
        .filter_by(flow_id=flow.flow_id)
        .order_by(OrchestrationFlowAccessCertification.certified_at.desc())
        .first()
    )
    return {
        "current": active is not None,
        "certification_id": active.certification_id if active else None,
        "certified_at": active.certified_at.isoformat() if active and active.certified_at else None,
        "next_due_at": active.next_due_at.isoformat() if active and active.next_due_at else None,
        "recertify_interval_days": interval_days,
        "last_certification_status": latest.status if latest else None,
        "never_certified": latest is None,
    }


def build_iga_posture(db: Session, ctx: ActorContext, flow: OrchestrationFlowDefinition) -> dict[str, Any]:
    policy = parse_access_policy(getattr(flow, "access_policy_json", None))
    entitlement_ok, entitlement_id, entitlement_reason = check_orchestration_entitlement(
        db, ctx, flow, FLOW_ACCESS_ACTION_RUN
    )
    stage_state = parse_approval_stage_state(getattr(flow, "approval_stage_state_json", None))
    return {
        "flow_id": flow.flow_id,
        "environment": flow.environment,
        "approval_status": flow.approval_status,
        "policy_version": policy.get("version", 1),
        "sod": build_sod_status(policy, flow.environment),
        "certification": build_certification_status(db, flow, policy),
        "staged_approval": {
            "mode": "staged" if is_staged_approvers(policy) else "simple",
            "stages": get_approval_stages(policy),
            "state": stage_state,
        },
        "active_jit_grants": [
            {
                "request_id": grant.request_id,
                "requester_id": grant.requester_id,
                "requested_action": grant.requested_action,
                "expires_at": grant.expires_at.isoformat() if grant.expires_at else None,
            }
            for grant in list_active_jit_grants(db, flow.flow_id)
        ],
        "entitlement": {
            "configured": bool(entitlement_id),
            "entitlement_id": entitlement_id,
            "satisfied": entitlement_ok,
            "reason": entitlement_reason,
        },
    }


def explain_orchestration_access(
    db: Session,
    ctx: ActorContext,
    flow: OrchestrationFlowDefinition,
    action: str,
) -> dict[str, Any]:
    policy = parse_access_policy(getattr(flow, "access_policy_json", None))
    factors: list[dict[str, Any]] = []
    allowed = False
    decision = "deny"
    error_code: Optional[str] = None

    if platform_bypasses_flow_scope(ctx):
        factors.append({"factor": "platform_bypass", "result": "allow"})
        allowed = True
        decision = "allow"
    else:
        scope = resolve_actor_directory_scope(db, ctx.actor_id)
        try:
            from app.services.orchestration_access import enforce_flow_access as _enforce

            _enforce(db, ctx, flow, action)
            allowed = True
            decision = "allow"
            factors.append({"factor": "access_policy", "result": "allow"})
        except HTTPException as exc:
            detail = exc.detail if isinstance(exc.detail, dict) else {"message": str(exc.detail)}
            error_code = detail.get("error_code")
            factors.append({"factor": "access_policy", "result": "deny", "error_code": error_code})

            jit_grant = get_active_jit_grant(db, flow_id=flow.flow_id, actor_id=ctx.actor_id, action=action)
            if jit_grant:
                allowed = True
                decision = "allow"
                factors.append(
                    {
                        "factor": "jit_grant",
                        "result": "allow",
                        "request_id": jit_grant.request_id,
                        "expires_at": jit_grant.expires_at.isoformat() if jit_grant.expires_at else None,
                    }
                )

    entitlement_ok, entitlement_id, entitlement_reason = check_orchestration_entitlement(db, ctx, flow, action)
    if entitlement_id:
        factors.append(
            {
                "factor": "entitlement",
                "result": "allow" if entitlement_ok else "deny",
                "entitlement_id": entitlement_id,
                "reason": entitlement_reason,
            }
        )
        if not entitlement_ok:
            allowed = False
            decision = "deny"
            error_code = "AUTHZ_IGA_ENTITLEMENT_REQUIRED"

    if (
        action == FLOW_ACCESS_ACTION_RUN
        and str(flow.environment or "").strip().lower() == "prod"
        and prod_run_requires_access_certification(db)
        and not platform_bypasses_flow_scope(ctx)
    ):
        cert_current = check_certification_current(db, flow)
        factors.append({"factor": "access_certification", "result": "allow" if cert_current else "deny"})
        if not cert_current:
            allowed = False
            decision = "deny"
            error_code = "AUTHZ_IGA_CERTIFICATION_EXPIRED"

    sod_rules = get_sod_rules(policy, flow.environment)
    if action == FLOW_ACCESS_ACTION_APPROVE and sod_rules.get("require_dual_approval_prod"):
        factors.append(
            {
                "factor": "dual_approval_required",
                "result": "info",
                "required_in_prod": str(flow.environment).strip().lower() == "prod",
            }
        )

    return {
        "flow_id": flow.flow_id,
        "action": action,
        "decision": decision,
        "allowed": allowed,
        "error_code": error_code,
        "factors": factors,
        "policy_version": policy.get("version", 1),
        "decision_trace_id": "orchestration-iga-explain",
    }


def flows_due_for_recertification(db: Session, *, limit: int = 100) -> list[dict[str, Any]]:
    now = datetime.utcnow()
    flows = db.query(OrchestrationFlowDefinition).filter(OrchestrationFlowDefinition.status != "deprecated").all()
    due: list[dict[str, Any]] = []
    for flow in flows:
        policy = parse_access_policy(getattr(flow, "access_policy_json", None))
        active = get_active_certification(db, flow.flow_id)
        if active is None:
            latest = (
                db.query(OrchestrationFlowAccessCertification)
                .filter_by(flow_id=flow.flow_id)
                .order_by(OrchestrationFlowAccessCertification.certified_at.desc())
                .first()
            )
            due.append(
                {
                    "flow_id": flow.flow_id,
                    "flow_name": flow.flow_name,
                    "environment": flow.environment,
                    "reason": "never_certified" if latest is None else "expired",
                    "next_due_at": latest.next_due_at.isoformat() if latest and latest.next_due_at else None,
                    "recertify_interval_days": get_recertify_interval_days(policy),
                }
            )
        if len(due) >= limit:
            break
    return due[:limit]


def supersede_prior_certifications(db: Session, flow_id: str) -> None:
    rows = db.query(OrchestrationFlowAccessCertification).filter_by(flow_id=flow_id, status="active").all()
    for row in rows:
        row.status = "superseded"


def compute_next_due_at(policy: dict[str, Any], *, from_time: Optional[datetime] = None) -> datetime:
    base = from_time or datetime.utcnow()
    return base + timedelta(days=get_recertify_interval_days(policy))
