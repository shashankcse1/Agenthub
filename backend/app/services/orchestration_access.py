from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import DirectoryGroupMembership, DirectoryTeamMembership, OrchestrationFlowDefinition
from app.policy_constants import ROLE_MASTER_ADMIN, ROLE_PLATFORM_ADMIN, ROLE_SUPER_ADMIN
from app.security import ActorContext
from app.services.orchestration_scope_resolver import ScopeResolveError, resolve_scope_spec, validate_resolve_from

FLOW_ACCESS_ACTION_MANAGE = "manage"
FLOW_ACCESS_ACTION_RUN = "run"
FLOW_ACCESS_ACTION_SCHEDULE = "schedule"
FLOW_ACCESS_ACTION_APPROVE = "approve"
FLOW_ACCESS_ACTION_READ = "read"

_PLATFORM_BYPASS_ROLES = {ROLE_MASTER_ADMIN, ROLE_SUPER_ADMIN, ROLE_PLATFORM_ADMIN}


@dataclass(frozen=True)
class ActorDirectoryScope:
    user_id: str
    group_ids: tuple[str, ...]
    team_ids: tuple[str, ...]


def resolve_actor_directory_scope(db: Session, actor_id: str) -> ActorDirectoryScope:
    normalized = str(actor_id or "").strip()
    group_rows = db.query(DirectoryGroupMembership.group_id).filter_by(user_id=normalized).all()
    team_rows = db.query(DirectoryTeamMembership.team_id).filter_by(user_id=normalized).all()
    return ActorDirectoryScope(
        user_id=normalized,
        group_ids=tuple(sorted({str(row[0]).strip() for row in group_rows if str(row[0]).strip()})),
        team_ids=tuple(sorted({str(row[0]).strip() for row in team_rows if str(row[0]).strip()})),
    )


def default_access_policy_json(actor_id: str) -> str:
    policy = {
        "version": 1,
        "owners": {"users": [actor_id], "groups": [], "teams": [], "match": "any"},
        "runners": {"users": [], "groups": [], "teams": [], "match": "any"},
        "schedulers": {"users": [], "groups": [], "teams": [], "match": "any"},
        "approvers": {"match": "any", "clauses": []},
    }
    return json.dumps(policy, separators=(",", ":"))


def parse_access_policy(raw: Optional[str]) -> dict[str, Any]:
    if not raw or not str(raw).strip():
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=422,
            detail={
                "error_code": "VALIDATION_ERROR",
                "message": "access_policy_json must be valid JSON",
                "decision_trace_id": "orchestration-access-policy-json",
            },
        ) from exc
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=422, detail="access_policy_json must be a JSON object")
    return parsed


def validate_access_policy(policy: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    for key in ("owners", "runners", "schedulers"):
        spec = policy.get(key)
        if spec is None:
            continue
        if not isinstance(spec, dict):
            errors.append(f"access_policy.{key} must be an object")
            continue
        errors.extend(_validate_scope_spec(spec, f"access_policy.{key}"))
    approvers = policy.get("approvers")
    if approvers is not None:
        if not isinstance(approvers, dict):
            errors.append("access_policy.approvers must be an object")
        else:
            mode = str(approvers.get("mode") or "simple").strip().lower()
            if mode not in {"simple", "staged"}:
                errors.append("access_policy.approvers.mode must be simple or staged")
            match = str(approvers.get("match") or "any").strip().lower()
            if match not in {"any", "all"}:
                errors.append("access_policy.approvers.match must be any or all")
            if mode == "staged":
                stages = approvers.get("stages")
                if not isinstance(stages, list) or not stages:
                    errors.append("access_policy.approvers.stages must be a non-empty array when mode=staged")
                elif isinstance(stages, list):
                    for index, stage in enumerate(stages):
                        if not isinstance(stage, dict):
                            errors.append(f"access_policy.approvers.stages[{index}] must be an object")
                            continue
                        if not str(stage.get("stage_id") or "").strip():
                            errors.append(f"access_policy.approvers.stages[{index}].stage_id is required")
                        stage_match = str(stage.get("match") or "any").strip().lower()
                        if stage_match not in {"any", "all"}:
                            errors.append(f"access_policy.approvers.stages[{index}].match must be any or all")
                        clauses = stage.get("clauses")
                        if clauses is not None and isinstance(clauses, list):
                            for clause_index, clause in enumerate(clauses):
                                if not isinstance(clause, dict):
                                    errors.append(
                                        f"access_policy.approvers.stages[{index}].clauses[{clause_index}] must be an object"
                                    )
                                    continue
                                errors.extend(
                                    _validate_scope_spec(
                                        clause,
                                        f"access_policy.approvers.stages[{index}].clauses[{clause_index}]",
                                    )
                                )
            else:
                clauses = approvers.get("clauses")
                if clauses is not None:
                    if not isinstance(clauses, list):
                        errors.append("access_policy.approvers.clauses must be an array")
                    else:
                        for index, clause in enumerate(clauses):
                            if not isinstance(clause, dict):
                                errors.append(f"access_policy.approvers.clauses[{index}] must be an object")
                                continue
                            errors.extend(_validate_scope_spec(clause, f"access_policy.approvers.clauses[{index}]"))
    return errors


def _validate_scope_spec(spec: dict[str, Any], path: str) -> list[str]:
    errors: list[str] = []
    match = str(spec.get("match") or "any").strip().lower()
    if match not in {"any", "all"}:
        errors.append(f"{path}.match must be any or all")
    for field in ("users", "groups", "teams"):
        value = spec.get(field)
        if value is None:
            continue
        if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
            errors.append(f"{path}.{field} must be an array of strings")
    errors.extend(validate_resolve_from(spec, path))
    return errors


def _scope_spec_empty(spec: dict[str, Any]) -> bool:
    users = spec.get("users") or []
    groups = spec.get("groups") or []
    teams = spec.get("teams") or []
    resolve_from = spec.get("resolve_from")
    has_resolve = isinstance(resolve_from, dict) and bool(resolve_from.get("type"))
    return not users and not groups and not teams and not has_resolve


def _maybe_resolve_scope_spec(
    spec: dict[str, Any],
    *,
    db: Optional[Session] = None,
    ctx: Optional[ActorContext] = None,
    flow: Optional[OrchestrationFlowDefinition] = None,
) -> dict[str, Any]:
    if not spec or not isinstance(spec, dict):
        return spec or {}
    resolve_from = spec.get("resolve_from")
    if not isinstance(resolve_from, dict) or not resolve_from.get("type"):
        return spec
    if db is None or ctx is None or flow is None:
        return spec
    return resolve_scope_spec(db, ctx, flow, spec)


def actor_matches_scope_spec(
    scope: ActorDirectoryScope,
    spec: dict[str, Any],
    *,
    db: Optional[Session] = None,
    ctx: Optional[ActorContext] = None,
    flow: Optional[OrchestrationFlowDefinition] = None,
) -> bool:
    if not spec or _scope_spec_empty(spec):
        return True
    try:
        effective = _maybe_resolve_scope_spec(spec, db=db, ctx=ctx, flow=flow)
    except ScopeResolveError:
        raise
    users = [str(item).strip() for item in (effective.get("users") or []) if str(item).strip()]
    groups = [str(item).strip() for item in (effective.get("groups") or []) if str(item).strip()]
    teams = [str(item).strip() for item in (effective.get("teams") or []) if str(item).strip()]
    match_mode = str(effective.get("match") or spec.get("match") or "any").strip().lower()

    user_ok = scope.user_id in users if users else True
    group_ok = any(group_id in scope.group_ids for group_id in groups) if groups else True
    team_ok = any(team_id in scope.team_ids for team_id in teams) if teams else True

    if match_mode == "all":
        checks: list[bool] = []
        if users:
            checks.append(user_ok)
        if groups:
            checks.append(group_ok)
        if teams:
            checks.append(team_ok)
        return all(checks) if checks else True

    hits: list[bool] = []
    if users:
        hits.append(user_ok)
    if groups:
        hits.append(group_ok)
    if teams:
        hits.append(team_ok)
    return any(hits) if hits else True


def actor_matches_approver_policy(
    scope: ActorDirectoryScope,
    policy: dict[str, Any],
    *,
    db: Optional[Session] = None,
    ctx: Optional[ActorContext] = None,
    flow: Optional[OrchestrationFlowDefinition] = None,
    stage_id: Optional[str] = None,
) -> bool:
    approvers = policy.get("approvers") if isinstance(policy.get("approvers"), dict) else {}
    mode = str(approvers.get("mode") or "simple").strip().lower()
    if mode == "staged" and stage_id:
        from app.services.orchestration_iga import actor_matches_stage, get_approval_stages

        for stage in get_approval_stages(policy):
            if stage["stage_id"] == str(stage_id).strip():
                return actor_matches_stage(scope, stage, db=db, ctx=ctx, flow=flow)  # type: ignore[arg-type]
        return False
    clauses = approvers.get("clauses")
    if not isinstance(clauses, list) or not clauses:
        return actor_matches_scope_spec(scope, approvers, db=db, ctx=ctx, flow=flow)
    combination = str(approvers.get("match") or "any").strip().lower()
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


def actor_can_read_flow(
    scope: ActorDirectoryScope,
    policy: dict[str, Any],
    flow: OrchestrationFlowDefinition,
    *,
    db: Optional[Session] = None,
    ctx: Optional[ActorContext] = None,
) -> bool:
    if not policy:
        return True
    if actor_matches_scope_spec(scope, policy.get("owners") or {}, db=db, ctx=ctx, flow=flow):
        return True
    if actor_matches_scope_spec(scope, policy.get("runners") or {}, db=db, ctx=ctx, flow=flow):
        return True
    if actor_matches_scope_spec(scope, policy.get("schedulers") or {}, db=db, ctx=ctx, flow=flow):
        return True
    if actor_matches_approver_policy(scope, policy, db=db, ctx=ctx, flow=flow):
        return True
    if scope.user_id and scope.user_id == str(flow.created_by or "").strip():
        return True
    return False


def platform_bypasses_flow_scope(ctx: ActorContext) -> bool:
    return ctx.actor_role in _PLATFORM_BYPASS_ROLES


def enforce_flow_access(
    db: Session,
    ctx: ActorContext,
    flow: OrchestrationFlowDefinition,
    action: str,
    *,
    schedule_change: bool = False,
) -> None:
    if platform_bypasses_flow_scope(ctx):
        return

    policy = parse_access_policy(getattr(flow, "access_policy_json", None))
    if not policy:
        return

    scope = resolve_actor_directory_scope(db, ctx.actor_id)

    allowed = False
    try:
        if action == FLOW_ACCESS_ACTION_MANAGE:
            allowed = actor_matches_scope_spec(scope, policy.get("owners") or {}, db=db, ctx=ctx, flow=flow)
        elif action == FLOW_ACCESS_ACTION_RUN:
            allowed = actor_matches_scope_spec(scope, policy.get("runners") or {}, db=db, ctx=ctx, flow=flow)
        elif action == FLOW_ACCESS_ACTION_SCHEDULE:
            allowed = actor_matches_scope_spec(scope, policy.get("schedulers") or {}, db=db, ctx=ctx, flow=flow)
        elif action == FLOW_ACCESS_ACTION_APPROVE:
            allowed = actor_matches_approver_policy(scope, policy, db=db, ctx=ctx, flow=flow)
        elif action == FLOW_ACCESS_ACTION_READ:
            allowed = actor_can_read_flow(scope, policy, flow, db=db, ctx=ctx)
        else:
            allowed = False

        if schedule_change and not allowed and action != FLOW_ACCESS_ACTION_SCHEDULE:
            allowed = actor_matches_scope_spec(scope, policy.get("schedulers") or {}, db=db, ctx=ctx, flow=flow)
    except ScopeResolveError as exc:
        raise HTTPException(
            status_code=403,
            detail={
                "error_code": "AUTHZ_FLOW_SCOPE_RESOLVE_FAILED",
                "message": str(exc.message),
                "actor_id": ctx.actor_id,
                "flow_id": flow.flow_id,
                "required_action": action,
                "decision_trace_id": "orchestration-flow-scope-resolve",
                "remediation_hint": "Fix access_policy_json resolve_from configuration or data connection registry.",
            },
        ) from exc

    if allowed:
        return

    from app.services.orchestration_iga import get_active_jit_grant

    jit_grant = get_active_jit_grant(db, flow_id=flow.flow_id, actor_id=ctx.actor_id, action=action)
    if jit_grant is not None:
        return

    raise HTTPException(
        status_code=403,
        detail={
            "error_code": "AUTHZ_FLOW_SCOPE_FORBIDDEN",
            "message": f"Actor is not authorized for orchestration flow action '{action}'.",
            "actor_id": ctx.actor_id,
            "flow_id": flow.flow_id,
            "required_action": action,
            "policy_version": policy.get("version", 1),
            "decision_trace_id": "orchestration-flow-access-check",
            "remediation_hint": "Update flow access_policy_json owners/runners/schedulers/approvers or request membership in an allowed group or team.",
        },
    )


def merge_access_policy_on_create(raw_policy: Optional[str], actor_id: str) -> str:
    if not raw_policy or not str(raw_policy).strip():
        return default_access_policy_json(actor_id)
    policy = parse_access_policy(raw_policy)
    owners = policy.get("owners") if isinstance(policy.get("owners"), dict) else {}
    users = [str(item).strip() for item in (owners.get("users") or []) if str(item).strip()]
    if actor_id not in users:
        users.append(actor_id)
    owners["users"] = users
    owners.setdefault("groups", [])
    owners.setdefault("teams", [])
    owners.setdefault("match", "any")
    policy["owners"] = owners
    policy.setdefault("version", 1)
    policy.setdefault("runners", {"users": [], "groups": [], "teams": [], "match": "any"})
    policy.setdefault("schedulers", {"users": [], "groups": [], "teams": [], "match": "any"})
    policy.setdefault("approvers", {"match": "any", "clauses": []})
    from app.services.orchestration_iga import validate_iga_policy

    errors = validate_access_policy(policy)
    errors.extend(validate_iga_policy(policy, "dev", actor_id))
    if errors:
        raise HTTPException(
            status_code=422,
            detail={
                "error_code": "VALIDATION_ERROR",
                "message": "access_policy_json validation failed",
                "errors": errors[:10],
                "decision_trace_id": "orchestration-access-policy-validate",
            },
        )
    return json.dumps(policy, separators=(",", ":"))
