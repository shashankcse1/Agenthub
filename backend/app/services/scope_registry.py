from __future__ import annotations

from collections.abc import Iterable

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import DirectoryGroup, DirectoryTeam
from app.policy_constants import (
    COST_SCOPE_ACTOR,
    COST_SCOPE_GROUP,
    COST_SCOPE_OWNER,
    COST_SCOPE_TEAM,
    COST_SCOPE_USER,
)

SUPPORTED_OWNER_SCOPE_TYPES = {
    COST_SCOPE_USER,
    COST_SCOPE_TEAM,
    COST_SCOPE_GROUP,
    COST_SCOPE_OWNER,
    COST_SCOPE_ACTOR,
}


def _scope_error(status_code: int, error_code: str, message: str, **extra: object) -> HTTPException:
    detail = {
        "error_code": error_code,
        "message": message,
        "policy_version": "v1",
    }
    detail.update(extra)
    return HTTPException(status_code=status_code, detail=detail)


def normalize_scope_reference(
    db: Session,
    *,
    scope_type: str,
    scope_id: str,
    allowed_scope_types: set[str],
    resource_label: str = "scope",
    require_directory_entity: bool = False,
) -> tuple[str, str]:
    normalized_scope_type = str(scope_type or "").strip().lower()
    normalized_scope_id = str(scope_id or "").strip()

    if not normalized_scope_type:
        raise _scope_error(422, "SCOPE_TYPE_REQUIRED", f"{resource_label} type is required")
    if not normalized_scope_id:
        raise _scope_error(422, "SCOPE_ID_REQUIRED", f"{resource_label} id is required")
    if normalized_scope_type not in allowed_scope_types:
        raise _scope_error(
            422,
            "SCOPE_TYPE_UNSUPPORTED",
            f"Unsupported {resource_label} type.",
            scope_type=normalized_scope_type,
            allowed_scope_types=sorted(allowed_scope_types),
        )

    if require_directory_entity and normalized_scope_type == COST_SCOPE_TEAM:
        team = db.query(DirectoryTeam).filter_by(team_id=normalized_scope_id).first()
        if not team:
            raise _scope_error(
                404,
                "DIRECTORY_TEAM_NOT_FOUND",
                "Referenced directory team was not found.",
                scope_type=normalized_scope_type,
                scope_id=normalized_scope_id,
                decision_trace_id="directory-team-scope-lookup",
            )

    if require_directory_entity and normalized_scope_type == COST_SCOPE_GROUP:
        group = db.query(DirectoryGroup).filter_by(group_id=normalized_scope_id).first()
        if not group:
            raise _scope_error(
                404,
                "DIRECTORY_GROUP_NOT_FOUND",
                "Referenced directory group was not found.",
                scope_type=normalized_scope_type,
                scope_id=normalized_scope_id,
                decision_trace_id="directory-group-scope-lookup",
            )

    return normalized_scope_type, normalized_scope_id


def normalize_owner_scope(
    db: Session,
    *,
    owner_scope: str | None = None,
    owner_scope_type: str | None = None,
    owner_scope_id: str | None = None,
) -> tuple[str, str, str]:
    raw_owner_scope = str(owner_scope or "").strip()
    raw_scope_type = str(owner_scope_type or "").strip()
    raw_scope_id = str(owner_scope_id or "").strip()

    if raw_owner_scope:
        if ":" not in raw_owner_scope:
            normalized_scope_id = raw_owner_scope
            return COST_SCOPE_OWNER, normalized_scope_id, f"{COST_SCOPE_OWNER}:{normalized_scope_id}"
        parsed_scope_type, parsed_scope_id = raw_owner_scope.split(":", 1)
        normalized_scope_type, normalized_scope_id = normalize_scope_reference(
            db,
            scope_type=parsed_scope_type,
            scope_id=parsed_scope_id,
            allowed_scope_types=SUPPORTED_OWNER_SCOPE_TYPES,
            resource_label="owner scope",
        )
        return normalized_scope_type, normalized_scope_id, f"{normalized_scope_type}:{normalized_scope_id}"

    normalized_scope_type, normalized_scope_id = normalize_scope_reference(
        db,
        scope_type=raw_scope_type,
        scope_id=raw_scope_id,
        allowed_scope_types=SUPPORTED_OWNER_SCOPE_TYPES,
        resource_label="owner scope",
    )
    return normalized_scope_type, normalized_scope_id, f"{normalized_scope_type}:{normalized_scope_id}"


def normalize_scope_id_list(
    db: Session,
    *,
    scope_type: str,
    scope_ids: Iterable[str] | None,
) -> list[str]:
    normalized_scope_ids: list[str] = []
    seen_scope_ids: set[str] = set()

    for scope_id in scope_ids or []:
        _, normalized_scope_id = normalize_scope_reference(
            db,
            scope_type=scope_type,
            scope_id=scope_id,
            allowed_scope_types={scope_type},
            resource_label=f"{scope_type} scope",
        )
        if normalized_scope_id in seen_scope_ids:
            continue
        seen_scope_ids.add(normalized_scope_id)
        normalized_scope_ids.append(normalized_scope_id)

    return normalized_scope_ids