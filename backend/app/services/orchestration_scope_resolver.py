from __future__ import annotations

import hashlib
import json
import re
import time
from copy import deepcopy
from typing import Any, Optional

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.models import OrchestrationFlowDefinition
from app.security import ActorContext
from app.services.credential_resolution import load_active_binding_by_id, resolve_binding_for_runtime
from app.services.orchestration_data_connections import execute_read_query
from app.services.orchestration_flows import _validate_http_url

RESOLVE_TYPE_DATABASE_QUERY = "database_query"
RESOLVE_TYPE_HTTP_JSON = "http_json"
ALLOWED_RESOLVE_TYPES = {RESOLVE_TYPE_DATABASE_QUERY, RESOLVE_TYPE_HTTP_JSON}

HTTP_METHODS = {"GET", "POST", "HEAD"}

_FORBIDDEN_SQL_PATTERN = re.compile(
    r"\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|GRANT|REVOKE|EXEC|EXECUTE|CALL|MERGE|REPLACE|UPSERT)\b",
    re.IGNORECASE,
)

_resolve_cache: dict[str, tuple[float, dict[str, list[str]]]] = {}


class ScopeResolveError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


def validate_resolve_from(spec: dict[str, Any], path: str) -> list[str]:
    errors: list[str] = []
    resolve_from = spec.get("resolve_from")
    if resolve_from is None:
        return errors
    if not isinstance(resolve_from, dict):
        return [f"{path}.resolve_from must be an object"]

    resolve_type = str(resolve_from.get("type") or "").strip().lower()
    if resolve_type not in ALLOWED_RESOLVE_TYPES:
        errors.append(f"{path}.resolve_from.type must be database_query or http_json")
        return errors

    cache_seconds = resolve_from.get("cache_seconds", 0)
    if cache_seconds is not None and (
        not isinstance(cache_seconds, int) or cache_seconds < 0 or cache_seconds > 3600
    ):
        errors.append(f"{path}.resolve_from.cache_seconds must be an integer 0-3600")

    mapping = resolve_from.get("mapping")
    if mapping is not None and not isinstance(mapping, dict):
        errors.append(f"{path}.resolve_from.mapping must be an object")

    if resolve_type == RESOLVE_TYPE_DATABASE_QUERY:
        connection_id = str(resolve_from.get("connection_id") or "").strip()
        if not connection_id:
            errors.append(f"{path}.resolve_from.connection_id is required")
        sql = str(resolve_from.get("sql") or "").strip()
        if not sql:
            errors.append(f"{path}.resolve_from.sql is required")
        elif _sql_validation_error(sql):
            errors.append(f"{path}.resolve_from.sql {_sql_validation_error(sql)}")
        parameters = resolve_from.get("parameters")
        if parameters is not None and not isinstance(parameters, dict):
            errors.append(f"{path}.resolve_from.parameters must be an object")

    if resolve_type == RESOLVE_TYPE_HTTP_JSON:
        url = str(resolve_from.get("url") or "").strip()
        if not url:
            errors.append(f"{path}.resolve_from.url is required")
        method = str(resolve_from.get("method") or "GET").strip().upper()
        if method not in HTTP_METHODS:
            errors.append(f"{path}.resolve_from.method must be GET, POST, or HEAD")
        auth_binding_id = resolve_from.get("auth_binding_id")
        if auth_binding_id is not None and not isinstance(auth_binding_id, str):
            errors.append(f"{path}.resolve_from.auth_binding_id must be a string")

    return errors


def validate_read_only_sql(sql: str) -> Optional[str]:
    return _sql_validation_error(sql)


def _sql_validation_error(sql: str) -> Optional[str]:
    normalized = str(sql or "").strip()
    if not normalized:
        return "must not be empty"
    if ";" in normalized:
        return "must not contain semicolons"
    if "--" in normalized or "/*" in normalized or "*/" in normalized:
        return "must not contain SQL comments"
    if not re.match(r"(?is)^select\b", normalized):
        return "must start with SELECT"
    if _FORBIDDEN_SQL_PATTERN.search(normalized):
        return "must be a read-only SELECT query"
    return None


def build_template_context(ctx: ActorContext, flow: OrchestrationFlowDefinition) -> dict[str, str]:
    return _template_context(ctx, flow)


def _template_context(ctx: ActorContext, flow: OrchestrationFlowDefinition) -> dict[str, str]:
    return {
        "flow.flow_id": str(flow.flow_id or "").strip(),
        "flow.environment": str(flow.environment or "").strip(),
        "flow.tenant_id": str(flow.tenant_id or "").strip(),
        "flow.flow_name": str(flow.flow_name or "").strip(),
        "actor.actor_id": str(ctx.actor_id or "").strip(),
    }


def _apply_templates(value: Any, templates: dict[str, str]) -> Any:
    if isinstance(value, str):
        result = value
        for key, replacement in templates.items():
            result = result.replace(f"{{{{{key}}}}}", replacement)
        return result
    if isinstance(value, dict):
        return {str(k): _apply_templates(v, templates) for k, v in value.items()}
    if isinstance(value, list):
        return [_apply_templates(item, templates) for item in value]
    return value


def _cache_key(flow_id: str, resolve_from: dict[str, Any]) -> str:
    payload = json.dumps(resolve_from, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]
    resolve_type = str(resolve_from.get("type") or "").strip().lower()
    return f"{flow_id}:{resolve_type}:{digest}"


def _get_cached(flow_id: str, resolve_from: dict[str, Any]) -> Optional[dict[str, list[str]]]:
    cache_seconds = int(resolve_from.get("cache_seconds") or 0)
    if cache_seconds <= 0:
        return None
    key = _cache_key(flow_id, resolve_from)
    entry = _resolve_cache.get(key)
    if not entry:
        return None
    expires_at, payload = entry
    if time.monotonic() >= expires_at:
        _resolve_cache.pop(key, None)
        return None
    return payload


def _set_cached(flow_id: str, resolve_from: dict[str, Any], payload: dict[str, list[str]]) -> None:
    cache_seconds = int(resolve_from.get("cache_seconds") or 0)
    if cache_seconds <= 0:
        return
    key = _cache_key(flow_id, resolve_from)
    _resolve_cache[key] = (time.monotonic() + cache_seconds, payload)


def _dedupe_strings(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        normalized = str(value or "").strip()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        result.append(normalized)
    return result


def _mapping_field(mapping: dict[str, Any], key: str, default: str) -> str:
    return str(mapping.get(key) or default).strip() or default


def _rows_to_scope(rows: list[dict[str, Any]], mapping: dict[str, Any]) -> dict[str, list[str]]:
    user_field = _mapping_field(mapping, "user_field", "user_id")
    group_field = _mapping_field(mapping, "group_field", "group_id")
    team_field = _mapping_field(mapping, "team_field", "team_id")
    users: list[str] = []
    groups: list[str] = []
    teams: list[str] = []
    for row in rows:
        if user_field in row and row[user_field] is not None:
            users.append(str(row[user_field]))
        if group_field in row and row[group_field] is not None:
            groups.append(str(row[group_field]))
        if team_field in row and row[team_field] is not None:
            teams.append(str(row[team_field]))
    return {
        "users": _dedupe_strings(users),
        "groups": _dedupe_strings(groups),
        "teams": _dedupe_strings(teams),
    }


def _extract_json_path(data: Any, path: str) -> list[Any]:
    normalized = str(path or "").strip()
    if not normalized.startswith("$."):
        return []
    tokens = normalized[2:].split(".")
    current: list[Any] = [data]
    for token in tokens:
        next_values: list[Any] = []
        wildcard = token.endswith("[*]")
        key = token[:-3] if wildcard else token
        for item in current:
            if not isinstance(item, dict):
                continue
            if key not in item:
                continue
            value = item[key]
            if wildcard:
                if isinstance(value, list):
                    next_values.extend(value)
            else:
                next_values.append(value)
        current = next_values
        if not current:
            break
    return current


def _json_paths_to_scope(data: Any, mapping: dict[str, Any]) -> dict[str, list[str]]:
    users_path = str(mapping.get("users_json_path") or "").strip()
    groups_path = str(mapping.get("groups_json_path") or "").strip()
    teams_path = str(mapping.get("teams_json_path") or "").strip()
    users = [str(item) for item in _extract_json_path(data, users_path) if item is not None] if users_path else []
    groups = [str(item) for item in _extract_json_path(data, groups_path) if item is not None] if groups_path else []
    teams = [str(item) for item in _extract_json_path(data, teams_path) if item is not None] if teams_path else []
    return {
        "users": _dedupe_strings(users),
        "groups": _dedupe_strings(groups),
        "teams": _dedupe_strings(teams),
    }


def _resolve_from_spec(
    db: Session,
    ctx: ActorContext,
    flow: OrchestrationFlowDefinition,
    resolve_from: dict[str, Any],
) -> dict[str, list[str]]:
    cached = _get_cached(flow.flow_id, resolve_from)
    if cached is not None:
        return cached

    templates = _template_context(ctx, flow)
    resolve_type = str(resolve_from.get("type") or "").strip().lower()

    if resolve_type == RESOLVE_TYPE_DATABASE_QUERY:
        sql = str(resolve_from.get("sql") or "").strip()
        sql_error = _sql_validation_error(sql)
        if sql_error:
            raise ScopeResolveError(f"Invalid SQL: {sql_error}")
        parameters = _apply_templates(resolve_from.get("parameters") or {}, templates)
        if not isinstance(parameters, dict):
            raise ScopeResolveError("resolve_from.parameters must resolve to an object")
        rows = execute_read_query(
            db,
            connection_id=str(resolve_from.get("connection_id") or "").strip(),
            sql=sql,
            parameters=parameters,
        )
        mapping = resolve_from.get("mapping") if isinstance(resolve_from.get("mapping"), dict) else {}
        resolved = _rows_to_scope(rows, mapping)
    elif resolve_type == RESOLVE_TYPE_HTTP_JSON:
        url = str(_apply_templates(resolve_from.get("url") or "", templates)).strip()
        url_error = _validate_http_url(db, url)
        if url_error:
            raise ScopeResolveError(url_error)
        method = str(resolve_from.get("method") or "GET").strip().upper()
        headers: dict[str, str] = {}
        auth_binding_id = str(resolve_from.get("auth_binding_id") or "").strip()
        if auth_binding_id:
            binding = load_active_binding_by_id(db, auth_binding_id)
            resolved_cred = resolve_binding_for_runtime(db, binding)
            token = str(resolved_cred.secret_value or "").strip()
            if token:
                headers["Authorization"] = f"Bearer {token}"
        try:
            response = httpx.request(method, url, headers=headers, timeout=8.0)
            response.raise_for_status()
            payload = response.json()
        except ScopeResolveError:
            raise
        except Exception as exc:
            raise ScopeResolveError(f"HTTP resolver request failed: {exc}") from exc
        mapping = resolve_from.get("mapping") if isinstance(resolve_from.get("mapping"), dict) else {}
        resolved = _json_paths_to_scope(payload, mapping)
    else:
        raise ScopeResolveError(f"Unsupported resolve_from.type: {resolve_type}")

    _set_cached(flow.flow_id, resolve_from, resolved)
    return resolved


def _merge_scope_lists(static: list[str], dynamic: list[str]) -> list[str]:
    return _dedupe_strings([*(static or []), *(dynamic or [])])


def resolve_scope_spec(
    db: Session,
    ctx: ActorContext,
    flow: OrchestrationFlowDefinition,
    spec: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(spec, dict):
        return {}
    merged = deepcopy(spec)
    resolve_from = spec.get("resolve_from")
    if not isinstance(resolve_from, dict):
        return merged

    resolved = _resolve_from_spec(db, ctx, flow, resolve_from)
    merged["users"] = _merge_scope_lists(
        [str(item) for item in (spec.get("users") or []) if str(item).strip()],
        resolved.get("users") or [],
    )
    merged["groups"] = _merge_scope_lists(
        [str(item) for item in (spec.get("groups") or []) if str(item).strip()],
        resolved.get("groups") or [],
    )
    merged["teams"] = _merge_scope_lists(
        [str(item) for item in (spec.get("teams") or []) if str(item).strip()],
        resolved.get("teams") or [],
    )
    return merged


def preview_resolved_policy(
    db: Session,
    ctx: ActorContext,
    flow: OrchestrationFlowDefinition,
    policy: dict[str, Any],
) -> dict[str, Any]:
    preview = deepcopy(policy)
    errors: list[str] = []

    def _resolve_block(block_key: str) -> None:
        block = preview.get(block_key)
        if not isinstance(block, dict):
            return
        try:
            preview[block_key] = resolve_scope_spec(db, ctx, flow, block)
        except ScopeResolveError as exc:
            errors.append(f"{block_key}: {exc.message}")

    for key in ("owners", "runners", "schedulers"):
        _resolve_block(key)

    approvers = preview.get("approvers")
    if isinstance(approvers, dict):
        mode = str(approvers.get("mode") or "simple").strip().lower()
        if mode == "staged":
            stages = approvers.get("stages")
            if isinstance(stages, list):
                resolved_stages: list[Any] = []
                for stage_index, stage in enumerate(stages):
                    if not isinstance(stage, dict):
                        resolved_stages.append(stage)
                        continue
                    stage_copy = deepcopy(stage)
                    clauses = stage_copy.get("clauses")
                    if isinstance(clauses, list):
                        resolved_clauses: list[dict[str, Any]] = []
                        for clause_index, clause in enumerate(clauses):
                            if not isinstance(clause, dict):
                                resolved_clauses.append(clause)
                                continue
                            try:
                                resolved_clauses.append(resolve_scope_spec(db, ctx, flow, clause))
                            except ScopeResolveError as exc:
                                errors.append(
                                    f"approvers.stages[{stage_index}].clauses[{clause_index}]: {exc.message}"
                                )
                                resolved_clauses.append(clause)
                        stage_copy["clauses"] = resolved_clauses
                    resolved_stages.append(stage_copy)
                approvers["stages"] = resolved_stages
        else:
            clauses = approvers.get("clauses")
            if isinstance(clauses, list):
                resolved_clauses = []
                for index, clause in enumerate(clauses):
                    if not isinstance(clause, dict):
                        resolved_clauses.append(clause)
                        continue
                    try:
                        resolved_clauses.append(resolve_scope_spec(db, ctx, flow, clause))
                    except ScopeResolveError as exc:
                        errors.append(f"approvers.clauses[{index}]: {exc.message}")
                        resolved_clauses.append(clause)
                approvers["clauses"] = resolved_clauses
        try:
            preview["approvers"] = resolve_scope_spec(db, ctx, flow, approvers)
        except ScopeResolveError as exc:
            errors.append(f"approvers: {exc.message}")
            preview["approvers"] = approvers

    if errors:
        preview["_resolve_errors"] = errors
    return preview
