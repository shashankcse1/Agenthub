from __future__ import annotations

from typing import Any, Optional

from fastapi import HTTPException

POLICY_VERSION = "v1"


def api_error(
    status_code: int,
    *,
    error_code: str,
    message: str,
    decision_trace_id: str,
    remediation_hint: Optional[str] = None,
    **extra: Any,
) -> HTTPException:
    detail: dict[str, Any] = {
        "error_code": error_code,
        "message": message,
        "policy_version": POLICY_VERSION,
        "decision_trace_id": decision_trace_id,
    }
    if remediation_hint:
        detail["remediation_hint"] = remediation_hint
    detail.update(extra)
    return HTTPException(status_code=status_code, detail=detail)


def authz_scope_forbidden(
    *,
    message: str,
    actor_role: str,
    required_scope: str,
    decision_trace_id: str,
    remediation_hint: str,
) -> HTTPException:
    return api_error(
        403,
        error_code="AUTHZ_SCOPE_FORBIDDEN",
        message=message,
        decision_trace_id=decision_trace_id,
        remediation_hint=remediation_hint,
        actor_role=actor_role,
        required_scope=required_scope,
    )


def validation_error(
    message: str,
    *,
    decision_trace_id: str = "validation-error",
    remediation_hint: Optional[str] = None,
    status_code: int = 400,
    **extra: Any,
) -> HTTPException:
    return api_error(
        status_code,
        error_code="VALIDATION_ERROR",
        message=message,
        decision_trace_id=decision_trace_id,
        remediation_hint=remediation_hint,
        **extra,
    )


def not_found_error(
    resource_type: str,
    resource_id: str,
    *,
    decision_trace_id: Optional[str] = None,
) -> HTTPException:
    trace_id = decision_trace_id or f"not-found-{resource_type}"
    return api_error(
        404,
        error_code="RESOURCE_NOT_FOUND",
        message=f"{resource_type} not found.",
        decision_trace_id=trace_id,
        remediation_hint="Verify the identifier and try again.",
        resource_type=resource_type,
        resource_id=resource_id,
    )


def conflict_error(
    message: str,
    *,
    decision_trace_id: str = "resource-conflict",
    remediation_hint: Optional[str] = None,
    **extra: Any,
) -> HTTPException:
    return api_error(
        409,
        error_code="RESOURCE_CONFLICT",
        message=message,
        decision_trace_id=decision_trace_id,
        remediation_hint=remediation_hint,
        **extra,
    )


def unauthorized_error(
    message: str = "Authentication failed.",
    *,
    decision_trace_id: str = "authn-failed",
    remediation_hint: Optional[str] = None,
) -> HTTPException:
    return api_error(
        401,
        error_code="AUTHN_INVALID_CREDENTIALS",
        message=message,
        decision_trace_id=decision_trace_id,
        remediation_hint=remediation_hint or "Verify credentials and retry.",
    )


def upstream_error(
    message: str,
    *,
    decision_trace_id: str = "upstream-provider-error",
    remediation_hint: Optional[str] = None,
) -> HTTPException:
    return api_error(
        502,
        error_code="UPSTREAM_PROVIDER_ERROR",
        message=message,
        decision_trace_id=decision_trace_id,
        remediation_hint=remediation_hint or "Retry later or verify provider configuration.",
    )

