from __future__ import annotations

from typing import Iterable

from app.logging_utils import get_logger
from app.services.compliance_controls import known_control_ids

logger = get_logger(__name__)

ROUTE_CONTROL_MAP: list[tuple[str, list[str]]] = [
    ("/agents", ["CTRL-AUTHZ-ROLE", "CTRL-AUDIT-IMMUTABLE"]),
    ("/owners", ["CTRL-AUTHZ-ROLE", "CTRL-AUDIT-IMMUTABLE"]),
    ("/discovery", ["CTRL-AUTHZ-ROLE", "CTRL-AUDIT-IMMUTABLE"]),
    ("/benchmarks", ["CTRL-READINESS-SIGNED", "CTRL-AUDIT-IMMUTABLE"]),
    ("/scans", ["CTRL-READINESS-SIGNED", "CTRL-AUDIT-IMMUTABLE"]),
    ("/cost", ["CTRL-BUDGET-GUARD", "CTRL-AUDIT-IMMUTABLE"]),
    ("/modules", ["CTRL-AUTHZ-ROLE", "CTRL-AUDIT-IMMUTABLE"]),
    ("/keys", ["CTRL-AUTHZ-ROLE", "CTRL-AUDIT-IMMUTABLE", "CTRL-BUDGET-GUARD"]),
    ("/gateway", ["CTRL-AUTHZ-ROLE", "CTRL-BUDGET-GUARD", "CTRL-AUDIT-IMMUTABLE"]),
    ("/v1", ["CTRL-AUTHZ-ROLE", "CTRL-BUDGET-GUARD", "CTRL-AUDIT-IMMUTABLE"]),
    ("/observability", ["CTRL-AUDIT-IMMUTABLE"]),
    ("/audit", ["CTRL-AUDIT-IMMUTABLE"]),
    ("/compliance", ["CTRL-AUDIT-IMMUTABLE"]),
    ("/governance", ["CTRL-AUDIT-IMMUTABLE"]),
    ("/playground", ["CTRL-AUTHZ-ROLE", "CTRL-BUDGET-GUARD", "CTRL-AUDIT-IMMUTABLE"]),
    ("/route-drafts", ["CTRL-AUTHZ-ROLE", "CTRL-AUDIT-IMMUTABLE"]),
    ("/auth", ["CTRL-AUTHZ-ROLE", "CTRL-AUDIT-IMMUTABLE"]),
    ("/agentic", ["CTRL-READINESS-SIGNED", "CTRL-AUDIT-IMMUTABLE"]),
    ("/secrets", ["CTRL-AUTHZ-ROLE", "CTRL-AUDIT-IMMUTABLE"]),
    ("/providers", ["CTRL-AUTHZ-ROLE", "CTRL-AUDIT-IMMUTABLE"]),
    ("/runtime-config", ["CTRL-AUTHZ-ROLE", "CTRL-AUDIT-IMMUTABLE"]),
    ("/agent-configs", ["CTRL-AUTHZ-ROLE", "CTRL-AUDIT-IMMUTABLE"]),
    ("/browser", ["CTRL-AUTHZ-ROLE", "CTRL-AUDIT-IMMUTABLE"]),
    ("/orchestration", ["CTRL-AUTHZ-ROLE", "CTRL-AUDIT-IMMUTABLE"]),
    ("/platform", ["CTRL-AUTHZ-ROLE", "CTRL-AUDIT-IMMUTABLE"]),
    ("/rag", ["CTRL-AUTHZ-ROLE", "CTRL-AUDIT-IMMUTABLE"]),
]

EXCLUDED_PATHS = {"/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json", "/health"}


def controls_for_path(path: str) -> list[str]:
    for prefix, control_ids in ROUTE_CONTROL_MAP:
        if path.startswith(prefix):
            return control_ids
    return []


def referenced_control_ids() -> set[str]:
    return {control_id for _, control_ids in ROUTE_CONTROL_MAP for control_id in control_ids}


def unknown_referenced_control_ids(known_ids: set[str] | None = None) -> list[str]:
    logger.trace("control_coverage_unknown_id_check")
    resolved_known_ids = known_ids if known_ids is not None else known_control_ids()
    unknown = referenced_control_ids() - resolved_known_ids
    return sorted(unknown)


def build_route_coverage(routes: Iterable[object]) -> dict:
    logger.trace("control_coverage_build_start")
    rows: list[dict] = []
    uncovered_paths: list[str] = []

    for route in routes:
        path = getattr(route, "path", "")
        methods = sorted(getattr(route, "methods", set()) or set())
        if not path or path in EXCLUDED_PATHS:
            continue
        api_methods = [m for m in methods if m in {"GET", "POST", "PATCH", "PUT", "DELETE"}]
        if not api_methods:
            continue

        control_ids = controls_for_path(path)
        covered = len(control_ids) > 0
        if not covered:
            uncovered_paths.append(path)

        rows.append(
            {
                "path": path,
                "methods": api_methods,
                "control_ids": control_ids,
                "covered": covered,
            }
        )

    uncovered_unique = sorted(set(uncovered_paths))
    rows.sort(key=lambda r: r["path"])
    report = {
        "total_routes": len(rows),
        "covered_routes": sum(1 for r in rows if r["covered"]),
        "uncovered_routes": len(uncovered_unique),
        "uncovered_paths": uncovered_unique,
        "items": rows,
    }
    logger.info(
        "control_coverage_build_completed total_routes=%s uncovered_routes=%s",
        report["total_routes"],
        report["uncovered_routes"],
    )
    return report
