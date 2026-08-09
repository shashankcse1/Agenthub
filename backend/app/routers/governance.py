from datetime import datetime

from fastapi import APIRouter, Depends, Request

from app.logging_utils import get_logger, sanitize_fields
from app.router_constants import COMPLIANCE_READ_ROLES
from app.schemas import UiCoverageInventoryResponse, UiCoverageReportResponse
from app.security import ActorContext, get_actor_context, require_role
from app.services.ui_coverage import build_ui_coverage_report, load_api_inventory_entries

router = APIRouter()
logger = get_logger(__name__)


@router.get(
    "/governance/ui-coverage",
    response_model=UiCoverageReportResponse,
    summary="UI coverage gap report",
    description=(
        "Parses the canonical API inventory markdown and compares documented UI coverage "
        "against live backend routes. Surfaces Gap/Partial endpoints and undocumented routes. "
        "Read-only; requires COMPLIANCE_READ_ROLES."
    ),
    responses={
        200: {"description": "Coverage report with gap/partial/undocumented counts and item lists."},
        403: {"description": "Actor role is not allowed for governance read operations."},
    },
)
def get_ui_coverage_report(
    request: Request,
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, COMPLIANCE_READ_ROLES)
    report = build_ui_coverage_report(request.app.routes)
    logger.info(
        "governance_ui_coverage_generated %s",
        sanitize_fields(
            {
                "actor_id": ctx.actor_id,
                "inventory_total": report["total_inventory_endpoints"],
                "gap_total": report["gap_coverage_endpoints"],
                "partial_total": report["partial_coverage_endpoints"],
                "undocumented_total": report["undocumented_backend_routes"],
            }
        ),
    )
    return report


@router.get(
    "/governance/ui-coverage/inventory",
    response_model=UiCoverageInventoryResponse,
    summary="Machine-readable API inventory",
    description=(
        "Returns endpoint-level UI coverage from the canonical API inventory markdown. "
        "Used by the frontend to gate calls to backend-only (`Gap`) endpoints at boot. "
        "Read-only; requires COMPLIANCE_READ_ROLES."
    ),
    responses={
        200: {"description": "Inventory items with ui_coverage and frontend_available flags."},
        403: {"description": "Actor role is not allowed for governance read operations."},
    },
)
def get_ui_coverage_inventory(
    ctx: ActorContext = Depends(get_actor_context),
):
    require_role(ctx, COMPLIANCE_READ_ROLES)
    entries = load_api_inventory_entries()
    logger.info(
        "governance_ui_coverage_inventory_served %s",
        sanitize_fields({"actor_id": ctx.actor_id, "entries": len(entries)}),
    )
    return {
        "generated_at": datetime.utcnow(),
        "inventory_source": "docs/governance/api-inventory-and-ui-map.md",
        "items": entries,
    }
