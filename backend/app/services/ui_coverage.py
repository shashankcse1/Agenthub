from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Iterable

from app.logging_utils import get_logger

logger = get_logger(__name__)

INVENTORY_RELATIVE_PATH = Path("docs/governance/api-inventory-and-ui-map.md")
INVENTORY_ROW_RE = re.compile(
    r"^\|\s*(GET|POST|PUT|PATCH|DELETE)\s*\|\s*`([^`]+)`\s*\|\s*(Full|Partial|Gap)\s*\|\s*(.+?)\s*\|$"
)
EXCLUDED_LIVE_PATHS = {"/docs", "/docs/oauth2-redirect", "/redoc", "/openapi.json", "/health"}
API_METHODS = {"GET", "POST", "PATCH", "PUT", "DELETE"}


def inventory_file_path() -> Path:
    backend_root = Path(__file__).resolve().parents[2]
    return backend_root / INVENTORY_RELATIVE_PATH


def parse_api_inventory(text: str) -> list[dict]:
    entries: list[dict] = []
    current_router: str | None = None

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("### `app/routers/"):
            current_router = stripped.removeprefix("### ").strip("`")
            continue
        match = INVENTORY_ROW_RE.match(stripped)
        if not match:
            continue
        method, route, coverage, notes = match.groups()
        entries.append(
            {
                "router_module": current_router,
                "method": method,
                "route": route,
                "ui_coverage": coverage,
                "frontend_available": coverage == "Full",
                "notes": notes.strip(),
            }
        )
    return entries


def load_api_inventory_entries() -> list[dict]:
    inventory_path = inventory_file_path()
    if not inventory_path.is_file():
        logger.error("ui_coverage_inventory_missing path=%s", inventory_path)
        return []
    text = inventory_path.read_text(encoding="utf-8")
    entries = parse_api_inventory(text)
    logger.info("ui_coverage_inventory_loaded entries=%s path=%s", len(entries), inventory_path)
    return entries


def route_template_matches(live_path: str, template_path: str) -> bool:
    live_segments = [segment for segment in live_path.split("/") if segment]
    template_segments = [segment for segment in template_path.split("/") if segment]
    if len(live_segments) != len(template_segments):
        return False
    for live_segment, template_segment in zip(live_segments, template_segments):
        if template_segment.startswith("{") and template_segment.endswith("}"):
            continue
        if live_segment != template_segment:
            return False
    return True


def inventory_entry_key(method: str, route: str) -> str:
    normalized_method = method.upper()
    normalized_route = route if route.startswith("/") else f"/{route}"
    return f"{normalized_method}:{normalized_route.rstrip('/') or '/'}"


def live_route_key(method: str, path: str) -> str:
    normalized_path = path.rstrip("/") or "/"
    return f"{method.upper()}:{normalized_path}"


def match_inventory_entry(method: str, path: str, entries: Iterable[dict]) -> dict | None:
    normalized_path = path.split("?")[0].rstrip("/") or "/"
    normalized_method = method.upper()
    exact_key = live_route_key(normalized_method, normalized_path)
    indexed = {inventory_entry_key(item["method"], item["route"]): item for item in entries}
    if exact_key in indexed:
        return indexed[exact_key]
    for item in entries:
        if item["method"] != normalized_method:
            continue
        if route_template_matches(normalized_path, item["route"]):
            return item
    return None


def collect_live_route_rows(routes: Iterable[object]) -> list[dict]:
    rows: list[dict] = []
    for route in routes:
        path = getattr(route, "path", "")
        methods = sorted(getattr(route, "methods", set()) or set())
        if not path or path in EXCLUDED_LIVE_PATHS:
            continue
        api_methods = [method for method in methods if method in API_METHODS]
        if not api_methods:
            continue
        for method in api_methods:
            rows.append({"method": method, "path": path})
    rows.sort(key=lambda row: (row["path"], row["method"]))
    return rows


def build_ui_coverage_report(routes: Iterable[object]) -> dict:
    entries = load_api_inventory_entries()
    live_rows = collect_live_route_rows(routes)
    indexed_entries = {inventory_entry_key(item["method"], item["route"]): item for item in entries}
    matched_inventory_keys: set[str] = set()

    gap_items: list[dict] = []
    partial_items: list[dict] = []
    full_items: list[dict] = []

    for item in entries:
        key = inventory_entry_key(item["method"], item["route"])
        if item["ui_coverage"] == "Gap":
            gap_items.append(item)
        elif item["ui_coverage"] == "Partial":
            partial_items.append(item)
        else:
            full_items.append(item)

    undocumented_items: list[dict] = []
    for row in live_rows:
        matched = match_inventory_entry(row["method"], row["path"], entries)
        if matched is None:
            undocumented_items.append(
                {
                    "method": row["method"],
                    "route": row["path"],
                    "ui_coverage": "Undocumented",
                    "frontend_available": False,
                    "notes": "Live backend route is missing from API inventory.",
                }
            )
            continue
        matched_inventory_keys.add(inventory_entry_key(matched["method"], matched["route"]))

    stale_inventory_items: list[dict] = []
    for item in entries:
        key = inventory_entry_key(item["method"], item["route"])
        if key in matched_inventory_keys:
            continue
        if not any(
            row["method"] == item["method"] and route_template_matches(row["path"], item["route"])
            for row in live_rows
        ):
            stale_inventory_items.append(
                {
                    **item,
                    "notes": f"{item['notes']} Inventory entry has no matching live backend route.",
                }
            )

    report = {
        "generated_at": datetime.utcnow(),
        "inventory_source": str(INVENTORY_RELATIVE_PATH).replace("\\", "/"),
        "total_inventory_endpoints": len(entries),
        "full_coverage_endpoints": len(full_items),
        "partial_coverage_endpoints": len(partial_items),
        "gap_coverage_endpoints": len(gap_items),
        "frontend_unavailable_endpoints": len(gap_items) + len(partial_items),
        "undocumented_backend_routes": len(undocumented_items),
        "stale_inventory_entries": len(stale_inventory_items),
        "gap_items": gap_items,
        "partial_items": partial_items,
        "undocumented_items": undocumented_items,
        "stale_inventory_items": stale_inventory_items,
        "items": entries,
    }
    logger.info(
        "ui_coverage_report_built inventory=%s gaps=%s partial=%s undocumented=%s stale=%s",
        report["total_inventory_endpoints"],
        report["gap_coverage_endpoints"],
        report["partial_coverage_endpoints"],
        report["undocumented_backend_routes"],
        report["stale_inventory_entries"],
    )
    return report
