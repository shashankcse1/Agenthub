from app.services.ui_coverage import (
    build_ui_coverage_report,
    inventory_entry_key,
    load_api_inventory_entries,
    match_inventory_entry,
    parse_api_inventory,
    route_template_matches,
)


SAMPLE_INVENTORY = """
### `app/routers/example.py`

| Method | Route | UI Coverage | Notes |
|---|---|---|---|
| GET | `/example/items` | Full | Covered in UI. |
| POST | `/example/items` | Gap | Backend only. |
| GET | `/example/items/{item_id}` | Partial | Read-only subset. |
"""


def test_parse_api_inventory_extracts_coverage_rows():
    entries = parse_api_inventory(SAMPLE_INVENTORY)
    assert len(entries) == 3
    assert entries[0]["method"] == "GET"
    assert entries[0]["route"] == "/example/items"
    assert entries[0]["ui_coverage"] == "Full"
    assert entries[0]["frontend_available"] is True
    assert entries[1]["ui_coverage"] == "Gap"
    assert entries[1]["frontend_available"] is False
    assert entries[2]["ui_coverage"] == "Partial"
    assert entries[2]["frontend_available"] is False


def test_route_template_matches_path_parameters():
    assert route_template_matches("/example/items/abc-123", "/example/items/{item_id}")
    assert not route_template_matches("/example/items/abc-123/extra", "/example/items/{item_id}")


def test_match_inventory_entry_supports_templates():
    entries = parse_api_inventory(SAMPLE_INVENTORY)
    matched = match_inventory_entry("GET", "/example/items/some-id", entries)
    assert matched is not None
    assert matched["ui_coverage"] == "Partial"


def test_load_api_inventory_entries_reads_canonical_doc():
    entries = load_api_inventory_entries()
    assert len(entries) >= 50
    assert any(item["route"] == "/discovery/agents" for item in entries)


def test_build_ui_coverage_report_includes_inventory_counts():
    report = build_ui_coverage_report([])
    assert report["total_inventory_endpoints"] >= 50
    assert report["full_coverage_endpoints"] >= 1
    assert report["partial_coverage_endpoints"] >= 1
    assert isinstance(report["gap_items"], list)
    assert isinstance(report["undocumented_items"], list)
    assert isinstance(report["items"], list)


def _governance_test_client():
    import importlib.util
    from pathlib import Path

    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    router_path = Path(__file__).resolve().parents[1] / "app" / "routers" / "governance.py"
    spec = importlib.util.spec_from_file_location("governance_router_under_test", router_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)

    app = FastAPI()
    app.include_router(module.router)
    return TestClient(app)


def test_governance_ui_coverage_report_endpoint():
    client = _governance_test_client()
    response = client.get(
        "/governance/ui-coverage",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-ui-coverage"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["total_inventory_endpoints"] >= 50
    assert payload["partial_coverage_endpoints"] >= 1
    assert isinstance(payload["partial_items"], list)
    assert isinstance(payload["undocumented_items"], list)


def test_governance_ui_coverage_inventory_endpoint():
    client = _governance_test_client()
    response = client.get(
        "/governance/ui-coverage/inventory",
        headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-ui-inventory"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["inventory_source"] == "docs/governance/api-inventory-and-ui-map.md"
    assert isinstance(payload["items"], list)
    assert any(
        inventory_entry_key(item["method"], item["route"]) == "GET:/discovery/agents"
        for item in payload["items"]
    )


def test_governance_ui_coverage_denies_non_compliance_read_roles():
    client = _governance_test_client()
    headers = {"X-Actor-Role": "Agent Owner", "X-Actor-Id": "owner-ui-coverage-deny"}
    report = client.get("/governance/ui-coverage", headers=headers)
    inventory = client.get("/governance/ui-coverage/inventory", headers=headers)
    assert report.status_code == 403
    assert inventory.status_code == 403
    assert report.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"
    assert inventory.json()["detail"]["error_code"] == "AUTHZ_ROLE_FORBIDDEN"
