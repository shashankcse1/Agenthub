import json

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _approved_headers(actor_id: str, approver_id: str) -> dict[str, str]:
    return {
        "X-Actor-Role": "Platform Admin",
        "X-Actor-Id": actor_id,
        "X-Approver-Role": "Security Approver",
        "X-Approver-Id": approver_id,
    }


def test_compliance_control_catalog_can_be_runtime_config_overridden():
    key = "compliance.control_catalog_json"
    payload = {
        "CTRL-AUDIT-IMMUTABLE": "Runtime Catalog Title Override",
        "CTRL-AUTHZ-ROLE": "Role-based authorization enforcement",
        "CTRL-BUDGET-GUARD": "Budget policy guardrail enforcement",
        "CTRL-READINESS-SIGNED": "Readiness certification integrity and evidence signing",
        "CTRL-SCALE-CERT": "Scale and load certification evidence",
    }

    try:
        upsert = client.put(
            f"/runtime-config/{key}",
            json={
                "config_value": json.dumps(payload),
                "description": "test override",
            },
            headers=_approved_headers("admin-compliance-runtime", "security-compliance-runtime"),
        )
        assert upsert.status_code == 200

        controls = client.get(
            "/compliance/controls",
            headers={"X-Actor-Role": "Auditor", "X-Actor-Id": "aud-compliance-runtime"},
        )
        assert controls.status_code == 200
        items = controls.json()
        target = next((item for item in items if item["control_id"] == "CTRL-AUDIT-IMMUTABLE"), None)
        assert target is not None
        assert target["title"] == "Runtime Catalog Title Override"
    finally:
        client.delete(
            f"/runtime-config/{key}",
            headers=_approved_headers("admin-compliance-runtime-cleanup", "security-compliance-runtime-cleanup"),
        )
