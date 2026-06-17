from app.main import app
from fastapi.testclient import TestClient

client = TestClient(app)


def test_openapi_documents_platform_feedback_swagger_contracts():
    response = client.get("/openapi.json")
    assert response.status_code == 200
    document = response.json()
    paths = document["paths"]

    create = paths["/platform/feedback"]["post"]
    assert create["summary"] == "Submit operator feedback"
    assert "operator_feedback" in (create.get("description") or "")
    assert "platform.feedback.create" in (create.get("description") or "")
    assert "403" in create["responses"]
    assert "422" in create["responses"]

    create_body_ref = create["requestBody"]["content"]["application/json"]["schema"]
    schema_name = "OperatorFeedbackCreateRequest"
    if "$ref" in create_body_ref:
        ref = create_body_ref["$ref"].split("/")[-1]
        assert ref == schema_name
        assert schema_name in document["components"]["schemas"]
    else:
        assert "comment" in create_body_ref.get("properties", {})

    list_feedback = paths["/platform/feedback"]["get"]
    assert list_feedback["summary"] == "List operator feedback"
    assert "403" in list_feedback["responses"]

    analytics = paths["/platform/feedback/analytics"]["get"]
    assert analytics["summary"] == "Operator feedback analytics"
    assert "since_hours" in str(analytics.get("parameters", []))

    triage = paths["/platform/feedback/{feedback_id}/actions"]["post"]
    assert triage["summary"] == "Apply feedback triage action"
    assert "404" in triage["responses"]
    assert "403" in triage["responses"]

    operational = paths["/platform/operational-status"]["get"]
    assert operational["summary"] == "Platform operational posture"
    assert "maintenance" in (operational.get("description") or "").lower()


def test_openapi_documents_governance_and_health_swagger_contracts():
    response = client.get("/openapi.json")
    assert response.status_code == 200
    document = response.json()
    paths = document["paths"]
    tags = {item["name"]: item for item in document.get("tags", [])}

    assert "Platform" in tags
    assert "operator_feedback" in tags["Platform"]["description"].lower()
    assert "Governance" in tags
    assert "ui coverage" in tags["Governance"]["description"].lower()

    coverage = paths["/governance/ui-coverage"]["get"]
    assert coverage["summary"] == "UI coverage gap report"
    assert "403" in coverage["responses"]

    inventory = paths["/governance/ui-coverage/inventory"]["get"]
    assert inventory["summary"] == "Machine-readable API inventory"

    health = paths["/health"]["get"]
    assert health["summary"] == "Service health"
    assert "runtime config cache" in (health.get("description") or "").lower()
