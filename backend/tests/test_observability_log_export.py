from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def _auditor_headers(actor_id: str = "aud-obs-export") -> dict[str, str]:
    return {"X-Actor-Role": "Auditor", "X-Actor-Id": actor_id}


def test_observability_logs_export_csv():
    response = client.get("/observability/logs/export?format=csv&limit=10", headers=_auditor_headers())
    assert response.status_code == 200
    assert "text/csv" in response.headers.get("content-type", "")
    assert "timestamp,actor_id" in response.text.splitlines()[0]


def test_observability_logs_export_json():
    response = client.get("/observability/logs/export?format=json&limit=5", headers=_auditor_headers("aud-obs-export-json"))
    assert response.status_code == 200
    assert "application/json" in response.headers.get("content-type", "")
