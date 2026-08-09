from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
ADMIN_HEADERS = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-upstream"}

def test_v1_vector_stores_store_id_missing_auth():
    response = client.get("/v1/vector_stores/{store_id}")
    assert response.status_code in (401, 403)

def test_v1_vector_stores_store_id_deny_role():
    response = client.get(
        "/v1/vector_stores/{store_id}",
        headers={"X-Actor-Role": "Guest", "X-Actor-Id": "guest-test"},
    )
    assert response.status_code in (403, 404)

def test_v1_vector_stores_store_id_admin_status():
    response = client.get("/v1/vector_stores/{store_id}", headers=ADMIN_HEADERS)
    assert response.status_code in (200, 404, 422, 501)
