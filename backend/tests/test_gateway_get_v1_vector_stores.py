from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
ADMIN_HEADERS = {"X-Actor-Role": "Platform Admin", "X-Actor-Id": "admin-upstream"}

def test_v1_vector_stores_missing_auth():
    response = client.get("/v1/vector_stores")
    assert response.status_code in (401, 403)

def test_v1_vector_stores_deny_role():
    response = client.get(
        "/v1/vector_stores",
        headers={"X-Actor-Role": "Guest", "X-Actor-Id": "guest-test"},
    )
    assert response.status_code in (403, 404)

def test_v1_vector_stores_admin_status():
    response = client.get("/v1/vector_stores", headers=ADMIN_HEADERS)
    assert response.status_code in (200, 404, 422, 501)
