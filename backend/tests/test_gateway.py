from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app import main, schemas
from backend.app.api.deps import get_db
from backend.app.crud import vector_stores as crud_vector_stores
from backend.app.schemas.vector_stores import VectorStoreCreate

def test_read_vector_stores(client: TestClient, db: Session):
    response = client.get("/v1/vector_stores")
    assert response.status_code == 200
    data = response.json()
    assert "vector_stores" in data

def test_create_vector_store(client: TestClient, db: Session):
    vector_store_in = VectorStoreCreate(name="test_vector_store", description="Test vector store")
    response = client.post("/v1/vector_stores", json=vector_store_in.dict())
    assert response.status_code == 200
    data = response.json()
    assert "id" in data

def test_update_vector_store(client: TestClient, db: Session):
    vector_store_in = VectorStoreCreate(name="test_vector_store", description="Test vector store")
    created_vector_store = crud_vector_stores.create(db=db, obj_in=vector_store_in)
    updated_vector_store = VectorStoreUpdate(name="updated_test_vector_store", description="Updated test vector store")
    response = client.patch(f"/v1/vector_stores/{created_vector_store.id}", json=updated_vector_store.dict())
    assert response.status_code == 200
    data = response.json()
    assert "id" in data

def test_delete_vector_store(client: TestClient, db: Session):
    vector_store_in = VectorStoreCreate(name="test_vector_store", description="Test vector store")
    created_vector_store = crud_vector_stores.create(db=db, obj_in=vector_store_in)
    response = client.delete(f"/v1/vector_stores/{created_vector_store.id}")
    assert response.status_code == 200
    data = response.json()
    assert "id" in data
