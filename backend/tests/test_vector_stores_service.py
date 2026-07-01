import pytest
from backend.app.services.vector_stores import VectorStoresService

class TestVectorStoresService:
    def test_get_vector_stores(self, monkeypatch):
        mock_data = [
            {"id": "1", "name": "Store 1"},
            {"id": "2", "name": "Store 2"}
        ]
        
        def mock_open(*args, **kwargs):
            class MockFile:
                def read(self):
                    return json.dumps(mock_data)
            return MockFile()
        
        monkeypatch.setattr('builtins.open', mock_open)
        
        service = VectorStoresService()
        vector_stores = service.get_vector_stores()
        
        assert vector_stores == mock_data
