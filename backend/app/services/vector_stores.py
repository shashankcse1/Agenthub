from typing import List
import json

class VectorStoresService:
    def __init__(self):
        self.vector_stores_json = "/path/to/vector_stores.json"

    def get_vector_stores(self) -> List[dict]:
        with open(self.vector_stores_json, 'r') as file:
            vector_stores_data = json.load(file)
        return vector_stores_data
