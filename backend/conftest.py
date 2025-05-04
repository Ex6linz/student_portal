import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest

@pytest.fixture
def client():
    from app.main import app
    with app.test_client() as client:
        yield client