# tests/test_rate_limit.py
from fastapi.testclient import TestClient
import pytest
from app.main import app
import psycopg2

client = TestClient(app)

def test_login_rate_limit():
    import uuid
    
    # Generowanie unikalnego adresu email dla tego testu
    unique_email = f"test_{uuid.uuid4()}@example.com"
    password = "123456"
    
    # Rejestracja nowego użytkownika
    client.post("/auth/register", json={"email": unique_email, "password": password})
    
    # Test rate limitingu
    for _ in range(5):
        r = client.post("/auth/login", json={"email": unique_email, "password": password})
        assert r.status_code in (200, 401)
    
    # Szóste żądanie powinno zostać ograniczone
    r6 = client.post("/auth/login", json={"email": unique_email, "password": password})
    assert r6.status_code == 429