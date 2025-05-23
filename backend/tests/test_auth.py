# tests/test_auth.py
from fastapi.testclient import TestClient
from app.main import app
import psycopg2

client = TestClient(app)

def test_register_and_login():
    # test rejestracji
    r = client.post("/auth/register", json={"email": "a@test.io", "password": "123456"})
    assert r.status_code == 201

    # test logowania
    login_res = client.post("/auth/login", json={"email": "a@test.io", "password": "123456"})
    assert login_res.status_code == 200
    data = login_res.json()
    assert "access_token" in data