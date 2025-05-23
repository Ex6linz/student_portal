# tests/test_refresh.py
from fastapi.testclient import TestClient
from app.main import app
import psycopg2

client = TestClient(app)

def test_refresh_flow():
    # register + login
    client.post("/auth/register", json={"email": "foo@bar.io", "password": "P@ssw0rd"})
    login_res = client.post("/auth/login", json={"email": "foo@bar.io", "password": "P@ssw0rd"})
    rt = login_res.cookies.get("refresh_token")
    assert rt is not None

    # refresh
    refresh_res = client.post("/auth/refresh", cookies={"refresh_token": rt})
    assert refresh_res.status_code == 200
    data = refresh_res.json()
    assert "access_token" in data