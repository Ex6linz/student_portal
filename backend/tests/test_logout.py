# tests/test_logout.py
from fastapi.testclient import TestClient
from app.main import app
import psycopg2


client = TestClient(app)

def test_logout_revokes_rt():
    # register + login
    client.post("/auth/register", json={"email": "bob@uni.io", "password": "P@ssw0rd"})
    login_res = client.post("/auth/login", json={"email": "bob@uni.io", "password": "P@ssw0rd"})
    rt = login_res.cookies.get("refresh_token")
    assert rt is not None

    # logout
    logout_res = client.post("/auth/logout", cookies={"refresh_token": rt})
    assert logout_res.status_code == 204

    # refresh po logout should być 401
    refresh_res = client.post("/auth/refresh", cookies={"refresh_token": rt})
    assert refresh_res.status_code == 401