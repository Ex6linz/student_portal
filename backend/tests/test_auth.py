from httpx import AsyncClient
from app.main import app

async def test_register_and_login():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        r = await ac.post("/auth/register", json={"email": "a@test.io", "password": "123456"})
        assert r.status_code == 201
        token = (await ac.post("/auth/login", data={"username": "a@test.io", "password": "123456"})).json()
        assert "access_token" in token