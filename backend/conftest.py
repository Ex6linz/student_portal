import sys
import os
import pytest
from httpx import AsyncClient
from app.main import app
from app.core.database import get_session
from app.auth.router import router as auth_router
from fastapi_limiter import FastAPILimiter
from app.core.limiter import limiter, _rate_limit_exceeded_handler

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import pytest
from app.main import limiter

@pytest.fixture
def client():
    from app.main import app
    with app.test_client() as client:
        yield client

@pytest.fixture(autouse=True)
def _reset_rate_limits():
    """Czyści stany SlowAPI między testami."""
    yield
    limiter.reset()

@pytest.fixture(scope="session")
def anyio_backend():
    return "asyncio"

@pytest.fixture
async def client():
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

@pytest.fixture
async def auth_headers(client):
    # rejestracja
    email = "test@local"
    pw = "Secret123!"
    await client.post("/auth/register", json={"email": email, "password": pw})
    login = await client.post("/auth/login", json={"email": email, "password": pw})
    token = login.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}

@pytest.fixture
async def user_factory(get_session):
    async def _create(email: str, password: str):
        # użyj istniejącego endpointu register, lub bezpośrednio wbij rekord do DB
        ...

    return _create