import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock
from fastapi.testclient import TestClient


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session", autouse=True)
def mock_redis_and_limiters():
    """Mock Redis connection and rate limiters for all tests"""
    
    # Mock Redis
    with patch('redis.asyncio.from_url') as mock_redis_client:
        mock_client = AsyncMock()
        mock_redis_client.return_value = mock_client
        
        # Mock FastAPILimiter methods
        with patch('fastapi_limiter.FastAPILimiter.init') as mock_init, \
             patch('fastapi_limiter.FastAPILimiter.close') as mock_close, \
             patch('fastapi_limiter.depends.RateLimiter') as mock_rate_limiter:
            
            mock_init.return_value = None
            mock_close.return_value = None
            
            # Make RateLimiter return a dummy dependency function
            def dummy_dependency():
                return None
            
            mock_rate_limiter.return_value = dummy_dependency
            
            yield mock_client


@pytest.fixture(scope="session")
def client(mock_redis_and_limiters):
    """Create test client with mocked Redis and rate limiters"""
    # Import here to ensure mocks are in place
    from app.main import app
    
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture(scope="module")
def auth_headers(client):
    """Create authenticated user and return auth headers"""
    # register & login one user
    email = "forum_user@test.io"
    pw = "Forum123!"
    client.post("/auth/register", json={"email": email, "password": pw})
    login = client.post("/auth/login", json={"email": email, "password": pw})
    token = login.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def reset_rate_limits():
    """Clear SlowAPI state between tests."""
    from app.core.limiter import limiter
    yield
    try:
        limiter.reset()
    except Exception:
        pass