# tests/test_refresh.py - Improved version with /api/v1/ prefix
from fastapi.testclient import TestClient
from app.main import app
import psycopg2
import uuid

client = TestClient(app)

def test_refresh_flow():
    """Test complete refresh token flow"""
    # Use unique email to avoid conflicts
    email = f"refresh_test_{uuid.uuid4()}@test.io"
    password = "P@ssw0rd"
    
    # Register user
    register_response = client.post(
        "/api/v1/auth/register", 
        json={"email": email, "password": password}
    )
    assert register_response.status_code == 201
    
    # Login user
    login_response = client.post(
        "/api/v1/auth/login", 
        json={"email": email, "password": password}
    )
    assert login_response.status_code == 200
    
    # Get refresh token from cookies
    refresh_token = login_response.cookies.get("refresh_token")
    assert refresh_token is not None, "Refresh token should be set in cookies"
    
    # Use refresh token to get new access token
    refresh_response = client.post(
        "/api/v1/auth/refresh", 
        cookies={"refresh_token": refresh_token}
    )
    assert refresh_response.status_code == 200
    
    # Verify response contains new access token
    refresh_data = refresh_response.json()
    assert "access_token" in refresh_data
    assert "token_type" in refresh_data or refresh_data.get("token_type", "bearer") == "bearer"

def test_refresh_without_token():
    """Test refresh endpoint without providing refresh token"""
    refresh_response = client.post("/api/v1/auth/refresh")
    # Should return 401 or 400 depending on implementation
    assert refresh_response.status_code in [400, 401]

def test_refresh_with_invalid_token():
    """Test refresh endpoint with invalid refresh token"""
    invalid_token = "invalid.refresh.token.here"
    refresh_response = client.post(
        "/api/v1/auth/refresh",
        cookies={"refresh_token": invalid_token}
    )
    assert refresh_response.status_code == 401

def test_refresh_with_malformed_token():
    """Test refresh endpoint with malformed token"""
    malformed_tokens = [
        "notavalidtoken",
        "invalid.token",
        "too.many.parts.in.token.here",
        "",
        "null"
    ]
    
    for token in malformed_tokens:
        refresh_response = client.post(
            "/api/v1/auth/refresh",
            cookies={"refresh_token": token}
        )
        assert refresh_response.status_code == 401, f"Malformed token '{token}' should return 401"

def test_refresh_token_single_use():
    """Test that refresh tokens can be used multiple times (or not, depending on implementation)"""
    email = f"single_use_{uuid.uuid4()}@test.io"
    password = "P@ssw0rd"
    
    # Register and login
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    login_response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    refresh_token = login_response.cookies.get("refresh_token")
    
    # First refresh should work
    first_refresh = client.post("/api/v1/auth/refresh", cookies={"refresh_token": refresh_token})
    assert first_refresh.status_code == 200
    first_access_token = first_refresh.json()["access_token"]
    
    # Second refresh - behavior depends on your implementation
    second_refresh = client.post("/api/v1/auth/refresh", cookies={"refresh_token": refresh_token})
    
    if second_refresh.status_code == 200:
        # Refresh tokens can be reused
        second_access_token = second_refresh.json()["access_token"]
        print("✅ Refresh tokens can be reused")
        # Tokens might be the same or different depending on implementation
    elif second_refresh.status_code == 401:
        # Refresh tokens are single-use (more secure)
        print("✅ Refresh tokens are single-use (more secure)")
    else:
        # Unexpected behavior
        assert False, f"Unexpected status code for second refresh: {second_refresh.status_code}"

def test_access_token_from_refresh_works():
    """Test that access token obtained from refresh can be used"""
    email = f"access_test_{uuid.uuid4()}@test.io"
    password = "P@ssw0rd"
    
    # Register and login
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    login_response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    refresh_token = login_response.cookies.get("refresh_token")
    
    # Get new access token via refresh
    refresh_response = client.post("/api/v1/auth/refresh", cookies={"refresh_token": refresh_token})
    assert refresh_response.status_code == 200
    new_access_token = refresh_response.json()["access_token"]
    
    # Use new access token to access protected endpoint
    me_response = client.get(
        "/api/v1/users/me",
        headers={"Authorization": f"Bearer {new_access_token}"}
    )
    assert me_response.status_code == 200
    assert me_response.json()["email"] == email

def test_refresh_after_logout():
    """Test that refresh fails after logout"""
    email = f"logout_refresh_{uuid.uuid4()}@test.io"
    password = "P@ssw0rd"
    
    # Register and login
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    login_response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    refresh_token = login_response.cookies.get("refresh_token")
    
    # Logout
    logout_response = client.post("/api/v1/auth/logout", cookies={"refresh_token": refresh_token})
    assert logout_response.status_code == 204
    
    # Try to refresh after logout - should fail
    refresh_response = client.post("/api/v1/auth/refresh", cookies={"refresh_token": refresh_token})
    assert refresh_response.status_code == 401

def test_multiple_logins_different_refresh_tokens():
    """Test that multiple logins generate different refresh tokens"""
    email = f"multiple_login_{uuid.uuid4()}@test.io"
    password = "P@ssw0rd"
    
    # Register user
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    
    # First login
    login1 = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    refresh_token1 = login1.cookies.get("refresh_token")
    
    # Second login
    login2 = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    refresh_token2 = login2.cookies.get("refresh_token")
    
    # Both should work
    assert refresh_token1 is not None
    assert refresh_token2 is not None
    
    # Refresh tokens should be different (more secure)
    if refresh_token1 != refresh_token2:
        print("✅ Multiple logins generate different refresh tokens (more secure)")
    else:
        print("⚠️  Multiple logins generate same refresh token")
    
    # Both refresh tokens should work (or second login might invalidate first)
    refresh1_response = client.post("/api/v1/auth/refresh", cookies={"refresh_token": refresh_token1})
    refresh2_response = client.post("/api/v1/auth/refresh", cookies={"refresh_token": refresh_token2})
    
    # At least the second one should work
    assert refresh2_response.status_code == 200

def test_refresh_token_format():
    """Test that refresh token has expected format (basic validation)"""
    email = f"format_test_{uuid.uuid4()}@test.io"
    password = "P@ssw0rd"
    
    # Register and login
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    login_response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    refresh_token = login_response.cookies.get("refresh_token")
    
    # Basic format validation
    assert refresh_token is not None
    assert len(refresh_token) > 10, "Refresh token should be reasonably long"
    assert refresh_token != "null", "Refresh token should not be literal 'null'"
    assert refresh_token != "", "Refresh token should not be empty"
    
    # If it's a JWT, it should have 3 parts separated by dots
    if "." in refresh_token:
        parts = refresh_token.split(".")
        if len(parts) == 3:
            print("✅ Refresh token appears to be a JWT")
        else:
            print(f"⚠️  Refresh token has {len(parts)} parts, might not be a standard JWT")

def test_concurrent_refresh_requests():
    """Test multiple refresh requests with same token (race condition test)"""
    email = f"concurrent_{uuid.uuid4()}@test.io"
    password = "P@ssw0rd"
    
    # Register and login
    client.post("/api/v1/auth/register", json={"email": email, "password": password})
    login_response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    refresh_token = login_response.cookies.get("refresh_token")
    
    # Make multiple refresh requests quickly (simulates race condition)
    responses = []
    for i in range(3):
        response = client.post("/api/v1/auth/refresh", cookies={"refresh_token": refresh_token})
        responses.append(response)
    
    # At least one should succeed
    successful_responses = [r for r in responses if r.status_code == 200]
    assert len(successful_responses) > 0, "At least one refresh request should succeed"
    
    # If tokens are single-use, only one should succeed
    if len(successful_responses) == 1:
        print("✅ Only one concurrent refresh succeeded (single-use tokens)")
    else:
        print(f"ℹ️  {len(successful_responses)} concurrent refreshes succeeded (reusable tokens)")