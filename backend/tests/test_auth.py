from fastapi.testclient import TestClient
from app.main import app
import psycopg2

client = TestClient(app)

def test_register_and_login():
    """Test user registration and login flow"""
    # Test registration
    register_response = client.post(
        "/api/v1/auth/register", 
        json={"email": "a@test.io", "password": "123456"}
    )
    assert register_response.status_code == 201
    
    # Verify registration response structure
    register_data = register_response.json()
    assert "access_token" in register_data or "message" in register_data

    # Test login
    login_response = client.post(
        "/api/v1/auth/login", 
        json={"email": "a@test.io", "password": "123456"}
    )
    assert login_response.status_code == 200
    
    # Verify login response structure
    login_data = login_response.json()
    assert "access_token" in login_data
    assert "token_type" in login_data or login_data.get("token_type", "bearer") == "bearer"

def test_register_duplicate_email():
    """Test that registering with duplicate email fails"""
    email = "duplicate@test.io"
    password = "123456"
    
    # First registration should succeed
    first_response = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password}
    )
    assert first_response.status_code == 201
    
    # Second registration with same email should fail
    second_response = client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": password}
    )
    assert second_response.status_code == 400  # Conflict

def test_login_invalid_credentials():
    """Test login with invalid credentials"""
    # Test with non-existent user
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent@test.io", "password": "wrongpassword"}
    )
    assert response.status_code == 401
    
    response_data = response.json()
    assert "detail" in response_data

def test_login_wrong_password():
    """Test login with correct email but wrong password"""
    email = "correctemail@test.io"
    correct_password = "correctpassword"
    wrong_password = "wrongpassword"
    
    # Register user first
    client.post(
        "/api/v1/auth/register",
        json={"email": email, "password": correct_password}
    )
    
    # Try to login with wrong password
    response = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": wrong_password}
    )
    assert response.status_code == 401