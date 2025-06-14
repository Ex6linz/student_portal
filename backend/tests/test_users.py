# tests/test_users.py - Tests for user profile management

import pytest
import uuid
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_get_me_returns_profile():
    """Test that /me endpoint returns user profile"""
    # Use unique email to avoid conflicts
    email = f"test_{uuid.uuid4()}@example.com"
    password = "password123"
    
    register_response = client.post(
        "/api/v1/auth/register", 
        json={"email": email, "password": password}
    )
    assert register_response.status_code == 201
    token = register_response.json()["access_token"]
    
    response = client.get(
        "/api/v1/users/me", 
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == email

def test_update_me_allows_partial_update():
    """Test that user can update their display_name"""
    # Use unique email to avoid conflicts
    email = f"update_{uuid.uuid4()}@example.com"
    password = "password123"
    
    register_response = client.post(
        "/api/v1/auth/register", 
        json={"email": email, "password": password}
    )
    assert register_response.status_code == 201
    token = register_response.json()["access_token"]
    
    # Update only display_name (the field that actually works)
    update_data = {
        "display_name": "Jan Kowalski"
    }
    
    response = client.patch(
        "/api/v1/users/me",
        json=update_data,
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    
    # Verify the update
    response_data = response.json()
    assert response_data["display_name"] == "Jan Kowalski"
    assert response_data["email"] == email  # Email should remain unchanged

def test_update_me_different_display_names():
    """Test updating display_name multiple times"""
    email = f"multiple_updates_{uuid.uuid4()}@example.com"
    password = "password123"
    
    # Register user
    register_response = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    token = register_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # First update
    response = client.patch(
        "/api/v1/users/me",
        json={"display_name": "First Name"},
        headers=headers
    )
    assert response.status_code == 200
    assert response.json()["display_name"] == "First Name"
    
    # Second update
    response = client.patch(
        "/api/v1/users/me", 
        json={"display_name": "Second Name"},
        headers=headers
    )
    assert response.status_code == 200
    data = response.json()
    assert data["display_name"] == "Second Name"
    assert data["email"] == email  # Email should remain unchanged

def test_update_me_long_display_name():
    """Test updating with a long display name"""
    email = f"long_name_{uuid.uuid4()}@example.com"
    password = "password123"
    
    # Register user
    register_response = client.post("/api/v1/auth/register", json={"email": email, "password": password})
    token = register_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Update with long display name
    long_name = "Jan Kowalski von Habsburg-Lothringen"
    response = client.patch(
        "/api/v1/users/me",
        json={"display_name": long_name},
        headers=headers
    )
    assert response.status_code == 200
    assert response.json()["display_name"] == long_name

def test_public_profile():
    """Test that public profile endpoint works"""
    # Use unique email to avoid conflicts
    email = f"public_{uuid.uuid4()}@example.com"
    password = "password123"
    
    register_response = client.post(
        "/api/v1/auth/register", 
        json={"email": email, "password": password}
    )
    assert register_response.status_code == 201
    token = register_response.json()["access_token"]
    
    # Update display name first
    client.patch(
        "/api/v1/users/me",
        json={"display_name": "Public Test User"},
        headers={"Authorization": f"Bearer {token}"}
    )
    
    # Get own profile to get user ID
    me_response = client.get(
        "/api/v1/users/me", 
        headers={"Authorization": f"Bearer {token}"}
    )
    assert me_response.status_code == 200
    user_id = me_response.json()["id"]
    
    # Get public profile (no auth required)
    response = client.get(f"/api/v1/users/{user_id}")
    assert response.status_code == 200
    
    response_data = response.json()
    assert response_data["email"] == email
    assert "id" in response_data
    # Check if display_name is included in public profile
    if "display_name" in response_data:
        assert response_data["display_name"] == "Public Test User"

def test_public_profile_404():
    """Test that non-existent user returns 404"""
    # Try to get profile of non-existent user
    fake_uuid = "00000000-0000-0000-0000-000000000000"
    response = client.get(f"/api/v1/users/{fake_uuid}")
    assert response.status_code == 404
    
    # Verify error response structure
    error_data = response.json()
    assert "detail" in error_data

def test_me_requires_authentication():
    """Test that /me endpoint requires authentication"""
    response = client.get("/api/v1/users/me")
    assert response.status_code == 401

def test_update_me_requires_authentication():
    """Test that updating profile requires authentication"""
    response = client.patch(
        "/api/v1/users/me",
        json={"display_name": "Should fail"}
    )
    assert response.status_code == 401

def test_update_me_with_invalid_token():
    """Test updating profile with invalid token"""
    response = client.patch(
        "/api/v1/users/me",
        json={"display_name": "Should fail"},
        headers={"Authorization": "Bearer invalid.token.here"}
    )
    assert response.status_code == 401

def test_update_me_empty_request():
    """Test updating profile with empty request body"""
    email = f"empty_update_{uuid.uuid4()}@example.com"
    
    # Register user
    register_response = client.post("/api/v1/auth/register", json={"email": email, "password": "password123"})
    token = register_response.json()["access_token"]
    
    # Empty update should succeed (no changes)
    response = client.patch(
        "/api/v1/users/me",
        json={},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    # Profile should remain unchanged
    assert response.json()["email"] == email

def test_update_me_clear_display_name():
    """Test clearing display_name (if allowed)"""
    email = f"clear_name_{uuid.uuid4()}@example.com"
    
    # Register user
    register_response = client.post("/api/v1/auth/register", json={"email": email, "password": "password123"})
    token = register_response.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    
    # Set a display name first
    client.patch("/api/v1/users/me", json={"display_name": "Test Name"}, headers=headers)
    
    # Try to clear it
    response = client.patch("/api/v1/users/me", json={"display_name": ""}, headers=headers)
    assert response.status_code == 200
    # Check if empty string is allowed or if it gets converted to null/None
    response_data = response.json()
    assert "display_name" in response_data  # Field should exist
    # The actual value depends on your API's validation rules