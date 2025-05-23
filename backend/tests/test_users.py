# tests/test_users.py
import pytest
from httpx import AsyncClient
from fastapi.testclient import TestClient
from app.main import app

# Opcja 1: Użycie TestClient (synchroniczny)
client = TestClient(app)

def test_get_me_returns_profile():
    # Najpierw zaloguj użytkownika i uzyskaj token
    register_response = client.post(
        "/auth/register", 
        json={"email": "test@example.com", "password": "password123"}
    )
    assert register_response.status_code == 201
    token = register_response.json()["access_token"]
    
    # Wykonaj zapytanie o profil z tokenem
    response = client.get(
        "/users/me", 
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "test@example.com"

def test_update_me_allows_partial_update():
    # Logowanie i uzyskanie tokenu
    register_response = client.post(
        "/auth/register", 
        json={"email": "update@example.com", "password": "password123"}
    )
    assert register_response.status_code == 201
    token = register_response.json()["access_token"]
    
    # Aktualizacja pojedynczego pola (display_name)
    response = client.patch(
        "/users/me",
        json={"display_name": "Jan Kowalski",
              "bio": "Student at XYZ University",
              "avatar_url": "https://cdn.pixabay.com/photo/2016/12/23/08/15/graphics-1926979_960_720.jpg"},
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert response.json()["display_name"] == "Jan Kowalski"

def test_public_profile():
    # Zarejestruj użytkownika i uzyskaj jego ID
    register_response = client.post(
        "/auth/register", 
        json={"email": "public@example.com", "password": "password123"}
    )
    assert register_response.status_code == 201
    token = register_response.json()["access_token"]
    
    # Pobierz ID użytkownika z /users/me
    me_response = client.get(
        "/users/me", 
        headers={"Authorization": f"Bearer {token}"}
    )
    user_id = me_response.json()["id"]
    
    # Pobierz publiczny profil
    response = client.get(f"/users/{user_id}")
    assert response.status_code == 200
    assert response.json()["email"] == "public@example.com"

def test_public_profile_404():
    # Sprawdź zachowanie dla nieistniejącego ID
    response = client.get("/users/00000000-0000-0000-0000-000000000000")
    assert response.status_code == 404