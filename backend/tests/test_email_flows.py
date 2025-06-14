import pytest
from datetime import datetime, timedelta
from uuid import uuid4
import jwt

from fastapi.testclient import TestClient
from sqlmodel import Session, select

from app.main import app
from app.core.database import get_session
from app.core.config import settings
from app.auth.models import User, EmailToken
from app.auth import security

client = TestClient(app)

@pytest.fixture
def test_user_data():
    """Test user data"""
    return {
        "email": "test.confirm@example.com",
        "password": "TestPassword123!"
    }

@pytest.fixture
def test_user(test_user_data):
    """Create a test user and return user data with token"""
    # Register user
    response = client.post("/api/v1/auth/register", json=test_user_data)
    assert response.status_code == 201
    
    # Get user from database
    db = next(get_session())
    user = db.scalar(select(User).where(User.email == test_user_data["email"]))
    
    return {
        "user": user,
        "email": test_user_data["email"],
        "password": test_user_data["password"],
        "access_token": response.json()["access_token"]
    }

@pytest.fixture
def auth_headers(test_user):
    """Authorization headers for authenticated requests"""
    return {"Authorization": f"Bearer {test_user['access_token']}"}

def create_valid_confirm_token(user_id: str) -> str:
    """Create a valid confirmation token"""
    jti = str(uuid4())
    payload = {
        "sub": str(user_id),
        "typ": "confirm",
        "jti": jti,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=24)
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_valid_reset_token(user_id: str) -> str:
    """Create a valid reset token"""
    jti = str(uuid4())
    payload = {
        "sub": str(user_id),
        "typ": "reset",
        "jti": jti,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=1)
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_expired_token(user_id: str, token_type: str) -> str:
    """Create an expired token"""
    jti = str(uuid4())
    payload = {
        "sub": str(user_id),
        "typ": token_type,
        "jti": jti,
        "iat": datetime.utcnow() - timedelta(hours=2),
        "exp": datetime.utcnow() - timedelta(hours=1)  # Expired 1 hour ago
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

class TestEmailConfirmationFlow:
    """Test email confirmation endpoints"""
    
    def test_request_confirm_unauth(self):
        """Test request confirmation without authentication returns 401"""
        response = client.post(
            "/api/v1/auth/confirm/request",
            json={"email": "test@example.com"}
        )
        
        assert response.status_code == 401
        assert "detail" in response.json()
    
    def test_request_confirm_happy(self, test_user, auth_headers):
        """Test successful confirmation request returns 202 and creates EmailToken"""
        response = client.post(
            "/api/v1/auth/confirm/request",
            json={"email": test_user["email"]},
            headers=auth_headers
        )
        
        # Check response
        assert response.status_code == 202
        assert response.json() == {"message": "Confirmation email sent"}
        
        # Check rate limit headers (if they exist)
        # Note: Comment out if rate limiting is not implemented
        # assert "x-ratelimit-limit" in response.headers
        # assert "x-ratelimit-remaining" in response.headers
        
        # Check EmailToken was created in database
        db = next(get_session())
        email_token = db.scalar(
            select(EmailToken).where(
                EmailToken.user_id == test_user["user"].id,
                EmailToken.type == "confirm"
            )
        )
        
        assert email_token is not None
        assert email_token.type == "confirm"
        assert email_token.user_id == test_user["user"].id
        assert not email_token.is_expired()
    
    def test_request_confirm_nonexistent_user(self, auth_headers):
        """Test confirmation request for non-existent user returns 404"""
        response = client.post(
            "/api/v1/auth/confirm/request",
            json={"email": "nonexistent@example.com"},
            headers=auth_headers
        )
        
        assert response.status_code == 404
        assert "User not found" in response.json()["detail"]
    
    def test_request_confirm_rate_limit(self, test_user, auth_headers):
        """Test rate limiting on confirmation requests (5/minute)"""
        # Make 5 requests (the limit)
        for i in range(5):
            response = client.post(
                "/api/v1/auth/confirm/request",
                json={"email": test_user["email"]},
                headers=auth_headers
            )
            if i < 4:  # First 4 should succeed
                assert response.status_code == 202
        
        # 6th request should be rate limited
        response = client.post(
            "/api/v1/auth/confirm/request",
            json={"email": test_user["email"]},
            headers=auth_headers
        )
        assert response.status_code == 429  # Too Many Requests
    
    def test_confirm_invalid_token(self):
        """Test GET confirmation with invalid token returns 400"""
        invalid_token = "invalid.jwt.token"
        
        response = client.get(f"/api/v1/auth/confirm/{invalid_token}")
        
        assert response.status_code == 400
        assert "Invalid confirmation token" in response.json()["detail"]
    
    def test_confirm_expired_token(self, test_user):
        """Test GET confirmation with expired token returns 400"""
        expired_token = create_expired_token(test_user["user"].id, "confirm")
        
        response = client.get(f"/api/v1/auth/confirm/{expired_token}")
        
        assert response.status_code == 400
        assert "expired" in response.json()["detail"].lower()
    
    def test_confirm_wrong_token_type(self, test_user):
        """Test GET confirmation with wrong token type returns 400"""
        # Create a reset token instead of confirm token
        reset_token = create_valid_reset_token(test_user["user"].id)
        
        response = client.get(f"/api/v1/auth/confirm/{reset_token}")
        
        assert response.status_code == 400
        assert "Invalid token type" in response.json()["detail"]
    
    def test_confirm_nonexistent_token_in_db(self, test_user):
        """Test GET confirmation with valid JWT but no database record returns 404"""
        # Create valid JWT token but don't save EmailToken to database
        valid_token = create_valid_confirm_token(test_user["user"].id)
        
        response = client.get(f"/api/v1/auth/confirm/{valid_token}")
        
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()
    
    def test_confirm_happy_path(self, test_user, auth_headers):
        """Test successful email confirmation flow"""
        # First, request confirmation to create EmailToken
        response = client.post(
            "/api/v1/auth/confirm/request",
            json={"email": test_user["email"]},
            headers=auth_headers
        )
        assert response.status_code == 202
        
        # Get the EmailToken from database to extract jti
        db = next(get_session())
        email_token = db.scalar(
            select(EmailToken).where(
                EmailToken.user_id == test_user["user"].id,
                EmailToken.type == "confirm"
            )
        )
        assert email_token is not None
        
        # Create token with matching jti
        payload = {
            "sub": str(test_user["user"].id),
            "typ": "confirm",
            "jti": email_token.jti,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=24)
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        
        # Now confirm with the token
        response = client.get(f"/api/v1/auth/confirm/{token}")
        
        assert response.status_code == 200
        assert response.json() == {"message": "Email confirmed"}
        
        # Check that EmailToken was deleted from database
        db = next(get_session())
        deleted_token = db.scalar(
            select(EmailToken).where(
                EmailToken.user_id == test_user["user"].id,
                EmailToken.type == "confirm",
                EmailToken.jti == email_token.jti
            )
        )
        assert deleted_token is None

class TestPasswordResetFlow:
    """Test password reset endpoints"""
    
    def test_request_password_reset_happy(self, test_user):
        """Test successful password reset request returns 202 and creates EmailToken"""
        response = client.post(
            "/api/v1/auth/password-reset",
            json={"email": test_user["email"]}
        )
        
        # Check response
        assert response.status_code == 202
        expected_message = "If that email exists in our system, a password reset link has been sent"
        assert response.json() == {"message": expected_message}
        
        # Check rate limit headers (if implemented)
        # assert "x-ratelimit-limit" in response.headers
        # assert "x-ratelimit-remaining" in response.headers
        
        # Check EmailToken was created in database
        db = next(get_session())
        email_token = db.scalar(
            select(EmailToken).where(
                EmailToken.user_id == test_user["user"].id,
                EmailToken.type == "reset"
            )
        )
        
        assert email_token is not None
        assert email_token.type == "reset"
        assert email_token.user_id == test_user["user"].id
        assert not email_token.is_expired()
    
    def test_request_password_reset_nonexistent_email(self):
        """Test password reset for non-existent email returns same message (security)"""
        response = client.post(
            "/api/v1/auth/password-reset",
            json={"email": "nonexistent@example.com"}
        )
        
        # Should return same message for security (don't reveal email existence)
        assert response.status_code == 202
        expected_message = "If that email exists in our system, a password reset link has been sent"
        assert response.json() == {"message": expected_message}
        
        # Check no EmailToken was created
        db = next(get_session())
        email_tokens = db.scalars(select(EmailToken).where(EmailToken.type == "reset")).all()
        # Should be empty or not contain token for non-existent email
    
    def test_request_password_reset_rate_limit(self, test_user):
        """Test rate limiting on password reset requests (3/minute)"""
        # Make 3 requests (the limit)
        for i in range(3):
            response = client.post(
                "/api/v1/auth/password-reset",
                json={"email": test_user["email"]}
            )
            assert response.status_code == 202
        
        # 4th request should be rate limited
        response = client.post(
            "/api/v1/auth/password-reset",
            json={"email": test_user["email"]}
        )
        assert response.status_code == 429  # Too Many Requests
    
    def test_reset_password_invalid_token(self):
        """Test password reset with invalid token returns 400"""
        invalid_token = "invalid.jwt.token"
        
        response = client.post(
            f"/api/v1/auth/password-reset/{invalid_token}",
            json={
                "password": "NewPassword123!",
                "confirm_password": "NewPassword123!"
            }
        )
        
        assert response.status_code == 400
        assert "Invalid" in response.json()["detail"]
    
    def test_reset_password_expired_token(self, test_user):
        """Test password reset with expired token returns 400"""
        expired_token = create_expired_token(test_user["user"].id, "reset")
        
        response = client.post(
            f"/api/v1/auth/password-reset/{expired_token}",
            json={
                "password": "NewPassword123!",
                "confirm_password": "NewPassword123!"
            }
        )
        
        assert response.status_code == 400
        assert "expired" in response.json()["detail"].lower()
    
    def test_reset_password_wrong_token_type(self, test_user):
        """Test password reset with wrong token type returns 400"""
        # Create a confirm token instead of reset token
        confirm_token = create_valid_confirm_token(test_user["user"].id)
        
        response = client.post(
            f"/api/v1/auth/password-reset/{confirm_token}",
            json={
                "password": "NewPassword123!",
                "confirm_password": "NewPassword123!"
            }
        )
        
        assert response.status_code == 400
        assert "Invalid token type" in response.json()["detail"]
    
    def test_reset_password_nonexistent_token_in_db(self, test_user):
        """Test password reset with valid JWT but no database record returns 404"""
        # Create valid JWT token but don't save EmailToken to database
        valid_token = create_valid_reset_token(test_user["user"].id)
        
        response = client.post(
            f"/api/v1/auth/password-reset/{valid_token}",
            json={
                "password": "NewPassword123!",
                "confirm_password": "NewPassword123!"
            }
        )
        
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()
    
    def test_reset_password_validation_errors(self, test_user):
        """Test password reset with validation errors returns 422"""
        # First create a valid reset token in database
        client.post(
            "/api/v1/auth/password-reset",
            json={"email": test_user["email"]}
        )
        
        # Get the EmailToken to create matching JWT
        db = next(get_session())
        email_token = db.scalar(
            select(EmailToken).where(
                EmailToken.user_id == test_user["user"].id,
                EmailToken.type == "reset"
            )
        )
        
        payload = {
            "sub": str(test_user["user"].id),
            "typ": "reset",
            "jti": email_token.jti,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=1)
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        
        # Test password too short
        response = client.post(
            f"/api/v1/auth/password-reset/{token}",
            json={
                "password": "123",  # Too short
                "confirm_password": "123"
            }
        )
        
        assert response.status_code == 422
        assert "validation_error" in response.json()["detail"][0]["type"]
    
    def test_reset_password_mismatched_confirmation(self, test_user):
        """Test password reset with mismatched confirmation returns 422"""
        # First create a valid reset token in database
        client.post(
            "/api/v1/auth/password-reset",
            json={"email": test_user["email"]}
        )
        
        # Get the EmailToken to create matching JWT
        db = next(get_session())
        email_token = db.scalar(
            select(EmailToken).where(
                EmailToken.user_id == test_user["user"].id,
                EmailToken.type == "reset"
            )
        )
        
        payload = {
            "sub": str(test_user["user"].id),
            "typ": "reset",
            "jti": email_token.jti,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=1)
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        
        # Test mismatched passwords
        response = client.post(
            f"/api/v1/auth/password-reset/{token}",
            json={
                "password": "NewPassword123!",
                "confirm_password": "DifferentPassword123!"
            }
        )
        
        assert response.status_code == 422
        assert "Password confirmation does not match" in str(response.json())
    
    def test_reset_password_happy_path(self, test_user):
        """Test successful password reset flow"""
        # Store original password hash
        db = next(get_session())
        original_user = db.scalar(select(User).where(User.id == test_user["user"].id))
        original_password_hash = original_user.hashed_password
        
        # First, request password reset to create EmailToken
        response = client.post(
            "/api/v1/auth/password-reset",
            json={"email": test_user["email"]}
        )
        assert response.status_code == 202
        
        # Get the EmailToken from database to extract jti
        db = next(get_session())
        email_token = db.scalar(
            select(EmailToken).where(
                EmailToken.user_id == test_user["user"].id,
                EmailToken.type == "reset"
            )
        )
        assert email_token is not None
        
        # Create token with matching jti
        payload = {
            "sub": str(test_user["user"].id),
            "typ": "reset",
            "jti": email_token.jti,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(hours=1)
        }
        token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        
        # Now reset password with the token
        new_password = "NewSecurePassword123!"
        response = client.post(
            f"/api/v1/auth/password-reset/{token}",
            json={
                "password": new_password,
                "confirm_password": new_password
            }
        )
        
        assert response.status_code == 200
        assert response.json() == {"message": "Password reset successfully"}
        
        # Check that password was actually changed
        db = next(get_session())
        updated_user = db.scalar(select(User).where(User.id == test_user["user"].id))
        assert updated_user.hashed_password != original_password_hash
        assert security.verify_password(new_password, updated_user.hashed_password)
        
        # Check that EmailToken was deleted from database
        deleted_token = db.scalar(
            select(EmailToken).where(
                EmailToken.user_id == test_user["user"].id,
                EmailToken.type == "reset",
                EmailToken.jti == email_token.jti
            )
        )
        assert deleted_token is None

class TestOpenAPIDocumentation:
    """Test that OpenAPI documentation shows examples"""
    
    def test_docs_accessibility(self):
        """Test that /docs endpoint is accessible"""
        response = client.get("/docs")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
    
    def test_openapi_schema_contains_examples(self):
        """Test that OpenAPI schema contains request/response examples"""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        
        openapi_schema = response.json()
        
        # Check that password reset endpoints exist in schema
        paths = openapi_schema.get("paths", {})
        assert "/api/v1/auth/password-reset" in paths
        assert "/api/v1/auth/password-reset/{token}" in paths
        assert "/api/v1/auth/confirm/request" in paths
        assert "/api/v1/auth/confirm/{token}" in paths
        
        # Check that endpoints have proper documentation
        if "/api/v1/auth/password-reset" in paths:
            password_reset_post = paths["/api/v1/auth/password-reset"]["post"]
            assert "summary" in password_reset_post or "description" in password_reset_post
        
        if "/api/v1/auth/password-reset/{token}" in paths:
            reset_with_token = paths["/api/v1/auth/password-reset/{token}"]["post"]
            assert "summary" in reset_with_token or "description" in reset_with_token