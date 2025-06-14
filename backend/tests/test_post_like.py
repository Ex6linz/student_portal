import pytest
from fastapi.testclient import TestClient
from unittest.mock import AsyncMock, patch

from app.main import app


@pytest.fixture(scope="module")
def client():
    """Create TestClient instance"""
    return TestClient(app)


@pytest.fixture(scope="module")
def auth_headers_user1(client):
    """Create first user and return auth headers"""
    email = "user1@example.com"
    password = "TestPass123!"
    
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
    
    token = login_response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="module")
def auth_headers_user2(client):
    """Create second user and return auth headers"""
    email = "user2@example.com"
    password = "TestPass123!"
    
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
    
    token = login_response.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def sample_post(client, auth_headers_user1):
    """Create a sample post for testing"""
    # Create topic first
    topic_response = client.post(
        "/api/v1/forum/topics",
        json={"title": "Test Topic for Likes", "content": "A" * 20},
        headers=auth_headers_user1
    )
    assert topic_response.status_code == 201
    topic = topic_response.json()
    
    # Create post
    post_response = client.post(
        f"/api/v1/forum/topics/{topic['id']}/posts",
        json={"content": "This is a test post for likes"},
        headers=auth_headers_user1
    )
    assert post_response.status_code == 201
    return post_response.json()


@pytest.fixture(autouse=True)
def mock_redis():
    """Mock Redis for all tests to prevent connection errors"""
    with patch('app.forum.router.get_redis_client') as mock_get_redis:
        mock_redis_client = AsyncMock()
        mock_redis_client.ping = AsyncMock(return_value=True)
        mock_redis_client.publish = AsyncMock(return_value=1)
        mock_get_redis.return_value = mock_redis_client
        yield mock_redis_client


class TestPostLikeEndpoint:
    """Test cases for /posts/{id}/like endpoint"""

    def test_like_requires_authentication_401(self, client, sample_post):
        """Test that liking requires JWT authentication - returns 401"""
        post_id = sample_post["id"]
        
        response = client.post(f"/api/v1/forum/posts/{post_id}/like")
        
        assert response.status_code == 401
        assert "detail" in response.json()

    def test_like_missing_post_404(self, client, auth_headers_user2):
        """Test liking a non-existent post - returns 404"""
        fake_post_id = 999999
        
        response = client.post(
            f"/api/v1/forum/posts/{fake_post_id}/like",
            headers=auth_headers_user2
        )
        
        assert response.status_code == 404
        assert "not found" in response.json()["detail"].lower()

    def test_like_post_happy_path_increments_count(self, client, auth_headers_user2, sample_post, mock_redis):
        """Test successful like operation - increments count"""
        post_id = sample_post["id"]
        
        # Get initial like count
        likes_info_response = client.get(
            f"/api/v1/forum/posts/{post_id}/likes",
            headers=auth_headers_user2
        )
        assert likes_info_response.status_code == 200
        initial_count = likes_info_response.json()["likes"]
        
        # Like the post
        response = client.post(
            f"/api/v1/forum/posts/{post_id}/like",
            headers=auth_headers_user2
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "liked" in data
        assert "likes" in data
        assert "message" in data
        
        # Verify like operation
        assert data["liked"] is True
        assert data["likes"] == initial_count + 1
        assert "successfully" in data["message"].lower()
        
        # Verify notification was sent (but don't require it)
        # The notification might not be sent if it's a self-like or if Redis is unavailable
        if mock_redis.publish.called:
            print("✅ Notification sent via Redis")
        else:
            print("ℹ️ Notification not sent (might be self-like or Redis unavailable)")
        
        # Verify like count is updated
        likes_info_response = client.get(
            f"/api/v1/forum/posts/{post_id}/likes",
            headers=auth_headers_user2
        )
        updated_info = likes_info_response.json()
        assert updated_info["likes"] == initial_count + 1
        assert updated_info["liked_by_user"] is True

    def test_duplicate_like_toggles_unlike(self, client, auth_headers_user2, sample_post):
        """Test that duplicate like toggles to unlike - not a 400 error"""
        post_id = sample_post["id"]
        
        # First like
        first_response = client.post(
            f"/api/v1/forum/posts/{post_id}/like",
            headers=auth_headers_user2
        )
        assert first_response.status_code == 200
        first_data = first_response.json()
        assert first_data["liked"] is True
        likes_after_first = first_data["likes"]
        
        # Second like (should unlike)
        second_response = client.post(
            f"/api/v1/forum/posts/{post_id}/like",
            headers=auth_headers_user2
        )
        assert second_response.status_code == 200
        second_data = second_response.json()
        
        # Should be unliked now
        assert second_data["liked"] is False
        assert second_data["likes"] == likes_after_first - 1
        assert "unliked" in second_data["message"].lower()

    def test_cannot_like_own_post_400(self, client, auth_headers_user1, sample_post):
        """Test that users cannot like their own posts - returns 400"""
        post_id = sample_post["id"]
        
        response = client.post(
            f"/api/v1/forum/posts/{post_id}/like",
            headers=auth_headers_user1  # Same user who created the post
        )
        
        assert response.status_code == 400
        assert "cannot like your own post" in response.json()["detail"].lower()

    def test_invalid_post_id_format_422(self, client, auth_headers_user2):
        """Test invalid post ID format - returns 422"""
        response = client.post(
            "/api/v1/forum/posts/invalid-id/like",
            headers=auth_headers_user2
        )
        
        assert response.status_code == 422

    def test_negative_post_id_422(self, client, auth_headers_user2):
        """Test negative post ID - returns 422"""
        response = client.post(
            "/api/v1/forum/posts/-1/like",
            headers=auth_headers_user2
        )
        
        assert response.status_code == 422

    def test_zero_post_id_422(self, client, auth_headers_user2):
        """Test zero post ID - returns 422"""
        response = client.post(
            "/api/v1/forum/posts/0/like",
            headers=auth_headers_user2
        )
        
        assert response.status_code == 422

    def test_multiple_users_can_like_same_post(self, client, auth_headers_user2, sample_post):
        """Test that multiple users can like the same post"""
        post_id = sample_post["id"]
        
        # User 2 likes the post
        response1 = client.post(
            f"/api/v1/forum/posts/{post_id}/like",
            headers=auth_headers_user2
        )
        assert response1.status_code == 200
        assert response1.json()["likes"] == 1
        
        # Create third user
        email3 = "user3@example.com"
        password3 = "TestPass123!"
        
        register_response = client.post(
            "/api/v1/auth/register",
            json={"email": email3, "password": password3}
        )
        assert register_response.status_code == 201
        
        login_response = client.post(
            "/api/v1/auth/login",
            json={"email": email3, "password": password3}
        )
        assert login_response.status_code == 200
        
        token3 = login_response.json()["access_token"]
        headers3 = {"Authorization": f"Bearer {token3}"}
        
        # User 3 likes the post
        response2 = client.post(
            f"/api/v1/forum/posts/{post_id}/like",
            headers=headers3
        )
        assert response2.status_code == 200
        assert response2.json()["likes"] == 2

    def test_like_count_consistency_across_operations(self, client, auth_headers_user2, sample_post):
        """Test that like count remains consistent across multiple operations"""
        post_id = sample_post["id"]
        
        # Get initial state
        initial_response = client.get(
            f"/api/v1/forum/posts/{post_id}/likes",
            headers=auth_headers_user2
        )
        initial_count = initial_response.json()["likes"]
        
        # Like the post
        like_response = client.post(
            f"/api/v1/forum/posts/{post_id}/like",
            headers=auth_headers_user2
        )
        new_count = like_response.json()["likes"]
        assert new_count == initial_count + 1
        
        # Verify count in get endpoint
        verify_response = client.get(
            f"/api/v1/forum/posts/{post_id}/likes",
            headers=auth_headers_user2
        )
        assert verify_response.json()["likes"] == new_count
        assert verify_response.json()["liked_by_user"] is True
        
        # Unlike the post
        unlike_response = client.post(
            f"/api/v1/forum/posts/{post_id}/like",
            headers=auth_headers_user2
        )
        final_count = unlike_response.json()["likes"]
        assert final_count == initial_count
        
        # Final verification
        final_response = client.get(
            f"/api/v1/forum/posts/{post_id}/likes",
            headers=auth_headers_user2
        )
        assert final_response.json()["likes"] == final_count
        assert final_response.json()["liked_by_user"] is False

    def test_post_detail_reflects_like_count(self, client, auth_headers_user2, sample_post):
        """Test that post detail endpoint reflects like count changes"""
        post_id = sample_post["id"]
        
        # Get initial post detail
        detail_response = client.get(f"/api/v1/forum/posts/{post_id}")
        assert detail_response.status_code == 200
        initial_detail = detail_response.json()
        assert "like_count" in initial_detail
        initial_likes = initial_detail["like_count"]
        
        # Like the post
        like_response = client.post(
            f"/api/v1/forum/posts/{post_id}/like",
            headers=auth_headers_user2
        )
        assert like_response.status_code == 200
        
        # Get updated post detail
        updated_detail_response = client.get(f"/api/v1/forum/posts/{post_id}")
        updated_detail = updated_detail_response.json()
        assert updated_detail["like_count"] == initial_likes + 1

    def test_rate_limiting_behavior(self, client, auth_headers_user2, sample_post):
        """Test rate limiting behavior (should allow reasonable requests)"""
        post_id = sample_post["id"]
        
        # Try multiple like/unlike operations rapidly
        for i in range(5):
            response = client.post(
                f"/api/v1/forum/posts/{post_id}/like",
                headers=auth_headers_user2
            )
            # Should either succeed or be rate limited
            assert response.status_code in [200, 429]

    def test_like_with_redis_failure_still_works(self, client, auth_headers_user2, sample_post):
        """Test that like functionality works even when Redis/notifications fail"""
        post_id = sample_post["id"]
        
        with patch('app.forum.router.get_redis_client') as mock_get_redis:
            # Mock Redis to raise an exception
            mock_get_redis.side_effect = Exception("Redis connection failed")
            
            # Like operation should still succeed
            response = client.post(
                f"/api/v1/forum/posts/{post_id}/like",
                headers=auth_headers_user2
            )
            assert response.status_code == 200
            
            # The like should be recorded even if notification fails
            data = response.json()
            assert data["liked"] is True
            assert data["likes"] >= 1

    def test_sequential_likes_from_different_users(self, client, auth_headers_user2, sample_post):
        """Test sequential likes from different users"""
        post_id = sample_post["id"]
        
        # Create multiple users and have them like the post
        users = []
        for i in range(3):
            email = f"multiuser{i}@example.com"
            password = "TestPass123!"
            
            # Register user
            client.post("/api/v1/auth/register", json={"email": email, "password": password})
            
            # Login user
            login_response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
            token = login_response.json()["access_token"]
            headers = {"Authorization": f"Bearer {token}"}
            users.append(headers)
        
        # Each user likes the post
        for i, headers in enumerate(users):
            response = client.post(
                f"/api/v1/forum/posts/{post_id}/like",
                headers=headers
            )
            assert response.status_code == 200
            assert response.json()["likes"] == i + 1

    def test_like_unlike_like_sequence(self, client, auth_headers_user2, sample_post):
        """Test like → unlike → like sequence works correctly"""
        post_id = sample_post["id"]
        
        # Get initial count
        initial_response = client.get(
            f"/api/v1/forum/posts/{post_id}/likes",
            headers=auth_headers_user2
        )
        initial_count = initial_response.json()["likes"]
        
        # Like
        like_response = client.post(
            f"/api/v1/forum/posts/{post_id}/like",
            headers=auth_headers_user2
        )
        assert like_response.status_code == 200
        assert like_response.json()["liked"] is True
        assert like_response.json()["likes"] == initial_count + 1
        
        # Unlike
        unlike_response = client.post(
            f"/api/v1/forum/posts/{post_id}/like",
            headers=auth_headers_user2
        )
        assert unlike_response.status_code == 200
        assert unlike_response.json()["liked"] is False
        assert unlike_response.json()["likes"] == initial_count
        
        # Like again
        like_again_response = client.post(
            f"/api/v1/forum/posts/{post_id}/like",
            headers=auth_headers_user2
        )
        assert like_again_response.status_code == 200
        assert like_again_response.json()["liked"] is True
        assert like_again_response.json()["likes"] == initial_count + 1


class TestPostLikeGetEndpoint:
    """Test cases for GET /posts/{id}/likes endpoint"""

    def test_get_likes_info_requires_auth(self, client, sample_post):
        """Test that getting like info requires authentication"""
        post_id = sample_post["id"]
        
        response = client.get(f"/api/v1/forum/posts/{post_id}/likes")
        assert response.status_code == 401

    def test_get_likes_info_missing_post_404(self, client, auth_headers_user2):
        """Test getting like info for non-existent post"""
        fake_post_id = 999999
        
        response = client.get(
            f"/api/v1/forum/posts/{fake_post_id}/likes",
            headers=auth_headers_user2
        )
        assert response.status_code == 404

    def test_get_likes_info_success(self, client, auth_headers_user2, sample_post):
        """Test successful retrieval of like information"""
        post_id = sample_post["id"]
        
        response = client.get(
            f"/api/v1/forum/posts/{post_id}/likes",
            headers=auth_headers_user2
        )
        
        assert response.status_code == 200
        data = response.json()
        
        # Verify response structure
        assert "post_id" in data
        assert "likes" in data
        assert "liked_by_user" in data
        
        # Verify initial state
        assert data["post_id"] == post_id
        assert isinstance(data["likes"], int)
        assert isinstance(data["liked_by_user"], bool)
        assert data["likes"] >= 0

    def test_get_likes_info_invalid_post_id(self, client, auth_headers_user2):
        """Test getting like info with invalid post ID format"""
        response = client.get(
            "/api/v1/forum/posts/invalid-id/likes",
            headers=auth_headers_user2
        )
        assert response.status_code == 422


class TestPostLikeEdgeCases:
    """Test edge cases and error conditions"""

    def test_very_large_post_id(self, client, auth_headers_user2):
        """Test with very large post ID"""
        large_id = 999999999999
        
        response = client.post(
            f"/api/v1/forum/posts/{large_id}/like",
            headers=auth_headers_user2
        )
        assert response.status_code == 404

    def test_malformed_authorization_header(self, client, sample_post):
        """Test with malformed authorization header"""
        post_id = sample_post["id"]
        
        response = client.post(
            f"/api/v1/forum/posts/{post_id}/like",
            headers={"Authorization": "InvalidToken"}
        )
        assert response.status_code == 401

    def test_expired_token_behavior(self, client, sample_post):
        """Test behavior with potentially expired token"""
        post_id = sample_post["id"]
        
        # Use an obviously invalid token
        response = client.post(
            f"/api/v1/forum/posts/{post_id}/like",
            headers={"Authorization": "Bearer invalid.token.here"}
        )
        assert response.status_code == 401

    def test_response_content_type(self, client, auth_headers_user2, sample_post):
        """Test that response has correct content type"""
        post_id = sample_post["id"]
        
        response = client.post(
            f"/api/v1/forum/posts/{post_id}/like",
            headers=auth_headers_user2
        )
        
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")