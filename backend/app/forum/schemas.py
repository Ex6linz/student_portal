# app/forum/schemas.py - Updated to match your current structure
from datetime import datetime
from uuid import UUID
from typing import List, Optional, Generic, TypeVar
from pydantic import BaseModel, Field, field_validator, ConfigDict


# ─────────────────────────  CREATE SCHEMAS  ──────────────────────────
class TopicCreate(BaseModel):
    title: str = Field(
        ...,
        min_length=10,
        max_length=120,
        description="Topic title (10-120 characters)"
    )
    content: str = Field(
        ...,
        min_length=20,
        description="Topic content (min 20 characters)"
    )

    @field_validator('title')
    @classmethod
    def validate_title(cls, v):
        if len(v.strip()) < 10:
            raise ValueError('Title must be at least 10 characters long')
        return v.strip()

    @field_validator('content')
    @classmethod
    def validate_content(cls, v):
        if len(v.strip()) < 20:
            raise ValueError('Content must be at least 20 characters long')
        return v.strip()


class PostCreate(BaseModel):
    content: str = Field(
        ...,
        min_length=1,
        description="Post content (min 1 character)"
    )

    @field_validator('content')
    @classmethod
    def validate_content(cls, v):
        if len(v.strip()) < 1:
            raise ValueError('Content cannot be empty')
        return v.strip()


class CommentCreate(BaseModel):
    content: str = Field(
        ...,
        min_length=1,
        description="Comment content (min. 1 character)"
    )

    @field_validator('content')
    @classmethod
    def validate_content(cls, v):
        if len(v.strip()) < 1:
            raise ValueError('Comment cannot be empty')
        return v.strip()


# ───────────────────────────  READ SCHEMAS  ───────────────────────────
class CommentRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    post_id: int
    author_id: UUID
    content: str
    created_at: datetime


class PostRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    topic_id: int
    author_id: UUID
    content: str
    like_count: int = Field(default=0, description="Number of likes on this post")  # 🆕 ADDED
    created_at: datetime
    comments: List[CommentRead] = []


class TopicRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: int
    title: str
    author_id: UUID
    created_at: datetime


class TopicReadWithPosts(TopicRead):
    posts: List[PostRead] = []


# ──────────────────────────  PAGINATION SCHEMAS  ──────────────────────────
T = TypeVar('T')

class PaginatedResponse(BaseModel, Generic[T]):
    items: List[T]
    total: int
    page: int
    page_size: int
    total_pages: int


class TopicList(BaseModel):
    items: List[TopicRead]
    total: int
    page: int
    page_size: int
    total_pages: int


class PostList(BaseModel):
    items: List[PostRead]
    total: int
    page: int
    page_size: int
    total_pages: int


class CommentList(BaseModel):
    items: List[CommentRead]
    total: int
    page: int
    page_size: int
    total_pages: int


# ──────────────────────────  LIKE SCHEMAS  ──────────────────────────
class PostLikeResponse(BaseModel):
    """Response schema for post like/unlike actions"""
    liked: bool = Field(..., description="Whether the post is now liked by the user")
    likes: int = Field(..., description="Current total number of likes on the post")
    message: str = Field(..., description="Description of the action performed")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "liked": True,
                "likes": 15,
                "message": "Post liked successfully"
            }
        }
    )


class PostLikeInfo(BaseModel):
    """Schema for getting post like information"""
    post_id: int = Field(..., description="ID of the post")  # 🔄 CHANGED: int not string
    likes: int = Field(..., description="Total number of likes on the post")
    liked_by_user: bool = Field(..., description="Whether the current user has liked this post")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "post_id": 123,  # 🔄 CHANGED: int not UUID string
                "likes": 15,
                "liked_by_user": True
            }
        }
    )


class PostLikeBase(BaseModel):
    """Base schema for post likes"""
    post_id: int  # 🔄 CHANGED: int not UUID
    user_id: UUID


class PostLikeRead(PostLikeBase):
    """Read schema for post likes"""
    id: int  # 🔄 CHANGED: int not UUID
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)


# Enhanced PostRead with like information for authenticated users
class PostReadWithLikeInfo(PostRead):
    """Enhanced post read schema that includes user's like status"""
    liked_by_user: Optional[bool] = Field(None, description="Whether the current user has liked this post")
    
    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": 123,  # 🔄 CHANGED: int not UUID
                "topic_id": 1,
                "author_id": "123e4567-e89b-12d3-a456-426614174000",
                "content": "This is an example post content.",
                "like_count": 15,
                "liked_by_user": True,
                "created_at": "2025-01-30T12:00:00Z",
                "comments": []
            }
        }
    )


# Validation for like-related operations
class PostLikeValidation:
    """Utility class for like-related validations"""
    
    @staticmethod
    def validate_post_id(v: int) -> int:  # 🔄 CHANGED: int not UUID
        """Validate that post_id is a positive integer"""
        if v <= 0:
            raise ValueError("Post ID must be a positive integer")
        return v
    
    @staticmethod
    def validate_like_count(v: int) -> int:
        """Validate that like count is non-negative"""
        if v < 0:
            raise ValueError("Like count cannot be negative")
        return v