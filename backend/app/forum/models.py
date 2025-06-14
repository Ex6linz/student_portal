# app/forum/models.py - Updated to match your SQLModel structure
from datetime import datetime
from uuid import UUID
from typing import Optional, List

from sqlmodel import SQLModel, Field, Relationship
import sqlalchemy as sa
from sqlalchemy import func, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID as PG_UUID


class Comment(SQLModel, table=True):
    __tablename__ = "comments"

    id: Optional[int] = Field(default=None, primary_key=True)
    post_id: int = Field(foreign_key="posts.id")
    author_id: UUID = Field(
        sa_column=sa.Column(
            PG_UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False
        )
    )
    content: str = Field(sa_column=sa.Column(sa.Text, nullable=False))
    created_at: datetime = Field(
        sa_column=sa.Column(
            sa.DateTime(timezone=True),
            server_default=func.now(),
            nullable=False
        )
    )
    
    # Relationships
    post: Optional["Post"] = Relationship(back_populates="comments")


class Topic(SQLModel, table=True):
    __tablename__ = "topics"

    id: Optional[int] = Field(default=None, primary_key=True)
    title: str = Field(max_length=120)
    author_id: UUID = Field(
        sa_column=sa.Column(
            PG_UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False
        )
    )
    created_at: datetime = Field(
        sa_column=sa.Column(
            sa.DateTime(timezone=True),
            server_default=func.now(),
            nullable=False
        )
    )
    
    # Relationship to posts
    posts: List["Post"] = Relationship(back_populates="topic")


class Post(SQLModel, table=True):
    __tablename__ = "posts"

    id: Optional[int] = Field(default=None, primary_key=True)
    topic_id: int = Field(foreign_key="topics.id")
    author_id: UUID = Field(
        sa_column=sa.Column(
            PG_UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False
        )
    )
    content: str = Field(sa_column=sa.Column(sa.Text, nullable=False))
    like_count: int = Field(default=0, description="Number of likes on this post")  # 🆕 NEW FIELD
    created_at: datetime = Field(
        sa_column=sa.Column(
            sa.DateTime(timezone=True),
            server_default=func.now(),
            nullable=False
        )
    )
    
    # Relationships
    topic: Optional[Topic] = Relationship(back_populates="posts")
    comments: List[Comment] = Relationship(
        back_populates="post", 
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )
    likes: List["PostLike"] = Relationship(  # 🆕 NEW RELATIONSHIP
        back_populates="post",
        sa_relationship_kwargs={"cascade": "all, delete-orphan"}
    )


class PostLike(SQLModel, table=True):  # 🆕 NEW MODEL
    """
    Model to track post likes with unique constraint to prevent duplicate likes.
    
    Uses integer post_id to match your existing Post model structure.
    """
    __tablename__ = "post_likes"
    
    id: Optional[int] = Field(default=None, primary_key=True)
    post_id: int = Field(foreign_key="posts.id", description="ID of the liked post")
    user_id: UUID = Field(
        sa_column=sa.Column(
            PG_UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False
        ),
        description="ID of the user who liked the post"
    )
    created_at: datetime = Field(
        sa_column=sa.Column(
            sa.DateTime(timezone=True),
            server_default=func.now(),
            nullable=False
        )
    )
    
    # Relationships
    post: Optional[Post] = Relationship(back_populates="likes")
    # You might want to add a relationship to User as well:
    # user: Optional["User"] = Relationship(back_populates="post_likes")
    
    # Unique constraint to prevent duplicate likes
    __table_args__ = (
        UniqueConstraint('post_id', 'user_id', name='uq_post_likes_post_user'),
    )