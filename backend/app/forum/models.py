from datetime import datetime
from uuid import uuid4, UUID


from sqlmodel import SQLModel, Field
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import declarative_base
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import relationship

Base = declarative_base()  # shared metadata object


class Topic(Base):
    __tablename__ = "topics"

    id: int | None = Column(Integer, primary_key=True, autoincrement=True)
    title: str = Column(String(120), nullable=False)
    author_id: UUID = Field(
        sa_column=Column(
            PG_UUID(as_uuid=True),
            ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False
        )
    )
    created_at: datetime = Field(
        sa_column=Column(
            sa.DateTime(timezone=True),
            server_default=func.now(),
            nullable=False
        )
    )
    posts = relationship("Post", back_populates="topic", order_by="Post.created_at")


class Post(Base):
    __tablename__ = "posts"

    id: int | None = Column(Integer, primary_key=True, autoincrement=True)
    topic_id: int = Column(Integer, ForeignKey("topics.id"), nullable=False)
    author_id: UUID = Field(
        sa_column=Column(
            PG_UUID(as_uuid=True),
            ForeignKey("user.id", ondelete="CASCADE"),
            nullable=False
        )
    )
    content: str = Column(Text, nullable=False)
    created_at: datetime = Field(
        sa_column=Column(
            sa.DateTime(timezone=True),
            server_default=func.now(),
            nullable=False
        )
    )
    topic = relationship("Topic", back_populates="posts")