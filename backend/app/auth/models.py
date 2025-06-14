from datetime import datetime, timedelta, timezone
from uuid import uuid4, UUID
from typing import Optional, Literal, List

from sqlalchemy import ForeignKey
from sqlmodel import SQLModel, Field, Relationship  # IMPORTANT: Import Relationship from sqlmodel
from sqlalchemy import Column, String, DateTime, Boolean, Text, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID


class User(SQLModel, table=True):
    __tablename__ = "users"
    __table_args__ = {"extend_existing": True}

    id: UUID = Field(
        sa_column=Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4),
    )
    email: str = Field(
        sa_column=Column(String, unique=True, nullable=False, index=True),
    )
    hashed_password: str = Field(
        sa_column=Column(String, nullable=False),
    )
    role: str = Field(
        default="user",
        sa_column=Column(String, nullable=False, server_default="user"),
    )
    display_name: Optional[str] = Field(
        default=None,
        sa_column=Column(String, nullable=True),
    )
    bio: Optional[str] = Field(
        default=None,
        sa_column=Column(Text, nullable=True),
    )
    avatar_url: Optional[str] = Field(
        default=None,
        sa_column=Column(String, nullable=True),
    )
    created_at: datetime = Field(
       default_factory=lambda: datetime.now(timezone.utc),
       sa_column=Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    )

    # SQLModel relationship syntax
    email_tokens: List["EmailToken"] = Relationship(back_populates="user")


class RefreshToken(SQLModel, table=True):
    __tablename__ = "refresh_token"
    __table_args__ = {"extend_existing": True}

    id: UUID = Field(
        sa_column=Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4),
    )
    user_id: UUID = Field(
        sa_column=Column(
            PG_UUID(as_uuid=True),
            ForeignKey("users.id"),
            nullable=False,
            index=True
        ),
    )
    jti: UUID = Field(
        sa_column=Column(PG_UUID(as_uuid=True), unique=True, nullable=False, default=uuid4),
    )
    created_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), server_default=func.now(), nullable=False),
    )
    expires_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False),
    )
    revoked: bool = Field(
        default=False,
        sa_column=Column(Boolean, nullable=False, server_default="false"),
    )

    @classmethod
    def create_for_user(cls, user_id: UUID, days_valid: int):
        now = datetime.utcnow()
        return cls(
            user_id=user_id,
            jti=uuid4(),
            created_at=now,
            expires_at=now + timedelta(days=days_valid),
        )

    
class EmailToken(SQLModel, table=True):
    """Email verification and password reset tokens"""
    __tablename__ = 'email_token'

    id: UUID = Field(
        sa_column=Column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4),
    )
    
    user_id: UUID = Field(
        sa_column=Column(
            PG_UUID(as_uuid=True),
            ForeignKey("users.id"),
            nullable=False,
            index=True
        ),
    )
    
    type: Literal['confirm', 'reset'] = Field(
        sa_column=Column(String(10), nullable=False, index=True),
    )
    
    jti: str = Field(
        sa_column=Column(String(255), nullable=False, unique=True, index=True),
    )
    
    exp: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False, index=True),
    )
    
    created_at: datetime = Field(
        sa_column=Column(DateTime(timezone=True), nullable=False, server_default=func.now()),
        default_factory=lambda: datetime.now(timezone.utc)
    )

    # SQLModel relationship syntax
    user: Optional["User"] = Relationship(back_populates="email_tokens")

    def is_expired(self) -> bool:
        """Check if token is expired"""
        return datetime.utcnow() > self.exp