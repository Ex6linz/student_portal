from datetime import datetime
from uuid import uuid4, UUID
from sqlmodel import SQLModel, Field, Column, String, DateTime

class User(SQLModel, table=True):
    __tablename__ = "user"

    id: UUID | None = Field(default_factory=uuid4, primary_key=True, index=True)
    email: str = Field(sa_column=Column(String, unique=True, nullable=False, index=True))
    hashed_password: str = Field(nullable=False, max_length=255)
    created_at: datetime = Field(default_factory=datetime.utcnow, sa_column=Column(DateTime(timezone=True)))


class RefreshToken(SQLModel, table=True):
    __tablename__ = "refresh_token"

    id: UUID | None = Field(default_factory=uuid4, primary_key=True, index=True)
    user_id: UUID = Field(foreign_key="user.id", nullable=False)
    jti: UUID = Field(index=True, unique=True)                       # JWT ID
    expires_at: datetime
    revoked: bool = Field(default=False)