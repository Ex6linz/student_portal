from datetime import datetime
from uuid import UUID, uuid4
from typing import Optional

from sqlmodel import SQLModel, Field
import sqlalchemy as sa
from sqlalchemy import func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID


class Media(SQLModel, table=True):
    __tablename__ = "media"

    id: UUID = Field(
        default_factory=uuid4,
        sa_column=sa.Column(
            PG_UUID(as_uuid=True),
            primary_key=True,
            default=uuid4
        )
    )
    owner_id: UUID = Field(
        sa_column=sa.Column(
            PG_UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False
        )
    )
    filename: str = Field(max_length=255)
    mime: str = Field(max_length=100)
    size: int = Field(ge=0, description="File size in bytes")
    width: Optional[int] = Field(default=None, ge=0, description="Image width in pixels")
    height: Optional[int] = Field(default=None, ge=0, description="Image height in pixels")
    thumb_url: Optional[str] = Field(default=None, max_length=500, description="Thumbnail URL")
    purpose: str = Field(
        default="other",
        max_length=20,
        description="Media purpose: avatar, post, or other"
    )
    created_at: datetime = Field(
        sa_column=sa.Column(
            sa.DateTime(timezone=True),
            server_default=func.now(),
            nullable=False
        )
    )

    # Optional: Add validation for purpose enum
    def __init__(self, **data):
        if "purpose" in data and data["purpose"] not in ["avatar", "post", "other"]:
            raise ValueError("Purpose must be one of: avatar, post, other")
        super().__init__(**data)