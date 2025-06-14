from datetime import datetime
from uuid import UUID
from typing import Optional, List, Literal, Union
from pydantic import BaseModel, Field, field_validator, ConfigDict


# ─────────────────────────  READ SCHEMAS  ──────────────────────────
class MediaMeta(BaseModel):
    """Media metadata schema for API responses"""
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    url: str  # Changed from HttpUrl to str for local development
    thumb_url: Optional[str] = None  # Changed from Optional[HttpUrl] to Optional[str]
    mime: str
    size: int
    width: Optional[int] = None
    height: Optional[int] = None
    created_at: datetime


class MediaRead(BaseModel):
    """Complete media information schema"""
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    owner_id: UUID
    filename: str
    mime: str
    size: int
    width: Optional[int] = None
    height: Optional[int] = None
    url: str  # Changed from HttpUrl to str
    thumb_url: Optional[str] = None  # Changed from Optional[HttpUrl] to Optional[str]
    purpose: str
    created_at: datetime


class MediaList(BaseModel):
    """Paginated media list response"""
    items: List[MediaRead]
    total: int
    page: int
    page_size: int
    total_pages: int


# ─────────────────────────  CREATE SCHEMAS  ──────────────────────────
class MediaUpload(BaseModel):
    """Schema for media upload request"""
    purpose: Literal["avatar", "post", "other"] = Field(
        default="other",
        description="Media purpose: avatar, post, or other"
    )


class MediaCreate(BaseModel):
    """Internal schema for creating media records"""
    owner_id: UUID
    filename: str
    mime: str
    size: int
    width: Optional[int] = None
    height: Optional[int] = None
    thumb_url: Optional[str] = None
    purpose: str = "other"
    
    @field_validator('purpose')
    @classmethod
    def validate_purpose(cls, v):
        if v not in ["avatar", "post", "other"]:
            raise ValueError('Purpose must be one of: avatar, post, other')
        return v
    
    @field_validator('size')
    @classmethod
    def validate_size(cls, v):
        if v < 0:
            raise ValueError('Size must be non-negative')
        return v
    
    @field_validator('width', 'height')
    @classmethod
    def validate_dimensions(cls, v):
        if v is not None and v < 0:
            raise ValueError('Dimensions must be non-negative')
        return v


# ─────────────────────────  UPDATE SCHEMAS  ──────────────────────────
class MediaUpdate(BaseModel):
    """Schema for updating media metadata"""
    purpose: Optional[Literal["avatar", "post", "other"]] = None
    thumb_url: Optional[str] = None
    width: Optional[int] = None
    height: Optional[int] = None
    
    @field_validator('thumb_url')
    @classmethod
    def validate_thumb_url(cls, v):
        if v is not None and len(v.strip()) == 0:
            return None
        return v
    
    @field_validator('width', 'height')
    @classmethod
    def validate_dimensions(cls, v):
        if v is not None and v < 0:
            raise ValueError('Dimensions must be non-negative')
        return v


# ─────────────────────────  RESPONSE SCHEMAS  ──────────────────────────
class MediaUploadResponse(BaseModel):
    """Response schema for successful file upload"""
    message: str = "File uploaded successfully"
    media: MediaRead
    
    
class MediaDeleteResponse(BaseModel):
    """Response schema for file deletion"""
    message: str = "File deleted successfully"
    deleted_id: UUID


# ─────────────────────────  FILTER SCHEMAS  ──────────────────────────
class MediaFilter(BaseModel):
    """Schema for filtering media queries"""
    purpose: Optional[Literal["avatar", "post", "other"]] = None
    mime_type: Optional[str] = None
    min_size: Optional[int] = Field(None, ge=0)
    max_size: Optional[int] = Field(None, ge=0)
    
    @field_validator('max_size')
    @classmethod
    def validate_max_size(cls, v, info):
        if v is not None and 'min_size' in info.data and info.data['min_size'] is not None:
            if v < info.data['min_size']:
                raise ValueError('max_size must be greater than or equal to min_size')
        return v