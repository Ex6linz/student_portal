# app/users/schemas.py
from pydantic import BaseModel, EmailStr, HttpUrl, ConfigDict
from typing import Optional
from uuid import UUID
from datetime import datetime
from pydantic import Field

class UserBase(BaseModel):
    email: EmailStr
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None

class UserPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    
    id: UUID
    email: EmailStr
    display_name: str | None = None
    avatar_url: HttpUrl | None = None
    created_at: datetime

class UserRead(UserPublic):
    model_config = ConfigDict(from_attributes=True)
    
    email: EmailStr
    role: str
    created_at: datetime

class UserMe(UserPublic):
    model_config = ConfigDict(from_attributes=True)
    
    email: EmailStr
    bio: str | None = None

class UserUpdate(BaseModel):
    display_name: str | None = Field(default=None, max_length=40)
    bio: str | None = Field(default=None, max_length=280)