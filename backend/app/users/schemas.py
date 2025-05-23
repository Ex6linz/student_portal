# app/users/schemas.py
from pydantic import BaseModel, EmailStr, HttpUrl
from typing import Optional
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel, EmailStr, Field

class UserBase(BaseModel):
    email: EmailStr
    display_name: Optional[str] = None
    bio: Optional[str] = None
    avatar_url: Optional[str] = None

class UserPublic(BaseModel):
    id: UUID
    email: EmailStr
    display_name: str | None = None
    avatar_url: HttpUrl | None = None
    created_at: datetime

    class Config:
        orm_mode = True

class UserRead(UserPublic):
    email: EmailStr
    role: str
    created_at: datetime

    class Config:
        orm_mode = True


class UserMe(UserPublic):
    email: EmailStr
    bio: str | None = None

class UserUpdate(BaseModel):
    display_name: str | None = Field(max_length=40)
    bio: str | None = Field(max_length=280)
    