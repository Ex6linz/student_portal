from pydantic import EmailStr, BaseModel, Field
from uuid import UUID

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)

class UserRead(BaseModel):
    id: UUID
    email: EmailStr

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"