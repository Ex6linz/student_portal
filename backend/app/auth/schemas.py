# app/auth/schemas.py
from pydantic import EmailStr, BaseModel, Field, field_validator
from uuid import UUID
from typing import Optional
class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6, max_length=128)

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserRead(BaseModel):
    id: UUID
    email: EmailStr

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class NewPasswordSchema(BaseModel):
    """Schema for new password during password reset"""
    
    password: str = Field(
        ...,
        min_length=6,
        max_length=128,
        description="New password (6-128 characters)",
        example="MyNewSecurePassword123!"
    )
    
    confirm_password: Optional[str] = Field(
        None,
        min_length=6,
        max_length=128,
        description="Password confirmation (optional but recommended)",
        example="MyNewSecurePassword123!"
    )
    
    @field_validator('password')
    @classmethod
    def validate_password_strength(cls, v):
        """Basic password strength validation"""
        if len(v.strip()) < 6:
            raise ValueError('Password must be at least 6 characters long')
        
        # Optional: Add more strength requirements
        # if not any(c.isupper() for c in v):
        #     raise ValueError('Password must contain at least one uppercase letter')
        # if not any(c.islower() for c in v):
        #     raise ValueError('Password must contain at least one lowercase letter')
        # if not any(c.isdigit() for c in v):
        #     raise ValueError('Password must contain at least one digit')
        
        return v.strip()
    
    @field_validator('confirm_password')
    @classmethod
    def validate_password_match(cls, v, info):
        """Validate password confirmation matches"""
        if v is not None and 'password' in info.data:
            if v != info.data['password']:
                raise ValueError('Password confirmation does not match')
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "password": "MyNewSecurePassword123!",
                "confirm_password": "MyNewSecurePassword123!"
            }
        }