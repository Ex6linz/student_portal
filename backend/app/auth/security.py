from datetime import datetime, timedelta
from uuid import UUID
import jwt
from passlib.context import CryptContext
from app.core.config import settings

pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(plain: str) -> str:
    return pwd_ctx.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_ctx.verify(plain, hashed)

def create_access_token(sub: UUID | str, expires_minutes: int | None = None) -> str:
    expire = datetime.utcnow() + timedelta(
        minutes=expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    to_encode = {"sub": str(sub), "iat": datetime.utcnow(), "exp": expire}
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def _jwt_encode(payload: dict) -> str:
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_access_token(sub: UUID | str,
                        expires_minutes: int | None = None) -> str:
    expire = datetime.utcnow() + timedelta(
        minutes=expires_minutes or settings.ACCESS_TOKEN_EXPIRE_MINUTES
    )
    payload = {
        "sub": str(sub),
        "typ": "access",
        "iat": datetime.utcnow(),
        "exp": expire,
    }
    return _jwt_encode(payload)

def create_refresh_token(sub: UUID | str,
                         jti: UUID,
                         expires_days: int | None = None) -> str:
    expire = datetime.utcnow() + timedelta(
        days=expires_days or settings.REFRESH_TOKEN_EXPIRE_DAYS
    )
    payload = {
        "sub": str(sub),
        "jti": str(jti),
        "typ": "refresh",
        "iat": datetime.utcnow(),
        "exp": expire,
    }
    return _jwt_encode(payload)