# app/auth/router.py
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status, Response, Cookie, Request
from fastapi import Body

from sqlalchemy.orm import Session
from sqlmodel import select

import jwt
from app.core.database import get_session
from app.auth import models, schemas, security
from app.core.config import settings
from app.core.limiter import limiter

router = APIRouter(prefix="/auth", tags=["auth"])

_login_attempts: dict[str, list[datetime]] = {}

def _set_refresh_cookie(response: Response, token: str, max_age: int):
    
    response.set_cookie(
        "refresh_token",
        token,
        httponly=False, # zmiana na true produkcyjnie
        samesite=None,  #zmiana na lax produkcyjnie
        max_age=max_age,
        path="/auth",
    )

@router.post("/register", response_model=schemas.Token, status_code=201)
def register(user_in: schemas.UserCreate, db: Session = Depends(get_session)):
    exists = db.scalar(select(models.User).where(models.User.email == user_in.email))
    if exists:
        raise HTTPException(400, "E-mail already registered")
    user = models.User(
        id=uuid4(),
        email=user_in.email,
        hashed_password=security.hash_password(user_in.password),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    access = security.create_access_token(sub=user.id)
    return {"access_token": access, "token_type": "bearer"}

@router.post("/login", response_model=schemas.Token, status_code=status.HTTP_200_OK)
@limiter.limit("5/minute")
def login(
    request: Request,
    response: Response,
    user_in: schemas.UserLogin | None = Body(...),
    db: Session = Depends(get_session),
):
    
    #now = datetime.utcnow()
    #attempts = _login_attempts.get(user_in.email, [])
    
   # attempts = [t for t in attempts if now - t < timedelta(minutes=1)]
   # if len(attempts) >= 5:
   #     raise HTTPException(
   #         status.HTTP_429_TOO_MANY_REQUESTS,
   #         "Too many login attempts, try again later"
   #     )
   # attempts.append(now)
   # _login_attempts[user_in.email] = attempts
    
    #if not user_in:
    #    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect credentials")
    user = db.scalar(select(models.User).where(models.User.email == user_in.email))
    if not user or not security.verify_password(user_in.password, user.hashed_password):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Incorrect credentials")
    access_token = security.create_access_token(sub=str(user.id))


    jti = uuid4()
    expires = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    db_rt = models.RefreshToken(
        id=jti,
        user_id=user.id,
        jti=jti,
        expires_at=expires,
        revoked=False,
        created_at=datetime.utcnow(),
    )
    db.add(db_rt)
    db.commit()

    db.add(db_rt)
    db.commit()

    refresh_jwt = security.create_refresh_token(sub=str(user.id), jti=jti)

    _set_refresh_cookie(
        response,
        refresh_jwt,
        max_age=int(timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS).total_seconds()),
    )

    return {"access_token": access_token, "token_type": "bearer"}

@router.post("/refresh", response_model=schemas.Token)
def refresh_token(
    response: Response,
    rt_cookie: str = Cookie(None, alias="refresh_token"),
    db: Session = Depends(get_session),
):
    if not rt_cookie:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "No refresh token")
    try:
        payload = jwt.decode(
            rt_cookie, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
        )
        if payload.get("typ") != "refresh":
            raise jwt.PyJWTError
        jti = UUID(payload["jti"])
    except jwt.PyJWTError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid refresh token")

    db_rt = db.scalar(
        select(models.RefreshToken)
        .where(models.RefreshToken.jti == jti)
    )
    if not db_rt or db_rt.revoked or db_rt.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Refresh token expired")

    db_rt.revoked = True
    new_rt = models.RefreshToken.create_for_user(
        user_id=db_rt.user_id,
        days_valid=settings.REFRESH_TOKEN_EXPIRE_DAYS,
    )
    db.add(new_rt)
    db.commit()

    new_payload = {
        "sub": str(new_rt.user_id),
        "jti": str(new_rt.jti),
        "typ": "refresh",
        "iat": datetime.utcnow(),
        "exp": new_rt.expires_at,
    }
    new_rt_jwt = jwt.encode(
        new_payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM
    )
    _set_refresh_cookie(
        response,
        new_rt_jwt,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 3600,
    )

    access = security.create_access_token(sub=new_rt.user_id)
    return {"access_token": access, "token_type": "bearer"}

@router.post("/logout", status_code=204)
def logout(
    response: Response,
    rt_cookie: str = Cookie(None, alias="refresh_token"),
    db: Session = Depends(get_session),
):
    if rt_cookie:
        try:
            payload = jwt.decode(
                rt_cookie, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
            )
            jti = UUID(payload["jti"])
            
            db_rt = db.scalar(
                select(models.RefreshToken)
                .where(models.RefreshToken.jti == jti)
            )
            
            if db_rt:
                db_rt.revoked = True
                db.commit()
        except jwt.PyJWTError:
            pass
    response.delete_cookie("refresh_token", path="/auth")
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
    