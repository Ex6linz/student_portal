from fastapi import APIRouter, Depends, HTTPException, status, Response, Cookie
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import select
from uuid import uuid4
from app.core.database import get_session
from app.auth import models, schemas, security

router = APIRouter(prefix="/auth", tags=["auth"])

def _set_refresh_cookie(response: Response, rt_jwt: str):
    response.set_cookie(
        "refresh_token",
        rt_jwt,
        httponly=True,
        samesite="lax",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        secure=False,            # ustaw True w prod, jeśli masz HTTPS
        path="/auth/refresh",
    )

# --- register ------------------------------------------------------------
@router.post("/register", response_model=schemas.Token, status_code=201)
async def register(user_in: schemas.UserCreate,
                   response: Response,
                   db: AsyncSession = Depends(get_session)):

    if await db.scalar(select(models.User).where(models.User.email == user_in.email)):
        raise HTTPException(400, "E-mail already registered")

    user = models.User(
        id=uuid4(),
        email=user_in.email,
        hashed_password=security.hash_password(user_in.password),
    )
    db.add(user)

    # 1) od razu refresh-token
    jti = uuid4()
    rt = models.RefreshToken(
        user_id=user.id,
        jti=jti,
        expires_at=datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(rt)
    await db.commit()

    rt_jwt = security.create_refresh_token(sub=user.id, jti=jti)
    _set_refresh_cookie(response, rt_jwt)

    access = security.create_access_token(sub=user.id)
    return {"access_token": access, "token_type": "bearer"}

# --- login ---------------------------------------------------------------
@router.post("/login", response_model=schemas.Token)
async def login(user_in: schemas.UserCreate,
                response: Response,
                db: AsyncSession = Depends(get_session)):

    stmt = select(models.User).where(models.User.email == user_in.email)
    user: models.User | None = await db.scalar(stmt)
    if not user or not security.verify_password(user_in.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect credentials")

    # nowy refresh (rotacja – stare pozostają aktywne; revokacja to osobny temat)
    jti = uuid4()
    rt = models.RefreshToken(
        user_id=user.id,
        jti=jti,
        expires_at=datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(rt)
    await db.commit()

    rt_jwt = security.create_refresh_token(sub=user.id, jti=jti)
    _set_refresh_cookie(response, rt_jwt)

    access = security.create_access_token(sub=user.id)
    return {"access_token": access, "token_type": "bearer"}

# --- refresh -------------------------------------------------------------
@router.post("/refresh", response_model=schemas.Token)
async def refresh_token(response: Response,
                        rt_cookie: str = Cookie(..., alias="refresh_token"),
                        db: AsyncSession = Depends(get_session)):

    try:
        payload = jwt.decode(rt_cookie, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("typ") != "refresh":
            raise JWTError
        jti = UUID(payload["jti"])
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

    db_rt: models.RefreshToken | None = await db.get(models.RefreshToken, jti)
    if not db_rt or db_rt.revoked or db_rt.expires_at < datetime.utcnow():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token expired")

    # ROTACJA: unieważnij stary, wystaw nowy
    db_rt.revoked = True
    new_jti = uuid4()
    new_rt = models.RefreshToken(
        user_id=db_rt.user_id,
        jti=new_jti,
        expires_at=datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(new_rt)
    await db.commit()

    new_rt_jwt = security.create_refresh_token(sub=db_rt.user_id, jti=new_jti)
    _set_refresh_cookie(response, new_rt_jwt)

    access = security.create_access_token(sub=db_rt.user_id)
    return {"access_token": access, "token_type": "bearer"}

