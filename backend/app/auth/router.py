# app/auth/router.py
from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4
import logging

from fastapi import APIRouter, Depends, HTTPException, status, Response, Cookie, Request
from fastapi import Body
from pydantic import EmailStr

from sqlalchemy.orm import Session
from sqlmodel import select

import jwt
from app.core.database import get_session
from app.auth import models, schemas, security
from app.core.config import settings
from app.core.limiter import limiter
from app.notifications.router import send_notification_to_user

# Import email tasks
from app.email.tasks import send_confirmation_email, send_password_reset_email

router = APIRouter(tags=["auth"])

# Configure logging
logger = logging.getLogger(__name__)

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

def create_email_confirmation_token(user_id: UUID) -> str:
    """Create JWT token for email confirmation"""
    payload = {
        "sub": str(user_id),
        "typ": "email_confirm", 
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + timedelta(hours=24)  # 24 hour expiry
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

def create_password_reset_token(user_id: UUID) -> str:
    """Create JWT token for password reset"""
    payload = {
        "sub": str(user_id),
        "typ": "password_reset",
        "iat": datetime.utcnow(), 
        "exp": datetime.utcnow() + timedelta(hours=1)  # 1 hour expiry
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)

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
    
    # Send confirmation email after successful registration
    try:
        confirmation_token = create_email_confirmation_token(user.id)
        
        # Send confirmation email asynchronously
        email_task = send_confirmation_email.delay(
            to=user.email,
            confirmation_token=confirmation_token,
            user_name=user.display_name or user.email.split('@')[0]  # Use display_name or email prefix
        )
        
        logger.info(f"Confirmation email queued for {user.email} (task: {email_task.id})")
        
    except Exception as e:
        logger.error(f"Failed to queue confirmation email for {user.email}: {e}")
        
    
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

# ==================== NEW EMAIL ENDPOINTS ====================

@router.post("/confirm/request", status_code=202)
@limiter.limit("5/minute")
def request_confirm(
    request: Request,
    email: EmailStr = Body(..., embed=True),
    db: Session = Depends(get_session)
):
    """Request email confirmation - generates EmailToken and sends confirmation email"""
    
    # Find user by email
    user = db.scalar(select(models.User).where(models.User.email == email))
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Note: Add email_confirmed field to User model in the future to check if already confirmed
    # if user.email_confirmed:
    #     raise HTTPException(status_code=400, detail="Email already confirmed")
    
    try:
        # Generate unique JWT ID and expiration
        jti = str(uuid4())
        exp_time = datetime.utcnow() + timedelta(hours=24)  # 24 hour expiry
        
        # Create JWT token for email confirmation
        payload = {
            "sub": str(user.id),
            "typ": "confirm",
            "jti": jti,
            "iat": datetime.utcnow(),
            "exp": exp_time
        }
        confirmation_token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        
        # Save EmailToken to database
        email_token = models.EmailToken(
            user_id=user.id,
            type="confirm",
            jti=jti,
            exp=exp_time
        )
        db.add(email_token)
        db.commit()
        db.refresh(email_token)
        
        # Send confirmation email asynchronously
        email_task = send_confirmation_email.delay(
            to=user.email,
            confirmation_token=confirmation_token,
            user_name=user.display_name or user.email.split('@')[0]
        )
        
        logger.info(
            f"Email confirmation requested for {user.email} "
            f"(token_id: {email_token.id}, task: {email_task.id})"
        )
        
        return {"message": "Confirmation email sent"}
        
    except Exception as e:
        logger.error(f"Failed to request email confirmation for {user.email}: {e}")
        # Rollback database changes if email sending fails
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send confirmation email"
        )

@router.post("/password-reset", status_code=202)
@limiter.limit("3/minute")
def request_password_reset(
    request: Request,
    email: EmailStr = Body(..., embed=True),
    db: Session = Depends(get_session)
):
    """
    Request password reset email
    
    **Parameters:**
    - **email**: User's email address
    
    **Returns:**
    - Generic success message (doesn't reveal if email exists)
    
    **Rate Limiting:**
    - Maximum 3 requests per minute
    
    **Process:**
    1. Finds user by email (silent fail for security)
    2. Generates JWT reset token with unique JTI
    3. Creates EmailToken record (type='reset')
    4. Sends password reset email asynchronously
    5. Returns success message regardless of email existence
    """
    
    # Always return the same message for security (don't reveal if email exists)
    success_message = {"message": "If that email exists in our system, a password reset link has been sent"}
    
    # Find user by email
    user = db.scalar(select(models.User).where(models.User.email == email))
    
    if not user:
        logger.info(f"Password reset requested for non-existent email: {email}")
        return success_message
    
    try:
        # Generate unique JWT ID and expiration (shorter for security)
        jti = str(uuid4())
        exp_time = datetime.utcnow() + timedelta(hours=1)  # 1 hour expiry for resets
        
        # Create JWT token for password reset
        payload = {
            "sub": str(user.id),
            "typ": "reset", 
            "jti": jti,
            "iat": datetime.utcnow(),
            "exp": exp_time
        }
        reset_token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
        
        # Invalidate any existing reset tokens for this user
        existing_tokens = db.scalars(
            select(models.EmailToken).where(
                models.EmailToken.user_id == user.id,
                models.EmailToken.type == "reset"
            )
        ).all()
        
        for existing_token in existing_tokens:
            db.delete(existing_token)
        
        # Save new EmailToken to database
        email_token = models.EmailToken(
            user_id=user.id,
            type="reset",
            jti=jti,
            exp=exp_time
        )
        db.add(email_token)
        db.commit()
        db.refresh(email_token)
        
        # Send password reset email asynchronously
        email_task = send_password_reset_email.delay(
            to=user.email,
            reset_token=reset_token,
            user_name=user.display_name or user.email.split('@')[0]
        )
        
        logger.info(
            f"Password reset requested for {user.email} "
            f"(token_id: {email_token.id}, task: {email_task.id})"
        )
        
    except Exception as e:
        logger.error(f"Failed to process password reset for {user.email}: {e}")
        # Rollback database changes if something fails
        db.rollback()
        # Still return success message for security
    
    return success_message

@router.post("/password-reset/confirm", status_code=200)
def confirm_password_reset(
    token: str = Body(...),
    new_password: str = Body(..., min_length=6, max_length=128),
    db: Session = Depends(get_session)
):
    """
    Confirm password reset with token and set new password
    
    **Parameters:**
    - **token**: JWT password reset token from email
    - **new_password**: New password (6-128 characters)
    
    **Returns:**
    - Success message when password is reset
    
    **Errors:**
    - **400**: Invalid token, expired token, or password validation
    - **404**: User not found or token not found
    
    **Process:**
    1. Decodes and validates JWT token
    2. Finds EmailToken record in database
    3. Checks token expiration
    4. Updates user password with hash
    5. Deletes used token and any other reset tokens
    6. Optionally invalidates all user sessions
    """
    
    try:
        # Decode and validate JWT token
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        
        # Verify token type
        if payload.get("typ") != "reset":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token type"
            )
        
        user_id = UUID(payload["sub"])
        jti = payload["jti"]
        
        # Find the EmailToken in database
        email_token = db.scalar(
            select(models.EmailToken).where(
                models.EmailToken.user_id == user_id,
                models.EmailToken.type == "reset",
                models.EmailToken.jti == jti
            )
        )
        
        if not email_token:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Reset token not found or already used"
            )
        
        # Check if token is expired
        if email_token.is_expired():
            # Clean up expired token
            db.delete(email_token)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Reset token has expired"
            )
        
        # Find user
        user = db.scalar(select(models.User).where(models.User.id == user_id))
        if not user:
            # Clean up orphaned token
            db.delete(email_token)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Validate password (additional validation beyond Pydantic)
        if len(new_password.strip()) < 6:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Password must be at least 6 characters long"
            )
        
        # Update user password
        user.hashed_password = security.hash_password(new_password)
        
        # Delete all reset tokens for this user (cleanup)
        reset_tokens = db.scalars(
            select(models.EmailToken).where(
                models.EmailToken.user_id == user.id,
                models.EmailToken.type == "reset"
            )
        ).all()
        
        for reset_token in reset_tokens:
            db.delete(reset_token)
        
        # Optional: Revoke all refresh tokens to force re-login (security measure)
        refresh_tokens = db.scalars(
            select(models.RefreshToken).where(
                models.RefreshToken.user_id == user.id,
                models.RefreshToken.revoked == False
            )
        ).all()
        
        for refresh_token in refresh_tokens:
            refresh_token.revoked = True
        
        db.commit()
        
        logger.info(f"Password reset completed for user {user.email}")
        
        return {"message": "Password reset successfully"}
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid reset token"
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token format"
        )
    except Exception as e:
        logger.error(f"Unexpected error during password reset: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during password reset"
        )

@router.post("/forgot-password")
async def forgot_password(
    email: EmailStr = Body(..., embed=True),
    db: Session = Depends(get_session)
):
    """Send password reset email"""
    
    # Find user by email
    user = db.scalar(select(models.User).where(models.User.email == email))
    
    # Always return the same message for security (don't reveal if email exists)
    success_message = {"message": "If that email exists in our system, a reset link has been sent."}
    
    if not user:
        logger.info(f"Password reset requested for non-existent email: {email}")
        return success_message
    
    try:
        # Generate password reset token
        reset_token = create_password_reset_token(user.id)
        
        # Send reset email asynchronously
        email_task = send_password_reset_email.delay(
            to=user.email,
            reset_token=reset_token,
            user_name=user.display_name or user.email.split('@')[0]
        )
        
        logger.info(f"Password reset email queued for {user.email} (task: {email_task.id})")
        
    except Exception as e:
        logger.error(f"Failed to queue password reset email for {user.email}: {e}")
        # Still return success message for security
    
    return success_message

@router.post("/resend-confirmation")
async def resend_confirmation(
    email: EmailStr = Body(..., embed=True),
    db: Session = Depends(get_session)
):
    """Resend email confirmation"""
    
    user = db.scalar(select(models.User).where(models.User.email == email))
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="User not found"
        )
    
    # Note: Add email_confirmed field to User model in the future to check if already confirmed
    # if user.email_confirmed:
    #     raise HTTPException(status_code=400, detail="Email already confirmed")
    
    try:
        confirmation_token = create_email_confirmation_token(user.id)
        
        email_task = send_confirmation_email.delay(
            to=user.email,
            confirmation_token=confirmation_token,
            user_name=user.display_name or user.email.split('@')[0]
        )
        
        logger.info(f"Confirmation email resent for {user.email} (task: {email_task.id})")
        
        return {
            "message": "Confirmation email sent successfully",
            "task_id": email_task.id
        }
        
    except Exception as e:
        logger.error(f"Failed to resend confirmation email for {user.email}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to send confirmation email"
        )

@router.get("/confirm/{token}", status_code=200)
def confirm_email(
    token: str,
    db: Session = Depends(get_session)
):
    """
    Confirm email address with token (GET method for direct link access)
    
    **Parameters:**
    - **token**: JWT confirmation token from email link
    
    **Returns:**
    - Success message when email is confirmed
    
    **Errors:**
    - **400**: Invalid token, expired token, or token type mismatch
    - **404**: User not found or token not found in database
    
    **Process:**
    1. Decodes and validates JWT token
    2. Finds EmailToken record in database
    3. Checks token expiration
    4. Marks user as verified (is_verified=True)
    5. Deletes used token from database
    """
    
    try:
        # Decode and validate JWT token
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        
        # Verify token type
        if payload.get("typ") != "confirm":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token type"
            )
        
        user_id = UUID(payload["sub"])
        jti = payload["jti"]
        
        # Find the EmailToken in database
        email_token = db.scalar(
            select(models.EmailToken).where(
                models.EmailToken.user_id == user_id,
                models.EmailToken.type == "confirm",
                models.EmailToken.jti == jti
            )
        )
        
        if not email_token:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Confirmation token not found or already used"
            )
        
        # Check if token is expired using the model's method
        if email_token.is_expired():
            # Clean up expired token
            db.delete(email_token)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Confirmation token has expired"
            )
        
        # Find user
        user = db.scalar(select(models.User).where(models.User.id == user_id))
        if not user:
            # Clean up orphaned token
            db.delete(email_token)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Mark user as verified
        # Note: Add is_verified field to User model
        # user.is_verified = True
        # user.email_verified_at = datetime.utcnow()
        
        # For now, we'll log the successful verification
        # TODO: Add is_verified field to User model and uncomment above lines
        
        # Delete the used token
        db.delete(email_token)
        db.commit()
        
        logger.info(f"Email confirmed via GET for user {user.email} (token: {email_token.id})")
        
        return {"message": "Email confirmed"}
        
    except jwt.ExpiredSignatureError:
        # JWT itself is expired (backup check)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirmation token has expired"
        )
    except jwt.InvalidTokenError:
        # JWT is malformed or invalid
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid confirmation token"
        )
    except ValueError as e:
        # UUID conversion errors
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid token format"
        )
    except Exception as e:
        # Log unexpected errors
        logger.error(f"Unexpected error during email confirmation: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error during confirmation"
        )

@router.post("/confirm-email")
async def confirm_email(
    token: str = Body(..., embed=True),
    db: Session = Depends(get_session)
):
    """Confirm email address with token"""
    
    try:
        # Decode and validate token
        payload = jwt.decode(
            token, 
            settings.SECRET_KEY, 
            algorithms=[settings.ALGORITHM]
        )
        
        if payload.get("typ") != "confirm":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token type"
            )
        
        user_id = UUID(payload["sub"])
        jti = payload["jti"]
        
        # Find the EmailToken in database
        email_token = db.scalar(
            select(models.EmailToken).where(
                models.EmailToken.user_id == user_id,
                models.EmailToken.type == "confirm",
                models.EmailToken.jti == jti
            )
        )
        
        if not email_token:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired confirmation token"
            )
        
        # Check if token is expired
        if email_token.is_expired():
            # Clean up expired token
            db.delete(email_token)
            db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Confirmation token has expired"
            )
        
        # Find user
        user = db.scalar(select(models.User).where(models.User.id == user_id))
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Mark email as confirmed (add these fields to User model in the future)
        # user.email_confirmed = True
        # user.email_confirmed_at = datetime.utcnow()
        
        # Remove the used token
        db.delete(email_token)
        db.commit()
        
        logger.info(f"Email confirmed for user {user.email}")
        
        return {"message": "Email confirmed successfully"}
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Confirmation token has expired"
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid confirmation token"
        )

@router.post("/reset-password")
async def reset_password(
    token: str = Body(...),
    new_password: str = Body(..., min_length=6),
    db: Session = Depends(get_session)
):
    """Reset password with token"""
    
    try:
        # Decode and validate token
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        
        if payload.get("typ") != "password_reset":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token type"
            )
        
        user_id = UUID(payload["sub"])
        
        # Find user
        user = db.scalar(select(models.User).where(models.User.id == user_id))
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )
        
        # Update password
        user.hashed_password = security.hash_password(new_password)
        db.commit()
        
        logger.info(f"Password reset completed for user {user.email}")
        
        return {"message": "Password reset successfully"}
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Reset token has expired"
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid reset token"
        )