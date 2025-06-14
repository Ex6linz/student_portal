# app/users/router.py
from fastapi import APIRouter, Depends, HTTPException, status, Body
from sqlalchemy.orm import Session
from app.core.database import get_session
from uuid import UUID
from app.auth.deps import get_current_user
from app.users import schemas
from app.auth import models
from pydantic import EmailStr


from app.email.tasks import send_confirmation_email, send_password_reset_email

router = APIRouter(tags=["users"])

@router.get("/me", response_model=schemas.UserRead)
def read_current_user(
    current_user: models.User = Depends(get_current_user),
):
    return current_user

@router.patch("/me", response_model=schemas.UserRead)
def update_current_user(
    user_in: schemas.UserUpdate,
    db: Session = Depends(get_session),
    current_user: models.User = Depends(get_current_user),
):
    for field, val in user_in.dict(exclude_unset=True).items():
        setattr(current_user, field, val)
    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    return current_user

@router.get("/{user_id}", response_model=schemas.UserPublic)
def public_profile(user_id: UUID, db: Session = Depends(get_session)):
    user = db.get(models.User, user_id)
    if not user:
        raise HTTPException(404, "User not found")
    return user

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
        
        if payload.get("typ") != "email_confirm":
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
        
        # Note: Add email_confirmed field to User model in the future
        # user.email_confirmed = True
        # user.email_confirmed_at = datetime.utcnow()
        # db.commit()
        
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