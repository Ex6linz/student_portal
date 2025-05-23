# app/users/router.py
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.database import get_session
from uuid import UUID
from app.auth.deps import get_current_user
from app.users import schemas
from app.auth import models

router = APIRouter(prefix="/users", tags=["users"])

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