import os
import logging  # Added logging import
from typing import List
from pathlib import Path
from uuid import UUID  # Added UUID import

from fastapi import (
    APIRouter, 
    Depends, 
    HTTPException, 
    File, 
    Form, 
    UploadFile, 
    Request,
    status
)
from sqlalchemy.orm import Session
from sqlalchemy import select, desc

from app.core.database import get_session
from app.auth.deps import get_current_user
from app.auth.models import User
from app.core.limiter import limiter
from app.core.storage import save_file, delete_file, get_file_url
from app.media.models import Media
from app.media.schemas import MediaMeta, MediaRead, MediaList, MediaUploadResponse
from app.core.config import settings  # Add this import

router = APIRouter(tags=["media"])

# Configure logging
logger = logging.getLogger(__name__)

# Allowed MIME types
ALLOWED_MIME_TYPES = ["image/jpeg", "image/png", "image/webp"]

# Maximum file size: 5MB
MAX_FILE_SIZE = 5 * 1024 * 1024


def _get_image_dimensions(file_path: str) -> tuple[int, int] | None:
    """Get image dimensions using PIL (if available)"""
    try:
        from PIL import Image
        with Image.open(file_path) as img:
            return img.size  # Returns (width, height)
    except ImportError:
        # PIL not available, return None
        return None
    except Exception:
        # Could not read image
        return None


@router.post(
    "/", 
    response_model=MediaMeta, 
    status_code=status.HTTP_201_CREATED,
    summary="Upload media file",
    description="Upload image file (JPEG, PNG, WebP) up to 5MB"
)
@limiter.limit("10/minute")
def upload_file(
    request: Request,
    file: UploadFile = File(...),
    purpose: str = Form("other"),
    db: Session = Depends(get_session),
    user: User = Depends(get_current_user),
):
    """
    Upload a media file.
    
    - **file**: Image file (JPEG, PNG, WebP)
    - **purpose**: File purpose (avatar, post, other)
    - Returns media metadata with URL
    """
    
    try:
        logger.info(f"Media upload attempt: user={user.id}, purpose={purpose}, filename={file.filename}")
        
        # 1. Validate MIME type
        if file.content_type not in ALLOWED_MIME_TYPES:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"Invalid file type. Allowed types: {', '.join(ALLOWED_MIME_TYPES)}"
            )
        
        # 2. Validate file size
        if hasattr(file, 'size') and file.size:
            if file.size > MAX_FILE_SIZE:
                raise HTTPException(
                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                    detail=f"File too large. Maximum size: {MAX_FILE_SIZE} bytes ({MAX_FILE_SIZE // (1024*1024)}MB)"
                )
        
        # Read file content to check actual size
        file_content = file.file.read()
        actual_size = len(file_content)
        
        if actual_size > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"File too large. Maximum size: {MAX_FILE_SIZE} bytes ({MAX_FILE_SIZE // (1024*1024)}MB)"
            )
        
        # Reset file pointer
        file.file.seek(0)
        
        # 3. Save file using storage abstraction
        url, local_path, generated_filename = save_file(file, purpose)
        
        # Get image dimensions if possible
        width, height = None, None
        dimensions = _get_image_dimensions(local_path)
        if dimensions:
            width, height = dimensions
        
        # 4. Create Media record in database (store the generated filename)
        media = Media(
            owner_id=user.id,
            filename=generated_filename,  # Store the generated filename, not the original
            mime=file.content_type,
            size=actual_size,
            width=width,
            height=height,
            thumb_url=None,  # Will be set by thumbnail generation
            purpose=purpose
        )
        
        db.add(media)
        db.commit()
        db.refresh(media)
        
        # 5. Enqueue thumbnail generation (optional - skip if Celery not available)
        try:
            from app.media.tasks import generate_thumbnail
            task = generate_thumbnail.delay(str(media.id))
            logger.info(f"Thumbnail generation queued for media {media.id}, task_id: {task.id}")
        except ImportError:
            logger.info("Celery tasks not available, skipping thumbnail generation")
        except Exception as e:
            # Don't fail the upload if thumbnail generation fails to queue
            logger.warning(f"Failed to queue thumbnail generation for media {media.id}: {e}")
        
        # Create response with URL
        media_response = MediaMeta(
            id=media.id,
            url=url,
            thumb_url=media.thumb_url,
            mime=media.mime,
            size=media.size,
            width=media.width,
            height=media.height,
            created_at=media.created_at
        )
        
        logger.info(f"Media upload successful: {media.id}")
        return media_response
        
    except HTTPException:
        # Re-raise HTTP exceptions (from storage layer)
        raise
    except Exception as e:
        # Clean up file if database operation failed
        if 'local_path' in locals():
            delete_file(local_path)
        
        logger.error(f"Media upload failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload file: {str(e)}"
        )


@router.get(
    "/{media_id}", 
    response_model=MediaMeta,
    summary="Get media metadata",
    description="Get metadata for a specific media file by ID"
)
def media_meta(
    media_id: UUID, 
    db: Session = Depends(get_session)
):
    """
    Get media metadata by ID.
    
    - **media_id**: UUID of the media file
    - Returns media metadata with URLs
    """
    media = db.get(Media, media_id)
    if not media:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, 
            detail="Media not found"
        )
    
    # Generate URL for the media file
    from app.core.storage import get_file_url
    base_path = getattr(settings, 'UPLOAD_PATH', 'backend/uploads')
    
    # Construct the full path using the stored filename
    local_path = f"{base_path}/{media.purpose}/{media.filename}"
    url = get_file_url(local_path)
    
    return MediaMeta(
        id=media.id,
        url=url,
        thumb_url=media.thumb_url,
        mime=media.mime,
        size=media.size,
        width=media.width,
        height=media.height,
        created_at=media.created_at
    )


@router.get(
    "/",
    response_model=MediaList,
    summary="List user's media files",
    description="Get paginated list of user's uploaded media files"
)
def list_media(
    page: int = 1,
    page_size: int = 20,
    purpose: str = None,
    db: Session = Depends(get_session),
    user: User = Depends(get_current_user),
):
    """List user's media files with pagination"""
    
    # Build query
    stmt = select(Media).where(Media.owner_id == user.id)
    
    # Filter by purpose if provided
    if purpose and purpose in ["avatar", "post", "other"]:
        stmt = stmt.where(Media.purpose == purpose)
    
    # Order by creation date (newest first)
    stmt = stmt.order_by(desc(Media.created_at))
    
    # Count total items
    total_stmt = select(Media).where(Media.owner_id == user.id)
    if purpose and purpose in ["avatar", "post", "other"]:
        total_stmt = total_stmt.where(Media.purpose == purpose)
    
    total = len(db.scalars(total_stmt).all())
    
    # Calculate pagination
    total_pages = (total + page_size - 1) // page_size if total > 0 else 0
    offset = (page - 1) * page_size
    
    # Get paginated results
    stmt = stmt.limit(page_size).offset(offset)
    media_items = db.scalars(stmt).all()
    
    # Convert to response format with URLs
    media_reads = []
    base_path = getattr(settings, 'UPLOAD_PATH', 'backend/uploads')
    for media in media_items:
        # Construct path using stored filename
        local_path = f"{base_path}/{media.purpose}/{media.filename}"
        url = get_file_url(local_path)
            
        media_read = MediaRead(
            id=media.id,
            owner_id=media.owner_id,
            filename=media.filename,
            mime=media.mime,
            size=media.size,
            width=media.width,
            height=media.height,
            url=url,
            thumb_url=media.thumb_url,
            purpose=media.purpose,
            created_at=media.created_at
        )
        media_reads.append(media_read)
    
    return MediaList(
        items=media_reads,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages
    )


@router.get(
    "/{media_id}/details",  # Changed path to avoid conflict
    response_model=MediaRead,
    summary="Get detailed media information",
    description="Get complete details of a specific media file (requires ownership)"
)
def get_media(
    media_id: str,
    db: Session = Depends(get_session),
    user: User = Depends(get_current_user),
):
    """Get specific media file details"""
    
    media = db.scalar(
        select(Media).where(
            Media.id == media_id,
            Media.owner_id == user.id
        )
    )
    
    if not media:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Media file not found"
        )
    
    # Generate URL for the media
    base_path = getattr(settings, 'UPLOAD_PATH', 'backend/uploads')
    local_path = f"{base_path}/{media.purpose}/{media.filename}"
    url = get_file_url(local_path)
    
    return MediaRead(
        id=media.id,
        owner_id=media.owner_id,
        filename=media.filename,
        mime=media.mime,
        size=media.size,
        width=media.width,
        height=media.height,
        url=url,
        thumb_url=media.thumb_url,
        purpose=media.purpose,
        created_at=media.created_at
    )


@router.delete(
    "/{media_id}/delete",  # Changed path to avoid conflict
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete media file",
    description="Delete a media file and its database record (requires ownership)"
)
def delete_media(
    media_id: str,
    db: Session = Depends(get_session),
    user: User = Depends(get_current_user),
):
    """Delete a media file"""
    
    media = db.scalar(
        select(Media).where(
            Media.id == media_id,
            Media.owner_id == user.id
        )
    )
    
    if not media:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Media file not found"
        )
    
    # Delete physical file
    base_path = getattr(settings, 'UPLOAD_PATH', 'backend/uploads')
    file_path = f"{base_path}/{media.purpose}/{media.filename}"
    delete_file(file_path)
    
    # Delete database record
    db.delete(media)
    db.commit()
    
    return None  # 204 No Content