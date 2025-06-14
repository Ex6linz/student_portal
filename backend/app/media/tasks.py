import os
import tempfile
import logging
from pathlib import Path
from typing import Optional
from uuid import UUID

from celery import Celery
from PIL import Image, ImageOps
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.core.database import get_session
from app.core.storage import save_file, get_file_url, file_exists
from app.media.models import Media

# Configure logging
logger = logging.getLogger(__name__)

# Celery app configuration
celery_app = Celery(
    "media_tasks",
    broker=os.getenv("CELERY_BROKER_URL", "redis://localhost:6379/0"),
    backend=os.getenv("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")
)

# Configure Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=300,  # 5 minutes max
    task_soft_time_limit=240,  # 4 minutes soft limit
    worker_prefetch_multiplier=1,
    task_acks_late=True,
    worker_max_tasks_per_child=1000,
)


class ThumbnailGenerationError(Exception):
    """Custom exception for thumbnail generation errors"""
    pass


def _get_image_format(mime_type: str) -> str:
    """Convert MIME type to PIL format"""
    format_map = {
        "image/jpeg": "JPEG",
        "image/jpg": "JPEG", 
        "image/png": "PNG",
        "image/webp": "WebP",
        "image/bmp": "BMP",
        "image/tiff": "TIFF",
    }
    return format_map.get(mime_type.lower(), "JPEG")


def _create_thumbnail_filename(original_filename: str, size: int) -> str:
    """Create thumbnail filename from original"""
    path = Path(original_filename)
    stem = path.stem
    ext = path.suffix
    return f"{stem}_thumb_{size}x{size}{ext}"


def _optimize_image(image: Image.Image, format_type: str) -> Image.Image:
    """Optimize image for web use"""
    # Convert to RGB if necessary (for JPEG compatibility)
    if format_type == "JPEG" and image.mode in ("RGBA", "P", "LA"):
        # Create white background for transparency
        background = Image.new("RGB", image.size, (255, 255, 255))
        if image.mode == "P":
            image = image.convert("RGBA")
        background.paste(image, mask=image.split()[-1] if image.mode == "RGBA" else None)
        image = background
    
    # Auto-orient image based on EXIF data
    try:
        image = ImageOps.exif_transpose(image)
    except Exception as e:
        logger.warning(f"Failed to auto-orient image: {e}")
    
    return image


@celery_app.task(bind=True, autoretry_for=(Exception,), retry_kwargs={'max_retries': 3, 'countdown': 60})
def generate_thumbnail(self, media_id: str, size: int = 256) -> dict:
    """
    Generate thumbnail for uploaded media file.
    
    Args:
        media_id: UUID of the media record
        size: Thumbnail size (square, default 256px)
    
    Returns:
        dict: Task result with success status and thumbnail info
    
    Raises:
        ThumbnailGenerationError: If thumbnail generation fails
    """
    logger.info(f"Starting thumbnail generation for media {media_id}, size {size}px")
    
    # Validate inputs
    try:
        media_uuid = UUID(media_id)
    except ValueError:
        raise ThumbnailGenerationError(f"Invalid media_id format: {media_id}")
    
    if size <= 0 or size > 2048:
        raise ThumbnailGenerationError(f"Invalid thumbnail size: {size}. Must be 1-2048px")
    
    # Create database session
    db = next(get_session())
    
    try:
        # 1. Fetch Media from DB
        media = db.scalar(select(Media).where(Media.id == media_uuid))
        if not media:
            raise ThumbnailGenerationError(f"Media record not found: {media_id}")
        
        # Check for idempotency - skip if thumbnail already exists
        if media.thumb_url and size == 256:  # Default size check
            logger.info(f"Thumbnail already exists for media {media_id}")
            return {
                "success": True,
                "media_id": media_id,
                "message": "Thumbnail already exists",
                "thumb_url": media.thumb_url,
                "skipped": True
            }
        
        # Construct original file path
        original_path = f"backend/uploads/{media.purpose}/{media.filename}"
        
        # Check if original file exists
        if not file_exists(original_path):
            raise ThumbnailGenerationError(f"Original file not found: {original_path}")
        
        # 2. Open original image via PIL
        try:
            with Image.open(original_path) as image:
                logger.info(f"Opened image: {image.size} {image.mode} {image.format}")
                
                # Update media dimensions if not set
                if not media.width or not media.height:
                    media.width, media.height = image.size
                    logger.info(f"Updated media dimensions: {media.width}x{media.height}")
                
                # Optimize image
                image = _optimize_image(image, _get_image_format(media.mime))
                
                # 3. Create thumbnail
                original_size = image.size
                image.thumbnail((size, size), Image.Resampling.LANCZOS)
                thumbnail_size = image.size
                
                logger.info(f"Created thumbnail: {original_size} -> {thumbnail_size}")
                
                # 4. Save thumbnail to temporary file
                with tempfile.NamedTemporaryFile(suffix=".jpg", delete=False) as temp_file:
                    temp_path = temp_file.name
                    
                    # Save as JPEG with optimization
                    image.save(
                        temp_path, 
                        format="JPEG",
                        quality=85,
                        optimize=True,
                        progressive=True
                    )
                
                # 5. Upload thumbnail via storage
                thumbnail_filename = _create_thumbnail_filename(media.filename, size)
                
                # Create a file-like object for storage.save_file
                from fastapi import UploadFile
                import io
                
                with open(temp_path, "rb") as thumb_file:
                    thumb_content = thumb_file.read()
                
                thumb_upload = UploadFile(
                    filename=thumbnail_filename,
                    file=io.BytesIO(thumb_content),
                    content_type="image/jpeg"
                )
                
                # Save thumbnail with "thumb" purpose or same as original
                thumb_purpose = f"{media.purpose}_thumb" if media.purpose != "other" else "thumb"
                thumb_url, thumb_path = save_file(thumb_upload, thumb_purpose)
                
                # Clean up temporary file
                try:
                    os.unlink(temp_path)
                except Exception as e:
                    logger.warning(f"Failed to clean up temp file {temp_path}: {e}")
                
                # 6. Update media record
                media.thumb_url = thumb_url
                db.commit()
                
                logger.info(f"Thumbnail generated successfully: {thumb_url}")
                
                return {
                    "success": True,
                    "media_id": media_id,
                    "thumb_url": thumb_url,
                    "thumb_size": thumbnail_size,
                    "original_size": original_size,
                    "file_size": len(thumb_content),
                    "skipped": False
                }
                
        except Exception as e:
            raise ThumbnailGenerationError(f"Failed to process image: {str(e)}")
    
    except ThumbnailGenerationError:
        # Re-raise custom errors
        raise
    except Exception as e:
        # Wrap unexpected errors
        logger.error(f"Unexpected error in thumbnail generation: {e}")
        raise ThumbnailGenerationError(f"Unexpected error: {str(e)}")
    
    finally:
        db.close()


@celery_app.task(bind=True)
def cleanup_orphaned_files(self) -> dict:
    """
    Cleanup task to remove orphaned thumbnail files.
    Run periodically to clean up files without database records.
    """
    logger.info("Starting cleanup of orphaned thumbnail files")
    
    # This is a placeholder for a cleanup task
    # In a real implementation, you would:
    # 1. Scan upload directories for files
    # 2. Check if corresponding Media records exist
    # 3. Remove files without database records
    # 4. Log cleanup actions
    
    return {
        "success": True,
        "message": "Cleanup completed",
        "files_removed": 0  # Placeholder
    }


@celery_app.task(bind=True)
def regenerate_thumbnails(self, size: int = 256) -> dict:
    """
    Regenerate all thumbnails with new size.
    Useful for changing thumbnail dimensions across all media.
    """
    logger.info(f"Starting bulk thumbnail regeneration with size {size}px")
    
    db = next(get_session())
    
    try:
        # Get all media records without thumbnails or with old thumbnails
        media_query = select(Media).where(
            Media.mime.like("image/%")  # Only image files
        )
        
        media_list = db.scalars(media_query).all()
        total_count = len(media_list)
        
        logger.info(f"Found {total_count} media files to process")
        
        # Queue thumbnail generation tasks
        task_ids = []
        for media in media_list:
            task = generate_thumbnail.delay(str(media.id), size)
            task_ids.append(task.id)
        
        return {
            "success": True,
            "message": f"Queued {total_count} thumbnail generation tasks",
            "total_files": total_count,
            "task_ids": task_ids[:10],  # Return first 10 task IDs
            "size": size
        }
        
    except Exception as e:
        logger.error(f"Failed to queue thumbnail regeneration: {e}")
        return {
            "success": False,
            "error": str(e)
        }
    
    finally:
        db.close()


# Periodic tasks configuration (if using celery beat)
celery_app.conf.beat_schedule = {
    'cleanup-orphaned-files': {
        'task': 'app.media.tasks.cleanup_orphaned_files',
        'schedule': 86400.0,  # Run daily
    },
}
celery_app.conf.timezone = 'UTC'