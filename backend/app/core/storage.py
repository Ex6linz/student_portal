import os
import uuid
from pathlib import Path
from typing import Tuple
from datetime import datetime
import mimetypes
import logging

from fastapi import UploadFile, HTTPException

from app.core.config import settings

logger = logging.getLogger(__name__)


class StorageError(Exception):
    """Base exception for storage operations"""
    pass


def _ensure_upload_directories():
    """Create upload directories if they don't exist"""
    base_path = Path(getattr(settings, 'UPLOAD_PATH', 'backend/uploads'))
    
    for purpose in ["avatar", "post", "other"]:
        purpose_dir = base_path / purpose
        purpose_dir.mkdir(parents=True, exist_ok=True)


def _generate_filename(original_filename: str, purpose: str) -> str:
    """Generate unique filename with timestamp and UUID"""
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    unique_id = str(uuid.uuid4())[:8]
    
    # Extract file extension
    ext = Path(original_filename).suffix.lower()
    if not ext:
        # Try to guess extension from mimetype
        mime_type = mimetypes.guess_type(original_filename)[0]
        if mime_type:
            ext = mimetypes.guess_extension(mime_type) or ""
    
    # Clean original filename (remove path, keep only basename)
    clean_name = Path(original_filename).name
    
    return f"{timestamp}_{unique_id}_{clean_name}"


def save_file(file: UploadFile, purpose: str = "other") -> Tuple[str, str, str]:
    """
    Save uploaded file to local disk.
    
    Args:
        file: FastAPI UploadFile instance
        purpose: File purpose ("avatar", "post", "other")
    
    Returns:
        Tuple of (url, local_path, generated_filename) where:
        - url: Accessible URL for the file (e.g., "/uploads/avatar/file.jpg")
        - local_path: Full local filesystem path for storage/deletion
        - generated_filename: The actual filename used for storage (with timestamp/UUID)
    
    Raises:
        HTTPException: If validation fails or save operation fails
    """
    # Validate purpose
    if purpose not in ["avatar", "post", "other"]:
        raise HTTPException(
            status_code=400, 
            detail="Purpose must be one of: avatar, post, other"
        )
    
    # Validate file
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")
    
    # Check file size (optional)
    max_size = getattr(settings, 'MAX_FILE_SIZE', 10 * 1024 * 1024)  # 10MB default
    if hasattr(file, 'size') and file.size:
        try:
            # Handle case where file.size might be a mock object in tests
            file_size = int(file.size) if file.size is not None else 0
            if file_size > max_size:
                raise HTTPException(
                    status_code=413, 
                    detail=f"File too large. Maximum size: {max_size} bytes"
                )
        except (TypeError, ValueError):
            # Skip size check if file.size is not a valid number (e.g., in tests)
            pass
    
    try:
        # Ensure directories exist
        _ensure_upload_directories()
        
        # Generate unique filename
        filename = _generate_filename(file.filename, purpose)
        
        # Create paths
        base_path = Path(getattr(settings, 'UPLOAD_PATH', 'backend/uploads'))
        base_url = getattr(settings, 'UPLOAD_URL', '/uploads').rstrip('/')
        
        purpose_dir = base_path / purpose
        file_path = purpose_dir / filename
        
        # Save file
        with open(file_path, "wb") as buffer:
            content = file.file.read()
            buffer.write(content)
        
        # Reset file pointer for potential reuse
        file.file.seek(0)
        
        # Generate URL and return paths
        url = f"{base_url}/{purpose}/{filename}"
        local_path = str(file_path)
        
        logger.info(f"File saved locally: {local_path}")
        return url, local_path, filename  # Return the generated filename too
        
    except Exception as e:
        logger.error(f"Failed to save file: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to save file: {str(e)}"
        )


def delete_file(local_path: str) -> bool:
    """
    Delete file by local path.
    
    Args:
        local_path: Full local filesystem path to the file
    
    Returns:
        bool: True if file was deleted, False if file didn't exist or deletion failed
    """
    try:
        file_path = Path(local_path)
        if file_path.exists():
            file_path.unlink()
            logger.info(f"File deleted: {local_path}")
            return True
        else:
            logger.warning(f"File not found for deletion: {local_path}")
            return False
    except Exception as e:
        logger.error(f"Failed to delete file {local_path}: {e}")
        return False


def get_file_url(local_path: str) -> str:
    """
    Convert local file path to accessible URL.
    
    Args:
        local_path: Full local filesystem path
    
    Returns:
        str: URL path for accessing the file
    """
    try:
        base_path = Path(getattr(settings, 'UPLOAD_PATH', 'backend/uploads'))
        base_url = getattr(settings, 'UPLOAD_URL', '/uploads').rstrip('/')
        
        file_path = Path(local_path)
        
        # Check if path is under our upload directory
        if base_path in file_path.parents or file_path == base_path:
            relative_path = file_path.relative_to(base_path)
            return f"{base_url}/{relative_path.as_posix()}"
        else:
            logger.warning(f"File path outside upload directory: {local_path}")
            return local_path  # Return as-is if not in our upload structure
            
    except Exception as e:
        logger.error(f"Failed to generate URL for {local_path}: {e}")
        return local_path


def get_file_size(local_path: str) -> int:
    """
    Get file size in bytes.
    
    Args:
        local_path: Full local filesystem path
    
    Returns:
        int: File size in bytes, 0 if file doesn't exist
    """
    try:
        file_path = Path(local_path)
        if file_path.exists():
            return file_path.stat().st_size
        return 0
    except Exception as e:
        logger.error(f"Failed to get file size for {local_path}: {e}")
        return 0


def file_exists(local_path: str) -> bool:
    """
    Check if file exists.
    
    Args:
        local_path: Full local filesystem path
    
    Returns:
        bool: True if file exists, False otherwise
    """
    try:
        return Path(local_path).exists()
    except Exception:
        return False