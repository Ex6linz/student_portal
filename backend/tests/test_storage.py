import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import patch
from io import BytesIO

from fastapi import UploadFile, HTTPException
from app.core.storage import save_file, delete_file, get_file_url, file_exists, get_file_size


@pytest.fixture
def temp_upload_dir():
    """Create temporary directory for testing"""
    temp_path = tempfile.mkdtemp()
    yield temp_path
    shutil.rmtree(temp_path)


@pytest.fixture
def mock_upload_file():
    """Create mock UploadFile"""
    file_content = b"test file content"
    file_obj = BytesIO(file_content)
    
    # Fixed: Use 'headers' parameter instead of 'content_type'
    upload_file = UploadFile(
        filename="test.jpg",
        file=file_obj,
        headers={"content-type": "image/jpeg"}
    )
    return upload_file


class TestLocalStorage:
    
    def test_save_file_success(self, temp_upload_dir, mock_upload_file):
        """Test successful file save"""
        with patch('app.core.storage.settings') as mock_settings:
            mock_settings.UPLOAD_PATH = temp_upload_dir
            mock_settings.UPLOAD_URL = "/test-uploads"
            mock_settings.MAX_FILE_SIZE = 10 * 1024 * 1024
            
            url, local_path, generated_filename = save_file(mock_upload_file, "avatar")
            
            # Check that file was created
            assert Path(local_path).exists()
            
            # Check URL format
            assert url.startswith("/test-uploads/avatar/")
            assert url.endswith("_test.jpg")
            
            # Check that generated filename is different from original
            assert generated_filename != "test.jpg"
            assert generated_filename.endswith("_test.jpg")
            
            # Check file content
            with open(local_path, "rb") as f:
                assert f.read() == b"test file content"
    
    def test_save_file_invalid_purpose(self, mock_upload_file):
        """Test save_file with invalid purpose"""
        with pytest.raises(HTTPException) as exc_info:
            save_file(mock_upload_file, "invalid")
        
        assert exc_info.value.status_code == 400
        assert "Purpose must be one of" in str(exc_info.value.detail)
    
    def test_save_file_no_filename(self):
        """Test save_file with no filename"""
        file_obj = BytesIO(b"content")
        upload_file = UploadFile(filename=None, file=file_obj)
        
        with pytest.raises(HTTPException) as exc_info:
            save_file(upload_file, "avatar")
        
        assert exc_info.value.status_code == 400
        assert "Filename is required" in str(exc_info.value.detail)
    
    def test_delete_file_success(self, temp_upload_dir, mock_upload_file):
        """Test successful file deletion"""
        with patch('app.core.storage.settings') as mock_settings:
            mock_settings.UPLOAD_PATH = temp_upload_dir
            mock_settings.UPLOAD_URL = "/test-uploads"
            
            # Save file first
            url, local_path, generated_filename = save_file(mock_upload_file, "post")
            assert Path(local_path).exists()
            
            # Delete file
            result = delete_file(local_path)
            assert result is True
            assert not Path(local_path).exists()
    
    def test_delete_nonexistent_file(self):
        """Test deleting non-existent file"""
        result = delete_file("/nonexistent/path/file.jpg")
        assert result is False
    
    def test_get_file_url(self, temp_upload_dir):
        """Test URL generation"""
        with patch('app.core.storage.settings') as mock_settings:
            mock_settings.UPLOAD_PATH = temp_upload_dir
            mock_settings.UPLOAD_URL = "/test-uploads"
            
            local_path = f"{temp_upload_dir}/avatar/test_file.jpg"
            url = get_file_url(local_path)
            assert url == "/test-uploads/avatar/test_file.jpg"
    
    def test_file_exists(self, temp_upload_dir, mock_upload_file):
        """Test file existence check"""
        with patch('app.core.storage.settings') as mock_settings:
            mock_settings.UPLOAD_PATH = temp_upload_dir
            mock_settings.UPLOAD_URL = "/test-uploads"
            
            # Save file
            url, local_path, generated_filename = save_file(mock_upload_file, "other")
            
            # Check existence
            assert file_exists(local_path) is True
            assert file_exists("/nonexistent/file.jpg") is False
    
    def test_get_file_size(self, temp_upload_dir, mock_upload_file):
        """Test file size retrieval"""
        with patch('app.core.storage.settings') as mock_settings:
            mock_settings.UPLOAD_PATH = temp_upload_dir
            mock_settings.UPLOAD_URL = "/test-uploads"
            
            # Save file
            url, local_path, generated_filename = save_file(mock_upload_file, "post")
            
            # Check size
            size = get_file_size(local_path)
            assert size == len(b"test file content")
            
            # Non-existent file
            assert get_file_size("/nonexistent/file.jpg") == 0