# app/core/config.py
from pydantic_settings import BaseSettings, SettingsConfigDict
from pathlib import Path

class Settings(BaseSettings):
    DATABASE_URL: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/student_portal"
    SECRET_KEY: str = "CHANGE_ME"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Celery settings
    CELERY_BROKER_URL: str = "redis://localhost:6379/0"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/0"

    # Local storage settings
    UPLOAD_PATH: str = "backend/uploads"
    UPLOAD_URL: str = "/uploads"
    MAX_FILE_SIZE: int = 10 * 1024 * 1024  # 10MB

    model_config = SettingsConfigDict(
        env_file=Path(__file__).resolve().parent.parent.parent / ".env",
        env_file_encoding="utf-8",
        extra="ignore"  # This allows extra fields to be ignored
    )
    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 1025  # MailHog SMTP port
    SMTP_USER: str = ""    # MailHog doesn't require auth
    SMTP_PASSWORD: str = ""
    SMTP_TLS: bool = False
    SMTP_SSL: bool = False
    
    # Email sender info
    EMAIL_FROM: str = "noreply@studentportal.local"
    EMAIL_FROM_NAME: str = "Student Portal"
    
    # MailHog web interface (for viewing emails)
    MAILHOG_WEB_URL: str = "http://localhost:8025"
    
    # Email templates
    EMAIL_TEMPLATES_DIR: str = "app/email/templates"

    REDIS_URL: str = "redis://localhost:6379"
    REDIS_DB: int = 0
    REDIS_PASSWORD: str = ""
    REDIS_SOCKET_TIMEOUT: int = 5
    REDIS_SOCKET_KEEPALIVE: bool = True
    REDIS_HEALTH_CHECK_INTERVAL: int = 30
    
    # WebSocket settings
    WEBSOCKET_MAX_CONNECTIONS_PER_USER: int = 5
    WEBSOCKET_RATE_LIMIT_WINDOW: int = 60  # seconds
    WEBSOCKET_PING_INTERVAL: int = 20  # seconds
    WEBSOCKET_PING_TIMEOUT: int = 10   # seconds

settings = Settings()