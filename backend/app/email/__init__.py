"""
Email module for Student Portal

This module provides email functionality including:
- SMTP email sending via Celery tasks
- Email confirmation templates
- Password reset templates
- MailHog integration for development

Usage:
    from app.email.tasks import send_email, send_confirmation_email
    
    # Send basic email
    result = send_email.delay("user@example.com", "Subject", "Body")
    
    # Send confirmation email
    result = send_confirmation_email.delay("user@example.com", "token123", "John")
"""

from .tasks import (
    send_email,
    send_confirmation_email,
    send_password_reset_email,
)

__all__ = [
    "send_email",
    "send_confirmation_email", 
    "send_password_reset_email",
]