"""
Email service layer for common email operations
"""

import logging
from datetime import datetime
from typing import Optional

from app.email.tasks import send_email, send_confirmation_email, send_password_reset_email
from app.celery_app import celery_app

logger = logging.getLogger(__name__)


class EmailService:
    """Service class for email operations"""
    
    @staticmethod
    def send_welcome_email(user_email: str, user_name: str) -> str:
        """Send a welcome email to new user"""
        
        subject = "Welcome to Student Portal!"
        body = f"""
Hello {user_name},

Welcome to Student Portal! We're excited to have you on board.

Here are a few things you can do to get started:
• Complete your profile
• Join discussions in the forum
• Upload your avatar

If you have any questions, feel free to reach out to our support team.

Best regards,
The Student Portal Team
        """
        
        html_body = f"""
<!DOCTYPE html>
<html>
<head><title>Welcome to Student Portal</title></head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #2c3e50;">Welcome to Student Portal! 🎉</h2>
        
        <p>Hello {user_name},</p>
        
        <p>Welcome to Student Portal! We're excited to have you on board.</p>
        
        <h3>Get Started:</h3>
        <ul>
            <li>Complete your profile</li>
            <li>Join discussions in the forum</li>
            <li>Upload your avatar</li>
        </ul>
        
        <p>If you have any questions, feel free to reach out to our support team.</p>
        
        <p>Best regards,<br>The Student Portal Team</p>
    </div>
</body>
</html>
        """
        
        # Send asynchronously
        task = send_email.delay(user_email, subject, body, html_body)
        
        logger.info(f"Welcome email queued for {user_email} (task: {task.id})")
        return task.id
    
    @staticmethod
    def send_notification_email(
        user_email: str, 
        user_name: str, 
        notification_type: str, 
        message: str
    ) -> str:
        """Send a notification email"""
        
        subject = f"Student Portal Notification: {notification_type}"
        
        body = f"""
Hello {user_name},

You have a new notification from Student Portal:

{message}

Best regards,
Student Portal Team
        """
        
        task = send_email.delay(user_email, subject, body)
        
        logger.info(f"Notification email queued for {user_email} (task: {task.id})")
        return task.id
    
    @staticmethod
    def trigger_email_confirmation(user_email: str, token: str, user_name: str = None) -> str:
        """Trigger email confirmation"""
        
        task = send_confirmation_email.delay(user_email, token, user_name)
        
        logger.info(f"Email confirmation queued for {user_email} (task: {task.id})")
        return task.id
    
    @staticmethod
    def trigger_password_reset(user_email: str, token: str, user_name: str = None) -> str:
        """Trigger password reset email"""
        
        task = send_password_reset_email.delay(user_email, token, user_name)
        
        logger.info(f"Password reset email queued for {user_email} (task: {task.id})")
        return task.id
    
    @staticmethod
    def check_email_status(task_id: str) -> dict:
        """Check the status of an email task"""
        
        result = celery_app.AsyncResult(task_id)
        
        return {
            "task_id": task_id,
            "status": result.status,
            "result": result.result if result.successful() else None,
            "error": str(result.result) if result.failed() else None,
            "traceback": result.traceback if result.failed() else None,
            "completed_at": result.date_done.isoformat() if result.date_done else None
        }


# Convenience functions for direct import
def send_welcome_email(user_email: str, user_name: str) -> str:
    return EmailService.send_welcome_email(user_email, user_name)

def check_email_status(task_id: str) -> dict:
    return EmailService.check_email_status(task_id)