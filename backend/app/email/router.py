from fastapi import APIRouter, HTTPException, Depends, status
from pydantic import BaseModel, EmailStr
from typing import Optional
from datetime import datetime
import logging

from app.auth.deps import get_current_user
from app.auth.models import User
from app.email.tasks import send_email
from app.celery_app import celery_app

router = APIRouter(tags=["email"])
logger = logging.getLogger(__name__)


class EmailRequest(BaseModel):
    to: EmailStr
    subject: str
    body: str
    html_body: Optional[str] = None


class EmailStatusResponse(BaseModel):
    task_id: str
    status: str
    result: Optional[dict] = None
    traceback: Optional[str] = None


@router.post("/send")
async def send_custom_email(
    email_request: EmailRequest,
    current_user: User = Depends(get_current_user)
):
    """Send a custom email (admin only)"""
    
    # Add role-based access control if needed
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can send custom emails"
        )
    
    try:
        task = send_email.delay(
            to=email_request.to,
            subject=email_request.subject,
            body=email_request.body,
            html_body=email_request.html_body
        )
        
        logger.info(f"Custom email queued by {current_user.email} to {email_request.to} (task: {task.id})")
        
        return {
            "message": "Email queued successfully",
            "task_id": task.id,
            "status": "queued",
            "recipient": email_request.to
        }
        
    except Exception as e:
        logger.error(f"Failed to queue custom email: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to queue email: {str(e)}"
        )


@router.get("/status/{task_id}", response_model=EmailStatusResponse)
async def get_email_status(
    task_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get email task status"""
    
    try:
        result = celery_app.AsyncResult(task_id)
        
        return EmailStatusResponse(
            task_id=task_id,
            status=result.status,
            result=result.result if result.successful() else None,
            traceback=result.traceback if result.failed() else None
        )
        
    except Exception as e:
        logger.error(f"Failed to get task status for {task_id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get task status: {str(e)}"
        )


@router.post("/test")
async def send_test_email(
    to: EmailStr,
    current_user: User = Depends(get_current_user)
):
    """Send a test email (for debugging)"""
    
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only admins can send test emails"
        )
    
    try:
        task = send_email.delay(
            to=to,
            subject="Test Email from Student Portal",
            body=f"""
Hello!

This is a test email sent from Student Portal.

Sent to: {to}
Sent by: {current_user.email}
Time: {datetime.utcnow().isoformat()}

If you received this email, the email system is working correctly!

Best regards,
Student Portal System
            """,
            html_body=f"""
<!DOCTYPE html>
<html>
<head><title>Test Email</title></head>
<body style="font-family: Arial, sans-serif;">
    <h2 style="color: #2c3e50;">Test Email ✅</h2>
    <p>This is a test email sent from Student Portal.</p>
    <ul>
        <li><strong>Sent to:</strong> {to}</li>
        <li><strong>Sent by:</strong> {current_user.email}</li>
        <li><strong>Time:</strong> {datetime.utcnow().isoformat()}</li>
    </ul>
    <p>If you received this email, the email system is working correctly!</p>
    <hr>
    <p><small>Student Portal System</small></p>
</body>
</html>
            """
        )
        
        logger.info(f"Test email sent by {current_user.email} to {to} (task: {task.id})")
        
        return {
            "message": "Test email sent",
            "task_id": task.id,
            "recipient": to,
            "mailhog_url": "http://localhost:8025"
        }
        
    except Exception as e:
        logger.error(f"Failed to send test email: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to send test email: {str(e)}"
        )