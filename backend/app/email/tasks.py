import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from typing import Optional

from celery import Task
from celery.exceptions import Retry

from app.celery_app import celery_app
from app.core.config import settings

# Configure logging
logger = logging.getLogger(__name__)


class EmailTask(Task):
    """Base task class for email operations with custom retry logic"""
    
    autoretry_for = (
        smtplib.SMTPException,
        smtplib.SMTPConnectError,
        smtplib.SMTPServerDisconnected,
        ConnectionError,
        TimeoutError,
    )
    max_retries = 3
    default_retry_delay = 60  # 1 minute
    retry_backoff = True
    retry_backoff_max = 300  # 5 minutes
    retry_jitter = True

    def retry(self, args=None, kwargs=None, exc=None, throw=True, eta=None, countdown=None, max_retries=None, **options):
        """Custom retry logic with logging"""
        if exc:
            logger.warning(
                f"Email task {self.name} failed with {type(exc).__name__}: {exc}. "
                f"Retrying in {countdown or self.default_retry_delay} seconds. "
                f"Attempt {self.request.retries + 1}/{max_retries or self.max_retries}"
            )
        return super().retry(args, kwargs, exc, throw, eta, countdown, max_retries, **options)


@celery_app.task(bind=True, base=EmailTask, name="app.email.tasks.send_email")
def send_email(
    self,
    to: str,
    subject: str,
    body: str,
    html_body: Optional[str] = None,
    from_email: Optional[str] = None,
    from_name: Optional[str] = None
) -> dict:
    """
    Send an email via SMTP (MailHog for development)
    
    Args:
        to: Recipient email address
        subject: Email subject
        body: Plain text email body
        html_body: Optional HTML email body
        from_email: Optional sender email (defaults to settings.EMAIL_FROM)
        from_name: Optional sender name (defaults to settings.EMAIL_FROM_NAME)
    
    Returns:
        dict: Result with status and message info
    
    Raises:
        Exception: If email sending fails after all retries
    """
    
    # Use defaults if not provided
    from_email = from_email or settings.EMAIL_FROM
    from_name = from_name or settings.EMAIL_FROM_NAME
    
    # Log the email attempt
    logger.info(
        f"Sending email to {to} with subject '{subject}' "
        f"(task_id: {self.request.id})"
    )
    
    try:
        # Create message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = Header(subject, "utf-8")
        msg["From"] = f"{from_name} <{from_email}>"
        msg["To"] = to
        msg["Message-ID"] = f"<{self.request.id}@studentportal.local>"
        
        # Add plain text part
        text_part = MIMEText(body, "plain", "utf-8")
        msg.attach(text_part)
        
        # Add HTML part if provided
        if html_body:
            html_part = MIMEText(html_body, "html", "utf-8")
            msg.attach(html_part)
        
        # Connect to SMTP server (MailHog)
        smtp_server = smtplib.SMTP(
            host=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            timeout=30
        )
        
        try:
            # MailHog doesn't require authentication, but handle it if needed
            if settings.SMTP_TLS:
                smtp_server.starttls()
            
            if settings.SMTP_USER and settings.SMTP_PASSWORD:
                smtp_server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            
            # Send the email
            text = msg.as_string()
            smtp_server.sendmail(from_email, [to], text)
            
            logger.info(
                f"Email successfully sent to {to} "
                f"(task_id: {self.request.id})"
            )
            
            return {
                "status": "success",
                "task_id": self.request.id,
                "to": to,
                "subject": subject,
                "message": "Email sent successfully",
                "mailhog_url": f"{settings.MAILHOG_WEB_URL}"
            }
            
        finally:
            smtp_server.quit()
            
    except Exception as exc:
        logger.error(
            f"Failed to send email to {to}: {type(exc).__name__}: {exc} "
            f"(task_id: {self.request.id})"
        )
        
        # Check if we should retry
        if self.request.retries < self.max_retries:
            # Calculate exponential backoff delay
            countdown = min(
                self.default_retry_delay * (2 ** self.request.retries),
                self.retry_backoff_max
            )
            raise self.retry(exc=exc, countdown=countdown)
        
        # Final failure after all retries
        logger.critical(
            f"Email to {to} failed permanently after {self.max_retries} retries "
            f"(task_id: {self.request.id})"
        )
        
        return {
            "status": "failed",
            "task_id": self.request.id,
            "to": to,
            "subject": subject,
            "error": str(exc),
            "message": f"Email failed after {self.max_retries} retries"
        }


@celery_app.task(bind=True, base=EmailTask, name="app.email.tasks.send_confirmation_email")
def send_confirmation_email(self, to: str, confirmation_token: str, user_name: str = None) -> dict:
    """
    Send email confirmation email
    
    Args:
        to: User email address
        confirmation_token: Email confirmation token
        user_name: Optional user name for personalization
    
    Returns:
        dict: Result from send_email task
    """
    
    subject = "Confirm Your Email Address - Student Portal"
    
    # Create confirmation URL (adjust based on your frontend)
    confirmation_url = f"http://localhost:3000/confirm-email?token={confirmation_token}"
    
    # Plain text body
    body = f"""
Hello{f' {user_name}' if user_name else ''},

Thank you for registering with Student Portal!

Please confirm your email address by clicking the link below:
{confirmation_url}

This link will expire in 24 hours.

If you didn't create an account with us, you can safely ignore this email.

Best regards,
Student Portal Team
"""
    
    # HTML body
    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Confirm Your Email</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #2c3e50;">Welcome to Student Portal!</h2>
        
        <p>Hello{f' {user_name}' if user_name else ''},</p>
        
        <p>Thank you for registering with Student Portal!</p>
        
        <p>Please confirm your email address by clicking the button below:</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{confirmation_url}" 
               style="background-color: #3498db; color: white; padding: 12px 30px; 
                      text-decoration: none; border-radius: 5px; display: inline-block;">
                Confirm Email Address
            </a>
        </div>
        
        <p>Or copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #7f8c8d;">{confirmation_url}</p>
        
        <p><small>This link will expire in 24 hours.</small></p>
        
        <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
        
        <p style="color: #7f8c8d; font-size: 12px;">
            If you didn't create an account with us, you can safely ignore this email.
        </p>
    </div>
</body>
</html>
"""
    
    # Use the main send_email task
    return send_email.apply_async(
        args=[to, subject, body],
        kwargs={"html_body": html_body}
    )


@celery_app.task(bind=True, base=EmailTask, name="app.email.tasks.send_password_reset_email")
def send_password_reset_email(self, to: str, reset_token: str, user_name: str = None) -> dict:
    """
    Send password reset email
    
    Args:
        to: User email address
        reset_token: Password reset token
        user_name: Optional user name for personalization
    
    Returns:
        dict: Result from send_email task
    """
    
    subject = "Reset Your Password - Student Portal"
    
    # Create reset URL (adjust based on your frontend)
    reset_url = f"http://localhost:3000/reset-password?token={reset_token}"
    
    # Plain text body
    body = f"""
Hello{f' {user_name}' if user_name else ''},

You requested to reset your password for your Student Portal account.

Click the link below to reset your password:
{reset_url}

This link will expire in 1 hour for security reasons.

If you didn't request this password reset, you can safely ignore this email.

Best regards,
Student Portal Team
"""
    
    # HTML body
    html_body = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Reset Your Password</title>
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
    <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
        <h2 style="color: #e74c3c;">Password Reset Request</h2>
        
        <p>Hello{f' {user_name}' if user_name else ''},</p>
        
        <p>You requested to reset your password for your Student Portal account.</p>
        
        <p>Click the button below to reset your password:</p>
        
        <div style="text-align: center; margin: 30px 0;">
            <a href="{reset_url}" 
               style="background-color: #e74c3c; color: white; padding: 12px 30px; 
                      text-decoration: none; border-radius: 5px; display: inline-block;">
                Reset Password
            </a>
        </div>
        
        <p>Or copy and paste this link into your browser:</p>
        <p style="word-break: break-all; color: #7f8c8d;">{reset_url}</p>
        
        <p><small>This link will expire in 1 hour for security reasons.</small></p>
        
        <hr style="border: none; border-top: 1px solid #eee; margin: 30px 0;">
        
        <p style="color: #7f8c8d; font-size: 12px;">
            If you didn't request this password reset, you can safely ignore this email.
        </p>
    </div>
</body>
</html>
"""
    
    # Use the main send_email task
    return send_email.apply_async(
        args=[to, subject, body],
        kwargs={"html_body": html_body}
    )