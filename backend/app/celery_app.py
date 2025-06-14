from celery import Celery
from app.core.config import settings

# Create Celery app instance
celery_app = Celery(
    "student_portal",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=[
        "app.email.tasks",
        "app.media.tasks",  # Include existing media tasks
    ]
)

# Celery configuration
celery_app.conf.update(
    # Task routing
    task_routes={
        "app.email.tasks.*": {"queue": "email"},
        "app.media.tasks.*": {"queue": "media"},
    },
    
    # Task execution settings
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    
    # Task result settings
    result_expires=3600,  # 1 hour
    
    # Task retry settings
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    
    # Worker settings
    worker_prefetch_multiplier=1,
    worker_max_tasks_per_child=1000,
    
    # Task time limits
    task_soft_time_limit=60,  # 1 minute soft limit
    task_time_limit=120,      # 2 minute hard limit
    
    # Email task specific settings
    task_annotations={
        "app.email.tasks.send_email": {
            "rate_limit": "10/m",  # 10 emails per minute
            "retry_policy": {
                "max_retries": 3,
                "interval_start": 0,
                "interval_step": 0.2,
                "interval_max": 0.2,
            },
        },
    },
)

# Auto-discover tasks in modules
celery_app.autodiscover_tasks([
    "app.email",
    "app.media",
])

if __name__ == "__main__":
    celery_app.start()