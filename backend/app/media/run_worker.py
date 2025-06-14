#!/usr/bin/env python3
"""
Script to run Celery worker for media processing tasks.
Usage: python run_worker.py
"""

import os
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import and configure Celery app
from app.media.tasks import celery_app

if __name__ == "__main__":
    # Start Celery worker
    celery_app.worker_main([
        "worker",
        "--loglevel=info",
        "--concurrency=2",
        "--pool=threads",  # Use threads for I/O bound tasks
    ])