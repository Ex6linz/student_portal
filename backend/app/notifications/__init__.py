"""
Real-time notifications module for Student Portal

This module provides WebSocket-based real-time notifications using Redis pub/sub.

Features:
- JWT authentication for WebSocket connections
- Redis pub/sub for scalable message distribution  
- Rate limiting (5 connections per user per minute)
- Automatic connection management and cleanup
- Broadcast and targeted notifications

Usage:
    # Send notification to specific user
    from app.notifications.router import send_notification_to_user
    
    await send_notification_to_user(
        user_id=user.id,
        notification_type="message",
        title="New Message",
        message="You have a new message from John",
        data={"message_id": 123}
    )
    
    # Send broadcast notification
    from app.notifications.router import send_notification_to_all_users
    
    await send_notification_to_all_users(
        notification_type="system",
        title="System Maintenance",
        message="System will be down for maintenance in 30 minutes"
    )

WebSocket Client Example:
    const ws = new WebSocket('ws://localhost:8000/ws/notifications?token=your_jwt_token');
    
    ws.onopen = () => console.log('Connected to notifications');
    ws.onmessage = (event) => {
        const notification = JSON.parse(event.data);
        console.log('Notification:', notification);
    };
    ws.onerror = (error) => console.error('WebSocket error:', error);
    ws.onclose = (event) => console.log('Connection closed:', event.code, event.reason);
"""

from .router import (
    router,
    send_notification_to_user,
    send_notification_to_all_users,
    get_redis_client,
)

__all__ = [
    "router",
    "send_notification_to_user", 
    "send_notification_to_all_users",
    "get_redis_client",
]