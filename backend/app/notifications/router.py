import asyncio
import json
import logging
from typing import Dict, Set, Optional
from uuid import UUID
from datetime import datetime, timedelta
import jwt
import redis.asyncio as redis
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query, HTTPException
from fastapi.websockets import WebSocketState
from sqlmodel import Session, select

from app.core.config import settings
from app.core.database import get_session
from app.auth.models import User

router = APIRouter(prefix="/ws", tags=["websockets"])

# Configure logging
logger = logging.getLogger(__name__)

# Redis client for pub/sub
redis_client: Optional[redis.Redis] = None

# Active WebSocket connections: {user_id: {websocket_id: websocket}}
active_connections: Dict[UUID, Dict[str, WebSocket]] = {}

# Rate limiting: {user_id: {count: int, reset_time: datetime}}
rate_limits: Dict[UUID, Dict[str, any]] = {}

# WebSocket connection counter for unique IDs
connection_counter = 0


async def get_redis_client() -> redis.Redis:
    """Get or create Redis client for pub/sub"""
    global redis_client
    
    if redis_client is None:
        redis_url = getattr(settings, 'REDIS_URL', 'redis://localhost:6379')
        redis_client = redis.from_url(
            redis_url,
            encoding="utf-8",
            decode_responses=True,
            socket_connect_timeout=5,
            socket_keepalive=True,
            socket_keepalive_options={},
            health_check_interval=30,
        )
        
        # Test connection
        try:
            await redis_client.ping()
            logger.info("Redis client connected successfully")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            raise
    
    return redis_client


async def authenticate_websocket_token(token: str) -> UUID:
    """
    Authenticate WebSocket token and return user_id
    
    Args:
        token: JWT access token
        
    Returns:
        UUID: User ID if valid
        
    Raises:
        HTTPException: If token is invalid
    """
    try:
        # Decode JWT token
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM]
        )
        
        # Check token type (should be access token)
        if payload.get("typ") and payload.get("typ") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        
        user_id = UUID(payload["sub"])
        
        # Verify user exists in database
        db = next(get_session())
        user = db.scalar(select(User).where(User.id == user_id))
        
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        
        return user_id
        
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid user ID format")


async def check_rate_limit(user_id: UUID) -> bool:
    """
    Check WebSocket connection rate limit
    
    Args:
        user_id: User ID to check
        
    Returns:
        bool: True if within rate limit, False if exceeded
    """
    now = datetime.utcnow()
    
    # Clean up old rate limit entries
    if user_id in rate_limits:
        if now > rate_limits[user_id]["reset_time"]:
            del rate_limits[user_id]
    
    # Check current rate limit
    if user_id not in rate_limits:
        rate_limits[user_id] = {
            "count": 1,
            "reset_time": now + timedelta(minutes=1)  # 1 minute window
        }
        return True
    
    # Check if limit exceeded (max 5 connections per minute)
    if rate_limits[user_id]["count"] >= 5:
        return False
    
    rate_limits[user_id]["count"] += 1
    return True


async def add_connection(user_id: UUID, websocket: WebSocket) -> str:
    """
    Add WebSocket connection to active connections
    
    Args:
        user_id: User ID
        websocket: WebSocket instance
        
    Returns:
        str: Unique connection ID
    """
    global connection_counter
    connection_counter += 1
    
    connection_id = f"ws_{connection_counter}_{datetime.utcnow().timestamp()}"
    
    if user_id not in active_connections:
        active_connections[user_id] = {}
    
    active_connections[user_id][connection_id] = websocket
    
    logger.info(f"Added WebSocket connection {connection_id} for user {user_id}")
    return connection_id


async def remove_connection(user_id: UUID, connection_id: str):
    """
    Remove WebSocket connection from active connections
    
    Args:
        user_id: User ID
        connection_id: Connection ID to remove
    """
    if user_id in active_connections:
        if connection_id in active_connections[user_id]:
            del active_connections[user_id][connection_id]
            logger.info(f"Removed WebSocket connection {connection_id} for user {user_id}")
        
        # Clean up empty user entries
        if not active_connections[user_id]:
            del active_connections[user_id]


async def subscribe_to_notifications(user_id: UUID, websocket: WebSocket):
    """
    Subscribe to Redis channel and forward notifications to WebSocket
    
    Args:
        user_id: User ID to subscribe for
        websocket: WebSocket to send notifications to
    """
    redis_conn = await get_redis_client()
    pubsub = redis_conn.pubsub()
    
    channel_name = f"notif:{user_id}"
    
    try:
        # Subscribe to user's notification channel
        await pubsub.subscribe(channel_name)
        logger.info(f"Subscribed to Redis channel: {channel_name}")
        
        # Listen for messages
        async for message in pubsub.listen():
            if message["type"] == "message":
                try:
                    # Parse notification data
                    notification_data = json.loads(message["data"])
                    
                    # Add timestamp if not present
                    if "timestamp" not in notification_data:
                        notification_data["timestamp"] = datetime.utcnow().isoformat()
                    
                    # Send notification to WebSocket
                    if websocket.client_state == WebSocketState.CONNECTED:
                        await websocket.send_json(notification_data)
                        logger.debug(f"Sent notification to user {user_id}: {notification_data}")
                    else:
                        logger.warning(f"WebSocket disconnected for user {user_id}")
                        break
                        
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to decode notification message: {e}")
                except Exception as e:
                    logger.error(f"Error sending notification to user {user_id}: {e}")
                    break
                    
    except Exception as e:
        logger.error(f"Error in Redis subscription for user {user_id}: {e}")
    finally:
        try:
            await pubsub.unsubscribe(channel_name)
            await pubsub.aclose()
            logger.info(f"Unsubscribed from Redis channel: {channel_name}")
        except Exception as e:
            logger.error(f"Error closing Redis subscription: {e}")


@router.websocket("/notifications")
async def ws_notifications(
    websocket: WebSocket,
    token: str = Query(..., description="JWT access token for authentication")
):
    """
    WebSocket endpoint for real-time notifications
    
    **Authentication:**
    - Requires valid JWT access token as query parameter
    - Token must be non-expired and associated with existing user
    
    **Rate Limiting:**
    - Maximum 5 connections per user per minute
    - Connections are tracked and cleaned up automatically
    
    **Notification Format:**
    ```json
    {
        "type": "notification_type",
        "title": "Notification Title", 
        "message": "Notification message",
        "data": {...},
        "timestamp": "2025-01-30T12:00:00.000Z"
    }
    ```
    
    **Usage:**
    ```javascript
    const ws = new WebSocket('ws://localhost:8000/ws/notifications?token=your_jwt_token');
    ws.onmessage = (event) => {
        const notification = JSON.parse(event.data);
        console.log('Received notification:', notification);
    };
    ```
    
    **Error Handling:**
    - 1008: Authentication failed
    - 1013: Rate limit exceeded  
    - 1011: Internal server error
    """
    
    connection_id = None
    user_id = None
    
    try:
        # Authenticate token
        try:
            user_id = await authenticate_websocket_token(token)
        except HTTPException as e:
            await websocket.close(code=1008, reason=f"Authentication failed: {e.detail}")
            return
        
        # Check rate limit
        if not await check_rate_limit(user_id):
            await websocket.close(code=1013, reason="Rate limit exceeded. Max 5 connections per minute.")
            return
        
        # Accept WebSocket connection
        await websocket.accept()
        logger.info(f"WebSocket connection accepted for user {user_id}")
        
        # Add to active connections
        connection_id = await add_connection(user_id, websocket)
        
        # Send connection confirmation
        await websocket.send_json({
            "type": "connection_established",
            "message": "Successfully connected to notifications",
            "user_id": str(user_id),
            "connection_id": connection_id,
            "timestamp": datetime.utcnow().isoformat()
        })
        
        # Start listening for notifications
        await subscribe_to_notifications(user_id, websocket)
        
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for user {user_id}")
    except Exception as e:
        logger.error(f"WebSocket error for user {user_id}: {e}")
        try:
            if websocket.client_state == WebSocketState.CONNECTED:
                await websocket.close(code=1011, reason="Internal server error")
        except:
            pass
    finally:
        # Clean up connection
        if user_id and connection_id:
            await remove_connection(user_id, connection_id)


# Utility functions for sending notifications

async def send_notification_to_user(
    user_id: UUID,
    notification_type: str,
    title: str,
    message: str,
    data: dict = None
):
    """
    Send notification to specific user via Redis pub/sub
    
    Args:
        user_id: Target user ID
        notification_type: Type of notification (e.g., 'message', 'alert', 'update')
        title: Notification title
        message: Notification message
        data: Additional data payload
    """
    try:
        redis_conn = await get_redis_client()
        
        notification_payload = {
            "type": notification_type,
            "title": title,
            "message": message,
            "data": data or {},
            "timestamp": datetime.utcnow().isoformat()
        }
        
        channel_name = f"notif:{user_id}"
        
        # Publish to Redis channel
        await redis_conn.publish(channel_name, json.dumps(notification_payload))
        
        logger.info(f"Published notification to channel {channel_name}: {notification_type}")
        
    except Exception as e:
        logger.error(f"Failed to send notification to user {user_id}: {e}")


async def send_notification_to_all_users(
    notification_type: str,
    title: str,
    message: str,
    data: dict = None
):
    """
    Send notification to all connected users
    
    Args:
        notification_type: Type of notification
        title: Notification title  
        message: Notification message
        data: Additional data payload
    """
    try:
        # Send to all currently connected users
        for user_id in list(active_connections.keys()):
            await send_notification_to_user(user_id, notification_type, title, message, data)
            
        logger.info(f"Sent broadcast notification to {len(active_connections)} users")
        
    except Exception as e:
        logger.error(f"Failed to send broadcast notification: {e}")


# Health check endpoint for WebSocket service
@router.get("/health")
async def websocket_health():
    """Health check for WebSocket notification service"""
    try:
        redis_conn = await get_redis_client()
        await redis_conn.ping()
        
        return {
            "status": "healthy",
            "redis_connected": True,
            "active_connections": len(active_connections),
            "total_connections": sum(len(conns) for conns in active_connections.values()),
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "redis_connected": False,
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }