import logging
import asyncio
from typing import List, Optional
from uuid import UUID

from fastapi import Depends, HTTPException, Path, Body, status, Request, Query, APIRouter
from sqlalchemy.orm import Session
from sqlalchemy import select, desc, asc, func, and_
from sqlalchemy.orm import selectinload, joinedload
from sqlalchemy.exc import IntegrityError

from app.core.database import get_session          
from app.forum.models import Topic, Post, Comment, PostLike  # Added PostLike
from app.auth.deps import get_current_user
from app.auth.models import User
from app.core.limiter import limiter
from app.forum.schemas import (
    TopicRead, TopicReadWithPosts, TopicCreate, PostCreate, CommentCreate, 
    CommentRead, PostRead, TopicList, PostList, CommentList, PostLikeResponse, PostLikeBase, PostLikeInfo
)

# Redis imports with error handling
try:
    import redis.asyncio as redis
    import json
    from app.core.config import settings
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

router = APIRouter(tags=["forum"])

# Configure logging
logger = logging.getLogger(__name__)

PAGE_SIZE = 20

# Redis client for notifications (optional)
redis_client: Optional[redis.Redis] = None

async def get_redis_client():
    """Get Redis client for publishing notifications"""
    global redis_client
    if not REDIS_AVAILABLE:
        return None
        
    if redis_client is None:
        try:
            redis_url = getattr(settings, 'REDIS_URL', 'redis://localhost:6379')
            redis_client = redis.from_url(redis_url, encoding="utf-8", decode_responses=True)
            # Test connection
            await redis_client.ping()
        except Exception as e:
            logger.warning(f"Redis not available for notifications: {e}")
            return None
    return redis_client

async def publish_notification(notification_data: dict):
    """
    Publish notification to Redis channel (gracefully handles Redis unavailability)
    
    Args:
        notification_data: Notification payload to publish
    """
    try:
        if not REDIS_AVAILABLE:
            logger.debug("Redis not available, skipping notification")
            return
            
        redis_conn = await get_redis_client()
        if not redis_conn:
            logger.debug("Redis client not available, skipping notification")
            return
        
        # Extract target user ID
        target_user_id = notification_data.get("to")
        if not target_user_id:
            logger.warning("No target user ID in notification data")
            return
        
        # Publish to user's notification channel
        channel_name = f"notif:{target_user_id}"
        
        # Convert notification data to match WebSocket format
        websocket_notification = {
            "type": notification_data.get("type", "notification"),
            "title": "New Reply" if notification_data.get("type") == "new_reply" else "New Comment",
            "message": notification_data.get("message", "You have a new notification"),
            "data": notification_data,
            "timestamp": None  # Will be added by WebSocket handler
        }
        
        await redis_conn.publish(channel_name, json.dumps(websocket_notification))
        logger.info(f"Published notification to channel {channel_name}: {notification_data}")
        
    except Exception as e:
        # Don't fail the request if notifications fail
        logger.error(f"Failed to publish notification: {e}")


def run_async_safely(coro):
    """
    Safely run async function in sync context (for testing compatibility)
    """
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If we're already in an async context, create a task
            asyncio.create_task(coro)
        else:
            # If we're in a sync context, run the coroutine
            loop.run_until_complete(coro)
    except Exception as e:
        logger.error(f"Error running async notification: {e}")


@router.get(
    "/topics",
    response_model=TopicList,
    status_code=status.HTTP_200_OK,
    summary="Lista tematów",
    description="Zwraca 20 tematów na stronę z informacjami o paginacji.",
)
def list_topics(
    page: int = Query(1, ge=1, description="Numer strony (od 1)"),
    db: Session = Depends(get_session),
):
    # Count total topics
    total_stmt = select(func.count(Topic.id))
    total = db.scalar(total_stmt)
    
    # Calculate total pages
    total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE if total > 0 else 0
    
    # Get topics for current page
    stmt = (
        select(Topic)
        .order_by(desc(Topic.created_at))
        .limit(PAGE_SIZE)
        .offset((page - 1) * PAGE_SIZE)
    )
    topics = db.scalars(stmt).all()
    
    return TopicList(
        items=topics,
        total=total,
        page=page,
        page_size=PAGE_SIZE,
        total_pages=total_pages
    )


@router.get(
    "/topics/{id}",
    response_model=TopicReadWithPosts,
    status_code=status.HTTP_200_OK,
    summary="Szczegóły tematu z postami",
)
def topic_detail(
    id: int = Path(..., ge=1, description="ID tematu"),
    db: Session = Depends(get_session),
):
    # Use joinedload and manual sorting for posts too
    stmt = (
        select(Topic)
        .options(joinedload(Topic.posts))
        .where(Topic.id == id)
    )
    topic: Topic | None = db.scalar(stmt)

    if not topic:
        raise HTTPException(status_code=404, detail="Topic not found")

    # Sort posts manually after loading
    if topic.posts:
        topic.posts.sort(key=lambda p: p.created_at)

    return topic


@router.get(
    "/topics/{id}/posts",
    response_model=PostList,
    status_code=status.HTTP_200_OK,
    summary="Lista postów w temacie",
    description="Zwraca posty w temacie z paginacją.",
)
def list_topic_posts(
    id: int = Path(..., ge=1, description="ID tematu"),
    page: int = Query(1, ge=1, description="Numer strony (od 1)"),
    db: Session = Depends(get_session),
):
    # Check if topic exists
    topic_exists = db.scalar(select(Topic.id).where(Topic.id == id))
    if not topic_exists:
        raise HTTPException(status_code=404, detail="Topic not found")
    
    # Count total posts in topic
    total_stmt = select(func.count(Post.id)).where(Post.topic_id == id)
    total = db.scalar(total_stmt)
    
    # Calculate total pages
    total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE if total > 0 else 0
    
    # Get posts for current page
    stmt = (
        select(Post)
        .where(Post.topic_id == id)
        .order_by(asc(Post.created_at))
        .limit(PAGE_SIZE)
        .offset((page - 1) * PAGE_SIZE)
    )
    posts = db.scalars(stmt).all()
    
    return PostList(
        items=posts,
        total=total,
        page=page,
        page_size=PAGE_SIZE,
        total_pages=total_pages
    )


@router.post(
    "/topics",
    status_code=status.HTTP_201_CREATED,
    response_model=TopicRead,
    summary="Utwórz nowy temat",
    description="Wymaga JWT; tytuł 10-120 znaków, treść min 20 znaków.",
)
@limiter.limit("30/minute")
def create_topic(
    request: Request,
    payload: TopicCreate = Body(...),
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    topic = Topic(title=payload.title, author_id=current_user.id)
    db.add(topic)
    db.flush()                        

    if hasattr(payload, "content") and payload.content:
        first_post = Post(
            topic_id=topic.id,
            author_id=current_user.id,
            content=payload.content,
        )
        db.add(first_post)

    db.commit()
    db.refresh(topic)
    return topic


@router.post(
    "/topics/{id}/posts",
    status_code=status.HTTP_201_CREATED,
    summary="Dodaj posta do tematu",
    description="Wymaga JWT; treść min. 1 znak.",
)
@limiter.limit("30/minute")
def create_post(
    request: Request,
    id: int = Path(..., ge=1, description="ID tematu"),
    payload: PostCreate = Body(...),
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    # 1. Check if topic exists and get topic details
    topic = db.scalar(select(Topic).where(Topic.id == id))
    if not topic:
        raise HTTPException(status_code=404, detail="Topic not found")

    # 2. Create the post
    post = Post(
        topic_id=id,
        author_id=current_user.id,
        content=payload.content,
    )
    db.add(post)
    db.commit()
    db.refresh(post)

    # 3. Send notification asynchronously (non-blocking)
    # Only notify if the post author is different from topic author
    if topic.author_id != current_user.id:
        notification_data = {
            "to": str(topic.author_id),  # Target user (topic author)
            "type": "new_reply",
            "post_id": post.id,
            "topic_id": id,
            "topic_title": topic.title,
            "author_email": current_user.email,
            "author_id": str(current_user.id),
            "message": f"Someone replied to your topic '{topic.title}'",
            "post_content_preview": payload.content[:100] + "..." if len(payload.content) > 100 else payload.content
        }
        
        # Run notification in background without blocking the response
        run_async_safely(publish_notification(notification_data))

    return {"id": post.id}


@router.get(
    "/posts/{id}",
    response_model=PostRead,
    summary="Szczegóły posta z komentarzami",
    description="Zwraca post i wszystkie komentarze posortowane rosnąco.",
)
def post_detail(
    id: int = Path(..., ge=1),
    db: Session = Depends(get_session),
):
    # Use joinedload instead of selectinload (works better with ordering)
    stmt = (
        select(Post)
        .options(joinedload(Post.comments))
        .where(Post.id == id)
    )
    post = db.scalar(stmt)
    if not post:
        raise HTTPException(404, "Post not found")
    
    # Sort comments manually after loading (most reliable approach)
    if post.comments:
        post.comments.sort(key=lambda c: c.created_at)
    
    return post


@router.get(
    "/posts/{id}/comments",
    response_model=CommentList,
    status_code=status.HTTP_200_OK,
    summary="Lista komentarzy posta",
    description="Zwraca komentarze posta z paginacją.",
)
def list_post_comments(
    id: int = Path(..., ge=1, description="ID posta"),
    page: int = Query(1, ge=1, description="Numer strony (od 1)"),
    db: Session = Depends(get_session),
):
    # Check if post exists
    post_exists = db.scalar(select(Post.id).where(Post.id == id))
    if not post_exists:
        raise HTTPException(status_code=404, detail="Post not found")
    
    # Count total comments in post
    total_stmt = select(func.count(Comment.id)).where(Comment.post_id == id)
    total = db.scalar(total_stmt)
    
    # Calculate total pages
    total_pages = (total + PAGE_SIZE - 1) // PAGE_SIZE if total > 0 else 0
    
    # Get comments for current page
    stmt = (
        select(Comment)
        .where(Comment.post_id == id)
        .order_by(asc(Comment.created_at))
        .limit(PAGE_SIZE)
        .offset((page - 1) * PAGE_SIZE)
    )
    comments = db.scalars(stmt).all()
    
    return CommentList(
        items=comments,
        total=total,
        page=page,
        page_size=PAGE_SIZE,
        total_pages=total_pages
    )


@router.post(
    "/posts/{id}/comments",
    status_code=status.HTTP_201_CREATED,
    response_model=dict,
    summary="Dodaj komentarz",
    description="Wymaga JWT; content ≥1 znak.",
)
@limiter.limit("30/minute")
def create_comment(
    request: Request,
    id: int = Path(..., ge=1, description="ID posta"),
    payload: CommentCreate = Body(...),
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    
    # 1. Get post with topic info for notifications
    post = db.scalar(
        select(Post)
        .options(joinedload(Post.topic))
        .where(Post.id == id)
    )
    if not post:
        raise HTTPException(404, "Post not found")
    
    # 2. Create the comment
    comment = Comment(
        post_id=id,
        author_id=current_user.id,
        content=payload.content,
    )
    db.add(comment)
    db.commit()
    db.refresh(comment)
    
    # 3. Send notification asynchronously (non-blocking)
    if post.author_id != current_user.id:
        notification_data = {
            "to": str(post.author_id),  # Target user (post author)
            "type": "new_comment",
            "comment_id": comment.id,
            "post_id": id,
            "topic_id": post.topic_id,
            "topic_title": post.topic.title if post.topic else "Unknown Topic",
            "author_email": current_user.email,
            "author_id": str(current_user.id),
            "message": f"Someone commented on your post in '{post.topic.title if post.topic else 'Unknown Topic'}'",
            "comment_content_preview": payload.content[:100] + "..." if len(payload.content) > 100 else payload.content
        }
        
        # Run notification in background without blocking the response
        run_async_safely(publish_notification(notification_data))
    
    return {"id": comment.id}


# ============== NEW LIKE FUNCTIONALITY ==============

@router.post(
    "/posts/{post_id}/like",
    status_code=status.HTTP_200_OK,
    response_model=PostLikeResponse,  # 🔄 CHANGED: Use proper response model
    summary="Like/Unlike a post",
    description="Like a post if not already liked, or unlike if already liked. Returns updated like count.",
)
@limiter.limit("60/minute")  # More generous limit for likes
def like_post(
    request: Request,
    post_id: int = Path(..., ge=1, description="ID of the post to like/unlike"),  # 🔄 CHANGED: int not UUID
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Like or unlike a post.
    
    **Behavior:**
    - If user hasn't liked the post: creates a like and increments like_count
    - If user has already liked the post: removes the like and decrements like_count
    - Prevents users from liking their own posts
    - Handles race conditions with proper error handling
    
    **Returns:**
    - `liked`: boolean indicating if post is now liked by user
    - `likes`: current total like count for the post
    - `message`: description of the action taken
    
    **Rate Limiting:**
    - Maximum 60 like/unlike actions per minute per user
    
    **Errors:**
    - **404**: Post not found
    - **400**: Cannot like own post, or database constraint violation
    - **429**: Rate limit exceeded
    """
    
    # 1. Check if post exists
    post = db.scalar(select(Post).where(Post.id == post_id))
    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post not found"
        )
    
    # 2. Prevent self-liking
    if post.author_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot like your own post"
        )
    
    # 3. Check if user has already liked this post
    existing_like = db.scalar(
        select(PostLike).where(
            and_(
                PostLike.post_id == post_id,
                PostLike.user_id == current_user.id
            )
        )
    )
    
    try:
        if existing_like:
            # 4a. User has already liked - UNLIKE the post
            db.delete(existing_like)
            
            # Decrement like count with proper SQL update
            db.execute(
                Post.__table__.update()
                .where(Post.id == post_id)
                .values(like_count=Post.like_count - 1)
            )
            
            db.commit()
            
            # Get updated like count
            updated_post = db.scalar(select(Post).where(Post.id == post_id))
            
            logger.info(f"User {current_user.id} unliked post {post_id}")
            
            # Send notification to post author about unlike (optional)
            if post.author_id != current_user.id:
                notification_data = {
                    "to": str(post.author_id),
                    "type": "post_unliked",
                    "post_id": post_id,  # 🔄 CHANGED: int not str(UUID)
                    "user_email": current_user.email,
                    "user_id": str(current_user.id),
                    "message": f"Someone unliked your post",
                    "like_count": updated_post.like_count
                }
                run_async_safely(publish_notification(notification_data))
            
            return PostLikeResponse(
                liked=False,
                likes=updated_post.like_count,
                message="Post unliked successfully"
            )
            
        else:
            # 4b. User hasn't liked - LIKE the post
            new_like = PostLike(
                post_id=post_id,
                user_id=current_user.id
            )
            db.add(new_like)
            
            # Increment like count with proper SQL update
            db.execute(
                Post.__table__.update()
                .where(Post.id == post_id)
                .values(like_count=Post.like_count + 1)
            )
            
            db.commit()
            
            # Get updated like count
            updated_post = db.scalar(select(Post).where(Post.id == post_id))
            
            logger.info(f"User {current_user.id} liked post {post_id}")
            
            # Send notification to post author about new like
            if post.author_id != current_user.id:
                notification_data = {
                    "to": str(post.author_id),
                    "type": "post_liked",
                    "post_id": post_id,  # 🔄 CHANGED: int not str(UUID)
                    "user_email": current_user.email,
                    "user_id": str(current_user.id),
                    "message": f"Someone liked your post",
                    "like_count": updated_post.like_count
                }
                run_async_safely(publish_notification(notification_data))
            
            return PostLikeResponse(
                liked=True,
                likes=updated_post.like_count,
                message="Post liked successfully"
            )
            
    except IntegrityError as e:
        # 5. Handle unique constraint violations
        db.rollback()
        logger.warning(f"Integrity error in like_post for user {current_user.id}, post {post_id}: {e}")
        
        # This could happen in race conditions where multiple requests try to like simultaneously
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Like action failed due to database constraint. Please try again."
        )
    
    except Exception as e:
        # 6. Handle unexpected errors
        db.rollback()
        logger.error(f"Unexpected error in like_post for user {current_user.id}, post {post_id}: {e}")
        
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while processing the like action"
        )


@router.get(
    "/posts/{post_id}/likes",
    status_code=status.HTTP_200_OK,
    response_model=PostLikeInfo,  # 🔄 CHANGED: Use proper response model
    summary="Get post like information",
    description="Get like count and check if current user has liked the post.",
)
def get_post_likes(
    post_id: int = Path(..., ge=1, description="ID of the post"),  # 🔄 CHANGED: int not UUID
    db: Session = Depends(get_session),
    current_user: User = Depends(get_current_user),
):
    """
    Get like information for a post.
    
    **Returns:**
    - `post_id`: ID of the post
    - `likes`: total number of likes on the post
    - `liked_by_user`: whether the current user has liked this post
    
    **Errors:**
    - **404**: Post not found
    """
    
    # Check if post exists
    post = db.scalar(select(Post).where(Post.id == post_id))
    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post not found"
        )
    
    # Check if current user has liked this post
    user_liked = bool(db.scalar(
        select(PostLike).where(
            and_(
                PostLike.post_id == post_id,
                PostLike.user_id == current_user.id
            )
        )
    ))
    
    return PostLikeInfo(
        post_id=post_id,  # 🔄 CHANGED: int not str(UUID)
        likes=post.like_count,
        liked_by_user=user_liked
    )