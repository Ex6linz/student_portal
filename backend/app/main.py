import os
from fastapi import FastAPI
from fastapi_limiter import FastAPILimiter
from fastapi.middleware.cors import CORSMiddleware
import redis.asyncio as redis
from app.core.limiter import limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.auth.router import router as auth_router
from app.core.database import init_db
from app.users.router import router as users_router
from app.forum.router import router as forum_router
from app.media.router import router as media_router
from app.notifications.router import router as notifications_router

# Import email router s
from app.email.router import router as email_router

app = FastAPI(title="Student Portal API", version="0.1.0")

# Set up SlowAPI limiter
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.on_event("startup")
async def startup():
    # Initialize database
    init_db()
    
    # Clear slowapi limiter storage
    try:
        limiter._storage.clear()
    except Exception:
        pass
    
    # Initialize FastAPILimiter with Redis
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
    try:
        redis_client = redis.from_url(redis_url, encoding="utf-8", decode_responses=True)
        await FastAPILimiter.init(redis_client)
        print("FastAPILimiter initialized successfully")
    except Exception as e:
        print(f"Failed to initialize FastAPILimiter: {e}")

@app.on_event("shutdown")
async def shutdown():
    # Clean up FastAPILimiter
    try:
        await FastAPILimiter.close()
    except Exception as e:
        print(f"Error closing FastAPILimiter: {e}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",  # React frontend
        "http://localhost:8080",  # Alternative frontend port
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080",
        # Add your production domains here
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    # WebSocket specific headers
    expose_headers=["*"],
)


# Include all routers

app.include_router(auth_router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(users_router, prefix="/api/v1/users", tags=["users"])
app.include_router(forum_router, prefix="/api/v1/forum", tags=["forum"])
app.include_router(media_router, prefix="/api/v1/media", tags=["media"])
app.include_router(email_router, prefix="/api/v1/email", tags=["email"])
app.include_router(notifications_router, prefix="/api/v1/ws", tags=["websockets"])