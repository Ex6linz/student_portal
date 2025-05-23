# app/main.py
from fastapi import FastAPI
from app.core.limiter import limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from app.auth.router import router as auth_router
from app.core.database import init_db
from app.users.router import router as users_router
from app.forum.router import router as forum_router

app = FastAPI(title="Student Portal API", version="0.1.0")

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# przy starcie twórz tabele
@app.on_event("startup")
def on_startup():
    init_db()
    try:
        limiter._storage.clear()
    except Exception:
        pass

app.include_router(auth_router)
app.include_router(users_router)
app.include_router(forum_router)