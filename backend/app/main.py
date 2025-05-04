from fastapi import FastAPI
from app.auth.router import router as auth_router

app = FastAPI(title="Student Portal API", version="0.1.0")
app.include_router(auth_router)

# przy development-owym starcie (bez Alembic):
# from app.core.database import init_db
# @app.on_event("startup")
# async def startup():
#     await init_db()