# app/core/database.py
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlmodel import SQLModel
from app.core.config import settings

# Sync engine
sync_url = settings.DATABASE_URL.replace("+asyncpg", "")
engine   = create_engine(sync_url, echo=False)

# Sync sessionmaker
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

# Dependency
def get_session() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Init DB (e.g. w startup)
def init_db():
    SQLModel.metadata.drop_all(bind=engine)
    SQLModel.metadata.create_all(bind=engine)