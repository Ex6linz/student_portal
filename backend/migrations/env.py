import os
import sys
import asyncio
from logging.config import fileConfig
from logging import getLogger

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel

import app.media
import app.media.models

# ——— DEBUG: Ensure correct env.py is loaded ———
print(f">>> DEBUG: loading env.py from {__file__}")
print(f">>> DEBUG: sys.path = {sys.path}")
# —————————————————————————————————————

# ——— Import all modules with SQLModel(table=True) so metadata is populated ———
import app.auth.models
import app.forum.models
from app.forum.models import Topic, Post, Comment
import app.media.models     
# class User(table=True)
# import app.auth.models.refresh_token
# import app.users.models
# import app.media.models
# import app.forum.models
# —————————————————————————————————————————————————

from app.core.config import settings

# Collect metadata for all tables
target_metadata = SQLModel.metadata

# ——— DEBUG: show tables in metadata ———
logger = getLogger("alembic.env")
logger.setLevel("INFO")
logger.info(
    ">>> DEBUG: metadata.tables = %r",
    list(target_metadata.tables.keys())
)
print(f">>> DEBUG: metadata.tables = {list(target_metadata.tables.keys())}")
# —————————————————————————————

# Define sync and async database URLs
sync_url = settings.DATABASE_URL.replace("+asyncpg", "")
async_url = settings.DATABASE_URL

# Create the async SQLAlchemy engine
engine = create_async_engine(async_url, echo=False)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (generate SQL without DB connectivity)."""
    context.configure(
        url=sync_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    """Run migrations in 'online' mode (connect to DB asynchronously)."""
    def do_migrations(sync_conn):
        context.configure(
            connection=sync_conn,
            target_metadata=target_metadata,
            compare_type=True,
            render_as_batch=True,
        )
        context.run_migrations()

    async with engine.begin() as conn:
        await conn.run_sync(do_migrations)


# Execute the appropriate migration function based on context mode
if context.is_offline_mode():
    run_migrations_offline()
else:
    # For both revision --autogenerate and upgrade commands, run online migrations
    asyncio.run(run_migrations_online())
