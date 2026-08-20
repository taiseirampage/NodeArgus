from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.config import settings

from .models import Base


engine = create_async_engine(settings.POSTGRES_ASYNC_URL, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Yield an async database session for a request or background task."""
    async with AsyncSessionLocal() as session:
        yield session


async def init_db() -> None:
    """Create all tables for local development only.

    Production deployments must apply the Alembic migrations instead.
    """
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
