"""Async SQLAlchemy engine/session wiring.

The engine is built lazily (not at import time) so tests can point it at a
throwaway SQLite database instead of the real Postgres instance via
`app.dependency_overrides[get_db]`.
"""
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.config import settings


def _asyncpg_dsn(dsn: str) -> str:
    if dsn.startswith("postgresql://"):
        return dsn.replace("postgresql://", "postgresql+asyncpg://", 1)
    return dsn


engine = create_async_engine(_asyncpg_dsn(settings.POSTGRES_DSN), pool_pre_ping=True)
async_session_maker = async_sessionmaker(engine, expire_on_commit=False)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_maker() as session:
        yield session
