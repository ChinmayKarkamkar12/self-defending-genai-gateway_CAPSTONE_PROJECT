"""Shared pytest fixtures.

Sets dummy required env vars *before* any `app.*` module is imported, so
`Settings()` (which requires POSTGRES_DSN / REDIS_URL / API keys) can be
instantiated in CI and local runs without a real `.env` file present.
Real values always win if they're already set in the environment.

DB-dependent tests run against an in-memory SQLite database (via the
`get_db` dependency override), not a live Postgres instance — keeps unit
and integration tests fast and hermetic. The Postgres-specific migration
in alembic/versions/ is exercised separately, against a real Postgres.
"""
import os

os.environ.setdefault("POSTGRES_DSN", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("OPENAI_API_KEY", "test-key")
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key")

import pytest
from fakeredis.aioredis import FakeRedis
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.auth import hash_key
from app.core.governance.redis_client import get_redis
from app.db.base import Base
from app.db.models import ApiKey, Team
from app.db.session import get_db
from app.main import app

RAW_TEST_KEY = "sk-gw-test-key"


@pytest.fixture
async def db_session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_maker = async_sessionmaker(engine, expire_on_commit=False)
    async with session_maker() as session:
        yield session

    await engine.dispose()


@pytest.fixture
async def seeded_team_and_key(db_session):
    team = Team(name="Test Team")
    db_session.add(team)
    await db_session.flush()

    api_key = ApiKey(key_hash=hash_key(RAW_TEST_KEY), team_id=team.id, name="test-key")
    db_session.add(api_key)
    await db_session.commit()

    return team, api_key


@pytest.fixture
async def fake_redis():
    redis = FakeRedis(decode_responses=True)
    yield redis
    await redis.aclose()


@pytest.fixture
async def client(db_session, seeded_team_and_key, fake_redis):
    async def _override_get_db():
        yield db_session

    async def _override_get_redis():
        return fake_redis

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_redis] = _override_get_redis
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()
