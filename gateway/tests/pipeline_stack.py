"""A whole gateway for module 9's cross-cutting tests.

The per-module suites share one SQLite session per test and a fake Redis
(conftest.py). The tests here want the gateway as it runs in production -
every request gets its own database session, the audit writer runs on its
own connection, and nothing is overridden but the upstream provider - on
two backends:

  sqlite    SQLite file (WAL) + fakeredis. Always runs.
  postgres  A scratch Postgres database migrated with `alembic upgrade
            head` (so triggers and column types are the real ones) and a
            real Redis. Runs when TEST_POSTGRES_DSN and TEST_REDIS_URL are
            set, e.g. against `docker compose up -d postgres redis`:

                TEST_POSTGRES_DSN=postgresql://postgres:postgres@localhost:5432/postgres
                TEST_REDIS_URL=redis://localhost:6379/15

            The Redis database in TEST_REDIS_URL is flushed before and
            after each test - point it at a database nothing else uses.
"""

import os
import subprocess
import sys
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

import pytest
from fakeredis.aioredis import FakeRedis
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis
from sqlalchemy import event, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.admin_auth import require_admin
from app.core.audit.writer import AuditWriter, reset_audit_writer, set_audit_writer
from app.core.auth import hash_key
from app.core.governance.redis_client import get_redis
from app.db.base import Base
from app.db.models import ApiKey, Team
from app.db.session import _asyncpg_dsn, get_db
from app.main import app
from tests.conftest import RAW_TEST_KEY, TEST_ADMIN

POSTGRES_DSN = os.environ.get("TEST_POSTGRES_DSN")
REDIS_URL = os.environ.get("TEST_REDIS_URL")
GATEWAY_DIR = Path(__file__).resolve().parents[1]

BACKENDS = [
    pytest.param("sqlite", id="sqlite"),
    pytest.param(
        "postgres",
        id="postgres",
        marks=pytest.mark.skipif(
            not (POSTGRES_DSN and REDIS_URL), reason="TEST_POSTGRES_DSN / TEST_REDIS_URL not set"
        ),
    ),
]


@dataclass
class Stack:
    backend: str
    client: AsyncClient
    session_maker: async_sessionmaker
    redis: Redis
    writer: AuditWriter
    team_id: uuid.UUID
    api_key_id: uuid.UUID

    @property
    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {RAW_TEST_KEY}"}


@asynccontextmanager
async def _sqlite_session_maker(tmp_path: Path) -> AsyncIterator[async_sessionmaker]:
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'stack.db'}")

    @event.listens_for(engine.sync_engine, "connect")
    def _wal(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    try:
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()


@asynccontextmanager
async def _postgres_session_maker() -> AsyncIterator[async_sessionmaker]:
    name = f"stack_test_{uuid.uuid4().hex[:12]}"
    admin = create_async_engine(_asyncpg_dsn(POSTGRES_DSN), isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text(f'CREATE DATABASE "{name}"'))
    dsn = make_url(POSTGRES_DSN).set(database=name).render_as_string(hide_password=False)
    engine = None
    try:
        subprocess.run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=GATEWAY_DIR,
            env={**os.environ, "POSTGRES_DSN": dsn},
            check=True,
            capture_output=True,
        )
        engine = create_async_engine(_asyncpg_dsn(dsn))
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        if engine is not None:
            await engine.dispose()
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        await admin.dispose()


@asynccontextmanager
async def _redis(backend: str) -> AsyncIterator[Redis]:
    redis = (
        FakeRedis(decode_responses=True)
        if backend == "sqlite"
        else Redis.from_url(REDIS_URL, decode_responses=True)
    )
    await redis.flushdb()
    try:
        yield redis
    finally:
        await redis.flushdb()
        await redis.aclose()


async def build_stack(backend: str, tmp_path: Path) -> AsyncIterator[Stack]:
    """An async generator, for a pytest fixture to yield from."""
    database = _sqlite_session_maker(tmp_path) if backend == "sqlite" else _postgres_session_maker()
    async with database as session_maker, _redis(backend) as redis:
        async with session_maker() as session, session.begin():
            team = Team(name="Pipeline Team")
            session.add(team)
            await session.flush()
            api_key = ApiKey(key_hash=hash_key(RAW_TEST_KEY), team_id=team.id, name="app")
            session.add(api_key)
            await session.flush()
            team_id, api_key_id = team.id, api_key.id

        # One session per request, as app.db.session.get_db does.
        async def _get_db():
            async with session_maker() as session:
                yield session

        async def _get_redis():
            return redis

        writer = AuditWriter(session_maker)
        writer.start()
        set_audit_writer(writer)
        app.dependency_overrides[get_db] = _get_db
        app.dependency_overrides[get_redis] = _get_redis
        app.dependency_overrides[require_admin] = lambda: TEST_ADMIN
        try:
            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="http://test"
            ) as client:
                yield Stack(backend, client, session_maker, redis, writer, team_id, api_key_id)
        finally:
            app.dependency_overrides.clear()
            await writer.stop()
            reset_audit_writer()


async def rows(session_maker, model) -> list:
    async with session_maker() as session:
        return list((await session.execute(select(model))).scalars().all())


async def dump_database(session_maker) -> str:
    """Every row of every table, as text - for searching it for values that
    must never be stored."""
    parts = []
    async with session_maker() as session:
        for table in Base.metadata.sorted_tables:
            for row in (await session.execute(table.select())).all():
                parts.append(f"{table.name}: {tuple(row)!r}")
    return "\n".join(parts)


async def dump_redis(redis: Redis) -> str:
    """Every key and value in the Redis database, whatever its type."""
    parts = []
    async for key in redis.scan_iter():
        kind = await redis.type(key)
        if kind == "string":
            value = await redis.get(key)
        elif kind == "hash":
            value = await redis.hgetall(key)
        elif kind == "list":
            value = await redis.lrange(key, 0, -1)
        elif kind == "set":
            value = await redis.smembers(key)
        elif kind == "zset":
            value = await redis.zrange(key, 0, -1, withscores=True)
        elif kind == "stream":
            value = await redis.xrange(key)
        else:
            value = f"<{kind}>"
        parts.append(f"{key}: {value!r}")
    return "\n".join(parts)
