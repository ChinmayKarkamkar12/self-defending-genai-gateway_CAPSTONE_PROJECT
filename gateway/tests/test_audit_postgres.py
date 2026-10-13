"""Module 7 against a real Postgres: what the SQLite suite can't show.

  - the hash survives the JSONB / numeric / timestamptz round trip
  - migration 0008's trigger refuses UPDATE, DELETE and TRUNCATE
  - two writers (= two gateway processes) don't fork the chain
  - 100 concurrent requests all succeed and are all audited

Skipped unless TEST_POSTGRES_DSN points at a Postgres server whose user may
create databases, e.g. with `docker compose up -d postgres`:

    TEST_POSTGRES_DSN=postgresql://postgres:postgres@localhost:5432/postgres

Each test creates a scratch database, migrates it with `alembic upgrade
head` (so the trigger is the real one) and drops it afterwards.
"""
import asyncio
import os
import subprocess
import sys
import uuid
from decimal import Decimal
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.audit.hashing import compute_entry_hash, entry_fields
from app.core.audit.verify import verify_chain
from app.core.audit.writer import (
    AuditWriter,
    append_entries,
    reset_audit_writer,
    set_audit_writer,
)
from app.core.auth import hash_key
from app.core.governance.redis_client import get_redis
from app.core.providers.openai import OpenAIProvider
from app.db.models import ApiKey, Team
from app.db.session import _asyncpg_dsn, get_db
from app.main import app
from tests.audit_helpers import AUTH, all_entries, chat_body, make_record
from tests.conftest import RAW_TEST_KEY

CANNED_RESPONSE = {
    "id": "chatcmpl-123",
    "object": "chat.completion",
    "model": "gpt-4",
    "choices": [
        {"index": 0, "message": {"role": "assistant", "content": "hi"}, "finish_reason": "stop"}
    ],
    "usage": {"prompt_tokens": 5, "completion_tokens": 3},
}

ADMIN_DSN = os.environ.get("TEST_POSTGRES_DSN")
GATEWAY_DIR = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(not ADMIN_DSN, reason="TEST_POSTGRES_DSN not set")


@pytest.fixture
async def pg_session_maker():
    name = f"audit_test_{uuid.uuid4().hex[:12]}"
    admin = create_async_engine(_asyncpg_dsn(ADMIN_DSN), isolation_level="AUTOCOMMIT")
    async with admin.connect() as conn:
        await conn.execute(text(f'CREATE DATABASE "{name}"'))
    dsn = make_url(ADMIN_DSN).set(database=name).render_as_string(hide_password=False)
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=GATEWAY_DIR,
        env={**os.environ, "POSTGRES_DSN": dsn},
        check=True,
        capture_output=True,
    )
    engine = create_async_engine(_asyncpg_dsn(dsn), pool_size=20, max_overflow=20)
    try:
        yield async_sessionmaker(engine, expire_on_commit=False)
    finally:
        await engine.dispose()
        async with admin.connect() as conn:
            await conn.execute(text(f'DROP DATABASE "{name}" WITH (FORCE)'))
        await admin.dispose()


@pytest.fixture
async def pg_team_and_key(pg_session_maker):
    async with pg_session_maker() as session, session.begin():
        team = Team(name="PG Team")
        session.add(team)
        await session.flush()
        api_key = ApiKey(key_hash=hash_key(RAW_TEST_KEY), team_id=team.id, name="pg-key")
        session.add(api_key)
    return team, api_key


async def _verify(session_maker):
    async with session_maker() as session:
        return await verify_chain(session)


async def test_hash_survives_postgres_round_trip(pg_session_maker, pg_team_and_key):
    team, api_key = pg_team_and_key
    writer = AuditWriter(pg_session_maker)
    writer.start()
    awkward = [
        {"threat_score": {"benign": 0.1 + 0.2, "prompt_injection": 1e-05, "jailbreak": 0.0}},
        {"threat_score": {"jailbreak": 1.0, "benign": 0.0, "prompt_injection": 2.5e-17}},
        {"cost_usd": Decimal("0.00033")},
        {"cost_usd": Decimal("1234.5")},
        {"redaction_summary": {"US_SSN": 2, "EMAIL_ADDRESS": 10, "API_KEY": 1}},
        {"output_flags": None, "threat_score": None, "threat_event_id": None},
    ]
    for overrides in awkward:
        writer.enqueue(make_record(team.id, api_key.id, **overrides))
    await writer.stop()

    entries = await all_entries(pg_session_maker)
    assert len(entries) == len(awkward)
    for entry in entries:
        assert entry.entry_hash == compute_entry_hash(entry_fields(entry), entry.prev_hash)
    assert (await _verify(pg_session_maker)).valid


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_log_entries SET action_taken = 'allow'",
        "DELETE FROM audit_log_entries",
        "TRUNCATE audit_log_entries",
    ],
)
async def test_trigger_refuses_changes(pg_session_maker, pg_team_and_key, statement):
    team, api_key = pg_team_and_key
    async with pg_session_maker() as session, session.begin():
        await append_entries(session, [make_record(team.id, api_key.id, action_taken="block")])

    with pytest.raises(DBAPIError, match="append-only"):
        async with pg_session_maker() as session, session.begin():
            await session.execute(text(statement))

    (entry,) = await all_entries(pg_session_maker)
    assert entry.action_taken == "block"


async def test_two_writers_do_not_fork_the_chain(pg_session_maker, pg_team_and_key):
    """Two writers stand in for two gateway processes; the advisory lock
    makes their appends take turns."""
    team, api_key = pg_team_and_key
    writers = [AuditWriter(pg_session_maker, batch_size=5) for _ in range(2)]
    for writer in writers:
        writer.start()
    for i in range(100):
        writers[i % 2].enqueue(make_record(team.id, api_key.id))
    await asyncio.gather(*(writer.stop() for writer in writers))

    entries = await all_entries(pg_session_maker)
    assert [e.sequence_number for e in entries] == list(range(1, 101))
    assert (await _verify(pg_session_maker)).valid


async def test_no_log_entries_lost_under_load_on_postgres(
    pg_session_maker, pg_team_and_key, fake_redis, monkeypatch
):
    """The upstream call is stubbed at the adapter, not through respx:
    the adapters build a new httpx client per call, and each one loads
    the CA bundle (~300 ms, blocking the event loop) - a module 2 cost
    (LIMITATIONS.md L2-2) that would make this a test of that instead."""

    async def stub_completion(self, payload):
        return CANNED_RESPONSE

    monkeypatch.setattr(OpenAIProvider, "chat_completion", stub_completion)
    writer = AuditWriter(pg_session_maker)
    writer.start()
    set_audit_writer(writer)

    async def _session_per_request():
        async with pg_session_maker() as session:
            yield session

    async def _redis():
        return fake_redis

    app.dependency_overrides[get_db] = _session_per_request
    app.dependency_overrides[get_redis] = _redis
    n = 100
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            responses = await asyncio.gather(
                *(
                    ac.post("/v1/chat/completions", headers=AUTH, json=chat_body(f"req {i}"))
                    for i in range(n)
                )
            )
        await writer.flush()
    finally:
        app.dependency_overrides.clear()
        await writer.stop()
        reset_audit_writer()

    assert [r.status_code for r in responses] == [200] * n
    entries = await all_entries(pg_session_maker)
    assert len(entries) == n
    assert {str(e.request_id) for e in entries} == {
        r.headers["x-gateway-request-id"] for r in responses
    }
    assert (await _verify(pg_session_maker)).valid
    assert writer.dropped == 0
