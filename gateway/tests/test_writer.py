"""Module 7: the async audit writer (app/core/audit/writer.py) and how the
chat endpoint depends on it."""
import asyncio
import uuid

import pytest
import respx
from httpx import ASGITransport, AsyncClient
from sqlalchemy.exc import OperationalError

from app.config import settings
from app.core.audit import writer as writer_module
from app.core.audit.verify import verify_chain
from app.core.audit.writer import AuditQueueFull, AuditWriter, AuditWriterNotRunning
from app.core.governance.redis_client import get_redis
from app.core.providers.openai import OpenAIProvider
from app.db.session import get_db
from app.main import app
from tests.audit_helpers import AUTH, all_entries, chat_body, make_record, mock_openai
from tests.test_audit_postgres import CANNED_RESPONSE


async def stub_completion(self, payload):
    return CANNED_RESPONSE


async def _verify(session_maker):
    async with session_maker() as session:
        return await verify_chain(session)


@respx.mock
async def test_logging_does_not_block_response(client, audit_writer, session_maker, monkeypatch):
    """The response must come back while its audit entry is still unwritten:
    the database write is held until after the response is received."""
    mock_openai()
    release = asyncio.Event()
    real_append = writer_module.append_entries

    async def held_append(session, records):
        await release.wait()
        await real_append(session, records)

    monkeypatch.setattr(writer_module, "append_entries", held_append)

    response = await asyncio.wait_for(
        client.post("/v1/chat/completions", headers=AUTH, json=chat_body()), timeout=10
    )

    assert response.status_code == 200
    assert await all_entries(session_maker) == []  # not written yet...
    release.set()
    await audit_writer.flush()
    entries = await all_entries(session_maker)  # ...and written once released
    assert len(entries) == 1
    assert str(entries[0].request_id) == response.headers["x-gateway-request-id"]


@pytest.fixture
async def concurrent_client(session_maker, seeded_team_and_key, fake_redis, audit_writer):
    """Like `client`, but each request gets its own DB session, as in
    production - the shared test session can't be used concurrently."""

    async def _session_per_request():
        async with session_maker() as session:
            yield session

    async def _redis():
        return fake_redis

    app.dependency_overrides[get_db] = _session_per_request
    app.dependency_overrides[get_redis] = _redis
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


async def test_no_log_entries_lost_under_load(
    concurrent_client, audit_writer, session_maker, monkeypatch
):
    """100 concurrent requests -> exactly 100 audit entries, one per request,
    on one unbroken chain.

    On SQLite some requests fail on their own: SQLite allows one writer at a
    time, and other stages (usage recording, the session agent) get
    "database is locked" under this much contention and fail closed with
    503. That is a test-database artifact - test_audit_postgres.py runs the
    same load on Postgres, where every request succeeds. Here it only makes
    the check stronger: refused requests must be audited too.

    The upstream call is stubbed at the adapter for the reason given in
    test_audit_postgres.py (LIMITATIONS.md L2-2)."""
    monkeypatch.setattr(OpenAIProvider, "chat_completion", stub_completion)
    n = 100

    responses = await asyncio.gather(
        *(
            concurrent_client.post(
                "/v1/chat/completions", headers=AUTH, json=chat_body(f"request {i}")
            )
            for i in range(n)
        )
    )
    await audit_writer.flush()

    status_by_request = {r.headers["x-gateway-request-id"]: r.status_code for r in responses}
    assert len(status_by_request) == n
    entries = await all_entries(session_maker)
    assert len(entries) == n
    assert {str(e.request_id): e.http_status for e in entries} == status_by_request
    assert [e.sequence_number for e in entries] == list(range(1, n + 1))
    assert (await _verify(session_maker)).valid
    assert audit_writer.dropped == 0


async def test_transient_errors_are_retried(session_maker, seeded_team_and_key, monkeypatch):
    team, api_key = seeded_team_and_key
    monkeypatch.setattr(writer_module, "_BACKOFF_START", 0.001)
    real_append = writer_module.append_entries
    failures = {"left": 2}

    async def flaky_append(session, records):
        if failures["left"]:
            failures["left"] -= 1
            raise OperationalError("INSERT", {}, Exception("database is locked"))
        await real_append(session, records)

    monkeypatch.setattr(writer_module, "append_entries", flaky_append)
    writer = AuditWriter(session_maker)
    writer.start()
    for _ in range(3):
        writer.enqueue(make_record(team.id, api_key.id))
    await writer.stop()

    assert failures["left"] == 0
    assert writer.written == 3
    assert writer.dropped == 0
    assert len(await all_entries(session_maker)) == 3


async def test_pool_timeout_is_transient_not_a_bad_entry(
    session_maker, seeded_team_and_key, monkeypatch
):
    """sqlalchemy's pool TimeoutError is not the builtin TimeoutError; an
    exhausted pool must be waited out, never cause an entry to be dropped."""
    from sqlalchemy.exc import TimeoutError as PoolTimeoutError

    team, api_key = seeded_team_and_key
    monkeypatch.setattr(writer_module, "_BACKOFF_START", 0.001)
    real_append = writer_module.append_entries
    failures = {"left": 1}

    async def exhausted_then_ok(session, records):
        if failures["left"]:
            failures["left"] -= 1
            raise PoolTimeoutError("QueuePool limit reached")
        await real_append(session, records)

    monkeypatch.setattr(writer_module, "append_entries", exhausted_then_ok)
    writer = AuditWriter(session_maker)
    writer.start()
    writer.enqueue(make_record(team.id, api_key.id))
    await writer.stop()

    assert writer.dropped == 0
    assert len(await all_entries(session_maker)) == 1


async def test_rejected_entry_does_not_block_the_others(session_maker, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    writer = AuditWriter(session_maker)
    writer.start()
    good_ids = [uuid.uuid4(), uuid.uuid4()]
    writer.enqueue(make_record(team.id, api_key.id, request_id=good_ids[0]))
    writer.enqueue(make_record(team.id, api_key.id, tokens_in=None))  # NOT NULL violation
    writer.enqueue(make_record(team.id, api_key.id, request_id=good_ids[1]))
    await writer.stop()

    entries = await all_entries(session_maker)
    assert [e.request_id for e in entries] == good_ids
    assert writer.dropped == 1
    assert (await _verify(session_maker)).valid


async def test_stop_drains_the_queue(session_maker, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    writer = AuditWriter(session_maker, batch_size=7)
    writer.start()
    for _ in range(50):
        writer.enqueue(make_record(team.id, api_key.id))
    await writer.stop()

    assert len(await all_entries(session_maker)) == 50
    assert (await _verify(session_maker)).valid


async def test_enqueue_refuses_when_full_or_stopped(session_maker, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    writer = AuditWriter(session_maker, max_queue=1)
    with pytest.raises(AuditWriterNotRunning):
        writer.enqueue(make_record(team.id, api_key.id))

    writer.start()
    writer.enqueue(make_record(team.id, api_key.id))  # worker hasn't run yet: queue is full
    with pytest.raises(AuditQueueFull):
        writer.enqueue(make_record(team.id, api_key.id))
    await writer.stop()


@respx.mock
async def test_unauditable_success_fails_closed(client, audit_writer, session_maker):
    mock_openai()
    await audit_writer.stop()

    response = await client.post("/v1/chat/completions", headers=AUTH, json=chat_body())

    assert response.status_code == 503


@respx.mock
async def test_unauditable_success_passes_under_fail_open(
    client, audit_writer, session_maker, monkeypatch
):
    mock_openai()
    monkeypatch.setattr(settings, "FAIL_MODE", "open")
    await audit_writer.stop()

    response = await client.post("/v1/chat/completions", headers=AUTH, json=chat_body())

    assert response.status_code == 200


async def test_audit_failure_does_not_mask_a_refusal(client, audit_writer):
    await audit_writer.stop()

    response = await client.post(
        "/v1/chat/completions", headers=AUTH, json=chat_body(model="not-a-real-model")
    )

    assert response.status_code == 422  # the real error, not the audit's 503
