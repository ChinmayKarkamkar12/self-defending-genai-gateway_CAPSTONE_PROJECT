"""Shared pytest fixtures.

Sets dummy required env vars *before* any `app.*` module is imported, so
`Settings()` (which requires POSTGRES_DSN / REDIS_URL / API keys) can be
instantiated in CI and local runs without a real `.env` file present.
Real values always win if they're already set in the environment.

DB-dependent tests run against a throwaway SQLite database file per test
(via the `get_db` dependency override), not a live Postgres instance — keeps
unit and integration tests fast and hermetic. The Postgres-specific migration
in alembic/versions/ is exercised separately, against a real Postgres.

It is a file in WAL mode rather than `:memory:` because the audit writer
(module 7) needs its own connection: an in-memory aiosqlite engine hands
every session the *same* connection (StaticPool), so the writer's commit
would also commit, and survive the rollback of, whatever the request's
session had pending. A file gives each session a real connection; WAL lets
the writer write while a request session holds a read transaction.
"""
import os

os.environ.setdefault("POSTGRES_DSN", "postgresql://test:test@localhost:5432/test")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("OPENAI_API_KEY", "test-key")
os.environ.setdefault("ANTHROPIC_API_KEY", "test-key")
os.environ.setdefault("REDACTION_VAULT_KEY", "CsmRGHfMdzTqw8f6YCOh6vsLs9cAxgnDuoEDsPMOrw0=")

import pytest
from fakeredis.aioredis import FakeRedis
from httpx import ASGITransport, AsyncClient
from sqlalchemy import event
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import settings
from app.core.audit.writer import AuditWriter, reset_audit_writer, set_audit_writer
from app.core.auth import hash_key
from app.core.defense.rl.policy import reset_session_policy_cache
from app.core.defense.store import bandit_store
from app.core.governance.redis_client import get_redis
from app.core.stages import bandit_policy
from app.core.stages.threat_detection import system_prompt_cache
from app.core.threat.classifier import (
    ScanResult,
    ThreatScore,
    WindowScan,
    WindowSpan,
    reset_threat_classifier,
    set_threat_classifier,
)
from app.db.base import Base
from app.db.models import ApiKey, Team
from app.db.session import get_db
from app.main import app

RAW_TEST_KEY = "sk-gw-test-key"


class FakeThreatClassifier:
    """Test double for ThreatClassifier - returns a fixed score without
    loading torch or the real checkpoint. Tests that care about specific
    scores (gateway/tests/test_threat_stage.py) construct their own
    instance and call `set_threat_classifier` again mid-test; every other
    test gets this all-benign default via the autouse fixture below, so
    no test pays the cost of loading the real model."""

    def __init__(self, fixed_score: ThreatScore | None = None):
        self._fixed_score = fixed_score or ThreatScore(
            benign=1.0, prompt_injection=0.0, jailbreak=0.0
        )

        self.seen_texts: list[str] = []

    def score(self, text: str) -> ThreatScore:  # noqa: ARG002 - fixed regardless of input
        return self._fixed_score

    def score_texts(self, texts: list[str]) -> ScanResult:
        self.seen_texts.extend(texts)
        return ScanResult(score=self._fixed_score, windows=len(texts), truncated=False)

    def scan_windows(self, text: str) -> WindowScan:
        """One window covering the whole text, scored like `score_texts`.
        Tests that need several windows (test_strip.py) use their own fake."""
        if not text:
            return WindowScan(windows=[], unscanned_from=None)
        attack = 1.0 - self._fixed_score.benign
        return WindowScan(
            windows=[WindowSpan(start=0, end=len(text), attack_probability=attack)],
            unscanned_from=None,
        )


@pytest.fixture(autouse=True)
def fake_threat_classifier():
    # The system-prompt score cache already resets when the classifier
    # changes; clearing here too keeps every test fully independent.
    system_prompt_cache.clear()
    set_threat_classifier(FakeThreatClassifier())
    yield
    reset_threat_classifier()
    system_prompt_cache.clear()


@pytest.fixture(autouse=True)
def isolated_bandit(monkeypatch):
    """Every test starts from the warm-start prior (no cached parameters
    from an earlier test) with spot-check sampling off, so a random 2%
    sample can't add review items to tests that don't expect them. Tests of
    the sampling itself set BANDIT_SPOT_CHECK_RATE explicitly."""
    bandit_store.reset()
    monkeypatch.setattr(settings, "BANDIT_SPOT_CHECK_RATE", 0.0)
    bandit_policy.spot_check_rng.seed(0)
    yield
    bandit_store.reset()


@pytest.fixture(autouse=True)
def isolated_session_policy(monkeypatch):
    """Module 6b's session agent is set to "maintain" (track and log, never
    change the bias) so module 6a's tests measure 6a alone: under the
    default rule policy, a test sending several suspicious requests from
    one key would see the session tighten. 6b's own tests set
    SESSION_POLICY explicitly."""
    monkeypatch.setattr(settings, "SESSION_POLICY", "maintain")
    reset_session_policy_cache()
    yield
    reset_session_policy_cache()


@pytest.fixture
async def db_engine(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}")

    @event.listens_for(engine.sync_engine, "connect")
    def _wal(dbapi_connection, _record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.close()

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest.fixture
def session_maker(db_engine):
    return async_sessionmaker(db_engine, expire_on_commit=False)


@pytest.fixture
async def db_session(session_maker):
    async with session_maker() as session:
        yield session


@pytest.fixture
async def audit_writer(session_maker):
    """A running audit writer on the test database, installed as the
    process-wide one (the app's lifespan, which starts it in production,
    never runs under ASGITransport). `await audit_writer.flush()` waits
    until everything queued is written."""
    writer = AuditWriter(session_maker)
    writer.start()
    set_audit_writer(writer)
    yield writer
    await writer.stop()
    reset_audit_writer()


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
async def client(db_session, seeded_team_and_key, fake_redis, audit_writer):
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
