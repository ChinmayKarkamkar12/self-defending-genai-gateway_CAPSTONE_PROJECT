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
os.environ.setdefault("REDACTION_VAULT_KEY", "CsmRGHfMdzTqw8f6YCOh6vsLs9cAxgnDuoEDsPMOrw0=")

import pytest
from fakeredis.aioredis import FakeRedis
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.auth import hash_key
from app.core.governance.redis_client import get_redis
from app.core.stages.threat_detection import system_prompt_cache
from app.core.threat.classifier import (
    ScanResult,
    ThreatScore,
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


@pytest.fixture(autouse=True)
def fake_threat_classifier():
    # The system-prompt score cache already resets when the classifier
    # changes; clearing here too keeps every test fully independent.
    system_prompt_cache.clear()
    set_threat_classifier(FakeThreatClassifier())
    yield
    reset_threat_classifier()
    system_prompt_cache.clear()


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
