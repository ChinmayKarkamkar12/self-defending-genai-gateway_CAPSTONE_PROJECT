"""Module 10: the deployment scripts.

  scripts/db_setup.py    migrations + the gateway's restricted role (L7-6)
  scripts/seed_demo.py   demo teams, keys, policies, admin - idempotent
  scripts/fetch_model.py the classifier is in place before the gateway starts

The role tests need a Postgres server whose user may create databases and
roles (TEST_POSTGRES_DSN, as for test_audit_postgres.py); they make a scratch
database and a uniquely named role, and drop both afterwards.
"""

import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import huggingface_hub
import pytest
import respx
from httpx import ASGITransport, AsyncClient, Response
from sqlalchemy import func, select, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import settings
from app.core.admin_auth import require_admin
from app.core.audit.verify import verify_chain
from app.core.audit.writer import AuditWriter, reset_audit_writer, set_audit_writer
from app.core.governance.redis_client import get_redis
from app.core.providers.openai import OPENAI_BASE_URL
from app.core.threat.classifier import ThreatScore, set_threat_classifier
from app.db.models import (
    AdminUser,
    ApiKey,
    AuditLogEntry,
    BudgetPolicy,
    RedactionPolicy,
    ReviewQueueItem,
    Team,
)
from app.db.session import _asyncpg_dsn, get_db
from app.main import app
from scripts import fetch_model, seed_demo
from tests.conftest import TEST_ADMIN, FakeThreatClassifier

ADMIN_DSN = os.environ.get("TEST_POSTGRES_DSN")
GATEWAY_DIR = Path(__file__).resolve().parents[1]
needs_postgres = pytest.mark.skipif(not ADMIN_DSN, reason="TEST_POSTGRES_DSN not set")

SECRET = "test-demo-secret-0123456789"
UPSTREAM_OK = {
    "choices": [{"message": {"role": "assistant", "content": "ok"}}],
    "usage": {"prompt_tokens": 5, "completion_tokens": 3},
}


# ---------------------------------------------------------------- seed_demo


def test_demo_keys_are_derived_not_stored(monkeypatch):
    monkeypatch.setenv("DEMO_SECRET", SECRET)
    keys = {team.slug: seed_demo.demo_key(team.slug) for team in seed_demo.TEAMS}

    assert len(set(keys.values())) == len(seed_demo.TEAMS)  # one per team
    assert keys["acme"] == seed_demo.demo_key("acme")  # same .env, same keys
    monkeypatch.setenv("DEMO_SECRET", SECRET + "x")
    assert seed_demo.demo_key("acme") != keys["acme"]  # a new secret, new keys


def test_demo_secret_is_required(monkeypatch):
    monkeypatch.setenv("DEMO_SECRET", "short")
    with pytest.raises(SystemExit, match="DEMO_SECRET"):
        seed_demo.demo_key("acme")


def test_demo_traffic_leaves_the_budget_team_alone():
    plan = seed_demo.traffic_plan("local-llama3")
    teams = [slug for slug, _ in plan]

    assert "research" not in teams  # its budget is the live demo's to spend
    # Attacks come from the sandbox, after everything else, two at most: the
    # session agent locks a key after 4 refusals in a row.
    first_attack = teams.index("sandbox")
    assert set(teams[first_attack:]) == {"sandbox"}
    assert teams.count("sandbox") == 2


# -------------------------------------------------------------- fetch_model


def test_fetch_model_does_nothing_when_the_model_is_there(tmp_path, monkeypatch):
    (tmp_path / "config.json").write_text("{}")
    monkeypatch.setenv("THREAT_MODEL_DIR", str(tmp_path))
    monkeypatch.delenv("HF_TOKEN", raising=False)

    fetch_model.main()  # no download, no error


def test_fetch_model_without_model_or_token_says_what_to_do(tmp_path, monkeypatch):
    monkeypatch.setenv("THREAT_MODEL_DIR", str(tmp_path / "model"))
    monkeypatch.delenv("HF_TOKEN", raising=False)

    with pytest.raises(SystemExit, match="copy that folder|HF_TOKEN"):
        fetch_model.main()


def test_fetch_model_downloads_and_moves_config_last(tmp_path, monkeypatch):
    target = tmp_path / "model"
    monkeypatch.setenv("THREAT_MODEL_DIR", str(target))
    monkeypatch.setenv("HF_TOKEN", "hf_test")
    moved = []

    def fake_download(repo, allow_patterns, local_dir, token):
        assert token == "hf_test" and allow_patterns == ["classifier_v2/*"]
        folder = Path(local_dir, "classifier_v2")
        folder.mkdir(parents=True)
        for name in ("config.json", "model.safetensors", "tokenizer.json"):
            (folder / name).write_text(name)

    real_move = shutil.move
    monkeypatch.setattr(huggingface_hub, "snapshot_download", fake_download)
    monkeypatch.setattr(
        fetch_model.shutil,
        "move",
        lambda src, dst: (moved.append(Path(dst).name), real_move(src, dst)),
    )

    fetch_model.main()

    assert moved[-1] == "config.json"  # a cut-short download never looks complete
    assert sorted(p.name for p in target.iterdir()) == [
        "config.json",
        "model.safetensors",
        "tokenizer.json",
    ]  # and the staging folder is gone


# ------------------------------------------------- db_setup, on Postgres


@pytest.fixture
def scratch_database():
    """A fresh database and a fresh role name; both dropped afterwards."""
    import asyncio

    name = f"deploy_test_{uuid.uuid4().hex[:10]}"
    role = f"gw_app_{uuid.uuid4().hex[:10]}"

    async def admin(statement: str) -> None:
        engine = create_async_engine(_asyncpg_dsn(ADMIN_DSN), isolation_level="AUTOCOMMIT")
        async with engine.connect() as conn:
            await conn.execute(text(statement))
        await engine.dispose()

    asyncio.run(admin(f'CREATE DATABASE "{name}"'))
    dsn = make_url(ADMIN_DSN).set(database=name)
    try:
        yield dsn, role
    finally:
        asyncio.run(admin(f'DROP DATABASE "{name}" WITH (FORCE)'))
        asyncio.run(admin(f'DROP ROLE IF EXISTS "{role}"'))


def run_db_setup(dsn, role: str, password: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "scripts.db_setup"],
        cwd=GATEWAY_DIR,
        env={
            **os.environ,
            "POSTGRES_DSN": dsn.render_as_string(hide_password=False),
            "POSTGRES_APP_USER": role,
            "POSTGRES_APP_PASSWORD": password,
            "DEMO_SEED": "true",
            "DEMO_SECRET": SECRET,
            "DEMO_ADMIN_USERNAME": "demo-admin",
            "DEMO_ADMIN_PASSWORD": "a-long-demo-password",
        },
        capture_output=True,
        text=True,
    )


def as_role(dsn, role: str, password: str) -> str:
    return _asyncpg_dsn(
        dsn.set(username=role, password=password).render_as_string(hide_password=False)
    )


@needs_postgres
def test_db_setup_twice_seeds_once(scratch_database):
    dsn, role = scratch_database

    for _ in range(2):  # idempotent: the second run changes nothing
        result = run_db_setup(dsn, role, "role-password-1")
        assert result.returncode == 0, result.stderr

    import asyncio

    async def counts():
        engine = create_async_engine(_asyncpg_dsn(dsn.render_as_string(hide_password=False)))
        async with engine.connect() as conn:
            out = {
                model.__tablename__: await conn.scalar(select(func.count()).select_from(model))
                for model in (Team, ApiKey, BudgetPolicy, RedactionPolicy, AdminUser)
            }
        await engine.dispose()
        return out

    assert asyncio.run(counts()) == {
        "teams": 4,
        "api_keys": 4,
        "budget_policies": 4,
        "redaction_policies": 1,
        "admin_users": 1,
    }
    # Running it again with a new password updates the role (a rotated .env).
    assert run_db_setup(dsn, role, "role-password-2").returncode == 0


@needs_postgres
@pytest.mark.parametrize(
    ("statement", "refusal"),
    [
        # What the hash chain's attacker would try first (module 7, L7-6).
        ("ALTER TABLE audit_log_entries DISABLE TRIGGER ALL", "must be owner"),
        ("SET session_replication_role = replica", "permission denied"),
        ("TRUNCATE audit_log_entries", "permission denied"),
        ("UPDATE audit_log_entries SET action_taken = 'allow'", "permission denied"),
        ("DELETE FROM audit_log_entries", "permission denied"),
        ("DROP TABLE audit_log_entries", "must be owner"),
        ("SELECT * FROM alembic_version", "permission denied"),
        ("CREATE TABLE sneaky (id int)", "permission denied"),
    ],
)
async def test_gateway_role_cannot_touch_the_audit_protection(scratch_database, statement, refusal):
    dsn, role = scratch_database
    assert run_db_setup(dsn, role, "role-password").returncode == 0
    engine = create_async_engine(as_role(dsn, role, "role-password"))
    try:
        with pytest.raises(DBAPIError, match=refusal):
            async with engine.begin() as conn:
                await conn.execute(text(statement))
    finally:
        await engine.dispose()


@needs_postgres
@respx.mock
async def test_gateway_works_as_the_restricted_role(scratch_database, fake_redis, monkeypatch):
    """Everything a request and an admin do, logged in as the role: if a
    grant were missing, the live gateway would fail exactly here."""
    dsn, role = scratch_database
    assert run_db_setup(dsn, role, "role-password").returncode == 0
    engine = create_async_engine(as_role(dsn, role, "role-password"))
    session_maker = async_sessionmaker(engine, expire_on_commit=False)

    async def _get_db():
        async with session_maker() as session:
            yield session

    writer = AuditWriter(session_maker)
    writer.start()
    set_audit_writer(writer)
    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_redis] = lambda: fake_redis
    app.dependency_overrides[require_admin] = lambda: TEST_ADMIN
    monkeypatch.setenv("DEMO_SECRET", SECRET)
    monkeypatch.setattr(settings, "BANDIT_ALPHA", 0.0)  # no exploration: 0.7 is escalated
    respx.post(f"{OPENAI_BASE_URL}/chat/completions").mock(
        return_value=Response(200, json=UPSTREAM_OK)
    )
    try:
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as client:
            auth = {"Authorization": f"Bearer {seed_demo.demo_key('acme')}"}
            body = {"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]}
            # Allowed: budget, usage record, bandit event, session event, audit entry.
            assert (
                await client.post("/v1/chat/completions", headers=auth, json=body)
            ).status_code == 200
            # Held for review: bandit state row locked FOR UPDATE, review item written.
            set_threat_classifier(FakeThreatClassifier(ThreatScore(0.3, 0.7, 0.0)))
            assert (
                await client.post("/v1/chat/completions", headers=auth, json=body)
            ).status_code == 422
            set_threat_classifier(FakeThreatClassifier())
            await writer.flush()

            # The admin side: decide the review item, change a budget, verify the log.
            async with session_maker() as session:
                item = await session.scalar(select(ReviewQueueItem))
            assert item is not None
            decided = await client.post(
                f"/v1/admin/review-queue/{item.id}/decide", json={"decision": "attack"}
            )
            assert decided.status_code == 200
            team_id = (await client.get("/v1/admin/teams")).json()[0]["id"]
            budget = await client.put(
                f"/v1/admin/budget/{team_id}",
                json={"period": "daily", "limit_usd": "9.00", "rate_limit_rps": 5},
            )
            assert budget.status_code == 200, budget.text
            assert (await client.get("/v1/admin/logs/verify")).json()["valid"] is True
        async with session_maker() as session:
            assert len((await session.execute(select(AuditLogEntry))).all()) == 2
            assert (await verify_chain(session)).valid
    finally:
        app.dependency_overrides.clear()
        await writer.stop()
        reset_audit_writer()
        await engine.dispose()
