"""Tamper demo for the audit log (module 7). See project_plan/07-audit-logging.md §3, §7.

Shows the hash chain catching an edit made directly in the database - the
"insider with database access hides a blocked attack" scenario:

  1. verify the chain              -> VALID
  2. rewrite one entry's action_taken (e.g. block -> allow) with raw SQL,
     bypassing the application entirely
  3. verify again                  -> BROKEN, pointing at that exact entry
  4. put the original value back   -> VALID again

    python -m scripts.tamper_demo                   # throwaway SQLite database
    python -m scripts.tamper_demo --postgres        # the gateway's real database
    python -m scripts.tamper_demo --postgres --hold # pause while tampered, so the
                                                    # dashboard's "Check integrity"
                                                    # can catch it live; Enter restores

The default mode creates a temporary database, writes 10 sample entries
through the real AuditWriter, and deletes it afterwards.

--postgres tampers with an *existing* entry in the configured database
(send a few requests through the gateway first) and restores it before
exiting. It writes no sample entries there: the log is append-only, so
they could never be removed. On Postgres the step-2 edit first has to get
past the immutability trigger; it does so the way only a superuser could
(`SET LOCAL session_replication_role = replica`, which skips triggers for
that one transaction) - which is exactly the attacker the hash chain is
for. Needs the gateway's DB user to be a superuser (it is in the Docker
Compose setup).
"""
import argparse
import asyncio
import shutil
import sys
import tempfile
import uuid
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from pathlib import Path

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from app.core.audit.verify import VerificationResult, verify_chain
from app.core.audit.writer import AuditWriter
from app.db.base import Base
from app.db.models import ApiKey, AuditLogEntry, AuditOutcome, Team
from app.db.session import _asyncpg_dsn


def _say(text_: str = "") -> None:
    print(text_, flush=True)


def _report(result: VerificationResult) -> None:
    if result.valid:
        _say(f"   -> VALID: {result.entry_count} entries, head hash {result.head_hash[:16]}...")
    else:
        _say(f"   -> BROKEN at entry #{result.first_broken_sequence} ({result.first_broken_entry})")
        _say(f"      reason: {result.reason}")
        _say(f"      entries before it that still check out: {result.entry_count}")


async def _verify(session_maker) -> VerificationResult:
    async with session_maker() as session:
        return await verify_chain(session)


async def _seed_sqlite(session_maker) -> None:
    async with session_maker() as session, session.begin():
        team = Team(name="Demo Team")
        session.add(team)
        await session.flush()
        api_key = ApiKey(key_hash=uuid.uuid4().hex * 2, team_id=team.id, name="demo-key")
        session.add(api_key)
        await session.flush()
        team_id, api_key_id = team.id, api_key.id

    writer = AuditWriter(session_maker)
    writer.start()
    start = datetime.now(UTC) - timedelta(minutes=10)
    for i in range(10):
        attack = i in (2, 5, 8)
        writer.enqueue(
            {
                "id": uuid.uuid4(),
                "timestamp": start + timedelta(minutes=i),
                "request_id": uuid.uuid4(),
                "team_id": team_id,
                "api_key_id": api_key_id,
                "model": "gpt-4",
                "http_status": 422 if attack else 200,
                "outcome": AuditOutcome.BLOCKED_THREAT if attack else AuditOutcome.ALLOWED,
                "pipeline_stage": "bandit_policy_stage" if attack else None,
                "redaction_summary": {"EMAIL_ADDRESS": 1} if i % 4 == 0 else {},
                "threat_score": (
                    {"benign": 0.002, "prompt_injection": 0.997, "jailbreak": 0.001}
                    if attack
                    else {"benign": 0.998, "prompt_injection": 0.001, "jailbreak": 0.001}
                ),
                "action_taken": "block" if attack else "allow",
                "threat_event_id": uuid.uuid4(),
                "session_id": uuid.uuid4().hex,
                "session_action": "maintain",
                "output_flags": None if attack else {
                    "system_prompt_leaked": False,
                    "echoed_redaction_tokens": 0,
                },
                "tokens_in": 0 if attack else 42,
                "tokens_out": 0 if attack else 17,
                "cost_usd": Decimal("0") if attack else Decimal("0.002280"),
                "latency_ms": 35 + i,
            }
        )
    await writer.stop()


async def _pick_target(session_maker) -> AuditLogEntry | None:
    """A blocked entry if there is one (the story: hide an attack), else
    the middle entry."""
    async with session_maker() as session:
        blocked = await session.scalar(
            select(AuditLogEntry)
            .where(AuditLogEntry.action_taken.in_(("block", "escalate_to_human")))
            .order_by(AuditLogEntry.sequence_number)
            .limit(1)
        )
        if blocked is not None:
            return blocked
        count = await session.scalar(select(AuditLogEntry.sequence_number).order_by(
            AuditLogEntry.sequence_number.desc()
        ).limit(1))
        if not count:
            return None
        return await session.scalar(
            select(AuditLogEntry).where(AuditLogEntry.sequence_number == (count + 1) // 2)
        )


async def _set_action(session_maker, engine: AsyncEngine, entry_id: uuid.UUID, value: str):
    """Raw SQL, outside the application: the ORM guard never sees it."""
    async with session_maker() as session, session.begin():
        if engine.dialect.name == "postgresql":
            # Superuser-only: skip the immutability trigger for this transaction.
            await session.execute(text("SET LOCAL session_replication_role = replica"))
            id_param = str(entry_id)
        else:
            id_param = entry_id.hex  # SQLite stores UUIDs as 32 hex characters
        await session.execute(
            text("UPDATE audit_log_entries SET action_taken = :value WHERE id = :id"),
            {"value": value, "id": id_param},
        )


async def run(postgres: bool, hold: bool = False) -> int:
    tmpdir = None
    if postgres:
        from app.config import settings

        engine = create_async_engine(_asyncpg_dsn(settings.POSTGRES_DSN))
        _say("Using the gateway's configured Postgres database.")
    else:
        tmpdir = tempfile.mkdtemp(prefix="audit_tamper_demo_")
        engine = create_async_engine(f"sqlite+aiosqlite:///{Path(tmpdir) / 'demo.db'}")
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        _say("Using a throwaway SQLite database.")
    session_maker = async_sessionmaker(engine, expire_on_commit=False)

    try:
        if not postgres:
            _say("\n0. Writing 10 sample audit entries through the real AuditWriter")
            await _seed_sqlite(session_maker)

        _say("\n1. Verifying the untouched chain")
        before = await _verify(session_maker)
        _report(before)
        if not before.valid:
            _say("   The chain is already broken - not tampering further.")
            return 1

        target = await _pick_target(session_maker)
        if target is None:
            _say("   No entries to tamper with - send a few requests through the gateway first.")
            return 1
        original = target.action_taken
        forged = "allow" if original != "allow" else "block"

        _say(
            f"\n2. Tampering: entry #{target.sequence_number} "
            f"action_taken '{original}' -> '{forged}' (raw SQL, bypassing the app)"
        )
        await _set_action(session_maker, engine, target.id, forged)
        try:
            _say("\n3. Verifying again")
            after = await _verify(session_maker)
            _report(after)
            caught = (not after.valid) and after.first_broken_entry == str(target.id)
            if hold:
                _say(
                    f"\n   Entry #{target.sequence_number} is tampered right now. Open the"
                    "\n   dashboard's Audit log and click 'Check integrity' to see it caught."
                )
                await asyncio.to_thread(input, "   Press Enter to restore it... ")
        finally:
            _say(f"\n4. Restoring entry #{target.sequence_number} to '{original}'")
            await _set_action(session_maker, engine, target.id, original)
            restored = await _verify(session_maker)
            _report(restored)

        _say()
        if caught and restored.valid:
            _say("RESULT: the hash chain caught the edit and named the exact entry.")
            return 0
        _say("RESULT: unexpected - the edit was NOT detected as expected.")
        return 1
    finally:
        await engine.dispose()
        if tmpdir:
            shutil.rmtree(tmpdir, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--postgres",
        action="store_true",
        help="tamper with (and restore) an existing entry in the configured database",
    )
    parser.add_argument(
        "--hold",
        action="store_true",
        help="with --postgres: wait for Enter before restoring (for showing it in the dashboard)",
    )
    args = parser.parse_args()
    if args.hold and not args.postgres:
        parser.error("--hold needs --postgres (the dashboard reads the real database)")
    sys.exit(asyncio.run(run(args.postgres, args.hold)))


if __name__ == "__main__":
    main()
