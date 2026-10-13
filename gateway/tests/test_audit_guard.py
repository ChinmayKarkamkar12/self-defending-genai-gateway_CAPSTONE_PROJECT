"""Module 7: the ORM-level append-only guard (app/core/audit/guard.py)."""
import pytest
from sqlalchemy import delete, update

from app.core.audit.guard import AuditLogImmutableError
from app.db.models import AuditLogEntry
from tests.audit_helpers import all_entries, write_chain


async def _first_id(session_maker):
    return (await all_entries(session_maker))[0].id


async def test_orm_update_is_refused(session_maker, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    await write_chain(session_maker, team.id, api_key.id, 1)

    async with session_maker() as session:
        entry = await session.get(AuditLogEntry, await _first_id(session_maker))
        entry.action_taken = "block"  # make_record's default is "allow"
        with pytest.raises(AuditLogImmutableError):
            await session.commit()


async def test_orm_delete_is_refused(session_maker, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    await write_chain(session_maker, team.id, api_key.id, 1)

    async with session_maker() as session:
        entry = await session.get(AuditLogEntry, await _first_id(session_maker))
        await session.delete(entry)
        with pytest.raises(AuditLogImmutableError):
            await session.commit()


async def test_bulk_update_and_delete_are_refused(session_maker, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    await write_chain(session_maker, team.id, api_key.id, 2)

    async with session_maker() as session:
        with pytest.raises(AuditLogImmutableError):
            await session.execute(update(AuditLogEntry).values(action_taken="allow"))
        with pytest.raises(AuditLogImmutableError):
            await session.execute(delete(AuditLogEntry))

    assert len(await all_entries(session_maker)) == 2


async def test_appending_is_unaffected(session_maker, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    await write_chain(session_maker, team.id, api_key.id, 2)
    await write_chain(session_maker, team.id, api_key.id, 2)
    assert len(await all_entries(session_maker)) == 4
