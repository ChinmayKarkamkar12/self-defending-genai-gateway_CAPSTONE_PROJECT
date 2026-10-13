"""Module 7: chain verification (app/core/audit/verify.py).

The tampering here is raw SQL on purpose: it is what someone with direct
database access would do, bypassing the ORM guard (test_audit_guard.py)
and, on Postgres, after disabling the trigger. Only the hash chain is
left to catch it.
"""
from sqlalchemy import text

from app.core.audit.hashing import compute_entry_hash, entry_fields
from app.core.audit.verify import verify_chain
from tests.audit_helpers import all_entries, write_chain


async def _verify(session_maker):
    async with session_maker() as session:
        return await verify_chain(session)


async def _sql(session_maker, statement: str, **params):
    async with session_maker() as session, session.begin():
        await session.execute(text(statement), params)


async def test_valid_chain_passes(session_maker, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    await write_chain(session_maker, team.id, api_key.id, 10)

    result = await _verify(session_maker)

    entries = await all_entries(session_maker)
    assert result.valid
    assert result.first_broken_entry is None
    assert result.entry_count == 10
    assert result.head_hash == entries[-1].entry_hash


async def test_empty_log_is_valid(session_maker):
    result = await _verify(session_maker)
    assert result.valid
    assert result.entry_count == 0


async def test_detects_tampered_entry(session_maker, seeded_team_and_key):
    """The headline test: change one field of one stored entry (a blocked
    request rewritten as allowed) and verify must flag exactly that entry."""
    team, api_key = seeded_team_and_key
    await write_chain(session_maker, team.id, api_key.id, 10, action_taken="block")
    target = (await all_entries(session_maker))[6]

    await _sql(
        session_maker,
        "UPDATE audit_log_entries SET action_taken = 'allow' WHERE id = :id",
        id=target.id.hex,
    )
    result = await _verify(session_maker)

    assert not result.valid
    assert result.first_broken_entry == str(target.id)
    assert result.first_broken_sequence == 7
    assert result.reason == "entry_hash does not match the entry's contents"
    assert result.entry_count == 6  # the six before it still check out


async def test_detects_tampered_json_field(session_maker, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    await write_chain(session_maker, team.id, api_key.id, 5)
    target = (await all_entries(session_maker))[2]

    await _sql(
        session_maker,
        "UPDATE audit_log_entries SET redaction_summary = '{}' WHERE id = :id",
        id=target.id.hex,
    )
    result = await _verify(session_maker)

    assert not result.valid
    assert result.first_broken_sequence == 3


async def test_detects_rehashed_entry_by_the_broken_link(session_maker, seeded_team_and_key):
    """A tamperer who also recomputes the edited entry's own hash breaks
    the link to the next entry instead."""
    team, api_key = seeded_team_and_key
    await write_chain(session_maker, team.id, api_key.id, 5, action_taken="block")
    target = (await all_entries(session_maker))[1]
    target.action_taken = "allow"  # detached copy, only used to compute the forgery
    forged_hash = compute_entry_hash(entry_fields(target), target.prev_hash)

    await _sql(
        session_maker,
        "UPDATE audit_log_entries SET action_taken = 'allow', entry_hash = :h WHERE id = :id",
        h=forged_hash,
        id=target.id.hex,
    )
    result = await _verify(session_maker)

    assert not result.valid
    assert result.first_broken_sequence == 3
    assert result.reason == "prev_hash does not match the previous entry's hash"


async def test_detects_deleted_entry(session_maker, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    await write_chain(session_maker, team.id, api_key.id, 5)

    await _sql(session_maker, "DELETE FROM audit_log_entries WHERE sequence_number = 3")
    result = await _verify(session_maker)

    assert not result.valid
    assert result.first_broken_sequence == 4
    assert result.reason == "sequence gap: expected 3, found 4"


async def test_tail_truncation_is_only_visible_through_the_head(
    session_maker, seeded_team_and_key
):
    """Documented limit (LIMITATIONS.md L7-2): deleting the newest entries
    leaves a valid chain. What changes is entry_count/head_hash, which is
    why verify reports them."""
    team, api_key = seeded_team_and_key
    await write_chain(session_maker, team.id, api_key.id, 5)
    before = await _verify(session_maker)

    await _sql(session_maker, "DELETE FROM audit_log_entries WHERE sequence_number = 5")
    after = await _verify(session_maker)

    assert after.valid
    assert after.entry_count == before.entry_count - 1
    assert after.head_hash != before.head_hash
