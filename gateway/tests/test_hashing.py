"""Module 7: the hash chain's building blocks (app/core/audit/hashing.py)."""
import math
import uuid
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal

import pytest

from app.core.audit.hashing import (
    GENESIS_HASH,
    HASHED_FIELDS,
    canonical_value,
    compute_entry_hash,
    entry_fields,
)
from tests.audit_helpers import all_entries, write_chain

FIELDS = {"a": 1, "b": {"y": 0.5, "x": "z"}, "c": None}


def test_hash_deterministic():
    first = compute_entry_hash(FIELDS, GENESIS_HASH)
    assert compute_entry_hash(dict(FIELDS), GENESIS_HASH) == first
    # Key order must not matter (Postgres JSONB doesn't preserve it).
    reordered = {"c": None, "b": {"x": "z", "y": 0.5}, "a": 1}
    assert compute_entry_hash(reordered, GENESIS_HASH) == first


def test_hash_changes_with_any_field_or_prev_hash():
    base = compute_entry_hash(FIELDS, GENESIS_HASH)
    assert compute_entry_hash({**FIELDS, "a": 2}, GENESIS_HASH) != base
    assert compute_entry_hash({**FIELDS, "b": {"y": 0.51, "x": "z"}}, GENESIS_HASH) != base
    assert compute_entry_hash(FIELDS, "1" * 64) != base


def test_nan_is_rejected_not_hashed():
    with pytest.raises(ValueError):
        compute_entry_hash({"score": math.nan}, GENESIS_HASH)


def test_canonical_values_survive_database_round_trips():
    # The same instant as aware UTC, aware +05:30, and SQLite's naive UTC.
    aware = datetime(2026, 10, 13, 12, 0, 0, 123456, tzinfo=UTC)
    ist = aware.astimezone(timezone(timedelta(hours=5, minutes=30)))
    naive = aware.replace(tzinfo=None)
    assert canonical_value(aware) == canonical_value(ist) == canonical_value(naive)
    # numeric(10,6) formatting differences, and SQLite's float fallback.
    assert canonical_value(Decimal("0.00033")) == "0.000330"
    assert canonical_value(Decimal("0.000330")) == "0.000330"
    assert canonical_value(0.00033) == "0.000330"
    u = uuid.uuid4()
    assert canonical_value(u) == str(u)


def test_hashed_fields_cover_every_column_but_the_hashes():
    assert "entry_hash" not in HASHED_FIELDS
    assert "prev_hash" not in HASHED_FIELDS
    for name in ("sequence_number", "outcome", "action_taken", "cost_usd", "threat_score"):
        assert name in HASHED_FIELDS


async def test_chain_links_correctly(session_maker, seeded_team_and_key):
    team, api_key = seeded_team_and_key
    await write_chain(session_maker, team.id, api_key.id, 3)
    await write_chain(session_maker, team.id, api_key.id, 2)  # a later batch continues it

    entries = await all_entries(session_maker)
    assert [e.sequence_number for e in entries] == [1, 2, 3, 4, 5]
    assert entries[0].prev_hash == GENESIS_HASH
    for previous, entry in zip(entries, entries[1:], strict=False):
        assert entry.prev_hash == previous.entry_hash
    # The stored hash is reproducible from what the database hands back.
    for entry in entries:
        assert entry.entry_hash == compute_entry_hash(entry_fields(entry), entry.prev_hash)
