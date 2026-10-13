"""The hash chain behind the audit log. See project_plan/07-audit-logging.md §3.

    entry_hash = sha256(prev_hash + canonical JSON of the entry's fields)

`prev_hash` is the previous entry's `entry_hash` (GENESIS_HASH for the
first entry), so changing any field of any stored entry changes its hash
and no longer matches the `prev_hash` the next entry was written with.

The hash is computed once when the writer inserts the row and again by
verify.py from what the database hands back, so the canonical form must
not depend on how a value made the round trip: Postgres JSONB reorders
keys, `numeric(10,6)` comes back as a Decimal with its own formatting, and
SQLite drops the timezone. `canonical_value` reduces each value to one
fixed text form so both sides hash identical bytes.
"""
import hashlib
import json
from datetime import UTC, datetime
from decimal import Decimal
from enum import Enum
from typing import Any
from uuid import UUID

from app.db.models import AuditLogEntry

GENESIS_HASH = "0" * 64

# Every column except the two hash columns themselves. prev_hash is still
# covered: it is prepended to the canonical JSON before hashing.
HASHED_FIELDS: tuple[str, ...] = tuple(
    column.name
    for column in AuditLogEntry.__table__.columns
    if column.name not in ("entry_hash", "prev_hash")
)

_COST_QUANTUM = Decimal("0.000001")  # cost_usd is numeric(10,6)


def canonical_value(value: Any) -> Any:
    """One fixed JSON-ready form for a column value."""
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, datetime):
        # SQLite returns naive datetimes; every timestamp written is UTC.
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(value, Decimal | float) and not isinstance(value, bool):
        # Only cost_usd is a bare number column; JSON columns keep their
        # floats (json.dumps writes the shortest round-trip repr).
        return format(Decimal(str(value)).quantize(_COST_QUANTUM), "f")
    return value


def entry_fields(entry: AuditLogEntry) -> dict[str, Any]:
    """The hashed content of an entry, in canonical form."""
    return {name: canonical_value(getattr(entry, name)) for name in HASHED_FIELDS}


def compute_entry_hash(entry_fields: dict[str, Any], prev_hash: str) -> str:
    # allow_nan=False: NaN/Infinity aren't valid JSON and Postgres JSONB
    # rejects them, so a NaN score must fail here, loudly, not later.
    canonical = json.dumps(entry_fields, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()
