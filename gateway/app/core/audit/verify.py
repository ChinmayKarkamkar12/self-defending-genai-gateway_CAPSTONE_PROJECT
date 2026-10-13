"""Audit-log chain verification. See project_plan/07-audit-logging.md §5.

Walks every AuditLogEntry in sequence order and checks, for each one:
  1. sequence_number is exactly one more than the previous entry's
     (catches a deleted entry in the middle, and a forged one inserted)
  2. prev_hash equals the previous entry's entry_hash (GENESIS_HASH for
     the first) - the chain link
  3. entry_hash equals the hash recomputed from the stored fields
     (catches any edited field, including an edited entry_hash)
and reports the first entry where any of them fails.

What it cannot see on its own: entries deleted from the *end* of the log,
since what's left is still a valid chain. `entry_count` and `head_hash`
are returned so they can be recorded somewhere else and compared on a
later run (LIMITATIONS.md L7-2).

Run from the command line against the configured database:
    python -m app.core.audit.verify
"""
import asyncio
import json
import sys
from dataclasses import asdict, dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit.hashing import GENESIS_HASH, compute_entry_hash, entry_fields
from app.db.models import AuditLogEntry

_BATCH = 1000


@dataclass
class VerificationResult:
    valid: bool
    entry_count: int
    head_hash: str
    first_broken_entry: str | None = None
    first_broken_sequence: int | None = None
    reason: str | None = None


async def verify_chain(session: AsyncSession) -> VerificationResult:
    expected_sequence = 1
    prev_hash = GENESIS_HASH
    count = 0
    stream = await session.stream_scalars(
        select(AuditLogEntry)
        .order_by(AuditLogEntry.sequence_number)
        .execution_options(yield_per=_BATCH)
    )
    async for entry in stream:
        reason = None
        if entry.sequence_number != expected_sequence:
            reason = (
                f"sequence gap: expected {expected_sequence}, found {entry.sequence_number}"
            )
        elif entry.prev_hash != prev_hash:
            reason = "prev_hash does not match the previous entry's hash"
        elif entry.entry_hash != compute_entry_hash(entry_fields(entry), entry.prev_hash):
            reason = "entry_hash does not match the entry's contents"
        if reason is not None:
            await stream.close()
            return VerificationResult(
                valid=False,
                entry_count=count,
                head_hash=prev_hash,
                first_broken_entry=str(entry.id),
                first_broken_sequence=entry.sequence_number,
                reason=reason,
            )
        count += 1
        expected_sequence += 1
        prev_hash = entry.entry_hash
    return VerificationResult(valid=True, entry_count=count, head_hash=prev_hash)


async def _main() -> int:
    from app.db.session import async_session_maker, engine

    async with async_session_maker() as session:
        result = await verify_chain(session)
    await engine.dispose()
    print(json.dumps(asdict(result), indent=2))
    return 0 if result.valid else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(_main()))
