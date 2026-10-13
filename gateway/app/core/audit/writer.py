"""Async audit-log writer: a bounded in-memory queue and one background
worker. See project_plan/07-audit-logging.md §4.

The request path only calls `enqueue`, which is a non-blocking
`put_nowait` - writing the entry never delays the client's response. The
worker drains the queue and writes entries in batches, one batch at a
time, because each entry's hash depends on the one before it: chaining is
inherently sequential. That single writer is the throughput ceiling of the
audit log (LIMITATIONS.md L7-3); at demo scale it is far above the load.

Each batch is one transaction that reads the current chain head and
inserts the new entries after it. On Postgres the transaction first takes
an advisory lock, so even several gateway processes (each with its own
worker) would append one after another instead of forking the chain.

Failures:
  - queue full or worker not running -> `enqueue` raises; the audit stage
    then fails, and under FAIL_MODE=closed the request gets a 503 rather
    than an unaudited success (ADR-0001).
  - transient DB error (connection lost, database locked) -> the batch is
    retried with backoff until it succeeds; the queue fills meanwhile,
    which is what turns a long outage into 503s.
  - permanent error (the DB rejects a row) -> the batch is split and
    retried entry by entry, so one bad entry can't block the others; an
    entry the DB rejects on its own is dropped, counted in `dropped` and
    logged by request ID.
  - process crash -> entries still in the queue are lost (L7-1). A
    durable queue (Redis Streams, Kafka) would fix that; deliberately not
    built for a single-node demo deployment.
"""
import asyncio
import logging
from typing import Any

from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, InterfaceError, OperationalError
from sqlalchemy.exc import TimeoutError as PoolTimeoutError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.core.audit.hashing import GENESIS_HASH, compute_entry_hash, entry_fields
from app.db.models import AuditLogEntry

logger = logging.getLogger("gateway.audit")

# Arbitrary constant naming the advisory lock that serializes chain appends.
CHAIN_LOCK_KEY = 70_700_007

DEFAULT_MAX_QUEUE = 10_000
DEFAULT_BATCH_SIZE = 100
_BACKOFF_START = 0.1
_BACKOFF_MAX = 5.0
# sqlalchemy's pool TimeoutError is not the builtin TimeoutError: a pool
# exhausted by request traffic must be waited out, not treated as a bad entry.
_TRANSIENT_ERRORS = (OperationalError, InterfaceError, PoolTimeoutError, OSError, TimeoutError)


def _is_transient(exc: Exception) -> bool:
    if isinstance(exc, _TRANSIENT_ERRORS):
        return True
    # e.g. asyncpg's ConnectionDoesNotExistError arrives as a plain DBAPIError
    return isinstance(exc, DBAPIError) and exc.connection_invalidated


class AuditQueueFull(Exception):
    """The audit queue is at capacity (the worker is behind or stalled)."""


class AuditWriterNotRunning(Exception):
    """An entry was enqueued while no worker is running to write it."""


async def append_entries(session: AsyncSession, records: list[dict[str, Any]]) -> None:
    """Chain `records` onto the end of the log and add them to `session`.
    The caller owns the transaction (and must hold it until commit)."""
    if session.bind.dialect.name == "postgresql":
        await session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": CHAIN_LOCK_KEY})
    head = (
        await session.execute(
            select(AuditLogEntry.sequence_number, AuditLogEntry.entry_hash)
            .order_by(AuditLogEntry.sequence_number.desc())
            .limit(1)
        )
    ).first()
    sequence, prev_hash = (head[0], head[1]) if head else (0, GENESIS_HASH)
    for record in records:
        sequence += 1
        entry = AuditLogEntry(**record, sequence_number=sequence, prev_hash=prev_hash)
        entry.entry_hash = compute_entry_hash(entry_fields(entry), prev_hash)
        session.add(entry)
        prev_hash = entry.entry_hash


class AuditWriter:
    def __init__(
        self,
        session_maker: async_sessionmaker[AsyncSession],
        max_queue: int = DEFAULT_MAX_QUEUE,
        batch_size: int = DEFAULT_BATCH_SIZE,
    ):
        self._session_maker = session_maker
        self._queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=max_queue)
        self._batch_size = batch_size
        self._task: asyncio.Task | None = None
        self.written = 0
        self.dropped = 0

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def pending(self) -> int:
        return self._queue.qsize()

    def start(self) -> None:
        if not self.running:
            self._task = asyncio.create_task(self._run(), name="audit-writer")

    def enqueue(self, record: dict[str, Any]) -> None:
        if not self.running:
            raise AuditWriterNotRunning()
        try:
            self._queue.put_nowait(record)
        except asyncio.QueueFull:
            raise AuditQueueFull() from None

    async def flush(self) -> None:
        """Wait until every entry enqueued so far is written (or dropped)."""
        await self._queue.join()

    async def stop(self, timeout: float = 10.0) -> None:
        """Drain the queue (up to `timeout` seconds), then stop the worker."""
        if self._task is None:
            return
        try:
            await asyncio.wait_for(self._queue.join(), timeout)
        except TimeoutError:
            logger.error("audit writer stopped with %d entries unwritten", self._queue.qsize())
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None

    async def _run(self) -> None:
        while True:
            batch = [await self._queue.get()]
            while len(batch) < self._batch_size and not self._queue.empty():
                batch.append(self._queue.get_nowait())
            try:
                await self._write(batch)
            finally:
                for _ in batch:
                    self._queue.task_done()

    async def _write(self, batch: list[dict[str, Any]]) -> None:
        try:
            await self._write_until_done(batch)
        except Exception as exc:  # noqa: BLE001 - permanent error, see module docstring
            if len(batch) > 1:
                for record in batch:
                    await self._write([record])
                return
            # Type name and request ID only: the entry holds no text, but
            # a driver error message is not worth trusting to that.
            logger.error(
                "audit entry for request %s rejected by the database (%s); dropped",
                batch[0].get("request_id"),
                type(exc).__name__,
            )
            self.dropped += 1

    async def _write_until_done(self, batch: list[dict[str, Any]]) -> None:
        delay = _BACKOFF_START
        while True:
            try:
                async with self._session_maker() as session, session.begin():
                    await append_entries(session, batch)
                self.written += len(batch)
                return
            except Exception as exc:  # noqa: BLE001 - classified just below
                if not _is_transient(exc):
                    raise
                logger.warning(
                    "audit write failed (%s); retrying in %.1fs", type(exc).__name__, delay
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, _BACKOFF_MAX)


_writer: AuditWriter | None = None


def get_audit_writer() -> AuditWriter:
    global _writer
    if _writer is None:
        from app.db.session import async_session_maker

        _writer = AuditWriter(async_session_maker)
    return _writer


def set_audit_writer(writer: AuditWriter) -> None:
    """Test hook, same pattern as set_threat_classifier."""
    global _writer
    _writer = writer


def reset_audit_writer() -> None:
    global _writer
    _writer = None
