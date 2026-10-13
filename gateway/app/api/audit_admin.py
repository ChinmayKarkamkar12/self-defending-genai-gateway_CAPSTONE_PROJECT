"""Admin endpoints for the audit log (module 7), consumed by the dashboard's
log viewer (module 8). See project_plan/07-audit-logging.md §6.

    GET /v1/admin/logs             filtered, paginated query, newest first
    GET /v1/admin/logs/verify      re-checks the whole hash chain
    GET /v1/admin/logs/export      CSV compliance export, same filters

Read-only: nothing here (or anywhere) updates or deletes an entry. Like
every /v1/admin route these have no authentication yet (LIMITATIONS.md L3-1).
"""
import csv
import io
import json
from collections.abc import Iterator
from dataclasses import asdict
from datetime import datetime
from decimal import Decimal
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit.hashing import HASHED_FIELDS
from app.core.audit.verify import verify_chain
from app.db.models import AuditLogEntry, AuditOutcome
from app.db.session import get_db

router = APIRouter(prefix="/v1/admin/logs")

MAX_PAGE = 500
# The export is built in memory before it streams; this bounds it.
MAX_EXPORT_ROWS = 100_000

CSV_COLUMNS: tuple[str, ...] = (*HASHED_FIELDS, "prev_hash", "entry_hash")
# A cell starting with one of these is a formula to Excel/Sheets/LibreOffice
# (CSV injection, CWE-1236).
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


class AuditLogEntryOut(BaseModel):
    id: UUID
    sequence_number: int
    timestamp: datetime
    request_id: UUID
    team_id: UUID
    api_key_id: UUID
    model: str
    http_status: int
    outcome: AuditOutcome
    pipeline_stage: str | None
    redaction_summary: dict[str, int]
    threat_score: dict[str, float] | None
    action_taken: str
    threat_event_id: UUID | None
    session_id: str | None
    session_action: str | None
    output_flags: dict[str, Any] | None
    tokens_in: int
    tokens_out: int
    cost_usd: Decimal
    latency_ms: int
    prev_hash: str
    entry_hash: str

    model_config = {"from_attributes": True}


class AuditLogPage(BaseModel):
    entries: list[AuditLogEntryOut]
    # Pass as `before_sequence` to get the next (older) page; null at the end.
    next_before_sequence: int | None


class VerifyOut(BaseModel):
    valid: bool
    first_broken_entry: str | None
    first_broken_sequence: int | None
    reason: str | None
    # Entries checked and found valid, and the hash of the last of them.
    # Record both: a later run with fewer entries means the end was cut off.
    entry_count: int
    head_hash: str


def _filtered(
    team_id: UUID | None,
    from_: datetime | None,
    to: datetime | None,
    action: str | None,
    outcome: AuditOutcome | None,
) -> Select:
    stmt = select(AuditLogEntry)
    if team_id is not None:
        stmt = stmt.where(AuditLogEntry.team_id == team_id)
    if from_ is not None:
        stmt = stmt.where(AuditLogEntry.timestamp >= from_)
    if to is not None:
        stmt = stmt.where(AuditLogEntry.timestamp <= to)
    if action is not None:
        stmt = stmt.where(AuditLogEntry.action_taken == action)
    if outcome is not None:
        stmt = stmt.where(AuditLogEntry.outcome == outcome)
    return stmt


@router.get("", response_model=AuditLogPage)
async def query_logs(
    team_id: UUID | None = None,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    action: str | None = None,
    outcome: AuditOutcome | None = None,
    before_sequence: int | None = None,
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE)] = 100,
    db: AsyncSession = Depends(get_db),  # noqa: B008 - standard FastAPI DI pattern
) -> AuditLogPage:
    stmt = _filtered(team_id, from_, to, action, outcome)
    if before_sequence is not None:
        stmt = stmt.where(AuditLogEntry.sequence_number < before_sequence)
    stmt = stmt.order_by(AuditLogEntry.sequence_number.desc()).limit(limit + 1)
    rows = list((await db.execute(stmt)).scalars().all())
    has_more = len(rows) > limit
    rows = rows[:limit]
    return AuditLogPage(
        entries=[AuditLogEntryOut.model_validate(row) for row in rows],
        next_before_sequence=rows[-1].sequence_number if has_more else None,
    )


@router.get("/verify", response_model=VerifyOut)
async def verify_logs(
    db: AsyncSession = Depends(get_db),  # noqa: B008 - standard FastAPI DI pattern
) -> VerifyOut:
    return VerifyOut(**asdict(await verify_chain(db)))


def _csv_cell(value: Any) -> Any:
    if value is None:
        return ""
    if isinstance(value, dict | list):
        return json.dumps(value, sort_keys=True)
    if isinstance(value, str) and value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


def _csv_rows(entries: list[AuditLogEntry]) -> Iterator[str]:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(CSV_COLUMNS)
    for entry in entries:
        writer.writerow([_csv_cell(getattr(entry, column)) for column in CSV_COLUMNS])
        yield buffer.getvalue()
        buffer.seek(0)
        buffer.truncate()
    yield buffer.getvalue()


@router.get("/export")
async def export_logs(
    format: Literal["csv"] = "csv",
    team_id: UUID | None = None,
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    action: str | None = None,
    outcome: AuditOutcome | None = None,
    db: AsyncSession = Depends(get_db),  # noqa: B008 - standard FastAPI DI pattern
) -> StreamingResponse:
    stmt = (
        _filtered(team_id, from_, to, action, outcome)
        .order_by(AuditLogEntry.sequence_number)
        .limit(MAX_EXPORT_ROWS)
    )
    # Read inside the request, before streaming starts: the DB session is a
    # yield-dependency, and when those close relative to a streaming body
    # has changed between FastAPI versions.
    entries = list((await db.execute(stmt)).scalars().all())
    return StreamingResponse(
        _csv_rows(entries),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="audit_log.csv"'},
    )
