"""Summary statistics for the dashboard (module 8).

    GET /v1/admin/stats/overview   one window: route through the checkpoint,
                                   decisions, spend, PII entity counts
    GET /v1/admin/stats/timeline   decisions per hour/day
    GET /v1/admin/stats/spend      cost and tokens per bucket, team and model

Computed here, not in the dashboard (project_plan/08-admin-dashboard.md §1:
the dashboard holds no business logic). Built on the audit log, which has
one entry per authenticated request whatever happened to it, and on usage
records for spend. Rows in the window are aggregated in Python, which keeps
one code path for Postgres and the SQLite test database; fine at demo scale
(LIMITATIONS.md L8-2).
"""
from collections import Counter
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    AuditLogEntry,
    AuditOutcome,
    DefenseAction,
    ReviewQueueItem,
    ReviewStatus,
    UsageRecord,
)
from app.db.session import get_db

router = APIRouter(prefix="/v1/admin/stats")

DEFAULT_TIMELINE_WINDOW = timedelta(days=7)


class Decision(StrEnum):
    """What happened to a request, as the dashboard colours it."""

    ALLOWED = "allowed"  # answered unchanged
    CLEANED = "cleaned"  # answered, with PII or flagged text removed first
    HELD = "held"  # escalated to a human reviewer
    REFUSED = "refused"  # stopped by a check
    FAILED = "failed"  # an error, not a decision


_REFUSED = {
    AuditOutcome.BLOCKED_SESSION_LOCKED,
    AuditOutcome.BLOCKED_BUDGET,
    AuditOutcome.BLOCKED_RATE_LIMIT,
    AuditOutcome.BLOCKED_THREAT,
    AuditOutcome.BLOCKED_OUTPUT_LEAK,
    AuditOutcome.REJECTED_UNKNOWN_MODEL,
    AuditOutcome.REJECTED_STREAMING,
}
_FAILED = {AuditOutcome.UPSTREAM_ERROR, AuditOutcome.PIPELINE_ERROR, AuditOutcome.INTERNAL_ERROR}


def classify(outcome: str, redaction_summary: dict[str, Any] | None, action_taken: str) -> Decision:
    outcome = AuditOutcome(outcome)
    if outcome == AuditOutcome.ALLOWED:
        if redaction_summary or action_taken == DefenseAction.REDACT_AND_ALLOW.value:
            return Decision.CLEANED
        return Decision.ALLOWED
    if outcome == AuditOutcome.ESCALATED:
        return Decision.HELD
    if outcome in _REFUSED:
        return Decision.REFUSED
    if outcome in _FAILED:
        return Decision.FAILED
    return Decision.FAILED  # an outcome added later without a mapping


# The checkpoints a request passes, in pipeline order (app/core/pipeline.py
# and app/api/chat.py). For each: which audit outcomes mean "stopped here".
# `screening` is threat detection + PII redaction + the bandit's decision.
_ROUTE: tuple[tuple[str, frozenset[AuditOutcome]], ...] = (
    ("intake", frozenset({AuditOutcome.REJECTED_STREAMING})),
    ("session", frozenset({AuditOutcome.BLOCKED_SESSION_LOCKED})),
    ("budget", frozenset({AuditOutcome.BLOCKED_BUDGET, AuditOutcome.BLOCKED_RATE_LIMIT})),
    ("screening", frozenset({AuditOutcome.BLOCKED_THREAT, AuditOutcome.ESCALATED})),
    ("provider", frozenset({AuditOutcome.REJECTED_UNKNOWN_MODEL, AuditOutcome.UPSTREAM_ERROR})),
    ("output", frozenset({AuditOutcome.BLOCKED_OUTPUT_LEAK})),
)


class RouteStage(BaseModel):
    key: str
    reached: int  # requests that got this far
    stopped: int  # refused, held or failed here
    cleaned: int  # passed on with something removed (screening only)


class OverviewOut(BaseModel):
    window_from: datetime
    window_to: datetime
    total_requests: int
    answered: int
    route: list[RouteStage]
    decisions: dict[Decision, int]
    outcomes: dict[AuditOutcome, int]
    # Pipeline or internal errors, which can happen at any stage.
    errors: int
    spend_usd: Decimal
    tokens_in: int
    tokens_out: int
    pii_entities: dict[str, int]
    pending_reviews: int


class TimelineBucket(BaseModel):
    bucket_start: datetime
    decisions: dict[Decision, int]
    total: int


class TimelineOut(BaseModel):
    window_from: datetime
    window_to: datetime
    bucket: Literal["hour", "day"]
    buckets: list[TimelineBucket]


class SpendPoint(BaseModel):
    bucket_start: datetime
    team_id: UUID
    model: str
    requests: int
    tokens_in: int
    tokens_out: int
    cost_usd: Decimal


class SpendOut(BaseModel):
    window_from: datetime
    window_to: datetime
    bucket: Literal["hour", "day"]
    points: list[SpendPoint]
    total_usd: Decimal


def _as_utc(value: datetime) -> datetime:
    # SQLite (the test database) drops tzinfo; Postgres keeps it.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _window(
    from_: datetime | None, to: datetime | None, default: timedelta | None
) -> tuple[datetime, datetime]:
    window_to = _as_utc(to) if to else datetime.now(UTC)
    if from_ is not None:
        window_from = _as_utc(from_)
    elif default is not None:
        window_from = window_to - default
    else:  # since midnight UTC
        window_from = window_to.replace(hour=0, minute=0, second=0, microsecond=0)
    if window_from > window_to:
        raise HTTPException(status_code=422, detail="'from' must not be later than 'to'")
    return window_from, window_to


def _bucket_start(at: datetime, bucket: str) -> datetime:
    at = _as_utc(at)
    if bucket == "day":
        return at.replace(hour=0, minute=0, second=0, microsecond=0)
    return at.replace(minute=0, second=0, microsecond=0)


def _team_filter(stmt, column, team_id: UUID | None):
    return stmt if team_id is None else stmt.where(column == team_id)


@router.get("/overview", response_model=OverviewOut)
async def overview(
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    team_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),  # noqa: B008 - standard FastAPI DI pattern
) -> OverviewOut:
    """Defaults to today (since midnight UTC)."""
    window_from, window_to = _window(from_, to, default=None)
    stmt = select(
        AuditLogEntry.outcome,
        AuditLogEntry.redaction_summary,
        AuditLogEntry.action_taken,
        AuditLogEntry.tokens_in,
        AuditLogEntry.tokens_out,
        AuditLogEntry.cost_usd,
    ).where(AuditLogEntry.timestamp >= window_from, AuditLogEntry.timestamp <= window_to)
    rows = (await db.execute(_team_filter(stmt, AuditLogEntry.team_id, team_id))).all()

    outcomes: Counter[AuditOutcome] = Counter()
    decisions: Counter[Decision] = Counter({d: 0 for d in Decision})
    pii: Counter[str] = Counter()
    screening_cleaned = 0
    spend = Decimal("0")
    tokens_in = tokens_out = 0
    for outcome, redaction_summary, action_taken, t_in, t_out, cost in rows:
        outcome = AuditOutcome(outcome)
        outcomes[outcome] += 1
        decision = classify(outcome, redaction_summary, action_taken)
        decisions[decision] += 1
        if decision == Decision.CLEANED:
            screening_cleaned += 1
        for entity, count in (redaction_summary or {}).items():
            pii[entity] += int(count)
        spend += Decimal(cost)
        tokens_in += t_in
        tokens_out += t_out

    errors = outcomes[AuditOutcome.PIPELINE_ERROR] + outcomes[AuditOutcome.INTERNAL_ERROR]
    route: list[RouteStage] = []
    reached = len(rows) - errors
    for key, stopping in _ROUTE:
        stopped = sum(outcomes[o] for o in stopping)
        route.append(
            RouteStage(
                key=key,
                reached=reached,
                stopped=stopped,
                cleaned=screening_cleaned if key == "screening" else 0,
            )
        )
        reached -= stopped

    pending = await db.scalar(
        select(func.count())
        .select_from(ReviewQueueItem)
        .where(ReviewQueueItem.status == ReviewStatus.PENDING)
    )
    return OverviewOut(
        window_from=window_from,
        window_to=window_to,
        total_requests=len(rows),
        answered=outcomes[AuditOutcome.ALLOWED],
        route=route,
        decisions=dict(decisions),
        outcomes={o: outcomes[o] for o in AuditOutcome},
        errors=errors,
        spend_usd=spend,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        pii_entities=dict(pii.most_common()),
        pending_reviews=int(pending or 0),
    )


@router.get("/timeline", response_model=TimelineOut)
async def timeline(
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    bucket: Literal["hour", "day"] = "hour",
    team_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),  # noqa: B008 - standard FastAPI DI pattern
) -> TimelineOut:
    """Defaults to the last 7 days."""
    window_from, window_to = _window(from_, to, default=DEFAULT_TIMELINE_WINDOW)
    stmt = select(
        AuditLogEntry.timestamp,
        AuditLogEntry.outcome,
        AuditLogEntry.redaction_summary,
        AuditLogEntry.action_taken,
    ).where(AuditLogEntry.timestamp >= window_from, AuditLogEntry.timestamp <= window_to)
    rows = (await db.execute(_team_filter(stmt, AuditLogEntry.team_id, team_id))).all()

    buckets: dict[datetime, Counter[Decision]] = {}
    for timestamp, outcome, redaction_summary, action_taken in rows:
        counts = buckets.setdefault(_bucket_start(timestamp, bucket), Counter())
        counts[classify(outcome, redaction_summary, action_taken)] += 1
    return TimelineOut(
        window_from=window_from,
        window_to=window_to,
        bucket=bucket,
        buckets=[
            TimelineBucket(
                bucket_start=start,
                decisions={d: counts[d] for d in Decision},
                total=sum(counts.values()),
            )
            for start, counts in sorted(buckets.items())
        ],
    )


@router.get("/spend", response_model=SpendOut)
async def spend(
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    bucket: Literal["hour", "day"] = "day",
    team_id: UUID | None = None,
    db: AsyncSession = Depends(get_db),  # noqa: B008 - standard FastAPI DI pattern
) -> SpendOut:
    """Defaults to the last 7 days. From usage records, which hold the
    provider-reported tokens and the reconciled cost."""
    window_from, window_to = _window(from_, to, default=DEFAULT_TIMELINE_WINDOW)
    stmt = select(
        UsageRecord.timestamp,
        UsageRecord.team_id,
        UsageRecord.model,
        UsageRecord.tokens_in,
        UsageRecord.tokens_out,
        UsageRecord.cost_usd,
    ).where(UsageRecord.timestamp >= window_from, UsageRecord.timestamp <= window_to)
    rows = (await db.execute(_team_filter(stmt, UsageRecord.team_id, team_id))).all()

    totals: dict[tuple[datetime, UUID, str], list[Any]] = {}
    for timestamp, row_team, model, t_in, t_out, cost in rows:
        key = (_bucket_start(timestamp, bucket), row_team, model)
        acc = totals.setdefault(key, [0, 0, 0, Decimal("0")])
        acc[0] += 1
        acc[1] += t_in
        acc[2] += t_out
        acc[3] += Decimal(cost)
    points = [
        SpendPoint(
            bucket_start=start,
            team_id=row_team,
            model=model,
            requests=acc[0],
            tokens_in=acc[1],
            tokens_out=acc[2],
            cost_usd=acc[3],
        )
        for (start, row_team, model), acc in sorted(
            totals.items(), key=lambda item: (item[0][0], str(item[0][1]), item[0][2])
        )
    ]
    return SpendOut(
        window_from=window_from,
        window_to=window_to,
        bucket=bucket,
        points=points,
        total_usd=sum((p.cost_usd for p in points), Decimal("0")),
    )
