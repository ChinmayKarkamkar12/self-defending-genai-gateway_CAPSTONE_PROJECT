"""Admin endpoints for the tactical bandit, consumed by the dashboard
(module 8). See project_plan/06a-adaptive-defense-bandit.md §6.

Same caveat as every /v1/admin route today (LIMITATIONS.md L3-1, L6a-4):
there is no admin authentication until module 8, and a forged review
decision here would train the bandit on a false label.
"""
from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.defense import review_queue
from app.core.defense.bandit import ACTIONS
from app.core.defense.store import POLICY_NAME, bandit_store
from app.db.models import (
    BanditState,
    DefenseAction,
    ReviewQueueItem,
    ReviewReason,
    ReviewStatus,
    RewardSource,
    ThreatEvent,
    ThreatLabel,
)
from app.db.session import get_db

router = APIRouter(prefix="/v1/admin")

DEFAULT_STATS_WINDOW = timedelta(days=7)


class ReviewItemOut(BaseModel):
    id: UUID
    threat_event_id: UUID
    request_id: UUID
    team_id: UUID
    reason: ReviewReason
    status: ReviewStatus
    action_taken: DefenseAction
    outcome: DefenseAction
    threat_score: dict[str, float]
    bandit_confidence: float
    prompt_excerpt: str
    created_at: datetime
    reviewer: str | None
    decision: ThreatLabel | None
    reviewed_at: datetime | None
    amendments: list[dict[str, Any]]


class ReviewDecisionIn(BaseModel):
    decision: ThreatLabel
    reviewer: str = Field(min_length=1, max_length=200)


class ReviewDecisionOut(BaseModel):
    item: ReviewItemOut
    reward_applied: float | None
    bandit_updated: bool


class TimelineBucket(BaseModel):
    bucket_start: datetime
    counts: dict[DefenseAction, int]
    total: int


class RewardPoint(BaseModel):
    at: datetime
    reward: float
    cumulative: float
    source: RewardSource


class BanditStatsOut(BaseModel):
    window_from: datetime
    window_to: datetime
    model_version: int
    updates_per_action: dict[DefenseAction, int]
    pending_reviews: int
    action_counts: dict[DefenseAction, int]
    timeline: list[TimelineBucket]
    reward_trend: list[RewardPoint]
    cumulative_reward: float
    mean_reward: float | None


def _as_utc(value: datetime) -> datetime:
    # SQLite (the test database) drops tzinfo; Postgres keeps it.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def _item_out(item: ReviewQueueItem) -> ReviewItemOut:
    event = item.threat_event
    return ReviewItemOut(
        id=item.id,
        threat_event_id=event.id,
        request_id=event.request_id,
        team_id=event.team_id,
        reason=item.reason,
        status=item.status,
        action_taken=event.action_taken,
        outcome=event.outcome or event.action_taken,
        threat_score=event.threat_score,
        bandit_confidence=event.bandit_confidence,
        prompt_excerpt=item.prompt_excerpt,
        created_at=_as_utc(item.created_at),
        reviewer=item.reviewer,
        decision=item.decision,
        reviewed_at=_as_utc(item.reviewed_at) if item.reviewed_at else None,
        amendments=list(item.amendments or []),
    )


@router.get("/review-queue", response_model=list[ReviewItemOut])
async def get_review_queue(
    status: ReviewStatus = ReviewStatus.PENDING,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
    db: AsyncSession = Depends(get_db),  # noqa: B008 - standard FastAPI DI pattern
) -> list[ReviewItemOut]:
    items = await review_queue.list_items(db, status=status, limit=limit, offset=offset)
    out = [_item_out(item) for item in items]
    await db.commit()  # list_items expires stale items first
    return out


@router.post("/review-queue/{item_id}/decide", response_model=ReviewDecisionOut)
async def decide_review_item(
    item_id: UUID,
    body: ReviewDecisionIn,
    db: AsyncSession = Depends(get_db),  # noqa: B008 - standard FastAPI DI pattern
) -> ReviewDecisionOut:
    try:
        outcome = await review_queue.decide(db, item_id, body.decision, body.reviewer)
    except review_queue.ReviewItemNotFound:
        raise HTTPException(status_code=404, detail="review item not found") from None
    except review_queue.ReviewItemAlreadyDecided:
        raise HTTPException(
            status_code=409, detail="review item already decided; use /amend to change it"
        ) from None
    except review_queue.ReviewItemExpired:
        raise HTTPException(status_code=409, detail="review item expired") from None
    return _decision_out(outcome)


@router.post("/review-queue/{item_id}/amend", response_model=ReviewDecisionOut)
async def amend_review_item(
    item_id: UUID,
    body: ReviewDecisionIn,
    db: AsyncSession = Depends(get_db),  # noqa: B008 - standard FastAPI DI pattern
) -> ReviewDecisionOut:
    """Change an already-decided verdict: the old reward is withdrawn from
    the bandit and the new one applied. The old verdict and who amended it
    are kept on the item."""
    try:
        outcome = await review_queue.amend(db, item_id, body.decision, body.reviewer)
    except review_queue.ReviewItemNotFound:
        raise HTTPException(status_code=404, detail="review item not found") from None
    except review_queue.ReviewItemNotDecided:
        raise HTTPException(status_code=409, detail="review item has not been decided") from None
    return _decision_out(outcome)


def _decision_out(outcome: review_queue.DecisionOutcome) -> ReviewDecisionOut:
    return ReviewDecisionOut(
        item=_item_out(outcome.item),
        reward_applied=outcome.reward,
        bandit_updated=outcome.bandit_updated,
    )


def _bucket_start(at: datetime, bucket: str) -> datetime:
    at = _as_utc(at)
    if bucket == "day":
        return at.replace(hour=0, minute=0, second=0, microsecond=0)
    return at.replace(minute=0, second=0, microsecond=0)


@router.get("/bandit/stats", response_model=BanditStatsOut)
async def get_bandit_stats(
    from_: Annotated[datetime | None, Query(alias="from")] = None,
    to: datetime | None = None,
    bucket: Literal["hour", "day"] = "hour",
    db: AsyncSession = Depends(get_db),  # noqa: B008 - standard FastAPI DI pattern
) -> BanditStatsOut:
    window_to = _as_utc(to) if to else datetime.now(UTC)
    window_from = _as_utc(from_) if from_ else window_to - DEFAULT_STATS_WINDOW
    if window_from > window_to:
        raise HTTPException(status_code=422, detail="'from' must not be after 'to'")

    decisions = (
        await db.execute(
            select(ThreatEvent.created_at, ThreatEvent.action_taken)
            .where(ThreatEvent.created_at >= window_from, ThreatEvent.created_at <= window_to)
            .order_by(ThreatEvent.created_at)
        )
    ).all()
    action_counts: Counter[str] = Counter()
    buckets: dict[datetime, Counter[str]] = {}
    for created_at, action in decisions:
        action_counts[action] += 1
        buckets.setdefault(_bucket_start(created_at, bucket), Counter())[action] += 1

    rewards = (
        await db.execute(
            select(ThreatEvent.rewarded_at, ThreatEvent.reward_applied, ThreatEvent.reward_source)
            .where(
                ThreatEvent.reward_applied.is_not(None),
                ThreatEvent.rewarded_at >= window_from,
                ThreatEvent.rewarded_at <= window_to,
            )
            .order_by(ThreatEvent.rewarded_at)
        )
    ).all()
    trend: list[RewardPoint] = []
    cumulative = 0.0
    for rewarded_at, reward, source in rewards:
        cumulative += reward
        point = RewardPoint(
            at=_as_utc(rewarded_at), reward=reward, cumulative=cumulative, source=source
        )
        trend.append(point)

    version = (
        await db.execute(select(BanditState.version).where(BanditState.name == POLICY_NAME))
    ).scalar_one_or_none()
    bandit = await bandit_store.current(db)

    def per_action(counts: Any) -> dict[DefenseAction, int]:
        return {action: int(counts[action.value]) for action in ACTIONS}

    pending = await review_queue.count_pending(db)
    await db.commit()  # count_pending expires stale items first
    return BanditStatsOut(
        window_from=window_from,
        window_to=window_to,
        model_version=version or 0,
        updates_per_action={
            action: int(n) for action, n in zip(ACTIONS, bandit.update_counts, strict=True)
        },
        pending_reviews=pending,
        action_counts=per_action(action_counts),
        timeline=[
            TimelineBucket(bucket_start=start, counts=per_action(c), total=sum(c.values()))
            for start, c in sorted(buckets.items())
        ],
        reward_trend=trend,
        cumulative_reward=cumulative,
        mean_reward=cumulative / len(trend) if trend else None,
    )
